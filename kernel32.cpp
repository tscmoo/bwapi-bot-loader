#include "environment.h"
#include "wintypes.h"
using namespace wintypes;
#include "modules.h"
#include "native_api.h"

#include <cstdint>
#include <mutex>
#include <deque>
#include <atomic>
#include <map>
#include <list>
#include <vector>
#include <chrono>
#include <ctime>
#include <thread>
#include <algorithm>
#include <array>
#include <memory>
#include <condition_variable>

namespace kernel32 {
;

modules::module_info* main_module_info = nullptr;

struct thread;

struct TLB {
	DWORD last_error = 0;
	DWORD thread_id = 0;
	thread* current_thread = nullptr;
};

thread_local TLB tlb;


DWORD WINAPI GetLastError() {
	return tlb.last_error;
}

void WINAPI SetLastError(DWORD err) {
	log("SetLastError %d\n", err);
	tlb.last_error = err;
}

struct OSVERSIONINFOA {
	DWORD dwOSVersionInfoSize;
	DWORD dwMajorVersion;
	DWORD dwMinorVersion;
	DWORD dwBuildNumber;
	DWORD dwPlatformId;
	CHAR szCSDVersion[128];
};

BOOL WINAPI GetVersionExA(OSVERSIONINFOA* lpVersionInfo) {
	if (lpVersionInfo->dwOSVersionInfoSize != sizeof(OSVERSIONINFOA)) {
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}
	lpVersionInfo->dwMajorVersion = 6;
	lpVersionInfo->dwMinorVersion = 3;
	lpVersionInfo->dwBuildNumber = 9200;
	lpVersionInfo->dwPlatformId = 2;
	return TRUE;
}

DWORD WINAPI GetVersion() {
	return 6 | (3 << 8) | (9200 << 16);
}

HMODULE WINAPI GetModuleHandleA(const char* name) {
	auto* i = name ? modules::get_module_info(name) : main_module_info;
	if (!i) {
		log("module '%s' not found\n", name);
		SetLastError(ERROR_MOD_NOT_FOUND);
		return nullptr;
	}
	log("module '%s' is at %p\n", name, i->base);
	return i->base;
}

void* WINAPI GetProcAddress(HMODULE hm, const char* name) {
	auto* i = hm ? modules::get_module_info(hm) : main_module_info;
	if (!i) {
		SetLastError(ERROR_MOD_NOT_FOUND);
		log("GetProcAddress: module %p not found\n", hm);
		return nullptr;
	}
	bool is_ordinal = (uintptr_t)name < 0x10000;
	DWORD ordinal = (uintptr_t)name & 0xffff;
	std::string override_name;
	if (is_ordinal) override_name = format("%s:ordinal %d", i->lcase_name_no_ext, ordinal);
	else override_name = format("%s:%s", i->lcase_name_no_ext, name);
	void* r = get_implemented_function(override_name);
	if (!r) r = get_unimplemented_stub(override_name);
	log("GetProcAddress: %p::%s (%s) -> %p\n", hm, name, override_name, r);
	if (!r) {
		SetLastError(ERROR_PROC_NOT_FOUND);
	}
	return r;
}

HMODULE WINAPI LoadLibraryA(const char* name) {
	auto* i = modules::load_library(name, false);
	if (!i) {
		SetLastError(ERROR_FILE_NOT_FOUND);
		return nullptr;
	}
	log("LoadLibrary %s -> %p\n", name, i->base);
	return i->base;
}


template<typename T, size_t list_size>
class id_list {
	std::array<std::atomic<T>, list_size> list {};
	// Just a hint, might be momentarily inaccurate.
	std::atomic<size_t> n_available { list_size };
	// Also just a hint to make searching faster.
	std::atomic<size_t> next { 0 };
	static const size_t npos = (size_t)-1;
public:
	size_t allocate(T value) {
		if (!value) fatal_error("id_list: allocate null value");
		for (size_t i = next.load(std::memory_order_relaxed);; ++i) {
			if (i >= list.size()) i = 0;
			if (n_available.load(std::memory_order_relaxed) == 0) return npos;
			auto& ref = list[i];
			auto val = ref.load(std::memory_order_relaxed);
			if (val) continue;
			if (!ref.compare_exchange_weak(val, value, std::memory_order_relaxed)) continue;
			next.store(i + 1, std::memory_order_relaxed);
			n_available.fetch_sub(1, std::memory_order_relaxed);
			return i;
		}
	}
	T get(size_t index) {
		return list[index].load(std::memory_order_consume);
	}
	void deallocate(size_t index) {
		n_available.fetch_add(1, std::memory_order_relaxed);
		list[index].store(nullptr, std::memory_order_relaxed);
	}
	bool deallocate_if_equal(size_t index, T compare_value) {
		auto old_val = n_available.fetch_add(1, std::memory_order_relaxed);
		if (replace_if_equal(index, compare_value, nullptr)) {
			if (old_val == 0) next.store(index, std::memory_order_relaxed);
			return true;
		} else {
			n_available.fetch_sub(1, std::memory_order_relaxed);
			return false;
		}
	}
	bool replace_if_equal(size_t index, T compare_value, T new_value) {
		if (list[index].compare_exchange_weak(compare_value, new_value, std::memory_order_relaxed)) {
			return true;
		} else {
			return false;
		}
	}
	constexpr size_t size() const {
		return list_size;
	}
};
static const size_t npos = (size_t)-1;

struct object {
	enum { t_invalid, t_thread, t_event, t_file };
	virtual ~object() {}
	int object_type = t_invalid;
	std::atomic<size_t> refcount { 0 };
};

template<typename T>
struct handle {
	HANDLE h = nullptr;
	T* ptr = nullptr;
	constexpr handle(std::nullptr_t) : ptr(nullptr) {}
	explicit handle(HANDLE h, T* ptr) : h(h), ptr(ptr) {}
	handle(const handle& n) = delete;
	handle(handle&& n) {
		h = n.h;
		ptr = n.ptr;
		n.ptr = nullptr;
		n.h = nullptr;
	}
	~handle() {
		if (ptr) {
			deref_HANDLE(h);
// 			if (ptr->refcount.fetch_sub(1, std::memory_order_release) == 1) {
// 				if (delete_HANDLE(h, ptr)) {
// 					delete_object(ptr);
// 				}
// 			} else delete_HANDLE(h, ptr);
		}
	}
	handle& operator=(const handle& n) = delete;
	handle& operator=(handle&& n) {
		std::swap(h, n.h);
		std::swap(ptr, n.ptr);
	}
	T& operator*() const {
		return *ptr;
	}
	T* operator->() const {
		return ptr;
	}
	T* get() const {
		return ptr;
	}
	explicit operator bool() const {
		return ptr != nullptr;
	}
	HANDLE release_HANDLE() {
		HANDLE r = h;
		h = nullptr;
		ptr = nullptr;
		return r;
	}
};

constexpr size_t handles_per_container = 2;

struct handle_container {
	size_t base = 0;
	std::atomic<handle_container*> next { nullptr };
	id_list<object*, handles_per_container> list;
	std::array<std::atomic<size_t>, handles_per_container> refcounts {};
};

handle_container root_handle_container;
std::mutex create_handle_container_mut;
std::atomic<handle_container*> next_handle_container = &root_handle_container;
std::atomic<size_t> total_allocated_handles;

HANDLE handle_n_to_HANDLE(size_t n) {
	return (void*)((uintptr_t)(1 + n) << 2);
}

size_t HANDLE_to_handle_n(HANDLE h) {
	return (size_t)(((uintptr_t)h >> 2) - 1);
}

std::pair<handle_container*, size_t> container_and_index_for_HANDLE(HANDLE h) {
	size_t n = HANDLE_to_handle_n(h);
	size_t container_n = n / handles_per_container;
	handle_container* c = &root_handle_container;
	for (; container_n; --container_n) {
		c = c->next.load(std::memory_order_relaxed);
		if (!c) return { nullptr, 0 };
	}
	size_t index = n % handles_per_container;
	return { c, index };
}

template<typename T>
HANDLE new_HANDLE(T* obj) {
	if (total_allocated_handles.load(std::memory_order_relaxed) >= 16 * 1024 * 1024) return nullptr;
	HANDLE r;
	auto find = [&](handle_container* from, handle_container* to) {
		for (auto* i = from; i != to; i = i->next.load(std::memory_order_consume)) {
			size_t n = i->list.allocate(obj);
			if (n != npos) {
				next_handle_container.store(i, std::memory_order_relaxed);
				if (i->refcounts[n].load(std::memory_order_relaxed)) fatal_error("new_HANDLE: refcount is non-zero");
				i->refcounts[n].store(1, std::memory_order_relaxed);
				r = handle_n_to_HANDLE(i->base + n);
				log("created new handle %p\n", r);
				return true;
			}
		}
		return false;
	};
	auto* next = next_handle_container.load(std::memory_order_relaxed);
	if (find(next, nullptr)) return r;
	if (find(&root_handle_container, next)) return r;
	std::lock_guard<std::mutex> l(create_handle_container_mut);
	if (find(&root_handle_container, nullptr)) return r;
	size_t base = 0;
	handle_container* last_container = nullptr;
	for (auto* i = &root_handle_container; i; i = i->next) {
		base += handles_per_container;
		last_container = i;
	}
	handle_container* new_container = new handle_container();
	new_container->base = base;
	last_container->next.store(new_container, std::memory_order_relaxed);
	if (find(new_container, nullptr)) return r;
	fatal_error("unreachable: failed to allocate handle from newly created container");
	return nullptr;
}

void delete_object(object* o);

void deref_handle(handle_container* c, size_t index) {
	if (c->refcounts[index].fetch_sub(1, std::memory_order_relaxed) == 1) {
		c->list.deallocate(index);
		auto* o = c->list.get(index);
		if (o->refcount.fetch_sub(1, std::memory_order_release) == 1) {
			delete_object(o);
		}
	}
}

void deref_HANDLE(HANDLE h) {
	handle_container* c;
	size_t index;
	std::tie(c, index) = container_and_index_for_HANDLE(h);
	if (!c) fatal_error("release_HANDLE: no container for HANDLE %p\n", (void*)h);
	deref_handle(c, index);
}


template<typename T>
handle<T> duplicate_handle(const handle<T>& o) {
	HANDLE h = new_HANDLE(&*o);
	if (!h) return nullptr;
	return handle<T>(h, &*o);
}

template<typename T>
handle<T> new_object() {
	auto o = std::make_unique<T>();
	o->object_type = T::static_type;
	o->refcount.fetch_add(1, std::memory_order_relaxed);
	std::atomic_thread_fence(std::memory_order_release);
	HANDLE h = new_HANDLE(&*o);
	if (!h) return nullptr;
	log("new object %s handle %p\n", typeid(*o).name(), (void*)h);
	return handle<T>(h, o.release());
}

void delete_object(object* o) {
	log("delete object %s\n", typeid(*o).name());
	std::atomic_thread_fence(std::memory_order_acquire);
	delete o;
}

template<typename T>
bool object_is(object* o) {
	return o->object_type == T::static_type;
}
template<>
bool object_is<object>(object* o) {
	return true;
}

template<typename T>
handle<T> get_object(HANDLE h) {
	handle_container* c;
	size_t index;
	std::tie(c, index) = container_and_index_for_HANDLE(h);
	if (!c) {
		log("get_object<%s> handle out of bounds\n", typeid(T).name());
		return nullptr;
	}

	auto& ref = c->refcounts[index];
	auto val = ref.load(std::memory_order_relaxed);
	while (true) {
		if (val == 0) {
			log("get_object<%s> handle dead\n", typeid(T).name());
			return nullptr;
		}
		if (ref.compare_exchange_weak(val, val + 1, std::memory_order_relaxed)) break;
	}
	auto o = c->list.get(index);
	if (!object_is<T>(o)) {
		log("get_object<%s> wrong object type\n", typeid(T).name());
		deref_HANDLE(h);
		return nullptr;
	}
	log("get_object<%s> success\n", typeid(T).name());
	return handle<T>(h, (T*)o);
}

struct heap {
	DWORD flags;
	size_t initial_size;
	size_t max_size;
};
std::list<heap> all_heaps;
std::mutex heap_mut;

struct alignas(int64_t) heap_block_header {
	size_t size;
};

HANDLE WINAPI HeapCreate(DWORD flags, size_t initial_size, size_t max_size) {
	std::lock_guard<std::mutex> l(heap_mut);
	all_heaps.push_back({ flags,initial_size,max_size });
	//log("HeapCreate %x %d %d\n", flags, initial_size, max_size);
	return &all_heaps.back();
}

void* WINAPI HeapAlloc(HANDLE hHeap, DWORD flags, size_t size) {
	heap_block_header* h = (heap_block_header*)malloc(sizeof(heap_block_header) + size);
	if (flags & 8) memset(h, 0, sizeof(heap_block_header) + size);
	h->size = size;
	//log("HeapAlloc -> %p\n", h + 1);
	return h + 1;
}

BOOL WINAPI HeapFree(HANDLE hHeap, DWORD flags, void* ptr) {
	heap_block_header* h = (heap_block_header*)ptr - 1;
	free(h);
	return TRUE;
}

SIZE_T WINAPI HeapSize(HANDLE hHeap, DWORD flags, void* ptr) {
	heap_block_header* h = (heap_block_header*)ptr - 1;
	return h->size;
}


void WINAPI InitializeCriticalSection(CRITICAL_SECTION* cs) {
	cs->DebugInfo = nullptr;
	cs->LockCount = -1;
	cs->RecursionCount = 0;
	cs->OwningThread = nullptr;
	cs->LockSemaphore = new std::recursive_mutex();
	cs->SpinCount = 0;
}

 void WINAPI InitializeCriticalSectionAndSpinCount(CRITICAL_SECTION* cs, DWORD SpinCount) {
	cs->DebugInfo = nullptr;
	cs->LockCount = -1;
	cs->RecursionCount = 0;
	cs->OwningThread = nullptr;
	cs->LockSemaphore = new std::recursive_mutex();;
	cs->SpinCount = SpinCount;
}

void WINAPI DeleteCriticalSection(CRITICAL_SECTION* cs) {
	cs->DebugInfo = nullptr;
	cs->LockCount = 0;
	cs->RecursionCount = 0;
	cs->OwningThread = nullptr;
	delete (std::recursive_mutex*)cs->LockSemaphore;
	cs->LockSemaphore = nullptr;
	cs->SpinCount = 0;
}

void WINAPI EnterCriticalSection(CRITICAL_SECTION* cs) {
	((std::recursive_mutex*)cs->LockSemaphore)->lock();
}
void WINAPI LeaveCriticalSection(CRITICAL_SECTION* cs) {
	((std::recursive_mutex*)cs->LockSemaphore)->unlock();
}

struct local_storage {
	struct index {
		std::atomic<bool> busy { false };
		void* data;
		void* callback;
	};
	std::vector<index> ls = std::vector<index>(1088);
	std::atomic<size_t> next_index;

	index& operator[](size_t index) {
		return ls[index];
	}

	size_t get_next_index() {
		size_t index = next_index;
		if (index >= ls.size()) {
			return 0xffffffff;
		}
		while (!next_index.compare_exchange_weak(index, index + 1, std::memory_order_relaxed, std::memory_order_relaxed)) {
			index = next_index;
			if (index >= ls.size()) {
				return 0xffffffff;
			}
		}
		return index;
	}

	size_t get_free_index() {
		auto take = [&](size_t index) {
			bool was_busy = ls[index].busy;
			if (!was_busy) {
				while (!ls[index].busy.compare_exchange_weak(was_busy, true)) {
					was_busy = ls[index].busy;
					if (was_busy) return false;
				}
				return true;
			}
			return false;
		};
		size_t index = get_next_index();
		while (index < ls.size()) {
			if (take(index)) return index;
			index = get_next_index();
		}
		for (index = 0; index != ls.size(); ++index) {
			if (take(index)) return index;
		}
		return 0xffffffff;
	}
};

local_storage fls;

DWORD WINAPI FlsAlloc(void* callback) {
	size_t index = fls.get_free_index();
	if (index == 0xffffffff) return 0xffffffff;
	fls[index].callback = callback;
	fls[index].data = nullptr;
	//log("FlsAlloc -> %d\n", index);
	return index;
}

BOOL WINAPI FlsFree(DWORD index) {
	if (index >= fls.next_index || !fls[index].busy) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	fls[index].busy = false;
	return TRUE;
}

BOOL WINAPI FlsSetValue(DWORD index, void* data) {
	if (index >= fls.next_index || !fls[index].busy) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	fls[index].data = data;
	//log("FlsSetValue %d -> %p\n", index, data);
	return TRUE;
}

void* WINAPI FlsGetValue(DWORD index) {
	if (index >= fls.next_index || !fls[index].busy) {
		SetLastError(ERROR_INVALID_PARAMETER);
		//log("FlsGetValue failed\n");
		return nullptr;
	}
	//log("FlsGetValue %d -> %p\n", index, fls[index].data);
	return fls[index].data;
}

DWORD WINAPI GetModuleFileNameA(HMODULE hm, char* dst, DWORD size) {
	auto* i = hm ? modules::get_module_info(hm) : main_module_info;
	if (!i) {
		log("GetModuleFileName %p module not found\n", (void*)hm);
		SetLastError(ERROR_MOD_NOT_FOUND);
		return 0;
	}
	auto& module_filename = i->full_path;
	if (size < module_filename.size() + 1) {
		if (size) {
			memcpy(dst, module_filename.data(), size - 1);
			dst[size - 1] = 0;
		}
		log("GetModuleFileName insufficient buffer\n");
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return size;
	} else {
		memcpy(dst, module_filename.data(), module_filename.size());
		dst[module_filename.size()] = 0;
		log("GetModuleFileName %p -> '%s'\n", hm, dst);
		SetLastError(ERROR_SUCCESS);
		return module_filename.size();
	}
}

DWORD WINAPI GetCurrentThreadId() {
	return tlb.thread_id;
}

void WINAPI GetStartupInfoA(STARTUPINFOA* i) {
	memset(i, 0, sizeof(*i));
	i->cb = sizeof(STARTUPINFOA);
}

struct file : object {
	static const auto static_type = object::t_file;
	DWORD access = 0;
	FILE_TYPE file_type = FILE_TYPE_UNKNOWN;

	std::function<uint64_t(uint64_t offset, MOVE_METHOD method)> set_pos;
	std::function<uint64_t()> get_pos;
	std::function<bool(void* buffer, size_t to_read, size_t* read)> read;
};

handle<file> new_console_handle(bool input, bool output) {
	auto o = new_object<file>();
	if (o) {
		if (input) o->access |= GENERIC_READ;
		if (output) o->access |= GENERIC_WRITE;
	}
	o->file_type = FILE_TYPE_CHAR;
	return o;
}

HANDLE std_input_handle;
HANDLE std_output_handle;
HANDLE std_error_handle;

HANDLE WINAPI GetStdHandle(DWORD n) {
	if (n == (DWORD)-10) return std_input_handle;
	if (n == (DWORD)-11) return std_output_handle;
	if (n == (DWORD)-12) return std_error_handle;
	SetLastError(ERROR_INVALID_PARAMETER);
	return INVALID_HANDLE_VALUE;
}

DWORD WINAPI GetFileType(HANDLE h) {
	auto o = get_object<file>(h);
	if (!o) {
		SetLastError(ERROR_INVALID_HANDLE);
		return FILE_TYPE_UNKNOWN;
	}
	log("GetFileType %p -> %d\n", (void*)h, (DWORD)o->file_type);
	SetLastError(ERROR_SUCCESS);
	return o->file_type;
}

UINT WINAPI SetHandleCount(UINT n) {
	return n;
}

struct page_attributes {
	DWORD protect = 0;
	DWORD state = 0;
};

struct virtual_region {
	void* base;
	size_t size;
	std::vector<page_attributes> pages;
	DWORD allocation_protect;
};
std::map<void*, virtual_region> virtual_regions;
std::mutex virtual_mut;
size_t vm_total_allocated = 0;

void add_virtual_region_nolock(void* addr, size_t size, DWORD state, PAGE_PROTECT protect) {
	if ((uintptr_t)addr & 0xfff) fatal_error("attempt to add virtual region not on page boundary");
	size = (size + 0xfff) & ~0xfff;
	log("add virtual region [%p, %p)\n", addr, (char*)addr + size);
	auto i = virtual_regions.lower_bound(addr);
	if (i != virtual_regions.begin()) {
		auto pi = i;
		--pi;
		auto* pr = &pi->second;
		if ((char*)pr->base + pr->size > addr) fatal_error("attempt to add an already mapped virtual region");
	}
	if (i != virtual_regions.end()) {
		auto* nr = &i->second;
		if ((char*)addr + size > nr->base) fatal_error("attempt to add an already mapped virtual region");
	}
	size_t pages = size / 0x1000;
	auto it = virtual_regions.emplace(addr, virtual_region { addr, size, std::vector<page_attributes>(pages), protect });
	for (auto& v : it.first->second.pages) {
		v.protect = protect;
		v.state = state;
	}
	vm_total_allocated += size;
	//log("added virtual region [%p, %p)\n", addr, (char*)addr + size);
}

void add_virtual_region(void* addr, size_t size, MEM_STATE state, PAGE_PROTECT protect) {
	std::lock_guard<std::mutex> l(virtual_mut);
	add_virtual_region_nolock(addr, size, state, protect);
}

void remove_virtual_region_nolock(void* addr) {
	auto i = virtual_regions.find(addr);
	vm_total_allocated -= i->second.size;
	virtual_regions.erase(i);
}

void remove_virtual_region(void* addr) {
	std::lock_guard<std::mutex> l(virtual_mut);
	remove_virtual_region_nolock(addr);
}

virtual_region* find_virtual_region(void* addr) {
	auto i = virtual_regions.upper_bound(addr);
	if (i == virtual_regions.begin()) return nullptr;
	--i;
	auto* r = &i->second;
	if ((char*)r->base + r->size <= addr) return nullptr;
	return r;
}

native_api::memory_access access_from_protect(PAGE_PROTECT protect) {
	if (protect & PAGE_READONLY) return native_api::memory_access::read;
	else if (protect & PAGE_READWRITE) return native_api::memory_access::read_write;
	else if (protect & PAGE_EXECUTE) return native_api::memory_access::read_execute;
	else if (protect & PAGE_EXECUTE_READ) return native_api::memory_access::read_execute;
	else if (protect & PAGE_EXECUTE_READWRITE) return native_api::memory_access::read_write_execute;
	return native_api::memory_access::none;
}

const uintptr_t vm_begin_addr = (uintptr_t)64 * 1024 * 1024;
const uintptr_t vm_end_addr = (uintptr_t)2048 * 1024 * 1024;
const uintptr_t vm_search_granularity = (uintptr_t)1024 * 1024;
const uintptr_t vm_allocation_granularity = (uintptr_t)64 * 1024;

uintptr_t next_addr = vm_begin_addr;

void* virtual_allocate_nolock(void* addr, size_t size, MEM_STATE allocation_type, PAGE_PROTECT protect, void* preferred_addr) {
	native_api::allocated_memory mem;
	native_api::memory_access access = native_api::memory_access::none;
	if (allocation_type == MEM_COMMIT) {
		access = access_from_protect(protect);
	} else if (allocation_type == MEM_RESERVE) {
		protect = PAGE_NOACCESS;
		access = access_from_protect(protect);
	} else {
		fatal_error("virtual_allocate_nolock: invalid allocation_type %#x\n", allocation_type);
	}
	size = (size + 0xfff) & ~0xfff;
	if (addr) {
		mem.allocate(addr, size, access);
	} else {
		auto next_allocation_granularity = [&](uintptr_t ptr) {
			return (ptr + vm_allocation_granularity - 1) & ~(vm_allocation_granularity - 1);
		};
		auto trymap = [&](uintptr_t begin, uintptr_t end) {
			log("trying to map in range [%p, %p)\n", (void*)begin, (void*)end);
			begin = next_allocation_granularity(begin);
			mem.allocate((void*)begin, size, access);
			if (mem) return true;
			auto next = next_allocation_granularity(begin + size);
			if (next != begin) {
				mem.allocate((void*)next, size, access);
				if (mem) return true;
			}
			next += vm_allocation_granularity;
			for (uintptr_t i = (begin + size + vm_search_granularity - 1)&~(vm_search_granularity - 1); i < end; i += vm_search_granularity) {
				mem.allocate((void*)i, size, access);
				if (mem) return true;
			}
			return false;
		};
		auto search = [&](uintptr_t begin, uintptr_t end) {
			log("search %p %p\n", (void*)begin, (void*)end);
			auto i = virtual_regions.upper_bound((void*)begin);
			if (i != virtual_regions.begin()) {
				--i;
				uintptr_t ie = (uintptr_t)i->first + i->second.size;
				if (ie > begin) begin = ie;
				++i;
			}
			uintptr_t taddr = begin;
			while (i != virtual_regions.end()) {
				uintptr_t ib = (uintptr_t)i->first;
				if (taddr + size <= ib && trymap(taddr, ib)) {
					return;
				}
				taddr = ib + i->second.size;
				++i;
			}
			trymap(taddr, end);
		};
		if (preferred_addr) {
			search((uintptr_t)preferred_addr, vm_end_addr);
			if (!mem) search(vm_begin_addr, (uintptr_t)preferred_addr);
		} else {
			search(next_addr, vm_end_addr);
			if (!mem) search(vm_begin_addr, next_addr);
			if (mem) next_addr = (uintptr_t)mem.ptr + size;
		}
		//fatal_error("stop");
	}
	if (!mem) return nullptr;
	void* ptr = mem.detach();
	add_virtual_region_nolock(ptr, size, allocation_type, protect);
	log("virtual allocate -> %p\n", ptr);
// 	log("virtual regions -\n");
// 	for (auto& v : virtual_regions) {
// 		log(" [%p, %p)\n", v.second.base, (uint8_t*)v.second.base + v.second.size);
// 	}
	return ptr;
}
void virtual_deallocate_nolock(virtual_region* r) {
	native_api::allocated_memory mem(r->base, r->size);
	log("released [%p, %p)\n", r->base, (uint8_t*)r->base + r->size);
	remove_virtual_region_nolock(r->base);
}

void* virtual_allocate(void* addr, size_t size, MEM_STATE allocation_type, PAGE_PROTECT protect, void* preferred_addr) {
	std::lock_guard<std::mutex> l(virtual_mut);
	return virtual_allocate_nolock(addr, size, allocation_type, protect, preferred_addr);
}
void virtual_deallocate(void* addr) {
	std::lock_guard<std::mutex> l(virtual_mut);
	auto* r = find_virtual_region(addr);
	if (!r) fatal_error("attempt to free non-existing virtual region at %p\n", addr);
	return virtual_deallocate_nolock(r);
}

void virtual_protect_nolock(virtual_region* r, size_t page_begin, size_t page_end, PAGE_PROTECT protect) {
	auto access = access_from_protect(protect);
	for (size_t p = page_begin; p != page_end; ++p) {
		if (r->pages[p].state == MEM_COMMIT && ~r->pages[p].protect != protect) {
			native_api::set_memory_access((uint8_t*)r->base + p * 0x1000, 0x1000, access);
			r->pages[p].protect = protect;
		}
	}
}

void virtual_protect(void* addr, size_t size, PAGE_PROTECT protect) {
	auto* r = find_virtual_region(addr);
	if (!r) fatal_error("virtual_protect: no region at %p", addr);
	uintptr_t offset = ((uintptr_t)addr - (uintptr_t)r->base) & ~0xfff;
	size_t page = offset / 0x1000;
	size_t pages = (size + 0xfff) / 0x1000;
	virtual_protect_nolock(r, page, page + pages, protect);
}

SIZE_T WINAPI VirtualQuery(void* addr, MEMORY_BASIC_INFORMATION* buffer, size_t buffer_size) {
	log("VirtualQuery %p\n", addr);
	std::lock_guard<std::mutex> l(virtual_mut);
	auto* r = find_virtual_region(addr);
	if (buffer_size < sizeof(MEMORY_BASIC_INFORMATION)) {
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}
	uintptr_t offset = ((uintptr_t)addr - (uintptr_t)r->base) & ~0xfff;
	size_t page = offset / 0x1000;
	buffer->BaseAddress = (uint8_t*)r->base + offset;
	buffer->AllocationBase = r->base;
	buffer->AllocationProtect = r->allocation_protect;
	buffer->RegionSize = 0x1000;
	buffer->State = r->pages[page].state;
	buffer->Protect = r->pages[page].protect;
	buffer->Type = 0x20000;
	return sizeof(*buffer);
}

void* WINAPI VirtualAlloc(void* addr, SIZE_T size, DWORD allocation_type, PAGE_PROTECT protect) {
	log("VirtualAlloc %p size %#x, type %#08x protect %#08x\n", addr, size, allocation_type, (DWORD)protect);
	if (protect == 0) {
		SetLastError(ERROR_INVALID_PARAMETER);
		log("VirtualAlloc failed (invalid parameter)\n");
		return nullptr;
	}
	std::lock_guard<std::mutex> l(virtual_mut);
	if (addr) {
		auto* r = find_virtual_region(addr);
		if (!r) {
			SetLastError(ERROR_INVALID_ADDRESS);
			log("VirtualAlloc failed (invalid address)\n");
			return nullptr;
		}
		if (allocation_type & MEM_COMMIT) {
			uintptr_t offset = ((uintptr_t)addr - (uintptr_t)r->base) & ~0xfff;
			size_t page = offset / 0x1000;
			size_t pages = (size + 0xfff) / 0x1000;
			if (pages < pages || pages > r->pages.size()) {
				SetLastError(ERROR_INVALID_ADDRESS);
				log("VirtualAlloc failed (invalid address)\n");
				return nullptr;
			}
			auto access = access_from_protect(protect);
			for (size_t i = 0; i != pages; ++i) {
				size_t p = page + i;

				if (r->pages[p].state == MEM_RESERVE) {
					native_api::set_memory_access((uint8_t*)r->base + p * 0x1000, 0x1000, access);
					r->pages[p].state = MEM_COMMIT;
					r->pages[p].protect = protect;
					log("committed a page\n");
				}
			}
		} else if (allocation_type & MEM_RESERVE) {
			SetLastError(ERROR_NOT_SUPPORTED);
			log("VirtualAlloc failed (reserve specific address; not supported)\n");
			return nullptr;
		} else {
			SetLastError(ERROR_INVALID_PARAMETER);
			log("VirtualAlloc failed (invalid parameter)\n");
			return nullptr;
		}
		return r->base;
	}
	MEM_STATE state;
	if (allocation_type & MEM_COMMIT) {
		state = MEM_COMMIT;
	} else if (allocation_type & MEM_RESERVE) {
		state = MEM_RESERVE;
	} else {
		SetLastError(ERROR_INVALID_PARAMETER);
		log("VirtualAlloc failed\n");
		return nullptr;
	}
	void* ptr = virtual_allocate_nolock(addr, size, state, protect, nullptr);
	if (!ptr) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		log("VirtualAlloc failed\n");
		return nullptr;
	}
	return ptr;
}

BOOL WINAPI VirtualFree(void* addr, SIZE_T size, FREE_TYPE free_type) {
	std::lock_guard<std::mutex> l(virtual_mut);
	auto* r = find_virtual_region(addr);
	if (!r) {
		SetLastError(ERROR_INVALID_ADDRESS);
		return FALSE;
	}
	uintptr_t offset = ((uintptr_t)addr - (uintptr_t)r->base) & ~0xfff;
	size_t page = offset / 0x1000;
	size_t pages = (size + 0xfff) / 0x1000;
	if (free_type == MEM_DECOMMIT) {
		for (size_t i = 0; i != pages; ++i) {
			size_t p = page + i;
			if (r->pages[p].state == MEM_COMMIT) {
				native_api::set_memory_access((uint8_t*)r->base + p * 0x1000, 0x1000, native_api::memory_access::none);
				r->pages[p].state = MEM_RESERVE;
				r->pages[p].protect = PAGE_NOACCESS;
				log("decommitted a page\n");
			}
		}
		return TRUE;
	} else if (free_type == MEM_RELEASE) {
		if (size || addr != r->base) {
			SetLastError(ERROR_INVALID_PARAMETER);
			return FALSE;
		}
		virtual_deallocate_nolock(r);
		return TRUE;
	} else {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
}

LONG WINAPI UnhandledExceptionFilter(EXCEPTION_POINTERS* info) {
	fatal_error("unhandled exception %#x at %p\n", info->ExceptionRecord->ExceptionCode, info->ExceptionRecord->ExceptionAddress);
	return 0;
}

void* WINAPI SetUnhandledExceptionFilter(void* func) {
	return nullptr;
}

std::string cmdline;

const char* WINAPI GetCommandLineA() {
	return cmdline.c_str();
}

const int16_t env_strings[] = { 0, 0 };

const int16_t* WINAPI GetEnvironmentStringsW() {
	return env_strings;
}

int WINAPI WideCharToMultiByte(UINT code_page, DWORD flags, int16_t* widestr, int widelen, char* outstr, int outlen, const char* default_char, BOOL* used_default_char) {
	if (used_default_char) *used_default_char = FALSE;
	if (widelen == -1) {
		widelen = 0;
		for (int16_t* p = widestr; *p; ++p, ++widelen);
	}
	if (outlen == 0) return widelen;
	for (int i = 0; i < widelen; ++i) {
		if (outlen <= i) return i;
		outstr[i] = (char)widestr[i];
	}
	return widelen;
}

BOOL WINAPI FreeEnvironmentStringsW(int16_t*) {
	return TRUE;
}

UINT WINAPI GetACP() {
	return 65001;
}

BOOL WINAPI GetCPInfo(UINT code_page, CPINFO* info) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
}

BOOL WINAPI IsProcessorFeaturePresent(DWORD feature) {
	if (feature != 0) fatal_error("check for processor feature %d", feature);
	return FALSE;
}

template<typename T>
uint64_t time_point_to_FILETIME(T time) {
	auto c = std::chrono::duration_cast<std::chrono::duration<uint64_t, std::ratio<1, 10000000>>>((time - T::clock::from_time_t(0)));
	return c.count() + 116444736000000000;
}

void WINAPI GetSystemTimeAsFileTime(uint64_t* out) {
	*out = time_point_to_FILETIME(std::chrono::system_clock::now());
}

DWORD WINAPI GetCurrentProcessId() {
	return 1;
}

std::chrono::high_resolution_clock clock;
auto start_time = clock.now();

DWORD WINAPI GetTickCount() {
	return std::chrono::duration_cast<std::chrono::duration<DWORD, std::ratio<1, 1000>>>(clock.now() - start_time).count();
}

BOOL WINAPI QueryPerformanceCounter(uint64_t* count) {
	*count = (uint64_t)(clock.now() - start_time).count();
	return TRUE;
}

struct event: object {
	static const auto static_type = object::t_event;
	bool manual_reset = false;
	std::atomic<int> state { false };
	std::mutex wait_mut;
	std::condition_variable wait_cv;
};


HANDLE WINAPI CreateEventA(void* security_attributes, BOOL manual_reset, BOOL initial_state, const char* name) {
	auto e = new_object<event>();
	if (!e) {
		SetLastError(ERROR_NO_SYSTEM_RESOURCES);
		return nullptr;
	}
	e->manual_reset = manual_reset != FALSE;
	e->state = initial_state;
	log("CreateEventA '%s' %d %d -> %p\n", name, (int)manual_reset, (int)initial_state, (void*)e.h);
	std::atomic_thread_fence(std::memory_order_release);
	return e.release_HANDLE();
}

struct thread: object {
	static const auto static_type = object::t_thread;
	DWORD id = 0;
	std::thread thread_obj;
	bool running = true;
	DWORD exit_code = 259;
};
id_list<thread*, 0xffff> all_threads;

handle<thread> new_thread() {
	auto t = new_object<thread>();
	if (!t) return nullptr;
	auto id = all_threads.allocate(&*t);
	if (id == npos) return nullptr;
	t->id = 1 + id;
	return t;
}

HANDLE default_process_heap = nullptr;

void initialize_things() {
	std_input_handle = new_console_handle(true, false).release_HANDLE();
	std_output_handle = new_console_handle(false, true).release_HANDLE();
	std_error_handle = new_console_handle(false, true).release_HANDLE();

	default_process_heap = HeapCreate(0, 0, 0);
	if (!default_process_heap) fatal_error("failed to create default process heap");
}

void enter_main_thread(const std::function<void()>& f) {

	initialize_things();

	auto t = new_thread();
	if (!t) fatal_error("failed to create main thread");
	tlb.thread_id = t->id;
	tlb.current_thread = &*t;
	log("main thread id is %d\n", GetCurrentThreadId());
	f();
}

HANDLE WINAPI CreateThread(void* security_attributes, SIZE_T stack_size, void* start_address, void* parameter, DWORD creation_flags, DWORD* thread_id) {
	if (creation_flags & 4) {
		SetLastError(ERROR_NOT_SUPPORTED);
		log("CreateThread: CREATE_SUSPENDED is not supported");
		return nullptr;
	}
	auto t = new_thread();
	auto t2 = duplicate_handle(t);
	if (!t || !t2) {
		SetLastError(ERROR_NO_SYSTEM_RESOURCES);
		return nullptr;
	}
	log("created a new thread with id %d\n", t->id);
	t->thread_obj = std::thread([t = std::move(t2), start_address, parameter]() mutable {
		environment::enter_thread([t = std::move(t), start_address, parameter]() {
			tlb.thread_id = t->id;
			tlb.current_thread = &*t;
			log("thread running, yey\n");
			modules::call_thread_attach();
			log("calling thread entry point at %p\n", start_address);
			t->exit_code = ((DWORD(WINAPI*)(void*))start_address)(parameter);
			modules::call_thread_detach();
			t->running = false;
		});
	});
	if (thread_id) *thread_id = t->id;
	std::atomic_thread_fence(std::memory_order_release);
	return t.release_HANDLE();
}

BOOL WINAPI SetThreadPriority(HANDLE h, int priority) {
	SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}

void set_main_module(modules::module_info* i) {
	main_module_info = i;
}

void WINAPI GetSystemInfo(SYSTEM_INFO* info) {
	info->wProcessorArchitecture = 0;
	info->wReserved = 0;
	info->dwPageSize = 0x1000;
	info->lpMinimumApplicationAddress = (void*)0x10000;
	info->lpMaximumApplicationAddress = (void*)((uintptr_t)2048 * 1024 * 1024);
	info->dwActiveProcessorMask = 1;
	info->dwNumberOfProcessors = 1;
	info->dwProcessorType = 586;
	info->dwAllocationGranularity = vm_allocation_granularity;
	info->wProcessorLevel = 1;
	info->wProcessorRevision = 257;
}

BOOL WINAPI GetDiskFreeSpaceA(const char* root_path, DWORD* out_sectors_per_cluster, DWORD* out_bytes_per_sector, DWORD* out_free_clusters, DWORD* out_total_number_of_clusters) {
	return FALSE;
}

void WINAPI GlobalMemoryStatus(MEMORYSTATUS* status) {
	status->dwLength = sizeof(*status);
	status->dwMemoryLoad = 1;
	status->dwTotalPhys = 0xffffffff;
	status->dwAvailPhys = 0xffffffff;
	status->dwTotalPageFile = 0xffffffff;
	status->dwAvailPageFile = 0xffffffff;
	status->dwTotalVirtual = vm_end_addr - vm_begin_addr;
	status->dwAvailVirtual = (vm_end_addr - vm_begin_addr) - vm_total_allocated;
}

HANDLE WINAPI GetCurrentProcess() {
	return (HANDLE)-1;
}

BOOL WINAPI SetConsoleCtrlHandler(void* handler, BOOL add) {
	return TRUE;
}

DWORD WINAPI GetFileAttributesA(const char* filename) {
	log("GetFileAttributes for %s\n", filename);
	SetLastError(ERROR_NOT_SUPPORTED);
	return (DWORD)-1;
}

DWORD WINAPI GetFullPathNameA(const char* path, DWORD buflen, char* buf, char** filepart) {
	auto s = get_full_path(path);
	if (s.size() + 1 > buflen) {
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		log("GetFullPathName insufficient buffer\n");
		return s.size() + 1;
	}
	for (size_t i = 0; i < std::min(s.size() + 1, (size_t)buflen); ++i) {
		char c = s.data()[i];
		buf[i] = c;
		if (filepart && (c == '/' || c == '\\')) *filepart = &buf[i + 1];
	}
	log("GetFullPathName '%s' -> '%s' (filepart '%s')\n", path, buf, filepart ? *filepart : nullptr);
	return s.size();
}

UINT WINAPI GetDriveTypeA(const char* path_name) {
	log("GetDriveType '%s'\n", path_name);
	return 0;
}

BOOL WINAPI GetVolumeInformationA(const char* root_path, char* volume_name, DWORD volume_name_size, DWORD* serial_number, DWORD* max_component_length, DWORD* filesystem_flags, char* filesystem_name, DWORD filesystem_name_size) {
	SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}

native_api::file_set_pos_origin move_method_to_native_origin(MOVE_METHOD method) {
	if (method == FILE_BEGIN) return native_api::file_set_pos_origin::begin;
	if (method == FILE_CURRENT) return native_api::file_set_pos_origin::current;
	if (method == FILE_END) return native_api::file_set_pos_origin::end;
	return native_api::file_set_pos_origin::begin;
}

static const DWORD FILE_FLAG_OVERLAPPED = 0x40000000;

HANDLE WINAPI CreateFileA(const char* filename, DWORD access, DWORD share_mode, void* security_attributes, DWORD creation_disposition, DWORD flags_and_file_attributes, void* template_file) {
	log("CreateFile '%s' access %#x share %#x creation %#x\n", filename, access, share_mode, creation_disposition);

	if (flags_and_file_attributes & FILE_FLAG_OVERLAPPED) {
		log("CreateFile: overlapped IO not suppored\n");
		SetLastError(ERROR_NOT_SUPPORTED);
		return INVALID_HANDLE_VALUE;
	}

	auto s = path_to_native(filename);

	log("native path '%s'\n", s);

	native_api::file_access file_access;
	if ((access & GENERIC_WRITE) || (access & GENERIC_ALL)) file_access = native_api::file_access::read_write;
	else file_access = native_api::file_access::read;

	const DWORD CREATE_NEW = 1;
	const DWORD CREATE_ALWAYS = 2;
	const DWORD OPEN_EXISTING = 3;
	const DWORD OPEN_ALWAYS = 4;
	const DWORD TRUNCATE_EXISTING = 5;

	native_api::file_open_mode open_mode;
	if (creation_disposition == CREATE_NEW) open_mode = native_api::file_open_mode::create_new;
	else if (creation_disposition == CREATE_ALWAYS) {
		log("CreateFile: CREATE_ALWAYS not supported\n");
		SetLastError(ERROR_NOT_SUPPORTED);
		return INVALID_HANDLE_VALUE;
	} else if (creation_disposition == OPEN_EXISTING) open_mode = native_api::file_open_mode::open_existing;
	else if (creation_disposition == OPEN_ALWAYS) {
		log("CreateFile: OPEN_ALWAYS not supported\n");
		SetLastError(ERROR_NOT_SUPPORTED);
		return INVALID_HANDLE_VALUE;
	} else if (creation_disposition == TRUNCATE_EXISTING) {
		log("CreateFile: TRUNCATE_EXISTING not supported\n");
		SetLastError(ERROR_NOT_SUPPORTED);
		return INVALID_HANDLE_VALUE;
	} else {
		SetLastError(ERROR_INVALID_PARAMETER);
		return INVALID_HANDLE_VALUE;
	}

	auto o = new_object<file>();
	if (!o) {
		SetLastError(ERROR_NO_SYSTEM_RESOURCES);
		return INVALID_HANDLE_VALUE;
	}
	native_api::file_io file_io;
	if (!file_io.open(s.c_str(), file_access, open_mode)) {
		SetLastError(ERROR_FILE_NOT_FOUND);
		return INVALID_HANDLE_VALUE;
	}
	o->access = access;

	auto f = std::make_shared<native_api::file_io>(std::move(file_io));

	o->set_pos = [f](uint64_t pos, MOVE_METHOD method) {
		return f->set_pos(pos, move_method_to_native_origin(method));
	};
	o->get_pos = [f]() {
		return f->get_pos();
	};
	o->read = [f](void* buffer, size_t to_read, size_t* read) {
		bool r = f->read(buffer, to_read);
		*read = to_read;
		if (!r) {
			SetLastError(ERROR_READ_FAULT);
		}
		return r;
	};

	log("create file ok\n");
	std::atomic_thread_fence(std::memory_order_release);
	return o.release_HANDLE();
}

DWORD WINAPI SetFilePointer(HANDLE h, LONG move, LONG* move_high, MOVE_METHOD method) {
	log("SetFilePointer %p %d %p %d\n", (void*)h, move, move_high, (int)method);
	auto o = get_object<file>(h);
	if (!o) {
		SetLastError(ERROR_INVALID_HANDLE);
		return INVALID_SET_FILE_POINTER;
	}
	if (!o->set_pos) {
		log("SetFilePointer: no set_pos for object\n");
		SetLastError(ERROR_INVALID_HANDLE);
		return INVALID_SET_FILE_POINTER;
	}
	uint64_t pos;
	if (move_high) {
		pos = (ULONG)move;
		pos |= (uint64_t)move_high << 32;
	} else pos = move;
	SetLastError(ERROR_SUCCESS);
	return (DWORD)o->set_pos(pos, method);
}

BOOL WINAPI ReadFile(HANDLE h, void* buffer, DWORD to_read, DWORD* read, void* overlapped) {
	if (read) *read = 0;
	auto o = get_object<file>(h);
	if (!o) {
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	if (!o->read) {
		log("ReadFile: no read for object\n");
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	size_t n_read = 0;
	SetLastError(ERROR_SUCCESS);
	bool success = o->read(buffer, (size_t)to_read, &n_read);
	*read = (DWORD)n_read;
	log("ReadFile %p %p %d %p -> %d (%d read)\n", (void*)h, buffer, to_read, read, success, n_read);
	return success ? TRUE : FALSE;
}

LONG WINAPI InterlockedIncrement(LONG* value) {
	return native_api::interlocked_increment(value);
}

HANDLE WINAPI GetProcessHeap() {
	return default_process_heap;
}

HANDLE WINAPI FindFirstFileA(const char* filename, WIN32_FIND_DATAA* data) {
	log("find first file '%s'\n", filename);
	return nullptr;
}

enum WAIT_RETVAL : DWORD {
	WAIT_OBJECT_0 = 0,
	WAIT_ABANDONED = 0x80,
	WAIT_TIMEOUT = 0x102,
	WAIT_FAILED = 0xffffffff
};

WAIT_RETVAL WINAPI WaitForSingleObject(HANDLE h, DWORD milliseconds) {
	log("WaitForSingleObject %p %d\n", (void*)h, milliseconds);
	auto o = get_object<object>(h);
	if (!o) {
		SetLastError(ERROR_INVALID_HANDLE);
		return WAIT_FAILED;
	}
	if (o->object_type == object::t_event) {
		event* e = (event*)o.get();
		auto val = e->state.load(std::memory_order_relaxed);
		if (val) {
			if (e->state.compare_exchange_weak(val, true, std::memory_order_relaxed)) {
				return WAIT_OBJECT_0;
			}
		}
		auto t = tlb.current_thread;
		std::unique_lock<std::mutex> l(e->wait_mut);
		if (e->state.load(std::memory_order_relaxed)) return WAIT_OBJECT_0;
		log("thread %#x is waiting for event %p\n", t->id, (void*)h);
		auto pred = [e, t]() {
			auto val = e->state.load(std::memory_order_relaxed);
			if (!val) return false;
			if (e->manual_reset) return true;
			if (e->state.compare_exchange_weak(val, false, std::memory_order_relaxed)) return true;
			return false;
		};
		if (milliseconds == (DWORD)-1) {
			e->wait_cv.wait(l, pred);
		} else {
			e->wait_cv.wait_for(l, std::chrono::milliseconds(milliseconds), pred);
		}
		log("thread %#x woke up from waiting for event %p\n", t->id, (void*)h);
		return WAIT_OBJECT_0;
	} else {
		log("WaitForSingleObject: object_type %d not supported\n", (int)o->object_type);
		SetLastError(ERROR_NOT_SUPPORTED);
		return WAIT_FAILED;
	}
}

void WINAPI Sleep(DWORD milliseconds) {
	std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

BOOL WINAPI SetEvent(HANDLE h) {
	log("SetEvent %p\n", (void*)h);
	auto o = get_object<event>(h);
	if (!o) {
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	std::unique_lock<std::mutex> l(o->wait_mut);
	o->state.store(true, std::memory_order_relaxed);
	o->wait_cv.notify_all();
	return TRUE;
}

void CloseHandle(HANDLE h) {
	log("CloseHandle %p\n", (void*)h);
	auto o = get_object<object>(h);
	fatal_error("fixme close %s", typeid(*o).name());
}

register_funcs funcs({
	{ "kernel32:SetLastError", SetLastError },
	{ "kernel32:GetLastError", GetLastError },
	{ "kernel32:GetVersionExA", GetVersionExA },
	{ "kernel32:GetVersion", GetVersion },
	{ "kernel32:GetModuleHandleA", GetModuleHandleA },
	{ "kernel32:GetProcAddress", GetProcAddress },
	{ "kernel32:LoadLibraryA", LoadLibraryA },
	{ "kernel32:HeapCreate", HeapCreate },
	{ "kernel32:HeapAlloc", HeapAlloc },
	{ "kernel32:HeapFree", HeapFree },
	{ "kernel32:HeapSize", HeapSize },
	{ "kernel32:InitializeCriticalSection", InitializeCriticalSection },
	{ "kernel32:InitializeCriticalSectionAndSpinCount", InitializeCriticalSectionAndSpinCount },
	{ "kernel32:DeleteCriticalSection", DeleteCriticalSection },
	{ "kernel32:EnterCriticalSection", EnterCriticalSection },
	{ "kernel32:LeaveCriticalSection", LeaveCriticalSection },
	{ "kernel32:FlsAlloc", FlsAlloc},
	{ "kernel32:FlsFree", FlsFree },
	{ "kernel32:FlsSetValue", FlsSetValue },
	{ "kernel32:FlsGetValue", FlsGetValue },
	{ "kernel32:GetModuleFileNameA", GetModuleFileNameA },
	{ "kernel32:GetCurrentThreadId", GetCurrentThreadId },
	{ "kernel32:GetStartupInfoA", GetStartupInfoA },
	{ "kernel32:GetStdHandle", GetStdHandle },
	{ "kernel32:GetFileType", GetFileType },
	{ "kernel32:SetHandleCount", SetHandleCount },
	{ "kernel32:VirtualQuery", VirtualQuery },
	{ "kernel32:VirtualAlloc", VirtualAlloc },
	{ "kernel32:VirtualFree", VirtualFree },
	{ "kernel32:UnhandledExceptionFilter", UnhandledExceptionFilter },
	{ "kernel32:SetUnhandledExceptionFilter", SetUnhandledExceptionFilter },
	{ "kernel32:GetCommandLineA", GetCommandLineA },
	{ "kernel32:GetEnvironmentStringsW", GetEnvironmentStringsW },
	{ "kernel32:FreeEnvironmentStringsW", FreeEnvironmentStringsW },
	{ "kernel32:WideCharToMultiByte", WideCharToMultiByte },
	{ "kernel32:GetACP", GetACP },
	{ "kernel32:GetCPInfo", GetCPInfo },
	{ "kernel32:IsProcessorFeaturePresent", IsProcessorFeaturePresent },
	{ "kernel32:GetSystemTimeAsFileTime", GetSystemTimeAsFileTime },
	{ "kernel32:GetCurrentProcessId", GetCurrentProcessId },
	{ "kernel32:GetTickCount", GetTickCount },
	{ "kernel32:QueryPerformanceCounter", QueryPerformanceCounter },
	{ "kernel32:CreateEventA", CreateEventA },
	{ "kernel32:GetSystemInfo", GetSystemInfo },
	{ "kernel32:GetDiskFreeSpaceA", GetDiskFreeSpaceA },
	{ "kernel32:GlobalMemoryStatus", GlobalMemoryStatus },
	{ "kernel32:GetCurrentProcess", GetCurrentProcess },
	{ "kernel32:SetConsoleCtrlHandler", SetConsoleCtrlHandler },
	{ "kernel32:CreateThread", CreateThread },
	{ "kernel32:SetThreadPriority", SetThreadPriority },
	{ "kernel32:GetFileAttributesA", GetFileAttributesA },
	{ "kernel32:GetFullPathNameA", GetFullPathNameA },
	{ "kernel32:GetDriveTypeA", GetDriveTypeA },
	{ "kernel32:GetVolumeInformationA", GetVolumeInformationA },
	{ "kernel32:CreateFileA", CreateFileA },
	{ "kernel32:SetFilePointer", SetFilePointer },
	{ "kernel32:ReadFile", ReadFile },
	{ "kernel32:InterlockedIncrement", InterlockedIncrement },
	{ "kernel32:GetProcessHeap", GetProcessHeap },
	//{ "kernel32:FindFirstFileA", FindFirstFileA },
	{ "kernel32:WaitForSingleObject", WaitForSingleObject },
	{ "kernel32:Sleep", Sleep },
	{ "kernel32:SetEvent", SetEvent },
	{ "kernel32:CloseHandle", CloseHandle },
});


}

