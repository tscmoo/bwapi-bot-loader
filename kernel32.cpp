#include "kernel32.h"
#include "environment.h"
#include "wintypes.h"
using namespace wintypes;
#include "modules.h"
#include "native_api.h"
#include "intrusive_list.h"

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
#include <random>

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


FILETIME to_FILETIME(uint64_t val) {
	return FILETIME { (DWORD)(val >> 32),(DWORD)val };
}
uint64_t from_FILETIME(FILETIME val) {
	return (uint64_t)val.dwLowDateTime | ((uint64_t)val.dwHighDateTime << 32);
}

static FILETIME time_point_to_FILETIME(std::chrono::system_clock::time_point time) {
	auto c = std::chrono::duration_cast<std::chrono::duration<uint64_t, std::ratio<1, 10000000>>>(time - std::chrono::system_clock::from_time_t(0));
	return to_FILETIME(c.count() + 116444736000000000);
}

static std::chrono::system_clock::time_point FILETIME_to_time_point(FILETIME time) {
	auto r = std::chrono::system_clock::from_time_t(0);
	return r + std::chrono::duration<uint64_t, std::ratio<1, 10000000>>(from_FILETIME(time) - 116444736000000000);
}

DWORD WINAPI GetLastError() {
	return tlb.last_error;
}

void WINAPI SetLastError(DWORD err) {
	//log("SetLastError %d\n", err);
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
		log("GetModuleHandle: module '%s' not found\n", name);
		//fatal_error("'%s' not found", name);
		SetLastError(ERROR_MOD_NOT_FOUND);
		return nullptr32;
	}
	log("module '%s' is at %p\n", name, i->base);
	return to_pointer32(i->base);
}

BOOL WINAPI GetModuleHandleExA(DWORD flags, const char* name, HMODULE* out_module) {
	*out_module = nullptr32;
	if (flags & 4) {
		fatal_error("fixme: GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS");
	}
	auto* i = name ? modules::get_module_info(name) : main_module_info;
	if (!i) {
		log("GetModuleHandleEx: module '%s' not found\n", name);
		//fatal_error("'%s' not found retaddr %p", name, _ReturnAddress());
		SetLastError(ERROR_MOD_NOT_FOUND);
		return FALSE;
	}
	*out_module = to_pointer32(i->base);
	return TRUE;
}

void* WINAPI GetProcAddress(HMODULE hm, const char* name) {
	auto* i = hm ? modules::get_module_info((void*)hm) : main_module_info;
	if (!i) {
		SetLastError(ERROR_MOD_NOT_FOUND);
		log("GetProcAddress: module %p not found\n", (void*)hm);
		return nullptr;
	}
	bool is_ordinal = (uintptr_t)name < 0x10000;
	DWORD ordinal = (uintptr_t)name & 0xffff;
	if (is_ordinal) name = "(ordinal)";
	if (is_ordinal) {
		size_t index = (size_t)ordinal - i->ordinal_base;
		if (index < i->exports.size()) {
			void* addr = i->exports[index];
			log("GetProcAddress: %p ordinal %d found at %p\n", (void*)hm, ordinal, addr);
			SetLastError(ERROR_SUCCESS);
			return addr;
		} else {
			log("GetProcAddress: %p ordinal %d not found\n", (void*)hm, ordinal);
		}
	} else {
		auto it = i->export_names.find(name);
		if (it != i->export_names.end() && it->second < i->exports.size()) {
			void* addr = i->exports[it->second];
			log("GetProcAddress: %p::%s found at %p\n", (void*)hm, name, addr);
			SetLastError(ERROR_SUCCESS);
			return addr;
		} else {
			log("GetProcAddress: %p::%s not found\n", (void*)hm, name);
		}
	}
	std::string override_name;
	if (is_ordinal) override_name = format("%s:ordinal %d", i->lcase_name_no_ext, ordinal);
	else override_name = format("%s:%s", i->lcase_name_no_ext, name);
	void* r = environment::get_implemented_function(override_name);
	//if (!r) r = environment::get_unimplemented_stub(override_name);
	log("GetProcAddress: %p::%s (%s) -> %p\n", (void*)hm, name, override_name, r);
	if (!r) {
		SetLastError(ERROR_PROC_NOT_FOUND);
	}
	return r;
}

HMODULE WINAPI LoadLibraryA(const char* name) {
	auto* i = modules::load_library(name, false, false);
	if (!i) {
		SetLastError(ERROR_FILE_NOT_FOUND);
		return nullptr32;
	}
	log("LoadLibrary %s -> %p\n", name, i->base);
	return to_pointer32(i->base);
}

HMODULE WINAPI LoadLibraryExA(const char* name, HANDLE h_reserved, DWORD flags) {
	//fatal_error("LoadLibraryEx: name '%s', h_reserved %p, flags %x\n", name, h_reserved, flags);
	auto* i = modules::load_library(name, false, false);
	if (!i) {
		SetLastError(ERROR_FILE_NOT_FOUND);
		return nullptr32;
	}
	log("LoadLibraryEx %s -> %p\n", name, i->base);
	return to_pointer32(i->base);
}


// HMODULE WINAPI LoadLibraryExW(const char16_t* name, HANDLE h_reserved, DWORD flags) {
// 	fatal_error("LoadLibraryExW: name '%s', h_reserved %p, flags %x\n", utf16_to_utf8(name), h_reserved, flags);
// 	auto name_utf8 = utf16_to_utf8(name);
// 	auto* i = modules::load_library(name_utf8.c_str(), false, false);
// 	if (!i) {
// 		SetLastError(ERROR_FILE_NOT_FOUND);
// 		return nullptr;
// 	}
// 	log("LoadLibraryExW %s -> %p\n", name_utf8, i->base);
// 	return i->base;
// }

BOOL WINAPI FreeLibrary(HMODULE h) {
	auto* i = modules::get_module_info((void*)h);
	if (!i) {
		log("FreeLibrary: module %p not found\n", (void*)h);
		SetLastError(ERROR_MOD_NOT_FOUND);
		return FALSE;
	}
	log("FreeLibrary (%s): not supported\n", i->name);
	return TRUE;
}

BOOL WINAPI DisableThreadLibraryCalls(HMODULE h) {
	auto* i = modules::get_module_info((void*)h);
	if (!i) {
		SetLastError(ERROR_MOD_NOT_FOUND);
		return FALSE;
	}
	i->thread_library_calls_enabled = false;
	return TRUE;
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
	enum { t_invalid, t_thread, t_event, t_file, t_mutex, t_file_mapping };
	virtual ~object() {}
	int object_type = t_invalid;
	std::atomic<size_t> refcount { 0 };
};

void deref_HANDLE(HANDLE h);

template<typename T>
struct handle {
	HANDLE h = nullptr32;
	T* ptr = nullptr;
	handle() = default;
	constexpr handle(std::nullptr_t) : ptr(nullptr) {}
	explicit handle(HANDLE h, T* ptr) : h(h), ptr(ptr) {}
	handle(const handle& n) = delete;
	handle(handle&& n) {
		h = n.h;
		ptr = n.ptr;
		n.ptr = nullptr;
		n.h = nullptr32;
	}
	~handle() {
		if (h) {
			deref_HANDLE(h);
		}
	}
	handle& operator=(const handle& n) = delete;
	handle& operator=(handle&& n) {
		std::swap(h, n.h);
		std::swap(ptr, n.ptr);
		return *this;
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
};

constexpr size_t handles_per_container = 0x100;

struct handle_container {
	size_t base = 0;
	std::atomic<handle_container*> next { nullptr };
	id_list<object*, handles_per_container> list;
	std::array<std::atomic_flag, handles_per_container> handle_is_closed {};
	std::array<std::atomic<size_t>, handles_per_container> refcounts {};
};

handle_container root_handle_container;
std::mutex create_handle_container_mut;
std::atomic<handle_container*> next_handle_container { &root_handle_container };
std::atomic<size_t> total_allocated_handles;

HANDLE handle_n_to_HANDLE(size_t n) {
	return to_pointer32((void*)((uintptr_t)(1 + n) << 2));
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
	if (total_allocated_handles.load(std::memory_order_relaxed) >= 16 * 1024 * 1024) return nullptr32;
	HANDLE r;
	auto find = [&](handle_container* from, handle_container* to) {
		for (auto* i = from; i != to; i = i->next.load(std::memory_order_consume)) {
			size_t n = i->list.allocate(obj);
			if (n != npos) {
				next_handle_container.store(i, std::memory_order_relaxed);
				if (i->refcounts[n].load(std::memory_order_relaxed)) fatal_error("new_HANDLE: refcount is non-zero");
				i->refcounts[n].store(1, std::memory_order_relaxed);
				r = handle_n_to_HANDLE(i->base + n);
				log("created new handle %p\n", (void*)r);
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
	if (!find(new_container, nullptr)) fatal_error("unreachable: failed to allocate handle from newly created container");
	std::atomic_thread_fence(std::memory_order_release);
	last_container->next.store(new_container, std::memory_order_relaxed);
	return r;
}

void delete_object(object* o);

void deref_handle(handle_container* c, size_t index) {
	if (c->refcounts[index].fetch_sub(1, std::memory_order_relaxed) == 1) {
		auto* o = c->list.get(index);
		c->list.deallocate(index);
		if (o->refcount.fetch_sub(1, std::memory_order_release) == 1) {
			delete_object(o);
		}
	}
}

void deref_HANDLE(HANDLE h) {
	handle_container* c;
	size_t index;
	std::tie(c, index) = container_and_index_for_HANDLE(h);
	if (!c) fatal_error("deref_HANDLE: no container for HANDLE %p\n", (void*)h);
	deref_handle(c, index);
}

template<typename T>
HANDLE open_handle(T&& o) {
	if (!o.h) fatal_error("attempt to open a null handle");
	handle_container* c;
	size_t index;
	std::tie(c, index) = container_and_index_for_HANDLE(o.h);
	c->handle_is_closed[index].clear(std::memory_order_relaxed);
	HANDLE r = o.h;
	o.h = nullptr32;
	o.ptr = nullptr;
	return r;
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
	if (!h) {
		fatal_error("new_object failed\n");
		return nullptr;
	}
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
	return to_pointer32(&all_heaps.back()); // fixme pointer
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
	cs->OwningThread = nullptr32;
	cs->LockSemaphore = to_pointer32(new std::recursive_mutex()); // fixme pointer
	cs->SpinCount = 0;
}

 void WINAPI InitializeCriticalSectionAndSpinCount(CRITICAL_SECTION* cs, DWORD SpinCount) {
	cs->DebugInfo = nullptr;
	cs->LockCount = -1;
	cs->RecursionCount = 0;
	cs->OwningThread = nullptr32;
	cs->LockSemaphore = to_pointer32(new std::recursive_mutex()); // fixme pointer
	cs->SpinCount = SpinCount;
}

void WINAPI DeleteCriticalSection(CRITICAL_SECTION* cs) {
	cs->DebugInfo = nullptr;
	cs->LockCount = 0;
	cs->RecursionCount = 0;
	cs->OwningThread = nullptr32;
	delete (std::recursive_mutex*)cs->LockSemaphore; // fixme pointer
	cs->LockSemaphore = nullptr32;
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
		size_t index = next_index.load(std::memory_order_relaxed);
		if (index >= ls.size()) {
			return 0xffffffff;
		}
		while (!next_index.compare_exchange_weak(index, index + 1, std::memory_order_relaxed, std::memory_order_relaxed)) {
			if (index >= ls.size()) {
				return 0xffffffff;
			}
		}
		return index;
	}

	size_t get_free_index() {
		auto take = [&](size_t index) {
			bool was_busy = ls[index].busy.load(std::memory_order_relaxed);
			if (was_busy) return false;
			return ls[index].busy.compare_exchange_weak(was_busy, true, std::memory_order_relaxed, std::memory_order_relaxed);
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

thread_local local_storage fls;

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
	auto* i = hm ? modules::get_module_info((void*)hm) : main_module_info;
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
		log("GetModuleFileName %p -> '%s'\n", (void*)hm, dst);
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

void WINAPI GetStartupInfoW(STARTUPINFOW* i) {
	memset(i, 0, sizeof(*i));
	i->cb = sizeof(STARTUPINFOW);
}

struct file : object {
	static const auto static_type = object::t_file;
	DWORD access = 0;
	FILE_TYPE file_type = FILE_TYPE_UNKNOWN;

	std::function<uint64_t(uint64_t offset, MOVE_METHOD method)> set_pos;
	std::function<uint64_t()> get_pos;
	std::function<bool(void* buffer, size_t to_read, size_t* read)> read;
	std::function<uint64_t()> get_size;
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
	bool was_ever_committed = false;
	PAGE_PROTECT protect = (PAGE_PROTECT)0;
	MEM_STATE state = (MEM_STATE)0;
};

struct virtual_region {
	void* base;
	size_t size;
	std::vector<page_attributes> pages;
	PAGE_PROTECT allocation_protect;
};
std::map<void*, virtual_region> virtual_regions;
std::mutex virtual_mut;
size_t vm_total_allocated = 0;

void add_virtual_region_nolock(void* addr, size_t size, MEM_STATE state, PAGE_PROTECT protect) {
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
	if (ptr && (protect == PAGE_READONLY || protect == PAGE_READWRITE)) {
		for (size_t i = 0; i < size; ++i) {
			char* p = (char*)ptr;
			if (p[i]) fatal_error("waa");
		}
	}
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
	auto state = r->pages[page].state;
	auto protect = r->pages[page].protect;
	size_t pages = 1;
	for (size_t i = page + 1; i != r->pages.size(); ++i) {
		if (r->pages[page].state != state || r->pages[page].protect != protect) break;
		++pages;
	}
	buffer->BaseAddress = (uint8_t*)r->base + offset;
	buffer->AllocationBase = r->base;
	buffer->AllocationProtect = r->allocation_protect;
	buffer->RegionSize = 0x1000 * pages;
	buffer->State = state;
	buffer->Protect = protect;
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
					if (r->pages[p].was_ever_committed && access != native_api::memory_access::read_write && access != native_api::memory_access::read_write_execute) {
						native_api::set_memory_access((uint8_t*)r->base + p * 0x1000, 0x1000, native_api::memory_access::read_write);
						memset((uint8_t*)r->base + p * 0x1000, 0, 0x1000);
						native_api::set_memory_access((uint8_t*)r->base + p * 0x1000, 0x1000, access);
					} else {
						native_api::set_memory_access((uint8_t*)r->base + p * 0x1000, 0x1000, access);
						if (r->pages[p].was_ever_committed) memset((uint8_t*)r->base + p * 0x1000, 0, 0x1000);
					}
					r->pages[p].was_ever_committed = true;
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
			SetLastError(ERROR_INVALID_ADDRESS);
			return FALSE;
		}
		virtual_deallocate_nolock(r);
		return TRUE;
	} else {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
}

BOOL WINAPI VirtualLock(void* addr, SIZE_T size) {
	log("VirtualLock: not supported\n");
	SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}
BOOL WINAPI VirtualUnlock(void* addr, SIZE_T size) {
	log("VirtualUnlock: not supported\n");
	SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}

LONG WINAPI UnhandledExceptionFilter(EXCEPTION_POINTERS* info) {
	fatal_error("unhandled exception %#x at %p\n", info->ExceptionRecord->ExceptionCode, info->ExceptionRecord->ExceptionAddress);
	return 0;
}

void* WINAPI SetUnhandledExceptionFilter(void* func) {
	return nullptr;
}

std::string cmdline;
std::u16string cmdlinew;

void set_cmdline(const std::string& str) {
	cmdline = str;
	cmdlinew = utf8_to_utf16(str);
}

const char* WINAPI GetCommandLineA() {
	return cmdline.c_str();
}

const char16_t* WINAPI GetCommandLineW() {
	return cmdlinew.c_str();
}

const int16_t env_strings[] = { 0, 0 };

const int16_t* WINAPI GetEnvironmentStringsW() {
	return env_strings;
}

int WINAPI WideCharToMultiByte(UINT code_page, DWORD flags, char16_t* widestr, int widelen, char* outstr, int outlen, const char* default_char, BOOL* used_default_char) {
	if (used_default_char) *used_default_char = FALSE;
	if (widelen == -1) {
		widelen = 0;
		for (auto* p = widestr; *p; ++p, ++widelen);
		++widelen;
	}
	bool include_null = widestr[widelen] == 0;
	auto s = utf16_to_utf8(std::u16string(widestr, widelen));
	if (outlen == 0) return widelen;
	int reqlen = s.size();
	if (include_null) ++reqlen;
	if (outlen < reqlen) {
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}
	memcpy(outstr, s.data(), reqlen);
	return reqlen;
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

enum processor_feature {
	PF_FLOATING_POINT_EMULATED = 1,
	PF_COMPARE_EXCHANGE_DOUBLE = 2,
	PF_MMX_INSTRUCTIONS_AVAILABLE = 3,
	PF_XMMI_INSTRUCTIONS_AVAILABLE = 6,
	PF_RDTSC_INSTRUCTION_AVAILABLE = 8,
	PF_PAE_ENABLED = 9,
	PF_XMMI64_INSTRUCTIONS_AVAILABLE = 10,
	PF_SSE3_INSTRUCTIONS_AVAILABLE = 13,
	PF_COMPARE_EXCHANGE128 = 14,
	PF_XSAVE_ENABLED = 17,
};

std::array<bool, 32> processor_features {};

void set_processor_features() {
	uint32_t regs[4];
	environment::cpuid(0, 0, regs);
	if (regs[0] >= 1) {
		environment::cpuid(1, 0, regs);
		processor_features[PF_FLOATING_POINT_EMULATED] = ~regs[3] & 1;
		processor_features[PF_RDTSC_INSTRUCTION_AVAILABLE] = (regs[3] >> 4) & 1;
		processor_features[PF_PAE_ENABLED] = (regs[3] >> 6) & 1;
		processor_features[PF_COMPARE_EXCHANGE_DOUBLE] = (regs[3] >> 8) & 1;
		processor_features[PF_MMX_INSTRUCTIONS_AVAILABLE] = (regs[3] >> 23) & 1;
		processor_features[PF_XMMI_INSTRUCTIONS_AVAILABLE] = (regs[3] >> 25) & 1;
		processor_features[PF_XMMI64_INSTRUCTIONS_AVAILABLE] = (regs[3] >> 26) & 1;
		processor_features[PF_SSE3_INSTRUCTIONS_AVAILABLE] = (regs[2] >> 0) & 1;
		processor_features[PF_XSAVE_ENABLED] = (regs[2] >> 27) & 1;
		processor_features[PF_COMPARE_EXCHANGE128] = (regs[2] >> 13) & 1;
	}
}

BOOL WINAPI IsProcessorFeaturePresent(DWORD feature) {
	if (feature < processor_features.size()) return processor_features[feature] ? TRUE : FALSE;
	return FALSE;
}

void WINAPI GetSystemTimeAsFileTime(FILETIME* out) {
	*out = time_point_to_FILETIME(std::chrono::system_clock::now());
}

DWORD WINAPI GetCurrentProcessId() {
	return 1;
}

std::chrono::high_resolution_clock highres_clock;
auto highres_start = highres_clock.now();
std::chrono::steady_clock tick_clock;
auto tick_start = tick_clock.now();

DWORD WINAPI GetTickCount() {
	return std::chrono::duration_cast<std::chrono::duration<DWORD, std::ratio<1, 1000>>>(tick_clock.now() - tick_start).count() + 600000;
}

ULONGLONG WINAPI GetTickCount64() {
	return std::chrono::duration_cast<std::chrono::duration<ULONGLONG, std::ratio<1, 1000>>>(tick_clock.now() - tick_start).count() + 600000;
}

BOOL WINAPI QueryPerformanceCounter(uint64_t* count) {
	*count = (uint64_t)(highres_clock.now() - highres_start).count();
	return TRUE;
}

struct thread : object {
	static const auto static_type = object::t_thread;
	DWORD id = 0;
	std::thread thread_obj;
	bool running = true;
	DWORD exit_code = 259;

	std::mutex wait_mut;
	std::condition_variable wait_cv;
	std::pair<thread*, thread*> sleep_queue_link;
};

class sleep_queue {
	std::mutex mut;
	using queue_t = intrusive_list<thread, void, &thread::sleep_queue_link>;
	queue_t queue;
public:
	struct queue_unlinker {
		queue_t::iterator iterator;
		~queue_unlinker() {
			if (iterator != queue_t::iterator()) queue_t::erase(iterator);
		}
	};
	template<typename pred_T>
	void wait(pred_T&& pred) {
		auto t = tlb.current_thread;
		std::unique_lock<std::mutex> ml(mut);
		if (pred()) return;
		queue_unlinker unlinker { queue.insert(queue.end(), *t) };
		t->wait_cv.wait(ml, std::forward<pred_T>(pred));
	}
	template<typename rep, typename period, typename pred_T>
	bool wait_for(const std::chrono::duration<rep, period>& timeout_duration, pred_T&& pred) {
		auto t = tlb.current_thread;
		std::unique_lock<std::mutex> ml(mut);
		if (pred()) return true;
		queue_unlinker unlinker { queue.insert(queue.end(), *t) };
		return t->wait_cv.wait_for(ml, timeout_duration, std::forward<pred_T>(pred));
	}
	void notify_one() {
		fatal_error("sleep_queue::notify_one");
	}
	void notify_all() {
		std::lock_guard<std::mutex> ml(mut);
		for (auto& v : queue) {
			std::lock_guard<std::mutex> tl(v.wait_mut);
			v.wait_cv.notify_all();
		}
	}
	bool empty() {
		std::lock_guard<std::mutex> l(mut);
		return queue.empty();
	}
	template<typename rep, typename period, typename pred_T>
	static bool wait_multiple(size_t n, sleep_queue** queues, const std::chrono::duration<rep, period>& timeout_duration, pred_T&& pred) {
		auto t = tlb.current_thread;
		std::vector<std::pair<std::unique_lock<std::mutex>, queue_unlinker>> locks_and_unlinkers;
		for (size_t i = 0; i < n; ++i) {
			locks_and_unlinkers.emplace_back(std::piecewise_construct, std::tie(queues[i]->mut), std::tie());
		}
		if (pred()) return true;
		std::unique_lock<std::mutex> l(t->wait_mut);
		for (size_t i = 0; i < n; ++i) {
			auto& v = locks_and_unlinkers[i];
			auto& q = queues[i]->queue;
			v.second = queue_unlinker { q.insert(q.end(), *t) };
			v.first.unlock();
		}
		return t->wait_cv.wait_for(l, timeout_duration, std::forward<pred_T>(pred));
	}
};

struct event: object {
	static const auto static_type = object::t_event;
	bool manual_reset = false;
	std::atomic<int> state { false };
	sleep_queue queue;
};


HANDLE WINAPI CreateEventA(void* security_attributes, BOOL manual_reset, BOOL initial_state, const char* name) {
	auto e = new_object<event>();
	if (!e) {
		SetLastError(ERROR_NO_SYSTEM_RESOURCES);
		return nullptr32;
	}
	e->manual_reset = manual_reset != FALSE;
	e->state = initial_state;
	log("CreateEventA '%s' %d %d -> %p\n", name, (int)manual_reset, (int)initial_state, (void*)e.h);
	std::atomic_thread_fence(std::memory_order_release);
	return open_handle(e);
}


id_list<thread*, 0xffff> all_threads;

handle<thread> new_thread() {
	auto t = new_object<thread>();
	if (!t) return nullptr;
	auto id = all_threads.allocate(&*t);
	if (id == npos) return nullptr;
	t->id = 1 + id;
	return t;
}

HANDLE default_process_heap = nullptr32;

void initialize_things() {
	std_input_handle = open_handle(new_console_handle(true, false));
	std_output_handle = open_handle(new_console_handle(false, true));
	std_error_handle = open_handle(new_console_handle(false, true));

	default_process_heap = HeapCreate(0, 0, 0);
	if (!default_process_heap) fatal_error("failed to create default process heap");

	set_processor_features();
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
		return nullptr32;
	}
	auto t = new_thread();
	auto t2 = duplicate_handle(t);
	if (!t || !t2) {
		SetLastError(ERROR_NO_SYSTEM_RESOURCES);
		return nullptr32;
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
	return open_handle(t);
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
	auto s = get_native_path(filename);
	auto rv = [&]() {
		if (native_api::is_directory(s.c_str())) return 0x10;
		else if (native_api::is_file(s.c_str())) return 0x80;
		else return -1;
	};
	auto r = rv();
	log("GetFileAttributes for %s (%s): %d\n", filename, s, r);
	if (r != -1) return r;
	SetLastError(ERROR_FILE_NOT_FOUND);
	return (DWORD)-1;
}

DWORD WINAPI GetFullPathNameA(const char* path, DWORD buflen, char* buf, pointer32_T<char>* filepart) {
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
	log("GetFullPathName '%s' -> '%s' (filepart '%s')\n", path, buf, (char*)(filepart ? *filepart : nullptr));
	return s.size();
}

static const auto DRIVE_UNKNOWN = 0;
static const auto DRIVE_NO_ROOT_DIR = 1;
static const auto DRIVE_FIXED = 3;

UINT WINAPI GetDriveTypeA(const char* path_name) {
	log("GetDriveType '%s'\n", path_name);
	if (!path_name) return DRIVE_FIXED;
	size_t len = strlen(path_name);
	if (len == 0 || path_name[len - 1] != '\\') return DRIVE_NO_ROOT_DIR;
	if (len == 3 && (path_name[0] == 'Z' || path_name[0] == 'z') && path_name[1] == ':') return DRIVE_FIXED;
	return DRIVE_UNKNOWN;
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

	auto s = get_native_path(filename);

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
		log("failed to open file\n");
		SetLastError(ERROR_FILE_NOT_FOUND);
		return INVALID_HANDLE_VALUE;
	}
	o->access = access;
	o->file_type = FILE_TYPE_DISK;

	auto f = std::make_shared<native_api::file_io>(std::move(file_io));

	o->set_pos = [f](uint64_t pos, MOVE_METHOD method) {
		return f->set_pos(pos, move_method_to_native_origin(method));
	};
	o->get_pos = [f]() {
		return f->get_pos();
	};
	o->read = [f](void* buffer, size_t to_read, size_t* read) {
		bool r = f->read(buffer, to_read, read);
		if (!r) {
			SetLastError(ERROR_READ_FAULT);
		}
		return r;
	};
	o->get_size = [f]() {
		return f->get_size();
	};

	log("create file ok\n");
	std::atomic_thread_fence(std::memory_order_release);
	return open_handle(o);
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

DWORD WINAPI GetFileSize(HANDLE h, DWORD* size_high) {
	auto o = get_object<file>(h);
	if (!o) {
		SetLastError(ERROR_INVALID_HANDLE);
		return (DWORD)-1;
	}
	if (!o->get_size) {
		log("GetFileSize: no size for object\n");
		SetLastError(ERROR_INVALID_HANDLE);
		return (DWORD)-1;
	}
	uint64_t size = o->get_size();
	log("GetFileSize: returning %d\n", size);
	SetLastError(ERROR_SUCCESS);
	if (size_high) *size_high = (DWORD)(size >> 32);
	return (DWORD)size;
}

LONG WINAPI InterlockedIncrement(LONG* value) {
	return native_api::fetch_add(value) + 1;
}

HANDLE WINAPI GetProcessHeap() {
	return default_process_heap;
}

// Windows has some really weird wildcard matching. This is not probably not
// accurate, but it supports at least some of the weird behavior.
bool matches_file_pattern(const std::string& filename, const std::string& pattern) {
	if (pattern == "*.*") return true;
	const char* fc = filename.data();
	const char* fe = fc + filename.size();
	const char* pc = pattern.data();
	const char* pe = pc + pattern.size();
	while (pc != pe) {
		char c = *pc;
		if (fc == fe) {
			if (c == '.' && pc + 1 != pe && (pc[1] == '?' || pc[1] == '>')) return true;
			if (c == '?' || c == '>') return true;
			if (c == '*' || c == '<') return true;
			return false;
		}
		switch (c) {
		case '?': case '>':
			if (*fc == '.') {
				while (true) {
					++pc;
					if (pc == pe) break;
					if (*pc != '?' && *pc != '>') break;
				}
				if (pc != pe && *pc == '.') ++pc;
			} else ++pc;
			if (pc == pe) return true;
			++fc;
			break;
		case '*': case '<':
			++pc;
			if (pc == pe) return true;
			while ((*pc == '*' || *pc == '<' || *pc == '?' || *pc == '>') && pc != pe) ++pc;
			c = *pc;
			if (c == '"') c = '.';
			while (true) {
				++fc;
				if (fc == fe) return pc + 1 == pe && c == '.';
				if (*fc == c) break;
			}
			break;
		case '"':
			if (*fc != '.') return false;
			++pc;
			++fc;
			break;
		default:
			if (*fc != c) return false;
			++pc;
			++fc;
			break;
		}
	}
	return fc == fe;
}

struct find_file {
	static const uint32_t magic_value = 0x4801f7c2;
	uint32_t magic = magic_value;
	std::string pattern;
	native_api::directory_io dir_io;
};

void copy_find_data(WIN32_FIND_DATAA* data, const native_api::directory_entry& e) {
	data->dwFileAttributes = 0;
	if (e.is_directory) data->dwFileAttributes |= 0x10;
	data->ftCreationTime = time_point_to_FILETIME(e.creation_time);
	data->ftLastAccessTime = time_point_to_FILETIME(e.access_time);
	data->ftLastWriteTime = time_point_to_FILETIME(e.write_time);
	data->nFileSizeHigh = (DWORD)(e.file_size >> 32);
	data->nFileSizeLow = (DWORD)e.file_size;
	data->dwReserved0 = 0;
	data->dwReserved1 = 0;
	size_t len = e.file_name.size();
	if (len >= 260) len = 260 - 1;
	memcpy(data->cFileName, e.file_name.data(), len);
	data->cFileName[len] = 0;
	len = e.file_name.size();
	if (len >= 14) len = 14 - 1;
	memcpy(data->cAlternateFileName, e.file_name.data(), len);
	data->cAlternateFileName[len] = 0;
}

HANDLE WINAPI FindFirstFileA(const char* filename, WIN32_FIND_DATAA* data) {
	const char* last_slash = filename;
	for (const char* c = filename; *c; ++c) {
		if (*c == '/' || *c == '\\') last_slash = c;
	}
	if (!*(last_slash + 1)) {
		SetLastError(ERROR_FILE_NOT_FOUND);
		return INVALID_HANDLE_VALUE;
	}
	std::string pattern = last_slash + 1;
	auto path = get_full_path(std::string(filename, last_slash));
	auto native_path = get_native_path(path);
	native_api::directory_io dir_io;
	if (!dir_io.open(native_path.c_str())) {
		SetLastError(ERROR_PATH_NOT_FOUND);
		return INVALID_HANDLE_VALUE;
	}
	while (true) {
		auto e = dir_io.get();
		bool m = matches_file_pattern(e.file_name, pattern);
		log("match '%s' pattern '%s' ? %d\n", e.file_name, pattern, m);
		if (m) {
			log("FindFirstFile '%s': file found (%s)\n", filename, e.file_name);
			auto* o = new find_file();
			o->pattern = std::move(pattern);
			o->dir_io = std::move(dir_io);

			copy_find_data(data, e);

			log("returning file '%s' attribs %x\n", data->cFileName, data->dwFileAttributes);
			//Sleep(1000);
			return (HANDLE)o;
		}
		if (!dir_io.next()) break;
	}
	log("FindFirstFile '%s': not found\n", filename);
	SetLastError(ERROR_FILE_NOT_FOUND);
	return INVALID_HANDLE_VALUE;
}

BOOL WINAPI FindNextFileA(HANDLE h, WIN32_FIND_DATAA* data) {
	auto* o = (find_file*)h;
	if (o->magic != o->magic_value) fatal_error("FindNextFile: invalid handle");
	while (true) {
		auto e = o->dir_io.get();
		if (!o->dir_io.next()) break;
		bool m = matches_file_pattern(e.file_name, o->pattern);
		log("match '%s' pattern '%s' ? %d\n", e.file_name, o->pattern, m);
		if (m) {
			copy_find_data(data, e);
			log("returning file '%s' attribs %x\n", data->cFileName, data->dwFileAttributes);
			//Sleep(1000);
			return TRUE;
		}
	}
	log("FindNextFile: not found\n");
	SetLastError(ERROR_FILE_NOT_FOUND);
	return FALSE;
}

BOOL WINAPI FindClose(HANDLE h) {
	auto* o = (find_file*)h;
	if (o->magic != o->magic_value) fatal_error("FindClose: invalid handle");
	o->magic = ~o->magic_value;
	delete o;
	return TRUE;
}

struct mutex : object {
	static const auto static_type = object::t_mutex;
	std::atomic<thread*> owner { nullptr };
	sleep_queue queue;
};

bool wait_pred(event* o) {
	auto val = o->state.load(std::memory_order_relaxed);
	if (!val) return false;
	if (o->manual_reset) return true;
	if (o->state.compare_exchange_weak(val, false, std::memory_order_relaxed)) return true;
	return false;
}

bool wait_pred(mutex* o) {
	thread* owner = o->owner.load(std::memory_order_relaxed);
	if (owner) return false;
	if (o->owner.compare_exchange_weak(owner, tlb.current_thread, std::memory_order_relaxed)) return true;
	return false;
}

enum WAIT_RETVAL : DWORD {
	WAIT_OBJECT_0 = 0,
	WAIT_ABANDONED = 0x80,
	WAIT_TIMEOUT = 0x102,
	WAIT_FAILED = 0xffffffff
};

WAIT_RETVAL WINAPI WaitForSingleObject(HANDLE h, DWORD milliseconds) {
	log("WaitForSingleObject %p %d\n", (void*)h, milliseconds);
	auto go = get_object<object>(h);
	if (!go) {
		SetLastError(ERROR_INVALID_HANDLE);
		return WAIT_FAILED;
	}
	auto wait = [&](auto* o) {
		auto* t = tlb.current_thread;
		auto pred = std::bind((bool(*)(decltype(o)))wait_pred, o);
		if (pred()) {
			log("thread %#x did not have to wait for event %p\n", t->id, (void*)h);
			return WAIT_OBJECT_0;
		}
		log("thread %#x is waiting for event %p\n", t->id, (void*)h);
		if (milliseconds == (DWORD)-1) {
			o->queue.wait(pred);
		} else if (milliseconds != 0) {
			if (!o->queue.wait_for(std::chrono::milliseconds(milliseconds), pred)) {
				log("thread %#x timed out from waiting for event %p\n", t->id, (void*)h);
				return WAIT_TIMEOUT;
			}
		}
		log("thread %#x woke up from waiting for event %p\n", t->id, (void*)h);
		return WAIT_OBJECT_0;
	};
	if (go->object_type == object::t_event) {
		return wait((event*)go.get());
	} else if (go->object_type == object::t_mutex) {
		return wait((mutex*)go.get());
	} else {
		fatal_error("WaitForSingleObject: wait for unknown object type %d (%s)\n", (int)go->object_type, typeid(*go).name());
		log("WaitForSingleObject: object_type %d not supported\n", (int)go->object_type);
		SetLastError(ERROR_NOT_SUPPORTED);
		return WAIT_FAILED;
	}
}

DWORD WINAPI WaitForMultipleObjects(DWORD count, const HANDLE* input_handles, BOOL wait_for_all, DWORD milliseconds) {
	if (count == 0 || count > 64) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return WAIT_FAILED;
	}
	size_t n = (size_t)count;
	for (size_t i = 0; i < n; ++i) {
		for (size_t i2 = i + 1; i2 < n; ++i2) {
			if (input_handles[i] == input_handles[i2]) {
				SetLastError(ERROR_INVALID_PARAMETER);
				return WAIT_FAILED;
			}
		}
	}
	std::array<handle<object>, 64> handles;
	std::array<sleep_queue*, 64> queues;
	std::array<std::pair<object*, bool>, 64> objects;
	for (size_t i = 0; i < n; ++i) {
		auto o = get_object<object>(input_handles[i]);
		if (!o) {
			SetLastError(ERROR_INVALID_HANDLE);
			return WAIT_FAILED;
		}
		if (o->object_type == object::t_event) {
			queues[i] = &((event&)*o).queue;
			objects[i] = { &*o, false };
			handles[i] = std::move(o);
		} else {
			fatal_error("WaitForMultipleObjects: wait for unknown object type %d (%s)\n", (int)o->object_type, typeid(*o).name());
			log("WaitForMultipleObjects: object_type %d not supported\n", (int)o->object_type);
			SetLastError(ERROR_NOT_SUPPORTED);
			return WAIT_FAILED;
		}
	}
	auto* t = tlb.current_thread;
	log("thread %#x is waiting for multiple objects\n", t->id);
	size_t n_signalled = 0;
	size_t req_signalled = wait_for_all ? n : 1;
	size_t first_signalled = 0;
	auto pred = [&objects, n, &n_signalled, &first_signalled, req_signalled]() {
		for (size_t i = 0; i < n; ++i) {
			auto& v = objects[i];
			if (v.second) continue;
			auto* o = v.first;
			if (o->object_type == object::t_event) {
				if (wait_pred((event*)&*o)) {
					v.second = true;
					if (n_signalled == 0) first_signalled = i;
					++n_signalled;
				}
			}
		}
		return n_signalled >= req_signalled;
	};
	std::chrono::milliseconds timeout_duration(milliseconds);
	if (milliseconds == (DWORD)-1) timeout_duration = std::chrono::hours(1);
	if (!sleep_queue::wait_multiple(n, queues.data(), timeout_duration, pred)) {
		log("thread %#x timed out from waiting for multiple objects\n", t->id);
		return WAIT_TIMEOUT;
	}

	DWORD retval = wait_for_all ? WAIT_OBJECT_0 : WAIT_OBJECT_0 + first_signalled;

	log("thread %#x woke up from waiting for multiple objects\n", t->id);
	return retval;
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
	o->state.store(true, std::memory_order_relaxed);
	o->queue.notify_all();
	return TRUE;
}

BOOL WINAPI CloseHandle(HANDLE h) {
	log("CloseHandle %p\n", (void*)h);
	auto o = get_object<object>(h);
	if (!o) {
		log("CloseHandle %p: invalid handle\n", (void*)h);
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	if (o->object_type == object::t_mutex) fatal_error("stop");
	handle_container* c;
	size_t index;
	std::tie(c, index) = container_and_index_for_HANDLE(h);
	if (!c) fatal_error("CloseHandle: no container for HANDLE %p\n", (void*)h);
	if (c->refcounts[index].load(std::memory_order_relaxed) < 2) fatal_error("CloseHandle: handle refcount is < 2");
	bool already_closed = c->handle_is_closed[index].test_and_set(std::memory_order_relaxed);
	if (already_closed) {
		log("CloseHandle %s %p: already closed\n", typeid(*o).name(), (void*)h);
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	deref_handle(c, index);
	return TRUE;
}

uintptr_t encode_pointer_value = 0x12345678 ^ std::random_device()();

void* WINAPI EncodePointer(void* ptr) {
	return (void*)((uintptr_t)ptr ^ encode_pointer_value);
}
void* WINAPI DecodePointer(void* ptr) {
	return (void*)((uintptr_t)ptr ^ encode_pointer_value);
}

BOOL WINAPI IsDebuggerPresent() {
	return FALSE;
}

void WINAPI InitializeSListHead(SLIST_HEADER* head) {
	head->value = 0;
}

SLIST_ENTRY* WINAPI InterlockedFlushSList(SLIST_HEADER* head) {
	auto val = *head;
	SLIST_HEADER null_val { 0xffff000000000000 };
	while (!native_api::compare_exchange(head, val, null_val));
	return (SLIST_ENTRY*&)val;
}

HANDLE WINAPI CreateMutexA(void* security_attributes, BOOL initial_owner, const char* name) {
	auto o = new_object<mutex>();
	if (!o) {
		SetLastError(ERROR_NO_SYSTEM_RESOURCES);
		return nullptr32;
	}
	if (initial_owner) o->owner.store(tlb.current_thread, std::memory_order_relaxed);
	log("CreateMutex '%s' %d -> %p\n", name, (int)initial_owner, (void*)o.h);
	std::atomic_thread_fence(std::memory_order_release);
	return open_handle(o);
}

BOOL WINAPI ReleaseMutex(HANDLE h) {
	auto o = get_object<mutex>(h);
	if (!o) {
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	auto* t = tlb.current_thread;
	if (o->owner != t) {
		SetLastError(ERROR_NOT_OWNER);
		return FALSE;
	}
	o->owner.store(nullptr, std::memory_order_relaxed);
	return TRUE;
}

struct file_mapping: object {
	static const auto static_type = object::t_file_mapping;
	uint64_t size = 0;
	PAGE_PROTECT protect = PAGE_NOACCESS;
// 	bool is_native_shm = false;
// 	native_api::shm_io shm_io;
};

HANDLE WINAPI CreateFileMappingA(HANDLE hfile, void* security_attributes, DWORD protect, DWORD max_size_high, DWORD max_size_low, const char* name) {
	if (hfile != INVALID_HANDLE_VALUE) {
		fatal_error("CreateFileMapping: h != INVALID_HANDLE_VALUE, fixme?");
	}
	uint64_t size = (uint64_t)max_size_low | ((uint64_t)max_size_high << 32);
	if (size == 0) {
		SetLastError(ERROR_FILE_INVALID);
		return nullptr32;
	}
	auto o = new_object<file_mapping>();
	if (!o) {
		SetLastError(ERROR_NO_SYSTEM_RESOURCES);
		return nullptr32;
	}
	o->protect = (PAGE_PROTECT)(protect & 0xff);
	o->size = size;
// 	if (true) {
// 		o->is_native_shm = true;
// 		std::string strname = name;
// 		size_t slash_pos = strname.find('\\');
// 		if (slash_pos != std::string::npos) strname = strname.substr(slash_pos + 1);
// 		if (!o->shm_io.open(strname.c_str(), size)) {
// 			log("native shm open '%s' failed\n", strname);
// 			SetLastError(ERROR_OPEN_FAILED);
// 			return nullptr;
// 		}
// 		log("native shm open '%s' success\n", strname);
// 	}
	std::atomic_thread_fence(std::memory_order_release);
	SetLastError(ERROR_SUCCESS);
	return open_handle(o);
}

enum {
	FILE_MAP_COPY = 1,
	FILE_MAP_WRITE = 2,
	FILE_MAP_READ = 4
};

void* WINAPI MapViewOfFile(HANDLE h, DWORD access, DWORD offset_high, DWORD offset_low, SIZE_T size_arg) {
	auto o = get_object<file_mapping>(h);
	if (!o) {
		SetLastError(ERROR_INVALID_HANDLE);
		return nullptr;
	}
	uint64_t offset = (uint64_t)offset_low | ((uint64_t)offset_high << 32);
	if (offset & (vm_allocation_granularity - 1)) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return nullptr;
	}
	size_t size = size_arg;
	if (offset + size > o->size || offset == o->size) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return nullptr;
	}
	if (size == 0) {
		uint64_t size64 = o->size - offset;
		if ((uint64_t)(size_t)size64 != size64) {
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return nullptr;
		}
	}
// 	if (o->is_native_shm) {
// 		int flags = 0;
// 		if (access & FILE_MAP_COPY) flags |= native_api::shm_io_copy_on_write;
// 		if (access & FILE_MAP_WRITE) flags |= native_api::shm_io_write;
// 		if (access & FILE_MAP_READ) flags |= native_api::shm_io_read;
// 		void* r = o->shm_io.map(nullptr, offset, size, flags);
// 		if (!r) {
// 			log("MapViewOfFile native map failed\n");
// 			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
// 			return nullptr;
// 		}
// 		return r;
// 	}
	void* r = virtual_allocate(nullptr, size, MEM_COMMIT, PAGE_READWRITE, nullptr);
	log("MapViewOfFile %p %#x %#x %#x -> %p\n", (void*)h, access, offset, size, r);
	if (!r) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return nullptr;
	}
	return r;
}

BOOL WINAPI UnmapViewOfFile(void* addr) {
	std::lock_guard<std::mutex> l(virtual_mut);
	auto* r = find_virtual_region(addr);
	if (!r) {
		SetLastError(ERROR_INVALID_ADDRESS);
		return FALSE;
	}
	if (r->base != addr) {
		SetLastError(ERROR_INVALID_ADDRESS);
		return FALSE;
	}
	virtual_deallocate_nolock(r);
	return TRUE;
}

WORD WINAPI GetUserDefaultLangID() {
	return 0;
}

UINT WINAPI SetErrorMode() {
	return 0;
}

UINT WINAPI GetProfileIntA(const char* appname, const char* keyname, INT default) {
	log("GetProfileIntA %s %s %d\n", appname, keyname, default);
	return default;
}

BOOL WINAPI CreateDirectoryA(const char* name, void* security_attributes) {
	log("create directory %s\n", name);
	SetLastError(ERROR_ALREADY_EXISTS);
	return FALSE;
}

void* WINAPI FindResourceA(HMODULE hm, const char* name, const char* type) {
	auto* i = hm ? modules::get_module_info((void*)hm) : main_module_info;
	if (!i) {
		SetLastError(ERROR_MOD_NOT_FOUND);
		return nullptr32;
	}
	bool name_is_id = (uintptr_t)name < 0x10000;
	DWORD name_id = (uintptr_t)name & 0xffff;
	if (name_is_id) name = "(id)";
	bool type_is_id = (uintptr_t)type < 0x10000;
	DWORD type_id = (uintptr_t)type & 0xffff;
	if (type_is_id) type = "(id)";
	if (!i->root_resource_directory) {
		SetLastError(ERROR_RESOURCE_NOT_FOUND);
		return nullptr;
	}
	std::string str;
	std::function<void(modules::resource_directory*, int)> dump = [&](modules::resource_directory* dir, int level) {
		if (!dir) return;
		for (auto& v : dir->named) {
			for (int i = 0; i < level; ++i) str += " ";
			str += format("'%s' -\n", utf16_to_utf8(v.first));
			if (v.second.dir) dump(v.second.dir, level + 1);
		}
		for (auto& v : dir->id) {
			for (int i = 0; i < level; ++i) str += " ";
			str += format("%d -\n", v.first);
			if (v.second.dir) dump(v.second.dir, level + 1);
		}
	};
	dump(i->root_resource_directory, 2);
	log("FindResource: root -\n%s\n", str);
	modules::resource_entry* re = nullptr;
	if (type_is_id) {
		auto it = i->root_resource_directory->id.find(type_id);
		if (it != i->root_resource_directory->id.end()) re = &it->second;
	} else {
		auto it = i->root_resource_directory->named.find(utf8_to_utf16(type));
		if (it != i->root_resource_directory->named.end()) re = &it->second;
	}
	if (!re || !re->dir) {
		SetLastError(ERROR_RESOURCE_NOT_FOUND);
		return nullptr;
	}
	modules::resource_entry* re2 = nullptr;
	if (name_is_id) {
		auto it = re->dir->id.find(name_id);
		if (it != re->dir->id.end()) re2 = &it->second;
	} else {
		auto it = re->dir->named.find(utf8_to_utf16(name));
		if (it != re->dir->named.end()) re2 = &it->second;
	}
	if (re2 && re2->dir) {
		auto it = re2->dir->id.find(1033);
		if (it != re2->dir->id.end()) re2 = &it->second;
	}
	if (!re2 || !re2->data) {
		SetLastError(ERROR_RESOURCE_NOT_FOUND);
		return nullptr;
	}
	log("FindResource %p %s %s -> %p\n", (void*)hm, name, type, re2);
	SetLastError(ERROR_SUCCESS);
	return re2;
}

DWORD WINAPI SizeofResource(HMODULE hm, void* resinfo) {
	modules::resource_entry* re = (modules::resource_entry*)resinfo;
	return (DWORD)re->size;
}

void* WINAPI LoadResource(HMODULE hm, void* resinfo) {
	modules::resource_entry* re = (modules::resource_entry*)resinfo;
	return re->data;
}

void* WINAPI LockResource(void* data) {
	log("LockResource: %p\n", data);
	return data;
}

BOOL WINAPI DeleteFileA(const char* filename) {
	log("DeleteFile: %s\n", filename);
	if (native_api::delete_file(filename)) return TRUE;
	SetLastError(ERROR_FILE_NOT_FOUND);
	return FALSE;
}

register_funcs funcs("kernel32", {
	{ "SetLastError", SetLastError },
	{ "GetLastError", GetLastError },
	{ "GetVersionExA", GetVersionExA },
	{ "GetVersion", GetVersion },
	{ "GetModuleHandleA", GetModuleHandleA },
	{ "GetModuleHandleW", wtoa_function(GetModuleHandleA) },
	{ "GetModuleHandleExA", GetModuleHandleExA },
	{ "GetModuleHandleExW", wtoa_function(GetModuleHandleExA) },
	{ "GetProcAddress", GetProcAddress },
	{ "LoadLibraryA", LoadLibraryA },
	{ "LoadLibraryW", wtoa_function(LoadLibraryA) },
	{ "LoadLibraryExA", LoadLibraryExA },
	{ "LoadLibraryExW", wtoa_function(LoadLibraryExA) },
	{ "FreeLibrary", FreeLibrary },
	{ "DisableThreadLibraryCalls", DisableThreadLibraryCalls },
	{ "HeapCreate", HeapCreate },
	{ "HeapAlloc", HeapAlloc },
	{ "HeapFree", HeapFree },
	{ "HeapSize", HeapSize },
	{ "InitializeCriticalSection", InitializeCriticalSection },
	{ "InitializeCriticalSectionAndSpinCount", InitializeCriticalSectionAndSpinCount },
	{ "DeleteCriticalSection", DeleteCriticalSection },
	{ "EnterCriticalSection", EnterCriticalSection },
	{ "LeaveCriticalSection", LeaveCriticalSection },
	{ "FlsAlloc", FlsAlloc },
	{ "FlsFree", FlsFree },
	{ "FlsSetValue", FlsSetValue },
	{ "FlsGetValue", FlsGetValue },
	{ "GetModuleFileNameA", GetModuleFileNameA },
	{ "GetCurrentThreadId", GetCurrentThreadId },
	{ "GetStartupInfoA", GetStartupInfoA },
	{ "GetStartupInfoW", GetStartupInfoW },
	{ "GetStdHandle", GetStdHandle },
	{ "GetFileType", GetFileType },
	{ "SetHandleCount", SetHandleCount },
	{ "VirtualQuery", VirtualQuery },
	{ "VirtualAlloc", VirtualAlloc },
	{ "VirtualFree", VirtualFree },
	{ "VirtualLock", VirtualLock },
	{ "VirtualUnlock", VirtualUnlock },
	{ "UnhandledExceptionFilter", UnhandledExceptionFilter },
	{ "SetUnhandledExceptionFilter", SetUnhandledExceptionFilter },
	{ "GetCommandLineA", GetCommandLineA },
	{ "GetCommandLineW", GetCommandLineW },
	{ "GetEnvironmentStringsW", GetEnvironmentStringsW },
	{ "FreeEnvironmentStringsW", FreeEnvironmentStringsW },
	{ "WideCharToMultiByte", WideCharToMultiByte },
	{ "GetACP", GetACP },
	{ "GetCPInfo", GetCPInfo },
	{ "IsProcessorFeaturePresent", IsProcessorFeaturePresent },
	{ "GetSystemTimeAsFileTime", GetSystemTimeAsFileTime },
	{ "GetCurrentProcessId", GetCurrentProcessId },
	{ "GetTickCount", GetTickCount },
	{ "GetTickCount64", GetTickCount64 },
	{ "QueryPerformanceCounter", QueryPerformanceCounter },
	{ "CreateEventA", CreateEventA },
	{ "CreateEventW", wtoa_function(CreateEventA) },
	{ "GetSystemInfo", GetSystemInfo },
	{ "GetDiskFreeSpaceA", GetDiskFreeSpaceA },
	{ "GetDiskFreeSpaceW", wtoa_function(GetDiskFreeSpaceA) },
	{ "GlobalMemoryStatus", GlobalMemoryStatus },
	{ "GetCurrentProcess", GetCurrentProcess },
	{ "SetConsoleCtrlHandler", SetConsoleCtrlHandler },
	{ "CreateThread", CreateThread },
	{ "SetThreadPriority", SetThreadPriority },
	{ "GetFileAttributesA", GetFileAttributesA },
	{ "GetFileAttributesW", wtoa_function(GetFileAttributesA) },
	{ "GetFullPathNameA", GetFullPathNameA },
	{ "GetDriveTypeA", GetDriveTypeA },
	{ "GetDriveTypeW", wtoa_function(GetDriveTypeA) },
	{ "GetVolumeInformationA", GetVolumeInformationA },
	{ "GetVolumeInformationW", wtoa_function(GetVolumeInformationA) },
	{ "CreateFileA", CreateFileA },
	{ "CreateFileW", wtoa_function(CreateFileA) },
	{ "SetFilePointer", SetFilePointer },
	{ "ReadFile", ReadFile },
	{ "GetFileSize", GetFileSize },
	{ "InterlockedIncrement", InterlockedIncrement },
	{ "GetProcessHeap", GetProcessHeap },
	{ "FindFirstFileA", FindFirstFileA },
	{ "FindNextFileA", FindNextFileA },
	{ "FindClose", FindClose },
	{ "WaitForSingleObject", WaitForSingleObject },
	{ "WaitForMultipleObjects", WaitForMultipleObjects },
	{ "Sleep", Sleep },
	{ "SetEvent", SetEvent },
	{ "CloseHandle", CloseHandle },
	{ "EncodePointer", EncodePointer },
	{ "DecodePointer", DecodePointer },
	{ "IsDebuggerPresent", IsDebuggerPresent },
	{ "InitializeSListHead", InitializeSListHead },
	{ "InterlockedFlushSList", InterlockedFlushSList },
	{ "CreateMutexA", CreateMutexA },
	{ "CreateMutexW", wtoa_function(CreateMutexA) },
	{ "ReleaseMutex", ReleaseMutex },
	{ "CreateFileMappingA", CreateFileMappingA },
	{ "CreateFileMappingW", wtoa_function(CreateFileMappingA) },
	{ "MapViewOfFile", MapViewOfFile },
	{ "UnmapViewOfFile", UnmapViewOfFile },
	{ "GetUserDefaultLangID", GetUserDefaultLangID },
	{ "SetErrorMode", SetErrorMode },
	{ "GetProfileIntA", GetProfileIntA },
	{ "GetProfileIntW", wtoa_function(GetProfileIntA) },
	{ "CreateDirectoryA", CreateDirectoryA },
	{ "CreateDirectoryW", wtoa_function(CreateDirectoryA) },
	{ "FindResourceA", FindResourceA },
	{ "FindResourceW", wtoa_function(FindResourceA) },
	{ "SizeofResource", SizeofResource },
	{ "LoadResource", LoadResource },
	{ "LockResource", LockResource },
	{ "DeleteFileA", DeleteFileA },
	{ "DeleteFileW", wtoa_function(DeleteFileA) },
});


}

