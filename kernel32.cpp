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

namespace kernel32 {
;

struct TLB {
	DWORD last_error = 0;
	modules::module_info* main_module_info;
	DWORD thread_id = 0;
};

thread_local TLB tlb;


DWORD WINAPI GetLastError() {
	return tlb.last_error;
}

void WINAPI SetLastError(DWORD err) {
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
	auto* i = name ? modules::get_module_info(name) : tlb.main_module_info;
	if (!i) {
		log("module '%s' not found\n", name);
		SetLastError(ERROR_MOD_NOT_FOUND);
		return nullptr;
	}
	log("module '%s' is at %p\n", name, i->base);
	return i->base;
}

void* WINAPI GetProcAddress(HMODULE hm, const char* name) {
	auto* i = hm ? modules::get_module_info(hm) : tlb.main_module_info;
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
	auto* i = modules::get_module_info(hm);
	if (!i) {
		SetLastError(ERROR_MOD_NOT_FOUND);
		return 0;
	}
	auto& module_filename = i->name;
	if (size < module_filename.size() + 1) {
		if (size) {
			memcpy(dst, module_filename.data(), size - 1);
			dst[size - 1] = 0;
		}
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return size;
	} else {
		memcpy(dst, module_filename.data(), module_filename.size());
		dst[module_filename.size()] = 0;
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

struct io_handle {
};

io_handle null_handle;

HANDLE WINAPI GetStdHandle(DWORD n) {
	if (n == (DWORD)-10) return &null_handle;
	if (n == (DWORD)-11) return &null_handle;
	if (n == (DWORD)-12) return &null_handle;
	SetLastError(ERROR_INVALID_PARAMETER);
	return INVALID_HANDLE_VALUE;
}

DWORD WINAPI GetFileType(HANDLE h) {
	return 2;
}

UINT WINAPI SetHandleCount(UINT) {
	return std::numeric_limits<size_t>::max() / sizeof(io_handle);
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

void add_virtual_region(void* addr, size_t size, DWORD state, PAGE_PROTECT protect) {
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

void* virtual_allocate_nolock(void* addr, size_t size, DWORD allocation_type, PAGE_PROTECT protect, void* preferred_addr) {
	native_api::allocated_memory mem;
	native_api::memory_access access = native_api::memory_access::none;
	if (allocation_type & MEM_COMMIT) {
		access = access_from_protect(protect);
	} else protect = PAGE_NOACCESS;
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
	log("virtual regions -\n");
	for (auto& v : virtual_regions) {
		log(" [%p, %p)\n", v.second.base, (uint8_t*)v.second.base + v.second.size);
	}
	return ptr;
}
void virtual_deallocate_nolock(virtual_region* r) {
	native_api::allocated_memory mem(r->base, r->size);
	log("released [%p, %p)\n", r->base, (uint8_t*)r->base + r->size);
	remove_virtual_region_nolock(r->base);
}

void* virtual_allocate(void* addr, size_t size, DWORD allocation_type, PAGE_PROTECT protect, void* preferred_addr) {
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
		if (r->pages[p].state & MEM_COMMIT && ~r->pages[p].protect != protect) {
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
		SetLastError(ERROR_INVALID_ADDRESS);
		log("VirtualAlloc failed\n");
		return nullptr;
	}
	if (addr) {
		if (allocation_type & MEM_RESERVE) {
			SetLastError(ERROR_INVALID_ADDRESS);
			log("VirtualAlloc failed\n");
			return nullptr;
		}
	}
	std::lock_guard<std::mutex> l(virtual_mut);
	if (addr) {
		auto* r = find_virtual_region(addr);
		if (!r) {
			SetLastError(ERROR_INVALID_ADDRESS);
			log("VirtualAlloc failed\n");
			return nullptr;
		}
		if (allocation_type & MEM_COMMIT) {
			uintptr_t offset = ((uintptr_t)addr - (uintptr_t)r->base) & ~0xfff;
			size_t page = offset / 0x1000;
			size_t pages = (size + 0xfff) / 0x1000;
			auto access = access_from_protect(protect);
			for (size_t i = 0; i != pages; ++i) {
				size_t p = page + i;

				if (~r->pages[p].state & MEM_COMMIT) {
					native_api::set_memory_access((uint8_t*)r->base + p * 0x1000, 0x1000, access);
					r->pages[p].state |= MEM_COMMIT;
					r->pages[p].protect = protect;
					log("committed a page\n");
				}
			}
		}
		return r->base;
	}
	if (~allocation_type & MEM_RESERVE) {
		SetLastError(ERROR_INVALID_PARAMETER);
		log("VirtualAlloc failed\n");
		return nullptr;
	}
	void* ptr = virtual_allocate_nolock(addr, size, allocation_type, protect, nullptr);
	if (!ptr) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		log("VirtualAlloc failed\n");
		return nullptr;
	}
	return ptr;
}

BOOL WINAPI VirtualFree(void* addr, SIZE_T size, DWORD free_type) {
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
			if (r->pages[p].state & MEM_COMMIT) {
				native_api::set_memory_access((uint8_t*)r->base + p * 0x1000, 0x1000, native_api::memory_access::none);
				r->pages[p].state &= MEM_COMMIT;
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

std::string cmdline = "";

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

void WINAPI GetSystemTimeAsFileTime(uint64_t* out) {
	auto c = std::chrono::duration_cast<std::chrono::duration<uint64_t, std::ratio<1, 10000000>>>((std::chrono::system_clock::now() - std::chrono::system_clock::from_time_t(0)));
	*out = c.count() + 116444736000000000;
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

struct object {
	enum { t_invalid, t_thread, t_event };
	object(int type) : type(type) {}
	virtual ~object() {}
	int type;
	std::atomic<int> refcount = 1;
};

template<typename T>
struct handle {
	T* ptr = nullptr;
	handle(T* ptr) : ptr(ptr) {}
	handle(const handle& n) {
		ptr = n.ptr;
		if (ptr) ++ptr->refcount;
	}
	handle(handle&& n) {
		ptr = n.ptr;
		n.ptr = nullptr;
	}
	~handle() {
		if (ptr && --ptr->refcount == 0) {
			delete ptr;
		}
	}
	handle& operator=(const handle& n) {
		ptr = n.ptr;
		if (ptr) ++ptr->refcount;
	}
	handle& operator=(handle&& n) {
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
};

template<typename T>
handle<T> new_object() {
	return handle<T>(new T());
}

struct event: object {
	event() : object(object::t_event) {}
	bool manual_reset = false;
};

std::list<event> all_events;
std::mutex events_mut;

HANDLE WINAPI CreateEventA(void* security_attributes, BOOL manual_reset, BOOL initial_state, const char* name) {
	std::lock_guard<std::mutex> l(events_mut);
	all_events.emplace_back();
	auto* e = &all_events.back();
	e->manual_reset = manual_reset != FALSE;
	log("CreateEventA '%s' -> %p\n", name, e);
	return e;
}

struct thread: object {
	thread() : object(object::t_thread) {}
	DWORD id = 0;
	std::thread thread_obj;
	bool running = true;
	DWORD exit_code = 259;
};

std::vector<std::atomic<thread*>> all_threads(0x10000);
std::atomic<size_t> thread_ids_available = all_threads.size() - 1;
std::atomic<size_t> next_thread_id = 1;

handle<thread> new_thread() {
	auto t = new_object<thread>();
	for (size_t i = next_thread_id;;++i) {
		if (i >= all_threads.size()) i = 1;
		if (thread_ids_available == 0) return nullptr;
		auto& ref = all_threads[i];
		auto val = ref.load(std::memory_order_consume);
		if (val) continue;
		if (!ref.compare_exchange_weak(val, &*t, std::memory_order_relaxed)) continue;
		next_thread_id = i + 1;
		--thread_ids_available;
		t->id = i;
		break;
	}
	return t;
}

HANDLE WINAPI CreateThread(void* security_attributes, SIZE_T stack_size, void* start_address, void* parameter, DWORD creation_flags, DWORD* thread_id) {
	if (creation_flags & 4) {
		SetLastError(ERROR_NOT_SUPPORTED);
		log("CreateThread: CREATE_SUSPENDED is not supported");
		return nullptr;
	}
	auto t = new_thread();
	if (!t) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return nullptr;
	}
	log("created a new thread with id %d\n", t->id);
	t->thread_obj = std::thread(std::bind(environment::enter_thread, [t, start_address, parameter]() {
		tlb.thread_id = t->id;
		log("thread running, yey\n");
		modules::call_thread_attach();
		t->exit_code = ((DWORD(WINAPI*)(void*))start_address)(parameter);
		modules::call_thread_detach();
		t->running = false;
	}));
	if (thread_id) *thread_id = t->id;
	return &*t;
}

BOOL WINAPI SetThreadPriority(HANDLE h, int priority) {
	SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}

void set_main_module(modules::module_info* i) {
	tlb.main_module_info = i;
	tlb.thread_id = new_thread()->id;
	log("main thread id is %d\n", tlb.thread_id);
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
	for (size_t i = 0; i < std::min(s.size() + 1, (size_t)buflen); ++i) {
		buf[i] = s.data()[i];
	}
	if (s.size() + 1 > buflen) {
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return s.size() + 1;
	}
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
});


}

