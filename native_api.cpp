#include "native_api.h"
#include "environment.h"

#include <cstdint>
#include <algorithm>

namespace native_api {
	;

struct file_io_impl;

#ifdef _WIN32
#include <windows.h>

void allocated_memory::allocate(void* addr, size_t size, memory_access access) {
	if (ptr) deallocate();
	DWORD protect = 0;
	if (access == memory_access::none) protect = PAGE_NOACCESS;
	else if (access == memory_access::read) protect = PAGE_READONLY;
	else if (access == memory_access::read_write) protect = PAGE_READWRITE;
	else if (access == memory_access::read_execute) protect = PAGE_EXECUTE_READ;
	else if (access == memory_access::read_write_execute) protect = PAGE_EXECUTE_READWRITE;
	ptr = VirtualAlloc(addr, size, MEM_RESERVE | MEM_COMMIT, protect);
	if (ptr && addr && ptr != addr) {
		VirtualFree(ptr, 0, MEM_RELEASE);
		ptr = nullptr;
	}
	this->size = ptr ? size : 0;
}
void allocated_memory::deallocate() {
	if (!ptr) return;
	VirtualFree(ptr, 0, MEM_RELEASE);
	ptr = nullptr;
	size = 0;
}

bool set_memory_access(void* ptr, size_t size, memory_access access) {
	DWORD protect = 0;
	if (access == memory_access::none) protect = PAGE_NOACCESS;
	else if (access == memory_access::read) protect = PAGE_READONLY;
	else if (access == memory_access::read_write) protect = PAGE_READWRITE;
	else if (access == memory_access::read_execute) protect = PAGE_EXECUTE_READ;
	else if (access == memory_access::read_write_execute) protect = PAGE_EXECUTE_READWRITE;
	DWORD old_protect;
	return VirtualProtect(ptr, size, protect, &old_protect) != FALSE;
}

struct file_io_impl {
	HANDLE h;
	file_io_impl() {
		h = INVALID_HANDLE_VALUE;
	}
	~file_io_impl() {
		if (h) CloseHandle(h);
	}
	bool open(const char* fn, file_access access, file_open_mode mode) {
		DWORD desired_access = 0;
		if (access == file_access::read) desired_access = GENERIC_READ;
		else if (access == file_access::read_write) desired_access = GENERIC_READ | GENERIC_WRITE;
		DWORD creation_disposition = OPEN_EXISTING;
		if (mode == file_open_mode::open_existing) creation_disposition = OPEN_EXISTING;
		if (mode == file_open_mode::create_new) creation_disposition = CREATE_NEW;
		h = CreateFileA(fn, desired_access, FILE_SHARE_READ, nullptr, creation_disposition, 0, nullptr);
		return h != INVALID_HANDLE_VALUE;
	}
	bool read(void* buffer, size_t size) {
		DWORD read = 0;
		return ReadFile(h, buffer, size, &read, nullptr) && read == size;
	}
	uint64_t set_pos(uint64_t pos, file_set_pos_origin origin) {
		uint64_t r = 0;
		DWORD move_method = FILE_BEGIN;
		if (origin == file_set_pos_origin::current) move_method = FILE_CURRENT;
		if (origin == file_set_pos_origin::end) move_method = FILE_END;
		SetFilePointerEx(h, (LARGE_INTEGER&)pos, &(LARGE_INTEGER&)r, move_method);
		return r;
	}
	uint64_t get_pos() {
		uint64_t move = 0;
		uint64_t r = 0;
		SetFilePointerEx(h, (LARGE_INTEGER&)move, &(LARGE_INTEGER&)r, FILE_CURRENT);
		return r;
	}
};

template<typename T, typename std::enable_if<sizeof(T) == sizeof(long)>::type* = nullptr>
T interlocked_increment(T* ptr) {
	return _InterlockedIncrement((long*)ptr);
}

int32_t interlocked_increment(int32_t* ptr) {
	return interlocked_increment<int32_t>(ptr);
}

#else

#include <sys/mman.h>
#include <cstdio>

namespace native_api {
;

void allocated_memory::allocate(void* addr, size_t size, memory_access access) {
	if (ptr) deallocate();
	int protect = 0;
	if (access == memory_access::none) protect = PROT_NONE;
	else if (access == memory_access::read) protect = PROT_READ;
	else if (access == memory_access::read_write) protect = PROT_READ | PROT_WRITE;
	else if (access == memory_access::read_execute) protect = PROT_READ | PROT_EXEC;
	else if (access == memory_access::read_write_execute) protect = PROT_READ | PROT_WRITE | PROT_EXEC;
	ptr = mmap(addr, size, protect, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ptr && addr && ptr != addr) {
		munmap(ptr, size);
		ptr = nullptr;
	}
	this->size = ptr ? size : 0;
}
void allocated_memory::deallocate() {
	if (!ptr) return;
	munmap(ptr, size);
	ptr = nullptr;
	size = 0;
}

bool set_memory_access(void* ptr, size_t size, memory_access access) {
	int protect = 0;
	if (access == memory_access::none) protect = PROT_NONE;
	else if (access == memory_access::read) protect = PROT_READ;
	else if (access == memory_access::read_write) protect = PROT_READ | PROT_WRITE;
	else if (access == memory_access::read_execute) protect = PROT_READ | PROT_EXEC;
	else if (access == memory_access::read_write_execute) protect = PROT_READ | PROT_WRITE | PROT_EXEC;
	return mprotect(ptr, size, protect) == 0;
}

file_io::file_io() {
	h = nullptr;
}
file_io::~file_io() {
	if (h) fclose((FILE*)h);
}
bool file_io::open(const char* fn, file_access access, file_open_mode mode) {
	const char* open_mode = "r";
	if (access == file_access::read) open_mode = "rb";
	else if (access == file_access::read_write) open_mode = "wb";
	h = fopen(fn, open_mode);
	return h != nullptr;
}
bool file_io::read(void* buffer, size_t size) {
	return fread(buffer, size, 1, (FILE*)h);
}
void file_io::set_pos(uint64_t pos) {
	fseek((FILE*)h, (size_t)pos, SEEK_SET);
}
uint64_t file_io::get_pos() {
	return ftell((FILE*)h);
}

#endif


file_io::file_io() {
	impl = std::make_unique<file_io_impl>();
}
file_io::file_io(file_io&& n) {
	std::swap(impl, n.impl);
}
file_io::~file_io() {
}
bool file_io::open(const char* fn, file_access access, file_open_mode mode) {
	return impl->open(fn, access, mode);
}
bool file_io::read(void* buffer, size_t size) {
	return impl->read(buffer, size);
}
uint64_t file_io::set_pos(uint64_t pos, file_set_pos_origin origin) {
	return impl->set_pos(pos, origin);
}
uint64_t file_io::get_pos() {
	return impl->get_pos();
}

}

