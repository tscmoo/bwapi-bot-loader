#include "native_api.h"
#include "environment.h"

#include <cstdint>

#ifdef _WIN32
#include <windows.h>

namespace native_api {
;

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

file_io::file_io() {
	h = INVALID_HANDLE_VALUE;
}
file_io::~file_io() {
	if (h) CloseHandle(h);
}
bool file_io::open(const char* fn, file_access access, file_open_mode mode) {
	DWORD desired_access = 0;
	if (access == file_access::read) desired_access = GENERIC_READ;
	else if (access == file_access::read_write) desired_access = GENERIC_READ | GENERIC_WRITE;
	DWORD creation_disposition = OPEN_EXISTING;
	if (mode == file_open_mode::open_existing) creation_disposition = OPEN_EXISTING;
	if (mode == file_open_mode::create_new) creation_disposition = CREATE_NEW;
	h = CreateFileA(fn, desired_access, FILE_SHARE_READ, nullptr, creation_disposition, 0, nullptr);
	return h != INVALID_HANDLE_VALUE;
}
bool file_io::read(void* buffer, size_t size) {
	DWORD read = 0;
	return ReadFile(h, buffer, size, &read, nullptr) && read == size;
}
void file_io::set_pos(uint64_t pos) {
	SetFilePointerEx(h, (LARGE_INTEGER&)pos, nullptr, FILE_BEGIN);
}
uint64_t file_io::get_pos() {
	uint64_t move = 0;
	uint64_t r = 0;
	SetFilePointerEx(h, (LARGE_INTEGER&)move, &(LARGE_INTEGER&)r, FILE_CURRENT);
	return r;
}

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

}

#endif

