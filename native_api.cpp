#include "native_api.h"
//#include "environment.h"

#include <cstdint>
#include <algorithm>
#include <chrono>

static std::chrono::system_clock::time_point FILETIME_to_time_point(uint64_t time) {
	auto r = std::chrono::system_clock::from_time_t(0);
	return r + std::chrono::duration<uint64_t, std::ratio<1, 10000000>>(time - 116444736000000000);
}

struct file_io_impl;

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

struct file_io_impl {
	HANDLE h;
	file_io_impl() {
		h = INVALID_HANDLE_VALUE;
	}
	~file_io_impl() {
		if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
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
	bool read(void* buffer, size_t size, size_t* read) {
		DWORD dw_read = 0;
		BOOL r = ReadFile(h, buffer, size, &dw_read, nullptr);
		*read = (size_t)dw_read;
		return r != FALSE;
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

struct directory_io_impl {
	HANDLE h;
	WIN32_FIND_DATAA data;
	directory_io_impl() {
		h = INVALID_HANDLE_VALUE;
	}
	~directory_io_impl() {
		if (h != INVALID_HANDLE_VALUE) FindClose(h);
	}
	bool open(const char* fn) {
		std::string str = fn;
		str += "\\*";
		h = FindFirstFileA(str.c_str(), &data);
		return h != INVALID_HANDLE_VALUE;
	}
	bool next() {
		return FindNextFileA(h, &data) != FALSE;
	}
	directory_entry get() {
		directory_entry r;
		r.file_name = data.cFileName;
		r.creation_time = FILETIME_to_time_point((uint64_t&)data.ftCreationTime);
		r.access_time = FILETIME_to_time_point((uint64_t&)data.ftLastAccessTime);
		r.write_time = FILETIME_to_time_point((uint64_t&)data.ftLastWriteTime);
		r.file_size = data.nFileSizeLow | ((uint64_t)data.nFileSizeHigh << 32);
		r.is_directory = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
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

}

#else

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

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

struct file_io_impl {
	int fd;
	file_io_impl() {
		fd = -1;
	}
	~file_io_impl() {
		if (fd >= 0) close(fd);
	}
	bool open(const char* fn, file_access access, file_open_mode mode) {
		int flags = 0;
		if (access == file_access::read) flags |= O_RDONLY;
		else if (access == file_access::read_write) flags |= O_RDWR;
		if (mode == file_open_mode::open_existing) flags |= 0;
		if (mode == file_open_mode::create_new) flags |= O_CREAT | O_EXCL;
		fd = open64(fn, flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
		return fd >= 0;
	}
	bool read(void* buffer, size_t size, size_t* out_read) {
		*out_read = 0;
		auto r = ::read(fd, buffer, size);
		if (r >= 0 && r <= size) {
			*out_read = (size_t)r;
			return true;
		}
		return false;
	}
	uint64_t set_pos(uint64_t pos, file_set_pos_origin origin) {
		int whence = SEEK_SET;
		if (origin == file_set_pos_origin::current) whence = SEEK_CUR;
		if (origin == file_set_pos_origin::end) whence = SEEK_END;
		auto r = lseek64(fd, pos, whence);
		if (r < 0) r = 0;
		return r;
	}
	uint64_t get_pos() {
		auto r = lseek64(fd, 0, SEEK_CUR);
		if (r < 0) r = 0;
		return r;
	}
};

template<typename T>
T interlocked_increment(T* ptr) {
	return __sync_fetch_and_add(ptr, 1) + 1;
}

int32_t interlocked_increment(int32_t* ptr) {
	return interlocked_increment<int32_t>(ptr);
}


}

#endif

namespace native_api {
;

file_io::file_io() {
	impl = std::make_unique<file_io_impl>();
}
file_io::file_io(file_io&& n) = default;
file_io::~file_io() {
}
file_io& file_io::operator=(file_io&& n) = default;
bool file_io::open(const char* fn, file_access access, file_open_mode mode) {
	return impl->open(fn, access, mode);
}
bool file_io::read(void* buffer, size_t size, size_t* read) {
	return impl->read(buffer, size, read);
}
uint64_t file_io::set_pos(uint64_t pos, file_set_pos_origin origin) {
	return impl->set_pos(pos, origin);
}
uint64_t file_io::get_pos() {
	return impl->get_pos();
}

directory_io::directory_io() {
	impl = std::make_unique<directory_io_impl>();
}
directory_io::directory_io(directory_io&& n) = default;
directory_io::~directory_io() {
}
directory_io& directory_io::operator=(directory_io&& n) = default;
bool directory_io::open(const char* fn) {
	return impl->open(fn);
}
directory_entry directory_io::get() {
	return impl->get();
}
bool directory_io::next() {
	return impl->next();
}

}

