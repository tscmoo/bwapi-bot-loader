#include "native_api.h"
//#include "environment.h"

#include <cstdint>
#include <algorithm>
#include <chrono>
#include <cstddef>

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
		if (mode == file_open_mode::create_always) creation_disposition = CREATE_ALWAYS;
		h = CreateFileA(fn, desired_access, FILE_SHARE_READ, nullptr, creation_disposition, 0, nullptr);
		return h != INVALID_HANDLE_VALUE;
	}
	bool read(void* buffer, size_t size, size_t* read) {
		DWORD dw_read = 0;
		BOOL r = ReadFile(h, buffer, size, &dw_read, nullptr);
		*read = (size_t)dw_read;
		return r != FALSE;
	}
	bool write(void* buffer, size_t size, size_t* written) {
		DWORD dw_written = 0;
		BOOL r = WriteFile(h, buffer, size, &dw_written, nullptr);
		*written = (size_t)dw_written;
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
	uint64_t get_size() {
		uint64_t r = 0;
		GetFileSizeEx(h, (LARGE_INTEGER*)&r);
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

bool is_directory(const char* path) {
	DWORD attr = GetFileAttributesA(path);
	if (attr == INVALID_FILE_ATTRIBUTES) return false;
	return attr & FILE_ATTRIBUTE_DIRECTORY ? true : false;
}

bool is_file(const char* path) {
	DWORD attr = GetFileAttributesA(path);
	if (attr == INVALID_FILE_ATTRIBUTES) return false;
	return ~attr & FILE_ATTRIBUTE_DIRECTORY ? true : false;
}

bool delete_file(const char* path) {
	return DeleteFileA(path) ? true : false;
}

bool create_directory(const char* path) {
	return CreateDirectoryA(path, nullptr) ? true : false;
}

template<typename T, typename std::enable_if<sizeof(T) == sizeof(long)>::type* = nullptr>
T fetch_add(T* ptr) {
	return _InterlockedIncrement((long*)ptr) - 1;
}

int32_t fetch_add(int32_t* ptr) {
	return fetch_add<int32_t>(ptr);
}

template<typename T, typename std::enable_if<sizeof(T) == sizeof(long)>::type* = nullptr>
bool compare_exchange_impl(T* ptr, T& expected, T desired) {
	auto old_expected = expected;
	return (expected = _InterlockedCompareExchange((long*)ptr, (long)desired, (long)expected)) == old_expected;
}

template<typename T, typename std::enable_if<sizeof(T) == sizeof(long long)>::type* = nullptr>
bool compare_exchange_impl(T* ptr, T& expected, T desired) {
	auto old_expected = expected;
	return (expected = _InterlockedCompareExchange64((long long*)ptr, (long long)desired, (long long)expected)) == old_expected;
}

bool compare_exchange(int32_t* ptr, int32_t& expected, int32_t desired) {
	return compare_exchange_impl<int32_t>(ptr, expected, desired);
}

bool compare_exchange(int64_t* ptr, int64_t& expected, int64_t desired) {
	return compare_exchange_impl<int64_t>(ptr, expected, desired);
}

struct shm_io_impl {
	HANDLE h;
	shm_io_impl() {
		h = nullptr;
	}
	~shm_io_impl() {
		if (h) CloseHandle(h);
	}
	bool open(const char* fn, uint64_t size) {
		std::string str_fn = "Global\\";
		str_fn += fn;
		h = CreateFileMappingA(nullptr, nullptr, PAGE_READWRITE, size >> 32, (DWORD)size, str_fn.c_str());
		return h != nullptr;
	}
	void* map(void* addr, uint64_t offset, size_t size, int flags) {
		DWORD access = 0;
		if (flags & shm_io_read) access |= FILE_MAP_READ;
		if (flags & shm_io_write) access |= FILE_MAP_WRITE;
		if (flags & shm_io_copy_on_write) access |= FILE_MAP_COPY;
		return MapViewOfFileEx(h, access, offset >> 32, (DWORD)offset, size, addr);
	}
};

}

#else

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

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
		if (mode == file_open_mode::create_always) flags |= O_CREAT | O_TRUNC;
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
	bool write(void* buffer, size_t size, size_t* out_written) {
		*out_written = 0;
		auto r = ::write(fd, buffer, size);
		if (r >= 0 && r <= size) {
			*out_written = (size_t)r;
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
		uint64_t get_size() {
		uint64_t r = 0;
		struct stat st;
		if (fstat(fd, &st) == 0) {
			r = (uint64_t)st.st_size;
		}
		return r;
	}
};

struct directory_io_impl {
	std::string path;
	DIR* dir = nullptr;
	struct stat st;
	union {
		dirent d;
		char b[offsetof(dirent, d_name) + NAME_MAX + 1];
	} ent;
	directory_io_impl() {
	}
	~directory_io_impl() {
		if (dir) closedir(dir);
	}
	bool open(const char* fn) {
		dir = opendir(fn);
		if (dir) {
			path = fn;
			next();
		}
		return dir != nullptr;
	}
	bool next() {
		dirent* res = nullptr;
		if (readdir_r(dir, &ent.d, &res) == 0) {
			return stat((path + ent.d.d_name).c_str(), &st) == 0;
		}
		return false;
	}
	directory_entry get() {
		directory_entry r;
		r.file_name = ent.d.d_name;
		r.creation_time = std::chrono::system_clock::from_time_t(st.st_ctime);
		r.access_time = std::chrono::system_clock::from_time_t(st.st_atime);
		r.write_time = std::chrono::system_clock::from_time_t(st.st_mtime);
		r.file_size = st.st_size;
		r.is_directory = (st.st_mode & S_IFDIR) != 0;
		return r;
	}
};

bool is_directory(const char* path) {
	struct stat st;
	if (stat(path, &st) != 0) return false;
	return S_ISDIR(st.st_mode);
}

bool is_file(const char* path) {
	struct stat st;
	if (stat(path, &st) != 0) return false;
	return !S_ISDIR(st.st_mode);
}

bool delete_file(const char* path) {
	return unlink(path) == 0;
}

bool create_directory(const char* path) {
	return mkdir(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
}

template<typename T>
T fetch_add(T* ptr) {
	return __sync_fetch_and_add(ptr, 1);
}

int32_t fetch_add(int32_t* ptr) {
	return fetch_add<int32_t>(ptr);
}

template<typename T>
bool compare_exchange_impl(T* ptr, T& expected, T desired) {
	bool r = __sync_bool_compare_and_swap(ptr, expected, desired);
	if (r) expected = desired;
	return r;
}

bool compare_exchange(int32_t* ptr, int32_t& expected, int32_t desired) {
	return compare_exchange_impl<int32_t>(ptr, expected, desired);
}

bool compare_exchange(int64_t* ptr, int64_t& expected, int64_t desired) {
	return compare_exchange_impl<int64_t>(ptr, expected, desired);
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
bool file_io::write(void* buffer, size_t size, size_t* written) {
	return impl->write(buffer, size, written);
}
uint64_t file_io::set_pos(uint64_t pos, file_set_pos_origin origin) {
	return impl->set_pos(pos, origin);
}
uint64_t file_io::get_pos() {
	return impl->get_pos();
}
uint64_t file_io::get_size() {
	return impl->get_size();
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

// shm_io::shm_io() {
// 	impl = std::make_unique<shm_io_impl>();
// }
// shm_io::shm_io(shm_io&& n) = default;
// shm_io::~shm_io() {
// }
// shm_io& shm_io::operator=(shm_io&& n) = default;
// bool shm_io::open(const char* fn, uint64_t size) {
// 	return impl->open(fn, size);
// }
// void* shm_io::map(void* addr, uint64_t offset, size_t size, int flags) {
// 	return impl->map(addr, offset, size, flags);
// }

}

