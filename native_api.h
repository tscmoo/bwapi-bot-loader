#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <chrono>

namespace native_api {

	enum class memory_access {
		none,
		read,
		read_write,
		read_execute,
		read_write_execute
	};

	struct allocated_memory {
		void* ptr = nullptr;
		size_t size = 0;
		void* detach() {
			void* r = ptr;
			ptr = nullptr;
			return r;
		}
		allocated_memory() = default;
		explicit allocated_memory(void* ptr, size_t size) : ptr(ptr), size(size) {}
		explicit allocated_memory(void* addr, size_t size, memory_access access) : ptr(nullptr) {
			allocate(addr, size, access);
		}
		~allocated_memory() {
			deallocate();
		}
		explicit operator bool() {
			return ptr != nullptr;
		}

		void allocate(void* addr, size_t size, memory_access access);
		void deallocate();
	};

	bool set_memory_access(void* ptr, size_t size, memory_access access);

	enum class file_access {
		read,
		read_write
	};

	enum class file_open_mode {
		open_existing,
		create_new
	};

	enum class file_set_pos_origin {
		begin,
		current,
		end
	};

	struct file_io_impl;

	class file_io {
		std::unique_ptr<file_io_impl> impl;
	public:
		file_io();
		file_io(file_io&& n);
		~file_io();
		bool open(const char* fn, file_access access, file_open_mode mode);
		bool read(void* buffer, size_t size);
		uint64_t set_pos(uint64_t pos, file_set_pos_origin origin);
		uint64_t get_pos();
	};

	struct directory_io_impl;

	struct directory_entry {
		std::string file_name;
		std::chrono::system_clock::time_point creation_time;
		std::chrono::system_clock::time_point access_time;
		std::chrono::system_clock::time_point write_time;
		uint64_t file_size = 0;
		bool is_directory = false;
	};

	struct directory_io {
		std::unique_ptr<directory_io_impl> impl;
	public:
		directory_io();
		directory_io(directory_io&& n);
		~directory_io();
		bool open(const char* fn);
		directory_entry get();
		bool next();
	};

	int32_t interlocked_increment(int32_t*);

};

