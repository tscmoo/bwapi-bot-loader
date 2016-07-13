#include <cstdint>
#include <cstdlib>

namespace native_api {

	enum class memory_access {
		none,
		read,
		read_write,
		read_execute,
		read_write_execute
	};

	struct allocated_memory {
		void* ptr;
		size_t size;
		void* detach() {
			void* r = ptr;
			ptr = nullptr;
			return r;
		}
		allocated_memory() = default;
		explicit allocated_memory(void* ptr, size_t size) : ptr(ptr), size(size) {}
		explicit allocated_memory(size_t size, memory_access access) : ptr(nullptr) {
			allocate(size, access);
		}
		~allocated_memory() {
			deallocate();
		}
		explicit operator bool() {
			return ptr != nullptr;
		}

		void allocate(size_t size, memory_access access);
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

	class file_io {
		void* h;
	public:
		file_io();
		~file_io();
		bool open(const char* fn, file_access access, file_open_mode mode);
		bool read(void* buffer, size_t size);
		void set_pos(uint64_t pos);
		uint64_t get_pos();
	};

};

