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
		file_io& operator=(file_io&& n);
		bool open(const char* fn, file_access access, file_open_mode mode);
		bool read(void* buffer, size_t size, size_t* read);
		uint64_t set_pos(uint64_t pos, file_set_pos_origin origin);
		uint64_t get_pos();
		uint64_t get_size();
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
		directory_io& operator=(directory_io&& n);
		bool open(const char* fn);
		directory_entry get();
		bool next();
	};

	bool is_directory(const char* path);
	bool is_file(const char* path);
	bool delete_file(const char* path);

	int32_t fetch_add(int32_t*);
	bool compare_exchange(int64_t* pointer, int64_t& expected, int64_t desired);

	template<size_t size, size_t alignment> struct atomic_type;
	template<size_t alignment>
	struct atomic_type<4, alignment> {
		using type = typename std::enable_if<alignment <= 4 && (alignment & (alignment - 1)) == 0, int32_t>::type;
	};
	template<size_t alignment>
	struct atomic_type<8, alignment> {
		using type = typename std::enable_if<alignment <= 8 && (alignment & (alignment - 1)) == 0, int64_t>::type;
	};

	template<typename T>
	struct atomic_type_for {
		using type = typename std::enable_if<std::is_trivially_copyable<T>::value, typename atomic_type<sizeof(T), alignof(T)>::type>::type;
		static_assert(sizeof(type) == sizeof(T) && alignof(T) <= alignof(type), "type size/alignment mismatch");
	};

	template<typename T, typename atomic_type_for<T>::type* = nullptr>
	bool compare_exchange(T* pointer, T& expected, const T& desired) {
		using AT = typename atomic_type_for<T>::type;
		return compare_exchange((AT*)pointer, (AT&)expected, (const AT&)desired);
	}

	struct shm_io_impl;

	enum {
		shm_io_read = 1,
		shm_io_write = 2,
		shm_io_copy_on_write = 4,
	};

	struct shm_io {
		std::unique_ptr<shm_io_impl> impl;
	public:
		shm_io();
		shm_io(shm_io&& n);
		~shm_io();
		shm_io& operator=(shm_io&& n);
		bool open(const char* fn, uint64_t size);
		void* map(void* addr, uint64_t offset, size_t size, int flags);
	};

};

