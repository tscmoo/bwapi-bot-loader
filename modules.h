#ifndef MODULES_H
#define MODULES_H

#include <string>
#include <unordered_map>
#include <vector>
#include <list>
#include <functional>

namespace modules {

	struct resource_directory;
	struct resource_entry {
		resource_directory* dir = nullptr;
		void* data = nullptr;
		size_t size;
	};
	struct resource_directory {
		std::unordered_map<std::u16string, resource_entry> named;
		std::unordered_map<size_t, resource_entry> id;
	};

	struct module_info {
		std::string full_path;
		std::string name;
		std::string name_no_ext;
		std::string lcase_name_no_ext;
		void* base = nullptr;
		void* entry = nullptr;
		std::unordered_map<std::string, size_t> export_names;
		std::vector<void*> exports;
		size_t ordinal_base = 0;

		resource_directory* root_resource_directory = nullptr;
		std::list<resource_directory> all_resource_directories;
	};

	module_info* get_module_info(const char* name);
	module_info* get_module_info(void* base);

	module_info* load_library(const char* path, bool is_load_time);

	extern std::function<void()> pre_entry_callback;

	module_info* load_main(const char* path, bool overwrite = false);
	module_info* load_fake_module(const char* name);

	void call_thread_attach();
	void call_thread_detach();

};

#endif
