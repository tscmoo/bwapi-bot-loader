#ifndef MODULES_H
#define MODULES_H

#include <string>
#include <unordered_map>

namespace modules {

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
	};

	module_info* get_module_info(const char* name);
	module_info* get_module_info(void* base);

	module_info* load_library(const char* path, bool is_load_time);

	module_info* load(const char* path, bool overwrite = false);
	module_info* load_fake_module(const char* name);

};

#endif
