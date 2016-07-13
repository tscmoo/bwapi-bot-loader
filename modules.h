#ifndef MODULES_H
#define MODULES_H

#include <string>
#include <unordered_map>

namespace modules {

	struct module_info {
		std::string name;
		std::string name_no_ext;
		std::string lcase_name_no_ext;
		void* base;
		void* entry;
		std::unordered_map<std::string, void*> exports;
	};

	module_info* get_module_info(const char* name);
	module_info* get_module_info(void* base);

	module_info* load_library(const char* path);

	module_info* load(const char* path, bool overwrite = false);
	module_info* load_fake_module(const char* name);

};

#endif
