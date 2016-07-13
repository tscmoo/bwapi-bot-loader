#ifndef KERNEL32_H
#define KERNEL32_H

#include "wintypes.h"

#include <string>

namespace modules {
	struct module_info;
};

namespace kernel32 {
	using namespace wintypes;

	void set_main_module(modules::module_info*);

	void add_virtual_region(void* addr, size_t size, DWORD state, PAGE_PROTECT protect);

	extern std::string cmdline;
}

#endif
