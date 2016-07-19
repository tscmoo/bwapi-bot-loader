#ifndef KERNEL32_H
#define KERNEL32_H

#include "wintypes.h"
#include "environment.h"

#include <string>
#include <functional>

namespace modules {
	struct module_info;
};

namespace kernel32 {
	using namespace wintypes;

	void set_main_module(modules::module_info*);
	void enter_main_thread(const std::function<void()>& f);

	void add_virtual_region(void* addr, size_t size, MEM_STATE state, PAGE_PROTECT protect);

	void set_cmdline(const std::string& str);

	void* virtual_allocate(void* addr, size_t size, MEM_STATE allocation_type, PAGE_PROTECT protect, void* preferred_addr = nullptr);
	void virtual_deallocate(void* addr);

	void virtual_protect(void* addr, size_t size, PAGE_PROTECT protect);

	void WINAPI SetLastError(DWORD err);
	DWORD WINAPI GetLastError();
	DWORD WINAPI GetCurrentThreadId();
	void WINAPI Sleep(DWORD milliseconds);
	DWORD WINAPI GetTickCount();
}

#endif
