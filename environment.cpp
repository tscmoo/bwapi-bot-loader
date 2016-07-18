
#include "environment.h"
#include "kernel32.h"
#include "native_api.h"
#include "wintypes.h"
using namespace wintypes;
#include <array>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

#ifndef _WIN32
#include <unistd.h>
#include <asm/ldt.h>
#include <sys/syscall.h>
#endif

namespace environment {

struct TIB {
	void* seh = nullptr;
	void* stack_bot = nullptr;
	void* stack_top = nullptr;
	void* subsystem_tib = nullptr;
	void* fiber_data = nullptr;
	void* data_slot = nullptr;
	void* this_tib = nullptr;
	std::array<char, 0x100> filler;
	void* old_fs_value = nullptr;
	void* retaddr = nullptr;
};

#ifndef _WIN32
thread_local TIB tib;
#endif

TIB*(*get_tib)();
void(*set_fs)(uint16_t);

void generate_get_tib(uint8_t*& p) {
	*p++ = 0x64; // mov eax, fs:0x18
	*p++ = 0xa1;
	*(uint32_t*)p = 0x18;
	p += 4;
	
	*p++ = 0xc3; // ret
}
void generate_set_fs(uint8_t*& p) {
	*p++ = 0x8b; // mov eax, [esp + 4]
	*p++ = 0x44;
	*p++ = 0x24;
	*p++ = 0x04;

	*p++ = 0x66; // mov fs, ax
	*p++ = 0x8e;
	*p++ = 0xe0;

	*p++ = 0xc3; // ret
}

void(*switch_stack)(void* sp_top, void* sp_bot, void(*func)(void* sp_top, void* sp_bot));

void generate_switch_stack(uint8_t*& p) {
	const char* code = "\x55\x8b\xec\x8b\x45\x08\x8b\x4d\x0c\x8b\x55\x10\x8b\xe0\x51\x50\xff\xd2\x83\xc4\x08\x8b\xe5\x5d\xc3";
	memcpy(p, code, 0x19);
	p += 0x19;
}

void(*cpuid_f)(int function, int subfunction, uint32_t info[4]);

void cpuid(int function, int subfunction, uint32_t info[4]) {
	return cpuid_f(function, subfunction, info);
}

void generate_cpuid(uint8_t*& p) {
	const char* code = "\x53\x56\x8b\x44\x24\x0c\x8b\x4c\x24\x10\x8b\x74\x24\x14\x0f\xa2\x89\x06\x89\x5e\x04\x89\x4e\x08\x89\x56\x0c\x5e\x5b\xc3";
	memcpy(p, code, 0x1e);
	p += 0x1e;
}

void enter_thread(const std::function<void()>& f) {
#ifndef _WIN32
	user_desc ldt = { (unsigned int)-1, (unsigned int)&tib, 0xfff, 1, 0, 0, 1, 0, 1 };
	int r = syscall(SYS_set_thread_area, &ldt);
	if (r) fatal_error("set_thread_area failed");
	set_fs((ldt.entry_number << 3) | 3);
	tib.this_tib = &tib;
#endif

	size_t stack_size = 2 * 1024 * 1024;

	void* stack = kernel32::virtual_allocate(nullptr, stack_size, MEM_COMMIT, PAGE_NOACCESS);
	if (!stack) fatal_error("failed to allocate stack");

	intptr_t sp_bot = (intptr_t)stack + 0x1000;
	intptr_t sp_top = (intptr_t)stack + stack_size - 0x1000;

	kernel32::virtual_protect((void*)sp_bot, stack_size - 0x2000, PAGE_READWRITE);

	log("stack is %p - %p\n", (void*)sp_top, (void*)sp_bot);

	sp_top -= 4;
	*(uint32_t*)sp_top = (uint32_t)&f;

	switch_stack((void*)sp_top, (void*)sp_bot, [](void* sp_top, void* sp_bot) {
		(**(const std::function<void()>**)sp_top)();
	});

}

void init() {
	add_func("", &init, true);

	void* funcs_mem = native_api::allocated_memory(nullptr, 0x1000, native_api::memory_access::read_write_execute).detach();
	if (!funcs_mem) fatal_error("memory allocation failed");
	memset(funcs_mem, 0xcc, 0x1000);

	uint8_t* p = (uint8_t*)funcs_mem + 8;
	while ((uintptr_t)p % 4) ++p;
	(void*&)get_tib = p;
	generate_get_tib(p);
	while ((uintptr_t)p % 4) ++p;
	(void*&)set_fs = p;
	generate_set_fs(p);
	while ((uintptr_t)p % 4) ++p;
	(void*&)switch_stack = p;
	generate_switch_stack(p);
	while ((uintptr_t)p % 4) ++p;
	(void*&)cpuid_f = p;
	generate_cpuid(p);
}

void unimplemented_stub(const char* name, void* retaddr) {
	fatal_error("unimplemented: %s (called from %p)", name, retaddr);
}

uint8_t* next_unimplemented_stub = nullptr;
uint8_t* unimplemented_stub_end = nullptr;

void* generate_unimplemented_stub(std::string name) {
	if (name.size() >= 0x400) name.resize(0x400);
	if (next_unimplemented_stub + name.size() + 1 + 0x10 >= unimplemented_stub_end) {
		void* mem = native_api::allocated_memory(nullptr, 0x10000, native_api::memory_access::read_write_execute).detach();
		if (!mem) fatal_error("memory allocation failed");
		memset(mem, 0xcc, 0x10000);
		next_unimplemented_stub = (uint8_t*)mem;
		unimplemented_stub_end = next_unimplemented_stub + 0x10000;
	}

	uint8_t* p = (uint8_t*)next_unimplemented_stub;
	char* name_ptr = (char*)p;
	memcpy(name_ptr, name.c_str(), name.size() + 1);
	p += name.size() + 1;

	p = (uint8_t*)(((uintptr_t)p + 3) & -4);
	auto* r = p;

	*p++ = 0x68; // push mem
	*(uint32_t*)p = (uint32_t)next_unimplemented_stub;
	p += 4;
	*p++ = 0xe8; // call unimplemented_stub
	*(uint32_t*)p = (uint32_t)&unimplemented_stub - (uint32_t)p - 4;
	p += 4;
	*p++ = 0xcc; // breakpoint

	next_unimplemented_stub = p;

	return r;
}

std::unordered_map<std::string, func_ptr> implemented_functions;
std::unordered_set<std::string> implemented_modules;

void* get_implemented_function(const std::string& name) {
	auto i = implemented_functions.find(name);
	if (i == implemented_functions.end()) return nullptr;
	return i->second.raw_ptr_value;
}
std::unordered_map<std::string, void*> unimplemented_stubs;
std::mutex get_unimplemented_stub_mut;
void* get_unimplemented_stub(const std::string& name) {
	std::lock_guard<std::mutex> l(get_unimplemented_stub_mut);
	void*& r = unimplemented_stubs[name];
	if (!r) r = generate_unimplemented_stub(name);
	return r;
}

void add_func(const std::string& name, func_ptr func, bool has_initialized) {
	static std::unordered_map<std::string, func_ptr> local_implemented_functions;
	if (has_initialized) {
		implemented_functions = local_implemented_functions;
		for (auto& v : implemented_functions) {
			auto& str = v.first;
			size_t i = str.find(':');
			if (i != std::string::npos) {
				auto mod = str.substr(0, i);
				implemented_modules.insert(mod);
			}
		}
		return;
	}
	if (!local_implemented_functions.emplace(name, func).second) fatal_error("function %s already implemented", name);
}

bool has_implemented_functions_in_module(const std::string& name) {
	return implemented_modules.find(name) != implemented_modules.end();
}

}
