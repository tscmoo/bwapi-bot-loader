#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <array>
#include <vector>
#include <map>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>

#include "environ.h"
#include "modules.h"
//#include "codegen.h"
#include "native_api.h"
#include "kernel32.h"

void unimplemented_stub(const char* name, void* retaddr) {
	fatal_error("unimplemented: %s (called from %p)", name, retaddr);
}

void* generate_unimplemented_stub(std::string name) {
	void* mem = native_api::allocated_memory(0x1000, native_api::memory_access::read_write_execute).detach();
	if (!mem) fatal_error("memory allocation failed");
	if (name.size() >= 0x400) name.resize(0x400);
	memcpy(mem, name.c_str(), name.size() + 1);
	uint8_t* p = (uint8_t*)mem + name.size() + 1;
	p = (uint8_t*)(((uintptr_t)p + 3) & -4);

	auto* r = p;

	*p++ = 0x68; // push mem
	*(uint32_t*)p = (uint32_t)mem;
	p += 4;	
	*p++ = 0xe8; // call unimplemented_stub
	*(uint32_t*)p = (uint32_t)&unimplemented_stub - (uint32_t)p - 4;
	p += 4;

// 	out_buf_ptr code_buf(p);
// 	codegen gen(&code_buf);
// 
// 	gen.push_imm32((uint32_t)mem);
// 	gen.call_rel32((uint32_t)&unimplemented_stub);

	return r;
}

std::unordered_map<std::string, func_ptr> implemented_functions;

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
		return;
	}
	if (!local_implemented_functions.emplace(name, func).second) fatal_error("function %s already implemented", name);
}

char image_buffer[5 * 1024 * 1024];

int main() {

	add_func("", &main, true);

	void* base = (void*)0x400000;

	size_t size = 1024 * 1024 * 3; // starcraft image is slightly less than 3MB

	char* b = image_buffer;
	char* e = b + sizeof(image_buffer);
	if ((char*)base < b || (char*)base >= e || (char*)base + size < b || (char*)base + size >= e) {
		log("error: image_buffer is [%p,%p), which does not contain [%p,%p).\n", b, e, base, (char*)base + size);
		log("This image must be linked with base address 0x300000 and relocations stripped.\n");
		return -1;
	}

	std::string module_filename = R"(X:\starcraft\starcraft\starcraft.exe)";

	kernel32::cmdline = module_filename;

	auto* i = modules::load(module_filename.c_str(), true);
	if (!i) fatal_error("failed to load %s", module_filename);
	//pe_info pi;
	//if (!load(module_filename.c_str(), &pi, true)) fatal_error("failed to load %s", module_filename);

	((void(*)())i->entry)();

	return 0;
}
