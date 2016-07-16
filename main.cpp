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

#include "environment.h"
#include "modules.h"
//#include "codegen.h"
#include "native_api.h"
#include "kernel32.h"

char image_buffer[5 * 1024 * 1024];

#ifdef _WIN32
#include <windows.h>
#endif

int main() {
#ifdef _WIN32
	SetCurrentDirectoryA("X:\\starcraft\\starcraft");
#endif

// 	MEMORY_BASIC_INFORMATION meminfo;
// 	VirtualQuery((void*)0x1000000, &meminfo, sizeof(meminfo));
// 	log("alloc base %p\n", meminfo.AllocationBase);
// 	log("base %p\n", meminfo.BaseAddress);
// 	log("size %x\n", meminfo.RegionSize);
// 	log("state %x\n", meminfo.State);
// 
// 
// 	SetLastError(-1);
// 	void* addr = VirtualAlloc((void*)0x1000000, 0x1000, MEM_RESERVE, PAGE_READWRITE);
// 	log("addr %p, error %d\n", addr, GetLastError());
// 	void* addr2 = VirtualAlloc((void*)0x1010000, 0x1000, MEM_RESERVE, PAGE_READWRITE);
// 	log("addr2 %p, error %d\n", addr2, GetLastError());
// 
// 	void* addr3 = VirtualAlloc((void*)0x1000000, 0x1000, MEM_COMMIT, PAGE_READWRITE);
// 	log("addr3 %p, error %d\n", addr3, GetLastError());
// 
// 	VirtualQuery((void*)0x1000000, &meminfo, sizeof(meminfo));
// 	log("alloc base %p\n", meminfo.AllocationBase);
// 	log("base %p\n", meminfo.BaseAddress);
// 	log("size %x\n", meminfo.RegionSize);
// 	log("state %x\n", meminfo.State);
// 
// 	fatal_error("stop");

// 	//HANDLE h = CreateFileA("tmp.txt", 0, 0, nullptr, OPEN_EXISTING, 0, nullptr);
// 	HANDLE h = (HANDLE)8;
// 	log("h %p\n", h);
// 	//log("write: %d\n", WriteFile(h, "test", 4, nullptr, nullptr));
// 	log("SetFilePos: %d\n", SetFilePointer(h, 10, nullptr, FILE_BEGIN));
// 	log("error %d\n", GetLastError());
// 	fatal_error("stop");

// 	char buf[0x100];
// 	memset(buf, 0, sizeof(buf));
// 	strcpy(buf, "uninit");
// 	char* filepart = nullptr;
// 	DWORD len = GetFullPathNameA("moo", 27, buf, &filepart);
// 	log("len %d\n", len);
// 	log("buf %s\n", buf);
// 	log("filepart %s\n", filepart);
// 	log("strlen(buf) %d\n", strlen(buf));
// 	fatal_error("stop");

// 	log("input: %p\n", GetStdHandle(STD_INPUT_HANDLE));
// 	log("output: %p\n", GetStdHandle(STD_OUTPUT_HANDLE));
// 	log("error: %p\n", GetStdHandle(STD_ERROR_HANDLE));
// 
// 	DWORD read;
// 	char buf[1];
// 	//ReadFile((HANDLE)3, buf, 1, &read, nullptr);
// 
// 	log("%c\n", buf[0]);
// 
// 	WriteFile((HANDLE)4, "test", 4, nullptr, nullptr);
// 
// 	Sleep(-1);
// 	fatal_error("stop");

	environment::init();

	void* base = (void*)0x400000;

	size_t size = 1024 * 1024 * 3; // starcraft image is slightly less than 3MB

	char* b = image_buffer;
	char* e = b + sizeof(image_buffer);
	if ((char*)base < b || (char*)base >= e || (char*)base + size < b || (char*)base + size >= e) {
		log("error: image_buffer is [%p,%p), which does not contain [%p,%p).\n", b, e, base, (char*)base + size);
		log("This image must be linked with base address 0x300000 and relocations stripped.\n");
		return -1;
	}

	std::string module_filename = "StarCraft.exe";

	kernel32::cmdline = module_filename;

	auto* i = modules::load_main(module_filename.c_str(), true);
	if (!i) fatal_error("failed to load %s", module_filename);

	return 0;
}
