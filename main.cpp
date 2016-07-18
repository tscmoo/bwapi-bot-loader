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
#include "native_api.h"
#include "kernel32.h"

char image_buffer[5 * 1024 * 1024];

int main() {

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

	kernel32::set_cmdline(module_filename);

	auto* i = modules::load_main(module_filename.c_str(), true);
	if (!i) fatal_error("failed to load %s", module_filename);

	return 0;
}
