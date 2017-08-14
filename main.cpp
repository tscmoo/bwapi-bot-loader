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

#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

extern "C" void* LoadLibrary(const char* name) {
	return wintypes::to_pointer(kernel32::LoadLibraryA(name));	
}

extern "C" void* GetProcAddress(void* module, const char* name) {
	return kernel32::GetProcAddress(wintypes::to_pointer32(module), name);
}

static modules::module_info* mi = nullptr;

void stack_probe() {
  char test[1024 * 1024 * 4];
	for (volatile char* ptr = test; ptr < test + sizeof(test); ptr += 0x1000) {
		*ptr;
	}
}

extern "C" void loadDll(const char* path) {
	
	stack_probe();
	
	environment::init();

	modules::load_fake_main("main", [&]() {
		mi = modules::load_library(path, true, false, true);
		if (!mi) fatal_error("failed to load %s", path);
	});
	
}

void* game_ptr;

extern "C" DLLEXPORT void gameInit(void* game) {
	game_ptr = game;
}
extern "C" DLLEXPORT void* newAIModule() {
	if (!mi) fatal_error("loadDll must be called before newAIModule");
	
	auto getf = [&](const char* name, bool error) {
		auto i = mi->export_names.find(name);
		if (i == mi->export_names.end() || i->second >= mi->exports.size()) {
			if (!error) return (void*)nullptr;
			fatal_error("'%s' does not have an exported function by name '%s'", mi->name, name);
		}
		return mi->exports[i->second];
	};
	
	log("calling gameInit()\n");

	if (getf("gameInit", false)) {
		((void(*)(void*))getf("gameInit", true))(game_ptr);
	
		auto* r = ((void*(*)())getf("newAIModule", true))();
		log("returning %p\n", r);
	
		return r;
	} else {
		auto* r = ((void*(*)(void*))getf("newAIModule", true))(game_ptr);
		log("returning %p\n", r);
	
		return r;
	}
}

