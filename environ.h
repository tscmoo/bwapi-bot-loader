#ifndef ENVIRON_H
#define ENVIRON_H

#include <string>
#include <unordered_map>

#include "strf.h"

template<typename...T>
static std::string format(const char* fmt, T&&...args) {
	std::string r;
	tsc::strf::format(r, fmt, std::forward<T>(args)...);
	return r;
}

template<typename...T>
static void log(const char* fmt, T&&...args) {
	auto s = format(fmt, std::forward<T>(args)...);
	fwrite(s.data(), s.size(), 1, stdout);
}

template<typename...T>
static void fatal_error(const char* fmt, T&&... args) {
	log("fatal error: %s\n", format(fmt, std::forward<T>(args)...));
	std::quick_exit(-1);
	//TerminateProcess(GetCurrentProcess(), (UINT)-1);
}

#ifdef _MSC_VER
#define WINAPI __stdcall
#else
#define WINAPI __attribute__((stdcall))
#endif

struct func_ptr {
	void* raw_ptr_value;
	template<typename R, typename... args_T>
	func_ptr(R(*ptr)(args_T...)) {
		raw_ptr_value = (void*)ptr;
	}
	template<typename R, typename... args_T>
	func_ptr(R(WINAPI*ptr)(args_T...)) {
		raw_ptr_value = (void*)ptr;
	}
};


void add_func(const std::string& name, func_ptr func, bool has_initialized = false);
void* get_implemented_function(const std::string& name);
void* get_unimplemented_stub(const std::string& name);

struct register_funcs {
	register_funcs(const std::unordered_map<std::string, func_ptr>& funcs) {
		for (auto& v : funcs) {
			add_func(v.first, v.second);
		}
	}
};

template<typename T1, typename T2>
static bool str_icase_eq(const T1& str1, const T2& str2) {
	const char* a = &str1[0];
	const char* b = &str2[0];
	while (true) {
		char ac = *a;
		char bc = *b;
		if (ac >= 'A' && ac <= 'Z') ac |= 0x20;
		if (bc >= 'A' && bc <= 'Z') bc |= 0x20;
		if (ac != bc) return false;
		++a;
		++b;
		if (!ac) break;
	}
	return true;
}

#endif
