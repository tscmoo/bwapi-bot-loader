#ifndef ENVIRON_H
#define ENVIRON_H

#include <string>
#include <vector>
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

static std::string full_path(const std::string& path, char separator = '\\') {
	std::vector<std::pair<size_t, size_t>> ps;
	size_t nstart = 0;
	for (size_t i = 0;; ++i) {
		bool is_end = i == path.size();
		if (is_end || path[i] == '\\' || path[i] == '/') {
			size_t len = i - nstart;
			if (len && (len != 1 || path[nstart] != '.')) {
				if (len == 2 && path[nstart] == '.' && path[nstart + 1] == '.') {
					if (!ps.empty()) ps.pop_back();
				} else ps.emplace_back(nstart, len);
			}
			nstart = i + 1;
			if (is_end) break;
		}
	}
	std::string r;
	for (auto& v : ps) {
		r += separator;
		r.append(path.data() + v.first, v.second);
	}
	return r;
}

static std::string path_to_native(const std::string& path) {
	return "." + full_path(path, '/');
}

static std::string get_full_path(const std::string& path) {
	return full_path(path, '\\');
}
static std::string get_filename(const std::string& path) {
	auto s = full_path(path, '\\');
	size_t slash = s.rfind('\\');
	if (slash == std::string::npos) return "";
	return s.substr(slash + 1);
}
static std::string get_directory(const std::string& path) {
	auto s = full_path(path, '\\');
	size_t slash = s.rfind('\\');
	return s.substr(0, slash);
}

#endif
