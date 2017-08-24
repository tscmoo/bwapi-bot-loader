#ifndef ENVIRON_H
#define ENVIRON_H

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <chrono>
#include <locale>
#include <codecvt>

#include "strf.h"

#if defined(__x86_64__) || defined(_M_X64)
#define x86_64
#endif

#ifndef x86_64
#ifdef _MSC_VER
#define STDCALL __stdcall
#else
#define STDCALL __attribute__((stdcall))
#endif
#else
#define STDCALL
#endif

#define WINAPI STDCALL

template<typename...T>
static std::string format(const char* fmt, T&&...args) {
	std::string r;
	tsc::strf::format(r, fmt, std::forward<T>(args)...);
	return r;
}

namespace kernel32 {
	uint32_t WINAPI GetCurrentThreadId();
};

template<typename...T>
static void log_impl(const char* fmt, T&&...args) {
	auto s = format(fmt, std::forward<T>(args)...);
	auto s2 = format("%04x: %s", kernel32::GetCurrentThreadId(), s);
	fwrite(s2.data(), s2.size(), 1, stdout);
}

template<typename...T>
static void log(const char* fmt, T&&...args) {
#ifdef LOG_ENABLED
	log_impl(fmt, std::forward<T>(args)...);
#endif
}

template<typename...T>
static void fatal_error(const char* fmt, T&&... args) {
	log_impl("fatal error: %s\n", format(fmt, std::forward<T>(args)...));
	std::quick_exit(-1);
}

// template<typename R, typename... args_T>
// wrap_wide_strings(R(STDCALL*ptr)(args_T...)) {
// 	raw_ptr_value = (void*)ptr;
// }

template<typename T>
void assert_32bit(T v) {
	uintptr_t n = (uintptr_t)v;
	if ((uintptr_t)(uint32_t)n != n) fatal_error("value %#x does not fit in 32 bits\n", n);
}

struct func_ptr {
	void* raw_ptr_value;
	template<typename R, typename... args_T>
	func_ptr(R(*ptr)(args_T...)) {
		raw_ptr_value = (void*)ptr;
	}
#ifndef x86_64
	template<typename R, typename... args_T>
	func_ptr(R(STDCALL*ptr)(args_T...)) {
		raw_ptr_value = (void*)ptr;
	}
#endif
};

#define wtoa_function(func) environment::get_wide_function<decltype(&func), &func>(&func)

#ifdef _MSC_VER
static std::u16string utf8_to_utf16(const std::string& str) {
	return (std::u16string&)std::wstring_convert<std::codecvt_utf8_utf16<int16_t>, int16_t>{}.from_bytes(str);
}
static std::string utf16_to_utf8(const std::u16string& str) {
	return std::wstring_convert<std::codecvt_utf8_utf16<int16_t>, int16_t>{}.to_bytes((int16_t*)str.data());
}
#else
static std::u16string utf8_to_utf16(const std::string& str) {
	return std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>{}.from_bytes(str);
}
static std::string utf16_to_utf8(const std::u16string& str) {
	return std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>{}.to_bytes(str.data());
}
#endif

namespace environment {
	void init();
	struct func_wrapper {
		void(*func)(void*arg);
		void* arg;
		void operator()() {
			func(arg);
		}
	};
	void enter_thread(const std::function<void()>& f, bool create_stack = true);
	template<typename F>
	void enter_thread(const F& f, bool create_stack = true) {
		enter_thread(std::function<void()>([&]() {
			f();
		}), create_stack);
	}

	void add_func(const std::string& name, func_ptr func, bool has_initialized = false);
	void* get_implemented_function(const std::string& name);
	void* get_unimplemented_stub(const std::string& name);

	bool has_implemented_functions_in_module(const std::string& name);

	void add_oninit(std::function<void()>, bool has_initialized = false);

	void cpuid(int function, int subfunction, uint32_t info[4]);

	uint32_t call_thread_entry(void* entry, void* arg);

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

	extern TIB*(*get_tib)();

	template<typename T>
	struct ansi_to_wide {
		using type = T;
	};
	template<>
	struct ansi_to_wide<const char*> {
		using type = const char16_t*;
	};

	template<typename T>
	struct wide_to_ansi {
		T operator()(T value) {
			return value;
		}
	};

	template<>
	struct wide_to_ansi<const char16_t*> {
		std::string str;
		const char* operator()(const char16_t* input) {
			if (!input) return nullptr;
			str = utf16_to_utf8(input);
			return str.c_str();
		}
	};

	template<typename func_T, func_T func, typename R, typename... args_T>
	R WINAPI wide_function(args_T... args) {
		return func(wide_to_ansi<args_T>()(args)...);
	}

	template<typename func_T, func_T func, typename R, typename... args_T>
	auto get_wide_function(R(WINAPI*ptr)(args_T...)) {
		return &wide_function<func_T, func, R, typename ansi_to_wide<args_T>::type...>;
	}
}

struct register_funcs {
	register_funcs(const std::string& libname, const std::vector<std::pair<std::string, func_ptr>>& funcs) {
		for (auto& v : funcs) {
			environment::add_func(libname + ":" + v.first, v.second);
		}
	}
};

struct oninit_func {
	template<typename T>
	oninit_func(T&& func) {
		environment::add_oninit(std::forward<T>(func));
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
	if (ps.empty()) {
		r += "Z:";
		r += separator;
	} else {
		auto& v = ps.front();
		if (v.second != 2 || path.data()[v.first + 1] != ':') {
			r += "Z:";
			r += separator;
		} else if (ps.size() == 1) ps.emplace_back(0, 0);
	}
	bool is_first = true;
	for (auto& v : ps) {
		if (is_first) is_first = false;
		else r += separator;
		r.append(path.data() + v.first, v.second);
	}
	return r;
}

static std::string get_native_path(const std::string& path) {
	auto s = full_path(path, '/');
	if (s.size() < 3 || s[1] != ':') fatal_error("full path returned '%s', which does not start with a drive letter", s);
	char drive = s[0];
	std::string r = ".";
	if (drive != 'Z') {
		r += "/drive/";
		r += drive;
	}
	r += &s[2];
	return r;
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
