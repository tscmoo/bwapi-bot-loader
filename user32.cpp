
#include "environment.h"
#include "modules.h"
#include "wintypes.h"
using namespace wintypes;
#include "kernel32.h"
#include <cstdarg>

namespace user32 {
;

int WINAPI LoadStringA(HINSTANCE h, UINT id, char* buffer, int size) {
	if (buffer && size) *buffer = 0;
	log("LoadString %p %d %p %d; not supported\n", (void*)h, id, buffer, size);
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return 0;
}

void* WINAPI LoadAcceleratorsA(HINSTANCE h, const char* table_name) {
	log("LoadAccelerators %p %p; not supported\n", (void*)h, table_name);
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return nullptr;
}

void* WINAPI LoadIconA(HINSTANCE h, const char* icon_name) {
	log("LoadIcon %p %p; not supported\n", (void*)h, icon_name);
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return nullptr;
}

HANDLE WINAPI LoadImageA(HINSTANCE h, const char* name, UINT type, int width, int height, UINT load) {
	log("LoadImage %p %p %d %d %d %d; not supported\n", (void*)h, name, type, width, height, load);
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return nullptr;
}

void* WINAPI LoadCursorA(HINSTANCE h, const char* cursor_name) {
	log("LoadCursor %p %p; not supported\n", (void*)h, cursor_name);
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return nullptr;
}

HWND WINAPI GetForegroundWindow() {
	return nullptr;
}


template<typename char_T, typename the_other_char_T>
struct wsprintf {

	const char_T* fmt_pos;
	char_T* o;
	char_T* e;

	struct descriptor {
		bool end;
		bool flag_left_justify, flag_sign, flag_space, flag_hash, flag_zero;
		unsigned int width, precision;
		char_T c;
		char_T mod;
		descriptor() : end(true) {}
	};

	descriptor desc;

	template<typename T, int base, bool caps>
	void do_num(T v) {
		char buf[sizeof(v) * 4];
		bool negative = std::is_signed<T>::value ? (typename std::make_signed<T>::type)v < 0 : false;
		char* c = &buf[sizeof(buf)];
		bool is_zero = v == 0;
		if (is_zero) {
			if (desc.precision != 0) *--c = '0';
		} else {
			if (negative) v = 0 - v;
			typename std::make_unsigned<T>::type& uv = (typename std::make_unsigned<T>::type&)v;
			while (uv) {
				char n = uv%base;
				uv /= base;
				char d;
				if (base > 10 && n > 9) d = n - 10 + (caps ? 'A' : 'a');
				else d = '0' + n;
				*--c = d;
			}
		}
		size_t len = &buf[sizeof(buf)] - c;
		const char_T* num = c;
		char_T prefix[4];
		c = &prefix[0];
		if (desc.flag_hash && !is_zero) {
			if (base == 8) *c++ = '0';
			else if (base == 16) {
				*c++ = '0';
				if (caps) *c++ = 'X';
				else *c++ = 'x';
			}
		}
		if (negative) {
			*c++ = '-';
		} else {
			if (desc.flag_sign) *c++ = '+';
			else if (desc.flag_space) *c++ = ' ';
		}
		size_t prefix_len = c - &prefix[0];
		size_t outlen = prefix_len + len;
		if (desc.precision != -1 && desc.precision > len) outlen += (desc.precision - len);
		size_t numlen = outlen;
		if (desc.width != -1 && desc.width > outlen) outlen = desc.width;
		if (!desc.flag_zero && !desc.flag_left_justify) {
			for (size_t i = 0; i < outlen - numlen; i++) {
				if (o != e) *o++ = ' ';
			}
		}
		if (prefix_len) {
			if (prefix_len >= (size_t)(e - o)) prefix_len = e - o;
			memcpy(o, prefix, prefix_len * sizeof(char_T));
			o += prefix_len;
		}
		if (desc.flag_zero) {
			for (size_t i = 0; i<outlen - numlen; i++) {
				if (o != e) *o++ = '0';
			}
		}
		if (desc.precision != -1 && desc.precision > len) {
			for (size_t i = 0; i < desc.precision - len; i++) {
				if (o != e) *o++ = '0';
			}
		}
		if (len >= (size_t)(e - o)) len = e - o;
		memcpy(o, num, len * sizeof(char_T));
		o += len;
		if (desc.flag_left_justify) {
			//if (desc.flag_zero) bad("zero flag and left justify flag cannot be specified together");
			for (size_t i = 0; i < outlen - numlen; i++){
				if (o != e) *o++ = ' ';
			}
		}
	}

	template<typename T>
	void do_char(T c) {
		//if (desc.flag_zero || desc.flag_hash || desc.flag_sign || desc.flag_space) bad("bad flags for character");
		size_t outlen = 1;
		if (desc.width != -1 && desc.width > outlen) outlen = desc.width;
		if (!desc.flag_left_justify) {
			for (size_t i = 0; i < outlen - 1; i++) {
				if (o != e) *o++ = ' ';
			}
		}
		if (o != e) *o++ = (char_T)c;
		if (desc.flag_left_justify) {
			for (size_t i = 0; i < outlen - 1; i++) {
				if (o != e) *o++ = ' ';
			}
		}
	};

	template<typename T>
	void do_string(const T* s) {
		size_t len = 0;
		if (s) {
			const T* c = s;
			for (; *c; ++c) ++len;
		}
		do_string(s, len);
	}

	template<typename T>
	void do_string(const T* s, size_t len) {
		//if (desc.flag_zero || desc.flag_hash || desc.flag_sign || desc.flag_space) bad("bad flags for string");
		if (!s) {
			return do_string("(null)", 6);
		}
		size_t outlen = len;
		if (desc.precision != -1 && outlen>desc.precision) outlen = desc.precision;
		if (outlen < len) len = outlen;
		if (desc.width != -1 && desc.width>outlen) outlen = desc.width;
		if (!desc.flag_left_justify) {
			for (size_t i = 0; i < outlen - len; i++) {
				if (o != e) *o++ = ' ';
			}
		}
		if (len >= (size_t)(e - o)) len = e - o;
		for (size_t i = 0; i < len; ++i) {
			*o++ = (char_T)s[i];
		}
		if (desc.flag_left_justify) {
			for (size_t i = 0; i < outlen - len; i++) {
				if (o != e) *o++ = ' ';
			}
		}
	}

	descriptor next() {
		descriptor r;
		const char_T* c = fmt_pos;
		auto flush = [&]() {
			if (c == fmt_pos) return;
			size_t n = c - fmt_pos;
			if (n > (size_t)(e - o)) n = e - o;
			memcpy(o, fmt_pos, n * sizeof(char_T));
			o += n;
		};
		auto testflag = [&]() -> bool {
			switch (*c) {
			case '-': r.flag_left_justify = true; break;
			case '+': r.flag_sign = true; break;
			//case ' ': r.flag_space = true; break;
			case '#': r.flag_hash = true; break;
			case '0': r.flag_zero = true; break;
			default: return false;
			}
			c++;
			return true;
		};
		auto num = [&](unsigned int& dstv) {
			if (*c == '*') {
				dstv = ~1;
				c++;
				return;
			}
			const char_T* e = c;
			unsigned int m = 1;
			if (*e >= '0'&&*e <= '9') e++;
			while (*e >= '0'&&*e <= '9') { e++; m *= 10; };
			if (e == c) return;
			unsigned rv = 0;
			for (; c != e; c++) {
				rv += (*c - '0')*m;
				m /= 10;
			}
			dstv = rv;
		};
		while (*c) {
			if (*c == '%') {
				flush();
				if (*++c == '%') {
					if (o != e) *o++ = '%';
					++c;
					fmt_pos = c;
				} else {
					r.end = false;
					r.flag_left_justify = false;
					r.flag_sign = false;
					r.flag_space = false;
					r.flag_hash = false;
					r.flag_zero = false;
					while (testflag());
					r.width = ~0;
					r.precision = ~0;
					num(r.width);
					if (*c == '.') ++c, num(r.precision);
					r.c = *c++;
					r.mod = 0;
					auto is_valid_format_character = [&](char_T c) {
						switch (c) {
						case 'c': case 'C': case 'd': case 'i': case 'p': case 's': case 'S': case 'u': case 'x': case 'X':
							return true;
						default:
							return false;
						}
					};
					if (!is_valid_format_character(r.c)) {
						if (r.c == 'h' || r.c == 'l') {
							r.mod = r.c;
							r.c = *c++;
							if (!is_valid_format_character(r.c)) {
								flush();
								continue;
							}
						} else {
							flush();
							continue;
						}
					}
					fmt_pos = c;
					return r;
				}
			}
			c++;
		}
		flush();
		r.end = true;
		return r;
	};

	int operator()(char_T* dst, const char_T* fmt, va_list args) {
		fmt_pos = fmt;
		o = dst;
		e = dst + 1024 / sizeof(char_T);

		while (true) {
			desc = next();
			if (desc.end) break;
			switch (desc.c) {
			case 'c':
				if (desc.mod == 'h') {
					auto c = va_arg(args, int);
					if (c) do_char<char16_t>(c);
				} else if (desc.mod == 'l') {
					auto c = va_arg(args, int);
					if (c) do_char<char16_t>(c);
				} else do_char<char16_t>(va_arg(args, int));
				break;
			case 'C':
				if (desc.mod == 'h') {
					auto c = va_arg(args, int);
					if (c) do_char<char16_t>(c);
				} else if (desc.mod == 'l') {
					auto c = va_arg(args, int);
					if (c) do_char<char16_t>(c);
				} else do_char<char16_t>(va_arg(args, int));
				break;
			case 'd': case 'i':
				if (desc.mod == 'h') {
					do_num<int16_t, 10, false>(va_arg(args, int));
				} else if (desc.mod == 'l') {
					do_num<long, 10, false>(va_arg(args, long));
				} else do_num<int32_t, 10, false>(va_arg(args, int));
				break;
			case 'u':
				if (desc.mod == 'h') {
					do_num<uint16_t, 10, false>(va_arg(args, int));
				} else if (desc.mod == 'l') {
					do_num<unsigned long, 10, false>(va_arg(args, unsigned long));
				} else do_num<uint32_t, 10, false>(va_arg(args, int));
				break;
			case 'p':
				desc.flag_hash = true;
				do_num<uintptr_t, 16, false>(va_arg(args, uintptr_t));
				break;
			case 's':
				if (desc.mod == 'h') {
					do_string(va_arg(args, char*));
				} else if (desc.mod == 'l') {
					do_string(va_arg(args, char16_t*));
				} else {
					const char* s = va_arg(args, char_T*);
					do_string(s);
				}
				break;
			case 'S':
				if (desc.mod == 'h') {
					do_string(va_arg(args, char*));
				} else if (desc.mod == 'l') {
					do_string(va_arg(args, char16_t*));
				} else do_string(va_arg(args, the_other_char_T*));
				break;
			case 'x':
				do_num<uint32_t, 16, false>(va_arg(args, uint32_t));
				break;
			case 'X':
				if (desc.mod == 'l') {
					do_num<unsigned long, 16, true>(va_arg(args, unsigned long));
				} else do_num<uint32_t, 16, true>(va_arg(args, uint32_t));
				break;
			}
		}
		size_t len = o - dst;
		if (o != e) *o++ = 0;
		return len;
	}
};

int wsprintfA(char* dst, const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);

	int r = wsprintf<char, char16_t>()(dst, fmt, args);

	log("wsprintfA %d - %s\n", r, dst);
	
	va_end(args);
	return r;
}

BOOL WINAPI SetRect(RECT* out, LONG left, LONG top, LONG right, LONG bottom) {
	out->left = left;
	out->top = top;
	out->right = right;
	out->bottom = bottom;
	return TRUE;
}

BOOL WINAPI ClientToScreen(HWND h, POINT* inout) {
	return TRUE;
}

BOOL WINAPI PeekMessageA(void* msg, HWND hwnd, UINT msg_filter_min, UINT msg_filter_max, UINT remove_msg) {
	log("PeekMessage: not supported\n");
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}

void* WINAPI RegisterClassA(void* wnd_class) {
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return nullptr;
}

BOOL WINAPI GetClassInfoA(HINSTANCE h, const char* class_name, void* wnd_class) {
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}

register_funcs funcs({
	{ "user32:LoadStringA", LoadStringA },
	{ "user32:LoadAcceleratorsA", LoadAcceleratorsA },
	{ "user32:LoadIconA", LoadIconA },
	{ "user32:LoadImageA", LoadImageA },
	{ "user32:LoadCursorA", LoadCursorA },
	{ "user32:GetForegroundWindow", GetForegroundWindow },
	{ "user32:wsprintfA", (int(*)(char*,const char*))wsprintfA },
	{ "user32:SetRect", SetRect },
	{ "user32:ClientToScreen", ClientToScreen },
	{ "user32:PeekMessageA", PeekMessageA },
	{ "user32:RegisterClassA", RegisterClassA },
	{ "user32:GetClassInfoA", GetClassInfoA },
});

}
