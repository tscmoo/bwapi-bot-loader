#include "user32.h"
#include "environment.h"
#include "modules.h"
#include "wintypes.h"
using namespace wintypes;
#include "kernel32.h"
#include "native_window.h"
#include <cstdarg>
#include <mutex>

namespace user32 {
;


using WNDPROC = LRESULT(STDCALL*)(HWND, UINT, WPARAM, LPARAM);

struct WNDCLASSEXA {
	UINT cbSize;
	UINT style;
	WNDPROC lpfnWndProc;
	int cbClsExtra;
	int cbWndExtra;
	HINSTANCE hInstance;
	void* hIcon;
	void* hCursor;
	void* hbrBackground;
	const char* lpszMenuName;
	const char* lpszClassName;
	void* hIconSm;
};

struct window_class {
	bool taken = false;
	WNDPROC wnd_proc = nullptr;
	std::string name;
};

std::vector<window_class> window_classes(0xffff);
std::mutex windows_mut;

struct window {
	window_class* c = nullptr;
	native_window::window w;
};

std::vector<std::unique_ptr<window>> all_windows(0x1000);

window* get_window(HWND h) {
	if (!h) return nullptr;
	return (*(std::unique_ptr<window>*)h).get();
}

native_window::window* get_native_window(HWND h) {
	auto* w = get_window(h);
	if (!h) return nullptr;
	return &w->w;
}


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
	return nullptr32;
}

void* WINAPI LoadCursorA(HINSTANCE h, const char* cursor_name) {
	log("LoadCursor %p %p; not supported\n", (void*)h, cursor_name);
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return nullptr;
}

HWND focus_window = nullptr32;

HWND WINAPI GetForegroundWindow() {
	return focus_window;
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

BOOL WINAPI PeekMessageA(MSG* msg, HWND hwnd, UINT msg_filter_min, UINT msg_filter_max, UINT remove_msg) {	
	if (!hwnd) hwnd = focus_window;
	auto* w = get_window(hwnd);
	if (!w) {
		log("PeekMessage: invalid handle %p\n", (void*)hwnd);
		kernel32::SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	if (remove_msg != 1) fatal_error("PeekMessageA: fixme: remove_msg is %d", remove_msg);
	memset(msg, 0, sizeof(*msg));
	msg->hwnd = hwnd;
	msg->time = kernel32::GetTickCount();
	return w->w.peek_message(msg) ? TRUE : FALSE;
}

LRESULT WINAPI DispatchMessageA(const MSG* msg) {
	auto* w = get_window(msg->hwnd);
	if (!w) return 0;
	return w->c->wnd_proc(msg->hwnd, msg->message, msg->wParam, msg->lParam);
}

BOOL WINAPI TranslateMessage(const MSG* msg) {
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

ATOM WINAPI RegisterClassExA(const WNDCLASSEXA* cx) {
	std::lock_guard<std::mutex> l(windows_mut);
	for (size_t i = 0; i < window_classes.size(); ++i) {
		auto& v = window_classes[i];
		if (v.taken &&  str_icase_eq(cx->lpszClassName, v.name)) {
			kernel32::SetLastError(ERROR_CLASS_ALREADY_EXISTS);
			return 0;
		}
	}
	for (size_t i = 0; i < window_classes.size(); ++i) {
		auto& v = window_classes[i];
		if (!v.taken) {
			v.taken = true;
			v.name = cx->lpszClassName;
			v.wnd_proc = cx->lpfnWndProc;
			return (ATOM)(i + 1);
		}
	}
	kernel32::SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	return 0;
}

static const auto SM_CXSCREEN = 0;
static const auto SM_CYSCREEN = 1;

int WINAPI GetSystemMetrics(int index) {
	if (index == SM_CXSCREEN) {
		return 640;
	}
	if (index == SM_CYSCREEN) {
		return 480;
	}
	fatal_error("GetSystemMetrics %d\n", index);
	return 0;
}

int show_cursor_count = 0;

struct CREATESTRUCTA {
	pointer32_T<void> lpCreateParams;
	HINSTANCE hInstance;
	pointer32_T<void> hMenu;
	HWND hwndParent;
	int cy;
	int cx;
	int y;
	int x;
	LONG style;
	pointer32_T<const char> lpszName;
	pointer32_T<const char> lpszClass;
	DWORD dwExStyle;
};

HWND WINAPI CreateWindowExA(DWORD ex_style, const char* class_name, const char* window_name, DWORD style, int x, int y, int width, int height, HWND parent, HWND menu, HINSTANCE hinstance, void* param) {
	kernel32::SetLastError(ERROR_SUCCESS);
	std::lock_guard<std::mutex> l(windows_mut);
	bool is_atom = (uintptr_t)class_name < 0x10000;
	size_t atom = (uintptr_t)class_name & 0xffff;
	if (is_atom) class_name = "(atom)";
	else {
		atom = 0;
		for (size_t i = 0; i < window_classes.size(); ++i) {
			auto& v = window_classes[i];
			if (v.taken && str_icase_eq(class_name, v.name)) {
				atom = i + 1;
				break;
			}
		}
	}
	log("CreateWindowEx %#x '%s' '%s' %#x %d %d %d %d %p %p %p %p\n", ex_style, class_name, window_name, style, x, y, width, height, (void*)parent, (void*)menu, (void*)hinstance, param);
	window_class* c = nullptr;
	if (atom - 1 < window_classes.size()) c = &window_classes[atom - 1];
	if (!c || !c->taken) {
		kernel32::SetLastError(ERROR_CANNOT_FIND_WND_CLASS);
		return nullptr32;
	}

	for (size_t i = 0; i < all_windows.size(); ++i) {
		auto& v = all_windows[i];
		if (!v) {
			v = std::make_unique<window>();
			v->c = c;
			if (!v->w.create(window_name, style, ex_style, x, y, width, height)) {
				v.reset();
				return nullptr32;
			}
			CREATESTRUCTA cs;
			cs.lpCreateParams = param;
			cs.hInstance = hinstance;
			cs.hMenu = (void*)menu;
			cs.hwndParent = parent;
			cs.cy = height;
			cs.cx = width;
			cs.y = y;
			cs.x = x;
			cs.style = style;
			cs.lpszName = window_name;
			cs.lpszClass = class_name;
			cs.dwExStyle = ex_style;
			if (c->wnd_proc((HWND)&v, WM_CREATE, 0, (LPARAM)&cs) == -1) {
				v.reset();
				return nullptr32;
			}
			HWND wnd = (HWND)&v;
			c->wnd_proc(wnd, WM_SIZE, 0, MAKELPARAM(width, height));
			c->wnd_proc(wnd, WM_MOVE, 0, MAKELPARAM(x, y));
			c->wnd_proc(wnd, WM_SHOWWINDOW, 0, 0);
			c->wnd_proc(wnd, WM_ACTIVATEAPP, 1, 0);
			c->wnd_proc(wnd, WM_ACTIVATE, 1, (HWND)&v);
			focus_window = wnd;
			c->wnd_proc(wnd, WM_SETFOCUS, 0, 0);
			log("created window %p\n", (void*)wnd);
			v->w.show_cursor(show_cursor_count >= 0);
			return wnd;
		}
	}

	kernel32::SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	return nullptr32;
}

LRESULT WINAPI DefWindowProcA(HWND h, UINT msg, WPARAM wparam, LPARAM lparam) {
	return 0;
}

BOOL WINAPI UpdateWindow(HWND h) {
	log("UpdateWindow %p\n", (void*)h);
	window* w = get_window(h);
	if (!h) {
		kernel32::SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	w->c->wnd_proc(h, WM_PAINT, 0, 0);
	log("WM_PAINT returned\n");
	return TRUE;
}

struct PAINTSTRUCT {
	HDC hdc;
	BOOL fErase;
	RECT rcPaint;
	BOOL fRestore;
	BOOL fIncUpdate;
	BYTE rgbReserved[32];
};

HDC WINAPI BeginPaint(HWND wnd, PAINTSTRUCT* paint) {
	return nullptr32;
}

BOOL WINAPI EndPaint(HWND wnd, const PAINTSTRUCT* paint) {
	return TRUE;
}

HWND WINAPI SetFocus(HWND wnd) {
	kernel32::SetLastError(ERROR_SUCCESS);
	return nullptr32;
}

pointer32_t WINAPI SetCursor(pointer32_t cursor) {
	return nullptr32;
}

BOOL WINAPI ShowWindow(HWND wnd, int cmd) {
	return TRUE;
}

BOOL WINAPI SetCursorPos(int x, int y) {
	log("SetCursorPos %d %d\n", x, y);
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}

BOOL WINAPI GetCursorPos(POINT* r) {
	auto* w = get_window(focus_window);
	if (!w) {
		kernel32::SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	int x = 0;
	int y = 0;
	w->w.get_cursor_pos(&x, &y);
	r->x = x;
	r->y = y;
	return TRUE;
}

BOOL WINAPI ClipCursor(RECT* rect) {
	log("ClipCursor %d %d %d %d\n", rect->left, rect->top, rect->right, rect->bottom);
	return TRUE;
}

int WINAPI ShowCursor(BOOL show) {
	if (show) ++show_cursor_count;
	else --show_cursor_count;
	auto* w = get_window(focus_window);
	if (!w) return show_cursor_count;
	w->w.show_cursor(show_cursor_count >= 0) ? 1 : 0;
	return show_cursor_count;
}

BOOL WINAPI IsIconic(HWND wnd) {
	return FALSE;
}

BOOL WINAPI IsWindowVisible(HWND wnd) {
	return TRUE;
}

HWND WINAPI SetCapture(HWND wnd) {
	return nullptr32;
}

BOOL WINAPI ReleaseCapture() {
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}

BOOL WINAPI KillTimer(HWND wnd, UINT_PTR id) {
	log("KillTimer %p %d\n", (void*)wnd, id);
	kernel32::SetLastError(ERROR_INVALID_HANDLE);
	return FALSE;
}

UINT_PTR WINAPI SetTimer(HWND wnd, UINT_PTR id, UINT timeout, void* func) {
	log("SetTimer %p %d %d %p\n", (void*)wnd, id, timeout, func);
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return 0;
}

BOOL WINAPI PtInRect(const RECT* rect, POINT point) {
	return point.x >= rect->left && point.x < rect->right && point.y >= rect->top && point.y < rect->bottom ? TRUE : FALSE;
}

register_funcs funcs("user32", {
	{ "LoadStringA", LoadStringA },
	{ "LoadAcceleratorsA", LoadAcceleratorsA },
	{ "LoadIconA", LoadIconA },
	{ "LoadImageA", LoadImageA },
	{ "LoadCursorA", LoadCursorA },
	{ "GetForegroundWindow", GetForegroundWindow },
	{ "wsprintfA", (int(*)(char*,const char*))wsprintfA },
	{ "SetRect", SetRect },
	{ "ClientToScreen", ClientToScreen },
	{ "PeekMessageA", PeekMessageA },
	{ "DispatchMessageA", DispatchMessageA },
	{ "TranslateMessage", TranslateMessage },
	{ "RegisterClassA", RegisterClassA },
	{ "GetClassInfoA", GetClassInfoA },
	{ "RegisterClassExA", RegisterClassExA },
	{ "GetSystemMetrics", GetSystemMetrics },
	{ "CreateWindowExA", CreateWindowExA },
	{ "DefWindowProcA", DefWindowProcA },
	{ "UpdateWindow", UpdateWindow },
	{ "BeginPaint", BeginPaint },
	{ "EndPaint", EndPaint },
	{ "SetFocus", SetFocus },
	{ "SetCursor", SetCursor },
	{ "ShowWindow", ShowWindow },
	{ "SetCursorPos", SetCursorPos },
	{ "GetCursorPos", GetCursorPos },
	{ "ShowCursor", ShowCursor },
	{ "ClipCursor", ClipCursor },
	{ "IsIconic", IsIconic },
	{ "IsWindowVisible", IsWindowVisible },
	{ "SetCapture", SetCapture },
	{ "ReleaseCapture", ReleaseCapture },
	{ "KillTimer", KillTimer },
	{ "SetTimer", SetTimer },
	{ "PtInRect", PtInRect },
});

}
