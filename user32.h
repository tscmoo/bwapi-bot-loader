#ifndef USER32_H
#define USER32_H

#include "wintypes.h"

namespace native_window {
	struct window;
}

namespace user32 {
	using namespace wintypes;

	enum windowstyles : DWORD {
		WS_VISIBLE = 0x10000000
	};

	enum wms {
		WM_CREATE = 1,
		WM_MOVE = 3,
		WM_SIZE = 5,
		WM_ACTIVATE = 6,
		WM_SETFOCUS = 7,
		WM_SHOWWINDOW = 0x18,
		WM_PAINT = 0xf,
		WM_ACTIVATEAPP = 0x1c,
		WM_TIMER = 0x113,
		WM_MOUSEMOVE = 0x200,
		WM_LBUTTONDOWN = 0x201,
		WM_LBUTTONUP = 0x202,
		WM_RBUTTONDOWN = 0x204,
		WM_RBUTTONUP = 0x205,
	};

	native_window::window* get_native_window(HWND h);

}

#endif
