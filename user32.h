#ifndef USER32_H
#define USER32_H

#include "wintypes.h"

namespace user32 {
	using namespace wintypes;

	enum windowstyles : DWORD {
		WS_VISIBLE = 0x10000000
	};

	enum wms {
		WM_CREATE = 1,
		WM_PAINT = 0xf
	};

}

#endif
