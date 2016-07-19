#ifndef WINDOW_H

#include "wintypes.h"
#include <memory>

namespace native_window {
	using namespace wintypes;

	struct window_impl;

	struct window {
		std::unique_ptr<window_impl> impl;
		window();
		~window();
		bool create(const char* title, DWORD style, DWORD ex_style, int x, int y, int width, int height);
	};
}

#endif

