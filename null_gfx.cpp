#include "native_window.h"
#include "native_window_drawing.h"
#include "environment.h"
#include "wintypes.h"
using namespace wintypes;
#include "user32.h"

namespace native_window {
struct window_impl {

};

window::window() {
	impl = std::make_unique<window_impl>();
}

window::~window() {
}

bool window::create(const char* title, DWORD style, DWORD ex_style, int x, int y, int width, int height) {
	return false;
}

void window::get_cursor_pos(int* x, int* y) {
	*x = 0;
	*y = 0;
}

bool window::peek_message(MSG* msg) {
	return false;
}

bool window::show_cursor(bool show) {
	return false;
}

bool window::get_key_state(int vkey) {
	return false;
}

}

namespace native_window_drawing {

struct palette_impl : palette {
	palette_impl() {
	}
	virtual ~palette_impl() override {
	}
	virtual void set_colors(color colors[256]) {
	}
};

struct surface_impl : surface {
	virtual void create(wintypes::HWND wnd) override {
	}
	virtual void set_palette(palette* pal) override {

	}
	virtual void* lock() override {
		return nullptr;
	}
	virtual void unlock() override {
	}
};

palette* new_palette() {
	return new palette_impl();
}
void delete_palette(palette* pal) {
	delete pal;
}
surface* new_surface() {
	return new surface_impl();
}
void delete_surface(surface* surf) {
	delete surf;
}

};
