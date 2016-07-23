#include "native_window.h"
#include "native_window_drawing.h"
#include "environment.h"
#include "wintypes.h"
using namespace wintypes;
#include "user32.h"
#include "SDL.h"
#include <mutex>
#include <array>

namespace native_window {
;

std::mutex init_mut;
bool sdl_initialized = false;
void sdl_init() {
	std::lock_guard<std::mutex> l(init_mut);
	if (!sdl_initialized) {
		if (SDL_Init(SDL_INIT_VIDEO) == 0) {
			sdl_initialized = true;
		} else {
			log("SDL_Init failed: %s\n", SDL_GetError());
		}
	}
}

static const int sdl_scancode_to_vk_table[] = {
	0,0,0,0,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x31,0x32,
	0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0xd,0x1b,0x8,0x9,0x20,0xbb,0xdb,0xdd,0xba,0xbf,0,0xc0,0xde,0xdc,0xbc,0xbe,0xbd,0x14,0x70,0x71,0x72,0x73,0x74,0x75,
	0x76,0x77,0x78,0x79,0x7a,0x7b,0x6a,0x91,0x13,0x2d,0x24,0x21,0x2e,0x23,0x22,0x27,0x25,0x28,0x26,0x90,0xbd,0x1006a,0x6d,0x14,0xd,0x10023,0x10028,0x10022,0x10025,0xc,0x10027,0x10024,
	0x10026,0x10021,0x1002d,0x1002e,0xe2,0xf9,0,0x92,0x7c,0x7d,0x7e,0x7f,0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x2b,0x2f,0,0x29,0,0,0,0,0,0,0,0,
	0xaf,0xae,0,0,0,0,0,0xc1,0,0,0,0xeb,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xf6,0,0xc,0,0,0,
	0,0,0,0xf7,0xf8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0x11,0x10,0x12,0xf1,0x11,0x10,0x12,0xea,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0x1f,0xb0,0xb1,0xb2,0xb3,0xad,0xb5,0,0xb4,0,0,0xaa,0xac,0xa6,0xa7,0xa9,0xa8,0xab,0,0,0,0,0,0,0,0,0xb6,0xb7,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

struct window_impl {

	SDL_Window* window = nullptr;

	window_impl() {
		sdl_init();
	}
	~window_impl() {
		if (window) SDL_DestroyWindow(window);
	}

	bool create(const char* title, DWORD style, DWORD ex_style, int x, int y, int width, int height) {
		Uint32 flags = 0;
		if (~style & user32::WS_VISIBLE) flags |= SDL_WINDOW_HIDDEN;
		window = SDL_CreateWindow(title, SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED, width, height, flags);
		if (!window) log("SDL_CreateWindow failed: %s\n", SDL_GetError());
		if (window) {
			SDL_StartTextInput();
		}
		return window != nullptr;
	}

	void get_cursor_pos(int* x, int* y) {
		SDL_GetMouseState(x, y);
	}

	std::array<int, 0x100> key_state {};

	bool peek_message(MSG* msg) {
		SDL_Event e;
		if (!SDL_PollEvent(&e)) return false;
		switch (e.type) {
		case SDL_MOUSEMOTION:
			msg->message = user32::WM_MOUSEMOVE;
			msg->wParam = 0;
			msg->lParam = MAKELPARAM(e.motion.x, e.motion.y);
			return true;
		case SDL_MOUSEBUTTONDOWN:
		case SDL_MOUSEBUTTONUP: {
			bool down = e.type == SDL_MOUSEBUTTONDOWN;
			bool left = e.button.button == SDL_BUTTON_LEFT;
			bool middle = e.button.button == SDL_BUTTON_MIDDLE;
			bool right = e.button.button == SDL_BUTTON_RIGHT;
			bool x1 = e.button.button == SDL_BUTTON_X1;
			bool x2 = e.button.button == SDL_BUTTON_X2;

			WPARAM w = 0;
			auto state = SDL_GetMouseState(nullptr, nullptr);
			if (state & SDL_BUTTON(SDL_BUTTON_LEFT)) w |= 1;
			if (state & SDL_BUTTON(SDL_BUTTON_RIGHT)) w |= 2;

			msg->lParam = MAKELPARAM(e.button.x, e.button.y);
			if (left) {
				msg->message = down ? user32::WM_LBUTTONDOWN : user32::WM_LBUTTONUP;
				return true;
			} else if (right) {
				msg->message = down ? user32::WM_RBUTTONDOWN : user32::WM_RBUTTONUP;
				return true;
			}
		}
		case SDL_KEYDOWN:
		case SDL_KEYUP: {
			bool key_down = e.type == SDL_KEYDOWN;

			unsigned int vkey = sdl_scancode_to_vk_table[e.key.keysym.scancode];
			bool extended = false;
			if (vkey & (1 << 16)) {
				extended = true;
				vkey &= ~(1 << 16);
			}
			key_state[vkey] = key_down ? 1 : 0;

			msg->message = key_down ? user32::WM_KEYDOWN : user32::WM_KEYUP;
			msg->wParam = (uint8_t)vkey;
			msg->lParam = (uint32_t)(uint16_t)e.key.repeat | ((uint32_t)(uint8_t)e.key.keysym.scancode << 16);
			if (extended) msg->lParam |= 1 << 24;
			if (key_down && e.key.repeat) msg->lParam |= 1 << 30;
			if (!key_down) msg->lParam |= 1 << 30;
			if (!key_down) msg->lParam |= 1 << 31;
			return true;
		}
		case SDL_TEXTINPUT: {
			// This is the wrong way to generate WM_CHAR messages, it should be done
			// in TranslateMessage
			msg->message = user32::WM_CHAR;
			msg->wParam = e.text.text[0];
			msg->lParam = 0;
			return true;
			break;
		}
		}
		return false;
	}

	bool show_cursor(bool show) {
		return SDL_ShowCursor(show ? SDL_ENABLE : SDL_DISABLE) ? true : false;
	}

	bool get_key_state(int vkey) {
		return key_state[vkey] ? true : false;
	}

};

window::window() {
	impl = std::make_unique<window_impl>();
}

window::~window() {
}

bool window::create(const char* title, DWORD style, DWORD ex_style, int x, int y, int width, int height) {
	return impl->create(title, style, ex_style, x, y, width, height);
}

void window::get_cursor_pos(int* x, int* y) {
	return impl->get_cursor_pos(x, y);
}

bool window::peek_message(MSG* msg) {
	return impl->peek_message(msg);
}

bool window::show_cursor(bool show) {
	return impl->show_cursor(show);
}

bool window::get_key_state(int vkey) {
	return impl->get_key_state(vkey);
}

}

namespace native_window_drawing {
;

struct palette_impl : palette {
	SDL_Palette* pal = nullptr;
	palette_impl() {
		pal = SDL_AllocPalette(256);
	}
	virtual ~palette_impl() override {
		SDL_FreePalette(pal);
	}
	virtual void set_colors(color colors[256]) {
		std::array<SDL_Color, 256> col;
		for (size_t i = 0; i < 256; ++i) {
			col[i].r = colors[i].r;
			col[i].g = colors[i].g;
			col[i].b = colors[i].b;
			col[i].a = colors[i].a;
		}
		if (SDL_SetPaletteColors(pal, col.data(), 0, 256)) fatal_error("SDL_SetPaletteColors failed: %s", SDL_GetError());
	}
};

struct surface_impl : surface {
	SDL_Surface* window_s = nullptr;
	SDL_Surface* surf = nullptr;
	SDL_Window* window = nullptr;
	virtual void create(wintypes::HWND wnd) override {
		window = user32::get_native_window(wnd)->impl->window;
		window_s = SDL_GetWindowSurface(window);
		if (!window_s) fatal_error("SDL_GetWindowSurface failed: %s", SDL_GetError());

		surf = SDL_ConvertSurfaceFormat(window_s, SDL_PIXELFORMAT_INDEX8, 0);
		if (!surf) fatal_error("SDL_ConvertSurfaceFormat failed: %s", SDL_GetError());
	}
	virtual void set_palette(palette* pal) override {
		if (SDL_SetSurfacePalette(surf, ((palette_impl*)pal)->pal)) fatal_error("SDL_SetSurfacePalette failed: %s", SDL_GetError());
	}
	virtual void* lock() override {
		if (SDL_LockSurface(surf)) fatal_error("SDL_LockSurface failed: %s", SDL_GetError());
		return surf->pixels;
	}
	virtual void unlock() override {
		SDL_UnlockSurface(surf);
		SDL_BlitSurface(surf, nullptr, window_s, nullptr);
		SDL_UpdateWindowSurface(window);
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
