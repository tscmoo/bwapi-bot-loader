#include "native_window.h"
#include "environment.h"
#include "wintypes.h"
using namespace wintypes;
#include "user32.h"
#include "SDL.h"
#include <mutex>

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
		window = SDL_CreateWindow(title, x, y, width, height, flags);
		if (!window) log("SDL_CreateWindow failed: %s\n", SDL_GetError());
		return window != nullptr;
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

}
