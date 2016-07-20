
#include "environment.h"
#include "wintypes.h"
using namespace wintypes;
#include "kernel32.h"

namespace gdi32 {
;

using HGDIOBJ = void*;

enum {
	NULL_BRUSH = 5,
	HOLLOW_BRUSH = 5,
};

int null_brush;

HGDIOBJ WINAPI GetStockObject(int n) {
	if (n == NULL_BRUSH) {
		return &null_brush;
	}
	fatal_error("GetStockObject %d", n);
	return nullptr;
}

void* WINAPI CreatePalette(void*) {
	return nullptr;
}

register_funcs funcs("gdi32", {
	{ "GetStockObject", GetStockObject },
	{ "CreatePalette", CreatePalette },
});

}
