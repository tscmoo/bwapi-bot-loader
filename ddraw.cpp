#include "environment.h"
#include "wintypes.h"
using namespace wintypes;
#include "kernel32.h"
#include "native_window_drawing.h"
#include <array>

namespace ddraw {
;

static const HRESULT E_INVALIDARG = 0x80070057;

static const HRESULT DDERR_INVALIDPARAMS = E_INVALIDARG;
static const HRESULT DDERR_INVALIDDIRECTDRAWGUID = 0x88760231;
static const HRESULT DDERR_NOCOOPERATIVELEVELSET = 0x88760212;

enum DDERRORS : HRESULT {
	DD_OK = 0
};

std::string guid_to_string(const GUID* guid) {
	return format("%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x", guid->Data1, guid->Data2, guid->Data3, guid->Data4[0], guid->Data4[2], guid->Data4[2], guid->Data4[3], guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
}

struct PALETTEENTRY {
	BYTE peRed;
	BYTE peGreen;
	BYTE peBlue;
	BYTE peFlags;
};

struct DDCOLORKEY {
	DWORD dwColorSpaceLowValue;
	DWORD dwColorSpaceHighValue;
};

struct DDPIXELFORMAT {
	DWORD dwSize;
	DWORD dwFlags;
	DWORD dwFourCC;
	union {
		DWORD dwRGBBitCount;
		DWORD dwYUVBitCount;
		DWORD dwZBufferBitDepth;
		DWORD dwAlphaBitDepth;
		DWORD dwLuminanceBitCount;
		DWORD dwBumpBitCount;
		DWORD dwPrivateFormatBitCount;
	};
	union {
		DWORD dwRBitMask;
		DWORD dwYBitMask;
		DWORD dwStencilBitDepth;
		DWORD dwLuminanceBitMask;
		DWORD dwBumpDuBitMask;
		DWORD dwOperations;
	};
	union {
		DWORD dwGBitMask;
		DWORD dwUBitMask;
		DWORD dwZBitMask;
		DWORD dwBumpDvBitMask;
		struct {
			WORD wFlipMSTypes;
			WORD wBltMSTypes;
		} MultiSampleCaps;
	};
	union {
		DWORD dwBBitMask;
		DWORD dwVBitMask;
		DWORD dwStencilBitMask;
		DWORD dwBumpLuminanceBitMask;
	};
	union {
		DWORD dwRGBAlphaBitMask;
		DWORD dwYUVAlphaBitMask;
		DWORD dwLuminanceAlphaBitMask;
		DWORD dwRGBZBitMask;
		DWORD dwYUVZBitMask;
	};
};

struct DDSCAPS2 {
	DWORD dwCaps;
	DWORD dwCaps2;
	DWORD dwCaps3;
	DWORD dwCaps4;
};

struct DDSURFACEDESC2 {
	DWORD dwSize;
	DWORD dwFlags;
	DWORD dwHeight;
	DWORD dwWidth;
	union {
		LONG lPitch;
		DWORD dwLinearSize;
	};
	union {
		DWORD dwBackBufferCount;
		DWORD dwDepth;
	};
	union {
		DWORD dwMipMapCount;
		DWORD dwRefreshRate;
		DWORD dwSrcVBHandle;
	};
	DWORD dwAlphaBitDepth;
	DWORD dwReserved;
	pointer32_T<void> lpSurface;
	union {
		DDCOLORKEY ddckCKDestOverlay;
		DWORD dwEmptyFaceColor;
	};
	DDCOLORKEY ddckCKDestBlt;
	DDCOLORKEY ddckCKSrcOverlay;
	DDCOLORKEY ddckCKSrcBlt;
	union {
		DDPIXELFORMAT ddpfPixelFormat;
		DWORD dwFVF;
	};
	DDSCAPS2 ddsCaps;
	DWORD dwTextureStage;
};


// IDirectDrawPalette
// 0  QueryInterface
// 1  AddRef
// 2  Release
// 3  GetCaps
// 4  GetEntries
// 5  Initialize
// 6  SetEntries
std::array<pointer32_T<void>, 7> IDirectDrawPalette_vftable;

struct IDirectDrawPalette {
	pointer32_T<std::array<pointer32_T<void>, 7>> vftable;
	std::array<PALETTEENTRY, 256> palette;

	native_window_drawing::palette* pal;

	IDirectDrawPalette() {
		vftable = &IDirectDrawPalette_vftable; // fixme pointer

		pal = native_window_drawing::new_palette();
	}
	~IDirectDrawPalette() {
		native_window_drawing::delete_palette(pal);
	}
	void palette_changed() {
		std::array<native_window_drawing::color, 256> colors;
		for (size_t i = 0; i < 256; ++i) {
			colors[i].r = palette[i].peRed;
			colors[i].g = palette[i].peGreen;
			colors[i].b = palette[i].peBlue;
			colors[i].a = 255;
		}
		pal->set_colors(colors.data());
	}
	static HRESULT STDCALL GetEntries(IDirectDrawPalette* self, DWORD flags, DWORD base, DWORD num_entries, PALETTEENTRY* out_entries) {
		if (flags) return DDERR_INVALIDPARAMS;
		for (size_t i = 0; i < (size_t)num_entries; ++i) {
			out_entries[i] = self->palette[(size_t)base + i];
		}
		self->palette_changed();
		return DD_OK;
	}
	static HRESULT STDCALL SetEntries(IDirectDrawPalette* self, DWORD flags, DWORD base, DWORD num_entries, PALETTEENTRY* in_entries) {
		if (flags) return DDERR_INVALIDPARAMS;
		for (size_t i = 0; i < (size_t)num_entries; ++i) {
			self->palette[(size_t)base + i] = in_entries[i];
			log("set palette entry %u to %u %u %u %u\n", (size_t)base + i, in_entries[i].peRed, in_entries[i].peGreen, in_entries[i].peBlue, in_entries->peFlags);
		}
		self->palette_changed();
		return DD_OK;
	}
};

// 0  QueryInterface
// 1  AddRef
// 2  Release
// 3  AddAttachedSurface
// 4  AddOverlayDirtyRect
// 5  Blt
// 6  BltBatch
// 7  BltFast
// 8  DeleteAttachedSurface
// 9  EnumAttachedSurfaces
// 10 EnumOverlayZOrders
// 11 Flip
// 12 GetAttachedSurface
// 13 GetBltStatus
// 14 GetCaps
// 15 GetClipper
// 16 GetColorKey
// 17 GetDC
// 18 GetFlipStatus
// 19 GetOverlayPosition
// 20 GetPalette
// 21 GetPixelFormat
// 22 GetSurfaceDesc
// 23 Initialize
// 24 IsLost
// 25 Lock
// 26 ReleaseDC
// 27 Restore
// 28 SetClipper
// 29 SetColorKey
// 30 SetOverlayPosition
// 31 SetPalette
// 32 Unlock
// 33 UpdateOverlay
// 34 UpdateOverlayDisplay
// 35 UpdateOverlayZOrder
std::array<pointer32_T<void>, 36> IDirectDrawSurface_vftable;

struct IDirectDrawSurface {
	pointer32_T<std::array<pointer32_T<void>, 36>> vftable;
	IDirectDrawPalette* palette = nullptr;
	DDSURFACEDESC2 desc;
	native_window_drawing::surface* surf;
	IDirectDrawSurface() {
		vftable = &IDirectDrawSurface_vftable; // fixme pointer
		surf = native_window_drawing::new_surface();
	}
	~IDirectDrawSurface() {
		native_window_drawing::delete_surface(surf);
	}

	// 25
	static HRESULT STDCALL Lock(IDirectDrawSurface* self, RECT* rect, DDSURFACEDESC2* inout_desc, DWORD flags, HANDLE event) {
		if (event) return DDERR_INVALIDPARAMS;
		//log("lock flags %#x, desc flags %#x\n", flags, inout_desc->dwFlags);
		if (rect) fatal_error("lock rect");
		inout_desc->lpSurface = self->surf->lock();
		//log("locked surface is %p\n", (void*)inout_desc->lpSurface);
		inout_desc->dwWidth = 640;
		inout_desc->dwHeight = 480;
		inout_desc->lPitch = 640;
		return DD_OK;
	}

	// 31
	static HRESULT STDCALL SetPalette(IDirectDrawSurface* self, IDirectDrawPalette* palette) {
		self->palette = palette;
		self->surf->set_palette(palette->pal);
		return DD_OK;
	}

	// 32
	static HRESULT STDCALL Unlock(IDirectDrawSurface* self, RECT* rect) {
		self->surf->unlock();
		return DD_OK;
	}
};

// IDirectDraw7
// 0  QueryInterface
// 1  AddRef
// 2  Release
// 3  Compact
// 4  CreateClipper
// 5  CreatePalette
// 6  CreateSurface
// 7  DuplicateSurface
// 8  EnumDisplayModes
// 9  EnumSurfaces
// 10 FlipToGDISurface
// 11 GetCaps
// 12 GetDisplayMode
// 13 GetFourCCCodes
// 14 GetGDISurface
// 15 GetMonitorFrequency
// 16 GetScanLine
// 17 GetVerticalBlankStat
// 18 Initialize
// 19 RestoreDisplayMode
// 20 SetCooperativeLevel
// 21 SetDisplayMode
// 22 WaitForVerticalBlank
// 23 GetAvailableVidMem
// 24 GetSurfaceFromDC
// 25 RestoreAllSurfaces
// 26 TestCooperativeLevel
// 27 GetDeviceIdentifier
// 28 StartModeTest
// 29 EvaluateMode
std::array<pointer32_T<void>, 30> IDirectDraw7_vftable;

struct IDirectDraw7 {
	pointer32_T<std::array<pointer32_T<void>, 30>> vftable;
	HWND wnd = nullptr32;

	IDirectDraw7() {
		vftable = &IDirectDraw7_vftable; // fixme pointer
	}

	// 5
	static HRESULT STDCALL CreatePalette(IDirectDraw7* self, DWORD flags, PALETTEENTRY* colors, pointer32_T<IDirectDrawPalette>* out_iface, void* p_null) {
		if (p_null) return DDERR_INVALIDPARAMS;
		if (flags == 0x44) {
// 			for (size_t i = 0; i < 256; ++i) {
// 				log("%d: %02x %02x %02x %02x\n", i, colors[i].peRed, colors[i].peGreen, colors[i].peBlue, colors[i].peFlags);
// 			}
			auto* r = new IDirectDrawPalette();
			for (size_t i = 0; i < 256; ++i) {
				r->palette[i] = colors[i];
			}
			r->palette_changed();
			log("CreatePalette ok\n");
			*out_iface = r;
			return DD_OK;
		} else fatal_error("CreatePalette: unknown flags %#x", flags);
		return -1;
	}
	// 6
	static HRESULT STDCALL CreateSurface(IDirectDraw7* self, DDSURFACEDESC2* desc, pointer32_T<IDirectDrawSurface>* out_iface, void* p_null) {
		if (p_null) return DDERR_INVALIDPARAMS;
		if (!self->wnd) return DDERR_NOCOOPERATIVELEVELSET;
		if (desc->dwFlags == 1) { // caps
			log("caps: %#x\n", desc->ddsCaps.dwCaps);
			if (desc->ddsCaps.dwCaps != 0x200) fatal_error("CreateSurface: unknown caps %#x\n", desc->ddsCaps.dwCaps);
			auto* r = new IDirectDrawSurface();
			r->desc = *desc;
			*out_iface = r;
			r->surf->create(self->wnd);
			log("CreateSurface ok\n");
			return DD_OK;
		}
		fatal_error("CreateSurface: unknown flags %#x", desc->dwFlags);
		return -1;
	}
	// 20
	static HRESULT STDCALL SetCooperativeLevel(IDirectDraw7* self, HWND wnd, DWORD flags) {
		log("SetCooperativeLevel %p %#x\n", to_pointer(wnd), flags);
		self->wnd = wnd;
		return DD_OK;
	}
	// 21
	static HRESULT STDCALL SetDisplayMode(IDirectDraw7* self, DWORD width, DWORD height, DWORD bpp, DWORD refresh_rate, DWORD flags) {
		log("SetDisplayMode %p %d %d %d %d %#x\n", self, width, height, bpp, refresh_rate, flags);
		return DD_OK;
	}
};

HRESULT STDCALL DirectDrawCreate(const GUID* guid, pointer32_T<IDirectDraw7>* out_iface, void* p_null) {
	if (p_null) return DDERR_INVALIDPARAMS;
	*out_iface = new IDirectDraw7(); // fixme pointer
	return 0;
}

oninit_func oninit([] {
	for (size_t i = 0; i < IDirectDraw7_vftable.size(); ++i) {
		IDirectDraw7_vftable[i] = environment::get_unimplemented_stub(format("ddraw::IDirectDraw7::vfunction %d", i));
	}

	for (size_t i = 0; i < IDirectDrawPalette_vftable.size(); ++i) {
		IDirectDrawPalette_vftable[i] = environment::get_unimplemented_stub(format("ddraw::IDirectDrawPalette::vfunction %d", i));
	}

	for (size_t i = 0; i < IDirectDrawSurface_vftable.size(); ++i) {
		IDirectDrawSurface_vftable[i] = environment::get_unimplemented_stub(format("ddraw::IDirectDrawSurface::vfunction %d", i));
	}

	// fixme pointers

	IDirectDrawPalette_vftable[4] = &IDirectDrawPalette::GetEntries;
	IDirectDrawPalette_vftable[6] = &IDirectDrawPalette::SetEntries;

	IDirectDrawSurface_vftable[31] = &IDirectDrawSurface::SetPalette;
	IDirectDrawSurface_vftable[25] = &IDirectDrawSurface::Lock;
	IDirectDrawSurface_vftable[32] = &IDirectDrawSurface::Unlock;

	IDirectDraw7_vftable[5] = &IDirectDraw7::CreatePalette;
	IDirectDraw7_vftable[6] = &IDirectDraw7::CreateSurface;
	IDirectDraw7_vftable[20] = &IDirectDraw7::SetCooperativeLevel;
	IDirectDraw7_vftable[21] = &IDirectDraw7::SetDisplayMode;
});

register_funcs funcs("ddraw", {
	{ "DirectDrawCreate", DirectDrawCreate },
});

}
