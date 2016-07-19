#include "environment.h"
#include "wintypes.h"
using namespace wintypes;
#include "kernel32.h"
#include <array>

namespace ddraw {
;

static const HRESULT E_INVALIDARG = 0x80070057;

static const HRESULT DDERR_INVALIDPARAMS = E_INVALIDARG;
static const HRESULT DDERR_INVALIDDIRECTDRAWGUID = 0x88760231;

enum DDERRORS : HRESULT {
	DD_OK = 0
};

std::string guid_to_string(const GUID* guid) {
	return format("%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x", guid->Data1, guid->Data2, guid->Data3, guid->Data4[0], guid->Data4[2], guid->Data4[2], guid->Data4[3], guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
}

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

	IDirectDraw7() {
		vftable = &IDirectDraw7_vftable;
	}

	static HRESULT STDCALL SetCooperativeLevel(IDirectDraw7* self, HWND wnd, DWORD flags) {
		log("SetCooperativeLevel %p %#x\n", (void*)wnd, flags);
		return DD_OK;
	}
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
	// fixme pointers
	IDirectDraw7_vftable[20] = &IDirectDraw7::SetCooperativeLevel;
	IDirectDraw7_vftable[21] = &IDirectDraw7::SetDisplayMode;
});

register_funcs funcs("ddraw", {
	{ "DirectDrawCreate", DirectDrawCreate },
});

}