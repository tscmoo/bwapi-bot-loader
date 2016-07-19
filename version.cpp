
#include "environment.h"
#include "wintypes.h"
using namespace wintypes;
#include "kernel32.h"

namespace version {
;


DWORD WINAPI GetFileVersionInfoSizeA(const char* filename, DWORD* out_handle) {
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return 0;
}

register_funcs funcs("version", {
	{ "GetFileVersionInfoSizeA", GetFileVersionInfoSizeA },
});

}
