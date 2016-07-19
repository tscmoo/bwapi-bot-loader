
#include "environment.h"
#include "wintypes.h"
using namespace wintypes;
#include "kernel32.h"

namespace advapi32 {
;

LONG WINAPI RegOpenKeyExA(void* hkey, const char* subkey, DWORD options, DWORD regsam, void** result) {
	return ERROR_FILE_NOT_FOUND;
}

BOOL WINAPI AllocateAndInitializeSid(void*, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, void*) {
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}

BOOL WINAPI CryptAcquireContextA(void**, const char*, const char*, DWORD, DWORD) {
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}

register_funcs funcs("advapi32", {
	{ "RegOpenKeyExA", RegOpenKeyExA },
	{ "AllocateAndInitializeSid", AllocateAndInitializeSid },
	{ "CryptAcquireContextA", CryptAcquireContextA },
});

}
