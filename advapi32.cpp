
#include "environ.h"
#include "wintypes.h"
using namespace wintypes;

namespace advapi32 {
;

LONG WINAPI RegOpenKeyExA(void* hkey, const char* subkey, DWORD options, DWORD regsam, void** result) {
	return ERROR_FILE_NOT_FOUND;
}

register_funcs funcs({
	{ "advapi32:RegOpenKeyExA", RegOpenKeyExA }
});

}
