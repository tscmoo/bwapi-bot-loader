
#include "environment.h"
#include "wintypes.h"
using namespace wintypes;
#include "kernel32.h"
#include <cstring>

namespace ws2_32 {
;

struct WSAData {
	WORD wVersion;
	WORD wHighVersion;
	char szDescription[257];
	char szSystemStatus[129];
	unsigned short iMaxSockets;
	unsigned short iMaxUdpDg;
	void* lpVendorInfo;
};

int WINAPI WSAStartup(WORD version, WSAData* data) {
	data->wVersion = 0x0202;
	data->wHighVersion = 0x0202;
	memcpy(data->szDescription, "WinSock 2.0", 12);
	memcpy(data->szSystemStatus, "Running", 8);
	data->iMaxSockets = 0;
	data->iMaxUdpDg = 0;
	data->lpVendorInfo = nullptr;
	return 0;
}

int WINAPI WSACleanup() {
	return 0;
}

register_funcs funcs({
	{ "ws2_32:ordinal 115", WSAStartup },
	{ "ws2_32:ordinal 116", WSACleanup },
});

}
