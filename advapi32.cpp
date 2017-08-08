
#include "environment.h"
#include "wintypes.h"
using namespace wintypes;
#include "kernel32.h"

#include <random>
#include <mutex>
#include <thread>

namespace advapi32 {
;

LONG WINAPI RegOpenKeyExA(void* hkey, const char* subkey, DWORD options, DWORD regsam, void** result) {
	return ERROR_FILE_NOT_FOUND;
}

LONG WINAPI RegCreateKeyExA(void* hkey, const char* subkey, DWORD reserved, const char* classname, DWORD options, void* regsam, void* security_attributes, void** result, DWORD* disposition) {
	return ERROR_NOT_SUPPORTED;
}

BOOL WINAPI AllocateAndInitializeSid(void*, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, void*) {
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}

BOOL WINAPI CryptAcquireContextA(void**, const char*, const char*, DWORD, DWORD) {
	kernel32::SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}

struct rng_t {
	std::mt19937 e;
	rng_t() {
		std::array<uint32_t, 8> arr;
		arr[0] = 42;
		arr[1] = (uint32_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();
		arr[2] = (uint32_t)std::hash<std::thread::id>()(std::this_thread::get_id());
		arr[3] = (uint32_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();;
		arr[4] = (uint32_t)std::chrono::steady_clock::now().time_since_epoch().count();
		arr[5] = (uint32_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();;
		arr[6] = (uint32_t)std::chrono::system_clock::now().time_since_epoch().count();
		arr[7] = 1;
		std::seed_seq seq(arr.begin(), arr.end());
		e = std::mt19937(seq);
	}

	void generate(char* dst, size_t len) {
		std::uniform_int_distribution<int> d(0, 255);
		for (;len; --len) *dst = d(e);
	}
};

std::mutex rng_mut;
std::unique_ptr<rng_t> rng;

BOOL WINAPI RtlGenRandom(char* dst, ULONG len) {
	std::lock_guard<std::mutex> l(rng_mut);
	if (!rng) rng = std::make_unique<rng_t>();
	rng->generate(dst, (size_t)len);
	return TRUE;
}

register_funcs funcs("advapi32", {
	{ "RegOpenKeyExA", RegOpenKeyExA },
	{ "RegCreateKeyExA", RegCreateKeyExA },
	{ "AllocateAndInitializeSid", AllocateAndInitializeSid },
	{ "CryptAcquireContextA", CryptAcquireContextA },
	{ "SystemFunction036", RtlGenRandom }
});

}
