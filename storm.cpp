// I don't care if videos work right now, so we override
// the video functions here to do nothing for now.

#include "environment.h"

namespace storm {
;

int STDCALL SVidPlayBegin(const char* filename, int, int, int, int, int, int32_t* h) {
	*h = 1;
	return 0;
}

int STDCALL SVidPlayContinueSingle(int h, int, int) {
	return 0;
}

int STDCALL SVidPlayEnd(int h) {
	return 0;
}

register_funcs funcs("storm", {
	{ "ordinal 454", SVidPlayBegin },
	{ "ordinal 457", SVidPlayContinueSingle },
	{ "ordinal 458", SVidPlayEnd },
});

}
