#ifndef WINTYPES_H
#define WINTYPES_H

#include <stdint.h>

namespace wintypes {

	using BYTE = uint8_t;
	using WORD = uint16_t;
	using DWORD = uint32_t;

	using CHAR = int8_t;
	using SHORT = int16_t;
	using LONG = int32_t;

	using UINT = uint32_t;
	using ULONG = uint32_t;
	using ULONG_PTR = uint32_t;

	using SIZE_T = uint32_t;

	enum BOOL : int32_t {
		FALSE = 0,
		TRUE = 1
	};

	using HMODULE = void*;
	using HANDLE = void*;

	static const HANDLE INVALID_HANDLE_VALUE = (HANDLE)-1;

	enum errors {
		ERROR_SUCCESS = 0,
		ERROR_FILE_NOT_FOUND = 2,
		ERROR_INVALID_PARAMETER = 87,
		ERROR_INSUFFICIENT_BUFFER = 122,
		ERROR_MOD_NOT_FOUND = 126,
		ERROR_PROC_NOT_FOUND = 127,
	};

	enum PAGE_PROTECT : DWORD {
		PAGE_NOACCESS = 1,
		PAGE_READONLY = 2,
		PAGE_READWRITE = 4,
		PAGE_EXECUTE = 0x10,
		PAGE_EXECUTE_READ = 0x20,
		PAGE_EXECUTE_READWRITE = 0x40,
	};

	enum MEM_STATE : DWORD {
		MEM_COMMIT = 0x1000,
		MEM_RESERVE = 0x2000,
		MEM_FREE = 0x10000
	};

	struct IMAGE_DOS_HEADER {
		WORD e_magic;
		WORD e_cblp;
		WORD e_cp;
		WORD e_crlc;
		WORD e_cparhdr;
		WORD e_minalloc;
		WORD e_maxalloc;
		WORD e_ss;
		WORD e_sp;
		WORD e_csum;
		WORD e_ip;
		WORD e_cs;
		WORD e_lfarlc;
		WORD e_ovno;
		WORD e_res[4];
		WORD e_oemid;
		WORD e_oeminfo;
		WORD e_res2[10];
		LONG e_lfanew;
	};

	struct IMAGE_FILE_HEADER {
		WORD Machine;
		WORD NumberOfSections;
		DWORD TimeDateStamp;
		DWORD PointerToSymbolTable;
		DWORD NumberOfSymbols;
		WORD SizeOfOptionalHeader;
		WORD Characteristics;
	};

	struct IMAGE_DATA_DIRECTORY {
		DWORD VirtualAddress;
		DWORD Size;
	};

	struct IMAGE_OPTIONAL_HEADER {
		WORD Magic;
		BYTE MajorLinkerVersion;
		BYTE MinorLinkerVersion;
		DWORD SizeOfCode;
		DWORD SizeOfInitializedData;
		DWORD SizeOfUninitializedData;
		DWORD AddressOfEntryPoint;
		DWORD BaseOfCode;
		DWORD BaseOfData;
		DWORD ImageBase;
		DWORD SectionAlignment;
		DWORD FileAlignment;
		WORD MajorOperatingSystemVersion;
		WORD MinorOperatingSystemVersion;
		WORD MajorImageVersion;
		WORD MinorImageVersion;
		WORD MajorSubsystemVersion;
		WORD MinorSubsystemVersion;
		DWORD Win32VersionValue;
		DWORD SizeOfImage;
		DWORD SizeOfHeaders;
		DWORD CheckSum;
		WORD Subsystem;
		WORD DllCharacteristics;
		DWORD SizeOfStackReserve;
		DWORD SizeOfStackCommit;
		DWORD SizeOfHeapReserve;
		DWORD SizeOfHeapCommit;
		DWORD LoaderFlags;
		DWORD NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[16];
	};

	struct IMAGE_SECTION_HEADER {
		BYTE Name[8];
		union {
			DWORD PhysicalAddress;
			DWORD VirtualSize;
		} Misc;
		DWORD VirtualAddress;
		DWORD SizeOfRawData;
		DWORD PointerToRawData;
		DWORD PointerToRelocations;
		DWORD PointerToLinenumbers;
		WORD NumberOfRelocations;
		WORD NumberOfLinenumbers;
		DWORD Characteristics;
	};

	struct IMAGE_BASE_RELOCATION {
		DWORD VirtualAddress;
		DWORD SizeOfBlock;
	};

	struct IMAGE_IMPORT_DESCRIPTOR {
		DWORD OriginalFirstThunk;
		DWORD TimeDateStamp;
		DWORD ForwarderChain;
		DWORD Name;
		DWORD FirstThunk;
	};

	struct CRITICAL_SECTION {
		void* DebugInfo;
		LONG LockCount;
		LONG RecursionCount;
		HANDLE OwningThread;
		HANDLE LockSemaphore;
		ULONG_PTR SpinCount;
	};

	struct STARTUPINFOA {
		DWORD cb;
		const char* lpReserved;
		const char* lpDesktop;
		const char* lpTitle;
		DWORD dwX;
		DWORD dwY;
		DWORD dwXSize;
		DWORD dwYSize;
		DWORD dwXCountChars;
		DWORD dwYCountChars;
		DWORD dwFillAttribute;
		DWORD dwFlags;
		WORD wShowWindow;
		WORD cbReserved2;
		BYTE* lpReserved2;
		HANDLE hStdInput;
		HANDLE hStdOutput;
		HANDLE hStdError;
	};

	struct MEMORY_BASIC_INFORMATION {
		void* BaseAddress;
		void* AllocationBase;
		DWORD AllocationProtect;
		SIZE_T RegionSize;
		DWORD State;
		DWORD Protect;
		DWORD Type;
	};

	struct EXCEPTION_RECORD {
		DWORD ExceptionCode;
		DWORD ExceptionFlags;
		EXCEPTION_RECORD* ExceptionRecord;
		void* ExceptionAddress;
		DWORD NumberParameters;
		ULONG_PTR ExceptionInformation[15];
	};

	struct EXCEPTION_POINTERS {
		EXCEPTION_RECORD* ExceptionRecord;
		//CONTEXT* ContextRecord;
	};

	struct CPINFO {
		UINT MaxCharSize;
		BYTE DefaultChar[2];
		BYTE LeadByte[12];
	};

};

#endif
