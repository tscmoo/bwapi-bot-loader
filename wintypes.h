#ifndef WINTYPES_H
#define WINTYPES_H

#include "environment.h"
#include <stdint.h>

namespace wintypes {

	using BYTE = uint8_t;
	using WORD = uint16_t;
	using DWORD = uint32_t;

	using CHAR = int8_t;
	using SHORT = int16_t;
	using LONG = int32_t;

	using UCHAR = uint8_t;
	using USHORT = uint16_t;
	using UINT = uint32_t;
	using ULONG = uint32_t;

	using UINT_PTR = uint32_t;
	using LONG_PTR = int32_t;
	using ULONG_PTR = uint32_t;
	using DWORD_PTR = uint32_t;

	using SIZE_T = uint32_t;

	enum BOOL : int32_t {
		FALSE = 0,
		TRUE = 1
	};

	using pointer32_t = uint32_t;

	template<typename T>
	struct pointer32_T {
		uint32_t value = 0;
		pointer32_T() = default;
		pointer32_T(std::nullptr_t) : value(0) {};
		pointer32_T(T* value) : value((uint32_t)(uintptr_t)value) {}
		pointer32_T(const pointer32_T&) = default;
		template<typename T2>
		explicit pointer32_T(T2 value) : pointer32_T((T*)(uintptr_t)value) {}
		template<typename T2>
		pointer32_T& operator=(T2* v) {
			value = (uint32_t)(uintptr_t)(T*)(uintptr_t)v;
			return *this;
		}
		operator T*() {
			return (T*)value;
		}
		explicit operator bool() const {
			return value != 0;
		}
		template<typename T2>
		explicit operator T2() const {
			return (T2)value;
		}
		template<typename T2>
		bool operator==(const T2& n) const {
			return (uintptr_t)value == (uintptr_t)(T*)n;
		}
		template<typename T2>
		bool operator!=(const T2& n) const {
			return (uintptr_t)value == (uintptr_t)(T*)n;
		}
		template<typename T1 = T, typename std::enable_if<!std::is_same<T1, void>::value>::type* = nullptr, typename T2 = std::conditional<std::is_same<T1, void>, int, T1>::type>
		T2& operator*() const {
			return *(T2*)value;
		}
		template<typename T1 = T, typename std::enable_if<!std::is_same<T1, void>::value>::type* = nullptr>
		T* operator->() const {
			return (T*)value;
		}
	};

	static const pointer32_t nullptr32 = 0;

	static pointer32_t to_pointer32(void* ptr) {
		pointer32_t r = (pointer32_t)(uintptr_t)ptr;
		if ((uintptr_t)r != (uintptr_t)ptr) fatal_error("to_pointer32: the pointer %p does not fit in 32 bits", ptr);
		return r;
	}

	using HMODULE = pointer32_t;
	using HANDLE = pointer32_t;
	using HINSTANCE = pointer32_t;
	using HWND = pointer32_t;
	using HDC = pointer32_t;

	using ATOM = WORD;

	using LRESULT = LONG_PTR;
	using WPARAM = UINT_PTR;
	using LPARAM = LONG_PTR;

	using HRESULT = LONG;

	static const HANDLE INVALID_HANDLE_VALUE = (HANDLE)-1;

	static const DWORD GENERIC_READ = 0x80000000;
	static const DWORD GENERIC_WRITE = 0x40000000;
	static const DWORD GENERIC_ALL = 0x10000000;

	enum errors {
		ERROR_SUCCESS = 0,
		ERROR_FILE_NOT_FOUND = 2,
		ERROR_PATH_NOT_FOUND = 3,
		ERROR_INVALID_HANDLE = 6,
		ERROR_NOT_ENOUGH_MEMORY = 8,
		ERROR_READ_FAULT = 30,
		ERROR_NOT_SUPPORTED = 50,
		ERROR_INVALID_PARAMETER = 87,
		ERROR_OPEN_FAILED = 110,
		ERROR_INSUFFICIENT_BUFFER = 122,
		ERROR_MOD_NOT_FOUND = 126,
		ERROR_PROC_NOT_FOUND = 127,
		ERROR_NOT_OWNER = 288,
		ERROR_INVALID_ADDRESS = 487,
		ERROR_FILE_INVALID = 1006,
		ERROR_CANNOT_FIND_WND_CLASS = 1407,
		ERROR_CLASS_ALREADY_EXISTS = 1410,
		ERROR_NO_SYSTEM_RESOURCES = 1450
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

	enum FREE_TYPE : DWORD {
		MEM_DECOMMIT = 0x4000,
		MEM_RELEASE = 0x8000
	};

	enum FILE_TYPE : DWORD {
		FILE_TYPE_UNKNOWN = 0,
		FILE_TYPE_DISK = 1,
		FILE_TYPE_CHAR = 2,
		FILE_TYPE_PIPE = 3
	};

	enum MOVE_METHOD : DWORD {
		FILE_BEGIN = 0,
		FILE_CURRENT = 1,
		FILE_END = 2
	};

	static const DWORD INVALID_SET_FILE_POINTER = (DWORD)-1;

	struct FILETIME {
		DWORD dwLowDateTime;
		DWORD dwHighDateTime;
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
		pointer32_T<void> DebugInfo;
		LONG LockCount;
		LONG RecursionCount;
		HANDLE OwningThread;
		HANDLE LockSemaphore;
		ULONG_PTR SpinCount;
	};

	template<typename char_T>
	struct STARTUPINFOT {
		DWORD cb;
		pointer32_T<const char_T*> lpReserved;
		pointer32_T<const char_T*> lpDesktop;
		pointer32_T<const char_T*> lpTitle;
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
	using STARTUPINFOA = STARTUPINFOT<char>;
	using STARTUPINFOW = STARTUPINFOT<char16_t>;

	struct MEMORY_BASIC_INFORMATION {
		pointer32_T<void*> BaseAddress;
		pointer32_T<void*> AllocationBase;
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
		pointer32_T<void*> ExceptionAddress;
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

	struct IMAGE_EXPORT_DIRECTORY {
		DWORD Characteristics;
		DWORD TimeDateStamp;
		WORD MajorVersion;
		WORD MinorVersion;
		DWORD Name;
		DWORD Base;
		DWORD NumberOfFunctions;
		DWORD NumberOfNames;
		DWORD AddressOfFunctions;
		DWORD AddressOfNames;
		DWORD AddressOfNameOrdinals;
	};

	struct IMAGE_RESOURCE_DIRECTORY {
		DWORD Characteristics;
		DWORD TimeDateStamp;
		WORD MajorVersion;
		WORD MinorVersion;
		WORD NumberOfNamedEntries;
		WORD NumberOfIdEntries;
	};

	struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
		DWORD Name;
		DWORD OffsetToData;
	};

	struct IMAGE_RESOURCE_DATA_ENTRY {
		DWORD OffsetToData;
		DWORD Size;
		DWORD CodePage;
		DWORD Reserved;
	};

	struct SYSTEM_INFO {
		WORD wProcessorArchitecture;
		WORD wReserved;
		DWORD dwPageSize;
		pointer32_T<void*> lpMinimumApplicationAddress;
		pointer32_T<void*> lpMaximumApplicationAddress;
		DWORD_PTR dwActiveProcessorMask;
		DWORD dwNumberOfProcessors;
		DWORD dwProcessorType;
		DWORD dwAllocationGranularity;
		WORD wProcessorLevel;
		WORD wProcessorRevision;
	};

	struct MEMORYSTATUS {
		DWORD dwLength;
		DWORD dwMemoryLoad;
		SIZE_T dwTotalPhys;
		SIZE_T dwAvailPhys;
		SIZE_T dwTotalPageFile;
		SIZE_T dwAvailPageFile;
		SIZE_T dwTotalVirtual;
		SIZE_T dwAvailVirtual;
	};

	struct WIN32_FIND_DATAA {
		DWORD dwFileAttributes;
		FILETIME ftCreationTime;
		FILETIME ftLastAccessTime;
		FILETIME ftLastWriteTime;
		DWORD nFileSizeHigh;
		DWORD nFileSizeLow;
		DWORD dwReserved0;
		DWORD dwReserved1;
		char cFileName[260];
		char cAlternateFileName[14];
	};

	struct RECT {
		LONG left;
		LONG top;
		LONG right;
		LONG bottom;
	};

	struct POINT {
		LONG x;
		LONG y;
	};

	struct alignas(8) SLIST_HEADER {
		uint64_t value;
	};
	struct alignas(8) SLIST_ENTRY {
		pointer32_T<SLIST_ENTRY> next;
	};

	struct GUID {
		ULONG Data1;
		USHORT Data2;
		USHORT Data3;
		UCHAR Data4[8];
	};

};

#endif
