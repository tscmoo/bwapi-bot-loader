
#include "modules.h"
#include "environ.h"
#include "native_api.h"
#include "wintypes.h"
using namespace wintypes;
#include "kernel32.h"

#include <string.h>
#include <mutex>
#include <list>
#include <vector>

//#include <windows.h>

namespace modules {
;


std::list<module_info> loaded_modules;
std::mutex loaded_modules_mutex;

module_info* get_module_info(const char* name) {
	log("get_module_info name %p\n", name);
	std::lock_guard<std::mutex> l(loaded_modules_mutex);
	for (auto& v : loaded_modules) {
		if (str_icase_eq(name, v.name)) return &v;
	}
	for (auto& v : loaded_modules) {
		if (str_icase_eq(name, v.name_no_ext)) return &v;
	}
	return nullptr;
}

module_info* get_module_info(void* base) {
	log("get_module_info base %p\n", base);
	std::lock_guard<std::mutex> l(loaded_modules_mutex);
	for (auto& v : loaded_modules) {
		if (v.base == base) return &v;
	}
	return nullptr;
}

std::mutex load_library_mut;
module_info* load_library(const char* path) {
	std::lock_guard<std::mutex> l(load_library_mut);
	auto* i = load(path);
	if (!i) i = load_fake_module(path);
	return i;
}

module_info* load(const char* path, bool overwrite) {

	native_api::file_io f;
	if (!f.open(path, native_api::file_access::read)) {
		log("failed to open '%s' for reading\n", path);
		return nullptr;
	}

	native_api::allocated_memory addr_handle;
	void* addr = nullptr;

	auto get = [&](void* dst, size_t size) -> bool {
		return f.read(dst, size);
	};
	auto seek = [&](size_t pos) -> bool {
		f.set_pos(pos);
		return true;
	};

	IMAGE_DOS_HEADER dos;
	if (!get(&dos, sizeof(dos))) return nullptr;
	if (!seek(dos.e_lfanew)) return nullptr;
	DWORD signature;
	if (!get(&signature, 4)) return nullptr;
	if (signature != 0x00004550) return nullptr;
	IMAGE_FILE_HEADER fh;
	if (!get(&fh, sizeof(fh))) return nullptr;

	IMAGE_OPTIONAL_HEADER oh;
	memset(&oh, 0, sizeof(oh));
	get(&oh, sizeof(oh));

	size_t spos = dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + fh.SizeOfOptionalHeader;

	std::vector<IMAGE_SECTION_HEADER> sh;
	sh.resize(fh.NumberOfSections);

	if (!seek(spos)) return nullptr;
	if (!get(&sh[0], sizeof(IMAGE_SECTION_HEADER)*fh.NumberOfSections)) return nullptr;

	size_t image_size = sh[fh.NumberOfSections - 1].VirtualAddress + sh[fh.NumberOfSections - 1].Misc.VirtualSize;

	auto IMAGE_FILE_RELOCS_STRIPPED = 1;

	if (fh.Characteristics&IMAGE_FILE_RELOCS_STRIPPED) {
		if (!overwrite) {
			if (!addr) log("failed to allocate memory at the required address %08X\n", oh.ImageBase);
		} else {
			addr = (void*)oh.ImageBase;
			if (!native_api::set_memory_access(addr, image_size, native_api::memory_access::read_write_execute)) {
				log("failed to set memory access protection\n");
			}
		}
	} else {
		addr_handle.allocate(image_size, native_api::memory_access::read_write_execute);
		addr = addr_handle.ptr;
	}
	if (!addr) return nullptr;

	memset(addr, 0, image_size);

	if (!seek(0)) return nullptr;
	if (!get(addr, oh.SectionAlignment)) return nullptr;

	for (size_t i = 0; i < fh.NumberOfSections; i++) {
		if (sh[i].SizeOfRawData) {
			if (!seek(sh[i].PointerToRawData)) return nullptr;
			if (!get((char*)addr + sh[i].VirtualAddress, sh[i].SizeOfRawData)) return nullptr;
		}
	}

	auto IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;

	// relocations
	uint8_t* relocs = (uint8_t*)addr + oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	size_t pos = 0;
	while (pos < oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		IMAGE_BASE_RELOCATION* r = (IMAGE_BASE_RELOCATION*)(relocs + pos);
		pos += r->SizeOfBlock;
		WORD*w = (WORD*)(r + 1);
		while ((uint8_t*)w < relocs + pos) {
			auto IMAGE_REL_BASED_HIGHLOW = 3;
			if (*w >> 12 == IMAGE_REL_BASED_HIGHLOW) {
				DWORD*target = (DWORD*)((uint8_t*)addr + r->VirtualAddress + (*w & 0xfff));
				*target -= oh.ImageBase - (DWORD)addr;
			}
			++w;
		}
	}

	module_info* r;

	{
		std::lock_guard<std::mutex> l(loaded_modules_mutex);

		loaded_modules.emplace_back();
		r = &loaded_modules.back();

		r->name = path;
		r->name_no_ext = path;
		size_t dot_pos = r->name_no_ext.rfind('.');
		if (dot_pos != std::string::npos) r->name_no_ext.resize(dot_pos);
		r->lcase_name_no_ext = r->name_no_ext;
		for (char& c : r->lcase_name_no_ext) {
			if (c >= 'A' && c <= 'Z') c |= 0x20;
		}
		r->base = addr;
		r->entry = 0;

		kernel32::add_virtual_region(addr, image_size, PAGE_EXECUTE_READWRITE);

		if (loaded_modules.size() == 1) kernel32::set_main_module(r);

		log("module '%s' loaded at %p\n", r->name, r->base);
	}

	auto IMAGE_DIRECTORY_ENTRY_IMPORT = 1;

	// imports
	pos = 0;
	while (pos < oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		IMAGE_IMPORT_DESCRIPTOR* import = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)addr + oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + pos);
		if (import->FirstThunk == 0) break;
		std::string libname = (const char*)addr + import->Name;

		module_info* mi = load_library(libname.c_str());

		const char* dot = nullptr;
		for (char& c : libname) {
			if (c >= 'A' && c <= 'Z') c |= 0x20;
			if (c == '.') dot = &c;
		}
		if (dot) libname.resize(dot - libname.data());

		DWORD*dw = (DWORD*)((uint8_t*)addr + import->OriginalFirstThunk);
		for (int i = 0; *dw; i++) {
			std::string funcname;
			if (*dw & 0x80000000) funcname = format("ordinal %d", *dw & 0xffff);
			else {
				funcname = (const char*)addr + *dw + 2;
			}
			void* proc;
			std::string fullname = format("%s:%s", libname, funcname);
			proc = get_implemented_function(fullname);
			if (!proc) proc = get_unimplemented_stub(fullname);
			*((void**)((uint8_t*)addr + import->FirstThunk) + i) = proc;
			++dw;
		}
		pos += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	if (addr_handle) addr_handle.detach();

	if (oh.AddressOfEntryPoint) {
		r->entry = (uint8_t*)addr + oh.AddressOfEntryPoint;
	}

	return r;
}

module_info* load_fake_module(const char* name) {
	loaded_modules.emplace_back();
	auto* r = &loaded_modules.back();

	native_api::allocated_memory addr_handle;
	addr_handle.allocate(0x1000, native_api::memory_access::none);
	if (!addr_handle) fatal_error("failed to allocate memory for fake module");

	r->name = name;
	r->name_no_ext = name;
	size_t dot_pos = r->name_no_ext.rfind('.');
	if (dot_pos != std::string::npos) r->name_no_ext.resize(dot_pos);
	r->lcase_name_no_ext = r->name_no_ext;
	for (char& c : r->lcase_name_no_ext) {
		if (c >= 'A' && c <= 'Z') c |= 0x20;
	}
	r->base = addr_handle.detach();
	r->entry = 0;

	kernel32::add_virtual_region(r->base, 0x1000, PAGE_NOACCESS);

	log("loaded fake module '%s' at %p\n", name, r->base);

	return r;
}

}
