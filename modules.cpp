
#include "modules.h"
#include "environment.h"
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
	std::lock_guard<std::mutex> l(loaded_modules_mutex);
	for (auto& v : loaded_modules) {
		if (v.base == base) return &v;
	}
	return nullptr;
}

struct virtual_memory_handle {
	void* ptr = nullptr;
	~virtual_memory_handle() {
		if (ptr) kernel32::virtual_deallocate(ptr);
	}
};

void* const modules_start_addr = (void*)((uintptr_t)16 * 1024 * 1024);

module_info* load_module(const char* path, bool overwrite) {

	auto native_path = get_native_path(path);

	native_api::file_io f;
	if (!f.open(native_path.c_str(), native_api::file_access::read, native_api::file_open_mode::open_existing)) {
		log("failed to open '%s' (%s) for reading\n", path, native_path);
		return nullptr;
	}

	virtual_memory_handle addr_handle;
	void* addr = nullptr;

	auto get = [&](void* dst, size_t size) -> bool {
		size_t read = 0;
		return f.read(dst, size, &read) && read == size;
	};
	auto seek = [&](size_t pos) -> bool {
		f.set_pos(pos, native_api::file_set_pos_origin::begin);
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
		addr_handle.ptr = kernel32::virtual_allocate(nullptr, image_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE, modules_start_addr);
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

		r->full_path = get_full_path(path);
		r->name = get_filename(r->full_path);
		r->name_no_ext = r->name;
		size_t dot_pos = r->name_no_ext.rfind('.');
		if (dot_pos != std::string::npos) r->name_no_ext.resize(dot_pos);
		r->lcase_name_no_ext = r->name_no_ext;
		for (char& c : r->lcase_name_no_ext) {
			if (c >= 'A' && c <= 'Z') c |= 0x20;
		}
		r->base = addr;
		r->entry = 0;

		if (!addr_handle.ptr) kernel32::add_virtual_region(addr, image_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		else addr_handle.ptr = nullptr;

		if (loaded_modules.size() == 1) kernel32::set_main_module(r);

		log("module '%s' loaded at %p\n", r->name, r->base);
	}

	auto IMAGE_DIRECTORY_ENTRY_EXPORT = 0;

	auto& exp_entry = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (exp_entry.VirtualAddress) {
		IMAGE_EXPORT_DIRECTORY* exportd = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)addr + exp_entry.VirtualAddress);

		r->ordinal_base = exportd->Base;

		DWORD* funcs = (DWORD*)((uint8_t*)addr + exportd->AddressOfFunctions);
		DWORD* names = (DWORD*)((uint8_t*)addr + exportd->AddressOfNames);
		WORD* name_ordinals = (WORD*)((uint8_t*)addr + exportd->AddressOfNameOrdinals);

		for (size_t i = 0; i < exportd->NumberOfFunctions; ++i) {
			if (funcs[i]) r->exports.push_back((uint8_t*)addr + funcs[i]);
			else r->exports.push_back(nullptr);
		}
		for (size_t i = 0; i < exportd->NumberOfNames; ++i) {
			log("export name '%s'\n", (char*)(uint8_t*)addr + names[i]);
			r->export_names[(char*)(uint8_t*)addr + names[i]] = name_ordinals[i];
		}
	}

	auto IMAGE_DIRECTORY_ENTRY_IMPORT = 1;

	// imports
	pos = 0;
	while (pos < oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		IMAGE_IMPORT_DESCRIPTOR* import = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)addr + oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + pos);
		if (import->FirstThunk == 0) break;
		std::string libname = (const char*)addr + import->Name;

		module_info* mi = load_library(libname.c_str(), true);

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
			if (!proc) {
				if (*dw & 0x80000000) {
					size_t ordinal = (*dw & 0xffff) - mi->ordinal_base;
					if (ordinal < mi->exports.size()) {
						//log("imported ordinal %d from %s\n", ordinal + mi->ordinal_base, mi->name);
						proc = mi->exports[ordinal];
					}
				} else {
					const char* name = (const char*)addr + *dw + 2;
					log("import '%s'?\n", name);
				}
			}
			if (!proc) proc = get_unimplemented_stub(fullname);
			*((void**)((uint8_t*)addr + import->FirstThunk) + i) = proc;
			++dw;
		}
		pos += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	auto IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
	// resources
	uint8_t* res_start = (uint8_t*)addr + oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	std::function<resource_directory*(IMAGE_RESOURCE_DIRECTORY*)> resdir = [&](IMAGE_RESOURCE_DIRECTORY* dir) {
		r->all_resource_directories.emplace_back();
		resource_directory* d = &r->all_resource_directories.back();
		IMAGE_RESOURCE_DIRECTORY_ENTRY* e = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(dir + 1);
		for (size_t i = 0; i < dir->NumberOfNamedEntries; ++i, ++e) {
			if (e->Name & 0x80000000) {
				size_t offset = e->Name & 0x7fffffff;
				uint8_t* p = res_start + offset;
				WORD len = *(WORD*)p;
				std::u16string name((char16_t*)(p + 2), len);
				if (e->OffsetToData & 0x80000000) {
					d->named[std::move(name)].dir = resdir((IMAGE_RESOURCE_DIRECTORY*)(res_start + (e->OffsetToData & 0x7fffffff)));
				} else {
					IMAGE_RESOURCE_DATA_ENTRY* de = (IMAGE_RESOURCE_DATA_ENTRY*)(res_start + e->OffsetToData);
					auto& v = d->named[std::move(name)];
					v.data = res_start + de->OffsetToData;
					v.size = de->Size;
				}
			}
		}
		for (size_t i = 0; i < dir->NumberOfIdEntries; ++i, ++e) {
			if (~e->Name & 0x80000000) {
				size_t id = e->Name & 0xffff;
				if (e->OffsetToData & 0x80000000) {
					d->id[id].dir = resdir((IMAGE_RESOURCE_DIRECTORY*)(res_start + (e->OffsetToData & 0x7fffffff)));
				} else {
					IMAGE_RESOURCE_DATA_ENTRY* de = (IMAGE_RESOURCE_DATA_ENTRY*)(res_start + e->OffsetToData);
					auto& v = d->id[id];
					v.data = res_start + de->OffsetToData;
					v.size = de->Size;
				}
			}
		}
		return d;
	};
	if (oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) {
		r->root_resource_directory = resdir((IMAGE_RESOURCE_DIRECTORY*)res_start);
	}

	if (oh.AddressOfEntryPoint) {
		r->entry = (uint8_t*)addr + oh.AddressOfEntryPoint;
	}
	return r;
}

std::recursive_mutex load_mut;
std::list<std::pair<module_info*, bool>> dll_entries_to_call;
bool is_loading = false;
module_info* load_library(const char* path, bool is_load_time) {
	std::lock_guard<std::recursive_mutex> l(load_mut);
	auto filename = get_filename(path);
	auto* i = get_module_info(filename.c_str());
	if (i) return i;
	bool was_loading = is_loading;
	if (!was_loading) is_loading = true;
	i = load_module(path, false);
	if (!i) i = load_fake_module(path);
	if (i->entry) {
		if (!is_load_time) {
			log("calling entry point for %p\n", i->base);
			void* entry = i->entry;
			void* base = i->base;
			int load_time = is_load_time ? 1 : 0;
			BOOL r = ((BOOL(WINAPI*)(void*, DWORD, int))entry)(base, 1, load_time);
			log("entry point for %p returned\n", i->base);
			if (!r) fatal_error("DllEntryPoint for '%s' failed", i->full_path);
		} else {
			dll_entries_to_call.emplace_back(i, is_load_time);
		}
	}
	if (!was_loading) {
		for (auto& v : dll_entries_to_call) {
			log("calling entry point for %p\n", v.first->base);
			void* entry = v.first->entry;
			void* base = v.first->base;
			int load_time = v.second ? 1 : 0;
			BOOL r = ((BOOL(WINAPI*)(void*, DWORD, int))entry)(base, 1, load_time);
			log("entry point for %p returned\n", v.first->base);
			if (!r) fatal_error("DllEntryPoint for '%s' failed", v.first->full_path);
		}
		is_loading = false;
	}
	return i;
}

std::function<void()> pre_entry_callback;

module_info* load_main(const char* path, bool overwrite) {
	module_info* i = nullptr;
	std::list<std::pair<module_info*, bool>> dll_entries;
	{
		std::lock_guard<std::recursive_mutex> l(load_mut);
		if (is_loading) fatal_error("load_main: is_loading is set");
		if (!loaded_modules.empty()) fatal_error("load_main: loaded modules is not empty");
		is_loading = true;
		i = load_module(path, overwrite);
		dll_entries = std::move(dll_entries_to_call);
		dll_entries_to_call.clear();
		is_loading = false;
	}
	if (i) {
		environment::enter_thread([&]() {
			kernel32::enter_main_thread([&]() {
				for (auto& v : dll_entries) {
					log("calling entry point for %p\n", v.first->base);
					void* entry = v.first->entry;
					void* base = v.first->base;
					int load_time = v.second ? 1 : 0;
					BOOL r = ((BOOL(WINAPI*)(void*, DWORD, int))entry)(base, 1, load_time);
					log("entry point for %p returned\n", v.first->base);
					if (!r) fatal_error("DllEntryPoint for '%s' failed", v.first->full_path);
				}
				if (pre_entry_callback) pre_entry_callback();
				((void(*)())i->entry)();
			});
		});
	}
	return i;
}

module_info* load_fake_module(const char* name) {
	loaded_modules.emplace_back();
	auto* r = &loaded_modules.back();

	virtual_memory_handle addr_handle;
	addr_handle.ptr = kernel32::virtual_allocate(nullptr, 0x10000, MEM_RESERVE, PAGE_NOACCESS, modules_start_addr);
	if (!addr_handle.ptr) fatal_error("failed to allocate memory for fake module");

	r->name = name;
	r->name_no_ext = name;
	size_t dot_pos = r->name_no_ext.rfind('.');
	if (dot_pos != std::string::npos) r->name_no_ext.resize(dot_pos);
	r->lcase_name_no_ext = r->name_no_ext;
	for (char& c : r->lcase_name_no_ext) {
		if (c >= 'A' && c <= 'Z') c |= 0x20;
	}
	r->base = addr_handle.ptr;
	r->entry = 0;

	addr_handle.ptr = nullptr;

	log("loaded fake module '%s' at %p\n", name, r->base);

	return r;
}

void call_thread_attach() {
	std::vector<module_info*> dlls;
	{
		std::lock_guard<std::mutex> l(loaded_modules_mutex);
		for (auto& v : loaded_modules) {
			if (&v == &loaded_modules.front()) continue;
			dlls.push_back(&v);
		}
	}
	for (auto& v : dlls) {
		if (v->entry) {
			log("calling DLL_THREAD_ATTACH for %p\n", v->base);
			((BOOL(WINAPI*)(void*, DWORD, int))v->entry)(v->base, 2, 0);
		}
	}
}
void call_thread_detach() {
	std::vector<module_info*> dlls;
	{
		std::lock_guard<std::mutex> l(loaded_modules_mutex);
		for (auto& v : loaded_modules) {
			if (&v == &loaded_modules.front()) continue;
			dlls.push_back(&v);
		}
	}
	for (auto& v : dlls) {
		if (v->entry) {
			log("calling DLL_THREAD_DETACH for %p\n", v->base);
			((BOOL(WINAPI*)(void*, DWORD, int))v->entry)(v->base, 3, 0);
		}
	}
}

}
