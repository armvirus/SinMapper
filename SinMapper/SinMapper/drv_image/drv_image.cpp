#include "../drv_image/drv_image.hpp"

namespace portable_executable
{
	void relocate_image_by_delta(vec_relocs relocs, const uint64_t delta)
	{
		for (const auto& current_reloc : relocs)
		{
			for (auto i = 0u; i < current_reloc.count; ++i)
			{
				const uint16_t type = current_reloc.item[i] >> 12;
				const uint16_t offset = current_reloc.item[i] & 0xFFF;

				if (type == IMAGE_REL_BASED_DIR64)
					*reinterpret_cast<uint64_t*>(current_reloc.address + offset) += delta;
			}
		}
	}

	bool resolve_imports(vec_imports imports)
	{
		int import_count = 0;
		for (const auto& current_import : imports)
		{
			if (!util::get_module_base(current_import.module_name.c_str()))
			{
				std::printf("imported module [%s] not found\n", current_import.module_name.c_str());
				return false;
			}

			for (auto& current_function_data : current_import.function_datas)
			{
				const uint64_t function_address = (uint64_t)util::get_kernel_export(current_import.module_name.c_str(), current_function_data.name.c_str());

				if (!function_address)
				{
					std::printf("[-] failed to resolve import [%s]\n", current_function_data.name.c_str());
					return false;
				}

				import_count++;
				*current_function_data.address = function_address;
			}
		}

		std::printf("[+] resolved [%i] imports\n", import_count);

		return true;
	}

	PIMAGE_NT_HEADERS64 get_nt_headers(void* image_base)
	{
		const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);

		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uint64_t>(image_base) + dos_header->e_lfanew);

		if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		return nt_headers;
	}

	vec_relocs get_relocations(void* image_base)
	{
		const PIMAGE_NT_HEADERS64 nt_headers = get_nt_headers(image_base);

		if (!nt_headers)
			return {};

		vec_relocs relocs;

		auto current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint64_t>(image_base) + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (current_base_relocation->VirtualAddress)
		{
			RelocInfo reloc_info;

			reloc_info.address = reinterpret_cast<uint64_t>(image_base) + current_base_relocation->VirtualAddress;
			reloc_info.item = reinterpret_cast<uint16_t*>(reinterpret_cast<uint64_t>(current_base_relocation) + sizeof(IMAGE_BASE_RELOCATION));
			reloc_info.count = (current_base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);

			relocs.push_back(reloc_info);

			current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint64_t>(current_base_relocation) + current_base_relocation->SizeOfBlock);
		}

		return relocs;
	}

	vec_imports get_imports(void* image_base)
	{
		const PIMAGE_NT_HEADERS64 nt_headers = get_nt_headers(image_base);

		if (!nt_headers)
			return {};

		vec_imports imports;

		auto current_import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<uint64_t>(image_base) + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (current_import_descriptor->FirstThunk)
		{
			ImportInfo import_info;

			import_info.module_name = std::string(reinterpret_cast<char*>(reinterpret_cast<uint64_t>(image_base) + current_import_descriptor->Name));

			auto current_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint64_t>(image_base) + current_import_descriptor->FirstThunk);
			auto current_originalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint64_t>(image_base) + current_import_descriptor->OriginalFirstThunk);

			while (current_originalFirstThunk->u1.Function)
			{
				ImportFunctionInfo import_function_data;

				auto thunk_data = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<uint64_t>(image_base) + current_originalFirstThunk->u1.AddressOfData);

				import_function_data.name = thunk_data->Name;
				import_function_data.address = &current_first_thunk->u1.Function;

				import_info.function_datas.push_back(import_function_data);

				++current_originalFirstThunk;
				++current_first_thunk;
			}

			imports.push_back(import_info);
			++current_import_descriptor;
		}

		return imports;
	}
}