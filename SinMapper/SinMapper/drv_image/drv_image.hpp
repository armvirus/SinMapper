#pragma once
#include <vector>
#include <Windows.h>
#include <Winternl.h>
#include <ntstatus.h>

#include <functional>
#include <variant>
#include "../util/nt.hpp"
#include "../util/util.hpp"

namespace portable_executable
{
	struct RelocInfo
	{
		uint64_t address;
		uint16_t* item;
		uint32_t count;
	};

	struct ImportFunctionInfo
	{
		std::string name;
		uint64_t* address;
	};

	struct ImportInfo
	{
		std::string module_name;
		std::vector<ImportFunctionInfo> function_datas;
	};

	using vec_sections = std::vector<IMAGE_SECTION_HEADER>;
	using vec_relocs = std::vector<RelocInfo>;
	using vec_imports = std::vector<ImportInfo>;

	vec_imports get_imports(void* image_base);
	void relocate_image_by_delta(vec_relocs relocs, const uint64_t delta);
	bool resolve_imports(vec_imports imports);
	PIMAGE_NT_HEADERS64 get_nt_headers(void* image_base);
	vec_relocs get_relocations(void* image_base);
	vec_imports get_imports(void* image_base);
}