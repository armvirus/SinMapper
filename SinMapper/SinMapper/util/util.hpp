#pragma once
#include <Windows.h>
#include <cstdint>
#include <string_view>
#include <iterator>
#include <map>
#include <fstream>
#include <string>
#include <vector>
#include <tlhelp32.h>
#include <array>
#include <algorithm>
#include <atomic>
#include <filesystem>

#include "nt.hpp"

typedef struct PiDDBCacheEntry
{
	LIST_ENTRY		list;
	UNICODE_STRING	driver_name;
	ULONG			time_stamp;
	NTSTATUS		load_status;
	char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
}PIDCacheobj;


namespace util
{
	inline std::string get_service_path(SC_HANDLE sc_handle, const std::string& service_name)
	{
		SC_HANDLE hService(OpenServiceA(sc_handle, service_name.c_str(), SERVICE_QUERY_CONFIG));
		if (!hService)
			return "";

		std::vector<BYTE> buffer;
		DWORD dwBytesNeeded = sizeof(QUERY_SERVICE_CONFIGA);
		LPQUERY_SERVICE_CONFIGA pConfig;

		do
		{
			buffer.resize(dwBytesNeeded);
			pConfig = (LPQUERY_SERVICE_CONFIGA)&buffer[0];

			if (QueryServiceConfigA(hService, pConfig, buffer.size(), &dwBytesNeeded))
				return pConfig->lpBinaryPathName;
		} while (GetLastError() == ERROR_INSUFFICIENT_BUFFER);

		return "";
	}

	inline std::string get_driver_name(std::string const& path)
	{
		return path.substr(path.find_last_of("/\\") + 1);
	}

	inline int random_number_gen(int min, int max) //range : [min, max]
	{
		srand(time(NULL));
		return min + rand() % (max - min);
	}

	// taken from: https://github.com/z175/kdmapper/blob/master/kdmapper/utils.cpp#L30
	static void* get_kernel_export(const char* module_name, const char* export_name, bool rva = false)
	{
		void* buffer = nullptr;
		DWORD buffer_size = NULL;

		NTSTATUS status = NtQuerySystemInformation(
			static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation),
			buffer,
			buffer_size,
			&buffer_size
		);

		while (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			VirtualFree(buffer, 0, MEM_RELEASE);
			buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			status = NtQuerySystemInformation(
				static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation),
				buffer,
				buffer_size,
				&buffer_size
			);
		}

		if (!NT_SUCCESS(status))
		{
			VirtualFree(buffer, 0, MEM_RELEASE);
			return 0;
		}

		const auto modules = static_cast<PRTL_PROCESS_MODULES>(buffer);
		for (auto idx = 0u; idx < modules->NumberOfModules; ++idx)
		{
			// find module and then load library it
			const std::string current_module_name =
				std::string(reinterpret_cast<char*>(
					modules->Modules[idx].FullPathName) +
					modules->Modules[idx].OffsetToFileName
				);

			if (!_stricmp(current_module_name.c_str(), module_name))
			{
				// had to shoot the tires off of "\\SystemRoot\\"
				std::string full_path = reinterpret_cast<char*>(modules->Modules[idx].FullPathName);
				full_path.replace(
					full_path.find("\\SystemRoot\\"),
					sizeof("\\SystemRoot\\") - 1,
					std::string(getenv("SYSTEMROOT")).append("\\")
				);

				const auto module_base =
					LoadLibraryEx(
						full_path.c_str(),
						NULL,
						DONT_RESOLVE_DLL_REFERENCES
					);

				PIMAGE_DOS_HEADER p_idh;
				PIMAGE_NT_HEADERS p_inh;
				PIMAGE_EXPORT_DIRECTORY p_ied;

				PDWORD addr, name;
				PWORD ordinal;

				p_idh = (PIMAGE_DOS_HEADER)module_base;
				if (p_idh->e_magic != IMAGE_DOS_SIGNATURE)
					return NULL;

				p_inh = (PIMAGE_NT_HEADERS)((LPBYTE)module_base + p_idh->e_lfanew);
				if (p_inh->Signature != IMAGE_NT_SIGNATURE)
					return NULL;

				if (p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
					return NULL;

				p_ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module_base +
					p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

				addr = (PDWORD)((LPBYTE)module_base + p_ied->AddressOfFunctions);
				name = (PDWORD)((LPBYTE)module_base + p_ied->AddressOfNames);
				ordinal = (PWORD)((LPBYTE)module_base + p_ied->AddressOfNameOrdinals);

				// find exported function
				for (auto i = 0; i < p_ied->AddressOfFunctions; i++)
					if (!strcmp(export_name, (char*)module_base + name[i]))
					{
						if (!rva)
						{
							auto result = (void*)((std::uintptr_t)modules->Modules[idx].ImageBase + addr[ordinal[i]]);
							VirtualFree(buffer, NULL, MEM_RELEASE);
							return result;
						}
						else
						{
							auto result = (void*)addr[ordinal[i]];
							VirtualFree(buffer, NULL, MEM_RELEASE);
							return result;
						}
					}
			}
		}
		VirtualFree(buffer, NULL, MEM_RELEASE);
		return NULL;
	}

	inline std::vector<std::string>get_active_drivers_array()
	{
		SC_HANDLE manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

		if (manager == INVALID_HANDLE_VALUE)
		{
			return {};
		}

		DWORD bytes_needed;
		DWORD service_count;

		BOOL status = EnumServicesStatusExA(
			manager,
			SC_ENUM_PROCESS_INFO,
			SERVICE_DRIVER,
			SERVICE_ACTIVE,
			0,
			0,
			&bytes_needed,
			&service_count,
			0,
			0
		);

		PBYTE bytes_array = (PBYTE)malloc(bytes_needed);

		status = EnumServicesStatusExA(
			manager,
			SC_ENUM_PROCESS_INFO,
			SERVICE_DRIVER,
			SERVICE_ACTIVE,
			bytes_array,
			bytes_needed,
			&bytes_needed,
			&service_count,
			0,
			0
		);

		ENUM_SERVICE_STATUS_PROCESSA* service_array = (ENUM_SERVICE_STATUS_PROCESSA*)bytes_array;

		std::vector<std::string>return_array{};

		for (int i = 0; i < service_count; i++)
		{
			std::string driver_path = get_service_path(manager, service_array[i].lpServiceName);
			std::string driver_name = get_driver_name(driver_path);

			if (!driver_path.empty() && !driver_name.empty())
			{
				return_array.push_back(driver_name);
			}
		}

		free(bytes_array);

		return return_array;
	}

	//--- ranges of physical memory
	inline std::map<std::uintptr_t, std::size_t> pmem_ranges;

	//--- validates the address
	__forceinline auto is_valid(std::uintptr_t addr) -> bool
	{
		for (auto range : pmem_ranges)
			if (addr >= range.first && addr <= range.first + range.second)
				return true;
		return false;
	}

	inline const auto init_ranges = ([&]() -> bool
	{
			HKEY h_key;
			DWORD type, size;
			LPBYTE data;
			RegOpenKeyEx(HKEY_LOCAL_MACHINE, "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory", 0, KEY_READ, &h_key);
			RegQueryValueEx(h_key, ".Translated", NULL, &type, NULL, &size); //get size
			data = new BYTE[size];
			RegQueryValueEx(h_key, ".Translated", NULL, &type, data, &size);
			DWORD count = *(DWORD*)(data + 16);
			auto pmi = data + 24;
			for (int dwIndex = 0; dwIndex < count; dwIndex++)
			{
				pmem_ranges.emplace(*(uint64_t*)(pmi + 0), *(uint64_t*)(pmi + 8));
				pmi += 20;
			}
			delete[] data;
			RegCloseKey(h_key);
			return true;
	})();

	__forceinline auto get_module_base(const char* module_name) -> std::uintptr_t
	{
		void* buffer = nullptr;
		DWORD buffer_size = NULL;

		NTSTATUS status = NtQuerySystemInformation(
			static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation),
			buffer,
			buffer_size, 
			&buffer_size
		);

		while (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			VirtualFree(buffer, NULL, MEM_RELEASE);
			buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), buffer, buffer_size, &buffer_size);
		}

		if (!NT_SUCCESS(status))
		{
			VirtualFree(buffer, NULL, MEM_RELEASE);
			return NULL;
		}

		const auto modules = static_cast<PRTL_PROCESS_MODULES>(buffer);
		for (auto idx = 0u; idx < modules->NumberOfModules; ++idx)
		{
			const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[idx].FullPathName) + modules->Modules[idx].OffsetToFileName);
			if (!_stricmp(current_module_name.c_str(), module_name))
			{
				const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[idx].ImageBase);
				VirtualFree(buffer, NULL, MEM_RELEASE);
				return result;
			}
		}

		VirtualFree(buffer, NULL, MEM_RELEASE);
		return {};
	}

	__forceinline auto get_file_header(void* base_addr) -> PIMAGE_FILE_HEADER
	{
		if (!base_addr || *(short*)base_addr != IMAGE_DOS_SIGNATURE)
			return {};

		PIMAGE_DOS_HEADER dos_headers =
			reinterpret_cast<PIMAGE_DOS_HEADER>(base_addr);

		PIMAGE_NT_HEADERS nt_headers =
			reinterpret_cast<PIMAGE_NT_HEADERS>(
				reinterpret_cast<DWORD_PTR>(base_addr) + dos_headers->e_lfanew);

		return &nt_headers->FileHeader;
	}

	__forceinline auto get_pid(const char* proc_name) -> std::uint32_t
	{
		PROCESSENTRY32 proc_info;
		proc_info.dwSize = sizeof(proc_info);

		HANDLE proc_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (proc_snapshot == INVALID_HANDLE_VALUE)
			return NULL;

		Process32First(proc_snapshot, &proc_info);
		if (!strcmp(proc_info.szExeFile, proc_name))
		{
			CloseHandle(proc_snapshot);
			return proc_info.th32ProcessID;
		}

		while (Process32Next(proc_snapshot, &proc_info))
		{
			if (!strcmp(proc_info.szExeFile, proc_name))
			{
				CloseHandle(proc_snapshot);
				return proc_info.th32ProcessID;
			}
		}

		CloseHandle(proc_snapshot);
		return NULL;
	}

	__forceinline auto get_kmodule_base(const char* module_name) -> std::uintptr_t
	{
		void* buffer = nullptr;
		DWORD buffer_size = NULL;

		NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), buffer, buffer_size, &buffer_size);

		while (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			VirtualFree(buffer, NULL, MEM_RELEASE);
			buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), buffer, buffer_size, &buffer_size);
		}

		if (!NT_SUCCESS(status))
		{
			VirtualFree(buffer, NULL, MEM_RELEASE);
			return NULL;
		}

		const auto modules = static_cast<PRTL_PROCESS_MODULES>(buffer);
		for (auto idx = 0u; idx < modules->NumberOfModules; ++idx)
		{
			const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[idx].FullPathName) + modules->Modules[idx].OffsetToFileName);
			if (!_stricmp(current_module_name.c_str(), module_name))
			{
				const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[idx].ImageBase);
				VirtualFree(buffer, NULL, MEM_RELEASE);
				return result;
			}
		}

		VirtualFree(buffer, NULL, MEM_RELEASE);
		return NULL;
	}

	__forceinline auto get_kmodule_export(const char* module_name, const char* export_name, bool rva = false) -> void*
	{
		void* buffer = nullptr;
		DWORD buffer_size = 0;

		NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), buffer, buffer_size, &buffer_size);

		while (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			VirtualFree(buffer, 0, MEM_RELEASE);
			buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), buffer, buffer_size, &buffer_size);
		}

		if (!NT_SUCCESS(status))
		{
			VirtualFree(buffer, 0, MEM_RELEASE);
			return 0;
		}

		const auto modules = static_cast<PRTL_PROCESS_MODULES>(buffer);
		for (auto idx = 0u; idx < modules->NumberOfModules; ++idx)
		{
			// find module and then load library it
			const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[idx].FullPathName) + modules->Modules[idx].OffsetToFileName);
			if (!_stricmp(current_module_name.c_str(), module_name))
			{
				// had to shoot the tires off of "\\SystemRoot\\"
				std::string full_path = reinterpret_cast<char*>(modules->Modules[idx].FullPathName);
				full_path.replace(
					full_path.find("\\SystemRoot\\"),
					sizeof("\\SystemRoot\\") - 1,
					std::string(getenv("SYSTEMROOT")).append("\\")
				);

				auto module_base = LoadLibraryExA(full_path.c_str(), 
					NULL, DONT_RESOLVE_DLL_REFERENCES);
				PIMAGE_DOS_HEADER p_idh;
				PIMAGE_NT_HEADERS p_inh;
				PIMAGE_EXPORT_DIRECTORY p_ied;

				PDWORD addr, name;
				PWORD ordinal;

				p_idh = (PIMAGE_DOS_HEADER)module_base;
				if (p_idh->e_magic != IMAGE_DOS_SIGNATURE)
					return NULL;

				p_inh = (PIMAGE_NT_HEADERS)((LPBYTE)module_base + p_idh->e_lfanew);
				if (p_inh->Signature != IMAGE_NT_SIGNATURE)
					return NULL;

				if (p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
					return NULL;

				p_ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module_base +
					p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

				addr = (PDWORD)((LPBYTE)module_base + p_ied->AddressOfFunctions);
				name = (PDWORD)((LPBYTE)module_base + p_ied->AddressOfNames);
				ordinal = (PWORD)((LPBYTE)module_base + p_ied->AddressOfNameOrdinals);

				for (auto i = 0; i < p_ied->AddressOfFunctions; i++)
				{
					if (!strcmp(export_name, (char*)module_base + name[i]))
					{
						if (!rva)
						{
							auto result = (void*)((std::uintptr_t)modules->Modules[idx].ImageBase + addr[ordinal[i]]);
							VirtualFree(buffer, NULL, MEM_RELEASE);
							return result;
						}
						else
						{
							auto result = (void*)addr[ordinal[i]];
							VirtualFree(buffer, NULL, MEM_RELEASE);
							return result;
						}
					}
				}
			}
		}
		VirtualFree(buffer, NULL, MEM_RELEASE);
		return NULL;
	}

	__forceinline auto get_kmodule_export(void* module_base, const char* export_name) -> void*
	{
		PIMAGE_DOS_HEADER p_idh;
		PIMAGE_NT_HEADERS p_inh;
		PIMAGE_EXPORT_DIRECTORY p_ied;

		PDWORD addr, name;
		PWORD ordinal;

		p_idh = (PIMAGE_DOS_HEADER)module_base;
		if (p_idh->e_magic != IMAGE_DOS_SIGNATURE)
			return NULL;

		p_inh = (PIMAGE_NT_HEADERS)((LPBYTE)module_base + p_idh->e_lfanew);
		if (p_inh->Signature != IMAGE_NT_SIGNATURE)
			return NULL;

		if (p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
			return NULL;

		p_ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module_base +
			p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		addr = (PDWORD)((LPBYTE)module_base + p_ied->AddressOfFunctions);
		name = (PDWORD)((LPBYTE)module_base + p_ied->AddressOfNames);
		ordinal = (PWORD)((LPBYTE)module_base + p_ied->AddressOfNameOrdinals);

		for (auto i = 0; i < p_ied->AddressOfFunctions; i++)
		{
			if (!strcmp(export_name, (char*)module_base + name[i]))
			{
				auto result = (void*)((std::uintptr_t)module_base + addr[ordinal[i]]);
				return result;
			}
		}
		return NULL;
	}

	namespace memory
	{
		template<std::size_t pattern_length>
		__forceinline auto sig_scan(const char(&signature)[pattern_length], const char(&mask)[pattern_length]) -> std::pair<std::uintptr_t, std::uint32_t>
		{
			static const auto ntoskrnl_module =
				LoadLibraryEx(
					"ntoskrnl.exe",
					NULL,
					DONT_RESOLVE_DLL_REFERENCES
				);

			static const auto p_idh = reinterpret_cast<PIMAGE_DOS_HEADER>(ntoskrnl_module);
			if (p_idh->e_magic != IMAGE_DOS_SIGNATURE)
				return { {}, {} };

			static const auto p_inh = reinterpret_cast<PIMAGE_NT_HEADERS>((LPBYTE)ntoskrnl_module + p_idh->e_lfanew);
			if (p_inh->Signature != IMAGE_NT_SIGNATURE)
				return { {}, {} };

			const auto pattern_view =
				std::string_view
			{
				reinterpret_cast<char*>(ntoskrnl_module),
				p_inh->OptionalHeader.SizeOfImage
			};

			std::array<std::pair<char, char>, pattern_length - 1> pattern{};
			for (std::size_t index = 0; index < pattern_length - 1; index++)
				pattern[index] = { signature[index], mask[index] };

			auto resultant_address = std::search
			(
				pattern_view.cbegin(),
				pattern_view.cend(),
				pattern.cbegin(),
				pattern.cend(),
				[](char left, std::pair<char, char> right) -> bool {
					return (right.second == '?' || left == right.first);
				});

			const auto found_address =
				resultant_address == pattern_view.cend() ? 0 :
				reinterpret_cast<std::uintptr_t>(resultant_address.operator->());

			const auto rva = found_address - reinterpret_cast<std::uintptr_t>(ntoskrnl_module);
			return { found_address, rva };
		}

		inline void* get_piddb_lock()
		{
			const char piddb_lock_sig[] = "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C\x24";
			const char piddb_lock_mask[] = "xxx????x????xxxx";

			static const auto absolute_addr_instruction =
				util::memory::sig_scan(
					piddb_lock_sig,
					piddb_lock_mask
				);

			static const auto ntoskrnl_in_my_process =
				reinterpret_cast<std::uintptr_t>(GetModuleHandle("ntoskrnl.exe"));

			if (!absolute_addr_instruction.first || !ntoskrnl_in_my_process)
				return {};

			const auto lea_rip_rva = *(PLONG)(absolute_addr_instruction.first + 3);
			const auto real_rva = (absolute_addr_instruction.first + 7 + lea_rip_rva) - ntoskrnl_in_my_process;
			static const auto kernel_base = util::get_module_base("ntoskrnl.exe");

			if (!kernel_base)
				return {};

			return reinterpret_cast<void*>(kernel_base + real_rva);
		}

		inline void* get_mi_pte_address_fn()
		{
			static const auto kernel_base = util::get_module_base("ntoskrnl.exe");

			const char mm_pte_sig[] = "\x48\xC1\xE9\x09\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x23\xC8\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x03\xC1\xC3";
			const char mm_pte_mask[] = "xxxxxx????????xxxxx????????xxxx";

			auto sig_scan = util::memory::sig_scan(
				mm_pte_sig,
				mm_pte_mask
			);

			if (!sig_scan.first)
				return 0;

			return reinterpret_cast<void*>(kernel_base +
				sig_scan.second);
		}

		inline void* get_mi_pde_address_fn()
		{
			static const auto kernel_base = util::get_module_base("ntoskrnl.exe");

			const char mm_pde_sig[] = "\x48\xC1\xE9\x12\x81\xE1\x00\x00\x00\x00\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x03\xC1\xC3";
			const char mm_pde_mask[] = "xxxxxx????xx????????xxxx";

			auto sig_scan = util::memory::sig_scan(
				mm_pde_sig,
				mm_pde_mask
			);

			if (!sig_scan.first)
				return 0;

			return reinterpret_cast<void*>(kernel_base +
				sig_scan.second);
		}

		inline void* get_piddb_table()
		{
			const char piddb_table_sig[] = "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8D\x1D\x00\x00\x00\x00\x48\x85\xC0\x0F";
			const char piddb_table_mask[] = "xxx????x????xxx????xxxx";


			static const auto absolute_addr_instruction =
				util::memory::sig_scan(
					piddb_table_sig,
					piddb_table_mask
				);

			static const auto ntoskrnl_in_my_process =
				reinterpret_cast<std::uintptr_t>(GetModuleHandle("ntoskrnl.exe"));

			if (!absolute_addr_instruction.first || !ntoskrnl_in_my_process)
				return {};

			const auto lea_rip_rva = *(PLONG)(absolute_addr_instruction.first + 3);
			const auto real_rva = (absolute_addr_instruction.first + 7 + lea_rip_rva) - ntoskrnl_in_my_process;
			static const auto kernel_base = util::get_module_base("ntoskrnl.exe");

			if (!kernel_base)
				return {};

			return reinterpret_cast<void*>(kernel_base + real_rva);
		}
	}

	inline std::tuple<std::uintptr_t, std::size_t> get_section(std::uintptr_t local_module_base, std::string section_name)
	{
		const auto module_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(local_module_base);

		if (module_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return{};
		}

		const auto module_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(local_module_base + module_dos_header->e_lfanew);

		if (module_nt_headers->Signature != IMAGE_NT_SIGNATURE)
		{
			return{};
		}

		const auto section_count = module_nt_headers->FileHeader.NumberOfSections;
		const auto section_headers = IMAGE_FIRST_SECTION(module_nt_headers);

		for (WORD i = 0; i < section_count; ++i)
		{
			if (strcmp(reinterpret_cast<char*>(section_headers[i].Name), section_name.c_str()) == 0)
			{
				return { section_headers[i].VirtualAddress, section_headers[i].Misc.VirtualSize };
			}
		}

		return {};
	}

	inline potential_drivers get_driver_info(std::string driver_name, char* section_name, std::uint32_t driver_size)
	{
		LoadLibraryA("user32.dll");
		LoadLibraryA("win32u.dll");

		std::string driver_path = "C:\\Windows\\System32\\drivers\\" + driver_name;

		if (std::filesystem::exists(driver_path) == false)
		{
			return {};
		}

		std::ifstream input(driver_path, std::ios::binary);
		std::vector<std::uint8_t>file_buffer(std::istreambuf_iterator<char>(input), {});

		auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(file_buffer.data());
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return {};

		auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(file_buffer.data() + dos_header->e_lfanew);
		if (nt_header->Signature != IMAGE_NT_SIGNATURE) return {};

		const auto& [section_offset, section_size] = get_section(reinterpret_cast<std::uintptr_t>(file_buffer.data()), section_name);

		if (driver_size > section_size)
		{
			return {};
		}

		potential_drivers potential_driver{};

		potential_driver.file_path = driver_path;
		potential_driver.file_name = driver_name;

		potential_driver.number_of_sections = nt_header->FileHeader.NumberOfSections;

		potential_driver.section_offset = section_offset;
		potential_driver.section_size = section_size;

		return potential_driver;
	}
}
