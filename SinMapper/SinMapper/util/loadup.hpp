/*
	MIT License

	Copyright (c) 2020 xerox

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/


#pragma once
#include <Windows.h>
#include <Winternl.h>
#include <string>
#include <fstream>
#include <filesystem>

#pragma comment(lib, "ntdll.lib")
extern "C" NTSTATUS NtLoadDriver(PUNICODE_STRING);
extern "C" NTSTATUS NtUnloadDriver(PUNICODE_STRING);

namespace driver
{
	namespace util
	{
		__forceinline auto delete_service_entry(const std::string& service_name) -> bool
		{
			HKEY reg_handle;
			static const std::string reg_key("System\\CurrentControlSet\\Services\\");

			auto result = RegOpenKeyA(
				HKEY_LOCAL_MACHINE,
				reg_key.c_str(),
				&reg_handle
			);

			return ERROR_SUCCESS == RegDeleteKeyA(reg_handle, service_name.data()) &&
				ERROR_SUCCESS == RegCloseKey(reg_handle);;
		}

		__forceinline auto create_service_entry(const std::string& drv_path, const std::string& service_name) -> bool
		{
			HKEY reg_handle;
			std::string reg_key("System\\CurrentControlSet\\Services\\");
			reg_key += service_name;

			auto result = RegCreateKeyA(
				HKEY_LOCAL_MACHINE,
				reg_key.c_str(),
				&reg_handle
			);

			if (result != ERROR_SUCCESS)
				return false;

			std::uint8_t type_value = 1;
			result = RegSetValueExA(
				reg_handle,
				"Type",
				NULL,
				REG_DWORD,
				&type_value,
				4u
			);

			if (result != ERROR_SUCCESS)
				return false;

			std::uint8_t error_control_value = 3;
			result = RegSetValueExA(
				reg_handle,
				"ErrorControl",
				NULL,
				REG_DWORD,
				&error_control_value,
				4u
			);

			if (result != ERROR_SUCCESS)
				return false;

			std::uint8_t start_value = 3;
			result = RegSetValueExA(
				reg_handle,
				"Start",
				NULL,
				REG_DWORD,
				&start_value,
				4u
			);

			if (result != ERROR_SUCCESS)
				return false;

			result = RegSetValueExA(
				reg_handle,
				"ImagePath",
				NULL,
				REG_SZ,
				(std::uint8_t*) drv_path.c_str(),
				drv_path.size()
			);

			if (result != ERROR_SUCCESS)
				return false;

			return ERROR_SUCCESS == RegCloseKey(reg_handle);
		}

		__forceinline auto enable_privilege(const std::wstring& privilege_name) -> bool
		{
			HANDLE token_handle = nullptr;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle))
				return false;

			LUID luid{};
			if (!LookupPrivilegeValueW(nullptr, privilege_name.data(), &luid))
				return false;

			TOKEN_PRIVILEGES token_state{};
			token_state.PrivilegeCount = 1;
			token_state.Privileges[0].Luid = luid;
			token_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (!AdjustTokenPrivileges(token_handle, FALSE, &token_state, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
				return false;

			CloseHandle(token_handle);
			return true;
		}

		__forceinline auto get_service_image_path(const std::string& service_name) -> std::string
		{
			HKEY reg_handle;
			DWORD bytes_read;
			char image_path[0xFF];
			static const std::string reg_key("System\\CurrentControlSet\\Services\\");

			auto result = RegOpenKeyA(
				HKEY_LOCAL_MACHINE,
				reg_key.c_str(),
				&reg_handle
			);

			result = RegGetValueA(
				reg_handle,
				service_name.c_str(),
				"ImagePath",
				REG_SZ,
				NULL,
				image_path,
				&bytes_read
			);

			RegCloseKey(reg_handle);
			return std::string(image_path);
		}
	}

	__forceinline auto load(const std::string& drv_path, const std::string& service_name) -> bool
	{
		if (!util::enable_privilege(L"SeLoadDriverPrivilege"))
			return false;

		if (!util::create_service_entry("\\??\\" +
			std::filesystem::absolute(std::filesystem::path(drv_path)).string(), service_name))
			return false;

		std::string reg_path("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
		reg_path += service_name;

		ANSI_STRING driver_rep_path_cstr;
		UNICODE_STRING driver_reg_path_unicode;

		RtlInitAnsiString(&driver_rep_path_cstr, reg_path.c_str());
		RtlAnsiStringToUnicodeString(&driver_reg_path_unicode, &driver_rep_path_cstr, true);
		return ERROR_SUCCESS == NtLoadDriver(&driver_reg_path_unicode);
	}

	__forceinline auto load(const std::vector<std::uint8_t>& drv_buffer) -> std::tuple<bool, std::string>
	{
		static const auto random_file_name = [](std::size_t length) -> std::string
		{
			static const auto randchar = []() -> char
			{
				const char charset[] =
					"0123456789"
					"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
					"abcdefghijklmnopqrstuvwxyz";
				const std::size_t max_index = (sizeof(charset) - 1);
				return charset[rand() % max_index];
			};
			std::string str(length, 0);
			std::generate_n(str.begin(), length, randchar);
			return str;
		};

		const auto service_name = random_file_name(16);
		const auto file_path = std::filesystem::temp_directory_path().string() + service_name;
		std::ofstream output_file(file_path.c_str(), std::ios::binary);

		output_file.write((char*)drv_buffer.data(), drv_buffer.size());
		output_file.close();

		return { load(file_path, service_name), service_name };
	}

	__forceinline auto load(const std::uint8_t* buffer, const std::size_t size) -> std::tuple<bool, std::string>
	{
		std::vector<std::uint8_t> image(buffer, buffer + size);
		return load(image);
	}

	__forceinline auto unload(const std::string& service_name) -> bool
	{
		std::string reg_path("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
		reg_path += service_name;

		ANSI_STRING driver_rep_path_cstr;
		UNICODE_STRING driver_reg_path_unicode;

		RtlInitAnsiString(&driver_rep_path_cstr, reg_path.c_str());
		RtlAnsiStringToUnicodeString(&driver_reg_path_unicode, &driver_rep_path_cstr, true);

		const bool unload_drv = STATUS_SUCCESS == NtUnloadDriver(&driver_reg_path_unicode);
		const auto image_path = std::filesystem::temp_directory_path().string() + service_name;
		const bool delete_reg = util::delete_service_entry(service_name);

		// sometimes you cannot delete the driver off disk because there are still handles open
		// to the driver, this means the driver is still loaded into the kernel...
		try
		{
			std::filesystem::remove(image_path);
		}
		catch (std::exception& e)
		{
			return false;
		}
		return delete_reg && unload_drv;
	}
}