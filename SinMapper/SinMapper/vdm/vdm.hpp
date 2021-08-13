#pragma once
#include <windows.h>
#include <cstdint>

#include "../util/util.hpp"
#include "../util/loadup.hpp"
#include "raw_driver.hpp"

#define MAP_PHYSICAL 0xC3502004
#define UNMAP_PHYSICAL 0xC3502008

#pragma pack (push, 1)
typedef struct _gdrv_t
{
	unsigned long	interface_type;
	unsigned long	bus;
	std::uintptr_t  phys_addr;
	unsigned long	io_space;
	unsigned long	size;
} gdrv_t, *pgdrv_t;
#pragma pack (pop)

namespace vdm
{
	inline HANDLE drv_handle;
	__forceinline auto load_drv() -> std::pair <HANDLE, std::string>
	{
		LoadLibraryA("user32.dll");

		const auto [result, key] =
			driver::load(
				vdm::raw_driver,
				sizeof(vdm::raw_driver)
			);

		if (!result) 
			return { {}, {} };

		vdm::drv_handle = CreateFileA(
			"\\\\.\\GIO",
			GENERIC_READ | GENERIC_WRITE,
			NULL,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);

		return { vdm::drv_handle, key };
	}

	__forceinline bool unload_drv(HANDLE drv_handle, std::string drv_key)
	{
		return CloseHandle(drv_handle) && driver::unload(drv_key);
	}

	__forceinline bool read_phys(void* addr, void* buffer, std::size_t size)
	{
		if (!util::is_valid(reinterpret_cast<std::uintptr_t>(addr)))
			return false;

		gdrv_t in_buffer;
		in_buffer.bus = NULL;
		in_buffer.interface_type = NULL;
		in_buffer.phys_addr = reinterpret_cast<std::uintptr_t>(addr);
		in_buffer.io_space = NULL;
		in_buffer.size = size;

		void* out_buffer[2] = { 0 };
		unsigned long returned = 0;

		if (!DeviceIoControl(
			drv_handle,
			MAP_PHYSICAL,
			reinterpret_cast<void*>(&in_buffer),
			sizeof in_buffer,
			out_buffer,
			sizeof out_buffer,
			&returned, NULL
		))
			return false;

		__try
		{
			memcpy(buffer, out_buffer[0], size);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{}

		return DeviceIoControl(
			drv_handle,
			UNMAP_PHYSICAL,
			reinterpret_cast<void*>(&out_buffer[0]),
			sizeof out_buffer[0],
			out_buffer,
			sizeof out_buffer,
			&returned, NULL
		);
	}

	__forceinline bool write_phys(void* addr, void* buffer, std::size_t size)
	{
		if (!util::is_valid(reinterpret_cast<std::uintptr_t>(addr)))
			return false;

		gdrv_t in_buffer;
		in_buffer.bus = NULL;
		in_buffer.interface_type = NULL;
		in_buffer.phys_addr = reinterpret_cast<std::uintptr_t>(addr);
		in_buffer.io_space = NULL;
		in_buffer.size = size;

		void* out_buffer[2] = { 0 };
		unsigned long returned = 0;

		if (!DeviceIoControl(
			drv_handle,
			MAP_PHYSICAL,
			reinterpret_cast<void*>(&in_buffer),
			sizeof in_buffer,
			out_buffer,
			sizeof out_buffer,
			&returned, NULL
		))
			return false;

		__try
		{
			memcpy(out_buffer[0], buffer, size);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{}

		return DeviceIoControl(
			drv_handle,
			UNMAP_PHYSICAL,
			reinterpret_cast<void*>(&out_buffer[0]),
			sizeof out_buffer[0],
			out_buffer,
			sizeof out_buffer,
			&returned, NULL
		);
	}

	template <class T>
	__forceinline T read_phys_w(void* addr)
	{
		T buffer;
		read_phys(addr, (void*)&buffer, sizeof(T));
		return buffer;
	}

	template <class T>
	__forceinline bool write_phys_w(void* addr, const T& data)
	{
		return write_phys(addr, (void*)&data, sizeof(T));
	}
}