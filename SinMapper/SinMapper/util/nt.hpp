#pragma once
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <cstdint>
#include <cstddef>
#include <map>
#include <string>
#pragma comment(lib, "ntdll.lib")

#define PAGE_4KB 0x1000
#define MM_COPY_MEMORY_PHYSICAL             0x1
#define MM_COPY_MEMORY_VIRTUAL              0x2
#define PAGE_IN(addr, size) memset(addr, NULL, size)

constexpr auto SystemModuleInformation = 11;
constexpr auto SystemHandleInformation = 16;
constexpr auto SystemExtendedHandleInformation = 64;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef LARGE_INTEGER PHYSICAL_ADDRESS, * PPHYSICAL_ADDRESS;

typedef struct _MM_COPY_ADDRESS {
    union {
        PVOID            VirtualAddress;
        PHYSICAL_ADDRESS PhysicalAddress;
    };
} MM_COPY_ADDRESS, * PMMCOPY_ADDRESS;

using PEPROCESS = PVOID;

using PsLookupProcessByProcessId = NTSTATUS (__fastcall*)(
    HANDLE     ProcessId,
	PEPROCESS* Process
);

using MmCopyMemory = NTSTATUS(__stdcall*)(
    PVOID, 
    MM_COPY_ADDRESS,
    SIZE_T,
    ULONG, 
    PSIZE_T
);

using MmGetVirtualForPhysical = std::uintptr_t(__fastcall*)(
    __in std::uintptr_t PhysicalAddress
);

using MmGetPhysicalAddress = std::uintptr_t(__fastcall*)(
    __in std::uintptr_t BaseAddress
);

typedef enum _POOL_TYPE {
    NonPagedPool,
    NonPagedPoolExecute,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS,
    MaxPoolType,
    NonPagedPoolBase,
    NonPagedPoolBaseMustSucceed,
    NonPagedPoolBaseCacheAligned,
    NonPagedPoolBaseCacheAlignedMustS,
    NonPagedPoolSession,
    PagedPoolSession,
    NonPagedPoolMustSucceedSession,
    DontUseThisTypeSession,
    NonPagedPoolCacheAlignedSession,
    PagedPoolCacheAlignedSession,
    NonPagedPoolCacheAlignedMustSSession,
    NonPagedPoolNx,
    NonPagedPoolNxCacheAligned,
    NonPagedPoolSessionNx
} POOL_TYPE;

using ExAllocatePool = PVOID(__stdcall*) (POOL_TYPE, SIZE_T);
using MiGetPteAddress = std::uintptr_t(NTAPI*)(std::uintptr_t);

struct potential_drivers
{
    std::string file_path;
    std::string file_name;

    std::uint32_t section_offset;
    std::uint32_t section_size;

    int number_of_sections;
};

using EntryCall = NTSTATUS(__stdcall*)(std::uintptr_t mappedImageBase, std::size_t mappedImageSize);

typedef union _virt_addr_t
{
    void* value;
    struct
    {
        std::uint64_t offset : 12;
        std::uint64_t pt_index : 9;
        std::uint64_t pd_index : 9;
        std::uint64_t pdpt_index : 9;
        std::uint64_t pml4_index : 9;
        std::uint64_t reserved : 16;
    };
} virt_addr_t, *pvirt_addr_t;
static_assert(sizeof(virt_addr_t) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef union _pml4e
{
    std::uint64_t value;
    struct
    {
        std::uint64_t present : 1;          // Must be 1, region invalid if 0.
        std::uint64_t writeable : 1;        // If 0, writes not allowed.
        std::uint64_t user_supervisor : 1;   // If 0, user-mode accesses not allowed.
        std::uint64_t PageWriteThrough : 1; // Determines the memory type used to access PDPT.
        std::uint64_t page_cache : 1; // Determines the memory type used to access PDPT.
        std::uint64_t accessed : 1;         // If 0, this entry has not been used for translation.
        std::uint64_t Ignored1 : 1;
        std::uint64_t large_page : 1;         // Must be 0 for PML4E.
        std::uint64_t Ignored2 : 4;
        std::uint64_t pfn : 36; // The page frame number of the PDPT of this PML4E.
        std::uint64_t Reserved : 4;
        std::uint64_t Ignored3 : 11;
        std::uint64_t nx : 1; // If 1, instruction fetches not allowed.
    };
} pml4e, * ppml4e;
static_assert(sizeof(pml4e) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef union _pdpte
{
    std::uint64_t value;
    struct
    {
        std::uint64_t present : 1;          // Must be 1, region invalid if 0.
        std::uint64_t rw : 1;        // If 0, writes not allowed.
        std::uint64_t user_supervisor : 1;   // If 0, user-mode accesses not allowed.
        std::uint64_t PageWriteThrough : 1; // Determines the memory type used to access PD.
        std::uint64_t page_cache : 1; // Determines the memory type used to access PD.
        std::uint64_t accessed : 1;         // If 0, this entry has not been used for translation.
        std::uint64_t Ignored1 : 1;
        std::uint64_t large_page : 1;         // If 1, this entry maps a 1GB page.
        std::uint64_t Ignored2 : 4;
        std::uint64_t pfn : 36; // The page frame number of the PD of this PDPTE.
        std::uint64_t Reserved : 4;
        std::uint64_t Ignored3 : 11;
        std::uint64_t nx : 1; // If 1, instruction fetches not allowed.
    };
} pdpte, * ppdpte;
static_assert(sizeof(pdpte) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef union _pde
{
    std::uint64_t value;
    struct
    {
        std::uint64_t present : 1;          // Must be 1, region invalid if 0.
        std::uint64_t rw : 1;        // If 0, writes not allowed.
        std::uint64_t user_supervisor : 1;   // If 0, user-mode accesses not allowed.
        std::uint64_t PageWriteThrough : 1; // Determines the memory type used to access PT.
        std::uint64_t page_cache : 1; // Determines the memory type used to access PT.
        std::uint64_t accessed : 1;         // If 0, this entry has not been used for translation.
        std::uint64_t Ignored1 : 1;
        std::uint64_t large_page : 1; // If 1, this entry maps a 2MB page.
        std::uint64_t Ignored2 : 4;
        std::uint64_t pfn : 36; // The page frame number of the PT of this PDE.
        std::uint64_t Reserved : 4;
        std::uint64_t Ignored3 : 11;
        std::uint64_t nx : 1; // If 1, instruction fetches not allowed.
    };
} pde, * ppde;
static_assert(sizeof(pde) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef union _pte
{
    std::uint64_t value;
    struct
    {
        std::uint64_t present : 1;          // Must be 1, region invalid if 0.
        std::uint64_t rw : 1;        // If 0, writes not allowed.
        std::uint64_t user_supervisor : 1;   // If 0, user-mode accesses not allowed.
        std::uint64_t PageWriteThrough : 1; // Determines the memory type used to access the memory.
        std::uint64_t page_cache : 1; // Determines the memory type used to access the memory.
        std::uint64_t accessed : 1;         // If 0, this entry has not been used for translation.
        std::uint64_t Dirty : 1;            // If 0, the memory backing this page has not been written to.
        std::uint64_t PageAccessType : 1;   // Determines the memory type used to access the memory.
        std::uint64_t Global : 1;           // If 1 and the PGE bit of CR4 is set, translations are global.
        std::uint64_t Ignored2 : 3;
        std::uint64_t pfn : 36; // The page frame number of the backing physical page.
        std::uint64_t reserved : 4;
        std::uint64_t Ignored3 : 7;
        std::uint64_t ProtectionKey : 4;  // If the PKE bit of CR4 is set, determines the protection key.
        std::uint64_t nx : 1; // If 1, instruction fetches not allowed.
    };
} pte, * ppte;
static_assert(sizeof(pte) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

struct pt_entries
{
    std::pair<ppml4e, pml4e>	pml4;
    std::pair<ppdpte, pdpte>	pdpt;
    std::pair<ppde, pde>		pd;
    std::pair<ppte, pte>		pt;
};