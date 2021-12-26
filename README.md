# SinMapper

usermode driver mapper that forcefully loads any signed kernel driver (legit cert) with a big enough section (example: .data, .rdata) to map your driver over. the main focus of this project is to prevent modern anti-cheats (BattlEye, EAC) from finding your driver and having the power to hook anything and create system threads / callbacks due to being inside of legit memory (signed legit driver).

## Procedure
1. The usermode program loads a signed driver of your choice (signed with any valid cert, example: microsoft, intel, etc...)
2. Loads vulnerable driver to read/write physical memory which is needed for syscalls. credits: [vdm (xerox)](https://githacks.org/_xeroxz/vdm)
3. Changes the executable and writable bit of the page tables of the pe section of your choice where the wanted driver is going to be mapped.
4. All traces of the vulnerable driver are cleared including MmUnloadedDrivers list and PiddbCacheTable
5. The driver is mapped in the wanted pe section and the entry is called through syscalls.

## Requirements
Your driver needs an entry like the example driver:

```
NTSTATUS DriverEntry(std::uintptr_t mappedImageBase, std::size_t mappedImageSize)
{
	DebugPrint("Example Driver Mapped [%p] w/ Size [0x%x]\n", mappedImageBase, mappedImageSize);

	return STATUS_SUCCESS;
}
```
The current example passes a structure with the image base and size of the mapped driver but it can be modified to your own liking.

![DbgView Example](./example.PNG)

The project has been tested on ``Windows 10 20H2, 21H1 & Windows 11``

## Usage

```sinmapper.exe driver.sys signed_driver.sys .section_name```
