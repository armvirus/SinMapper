#include "Include.hpp"

NTSTATUS DriverEntry(std::uintptr_t mappedImageBase, std::size_t mappedImageSize)
{
	DebugPrint("Mapped [%p] w/ Size [0x%x]\n", mappedImageBase, mappedImageSize);

	return STATUS_SUCCESS;
}
