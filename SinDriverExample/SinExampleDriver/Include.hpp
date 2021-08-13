#pragma once

#include <ntifs.h>
#include <windef.h>

#include <cstdint>
#include <cstddef>
#include <ntimage.h>

#define DebugPrint(fmt, ...) DbgPrintEx(0, 0, "[SinExampleDriver] " fmt, ##__VA_ARGS__)