#pragma once
#pragma warning(disable: 4996)

//
// Necessary includes, but it excludes user-defined headers.
//

#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>

#include "ia32.h"

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// |                    Defines                         |
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

//
// Log function
//
#define LOG(...) DbgPrintEx(DPFLTR_ACPI_ID, 0, __VA_ARGS__);
#define LOGERR(...) DbgPrintEx(DPFLTR_ACPI_ID, 0, "[ERR] " __VA_ARGS__);
#define LOGINF(...) DbgPrintEx(DPFLTR_ACPI_ID, 0, "[INF] " __VA_ARGS__);

//
// Global pool tag
//
#define POOL_TAG 0x5265492e

//
// Global status value for extra error handling
//
using STATUS = unsigned int;
#define STAT_SUCCESS 0x0
#define STAT_ERROR_KNOWN 0x1
#define STAT_ERROR_UNKNOWN 0x2

//
// CPUID structure
//
typedef struct _CPUID
{
    int eax;
    int ebx;
    int ecx;
    int edx;
} CPUID, * PCPUID;

typedef union _CR_FIXED
{
    UINT64 Flags;

    struct
    {
        unsigned long Low;
        long          High;

    } Fields;

} CR_FIXED, * PCR_FIXED;

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// |                  Functions                         |
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

//
// Summary: Allocate Non-Paged Pool
//
PVOID AllocateNonPagedPool(SIZE_T NumberOfBytes);

//
// Summary: Allocate Non-Paged "Zero-ed" Pool
//
PVOID AllocateZeroedNonPagedPool(SIZE_T size);

//
// Summary: Allocate Contiguous "Zero-ed" Memory
//
PVOID AllocateContiguousZeroedMemory(SIZE_T NumberOfBytes);

//
// Summary: Free Non Paged Pool
//
void FreeNonPagedPool(PVOID address);

//
// Summary: VA 2 PA
//
_Use_decl_annotations_
UINT64
VirtualAddressToPhysicalAddress(_In_ PVOID VirtualAddress);

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// |              Functions (Kernel API)                |
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

extern "C" NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
    _In_ PKDEFERRED_ROUTINE Routine,
    _In_opt_ PVOID          Context);

extern "C" NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
    _In_ PVOID SystemArgument1);

extern "C" NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
    _In_ PVOID SystemArgument2);