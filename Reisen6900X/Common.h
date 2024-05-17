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
// Bitmap Bitset techniques
//
#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define BITMAP_ENTRY(_nr, _bmap) ((_bmap))[(_nr) / BITS_PER_LONG]
#define BITMAP_SHIFT(_nr)        ((_nr) % BITS_PER_LONG)

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

/**
 * @brief Segment selector registers in x86
 *
 */
typedef enum _SEGMENT_REGISTERS
{
    ES = 0,
    CS,
    SS,
    DS,
    FS,
    GS,
    LDTR,
    TR
} SEGMENT_REGISTERS;

/**
 * @brief General MSR Structure
 *
 */
typedef union _MSR
{
    struct
    {
        ULONG Low;
        ULONG High;
    } Fields;

    UINT64 Flags;

} MSR, * PMSR;

/**
 * @brief KPROCESS Brief structure
 *
 */
typedef struct _NT_KPROCESS
{
    DISPATCHER_HEADER Header;
    LIST_ENTRY        ProfileListHead;
    ULONG_PTR         DirectoryTableBase;
    UCHAR             Data[1];
} NT_KPROCESS, * PNT_KPROCESS;

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

//
// Summary: Set Bit
//
void SetBit(int BitNumber, unsigned long* addr);

//
// Summary: Test Bit
//
int
TestBit(int BitNumber, unsigned long* addr);

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

//
// VME Interrupts
//

/**
 * @brief Type of interrupts
 *
 */
typedef enum _INTERRUPT_TYPE
{
    INTERRUPT_TYPE_EXTERNAL_INTERRUPT = 0,
    INTERRUPT_TYPE_RESERVED = 1,
    INTERRUPT_TYPE_NMI = 2,
    INTERRUPT_TYPE_HARDWARE_EXCEPTION = 3,
    INTERRUPT_TYPE_SOFTWARE_INTERRUPT = 4,
    INTERRUPT_TYPE_PRIVILEGED_SOFTWARE_INTERRUPT = 5,
    INTERRUPT_TYPE_SOFTWARE_EXCEPTION = 6,
    INTERRUPT_TYPE_OTHER_EVENT = 7
} INTERRUPT_TYPE;

/**
 * @brief Exceptions enum
 *
 */
typedef enum _EXCEPTION_VECTORS
{
    EXCEPTION_VECTOR_DIVIDE_ERROR,
    EXCEPTION_VECTOR_DEBUG_BREAKPOINT,
    EXCEPTION_VECTOR_NMI,
    EXCEPTION_VECTOR_BREAKPOINT,
    EXCEPTION_VECTOR_OVERFLOW,
    EXCEPTION_VECTOR_BOUND_RANGE_EXCEEDED,
    EXCEPTION_VECTOR_UNDEFINED_OPCODE,
    EXCEPTION_VECTOR_NO_MATH_COPROCESSOR,
    EXCEPTION_VECTOR_DOUBLE_FAULT,
    EXCEPTION_VECTOR_RESERVED0,
    EXCEPTION_VECTOR_INVALID_TASK_SEGMENT_SELECTOR,
    EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT,
    EXCEPTION_VECTOR_STACK_SEGMENT_FAULT,
    EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT,
    EXCEPTION_VECTOR_PAGE_FAULT,
    EXCEPTION_VECTOR_RESERVED1,
    EXCEPTION_VECTOR_MATH_FAULT,
    EXCEPTION_VECTOR_ALIGNMENT_CHECK,
    EXCEPTION_VECTOR_MACHINE_CHECK,
    EXCEPTION_VECTOR_SIMD_FLOATING_POINT_NUMERIC_ERROR,
    EXCEPTION_VECTOR_VIRTUAL_EXCEPTION,
    EXCEPTION_VECTOR_RESERVED2,
    EXCEPTION_VECTOR_RESERVED3,
    EXCEPTION_VECTOR_RESERVED4,
    EXCEPTION_VECTOR_RESERVED5,
    EXCEPTION_VECTOR_RESERVED6,
    EXCEPTION_VECTOR_RESERVED7,
    EXCEPTION_VECTOR_RESERVED8,
    EXCEPTION_VECTOR_RESERVED9,
    EXCEPTION_VECTOR_RESERVED10,
    EXCEPTION_VECTOR_RESERVED11,
    EXCEPTION_VECTOR_RESERVED12,

    //
    // NT (Windows) specific exception vectors.
    //
    APC_INTERRUPT = 31,
    DPC_INTERRUPT = 47,
    CLOCK_INTERRUPT = 209,
    IPI_INTERRUPT = 225,
    PMI_INTERRUPT = 254,

} EXCEPTION_VECTORS;

typedef union _INTERRUPT_INFO
{
    struct
    {
        UINT32 Vector : 8;
        /* 0=Ext Int, 1=Rsvd, 2=NMI, 3=Exception, 4=Soft INT,
         * 5=Priv Soft Trap, 6=Unpriv Soft Trap, 7=Other */
        UINT32 InterruptType : 3;
        UINT32 DeliverCode : 1; /* 0=Do not deliver, 1=Deliver */
        UINT32 Reserved : 19;
        UINT32 Valid : 1; /* 0=Not valid, 1=Valid. Must be checked first */
    } Fields;
    UINT32 Flags;
} INTERRUPT_INFO, * PINTERRUPT_INFO;