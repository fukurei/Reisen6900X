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

#define PENDING_INTERRUPTS_BUFFER_CAPACITY 64

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

// Undefined VMCS Selector in ia32.h

#define VMCS_GUEST_DEBUGCTL_HIGH 0x2803
#define VIRTUAL_PROCESSOR_ID     0x00000000
#define VPID_TAG 0x1

#define HV_X64_MSR_GUEST_IDLE 0x400000F0
#define RESERVED_MSR_RANGE_LOW 0x40000000
#define RESERVED_MSR_RANGE_HI  0x400000F0


/**
 * @brief The number of 512GB PML4 entries in the page table
 *
 */
#define VMM_EPT_PML4E_COUNT 512

 /**
  * @brief The number of 1GB PDPT entries in the page table per 512GB PML4 entry
  *
  */
#define VMM_EPT_PML3E_COUNT 512

  /**
   * @brief Then number of 2MB Page Directory entries in the page table per 1GB
   *  PML3 entry
   *
   */
#define VMM_EPT_PML2E_COUNT 512

   /**
    * @brief Then number of 4096 byte Page Table entries in the page table per 2MB PML2
    * entry when dynamically split
    *
    */
#define VMM_EPT_PML1E_COUNT 512

#define MaximumHiddenBreakpointsOnPage 40

    /*
     * @brief Windows IRQ Levels
     */
#define PASSIVE_LEVEL  0  // Passive release level
#define LOW_LEVEL      0  // Lowest interrupt level
#define APC_LEVEL      1  // APC interrupt level
#define DISPATCH_LEVEL 2  // Dispatcher level
#define CMCI_LEVEL     5  // CMCI handler level
#define CLOCK_LEVEL    13 // Interval clock level
#define IPI_LEVEL      14 // Interprocessor interrupt level
#define DRS_LEVEL      14 // Deferred Recovery Service level
#define POWER_LEVEL    14 // Power failure level
#define PROFILE_LEVEL  15 // timer used for profiling.
#define HIGH_LEVEL     15 // Highest interrupt level

     /**
      * @brief Intel CPU flags in CR0
      */
#define X86_CR0_PE 0x00000001 /* Enable Protected Mode    (RW) */
#define X86_CR0_MP 0x00000002 /* Monitor Coprocessor      (RW) */
#define X86_CR0_EM 0x00000004 /* Require FPU Emulation    (RO) */
#define X86_CR0_TS 0x00000008 /* Task Switched            (RW) */
#define X86_CR0_ET 0x00000010 /* Extension type           (RO) */
#define X86_CR0_NE 0x00000020 /* Numeric Error Reporting  (RW) */
#define X86_CR0_WP 0x00010000 /* Supervisor Write Protect (RW) */
#define X86_CR0_AM 0x00040000 /* Alignment Checking       (RW) */
#define X86_CR0_NW 0x20000000 /* Not Write-Through        (RW) */
#define X86_CR0_CD 0x40000000 /* Cache Disable            (RW) */
#define X86_CR0_PG 0x80000000 /* Paging                         */

      /**
       * @brief Intel CPU features in CR4
       *
       */
#define X86_CR4_VME        0x0001 /* enable vm86 extensions */
#define X86_CR4_PVI        0x0002 /* virtual interrupts flag enable */
#define X86_CR4_TSD        0x0004 /* disable time stamp at ipl 3 */
#define X86_CR4_DE         0x0008 /* enable debugging extensions */
#define X86_CR4_PSE        0x0010 /* enable page size extensions */
#define X86_CR4_PAE        0x0020 /* enable physical address extensions */
#define X86_CR4_MCE        0x0040 /* Machine check enable */
#define X86_CR4_PGE        0x0080 /* enable global pages */
#define X86_CR4_PCE        0x0100 /* enable performance counters at ipl 3 */
#define X86_CR4_OSFXSR     0x0200 /* enable fast FPU save and restore */
#define X86_CR4_OSXMMEXCPT 0x0400 /* enable unmasked SSE exceptions */
#define X86_CR4_VMXE       0x2000 /* enable VMX */

       /**
        * @brief EFLAGS/RFLAGS
        *
        */
#define X86_FLAGS_CF                 (1 << 0)
#define X86_FLAGS_PF                 (1 << 2)
#define X86_FLAGS_AF                 (1 << 4)
#define X86_FLAGS_ZF                 (1 << 6)
#define X86_FLAGS_SF                 (1 << 7)
#define X86_FLAGS_TF                 (1 << 8)
#define X86_FLAGS_IF                 (1 << 9)
#define X86_FLAGS_DF                 (1 << 10)
#define X86_FLAGS_OF                 (1 << 11)
#define X86_FLAGS_STATUS_MASK        (0xfff)
#define X86_FLAGS_IOPL_MASK          (3 << 12)
#define X86_FLAGS_IOPL_SHIFT         (12)
#define X86_FLAGS_IOPL_SHIFT_2ND_BIT (13)
#define X86_FLAGS_NT                 (1 << 14)
#define X86_FLAGS_RF                 (1 << 16)
#define X86_FLAGS_VM                 (1 << 17)
#define X86_FLAGS_AC                 (1 << 18)
#define X86_FLAGS_VIF                (1 << 19)
#define X86_FLAGS_VIP                (1 << 20)
#define X86_FLAGS_ID                 (1 << 21)
#define X86_FLAGS_RESERVED_ONES      0x2
#define X86_FLAGS_RESERVED           0xffc0802a

#define X86_FLAGS_RESERVED_BITS 0xffc38028
#define X86_FLAGS_FIXED         0x00000002

typedef EPT_PML4E   EPT_PML4_POINTER, * PEPT_PML4_POINTER;
typedef EPT_PDPTE   EPT_PML3_POINTER, * PEPT_PML3_POINTER;
typedef EPT_PDE_2MB EPT_PML2_ENTRY, * PEPT_PML2_ENTRY;
typedef EPT_PDE     EPT_PML2_POINTER, * PEPT_PML2_POINTER;
typedef EPT_PTE     EPT_PML1_ENTRY, * PEPT_PML1_ENTRY;

typedef struct GUEST_REGS
{
    // Hint: Don't touch this struct with ANY reason
    UINT64 rax; // 0x00
    UINT64 rcx; // 0x08
    UINT64 rdx; // 0x10
    UINT64 rbx; // 0x18
    UINT64 rsp; // 0x20
    UINT64 rbp; // 0x28
    UINT64 rsi; // 0x30
    UINT64 rdi; // 0x38
    UINT64 r8;  // 0x40
    UINT64 r9;  // 0x48
    UINT64 r10; // 0x50
    UINT64 r11; // 0x58
    UINT64 r12; // 0x60
    UINT64 r13; // 0x68
    UINT64 r14; // 0x70
    UINT64 r15; // 0x78

} GUEST_REGS, * PGUEST_REGS;

typedef struct _VMM_EPT_PAGE_TABLE
{
    /**
     * @brief 28.2.2 Describes 512 contiguous 512GB memory regions each with 512 1GB regions.
     */
    DECLSPEC_ALIGN(PAGE_SIZE)
        EPT_PML4_POINTER PML4[VMM_EPT_PML4E_COUNT];

    /**
     * @brief Describes exactly 512 contiguous 1GB memory regions within a our singular 512GB PML4 region.
     */
    DECLSPEC_ALIGN(PAGE_SIZE)
        EPT_PML3_POINTER PML3[VMM_EPT_PML3E_COUNT];

    /**
     * @brief For each 1GB PML3 entry, create 512 2MB entries to map identity.
     * NOTE: We are using 2MB pages as the smallest paging size in our map, so we do not manage individual 4096 byte pages.
     * Therefore, we do not allocate any PML1 (4096 byte) paging structures.
     */
    DECLSPEC_ALIGN(PAGE_SIZE)
        EPT_PML2_ENTRY PML2[VMM_EPT_PML3E_COUNT][VMM_EPT_PML2E_COUNT];

} VMM_EPT_PAGE_TABLE, * PVMM_EPT_PAGE_TABLE;

typedef struct _VMX_VMXOFF_STATE
{
    BOOLEAN IsVmxoffExecuted; // Shows whether the VMXOFF executed or not
    UINT64  GuestRip;         // Rip address of guest to return
    UINT64  GuestRsp;         // Rsp address of guest to return

} VMX_VMXOFF_STATE, * PVMX_VMXOFF_STATE;

typedef enum _NMI_BROADCAST_ACTION_TYPE
{
    NMI_BROADCAST_ACTION_NONE = 0,
    NMI_BROADCAST_ACTION_TEST,
    NMI_BROADCAST_ACTION_REQUEST,
    NMI_BROADCAST_ACTION_INVALIDATE_EPT_CACHE_SINGLE_CONTEXT,
    NMI_BROADCAST_ACTION_INVALIDATE_EPT_CACHE_ALL_CONTEXTS,

} NMI_BROADCAST_ACTION_TYPE;

typedef struct _NMI_BROADCASTING_STATE
{
    volatile NMI_BROADCAST_ACTION_TYPE NmiBroadcastAction; // The broadcast action for NMI

} NMI_BROADCASTING_STATE, * PNMI_BROADCASTING_STATE;

typedef struct _EPT_HOOKS_CONTEXT
{
    UINT64 HookingTag; // This is same as the event tag
    UINT64 PhysicalAddress;
    UINT64 VirtualAddress;
} EPT_HOOKS_CONTEXT, * PEPT_HOOKS_CONTEXT;

typedef enum _EPT_HOOKED_LAST_VIOLATION
{
    EPT_HOOKED_LAST_VIOLATION_READ = 1,
    EPT_HOOKED_LAST_VIOLATION_WRITE = 2,
    EPT_HOOKED_LAST_VIOLATION_EXEC = 3

} EPT_HOOKED_LAST_VIOLATION;

typedef struct _EPT_HOOKED_PAGE_DETAIL
{
    DECLSPEC_ALIGN(PAGE_SIZE)
        CHAR FakePageContents[PAGE_SIZE];

    /**
     * @brief Linked list entries for each page hook.
     */
    LIST_ENTRY PageHookList;

    /**
     * @brief The virtual address from the caller perspective view (cr3)
     */
    UINT64 VirtualAddress;

    /**
     * @brief The virtual address of it's entry on g_EptHook2sDetourListHead
     * this way we can de-allocate the list whenever the hook is finished
     */
    UINT64 AddressOfEptHook2sDetourListEntry;

    /**
     * @brief The base address of the page. Used to find this structure in the list of page hooks
     * when a hook is hit.
     */
    SIZE_T PhysicalBaseAddress;

    /**
     * @brief Start address of the target physical address.
     */
    SIZE_T StartOfTargetPhysicalAddress;

    /**
     * @brief End address of the target physical address.
     */
    SIZE_T EndOfTargetPhysicalAddress;

    /**
     * @brief Tag used for notifying the caller.
     */
    UINT64 HookingTag;

    /**
     * @brief The base address of the page with fake contents. Used to swap page with fake contents
     * when a hook is hit.
     */
    SIZE_T PhysicalBaseAddressOfFakePageContents;

    /**
     * @brief The original page entry. Will be copied back when the hook is removed
     * from the page.
     */
    EPT_PML1_ENTRY OriginalEntry;

    /**
     * @brief The original page entry. Will be copied back when the hook is remove from the page.
     */
    EPT_PML1_ENTRY ChangedEntry;

    /**
     * @brief The buffer of the trampoline function which is used in the inline hook.
     */
    PCHAR Trampoline;

    /**
     * @brief This field shows whether the hook contains a hidden hook for execution or not
     */
    BOOLEAN IsExecutionHook;

    /**
     * @brief If TRUE shows that this is the information about
     * a hidden breakpoint command (not a monitor or hidden detours)
     */
    BOOLEAN IsHiddenBreakpoint;

    /**
     * @brief Temporary context for the post event monitors
     * It shows the context of the last address that triggered the hook
     * Note: Only used for read/write trigger events
     */
    EPT_HOOKS_CONTEXT LastContextState;

    /**
     * @brief This field shows whether the hook should call the post event trigger
     * after restoring the state or not
     */
    BOOLEAN IsPostEventTriggerAllowed;

    /**
     * @brief This field shows the last violation happened to this EPT hook
     */
    EPT_HOOKED_LAST_VIOLATION LastViolation;

    /**
     * @brief Address of hooked pages (multiple breakpoints on a single page)
     * this is only used in hidden breakpoints (not hidden detours)
     */
    UINT64 BreakpointAddresses[MaximumHiddenBreakpointsOnPage];

    /**
     * @brief Character that was previously used in BreakpointAddresses
     * this is only used in hidden breakpoints (not hidden detours)
     */
    CHAR PreviousBytesOnBreakpointAddresses[MaximumHiddenBreakpointsOnPage];

    /**
     * @brief Count of breakpoints (multiple breakpoints on a single page)
     * this is only used in hidden breakpoints (not hidden detours)
     */
    UINT64 CountOfBreakpoints;

} EPT_HOOKED_PAGE_DETAIL, * PEPT_HOOKED_PAGE_DETAIL;

typedef struct _VM_EXIT_TRANSPARENCY
{
    UINT64 PreviousTimeStampCounter;

    HANDLE  ThreadId;
    UINT64  RevealedTimeStampCounterByRdtsc;
    BOOLEAN CpuidAfterRdtscDetected;

} VM_EXIT_TRANSPARENCY, * PVM_EXIT_TRANSPARENCY;

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

/**
 * @brief The status of each core after and before VMX
 *
 */
typedef struct _VIRTUAL_MACHINE_STATE
{
    BOOLEAN      IsOnVmxRootMode;                                               // Detects whether the current logical core is on Executing on VMX Root Mode
    BOOLEAN      IncrementRip;                                                  // Checks whether it has to redo the previous instruction or not (it used mainly in Ept routines)
    BOOLEAN      HasLaunched;                                                   // Indicate whether the core is virtualized or not
    BOOLEAN      IgnoreMtfUnset;                                                // Indicate whether the core should ignore unsetting the MTF or not
    BOOLEAN      WaitForImmediateVmexit;                                        // Whether the current core is waiting for an immediate vm-exit or not
    BOOLEAN      EnableExternalInterruptsOnContinue;                            // Whether to enable external interrupts on the continue  or not
    BOOLEAN      EnableExternalInterruptsOnContinueMtf;                         // Whether to enable external interrupts on the continue state of MTF or not
    BOOLEAN      RegisterBreakOnMtf;                                            // Registered Break in the case of MTFs (used in instrumentation step-in)
    BOOLEAN      IgnoreOneMtf;                                                  // Ignore (mark as handled) for one MTF
    BOOLEAN      NotNormalEptp;                                                 // Indicate that the target processor is on the normal EPTP or not
    BOOLEAN      MbecEnabled;                                                   // Indicate that the target processor is on MBEC-enabled mode or not
    PUINT64      PmlBufferAddress;                                              // Address of buffer used for dirty logging
    BOOLEAN      Test;                                                          // Used for test purposes
    UINT64       TestNumber;                                                    // Used for test purposes (Number)
    GUEST_REGS* Regs;                                                          // The virtual processor's general-purpose registers
    UINT32       CoreId;                                                        // The core's unique identifier
    UINT32       ExitReason;                                                    // The core's exit reason
    UINT32       ExitQualification;                                             // The core's exit qualification
    UINT64       LastVmexitRip;                                                 // RIP in the current VM-exit
    UINT64       VmxonRegionPhysicalAddress;                                    // Vmxon region physical address
    UINT64       VmxonRegionVirtualAddress;                                     // VMXON region virtual address
    UINT64       VmcsRegionPhysicalAddress;                                     // VMCS region physical address
    UINT64       VmcsRegionVirtualAddress;                                      // VMCS region virtual address
    UINT64       VmmStack;                                                      // Stack for VMM in VM-Exit State
    UINT64       MsrBitmapVirtualAddress;                                       // Msr Bitmap Virtual Address
    UINT64       MsrBitmapPhysicalAddress;                                      // Msr Bitmap Physical Address
    UINT64       IoBitmapVirtualAddressA;                                       // I/O Bitmap Virtual Address (A)
    UINT64       IoBitmapPhysicalAddressA;                                      // I/O Bitmap Physical Address (A)
    UINT64       IoBitmapVirtualAddressB;                                       // I/O Bitmap Virtual Address (B)
    UINT64       IoBitmapPhysicalAddressB;                                      // I/O Bitmap Physical Address (B)
    UINT32       PendingExternalInterrupts[PENDING_INTERRUPTS_BUFFER_CAPACITY]; // This list holds a buffer for external-interrupts that are in pending state due to the external-interrupt
    // blocking and waits for interrupt-window exiting
    // From hvpp :
    // Pending interrupt queue (FIFO).
    // Make storage for up-to 64 pending interrupts.
    // In practice I haven't seen more than 2 pending interrupts.
    VMX_VMXOFF_STATE        VmxoffState;                                        // Shows the vmxoff state of the guest
    NMI_BROADCASTING_STATE  NmiBroadcastingState;                               // Shows the state of NMI broadcasting
    VM_EXIT_TRANSPARENCY    TransparencyState;                                  // The state of the debugger in transparent-mode
    PEPT_HOOKED_PAGE_DETAIL MtfEptHookRestorePoint;                             // It shows the detail of the hooked paged that should be restore in MTF vm-exit

    //
    // EPT Descriptors
    //
    EPT_POINTER         EptPointer;   // Extended-Page-Table Pointer
    PVMM_EPT_PAGE_TABLE EptPageTable; // Details of core-specific page-table

} VIRTUAL_MACHINE_STATE, * PVIRTUAL_MACHINE_STATE;

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

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// |                 Functions (Asm)                    |
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/**
 * @brief Get CS Register
 *
 * @return unsigned short
 */
extern "C" unsigned short
AsmGetCs();

/**
 * @brief Get DS Register
 *
 * @return unsigned short
 */
extern "C" unsigned short
AsmGetDs();

/**
 * @brief Get ES Register
 *
 * @return unsigned short
 */
extern "C" unsigned short
AsmGetEs();

/**
 * @brief Get SS Register
 *
 * @return unsigned short
 */
extern "C" unsigned short
AsmGetSs();

/**
 * @brief Get FS Register
 *
 * @return unsigned short
 */
extern "C" unsigned short
AsmGetFs();

/**
 * @brief Get GS Register
 *
 * @return unsigned short
 */
extern "C" unsigned short
AsmGetGs();

/**
 * @brief Get LDTR Register
 *
 * @return unsigned short
 */
extern "C" unsigned short
AsmGetLdtr();

/**
 * @brief Get TR Register
 *
 * @return unsigned short
 */
extern "C" unsigned short
AsmGetTr();

/* ******* Gdt related functions ******* */

/**
 * @brief get GDT base
 *
 * @return unsigned long long
 */
extern "C" unsigned long long inline AsmGetGdtBase();

/**
 * @brief Get GDT Limit
 *
 * @return unsigned short
 */
extern "C" unsigned short
AsmGetGdtLimit();

/* ******* Idt related functions ******* */

/**
 * @brief Get IDT base
 *
 * @return unsigned long long
 */
extern "C" unsigned long long inline AsmGetIdtBase();

/**
 * @brief Get IDT limit
 *
 * @return unsigned short
 */
extern "C" unsigned short
AsmGetIdtLimit();

extern "C" UINT32
AsmGetAccessRights(unsigned short Selector);

/**
 * @brief Get R/EFLAGS
 *
 * @return unsigned short
 */
extern "C" unsigned short
AsmGetRflags();

/**
 * @brief Vm-exit handler
 *
 */
extern "C" void
AsmVmexitHandler();

extern "C" void
AsmReloadGdtr(PVOID GdtBase, UINT32 GdtLimit);

extern "C" void
AsmReloadIdtr(PVOID IdtBase, UINT32 IdtLimit);

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// |                 Functions (VMX)                    |
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/**
* @brief VMX VMWRITE instruction (64-bit)
* @param Field
* @param FieldValue
*
* @return UCHAR
*/
inline UCHAR
VmxVmwrite64(size_t Field,
    UINT64 FieldValue);

/**
 * @brief VMX VMWRITE instruction (32-bit)
 * @param Field
 * @param FieldValue
 *
 * @return UCHAR
 */
inline UCHAR
VmxVmwrite32(size_t Field,
    UINT32 FieldValue);

/**
 * @brief VMX VMWRITE instruction (16-bit)
 * @param Field
 * @param FieldValue
 *
 * @return UCHAR
 */
inline UCHAR
VmxVmwrite16(size_t Field,
    UINT16 FieldValue);

/**
 * @brief VMX VMREAD instruction (64-bit)
 * @param Field
 * @param FieldValue
 *
 * @return UCHAR
 */
extern "C" inline UCHAR
VmxVmRead64P(size_t   Field,
    UINT64* FieldValue);

extern "C" inline UINT16
VmxVmRead16(size_t Field);

extern "C" inline UINT32
VmxVmRead32(size_t Field);

extern "C" inline UINT64
VmxVmRead64(size_t Field);

// Inject CPU Interruption event
VOID
EventInjectInterruption(INTERRUPT_TYPE InterruptionType, EXCEPTION_VECTORS Vector, BOOLEAN DeliverErrorCode, UINT32 ErrorCode);

// Inject CPU General Protection Exception Event
VOID
EventInjectGeneralProtection();

/**
 * @brief Suppress the incrementation of RIP
 *
 * @param VCpu The virtual processor's state
 *
 * @return VOID
 */
inline VOID
HvSuppressRipIncrement(VIRTUAL_MACHINE_STATE* VCpu);

/**
 * @brief Inject #UD to the guest (Invalid Opcode - Undefined Opcode)
 * @param VCpu The virtual processor's state
 *
 * @return VOID
 */
VOID
EventInjectUndefinedOpcode(VIRTUAL_MACHINE_STATE* VCpu);


/**
* @brief Clearing Vmcs status using vmclear instruction
*
* @param VCpu
* @return BOOLEAN If vmclear execution was successful it returns true
* otherwise and if there was error with vmclear then it returns false
*/
_Use_decl_annotations_
BOOLEAN
VmxClearVmcsState(VIRTUAL_MACHINE_STATE* VCpu);


/**
* @brief Implementation of VMPTRLD instruction
*
* @param VCpu
* @return BOOLEAN If vmptrld was unsuccessful then it returns false otherwise
* it returns false
*/
_Use_decl_annotations_
BOOLEAN
VmxLoadVmcs(VIRTUAL_MACHINE_STATE* VCpu);

/**
 * @brief Reset GDTR/IDTR and other old when you do vmxoff as the patchguard will detect them left modified
 *
 * @return VOID
 */
VOID
HvRestoreRegisters();