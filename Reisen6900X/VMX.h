/*
* Summary: Utility for VMX
*/

#pragma once

#include "Common.h"
#include "VMExitHandler.h"

#define VMXON_SIZE 4096
#define VMCS_SIZE 4096
#define VMM_STACK_SIZE 0x8000
#define ALIGNMENT_PAGE_SIZE 4096

/**
 * @brief PIN-Based Execution
 *
 */
#define PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT        0x00000001
#define PIN_BASED_VM_EXECUTION_CONTROLS_NMI_EXITING               0x00000008
#define PIN_BASED_VM_EXECUTION_CONTROLS_VIRTUAL_NMI               0x00000020
#define PIN_BASED_VM_EXECUTION_CONTROLS_ACTIVE_VMX_TIMER          0x00000040
#define PIN_BASED_VM_EXECUTION_CONTROLS_PROCESS_POSTED_INTERRUPTS 0x00000080

 /**
  * @brief CPU-Based Controls
  *
  */
#define CPU_BASED_VIRTUAL_INTR_PENDING        0x00000004
#define CPU_BASED_USE_TSC_OFFSETTING          0x00000008
#define CPU_BASED_HLT_EXITING                 0x00000080
#define CPU_BASED_INVLPG_EXITING              0x00000200
#define CPU_BASED_MWAIT_EXITING               0x00000400
#define CPU_BASED_RDPMC_EXITING               0x00000800
#define CPU_BASED_RDTSC_EXITING               0x00001000
#define CPU_BASED_CR3_LOAD_EXITING            0x00008000
#define CPU_BASED_CR3_STORE_EXITING           0x00010000
#define CPU_BASED_CR8_LOAD_EXITING            0x00080000
#define CPU_BASED_CR8_STORE_EXITING           0x00100000
#define CPU_BASED_TPR_SHADOW                  0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING         0x00400000
#define CPU_BASED_MOV_DR_EXITING              0x00800000
#define CPU_BASED_UNCOND_IO_EXITING           0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP          0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG           0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP         0x10000000
#define CPU_BASED_MONITOR_EXITING             0x20000000
#define CPU_BASED_PAUSE_EXITING               0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS 0x80000000

  /**
   * @brief Secondary CPU-Based Controls
   *
   */
#define CPU_BASED_CTL2_ENABLE_EPT                 0x2
#define CPU_BASED_CTL2_RDTSCP                     0x8
#define CPU_BASED_CTL2_ENABLE_VPID                0x20
#define CPU_BASED_CTL2_UNRESTRICTED_GUEST         0x80
#define CPU_BASED_CTL2_VIRTUAL_INTERRUPT_DELIVERY 0x200
#define CPU_BASED_CTL2_ENABLE_INVPCID             0x1000
#define CPU_BASED_CTL2_ENABLE_VMFUNC              0x2000
#define CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS       0x100000

   /**
	* @brief VM-exit Control Bits
	*
	*/
#define VM_EXIT_SAVE_DEBUG_CONTROLS        0x00000004
#define VM_EXIT_HOST_ADDR_SPACE_SIZE       0x00000200
#define VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL 0x00001000
#define VM_EXIT_ACK_INTR_ON_EXIT           0x00008000
#define VM_EXIT_SAVE_IA32_PAT              0x00040000
#define VM_EXIT_LOAD_IA32_PAT              0x00080000
#define VM_EXIT_SAVE_IA32_EFER             0x00100000
#define VM_EXIT_LOAD_IA32_EFER             0x00200000
#define VM_EXIT_SAVE_VMX_PREEMPTION_TIMER  0x00400000

	/**
	 * @brief VM-entry Control Bits
	 *
	 */
#define VM_ENTRY_LOAD_DEBUG_CONTROLS        0x00000004
#define VM_ENTRY_IA32E_MODE                 0x00000200
#define VM_ENTRY_SMM                        0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR         0x00000800
#define VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL 0x00002000
#define VM_ENTRY_LOAD_IA32_PAT              0x00004000
#define VM_ENTRY_LOAD_IA32_EFER             0x00008000

	 /**
	  * @brief CPUID RCX(s) - Based on Hyper-V
	  *
	  */
#define HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS 0x40000000
#define HYPERV_CPUID_INTERFACE                0x40000001
#define HYPERV_CPUID_VERSION                  0x40000002
#define HYPERV_CPUID_FEATURES                 0x40000003
#define HYPERV_CPUID_ENLIGHTMENT_INFO         0x40000004
#define HYPERV_CPUID_IMPLEMENT_LIMITS         0x40000005
#define HYPERV_HYPERVISOR_PRESENT_BIT         0x80000000
#define HYPERV_CPUID_MIN                      0x40000005
#define HYPERV_CPUID_MAX                      0x4000ffff

	  /**
	   * @brief GUEST_INTERRUPTIBILITY_INFO flags
	   *
	   */
#define GUEST_INTR_STATE_STI          0x00000001
#define GUEST_INTR_STATE_MOV_SS       0x00000002
#define GUEST_INTR_STATE_SMI          0x00000004
#define GUEST_INTR_STATE_NMI          0x00000008
#define GUEST_INTR_STATE_ENCLAVE_INTR 0x00000010

	   /**
		* @brief Interrupt shadow states
		*
		*/
#define SHADOW_INT_MOV_SS 0x01
#define SHADOW_INT_STI    0x02

typedef union
{
	struct
	{
		/**
		 * [Bits 3:0] Segment type.
		 */
		UINT32 Type : 4;

		/**
		 * [Bit 4] S - Descriptor type (0 = system; 1 = code or data).
		 */
		UINT32 DescriptorType : 1;

		/**
		 * [Bits 6:5] DPL - Descriptor privilege level.
		 */
		UINT32 DescriptorPrivilegeLevel : 2;

		/**
		 * [Bit 7] P - Segment present.
		 */
		UINT32 Present : 1;

		UINT32 Reserved1 : 4;

		/**
		 * [Bit 12] AVL - Available for use by system software.
		 */
		UINT32 AvailableBit : 1;

		/**
		 * [Bit 13] Reserved (except for CS). L - 64-bit mode active (for CS only).
		 */
		UINT32 LongMode : 1;

		/**
		 * [Bit 14] D/B - Default operation size (0 = 16-bit segment; 1 = 32-bit segment).
		 */
		UINT32 DefaultBig : 1;

		/**
		 * [Bit 15] G - Granularity.
		 */
		UINT32 Granularity : 1;
		/**
		 * [Bit 16] Segment unusable (0 = usable; 1 = unusable).
		 */
		UINT32 Unusable : 1;
		UINT32 Reserved2 : 15;
	};

	UINT32 AsUInt;
} VMX_SEGMENT_ACCESS_RIGHTS_TYPE;

/**
 * @brief Segment selector
 *
 */
typedef struct _VMX_SEGMENT_SELECTOR
{
	UINT16                         Selector;
	VMX_SEGMENT_ACCESS_RIGHTS_TYPE Attributes;
	UINT32                         Limit;
	UINT64                         Base;
} VMX_SEGMENT_SELECTOR, * PVMX_SEGMENT_SELECTOR;

/*
Assembly Start
*/

// VMX Related

extern "C" void inline AsmEnableVmxOperation();
extern "C" void AsmVmxSaveState();
extern "C" void AsmVmxRestoreState();

// VMX Utils

extern "C" BOOLEAN VmxVirtualizeCurrentSystem(PVOID GuestStack);

extern "C" BOOLEAN VmxVmexitHandler(PGUEST_REGS GuestRegs);
extern "C" UINT64 VmxReturnStackPointerForVmxoff();
extern "C" UINT64 VmxReturnInstructionPointerForVmxoff();
extern "C" VOID VmxVmresume();

/**
 * @brief Request Vmcall
 *
 * @param VmcallNumber
 * @param OptionalParam1
 * @param OptionalParam2
 * @param OptionalParam3
 * @return NTSTATUS
 */
extern "C" NTSTATUS inline AsmVmxVmcall(unsigned long long VmcallNumber,
	unsigned long long OptionalParam1,
	unsigned long long OptionalParam2,
	long long          OptionalParam3);

/*
Assembly End
*/

namespace VMX
{

	//
	// Summary: Check VMX Support for your computer.
	// Returns: 'true' if it the machine supports VMX, 'false' if not.
	//
	bool CheckVMXSupport();


	//
	// Summary: Initialize VMX.
	// Returns: STAT_SUCCESS if succeed, else for failed.
	//
	STATUS InitializeVMX();


	//
	// Summary: Initialize essential VMX Operation tasks
	// Returns: STAT_SUCCESS if succeed, else for failed.
	//
	STATUS PerformVirtualizationOnAllCores();

	/**
	* @brief Allocates Vmx regions for all logical cores (Vmxon region and Vmcs region)
	*
	* @return STAT_SUCCESS if succeed, else for failed.
	*/
	STATUS PerformVirtualizationOnSpecificCore();

	/**
	* @brief Fix values for cr0 and cr4 bits
	* @details The Cr4 And Cr0 Bits During VMX Operation Preventing Them From Any Change
	* (https://shhoya.github.io/hv_basic.html)
	*
	* @return VOID
	*/
	VOID VmxFixCr4AndCr0Bits();

	//
	// Summary: Allocate VMXON Region
	// Returns: STAT_SUCCESS if succeed, else for failed.
	//
	STATUS AllocateVMXONRegion(PVIRTUAL_MACHINE_STATE vcpu);

	//
	// Summary: Allocate VMCS Region
	// Returns: STAT_SUCCESS if succeed, else for failed.
	//
	STATUS AllocateVMCSRegion(PVIRTUAL_MACHINE_STATE vcpu);

	//
	// Summary: Allocate VMM Stack (for Host CPU)
	// Returns: STAT_SUCCESS if succeeed, else for failed
	//
	STATUS AllocateVMMStack(PVIRTUAL_MACHINE_STATE vcpu);

	//
	// Summary: Allocate MSR Bitmap
	// Returns: STAT_SUCCESS if succeed, else for failed
	//
	STATUS AllocateMSRBitmap(PVIRTUAL_MACHINE_STATE vcpu);

	//
	// Summary: Allocate I/O Bitmaps
	// Returns: STAT_SUCCESS if succeed, else for failed
	//
	STATUS AllocateIoBitmaps(PVIRTUAL_MACHINE_STATE vcpu);

	//
	// Summary: Important; Allocate invalid MSR bitmap that causes #GP
	// Returns: Global Invalid MSR Bitmap Address
	//
	PVOID AllocateInvalidMSRBitmap();

	//
	// Summary: Virtualize Current Guest CPU
	// Returns: TRUE if succeed, else for not
	//
	BOOLEAN VirtualizeCurrentSystem(PVOID GuestStack);

	//
	// Summary: Broadcast for `PerformVirtualizationOnSpecificCore`
	//
	BOOLEAN DpcRoutinePerformVirtualization(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

	//
	// Summary: Broadcast for `AsmSaveState`, `VirtualizeCurrentSystem`, `AsmRestoreState`
	//
	VOID DpcRoutineInitializeGuest(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

	//
	// Summary: Broadcast for `VmxTerminate`
	//
	VOID DpcRoutineTerminateGuest(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

	//
	// Summary: VM Exit Handler
	// Returns: TRUE if VMX off is executed, else for not.
	//
	BOOLEAN VmexitHandler(PGUEST_REGS GuestRegs);

	/**
	 * @brief Get the RIP of guest (VMCS_GUEST_RIP) in the case of return from VMXOFF
	 *
	 * @return UINT64 Returns the stack pointer, to change in the case of Vmxoff
	 */
	UINT64
		ReturnStackPointerForVmxoff();

	/**
	 * @brief Get the RIP of guest (VMCS_GUEST_RIP) in the case of return from VMXOFF
	 *
	 * @return UINT64 Returns the instruction pointer, to change in the case of Vmxoff
	 */
	UINT64
		ReturnInstructionPointerForVmxoff();

	/**
	 * @brief Resume GUEST_RIP to next instruction
	 *
	 * @return VOID
	 */
	VOID
		HvResumeToNextInstruction();

	/**
	 * @brief Resume VM using VMRESUME instruction
	 *
	 * @return VOID
	 */
	VOID
		Vmresume();

	// Ye, it is for terminating VMX
	// It is likely 'root' function of VMX termination something
	VOID
		VmxPerformTermination();


	/**
	 * @brief Broadcast to terminate VMX on all logical cores
	 *
	 * @return BOOLEAN Returns true if vmxoff successfully executed in vmcall or otherwise
	 * returns false
	 */
	BOOLEAN 
		VmxTerminate();

	// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
	// |               VM UTILS AREA                       |
	// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

	/**
	 * @brief Create and Configure a Vmcs Layout
	 *
	 * @param VCpu
	 * @param GuestStack
	 * @return BOOLEAN
	 */
	_Use_decl_annotations_
		BOOLEAN
		VmxSetupVmcs(VIRTUAL_MACHINE_STATE* VCpu, PVOID GuestStack);

	/**
	 * @brief Fill the guest's selector data
	 *
	 * @param GdtBase
	 * @param SegmentRegister
	 * @param Selector
	 * @return VOID
	 */
	VOID
		HvFillGuestSelectorData(PVOID GdtBase, UINT32 SegmentRegister, UINT16 Selector);

	/**
	 * @brief Get Segment Descriptor
	 *
	 * @param SegmentSelector
	 * @param Selector
	 * @param GdtBase
	 * @return BOOLEAN
	 */
	_Use_decl_annotations_
		BOOLEAN
		VmxGetSegmentDescriptor(PUCHAR GdtBase, UINT16 Selector, PVMX_SEGMENT_SELECTOR SegmentSelector);

	/**
	 * @brief Adjust controls for VMCS based on processor capability
	 *
	 * @param Ctl
	 * @param Msr
	 * @return UINT32 Returns the Cpu Based and Secondary Processor Based Controls
	 *  and other controls based on hardware support
	 */
	UINT32
		HvAdjustControls(UINT32 Ctl, UINT32 Msr);

	/**
	 * @brief Find cr3 of system process
	 *
	 * @return UINT64 Returns cr3 of System process (pid=4)
	 */
	UINT64
		LayoutGetSystemDirectoryTableBase();
};

