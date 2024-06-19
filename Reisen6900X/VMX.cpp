//
// Summary: Implementation for VMX.h
//

#include "VMX.h"

bool VMX::CheckVMXSupport() {

	CPUID cpuid = { 0, };
	IA32_FEATURE_CONTROL_REGISTER fc_register = { 0, };

	// Load CPU Instructions
	__cpuid((int*)&cpuid, 1);

	// cpuid.ecx[5] is check for VMX
	if (!_bittest((const LONG*)&cpuid.ecx, 5)) {
		return false;
	}

	fc_register.AsUInt = __readmsr(IA32_FEATURE_CONTROL);

	// check IA32 msr register for supporting VMX
	if (fc_register.EnableVmxOutsideSmx == FALSE) {
		return false;
	}

	return true;

}

STATUS VMX::InitializeVMX() {
	
	STATUS status = STAT_ERROR_UNKNOWN;

	if (PerformVirtualizationOnAllCores()) {
		LOGERR("Something went wrong");
		return status = STAT_ERROR_KNOWN;
	}

	auto ProcessorCount = KeQueryActiveProcessorCount(0);

	for (auto ProcessorID = 0; ProcessorID < ProcessorCount; ProcessorID++) {

		auto GuestState = &Global::g_GuestState[ProcessorID];

		if (AllocateVMMStack(GuestState) || AllocateIoBitmaps(GuestState) || AllocateMSRBitmap(GuestState) ) {
			return status = STAT_ERROR_KNOWN;
		}

	}

	Global::g_MsrBitmapInvalidMsrs = AllocateInvalidMSRBitmap();
	if (!Global::g_MsrBitmapInvalidMsrs) {
		LOGERR("Insufficient memory while allocating Invalid MSR Bitmap");
		return status = STAT_ERROR_KNOWN;
	}

	KeGenericCallDpc(DpcRoutineInitializeGuest, 0);

	//DbgBreakPoint();

	if (AsmVmxVmcall(VMCALL_TEST, 0x6974, 0xDEAD, 0x523) == STATUS_SUCCESS) {
		return status = STAT_SUCCESS;
	}
	else {
		LOGERR("Some function just got jerked");
		return status = STAT_ERROR_UNKNOWN;
	}

}

STATUS VMX::PerformVirtualizationOnAllCores() {

	PAGED_CODE();

	STATUS status = STAT_ERROR_UNKNOWN;

	// Check computer VMX support
	if (!CheckVMXSupport()) {
		LOGERR("Your computer does not supports VMX.");
		return status = STAT_ERROR_KNOWN;
	}

	
	// Allocate "global" ept state.
	EPT::g_EptState = (PEPT_STATE)AllocateZeroedNonPagedPool(sizeof(EPT_STATE));

	if (!EPT::g_EptState) {
		LOGERR("Failed allocating Ept State Pointer");
		return status = STAT_ERROR_KNOWN;
	}
	
	// Initialize the hook details pointer
	InitializeListHead(&EPT::g_EptState->HookedPagesList);

	LOGINF("Checking EPT support for computer...");

	// Check EPT supports for computer
	if (!EPT::CheckEPTSupport()) {
		LOGERR("EPT supports are down in this computer");
		return status = STAT_ERROR_KNOWN;
	}

	LOGINF("Building MTRR Map...");

	// Build MTRR Map
	if (!EPT::BuildMTRRMap()) {
		LOGERR("Failed to build MTRR map");
		return status = STAT_ERROR_KNOWN;
	}
	
	LOGINF("Initializing EPT...");

	// Initialize EPT
	if (EPT::EPTLogicalProcessorInit()) {
		LOGERR("Failed to initialize EPT");
		return status = STAT_ERROR_KNOWN;
	}
	
	// Perform Virtualization on 'individual' cores
	KeGenericCallDpc((PKDEFERRED_ROUTINE)DpcRoutinePerformVirtualization, NULL);
	
	return status = STAT_SUCCESS;

}

BOOLEAN VMX::DpcRoutinePerformVirtualization(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	//
	// Allocates Vmx regions for all logical cores (Vmxon region and Vmcs region)
	//
	PerformVirtualizationOnSpecificCore();

	//
	// Wait for all DPCs to synchronize at this point
	//
	KeSignalCallDpcSynchronize(SystemArgument2);

	//
	// Mark the DPC as being complete
	//
	KeSignalCallDpcDone(SystemArgument1);

	return TRUE;
}

STATUS VMX::PerformVirtualizationOnSpecificCore() {

	STATUS status = STAT_ERROR_UNKNOWN;

	ULONG                   CurrentCore = KeGetCurrentProcessorNumberEx(NULL);
	VIRTUAL_MACHINE_STATE* VCpu = &Global::g_GuestState[CurrentCore];

	LOG("==================== Virtualization (%u) ====================", CurrentCore);

	LOGINF("Enabling VMX..");
	
	//
	// Set 14th bit of cr4, which means enabling VMX extension
	//
	AsmEnableVmxOperation();

	//
	// Set CR4, CR0 fixed bits.
	//
	VmxFixCr4AndCr0Bits();

	LOGINF("VMX-Operation is successfully enabled");

	if (AllocateVMXONRegion(VCpu)) {
		LOGINF("Failed to setup VMXON Region");
		return status = STAT_ERROR_KNOWN;
	}

	if (AllocateVMCSRegion(VCpu)) {
		LOGINF("Failed to setup VMCS Region");
		return status = STAT_ERROR_KNOWN;
	}

	LOGINF("All ok setting up regions! (and vmxon)");
	return status = STAT_SUCCESS;
}

VOID VMX::VmxFixCr4AndCr0Bits() {

	CR_FIXED CrFixed = { 0 };
	CR4      Cr4 = { 0 };
	CR0      Cr0 = { 0 };

	//
	// Fix Cr0
	//
	CrFixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
	Cr0.AsUInt = __readcr0();
	Cr0.AsUInt |= CrFixed.Fields.Low;
	CrFixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
	Cr0.AsUInt &= CrFixed.Fields.Low;
	__writecr0(Cr0.AsUInt);

	//
	// Fix Cr4
	//
	CrFixed.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
	Cr4.AsUInt = __readcr4();
	Cr4.AsUInt |= CrFixed.Fields.Low;
	CrFixed.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
	Cr4.AsUInt &= CrFixed.Fields.Low;
	__writecr4(Cr4.AsUInt);

}

STATUS VMX::AllocateVMCSRegion(PVIRTUAL_MACHINE_STATE Vcpu) {

	STATUS status = STAT_ERROR_UNKNOWN;

	IA32_VMX_BASIC_REGISTER VmxBasicMsr = { 0 };
	SIZE_T                  VmcsSize;
	UINT8* VmcsRegion;
	UINT64                  VmcsPhysicalAddr;
	UINT64                  AlignedVmcsRegion;
	UINT64                  AlignedVmcsRegionPhysicalAddr;

#ifdef ENV_WINDOWS
	//
	// at IRQL > DISPATCH_LEVEL memory allocation routines don't work
	//
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();
#endif // ENV_WINDOWS

	VmcsSize = 2 * VMCS_SIZE;
	VmcsRegion = (UINT8*)AllocateContiguousZeroedMemory(VmcsSize + ALIGNMENT_PAGE_SIZE);
	if (VmcsRegion == NULL)
	{
		LOGERR("Err, couldn't allocate Buffer for VMCS region");
		return status = STAT_ERROR_KNOWN;
	}

	VmcsPhysicalAddr = VirtualAddressToPhysicalAddress(VmcsRegion);

	AlignedVmcsRegion = (UINT64)((ULONG_PTR)(VmcsRegion + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
	LOGINF("VMCS region address : %llx", AlignedVmcsRegion);

	AlignedVmcsRegionPhysicalAddr = (UINT64)((ULONG_PTR)(VmcsPhysicalAddr + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
	LOGINF("VMCS region physical address : %llx", AlignedVmcsRegionPhysicalAddr);

	// We need Revision ID for first 8 bytes of Vmcs-type Region

	VmxBasicMsr.AsUInt = __readmsr(IA32_VMX_BASIC);
	LOGINF("Revision Identifier (IA32_VMX_BASIC - MSR 0x480) : 0x%x", VmxBasicMsr.VmcsRevisionId);
	*(UINT64*)AlignedVmcsRegion = VmxBasicMsr.VmcsRevisionId;

	Vcpu->VmcsRegionPhysicalAddress = AlignedVmcsRegionPhysicalAddr;
	//
	// We save the allocated buffer (not the aligned buffer)
	// because we want to free it in vmx termination
	//
	Vcpu->VmcsRegionVirtualAddress = (UINT64)VmcsRegion;

	return status = STAT_SUCCESS;
}

STATUS VMX::AllocateVMXONRegion(PVIRTUAL_MACHINE_STATE Vcpu) {

	STATUS status = STAT_ERROR_UNKNOWN;

	IA32_VMX_BASIC_REGISTER VmxBasicMsr = { 0 };
	SIZE_T                  VmxonSize;
	UINT8                   VmxonStatus;
	UINT8* VmxonRegion;
	UINT64                  VmxonRegionPhysicalAddr;
	UINT64                  AlignedVmxonRegion;
	UINT64                  AlignedVmxonRegionPhysicalAddr;

#ifdef ENV_WINDOWS
	//
	// at IRQL > DISPATCH_LEVEL memory allocation routines don't work
	//
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();
#endif // ENV_WINDOWS

	VmxonSize = 2 * VMXON_SIZE;
	VmxonRegion = (UINT8*)AllocateContiguousZeroedMemory(VmxonSize + ALIGNMENT_PAGE_SIZE);
	if (VmxonRegion == NULL)
	{
		LOGERR("Err, couldn't allocate buffer for VMXON region");
		return status = STAT_ERROR_KNOWN;
	}

	VmxonRegionPhysicalAddr = VirtualAddressToPhysicalAddress(VmxonRegion);

	AlignedVmxonRegion = (UINT64)((ULONG_PTR)(VmxonRegion + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

	LOGINF("VMXON Region Address : %llx", AlignedVmxonRegion);

	AlignedVmxonRegionPhysicalAddr = (UINT64)((ULONG_PTR)(VmxonRegionPhysicalAddr + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

	LOGINF("VMXON Region Physical Address : %llx", AlignedVmxonRegionPhysicalAddr);

	// We need Revision ID for first 8 bytes of Vmcs-type Region

	VmxBasicMsr.AsUInt = __readmsr(IA32_VMX_BASIC);
	LOGINF("Revision Identifier (IA32_VMX_BASIC - MSR 0x480) : 0x%x", VmxBasicMsr.VmcsRevisionId);
	*(UINT64*)AlignedVmxonRegion = VmxBasicMsr.VmcsRevisionId;

	VmxonStatus = __vmx_on(&AlignedVmxonRegionPhysicalAddr);
	if (VmxonStatus)
	{
		LOGERR("Err, executing vmxon instruction failed with status : %d", VmxonStatus);
		return status = STAT_ERROR_KNOWN;
	}

	Vcpu->VmxonRegionPhysicalAddress = AlignedVmxonRegionPhysicalAddr;

	//
	// We save the allocated buffer (not the aligned buffer) because we want to free it in vmx termination
	//
	Vcpu->VmxonRegionVirtualAddress = (UINT64)VmxonRegion;

	return status = STAT_SUCCESS;
}

STATUS VMX::AllocateVMMStack(PVIRTUAL_MACHINE_STATE Vcpu) {
	
	STATUS status = STAT_ERROR_UNKNOWN;

	//
	// Allocate stack for the Host CPU
	//
	Vcpu->VmmStack = (UINT64)AllocateZeroedNonPagedPool(VMM_STACK_SIZE);

	if (!Vcpu->VmmStack) {
		LOGERR("Insufficient Memory for allocating VMM Stack");
		return status = STAT_ERROR_KNOWN;
	}

	LOGINF("VMM Stack for logical processor : 0x%llx", Vcpu->VmmStack);
	return status = STAT_SUCCESS;

}

STATUS VMX::AllocateMSRBitmap(PVIRTUAL_MACHINE_STATE Vcpu) {

	STATUS status = STAT_ERROR_UNKNOWN;

	//
	// Allocate memory for MSR Bitmap
	// Should be aligned
	//
	Vcpu->MsrBitmapVirtualAddress = (UINT64)AllocateZeroedNonPagedPool(PAGE_SIZE);

	if (!Vcpu->MsrBitmapVirtualAddress)
	{
		LOGERR("Insufficient memory in allocating MSR Bitmaps");
		return status = STAT_ERROR_KNOWN;
	}

	Vcpu->MsrBitmapPhysicalAddress = VirtualAddressToPhysicalAddress((PVOID)Vcpu->MsrBitmapVirtualAddress);

	LOGINF("MSR Bitmap virtual address  : 0x%llx", Vcpu->MsrBitmapVirtualAddress);
	LOGINF("MSR Bitmap physical address : 0x%llx", Vcpu->MsrBitmapPhysicalAddress);

	return status = STAT_SUCCESS;

}

STATUS VMX::AllocateIoBitmaps(PVIRTUAL_MACHINE_STATE Vcpu) {

	STATUS status = STAT_ERROR_UNKNOWN;

	//
	// Allocate memory for I/O Bitmap (A)
	//
	Vcpu->IoBitmapVirtualAddressA = (UINT64)AllocateZeroedNonPagedPool(PAGE_SIZE); // should be aligned

	if (!Vcpu->IoBitmapVirtualAddressA)
	{
		LOGERR("Insufficient memory in allocating I/O Bitmaps A");
		return status = STAT_ERROR_KNOWN;
	}

	Vcpu->IoBitmapPhysicalAddressA = VirtualAddressToPhysicalAddress((PVOID)Vcpu->IoBitmapVirtualAddressA);

	LOGINF("I/O Bitmap A Virtual Address  : 0x%llx", Vcpu->IoBitmapVirtualAddressA);
	LOGINF("I/O Bitmap A Physical Address : 0x%llx", Vcpu->IoBitmapPhysicalAddressA);

	//
	// Allocate memory for I/O Bitmap (B)
	//
	Vcpu->IoBitmapVirtualAddressB = (UINT64)AllocateZeroedNonPagedPool(PAGE_SIZE); // should be aligned

	if (!Vcpu->IoBitmapVirtualAddressB)
	{
		LOGERR("Insufficient memory in allocating I/O Bitmaps B");
		return status = STAT_ERROR_KNOWN;
	}

	Vcpu->IoBitmapPhysicalAddressB = VirtualAddressToPhysicalAddress((PVOID)Vcpu->IoBitmapVirtualAddressB);

	LOGINF("I/O Bitmap B virtual address  : 0x%llx", Vcpu->IoBitmapVirtualAddressB);
	LOGINF("I/O Bitmap B physical address : 0x%llx", Vcpu->IoBitmapPhysicalAddressB);

	return status = STAT_SUCCESS;
}

PVOID VMX::AllocateInvalidMSRBitmap() {

	PVOID InvalidMsrBitmap;

	InvalidMsrBitmap = AllocateZeroedNonPagedPool(0x1000 / 0x8);

	if (InvalidMsrBitmap == NULL)
	{
		return NULL;
	}

	for (UINT32 i = 0; i < 0x1000; ++i)
	{
		// Let's test MSR's and censor GP's unless we get unexpected BSOD lol
		__try
		{
			__readmsr(i);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			SetBit(i, (unsigned long*)InvalidMsrBitmap);
		}
	}

	return InvalidMsrBitmap;
}

VOID VMX::DpcRoutineInitializeGuest(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	//
	// Save the vmx state and prepare vmcs setup and finally execute vmlaunch instruction
	//
	AsmVmxSaveState();

	//
	// Wait for all DPCs to synchronize at this point
	//
	KeSignalCallDpcSynchronize(SystemArgument2);

	//
	// Mark the DPC as being complete
	//
	KeSignalCallDpcDone(SystemArgument1);
}

VOID VMX::DpcRoutineTerminateGuest(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	//
	// Terminate Vmx using vmcall
	//
	if (!VmxTerminate())
	{
		LOGERR("Err, there were an error terminating vmx");
	}

	//
	// Wait for all DPCs to synchronize at this point
	//
	KeSignalCallDpcSynchronize(SystemArgument2);

	//
	// Mark the DPC as being complete
	//
	KeSignalCallDpcDone(SystemArgument1);
}

BOOLEAN VMX::VirtualizeCurrentSystem(PVOID GuestStack) {

	UINT64                  ErrorCode = 0;
	ULONG                   CurrentCore = KeGetCurrentProcessorNumberEx(NULL);
	VIRTUAL_MACHINE_STATE* VCpu = &Global::g_GuestState[CurrentCore];

	LOGINF("Virtualizing current system (logical core : 0x%x)", CurrentCore);

	//
	// Clear the VMCS State
	//
	if (!VmxClearVmcsState(VCpu))
	{
		LOGINF("Err, failed to clear vmcs");
		return FALSE;
	}

	//
	// Load VMCS (Set the Current VMCS)
	//
	if (!VmxLoadVmcs(VCpu))
	{
		LOGINF("Err, failed to load vmcs");
		return FALSE;
	}

	LOGINF("Setting up VMCS for current logical core");

	VmxSetupVmcs(VCpu, GuestStack);

	LOGINF("Executing VMLAUNCH on logical core %d", CurrentCore);

	VCpu->HasLaunched = TRUE;
	__vmx_vmlaunch();

	//
	// ******** if Vmlaunch succeed will never be here ! ********
	//

	VCpu->HasLaunched = FALSE;

	//
	// Read error code firstly
	//
	__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &ErrorCode);

	LOGERR("Err, unable to execute VMLAUNCH, status : 0x%llx", ErrorCode);

	//
	// Then Execute Vmxoff
	//
	__vmx_off();
	LOGERR("Err, VMXOFF Executed Successfully but it was because of an error");

	return FALSE;
}

_Use_decl_annotations_
BOOLEAN
VMX::VmxSetupVmcs(VIRTUAL_MACHINE_STATE* VCpu, PVOID GuestStack) {

	UINT32                  CpuBasedVmExecControls;
	UINT32                  SecondaryProcBasedVmExecControls;
	PVOID                   HostRsp;
	UINT64                  GdtBase = 0;
	VMX_SEGMENT_SELECTOR    SegmentSelector = { 0 };
	IA32_VMX_BASIC_REGISTER VmxBasicMsr = { 0 };

	//
	// Reading IA32_VMX_BASIC_MSR
	//
	VmxBasicMsr.AsUInt = __readmsr(IA32_VMX_BASIC);

	VmxVmwrite64(VMCS_HOST_ES_SELECTOR, AsmGetEs() & 0xF8);
	VmxVmwrite64(VMCS_HOST_CS_SELECTOR, AsmGetCs() & 0xF8);
	VmxVmwrite64(VMCS_HOST_SS_SELECTOR, AsmGetSs() & 0xF8);
	VmxVmwrite64(VMCS_HOST_DS_SELECTOR, AsmGetDs() & 0xF8);
	VmxVmwrite64(VMCS_HOST_FS_SELECTOR, AsmGetFs() & 0xF8);
	VmxVmwrite64(VMCS_HOST_GS_SELECTOR, AsmGetGs() & 0xF8);
	VmxVmwrite64(VMCS_HOST_TR_SELECTOR, AsmGetTr() & 0xF8);

	//
	// Setting the link pointer to the required value for 4KB VMCS
	//
	VmxVmwrite64(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL);

	VmxVmwrite64(VMCS_GUEST_DEBUGCTL, __readmsr(IA32_DEBUGCTL) & 0xFFFFFFFF);
	VmxVmwrite64(VMCS_GUEST_DEBUGCTL_HIGH, __readmsr(IA32_DEBUGCTL) >> 32);

	//
	// ******* Time-stamp counter offset *******
	//
	VmxVmwrite64(VMCS_CTRL_TSC_OFFSET, 0);

	VmxVmwrite64(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
	VmxVmwrite64(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);

	VmxVmwrite64(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
	VmxVmwrite64(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);

	VmxVmwrite64(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
	VmxVmwrite64(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);

	GdtBase = AsmGetGdtBase();

	HvFillGuestSelectorData((PVOID)GdtBase, ES, AsmGetEs());
	HvFillGuestSelectorData((PVOID)GdtBase, CS, AsmGetCs());
	HvFillGuestSelectorData((PVOID)GdtBase, SS, AsmGetSs());
	HvFillGuestSelectorData((PVOID)GdtBase, DS, AsmGetDs());
	HvFillGuestSelectorData((PVOID)GdtBase, FS, AsmGetFs());
	HvFillGuestSelectorData((PVOID)GdtBase, GS, AsmGetGs());
	HvFillGuestSelectorData((PVOID)GdtBase, LDTR, AsmGetLdtr());
	HvFillGuestSelectorData((PVOID)GdtBase, TR, AsmGetTr());

	VmxVmwrite64(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
	VmxVmwrite64(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));
	
	CpuBasedVmExecControls = HvAdjustControls(CPU_BASED_ACTIVATE_IO_BITMAP | CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
		VmxBasicMsr.VmxControls ? IA32_VMX_TRUE_PROCBASED_CTLS : IA32_VMX_PROCBASED_CTLS);

	VmxVmwrite64(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, CpuBasedVmExecControls);

	LOGINF("CPU Based VM Exec Controls (Based on %s) : 0x%x",
		VmxBasicMsr.VmxControls ? "IA32_VMX_TRUE_PROCBASED_CTLS" : "IA32_VMX_PROCBASED_CTLS",
		CpuBasedVmExecControls);

	SecondaryProcBasedVmExecControls = HvAdjustControls(CPU_BASED_CTL2_RDTSCP | CPU_BASED_CTL2_ENABLE_EPT | CPU_BASED_CTL2_ENABLE_INVPCID | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS | CPU_BASED_CTL2_ENABLE_VPID,
		IA32_VMX_PROCBASED_CTLS2);

	VmxVmwrite64(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, SecondaryProcBasedVmExecControls);

	LOGINF("Secondary Proc Based VM Exec Controls (IA32_VMX_PROCBASED_CTLS2) : 0x%x", SecondaryProcBasedVmExecControls);

	VmxVmwrite64(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, HvAdjustControls(0, VmxBasicMsr.VmxControls ? IA32_VMX_TRUE_PINBASED_CTLS : IA32_VMX_PINBASED_CTLS));

	VmxVmwrite64(VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS, HvAdjustControls(VM_EXIT_HOST_ADDR_SPACE_SIZE, VmxBasicMsr.VmxControls ? IA32_VMX_TRUE_EXIT_CTLS : IA32_VMX_EXIT_CTLS));

	VmxVmwrite64(VMCS_CTRL_VMENTRY_CONTROLS, HvAdjustControls(VM_ENTRY_IA32E_MODE, VmxBasicMsr.VmxControls ? IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS));

	VmxVmwrite64(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
	VmxVmwrite64(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);

	VmxVmwrite64(VMCS_CTRL_CR0_READ_SHADOW, 0);
	VmxVmwrite64(VMCS_CTRL_CR4_READ_SHADOW, 0);

	VmxVmwrite64(VMCS_GUEST_CR0, __readcr0());
	VmxVmwrite64(VMCS_GUEST_CR3, __readcr3());
	VmxVmwrite64(VMCS_GUEST_CR4, __readcr4());

	VmxVmwrite64(VMCS_GUEST_DR7, 0x400);

	VmxVmwrite64(VMCS_HOST_CR0, __readcr0());
	VmxVmwrite64(VMCS_HOST_CR4, __readcr4());

	//
	// Because we may be executing in an arbitrary user-mode, process as part
	// of the DPC interrupt we execute in We have to save Cr3, for VMCS_HOST_CR3
	//

	VmxVmwrite64(VMCS_HOST_CR3, LayoutGetSystemDirectoryTableBase());

	VmxVmwrite64(VMCS_GUEST_GDTR_BASE, AsmGetGdtBase());
	VmxVmwrite64(VMCS_GUEST_IDTR_BASE, AsmGetIdtBase());

	VmxVmwrite64(VMCS_GUEST_GDTR_LIMIT, AsmGetGdtLimit());
	VmxVmwrite64(VMCS_GUEST_IDTR_LIMIT, AsmGetIdtLimit());

	VmxVmwrite64(VMCS_GUEST_RFLAGS, AsmGetRflags());

	VmxVmwrite64(VMCS_GUEST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
	VmxVmwrite64(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
	VmxVmwrite64(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

	VmxGetSegmentDescriptor((PUCHAR)AsmGetGdtBase(), AsmGetTr(), &SegmentSelector);
	VmxVmwrite64(VMCS_HOST_TR_BASE, SegmentSelector.Base);

	VmxVmwrite64(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
	VmxVmwrite64(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));

	VmxVmwrite64(VMCS_HOST_GDTR_BASE, AsmGetGdtBase());
	VmxVmwrite64(VMCS_HOST_IDTR_BASE, AsmGetIdtBase());

	VmxVmwrite64(VMCS_HOST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
	VmxVmwrite64(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
	VmxVmwrite64(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

	//
	// Set MSR Bitmaps
	//
	VmxVmwrite64(VMCS_CTRL_MSR_BITMAP_ADDRESS, VCpu->MsrBitmapPhysicalAddress);

	//
	// Set I/O Bitmaps
	//
	VmxVmwrite64(VMCS_CTRL_IO_BITMAP_A_ADDRESS, VCpu->IoBitmapPhysicalAddressA);
	VmxVmwrite64(VMCS_CTRL_IO_BITMAP_B_ADDRESS, VCpu->IoBitmapPhysicalAddressB);

	//
	// Set up EPT
	//
	VmxVmwrite64(VMCS_CTRL_EPT_POINTER, VCpu->EptPointer.AsUInt);

	//
	// Set up VPID

	//
	// For all processors, we will use a VPID = 1. This allows the processor to separate caching
	//  of EPT structures away from the regular OS page translation tables in the TLB.
	//
	VmxVmwrite64(VIRTUAL_PROCESSOR_ID, VPID_TAG);

	//
	// setup guest rsp
	//
	VmxVmwrite64(VMCS_GUEST_RSP, (UINT64)GuestStack);

	//
	// setup guest rip
	//
	VmxVmwrite64(VMCS_GUEST_RIP, (UINT64)AsmVmxRestoreState);

	//
	// Stack should be aligned to 16 because we wanna save XMM and FPU registers and those instructions
	// needs alignment to 16
	//
	HostRsp = (PVOID)((UINT64)VCpu->VmmStack + VMM_STACK_SIZE - 1);
	HostRsp = ((PVOID)((ULONG_PTR)(HostRsp) & ~(16 - 1)));
	VmxVmwrite64(VMCS_HOST_RSP, (UINT64)HostRsp);
	VmxVmwrite64(VMCS_HOST_RIP, (UINT64)AsmVmexitHandler);

	return TRUE;

}

VOID
VMX::HvFillGuestSelectorData(PVOID GdtBase, UINT32 SegmentRegister, UINT16 Selector)
{
	VMX_SEGMENT_SELECTOR SegmentSelector = { 0 };

	VmxGetSegmentDescriptor((PUCHAR)GdtBase, Selector, &SegmentSelector);

	if (Selector == 0x0)
	{
		SegmentSelector.Attributes.Unusable = TRUE;
	}

	SegmentSelector.Attributes.Reserved1 = 0;
	SegmentSelector.Attributes.Reserved2 = 0;

	VmxVmwrite64(VMCS_GUEST_ES_SELECTOR + SegmentRegister * 2, Selector);
	VmxVmwrite64(VMCS_GUEST_ES_LIMIT + SegmentRegister * 2, SegmentSelector.Limit);
	VmxVmwrite64(VMCS_GUEST_ES_ACCESS_RIGHTS + SegmentRegister * 2, SegmentSelector.Attributes.AsUInt);
	VmxVmwrite64(VMCS_GUEST_ES_BASE + SegmentRegister * 2, SegmentSelector.Base);
}

_Use_decl_annotations_
BOOLEAN
VMX::VmxGetSegmentDescriptor(PUCHAR GdtBase, UINT16 Selector, PVMX_SEGMENT_SELECTOR SegmentSelector) {

	SEGMENT_DESCRIPTOR_32* DescriptorTable32;
	SEGMENT_DESCRIPTOR_32* Descriptor32;
	SEGMENT_SELECTOR        SegSelector = { .AsUInt = Selector };

	if (!SegmentSelector)
		return FALSE;

#define SELECTOR_TABLE_LDT 0x1
#define SELECTOR_TABLE_GDT 0x0

	//
	// Ignore LDT
	//
	if ((Selector == 0x0) || (SegSelector.Table != SELECTOR_TABLE_GDT))
	{
		return FALSE;
	}

	DescriptorTable32 = (SEGMENT_DESCRIPTOR_32*)(GdtBase);
	Descriptor32 = &DescriptorTable32[SegSelector.Index];

	SegmentSelector->Selector = Selector;
	SegmentSelector->Limit = __segmentlimit(Selector);
	SegmentSelector->Base = ((UINT64)Descriptor32->BaseAddressLow | (UINT64)Descriptor32->BaseAddressMiddle << 16 | (UINT64)Descriptor32->BaseAddressHigh << 24);

	SegmentSelector->Attributes.AsUInt = (AsmGetAccessRights(Selector) >> 8);

	if (SegSelector.Table == 0 && SegSelector.Index == 0)
	{
		SegmentSelector->Attributes.Unusable = TRUE;
	}

	if ((Descriptor32->Type == SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY) || (Descriptor32->Type == SEGMENT_DESCRIPTOR_TYPE_CALL_GATE))
	{
		//
		// this is a TSS or callgate etc, save the base high part
		//

		UINT64 SegmentLimitHigh;
		SegmentLimitHigh = (*(UINT64*)((PUCHAR)Descriptor32 + 8));
		SegmentSelector->Base = (SegmentSelector->Base & 0xffffffff) | (SegmentLimitHigh << 32);
	}

	if (SegmentSelector->Attributes.Granularity)
	{
		//
		// 4096-bit granularity is enabled for this segment, scale the limit
		//
		SegmentSelector->Limit = (SegmentSelector->Limit << 12) + 0xfff;
	}

	return TRUE;

}

UINT32
VMX::HvAdjustControls(UINT32 Ctl, UINT32 Msr)
{
	MSR MsrValue = { 0 };

	MsrValue.Flags = __readmsr(Msr);
	Ctl &= MsrValue.Fields.High; /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.Fields.Low;  /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}

UINT64
VMX::LayoutGetSystemDirectoryTableBase()
{
	//
	// Return CR3 of the system process.
	//
	NT_KPROCESS* SystemProcess = (NT_KPROCESS*)(PsInitialSystemProcess);
	return SystemProcess->DirectoryTableBase;
}

VOID VMX::Vmresume() {

	UINT64 ErrorCode = 0;

	__vmx_vmresume();

	//
	// if VMRESUME succeed will never be here !
	//

	__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &ErrorCode);
	__vmx_off();

	//
	// It's such a bad error because we don't where to go !
	// prefer to break
	//
	LOGERR("Err,  in executing VMRESUME , status : 0x%llx", ErrorCode);

}

UINT64 VMX::ReturnStackPointerForVmxoff() {
	return Global::g_GuestState[KeGetCurrentProcessorNumberEx(NULL)].VmxoffState.GuestRsp;
}

UINT64 VMX::ReturnInstructionPointerForVmxoff() {
	return Global::g_GuestState[KeGetCurrentProcessorNumberEx(NULL)].VmxoffState.GuestRip;
}

BOOLEAN
VMX::VmexitHandler(PGUEST_REGS GuestRegs) {

	//DbgBreakPoint();

	UINT32                  ExitReason = 0;
	BOOLEAN                 Result = FALSE;
	BOOLEAN                 ShouldEmulateRdtscp = TRUE;
	VIRTUAL_MACHINE_STATE* VCpu = NULL;

	VCpu = &Global::g_GuestState[KeGetCurrentProcessorNumberEx(NULL)];
	VCpu->Regs = GuestRegs;
	VCpu->IsOnVmxRootMode = TRUE;

	ExitReason = VmxVmRead32(VMCS_EXIT_REASON);
	ExitReason &= 0xffff;

	VCpu->IncrementRip = TRUE;

	//
	// Save the current rip
	//
	__vmx_vmread(VMCS_GUEST_RIP, &VCpu->LastVmexitRip);

	//
	// Set the rsp in general purpose registers structure
	//
	__vmx_vmread(VMCS_GUEST_RSP, &VCpu->Regs->rsp);

	//
	// Read the exit qualification
	//
	VCpu->ExitQualification = VmxVmRead32(VMCS_EXIT_QUALIFICATION);

	//
	// Debugging purpose
	//
	//LOGINF("VM_EXIT_REASON : 0x%x", ExitReason);
	//LOGINF("VMCS_EXIT_QUALIFICATION : 0x%llx", VCpu->ExitQualification);

	//
	// 
	// -=-=-=-=-= VMEXIT HANDLING =-=-=-=-=-

	switch (ExitReason) {

	case VMX_EXIT_REASON_EXECUTE_RDMSR: {

		auto HandleResult = VMExitHandler::HandleRDMSR(VCpu);

		if (HandleResult == FALSE) return Result = FALSE;

		break;
	}

	case VMX_EXIT_REASON_EXECUTE_WRMSR: {
		
		auto HandleResult = VMExitHandler::HandleWRMSR(VCpu);

		if (HandleResult == FALSE) return Result = FALSE;

		break;
	}
	
	case VMX_EXIT_REASON_EXECUTE_VMCALL: {

		BOOLEAN      IsMyVmcall = FALSE;
		GUEST_REGS* GuestRegs = VCpu->Regs;

		//DbgBreakPoint();

		IsMyVmcall = (GuestRegs->r10 == 0x48564653 && GuestRegs->r11 == 0x564d43414c4c && GuestRegs->r12 == 0x4e4f485950455256);
		//
		// Check if it's our routines that request the VMCALL, or it relates to the Hyper-V
		//
		if (IsMyVmcall)
		{
			GuestRegs->rax = VMExitHandler::HandleVMCall(VCpu,
				GuestRegs->rcx,
				GuestRegs->rdx,
				GuestRegs->r8,
				GuestRegs->r9);
		}
		else
		{
			// We do not support Hyper-V
			LOGINF("We do not support Hyper-V");
			__halt();
		}

		break;
	}

	case VMX_EXIT_REASON_EXECUTE_CPUID: {

		VMExitHandler::HandleCPUID(VCpu);

		break;
	}

	}

	// -=-=-=-=-= VMEXIT HANDLING =-=-=-=-=-
	//
	//

	//
	// Check whether we need to increment the guest's ip or not
	// Also, we should not increment rip if a vmxoff executed
	//
	if (!VCpu->VmxoffState.IsVmxoffExecuted && VCpu->IncrementRip)
	{
		HvResumeToNextInstruction();
	}

	//
	// Check for vmxoff request
	//
	if (VCpu->VmxoffState.IsVmxoffExecuted)
	{
		Result = TRUE;
	}

	VCpu->IsOnVmxRootMode = FALSE;
	
	return Result; // TODO: Make VMXOFF working, currently crashing with double fault
}

VOID
VMX::HvResumeToNextInstruction()
{
	UINT64 ResumeRIP = 0;
	UINT64 CurrentRIP = 0;
	size_t ExitInstructionLength = 0;

	__vmx_vmread(VMCS_GUEST_RIP, &CurrentRIP);
	__vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &ExitInstructionLength);

	ResumeRIP = CurrentRIP + ExitInstructionLength;

	//LOGINF("Current RIP: %llx, Instruction Length: %llx, Resume RIP: %llx\n", CurrentRIP, ExitInstructionLength, ResumeRIP);
	//DbgBreakPoint();

	VmxVmwrite64(VMCS_GUEST_RIP, ResumeRIP);
}

/*
Assembly Wrappers Start
*/

extern "C" BOOLEAN VmxVirtualizeCurrentSystem(PVOID GuestStack) {
	return VMX::VirtualizeCurrentSystem(GuestStack);
}

extern "C" BOOLEAN VmxVmexitHandler(PGUEST_REGS GuestRegs) {
	return VMX::VmexitHandler(GuestRegs);
}

extern "C" UINT64 VmxReturnStackPointerForVmxoff() {
	return VMX::ReturnStackPointerForVmxoff();
}

extern "C" UINT64 VmxReturnInstructionPointerForVmxoff() {
	return VMX::ReturnInstructionPointerForVmxoff();
}

extern "C" VOID VmxVmresume() {
	return VMX::Vmresume();
}

/*
Assembly Wrappers End
*/

VOID VMX::VmxPerformTermination() {

	ULONG ProcessorsCount;

	LOGINF("Terminating VMX...\n");

	//
	// Get number of processors
	//
	ProcessorsCount = KeQueryActiveProcessorCount(0);

	//
	// ******* Terminating Vmx *******
	//

	//
	// Broadcast to terminate Vmx
	//
	KeGenericCallDpc(DpcRoutineTerminateGuest, 0x0);

	//
	// ****** De-allocatee global variables ******
	//

	//
	// Free the buffer related to MSRs that cause #GP
	//
	FreeNonPagedPool(Global::g_MsrBitmapInvalidMsrs);
	Global::g_MsrBitmapInvalidMsrs = NULL;

	//
	// Free Identity Page Table
	//
	for (size_t i = 0; i < ProcessorsCount; i++)
	{
		if (Global::g_GuestState[i].EptPageTable != NULL)
		{
			MmFreeContiguousMemory(Global::g_GuestState[i].EptPageTable);
		}

		Global::g_GuestState[i].EptPageTable = NULL;
	}

	//
	// Free EptState
	//
	FreeNonPagedPool(EPT::g_EptState);
	EPT::g_EptState = NULL;

	//
	// Free g_GuestState
	//
	FreeNonPagedPool(Global::g_GuestState);
	Global::g_GuestState = NULL;

	LOGINF("VMX operation turned off successfully");

}

BOOLEAN VMX::VmxTerminate() {
	NTSTATUS                Status = STATUS_SUCCESS;
	ULONG                   CurrentCore = KeGetCurrentProcessorNumberEx(NULL);
	VIRTUAL_MACHINE_STATE* VCpu = &Global::g_GuestState[CurrentCore];

	//
	// Execute Vmcall to to turn off vmx from Vmx root mode
	//
	Status = AsmVmxVmcall(VMCALL_VMXOFF, 0, 0, 0);
	
	if (Status == STATUS_SUCCESS)
	{
		LOGINF("VMX terminated on logical core %d\n", CurrentCore);

		//
		// Free the destination memory
		//
		MmFreeContiguousMemory((PVOID)VCpu->VmxonRegionVirtualAddress);
		MmFreeContiguousMemory((PVOID)VCpu->VmcsRegionVirtualAddress);
		FreeNonPagedPool((PVOID)VCpu->VmmStack);
		FreeNonPagedPool((PVOID)VCpu->MsrBitmapVirtualAddress);
		FreeNonPagedPool((PVOID)VCpu->IoBitmapVirtualAddressA);
		FreeNonPagedPool((PVOID)VCpu->IoBitmapVirtualAddressB);

		return TRUE;
	}

	return FALSE;
}