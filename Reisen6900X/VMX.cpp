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

	return status = STAT_SUCCESS;

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