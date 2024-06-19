#include "VMCall.h"

NTSTATUS VMCall::Test(UINT64 Op1, UINT64 Op2, UINT64 Op3) {
	LOGINF("Test! Ops: 0x%llx, 0x%llx, 0x%llx", Op1, Op2, Op3);
	return STATUS_SUCCESS;
}

VOID VMCall::VmxOff(PVIRTUAL_MACHINE_STATE VCpu) {

    UINT64 GuestRSP = 0; // Save a pointer to guest rsp for times that we want to return to previous guest stateS
    UINT64 GuestRIP = 0; // Save a pointer to guest rip for times that we want to return to previous guest state
    UINT64 GuestCr3 = 0;
    UINT64 ExitInstructionLength = 0;

    //
    // According to SimpleVisor :
    //  	Our callback routine may have interrupted an arbitrary user process,
    //  	and therefore not a thread running with a system-wide page directory.
    //  	Therefore if we return back to the original caller after turning off
    //  	VMX, it will keep our current "host" CR3 value which we set on entry
    //  	to the PML4 of the SYSTEM process. We want to return back with the
    //  	correct value of the "guest" CR3, so that the currently executing
    //  	process continues to run with its expected address space mappings.
    //

    __vmx_vmread(VMCS_GUEST_CR3, &GuestCr3);
    __writecr3(GuestCr3);

    //
    // Read guest rsp and rip
    //
    __vmx_vmread(VMCS_GUEST_RIP, &GuestRIP);
    __vmx_vmread(VMCS_GUEST_RSP, &GuestRSP);

    //
    // Read instruction length
    //
    __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &ExitInstructionLength);
    GuestRIP += ExitInstructionLength;

    //
    // Set the previous register states
    //
    VCpu->VmxoffState.GuestRip = GuestRIP;
    VCpu->VmxoffState.GuestRsp = GuestRSP;

    //
    // Notify the Vmexit handler that VMX already turned off
    //
    VCpu->VmxoffState.IsVmxoffExecuted = TRUE;

    //
    // Restore the previous FS, GS , GDTR and IDTR register as patchguard might find the modified
    //
    HvRestoreRegisters();

    //
    // Before using vmxoff, you first need to use vmclear on any VMCSes that you want to be able to use again.
    // See sections 24.1 and 24.11 of the SDM.
    //
    VmxClearVmcsState(VCpu);

    //
    // Execute Vmxoff
    //
    __vmx_off();

    //
    // Indicate the current core is not currently virtualized
    //
    VCpu->HasLaunched = FALSE;

    //
    // Now that VMX is OFF, we have to unset vmx-enable bit on cr4
    //
    __writecr4(__readcr4() & (~X86_CR4_VMXE));

}