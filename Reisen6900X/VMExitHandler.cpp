#include "VMExitHandler.h"

BOOLEAN VMExitHandler::HandleRDMSR(PVIRTUAL_MACHINE_STATE VCpu) {

	BOOLEAN Result = TRUE;

	PGUEST_REGS GuestRegs = VCpu->Regs;
	MSR    Msr = { 0 };
	UINT32 TargetMsr;

	TargetMsr = GuestRegs->rcx & 0xffffffff;

	if ((TargetMsr <= 0x00001FFF) || ((0xC0000000 <= TargetMsr) && (TargetMsr <= 0xC0001FFF)) ||
		(TargetMsr >= RESERVED_MSR_RANGE_LOW && (TargetMsr <= RESERVED_MSR_RANGE_HI)))
	{
		switch (TargetMsr)
		{
		case IA32_SYSENTER_CS:
			VmxVmRead64P(VMCS_GUEST_SYSENTER_CS, &Msr.Flags);
			break;

		case IA32_SYSENTER_ESP:
			VmxVmRead64P(VMCS_GUEST_SYSENTER_ESP, &Msr.Flags);
			break;

		case IA32_SYSENTER_EIP:
			VmxVmRead64P(VMCS_GUEST_SYSENTER_EIP, &Msr.Flags);
			break;

		case IA32_GS_BASE:
			VmxVmRead64P(VMCS_GUEST_GS_BASE, &Msr.Flags);
			break;

		case IA32_FS_BASE:
			VmxVmRead64P(VMCS_GUEST_FS_BASE, &Msr.Flags);
			break;

		case HV_X64_MSR_GUEST_IDLE:

			break;

		default:

			//
			// Check whether the MSR should cause #GP or not
			//
			if (TargetMsr <= 0xfff && TestBit(TargetMsr, (unsigned long*)Global::g_MsrBitmapInvalidMsrs) != 0)
			{
				//
				// Invalid MSR between 0x0 to 0xfff
				//
				EventInjectGeneralProtection();
				return Result = FALSE;
			}

			//
			// Msr is valid
			//
			Msr.Flags = __readmsr(TargetMsr);

			//
			// Check if it's EFER MSR then we show a false SCE state
			//
			if (GuestRegs->rcx == IA32_EFER)
			{
				IA32_EFER_REGISTER MsrEFER;
				MsrEFER.AsUInt = Msr.Flags;
				MsrEFER.SyscallEnable = TRUE;
				Msr.Flags = MsrEFER.AsUInt;
			}

			break;
		}

		GuestRegs->rax = 0;
		GuestRegs->rdx = 0;

		GuestRegs->rax = Msr.Fields.Low;
		GuestRegs->rdx = Msr.Fields.High;
	}
	else
	{
		//
		// MSR is invalid, inject #GP
		//
		EventInjectGeneralProtection();
		return Result = FALSE;
	}

	return Result;
}

BOOLEAN VMExitHandler::HandleWRMSR(PVIRTUAL_MACHINE_STATE VCpu) {

	BOOLEAN Result = TRUE;

	PGUEST_REGS GuestRegs = VCpu->Regs;
	MSR     Msr = { 0 };
	UINT32  TargetMsr;
	BOOLEAN UnusedIsKernel;

	TargetMsr = GuestRegs->rcx & 0xffffffff;

	Msr.Fields.Low = (ULONG)GuestRegs->rax;
	Msr.Fields.High = (ULONG)GuestRegs->rdx;

	//
	// Check for sanity of MSR if they're valid or they're for reserved range for WRMSR and RDMSR
	//
	if ((TargetMsr <= 0x00001FFF) || ((0xC0000000 <= TargetMsr) && (TargetMsr <= 0xC0001FFF)) ||
		(TargetMsr >= RESERVED_MSR_RANGE_LOW && (TargetMsr <= RESERVED_MSR_RANGE_HI)))
	{
		//
		// If the source register contains a non-canonical address and ECX specifies
		// one of the following MSRs:
		//
		// IA32_DS_AREA, IA32_FS_BASE, IA32_GS_BASE, IA32_KERNEL_GSBASE, IA32_LSTAR,
		// IA32_SYSENTER_EIP, IA32_SYSENTER_ESP
		//
		switch (TargetMsr)
		{
		case IA32_DS_AREA:
		case IA32_FS_BASE:
		case IA32_GS_BASE:
		case IA32_KERNEL_GS_BASE:
		case IA32_LSTAR:
		case IA32_SYSENTER_EIP:
		case IA32_SYSENTER_ESP:

			if (!EPT::CheckAddressCanonicality(Msr.Flags, &UnusedIsKernel))
			{
				//
				// Address is not canonical, inject #GP
				//
				EventInjectGeneralProtection();

				return Result = FALSE;
			}

			break;
		}

		switch (TargetMsr)
		{
		case IA32_SYSENTER_CS:
			VmxVmwrite64(VMCS_GUEST_SYSENTER_CS, Msr.Flags);
			break;

		case IA32_SYSENTER_ESP:
			VmxVmwrite64(VMCS_GUEST_SYSENTER_ESP, Msr.Flags);
			break;

		case IA32_SYSENTER_EIP:
			VmxVmwrite64(VMCS_GUEST_SYSENTER_EIP, Msr.Flags);
			break;

		case IA32_GS_BASE:
			VmxVmwrite64(VMCS_GUEST_GS_BASE, Msr.Flags);
			break;

		case IA32_FS_BASE:
			VmxVmwrite64(VMCS_GUEST_FS_BASE, Msr.Flags);
			break;

		default:

			__writemsr((unsigned long)GuestRegs->rcx, Msr.Flags);
			break;
		}
	}
	else
	{
		EventInjectGeneralProtection();
		return Result = FALSE;
	}

	return Result;
}

NTSTATUS VMExitHandler::HandleVMCall(PVIRTUAL_MACHINE_STATE VCpu, UINT64 VmcallNumber, UINT64 Op1, UINT64 Op2, UINT64 Op3) {

	NTSTATUS VmcallStatus = STATUS_UNSUCCESSFUL;

	switch (VmcallNumber)
	{
	case VMCALL_TEST:
	{
		VmcallStatus = VMCall::Test(Op1, Op2, Op3);
		break;
	}
	case VMCALL_VMXOFF:
	{
		VMCall::VmxOff(VCpu);
		VmcallStatus = STATUS_SUCCESS;

		break;
	}
	default:
	{
		LOGERR("Invalid VMCall");
		VmcallStatus = STATUS_UNSUCCESSFUL;
	}
	}

	return VmcallStatus;
}

