#pragma once
#include "EPT.h"

#define VMCALL_TEST 0x1
#define VMCALL_VMXOFF 0x2

namespace VMCall {

	// Test
	NTSTATUS Test(UINT64 Op1, UINT64 Op2, UINT64 Op3);

	// VmxOff
	VOID VmxOff(PVIRTUAL_MACHINE_STATE VCpu);

}