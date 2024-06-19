#pragma once
#include "VMCall.h"

///
/// Summary: The Handler for VM Exit, we need it because we can't handle them all in VMX.h nor VMX.cpp
///

namespace VMExitHandler {
	

	// These two are important as `rdmsr` and `wrmsr` opcode are in the functions:
	// 1. PpmInitializeGuest constantly uses rdmsr instruction
	// 2. HalpHvTimerArm constantly uses wrmsr instruction
	// Inappropriate implementation will cause livelock

	// Input: VCpu
	// Output: Result, False for RDMSR/WRMSR Failed.
	BOOLEAN HandleRDMSR(PVIRTUAL_MACHINE_STATE VCpu);
	BOOLEAN HandleWRMSR(PVIRTUAL_MACHINE_STATE VCpu);

	// Handle VMCall
	NTSTATUS HandleVMCall(PVIRTUAL_MACHINE_STATE VCpu, UINT64 num, UINT64 Op1, UINT64 Op2, UINT64 Op3);

}