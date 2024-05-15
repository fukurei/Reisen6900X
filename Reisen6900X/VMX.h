/*
* Summary: Utility for VMX
*/

#pragma once

#include "Common.h"
#include "EPT.h"
#include "VMXAsm.h"

#define VMXON_SIZE 4096
#define VMCS_SIZE 4096
#define ALIGNMENT_PAGE_SIZE 4096

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

	//
	// Summary: Broadcast for `PerformVirtualizationOnSpecificCore`
	//
	BOOLEAN DpcRoutinePerformVirtualization(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
	
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


};

