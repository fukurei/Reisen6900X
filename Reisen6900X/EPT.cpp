//
// Summary: Implementation for EPT.h
//

#include "EPT.h"

bool EPT::CheckEPTSupport() {

	IA32_VMX_EPT_VPID_CAP_REGISTER vpid = { 0, };
	IA32_MTRR_DEF_TYPE_REGISTER mtrr_def_type = { 0, };

	vpid.AsUInt = __readmsr(IA32_VMX_EPT_VPID_CAP);
	mtrr_def_type.AsUInt = __readmsr(IA32_MTRR_DEF_TYPE);

	if (!vpid.PageWalkLength4 || !vpid.MemoryTypeWriteBack || !vpid.Pde2MbPages) {
		LOGERR("EPT supports are disabled");
		return false;
	}

	if (!vpid.ExecuteOnlyPages) {
		LOGINF("Execute only pages support is disabled: the features of Reisen will not available");
		g_CompatibilityChecks.ExecuteOnlySupport = FALSE;
	}
	else {
		g_CompatibilityChecks.ExecuteOnlySupport = TRUE;
	}

	if (!mtrr_def_type.MtrrEnable) {
		LOGERR("MTRR dynamic range supports are disabled");
		return false;
	}

	LOGINF("All ok!");

	return true;

}

BOOLEAN EPT::BuildMTRRMap(VOID)
{
	IA32_MTRR_CAPABILITIES_REGISTER MTRRCap;
	IA32_MTRR_PHYSBASE_REGISTER     CurrentPhysBase;
	IA32_MTRR_PHYSMASK_REGISTER     CurrentPhysMask;
	IA32_MTRR_DEF_TYPE_REGISTER     MTRRDefType;
	PMTRR_RANGE_DESCRIPTOR          Descriptor;
	UINT32                          CurrentRegister;
	UINT32                          NumberOfBitsInMask;

	MTRRCap.AsUInt = __readmsr(IA32_MTRR_CAPABILITIES);
	MTRRDefType.AsUInt = __readmsr(IA32_MTRR_DEF_TYPE);

	//
	// All MTRRs are disabled when clear, and the
	// UC memory type is applied to all of physical memory.
	//
	if (!MTRRDefType.MtrrEnable)
	{
		g_EptState->DefaultMemoryType = MEMORY_TYPE_UNCACHEABLE;
		return TRUE;
	}

	//
	// The IA32_MTRR_DEF_TYPE MSR (named MTRRdefType MSR for the P6 family processors) sets the default
	// properties of the regions of physical memory that are not encompassed by MTRRs
	//
	g_EptState->DefaultMemoryType = (UINT8)MTRRDefType.DefaultMemoryType;

	//
	// The fixed memory ranges are mapped with 11 fixed-range registers of 64 bits each. Each of these registers is
	// divided into 8-bit fields that are used to specify the memory type for each of the sub-ranges the register controls:
	//  - Register IA32_MTRR_FIX64K_00000 - Maps the 512-KByte address range from 0H to 7FFFFH. This range
	//  is divided into eight 64-KByte sub-ranges.
	//
	//  - Registers IA32_MTRR_FIX16K_80000 and IA32_MTRR_FIX16K_A0000 - Maps the two 128-KByte
	//  address ranges from 80000H to BFFFFH. This range is divided into sixteen 16-KByte sub-ranges, 8 ranges per
	//  register.
	//
	//  - Registers IA32_MTRR_FIX4K_C0000 through IA32_MTRR_FIX4K_F8000 - Maps eight 32-KByte
	//  address ranges from C0000H to FFFFFH. This range is divided into sixty-four 4-KByte sub-ranges, 8 ranges per
	//  register.
	//
	if (MTRRCap.FixedRangeSupported && MTRRDefType.FixedRangeMtrrEnable)
	{
		const UINT32               K64Base = 0x0;
		const UINT32               K64Size = 0x10000;
		IA32_MTRR_FIXED_RANGE_TYPE K64Types = { __readmsr(IA32_MTRR_FIX64K_00000) };
		for (unsigned int i = 0; i < 8; i++)
		{
			Descriptor = &g_EptState->MemoryRanges[g_EptState->NumberOfEnabledMemoryRanges++];
			Descriptor->MemoryType = K64Types.s.Types[i];
			Descriptor->PhysicalBaseAddress = K64Base + (K64Size * i);
			Descriptor->PhysicalEndAddress = K64Base + (K64Size * i) + (K64Size - 1);
			Descriptor->FixedRange = TRUE;
		}

		const UINT32 K16Base = 0x80000;
		const UINT32 K16Size = 0x4000;
		for (unsigned int i = 0; i < 2; i++)
		{
			IA32_MTRR_FIXED_RANGE_TYPE K16Types = { __readmsr(IA32_MTRR_FIX16K_80000 + i) };
			for (unsigned int j = 0; j < 8; j++)
			{
				Descriptor = &g_EptState->MemoryRanges[g_EptState->NumberOfEnabledMemoryRanges++];
				Descriptor->MemoryType = K16Types.s.Types[j];
				Descriptor->PhysicalBaseAddress = (K16Base + (i * K16Size * 8)) + (K16Size * j);
				Descriptor->PhysicalEndAddress = (K16Base + (i * K16Size * 8)) + (K16Size * j) + (K16Size - 1);
				Descriptor->FixedRange = TRUE;
			}
		}

		const UINT32 K4Base = 0xC0000;
		const UINT32 K4Size = 0x1000;
		for (unsigned int i = 0; i < 8; i++)
		{
			IA32_MTRR_FIXED_RANGE_TYPE K4Types = { __readmsr(IA32_MTRR_FIX4K_C0000 + i) };

			for (unsigned int j = 0; j < 8; j++)
			{
				Descriptor = &g_EptState->MemoryRanges[g_EptState->NumberOfEnabledMemoryRanges++];
				Descriptor->MemoryType = K4Types.s.Types[j];
				Descriptor->PhysicalBaseAddress = (K4Base + (i * K4Size * 8)) + (K4Size * j);
				Descriptor->PhysicalEndAddress = (K4Base + (i * K4Size * 8)) + (K4Size * j) + (K4Size - 1);
				Descriptor->FixedRange = TRUE;
			}
		}
	}

	for (CurrentRegister = 0; CurrentRegister < MTRRCap.VariableRangeCount; CurrentRegister++)
	{
		//
		// For each dynamic register pair
		//
		CurrentPhysBase.AsUInt = __readmsr(IA32_MTRR_PHYSBASE0 + (CurrentRegister * 2));
		CurrentPhysMask.AsUInt = __readmsr(IA32_MTRR_PHYSMASK0 + (CurrentRegister * 2));

		//
		// Is the range enabled?
		//
		if (CurrentPhysMask.Valid)
		{
			//
			// We only need to read these once because the ISA dictates that MTRRs are
			// to be synchronized between all processors during BIOS initialization.
			//
			Descriptor = &g_EptState->MemoryRanges[g_EptState->NumberOfEnabledMemoryRanges++];

			//
			// Calculate the base address in bytes
			//
			Descriptor->PhysicalBaseAddress = CurrentPhysBase.PageFrameNumber * PAGE_SIZE;

			//
			// Calculate the total size of the range
			// The lowest bit of the mask that is set to 1 specifies the size of the range
			//
			_BitScanForward64((ULONG*)&NumberOfBitsInMask, CurrentPhysMask.PageFrameNumber * PAGE_SIZE);

			//
			// Size of the range in bytes + Base Address
			//
			Descriptor->PhysicalEndAddress = Descriptor->PhysicalBaseAddress + ((1ULL << NumberOfBitsInMask) - 1ULL);

			//
			// Memory Type (cacheability attributes)
			//
			Descriptor->MemoryType = (UCHAR)CurrentPhysBase.Type;

			Descriptor->FixedRange = FALSE;

			LOGINF("MTRR Range: Base=0x%llx End=0x%llx Type=0x%x", Descriptor->PhysicalBaseAddress, Descriptor->PhysicalEndAddress, Descriptor->MemoryType);
		}
	}

	LOGINF("Total MTRR ranges committed: 0x%x", g_EptState->NumberOfEnabledMemoryRanges);

	return TRUE;
}

STATUS EPT::EPTLogicalProcessorInit() {

	STATUS status = STAT_ERROR_UNKNOWN;

	ULONG processors_count = 0;
	PVMM_EPT_PAGE_TABLE page_table = { 0, };
	EPT_POINTER eptp = { 0 };
	
	processors_count = KeQueryActiveProcessorCount(NULL);

	for (size_t i = 0; i < processors_count; i++) {

		page_table = EPTAllocateAndCreateIdentityPageTable();

		if (!page_table) {

			// Try to deallocate previous things
			for (size_t j = 0; j < processors_count; j++) {

				if (Global::g_GuestState[j].EptPageTable != NULL) {
					MmFreeContiguousMemory(Global::g_GuestState[j].EptPageTable);
					Global::g_GuestState[j].EptPageTable = NULL;
				}

			}

			LOGERR("Couldn't allocate identity page table");

			return status = STAT_ERROR_KNOWN;
		}

		Global::g_GuestState[i].EptPageTable = page_table;

		eptp.MemoryType = g_EptState->DefaultMemoryType;

		// We might utilize the 'access' and 'dirty' flag features in the dirty logging mechanism
		eptp.EnableAccessAndDirtyFlags = TRUE;

		eptp.PageWalkLength = 3;

		eptp.PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&page_table->PML4) / PAGE_SIZE;

		Global::g_GuestState[i].EptPointer = eptp;

	}

	return status = STAT_SUCCESS;

}

PVMM_EPT_PAGE_TABLE EPT::EPTAllocateAndCreateIdentityPageTable() {

	PVMM_EPT_PAGE_TABLE PageTable;
	EPT_PML3_POINTER    RWXTemplate;
	EPT_PML2_ENTRY      PML2EntryTemplate;
	SIZE_T              EntryGroupIndex;
	SIZE_T              EntryIndex;

	//
	// Allocate all paging structures as 4KB aligned pages
	//

	//
	// Allocate address anywhere in the OS's memory space and
	// zero out all entries to ensure all unused entries are marked Not Present
	//
	PageTable = (PVMM_EPT_PAGE_TABLE)AllocateContiguousZeroedMemory(sizeof(VMM_EPT_PAGE_TABLE));

	if (PageTable == NULL)
	{
		LOGERR("Err, failed to allocate memory for PageTable");
		return NULL;
	}

	//
	// Mark the first 512GB PML4 entry as present, which allows us to manage up
	// to 512GB of discrete paging structures.
	//
	PageTable->PML4[0].PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&PageTable->PML3[0]) / PAGE_SIZE;
	PageTable->PML4[0].ReadAccess = 1;
	PageTable->PML4[0].WriteAccess = 1;
	PageTable->PML4[0].ExecuteAccess = 1;

	//
	// Now mark each 1GB PML3 entry as RWX and map each to their PML2 entry
	//

	//
	// Ensure stack memory is cleared
	//
	RWXTemplate.AsUInt = 0;

	//
	// Set up one 'template' RWX PML3 entry and copy it into each of the 512 PML3 entries
	// Using the same method as SimpleVisor for copying each entry using intrinsics.
	//
	RWXTemplate.ReadAccess = 1;
	RWXTemplate.WriteAccess = 1;
	RWXTemplate.ExecuteAccess = 1;

	//
	// Copy the template into each of the 512 PML3 entry slots
	//
	__stosq((SIZE_T*)&PageTable->PML3[0], RWXTemplate.AsUInt, VMM_EPT_PML3E_COUNT);

	//
	// For each of the 512 PML3 entries
	//
	for (EntryIndex = 0; EntryIndex < VMM_EPT_PML3E_COUNT; EntryIndex++)
	{
		//
		// Map the 1GB PML3 entry to 512 PML2 (2MB) entries to describe each large page.
		// NOTE: We do *not* manage any PML1 (4096 byte) entries and do not allocate them.
		//
		PageTable->PML3[EntryIndex].PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&PageTable->PML2[EntryIndex][0]) / PAGE_SIZE;
	}

	PML2EntryTemplate.AsUInt = 0;

	//
	// All PML2 entries will be RWX and 'present'
	//
	PML2EntryTemplate.WriteAccess = 1;
	PML2EntryTemplate.ReadAccess = 1;
	PML2EntryTemplate.ExecuteAccess = 1;

	//
	// We are using 2MB large pages, so we must mark this 1 here
	//
	PML2EntryTemplate.LargePage = 1;

	//
	// For each collection of 512 PML2 entries (512 collections * 512 entries per collection),
	// mark it RWX using the same template above.
	// This marks the entries as "Present" regardless of if the actual system has memory at
	// this region or not. We will cause a fault in our EPT handler if the guest access a page
	// outside a usable range, despite the EPT frame being present here.
	//
	__stosq((SIZE_T*)&PageTable->PML2[0], PML2EntryTemplate.AsUInt, VMM_EPT_PML3E_COUNT * VMM_EPT_PML2E_COUNT);

	//
	// For each of the 512 collections of 512 2MB PML2 entries
	//
	for (EntryGroupIndex = 0; EntryGroupIndex < VMM_EPT_PML3E_COUNT; EntryGroupIndex++)
	{
		//
		// For each 2MB PML2 entry in the collection
		//
		for (EntryIndex = 0; EntryIndex < VMM_EPT_PML2E_COUNT; EntryIndex++)
		{
			//
			// Setup the memory type and frame number of the PML2 entry
			//
			EPTSetupPML2Entry(PageTable, &PageTable->PML2[EntryGroupIndex][EntryIndex], (EntryGroupIndex * VMM_EPT_PML2E_COUNT) + EntryIndex);
		}
	}

	return PageTable;
}

BOOLEAN EPT::EPTSetupPML2Entry(PVMM_EPT_PAGE_TABLE EptPageTable, PEPT_PML2_ENTRY NewEntry, SIZE_T PageFrameNumber) {

	PVOID TargetBuffer;

	//
	// Each of the 512 collections of 512 PML2 entries is setup here
	// This will, in total, identity map every physical address from 0x0
	// to physical address 0x8000000000 (512GB of memory)
	// ((EntryGroupIndex * VMM_EPT_PML2E_COUNT) + EntryIndex) * 2MB is
	// the actual physical address we're mapping
	//
	NewEntry->PageFrameNumber = PageFrameNumber;

	if (EPTIsValidForLargePage(PageFrameNumber))
	{
		NewEntry->MemoryType = EPTGetMemoryType(PageFrameNumber, TRUE);

		return TRUE;
	}
	else
	{
		TargetBuffer = (PVOID)AllocateNonPagedPool(sizeof(VMM_EPT_DYNAMIC_SPLIT));

		if (!TargetBuffer)
		{
			LOGERR("Err, cannot allocate page for splitting edge large pages");
			return FALSE;
		}

		return EPTSplitLargePage(EptPageTable, TargetBuffer, PageFrameNumber * SIZE_2_MB);
	}

}

bool EPT::EPTIsValidForLargePage(SIZE_T PageFrameNumber) {

	SIZE_T                  StartAddressOfPage = PageFrameNumber * SIZE_2_MB;
	SIZE_T                  EndAddressOfPage = StartAddressOfPage + (SIZE_2_MB - 1);
	MTRR_RANGE_DESCRIPTOR* CurrentMemoryRange;
	SIZE_T                  CurrentMtrrRange;

	for (CurrentMtrrRange = 0; CurrentMtrrRange < g_EptState->NumberOfEnabledMemoryRanges; CurrentMtrrRange++)
	{
		CurrentMemoryRange = &g_EptState->MemoryRanges[CurrentMtrrRange];

		if ((StartAddressOfPage <= CurrentMemoryRange->PhysicalEndAddress &&
			EndAddressOfPage > CurrentMemoryRange->PhysicalEndAddress) ||
			(StartAddressOfPage < CurrentMemoryRange->PhysicalBaseAddress &&
				EndAddressOfPage >= CurrentMemoryRange->PhysicalBaseAddress))
		{
			return FALSE;
		}
	}

	return TRUE;

}

BOOLEAN EPT::EPTSplitLargePage(PVMM_EPT_PAGE_TABLE EptPageTable, PVOID PreAllocatedBuffer, SIZE_T PhysicalAddress) {
	PVMM_EPT_DYNAMIC_SPLIT NewSplit;
	EPT_PML1_ENTRY         EntryTemplate;
	SIZE_T                 EntryIndex;
	PEPT_PML2_ENTRY        TargetEntry;
	EPT_PML2_POINTER       NewPointer;

	//
	// Find the PML2 entry that's currently used
	//
	TargetEntry = EPTGetPml2Entry(EptPageTable, PhysicalAddress);

	if (!TargetEntry)
	{
		LOGERR("Err, an invalid physical address passed");
		return FALSE;
	}

	//
	// If this large page is not marked a large page, that means it's a pointer already.
	// That page is therefore already split.
	//
	if (!TargetEntry->LargePage)
	{
		//
		// As it's a large page and we request a pool for it, we need to
		// free the pool because it's not used anymore
		//
		FreeNonPagedPool((PVOID)PreAllocatedBuffer);

		return TRUE;
	}

	//
	// Allocate the PML1 entries
	//
	NewSplit = (PVMM_EPT_DYNAMIC_SPLIT)PreAllocatedBuffer;
	if (!NewSplit)
	{
		LOGERR("Err, failed to allocate dynamic split memory");
		return FALSE;
	}
	RtlZeroMemory(NewSplit, sizeof(VMM_EPT_DYNAMIC_SPLIT));

	//
	// Point back to the entry in the dynamic split for easy reference for which entry that
	// dynamic split is for
	//
	NewSplit->u.Entry = TargetEntry;

	//
	// Make a template for RWX
	//
	EntryTemplate.AsUInt = 0;
	EntryTemplate.ReadAccess = 1;
	EntryTemplate.WriteAccess = 1;
	EntryTemplate.ExecuteAccess = 1;

	//
	// copy other bits from target entry
	//
	EntryTemplate.MemoryType = TargetEntry->MemoryType;
	EntryTemplate.IgnorePat = TargetEntry->IgnorePat;
	EntryTemplate.SuppressVe = TargetEntry->SuppressVe;

	//
	// Copy the template into all the PML1 entries
	//
	__stosq((SIZE_T*)&NewSplit->PML1[0], EntryTemplate.AsUInt, VMM_EPT_PML1E_COUNT);

	//
	// Set the page frame numbers for identity mapping
	//
	for (EntryIndex = 0; EntryIndex < VMM_EPT_PML1E_COUNT; EntryIndex++)
	{
		//
		// Convert the 2MB page frame number to the 4096 page entry number plus the offset into the frame
		//
		NewSplit->PML1[EntryIndex].PageFrameNumber = ((TargetEntry->PageFrameNumber * SIZE_2_MB) / PAGE_SIZE) + EntryIndex;
		NewSplit->PML1[EntryIndex].MemoryType = EPTGetMemoryType(NewSplit->PML1[EntryIndex].PageFrameNumber, FALSE);
	}

	//
	// Allocate a new pointer which will replace the 2MB entry with a pointer to 512 4096 byte entries
	//
	NewPointer.AsUInt = 0;
	NewPointer.WriteAccess = 1;
	NewPointer.ReadAccess = 1;
	NewPointer.ExecuteAccess = 1;
	NewPointer.PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&NewSplit->PML1[0]) / PAGE_SIZE;

	//
	// Now, replace the entry in the page table with our new split pointer
	//
	RtlCopyMemory(TargetEntry, &NewPointer, sizeof(NewPointer));

	return TRUE;
}


UINT8 EPT::EPTGetMemoryType(SIZE_T PageFrameNumber, BOOLEAN IsLargePage)
{
	UINT8                   TargetMemoryType;
	SIZE_T                  AddressOfPage;
	SIZE_T                  CurrentMtrrRange;
	MTRR_RANGE_DESCRIPTOR* CurrentMemoryRange;

	AddressOfPage = IsLargePage ? PageFrameNumber * SIZE_2_MB : PageFrameNumber * PAGE_SIZE;

	TargetMemoryType = (UINT8)-1;

	//
	// For each MTRR range
	//
	for (CurrentMtrrRange = 0; CurrentMtrrRange < g_EptState->NumberOfEnabledMemoryRanges; CurrentMtrrRange++)
	{
		CurrentMemoryRange = &g_EptState->MemoryRanges[CurrentMtrrRange];

		//
		// If the physical address is described by this MTRR
		//
		if (AddressOfPage >= CurrentMemoryRange->PhysicalBaseAddress &&
			AddressOfPage < CurrentMemoryRange->PhysicalEndAddress)
		{
			// LogInfo("0x%X> Range=%llX -> %llX | Begin=%llX End=%llX", PageFrameNumber, AddressOfPage, AddressOfPage + SIZE_2_MB - 1, g_EptState->MemoryRanges[CurrentMtrrRange].PhysicalBaseAddress, g_EptState->MemoryRanges[CurrentMtrrRange].PhysicalEndAddress);

			//
			// 12.11.4.1 MTRR Precedences
			//
			if (CurrentMemoryRange->FixedRange)
			{
				//
				// When the fixed-range MTRRs are enabled, they take priority over the variable-range
				// MTRRs when overlaps in ranges occur.
				//
				TargetMemoryType = CurrentMemoryRange->MemoryType;
				break;
			}

			if (TargetMemoryType == MEMORY_TYPE_UNCACHEABLE)
			{
				//
				// If this is going to be marked uncacheable, then we stop the search as UC always
				// takes precedence
				//
				TargetMemoryType = CurrentMemoryRange->MemoryType;
				break;
			}

			if (TargetMemoryType == MEMORY_TYPE_WRITE_THROUGH || CurrentMemoryRange->MemoryType == MEMORY_TYPE_WRITE_THROUGH)
			{
				if (TargetMemoryType == MEMORY_TYPE_WRITE_BACK)
				{
					//
					// If two or more MTRRs overlap and describe the same region, and at least one is WT and
					// the other one(s) is/are WB, use WT. However, continue looking, as other MTRRs
					// may still specify the address as UC, which always takes precedence
					//
					TargetMemoryType = MEMORY_TYPE_WRITE_THROUGH;
					continue;
				}
			}

			//
			// Otherwise, just use the last MTRR that describes this address
			//
			TargetMemoryType = CurrentMemoryRange->MemoryType;
		}
	}

	//
	// If no MTRR was found, return the default memory type
	//
	if (TargetMemoryType == (UINT8)-1)
	{
		TargetMemoryType = g_EptState->DefaultMemoryType;
	}

	return TargetMemoryType;
}

PEPT_PML2_ENTRY EPT::EPTGetPml2Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress)
{
	SIZE_T          Directory, DirectoryPointer, PML4Entry;
	PEPT_PML2_ENTRY PML2;

	Directory = ADDRMASK_EPT_PML2_INDEX(PhysicalAddress);
	DirectoryPointer = ADDRMASK_EPT_PML3_INDEX(PhysicalAddress);
	PML4Entry = ADDRMASK_EPT_PML4_INDEX(PhysicalAddress);

	//
	// Addresses above 512GB are invalid because it is > physical address bus width
	//
	if (PML4Entry > 0)
	{
		return NULL;
	}

	PML2 = &EptPageTable->PML2[DirectoryPointer][Directory];
	return PML2;
}

BOOLEAN
EPT::CheckAddressCanonicality(UINT64 VAddr, PBOOLEAN IsKernelAddress)
{
	UINT64 Addr = (UINT64)VAddr;
	UINT64 MaxVirtualAddrLowHalf, MinVirtualAddressHighHalf;

	//
	// Get processor's address width for VA
	//
	UINT32 AddrWidth = g_CompatibilityChecks.VirtualAddressWidth;

	//
	// get max address in lower-half canonical addr space
	// e.g. if width is 48, then 0x00007FFF_FFFFFFFF
	//
	MaxVirtualAddrLowHalf = ((UINT64)1ull << (AddrWidth - 1)) - 1;

	//
	// get min address in higher-half canonical addr space
	// e.g., if width is 48, then 0xFFFF8000_00000000
	//
	MinVirtualAddressHighHalf = ~MaxVirtualAddrLowHalf;

	//
	// Check to see if the address in a canonical address
	//
	if ((Addr > MaxVirtualAddrLowHalf) && (Addr < MinVirtualAddressHighHalf))
	{
		*IsKernelAddress = FALSE;
		return FALSE;
	}

	//
	// Set whether it's a kernel address or not
	//
	if (MinVirtualAddressHighHalf < Addr)
	{
		*IsKernelAddress = TRUE;
	}
	else
	{
		*IsKernelAddress = FALSE;
	}

	return TRUE;
}