//
// Summary: EPT Feature implementation
//

#pragma once

#include "Global.h"

#define MAX_VARIABLE_RANGE_MTRRS 255
#define NUM_FIXED_RANGE_MTRRS ((1 + 2 + 8) * RTL_NUMBER_OF_FIELD(IA32_MTRR_FIXED_RANGE_TYPE, s.Types)) // = 88
#define NUM_MTRR_ENTRIES (MAX_VARIABLE_RANGE_MTRRS + NUM_FIXED_RANGE_MTRRS) // = 343

#define SIZE_2_MB ((SIZE_T)(512 * PAGE_SIZE))

/**
 * @brief Offset into the 1st paging structure (4096 byte)
 *
 */
#define ADDRMASK_EPT_PML1_OFFSET(_VAR_) ((_VAR_) & 0xFFFULL)

 /**
  * @brief Index of the 1st paging structure (4096 byte)
  *
  */
#define ADDRMASK_EPT_PML1_INDEX(_VAR_) (((_VAR_) & 0x1FF000ULL) >> 12)

  /**
   * @brief Index of the 2nd paging structure (2MB)
   *
   */
#define ADDRMASK_EPT_PML2_INDEX(_VAR_) (((_VAR_) & 0x3FE00000ULL) >> 21)

   /**
    * @brief Index of the 3rd paging structure (1GB)
    *
    */
#define ADDRMASK_EPT_PML3_INDEX(_VAR_) (((_VAR_) & 0x7FC0000000ULL) >> 30)

    /**
     * @brief Index of the 4th paging structure (512GB)
     *
     */
#define ADDRMASK_EPT_PML4_INDEX(_VAR_) (((_VAR_) & 0xFF8000000000ULL) >> 39)

//
// MTRR Range Descriptor.
//
typedef struct _MTRR_RANGE_DESCRIPTOR
{
    SIZE_T  PhysicalBaseAddress;
    SIZE_T  PhysicalEndAddress;
    UCHAR   MemoryType;
    BOOLEAN FixedRange;
} MTRR_RANGE_DESCRIPTOR, * PMTRR_RANGE_DESCRIPTOR;

typedef union _IA32_MTRR_FIXED_RANGE_TYPE
{
    UINT64 AsUInt;
    struct
    {
        UINT8 Types[8];
    } s;
} IA32_MTRR_FIXED_RANGE_TYPE;

//
// EPT State struct
//
typedef struct _EPT_STATE
{
    LIST_ENTRY            HookedPagesList;                     // A list of the details about hooked pages
    MTRR_RANGE_DESCRIPTOR MemoryRanges[NUM_MTRR_ENTRIES];      // Physical memory ranges described by the BIOS in the MTRRs. Used to build the EPT identity mapping.
    UINT32                 NumberOfEnabledMemoryRanges;         // Number of memory ranges specified in MemoryRanges
    PVMM_EPT_PAGE_TABLE   EptPageTable;                        // Page table entries for EPT operation
    PVMM_EPT_PAGE_TABLE   ModeBasedUserDisabledEptPageTable;   // Page table entries for hooks based on user-mode disabled mode-based execution control bits
    PVMM_EPT_PAGE_TABLE   ModeBasedKernelDisabledEptPageTable; // Page table entries for hooks based on kernel-mode disabled mode-based execution control bits
    EPT_POINTER           ModeBasedUserDisabledEptPointer;     // Extended-Page-Table Pointer for user-disabled mode-based execution
    EPT_POINTER           ModeBasedKernelDisabledEptPointer;   // Extended-Page-Table Pointer for kernel-disabled mode-based execution
    EPT_POINTER           ExecuteOnlyEptPointer;               // Extended-Page-Table Pointer for execute-only execution
    UINT8                 DefaultMemoryType;
} EPT_STATE, * PEPT_STATE;

//
// Compatibility checks struct
//
typedef struct _COMPATIBILITY_CHECKS_STATUS
{
    BOOLEAN IsX2Apic;                  // X2APIC or XAPIC routine
    BOOLEAN RtmSupport;                // check for RTM support
    BOOLEAN PmlSupport;                // check Page Modification Logging (PML) support
    BOOLEAN ModeBasedExecutionSupport; // check for mode based execution support (processors after Kaby Lake release will support this feature)
    BOOLEAN ExecuteOnlySupport;        // Support for execute-only pages (indicating that data accesses are not allowed while instruction fetches are allowed)
    UINT32  VirtualAddressWidth;       // Virtual address width for x86 processors
    UINT32  PhysicalAddressWidth;      // Physical address width for x86 processors

} COMPATIBILITY_CHECKS_STATUS, * PCOMPATIBILITY_CHECKS_STATUS;

typedef struct _VMM_EPT_DYNAMIC_SPLIT
{
    /**
     * @brief The 4096 byte page table entries that correspond to the split 2MB table entry
     *
     */
    DECLSPEC_ALIGN(PAGE_SIZE)
        EPT_PML1_ENTRY PML1[VMM_EPT_PML1E_COUNT];

    /**
     * @brief The pointer to the 2MB entry in the page table which this split is servicing.
     *
     */
    union
    {
        PEPT_PML2_ENTRY   Entry;
        PEPT_PML2_POINTER Pointer;
    } u;

    /**
     * @brief Linked list entries for each dynamic split
     *
     */
    LIST_ENTRY DynamicSplitList;

} VMM_EPT_DYNAMIC_SPLIT, * PVMM_EPT_DYNAMIC_SPLIT;

namespace EPT
{

    //
    // Summary: Global EPT State. For specific, See reference EPT.h
    //
    inline PEPT_STATE g_EptState;

    //
    // Summary: Global compatibility check var
    //
    inline COMPATIBILITY_CHECKS_STATUS g_CompatibilityChecks;

    //
    // Summary: Check EPT Support for computer.
    // Return: 'true' if the computer supports EPT, 'false' for not.
    //
    bool CheckEPTSupport();
    
    //
    // Summary: Build MTRR map
    // Returns: TRUE if succeed, else for failed.
    //
    BOOLEAN BuildMTRRMap();

    //
    // Summary: Initialize EPT for an individual logical processor
    // Returns: STAT_SUCCESS if succeed, else for failed.
    //
    STATUS EPTLogicalProcessorInit();

    //
    // Summary: Allocates page maps and create identity page table
    // Returns: Pointer for allocated page table, nullptr for failed.
    //
    PVMM_EPT_PAGE_TABLE EPTAllocateAndCreateIdentityPageTable();

    /**
    * @brief Set up PML2 Entries
    *
    * @param EptPageTable
    * @param NewEntry The PML2 Entry
    * @param PageFrameNumber PFN (Physical Address)
    * @return 'true' if succeed, else for failed.
    */
    BOOLEAN EPTSetupPML2Entry(PVMM_EPT_PAGE_TABLE EptPageTable, PEPT_PML2_ENTRY NewEntry, SIZE_T PageFrameNumber);


    /**
    * @brief Check if potential large page doesn't land on two or more different cache memory types
    *
    * @param PageFrameNumber PFN (Physical Address)
    * @return BOOLEAN
    */
    bool EPTIsValidForLargePage(SIZE_T PageFrameNumber);

    /**
    * @brief Split 2MB (LargePage) into 4kb pages
    *
    * @param EptPageTable The EPT Page Table
    * @param PreAllocatedBuffer The address of pre-allocated buffer
    * @param PhysicalAddress Physical address of where we want to split
    *
    * @return 'true' if succeed, else for failed.
    */
    BOOLEAN EPTSplitLargePage(PVMM_EPT_PAGE_TABLE EptPageTable, PVOID PreAllocatedBuffer, SIZE_T PhysicalAddress);


    /**
    * @brief Check whether EPT features are present or not
    *
    * @param PageFrameNumber
    * @param IsLargePage
    * @return UINT8 Return desired type of memory for particular small/large page
    */
    UINT8 EPTGetMemoryType(SIZE_T PageFrameNumber, BOOLEAN IsLargePage);

    /**
    * @brief Get the PML2 entry for this physical address
    *
    * @param EptPageTable The EPT Page Table
    * @param PhysicalAddress Physical Address that we want to get its PML2
    * @return PEPT_PML2_ENTRY The PML2 Entry Structure
    */
    PEPT_PML2_ENTRY EPTGetPml2Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress);

};

