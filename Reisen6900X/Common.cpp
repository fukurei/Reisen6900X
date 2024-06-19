//
// Summary: Implementation for functions of Common.h
//

#include "Common.h"

PVOID AllocateNonPagedPool(SIZE_T NumberOfBytes)
{
    PVOID Result = ExAllocatePoolWithTag(NonPagedPool, NumberOfBytes, POOL_TAG);

    return Result;
}

PVOID AllocateZeroedNonPagedPool(SIZE_T size) {

    auto ret = ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG);

    // If it is failed, return nullptr
    if (!ret) {
        return nullptr;
    }

    RtlZeroMemory(ret, size);
    return ret;

}

PVOID AllocateContiguousZeroedMemory(SIZE_T NumberOfBytes)
{
    PVOID            Result = NULL;
    PHYSICAL_ADDRESS MaxPhysicalAddr = { 0, };
    MaxPhysicalAddr.QuadPart = MAXULONG64;

    Result = MmAllocateContiguousMemory(NumberOfBytes, MaxPhysicalAddr);
    if (Result != NULL)
        RtlSecureZeroMemory(Result, NumberOfBytes);

    return Result;
}

void FreeNonPagedPool(PVOID address) {

    ExFreePoolWithTag(address, POOL_TAG);
    return;

}

_Use_decl_annotations_
UINT64
VirtualAddressToPhysicalAddress(_In_ PVOID VirtualAddress)
{
    return MmGetPhysicalAddress(VirtualAddress).QuadPart;
}

void
SetBit(int BitNumber, unsigned long* addr)
{
    BITMAP_ENTRY(BitNumber, addr) |= (1UL << BITMAP_SHIFT(BitNumber));
}

int
TestBit(int BitNumber, unsigned long* addr)
{
    return (BITMAP_ENTRY(BitNumber, addr) >> BITMAP_SHIFT(BitNumber)) & 1;
}

extern "C" inline UCHAR
VmxVmRead64P(size_t   Field,
    UINT64* FieldValue)
{
    return __vmx_vmread((size_t)Field, (size_t*)FieldValue);
}

inline UCHAR
VmxVmwrite16(size_t Field,
    UINT16 FieldValue)
{
    UINT64 TargetValue = 0;
    TargetValue = (UINT64)FieldValue;
    return __vmx_vmwrite((size_t)Field, (size_t)TargetValue);
}

inline UCHAR
VmxVmwrite32(size_t Field,
    UINT32 FieldValue)
{
    UINT64 TargetValue = 0;
    TargetValue = (UINT64)FieldValue;
    return __vmx_vmwrite((size_t)Field, (size_t)TargetValue);
}

inline UCHAR
VmxVmwrite64(size_t Field,
    UINT64 FieldValue)
{
    return __vmx_vmwrite((size_t)Field, (size_t)FieldValue);
}

inline UINT64
VmxVmRead64(size_t Field)
{
    UINT64 TargetField;
    __vmx_vmread((size_t)Field, (size_t*)&TargetField);
    return TargetField;
}

extern "C" inline UINT32
VmxVmRead32(size_t Field)
{
    UINT64 TargetField;
    __vmx_vmread((size_t)Field, (size_t*)&TargetField);
    return (UINT16)(TargetField & 0xFFFFFFFF);
}

extern "C" inline UINT16
VmxVmRead16(size_t Field)
{
    UINT64 TargetField;
    __vmx_vmread((size_t)Field, (size_t*)&TargetField);
    return (UINT16)(TargetField & 0xFFFF);
}

VOID
EventInjectGeneralProtection()
{
    UINT32 ExitInstrLength;

    EventInjectInterruption(INTERRUPT_TYPE_HARDWARE_EXCEPTION, EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, TRUE, 0);

    ExitInstrLength = VmxVmRead32(VMCS_VMEXIT_INSTRUCTION_LENGTH);
    VmxVmwrite64(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, ExitInstrLength);

}

VOID
EventInjectInterruption(INTERRUPT_TYPE InterruptionType, EXCEPTION_VECTORS Vector, BOOLEAN DeliverErrorCode, UINT32 ErrorCode)
{
    INTERRUPT_INFO Inject = { 0 };
    Inject.Fields.Valid = TRUE;
    Inject.Fields.InterruptType = InterruptionType;
    Inject.Fields.Vector = Vector;
    Inject.Fields.DeliverCode = DeliverErrorCode;

    VmxVmwrite64(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, Inject.Flags);

    if (DeliverErrorCode)
    {
        VmxVmwrite64(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, ErrorCode);
    }
}

VOID 
HvSuppressRipIncrement(VIRTUAL_MACHINE_STATE* VCpu)
{
    VCpu->IncrementRip = FALSE;
}

VOID
EventInjectUndefinedOpcode(VIRTUAL_MACHINE_STATE* VCpu)
{
    EventInjectInterruption(INTERRUPT_TYPE_HARDWARE_EXCEPTION, EXCEPTION_VECTOR_UNDEFINED_OPCODE, FALSE, 0);

    //
    // Suppress RIP increment
    //
    HvSuppressRipIncrement(VCpu);
}

_Use_decl_annotations_
BOOLEAN
VmxLoadVmcs(VIRTUAL_MACHINE_STATE* VCpu)
{
    int VmptrldStatus;

    VmptrldStatus = __vmx_vmptrld(&VCpu->VmcsRegionPhysicalAddress);
    if (VmptrldStatus)
    {
        LOGINF("VMCS failed to load, status : 0x%x", VmptrldStatus);
        return FALSE;
    }
    return TRUE;
}

_Use_decl_annotations_
BOOLEAN
VmxClearVmcsState(VIRTUAL_MACHINE_STATE* VCpu)
{
    UINT8 VmclearStatus;

    //
    // Clear the state of the VMCS to inactive
    //
    VmclearStatus = __vmx_vmclear(&VCpu->VmcsRegionPhysicalAddress);

    LOGINF("VMCS VMCLEAR status : 0x%x", VmclearStatus);

    if (VmclearStatus)
    {
        //
        // Otherwise terminate the VMX
        //
        LOGINF("VMCS failed to clear, status : 0x%x", VmclearStatus);
        __vmx_off();
        return FALSE;
    }
    return TRUE;
}

VOID
HvRestoreRegisters()
{
    UINT64 FsBase;
    UINT64 GsBase;
    UINT64 GdtrBase;
    UINT64 GdtrLimit;
    UINT64 IdtrBase;
    UINT64 IdtrLimit;

    //
    // Restore FS Base
    //
    __vmx_vmread(VMCS_GUEST_FS_BASE, &FsBase);
    __writemsr(IA32_FS_BASE, FsBase);

    //
    // Restore Gs Base
    //
    __vmx_vmread(VMCS_GUEST_GS_BASE, &GsBase);
    __writemsr(IA32_GS_BASE, GsBase);

    //
    // Restore GDTR
    //
    __vmx_vmread(VMCS_GUEST_GDTR_BASE, &GdtrBase);
    __vmx_vmread(VMCS_GUEST_GDTR_LIMIT, &GdtrLimit);

    AsmReloadGdtr((void*)GdtrBase, (unsigned long)GdtrLimit);

    //
    // Restore IDTR
    //
    __vmx_vmread(VMCS_GUEST_IDTR_BASE, &IdtrBase);
    __vmx_vmread(VMCS_GUEST_IDTR_LIMIT, &IdtrLimit);

    AsmReloadIdtr((void*)IdtrBase, (unsigned long)IdtrLimit);
}