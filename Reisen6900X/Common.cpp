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