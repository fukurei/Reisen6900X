//
// Summary: Implementation for Global namespace of Global.h
//

#include "Global.h"

STATUS Global::InitializeGuestState() {

    STATUS status = STAT_ERROR_UNKNOWN;
    SSIZE_T BufferSizeInByte = sizeof(VIRTUAL_MACHINE_STATE) * KeQueryActiveProcessorCount(0);

    //
    // Allocate global variable to hold Guest(s) state
    //
    if (!g_GuestState)
    {
        g_GuestState = (PVIRTUAL_MACHINE_STATE)AllocateNonPagedPool(BufferSizeInByte);

        if (!g_GuestState)
        {
            LOGERR("Err, insufficient memory\n");
            return STAT_ERROR_KNOWN;
        }
    }

    //
    // Zero the memory
    //
    RtlZeroMemory(g_GuestState, BufferSizeInByte);

    return STAT_SUCCESS;

}