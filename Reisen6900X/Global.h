//
// Summary: Global variables / structures containing VM things
//

#pragma once

#include "Common.h"

namespace Global
{

    //
    // Summary: Save state for guests
    //
    extern VIRTUAL_MACHINE_STATE* g_GuestState;

    //
    // Summary: Global Invalid MSR Bitmap
    //
    extern PVOID g_MsrBitmapInvalidMsrs;

    //
    // Summary: Stealth??
    //
    extern BOOLEAN g_TransparentMode;

    //
    // Summary: Initialize Guest State
    // Return: STAT_SUCCESS if succeed, else for not.
    //
    STATUS InitializeGuestState();

};