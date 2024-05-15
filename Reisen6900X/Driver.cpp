//
// Summary: The main entry of driver
//

#include "VMX.h"

VOID DriverExit(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	return;
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverExit;

	if (Global::InitializeGuestState()) {
		LOGERR("Something went wrong");
		return STATUS_UNSUCCESSFUL;
	}

	if (VMX::InitializeVMX()) {
		LOGERR("Something went wrong");
		return STATUS_UNSUCCESSFUL;
	}

	LOGINF("Test success!");

	return STATUS_SUCCESS;
}