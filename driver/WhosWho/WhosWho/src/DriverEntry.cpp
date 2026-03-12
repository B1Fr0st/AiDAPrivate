#include <ntifs.h>
#include <Crypter.h>
#include <imports/Defs.h>
#include <function/Dispatcher.h>
#include <function/Stealth.h>
#include <function/CoreSecurity.h>
#include <function/AntiDebug.h>

// Forward declaration for network subsystem init/cleanup
namespace net_capture {
    NTSTATUS initialize(PDEVICE_OBJECT devObj);
    void cleanup();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);


    if (!SetupFunctions()) {
        return STATUS_UNSUCCESSFUL;
    }


    if (!device_names::initialize_names()) {
        return STATUS_UNSUCCESSFUL;
    }


    UNICODE_STRING deviceName = {};
    _RtlInitUnicodeString(&deviceName, device_names::get_device_name());

    PDEVICE_OBJECT deviceObject = nullptr;

    NTSTATUS status = _IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }


    UNICODE_STRING symLink = {};
    _RtlInitUnicodeString(&symLink, device_names::get_symlink_name());

    // Remove any stale symlink left by a previous failed load attempt.
    _IoDeleteSymbolicLink(&symLink);

    status = _IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        _IoDeleteDevice(deviceObject);
        return status;
    }


    SetFlag(deviceObject->Flags, DO_BUFFERED_IO);

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = dispatcher::Pilot;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = dispatcher::Pilot;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatcher::Controller;

    DriverObject->DriverUnload = nullptr;

    ClearFlag(deviceObject->Flags, DO_DEVICE_INITIALIZING);

    // Initialize network subsystem and fail fast if callout registration is broken.
    status = net_capture::initialize(deviceObject);
    if (!NT_SUCCESS(status)) {
        _IoDeleteSymbolicLink(&symLink);
        _IoDeleteDevice(deviceObject);
        return status;
    }

    stealth::ScheduleDelayedHide(DriverObject);

    signed_memory::RelocateDispatchToSignedMemory(DriverObject, 0x800);


    return STATUS_SUCCESS;
}
