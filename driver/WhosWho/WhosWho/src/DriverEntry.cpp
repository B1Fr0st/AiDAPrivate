#include <ntifs.h>
#include <Crypter.h>
#include <imports/Defs.h>

#define SAFETY_NET_IMPLEMENT
#include <function/Dispatcher.h>
#include <function/Stealth.h>
#include <function/CoreSecurity.h>
#include <function/AntiDebug.h>
#include <function/SentinelBridge.h>
#include <function/ProcessGuard.h>
#include <function/DebugEvents.h>
#include <function/impl/driver/FileHandleScanner.h>
#include <function/KernelDebugCapture.h>

namespace net_capture {
    NTSTATUS initialize(PDEVICE_OBJECT devObj);
    void cleanup();
}

namespace debug_attach_monitor {
    VOID start();
    VOID stop();
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
    if (!FilePath) {
        return FALSE;
    }
    if (!FilePath->Buffer) {
        return FALSE;
    }
    if (!_ZwSetInformationFile) {
        return FALSE;
    }

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

            if (NT_SUCCESS(clearStatus) && fileObj) {
                PSECTION_OBJECT_POINTERS sop = fileObj->SectionObjectPointer;

                if (sop) {
                    sop->ImageSectionObject = NULL;

                } else {
                }

                ObDereferenceObject(fileObj);
            } else {
            }

            _ZwClose(clearHandle);
        } else {
        }
    }


    if (_IoCreateFileEx) {
        HANDLE fileHandle = NULL;
        IO_STATUS_BLOCK ioStatus = {};
        IO_DRIVER_CREATE_CONTEXT createCtx = {};
        createCtx.Size = sizeof(createCtx);

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

            if (NT_SUCCESS(status)) {
                return TRUE;
            }

        }
        else {
        }
    }


    if (_ZwDeleteFile) {
        NTSTATUS st = _ZwDeleteFile(&objAttr);
        if (NT_SUCCESS(st)) {
            return TRUE;
        }
    }


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
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
            NULL, 0,
            CreateFileTypeNone,
            NULL,
            IO_IGNORE_SHARE_ACCESS_CHECK,
            &createCtx
        );

        if (NT_SUCCESS(status)) {

            _ZwClose(fileHandle);
            return TRUE;
        }

    }


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

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }


    struct {
        BOOLEAN DeleteFile;
    } dispInfo = { TRUE };

    status = _ZwSetInformationFile(
        fileHandle, &ioStatus,
        &dispInfo, sizeof(dispInfo),
        (FILE_INFORMATION_CLASS)13
    );

    _ZwClose(fileHandle);

    if (NT_SUCCESS(status)) {
    } else {
    }

    return NT_SUCCESS(status);
}

static VOID DeleteDriverOnDisk(PUNICODE_STRING RegistryPath)
{
    if (!RegistryPath || !RegistryPath->Buffer) {
        return;
    }

    if (!_ZwOpenKey || !_ZwQueryValueKey || !_ZwClose) {
        return;
    }

    OBJECT_ATTRIBUTES keyAttr;
    InitializeObjectAttributes(&keyAttr, RegistryPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE keyHandle = NULL;
    NTSTATUS status = _ZwOpenKey(&keyHandle, KEY_READ, &keyAttr);
    if (!NT_SUCCESS(status)) {
        return;
    }

    UNICODE_STRING valueName;
    _RtlInitUnicodeString(&valueName, L"ImagePath");

    ULONG kvSize = 0;
    status = _ZwQueryValueKey(keyHandle, &valueName,
        KeyValuePartialInformation, NULL, 0, &kvSize);

    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        _ZwClose(keyHandle);
        return;
    }

    auto kvInfo = static_cast<PKEY_VALUE_PARTIAL_INFORMATION>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, kvSize, TAG_DEL));

    if (!kvInfo) {
        _ZwClose(keyHandle);
        return;
    }

    status = _ZwQueryValueKey(keyHandle, &valueName,
        KeyValuePartialInformation, kvInfo, kvSize, &kvSize);
    _ZwClose(keyHandle);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(kvInfo, TAG_DEL);
        return;
    }

    if (kvInfo->Type != REG_SZ && kvInfo->Type != REG_EXPAND_SZ) {
        ExFreePoolWithTag(kvInfo, TAG_DEL);
        return;
    }


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

    } else {
    }

    ExFreePoolWithTag(kvInfo, TAG_DEL);

}

static void ZeroUninitializedSectionsSelf(PVOID self_anchor)
{
    if (!self_anchor) {
        return;
    }

    ULONG_PTR cursor = reinterpret_cast<ULONG_PTR>(self_anchor) & ~(static_cast<ULONG_PTR>(0xFFF));
    PIMAGE_DOS_HEADER dos = nullptr;
    for (ULONG steps = 0; steps < 0x4000; ++steps) {
        PIMAGE_DOS_HEADER candidate = reinterpret_cast<PIMAGE_DOS_HEADER>(cursor);
        if (candidate->e_magic == IMAGE_DOS_SIGNATURE) {
            LONG nt_offset = candidate->e_lfanew;
            if (nt_offset > 0 && nt_offset < 0x1000) {
                PIMAGE_NT_HEADERS64 nt_check = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                    reinterpret_cast<UCHAR*>(candidate) + nt_offset);
                if (nt_check->Signature == IMAGE_NT_SIGNATURE &&
                    nt_check->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
                    dos = candidate;
                    break;
                }
            }
        }
        if (cursor < 0x1000) {
            return;
        }
        cursor -= 0x1000;
    }

    if (!dos) {
        return;
    }

    UCHAR* base = reinterpret_cast<UCHAR*>(dos);
    PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    USHORT count = nt->FileHeader.NumberOfSections;
    for (USHORT i = 0; i < count; ++i) {
        ULONG vsize = sec[i].Misc.VirtualSize;
        ULONG rsize = sec[i].SizeOfRawData;
        if (vsize > rsize) {
            UCHAR* dst = base + sec[i].VirtualAddress + rsize;
            ULONG diff = vsize - rsize;
            RtlZeroMemory(dst, diff);
        }
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

    dbg_capture::write_immediate_formatted("[WW-EARLY] DriverEntry entered driver_object_present=%u registry_path_present=%u\n",
        DriverObject != nullptr ? 1u : 0u,
        RegistryPath != nullptr ? 1u : 0u);
    ZeroUninitializedSectionsSelf(reinterpret_cast<PVOID>(&DriverEntry));
    dbg_capture::write_immediate_formatted("[WW-EARLY] SetupFunctions begin\n");

    if (!SetupFunctions()) {
        dbg_capture::write_immediate_formatted("[WW-EARLY] SetupFunctions FAILED\n");
        return STATUS_UNSUCCESSFUL;
    }

    dbg_capture::write_immediate_formatted("[WW-EARLY] SetupFunctions OK\n");

    dbg_capture::initialize();

    WW_LOG("DriverEntry: SetupFunctions OK");

    if (!device_names::initialize_names()) {
        WW_LOG("DriverEntry: initialize_names FAILED");
        return STATUS_UNSUCCESSFUL;
    }

    WW_LOG("DriverEntry: device names initialized");

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
        WW_LOG("DriverEntry: IoCreateDevice FAILED status=0x%08lx", status);
        return status;
    }

    WW_LOG("DriverEntry: device created present=%u", deviceObject != nullptr ? 1u : 0u);

    UNICODE_STRING symLink = {};
    _RtlInitUnicodeString(&symLink, device_names::get_symlink_name());

    _IoDeleteSymbolicLink(&symLink);

    status = _IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        WW_LOG("DriverEntry: IoCreateSymbolicLink FAILED status=0x%08lx", status);
        _IoDeleteDevice(deviceObject);
        return status;
    }

    WW_LOG("DriverEntry: symlink created");

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
        WW_LOG("DriverEntry: net_capture::initialize FAILED status=0x%08lx", status);
        _IoDeleteSymbolicLink(&symLink);
        _IoDeleteDevice(deviceObject);
        return status;
    }

    WW_LOG("DriverEntry: net_capture initialized");


    if (DriverObject->DriverSection) {
        auto ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
        PVOID base = ldr->DllBase;
        WW_LOG("DriverEntry: DriverSection base_present=%u SizeOfImage=0x%lx", base != nullptr ? 1u : 0u, ldr->SizeOfImage);
        if (base && _MmIsAddressValid(base)) {
            PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(base);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                    static_cast<UCHAR*>(base) + dos->e_lfanew);
                if (_MmIsAddressValid(nt) && nt->Signature == IMAGE_NT_SIGNATURE) {
                    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
                    bool found_text = false;
                    WW_LOG("DriverEntry: PE valid, %u sections", nt->FileHeader.NumberOfSections);
                    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                        WW_LOG("DriverEntry: section[%u] name=%.8s VA=0x%lx size=0x%lx",
                            i, sec[i].Name, sec[i].VirtualAddress, sec[i].Misc.VirtualSize);
                        if (sec[i].Name[0] == '.' && sec[i].Name[1] == 't' &&
                            sec[i].Name[2] == 'e' && sec[i].Name[3] == 'x' &&
                            sec[i].Name[4] == 't') {
                            PVOID text_base = static_cast<UCHAR*>(base) + sec[i].VirtualAddress;
                            ULONG text_size = sec[i].Misc.VirtualSize;
                            WW_LOG("DriverEntry: .text found present=%u size=0x%lx", text_base != nullptr ? 1u : 0u, text_size);
                            sentinel_bridge::init(text_base, text_size);
                            found_text = true;
                            break;
                        }
                    }
                    if (!found_text) {
                        WW_LOG("DriverEntry: .text section NOT FOUND");
                    }
                } else {
                    WW_LOG("DriverEntry: NT headers invalid");
                }
            } else {
                WW_LOG("DriverEntry: DOS signature invalid");
            }
        } else {
            WW_LOG("DriverEntry: base invalid or not valid address present=%u", base != nullptr ? 1u : 0u);
        }
    } else {
        WW_LOG("DriverEntry: DriverSection is NULL");
    }

    WW_LOG("DriverEntry: starting watchdog...");
    if (!dispatcher::verify_dispatch_integrity(DriverObject)) {
        WW_LOG("DriverEntry: dispatch integrity check FAILED before watchdog start");
        _IoDeleteSymbolicLink(&symLink);
        _IoDeleteDevice(deviceObject);
        return STATUS_ACCESS_DENIED;
    }
    sentinel_bridge::start_watchdog();

    sentinel_bridge::allocate_evidence_blob();
    anti_debug::initialize_kd_baseline();
    debug_attach_monitor::start();
    anti_dma_canary::init_timer();
    file_handle_scanner::start(30);

    NTSTATUS ob_status = process_guard::init();
    WW_LOG("DriverEntry: process_guard::init returned 0x%08lx", ob_status);

    NTSTATUS dbe_status = debug_events::initialize();
    WW_LOG("DriverEntry: debug_events::initialize returned 0x%08lx", dbe_status);

    WW_LOG("DriverEntry: invoking malware_safe::init (after process_guard)...");
    NTSTATUS ms_status = malware_safe::init(DriverObject);
    if (!NT_SUCCESS(ms_status) && ms_status != STATUS_ALREADY_REGISTERED) {
        WW_LOG("DriverEntry: malware_safe::init FAILED 0x%08lx - continuing with malware-safe gating DISABLED",
            ms_status);
    } else {
        WW_LOG("DriverEntry: malware_safe::init OK status=0x%08lx callback_registered=%d create_notify_registered=%d",
            ms_status,
            malware_safe::g_registry_callback_registered,
            malware_safe::g_create_notify_registered);
    }

    WW_LOG("DriverEntry: scheduling stealth hide...");
    stealth::ScheduleDelayedHide(DriverObject);

    if (!hvci_detect::is_hvci_enabled()) {
        WW_LOG("DriverEntry: HVCI not enabled, relocating dispatch to signed memory");
        signed_memory::RelocateDispatchToSignedMemory(DriverObject, 0x800);
    } else {
        WW_LOG("DriverEntry: HVCI enabled, skipping signed memory relocation");
    }

    WW_LOG("DriverEntry: deleting driver on disk...");
    DeleteDriverOnDisk(RegistryPath);

    WW_LOG("DriverEntry: COMPLETE, bridge_present=1 magic_set=%u whoswho_tsc=%lld sentinel_tsc=%lld",
        sentinel_bridge::g_bridge.magic != 0 ? 1u : 0u,
        sentinel_bridge::g_bridge.whoswho_tsc, sentinel_bridge::g_bridge.sentinel_tsc);

    return STATUS_SUCCESS;
}
