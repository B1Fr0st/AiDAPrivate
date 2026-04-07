#include <ntifs.h>
#include <Crypter.h>
#include <imports/Defs.h>
#include <core/Guardian.h>


#pragma data_seg(".sntl")
volatile PVOID  g_target_driver_base   = nullptr;
volatile PVOID  g_target_driver_object = nullptr;
volatile ULONG  g_target_driver_size   = 0;
#pragma data_seg()


#pragma comment(linker, "/SECTION:.sntl,RW")


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

constexpr ULONG TAG_DEL = 'leDW';


static PDRIVER_OBJECT g_sentinel_driver_object = nullptr;
static volatile LONG  g_shutdown_flag = 0;
static HANDLE         g_init_thread_handle = nullptr;
static WCHAR          g_registry_path_buffer[512] = {};
static UNICODE_STRING g_registry_path = {};


static bool find_text_section(PVOID image_base, PVOID* out_base, ULONG* out_size) {
    if (!image_base || !_MmIsAddressValid(image_base))
        return false;

    __try {
        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(image_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(image_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {


            if (sections[i].Name[0] == '.' &&
                sections[i].Name[1] == 't' &&
                sections[i].Name[2] == 'e' &&
                sections[i].Name[3] == 'x' &&
                sections[i].Name[4] == 't') {
                *out_base = static_cast<UCHAR*>(image_base) + sections[i].VirtualAddress;
                *out_size = sections[i].Misc.VirtualSize;
                return true;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    return false;
}


static bool find_target_text(PVOID target_base, PVOID* out_text, ULONG* out_text_size) {
    return find_text_section(target_base, out_text, out_text_size);
}


static PDRIVER_OBJECT find_target_driver_object(PVOID target_base) {

    if (g_target_driver_object && _MmIsAddressValid((PVOID)g_target_driver_object))
        return static_cast<PDRIVER_OBJECT>((PVOID)g_target_driver_object);


    return nullptr;
}


static BOOLEAN ForceDeleteFileByPath(PUNICODE_STRING FilePath) {
    if (!FilePath || !FilePath->Buffer || !_ZwSetInformationFile)
        return FALSE;

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, FilePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Pre-step: clear ImageSectionObject so the file can be deleted
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
            NULL, 0);

        if (NT_SUCCESS(clearStatus) && clearHandle) {
            PFILE_OBJECT fileObj = NULL;
            clearStatus = ObReferenceObjectByHandle(
                clearHandle, 0, *IoFileObjectType, KernelMode,
                reinterpret_cast<PVOID*>(&fileObj), NULL);

            if (NT_SUCCESS(clearStatus) && fileObj) {
                PSECTION_OBJECT_POINTERS sop = fileObj->SectionObjectPointer;
                if (sop)
                    sop->ImageSectionObject = NULL;
                ObDereferenceObject(fileObj);
            }
            _ZwClose(clearHandle);
        }
    }

    // Tier 0: POSIX unlink via IoCreateFileEx + FileDispositionInformationEx
    if (_IoCreateFileEx) {
        HANDLE fileHandle = NULL;
        IO_STATUS_BLOCK ioStatus = {};
        IO_DRIVER_CREATE_CONTEXT createCtx = {};
        createCtx.Size = sizeof(createCtx);

        NTSTATUS status = _IoCreateFileEx(
            &fileHandle,
            DELETE | SYNCHRONIZE | FILE_WRITE_ATTRIBUTES,
            &objAttr, &ioStatus, NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0, CreateFileTypeNone, NULL,
            IO_IGNORE_SHARE_ACCESS_CHECK, &createCtx);

        if (NT_SUCCESS(status)) {
            struct { ULONG Flags; } dispEx = {};
            dispEx.Flags = FILE_DISPOSITION_FLAG_DELETE
                         | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
                         | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;

            status = _ZwSetInformationFile(
                fileHandle, &ioStatus,
                &dispEx, sizeof(dispEx),
                FileDispositionInformationExClass);
            _ZwClose(fileHandle);

            if (NT_SUCCESS(status))
                return TRUE;
        }
    }

    // Tier 1: ZwDeleteFile
    if (_ZwDeleteFile) {
        if (NT_SUCCESS(_ZwDeleteFile(&objAttr)))
            return TRUE;
    }

    // Tier 2: DELETE_ON_CLOSE via IoCreateFileEx
    if (_IoCreateFileEx) {
        HANDLE fileHandle = NULL;
        IO_STATUS_BLOCK ioStatus = {};
        IO_DRIVER_CREATE_CONTEXT createCtx = {};
        createCtx.Size = sizeof(createCtx);

        NTSTATUS status = _IoCreateFileEx(
            &fileHandle,
            DELETE | SYNCHRONIZE,
            &objAttr, &ioStatus, NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
            NULL, 0, CreateFileTypeNone, NULL,
            IO_IGNORE_SHARE_ACCESS_CHECK, &createCtx);

        if (NT_SUCCESS(status)) {
            _ZwClose(fileHandle);
            return TRUE;
        }
    }

    // Tier 3: standard FileDispositionInformation
    {
        HANDLE fileHandle = NULL;
        IO_STATUS_BLOCK ioStatus = {};
        NTSTATUS status = ZwCreateFile(
            &fileHandle,
            DELETE | SYNCHRONIZE,
            &objAttr, &ioStatus, NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0);

        if (!NT_SUCCESS(status))
            return FALSE;

        struct { BOOLEAN DeleteFile; } dispInfo = { TRUE };
        status = _ZwSetInformationFile(
            fileHandle, &ioStatus,
            &dispInfo, sizeof(dispInfo),
            static_cast<FILE_INFORMATION_CLASS>(13));
        _ZwClose(fileHandle);
        return NT_SUCCESS(status);
    }
}


static VOID DeleteDriverOnDisk(PUNICODE_STRING RegistryPath) {
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

    ULONG dataLen = kvInfo->DataLength;
    if (dataLen >= sizeof(WCHAR)) {
        PWCHAR imgBuf = reinterpret_cast<PWCHAR>(kvInfo->Data);
        ULONG chars = dataLen / sizeof(WCHAR);
        if (imgBuf[chars - 1] == L'\0')
            chars--;

        UNICODE_STRING imagePath;
        imagePath.Buffer = imgBuf;
        imagePath.Length = static_cast<USHORT>(chars * sizeof(WCHAR));
        imagePath.MaximumLength = static_cast<USHORT>(dataLen);

        ForceDeleteFileByPath(&imagePath);
    }

    ExFreePoolWithTag(kvInfo, TAG_DEL);
}


static void NTAPI init_thread_routine(PVOID ) {


    constexpr ULONG MAX_POLLS = 300;
    constexpr LONG64 POLL_INTERVAL = -1'000'000LL;

    LARGE_INTEGER interval;
    interval.QuadPart = POLL_INTERVAL;

    for (ULONG i = 0; i < MAX_POLLS; i++) {
        if (_InterlockedCompareExchange(&g_shutdown_flag, 0, 0))
            goto exit_thread;

        if (g_target_driver_base != nullptr)
            break;

        _KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }


    if (g_target_driver_base == nullptr)
        goto exit_thread;


    {
        PVOID target_base = (PVOID)g_target_driver_base;

        if (!_MmIsAddressValid(target_base))
            goto exit_thread;


        if (reinterpret_cast<ULONG_PTR>(target_base) < 0xFFFF800000000000ULL)
            goto exit_thread;


        PVOID target_text = nullptr;
        ULONG target_text_size = 0;
        if (!find_target_text(target_base, &target_text, &target_text_size))
            goto exit_thread;

        if (!target_text || target_text_size == 0 || target_text_size > 10 * 1024 * 1024)
            goto exit_thread;


        PDRIVER_OBJECT target_driver_obj = find_target_driver_object(target_base);


        integrity::init(target_text, target_text_size);


        if (target_driver_obj)
            dispatch_guard::snapshot(target_driver_obj);

        // Initialize PsLoadedModuleList access so dispatch_guard::verify() can
        // distinguish legitimately-loaded kernel modules (anticheat drivers) from
        // rogue pool / manually-mapped memory when a dispatch pointer changes.
        dispatch_guard::init_module_list(g_sentinel_driver_object);


        {
            PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
            if (nt_base) {
                etw_disable::init();
            }
        }


        {
            PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
            if (nt_base) {
                callback_scanner::init();
            }
        }


        {
            PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
            if (nt_base) {
                pool_scrub::init();
                pool_scrub::scrub_tags();
            }
        }


        {
            heartbeat::init(target_base,
                            g_target_driver_size ? g_target_driver_size : target_text_size * 4);
        }


        if (target_driver_obj)
            object_guard::init(target_driver_obj);


        thread_guard::ipi_clear_all_cpus();


        // Apply stealth now — runs in system thread at PASSIVE_LEVEL,
        // after DriverEntry has returned and IopLoadDriver released its locks
        self_protect::apply_stealth(g_sentinel_driver_object);


        // Delete the Sentinel driver .sys from disk
        if (g_registry_path.Buffer && g_registry_path.Length > 0)
            DeleteDriverOnDisk(&g_registry_path);


        guardian::start();
    }

exit_thread:
    _PsTerminateSystemThread(STATUS_SUCCESS);
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {


    if (!SetupFunctions())
        return STATUS_UNSUCCESSFUL;

    g_sentinel_driver_object = DriverObject;


    // Deep-copy RegistryPath for use in the init thread (the original buffer
    // is only valid for the duration of DriverEntry)
    if (RegistryPath && RegistryPath->Buffer && RegistryPath->Length > 0) {
        USHORT copy_len = RegistryPath->Length;
        if (copy_len > sizeof(g_registry_path_buffer) - sizeof(WCHAR))
            copy_len = sizeof(g_registry_path_buffer) - sizeof(WCHAR);

        RtlCopyMemory(g_registry_path_buffer, RegistryPath->Buffer, copy_len);
        g_registry_path_buffer[copy_len / sizeof(WCHAR)] = L'\0';

        g_registry_path.Buffer = g_registry_path_buffer;
        g_registry_path.Length = copy_len;
        g_registry_path.MaximumLength = sizeof(g_registry_path_buffer);
    }


    DriverObject->DriverUnload = nullptr;


    if (DriverObject->DriverSection) {
        auto ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
        ldr->Flags |= 0x20u;
    }


    PVOID own_text = nullptr;
    ULONG own_text_size = 0;
    PVOID own_base = nullptr;

    if (DriverObject->DriverSection && _MmIsAddressValid(DriverObject->DriverSection)) {
        auto ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
        own_base = ldr->DllBase;
    }

    if (own_base) {
        find_text_section(own_base, &own_text, &own_text_size);
    }


    if (own_text && own_text_size > 0)
        self_protect::init_baseline(own_text, own_text_size);


    HANDLE thread_handle = nullptr;
    NTSTATUS status = _PsCreateSystemThread(
        &thread_handle,
        THREAD_ALL_ACCESS,
        nullptr,
        nullptr,
        nullptr,
        init_thread_routine,
        nullptr);

    if (NT_SUCCESS(status) && thread_handle) {
        g_init_thread_handle = thread_handle;


        _ZwClose(thread_handle);
        g_init_thread_handle = nullptr;
    }


    return STATUS_SUCCESS;
}
