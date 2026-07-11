#pragma once
#include <imports/Defs.h>
#include <core/Heartbeat.h>
#include <core/ObjectGuard.h>
#include <core/ThreadGuard.h>
#include <core/DriverLoadAudit.h>

namespace process_notify {

    inline volatile LONG g_registered = 0;
    inline volatile LONG g_image_registered = 0;
    inline volatile LONG g_registered_ex = 0;

    inline volatile HANDLE g_protected_pid = nullptr;

    inline NTSTATUS (NTAPI* _pfn_ZwCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    inline NTSTATUS (NTAPI* _pfn_ZwReadFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    inline NTSTATUS (NTAPI* _pfn_ZwQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
    inline volatile LONG g_dynamic_funcs_resolved = 0;

    inline volatile LONG g_process_hidden = 0;
    inline LIST_ENTRY g_saved_active_links = {};
    inline KSPIN_LOCK g_hide_lock = {};

    struct ce_driver_name_t {
        const char* name;
        int         len;
    };

    constexpr ce_driver_name_t g_ce_driver_names[] = {
        { "DBK64.sys",     10 },
        { "DBK32.sys",     10 },
        { "ceserver.sys",  13 },
        { "ce_driver",      9 },
        { "cedriver",       9 },
        { "mod_driver",    10 },
        { "moddriver",      9 },
        { "PROCEXP152",    11 },
        { "PROCEXP",         7 },
        { "physmem",         7 },
        { "rdpdr",           5 },
    };
    constexpr int g_ce_driver_name_count = sizeof(g_ce_driver_names) / sizeof(g_ce_driver_names[0]);

    struct ce_driver_hash_t {
        UINT8 hash[32];
    };

    inline ce_driver_hash_t g_ce_driver_hashes[32] = {};
    inline volatile LONG g_ce_driver_hash_count = 0;
    inline KSPIN_LOCK g_ce_hash_lock = {};

    __forceinline bool resolve_dynamic_funcs() {
        if (_InterlockedCompareExchange(&g_dynamic_funcs_resolved, 1, 0) == 1)
            return true;

        PVOID kernelBase = (PVOID)get_nt_base();
        if (!kernelBase) return false;

        *(PVOID*)&_pfn_ZwCreateFile = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwCreateFile"));
        *(PVOID*)&_pfn_ZwReadFile = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwReadFile"));
        *(PVOID*)&_pfn_ZwQueryInformationFile = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwQueryInformationFile"));

        SN_LOG("process_notify: dynamic funcs ZwCreateFile=%p ZwReadFile=%p ZwQueryInformationFile=%p",
            _pfn_ZwCreateFile, _pfn_ZwReadFile, _pfn_ZwQueryInformationFile);

        return _pfn_ZwCreateFile && _pfn_ZwReadFile && _pfn_ZwQueryInformationFile;
    }

    __forceinline ULONG_PTR resolve_active_process_links_offset() {
        RTL_OSVERSIONINFOW ver = {};
        ver.dwOSVersionInfoSize = sizeof(ver);
        if (!_RtlGetVersion || !NT_SUCCESS(_RtlGetVersion(&ver)))
            return 0;

        if (ver.dwBuildNumber >= 26100) return 0x1D8;
        if (ver.dwBuildNumber >= 19041) return 0x448;
        if (ver.dwBuildNumber >= 17763) return 0x448;
        return 0;
    }

    __forceinline bool compute_file_sha256(const wchar_t* file_path, UINT8 out_hash[32]) {
        if (!_pfn_ZwCreateFile || !_pfn_ZwReadFile || !_pfn_ZwQueryInformationFile)
            return false;
        if (!file_path)
            return false;

        UNICODE_STRING path_u = {};
        _RtlInitUnicodeString(&path_u, file_path);

        OBJECT_ATTRIBUTES oa = {};
        InitializeObjectAttributes(&oa, &path_u,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            nullptr, nullptr);

        IO_STATUS_BLOCK iosb = {};
        HANDLE file_handle = nullptr;
        NTSTATUS st = _pfn_ZwCreateFile(
            &file_handle,
            FILE_READ_DATA | SYNCHRONIZE,
            &oa, &iosb, nullptr,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            nullptr, 0);

        if (!NT_SUCCESS(st) || !file_handle) {
            SN_LOG("process_notify: ZwCreateFile FAIL 0x%08lx path=%ws", st, file_path);
            return false;
        }

        IO_STATUS_BLOCK size_iosb = {};
        FILE_STANDARD_INFORMATION file_info = {};
        st = _pfn_ZwQueryInformationFile(
            file_handle, &size_iosb,
            &file_info, sizeof(file_info),
            FileStandardInformation);

        if (!NT_SUCCESS(st)) {
            SN_LOG("process_notify: ZwQueryInformationFile FAIL 0x%08lx", st);
            _ZwClose(file_handle);
            return false;
        }

        if (file_info.EndOfFile.QuadPart <= 0 || file_info.EndOfFile.QuadPart > (16 * 1024 * 1024)) {
            SN_LOG("process_notify: file size invalid %lld", file_info.EndOfFile.QuadPart);
            _ZwClose(file_handle);
            return false;
        }

        ULONG file_size = static_cast<ULONG>(file_info.EndOfFile.QuadPart);
        PVOID read_buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, file_size, 'hceS');
        if (!read_buffer) {
            _ZwClose(file_handle);
            return false;
        }

        kernel_crypto::sha256_ctx_t sha_ctx = {};
        kernel_crypto::sha256_init(&sha_ctx);

        ULONG total_read = 0;
        LARGE_INTEGER byte_offset = {};
        byte_offset.QuadPart = 0;
        const ULONG CHUNK_SIZE = 65536;
        UINT8 chunk[CHUNK_SIZE];

        while (total_read < file_size) {
            ULONG to_read = file_size - total_read;
            if (to_read > CHUNK_SIZE) to_read = CHUNK_SIZE;

            IO_STATUS_BLOCK read_iosb = {};
            st = _pfn_ZwReadFile(
                file_handle, nullptr, nullptr, nullptr,
                &read_iosb, chunk, to_read, &byte_offset, nullptr);

            if (!NT_SUCCESS(st)) {
                SN_LOG("process_notify: ZwReadFile FAIL 0x%08lx at offset %u", st, total_read);
                break;
            }

            ULONG bytes_read = static_cast<ULONG>(read_iosb.Information);
            if (bytes_read == 0) break;

            kernel_crypto::sha256_update(&sha_ctx, chunk, bytes_read);
            total_read += bytes_read;
            byte_offset.QuadPart = total_read;
        }

        _ZwClose(file_handle);

        bool success = (total_read == file_size);
        if (success) {
            kernel_crypto::sha256_final(&sha_ctx, out_hash);
            SN_LOG("process_notify: SHA-256 computed bytes=%u", total_read);
        } else {
            SN_LOG("process_notify: SHA-256 FAIL read %u/%u", total_read, file_size);
        }

        RtlSecureZeroMemory(&sha_ctx, sizeof(sha_ctx));
        RtlSecureZeroMemory(chunk, sizeof(chunk));
        ExFreePoolWithTag(read_buffer, 'hceS');
        return success;
    }

    __forceinline bool match_driver_name_ci(const UCHAR* name, int name_len, const char* target, int target_len) {
        if (name_len < target_len)
            return false;
        for (int i = 0; i < target_len; ++i) {
            char a = (char)(name[i] | 0x20);
            char b = (char)(target[i] | 0x20);
            if (a != b) return false;
        }
        return true;
    }

    __forceinline bool is_ce_driver_name(const UCHAR* name, int name_len) {
        for (int i = 0; i < g_ce_driver_name_count; ++i) {
            if (match_driver_name_ci(name, name_len, g_ce_driver_names[i].name, g_ce_driver_names[i].len))
                return true;
        }
        return false;
    }

    __forceinline bool hash_matches_ce_list(const UINT8 hash[32]) {
        KIRQL old_irql;
        KeAcquireSpinLock(&g_ce_hash_lock, &old_irql);
        LONG count = g_ce_driver_hash_count;
        bool match = false;
        for (LONG i = 0; i < count && i < 32; ++i) {
            if (RtlEqualMemory(hash, g_ce_driver_hashes[i].hash, 32)) {
                match = true;
                break;
            }
        }
        KeReleaseSpinLock(&g_ce_hash_lock, old_irql);
        return match;
    }

    __forceinline void update_ce_driver_hashes(const UINT8* hash_data, ULONG hash_count) {
        if (!hash_data || hash_count == 0)
            return;
        if (hash_count > 32)
            hash_count = 32;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_ce_hash_lock, &old_irql);

        RtlZeroMemory(g_ce_driver_hashes, sizeof(g_ce_driver_hashes));
        for (ULONG i = 0; i < hash_count; ++i) {
            RtlCopyMemory(g_ce_driver_hashes[i].hash, hash_data + (i * 32), 32);
        }
        _InterlockedExchange(&g_ce_driver_hash_count, static_cast<LONG>(hash_count));

        KeReleaseSpinLock(&g_ce_hash_lock, old_irql);
        SN_LOG("process_notify: update_ce_driver_hashes count=%lu", hash_count);
    }

    __forceinline HANDLE get_effective_protected_pid() {
        HANDLE bridge_pid = heartbeat::get_bridge_protected_pid();
        if (bridge_pid)
            return bridge_pid;
        return reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&g_protected_pid), 0, 0));
    }

    __forceinline UINT64 compute_driver_name_hash(const UCHAR* name, int name_len) {
        UINT64 hash = 14695981039346656037ULL;
        for (int i = 0; i < name_len; ++i) {
            hash ^= static_cast<UINT8>(name[i] | 0x20);
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    __forceinline void detect_ce_driver() {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return;
        if (!resolve_dynamic_funcs())
            return;

        ULONG required_size = 0;
        ZwQuerySystemInformation(
            SystemModuleInformationInternal,
            nullptr, 0, &required_size);
        if (required_size == 0)
            return;

        required_size += sizeof(RTL_PROCESS_MODULE_INFORMATION) * 16;
        PRTL_PROCESS_MODULES modules = static_cast<PRTL_PROCESS_MODULES>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, required_size, 'ceDM'));
        if (!modules)
            return;

        NTSTATUS st = ZwQuerySystemInformation(
            SystemModuleInformationInternal,
            modules, required_size, nullptr);
        if (!NT_SUCCESS(st)) {
            ExFreePoolWithTag(modules, 'ceDM');
            SN_LOG("process_notify: detect_ce_driver ZwQuerySystemInformation FAIL 0x%08lx", st);
            return;
        }

        SN_LOG("process_notify: detect_ce_driver scanning %lu modules", modules->NumberOfModules);

        for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
            const UCHAR* full_path = modules->Modules[i].FullPathName;
            ULONG path_len = 0;
            while (path_len < 256 && full_path[path_len] != 0) ++path_len;

            USHORT name_start = modules->Modules[i].OffsetToFileName;
            const UCHAR* drv_name = full_path + name_start;
            int drv_name_len = static_cast<int>(path_len - name_start);

            if (!is_ce_driver_name(drv_name, drv_name_len))
                continue;

            SN_LOG("process_notify: CE driver name match '%.*s' -- hashing file",
                drv_name_len, drv_name);

            wchar_t wide_path[260] = {};
            for (ULONG j = 0; j < path_len && j < 259; ++j)
                wide_path[j] = (wchar_t)full_path[j];

            UINT8 file_hash[32] = {};
            bool hash_ok = compute_file_sha256(wide_path, file_hash);

            if (hash_ok) {
                bool hash_match = hash_matches_ce_list(file_hash);
                if (hash_match) {
                    SN_LOG("process_notify: CE driver HASH MATCH -- BSOD driver='%.*s'",
                        drv_name_len, drv_name);
                    driver_load_audit::record(
                        compute_driver_name_hash(drv_name, drv_name_len),
                        reinterpret_cast<UINT64>(modules->Modules[i].ImageBase),
                        modules->Modules[i].ImageSize,
                        3);
                    ExFreePoolWithTag(modules, 'ceDM');
#ifndef AIDA_DEV_MODE
                    if (_KeBugCheckEx) {
                        _KeBugCheckEx(0xA1DA0007,
                            (ULONG_PTR)i,
                            (ULONG_PTR)modules->Modules[i].ImageBase,
                            0, 0);
                    }
#endif
                    return;
                }

                SN_LOG("process_notify: CE driver name match but hash NOT in list -- tier 1 log '%.*s'",
                    drv_name_len, drv_name);
                driver_load_audit::record(
                    compute_driver_name_hash(drv_name, drv_name_len),
                    reinterpret_cast<UINT64>(modules->Modules[i].ImageBase),
                    modules->Modules[i].ImageSize,
                    1);
                heartbeat::send_command(heartbeat::BRIDGE_CMD_HOSTILE_DRIVER,
                    static_cast<ULONG>(i));
            } else {
                SN_LOG("process_notify: CE driver name match but hash FAIL -- BSOD (high confidence) '%.*s'",
                    drv_name_len, drv_name);

                const char* high_confidence_names[] = { "DBK64.sys", "DBK32.sys", "ceserver.sys" };
                bool high_confidence = false;
                for (int j = 0; j < 3; ++j) {
                    int hlen = 0;
                    while (high_confidence_names[j][hlen]) ++hlen;
                    if (match_driver_name_ci(drv_name, drv_name_len, high_confidence_names[j], hlen)) {
                        high_confidence = true;
                        break;
                    }
                }

                if (high_confidence) {
                    driver_load_audit::record(
                        compute_driver_name_hash(drv_name, drv_name_len),
                        reinterpret_cast<UINT64>(modules->Modules[i].ImageBase),
                        modules->Modules[i].ImageSize,
                        3);
                    ExFreePoolWithTag(modules, 'ceDM');
#ifndef AIDA_DEV_MODE
                    if (_KeBugCheckEx) {
                        _KeBugCheckEx(0xA1DA0007,
                            (ULONG_PTR)i,
                            (ULONG_PTR)modules->Modules[i].ImageBase,
                            0, 0);
                    }
#endif
                    return;
                }

                driver_load_audit::record(
                    compute_driver_name_hash(drv_name, drv_name_len),
                    reinterpret_cast<UINT64>(modules->Modules[i].ImageBase),
                    modules->Modules[i].ImageSize,
                    1);
                heartbeat::send_command(heartbeat::BRIDGE_CMD_HOSTILE_DRIVER,
                    static_cast<ULONG>(i));
            }
        }

        ExFreePoolWithTag(modules, 'ceDM');
        SN_LOG("process_notify: detect_ce_driver scan complete");
    }

    __forceinline NTSTATUS hide_aida_process() {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return STATUS_INVALID_DEVICE_STATE;

        HANDLE prot_pid = get_effective_protected_pid();
        if (!prot_pid)
            return STATUS_NOT_FOUND;

        ULONG_PTR links_offset = resolve_active_process_links_offset();
        if (links_offset == 0)
            return STATUS_NOT_SUPPORTED;

        PEPROCESS proc = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId(prot_pid, &proc);
        if (!NT_SUCCESS(st) || !proc)
            return st;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_hide_lock, &old_irql);

        if (_InterlockedCompareExchange(&g_process_hidden, 1, 0) != 0) {
            KeReleaseSpinLock(&g_hide_lock, old_irql);
            _ObfDereferenceObject(proc);
            return STATUS_ALREADY_COMPLETE;
        }

        NTSTATUS result = STATUS_SUCCESS;
        __try {
            PLIST_ENTRY links = reinterpret_cast<PLIST_ENTRY>(
                reinterpret_cast<UINT8*>(proc) + links_offset);

            if (!_MmIsAddressValid(links)) {
                result = STATUS_INVALID_ADDRESS;
                _InterlockedExchange(&g_process_hidden, 0);
            } else {
                g_saved_active_links.Flink = links->Flink;
                g_saved_active_links.Blink = links->Blink;

                if (links->Flink && links->Blink) {
                    links->Blink->Flink = links->Flink;
                    links->Flink->Blink = links->Blink;
                    links->Flink = links;
                    links->Blink = links;
                }

                SN_LOG("process_notify: hide_aida_process SUCCESS pid=%llu links_offset=0x%llx",
                    (UINT64)(ULONG_PTR)prot_pid, (UINT64)links_offset);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            result = STATUS_UNSUCCESSFUL;
            _InterlockedExchange(&g_process_hidden, 0);
        }

        KeReleaseSpinLock(&g_hide_lock, old_irql);
        _ObfDereferenceObject(proc);
        return result;
    }

    __forceinline NTSTATUS unhide_aida_process() {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return STATUS_INVALID_DEVICE_STATE;

        HANDLE prot_pid = get_effective_protected_pid();
        if (!prot_pid)
            return STATUS_NOT_FOUND;

        ULONG_PTR links_offset = resolve_active_process_links_offset();
        if (links_offset == 0)
            return STATUS_NOT_SUPPORTED;

        PEPROCESS proc = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId(prot_pid, &proc);
        if (!NT_SUCCESS(st) || !proc)
            return st;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_hide_lock, &old_irql);

        if (_InterlockedCompareExchange(&g_process_hidden, 0, 1) != 1) {
            KeReleaseSpinLock(&g_hide_lock, old_irql);
            _ObfDereferenceObject(proc);
            return STATUS_ALREADY_COMPLETE;
        }

        NTSTATUS result = STATUS_SUCCESS;
        __try {
            PLIST_ENTRY links = reinterpret_cast<PLIST_ENTRY>(
                reinterpret_cast<UINT8*>(proc) + links_offset);

            if (!_MmIsAddressValid(links)) {
                result = STATUS_INVALID_ADDRESS;
            } else if (g_saved_active_links.Flink && g_saved_active_links.Blink) {
                links->Flink = g_saved_active_links.Flink;
                links->Blink = g_saved_active_links.Blink;
                links->Flink->Blink = links;
                links->Blink->Flink = links;

                g_saved_active_links.Flink = nullptr;
                g_saved_active_links.Blink = nullptr;

                SN_LOG("process_notify: unhide_aida_process SUCCESS pid=%llu",
                    (UINT64)(ULONG_PTR)prot_pid);
            } else {
                result = STATUS_INVALID_PARAMETER;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            result = STATUS_UNSUCCESSFUL;
        }

        KeReleaseSpinLock(&g_hide_lock, old_irql);
        _ObfDereferenceObject(proc);
        return result;
    }

    struct tool_sig_t {
        const char* prefix;
        int         len;
    };

    __forceinline bool match_prefix_ci(const UCHAR* name, const char* prefix, int prefix_len) {
        for (int i = 0; i < prefix_len; ++i) {
            char a = static_cast<char>(name[i] | 0x20);
            char b = static_cast<char>(prefix[i] | 0x20);
            if (a != b) return false;
        }
        return true;
    }

    static VOID process_create_callback_ex(
        PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO create_info)
    {
        UNREFERENCED_PARAMETER(process);

        if (!create_info) {
            HANDLE prot_pid = get_effective_protected_pid();
            if (prot_pid && pid == prot_pid) {
                LONG64 previous = _InterlockedCompareExchange64(
                    reinterpret_cast<volatile LONG64*>(&g_protected_pid), 0,
                    reinterpret_cast<LONG64>(prot_pid));
                if (previous == reinterpret_cast<LONG64>(prot_pid)) {
                    object_guard::set_protected_pid(nullptr);
                    SN_LOG("process_notify: protected_pid exited and cleared pid=%llu", (UINT64)(ULONG_PTR)pid);
                }
            }
            return;
        }

        HANDLE prot_pid = get_effective_protected_pid();
        if (!prot_pid)
            return;

        if (!create_info->ImageFileName || !create_info->ImageFileName->Buffer)
            return;

        __try {
            PCUNICODE_STRING img = create_info->ImageFileName;
            USHORT chars = img->Length / sizeof(WCHAR);
            USHORT name_start = chars;
            for (USHORT i = chars; i > 0; --i) {
                if (img->Buffer[i - 1] == L'\\' || img->Buffer[i - 1] == L'/') {
                    name_start = i;
                    break;
                }
            }

            char narrow[64] = {};
            USHORT copy_len = chars - name_start;
            if (copy_len > 63) copy_len = 63;
            for (USHORT i = 0; i < copy_len; ++i)
                narrow[i] = (char)(img->Buffer[name_start + i] & 0x7F);

            UNREFERENCED_PARAMETER(narrow);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    static VOID process_create_callback(HANDLE, HANDLE pid, BOOLEAN create) {
        if (!create) {
            HANDLE prot_pid = get_effective_protected_pid();
            if (prot_pid && pid == prot_pid) {
                LONG64 previous = _InterlockedCompareExchange64(
                    reinterpret_cast<volatile LONG64*>(&g_protected_pid), 0,
                    reinterpret_cast<LONG64>(prot_pid));
                if (previous == reinterpret_cast<LONG64>(prot_pid)) {
                    object_guard::set_protected_pid(nullptr);
                    SN_LOG("process_notify: protected_pid legacy exit cleared pid=%llu", (UINT64)(ULONG_PTR)pid);
                }
            }
            return;
        }

        HANDLE prot_pid = get_effective_protected_pid();
        if (!prot_pid)
            return;

        __try {
            PEPROCESS proc = nullptr;
            NTSTATUS st = PsLookupProcessByProcessId(pid, &proc);
            if (!NT_SUCCESS(st) || !proc)
                return;

            UCHAR* name = PsGetProcessImageFileName(proc);
            UNREFERENCED_PARAMETER(name);
            _ObfDereferenceObject(proc);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    __forceinline void set_protected_pid(HANDLE pid) {
        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_protected_pid),
            reinterpret_cast<LONG64>(pid));
        object_guard::set_protected_pid(pid);
        SN_LOG("process_notify: protected_pid set to %llu", (UINT64)(ULONG_PTR)pid);
    }

    struct suspicious_dll_t {
        const char* name;
        int         len;
    };

    constexpr suspicious_dll_t g_suspicious_dlls[] = {
        { "frida",      5 },
        { "titanh",     6 },
        { "hyperdbg",   8 },
        { "dbghelp",    7 },
        { "symsrv",     6 },
        { "minhook",    7 },
        { "detours",    7 },
        { "easyhook",   8 },
        { "polyhook",   8 },
        { "inject",     6 },
        { "cedll",      5 },
        { "cedll64",    7 },
        { "cehook",     6 },
        { "ceserver",   8 },
        { "luaclient",  9 },
        { "celua",      5 },
        { "vivalaflex", 10 },
        { "artmoney",   8 },
        { "memrecon",   8 },
        { "dumpchk",    7 },
    };
    constexpr int g_num_suspicious_dlls = sizeof(g_suspicious_dlls) / sizeof(g_suspicious_dlls[0]);

    static VOID image_load_callback(
        PUNICODE_STRING FullImageName,
        HANDLE ProcessId,
        PIMAGE_INFO ImageInfo)
    {
        UNREFERENCED_PARAMETER(ImageInfo);

        if (FullImageName && FullImageName->Buffer && FullImageName->Length > 0) {
            USHORT chars = FullImageName->Length / sizeof(WCHAR);
            USHORT name_start = chars;
            for (USHORT i = chars; i > 0; --i) {
                if (FullImageName->Buffer[i - 1] == L'\\' || FullImageName->Buffer[i - 1] == L'/') {
                    name_start = i;
                    break;
                }
            }

            char narrow[64] = {};
            USHORT copy_len = chars - name_start;
            if (copy_len > 63) copy_len = 63;
            for (USHORT i = 0; i < copy_len; ++i) {
                narrow[i] = (char)(FullImageName->Buffer[name_start + i] & 0x7F);
            }

            if (!ProcessId) {
                if (copy_len >= 4) {
                    char ext[4] = {};
                    for (int i = 0; i < 4; ++i)
                        ext[i] = (char)(narrow[copy_len - 4 + i] | 0x20);

                    if (ext[0] == '.' && ext[1] == 's' && ext[2] == 'y' && ext[3] == 's') {
                        if (is_ce_driver_name((const UCHAR*)narrow, static_cast<int>(copy_len))) {
                            SN_LOG("process_notify: CE driver loading into kernel '%.*s' -- hashing",
                                static_cast<int>(copy_len), narrow);

                            wchar_t wide_path[260] = {};
                            for (USHORT i = 0; i < chars && i < 259; ++i)
                                wide_path[i] = FullImageName->Buffer[i];

                            UINT8 file_hash[32] = {};
                            bool hash_ok = compute_file_sha256(wide_path, file_hash);

                            if (hash_ok && hash_matches_ce_list(file_hash)) {
                                SN_LOG("process_notify: CE driver HASH MATCH at load -- BSOD '%.*s'",
                                    static_cast<int>(copy_len), narrow);
                                driver_load_audit::record(
                                    compute_driver_name_hash((const UCHAR*)narrow, static_cast<int>(copy_len)),
                                    reinterpret_cast<UINT64>(ImageInfo->ImageBase),
                                    ImageInfo->ImageSize,
                                    3);
                                hide_aida_process();
#ifndef AIDA_DEV_MODE
                                if (_KeBugCheckEx) {
                                    _KeBugCheckEx(0xA1DA0007,
                                        (ULONG_PTR)ProcessId,
                                        (ULONG_PTR)ImageInfo->ImageBase,
                                        0, 0);
                                }
#endif
                                return;
                            }

                            const char* high_confidence[] = { "DBK64.sys", "DBK32.sys", "ceserver.sys" };
                            bool high = false;
                            for (int j = 0; j < 3; ++j) {
                                int hlen = 0;
                                while (high_confidence[j][hlen]) ++hlen;
                                if (match_driver_name_ci((const UCHAR*)narrow,
                                    static_cast<int>(copy_len),
                                    high_confidence[j], hlen)) {
                                    high = true;
                                    break;
                                }
                            }

                            if (high) {
                                SN_LOG("process_notify: CE high-confidence driver at load -- BSOD '%.*s'",
                                    static_cast<int>(copy_len), narrow);
                                driver_load_audit::record(
                                    compute_driver_name_hash((const UCHAR*)narrow, static_cast<int>(copy_len)),
                                    reinterpret_cast<UINT64>(ImageInfo->ImageBase),
                                    ImageInfo->ImageSize,
                                    3);
                                hide_aida_process();
#ifndef AIDA_DEV_MODE
                                if (_KeBugCheckEx) {
                                    _KeBugCheckEx(0xA1DA0007,
                                        (ULONG_PTR)ProcessId,
                                        (ULONG_PTR)ImageInfo->ImageBase,
                                        0, 0);
                                }
#endif
                                return;
                            }

                            driver_load_audit::record(
                                compute_driver_name_hash((const UCHAR*)narrow, static_cast<int>(copy_len)),
                                reinterpret_cast<UINT64>(ImageInfo->ImageBase),
                                ImageInfo->ImageSize,
                                1);
                            heartbeat::send_command(heartbeat::BRIDGE_CMD_HOSTILE_DRIVER, 0);
                        }
                    }
                }
            }
        }

        HANDLE prot_pid = get_effective_protected_pid();
        if (!prot_pid || ProcessId != prot_pid)
            return;

        if (!FullImageName || !FullImageName->Buffer || FullImageName->Length == 0)
            return;

        __try {
            USHORT chars = FullImageName->Length / sizeof(WCHAR);
            USHORT name_start = chars;
            for (USHORT i = chars; i > 0; --i) {
                if (FullImageName->Buffer[i - 1] == L'\\' || FullImageName->Buffer[i - 1] == L'/') {
                    name_start = i;
                    break;
                }
            }

            char narrow[64] = {};
            USHORT copy_len = chars - name_start;
            if (copy_len > 63) copy_len = 63;
            for (USHORT i = 0; i < copy_len; ++i) {
                narrow[i] = (char)(FullImageName->Buffer[name_start + i] & 0x7F);
            }

            for (int d = 0; d < g_num_suspicious_dlls; ++d) {
                if (match_prefix_ci((const UCHAR*)narrow, g_suspicious_dlls[d].name, g_suspicious_dlls[d].len)) {
                    SN_LOG("process_notify: SUSPICIOUS DLL loaded into protected process: %.60s pid=%llu",
                        narrow, (UINT64)(ULONG_PTR)ProcessId);
                    heartbeat::send_command(heartbeat::BRIDGE_CMD_DUMP_TOOL_FOUND,
                        static_cast<ULONG>((ULONG_PTR)ProcessId & 0xFFFFFFFF));
                    return;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    inline volatile LONG g_thread_notify_registered = 0;

    static VOID thread_create_callback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
        if (!Create)
            return;

        HANDLE prot_pid = get_effective_protected_pid();
        if (!prot_pid || ProcessId != prot_pid)
            return;

        HANDLE caller_pid = PsGetCurrentProcessId();
        if (caller_pid == prot_pid)
            return;
        if ((ULONG_PTR)caller_pid == 4)
            return;
        if ((ULONG_PTR)caller_pid == 0)
            return;

        SN_LOG("process_notify: REMOTE_THREAD detected protected_pid=%llu creator_pid=%llu tid=%llu",
            (UINT64)(ULONG_PTR)ProcessId,
            (UINT64)(ULONG_PTR)caller_pid,
            (UINT64)(ULONG_PTR)ThreadId);

        targeting_latch::latch_targeting(
            targeting_latch::RE_REASON_OB_CREATE_THREAD,
            (UINT64)(ULONG_PTR)caller_pid,
            (UINT64)(ULONG_PTR)ThreadId,
            0, 0
        );

        heartbeat::send_command(heartbeat::BRIDGE_CMD_DUMP_TOOL_FOUND,
            static_cast<ULONG>((ULONG_PTR)caller_pid & 0xFFFFFFFF));

        thread_guard::detect_remote_thread_injection(ProcessId, ThreadId);

        hide_aida_process();
    }

    __forceinline bool init() {
        NTSTATUS st;

        if (_PsSetCreateProcessNotifyRoutineEx) {
            st = _PsSetCreateProcessNotifyRoutineEx(process_create_callback_ex, FALSE);
            if (NT_SUCCESS(st)) {
                _InterlockedExchange(&g_registered, 1);
                _InterlockedExchange(&g_registered_ex, 1);
                SN_LOG("process_notify::init: registered Ex callback (pre-create blocking)");
            } else {
                SN_LOG("process_notify::init: Ex FAILED 0x%lx, falling back", st);
                goto fallback;
            }
        } else {
fallback:
            if (!_PsSetCreateProcessNotifyRoutine)
                return false;
            st = _PsSetCreateProcessNotifyRoutine(process_create_callback, FALSE);
            if (NT_SUCCESS(st)) {
                _InterlockedExchange(&g_registered, 1);
                SN_LOG("process_notify::init: registered legacy callback");
            } else {
                SN_LOG("process_notify::init: FAILED status=0x%lx", st);
                return false;
            }
        }

        if (_PsSetLoadImageNotifyRoutine) {
            st = _PsSetLoadImageNotifyRoutine(image_load_callback);
            if (NT_SUCCESS(st)) {
                _InterlockedExchange(&g_image_registered, 1);
                SN_LOG("process_notify::init: registered image load callback");
            }
        }

        st = PsSetCreateThreadNotifyRoutine(thread_create_callback);
        if (NT_SUCCESS(st)) {
            _InterlockedExchange(&g_thread_notify_registered, 1);
            SN_LOG("process_notify::init: registered thread create callback");
        } else {
            SN_LOG("process_notify::init: PsSetCreateThreadNotifyRoutine failed 0x%lx", st);
        }

        return true;
    }

    __forceinline void cleanup() {
        if (_InterlockedCompareExchange(&g_thread_notify_registered, 0, 1) == 1) {
            PsRemoveCreateThreadNotifyRoutine(thread_create_callback);
        }
        if (_InterlockedCompareExchange(&g_registered, 0, 1) == 1) {
            if (_InterlockedCompareExchange(&g_registered_ex, 0, 0) == 1) {
                _InterlockedExchange(&g_registered_ex, 0);
                if (_PsSetCreateProcessNotifyRoutineEx)
                    _PsSetCreateProcessNotifyRoutineEx(process_create_callback_ex, TRUE);
            } else if (_PsSetCreateProcessNotifyRoutine) {
                _PsSetCreateProcessNotifyRoutine(process_create_callback, TRUE);
            }
        }
        if (_InterlockedCompareExchange(&g_image_registered, 0, 1) == 1) {
            if (_PsRemoveLoadImageNotifyRoutine)
                _PsRemoveLoadImageNotifyRoutine(image_load_callback);
        }
    }
}
