#pragma once
#include <imports/Defs.h>
#include <core/ProcessNotify.h>
#include <core/DriverLoadAudit.h>


namespace callback_scanner {


    constexpr ULONG MAX_CALLBACKS = 64;

    __forceinline ULONG64 driver_name_fnv64(PCUNICODE_STRING name) {
        ULONG64 h = 0xCBF29CE484222325ULL;
        if (!name || !name->Buffer) return h;
        USHORT cnt = name->Length / sizeof(WCHAR);
        for (USHORT i = 0; i < cnt; ++i) {
            WCHAR c = name->Buffer[i];
            if (c >= L'A' && c <= L'Z') c = static_cast<WCHAR>(c + 0x20);
            h ^= static_cast<ULONG64>(c);
            h *= 0x100000001B3ULL;
        }
        return h;
    }

    __forceinline BOOLEAN is_tier_a_hostile_name(PCUNICODE_STRING name) {
        static const wchar_t* kTierA[] = {
            L"dbk64.sys", L"dbk32.sys", L"hyperdbg.sys", L"kldbgdrv.sys",
            L"syser.sys", L"livekd.sys", L"pcileech.sys", L"rwdrv.sys", L"winio.sys",
            L"winio64.sys", L"capcom.sys", L"gdrv.sys", L"atszio64.sys", L"asmmap64.sys",
            L"dumpit.sys", L"physmem.sys"
        };
        if (!name || !name->Buffer || name->Length == 0) return FALSE;
        UNICODE_STRING lower;
        WCHAR buf[260];
        lower.Buffer = buf;
        lower.MaximumLength = sizeof(buf);
        lower.Length = 0;
        if (!NT_SUCCESS(RtlDowncaseUnicodeString(&lower, const_cast<PUNICODE_STRING>(name), FALSE)))
            return FALSE;
        for (const wchar_t* tgt : kTierA) {
            UNICODE_STRING us;
            RtlInitUnicodeString(&us, tgt);
            if (RtlSuffixUnicodeString(&us, &lower, FALSE))
                return TRUE;
        }
        return FALSE;
    }

    __forceinline VOID classify_driver_name(PCUNICODE_STRING name,
                                            BOOLEAN* out_hostile,
                                            BOOLEAN* out_tier_a) {
        if (out_hostile) *out_hostile = FALSE;
        if (out_tier_a) *out_tier_a = FALSE;

        if (!name || !name->Buffer || name->Length == 0)
            return;

        WCHAR lower_buf[260];
        UNICODE_STRING lower;
        lower.Buffer = lower_buf;
        lower.MaximumLength = sizeof(lower_buf);
        lower.Length = 0;
        if (!NT_SUCCESS(RtlDowncaseUnicodeString(&lower, const_cast<PUNICODE_STRING>(name), FALSE)))
            return;

        static const wchar_t* kTierA[] = {
            L"dbk64.sys", L"dbk32.sys", L"hyperdbg.sys", L"kldbgdrv.sys",
            L"syser.sys", L"livekd.sys", L"pcileech.sys", L"rwdrv.sys", L"winio.sys",
            L"winio64.sys", L"capcom.sys", L"gdrv.sys", L"atszio64.sys", L"asmmap64.sys",
            L"dumpit.sys", L"physmem.sys"
        };

        if (out_tier_a) {
            for (const wchar_t* tgt : kTierA) {
                UNICODE_STRING us;
                RtlInitUnicodeString(&us, tgt);
                if (RtlSuffixUnicodeString(&us, &lower, FALSE)) {
                    *out_tier_a = TRUE;
                    break;
                }
            }
        }

        if (out_hostile) {
            static const wchar_t* kHostile[] = {
                L"kldbgdrv.sys", L"dbk64.sys",
                L"virtualkd", L"livekd", L"kdcom.dll",
                L"syser.sys", L"pchunter", L"kerneldetective",
                L"windbg", L"kprocesshacker", L"processhacker",
                L"titanhide", L"scyllahide", L"sharpod",
                L"hyperdbg", L"drivermon", L"rwdrv.sys",
                L"pcileech", L"ftd2xx", L"dumpit.sys"
            };

            USHORT lower_chars = lower.Length / sizeof(WCHAR);
            USHORT start_idx = 0;
            for (USHORT i = lower_chars; i > 0; --i) {
                if (lower.Buffer[i - 1] == L'\\') {
                    start_idx = i;
                    break;
                }
            }

            USHORT filename_len = lower_chars - start_idx;
            const WCHAR* filename = &lower.Buffer[start_idx];

            for (const wchar_t* tgt : kHostile) {
                USHORT tlen = 0;
                while (tgt[tlen]) tlen++;
                if (tlen > filename_len) continue;

                BOOLEAN match = TRUE;
                for (USHORT c = 0; c < tlen; ++c) {
                    if (filename[c] != tgt[c]) {
                        match = FALSE;
                        break;
                    }
                }
                if (match) {
                    *out_hostile = TRUE;
                    break;
                }
            }
        }
    }

    struct callback_info_t {
        PVOID   routine;
        PVOID   owning_module_base;
        ULONG   owning_module_size;
    };

    inline ULONG g_baseline_load_image_count = 0;
    inline ULONG g_baseline_create_process_count = 0;
    inline volatile PVOID g_nt_base = nullptr;
    inline volatile LONG g_initialized = 0;


    __forceinline PVOID find_pattern_safe(PVOID start, ULONG size,
                                          const UCHAR* pattern, const char* mask) {
        if (!start || !pattern || !mask || size == 0)
            return nullptr;

        ULONG mask_len = 0;
        while (mask[mask_len]) mask_len++;
        if (mask_len == 0 || mask_len > size)
            return nullptr;

        const UCHAR* base = static_cast<const UCHAR*>(start);
        constexpr ULONG page_size = 0x1000;

        __try {
            for (ULONG i = 0; i <= size - mask_len; ) {
                ULONG_PTR current_addr = reinterpret_cast<ULONG_PTR>(base + i);
                ULONG_PTR current_page = current_addr & ~(static_cast<ULONG_PTR>(page_size) - 1);

                if (!_MmIsAddressValid(reinterpret_cast<PVOID>(current_page))) {
                    ULONG_PTR next_page = current_page + page_size;
                    ULONG skip = static_cast<ULONG>(next_page - current_addr);
                    i += skip;
                    continue;
                }

                ULONG_PTR page_end = current_page + page_size;
                ULONG max_this_page = static_cast<ULONG>(page_end - reinterpret_cast<ULONG_PTR>(base));
                if (max_this_page > size) max_this_page = size;

                for (; i <= max_this_page - mask_len && i <= size - mask_len; ++i) {
                    bool found = true;
                    for (ULONG j = 0; j < mask_len && found; j++) {
                        if (mask[j] == 'x' && base[i + j] != pattern[j])
                            found = false;
                    }
                    if (found)
                        return (PVOID)(base + i);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }

        return nullptr;
    }

    __forceinline PVOID resolve_relative(PVOID instruction, ULONG offset_to_disp, ULONG total_size) {
        if (!instruction)
            return nullptr;

        UCHAR* ip = static_cast<UCHAR*>(instruction);
        INT32 disp = *reinterpret_cast<INT32*>(ip + offset_to_disp);
        return reinterpret_cast<PVOID>(ip + total_size + disp);
    }


    __forceinline ULONG count_callback_array(PVOID array_base) {
        if (!array_base || !_MmIsAddressValid(array_base))
            return 0;

        ULONG count = 0;
        PVOID* entries = static_cast<PVOID*>(array_base);

        __try {
            for (ULONG i = 0; i < MAX_CALLBACKS; i++) {
                if (!_MmIsAddressValid(&entries[i]))
                    break;

                ULONG_PTR raw = reinterpret_cast<ULONG_PTR>(entries[i]);

                PVOID block = reinterpret_cast<PVOID>(raw & ~0xFULL);

                if (block && _MmIsAddressValid(block))
                    count++;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return count;
        }

        return count;
    }


    __forceinline PVOID find_load_image_array(PVOID nt_base) {
        if (!nt_base || !_MmIsAddressValid(nt_base))
            return nullptr;


        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(nt_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(nt_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (!(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            PVOID section_base = static_cast<UCHAR*>(nt_base) + sections[i].VirtualAddress;
            ULONG section_size = sections[i].Misc.VirtualSize;


            static const UCHAR pat1[] = {
                0x48, 0x8D, 0x0D
            };

            PVOID found = find_pattern_safe(section_base, section_size, pat1, "xxx");
            if (found) {


                UCHAR* check = static_cast<UCHAR*>(found);
                bool valid = false;
                for (int off = 7; off < 20; off++) {
                    if (_MmIsAddressValid(&check[off]) &&
                        _MmIsAddressValid(&check[off + 4]) &&
                        check[off] == 0xBA &&
                        check[off + 1] == 0x40 &&
                        check[off + 2] == 0x00) {
                        valid = true;
                        break;
                    }
                }

                if (valid) {
                    PVOID array = resolve_relative(found, 3, 7);
                    if (array && _MmIsAddressValid(array))
                        return array;
                }
            }
        }

        return nullptr;
    }

    __forceinline PVOID find_create_process_array(PVOID nt_base) {
        if (!nt_base || !_MmIsAddressValid(nt_base))
            return nullptr;

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(nt_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(nt_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (!(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            PVOID section_base = static_cast<UCHAR*>(nt_base) + sections[i].VirtualAddress;
            ULONG section_size = sections[i].Misc.VirtualSize;


            static const UCHAR pat1[] = {
                0x4C, 0x8D, 0x05
            };

            PVOID found = find_pattern_safe(section_base, section_size, pat1, "xxx");
            if (found) {
                UCHAR* check = static_cast<UCHAR*>(found);
                bool valid = false;
                for (int off = 7; off < 20; off++) {
                    if (_MmIsAddressValid(&check[off]) &&
                        _MmIsAddressValid(&check[off + 4])) {

                        if ((check[off] == 0xBA || check[off] == 0x41) &&
                            check[off + 1] == 0x40) {
                            valid = true;
                            break;
                        }
                    }
                }

                if (valid) {
                    PVOID array = resolve_relative(found, 3, 7);
                    if (array && _MmIsAddressValid(array))
                        return array;
                }
            }
        }

        return nullptr;
    }

    inline PVOID g_load_image_array = nullptr;
    inline PVOID g_create_process_array = nullptr;

    __forceinline bool init() {
        PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
        SN_LOG("callback_scanner::init: nt_base=%p", nt_base);
        if (!nt_base)
            return false;

        g_nt_base = nt_base;

        g_load_image_array = find_load_image_array(nt_base);
        g_create_process_array = find_create_process_array(nt_base);
        SN_LOG("callback_scanner::init: load_image=%p create_process=%p",
            g_load_image_array, g_create_process_array);

        if (g_load_image_array)
            g_baseline_load_image_count = count_callback_array(g_load_image_array);

        if (g_create_process_array)
            g_baseline_create_process_count = count_callback_array(g_create_process_array);

        _InterlockedExchange(&g_initialized, 1);
        SN_LOG("callback_scanner::init: SUCCESS load=%lu proc=%lu",
            g_baseline_load_image_count, g_baseline_create_process_count);

        return true;
    }

    inline PVOID g_ob_callback_list = nullptr;
    inline ULONG g_baseline_ob_callback_count = 0;

    __forceinline ULONG count_ob_callbacks()
    {
        if (!g_ob_callback_list || !_MmIsAddressValid(g_ob_callback_list))
            return 0;

        ULONG count = 0;

        __try {
            PLIST_ENTRY head = (PLIST_ENTRY)g_ob_callback_list;
            PLIST_ENTRY entry = head->Flink;

            for (ULONG i = 0; i < MAX_CALLBACKS && entry != head; ++i, entry = entry->Flink)
            {
                if (!_MmIsAddressValid(entry)) break;
                count++;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        return count;
    }

    __forceinline bool verify() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return true;

        bool callbacks_intact = true;

        if (g_load_image_array) {
            ULONG current = count_callback_array(g_load_image_array);
            if (current > g_baseline_load_image_count + 2) {
                g_baseline_load_image_count = current;
            }
            if (current < g_baseline_load_image_count && g_baseline_load_image_count > 0) {
                SN_LOG("callback_scanner: load_image callbacks REMOVED baseline=%lu current=%lu",
                       g_baseline_load_image_count, current);
                callbacks_intact = false;
            }
        }

        if (g_create_process_array) {
            ULONG current = count_callback_array(g_create_process_array);
            if (current > g_baseline_create_process_count + 2) {
                g_baseline_create_process_count = current;
            }
            if (current < g_baseline_create_process_count && g_baseline_create_process_count > 0) {
                SN_LOG("callback_scanner: create_process callbacks REMOVED baseline=%lu current=%lu",
                       g_baseline_create_process_count, current);
                callbacks_intact = false;
            }
        }

        if (g_ob_callback_list) {
            ULONG current = count_ob_callbacks();
            if (current < g_baseline_ob_callback_count && g_baseline_ob_callback_count > 0) {
                SN_LOG("callback_scanner: ObRegisterCallbacks entries REMOVED baseline=%lu current=%lu",
                       g_baseline_ob_callback_count, current);
                callbacks_intact = false;
            }
            if (current > g_baseline_ob_callback_count + 2) {
                g_baseline_ob_callback_count = current;
            }
        }

        return callbacks_intact;
    }


    __forceinline PVOID find_ob_callback_list(PVOID nt_base)
    {
        if (!nt_base || !_MmIsAddressValid(nt_base))
            return nullptr;

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(nt_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(nt_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (!(sections[i].Characteristics & IMAGE_SCN_MEM_WRITE))
                continue;

            PVOID section_base = static_cast<UCHAR*>(nt_base) + sections[i].VirtualAddress;
            ULONG section_size = sections[i].Misc.VirtualSize;

            if (section_size < 0x100)
                continue;

            static const UCHAR magic_bytes[] = {
                0x48, 0x8D, 0x0D
            };

            PVOID found = find_pattern_safe(section_base, section_size, magic_bytes, "xxx");
            if (found) {
                PVOID candidate = resolve_relative(found, 3, 7);
                if (candidate && _MmIsAddressValid(candidate)) {
                    PLIST_ENTRY test = (PLIST_ENTRY)candidate;
                    if (_MmIsAddressValid(test->Flink) && _MmIsAddressValid(test->Blink))
                        return candidate;
                }
            }
        }

        return nullptr;
    }

    __forceinline bool init_ob_monitoring()
    {
        PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
        if (!nt_base) return false;

        g_ob_callback_list = find_ob_callback_list(nt_base);
        if (g_ob_callback_list) {
            g_baseline_ob_callback_count = count_ob_callbacks();
            SN_LOG("callback_scanner: ob_callbacks baseline=%lu",
                   g_baseline_ob_callback_count);
            return true;
        }
        return false;
    }

    inline volatile LONG g_image_notify_active = 0;
    inline volatile UINT64 g_hostile_driver_loads = 0;

    __forceinline bool is_hostile_driver_name(PUNICODE_STRING image_name) {
        if (!image_name || !image_name->Buffer || image_name->Length == 0)
            return false;

        const wchar_t* hostile_drivers[] = {
            L"kldbgdrv.sys", L"dbk64.sys",
            L"virtualKD", L"livekd", L"kdcom.dll",
            L"syser.sys", L"pchunter", L"kerneldetective",
            L"windbg", L"kprocesshacker", L"processhacker",
            L"titanhide", L"scyllahide", L"sharpod",
            L"hyperdbg", L"DriverMon", L"rwdrv.sys",
            L"pcileech", L"ftd2xx", L"DumpIt.sys"
        };
        constexpr int num_hostile = sizeof(hostile_drivers) / sizeof(hostile_drivers[0]);

        USHORT name_chars = image_name->Length / sizeof(WCHAR);
        USHORT start_idx = 0;
        for (USHORT i = name_chars; i > 0; --i) {
            if (image_name->Buffer[i - 1] == L'\\') {
                start_idx = i;
                break;
            }
        }

        USHORT filename_len = name_chars - start_idx;
        const WCHAR* filename = &image_name->Buffer[start_idx];

        for (int h = 0; h < num_hostile; ++h) {
            const wchar_t* target = hostile_drivers[h];
            USHORT tlen = 0;
            while (target[tlen]) tlen++;
            if (tlen > filename_len) continue;

            bool match = true;
            for (USHORT c = 0; c < tlen; ++c) {
                WCHAR a = filename[c];
                WCHAR b = target[c];
                if (a >= L'A' && a <= L'Z') a += 32;
                if (b >= L'A' && b <= L'Z') b += 32;
                if (a != b) { match = false; break; }
            }
            if (match) return true;
        }

        return false;
    }

    static VOID image_load_notify_routine(
        PUNICODE_STRING FullImageName,
        HANDLE ProcessId,
        PIMAGE_INFO ImageInfo)
    {
        if (ProcessId != nullptr) return;

        if (!FullImageName || !FullImageName->Buffer) return;

        BOOLEAN is_hostile = FALSE;
        BOOLEAN is_tier_a = FALSE;
        classify_driver_name(FullImageName, &is_hostile, &is_tier_a);

        if (is_hostile) {
            InterlockedIncrement64((volatile LONG64*)&g_hostile_driver_loads);
            SN_LOG("callback_scanner: HOSTILE DRIVER LOAD: %wZ", FullImageName);
            heartbeat::send_command(heartbeat::BRIDGE_CMD_INTEGRITY_FAIL,
                static_cast<ULONG>(g_hostile_driver_loads & 0xFFFFFFFF));
        }

        ULONG64 name_hash = driver_name_fnv64(FullImageName);
        ULONG_PTR image_base = ImageInfo ? reinterpret_cast<ULONG_PTR>(ImageInfo->ImageBase) : 0;
        ULONG_PTR image_size = ImageInfo ? static_cast<ULONG_PTR>(ImageInfo->ImageSize) : 0;

        {
            UINT32 tier = 0;
            if (is_tier_a) tier = 2;
            else if (is_hostile) tier = 1;
            driver_load_audit::record(name_hash,
                static_cast<UINT64>(image_base),
                static_cast<UINT32>(image_size & 0xFFFFFFFF),
                tier);
        }

        if (is_tier_a) {
            HANDLE prot_pid = reinterpret_cast<HANDLE>(
                _InterlockedCompareExchange64(
                    reinterpret_cast<volatile LONG64*>(&process_notify::g_protected_pid), 0, 0));

            if (prot_pid) {
                heartbeat::send_command(heartbeat::BRIDGE_CMD_HOSTILE_DRIVER,
                    static_cast<ULONG>(image_base & 0xFFFFFFFF));
                SN_LOG("callback_scanner: TIER-A DRIVER LOAD while AiDA running - BUGCHECK: %wZ", FullImageName);
                if (_KeBugCheckEx) {
                    _KeBugCheckEx(heartbeat::BUGCHECK_HOSTILE_DRIVER_LOAD,
                        static_cast<ULONG_PTR>(name_hash),
                        image_base,
                        image_size,
                        0);
                }
            } else {
                SN_LOG("callback_scanner: TIER-A DRIVER pre-loaded (AiDA not running) signaling: %wZ", FullImageName);
                heartbeat::send_command(heartbeat::BRIDGE_CMD_TIER_A_PRE_LOADED,
                    static_cast<ULONG>(name_hash & 0xFFFFFFFF));
            }
        }
    }

    __forceinline NTSTATUS start_image_load_monitoring() {
        if (_InterlockedCompareExchange(&g_image_notify_active, 1, 0) != 0)
            return STATUS_ALREADY_REGISTERED;

        NTSTATUS status = PsSetLoadImageNotifyRoutine(image_load_notify_routine);
        if (!NT_SUCCESS(status)) {
            _InterlockedExchange(&g_image_notify_active, 0);
            SN_LOG("callback_scanner: PsSetLoadImageNotifyRoutine failed 0x%08x", status);
        } else {
            SN_LOG("callback_scanner: image load monitoring ACTIVE");
        }
        return status;
    }

    __forceinline void stop_image_load_monitoring() {
        if (_InterlockedCompareExchange(&g_image_notify_active, 0, 1) != 1)
            return;
        PsRemoveLoadImageNotifyRoutine(image_load_notify_routine);
        SN_LOG("callback_scanner: image load monitoring STOPPED");
    }
}
