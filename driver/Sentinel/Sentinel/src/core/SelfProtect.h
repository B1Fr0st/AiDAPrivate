#pragma once
#include <imports/Defs.h>
#include <core/Integrity.h>


namespace self_protect {

    inline volatile UINT32 g_own_baseline_crc = 0;
    inline volatile PVOID  g_own_code_base = nullptr;
    inline volatile ULONG  g_own_code_size = 0;
    inline volatile LONG   g_initialized = 0;


    __forceinline bool safe_write_memory(PVOID dest, const PVOID src, SIZE_T size) {
        if (!dest || !src || size == 0)
            return false;

        __try {
            PMDL mdl = _IoAllocateMdl(dest, (ULONG)size, FALSE, FALSE, nullptr);
            if (!mdl)
                return false;

            _MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
            PVOID mapped = _MmMapLockedPagesSpecifyCache(
                mdl, KernelMode, MmCached, nullptr, FALSE, NormalPagePriority);

            if (mapped) {
                RtlCopyMemory(mapped, src, size);
                _MmUnmapLockedPages(mapped, mdl);
            }

            _MmUnlockPages(mdl);
            _IoFreeMdl(mdl);
            return mapped != nullptr;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }


    __forceinline PVOID find_pattern_safe(PVOID start, ULONG size,
                                          const UCHAR* pattern, const char* mask) {
        if (!start || !pattern || !mask || size == 0)
            return nullptr;

        ULONG mask_len = 0;
        while (mask[mask_len]) mask_len++;
        if (mask_len == 0 || mask_len > size)
            return nullptr;

        const UCHAR* base = static_cast<const UCHAR*>(start);

        __try {
            for (ULONG i = 0; i <= size - mask_len; i++) {
                if (!_MmIsAddressValid((PVOID)(base + i)))
                    continue;

                bool found = true;
                for (ULONG j = 0; j < mask_len && found; j++) {
                    if (!_MmIsAddressValid((PVOID)(base + i + j))) {
                        found = false;
                        break;
                    }
                    if (mask[j] == 'x' && base[i + j] != pattern[j])
                        found = false;
                }

                if (found)
                    return (PVOID)(base + i);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }

        return nullptr;
    }

    __forceinline PVOID find_pattern_in_all_sections(PVOID image_base,
                                                      const UCHAR* pattern,
                                                      const char* mask) {
        if (!image_base || !_MmIsAddressValid(image_base))
            return nullptr;

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(image_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(image_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            PVOID section_base = static_cast<UCHAR*>(image_base) + sections[i].VirtualAddress;
            ULONG section_size = sections[i].Misc.VirtualSize;

            PVOID result = find_pattern_safe(section_base, section_size, pattern, mask);
            if (result)
                return result;
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


    struct PIDDB_CACHE_ENTRY {
        LIST_ENTRY   List;
        UNICODE_STRING DriverName;
        ULONG        TimeDateStamp;
        NTSTATUS     LoadStatus;
        char         _pad[16];
    };


    struct PIDDB_CACHE_ENTRY_WIN11 {
        LIST_ENTRY   List;
        UNICODE_STRING DriverName;
        ULONG        TimeDateStamp;
        NTSTATUS     LoadStatus;
        ULONG64      DriverHash;
        char         _pad[8];
    };

    __forceinline bool clean_piddb_cache(PVOID nt_base, PLDR_DATA_TABLE_ENTRY ldr_entry) {
        if (!nt_base || !ldr_entry || !_MmIsAddressValid(nt_base) || !_MmIsAddressValid(ldr_entry))
            return false;

        if (!_ExAcquireResourceExclusiveLite || !_ExReleaseResourceLite)
            return false;


        static const UCHAR patA[] = { 0x48, 0x8D, 0x0D };


        PVOID found = nullptr;
        PVOID lock_ptr = nullptr;
        PVOID table_ptr = nullptr;


        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(nt_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS64 nt_hdr = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(nt_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt_hdr) || nt_hdr->Signature != IMAGE_NT_SIGNATURE)
            return false;

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt_hdr);

        for (USHORT s = 0; s < nt_hdr->FileHeader.NumberOfSections; s++) {
            if (!(sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            PVOID section_base = static_cast<UCHAR*>(nt_base) + sections[s].VirtualAddress;
            ULONG section_size = sections[s].Misc.VirtualSize;


            found = find_pattern_safe(section_base, section_size, patA, "xxx");
            while (found) {
                UCHAR* check = static_cast<UCHAR*>(found);


                bool valid_lock = false;
                for (int off = 7; off < 20; off++) {
                    if (_MmIsAddressValid(&check[off]) && _MmIsAddressValid(&check[off+1])) {
                        if (check[off] == 0xBA && check[off+1] == 0x01) {
                            valid_lock = true;
                            break;
                        }
                    }
                }

                if (valid_lock) {
                    lock_ptr = resolve_relative(found, 3, 7);
                    if (lock_ptr && _MmIsAddressValid(lock_ptr)) {


                        for (int scan = 7; scan < 80; scan++) {
                            if (_MmIsAddressValid(&check[scan]) &&
                                _MmIsAddressValid(&check[scan+2])) {
                                if (check[scan] == 0x48 && check[scan+1] == 0x8D &&
                                    (check[scan+2] == 0x0D || check[scan+2] == 0x15 ||
                                     check[scan+2] == 0x05 || check[scan+2] == 0x35)) {
                                    PVOID candidate = resolve_relative(&check[scan], 3, 7);
                                    if (candidate && _MmIsAddressValid(candidate) &&
                                        candidate != lock_ptr) {
                                        table_ptr = candidate;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if (lock_ptr && table_ptr)
                        break;
                }


                ULONG remaining = section_size - (ULONG)((UCHAR*)found - (UCHAR*)section_base) - 3;
                found = find_pattern_safe(static_cast<UCHAR*>(found) + 3, remaining, patA, "xxx");
            }

            if (lock_ptr && table_ptr)
                break;
        }

        if (!lock_ptr || !table_ptr)
            return false;


        PERESOURCE lock = static_cast<PERESOURCE>(lock_ptr);

        __try {
            _ExAcquireResourceExclusiveLite(lock, TRUE);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        bool cleaned = false;

        __try {


            RTL_AVL_TABLE* avl_table = static_cast<RTL_AVL_TABLE*>(table_ptr);

            if (_MmIsAddressValid(avl_table) && _RtlLookupElementGenericTableAvl) {

                PIDDB_CACHE_ENTRY lookup = {};
                if (ldr_entry->BaseDllName.Buffer && _MmIsAddressValid(ldr_entry->BaseDllName.Buffer)) {
                    lookup.DriverName = ldr_entry->BaseDllName;

                    PVOID entry = _RtlLookupElementGenericTableAvl(avl_table, &lookup);
                    if (entry && _MmIsAddressValid(entry)) {
                        PIDDB_CACHE_ENTRY* cache_entry = static_cast<PIDDB_CACHE_ENTRY*>(entry);


                        if (_MmIsAddressValid(&cache_entry->List) &&
                            cache_entry->List.Flink && _MmIsAddressValid(cache_entry->List.Flink) &&
                            cache_entry->List.Blink && _MmIsAddressValid(cache_entry->List.Blink)) {
                            RemoveEntryList(&cache_entry->List);
                        }

                        if (_RtlDeleteElementGenericTableAvl)
                            _RtlDeleteElementGenericTableAvl(avl_table, &lookup);

                        cleaned = true;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            cleaned = false;
        }

        __try {
            _ExReleaseResourceLite(lock);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        return cleaned;
    }


    struct MM_UNLOADED_DRIVER {
        UNICODE_STRING Name;
        PVOID ModuleStart;
        PVOID ModuleEnd;
        LARGE_INTEGER UnloadTime;
    };

    __forceinline bool clean_mm_unloaded_drivers(PVOID nt_base) {
        if (!nt_base || !_MmIsAddressValid(nt_base))
            return false;


        static const UCHAR pat1[] = { 0x48, 0x8B, 0x3D };
        static const UCHAR pat2[] = { 0x4C, 0x8B, 0x15 };
        static const UCHAR pat3[] = { 0x4C, 0x8B, 0x0D };
        static const UCHAR pat4[] = { 0x48, 0x8B, 0x0D };

        struct { const UCHAR* pat; const char* mask; } patterns[] = {
            { pat1, "xxx" }, { pat2, "xxx" }, { pat3, "xxx" }, { pat4, "xxx" }
        };

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(nt_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS64 nt_hdr = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(nt_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt_hdr) || nt_hdr->Signature != IMAGE_NT_SIGNATURE)
            return false;

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt_hdr);

        for (USHORT s = 0; s < nt_hdr->FileHeader.NumberOfSections; s++) {
            if (!(sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            PVOID section_base = static_cast<UCHAR*>(nt_base) + sections[s].VirtualAddress;
            ULONG section_size = sections[s].Misc.VirtualSize;

            for (int p = 0; p < 4; p++) {
                PVOID found = find_pattern_safe(section_base, section_size,
                                                 patterns[p].pat, patterns[p].mask);
                if (!found)
                    continue;


                UCHAR* check = static_cast<UCHAR*>(found);


                bool valid = false;
                for (int off = 7; off < 40; off++) {
                    if (_MmIsAddressValid(&check[off]) && _MmIsAddressValid(&check[off+2])) {
                        UCHAR b0 = check[off];
                        UCHAR b2 = check[off+2];

                        if ((b0 == 0x48 || b0 == 0x4C || b0 == 0x44 || b0 == 0x8B) &&
                            (b2 == 0x05 || b2 == 0x0D || b2 == 0x15 || b2 == 0x25 || b2 == 0x35)) {
                            valid = true;
                            break;
                        }
                    }
                }

                if (!valid)
                    continue;

                PVOID ptr_addr = resolve_relative(found, 3, 7);
                if (!ptr_addr || !_MmIsAddressValid(ptr_addr))
                    continue;

                MM_UNLOADED_DRIVER** drivers_ptr = static_cast<MM_UNLOADED_DRIVER**>(ptr_addr);
                if (!_MmIsAddressValid(drivers_ptr) || !*drivers_ptr || !_MmIsAddressValid(*drivers_ptr))
                    continue;


                __try {
                    RtlZeroMemory(*drivers_ptr, sizeof(MM_UNLOADED_DRIVER) * 50);
                    return true;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    continue;
                }
            }
        }

        return false;
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
                if (_MmIsAddressValid(debug_dir)) {

                    UCHAR zeros[256] = {};
                    ULONG to_zero = min(debug_size, (ULONG)sizeof(zeros));
                    safe_write_memory(debug_dir, zeros, to_zero);
                }


                ULONG64 zero = 0;
                safe_write_memory(
                    &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG],
                    &zero, sizeof(IMAGE_DATA_DIRECTORY));
            }


            static const ULONG plausible_stamps[] = {
                0x5D6EF3A1, 0x5E98B2C4, 0x60A1F123, 0x61C7D834,
                0x62F4A789, 0x63B12345, 0x64DEF678, 0x5F123ABC
            };
            ULONG stamp_idx = (ULONG)((__rdtsc() >> 4) % (sizeof(plausible_stamps) / sizeof(plausible_stamps[0])));
            ULONG new_stamp = plausible_stamps[stamp_idx];
            safe_write_memory(&nt_hdr->FileHeader.TimeDateStamp, &new_stamp, sizeof(ULONG));

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return;
        }
    }


    __forceinline void apply_stealth(PDRIVER_OBJECT driver_object) {
        if (!driver_object)
            return;

        PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
        if (!nt_base)
            return;

        PLDR_DATA_TABLE_ENTRY ldr = nullptr;
        if (driver_object->DriverSection && _MmIsAddressValid(driver_object->DriverSection))
            ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(driver_object->DriverSection);


        if (ldr && ldr->DllBase)
            clean_piddb_cache(nt_base, ldr);

        clean_mm_unloaded_drivers(nt_base);


        scrub_pe_metadata(driver_object);


        disguise_module_entry(driver_object);
    }


    __forceinline bool init(PDRIVER_OBJECT driver_object, PVOID own_code_base, ULONG own_code_size) {
        if (!own_code_base || own_code_size == 0)
            return false;

        g_own_code_base = own_code_base;
        g_own_code_size = own_code_size;


        g_own_baseline_crc = integrity::compute_crc32(own_code_base, own_code_size);

        if (g_own_baseline_crc == 0)
            return false;


        if (driver_object)
            apply_stealth(driver_object);

        _InterlockedExchange(&g_initialized, 1);
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
}
