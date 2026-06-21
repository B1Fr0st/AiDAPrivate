#pragma once
#include <imports/Defs.h>
#include <core/NtVersion.h>


namespace pool_scrub {


    struct POOL_TRACKER_BIG_PAGES {
        volatile PVOID  Va;
        ULONG           Key;
        ULONG           Pattern;
        ULONG           PoolType;
        ULONG           SlushSize;
    };

    inline volatile UCHAR*                  g_big_pool_table = nullptr;
    inline volatile ULONG                   g_big_pool_table_size = 0;
    inline volatile ULONG                   g_big_pool_entry_stride = sizeof(POOL_TRACKER_BIG_PAGES);
    inline volatile LONG                    g_initialized = 0;


    struct tag_mapping_t {
        ULONG original_tag;
        ULONG replacement_tag;
    };


    inline const tag_mapping_t g_tag_map[] = {
        { 'WNkp', 'mCmM' },
        { 'WNij', 'tSmM' },
        { 'WNrf', 'sFtN' },
        { 'WDel', 'cScC' },
        { 'WNpd', 'nfMF' },
        { 'WNts', 'iDbO' },
        { 'WNwb', 'oCOI' },
    };

    constexpr ULONG TAG_MAP_COUNT = sizeof(g_tag_map) / sizeof(g_tag_map[0]);


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

                if (max_this_page >= mask_len) {
                    ULONG scan_limit = max_this_page - mask_len;
                    ULONG max_start = size - mask_len;
                    if (scan_limit > max_start) scan_limit = max_start;

                    for (; i <= scan_limit; ++i) {
                        bool found = true;
                        for (ULONG j = 0; j < mask_len && found; j++) {
                            if (mask[j] == 'x' && base[i + j] != pattern[j])
                                found = false;
                        }
                        if (found)
                            return (PVOID)(base + i);
                    }
                }

                ULONG next_i = static_cast<ULONG>(page_end - reinterpret_cast<ULONG_PTR>(base));
                if (next_i <= i)
                    ++i;
                else
                    i = next_i;
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

    __forceinline bool validate_big_pool_table_sample(PVOID table, ULONGLONG size64) {
        if (!table || size64 == 0 || size64 > 0x100000ULL || !_MmIsAddressValid(table))
            return false;

        ULONG probes = size64 < 64 ? static_cast<ULONG>(size64) : 64;
        if (probes == 0)
            return false;

        __try {
            for (ULONG i = 0; i < probes; ++i) {
                volatile UCHAR* entry = static_cast<volatile UCHAR*>(table) + (static_cast<SIZE_T>(i) * 0x20);
                if (!_MmIsAddressValid((PVOID)entry) || !_MmIsAddressValid((PVOID)(entry + 0x1F)))
                    return false;

                ULONGLONG va = *reinterpret_cast<volatile ULONGLONG*>(entry);
                ULONGLONG number_of_bytes = *reinterpret_cast<volatile ULONGLONG*>(entry + 0x10);
                ULONG_PTR normalized_va = static_cast<ULONG_PTR>(va & ~1ULL);
                if (normalized_va != 0 && normalized_va < 0xFFFF800000000000ULL)
                    return false;
                if (number_of_bytes > 0x100000000ULL)
                    return false;
            }
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    __forceinline bool resolve_big_pool_table_win11(PVOID nt_base) {
        if (!nt_base || !_MmIsAddressValid(nt_base))
            return false;

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(nt_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(nt_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        static const UCHAR pat[] = {
            0x48, 0x8B, 0x15, 0x00, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x85, 0xD2
        };

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        PVOID selected_table = nullptr;
        ULONG selected_size = 0;
        PVOID selected_found = nullptr;
        ULONG raw_candidates = 0;
        ULONG valid_candidates = 0;

        for (USHORT s = 0; s < nt->FileHeader.NumberOfSections; s++) {
            if (!(sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            PVOID section_base = static_cast<UCHAR*>(nt_base) + sections[s].VirtualAddress;
            ULONG section_size = sections[s].Misc.VirtualSize;
            ULONG search_offset = 0;

            for (;;) {
                if (search_offset >= section_size)
                    break;

                PVOID search_base = static_cast<UCHAR*>(section_base) + search_offset;
                ULONG remaining = section_size - search_offset;
                PVOID found = find_pattern_safe(search_base, remaining, pat, "xxx????xxx????xxx");
                if (!found)
                    break;

                raw_candidates++;
                PVOID table_ptr = resolve_relative(found, 3, 7);
                PVOID size_ptr = resolve_relative(static_cast<UCHAR*>(found) + 7, 3, 7);
                bool globals_valid =
                    table_ptr && size_ptr &&
                    nt_section_contains(nt_base, table_ptr, sizeof(PVOID), IMAGE_SCN_MEM_WRITE) &&
                    nt_section_contains(nt_base, size_ptr, sizeof(ULONGLONG), IMAGE_SCN_MEM_WRITE) &&
                    reinterpret_cast<ULONG_PTR>(size_ptr) == reinterpret_cast<ULONG_PTR>(table_ptr) + sizeof(PVOID);

                PVOID table = nullptr;
                ULONGLONG size64 = 0;
                if (globals_valid) {
                    __try {
                        table = *static_cast<PVOID*>(table_ptr);
                        size64 = *static_cast<ULONGLONG*>(size_ptr);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        table = nullptr;
                        size64 = 0;
                    }
                }

                bool sample_valid = globals_valid && validate_big_pool_table_sample(table, size64);
                SN_LOG("pool_scrub::resolve_big_pool_table_win11 candidate section=%u found=%p table_ptr=%p size_ptr=%p table=%p size=%llu globals=%u sample=%u raw=%lu valid_count=%lu",
                    s,
                    found,
                    table_ptr,
                    size_ptr,
                    table,
                    static_cast<unsigned long long>(size64),
                    globals_valid ? 1u : 0u,
                    sample_valid ? 1u : 0u,
                    raw_candidates,
                    valid_candidates + (sample_valid ? 1u : 0u));

                if (sample_valid) {
                    valid_candidates++;
                    if (valid_candidates == 1) {
                        selected_table = table;
                        selected_size = static_cast<ULONG>(size64);
                        selected_found = found;
                    }
                }

                ULONG consumed = static_cast<ULONG>(
                    static_cast<UCHAR*>(found) - static_cast<UCHAR*>(section_base)) + 1;
                if (consumed <= search_offset || consumed >= section_size)
                    break;
                search_offset = consumed;
            }
        }

        if (valid_candidates == 1 && selected_table && selected_size != 0) {
            g_big_pool_table = static_cast<volatile UCHAR*>(selected_table);
            g_big_pool_table_size = selected_size;
            g_big_pool_entry_stride = 0x20;
            SN_LOG("pool_scrub::resolve_big_pool_table_win11 selected found=%p table=%p size=%lu stride=%lu raw=%lu",
                selected_found,
                (PVOID)g_big_pool_table,
                g_big_pool_table_size,
                g_big_pool_entry_stride,
                raw_candidates);
            return true;
        }

        SN_LOG("pool_scrub::resolve_big_pool_table_win11 fail_closed raw=%lu valid=%lu selected=%p size=%lu",
            raw_candidates,
            valid_candidates,
            selected_table,
            selected_size);
        return false;
    }


    __forceinline bool resolve_big_pool_table(PVOID nt_base) {
        if (!nt_base || !_MmIsAddressValid(nt_base))
            return false;

        if (nt_version::is_windows_11_or_newer()) {
            SN_LOG("pool_scrub::resolve_big_pool_table windows11_path build=%lu",
                nt_version::build_number());
            return resolve_big_pool_table_win11(nt_base);
        }

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(nt_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(nt_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);

        for (USHORT s = 0; s < nt->FileHeader.NumberOfSections; s++) {
            if (!(sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            PVOID section_base = static_cast<UCHAR*>(nt_base) + sections[s].VirtualAddress;
            ULONG section_size = sections[s].Misc.VirtualSize;


            static const UCHAR pat_table[] = { 0x48, 0x8B, 0x05 };

            static const UCHAR pat_table_alt[] = { 0x4C, 0x8B, 0x25 };


            static const UCHAR pat_size[] = { 0x44, 0x8B, 0x35 };
            static const UCHAR pat_size_alt[] = { 0x8B, 0x0D };


            PVOID found_table = find_pattern_safe(section_base, section_size, pat_table, "xxx");
            if (!found_table)
                found_table = find_pattern_safe(section_base, section_size, pat_table_alt, "xxx");

            if (!found_table)
                continue;

            PVOID table_ptr = resolve_relative(found_table, 3, 7);
            if (!table_ptr || !_MmIsAddressValid(table_ptr))
                continue;

            PVOID* actual_table_ptr = static_cast<PVOID*>(table_ptr);
            if (!_MmIsAddressValid(*actual_table_ptr))
                continue;


            PVOID found_size = find_pattern_safe(section_base, section_size, pat_size, "xxx");
            ULONG size_disp_offset = 3;
            ULONG size_total = 7;
            if (!found_size) {
                found_size = find_pattern_safe(section_base, section_size, pat_size_alt, "xx");
                size_disp_offset = 2;
                size_total = 6;
            }

            if (!found_size)
                continue;

            PVOID size_ptr = resolve_relative(found_size, size_disp_offset, size_total);
            if (!size_ptr || !_MmIsAddressValid(size_ptr))
                continue;

            g_big_pool_table = static_cast<volatile UCHAR*>(*actual_table_ptr);
            g_big_pool_table_size = *static_cast<ULONG*>(size_ptr);
            g_big_pool_entry_stride = sizeof(POOL_TRACKER_BIG_PAGES);

            if (g_big_pool_table && g_big_pool_table_size > 0 &&
                g_big_pool_table_size < 0x1000000)
                return true;

            g_big_pool_table = nullptr;
            g_big_pool_table_size = 0;
        }

        return false;
    }


    __forceinline void scrub_tags() {
        if (!g_big_pool_table || g_big_pool_table_size == 0)
            return;

        __try {
            for (ULONG i = 0; i < g_big_pool_table_size; i++) {
                volatile UCHAR* entry =
                    g_big_pool_table + (static_cast<SIZE_T>(i) * g_big_pool_entry_stride);

                if (!_MmIsAddressValid((PVOID)entry) ||
                    !_MmIsAddressValid((PVOID)(entry + sizeof(PVOID) - 1)) ||
                    !_MmIsAddressValid((PVOID)(entry + 8 + sizeof(ULONG) - 1)))
                    break;


                PVOID va = *reinterpret_cast<volatile PVOID*>(entry);
                if (!va || va == (PVOID)1)
                    continue;

                ULONG_PTR normalized_va = reinterpret_cast<ULONG_PTR>(va) & ~1ULL;
                if (normalized_va < 0xFFFF800000000000ULL)
                    continue;

                ULONG key = *reinterpret_cast<volatile ULONG*>(entry + 8);
                if (key == 0)
                    continue;

                if (g_big_pool_entry_stride == 0x20) {
                    ULONGLONG number_of_bytes = *reinterpret_cast<volatile ULONGLONG*>(entry + 0x10);
                    if (number_of_bytes == 0 || number_of_bytes > 0x100000000ULL)
                        continue;
                }

                for (ULONG t = 0; t < TAG_MAP_COUNT; t++) {
                    if (key == g_tag_map[t].original_tag) {

                        SN_LOG("pool_scrub::scrub_tags replace index=%lu entry=%p va=%p old=0x%08lx new=0x%08lx stride=%lu",
                            i,
                            (PVOID)entry,
                            va,
                            key,
                            g_tag_map[t].replacement_tag,
                            g_big_pool_entry_stride);
                        *reinterpret_cast<volatile ULONG*>(entry + 8) =
                            g_tag_map[t].replacement_tag;
                        break;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return;
        }
    }

    __forceinline bool init() {
        PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
        SN_LOG("pool_scrub::init: nt_base=%p", nt_base);
        if (!nt_base)
            return false;

        bool resolved = resolve_big_pool_table(nt_base);
        SN_LOG("pool_scrub::init: big_pool_table=%p size=%lu",
            (PVOID)g_big_pool_table, g_big_pool_table_size);

        if (resolved)
            scrub_tags();
        else
            SN_LOG("pool_scrub::init: fail_closed reason=big_pool_table_unresolved build=%lu",
                nt_version::build_number());

        _InterlockedExchange(&g_initialized, 1);
        SN_LOG("pool_scrub::init: done resolved=%u",
            resolved ? 1u : 0u);
        return resolved;
    }

    __forceinline void periodic_scrub() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return;

        scrub_tags();
    }
}
