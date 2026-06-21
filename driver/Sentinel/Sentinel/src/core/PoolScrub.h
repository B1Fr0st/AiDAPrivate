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
        for (USHORT s = 0; s < nt->FileHeader.NumberOfSections; s++) {
            if (!(sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            PVOID section_base = static_cast<UCHAR*>(nt_base) + sections[s].VirtualAddress;
            ULONG section_size = sections[s].Misc.VirtualSize;
            PVOID found = find_pattern_safe(section_base, section_size, pat, "xxx????xxx????xxx");
            if (!found)
                continue;

            PVOID table_ptr = resolve_relative(found, 3, 7);
            PVOID size_ptr = resolve_relative(static_cast<UCHAR*>(found) + 7, 3, 7);
            if (!table_ptr || !size_ptr || !_MmIsAddressValid(table_ptr) || !_MmIsAddressValid(size_ptr))
                continue;

            PVOID table = *static_cast<PVOID*>(table_ptr);
            if (!table || !_MmIsAddressValid(table))
                continue;

            ULONGLONG size64 = *static_cast<ULONGLONG*>(size_ptr);
            if (size64 == 0 || size64 > 0x1000000ULL)
                continue;

            g_big_pool_table = static_cast<volatile UCHAR*>(table);
            g_big_pool_table_size = static_cast<ULONG>(size64);
            g_big_pool_entry_stride = 0x20;
            SN_LOG("pool_scrub::resolve_big_pool_table_win11 table=%p size=%lu stride=%lu",
                (PVOID)g_big_pool_table,
                g_big_pool_table_size,
                g_big_pool_entry_stride);
            return true;
        }

        SN_LOG("pool_scrub::resolve_big_pool_table_win11 miss");
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

                ULONG key = *reinterpret_cast<volatile ULONG*>(entry + 8);
                if (key == 0)
                    continue;


                for (ULONG t = 0; t < TAG_MAP_COUNT; t++) {
                    if (key == g_tag_map[t].original_tag) {


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

        resolve_big_pool_table(nt_base);
        SN_LOG("pool_scrub::init: big_pool_table=%p size=%lu",
            (PVOID)g_big_pool_table, g_big_pool_table_size);

        scrub_tags();

        _InterlockedExchange(&g_initialized, 1);
        SN_LOG("pool_scrub::init: SUCCESS");
        return true;
    }

    __forceinline void periodic_scrub() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return;

        scrub_tags();
    }
}
