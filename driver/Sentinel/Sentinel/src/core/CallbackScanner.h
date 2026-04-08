#pragma once
#include <imports/Defs.h>


namespace callback_scanner {


    constexpr ULONG MAX_CALLBACKS = 64;

    struct callback_info_t {
        PVOID   routine;
        PVOID   owning_module_base;
        ULONG   owning_module_size;
    };

    inline ULONG g_baseline_load_image_count = 0;
    inline ULONG g_baseline_create_process_count = 0;
    inline volatile PVOID g_nt_base = nullptr;
    inline volatile LONG g_initialized = 0;


    // Page-level MmIsAddressValid check instead of per-byte.
    // MmIsAddressValid acquires the PFN lock or walks the TLB — calling it
    // per byte on a 1 MB scan means 1 million calls. Checking once per 4 KB
    // page reduces this to ~256 calls (4000x fewer lock acquisitions).
    // Pattern matches the optimized approach already used in SelfProtect.h.
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

    __forceinline bool verify() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return true;


        if (g_load_image_array) {
            ULONG current = count_callback_array(g_load_image_array);
            if (current > g_baseline_load_image_count + 2) {


                g_baseline_load_image_count = current;
            }
        }

        if (g_create_process_array) {
            ULONG current = count_callback_array(g_create_process_array);
            if (current > g_baseline_create_process_count + 2) {

                g_baseline_create_process_count = current;
            }
        }

        return true;
    }
}
