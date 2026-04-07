#pragma once
#include <imports/Defs.h>


namespace heartbeat {


    struct sentinel_bridge_t {
        volatile UINT64 heartbeat_tsc;
        volatile UINT64 sentinel_heartbeat_tsc;
        volatile UINT32 bridge_magic;
        volatile UINT32 bridge_version;
        volatile UINT64 whoswho_code_base;
        volatile UINT64 whoswho_code_size;
        volatile UINT32 sentinel_magic;
        volatile UINT32 sentinel_active;
    };


    constexpr UINT64 HEARTBEAT_TIMEOUT_TSC = 30ULL * 3000000000ULL;

    inline volatile sentinel_bridge_t* g_bridge = nullptr;
    inline volatile UINT64             g_last_whoswho_tsc = 0;
    inline volatile UINT64             g_last_check_tsc = 0;
    inline volatile LONG               g_initialized = 0;
    inline volatile LONG               g_first_heartbeat_seen = 0;


    __forceinline bool locate_bridge(PVOID whoswho_base, ULONG whoswho_size) {
        if (!whoswho_base || whoswho_size == 0)
            return false;

        if (!_MmIsAddressValid(whoswho_base))
            return false;


        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(whoswho_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(whoswho_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);

        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {


            UCHAR* section_base = static_cast<UCHAR*>(whoswho_base) + sections[i].VirtualAddress;
            ULONG section_size = sections[i].Misc.VirtualSize;

            if (section_size < sizeof(sentinel_bridge_t))
                continue;

            __try {

                for (ULONG offset = 0; offset <= section_size - sizeof(sentinel_bridge_t); offset += 4) {
                    if (!_MmIsAddressValid(section_base + offset))
                        continue;


                    volatile UINT32* candidate = reinterpret_cast<volatile UINT32*>(section_base + offset + 16);

                    if (!_MmIsAddressValid((PVOID)candidate))
                        continue;

                    if (*candidate != 0x57484F53)
                        continue;


                    volatile UINT32* version_ptr = candidate + 1;
                    if (!_MmIsAddressValid((PVOID)version_ptr))
                        continue;

                    if (*version_ptr != 1)
                        continue;


                    volatile sentinel_bridge_t* bridge =
                        reinterpret_cast<volatile sentinel_bridge_t*>(section_base + offset);

                    if (!_MmIsAddressValid((PVOID)bridge))
                        continue;

                    UINT64 code_base = bridge->whoswho_code_base;
                    UINT64 code_size = bridge->whoswho_code_size;


                    if (code_base > 0xFFFF800000000000ULL &&
                        code_size > 0 && code_size < 10 * 1024 * 1024) {

                        g_bridge = bridge;


                        bridge->sentinel_magic = 0x53454E54;
                        bridge->sentinel_active = 1;


                        g_last_whoswho_tsc = bridge->heartbeat_tsc;
                        g_last_check_tsc = __rdtsc();

                        return true;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }

        return false;
    }

    __forceinline bool init(PVOID whoswho_base, ULONG whoswho_size) {
        if (!whoswho_base || whoswho_size == 0)
            return false;

        if (!locate_bridge(whoswho_base, whoswho_size))
            return false;

        _InterlockedExchange(&g_initialized, 1);
        return true;
    }


    __forceinline bool update_and_check() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return true;

        if (!g_bridge || !_MmIsAddressValid((PVOID)g_bridge))
            return true;

        __try {

            g_bridge->sentinel_heartbeat_tsc = __rdtsc();


            UINT64 current_whoswho_tsc = g_bridge->heartbeat_tsc;
            UINT64 now_tsc = __rdtsc();


            if (!_InterlockedCompareExchange(&g_first_heartbeat_seen, 0, 0)) {
                if (current_whoswho_tsc != 0) {
                    _InterlockedExchange(&g_first_heartbeat_seen, 1);
                    g_last_whoswho_tsc = current_whoswho_tsc;
                    g_last_check_tsc = now_tsc;
                }

                return true;
            }


            if (current_whoswho_tsc != g_last_whoswho_tsc) {

                g_last_whoswho_tsc = current_whoswho_tsc;
                g_last_check_tsc = now_tsc;
                return true;
            }


            UINT64 elapsed = now_tsc - g_last_check_tsc;

            if (elapsed > HEARTBEAT_TIMEOUT_TSC) {


                if (_KeBugCheckEx) {
                    _KeBugCheckEx(
                        0xDEAD5E05,
                        (ULONG_PTR)g_last_whoswho_tsc,
                        (ULONG_PTR)now_tsc,
                        (ULONG_PTR)HEARTBEAT_TIMEOUT_TSC,
                        (ULONG_PTR)elapsed
                    );
                }
                return false;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return true;
        }

        return true;
    }
}
