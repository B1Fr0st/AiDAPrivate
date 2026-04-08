#pragma once
#include <imports/Defs.h>


namespace heartbeat {


    struct sentinel_bridge_t {
        volatile ULONG  magic;
        volatile ULONG  version;
        volatile PVOID  code_base;
        volatile ULONG  code_size;
        volatile LONG64 whoswho_tsc;
        volatile LONG64 sentinel_tsc;
    };


    constexpr ULONG  BRIDGE_MAGIC = 0x57484F53;
    constexpr ULONG  BRIDGE_VERSION = 1;
    // Increased from 30s to 60s to match WhosWho's new SENTINEL_TIMEOUT_MS = 60000.
    // With the Guardian DPC now firing every 10s (was 3s), Sentinel updates its
    // bridge TSC every 10s. WhosWho needs at least 6 missed updates (60s) before
    // concluding Sentinel is dead. Sentinel mirrors this: if WhosWho hasn't
    // updated its TSC in 60s, something is wrong.
    constexpr UINT64 HEARTBEAT_TIMEOUT_TSC = 60ULL * 3000000000ULL;

    inline volatile sentinel_bridge_t* g_bridge = nullptr;
    inline volatile UINT64             g_last_whoswho_tsc = 0;
    inline volatile UINT64             g_last_check_tsc = 0;
    inline volatile LONG               g_initialized = 0;
    inline volatile LONG               g_first_heartbeat_seen = 0;


    __forceinline bool locate_bridge(PVOID whoswho_base, ULONG whoswho_size) {

        if (!whoswho_base || whoswho_size == 0) {
            return false;
        }

        if (!_MmIsAddressValid(whoswho_base)) {
            return false;
        }

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(whoswho_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(whoswho_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

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

                    volatile UINT32* magic_ptr = reinterpret_cast<volatile UINT32*>(section_base + offset);
                    if (!_MmIsAddressValid(reinterpret_cast<PVOID>(const_cast<UINT32*>(magic_ptr))))
                        continue;

                    if (*magic_ptr != BRIDGE_MAGIC)
                        continue;

                    volatile UINT32* version_ptr = magic_ptr + 1;
                    if (!_MmIsAddressValid(reinterpret_cast<PVOID>(const_cast<UINT32*>(version_ptr))))
                        continue;

                    if (*version_ptr != BRIDGE_VERSION)
                        continue;

                    volatile sentinel_bridge_t* bridge =
                        reinterpret_cast<volatile sentinel_bridge_t*>(section_base + offset);

                    if (!_MmIsAddressValid(reinterpret_cast<PVOID>(const_cast<sentinel_bridge_t*>(bridge))))
                        continue;

                    PVOID cb = bridge->code_base;
                    ULONG cs = bridge->code_size;

                    if (reinterpret_cast<ULONG_PTR>(cb) > 0xFFFF800000000000ULL &&
                        cs > 0 && cs < 10 * 1024 * 1024) {
                        g_bridge = bridge;
                        g_last_whoswho_tsc = static_cast<UINT64>(bridge->whoswho_tsc);
                        g_last_check_tsc = __rdtsc();
                        return true;
                    } else {
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }

        return false;
    }

    __forceinline bool init(PVOID whoswho_base, ULONG whoswho_size) {
        if (!whoswho_base || whoswho_size == 0) {
            return false;
        }

        if (!locate_bridge(whoswho_base, whoswho_size)) {
            return false;
        }

        _InterlockedExchange(&g_initialized, 1);
        return true;
    }


    __forceinline bool update_and_check() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return true;

        if (!g_bridge || !_MmIsAddressValid(reinterpret_cast<PVOID>(
                const_cast<sentinel_bridge_t*>(g_bridge)))) {
            return true;
        }

        __try {
            LONG64 now_tsc = static_cast<LONG64>(__rdtsc());
            InterlockedExchange64(
                const_cast<volatile LONG64*>(&g_bridge->sentinel_tsc), now_tsc);

            UINT64 current_whoswho_tsc = static_cast<UINT64>(g_bridge->whoswho_tsc);
            UINT64 now_check = __rdtsc();

            if (!_InterlockedCompareExchange(&g_first_heartbeat_seen, 0, 0)) {
                if (current_whoswho_tsc != 0) {
                    _InterlockedExchange(&g_first_heartbeat_seen, 1);
                    g_last_whoswho_tsc = current_whoswho_tsc;
                    g_last_check_tsc = now_check;
                }
                return true;
            }

            if (current_whoswho_tsc != g_last_whoswho_tsc) {
                g_last_whoswho_tsc = current_whoswho_tsc;
                g_last_check_tsc = now_check;
                return true;
            }

            UINT64 elapsed = now_check - g_last_check_tsc;

            if (elapsed > HEARTBEAT_TIMEOUT_TSC) {
                if (_KeBugCheckEx) {
                    _KeBugCheckEx(
                        0xDEAD5E05,
                        (ULONG_PTR)g_last_whoswho_tsc,
                        (ULONG_PTR)now_check,
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
