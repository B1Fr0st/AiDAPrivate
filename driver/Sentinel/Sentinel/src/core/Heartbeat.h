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


    constexpr UINT64 HEARTBEAT_TIMEOUT_TSC = 60ULL * 3000000000ULL;

    inline volatile sentinel_bridge_t* g_bridge = nullptr;
    inline volatile UINT64             g_last_whoswho_tsc = 0;
    inline volatile UINT64             g_last_check_tsc = 0;
    inline volatile LONG               g_initialized = 0;
    inline volatile LONG               g_first_heartbeat_seen = 0;


    __forceinline bool locate_bridge(PVOID whoswho_base, ULONG whoswho_size) {

        SN_LOG("locate_bridge: whoswho_base=%p whoswho_size=0x%lx", whoswho_base, whoswho_size);

        if (!whoswho_base || whoswho_size == 0) {
            SN_LOG("locate_bridge: FAIL - null base or zero size");
            return false;
        }

        if (!_MmIsAddressValid(whoswho_base)) {
            SN_LOG("locate_bridge: FAIL - whoswho_base %p not valid", whoswho_base);
            return false;
        }

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(whoswho_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            SN_LOG("locate_bridge: FAIL - bad DOS sig at %p (got 0x%x)", whoswho_base, dos->e_magic);
            return false;
        }

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(whoswho_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE) {
            SN_LOG("locate_bridge: FAIL - bad NT headers at %p", nt);
            return false;
        }

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        SN_LOG("locate_bridge: PE valid, %u sections", nt->FileHeader.NumberOfSections);

        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            UCHAR* section_base = static_cast<UCHAR*>(whoswho_base) + sections[i].VirtualAddress;
            ULONG section_size = sections[i].Misc.VirtualSize;

            SN_LOG("locate_bridge: section[%u] name=%.8s base=%p size=0x%lx",
                i, sections[i].Name, section_base, section_size);

            if (section_size < sizeof(sentinel_bridge_t)) {
                SN_LOG("locate_bridge: section[%u] too small for bridge (%lu < %llu)",
                    i, section_size, (ULONGLONG)sizeof(sentinel_bridge_t));
                continue;
            }

            __try {
                ULONG magic_hits = 0;
                for (ULONG offset = 0; offset <= section_size - sizeof(sentinel_bridge_t); offset += 4) {
                    if (!_MmIsAddressValid(section_base + offset))
                        continue;

                    volatile UINT32* magic_ptr = reinterpret_cast<volatile UINT32*>(section_base + offset);
                    if (!_MmIsAddressValid(reinterpret_cast<PVOID>(const_cast<UINT32*>(magic_ptr))))
                        continue;

                    if (*magic_ptr != BRIDGE_MAGIC)
                        continue;

                    magic_hits++;
                    SN_LOG("locate_bridge: MAGIC hit at section[%u]+0x%lx (addr=%p)", i, offset, magic_ptr);

                    volatile UINT32* version_ptr = magic_ptr + 1;
                    if (!_MmIsAddressValid(reinterpret_cast<PVOID>(const_cast<UINT32*>(version_ptr)))) {
                        SN_LOG("locate_bridge: version_ptr %p not valid", version_ptr);
                        continue;
                    }

                    if (*version_ptr != BRIDGE_VERSION) {
                        SN_LOG("locate_bridge: version mismatch: got %u expected %u", *version_ptr, BRIDGE_VERSION);
                        continue;
                    }

                    volatile sentinel_bridge_t* bridge =
                        reinterpret_cast<volatile sentinel_bridge_t*>(section_base + offset);

                    if (!_MmIsAddressValid(reinterpret_cast<PVOID>(const_cast<sentinel_bridge_t*>(bridge)))) {
                        SN_LOG("locate_bridge: bridge struct at %p not valid", bridge);
                        continue;
                    }

                    PVOID cb = bridge->code_base;
                    ULONG cs = bridge->code_size;

                    SN_LOG("locate_bridge: candidate bridge at %p code_base=%p code_size=0x%lx whoswho_tsc=%lld sentinel_tsc=%lld",
                        bridge, cb, cs, bridge->whoswho_tsc, bridge->sentinel_tsc);

                    if (reinterpret_cast<ULONG_PTR>(cb) > 0xFFFF800000000000ULL &&
                        cs > 0 && cs < 10 * 1024 * 1024) {
                        g_bridge = bridge;
                        g_last_whoswho_tsc = static_cast<UINT64>(bridge->whoswho_tsc);
                        g_last_check_tsc = __rdtsc();
                        SN_LOG("locate_bridge: SUCCESS - bridge=%p tsc_now=%llu", bridge, g_last_check_tsc);
                        return true;
                    } else {
                        SN_LOG("locate_bridge: REJECTED bridge - code_base=%p code_size=0x%lx out of range", cb, cs);
                    }
                }
                if (magic_hits == 0) {
                    SN_LOG("locate_bridge: section[%u] no magic hits", i);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                SN_LOG("locate_bridge: EXCEPTION in section[%u]", i);
                continue;
            }
        }

        SN_LOG("locate_bridge: FAIL - bridge not found in any section");
        return false;
    }

    __forceinline bool init(PVOID whoswho_base, ULONG whoswho_size) {
        SN_LOG("heartbeat::init: whoswho_base=%p whoswho_size=0x%lx", whoswho_base, whoswho_size);

        if (!whoswho_base || whoswho_size == 0) {
            SN_LOG("heartbeat::init: FAIL - null base or zero size");
            return false;
        }

        if (!locate_bridge(whoswho_base, whoswho_size)) {
            SN_LOG("heartbeat::init: FAIL - locate_bridge returned false");
            return false;
        }

        _InterlockedExchange(&g_initialized, 1);
        SN_LOG("heartbeat::init: SUCCESS - g_initialized=1 g_bridge=%p", g_bridge);
        return true;
    }


    __forceinline bool update_and_check() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1)) {
            SN_LOG("heartbeat::update_and_check: not initialized, skip");
            return true;
        }

        if (!g_bridge || !_MmIsAddressValid(reinterpret_cast<PVOID>(
                const_cast<sentinel_bridge_t*>(g_bridge)))) {
            SN_LOG("heartbeat::update_and_check: bridge %p invalid or NULL", g_bridge);
            return true;
        }

        __try {
            LONG64 now_tsc = static_cast<LONG64>(__rdtsc());
            InterlockedExchange64(
                const_cast<volatile LONG64*>(&g_bridge->sentinel_tsc), now_tsc);

            SN_LOG("heartbeat::update_and_check: wrote sentinel_tsc=%lld to bridge %p", now_tsc, g_bridge);

            UINT64 current_whoswho_tsc = static_cast<UINT64>(g_bridge->whoswho_tsc);
            UINT64 now_check = __rdtsc();

            if (!_InterlockedCompareExchange(&g_first_heartbeat_seen, 0, 0)) {
                if (current_whoswho_tsc != 0) {
                    _InterlockedExchange(&g_first_heartbeat_seen, 1);
                    g_last_whoswho_tsc = current_whoswho_tsc;
                    g_last_check_tsc = now_check;
                    SN_LOG("heartbeat::update_and_check: first WW heartbeat seen, whoswho_tsc=%llu", current_whoswho_tsc);
                } else {
                    SN_LOG("heartbeat::update_and_check: waiting for first WW heartbeat (whoswho_tsc=0)");
                }
                return true;
            }

            if (current_whoswho_tsc != g_last_whoswho_tsc) {
                SN_LOG("heartbeat::update_and_check: WW alive, tsc changed %llu -> %llu",
                    g_last_whoswho_tsc, current_whoswho_tsc);
                g_last_whoswho_tsc = current_whoswho_tsc;
                g_last_check_tsc = now_check;
                return true;
            }

            UINT64 elapsed = now_check - g_last_check_tsc;

            SN_LOG("heartbeat::update_and_check: WW STALE whoswho_tsc=%llu elapsed=%llu timeout=%llu",
                current_whoswho_tsc, elapsed, HEARTBEAT_TIMEOUT_TSC);

            if (elapsed > HEARTBEAT_TIMEOUT_TSC) {
                SN_LOG("heartbeat::update_and_check: TIMEOUT EXCEEDED - BUGCHECK 0xDEAD5E05");
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
            SN_LOG("heartbeat::update_and_check: EXCEPTION");
            return true;
        }

        return true;
    }
}
