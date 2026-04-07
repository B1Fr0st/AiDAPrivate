#pragma once


namespace sentinel_bridge {


    constexpr ULONG BRIDGE_MAGIC   = 0x57484F53;
    constexpr ULONG BRIDGE_VERSION = 1;


    struct bridge_t {
        volatile ULONG   magic;
        volatile ULONG   version;
        volatile PVOID   code_base;
        volatile ULONG   code_size;
        volatile LONG64  whoswho_tsc;
        volatile LONG64  sentinel_tsc;
    };


    inline bridge_t g_bridge = {
        BRIDGE_MAGIC,
        BRIDGE_VERSION,
        nullptr,
        0,
        0,
        0
    };


    __forceinline void init(PVOID text_base, ULONG text_size) {
        g_bridge.code_base = text_base;
        g_bridge.code_size = text_size;
    }


    __forceinline void tick() {
        _InterlockedExchange64(&g_bridge.whoswho_tsc, static_cast<LONG64>(__rdtsc()));
    }
}
