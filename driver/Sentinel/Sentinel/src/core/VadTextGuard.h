#pragma once
#include <imports/Defs.h>
#include <core/TargetingLatch.h>

namespace vad_text_guard {

    inline volatile UINT64 g_text_base = 0;
    inline volatile UINT64 g_text_size = 0;

    constexpr ULONG_PTR VADROOT_OFFSET   = 0x7D8;
    constexpr ULONG_PTR VAD_NODE_OFFSET  = 0x000;
    constexpr ULONG_PTR STARTING_VPN_OFF = 0x018;
    constexpr ULONG_PTR ENDING_VPN_OFF   = 0x01C;
    constexpr ULONG_PTR VAD_FLAGS_OFF    = 0x030;

    constexpr ULONG MM_EXECUTE_READ      = 2u;
    constexpr ULONG VAD_PROT_MASK        = 0x1Fu;

    __forceinline void init(UINT64 text_base, UINT64 text_size)
    {
        _InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_text_base),
            static_cast<LONG64>(text_base));
        _InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_text_size),
            static_cast<LONG64>(text_size));
    }

    __forceinline ULONG_PTR safe_read_ptr(PVOID addr)
    {
        ULONG_PTR val = 0;
        __try {
            if (_MmIsAddressValid(addr))
                val = *reinterpret_cast<volatile ULONG_PTR*>(addr);
        } __except (EXCEPTION_EXECUTE_HANDLER) { val = 0; }
        return val;
    }

    __forceinline ULONG safe_read_ulong(PVOID addr)
    {
        ULONG val = 0;
        __try {
            if (_MmIsAddressValid(addr))
                val = *reinterpret_cast<volatile ULONG*>(addr);
        } __except (EXCEPTION_EXECUTE_HANDLER) { val = 0; }
        return val;
    }

    __forceinline void walk_vad_node(PVOID node, UINT64 text_base, UINT64 text_end,
                                     int depth, bool& hit_out,
                                     UINT64& hit_start, UINT64& hit_end, ULONG& hit_prot)
    {
        if (!node || depth > 64 || hit_out)
            return;

        if (!_MmIsAddressValid(node))
            return;

        ULONG_PTR start_vpn = safe_read_ulong(
            reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(node) + STARTING_VPN_OFF));
        ULONG_PTR end_vpn = safe_read_ulong(
            reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(node) + ENDING_VPN_OFF));

        UINT64 vad_start = start_vpn << 12;
        UINT64 vad_end   = ((end_vpn + 1) << 12);

        if (vad_start < text_end && vad_end > text_base) {
            ULONG flags_raw = safe_read_ulong(
                reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(node) + VAD_FLAGS_OFF));
            ULONG prot = (flags_raw >> 24) & VAD_PROT_MASK;
            if (prot != MM_EXECUTE_READ) {
                hit_out   = true;
                hit_start = vad_start;
                hit_end   = vad_end;
                hit_prot  = prot;
                return;
            }
        }

        ULONG_PTR* node_links = reinterpret_cast<ULONG_PTR*>(
            reinterpret_cast<ULONG_PTR>(node) + VAD_NODE_OFFSET);

        PVOID left  = reinterpret_cast<PVOID>(safe_read_ptr(
            reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(node_links) + 0x10)));
        PVOID right = reinterpret_cast<PVOID>(safe_read_ptr(
            reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(node_links) + 0x18)));

        if (left)
            walk_vad_node(left, text_base, text_end, depth + 1, hit_out, hit_start, hit_end, hit_prot);
        if (!hit_out && right)
            walk_vad_node(right, text_base, text_end, depth + 1, hit_out, hit_start, hit_end, hit_prot);
    }

    __forceinline void check(HANDLE client_pid)
    {
        UINT64 text_base = g_text_base;
        UINT64 text_size = g_text_size;
        if (!text_base || !text_size || !client_pid)
            return;

        PEPROCESS proc = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId(client_pid, &proc);
        if (!NT_SUCCESS(st) || !proc)
            return;

        __try {
            PVOID vad_root_ptr = reinterpret_cast<PVOID>(
                reinterpret_cast<ULONG_PTR>(proc) + VADROOT_OFFSET);

            ULONG_PTR root_val = safe_read_ptr(vad_root_ptr);
            if (root_val == 0 || root_val == reinterpret_cast<ULONG_PTR>(vad_root_ptr))
                goto cleanup;

            PVOID root_node = reinterpret_cast<PVOID>(root_val);

            bool hit = false;
            UINT64 hit_start = 0, hit_end = 0;
            ULONG  hit_prot  = 0;

            walk_vad_node(root_node, text_base, text_base + text_size,
                          0, hit, hit_start, hit_end, hit_prot);

            if (hit) {
                targeting_latch::latch_targeting(
                    targeting_latch::RE_REASON_TEXT_WRITABLE,
                    hit_start,
                    hit_end,
                    static_cast<UINT64>(hit_prot),
                    0
                );
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

    cleanup:
        _ObfDereferenceObject(proc);
    }
}
