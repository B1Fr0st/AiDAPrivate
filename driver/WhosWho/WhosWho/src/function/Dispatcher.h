#pragma once
#include <ntifs.h>
#include <intrin.h>

#include <function/Struct.h>
#include <function/Functions.h>
#include <function/CoreSecurity.h>
#include <function/AntiDebug.h>
#include <function/SentinelBridge.h>
#include <function/impl/AntiDumpKernel.h>
#include <function/impl/driver/FileHandleScanner.h>
#include <function/DmaCanary.h>
#include <function/TargetingLatch.h>
#include <function/DebugEvents.h>
#include <function/MalwareSafe.h>
#include <hv_detect/hv_detect.h>
#include <core/HardwareId.h>

namespace dll_protection {
    ULONG cleanup_for_session_reset(UINT32 pid, const char* reason);
}

__forceinline ULONG hash_build_key(ULONG key) {
    key ^= key >> 16;
    key *= 0x85ebca6bu;
    key ^= key >> 13;
    key *= 0xc2b2ae35u;
    key ^= key >> 16;
    return key;
}

__forceinline ULONG secondary_hash(ULONG key) {
    key = ((key >> 16) ^ key) * 0x45d9f3b;
    key = ((key >> 16) ^ key) * 0x45d9f3b;
    key = (key >> 16) ^ key;
    return key;
}

namespace ioctl_codes {
    inline volatile ULONG g_server_ioctl_seed = 0;

    __forceinline ULONG get_base() {
        ULONG key = dynamic_key::get();
        ULONG base = ((hash_build_key(key) ^ secondary_hash(key >> 3)) & 0x7FF) | 0x800;
        ULONG seed = g_server_ioctl_seed;
        if (seed != 0) {
            base ^= hash_build_key(seed) & 0x7FF;
            base |= 0x800;
        }
        return base;
    }

    __forceinline ULONG make(ULONG offset) {
        return 0x00220000u | ((get_base() + offset) << 2);
    }

    __forceinline ULONG DB()  { return make(0); }
    __forceinline ULONG PRW() { return make(1); }
    __forceinline ULONG BA()  { return make(2); }
    __forceinline ULONG RC()  { return make(4); }
    __forceinline ULONG CR()  { return make(5); }
    __forceinline ULONG AM()  { return make(6); }
    __forceinline ULONG FM()  { return make(7); }
    __forceinline ULONG HB()  { return make(8); }


    __forceinline ULONG TCTX()  { return make(9); }
    __forceinline ULONG TENUM() { return make(10); }
    __forceinline ULONG TSR()   { return make(11); }
    __forceinline ULONG QM()    { return make(12); }
    __forceinline ULONG PM()    { return make(13); }
    __forceinline ULONG ER()    { return make(14); }
    __forceinline ULONG RPEB()  { return make(15); }
    __forceinline ULONG SDF()   { return make(16); }
    __forceinline ULONG MEX()   { return make(17); }
    __forceinline ULONG V2P()   { return make(18); }


    __forceinline ULONG NCON() { return make(19); }
    __forceinline ULONG NCAP() { return make(20); }
    __forceinline ULONG NCPG() { return make(21); }
    __forceinline ULONG NDNS() { return make(22); }
    __forceinline ULONG NFLT() { return make(23); }
    __forceinline ULONG NSTS() { return make(24); }


    __forceinline ULONG EWFP() { return make(25); }
    __forceinline ULONG GSKT() { return make(26); }
    __forceinline ULONG SNBF() { return make(27); }
    __forceinline ULONG DTCP() { return make(28); }


    __forceinline ULONG PINJ() { return make(29); }
    __forceinline ULONG PMOD() { return make(30); }
    __forceinline ULONG PRED() { return make(31); }
    __forceinline ULONG STRM() { return make(32); }
    __forceinline ULONG DPIN() { return make(33); }
    __forceinline ULONG IHLD() { return make(34); }
    __forceinline ULONG CKIL() { return make(35); }
    __forceinline ULONG DNSS() { return make(36); }
    __forceinline ULONG BWMN() { return make(37); }
    __forceinline ULONG NIFS() { return make(38); }
    __forceinline ULONG PCEX() { return make(39); }
    __forceinline ULONG NFPR() { return make(40); }
    __forceinline ULONG DPRT() { return make(41); }
    __forceinline ULONG ABRT() { return make(42); }
    __forceinline ULONG ADBG() { return make(43); }
    __forceinline ULONG SRVT() { return make(44); }

    __forceinline ULONG ADMP() { return make(45); }
    __forceinline ULONG SRV2() { return make(46); }
    __forceinline ULONG RECU() { return make(47); }
    __forceinline ULONG TIRA() { return make(48); }
    __forceinline ULONG CANR() { return make(49); }
    __forceinline ULONG CANQ() { return make(50); }
    __forceinline ULONG DBGA() { return make(51); }
    __forceinline ULONG HVDT() { return make(52); }
    __forceinline ULONG RELA() { return make(53); }
    __forceinline ULONG EVTS() { return make(54); }

    __forceinline ULONG PSBX() { return make(55); }
    __forceinline ULONG USBX() { return make(56); }
    __forceinline ULONG NLOG() { return make(57); }
    __forceinline ULONG NPKT() { return make(58); }
    __forceinline ULONG SSDT() { return make(59); }
}

namespace phase3_msg {

    struct latch_targeting_request_k {
        UINT32 magic;
        UINT32 session_key;
        UINT32 reason;
        UINT32 reserved;
    };
    static_assert(sizeof(latch_targeting_request_k) == 16, "latch_targeting_request_k must be 16 bytes");

    struct re_evidence_blob_k {
        UINT64 magic;
        UINT32 version;
        UINT32 signal_family;
        UINT32 signal_id;
        UINT32 score;
        UINT32 pid;
        UINT32 reserved0;
        UINT64 caller_image_hash;
        UINT64 signals_bitmap_hash;
        UINT64 timestamp;
    };
    static_assert(sizeof(re_evidence_blob_k) == 56, "re_evidence_blob_k must be 56 bytes");

    struct re_confirmed_usermode_request_k {
        UINT32 magic;
        UINT32 session_key;
        re_evidence_blob_k evidence;
    };
    static_assert(sizeof(re_confirmed_usermode_request_k) == 64, "re_confirmed_usermode_request_k must be 64 bytes");

    struct tier_a_query_request_k {
        UINT32 magic;
        UINT32 session_key;
        UINT32 present_flag;
        UINT32 tier_mask;
        UINT64 first_driver_base;
    };
    static_assert(sizeof(tier_a_query_request_k) == 24, "tier_a_query_request_k must be 24 bytes");

    struct canary_register_request_k {
        UINT32 magic;
        UINT32 session_key;
        UINT64 va;
        UINT64 size;
        UINT32 pid;
        UINT32 result;
    };
    static_assert(sizeof(canary_register_request_k) == 32, "canary_register_request_k must be 32 bytes");

    struct debug_attach_request_k {
        UINT32 magic;
        UINT32 session_key;
        UINT32 pid;
        UINT32 result_flags;
        UINT64 reserved;
    };
    static_assert(sizeof(debug_attach_request_k) == 24, "debug_attach_request_k must be 24 bytes");
}

namespace dispatcher {

    inline volatile LONG64 g_request_counter = 0;
    inline volatile LONG64 g_last_request_time = 0;
    inline volatile ULONG g_entropy_seed = 0x5A5A5A5Au;

    inline volatile LONG64 g_last_heartbeat_time = 0;
    inline volatile ULONG g_heartbeat_counter = 0;
    inline volatile ULONG g_session_key = 0;
    inline volatile LONG g_driver_activated = 0;
    inline volatile LONG g_heartbeat_inflight = 0;
    inline volatile LONG64 g_last_heartbeat_log_time = 0;
    inline volatile ULONG g_heartbeat_log_suppressed = 0;
    inline volatile ULONG g_heartbeat_fast_intervals = 0;
    inline volatile ULONG g_heartbeat_reentrant = 0;
    inline volatile LONG64 g_hvdt_dispatch_trace_id = 0;
    inline volatile LONG64 g_tier_a_dispatch_trace_id = 0;

    inline volatile LONG64 g_server_token_time = 0;
    inline volatile ULONG g_server_token_hash = 0;
    constexpr LONG64 SERVER_TOKEN_TIMEOUT = 300000000LL;

    inline volatile UINT64 g_integrity_check_tsc = 0;
    inline volatile LONG g_integrity_verified = 0;
    constexpr UINT64 INTEGRITY_CHECK_INTERVAL = 500000000ULL;

    constexpr LONG64 HEARTBEAT_TIMEOUT = 300000000LL;
    constexpr LONG64 HEARTBEAT_LOG_INTERVAL = 10000000LL;

    __forceinline UINT64 handle_to_u64(HANDLE value) {
        return static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(value));
    }

    __forceinline UINT64 requestor_pid_to_u64(PIRP irp) {
        return irp ? static_cast<UINT64>(IoGetRequestorProcessId(irp)) : 0;
    }

    __forceinline LONG64 next_hvdt_trace_id() {
        return _InterlockedIncrement64(&g_hvdt_dispatch_trace_id);
    }

    __forceinline LONG64 next_tier_a_trace_id() {
        return _InterlockedIncrement64(&g_tier_a_dispatch_trace_id);
    }

    __forceinline UINT64 elapsed_us_from_qpc(const LARGE_INTEGER& start, const LARGE_INTEGER& freq) {
        LARGE_INTEGER now = KeQueryPerformanceCounter(nullptr);
        if (freq.QuadPart <= 0 || now.QuadPart < start.QuadPart)
            return 0;
        return static_cast<UINT64>(((now.QuadPart - start.QuadPart) * 1000000ULL) / static_cast<UINT64>(freq.QuadPart));
    }

    struct hvdt_ioctl_decode_snapshot_t {
        ULONG encoded;
        ULONG base;
        ULONG offset;
        ULONG expected_hvdt_code;
        ULONG key_hash;
        ULONG ioctl_seed_hash;
        BOOLEAN valid;
    };

    __forceinline hvdt_ioctl_decode_snapshot_t decode_ioctl_snapshot(ULONG code) {
        hvdt_ioctl_decode_snapshot_t out{};
        out.offset = 0xffffffffu;
        ULONG key = dynamic_key::get();
        out.base = ioctl_codes::get_base();
        out.expected_hvdt_code = ioctl_codes::HVDT();
        out.key_hash = hash_build_key(key);
        out.ioctl_seed_hash = ioctl_codes::g_server_ioctl_seed != 0 ? hash_build_key(ioctl_codes::g_server_ioctl_seed) : 0;
        if ((code & 0xFFFF0000u) != 0x00220000u)
            return out;
        out.encoded = (code & 0x0000FFFFu) >> 2;
        if (out.encoded >= out.base) {
            ULONG candidate = out.encoded - out.base;
            if (candidate <= 59u) {
                out.offset = candidate;
                out.valid = TRUE;
            }
        }
        return out;
    }

    __forceinline BOOLEAN looks_like_hvdt_buffer_shape(ULONG input_size, ULONG output_size) {
        if (input_size == sizeof(hv_detect_result_k) && output_size == sizeof(hv_detect_result_k))
            return TRUE;

        if (input_size >= sizeof(hv_detect_request_k) &&
            output_size >= sizeof(hv_detect_result_k) &&
            input_size == output_size &&
            input_size >= 0x1000u &&
            input_size <= 0x2000u)
            return TRUE;

        const ULONG secure_in = static_cast<ULONG>(secure_comm::SECURE_WIRE_PREFIX + sizeof(hv_detect_request_k));
        const ULONG secure_out = static_cast<ULONG>(secure_comm::SECURE_WIRE_PREFIX + sizeof(hv_detect_result_k));
        return input_size == secure_in && output_size == secure_out;
    }

    __forceinline BOOLEAN is_hvdt_trace_candidate(ULONG code, ULONG input_size, ULONG output_size, const hvdt_ioctl_decode_snapshot_t& decoded) {
        if (code == decoded.expected_hvdt_code)
            return TRUE;

        if (decoded.valid && decoded.offset == 52u)
            return TRUE;

        return looks_like_hvdt_buffer_shape(input_size, output_size);
    }

    __forceinline BOOLEAN looks_like_tier_a_buffer_shape(ULONG input_size, ULONG output_size) {
        return input_size >= sizeof(phase3_msg::tier_a_query_request_k) &&
               output_size >= sizeof(phase3_msg::tier_a_query_request_k);
    }

    __forceinline BOOLEAN is_tier_a_trace_candidate(
        ULONG code,
        ULONG input_size,
        ULONG output_size,
        const hvdt_ioctl_decode_snapshot_t& decoded,
        ULONG expected_tira_code)
    {
        if (code == expected_tira_code)
            return TRUE;
        if (decoded.valid && decoded.offset == 48u)
            return TRUE;
        return looks_like_tier_a_buffer_shape(input_size, output_size);
    }

    __forceinline void complete_hvdt_trace_irp(
        PIRP irp,
        NTSTATUS status,
        ULONG_PTR information,
        LONG64 trace_id,
        const char* phase,
        const LARGE_INTEGER& start,
        const LARGE_INTEGER& freq)
    {
        HVD_LOG_IMMEDIATE("dispatch_complete_early trace=%lld phase=%s status=0x%08lx bytes=%llu io_status=0x%08lx io_info=%llu elapsed_us=%llu cpu=%lu irql=%lu pid=%llu tid=%llu requestor_pid=%llu",
            trace_id,
            phase ? phase : "unknown",
            status,
            static_cast<UINT64>(information),
            irp ? irp->IoStatus.Status : STATUS_INVALID_PARAMETER,
            irp ? static_cast<UINT64>(irp->IoStatus.Information) : 0,
            elapsed_us_from_qpc(start, freq),
            KeGetCurrentProcessorNumber(),
            (ULONG)KeGetCurrentIrql(),
            handle_to_u64(PsGetCurrentProcessId()),
            handle_to_u64(PsGetCurrentThreadId()),
            requestor_pid_to_u64(irp));
    }

    __forceinline ULONG get_heartbeat_magic() {
        return 0xDEADBEEFu ^ dynamic_key::get();
    }

    __forceinline BOOLEAN should_log_heartbeat(LONG64 now, ULONG* suppressed) {
        if (suppressed) *suppressed = 0;
        LONG64 last = _InterlockedCompareExchange64(&g_last_heartbeat_log_time, 0, 0);
        if (last != 0 && now - last < HEARTBEAT_LOG_INTERVAL) {
            _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_heartbeat_log_suppressed));
            return FALSE;
        }
        if (_InterlockedCompareExchange64(&g_last_heartbeat_log_time, now, last) == last) {
            if (suppressed) {
                *suppressed = static_cast<ULONG>(
                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_heartbeat_log_suppressed), 0));
            }
            return TRUE;
        }
        _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_heartbeat_log_suppressed));
        return FALSE;
    }

    __forceinline BOOLEAN is_re_abort_reason(ULONG reason) {
        if (reason >= 0xAE00u && reason <= 0xAEFFu)
            return TRUE;

        switch (reason) {
        case sentinel_bridge::RE_REASON_GENERIC:
        case sentinel_bridge::RE_REASON_DEBUG_ATTACH:
        case sentinel_bridge::RE_REASON_DR_SET:
        case sentinel_bridge::RE_REASON_FOREIGN_HND:
        case sentinel_bridge::RE_REASON_INJECTED_DLL:
        case sentinel_bridge::RE_REASON_WATCHDOG_STALL:
        case sentinel_bridge::RE_REASON_PARENT_RE_TOOL:
        case sentinel_bridge::RE_REASON_VAD_MAPPED_IN_RE:
        case sentinel_bridge::RE_REASON_TEXT_WRITABLE:
        case sentinel_bridge::RE_REASON_HOSTILE_DRIVER:
        case sentinel_bridge::RE_REASON_HOSTILE_DEVICE:
        case sentinel_bridge::RE_REASON_KD_ENABLED:
        case sentinel_bridge::RE_REASON_DMA_CANARY:
        case sentinel_bridge::RE_REASON_TARGET_FILE_OPENED:
        case sentinel_bridge::RE_REASON_TARGET_SECTION_MAPPED:
        case sentinel_bridge::RE_REASON_DEBUG_BY_RE_TOOL:
        case sentinel_bridge::RE_REASON_KD_TARGETING_US:
        case sentinel_bridge::RE_REASON_OB_WRITE:
        case sentinel_bridge::RE_REASON_OB_CREATE_THREAD:
        case sentinel_bridge::RE_REASON_OB_SUSPEND:
        case sentinel_bridge::RE_REASON_DEBUG_PORT_TRAP:
        case sentinel_bridge::RE_REASON_SIDECHANNEL_CORROBORATED:
        case 0x0002u:
            return TRUE;
        default:
            return FALSE;
        }
    }

    __forceinline void activate_server_seed_state(UINT64 server_nonce, UINT32 token_hash, UINT32 session_key) {
        dynamic_key::set_server_seed(server_nonce, token_hash, session_key);
        UINT32 nonce_lo = static_cast<UINT32>(server_nonce);
        UINT32 nonce_hi = static_cast<UINT32>(server_nonce >> 32);
        UINT32 ioctl_seed = hash_build_key(nonce_lo ^ _rotl(nonce_hi, 7) ^ token_hash ^ _rotl(session_key, 13));
        ioctl_seed ^= secondary_hash(token_hash ^ session_key ^ 0xA17A5EEDu);
        if (ioctl_seed == 0) ioctl_seed = 1;
        _InterlockedExchange(reinterpret_cast<volatile LONG*>(&ioctl_codes::g_server_ioctl_seed), static_cast<LONG>(ioctl_seed));
    }

    __forceinline void reset_dynamic_session_state(const char* reason, HANDLE prev_client, ULONG cleared_canaries, BOOLEAN cleanup_client) {
        LONG64 last_hb = _InterlockedCompareExchange64(&g_last_heartbeat_time, 0, 0);
        LONG64 server_token_time = _InterlockedCompareExchange64(&g_server_token_time, 0, 0);
        ULONG session_key = static_cast<ULONG>(_InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&g_session_key), 0, 0));
        ULONG heartbeat_counter = static_cast<ULONG>(_InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&g_heartbeat_counter), 0, 0));
        ULONG server_seed = dynamic_key::g_server_seed;
        ULONG ioctl_seed = ioctl_codes::g_server_ioctl_seed;
        LONG activated = _InterlockedCompareExchange(&g_driver_activated, 0, 0);
        HANDLE caller_pid = PsGetCurrentProcessId();

        WW_LOG("SESSION_RESET: reason=%s prev_client=%lu caller_pid=%lu cleared_canaries=%lu had_session=%u heartbeat_counter=%lu activated=%ld last_hb=%lld server_token_time=%lld server_seed_set=%u ioctl_seed_set=%u cleanup_client=%u",
            reason ? reason : "unknown",
            static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(prev_client)),
            static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(caller_pid)),
            cleared_canaries,
            session_key != 0 ? 1u : 0u,
            heartbeat_counter,
            activated,
            last_hb,
            server_token_time,
            server_seed != 0 ? 1u : 0u,
            ioctl_seed != 0 ? 1u : 0u,
            cleanup_client ? 1u : 0u);

        if (activated != 0 && (server_seed == 0 || ioctl_seed == 0)) {
            WW_LOG("SESSION_RESET: SECURITY_FAILURE activated_without_seed reason=%s had_server_seed=%u had_ioctl_seed=%u heartbeat_counter=%lu",
                reason ? reason : "unknown",
                server_seed != 0 ? 1u : 0u,
                ioctl_seed != 0 ? 1u : 0u,
                heartbeat_counter);
        }

        file_handle_scanner::stop(reason ? reason : "session_reset", prev_client, cleanup_client ? TRUE : FALSE);
        anti_dma_canary::stop_timer(reason ? reason : "session_reset",
            static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(prev_client)),
            cleanup_client ? TRUE : FALSE);

        _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_server_seed), 0);
        _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_cached_key), 0);
        _InterlockedExchange(reinterpret_cast<volatile LONG*>(&ioctl_codes::g_server_ioctl_seed), 0);
        _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_session_key), 0);
        _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_heartbeat_counter), 0);
        _InterlockedExchange(&g_driver_activated, 0);
        _InterlockedExchange64(&g_last_heartbeat_time, 0);
        _InterlockedExchange64(&g_server_token_time, 0);
        _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_server_token_hash), 0);
        caller_validation::unregister_client();
        secure_comm::reset();

        if (cleanup_client && prev_client) {
            UINT32 prev_pid = static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(prev_client));
            ULONG cleanup_cleared = anti_dma_canary::cleanup_for_pid(prev_pid);
            ULONG dprt_cleared = dll_protection::cleanup_for_session_reset(prev_pid, reason);
            continuous_anti_debug::stop();
            continuous_anti_dump::stop();
            WW_LOG("SESSION_RESET: cleanup_done reason=%s prev_pid=%u canaries_cleared=%lu dprt_slots_cleared=%lu",
                reason ? reason : "unknown",
                prev_pid,
                cleanup_cleared,
                dprt_cleared);
        }
    }

    __forceinline BOOLEAN verify_dispatch_integrity(PDRIVER_OBJECT driver_obj) {
        if (!driver_obj) return FALSE;

        __try {
            volatile PDRIVER_DISPATCH create_handler = driver_obj->MajorFunction[IRP_MJ_CREATE];
            volatile PDRIVER_DISPATCH ioctl_handler = driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL];

            if (!create_handler || !ioctl_handler) return FALSE;

            UINT64 create_addr = reinterpret_cast<UINT64>(create_handler);
            UINT64 ioctl_addr = reinterpret_cast<UINT64>(ioctl_handler);

            if (create_addr < 0xFFFF800000000000ULL) return FALSE;
            if (ioctl_addr < 0xFFFF800000000000ULL) return FALSE;

            PUINT8 create_bytes = reinterpret_cast<PUINT8>(create_handler);
            PUINT8 ioctl_bytes = reinterpret_cast<PUINT8>(ioctl_handler);

            if (*create_bytes == 0xE9 || *create_bytes == 0xFF) return FALSE;
            if (*ioctl_bytes == 0xE9 || *ioctl_bytes == 0xFF) return FALSE;

            if (create_bytes[0] == 0x48 && create_bytes[1] == 0xB8) return FALSE;
            if (ioctl_bytes[0] == 0x48 && ioctl_bytes[1] == 0xB8) return FALSE;

        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }

        return TRUE;
    }

    __forceinline BOOLEAN is_session_valid() {
        if (g_driver_activated == 0)
            return FALSE;

        LARGE_INTEGER current_time;
        KeQuerySystemTime(&current_time);

        LONG64 last_hb = _InterlockedCompareExchange64(&g_last_heartbeat_time, 0, 0);
        if (last_hb == 0)
            return FALSE;

        LONG64 elapsed = current_time.QuadPart - last_hb;
        if (elapsed > HEARTBEAT_TIMEOUT) {
            reset_dynamic_session_state("is_session_valid_timeout", caller_validation::g_registered_client_pid, 0, TRUE);
            return FALSE;
        }

        LONG64 srv_time = _InterlockedCompareExchange64(&g_server_token_time, 0, 0);
        if (srv_time != 0) {
            LONG64 srv_elapsed = current_time.QuadPart - srv_time;
            if (srv_elapsed > SERVER_TOKEN_TIMEOUT) {
                reset_dynamic_session_state("server_token_timeout", caller_validation::g_registered_client_pid, 0, TRUE);
                return FALSE;
            }
        }

        if (!caller_validation::is_valid_request()) {
            return FALSE;
        }

        return TRUE;
    }

    __forceinline ULONG next_random() {
        ULONG x = g_entropy_seed;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        g_entropy_seed = x;
        return x;
    }

    __forceinline void add_timing_noise() {
        volatile LONG64 tsc = (LONG64)__rdtsc();
        volatile ULONG spin = ((ULONG)tsc & 0x7) + 1;
        while (spin--) {
            YieldProcessor();
        }
        g_entropy_seed ^= (ULONG)(tsc & 0xFFFFFFFFu);
    }

    __forceinline void scatter_kernel() {
        ULONG pattern = next_random() & 0xF;
        switch (pattern) {
            case 0: YieldProcessor(); break;
            case 1: add_timing_noise(); break;
            case 2: YieldProcessor(); YieldProcessor(); break;
            case 3: KeMemoryBarrier(); break;
            case 4: { volatile int v = 0; for(int i = 0; i < 2; i++) { v += i; YieldProcessor(); } } break;
            case 5: { volatile ULONG x = g_entropy_seed; x ^= x << 7; g_entropy_seed = x; } break;
            case 6: add_timing_noise(); YieldProcessor(); break;
            case 7: { for(int i = 0; i < 3; i++) YieldProcessor(); } break;
            case 8: KeMemoryBarrier(); YieldProcessor(); break;
            case 9: { volatile LONG64 t = (LONG64)__rdtsc(); g_last_request_time = t; } break;
            case 10: { volatile int v = 0; v = (int)(next_random() & 0x3); } break;
            default: YieldProcessor(); break;
        }
    }

    __forceinline BOOLEAN check_rate_limit() {
        LONG64 current_count = _InterlockedIncrement64(&g_request_counter);

        LARGE_INTEGER current_time;
        KeQuerySystemTime(&current_time);

        LONG64 last_time = _InterlockedCompareExchange64(&g_last_request_time, current_time.QuadPart, 0);

        if (last_time != 0) {
            LONG64 elapsed = current_time.QuadPart - last_time;
            if (elapsed > 10000000) {
                _InterlockedExchange64(&g_last_request_time, current_time.QuadPart);
                _InterlockedExchange64(&g_request_counter, 0);
            }
        }

        if (current_count > 50000) {
            return FALSE;
        }

        return TRUE;
    }

    __forceinline NTSTATUS Pilot(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);

        add_timing_noise();
        scatter_kernel();

        if (malware_safe::any_sandboxed()) {
            HANDLE caller_pid = PsGetCurrentProcessId();
            ULONG flags = 0;
            if (malware_safe::is_sandboxed_pid(caller_pid, &flags) &&
                (flags & malware_safe::FLAG_BLOCK_KERNEL_HANDLE)) {
                malware_safe::record_denial(caller_pid);
                WW_MALSAFE_LOG_INFO("DENY kernel_device_open pid=%lu flags=0x%08X status=0x%08X",
                    (ULONG)(ULONG_PTR)caller_pid, flags, STATUS_ACCESS_DENIED);
                irp->IoStatus.Status = STATUS_ACCESS_DENIED;
                irp->IoStatus.Information = 0;
                _IofCompleteRequest(irp, IO_NO_INCREMENT);
                return STATUS_ACCESS_DENIED;
            }
        }

        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        _IofCompleteRequest(irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;
    }

    __forceinline NTSTATUS Controller(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);

        PIO_STACK_LOCATION early_stack = irp ? IoGetCurrentIrpStackLocation(irp) : nullptr;
        const ULONG early_code = early_stack ? early_stack->Parameters.DeviceIoControl.IoControlCode : 0;
        const ULONG early_input_size = early_stack ? early_stack->Parameters.DeviceIoControl.InputBufferLength : 0;
        const ULONG early_output_size = early_stack ? early_stack->Parameters.DeviceIoControl.OutputBufferLength : 0;
        const hvdt_ioctl_decode_snapshot_t early_decode = decode_ioctl_snapshot(early_code);
        const BOOLEAN hvdt_trace = is_hvdt_trace_candidate(early_code, early_input_size, early_output_size, early_decode);
        const LONG64 hvdt_trace_id = hvdt_trace ? next_hvdt_trace_id() : 0;
        const ULONG early_expected_tira = ioctl_codes::TIRA();
        const BOOLEAN tier_a_trace = is_tier_a_trace_candidate(early_code, early_input_size, early_output_size, early_decode, early_expected_tira);
        const LONG64 tier_a_trace_id = tier_a_trace ? next_tier_a_trace_id() : 0;
        LARGE_INTEGER hvdt_dispatch_freq{};
        LARGE_INTEGER hvdt_dispatch_start = KeQueryPerformanceCounter(&hvdt_dispatch_freq);
        if (tier_a_trace) {
            WW_LOG("TIRA_DISPATCH_ENTER trace=%lld raw_code=0x%08lx expected_tira=0x%08lx decoded_valid=%u decoded_offset=%lu encoded=0x%lx dyn_base=0x%lx key_hash=0x%08lx ioctl_seed_hash=0x%08lx input_size=%lu output_size=%lu requestor=%u requestor_pid=%llu current_pid=%llu current_tid=%llu cpu=%lu irql=%lu buffer_present=%u device_present=%u shape=%u activated=%ld registered_pid=%llu server_seed_set=%u ioctl_seed_set=%u",
                tier_a_trace_id,
                early_code,
                early_expected_tira,
                early_decode.valid ? 1u : 0u,
                early_decode.offset,
                early_decode.encoded,
                early_decode.base,
                early_decode.key_hash,
                early_decode.ioctl_seed_hash,
                early_input_size,
                early_output_size,
                irp ? static_cast<ULONG>(irp->RequestorMode) : 0xffffffffu,
                requestor_pid_to_u64(irp),
                handle_to_u64(PsGetCurrentProcessId()),
                handle_to_u64(PsGetCurrentThreadId()),
                KeGetCurrentProcessorNumber(),
                static_cast<ULONG>(KeGetCurrentIrql()),
                (irp && irp->AssociatedIrp.SystemBuffer) ? 1u : 0u,
                device_object ? 1u : 0u,
                looks_like_tier_a_buffer_shape(early_input_size, early_output_size) ? 1u : 0u,
                _InterlockedCompareExchange(&g_driver_activated, 0, 0),
                handle_to_u64(caller_validation::g_registered_client_pid),
                dynamic_key::g_server_seed != 0 ? 1u : 0u,
                ioctl_codes::g_server_ioctl_seed != 0 ? 1u : 0u);
        }
        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_enter trace=%lld step=%lu irp=%p system_buffer=%p raw_code=0x%08lx expected_hvdt=0x%08lx decoded_valid=%u decoded_offset=%lu encoded=0x%lx dyn_base=0x%lx key_hash=0x%08lx ioctl_seed_hash=0x%08lx input_size=%lu output_size=%lu requestor=%u requestor_pid=%llu current_pid=%llu current_tid=%llu cpu=%lu irql=%lu buffer_present=%u device_present=%u shape=%u io_status=0x%08lx io_info=%llu",
                hvdt_trace_id,
                1u,
                irp,
                irp ? irp->AssociatedIrp.SystemBuffer : nullptr,
                early_code,
                early_decode.expected_hvdt_code,
                early_decode.valid ? 1u : 0u,
                early_decode.offset,
                early_decode.encoded,
                early_decode.base,
                early_decode.key_hash,
                early_decode.ioctl_seed_hash,
                early_input_size,
                early_output_size,
                irp ? static_cast<ULONG>(irp->RequestorMode) : 0xffffffffu,
                requestor_pid_to_u64(irp),
                handle_to_u64(PsGetCurrentProcessId()),
                handle_to_u64(PsGetCurrentThreadId()),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql(),
                (irp && irp->AssociatedIrp.SystemBuffer) ? 1u : 0u,
                device_object ? 1u : 0u,
                looks_like_hvdt_buffer_shape(early_input_size, early_output_size) ? 1u : 0u,
                irp ? irp->IoStatus.Status : STATUS_INVALID_PARAMETER,
                irp ? static_cast<UINT64>(irp->IoStatus.Information) : 0);
            HVD_LOG_IMMEDIATE("dispatch_timing_noise_pre trace=%lld step=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id, 2u, elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql());
        }
        add_timing_noise();
        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_timing_noise_post trace=%lld step=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id, 3u, elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql());
            HVD_LOG_IMMEDIATE("dispatch_scatter_pre trace=%lld step=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id, 4u, elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql());
        }
        scatter_kernel();
        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_scatter_post trace=%lld step=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id, 5u, elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql());
            HVD_LOG_IMMEDIATE("dispatch_integrity_pre trace=%lld step=%lu device_present=%u driver_present=%u elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id, 6u, device_object ? 1u : 0u,
                (device_object && device_object->DriverObject) ? 1u : 0u,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql());
        }

        if (device_object && !verify_dispatch_integrity(device_object->DriverObject)) {
            if (hvdt_trace) {
                HVD_LOG_IMMEDIATE("dispatch_integrity_post trace=%lld step=%lu ok=0 status=0x%08lx elapsed_us=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id, 7u, STATUS_ACCESS_DENIED,
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql());
            }
            if (tier_a_trace) {
                WW_LOG("TIRA_DISPATCH_REJECT trace=%lld phase=dispatch_integrity status=0x%08lx raw_code=0x%08lx expected_tira=0x%08lx elapsed_us=%llu driver_object=%p",
                    tier_a_trace_id,
                    STATUS_ACCESS_DENIED,
                    early_code,
                    early_expected_tira,
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    device_object ? device_object->DriverObject : nullptr);
            }
            _InterlockedExchange(&g_driver_activated, 0);
            caller_validation::unregister_client();
            irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            irp->IoStatus.Information = 0;
            if (hvdt_trace)
                complete_hvdt_trace_irp(irp, STATUS_ACCESS_DENIED, 0, hvdt_trace_id, "integrity_reject", hvdt_dispatch_start, hvdt_dispatch_freq);
            _IofCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }
        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_integrity_post trace=%lld step=%lu ok=1 elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id, 7u, elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql());
            HVD_LOG_IMMEDIATE("dispatch_rate_limit_pre trace=%lld step=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id, 8u, elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql());
        }

        if (!check_rate_limit()) {
            if (hvdt_trace) {
                HVD_LOG_IMMEDIATE("dispatch_rate_limit_post trace=%lld step=%lu ok=0 status=0x%08lx elapsed_us=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id, 9u, STATUS_DEVICE_BUSY,
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql());
            }
            if (tier_a_trace) {
                WW_LOG("TIRA_DISPATCH_REJECT trace=%lld phase=rate_limit status=0x%08lx raw_code=0x%08lx requestor_pid=%llu elapsed_us=%llu",
                    tier_a_trace_id,
                    STATUS_DEVICE_BUSY,
                    early_code,
                    requestor_pid_to_u64(irp),
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
            }
            irp->IoStatus.Status = STATUS_DEVICE_BUSY;
            irp->IoStatus.Information = 0;
            if (hvdt_trace)
                complete_hvdt_trace_irp(irp, STATUS_DEVICE_BUSY, 0, hvdt_trace_id, "rate_limit_reject", hvdt_dispatch_start, hvdt_dispatch_freq);
            _IofCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_DEVICE_BUSY;
        }
        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_rate_limit_post trace=%lld step=%lu ok=1 elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id, 9u, elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql());
        }

        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_sandbox_gate_pre trace=%lld step=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id, 10u, elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql());
        }
        BOOLEAN hvdt_sandbox_checked = FALSE;
        if (malware_safe::any_sandboxed()) {
            hvdt_sandbox_checked = TRUE;
            HANDLE caller_pid = PsGetCurrentProcessId();
            HANDLE client_pid = caller_validation::g_registered_client_pid;
            if (caller_pid != client_pid) {
                ULONG sbx_flags = 0;
                if (malware_safe::is_sandboxed_pid(caller_pid, &sbx_flags) &&
                    (sbx_flags & malware_safe::FLAG_BLOCK_KERNEL_HANDLE)) {
                    malware_safe::record_denial(caller_pid);
                    WW_MALSAFE_LOG_INFO("DENY ioctl_from_sandbox pid=%lu flags=0x%08X status=0x%08X",
                        (ULONG)(ULONG_PTR)caller_pid, sbx_flags, STATUS_ACCESS_DENIED);
                    if (tier_a_trace) {
                        WW_LOG("TIRA_DISPATCH_REJECT trace=%lld phase=sandbox status=0x%08lx caller_pid=%llu client_pid=%llu flags=0x%08lx elapsed_us=%llu",
                            tier_a_trace_id,
                            STATUS_ACCESS_DENIED,
                            handle_to_u64(caller_pid),
                            handle_to_u64(client_pid),
                            sbx_flags,
                            elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                    }
                    irp->IoStatus.Status = STATUS_ACCESS_DENIED;
                    irp->IoStatus.Information = 0;
                    if (hvdt_trace)
                        complete_hvdt_trace_irp(irp, STATUS_ACCESS_DENIED, 0, hvdt_trace_id, "sandbox_reject", hvdt_dispatch_start, hvdt_dispatch_freq);
                    _IofCompleteRequest(irp, IO_NO_INCREMENT);
                    return STATUS_ACCESS_DENIED;
                }
            }
            else {
                ULONG sbx_flags_self = 0;
                if (malware_safe::is_sandboxed_pid(caller_pid, &sbx_flags_self)) {
                    WW_MALSAFE_LOG_INFO("EXEMPT ioctl_from_sandbox pid=%lu flags=0x%08X (registered client, self-sandbox)",
                        (ULONG)(ULONG_PTR)caller_pid, sbx_flags_self);
                }
            }
        }
        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_sandbox_gate_post trace=%lld step=%lu sandbox_present=%u elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id, 11u, hvdt_sandbox_checked ? 1u : 0u,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql());
            HVD_LOG_IMMEDIATE("dispatch_heartbeat_timeout_pre trace=%lld step=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id, 12u, elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql());
        }


        {
            LONG64 last_hb = _InterlockedCompareExchange64(&g_last_heartbeat_time, 0, 0);
            if (last_hb != 0) {
                LARGE_INTEGER now;
                KeQuerySystemTime(&now);
                LONG64 elapsed = now.QuadPart - last_hb;
                if (elapsed > HEARTBEAT_TIMEOUT) {
                    WW_LOG("Controller: session timed out (elapsed=%lld > %lld), resetting dynamic state for reconnection",
                        elapsed, (LONG64)HEARTBEAT_TIMEOUT);
                    HANDLE prev_client = caller_validation::g_registered_client_pid;
                    reset_dynamic_session_state("controller_timeout", prev_client, 0, TRUE);
                }
            }
        }
        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_heartbeat_timeout_post trace=%lld step=%lu activated=%ld last_hb_set=%u server_seed_set=%u ioctl_seed_set=%u elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id,
                13u,
                _InterlockedCompareExchange(&g_driver_activated, 0, 0),
                _InterlockedCompareExchange64(&g_last_heartbeat_time, 0, 0) != 0 ? 1u : 0u,
                dynamic_key::g_server_seed != 0 ? 1u : 0u,
                ioctl_codes::g_server_ioctl_seed != 0 ? 1u : 0u,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql());
        }

        NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
        ULONG bytes = 0;
        BOOLEAN tier_a_handler_reached = FALSE;

        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

        const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
        const ULONG input_size = stack->Parameters.DeviceIoControl.InputBufferLength;
        const ULONG output_size = stack->Parameters.DeviceIoControl.OutputBufferLength;
        PVOID buffer = irp->AssociatedIrp.SystemBuffer;
        PVOID original_buffer = buffer;
        PVOID secure_work_buffer = nullptr;
        BOOLEAN secure_wrapped = FALSE;
        UINT64 secure_request_entropy = 0;
        UINT64 secure_request_id = 0;
        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_stack_loaded trace=%lld step=%lu code=0x%08lx expected_hvdt=0x%08lx hvdt_match=%u decoded_valid=%u decoded_offset=%lu encoded=0x%lx dyn_base=0x%lx key_hash=0x%08lx ioctl_seed_hash=0x%08lx input_size=%lu output_size=%lu buffer=%p original_buffer=%p requestor=%u requestor_pid=%llu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id,
                14u,
                code,
                early_decode.expected_hvdt_code,
                code == early_decode.expected_hvdt_code ? 1u : 0u,
                early_decode.valid ? 1u : 0u,
                early_decode.offset,
                early_decode.encoded,
                early_decode.base,
                early_decode.key_hash,
                early_decode.ioctl_seed_hash,
                input_size,
                output_size,
                buffer,
                original_buffer,
                static_cast<ULONG>(irp->RequestorMode),
                requestor_pid_to_u64(irp),
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql());
        }

        if (!buffer) {
            if (code == ioctl_codes::STRM() || code == ioctl_codes::CKIL()) {
                WW_LOG("netaction::DISPATCH null_buffer code=0x%08X input_size=%lu output_size=%lu",
                    code, input_size, output_size);
            }
            if (tier_a_trace) {
                WW_LOG("TIRA_DISPATCH_REJECT trace=%lld phase=null_buffer status=0x%08lx raw_code=0x%08lx expected_tira=0x%08lx input_size=%lu output_size=%lu elapsed_us=%llu",
                    tier_a_trace_id,
                    STATUS_INVALID_PARAMETER,
                    code,
                    early_expected_tira,
                    input_size,
                    output_size,
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
            }
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            if (hvdt_trace)
                complete_hvdt_trace_irp(irp, STATUS_INVALID_PARAMETER, 0, hvdt_trace_id, "null_buffer", hvdt_dispatch_start, hvdt_dispatch_freq);
            _IofCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_INVALID_PARAMETER;
        }

        if (code == IOCTL_AIDA_GET_HWID) {
            NTSTATUS hwid_status = HardwareIdHandleIoctl(irp, stack);
            ULONG hwid_bytes = static_cast<ULONG>(irp->IoStatus.Information);
            irp->IoStatus.Status = hwid_status;
            irp->IoStatus.Information = hwid_bytes;
            if (hvdt_trace)
                complete_hvdt_trace_irp(irp, hwid_status, hwid_bytes, hvdt_trace_id, "hwid_passthrough", hvdt_dispatch_start, hvdt_dispatch_freq);
            _IofCompleteRequest(irp, IO_NO_INCREMENT);
            return hwid_status;
        }

        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_secure_gate trace=%lld step=%lu needs_secure=%u comm_initialized=%ld master_key_valid=%ld input_size=%lu output_size=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id,
                15u,
                code != ioctl_codes::HB() ? 1u : 0u,
                _InterlockedCompareExchange(&secure_comm::g_comm_initialized, 0, 0),
                _InterlockedCompareExchange(&secure_comm::g_master_key_valid, 0, 0),
                input_size,
                output_size,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql());
        }

        if (code != ioctl_codes::HB() && secure_comm::g_comm_initialized != 0) {
            if (hvdt_trace) {
                HVD_LOG_IMMEDIATE("dispatch_secure_header_pre trace=%lld step=%lu input_size=%lu required=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id,
                    16u,
                    input_size,
                    (ULONG)sizeof(secure_comm::SECURE_HEADER),
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    KeGetCurrentProcessorNumber(),
                    (ULONG)KeGetCurrentIrql());
            }
            if (input_size < sizeof(secure_comm::SECURE_HEADER)) {
                if (code == ioctl_codes::STRM() || code == ioctl_codes::CKIL()) {
                    WW_LOG("netaction::DISPATCH secure_header_too_small code=0x%08X input_size=%lu required=%lu",
                        code, input_size, (ULONG)sizeof(secure_comm::SECURE_HEADER));
                }
                if (tier_a_trace) {
                    WW_LOG("TIRA_DISPATCH_REJECT trace=%lld phase=secure_header_too_small status=0x%08lx raw_code=0x%08lx input_size=%lu required=%lu comm_initialized=%ld elapsed_us=%llu",
                        tier_a_trace_id,
                        STATUS_ACCESS_DENIED,
                        code,
                        input_size,
                        static_cast<ULONG>(sizeof(secure_comm::SECURE_HEADER)),
                        _InterlockedCompareExchange(&secure_comm::g_comm_initialized, 0, 0),
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                }
                irp->IoStatus.Status = STATUS_ACCESS_DENIED;
                irp->IoStatus.Information = 0;
                if (hvdt_trace)
                    complete_hvdt_trace_irp(irp, STATUS_ACCESS_DENIED, 0, hvdt_trace_id, "secure_header_too_small", hvdt_dispatch_start, hvdt_dispatch_freq);
                _IofCompleteRequest(irp, IO_NO_INCREMENT);
                return STATUS_ACCESS_DENIED;
            }

            secure_comm::SECURE_HEADER sec_hdr{};
            RtlCopyMemory(&sec_hdr, buffer, sizeof(sec_hdr));
            secure_request_entropy = sec_hdr.entropy;
            secure_request_id = sec_hdr.request_id;
            if (hvdt_trace) {
                HVD_LOG_IMMEDIATE("dispatch_secure_header_post trace=%lld step=%lu payload_size=%lu entropy_present=%u request_id_present=%u elapsed_us=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id,
                    17u,
                    sec_hdr.payload_size,
                    secure_request_entropy != 0 ? 1u : 0u,
                    secure_request_id != 0 ? 1u : 0u,
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    KeGetCurrentProcessorNumber(),
                    (ULONG)KeGetCurrentIrql());
            }

            SIZE_T work_size = output_size > input_size ? output_size : input_size;
            if (work_size < sizeof(secure_comm::SECURE_HEADER))
                work_size = sizeof(secure_comm::SECURE_HEADER);

            if (hvdt_trace) {
                HVD_LOG_IMMEDIATE("dispatch_secure_alloc_pre trace=%lld step=%lu work_size=%llu elapsed_us=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id,
                    18u,
                    static_cast<UINT64>(work_size),
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    KeGetCurrentProcessorNumber(),
                    (ULONG)KeGetCurrentIrql());
            }
            secure_work_buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, work_size, 'mocS');
            if (!secure_work_buffer) {
                if (code == ioctl_codes::STRM() || code == ioctl_codes::CKIL()) {
                    WW_LOG("netaction::DISPATCH secure_work_buffer_alloc_failed code=0x%08X work_size=%llu",
                        code, (ULONG64)work_size);
                }
                if (tier_a_trace) {
                    WW_LOG("TIRA_DISPATCH_REJECT trace=%lld phase=secure_alloc_failed status=0x%08lx raw_code=0x%08lx work_size=%llu elapsed_us=%llu",
                        tier_a_trace_id,
                        STATUS_INSUFFICIENT_RESOURCES,
                        code,
                        static_cast<UINT64>(work_size),
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                }
                irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                irp->IoStatus.Information = 0;
                if (hvdt_trace)
                    complete_hvdt_trace_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0, hvdt_trace_id, "secure_alloc_failed", hvdt_dispatch_start, hvdt_dispatch_freq);
                _IofCompleteRequest(irp, IO_NO_INCREMENT);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            if (hvdt_trace) {
                HVD_LOG_IMMEDIATE("dispatch_secure_alloc_post trace=%lld step=%lu ok=1 work_size=%llu elapsed_us=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id,
                    19u,
                    static_cast<UINT64>(work_size),
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    KeGetCurrentProcessorNumber(),
                    (ULONG)KeGetCurrentIrql());
            }

            SIZE_T plain_size = 0;
            if (hvdt_trace) {
                HVD_LOG_IMMEDIATE("dispatch_secure_decrypt_pre trace=%lld step=%lu input_size=%lu work_size=%llu elapsed_us=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id,
                    20u,
                    input_size,
                    static_cast<UINT64>(work_size),
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    KeGetCurrentProcessorNumber(),
                    (ULONG)KeGetCurrentIrql());
            }
            if (!secure_comm::decrypt_request(buffer, input_size,
                secure_work_buffer, work_size, &plain_size)) {
                if (code == ioctl_codes::STRM() || code == ioctl_codes::CKIL()) {
                    WW_LOG("netaction::DISPATCH secure_decrypt_failed code=0x%08X input_size=%lu work_size=%llu",
                        code, input_size, (ULONG64)work_size);
                }
                if (tier_a_trace) {
                    WW_LOG("TIRA_DISPATCH_REJECT trace=%lld phase=secure_decrypt_failed status=0x%08lx raw_code=0x%08lx input_size=%lu work_size=%llu payload_size=%lu request_id_present=%u elapsed_us=%llu",
                        tier_a_trace_id,
                        STATUS_ACCESS_DENIED,
                        code,
                        input_size,
                        static_cast<UINT64>(work_size),
                        sec_hdr.payload_size,
                        secure_request_id != 0 ? 1u : 0u,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                }
                if (hvdt_trace) {
                    HVD_LOG_IMMEDIATE("dispatch_secure_decrypt_post trace=%lld step=%lu ok=0 status=0x%08lx plain_size=%llu elapsed_us=%llu cpu=%lu irql=%lu",
                        hvdt_trace_id,
                        21u,
                        STATUS_ACCESS_DENIED,
                        static_cast<UINT64>(plain_size),
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                        KeGetCurrentProcessorNumber(),
                        (ULONG)KeGetCurrentIrql());
                }
                ExFreePoolWithTag(secure_work_buffer, 'mocS');
                irp->IoStatus.Status = STATUS_ACCESS_DENIED;
                irp->IoStatus.Information = 0;
                if (hvdt_trace)
                    complete_hvdt_trace_irp(irp, STATUS_ACCESS_DENIED, 0, hvdt_trace_id, "secure_decrypt_failed", hvdt_dispatch_start, hvdt_dispatch_freq);
                _IofCompleteRequest(irp, IO_NO_INCREMENT);
                return STATUS_ACCESS_DENIED;
            }
            if (hvdt_trace) {
                HVD_LOG_IMMEDIATE("dispatch_secure_decrypt_post trace=%lld step=%lu ok=1 plain_size=%llu elapsed_us=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id,
                    21u,
                    static_cast<UINT64>(plain_size),
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    KeGetCurrentProcessorNumber(),
                    (ULONG)KeGetCurrentIrql());
            }

            buffer = secure_work_buffer;
            secure_wrapped = TRUE;
        }
        else if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_secure_skip trace=%lld step=%lu secure_wrapped=0 comm_initialized=%ld elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id,
                22u,
                _InterlockedCompareExchange(&secure_comm::g_comm_initialized, 0, 0),
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql());
        }

        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_session_validate_pre trace=%lld step=%lu code=0x%08lx activated=%ld registered_pid=%llu secure_wrapped=%u elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id,
                23u,
                code,
                _InterlockedCompareExchange(&g_driver_activated, 0, 0),
                handle_to_u64(caller_validation::g_registered_client_pid),
                secure_wrapped ? 1u : 0u,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql());
        }
        BOOLEAN hvdt_session_ok = TRUE;
        if (code != ioctl_codes::HB() && code != ioctl_codes::SRVT() && code != ioctl_codes::SRV2())
            hvdt_session_ok = is_session_valid();
        if (code != ioctl_codes::HB() && code != ioctl_codes::SRVT() && code != ioctl_codes::SRV2() && !hvdt_session_ok) {
            if (code == ioctl_codes::STRM() || code == ioctl_codes::CKIL()) {
                WW_LOG("netaction::DISPATCH session_invalid code=0x%08X g_driver_activated=%ld",
                    code, _InterlockedCompareExchange(&g_driver_activated, 0, 0));
            }
            if (tier_a_trace) {
                WW_LOG("TIRA_DISPATCH_REJECT trace=%lld phase=session_invalid status=0x%08lx raw_code=0x%08lx expected_tira=0x%08lx activated=%ld registered_pid=%llu last_hb_set=%u server_seed_set=%u ioctl_seed_set=%u secure_wrapped=%u elapsed_us=%llu",
                    tier_a_trace_id,
                    STATUS_INVALID_DEVICE_REQUEST,
                    code,
                    early_expected_tira,
                    _InterlockedCompareExchange(&g_driver_activated, 0, 0),
                    handle_to_u64(caller_validation::g_registered_client_pid),
                    _InterlockedCompareExchange64(&g_last_heartbeat_time, 0, 0) != 0 ? 1u : 0u,
                    dynamic_key::g_server_seed != 0 ? 1u : 0u,
                    ioctl_codes::g_server_ioctl_seed != 0 ? 1u : 0u,
                    secure_wrapped ? 1u : 0u,
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
            }
            if (secure_work_buffer)
                ExFreePoolWithTag(secure_work_buffer, 'mocS');
            irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            irp->IoStatus.Information = 0;
            if (hvdt_trace) {
                HVD_LOG_IMMEDIATE("dispatch_session_validate_post trace=%lld step=%lu ok=0 status=0x%08lx elapsed_us=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id,
                    24u,
                    STATUS_INVALID_DEVICE_REQUEST,
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    KeGetCurrentProcessorNumber(),
                    (ULONG)KeGetCurrentIrql());
                complete_hvdt_trace_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0, hvdt_trace_id, "session_invalid", hvdt_dispatch_start, hvdt_dispatch_freq);
            }
            _IofCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_session_validate_post trace=%lld step=%lu ok=%u elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id,
                24u,
                hvdt_session_ok ? 1u : 0u,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql());
            HVD_LOG_IMMEDIATE("dispatch_post_session_timing_pre trace=%lld step=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id,
                25u,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql());
        }

        add_timing_noise();
        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_post_session_timing_post trace=%lld step=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id,
                26u,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql());
        }

        if (code == ioctl_codes::PRW()) {
            if (input_size >= sizeof(_PRW) && output_size >= sizeof(_PRW)) {
                status = functions::handle777e((p_physical_rw)buffer);
                bytes = sizeof(_PRW);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::BA()) {
            if (input_size >= sizeof(_BA) && output_size >= sizeof(_BA)) {
                status = functions::handle777f((p_base_address)buffer);
                bytes = sizeof(_BA);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::DB()) {
            if (input_size >= sizeof(_DB) && output_size >= sizeof(_DB)) {
                status = functions::handle777d((p_dtb_solve)buffer);
                bytes = sizeof(_DB);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::RC()) {
            if (input_size >= sizeof(_RC) && output_size >= sizeof(_RC)) {
                status = functions::handle7781((p_remote_call)buffer);
                bytes = sizeof(_RC);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::CR()) {
            if (input_size >= sizeof(_CR) && output_size >= sizeof(_CR)) {
                status = functions::handle7782((p_call_result)buffer);
                bytes = sizeof(_CR);
            }
            else if (input_size >= (sizeof(_CR) - sizeof(UINT64)) && output_size >= (sizeof(_CR) - sizeof(UINT64))) {
                status = functions::handle7782_legacy((p_call_result)buffer);
                bytes = sizeof(_CR) - sizeof(UINT64);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::AM()) {
            if (input_size >= sizeof(_AM) && output_size >= sizeof(_AM)) {
                status = functions::handle7783((p_alloc_mem)buffer);
                bytes = sizeof(_AM);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::FM()) {
            if (input_size >= sizeof(_FM) && output_size >= sizeof(_FM)) {
                status = functions::handle7784((p_free_mem)buffer);
                bytes = sizeof(_FM);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }

        else if (code == ioctl_codes::TCTX()) {
            if (input_size >= sizeof(thread_ctx) && output_size >= sizeof(thread_ctx)) {
                status = functions::handle_thread_ctx((p_thread_ctx)buffer);
                bytes = sizeof(thread_ctx);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::TENUM()) {
            if (input_size >= sizeof(thread_enum) && output_size >= sizeof(thread_enum)) {
                status = functions::handle_thread_enum((p_thread_enum)buffer);
                bytes = sizeof(thread_enum);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::TSR()) {
            if (input_size >= sizeof(suspend_resume_thread) && output_size >= sizeof(suspend_resume_thread)) {
                status = functions::handle_suspend_resume_thread((p_suspend_resume_thread)buffer);
                bytes = sizeof(suspend_resume_thread);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::QM()) {
            if (input_size >= sizeof(query_memory) && output_size >= sizeof(query_memory)) {
                status = functions::handle_query_memory((p_query_memory)buffer);
                bytes = sizeof(query_memory);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::PM()) {
            if (input_size >= sizeof(protect_memory) && output_size >= sizeof(protect_memory)) {
                p_protect_memory pm_req = (p_protect_memory)buffer;
                WW_LOG("memory::protect_memory: ENTER pid=%lu addr=0x%016llX size=0x%llX new=0x%08X input_size=%lu output_size=%lu",
                    (ULONG)pm_req->pid,
                    (unsigned long long)pm_req->address,
                    (unsigned long long)pm_req->size,
                    (ULONG)pm_req->new_protect,
                    (ULONG)input_size,
                    (ULONG)output_size);
                status = functions::handle_protect_memory(pm_req);
                bytes = sizeof(protect_memory);
                WW_LOG("memory::protect_memory: EXIT pid=%lu addr=0x%016llX size=0x%llX new=0x%08X old=0x%08X status=0x%08X bytes=%lu",
                    (ULONG)pm_req->pid,
                    (unsigned long long)pm_req->address,
                    (unsigned long long)pm_req->size,
                    (ULONG)pm_req->new_protect,
                    (ULONG)pm_req->old_protect,
                    (ULONG)status,
                    (ULONG)bytes);
            }
            else {
                WW_LOG("memory::protect_memory: SIZE_MISMATCH input_size=%lu output_size=%lu expected=%llu",
                    (ULONG)input_size, (ULONG)output_size,
                    (unsigned long long)sizeof(protect_memory));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::ER()) {
            if (input_size >= sizeof(enum_regions) && output_size >= sizeof(enum_regions)) {
                status = functions::handle_enum_regions((p_enum_regions)buffer);
                bytes = sizeof(enum_regions);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::RPEB()) {
            if (input_size >= sizeof(read_peb) && output_size >= sizeof(read_peb)) {
                status = functions::handle_read_peb((p_read_peb)buffer);
                bytes = sizeof(read_peb);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::SDF()) {
            if (input_size >= sizeof(spoof_debug) && output_size >= sizeof(spoof_debug)) {
                status = functions::handle_spoof_debug_flags((p_spoof_debug)buffer);
                bytes = sizeof(spoof_debug);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::MEX()) {
            if (input_size >= sizeof(module_export) && output_size >= sizeof(module_export)) {
                status = functions::handle_get_module_export((p_module_export)buffer);
                bytes = sizeof(module_export);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::V2P()) {
            if (input_size >= sizeof(virt_to_phys) && output_size >= sizeof(virt_to_phys)) {
                status = functions::handle_virt_to_phys((p_virt_to_phys)buffer);
                bytes = sizeof(virt_to_phys);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::SSDT()) {
            if (input_size >= sizeof(ssdt_query) && output_size >= sizeof(ssdt_query)) {
                status = functions::handle_query_ssdt((p_ssdt_query)buffer);
                bytes = sizeof(ssdt_query);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NCON()) {
            if (input_size >= sizeof(net_enum_conn) && output_size >= sizeof(net_enum_conn)) {
                status = functions::handle_net_enum_conn((p_net_enum_conn)buffer);
                bytes = sizeof(net_enum_conn);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NCAP()) {
            if (input_size >= sizeof(net_cap_ctrl) && output_size >= sizeof(net_cap_ctrl)) {
                status = functions::handle_net_cap_ctrl((p_net_cap_ctrl)buffer);
                bytes = sizeof(net_cap_ctrl);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NCPG()) {
            if (input_size >= sizeof(net_cap_get) && output_size >= sizeof(net_cap_get)) {
                status = functions::handle_net_cap_get((p_net_cap_get)buffer);
                bytes = sizeof(net_cap_get);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NDNS()) {
            if (input_size >= sizeof(net_dns_get) && output_size >= sizeof(net_dns_get)) {
                status = functions::handle_net_dns_get((p_net_dns_get)buffer);
                bytes = sizeof(net_dns_get);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NFLT()) {
            if (input_size >= sizeof(net_filter_rule) && output_size >= sizeof(net_filter_rule)) {
                status = functions::handle_net_filter_rule((p_net_filter_rule)buffer);
                bytes = sizeof(net_filter_rule);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NSTS()) {
            if (input_size >= sizeof(net_stats) && output_size >= sizeof(net_stats)) {
                status = functions::handle_net_stats((p_net_stats)buffer);
                bytes = sizeof(net_stats);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::EWFP()) {
            if (input_size >= sizeof(wfp_callout_enum) && output_size >= sizeof(wfp_callout_enum)) {
                status = functions::handle_wfp_callout_enum((p_wfp_callout_enum)buffer);
                bytes = sizeof(wfp_callout_enum);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::GSKT()) {
            if (input_size >= sizeof(socket_handle_enum) && output_size >= sizeof(socket_handle_enum)) {
                status = functions::handle_socket_handle_enum((p_socket_handle_enum)buffer);
                bytes = sizeof(socket_handle_enum);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::SNBF()) {
            if (input_size >= sizeof(sniff_net_buffers) && output_size >= sizeof(sniff_net_buffers)) {
                status = functions::handle_sniff_net_buffers((p_sniff_net_buffers)buffer);
                bytes = sizeof(sniff_net_buffers);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::DTCP()) {
            if (input_size >= sizeof(tcpip_conn_dump) && output_size >= sizeof(tcpip_conn_dump)) {
                status = functions::handle_tcpip_conn_dump((p_tcpip_conn_dump)buffer);
                bytes = sizeof(tcpip_conn_dump);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }

        else if (code == ioctl_codes::PINJ()) {
            if (input_size >= sizeof(packet_inject_request) && output_size >= sizeof(packet_inject_request)) {
                status = functions::handle_packet_inject((p_packet_inject_request)buffer);
                bytes = sizeof(packet_inject_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::PMOD()) {
            if (input_size >= sizeof(packet_mod_rule_list) && output_size >= sizeof(packet_mod_rule_list) &&
                ((p_packet_mod_rule_list)buffer)->operation == 2) {
                auto* req = (p_packet_mod_rule_list)buffer;
                WW_LOG("netaction::PMOD_DISPATCH ENTER kind=list code=0x%08X input_size=%lu output_size=%lu op=%u",
                    code,
                    input_size,
                    output_size,
                    req->operation);
                status = functions::handle_packet_mod_rule_list((p_packet_mod_rule_list)buffer);
                bytes = sizeof(packet_mod_rule_list);
                WW_LOG("netaction::PMOD_DISPATCH EXIT kind=list status=0x%08X bytes=%lu rule_count=%u",
                    status,
                    bytes,
                    req->rule_count);
            }
            else if (input_size >= sizeof(packet_mod_rule) && output_size >= sizeof(packet_mod_rule)) {
                auto* req = (p_packet_mod_rule)buffer;
                WW_LOG("netaction::PMOD_DISPATCH ENTER kind=rule code=0x%08X input_size=%lu output_size=%lu op=%u rule_id=%u direction=%u protocol=%u port=%u pid=%u pattern_size=%u replace_size=%u",
                    code,
                    input_size,
                    output_size,
                    req->operation,
                    req->rule_id,
                    req->direction,
                    req->protocol,
                    req->port,
                    req->pid,
                    req->pattern_size,
                    req->replace_size);
                status = functions::handle_packet_mod_rule(req);
                bytes = sizeof(packet_mod_rule);
                WW_LOG("netaction::PMOD_DISPATCH EXIT kind=rule status=0x%08X bytes=%lu op=%u rule_id=%u active=%u",
                    status,
                    bytes,
                    req->operation,
                    req->rule_id,
                    req->active);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::PRED()) {
            if (input_size >= sizeof(traffic_redirect_list) && output_size >= sizeof(traffic_redirect_list) &&
                ((p_traffic_redirect_list)buffer)->operation == 2) {
                status = functions::handle_traffic_redirect_list((p_traffic_redirect_list)buffer);
                bytes = sizeof(traffic_redirect_list);
            }
            else if (input_size >= sizeof(traffic_redirect_rule) && output_size >= sizeof(traffic_redirect_rule)) {
                status = functions::handle_traffic_redirect((p_traffic_redirect_rule)buffer);
                bytes = sizeof(traffic_redirect_rule);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::STRM()) {
            WW_LOG("netaction::STRM ENTER code=0x%08X input_size=%lu output_size=%lu required=%lu secure_wrapped=%d buffer=%p",
                code, input_size, output_size, (ULONG)sizeof(stream_reassemble_request),
                (int)secure_wrapped, buffer);
            if (input_size >= sizeof(stream_reassemble_request) && output_size >= sizeof(stream_reassemble_request)) {
                p_stream_reassemble_request strm_req = (p_stream_reassemble_request)buffer;
                WW_LOG("netaction::STRM dispatch op=%u src_port=%u dst_port=%u pid=%u",
                    strm_req->operation, strm_req->src_port, strm_req->dst_port, strm_req->pid);
                status = functions::handle_stream_reassemble(strm_req);
                bytes = sizeof(stream_reassemble_request);
                WW_LOG("netaction::STRM EXIT status=0x%08X bytes=%lu stream_size=%u total_packets=%u stream_count=%u truncated=%u",
                    status, bytes, strm_req->stream_size, strm_req->total_packets,
                    strm_req->stream_count, strm_req->truncated);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
                WW_LOG("netaction::STRM REJECT length_mismatch input_size=%lu output_size=%lu required=%lu status=0x%08X",
                    input_size, output_size, (ULONG)sizeof(stream_reassemble_request), status);
            }
        }
        else if (code == ioctl_codes::DPIN()) {
            if (input_size >= sizeof(dpi_request) && output_size >= sizeof(dpi_request)) {
                status = functions::handle_deep_inspect((p_dpi_request)buffer);
                bytes = sizeof(dpi_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::IHLD()) {
            if (input_size >= sizeof(intercept_request) && output_size >= sizeof(intercept_request)) {
                status = functions::handle_intercept_hold((p_intercept_request)buffer);
                bytes = sizeof(intercept_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::CKIL()) {
            WW_LOG("netaction::CKIL ENTER code=0x%08X input_size=%lu output_size=%lu required=%lu secure_wrapped=%d buffer=%p",
                code, input_size, output_size, (ULONG)sizeof(conn_kill_request),
                (int)secure_wrapped, buffer);
            if (input_size >= sizeof(conn_kill_request) && output_size >= sizeof(conn_kill_request)) {
                p_conn_kill_request ckil_req = (p_conn_kill_request)buffer;
                WW_LOG("netaction::CKIL dispatch protocol=%u af=%u src_port=%u dst_port=%u pid=%u src=%u.%u.%u.%u dst=%u.%u.%u.%u",
                    ckil_req->protocol, ckil_req->address_family,
                    ckil_req->src_port, ckil_req->dst_port, ckil_req->pid,
                    ckil_req->src_addr[0], ckil_req->src_addr[1], ckil_req->src_addr[2], ckil_req->src_addr[3],
                    ckil_req->dst_addr[0], ckil_req->dst_addr[1], ckil_req->dst_addr[2], ckil_req->dst_addr[3]);
                status = functions::handle_conn_kill(ckil_req);
                bytes = sizeof(conn_kill_request);
                WW_LOG("netaction::CKIL EXIT status=0x%08X bytes=%lu request_status=%u",
                    status, bytes, ckil_req->status);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
                WW_LOG("netaction::CKIL REJECT length_mismatch input_size=%lu output_size=%lu required=%lu status=0x%08X",
                    input_size, output_size, (ULONG)sizeof(conn_kill_request), status);
            }
        }
        else if (code == ioctl_codes::DNSS()) {
            if (input_size >= sizeof(dns_spoof_list) && output_size >= sizeof(dns_spoof_list) &&
                ((p_dns_spoof_list)buffer)->operation == 2) {
                status = functions::handle_dns_spoof_list((p_dns_spoof_list)buffer);
                bytes = sizeof(dns_spoof_list);
            }
            else if (input_size >= sizeof(dns_spoof_rule) && output_size >= sizeof(dns_spoof_rule)) {
                status = functions::handle_dns_spoof((p_dns_spoof_rule)buffer);
                bytes = sizeof(dns_spoof_rule);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::BWMN()) {
            if (input_size >= sizeof(bw_monitor_request) && output_size >= sizeof(bw_monitor_request)) {
                status = functions::handle_bw_monitor((p_bw_monitor_request)buffer);
                bytes = sizeof(bw_monitor_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::NIFS()) {
            if (input_size >= sizeof(net_interface_enum) && output_size >= sizeof(net_interface_enum)) {
                status = functions::handle_net_iface_enum((p_net_interface_enum)buffer);
                bytes = sizeof(net_interface_enum);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::PCEX()) {
            if (input_size >= sizeof(pcap_export_request) && output_size >= sizeof(pcap_export_request)) {
                status = functions::handle_pcap_export((p_pcap_export_request)buffer);
                bytes = sizeof(pcap_export_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::NFPR()) {
            if (input_size >= sizeof(net_fingerprint_request) && output_size >= sizeof(net_fingerprint_request)) {
                status = functions::handle_net_fingerprint((p_net_fingerprint_request)buffer);
                bytes = sizeof(net_fingerprint_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::DPRT()) {
            if (input_size >= sizeof(dll_protect) && output_size >= sizeof(dll_protect)) {
                status = functions::handle_dll_protect((p_dll_protect)buffer);
                bytes = sizeof(dll_protect);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::ABRT()) {
            LARGE_INTEGER abrt_freq{};
            LARGE_INTEGER abrt_start = KeQueryPerformanceCounter(&abrt_freq);
            const ULONG abrt_requestor = static_cast<ULONG>(irp->RequestorMode);
            const ULONG abrt_requestor_pid = IoGetRequestorProcessId(irp);
            const UINT64 abrt_current_pid = handle_to_u64(PsGetCurrentProcessId());
            const UINT64 abrt_current_tid = handle_to_u64(PsGetCurrentThreadId());
            const ULONG abrt_irql = (ULONG)KeGetCurrentIrql();
            if (input_size >= sizeof(abort_request)) {
                p_abort_request abrt = (p_abort_request)buffer;
                const ULONG expected_magic = g_session_key ^ dynamic_key::get() ^ 0xABCD1234u;
                const LONG activated_snapshot = _InterlockedCompareExchange(&g_driver_activated, 0, 0);
                const BOOLEAN magic_match = (abrt->magic == expected_magic) ? TRUE : FALSE;
                const BOOLEAN session_present = g_session_key != 0 ? TRUE : FALSE;
                const BOOLEAN server_seed_set = dynamic_key::g_server_seed != 0 ? TRUE : FALSE;
                const BOOLEAN ioctl_seed_set = ioctl_codes::g_server_ioctl_seed != 0 ? TRUE : FALSE;
                const ULONG reason = abrt->reason_code;
                const BOOLEAN re_reason = is_re_abort_reason(reason);
                const ULONG re_family = static_cast<ULONG>(sentinel_bridge::evidence_accumulator::classify_family(reason));

                WW_LOG("ABRT: ENTRY reason=0x%lx evidence=0x%llx request_tsc=0x%llx input_size=%lu output_size=%lu requestor=%lu requestor_pid=%lu current_pid=%llu current_tid=%llu irql=%lu activated=%ld magic_match=%u session_present=%u server_seed_set=%u ioctl_seed_set=%u re_reason=%u family=0x%lx elapsed_us=%llu",
                    reason,
                    static_cast<unsigned long long>(abrt->evidence_hash),
                    static_cast<unsigned long long>(abrt->timestamp),
                    input_size,
                    output_size,
                    abrt_requestor,
                    abrt_requestor_pid,
                    abrt_current_pid,
                    abrt_current_tid,
                    abrt_irql,
                    activated_snapshot,
                    magic_match ? 1u : 0u,
                    session_present ? 1u : 0u,
                    server_seed_set ? 1u : 0u,
                    ioctl_seed_set ? 1u : 0u,
                    re_reason ? 1u : 0u,
                    re_family,
                    elapsed_us_from_qpc(abrt_start, abrt_freq));

                if (magic_match && activated_snapshot != 0) {

                    BOOLEAN should_bsod = TRUE;
                    UINT32 det_flags = 0;
                    UINT64 dbg_pid = 0;
                    NTSTATUS scan_st = STATUS_NOT_SUPPORTED;
                    BOOLEAN scan_hit = FALSE;
                    BOOLEAN kernel_confirmed = FALSE;
                    LONG spurious_count = 0;

                    if (re_reason) {
                        det_flags = anti_debug::run_all_checks();
                        scan_st = anti_debug::scan_for_debugger_processes(&dbg_pid);
                        scan_hit = NT_SUCCESS(scan_st) && dbg_pid != 0;
                        kernel_confirmed = (det_flags != 0 || scan_hit) ? TRUE : FALSE;

                        if (!kernel_confirmed) {
                            static volatile LONG g_spurious_count = 0;
                            static volatile LONG64 g_spurious_window_tsc = 0;
                            LONG64 now_tsc = static_cast<LONG64>(__rdtsc());
                            LONG64 window = _InterlockedCompareExchange64(
                                &g_spurious_window_tsc, 0, 0);
                            constexpr LONG64 WINDOW_TSC = 30LL * 3000000000LL;
                            if (window == 0 || (now_tsc - window) > WINDOW_TSC) {
                                _InterlockedExchange64(&g_spurious_window_tsc, now_tsc);
                                _InterlockedExchange(&g_spurious_count, 1);
                                spurious_count = 1;
                            } else {
                                spurious_count = _InterlockedIncrement(&g_spurious_count);
                            }
                            should_bsod = FALSE;
                            WW_LOG("ABRT: RE reason without kernel confirmation observed reason=0x%lx evidence=0x%llx family=0x%lx det_flags=0x%lx scan_status=0x%08lx scan_hit=%u dbg_pid=%llu spurious=%ld window_tsc=%lld now_tsc=%lld requestor_pid=%lu current_pid=%llu elapsed_us=%llu should_bsod=0",
                                reason,
                                static_cast<unsigned long long>(abrt->evidence_hash),
                                re_family,
                                det_flags,
                                scan_st,
                                scan_hit ? 1u : 0u,
                                dbg_pid,
                                spurious_count,
                                window,
                                now_tsc,
                                abrt_requestor_pid,
                                abrt_current_pid,
                                elapsed_us_from_qpc(abrt_start, abrt_freq));
                        } else {
                            WW_LOG("ABRT: RE reason confirmed by kernel reason=0x%lx evidence=0x%llx family=0x%lx det_flags=0x%lx scan_status=0x%08lx scan_hit=%u dbg_pid=%llu requestor_pid=%lu current_pid=%llu elapsed_us=%llu should_bsod=1",
                                reason,
                                static_cast<unsigned long long>(abrt->evidence_hash),
                                re_family,
                                det_flags,
                                scan_st,
                                scan_hit ? 1u : 0u,
                                dbg_pid,
                                abrt_requestor_pid,
                                abrt_current_pid,
                                elapsed_us_from_qpc(abrt_start, abrt_freq));
                        }
                    } else {
                        WW_LOG("ABRT: non-RE destructive request accepted reason=0x%lx evidence=0x%llx requestor_pid=%lu current_pid=%llu elapsed_us=%llu should_bsod=1",
                            reason,
                            static_cast<unsigned long long>(abrt->evidence_hash),
                            abrt_requestor_pid,
                            abrt_current_pid,
                            elapsed_us_from_qpc(abrt_start, abrt_freq));
                    }

                    if (should_bsod && _KeBugCheckEx) {
                        WW_LOG("ABRT: PRE_BUGCHECK code=0xDEAD0001 reason=0x%lx evidence=0x%llx request_tsc=0x%llx requestor=%lu requestor_pid=%lu current_pid=%llu current_tid=%llu irql=%lu re_reason=%u family=0x%lx kernel_confirmed=%u det_flags=0x%lx scan_status=0x%08lx scan_hit=%u dbg_pid=%llu spurious=%ld elapsed_us=%llu",
                            reason,
                            static_cast<unsigned long long>(abrt->evidence_hash),
                            static_cast<unsigned long long>(abrt->timestamp),
                            abrt_requestor,
                            abrt_requestor_pid,
                            abrt_current_pid,
                            abrt_current_tid,
                            abrt_irql,
                            re_reason ? 1u : 0u,
                            re_family,
                            kernel_confirmed ? 1u : 0u,
                            det_flags,
                            scan_st,
                            scan_hit ? 1u : 0u,
                            dbg_pid,
                            spurious_count,
                            elapsed_us_from_qpc(abrt_start, abrt_freq));
                        sentinel_bridge::g_bridge.sentinel_cmd = sentinel_bridge::BRIDGE_CMD_PRE_BSOD_INTENT;
                        sentinel_bridge::g_bridge.sentinel_cmd_param = reason;

                        _KeBugCheckEx(
                            0xDEAD0001u,
                            (ULONG_PTR)abrt->reason_code,
                            (ULONG_PTR)abrt->evidence_hash,
                            (ULONG_PTR)abrt->timestamp,
                            (ULONG_PTR)g_session_key
                        );
                    } else if (should_bsod && !_KeBugCheckEx) {
                        WW_LOG("ABRT: BUGCHECK_UNAVAILABLE reason=0x%lx evidence=0x%llx request_tsc=0x%llx re_reason=%u kernel_confirmed=%u requestor_pid=%lu current_pid=%llu elapsed_us=%llu",
                            reason,
                            static_cast<unsigned long long>(abrt->evidence_hash),
                            static_cast<unsigned long long>(abrt->timestamp),
                            re_reason ? 1u : 0u,
                            kernel_confirmed ? 1u : 0u,
                            abrt_requestor_pid,
                            abrt_current_pid,
                            elapsed_us_from_qpc(abrt_start, abrt_freq));
                    }

                    WW_LOG("ABRT: EXIT status=0x%08lx reason=0x%lx should_bsod=%u re_reason=%u kernel_confirmed=%u spurious=%ld bytes=%lu elapsed_us=%llu",
                        STATUS_SUCCESS,
                        reason,
                        should_bsod ? 1u : 0u,
                        re_reason ? 1u : 0u,
                        kernel_confirmed ? 1u : 0u,
                        spurious_count,
                        static_cast<ULONG>(sizeof(abort_request)),
                        elapsed_us_from_qpc(abrt_start, abrt_freq));
                    status = STATUS_SUCCESS;
                } else {
                    WW_LOG("ABRT: REJECTED reason=0x%lx magic_match=%u activated=%ld session_present=%u server_seed_set=%u ioctl_seed_set=%u input_size=%lu output_size=%lu requestor=%lu requestor_pid=%lu current_pid=%llu current_tid=%llu irql=%lu elapsed_us=%llu",
                        reason,
                        magic_match ? 1u : 0u,
                        activated_snapshot,
                        session_present ? 1u : 0u,
                        server_seed_set ? 1u : 0u,
                        ioctl_seed_set ? 1u : 0u,
                        input_size,
                        output_size,
                        abrt_requestor,
                        abrt_requestor_pid,
                        abrt_current_pid,
                        abrt_current_tid,
                        abrt_irql,
                        elapsed_us_from_qpc(abrt_start, abrt_freq));
                    status = STATUS_ACCESS_DENIED;
                }
                bytes = sizeof(abort_request);
            }
            else {
                WW_LOG("ABRT: BAD_SIZE input_size=%lu output_size=%lu required=%llu requestor=%lu requestor_pid=%lu current_pid=%llu current_tid=%llu irql=%lu elapsed_us=%llu",
                    input_size,
                    output_size,
                    static_cast<UINT64>(sizeof(abort_request)),
                    abrt_requestor,
                    abrt_requestor_pid,
                    abrt_current_pid,
                    abrt_current_tid,
                    abrt_irql,
                    elapsed_us_from_qpc(abrt_start, abrt_freq));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::ADBG()) {
            if (input_size >= sizeof(anti_debug_request) && output_size >= sizeof(anti_debug_request)) {
                status = functions::handle_anti_debug((p_anti_debug_request)buffer);
                bytes = sizeof(anti_debug_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::SRVT()) {
            if (input_size >= sizeof(server_token_relay) && output_size >= sizeof(server_token_relay)) {
                p_server_token_relay srvt = (p_server_token_relay)buffer;
                UINT64 caller_pid = handle_to_u64(PsGetCurrentProcessId());
                UINT64 registered_pid = handle_to_u64(caller_validation::g_registered_client_pid);

                if (srvt->session_key == g_session_key) {
                    LARGE_INTEGER current_time;
                    KeQuerySystemTime(&current_time);

                    ULONG expected_hash = srvt->token_hash ^ dynamic_key::get() ^ (ULONG)(srvt->server_nonce & 0xFFFFFFFFu);
                    _InterlockedExchange((volatile LONG*)&g_server_token_hash, (LONG)expected_hash);
                    _InterlockedExchange64(&g_server_token_time, current_time.QuadPart);
                    activate_server_seed_state(srvt->server_nonce, srvt->token_hash, srvt->session_key);
                    _InterlockedExchange(&g_driver_activated, 1);
                    _InterlockedExchange64(&g_last_heartbeat_time, current_time.QuadPart);

                    srvt->result = 1;
                    WW_LOG("SRVT: accepted result=%u expected_bytes=%llu returned_bytes=%llu token_present=%u nonce_present=%u session_present=%u caller_pid=%llu registered_pid=%llu server_seed_set=%u ioctl_seed_set=%u elapsed_us=%llu",
                        srvt->result,
                        static_cast<UINT64>(sizeof(server_token_relay)),
                        static_cast<UINT64>(sizeof(server_token_relay)),
                        srvt->token_hash != 0 ? 1u : 0u,
                        srvt->server_nonce != 0 ? 1u : 0u,
                        srvt->session_key != 0 ? 1u : 0u,
                        caller_pid,
                        registered_pid,
                        dynamic_key::g_server_seed != 0 ? 1u : 0u,
                        ioctl_codes::g_server_ioctl_seed != 0 ? 1u : 0u,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                    status = STATUS_SUCCESS;
                } else {
                    srvt->result = 0;
                    WW_LOG("SRVT: rejected result=%u expected_bytes=%llu returned_bytes=%llu token_present=%u nonce_present=%u session_present=%u session_match=0 caller_pid=%llu registered_pid=%llu elapsed_us=%llu",
                        srvt->result,
                        static_cast<UINT64>(sizeof(server_token_relay)),
                        static_cast<UINT64>(sizeof(server_token_relay)),
                        srvt->token_hash != 0 ? 1u : 0u,
                        srvt->server_nonce != 0 ? 1u : 0u,
                        srvt->session_key != 0 ? 1u : 0u,
                        caller_pid,
                        registered_pid,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                    status = STATUS_ACCESS_DENIED;
                }
                bytes = sizeof(server_token_relay);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::HB()) {
            if (input_size >= sizeof(_HB) && output_size >= sizeof(_HB)) {
                p_heartbeat hb = (p_heartbeat)buffer;
                LARGE_INTEGER current_time;
                KeQuerySystemTime(&current_time);

                ULONG expectedMagic = get_heartbeat_magic();
                LONG in_flight = _InterlockedIncrement(&g_heartbeat_inflight);
                if (in_flight > 1) {
                    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_heartbeat_reentrant));
                }

                LONG64 previous_hb = _InterlockedCompareExchange64(&g_last_heartbeat_time, 0, 0);
                LONG64 hb_interval = previous_hb != 0 ? current_time.QuadPart - previous_hb : -1;
                ULONG fast_intervals = static_cast<ULONG>(
                    _InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&g_heartbeat_fast_intervals), 0, 0));
                if (hb_interval >= 0 && hb_interval < HEARTBEAT_LOG_INTERVAL) {
                    fast_intervals = static_cast<ULONG>(
                        _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_heartbeat_fast_intervals)));
                }
                ULONG suppressed_hb_logs = 0;
                BOOLEAN log_hb = should_log_heartbeat(current_time.QuadPart, &suppressed_hb_logs);

                if (log_hb) {
                    WW_LOG("HB: received magic_match=%u session_present=%u in_flight=%ld suppressed=%lu interval_100ns=%lld fast_intervals=%lu reentrant=%lu activated=%ld server_seed_set=%u ioctl_seed_set=%u",
                        hb->magic == expectedMagic ? 1u : 0u,
                        hb->session_key != 0 ? 1u : 0u,
                        in_flight,
                        suppressed_hb_logs,
                        hb_interval,
                        fast_intervals,
                        static_cast<ULONG>(_InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&g_heartbeat_reentrant), 0, 0)),
                        _InterlockedCompareExchange(&g_driver_activated, 0, 0),
                        dynamic_key::g_server_seed != 0 ? 1u : 0u,
                        ioctl_codes::g_server_ioctl_seed != 0 ? 1u : 0u);
                }

                if (hb->magic == expectedMagic) {
                    {
                        LONG existing_key = _InterlockedCompareExchange((volatile LONG*)&g_session_key, (LONG)hb->session_key, 0);
                        if (existing_key != 0 && (ULONG)existing_key != hb->session_key) {
                            WW_LOG("HB: session key mismatch, resetting");
                            HANDLE prev_client = caller_validation::g_registered_client_pid;
                            LONG64 last_hb_snapshot = _InterlockedCompareExchange64(&g_last_heartbeat_time, 0, 0);
                            LONG64 mismatch_elapsed = current_time.QuadPart - last_hb_snapshot;
                            HANDLE caller_pid = PsGetCurrentProcessId();
                            WW_LOG("HB: mismatch_context caller_pid=%lu registered_pid=%lu elapsed_since_last_hb=%lld heartbeat_counter=%lu activated=%ld validation_enabled=%ld",
                                static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(caller_pid)),
                                static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(prev_client)),
                                last_hb_snapshot != 0 ? mismatch_elapsed : -1,
                                g_heartbeat_counter,
                                g_driver_activated,
                                caller_validation::g_validation_enabled);
                            reset_dynamic_session_state("heartbeat_key_mismatch", prev_client, 0, TRUE);
                            existing_key = _InterlockedCompareExchange((volatile LONG*)&g_session_key, (LONG)hb->session_key, 0);
                        }

                        if (existing_key == 0 || (ULONG)existing_key == hb->session_key) {
                            _InterlockedExchange64(&g_last_heartbeat_time, current_time.QuadPart);
                            _InterlockedIncrement((volatile LONG*)&g_heartbeat_counter);
                            sentinel_bridge::tick();
                            hb->whoswho_tsc = (UINT64)sentinel_bridge::g_bridge.whoswho_tsc;
                            hb->sentinel_tsc = (UINT64)sentinel_bridge::g_bridge.sentinel_tsc;

                            BOOLEAN need_client_register = (existing_key == 0 ||
                                caller_validation::g_registered_client_pid == nullptr);
                            if (need_client_register) {
                                WW_LOG("HB: registering client, first=%d counter=%ld",
                                    existing_key == 0 ? 1 : 0,
                                    g_heartbeat_counter);
                                caller_validation::register_client();

                                HANDLE caller_pid = PsGetCurrentProcessId();
                                UINT32 client_pid = (UINT32)(ULONG_PTR)caller_pid;
                                continuous_anti_debug::start(client_pid);
                                file_handle_scanner::start(30, "heartbeat_register", caller_pid, g_heartbeat_counter);
                                WW_LOG("HB: continuous anti-debug started for pid=%u (anti-dump deferred until user-mode finalize_after_activation)", client_pid);
                            }

                            hb->response = (UINT64)g_heartbeat_counter ^ dynamic_key::get();


                            if (log_hb) {
                                WW_LOG("HB: OK counter=%ld activated=%ld bridge_whoswho_seen=%u bridge_sentinel_seen=%u",
                                    g_heartbeat_counter,
                                    _InterlockedCompareExchange(&g_driver_activated, 0, 0),
                                    sentinel_bridge::g_bridge.whoswho_tsc != 0 ? 1u : 0u,
                                    sentinel_bridge::g_bridge.sentinel_tsc != 0 ? 1u : 0u);
                            }
                            status = STATUS_SUCCESS;
                        } else {
                            if (log_hb) {
                                WW_LOG("HB: ACCESS_DENIED session_mismatch=1");
                            }
                            hb->response = 0;
                            hb->whoswho_tsc = 0;
                            hb->sentinel_tsc = 0;
                            status = STATUS_ACCESS_DENIED;
                        }
                    }
                } else {
                    if (log_hb) {
                        WW_LOG("HB: INVALID_PARAMETER magic mismatch");
                    }
                    hb->response = 0;
                    hb->whoswho_tsc = 0;
                    hb->sentinel_tsc = 0;
                    status = STATUS_INVALID_PARAMETER;
                }
                _InterlockedDecrement(&g_heartbeat_inflight);
                bytes = sizeof(_HB);
            }
            else {
                WW_LOG("HB: INFO_LENGTH_MISMATCH input=%lu output=%lu", input_size, output_size);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::ADMP()) {
            if (input_size >= sizeof(anti_dump_request) && output_size >= sizeof(anti_dump_request)) {
                status = functions::handle_anti_dump((p_anti_dump_request)buffer);
                bytes = sizeof(anti_dump_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::SRV2()) {
            if (input_size >= sizeof(server_token_relay_v2) && output_size >= sizeof(server_token_relay_v2)) {
                auto* srvt2 = (p_server_token_relay_v2)buffer;
                UINT64 caller_pid = handle_to_u64(PsGetCurrentProcessId());
                UINT64 registered_pid = handle_to_u64(caller_validation::g_registered_client_pid);
                status = functions::handle_server_token_v2(srvt2);
                if (NT_SUCCESS(status) && srvt2->result == 1) {
                    activate_server_seed_state(srvt2->server_nonce, srvt2->token_hash, srvt2->session_key);
                    _InterlockedExchange(&g_driver_activated, 1);
                    WW_LOG("SRVT2: accepted result=%u expected_bytes=%llu returned_bytes=%llu token_present=%u nonce_present=%u proof_set=%u session_present=%u caller_pid=%llu registered_pid=%llu action=%u server_seed_set=%u ioctl_seed_set=%u elapsed_us=%llu",
                        srvt2->result,
                        static_cast<UINT64>(sizeof(server_token_relay_v2)),
                        static_cast<UINT64>(sizeof(server_token_relay_v2)),
                        srvt2->token_hash != 0 ? 1u : 0u,
                        srvt2->server_nonce != 0 ? 1u : 0u,
                        srvt2->driver_proof != 0 ? 1u : 0u,
                        srvt2->session_key != 0 ? 1u : 0u,
                        caller_pid,
                        registered_pid,
                        srvt2->action,
                        dynamic_key::g_server_seed != 0 ? 1u : 0u,
                        ioctl_codes::g_server_ioctl_seed != 0 ? 1u : 0u,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                } else {
                    WW_LOG("SRVT2: rejected status=0x%08lx result=%u expected_bytes=%llu returned_bytes=%llu token_present=%u nonce_present=%u proof_set=%u session_present=%u caller_pid=%llu registered_pid=%llu action=%u elapsed_us=%llu",
                        status,
                        srvt2->result,
                        static_cast<UINT64>(sizeof(server_token_relay_v2)),
                        static_cast<UINT64>(sizeof(server_token_relay_v2)),
                        srvt2->token_hash != 0 ? 1u : 0u,
                        srvt2->server_nonce != 0 ? 1u : 0u,
                        srvt2->driver_proof != 0 ? 1u : 0u,
                        srvt2->session_key != 0 ? 1u : 0u,
                        caller_pid,
                        registered_pid,
                        srvt2->action,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                }


                bytes = sizeof(server_token_relay_v2);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::DBGA()) {
            if (input_size >= sizeof(phase3_msg::debug_attach_request_k) &&
                output_size >= sizeof(phase3_msg::debug_attach_request_k)) {
                auto* req = reinterpret_cast<phase3_msg::debug_attach_request_k*>(buffer);
                if (req->session_key != g_session_key) {
                    status = STATUS_ACCESS_DENIED;
                } else {
                    ULONG pid = req->pid;
                    if (pid == 0)
                        pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
                            caller_validation::g_registered_client_pid));

                    UINT32 flags = 0;
                    BOOLEAN kd_now = anti_debug::kd_transitioned_to_enabled();
                    if (kd_now) flags |= 0x1;

                    if (flags != 0) {
                        sentinel_bridge::populate_evidence_blob(
                            0x20u, sentinel_bridge::RE_REASON_DEBUG_ATTACH,
                            100, pid, 0, 0, flags);
                        ULONG cmd = sentinel_bridge::BRIDGE_CMD_DEBUGGER_FOUND;
                        ULONG par = pid;
                        sentinel_bridge::bridge_encrypt_cmd(cmd, par);
                        _InterlockedExchange(
                            reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd),
                            static_cast<LONG>(cmd));
                        _InterlockedExchange(
                            reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd_param),
                            static_cast<LONG>(par));
                        if (_KeBugCheckEx) {
                            _KeBugCheckEx(
                                sentinel_bridge::BUGCHECK_RE_USERMODE_CONFIRMED,
                                sentinel_bridge::RE_REASON_DEBUG_ATTACH,
                                sentinel_bridge::g_evidence_blob_offset,
                                static_cast<ULONG_PTR>(pid),
                                static_cast<ULONG_PTR>(flags));
                        }
                    }
                    req->result_flags = flags;
                    status = STATUS_SUCCESS;
                }
                bytes = sizeof(phase3_msg::debug_attach_request_k);
            } else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::CANR()) {
            if (input_size >= sizeof(phase3_msg::canary_register_request_k) &&
                output_size >= sizeof(phase3_msg::canary_register_request_k)) {
                auto* req = reinterpret_cast<phase3_msg::canary_register_request_k*>(buffer);
                if (req->session_key != g_session_key) {
                    WW_LOG("CANR: ACCESS_DENIED session_match=0 va=0x%llx size=0x%llx pid=%u",
                        static_cast<unsigned long long>(req->va),
                        static_cast<unsigned long long>(req->size),
                        req->pid);
                    status = STATUS_ACCESS_DENIED;
                } else {
                    ULONG client_pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
                        caller_validation::g_registered_client_pid));
                    ULONG caller_pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
                        PsGetCurrentProcessId()));
                    ULONG pid = req->pid;
                    if (pid == 0)
                        pid = client_pid;
                    if (client_pid == 0 || pid != client_pid || caller_pid != client_pid) {
                        WW_LOG("CANR: REJECT cross_pid_or_unregistered req_pid=%u client_pid=%lu caller_pid=%lu",
                            req->pid, client_pid, caller_pid);
                        req->result = 0;
                        status = STATUS_ACCESS_DENIED;
                    } else {
                        WW_LOG("CANR: request va=0x%llx size=0x%llx requested_pid=%u resolved_pid=%lu session_match=1 count_before=%lu",
                            static_cast<unsigned long long>(req->va),
                            static_cast<unsigned long long>(req->size),
                            req->pid,
                            pid,
                            anti_dma_canary::g_canary_count);
                        req->result = anti_dma_canary::register_canary(req->va, req->size, pid) ? 1u : 0u;
                        WW_LOG("CANR: result=%u resolved_pid=%lu count_after=%lu",
                            req->result,
                            pid,
                            anti_dma_canary::g_canary_count);
                        status = STATUS_SUCCESS;
                    }
                }
                bytes = sizeof(phase3_msg::canary_register_request_k);
            } else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::CANQ()) {
            if (input_size >= sizeof(phase3_msg::canary_register_request_k) &&
                output_size >= sizeof(phase3_msg::canary_register_request_k)) {
                auto* req = reinterpret_cast<phase3_msg::canary_register_request_k*>(buffer);
                if (req->session_key != g_session_key) {
                    status = STATUS_ACCESS_DENIED;
                } else {
                    req->result = anti_dma_canary::g_canary_count;
                    status = STATUS_SUCCESS;
                }
                bytes = sizeof(phase3_msg::canary_register_request_k);
            } else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::TIRA()) {
            tier_a_handler_reached = TRUE;
            if (input_size >= sizeof(phase3_msg::tier_a_query_request_k) &&
                output_size >= sizeof(phase3_msg::tier_a_query_request_k)) {
                auto* req = reinterpret_cast<phase3_msg::tier_a_query_request_k*>(buffer);
                UINT64 caller_pid = handle_to_u64(PsGetCurrentProcessId());
                UINT64 registered_pid = handle_to_u64(caller_validation::g_registered_client_pid);
                WW_LOG("TIRA: handler_entry trace=%lld raw_code=0x%08lx expected_tira=0x%08lx input_size=%lu output_size=%lu session_present=%u session_match=%u caller_pid=%llu registered_pid=%llu activated=%ld secure_wrapped=%u bridge_cmd=0x%08lx bridge_whoswho_seen=%u bridge_sentinel_seen=%u elapsed_us=%llu",
                    tier_a_trace_id,
                    code,
                    early_expected_tira,
                    input_size,
                    output_size,
                    req->session_key != 0 ? 1u : 0u,
                    req->session_key == g_session_key ? 1u : 0u,
                    caller_pid,
                    registered_pid,
                    _InterlockedCompareExchange(&g_driver_activated, 0, 0),
                    secure_wrapped ? 1u : 0u,
                    static_cast<ULONG>(sentinel_bridge::g_bridge.sentinel_cmd),
                    sentinel_bridge::g_bridge.whoswho_tsc != 0 ? 1u : 0u,
                    sentinel_bridge::g_bridge.sentinel_tsc != 0 ? 1u : 0u,
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                if (req->session_key != g_session_key) {
                    status = STATUS_ACCESS_DENIED;
                    WW_LOG("TIRA: rejected expected_bytes=%llu returned_bytes=%llu session_present=%u session_match=0 caller_pid=%llu registered_pid=%llu elapsed_us=%llu",
                        static_cast<UINT64>(sizeof(phase3_msg::tier_a_query_request_k)),
                        static_cast<UINT64>(sizeof(phase3_msg::tier_a_query_request_k)),
                        req->session_key != 0 ? 1u : 0u,
                        caller_pid,
                        registered_pid,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                } else {
                    BOOLEAN tier_present = anti_dma_canary::query_tier_a_preloaded();
                    req->present_flag      = tier_present ? 1u : 0u;
                    req->tier_mask         = req->present_flag;
                    req->first_driver_base = 0;
                    status = STATUS_SUCCESS;
                    WW_LOG("TIRA: accepted result=%u expected_bytes=%llu returned_bytes=%llu tier_mask=0x%08X first_base=0x%llX session_present=%u caller_pid=%llu registered_pid=%llu reason=%s elapsed_us=%llu",
                        req->present_flag,
                        static_cast<UINT64>(sizeof(phase3_msg::tier_a_query_request_k)),
                        static_cast<UINT64>(sizeof(phase3_msg::tier_a_query_request_k)),
                        req->tier_mask,
                        req->first_driver_base,
                        req->session_key != 0 ? 1u : 0u,
                        caller_pid,
                        registered_pid,
                        req->present_flag ? "tier_a_present" : "healthy_absent",
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                }
                bytes = sizeof(phase3_msg::tier_a_query_request_k);
            } else {
                WW_LOG("TIRA: size_mismatch trace=%lld raw_code=0x%08lx expected_tira=0x%08lx input_size=%lu output_size=%lu required=%llu elapsed_us=%llu",
                    tier_a_trace_id,
                    code,
                    early_expected_tira,
                    input_size,
                    output_size,
                    static_cast<UINT64>(sizeof(phase3_msg::tier_a_query_request_k)),
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::RECU()) {
            if (input_size >= sizeof(phase3_msg::re_confirmed_usermode_request_k) &&
                output_size >= sizeof(phase3_msg::re_confirmed_usermode_request_k)) {
                auto* req = reinterpret_cast<phase3_msg::re_confirmed_usermode_request_k*>(buffer);
                if (req->session_key != g_session_key) {
                    status = STATUS_ACCESS_DENIED;
                } else {
                    sentinel_bridge::populate_evidence_blob(
                        req->evidence.signal_family,
                        req->evidence.signal_id,
                        req->evidence.score,
                        req->evidence.pid,
                        req->evidence.caller_image_hash,
                        req->evidence.signals_bitmap_hash,
                        req->evidence.timestamp);
                    ULONG cmd = sentinel_bridge::BRIDGE_CMD_RE_CONFIRMED_USERMODE;
                    ULONG par = req->evidence.pid;
                    sentinel_bridge::bridge_encrypt_cmd(cmd, par);
                    _InterlockedExchange(
                        reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd),
                        static_cast<LONG>(cmd));
                    _InterlockedExchange(
                        reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd_param),
                        static_cast<LONG>(par));
                    if (_KeBugCheckEx) {
                        _KeBugCheckEx(
                            sentinel_bridge::BUGCHECK_RE_USERMODE_CONFIRMED,
                            static_cast<ULONG_PTR>(req->evidence.signal_id),
                            (static_cast<ULONG_PTR>(req->evidence.score) << 32) |
                                req->evidence.signal_family,
                            static_cast<ULONG_PTR>(req->evidence.pid),
                            static_cast<ULONG_PTR>(req->evidence.signals_bitmap_hash));
                    }
                    status = STATUS_SUCCESS;
                }
                bytes = sizeof(phase3_msg::re_confirmed_usermode_request_k);
            } else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::HVDT()) {
            LARGE_INTEGER hvdt_start;
            LARGE_INTEGER hvdt_freq;
            hvdt_start = KeQueryPerformanceCounter(&hvdt_freq);
            UINT64 hvdt_tsc = __rdtsc();
            HANDLE hvdt_pid = PsGetCurrentProcessId();
            HANDLE hvdt_tid = PsGetCurrentThreadId();
            KPROCESSOR_MODE hvdt_requestor = irp->RequestorMode;
            UINT64 hvdt_first8 = 0;
            if (buffer && input_size >= sizeof(hvdt_first8))
                RtlCopyMemory(&hvdt_first8, buffer, sizeof(hvdt_first8));
            HVD_LOG_IMMEDIATE("branch_enter trace=%lld step=%lu irp=%p buffer=%p original_buffer=%p raw_code=0x%08lx expected_hvdt=0x%08lx decoded_valid=%u decoded_offset=%lu encoded=0x%lx dyn_base=0x%lx key_hash=0x%08lx ioctl_seed_hash=0x%08lx input_size=%lu output_size=%lu first8=0x%llx flags=0x%llx requestor=%u requestor_pid=%llu caller_pid=%llu caller_tid=%llu qpc=%lld tsc=%llu cpu=%lu irql=%lu secure_wrapped=%u elapsed_us=%llu",
                hvdt_trace_id,
                27u,
                irp,
                buffer,
                original_buffer,
                code,
                early_decode.expected_hvdt_code,
                early_decode.valid ? 1u : 0u,
                early_decode.offset,
                early_decode.encoded,
                early_decode.base,
                early_decode.key_hash,
                early_decode.ioctl_seed_hash,
                input_size,
                output_size,
                hvdt_first8,
                hvdt_first8,
                static_cast<ULONG>(hvdt_requestor),
                requestor_pid_to_u64(irp),
                handle_to_u64(hvdt_pid),
                handle_to_u64(hvdt_tid),
                hvdt_start.QuadPart,
                hvdt_tsc,
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql(),
                secure_wrapped ? 1u : 0u,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
            HVD_LOG_IMMEDIATE("branch_size_gate_pre trace=%lld step=%lu input_size=%lu output_size=%lu required_in=%lu required_out=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id,
                28u,
                input_size,
                output_size,
                (ULONG)sizeof(hv_detect_request_k),
                (ULONG)sizeof(hv_detect_result_k),
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql());
            if (input_size >= sizeof(hv_detect_request_k) &&
                output_size >= sizeof(hv_detect_result_k)) {
                auto* req = reinterpret_cast<hv_detect_request_k*>(buffer);
                hv_detect_result_k result_buf{};
                const ULONG hvdt_irql = (ULONG)KeGetCurrentIrql();
                const UINT64 hvdt_rflags = __readeflags();
                HVD_LOG_IMMEDIATE("branch_precondition trace=%lld step=%lu flags=0x%llx passive=%u interrupts_enabled=%u requestor_pid=%llu secure_wrapped=%u elapsed_us=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id,
                    29u,
                    req->flags,
                    hvdt_irql == PASSIVE_LEVEL ? 1u : 0u,
                    (hvdt_rflags & 0x200ULL) != 0 ? 1u : 0u,
                    requestor_pid_to_u64(irp),
                    secure_wrapped ? 1u : 0u,
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    KeGetCurrentProcessorNumber(),
                    hvdt_irql);
                if (hvdt_irql != PASSIVE_LEVEL || (hvdt_rflags & 0x200ULL) == 0) {
                    status = STATUS_INVALID_DEVICE_STATE;
                    bytes = 0;
                    HVD_LOG_IMMEDIATE("branch_precondition_reject trace=%lld step=%lu status=0x%08lx flags=0x%llx passive=%u interrupts_enabled=%u elapsed_us=%llu cpu=%lu irql=%lu",
                        hvdt_trace_id,
                        30u,
                        status,
                        req->flags,
                        hvdt_irql == PASSIVE_LEVEL ? 1u : 0u,
                        (hvdt_rflags & 0x200ULL) != 0 ? 1u : 0u,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                        KeGetCurrentProcessorNumber(),
                        hvdt_irql);
                } else {
                    HVD_LOG_IMMEDIATE("handle_request_pre trace=%lld step=%lu flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
                        hvdt_trace_id,
                        31u,
                        req->flags,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                        KeGetCurrentProcessorNumber(),
                        (ULONG)KeGetCurrentIrql());
                    status = hv_detect::handle_request(req, &result_buf);
                    HVD_LOG_IMMEDIATE("handle_request_post trace=%lld step=%lu status=0x%08lx total_run=%u total_failed=%u is_vm=%u ms_hv_root=%u elapsed_us=%llu cpu=%lu irql=%lu",
                        hvdt_trace_id,
                        32u,
                        status,
                        result_buf.total_run,
                        result_buf.total_failed,
                        result_buf.is_virtual_machine,
                        result_buf.ms_hv_root,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                        KeGetCurrentProcessorNumber(),
                        (ULONG)KeGetCurrentIrql());
                    if (NT_SUCCESS(status)) {
                        HVD_LOG_IMMEDIATE("branch_copy_result_pre trace=%lld step=%lu bytes=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                            hvdt_trace_id,
                            33u,
                            (ULONG)sizeof(hv_detect_result_k),
                            elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                            KeGetCurrentProcessorNumber(),
                            (ULONG)KeGetCurrentIrql());
                        RtlCopyMemory(buffer, &result_buf, sizeof(hv_detect_result_k));
                        bytes = sizeof(hv_detect_result_k);
                        HVD_LOG_IMMEDIATE("branch_copy_result_post trace=%lld step=%lu bytes=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                            hvdt_trace_id,
                            34u,
                            bytes,
                            elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                            KeGetCurrentProcessorNumber(),
                            (ULONG)KeGetCurrentIrql());
                    } else {
                        bytes = 0;
                    }
                }
                LARGE_INTEGER hvdt_end = KeQueryPerformanceCounter(nullptr);
                UINT64 hvdt_elapsed_us = 0;
                if (hvdt_freq.QuadPart > 0 && hvdt_end.QuadPart >= hvdt_start.QuadPart) {
                    hvdt_elapsed_us = static_cast<UINT64>(((hvdt_end.QuadPart - hvdt_start.QuadPart) * 1000000ULL) / static_cast<UINT64>(hvdt_freq.QuadPart));
                }
                HVD_LOG_IMMEDIATE("branch_exit trace=%lld step=%lu status=0x%08lx bytes=%lu flags=0x%llx total_run=%u total_failed=%u is_vm=%u ms_hv_root=%u sidt=%u%u%u%u%u%u%u%u%u lidt=%u%u%u%u%u%u%u ve=%u%u%u%u vmf=%u%u%u%u%u%u%u%u elapsed_us=%llu dispatch_elapsed_us=%llu qpc=%lld tsc=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id,
                    35u,
                    status,
                    bytes,
                    req->flags,
                    result_buf.total_run,
                    result_buf.total_failed,
                    result_buf.is_virtual_machine,
                    result_buf.ms_hv_root,
                    result_buf.sidt_lock_prefix,
                    result_buf.sidt_invalid_pf,
                    result_buf.sidt_tlb_only,
                    result_buf.sidt_timing,
                    result_buf.sidt_compat_mode,
                    result_buf.sidt_noncanonical_gp,
                    result_buf.sidt_noncanonical_ss,
                    result_buf.sidt_cpl3_umip_off,
                    result_buf.sidt_cpl3_umip_on,
                    result_buf.lidt_lock_prefix,
                    result_buf.lidt_invalid_pf,
                    result_buf.lidt_tlb_only,
                    result_buf.lidt_timing,
                    result_buf.lidt_noncanonical_gp,
                    result_buf.lidt_noncanonical_ss,
                    result_buf.lidt_cpl3_gp,
                    result_buf.ve_trigger,
                    result_buf.ve_lbr_stack,
                    result_buf.ve_xsetbv_gp,
                    result_buf.ve_cr4_vmxe,
                    result_buf.vmf_cpuid_vendor,
                    result_buf.vmf_hyperv_guest,
                    result_buf.vmf_smbios_vm,
                    result_buf.vmf_acpi_vm,
                    result_buf.vmf_pci_vm,
                    result_buf.vmf_disk_vm,
                    result_buf.vmf_mac_vm,
                    result_buf.vmf_registry_vm,
                    hvdt_elapsed_us,
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    hvdt_end.QuadPart,
                    __rdtsc(),
                    KeGetCurrentProcessorNumber(),
                    (ULONG)KeGetCurrentIrql());
            } else {
                status = STATUS_INFO_LENGTH_MISMATCH;
                LARGE_INTEGER hvdt_end = KeQueryPerformanceCounter(nullptr);
                UINT64 hvdt_elapsed_us = 0;
                if (hvdt_freq.QuadPart > 0 && hvdt_end.QuadPart >= hvdt_start.QuadPart) {
                    hvdt_elapsed_us = static_cast<UINT64>(((hvdt_end.QuadPart - hvdt_start.QuadPart) * 1000000ULL) / static_cast<UINT64>(hvdt_freq.QuadPart));
                }
                HVD_LOG_IMMEDIATE("branch_reject trace=%lld step=%lu status=0x%08lx input_size=%lu output_size=%lu required_in=%lu required_out=%lu elapsed_us=%llu dispatch_elapsed_us=%llu qpc=%lld tsc=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id,
                    36u,
                    status,
                    input_size,
                    output_size,
                    (ULONG)sizeof(hv_detect_request_k),
                    (ULONG)sizeof(hv_detect_result_k),
                    hvdt_elapsed_us,
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    hvdt_end.QuadPart,
                    __rdtsc(),
                    KeGetCurrentProcessorNumber(),
                    (ULONG)KeGetCurrentIrql());
            }
        }
        else if (code == ioctl_codes::RELA()) {
            if (input_size >= sizeof(phase3_msg::latch_targeting_request_k)) {
                auto* req = reinterpret_cast<phase3_msg::latch_targeting_request_k*>(buffer);
                ULONG expected_magic = g_session_key ^ dynamic_key::get() ^ 0x1A7C4B2Eu;
                UINT64 caller_pid = handle_to_u64(PsGetCurrentProcessId());
                UINT64 registered_pid = handle_to_u64(caller_validation::g_registered_client_pid);
                if (req->magic == expected_magic && req->session_key == g_session_key) {
                    targeting_latch::latch_targeting(
                        req->reason,
                        (UINT64)(ULONG_PTR)caller_validation::g_registered_client_pid,
                        0, 0, 0
                    );
                    status = STATUS_SUCCESS;
                    WW_LOG("RELA: accepted reason=0x%08X expected_bytes=%llu returned_bytes=%llu magic_match=1 session_present=%u session_match=1 caller_pid=%llu registered_pid=%llu elapsed_us=%llu",
                        req->reason,
                        static_cast<UINT64>(sizeof(phase3_msg::latch_targeting_request_k)),
                        static_cast<UINT64>(sizeof(phase3_msg::latch_targeting_request_k)),
                        req->session_key != 0 ? 1u : 0u,
                        caller_pid,
                        registered_pid,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                } else {
                    status = STATUS_ACCESS_DENIED;
                    WW_LOG("RELA: rejected reason=0x%08X expected_bytes=%llu returned_bytes=%llu magic_match=%u session_present=%u session_match=%u caller_pid=%llu registered_pid=%llu elapsed_us=%llu",
                        req->reason,
                        static_cast<UINT64>(sizeof(phase3_msg::latch_targeting_request_k)),
                        static_cast<UINT64>(sizeof(phase3_msg::latch_targeting_request_k)),
                        req->magic == expected_magic ? 1u : 0u,
                        req->session_key != 0 ? 1u : 0u,
                        req->session_key == g_session_key ? 1u : 0u,
                        caller_pid,
                        registered_pid,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                }
                bytes = sizeof(phase3_msg::latch_targeting_request_k);
            } else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::PSBX()) {
            struct protect_sandbox_request_k {
                UINT32 magic;
                UINT32 session_key;
                UINT32 pid;
                UINT32 flags;
                UINT32 result;
                UINT32 reserved;
                UINT64 denials_so_far;
            };
            static_assert(sizeof(protect_sandbox_request_k) == 32, "protect_sandbox_request_k must match um struct");
            ULONG psbx_caller_pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
            WW_MALSAFE_LOG_INFO("ioctl PSBX ENTRY caller=%lu input=%lu output=%lu need=%lu",
                psbx_caller_pid, input_size, output_size, (ULONG)sizeof(protect_sandbox_request_k));
            if (input_size >= sizeof(protect_sandbox_request_k) &&
                output_size >= sizeof(protect_sandbox_request_k)) {
                auto* req = reinterpret_cast<protect_sandbox_request_k*>(buffer);
                ULONG expected_magic = g_session_key ^ dynamic_key::get() ^ 0x5A4E0B01u;
                WW_MALSAFE_LOG_INFO("ioctl PSBX req pid=%lu flags=0x%08X magic_match=%u session_match=%u",
                    req->pid, req->flags, req->magic == expected_magic ? 1u : 0u, req->session_key == g_session_key ? 1u : 0u);
                if (req->magic == expected_magic && req->session_key == g_session_key) {
                    LONG64 denials = 0;
                    bool ok = malware_safe::protect_pid(req->pid, req->flags, &denials);
                    req->result = ok ? 1u : 0u;
                    req->denials_so_far = static_cast<UINT64>(denials);
                    status = STATUS_SUCCESS;
                    WW_MALSAFE_LOG_INFO("ioctl PSBX EXIT pid=%lu flags=0x%08X result=%d denials=%llu status=0x%08X",
                        req->pid, req->flags, ok ? 1 : 0, (unsigned long long)req->denials_so_far, (ULONG)status);
                } else {
                    WW_MALSAFE_LOG_WARN("ioctl PSBX REJECTED auth_fail caller=%lu req_pid=%lu magic_match=%u session_match=%u",
                        psbx_caller_pid, req->pid, req->magic == expected_magic ? 1u : 0u, req->session_key == g_session_key ? 1u : 0u);
                    status = STATUS_ACCESS_DENIED;
                }
                bytes = sizeof(protect_sandbox_request_k);
            } else {
                WW_MALSAFE_LOG_WARN("ioctl PSBX REJECT length_mismatch input=%lu output=%lu need=%lu",
                    input_size, output_size, (ULONG)sizeof(protect_sandbox_request_k));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::USBX()) {
            struct protect_sandbox_request_k {
                UINT32 magic;
                UINT32 session_key;
                UINT32 pid;
                UINT32 flags;
                UINT32 result;
                UINT32 reserved;
                UINT64 denials_so_far;
            };
            ULONG usbx_caller_pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
            WW_MALSAFE_LOG_INFO("ioctl USBX ENTRY caller=%lu input=%lu output=%lu need=%lu",
                usbx_caller_pid, input_size, output_size, (ULONG)sizeof(protect_sandbox_request_k));
            if (input_size >= sizeof(protect_sandbox_request_k) &&
                output_size >= sizeof(protect_sandbox_request_k)) {
                auto* req = reinterpret_cast<protect_sandbox_request_k*>(buffer);
                ULONG expected_magic = g_session_key ^ dynamic_key::get() ^ 0x5A4E0B02u;
                WW_MALSAFE_LOG_INFO("ioctl USBX req pid=%lu magic_match=%u session_match=%u",
                    req->pid, req->magic == expected_magic ? 1u : 0u, req->session_key == g_session_key ? 1u : 0u);
                if (req->magic == expected_magic && req->session_key == g_session_key) {
                    LONG64 denials = 0;
                    bool ok = malware_safe::unprotect_pid(req->pid, &denials);
                    req->result = ok ? 1u : 0u;
                    req->denials_so_far = static_cast<UINT64>(denials);
                    status = STATUS_SUCCESS;
                    WW_MALSAFE_LOG_INFO("ioctl USBX EXIT pid=%lu result=%d denials=%llu status=0x%08X",
                        req->pid, ok ? 1 : 0, (unsigned long long)req->denials_so_far, (ULONG)status);
                } else {
                    WW_MALSAFE_LOG_WARN("ioctl USBX REJECTED auth_fail caller=%lu req_pid=%lu magic_match=%u session_match=%u",
                        usbx_caller_pid, req->pid, req->magic == expected_magic ? 1u : 0u, req->session_key == g_session_key ? 1u : 0u);
                    status = STATUS_ACCESS_DENIED;
                }
                bytes = sizeof(protect_sandbox_request_k);
            } else {
                WW_MALSAFE_LOG_WARN("ioctl USBX REJECT length_mismatch input=%lu output=%lu need=%lu",
                    input_size, output_size, (ULONG)sizeof(protect_sandbox_request_k));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NLOG()) {
            struct net_log_register_request_k {
                UINT32 magic;
                UINT32 session_key;
                UINT32 pid;
                UINT32 operation;
                UINT32 result;
                UINT32 reserved;
            };
            static_assert(sizeof(net_log_register_request_k) == 24, "net_log_register_request_k must match um struct");
            ULONG nlog_caller_pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
            WW_MALSAFE_LOG_INFO("ioctl NLOG ENTRY caller=%lu input=%lu output=%lu need=%lu",
                nlog_caller_pid, input_size, output_size, (ULONG)sizeof(net_log_register_request_k));
            if (input_size >= sizeof(net_log_register_request_k) &&
                output_size >= sizeof(net_log_register_request_k)) {
                auto* req = reinterpret_cast<net_log_register_request_k*>(buffer);
                ULONG expected_magic = g_session_key ^ dynamic_key::get() ^ 0x5A4E0B03u;
                WW_MALSAFE_LOG_INFO("ioctl NLOG req pid=%lu op=%lu magic_match=%u session_match=%u",
                    req->pid, req->operation, req->magic == expected_magic ? 1u : 0u, req->session_key == g_session_key ? 1u : 0u);
                if (req->magic == expected_magic && req->session_key == g_session_key) {
                    bool ok = malware_safe::set_net_log(req->pid, req->operation != 0);
                    req->result = ok ? 1u : 0u;
                    status = STATUS_SUCCESS;
                    WW_MALSAFE_LOG_INFO("ioctl NLOG EXIT pid=%lu op=%lu result=%d status=0x%08X",
                        req->pid, req->operation, ok ? 1 : 0, (ULONG)status);
                } else {
                    status = STATUS_ACCESS_DENIED;
                    WW_MALSAFE_LOG_WARN("ioctl NLOG REJECTED auth_fail caller=%lu req_pid=%lu magic_match=%u session_match=%u",
                        nlog_caller_pid, req->pid, req->magic == expected_magic ? 1u : 0u, req->session_key == g_session_key ? 1u : 0u);
                }
                bytes = sizeof(net_log_register_request_k);
            } else {
                WW_MALSAFE_LOG_WARN("ioctl NLOG REJECT length_mismatch input=%lu output=%lu need=%lu",
                    input_size, output_size, (ULONG)sizeof(net_log_register_request_k));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NPKT()) {
            struct net_packet_pull_request_k {
                UINT32 magic;
                UINT32 session_key;
                UINT32 pid;
                UINT32 max_records;
                UINT32 reserved;
                UINT32 padding;
            };
            static_assert(sizeof(net_packet_pull_request_k) == 24, "net_packet_pull_request_k must be 24 bytes");

            struct net_packet_pull_response_k {
                UINT32 magic;
                UINT32 record_count;
                UINT64 dropped_since_last_pull;
            };
            static_assert(sizeof(net_packet_pull_response_k) == 16, "net_packet_pull_response_k must be 16 bytes");

            WW_MALSAFE_LOG_VERBOSE("ioctl NPKT entry input=%lu output=%lu rec_size=%lu",
                input_size, output_size, (ULONG)malware_safe::NET_PKT_RECORD_SIZE);

            if (input_size < sizeof(net_packet_pull_request_k) ||
                output_size < sizeof(net_packet_pull_response_k)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
            } else {
                UINT32 req_magic_value = 0;
                UINT32 req_session_key_value = 0;
                UINT32 req_pid_value = 0;
                UINT32 req_max_records_value = 0;
                {
                    auto* req = reinterpret_cast<net_packet_pull_request_k*>(buffer);
                    req_magic_value = req->magic;
                    req_session_key_value = req->session_key;
                    req_pid_value = req->pid;
                    req_max_records_value = req->max_records;
                }

                ULONG expected_magic = g_session_key ^ dynamic_key::get() ^ 0x5A4E0B04u;
                if (req_magic_value != expected_magic || req_session_key_value != g_session_key) {
                    status = STATUS_ACCESS_DENIED;
                    auto* resp = reinterpret_cast<net_packet_pull_response_k*>(buffer);
                    resp->magic = malware_safe::NET_PKT_PULL_RESP_MAGIC;
                    resp->record_count = 0;
                    resp->dropped_since_last_pull = 0;
                    bytes = sizeof(net_packet_pull_response_k);
                    WW_MALSAFE_LOG_WARN("ioctl NPKT REJECTED magic_match=%u session_match=%u",
                        req_magic_value == expected_magic ? 1u : 0u, req_session_key_value == g_session_key ? 1u : 0u);
                } else {
                    ULONG records_capacity_bytes = (output_size > sizeof(net_packet_pull_response_k))
                        ? (output_size - (ULONG)sizeof(net_packet_pull_response_k)) : 0;
                    ULONG cap_by_buf = records_capacity_bytes /
                        (ULONG)sizeof(malware_safe::net_packet_record_t);
                    ULONG max_records = req_max_records_value;
                    if (max_records == 0 || max_records > cap_by_buf) max_records = cap_by_buf;
                    if (max_records > malware_safe::NET_PKT_RING_CAPACITY) max_records = malware_safe::NET_PKT_RING_CAPACITY;

                    auto* resp = reinterpret_cast<net_packet_pull_response_k*>(buffer);
                    auto* records = reinterpret_cast<malware_safe::net_packet_record_t*>(
                        reinterpret_cast<UCHAR*>(buffer) + sizeof(net_packet_pull_response_k));

                    UINT64 dropped_window = 0;
                    ULONG returned = 0;
                    if (max_records > 0) {
                        returned = malware_safe::pull_packets(req_pid_value, max_records,
                            records, max_records, &dropped_window);
                    }

                    resp->magic = malware_safe::NET_PKT_PULL_RESP_MAGIC;
                    resp->record_count = returned;
                    resp->dropped_since_last_pull = dropped_window;

                    bytes = (ULONG)sizeof(net_packet_pull_response_k) +
                        returned * (ULONG)sizeof(malware_safe::net_packet_record_t);
                    status = STATUS_SUCCESS;
                    WW_MALSAFE_LOG_INFO("ioctl NPKT pid=%lu max=%lu returned=%lu dropped_since=%llu out_bytes=%lu",
                        req_pid_value, max_records, returned, (unsigned long long)dropped_window, bytes);
                }
            }
        }
        else if (code == ioctl_codes::EVTS()) {
            if (input_size >= sizeof(debug_events::DRAIN_DEBUG_EVENTS_REQUEST_T) &&
                output_size >= sizeof(debug_events::DRAIN_DEBUG_EVENTS_REQUEST_T)) {
                auto* req = reinterpret_cast<debug_events::PDRAIN_DEBUG_EVENTS_REQUEST_T>(buffer);
                if (req->session_key != g_session_key) {
                    status = STATUS_ACCESS_DENIED;
                } else {
                    ULONG cap = static_cast<ULONG>(
                        sizeof(req->events) / sizeof(req->events[0]));
                    ULONG limit = req->max_events;
                    if (limit == 0 || limit > cap) limit = cap;

                    ULONG dropped_window = 0;
                    UINT64 total_dropped = 0;
                    UINT64 total_published = 0;
                    ULONG returned = debug_events::drain_into(
                        req->events,
                        limit,
                        &dropped_window,
                        reinterpret_cast<PULONG64>(&total_dropped),
                        reinterpret_cast<PULONG64>(&total_published));

                    req->returned_count = returned;
                    req->dropped_since_last_drain = dropped_window;
                    req->total_dropped = total_dropped;
                    req->total_published = total_published;
                    status = STATUS_SUCCESS;
                }
                bytes = sizeof(debug_events::DRAIN_DEBUG_EVENTS_REQUEST_T);
            } else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else {


            UINT32 base_key = dynamic_key::compute();

            UINT32 orig_server_seed = dynamic_key::g_server_seed;
            BOOLEAN was_seeded = (orig_server_seed != 0 || ioctl_codes::g_server_ioctl_seed != 0);
            if (was_seeded) {

                _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_server_seed), 0);
                _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_cached_key), 0);
                UINT32 base_key_clean = dynamic_key::compute();
                ULONG base_ioctl_base = ((hash_build_key(base_key_clean) ^ secondary_hash(base_key_clean >> 3)) & 0x7FF) | 0x800;
                ULONG base_hb_code = 0x00220000u | ((base_ioctl_base + 8) << 2);
                ULONG base_tira_code = 0x00220000u | ((base_ioctl_base + 48) << 2);

                if (code == base_hb_code && input_size >= sizeof(_HB) && output_size >= sizeof(_HB)) {
                    WW_LOG("HB-RECONNECT: detected fresh client using base IOCTL code 0x%lx (seeded was 0x%lx)",
                        base_hb_code, ioctl_codes::HB());

                    HANDLE prev_client = caller_validation::g_registered_client_pid;
                    HANDLE caller_pid = PsGetCurrentProcessId();
                    if (prev_client != NULL && prev_client == caller_pid) {
                        p_heartbeat hb = (p_heartbeat)buffer;
                        ULONG expectedMagic = 0xDEADBEEFu ^ base_key_clean;
                        _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_server_seed),
                            static_cast<LONG>(orig_server_seed));
                        _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_cached_key), 0);
                        if (hb->magic == expectedMagic && hb->session_key == g_session_key) {
                            LARGE_INTEGER current_time;
                            KeQuerySystemTime(&current_time);
                            _InterlockedExchange64(&g_last_heartbeat_time, current_time.QuadPart);
                            _InterlockedIncrement((volatile LONG*)&g_heartbeat_counter);
                            sentinel_bridge::tick();
                            hb->response = (UINT64)g_heartbeat_counter ^ dynamic_key::get();
                            WW_LOG("HB-RECONNECT: accepted stale base heartbeat from active client pid=%llu without session reset",
                                (unsigned long long)(ULONG_PTR)caller_pid);
                            status = STATUS_SUCCESS;
                            bytes = sizeof(_HB);
                        } else {
                            WW_LOG("HB-RECONNECT: rejected stale base heartbeat from active client pid=%llu magic_match=%u session_match=%u",
                                (unsigned long long)(ULONG_PTR)caller_pid,
                                hb->magic == expectedMagic ? 1u : 0u,
                                hb->session_key == g_session_key ? 1u : 0u);
                            hb->response = 0;
                            status = STATUS_ACCESS_DENIED;
                            bytes = sizeof(_HB);
                        }
                    } else {
                        reset_dynamic_session_state("heartbeat_reconnect_base_ioctl", prev_client, 0, TRUE);


                        p_heartbeat hb = (p_heartbeat)buffer;
                        ULONG expectedMagic = 0xDEADBEEFu ^ base_key_clean;
                        WW_LOG("HB-RECONNECT: magic check match=%u session_present=%u",
                            hb->magic == expectedMagic ? 1u : 0u,
                            hb->session_key != 0 ? 1u : 0u);

                        if (hb->magic == expectedMagic) {
                            LARGE_INTEGER current_time;
                            KeQuerySystemTime(&current_time);

                            _InterlockedExchange((volatile LONG*)&g_session_key, (LONG)hb->session_key);
                            _InterlockedExchange64(&g_last_heartbeat_time, current_time.QuadPart);
                            _InterlockedIncrement((volatile LONG*)&g_heartbeat_counter);
                            sentinel_bridge::tick();

                            WW_LOG("HB-RECONNECT: registering new client");
                            caller_validation::register_client();

                            UINT32 client_pid = (UINT32)(ULONG_PTR)caller_pid;
                            continuous_anti_debug::start(client_pid);
                            file_handle_scanner::start(30, "heartbeat_reconnect", caller_pid, g_heartbeat_counter);

                            hb->response = (UINT64)g_heartbeat_counter ^ dynamic_key::get();


                            WW_LOG("HB-RECONNECT: SUCCESS, session re-established (anti-dump deferred until user-mode finalize_after_activation)");
                            status = STATUS_SUCCESS;
                        } else {
                            WW_LOG("HB-RECONNECT: magic mismatch, rejecting");
                            hb->response = 0;
                            status = STATUS_INVALID_PARAMETER;
                        }
                        bytes = sizeof(_HB);
                    }
                } else if (code == base_tira_code && input_size >= sizeof(phase3_msg::tier_a_query_request_k) &&
                    output_size >= sizeof(phase3_msg::tier_a_query_request_k)) {
                    tier_a_handler_reached = TRUE;
                    HANDLE prev_client = caller_validation::g_registered_client_pid;
                    HANDLE caller_pid = PsGetCurrentProcessId();
                    auto* req = reinterpret_cast<phase3_msg::tier_a_query_request_k*>(buffer);
                    WW_LOG("TIRA: stale_base_handler_entry trace=%lld raw_code=0x%08lx base_tira=0x%08lx seeded_tira=0x%08lx input_size=%lu output_size=%lu session_present=%u active_match=%u session_match=%u caller_pid=%llu registered_pid=%llu elapsed_us=%llu",
                        tier_a_trace_id,
                        code,
                        base_tira_code,
                        early_expected_tira,
                        input_size,
                        output_size,
                        req->session_key != 0 ? 1u : 0u,
                        (prev_client != NULL && prev_client == caller_pid) ? 1u : 0u,
                        req->session_key == g_session_key ? 1u : 0u,
                        (unsigned long long)(ULONG_PTR)caller_pid,
                        (unsigned long long)(ULONG_PTR)prev_client,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_server_seed),
                        static_cast<LONG>(orig_server_seed));
                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_cached_key), 0);
                    if (prev_client != NULL && prev_client == caller_pid && req->session_key == g_session_key) {
                        BOOLEAN tier_present = anti_dma_canary::query_tier_a_preloaded();
                        req->present_flag      = tier_present ? 1u : 0u;
                        req->tier_mask         = req->present_flag;
                        req->first_driver_base = 0;
                        WW_LOG("TIRA: accepted stale base query result=%u expected_bytes=%llu returned_bytes=%llu tier_mask=0x%08X first_base=0x%llX session_present=%u caller_pid=%llu registered_pid=%llu reason=%s elapsed_us=%llu",
                            req->present_flag,
                            static_cast<UINT64>(sizeof(phase3_msg::tier_a_query_request_k)),
                            static_cast<UINT64>(sizeof(phase3_msg::tier_a_query_request_k)),
                            req->tier_mask,
                            req->first_driver_base,
                            req->session_key != 0 ? 1u : 0u,
                            (unsigned long long)(ULONG_PTR)caller_pid,
                            (unsigned long long)(ULONG_PTR)prev_client,
                            req->present_flag ? "tier_a_present" : "healthy_absent",
                            elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                        status = STATUS_SUCCESS;
                    } else {
                        WW_LOG("TIRA: rejected stale base query expected_bytes=%llu returned_bytes=%llu session_present=%u pid=%llu registered_pid=%llu active_match=%u session_match=%u elapsed_us=%llu",
                            static_cast<UINT64>(sizeof(phase3_msg::tier_a_query_request_k)),
                            static_cast<UINT64>(sizeof(phase3_msg::tier_a_query_request_k)),
                            req->session_key != 0 ? 1u : 0u,
                            (unsigned long long)(ULONG_PTR)caller_pid,
                            (unsigned long long)(ULONG_PTR)prev_client,
                            (prev_client != NULL && prev_client == caller_pid) ? 1u : 0u,
                            req->session_key == g_session_key ? 1u : 0u,
                            elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                        status = STATUS_ACCESS_DENIED;
                    }
                    bytes = sizeof(phase3_msg::tier_a_query_request_k);
                } else {

                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_server_seed),
                        static_cast<LONG>(orig_server_seed));
                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_cached_key), 0);
                    if (tier_a_trace) {
                        WW_LOG("TIRA_DISPATCH_REJECT trace=%lld phase=no_seeded_or_base_match status=0x%08lx raw_code=0x%08lx expected_tira=0x%08lx base_tira=0x%08lx decoded_valid=%u decoded_offset=%lu input_size=%lu output_size=%lu elapsed_us=%llu",
                            tier_a_trace_id,
                            STATUS_INVALID_DEVICE_REQUEST,
                            code,
                            early_expected_tira,
                            base_tira_code,
                            early_decode.valid ? 1u : 0u,
                            early_decode.offset,
                            input_size,
                            output_size,
                            elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                    }
                    status = STATUS_INVALID_DEVICE_REQUEST;
                    bytes = 0;
                }
            } else {
                if (tier_a_trace) {
                    WW_LOG("TIRA_DISPATCH_REJECT trace=%lld phase=no_dynamic_seed status=0x%08lx raw_code=0x%08lx expected_tira=0x%08lx decoded_valid=%u decoded_offset=%lu input_size=%lu output_size=%lu elapsed_us=%llu",
                        tier_a_trace_id,
                        STATUS_INVALID_DEVICE_REQUEST,
                        code,
                        early_expected_tira,
                        early_decode.valid ? 1u : 0u,
                        early_decode.offset,
                        input_size,
                        output_size,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
                }
                status = STATUS_INVALID_DEVICE_REQUEST;
                bytes = 0;
            }
        }

        if (tier_a_trace) {
            WW_LOG("TIRA_DISPATCH_PRE_COMPLETE trace=%lld raw_code=0x%08lx expected_tira=0x%08lx status=0x%08lx bytes=%lu handler_reached=%u secure_wrapped=%u activated=%ld registered_pid=%llu bridge_whoswho_seen=%u bridge_sentinel_seen=%u elapsed_us=%llu",
                tier_a_trace_id,
                code,
                early_expected_tira,
                status,
                bytes,
                tier_a_handler_reached ? 1u : 0u,
                secure_wrapped ? 1u : 0u,
                _InterlockedCompareExchange(&g_driver_activated, 0, 0),
                handle_to_u64(caller_validation::g_registered_client_pid),
                sentinel_bridge::g_bridge.whoswho_tsc != 0 ? 1u : 0u,
                sentinel_bridge::g_bridge.sentinel_tsc != 0 ? 1u : 0u,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq));
        }

        if (hvdt_trace && code != early_decode.expected_hvdt_code) {
            HVD_LOG_IMMEDIATE("dispatch_hvdt_trace_no_branch trace=%lld step=%lu raw_code=0x%08lx expected_hvdt=0x%08lx decoded_valid=%u decoded_offset=%lu input_size=%lu output_size=%lu status=0x%08lx bytes=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id,
                36u,
                code,
                early_decode.expected_hvdt_code,
                early_decode.valid ? 1u : 0u,
                early_decode.offset,
                input_size,
                output_size,
                status,
                bytes,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql());
        }

        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_final_timing_pre trace=%lld step=%lu status=0x%08lx bytes=%lu secure_wrapped=%u elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id,
                37u,
                status,
                bytes,
                secure_wrapped ? 1u : 0u,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql());
        }
        add_timing_noise();
        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_final_timing_post trace=%lld step=%lu status=0x%08lx bytes=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id,
                38u,
                status,
                bytes,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql());
        }

        if (secure_wrapped && NT_SUCCESS(status) && bytes > 0) {
            if (hvdt_trace) {
                HVD_LOG_IMMEDIATE("dispatch_secure_response_pre trace=%lld step=%lu plain_bytes=%lu output_size=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id,
                    39u,
                    bytes,
                    output_size,
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    KeGetCurrentProcessorNumber(),
                    (ULONG)KeGetCurrentIrql());
            }
            if (!secure_comm::encrypt_response(
                buffer,
                bytes,
                original_buffer,
                output_size,
                secure_request_entropy,
                secure_request_id)) {
                status = STATUS_ACCESS_DENIED;
                bytes = 0;
                if (hvdt_trace) {
                    HVD_LOG_IMMEDIATE("dispatch_secure_response_post trace=%lld step=%lu ok=0 status=0x%08lx bytes=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                        hvdt_trace_id,
                        40u,
                        status,
                        bytes,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                        KeGetCurrentProcessorNumber(),
                        (ULONG)KeGetCurrentIrql());
                }
            } else {
                bytes += sizeof(secure_comm::SECURE_HEADER);
                if (hvdt_trace) {
                    HVD_LOG_IMMEDIATE("dispatch_secure_response_post trace=%lld step=%lu ok=1 final_bytes=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                        hvdt_trace_id,
                        40u,
                        bytes,
                        elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                        KeGetCurrentProcessorNumber(),
                        (ULONG)KeGetCurrentIrql());
                }
            }
        } else if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_secure_response_skip trace=%lld step=%lu secure_wrapped=%u status=0x%08lx bytes=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                hvdt_trace_id,
                39u,
                secure_wrapped ? 1u : 0u,
                status,
                bytes,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql());
        }

        if (secure_work_buffer) {
            if (hvdt_trace) {
                HVD_LOG_IMMEDIATE("dispatch_secure_free_pre trace=%lld step=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id,
                    41u,
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    KeGetCurrentProcessorNumber(),
                    (ULONG)KeGetCurrentIrql());
            }
            ExFreePoolWithTag(secure_work_buffer, 'mocS');
            if (hvdt_trace) {
                HVD_LOG_IMMEDIATE("dispatch_secure_free_post trace=%lld step=%lu elapsed_us=%llu cpu=%lu irql=%lu",
                    hvdt_trace_id,
                    42u,
                    elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                    KeGetCurrentProcessorNumber(),
                    (ULONG)KeGetCurrentIrql());
            }
        }

        if (code == ioctl_codes::STRM() || code == ioctl_codes::CKIL()) {
            WW_LOG("netaction::DISPATCH COMPLETE code=0x%08X final_status=0x%08X final_bytes=%lu secure_wrapped=%d",
                code, status, bytes, (int)secure_wrapped);
        }

        irp->IoStatus.Status = status;
        irp->IoStatus.Information = bytes;
        if (hvdt_trace) {
            HVD_LOG_IMMEDIATE("dispatch_complete trace=%lld step=%lu code=0x%08lx expected_hvdt=0x%08lx final_status=0x%08lx final_bytes=%lu io_status=0x%08lx io_info=%llu secure_wrapped=%u elapsed_us=%llu cpu=%lu irql=%lu requestor_pid=%llu",
                hvdt_trace_id,
                43u,
                code,
                early_decode.expected_hvdt_code,
                status,
                bytes,
                irp->IoStatus.Status,
                static_cast<UINT64>(irp->IoStatus.Information),
                secure_wrapped ? 1u : 0u,
                elapsed_us_from_qpc(hvdt_dispatch_start, hvdt_dispatch_freq),
                KeGetCurrentProcessorNumber(),
                (ULONG)KeGetCurrentIrql(),
                requestor_pid_to_u64(irp));
        }
        _IofCompleteRequest(irp, IO_NO_INCREMENT);

        return status;
    }
}
