#pragma once

#include <windows.h>
#include <intrin.h>

#include <cstdint>

#include "state.hpp"
#include "integrity.hpp"
#include "anti_debug.hpp"
#include "anti_hook.hpp"
#include "anti_emulation.hpp"
#include "enforcement.hpp"
#include "webhook.hpp"
#include "obfuscation_macros.hpp"

namespace anti_tamper {

enum check_class_t : uint32_t
{
    CHECK_FAST           = 0,
    CHECK_CODE_INTEGRITY = 1,
    CHECK_DEEP           = 2,
    CHECK_PAGE_PROTECT   = 3
};

namespace token_chain {

#pragma region RDTSC_ENTANGLE
    namespace detail {

        inline std::atomic<bool>& rdtsc_entangle_enabled_flag()
        {
            static std::atomic<bool> v{false};
            return v;
        }

        inline std::atomic<bool>& rdtsc_entangle_violation_flag()
        {
            static std::atomic<bool> v{false};
            return v;
        }

        __forceinline uint64_t rdtsc_entangle_sample()
        {
            int regs[4] = {0, 0, 0, 0};
            _mm_lfence();
            uint64_t t0 = __rdtsc();
            _mm_lfence();
            __cpuid(regs, 0);
            __cpuid(regs, 1);
            __cpuid(regs, 0);
            _mm_lfence();
            uint64_t t1 = __rdtsc();
            _mm_lfence();

            uint64_t delta = t1 - t0;
            uint32_t d32 = static_cast<uint32_t>(delta);

            uint64_t teb_self = __readgsqword(0x30);

            if (delta < 200ULL || delta > 200000ULL)
            {
                rdtsc_entangle_violation_flag().store(true, std::memory_order_release);
                return (static_cast<uint64_t>(d32) ^ teb_self)
                     ^ 0xDEADBEEFC0FFEE01ULL;
            }

            uint32_t feat = static_cast<uint32_t>(regs[0] ^ regs[1] ^ regs[2] ^ regs[3]);
            return (static_cast<uint64_t>(d32) | (static_cast<uint64_t>(feat) << 32))
                 ^ teb_self;
        }
    }

    inline void enable_rdtsc_entangle(bool on)
    {
        detail::rdtsc_entangle_enabled_flag().store(on, std::memory_order_release);
    }

    inline bool is_rdtsc_entangle_enabled()
    {
        return detail::rdtsc_entangle_enabled_flag().load(std::memory_order_acquire);
    }

    inline bool rdtsc_entangle_violation_observed()
    {
        return detail::rdtsc_entangle_violation_flag().load(std::memory_order_acquire);
    }
#pragma endregion

    namespace detail {

        inline int64_t now_ms()
        {
            LARGE_INTEGER f, c;
            QueryPerformanceFrequency(&f);
            QueryPerformanceCounter(&c);
            return static_cast<int64_t>((c.QuadPart * 1000) / f.QuadPart);
        }

        inline std::atomic<int>& trusted_ui_depth()
        {
            static std::atomic<int> v{0};
            return v;
        }

        inline std::atomic<int64_t>& trusted_ui_until_ms()
        {
            static std::atomic<int64_t> v{0};
            return v;
        }

        inline std::atomic<int64_t>& stale_log_ms()
        {
            static std::atomic<int64_t> v{0};
            return v;
        }

        inline void refresh_check_times(state::runtime_t& rt, int64_t now)
        {
            rt.chain.last_fast_check_ms.store(now, std::memory_order_release);
            rt.chain.last_integrity_check_ms.store(now, std::memory_order_release);
        }

        inline uint64_t mix_token(uint64_t check_result, uint64_t chain_prev,
                                   uint64_t rdtsc_val, uint64_t proof_hash,
                                   uint64_t k0, uint64_t k1)
        {
            uint8_t buf[32];
            uint64_t a = check_result ^ chain_prev;
            uint64_t b = rdtsc_val ^ proof_hash;
            memcpy(buf, &a, 8);
            memcpy(buf + 8, &b, 8);
            memcpy(buf + 16, &chain_prev, 8);
            memcpy(buf + 24, &check_result, 8);
            return integrity::siphash::hash(buf, 32, k0, k1);
        }

#pragma region RDTSC_ENTANGLE
        __forceinline uint64_t mix_token_entangled(uint64_t check_result, uint64_t chain_prev,
                                                    uint64_t rdtsc_val, uint64_t proof_hash,
                                                    uint64_t k0, uint64_t k1)
        {
            uint64_t e0 = rdtsc_entangle_sample();
            uint64_t e1 = rdtsc_entangle_sample();

            uint8_t buf[48];
            uint64_t a = check_result ^ chain_prev;
            uint64_t b = rdtsc_val ^ proof_hash;
            uint64_t c = MBA_TRANSFORM(e0, _rotl64(rdtsc_val, 7));
            uint64_t d = MBA_TRANSFORM(e1, _rotl64(chain_prev, 17));
            memcpy(buf, &a, 8);
            memcpy(buf + 8, &b, 8);
            memcpy(buf + 16, &chain_prev, 8);
            memcpy(buf + 24, &check_result, 8);
            memcpy(buf + 32, &c, 8);
            memcpy(buf + 40, &d, 8);
            return integrity::siphash::hash(buf, 48, k0, k1);
        }
#pragma endregion


        inline uint64_t run_fast_checks(state::runtime_t& rt)
        {
            uint64_t result = 0;

            auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
            if (peb[2] != 0)
                result |= 1ULL;

            uint32_t flags = *reinterpret_cast<const volatile uint32_t*>(peb + 0xBC);
            if (flags & 0x70)
                result |= 2ULL;

            unsigned int aux;
            uint64_t t0 = __rdtscp(&aux);
            volatile int x = 0;
            for (int i = 0; i < 100; ++i) x += i;
            uint64_t t1 = __rdtscp(&aux);
            if ((t1 - t0) > 10000000ULL)
                result |= 4ULL;

            auto* kuser = reinterpret_cast<const volatile uint8_t*>(
                reinterpret_cast<void*>(static_cast<uintptr_t>(0x7FFE0000)));
            uint8_t kd_active = kuser[0x2D4];
            uint8_t kd_not_present = kuser[0x2D5];
            if (kd_active != 0 && kd_not_present == 0)
                result |= 8ULL;

            bool hw_bp = false;
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(GetCurrentThread(), &ctx))
            {
                if (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3)
                    hw_bp = true;
            }
            if (hw_bp)
                result |= 16ULL;

            return result;
        }

        inline uint64_t run_code_integrity_checks(state::runtime_t& rt)
        {
            uint64_t result = 0;

            if (!integrity::verify_block_chain(rt.code_snap, rt.block_chain))
                result |= 1ULL;

            if (!integrity::verify_self_hash())
                result |= 2ULL;

            if (!integrity::verify_iat(rt.iat_snap))
                result |= 4ULL;

            return result;
        }

        inline uint64_t run_deep_checks(state::runtime_t& rt)
        {
            uint64_t result = 0;

            auto dbg = anti_debug::full_scan(rt.code_snap.module_base, rt.code_snap.module_end);
            if (dbg.any_detected())
                result |= 1ULL;

            auto hook = anti_hook::full_scan(rt.iat_snap);
            if (hook.any_detected())
                result |= 2ULL;

            auto emu = anti_emulation::full_scan();
            if (emu.cpuid_features || emu.fpu_precision || emu.self_modifying_code)
                result |= 8ULL;

            return result;
        }

        inline uint64_t run_page_protect_checks(state::runtime_t& rt)
        {
            uint64_t result = 0;

            if (!integrity::verify_page_protections(rt.code_snap))
                result |= 1ULL;

            if (!integrity::verify_usermode(rt.code_snap))
                result |= 2ULL;

            return result;
        }

    }

    inline uint64_t run_inline_check(check_class_t which, uint64_t proof_hash)
    {
        auto& rt = state::get();
        uint64_t token = 0;

        if (!rt.initialized.load(std::memory_order_acquire))
            return 0;

        if (rt.violation_latched.load(std::memory_order_acquire))
            return 0;

        int64_t now = detail::now_ms();
        uint64_t check_result = 0;
        bool violation = false;
        const char* violation_reason = nullptr;

        OBFUSCATE_JUNK(tic_pre);

        CFF_BEGIN(tic_cff)
        CFF_STATE(tic_cff, 0)
        {
            switch (which)
            {
            case CHECK_FAST:
                check_result = detail::run_fast_checks(rt);
                rt.chain.last_fast_check_ms.store(now, std::memory_order_release);
                rt.chain.fast_check_count.fetch_add(1, std::memory_order_relaxed);
                if (check_result & 0x1F)
                {
                    violation = true;
                    violation_reason = "fast_check_tamper";
                }
                break;

            case CHECK_CODE_INTEGRITY:
                check_result = detail::run_code_integrity_checks(rt);
                rt.chain.last_integrity_check_ms.store(now, std::memory_order_release);
                if (check_result != 0)
                {
                    violation = true;
                    violation_reason = "code_integrity_violation";
                }
                break;

            case CHECK_DEEP:
                check_result = detail::run_deep_checks(rt);
                rt.chain.last_deep_check_ms.store(now, std::memory_order_release);
                rt.chain.deep_check_count.fetch_add(1, std::memory_order_relaxed);
                if (check_result != 0)
                {
                    violation = true;
                    violation_reason = "deep_scan_violation";
                }
                break;

            case CHECK_PAGE_PROTECT:
                check_result = detail::run_page_protect_checks(rt);
                if (check_result != 0)
                {
                    violation = true;
                    violation_reason = "page_protection_violation";
                }
                break;
            }
            CFF_GOTO(tic_cff, 1);
        }
        CFF_STATE(tic_cff, 1)
        {
            OBFUSCATE_JUNK(tic_mid);

            if (violation)
            {
            std::string detail_str;
            char hdr[128];
            snprintf(hdr, sizeof(hdr), "class=%u result=0x%llx",
                static_cast<unsigned>(which), check_result);
            detail_str = hdr;

            switch (which)
            {
            case CHECK_FAST:
            {
                std::string flags;
                if (check_result & 1ULL) flags += "peb_debugged ";
                if (check_result & 2ULL) flags += "ntglobalflag ";
                if (check_result & 4ULL) flags += "rdtsc_timing ";
                if (check_result & 8ULL) flags += "kuser_kd ";
                if (check_result & 16ULL) flags += "hw_breakpoints ";
                detail_str += " [" + flags + "]";
                break;
            }
            case CHECK_CODE_INTEGRITY:
            {
                std::string flags;
                if (check_result & 1ULL) flags += "block_chain ";
                if (check_result & 2ULL) flags += "self_hash ";
                if (check_result & 4ULL) flags += "iat_modified ";
                detail_str += " [" + flags + "]";
                break;
            }
            case CHECK_DEEP:
            {
                std::string flags;
                if (check_result & 1ULL) flags += "debugger ";
                if (check_result & 2ULL) flags += "hooks ";
                if (check_result & 8ULL) flags += "emulation ";
                detail_str += " [" + flags + "]";
                break;
            }
            case CHECK_PAGE_PROTECT:
            {
                std::string flags;
                if (check_result & 1ULL) flags += "writable_code ";
                if (check_result & 2ULL) flags += "text_modified ";
                detail_str += " [" + flags + "]";
                break;
            }
            }

            webhook::send_debug_log("token_chain", detail_str, true);
            enforce_violation(violation_reason, detail_str);
            CFF_EXIT(tic_cff);
        }

            CFF_GOTO(tic_cff, 2);
        }
        CFF_STATE(tic_cff, 2)
        {
            unsigned int aux;
            uint64_t tsc = __rdtscp(&aux);
            uint64_t prev = rt.chain.chain_accumulator.load(std::memory_order_acquire);

#pragma region RDTSC_ENTANGLE
            if (detail::rdtsc_entangle_enabled_flag().load(std::memory_order_acquire))
            {
                token = detail::mix_token_entangled(
                    check_result, prev, tsc, proof_hash,
                    rt.chain.siphash_key[0], rt.chain.siphash_key[1]);
            }
            else
#pragma endregion
            {
                token = detail::mix_token(
                    check_result, prev, tsc, proof_hash,
                    rt.chain.siphash_key[0], rt.chain.siphash_key[1]);
            }

            rt.chain.chain_accumulator.store(
                MBA_TRANSFORM(prev ^ token, _rotl64(tsc, 13)),
                std::memory_order_release);

            CFF_EXIT(tic_cff);
        }
        CFF_END(tic_cff)

        OBFUSCATE_JUNK(tic_post);
        return token;
    }

    inline void resync_freshness()
    {
        auto& rt = state::get();
        detail::refresh_check_times(rt, detail::now_ms());
    }

    inline void begin_trusted_interaction()
    {
        detail::trusted_ui_depth().fetch_add(1, std::memory_order_acq_rel);
        resync_freshness();
    }

    inline void end_trusted_interaction()
    {
        auto& depth = detail::trusted_ui_depth();
        int prev = depth.fetch_sub(1, std::memory_order_acq_rel);
        int64_t now = detail::now_ms();
        if (prev <= 1)
        {
            depth.store(0, std::memory_order_release);
            detail::trusted_ui_until_ms().store(now + 15000, std::memory_order_release);
        }
        auto& rt = state::get();
        detail::refresh_check_times(rt, now);
    }

    struct trusted_interaction_scope_t
    {
        bool active = false;

        trusted_interaction_scope_t()
        {
            begin_trusted_interaction();
            active = true;
        }

        trusted_interaction_scope_t(const trusted_interaction_scope_t&) = delete;
        trusted_interaction_scope_t& operator=(const trusted_interaction_scope_t&) = delete;

        ~trusted_interaction_scope_t()
        {
            if (active)
                end_trusted_interaction();
        }
    };

    inline bool is_chain_stale()
    {
        auto& rt = state::get();

        if (rt.license_pending_activation.load(std::memory_order_acquire))
            return false;

        int64_t now = detail::now_ms();

        if (detail::trusted_ui_depth().load(std::memory_order_acquire) > 0 ||
            now < detail::trusted_ui_until_ms().load(std::memory_order_acquire))
        {
            detail::refresh_check_times(rt, now);
            return false;
        }

        int64_t init_time = rt.chain.last_deep_check_ms.load(std::memory_order_acquire);
        if (init_time > 0 && (now - init_time) < 30000)
            return false;

        int64_t last_fast = rt.chain.last_fast_check_ms.load(std::memory_order_acquire);
        int64_t last_integ = rt.chain.last_integrity_check_ms.load(std::memory_order_acquire);
        bool fast_stale = last_fast > 0 && (now - last_fast) > 10000;
        bool integ_stale = last_integ > 0 && (now - last_integ) > 60000;
        if (fast_stale || integ_stale)
        {
            int64_t last_log = detail::stale_log_ms().load(std::memory_order_acquire);
            if ((now - last_log) > 5000 &&
                detail::stale_log_ms().compare_exchange_strong(last_log, now, std::memory_order_acq_rel))
            {
                char buf[192];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "chain_freshness_resync fast_age=%lld integ_age=%lld",
                    static_cast<long long>(last_fast > 0 ? now - last_fast : 0),
                    static_cast<long long>(last_integ > 0 ? now - last_integ : 0));
                webhook::write_log("token_chain", buf);
            }
            detail::refresh_check_times(rt, now);
        }

        return false;
    }

    inline void initialize_keys()
    {
        auto& rt = state::get();
        uint64_t k0 = 0, k1 = 0;
        integrity::get_session_keys(k0, k1);
        rt.chain.siphash_key[0] = k0;
        rt.chain.siphash_key[1] = k1;
        rt.chain.chain_accumulator.store(
            k0 ^ k1 ^ __rdtsc(),
            std::memory_order_release);

        int64_t now = detail::now_ms();
        rt.chain.last_fast_check_ms.store(now, std::memory_order_release);
        rt.chain.last_deep_check_ms.store(now, std::memory_order_release);
        rt.chain.last_integrity_check_ms.store(now, std::memory_order_release);
    }

}
}
