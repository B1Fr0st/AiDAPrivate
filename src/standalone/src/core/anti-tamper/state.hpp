#pragma once

#include <windows.h>
#include <psapi.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "key_pipeline.hpp"
#include "hardware_id/hardware_id.hpp"

namespace anti_tamper {
namespace state {

struct code_snapshot_t
{
    uint64_t text_base = 0;
    uint32_t text_size = 0;
    uint64_t text_hash = 0;
    uint8_t  text_sha256[32] = {};
    uint64_t module_base = 0;
    uint64_t module_end = 0;
};

struct block_hash_t
{
    uint64_t block_base;
    uint32_t block_size;
    uint64_t chained_hash;
};

struct iat_entry_t
{
    uint64_t slot_va;
    uint64_t resolved_va;
};

struct token_chain_state_t
{
    std::atomic<uint64_t> chain_accumulator{0};
    std::atomic<int64_t>  last_fast_check_ms{0};
    std::atomic<int64_t>  last_deep_check_ms{0};
    std::atomic<int64_t>  last_integrity_check_ms{0};
    std::atomic<uint64_t> fast_check_count{0};
    std::atomic<uint64_t> deep_check_count{0};
    uint64_t              siphash_key[2] = {};
};

struct runtime_t
{
    std::mutex mtx;
    std::atomic<bool> initialized{false};
    std::atomic<bool> violation_latched{false};
    std::atomic<bool> monitors_running{false};

    code_snapshot_t code_snap{};
    std::vector<block_hash_t> block_chain;
    std::vector<iat_entry_t> iat_snap;

    token_chain_state_t chain{};

    uint32_t verify_counter = 0;
    std::string violation_reason;
    uint64_t last_server_nonce_hash = 0;
    void* canary_page = nullptr;

    std::atomic<uint8_t> last_peb_being_debugged{0};
    std::atomic<uint8_t> last_debug_port_present{0};
    uint32_t veh_baseline_count = 0;
    std::atomic<bool> veh_baseline_captured{false};
    std::atomic<bool> self_job_active{false};
    uint64_t last_sentinel_ready_since_tsc = 0;
    uint64_t kernel_flags_settle_start_ms = 0;
    uint32_t last_kernel_flags = 0;
    uint32_t kernel_flag_persist_count = 0;
    std::atomic<bool> license_pending_activation{true};
    std::atomic<bool> activation_hardening_done{false};

    std::vector<uint32_t> vm_nested_rvas;
    std::unordered_map<uint32_t, uint32_t> atp_flags;

    std::atomic<uint64_t> watchdog_last_tick_ms{0};
    std::atomic<uint64_t> worker_a_last_tick_ms{0};
    std::atomic<uint64_t> worker_b_last_tick_ms{0};
    std::atomic<uint64_t> worker_c_last_tick_ms{0};
    std::atomic<uint64_t> witness_chain_a{0};
    std::atomic<uint64_t> witness_chain_b{0};
    std::atomic<uint64_t> witness_chain_c{0};
    std::atomic<uint64_t> reattest_last_proof_token{0};
    std::atomic<uint64_t> reattest_last_success_ms{0};
    std::atomic<uint64_t> reattest_first_failure_ms{0};
    std::atomic<bool> watchdog_running{false};

    std::atomic<bool>     decoy_honeypot_tripped{false};
    std::atomic<int64_t>  decoy_honeypot_trip_ms{0};
    std::atomic<bool>     decoy_degrade_active{false};
    std::atomic<uint32_t> decoy_honeypot_count{0};
};

inline runtime_t& get()
{
    static runtime_t inst;
    return inst;
}

namespace detail_master_key {

    constexpr uint64_t kVmKeyMaxCacheMs = 100ULL;

    inline std::mutex& cache_mutex()
    {
        static std::mutex m;
        return m;
    }

    inline uint8_t* cache_storage()
    {
        alignas(32) static uint8_t buf[32] = {};
        return buf;
    }

    inline std::atomic<uint64_t>& cache_expiry_ms()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline uint64_t now_ms_steady()
    {
        return static_cast<uint64_t>(GetTickCount64());
    }

    inline bool derive_into(uint8_t out[32])
    {
        auto anchors = aida::hardware_id::collect_user_mode();
        std::string canonical = aida::hardware_id::canonical_string(anchors);

        bool ok = key_pipeline::derive(
            "aida.vm.master",
            reinterpret_cast<const uint8_t*>(canonical.data()),
            canonical.size(),
            out, 32);

        if (!ok)
        {
            int cpu_info[4] = {};
            __cpuid(cpu_info, 1);
            uint8_t fallback_salt[32];
            std::memcpy(fallback_salt, cpu_info, sizeof(cpu_info));
            uint64_t pid_tsc[2] = { static_cast<uint64_t>(GetCurrentProcessId()), __rdtsc() };
            std::memcpy(fallback_salt + 16, pid_tsc, 16);

            ok = key_pipeline::derive(
                "aida.vm.master.fallback",
                fallback_salt, sizeof(fallback_salt),
                out, 32);
            SecureZeroMemory(fallback_salt, sizeof(fallback_salt));
        }

        return ok;
    }

    inline void scrub_cache_locked()
    {
        SecureZeroMemory(cache_storage(), 32);
        cache_expiry_ms().store(0, std::memory_order_release);
    }

}

inline bool materialize_vm_master_key(uint8_t out[32])
{
    uint64_t now = detail_master_key::now_ms_steady();
    {
        std::lock_guard<std::mutex> lk(detail_master_key::cache_mutex());
        uint64_t exp = detail_master_key::cache_expiry_ms().load(std::memory_order_acquire);
        if (exp != 0 && now < exp)
        {
            std::memcpy(out, detail_master_key::cache_storage(), 32);
            return true;
        }
        detail_master_key::scrub_cache_locked();
    }

    uint8_t fresh[32] = {};
    if (!detail_master_key::derive_into(fresh))
    {
        SecureZeroMemory(fresh, 32);
        __fastfail(0xA1DAA0E1u);
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(detail_master_key::cache_mutex());
        std::memcpy(detail_master_key::cache_storage(), fresh, 32);
        detail_master_key::cache_expiry_ms().store(
            now + detail_master_key::kVmKeyMaxCacheMs,
            std::memory_order_release);
        std::memcpy(out, fresh, 32);
    }

    SecureZeroMemory(fresh, 32);
    return true;
}

inline void clear_vm_master_key_cache()
{
    std::lock_guard<std::mutex> lk(detail_master_key::cache_mutex());
    detail_master_key::scrub_cache_locked();
}

struct vm_master_key_scoped_t
{
    alignas(32) uint8_t bytes[32] = {};
    bool ok = false;

    vm_master_key_scoped_t() noexcept
    {
        ok = materialize_vm_master_key(bytes);
    }
    ~vm_master_key_scoped_t() noexcept
    {
        SecureZeroMemory(bytes, sizeof(bytes));
    }
    vm_master_key_scoped_t(const vm_master_key_scoped_t&) = delete;
    vm_master_key_scoped_t& operator=(const vm_master_key_scoped_t&) = delete;

    const uint8_t* data() const noexcept { return bytes; }
};

struct vm_master_key_proxy_t
{
    operator const uint8_t*() const noexcept
    {
        thread_local alignas(32) uint8_t tls_buf[32] = {};
        thread_local uint64_t tls_expiry = 0;
        uint64_t now = detail_master_key::now_ms_steady();
        if (tls_expiry == 0 || now >= tls_expiry)
        {
            if (!materialize_vm_master_key(tls_buf))
            {
                SecureZeroMemory(tls_buf, sizeof(tls_buf));
                tls_expiry = 0;
                return tls_buf;
            }
            tls_expiry = now + detail_master_key::kVmKeyMaxCacheMs;
        }
        return tls_buf;
    }
    const uint8_t* data() const noexcept
    {
        return static_cast<const uint8_t*>(*this);
    }
};

inline const vm_master_key_proxy_t g_vm_master_key{};

}
}
