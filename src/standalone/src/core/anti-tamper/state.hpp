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
#include "hardware_id/hardware_id_v2.hpp"

namespace anti_tamper {
namespace state {

#pragma pack(push, 1)
struct reloc_mask_entry_t
{
    uint32_t offset;
    uint32_t size;
    uint32_t reloc_type;
    uint32_t _pad;
    uint8_t  original_value[8];
};
#pragma pack(pop)

static_assert(sizeof(reloc_mask_entry_t) == 24, "reloc_mask_entry_t must be 24 bytes packed");

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
    char     expected_module[64] = {};
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
    std::atomic<bool> full_test_running{false};
    std::atomic<uint64_t> full_test_suppression_until_ms{0};
    std::atomic<uint32_t> trusted_thread_suspension_depth{0};
    std::atomic<uint64_t> trusted_thread_suspension_until_ms{0};

    code_snapshot_t code_snap{};
    std::vector<block_hash_t> block_chain;
    std::vector<iat_entry_t> iat_snap;

    token_chain_state_t chain{};

    uint32_t verify_counter = 0;
    std::string violation_reason;
    std::string violation_detail;
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
    std::atomic<bool> driver_hardening_done{false};
    std::atomic<bool> driver_hardening_active{false};
    std::atomic<uint64_t> driver_hardening_started_ms{0};

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

    struct honeypot_state_t {
        std::atomic<uint32_t> corruption_count{0};
        std::atomic<uint32_t> bsod_count{0};
    };
    honeypot_state_t honeypot;

    std::vector<reloc_mask_entry_t> reloc_mask_table;
    uint64_t preferred_image_base = 0;
};

inline runtime_t& get()
{
    static runtime_t inst;
    return inst;
}

inline uint64_t monotonic_ms()
{
    return static_cast<uint64_t>(GetTickCount64());
}

inline void arm_full_test_suppression(uint64_t duration_ms)
{
    if (duration_ms == 0)
        return;
    const uint64_t now = monotonic_ms();
    const uint64_t max_u64 = ~uint64_t{0};
    const uint64_t until = duration_ms > max_u64 - now ? max_u64 : now + duration_ms;
    auto& slot = get().full_test_suppression_until_ms;
    uint64_t cur = slot.load(std::memory_order_acquire);
    while (cur < until &&
           !slot.compare_exchange_weak(cur, until, std::memory_order_acq_rel, std::memory_order_acquire)) {
    }
}

inline bool full_test_suppression_active(uint64_t* remaining_ms = nullptr)
{
    const uint64_t until = get().full_test_suppression_until_ms.load(std::memory_order_acquire);
    const uint64_t now = monotonic_ms();
    if (until == 0 || now >= until) {
        if (remaining_ms)
            *remaining_ms = 0;
        return false;
    }
    if (remaining_ms)
        *remaining_ms = until - now;
    return true;
}

inline void arm_trusted_thread_suspension_window(uint64_t duration_ms)
{
    if (duration_ms == 0)
        return;
    const uint64_t now = monotonic_ms();
    const uint64_t max_u64 = ~uint64_t{0};
    const uint64_t until = duration_ms > max_u64 - now ? max_u64 : now + duration_ms;
    auto& slot = get().trusted_thread_suspension_until_ms;
    uint64_t cur = slot.load(std::memory_order_acquire);
    while (cur < until &&
           !slot.compare_exchange_weak(cur, until, std::memory_order_acq_rel, std::memory_order_acquire)) {
    }
}

inline bool trusted_thread_suspension_window_active(uint64_t* remaining_ms = nullptr, uint32_t* depth_out = nullptr)
{
    auto& rt = get();
    const uint64_t until = rt.trusted_thread_suspension_until_ms.load(std::memory_order_acquire);
    const uint64_t now = monotonic_ms();
    const uint32_t depth = rt.trusted_thread_suspension_depth.load(std::memory_order_acquire);
    if (depth_out)
        *depth_out = depth;
    if (until == 0 || now >= until) {
        if (remaining_ms)
            *remaining_ms = 0;
        return false;
    }
    if (remaining_ms)
        *remaining_ms = until - now;
    return true;
}

class trusted_thread_suspension_scope_t
{
public:
    explicit trusted_thread_suspension_scope_t(uint64_t duration_ms) noexcept
    {
        if (duration_ms == 0)
            return;
        get().trusted_thread_suspension_depth.fetch_add(1, std::memory_order_acq_rel);
        arm_trusted_thread_suspension_window(duration_ms);
        armed_ = true;
    }

    trusted_thread_suspension_scope_t(const trusted_thread_suspension_scope_t&) = delete;
    trusted_thread_suspension_scope_t& operator=(const trusted_thread_suspension_scope_t&) = delete;

    ~trusted_thread_suspension_scope_t() noexcept
    {
        if (!armed_)
            return;
        auto& depth = get().trusted_thread_suspension_depth;
        uint32_t cur = depth.load(std::memory_order_acquire);
        while (cur != 0 &&
               !depth.compare_exchange_weak(cur, cur - 1, std::memory_order_acq_rel, std::memory_order_acquire)) {
        }
        arm_trusted_thread_suspension_window(2500);
    }

private:
    bool armed_ = false;
};

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
        aida::hardware_id::v2::collection_t collection{};
        std::string err;
        bool collected = aida::hardware_id::v2::collect(collection, err);

        bool ok = collected && key_pipeline::derive(
            "aida.vm.master.v2",
            collection.hwid_hash.data(),
            collection.hwid_hash.size(),
            out, 32);

        SecureZeroMemory(collection.hwid_hash.data(), collection.hwid_hash.size());
        for (auto& factor : collection.factors)
        {
            SecureZeroMemory(factor.factor_hash.data(), factor.factor_hash.size());
            if (!factor.bytes.empty()) SecureZeroMemory(factor.bytes.data(), factor.bytes.size());
        }

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
