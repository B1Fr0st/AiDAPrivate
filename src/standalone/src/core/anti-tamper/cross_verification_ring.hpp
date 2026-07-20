#pragma once

#include <windows.h>
#include <intrin.h>
#include <nmmintrin.h>
#include <immintrin.h>
#include <wmmintrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include "state.hpp"
#include "webhook.hpp"
#include "integrity.hpp"
#include "enforcement.hpp"
#include "fnv1a.hpp"
#include "xxhash.hpp"
#include "blake3.hpp"
#include "sha1.hpp"
#include "hash_test_vectors.hpp"
#include "reloc_mask.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../../helpers/diag_log.hpp"
#include "../infra/executor.hpp"
#include "../runtime/reason_ids.hpp"

namespace anti_tamper {
namespace cross_ring {

#pragma pack(push, 1)

enum class hash_algo_t : uint32_t {
    crc32c      = 0,
    fnv1a_64    = 1,
    xxhash_64   = 2,
    siphash_2_4 = 3,
    sha256      = 4,
    sha1        = 5,
    aes_gmac    = 6,
    blake3      = 7,
};

struct ring_entry_t {
    uint32_t    checker_id;
    uint32_t    hash_algo_id;
    uint64_t    region_base;
    uint64_t    region_size;
    uint8_t     expected_hash[32];
    uint8_t     live_hash[32];
    uint32_t    verification_targets[3];
    uint64_t    last_verified_tick;
    uint32_t    _pad;
};

static_assert(sizeof(ring_entry_t) == 112,
    "ring_entry_t must be exactly 112 bytes with #pragma pack(1)");

struct cross_ring_evidence_t {
    uint32_t    detecting_checker_id;
    uint32_t    target_checker_id;
    uint64_t    region_base;
    uint64_t    region_size;
    uint8_t     expected_hash[32];
    uint8_t     actual_hash[32];
    uint8_t     modified_bytes[256];
    uint32_t    modified_bytes_len;
    uint32_t    _pad;
};

#pragma pack(pop)

struct ring_state_t {
    std::mutex              mtx;
    ring_entry_t            entries[8];
    std::atomic<bool>       running{false};
    std::atomic<bool>       violation_flag{false};
    std::atomic<uint64_t>   generation{0};
    std::atomic<uint32_t>   active_checkers{0};
    bool                    algo_verified[8]{};
    uint32_t                active_ids[8]{};
    uint32_t                active_count{0};
    uint32_t                topology[8][3]{};
};

inline ring_state_t& state()
{
    static ring_state_t s;
    return s;
}

constexpr uint32_t kCheckerCount = 8;
constexpr uint32_t kPageSize = 4096;
constexpr uint64_t kBaseSleepMs = 3000;
constexpr uint64_t kJitterRangeMs = 2000;

static const uint32_t kDefaultTopology[8][3] = {
    {2, 4, 6},
    {3, 5, 7},
    {4, 6, 0},
    {5, 7, 1},
    {6, 0, 2},
    {7, 1, 3},
    {0, 2, 4},
    {1, 3, 5},
};

__forceinline bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

__declspec(noinline) uint32_t compute_crc32c(const void* data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    const auto* p = static_cast<const uint8_t*>(data);

    size_t aligned_end = len & ~7ULL;
    for (size_t i = 0; i < aligned_end; i += 8)
    {
        uint64_t block = 0;
        memcpy(&block, p + i, 8);
        crc = static_cast<uint32_t>(_mm_crc32_u64(crc, block));
    }
    for (size_t i = aligned_end; i < len; ++i)
        crc = _mm_crc32_u8(crc, p[i]);

    return crc ^ 0xFFFFFFFFu;
}

__declspec(noinline) void compute_crc32c_32(const void* data, size_t len, uint8_t out[32])
{
    uint32_t h = compute_crc32c(data, len);
    for (int i = 0; i < 8; ++i)
    {
        uint32_t v = h ^ (static_cast<uint32_t>(i) * 0x9E3779B9u);
        memcpy(out + i * 4, &v, 4);
    }
}

__declspec(noinline) void compute_aes_gmac_32(const void* data, size_t len, uint8_t out[32])
{
    uint8_t key[16] = {};
    uint8_t iv[12] = {};

    integrity::detail::compute_aes_gmac_tag(
        key, iv,
        static_cast<const uint8_t*>(data), len,
        out);

    for (int i = 16; i < 32; ++i)
        out[i] = out[i % 16] ^ out[(i + 5) % 16] ^ 0xA5u;
}

__declspec(noinline) void compute_hash_by_algo(hash_algo_t algo,
                                                 const void* data, size_t len,
                                                 uint8_t out[32])
{
    switch (algo)
    {
    case hash_algo_t::crc32c:
        compute_crc32c_32(data, len, out);
        break;
    case hash_algo_t::fnv1a_64:
        fnv1a::hash_32(data, len, out);
        break;
    case hash_algo_t::xxhash_64:
        xxhash::hash_32(data, len, out);
        break;
    case hash_algo_t::siphash_2_4:
    {
        uint64_t k0 = integrity::detail::load_k0();
        uint64_t k1 = integrity::detail::load_k1();
        uint64_t h = integrity::siphash::hash(
            static_cast<const uint8_t*>(data), len, k0, k1);
        memcpy(out, &h, 8);
        uint64_t h2 = integrity::siphash::hash(
            static_cast<const uint8_t*>(data), len, k0 ^ 0xDEAD, k1 ^ 0xBEEF);
        memcpy(out + 8, &h2, 8);
        uint64_t h3 = integrity::siphash::hash(
            static_cast<const uint8_t*>(data), len, ~k0, ~k1);
        memcpy(out + 16, &h3, 8);
        uint64_t h4 = integrity::siphash::hash(
            static_cast<const uint8_t*>(data), len, k0 ^ 0xCAFE, k1 ^ 0xBABE);
        memcpy(out + 24, &h4, 8);
        break;
    }
    case hash_algo_t::sha256:
        integrity::sha256::hash(data, len, out);
        break;
    case hash_algo_t::sha1:
        sha1::hash_32(data, len, out);
        break;
    case hash_algo_t::aes_gmac:
        compute_aes_gmac_32(data, len, out);
        break;
    case hash_algo_t::blake3:
        blake3::hash(data, len, out);
        break;
    default:
        memset(out, 0, 32);
        break;
    }
}

inline bool verify_hash_algorithm(hash_algo_t algo)
{
    uint8_t computed[32] = {};
    const auto* tv = reinterpret_cast<const uint8_t*>(hash_test_vectors::kTestVector);

    switch (algo)
    {
    case hash_algo_t::crc32c:
    {
        uint32_t h = compute_crc32c(tv, hash_test_vectors::kTestVectorLen);
        return h == hash_test_vectors::kExpectedCRC32C;
    }
    case hash_algo_t::fnv1a_64:
    {
        uint64_t h = fnv1a::hash(tv, hash_test_vectors::kTestVectorLen);
        return h == hash_test_vectors::kExpectedFNV1a64;
    }
    case hash_algo_t::xxhash_64:
    {
        uint64_t h = xxhash::hash(tv, hash_test_vectors::kTestVectorLen, 0);
        return h == hash_test_vectors::kExpectedXXHash64;
    }
    case hash_algo_t::siphash_2_4:
    {
        uint64_t h = integrity::siphash::hash(
            tv, hash_test_vectors::kTestVectorLen,
            hash_test_vectors::kSipHashTestK0,
            hash_test_vectors::kSipHashTestK1);
        return h == hash_test_vectors::kExpectedSipHash;
    }
    case hash_algo_t::sha256:
    {
        uint8_t digest[32] = {};
        integrity::sha256::hash(tv, hash_test_vectors::kTestVectorLen, digest);
        return constant_time_compare(digest, hash_test_vectors::kExpectedSHA256, 32);
    }
    case hash_algo_t::sha1:
    {
        uint8_t digest[32] = {};
        sha1::hash_32(tv, hash_test_vectors::kTestVectorLen, digest);
        uint8_t sha1_expected[32] = {};
        memcpy(sha1_expected, hash_test_vectors::kExpectedSHA1, 20);
        for (int i = 20; i < 32; ++i)
            sha1_expected[i] = static_cast<uint8_t>(
                hash_test_vectors::kExpectedSHA1[i % 20] ^
                hash_test_vectors::kExpectedSHA1[(i + 3) % 20] ^ 0xA5);
        return constant_time_compare(digest, sha1_expected, 32);
    }
    case hash_algo_t::aes_gmac:
    {
        uint8_t tag[16] = {};
        integrity::detail::compute_aes_gmac_tag(
            hash_test_vectors::kAESGMAC_TestKey,
            hash_test_vectors::kAESGMAC_TestIV,
            tv, hash_test_vectors::kTestVectorLen, tag);
        return constant_time_compare(tag, hash_test_vectors::kExpectedAESGMAC, 16);
    }
    case hash_algo_t::blake3:
    {
        uint8_t digest[32] = {};
        blake3::hash(tv, hash_test_vectors::kTestVectorLen, digest);
        return constant_time_compare(digest, hash_test_vectors::kExpectedBLAKE3, 32);
    }
    default:
        return false;
    }
}

inline void recompute_topology()
{
    auto& s = state();
    s.active_count = 0;

    for (uint32_t i = 0; i < kCheckerCount; ++i)
    {
        if (s.algo_verified[i])
        {
            s.active_ids[s.active_count] = i;
            ++s.active_count;
        }
    }

    if (s.active_count < 2)
    {
        for (uint32_t i = 0; i < kCheckerCount; ++i)
            for (uint32_t j = 0; j < 3; ++j)
                s.topology[i][j] = 0xFFFFFFFFu;
        return;
    }

    for (uint32_t idx = 0; idx < s.active_count; ++idx)
    {
        uint32_t checker = s.active_ids[idx];
        uint32_t targets_assigned = 0;

        for (uint32_t step = 1; step < s.active_count && targets_assigned < 3; ++step)
        {
            uint32_t target_idx = (idx + step) % s.active_count;
            uint32_t target = s.active_ids[target_idx];
            if (target != checker)
            {
                s.topology[checker][targets_assigned] = target;
                ++targets_assigned;
            }
        }

        while (targets_assigned < 3)
        {
            s.topology[checker][targets_assigned] = 0xFFFFFFFFu;
            ++targets_assigned;
        }
    }
}

inline void assign_regions(uint64_t text_base, uint32_t text_size)
{
    auto& s = state();

    uint32_t total_pages = (text_size + kPageSize - 1) / kPageSize;
    uint32_t pages_per_checker = total_pages / kCheckerCount;
    if (pages_per_checker == 0) pages_per_checker = 1;

    for (uint32_t i = 0; i < kCheckerCount; ++i)
    {
        uint64_t region_base = text_base + static_cast<uint64_t>(i * pages_per_checker) * kPageSize;
        uint64_t region_end = text_base + static_cast<uint64_t>((i + 1) * pages_per_checker) * kPageSize;
        if (i == kCheckerCount - 1)
            region_end = text_base + text_size;
        if (region_end > text_base + text_size)
            region_end = text_base + text_size;

        s.entries[i].checker_id = i;
        s.entries[i].hash_algo_id = static_cast<uint32_t>(i);
        s.entries[i].region_base = region_base;
        s.entries[i].region_size = region_end - region_base;
        s.entries[i].last_verified_tick = 0;
        s.entries[i]._pad = 0;

        for (uint32_t j = 0; j < 3; ++j)
            s.entries[i].verification_targets[j] = kDefaultTopology[i][j];

        compute_hash_by_algo(static_cast<hash_algo_t>(i),
            reinterpret_cast<const void*>(region_base),
            static_cast<size_t>(region_end - region_base),
            s.entries[i].expected_hash);

        memcpy(s.entries[i].live_hash, s.entries[i].expected_hash, 32);
    }
}

inline bool report_evidence_to_sentinel(const cross_ring_evidence_t& evidence)
{
    if (!driver_bridge::is_loaded() || !driver_bridge::using_kernel_driver())
        return false;

    return driver_bridge::verify_cross_ring_evidence(
        reinterpret_cast<const uint8_t*>(&evidence),
        static_cast<uint32_t>(sizeof(evidence)));
}

__declspec(noinline) void capture_modified_bytes(
    const uint8_t* expected_region, const uint8_t* live_region,
    size_t region_size, uint8_t* out_bytes, uint32_t* out_len)
{
    uint32_t captured = 0;
    size_t max_capture = (region_size < 256) ? region_size : 256;

    for (size_t i = 0; i < max_capture && captured + 2 <= 256; ++i)
    {
        if (expected_region[i] != live_region[i])
        {
            if (captured + 2 > 256) break;
            out_bytes[captured]     = static_cast<uint8_t>(i & 0xFF);
            out_bytes[captured + 1] = live_region[i];
            captured += 2;
        }
    }

    *out_len = captured;
}

__declspec(noinline) void capture_live_region_snapshot_seh(
    uint64_t region_base, size_t snapshot_size, uint8_t out_snapshot[256])
{
    __try
    {
        memcpy(out_snapshot, reinterpret_cast<const void*>(region_base), snapshot_size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        memset(out_snapshot, 0xFF, 256);
    }
}

__declspec(noinline) void handle_hash_mismatch(
    uint32_t detecting_checker_id,
    uint32_t target_checker_id,
    uint64_t region_base,
    uint64_t region_size,
    const uint8_t expected_hash[32],
    const uint8_t actual_hash[32])
{
    auto& s = state();

    if (s.violation_flag.exchange(true))
        return;

    cross_ring_evidence_t evidence{};
    evidence.detecting_checker_id = detecting_checker_id;
    evidence.target_checker_id = target_checker_id;
    evidence.region_base = region_base;
    evidence.region_size = region_size;
    memcpy(evidence.expected_hash, expected_hash, 32);
    memcpy(evidence.actual_hash, actual_hash, 32);

    uint8_t live_region_snapshot[256] = {};

    size_t snapshot_size = (region_size < 256) ? region_size : 256;
    capture_live_region_snapshot_seh(region_base, snapshot_size, live_region_snapshot);

    evidence.modified_bytes_len = static_cast<uint32_t>(snapshot_size);
    memcpy(evidence.modified_bytes, live_region_snapshot, snapshot_size);
    evidence.modified_bytes_len = static_cast<uint32_t>(snapshot_size);

    char dbg[512];
    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
        "cross_ring_violation detector=%u target=%u region_base=0x%llX region_size=0x%llX",
        detecting_checker_id,
        target_checker_id == 0xFFFFFFFFu ? 0xFFFFFFFFu : target_checker_id,
        static_cast<unsigned long long>(region_base),
        static_cast<unsigned long long>(region_size));
    diag::log_tagged_critical("cross_ring", dbg);
    webhook::write_log_critical("cross_ring", dbg);

    bool sentinel_ok = report_evidence_to_sentinel(evidence);

    if (!sentinel_ok)
    {
        DWORD gle = GetLastError();
        char wdbg[256];
        _snprintf_s(wdbg, sizeof(wdbg), _TRUNCATE,
            "cross_ring_evidence_ioctl_failed: checker_id=%u, target=%u, gle=%lu",
            detecting_checker_id,
            target_checker_id == 0xFFFFFFFFu ? 0xFFFFFFFFu : target_checker_id,
            static_cast<unsigned long>(gle));
        diag::log_tagged_critical("cross_ring", wdbg);
        webhook::write_log("cross_ring", wdbg);

        std::string extra = "cross_ring_hash_mismatch checker=" +
            std::to_string(detecting_checker_id) + " target=" +
            std::to_string(target_checker_id);
        enforce_violation_id(
            aida::reason_ids::reason_id_from_string("cross_ring_hash_mismatch"),
            extra);
    }
}

__declspec(noinline) void checker_loop(uint32_t checker_id)
{
    auto& s = state();

    if (checker_id >= kCheckerCount) return;
    if (!s.algo_verified[checker_id]) return;

    hash_algo_t algo = static_cast<hash_algo_t>(checker_id);

    while (s.running.load(std::memory_order_acquire))
    {
        uint64_t jitter = (GetTickCount64() ^ GetCurrentThreadId() ^ checker_id) % kJitterRangeMs;
        uint64_t sleep_ms = kBaseSleepMs + jitter;
        Sleep(static_cast<DWORD>(sleep_ms));

        if (!s.running.load(std::memory_order_acquire))
            break;

        ring_entry_t local_entry;
        {
            std::lock_guard<std::mutex> lk(s.mtx);
            local_entry = s.entries[checker_id];
        }

        if (local_entry.region_base == 0 || local_entry.region_size == 0)
            continue;

        uint8_t computed[32] = {};
        compute_hash_by_algo(algo,
            reinterpret_cast<const void*>(local_entry.region_base),
            static_cast<size_t>(local_entry.region_size),
            computed);

        {
            std::lock_guard<std::mutex> lk(s.mtx);
            memcpy(s.entries[checker_id].live_hash, computed, 32);
            s.entries[checker_id].last_verified_tick = GetTickCount64();
        }

        if (!constant_time_compare(computed, local_entry.expected_hash, 32))
        {
            handle_hash_mismatch(
                checker_id,
                0xFFFFFFFFu,
                local_entry.region_base,
                local_entry.region_size,
                local_entry.expected_hash,
                computed);
            return;
        }

        for (uint32_t t = 0; t < 3; ++t)
        {
            uint32_t target_id = local_entry.verification_targets[t];
            if (target_id >= kCheckerCount) continue;
            if (!s.algo_verified[target_id]) continue;

            ring_entry_t target_entry;
            {
                std::lock_guard<std::mutex> lk(s.mtx);
                target_entry = s.entries[target_id];
            }

            if (target_entry.region_base == 0 || target_entry.region_size == 0)
                continue;

            uint8_t target_computed[32] = {};
            compute_hash_by_algo(algo,
                reinterpret_cast<const void*>(target_entry.region_base),
                static_cast<size_t>(target_entry.region_size),
                target_computed);

            uint8_t target_expected[32];
            {
                std::lock_guard<std::mutex> lk(s.mtx);
                memcpy(target_expected, s.entries[target_id].expected_hash, 32);
            }

            if (!constant_time_compare(target_computed, target_expected, 32))
            {
                handle_hash_mismatch(
                    checker_id,
                    target_id,
                    target_entry.region_base,
                    target_entry.region_size,
                    target_expected,
                    target_computed);
                return;
            }
        }
    }
}

inline bool verify_all_algorithms()
{
    auto& s = state();
    uint32_t passed = 0;

    for (uint32_t i = 0; i < kCheckerCount; ++i)
    {
        hash_algo_t algo = static_cast<hash_algo_t>(i);
        bool ok = verify_hash_algorithm(algo);
        s.algo_verified[i] = ok;

        {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "cross_ring_algo_verify id=%u algo=%u ok=%d",
                i, i, ok ? 1 : 0);
            diag::log_tagged_critical("cross_ring", dbg);
            webhook::write_log("cross_ring", dbg);
        }

        if (ok) ++passed;
    }

    s.active_checkers.store(passed, std::memory_order_release);

    {
        char dbg[96];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "cross_ring_algo_verify_summary passed=%u total=%u",
            passed, kCheckerCount);
        diag::log_tagged_critical("cross_ring", dbg);
        webhook::write_log_critical("cross_ring", dbg);
    }

    return passed >= 2;
}

inline bool initialize(uint64_t text_base, uint32_t text_size)
{
    auto& s = state();

    webhook::write_log_critical_fmt("cross_ring",
        "initialize_begin text_base=0x%llX text_size=0x%X",
        static_cast<unsigned long long>(text_base),
        text_size);
    diag::log_tagged_critical_fmt("cross_ring",
        "initialize_begin text_base=0x%llX text_size=0x%X",
        static_cast<unsigned long long>(text_base),
        text_size);

    if (!verify_all_algorithms())
    {
        webhook::write_log_critical("cross_ring",
            "initialize_failed_algo_verification");
        diag::log_tagged_critical("cross_ring",
            "initialize_failed_algo_verification");
        return false;
    }

    recompute_topology();

    assign_regions(text_base, text_size);

    {
        char dbg[256];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "cross_ring_initialized active=%u generation=%llu",
            s.active_checkers.load(),
            static_cast<unsigned long long>(s.generation.load()));
        webhook::write_log_critical("cross_ring", dbg);
        diag::log_tagged_critical("cross_ring", dbg);
    }

    return true;
}

inline bool start()
{
    auto& s = state();

    if (s.running.exchange(true))
    {
        webhook::write_log("cross_ring", "start_already_running");
        return true;
    }

    s.generation.fetch_add(1, std::memory_order_release);
    s.violation_flag.store(false, std::memory_order_release);

    uint32_t launched = 0;
    for (uint32_t i = 0; i < kCheckerCount; ++i)
    {
        if (!s.algo_verified[i])
        {
            webhook::write_log_critical_fmt("cross_ring",
                "start_skip_checker id=%u algo_not_verified", i);
            continue;
        }

        uint32_t cid = i;
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "cross_ring";
        sub.label = "cross_ring.checker";
        sub.thread_class = "security_task";
        sub.domain = aida::infra::executor::domain_t::security_liveness;
        sub.priority = 0;
        sub.body = [cid]() { checker_loop(cid); };
        bool posted = aida::infra::executor::submit(std::move(sub)).submitted;

        if (posted)
        {
            ++launched;
            webhook::write_log_critical_fmt("cross_ring",
                "start_checker_launched id=%u", i);
        }
        else
        {
            webhook::write_log_critical_fmt("cross_ring",
                "start_checker_launch_failed id=%u", i);
            diag::log_tagged_critical_fmt("cross_ring",
                "start_checker_launch_failed id=%u", i);
        }
    }

    {
        char dbg[128];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "cross_ring_started launched=%u active=%u generation=%llu",
            launched,
            s.active_checkers.load(),
            static_cast<unsigned long long>(s.generation.load()));
        webhook::write_log_critical("cross_ring", dbg);
        diag::log_tagged_critical("cross_ring", dbg);
    }

    return launched > 0;
}

inline void stop()
{
    auto& s = state();
    s.running.store(false, std::memory_order_release);
}

inline bool is_violation()
{
    return state().violation_flag.load(std::memory_order_acquire);
}

}
}
