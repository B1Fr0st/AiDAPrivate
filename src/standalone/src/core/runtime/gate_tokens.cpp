#include "gate_tokens.hpp"

#include <Windows.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include <atomic>
#include <cstring>
#include <mutex>

namespace
{
    using aida::gate_tokens::slot_count;

    std::mutex s_session_mtx;

    bool s_session_active = false;

    alignas(32) uint8_t s_session_key[32] = {};

    alignas(32) uint8_t s_gate_root_commitment[32] = {};

    alignas(32) uint8_t s_slot_keys[slot_count][32] = {};

    std::atomic<uint64_t> s_slot_counters[slot_count] = {};

    std::atomic<uint64_t> s_proof_hash{0};

    std::atomic<int64_t> s_last_issue_ms[slot_count] = {};

    constexpr int64_t k_token_max_age_ms = 10000;

    struct per_thread_issue_t
    {
        uint64_t token;
        uint64_t counter;
        int64_t  ms;
        uint32_t slot;
    };

    thread_local per_thread_issue_t t_last_issue[slot_count] = {};

    bool hmac_sha256(const uint8_t* key, size_t key_len,
                     const uint8_t* data, size_t data_len,
                     uint8_t out[32])
    {
        unsigned int out_len = 0;
        if (!HMAC(EVP_sha256(),
                  key, static_cast<int>(key_len),
                  data, data_len,
                  out, &out_len) || out_len != 32)
        {
            return false;
        }
        return true;
    }

    bool derive_slot_key_locked(uint32_t slot_index, uint8_t out[32])
    {
        uint8_t info[9] = { 's', 'l', 'o', 't', '|', 0, 0, 0, 0 };
        info[5] = static_cast<uint8_t>(slot_index & 0xFFu);
        info[6] = static_cast<uint8_t>((slot_index >> 8) & 0xFFu);
        info[7] = static_cast<uint8_t>((slot_index >> 16) & 0xFFu);
        info[8] = static_cast<uint8_t>((slot_index >> 24) & 0xFFu);
        return hmac_sha256(s_session_key, 32, info, sizeof(info), out);
    }

    void compute_slot_keys_locked()
    {
        for (uint32_t i = 0; i < slot_count; ++i)
        {
            derive_slot_key_locked(i, s_slot_keys[i]);
            s_slot_counters[i].store(0, std::memory_order_release);
            s_last_issue_ms[i].store(0, std::memory_order_release);
        }
    }

    void put_le64(uint64_t v, uint8_t out[8])
    {
        for (int i = 0; i < 8; ++i)
        {
            out[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xFFu);
        }
    }

    int64_t now_ms()
    {
        return static_cast<int64_t>(GetTickCount64());
    }

    bool compute_expected_token_locked(uint32_t slot_index,
                                       uint64_t counter,
                                       int64_t  approx_ms,
                                       uint64_t& out_token)
    {
        uint64_t bucket = static_cast<uint64_t>(approx_ms) / 1000ULL;
        uint8_t input[16] = {};
        put_le64(counter, input + 0);
        put_le64(bucket,  input + 8);
        uint8_t mac[32] = {};
        if (!hmac_sha256(s_slot_keys[slot_index], 32, input, sizeof(input), mac))
        {
            SecureZeroMemory(input, sizeof(input));
            SecureZeroMemory(mac, sizeof(mac));
            return false;
        }
        uint64_t token = 0;
        for (int i = 0; i < 8; ++i)
        {
            token |= (static_cast<uint64_t>(mac[i]) << (i * 8));
        }
        out_token = token;
        SecureZeroMemory(input, sizeof(input));
        SecureZeroMemory(mac, sizeof(mac));
        return true;
    }
}

namespace aida::gate_tokens
{
    bool initialize_session(const uint8_t session_key[32],
                            const uint8_t gate_root_commitment[32],
                            std::string& last_error)
    {
        if (session_key == nullptr || gate_root_commitment == nullptr)
        {
            last_error = "gate_tokens_null_input";
            return false;
        }
        std::lock_guard<std::mutex> lk(s_session_mtx);
        std::memcpy(s_session_key, session_key, 32);
        std::memcpy(s_gate_root_commitment, gate_root_commitment, 32);
        compute_slot_keys_locked();
        s_session_active = true;
        s_proof_hash.store(0, std::memory_order_release);
        return true;
    }

    uint64_t issue_token(uint32_t slot_index)
    {
        if (slot_index >= slot_count) return 0;
        std::lock_guard<std::mutex> lk(s_session_mtx);
        if (!s_session_active) return 0;
        uint64_t counter = s_slot_counters[slot_index].fetch_add(1, std::memory_order_acq_rel) + 1;
        int64_t  ms = now_ms();
        uint64_t token = 0;
        if (!compute_expected_token_locked(slot_index, counter, ms, token)) return 0;
        s_last_issue_ms[slot_index].store(ms, std::memory_order_release);
        t_last_issue[slot_index].token   = token;
        t_last_issue[slot_index].counter = counter;
        t_last_issue[slot_index].ms      = ms;
        t_last_issue[slot_index].slot    = slot_index;
        return token;
    }

    bool verify_token(uint32_t slot_index, uint64_t token, std::string& last_error)
    {
        if (slot_index >= slot_count)
        {
            last_error = "gate_tokens_bad_slot";
            return false;
        }
        if (token == 0)
        {
            last_error = "gate_tokens_zero_token";
            return false;
        }
        const per_thread_issue_t snap = t_last_issue[slot_index];
        if (snap.slot != slot_index || snap.token == 0 || snap.ms == 0)
        {
            last_error = "gate_tokens_no_issue";
            return false;
        }
        if (snap.token != token)
        {
            last_error = "gate_tokens_token_substituted";
            return false;
        }
        std::lock_guard<std::mutex> lk(s_session_mtx);
        if (!s_session_active)
        {
            last_error = "gate_tokens_no_session";
            return false;
        }
        int64_t now = now_ms();
        if ((now - snap.ms) > k_token_max_age_ms)
        {
            last_error = "gate_tokens_stale";
            return false;
        }
        uint64_t expected = 0;
        if (!compute_expected_token_locked(slot_index, snap.counter, snap.ms, expected))
        {
            last_error = "gate_tokens_recompute_failed";
            return false;
        }
        uint8_t a[8];
        uint8_t b[8];
        put_le64(token, a);
        put_le64(expected, b);
        int cmp = CRYPTO_memcmp(a, b, 8);
        SecureZeroMemory(a, sizeof(a));
        SecureZeroMemory(b, sizeof(b));
        if (cmp != 0)
        {
            last_error = "gate_tokens_mismatch";
            return false;
        }
        return true;
    }

    void rotate_root(const uint8_t new_root[32])
    {
        if (new_root == nullptr) return;
        std::lock_guard<std::mutex> lk(s_session_mtx);
        if (!s_session_active) return;
        std::memcpy(s_gate_root_commitment, new_root, 32);
    }

    void clear_session()
    {
        std::lock_guard<std::mutex> lk(s_session_mtx);
        SecureZeroMemory(s_session_key, sizeof(s_session_key));
        SecureZeroMemory(s_gate_root_commitment, sizeof(s_gate_root_commitment));
        SecureZeroMemory(s_slot_keys, sizeof(s_slot_keys));
        for (uint32_t i = 0; i < slot_count; ++i)
        {
            s_slot_counters[i].store(0, std::memory_order_release);
            s_last_issue_ms[i].store(0, std::memory_order_release);
        }
        s_proof_hash.store(0, std::memory_order_release);
        s_session_active = false;
    }

    bool is_session_active()
    {
        std::lock_guard<std::mutex> lk(s_session_mtx);
        return s_session_active;
    }

    bool current_slot_counter(uint32_t slot_index, uint64_t& out_counter)
    {
        if (slot_index >= slot_count) return false;
        out_counter = s_slot_counters[slot_index].load(std::memory_order_acquire);
        return true;
    }

    bool check_feature_allowed(uint32_t slot_index)
    {
        if (slot_index >= slot_count) return false;
        if (!aida::license_state::is_valid_or_degraded()) return false;
        if (!aida::license_state::is_arc_loaded()) return false;
        return true;
    }

    void fold_integrity_token(uint64_t token)
    {
        if (token == 0) return;
        uint64_t prev = s_proof_hash.load(std::memory_order_acquire);
        uint64_t rot = ((token << 31) | (token >> (64 - 31)));
        uint64_t next = prev ^ token ^ rot;
        s_proof_hash.store(next, std::memory_order_release);
    }

    uint64_t current_proof_hash()
    {
        return s_proof_hash.load(std::memory_order_acquire);
    }
}
