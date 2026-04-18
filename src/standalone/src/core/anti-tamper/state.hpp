#pragma once

#include <windows.h>
#include <psapi.h>

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

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
};

inline runtime_t& get()
{
    static runtime_t inst;
    return inst;
}

}
}
