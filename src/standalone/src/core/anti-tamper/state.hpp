#pragma once

#include <windows.h>
#include <psapi.h>

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
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

    std::vector<uint32_t> vm_nested_rvas;
    std::unordered_map<uint32_t, uint32_t> atp_flags;
};

inline runtime_t& get()
{
    static runtime_t inst;
    return inst;
}

inline constexpr uint8_t g_vm_master_key[32] = {
    0x3C, 0x6E, 0xF3, 0x72, 0xFE, 0x94, 0xF8, 0x2B,
    0xA5, 0x4F, 0xF5, 0x3A, 0x5F, 0x1D, 0x36, 0xF1,
    0x51, 0x0E, 0x52, 0x7F, 0xAD, 0xE6, 0x82, 0xD1,
    0x9B, 0x05, 0x68, 0x8C, 0x2B, 0x3E, 0x6C, 0x1F
};

}
}
