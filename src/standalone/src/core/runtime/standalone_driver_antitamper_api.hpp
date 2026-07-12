#pragma once

#include <cstdint>
#include <string>

namespace anti_tamper {

enum check_class_t : uint32_t;

inline constexpr check_class_t CHECK_FAST = static_cast<check_class_t>(0);
inline constexpr check_class_t CHECK_CODE_INTEGRITY = static_cast<check_class_t>(1);
inline constexpr check_class_t CHECK_DEEP = static_cast<check_class_t>(2);
inline constexpr check_class_t CHECK_PAGE_PROTECT = static_cast<check_class_t>(3);

bool initialize();
uint64_t run_inline_check(check_class_t which, uint64_t proof_hash = 0);
std::string runtime_integrity_latch_source_snapshot();

}

namespace self_guard {

enum class self_guard_result_t : uint32_t {
    allow               = 0,
    bsod_self_pid       = 1,
    bsod_self_address   = 2,
    bsod_self_binary    = 3,
    bsod_self_watermark = 4,
    bsod_blocklist      = 5,
    bsod_ida_plugin     = 6,
};

struct self_guard_context_t {
    std::string     tool_name;
    uint32_t        target_pid = 0;
    uint64_t        target_address = 0;
    std::string     target_binary_path;
    std::string     target_binary_id;
    bool            has_pid = false;
    bool            has_address = false;
    bool            has_binary_path = false;
};

bool is_self_or_child_pid(uint32_t pid);
self_guard_result_t invoke_self_guard(const self_guard_context_t& ctx);
void execute_self_guard_bsod(self_guard_result_t result, const self_guard_context_t& ctx);

}
