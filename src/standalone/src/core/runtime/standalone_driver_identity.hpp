#pragma once

#include <cstdint>
#include <string>

namespace driver_bridge::identity {

enum class staleness_t : std::uint8_t {
    none = 0,
    self_target_refused,
    process_unavailable,
    process_exited,
    process_identity_changed,
    module_unavailable,
    module_identity_changed,
};

struct process_creation_identity_t {
    std::uint32_t pid = 0;
    std::uint64_t creation_time_100ns = 0;
    std::string normalized_process_path;
};

struct module_identity_t {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::string normalized_name;
    std::string normalized_path;
};

struct live_target_identity_t {
    process_creation_identity_t process;
    module_identity_t module;
    std::uint64_t observed_at_100ns = 0;
};

struct validation_result_t {
    bool matches = false;
    staleness_t staleness = staleness_t::process_unavailable;
    live_target_identity_t observed;
    std::string detail;
};

bool capture_live_target_identity(std::uint32_t pid,
                                  std::uint64_t preferred_module_base,
                                  live_target_identity_t& out,
                                  std::string* out_error = nullptr);
validation_result_t validate_live_target_identity(const live_target_identity_t& expected);
validation_result_t validate_attached_target_identity(const live_target_identity_t& expected);
bool refresh_attached_target_identity(const live_target_identity_t& expected,
                                      std::string* out_error = nullptr);
const char* staleness_code(staleness_t value) noexcept;

}
