#pragma once

#include <cstdint>
#include <string>

namespace shadow_fs_client {

bool initialize();
void shutdown();

bool is_connected();

bool register_sandbox_pid(uint32_t pid, uint32_t flags, const std::wstring& sandbox_root);
bool unregister_sandbox_pid(uint32_t pid);
bool ping();

struct shadow_stats_t {
    uint32_t active_pid_count;
    int64_t  denials;
    int64_t  redirects;
    int64_t  copies;
    int64_t  bytes_copied;
    int64_t  fsctl_denials;
    int64_t  ads_denials;
    int64_t  mapping_denials;
    int64_t  unc_denials;
    int64_t  raw_device_denials;
    int64_t  set_info_denials;
    int64_t  dir_merge_emits;
};
bool query_stats(shadow_stats_t& out);

const std::string& last_error();

constexpr uint32_t k_default_flags = 0x00000037u;

}
