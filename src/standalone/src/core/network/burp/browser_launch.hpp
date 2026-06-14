#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace browser {

enum class certificate_strategy_t : uint8_t
{
    trust_store_only = 0,
    camoufox_spki_allowlist = 1,
    unsafe_ignore_all_for_debug_builds_only = 2
};

struct browser_launch_config_t
{
    std::string proxy_host = "127.0.0.1";
    uint16_t    proxy_port = 8443;
    std::string profile_subdir = "BurpBrowser";
    std::string initial_url;
    certificate_strategy_t certificate_strategy = certificate_strategy_t::camoufox_spki_allowlist;
    std::string spki_allowlist;
    bool        clear_profile_first = false;
};

struct browser_status_t
{
    bool        running = false;
    uint32_t    pid = 0;
    std::string browser_path;
    std::string profile_path;
    uint16_t    proxy_port = 0;
    uint64_t    launched_ms = 0;
    certificate_strategy_t certificate_strategy = certificate_strategy_t::camoufox_spki_allowlist;
    std::string spki_hash_prefix;
};

bool initialize();
void shutdown();

bool launch(const browser_launch_config_t& cfg, uint32_t& out_pid);
bool kill(uint32_t pid);
bool kill_all();

std::vector<browser_status_t> list_running();
void                          register_browser_pid(uint32_t pid);

bool        detect_camoufox_path(std::string& out_path);
std::string profile_root();
std::string compute_profile_path(const std::string& subdir);
std::wstring build_command_line_for_test(const std::string& browser_path,
                                         const browser_launch_config_t& cfg,
                                         const std::string& profile_path);

bool        certificate_strategy_debug_only_available();
const char* certificate_strategy_name(certificate_strategy_t strategy);
bool        certificate_strategy_from_string(const std::string& name, certificate_strategy_t& out);
std::string spki_hash_prefix(const std::string& allowlist);
std::string last_error();

}
}
}
