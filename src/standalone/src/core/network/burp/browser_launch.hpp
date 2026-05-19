#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace browser {

struct browser_launch_config_t
{
    std::string proxy_host = "127.0.0.1";
    uint16_t    proxy_port = 8443;
    std::string profile_subdir = "BurpBrowser";
    std::string initial_url;
    bool        prefer_chrome = false;
    bool        ignore_cert_errors = true;
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
};

bool initialize();
void shutdown();

bool launch(const browser_launch_config_t& cfg, uint32_t& out_pid);
bool kill(uint32_t pid);
bool kill_all();

std::vector<browser_status_t> list_running();
void                          register_browser_pid(uint32_t pid);

bool        detect_edge_path(std::string& out_path);
bool        detect_chrome_path(std::string& out_path);
std::string profile_root();
std::string compute_profile_path(const std::string& subdir);

std::string last_error();

}
}
}
