#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace mitm_proxy {
namespace pac_resolver {

enum class proxy_entry_type {
    direct,
    http,
    socks4,
    socks5
};

struct proxy_entry {
    proxy_entry_type type = proxy_entry_type::direct;
    std::string host;
    uint16_t port = 0;
    std::string raw;
};

struct pac_result {
    bool supported = false;
    bool matched = false;
    bool fail_closed = false;
    std::string matched_rule;
    std::string error;
    std::vector<proxy_entry> entries;
};

std::vector<proxy_entry> parse_proxy_list(const std::string& proxy_list, std::string* error = nullptr);
pac_result resolve(const std::string& pac_script,
                   const std::string& url,
                   const std::string& host,
                   uint16_t default_port,
                   bool fail_closed);
const char* to_string(proxy_entry_type type);

}
}
