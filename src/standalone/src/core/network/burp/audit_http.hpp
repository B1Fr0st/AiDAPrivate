#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "burp_events.hpp"

namespace aida {
namespace burp {
namespace audit_http {

struct send_options_t
{
    int     timeout_ms = 15000;
    bool    follow_redirects = false;
    int     max_redirects = 3;
    bool    enforce_scope = true;
    std::string sni_override;
};

std::optional<exchange_observed_t> send(const std::vector<uint8_t>& raw_request,
                                        const std::string& host,
                                        uint16_t port,
                                        bool tls,
                                        const send_options_t& options);

std::string last_error();

bool        parse_url(const std::string& url,
                      std::string& scheme,
                      std::string& host,
                      uint16_t& port,
                      std::string& path);

}
}
}
