#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "insertion_points.hpp"

namespace aida {
namespace burp {
namespace dom_xss {

struct sentinel_t
{
    std::string token;
    std::string canary_fn;
    std::string results_global;
};

sentinel_t   make_sentinel();

std::string  build_pre_injection_script(const sentinel_t& s);

struct payload_set_t
{
    std::string              name;
    std::vector<std::string> templates;
};

std::vector<payload_set_t> default_payload_sets();

struct fire_result_t
{
    bool                     ok = false;
    bool                     canary_fired = false;
    std::vector<std::string> sink_log;
    std::string              last_screenshot_path;
    std::string              error;
};

fire_result_t fire_payload(const insertion_point_t& ip,
                           const std::string&       payload_template,
                           const sentinel_t&        s,
                           bool                     capture_screenshot,
                           int                      per_payload_timeout_ms,
                           const std::string&       scheme_hint = std::string(),
                           uint16_t                 port_hint   = 0);

struct scan_options_t
{
    bool   include_polyglot           = true;
    bool   include_dom_only           = true;
    bool   include_standard           = true;
    bool   capture_screenshots        = false;
    int    per_payload_timeout_ms     = 8000;
    size_t max_payloads_per_point     = 16;
    uint64_t deadline_ms              = 0;
    size_t max_browser_failures       = 1;
    bool   abort_on_browser_error     = true;
    std::function<bool()> cancelled;
    uint64_t audit_id                 = 0;
    std::string scheme;
    std::string host;
    uint16_t    port                  = 0;
};

size_t scan_insertion_point(const insertion_point_t& ip, const scan_options_t& opts);

bool confirm_reflected_in_browser(const std::string&              url,
                                  const std::string&              canary_marker,
                                  std::vector<std::string>&       out_sink_log,
                                  int                             per_payload_timeout_ms = 8000);

bool        initialize();
void        shutdown();
std::string last_error();

}
}
}
