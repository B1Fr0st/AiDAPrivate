#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "burp_events.hpp"
#include "insertion_points.hpp"
#include "issue.hpp"

namespace aida {
namespace burp {
namespace scanner {

struct probe_t
{
    std::string payload;
    std::string marker;
    std::string variant;
};

struct module_context_t
{
    uint64_t                          audit_id = 0;
    std::string                       session_id;
    uint64_t                          scan_id = 0;
    std::string                       url;
    std::string                       host;
    uint16_t                          port = 0;
    bool                              tls = false;
    int                               timeout_ms = 15000;
    bool                              follow_redirects = false;
    std::function<bool()>             cancelled;
    uint64_t                          baseline_latency_ms = 0;
    std::vector<uint8_t>              baseline_response_body;
    std::vector<std::pair<std::string, std::string>> baseline_response_headers;
    int                               baseline_status_code = 0;
};

struct response_marker_t
{
    std::string label;
    std::string text;
};

struct response_diff_t
{
    bool status_changed = false;
    bool location_changed = false;
    bool content_type_changed = false;
    bool body_hash_changed = false;
    bool meaningful_body_delta = false;
    bool baseline_known = false;
    bool same_status = false;
    int baseline_status = 0;
    int response_status = 0;
    uint64_t baseline_body_hash = 0;
    uint64_t response_body_hash = 0;
    size_t baseline_body_length = 0;
    size_t response_body_length = 0;
    size_t body_length_delta = 0;
    double body_length_ratio = 1.0;
    std::string baseline_location;
    std::string response_location;
    std::string baseline_content_type;
    std::string response_content_type;
    std::vector<std::string> removed_markers;
    std::vector<std::string> added_markers;
    std::string evidence;
};

using send_fn_t = std::function<std::optional<exchange_observed_t>(const std::vector<uint8_t>& raw_request,
                                                                   const probe_t& probe)>;

struct module_t
{
    std::string  id;
    std::string  name;
    std::string  category;
    int          max_probes_per_point = 6;
    std::function<std::vector<probe_t>(const insertion_point_t&, const module_context_t&)> probes;
    std::function<std::optional<issue_t>(const insertion_point_t&,
                                          const probe_t&,
                                          const exchange_observed_t& resp,
                                          const module_context_t&)>           detect;
    std::function<void(const insertion_point_t&,
                       const module_context_t&,
                       const send_fn_t&)>                                     custom_run;
};

bool                        register_module(module_t mod);
std::vector<module_t>       all_modules();
const module_t*             find(const std::string& id);
size_t                      count();

std::string                 random_marker(const std::string& prefix);
bool                        body_contains(const exchange_observed_t& resp, const std::string& needle);
bool                        body_contains_ci(const exchange_observed_t& resp, const std::string& needle);
double                      body_length_ratio(const exchange_observed_t& a, const exchange_observed_t& b);
response_diff_t             compare_response_to_baseline(const exchange_observed_t& resp,
                                                         const module_context_t& ctx,
                                                         const std::vector<response_marker_t>& removed_markers = {},
                                                         const std::vector<response_marker_t>& added_markers = {});
response_diff_t             compare_responses(const exchange_observed_t& baseline,
                                              const exchange_observed_t& resp,
                                              const std::vector<response_marker_t>& removed_markers = {},
                                              const std::vector<response_marker_t>& added_markers = {});

issue_t                     make_issue(const std::string& type_key,
                                       const std::string& name,
                                       severity_t severity,
                                       confidence_t confidence,
                                       const insertion_point_t& ip,
                                       const probe_t& probe,
                                       const exchange_observed_t& resp,
                                       const module_context_t& ctx,
                                       const std::string& evidence_snippet);

}
}
}
