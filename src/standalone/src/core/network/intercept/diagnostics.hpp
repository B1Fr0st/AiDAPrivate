#pragma once

#include "standalone_driver.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace cert_intercept {

enum class classification_t {
    unknown,
    ready,
    no_proxy_route,
    ca_not_trusted,
    hostname_san_mismatch,
    browser_trust_policy_ct,
    mutual_tls,
    non_http_tls,
    quic_http3,
    app_specific_tls_stack,
    true_pinning,
    controlled_browser_recommended,
    unsupported_target
};

enum class severity_t {
    info,
    warning,
    high
};

struct module_summary_t {
    uint64_t base = 0;
    uint32_t size = 0;
    std::string name;
    std::string path;
    bool browser_runtime = false;
    bool system_tls = false;
    bool app_tls_stack = false;
    bool managed_runtime = false;
    bool quic_capable = false;
    bool proxy_aware = false;
    bool stable_export_candidate = false;
    std::vector<std::string> evidence;
};

struct diagnostic_finding_t {
    classification_t classification = classification_t::unknown;
    severity_t severity = severity_t::info;
    std::string title;
    std::string evidence;
    std::string next_action;
};

struct diagnostic_context_t {
    bool proxy_running = false;
    bool ca_trusted = false;
    bool controlled_browser = false;
    bool quic_observed = false;
    bool interception_observed = false;
    bool interception_still_failing = false;
    bool hostname_san_mismatch_observed = false;
    bool browser_trust_policy_or_ct_block = false;
    bool mutual_tls_requested = false;
    bool non_http_tls_observed = false;
    std::string process_name;
    std::string proxy_endpoint;
    std::string ca_certificate_path;
    std::vector<std::string> observation_evidence;
};

struct process_diagnostics_t {
    uint32_t pid = 0;
    std::string process_name;
    classification_t primary = classification_t::unknown;
    bool read_only = true;
    std::string recommended_tier;
    std::string summary;
    std::vector<module_summary_t> modules;
    std::vector<diagnostic_finding_t> findings;
};

std::string to_string(classification_t value);
std::string to_string(severity_t value);
module_summary_t summarize_module(const driver_bridge::module_info_t& module);
process_diagnostics_t classify_modules(uint32_t pid,
                                       const std::vector<driver_bridge::module_info_t>& modules,
                                       const diagnostic_context_t& context);
process_diagnostics_t diagnose_process(uint32_t pid, const diagnostic_context_t& context);

}
