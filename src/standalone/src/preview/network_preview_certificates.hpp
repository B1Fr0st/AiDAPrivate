#pragma once

#include "network_preview_adapter.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace aida::preview::network {

inline std::string filesystem_path_utf8(const std::filesystem::path& path) {
    const auto encoded = path.u8string();
    return std::string(reinterpret_cast<const char*>(encoded.data()), encoded.size());
}

}

namespace cert_generator {

struct root_ca_t { bool valid = true; };

inline root_ca_t& ca_storage() {
    static root_ca_t ca;
    return ca;
}

inline bool initialize() {
    ca_storage().valid = true;
    aida::preview::network::record_receipt("AiDA preview CA", "initialized");
    return true;
}

inline bool is_ready() { return ca_storage().valid; }
inline const root_ca_t& get_root_ca() { return ca_storage(); }
inline bool is_root_ca_installed(const root_ca_t& ca) { return ca.valid; }

inline bool install_root_ca(const root_ca_t& ca) {
    aida::preview::network::record_receipt("AiDA preview CA", "trusted for preview");
    return ca.valid;
}

inline std::string spki_sha256_base64(const root_ca_t&) {
    return "n3LzqMY7lB8L1mJ7QdIlVwZtPp9F8+eGxVSTUDIOFIXTURE=";
}

}

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

enum class severity_t { info, warning, high };

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

inline std::string to_string(classification_t value) {
    switch (value) {
    case classification_t::ready: return "ready";
    case classification_t::no_proxy_route: return "no_proxy_route";
    case classification_t::ca_not_trusted: return "ca_not_trusted";
    case classification_t::hostname_san_mismatch: return "hostname_san_mismatch";
    case classification_t::browser_trust_policy_ct: return "browser_trust_policy_ct";
    case classification_t::mutual_tls: return "mutual_tls";
    case classification_t::non_http_tls: return "non_http_tls";
    case classification_t::quic_http3: return "quic_http3";
    case classification_t::app_specific_tls_stack: return "app_specific_tls_stack";
    case classification_t::true_pinning: return "true_pinning";
    case classification_t::controlled_browser_recommended: return "controlled_browser_recommended";
    case classification_t::unsupported_target: return "unsupported_target";
    case classification_t::unknown: return "unknown";
    }
    return "unknown";
}

inline std::string to_string(severity_t value) {
    switch (value) {
    case severity_t::info: return "info";
    case severity_t::warning: return "warning";
    case severity_t::high: return "high";
    }
    return "info";
}

inline process_diagnostics_t diagnose_process(uint32_t pid, const diagnostic_context_t& context) {
    process_diagnostics_t result;
    result.pid = pid;
    result.process_name = pid == 12064 ? "camoufox.exe" : "suspect.exe";
    result.primary = context.interception_observed ? classification_t::ready : classification_t::true_pinning;
    result.recommended_tier = context.interception_observed ? "Controlled browser" : "Instrumentation handoff";
    result.summary = context.interception_observed
        ? "TLS interception is observable through the controlled preview route"
        : "The target uses an application-specific TLS validation path";
    result.findings = {
        { result.primary, severity_t::high, "Application-specific trust enforcement",
          "The target retains a dedicated certificate-validation path", "Generate a provider handoff and inspect the validation boundary" },
        { classification_t::controlled_browser_recommended, severity_t::info, "Controlled browser available",
          "Camoufox privacy and proxy policy are ready", "Reproduce the request through the controlled browser" },
        { classification_t::quic_http3, severity_t::warning, "HTTP/3 route review",
          "QUIC can bypass an HTTP CONNECT interception route", "Keep QUIC disabled while validating interception" }
    };
    aida::preview::network::record_receipt("Certificate diagnostics", std::to_string(pid));
    return result;
}

enum class provider_state_t { not_applicable, available, needs_user_launch, attached, failed, detached };

struct provider_descriptor_t {
    std::string provider_id;
    std::string display_name;
    std::string intent;
    std::string behavior;
    bool forces_certificate_success = false;
    bool requires_explicit_target = true;
    bool supports_attach = false;
};

struct provider_status_t {
    provider_descriptor_t descriptor;
    uint32_t pid = 0;
    provider_state_t state = provider_state_t::not_applicable;
    bool active = false;
    std::string reason;
    std::vector<std::string> evidence;
};

inline std::string to_string(provider_state_t value) {
    switch (value) {
    case provider_state_t::available: return "available";
    case provider_state_t::needs_user_launch: return "needs_user_launch";
    case provider_state_t::attached: return "attached";
    case provider_state_t::failed: return "failed";
    case provider_state_t::detached: return "detached";
    case provider_state_t::not_applicable: return "not_applicable";
    }
    return "not_applicable";
}

class provider_registry_t {
public:
    static provider_registry_t& instance() {
        static provider_registry_t registry;
        return registry;
    }

    std::vector<provider_status_t> evaluate(uint32_t pid, const process_diagnostics_t&) {
        return {
            { { "frida-handoff", "Frida handoff", "Observe the validation path", "Generates a target-bound script package", false, true, true },
              pid, provider_state_t::available, false, "Ready for explicit launch", { "Target PID selected", "Proxy endpoint configured" } },
            { { "camoufox-control", "Camoufox control", "Use a controlled browser", "Routes through the AiDA MITM proxy", false, false, false },
              pid, provider_state_t::available, true, "Controlled browser route is ready", { "WebRTC blocked", "Native UA retained" } }
        };
    }
};

namespace profiles {
struct public_ca_export_t {
    bool ok = false;
    std::filesystem::path directory;
    std::filesystem::path pem_path;
    std::filesystem::path der_path;
    std::string error;
};

inline public_ca_export_t export_public_ca_files(const cert_generator::root_ca_t& ca) {
    public_ca_export_t result;
    result.ok = ca.valid;
    result.directory = "/aida-preview/certificates";
    result.pem_path = result.directory / "aida-preview-ca.pem";
    result.der_path = result.directory / "aida-preview-ca.der";
    if (!result.ok) result.error = "preview_ca_unavailable";
    return result;
}
}

struct handoff_request_t {
    process_diagnostics_t diagnostics;
    std::vector<provider_status_t> provider_statuses;
    std::string target_label;
    std::string proxy_endpoint;
    std::string ca_cert_pem_path;
    std::string ca_cert_der_path;
    bool include_module_paths = true;
};

struct handoff_result_t {
    bool ok = false;
    std::filesystem::path directory;
    std::filesystem::path metadata_path;
    std::vector<std::filesystem::path> script_paths;
    std::string error;
};

inline handoff_result_t generate_handoff(const handoff_request_t& request) {
    handoff_result_t result;
    result.ok = request.diagnostics.pid != 0;
    result.directory = std::filesystem::path("/aida-preview/handoffs") / request.target_label;
    result.metadata_path = result.directory / "handoff.json";
    result.script_paths = { result.directory / "observe-tls.js", result.directory / "launch.json" };
    if (!result.ok) result.error = "target_pid_required";
    aida::preview::network::record_receipt(
        "Certificate handoff",
        aida::preview::network::filesystem_path_utf8(result.metadata_path));
    return result;
}

}

namespace cert_pin_bypass {

struct applied_bypass {
    std::string signature_name;
    std::string module_name;
    uint64_t address = 0;
    std::vector<uint8_t> original_bytes;
    std::vector<uint8_t> patch_bytes;
    bool active = false;
};

inline bool is_bypass_active() { return false; }
inline std::vector<applied_bypass> get_active_bypasses() { return {}; }
inline int revert_all_bypasses() {
    aida::preview::network::record_receipt("Legacy certificate patches", "none active");
    return 0;
}

}
