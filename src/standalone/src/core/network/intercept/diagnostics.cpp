#include "diagnostics.hpp"

#include <algorithm>
#include <cctype>
#include <utility>

namespace cert_intercept {
namespace {

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

bool contains_any(const std::string& haystack, const std::vector<const char*>& needles) {
    for (const char* needle : needles) {
        if (haystack.find(needle) != std::string::npos) return true;
    }
    return false;
}

void add_finding(process_diagnostics_t& report,
                 classification_t classification,
                 severity_t severity,
                 std::string title,
                 std::string evidence,
                 std::string next_action) {
    diagnostic_finding_t finding;
    finding.classification = classification;
    finding.severity = severity;
    finding.title = std::move(title);
    finding.evidence = std::move(evidence);
    finding.next_action = std::move(next_action);
    report.findings.push_back(std::move(finding));
}

bool has_classification(const process_diagnostics_t& report, classification_t classification) {
    for (const auto& finding : report.findings) {
        if (finding.classification == classification) return true;
    }
    return false;
}

std::string observed_evidence(const diagnostic_context_t& context, const std::string& fallback) {
    if (context.observation_evidence.empty()) return fallback;
    std::string out;
    for (const auto& entry : context.observation_evidence) {
        if (entry.empty()) continue;
        if (!out.empty()) out += "; ";
        out += entry;
        if (out.size() > 512) break;
    }
    return out.empty() ? fallback : out;
}

}

std::string to_string(classification_t value) {
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
    default: return "unknown";
    }
}

std::string to_string(severity_t value) {
    switch (value) {
    case severity_t::warning: return "warning";
    case severity_t::high: return "high";
    default: return "info";
    }
}

module_summary_t summarize_module(const driver_bridge::module_info_t& module) {
    module_summary_t out;
    out.base = module.base;
    out.size = module.size;
    out.name = module.name;
    out.path = module.path;

    const std::string name = lower_ascii(module.name);
    const std::string path = lower_ascii(module.path);
    const std::string joined = name + " " + path;

    out.browser_runtime = contains_any(joined, {
        "camoufox.exe", "camoufox"
    });
    out.system_tls = contains_any(joined, {
        "crypt32.dll", "schannel.dll", "secur32.dll", "winhttp.dll", "wininet.dll"
    });
    out.app_tls_stack = contains_any(joined, {
        "libssl", "libcrypto", "openssl", "nss3.dll", "wolfssl", "mbedtls", "rustls", "boringssl", "curl"
    });
    out.managed_runtime = contains_any(joined, {
        "clr.dll", "coreclr.dll", "system.net.security", "system.private.corelib", "mscorlib"
    });
    out.quic_capable = contains_any(joined, {
        "msquic", "quic"
    });
    out.proxy_aware = contains_any(joined, {
        "winhttp.dll", "wininet.dll", "urlmon.dll", "libcurl", "curl"
    });
    out.stable_export_candidate = contains_any(joined, {
        "libssl", "libcrypto", "openssl"
    }) && !contains_any(joined, {
        "boringssl"
    });

    if (out.browser_runtime) out.evidence.push_back("browser_runtime");
    if (out.system_tls) out.evidence.push_back("system_tls");
    if (out.app_tls_stack) out.evidence.push_back("app_specific_tls_stack");
    if (out.managed_runtime) out.evidence.push_back("managed_runtime");
    if (out.quic_capable) out.evidence.push_back("quic_http3_capable");
    if (out.proxy_aware) out.evidence.push_back("proxy_aware_api");
    if (out.stable_export_candidate) out.evidence.push_back("stable_export_candidate");

    return out;
}

process_diagnostics_t classify_modules(uint32_t pid,
                                       const std::vector<driver_bridge::module_info_t>& modules,
                                       const diagnostic_context_t& context) {
    process_diagnostics_t report;
    report.pid = pid;
    report.process_name = context.process_name;
    report.read_only = true;
    report.primary = classification_t::unknown;

    bool has_browser = false;
    bool has_system_tls = false;
    bool has_app_tls = false;
    bool has_managed = false;
    bool has_quic = context.quic_observed;
    bool has_stable_export = false;

    report.modules.reserve(modules.size());
    for (const auto& module : modules) {
        module_summary_t summary = summarize_module(module);
        has_browser = has_browser || summary.browser_runtime;
        has_system_tls = has_system_tls || summary.system_tls;
        has_app_tls = has_app_tls || summary.app_tls_stack;
        has_managed = has_managed || summary.managed_runtime;
        has_quic = has_quic || summary.quic_capable;
        has_stable_export = has_stable_export || summary.stable_export_candidate;
        report.modules.push_back(std::move(summary));
    }

    if (!context.proxy_running) {
        add_finding(report,
            classification_t::no_proxy_route,
            severity_t::high,
            "No proxy route",
            "The target has no confirmed path through the AiDA proxy",
            "Start the proxy path or launch a controlled browser profile");
    }

    if (context.proxy_running && !context.ca_trusted) {
        add_finding(report,
            classification_t::ca_not_trusted,
            severity_t::high,
            "CA not trusted",
            "The target does not have confirmed trust for the AiDA interception CA",
            "Install or repair trust for AiDA's exact CA certificate");
    }

    if (context.hostname_san_mismatch_observed) {
        add_finding(report,
            classification_t::hostname_san_mismatch,
            severity_t::high,
            "Hostname or SAN mismatch",
            observed_evidence(context, "The generated leaf certificate name set does not match the target hostname observed by the client"),
            "Regenerate the leaf certificate for the exact SNI or Host authority and retry without modifying target code");
    }

    if (context.browser_trust_policy_or_ct_block || (has_browser && context.proxy_running && context.ca_trusted && context.interception_still_failing)) {
        add_finding(report,
            classification_t::browser_trust_policy_ct,
            severity_t::high,
            "Browser trust policy or CT block",
            observed_evidence(context, "A browser runtime is still rejecting the chain after proxy route and CA trust are present"),
            "Use the controlled browser profile with scoped SPKI allowlisting and policy status inspection");
    }

    if (context.mutual_tls_requested) {
        add_finding(report,
            classification_t::mutual_tls,
            severity_t::high,
            "Mutual TLS requested",
            observed_evidence(context, "The server or application requires client certificate authentication that the proxy cannot synthesize"),
            "Import the authorized client certificate into the controlled test profile or use pass-through for that endpoint");
    }

    if (context.non_http_tls_observed) {
        add_finding(report,
            classification_t::non_http_tls,
            severity_t::warning,
            "Non-HTTP TLS protocol",
            observed_evidence(context, "The TLS stream does not parse as HTTP, HTTP/2, WebSocket, or another proxy-supported HTTP protocol"),
            "Route it through protocol-specific tooling or leave the connection in tunnel mode");
    }

    if (has_quic) {
        add_finding(report,
            classification_t::quic_http3,
            severity_t::warning,
            "QUIC or HTTP/3 capable",
            "The module list indicates UDP-based HTTP can bypass a classic HTTP proxy path",
            "Disable QUIC for the controlled profile or route UDP capture explicitly");
    }

    if (has_app_tls || has_managed) {
        add_finding(report,
            classification_t::app_specific_tls_stack,
            severity_t::warning,
            "Application TLS stack",
            "The target carries its own TLS or managed network runtime",
            "Use provider diagnostics or script handoff instead of native code patching");
    }

    if (context.interception_still_failing && context.proxy_running && context.ca_trusted && (has_app_tls || has_managed)) {
        add_finding(report,
            classification_t::true_pinning,
            severity_t::high,
            "Probable custom pinning",
            "Proxy route and CA trust are present, but target-specific TLS logic is still blocking interception",
            "Generate a handoff package for explicit instrumentation of stable exported APIs or manual analysis");
    }

    if (has_browser && !context.controlled_browser) {
        add_finding(report,
            classification_t::controlled_browser_recommended,
            severity_t::info,
            "Controlled profile recommended",
            "Browser-like runtime detected without confirmed AiDA profile control",
            "Launch the target through AiDA's controlled browser workflow");
    }

    if (has_classification(report, classification_t::no_proxy_route)) {
        report.primary = classification_t::no_proxy_route;
        report.recommended_tier = "proxy_route";
        report.summary = "Proxy routing is not confirmed";
    } else if (has_classification(report, classification_t::ca_not_trusted)) {
        report.primary = classification_t::ca_not_trusted;
        report.recommended_tier = "trust_repair";
        report.summary = "CA trust is not confirmed";
    } else if (has_classification(report, classification_t::hostname_san_mismatch)) {
        report.primary = classification_t::hostname_san_mismatch;
        report.recommended_tier = "certificate_regeneration";
        report.summary = "The generated leaf certificate does not match the requested name";
    } else if (has_classification(report, classification_t::mutual_tls)) {
        report.primary = classification_t::mutual_tls;
        report.recommended_tier = "client_certificate_workflow";
        report.summary = "Client certificate authentication is blocking interception";
    } else if (has_classification(report, classification_t::browser_trust_policy_ct)) {
        report.primary = classification_t::browser_trust_policy_ct;
        report.recommended_tier = "controlled_browser";
        report.summary = "Browser trust policy or certificate transparency behavior needs a controlled profile";
    } else if (has_classification(report, classification_t::non_http_tls)) {
        report.primary = classification_t::non_http_tls;
        report.recommended_tier = "protocol_specific_tunnel";
        report.summary = "The target is using TLS for a non-HTTP protocol";
    } else if (has_classification(report, classification_t::true_pinning)) {
        report.primary = classification_t::true_pinning;
        report.recommended_tier = has_stable_export ? "script_handoff" : "manual_analysis";
        report.summary = "Target-specific certificate validation is likely";
    } else if (has_classification(report, classification_t::quic_http3)) {
        report.primary = classification_t::quic_http3;
        report.recommended_tier = "controlled_browser";
        report.summary = "QUIC or HTTP/3 may hide traffic from the proxy";
    } else if (has_classification(report, classification_t::app_specific_tls_stack)) {
        report.primary = classification_t::app_specific_tls_stack;
        report.recommended_tier = has_stable_export ? "provider_diagnostics" : "manual_analysis";
        report.summary = "Target-specific TLS behavior needs diagnostics";
    } else if (context.proxy_running && context.ca_trusted) {
        report.primary = classification_t::ready;
        report.recommended_tier = "intercept_ready";
        report.summary = "Proxy route and CA trust are ready";
    } else {
        report.primary = classification_t::unknown;
        report.recommended_tier = "diagnose_target";
        report.summary = "More target context is required";
    }

    if (modules.empty()) {
        report.primary = classification_t::unsupported_target;
        report.recommended_tier = "module_enumeration";
        report.summary = "No modules were available for read-only classification";
        add_finding(report,
            classification_t::unsupported_target,
            severity_t::warning,
            "No modules available",
            "Read-only module enumeration returned no target modules",
            "Attach a supported target or retry after the process is fully started");
    }

    return report;
}

process_diagnostics_t diagnose_process(uint32_t pid, const diagnostic_context_t& context) {
    if (pid == 0 || !driver_bridge::is_loaded()) {
        process_diagnostics_t report;
        report.pid = pid;
        report.process_name = context.process_name;
        report.primary = classification_t::unsupported_target;
        report.read_only = true;
        report.recommended_tier = "module_enumeration";
        report.summary = "Driver module enumeration is unavailable";
        add_finding(report,
            classification_t::unsupported_target,
            severity_t::warning,
            "Module enumeration unavailable",
            "Diagnostics did not read or modify target memory",
            "Select a live target with module enumeration support");
        return report;
    }

    auto modules = driver_bridge::enumerate_modules_for(pid);
    return classify_modules(pid, modules, context);
}

}
