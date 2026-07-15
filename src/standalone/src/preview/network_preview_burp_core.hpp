#pragma once

#include "network_preview_adapter.hpp"

#include "../core/network/burp/burp_events.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <regex>
#include <string>
#include <utility>
#include <vector>

namespace aida::burp::logger {

enum class source_t : int { proxy = 0, repeater, scanner, intruder, crawler, manual, api, fuzzer };

inline const char* source_label(source_t source) {
    switch (source) {
    case source_t::proxy: return "Proxy";
    case source_t::repeater: return "Repeater";
    case source_t::scanner: return "Scanner";
    case source_t::intruder: return "Intruder";
    case source_t::crawler: return "Crawler";
    case source_t::manual: return "Manual";
    case source_t::api: return "API";
    case source_t::fuzzer: return "Fuzzer";
    }
    return "Manual";
}

inline bool parse_source(const std::string& value, source_t& out) {
    for (int i = 0; i <= static_cast<int>(source_t::fuzzer); ++i) {
        const auto candidate = static_cast<source_t>(i);
        std::string label = source_label(candidate);
        std::transform(label.begin(), label.end(), label.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::string lowered = value;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (label == lowered) { out = candidate; return true; }
    }
    return false;
}

struct log_row_t {
    uint64_t id = 0;
    uint64_t ts_ms = 0;
    std::string method;
    std::string url;
    std::string host;
    uint16_t port = 0;
    int status = 0;
    size_t request_length = 0;
    size_t response_length = 0;
    uint64_t latency_ms = 0;
    std::string mime_type;
    source_t source = source_t::manual;
    uint64_t exchange_id = 0;
};

struct log_filter_t {
    std::string method;
    std::string host_regex;
    std::string url_regex;
    int status_min = 0;
    int status_max = 1000;
    std::string source;
    uint64_t time_from_ms = 0;
    uint64_t time_to_ms = 0;
    std::string mime_type;
};

inline std::vector<log_row_t>& rows() {
    static std::vector<log_row_t> value = {
        { 101, aida::preview::network::monotonic_ms() - 9100, "GET", "https://portal.aidapro.net/api/v2/session", "portal.aidapro.net", 443, 200, 284, 842, 84, "application/json", source_t::proxy, 2041 },
        { 102, aida::preview::network::monotonic_ms() - 7800, "POST", "https://sandbox.aidapro.net/v1/analyze", "sandbox.aidapro.net", 443, 202, 914, 132, 131, "application/json", source_t::repeater, 2042 },
        { 103, aida::preview::network::monotonic_ms() - 6400, "GET", "https://portal.aidapro.net/api/v2/symbols?module=suspect.dll", "portal.aidapro.net", 443, 200, 198, 19422, 62, "application/json", source_t::crawler, 2043 },
        { 104, aida::preview::network::monotonic_ms() - 4300, "POST", "https://telemetry.aidapro.net/v1/events", "telemetry.aidapro.net", 443, 204, 640, 0, 43, "", source_t::api, 2044 },
        { 105, aida::preview::network::monotonic_ms() - 2500, "GET", "https://sandbox.aidapro.net/api/files/..%252fboot.ini", "sandbox.aidapro.net", 443, 200, 332, 941, 73, "text/plain", source_t::fuzzer, 2045 }
    };
    return value;
}

inline bool match_regex(const std::string& value, const std::string& pattern) {
    if (pattern.empty()) return true;
    try { return std::regex_search(value, std::regex(pattern, std::regex::icase)); }
    catch (...) { return value.find(pattern) != std::string::npos; }
}

inline std::vector<log_row_t> query(const log_filter_t& filter, size_t limit) {
    std::vector<log_row_t> result;
    for (const auto& row : rows()) {
        if (!filter.method.empty() && row.method != filter.method) continue;
        if (!match_regex(row.host, filter.host_regex) || !match_regex(row.url, filter.url_regex)) continue;
        if (row.status < filter.status_min || row.status > filter.status_max) continue;
        if (!filter.mime_type.empty() && row.mime_type.find(filter.mime_type) == std::string::npos) continue;
        if (!filter.source.empty()) {
            source_t source;
            if (!parse_source(filter.source, source) || row.source != source) continue;
        }
        result.push_back(row);
        if (result.size() >= limit) break;
    }
    return result;
}

inline size_t total_rows() { return rows().size(); }
inline size_t capacity() { return 10000; }
inline void clear() { rows().clear(); aida::preview::network::record_receipt("Burp logger", "cleared"); }

inline bool export_csv(const std::string& path, const log_filter_t& filter) {
    const auto exported = query(filter, capacity());
    aida::preview::network::record_receipt("Burp logger CSV", path + " " + std::to_string(exported.size()) + " rows");
    return !path.empty();
}

inline std::string last_error() { return {}; }

}

namespace aida::burp::csp {

struct csp_directive_t { std::string name; std::vector<std::string> values; };
struct csp_finding_t { std::string id; std::string title; std::string severity; std::string description; std::string evidence; };
struct csp_result_t {
    std::vector<csp_directive_t> directives;
    std::vector<csp_finding_t> findings;
    int score = 100;
    bool has_csp = false;
    bool is_report_only = false;
};

inline csp_result_t analyze(const std::string& value, bool report_only) {
    csp_result_t result;
    result.has_csp = !value.empty();
    result.is_report_only = report_only;
    result.score = value.find("unsafe-inline") != std::string::npos ? 58 : 86;
    result.directives = {
        { "default-src", { "'self'" } },
        { "script-src", { "'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net" } },
        { "connect-src", { "'self'", "wss://portal.aidapro.net" } }
    };
    result.findings = {
        { "csp-script-inline", "Inline script execution is allowed", "high", "The policy permits inline script execution", "script-src contains 'unsafe-inline'" },
        { "csp-object-missing", "object-src is not constrained", "medium", "Plugin content does not have an explicit deny rule", "object-src directive absent" }
    };
    aida::preview::network::record_receipt("CSP analysis", report_only ? "report-only" : "enforced");
    return result;
}

inline std::string last_error() { return {}; }

}

namespace aida::burp::upstream {

struct upstream_hop_t { std::string type; std::string host; uint16_t port = 0; std::string username; std::string password; };
struct upstream_chain_t { uint64_t id = 0; std::string label; std::vector<upstream_hop_t> hops; bool active = false; };

inline std::vector<upstream_chain_t>& chains() {
    static std::vector<upstream_chain_t> value = {
        { 1, "Reverse lab route", { { "http_connect", "127.0.0.1", 8443, {}, {} } }, true },
        { 2, "Tor research route", { { "socks5", "127.0.0.1", 9050, {}, {} }, { "http_connect", "lab-gateway.local", 8080, "analyst", "" } }, false }
    };
    return value;
}

inline uint64_t add_chain(const upstream_chain_t& source) {
    upstream_chain_t chain = source;
    static uint64_t next_id = 10;
    chain.id = next_id++;
    chains().push_back(chain);
    aida::preview::network::record_receipt("Upstream chain added", chain.label);
    return chain.id;
}

inline bool remove_chain(uint64_t id) {
    auto& value = chains();
    const auto old_size = value.size();
    value.erase(std::remove_if(value.begin(), value.end(), [id](const auto& chain) { return chain.id == id; }), value.end());
    return value.size() != old_size;
}

inline std::vector<upstream_chain_t> list_chains() { return chains(); }

inline bool get_chain(uint64_t id, upstream_chain_t& out) {
    for (const auto& chain : chains()) if (chain.id == id) { out = chain; return true; }
    return false;
}

inline bool set_active_chain(uint64_t id) {
    bool found = false;
    for (auto& chain : chains()) { chain.active = chain.id == id; found = found || chain.active; }
    if (found) aida::preview::network::record_receipt("Upstream chain active", std::to_string(id));
    return found;
}

inline uint64_t get_active_chain_id() {
    for (const auto& chain : chains()) if (chain.active) return chain.id;
    return 0;
}

inline bool update_chain(const upstream_chain_t& source) {
    for (auto& chain : chains()) if (chain.id == source.id) { chain = source; return true; }
    return false;
}

inline bool test_chain(uint64_t id, const std::string& host, uint16_t port, std::string& error) {
    upstream_chain_t chain;
    const bool ok = get_chain(id, chain) && !host.empty() && port != 0;
    error = ok ? std::string() : "Select a chain and target";
    aida::preview::network::record_receipt("Upstream chain test", ok ? host + ":" + std::to_string(port) : error);
    return ok;
}

inline std::string last_error() { return {}; }

}
