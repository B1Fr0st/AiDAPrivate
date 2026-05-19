#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "dom_xss_mcp.hpp"

#include "camoufox_bridge.hpp"
#include "dom_xss_engine.hpp"
#include "audit_http.hpp"
#include "insertion_points.hpp"
#include "issue.hpp"
#include "scope.hpp"
#include "scanner_module.hpp"

#include "../../settings/standalone_compat.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {

namespace {

using json          = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

std::atomic<uint64_t>& last_scan_ms_slot() { static std::atomic<uint64_t> v{0}; return v; }
std::atomic<uint64_t>& total_payloads_slot() { static std::atomic<uint64_t> v{0}; return v; }
std::atomic<uint64_t>& total_scans_slot() { static std::atomic<uint64_t> v{0}; return v; }

uint64_t now_ms_wall()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::vector<uint8_t> base64_decode(const std::string& s)
{
    static const int8_t tbl[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() * 3 / 4);
    uint32_t buf = 0; int bits = 0;
    for (unsigned char c : s) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        int v = tbl[c];
        if (v == -1) return std::vector<uint8_t>();
        if (v == -2) break;
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

bool ensure_double_crlf_terminated(std::vector<uint8_t>& raw)
{
    if (raw.empty()) return false;
    bool ends_dcrlf = (raw.size() >= 4 &&
                     raw[raw.size() - 4] == '\r' && raw[raw.size() - 3] == '\n' &&
                     raw[raw.size() - 2] == '\r' && raw[raw.size() - 1] == '\n');
    if (!ends_dcrlf) {
        raw.push_back('\r'); raw.push_back('\n');
        raw.push_back('\r'); raw.push_back('\n');
    }
    return true;
}

std::vector<uint8_t> synthesize_get_request(const std::string& path, const std::string& host)
{
    std::string p = path.empty() ? std::string("/") : path;
    std::string s;
    s.reserve(64 + p.size() + host.size());
    s += "GET ";
    s += p;
    s += " HTTP/1.1\r\n";
    s += "Host: ";
    s += host;
    s += "\r\n";
    s += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
    s += "Accept-Language: en-US,en;q=0.5\r\n";
    s += "Connection: close\r\n";
    s += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AiDA/1.0\r\n";
    s += "\r\n";
    return std::vector<uint8_t>(s.begin(), s.end());
}

tool_result_t tool_status(const json& params)
{
    (void)params;
    json data;
    data["camoufox_ready"]  = camoufox::is_ready();
    auto st = camoufox::get_status();
    data["bridge_state"]    = static_cast<int>(st.state);
    data["browser_open"]    = st.browser_open;
    data["active_page_url"] = st.active_page_url;
    data["last_scan_ms"]    = last_scan_ms_slot().load();
    data["total_payloads_fired"] = total_payloads_slot().load();
    data["total_scans"]     = total_scans_slot().load();
    return tool_result_t::ok(data);
}

tool_result_t tool_test_payload(const json& params)
{
    if (!params.is_object()) return tool_result_t::error("expected object params");
    if (!params.contains("target_url") || !params["target_url"].is_string())
        return tool_result_t::error("missing 'target_url'");
    if (!params.contains("payload") || !params["payload"].is_string())
        return tool_result_t::error("missing 'payload'");

    const std::string target_url = params["target_url"].get<std::string>();
    const std::string payload_tpl = params["payload"].get<std::string>();
    bool capture = false;
    if (params.contains("capture_screenshot") && params["capture_screenshot"].is_boolean())
        capture = params["capture_screenshot"].get<bool>();
    int per_timeout = 8000;
    if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer())
        per_timeout = params["timeout_ms"].get<int>();
    if (per_timeout < 1000)  per_timeout = 1000;
    if (per_timeout > 30000) per_timeout = 30000;

    if (!camoufox::is_ready())
        return tool_result_t::error("camoufox bridge not ready");
    if (!scope::in_scope(target_url))
        return tool_result_t::error("target out of scope");

    std::string scheme, host, path;
    uint16_t port = 0;
    if (!audit_http::parse_url(target_url, scheme, host, port, path))
        return tool_result_t::error("invalid target_url");

    auto raw = synthesize_get_request(path, host);
    auto points = insertion_points::analyze(raw, target_url);
    const insertion_point_t* chosen = nullptr;
    for (const auto& ip : points) {
        if (ip.kind == "query") { chosen = &ip; break; }
    }
    if (!chosen) {
        for (const auto& ip : points) {
            if (ip.kind == "path") { chosen = &ip; break; }
        }
    }
    if (!chosen)
        return tool_result_t::error("no query or path insertion point available for the target");

    auto s = dom_xss::make_sentinel();
    auto r = dom_xss::fire_payload(*chosen, payload_tpl, s, capture, per_timeout, scheme, port);
    total_payloads_slot().fetch_add(1);

    json data;
    data["ok"] = r.ok;
    data["canary_fired"] = r.canary_fired;
    data["error"] = r.error;
    data["sink_log"] = r.sink_log;
    data["screenshot_path"] = r.last_screenshot_path;
    data["sentinel_token"] = s.token;
    data["canary_fn"] = s.canary_fn;
    return tool_result_t::ok(data);
}

tool_result_t tool_scan(const json& params)
{
    if (!params.is_object()) return tool_result_t::error("expected object params");
    if (!params.contains("target_url") || !params["target_url"].is_string())
        return tool_result_t::error("missing 'target_url'");

    const std::string target_url = params["target_url"].get<std::string>();
    if (!camoufox::is_ready())
        return tool_result_t::error("camoufox bridge not ready");
    if (!scope::in_scope(target_url))
        return tool_result_t::error("target out of scope");

    std::string scheme, host, path;
    uint16_t port = 0;
    if (!audit_http::parse_url(target_url, scheme, host, port, path))
        return tool_result_t::error("invalid target_url");

    std::vector<uint8_t> raw_request;
    if (params.contains("raw_request_b64") && params["raw_request_b64"].is_string()) {
        raw_request = base64_decode(params["raw_request_b64"].get<std::string>());
        if (raw_request.empty()) return tool_result_t::error("raw_request_b64 invalid base64");
        ensure_double_crlf_terminated(raw_request);
    } else if (params.contains("raw_request") && params["raw_request"].is_string()) {
        const auto& s = params["raw_request"].get_ref<const std::string&>();
        raw_request.assign(s.begin(), s.end());
        ensure_double_crlf_terminated(raw_request);
    } else {
        raw_request = synthesize_get_request(path, host);
    }

    dom_xss::scan_options_t opts;
    if (params.contains("include_polyglot") && params["include_polyglot"].is_boolean())
        opts.include_polyglot = params["include_polyglot"].get<bool>();
    if (params.contains("include_standard") && params["include_standard"].is_boolean())
        opts.include_standard = params["include_standard"].get<bool>();
    if (params.contains("include_dom_only") && params["include_dom_only"].is_boolean())
        opts.include_dom_only = params["include_dom_only"].get<bool>();
    if (params.contains("capture_screenshots") && params["capture_screenshots"].is_boolean())
        opts.capture_screenshots = params["capture_screenshots"].get<bool>();
    if (params.contains("per_payload_timeout_ms") && params["per_payload_timeout_ms"].is_number_integer()) {
        int v = params["per_payload_timeout_ms"].get<int>();
        if (v < 1000)  v = 1000;
        if (v > 30000) v = 30000;
        opts.per_payload_timeout_ms = v;
    }
    if (params.contains("max_payloads_per_point") && params["max_payloads_per_point"].is_number_unsigned()) {
        size_t v = params["max_payloads_per_point"].get<size_t>();
        if (v == 0) v = 1;
        if (v > 64) v = 64;
        opts.max_payloads_per_point = v;
    }
    opts.scheme = scheme;
    opts.host   = host;
    opts.port   = port;

    auto points = insertion_points::analyze(raw_request, target_url);
    size_t total_emitted = 0;
    json per_point = json::array();
    for (const auto& ip : points) {
        if (ip.kind != "query" && ip.kind != "path" &&
            ip.kind != "body_form" && ip.kind != "body_json" &&
            ip.kind != "header" && ip.kind != "cookie") continue;
        size_t emitted = dom_xss::scan_insertion_point(ip, opts);
        total_emitted += emitted;
        total_payloads_slot().fetch_add(opts.max_payloads_per_point);
        json e;
        e["kind"] = ip.kind;
        e["name"] = ip.name;
        e["emitted"] = emitted;
        per_point.push_back(std::move(e));
    }
    last_scan_ms_slot().store(now_ms_wall());
    total_scans_slot().fetch_add(1);

    json data;
    data["target_url"]    = target_url;
    data["points_total"]  = points.size();
    data["points_scanned"] = per_point.size();
    data["per_point"]     = per_point;
    data["issues_emitted"] = total_emitted;
    data["last_engine_error"] = dom_xss::last_error();
    return tool_result_t::ok(data);
}

}

void register_dom_xss_tools(mcp_standalone::server_t& srv)
{
    dom_xss::initialize();

    register_compat(srv, {
        "burp_dom_xss_status", "scanner",
        "Report the DOM-XSS engine status and Camoufox bridge readiness. "
        "Returns whether the headless-browser bridge is up, the active page URL, "
        "total payloads fired, total scans run, and the wall-clock timestamp of the last scan.",
        {},
        tool_status, true
    });

    register_compat(srv, {
        "burp_dom_xss_test_payload", "scanner",
        "Fire one DOM-XSS payload at the target URL via Camoufox and report whether the "
        "sentinel canary was triggered. Use this to test a custom payload template against "
        "a single query/path parameter. The payload may contain '{CANARY_FN}' and '{CANARY}' "
        "placeholders which are substituted with the per-scan sentinel token before delivery.",
        {
            {"target_url",          "string",  "Absolute URL with at least one query or path parameter to inject into.", true},
            {"payload",             "string",  "Payload template (may use {CANARY_FN} / {CANARY} placeholders).", true},
            {"capture_screenshot",  "boolean", "If true and a sink fires, capture a PNG screenshot of the loaded page.", false},
            {"timeout_ms",          "number",  "Per-payload navigation/eval timeout in milliseconds (1000-30000).", false}
        },
        tool_test_payload, false
    });

    register_compat(srv, {
        "burp_dom_xss_scan", "scanner",
        "Run a full DOM-XSS sweep against every query/path/body/cookie/header insertion point "
        "in the supplied request. Each insertion point is exercised with a curated polyglot + "
        "standard + dom-only payload battery; the headless browser's runtime hooks record any "
        "sink that fires (alert, eval, Function, setTimeout(string), document.write, innerHTML "
        "setter, location assignment, etc.). When a sink is triggered the engine emits a "
        "high-severity, certain-confidence issue to the global issue store.",
        {
            {"target_url",              "string",  "Absolute URL of the target.", true},
            {"raw_request",             "string",  "Raw HTTP/1.1 textual request (optional - if omitted a synthesized GET is used).", false},
            {"raw_request_b64",         "string",  "Base64-encoded raw request (optional alternative to raw_request).", false},
            {"include_polyglot",        "boolean", "Include polyglot payload set (default true).", false},
            {"include_standard",        "boolean", "Include standard payload set (default true).", false},
            {"include_dom_only",        "boolean", "Include DOM-only fragment/event payload set (default true).", false},
            {"capture_screenshots",     "boolean", "Capture a screenshot on each certain hit (default false).", false},
            {"max_payloads_per_point",  "number",  "Cap on payloads per insertion point (1-64, default 16).", false},
            {"per_payload_timeout_ms",  "number",  "Per-payload navigation/eval timeout in milliseconds (1000-30000, default 8000).", false}
        },
        tool_scan, false
    });

    diag::log_tagged("dom_xss", "dom_xss_mcp registered 3 tools");
}

}
}
