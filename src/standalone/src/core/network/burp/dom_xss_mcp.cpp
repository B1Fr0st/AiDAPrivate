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
#include <exception>
#include <mutex>
#include <sstream>
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

uint64_t now_ms_steady()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

const char* json_type_name(const json& j)
{
    if (j.is_object()) return "object";
    if (j.is_array()) return "array";
    if (j.is_string()) return "string";
    if (j.is_boolean()) return "boolean";
    if (j.is_number()) return "number";
    if (j.is_null()) return "null";
    return "other";
}

std::string json_shape(const json& j, size_t max_keys = 12)
{
    std::ostringstream oss;
    oss << json_type_name(j);
    if (j.is_object())
    {
        oss << "{";
        size_t n = 0;
        for (auto it = j.begin(); it != j.end() && n < max_keys; ++it, ++n)
        {
            if (n) oss << ",";
            oss << it.key() << ":" << json_type_name(it.value());
        }
        if (j.size() > max_keys) oss << ",...";
        oss << "}";
    }
    else if (j.is_array())
    {
        oss << "[" << j.size() << "]";
    }
    return oss.str();
}

std::string ascii_lower_copy(std::string s)
{
    for (char& c : s)
    {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    }
    return s;
}

bool is_browser_infrastructure_error(const std::string& msg)
{
    std::string s = ascii_lower_copy(msg);
    return s.find("connection closed while reading from the driver") != std::string::npos ||
           s.find("connection closed") != std::string::npos ||
           s.find("camoufox bridge not ready") != std::string::npos ||
           s.find("camoufox driver closed") != std::string::npos ||
           s.find("bridge state is busy") != std::string::npos ||
           s.find("target page, context or browser has been closed") != std::string::npos ||
           s.find("browser has been closed") != std::string::npos ||
           s.find("page has been closed") != std::string::npos ||
           s.find("target closed") != std::string::npos ||
           s.find("page crashed") != std::string::npos ||
           s.find("deadline exceeded") != std::string::npos ||
           s.find("harness navigate") != std::string::npos ||
           s.find("navigate failed") != std::string::npos ||
           s.find("evaluate_js failed") != std::string::npos ||
           s.find("add_init_script") != std::string::npos;
}

std::string path_without_query(std::string path)
{
    size_t q = path.find('?');
    if (q != std::string::npos) path.resize(q);
    size_t f = path.find('#');
    if (f != std::string::npos) path.resize(f);
    if (path.empty()) path = "/";
    if (path.size() > 240)
    {
        path.resize(240);
        path += "...";
    }
    return path;
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
    diag::log_tagged_fmt("mcp_burp", "dom_xss_status entry");
    json data;
    const bool ready = camoufox::is_ready();
    auto st = camoufox::get_status();
    data["camoufox_ready"]  = ready;
    data["bridge_state"]    = static_cast<int>(st.state);
    data["browser_open"]    = st.browser_open;
    data["page_verified"]   = st.page_verified;
    data["child_alive"]     = st.child_alive;
    data["cleanup_pending"] = st.cleanup_pending;
    data["child_pid"]       = st.child_pid;
    data["generation"]      = st.generation;
    data["active_page_url"] = st.active_page_url;
    data["active_page_title"] = st.active_page_title;
    data["last_error"]      = st.last_error;
    data["last_scan_ms"]    = last_scan_ms_slot().load();
    data["total_payloads_fired"] = total_payloads_slot().load();
    data["total_scans"]     = total_scans_slot().load();
    diag::log_tagged_fmt("mcp_burp", "dom_xss_status ok ready=%d state=%d browser_open=%d page_verified=%d child_alive=%d cleanup_pending=%d child_pid=%lu total_scans=%llu",
        static_cast<int>(ready), static_cast<int>(st.state), static_cast<int>(st.browser_open),
        static_cast<int>(st.page_verified), static_cast<int>(st.child_alive), static_cast<int>(st.cleanup_pending),
        static_cast<unsigned long>(st.child_pid), static_cast<unsigned long long>(total_scans_slot().load()));
    return tool_result_t::ok(data);
}

tool_result_t tool_test_payload(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "dom_xss_test_payload entry params_shape=%s", json_shape(params).c_str());
    if (!params.is_object())
    {
        diag::log_tagged_fmt("mcp_burp", "dom_xss_test_payload invalid_params");
        return tool_result_t::error("expected object params");
    }
    if (!params.contains("target_url") || !params["target_url"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "dom_xss_test_payload missing target_url");
        return tool_result_t::error("missing 'target_url'");
    }
    if (!params.contains("payload") || !params["payload"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "dom_xss_test_payload missing payload");
        return tool_result_t::error("missing 'payload'");
    }

    const std::string target_url = params["target_url"].get<std::string>();
    const std::string payload_tpl = params["payload"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "dom_xss_test_payload request url_len=%zu payload_len=%zu has_capture=%d has_timeout=%d",
        target_url.size(), payload_tpl.size(), (int)params.contains("capture_screenshot"), (int)params.contains("timeout_ms"));
    bool capture = false;
    if (params.contains("capture_screenshot") && params["capture_screenshot"].is_boolean())
        capture = params["capture_screenshot"].get<bool>();
    int per_timeout = 8000;
    if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer())
        per_timeout = params["timeout_ms"].get<int>();
    if (per_timeout < 1000)  per_timeout = 1000;
    if (per_timeout > 30000) per_timeout = 30000;

    if (!camoufox::ensure_ready())
    {
        auto st = camoufox::get_status();
        std::string err = st.last_error.empty() ? camoufox::last_error() : st.last_error;
        diag::log_tagged_fmt("mcp_burp", "dom_xss_test_payload bridge_not_ready state=%d errors=%llu last_error_len=%zu",
            static_cast<int>(st.state), static_cast<unsigned long long>(st.total_errors), st.last_error.size());
        return tool_result_t::error(err.empty() ? std::string("camoufox bridge not ready") : err);
    }
    if (!scope::in_scope(target_url))
    {
        diag::log_tagged_fmt("mcp_burp", "dom_xss_test_payload out_of_scope url_len=%zu", target_url.size());
        return tool_result_t::error("target out of scope");
    }

    std::string scheme, host, path;
    uint16_t port = 0;
    if (!audit_http::parse_url(target_url, scheme, host, port, path))
    {
        diag::log_tagged_fmt("mcp_burp", "dom_xss_test_payload invalid_url url_len=%zu", target_url.size());
        return tool_result_t::error("invalid target_url");
    }
    const std::string safe_path = path_without_query(path);
    diag::log_tagged_fmt("mcp_burp", "dom_xss_test_payload parsed scheme=%s host=%s port=%u path=%s query=%d timeout_ms=%d capture=%d",
        scheme.c_str(), host.c_str(), static_cast<unsigned>(port), safe_path.c_str(), (int)(path.find('?') != std::string::npos), per_timeout, (int)capture);

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
    {
        diag::log_tagged_fmt("mcp_burp", "dom_xss_test_payload no_insertion_point host=%s path=%s points=%zu",
            host.c_str(), safe_path.c_str(), points.size());
        return tool_result_t::error("no query or path insertion point available for the target");
    }

    auto s = dom_xss::make_sentinel();
    dom_xss::fire_result_t r;
    const auto bridge_before = camoufox::get_status();
    const uint64_t fire_start_ms = GetTickCount64();
    diag::log_tagged_fmt("mcp_burp", "dom_xss_test_payload fire_begin host=%s path=%s chosen_kind=%s chosen_name=%s state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu last_error_len=%zu timeout_ms=%d capture=%d",
        host.c_str(), safe_path.c_str(), chosen->kind.c_str(), chosen->name.c_str(),
        static_cast<int>(bridge_before.state), static_cast<unsigned long long>(bridge_before.generation),
        static_cast<unsigned long>(bridge_before.child_pid), bridge_before.child_alive ? 1 : 0,
        bridge_before.browser_open ? 1 : 0, bridge_before.page_verified ? 1 : 0,
        bridge_before.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(bridge_before.total_calls),
        static_cast<unsigned long long>(bridge_before.total_errors), bridge_before.last_error.size(),
        per_timeout, capture ? 1 : 0);
    try {
        r = dom_xss::fire_payload(*chosen, payload_tpl, s, capture, per_timeout, scheme, port);
    } catch (const std::exception& ex) {
        const auto bridge_after = camoufox::get_status();
        diag::log_tagged_critical_fmt("mcp_burp", "dom_xss_test_payload exception host=%s path=%s chosen_kind=%s elapsed_ms=%llu state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu last_error_len=%zu err=%s",
            host.c_str(), safe_path.c_str(), chosen->kind.c_str(),
            static_cast<unsigned long long>(GetTickCount64() - fire_start_ms),
            static_cast<int>(bridge_after.state), static_cast<unsigned long long>(bridge_after.generation),
            static_cast<unsigned long>(bridge_after.child_pid), bridge_after.child_alive ? 1 : 0,
            bridge_after.browser_open ? 1 : 0, bridge_after.page_verified ? 1 : 0,
            bridge_after.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(bridge_after.total_calls),
            static_cast<unsigned long long>(bridge_after.total_errors), bridge_after.last_error.size(), ex.what());
        return tool_result_t::error(std::string("DOM-XSS payload exception: ") + ex.what());
    } catch (...) {
        const auto bridge_after = camoufox::get_status();
        diag::log_tagged_critical_fmt("mcp_burp", "dom_xss_test_payload exception host=%s path=%s chosen_kind=%s elapsed_ms=%llu state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu last_error_len=%zu err=unknown",
            host.c_str(), safe_path.c_str(), chosen->kind.c_str(),
            static_cast<unsigned long long>(GetTickCount64() - fire_start_ms),
            static_cast<int>(bridge_after.state), static_cast<unsigned long long>(bridge_after.generation),
            static_cast<unsigned long>(bridge_after.child_pid), bridge_after.child_alive ? 1 : 0,
            bridge_after.browser_open ? 1 : 0, bridge_after.page_verified ? 1 : 0,
            bridge_after.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(bridge_after.total_calls),
            static_cast<unsigned long long>(bridge_after.total_errors), bridge_after.last_error.size());
        return tool_result_t::error("DOM-XSS payload exception: unknown");
    }
    total_payloads_slot().fetch_add(1);
    const auto bridge_after = camoufox::get_status();
    diag::log_tagged_fmt("mcp_burp", "dom_xss_test_payload result ok=%d canary_fired=%d host=%s path=%s chosen_kind=%s chosen_name=%s error_len=%zu sink_entries=%zu screenshot_len=%zu elapsed_ms=%llu state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu last_error_len=%zu",
        (int)r.ok, (int)r.canary_fired, host.c_str(), safe_path.c_str(), chosen->kind.c_str(), chosen->name.c_str(),
        r.error.size(), r.sink_log.size(), r.last_screenshot_path.size(),
        static_cast<unsigned long long>(GetTickCount64() - fire_start_ms),
        static_cast<int>(bridge_after.state), static_cast<unsigned long long>(bridge_after.generation),
        static_cast<unsigned long>(bridge_after.child_pid), bridge_after.child_alive ? 1 : 0,
        bridge_after.browser_open ? 1 : 0, bridge_after.page_verified ? 1 : 0,
        bridge_after.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(bridge_after.total_calls),
        static_cast<unsigned long long>(bridge_after.total_errors), bridge_after.last_error.size());

    json data;
    data["ok"] = r.ok;
    data["canary_fired"] = r.canary_fired;
    data["error"] = r.error;
    data["sink_log"] = r.sink_log;
    data["screenshot_path"] = r.last_screenshot_path;
    data["sentinel_token"] = s.token;
    data["canary_fn"] = s.canary_fn;
    if (!r.ok && is_browser_infrastructure_error(r.error))
        return tool_result_t::error(r.error.empty() ? std::string("DOM-XSS browser execution failed") : r.error);
    return tool_result_t::ok(data);
}

tool_result_t tool_scan(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "dom_xss_scan entry params_shape=%s", json_shape(params).c_str());
    if (!params.is_object()) {
        diag::log_tagged_fmt("mcp_burp", "dom_xss_scan invalid_params");
        return tool_result_t::error("expected object params");
    }
    if (!params.contains("target_url") || !params["target_url"].is_string()) {
        diag::log_tagged_fmt("mcp_burp", "dom_xss_scan missing target_url");
        return tool_result_t::error("missing 'target_url'");
    }

    const std::string target_url = params["target_url"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "dom_xss_scan request url_len=%zu has_raw=%d has_raw_b64=%d",
        target_url.size(), (int)params.contains("raw_request"), (int)params.contains("raw_request_b64"));
    if (!camoufox::ensure_ready()) {
        auto st = camoufox::get_status();
        std::string err = st.last_error.empty() ? camoufox::last_error() : st.last_error;
        diag::log_tagged_fmt("mcp_burp", "dom_xss_scan bridge_not_ready state=%d errors=%llu last_error_len=%zu",
            static_cast<int>(st.state), static_cast<unsigned long long>(st.total_errors), st.last_error.size());
        return tool_result_t::error(err.empty() ? std::string("camoufox bridge not ready") : err);
    }
    if (!scope::in_scope(target_url)) {
        diag::log_tagged_fmt("mcp_burp", "dom_xss_scan out_of_scope url_len=%zu", target_url.size());
        return tool_result_t::error("target out of scope");
    }

    std::string scheme, host, path;
    uint16_t port = 0;
    if (!audit_http::parse_url(target_url, scheme, host, port, path))
    {
        diag::log_tagged_fmt("mcp_burp", "dom_xss_scan invalid_url url_len=%zu", target_url.size());
        return tool_result_t::error("invalid target_url");
    }
    const std::string safe_path = path_without_query(path);
    diag::log_tagged_fmt("mcp_burp", "dom_xss_scan parsed scheme=%s host=%s port=%u path=%s query=%d",
        scheme.c_str(), host.c_str(), static_cast<unsigned>(port), safe_path.c_str(), (int)(path.find('?') != std::string::npos));

    std::vector<uint8_t> raw_request;
    if (params.contains("raw_request_b64") && params["raw_request_b64"].is_string()) {
        const std::string& raw_b64 = params["raw_request_b64"].get_ref<const std::string&>();
        raw_request = base64_decode(raw_b64);
        if (raw_request.empty()) {
            diag::log_tagged_fmt("mcp_burp", "dom_xss_scan raw_b64_decode_failed b64_len=%zu", raw_b64.size());
            return tool_result_t::error("raw_request_b64 invalid base64");
        }
        ensure_double_crlf_terminated(raw_request);
        diag::log_tagged_fmt("mcp_burp", "dom_xss_scan raw_request_from_b64 b64_len=%zu raw_len=%zu", raw_b64.size(), raw_request.size());
    } else if (params.contains("raw_request") && params["raw_request"].is_string()) {
        const auto& s = params["raw_request"].get_ref<const std::string&>();
        raw_request.assign(s.begin(), s.end());
        ensure_double_crlf_terminated(raw_request);
        diag::log_tagged_fmt("mcp_burp", "dom_xss_scan raw_request_from_text raw_len=%zu", raw_request.size());
    } else {
        raw_request = synthesize_get_request(path, host);
        diag::log_tagged_fmt("mcp_burp", "dom_xss_scan synthesized_get raw_len=%zu", raw_request.size());
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
    int scan_timeout_ms = 120000;
    if (params.contains("scan_timeout_ms") && params["scan_timeout_ms"].is_number_integer())
        scan_timeout_ms = params["scan_timeout_ms"].get<int>();
    else if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer())
        scan_timeout_ms = params["timeout_ms"].get<int>();
    if (scan_timeout_ms < 5000) scan_timeout_ms = 5000;
    if (scan_timeout_ms > 300000) scan_timeout_ms = 300000;
    opts.deadline_ms = now_ms_steady() + static_cast<uint64_t>(scan_timeout_ms);
    opts.abort_on_browser_error = true;
    opts.max_browser_failures = 1;
    opts.scheme = scheme;
    opts.host   = host;
    opts.port   = port;
    diag::log_tagged_fmt("mcp_burp", "dom_xss_scan options polyglot=%d standard=%d dom_only=%d screenshots=%d per_timeout_ms=%d max_payloads=%zu scan_timeout_ms=%d raw_len=%zu",
        (int)opts.include_polyglot, (int)opts.include_standard, (int)opts.include_dom_only,
        (int)opts.capture_screenshots, opts.per_payload_timeout_ms, opts.max_payloads_per_point, scan_timeout_ms, raw_request.size());

    auto points = insertion_points::analyze(raw_request, target_url);
    diag::log_tagged_fmt("mcp_burp", "dom_xss_scan insertion_points total=%zu host=%s path=%s", points.size(), host.c_str(), safe_path.c_str());
    size_t total_emitted = 0;
    json per_point = json::array();
    for (const auto& ip : points) {
        if (ip.kind != "query" && ip.kind != "path" &&
            ip.kind != "body_form" && ip.kind != "body_json" &&
            ip.kind != "header" && ip.kind != "cookie") continue;
        size_t emitted = 0;
        try {
            emitted = dom_xss::scan_insertion_point(ip, opts);
        } catch (const std::exception& ex) {
            last_scan_ms_slot().store(now_ms_wall());
            total_scans_slot().fetch_add(1);
            diag::log_tagged_critical_fmt("mcp_burp", "dom_xss_scan exception host=%s path=%s kind=%s param=%s err=%s",
                host.c_str(), safe_path.c_str(), ip.kind.c_str(), ip.name.c_str(), ex.what());
            return tool_result_t::error(std::string("DOM-XSS scan exception: ") + ex.what());
        } catch (...) {
            last_scan_ms_slot().store(now_ms_wall());
            total_scans_slot().fetch_add(1);
            diag::log_tagged_critical_fmt("mcp_burp", "dom_xss_scan exception host=%s path=%s kind=%s param=%s err=unknown",
                host.c_str(), safe_path.c_str(), ip.kind.c_str(), ip.name.c_str());
            return tool_result_t::error("DOM-XSS scan exception: unknown");
        }
        total_emitted += emitted;
        total_payloads_slot().fetch_add(opts.max_payloads_per_point);
        std::string point_error = dom_xss::last_error();
        json e;
        e["kind"] = ip.kind;
        e["name"] = ip.name;
        e["emitted"] = emitted;
        e["error"] = point_error;
        per_point.push_back(std::move(e));
        if (!point_error.empty() && is_browser_infrastructure_error(point_error)) {
            last_scan_ms_slot().store(now_ms_wall());
            total_scans_slot().fetch_add(1);
            diag::log_tagged_fmt("mcp_burp", "dom_xss_scan abort host=%s path=%s points_scanned=%zu issues_emitted=%zu error=%s",
                host.c_str(), safe_path.c_str(), per_point.size(), total_emitted, point_error.c_str());
            return tool_result_t::error(point_error);
        }
    }
    last_scan_ms_slot().store(now_ms_wall());
    total_scans_slot().fetch_add(1);

    json data;
    data["target_url"]    = target_url;
    data["points_total"]  = points.size();
    data["points_scanned"] = per_point.size();
    data["per_point"]     = per_point;
    data["issues_emitted"] = total_emitted;
    std::string engine_error = dom_xss::last_error();
    data["last_engine_error"] = engine_error;
    diag::log_tagged_fmt("mcp_burp", "dom_xss_scan ok host=%s path=%s points_total=%zu points_scanned=%zu issues_emitted=%zu engine_error_len=%zu response_shape=%s",
        host.c_str(), safe_path.c_str(), points.size(), per_point.size(), total_emitted,
        engine_error.size(), json_shape(data).c_str());
    if (!engine_error.empty() && is_browser_infrastructure_error(engine_error))
        return tool_result_t::error(engine_error);
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
            {"per_payload_timeout_ms",  "number",  "Per-payload navigation/eval timeout in milliseconds (1000-30000, default 8000).", false},
            {"scan_timeout_ms",         "number",  "Total scan deadline in milliseconds (5000-300000, default 120000).", false},
            {"timeout_ms",              "number",  "Alias for scan_timeout_ms.", false}
        },
        tool_scan, false
    });

    diag::log_tagged("dom_xss", "dom_xss_mcp registered 3 tools");
}

}
}
