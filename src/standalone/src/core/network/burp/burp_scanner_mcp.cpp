#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_scanner_mcp.hpp"

#include "active_scanner.hpp"
#include "audit_http.hpp"
#include "issue.hpp"
#include "passive_scanner.hpp"
#include "scanner_module.hpp"

#include "../../settings/standalone_compat.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

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

bool extract_request_payload(const json& params, std::vector<uint8_t>& out_raw, std::string& err)
{
    if (params.contains("raw_request_b64") && params["raw_request_b64"].is_string()) {
        auto dec = base64_decode(params["raw_request_b64"].get<std::string>());
        if (dec.empty()) { err = "raw_request_b64 invalid base64"; return false; }
        out_raw = std::move(dec);
        return true;
    }
    if (params.contains("raw_request") && params["raw_request"].is_string()) {
        const std::string& s = params["raw_request"].get_ref<const std::string&>();
        out_raw.assign(s.begin(), s.end());
        return true;
    }
    err = "missing raw_request or raw_request_b64";
    return false;
}

size_t issue_count_for_audit(uint64_t audit_id)
{
    issue_store::initialize();
    issue_filter_t filter;
    filter.has_audit_id = true;
    filter.audit_id = audit_id;
    return issue_store::list(filter).size();
}

tool_result_t tool_start_audit(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "tool_start_audit url=%s", p.contains("url") && p["url"].is_string() ? p["url"].get<std::string>().c_str() : "<missing>");
    if (!p.contains("url") || !p["url"].is_string()) return tool_result_t::error("missing 'url'");
    std::vector<uint8_t> raw;
    std::string err;
    if (!extract_request_payload(p, raw, err)) { diag::log_tagged_fmt("mcp_burp", "tool_start_audit payload_error=%s", err.c_str()); return tool_result_t::error(err); }
    if (raw.size() >= 2) {
        bool ends_dcrlf = (raw.size() >= 4 &&
                          raw[raw.size() - 4] == '\r' && raw[raw.size() - 3] == '\n' &&
                          raw[raw.size() - 2] == '\r' && raw[raw.size() - 1] == '\n');
        if (!ends_dcrlf) {
            raw.push_back('\r'); raw.push_back('\n');
            raw.push_back('\r'); raw.push_back('\n');
        }
    }
    active_scanner::audit_config_t cfg;
    if (p.contains("modules") && p["modules"].is_array()) {
        for (const auto& m : p["modules"]) if (m.is_string()) cfg.enabled_modules.push_back(m.get<std::string>());
    }
    if (p.contains("scope_only") && p["scope_only"].is_boolean()) cfg.scope_only = p["scope_only"].get<bool>();
    if (p.contains("follow_redirects") && p["follow_redirects"].is_boolean()) cfg.follow_redirects = p["follow_redirects"].get<bool>();
    if (p.contains("timeout_ms") && p["timeout_ms"].is_number_integer()) cfg.timeout_ms = p["timeout_ms"].get<int>();
    if (p.contains("max_concurrent") && p["max_concurrent"].is_number_unsigned())
        cfg.max_concurrent_requests = p["max_concurrent"].get<size_t>();
    if (p.contains("throttle_ms") && p["throttle_ms"].is_number_unsigned())
        cfg.request_throttle_ms = p["throttle_ms"].get<size_t>();
    if (p.contains("per_module_cap") && p["per_module_cap"].is_number_unsigned())
        cfg.per_module_request_cap = p["per_module_cap"].get<size_t>();

    auto id = active_scanner::enqueue_target(raw, p["url"].get<std::string>(), cfg);
    if (id == 0) { diag::log_tagged_fmt("mcp_burp", "tool_start_audit enqueue_failed err=%s", active_scanner::last_error().c_str()); return tool_result_t::error(active_scanner::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "tool_start_audit ok audit_id=%llu", static_cast<unsigned long long>(id));
    json data;
    data["audit_id"] = id;
    return tool_result_t::ok(std::string("Audit started: ") + std::to_string(id), data);
}

tool_result_t tool_audit_status(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "tool_audit_status audit_id=%llu", p.contains("audit_id") && p["audit_id"].is_number_unsigned() ? static_cast<unsigned long long>(p["audit_id"].get<uint64_t>()) : 0ULL);
    if (!p.contains("audit_id") || !p["audit_id"].is_number_unsigned())
        return tool_result_t::error("missing 'audit_id'");
    uint64_t id = p["audit_id"].get<uint64_t>();
    active_scanner::audit_status_t st;
    if (!active_scanner::get_status(id, st)) { diag::log_tagged_fmt("mcp_burp", "tool_audit_status not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("audit not found"); }
    const size_t stored_issues = issue_count_for_audit(id);
    const size_t issues_found = std::max(st.issues_found, stored_issues);
    json data;
    data["id"] = st.id;
    data["url"] = st.url;
    data["host"] = st.host;
    data["port"] = st.port;
    data["tls"] = st.tls;
    data["total_points"] = st.total_points;
    data["total_probes"] = st.total_probes;
    data["completed_probes"] = st.completed_probes;
    data["issues_found"] = issues_found;
    data["running"] = st.running;
    data["cancelled"] = st.cancelled;
    data["started_ms"] = st.started_ms;
    data["ended_ms"] = st.ended_ms;
    diag::log_tagged_fmt("mcp_burp", "tool_audit_status ok id=%llu running=%d runtime_issues=%zu stored_issues=%zu reported_issues=%zu", static_cast<unsigned long long>(id), (int)st.running, st.issues_found, stored_issues, issues_found);
    return tool_result_t::ok(data);
}

tool_result_t tool_list_audits(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "tool_list_audits entry");
    auto v = active_scanner::list_audits();
    json arr = json::array();
    for (const auto& st : v) {
        const size_t stored_issues = issue_count_for_audit(st.id);
        const size_t issues_found = std::max(st.issues_found, stored_issues);
        json e;
        e["id"] = st.id;
        e["url"] = st.url;
        e["host"] = st.host;
        e["port"] = st.port;
        e["tls"] = st.tls;
        e["total_probes"] = st.total_probes;
        e["completed_probes"] = st.completed_probes;
        e["issues_found"] = issues_found;
        e["running"] = st.running;
        e["cancelled"] = st.cancelled;
        e["started_ms"] = st.started_ms;
        e["ended_ms"] = st.ended_ms;
        arr.push_back(std::move(e));
    }
    json data;
    data["count"] = arr.size();
    data["audits"] = std::move(arr);
    diag::log_tagged_fmt("mcp_burp", "tool_list_audits ok count=%zu", v.size());
    return tool_result_t::ok(data);
}

tool_result_t tool_cancel(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "tool_cancel audit_id=%llu", p.contains("audit_id") && p["audit_id"].is_number_unsigned() ? static_cast<unsigned long long>(p["audit_id"].get<uint64_t>()) : 0ULL);
    if (!p.contains("audit_id") || !p["audit_id"].is_number_unsigned())
        return tool_result_t::error("missing 'audit_id'");
    uint64_t id = p["audit_id"].get<uint64_t>();
    if (!active_scanner::cancel_audit(id)) { diag::log_tagged_fmt("mcp_burp", "tool_cancel not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("audit not found"); }
    const bool drained = active_scanner::wait_for_audit_idle(id, 20000);
    diag::log_tagged_fmt("mcp_burp", "tool_cancel ok id=%llu drained=%d", static_cast<unsigned long long>(id), drained ? 1 : 0);
    json data; data["audit_id"] = id; data["cancelled"] = true; data["drained"] = drained;
    return tool_result_t::ok(std::string("Cancelled audit ") + std::to_string(id), data);
}

tool_result_t tool_list_issues(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "tool_list_issues entry");
    issue_filter_t f;
    if (p.contains("severity_min") && p["severity_min"].is_string()) {
        severity_t sv; if (parse_severity(p["severity_min"].get<std::string>(), sv)) {
            f.has_severity_min = true; f.severity_min = sv;
        }
    }
    if (p.contains("confidence_min") && p["confidence_min"].is_string()) {
        confidence_t cf; if (parse_confidence(p["confidence_min"].get<std::string>(), cf)) {
            f.has_confidence_min = true; f.confidence_min = cf;
        }
    }
    if (p.contains("host") && p["host"].is_string()) f.host_substring = p["host"].get<std::string>();
    if (p.contains("type") && p["type"].is_string()) f.type_key_substring = p["type"].get<std::string>();
    if (p.contains("audit_id") && p["audit_id"].is_number_unsigned()) {
        f.has_audit_id = true; f.audit_id = p["audit_id"].get<uint64_t>();
    }
    if (p.contains("limit") && p["limit"].is_number_unsigned()) f.limit = p["limit"].get<size_t>();
    json data = issue_store::export_json(f);
    diag::log_tagged_fmt("mcp_burp", "tool_list_issues ok");
    return tool_result_t::ok(data);
}

tool_result_t tool_get_issue(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "tool_get_issue issue_id=%llu", p.contains("issue_id") && p["issue_id"].is_number_unsigned() ? static_cast<unsigned long long>(p["issue_id"].get<uint64_t>()) : 0ULL);
    if (!p.contains("issue_id") || !p["issue_id"].is_number_unsigned())
        return tool_result_t::error("missing 'issue_id'");
    uint64_t id = p["issue_id"].get<uint64_t>();
    issue_t it;
    if (!issue_store::get(id, it)) { diag::log_tagged_fmt("mcp_burp", "tool_get_issue not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("issue not found"); }
    diag::log_tagged_fmt("mcp_burp", "tool_get_issue ok id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok(issue_store::issue_to_json(it));
}

tool_result_t tool_passive_status(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "tool_passive_status entry");
    auto st = passive_scanner::get_stats();
    json data;
    data["enabled"] = passive_scanner::is_enabled();
    data["exchanges_scanned"] = st.exchanges_scanned;
    data["issues_found"] = st.issues_found;
    data["last_scan_ms"] = st.last_scan_ms;
    diag::log_tagged_fmt("mcp_burp", "tool_passive_status ok enabled=%d scanned=%zu issues=%zu", (int)passive_scanner::is_enabled(), st.exchanges_scanned, st.issues_found);
    return tool_result_t::ok(data);
}

tool_result_t tool_list_modules(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "tool_list_modules entry");
    auto v = scanner::all_modules();
    json arr = json::array();
    for (const auto& m : v) {
        json e;
        e["id"] = m.id;
        e["name"] = m.name;
        e["category"] = m.category;
        e["max_probes_per_point"] = m.max_probes_per_point;
        arr.push_back(std::move(e));
    }
    json data;
    data["count"] = arr.size();
    data["modules"] = std::move(arr);
    diag::log_tagged_fmt("mcp_burp", "tool_list_modules ok count=%zu", v.size());
    return tool_result_t::ok(data);
}

tool_result_t tool_clear_issues(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "tool_clear_issues entry");
    size_t n = issue_store::count();
    issue_store::clear();
    diag::log_tagged_fmt("mcp_burp", "tool_clear_issues ok cleared=%zu", n);
    json data; data["cleared"] = n;
    return tool_result_t::ok(std::string("Cleared ") + std::to_string(n) + std::string(" issues"), data);
}

tool_result_t tool_passive_enable(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "tool_passive_enable enabled=%d", p.contains("enabled") && p["enabled"].is_boolean() ? (int)p["enabled"].get<bool>() : -1);
    if (!p.contains("enabled") || !p["enabled"].is_boolean())
        return tool_result_t::error("missing 'enabled' boolean");
    passive_scanner::set_enabled(p["enabled"].get<bool>());
    json data; data["enabled"] = passive_scanner::is_enabled();
    diag::log_tagged_fmt("mcp_burp", "tool_passive_enable ok enabled=%d", (int)passive_scanner::is_enabled());
    return tool_result_t::ok(data);
}

}

void register_scanner_tools(mcp_standalone::server_t& srv)
{
    active_scanner::initialize();
    passive_scanner::initialize();
    issue_store::initialize();

    register_compat(srv, {
        "burp_scanner_manage", "scanner",
        "Manage Burp-style active/passive scanning and issue storage. Actions: start_audit, audit_status, list_audits, cancel, list_issues, get_issue, clear_issues, passive_status, list_modules, passive_enable.",
        {{"action", "string", "start_audit|audit_status|list_audits|cancel|list_issues|get_issue|clear_issues|passive_status|list_modules|passive_enable", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "start_audit") return tool_start_audit(p);
            if (action == "audit_status") return tool_audit_status(p);
            if (action == "list_audits") return tool_list_audits(p);
            if (action == "cancel") return tool_cancel(p);
            if (action == "list_issues") return tool_list_issues(p);
            if (action == "get_issue") return tool_get_issue(p);
            if (action == "clear_issues") return tool_clear_issues(p);
            if (action == "passive_status") return tool_passive_status(p);
            if (action == "list_modules") return tool_list_modules(p);
            if (action == "passive_enable") return tool_passive_enable(p);
            return compat_unknown_action("burp_scanner_manage", action);
        },
        false
    });

    diag::log_tagged_fmt("burp", "burp_scanner_mcp registered %zu tools (modules=%zu)",
        static_cast<size_t>(1), scanner::count());
}

}
}
