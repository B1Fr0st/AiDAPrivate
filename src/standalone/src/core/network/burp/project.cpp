#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "project.hpp"

#include "active_scanner.hpp"
#include "burp_logger.hpp"
#include "collaborator.hpp"
#include "cookie_jar.hpp"
#include "crawl_audit.hpp"
#include "crawler.hpp"
#include "issue.hpp"
#include "match_replace.hpp"
#include "repeater.hpp"
#include "scope.hpp"
#include "session_handler.hpp"
#include "site_map.hpp"

#include "../../settings/standalone_compat.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace project {

namespace {

using json = nlohmann::json;

std::mutex& err_mtx()
{
    static std::mutex m;
    return m;
}

std::string& err_slot()
{
    static std::string e;
    return e;
}

void set_err(const std::string& e)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = e;
}

uint64_t now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string base64_encode(const std::vector<uint8_t>& data)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 2 < data.size()) {
        const uint32_t v = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8) | static_cast<uint32_t>(data[i + 2]);
        out.push_back(tbl[(v >> 18) & 0x3f]);
        out.push_back(tbl[(v >> 12) & 0x3f]);
        out.push_back(tbl[(v >> 6) & 0x3f]);
        out.push_back(tbl[v & 0x3f]);
        i += 3;
    }
    if (i < data.size()) {
        const size_t rem = data.size() - i;
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        if (rem > 1) v |= static_cast<uint32_t>(data[i + 1]) << 8;
        out.push_back(tbl[(v >> 18) & 0x3f]);
        out.push_back(tbl[(v >> 12) & 0x3f]);
        out.push_back(rem > 1 ? tbl[(v >> 6) & 0x3f] : '=');
        out.push_back('=');
    }
    return out;
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
    uint32_t buf = 0;
    int bits = 0;
    for (unsigned char c : s) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        int v = tbl[c];
        if (v == -1) return {};
        if (v == -2) break;
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xff));
        }
    }
    return out;
}

json cookie_to_json(const cookie_jar::parsed_cookie_t& c)
{
    return {
        {"host_key", c.domain},
        {"name", c.name},
        {"value", c.value},
        {"domain", c.domain},
        {"path", c.path},
        {"expires_unix_ms", c.expires_unix_ms},
        {"has_expires", c.has_expires},
        {"secure", c.secure},
        {"http_only", c.http_only},
        {"host_only", c.host_only},
        {"same_site", cookie_jar::same_site_str(c.same_site)},
        {"created_unix_ms", c.created_unix_ms}
    };
}

bool cookie_from_json(const json& j, std::string& host_key, cookie_jar::parsed_cookie_t& c)
{
    if (!j.is_object()) return false;
    c = cookie_jar::parsed_cookie_t{};
    host_key = j.value("host_key", std::string());
    c.name = j.value("name", std::string());
    c.value = j.value("value", std::string());
    c.domain = j.value("domain", host_key);
    c.path = j.value("path", std::string("/"));
    c.expires_unix_ms = j.value("expires_unix_ms", static_cast<int64_t>(0));
    c.has_expires = j.value("has_expires", false);
    c.secure = j.value("secure", false);
    c.http_only = j.value("http_only", false);
    c.host_only = j.value("host_only", false);
    c.same_site = cookie_jar::parse_same_site(j.value("same_site", std::string()));
    c.created_unix_ms = j.value("created_unix_ms", static_cast<int64_t>(0));
    if (host_key.empty()) host_key = c.domain;
    return !host_key.empty() && !c.name.empty();
}

json headers_to_json(const std::vector<std::pair<std::string, std::string>>& headers)
{
    json arr = json::array();
    for (const auto& h : headers) arr.push_back({{"name", h.first}, {"value", h.second}});
    return arr;
}

std::vector<std::pair<std::string, std::string>> headers_from_json(const json& arr)
{
    std::vector<std::pair<std::string, std::string>> out;
    if (!arr.is_array()) return out;
    for (const auto& h : arr) {
        if (!h.is_object()) continue;
        out.emplace_back(h.value("name", std::string()), h.value("value", std::string()));
    }
    return out;
}

json exchange_to_project_json(const exchange_observed_t& e)
{
    json j = sitemap::exchange_to_json(e, false);
    j["request_body_base64"] = base64_encode(e.req_body);
    j["response_body_base64"] = base64_encode(e.resp_body);
    return j;
}

bool exchange_from_json(const json& j, exchange_observed_t& e)
{
    if (!j.is_object()) return false;
    e = exchange_observed_t{};
    e.id = j.value("id", static_cast<uint64_t>(0));
    e.timestamp_ms = j.value("timestamp_ms", static_cast<uint64_t>(0));
    e.method = j.value("method", std::string());
    e.scheme = j.value("scheme", std::string());
    e.host = j.value("host", std::string());
    e.port = static_cast<uint16_t>((std::min)(j.value("port", 0), 65535));
    e.path = j.value("path", std::string());
    e.query = j.value("query", std::string());
    e.status_code = j.value("status_code", 0);
    e.reason_phrase = j.value("reason", std::string());
    e.req_headers = headers_from_json(j.value("request_headers", json::array()));
    e.resp_headers = headers_from_json(j.value("response_headers", json::array()));
    e.req_body = base64_decode(j.value("request_body_base64", std::string()));
    e.resp_body = base64_decode(j.value("response_body_base64", std::string()));
    e.latency_ms = j.value("latency_ms", static_cast<uint64_t>(0));
    e.is_websocket = j.value("is_websocket", false);
    e.is_h2 = j.value("is_h2", false);
    e.tls_version = j.value("tls_version", std::string());
    e.alpn = j.value("alpn", std::string());
    e.client_addr = j.value("client_addr", std::string());
    e.client_port = static_cast<uint16_t>((std::min)(j.value("client_port", 0), 65535));
    e.source = j.value("source", std::string());
    return !e.host.empty() && !e.scheme.empty();
}

json audit_status_to_json(const active_scanner::audit_status_t& st)
{
    return {
        {"id", st.id},
        {"url", st.url},
        {"host", st.host},
        {"port", st.port},
        {"tls", st.tls},
        {"total_points", st.total_points},
        {"total_probes", st.total_probes},
        {"completed_probes", st.completed_probes},
        {"issues_found", st.issues_found},
        {"running", st.running},
        {"cancelled", st.cancelled},
        {"cancel_requested", st.cancel_requested},
        {"drained", st.drained},
        {"started_ms", st.started_ms},
        {"ended_ms", st.ended_ms},
        {"request_length", st.request_length},
        {"queued_workers", st.queued_workers},
        {"active_workers", st.active_workers},
        {"in_flight_requests", st.in_flight_requests},
        {"responses_received", st.responses_received},
        {"no_response_count", st.no_response_count},
        {"transport_failures", st.transport_failures},
        {"last_transport_error", st.last_transport_error},
        {"transport_error_code", st.transport_error_code},
        {"transport_error_class", st.transport_error_class}
    };
}

json crawler_status_to_json(const crawler::crawl_status_t& st)
{
    json discovered = json::array();
    for (const auto& d : st.discovered) {
        discovered.push_back({
            {"url", d.url},
            {"status", d.status},
            {"body_bytes", d.body_bytes},
            {"content_type", d.content_type},
            {"depth", d.depth},
            {"source_url", d.source_url},
            {"fetched_unix_ms", d.fetched_unix_ms}
        });
    }
    return {
        {"id", st.id},
        {"queue_depth", st.queue_depth},
        {"pages_visited", st.pages_visited},
        {"pages_failed", st.pages_failed},
        {"urls_found", st.urls_found},
        {"started_unix_ms", st.started_unix_ms},
        {"finished_unix_ms", st.finished_unix_ms},
        {"last_progress_unix_ms", st.last_progress_unix_ms},
        {"pages_per_sec", st.pages_per_sec},
        {"in_flight", st.in_flight},
        {"last_url", st.last_url},
        {"last_error", st.last_error},
        {"discovered", std::move(discovered)},
        {"log", st.log}
    };
}

bool import_scope(const json& section)
{
    if (!section.is_object()) return true;
    scope::clear_all();
    const json rules = section.value("rules", json::array());
    if (!rules.is_array()) return false;
    for (const auto& jr : rules) {
        scope::rule_t r;
        if (scope::rule_from_json(jr, r)) scope::add_rule(r);
    }
    return true;
}

bool import_cookies(const json& section)
{
    const json arr = section.is_object() ? section.value("cookies", json::array()) : section;
    if (!arr.is_array()) return false;
    cookie_jar::clear_all();
    for (const auto& jc : arr) {
        std::string host;
        cookie_jar::parsed_cookie_t c;
        if (cookie_from_json(jc, host, c)) cookie_jar::set_cookie(host, c);
    }
    return true;
}

bool import_site_map(const json& section)
{
    if (!section.is_object()) return true;
    const json arr = section.value("exchanges", json::array());
    if (!arr.is_array()) return false;
    std::vector<exchange_observed_t> exchanges;
    for (const auto& je : arr) {
        exchange_observed_t e;
        if (exchange_from_json(je, e)) exchanges.push_back(std::move(e));
    }
    return sitemap::import_exchanges(exchanges, true);
}

bool import_logger(const json& section)
{
    if (!section.is_object()) return true;
    const json arr = section.value("rows", json::array());
    if (!arr.is_array()) return false;
    std::vector<logger::log_row_t> rows;
    for (const auto& jr : arr) {
        logger::log_row_t row;
        if (logger::row_from_json(jr, row)) rows.push_back(row);
    }
    return logger::import_rows(rows, true);
}

}

bool initialize()
{
    return true;
}

void shutdown()
{
}

nlohmann::json export_json()
{
    json root;
    root["version"] = 1;
    root["saved_unix_ms"] = now_ms();

    json scope_rules = json::array();
    for (const auto& r : scope::list_rules()) scope_rules.push_back(scope::rule_to_json(r));
    root["scope"] = {{"rules", std::move(scope_rules)}};

    json cookies = json::array();
    for (const auto& c : cookie_jar::list_all()) cookies.push_back(cookie_to_json(c));
    root["cookies"] = {{"cookies", std::move(cookies)}};

    root["match_replace"] = {{"rules", match_replace::export_json()}};
    root["session"] = session_handler::export_json();
    root["repeater"] = repeater::export_json();

    issue_filter_t issue_filter;
    root["issues"] = issue_store::export_json(issue_filter);

    json exchanges = json::array();
    for (const auto& e : sitemap::list_all_exchanges()) exchanges.push_back(exchange_to_project_json(e));
    root["site_map"] = {{"exchanges", std::move(exchanges)}};

    logger::log_filter_t log_filter;
    auto rows = logger::query(log_filter, 0);
    std::reverse(rows.begin(), rows.end());
    json log_rows = json::array();
    for (const auto& row : rows) log_rows.push_back(logger::row_to_json(row));
    root["logger"] = {{"rows", std::move(log_rows)}, {"capacity", logger::capacity()}};

    json audits = json::array();
    for (const auto& audit : active_scanner::list_audits()) audits.push_back(audit_status_to_json(audit));
    root["scanner"] = {{"audits", std::move(audits)}, {"load", {{"active_audits", active_scanner::load_snapshot().active_audits}}}};

    json crawls = json::array();
    for (const auto& crawl : crawler::list()) crawls.push_back(crawler_status_to_json(crawl));
    root["crawler"] = {{"crawls", std::move(crawls)}};

    root["crawl_audit"] = crawl_audit::export_json();
    root["collaborator"] = collaborator::export_json();
    return root;
}

bool import_json(const nlohmann::json& doc, bool replace_existing)
{
    if (!doc.is_object() || doc.value("version", 0) < 1) {
        set_err("project.import: invalid project schema");
        return false;
    }
    bool ok = true;
    if (replace_existing) {
        for (const auto& audit : active_scanner::list_audits()) active_scanner::cancel_audit(audit.id);
        for (const auto& crawl : crawler::list()) crawler::stop(crawl.id);
    }
    if (doc.contains("scope")) ok = import_scope(doc["scope"]) && ok;
    if (doc.contains("cookies")) ok = import_cookies(doc["cookies"]) && ok;
    if (doc.contains("match_replace")) {
        const json rules = doc["match_replace"].is_object() ? doc["match_replace"].value("rules", json::array()) : doc["match_replace"];
        ok = match_replace::import_json(rules, replace_existing) && ok;
    }
    if (doc.contains("session")) ok = session_handler::import_json(doc["session"], replace_existing) && ok;
    if (doc.contains("repeater")) ok = repeater::import_json(doc["repeater"], replace_existing) && ok;
    if (doc.contains("issues")) ok = issue_store::import_json(doc["issues"], replace_existing) && ok;
    if (doc.contains("site_map")) ok = import_site_map(doc["site_map"]) && ok;
    if (doc.contains("logger")) ok = import_logger(doc["logger"]) && ok;
    if (doc.contains("crawl_audit")) {
        ok = crawl_audit::import_json(doc["crawl_audit"], replace_existing) && ok;
    } else if (replace_existing) {
        ok = crawl_audit::import_json({{"version", 1}, {"pipelines", json::array()}}, true) && ok;
    }
    if (doc.contains("collaborator")) ok = collaborator::import_json(doc["collaborator"], replace_existing) && ok;
    if (!ok) set_err("project.import: one or more sections failed");
    return ok;
}

bool save_to_file(const std::string& path)
{
    if (path.empty()) {
        set_err("project.save: empty path");
        return false;
    }
    std::filesystem::path fs_path(path);
    std::error_code ec;
    if (!fs_path.parent_path().empty()) std::filesystem::create_directories(fs_path.parent_path(), ec);
    if (ec) {
        set_err("project.save: create parent failed: " + ec.message());
        return false;
    }
    const std::string tmp = path + ".tmp";
    const std::string dump = export_json().dump(2);
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            set_err("project.save: open failed");
            return false;
        }
        out.write(dump.data(), static_cast<std::streamsize>(dump.size()));
        if (!out) {
            set_err("project.save: write failed");
            return false;
        }
    }
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(path, ec);
        ec.clear();
        std::filesystem::rename(tmp, path, ec);
        if (ec) {
            set_err("project.save: replace failed: " + ec.message());
            return false;
        }
    }
    diag::log_tagged_fmt("burp_project", "save ok path=%s bytes=%zu", path.c_str(), dump.size());
    return true;
}

bool load_from_file(const std::string& path, bool replace_existing)
{
    if (path.empty()) {
        set_err("project.load: empty path");
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        set_err("project.load: open failed");
        return false;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string raw = ss.str();
    json doc = json::parse(raw, nullptr, false);
    if (doc.is_discarded()) {
        set_err("project.load: parse failed");
        return false;
    }
    const bool ok = import_json(doc, replace_existing);
    diag::log_tagged_fmt("burp_project", "load path=%s bytes=%zu ok=%d replace=%d", path.c_str(), raw.size(), ok ? 1 : 0, replace_existing ? 1 : 0);
    return ok;
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    return err_slot();
}

void register_project_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_project_manage", "burp",
        "Save, load, export, and import the Burp project model including target scope, cookies, session state, repeater tabs, issues, traffic, logger rows, crawl-audit state, and collaborator state.",
        {{"action", "string", "export|import|save|load|status", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> mcp_standalone::tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "export") {
                return mcp_standalone::tool_result_t::ok(export_json());
            }
            if (action == "import") {
                if (!p.contains("project") || !p["project"].is_object())
                    return mcp_standalone::tool_result_t::error("project object required");
                const bool replace_existing = p.value("replace_existing", true);
                if (!import_json(p["project"], replace_existing))
                    return mcp_standalone::tool_result_t::error(last_error());
                json out;
                out["replace_existing"] = replace_existing;
                out["status"] = "imported";
                out["project"] = export_json();
                return mcp_standalone::tool_result_t::ok("project imported", out);
            }
            if (action == "save") {
                if (!p.contains("path") || !p["path"].is_string() || p["path"].get<std::string>().empty())
                    return mcp_standalone::tool_result_t::error("path parameter required");
                const std::string path = p["path"].get<std::string>();
                if (!save_to_file(path))
                    return mcp_standalone::tool_result_t::error(last_error());
                json out;
                out["path"] = path;
                out["status"] = "saved";
                out["saved_unix_ms"] = now_ms();
                return mcp_standalone::tool_result_t::ok("project saved", out);
            }
            if (action == "load") {
                if (!p.contains("path") || !p["path"].is_string() || p["path"].get<std::string>().empty())
                    return mcp_standalone::tool_result_t::error("path parameter required");
                const bool replace_existing = p.value("replace_existing", true);
                const std::string path = p["path"].get<std::string>();
                if (!load_from_file(path, replace_existing))
                    return mcp_standalone::tool_result_t::error(last_error());
                json out;
                out["path"] = path;
                out["replace_existing"] = replace_existing;
                out["status"] = "loaded";
                out["project"] = export_json();
                return mcp_standalone::tool_result_t::ok("project loaded", out);
            }
            if (action == "status") {
                json out;
                out["version"] = 1;
                out["last_error"] = last_error();
                out["section_count"] = export_json().size();
                out["collaborator_state"] = collaborator::export_json().value("capabilities", json::object());
                return mcp_standalone::tool_result_t::ok(out);
            }
            return compat_unknown_action("burp_project_manage", action);
        },
        false
    });
}

}
}
}
