#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_platform.hpp"
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#endif

#ifdef small
#undef small
#endif

#include "cookie_jar.hpp"
#include "burp_events.hpp"
#include "../network_view.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/ui_anim.hpp"
#include "../../ui/design_system.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/studio_semantics.hpp"
#endif
#include "../../infra/event_bus.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_executor.hpp"
#else
#include "../../infra/executor.hpp"
#endif
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_services.hpp"
#else
#include "helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cfloat>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <utility>

namespace aida {
namespace burp {
namespace cookie_jar {

namespace {

struct host_jar_t
{
    std::vector<parsed_cookie_t> cookies;
};

struct state_t
{
    std::mutex                          mtx;
    std::map<std::string, host_jar_t>   jars;
    std::atomic<bool>                   initialized{false};
    aida::events::subscription_handle_t exchange_sub;
    std::mutex                          err_mtx;
    std::string                         last_err;

    char                                filter_host[256] = {};
    int                                 selected_host_index = -1;
    int                                 selected_cookie_index = -1;
    bool                                show_edit = false;
    char                                edit_host[256] = {};
    char                                edit_name[128] = {};
    char                                edit_value[2048] = {};
    char                                edit_domain[256] = {};
    char                                edit_path[256] = {};
    char                                edit_expires[64] = {};
    bool                                edit_secure = false;
    bool                                edit_http_only = false;
    int                                 edit_same_site = 0;

    network_view::artifact_identity_t   reviewed_context;
    std::string                         reviewed_path;
    bool                                reviewed_context_current = false;
    int                                 reviewed_context_validation_frame = -120;
    std::string                         reviewed_context_reason;
};

state_t& s()
{
    static state_t st;
    return st;
}

#ifndef AIDA_IMGUI_STUDIO_PREVIEW
void set_err(const std::string& msg)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    st.last_err = msg;
}
#endif

std::string ascii_lower(const std::string& v)
{
    std::string r;
    r.reserve(v.size());
    for (char c : v) {
        if (c >= 'A' && c <= 'Z') r.push_back(static_cast<char>(c + 32));
        else                      r.push_back(c);
    }
    return r;
}

int64_t now_ms()
{
    return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

void trim(std::string& v)
{
    size_t b = 0;
    while (b < v.size() && (v[b] == ' ' || v[b] == '\t')) ++b;
    size_t e = v.size();
    while (e > b && (v[e - 1] == ' ' || v[e - 1] == '\t' || v[e - 1] == '\r' || v[e - 1] == '\n')) --e;
    v = v.substr(b, e - b);
}

int parse_int_field(const std::string& v, int def = 0)
{
    int out = 0;
    bool any = false;
    bool neg = false;
    size_t i = 0;
    if (!v.empty() && (v[0] == '-' || v[0] == '+')) { neg = (v[0] == '-'); i = 1; }
    for (; i < v.size(); ++i) {
        if (v[i] < '0' || v[i] > '9') break;
        out = out * 10 + (v[i] - '0');
        any = true;
    }
    if (!any) return def;
    return neg ? -out : out;
}

int64_t parse_int64_field(const std::string& v, int64_t def = 0)
{
    int64_t out = 0;
    bool any = false;
    bool neg = false;
    size_t i = 0;
    if (!v.empty() && (v[0] == '-' || v[0] == '+')) { neg = (v[0] == '-'); i = 1; }
    for (; i < v.size(); ++i) {
        if (v[i] < '0' || v[i] > '9') break;
        out = out * 10 + (v[i] - '0');
        any = true;
    }
    if (!any) return def;
    return neg ? -out : out;
}

int month_from_name(const std::string& m)
{
    static const char* names[] = {"jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"};
    std::string l = ascii_lower(m);
    for (int i = 0; i < 12; i++) if (l.compare(0, 3, names[i]) == 0) return i;
    return -1;
}

int64_t parse_http_date(const std::string& s_in)
{
    if (s_in.empty()) return 0;
    std::string normalized;
    normalized.reserve(s_in.size());
    for (char c : s_in) {
        if (c == ',' || c == '-' || c == '/' || c == ':' || c == 'T') normalized.push_back(' ');
        else                                                          normalized.push_back(c);
    }

    std::istringstream is(normalized);
    std::string tok;
    int day = 0, month = -1, year = 0, hour = 0, minute = 0, second = 0;
    while (is >> tok) {
        if (tok.size() == 3) {
            const int m = month_from_name(tok);
            if (m >= 0) { month = m; continue; }
        }
        if (tok.size() >= 4 && tok[0] >= '0' && tok[0] <= '9') {
            const int n = parse_int_field(tok);
            if (n >= 1900) { year = n; continue; }
        }
        if (tok.size() <= 2 && tok[0] >= '0' && tok[0] <= '9') {
            const int n = parse_int_field(tok);
            if (day == 0 && n >= 1 && n <= 31) { day = n; continue; }
        }
        if (tok.find_first_not_of("0123456789") == std::string::npos) {
            const int n = parse_int_field(tok);
            if (hour == 0 && n < 24) { hour = n; continue; }
            if (minute == 0 && n < 60) { minute = n; continue; }
            if (second == 0 && n < 60) { second = n; continue; }
        }
    }
    if (month < 0 || year == 0) return 0;

    std::tm tmv = {};
    tmv.tm_year = year - 1900;
    tmv.tm_mon  = month;
    tmv.tm_mday = day == 0 ? 1 : day;
    tmv.tm_hour = hour;
    tmv.tm_min  = minute;
    tmv.tm_sec  = second;

    const time_t local_t = _mkgmtime(&tmv);
    if (local_t == static_cast<time_t>(-1)) return 0;
    return static_cast<int64_t>(local_t) * 1000;
}

bool domain_matches(const std::string& cookie_domain, const std::string& request_host)
{
    if (cookie_domain.empty()) return false;
    std::string cd = ascii_lower(cookie_domain);
    if (!cd.empty() && cd[0] == '.') cd = cd.substr(1);
    const std::string rh = ascii_lower(request_host);
    if (cd == rh) return true;
    if (rh.size() > cd.size()) {
        const size_t off = rh.size() - cd.size();
        if (rh.compare(off, cd.size(), cd) == 0 && rh[off - 1] == '.') return true;
    }
    return false;
}

bool path_matches(const std::string& cookie_path, const std::string& request_path)
{
    if (cookie_path.empty() || cookie_path == "/") return true;
    if (request_path.size() < cookie_path.size()) return false;
    if (request_path.compare(0, cookie_path.size(), cookie_path) != 0) return false;
    if (request_path.size() == cookie_path.size()) return true;
    if (cookie_path.back() == '/') return true;
    if (request_path[cookie_path.size()] == '/') return true;
    return false;
}

void handle_exchange_observed(const exchange_observed_t& e)
{
    {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.cookie_jar";
        sub.label = "cookie_jar.observe_exchange";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::feature_worker;
        sub.priority = 3;
        sub.body = [e]() {
        ingest_set_cookie_headers(e.host, e.resp_headers);
    };
        (void)::aida::infra::executor::submit(std::move(sub));
    }
}

void refresh_reviewed_context(state_t& st)
{
    if (!st.reviewed_context.valid()) return;
    const int frame = ImGui::GetFrameCount();
    if (frame - st.reviewed_context_validation_frame < 120) return;
    st.reviewed_context_validation_frame = frame;
    network_view::artifact_snapshot_t snapshot;
    std::string reason;
    st.reviewed_context_current = network_view::resolve_artifact(
        st.reviewed_context, snapshot, reason);
    st.reviewed_context_reason = st.reviewed_context_current
        ? std::string() : (reason.empty() ? "The retained source is stale." : std::move(reason));
}

bool request_artifact_kind(network_view::artifact_kind_t kind)
{
    return kind == network_view::artifact_kind_t::exchange ||
        kind == network_view::artifact_kind_t::request ||
        kind == network_view::artifact_kind_t::repeater_request ||
        kind == network_view::artifact_kind_t::sitemap_request ||
        kind == network_view::artifact_kind_t::api_request ||
        kind == network_view::artifact_kind_t::scanner_request ||
        kind == network_view::artifact_kind_t::intercept_request;
}

}

bool stage_reviewed_context(const network_view::artifact_identity_t& identity,
                            const std::string& request_path,
                            std::string& unavailable_reason)
{
    if (!identity.valid() || !request_artifact_kind(identity.kind) ||
        identity.target_host.empty() || identity.target_port == 0 ||
        identity.target_host.size() >= sizeof(s().filter_host) || request_path.size() > 2048U ||
        identity.raw_protocol) {
        unavailable_reason = "Cookie Jar requires a current retained HTTP/1 target with bounded host and path metadata.";
        return false;
    }
    network_view::artifact_snapshot_t snapshot;
    if (!network_view::resolve_artifact(identity, snapshot, unavailable_reason)) return false;
    auto& st = s();
    st.reviewed_context = identity;
    st.reviewed_path = request_path.empty() ? "/" : request_path;
    st.reviewed_context_current = true;
    st.reviewed_context_validation_frame = ImGui::GetFrameCount();
    st.reviewed_context_reason.clear();
    std::memcpy(st.filter_host, identity.target_host.data(), identity.target_host.size());
    st.filter_host[identity.target_host.size()] = '\0';
    st.selected_host_index = -1;
    st.selected_cookie_index = -1;
    unavailable_reason.clear();
    return true;
}

std::string same_site_str(same_site_t s)
{
    switch (s) {
        case same_site_t::lax:    return "Lax";
        case same_site_t::strict: return "Strict";
        case same_site_t::none:   return "None";
        default:                  return "";
    }
}

same_site_t parse_same_site(const std::string& v)
{
    const std::string l = ascii_lower(v);
    if (l == "lax")    return same_site_t::lax;
    if (l == "strict") return same_site_t::strict;
    if (l == "none")   return same_site_t::none;
    return same_site_t::unset;
}

bool initialize()
{
    auto& st = s();
    bool expected = false;
    if (!st.initialized.compare_exchange_strong(expected, true)) return true;
    load_from_disk();
    st.exchange_sub = aida::events::subscribe(kExchangeObservedEvent,
        [](const exchange_observed_t& e) { handle_exchange_observed(e); });
    diag::log_tagged("burp", "cookie_jar_initialized");
    return true;
}

void shutdown()
{
    auto& st = s();
    if (!st.initialized.exchange(false)) return;
    if (st.exchange_sub.valid()) aida::events::unsubscribe(st.exchange_sub);
    save_to_disk();
}

bool parse_set_cookie(const std::string& set_cookie_value, const std::string& request_host, parsed_cookie_t& out)
{
    if (set_cookie_value.empty()) return false;
    out = parsed_cookie_t{};
    out.created_unix_ms = now_ms();

    std::vector<std::string> attrs;
    {
        size_t start = 0;
        for (size_t i = 0; i < set_cookie_value.size(); i++) {
            if (set_cookie_value[i] == ';') {
                attrs.push_back(set_cookie_value.substr(start, i - start));
                start = i + 1;
            }
        }
        if (start < set_cookie_value.size()) attrs.push_back(set_cookie_value.substr(start));
    }
    if (attrs.empty()) return false;

    std::string first = attrs[0];
    trim(first);
    const size_t eq = first.find('=');
    if (eq == std::string::npos) return false;
    out.name = first.substr(0, eq);
    trim(out.name);
    out.value = first.substr(eq + 1);
    trim(out.value);
    if (out.name.empty()) return false;

    int64_t max_age_seconds = -1;

    for (size_t i = 1; i < attrs.size(); i++) {
        std::string a = attrs[i];
        trim(a);
        if (a.empty()) continue;
        const size_t aeq = a.find('=');
        std::string key, val;
        if (aeq == std::string::npos) { key = a; }
        else { key = a.substr(0, aeq); val = a.substr(aeq + 1); }
        trim(key);
        trim(val);
        const std::string lk = ascii_lower(key);
        if (lk == "domain") {
            out.domain = ascii_lower(val);
            if (!out.domain.empty() && out.domain[0] == '.') out.domain = out.domain.substr(1);
        } else if (lk == "path") {
            out.path = val;
        } else if (lk == "expires") {
            out.has_expires = true;
            out.expires_unix_ms = parse_http_date(val);
        } else if (lk == "max-age") {
            max_age_seconds = parse_int64_field(val, -1);
        } else if (lk == "secure") {
            out.secure = true;
        } else if (lk == "httponly") {
            out.http_only = true;
        } else if (lk == "samesite") {
            out.same_site = parse_same_site(val);
        }
    }

    if (max_age_seconds >= 0) {
        out.has_expires = true;
        out.expires_unix_ms = out.created_unix_ms + max_age_seconds * 1000;
    }

    if (out.domain.empty()) {
        out.domain = ascii_lower(request_host);
        out.host_only = true;
    }
    if (out.path.empty()) out.path = "/";
    return true;
}

void set_cookie(const std::string& host, const parsed_cookie_t& c)
{
    auto& st = s();
    const std::string key = ascii_lower(c.domain.empty() ? host : c.domain);
    if (key.empty() || c.name.empty()) return;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        auto& jar = st.jars[key];
        for (auto it = jar.cookies.begin(); it != jar.cookies.end(); ++it) {
            if (it->name == c.name && it->path == c.path && ascii_lower(it->domain) == ascii_lower(c.domain)) {
                *it = c;
                save_to_disk();
                aida::events::publish(kCookieChangedEvent, cookie_changed_t{key, c.name, "update"});
                return;
            }
        }
        jar.cookies.push_back(c);
    }
    save_to_disk();
    aida::events::publish(kCookieChangedEvent, cookie_changed_t{key, c.name, "set"});
}

void ingest_set_cookie_headers(const std::string& request_host,
                               const std::vector<std::pair<std::string, std::string>>& resp_headers)
{
    for (const auto& h : resp_headers) {
        if (ascii_lower(h.first) != "set-cookie") continue;
        parsed_cookie_t pc;
        if (parse_set_cookie(h.second, request_host, pc)) set_cookie(request_host, pc);
    }
}

std::vector<parsed_cookie_t> cookies_for(const std::string& host, const std::string& path, bool tls)
{
    auto& st = s();
    std::vector<parsed_cookie_t> out;
    const int64_t now = now_ms();
    std::lock_guard<std::mutex> lk(st.mtx);
    for (const auto& kv : st.jars) {
        for (const auto& c : kv.second.cookies) {
            if (c.has_expires && c.expires_unix_ms > 0 && c.expires_unix_ms <= now) continue;
            if (c.secure && !tls) continue;
            if (!domain_matches(c.domain.empty() ? kv.first : c.domain, host)) continue;
            if (!path_matches(c.path, path)) continue;
            if (c.host_only && ascii_lower(c.domain) != ascii_lower(host)) {
                if (ascii_lower(kv.first) != ascii_lower(host)) continue;
            }
            out.push_back(c);
        }
    }
    std::sort(out.begin(), out.end(), [](const parsed_cookie_t& a, const parsed_cookie_t& b) {
        if (a.path.size() != b.path.size()) return a.path.size() > b.path.size();
        return a.created_unix_ms < b.created_unix_ms;
    });
    return out;
}

std::string build_cookie_header(const std::string& host, const std::string& path, bool tls)
{
    const auto cs = cookies_for(host, path, tls);
    std::string out;
    bool first = true;
    for (const auto& c : cs) {
        if (!first) out.append("; ");
        out.append(c.name);
        out.push_back('=');
        out.append(c.value);
        first = false;
    }
    return out;
}

std::vector<parsed_cookie_t> list_for_host(const std::string& host)
{
    auto& st = s();
    std::vector<parsed_cookie_t> out;
    std::lock_guard<std::mutex> lk(st.mtx);
    const auto it = st.jars.find(ascii_lower(host));
    if (it != st.jars.end()) out = it->second.cookies;
    return out;
}

std::vector<parsed_cookie_t> list_all()
{
    auto& st = s();
    std::vector<parsed_cookie_t> out;
    std::lock_guard<std::mutex> lk(st.mtx);
    for (const auto& kv : st.jars) {
        for (const auto& c : kv.second.cookies) out.push_back(c);
    }
    return out;
}

bool delete_cookie(const std::string& host, const std::string& name, const std::string& path)
{
    auto& st = s();
    bool removed = false;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        const auto it = st.jars.find(ascii_lower(host));
        if (it != st.jars.end()) {
            auto& v = it->second.cookies;
            for (auto cit = v.begin(); cit != v.end(); ) {
                const bool path_ok = path.empty() ? true : (cit->path == path);
                if (cit->name == name && path_ok) {
                    cit = v.erase(cit);
                    removed = true;
                } else {
                    ++cit;
                }
            }
            if (v.empty()) st.jars.erase(it);
        }
    }
    if (removed) {
        save_to_disk();
        aida::events::publish(kCookieChangedEvent, cookie_changed_t{ascii_lower(host), name, "delete"});
    }
    return removed;
}

void clear_for_host(const std::string& host)
{
    auto& st = s();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.jars.erase(ascii_lower(host));
    }
    save_to_disk();
    aida::events::publish(kCookieChangedEvent, cookie_changed_t{ascii_lower(host), "", "clear_host"});
}

void clear_all()
{
    auto& st = s();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.jars.clear();
    }
    save_to_disk();
    aida::events::publish(kCookieChangedEvent, cookie_changed_t{"", "", "clear_all"});
}

std::string storage_path()
{
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    return "/aida-preview/state/cookies.json";
#else
    PWSTR appdata = nullptr;
    std::string base;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata)) && appdata) {
        const int needed = WideCharToMultiByte(CP_UTF8, 0, appdata, -1, nullptr, 0, nullptr, nullptr);
        if (needed > 1) {
            base.assign(static_cast<size_t>(needed - 1), '\0');
            WideCharToMultiByte(CP_UTF8, 0, appdata, -1, base.data(), needed, nullptr, nullptr);
        }
        CoTaskMemFree(appdata);
    }
    if (base.empty()) {
        char buf[MAX_PATH] = {};
        const DWORD len = GetEnvironmentVariableA("USERPROFILE", buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) base.assign(buf, len);
        else                            base = "C:\\Users\\Public";
        base += "\\AppData\\Roaming";
    }
    base += "\\AiDA\\Standalone\\burp";
    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    base += "\\cookies.json";
    return base;
#endif
}

bool save_to_disk()
{
    auto& st = s();
    nlohmann::json root = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (const auto& kv : st.jars) {
            for (const auto& c : kv.second.cookies) {
                nlohmann::json j;
                j["host_key"]         = kv.first;
                j["name"]             = c.name;
                j["value"]            = c.value;
                j["domain"]           = c.domain;
                j["path"]             = c.path;
                j["expires_unix_ms"]  = c.expires_unix_ms;
                j["has_expires"]      = c.has_expires;
                j["secure"]           = c.secure;
                j["http_only"]        = c.http_only;
                j["host_only"]        = c.host_only;
                j["same_site"]        = same_site_str(c.same_site);
                j["created_unix_ms"]  = c.created_unix_ms;
                root.push_back(j);
            }
        }
    }
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    return !root.is_discarded();
#else
    const std::string path = storage_path();
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        set_err("failed to open cookies.json for write");
        return false;
    }
    const std::string dump = root.dump(2);
    out.write(dump.data(), static_cast<std::streamsize>(dump.size()));
    return true;
#endif
}

bool load_from_disk()
{
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    return !list_all().empty();
#else
    auto& st = s();
    const std::string path = storage_path();
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string data = ss.str();
    if (data.empty()) return false;
    nlohmann::json arr;
    try { arr = nlohmann::json::parse(data, nullptr, false); }
    catch (...) { set_err("cookies.json parse failed"); return false; }
    if (arr.is_discarded() || !arr.is_array()) {
        set_err("cookies.json not an array");
        return false;
    }
    std::map<std::string, host_jar_t> loaded;
    for (const auto& j : arr) {
        if (!j.is_object()) continue;
        const std::string key = j.value("host_key", std::string());
        if (key.empty()) continue;
        parsed_cookie_t c;
        c.name             = j.value("name", std::string());
        c.value            = j.value("value", std::string());
        c.domain           = j.value("domain", std::string());
        c.path             = j.value("path", std::string("/"));
        c.expires_unix_ms  = j.value("expires_unix_ms", static_cast<int64_t>(0));
        c.has_expires      = j.value("has_expires", false);
        c.secure           = j.value("secure", false);
        c.http_only        = j.value("http_only", false);
        c.host_only        = j.value("host_only", false);
        c.same_site        = parse_same_site(j.value("same_site", std::string()));
        c.created_unix_ms  = j.value("created_unix_ms", static_cast<int64_t>(0));
        if (c.name.empty()) continue;
        loaded[ascii_lower(key)].cookies.push_back(c);
    }
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.jars = std::move(loaded);
    }
    return true;
#endif
}

bool export_netscape(const std::string& file_path)
{
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    return !file_path.empty();
#else
    std::ofstream out(file_path, std::ios::binary | std::ios::trunc);
    if (!out) { set_err("export: failed to open file"); return false; }
    out << "# Netscape HTTP Cookie File\n";
    out << "# https://curl.se/docs/http-cookies.html\n";
    out << "# This file was generated by AiDA Burp Cookie Jar\n\n";
    const auto all = list_all();
    for (const auto& c : all) {
        const std::string domain = c.domain.empty() ? "" : (c.host_only ? c.domain : std::string(".") + c.domain);
        const std::string include_sub = c.host_only ? "FALSE" : "TRUE";
        const std::string secure = c.secure ? "TRUE" : "FALSE";
        const int64_t expires = c.has_expires ? (c.expires_unix_ms / 1000) : 0;
        out << domain << '\t' << include_sub << '\t' << c.path << '\t' << secure << '\t'
            << expires << '\t' << c.name << '\t' << c.value << '\n';
    }
    return true;
#endif
}

bool import_netscape(const std::string& file_path)
{
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    if (file_path.empty()) return false;
    parsed_cookie_t cookie;
    cookie.created_unix_ms = now_ms();
    cookie.domain = "portal.aidapro.net";
    cookie.path = "/";
    cookie.secure = true;
    cookie.http_only = true;
    cookie.host_only = true;
    cookie.name = "aida_preview_session";
    cookie.value = "studio-fixture";
    set_cookie(cookie.domain, cookie);
    return true;
#else
    std::ifstream in(file_path, std::ios::binary);
    if (!in) { set_err("import: failed to open file"); return false; }
    std::string line;
    size_t added = 0;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> cols;
        {
            size_t start = 0;
            for (size_t i = 0; i < line.size(); i++) {
                if (line[i] == '\t') { cols.push_back(line.substr(start, i - start)); start = i + 1; }
            }
            cols.push_back(line.substr(start));
        }
        if (cols.size() < 7) continue;
        parsed_cookie_t c;
        c.created_unix_ms = now_ms();
        c.domain = cols[0];
        if (!c.domain.empty() && c.domain[0] == '.') { c.domain = c.domain.substr(1); c.host_only = false; }
        else                                           { c.host_only = true; }
        c.path   = cols[2];
        c.secure = (ascii_lower(cols[3]) == "true");
        const int64_t expires_sec = parse_int64_field(cols[4], 0);
        if (expires_sec > 0) { c.has_expires = true; c.expires_unix_ms = expires_sec * 1000; }
        c.name   = cols[5];
        c.value  = cols[6];
        if (c.name.empty()) continue;
        set_cookie(c.domain, c);
        ++added;
    }
    diag::log_tagged_fmt("burp", "cookie_import_netscape file=%s added=%zu", file_path.c_str(), added);
    return true;
#endif
}

std::string last_error()
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    return st.last_err;
}

namespace {

void render_table(state_t& st, const ImVec2& origin, float width, float height, float alpha)
{
    const auto& th = aida::ui::resolved();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const float row_h = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;

    const float col_host   = 220.f;
    const float col_name   = 180.f;
    const float col_secure = 60.f;
    const float col_http   = 60.f;
    const float col_same   = 70.f;
    const float col_exp    = 160.f;
    const float col_value  = std::max(180.f, width - col_host - col_name - col_secure - col_http - col_same - col_exp - 20.f);

    dl->AddRectFilled(ImVec2(origin.x, origin.y), ImVec2(origin.x + width, origin.y + row_h),
                      aida::ui::with_alpha(th.panel_header, alpha));
    float cx = origin.x + 8.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    dl->AddText(ImVec2(cx, origin.y + text_oy), hdr_col, "Host");      cx += col_host;
    dl->AddText(ImVec2(cx, origin.y + text_oy), hdr_col, "Name");      cx += col_name;
    dl->AddText(ImVec2(cx, origin.y + text_oy), hdr_col, "Value");     cx += col_value;
    dl->AddText(ImVec2(cx, origin.y + text_oy), hdr_col, "Secure");    cx += col_secure;
    dl->AddText(ImVec2(cx, origin.y + text_oy), hdr_col, "HttpOnly");  cx += col_http;
    dl->AddText(ImVec2(cx, origin.y + text_oy), hdr_col, "SameSite");  cx += col_same;
    dl->AddText(ImVec2(cx, origin.y + text_oy), hdr_col, "Expires");

    ImGui::SetCursorPosY(row_h + 4.f);

    std::vector<std::pair<std::string, parsed_cookie_t>> flat;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (const auto& kv : st.jars) {
            for (const auto& c : kv.second.cookies) flat.emplace_back(kv.first, c);
        }
    }

    const std::string filter = ascii_lower(st.filter_host);
    static float s_anim_time = 0.f;
    s_anim_time += ImGui::GetIO().DeltaTime;

    int visible = 0;
    for (int i = 0; i < static_cast<int>(flat.size()); i++) {
        const auto& host = flat[static_cast<size_t>(i)].first;
        const auto& c    = flat[static_cast<size_t>(i)].second;
        if (!filter.empty() && host.find(filter) == std::string::npos) continue;

        const float row_alpha_anim = ui_anim::render_row_entrance(visible, s_anim_time, 0.010f);
        const float r_alpha = alpha * row_alpha_anim;
        const float abs_ry = ImGui::GetCursorScreenPos().y;

        const bool selected = (st.selected_cookie_index == i);
        if (visible & 1) {
            dl->AddRectFilled(ImVec2(origin.x, abs_ry), ImVec2(origin.x + width, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha * 0.30f));
        }
        if (selected) {
            dl->AddRectFilled(ImVec2(origin.x, abs_ry), ImVec2(origin.x + width, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, r_alpha), 4.f);
        }

        ImGui::PushID(i);
        ImGui::InvisibleButton("##cookie_row", ImVec2(width, row_h));
        if (ImGui::IsItemClicked()) {
            st.selected_cookie_index = i;
            std::strncpy(st.edit_host, host.c_str(), sizeof(st.edit_host) - 1);
            st.edit_host[sizeof(st.edit_host) - 1] = '\0';
            std::strncpy(st.edit_name, c.name.c_str(), sizeof(st.edit_name) - 1);
            st.edit_name[sizeof(st.edit_name) - 1] = '\0';
            std::strncpy(st.edit_value, c.value.c_str(), sizeof(st.edit_value) - 1);
            st.edit_value[sizeof(st.edit_value) - 1] = '\0';
            std::strncpy(st.edit_domain, c.domain.c_str(), sizeof(st.edit_domain) - 1);
            st.edit_domain[sizeof(st.edit_domain) - 1] = '\0';
            std::strncpy(st.edit_path, c.path.c_str(), sizeof(st.edit_path) - 1);
            st.edit_path[sizeof(st.edit_path) - 1] = '\0';
            st.edit_secure = c.secure;
            st.edit_http_only = c.http_only;
            st.edit_same_site = static_cast<int>(c.same_site);
            if (c.has_expires) {
                const time_t t = static_cast<time_t>(c.expires_unix_ms / 1000);
                std::tm tmv = {};
                gmtime_s(&tmv, &t);
                std::strftime(st.edit_expires, sizeof(st.edit_expires), "%Y-%m-%d %H:%M:%S UTC", &tmv);
            } else {
                st.edit_expires[0] = '\0';
            }
        }
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) st.show_edit = true;

        ImU32 txt = aida::ui::with_alpha(th.text_primary, r_alpha);
        float lx = origin.x + 8.f;
        const float ty = abs_ry + text_oy;
        dl->AddText(ImVec2(lx, ty), txt, host.c_str()); lx += col_host;
        dl->AddText(ImVec2(lx, ty), txt, c.name.c_str()); lx += col_name;

        std::string val_preview = c.value;
        if (val_preview.size() > 96) val_preview = val_preview.substr(0, 96) + "...";
        dl->AddText(ImVec2(lx, ty), aida::ui::with_alpha(th.text_secondary, r_alpha), val_preview.c_str());
        lx += col_value;

        dl->AddText(ImVec2(lx, ty), c.secure ? aida::ui::with_alpha(th.success, r_alpha) : aida::ui::with_alpha(th.text_dim, r_alpha),
                    c.secure ? "yes" : "no");
        lx += col_secure;
        dl->AddText(ImVec2(lx, ty), c.http_only ? aida::ui::with_alpha(th.success, r_alpha) : aida::ui::with_alpha(th.text_dim, r_alpha),
                    c.http_only ? "yes" : "no");
        lx += col_http;
        const std::string ss = same_site_str(c.same_site);
        dl->AddText(ImVec2(lx, ty), txt, ss.empty() ? "-" : ss.c_str());
        lx += col_same;

        char exp_buf[64];
        if (c.has_expires && c.expires_unix_ms > 0) {
            const time_t t = static_cast<time_t>(c.expires_unix_ms / 1000);
            std::tm tmv = {};
            gmtime_s(&tmv, &t);
            std::strftime(exp_buf, sizeof(exp_buf), "%Y-%m-%d %H:%M UTC", &tmv);
        } else {
            std::snprintf(exp_buf, sizeof(exp_buf), "session");
        }
        dl->AddText(ImVec2(lx, ty), aida::ui::with_alpha(th.text_dim, r_alpha), exp_buf);

        ImGui::PopID();
        ++visible;
    }

    if (visible == 0) {
        const ImVec2 c_org = ImGui::GetWindowPos();
        const ImVec2 c_sz  = ImGui::GetWindowSize();
        const char* msg = "No cookies stored yet.";
        const ImVec2 sz = ImGui::CalcTextSize(msg);
        dl->AddText(ImVec2(c_org.x + (c_sz.x - sz.x) * 0.5f, c_org.y + (c_sz.y - sz.y) * 0.5f),
                    aida::ui::with_alpha(th.text_dim, alpha * 0.85f), msg);
    }
    ImGui::Dummy(ImVec2(0.f, 0.f));
    (void)height;
}

}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();
    auto& st = s();

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##burp_cookies_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + 28.f),
                      aida::ui::with_alpha(th.panel_header, alpha));
    dl->AddText(ImVec2(org.x + 8.f, org.y + 6.f),
                aida::ui::with_alpha(th.text_primary, alpha),
                "Cookie jar");

    float toolbar_y = 36.f;
    if (st.reviewed_context.valid()) {
        ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + toolbar_y));
        const float context_height = st.reviewed_context_current ? 58.f : 76.f;
        ImGui::BeginChild("##cookies_reviewed_context", ImVec2(width - 12.f, context_height), true);
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
        const ImVec2 context_min = ImGui::GetWindowPos();
        const ImVec2 context_max(context_min.x + ImGui::GetWindowSize().x,
                                 context_min.y + ImGui::GetWindowSize().y);
        aida::preview::semantics::register_region(
            "aida.network.cookies.reviewed-context", "reviewed-network-context",
            ImGui::GetID("##cookies_reviewed_context_region"), context_min, context_max, false,
            false, "aida.dock-window.view.network.cookies");
#endif
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(
            st.reviewed_context_current ? th.success : th.error, alpha)), "%s",
            st.reviewed_context_current ? "CURRENT AT LAST CHECK" : "STALE FILTER CONTEXT");
        ImGui::SameLine();
        if (ImGui::SmallButton("Recheck##cookies_reviewed_context_recheck")) {
            st.reviewed_context_validation_frame = -120;
            refresh_reviewed_context(st);
        }
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
        aida::preview::semantics::register_last_item(
            "aida.network.cookies.reviewed-context.recheck", "revalidate-reviewed-context",
            false, false, "aida.network.cookies.reviewed-context");
#endif
        ImGui::SameLine();
        if (ImGui::SmallButton("Clear##cookies_reviewed_context_clear")) {
            st.reviewed_context = {};
            st.reviewed_path.clear();
            st.reviewed_context_current = false;
            st.reviewed_context_reason.clear();
        }
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
        aida::preview::semantics::register_last_item(
            "aida.network.cookies.reviewed-context.clear", "clear-reviewed-context",
            false, false, "aida.network.cookies.reviewed-context");
#endif
        ImGui::SameLine();
        ImGui::TextUnformatted(st.reviewed_context.label.empty()
            ? st.reviewed_context.id.c_str() : st.reviewed_context.label.c_str());
        ImGui::TextDisabled("%s://%s:%u%s | rev %llu | hash %016llX | %zu bytes",
            st.reviewed_context.use_tls ? "https" : "http",
            st.reviewed_context.target_host.c_str(),
            static_cast<unsigned>(st.reviewed_context.target_port), st.reviewed_path.c_str(),
            static_cast<unsigned long long>(st.reviewed_context.revision),
            static_cast<unsigned long long>(st.reviewed_context.content_hash),
            st.reviewed_context.content_size);
        if (!st.reviewed_context_current && !st.reviewed_context_reason.empty())
            ImGui::TextDisabled("%s", st.reviewed_context_reason.c_str());
        ImGui::EndChild();
        toolbar_y += context_height + 6.f;
    }

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + toolbar_y));
    ImGui::PushID("burp_cookies_toolbar");
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Filter host:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(240.f);
    ImGui::InputTextWithHint("##cookies_filter", "example.com", st.filter_host, sizeof(st.filter_host));
    ImGui::SameLine();
    if (ImGui::Button("Edit selected", ImVec2(120.f, 22.f))) st.show_edit = true;
    ImGui::SameLine();
    if (ImGui::Button("Delete selected", ImVec2(140.f, 22.f))) {
        if (st.edit_host[0] && st.edit_name[0]) {
            delete_cookie(st.edit_host, st.edit_name, st.edit_path);
            st.edit_host[0] = '\0';
            st.edit_name[0] = '\0';
            st.edit_value[0] = '\0';
            st.edit_path[0] = '\0';
            st.edit_domain[0] = '\0';
            st.edit_expires[0] = '\0';
            st.selected_cookie_index = -1;
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear all##cookies_clear", ImVec2(96.f, 22.f))) clear_all();
    ImGui::PopID();

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + toolbar_y + 32.f));
    const float table_height = (std::max)(80.f, height - toolbar_y - 74.f);
    ImGui::BeginChild("##cookies_table", ImVec2(width - 12.f, table_height), false, ImGuiWindowFlags_NoBackground);
    render_table(st, ImGui::GetWindowPos(), width - 12.f, table_height, alpha);
    ImGui::EndChild();

    if (st.show_edit) {
        ImGui::OpenPopup("Edit cookie##burp_cookie_edit");
    }
    if (aida::ui::design::begin_dialog_exact("Edit cookie##burp_cookie_edit",
        ImVec2(560.f, 480.f), ImVec2(420.f, 340.f), &st.show_edit)) {
        const float footer = aida::ui::design::dialog_footer_reserve_height("Save");
        if (aida::ui::design::begin_dialog_body("cookie_edit_body", footer)) {
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::InputText("Host",     st.edit_host,    sizeof(st.edit_host));
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::InputText("Name",     st.edit_name,    sizeof(st.edit_name));
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::InputText("Value",    st.edit_value,   sizeof(st.edit_value));
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::InputText("Domain",   st.edit_domain,  sizeof(st.edit_domain));
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::InputText("Path",     st.edit_path,    sizeof(st.edit_path));
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::InputText("Expires",  st.edit_expires, sizeof(st.edit_expires));
            ImGui::Checkbox("Secure",    &st.edit_secure);
            ImGui::SameLine();
            ImGui::Checkbox("HttpOnly",  &st.edit_http_only);
            const char* ss_labels[] = {"Unset", "Lax", "Strict", "None"};
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::Combo("SameSite",  &st.edit_same_site, ss_labels, 4);
        }
        aida::ui::design::end_dialog_body();
        const auto result = aida::ui::design::dialog_footer(
            "cookie_edit_footer", "Save", true, false);
        if (result.confirmed) {
            parsed_cookie_t c;
            c.name      = st.edit_name;
            c.value     = st.edit_value;
            c.domain    = ascii_lower(st.edit_domain);
            c.path      = st.edit_path[0] ? std::string(st.edit_path) : std::string("/");
            c.secure    = st.edit_secure;
            c.http_only = st.edit_http_only;
            c.same_site = static_cast<same_site_t>(st.edit_same_site);
            c.created_unix_ms = now_ms();
            if (st.edit_expires[0] != '\0') {
                c.has_expires = true;
                c.expires_unix_ms = parse_http_date(st.edit_expires);
            }
            set_cookie(st.edit_host, c);
            st.show_edit = false;
            ImGui::CloseCurrentPopup();
        }
        if (result.cancelled) {
            st.show_edit = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    ImGui::EndChild();
}

}
}
}
