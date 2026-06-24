#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#ifdef small
#undef small
#endif

#include "dom_xss_engine.hpp"
#include "camoufox_bridge.hpp"
#include "issue.hpp"
#include "scanner_module.hpp"
#include "scope.hpp"

#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace aida {
namespace burp {
namespace dom_xss {

namespace {

std::mutex&   err_mtx()   { static std::mutex m; return m; }
std::string&  err_slot()  { static std::string s; return s; }

void set_err(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = msg;
    diag::log_tagged("dom_xss", msg.c_str());
}

void clear_err()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot().clear();
}

std::string current_err()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    return err_slot();
}

uint64_t now_ms_steady()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

uint64_t now_ms_wall()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::atomic<bool>&     initialized_flag() { static std::atomic<bool> f{false}; return f; }
std::atomic<uint64_t>& last_scan_ms()     { static std::atomic<uint64_t> v{0}; return v; }
std::atomic<uint64_t>& sentinel_counter() { static std::atomic<uint64_t> v{0}; return v; }
std::atomic<uint64_t>& dom_page_counter() { static std::atomic<uint64_t> v{0}; return v; }
std::recursive_mutex&  browser_global_mtx() { static std::recursive_mutex m; return m; }
constexpr uint64_t kVisibleBrowserRelaunchBudgetMs = 70000;

std::string json_shape_local(const nlohmann::json& j);
constexpr const char* kConsoleCanaryPrefix = "AIDA_DOM_XSS_CANARY:";

std::string bytes_to_hex(const uint8_t* b, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out[i * 2 + 0] = hex[(b[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[b[i] & 0xF];
    }
    return out;
}

std::string stable_hash64(const std::string& s)
{
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s)
    {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ull;
    }
    uint8_t b[8];
    for (size_t i = 0; i < sizeof(b); ++i)
        b[i] = static_cast<uint8_t>((h >> ((7 - i) * 8)) & 0xFFu);
    return bytes_to_hex(b, sizeof(b));
}

std::string page_id_from_result(const camoufox::call_result_t& r, const std::string& fallback)
{
    try {
        if (r.data.is_object()) {
            auto it = r.data.find("page_id");
            if (it != r.data.end() && it->is_string() && !it->get<std::string>().empty())
                return it->get<std::string>();
            auto page = r.data.find("page");
            if (page != r.data.end() && page->is_object()) {
                auto pit = page->find("page_id");
                if (pit != page->end() && pit->is_string() && !pit->get<std::string>().empty())
                    return pit->get<std::string>();
            }
        }
    } catch (...) {}
    return fallback;
}

std::string make_dom_page_id(const char* phase, const sentinel_t& s)
{
    const uint64_t n = dom_page_counter().fetch_add(1, std::memory_order_acq_rel) + 1;
    std::string token = s.token;
    if (token.size() > 16)
        token.resize(16);
    std::string out = "dom_xss_";
    out += phase ? phase : "page";
    out += "_";
    out += token.empty() ? std::to_string(static_cast<unsigned long long>(now_ms_steady())) : token;
    out += "_";
    out += std::to_string(static_cast<unsigned long long>(n));
    for (char& c : out) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) c = '_';
    }
    return out;
}

struct browser_page_scope_t
{
    std::string page_id;
    std::string previous_page_id;
    bool created = false;

    browser_page_scope_t(const char* phase, const sentinel_t& s)
    {
        camoufox::bridge_status_t before_status;
        bool before_status_ok = false;
        try {
            before_status = camoufox::get_status();
            before_status_ok = true;
            previous_page_id = before_status.active_page_id;
        } catch (...) {
            previous_page_id.clear();
        }
        const std::string requested = make_dom_page_id(phase, s);
        camoufox::call_result_t r;
        try {
            r = camoufox::new_page("default", requested, "about:blank", false);
        } catch (...) {
            r.ok = false;
            r.error = "new_page threw";
        }
        if (r.ok) {
            page_id = page_id_from_result(r, requested);
            created = !page_id.empty();
            camoufox::bridge_status_t after_status;
            bool after_status_ok = false;
            try {
                after_status = camoufox::get_status();
                after_status_ok = true;
            } catch (...) {
            }
            diag::log_tagged_fmt("dom_xss", "page_scope_create phase=%s requested_page_id=%s page_id=%s make_active=0 previous_page_id=%s before_ok=%d before_active=%s before_pages=%u after_ok=%d after_active=%s after_pages=%u data_shape=%s",
                phase ? phase : "", requested.c_str(), page_id.c_str(), previous_page_id.c_str(),
                before_status_ok ? 1 : 0, before_status.active_page_id.c_str(), static_cast<unsigned>(before_status.page_count),
                after_status_ok ? 1 : 0, after_status.active_page_id.c_str(), static_cast<unsigned>(after_status.page_count),
                json_shape_local(r.data).c_str());
        } else {
            diag::log_tagged_fmt("dom_xss", "page_scope_create_failed phase=%s requested_page_id=%s make_active=0 previous_page_id=%s before_ok=%d before_active=%s before_pages=%u err=%s data_shape=%s",
                phase ? phase : "", requested.c_str(), previous_page_id.c_str(),
                before_status_ok ? 1 : 0, before_status.active_page_id.c_str(), static_cast<unsigned>(before_status.page_count),
                r.error.c_str(), json_shape_local(r.data).c_str());
        }
    }

    ~browser_page_scope_t()
    {
        if (created && !page_id.empty()) {
            camoufox::call_result_t closed;
            try { closed = camoufox::close_page("default", page_id); }
            catch (...) { closed.ok = false; closed.error = "close_page threw"; }
            camoufox::bridge_status_t after_close;
            bool after_close_ok = false;
            try {
                after_close = camoufox::get_status();
                after_close_ok = true;
            } catch (...) {
            }
            diag::log_tagged_fmt("dom_xss", "page_scope_close page_id=%s ok=%d after_ok=%d after_active=%s after_pages=%u err=%s data_shape=%s",
                page_id.c_str(), closed.ok ? 1 : 0, after_close_ok ? 1 : 0,
                after_close.active_page_id.c_str(), static_cast<unsigned>(after_close.page_count),
                closed.error.c_str(), json_shape_local(closed.data).c_str());
        }
        if (!previous_page_id.empty()) {
            camoufox::call_result_t selected;
            try { selected = camoufox::select_page("default", previous_page_id); }
            catch (...) { selected.ok = false; selected.error = "select_page threw"; }
            camoufox::bridge_status_t after_restore;
            bool after_restore_ok = false;
            try {
                after_restore = camoufox::get_status();
                after_restore_ok = true;
            } catch (...) {
            }
            diag::log_tagged_fmt("dom_xss", "page_scope_restore previous_page_id=%s ok=%d after_ok=%d after_active=%s after_pages=%u err=%s data_shape=%s",
                previous_page_id.c_str(), selected.ok ? 1 : 0, after_restore_ok ? 1 : 0,
                after_restore.active_page_id.c_str(), static_cast<unsigned>(after_restore.page_count),
                selected.error.c_str(), json_shape_local(selected.data).c_str());
        }
    }

    bool ok() const
    {
        return created && !page_id.empty();
    }
};

bool random_bytes(uint8_t* out, size_t n)
{
    NTSTATUS s = BCryptGenRandom(nullptr, out, static_cast<ULONG>(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return s == 0;
}

std::string replace_all(std::string s, const std::string& from, const std::string& to)
{
    if (from.empty()) return s;
    size_t p = 0;
    while ((p = s.find(from, p)) != std::string::npos) {
        s.replace(p, from.size(), to);
        p += to.size();
    }
    return s;
}

std::string ascii_lower_copy(std::string s)
{
    for (char& c : s)
    {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    }
    return s;
}

bool is_browser_transport_error(const std::string& msg)
{
    std::string s = ascii_lower_copy(msg);
    return s.find("connection closed while reading from the driver") != std::string::npos ||
           s.find("connection closed") != std::string::npos ||
           s.find("camoufox driver closed") != std::string::npos ||
           s.find("camoufox bridge not ready") != std::string::npos ||
           s.find("bridge state is busy") != std::string::npos ||
           s.find("target page, context or browser has been closed") != std::string::npos ||
           s.find("browser has been closed") != std::string::npos ||
           s.find("page has been closed") != std::string::npos ||
           s.find("target closed") != std::string::npos ||
           s.find("page crashed") != std::string::npos ||
           s.find("deadline exceeded") != std::string::npos ||
           s.find("add_init_script failed") != std::string::npos ||
           s.find("navigate failed") != std::string::npos ||
           s.find("harness navigate") != std::string::npos ||
           s.find("harness evaluate_js failed") != std::string::npos ||
           s.find("results read failed") != std::string::npos;
}

int bounded_payload_timeout_ms(int timeout_ms)
{
    if (timeout_ms < 1000) return 1000;
    if (timeout_ms > 30000) return 30000;
    return timeout_ms;
}

uint64_t payload_deadline_ms(int timeout_ms)
{
    return now_ms_steady() + static_cast<uint64_t>(bounded_payload_timeout_ms(timeout_ms)) + 5000ULL;
}

long long remaining_until_deadline_ms(uint64_t deadline_ms)
{
    if (deadline_ms == 0) return 9223372036854775807LL;
    const uint64_t now = now_ms_steady();
    if (now >= deadline_ms) return 0;
    const uint64_t remaining = deadline_ms - now;
    return remaining > 9223372036854775807ULL ? 9223372036854775807LL : static_cast<long long>(remaining);
}

bool browser_transport_retry_allowed(const char* phase, int attempt, int max_attempts, uint64_t deadline_ms, const std::string& err)
{
    if (!is_browser_transport_error(err) || attempt >= max_attempts)
        return false;
    const long long remaining_ms = remaining_until_deadline_ms(deadline_ms);
    if (deadline_ms != 0 && remaining_ms < static_cast<long long>(kVisibleBrowserRelaunchBudgetMs))
    {
        std::ostringstream oss;
        oss << (phase ? phase : "browser")
            << " browser transport retry suppressed: remaining_ms=" << remaining_ms
            << " relaunch_budget_ms=" << kVisibleBrowserRelaunchBudgetMs
            << " attempt=" << attempt
            << " err=" << err;
        set_err(oss.str());
        diag::log_tagged_fmt("dom_xss", "browser_transport_retry_suppressed phase=%s attempt=%d remaining_ms=%lld relaunch_budget_ms=%llu err=%s",
            phase ? phase : "", attempt, remaining_ms,
            static_cast<unsigned long long>(kVisibleBrowserRelaunchBudgetMs), err.c_str());
        return false;
    }
    diag::log_tagged_fmt("dom_xss", "browser_transport_retry_allowed phase=%s attempt=%d remaining_ms=%lld err=%s",
        phase ? phase : "", attempt, remaining_ms, err.c_str());
    return true;
}

bool sleep_before_deadline(int requested_ms, uint64_t deadline_ms)
{
    if (requested_ms <= 0)
        return deadline_ms == 0 || remaining_until_deadline_ms(deadline_ms) > 0;
    int sleep_ms = requested_ms;
    if (deadline_ms != 0) {
        const long long remaining_ms = remaining_until_deadline_ms(deadline_ms);
        if (remaining_ms <= 0)
            return false;
        if (remaining_ms <= 10)
            return true;
        const long long max_sleep_ms = remaining_ms - 10;
        if (sleep_ms > max_sleep_ms)
            sleep_ms = static_cast<int>(max_sleep_ms);
    }
    if (sleep_ms > 0)
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
    return deadline_ms == 0 || remaining_until_deadline_ms(deadline_ms) > 0;
}

void recover_browser_transport(const char* phase, int attempt, const std::string& err, uint64_t deadline_ms)
{
    const auto before = camoufox::get_status();
    const uint64_t t0 = now_ms_steady();
    const int sleep_ms = 750 + (attempt * 500);
    diag::log_tagged_fmt("dom_xss", "browser_transport_recover phase=%s attempt=%d state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d errors=%llu err=%s",
        phase ? phase : "", attempt, static_cast<int>(before.state),
        static_cast<unsigned long long>(before.generation), static_cast<unsigned long>(before.child_pid),
        before.child_alive ? 1 : 0, before.browser_open ? 1 : 0, before.page_verified ? 1 : 0,
        before.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(before.total_errors), err.c_str());
    std::string stop_reason = "dom_xss.recover.";
    stop_reason += phase ? phase : "browser";
    const bool stopped = camoufox::stop_bridge(stop_reason.c_str());
    const auto after = camoufox::get_status();
    diag::log_tagged_fmt("dom_xss", "browser_transport_recover_stop phase=%s attempt=%d stop_ok=%d elapsed_ms=%llu state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d errors=%llu sleep_ms=%d err=%s",
        phase ? phase : "", attempt, stopped ? 1 : 0,
        static_cast<unsigned long long>(now_ms_steady() - t0), static_cast<int>(after.state),
        static_cast<unsigned long long>(after.generation), static_cast<unsigned long>(after.child_pid),
        after.child_alive ? 1 : 0, after.browser_open ? 1 : 0, after.page_verified ? 1 : 0,
        after.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(after.total_errors), sleep_ms,
        err.c_str());
    if (!sleep_before_deadline(sleep_ms, deadline_ms))
        set_err("DOM-XSS scan deadline exceeded");
}

struct bridge_activity_scope_t
{
    const char* owner = nullptr;
    uint64_t token = 0;

    explicit bridge_activity_scope_t(const char* activity_owner)
        : owner(activity_owner), token(camoufox::begin_activity(activity_owner))
    {
    }

    ~bridge_activity_scope_t()
    {
        camoufox::end_activity(token, owner);
    }

    bridge_activity_scope_t(const bridge_activity_scope_t&) = delete;
    bridge_activity_scope_t& operator=(const bridge_activity_scope_t&) = delete;
};

std::string js_string_literal(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "\\u%04x", static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    out.push_back('"');
    return out;
}

std::string make_screenshot_path(const std::string& tag)
{
    std::filesystem::path dir = std::filesystem::temp_directory_path() / "aida_dom_xss";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    std::string fname = "shot_" + tag + "_" + std::to_string(now_ms_wall()) + ".png";
    return (dir / fname).string();
}

struct request_line_t
{
    std::string method;
    std::string uri;
    std::string version;
    size_t      headers_offset = 0;
    bool        valid = false;
};

request_line_t parse_request_line_local(const std::string& raw)
{
    request_line_t out;
    auto eol = raw.find("\r\n");
    if (eol == std::string::npos) return out;
    auto sp1 = raw.find(' ');
    if (sp1 == std::string::npos || sp1 >= eol) return out;
    auto sp2 = raw.find(' ', sp1 + 1);
    if (sp2 == std::string::npos || sp2 >= eol) return out;
    out.method = raw.substr(0, sp1);
    out.uri    = raw.substr(sp1 + 1, sp2 - sp1 - 1);
    out.version = raw.substr(sp2 + 1, eol - sp2 - 1);
    out.headers_offset = eol + 2;
    out.valid = true;
    return out;
}

bool extract_host_header(const std::string& raw, size_t headers_offset, std::string& out_host)
{
    size_t p = headers_offset;
    auto body_sep = raw.find("\r\n\r\n", p);
    size_t end = (body_sep == std::string::npos) ? raw.size() : body_sep;
    while (p < end) {
        auto eol = raw.find("\r\n", p);
        if (eol == std::string::npos || eol > end) break;
        auto colon = raw.find(':', p);
        if (colon == std::string::npos || colon >= eol) { p = eol + 2; continue; }
        std::string name = raw.substr(p, colon - p);
        std::string lname; lname.reserve(name.size());
        for (char c : name) lname.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        if (lname == "host") {
            size_t vs = colon + 1;
            while (vs < eol && (raw[vs] == ' ' || raw[vs] == '\t')) ++vs;
            size_t ve = eol;
            while (ve > vs && (raw[ve - 1] == ' ' || raw[ve - 1] == '\t')) --ve;
            out_host = raw.substr(vs, ve - vs);
            return true;
        }
        p = eol + 2;
    }
    return false;
}

std::string assemble_url_from_built(const std::vector<uint8_t>& built,
                                    const std::string&          fallback_scheme,
                                    uint16_t                    fallback_port)
{
    std::string raw(reinterpret_cast<const char*>(built.data()), built.size());
    auto rl = parse_request_line_local(raw);
    if (!rl.valid) return std::string();
    std::string host;
    if (!extract_host_header(raw, rl.headers_offset, host) || host.empty()) return std::string();
    std::string scheme = fallback_scheme.empty() ? std::string("http") : fallback_scheme;
    uint16_t port = fallback_port;
    if (port == 0) port = (scheme == "https") ? 443 : 80;
    auto colon_in_host = host.find(':');
    if (colon_in_host == std::string::npos) {
        if ((scheme == "https" && port != 443) || (scheme == "http" && port != 80)) {
            host += ":";
            host += std::to_string(port);
        }
    }
    std::string url;
    url.reserve(scheme.size() + 3 + host.size() + rl.uri.size());
    url += scheme;
    url += "://";
    url += host;
    if (rl.uri.empty() || rl.uri[0] != '/') url += '/';
    url += rl.uri;
    return url;
}

bool extract_method_path_body(const std::vector<uint8_t>& built,
                              std::string& out_method,
                              std::string& out_uri,
                              std::vector<std::pair<std::string, std::string>>& out_headers,
                              std::string& out_body)
{
    std::string raw(reinterpret_cast<const char*>(built.data()), built.size());
    auto rl = parse_request_line_local(raw);
    if (!rl.valid) return false;
    out_method = rl.method;
    out_uri = rl.uri;
    auto body_sep = raw.find("\r\n\r\n", rl.headers_offset);
    size_t end = (body_sep == std::string::npos) ? raw.size() : body_sep;
    size_t p = rl.headers_offset;
    while (p < end) {
        auto eol = raw.find("\r\n", p);
        if (eol == std::string::npos || eol > end) break;
        auto colon = raw.find(':', p);
        if (colon == std::string::npos || colon >= eol) { p = eol + 2; continue; }
        std::string name = raw.substr(p, colon - p);
        size_t vs = colon + 1;
        while (vs < eol && (raw[vs] == ' ' || raw[vs] == '\t')) ++vs;
        size_t ve = eol;
        while (ve > vs && (raw[ve - 1] == ' ' || raw[ve - 1] == '\t')) --ve;
        out_headers.emplace_back(std::move(name), raw.substr(vs, ve - vs));
        p = eol + 2;
    }
    if (body_sep != std::string::npos) {
        out_body.assign(raw.begin() + static_cast<std::ptrdiff_t>(body_sep + 4), raw.end());
    }
    return true;
}

std::string build_fetch_harness_js(const std::string& method,
                                   const std::string& abs_url,
                                   const std::vector<std::pair<std::string, std::string>>& headers,
                                   const std::string& body)
{
    nlohmann::json hdrs = nlohmann::json::object();
    for (const auto& kv : headers) {
        std::string lk; lk.reserve(kv.first.size());
        for (char c : kv.first) lk.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        if (lk == "host" || lk == "content-length" || lk == "connection" ||
            lk == "transfer-encoding" || lk == "accept-encoding") continue;
        hdrs[kv.first] = kv.second;
    }
    bool has_body = !body.empty() && method != "GET" && method != "HEAD";
    std::ostringstream os;
    os << "(async function(){";
    os << "try{";
    os << "const r=await fetch(" << js_string_literal(abs_url) << ",{";
    os << "method:" << js_string_literal(method) << ",";
    os << "headers:" << hdrs.dump() << ",";
    os << "credentials:'omit',";
    os << "mode:'cors',";
    os << "redirect:'follow'";
    if (has_body) {
        os << ",body:" << js_string_literal(body);
    }
    os << "});";
    os << "const t=await r.text();";
    os << "document.open();";
    os << "document.write(t);";
    os << "document.close();";
    os << "return {ok:true,status:r.status,len:t.length};";
    os << "}catch(e){return {ok:false,error:String(e&&e.message?e.message:e)};}";
    os << "})();";
    return os.str();
}

std::string build_results_read_js(const sentinel_t& s)
{
    std::ostringstream os;
    os << "JSON.stringify(window[" << js_string_literal(s.results_global) << "]||[])";
    return os.str();
}

std::string build_canary_probe_js(const sentinel_t& s)
{
    std::ostringstream os;
    os << "(function(){";
    os << "var RG=" << js_string_literal(s.results_global) << ";";
    os << "var CF=" << js_string_literal(s.canary_fn) << ";";
    os << "var TOK=" << js_string_literal(s.token) << ";";
    os << "var html='';try{html=document.documentElement?document.documentElement.outerHTML:'';}catch(e){}";
    os << "var arr=window[RG];";
    os << "var DG='__aida_dom_xss_diag_'+TOK;";
    os << "var diag=null;try{diag=window[DG]||null;}catch(e){}";
    os << "var fixture=window.aidaDomXssFixtureLog;";
    os << "var reflect='';try{var de=document.getElementById('dom-reflect');reflect=de?de.innerHTML:'';}catch(e){}";
    os << "var setterText='';try{var d=Object.getOwnPropertyDescriptor(Element.prototype,'innerHTML');if(d&&d.set)setterText=String(d.set).slice(0,240);}catch(e){}";
    os << "var evs={total:0,withToken:0,withFn:0,withConsole:0,sample:''};try{var ns=document.querySelectorAll('*');for(var i=0;i<ns.length&&i<4096;i++){var as=ns[i].attributes||[];for(var j=0;j<as.length&&evs.total<8192;j++){var n=String(as[j].name||'').toLowerCase();var v=String(as[j].value||'');if(n.indexOf('on')===0||n==='href'||n==='src'||n==='xlink:href'||n==='formaction'||n==='action'||n==='srcdoc'){evs.total++;var ht=v.indexOf(TOK)>=0;var hf=v.indexOf(CF)>=0;var hc=v.indexOf('AIDA_DOM_XSS_CANARY')>=0;if(ht)evs.withToken++;if(hf)evs.withFn++;if(hc)evs.withConsole++;if(!evs.sample&&(ht||hf||hc))evs.sample=(n+'='+v).slice(0,240);}}}}catch(e){evs.error=String(e&&e.message?e.message:e).slice(0,160);}";
    os << "return JSON.stringify({";
    os << "fnType:typeof window[CF],";
    os << "resultsIsArray:Array.isArray(arr),";
    os << "resultsLen:Array.isArray(arr)?arr.length:-1,";
    os << "resultsTail:Array.isArray(arr)?arr.slice(Math.max(0,arr.length-3)):[],";
    os << "diag:diag,";
    os << "fixtureLogLen:Array.isArray(fixture)?fixture.length:-1,";
    os << "fixtureLast:Array.isArray(fixture)&&fixture.length?fixture[fixture.length-1]:null,";
    os << "domReflectLen:reflect.length,";
    os << "domReflectHasToken:reflect.indexOf(TOK)>=0,";
    os << "domReflectHasFn:reflect.indexOf(CF)>=0,";
    os << "eventAttrStats:evs,";
    os << "innerHTMLSetterLooksAida:setterText.indexOf('innerHTML:')>=0||setterText.indexOf('push')>=0,";
    os << "innerHTMLSetterHead:setterText,";
    os << "readyState:String(document.readyState||''),";
    os << "url:String(location.href||'').slice(0,512),";
    os << "title:String(document.title||'').slice(0,240),";
    os << "htmlLen:html.length,";
    os << "htmlHasToken:html.indexOf(TOK)>=0,";
    os << "htmlHasFn:html.indexOf(CF)>=0,";
    os << "htmlHead:html.slice(0,700)";
    os << "});";
    os << "})()";
    return os.str();
}

std::string build_active_dom_replay_js(const sentinel_t& s)
{
    std::ostringstream os;
    os << "(function(){";
    os << "var RG=" << js_string_literal(s.results_global) << ";";
    os << "var CF=" << js_string_literal(s.canary_fn) << ";";
    os << "var TOK=" << js_string_literal(s.token) << ";";
    os << "var PREF=" << js_string_literal(std::string(kConsoleCanaryPrefix)) << ";";
    os << "var out={url:String(location.href||'').slice(0,512),readyState:String(document.readyState||''),nodes:0,attrs:0,candidates:0,eventAttrs:0,urlAttrs:0,srcdocAttrs:0,dispatches:0,fnCalls:0,pushes:0,resultsLen:-1,errors:[],samples:[]};";
    os << "var sample=function(k,v){try{if(out.samples.length<8)out.samples.push({k:String(k||'').slice(0,80),v:String(v||'').slice(0,240)});}catch(e){}};";
    os << "var arr=null;try{arr=window[RG];if(!Array.isArray(arr)){arr=[];try{Object.defineProperty(window,RG,{value:arr,writable:false,configurable:false,enumerable:false});}catch(e){try{window[RG]=arr;}catch(e2){out.errors.push('arr:'+String(e2&&e2.message?e2.message:e2).slice(0,120));}}}}catch(e){out.errors.push('arr_outer:'+String(e&&e.message?e.message:e).slice(0,120));}";
    os << "var emit=function(entry){try{console.log(PREF+JSON.stringify(entry));}catch(e){}};";
    os << "var push=function(id,src,tag){try{var entry={id:String(id||'dom-replay:'+TOK).slice(0,160),src:String(src||'').slice(0,400),tag:String(tag||'').slice(0,64),t:Date.now(),token:TOK,replay:true};var a=window[RG];if(Array.isArray(a)){a.push(entry);out.pushes++;}emit(entry);return true;}catch(e){out.errors.push('push:'+String(e&&e.message?e.message:e).slice(0,120));return false;}};";
    os << "var callCanary=function(label,src,tag){var ok=false;try{if(typeof window[CF]==='function'){window[CF](label);out.fnCalls++;ok=true;}}catch(e){out.errors.push('fn:'+String(e&&e.message?e.message:e).slice(0,120));}if(!ok)ok=push(label,src,tag);return ok;};";
    os << "var invokeRefs=function(text,src,tag){var made=0;try{var re=/(__aida_xss_canary_[A-Za-z0-9]+__)\\s*\\(\\s*(['\\\"])(.*?)\\2\\s*\\)/g;var s=String(text||'');var m;while((m=re.exec(s))){if(m[1]===CF){out.candidates++;sample(tag,s);if(callCanary('dom-replay-call:'+TOK,String(m[3]||src||'').slice(0,160),tag))made++;}}}catch(e){out.errors.push('invoke:'+String(e&&e.message?e.message:e).slice(0,120));}return made;};";
    os << "var executable=function(v){var s=String(v||'');return s.indexOf(CF)>=0||s.indexOf('AIDA_DOM_XSS_CANARY')>=0;};";
    os << "try{var nodes=document.querySelectorAll('*');out.nodes=nodes.length;var max=Math.min(nodes.length,4096);for(var i=0;i<max;i++){var el=nodes[i];var tag=(el&&el.tagName?String(el.tagName).toLowerCase():'node');var attrs=el&&el.attributes?el.attributes:[];for(var j=0;j<attrs.length&&out.attrs<8192;j++){out.attrs++;var n=String(attrs[j].name||'');var ln=n.toLowerCase();var v=String(attrs[j].value||'');if(v.indexOf(TOK)<0&&v.indexOf(CF)<0&&v.indexOf('AIDA_DOM_XSS_CANARY')<0)continue;if(ln.indexOf('on')===0&&ln.length>2&&executable(v)){out.eventAttrs++;out.candidates++;sample(tag+'.'+ln,v);try{el.dispatchEvent(new Event(ln.slice(2),{bubbles:true,cancelable:true}));out.dispatches++;}catch(e){out.errors.push('dispatch:'+ln+':'+String(e&&e.message?e.message:e).slice(0,80));}invokeRefs(v,v,tag+'.'+ln);continue;}var lv=v.toLowerCase();if((ln==='href'||ln==='src'||ln==='xlink:href'||ln==='formaction'||ln==='action')&&lv.indexOf('javascript:')>=0&&executable(v)){out.urlAttrs++;out.candidates++;sample(tag+'.'+ln,v);invokeRefs(v,v,tag+'.'+ln);continue;}if(ln==='srcdoc'&&executable(v)){out.srcdocAttrs++;out.candidates++;sample(tag+'.srcdoc',v);invokeRefs(v,v,tag+'.srcdoc');}}}}catch(e){out.errors.push('scan:'+String(e&&e.message?e.message:e).slice(0,160));}";
    os << "try{out.resultsLen=Array.isArray(window[RG])?window[RG].length:-1;}catch(e){out.resultsLen=-2;out.errors.push('len:'+String(e&&e.message?e.message:e).slice(0,120));}";
    os << "return JSON.stringify(out);";
    os << "})()";
    return os.str();
}

int result_read_timeout_ms(uint64_t deadline_ms)
{
    if (deadline_ms == 0)
        return 30000;
    const long long remaining_ms = remaining_until_deadline_ms(deadline_ms);
    if (remaining_ms <= 0)
        return 0;
    const long long bounded = std::min<long long>(remaining_ms, 30000);
    return static_cast<int>(bounded);
}

camoufox::call_result_t deadline_failure_result(const char* tool_name, uint64_t deadline_ms, const std::string& page_id)
{
    camoufox::call_result_t r;
    r.ok = false;
    r.error = "DOM-XSS scan deadline exceeded";
    r.data = nlohmann::json{
        {"status", "deadline_exceeded"},
        {"tool", tool_name ? tool_name : ""},
        {"page_id", page_id},
        {"deadline_ms", deadline_ms},
        {"remaining_ms", remaining_until_deadline_ms(deadline_ms)}
    };
    return r;
}

camoufox::call_result_t call_evaluate_js_deadline(const std::string& expression,
                                                  bool await_promise,
                                                  const std::string& page_id,
                                                  uint64_t deadline_ms)
{
    const int timeout_ms = result_read_timeout_ms(deadline_ms);
    if (deadline_ms != 0 && timeout_ms <= 0)
        return deadline_failure_result("evaluate_js", deadline_ms, page_id);
    nlohmann::json args;
    args["expression"] = expression;
    args["await_promise"] = await_promise;
    if (!page_id.empty())
        args["page_id"] = page_id;
    return camoufox::call_tool("evaluate_js", args, timeout_ms);
}

camoufox::call_result_t call_console_logs_deadline(size_t max_records,
                                                   const std::string& page_id,
                                                   uint64_t deadline_ms)
{
    const int timeout_ms = result_read_timeout_ms(deadline_ms);
    if (deadline_ms != 0 && timeout_ms <= 0)
        return deadline_failure_result("get_console_logs", deadline_ms, page_id);
    nlohmann::json args;
    if (max_records != 0)
        args["max_records"] = static_cast<uint64_t>(max_records);
    if (!page_id.empty())
        args["page_id"] = page_id;
    return camoufox::call_tool("get_console_logs", args, timeout_ms);
}

camoufox::call_result_t reset_browser_state_deadline(uint64_t deadline_ms)
{
    const int timeout_ms = result_read_timeout_ms(deadline_ms);
    if (deadline_ms != 0 && timeout_ms <= 0)
        return deadline_failure_result("reset_browser_state", deadline_ms, std::string());
    const auto st = camoufox::get_status();
    nlohmann::json args;
    args["clear_persistent_hooks"] = true;
    args["clear_network_capture"] = true;
    args["clear_active_routes"] = true;
    args["clear_cookies"] = false;
    args["clear_storage"] = false;
    args["close_page_prefix"] = "dom_xss_";
    args["close_empty_contexts"] = true;
    if (!st.active_page_id.empty())
        args["restore_page_id"] = st.active_page_id;
    return camoufox::call_tool("reset_browser_state", args, timeout_ms);
}

camoufox::call_result_t add_init_script_deadline(const std::string& script, uint64_t deadline_ms)
{
    const int timeout_ms = result_read_timeout_ms(deadline_ms);
    if (deadline_ms != 0 && timeout_ms <= 0)
        return deadline_failure_result("add_init_script", deadline_ms, std::string());
    nlohmann::json args;
    args["script"] = script;
    return camoufox::call_tool("add_init_script", args, timeout_ms);
}

int browser_navigation_timeout_for_deadline(int requested_ms, uint64_t deadline_ms, const char* phase)
{
    int effective_ms = bounded_payload_timeout_ms(requested_ms);
    if (deadline_ms == 0)
        return effective_ms;
    const long long remaining_ms = remaining_until_deadline_ms(deadline_ms);
    if (remaining_ms <= 5000)
    {
        std::string e = "DOM-XSS scan deadline exceeded";
        if (phase && *phase)
            e += std::string(" before ") + phase;
        set_err(e);
        return 0;
    }
    const long long max_requested_ms = remaining_ms - 5000;
    if (effective_ms > max_requested_ms)
        effective_ms = static_cast<int>(max_requested_ms);
    if (effective_ms <= 0)
    {
        set_err("DOM-XSS scan deadline exceeded");
        return 0;
    }
    return effective_ms;
}

std::string json_shape_local(const nlohmann::json& j)
{
    if (j.is_null()) return "null";
    if (j.is_boolean()) return "boolean";
    if (j.is_number()) return "number";
    if (j.is_string()) return "string";
    if (j.is_array()) return std::string("array[") + std::to_string(j.size()) + "]";
    if (!j.is_object()) return "unknown";
    std::string out = "object{";
    size_t n = 0;
    for (auto it = j.begin(); it != j.end() && n < 12; ++it, ++n) {
        if (n) out += ",";
        out += it.key();
    }
    if (j.size() > n) out += ",...";
    out += "}";
    return out;
}

const nlohmann::json* bridge_call_meta(const nlohmann::json& data)
{
    if (!data.is_object())
        return nullptr;
    auto it = data.find("bridge_call");
    if (it != data.end() && it->is_object())
        return &(*it);
    return nullptr;
}

uint64_t bridge_meta_u64(const nlohmann::json& data, const char* key)
{
    const nlohmann::json* meta = bridge_call_meta(data);
    if (!meta || !key)
        return 0;
    auto it = meta->find(key);
    if (it == meta->end())
        return 0;
    if (it->is_number_unsigned())
        return it->get<uint64_t>();
    if (it->is_number_integer())
        return static_cast<uint64_t>(std::max<int64_t>(it->get<int64_t>(), 0));
    return 0;
}

bool bridge_meta_bool(const nlohmann::json& data, const char* key)
{
    const nlohmann::json* meta = bridge_call_meta(data);
    if (!meta || !key)
        return false;
    auto it = meta->find(key);
    return it != meta->end() && it->is_boolean() && it->get<bool>();
}

std::string bridge_meta_string(const nlohmann::json& data, const char* key)
{
    const nlohmann::json* meta = bridge_call_meta(data);
    if (!meta || !key)
        return {};
    auto it = meta->find(key);
    return it != meta->end() && it->is_string() ? it->get<std::string>() : std::string();
}

std::string trim_payload(const std::string& s, size_t max_chars)
{
    if (s.size() <= max_chars) return s;
    return s.substr(0, max_chars) + "...";
}

std::string normalize_sink_log_entry(const nlohmann::json& e)
{
    if (e.is_string()) return e.get<std::string>();
    if (!e.is_object()) return e.dump();
    std::string id = "?";
    std::string src = "inline";
    if (e.contains("id") && e["id"].is_string()) id = e["id"].get<std::string>();
    if (e.contains("src") && e["src"].is_string()) src = e["src"].get<std::string>();
    std::string out;
    out += id;
    out += " (";
    out += src;
    out += ")";
    return out;
}

bool canary_entry_matches(const nlohmann::json& e, const sentinel_t& s)
{
    if (!e.is_object())
        return false;
    if (e.contains("token") && e["token"].is_string() && e["token"].get<std::string>() == s.token)
        return true;
    if (e.contains("id") && e["id"].is_string() && e["id"].get<std::string>().find(s.token) != std::string::npos)
        return true;
    return false;
}

void append_unique_sink(std::vector<std::string>& out, const std::string& value)
{
    if (value.empty())
        return;
    if (std::find(out.begin(), out.end(), value) == out.end())
        out.push_back(value);
}

bool parse_console_json_text(const std::string& text, nlohmann::json& out)
{
    if (text.empty())
        return false;
    try
    {
        out = nlohmann::json::parse(text);
        return true;
    }
    catch (...) {}
    size_t first = std::string::npos;
    const size_t arr = text.find('[');
    const size_t obj = text.find('{');
    if (arr != std::string::npos && obj != std::string::npos)
        first = std::min(arr, obj);
    else if (arr != std::string::npos)
        first = arr;
    else
        first = obj;
    if (first == std::string::npos)
        return false;
    const char close_ch = text[first] == '[' ? ']' : '}';
    const size_t last = text.rfind(close_ch);
    if (last == std::string::npos || last <= first)
        return false;
    try
    {
        out = nlohmann::json::parse(text.substr(first, last - first + 1));
        return true;
    }
    catch (...) {}
    return false;
}

nlohmann::json console_log_array_from_json(const nlohmann::json& data)
{
    if (data.is_array())
        return data;
    if (data.is_string())
    {
        const std::string text = data.get<std::string>();
        nlohmann::json parsed;
        if (parse_console_json_text(text, parsed))
            return console_log_array_from_json(parsed);
        nlohmann::json entry = nlohmann::json::object();
        entry["text"] = text;
        return nlohmann::json::array({entry});
    }
    if (data.is_object())
    {
        if (data.contains("text") && data["text"].is_string())
            return nlohmann::json::array({data});
        if (data.contains("value"))
        {
            nlohmann::json nested = console_log_array_from_json(data["value"]);
            if (!nested.empty())
                return nested;
        }
        if (data.contains("result"))
        {
            nlohmann::json nested = console_log_array_from_json(data["result"]);
            if (!nested.empty())
                return nested;
        }
        if (data.contains("logs"))
        {
            nlohmann::json nested = console_log_array_from_json(data["logs"]);
            if (!nested.empty())
                return nested;
        }
        if (data.contains("records"))
        {
            nlohmann::json nested = console_log_array_from_json(data["records"]);
            if (!nested.empty())
                return nested;
        }
        if (data.contains("items"))
        {
            nlohmann::json nested = console_log_array_from_json(data["items"]);
            if (!nested.empty())
                return nested;
        }
        if (data.contains("raw_text") && data["raw_text"].is_string())
        {
            const std::string text = data["raw_text"].get<std::string>();
            nlohmann::json parsed;
            if (parse_console_json_text(text, parsed))
                return console_log_array_from_json(parsed);
            nlohmann::json entry = nlohmann::json::object();
            entry["text"] = text;
            return nlohmann::json::array({entry});
        }
    }
    return nlohmann::json::array();
}

nlohmann::json console_log_array_from_result(const camoufox::call_result_t& r)
{
    return console_log_array_from_json(r.data);
}

std::vector<std::string> read_results_from_console(const sentinel_t& s, const char* phase, size_t max_records, const std::string& page_id, uint64_t deadline_ms)
{
    std::vector<std::string> out;
    camoufox::call_result_t r = call_console_logs_deadline(max_records, page_id, deadline_ms);
    nlohmann::json logs = console_log_array_from_result(r);
    if (r.ok && max_records != 0 && logs.is_array() && logs.size() > max_records)
    {
        nlohmann::json trimmed = nlohmann::json::array();
        for (size_t i = logs.size() - max_records; i < logs.size(); ++i)
            trimmed.push_back(logs[i]);
        logs = std::move(trimmed);
    }
    size_t inspected = 0;
    size_t prefix_hits = 0;
    size_t parse_errors = 0;
    if (r.ok)
    {
        for (const auto& e : logs)
        {
            ++inspected;
            if (!e.is_object() || !e.contains("text") || !e["text"].is_string())
                continue;
            const std::string text = e["text"].get<std::string>();
            const size_t p = text.find(kConsoleCanaryPrefix);
            if (p == std::string::npos)
                continue;
            ++prefix_hits;
            const std::string payload = text.substr(p + std::strlen(kConsoleCanaryPrefix));
            try
            {
                nlohmann::json entry = nlohmann::json::parse(payload);
                if (canary_entry_matches(entry, s))
                    append_unique_sink(out, normalize_sink_log_entry(entry));
            }
            catch (...)
            {
                ++parse_errors;
            }
        }
    }
    diag::log_tagged_fmt("dom_xss", "results_console_read token=%s page_id=%s phase=%s ok=%d deadline_ms=%llu remaining_ms=%lld logs_shape=%s inspected=%zu prefix_hits=%zu matches=%zu parse_errors=%zu err_len=%zu",
        s.token.c_str(), page_id.c_str(), phase ? phase : "", r.ok ? 1 : 0,
        static_cast<unsigned long long>(deadline_ms), remaining_until_deadline_ms(deadline_ms),
        json_shape_local(logs).c_str(),
        inspected, prefix_hits, out.size(), parse_errors, r.error.size());
    return out;
}

issue_t make_browser_certain_issue(const std::string&        type_key,
                                   const std::string&        title,
                                   const insertion_point_t&  ip,
                                   const std::string&        payload_text,
                                   const fire_result_t&      r,
                                   const scan_options_t&     opts,
                                   const std::string&        path_hint)
{
    issue_t iss;
    iss.type_key = type_key;
    iss.name = title;
    iss.severity = severity_t::high;
    iss.confidence = confidence_t::certain;
    iss.scheme = opts.scheme.empty() ? std::string("http") : opts.scheme;
    iss.host = opts.host;
    iss.port = opts.port;
    iss.path = path_hint;
    iss.parameter = ip.name;
    iss.insertion_point = ip.kind + (ip.name.empty() ? std::string() : (":" + ip.name));
    iss.seen_ms = now_ms_wall();
    iss.audit_id = opts.audit_id;
    iss.description = std::string(
        "A JavaScript-execution payload was delivered into the '") + ip.name +
        "' parameter and fired one or more sentinel-hooked sinks inside a headless browser. "
        "This is a high-confidence confirmation that the parameter is exploitable for cross-site scripting; "
        "the recorded sink log enumerates every hook (alert, eval, Function, setTimeout(string), document.write, "
        ".innerHTML setter, location assignment, etc.) that was reached by the injected expression.";
    iss.remediation = "Apply context-aware output encoding at all sinks; deploy a strict Content-Security-Policy "
        "that disallows inline event handlers and 'unsafe-inline' scripts; sanitize any DOM data flowing into "
        "innerHTML / outerHTML / document.write / eval-family APIs.";
    iss.cwe.push_back("CWE-79");
    if (type_key == "xss.dom_browser_confirmed") iss.cwe.push_back("CWE-79.1");

    evidence_t ev;
    std::ostringstream req;
    req << "Payload delivered to: " << ip.kind << ":" << ip.name << "\r\n";
    req << "Sentinel firing payload (truncated to 800 chars):\r\n";
    req << trim_payload(payload_text, 800);
    ev.request_raw = req.str();

    std::ostringstream resp;
    resp << "Browser sink hooks fired (" << r.sink_log.size() << "):\r\n";
    for (const auto& e : r.sink_log) {
        resp << "  - " << e << "\r\n";
    }
    if (!r.last_screenshot_path.empty()) {
        resp << "Screenshot: " << r.last_screenshot_path << "\r\n";
    }
    ev.response_raw = resp.str();
    ev.marker = r.sink_log.empty() ? std::string("(no sink log)") : r.sink_log.front();
    iss.evidence.push_back(std::move(ev));
    return iss;
}

bool navigate_with_init_script(const std::string& abs_url,
                               const sentinel_t&  s,
                               int                timeout_ms,
                               uint64_t           deadline_ms,
                               const std::string& page_id)
{
    std::string pre = build_pre_injection_script(s);
    constexpr int kMaxAttempts = 3;
    for (int attempt = 1; attempt <= kMaxAttempts; ++attempt) {
        if (!camoufox::ensure_ready()) {
            std::string e = camoufox::last_error();
            if (!browser_transport_retry_allowed("ensure_ready", attempt, kMaxAttempts, deadline_ms, e)) {
                if (current_err().empty())
                    set_err(e.empty() ? std::string("camoufox bridge not ready") : e);
                return false;
            }
            recover_browser_transport("ensure_ready", attempt, e, deadline_ms);
            continue;
        }
        camoufox::call_result_t add_result = add_init_script_deadline(pre, deadline_ms);
        if (!add_result.ok) {
            std::string e = add_result.error;
            diag::log_tagged_fmt("dom_xss", "add_init_script failed attempt=%d err=%s", attempt, e.c_str());
            if (!browser_transport_retry_allowed("add_init_script", attempt, kMaxAttempts, deadline_ms, e)) {
                if (current_err().empty())
                    set_err(std::string("add_init_script failed: ") + e);
                return false;
            }
            recover_browser_transport("add_init_script", attempt, e, deadline_ms);
            continue;
        }
        diag::log_tagged_fmt("dom_xss", "add_init_script ok attempt=%d token=%s page_id=%s pre_len=%zu remaining_ms=%lld",
            attempt, s.token.c_str(), page_id.c_str(), pre.size(), remaining_until_deadline_ms(deadline_ms));
        const int nav_timeout_ms = browser_navigation_timeout_for_deadline(timeout_ms, deadline_ms, "navigate");
        if (nav_timeout_ms <= 0)
            return false;
        if (camoufox::navigate(abs_url, "load", nav_timeout_ms, "default", page_id)) {
            camoufox::call_result_t probe = call_evaluate_js_deadline(build_canary_probe_js(s), true, page_id, deadline_ms);
            std::string data_tail = probe.data.is_discarded() ? std::string() : trim_payload(probe.data.dump(), 1400);
            std::string text_tail = trim_payload(probe.text, 1400);
            diag::log_tagged_fmt("dom_xss", "navigate_with_init_script post_nav_probe attempt=%d token=%s page_id=%s ok=%d data_shape=%s text_len=%zu data_tail=%s text_tail=%s",
                attempt, s.token.c_str(), page_id.c_str(), probe.ok ? 1 : 0, json_shape_local(probe.data).c_str(),
                probe.text.size(), data_tail.c_str(), text_tail.c_str());
            return true;
        }
        std::string e = camoufox::last_error();
        diag::log_tagged_fmt("dom_xss", "navigate failed attempt=%d err=%s", attempt, e.c_str());
        if (!browser_transport_retry_allowed("navigate", attempt, kMaxAttempts, deadline_ms, e)) {
            if (current_err().empty())
                set_err(std::string("navigate failed: ") + e);
            return false;
        }
        recover_browser_transport("navigate", attempt, e, deadline_ms);
    }
    set_err("navigate failed: exhausted browser transport retries");
    return false;
}

bool drive_fetch_harness(const std::string& abs_url,
                         const std::vector<uint8_t>& built_req,
                         const sentinel_t& s,
                         int timeout_ms,
                         uint64_t deadline_ms,
                         const std::string& page_id)
{
    std::string method;
    std::string uri;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    if (!extract_method_path_body(built_req, method, uri, headers, body)) {
        set_err("harness: could not parse built request");
        return false;
    }
    std::string pre = build_pre_injection_script(s);
    constexpr int kMaxAttempts = 3;
    for (int attempt = 1; attempt <= kMaxAttempts; ++attempt) {
        if (!camoufox::ensure_ready()) {
            std::string e = camoufox::last_error();
            if (!browser_transport_retry_allowed("harness_ensure_ready", attempt, kMaxAttempts, deadline_ms, e)) {
                if (current_err().empty())
                    set_err(e.empty() ? std::string("camoufox bridge not ready") : e);
                return false;
            }
            recover_browser_transport("harness_ensure_ready", attempt, e, deadline_ms);
            continue;
        }
        camoufox::call_result_t add_result = add_init_script_deadline(pre, deadline_ms);
        if (!add_result.ok) {
            std::string e = add_result.error;
            diag::log_tagged_fmt("dom_xss", "add_init_script(harness) failed attempt=%d err=%s", attempt, e.c_str());
            if (!browser_transport_retry_allowed("harness_add_init_script", attempt, kMaxAttempts, deadline_ms, e)) {
                if (current_err().empty())
                    set_err(std::string("add_init_script(harness) failed: ") + e);
                return false;
            }
            recover_browser_transport("harness_add_init_script", attempt, e, deadline_ms);
            continue;
        }
        const int nav_timeout_ms = browser_navigation_timeout_for_deadline(timeout_ms, deadline_ms, "harness_navigate");
        if (nav_timeout_ms <= 0)
            return false;
        if (!camoufox::navigate("about:blank", "load", nav_timeout_ms, "default", page_id)) {
            std::string e = camoufox::last_error();
            diag::log_tagged_fmt("dom_xss", "harness navigate(about:blank) failed attempt=%d err=%s", attempt, e.c_str());
            if (!browser_transport_retry_allowed("harness_navigate", attempt, kMaxAttempts, deadline_ms, e)) {
                if (current_err().empty())
                    set_err(std::string("harness navigate(about:blank) failed: ") + e);
                return false;
            }
            recover_browser_transport("harness_navigate", attempt, e, deadline_ms);
            continue;
        }
        std::string js = build_fetch_harness_js(method, abs_url, headers, body);
        auto r = call_evaluate_js_deadline(js, true, page_id, deadline_ms);
        if (r.ok) {
            return true;
        }
        std::string e = r.error;
        if (!browser_transport_retry_allowed("harness_evaluate_js", attempt, kMaxAttempts, deadline_ms, e)) {
            if (current_err().empty())
                set_err(std::string("harness evaluate_js failed: ") + e);
            return false;
        }
        recover_browser_transport("harness_evaluate_js", attempt, e, deadline_ms);
    }
    set_err("harness failed: exhausted browser transport retries");
    return false;
}

bool extract_results_array(const camoufox::call_result_t& r, nlohmann::json& arr)
{
    bool parsed = false;
    if (r.data.is_array()) {
        arr = r.data;
        parsed = true;
    }
    if (!parsed && r.data.is_object()) {
        if (r.data.contains("result") && r.data["result"].is_array()) {
            arr = r.data["result"];
            parsed = true;
        } else if (r.data.contains("result") && r.data["result"].is_string()) {
            try { arr = nlohmann::json::parse(r.data["result"].get<std::string>()); parsed = true; } catch (...) {}
        } else if (r.data.contains("value") && r.data["value"].is_array()) {
            arr = r.data["value"];
            parsed = true;
        } else if (r.data.contains("value") && r.data["value"].is_string()) {
            try { arr = nlohmann::json::parse(r.data["value"].get<std::string>()); parsed = true; } catch (...) {}
        }
    }
    if (!parsed && r.data.is_string()) {
        try { arr = nlohmann::json::parse(r.data.get<std::string>()); parsed = true; } catch (...) {}
    }
    if (!parsed && !r.text.empty()) {
        try { arr = nlohmann::json::parse(r.text); parsed = true; } catch (...) {}
    }
    return parsed;
}

std::vector<std::string> normalize_results_array(const nlohmann::json& arr)
{
    std::vector<std::string> out;
    if (!arr.is_array())
        return out;
    out.reserve(arr.size());
    for (const auto& e : arr)
        out.push_back(normalize_sink_log_entry(e));
    return out;
}

std::vector<std::string> read_results(const sentinel_t& s, uint64_t deadline_ms, const std::string& page_id)
{
    std::vector<std::string> out;
    std::string js = build_results_read_js(s);
    const auto before = camoufox::get_status();
    const uint64_t read_start_ms = now_ms_steady();
    const int initial_eval_timeout_ms = result_read_timeout_ms(deadline_ms);
    diag::log_tagged_fmt("dom_xss", "results_read_begin token=%s session_id=default page_id=%s expr_len=%zu deadline_ms=%llu remaining_ms=%lld eval_timeout_ms=%d state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu last_error_len=%zu",
        s.token.c_str(), page_id.c_str(), js.size(), static_cast<unsigned long long>(deadline_ms),
        remaining_until_deadline_ms(deadline_ms), initial_eval_timeout_ms,
        static_cast<int>(before.state), static_cast<unsigned long long>(before.generation),
        static_cast<unsigned long>(before.child_pid), before.child_alive ? 1 : 0,
        before.browser_open ? 1 : 0, before.page_verified ? 1 : 0,
        before.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(before.total_calls),
        static_cast<unsigned long long>(before.total_errors), before.last_error.size());
    out = read_results_from_console(s, "pre_evaluate", 200, page_id, deadline_ms);
    if (!out.empty()) {
        const auto console_after = camoufox::get_status();
        diag::log_tagged_fmt("dom_xss", "results_read_done token=%s sinks=%zu source=console_pre state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu last_error_len=%zu",
            s.token.c_str(), out.size(), static_cast<int>(console_after.state),
            static_cast<unsigned long long>(console_after.generation), static_cast<unsigned long>(console_after.child_pid),
            console_after.child_alive ? 1 : 0, console_after.browser_open ? 1 : 0, console_after.page_verified ? 1 : 0,
            console_after.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(console_after.total_calls),
            static_cast<unsigned long long>(console_after.total_errors), console_after.last_error.size());
        return out;
    }
    nlohmann::json args;
    args["expression"] = js;
    args["await_promise"] = true;
    if (!page_id.empty()) args["page_id"] = page_id;
    const uint64_t now = now_ms_steady();
    uint64_t poll_until = deadline_ms != 0 ? deadline_ms : now + 15000ULL;
    camoufox::call_result_t r;
    for (int attempt = 1; attempt <= 12; ++attempt) {
        const int eval_timeout_ms = result_read_timeout_ms(deadline_ms);
        if (deadline_ms != 0 && eval_timeout_ms <= 0)
        {
            set_err("DOM-XSS scan deadline exceeded");
            break;
        }
        const auto dispatch_status = camoufox::get_status();
        const uint64_t attempt_start_ms = now_ms_steady();
        diag::log_tagged_fmt("dom_xss", "results_read_eval_dispatch token=%s session_id=default page_id=%s attempt=%d deadline_ms=%llu remaining_ms=%lld eval_timeout_ms=%d state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d",
            s.token.c_str(), page_id.c_str(), attempt,
            static_cast<unsigned long long>(deadline_ms),
            remaining_until_deadline_ms(deadline_ms),
            eval_timeout_ms,
            static_cast<int>(dispatch_status.state),
            static_cast<unsigned long long>(dispatch_status.generation),
            static_cast<unsigned long>(dispatch_status.child_pid),
            dispatch_status.child_alive ? 1 : 0,
            dispatch_status.browser_open ? 1 : 0,
            dispatch_status.page_verified ? 1 : 0,
            dispatch_status.cleanup_pending ? 1 : 0);
        r = camoufox::call_tool("evaluate_js", args, eval_timeout_ms);
        const uint64_t request_id = bridge_meta_u64(r.data, "request_id");
        const uint64_t bridge_generation = bridge_meta_u64(r.data, "generation");
        const uint64_t bridge_child_pid = bridge_meta_u64(r.data, "child_pid");
        const bool bridge_late_result = bridge_meta_bool(r.data, "late_result");
        const std::string bridge_phase = bridge_meta_string(r.data, "phase");
        diag::log_tagged_fmt("dom_xss", "results_read_eval_result token=%s session_id=default page_id=%s attempt=%d request_id=%llu ok=%d deadline_ms=%llu remaining_ms=%lld eval_timeout_ms=%d elapsed_ms=%llu bridge_generation=%llu bridge_child_pid=%llu bridge_phase=%s late_result=%d data_shape=%s text_len=%zu err_len=%zu",
            s.token.c_str(), page_id.c_str(), attempt,
            static_cast<unsigned long long>(request_id),
            r.ok ? 1 : 0,
            static_cast<unsigned long long>(deadline_ms),
            remaining_until_deadline_ms(deadline_ms),
            eval_timeout_ms,
            static_cast<unsigned long long>(now_ms_steady() - attempt_start_ms),
            static_cast<unsigned long long>(bridge_generation),
            static_cast<unsigned long long>(bridge_child_pid),
            bridge_phase.empty() ? "<empty>" : bridge_phase.c_str(),
            bridge_late_result ? 1 : 0,
            json_shape_local(r.data).c_str(),
            r.text.size(),
            r.error.size());
        if (r.ok) {
            nlohmann::json arr;
            const bool parsed = extract_results_array(r, arr);
            if (!parsed) {
                diag::log_tagged_fmt("dom_xss", "results_read_unparsed token=%s page_id=%s attempt=%d request_id=%llu data_shape=%s text_len=%zu",
                    s.token.c_str(), page_id.c_str(), attempt, static_cast<unsigned long long>(request_id),
                    json_shape_local(r.data).c_str(), r.text.size());
            } else if (!arr.is_array()) {
                diag::log_tagged_fmt("dom_xss", "results_read_not_array token=%s page_id=%s attempt=%d request_id=%llu parsed_shape=%s",
                    s.token.c_str(), page_id.c_str(), attempt, static_cast<unsigned long long>(request_id),
                    json_shape_local(arr).c_str());
            } else {
                out = normalize_results_array(arr);
                if (!out.empty()) {
                    const auto after = camoufox::get_status();
                    diag::log_tagged_fmt("dom_xss", "results_read_done token=%s session_id=default page_id=%s request_id=%llu sinks=%zu source=evaluate attempt=%d elapsed_ms=%llu state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu last_error_len=%zu",
                        s.token.c_str(), page_id.c_str(), static_cast<unsigned long long>(request_id),
                        out.size(), attempt, static_cast<unsigned long long>(now_ms_steady() - read_start_ms),
                        static_cast<int>(after.state),
                        static_cast<unsigned long long>(after.generation), static_cast<unsigned long>(after.child_pid),
                        after.child_alive ? 1 : 0, after.browser_open ? 1 : 0, after.page_verified ? 1 : 0,
                        after.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(after.total_calls),
                        static_cast<unsigned long long>(after.total_errors), after.last_error.size());
                    return out;
                }
            }
            std::vector<std::string> console_out = read_results_from_console(s, "evaluate_empty", 300, page_id, deadline_ms);
            if (!console_out.empty()) {
                const auto console_after = camoufox::get_status();
                diag::log_tagged_fmt("dom_xss", "results_read_done token=%s sinks=%zu source=console_after_empty attempt=%d state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu last_error_len=%zu",
                    s.token.c_str(), console_out.size(), attempt, static_cast<int>(console_after.state),
                    static_cast<unsigned long long>(console_after.generation), static_cast<unsigned long>(console_after.child_pid),
                    console_after.child_alive ? 1 : 0, console_after.browser_open ? 1 : 0, console_after.page_verified ? 1 : 0,
                    console_after.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(console_after.total_calls),
                    static_cast<unsigned long long>(console_after.total_errors), console_after.last_error.size());
                return console_out;
            }
            camoufox::call_result_t replay = call_evaluate_js_deadline(build_active_dom_replay_js(s), true, page_id, deadline_ms);
            std::string replay_data = replay.data.is_discarded() ? std::string() : trim_payload(replay.data.dump(), 1400);
            std::string replay_text = trim_payload(replay.text, 1400);
            diag::log_tagged_fmt("dom_xss", "results_read_dom_replay token=%s attempt=%d ok=%d data_shape=%s text_len=%zu data=%s text=%s",
                s.token.c_str(), attempt, replay.ok ? 1 : 0, json_shape_local(replay.data).c_str(), replay.text.size(),
                replay_data.c_str(), replay_text.c_str());
            if (replay.ok) {
                const int replay_timeout_ms = result_read_timeout_ms(deadline_ms);
                if (deadline_ms != 0 && replay_timeout_ms <= 0)
                {
                    set_err("DOM-XSS scan deadline exceeded");
                    break;
                }
                camoufox::call_result_t replay_read = camoufox::call_tool("evaluate_js", args, replay_timeout_ms);
                const uint64_t replay_request_id = bridge_meta_u64(replay_read.data, "request_id");
                if (replay_read.ok) {
                    nlohmann::json replay_arr;
                    const bool replay_parsed = extract_results_array(replay_read, replay_arr);
                    if (replay_parsed && replay_arr.is_array()) {
                        out = normalize_results_array(replay_arr);
                        if (!out.empty()) {
                            const auto replay_after = camoufox::get_status();
                            diag::log_tagged_fmt("dom_xss", "results_read_done token=%s session_id=default page_id=%s request_id=%llu sinks=%zu source=dom_replay attempt=%d elapsed_ms=%llu state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu last_error_len=%zu",
                                s.token.c_str(), page_id.c_str(), static_cast<unsigned long long>(replay_request_id),
                                out.size(), attempt, static_cast<unsigned long long>(now_ms_steady() - read_start_ms),
                                static_cast<int>(replay_after.state),
                                static_cast<unsigned long long>(replay_after.generation), static_cast<unsigned long>(replay_after.child_pid),
                                replay_after.child_alive ? 1 : 0, replay_after.browser_open ? 1 : 0, replay_after.page_verified ? 1 : 0,
                                replay_after.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(replay_after.total_calls),
                                static_cast<unsigned long long>(replay_after.total_errors), replay_after.last_error.size());
                            return out;
                        }
                    }
                    diag::log_tagged_fmt("dom_xss", "results_read_dom_replay_empty token=%s page_id=%s attempt=%d request_id=%llu parsed=%d shape=%s text_len=%zu",
                        s.token.c_str(), page_id.c_str(), attempt, static_cast<unsigned long long>(replay_request_id),
                        replay_parsed ? 1 : 0, json_shape_local(replay_read.data).c_str(), replay_read.text.size());
                } else {
                    diag::log_tagged_fmt("dom_xss", "results_read_dom_replay_read_failed token=%s page_id=%s attempt=%d request_id=%llu err=%s data_shape=%s text_len=%zu timeout_ms=%d",
                        s.token.c_str(), page_id.c_str(), attempt, static_cast<unsigned long long>(replay_request_id),
                        replay_read.error.c_str(), json_shape_local(replay_read.data).c_str(), replay_read.text.size(),
                        replay_timeout_ms);
                }
                std::vector<std::string> replay_console_out = read_results_from_console(s, "dom_replay", 300, page_id, deadline_ms);
                if (!replay_console_out.empty()) {
                    const auto replay_console_after = camoufox::get_status();
                    diag::log_tagged_fmt("dom_xss", "results_read_done token=%s sinks=%zu source=console_after_dom_replay attempt=%d state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu last_error_len=%zu",
                        s.token.c_str(), replay_console_out.size(), attempt, static_cast<int>(replay_console_after.state),
                        static_cast<unsigned long long>(replay_console_after.generation), static_cast<unsigned long>(replay_console_after.child_pid),
                        replay_console_after.child_alive ? 1 : 0, replay_console_after.browser_open ? 1 : 0, replay_console_after.page_verified ? 1 : 0,
                        replay_console_after.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(replay_console_after.total_calls),
                        static_cast<unsigned long long>(replay_console_after.total_errors), replay_console_after.last_error.size());
                    return replay_console_out;
                }
            }
            camoufox::call_result_t probe = call_evaluate_js_deadline(build_canary_probe_js(s), true, page_id, deadline_ms);
            std::string data_tail = probe.data.is_discarded() ? std::string() : trim_payload(probe.data.dump(), 1400);
            std::string text_tail = trim_payload(probe.text, 1400);
            diag::log_tagged_fmt("dom_xss", "results_read_zero_sinks token=%s attempt=%d probe_ok=%d probe_shape=%s probe_text_len=%zu probe_data=%s probe_text=%s",
                s.token.c_str(), attempt, probe.ok ? 1 : 0, json_shape_local(probe.data).c_str(), probe.text.size(),
                data_tail.c_str(), text_tail.c_str());
        } else {
            const auto after = camoufox::get_status();
            diag::log_tagged_fmt("dom_xss", "results_read_failed token=%s session_id=default page_id=%s attempt=%d request_id=%llu timeout_ms=%d deadline_ms=%llu remaining_ms=%lld elapsed_ms=%llu err=%s data_shape=%s text_len=%zu bridge_phase=%s late_result=%d state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu last_error_len=%zu",
                s.token.c_str(), page_id.c_str(), attempt, static_cast<unsigned long long>(request_id),
                eval_timeout_ms, static_cast<unsigned long long>(deadline_ms), remaining_until_deadline_ms(deadline_ms),
                static_cast<unsigned long long>(now_ms_steady() - read_start_ms),
                r.error.c_str(), json_shape_local(r.data).c_str(), r.text.size(),
                bridge_phase.empty() ? "<empty>" : bridge_phase.c_str(), bridge_late_result ? 1 : 0,
                static_cast<int>(after.state), static_cast<unsigned long long>(after.generation),
                static_cast<unsigned long>(after.child_pid), after.child_alive ? 1 : 0,
                after.browser_open ? 1 : 0, after.page_verified ? 1 : 0,
                after.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(after.total_calls),
                static_cast<unsigned long long>(after.total_errors), after.last_error.size());
        }
        if (!r.ok && is_browser_transport_error(r.error)) {
            out = read_results_from_console(s, attempt == 1 ? "evaluate_transport_failure_1" : "evaluate_transport_failure_n", 300, page_id, deadline_ms);
            if (!out.empty()) {
                const auto console_after = camoufox::get_status();
                diag::log_tagged_fmt("dom_xss", "results_read_done token=%s sinks=%zu source=console_after_transport_failure attempt=%d state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu last_error_len=%zu",
                    s.token.c_str(), out.size(), attempt, static_cast<int>(console_after.state),
                    static_cast<unsigned long long>(console_after.generation), static_cast<unsigned long>(console_after.child_pid),
                    console_after.child_alive ? 1 : 0, console_after.browser_open ? 1 : 0, console_after.page_verified ? 1 : 0,
                    console_after.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(console_after.total_calls),
                    static_cast<unsigned long long>(console_after.total_errors), console_after.last_error.size());
                return out;
            }
            set_err(std::string("results read failed: ") + r.error);
            return out;
        }
        if (remaining_until_deadline_ms(deadline_ms) <= 250 || now_ms_steady() >= poll_until)
            break;
        if (!sleep_before_deadline(150, deadline_ms))
            break;
    }
    if (!r.ok && !r.error.empty())
        set_err(std::string("results read failed: ") + r.error);
    if (out.empty())
    {
        camoufox::call_result_t probe = call_evaluate_js_deadline(build_canary_probe_js(s), true, page_id, deadline_ms);
        std::string data_tail = probe.data.is_discarded() ? std::string() : trim_payload(probe.data.dump(), 1400);
        std::string text_tail = trim_payload(probe.text, 1400);
        diag::log_tagged_fmt("dom_xss", "results_read_final_empty token=%s probe_ok=%d probe_shape=%s probe_text_len=%zu probe_data=%s probe_text=%s",
            s.token.c_str(), probe.ok ? 1 : 0, json_shape_local(probe.data).c_str(), probe.text.size(),
            data_tail.c_str(), text_tail.c_str());
    }
    const auto after = camoufox::get_status();
    diag::log_tagged_fmt("dom_xss", "results_read_done token=%s session_id=default page_id=%s sinks=%zu source=empty elapsed_ms=%llu deadline_ms=%llu remaining_ms=%lld state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu last_error_len=%zu",
        s.token.c_str(), page_id.c_str(), out.size(),
        static_cast<unsigned long long>(now_ms_steady() - read_start_ms),
        static_cast<unsigned long long>(deadline_ms),
        remaining_until_deadline_ms(deadline_ms),
        static_cast<int>(after.state),
        static_cast<unsigned long long>(after.generation), static_cast<unsigned long>(after.child_pid),
        after.child_alive ? 1 : 0, after.browser_open ? 1 : 0, after.page_verified ? 1 : 0,
        after.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(after.total_calls),
        static_cast<unsigned long long>(after.total_errors), after.last_error.size());
    return out;
}

}

sentinel_t make_sentinel()
{
    diag::log_tagged_fmt("dom_xss", "make_sentinel entry");
    sentinel_t s;
    uint8_t buf[12] = {0};
    if (!random_bytes(buf, sizeof(buf))) {
        diag::log_tagged_fmt("dom_xss", "make_sentinel bcrypt_failed using_prng");
        std::mt19937_64 rng(static_cast<uint64_t>(now_ms_wall()) ^ sentinel_counter().fetch_add(1));
        for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = static_cast<uint8_t>(rng() & 0xFF);
    }
    s.token = bytes_to_hex(buf, sizeof(buf));
    s.canary_fn      = std::string("__aida_xss_canary_")  + s.token + "__";
    s.results_global = std::string("__aida_xss_results_") + s.token + "__";
    diag::log_tagged_fmt("dom_xss", "make_sentinel done token=%s", s.token.c_str());
    return s;
}

std::string build_pre_injection_script(const sentinel_t& s)
{
    diag::log_tagged_fmt("dom_xss", "build_pre_injection_script entry token=%s", s.token.c_str());
    std::ostringstream os;
    os << "(function(){";
    os << "try{";
    os << "var RG=" << js_string_literal(s.results_global) << ";";
    os << "var CF=" << js_string_literal(s.canary_fn) << ";";
    os << "var TOK=" << js_string_literal(s.token) << ";";
    os << "var DG='__aida_dom_xss_diag_'+TOK;";
    os << "var mark=function(k,v){try{var d=window[DG];if(!d){d={token:TOK,initAt:Date.now(),events:[]};Object.defineProperty(window,DG,{value:d,writable:false,configurable:false,enumerable:false});}d[k]=v;d.lastAt=Date.now();if(d.events&&d.events.length<64)d.events.push({k:k,v:v,t:Date.now(),rs:String(document.readyState||'')});}catch(e){}};";
    os << "mark('initReadyState',String(document.readyState||''));";
    os << "if(!window[RG]){";
    os <<   "Object.defineProperty(window,RG,{value:[],writable:false,configurable:false,enumerable:false});";
    os << "}";
    os << "var emit=function(entry){try{console.log(" << js_string_literal(std::string(kConsoleCanaryPrefix)) << "+JSON.stringify(entry));}catch(e){}};";
    os << "var push=function(id,src){try{var entry={id:id,src:String(src||'inline').slice(0,400),t:Date.now(),token:TOK};window[RG].push(entry);mark('lastPushId',String(id||'').slice(0,120));mark('pushCount',window[RG].length);emit(entry);}catch(e){mark('pushError',String(e&&e.message?e.message:e).slice(0,160));}};";
    os << "if(!window[CF]){";
    os <<   "Object.defineProperty(window,CF,{value:push,writable:false,configurable:false,enumerable:false});";
    os << "}";
    os << "mark('resultsIsArray',Array.isArray(window[RG]));";
    os << "mark('canaryType',typeof window[CF]);";

    os << "var stub=function(label){return function(){try{var a=arguments;var s=(a.length>0)?String(a[0]).slice(0,200):'';push(label+':'+TOK,s);}catch(e){}};};";

    os << "var def=function(obj,name,val){try{Object.defineProperty(obj,name,{value:val,writable:false,configurable:false,enumerable:false});}catch(e){try{obj[name]=val;}catch(e2){}}};";

    os << "def(window,'alert',stub('alert'));";
    os << "def(window,'confirm',stub('confirm'));";
    os << "def(window,'prompt',stub('prompt'));";
    os << "def(window,'print',stub('print'));";

    os << "try{";
    os <<   "var origEval=window.eval;";
    os <<   "window.eval=function(x){push('eval:'+TOK,String(x).slice(0,200));try{return origEval.call(window,x);}catch(e){return undefined;}};";
    os << "}catch(e){}";

    os << "try{";
    os <<   "var OrigFunc=window.Function;";
    os <<   "var NewFunc=function(){var args=Array.prototype.slice.call(arguments);push('Function:'+TOK,args.join('|').slice(0,200));try{return OrigFunc.apply(this,args);}catch(e){return function(){};}};";
    os <<   "NewFunc.prototype=OrigFunc.prototype;";
    os <<   "window.Function=NewFunc;";
    os << "}catch(e){}";

    os << "try{";
    os <<   "var oST=window.setTimeout;";
    os <<   "window.setTimeout=function(f,t){if(typeof f==='string'){push('setTimeout-str:'+TOK,String(f).slice(0,200));}return oST.apply(window,arguments);};";
    os <<   "var oSI=window.setInterval;";
    os <<   "window.setInterval=function(f,t){if(typeof f==='string'){push('setInterval-str:'+TOK,String(f).slice(0,200));}return oSI.apply(window,arguments);};";
    os << "}catch(e){}";

    os << "try{";
    os <<   "var oDW=document.write;";
    os <<   "document.write=function(){var s=Array.prototype.join.call(arguments,'');push('document.write:'+TOK,String(s).slice(0,200));return oDW.apply(document,arguments);};";
    os <<   "var oDWL=document.writeln;";
    os <<   "document.writeln=function(){var s=Array.prototype.join.call(arguments,'');push('document.writeln:'+TOK,String(s).slice(0,200));return oDWL.apply(document,arguments);};";
    os << "}catch(e){}";

    os << "try{";
    os <<   "var EP=Element.prototype;";
    os <<   "var orig=Object.getOwnPropertyDescriptor(EP,'innerHTML');";
    os <<   "if(orig&&orig.set){";
    os <<     "var oSet=orig.set;";
    os <<     "Object.defineProperty(EP,'innerHTML',{configurable:true,enumerable:true,";
    os <<       "get:orig.get,";
    os <<       "set:function(v){push('innerHTML:'+TOK,String(v).slice(0,200));return oSet.call(this,v);}";
    os <<     "});";
    os <<     "mark('innerHTMLHook','installed');";
    os <<   "}else{mark('innerHTMLHook','missing_descriptor');}";
    os <<   "var origOuter=Object.getOwnPropertyDescriptor(EP,'outerHTML');";
    os <<   "if(origOuter&&origOuter.set){";
    os <<     "var oSetO=origOuter.set;";
    os <<     "Object.defineProperty(EP,'outerHTML',{configurable:true,enumerable:true,";
    os <<       "get:origOuter.get,";
    os <<       "set:function(v){push('outerHTML:'+TOK,String(v).slice(0,200));return oSetO.call(this,v);}";
    os <<     "});";
    os <<   "}";
    os <<   "var origInsertAdj=EP.insertAdjacentHTML;";
    os <<   "if(origInsertAdj){";
    os <<     "EP.insertAdjacentHTML=function(pos,html){push('insertAdjacentHTML:'+TOK,String(html).slice(0,200));return origInsertAdj.call(this,pos,html);};";
    os <<   "}";
    os <<   "var origSetAttr=EP.setAttribute;";
    os <<   "if(origSetAttr){";
    os <<     "EP.setAttribute=function(n,v){try{if(typeof n==='string'&&n.length>2&&n.slice(0,2).toLowerCase()==='on'){push('setAttribute('+n+'):'+TOK,String(v).slice(0,200));}}catch(e){}return origSetAttr.call(this,n,v);};";
    os <<   "}";
    os << "}catch(e){}";

    os << "try{";
    os <<   "var origHrefDesc=Object.getOwnPropertyDescriptor(Location.prototype,'href');";
    os <<   "if(origHrefDesc&&origHrefDesc.set){";
    os <<     "var oHrefSet=origHrefDesc.set;";
    os <<     "Object.defineProperty(Location.prototype,'href',{configurable:true,enumerable:true,";
    os <<       "get:origHrefDesc.get,";
    os <<       "set:function(v){try{var sv=String(v);if(sv.toLowerCase().indexOf('javascript:')===0){push('location.href-javascript:'+TOK,sv.slice(0,200));}else{push('location.href:'+TOK,sv.slice(0,200));}}catch(e){}return oHrefSet.call(this,v);}";
    os <<     "});";
    os <<   "}";
    os <<   "var origAssign=Location.prototype.assign;";
    os <<   "if(origAssign){";
    os <<     "Location.prototype.assign=function(v){try{var sv=String(v);if(sv.toLowerCase().indexOf('javascript:')===0){push('location.assign-javascript:'+TOK,sv.slice(0,200));}else{push('location.assign:'+TOK,sv.slice(0,200));}}catch(e){}return origAssign.call(this,v);};";
    os <<   "}";
    os <<   "var origReplace=Location.prototype.replace;";
    os <<   "if(origReplace){";
    os <<     "Location.prototype.replace=function(v){try{var sv=String(v);if(sv.toLowerCase().indexOf('javascript:')===0){push('location.replace-javascript:'+TOK,sv.slice(0,200));}else{push('location.replace:'+TOK,sv.slice(0,200));}}catch(e){}return origReplace.call(this,v);};";
    os <<   "}";
    os << "}catch(e){}";

    os << "try{";
    os <<   "var origCreate=document.createElement;";
    os <<   "document.createElement=function(name){var el=origCreate.call(document,name);try{if(typeof name==='string'){var ln=name.toLowerCase();if(ln==='script'){var origSrcDesc=Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype,'src');if(origSrcDesc&&origSrcDesc.set){Object.defineProperty(el,'src',{configurable:true,enumerable:true,get:origSrcDesc.get,set:function(v){push('script.src:'+TOK,String(v).slice(0,200));return origSrcDesc.set.call(this,v);}});}}else if(ln==='iframe'){var origSrcDoc=Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype,'srcdoc');if(origSrcDoc&&origSrcDoc.set){Object.defineProperty(el,'srcdoc',{configurable:true,enumerable:true,get:origSrcDoc.get,set:function(v){push('iframe.srcdoc:'+TOK,String(v).slice(0,200));return origSrcDoc.set.call(this,v);}});}}}}catch(e){}return el;};";
    os << "}catch(e){}";

    os << "try{";
    os <<   "if(window.jQuery&&window.jQuery.fn){";
    os <<     "var origHtml=window.jQuery.fn.html;";
    os <<     "window.jQuery.fn.html=function(v){if(arguments.length>0){push('jQuery.html:'+TOK,String(v).slice(0,200));}return origHtml.apply(this,arguments);};";
    os <<     "var origAppend=window.jQuery.fn.append;";
    os <<     "window.jQuery.fn.append=function(){try{var s='';for(var i=0;i<arguments.length;++i)s+=String(arguments[i]);push('jQuery.append:'+TOK,s.slice(0,200));}catch(e){}return origAppend.apply(this,arguments);};";
    os <<   "}";
    os << "}catch(e){}";

    os << "try{";
    os <<   "var origPostMessage=window.postMessage;";
    os <<   "window.postMessage=function(){try{push('postMessage:'+TOK,String(arguments[0]).slice(0,200));}catch(e){}return origPostMessage.apply(this,arguments);};";
    os << "}catch(e){}";

    os << "}catch(outer){try{console.log('aida_xss init err:'+(outer&&outer.message?outer.message:outer));}catch(e){}}";
    os << "})();";
    std::string script = os.str();
    diag::log_tagged_fmt("dom_xss", "build_pre_injection_script done script_len=%zu", script.size());
    return script;
}

std::vector<payload_set_t> default_payload_sets()
{
    diag::log_tagged_fmt("dom_xss", "default_payload_sets entry");
    std::vector<payload_set_t> sets;

    payload_set_t polyglot;
    polyglot.name = "polyglot";
    polyglot.templates = {
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk={CANARY_FN}('polyglot1') )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!><sVg/<sVg/oNloAd={CANARY_FN}('polyglot1b')//>",
        "\">'><img src=x id=p2 onerror={CANARY_FN}('polyglot2')>",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+{CANARY_FN}(\"polyglot3\")//'>",
        "';alert(1);{CANARY_FN}('polyglot4');//'\"</script>{CANARY_FN}('polyglot4b');//",
        "<svg><script>123<1>{CANARY_FN}('polyglot5')</script>",
        "</noscript></style></title></textarea></iframe><img src=1 onerror={CANARY_FN}('polyglot6')>"
    };
    sets.push_back(std::move(polyglot));

    payload_set_t standard;
    standard.name = "standard";
    standard.templates = {
        R"(<img src=x onerror="try{{CANARY_FN}('s0')}catch(e){};try{console.log('AIDA_DOM_XSS_CANARY:'+JSON.stringify({id:'img:{CANARY}',src:'standard',token:'{CANARY}'}))}catch(e){}">)",
        "<script>{CANARY_FN}('s1')</script>",
        "<img src=x onerror={CANARY_FN}('s2')>",
        "<svg onload={CANARY_FN}('s3')>",
        "<iframe srcdoc='<script>parent.{CANARY_FN}(&quot;s4&quot;)</script>'></iframe>",
        "\"><script>{CANARY_FN}('s5')</script>",
        "';{CANARY_FN}('s6');//",
        "\"-{CANARY_FN}('s7')-\"",
        "<body onload={CANARY_FN}('s8')>",
        "<details ontoggle={CANARY_FN}('s9') open>",
        "<marquee onstart={CANARY_FN}('s10')>",
        "<input autofocus onfocus={CANARY_FN}('s11')>",
        "<a href=\"javascript:{CANARY_FN}('s12')\">x</a>"
    };
    sets.push_back(std::move(standard));

    payload_set_t dom_only;
    dom_only.name = "dom_only";
    dom_only.templates = {
        "#javascript:{CANARY_FN}('h1')",
        "?q=<svg onload={CANARY_FN}('q1')>",
        "\"</script><script>{CANARY_FN}('q2')</script>",
        "<img/src=`x`/onerror={CANARY_FN}('d1')>",
        "<svg><animate onbegin={CANARY_FN}('d2') attributeName=x dur=1s>",
        "<object data=\"javascript:{CANARY_FN}('d3')\">",
        "<form><button formaction=\"javascript:{CANARY_FN}('d4')\">x</button></form>"
    };
    sets.push_back(std::move(dom_only));

    diag::log_tagged_fmt("dom_xss", "default_payload_sets done sets=%zu", sets.size());
    return sets;
}

fire_result_t fire_payload(const insertion_point_t& ip,
                           const std::string&       payload_template,
                           const sentinel_t&        s,
                           bool                     capture_screenshot,
                           int                      per_payload_timeout_ms,
                           const std::string&       scheme_hint,
                           uint16_t                 port_hint,
                           uint64_t                 absolute_deadline_ms)
{
    std::lock_guard<std::recursive_mutex> global_lk(browser_global_mtx());
    bridge_activity_scope_t bridge_activity("dom_xss.fire_payload");
    fire_result_t out;
    clear_err();

    if (!camoufox::ensure_ready()) {
        out.error = "camoufox bridge not ready";
        set_err(out.error);
        return out;
    }
    if (!ip.build) {
        out.error = "insertion_point has no build()";
        set_err(out.error);
        return out;
    }

    std::string canary_fn_literal = js_string_literal(s.canary_fn);
    std::string payload = replace_all(payload_template, "{CANARY_FN_LIT}", canary_fn_literal);
    payload = replace_all(payload, "{CANARY_FN}", s.canary_fn);
    payload = replace_all(payload, "{CANARY}",     s.token);
    const std::string payload_hash = stable_hash64(payload);
    diag::log_tagged_fmt("dom_xss", "fire_payload build_begin kind=%s param=%s token=%s template_len=%zu payload_len=%zu payload_hash=%s template_preview=%s",
        ip.kind.c_str(), ip.name.c_str(), s.token.c_str(), payload_template.size(), payload.size(),
        payload_hash.c_str(), trim_payload(payload_template, 220).c_str());

    auto built = ip.build(payload);
    if (built.empty()) {
        out.error = "ip.build returned empty";
        set_err(out.error);
        return out;
    }

    std::string scheme = scheme_hint;
    std::string host;
    uint16_t    port = port_hint;
    std::string request_method;
    std::string request_uri;
    std::string request_hash;
    {
        std::string raw(reinterpret_cast<const char*>(built.data()), built.size());
        request_hash = stable_hash64(raw);
        auto rl = parse_request_line_local(raw);
        if (!rl.valid) {
            out.error = "failed to parse built request line";
            set_err(out.error);
            return out;
        }
        request_method = rl.method;
        request_uri = rl.uri;
        std::string host_header;
        extract_host_header(raw, rl.headers_offset, host_header);
        if (!host_header.empty()) {
            auto colon = host_header.find(':');
            host = (colon == std::string::npos) ? host_header : host_header.substr(0, colon);
            if (colon != std::string::npos) {
                try {
                    uint16_t parsed = static_cast<uint16_t>(std::stoul(host_header.substr(colon + 1)));
                    if (parsed != 0) port = parsed;
                } catch (...) {}
            }
        }
        if (scheme.empty()) scheme = "http";
        if (port == 0) port = (scheme == "https") ? 443 : 80;
        diag::log_tagged_fmt("dom_xss", "fire_payload request_built kind=%s param=%s token=%s method=%s uri_len=%zu uri_hash=%s host_header_len=%zu host=%s scheme=%s port=%u raw_len=%zu raw_hash=%s",
            ip.kind.c_str(), ip.name.c_str(), s.token.c_str(), request_method.c_str(), request_uri.size(),
            stable_hash64(request_uri).c_str(), host_header.size(), host.c_str(), scheme.c_str(),
            static_cast<unsigned>(port), raw.size(), request_hash.c_str());
    }

    {
        std::string check;
        check += scheme;
        check += "://";
        check += host;
        check += "/";
        if (!scope::in_scope(check)) {
            std::string alt = (scheme == "https") ? std::string("http://") : std::string("https://");
            std::string alt_check = alt + host + "/";
            if (!scope::in_scope(alt_check)) {
                out.error = "target out of scope";
                diag::log_tagged_fmt("dom_xss", "scope deny: %s", host.c_str());
                return out;
            } else {
                scheme = (scheme == "https") ? std::string("http") : std::string("https");
                if (scheme == "https" && (port == 80 || port == 0)) port = 443;
                else if (scheme == "http" && (port == 443 || port == 0)) port = 80;
            }
        }
    }

    std::string abs_url = assemble_url_from_built(built, scheme, port);
    if (abs_url.empty()) {
        out.error = "could not assemble absolute url from built request";
        set_err(out.error);
        return out;
    }

    if (absolute_deadline_ms != 0 && remaining_until_deadline_ms(absolute_deadline_ms) <= 0)
    {
        out.error = "DOM-XSS scan deadline exceeded";
        set_err(out.error);
        diag::log_tagged_fmt("dom_xss", "fire_payload deadline_before_reset kind=%s param=%s remaining_ms=%lld",
            ip.kind.c_str(), ip.name.c_str(), remaining_until_deadline_ms(absolute_deadline_ms));
        return out;
    }

    camoufox::call_result_t reset_result = absolute_deadline_ms == 0
        ? camoufox::call_result_t{}
        : reset_browser_state_deadline(absolute_deadline_ms);
    const bool reset_ok = absolute_deadline_ms == 0 ? camoufox::reset_browser_state() : reset_result.ok;
    if (!reset_ok) {
        out.error = absolute_deadline_ms == 0 ? camoufox::last_error() : reset_result.error;
        if (out.error.empty())
            out.error = "reset_browser_state failed";
        set_err(out.error);
        diag::log_tagged_fmt("dom_xss", "fire_payload reset_failed kind=%s param=%s err=%s data_shape=%s",
            ip.kind.c_str(), ip.name.c_str(), out.error.c_str(), json_shape_local(reset_result.data).c_str());
        return out;
    }

    uint64_t t0 = now_ms_steady();
    int effective_payload_timeout_ms = bounded_payload_timeout_ms(per_payload_timeout_ms);
    if (absolute_deadline_ms != 0)
    {
        const long long remaining_ms = remaining_until_deadline_ms(absolute_deadline_ms);
        if (remaining_ms <= 6000)
        {
            out.error = "DOM-XSS scan deadline exceeded";
            set_err(out.error);
            diag::log_tagged_fmt("dom_xss", "fire_payload deadline_before_dispatch kind=%s param=%s remaining_ms=%lld",
                ip.kind.c_str(), ip.name.c_str(), remaining_ms);
            return out;
        }
        const long long max_payload_ms = remaining_ms - 5000;
        if (effective_payload_timeout_ms > max_payload_ms)
            effective_payload_timeout_ms = static_cast<int>(max_payload_ms);
        if (effective_payload_timeout_ms < 1000)
        {
            out.error = "DOM-XSS scan deadline exceeded";
            set_err(out.error);
            diag::log_tagged_fmt("dom_xss", "fire_payload deadline_insufficient kind=%s param=%s remaining_ms=%lld effective_timeout_ms=%d",
                ip.kind.c_str(), ip.name.c_str(), remaining_ms, effective_payload_timeout_ms);
            return out;
        }
    }
    uint64_t deadline_ms = t0 + static_cast<uint64_t>(effective_payload_timeout_ms) + 5000ULL;
    if (absolute_deadline_ms != 0 && absolute_deadline_ms < deadline_ms)
        deadline_ms = absolute_deadline_ms;
    browser_page_scope_t page_scope("fire", s);
    if (!page_scope.ok()) {
        out.error = "new_page failed";
        set_err(out.error);
        return out;
    }
    diag::log_tagged_fmt("dom_xss", "fire_payload browser_start kind=%s param=%s page_id=%s mode=%s url_len=%zu timeout_ms=%d bounded_timeout_ms=%d effective_timeout_ms=%d absolute_deadline_ms=%llu deadline_remaining_ms=%lld",
        ip.kind.c_str(), ip.name.c_str(),
        page_scope.page_id.c_str(),
        (ip.kind == "query" || ip.kind == "path") ? "navigate" : "fetch_harness",
        abs_url.size(), per_payload_timeout_ms, bounded_payload_timeout_ms(per_payload_timeout_ms),
        effective_payload_timeout_ms,
        static_cast<unsigned long long>(absolute_deadline_ms),
        remaining_until_deadline_ms(deadline_ms));
    bool ok = false;
    if (ip.kind == "query" || ip.kind == "path") {
        ok = navigate_with_init_script(abs_url, s, effective_payload_timeout_ms, deadline_ms, page_scope.page_id);
    } else {
        ok = drive_fetch_harness(abs_url, built, s, effective_payload_timeout_ms, deadline_ms, page_scope.page_id);
    }
    if (!ok) {
        out.error = current_err();
        return out;
    }

    {
        camoufox::call_result_t probe = call_evaluate_js_deadline(build_canary_probe_js(s), true, page_scope.page_id, deadline_ms);
        std::string data_tail = probe.data.is_discarded() ? std::string() : trim_payload(probe.data.dump(), 1200);
        std::string text_tail = trim_payload(probe.text, 1200);
        const auto st = camoufox::get_status();
        diag::log_tagged_fmt("dom_xss", "fire_payload canary_probe token=%s ok=%d data_shape=%s text_len=%zu data_tail=%s text_tail=%s state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d errors=%llu",
            s.token.c_str(), probe.ok ? 1 : 0, json_shape_local(probe.data).c_str(), probe.text.size(),
            data_tail.c_str(), text_tail.c_str(), static_cast<int>(st.state),
            static_cast<unsigned long long>(st.generation), static_cast<unsigned long>(st.child_pid),
            st.child_alive ? 1 : 0, st.browser_open ? 1 : 0, st.page_verified ? 1 : 0,
            st.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(st.total_errors));
    }

    if (!sleep_before_deadline(300, deadline_ms)) {
        out.error = "DOM-XSS scan deadline exceeded";
        set_err(out.error);
        diag::log_tagged_fmt("dom_xss", "fire_payload deadline_before_result_read kind=%s param=%s remaining_ms=%lld",
            ip.kind.c_str(), ip.name.c_str(), remaining_until_deadline_ms(deadline_ms));
        return out;
    }

    out.sink_log = read_results(s, deadline_ms, page_scope.page_id);
    if (out.sink_log.empty()) {
        std::string e = current_err();
        if (is_browser_transport_error(e)) {
            out.error = e;
            return out;
        }
    }
    out.canary_fired = !out.sink_log.empty();
    out.ok = true;
    if (out.canary_fired) clear_err();

    if (out.canary_fired && capture_screenshot) {
        std::string sp = make_screenshot_path(s.token.substr(0, 8));
        if (camoufox::take_screenshot(sp, true, "default", page_scope.page_id)) {
            out.last_screenshot_path = sp;
        }
    }

    uint64_t elapsed = now_ms_steady() - t0;
    diag::log_tagged_fmt("dom_xss", "fire_payload kind=%s param=%s fired=%d sinks=%zu elapsed=%llums",
                         ip.kind.c_str(), ip.name.c_str(),
                         out.canary_fired ? 1 : 0,
                         out.sink_log.size(),
                         static_cast<unsigned long long>(elapsed));
    return out;
}

size_t scan_insertion_point(const insertion_point_t& ip, const scan_options_t& opts)
{
    diag::log_tagged_fmt("dom_xss", "scan_insertion_point entry kind=%s param=%s host=%s",
        ip.kind.c_str(), ip.name.c_str(), opts.host.c_str());
    clear_err();
    if (opts.cancelled && opts.cancelled()) {
        set_err("DOM-XSS scan cancelled");
        return 0;
    }
    if (opts.deadline_ms != 0 && now_ms_steady() >= opts.deadline_ms) {
        set_err("DOM-XSS scan deadline exceeded");
        return 0;
    }
    if (!camoufox::ensure_ready()) {
        diag::log_tagged("dom_xss", "scan_insertion_point: camoufox not ready, skipping");
        set_err("camoufox bridge not ready");
        return 0;
    }
    last_scan_ms().store(now_ms_wall());
    sentinel_t s = make_sentinel();

    std::vector<payload_set_t> all = default_payload_sets();
    std::vector<const payload_set_t*> active;
    for (auto& set : all) {
        if (set.name == "polyglot" && opts.include_polyglot) active.push_back(&set);
        else if (set.name == "standard" && opts.include_standard) active.push_back(&set);
        else if (set.name == "dom_only" && opts.include_dom_only) active.push_back(&set);
    }
    if (active.empty()) {
        diag::log_tagged_fmt("dom_xss", "scan_insertion_point no_active_sets");
        return 0;
    }

    std::string path_hint;
    {
        std::vector<uint8_t> probe_built = ip.build ? ip.build(std::string()) : std::vector<uint8_t>();
        if (!probe_built.empty()) {
            std::string raw(reinterpret_cast<const char*>(probe_built.data()), probe_built.size());
            auto rl = parse_request_line_local(raw);
            if (rl.valid) path_hint = rl.uri;
        }
    }

    diag::log_tagged_fmt("dom_xss", "scan_insertion_point active_sets=%zu path_hint=%s", active.size(), path_hint.c_str());
    size_t fired = 0;
    size_t issued = 0;
    size_t budget = opts.max_payloads_per_point;
    if (budget == 0) budget = 16;
    if (budget > 64) budget = 64;
    size_t browser_failures = 0;
    size_t max_browser_failures = opts.max_browser_failures == 0 ? 1 : opts.max_browser_failures;

    for (const auto* set : active) {
        if (fired >= budget) break;
        size_t set_index = 0;
        for (const auto& tpl : set->templates) {
            if (fired >= budget) break;
            if (opts.cancelled && opts.cancelled()) {
                set_err("DOM-XSS scan cancelled");
                diag::log_tagged_fmt("dom_xss", "scan_insertion_point cancelled kind=%s param=%s fired=%zu issued=%zu",
                    ip.kind.c_str(), ip.name.c_str(), fired, issued);
                return issued;
            }
            if (opts.deadline_ms != 0 && now_ms_steady() >= opts.deadline_ms) {
                set_err("DOM-XSS scan deadline exceeded");
                diag::log_tagged_fmt("dom_xss", "scan_insertion_point deadline kind=%s param=%s fired=%zu issued=%zu",
                    ip.kind.c_str(), ip.name.c_str(), fired, issued);
                return issued;
            }
            ++fired;
            ++set_index;
            diag::log_tagged_fmt("dom_xss", "scan_insertion_point firing kind=%s param=%s set=%s set_index=%zu global_index=%zu budget=%zu template_len=%zu template_hash=%s",
                ip.kind.c_str(), ip.name.c_str(), set->name.c_str(), set_index, fired, budget,
                tpl.size(), stable_hash64(tpl).c_str());
            auto r = fire_payload(ip, tpl, s, opts.capture_screenshots, opts.per_payload_timeout_ms,
                                  opts.scheme, opts.port, opts.deadline_ms);
            if (!r.ok) {
                std::string e = r.error.empty() ? current_err() : r.error;
                diag::log_tagged_fmt("dom_xss", "scan_insertion_point payload_failed kind=%s param=%s set=%s set_index=%zu global_index=%zu error_len=%zu error=%s",
                    ip.kind.c_str(), ip.name.c_str(), set->name.c_str(), set_index, fired,
                    e.size(), e.c_str());
                if (is_browser_transport_error(e)) {
                    ++browser_failures;
                    if (e.empty()) e = "DOM-XSS browser execution failed";
                    set_err(e);
                    diag::log_tagged_fmt("dom_xss", "scan_insertion_point browser_abort kind=%s param=%s failures=%zu fired=%zu error=%s",
                        ip.kind.c_str(), ip.name.c_str(), browser_failures, fired, e.c_str());
                    if (opts.abort_on_browser_error || browser_failures >= max_browser_failures) return issued;
                }
                continue;
            }
            if (!r.canary_fired)
            {
                diag::log_tagged_fmt("dom_xss", "scan_insertion_point no_sink kind=%s param=%s set=%s set_index=%zu global_index=%zu sink_entries=%zu error_len=%zu",
                    ip.kind.c_str(), ip.name.c_str(), set->name.c_str(), set_index, fired,
                    r.sink_log.size(), r.error.size());
                continue;
            }
            std::string type_key = (set->name == "dom_only") ? "xss.dom_browser_confirmed"
                                                              : "xss.reflected_browser_confirmed";
            std::string title = (set->name == "dom_only")
                ? std::string("Cross-Site Scripting (DOM, browser-confirmed)")
                : std::string("Cross-Site Scripting (browser-confirmed)");
            std::string payload = replace_all(tpl, "{CANARY_FN_LIT}", js_string_literal(s.canary_fn));
            payload = replace_all(payload, "{CANARY_FN}", s.canary_fn);
            payload = replace_all(payload, "{CANARY}", s.token);
            auto iss = make_browser_certain_issue(type_key, title, ip, payload, r, opts, path_hint);
            issue_store::add(std::move(iss));
            ++issued;
            diag::log_tagged_fmt("dom_xss", "scan_insertion_point confirmed kind=%s param=%s type=%s issued=%zu",
                ip.kind.c_str(), ip.name.c_str(), type_key.c_str(), issued);
            return issued;
        }
    }
    diag::log_tagged_fmt("dom_xss", "scan_insertion_point done fired=%zu issued=%zu", fired, issued);
    return issued;
}

bool confirm_reflected_in_browser(const std::string&        url,
                                  const std::string&        canary_marker,
                                  std::vector<std::string>& out_sink_log,
                                  int                       per_payload_timeout_ms)
{
    diag::log_tagged_fmt("dom_xss", "confirm_reflected_in_browser entry url=%s canary=%s timeout_ms=%d",
        url.c_str(), canary_marker.c_str(), per_payload_timeout_ms);
    std::lock_guard<std::recursive_mutex> global_lk(browser_global_mtx());
    bridge_activity_scope_t bridge_activity("dom_xss.confirm_reflected_in_browser");
    out_sink_log.clear();
    if (!camoufox::ensure_ready()) {
        diag::log_tagged_fmt("dom_xss", "confirm_reflected_in_browser camoufox_not_ready");
        return false;
    }
    if (url.empty()) {
        diag::log_tagged_fmt("dom_xss", "confirm_reflected_in_browser empty_url");
        return false;
    }

    sentinel_t s = make_sentinel();
    if (!canary_marker.empty()) {
        s.token = canary_marker;
    }
    if (!camoufox::reset_browser_state()) {
        std::string err = camoufox::last_error();
        if (err.empty())
            err = "reset_browser_state failed";
        set_err(err);
        diag::log_tagged_fmt("dom_xss", "confirm_reflected_in_browser reset_failed url=%s err=%s",
            url.c_str(), err.c_str());
        return false;
    }
    const uint64_t deadline_ms = payload_deadline_ms(per_payload_timeout_ms);
    browser_page_scope_t page_scope("confirm", s);
    if (!page_scope.ok()) {
        set_err("new_page failed");
        diag::log_tagged_fmt("dom_xss", "confirm_reflected_in_browser new_page_failed url=%s", url.c_str());
        return false;
    }
    if (!navigate_with_init_script(url, s, per_payload_timeout_ms, deadline_ms, page_scope.page_id)) {
        diag::log_tagged_fmt("dom_xss", "confirm_reflected_in_browser navigate_failed url=%s", url.c_str());
        return false;
    }
    if (!sleep_before_deadline(250, deadline_ms)) {
        set_err("DOM-XSS scan deadline exceeded");
        return false;
    }
    out_sink_log = read_results(s, deadline_ms, page_scope.page_id);
    diag::log_tagged_fmt("dom_xss", "confirm_reflected_in_browser done url=%s fired=%d sinks=%zu",
        url.c_str(), !out_sink_log.empty() ? 1 : 0, out_sink_log.size());
    return !out_sink_log.empty();
}

bool initialize()
{
    diag::log_tagged_fmt("dom_xss", "initialize entry");
    bool expected = false;
    if (!initialized_flag().compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("dom_xss", "initialize already_initialized");
        return true;
    }
    diag::log_tagged("dom_xss", "engine initialized");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("dom_xss", "shutdown entry");
    initialized_flag().store(false);
    diag::log_tagged_fmt("dom_xss", "shutdown done");
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    std::string e = err_slot();
    diag::log_tagged_fmt("dom_xss", "last_error queried val=%s", e.c_str());
    return e;
}

}
}
}
