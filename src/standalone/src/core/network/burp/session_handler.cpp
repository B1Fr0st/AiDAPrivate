#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>

#ifdef small
#undef small
#endif

#include "session_handler.hpp"
#include "audit_http.hpp"
#include "burp_events.hpp"

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <regex>
#include <sstream>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace session_handler {

namespace {

struct state_t
{
    std::mutex                          macros_mtx;
    std::vector<macro_t>                macros;
    std::atomic<uint64_t>               next_macro_id{1};
    std::mutex                          rules_mtx;
    std::vector<session_rule_t>         rules;
    std::atomic<uint64_t>               next_rule_id{1};
    std::atomic<bool>                   initialized{false};
    std::mutex                          err_mtx;
    std::string                         last_err;
};

state_t& s()
{
    static state_t st;
    return st;
}

void set_err(const std::string& msg)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    st.last_err = msg;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string base64_encode_internal(const uint8_t* data, size_t len)
{
    static const char* k = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= len) {
        const uint32_t t = (uint32_t(data[i]) << 16) | (uint32_t(data[i+1]) << 8) | uint32_t(data[i+2]);
        out.push_back(k[(t >> 18) & 63]);
        out.push_back(k[(t >> 12) & 63]);
        out.push_back(k[(t >> 6) & 63]);
        out.push_back(k[t & 63]);
        i += 3;
    }
    const size_t rem = len - i;
    if (rem == 1) {
        const uint32_t t = uint32_t(data[i]) << 16;
        out.push_back(k[(t >> 18) & 63]);
        out.push_back(k[(t >> 12) & 63]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        const uint32_t t = (uint32_t(data[i]) << 16) | (uint32_t(data[i+1]) << 8);
        out.push_back(k[(t >> 18) & 63]);
        out.push_back(k[(t >> 12) & 63]);
        out.push_back(k[(t >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

bool base64_decode_internal(const std::string& in, std::vector<uint8_t>& out)
{
    auto idx = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
        if (c >= '0' && c <= '9') return 52 + (c - '0');
        if (c == '+' || c == '-') return 62;
        if (c == '/' || c == '_') return 63;
        return -1;
    };
    out.clear();
    out.reserve((in.size() * 3) / 4 + 4);
    uint32_t buffer = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=') break;
        if (c == ' ' || c == '\r' || c == '\n' || c == '\t') continue;
        const int v = idx(c);
        if (v < 0) return false;
        buffer = (buffer << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return true;
}

std::string ascii_lower(const std::string& v)
{
    std::string out;
    out.reserve(v.size());
    for (char c : v) {
        if (c >= 'A' && c <= 'Z') out.push_back(static_cast<char>(c + 32));
        else                       out.push_back(c);
    }
    return out;
}

bool split_response(const exchange_observed_t& ex,
                    std::string& body,
                    std::string& headers_block,
                    std::string& full_url)
{
    body.assign(ex.resp_body.begin(), ex.resp_body.end());
    std::ostringstream hs;
    for (const auto& h : ex.resp_headers) {
        hs << h.first << ": " << h.second << "\r\n";
    }
    headers_block = hs.str();
    full_url.clear();
    if (!ex.scheme.empty() && !ex.host.empty()) {
        full_url = ex.scheme + "://" + ex.host;
        if (ex.port != 0 &&
            !(ex.scheme == "http" && ex.port == 80) &&
            !(ex.scheme == "https" && ex.port == 443)) {
            full_url += ":" + std::to_string(ex.port);
        }
        full_url += ex.path;
        if (!ex.query.empty()) {
            if (!ex.query.empty() && ex.query[0] != '?') full_url.push_back('?');
            full_url.append(ex.query);
        }
    }
    return true;
}

bool extract_value(const extract_t& ext, const exchange_observed_t& ex, std::string& out_value)
{
    std::string body, headers_block, full_url;
    split_response(ex, body, headers_block, full_url);
    std::string scope;
    if (ext.from == "resp_body") scope = body;
    else if (ext.from == "resp_headers") scope = headers_block;
    else if (ext.from == "resp_url") scope = full_url;
    else return false;
    if (ext.regex.empty()) return false;
    try {
        std::regex re(ext.regex, std::regex::ECMAScript);
        std::smatch m;
        if (!std::regex_search(scope, m, re)) return false;
        if (ext.group < 0 || ext.group >= static_cast<int>(m.size())) return false;
        out_value = m[static_cast<size_t>(ext.group)].str();
        return true;
    } catch (...) {
        return false;
    }
}

void substitute_tokens(std::string& text, const std::map<std::string, std::string>& kv)
{
    if (text.empty() || kv.empty()) return;
    std::string out;
    out.reserve(text.size());
    size_t i = 0;
    while (i < text.size()) {
        if (i + 2 < text.size() && text[i] == '{' && text[i + 1] == '{') {
            size_t end = text.find("}}", i + 2);
            if (end != std::string::npos) {
                std::string name = text.substr(i + 2, end - i - 2);
                size_t l = 0;
                while (l < name.size() && (name[l] == ' ' || name[l] == '\t')) ++l;
                size_t r = name.size();
                while (r > l && (name[r - 1] == ' ' || name[r - 1] == '\t')) --r;
                name = name.substr(l, r - l);
                auto it = kv.find(name);
                if (it != kv.end()) {
                    out.append(it->second);
                    i = end + 2;
                    continue;
                }
            }
        }
        out.push_back(text[i]);
        ++i;
    }
    text.swap(out);
}

bool split_request_segments(std::string& raw,
                            std::string& request_line,
                            std::string& headers_block,
                            std::string& body,
                            bool& crlf)
{
    crlf = raw.find("\r\n") != std::string::npos;
    size_t header_end = raw.find("\r\n\r\n");
    size_t term_len = 4;
    if (header_end == std::string::npos) {
        header_end = raw.find("\n\n");
        term_len = 2;
        if (header_end == std::string::npos) return false;
    }
    std::string head = raw.substr(0, header_end);
    body = raw.substr(header_end + term_len);
    size_t first_eol = head.find("\r\n");
    if (first_eol == std::string::npos) first_eol = head.find('\n');
    if (first_eol == std::string::npos) {
        request_line = head;
        headers_block.clear();
        return true;
    }
    request_line = head.substr(0, first_eol);
    size_t hdr_start = first_eol + ((head[first_eol] == '\r' && first_eol + 1 < head.size() && head[first_eol + 1] == '\n') ? 2 : 1);
    headers_block = head.substr(hdr_start);
    return true;
}

std::string rebuild_request(const std::string& request_line,
                            const std::string& headers_block,
                            const std::string& body,
                            bool crlf)
{
    const std::string sep = crlf ? "\r\n" : "\n";
    std::string out;
    out.reserve(request_line.size() + headers_block.size() + body.size() + 8);
    out.append(request_line);
    out.append(sep);
    if (!headers_block.empty()) {
        out.append(headers_block);
        if (headers_block.size() < sep.size() ||
            headers_block.compare(headers_block.size() - sep.size(), sep.size(), sep) != 0) {
            out.append(sep);
        }
    }
    out.append(sep);
    out.append(body);
    return out;
}

nlohmann::json extract_to_json(const extract_t& e)
{
    nlohmann::json j;
    j["name"]  = e.name;
    j["from"]  = e.from;
    j["regex"] = e.regex;
    j["group"] = e.group;
    return j;
}

bool extract_from_json(const nlohmann::json& j, extract_t& out)
{
    if (!j.is_object()) return false;
    out.name = j.value("name", std::string());
    out.from = j.value("from", std::string("resp_body"));
    out.regex = j.value("regex", std::string());
    out.group = j.value("group", 1);
    return true;
}

nlohmann::json step_to_json(const macro_step_t& s_in)
{
    nlohmann::json j;
    j["label"] = s_in.label;
    j["scheme"] = s_in.scheme;
    j["host"] = s_in.host;
    j["port"] = s_in.port;
    j["raw_request_b64"] = base64_encode_internal(s_in.raw_request.data(), s_in.raw_request.size());
    j["timeout_ms"] = s_in.timeout_ms;
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& e : s_in.extracts) arr.push_back(extract_to_json(e));
    j["extracts"] = arr;
    return j;
}

bool step_from_json(const nlohmann::json& j, macro_step_t& out)
{
    if (!j.is_object()) return false;
    out.label = j.value("label", std::string());
    out.scheme = j.value("scheme", std::string("https"));
    out.host = j.value("host", std::string());
    out.port = static_cast<uint16_t>(j.value("port", 443));
    out.timeout_ms = j.value("timeout_ms", 15000);
    out.raw_request.clear();
    if (j.contains("raw_request_b64") && j["raw_request_b64"].is_string()) {
        std::vector<uint8_t> dec;
        if (base64_decode_internal(j["raw_request_b64"].get<std::string>(), dec)) out.raw_request = std::move(dec);
    }
    if (j.contains("extracts") && j["extracts"].is_array()) {
        for (const auto& je : j["extracts"]) {
            extract_t e;
            if (extract_from_json(je, e)) out.extracts.push_back(e);
        }
    }
    return true;
}

nlohmann::json macro_to_json(const macro_t& m)
{
    nlohmann::json j;
    j["id"] = m.id;
    j["name"] = m.name;
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& st_step : m.steps) arr.push_back(step_to_json(st_step));
    j["steps"] = arr;
    nlohmann::json kvj;
    for (const auto& kv : m.last_extracted_values) kvj[kv.first] = kv.second;
    j["last_extracted_values"] = kvj;
    j["last_run_ms"] = m.last_run_ms;
    j["ok_last_run"] = m.ok_last_run;
    return j;
}

bool macro_from_json(const nlohmann::json& j, macro_t& out)
{
    if (!j.is_object()) return false;
    out = macro_t{};
    out.id = j.value("id", static_cast<uint64_t>(0));
    out.name = j.value("name", std::string());
    if (j.contains("steps") && j["steps"].is_array()) {
        for (const auto& js : j["steps"]) {
            macro_step_t mstep;
            if (step_from_json(js, mstep)) out.steps.push_back(mstep);
        }
    }
    if (j.contains("last_extracted_values") && j["last_extracted_values"].is_object()) {
        for (auto it = j["last_extracted_values"].begin(); it != j["last_extracted_values"].end(); ++it) {
            if (it.value().is_string()) out.last_extracted_values[it.key()] = it.value().get<std::string>();
        }
    }
    out.last_run_ms = j.value("last_run_ms", static_cast<uint64_t>(0));
    out.ok_last_run = j.value("ok_last_run", false);
    return true;
}

nlohmann::json rule_to_json(const session_rule_t& r)
{
    nlohmann::json j;
    j["id"]               = r.id;
    j["name"]             = r.name;
    j["match"]            = match_label(r.match);
    j["match_pattern"]    = r.match_pattern;
    j["match_status"]     = r.match_status;
    j["macro_id"]         = r.macro_id;
    j["replace_in_url"]   = r.replace_in_url;
    j["replace_in_headers"] = r.replace_in_headers;
    j["replace_in_body"]  = r.replace_in_body;
    j["active"]           = r.active;
    return j;
}

bool rule_from_json(const nlohmann::json& j, session_rule_t& out)
{
    if (!j.is_object()) return false;
    out = session_rule_t{};
    out.id = j.value("id", static_cast<uint64_t>(0));
    out.name = j.value("name", std::string());
    parse_match(j.value("match", std::string("url_regex")), out.match);
    out.match_pattern = j.value("match_pattern", std::string());
    out.match_status = j.value("match_status", 0);
    out.macro_id = j.value("macro_id", static_cast<uint64_t>(0));
    out.replace_in_url = j.value("replace_in_url", true);
    out.replace_in_headers = j.value("replace_in_headers", true);
    out.replace_in_body = j.value("replace_in_body", true);
    out.active = j.value("active", true);
    return true;
}

std::string storage_base()
{
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
    return base;
}

}

const char* match_label(sh_match_t m)
{
    switch (m) {
        case sh_match_t::url_regex:       return "url_regex";
        case sh_match_t::response_status: return "response_status";
        case sh_match_t::response_regex:  return "response_regex";
    }
    return "url_regex";
}

bool parse_match(const std::string& s_in, sh_match_t& out)
{
    const std::string lc = ascii_lower(s_in);
    if (lc == "url_regex") { out = sh_match_t::url_regex; return true; }
    if (lc == "response_status") { out = sh_match_t::response_status; return true; }
    if (lc == "response_regex") { out = sh_match_t::response_regex; return true; }
    return false;
}

bool initialize()
{
    auto& st = s();
    bool expected = false;
    if (!st.initialized.compare_exchange_strong(expected, true)) return true;
    load_from_disk();
    diag::log_tagged("burp", "session_handler_initialized");
    return true;
}

void shutdown()
{
    auto& st = s();
    if (!st.initialized.exchange(false)) return;
    save_to_disk();
}

uint64_t add_macro(macro_t m)
{
    auto& st = s();
    if (m.id == 0) m.id = st.next_macro_id.fetch_add(1, std::memory_order_acq_rel);
    else if (m.id >= st.next_macro_id.load()) st.next_macro_id.store(m.id + 1, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk(st.macros_mtx);
        st.macros.push_back(m);
    }
    save_to_disk();
    return m.id;
}

bool remove_macro(uint64_t id)
{
    auto& st = s();
    bool removed = false;
    {
        std::lock_guard<std::mutex> lk(st.macros_mtx);
        for (auto it = st.macros.begin(); it != st.macros.end(); ++it) {
            if (it->id == id) { st.macros.erase(it); removed = true; break; }
        }
    }
    if (removed) save_to_disk();
    return removed;
}

bool update_macro(const macro_t& m)
{
    auto& st = s();
    bool ok = false;
    {
        std::lock_guard<std::mutex> lk(st.macros_mtx);
        for (auto& e : st.macros) {
            if (e.id == m.id) { e = m; ok = true; break; }
        }
    }
    if (ok) save_to_disk();
    return ok;
}

std::vector<macro_t> list_macros()
{
    auto& st = s();
    std::vector<macro_t> snap;
    {
        std::lock_guard<std::mutex> lk(st.macros_mtx);
        snap = st.macros;
    }
    return snap;
}

bool get_macro(uint64_t id, macro_t& out)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.macros_mtx);
    for (const auto& m : st.macros) {
        if (m.id == id) { out = m; return true; }
    }
    return false;
}

bool run_macro(uint64_t id, std::map<std::string, std::string>& out_values)
{
    macro_t snap;
    if (!get_macro(id, snap)) {
        set_err("run_macro: macro not found");
        return false;
    }
    std::map<std::string, std::string> kv;
    bool any_failed = false;
    for (auto& step : snap.steps) {
        if (step.host.empty()) { any_failed = true; continue; }
        std::vector<uint8_t> req = step.raw_request;
        if (!kv.empty()) {
            std::string as_text(req.begin(), req.end());
            std::string rline, hblock, body;
            bool crlf = true;
            if (split_request_segments(as_text, rline, hblock, body, crlf)) {
                substitute_tokens(rline, kv);
                substitute_tokens(hblock, kv);
                substitute_tokens(body, kv);
                as_text = rebuild_request(rline, hblock, body, crlf);
            } else {
                substitute_tokens(as_text, kv);
            }
            req.assign(as_text.begin(), as_text.end());
        }
        audit_http::send_options_t opts;
        opts.timeout_ms = step.timeout_ms;
        opts.follow_redirects = false;
        opts.enforce_scope = false;
        const bool tls = (ascii_lower(step.scheme) == "https");
        const auto resp = audit_http::send(req, step.host, step.port, tls, opts);
        if (!resp) { any_failed = true; continue; }
        for (const auto& e : step.extracts) {
            std::string v;
            if (extract_value(e, *resp, v) && !e.name.empty()) kv[e.name] = v;
        }
    }
    snap.last_extracted_values = kv;
    snap.last_run_ms = now_ms();
    snap.ok_last_run = !any_failed;
    update_macro(snap);
    out_values = kv;
    return !any_failed;
}

uint64_t add_rule(session_rule_t r)
{
    auto& st = s();
    if (r.id == 0) r.id = st.next_rule_id.fetch_add(1, std::memory_order_acq_rel);
    else if (r.id >= st.next_rule_id.load()) st.next_rule_id.store(r.id + 1, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk(st.rules_mtx);
        st.rules.push_back(r);
    }
    save_to_disk();
    return r.id;
}

bool remove_rule(uint64_t id)
{
    auto& st = s();
    bool removed = false;
    {
        std::lock_guard<std::mutex> lk(st.rules_mtx);
        for (auto it = st.rules.begin(); it != st.rules.end(); ++it) {
            if (it->id == id) { st.rules.erase(it); removed = true; break; }
        }
    }
    if (removed) save_to_disk();
    return removed;
}

bool update_rule(const session_rule_t& r)
{
    auto& st = s();
    bool ok = false;
    {
        std::lock_guard<std::mutex> lk(st.rules_mtx);
        for (auto& e : st.rules) {
            if (e.id == r.id) { e = r; ok = true; break; }
        }
    }
    if (ok) save_to_disk();
    return ok;
}

std::vector<session_rule_t> list_rules()
{
    auto& st = s();
    std::vector<session_rule_t> snap;
    {
        std::lock_guard<std::mutex> lk(st.rules_mtx);
        snap = st.rules;
    }
    return snap;
}

bool apply_rules(std::vector<uint8_t>& raw_request,
                 const std::string& url, int last_status)
{
    auto& st = s();
    std::vector<session_rule_t> rules_snap;
    {
        std::lock_guard<std::mutex> lk(st.rules_mtx);
        rules_snap = st.rules;
    }
    bool modified = false;
    for (const auto& r : rules_snap) {
        if (!r.active) continue;
        bool match_hit = false;
        if (r.match == sh_match_t::url_regex) {
            if (r.match_pattern.empty()) continue;
            try {
                std::regex re(r.match_pattern, std::regex::ECMAScript | std::regex::icase);
                if (std::regex_search(url, re)) match_hit = true;
            } catch (...) {}
        } else if (r.match == sh_match_t::response_status) {
            if (last_status != 0 && last_status == r.match_status) match_hit = true;
        } else if (r.match == sh_match_t::response_regex) {
            try {
                std::regex re(r.match_pattern, std::regex::ECMAScript | std::regex::icase);
                std::string txt(raw_request.begin(), raw_request.end());
                if (std::regex_search(txt, re)) match_hit = true;
            } catch (...) {}
        }
        if (!match_hit) continue;

        std::map<std::string, std::string> values;
        if (!run_macro(r.macro_id, values)) continue;
        if (values.empty()) continue;

        std::string text(raw_request.begin(), raw_request.end());
        std::string rline, hblock, body;
        bool crlf = true;
        if (!split_request_segments(text, rline, hblock, body, crlf)) continue;
        if (r.replace_in_url) substitute_tokens(rline, values);
        if (r.replace_in_headers) substitute_tokens(hblock, values);
        if (r.replace_in_body) substitute_tokens(body, values);
        const std::string rebuilt = rebuild_request(rline, hblock, body, crlf);
        raw_request.assign(rebuilt.begin(), rebuilt.end());
        modified = true;
    }
    return modified;
}

std::string storage_path_macros()
{
    return storage_base() + "\\macros.json";
}

std::string storage_path_rules()
{
    return storage_base() + "\\session_rules.json";
}

bool save_to_disk()
{
    auto& st = s();
    {
        nlohmann::json arr = nlohmann::json::array();
        {
            std::lock_guard<std::mutex> lk(st.macros_mtx);
            for (const auto& m : st.macros) arr.push_back(macro_to_json(m));
        }
        std::ofstream out(storage_path_macros(), std::ios::binary | std::ios::trunc);
        if (!out) { set_err("failed to write macros.json"); return false; }
        const std::string dump = arr.dump(2);
        out.write(dump.data(), static_cast<std::streamsize>(dump.size()));
    }
    {
        nlohmann::json arr = nlohmann::json::array();
        {
            std::lock_guard<std::mutex> lk(st.rules_mtx);
            for (const auto& r : st.rules) arr.push_back(rule_to_json(r));
        }
        std::ofstream out(storage_path_rules(), std::ios::binary | std::ios::trunc);
        if (!out) { set_err("failed to write session_rules.json"); return false; }
        const std::string dump = arr.dump(2);
        out.write(dump.data(), static_cast<std::streamsize>(dump.size()));
    }
    return true;
}

bool load_from_disk()
{
    auto& st = s();
    {
        std::ifstream in(storage_path_macros(), std::ios::binary);
        if (in) {
            std::stringstream ss;
            ss << in.rdbuf();
            const std::string data = ss.str();
            if (!data.empty()) {
                nlohmann::json arr;
                try { arr = nlohmann::json::parse(data, nullptr, false); } catch (...) {}
                if (!arr.is_discarded() && arr.is_array()) {
                    std::vector<macro_t> loaded;
                    uint64_t max_id = 0;
                    for (const auto& j : arr) {
                        macro_t m;
                        if (macro_from_json(j, m)) {
                            if (m.id > max_id) max_id = m.id;
                            loaded.push_back(m);
                        }
                    }
                    std::lock_guard<std::mutex> lk(st.macros_mtx);
                    st.macros = std::move(loaded);
                    if (max_id >= st.next_macro_id.load())
                        st.next_macro_id.store(max_id + 1, std::memory_order_release);
                }
            }
        }
    }
    {
        std::ifstream in(storage_path_rules(), std::ios::binary);
        if (in) {
            std::stringstream ss;
            ss << in.rdbuf();
            const std::string data = ss.str();
            if (!data.empty()) {
                nlohmann::json arr;
                try { arr = nlohmann::json::parse(data, nullptr, false); } catch (...) {}
                if (!arr.is_discarded() && arr.is_array()) {
                    std::vector<session_rule_t> loaded;
                    uint64_t max_id = 0;
                    for (const auto& j : arr) {
                        session_rule_t r;
                        if (rule_from_json(j, r)) {
                            if (r.id > max_id) max_id = r.id;
                            loaded.push_back(r);
                        }
                    }
                    std::lock_guard<std::mutex> lk(st.rules_mtx);
                    st.rules = std::move(loaded);
                    if (max_id >= st.next_rule_id.load())
                        st.next_rule_id.store(max_id + 1, std::memory_order_release);
                }
            }
        }
    }
    return true;
}

std::string last_error()
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    return st.last_err;
}

}
}
}
