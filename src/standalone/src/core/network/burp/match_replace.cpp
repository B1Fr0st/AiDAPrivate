#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>

#ifdef small
#undef small
#endif

#include "match_replace.hpp"

#include "../../../helpers/diag_log.hpp"

#include <atomic>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <regex>
#include <sstream>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace match_replace {

namespace {

struct state_t
{
    std::mutex                  mtx;
    std::vector<rule_t>         rules;
    std::atomic<uint64_t>       next_id{1};
    std::atomic<bool>           initialized{false};
    std::mutex                  err_mtx;
    std::string                 last_err;
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

bool split_request(const std::string& raw,
                   std::string& request_line,
                   std::string& headers_block,
                   std::string& body)
{
    diag::log_tagged_fmt("match_replace", "split_request entry raw_len=%zu", raw.size());
    request_line.clear();
    headers_block.clear();
    body.clear();
    size_t header_end = raw.find("\r\n\r\n");
    size_t header_term_len = 4;
    if (header_end == std::string::npos) {
        header_end = raw.find("\n\n");
        header_term_len = 2;
        if (header_end == std::string::npos) {
            diag::log_tagged_fmt("match_replace", "split_request error no_header_terminator");
            return false;
        }
    }
    const std::string head = raw.substr(0, header_end);
    body = raw.substr(header_end + header_term_len);
    size_t first_line_end = head.find("\r\n");
    if (first_line_end == std::string::npos) first_line_end = head.find('\n');
    if (first_line_end == std::string::npos) {
        request_line = head;
        headers_block.clear();
    } else {
        request_line = head.substr(0, first_line_end);
        size_t hdr_off = first_line_end + ((head[first_line_end] == '\r' && first_line_end + 1 < head.size() && head[first_line_end + 1] == '\n') ? 2 : 1);
        headers_block = head.substr(hdr_off);
    }
    diag::log_tagged_fmt("match_replace", "split_request ok request_line_len=%zu headers_len=%zu body_len=%zu",
        request_line.size(), headers_block.size(), body.size());
    return true;
}

std::string join_request(const std::string& request_line,
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

bool detect_crlf(const std::string& raw)
{
    return raw.find("\r\n") != std::string::npos;
}

bool host_filter_matches(const std::string& host_filter, const std::string& host)
{
    if (host_filter.empty()) return true;
    try {
        std::regex re(host_filter, std::regex::ECMAScript | std::regex::icase);
        return std::regex_search(host, re);
    } catch (...) {
        return false;
    }
}

bool scheme_filter_matches(const std::string& scheme_filter, const std::string& scheme)
{
    if (scheme_filter.empty()) return true;
    return ascii_lower(scheme_filter) == ascii_lower(scheme);
}

bool apply_rule(const rule_t& r, std::string& text, bool& applied_once)
{
    diag::log_tagged_fmt("match_replace", "apply_rule entry id=%llu label='%s' regex=%d text_len=%zu",
        static_cast<unsigned long long>(r.id), r.label.c_str(), (int)r.regex, text.size());
    applied_once = false;
    if (!r.active) {
        diag::log_tagged_fmt("match_replace", "apply_rule id=%llu inactive skipping", static_cast<unsigned long long>(r.id));
        return true;
    }
    if (r.regex) {
        diag::log_tagged_fmt("match_replace", "apply_rule id=%llu regex_mode pattern_len=%zu replacement_len=%zu",
            static_cast<unsigned long long>(r.id), r.match_regex.size(), r.replacement.size());
        std::regex re;
        try {
            const auto flags = r.case_insensitive
                ? (std::regex::ECMAScript | std::regex::icase)
                : std::regex::ECMAScript;
            re = std::regex(r.match_regex, flags);
        } catch (...) {
            diag::log_tagged_fmt("match_replace", "apply_rule error invalid_regex id=%llu", static_cast<unsigned long long>(r.id));
            set_err("invalid regex: " + r.match_regex);
            return false;
        }
        std::string out;
        try {
            out = std::regex_replace(text, re, r.replacement, std::regex_constants::format_default);
        } catch (...) {
            diag::log_tagged_fmt("match_replace", "apply_rule error regex_replace_threw id=%llu", static_cast<unsigned long long>(r.id));
            set_err("regex_replace threw on rule " + r.label);
            return false;
        }
        if (out != text) {
            text.swap(out);
            applied_once = true;
            diag::log_tagged_fmt("match_replace", "apply_rule regex_applied id=%llu new_text_len=%zu", static_cast<unsigned long long>(r.id), text.size());
        } else {
            diag::log_tagged_fmt("match_replace", "apply_rule regex_no_change id=%llu", static_cast<unsigned long long>(r.id));
        }
        return true;
    }
    std::string needle = r.match_regex;
    if (needle.empty()) {
        diag::log_tagged_fmt("match_replace", "apply_rule literal_empty_needle id=%llu skipping", static_cast<unsigned long long>(r.id));
        return true;
    }
    diag::log_tagged_fmt("match_replace", "apply_rule literal_mode id=%llu needle_len=%zu case_insensitive=%d",
        static_cast<unsigned long long>(r.id), needle.size(), (int)r.case_insensitive);
    std::string haystack = text;
    std::string search_h = haystack;
    std::string search_n = needle;
    if (r.case_insensitive) {
        search_h = ascii_lower(haystack);
        search_n = ascii_lower(needle);
    }
    size_t pos = 0;
    bool changed = false;
    std::string out;
    out.reserve(text.size());
    while (pos < haystack.size()) {
        size_t found = search_h.find(search_n, pos);
        if (found == std::string::npos) {
            out.append(haystack.substr(pos));
            break;
        }
        out.append(haystack.substr(pos, found - pos));
        out.append(r.replacement);
        pos = found + needle.size();
        changed = true;
    }
    if (changed) {
        text.swap(out);
        applied_once = true;
        diag::log_tagged_fmt("match_replace", "apply_rule literal_applied id=%llu new_text_len=%zu", static_cast<unsigned long long>(r.id), text.size());
    } else {
        diag::log_tagged_fmt("match_replace", "apply_rule literal_no_match id=%llu", static_cast<unsigned long long>(r.id));
    }
    return true;
}

std::vector<rule_t> snapshot_rules()
{
    auto& st = s();
    std::vector<rule_t> snap;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        snap = st.rules;
    }
    return snap;
}

void bump_hit_count(uint64_t id)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.mtx);
    for (auto& r : st.rules) {
        if (r.id == id) { r.hit_count++; break; }
    }
}

bool apply_set(std::vector<uint8_t>& raw,
               const std::string& host,
               const std::string& scheme,
               bool is_request)
{
    diag::log_tagged_fmt("match_replace", "apply_set entry host=%s scheme=%s is_request=%d raw_len=%zu",
        host.c_str(), scheme.c_str(), (int)is_request, raw.size());
    if (raw.empty()) {
        diag::log_tagged_fmt("match_replace", "apply_set empty_raw returning");
        return false;
    }
    std::string text(raw.begin(), raw.end());
    const bool crlf = detect_crlf(text);
    std::string request_line, headers_block, body;
    const bool has_headers = split_request(text, request_line, headers_block, body);
    if (!has_headers) {
        diag::log_tagged_fmt("match_replace", "apply_set error split_failed host=%s", host.c_str());
        return false;
    }

    const auto rules = snapshot_rules();
    diag::log_tagged_fmt("match_replace", "apply_set rules_count=%zu host=%s", rules.size(), host.c_str());
    bool any_changed = false;

    auto run_on_segment = [&](match_kind_t kind, std::string& segment) -> bool {
        for (const auto& r : rules) {
            if (!r.active) continue;
            if (r.target != kind && r.target != match_kind_t::all) continue;
            if (!host_filter_matches(r.host_filter, host)) continue;
            if (!scheme_filter_matches(r.scheme_filter, scheme)) continue;
            bool changed = false;
            if (!apply_rule(r, segment, changed)) continue;
            if (changed) { bump_hit_count(r.id); any_changed = true; }
        }
        return true;
    };

    if (is_request) {
        std::string url_segment;
        std::string method;
        std::string version;
        {
            size_t first_sp = request_line.find(' ');
            size_t last_sp = request_line.rfind(' ');
            if (first_sp != std::string::npos && last_sp != std::string::npos && first_sp < last_sp) {
                method = request_line.substr(0, first_sp);
                url_segment = request_line.substr(first_sp + 1, last_sp - first_sp - 1);
                version = request_line.substr(last_sp + 1);
            } else {
                url_segment = request_line;
            }
        }
        run_on_segment(match_kind_t::request_url, url_segment);
        run_on_segment(match_kind_t::request_headers, headers_block);
        run_on_segment(match_kind_t::request_body, body);
        if (method.empty()) {
            request_line = url_segment;
        } else {
            request_line = method + " " + url_segment + " " + version;
        }
    } else {
        run_on_segment(match_kind_t::response_headers, headers_block);
        run_on_segment(match_kind_t::response_body, body);
    }

    if (!any_changed) {
        diag::log_tagged_fmt("match_replace", "apply_set no_changes host=%s", host.c_str());
        return false;
    }
    const std::string joined = join_request(request_line, headers_block, body, crlf);
    raw.assign(joined.begin(), joined.end());
    diag::log_tagged_fmt("match_replace", "apply_set modified host=%s new_raw_len=%zu", host.c_str(), raw.size());
    return true;
}

const char* kind_to_str(match_kind_t k)
{
    switch (k) {
        case match_kind_t::request_url:      return "request_url";
        case match_kind_t::request_headers:  return "request_headers";
        case match_kind_t::request_body:     return "request_body";
        case match_kind_t::response_headers: return "response_headers";
        case match_kind_t::response_body:    return "response_body";
        case match_kind_t::all:              return "all";
    }
    return "all";
}

nlohmann::json rule_to_json(const rule_t& r)
{
    nlohmann::json j;
    j["id"]              = r.id;
    j["label"]           = r.label;
    j["target"]          = kind_to_str(r.target);
    j["match_regex"]     = r.match_regex;
    j["replacement"]     = r.replacement;
    j["regex"]           = r.regex;
    j["case_insensitive"]= r.case_insensitive;
    j["active"]          = r.active;
    j["host_filter"]     = r.host_filter;
    j["scheme_filter"]   = r.scheme_filter;
    j["hit_count"]       = r.hit_count;
    return j;
}

bool rule_from_json(const nlohmann::json& j, rule_t& out)
{
    if (!j.is_object()) return false;
    out = rule_t{};
    out.id = j.value("id", static_cast<uint64_t>(0));
    out.label = j.value("label", std::string());
    parse_target(j.value("target", std::string("request_url")), out.target);
    out.match_regex = j.value("match_regex", std::string());
    out.replacement = j.value("replacement", std::string());
    out.regex = j.value("regex", true);
    out.case_insensitive = j.value("case_insensitive", false);
    out.active = j.value("active", true);
    out.host_filter = j.value("host_filter", std::string());
    out.scheme_filter = j.value("scheme_filter", std::string());
    out.hit_count = j.value("hit_count", static_cast<uint64_t>(0));
    return true;
}

}

const char* target_label(match_kind_t k) { return kind_to_str(k); }

bool parse_target(const std::string& s_in, match_kind_t& out)
{
    diag::log_tagged_fmt("match_replace", "parse_target entry s=%s", s_in.c_str());
    const std::string lc = ascii_lower(s_in);
    if (lc == "request_url")      { out = match_kind_t::request_url; return true; }
    if (lc == "request_headers")  { out = match_kind_t::request_headers; return true; }
    if (lc == "request_body")     { out = match_kind_t::request_body; return true; }
    if (lc == "response_headers") { out = match_kind_t::response_headers; return true; }
    if (lc == "response_body")    { out = match_kind_t::response_body; return true; }
    if (lc == "all")              { out = match_kind_t::all; return true; }
    diag::log_tagged_fmt("match_replace", "parse_target unknown s=%s", s_in.c_str());
    return false;
}

bool initialize()
{
    auto& st = s();
    bool expected = false;
    if (!st.initialized.compare_exchange_strong(expected, true)) return true;
    load_from_disk();
    diag::log_tagged("burp", "match_replace_initialized");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("match_replace", "shutdown entry");
    auto& st = s();
    if (!st.initialized.exchange(false)) {
        diag::log_tagged_fmt("match_replace", "shutdown already_stopped");
        return;
    }
    save_to_disk();
    diag::log_tagged_fmt("match_replace", "shutdown complete");
}

uint64_t add(rule_t r)
{
    auto& st = s();
    if (r.id == 0) r.id = st.next_id.fetch_add(1, std::memory_order_acq_rel);
    else if (r.id >= st.next_id.load()) st.next_id.store(r.id + 1, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.rules.push_back(r);
    }
    save_to_disk();
    diag::log_tagged_fmt("burp", "mr_rule_added id=%llu label='%s' target=%s",
        static_cast<unsigned long long>(r.id), r.label.c_str(), kind_to_str(r.target));
    return r.id;
}

bool update(const rule_t& r)
{
    diag::log_tagged_fmt("match_replace", "update entry id=%llu", static_cast<unsigned long long>(r.id));
    auto& st = s();
    bool ok = false;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (auto& e : st.rules) {
            if (e.id == r.id) { e = r; ok = true; break; }
        }
    }
    if (ok) {
        save_to_disk();
        diag::log_tagged_fmt("match_replace", "update ok id=%llu", static_cast<unsigned long long>(r.id));
    } else {
        diag::log_tagged_fmt("match_replace", "update not_found id=%llu", static_cast<unsigned long long>(r.id));
    }
    return ok;
}

bool remove(uint64_t id)
{
    diag::log_tagged_fmt("match_replace", "remove entry id=%llu", static_cast<unsigned long long>(id));
    auto& st = s();
    bool removed = false;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (auto it = st.rules.begin(); it != st.rules.end(); ++it) {
            if (it->id == id) { st.rules.erase(it); removed = true; break; }
        }
    }
    if (removed) {
        save_to_disk();
        diag::log_tagged_fmt("match_replace", "remove ok id=%llu", static_cast<unsigned long long>(id));
    } else {
        diag::log_tagged_fmt("match_replace", "remove not_found id=%llu", static_cast<unsigned long long>(id));
    }
    return removed;
}

std::vector<rule_t> list()
{
    diag::log_tagged_fmt("match_replace", "list entry");
    auto result = snapshot_rules();
    diag::log_tagged_fmt("match_replace", "list result count=%zu", result.size());
    return result;
}

void clear()
{
    diag::log_tagged_fmt("match_replace", "clear entry");
    auto& st = s();
    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        count = st.rules.size();
        st.rules.clear();
    }
    save_to_disk();
    diag::log_tagged_fmt("match_replace", "clear done cleared=%zu", count);
}

bool move(uint64_t id, int delta)
{
    diag::log_tagged_fmt("match_replace", "move entry id=%llu delta=%d", static_cast<unsigned long long>(id), delta);
    auto& st = s();
    bool ok = false;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        size_t idx = st.rules.size();
        for (size_t i = 0; i < st.rules.size(); ++i) {
            if (st.rules[i].id == id) { idx = i; break; }
        }
        if (idx >= st.rules.size()) {
            diag::log_tagged_fmt("match_replace", "move not_found id=%llu", static_cast<unsigned long long>(id));
            return false;
        }
        const int new_idx = static_cast<int>(idx) + delta;
        if (new_idx < 0 || new_idx >= static_cast<int>(st.rules.size())) {
            diag::log_tagged_fmt("match_replace", "move out_of_bounds id=%llu delta=%d", static_cast<unsigned long long>(id), delta);
            return false;
        }
        std::swap(st.rules[idx], st.rules[static_cast<size_t>(new_idx)]);
        ok = true;
    }
    if (ok) {
        save_to_disk();
        diag::log_tagged_fmt("match_replace", "move ok id=%llu delta=%d", static_cast<unsigned long long>(id), delta);
    }
    return ok;
}

bool apply_request(std::vector<uint8_t>& raw_request, const std::string& host, const std::string& scheme)
{
    diag::log_tagged_fmt("match_replace", "apply_request entry host=%s scheme=%s raw_len=%zu",
        host.c_str(), scheme.c_str(), raw_request.size());
    bool result = apply_set(raw_request, host, scheme, true);
    diag::log_tagged_fmt("match_replace", "apply_request result=%d host=%s", (int)result, host.c_str());
    return result;
}

bool apply_response(std::vector<uint8_t>& raw_response, const std::string& host, const std::string& scheme)
{
    diag::log_tagged_fmt("match_replace", "apply_response entry host=%s scheme=%s raw_len=%zu",
        host.c_str(), scheme.c_str(), raw_response.size());
    bool result = apply_set(raw_response, host, scheme, false);
    diag::log_tagged_fmt("match_replace", "apply_response result=%d host=%s", (int)result, host.c_str());
    return result;
}

bool apply_text(std::string& text, match_kind_t target,
                const std::string& host, const std::string& scheme,
                size_t* rules_applied)
{
    diag::log_tagged_fmt("match_replace", "apply_text entry target=%s host=%s text_len=%zu",
        kind_to_str(target), host.c_str(), text.size());
    if (rules_applied) *rules_applied = 0;
    const auto rules = snapshot_rules();
    bool any_changed = false;
    for (const auto& r : rules) {
        if (!r.active) continue;
        if (r.target != target && r.target != match_kind_t::all) continue;
        if (!host_filter_matches(r.host_filter, host)) continue;
        if (!scheme_filter_matches(r.scheme_filter, scheme)) continue;
        bool changed = false;
        if (!apply_rule(r, text, changed)) continue;
        if (changed) {
            bump_hit_count(r.id);
            any_changed = true;
            if (rules_applied) ++(*rules_applied);
        }
    }
    diag::log_tagged_fmt("match_replace", "apply_text result changed=%d rules_applied=%zu host=%s",
        (int)any_changed, rules_applied ? *rules_applied : 0, host.c_str());
    return any_changed;
}

bool test_rule(const rule_t& r, const std::string& sample, std::string& out)
{
    diag::log_tagged_fmt("match_replace", "test_rule entry id=%llu label='%s' sample_len=%zu",
        static_cast<unsigned long long>(r.id), r.label.c_str(), sample.size());
    out = sample;
    bool changed = false;
    bool result = apply_rule(r, out, changed);
    diag::log_tagged_fmt("match_replace", "test_rule result=%d changed=%d out_len=%zu", (int)result, (int)changed, out.size());
    return result;
}

std::string storage_path()
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
    base += "\\match_replace.json";
    return base;
}

bool save_to_disk()
{
    diag::log_tagged_fmt("match_replace", "save_to_disk entry");
    auto& st = s();
    nlohmann::json arr = nlohmann::json::array();
    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (const auto& r : st.rules) { arr.push_back(rule_to_json(r)); count++; }
    }
    const std::string path = storage_path();
    diag::log_tagged_fmt("match_replace", "save_to_disk path=%s rules=%zu", path.c_str(), count);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        diag::log_tagged_fmt("match_replace", "save_to_disk error open_failed path=%s", path.c_str());
        set_err("failed to open match_replace.json for write");
        return false;
    }
    const std::string dump = arr.dump(2);
    out.write(dump.data(), static_cast<std::streamsize>(dump.size()));
    diag::log_tagged_fmt("match_replace", "save_to_disk ok bytes=%zu", dump.size());
    return true;
}

bool load_from_disk()
{
    diag::log_tagged_fmt("match_replace", "load_from_disk entry");
    auto& st = s();
    const std::string path = storage_path();
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        diag::log_tagged_fmt("match_replace", "load_from_disk file_not_found path=%s", path.c_str());
        return false;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string data = ss.str();
    if (data.empty()) {
        diag::log_tagged_fmt("match_replace", "load_from_disk empty_file");
        return false;
    }
    nlohmann::json arr;
    try { arr = nlohmann::json::parse(data, nullptr, false); }
    catch (...) {
        diag::log_tagged_fmt("match_replace", "load_from_disk error parse_failed");
        set_err("match_replace.json parse failed");
        return false;
    }
    if (arr.is_discarded() || !arr.is_array()) {
        diag::log_tagged_fmt("match_replace", "load_from_disk error not_array");
        set_err("match_replace.json not an array");
        return false;
    }
    std::vector<rule_t> loaded;
    uint64_t max_id = 0;
    for (const auto& j : arr) {
        rule_t r;
        if (!rule_from_json(j, r)) continue;
        if (r.id > max_id) max_id = r.id;
        loaded.push_back(r);
    }
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.rules = std::move(loaded);
        if (max_id >= st.next_id.load()) st.next_id.store(max_id + 1, std::memory_order_release);
    }
    diag::log_tagged_fmt("match_replace", "load_from_disk ok rules=%zu max_id=%llu",
        loaded.size(), static_cast<unsigned long long>(max_id));
    return true;
}

std::string last_error()
{
    diag::log_tagged_fmt("match_replace", "last_error queried");
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    return st.last_err;
}

}
}
}
