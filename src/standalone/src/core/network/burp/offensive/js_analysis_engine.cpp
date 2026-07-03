#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "js_analysis_engine.hpp"

#include "../audit_http.hpp"
#include "../payload_library.hpp"
#include "../../js_analysis_tools_standalone.hpp"
#include "../../../mcp/mcp_standalone.hpp"
#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <map>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace offensive {
namespace js_analysis {

namespace {

using json = nlohmann::json;

struct source_t
{
    std::string label;
    std::string source;
    bool fetched = false;
    int status_code = 0;
    uint64_t exchange_id = 0;
    bool truncated = false;
    std::string error;
};

struct run_record_t
{
    std::string id;
    std::string action;
    std::string target_domain;
    uint64_t started_ms = 0;
    uint64_t finished_ms = 0;
    std::string status;
    json result;
};

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

std::mutex& runs_mtx()
{
    static std::mutex m;
    return m;
}

std::vector<run_record_t>& runs()
{
    static std::vector<run_record_t> r;
    return r;
}

std::atomic<uint64_t>& next_run_id()
{
    static std::atomic<uint64_t> v{1};
    return v;
}

uint64_t now_ms()
{
    return GetTickCount64();
}

void set_err(const std::string& e)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = e;
}

bool call_expired()
{
    const uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    return mcp_standalone::current_call_cancelled() || (deadline != 0 && now_ms() >= deadline);
}

int bounded_timeout_ms(const json& params, int fallback, int min_v, int max_v)
{
    int value = fallback;
    if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer())
        value = params["timeout_ms"].get<int>();
    value = (std::max)(min_v, (std::min)(max_v, value));
    const uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline != 0) {
        const uint64_t now = now_ms();
        if (deadline <= now)
            return 1;
        value = static_cast<int>((std::min<uint64_t>)(static_cast<uint64_t>(value), deadline - now));
    }
    return (std::max)(1, value);
}

std::string lower_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim_copy(const std::string& s)
{
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a])))
        ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1])))
        --b;
    return s.substr(a, b - a);
}

bool json_bool(const json& params, const char* name, bool def)
{
    if (!params.contains(name) || !params[name].is_boolean())
        return def;
    return params[name].get<bool>();
}

size_t json_size(const json& params, const char* name, size_t def, size_t min_v, size_t max_v)
{
    size_t value = def;
    if (params.contains(name) && params[name].is_number_unsigned())
        value = params[name].get<size_t>();
    else if (params.contains(name) && params[name].is_number_integer()) {
        int64_t parsed = params[name].get<int64_t>();
        if (parsed > 0)
            value = static_cast<size_t>(parsed);
    }
    return (std::max)(min_v, (std::min)(max_v, value));
}

std::string json_string(const json& params, const char* name)
{
    if (!params.contains(name) || !params[name].is_string())
        return {};
    return params[name].get<std::string>();
}

json secret_patterns_from_params(const json& params)
{
    if (params.contains("patterns"))
        return params["patterns"];
    payloads::initialize();
    const auto entries = payloads::entries("js/secrets_patterns", 64);
    json out = json::array();
    for (const auto& entry : entries) {
        if (!entry.empty())
            out.push_back(entry);
    }
    return out;
}

std::string host_header_value(const std::string& host, uint16_t port, bool tls)
{
    std::string h = host;
    if ((tls && port != 443) || (!tls && port != 80)) {
        h += ":";
        h += std::to_string(port);
    }
    return h;
}

bool sensitive_header_name(const std::string& name)
{
    const std::string n = lower_ascii(name);
    return n.find("authorization") != std::string::npos ||
           n.find("cookie") != std::string::npos ||
           n.find("token") != std::string::npos ||
           n.find("secret") != std::string::npos ||
           n.find("key") != std::string::npos ||
           n.find("credential") != std::string::npos;
}

std::map<std::string, std::string> headers_from_json(const json& params)
{
    std::map<std::string, std::string> out;
    if (!params.contains("headers") || !params["headers"].is_object())
        return out;
    for (auto it = params["headers"].begin(); it != params["headers"].end(); ++it) {
        if (!it.value().is_string())
            continue;
        const std::string name = trim_copy(it.key());
        if (name.empty() || name.find('\r') != std::string::npos || name.find('\n') != std::string::npos)
            continue;
        out[name] = it.value().get<std::string>();
    }
    return out;
}

std::vector<uint8_t> build_get_request(const std::string& host_header,
                                       const std::string& path,
                                       const std::map<std::string, std::string>& headers)
{
    std::string req;
    req += "GET ";
    req += path.empty() ? std::string("/") : path;
    req += " HTTP/1.1\r\n";
    req += "Host: ";
    req += host_header;
    req += "\r\n";
    req += "User-Agent: AiDA-Offensive-JS/1.0\r\n";
    req += "Accept: application/javascript,text/javascript,*/*;q=0.8\r\n";
    for (const auto& kv : headers) {
        if (lower_ascii(kv.first) == "host")
            continue;
        if (kv.first.find(':') != std::string::npos || kv.second.find('\r') != std::string::npos || kv.second.find('\n') != std::string::npos)
            continue;
        req += kv.first;
        req += ": ";
        req += kv.second;
        req += "\r\n";
    }
    req += "Connection: close\r\n\r\n";
    return std::vector<uint8_t>(req.begin(), req.end());
}

source_t fetch_url_source(const std::string& url, const json& params)
{
    source_t out;
    out.label = aida::network::js_analysis_tools::redact_url_for_output(url);
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    if (!audit_http::parse_url(url, scheme, host, port, path)) {
        out.error = "invalid_url";
        return out;
    }
    const bool tls = lower_ascii(scheme) == "https";
    audit_http::send_options_t opt;
    opt.timeout_ms = bounded_timeout_ms(params, 15000, 1000, 120000);
    opt.follow_redirects = json_bool(params, "follow_redirects", true);
    opt.max_redirects = 3;
    opt.enforce_scope = json_bool(params, "enforce_scope", true);
    opt.publish_exchange = true;
    opt.exchange_source = "offensive_js_analysis";
    const auto req = build_get_request(host_header_value(host, port, tls), path, headers_from_json(params));
    auto resp = audit_http::send(req, host, port, tls, opt);
    if (!resp.has_value()) {
        out.error = audit_http::last_error();
        return out;
    }
    out.fetched = true;
    out.status_code = resp->status_code;
    out.exchange_id = resp->id;
    const size_t cap = json_size(params, "max_source_bytes", 4194304, 4096, 16777216);
    const size_t n = (std::min)(cap, resp->resp_body.size());
    out.source.assign(reinterpret_cast<const char*>(resp->resp_body.data()), n);
    out.truncated = resp->resp_body.size() > n;
    return out;
}

std::vector<source_t> collect_sources(const json& params)
{
    std::vector<source_t> out;
    if (params.contains("source") && params["source"].is_string()) {
        source_t s;
        s.label = params.value("source_name", std::string("inline.js"));
        s.source = params["source"].get<std::string>();
        out.push_back(std::move(s));
    }
    if (params.contains("url") && params["url"].is_string() && !call_expired())
        out.push_back(fetch_url_source(params["url"].get<std::string>(), params));
    if (params.contains("urls") && params["urls"].is_array()) {
        const size_t cap = json_size(params, "max_urls", 16, 1, 64);
        for (const auto& item : params["urls"]) {
            if (out.size() >= cap || call_expired())
                break;
            if (item.is_string())
                out.push_back(fetch_url_source(item.get<std::string>(), params));
        }
    }
    if (params.contains("sources") && params["sources"].is_array()) {
        const size_t cap = json_size(params, "max_sources", 16, 1, 64);
        for (const auto& item : params["sources"]) {
            if (out.size() >= cap || call_expired())
                break;
            if (!item.is_object())
                continue;
            if (item.contains("source") && item["source"].is_string()) {
                source_t s;
                s.label = item.value("source_name", item.value("label", std::string("inline.js")));
                s.source = item["source"].get<std::string>();
                out.push_back(std::move(s));
            } else if (item.contains("url") && item["url"].is_string()) {
                json merged = params;
                if (item.contains("headers") && item["headers"].is_object())
                    merged["headers"] = item["headers"];
                out.push_back(fetch_url_source(item["url"].get<std::string>(), merged));
            }
        }
    }
    return out;
}

json source_summary(const source_t& s)
{
    json j;
    j["source"] = aida::network::js_analysis_tools::redact_url_for_output(s.label);
    j["bytes"] = static_cast<uint64_t>(s.source.size());
    j["sha256"] = aida::network::js_analysis_tools::sha256_hex(s.source);
    j["fetched"] = s.fetched;
    j["status_code"] = s.status_code;
    j["exchange_id"] = s.exchange_id;
    j["truncated"] = s.truncated;
    if (!s.error.empty())
        j["error"] = s.error;
    return j;
}

std::string target_domain_from_sources(const std::vector<source_t>& sources, const json& params)
{
    const std::string explicit_domain = json_string(params, "target_domain");
    if (!explicit_domain.empty())
        return lower_ascii(explicit_domain);
    for (const auto& s : sources) {
        std::string scheme;
        std::string host;
        std::string path;
        uint16_t port = 0;
        if (audit_http::parse_url(s.label, scheme, host, port, path))
            return lower_ascii(host);
    }
    return {};
}

std::string record_run(const std::string& action, const std::string& target_domain, json& result)
{
    run_record_t rec;
    rec.id = "js-" + std::to_string(next_run_id().fetch_add(1));
    rec.action = action;
    rec.target_domain = target_domain;
    rec.started_ms = now_ms();
    rec.finished_ms = rec.started_ms;
    rec.status = result.value("ok", true) ? "complete" : "error";
    result["run_id"] = rec.id;
    result["action"] = action;
    result["status"] = rec.status;
    rec.result = result;
    {
        std::lock_guard<std::mutex> lk(runs_mtx());
        auto& r = runs();
        r.push_back(std::move(rec));
        if (r.size() > 128)
            r.erase(r.begin(), r.begin() + static_cast<std::ptrdiff_t>(r.size() - 128));
    }
    return result["run_id"].get<std::string>();
}

json error_result(const std::string& action, const std::string& error, const std::string& target_domain = {})
{
    set_err(error);
    json out;
    out["ok"] = false;
    out["error"] = error;
    record_run(action, target_domain, out);
    return out;
}

json ok_result(const std::string& action, const std::string& target_domain, json out)
{
    out["ok"] = true;
    record_run(action, target_domain, out);
    return out;
}

std::string b64_decode(const std::string& s)
{
    static const int table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    std::string out;
    out.reserve((s.size() / 4) * 3);
    uint32_t val = 0;
    int bits = 0;
    for (unsigned char c : s) {
        if (c == '=')
            break;
        int v = table[c];
        if (v < 0)
            continue;
        val = (val << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((val >> bits) & 0xffu));
        }
    }
    return out;
}

std::string resolve_source_map_url(const std::string& source_label, const std::string& marker)
{
    if (marker.rfind("http://", 0) == 0 || marker.rfind("https://", 0) == 0 || marker.rfind("data:", 0) == 0)
        return marker;
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    if (!audit_http::parse_url(source_label, scheme, host, port, path))
        return marker;
    std::string base = scheme + "://" + host;
    if ((scheme == "https" && port != 443) || (scheme == "http" && port != 80))
        base += ":" + std::to_string(port);
    if (!marker.empty() && marker.front() == '/')
        return base + marker;
    const size_t slash = path.find_last_of('/');
    const std::string dir = slash == std::string::npos ? std::string("/") : path.substr(0, slash + 1);
    return base + dir + marker;
}

std::string find_source_map_marker(const std::string& source)
{
    try {
        std::regex re(R"(sourceMappingURL\s*=\s*([^\s*]+))", std::regex_constants::icase);
        std::smatch m;
        if (std::regex_search(source, m, re) && m.size() > 1)
            return trim_copy(m[1].str());
    } catch (...) {
    }
    return {};
}

json source_map_json_from_params(const json& params, const std::vector<source_t>& sources, json& fetches)
{
    fetches = json::array();
    if (params.contains("source_map") && params["source_map"].is_string()) {
        return json::parse(params["source_map"].get<std::string>(), nullptr, false);
    }
    std::string source_map_url = json_string(params, "source_map_url");
    if (source_map_url.empty()) {
        for (const auto& s : sources) {
            const std::string marker = find_source_map_marker(s.source);
            if (!marker.empty()) {
                source_map_url = resolve_source_map_url(s.label, marker);
                break;
            }
        }
    }
    if (source_map_url.empty())
        return json();
    if (source_map_url.rfind("data:", 0) == 0) {
        const size_t comma = source_map_url.find(',');
        if (comma == std::string::npos)
            return json();
        const std::string meta = lower_ascii(source_map_url.substr(0, comma));
        const std::string payload = source_map_url.substr(comma + 1);
        const std::string decoded = meta.find(";base64") != std::string::npos ? b64_decode(payload) : payload;
        return json::parse(decoded, nullptr, false);
    }
    if (!json_bool(params, "fetch_external", true))
        return json();
    source_t fetched = fetch_url_source(source_map_url, params);
    fetches.push_back(source_summary(fetched));
    if (!fetched.error.empty() || fetched.source.empty())
        return json();
    return json::parse(fetched.source, nullptr, false);
}

std::string hex4_to_utf8(unsigned value)
{
    if (value <= 0x7f)
        return std::string(1, static_cast<char>(value));
    if (value <= 0x7ff) {
        std::string out;
        out.push_back(static_cast<char>(0xc0 | ((value >> 6) & 0x1f)));
        out.push_back(static_cast<char>(0x80 | (value & 0x3f)));
        return out;
    }
    std::string out;
    out.push_back(static_cast<char>(0xe0 | ((value >> 12) & 0x0f)));
    out.push_back(static_cast<char>(0x80 | ((value >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (value & 0x3f)));
    return out;
}

std::string decode_js_escapes(const std::string& source)
{
    std::string out;
    out.reserve(source.size());
    for (size_t i = 0; i < source.size(); ++i) {
        if (source[i] == '\\' && i + 3 < source.size() && source[i + 1] == 'x' &&
            std::isxdigit(static_cast<unsigned char>(source[i + 2])) && std::isxdigit(static_cast<unsigned char>(source[i + 3]))) {
            unsigned v = 0;
            std::stringstream ss;
            ss << std::hex << source.substr(i + 2, 2);
            ss >> v;
            out.push_back(static_cast<char>(v));
            i += 3;
            continue;
        }
        if (source[i] == '\\' && i + 5 < source.size() && source[i + 1] == 'u') {
            bool ok = true;
            for (size_t j = i + 2; j < i + 6; ++j)
                ok = ok && std::isxdigit(static_cast<unsigned char>(source[j]));
            if (ok) {
                unsigned v = 0;
                std::stringstream ss;
                ss << std::hex << source.substr(i + 2, 4);
                ss >> v;
                out += hex4_to_utf8(v);
                i += 5;
                continue;
            }
        }
        out.push_back(source[i]);
    }
    return out;
}

std::string beautify_basic(const std::string& source, size_t cap)
{
    std::string decoded = decode_js_escapes(source);
    std::string out;
    out.reserve((std::min)(decoded.size() + decoded.size() / 8, cap + size_t{1024}));
    int indent = 0;
    bool in_string = false;
    char quote = 0;
    bool escape = false;
    auto newline = [&]() {
        while (!out.empty() && (out.back() == ' ' || out.back() == '\t'))
            out.pop_back();
        out.push_back('\n');
        for (int i = 0; i < indent; ++i)
            out += "  ";
    };
    for (char c : decoded) {
        if (out.size() >= cap)
            break;
        if (in_string) {
            out.push_back(c);
            if (escape) {
                escape = false;
            } else if (c == '\\') {
                escape = true;
            } else if (c == quote) {
                in_string = false;
            }
            continue;
        }
        if (c == '\'' || c == '"' || c == '`') {
            in_string = true;
            quote = c;
            out.push_back(c);
            continue;
        }
        if (c == '{' || c == '[' || c == '(') {
            out.push_back(c);
            ++indent;
            newline();
            continue;
        }
        if (c == '}' || c == ']' || c == ')') {
            indent = (std::max)(0, indent - 1);
            newline();
            out.push_back(c);
            continue;
        }
        if (c == ';' || c == ',') {
            out.push_back(c);
            newline();
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!out.empty() && !std::isspace(static_cast<unsigned char>(out.back())))
                out.push_back(' ');
            continue;
        }
        out.push_back(c);
    }
    return out;
}

json snippet_evidence(const std::string& source, size_t pos, size_t len)
{
    const size_t begin = pos > 80 ? pos - 80 : 0;
    const size_t end = (std::min)(source.size(), pos + len + 80);
    json j;
    j["offset"] = static_cast<uint64_t>(pos);
    j["context"] = aida::network::js_analysis_tools::redact_sensitive_values(source.substr(begin, end - begin));
    return j;
}

void detect_pattern(json& arr,
                    const std::string& source,
                    const std::string& source_label,
                    const std::string& name,
                    const std::string& category,
                    const std::regex& re,
                    double confidence)
{
    try {
        std::smatch m;
        if (!std::regex_search(source, m, re))
            return;
        json item;
        item["name"] = name;
        item["category"] = category;
        item["confidence"] = confidence;
        item["source"] = aida::network::js_analysis_tools::redact_url_for_output(source_label);
        item["evidence"] = snippet_evidence(source, static_cast<size_t>(m.position(0)), static_cast<size_t>(m.length(0)));
        if (m.size() > 1 && m[1].matched)
            item["version"] = m[1].str();
        arr.push_back(std::move(item));
    } catch (...) {
    }
}

struct semver_t
{
    int major = 0;
    int minor = 0;
    int patch = 0;
    bool valid = false;
};

semver_t parse_semver(std::string version)
{
    version = trim_copy(version);
    while (!version.empty() && !std::isdigit(static_cast<unsigned char>(version.front())))
        version.erase(version.begin());
    semver_t out;
    std::stringstream ss(version);
    char dot1 = 0;
    char dot2 = 0;
    if (ss >> out.major) {
        out.valid = true;
        if (ss >> dot1 >> out.minor) {
            if (!(ss >> dot2 >> out.patch))
                out.patch = 0;
        }
    }
    return out;
}

bool version_less(const std::string& a, const std::string& b)
{
    const semver_t av = parse_semver(a);
    const semver_t bv = parse_semver(b);
    if (!av.valid || !bv.valid)
        return false;
    if (av.major != bv.major)
        return av.major < bv.major;
    if (av.minor != bv.minor)
        return av.minor < bv.minor;
    return av.patch < bv.patch;
}

void add_dependency(json& deps, const std::string& name, const std::string& version, const std::string& scope, const std::string& source)
{
    if (name.empty())
        return;
    json item;
    item["name"] = name;
    item["version"] = version;
    item["scope"] = scope;
    item["source"] = source;
    deps.push_back(std::move(item));
}

void parse_dependency_object(json& deps, const json& obj, const std::string& scope, const std::string& source)
{
    if (!obj.is_object())
        return;
    for (auto it = obj.begin(); it != obj.end(); ++it) {
        if (it.value().is_string())
            add_dependency(deps, it.key(), it.value().get<std::string>(), scope, source);
    }
}

void audit_dependency_item(json& findings, const json& dep)
{
    const std::string name = lower_ascii(dep.value("name", std::string()));
    const std::string version = dep.value("version", std::string());
    struct rule_t
    {
        const char* name;
        const char* min_safe;
        const char* severity;
        const char* reason;
    };
    static const rule_t rules[] = {
        {"jquery", "3.5.0", "medium", "Legacy jQuery versions are frequently associated with DOM XSS gadget exposure."},
        {"lodash", "4.17.21", "high", "Legacy lodash versions are associated with prototype pollution and template injection advisories."},
        {"underscore", "1.13.2", "medium", "Legacy underscore versions are associated with template injection advisories."},
        {"moment", "2.29.4", "low", "Legacy moment versions are associated with ReDoS advisories and should be upgraded."},
        {"axios", "0.21.2", "medium", "Legacy axios versions are associated with SSRF and request-smuggling adjacent advisories."},
        {"webpack", "5.0.0", "low", "Legacy webpack major versions increase client bundle audit risk and should be reviewed."}
    };
    for (const auto& r : rules) {
        if (name != r.name || !version_less(version, r.min_safe))
            continue;
        json f;
        f["name"] = dep.value("name", std::string());
        f["version"] = version;
        f["minimum_reviewed_version"] = r.min_safe;
        f["severity"] = r.severity;
        f["reason"] = r.reason;
        f["source"] = dep.value("source", std::string());
        findings.push_back(std::move(f));
    }
}

bool id_selected(const run_record_t& r, const std::set<std::string>& ids)
{
    return ids.empty() || ids.count(r.id) != 0;
}

bool domain_selected(const run_record_t& r, const std::string& target_domain)
{
    if (target_domain.empty())
        return true;
    const std::string want = lower_ascii(target_domain);
    const std::string got = lower_ascii(r.target_domain);
    return got == want || got.find(want) != std::string::npos || want.find(got) != std::string::npos;
}

}

nlohmann::json extract_endpoints(const nlohmann::json& params)
{
    auto sources = collect_sources(params);
    if (sources.empty())
        return error_result("extract_endpoints", "source_or_url_required");
    const bool include_relative = json_bool(params, "include_relative", true);
    const size_t max_results = json_size(params, "max_results", 512, 1, 5000);
    json endpoints = json::array();
    json source_meta = json::array();
    std::set<std::string> seen;
    for (const auto& s : sources) {
        source_meta.push_back(source_summary(s));
        if (!s.error.empty() || s.source.empty() || call_expired())
            continue;
        json part = aida::network::js_analysis_tools::extract_endpoints_from_source(s.source, s.label, include_relative, max_results);
        for (const auto& item : part) {
            if (!item.is_object() || endpoints.size() >= max_results)
                break;
            const std::string key = item.dump();
            if (seen.insert(key).second)
                endpoints.push_back(item);
        }
    }
    json out;
    out["sources"] = source_meta;
    out["endpoints"] = endpoints;
    out["count"] = endpoints.size();
    out["cancelled"] = call_expired();
    return ok_result("extract_endpoints", target_domain_from_sources(sources, params), std::move(out));
}

nlohmann::json extract_secrets(const nlohmann::json& params)
{
    auto sources = collect_sources(params);
    if (sources.empty())
        return error_result("extract_secrets", "source_or_url_required");
    const double min_confidence = params.contains("min_confidence") && params["min_confidence"].is_number()
        ? (std::max)(0.0, (std::min)(1.0, params["min_confidence"].get<double>()))
        : 0.55;
    const size_t max_results = json_size(params, "max_results", 256, 1, 2000);
    json findings = json::array();
    json source_meta = json::array();
    std::set<std::string> seen;
    const json patterns = secret_patterns_from_params(params);
    for (const auto& s : sources) {
        source_meta.push_back(source_summary(s));
        if (!s.error.empty() || s.source.empty() || call_expired())
            continue;
        json part = aida::network::js_analysis_tools::extract_redacted_secrets_from_source(s.source, s.label, min_confidence, max_results, patterns);
        for (const auto& item : part) {
            if (!item.is_object() || findings.size() >= max_results)
                break;
            const std::string key = item.value("type", std::string()) + ":" + item.value("sha256", std::string()) + ":" + item.value("source", std::string());
            if (seen.insert(key).second)
                findings.push_back(item);
        }
    }
    json out;
    out["sources"] = source_meta;
    out["secrets"] = findings;
    out["count"] = findings.size();
    out["redacted"] = true;
    out["cancelled"] = call_expired();
    return ok_result("extract_secrets", target_domain_from_sources(sources, params), std::move(out));
}

nlohmann::json source_map_analyze(const nlohmann::json& params)
{
    auto sources = collect_sources(params);
    json source_meta = json::array();
    for (const auto& s : sources)
        source_meta.push_back(source_summary(s));
    json source_map_fetches;
    json sm = source_map_json_from_params(params, sources, source_map_fetches);
    if (!sm.is_object())
        return error_result("source_map_analyze", "source_map_unavailable_or_invalid", target_domain_from_sources(sources, params));
    json out;
    out["source_map_version"] = sm.value("version", 0);
    out["file"] = sm.value("file", std::string());
    out["source_root"] = aida::network::js_analysis_tools::redact_url_for_output(sm.value("sourceRoot", std::string()));
    out["sources_analyzed"] = source_meta;
    out["source_map_fetches"] = source_map_fetches;
    out["sources"] = json::array();
    out["endpoints"] = json::array();
    out["secrets"] = json::array();
    const size_t max_sources = json_size(params, "max_sources", 64, 1, 512);
    const size_t max_results = json_size(params, "max_results", 512, 1, 5000);
    if (sm.contains("sources") && sm["sources"].is_array()) {
        for (size_t i = 0; i < sm["sources"].size() && i < max_sources; ++i) {
            if (!sm["sources"][i].is_string())
                continue;
            json item;
            item["index"] = static_cast<uint64_t>(i);
            item["path"] = aida::network::js_analysis_tools::redact_url_for_output(sm["sources"][i].get<std::string>());
            if (sm.contains("sourcesContent") && sm["sourcesContent"].is_array() && i < sm["sourcesContent"].size() && sm["sourcesContent"][i].is_string()) {
                const std::string content = sm["sourcesContent"][i].get<std::string>();
                item["content_length"] = static_cast<uint64_t>(content.size());
                item["content_sha256"] = aida::network::js_analysis_tools::sha256_hex(content);
                const std::string label = item["path"].get<std::string>();
                json ep = aida::network::js_analysis_tools::extract_endpoints_from_source(content, label, true, max_results);
                const json patterns = secret_patterns_from_params(params);
                json sec = aida::network::js_analysis_tools::extract_redacted_secrets_from_source(content, label, 0.55, max_results, patterns);
                for (const auto& v : ep) {
                    if (out["endpoints"].size() < max_results)
                        out["endpoints"].push_back(v);
                }
                for (const auto& v : sec) {
                    if (out["secrets"].size() < max_results)
                        out["secrets"].push_back(v);
                }
            }
            out["sources"].push_back(std::move(item));
        }
    }
    out["sources_count"] = out["sources"].size();
    out["endpoint_count"] = out["endpoints"].size();
    out["secret_count"] = out["secrets"].size();
    out["redacted"] = true;
    out["cancelled"] = call_expired();
    return ok_result("source_map_analyze", target_domain_from_sources(sources, params), std::move(out));
}

nlohmann::json deobfuscate(const nlohmann::json& params)
{
    auto sources = collect_sources(params);
    if (sources.empty())
        return error_result("deobfuscate", "source_or_url_required");
    const size_t max_output = json_size(params, "max_output_bytes", 262144, 1024, 1048576);
    json outputs = json::array();
    for (const auto& s : sources) {
        if (!s.error.empty() || s.source.empty())
            continue;
        std::string transformed = beautify_basic(s.source, max_output);
        transformed = aida::network::js_analysis_tools::redact_sensitive_values(transformed);
        json item;
        item["source"] = aida::network::js_analysis_tools::redact_url_for_output(s.label);
        item["input_length"] = static_cast<uint64_t>(s.source.size());
        item["input_sha256"] = aida::network::js_analysis_tools::sha256_hex(s.source);
        item["output_length"] = static_cast<uint64_t>(transformed.size());
        item["output_sha256"] = aida::network::js_analysis_tools::sha256_hex(transformed);
        item["output"] = transformed;
        item["truncated"] = transformed.size() >= max_output;
        item["redacted"] = true;
        outputs.push_back(std::move(item));
    }
    json out;
    out["sources"] = json::array();
    for (const auto& s : sources)
        out["sources"].push_back(source_summary(s));
    out["outputs"] = outputs;
    out["count"] = outputs.size();
    return ok_result("deobfuscate", target_domain_from_sources(sources, params), std::move(out));
}

nlohmann::json framework_detect(const nlohmann::json& params)
{
    auto sources = collect_sources(params);
    if (sources.empty())
        return error_result("framework_detect", "source_or_url_required");
    json frameworks = json::array();
    json source_meta = json::array();
    for (const auto& s : sources) {
        source_meta.push_back(source_summary(s));
        if (!s.error.empty() || s.source.empty())
            continue;
        detect_pattern(frameworks, s.source, s.label, "React", "frontend_framework", std::regex(R"((?:React\.createElement|__REACT_DEVTOOLS_GLOBAL_HOOK__|react(?:\.production|\.development)?\.js))", std::regex_constants::icase), 0.86);
        detect_pattern(frameworks, s.source, s.label, "Vue", "frontend_framework", std::regex(R"((?:Vue\.createApp|new\s+Vue\s*\(|__VUE__|vue(?:\.runtime)?(?:\.global)?\.js))", std::regex_constants::icase), 0.86);
        detect_pattern(frameworks, s.source, s.label, "Angular", "frontend_framework", std::regex(R"((?:ng-version|angular\.module|@angular/core|webpackJsonpangular))", std::regex_constants::icase), 0.84);
        detect_pattern(frameworks, s.source, s.label, "Next.js", "meta_framework", std::regex(R"((?:__NEXT_DATA__|/_next/static|next/dist))", std::regex_constants::icase), 0.90);
        detect_pattern(frameworks, s.source, s.label, "Nuxt", "meta_framework", std::regex(R"((?:__NUXT__|/_nuxt/|nuxt\.js))", std::regex_constants::icase), 0.88);
        detect_pattern(frameworks, s.source, s.label, "Svelte", "frontend_framework", std::regex(R"((?:svelte/internal|data-svelte-h|__SVELTE))", std::regex_constants::icase), 0.82);
        detect_pattern(frameworks, s.source, s.label, "jQuery", "library", std::regex(R"((?:jquery[-.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)|jQuery\.fn\.jquery\s*=\s*["']([^"']+)["']))", std::regex_constants::icase), 0.86);
        detect_pattern(frameworks, s.source, s.label, "Webpack", "bundler", std::regex(R"((?:webpackChunk|__webpack_require__|webpackJsonp))", std::regex_constants::icase), 0.82);
        detect_pattern(frameworks, s.source, s.label, "Vite", "bundler", std::regex(R"((?:/@vite/client|import\.meta\.env|__vite__))", std::regex_constants::icase), 0.82);
    }
    json out;
    out["sources"] = source_meta;
    out["frameworks"] = frameworks;
    out["count"] = frameworks.size();
    return ok_result("framework_detect", target_domain_from_sources(sources, params), std::move(out));
}

nlohmann::json dependency_audit(const nlohmann::json& params)
{
    json deps = json::array();
    if (params.contains("package_json")) {
        json pkg = params["package_json"];
        if (pkg.is_string())
            pkg = json::parse(pkg.get<std::string>(), nullptr, false);
        if (pkg.is_object()) {
            parse_dependency_object(deps, pkg.value("dependencies", json::object()), "dependencies", "package_json");
            parse_dependency_object(deps, pkg.value("devDependencies", json::object()), "devDependencies", "package_json");
            parse_dependency_object(deps, pkg.value("peerDependencies", json::object()), "peerDependencies", "package_json");
            parse_dependency_object(deps, pkg.value("optionalDependencies", json::object()), "optionalDependencies", "package_json");
        }
    }
    if (params.contains("package_lock")) {
        json lock = params["package_lock"];
        if (lock.is_string())
            lock = json::parse(lock.get<std::string>(), nullptr, false);
        if (lock.is_object() && lock.contains("packages") && lock["packages"].is_object()) {
            for (auto it = lock["packages"].begin(); it != lock["packages"].end(); ++it) {
                if (!it.value().is_object() || !it.value().contains("version"))
                    continue;
                std::string name = it.value().value("name", std::string());
                if (name.empty()) {
                    std::string key = it.key();
                    const std::string prefix = "node_modules/";
                    const size_t pos = key.rfind(prefix);
                    if (pos != std::string::npos)
                        name = key.substr(pos + prefix.size());
                }
                if (it.value()["version"].is_string())
                    add_dependency(deps, name, it.value()["version"].get<std::string>(), "lockfile", "package_lock");
            }
        }
    }
    auto sources = collect_sources(params);
    for (const auto& s : sources) {
        if (s.error.empty() && !s.source.empty()) {
            try {
                std::regex lib_re(R"((jquery|lodash|underscore|moment|axios)[-.]([0-9]+\.[0-9]+(?:\.[0-9]+)?))", std::regex_constants::icase);
                for (auto it = std::sregex_iterator(s.source.begin(), s.source.end(), lib_re), end = std::sregex_iterator(); it != end; ++it)
                    add_dependency(deps, (*it)[1].str(), (*it)[2].str(), "bundle_reference", aida::network::js_analysis_tools::redact_url_for_output(s.label));
            } catch (...) {
            }
        }
    }
    json findings = json::array();
    for (const auto& dep : deps)
        audit_dependency_item(findings, dep);
    json out;
    out["dependencies"] = deps;
    out["dependency_count"] = deps.size();
    out["findings"] = findings;
    out["finding_count"] = findings.size();
    out["sources"] = json::array();
    for (const auto& s : sources)
        out["sources"].push_back(source_summary(s));
    return ok_result("dependency_audit", target_domain_from_sources(sources, params), std::move(out));
}

nlohmann::json get_status(const nlohmann::json& params)
{
    const std::string run_id = json_string(params, "run_id");
    json out;
    std::lock_guard<std::mutex> lk(runs_mtx());
    if (!run_id.empty()) {
        for (const auto& r : runs()) {
            if (r.id == run_id) {
                out["run_id"] = r.id;
                out["action"] = r.action;
                out["target_domain"] = r.target_domain;
                out["started_ms"] = r.started_ms;
                out["finished_ms"] = r.finished_ms;
                out["status"] = r.status;
                out["ok"] = r.status == "complete";
                return out;
            }
        }
        out["ok"] = false;
        out["error"] = "run_not_found";
        return out;
    }
    out["ok"] = true;
    out["runs"] = json::array();
    for (const auto& r : runs()) {
        json item;
        item["run_id"] = r.id;
        item["action"] = r.action;
        item["target_domain"] = r.target_domain;
        item["status"] = r.status;
        item["finished_ms"] = r.finished_ms;
        out["runs"].push_back(std::move(item));
    }
    out["count"] = out["runs"].size();
    return out;
}

nlohmann::json get_results(const nlohmann::json& params)
{
    const std::string run_id = json_string(params, "run_id");
    std::lock_guard<std::mutex> lk(runs_mtx());
    if (!run_id.empty()) {
        for (const auto& r : runs()) {
            if (r.id == run_id)
                return r.result;
        }
        json out;
        out["ok"] = false;
        out["error"] = "run_not_found";
        return out;
    }
    const size_t limit = json_size(params, "limit", 16, 1, 128);
    json out;
    out["ok"] = true;
    out["results"] = json::array();
    const auto& r = runs();
    const size_t start = r.size() > limit ? r.size() - limit : 0;
    for (size_t i = start; i < r.size(); ++i)
        out["results"].push_back(r[i].result);
    out["count"] = out["results"].size();
    return out;
}

nlohmann::json report_context(const std::string& target_domain, const std::vector<std::string>& run_ids)
{
    std::set<std::string> ids(run_ids.begin(), run_ids.end());
    json out;
    out["runs"] = json::array();
    std::lock_guard<std::mutex> lk(runs_mtx());
    for (const auto& r : runs()) {
        if (!id_selected(r, ids) || !domain_selected(r, target_domain))
            continue;
        json item;
        item["run_id"] = r.id;
        item["action"] = r.action;
        item["target_domain"] = r.target_domain;
        item["status"] = r.status;
        item["finished_ms"] = r.finished_ms;
        if (r.result.contains("count"))
            item["count"] = r.result["count"];
        if (r.result.contains("endpoint_count"))
            item["endpoint_count"] = r.result["endpoint_count"];
        if (r.result.contains("secret_count"))
            item["secret_count"] = r.result["secret_count"];
        if (r.result.contains("finding_count"))
            item["finding_count"] = r.result["finding_count"];
        if (r.result.contains("endpoints"))
            item["endpoints"] = r.result["endpoints"];
        if (r.result.contains("secrets"))
            item["secrets"] = r.result["secrets"];
        if (r.result.contains("frameworks"))
            item["frameworks"] = r.result["frameworks"];
        if (r.result.contains("findings"))
            item["dependency_findings"] = r.result["findings"];
        out["runs"].push_back(std::move(item));
    }
    out["count"] = out["runs"].size();
    return out;
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    return err_slot();
}

}
}
}
}
