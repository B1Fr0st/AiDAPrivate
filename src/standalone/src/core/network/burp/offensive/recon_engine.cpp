#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>

#ifdef small
#undef small
#endif

#include "recon_engine.hpp"

#include "../audit_http.hpp"
#include "../issue.hpp"
#include "../subdomain_enum.hpp"
#include "../tech_fingerprint.hpp"
#include "../../js_analysis_tools_standalone.hpp"
#include "../../../mcp/mcp_standalone.hpp"
#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

namespace aida {
namespace burp {
namespace offensive {
namespace recon {

namespace {

using json = nlohmann::json;

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

std::string target_domain_from_url_or_domain(const json& params)
{
    std::string d = json_string(params, "target_domain");
    if (!d.empty())
        return lower_ascii(d);
    d = json_string(params, "domain");
    if (!d.empty())
        return lower_ascii(d);
    std::string url = json_string(params, "url");
    if (!url.empty()) {
        std::string scheme;
        std::string host;
        std::string path;
        uint16_t port = 0;
        if (audit_http::parse_url(url, scheme, host, port, path))
            return lower_ascii(host);
    }
    d = json_string(params, "host");
    return lower_ascii(d);
}

std::string record_run(const std::string& action, const std::string& target_domain, json& result)
{
    run_record_t rec;
    rec.id = "recon-" + std::to_string(next_run_id().fetch_add(1));
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

bool sensitive_header_name(const std::string& name)
{
    const std::string n = lower_ascii(name);
    return n.find("authorization") != std::string::npos ||
           n.find("cookie") != std::string::npos ||
           n.find("token") != std::string::npos ||
           n.find("secret") != std::string::npos ||
           n.find("key") != std::string::npos ||
           n.find("credential") != std::string::npos ||
           n.find("signature") != std::string::npos;
}

json header_value_json(const std::string& name, const std::string& value)
{
    if (sensitive_header_name(name) || value.size() > 192) {
        json out;
        out["redacted"] = true;
        out["length"] = static_cast<uint64_t>(value.size());
        out["sha256"] = aida::network::js_analysis_tools::sha256_hex(value);
        return out;
    }
    return value;
}

json headers_json(const std::vector<std::pair<std::string, std::string>>& headers)
{
    json out = json::object();
    for (const auto& kv : headers)
        out[kv.first] = header_value_json(kv.first, kv.second);
    return out;
}

std::string header_value(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& name)
{
    const std::string want = lower_ascii(name);
    for (const auto& kv : headers) {
        if (lower_ascii(kv.first) == want)
            return kv.second;
    }
    return {};
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

std::vector<uint8_t> build_request(const std::string& method,
                                   const std::string& host_header,
                                   const std::string& path,
                                   const std::vector<std::pair<std::string, std::string>>& headers = {},
                                   const std::string& body = {})
{
    std::string req;
    req += method.empty() ? std::string("GET") : method;
    req += " ";
    req += path.empty() ? std::string("/") : path;
    req += " HTTP/1.1\r\nHost: ";
    req += host_header;
    req += "\r\nUser-Agent: AiDA-Offensive-Recon/1.0\r\nAccept: */*\r\n";
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
    if (!body.empty()) {
        req += "Content-Length: ";
        req += std::to_string(body.size());
        req += "\r\n";
    }
    req += "Connection: close\r\n\r\n";
    req += body;
    return std::vector<uint8_t>(req.begin(), req.end());
}

std::optional<exchange_observed_t> send_url(const std::string& url,
                                            const json& params,
                                            const std::string& method = "GET",
                                            const std::vector<std::pair<std::string, std::string>>& headers = {},
                                            const std::string& body = {},
                                            const std::string& source = "offensive_recon")
{
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    if (!audit_http::parse_url(url, scheme, host, port, path)) {
        set_err("invalid_url");
        return std::nullopt;
    }
    const bool tls = lower_ascii(scheme) == "https";
    audit_http::send_options_t opt;
    opt.timeout_ms = bounded_timeout_ms(params, 15000, 1000, 300000);
    opt.follow_redirects = json_bool(params, "follow_redirects", false);
    opt.max_redirects = 3;
    opt.enforce_scope = json_bool(params, "enforce_scope", true);
    opt.publish_exchange = true;
    opt.exchange_source = source;
    auto req = build_request(method, host_header_value(host, port, tls), path, headers, body);
    auto resp = audit_http::send(req, host, port, tls, opt);
    if (!resp.has_value())
        set_err(audit_http::last_error());
    return resp;
}

json response_summary(const exchange_observed_t& ex, bool include_headers)
{
    json out;
    out["status_code"] = ex.status_code;
    out["latency_ms"] = ex.latency_ms;
    out["exchange_id"] = ex.id;
    out["tls_version"] = ex.tls_version;
    out["alpn"] = ex.alpn;
    out["body_length"] = static_cast<uint64_t>(ex.resp_body.size());
    std::string body(reinterpret_cast<const char*>(ex.resp_body.data()), ex.resp_body.size());
    out["body_sha256"] = aida::network::js_analysis_tools::sha256_hex(body);
    if (include_headers)
        out["headers"] = headers_json(ex.resp_headers);
    return out;
}

json tech_to_json(const tech::tech_t& t)
{
    json j;
    j["name"] = t.name;
    j["category"] = t.category;
    j["version"] = t.version;
    j["confidence_label"] = t.confidence_label;
    return j;
}

json security_headers_json(const std::vector<std::pair<std::string, std::string>>& headers)
{
    const char* names[] = {
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy"
    };
    json out = json::object();
    for (const char* n : names) {
        const std::string value = header_value(headers, n);
        out[n] = value.empty() ? json("missing") : header_value_json(n, value);
    }
    return out;
}

std::string body_string_limited(const exchange_observed_t& ex, size_t cap)
{
    const size_t n = (std::min)(cap, ex.resp_body.size());
    return std::string(reinterpret_cast<const char*>(ex.resp_body.data()), n);
}

void add_waf_signal(json& signals, const std::string& name, const std::string& vendor, const std::string& evidence, int weight)
{
    json item;
    item["name"] = name;
    item["vendor"] = vendor;
    item["evidence"] = evidence;
    item["weight"] = weight;
    signals.push_back(std::move(item));
}

void detect_waf_headers(const exchange_observed_t& ex, json& signals)
{
    const std::string server = lower_ascii(header_value(ex.resp_headers, "server"));
    const std::string cf_ray = header_value(ex.resp_headers, "cf-ray");
    const std::string akamai = header_value(ex.resp_headers, "akamai-origin-hop");
    const std::string sucuri = header_value(ex.resp_headers, "x-sucuri-id");
    const std::string fastly = header_value(ex.resp_headers, "x-served-by");
    const std::string imperva = header_value(ex.resp_headers, "x-iinfo");
    const std::string awselb = header_value(ex.resp_headers, "x-amzn-requestid");
    if (server.find("cloudflare") != std::string::npos || !cf_ray.empty())
        add_waf_signal(signals, "Cloudflare", "Cloudflare Inc.", "cloudflare headers", 5);
    if (server.find("akamai") != std::string::npos || !akamai.empty())
        add_waf_signal(signals, "Akamai", "Akamai", "akamai headers", 4);
    if (!sucuri.empty())
        add_waf_signal(signals, "Sucuri", "Sucuri", "x-sucuri-id header", 5);
    if (server.find("sucuri") != std::string::npos)
        add_waf_signal(signals, "Sucuri", "Sucuri", "server header", 4);
    if (server.find("awselb") != std::string::npos || !awselb.empty())
        add_waf_signal(signals, "AWS WAF or ALB", "Amazon Web Services", "aws request headers", 2);
    if (server.find("fastly") != std::string::npos || lower_ascii(fastly).find("cache") != std::string::npos)
        add_waf_signal(signals, "Fastly", "Fastly", "fastly headers", 2);
    if (!imperva.empty() || server.find("imperva") != std::string::npos || server.find("incapsula") != std::string::npos)
        add_waf_signal(signals, "Imperva", "Imperva", "imperva headers", 5);
    if (server.find("mod_security") != std::string::npos || server.find("modsecurity") != std::string::npos)
        add_waf_signal(signals, "ModSecurity", "OWASP CRS or vendor rule set", "server header", 4);
}

void detect_waf_body(const exchange_observed_t& ex, json& signals)
{
    const std::string body = lower_ascii(body_string_limited(ex, 65536));
    if (body.find("checking your browser") != std::string::npos || body.find("cf-browser-verification") != std::string::npos)
        add_waf_signal(signals, "Cloudflare", "Cloudflare Inc.", "challenge page", 5);
    if (body.find("access denied") != std::string::npos && body.find("akamai") != std::string::npos)
        add_waf_signal(signals, "Akamai", "Akamai", "akamai block page", 5);
    if (body.find("sucuri website firewall") != std::string::npos)
        add_waf_signal(signals, "Sucuri", "Sucuri", "sucuri block page", 5);
    if (body.find("mod_security") != std::string::npos || body.find("modsecurity") != std::string::npos)
        add_waf_signal(signals, "ModSecurity", "OWASP CRS or vendor rule set", "modsecurity block page", 5);
    if (body.find("request blocked") != std::string::npos || body.find("web application firewall") != std::string::npos)
        add_waf_signal(signals, "Generic WAF", "Unknown", "generic block wording", 2);
}

std::string confidence_from_score(int score)
{
    if (score >= 5)
        return "firm";
    if (score >= 2)
        return "tentative";
    return "none";
}

std::vector<std::string> string_array_param(const json& params, const char* name, const std::vector<std::string>& fallback, size_t cap)
{
    std::vector<std::string> out;
    if (params.contains(name) && params[name].is_array()) {
        for (const auto& v : params[name]) {
            if (v.is_string()) {
                out.push_back(v.get<std::string>());
                if (out.size() >= cap)
                    break;
            }
        }
    }
    if (out.empty())
        out = fallback;
    if (out.size() > cap)
        out.resize(cap);
    return out;
}

void push_unique(json& arr, const std::string& value)
{
    if (value.empty())
        return;
    for (const auto& existing : arr) {
        if (existing.is_string() && existing.get<std::string>() == value)
            return;
    }
    arr.push_back(value);
}

void push_unique_json(json& arr, json value)
{
    const std::string key = value.dump();
    for (const auto& existing : arr) {
        if (existing.dump() == key)
            return;
    }
    arr.push_back(std::move(value));
}

std::string dns_txt_kind(const std::string& value)
{
    const std::string l = lower_ascii(value);
    if (l.find("v=spf1") != std::string::npos)
        return "spf";
    if (l.find("v=dmarc1") != std::string::npos)
        return "dmarc";
    if (l.find("v=dkim1") != std::string::npos)
        return "dkim";
    if (l.find("verification") != std::string::npos)
        return "ownership_verification";
    if (l.find("token") != std::string::npos || l.find("secret") != std::string::npos || l.find("api") != std::string::npos || l.find("password") != std::string::npos || l.find("key") != std::string::npos)
        return "sensitive_like";
    return "txt";
}

std::string dns_txt_preview(const std::string& value)
{
    std::string out = aida::network::js_analysis_tools::redact_sensitive_values(value);
    try {
        out = std::regex_replace(out, std::regex(R"re(((?:google-site-verification|facebook-domain-verification|apple-domain-verification|atlassian-domain-verification|ms|token|secret|api[_-]?key|password|key|p)\s*=\s*)[^\s;"]{4,})re", std::regex_constants::icase), "$1[REDACTED]");
    } catch (...) {
        out = "[REDACTION_FAILED]";
    }
    if (out.size() > 192)
        out = out.substr(0, 192) + "...";
    return out;
}

json dns_txt_json(const std::string& value)
{
    json out;
    out["kind"] = dns_txt_kind(value);
    out["redacted"] = true;
    out["length"] = static_cast<uint64_t>(value.size());
    out["sha256"] = aida::network::js_analysis_tools::sha256_hex(value);
    out["preview"] = dns_txt_preview(value);
    return out;
}

void query_dns_type(const std::string& domain, WORD type, json& out)
{
    DNS_RECORDA* records = nullptr;
    DNS_STATUS st = DnsQuery_A(domain.c_str(), type, DNS_QUERY_STANDARD, nullptr, reinterpret_cast<PDNS_RECORD*>(&records), nullptr);
    if (st != 0) {
        out["errors"][std::to_string(type)] = static_cast<uint64_t>(st);
        return;
    }
    for (DNS_RECORDA* p = records; p; p = p->pNext) {
        if (p->wType != type)
            continue;
        char buf[INET6_ADDRSTRLEN] = {};
        switch (type) {
            case DNS_TYPE_A: {
                IN_ADDR a{};
                a.S_un.S_addr = p->Data.A.IpAddress;
                if (InetNtopA(AF_INET, &a, buf, sizeof(buf)))
                    push_unique(out["records"]["A"], buf);
                break;
            }
            case DNS_TYPE_AAAA: {
                if (InetNtopA(AF_INET6, &p->Data.AAAA.Ip6Address, buf, sizeof(buf)))
                    push_unique(out["records"]["AAAA"], buf);
                break;
            }
            case DNS_TYPE_CNAME:
                if (p->Data.CNAME.pNameHost) push_unique(out["records"]["CNAME"], p->Data.CNAME.pNameHost);
                break;
            case DNS_TYPE_NS:
                if (p->Data.NS.pNameHost) push_unique(out["records"]["NS"], p->Data.NS.pNameHost);
                break;
            case DNS_TYPE_MX:
                if (p->Data.MX.pNameExchange) push_unique(out["records"]["MX"], std::string(p->Data.MX.pNameExchange) + " priority=" + std::to_string(p->Data.MX.wPreference));
                break;
            case DNS_TYPE_TEXT:
                for (DWORD i = 0; i < p->Data.TXT.dwStringCount; ++i) {
                    if (p->Data.TXT.pStringArray[i])
                        push_unique_json(out["records"]["TXT"], dns_txt_json(p->Data.TXT.pStringArray[i]));
                }
                break;
            case DNS_TYPE_SOA:
                if (p->Data.SOA.pNamePrimaryServer) {
                    std::string v = p->Data.SOA.pNamePrimaryServer;
                    if (p->Data.SOA.pNameAdministrator) {
                        v += " admin=";
                        v += p->Data.SOA.pNameAdministrator;
                    }
                    v += " serial=" + std::to_string(p->Data.SOA.dwSerialNo);
                    push_unique(out["records"]["SOA"], v);
                }
                break;
            case DNS_TYPE_SRV:
                if (p->Data.SRV.pNameTarget) {
                    std::string v = p->Data.SRV.pNameTarget;
                    v += " port=" + std::to_string(p->Data.SRV.wPort);
                    v += " priority=" + std::to_string(p->Data.SRV.wPriority);
                    v += " weight=" + std::to_string(p->Data.SRV.wWeight);
                    push_unique(out["records"]["SRV"], v);
                }
                break;
        }
    }
    if (records)
        DnsRecordListFree(records, DnsFreeRecordList);
}

std::vector<std::string> bucket_candidates(const std::string& domain, const json& params)
{
    std::vector<std::string> custom = string_array_param(params, "bucket_patterns", {}, 64);
    if (!custom.empty())
        return custom;
    std::string d = lower_ascii(domain);
    while (!d.empty() && d.back() == '.')
        d.pop_back();
    std::string hyphen = d;
    std::replace(hyphen.begin(), hyphen.end(), '.', '-');
    std::vector<std::string> out = {
        d,
        hyphen,
        d + "-assets",
        hyphen + "-assets",
        d + "-media",
        hyphen + "-media",
        d + "-static",
        hyphen + "-static",
        d + "-uploads",
        hyphen + "-uploads",
        d + "-backups",
        hyphen + "-backups",
        d + "-logs",
        hyphen + "-logs",
        d + ".assets",
        d + ".static"
    };
    return out;
}

bool valid_bucket_name(const std::string& name)
{
    if (name.size() < 3 || name.size() > 63 || name.front() == '.' || name.back() == '.' || name.front() == '-' || name.back() == '-')
        return false;
    bool prev_dot = false;
    for (unsigned char c : name) {
        const bool ok = std::islower(c) || std::isdigit(c) || c == '.' || c == '-';
        if (!ok)
            return false;
        if (c == '.') {
            if (prev_dot)
                return false;
            prev_dot = true;
        } else {
            prev_dot = false;
        }
    }
    return true;
}

json permission_from_status(int status)
{
    json out;
    out["status"] = status;
    out["allowed"] = status >= 200 && status < 300;
    out["requires_auth_or_forbidden"] = status == 401 || status == 403;
    out["not_found"] = status == 404;
    return out;
}

uint64_t create_issue(const std::string& type_key,
                      const std::string& name,
                      severity_t severity,
                      const std::string& scheme,
                      const std::string& host,
                      uint16_t port,
                      const std::string& path,
                      const std::string& description,
                      const std::string& remediation,
                      const std::string& marker,
                      uint64_t audit_id)
{
    issue_t iss;
    iss.type_key = type_key;
    iss.name = name;
    iss.severity = severity;
    iss.confidence = confidence_t::firm;
    iss.scheme = scheme;
    iss.host = host;
    iss.port = port;
    iss.path = path;
    iss.description = description;
    iss.remediation = remediation;
    iss.audit_id = audit_id;
    evidence_t ev;
    ev.marker = marker;
    iss.evidence.push_back(std::move(ev));
    return issue_store::add(std::move(iss));
}

std::string url_encode(const std::string& s)
{
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0xf]);
            out.push_back(hex[c & 0xf]);
        }
    }
    return out;
}

std::vector<std::string> query_param_names(const std::string& path)
{
    std::vector<std::string> out;
    const size_t q = path.find('?');
    if (q == std::string::npos)
        return out;
    size_t pos = q + 1;
    while (pos < path.size()) {
        size_t end = path.find('&', pos);
        if (end == std::string::npos)
            end = path.size();
        size_t eq = path.find('=', pos);
        if (eq != std::string::npos && eq < end) {
            std::string name = path.substr(pos, eq - pos);
            if (!name.empty())
                out.push_back(name);
        }
        pos = end + 1;
    }
    return out;
}

std::string replace_or_add_query_param(const std::string& path, const std::string& param, const std::string& value)
{
    const size_t hash = path.find('#');
    const std::string frag = hash == std::string::npos ? std::string() : path.substr(hash);
    const std::string base_path = hash == std::string::npos ? path : path.substr(0, hash);
    const size_t q = base_path.find('?');
    std::string base = q == std::string::npos ? base_path : base_path.substr(0, q);
    std::vector<std::pair<std::string, std::string>> params;
    bool replaced = false;
    if (q != std::string::npos) {
        size_t pos = q + 1;
        while (pos <= base_path.size()) {
            size_t end = base_path.find('&', pos);
            if (end == std::string::npos)
                end = base_path.size();
            std::string part = base_path.substr(pos, end - pos);
            size_t eq = part.find('=');
            std::string k = eq == std::string::npos ? part : part.substr(0, eq);
            std::string v = eq == std::string::npos ? std::string() : part.substr(eq + 1);
            if (k == param) {
                v = url_encode(value);
                replaced = true;
            }
            if (!k.empty())
                params.push_back({k, v});
            if (end == base_path.size())
                break;
            pos = end + 1;
        }
    }
    if (!replaced)
        params.push_back({param, url_encode(value)});
    std::string out = base;
    out += "?";
    for (size_t i = 0; i < params.size(); ++i) {
        if (i)
            out += "&";
        out += params[i].first;
        out += "=";
        out += params[i].second;
    }
    out += frag;
    return out;
}

json metadata_body_summary(const exchange_observed_t& ex)
{
    std::string body = body_string_limited(ex, 262144);
    const std::string low = lower_ascii(body);
    json out;
    out["status_code"] = ex.status_code;
    out["body_length"] = static_cast<uint64_t>(ex.resp_body.size());
    out["body_sha256"] = aida::network::js_analysis_tools::sha256_hex(body);
    out["redacted"] = true;
    out["indicators"] = json::array();
    const char* indicators[] = {
        "accesskeyid",
        "secretaccesskey",
        "token",
        "iam",
        "instanceid",
        "instance-id",
        "computeMetadata",
        "metadata",
        "subscriptionId",
        "serviceAccounts"
    };
    for (const char* indicator : indicators) {
        if (low.find(lower_ascii(indicator)) != std::string::npos)
            out["indicators"].push_back(indicator);
    }
    out["credential_like"] = low.find("secretaccesskey") != std::string::npos ||
                             low.find("accesskeyid") != std::string::npos ||
                             low.find("sessiontoken") != std::string::npos ||
                             low.find("access_token") != std::string::npos;
    return out;
}

std::string phase_label(subdomain_enum::enum_phase_t phase)
{
    switch (phase) {
        case subdomain_enum::enum_phase_t::pending: return "pending";
        case subdomain_enum::enum_phase_t::passive: return "passive";
        case subdomain_enum::enum_phase_t::brute: return "brute";
        case subdomain_enum::enum_phase_t::stopping: return "stopping";
        case subdomain_enum::enum_phase_t::complete: return "complete";
        case subdomain_enum::enum_phase_t::error: return "error";
    }
    return "unknown";
}

json subdomain_status_json(const subdomain_enum::enum_status_t& s)
{
    json out;
    out["id"] = s.id;
    out["phase"] = phase_label(s.phase);
    out["passive_count"] = s.passive_count;
    out["brute_attempts"] = s.brute_attempts;
    out["brute_resolved"] = s.brute_resolved;
    out["last_error"] = s.last_error;
    out["results"] = json::array();
    for (const auto& r : s.results) {
        json item;
        item["fqdn"] = r.fqdn;
        item["ips"] = r.ips;
        item["sources"] = r.sources;
        item["resolves"] = r.resolves;
        out["results"].push_back(std::move(item));
    }
    return out;
}

class winsock_session_t
{
public:
    winsock_session_t()
    {
        WSADATA data{};
        ok_ = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }
    ~winsock_session_t()
    {
        if (ok_)
            WSACleanup();
    }
    bool ok() const { return ok_; }
private:
    bool ok_ = false;
};

std::vector<uint16_t> default_ports()
{
    return {21, 22, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 5000, 5432, 5601, 5672, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 9000, 9200, 9300, 11211, 27017};
}

std::vector<uint16_t> parse_ports(const json& params)
{
    std::vector<uint16_t> ports;
    if (params.contains("ports") && params["ports"].is_array()) {
        for (const auto& v : params["ports"]) {
            uint64_t p = 0;
            if (v.is_number_unsigned())
                p = v.get<uint64_t>();
            else if (v.is_number_integer() && v.get<int64_t>() > 0)
                p = static_cast<uint64_t>(v.get<int64_t>());
            if (p > 0 && p <= 65535)
                ports.push_back(static_cast<uint16_t>(p));
        }
    }
    if (ports.empty() && params.contains("port_range") && params["port_range"].is_string()) {
        const std::string range = params["port_range"].get<std::string>();
        const size_t dash = range.find('-');
        if (dash != std::string::npos) {
            int a = std::atoi(range.substr(0, dash).c_str());
            int b = std::atoi(range.substr(dash + 1).c_str());
            if (a > 0 && b >= a && b <= 65535 && b - a <= 2048) {
                for (int p = a; p <= b; ++p)
                    ports.push_back(static_cast<uint16_t>(p));
            }
        }
    }
    if (ports.empty())
        ports = default_ports();
    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    const size_t cap = json_size(params, "max_ports", 256, 1, 2048);
    if (ports.size() > cap)
        ports.resize(cap);
    return ports;
}

std::string service_for_port(uint16_t port)
{
    switch (port) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 25: return "smtp";
        case 53: return "dns";
        case 80: return "http";
        case 110: return "pop3";
        case 143: return "imap";
        case 443: return "https";
        case 445: return "smb";
        case 465: return "smtps";
        case 587: return "smtp-submission";
        case 993: return "imaps";
        case 995: return "pop3s";
        case 1433: return "mssql";
        case 1521: return "oracle";
        case 2049: return "nfs";
        case 2375: return "docker";
        case 2376: return "docker-tls";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgres";
        case 5601: return "kibana";
        case 5672: return "amqp";
        case 5900: return "vnc";
        case 5985: return "winrm";
        case 5986: return "winrm-tls";
        case 6379: return "redis";
        case 8080: return "http-alt";
        case 8443: return "https-alt";
        case 9200: return "elasticsearch";
        case 11211: return "memcached";
        case 27017: return "mongodb";
    }
    return "unknown";
}

std::optional<json> connect_probe(const std::string& host, const addrinfo* ai, uint16_t port, int timeout_ms)
{
    SOCKET s = socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return std::nullopt;
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
    const auto* addr_begin = reinterpret_cast<const uint8_t*>(ai->ai_addr);
    std::vector<uint8_t> addrbuf(addr_begin, addr_begin + ai->ai_addrlen);
    sockaddr* sa = reinterpret_cast<sockaddr*>(addrbuf.data());
    if (sa->sa_family == AF_INET)
        reinterpret_cast<sockaddr_in*>(sa)->sin_port = htons(port);
    else if (sa->sa_family == AF_INET6)
        reinterpret_cast<sockaddr_in6*>(sa)->sin6_port = htons(port);
    else {
        closesocket(s);
        return std::nullopt;
    }
    int rc = connect(s, sa, static_cast<int>(ai->ai_addrlen));
    if (rc == SOCKET_ERROR) {
        const int gle = WSAGetLastError();
        if (gle != WSAEWOULDBLOCK && gle != WSAEINPROGRESS && gle != WSAEINVAL) {
            closesocket(s);
            return std::nullopt;
        }
    }
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);
    fd_set efds;
    FD_ZERO(&efds);
    FD_SET(s, &efds);
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    rc = select(0, nullptr, &wfds, &efds, &tv);
    if (rc <= 0 || !FD_ISSET(s, &wfds)) {
        closesocket(s);
        return std::nullopt;
    }
    int so_error = 0;
    int so_len = sizeof(so_error);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &so_len) != 0 || so_error != 0) {
        closesocket(s);
        return std::nullopt;
    }
    json item;
    item["port"] = port;
    item["service"] = service_for_port(port);
    item["host"] = host;
    item["open"] = true;
    timeval rtv{};
    rtv.tv_usec = 200000;
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    if (select(0, &rfds, nullptr, nullptr, &rtv) > 0 && FD_ISSET(s, &rfds)) {
        char buf[256] = {};
        int got = recv(s, buf, sizeof(buf), 0);
        if (got > 0) {
            std::string banner(buf, buf + got);
            item["banner_length"] = got;
            item["banner_sha256"] = aida::network::js_analysis_tools::sha256_hex(banner);
            item["banner_preview"] = aida::network::js_analysis_tools::redact_sensitive_values(banner.substr(0, 160));
        }
    }
    closesocket(s);
    return item;
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

nlohmann::json fingerprint(const nlohmann::json& params)
{
    const std::string url = json_string(params, "url");
    const std::string target_domain = target_domain_from_url_or_domain(params);
    if (url.empty())
        return error_result("fingerprint", "url_required", target_domain);
    auto resp = send_url(url, params, "GET", {}, {}, "offensive_recon_fingerprint");
    if (!resp.has_value())
        return error_result("fingerprint", last_error(), target_domain);
    tech::initialize();
    auto techs = tech::fingerprint(resp->resp_headers, resp->resp_body, url);
    json tech_arr = json::array();
    for (const auto& t : techs)
        tech_arr.push_back(tech_to_json(t));
    json out;
    out["url"] = url;
    out["server"] = header_value(resp->resp_headers, "server");
    out["status_code"] = resp->status_code;
    out["exchange_id"] = resp->id;
    out["latency_ms"] = resp->latency_ms;
    out["technologies"] = tech_arr;
    out["security_headers"] = security_headers_json(resp->resp_headers);
    out["response"] = response_summary(*resp, false);
    return ok_result("fingerprint", target_domain, std::move(out));
}

nlohmann::json waf_detect(const nlohmann::json& params)
{
    const std::string url = json_string(params, "url");
    const std::string target_domain = target_domain_from_url_or_domain(params);
    if (url.empty())
        return error_result("waf_detect", "url_required", target_domain);
    json signals = json::array();
    json probes = json::array();
    auto baseline = send_url(url, params, "GET", {}, {}, "offensive_recon_waf");
    if (!baseline.has_value())
        return error_result("waf_detect", last_error(), target_domain);
    detect_waf_headers(*baseline, signals);
    detect_waf_body(*baseline, signals);
    probes.push_back(response_summary(*baseline, true));
    if (json_bool(params, "aggressive", false)) {
        std::string scheme;
        std::string host;
        std::string path;
        uint16_t port = 0;
        if (audit_http::parse_url(url, scheme, host, port, path)) {
            const std::vector<std::pair<std::string, std::string>> payloads = {
                {"xss", "<script>alert(1)</script>"},
                {"sqli", "' OR 1=1--"},
                {"lfi", "../../../../etc/passwd"}
            };
            for (const auto& payload : payloads) {
                if (call_expired())
                    break;
                const std::string sep = path.find('?') == std::string::npos ? "?" : "&";
                const std::string probe_url = scheme + "://" + host + (((scheme == "https" && port != 443) || (scheme == "http" && port != 80)) ? ":" + std::to_string(port) : std::string()) + path + sep + "aida_waf_probe=" + url_encode(payload.second);
                auto r = send_url(probe_url, params, "GET", {}, {}, "offensive_recon_waf");
                if (!r.has_value())
                    continue;
                detect_waf_headers(*r, signals);
                detect_waf_body(*r, signals);
                json item = response_summary(*r, true);
                item["probe"] = payload.first;
                item["blocked"] = r->status_code == 401 || r->status_code == 403 || r->status_code == 406 || r->status_code == 429 || r->status_code == 503;
                probes.push_back(std::move(item));
                if (r->status_code == 401 || r->status_code == 403 || r->status_code == 406 || r->status_code == 429 || r->status_code == 503)
                    add_waf_signal(signals, "Generic WAF", "Unknown", "attack probe blocked", 2);
            }
        }
    }
    int score = 0;
    std::map<std::string, int> names;
    for (const auto& s : signals) {
        if (!s.is_object())
            continue;
        score += s.value("weight", 0);
        names[s.value("name", std::string("Generic WAF"))] += s.value("weight", 0);
    }
    std::string best_name;
    int best_score = 0;
    for (const auto& kv : names) {
        if (kv.second > best_score) {
            best_name = kv.first;
            best_score = kv.second;
        }
    }
    json out;
    out["url"] = url;
    out["waf_detected"] = score >= 2;
    out["waf_name"] = best_name.empty() ? json(nullptr) : json(best_name);
    out["confidence"] = confidence_from_score(score);
    out["signals"] = signals;
    out["probes"] = probes;
    out["aggressive"] = json_bool(params, "aggressive", false);
    return ok_result("waf_detect", target_domain, std::move(out));
}

nlohmann::json dns_enum(const nlohmann::json& params)
{
    const std::string domain = json_string(params, "domain");
    if (domain.empty())
        return error_result("dns_enum", "domain_required");
    json out;
    out["domain"] = domain;
    out["records"] = json::object();
    out["errors"] = json::object();
    const std::vector<std::string> types = string_array_param(params, "record_types", {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV"}, 16);
    for (const auto& t0 : types) {
        if (call_expired())
            break;
        const std::string t = lower_ascii(t0);
        if (t == "a") query_dns_type(domain, DNS_TYPE_A, out);
        else if (t == "aaaa") query_dns_type(domain, DNS_TYPE_AAAA, out);
        else if (t == "cname") query_dns_type(domain, DNS_TYPE_CNAME, out);
        else if (t == "mx") query_dns_type(domain, DNS_TYPE_MX, out);
        else if (t == "txt") query_dns_type(domain, DNS_TYPE_TEXT, out);
        else if (t == "ns") query_dns_type(domain, DNS_TYPE_NS, out);
        else if (t == "soa") query_dns_type(domain, DNS_TYPE_SOA, out);
        else if (t == "srv") query_dns_type(domain, DNS_TYPE_SRV, out);
    }
    const char* canonical[] = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV"};
    for (const char* k : canonical) {
        if (!out["records"].contains(k))
            out["records"][k] = json::array();
    }
    out["interesting_records"] = json::array();
    for (const auto& txt : out["records"]["TXT"]) {
        if (!txt.is_object())
            continue;
        const std::string kind = txt.value("kind", std::string());
        if (kind == "spf" || kind == "dmarc" || kind == "ownership_verification" || kind == "sensitive_like") {
            json item;
            item["type"] = "TXT";
            item["value"] = txt;
            item["note"] = "mail or ownership verification metadata";
            out["interesting_records"].push_back(std::move(item));
        }
    }
    out["cancelled"] = call_expired();
    return ok_result("dns_enum", lower_ascii(domain), std::move(out));
}

nlohmann::json s3_discovery(const nlohmann::json& params)
{
    const std::string domain = json_string(params, "domain");
    if (domain.empty())
        return error_result("s3_discovery", "domain_required");
    const bool check_permissions = json_bool(params, "check_permissions", true);
    const bool create_issues = json_bool(params, "create_issues", true);
    const uint64_t audit_id = params.value("audit_id", 0ull);
    std::vector<std::string> buckets = bucket_candidates(domain, params);
    const size_t cap = json_size(params, "max_buckets", 32, 1, 128);
    if (buckets.size() > cap)
        buckets.resize(cap);
    json found = json::array();
    json tested = json::array();
    json issue_ids = json::array();
    for (const auto& bucket : buckets) {
        if (call_expired())
            break;
        json item;
        item["name"] = bucket;
        item["valid_name"] = valid_bucket_name(bucket);
        if (!valid_bucket_name(bucket)) {
            tested.push_back(std::move(item));
            continue;
        }
        const std::string root_url = "https://s3.amazonaws.com/" + bucket;
        auto head = send_url(root_url, params, "HEAD", {}, {}, "offensive_recon_s3");
        if (!head.has_value()) {
            item["error"] = last_error();
            tested.push_back(std::move(item));
            continue;
        }
        item["head"] = response_summary(*head, true);
        const bool exists = head->status_code == 200 || head->status_code == 301 || head->status_code == 302 || head->status_code == 307 || head->status_code == 308 || head->status_code == 403;
        item["exists_evidence"] = exists;
        item["permissions"] = json::object();
        item["permissions"]["read"] = permission_from_status(head->status_code);
        if (check_permissions) {
            const std::string list_url = root_url + "?list-type=2&max-keys=0";
            auto list = send_url(list_url, params, "GET", {}, {}, "offensive_recon_s3");
            if (list.has_value())
                item["permissions"]["list"] = permission_from_status(list->status_code);
            else
                item["permissions"]["list"] = json{{"error", last_error()}, {"allowed", false}};
        }
        item["permissions"]["write"] = json{{"checked", false}, {"allowed", nullptr}};
        if (exists) {
            found.push_back(item);
            const bool public_read = item["permissions"]["read"].value("allowed", false);
            const bool public_list = item["permissions"].contains("list") && item["permissions"]["list"].is_object() && item["permissions"]["list"].value("allowed", false);
            if (create_issues && (public_read || public_list)) {
                const uint64_t id = create_issue("cloud.s3.public_bucket",
                                                 "Public AWS S3 bucket exposure",
                                                 public_list ? severity_t::high : severity_t::medium,
                                                 "https",
                                                 "s3.amazonaws.com",
                                                 443,
                                                 "/" + bucket,
                                                 "A generated bucket candidate responded with public access evidence.",
                                                 "Restrict bucket and object ACLs, block public access at the account and bucket level, and review object listings for sensitive data.",
                                                 item.dump(),
                                                 audit_id);
                if (id != 0)
                    issue_ids.push_back(id);
            }
        }
        tested.push_back(std::move(item));
    }
    json out;
    out["domain"] = domain;
    out["buckets_tested"] = tested.size();
    out["tested"] = tested;
    out["buckets_found"] = found;
    out["issues_created"] = issue_ids;
    out["cancelled"] = call_expired();
    return ok_result("s3_discovery", lower_ascii(domain), std::move(out));
}

nlohmann::json cloud_metadata_test(const nlohmann::json& params)
{
    const std::string url = json_string(params, "url");
    const std::string target_domain = target_domain_from_url_or_domain(params);
    if (url.empty())
        return error_result("cloud_metadata_test", "url_required", target_domain);
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    if (!audit_http::parse_url(url, scheme, host, port, path))
        return error_result("cloud_metadata_test", "invalid_url", target_domain);
    std::vector<std::string> params_to_test;
    const std::string target_param = json_string(params, "param_target");
    if (!target_param.empty())
        params_to_test.push_back(target_param);
    else
        params_to_test = query_param_names(path);
    if (params_to_test.empty())
        params_to_test = {"url", "uri", "target", "next", "redirect"};
    const std::vector<std::pair<std::string, std::string>> endpoints = {
        {"aws", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
        {"aws_instance", "http://169.254.169.254/latest/meta-data/instance-id"},
        {"azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"},
        {"gcp", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"},
        {"digitalocean", "http://169.254.169.254/metadata/v1/id"},
        {"oracle", "http://169.254.169.254/opc/v1/instance/"},
        {"alibaba", "http://100.100.100.200/latest/meta-data/instance-id"}
    };
    std::set<std::string> provider_filter;
    if (params.contains("providers") && params["providers"].is_array()) {
        for (const auto& p : params["providers"]) {
            if (p.is_string()) {
                const std::string v = lower_ascii(p.get<std::string>());
                if (v != "all")
                    provider_filter.insert(v);
            }
        }
    }
    json probes = json::array();
    json issue_ids = json::array();
    bool vulnerable = false;
    for (const auto& provider : endpoints) {
        if (call_expired())
            break;
        if (!provider_filter.empty() && provider_filter.count(provider.first) == 0)
            continue;
        for (const std::string& param : params_to_test) {
            if (call_expired())
                break;
            const std::string mutated_path = replace_or_add_query_param(path, param, provider.second);
            const std::string mutated_url = scheme + "://" + host + (((scheme == "https" && port != 443) || (scheme == "http" && port != 80)) ? ":" + std::to_string(port) : std::string()) + mutated_path;
            auto resp = send_url(mutated_url, params, "GET", {}, {}, "offensive_recon_metadata");
            if (!resp.has_value())
                continue;
            json item;
            item["provider"] = provider.first;
            item["parameter"] = param;
            item["metadata_url_sha256"] = aida::network::js_analysis_tools::sha256_hex(provider.second);
            item["response"] = metadata_body_summary(*resp);
            const bool hit = item["response"]["indicators"].is_array() && !item["response"]["indicators"].empty() && resp->status_code >= 200 && resp->status_code < 500;
            item["metadata_evidence"] = hit;
            probes.push_back(item);
            if (hit) {
                vulnerable = true;
                if (json_bool(params, "create_issues", true)) {
                    const uint64_t id = create_issue("ssrf.cloud_metadata",
                                                     "Cloud metadata SSRF evidence",
                                                     item["response"].value("credential_like", false) ? severity_t::critical : severity_t::high,
                                                     scheme,
                                                     host,
                                                     port,
                                                     path,
                                                     "A target URL parameter returned cloud metadata-shaped content when supplied with an instance metadata endpoint.",
                                                     "Allow-list outbound destinations, block link-local metadata addresses at egress, and proxy server-side fetches through a hardened fetch service.",
                                                     item.dump(),
                                                     params.value("audit_id", 0ull));
                    if (id != 0)
                        issue_ids.push_back(id);
                }
            }
        }
    }
    json out;
    out["url"] = aida::network::js_analysis_tools::redact_url_for_output(url);
    out["vulnerable"] = vulnerable;
    out["probes"] = probes;
    out["issues_created"] = issue_ids;
    out["redacted"] = true;
    out["cancelled"] = call_expired();
    return ok_result("cloud_metadata_test", target_domain, std::move(out));
}

nlohmann::json port_scan(const nlohmann::json& params)
{
    const std::string host = json_string(params, "host");
    if (host.empty())
        return error_result("port_scan", "host_required");
    const std::string scan_type = lower_ascii(params.value("scan_type", std::string("connect")));
    if (json_bool(params, "use_driver", false) || scan_type == "syn") {
        return error_result("port_scan", "driver_backed_or_syn_scan_not_enabled", lower_ascii(host));
    }
    winsock_session_t ws;
    if (!ws.ok())
        return error_result("port_scan", "winsock_startup_failed", lower_ascii(host));
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* resolved = nullptr;
    const int gai = getaddrinfo(host.c_str(), nullptr, &hints, &resolved);
    if (gai != 0 || !resolved)
        return error_result("port_scan", "resolve_failed", lower_ascii(host));
    const uint64_t started = now_ms();
    const int per_port_timeout = (std::max)(100, (std::min)(5000, params.value("per_port_timeout_ms", 750)));
    const std::vector<uint16_t> ports = parse_ports(params);
    json open = json::array();
    size_t scanned = 0;
    for (uint16_t p : ports) {
        if (call_expired())
            break;
        ++scanned;
        for (addrinfo* ai = resolved; ai; ai = ai->ai_next) {
            auto item = connect_probe(host, ai, p, per_port_timeout);
            if (item.has_value()) {
                open.push_back(*item);
                break;
            }
        }
    }
    char ipbuf[INET6_ADDRSTRLEN] = {};
    if (resolved->ai_family == AF_INET)
        InetNtopA(AF_INET, &reinterpret_cast<sockaddr_in*>(resolved->ai_addr)->sin_addr, ipbuf, sizeof(ipbuf));
    else if (resolved->ai_family == AF_INET6)
        InetNtopA(AF_INET6, &reinterpret_cast<sockaddr_in6*>(resolved->ai_addr)->sin6_addr, ipbuf, sizeof(ipbuf));
    freeaddrinfo(resolved);
    json out;
    out["host"] = host;
    out["ip"] = ipbuf;
    out["scan_type"] = "connect";
    out["ports_scanned"] = static_cast<uint64_t>(scanned);
    out["ports_open"] = open;
    out["scan_duration_ms"] = now_ms() - started;
    out["cancelled"] = call_expired();
    return ok_result("port_scan", lower_ascii(host), std::move(out));
}

nlohmann::json full_recon(const nlohmann::json& params)
{
    const std::string domain = json_string(params, "domain");
    if (domain.empty())
        return error_result("full_recon", "domain_required");
    const std::string url = params.value("url", std::string("https://") + domain + "/");
    json fp_params = params;
    fp_params["url"] = url;
    json out;
    out["domain"] = domain;
    out["fingerprint"] = fingerprint(fp_params);
    out["waf"] = waf_detect(fp_params);
    json dns_params;
    dns_params["domain"] = domain;
    if (params.contains("record_types"))
        dns_params["record_types"] = params["record_types"];
    out["dns"] = dns_enum(dns_params);
    json subdomains;
    subdomain_enum::initialize();
    subdomain_enum::config_t cfg;
    cfg.domain = domain;
    cfg.run_passive = true;
    cfg.run_brute = params.value("subdomain_bruteforce", false);
    cfg.request_timeout_ms = (std::max)(1000, (std::min)(10000, params.value("subdomain_timeout_ms", 4000)));
    uint64_t sub_id = subdomain_enum::start(cfg);
    if (sub_id != 0) {
        uint64_t wait_until = now_ms() + static_cast<uint64_t>((std::max)(1000, (std::min)(60000, params.value("subdomain_wait_ms", 8000))));
        subdomain_enum::enum_status_t st;
        while (!call_expired() && now_ms() < wait_until) {
            st = subdomain_enum::status(sub_id);
            if (st.phase == subdomain_enum::enum_phase_t::complete || st.phase == subdomain_enum::enum_phase_t::error)
                break;
            Sleep(100);
        }
        st = subdomain_enum::status(sub_id);
        subdomains = subdomain_status_json(st);
        if (st.phase != subdomain_enum::enum_phase_t::complete && st.phase != subdomain_enum::enum_phase_t::error)
            subdomain_enum::stop(sub_id);
    } else {
        subdomains = json{{"error", subdomain_enum::last_error()}};
    }
    out["subdomains"] = subdomains;
    json s3_params = params;
    s3_params["domain"] = domain;
    out["s3"] = s3_discovery(s3_params);
    json port_params = params;
    port_params["host"] = domain;
    if (!port_params.contains("ports"))
        port_params["ports"] = json::array({80, 443, 8080, 8443, 22});
    out["ports"] = port_scan(port_params);
    out["cancelled"] = call_expired();
    return ok_result("full_recon", lower_ascii(domain), std::move(out));
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

nlohmann::json report_context(const std::string& target_domain, const std::vector<std::string>& run_ids, bool include_recon)
{
    json out;
    out["runs"] = json::array();
    if (!include_recon) {
        out["count"] = 0;
        return out;
    }
    std::set<std::string> ids(run_ids.begin(), run_ids.end());
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
        if (r.result.contains("technologies"))
            item["technologies"] = r.result["technologies"];
        if (r.result.contains("security_headers"))
            item["security_headers"] = r.result["security_headers"];
        if (r.result.contains("waf_detected"))
            item["waf"] = {{"detected", r.result["waf_detected"]}, {"name", r.result.value("waf_name", json(nullptr))}, {"confidence", r.result.value("confidence", json(nullptr))}};
        if (r.result.contains("records"))
            item["dns_records"] = r.result["records"];
        if (r.result.contains("buckets_found"))
            item["buckets_found"] = r.result["buckets_found"];
        if (r.result.contains("ports_open"))
            item["ports_open"] = r.result["ports_open"];
        if (r.result.contains("vulnerable"))
            item["cloud_metadata"] = {{"vulnerable", r.result["vulnerable"]}, {"redacted", true}};
        if (r.result.contains("issues_created"))
            item["issues_created"] = r.result["issues_created"];
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
