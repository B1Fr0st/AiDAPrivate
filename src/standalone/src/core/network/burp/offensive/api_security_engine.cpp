#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "api_security_engine.hpp"

#include "../api_definition.hpp"
#include "../audit_http.hpp"
#include "../issue.hpp"
#include "../payload_library.hpp"
#include "../scope.hpp"
#include "../../js_analysis_tools_standalone.hpp"
#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace offensive {
namespace api_security {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

struct api_job_t
{
    std::uint64_t id = 0;
    std::string action;
    std::string target;
    std::uint64_t started_ms = 0;
    std::uint64_t finished_ms = 0;
    bool running = false;
    bool cancelled = false;
    std::size_t requests_sent = 0;
    std::size_t requests_failed = 0;
    std::size_t issues_created = 0;
    json result = json::object();
};

std::atomic<std::uint64_t>& next_job_id()
{
    static std::atomic<std::uint64_t> v{1};
    return v;
}

std::mutex& jobs_mtx()
{
    static std::mutex m;
    return m;
}

std::unordered_map<std::uint64_t, api_job_t>& jobs()
{
    static std::unordered_map<std::uint64_t, api_job_t> j;
    return j;
}

std::uint64_t wall_ms()
{
    using namespace std::chrono;
    return static_cast<std::uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

bool call_cancelled()
{
    if (mcp_standalone::current_call_cancelled())
        return true;
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    return deadline != 0 && static_cast<std::uint64_t>(GetTickCount64()) >= deadline;
}

int bounded_timeout_ms(const json& params, int fallback, int max_ms)
{
    int value = params.value("timeout_ms", fallback);
    value = std::max(250, std::min(value, max_ms));
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline != 0) {
        const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
        if (deadline <= now)
            return 1;
        value = static_cast<int>(std::min<std::uint64_t>(static_cast<std::uint64_t>(value), deadline - now));
    }
    return std::max(1, value);
}

std::string lower_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string upper_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

std::string trim_copy(const std::string& s)
{
    std::size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a])))
        ++a;
    std::size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1])))
        --b;
    return s.substr(a, b - a);
}

std::string body_to_string(const std::vector<std::uint8_t>& body)
{
    if (body.empty())
        return {};
    return std::string(reinterpret_cast<const char*>(body.data()), body.size());
}

std::string host_header_value(const std::string& host, std::uint16_t port, bool tls)
{
    if ((tls && port == 443) || (!tls && port == 80))
        return host;
    return host + ":" + std::to_string(static_cast<unsigned>(port));
}

bool sensitive_name(const std::string& name)
{
    const std::string n = lower_copy(name);
    static const char* markers[] = {
        "authorization", "cookie", "token", "secret", "password", "passwd", "pwd", "api_key",
        "apikey", "access_key", "private", "credential", "session", "license", "bearer", "jwt",
        "oauth", "refresh", "csrf", "xsrf", "authenticity"
    };
    for (const char* marker : markers) {
        if (n.find(marker) != std::string::npos)
            return true;
    }
    return false;
}

std::vector<std::pair<std::string, std::string>> headers_from_json(const json& src)
{
    std::vector<std::pair<std::string, std::string>> out;
    if (!src.is_object())
        return out;
    for (auto it = src.begin(); it != src.end(); ++it) {
        if (!it.value().is_string())
            continue;
        const std::string name = it.key();
        const std::string value = it.value().get<std::string>();
        if (name.find('\r') != std::string::npos || name.find('\n') != std::string::npos)
            continue;
        if (value.find('\r') != std::string::npos || value.find('\n') != std::string::npos)
            continue;
        const std::string lname = lower_copy(name);
        if (lname == "host" || lname == "content-length" || lname == "connection")
            continue;
        out.emplace_back(name, value);
    }
    return out;
}

std::vector<std::string> strings_from_json(const json& src, std::size_t max_count)
{
    std::vector<std::string> out;
    if (!src.is_array())
        return out;
    for (const auto& item : src) {
        if (out.size() >= max_count)
            break;
        if (!item.is_string())
            continue;
        std::string text = trim_copy(item.get<std::string>());
        if (!text.empty())
            out.push_back(std::move(text));
    }
    return out;
}

json job_status_json(const api_job_t& j)
{
    json out;
    out["job_id"] = j.id;
    out["action"] = j.action;
    out["target"] = aida::network::js_analysis_tools::redact_url_for_output(j.target);
    out["started_ms"] = j.started_ms;
    out["finished_ms"] = j.finished_ms;
    out["running"] = j.running;
    out["cancelled"] = j.cancelled;
    out["requests_sent"] = static_cast<std::uint64_t>(j.requests_sent);
    out["requests_failed"] = static_cast<std::uint64_t>(j.requests_failed);
    out["issues_created"] = static_cast<std::uint64_t>(j.issues_created);
    return out;
}

api_job_t begin_job(const std::string& action, const std::string& target)
{
    api_job_t job;
    job.id = next_job_id().fetch_add(1);
    job.action = action;
    job.target = target;
    job.started_ms = wall_ms();
    job.running = true;
    {
        std::lock_guard<std::mutex> lk(jobs_mtx());
        jobs()[job.id] = job;
    }
    return job;
}

void finish_job(api_job_t& job, json result)
{
    job.finished_ms = wall_ms();
    job.running = false;
    job.cancelled = call_cancelled() || job.cancelled;
    job.result = std::move(result);
    {
        std::lock_guard<std::mutex> lk(jobs_mtx());
        jobs()[job.id] = job;
    }
}

bool get_job(std::uint64_t id, api_job_t& out)
{
    std::lock_guard<std::mutex> lk(jobs_mtx());
    auto it = jobs().find(id);
    if (it == jobs().end())
        return false;
    out = it->second;
    return true;
}

std::string url_join_origin_path(const std::string& base_url, const std::string& path)
{
    std::string scheme;
    std::string host;
    std::string parsed_path;
    std::uint16_t port = 0;
    if (!audit_http::parse_url(base_url, scheme, host, port, parsed_path))
        return {};
    std::string out = scheme + "://" + host;
    if ((scheme == "https" && port != 443) || (scheme == "http" && port != 80))
        out += ":" + std::to_string(static_cast<unsigned>(port));
    if (path.empty())
        out += "/";
    else if (path.front() == '/')
        out += path;
    else
        out += "/" + path;
    return out;
}

bool parse_url_or_error(const std::string& url,
                        std::string& scheme,
                        std::string& host,
                        std::uint16_t& port,
                        std::string& path,
                        std::string& error)
{
    if (!audit_http::parse_url(url, scheme, host, port, path)) {
        error = "url parse failed";
        return false;
    }
    if (scheme != "http" && scheme != "https") {
        error = "url scheme must be http or https";
        return false;
    }
    return true;
}

std::vector<std::uint8_t> build_http_request(const std::string& method,
                                             const std::string& url,
                                             const json& headers_json,
                                             const std::string& body,
                                             const std::string& content_type,
                                             std::string& host,
                                             std::uint16_t& port,
                                             bool& tls,
                                             std::string& error)
{
    std::string scheme;
    std::string path;
    if (!parse_url_or_error(url, scheme, host, port, path, error))
        return {};
    tls = scheme == "https";
    std::vector<std::pair<std::string, std::string>> headers = headers_from_json(headers_json);
    if (!body.empty() && !content_type.empty()) {
        bool has_ct = false;
        for (const auto& h : headers) {
            if (lower_copy(h.first) == "content-type")
                has_ct = true;
        }
        if (!has_ct)
            headers.emplace_back("Content-Type", content_type);
    }
    std::ostringstream req;
    req << upper_copy(method.empty() ? std::string("GET") : method) << " " << (path.empty() ? "/" : path) << " HTTP/1.1\r\n";
    req << "Host: " << host_header_value(host, port, tls) << "\r\n";
    bool has_accept = false;
    for (const auto& h : headers) {
        if (lower_copy(h.first) == "accept")
            has_accept = true;
        req << h.first << ": " << h.second << "\r\n";
    }
    if (!has_accept)
        req << "Accept: application/json, text/plain, */*\r\n";
    req << "User-Agent: AiDA-REST-Offensive/1.0\r\n";
    if (!body.empty())
        req << "Content-Length: " << body.size() << "\r\n";
    req << "Connection: close\r\n\r\n";
    req << body;
    const std::string raw = req.str();
    return std::vector<std::uint8_t>(raw.begin(), raw.end());
}

std::optional<exchange_observed_t> send_url_request(const std::string& method,
                                                    const std::string& url,
                                                    const json& headers,
                                                    const std::string& body,
                                                    const std::string& content_type,
                                                    int timeout_ms,
                                                    bool enforce_scope,
                                                    std::string& error)
{
    if (enforce_scope && !scope::in_scope(url)) {
        error = "target out of scope";
        return std::nullopt;
    }
    std::string host;
    std::uint16_t port = 0;
    bool tls = false;
    std::vector<std::uint8_t> request = build_http_request(method, url, headers, body, content_type, host, port, tls, error);
    if (request.empty())
        return std::nullopt;
    audit_http::send_options_t opts;
    opts.timeout_ms = timeout_ms;
    opts.follow_redirects = false;
    opts.max_redirects = 0;
    opts.enforce_scope = enforce_scope;
    opts.exchange_source = "offensive_api_rest";
    auto resp = audit_http::send(request, host, port, tls, opts);
    if (!resp.has_value())
        error = audit_http::last_error();
    return resp;
}

std::string response_header(const exchange_observed_t& ex, const std::string& name)
{
    const std::string lname = lower_copy(name);
    for (const auto& h : ex.resp_headers) {
        if (lower_copy(h.first) == lname)
            return h.second;
    }
    return {};
}

std::set<std::string> json_top_keys(const std::string& body)
{
    std::set<std::string> out;
    json parsed = json::parse(body, nullptr, false);
    if (!parsed.is_object())
        return out;
    for (auto it = parsed.begin(); it != parsed.end(); ++it)
        out.insert(it.key());
    return out;
}

json set_diff_json(const std::set<std::string>& a, const std::set<std::string>& b)
{
    json out = json::array();
    for (const std::string& item : a) {
        if (b.find(item) == b.end())
            out.push_back(item);
    }
    return out;
}

json exchange_summary(const exchange_observed_t& ex)
{
    const std::string body = body_to_string(ex.resp_body);
    json out;
    out["status"] = ex.status_code;
    out["latency_ms"] = ex.latency_ms;
    out["body_length"] = static_cast<std::uint64_t>(ex.resp_body.size());
    out["body_sha256"] = aida::network::js_analysis_tools::sha256_hex(body);
    out["content_type"] = response_header(ex, "Content-Type");
    const std::string location = response_header(ex, "Location");
    if (!location.empty())
        out["location"] = aida::network::js_analysis_tools::redact_url_for_output(location);
    out["set_cookie_count"] = 0;
    for (const auto& h : ex.resp_headers) {
        if (lower_copy(h.first) == "set-cookie")
            out["set_cookie_count"] = out["set_cookie_count"].get<int>() + 1;
    }
    out["json_top_keys"] = json::array();
    for (const auto& key : json_top_keys(body))
        out["json_top_keys"].push_back(key);
    return out;
}

json endpoint_json(const api_definition::api_request_template_t& tpl, const std::string& source)
{
    json out;
    out["id"] = tpl.id;
    out["method"] = upper_copy(tpl.method.empty() ? std::string("UNKNOWN") : tpl.method);
    out["base_url"] = aida::network::js_analysis_tools::redact_url_for_output(tpl.base_url);
    out["path"] = tpl.path.empty() ? "/" : tpl.path;
    out["source"] = source;
    out["auth_kind"] = sensitive_name(tpl.auth_kind) ? "sensitive" : tpl.auth_kind;
    out["query_params"] = json::array();
    for (const auto& p : tpl.query_params)
        out["query_params"].push_back(p.first);
    out["body_params"] = json::array();
    for (const auto& p : tpl.body_params)
        out["body_params"].push_back(p.first);
    out["path_params"] = json::array();
    for (const auto& p : tpl.path_params)
        out["path_params"].push_back(p.first);
    return out;
}

void append_collection_endpoints(json& endpoints, const api_definition::api_collection_t& col, const std::string& source)
{
    for (const auto& tpl : col.requests)
        endpoints.push_back(endpoint_json(tpl, source));
}

std::uint64_t import_source_text(const std::string& text, const std::string& format)
{
    api_definition::api_format_t fmt = api_definition::api_format_t::auto_detect;
    api_definition::parse_format(format.empty() ? std::string("auto") : format, fmt);
    return api_definition::import_from_text(text, fmt);
}

std::vector<std::string> openapi_candidates(const std::string& base_url)
{
    static const char* paths[] = {
        "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
        "/api-docs", "/api/docs", "/v3/api-docs", "/swagger/v1/swagger.json",
        "/docs/openapi.json", "/.well-known/openapi.json"
    };
    std::vector<std::string> out;
    for (const char* p : paths) {
        std::string joined = url_join_origin_path(base_url, p);
        if (!joined.empty())
            out.push_back(joined);
    }
    return out;
}

std::uint64_t add_issue(const std::string& type_key,
                        const std::string& name,
                        severity_t severity,
                        confidence_t confidence,
                        const std::string& url,
                        const std::string& parameter,
                        const std::string& description,
                        const json& response_summary)
{
    issue_store::initialize();
    std::string scheme;
    std::string host;
    std::string path;
    std::uint16_t port = 0;
    audit_http::parse_url(url, scheme, host, port, path);
    issue_t issue;
    issue.type_key = type_key;
    issue.name = name;
    issue.severity = severity;
    issue.confidence = confidence;
    issue.scheme = scheme;
    issue.host = host;
    issue.port = port;
    issue.path = path.empty() ? "/" : path;
    issue.parameter = parameter;
    issue.insertion_point = parameter.empty() ? "api" : "api:" + parameter;
    issue.description = description;
    issue.remediation = "Apply server-side authorization, strict request schemas, bounded rate limits, and deny-by-default validation for unexpected fields or parameters.";
    issue.seen_ms = wall_ms();
    evidence_t evidence;
    evidence.request_raw = "url=" + aida::network::js_analysis_tools::redact_url_for_output(url) + " parameter=" + parameter;
    evidence.response_raw = response_summary.dump();
    evidence.marker = description;
    issue.evidence.push_back(std::move(evidence));
    return issue_store::add(std::move(issue));
}

json candidate_mass_fields(const json& params)
{
    json fields = json::object({
        {"isAdmin", true},
        {"admin", true},
        {"role", "admin"},
        {"roles", json::array({"admin"})},
        {"permissions", json::array({"*"})},
        {"verified", true},
        {"email_verified", true},
        {"owner", true},
        {"plan", "enterprise"},
        {"price", 0},
        {"balance", 999999}
    });
    if (params.contains("fields") && params["fields"].is_object()) {
        for (auto it = params["fields"].begin(); it != params["fields"].end(); ++it)
            fields[it.key()] = it.value();
    }
    if (params.contains("inject_fields") && params["inject_fields"].is_array()) {
        json selected = json::object();
        for (const auto& item : params["inject_fields"]) {
            if (item.is_string()) {
                const std::string name = item.get<std::string>();
                if (fields.contains(name))
                    selected[name] = fields[name];
                else
                    selected[name] = json(true);
            } else if (item.is_object() && item.contains("name") && item["name"].is_string()) {
                const std::string name = item["name"].get<std::string>();
                selected[name] = item.contains("value") ? item["value"] : json(true);
            }
        }
        if (!selected.empty())
            fields = std::move(selected);
    }
    return fields;
}

std::string append_query_param(const std::string& url, const std::string& name, const std::string& value)
{
    std::string out = url;
    const std::size_t hash = out.find('#');
    std::string fragment;
    if (hash != std::string::npos) {
        fragment = out.substr(hash);
        out.erase(hash);
    }
    out += out.find('?') == std::string::npos ? "?" : "&";
    out += name;
    out += "=";
    out += value;
    out += fragment;
    return out;
}

json status_payload(std::uint64_t job_id)
{
    json out;
    if (job_id != 0) {
        api_job_t job;
        if (!get_job(job_id, job)) {
            out["found"] = false;
            out["job_id"] = job_id;
            return out;
        }
        out["found"] = true;
        out["job"] = job_status_json(job);
        return out;
    }
    json arr = json::array();
    {
        std::lock_guard<std::mutex> lk(jobs_mtx());
        for (const auto& kv : jobs())
            arr.push_back(job_status_json(kv.second));
    }
    out["count"] = arr.size();
    out["jobs"] = std::move(arr);
    return out;
}

bool load_collection_from_params(const json& params,
                                 const std::string& prefix,
                                 api_definition::api_collection_t& out,
                                 json& source_summary,
                                 std::string& error)
{
    const std::string id_key = prefix.empty() ? std::string("collection_id") : prefix + "_collection_id";
    const std::string source_key = prefix.empty() ? std::string("source") : prefix + "_source";
    const std::string url_key = prefix.empty() ? std::string("url") : prefix + "_url";
    std::uint64_t id = 0;
    if (params.contains(id_key) && params[id_key].is_number_unsigned())
        id = params[id_key].get<std::uint64_t>();
    if (id == 0 && params.contains(id_key) && params[id_key].is_number_integer()) {
        const auto signed_id = params[id_key].get<std::int64_t>();
        if (signed_id > 0)
            id = static_cast<std::uint64_t>(signed_id);
    }
    if (id != 0) {
        if (!api_definition::get_collection(id, out)) {
            error = "collection not found";
            return false;
        }
        source_summary = json{{"type", "collection"}, {"collection_id", id}};
        return true;
    }
    if (params.contains(source_key) && params[source_key].is_string()) {
        const std::string source = params[source_key].get<std::string>();
        const std::uint64_t imported = import_source_text(source, params.value("format", std::string("auto")));
        if (imported == 0 || !api_definition::get_collection(imported, out)) {
            error = api_definition::last_error();
            return false;
        }
        source_summary = json{{"type", "inline_source"}, {"sha256", aida::network::js_analysis_tools::sha256_hex(source)}, {"collection_id", imported}};
        return true;
    }
    if (params.contains(url_key) && params[url_key].is_string()) {
        const std::string url = params[url_key].get<std::string>();
        if (params.value("enforce_scope", true) && !scope::in_scope(url)) {
            error = "target out of scope";
            return false;
        }
        const std::uint64_t imported = api_definition::import_from_url(url);
        if (imported == 0 || !api_definition::get_collection(imported, out)) {
            error = api_definition::last_error();
            return false;
        }
        source_summary = json{{"type", "url"}, {"url", aida::network::js_analysis_tools::redact_url_for_output(url)}, {"collection_id", imported}};
        return true;
    }
    error = prefix + " collection_id, source, or url required";
    return false;
}

std::set<std::string> endpoint_signature_set(const api_definition::api_collection_t& col)
{
    std::set<std::string> out;
    for (const auto& r : col.requests)
        out.insert(upper_copy(r.method.empty() ? std::string("UNKNOWN") : r.method) + " " + (r.path.empty() ? "/" : r.path));
    return out;
}

}

tool_result_t discover(const json& params)
{
    const std::string base_url = params.value("base_url", params.value("url", std::string()));
    const bool enforce_scope = params.value("enforce_scope", true);
    api_job_t job = begin_job("discover", base_url);
    api_definition::initialize();
    json endpoints = json::array();
    json sources = json::array();
    json probes = json::array();

    if (params.contains("collection_id")) {
        api_definition::api_collection_t col;
        std::string error;
        json source;
        if (load_collection_from_params(params, std::string(), col, source, error)) {
            append_collection_endpoints(endpoints, col, "collection");
            sources.push_back(std::move(source));
        }
    }

    if (params.contains("source") && params["source"].is_string()) {
        const std::string source = params["source"].get<std::string>();
        const std::uint64_t id = import_source_text(source, params.value("format", std::string("auto")));
        if (id != 0) {
            api_definition::api_collection_t col;
            if (api_definition::get_collection(id, col)) {
                append_collection_endpoints(endpoints, col, "inline_source");
                sources.push_back(json{{"type", "inline_source"}, {"collection_id", id}, {"sha256", aida::network::js_analysis_tools::sha256_hex(source)}});
            }
        } else {
            sources.push_back(json{{"type", "inline_source"}, {"error", api_definition::last_error()}, {"sha256", aida::network::js_analysis_tools::sha256_hex(source)}});
        }
    }

    std::vector<std::string> urls;
    if (params.contains("openapi_url") && params["openapi_url"].is_string())
        urls.push_back(params["openapi_url"].get<std::string>());
    if (!base_url.empty()) {
        std::vector<std::string> candidates = openapi_candidates(base_url);
        const int max_probes = std::max(1, std::min(params.value("max_probes", 10), 24));
        if (static_cast<int>(candidates.size()) > max_probes)
            candidates.resize(static_cast<std::size_t>(max_probes));
        urls.insert(urls.end(), candidates.begin(), candidates.end());
    }

    for (const std::string& url : urls) {
        if (call_cancelled()) {
            job.cancelled = true;
            break;
        }
        json probe;
        probe["url"] = aida::network::js_analysis_tools::redact_url_for_output(url);
        std::string error;
        auto resp = send_url_request("GET", url, params.value("headers", json::object()), {}, {},
                                     bounded_timeout_ms(params, 12000, 45000), enforce_scope, error);
        ++job.requests_sent;
        if (!resp.has_value()) {
            ++job.requests_failed;
            probe["ok"] = false;
            probe["error"] = error;
            probes.push_back(std::move(probe));
            continue;
        }
        probe["status"] = resp->status_code;
        probe["body_length"] = static_cast<std::uint64_t>(resp->resp_body.size());
        const std::string body = body_to_string(resp->resp_body);
        const std::uint64_t id = import_source_text(body, params.value("format", std::string("auto")));
        if (id != 0) {
            api_definition::api_collection_t col;
            if (api_definition::get_collection(id, col)) {
                append_collection_endpoints(endpoints, col, "openapi_probe");
                sources.push_back(json{{"type", "openapi_probe"}, {"url", aida::network::js_analysis_tools::redact_url_for_output(url)}, {"collection_id", id}, {"sha256", aida::network::js_analysis_tools::sha256_hex(body)}});
                probe["ok"] = true;
                probe["collection_id"] = id;
            }
        } else {
            probe["ok"] = false;
            probe["parse_error"] = api_definition::last_error();
        }
        probes.push_back(std::move(probe));
    }

    if (params.contains("js_endpoints") && params["js_endpoints"].is_array()) {
        for (const std::string& ep : strings_from_json(params["js_endpoints"], 512)) {
            json row;
            row["method"] = "UNKNOWN";
            row["path"] = ep;
            row["source"] = "js_endpoints";
            endpoints.push_back(std::move(row));
        }
        sources.push_back(json{{"type", "js_endpoints"}, {"count", static_cast<std::uint64_t>(params["js_endpoints"].size())}});
    }

    json out;
    out["job_id"] = job.id;
    out["base_url"] = aida::network::js_analysis_tools::redact_url_for_output(base_url);
    out["total_endpoints"] = endpoints.size();
    out["endpoints_discovered"] = std::move(endpoints);
    out["sources"] = std::move(sources);
    out["probes"] = std::move(probes);
    out["issues_created"] = json::array();
    finish_job(job, out);
    return tool_result_t::ok(out);
}

tool_result_t param_fuzz(const json& params)
{
    const std::string url = params.value("url", std::string());
    if (url.empty())
        return tool_result_t::error("url required");
    const bool enforce_scope = params.value("enforce_scope", true);
    const std::string method = params.value("method", std::string("GET"));
    api_job_t job = begin_job("param_fuzz", url);
    std::string error;
    auto baseline = send_url_request(method, url, params.value("headers", json::object()), params.value("body", std::string()), params.value("content_type", std::string()),
                                     bounded_timeout_ms(params, 15000, 45000), enforce_scope, error);
    ++job.requests_sent;
    if (!baseline.has_value()) {
        ++job.requests_failed;
        json out{{"job_id", job.id}, {"error", error}, {"url", aida::network::js_analysis_tools::redact_url_for_output(url)}};
        finish_job(job, out);
        return tool_result_t::error("baseline request failed", out);
    }

    std::vector<std::string> candidates = strings_from_json(params.value("known_params", json::array()), 256);
    if (candidates.empty()) {
        payloads::initialize();
        candidates = payloads::entries(params.value("wordlist_id", std::string("fuzz/common_params")), static_cast<std::size_t>(std::max(1, std::min(params.value("max_params", 64), 256))));
    }
    if (candidates.empty()) {
        candidates = {"debug", "test", "admin", "role", "isAdmin", "include", "callback", "redirect", "next", "format", "fields", "expand"};
    }
    const int max_params = std::max(1, std::min(params.value("max_params", 64), 256));
    if (static_cast<int>(candidates.size()) > max_params)
        candidates.resize(static_cast<std::size_t>(max_params));

    const json baseline_summary = exchange_summary(*baseline);
    const std::string baseline_body = body_to_string(baseline->resp_body);
    const std::set<std::string> baseline_keys = json_top_keys(baseline_body);
    json hits = json::array();
    json issues = json::array();
    const std::string marker = params.value("marker", std::string("aida_param_probe"));
    for (const std::string& param : candidates) {
        if (call_cancelled()) {
            job.cancelled = true;
            break;
        }
        const std::string probe_url = append_query_param(url, param, marker);
        std::string send_error;
        auto variant = send_url_request(method, probe_url, params.value("headers", json::object()), params.value("body", std::string()), params.value("content_type", std::string()),
                                        bounded_timeout_ms(params, 15000, 45000), enforce_scope, send_error);
        ++job.requests_sent;
        if (!variant.has_value()) {
            ++job.requests_failed;
            continue;
        }
        const std::string variant_body = body_to_string(variant->resp_body);
        const long long length_delta = static_cast<long long>(variant->resp_body.size()) - static_cast<long long>(baseline->resp_body.size());
        const bool status_changed = variant->status_code != baseline->status_code;
        const bool reflected = variant_body.find(marker) != std::string::npos && baseline_body.find(marker) == std::string::npos;
        const json added_keys = set_diff_json(json_top_keys(variant_body), baseline_keys);
        const bool interesting = status_changed || reflected || !added_keys.empty() || std::llabs(length_delta) > 64;
        if (!interesting)
            continue;
        json row;
        row["param"] = param;
        row["status_changed"] = status_changed;
        row["baseline_status"] = baseline->status_code;
        row["variant_status"] = variant->status_code;
        row["length_delta"] = length_delta;
        row["reflected_marker"] = reflected;
        row["json_keys_added"] = added_keys;
        row["summary"] = exchange_summary(*variant);
        hits.push_back(row);
    }
    if (!hits.empty()) {
        std::uint64_t issue_id = add_issue("api.hidden-parameter.differential",
                                           "API hidden parameter differential behavior",
                                           severity_t::info,
                                           confidence_t::firm,
                                           url,
                                           "multiple",
                                           "One or more fuzzed parameters changed response status, shape, length, or reflected a marker.",
                                           baseline_summary);
        issues.push_back(issue_id);
        job.issues_created = 1;
    }
    json out;
    out["job_id"] = job.id;
    out["url"] = aida::network::js_analysis_tools::redact_url_for_output(url);
    out["baseline"] = baseline_summary;
    out["tested"] = static_cast<std::uint64_t>(candidates.size());
    out["hits"] = std::move(hits);
    out["issues_created"] = std::move(issues);
    finish_job(job, out);
    return tool_result_t::ok(out);
}

tool_result_t mass_assignment(const json& params)
{
    const std::string url = params.value("url", std::string());
    if (url.empty())
        return tool_result_t::error("url required");
    json body = params.value("body", params.value("params", json::object()));
    if (!body.is_object())
        return tool_result_t::error("body object required");
    json headers = params.value("headers", json::object());
    if (params.contains("auth_token") && params["auth_token"].is_string())
        headers["Authorization"] = "Bearer " + params["auth_token"].get<std::string>();
    const std::string method = params.value("method", std::string("PATCH"));
    const bool enforce_scope = params.value("enforce_scope", true);
    api_job_t job = begin_job("mass_assignment", url);
    std::string error;
    auto baseline = send_url_request(method, url, headers, body.dump(), "application/json",
                                     bounded_timeout_ms(params, 15000, 60000), enforce_scope, error);
    ++job.requests_sent;
    if (!baseline.has_value()) {
        ++job.requests_failed;
        json out{{"job_id", job.id}, {"error", error}, {"url", aida::network::js_analysis_tools::redact_url_for_output(url)}};
        finish_job(job, out);
        return tool_result_t::error("baseline request failed", out);
    }
    const json baseline_summary = exchange_summary(*baseline);
    const std::string baseline_body = body_to_string(baseline->resp_body);
    const std::set<std::string> baseline_keys = json_top_keys(baseline_body);
    json fields = candidate_mass_fields(params);
    const int max_variants = std::max(1, std::min(params.value("max_variants", 10), 32));
    json accepted = json::array();
    int sent = 0;
    for (auto it = fields.begin(); it != fields.end() && sent < max_variants; ++it) {
        if (call_cancelled()) {
            job.cancelled = true;
            break;
        }
        if (body.contains(it.key()))
            continue;
        json variant_body = body;
        variant_body[it.key()] = it.value();
        std::string send_error;
        auto variant = send_url_request(method, url, headers, variant_body.dump(), "application/json",
                                        bounded_timeout_ms(params, 15000, 60000), enforce_scope, send_error);
        ++sent;
        ++job.requests_sent;
        if (!variant.has_value()) {
            ++job.requests_failed;
            continue;
        }
        const std::string variant_text = body_to_string(variant->resp_body);
        const long long length_delta = static_cast<long long>(variant->resp_body.size()) - static_cast<long long>(baseline->resp_body.size());
        const bool status_changed = variant->status_code != baseline->status_code;
        const bool field_reflected = baseline_body.find(it.key()) == std::string::npos && variant_text.find(it.key()) != std::string::npos;
        const json added_keys = set_diff_json(json_top_keys(variant_text), baseline_keys);
        if (status_changed || field_reflected || !added_keys.empty() || std::llabs(length_delta) > 64) {
            json row;
            row["field"] = it.key();
            row["value_type"] = it.value().type_name();
            row["baseline_status"] = baseline->status_code;
            row["variant_status"] = variant->status_code;
            row["length_delta"] = length_delta;
            row["field_reflected"] = field_reflected;
            row["json_keys_added"] = added_keys;
            row["summary"] = exchange_summary(*variant);
            accepted.push_back(std::move(row));
        }
    }
    json issues = json::array();
    if (!accepted.empty()) {
        std::uint64_t issue_id = add_issue("api.mass-assignment.differential",
                                           "Potential API mass assignment",
                                           severity_t::high,
                                           confidence_t::tentative,
                                           url,
                                           "json_body",
                                           "Unexpected JSON fields changed response status, body shape, length, or were reflected by the endpoint.",
                                           baseline_summary);
        issues.push_back(issue_id);
        job.issues_created = 1;
    }
    json out;
    out["job_id"] = job.id;
    out["url"] = aida::network::js_analysis_tools::redact_url_for_output(url);
    out["method"] = upper_copy(method);
    out["baseline"] = baseline_summary;
    out["variants_sent"] = sent;
    out["fields_accepted"] = std::move(accepted);
    out["issues_created"] = std::move(issues);
    if (params.contains("auth_token") && params["auth_token"].is_string()) {
        const std::string token = params["auth_token"].get<std::string>();
        out["auth_token_sha256"] = aida::network::js_analysis_tools::sha256_hex(token);
        out["auth_token_length"] = static_cast<std::uint64_t>(token.size());
        out["raw_auth_token_returned"] = false;
    }
    finish_job(job, out);
    return tool_result_t::ok(out);
}

tool_result_t authz_matrix(const json& params)
{
    const std::string url = params.value("url", std::string());
    if (url.empty())
        return tool_result_t::error("url required");
    const std::string method = params.value("method", std::string("GET"));
    const bool enforce_scope = params.value("enforce_scope", true);
    api_job_t job = begin_job("authz_matrix", url);
    json identities = params.value("identities", json::array());
    if (!identities.is_array() || identities.empty()) {
        identities = json::array({json{{"label", "unauthenticated"}, {"headers", json::object()}}});
        if (params.contains("auth_token_low") && params["auth_token_low"].is_string())
            identities.push_back(json{{"label", "low"}, {"auth_token", params["auth_token_low"]}});
        if (params.contains("auth_token_high") && params["auth_token_high"].is_string())
            identities.push_back(json{{"label", "high"}, {"auth_token", params["auth_token_high"]}});
    }
    const int max_identities = std::max(1, std::min(params.value("max_identities", 8), 16));
    json rows = json::array();
    json successful_labels = json::array();
    for (int i = 0; i < max_identities && i < static_cast<int>(identities.size()); ++i) {
        if (call_cancelled()) {
            job.cancelled = true;
            break;
        }
        if (!identities[static_cast<std::size_t>(i)].is_object())
            continue;
        const json& ident = identities[static_cast<std::size_t>(i)];
        json headers = params.value("headers", json::object());
        if (ident.contains("headers") && ident["headers"].is_object()) {
            for (auto it = ident["headers"].begin(); it != ident["headers"].end(); ++it)
                headers[it.key()] = it.value();
        }
        std::string token;
        if (ident.contains("auth_token") && ident["auth_token"].is_string()) {
            token = ident["auth_token"].get<std::string>();
            headers["Authorization"] = "Bearer " + token;
        }
        const std::string label = ident.value("label", std::string("identity_") + std::to_string(i));
        std::string error;
        auto resp = send_url_request(method, url, headers, params.value("body", std::string()), params.value("content_type", std::string()),
                                     bounded_timeout_ms(params, 15000, 60000), enforce_scope, error);
        ++job.requests_sent;
        json row;
        row["label"] = label;
        row["ok"] = resp.has_value();
        if (!token.empty()) {
            row["auth_token_sha256"] = aida::network::js_analysis_tools::sha256_hex(token);
            row["auth_token_length"] = static_cast<std::uint64_t>(token.size());
            row["raw_auth_token_returned"] = false;
        }
        if (resp.has_value()) {
            row["summary"] = exchange_summary(*resp);
            const bool success = resp->status_code >= 200 && resp->status_code < 400;
            row["success_status"] = success;
            if (success)
                successful_labels.push_back(label);
        } else {
            ++job.requests_failed;
            row["error"] = error;
        }
        rows.push_back(std::move(row));
    }
    json issues = json::array();
    if (successful_labels.size() > 1) {
        std::uint64_t issue_id = add_issue("api.authorization.matrix-equivalence",
                                           "API authorization matrix shows multiple successful identities",
                                           severity_t::high,
                                           confidence_t::tentative,
                                           url,
                                           "authorization",
                                           "Multiple identities received successful responses for the same endpoint. Review object and role authorization.",
                                           json{{"successful_identities", successful_labels}});
        issues.push_back(issue_id);
        job.issues_created = 1;
    }
    json out;
    out["job_id"] = job.id;
    out["url"] = aida::network::js_analysis_tools::redact_url_for_output(url);
    out["method"] = upper_copy(method);
    out["results"] = std::move(rows);
    out["successful_identities"] = successful_labels;
    out["issues_created"] = std::move(issues);
    finish_job(job, out);
    return tool_result_t::ok(out);
}

tool_result_t rate_limit_test(const json& params)
{
    const std::string url = params.value("url", std::string());
    if (url.empty())
        return tool_result_t::error("url required");
    const std::string method = params.value("method", std::string("GET"));
    const bool enforce_scope = params.value("enforce_scope", true);
    int request_count = params.value("request_count", 30);
    request_count = std::max(1, std::min(request_count, 120));
    api_job_t job = begin_job("rate_limit_test", url);
    json histogram = json::object();
    json samples = json::array();
    int limited = 0;
    for (int i = 0; i < request_count; ++i) {
        if (call_cancelled()) {
            job.cancelled = true;
            break;
        }
        json headers = params.value("headers", json::object());
        if (params.value("rotate_forwarded_for", true))
            headers["X-Forwarded-For"] = "127.0.0." + std::to_string((i % 250) + 1);
        std::string error;
        auto resp = send_url_request(method, url, headers, params.value("body", std::string()), params.value("content_type", std::string()),
                                     bounded_timeout_ms(params, 10000, 45000), enforce_scope, error);
        ++job.requests_sent;
        if (!resp.has_value()) {
            ++job.requests_failed;
            continue;
        }
        const std::string code = std::to_string(resp->status_code);
        histogram[code] = histogram.value(code, 0) + 1;
        const std::string retry_after = response_header(*resp, "Retry-After");
        if (resp->status_code == 429 || resp->status_code == 403 || !retry_after.empty())
            ++limited;
        if (samples.size() < 12)
            samples.push_back(exchange_summary(*resp));
    }
    json issues = json::array();
    if (request_count >= 30 && limited == 0 && !job.cancelled) {
        std::uint64_t issue_id = add_issue("api.rate-limit.absent",
                                           "API rate limit not observed",
                                           severity_t::low,
                                           confidence_t::tentative,
                                           url,
                                           "rate_limit",
                                           "A bounded request burst did not produce 429, 403, or Retry-After evidence.",
                                           json{{"request_count", request_count}, {"status_histogram", histogram}});
        issues.push_back(issue_id);
        job.issues_created = 1;
    }
    json out;
    out["job_id"] = job.id;
    out["url"] = aida::network::js_analysis_tools::redact_url_for_output(url);
    out["method"] = upper_copy(method);
    out["requests_attempted"] = request_count;
    out["requests_sent"] = static_cast<std::uint64_t>(job.requests_sent);
    out["limited_responses"] = limited;
    out["rate_limited"] = limited > 0;
    out["status_histogram"] = histogram;
    out["samples"] = std::move(samples);
    out["issues_created"] = std::move(issues);
    finish_job(job, out);
    return tool_result_t::ok(out);
}

tool_result_t schema_diff(const json& params)
{
    api_job_t job = begin_job("schema_diff", params.value("left_url", std::string()));
    api_definition::api_collection_t left;
    api_definition::api_collection_t right;
    json left_source;
    json right_source;
    std::string error;
    if (!load_collection_from_params(params, "left", left, left_source, error) &&
        !load_collection_from_params(params, "baseline", left, left_source, error)) {
        json out{{"job_id", job.id}, {"error", error}};
        finish_job(job, out);
        return tool_result_t::error("left schema unavailable", out);
    }
    if (!load_collection_from_params(params, "right", right, right_source, error) &&
        !load_collection_from_params(params, "candidate", right, right_source, error)) {
        json out{{"job_id", job.id}, {"error", error}};
        finish_job(job, out);
        return tool_result_t::error("right schema unavailable", out);
    }
    const auto lset = endpoint_signature_set(left);
    const auto rset = endpoint_signature_set(right);
    json added = json::array();
    json removed = json::array();
    for (const auto& s : rset) {
        if (lset.find(s) == lset.end())
            added.push_back(s);
    }
    for (const auto& s : lset) {
        if (rset.find(s) == rset.end())
            removed.push_back(s);
    }
    json out;
    out["job_id"] = job.id;
    out["left_source"] = left_source;
    out["right_source"] = right_source;
    out["left_endpoint_count"] = static_cast<std::uint64_t>(lset.size());
    out["right_endpoint_count"] = static_cast<std::uint64_t>(rset.size());
    out["added_endpoints"] = std::move(added);
    out["removed_endpoints"] = std::move(removed);
    out["issues_created"] = json::array();
    finish_job(job, out);
    return tool_result_t::ok(out);
}

tool_result_t get_status(const json& params)
{
    return tool_result_t::ok(status_payload(params.value("job_id", 0ull)));
}

tool_result_t get_results(const json& params)
{
    const std::uint64_t job_id = params.value("job_id", 0ull);
    if (job_id == 0)
        return tool_result_t::error("job_id required");
    api_job_t job;
    if (!get_job(job_id, job))
        return tool_result_t::error("job not found");
    json out = job.result;
    out["job"] = job_status_json(job);
    return tool_result_t::ok(out);
}

}
}
}
}
