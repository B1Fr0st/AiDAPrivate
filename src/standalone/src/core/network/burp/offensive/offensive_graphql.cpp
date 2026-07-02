#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "offensive_graphql.hpp"

#include "../audit_http.hpp"
#include "../graphql.hpp"
#include "../issue.hpp"
#include "../scope.hpp"
#include "../../js_analysis_tools_standalone.hpp"
#include "../../../settings/standalone_compat.hpp"
#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace offensive {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

struct gql_job_t
{
    std::uint64_t id = 0;
    std::string action;
    std::string endpoint;
    std::uint64_t started_ms = 0;
    std::uint64_t finished_ms = 0;
    bool running = false;
    bool cancelled = false;
    std::size_t requests_sent = 0;
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

std::unordered_map<std::uint64_t, gql_job_t>& jobs()
{
    static std::unordered_map<std::uint64_t, gql_job_t> j;
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

bool contains_ci(const std::string& text, const std::string& needle)
{
    if (needle.empty() || text.size() < needle.size())
        return false;
    return lower_copy(text).find(lower_copy(needle)) != std::string::npos;
}

std::string host_header_value(const std::string& host, std::uint16_t port, bool tls)
{
    if ((tls && port == 443) || (!tls && port == 80))
        return host;
    return host + ":" + std::to_string(static_cast<unsigned>(port));
}

std::string truncate_text(std::string text, std::size_t limit)
{
    if (text.size() <= limit)
        return text;
    text.resize(limit);
    text += "...";
    return text;
}

std::map<std::string, std::string> headers_to_map(const json& src)
{
    std::map<std::string, std::string> out;
    if (!src.is_object())
        return out;
    for (auto it = src.begin(); it != src.end(); ++it) {
        if (!it.value().is_string())
            continue;
        const std::string key = it.key();
        const std::string value = it.value().get<std::string>();
        if (key.find('\r') != std::string::npos || key.find('\n') != std::string::npos)
            continue;
        if (value.find('\r') != std::string::npos || value.find('\n') != std::string::npos)
            continue;
        const std::string lk = lower_copy(key);
        if (lk == "host" || lk == "content-length" || lk == "connection")
            continue;
        out[key] = value;
    }
    return out;
}

std::vector<std::string> string_array(const json& value, std::size_t max_count)
{
    std::vector<std::string> out;
    if (!value.is_array())
        return out;
    for (const auto& item : value) {
        if (out.size() >= max_count)
            break;
        if (item.is_string()) {
            std::string s = item.get<std::string>();
            if (!s.empty())
                out.push_back(std::move(s));
        }
    }
    return out;
}

json job_status_json(const gql_job_t& j)
{
    json out;
    out["job_id"] = j.id;
    out["action"] = j.action;
    out["endpoint"] = aida::network::js_analysis_tools::redact_url_for_output(j.endpoint);
    out["started_ms"] = j.started_ms;
    out["finished_ms"] = j.finished_ms;
    out["running"] = j.running;
    out["cancelled"] = j.cancelled;
    out["requests_sent"] = static_cast<std::uint64_t>(j.requests_sent);
    out["issues_created"] = static_cast<std::uint64_t>(j.issues_created);
    return out;
}

gql_job_t begin_job(const std::string& action, const std::string& endpoint)
{
    gql_job_t job;
    job.id = next_job_id().fetch_add(1);
    job.action = action;
    job.endpoint = endpoint;
    job.started_ms = wall_ms();
    job.running = true;
    {
        std::lock_guard<std::mutex> lk(jobs_mtx());
        jobs()[job.id] = job;
    }
    return job;
}

void finish_job(gql_job_t& job, json result, bool cancelled)
{
    job.finished_ms = wall_ms();
    job.running = false;
    job.cancelled = cancelled;
    job.result = std::move(result);
    {
        std::lock_guard<std::mutex> lk(jobs_mtx());
        jobs()[job.id] = job;
    }
}

bool get_job(std::uint64_t id, gql_job_t& out)
{
    std::lock_guard<std::mutex> lk(jobs_mtx());
    auto it = jobs().find(id);
    if (it == jobs().end())
        return false;
    out = it->second;
    return true;
}

bool enforce_scope_for_endpoint(const std::string& endpoint, bool enforce_scope, std::string& error)
{
    if (!enforce_scope)
        return true;
    if (!scope::in_scope(endpoint)) {
        error = "target out of scope";
        return false;
    }
    return true;
}

bool send_graphql_json(const std::string& endpoint,
                       const std::map<std::string, std::string>& headers,
                       const std::string& query,
                       const json& variables,
                       int timeout_ms,
                       bool enforce_scope,
                       json& response_json,
                       std::string& raw_text,
                       json& summary,
                       std::string& error)
{
    std::string scope_error;
    if (!enforce_scope_for_endpoint(endpoint, enforce_scope, scope_error)) {
        error = scope_error;
        return false;
    }

    std::string scheme;
    std::string host;
    std::string path;
    std::uint16_t port = 0;
    if (!audit_http::parse_url(endpoint, scheme, host, port, path)) {
        error = "endpoint parse failed";
        return false;
    }
    const bool tls = scheme == "https";
    json body;
    body["query"] = query;
    if (!variables.is_null())
        body["variables"] = variables;
    const std::string body_text = body.dump();
    std::ostringstream req;
    req << "POST " << (path.empty() ? "/" : path) << " HTTP/1.1\r\n";
    req << "Host: " << host_header_value(host, port, tls) << "\r\n";
    bool has_content_type = false;
    bool has_accept = false;
    for (const auto& h : headers) {
        const std::string lk = lower_copy(h.first);
        if (lk == "host" || lk == "content-length" || lk == "connection")
            continue;
        if (lk == "content-type")
            has_content_type = true;
        if (lk == "accept")
            has_accept = true;
        req << h.first << ": " << h.second << "\r\n";
    }
    if (!has_content_type)
        req << "Content-Type: application/json\r\n";
    if (!has_accept)
        req << "Accept: application/json\r\n";
    req << "User-Agent: AiDA-GraphQL-Offensive/1.0\r\n";
    req << "Content-Length: " << body_text.size() << "\r\n";
    req << "Connection: close\r\n\r\n";
    req << body_text;
    const std::string raw_request = req.str();
    std::vector<std::uint8_t> bytes(raw_request.begin(), raw_request.end());

    audit_http::send_options_t opts;
    opts.timeout_ms = timeout_ms;
    opts.follow_redirects = false;
    opts.max_redirects = 0;
    opts.enforce_scope = enforce_scope;
    opts.exchange_source = "offensive_graphql";
    auto resp = audit_http::send(bytes, host, port, tls, opts);
    if (!resp.has_value()) {
        error = audit_http::last_error();
        return false;
    }

    raw_text.assign(reinterpret_cast<const char*>(resp->resp_body.data()), resp->resp_body.size());
    summary["status"] = resp->status_code;
    summary["latency_ms"] = resp->latency_ms;
    summary["body_length"] = static_cast<std::uint64_t>(resp->resp_body.size());
    summary["body_sha256"] = aida::network::js_analysis_tools::sha256_hex(raw_text);
    summary["query_length"] = static_cast<std::uint64_t>(query.size());

    if (resp->status_code < 200 || resp->status_code >= 500) {
        error = "HTTP " + std::to_string(resp->status_code);
        response_json = json::object();
        return false;
    }

    response_json = json::parse(raw_text, nullptr, false);
    if (response_json.is_discarded()) {
        error = "response is not JSON";
        return false;
    }
    return true;
}

const graphql::gql_type_t* find_type(const graphql::gql_schema_t& schema, const std::string& name)
{
    for (const auto& t : schema.types) {
        if (t.name == name)
            return &t;
    }
    return nullptr;
}

std::string strip_modifiers(std::string s)
{
    for (;;) {
        bool changed = false;
        if (!s.empty() && s.front() == '[') {
            s.erase(s.begin());
            changed = true;
        }
        if (!s.empty() && s.back() == ']') {
            s.pop_back();
            changed = true;
        }
        if (!s.empty() && s.back() == '!') {
            s.pop_back();
            changed = true;
        }
        if (!changed)
            break;
    }
    return s;
}

bool scalar_like(const graphql::gql_schema_t& schema, const std::string& type_name)
{
    if (type_name == "String" || type_name == "ID" || type_name == "Int" || type_name == "Float" || type_name == "Boolean")
        return true;
    const auto* t = find_type(schema, type_name);
    return !t || t->kind == "SCALAR" || t->kind == "ENUM";
}

std::string default_value_for_type(const std::string& type_name)
{
    const std::string base = strip_modifiers(type_name);
    if (base == "Int")
        return "0";
    if (base == "Float")
        return "0.0";
    if (base == "Boolean")
        return "false";
    if (base == "String" || base == "ID")
        return "$aidaValue";
    return "null";
}

std::string selection_for_type(const graphql::gql_schema_t& schema, const std::string& type_name, int depth)
{
    const std::string base = strip_modifiers(type_name);
    if (depth <= 0 || scalar_like(schema, base))
        return {};
    const auto* t = find_type(schema, base);
    if (!t)
        return {};
    std::string out = "{ __typename";
    std::size_t added = 0;
    for (const auto& f : t->fields) {
        if (added >= 4)
            break;
        const std::string field_base = strip_modifiers(f.type_str);
        if (scalar_like(schema, field_base)) {
            out += " ";
            out += f.name;
            ++added;
        } else {
            std::string nested = selection_for_type(schema, field_base, depth - 1);
            if (!nested.empty()) {
                out += " ";
                out += f.name;
                out += " ";
                out += nested;
                ++added;
            }
        }
    }
    out += " }";
    return out;
}

const graphql::gql_field_t* first_field_with_args(const graphql::gql_schema_t& schema,
                                                  const std::string& root_type,
                                                  const std::string& preferred)
{
    const auto* root = find_type(schema, root_type);
    if (!root)
        return nullptr;
    if (!preferred.empty()) {
        for (const auto& f : root->fields) {
            if (f.name == preferred)
                return &f;
        }
    }
    for (const auto& f : root->fields) {
        if (!f.args.empty())
            return &f;
    }
    return root->fields.empty() ? nullptr : &root->fields.front();
}

std::string build_field_query(const graphql::gql_schema_t& schema,
                              const std::string& root_type,
                              const std::string& operation_kind,
                              const graphql::gql_field_t& field,
                              int depth)
{
    std::ostringstream q;
    bool has_variable_arg = false;
    q << operation_kind << " AiDAProbe";
    for (const auto& arg : field.args) {
        const std::string base = strip_modifiers(arg.second);
        if (base == "String" || base == "ID") {
            has_variable_arg = true;
            break;
        }
    }
    if (has_variable_arg)
        q << "($aidaValue: String)";
    q << " { " << field.name;
    if (!field.args.empty()) {
        q << "(";
        bool first = true;
        for (const auto& arg : field.args) {
            if (!first)
                q << ", ";
            first = false;
            q << arg.first << ": " << default_value_for_type(arg.second);
        }
        q << ")";
    }
    std::string selection = selection_for_type(schema, field.type_str, depth);
    if (!selection.empty())
        q << " " << selection;
    q << " }";
    (void)root_type;
    return q.str();
}

bool ensure_schema(const std::string& endpoint,
                   const std::map<std::string, std::string>& headers,
                   bool refresh,
                   bool enforce_scope,
                   graphql::gql_schema_t& out,
                   std::string& error)
{
    if (!refresh && graphql::get_cached_schema(endpoint, out))
        return true;
    std::string scope_error;
    if (!enforce_scope_for_endpoint(endpoint, enforce_scope, scope_error)) {
        error = scope_error;
        return false;
    }
    std::string raw;
    if (!graphql::introspect(endpoint, headers, out, raw)) {
        error = graphql::last_error();
        return false;
    }
    return true;
}

bool response_has_graphql_errors(const json& response)
{
    return response.is_object() && response.contains("errors") && response["errors"].is_array() && !response["errors"].empty();
}

std::string graphql_error_text(const json& response)
{
    std::ostringstream oss;
    if (!response.is_object() || !response.contains("errors") || !response["errors"].is_array())
        return {};
    std::size_t count = 0;
    for (const auto& err : response["errors"]) {
        if (count >= 5)
            break;
        if (err.is_object() && err.contains("message") && err["message"].is_string()) {
            if (count)
                oss << " | ";
            oss << err["message"].get<std::string>();
            ++count;
        }
    }
    return aida::network::js_analysis_tools::redact_sensitive_values(truncate_text(oss.str(), 1000));
}

std::string classify_injection_signal(const std::string& text)
{
    if (contains_ci(text, "sql syntax") || contains_ci(text, "mysql") || contains_ci(text, "postgres") ||
        contains_ci(text, "sqlite") || contains_ci(text, "ora-") || contains_ci(text, "odbc") ||
        contains_ci(text, "unterminated quoted string"))
        return "sqli";
    if (contains_ci(text, "<script") || contains_ci(text, "onerror=") || contains_ci(text, "svg/onload"))
        return "xss_reflection";
    if (contains_ci(text, "command not found") || contains_ci(text, "sh:") || contains_ci(text, "cmd.exe") ||
        contains_ci(text, "powershell"))
        return "cmdi";
    return {};
}

std::uint64_t add_issue(const std::string& type_key,
                        const std::string& name,
                        severity_t severity,
                        confidence_t confidence,
                        const std::string& endpoint,
                        const std::string& parameter,
                        const std::string& evidence_summary,
                        const json& response_summary)
{
    issue_store::initialize();
    std::string scheme;
    std::string host;
    std::string path;
    std::uint16_t port = 0;
    audit_http::parse_url(endpoint, scheme, host, port, path);
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
    issue.insertion_point = parameter.empty() ? "graphql" : "graphql:" + parameter;
    issue.description = evidence_summary;
    issue.remediation = "Restrict GraphQL schema exposure, enforce authorization per field and operation, and apply server-side input validation before resolver calls.";
    issue.seen_ms = wall_ms();
    evidence_t evidence;
    evidence.request_raw = "endpoint=" + aida::network::js_analysis_tools::redact_url_for_output(endpoint) + " parameter=" + parameter;
    evidence.response_raw = response_summary.dump();
    evidence.marker = evidence_summary;
    issue.evidence.push_back(std::move(evidence));
    return issue_store::add(std::move(issue));
}

json get_status_payload(std::uint64_t job_id)
{
    json out;
    if (job_id != 0) {
        gql_job_t job;
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

tool_result_t tool_status(const json& params)
{
    return tool_result_t::ok(get_status_payload(params.value("job_id", 0ull)));
}

tool_result_t tool_results(const json& params)
{
    const std::uint64_t job_id = params.value("job_id", 0ull);
    if (job_id == 0)
        return tool_result_t::error("job_id required");
    gql_job_t job;
    if (!get_job(job_id, job))
        return tool_result_t::error("job not found");
    json out = job.result;
    out["job"] = job_status_json(job);
    return tool_result_t::ok(out);
}

tool_result_t tool_introspection_abuse(const json& params)
{
    const std::string endpoint = params.value("endpoint", std::string());
    if (endpoint.empty())
        return tool_result_t::error("endpoint required");
    const bool enforce_scope = params.value("enforce_scope", true);
    auto headers = headers_to_map(params.value("headers", json::object()));
    gql_job_t job = begin_job("introspection_abuse", endpoint);
    json out;
    out["job_id"] = job.id;
    out["endpoint"] = aida::network::js_analysis_tools::redact_url_for_output(endpoint);
    graphql::gql_schema_t schema;
    std::string error;
    const bool ok = ensure_schema(endpoint, headers, true, enforce_scope, schema, error);
    out["introspection_enabled"] = ok;
    out["issues_created"] = json::array();
    if (ok) {
        out["schema"] = graphql::schema_to_json(schema);
        std::uint64_t issue_id = add_issue("graphql.introspection.enabled",
                                           "GraphQL introspection is enabled",
                                           severity_t::low,
                                           confidence_t::firm,
                                           endpoint,
                                           "__schema",
                                           "The GraphQL endpoint returned schema metadata through introspection.",
                                           json{{"types", static_cast<std::uint64_t>(schema.types.size())}});
        out["issues_created"].push_back(issue_id);
        job.issues_created = 1;
    } else {
        out["error"] = error;
    }
    job.requests_sent = 1;
    finish_job(job, out, call_cancelled());
    return ok ? tool_result_t::ok(out) : tool_result_t::ok("introspection not available", out);
}

tool_result_t tool_inject(const json& params)
{
    const std::string endpoint = params.value("endpoint", std::string());
    if (endpoint.empty())
        return tool_result_t::error("endpoint required");
    const bool enforce_scope = params.value("enforce_scope", true);
    auto headers = headers_to_map(params.value("headers", json::object()));
    const int timeout_ms = bounded_timeout_ms(params, 15000, 60000);
    gql_job_t job = begin_job("inject", endpoint);
    std::vector<std::string> payloads = string_array(params.value("injection_payloads", json::array()), 8);
    if (params.contains("injection_payload") && params["injection_payload"].is_string())
        payloads.insert(payloads.begin(), params["injection_payload"].get<std::string>());
    if (payloads.empty()) {
        payloads = {"' OR '1'='1", "\"><svg/onload=alert(1)>", ";id", "{{7*7}}", "../../etc/passwd"};
    }
    if (payloads.size() > 8)
        payloads.resize(8);

    std::string query = params.value("query", std::string());
    json variables = params.value("variables", json::object());
    const std::string injection_param = params.value("injection_param", params.value("parameter", std::string("aidaValue")));
    if (query.empty()) {
        graphql::gql_schema_t schema;
        std::string error;
        if (ensure_schema(endpoint, headers, false, enforce_scope, schema, error)) {
            const std::string root_name = schema.query_type.empty() ? std::string("Query") : schema.query_type;
            const auto* field = first_field_with_args(schema, root_name, params.value("field_name", std::string()));
            if (field)
                query = build_field_query(schema, root_name, "query", *field, 2);
        }
    }
    if (query.empty()) {
        finish_job(job, json{{"job_id", job.id}, {"error", "query required when no schema-backed field is available"}}, false);
        return tool_result_t::error("query required when no schema-backed field is available");
    }

    json probes = json::array();
    json issues = json::array();
    bool vulnerable = false;
    std::string detected_type;
    for (const std::string& payload : payloads) {
        if (call_cancelled()) {
            job.cancelled = true;
            break;
        }
        json vars = variables.is_object() ? variables : json::object();
        if (!injection_param.empty())
            vars[injection_param] = payload;
        if (vars.empty())
            vars["aidaValue"] = payload;
        json response;
        json summary;
        std::string raw;
        std::string error;
        const bool ok = send_graphql_json(endpoint, headers, query, vars, timeout_ms, enforce_scope, response, raw, summary, error);
        ++job.requests_sent;
        const std::string error_text = ok ? graphql_error_text(response) : error;
        const std::string combined = error_text + " " + aida::network::js_analysis_tools::redact_sensitive_values(truncate_text(raw, 2048));
        const std::string signal = classify_injection_signal(combined);
        json row;
        row["ok"] = ok;
        row["payload_sha256"] = aida::network::js_analysis_tools::sha256_hex(payload);
        row["payload_length"] = static_cast<std::uint64_t>(payload.size());
        row["parameter"] = injection_param;
        row["summary"] = summary;
        row["graphql_errors"] = response_has_graphql_errors(response);
        row["error_text"] = aida::network::js_analysis_tools::redact_sensitive_values(truncate_text(error_text, 500));
        row["signal"] = signal;
        probes.push_back(std::move(row));
        if (!signal.empty()) {
            vulnerable = true;
            detected_type = signal;
            std::uint64_t issue_id = add_issue("graphql.injection." + signal,
                                               "GraphQL resolver injection signal",
                                               signal == "sqli" || signal == "cmdi" ? severity_t::high : severity_t::medium,
                                               confidence_t::firm,
                                               endpoint,
                                               injection_param,
                                               "GraphQL response contained resolver-side injection evidence for " + signal + ".",
                                               summary);
            issues.push_back(issue_id);
            ++job.issues_created;
            break;
        }
    }
    json out;
    out["job_id"] = job.id;
    out["endpoint"] = aida::network::js_analysis_tools::redact_url_for_output(endpoint);
    out["vulnerable"] = vulnerable;
    out["injection_type"] = detected_type;
    out["parameter"] = injection_param;
    out["probes"] = std::move(probes);
    out["issues_created"] = std::move(issues);
    finish_job(job, out, job.cancelled);
    return tool_result_t::ok(vulnerable ? "GraphQL injection evidence observed" : "No GraphQL injection evidence observed", out);
}

tool_result_t tool_batch_abuse(const json& params)
{
    const std::string endpoint = params.value("endpoint", std::string());
    if (endpoint.empty())
        return tool_result_t::error("endpoint required");
    const bool enforce_scope = params.value("enforce_scope", true);
    auto headers = headers_to_map(params.value("headers", json::object()));
    int batch_count = params.value("batch_count", 50);
    batch_count = std::max(1, std::min(batch_count, 100));
    std::string operation = params.value("operation", params.value("query", std::string("query { __typename }")));
    const std::string query = graphql::build_batched_query(operation, static_cast<std::size_t>(batch_count));
    gql_job_t job = begin_job("batch_abuse", endpoint);
    json response;
    json summary;
    std::string raw;
    std::string error;
    const bool ok = send_graphql_json(endpoint, headers, query, params.value("variables", json::object()),
                                      bounded_timeout_ms(params, 30000, 120000), enforce_scope, response, raw, summary, error);
    job.requests_sent = 1;
    const bool graphql_errors = ok && response_has_graphql_errors(response);
    const bool accepted = ok && !graphql_errors;
    json issues = json::array();
    if (accepted && batch_count >= 20) {
        std::uint64_t issue_id = add_issue("graphql.batch.accepted",
                                           "GraphQL batching accepted high operation count",
                                           severity_t::medium,
                                           confidence_t::tentative,
                                           endpoint,
                                           "batch",
                                           "The endpoint accepted a high-count aliased GraphQL batch without GraphQL errors.",
                                           summary);
        issues.push_back(issue_id);
        job.issues_created = 1;
    }
    json out;
    out["job_id"] = job.id;
    out["endpoint"] = aida::network::js_analysis_tools::redact_url_for_output(endpoint);
    out["batch_count"] = batch_count;
    out["accepted"] = accepted;
    out["graphql_errors"] = graphql_errors;
    out["error_text"] = aida::network::js_analysis_tools::redact_sensitive_values(truncate_text(ok ? graphql_error_text(response) : error, 600));
    out["summary"] = summary;
    out["issues_created"] = std::move(issues);
    finish_job(job, out, call_cancelled());
    return ok ? tool_result_t::ok(out) : tool_result_t::error(error.empty() ? "GraphQL batch request failed" : error, out);
}

tool_result_t tool_mutation_fuzz(const json& params)
{
    const std::string endpoint = params.value("endpoint", std::string());
    if (endpoint.empty())
        return tool_result_t::error("endpoint required");
    const bool enforce_scope = params.value("enforce_scope", true);
    auto headers = headers_to_map(params.value("headers", json::object()));
    gql_job_t job = begin_job("mutation_fuzz", endpoint);
    graphql::gql_schema_t schema;
    std::string schema_error;
    if (!ensure_schema(endpoint, headers, false, enforce_scope, schema, schema_error)) {
        json out{{"job_id", job.id}, {"error", schema_error}, {"endpoint", aida::network::js_analysis_tools::redact_url_for_output(endpoint)}};
        finish_job(job, out, call_cancelled());
        return tool_result_t::error("schema unavailable for mutation fuzzing", out);
    }
    const std::string mutation_root = schema.mutation_type.empty() ? std::string("Mutation") : schema.mutation_type;
    const auto* root = find_type(schema, mutation_root);
    if (!root || root->fields.empty()) {
        json out{{"job_id", job.id}, {"mutation_root", mutation_root}, {"mutations_found", 0}};
        finish_job(job, out, false);
        return tool_result_t::ok("no mutations available", out);
    }
    std::vector<std::string> wanted = string_array(params.value("mutation_names", json::array()), 32);
    const int max_mutations = std::max(1, std::min(params.value("max_mutations", 5), 20));
    const std::string marker = params.value("marker", std::string("aida_mutation_probe"));
    json rows = json::array();
    json issues = json::array();
    int sent = 0;
    for (const auto& field : root->fields) {
        if (sent >= max_mutations || call_cancelled())
            break;
        if (!wanted.empty() && std::find(wanted.begin(), wanted.end(), field.name) == wanted.end())
            continue;
        std::string query = build_field_query(schema, mutation_root, "mutation", field, 2);
        json vars = json::object({{"aidaValue", marker}});
        json response;
        json summary;
        std::string raw;
        std::string error;
        const bool ok = send_graphql_json(endpoint, headers, query, vars, bounded_timeout_ms(params, 60000, 120000),
                                          enforce_scope, response, raw, summary, error);
        ++sent;
        ++job.requests_sent;
        const bool graphql_errors = ok && response_has_graphql_errors(response);
        json row;
        row["mutation"] = field.name;
        row["ok"] = ok;
        row["graphql_errors"] = graphql_errors;
        row["error_text"] = aida::network::js_analysis_tools::redact_sensitive_values(truncate_text(ok ? graphql_error_text(response) : error, 600));
        row["summary"] = summary;
        if (ok && !graphql_errors) {
            std::uint64_t issue_id = add_issue("graphql.mutation.accepted",
                                               "GraphQL mutation accepted fuzzed input",
                                               severity_t::medium,
                                               confidence_t::tentative,
                                               endpoint,
                                               field.name,
                                               "A mutation accepted generated fuzz input without GraphQL errors. Review authorization and side effects.",
                                               summary);
            issues.push_back(issue_id);
            ++job.issues_created;
        }
        rows.push_back(std::move(row));
    }
    json out;
    out["job_id"] = job.id;
    out["mutation_root"] = mutation_root;
    out["mutations_tested"] = sent;
    out["results"] = std::move(rows);
    out["issues_created"] = std::move(issues);
    finish_job(job, out, call_cancelled());
    return tool_result_t::ok(out);
}

std::string build_depth_query(const graphql::gql_schema_t& schema, int requested_depth)
{
    requested_depth = std::max(2, std::min(requested_depth, 24));
    const std::string root_name = schema.query_type.empty() ? std::string("Query") : schema.query_type;
    const auto* root = find_type(schema, root_name);
    if (!root || root->fields.empty())
        return "query AiDADepth { __typename }";
    const graphql::gql_field_t* current = nullptr;
    for (const auto& f : root->fields) {
        if (!scalar_like(schema, strip_modifiers(f.type_str))) {
            current = &f;
            break;
        }
    }
    if (!current)
        return graphql::build_batched_query("query { __typename }", static_cast<std::size_t>(requested_depth));
    std::ostringstream q;
    q << "query AiDADepth { " << current->name;
    std::string type_name = strip_modifiers(current->type_str);
    int open_blocks = 1;
    for (int depth = 1; depth < requested_depth; ++depth) {
        const auto* t = find_type(schema, type_name);
        if (!t)
            break;
        const graphql::gql_field_t* next = nullptr;
        for (const auto& f : t->fields) {
            if (!scalar_like(schema, strip_modifiers(f.type_str))) {
                next = &f;
                break;
            }
        }
        if (!next)
            break;
        q << " { " << next->name;
        ++open_blocks;
        type_name = strip_modifiers(next->type_str);
    }
    q << " { __typename }";
    for (int depth = 0; depth < open_blocks; ++depth)
        q << " }";
    return q.str();
}

tool_result_t tool_depth_or_cost(const json& params, const char* action)
{
    const std::string endpoint = params.value("endpoint", std::string());
    if (endpoint.empty())
        return tool_result_t::error("endpoint required");
    const bool enforce_scope = params.value("enforce_scope", true);
    auto headers = headers_to_map(params.value("headers", json::object()));
    gql_job_t job = begin_job(action, endpoint);
    graphql::gql_schema_t schema;
    std::string schema_error;
    if (!ensure_schema(endpoint, headers, false, enforce_scope, schema, schema_error)) {
        json out{{"job_id", job.id}, {"error", schema_error}};
        finish_job(job, out, call_cancelled());
        return tool_result_t::error("schema unavailable", out);
    }
    std::string query;
    int probe_size = 0;
    if (std::string(action) == "depth_limit_test") {
        probe_size = std::max(2, std::min(params.value("depth", 12), 24));
        query = build_depth_query(schema, probe_size);
    } else {
        probe_size = std::max(10, std::min(params.value("field_count", params.value("cost", 120)), 300));
        query = graphql::build_batched_query(params.value("operation", std::string("query { __typename }")), static_cast<std::size_t>(probe_size));
    }
    json response;
    json summary;
    std::string raw;
    std::string error;
    const bool ok = send_graphql_json(endpoint, headers, query, json::object(), bounded_timeout_ms(params, 30000, 120000),
                                      enforce_scope, response, raw, summary, error);
    job.requests_sent = 1;
    const bool limited = !ok || response_has_graphql_errors(response);
    const std::string err_text = ok ? graphql_error_text(response) : error;
    json issues = json::array();
    const bool depth_action = std::string(action) == "depth_limit_test";
    if (ok && !limited && ((!depth_action && probe_size >= 50) || (depth_action && probe_size >= 8))) {
        std::uint64_t issue_id = add_issue(std::string("graphql.") + (std::string(action) == "depth_limit_test" ? "depth" : "cost") + ".unbounded",
                                           std::string("GraphQL ") + (std::string(action) == "depth_limit_test" ? "depth" : "cost") + " limit not observed",
                                           severity_t::medium,
                                           confidence_t::tentative,
                                           endpoint,
                                           action,
                                           "A high-depth or high-cost GraphQL request was accepted without GraphQL errors.",
                                           summary);
        issues.push_back(issue_id);
        job.issues_created = 1;
    }
    json out;
    out["job_id"] = job.id;
    out["action"] = action;
    out["probe_size"] = probe_size;
    out["limited"] = limited;
    out["accepted"] = ok && !limited;
    out["error_text"] = aida::network::js_analysis_tools::redact_sensitive_values(truncate_text(err_text, 600));
    out["summary"] = summary;
    out["issues_created"] = std::move(issues);
    finish_job(job, out, call_cancelled());
    return tool_result_t::ok(out);
}

}

void register_api_graphql_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "aida_offensive_api_graphql_manage", "offensive_api",
        "Manage GraphQL offensive security checks. Actions: inject, batch_abuse, introspection_abuse, mutation_fuzz, depth_limit_test, cost_limit_test, get_status, get_results.",
        {{"action", "string", "inject|batch_abuse|introspection_abuse|mutation_fuzz|depth_limit_test|cost_limit_test|get_status|get_results", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "inject") return tool_inject(p);
            if (action == "batch_abuse" || action == "batch_attack") return tool_batch_abuse(p);
            if (action == "introspection_abuse" || action == "get_schema") return tool_introspection_abuse(p);
            if (action == "mutation_fuzz") return tool_mutation_fuzz(p);
            if (action == "depth_limit_test") return tool_depth_or_cost(p, "depth_limit_test");
            if (action == "cost_limit_test") return tool_depth_or_cost(p, "cost_limit_test");
            if (action == "get_status" || action == "status") return tool_status(p);
            if (action == "get_results" || action == "results") return tool_results(p);
            return compat_unknown_action("aida_offensive_api_graphql_manage", action);
        },
        false
    });
    diag::log_tagged("off_graphql", "registered aida_offensive_api_graphql_manage");
}

}
}
}
