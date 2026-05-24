#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifdef small
#undef small
#endif

#include "graphql.hpp"
#include "audit_http.hpp"

#include "../../../helpers/diag_log.hpp"

#include <httplib.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <mutex>
#include <sstream>
#include <unordered_map>

namespace aida {
namespace burp {
namespace graphql {

namespace {

std::mutex& err_mtx()  { static std::mutex m; return m; }
std::string& err_slot() { static std::string s; return s; }

void set_err(const std::string& m)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = m;
}

struct cache_t
{
    std::mutex                                   mtx;
    std::unordered_map<std::string, gql_schema_t> by_endpoint;
};

cache_t& cache()
{
    static cache_t c;
    return c;
}

std::string to_lower(std::string s)
{
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

struct url_log_t
{
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    bool has_query = false;
    size_t length = 0;
};

url_log_t summarize_url_for_log(const std::string& url)
{
    url_log_t out;
    out.length = url.size();
    std::string scheme, host, path;
    uint16_t port = 0;
    if (audit_http::parse_url(url, scheme, host, port, path))
    {
        out.scheme = scheme;
        out.host = host;
        out.port = port;
        size_t q = path.find('?');
        size_t f = path.find('#');
        out.has_query = q != std::string::npos;
        size_t path_end = path.size();
        if (q != std::string::npos) path_end = q;
        if (f != std::string::npos && f < path_end) path_end = f;
        out.path = path.substr(0, path_end);
        if (out.path.empty()) out.path = "/";
    }
    else
    {
        size_t cursor = 0;
        size_t scheme_pos = url.find("://");
        if (scheme_pos != std::string::npos)
        {
            out.scheme = url.substr(0, scheme_pos);
            cursor = scheme_pos + 3;
        }
        size_t host_end = url.find_first_of("/?#", cursor);
        if (host_end == std::string::npos) host_end = url.size();
        if (host_end > cursor) out.host = url.substr(cursor, host_end - cursor);
        size_t path_start = url.find('/', cursor);
        size_t q = url.find('?', cursor);
        size_t f = url.find('#', cursor);
        out.has_query = q != std::string::npos;
        size_t path_end = url.size();
        if (q != std::string::npos) path_end = q;
        if (f != std::string::npos && f < path_end) path_end = f;
        if (path_start != std::string::npos && path_start < path_end) out.path = url.substr(path_start, path_end - path_start);
    }
    if (out.host.empty()) out.host = "<missing>";
    if (out.path.empty()) out.path = "/";
    if (out.path.size() > 240)
    {
        out.path.resize(240);
        out.path += "...";
    }
    return out;
}

std::string introspection_query()
{
    return std::string(
        "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } "
        "types { ...FullType } } } "
        "fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description "
        "args { ...InputValue } type { ...TypeRef } } inputFields { ...InputValue } interfaces { ...TypeRef } "
        "enumValues(includeDeprecated: true) { name } possibleTypes { ...TypeRef } } "
        "fragment InputValue on __InputValue { name type { ...TypeRef } } "
        "fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { "
        "kind name ofType { kind name ofType { kind name } } } } } } }");
}

std::string typeref_to_str(const nlohmann::json& tr)
{
    if (!tr.is_object()) return std::string();
    std::string kind = tr.value("kind", std::string());
    std::string name = tr.value("name", std::string());
    if (kind == "NON_NULL" && tr.contains("ofType")) return typeref_to_str(tr["ofType"]) + "!";
    if (kind == "LIST"     && tr.contains("ofType")) return std::string("[") + typeref_to_str(tr["ofType"]) + "]";
    return name;
}

}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    std::string e = err_slot();
    diag::log_tagged_fmt("graphql", "last_error queried val=%s", e.c_str());
    return e;
}

bool introspect(const std::string& endpoint,
                const std::map<std::string, std::string>& headers,
                gql_schema_t& out,
                std::string& raw_response)
{
    const url_log_t endpoint_log = summarize_url_for_log(endpoint);
    diag::log_tagged_fmt("graphql", "introspect entry scheme=%s host=%s port=%u path=%s query=%d endpoint_len=%zu headers=%zu",
        endpoint_log.scheme.c_str(), endpoint_log.host.c_str(), static_cast<unsigned>(endpoint_log.port),
        endpoint_log.path.c_str(), (int)endpoint_log.has_query, endpoint_log.length, headers.size());
    nlohmann::json body;
    body["query"] = introspection_query();
    body["operationName"] = "IntrospectionQuery";
    nlohmann::json variables = nlohmann::json::object();

    nlohmann::json resp_json;
    diag::log_tagged_fmt("graphql", "introspect sending_introspection_query");
    if (!send_query(endpoint, headers, introspection_query(), variables, resp_json, raw_response)) {
        diag::log_tagged_fmt("graphql", "introspect send_query_failed host=%s path=%s",
            endpoint_log.host.c_str(), endpoint_log.path.c_str());
        return false;
    }
    diag::log_tagged_fmt("graphql", "introspect response_received raw_len=%zu", raw_response.size());

    if (!resp_json.is_object() || !resp_json.contains("data") || !resp_json["data"].is_object()) {
        diag::log_tagged_fmt("graphql", "introspect no_data_field host=%s path=%s response_type=%s",
            endpoint_log.host.c_str(), endpoint_log.path.c_str(), resp_json.type_name());
        set_err("graphql.introspect: no data field");
        return false;
    }
    const auto& data = resp_json["data"];
    if (!data.contains("__schema") || !data["__schema"].is_object()) {
        diag::log_tagged_fmt("graphql", "introspect no_schema_field host=%s path=%s data_keys=%zu",
            endpoint_log.host.c_str(), endpoint_log.path.c_str(), data.size());
        set_err("graphql.introspect: no __schema");
        return false;
    }
    const auto& schema = data["__schema"];
    diag::log_tagged_fmt("graphql", "introspect parsing_schema");

    gql_schema_t parsed;
    if (schema.contains("queryType") && schema["queryType"].is_object())
        parsed.query_type = schema["queryType"].value("name", std::string());
    if (schema.contains("mutationType") && schema["mutationType"].is_object())
        parsed.mutation_type = schema["mutationType"].value("name", std::string());
    if (schema.contains("subscriptionType") && schema["subscriptionType"].is_object())
        parsed.subscription_type = schema["subscriptionType"].value("name", std::string());

    diag::log_tagged_fmt("graphql", "introspect schema query_type=%s mutation_type=%s subscription_type=%s",
        parsed.query_type.c_str(), parsed.mutation_type.c_str(), parsed.subscription_type.c_str());

    if (schema.contains("types") && schema["types"].is_array()) {
        for (const auto& t : schema["types"]) {
            if (!t.is_object()) continue;
            gql_type_t gt;
            gt.name = t.value("name", std::string());
            gt.kind = t.value("kind", std::string());
            if (gt.name.rfind("__", 0) == 0) continue;
            if (t.contains("interfaces") && t["interfaces"].is_array()) {
                for (const auto& i : t["interfaces"]) {
                    if (i.is_object()) gt.interfaces.push_back(i.value("name", std::string()));
                }
            }
            if (t.contains("enumValues") && t["enumValues"].is_array()) {
                for (const auto& e : t["enumValues"]) {
                    if (e.is_object()) gt.enum_values.push_back(e.value("name", std::string()));
                }
            }
            if (t.contains("fields") && t["fields"].is_array()) {
                for (const auto& f : t["fields"]) {
                    if (!f.is_object()) continue;
                    gql_field_t gf;
                    gf.name = f.value("name", std::string());
                    if (f.contains("description") && f["description"].is_string())
                        gf.description = f["description"].get<std::string>();
                    if (f.contains("type")) gf.type_str = typeref_to_str(f["type"]);
                    if (f.contains("args") && f["args"].is_array()) {
                        for (const auto& a : f["args"]) {
                            if (!a.is_object()) continue;
                            std::string an = a.value("name", std::string());
                            std::string at;
                            if (a.contains("type")) at = typeref_to_str(a["type"]);
                            gf.args.emplace_back(an, at);
                        }
                    }
                    gt.fields.push_back(std::move(gf));
                }
            }
            if (t.contains("inputFields") && t["inputFields"].is_array()) {
                for (const auto& f : t["inputFields"]) {
                    if (!f.is_object()) continue;
                    gql_field_t gf;
                    gf.name = f.value("name", std::string());
                    if (f.contains("type")) gf.type_str = typeref_to_str(f["type"]);
                    gt.fields.push_back(std::move(gf));
                }
            }
            diag::log_tagged_fmt("graphql", "introspect type name=%s kind=%s fields=%zu",
                gt.name.c_str(), gt.kind.c_str(), gt.fields.size());
            parsed.types.push_back(std::move(gt));
        }
    }

    diag::log_tagged_fmt("graphql", "introspect caching schema types=%zu host=%s path=%s",
        parsed.types.size(), endpoint_log.host.c_str(), endpoint_log.path.c_str());
    cache_schema(endpoint, parsed);
    out = std::move(parsed);
    diag::log_tagged_fmt("graphql", "introspect ok host=%s path=%s types=%zu raw_len=%zu",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), out.types.size(), raw_response.size());
    return true;
}

namespace {

const gql_type_t* find_type(const gql_schema_t& s, const std::string& name)
{
    for (const auto& t : s.types) if (t.name == name) return &t;
    return nullptr;
}

std::string strip_modifiers(std::string s)
{
    while (!s.empty() && (s.front() == '[' || s.back() == ']' || s.back() == '!')) {
        if (!s.empty() && s.front() == '[') s.erase(s.begin());
        if (!s.empty() && s.back() == ']') s.pop_back();
        if (!s.empty() && s.back() == '!') s.pop_back();
    }
    return s;
}

bool is_scalar_or_enum(const gql_schema_t& s, const std::string& base_type)
{
    const auto* t = find_type(s, base_type);
    if (!t) {
        if (base_type == "Int" || base_type == "Float" || base_type == "String"
            || base_type == "Boolean" || base_type == "ID") return true;
        return true;
    }
    return t->kind == "SCALAR" || t->kind == "ENUM";
}

std::string field_selection(const gql_schema_t& s, const std::string& type_name, int depth, int max_depth)
{
    if (depth > max_depth) return std::string();
    const auto* tt = find_type(s, type_name);
    if (!tt) return std::string();
    if (tt->kind == "SCALAR" || tt->kind == "ENUM") return std::string();
    std::string out;
    out += " {";
    bool any = false;
    for (const auto& f : tt->fields) {
        std::string base = strip_modifiers(f.type_str);
        if (is_scalar_or_enum(s, base)) {
            out += " "; out += f.name;
            any = true;
        } else {
            std::string sub = field_selection(s, base, depth + 1, max_depth);
            if (!sub.empty()) {
                out += " "; out += f.name; out += sub;
                any = true;
            }
        }
    }
    if (!any) out += " __typename";
    out += " }";
    return out;
}

}

std::string build_example_query(const gql_schema_t& schema, const std::string& field_name, int depth)
{
    diag::log_tagged_fmt("graphql", "build_example_query entry field=%s depth=%d types=%zu",
        field_name.c_str(), depth, schema.types.size());
    if (depth < 1) depth = 1;
    if (depth > 5) depth = 5;
    std::string query_root_name = schema.query_type.empty() ? std::string("Query") : schema.query_type;
    const gql_type_t* root = find_type(schema, query_root_name);
    if (!root) {
        diag::log_tagged_fmt("graphql", "build_example_query root_type_not_found name=%s", query_root_name.c_str());
        return std::string("query { __typename }");
    }
    const gql_field_t* found = nullptr;
    for (const auto& f : root->fields) if (f.name == field_name) { found = &f; break; }
    if (!found) {
        diag::log_tagged_fmt("graphql", "build_example_query searching all types for field=%s", field_name.c_str());
        for (const auto& t : schema.types) {
            for (const auto& f : t.fields) {
                if (f.name == field_name) { found = &f; break; }
            }
            if (found) break;
        }
    }
    if (!found) {
        diag::log_tagged_fmt("graphql", "build_example_query field_not_found name=%s using_fallback", field_name.c_str());
        return std::string("query { ") + field_name + std::string(" }");
    }
    diag::log_tagged_fmt("graphql", "build_example_query field_found name=%s type=%s args=%zu",
        found->name.c_str(), found->type_str.c_str(), found->args.size());
    std::string out = "query Example {\n  " + field_name;
    if (!found->args.empty()) {
        out += "(";
        bool first = true;
        for (const auto& a : found->args) {
            if (!first) out += ", ";
            first = false;
            std::string base = strip_modifiers(a.second);
            out += a.first; out += ": ";
            if (base == "String" || base == "ID") out += "\"\"";
            else if (base == "Int") out += "0";
            else if (base == "Float") out += "0.0";
            else if (base == "Boolean") out += "false";
            else out += "null";
        }
        out += ")";
    }
    std::string base_ret = strip_modifiers(found->type_str);
    if (!is_scalar_or_enum(schema, base_ret)) {
        out += field_selection(schema, base_ret, 1, depth);
    }
    out += "\n}\n";
    diag::log_tagged_fmt("graphql", "build_example_query done query_len=%zu", out.size());
    return out;
}

std::string build_batched_query(const std::string& operation, size_t batch_count)
{
    diag::log_tagged_fmt("graphql", "build_batched_query entry batch_count=%zu op_len=%zu",
        batch_count, operation.size());
    if (batch_count == 0) batch_count = 1;
    std::string trimmed = operation;
    while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '\n' || trimmed.back() == '\r' || trimmed.back() == '\t')) trimmed.pop_back();
    std::string body;
    size_t open = trimmed.find('{');
    if (open == std::string::npos) {
        body = trimmed;
    } else {
        size_t close = trimmed.rfind('}');
        if (close == std::string::npos || close <= open) body = trimmed;
        else body = trimmed.substr(open + 1, close - open - 1);
    }
    std::string out = "query Batched {\n";
    for (size_t i = 0; i < batch_count; ++i) {
        out += "  a" + std::to_string(i) + ": ";
        out += body;
        out += "\n";
    }
    out += "}\n";
    diag::log_tagged_fmt("graphql", "build_batched_query done batch_count=%zu result_len=%zu",
        batch_count, out.size());
    return out;
}

std::string beautify_query(const std::string& source)
{
    diag::log_tagged_fmt("graphql", "beautify_query entry src_len=%zu", source.size());
    std::string out;
    int depth = 0;
    bool prev_space = true;
    for (size_t i = 0; i < source.size(); ++i) {
        char c = source[i];
        if (c == '{') {
            if (!out.empty() && out.back() != ' ' && out.back() != '\n') out += ' ';
            out += "{\n";
            depth++;
            for (int d = 0; d < depth; ++d) out += "  ";
            prev_space = true;
        } else if (c == '}') {
            depth--;
            if (depth < 0) depth = 0;
            while (!out.empty() && (out.back() == ' ' || out.back() == '\t')) out.pop_back();
            out += "\n";
            for (int d = 0; d < depth; ++d) out += "  ";
            out += "}";
            if (depth > 0) {
                out += "\n";
                for (int d = 0; d < depth; ++d) out += "  ";
            } else {
                out += "\n";
            }
            prev_space = true;
        } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            if (!prev_space) { out += ' '; prev_space = true; }
        } else {
            out += c;
            prev_space = false;
        }
    }
    return out;
}

std::string minify_query(const std::string& source)
{
    diag::log_tagged_fmt("graphql", "minify_query entry src_len=%zu", source.size());
    std::string out;
    out.reserve(source.size());
    bool prev_space = false;
    for (char c : source) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            if (!prev_space) { out += ' '; prev_space = true; }
        } else {
            out += c;
            prev_space = false;
        }
    }
    while (!out.empty() && out.front() == ' ') out.erase(out.begin());
    while (!out.empty() && out.back()  == ' ') out.pop_back();
    diag::log_tagged_fmt("graphql", "minify_query done result_len=%zu", out.size());
    return out;
}

bool send_query(const std::string& endpoint,
                const std::map<std::string, std::string>& headers,
                const std::string& query,
                const nlohmann::json& variables,
                nlohmann::json& response_json,
                std::string& raw_text)
{
    const url_log_t endpoint_log = summarize_url_for_log(endpoint);
    diag::log_tagged_fmt("graphql", "send_query entry scheme=%s host=%s port=%u path=%s query_param=%d endpoint_len=%zu query_len=%zu variables_type=%s headers=%zu",
        endpoint_log.scheme.c_str(), endpoint_log.host.c_str(), static_cast<unsigned>(endpoint_log.port),
        endpoint_log.path.c_str(), (int)endpoint_log.has_query, endpoint_log.length,
        query.size(), variables.type_name(), headers.size());
    std::string scheme, host, path; uint16_t port = 0;
    if (!audit_http::parse_url(endpoint, scheme, host, port, path)) {
        diag::log_tagged_fmt("graphql", "send_query parse_url_failed endpoint_len=%zu", endpoint.size());
        set_err("graphql.send_query: parse_url failed");
        return false;
    }
    diag::log_tagged_fmt("graphql", "send_query parsed scheme=%s host=%s port=%u path=%s query=%d",
        scheme.c_str(), host.c_str(), static_cast<unsigned>(port), endpoint_log.path.c_str(), (int)endpoint_log.has_query);
    std::string origin = scheme + "://" + host;
    if ((scheme == "https" && port != 443) || (scheme == "http" && port != 80))
        origin += ":" + std::to_string(port);

    httplib::Client cli(origin);
    cli.set_connection_timeout(0, 5000000);
    cli.set_read_timeout(20, 0);
    cli.set_write_timeout(20, 0);
    cli.enable_server_certificate_verification(true);

    httplib::Headers hh;
    bool has_ct = false;
    for (const auto& kv : headers) {
        hh.emplace(kv.first, kv.second);
        if (to_lower(kv.first) == "content-type") has_ct = true;
    }
    if (!has_ct) hh.emplace("Content-Type", std::string("application/json"));

    nlohmann::json body;
    body["query"] = query;
    if (!variables.is_null()) body["variables"] = variables;
    std::string body_str = body.dump();

    diag::log_tagged_fmt("graphql", "send_query posting host=%s port=%u path=%s headers=%zu body_len=%zu",
        host.c_str(), static_cast<unsigned>(port), endpoint_log.path.c_str(), hh.size(), body_str.size());
    auto res = cli.Post(path, hh, body_str, std::string("application/json"));
    if (!res) {
        diag::log_tagged_fmt("graphql", "send_query post_failed host=%s path=%s",
            host.c_str(), endpoint_log.path.c_str());
        set_err("graphql.send_query: POST failed");
        return false;
    }
    raw_text = res->body;
    diag::log_tagged_fmt("graphql", "send_query response_received status=%d body_len=%zu",
        res->status, raw_text.size());
    if (raw_text.empty()) {
        diag::log_tagged_fmt("graphql", "send_query empty_body host=%s path=%s status=%d",
            host.c_str(), endpoint_log.path.c_str(), res->status);
        set_err("graphql.send_query: empty body");
        return false;
    }
    response_json = nlohmann::json::parse(raw_text, nullptr, false);
    if (response_json.is_discarded()) {
        diag::log_tagged_fmt("graphql", "send_query response_not_json host=%s path=%s status=%d body_len=%zu",
            host.c_str(), endpoint_log.path.c_str(), res->status, raw_text.size());
        set_err("graphql.send_query: response is not JSON");
        return false;
    }
    diag::log_tagged_fmt("graphql", "send_query ok host=%s path=%s status=%d response_type=%s",
        host.c_str(), endpoint_log.path.c_str(), res->status, response_json.type_name());
    return true;
}

nlohmann::json schema_to_json(const gql_schema_t& s)
{
    diag::log_tagged_fmt("graphql", "schema_to_json entry types=%zu", s.types.size());
    nlohmann::json j;
    j["query_type"]        = s.query_type;
    j["mutation_type"]     = s.mutation_type;
    j["subscription_type"] = s.subscription_type;
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& t : s.types) {
        nlohmann::json tj;
        tj["name"] = t.name;
        tj["kind"] = t.kind;
        nlohmann::json fs = nlohmann::json::array();
        for (const auto& f : t.fields) {
            nlohmann::json fj;
            fj["name"] = f.name;
            fj["type"] = f.type_str;
            fj["description"] = f.description;
            nlohmann::json args = nlohmann::json::array();
            for (const auto& a : f.args) args.push_back(nlohmann::json{{"name", a.first}, {"type", a.second}});
            fj["args"] = std::move(args);
            fs.push_back(std::move(fj));
        }
        tj["fields"] = std::move(fs);
        tj["interfaces"]  = t.interfaces;
        tj["enum_values"] = t.enum_values;
        arr.push_back(std::move(tj));
    }
    j["types"] = std::move(arr);
    return j;
}

bool cache_schema(const std::string& endpoint, const gql_schema_t& schema)
{
    const url_log_t endpoint_log = summarize_url_for_log(endpoint);
    diag::log_tagged_fmt("graphql", "cache_schema host=%s path=%s endpoint_len=%zu types=%zu",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), endpoint_log.length, schema.types.size());
    auto& c = cache();
    std::lock_guard<std::mutex> lk(c.mtx);
    c.by_endpoint[endpoint] = schema;
    diag::log_tagged_fmt("graphql", "cache_schema cached total_entries=%zu", c.by_endpoint.size());
    return true;
}

bool get_cached_schema(const std::string& endpoint, gql_schema_t& out)
{
    const url_log_t endpoint_log = summarize_url_for_log(endpoint);
    diag::log_tagged_fmt("graphql", "get_cached_schema entry host=%s path=%s endpoint_len=%zu",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), endpoint_log.length);
    auto& c = cache();
    std::lock_guard<std::mutex> lk(c.mtx);
    auto it = c.by_endpoint.find(endpoint);
    if (it == c.by_endpoint.end()) {
        diag::log_tagged_fmt("graphql", "get_cached_schema not_found host=%s path=%s",
            endpoint_log.host.c_str(), endpoint_log.path.c_str());
        return false;
    }
    out = it->second;
    diag::log_tagged_fmt("graphql", "get_cached_schema found host=%s path=%s types=%zu",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), out.types.size());
    return true;
}

bool has_cached_schema(const std::string& endpoint)
{
    auto& c = cache();
    std::lock_guard<std::mutex> lk(c.mtx);
    bool found = c.by_endpoint.find(endpoint) != c.by_endpoint.end();
    const url_log_t endpoint_log = summarize_url_for_log(endpoint);
    diag::log_tagged_fmt("graphql", "has_cached_schema host=%s path=%s endpoint_len=%zu result=%d",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), endpoint_log.length, static_cast<int>(found));
    return found;
}

}
}
}
