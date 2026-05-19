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
    return err_slot();
}

bool introspect(const std::string& endpoint,
                const std::map<std::string, std::string>& headers,
                gql_schema_t& out,
                std::string& raw_response)
{
    nlohmann::json body;
    body["query"] = introspection_query();
    body["operationName"] = "IntrospectionQuery";
    nlohmann::json variables = nlohmann::json::object();

    nlohmann::json resp_json;
    if (!send_query(endpoint, headers, introspection_query(), variables, resp_json, raw_response)) {
        return false;
    }

    if (!resp_json.is_object() || !resp_json.contains("data") || !resp_json["data"].is_object()) {
        set_err("graphql.introspect: no data field");
        return false;
    }
    const auto& data = resp_json["data"];
    if (!data.contains("__schema") || !data["__schema"].is_object()) {
        set_err("graphql.introspect: no __schema");
        return false;
    }
    const auto& schema = data["__schema"];

    gql_schema_t parsed;
    if (schema.contains("queryType") && schema["queryType"].is_object())
        parsed.query_type = schema["queryType"].value("name", std::string());
    if (schema.contains("mutationType") && schema["mutationType"].is_object())
        parsed.mutation_type = schema["mutationType"].value("name", std::string());
    if (schema.contains("subscriptionType") && schema["subscriptionType"].is_object())
        parsed.subscription_type = schema["subscriptionType"].value("name", std::string());

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
            parsed.types.push_back(std::move(gt));
        }
    }

    cache_schema(endpoint, parsed);
    out = std::move(parsed);
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
    if (depth < 1) depth = 1;
    if (depth > 5) depth = 5;
    std::string query_root_name = schema.query_type.empty() ? std::string("Query") : schema.query_type;
    const gql_type_t* root = find_type(schema, query_root_name);
    if (!root) {
        return std::string("query { __typename }");
    }
    const gql_field_t* found = nullptr;
    for (const auto& f : root->fields) if (f.name == field_name) { found = &f; break; }
    if (!found) {
        for (const auto& t : schema.types) {
            for (const auto& f : t.fields) {
                if (f.name == field_name) { found = &f; break; }
            }
            if (found) break;
        }
    }
    if (!found) {
        return std::string("query { ") + field_name + std::string(" }");
    }
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
    return out;
}

std::string build_batched_query(const std::string& operation, size_t batch_count)
{
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
    return out;
}

std::string beautify_query(const std::string& source)
{
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
    return out;
}

bool send_query(const std::string& endpoint,
                const std::map<std::string, std::string>& headers,
                const std::string& query,
                const nlohmann::json& variables,
                nlohmann::json& response_json,
                std::string& raw_text)
{
    std::string scheme, host, path; uint16_t port = 0;
    if (!audit_http::parse_url(endpoint, scheme, host, port, path)) {
        set_err("graphql.send_query: parse_url failed");
        return false;
    }
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

    auto res = cli.Post(path, hh, body_str, std::string("application/json"));
    if (!res) {
        set_err("graphql.send_query: POST failed");
        return false;
    }
    raw_text = res->body;
    if (raw_text.empty()) {
        set_err("graphql.send_query: empty body");
        return false;
    }
    response_json = nlohmann::json::parse(raw_text, nullptr, false);
    if (response_json.is_discarded()) {
        set_err("graphql.send_query: response is not JSON");
        return false;
    }
    return true;
}

nlohmann::json schema_to_json(const gql_schema_t& s)
{
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
    auto& c = cache();
    std::lock_guard<std::mutex> lk(c.mtx);
    c.by_endpoint[endpoint] = schema;
    return true;
}

bool get_cached_schema(const std::string& endpoint, gql_schema_t& out)
{
    auto& c = cache();
    std::lock_guard<std::mutex> lk(c.mtx);
    auto it = c.by_endpoint.find(endpoint);
    if (it == c.by_endpoint.end()) return false;
    out = it->second;
    return true;
}

bool has_cached_schema(const std::string& endpoint)
{
    auto& c = cache();
    std::lock_guard<std::mutex> lk(c.mtx);
    return c.by_endpoint.find(endpoint) != c.by_endpoint.end();
}

}
}
}
