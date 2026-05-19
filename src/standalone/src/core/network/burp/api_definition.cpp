#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifdef small
#undef small
#endif

#include "api_definition.hpp"
#include "audit_http.hpp"
#include "scope.hpp"
#include "issue.hpp"

#include "../../../helpers/diag_log.hpp"

#include <httplib.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <fstream>
#include <functional>
#include <mutex>
#include <sstream>
#include <unordered_map>

namespace aida {
namespace burp {
namespace api_definition {

namespace {

std::mutex& err_mtx()  { static std::mutex m; return m; }
std::string& err_slot() { static std::string s; return s; }

void set_err(const std::string& m)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = m;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

struct store_t
{
    std::mutex                          mtx;
    std::vector<api_collection_t>       items;
    std::atomic<uint64_t>               next_id{1};
};

store_t& store()
{
    static store_t s;
    return s;
}

std::string to_lower(std::string s)
{
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

bool ends_with_ci(const std::string& s, const std::string& suffix)
{
    if (s.size() < suffix.size()) return false;
    return to_lower(s.substr(s.size() - suffix.size())) == to_lower(suffix);
}

std::string url_encode_component(const std::string& s)
{
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            char buf[4];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%%%02X", c);
            out += buf;
        }
    }
    return out;
}

std::string read_file_utf8(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return std::string();
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool split_url(const std::string& url, std::string& scheme, std::string& host, uint16_t& port, std::string& path)
{
    return audit_http::parse_url(url, scheme, host, port, path);
}

nlohmann::json schema_example(const nlohmann::json& schema,
                              const nlohmann::json& components,
                              int depth)
{
    if (depth > 6) return nlohmann::json();
    if (!schema.is_object()) return nlohmann::json();

    if (schema.contains("example"))   return schema["example"];
    if (schema.contains("default"))   return schema["default"];
    if (schema.contains("examples") && schema["examples"].is_array() && !schema["examples"].empty())
        return schema["examples"].front();

    if (schema.contains("$ref") && schema["$ref"].is_string()) {
        std::string r = schema["$ref"].get<std::string>();
        const std::string prefix = "#/components/schemas/";
        const std::string prefix_v2 = "#/definitions/";
        std::string key;
        if (r.rfind(prefix, 0) == 0)        key = r.substr(prefix.size());
        else if (r.rfind(prefix_v2, 0) == 0) key = r.substr(prefix_v2.size());
        if (!key.empty() && components.is_object() && components.contains(key))
            return schema_example(components[key], components, depth + 1);
        return nlohmann::json();
    }

    std::string type = schema.contains("type") && schema["type"].is_string()
                            ? schema["type"].get<std::string>()
                            : std::string();
    if (schema.contains("enum") && schema["enum"].is_array() && !schema["enum"].empty())
        return schema["enum"].front();

    if (type == "string")  {
        if (schema.contains("format") && schema["format"].is_string()) {
            const std::string fmt = schema["format"].get<std::string>();
            if (fmt == "date")        return std::string("2024-01-01");
            if (fmt == "date-time")   return std::string("2024-01-01T00:00:00Z");
            if (fmt == "uuid")        return std::string("00000000-0000-0000-0000-000000000000");
            if (fmt == "email")       return std::string("user@example.com");
            if (fmt == "uri")         return std::string("https://example.com/");
            if (fmt == "byte")        return std::string("aGVsbG8=");
            if (fmt == "binary")      return std::string();
            if (fmt == "ipv4")        return std::string("127.0.0.1");
            if (fmt == "ipv6")        return std::string("::1");
        }
        return std::string("string");
    }
    if (type == "integer") return 0;
    if (type == "number")  return 0.0;
    if (type == "boolean") return true;

    if (type == "array") {
        nlohmann::json a = nlohmann::json::array();
        if (schema.contains("items"))
            a.push_back(schema_example(schema["items"], components, depth + 1));
        return a;
    }

    if (type == "object" || schema.contains("properties")) {
        nlohmann::json o = nlohmann::json::object();
        if (schema.contains("properties") && schema["properties"].is_object()) {
            for (auto it = schema["properties"].begin(); it != schema["properties"].end(); ++it) {
                o[it.key()] = schema_example(it.value(), components, depth + 1);
            }
        }
        return o;
    }

    if (schema.contains("allOf") && schema["allOf"].is_array()) {
        nlohmann::json o = nlohmann::json::object();
        for (const auto& sub : schema["allOf"]) {
            auto piece = schema_example(sub, components, depth + 1);
            if (piece.is_object()) {
                for (auto it = piece.begin(); it != piece.end(); ++it) o[it.key()] = it.value();
            }
        }
        return o;
    }
    if (schema.contains("oneOf") && schema["oneOf"].is_array() && !schema["oneOf"].empty())
        return schema_example(schema["oneOf"].front(), components, depth + 1);
    if (schema.contains("anyOf") && schema["anyOf"].is_array() && !schema["anyOf"].empty())
        return schema_example(schema["anyOf"].front(), components, depth + 1);

    return nlohmann::json();
}

void parse_security_schemes(const nlohmann::json& schemes, api_request_template_t& tpl)
{
    if (!schemes.is_object()) return;
    for (auto it = schemes.begin(); it != schemes.end(); ++it) {
        if (!it.value().is_object()) continue;
        std::string scheme_type = it.value().value("type", std::string());
        if (scheme_type == "http") {
            std::string sch = it.value().value("scheme", std::string());
            if (sch == "basic")   { tpl.auth_kind = "basic";  return; }
            if (sch == "bearer")  { tpl.auth_kind = "bearer"; return; }
        }
        if (scheme_type == "apiKey")  { tpl.auth_kind = "api_key_header"; return; }
        if (scheme_type == "oauth2")  { tpl.auth_kind = "oauth2";         return; }
    }
}

void parse_openapi_v3(const nlohmann::json& doc, api_collection_t& col)
{
    std::string base_url;
    if (doc.contains("servers") && doc["servers"].is_array() && !doc["servers"].empty()) {
        const auto& srv = doc["servers"].front();
        if (srv.is_object() && srv.contains("url") && srv["url"].is_string())
            base_url = srv["url"].get<std::string>();
    }
    col.base_url = base_url;

    nlohmann::json components = nlohmann::json::object();
    if (doc.contains("components") && doc["components"].is_object()
        && doc["components"].contains("schemas") && doc["components"]["schemas"].is_object()) {
        components = doc["components"]["schemas"];
    }

    nlohmann::json sec_schemes = nlohmann::json::object();
    if (doc.contains("components") && doc["components"].is_object()
        && doc["components"].contains("securitySchemes") && doc["components"]["securitySchemes"].is_object()) {
        sec_schemes = doc["components"]["securitySchemes"];
    }

    if (!doc.contains("paths") || !doc["paths"].is_object()) return;
    const auto& paths = doc["paths"];

    const char* methods[] = { "get","post","put","patch","delete","head","options","trace" };

    for (auto pit = paths.begin(); pit != paths.end(); ++pit) {
        const std::string& path = pit.key();
        const auto& path_item = pit.value();
        if (!path_item.is_object()) continue;

        std::vector<nlohmann::json> path_level_params;
        if (path_item.contains("parameters") && path_item["parameters"].is_array()) {
            for (const auto& p : path_item["parameters"]) path_level_params.push_back(p);
        }

        for (const char* m : methods) {
            if (!path_item.contains(m)) continue;
            const auto& op = path_item[m];
            if (!op.is_object()) continue;

            api_request_template_t tpl;
            tpl.method   = to_lower(m);
            std::transform(tpl.method.begin(), tpl.method.end(), tpl.method.begin(),
                           [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
            tpl.path     = path;
            tpl.base_url = base_url;
            tpl.id       = op.value("operationId", std::string());
            if (tpl.id.empty()) { tpl.id = tpl.method + " " + path; }
            tpl.summary     = op.value("summary", std::string());
            tpl.description = op.value("description", std::string());

            if (op.contains("tags") && op["tags"].is_array())
                for (const auto& t : op["tags"]) if (t.is_string()) tpl.tags.push_back(t.get<std::string>());

            std::vector<nlohmann::json> params = path_level_params;
            if (op.contains("parameters") && op["parameters"].is_array())
                for (const auto& p : op["parameters"]) params.push_back(p);

            for (const auto& p : params) {
                if (!p.is_object()) continue;
                std::string in   = p.value("in", std::string());
                std::string name = p.value("name", std::string());
                std::string ex;
                if (p.contains("example")) ex = p["example"].is_string() ? p["example"].get<std::string>() : p["example"].dump();
                else if (p.contains("schema")) {
                    auto example = schema_example(p["schema"], components, 0);
                    if (!example.is_null())
                        ex = example.is_string() ? example.get<std::string>() : example.dump();
                }
                if (name.empty()) continue;
                if (in == "path")    tpl.path_params.emplace_back(name, ex);
                else if (in == "query")   tpl.query_params.emplace_back(name, ex);
                else if (in == "header")  tpl.headers.emplace_back(name, ex);
            }

            if (op.contains("requestBody") && op["requestBody"].is_object()) {
                const auto& rb = op["requestBody"];
                if (rb.contains("content") && rb["content"].is_object()) {
                    const auto& content = rb["content"];
                    auto pick_ct = [&content](const char* k) -> nlohmann::json {
                        if (content.contains(k)) return content[k];
                        return nlohmann::json();
                    };
                    nlohmann::json mt = pick_ct("application/json");
                    std::string ct = "application/json";
                    if (mt.is_null()) {
                        mt = pick_ct("application/x-www-form-urlencoded");
                        if (!mt.is_null()) ct = "application/x-www-form-urlencoded";
                    }
                    if (mt.is_null()) {
                        for (auto it = content.begin(); it != content.end(); ++it) {
                            mt = it.value(); ct = it.key();
                            break;
                        }
                    }
                    if (mt.is_object() && mt.contains("schema")) {
                        auto ex = schema_example(mt["schema"], components, 0);
                        if (!ex.is_null()) {
                            tpl.body_template = (ct.find("json") != std::string::npos) ? ex.dump(2)
                                              : (ex.is_string() ? ex.get<std::string>() : ex.dump());
                        }
                    }
                    tpl.headers.emplace_back("Content-Type", ct);
                }
            }

            if (op.contains("security") && op["security"].is_array() && !op["security"].empty()) {
                const auto& sec = op["security"].front();
                if (sec.is_object()) {
                    for (auto sit = sec.begin(); sit != sec.end(); ++sit) {
                        if (sec_schemes.contains(sit.key())) {
                            nlohmann::json filtered = nlohmann::json::object();
                            filtered[sit.key()] = sec_schemes[sit.key()];
                            parse_security_schemes(filtered, tpl);
                            break;
                        }
                    }
                }
            } else {
                parse_security_schemes(sec_schemes, tpl);
            }

            col.requests.push_back(std::move(tpl));
        }
    }
}

void parse_swagger_v2(const nlohmann::json& doc, api_collection_t& col)
{
    std::string base_url;
    std::string scheme = "https";
    if (doc.contains("schemes") && doc["schemes"].is_array() && !doc["schemes"].empty())
        if (doc["schemes"].front().is_string()) scheme = doc["schemes"].front().get<std::string>();
    if (doc.contains("host") && doc["host"].is_string()) {
        base_url = scheme + "://" + doc["host"].get<std::string>();
        if (doc.contains("basePath") && doc["basePath"].is_string())
            base_url += doc["basePath"].get<std::string>();
    }
    col.base_url = base_url;

    nlohmann::json components = nlohmann::json::object();
    if (doc.contains("definitions") && doc["definitions"].is_object())
        components = doc["definitions"];

    nlohmann::json sec_schemes = nlohmann::json::object();
    if (doc.contains("securityDefinitions") && doc["securityDefinitions"].is_object()) {
        sec_schemes = doc["securityDefinitions"];
    }

    if (!doc.contains("paths") || !doc["paths"].is_object()) return;
    const auto& paths = doc["paths"];

    const char* methods[] = { "get","post","put","patch","delete","head","options" };

    for (auto pit = paths.begin(); pit != paths.end(); ++pit) {
        const std::string& path = pit.key();
        const auto& path_item = pit.value();
        if (!path_item.is_object()) continue;
        for (const char* m : methods) {
            if (!path_item.contains(m)) continue;
            const auto& op = path_item[m];
            if (!op.is_object()) continue;
            api_request_template_t tpl;
            tpl.method   = to_lower(m);
            std::transform(tpl.method.begin(), tpl.method.end(), tpl.method.begin(),
                           [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
            tpl.path     = path;
            tpl.base_url = base_url;
            tpl.id       = op.value("operationId", std::string());
            if (tpl.id.empty()) tpl.id = tpl.method + " " + path;
            tpl.summary     = op.value("summary", std::string());
            tpl.description = op.value("description", std::string());

            if (op.contains("tags") && op["tags"].is_array())
                for (const auto& t : op["tags"]) if (t.is_string()) tpl.tags.push_back(t.get<std::string>());

            if (op.contains("parameters") && op["parameters"].is_array()) {
                for (const auto& p : op["parameters"]) {
                    if (!p.is_object()) continue;
                    std::string in   = p.value("in", std::string());
                    std::string name = p.value("name", std::string());
                    std::string ex;
                    if (p.contains("default")) ex = p["default"].is_string() ? p["default"].get<std::string>() : p["default"].dump();
                    else if (in == "body" && p.contains("schema")) {
                        auto example = schema_example(p["schema"], components, 0);
                        if (!example.is_null()) tpl.body_template = example.dump(2);
                        tpl.headers.emplace_back("Content-Type", std::string("application/json"));
                        continue;
                    }
                    if (name.empty()) continue;
                    if (in == "path")    tpl.path_params.emplace_back(name, ex);
                    else if (in == "query")   tpl.query_params.emplace_back(name, ex);
                    else if (in == "header")  tpl.headers.emplace_back(name, ex);
                    else if (in == "formData") tpl.body_params.emplace_back(name, ex);
                }
            }

            parse_security_schemes(sec_schemes, tpl);
            col.requests.push_back(std::move(tpl));
        }
    }
}

bool parse_url_components(const std::string& url,
                          std::string& scheme,
                          std::string& host,
                          uint16_t& port,
                          std::string& path)
{
    return audit_http::parse_url(url, scheme, host, port, path);
}

void parse_postman_item(const nlohmann::json& item,
                        const std::vector<std::string>& folder_stack,
                        api_collection_t& col)
{
    if (!item.is_object()) return;
    if (item.contains("item") && item["item"].is_array()) {
        std::vector<std::string> sub = folder_stack;
        if (item.contains("name") && item["name"].is_string()) sub.push_back(item["name"].get<std::string>());
        for (const auto& sub_item : item["item"]) parse_postman_item(sub_item, sub, col);
        return;
    }

    if (!item.contains("request")) return;
    const auto& req = item["request"];

    api_request_template_t tpl;
    tpl.id = item.value("name", std::string());
    if (tpl.id.empty()) tpl.id = std::string("postman_req_") + std::to_string(col.requests.size());
    for (const auto& f : folder_stack) tpl.tags.push_back(f);

    if (req.is_string()) {
        tpl.method = "GET";
        std::string u = req.get<std::string>();
        std::string sc, h, p; uint16_t pt = 0;
        if (parse_url_components(u, sc, h, pt, p)) {
            std::string base = sc + "://" + h;
            if ((sc == "https" && pt != 443) || (sc == "http" && pt != 80)) base += ":" + std::to_string(pt);
            tpl.base_url = base;
            tpl.path = p;
        }
        col.requests.push_back(std::move(tpl));
        return;
    }

    if (!req.is_object()) return;
    tpl.method = req.value("method", std::string("GET"));

    std::string url_str;
    if (req.contains("url")) {
        if (req["url"].is_string()) url_str = req["url"].get<std::string>();
        else if (req["url"].is_object()) {
            const auto& u = req["url"];
            if (u.contains("raw") && u["raw"].is_string()) url_str = u["raw"].get<std::string>();
            if (u.contains("query") && u["query"].is_array()) {
                for (const auto& q : u["query"]) {
                    if (!q.is_object()) continue;
                    std::string k = q.value("key", std::string());
                    std::string v = q.value("value", std::string());
                    if (!k.empty()) tpl.query_params.emplace_back(k, v);
                }
            }
            if (u.contains("variable") && u["variable"].is_array()) {
                for (const auto& v : u["variable"]) {
                    if (!v.is_object()) continue;
                    std::string k = v.value("key", std::string());
                    std::string val = v.value("value", std::string());
                    if (!k.empty()) tpl.path_params.emplace_back(k, val);
                }
            }
        }
    }

    if (!url_str.empty()) {
        std::string sc, h, p; uint16_t pt = 0;
        if (parse_url_components(url_str, sc, h, pt, p)) {
            std::string base = sc + "://" + h;
            if ((sc == "https" && pt != 443) || (sc == "http" && pt != 80)) base += ":" + std::to_string(pt);
            tpl.base_url = base;
            std::string path_only = p;
            auto q = path_only.find('?');
            if (q != std::string::npos) path_only = path_only.substr(0, q);
            tpl.path = path_only;
        }
    }

    if (req.contains("header") && req["header"].is_array()) {
        for (const auto& h : req["header"]) {
            if (!h.is_object()) continue;
            std::string k = h.value("key", std::string());
            std::string v = h.value("value", std::string());
            bool disabled = h.value("disabled", false);
            if (!disabled && !k.empty()) tpl.headers.emplace_back(k, v);
        }
    }

    if (req.contains("body") && req["body"].is_object()) {
        const auto& b = req["body"];
        std::string mode = b.value("mode", std::string());
        if (mode == "raw" && b.contains("raw") && b["raw"].is_string()) {
            tpl.body_template = b["raw"].get<std::string>();
            if (b.contains("options") && b["options"].is_object()
                && b["options"].contains("raw") && b["options"]["raw"].is_object()
                && b["options"]["raw"].contains("language")
                && b["options"]["raw"]["language"].is_string()) {
                const std::string lang = b["options"]["raw"]["language"].get<std::string>();
                if (lang == "json") tpl.headers.emplace_back("Content-Type", std::string("application/json"));
            }
        } else if (mode == "urlencoded" && b.contains("urlencoded") && b["urlencoded"].is_array()) {
            std::string body;
            for (const auto& it : b["urlencoded"]) {
                if (!it.is_object()) continue;
                std::string k = it.value("key", std::string());
                std::string v = it.value("value", std::string());
                if (k.empty()) continue;
                tpl.body_params.emplace_back(k, v);
                if (!body.empty()) body += "&";
                body += url_encode_component(k) + "=" + url_encode_component(v);
            }
            tpl.body_template = body;
            tpl.headers.emplace_back("Content-Type", std::string("application/x-www-form-urlencoded"));
        } else if (mode == "formdata" && b.contains("formdata") && b["formdata"].is_array()) {
            for (const auto& it : b["formdata"]) {
                if (!it.is_object()) continue;
                std::string k = it.value("key", std::string());
                std::string v = it.value("value", std::string());
                if (!k.empty()) tpl.body_params.emplace_back(k, v);
            }
            tpl.headers.emplace_back("Content-Type", std::string("multipart/form-data"));
        }
    }

    if (req.contains("auth") && req["auth"].is_object()) {
        std::string at = req["auth"].value("type", std::string());
        if (at == "bearer") tpl.auth_kind = "bearer";
        else if (at == "basic") tpl.auth_kind = "basic";
        else if (at == "apikey") tpl.auth_kind = "api_key_header";
        else if (at == "oauth2") tpl.auth_kind = "oauth2";
    }

    col.requests.push_back(std::move(tpl));
}

void parse_postman_collection(const nlohmann::json& doc, api_collection_t& col)
{
    if (doc.contains("info") && doc["info"].is_object()) {
        col.name = doc["info"].value("name", col.name);
    }
    if (doc.contains("item") && doc["item"].is_array()) {
        std::vector<std::string> stack;
        for (const auto& it : doc["item"]) parse_postman_item(it, stack, col);
    }
}

void parse_har(const nlohmann::json& doc, api_collection_t& col)
{
    if (!doc.contains("log") || !doc["log"].is_object()) return;
    const auto& log = doc["log"];
    if (!log.contains("entries") || !log["entries"].is_array()) return;

    size_t idx = 0;
    for (const auto& entry : log["entries"]) {
        if (!entry.is_object() || !entry.contains("request")) continue;
        const auto& req = entry["request"];
        api_request_template_t tpl;
        tpl.id     = std::string("har_") + std::to_string(idx++);
        tpl.method = req.value("method", std::string("GET"));
        std::string url = req.value("url", std::string());
        std::string sc, h, p; uint16_t pt = 0;
        if (!url.empty() && parse_url_components(url, sc, h, pt, p)) {
            std::string base = sc + "://" + h;
            if ((sc == "https" && pt != 443) || (sc == "http" && pt != 80)) base += ":" + std::to_string(pt);
            tpl.base_url = base;
            auto q = p.find('?');
            tpl.path = (q == std::string::npos) ? p : p.substr(0, q);
        }
        if (req.contains("queryString") && req["queryString"].is_array()) {
            for (const auto& q : req["queryString"]) {
                if (!q.is_object()) continue;
                std::string k = q.value("name", std::string());
                std::string v = q.value("value", std::string());
                if (!k.empty()) tpl.query_params.emplace_back(k, v);
            }
        }
        if (req.contains("headers") && req["headers"].is_array()) {
            for (const auto& hd : req["headers"]) {
                if (!hd.is_object()) continue;
                std::string k = hd.value("name", std::string());
                std::string v = hd.value("value", std::string());
                if (!k.empty()) tpl.headers.emplace_back(k, v);
            }
        }
        if (req.contains("postData") && req["postData"].is_object()) {
            const auto& pd = req["postData"];
            if (pd.contains("text") && pd["text"].is_string()) tpl.body_template = pd["text"].get<std::string>();
            if (pd.contains("mimeType") && pd["mimeType"].is_string()) {
                bool has_ct = false;
                for (auto& kv : tpl.headers) {
                    if (to_lower(kv.first) == "content-type") { has_ct = true; break; }
                }
                if (!has_ct) tpl.headers.emplace_back("Content-Type", pd["mimeType"].get<std::string>());
            }
        }
        col.requests.push_back(std::move(tpl));
    }
}

bool yaml_to_json_minimal(const std::string& text, nlohmann::json& out, std::string& err)
{
    std::vector<std::string> lines;
    {
        std::string cur;
        for (char c : text) {
            if (c == '\r') continue;
            if (c == '\n') { lines.push_back(cur); cur.clear(); }
            else cur.push_back(c);
        }
        if (!cur.empty()) lines.push_back(cur);
    }

    auto count_indent = [](const std::string& l) -> int {
        int n = 0;
        for (char c : l) { if (c == ' ') ++n; else if (c == '\t') n += 2; else break; }
        return n;
    };

    auto strip_trailing_comment = [](std::string l) -> std::string {
        bool in_dq = false, in_sq = false;
        for (size_t i = 0; i < l.size(); ++i) {
            if (l[i] == '"' && !in_sq) in_dq = !in_dq;
            else if (l[i] == '\'' && !in_dq) in_sq = !in_sq;
            else if (l[i] == '#' && !in_dq && !in_sq) { l.resize(i); break; }
        }
        while (!l.empty() && (l.back() == ' ' || l.back() == '\t')) l.pop_back();
        return l;
    };

    std::function<nlohmann::json(size_t&, int)> parse_block;
    parse_block = [&](size_t& idx, int base_indent) -> nlohmann::json {
        nlohmann::json node;
        bool is_seq = false, is_map = false;
        while (idx < lines.size()) {
            std::string raw = strip_trailing_comment(lines[idx]);
            if (raw.find_first_not_of(" \t") == std::string::npos) { ++idx; continue; }
            int ind = count_indent(raw);
            if (ind < base_indent) break;
            if (ind > base_indent) { ++idx; continue; }

            std::string content = raw.substr(static_cast<size_t>(ind));

            if (!content.empty() && content[0] == '-') {
                if (!is_seq) { node = nlohmann::json::array(); is_seq = true; }
                std::string rest = (content.size() > 1) ? content.substr(1) : std::string();
                while (!rest.empty() && rest.front() == ' ') rest.erase(rest.begin());
                if (rest.empty()) {
                    ++idx;
                    nlohmann::json child = parse_block(idx, base_indent + 2);
                    node.push_back(std::move(child));
                } else if (rest.find(':') != std::string::npos
                            && rest.find(':') != rest.size() - 1
                            && (rest[rest.find(':') + 1] == ' ' || rest[rest.find(':') + 1] == '\0')) {
                    nlohmann::json child = nlohmann::json::object();
                    size_t cp = rest.find(':');
                    std::string k = trim(rest.substr(0, cp));
                    std::string v = trim(rest.substr(cp + 1));
                    if (!k.empty() && k.front() == '"' && k.back() == '"') k = k.substr(1, k.size() - 2);
                    if (v.empty()) {
                        ++idx;
                        child[k] = parse_block(idx, base_indent + 2);
                    } else {
                        if (v == "true") child[k] = true;
                        else if (v == "false") child[k] = false;
                        else if (v == "null" || v == "~") child[k] = nullptr;
                        else if (!v.empty() && v.front() == '"' && v.back() == '"') child[k] = v.substr(1, v.size() - 2);
                        else if (!v.empty() && v.front() == '\'' && v.back() == '\'') child[k] = v.substr(1, v.size() - 2);
                        else {
                            try {
                                size_t pos = 0;
                                long long iv = std::stoll(v, &pos);
                                if (pos == v.size()) child[k] = iv;
                                else throw 0;
                            } catch (...) {
                                try {
                                    size_t pos = 0;
                                    double dv = std::stod(v, &pos);
                                    if (pos == v.size()) child[k] = dv;
                                    else throw 0;
                                } catch (...) {
                                    child[k] = v;
                                }
                            }
                        }
                        ++idx;
                    }
                    node.push_back(std::move(child));
                } else {
                    if (rest == "true") node.push_back(true);
                    else if (rest == "false") node.push_back(false);
                    else if (rest == "null" || rest == "~") node.push_back(nullptr);
                    else if (!rest.empty() && rest.front() == '"' && rest.back() == '"') node.push_back(rest.substr(1, rest.size() - 2));
                    else node.push_back(rest);
                    ++idx;
                }
                continue;
            }

            size_t cp = std::string::npos;
            {
                bool in_dq = false, in_sq = false;
                for (size_t i = 0; i < content.size(); ++i) {
                    if (content[i] == '"' && !in_sq) in_dq = !in_dq;
                    else if (content[i] == '\'' && !in_dq) in_sq = !in_sq;
                    else if (content[i] == ':' && !in_dq && !in_sq) { cp = i; break; }
                }
            }
            if (cp == std::string::npos) {
                ++idx;
                continue;
            }
            if (!is_map) { node = nlohmann::json::object(); is_map = true; }
            std::string k = trim(content.substr(0, cp));
            std::string v = trim(content.substr(cp + 1));
            if (!k.empty() && k.front() == '"' && k.back() == '"') k = k.substr(1, k.size() - 2);
            if (v.empty()) {
                ++idx;
                node[k] = parse_block(idx, base_indent + 2);
            } else if (v == ">" || v == "|" || v == ">-" || v == "|-") {
                ++idx;
                std::string blob;
                while (idx < lines.size()) {
                    std::string lr = lines[idx];
                    if (lr.find_first_not_of(" \t") == std::string::npos) { blob += '\n'; ++idx; continue; }
                    int li = count_indent(lr);
                    if (li <= base_indent) break;
                    blob += lr.substr(static_cast<size_t>(base_indent + 2));
                    blob += '\n';
                    ++idx;
                }
                node[k] = blob;
            } else {
                if (v == "true") node[k] = true;
                else if (v == "false") node[k] = false;
                else if (v == "null" || v == "~") node[k] = nullptr;
                else if (!v.empty() && v.front() == '"' && v.back() == '"') node[k] = v.substr(1, v.size() - 2);
                else if (!v.empty() && v.front() == '\'' && v.back() == '\'') node[k] = v.substr(1, v.size() - 2);
                else {
                    try {
                        size_t pos = 0;
                        long long iv = std::stoll(v, &pos);
                        if (pos == v.size()) node[k] = iv;
                        else throw 0;
                    } catch (...) {
                        try {
                            size_t pos = 0;
                            double dv = std::stod(v, &pos);
                            if (pos == v.size()) node[k] = dv;
                            else throw 0;
                        } catch (...) {
                            node[k] = v;
                        }
                    }
                }
                ++idx;
            }
        }
        if (!is_map && !is_seq) return nlohmann::json();
        return node;
    };

    size_t idx = 0;
    if (text.find('&') != std::string::npos || text.find('*') != std::string::npos
        || text.find("<<:") != std::string::npos) {
        err = "yaml_to_json: anchors/aliases/merge keys not supported";
        return false;
    }
    nlohmann::json root = parse_block(idx, 0);
    if (root.is_null()) {
        err = "yaml_to_json: empty document";
        return false;
    }
    out = std::move(root);
    return true;
}

uint64_t install_collection(api_collection_t col)
{
    auto& s = store();
    {
        std::lock_guard<std::mutex> lk(s.mtx);
        col.id          = s.next_id.fetch_add(1);
        col.imported_ms = now_ms();
        s.items.push_back(std::move(col));
        return s.items.back().id;
    }
}

api_format_t infer_format(const std::string& text)
{
    std::string head = text.substr(0, std::min<size_t>(text.size(), 4096));
    std::string lc = to_lower(head);
    if (lc.find("\"swagger\"") != std::string::npos && lc.find("\"2.0\"") != std::string::npos) return api_format_t::swagger_v2;
    if (lc.find("\"openapi\"") != std::string::npos) return api_format_t::openapi_json;
    if (lc.find("openapi:") != std::string::npos) return api_format_t::openapi_yaml;
    if (lc.find("\"info\"") != std::string::npos && lc.find("\"item\"") != std::string::npos
        && lc.find("postman") != std::string::npos) return api_format_t::postman_v2_1;
    if (lc.find("\"log\"") != std::string::npos && lc.find("\"entries\"") != std::string::npos) return api_format_t::har;
    if (lc.find("type query") != std::string::npos || lc.find("schema {") != std::string::npos
        || lc.find("type mutation") != std::string::npos) return api_format_t::graphql_sdl;
    if (!head.empty() && (head[0] == '{' || head[0] == '[')) return api_format_t::openapi_json;
    return api_format_t::openapi_yaml;
}

uint64_t import_text_with_format(const std::string& text, api_format_t fmt, const std::string& source_path)
{
    if (text.empty()) { set_err("api_definition.import: empty text"); return 0; }
    if (fmt == api_format_t::auto_detect) fmt = infer_format(text);

    api_collection_t col;
    col.format      = fmt;
    col.source_path = source_path;

    if (fmt == api_format_t::graphql_sdl) {
        col.name           = "graphql_sdl";
        api_request_template_t tpl;
        tpl.id   = "graphql_sdl_body";
        tpl.method = "POST";
        tpl.body_template = text;
        tpl.headers.emplace_back("Content-Type", std::string("application/graphql"));
        col.requests.push_back(std::move(tpl));
        return install_collection(std::move(col));
    }

    nlohmann::json doc;
    if (fmt == api_format_t::openapi_yaml) {
        std::string err;
        if (!yaml_to_json_minimal(text, doc, err)) {
            set_err(std::string("api_definition.import: yaml parse failed: ") + err);
            return 0;
        }
    } else {
        doc = nlohmann::json::parse(text, nullptr, false);
        if (doc.is_discarded()) {
            set_err("api_definition.import: json parse failed");
            return 0;
        }
    }

    if (fmt == api_format_t::openapi_json || fmt == api_format_t::openapi_yaml) {
        if (doc.is_object() && doc.contains("swagger")) parse_swagger_v2(doc, col);
        else                                              parse_openapi_v3(doc, col);
        if (doc.is_object() && doc.contains("info") && doc["info"].is_object()
            && doc["info"].contains("title") && doc["info"]["title"].is_string()) {
            col.name = doc["info"]["title"].get<std::string>();
        } else if (col.name.empty()) col.name = "openapi_collection";
    } else if (fmt == api_format_t::swagger_v2) {
        parse_swagger_v2(doc, col);
        if (col.name.empty()) col.name = "swagger_collection";
    } else if (fmt == api_format_t::postman_v2_1) {
        parse_postman_collection(doc, col);
        if (col.name.empty()) col.name = "postman_collection";
    } else if (fmt == api_format_t::har) {
        col.name = "har_collection";
        parse_har(doc, col);
    } else {
        set_err("api_definition.import: unsupported format");
        return 0;
    }

    if (col.requests.empty()) {
        set_err("api_definition.import: no requests parsed");
        return 0;
    }

    return install_collection(std::move(col));
}

bool fetch_text_url(const std::string& url, std::string& out)
{
    std::string scheme, host, path; uint16_t port = 0;
    if (!parse_url_components(url, scheme, host, port, path)) {
        set_err("api_definition.import_url: parse_url failed");
        return false;
    }

    std::string origin = scheme + "://" + host;
    if ((scheme == "https" && port != 443) || (scheme == "http" && port != 80)) {
        origin += ":" + std::to_string(port);
    }

    httplib::Client cli(origin);
    cli.set_connection_timeout(0, 5000000);
    cli.set_read_timeout(15, 0);
    cli.set_write_timeout(15, 0);
    cli.enable_server_certificate_verification(true);
    cli.set_follow_location(true);

    auto res = cli.Get(path);
    if (!res) {
        set_err(std::string("api_definition.import_url: GET failed"));
        return false;
    }
    if (res->status < 200 || res->status >= 300) {
        set_err(std::string("api_definition.import_url: HTTP ") + std::to_string(res->status));
        return false;
    }
    out = res->body;
    return true;
}

}

bool initialize()
{
    return true;
}

void shutdown()
{
    auto& s = store();
    std::lock_guard<std::mutex> lk(s.mtx);
    s.items.clear();
}

api_format_t detect_format_from_path(const std::string& path)
{
    if (ends_with_ci(path, ".json"))    return api_format_t::openapi_json;
    if (ends_with_ci(path, ".yaml") || ends_with_ci(path, ".yml")) return api_format_t::openapi_yaml;
    if (ends_with_ci(path, ".har"))     return api_format_t::har;
    if (ends_with_ci(path, ".graphql") || ends_with_ci(path, ".gql")) return api_format_t::graphql_sdl;
    return api_format_t::auto_detect;
}

api_format_t detect_format_from_text(const std::string& text)
{
    return infer_format(text);
}

const char* format_label(api_format_t f)
{
    switch (f) {
        case api_format_t::auto_detect:   return "auto";
        case api_format_t::openapi_json:  return "openapi_json";
        case api_format_t::openapi_yaml:  return "openapi_yaml";
        case api_format_t::swagger_v2:    return "swagger_v2";
        case api_format_t::postman_v2_1:  return "postman_v2_1";
        case api_format_t::har:           return "har";
        case api_format_t::graphql_sdl:   return "graphql_sdl";
    }
    return "auto";
}

bool parse_format(const std::string& s, api_format_t& out)
{
    std::string l = to_lower(s);
    if (l == "auto" || l.empty())            { out = api_format_t::auto_detect; return true; }
    if (l == "openapi_json" || l == "openapi") { out = api_format_t::openapi_json; return true; }
    if (l == "openapi_yaml" || l == "yaml")   { out = api_format_t::openapi_yaml; return true; }
    if (l == "swagger" || l == "swagger_v2") { out = api_format_t::swagger_v2; return true; }
    if (l == "postman" || l == "postman_v2_1") { out = api_format_t::postman_v2_1; return true; }
    if (l == "har")                           { out = api_format_t::har; return true; }
    if (l == "graphql" || l == "graphql_sdl") { out = api_format_t::graphql_sdl; return true; }
    return false;
}

uint64_t import_from_file(const std::string& path, api_format_t hint)
{
    std::string text = read_file_utf8(path);
    if (text.empty()) {
        set_err("api_definition.import_from_file: empty or unreadable file");
        return 0;
    }
    if (hint == api_format_t::auto_detect) hint = detect_format_from_path(path);
    return import_text_with_format(text, hint, path);
}

uint64_t import_from_text(const std::string& text, api_format_t format)
{
    return import_text_with_format(text, format, std::string());
}

uint64_t import_from_url(const std::string& url)
{
    std::string body;
    if (!fetch_text_url(url, body)) return 0;
    api_format_t fmt = api_format_t::auto_detect;
    return import_text_with_format(body, fmt, url);
}

std::vector<api_collection_t> list_collections()
{
    auto& s = store();
    std::lock_guard<std::mutex> lk(s.mtx);
    return s.items;
}

bool get_collection(uint64_t id, api_collection_t& out)
{
    auto& s = store();
    std::lock_guard<std::mutex> lk(s.mtx);
    for (const auto& it : s.items) if (it.id == id) { out = it; return true; }
    return false;
}

bool remove_collection(uint64_t id)
{
    auto& s = store();
    std::lock_guard<std::mutex> lk(s.mtx);
    for (auto it = s.items.begin(); it != s.items.end(); ++it) {
        if (it->id == id) { s.items.erase(it); return true; }
    }
    return false;
}

size_t collection_count()
{
    auto& s = store();
    std::lock_guard<std::mutex> lk(s.mtx);
    return s.items.size();
}

void clear_all()
{
    auto& s = store();
    std::lock_guard<std::mutex> lk(s.mtx);
    s.items.clear();
}

std::vector<uint8_t> render_to_raw_request(const api_request_template_t& tpl,
                                            const std::map<std::string, std::string>& path_values,
                                            const std::map<std::string, std::string>& query_values,
                                            const std::map<std::string, std::string>& header_values,
                                            const std::string& body_override)
{
    std::string path = tpl.path;
    for (const auto& kv : tpl.path_params) {
        const std::string ph_brace = std::string("{") + kv.first + "}";
        const std::string ph_colon = std::string(":") + kv.first;
        std::string value;
        auto vit = path_values.find(kv.first);
        if (vit != path_values.end()) value = vit->second;
        else                          value = kv.second;
        if (value.empty()) value = kv.first;
        std::string encoded = url_encode_component(value);
        size_t pos = 0;
        while ((pos = path.find(ph_brace, pos)) != std::string::npos) {
            path.replace(pos, ph_brace.size(), encoded);
            pos += encoded.size();
        }
        pos = 0;
        while ((pos = path.find(ph_colon, pos)) != std::string::npos) {
            size_t end = pos + ph_colon.size();
            if (end >= path.size() || path[end] == '/' || path[end] == '?' || path[end] == '#') {
                path.replace(pos, ph_colon.size(), encoded);
                pos += encoded.size();
            } else {
                pos = end;
            }
        }
    }

    std::string query;
    auto emit_query = [&](const std::string& k, const std::string& v) {
        if (!query.empty()) query += "&";
        query += url_encode_component(k) + "=" + url_encode_component(v);
    };
    for (const auto& kv : tpl.query_params) {
        auto vit = query_values.find(kv.first);
        std::string val = (vit != query_values.end()) ? vit->second : kv.second;
        emit_query(kv.first, val);
    }
    for (const auto& over : query_values) {
        bool exists = false;
        for (const auto& kv : tpl.query_params) if (kv.first == over.first) { exists = true; break; }
        if (!exists) emit_query(over.first, over.second);
    }

    std::string full_path = path;
    if (!query.empty()) {
        if (full_path.find('?') == std::string::npos) full_path += "?";
        else                                            full_path += "&";
        full_path += query;
    }
    if (full_path.empty()) full_path = "/";

    std::string host_from_base;
    {
        std::string sc, h, p; uint16_t pt = 0;
        if (!tpl.base_url.empty() && parse_url_components(tpl.base_url, sc, h, pt, p)) host_from_base = h;
    }

    std::string request_line = tpl.method + " " + full_path + " HTTP/1.1\r\n";

    std::vector<std::pair<std::string, std::string>> hdrs;
    for (const auto& h : tpl.headers) hdrs.push_back(h);

    auto override_header = [&](const std::string& name, const std::string& val) {
        for (auto& h : hdrs) {
            if (to_lower(h.first) == to_lower(name)) { h.second = val; return; }
        }
        hdrs.emplace_back(name, val);
    };

    for (const auto& over : header_values) override_header(over.first, over.second);

    bool has_host = false;
    for (const auto& h : hdrs) if (to_lower(h.first) == "host") { has_host = true; break; }
    if (!has_host && !host_from_base.empty()) hdrs.emplace_back("Host", host_from_base);

    std::string body = body_override.empty() ? tpl.body_template : body_override;

    bool has_cl = false;
    for (const auto& h : hdrs) if (to_lower(h.first) == "content-length") { has_cl = true; break; }
    if (!has_cl && !body.empty()) hdrs.emplace_back("Content-Length", std::to_string(body.size()));

    bool has_cn = false;
    for (const auto& h : hdrs) if (to_lower(h.first) == "connection") { has_cn = true; break; }
    if (!has_cn) hdrs.emplace_back("Connection", std::string("close"));

    std::string out = request_line;
    for (const auto& h : hdrs) out += h.first + ": " + h.second + "\r\n";
    out += "\r\n";
    out += body;

    return std::vector<uint8_t>(out.begin(), out.end());
}

bool audit_entire_collection(uint64_t collection_id,
                              const std::map<std::string, std::string>& auth_values,
                              audit_result_t& out)
{
    api_collection_t col;
    if (!get_collection(collection_id, col)) {
        set_err("audit_entire_collection: collection not found");
        return false;
    }

    out = audit_result_t{};
    out.audit_id = now_ms();
    out.status   = "started";

    audit_http::send_options_t opts;
    opts.timeout_ms       = 15000;
    opts.follow_redirects = false;
    opts.enforce_scope    = true;

    for (const auto& tpl : col.requests) {
        std::string scheme, host, path; uint16_t port = 0;
        if (!parse_url_components(tpl.base_url, scheme, host, port, path)) {
            out.requests_failed++;
            continue;
        }
        bool tls = (scheme == "https");
        std::map<std::string, std::string> hdrs;
        for (const auto& a : auth_values) {
            if (a.first == "bearer")          hdrs["Authorization"] = std::string("Bearer ") + a.second;
            else if (a.first == "basic")      hdrs["Authorization"] = std::string("Basic ")  + a.second;
            else if (a.first == "api_key")    hdrs["X-API-Key"]     = a.second;
            else                                hdrs[a.first]         = a.second;
        }
        auto raw = render_to_raw_request(tpl, {}, {}, hdrs, std::string());
        auto resp = audit_http::send(raw, host, port, tls, opts);
        if (resp.has_value()) {
            out.requests_sent++;
            aida::events::publish(kExchangeObservedEvent, *resp);

            issue_t iss;
            iss.audit_id        = out.audit_id;
            iss.host            = resp->host;
            iss.port            = resp->port;
            iss.scheme          = resp->scheme;
            iss.path            = resp->path;
            iss.src_exchange_id = resp->id;
            iss.type_key        = "api.audit.recorded";
            iss.name            = "API request recorded by audit";
            iss.severity        = severity_t::info;
            iss.confidence      = confidence_t::firm;
            iss.description     = std::string("Recorded API call ") + tpl.method + " " + tpl.path;
            evidence_t e;
            e.request_raw  = std::string(reinterpret_cast<const char*>(raw.data()), raw.size());
            std::string resp_text;
            resp_text += "HTTP/1.1 " + std::to_string(resp->status_code) + " " + resp->reason_phrase + "\r\n";
            for (const auto& h : resp->resp_headers) resp_text += h.first + ": " + h.second + "\r\n";
            resp_text += "\r\n";
            resp_text.append(reinterpret_cast<const char*>(resp->resp_body.data()), resp->resp_body.size());
            e.response_raw = resp_text;
            iss.evidence.push_back(std::move(e));
            issue_store::add(std::move(iss));
            out.issues_raised++;
        } else {
            out.requests_failed++;
        }
    }

    out.status = "completed";
    diag::log_tagged_fmt("burp.api", "audit_entire_collection collection_id=%llu sent=%zu failed=%zu issues=%zu",
        static_cast<unsigned long long>(collection_id),
        out.requests_sent, out.requests_failed, out.issues_raised);
    return true;
}

nlohmann::json template_to_json(const api_request_template_t& t)
{
    nlohmann::json j;
    j["id"]            = t.id;
    j["method"]        = t.method;
    j["base_url"]      = t.base_url;
    j["path"]          = t.path;
    j["body_template"] = t.body_template;
    j["auth_kind"]     = t.auth_kind;
    j["summary"]       = t.summary;
    j["description"]   = t.description;
    nlohmann::json hdrs = nlohmann::json::array();
    for (const auto& h : t.headers) hdrs.push_back(nlohmann::json{{"name", h.first}, {"value", h.second}});
    j["headers"] = std::move(hdrs);
    nlohmann::json pp = nlohmann::json::array();
    for (const auto& p : t.path_params) pp.push_back(nlohmann::json{{"name", p.first}, {"example", p.second}});
    j["path_params"] = std::move(pp);
    nlohmann::json qp = nlohmann::json::array();
    for (const auto& p : t.query_params) qp.push_back(nlohmann::json{{"name", p.first}, {"example", p.second}});
    j["query_params"] = std::move(qp);
    nlohmann::json bp = nlohmann::json::array();
    for (const auto& p : t.body_params) bp.push_back(nlohmann::json{{"name", p.first}, {"example", p.second}});
    j["body_params"] = std::move(bp);
    nlohmann::json tags = nlohmann::json::array();
    for (const auto& t2 : t.tags) tags.push_back(t2);
    j["tags"] = std::move(tags);
    return j;
}

nlohmann::json collection_to_json(const api_collection_t& c)
{
    nlohmann::json j;
    j["id"]          = c.id;
    j["name"]        = c.name;
    j["format"]      = format_label(c.format);
    j["source_path"] = c.source_path;
    j["base_url"]    = c.base_url;
    j["imported_ms"] = c.imported_ms;
    nlohmann::json reqs = nlohmann::json::array();
    for (const auto& r : c.requests) reqs.push_back(template_to_json(r));
    j["requests"] = std::move(reqs);
    return j;
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    return err_slot();
}

}
}
}
