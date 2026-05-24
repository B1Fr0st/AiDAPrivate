#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_api_mcp.hpp"
#include "api_definition.hpp"
#include "audit_http.hpp"
#include "graphql.hpp"
#include "ws_editor.hpp"
#include "burp_logger.hpp"
#include "report_generator.hpp"
#include "issue.hpp"

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace api_mcp {

namespace {

using tool_result_t = mcp_standalone::tool_result_t;
using json = nlohmann::json;

struct url_log_t
{
    std::string host;
    std::string path;
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
        out.host = host;
        size_t q = path.find('?');
        size_t f = path.find('#');
        out.has_query = q != std::string::npos;
        size_t path_end = path.size();
        if (q != std::string::npos) path_end = q;
        if (f != std::string::npos && f < path_end) path_end = f;
        out.path = path.substr(0, path_end);
    }
    else
    {
        size_t cursor = 0;
        size_t scheme_pos = url.find("://");
        if (scheme_pos != std::string::npos) cursor = scheme_pos + 3;
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

std::map<std::string, std::string> json_obj_to_map(const json& j)
{
    std::map<std::string, std::string> out;
    if (!j.is_object()) return out;
    for (auto it = j.begin(); it != j.end(); ++it) {
        if (it.value().is_string()) out[it.key()] = it.value().get<std::string>();
        else                          out[it.key()] = it.value().dump();
    }
    return out;
}

std::vector<uint8_t> base64_decode(const std::string& s)
{
    static const int8_t table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
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
    std::vector<uint8_t> out;
    out.reserve((s.size() / 4) * 3);
    uint32_t val = 0;
    int bits = 0;
    for (unsigned char c : s) {
        if (c == '=') break;
        int8_t v = table[c];
        if (v < 0) continue;
        val = (val << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
        }
    }
    return out;
}

std::string base64_encode_bytes(const uint8_t* data, size_t len)
{
    static const char* alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t a = data[i];
        uint32_t b = (i + 1 < len) ? data[i + 1] : 0;
        uint32_t c = (i + 2 < len) ? data[i + 2] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out.push_back(alpha[(triple >> 18) & 0x3F]);
        out.push_back(alpha[(triple >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? alpha[(triple >> 6) & 0x3F] : '=');
        out.push_back((i + 2 < len) ? alpha[triple & 0x3F]        : '=');
    }
    return out;
}

tool_result_t tool_api_import(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "api_import format=%s source_len=%zu", params.value("format", std::string("auto")).c_str(), params.value("source", std::string()).size());
    if (!params.is_object())
    {
        diag::log_tagged_fmt("mcp_burp", "api_import invalid_params");
        return tool_result_t::error("invalid params");
    }
    std::string format = params.value("format", std::string("auto"));
    std::string source = params.value("source", std::string());
    if (source.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "api_import missing_source");
        return tool_result_t::error("source is required");
    }
    api_definition::api_format_t fmt = api_definition::api_format_t::auto_detect;
    api_definition::parse_format(format, fmt);

    uint64_t id = 0;
    if (source.rfind("text:", 0) == 0) {
        diag::log_tagged_fmt("mcp_burp", "api_import from_text format=%s", format.c_str());
        id = api_definition::import_from_text(source.substr(5), fmt);
    } else if (source.rfind("url:", 0) == 0) {
        diag::log_tagged_fmt("mcp_burp", "api_import from_url url=%s", source.substr(4).c_str());
        id = api_definition::import_from_url(source.substr(4));
    } else if (source.rfind("http://", 0) == 0 || source.rfind("https://", 0) == 0) {
        diag::log_tagged_fmt("mcp_burp", "api_import from_url url=%s", source.c_str());
        id = api_definition::import_from_url(source);
    } else {
        diag::log_tagged_fmt("mcp_burp", "api_import from_file path=%s", source.c_str());
        id = api_definition::import_from_file(source, fmt);
    }
    if (id == 0)
    {
        diag::log_tagged_fmt("mcp_burp", "api_import failed err=%s", api_definition::last_error().c_str());
        return tool_result_t::error(api_definition::last_error());
    }

    diag::log_tagged_fmt("mcp_burp", "api_import ok collection_id=%llu", static_cast<unsigned long long>(id));
    json out;
    api_definition::api_collection_t col;
    if (api_definition::get_collection(id, col)) out = api_definition::collection_to_json(col);
    else                                          out["collection_id"] = id;
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_api_list(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "api_list entry");
    auto cols = api_definition::list_collections();
    json arr = json::array();
    for (const auto& c : cols) arr.push_back(api_definition::collection_to_json(c));
    diag::log_tagged_fmt("mcp_burp", "api_list ok count=%zu", cols.size());
    json out;
    out["count"]       = arr.size();
    out["collections"] = std::move(arr);
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_api_get(const json& params)
{
    uint64_t id = params.value("collection_id", 0ull);
    diag::log_tagged_fmt("mcp_burp", "api_get collection_id=%llu", static_cast<unsigned long long>(id));
    api_definition::api_collection_t col;
    if (!api_definition::get_collection(id, col))
    {
        diag::log_tagged_fmt("mcp_burp", "api_get not_found id=%llu", static_cast<unsigned long long>(id));
        return tool_result_t::error("collection not found");
    }
    diag::log_tagged_fmt("mcp_burp", "api_get ok id=%llu", static_cast<unsigned long long>(id));
    json j = api_definition::collection_to_json(col);
    return tool_result_t::ok(j.dump(2), j);
}

tool_result_t tool_api_remove(const json& params)
{
    uint64_t id = params.value("collection_id", 0ull);
    diag::log_tagged_fmt("mcp_burp", "api_remove collection_id=%llu", static_cast<unsigned long long>(id));
    bool ok = api_definition::remove_collection(id);
    if (!ok)
    {
        diag::log_tagged_fmt("mcp_burp", "api_remove not_found id=%llu", static_cast<unsigned long long>(id));
        return tool_result_t::error("collection not found");
    }
    diag::log_tagged_fmt("mcp_burp", "api_remove ok id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("removed");
}

tool_result_t tool_api_send(const json& params)
{
    uint64_t cid = params.value("collection_id", 0ull);
    std::string rid = params.value("request_id", std::string());
    diag::log_tagged_fmt("mcp_burp", "api_send collection_id=%llu request_id=%s", static_cast<unsigned long long>(cid), rid.c_str());
    api_definition::api_collection_t col;
    if (!api_definition::get_collection(cid, col))
    {
        diag::log_tagged_fmt("mcp_burp", "api_send collection_not_found id=%llu", static_cast<unsigned long long>(cid));
        return tool_result_t::error("collection not found");
    }
    const api_definition::api_request_template_t* tpl = nullptr;
    for (const auto& r : col.requests) if (r.id == rid) { tpl = &r; break; }
    if (!tpl)
    {
        diag::log_tagged_fmt("mcp_burp", "api_send request_not_found rid=%s", rid.c_str());
        return tool_result_t::error("request not found");
    }

    auto pv = json_obj_to_map(params.value("path_values", json::object()));
    auto qv = json_obj_to_map(params.value("query_values", json::object()));
    auto hv = json_obj_to_map(params.value("header_values", json::object()));
    std::string body = params.value("body_override", std::string());

    auto raw = api_definition::render_to_raw_request(*tpl, pv, qv, hv, body);

    std::string scheme, host, path; uint16_t port = 0;
    if (!audit_http::parse_url(tpl->base_url, scheme, host, port, path))
    {
        diag::log_tagged_fmt("mcp_burp", "api_send url_parse_failed url=%s", tpl->base_url.c_str());
        return tool_result_t::error("base_url parse failed");
    }
    bool tls = (scheme == "https");
    diag::log_tagged_fmt("mcp_burp", "api_send sending host=%s port=%d tls=%d", host.c_str(), (int)port, (int)tls);

    audit_http::send_options_t opts;
    opts.timeout_ms = 20000;
    opts.enforce_scope = params.value("enforce_scope", false);
    auto ex = audit_http::send(raw, host, port, tls, opts);
    if (!ex.has_value())
    {
        std::string err = audit_http::last_error();
        diag::log_tagged_fmt("mcp_burp", "api_send send_failed err=%s", err.c_str());
        return tool_result_t::error(err);
    }

    burp::logger::record(burp::logger::source_t::api, *ex);
    diag::log_tagged_fmt("mcp_burp", "api_send ok status=%d latency_ms=%lld host=%s", ex->status_code, static_cast<long long>(ex->latency_ms), host.c_str());

    json out;
    out["id"]          = ex->id;
    out["status"]      = ex->status_code;
    out["latency_ms"]  = ex->latency_ms;
    out["host"]        = ex->host;
    out["path"]        = ex->path;
    out["response_bytes"] = ex->resp_body.size();
    json hdrs = json::array();
    for (const auto& h : ex->resp_headers) hdrs.push_back(json{{"name", h.first}, {"value", h.second}});
    out["response_headers"] = std::move(hdrs);
    out["response_body_preview"] = std::string(
        reinterpret_cast<const char*>(ex->resp_body.data()),
        std::min<size_t>(ex->resp_body.size(), 8192));
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_api_audit(const json& params)
{
    uint64_t cid = params.value("collection_id", 0ull);
    diag::log_tagged_fmt("mcp_burp", "api_audit collection_id=%llu", static_cast<unsigned long long>(cid));
    auto auth = json_obj_to_map(params.value("auth_values", json::object()));
    api_definition::audit_result_t res;
    bool ok = api_definition::audit_entire_collection(cid, auth, res);
    if (!ok)
    {
        diag::log_tagged_fmt("mcp_burp", "api_audit failed err=%s", api_definition::last_error().c_str());
        return tool_result_t::error(api_definition::last_error());
    }
    diag::log_tagged_fmt("mcp_burp", "api_audit ok audit_id=%llu requests_sent=%zu issues=%zu", static_cast<unsigned long long>(res.audit_id), res.requests_sent, res.issues_raised);
    json out;
    out["audit_id"]        = res.audit_id;
    out["requests_sent"]   = res.requests_sent;
    out["requests_failed"] = res.requests_failed;
    out["issues_raised"]   = res.issues_raised;
    out["status"]          = res.status;
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_gql_introspect(const json& params)
{
    std::string ep = params.value("endpoint", std::string());
    const url_log_t endpoint_log = summarize_url_for_log(ep);
    diag::log_tagged_fmt("mcp_burp", "gql_introspect host=%s path=%s query=%d endpoint_len=%zu params_keys=%zu",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), (int)endpoint_log.has_query, endpoint_log.length,
        params.is_object() ? params.size() : 0);
    if (ep.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "gql_introspect missing_endpoint");
        return tool_result_t::error("endpoint required");
    }
    auto hdrs = json_obj_to_map(params.value("headers", json::object()));
    graphql::gql_schema_t sch;
    std::string raw;
    if (!graphql::introspect(ep, hdrs, sch, raw))
    {
        std::string err = graphql::last_error();
        diag::log_tagged_fmt("mcp_burp", "gql_introspect failed err=%s", err.c_str());
        return tool_result_t::error(err);
    }
    diag::log_tagged_fmt("mcp_burp", "gql_introspect ok host=%s path=%s raw_len=%zu types=%zu",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), raw.size(), sch.types.size());
    json j = graphql::schema_to_json(sch);
    return tool_result_t::ok(j.dump(2), j);
}

tool_result_t tool_gql_example(const json& params)
{
    std::string ep    = params.value("endpoint", std::string());
    std::string field = params.value("field_name", std::string());
    int depth         = params.value("depth", 2);
    const url_log_t endpoint_log = summarize_url_for_log(ep);
    diag::log_tagged_fmt("mcp_burp", "gql_example host=%s path=%s query=%d endpoint_len=%zu field=%s depth=%d",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), (int)endpoint_log.has_query, endpoint_log.length,
        field.c_str(), depth);
    if (field.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "gql_example missing_field_name");
        return tool_result_t::error("field_name required");
    }
    graphql::gql_schema_t sch;
    if (!graphql::get_cached_schema(ep, sch)) {
        diag::log_tagged_fmt("mcp_burp", "gql_example no_cached_schema introspecting host=%s path=%s",
            endpoint_log.host.c_str(), endpoint_log.path.c_str());
        std::string raw;
        if (!graphql::introspect(ep, {}, sch, raw))
        {
            std::string err = graphql::last_error();
            diag::log_tagged_fmt("mcp_burp", "gql_example introspect_failed err=%s", err.c_str());
            return tool_result_t::error(err);
        }
    }
    std::string q = graphql::build_example_query(sch, field, depth);
    diag::log_tagged_fmt("mcp_burp", "gql_example ok field=%s query_len=%zu", field.c_str(), q.size());
    json out;
    out["query"] = q;
    return tool_result_t::ok(q, out);
}

tool_result_t tool_gql_send(const json& params)
{
    std::string ep = params.value("endpoint", std::string());
    const url_log_t endpoint_log = summarize_url_for_log(ep);
    diag::log_tagged_fmt("mcp_burp", "gql_send host=%s path=%s query=%d endpoint_len=%zu params_keys=%zu",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), (int)endpoint_log.has_query, endpoint_log.length,
        params.is_object() ? params.size() : 0);
    if (ep.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "gql_send missing_endpoint");
        return tool_result_t::error("endpoint required");
    }
    auto hdrs = json_obj_to_map(params.value("headers", json::object()));
    std::string q = params.value("query", std::string());
    if (q.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "gql_send missing_query");
        return tool_result_t::error("query required");
    }
    json variables = params.value("variables", json::object());

    nlohmann::json resp;
    std::string raw;
    if (!graphql::send_query(ep, hdrs, q, variables, resp, raw))
    {
        std::string err = graphql::last_error();
        diag::log_tagged_fmt("mcp_burp", "gql_send failed err=%s", err.c_str());
        return tool_result_t::error(err);
    }
    diag::log_tagged_fmt("mcp_burp", "gql_send ok host=%s path=%s raw_len=%zu response_type=%s",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), raw.size(), resp.type_name());
    return tool_result_t::ok(resp.dump(2), resp);
}

tool_result_t tool_ws_connect(const json& params)
{
    ws_editor::ws_connection_config_t cfg;
    cfg.scheme = params.value("scheme", std::string("wss"));
    cfg.host   = params.value("host", std::string());
    cfg.port   = static_cast<uint16_t>(params.value("port", 443));
    cfg.path   = params.value("path", std::string("/"));
    cfg.origin = params.value("origin", std::string());
    cfg.subprotocol = params.value("subprotocol", std::string());
    cfg.verify_tls = params.value("verify_tls", true);
    diag::log_tagged_fmt("mcp_burp", "ws_connect scheme=%s host=%s port=%d path=%s", cfg.scheme.c_str(), cfg.host.c_str(), (int)cfg.port, cfg.path.c_str());
    if (params.contains("headers") && params["headers"].is_object()) {
        for (auto it = params["headers"].begin(); it != params["headers"].end(); ++it) {
            cfg.headers.emplace_back(it.key(),
                it.value().is_string() ? it.value().get<std::string>() : it.value().dump());
        }
    }
    uint64_t id = ws_editor::connect(cfg);
    if (id == 0)
    {
        std::string err = ws_editor::last_error();
        diag::log_tagged_fmt("mcp_burp", "ws_connect failed err=%s", err.c_str());
        return tool_result_t::error(err);
    }
    diag::log_tagged_fmt("mcp_burp", "ws_connect ok conn_id=%llu", static_cast<unsigned long long>(id));
    json out;
    out["conn_id"] = id;
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_ws_disconnect(const json& params)
{
    uint64_t id = params.value("conn_id", 0ull);
    diag::log_tagged_fmt("mcp_burp", "ws_disconnect conn_id=%llu", static_cast<unsigned long long>(id));
    if (!ws_editor::disconnect(id))
    {
        std::string err = ws_editor::last_error();
        diag::log_tagged_fmt("mcp_burp", "ws_disconnect failed err=%s", err.c_str());
        return tool_result_t::error(err);
    }
    diag::log_tagged_fmt("mcp_burp", "ws_disconnect ok conn_id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("disconnected");
}

tool_result_t tool_ws_send_text(const json& params)
{
    uint64_t id = params.value("conn_id", 0ull);
    std::string msg = params.value("msg", std::string());
    diag::log_tagged_fmt("mcp_burp", "ws_send_text conn_id=%llu msg_len=%zu", static_cast<unsigned long long>(id), msg.size());
    if (!ws_editor::send_text(id, msg))
    {
        std::string err = ws_editor::last_error();
        diag::log_tagged_fmt("mcp_burp", "ws_send_text failed err=%s", err.c_str());
        return tool_result_t::error(err);
    }
    diag::log_tagged_fmt("mcp_burp", "ws_send_text ok conn_id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("sent");
}

tool_result_t tool_ws_send_binary(const json& params)
{
    uint64_t id = params.value("conn_id", 0ull);
    std::string b64 = params.value("data_b64", std::string());
    diag::log_tagged_fmt("mcp_burp", "ws_send_binary conn_id=%llu b64_len=%zu", static_cast<unsigned long long>(id), b64.size());
    auto bin = base64_decode(b64);
    if (!ws_editor::send_binary(id, bin))
    {
        std::string err = ws_editor::last_error();
        diag::log_tagged_fmt("mcp_burp", "ws_send_binary failed err=%s", err.c_str());
        return tool_result_t::error(err);
    }
    diag::log_tagged_fmt("mcp_burp", "ws_send_binary ok conn_id=%llu bytes=%zu", static_cast<unsigned long long>(id), bin.size());
    return tool_result_t::ok("sent");
}

tool_result_t tool_ws_send_raw(const json& params)
{
    uint64_t id = params.value("conn_id", 0ull);
    int opcode = params.value("opcode", 1);
    bool fin = params.value("fin", true);
    bool masked = params.value("masked", true);
    std::string b64 = params.value("payload_b64", std::string());
    diag::log_tagged_fmt("mcp_burp", "ws_send_raw conn_id=%llu opcode=%d fin=%d masked=%d", static_cast<unsigned long long>(id), opcode, (int)fin, (int)masked);
    auto bin = base64_decode(b64);
    if (!ws_editor::send_raw_frame(id, static_cast<uint8_t>(opcode), fin, masked, bin))
    {
        std::string err = ws_editor::last_error();
        diag::log_tagged_fmt("mcp_burp", "ws_send_raw failed err=%s", err.c_str());
        return tool_result_t::error(err);
    }
    diag::log_tagged_fmt("mcp_burp", "ws_send_raw ok conn_id=%llu bytes=%zu", static_cast<unsigned long long>(id), bin.size());
    return tool_result_t::ok("sent");
}

tool_result_t tool_ws_list(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "ws_list entry");
    auto items = ws_editor::list_connections();
    json arr = json::array();
    for (const auto& s : items) {
        json j;
        j["id"]              = s.id;
        j["url"]             = s.url;
        j["connected"]       = s.connected;
        j["frames_sent"]     = s.frames_sent;
        j["frames_received"] = s.frames_received;
        j["opened_ms"]       = s.opened_ms;
        j["last_error"]      = s.last_error;
        arr.push_back(std::move(j));
    }
    diag::log_tagged_fmt("mcp_burp", "ws_list ok count=%zu", items.size());
    json out;
    out["count"] = arr.size();
    out["connections"] = std::move(arr);
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_ws_frames(const json& params)
{
    uint64_t id = params.value("conn_id", 0ull);
    size_t start = params.value("start", 0u);
    size_t maxv  = params.value("max", 256u);
    diag::log_tagged_fmt("mcp_burp", "ws_frames conn_id=%llu start=%zu max=%zu", static_cast<unsigned long long>(id), start, maxv);
    ws_editor::ws_status_t st;
    if (!ws_editor::get_status(id, st))
    {
        std::string err = "ws_editor.frames: not found";
        diag::log_tagged_fmt("mcp_burp", "ws_frames failed conn_id=%llu err=%s", static_cast<unsigned long long>(id), err.c_str());
        return tool_result_t::error(err);
    }
    auto rows = ws_editor::frames(id, start, maxv);
    json arr = json::array();
    for (const auto& f : rows) {
        json j;
        j["ts_ms"]   = f.ts_ms;
        j["outbound"] = f.outbound;
        j["opcode"]  = f.opcode;
        j["preview"] = f.preview;
        j["payload_b64"] = base64_encode_bytes(f.payload.data(), f.payload.size());
        arr.push_back(std::move(j));
    }
    diag::log_tagged_fmt("mcp_burp", "ws_frames ok conn_id=%llu frames=%zu", static_cast<unsigned long long>(id), rows.size());
    json out;
    out["count"]  = arr.size();
    out["frames"] = std::move(arr);
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_ws_clear(const json& params)
{
    uint64_t id = params.value("conn_id", 0ull);
    diag::log_tagged_fmt("mcp_burp", "ws_clear conn_id=%llu", static_cast<unsigned long long>(id));
    ws_editor::ws_status_t st;
    if (!ws_editor::get_status(id, st))
    {
        std::string err = "ws_editor.clear_frames: not found";
        diag::log_tagged_fmt("mcp_burp", "ws_clear failed conn_id=%llu err=%s", static_cast<unsigned long long>(id), err.c_str());
        return tool_result_t::error(err);
    }
    ws_editor::clear_frames(id);
    diag::log_tagged_fmt("mcp_burp", "ws_clear ok conn_id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("cleared");
}

tool_result_t tool_logger_query(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "logger_query entry");
    logger::log_filter_t f;
    if (params.contains("filter") && params["filter"].is_object()) {
        const auto& fp = params["filter"];
        f.method     = fp.value("method", std::string());
        f.host_regex = fp.value("host_regex", std::string());
        f.url_regex  = fp.value("url_regex", std::string());
        f.status_min = fp.value("status_min", 0);
        f.status_max = fp.value("status_max", 1000);
        f.source     = fp.value("source", std::string());
        f.mime_type  = fp.value("mime_type", std::string());
        f.time_from_ms = fp.value("time_from_ms", 0ull);
        f.time_to_ms   = fp.value("time_to_ms", 0ull);
    } else {
        f.method     = params.value("method", std::string());
        f.host_regex = params.value("host_regex", std::string());
        f.url_regex  = params.value("url_regex", std::string());
        f.status_min = params.value("status_min", 0);
        f.status_max = params.value("status_max", 1000);
        f.source     = params.value("source", std::string());
        f.mime_type  = params.value("mime_type", std::string());
    }
    size_t limit = params.value("limit", 100u);
    diag::log_tagged_fmt("mcp_burp", "logger_query host_regex=%s url_regex=%s limit=%zu", f.host_regex.c_str(), f.url_regex.c_str(), limit);
    auto rows = logger::query(f, limit);
    json arr = json::array();
    for (const auto& r : rows) {
        json j;
        j["id"]              = r.id;
        j["ts_ms"]           = r.ts_ms;
        j["method"]          = r.method;
        j["url"]             = r.url;
        j["host"]            = r.host;
        j["port"]            = r.port;
        j["status"]          = r.status;
        j["request_length"]  = r.request_length;
        j["response_length"] = r.response_length;
        j["latency_ms"]      = r.latency_ms;
        j["mime_type"]       = r.mime_type;
        j["source"]          = logger::source_label(r.source);
        j["exchange_id"]     = r.exchange_id;
        arr.push_back(std::move(j));
    }
    diag::log_tagged_fmt("mcp_burp", "logger_query ok rows=%zu", rows.size());
    json out;
    out["count"] = arr.size();
    out["rows"]  = std::move(arr);
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_logger_total(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "logger_total entry");
    const size_t total = logger::total_rows();
    const size_t cap = logger::capacity();
    diag::log_tagged_fmt("mcp_burp", "logger_total ok total=%zu capacity=%zu", total, cap);
    json out;
    out["total"] = total;
    out["capacity"] = cap;
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_logger_clear(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "logger_clear entry");
    logger::clear();
    diag::log_tagged_fmt("mcp_burp", "logger_clear ok");
    return tool_result_t::ok("cleared");
}

tool_result_t tool_logger_export_csv(const json& params)
{
    std::string path = params.value("path", std::string());
    diag::log_tagged_fmt("mcp_burp", "logger_export_csv path=%s", path.c_str());
    logger::log_filter_t f;
    if (params.contains("filter") && params["filter"].is_object()) {
        const auto& fp = params["filter"];
        f.method     = fp.value("method", std::string());
        f.host_regex = fp.value("host_regex", std::string());
        f.url_regex  = fp.value("url_regex", std::string());
        f.status_min = fp.value("status_min", 0);
        f.status_max = fp.value("status_max", 1000);
        f.source     = fp.value("source", std::string());
        f.mime_type  = fp.value("mime_type", std::string());
    }
    if (!logger::export_csv(path, f))
    {
        diag::log_tagged_fmt("mcp_burp", "logger_export_csv failed err=%s", logger::last_error().c_str());
        return tool_result_t::error(logger::last_error());
    }
    diag::log_tagged_fmt("mcp_burp", "logger_export_csv ok path=%s", path.c_str());
    json out;
    out["path"] = path;
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_report_generate(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "report_generate format=%s output=%s", params.value("format", std::string("html")).c_str(), params.value("output_path", std::string()).c_str());
    report::report_config_t cfg;
    cfg.title         = params.value("title", std::string());
    cfg.client        = params.value("client", std::string());
    cfg.scope_summary = params.value("scope_summary", std::string());
    cfg.output_path   = params.value("output_path", std::string());
    cfg.include_evidence    = params.value("include_evidence", true);
    cfg.include_remediation = params.value("include_remediation", true);
    std::string fmt_s = params.value("format", std::string("html"));
    report::parse_format(fmt_s, cfg.format);
    if (params.contains("include_issue_ids") && params["include_issue_ids"].is_array()) {
        for (const auto& v : params["include_issue_ids"])
            if (v.is_number_unsigned()) cfg.include_issue_ids.push_back(v.get<uint64_t>());
    }
    std::string out;
    if (!report::generate(cfg, out))
    {
        diag::log_tagged_fmt("mcp_burp", "report_generate failed err=%s", out.c_str());
        return tool_result_t::error(out);
    }
    diag::log_tagged_fmt("mcp_burp", "report_generate ok path=%s format=%s", out.c_str(), fmt_s.c_str());
    json j;
    j["output_path"] = out;
    j["format"]      = report::format_label(cfg.format);
    return tool_result_t::ok(out, j);
}

}

void register_api_tools(mcp_standalone::server_t& srv)
{
    using p = mcp_standalone::tool_param_t;

    srv.register_tool({
        "burp_api_import",
        "Import an API definition (OpenAPI/Swagger/Postman/HAR/GraphQL SDL). "
        "source may be a local file path, an http(s) URL, or 'text:<inline>' to import literal content.",
        {
            {"format", "string", "Format hint: auto|openapi_json|openapi_yaml|swagger_v2|postman_v2_1|har|graphql_sdl.", false},
            {"source", "string", "File path, URL, or 'text:' prefix for inline content.", true},
        },
        false, tool_api_import,
        mcp_standalone::tool_visibility_t::external_visible
    });

    srv.register_tool({
        "burp_api_list_collections",
        "List all imported API collections, with their parsed request templates.",
        {}, true, tool_api_list
    });

    srv.register_tool({
        "burp_api_get_collection",
        "Return a single API collection (with all request templates) by id.",
        { {"collection_id", "number", "Collection id.", true} },
        true, tool_api_get
    });

    srv.register_tool({
        "burp_api_remove_collection",
        "Remove an imported API collection by id.",
        { {"collection_id", "number", "Collection id.", true} },
        false, tool_api_remove
    });

    srv.register_tool({
        "burp_api_send_request",
        "Render an API request template, substitute path/query/header overrides, send it, and "
        "return the response (also logged into burp_logger as source=api).",
        {
            {"collection_id", "number", "Collection id.", true},
            {"request_id",    "string", "Request template id (operationId / Postman item name).", true},
            {"path_values",   "object", "Map of path parameter overrides.", false},
            {"query_values",  "object", "Map of query parameter overrides.", false},
            {"header_values", "object", "Map of header overrides.", false},
            {"body_override", "string", "Replace the template body with this raw text.", false},
            {"enforce_scope", "boolean", "If true, the call must pass scope checks (default false).", false},
        },
        false, tool_api_send
    });

    srv.register_tool({
        "burp_api_audit_collection",
        "Send every request in the collection through audit_http (issues are raised into issue_store).",
        {
            {"collection_id", "number", "Collection id.", true},
            {"auth_values",   "object", "Map: bearer|basic|api_key|<header_name> -> value.", false},
        },
        false, tool_api_audit
    });

    srv.register_tool({
        "burp_graphql_introspect",
        "Run a standard introspection query against a GraphQL endpoint and parse the schema.",
        {
            {"endpoint", "string", "GraphQL endpoint URL.", true},
            {"headers",  "object", "Extra headers (auth, cookies).", false},
        },
        false, tool_gql_introspect
    });

    srv.register_tool({
        "burp_graphql_example",
        "Build an example query selecting nested fields up to the given depth. Uses the cached schema.",
        {
            {"endpoint",   "string", "GraphQL endpoint URL.", true},
            {"field_name", "string", "Top-level Query field name.", true},
            {"depth",      "number", "Expansion depth (1..5).", false},
        },
        true, tool_gql_example
    });

    srv.register_tool({
        "burp_graphql_send",
        "Send a GraphQL query/mutation to the endpoint and return the parsed JSON response.",
        {
            {"endpoint",  "string", "GraphQL endpoint URL.", true},
            {"headers",   "object", "Extra headers.", false},
            {"query",     "string", "Query / mutation text.", true},
            {"variables", "object", "Variables JSON object.", false},
        },
        false, tool_gql_send
    });

    srv.register_tool({
        "burp_ws_connect",
        "Open a WebSocket (ws:// or wss://) connection and return its connection id.",
        {
            {"scheme",      "string",  "'ws' or 'wss'.", true},
            {"host",        "string",  "Server host.", true},
            {"port",        "number",  "Server port.", true},
            {"path",        "string",  "WebSocket path (default '/').", false},
            {"headers",     "object",  "Extra request headers for the upgrade.", false},
            {"origin",      "string",  "Origin header.", false},
            {"subprotocol", "string",  "Sec-WebSocket-Protocol header.", false},
            {"verify_tls",  "boolean", "Verify server certificate (wss).", false},
        },
        false, tool_ws_connect
    });

    srv.register_tool({
        "burp_ws_disconnect",
        "Close an open WebSocket connection.",
        { {"conn_id", "number", "Connection id from burp_ws_connect.", true} },
        false, tool_ws_disconnect
    });

    srv.register_tool({
        "burp_ws_send_text",
        "Send a text frame on a WebSocket connection (masked client-to-server per RFC 6455).",
        {
            {"conn_id", "number", "Connection id.", true},
            {"msg",     "string", "Text payload.", true},
        },
        false, tool_ws_send_text
    });

    srv.register_tool({
        "burp_ws_send_binary",
        "Send a binary frame (payload base64-decoded).",
        {
            {"conn_id",  "number", "Connection id.", true},
            {"data_b64", "string", "Base64 payload.", true},
        },
        false, tool_ws_send_binary
    });

    srv.register_tool({
        "burp_ws_send_raw",
        "Send a raw WebSocket frame with explicit opcode/fin/masked flags.",
        {
            {"conn_id",     "number",  "Connection id.", true},
            {"opcode",      "number",  "Opcode (0..15).", true},
            {"fin",         "boolean", "FIN flag.", false},
            {"masked",      "boolean", "Apply RFC 6455 masking.", false},
            {"payload_b64", "string",  "Base64 payload.", false},
        },
        false, tool_ws_send_raw
    });

    srv.register_tool({
        "burp_ws_list_connections",
        "List open WebSocket connections with frame counters and last error.",
        {}, true, tool_ws_list
    });

    srv.register_tool({
        "burp_ws_frames",
        "Return a slice of frames captured on the connection (preview text plus base64 payload).",
        {
            {"conn_id", "number", "Connection id.", true},
            {"start",   "number", "Starting frame index.", false},
            {"max",     "number", "Maximum frames to return.", false},
        },
        true, tool_ws_frames
    });

    srv.register_tool({
        "burp_ws_clear_frames",
        "Clear the frame log for a connection (does not disconnect).",
        { {"conn_id", "number", "Connection id.", true} },
        false, tool_ws_clear
    });

    srv.register_tool({
        "burp_logger_query",
        "Query the unified Burp logger ring buffer (filter object: method, host_regex, url_regex, status_min/max, source, mime_type).",
        {
            {"filter", "object", "Filter object.", false},
            {"limit",  "number", "Maximum rows to return.", false},
        },
        true, tool_logger_query
    });

    srv.register_tool({
        "burp_logger_total",
        "Return total row count and ring capacity of the logger.",
        {}, true, tool_logger_total
    });

    srv.register_tool({
        "burp_logger_clear",
        "Clear the logger ring buffer.",
        {}, false, tool_logger_clear
    });

    srv.register_tool({
        "burp_logger_export_csv",
        "Export filtered logger rows to a CSV file.",
        {
            {"path",   "string", "Output CSV file path.", true},
            {"filter", "object", "Filter object (same as burp_logger_query).", false},
        },
        false, tool_logger_export_csv
    });

    srv.register_tool({
        "burp_report_generate",
        "Generate a vulnerability report from issue_store. format = html|markdown|json|sarif_2_1_0|csv.",
        {
            {"title",                "string",  "Report title.", false},
            {"client",               "string",  "Client name.", false},
            {"scope_summary",        "string",  "Scope summary text.", false},
            {"include_issue_ids",    "array",   "Optional list of issue ids; empty = all issues.", false},
            {"format",               "string",  "Output format.", true},
            {"output_path",          "string",  "Destination file path.", true},
            {"include_evidence",     "boolean", "Embed request/response evidence (default true).", false},
            {"include_remediation",  "boolean", "Embed remediation text (default true).", false},
        },
        false, tool_report_generate
    });

    diag::log_tagged("burp.api_mcp", "registered Burp API/GraphQL/WS/Logger/Reports tools");
}

}
}
}
