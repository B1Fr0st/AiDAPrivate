#include "burp_search_mcp.hpp"

#include "../mitm_proxy.hpp"
#include "burp_logger.hpp"
#include "site_map.hpp"
#include "ws_editor.hpp"

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <map>
#include <regex>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace search_mcp {

namespace {

using json = nlohmann::json;
using mcp_standalone::tool_def_t;
using mcp_standalone::tool_result_t;

struct matcher_t
{
    std::string query;
    std::string query_lower;
    bool regex_valid = false;
    std::regex rx;
};

std::string lower_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

matcher_t make_matcher(const std::string& query)
{
    matcher_t m;
    m.query = query;
    m.query_lower = lower_ascii(query);
    try {
        m.rx = std::regex(query, std::regex_constants::icase | std::regex_constants::ECMAScript);
        m.regex_valid = true;
    } catch (...) {
        m.regex_valid = false;
    }
    return m;
}

bool find_match(const matcher_t& m, const std::string& text, size_t& offset)
{
    if (m.regex_valid) {
        std::smatch sm;
        if (std::regex_search(text, sm, m.rx)) {
            offset = static_cast<size_t>(sm.position());
            return true;
        }
    }
    const std::string t = lower_ascii(text);
    const size_t pos = t.find(m.query_lower);
    if (pos != std::string::npos) {
        offset = pos;
        return true;
    }
    return false;
}

std::string bytes_text(const std::vector<uint8_t>& data)
{
    const size_t cap = (std::min)(data.size(), static_cast<size_t>(2 * 1024 * 1024));
    return std::string(data.begin(), data.begin() + cap);
}

std::string header_text(const std::vector<std::pair<std::string, std::string>>& headers)
{
    std::string out;
    for (const auto& h : headers) {
        out += h.first;
        out += ": ";
        out += h.second;
        out += "\r\n";
    }
    return out;
}

std::string header_text(const std::vector<protocol_parser::http_header>& headers)
{
    std::string out;
    for (const auto& h : headers) {
        out += h.name;
        out += ": ";
        out += h.value;
        out += "\r\n";
    }
    return out;
}

std::string sitemap_url(const exchange_observed_t& e)
{
    std::string url = e.scheme.empty() ? (e.port == 443 ? "https://" : "http://") : (e.scheme + "://");
    url += e.host;
    if (!((url.rfind("https://", 0) == 0 && e.port == 443) || (url.rfind("http://", 0) == 0 && e.port == 80)) && e.port != 0) {
        url += ":";
        url += std::to_string(e.port);
    }
    url += e.path.empty() ? "/" : e.path;
    if (!e.query.empty()) {
        url += "?";
        url += e.query;
    }
    return url;
}

std::string proxy_url(const mitm_proxy::http_exchange& e)
{
    std::string url = e.is_tls ? "https://" : "http://";
    url += e.target_host;
    if (!((e.is_tls && e.target_port == 443) || (!e.is_tls && e.target_port == 80)) && e.target_port != 0) {
        url += ":";
        url += std::to_string(e.target_port);
    }
    url += e.request.uri.empty() ? "/" : e.request.uri;
    return url;
}

std::string snippet_for(const std::string& text, size_t offset)
{
    const size_t radius = 96;
    const size_t begin = offset > radius ? offset - radius : 0;
    const size_t end = (std::min)(text.size(), offset + radius);
    std::string s = text.substr(begin, end - begin);
    for (char& c : s) {
        if (c == '\r' || c == '\n' || c == '\t')
            c = ' ';
    }
    return s;
}

bool want_field(const std::string& search_in, const std::string& field)
{
    if (search_in.empty() || search_in == "all")
        return true;
    if (search_in == "request")
        return field.rfind("request_", 0) == 0 || field == "url";
    if (search_in == "response")
        return field.rfind("response_", 0) == 0;
    if (search_in == "headers")
        return field == "request_headers" || field == "response_headers";
    if (search_in == "body")
        return field == "request_body" || field == "response_body" || field == "ws_payload";
    if (search_in == "url")
        return field == "url";
    return true;
}

struct result_sink_t
{
    json matches = json::array();
    std::map<std::string, size_t> source_counts;
    size_t limit = 50;
    bool include_bodies = false;

    bool source_full(const std::string& source) const
    {
        const auto it = source_counts.find(source);
        return it != source_counts.end() && it->second >= limit;
    }

    void add(const std::string& source, json item)
    {
        if (source_full(source))
            return;
        item["source"] = source;
        matches.push_back(std::move(item));
        source_counts[source]++;
    }
};

void try_add_field(result_sink_t& sink, const matcher_t& matcher, const std::string& source, json base, const std::string& field, const std::string& value, bool body_field)
{
    if (sink.source_full(source))
        return;
    size_t offset = 0;
    if (!find_match(matcher, value, offset))
        return;
    base["matched_in"] = field;
    base["offset"] = offset;
    if (!body_field || sink.include_bodies)
        base["snippet"] = snippet_for(value, offset);
    sink.add(source, std::move(base));
}

void search_sitemap(result_sink_t& sink, const matcher_t& matcher, const std::string& search_in, bool scope_only)
{
    for (const auto& host : sitemap::list_hosts(scope_only)) {
        if (sink.source_full("sitemap"))
            return;
        for (const auto& path : sitemap::list_paths(host.host, host.port)) {
            if (sink.source_full("sitemap"))
                return;
            for (const auto& e : sitemap::list_exchanges_for(host.host, host.port, path)) {
                if (sink.source_full("sitemap"))
                    return;
                const std::string url = sitemap_url(e);
                json base;
                base["exchange_id"] = e.id;
                base["url"] = url;
                base["method"] = e.method;
                base["status_code"] = e.status_code;
                if (want_field(search_in, "url")) try_add_field(sink, matcher, "sitemap", base, "url", url, false);
                if (want_field(search_in, "request_headers")) try_add_field(sink, matcher, "sitemap", base, "request_headers", header_text(e.req_headers), false);
                if (want_field(search_in, "response_headers")) try_add_field(sink, matcher, "sitemap", base, "response_headers", header_text(e.resp_headers), false);
                if (want_field(search_in, "request_body")) try_add_field(sink, matcher, "sitemap", base, "request_body", bytes_text(e.req_body), true);
                if (want_field(search_in, "response_body")) try_add_field(sink, matcher, "sitemap", base, "response_body", bytes_text(e.resp_body), true);
            }
        }
    }
}

void search_proxy(result_sink_t& sink, const matcher_t& matcher, const std::string& search_in)
{
    const auto history = mitm_proxy::get_history(sink.limit == 0 ? 50 : sink.limit);
    for (const auto& e : history) {
        if (sink.source_full("proxy"))
            return;
        const std::string url = proxy_url(e);
        json base;
        base["exchange_id"] = e.id;
        base["url"] = url;
        base["method"] = e.request.method;
        base["status_code"] = e.response.status_code;
        if (want_field(search_in, "url")) try_add_field(sink, matcher, "proxy", base, "url", url, false);
        if (want_field(search_in, "request_headers")) try_add_field(sink, matcher, "proxy", base, "request_headers", header_text(e.request.headers), false);
        if (want_field(search_in, "response_headers")) try_add_field(sink, matcher, "proxy", base, "response_headers", header_text(e.response.headers), false);
        if (want_field(search_in, "request_body")) try_add_field(sink, matcher, "proxy", base, "request_body", bytes_text(e.request.body), true);
        if (want_field(search_in, "response_body")) try_add_field(sink, matcher, "proxy", base, "response_body", bytes_text(e.response.body), true);
    }
}

void search_logger(result_sink_t& sink, const matcher_t& matcher)
{
    logger::log_filter_t f;
    f.url_regex = matcher.query;
    const auto rows = logger::query(f, sink.limit == 0 ? 50 : sink.limit);
    for (const auto& r : rows) {
        if (sink.source_full("logger"))
            return;
        json base;
        base["log_id"] = r.id;
        base["exchange_id"] = r.exchange_id;
        base["url"] = r.url;
        base["method"] = r.method;
        base["status_code"] = r.status;
        size_t offset = 0;
        if (find_match(matcher, r.url, offset)) {
            base["matched_in"] = "url";
            base["offset"] = offset;
            base["snippet"] = snippet_for(r.url, offset);
            sink.add("logger", std::move(base));
        }
    }
}

void search_ws(result_sink_t& sink, const matcher_t& matcher, const std::string& search_in)
{
    if (!want_field(search_in, "ws_payload"))
        return;
    for (const auto& conn : ws_editor::list_connections()) {
        if (sink.source_full("websocket"))
            return;
        const auto count = ws_editor::frame_count(conn.id);
        const auto frames = ws_editor::frames(conn.id, count > sink.limit ? count - sink.limit : 0, sink.limit == 0 ? 50 : sink.limit);
        for (size_t i = 0; i < frames.size(); ++i) {
            if (sink.source_full("websocket"))
                return;
            const std::string payload = bytes_text(frames[i].payload);
            size_t offset = 0;
            if (!find_match(matcher, payload, offset))
                continue;
            json base;
            base["connection_id"] = conn.id;
            base["url"] = conn.url;
            base["frame_index"] = i;
            base["outbound"] = frames[i].outbound;
            base["opcode"] = frames[i].opcode;
            base["matched_in"] = "ws_payload";
            base["offset"] = offset;
            if (sink.include_bodies)
                base["snippet"] = snippet_for(payload, offset);
            sink.add("websocket", std::move(base));
        }
    }
}

tool_result_t tool_search(const json& params)
{
    if (!params.contains("query") || !params["query"].is_string() || params["query"].get<std::string>().empty())
        return tool_result_t::error("missing_query");
    result_sink_t sink;
    sink.limit = params.value("limit", 50u);
    if (sink.limit == 0)
        sink.limit = 50;
    if (sink.limit > 500)
        sink.limit = 500;
    sink.include_bodies = params.value("include_bodies", false);
    const std::string search_in = lower_ascii(params.value("search_in", std::string("all")));
    const bool scope_only = params.value("scope_only", false);
    const matcher_t matcher = make_matcher(params["query"].get<std::string>());
    search_sitemap(sink, matcher, search_in, scope_only);
    search_proxy(sink, matcher, search_in);
    if (search_in.empty() || search_in == "all" || search_in == "url")
        search_logger(sink, matcher);
    search_ws(sink, matcher, search_in);
    json sources = json::object();
    size_t total = 0;
    for (const auto& kv : sink.source_counts) {
        sources[kv.first] = kv.second;
        total += kv.second;
    }
    json out;
    out["total_matches"] = total;
    out["sources"] = sources;
    out["matches"] = sink.matches;
    out["regex_used"] = matcher.regex_valid;
    out["limit_per_source"] = sink.limit;
    return tool_result_t::ok(out);
}

}

void register_search_tools(mcp_standalone::server_t& srv)
{
    tool_def_t t;
    t.name = "burp_global_search";
    t.description = "Search captured Burp traffic across site map, proxy history, logger URLs, and WebSocket frames.";
    t.params = {
        {"query", "string", "Regex or plain text search query.", true},
        {"search_in", "string", "request|response|headers|body|url|all", false},
        {"scope_only", "boolean", "Restrict site map search to in-scope hosts.", false},
        {"limit", "number", "Maximum results per source.", false},
        {"include_bodies", "boolean", "Include body/WebSocket snippets for body matches.", false},
    };
    t.read_only = true;
    t.handler = [](const json& params) -> tool_result_t {
        diag::log_tagged_fmt("mcp_burp", "global_search query_present=%d", params.contains("query") ? 1 : 0);
        return tool_search(params);
    };
    srv.register_tool(std::move(t));
}

}
}
}
