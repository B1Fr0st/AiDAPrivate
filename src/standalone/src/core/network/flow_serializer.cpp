#include "flow_serializer.hpp"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace flow_serializer {
namespace {

using json = nlohmann::json;

std::string lower_ascii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

json headers_to_json(const std::vector<protocol_parser::http_header>& headers)
{
    json out = json::array();
    for (const auto& h : headers)
        out.push_back(json{{"name", h.name}, {"value", h.value}});
    return out;
}

std::vector<protocol_parser::http_header> headers_from_json(const json& value)
{
    std::vector<protocol_parser::http_header> out;
    if (!value.is_array())
        return out;
    for (const auto& item : value) {
        if (!item.is_object())
            continue;
        protocol_parser::http_header h;
        h.name = item.value("name", std::string());
        h.value = item.value("value", std::string());
        if (!h.name.empty())
            out.push_back(std::move(h));
    }
    return out;
}

const char* state_to_string(mitm_proxy::http_exchange::state_t state)
{
    switch (state) {
    case mitm_proxy::http_exchange::state_t::pending: return "pending";
    case mitm_proxy::http_exchange::state_t::forwarding: return "forwarding";
    case mitm_proxy::http_exchange::state_t::complete: return "complete";
    case mitm_proxy::http_exchange::state_t::dropped: return "dropped";
    case mitm_proxy::http_exchange::state_t::error: return "error";
    }
    return "pending";
}

mitm_proxy::http_exchange::state_t state_from_string(const std::string& value)
{
    const std::string v = lower_ascii(value);
    if (v == "forwarding") return mitm_proxy::http_exchange::state_t::forwarding;
    if (v == "complete") return mitm_proxy::http_exchange::state_t::complete;
    if (v == "dropped") return mitm_proxy::http_exchange::state_t::dropped;
    if (v == "error") return mitm_proxy::http_exchange::state_t::error;
    return mitm_proxy::http_exchange::state_t::pending;
}

std::string ws_opcode_to_string(protocol_parser::ws_opcode op)
{
    return protocol_parser::ws_opcode_name(op);
}

protocol_parser::ws_opcode ws_opcode_from_string(const std::string& value)
{
    const std::string v = lower_ascii(value);
    if (v == "continuation") return protocol_parser::ws_opcode::continuation;
    if (v == "binary") return protocol_parser::ws_opcode::binary;
    if (v == "close") return protocol_parser::ws_opcode::close;
    if (v == "ping") return protocol_parser::ws_opcode::ping;
    if (v == "pong") return protocol_parser::ws_opcode::pong;
    return protocol_parser::ws_opcode::text;
}

std::string iso_from_ms(uint64_t ms)
{
    std::time_t seconds = static_cast<std::time_t>(ms / 1000);
    std::tm tm{};
    gmtime_s(&tm, &seconds);
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << '.'
        << std::setw(3) << std::setfill('0') << (ms % 1000) << 'Z';
    return out.str();
}

bool parse_url(const std::string& url, bool& use_tls, std::string& host, uint16_t& port, std::string& path_query)
{
    std::string rest = url;
    use_tls = false;
    if (rest.rfind("https://", 0) == 0) {
        use_tls = true;
        rest.erase(0, 8);
    } else if (rest.rfind("http://", 0) == 0) {
        rest.erase(0, 7);
    }
    const size_t slash = rest.find('/');
    std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    path_query = slash == std::string::npos ? std::string("/") : rest.substr(slash);
    if (authority.empty())
        return false;
    port = use_tls ? 443 : 80;
    const size_t colon = authority.rfind(':');
    if (colon != std::string::npos && colon + 1 < authority.size()) {
        char* end = nullptr;
        unsigned long p = std::strtoul(authority.c_str() + colon + 1, &end, 10);
        if (end && *end == '\0' && p > 0 && p <= 65535) {
            port = static_cast<uint16_t>(p);
            authority.resize(colon);
        }
    }
    host = authority;
    return !host.empty();
}

std::string exchange_url(const mitm_proxy::http_exchange& exchange)
{
    std::string scheme = exchange.is_tls ? "https" : "http";
    std::string uri = exchange.request.uri.empty() ? "/" : exchange.request.uri;
    if (uri.rfind("http://", 0) == 0 || uri.rfind("https://", 0) == 0)
        return uri;
    std::ostringstream out;
    out << scheme << "://" << exchange.target_host;
    if ((exchange.is_tls && exchange.target_port != 443) || (!exchange.is_tls && exchange.target_port != 80))
        out << ':' << exchange.target_port;
    if (uri.empty() || uri[0] != '/')
        out << '/';
    out << uri;
    return out.str();
}

json tags_to_json(const std::vector<std::string>& tags)
{
    json out = json::array();
    for (const auto& tag : tags)
        if (!tag.empty())
            out.push_back(tag);
    return out;
}

std::vector<std::string> tags_from_json(const json& value)
{
    std::vector<std::string> out;
    if (!value.is_array())
        return out;
    for (const auto& item : value) {
        if (item.is_string()) {
            std::string tag = item.get<std::string>();
            if (!tag.empty() && std::find(out.begin(), out.end(), tag) == out.end())
                out.push_back(std::move(tag));
        }
    }
    return out;
}

std::string query_name(const std::string& item)
{
    const size_t eq = item.find('=');
    return eq == std::string::npos ? item : item.substr(0, eq);
}

std::string query_value(const std::string& item)
{
    const size_t eq = item.find('=');
    return eq == std::string::npos ? std::string() : item.substr(eq + 1);
}

json query_to_har(const std::string& path_query)
{
    json out = json::array();
    const size_t q = path_query.find('?');
    if (q == std::string::npos || q + 1 >= path_query.size())
        return out;
    std::string query = path_query.substr(q + 1);
    size_t pos = 0;
    while (pos <= query.size()) {
        size_t amp = query.find('&', pos);
        std::string item = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        if (!item.empty())
            out.push_back(json{{"name", query_name(item)}, {"value", query_value(item)}});
        if (amp == std::string::npos)
            break;
        pos = amp + 1;
    }
    return out;
}

std::string mime_from_headers(const std::vector<protocol_parser::http_header>& headers)
{
    std::string value = protocol_parser::find_header(headers, "Content-Type");
    const size_t semi = value.find(';');
    if (semi != std::string::npos)
        value.resize(semi);
    return value;
}

int64_t header_size_estimate(const std::vector<uint8_t>& raw, size_t body_size)
{
    if (raw.empty() || raw.size() < body_size)
        return -1;
    return static_cast<int64_t>(raw.size() - body_size);
}

}

std::string base64_encode(const std::vector<uint8_t>& data)
{
    static constexpr char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < data.size()) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < data.size()) n |= static_cast<uint32_t>(data[i + 2]);
        out.push_back(table[(n >> 18) & 0x3f]);
        out.push_back(table[(n >> 12) & 0x3f]);
        out.push_back(i + 1 < data.size() ? table[(n >> 6) & 0x3f] : '=');
        out.push_back(i + 2 < data.size() ? table[n & 0x3f] : '=');
    }
    return out;
}

bool base64_decode(const std::string& value, std::vector<uint8_t>& out)
{
    int reverse[256];
    std::fill(reverse, reverse + 256, -1);
    const std::string table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < table.size(); ++i)
        reverse[static_cast<unsigned char>(table[i])] = static_cast<int>(i);
    out.clear();
    int bits = 0;
    int val = 0;
    for (unsigned char c : value) {
        if (std::isspace(c))
            continue;
        if (c == '=')
            break;
        if (reverse[c] < 0)
            return false;
        val = (val << 6) | reverse[c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((val >> bits) & 0xff));
        }
    }
    return true;
}

std::vector<uint8_t> bytes_from_text(const std::string& value)
{
    return std::vector<uint8_t>(value.begin(), value.end());
}

std::string text_from_bytes(const std::vector<uint8_t>& value)
{
    return std::string(value.begin(), value.end());
}

std::vector<uint8_t> build_raw_request(const mitm_proxy::http_exchange& exchange)
{
    if (!exchange.raw_request.empty())
        return exchange.raw_request;
    std::ostringstream out;
    out << (exchange.request.method.empty() ? "GET" : exchange.request.method) << ' '
        << (exchange.request.uri.empty() ? "/" : exchange.request.uri) << ' '
        << (exchange.request.version.empty() ? "HTTP/1.1" : exchange.request.version) << "\r\n";
    bool host_seen = false;
    bool content_length_seen = false;
    for (const auto& h : exchange.request.headers) {
        if (lower_ascii(h.name) == "host")
            host_seen = true;
        if (lower_ascii(h.name) == "content-length")
            content_length_seen = true;
        out << h.name << ": " << h.value << "\r\n";
    }
    if (!host_seen && !exchange.target_host.empty()) {
        out << "Host: " << exchange.target_host;
        if ((exchange.is_tls && exchange.target_port != 443) || (!exchange.is_tls && exchange.target_port != 80))
            out << ':' << exchange.target_port;
        out << "\r\n";
    }
    if (!content_length_seen && !exchange.request.body.empty())
        out << "Content-Length: " << exchange.request.body.size() << "\r\n";
    out << "\r\n";
    std::string head = out.str();
    std::vector<uint8_t> raw(head.begin(), head.end());
    raw.insert(raw.end(), exchange.request.body.begin(), exchange.request.body.end());
    return raw;
}

std::vector<uint8_t> build_raw_response(const mitm_proxy::http_exchange& exchange)
{
    if (!exchange.raw_response.empty())
        return exchange.raw_response;
    std::ostringstream out;
    out << (exchange.response.version.empty() ? "HTTP/1.1" : exchange.response.version) << ' '
        << exchange.response.status_code << ' '
        << (exchange.response.reason.empty() ? "OK" : exchange.response.reason) << "\r\n";
    bool content_length_seen = false;
    for (const auto& h : exchange.response.headers) {
        if (lower_ascii(h.name) == "content-length")
            content_length_seen = true;
        out << h.name << ": " << h.value << "\r\n";
    }
    if (!content_length_seen)
        out << "Content-Length: " << exchange.response.body.size() << "\r\n";
    out << "\r\n";
    std::string head = out.str();
    std::vector<uint8_t> raw(head.begin(), head.end());
    raw.insert(raw.end(), exchange.response.body.begin(), exchange.response.body.end());
    return raw;
}

json exchange_to_json(const mitm_proxy::http_exchange& exchange)
{
    json ws = json::array();
    for (const auto& frame : exchange.ws_frames) {
        ws.push_back(json{
            {"timestamp", frame.timestamp},
            {"outbound", frame.outbound},
            {"opcode", ws_opcode_to_string(frame.opcode)},
            {"payload_b64", base64_encode(frame.payload)}
        });
    }
    json j;
    j["id"] = exchange.id;
    j["timestamp"] = exchange.timestamp;
    j["client"] = json{{"addr", exchange.client_addr}, {"port", exchange.client_port}};
    j["target"] = json{{"host", exchange.target_host}, {"port", exchange.target_port}};
    j["tls"] = json{{"enabled", exchange.is_tls}, {"sni", exchange.tls_sni}, {"version", exchange.tls_version_str}, {"alpn", exchange.alpn_protocol}};
    j["request"] = json{
        {"method", exchange.request.method},
        {"uri", exchange.request.uri},
        {"version", exchange.request.version},
        {"headers", headers_to_json(exchange.request.headers)},
        {"body_b64", base64_encode(exchange.request.body)},
        {"valid", exchange.request.valid},
        {"complete", exchange.request.complete},
        {"total_consumed", exchange.request.total_consumed}
    };
    j["response"] = json{
        {"status_code", exchange.response.status_code},
        {"reason", exchange.response.reason},
        {"version", exchange.response.version},
        {"headers", headers_to_json(exchange.response.headers)},
        {"body_b64", base64_encode(exchange.response.body)},
        {"valid", exchange.response.valid},
        {"complete", exchange.response.complete},
        {"total_consumed", exchange.response.total_consumed}
    };
    j["raw_request_b64"] = base64_encode(exchange.raw_request);
    j["raw_response_b64"] = base64_encode(exchange.raw_response);
    j["websocket"] = json{{"enabled", exchange.is_websocket}, {"sent", exchange.ws_frames_sent}, {"received", exchange.ws_frames_recv}, {"frames", ws}};
    j["http2"] = json{{"enabled", exchange.is_h2}, {"stream_id", exchange.h2_stream_id}};
    j["state"] = state_to_string(exchange.state);
    j["error"] = exchange.error_msg;
    j["timing"] = json{{"request_time", exchange.request_time}, {"response_time", exchange.response_time}, {"latency_ms", exchange.latency_ms}};
    j["sizes"] = json{{"request", exchange.request_size}, {"response", exchange.response_size}};
    j["tags"] = tags_to_json(exchange.tags);
    j["notes"] = exchange.notes;
    return j;
}

bool exchange_from_json(const json& value, mitm_proxy::http_exchange& out, std::string& error)
{
    if (!value.is_object()) {
        error = "flow entry is not an object";
        return false;
    }
    out = {};
    out.id = value.value("id", uint64_t{0});
    out.timestamp = value.value("timestamp", uint64_t{0});
    const json client = value.value("client", json::object());
    out.client_addr = client.value("addr", std::string());
    out.client_port = static_cast<uint16_t>(client.value("port", 0));
    const json target = value.value("target", json::object());
    out.target_host = target.value("host", std::string());
    out.target_port = static_cast<uint16_t>(target.value("port", 0));
    const json tls = value.value("tls", json::object());
    out.is_tls = tls.value("enabled", false);
    out.tls_sni = tls.value("sni", std::string());
    out.tls_version_str = tls.value("version", std::string());
    out.alpn_protocol = tls.value("alpn", std::string());
    const json req = value.value("request", json::object());
    out.request.method = req.value("method", std::string());
    out.request.uri = req.value("uri", std::string());
    out.request.version = req.value("version", std::string());
    out.request.headers = headers_from_json(req.value("headers", json::array()));
    if (!base64_decode(req.value("body_b64", std::string()), out.request.body)) {
        error = "invalid request body base64";
        return false;
    }
    out.request.valid = req.value("valid", false);
    out.request.complete = req.value("complete", false);
    out.request.total_consumed = req.value("total_consumed", size_t{0});
    const json resp = value.value("response", json::object());
    out.response.status_code = resp.value("status_code", 0);
    out.response.reason = resp.value("reason", std::string());
    out.response.version = resp.value("version", std::string());
    out.response.headers = headers_from_json(resp.value("headers", json::array()));
    if (!base64_decode(resp.value("body_b64", std::string()), out.response.body)) {
        error = "invalid response body base64";
        return false;
    }
    out.response.valid = resp.value("valid", false);
    out.response.complete = resp.value("complete", false);
    out.response.total_consumed = resp.value("total_consumed", size_t{0});
    if (!base64_decode(value.value("raw_request_b64", std::string()), out.raw_request)) {
        error = "invalid raw request base64";
        return false;
    }
    if (!base64_decode(value.value("raw_response_b64", std::string()), out.raw_response)) {
        error = "invalid raw response base64";
        return false;
    }
    const json websocket = value.value("websocket", json::object());
    out.is_websocket = websocket.value("enabled", false);
    out.ws_frames_sent = websocket.value("sent", uint32_t{0});
    out.ws_frames_recv = websocket.value("received", uint32_t{0});
    const json frames = websocket.value("frames", json::array());
    if (frames.is_array()) {
        for (const auto& f : frames) {
            mitm_proxy::http_exchange::ws_frame_entry frame;
            frame.timestamp = f.value("timestamp", uint64_t{0});
            frame.outbound = f.value("outbound", false);
            frame.opcode = ws_opcode_from_string(f.value("opcode", std::string("text")));
            if (!base64_decode(f.value("payload_b64", std::string()), frame.payload)) {
                error = "invalid websocket payload base64";
                return false;
            }
            out.ws_frames.push_back(std::move(frame));
        }
    }
    const json h2 = value.value("http2", json::object());
    out.is_h2 = h2.value("enabled", false);
    out.h2_stream_id = h2.value("stream_id", int32_t{0});
    out.state = state_from_string(value.value("state", std::string("pending")));
    out.error_msg = value.value("error", std::string());
    const json timing = value.value("timing", json::object());
    out.request_time = timing.value("request_time", uint64_t{0});
    out.response_time = timing.value("response_time", uint64_t{0});
    out.latency_ms = timing.value("latency_ms", uint64_t{0});
    const json sizes = value.value("sizes", json::object());
    out.request_size = sizes.value("request", out.raw_request.size());
    out.response_size = sizes.value("response", out.raw_response.size());
    out.tags = tags_from_json(value.value("tags", json::array()));
    out.notes = value.value("notes", std::string());
    return true;
}

json export_aida_json(const std::vector<mitm_proxy::http_exchange>& flows)
{
    json document;
    document["format"] = "aida-flow";
    document["version"] = 1;
    document["flows"] = json::array();
    for (const auto& flow : flows)
        document["flows"].push_back(exchange_to_json(flow));
    return document;
}

parse_result import_aida_json(const json& document)
{
    parse_result result;
    const json flows = document.value("flows", json::array());
    if (!flows.is_array()) {
        result.error = "aida flow document missing flows array";
        return result;
    }
    for (const auto& item : flows) {
        mitm_proxy::http_exchange ex;
        std::string error;
        if (!exchange_from_json(item, ex, error)) {
            result.error = error;
            return result;
        }
        result.flows.push_back(std::move(ex));
    }
    result.success = true;
    return result;
}

json export_har_1_2(const std::vector<mitm_proxy::http_exchange>& flows)
{
    json entries = json::array();
    for (const auto& flow : flows) {
        const std::string url = exchange_url(flow);
        json req_body;
        req_body["mimeType"] = mime_from_headers(flow.request.headers);
        req_body["text"] = base64_encode(flow.request.body);
        req_body["encoding"] = "base64";
        json resp_content;
        resp_content["size"] = flow.response.body.size();
        resp_content["mimeType"] = mime_from_headers(flow.response.headers);
        resp_content["text"] = base64_encode(flow.response.body);
        resp_content["encoding"] = "base64";
        json entry;
        entry["startedDateTime"] = iso_from_ms(flow.timestamp == 0 ? flow.request_time : flow.timestamp);
        entry["time"] = flow.latency_ms;
        entry["request"] = json{
            {"method", flow.request.method},
            {"url", url},
            {"httpVersion", flow.request.version.empty() ? "HTTP/1.1" : flow.request.version},
            {"headers", headers_to_json(flow.request.headers)},
            {"queryString", query_to_har(flow.request.uri)},
            {"cookies", json::array()},
            {"headersSize", header_size_estimate(flow.raw_request, flow.request.body.size())},
            {"bodySize", static_cast<int64_t>(flow.request.body.size())},
            {"postData", req_body}
        };
        entry["response"] = json{
            {"status", flow.response.status_code},
            {"statusText", flow.response.reason},
            {"httpVersion", flow.response.version.empty() ? "HTTP/1.1" : flow.response.version},
            {"headers", headers_to_json(flow.response.headers)},
            {"cookies", json::array()},
            {"content", resp_content},
            {"redirectURL", protocol_parser::find_header(flow.response.headers, "Location")},
            {"headersSize", header_size_estimate(flow.raw_response, flow.response.body.size())},
            {"bodySize", static_cast<int64_t>(flow.response.body.size())}
        };
        entry["cache"] = json::object();
        entry["timings"] = json{{"send", 0}, {"wait", flow.latency_ms}, {"receive", 0}};
        entry["_aida"] = json{{"id", flow.id}, {"target_host", flow.target_host}, {"target_port", flow.target_port}, {"tls", flow.is_tls}, {"tags", tags_to_json(flow.tags)}, {"notes", flow.notes}};
        entries.push_back(std::move(entry));
    }
    json root;
    root["log"] = json{{"version", "1.2"}, {"creator", json{{"name", "AiDA"}, {"version", "1"}}}, {"entries", entries}};
    return root;
}

parse_result import_har_1_2(const json& document)
{
    parse_result result;
    const json log = document.value("log", json::object());
    const json entries = log.value("entries", json::array());
    if (!entries.is_array()) {
        result.error = "HAR document missing log.entries array";
        return result;
    }
    for (const auto& entry : entries) {
        const json request = entry.value("request", json::object());
        const json response = entry.value("response", json::object());
        bool tls = false;
        std::string host;
        uint16_t port = 0;
        std::string path_query;
        if (!parse_url(request.value("url", std::string()), tls, host, port, path_query)) {
            result.error = "HAR entry has invalid request URL";
            return result;
        }
        mitm_proxy::http_exchange ex;
        ex.id = entry.value("_aida", json::object()).value("id", uint64_t{0});
        ex.timestamp = 0;
        ex.target_host = host;
        ex.target_port = port;
        ex.is_tls = tls;
        ex.request.method = request.value("method", std::string("GET"));
        ex.request.uri = path_query.empty() ? "/" : path_query;
        ex.request.version = request.value("httpVersion", std::string("HTTP/1.1"));
        ex.request.headers = headers_from_json(request.value("headers", json::array()));
        const json post = request.value("postData", json::object());
        if (post.value("encoding", std::string()) == "base64") {
            if (!base64_decode(post.value("text", std::string()), ex.request.body)) {
                result.error = "HAR request postData base64 is invalid";
                return result;
            }
        } else {
            ex.request.body = bytes_from_text(post.value("text", std::string()));
        }
        ex.request.valid = true;
        ex.request.complete = true;
        ex.response.status_code = response.value("status", 0);
        ex.response.reason = response.value("statusText", std::string());
        ex.response.version = response.value("httpVersion", std::string("HTTP/1.1"));
        ex.response.headers = headers_from_json(response.value("headers", json::array()));
        const json content = response.value("content", json::object());
        if (content.value("encoding", std::string()) == "base64") {
            if (!base64_decode(content.value("text", std::string()), ex.response.body)) {
                result.error = "HAR response content base64 is invalid";
                return result;
            }
        } else {
            ex.response.body = bytes_from_text(content.value("text", std::string()));
        }
        ex.response.valid = ex.response.status_code > 0;
        ex.response.complete = true;
        ex.raw_request = build_raw_request(ex);
        ex.raw_response = build_raw_response(ex);
        ex.request_size = ex.raw_request.size();
        ex.response_size = ex.raw_response.size();
        ex.latency_ms = entry.value("time", uint64_t{0});
        ex.state = mitm_proxy::http_exchange::state_t::complete;
        ex.tags = tags_from_json(entry.value("_aida", json::object()).value("tags", json::array()));
        ex.notes = entry.value("_aida", json::object()).value("notes", std::string());
        result.flows.push_back(std::move(ex));
    }
    result.success = true;
    return result;
}

bool save_file(const std::string& path, flow_format format, const std::vector<mitm_proxy::http_exchange>& flows, std::string& error)
{
    json document = format == flow_format::har_1_2 ? export_har_1_2(flows) : export_aida_json(flows);
    std::filesystem::path fs_path(path);
    std::error_code ec;
    if (!fs_path.parent_path().empty())
        std::filesystem::create_directories(fs_path.parent_path(), ec);
    std::ofstream out(fs_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "failed to open output file";
        return false;
    }
    out << document.dump(2);
    if (!out.good()) {
        error = "failed to write output file";
        return false;
    }
    return true;
}

parse_result load_file(const std::string& path, flow_format format)
{
    parse_result result;
    std::ifstream in(std::filesystem::path(path), std::ios::binary);
    if (!in) {
        result.error = "failed to open input file";
        return result;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    json document = json::parse(ss.str(), nullptr, false);
    if (document.is_discarded()) {
        result.error = "input is not valid JSON";
        return result;
    }
    return format == flow_format::har_1_2 ? import_har_1_2(document) : import_aida_json(document);
}

bool parse_format(const std::string& value, flow_format& out)
{
    const std::string v = lower_ascii(value);
    if (v == "aida" || v == "aida_json" || v == "json") {
        out = flow_format::aida_json;
        return true;
    }
    if (v == "har" || v == "har_1_2") {
        out = flow_format::har_1_2;
        return true;
    }
    return false;
}

const char* format_name(flow_format format)
{
    return format == flow_format::har_1_2 ? "har" : "aida";
}

}
