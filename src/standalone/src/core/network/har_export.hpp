#pragma once

#include "mitm_proxy.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

namespace har_export {

inline std::string b64_encode(const uint8_t* data, size_t len)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        const uint32_t b0 = data[i];
        const uint32_t b1 = (i + 1 < len) ? data[i + 1] : 0;
        const uint32_t b2 = (i + 2 < len) ? data[i + 2] : 0;
        const uint32_t triple = (b0 << 16) | (b1 << 8) | b2;
        out.push_back(alphabet[(triple >> 18) & 0x3f]);
        out.push_back(alphabet[(triple >> 12) & 0x3f]);
        out.push_back(i + 1 < len ? alphabet[(triple >> 6) & 0x3f] : '=');
        out.push_back(i + 2 < len ? alphabet[triple & 0x3f] : '=');
    }
    return out;
}

inline std::string b64_encode(const std::vector<uint8_t>& data)
{
    return data.empty() ? std::string() : b64_encode(data.data(), data.size());
}

inline int b64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

inline bool b64_decode(const std::string& text, std::vector<uint8_t>& out)
{
    out.clear();
    int val = 0;
    int valb = -8;
    for (unsigned char c : text) {
        if (std::isspace(c))
            continue;
        if (c == '=')
            break;
        const int d = b64_value(c);
        if (d < 0)
            return false;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<uint8_t>((val >> valb) & 0xff));
            valb -= 8;
        }
    }
    return true;
}

inline std::string bytes_to_string(const std::vector<uint8_t>& data)
{
    return std::string(data.begin(), data.end());
}

inline std::vector<uint8_t> string_to_bytes(const std::string& value)
{
    return std::vector<uint8_t>(value.begin(), value.end());
}

inline nlohmann::json headers_to_har(const std::vector<protocol_parser::http_header>& headers)
{
    auto arr = nlohmann::json::array();
    for (const auto& h : headers)
        arr.push_back({{"name", h.name}, {"value", h.value}});
    return arr;
}

inline nlohmann::json query_to_har(const std::string& uri)
{
    auto arr = nlohmann::json::array();
    const size_t q = uri.find('?');
    if (q == std::string::npos)
        return arr;
    size_t end = uri.find('#', q + 1);
    if (end == std::string::npos)
        end = uri.size();
    size_t start = q + 1;
    while (start <= end) {
        size_t amp = uri.find('&', start);
        if (amp == std::string::npos || amp > end)
            amp = end;
        std::string part = uri.substr(start, amp - start);
        if (!part.empty()) {
            const size_t eq = part.find('=');
            arr.push_back({
                {"name", eq == std::string::npos ? part : part.substr(0, eq)},
                {"value", eq == std::string::npos ? std::string() : part.substr(eq + 1)}
            });
        }
        if (amp == end)
            break;
        start = amp + 1;
    }
    return arr;
}

inline std::vector<protocol_parser::http_header> headers_from_har(const nlohmann::json& arr)
{
    std::vector<protocol_parser::http_header> headers;
    if (!arr.is_array())
        return headers;
    for (const auto& item : arr) {
        protocol_parser::http_header h;
        h.name = item.value("name", std::string());
        h.value = item.value("value", std::string());
        if (!h.name.empty())
            headers.push_back(std::move(h));
    }
    return headers;
}

inline bool content_is_text(const std::vector<protocol_parser::http_header>& headers, const std::vector<uint8_t>& body)
{
    const std::string ct = protocol_parser::find_header(headers, "Content-Type");
    std::string low = ct;
    std::transform(low.begin(), low.end(), low.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (low.find("text/") != std::string::npos || low.find("json") != std::string::npos ||
        low.find("xml") != std::string::npos || low.find("javascript") != std::string::npos ||
        low.find("x-www-form-urlencoded") != std::string::npos)
        return true;
    size_t printable = 0;
    const size_t n = std::min<size_t>(body.size(), 4096);
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = body[i];
        if (c >= 0x20 || c == '\n' || c == '\r' || c == '\t')
            ++printable;
    }
    return n > 0 && printable * 100 / n >= 92;
}

inline nlohmann::json content_to_har(const std::vector<protocol_parser::http_header>& headers,
                                     const std::vector<uint8_t>& body)
{
    nlohmann::json content;
    content["size"] = body.size();
    content["mimeType"] = protocol_parser::find_header(headers, "Content-Type");
    if (content_is_text(headers, body)) {
        content["text"] = bytes_to_string(body);
    } else {
        content["text"] = b64_encode(body);
        content["encoding"] = "base64";
    }
    return content;
}

inline std::vector<uint8_t> content_from_har(const nlohmann::json& content)
{
    if (!content.is_object() || !content.contains("text") || !content["text"].is_string())
        return {};
    const std::string text = content["text"].get<std::string>();
    if (content.value("encoding", std::string()) == "base64") {
        std::vector<uint8_t> decoded;
        if (b64_decode(text, decoded))
            return decoded;
        return {};
    }
    return string_to_bytes(text);
}

inline std::string iso_time(uint64_t epoch_ms)
{
    if (epoch_ms == 0)
        epoch_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    const std::time_t sec = static_cast<std::time_t>(epoch_ms / 1000);
    std::tm tmv{};
    gmtime_s(&tmv, &sec);
    std::ostringstream out;
    out << std::put_time(&tmv, "%Y-%m-%dT%H:%M:%S") << ".";
    out << std::setw(3) << std::setfill('0') << (epoch_ms % 1000) << "Z";
    return out.str();
}

inline void parse_url(const std::string& url, mitm_proxy::http_exchange& ex)
{
    std::string rest = url;
    const size_t scheme = rest.find("://");
    if (scheme != std::string::npos) {
        ex.is_tls = rest.substr(0, scheme) == "https";
        rest = rest.substr(scheme + 3);
    }
    const size_t slash = rest.find('/');
    std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    ex.request.uri = slash == std::string::npos ? "/" : rest.substr(slash);
    if (!authority.empty() && authority.front() == '[') {
        const size_t close = authority.find(']');
        ex.target_host = close == std::string::npos ? authority : authority.substr(1, close - 1);
        if (close != std::string::npos && close + 2 <= authority.size() && authority[close + 1] == ':')
            ex.target_port = static_cast<uint16_t>(std::max(0, std::atoi(authority.substr(close + 2).c_str())));
        else
            ex.target_port = ex.is_tls ? 443 : 80;
    } else if (const size_t colon = authority.rfind(':'); colon != std::string::npos) {
        ex.target_host = authority.substr(0, colon);
        ex.target_port = static_cast<uint16_t>(std::max(0, std::atoi(authority.substr(colon + 1).c_str())));
    } else {
        ex.target_host = authority;
        ex.target_port = ex.is_tls ? 443 : 80;
    }
}

inline std::vector<uint8_t> build_raw_request(const mitm_proxy::http_exchange& ex)
{
    std::ostringstream out;
    out << (ex.request.method.empty() ? "GET" : ex.request.method) << " "
        << (ex.request.uri.empty() ? "/" : ex.request.uri) << " "
        << (ex.request.version.empty() ? "HTTP/1.1" : ex.request.version) << "\r\n";
    for (const auto& h : ex.request.headers)
        out << h.name << ": " << h.value << "\r\n";
    out << "\r\n";
    std::string head = out.str();
    std::vector<uint8_t> raw(head.begin(), head.end());
    raw.insert(raw.end(), ex.request.body.begin(), ex.request.body.end());
    return raw;
}

inline std::vector<uint8_t> build_raw_response(const mitm_proxy::http_exchange& ex)
{
    std::ostringstream out;
    out << (ex.response.version.empty() ? "HTTP/1.1" : ex.response.version) << " "
        << ex.response.status_code << " " << ex.response.reason << "\r\n";
    for (const auto& h : ex.response.headers)
        out << h.name << ": " << h.value << "\r\n";
    out << "\r\n";
    std::string head = out.str();
    std::vector<uint8_t> raw(head.begin(), head.end());
    raw.insert(raw.end(), ex.response.body.begin(), ex.response.body.end());
    return raw;
}

inline nlohmann::json exchange_to_har(const mitm_proxy::http_exchange& ex)
{
    nlohmann::json entry;
    const int64_t request_headers_size = ex.raw_request.size() >= ex.request.body.size()
        ? static_cast<int64_t>(ex.raw_request.size() - ex.request.body.size())
        : -1;
    const int64_t response_headers_size = ex.raw_response.size() >= ex.response.body.size()
        ? static_cast<int64_t>(ex.raw_response.size() - ex.response.body.size())
        : -1;
    entry["startedDateTime"] = iso_time(ex.timestamp);
    entry["time"] = ex.latency_ms;
    entry["request"] = {
        {"method", ex.request.method},
        {"url", std::string(ex.is_tls ? "https://" : "http://") + ex.target_host + ex.request.uri},
        {"httpVersion", ex.request.version.empty() ? "HTTP/1.1" : ex.request.version},
        {"headers", headers_to_har(ex.request.headers)},
        {"queryString", query_to_har(ex.request.uri)},
        {"headersSize", request_headers_size},
        {"bodySize", ex.request.body.size()}
    };
    if (!ex.request.body.empty())
        entry["request"]["postData"] = content_to_har(ex.request.headers, ex.request.body);
    entry["response"] = {
        {"status", ex.response.status_code},
        {"statusText", ex.response.reason},
        {"httpVersion", ex.response.version.empty() ? "HTTP/1.1" : ex.response.version},
        {"headers", headers_to_har(ex.response.headers)},
        {"content", content_to_har(ex.response.headers, ex.response.body)},
        {"headersSize", response_headers_size},
        {"bodySize", ex.response.body.size()}
    };
    entry["cache"] = nlohmann::json::object();
    entry["timings"] = {{"send", 0}, {"wait", ex.latency_ms}, {"receive", 0}};
    entry["_aida"] = {
        {"id", ex.id},
        {"target_port", ex.target_port},
        {"client_addr", ex.client_addr},
        {"client_port", ex.client_port},
        {"is_tls", ex.is_tls},
        {"tls_sni", ex.tls_sni},
        {"tls_version", ex.tls_version_str},
        {"alpn", ex.alpn_protocol},
        {"is_h2", ex.is_h2},
        {"is_websocket", ex.is_websocket},
        {"request_time", ex.request_time},
        {"response_time", ex.response_time},
        {"raw_request_b64", b64_encode(ex.raw_request)},
        {"raw_response_b64", b64_encode(ex.raw_response)},
        {"tags", ex.tags},
        {"notes", ex.notes}
    };
    return entry;
}

inline nlohmann::json export_har(const std::vector<mitm_proxy::http_exchange>& flows)
{
    nlohmann::json entries = nlohmann::json::array();
    for (const auto& ex : flows)
        entries.push_back(exchange_to_har(ex));
    return {
        {"log", {
            {"version", "1.2"},
            {"creator", {{"name", "AiDA"}, {"version", "1.0"}}},
            {"entries", entries}
        }}
    };
}

struct import_result_t {
    bool ok = false;
    std::vector<mitm_proxy::http_exchange> flows;
    std::string error;
};

inline import_result_t import_har(const nlohmann::json& doc)
{
    import_result_t result;
    const auto* entries = doc.contains("log") && doc["log"].contains("entries") ? &doc["log"]["entries"] : nullptr;
    if (!entries || !entries->is_array()) {
        result.error = "HAR log.entries is missing";
        return result;
    }
    for (const auto& entry : *entries) {
        mitm_proxy::http_exchange ex;
        const auto& req = entry.value("request", nlohmann::json::object());
        const auto& resp = entry.value("response", nlohmann::json::object());
        ex.request.method = req.value("method", std::string("GET"));
        ex.request.version = req.value("httpVersion", std::string("HTTP/1.1"));
        parse_url(req.value("url", std::string()), ex);
        ex.request.headers = headers_from_har(req.value("headers", nlohmann::json::array()));
        if (req.contains("postData"))
            ex.request.body = content_from_har(req["postData"]);
        ex.request.valid = true;
        ex.request.complete = true;
        ex.response.status_code = resp.value("status", 0);
        ex.response.reason = resp.value("statusText", std::string());
        ex.response.version = resp.value("httpVersion", std::string("HTTP/1.1"));
        ex.response.headers = headers_from_har(resp.value("headers", nlohmann::json::array()));
        if (resp.contains("content"))
            ex.response.body = content_from_har(resp["content"]);
        ex.response.valid = ex.response.status_code > 0;
        ex.response.complete = true;
        if (entry.contains("time") && entry["time"].is_number())
            ex.latency_ms = static_cast<uint64_t>(std::max(0.0, entry["time"].get<double>()));
        if (entry.contains("_aida") && entry["_aida"].is_object()) {
            const auto& a = entry["_aida"];
            ex.id = a.value("id", 0ull);
            ex.target_port = static_cast<uint16_t>(a.value("target_port", static_cast<int>(ex.target_port)));
            ex.client_addr = a.value("client_addr", std::string());
            ex.client_port = static_cast<uint16_t>(a.value("client_port", 0));
            ex.is_tls = a.value("is_tls", ex.is_tls);
            ex.tls_sni = a.value("tls_sni", std::string());
            ex.tls_version_str = a.value("tls_version", std::string());
            ex.alpn_protocol = a.value("alpn", std::string());
            ex.is_h2 = a.value("is_h2", false);
            ex.is_websocket = a.value("is_websocket", false);
            ex.request_time = a.value("request_time", 0ull);
            ex.response_time = a.value("response_time", 0ull);
            ex.notes = a.value("notes", std::string());
            if (a.contains("tags") && a["tags"].is_array())
                ex.tags = a["tags"].get<std::vector<std::string>>();
            if (a.contains("raw_request_b64") && a["raw_request_b64"].is_string())
                b64_decode(a["raw_request_b64"].get<std::string>(), ex.raw_request);
            if (a.contains("raw_response_b64") && a["raw_response_b64"].is_string())
                b64_decode(a["raw_response_b64"].get<std::string>(), ex.raw_response);
        }
        if (ex.raw_request.empty())
            ex.raw_request = build_raw_request(ex);
        if (ex.raw_response.empty())
            ex.raw_response = build_raw_response(ex);
        ex.request_size = ex.raw_request.size();
        ex.response_size = ex.raw_response.size();
        ex.state = mitm_proxy::http_exchange::state_t::complete;
        result.flows.push_back(std::move(ex));
    }
    result.ok = true;
    return result;
}

inline bool save_har_file(const std::string& path,
                          const std::vector<mitm_proxy::http_exchange>& flows,
                          std::string& error)
{
    std::ofstream out(path, std::ios::binary);
    if (!out.is_open()) {
        error = "open failed";
        return false;
    }
    out << export_har(flows).dump(2);
    if (!out.good()) {
        error = "write failed";
        return false;
    }
    return true;
}

inline import_result_t load_har_file(const std::string& path)
{
    import_result_t result;
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        result.error = "open failed";
        return result;
    }
    std::stringstream buffer;
    buffer << in.rdbuf();
    auto doc = nlohmann::json::parse(buffer.str(), nullptr, false);
    if (doc.is_discarded()) {
        result.error = "invalid JSON";
        return result;
    }
    return import_har(doc);
}

}
