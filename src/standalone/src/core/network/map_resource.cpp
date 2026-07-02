#include "map_resource.hpp"

#include "flow_serializer.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <sstream>
#include <unordered_map>

namespace map_resource {
namespace {

struct state_t {
    std::mutex mutex;
    std::vector<local_rule> local_rules;
    std::vector<remote_rule> remote_rules;
    std::atomic<uint64_t> next_id{1};
};

state_t& state()
{
    static state_t s;
    return s;
}

std::string lower_ascii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool starts_with(const std::string& value, const std::string& prefix)
{
    return value.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), value.begin());
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
    } else {
        return false;
    }
    const size_t slash = rest.find('/');
    std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    path_query = slash == std::string::npos ? std::string("/") : rest.substr(slash);
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

std::string url_decode_path(const std::string& value)
{
    std::string out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '%' && i + 2 < value.size()) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int hi = hex(value[i + 1]);
            int lo = hex(value[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(value[i] == '/' ? '\\' : value[i]);
    }
    return out;
}

bool suspicious_relative_path(const std::string& value)
{
    if (value.find('\0') != std::string::npos || value.find(':') != std::string::npos)
        return true;
    std::filesystem::path p(value);
    if (p.is_absolute())
        return true;
    for (const auto& part : p) {
        if (part == "..")
            return true;
    }
    return false;
}

bool is_child_path(const std::filesystem::path& root, const std::filesystem::path& child)
{
    auto root_it = root.begin();
    auto child_it = child.begin();
    for (; root_it != root.end(); ++root_it, ++child_it) {
        if (child_it == child.end())
            return false;
        if (lower_ascii(root_it->string()) != lower_ascii(child_it->string()))
            return false;
    }
    return true;
}

bool read_file_limited(const std::filesystem::path& path, uint64_t max_bytes, std::vector<uint8_t>& out, std::string& error)
{
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) {
        error = "mapped path is not a regular file";
        return false;
    }
    const uintmax_t size = std::filesystem::file_size(path, ec);
    if (ec) {
        error = "failed to stat mapped file";
        return false;
    }
    if (size > max_bytes) {
        error = "mapped file exceeds configured byte limit";
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "failed to open mapped file";
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    if (!in.good() && !in.eof()) {
        error = "failed to read mapped file";
        return false;
    }
    return true;
}

std::vector<uint8_t> build_response(uint16_t status, const std::string& reason, const std::string& content_type, const std::vector<uint8_t>& body)
{
    std::ostringstream head;
    head << "HTTP/1.1 " << status << ' ' << (reason.empty() ? "OK" : reason) << "\r\n";
    head << "Content-Length: " << body.size() << "\r\n";
    if (!content_type.empty())
        head << "Content-Type: " << content_type << "\r\n";
    head << "Connection: close\r\n\r\n";
    std::string h = head.str();
    std::vector<uint8_t> out(h.begin(), h.end());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

std::filesystem::path resolve_local_path(const local_rule& rule, const std::string& url, std::string& error)
{
    std::error_code ec;
    std::filesystem::path configured(rule.local_path);
    if (rule.kind == local_rule_kind::exact_file) {
        auto canonical = std::filesystem::weakly_canonical(configured, ec);
        if (ec) {
            error = "failed to canonicalize mapped file";
            return {};
        }
        return canonical;
    }
    auto root = std::filesystem::weakly_canonical(configured, ec);
    if (ec) {
        error = "failed to canonicalize mapped root";
        return {};
    }
    std::string suffix = url.size() > rule.url_prefix.size() ? url.substr(rule.url_prefix.size()) : std::string();
    const size_t query = suffix.find('?');
    if (query != std::string::npos)
        suffix.resize(query);
    while (!suffix.empty() && (suffix[0] == '/' || suffix[0] == '\\'))
        suffix.erase(suffix.begin());
    suffix = url_decode_path(suffix);
    if (suspicious_relative_path(suffix)) {
        error = "mapped URL suffix is outside the configured local root";
        return {};
    }
    auto target = std::filesystem::weakly_canonical(root / std::filesystem::path(suffix), ec);
    if (ec) {
        error = "failed to canonicalize mapped target";
        return {};
    }
    if (!is_child_path(root, target)) {
        error = "mapped target escaped the configured local root";
        return {};
    }
    return target;
}

std::vector<uint8_t> replace_request_target(const std::vector<uint8_t>& raw_request,
                                            const std::string& path_query,
                                            const std::string& host_header,
                                            bool update_host_header)
{
    std::vector<uint8_t> source = raw_request;
    auto parsed = protocol_parser::parse_http_request(source.data(), source.size());
    if (!parsed.valid)
        return {};
    std::ostringstream out;
    out << parsed.method << ' ' << (path_query.empty() ? "/" : path_query) << ' '
        << (parsed.version.empty() ? "HTTP/1.1" : parsed.version) << "\r\n";
    bool host_seen = false;
    for (const auto& h : parsed.headers) {
        if (lower_ascii(h.name) == "host") {
            host_seen = true;
            if (update_host_header)
                out << h.name << ": " << host_header << "\r\n";
            else
                out << h.name << ": " << h.value << "\r\n";
        } else {
            out << h.name << ": " << h.value << "\r\n";
        }
    }
    if (!host_seen && update_host_header)
        out << "Host: " << host_header << "\r\n";
    out << "\r\n";
    std::string head = out.str();
    std::vector<uint8_t> rewritten(head.begin(), head.end());
    rewritten.insert(rewritten.end(), parsed.body.begin(), parsed.body.end());
    return rewritten;
}

}

uint64_t add_local_rule(const local_rule& rule)
{
    auto& s = state();
    local_rule copy = rule;
    if (copy.id == 0)
        copy.id = s.next_id.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(s.mutex);
    s.local_rules.push_back(std::move(copy));
    return s.local_rules.back().id;
}

uint64_t add_remote_rule(const remote_rule& rule)
{
    auto& s = state();
    remote_rule copy = rule;
    if (copy.id == 0)
        copy.id = s.next_id.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(s.mutex);
    s.remote_rules.push_back(std::move(copy));
    return s.remote_rules.back().id;
}

bool remove_local_rule(uint64_t id)
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    auto it = std::remove_if(s.local_rules.begin(), s.local_rules.end(), [id](const local_rule& rule) {
        return rule.id == id;
    });
    if (it == s.local_rules.end())
        return false;
    s.local_rules.erase(it, s.local_rules.end());
    return true;
}

bool remove_remote_rule(uint64_t id)
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    auto it = std::remove_if(s.remote_rules.begin(), s.remote_rules.end(), [id](const remote_rule& rule) {
        return rule.id == id;
    });
    if (it == s.remote_rules.end())
        return false;
    s.remote_rules.erase(it, s.remote_rules.end());
    return true;
}

void clear_local_rules()
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    s.local_rules.clear();
}

void clear_remote_rules()
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    s.remote_rules.clear();
}

std::vector<local_rule> list_local_rules()
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    return s.local_rules;
}

std::vector<remote_rule> list_remote_rules()
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    return s.remote_rules;
}

local_result try_local(const mitm_proxy::http_exchange& exchange)
{
    local_result result;
    const std::string url = exchange_url(exchange);
    std::vector<local_rule> rules = list_local_rules();
    for (const auto& rule : rules) {
        if (!rule.enabled || rule.url_prefix.empty() || rule.local_path.empty() || !starts_with(url, rule.url_prefix))
            continue;
        std::string error;
        std::filesystem::path path = resolve_local_path(rule, url, error);
        if (path.empty()) {
            result.matched = true;
            result.rule_id = rule.id;
            result.label = rule.label;
            result.error = error;
            return result;
        }
        std::vector<uint8_t> body;
        if (!read_file_limited(path, rule.max_bytes, body, error)) {
            result.matched = true;
            result.rule_id = rule.id;
            result.label = rule.label;
            result.error = error;
            return result;
        }
        result.matched = true;
        result.rule_id = rule.id;
        result.label = rule.label;
        std::string type = rule.content_type.empty() ? content_type_for_path(path.string()) : rule.content_type;
        result.raw_response = build_response(rule.status_code, rule.reason, type, body);
        result.tags = rule.tags;
        if (std::find(result.tags.begin(), result.tags.end(), "map-local") == result.tags.end())
            result.tags.push_back("map-local");
        return result;
    }
    return result;
}

remote_result try_remote(const mitm_proxy::http_exchange& exchange, const std::vector<uint8_t>& raw_request)
{
    remote_result result;
    const std::string url = exchange_url(exchange);
    std::vector<remote_rule> rules = list_remote_rules();
    for (const auto& rule : rules) {
        if (!rule.enabled || rule.url_prefix.empty() || rule.remote_prefix.empty() || !starts_with(url, rule.url_prefix))
            continue;
        const std::string suffix = url.substr(rule.url_prefix.size());
        const std::string rewritten_url = rule.remote_prefix + suffix;
        bool tls = false;
        std::string host;
        uint16_t port = 0;
        std::string path_query;
        if (!parse_url(rewritten_url, tls, host, port, path_query)) {
            result.matched = true;
            result.rule_id = rule.id;
            result.label = rule.label;
            result.error = "remote map target URL is invalid";
            return result;
        }
        std::string host_header = host;
        if ((tls && port != 443) || (!tls && port != 80))
            host_header += ":" + std::to_string(port);
        std::vector<uint8_t> request = raw_request.empty() ? flow_serializer::build_raw_request(exchange) : raw_request;
        std::vector<uint8_t> rewritten = replace_request_target(request, path_query, host_header, rule.update_host_header);
        if (rewritten.empty()) {
            result.matched = true;
            result.rule_id = rule.id;
            result.label = rule.label;
            result.error = "failed to rewrite mapped request";
            return result;
        }
        result.matched = true;
        result.rule_id = rule.id;
        result.label = rule.label;
        result.host = host;
        result.port = port;
        result.use_tls = tls;
        result.raw_request = std::move(rewritten);
        result.tags = rule.tags;
        if (std::find(result.tags.begin(), result.tags.end(), "map-remote") == result.tags.end())
            result.tags.push_back("map-remote");
        return result;
    }
    return result;
}

std::string exchange_url(const mitm_proxy::http_exchange& exchange)
{
    const std::string scheme = exchange.is_tls ? "https" : "http";
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

std::string content_type_for_path(const std::string& path)
{
    static const std::unordered_map<std::string, std::string> types = {
        {".html", "text/html; charset=utf-8"},
        {".htm", "text/html; charset=utf-8"},
        {".css", "text/css; charset=utf-8"},
        {".js", "application/javascript; charset=utf-8"},
        {".mjs", "application/javascript; charset=utf-8"},
        {".json", "application/json; charset=utf-8"},
        {".xml", "application/xml; charset=utf-8"},
        {".txt", "text/plain; charset=utf-8"},
        {".svg", "image/svg+xml"},
        {".png", "image/png"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".gif", "image/gif"},
        {".webp", "image/webp"},
        {".ico", "image/x-icon"},
        {".wasm", "application/wasm"},
        {".pdf", "application/pdf"},
        {".bin", "application/octet-stream"}
    };
    const std::string ext = lower_ascii(std::filesystem::path(path).extension().string());
    auto it = types.find(ext);
    return it == types.end() ? std::string("application/octet-stream") : it->second;
}

}
