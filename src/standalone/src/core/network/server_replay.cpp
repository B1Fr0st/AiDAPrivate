#include "server_replay.hpp"

#include "flow_serializer.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <mutex>

namespace server_replay {
namespace {

struct state_t {
    std::mutex mutex;
    std::vector<match_rule> rules;
    std::atomic_bool enabled{false};
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

std::string path_query_from_uri(const std::string& uri)
{
    if (uri.rfind("http://", 0) == 0 || uri.rfind("https://", 0) == 0) {
        const size_t scheme = uri.find("://");
        const size_t slash = uri.find('/', scheme == std::string::npos ? 0 : scheme + 3);
        return slash == std::string::npos ? std::string("/") : uri.substr(slash);
    }
    return uri.empty() ? std::string("/") : uri;
}

std::vector<uint8_t> request_body(const mitm_proxy::http_exchange& exchange, const std::vector<uint8_t>& raw_request)
{
    if (!exchange.request.body.empty())
        return exchange.request.body;
    if (raw_request.empty())
        return {};
    auto parsed = protocol_parser::parse_http_request(raw_request.data(), raw_request.size());
    return parsed.body;
}

bool same_string_ci(const std::string& a, const std::string& b)
{
    return lower_ascii(a) == lower_ascii(b);
}

bool rule_matches(const match_rule& rule,
                  const mitm_proxy::http_exchange& exchange,
                  const std::vector<uint8_t>& raw_request)
{
    if (!rule.enabled)
        return false;
    if (!rule.method.empty() && !same_string_ci(rule.method, exchange.request.method))
        return false;
    const std::string scheme = exchange.is_tls ? "https" : "http";
    if (!rule.scheme.empty() && !same_string_ci(rule.scheme, scheme))
        return false;
    if (!rule.host.empty() && !same_string_ci(rule.host, exchange.target_host))
        return false;
    if (rule.port != 0 && rule.port != exchange.target_port)
        return false;
    if (!rule.path_query.empty() && rule.path_query != path_query_from_uri(exchange.request.uri))
        return false;
    if (rule.body_mode == body_match_mode::exact && rule.request_body != request_body(exchange, raw_request))
        return false;
    return true;
}

match_rule rule_from_exchange(const mitm_proxy::http_exchange& flow, const load_options& options)
{
    match_rule rule;
    rule.enabled = true;
    rule.label = flow.request.method + " " + flow.target_host + path_query_from_uri(flow.request.uri);
    if (options.match_method)
        rule.method = flow.request.method;
    if (options.match_scheme)
        rule.scheme = flow.is_tls ? "https" : "http";
    rule.host = flow.target_host;
    if (options.match_port)
        rule.port = flow.target_port;
    rule.path_query = path_query_from_uri(flow.request.uri);
    rule.body_mode = options.exact_body ? body_match_mode::exact : body_match_mode::ignore;
    rule.request_body = flow.request.body;
    rule.raw_response = flow_serializer::build_raw_response(flow);
    rule.tags = flow.tags;
    if (std::find(rule.tags.begin(), rule.tags.end(), "server-replay-source") == rule.tags.end())
        rule.tags.push_back("server-replay-source");
    return rule;
}

}

uint64_t add_rule(const match_rule& rule)
{
    auto& s = state();
    match_rule copy = rule;
    if (copy.id == 0)
        copy.id = s.next_id.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(s.mutex);
    s.rules.push_back(std::move(copy));
    return s.rules.back().id;
}

size_t load_from_flows(const std::vector<mitm_proxy::http_exchange>& flows, const load_options& options)
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    if (options.replace_existing)
        s.rules.clear();
    size_t added = 0;
    for (const auto& flow : flows) {
        if (flow.request.method.empty() || flow.target_host.empty() || flow.response.status_code <= 0)
            continue;
        match_rule rule = rule_from_exchange(flow, options);
        rule.id = s.next_id.fetch_add(1, std::memory_order_relaxed);
        s.rules.push_back(std::move(rule));
        ++added;
    }
    if (added > 0)
        s.enabled.store(true, std::memory_order_release);
    return added;
}

bool remove_rule(uint64_t id)
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    auto it = std::remove_if(s.rules.begin(), s.rules.end(), [id](const match_rule& rule) {
        return rule.id == id;
    });
    if (it == s.rules.end())
        return false;
    s.rules.erase(it, s.rules.end());
    return true;
}

void clear_rules()
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    s.rules.clear();
}

void set_enabled(bool enabled)
{
    state().enabled.store(enabled, std::memory_order_release);
}

bool is_enabled()
{
    return state().enabled.load(std::memory_order_acquire);
}

std::vector<match_rule> list_rules()
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    return s.rules;
}

match_result match(const mitm_proxy::http_exchange& exchange, const std::vector<uint8_t>& raw_request)
{
    match_result result;
    auto& s = state();
    if (!s.enabled.load(std::memory_order_acquire))
        return result;
    std::lock_guard<std::mutex> lock(s.mutex);
    for (const auto& rule : s.rules) {
        if (!rule_matches(rule, exchange, raw_request))
            continue;
        result.matched = true;
        result.rule_id = rule.id;
        result.label = rule.label;
        result.raw_response = rule.raw_response;
        result.tags = rule.tags;
        if (std::find(result.tags.begin(), result.tags.end(), "server-replay") == result.tags.end())
            result.tags.push_back("server-replay");
        return result;
    }
    return result;
}

}
