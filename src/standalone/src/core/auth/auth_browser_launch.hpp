#pragma once

#include <array>
#include <atomic>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "anti-tamper/webhook.hpp"
#include "../infra/executor.hpp"
#include "../network/burp/camoufox_bridge.hpp"

namespace aida {
namespace auth {

inline constexpr std::uint64_t kBrowserExternalOperationDeadlineMs = 180000;
inline constexpr int kBrowserExternalNavigationTimeoutMs = 45000;
inline constexpr std::size_t kBrowserExternalMaximumUrlBytes = 8192;
inline constexpr std::uint32_t kBrowserExternalMaximumInFlight = 4;

enum class browser_open_result_t : std::uint8_t {
    opened = 0,
    queued,
    invalid_url,
    queue_rejected,
    cancelled,
    deadline_expired,
    ensure_ready_failed,
    navigate_failed,
    exception
};

struct browser_open_completion_t {
    browser_open_result_t result = browser_open_result_t::exception;
    std::uint64_t request_id = 0;
    std::uint64_t elapsed_ms = 0;

    bool opened() const noexcept { return result == browser_open_result_t::opened; }
};

using browser_open_completion_handler_t = std::function<void(const browser_open_completion_t&)>;

struct browser_open_submission_t {
    bool submitted = false;
    std::uint64_t task_id = 0;
    std::uint64_t request_id = 0;
    browser_open_result_t result = browser_open_result_t::queue_rejected;
    std::string reject_reason;
};

struct canonical_external_url_t {
    bool accepted = false;
    std::string value;
    std::string reason;
};

namespace detail {

inline std::atomic<std::uint64_t> g_browser_request_id{0};
inline std::atomic<std::uint32_t> g_browser_physical_in_flight{0};
inline std::atomic<unsigned> g_browser_fixture_failure{0};

inline bool consume_browser_fixture_failure(unsigned expected_value) noexcept
{
    return g_browser_fixture_failure.compare_exchange_strong(expected_value, 0,
        std::memory_order_acq_rel, std::memory_order_acquire);
}

inline const char* browser_result_name(browser_open_result_t result) noexcept
{
    switch (result) {
    case browser_open_result_t::opened: return "opened";
    case browser_open_result_t::queued: return "queued";
    case browser_open_result_t::invalid_url: return "invalid_url";
    case browser_open_result_t::queue_rejected: return "queue_rejected";
    case browser_open_result_t::cancelled: return "cancelled";
    case browser_open_result_t::deadline_expired: return "deadline_expired";
    case browser_open_result_t::ensure_ready_failed: return "ensure_ready_failed";
    case browser_open_result_t::navigate_failed: return "navigate_failed";
    case browser_open_result_t::exception: return "exception";
    default: return "unknown";
    }
}

inline void default_browser_log(const std::string& message)
{
    const std::string line = std::string("[aida.auth.browser] ") + message;
    anti_tamper::webhook::write_log("auth.browser", line.c_str());
}

struct browser_operation_adapter_t {
    std::function<bool()> ensure_ready;
    std::function<bool(const std::string&, const char*, int)> navigate;
    std::function<void(const std::string&)> log;
};

inline browser_operation_adapter_t production_browser_operation_adapter()
{
    browser_operation_adapter_t adapter;
    adapter.ensure_ready = []() { return aida::burp::camoufox::ensure_ready(); };
    adapter.navigate = [](const std::string& url, const char* wait_until, int timeout_ms) {
        return aida::burp::camoufox::navigate(url, wait_until, timeout_ms);
    };
    adapter.log = [](const std::string& message) { default_browser_log(message); };
    return adapter;
}

inline std::mutex& browser_adapter_mutex()
{
    static std::mutex value;
    return value;
}

inline browser_operation_adapter_t& browser_adapter_ref()
{
    static browser_operation_adapter_t value = production_browser_operation_adapter();
    return value;
}

inline browser_operation_adapter_t browser_adapter_snapshot()
{
    std::lock_guard<std::mutex> lock(browser_adapter_mutex());
    return browser_adapter_ref();
}

inline void browser_log_noexcept(const std::string& message) noexcept
{
    try {
        const browser_operation_adapter_t adapter = browser_adapter_snapshot();
        if (!adapter.log) return;
        const std::function<void()> guarded = [&]() { adapter.log(message); };
        aida::infra::win_thread::run_function_seh_guarded(guarded);
    } catch (...) {
    }
}

inline std::uint64_t next_browser_request_id() noexcept
{
    return g_browser_request_id.fetch_add(1, std::memory_order_acq_rel) + 1;
}

inline bool valid_utf8(const std::string& input) noexcept
{
    std::size_t i = 0;
    while (i < input.size()) {
        const unsigned char lead = static_cast<unsigned char>(input[i++]);
        if (lead < 0x80) continue;
        std::uint32_t value = 0;
        std::size_t count = 0;
        if (lead >= 0xC2 && lead <= 0xDF) {
            value = lead & 0x1F;
            count = 1;
        } else if (lead >= 0xE0 && lead <= 0xEF) {
            value = lead & 0x0F;
            count = 2;
        } else if (lead >= 0xF0 && lead <= 0xF4) {
            value = lead & 0x07;
            count = 3;
        } else {
            return false;
        }
        if (i + count > input.size()) return false;
        for (std::size_t n = 0; n < count; ++n) {
            const unsigned char next = static_cast<unsigned char>(input[i++]);
            if ((next & 0xC0) != 0x80) return false;
            value = (value << 6) | (next & 0x3F);
        }
        if ((count == 2 && value < 0x800) || (count == 3 && value < 0x10000)
            || value > 0x10FFFF || (value >= 0xD800 && value <= 0xDFFF)) return false;
    }
    return true;
}

inline int hex_value(unsigned char value) noexcept
{
    if (value >= '0' && value <= '9') return static_cast<int>(value - '0');
    if (value >= 'a' && value <= 'f') return static_cast<int>(value - 'a') + 10;
    if (value >= 'A' && value <= 'F') return static_cast<int>(value - 'A') + 10;
    return -1;
}

inline bool parse_ipv4(const std::string& input, std::array<std::uint8_t, 4>& bytes) noexcept
{
    std::size_t cursor = 0;
    for (std::size_t part = 0; part < bytes.size(); ++part) {
        const std::size_t end = input.find('.', cursor);
        const std::size_t stop = end == std::string::npos ? input.size() : end;
        if (stop == cursor || stop - cursor > 3) return false;
        if (stop - cursor > 1 && input[cursor] == '0') return false;
        unsigned value = 0;
        for (std::size_t i = cursor; i < stop; ++i) {
            const unsigned char ch = static_cast<unsigned char>(input[i]);
            if (ch < '0' || ch > '9') return false;
            value = value * 10u + static_cast<unsigned>(ch - '0');
        }
        if (value > 255u) return false;
        bytes[part] = static_cast<std::uint8_t>(value);
        if (part + 1 < bytes.size()) {
            if (end == std::string::npos) return false;
            cursor = end + 1;
        } else if (end != std::string::npos) {
            return false;
        }
    }
    return true;
}

inline std::string canonical_ipv4(const std::array<std::uint8_t, 4>& bytes)
{
    return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + "."
        + std::to_string(bytes[2]) + "." + std::to_string(bytes[3]);
}

inline bool parse_ipv6_piece(const std::string& piece, std::vector<std::uint16_t>& words,
	bool allow_ipv4)
{
    if (piece.empty()) return true;
    std::size_t cursor = 0;
    while (cursor <= piece.size()) {
        const std::size_t end = piece.find(':', cursor);
        const std::size_t stop = end == std::string::npos ? piece.size() : end;
        if (stop == cursor) return false;
        const std::string token = piece.substr(cursor, stop - cursor);
        if (token.find('.') != std::string::npos) {
            if (!allow_ipv4 || end != std::string::npos) return false;
            std::array<std::uint8_t, 4> bytes{};
            if (!parse_ipv4(token, bytes)) return false;
            words.push_back(static_cast<std::uint16_t>((bytes[0] << 8) | bytes[1]));
            words.push_back(static_cast<std::uint16_t>((bytes[2] << 8) | bytes[3]));
        } else {
            if (token.size() > 4) return false;
            unsigned value = 0;
            for (unsigned char ch : token) {
                const int digit = hex_value(ch);
                if (digit < 0) return false;
                value = (value << 4) | static_cast<unsigned>(digit);
            }
            words.push_back(static_cast<std::uint16_t>(value));
        }
        if (end == std::string::npos) break;
        cursor = end + 1;
    }
    return true;
}

inline bool parse_ipv6(const std::string& input, std::array<std::uint16_t, 8>& output)
{
    if (input.empty()) return false;
    const std::size_t compression = input.find("::");
    if (compression != std::string::npos && input.find("::", compression + 2) != std::string::npos)
        return false;
    std::vector<std::uint16_t> left;
    std::vector<std::uint16_t> right;
    if (compression == std::string::npos) {
        if (!parse_ipv6_piece(input, left, true) || left.size() != 8) return false;
    } else {
        if (!parse_ipv6_piece(input.substr(0, compression), left, false)) return false;
        if (!parse_ipv6_piece(input.substr(compression + 2), right, true)) return false;
        if (left.size() + right.size() >= 8) return false;
    }
    output.fill(0);
    for (std::size_t i = 0; i < left.size(); ++i) output[i] = left[i];
    for (std::size_t i = 0; i < right.size(); ++i) output[8 - right.size() + i] = right[i];
    return true;
}

inline std::string canonical_ipv6(const std::array<std::uint16_t, 8>& words)
{
    std::size_t best_begin = words.size();
    std::size_t best_count = 0;
    for (std::size_t i = 0; i < words.size();) {
        if (words[i] != 0) {
            ++i;
            continue;
        }
        std::size_t end = i;
        while (end < words.size() && words[end] == 0) ++end;
        if (end - i > best_count && end - i >= 2) {
            best_begin = i;
            best_count = end - i;
        }
        i = end;
    }
    std::string out;
    for (std::size_t i = 0; i < words.size();) {
        if (i == best_begin) {
            out += "::";
            i += best_count;
            continue;
        }
        if (!out.empty() && out.back() != ':') out.push_back(':');
        char buffer[8]{};
        std::snprintf(buffer, sizeof(buffer), "%x", static_cast<unsigned>(words[i]));
        out += buffer;
        ++i;
    }
    return out.empty() ? std::string("::") : out;
}

inline bool canonicalize_dns_host(std::string input, std::string& output)
{
    if (!input.empty() && input.back() == '.') input.pop_back();
    if (input.empty() || input.size() > 253) return false;
    output.clear();
    output.reserve(input.size());
    std::size_t cursor = 0;
    while (cursor < input.size()) {
        const std::size_t end = input.find('.', cursor);
        const std::size_t stop = end == std::string::npos ? input.size() : end;
        const std::size_t count = stop - cursor;
        if (count == 0 || count > 63 || input[cursor] == '-' || input[stop - 1] == '-') return false;
        if (!output.empty()) output.push_back('.');
        for (std::size_t i = cursor; i < stop; ++i) {
            const unsigned char ch = static_cast<unsigned char>(input[i]);
            if (!(std::isalnum(ch) || ch == '-')) return false;
            output.push_back(static_cast<char>(std::tolower(ch)));
        }
        if (end == std::string::npos) break;
        cursor = end + 1;
    }
    return true;
}

inline bool parse_port(const std::string& input, std::uint16_t& output) noexcept
{
    if (input.empty() || input.size() > 5) return false;
    unsigned value = 0;
    for (unsigned char ch : input) {
        if (ch < '0' || ch > '9') return false;
        value = value * 10u + static_cast<unsigned>(ch - '0');
    }
    if (value == 0 || value > 65535u) return false;
    output = static_cast<std::uint16_t>(value);
    return true;
}

inline bool unreserved(unsigned char ch) noexcept
{
    return std::isalnum(ch) || ch == '-' || ch == '.' || ch == '_' || ch == '~';
}

inline bool normalize_component(const std::string& input, std::string& output)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    output.clear();
    output.reserve(input.size());
    std::string decoded;
    decoded.reserve(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        const unsigned char ch = static_cast<unsigned char>(input[i]);
        if (ch == '%') {
            if (i + 2 >= input.size()) return false;
            const int hi = hex_value(static_cast<unsigned char>(input[i + 1]));
            const int lo = hex_value(static_cast<unsigned char>(input[i + 2]));
            if (hi < 0 || lo < 0) return false;
            const unsigned char value = static_cast<unsigned char>((hi << 4) | lo);
            if (value == 0 || value < 0x20 || value == 0x7F || value == '\\') return false;
            decoded.push_back(static_cast<char>(value));
            if (unreserved(value)) {
                output.push_back(static_cast<char>(value));
            } else {
                output.push_back('%');
                output.push_back(hex[value >> 4]);
                output.push_back(hex[value & 0x0F]);
            }
            i += 2;
        } else {
            if (ch == 0 || ch < 0x20 || ch == 0x7F || ch == '\\') return false;
            decoded.push_back(static_cast<char>(ch));
            output.push_back(static_cast<char>(ch));
        }
    }
    return valid_utf8(decoded);
}

inline std::string remove_dot_segments(const std::string& path)
{
    std::vector<std::string> segments;
    std::size_t cursor = 1;
    bool trailing = path.size() > 1 && path.back() == '/';
    while (cursor <= path.size()) {
        const std::size_t end = path.find('/', cursor);
        const std::size_t stop = end == std::string::npos ? path.size() : end;
        const std::string segment = path.substr(cursor, stop - cursor);
        if (segment == "..") {
            if (!segments.empty()) segments.pop_back();
            trailing = true;
        } else if (segment == ".") {
            trailing = true;
        } else {
            segments.push_back(segment);
        }
        if (end == std::string::npos) break;
        cursor = end + 1;
    }
    std::string out = "/";
    for (std::size_t i = 0; i < segments.size(); ++i) {
        if (i != 0) out.push_back('/');
        out += segments[i];
    }
    if (trailing && out.back() != '/') out.push_back('/');
    return out;
}

inline canonical_external_url_t canonicalize_url_impl(const std::string& input)
{
    canonical_external_url_t result;
    if (input.empty()) {
        result.reason = "empty_url";
        return result;
    }
    if (input.size() > kBrowserExternalMaximumUrlBytes) {
        result.reason = "url_too_large";
        return result;
    }
    if (!valid_utf8(input)) {
        result.reason = "url_invalid_utf8";
        return result;
    }
    for (unsigned char ch : input) {
        if (ch == 0 || ch <= 0x20 || ch == 0x7F || ch == '\\') {
            result.reason = "url_forbidden_character";
            return result;
        }
    }
    const std::size_t scheme_end = input.find(':');
    if (scheme_end == std::string::npos || scheme_end + 2 >= input.size()
        || input[scheme_end + 1] != '/' || input[scheme_end + 2] != '/') {
        result.reason = "url_missing_authority_scheme";
        return result;
    }
    std::string scheme = input.substr(0, scheme_end);
    for (char& ch : scheme) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    if (scheme != "http" && scheme != "https") {
        result.reason = "url_scheme_not_allowed";
        return result;
    }
    const std::size_t authority_begin = scheme_end + 3;
    const std::size_t authority_end = input.find_first_of("/?#", authority_begin);
    const std::size_t authority_stop = authority_end == std::string::npos ? input.size() : authority_end;
    const std::string authority = input.substr(authority_begin, authority_stop - authority_begin);
    if (authority.empty() || authority.find('@') != std::string::npos) {
        result.reason = "url_authority_invalid";
        return result;
    }
    std::string host;
    std::string port_text;
    bool port_present = false;
    bool ipv6 = false;
    if (authority.front() == '[') {
        const std::size_t close = authority.find(']');
        if (close == std::string::npos || close == 1) {
            result.reason = "url_ipv6_invalid";
            return result;
        }
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') {
                result.reason = "url_authority_invalid";
                return result;
            }
            port_text = authority.substr(close + 2);
            port_present = true;
        }
        std::array<std::uint16_t, 8> words{};
        if (!parse_ipv6(authority.substr(1, close - 1), words)) {
            result.reason = "url_ipv6_invalid";
            return result;
        }
        host = canonical_ipv6(words);
        ipv6 = true;
    } else {
        const std::size_t colon = authority.rfind(':');
        std::string raw_host = authority;
        if (colon != std::string::npos) {
            if (authority.find(':') != colon) {
                result.reason = "url_ipv6_brackets_required";
                return result;
            }
            raw_host = authority.substr(0, colon);
            port_text = authority.substr(colon + 1);
            port_present = true;
        }
        std::array<std::uint8_t, 4> bytes{};
        if (parse_ipv4(raw_host, bytes)) {
            host = canonical_ipv4(bytes);
        } else if (raw_host.find_first_not_of("0123456789.") == std::string::npos) {
            result.reason = "url_ipv4_invalid";
            return result;
        } else if (!canonicalize_dns_host(raw_host, host)) {
            result.reason = "url_host_invalid";
            return result;
        }
    }
    std::uint16_t port = 0;
    if (port_present && !parse_port(port_text, port)) {
        result.reason = "url_port_invalid";
        return result;
    }
    const bool default_port = (scheme == "http" && port == 80) || (scheme == "https" && port == 443);
    std::size_t path_end = input.find_first_of("?#", authority_stop);
    const std::size_t path_stop = path_end == std::string::npos ? input.size() : path_end;
    std::string raw_path = authority_stop < input.size() && input[authority_stop] == '/'
        ? input.substr(authority_stop, path_stop - authority_stop) : std::string("/");
    std::string path;
    if (!normalize_component(raw_path, path)) {
        result.reason = "url_path_encoding_invalid";
        return result;
    }
    path = remove_dot_segments(path);
    std::string suffix;
    if (path_end != std::string::npos && input[path_end] == '?') {
        const std::size_t fragment = input.find('#', path_end + 1);
        const std::size_t query_stop = fragment == std::string::npos ? input.size() : fragment;
        std::string query;
        if (!normalize_component(input.substr(path_end + 1, query_stop - path_end - 1), query)) {
            result.reason = "url_query_encoding_invalid";
            return result;
        }
        suffix.push_back('?');
        suffix += query;
        path_end = fragment;
    }
    if (path_end != std::string::npos && input[path_end] == '#') {
        std::string fragment;
        if (!normalize_component(input.substr(path_end + 1), fragment)) {
            result.reason = "url_fragment_encoding_invalid";
            return result;
        }
        suffix.push_back('#');
        suffix += fragment;
    }
    result.value = scheme + "://" + (ipv6 ? "[" + host + "]" : host);
    if (port != 0 && !default_port) result.value += ":" + std::to_string(port);
    result.value += path;
    result.value += suffix;
    result.accepted = true;
    return result;
}

inline bool try_acquire_physical_capacity() noexcept
{
    std::uint32_t current = g_browser_physical_in_flight.load(std::memory_order_acquire);
    while (current < kBrowserExternalMaximumInFlight) {
        if (g_browser_physical_in_flight.compare_exchange_weak(current, current + 1,
            std::memory_order_acq_rel, std::memory_order_acquire)) return true;
    }
    return false;
}

inline void release_physical_capacity() noexcept
{
    std::uint32_t current = g_browser_physical_in_flight.load(std::memory_order_acquire);
    while (current != 0 && !g_browser_physical_in_flight.compare_exchange_weak(current, current - 1,
        std::memory_order_acq_rel, std::memory_order_acquire)) {
    }
}

inline std::uint64_t bounded_deadline(std::uint64_t now, std::uint64_t budget) noexcept
{
    return now > (std::numeric_limits<std::uint64_t>::max)() - budget
        ? (std::numeric_limits<std::uint64_t>::max)() : now + budget;
}

inline browser_open_completion_t execute_browser_open(const std::string& canonical_url,
    std::uint64_t request_id, std::uint64_t deadline_ms, const std::atomic<bool>* cancelled) noexcept
{
    const std::uint64_t started_ms = aida::infra::executor::now_ms();
    browser_open_result_t result = browser_open_result_t::exception;
    try {
        const browser_operation_adapter_t adapter = browser_adapter_snapshot();
        const std::function<void()> guarded = [&]() {
            if (cancelled && cancelled->load(std::memory_order_acquire)) {
                result = browser_open_result_t::cancelled;
                return;
            }
            if (deadline_ms != 0 && aida::infra::executor::now_ms() >= deadline_ms) {
                result = browser_open_result_t::deadline_expired;
                return;
            }
            if (!adapter.ensure_ready || !adapter.ensure_ready()) {
                result = browser_open_result_t::ensure_ready_failed;
                return;
            }
            if (cancelled && cancelled->load(std::memory_order_acquire)) {
                result = browser_open_result_t::cancelled;
                return;
            }
            const std::uint64_t before_navigation = aida::infra::executor::now_ms();
            if (deadline_ms != 0 && before_navigation >= deadline_ms) {
                result = browser_open_result_t::deadline_expired;
                return;
            }
            int timeout_ms = kBrowserExternalNavigationTimeoutMs;
            if (deadline_ms != 0) {
                const std::uint64_t remaining = deadline_ms - before_navigation;
                if (remaining == 0) {
                    result = browser_open_result_t::deadline_expired;
                    return;
                }
                if (remaining < static_cast<std::uint64_t>(timeout_ms))
                    timeout_ms = static_cast<int>(remaining);
            }
            result = adapter.navigate && adapter.navigate(canonical_url, "domcontentloaded", timeout_ms)
                ? browser_open_result_t::opened : browser_open_result_t::navigate_failed;
        };
        if (aida::infra::win_thread::run_function_seh_guarded(guarded) != 0)
            result = browser_open_result_t::exception;
    } catch (...) {
        result = browser_open_result_t::exception;
    }
    const std::uint64_t now = aida::infra::executor::now_ms();
    if (result != browser_open_result_t::opened && cancelled
        && cancelled->load(std::memory_order_acquire)) result = browser_open_result_t::cancelled;
    if (result != browser_open_result_t::opened && deadline_ms != 0 && now >= deadline_ms
        && result != browser_open_result_t::cancelled) result = browser_open_result_t::deadline_expired;
    return browser_open_completion_t{result, request_id, now >= started_ms ? now - started_ms : 0};
}

enum class async_phase_t : std::uint8_t { queued, running, cancelled_before_start, finished, rejected };

struct async_browser_open_state_t {
    std::atomic<bool> cancelled{false};
    std::atomic<bool> published{false};
    std::atomic<bool> physical_released{false};
    std::atomic<async_phase_t> phase{async_phase_t::queued};
    std::uint64_t request_id = 0;
    std::uint64_t submitted_ms = 0;
    std::uint64_t deadline_ms = 0;
    browser_open_completion_handler_t completion;
};

inline void release_state_capacity(const std::shared_ptr<async_browser_open_state_t>& state) noexcept
{
    if (state && !state->physical_released.exchange(true, std::memory_order_acq_rel))
        release_physical_capacity();
}

struct physical_state_guard_t {
    std::shared_ptr<async_browser_open_state_t> state;
    ~physical_state_guard_t() noexcept { release_state_capacity(state); }
};

inline void invoke_completion_noexcept(const browser_open_completion_handler_t& completion,
    const browser_open_completion_t& value) noexcept
{
    if (!completion) return;
    try {
        const std::function<void()> guarded = [&]() { completion(value); };
        aida::infra::win_thread::run_function_seh_guarded(guarded);
    } catch (...) {
    }
}

inline void publish_browser_completion(const std::shared_ptr<async_browser_open_state_t>& state,
    browser_open_result_t result, std::uint64_t elapsed_ms) noexcept
{
    if (!state) return;
    bool expected = false;
	if (!state->published.compare_exchange_strong(expected, true,
		std::memory_order_acq_rel, std::memory_order_acquire)) return;
	invoke_completion_noexcept(state->completion,
		browser_open_completion_t{result, state->request_id, elapsed_ms});
	try {
		browser_log_noexcept("CAMOUFOX-OPEN-TERMINAL request_id="
			+ std::to_string(state->request_id) + " result=" + browser_result_name(result)
			+ " elapsed_ms=" + std::to_string(elapsed_ms));
	} catch (...) {
	}
}

inline void cancel_async_state(const std::shared_ptr<async_browser_open_state_t>& state) noexcept
{
    if (!state) return;
    state->cancelled.store(true, std::memory_order_release);
    async_phase_t expected = async_phase_t::queued;
    if (state->phase.compare_exchange_strong(expected, async_phase_t::cancelled_before_start,
        std::memory_order_acq_rel, std::memory_order_acquire)) release_state_capacity(state);
    const std::uint64_t now = aida::infra::executor::now_ms();
    const browser_open_result_t result = state->deadline_ms != 0 && now >= state->deadline_ms
        ? browser_open_result_t::deadline_expired : browser_open_result_t::cancelled;
    publish_browser_completion(state, result, now >= state->submitted_ms ? now - state->submitted_ms : 0);
}

}

inline canonical_external_url_t canonicalize_external_url(const std::string& input)
{
    try {
        return detail::canonicalize_url_impl(input);
    } catch (...) {
        canonical_external_url_t result;
        result.reason = "url_canonicalization_exception";
        return result;
    }
}

inline std::uint32_t browser_physical_in_flight() noexcept
{
    return detail::g_browser_physical_in_flight.load(std::memory_order_acquire);
}

inline bool open_url_external_until(const std::string& url, std::uint64_t absolute_deadline_ms) noexcept
{
	try {
		const std::uint64_t request_id = detail::next_browser_request_id();
		const canonical_external_url_t canonical = canonicalize_external_url(url);
		if (!canonical.accepted) {
			detail::browser_log_noexcept("CAMOUFOX-OPEN-REJECT request_id=" + std::to_string(request_id)
				+ " reason=" + canonical.reason + " url_bytes=" + std::to_string(url.size()));
			return false;
		}
		if (!detail::try_acquire_physical_capacity()) {
			detail::browser_log_noexcept("CAMOUFOX-OPEN-REJECT request_id=" + std::to_string(request_id)
				+ " reason=browser_capacity_exhausted");
			return false;
		}
		struct guard_t { ~guard_t() noexcept { detail::release_physical_capacity(); } } guard;
		const std::uint64_t now = aida::infra::executor::now_ms();
		const std::uint64_t deadline = absolute_deadline_ms == 0
			? detail::bounded_deadline(now, kBrowserExternalOperationDeadlineMs)
			: absolute_deadline_ms;
		return detail::execute_browser_open(canonical.value, request_id, deadline, nullptr).opened();
	} catch (...) {
		return false;
	}
}

inline bool open_url_external(const std::string& url) noexcept
{
    return open_url_external_until(url, 0);
}

inline browser_open_submission_t submit_open_url_external_until(std::string url,
    std::uint64_t absolute_deadline_ms, browser_open_completion_handler_t completion = {})
{
	browser_open_submission_t output;
	output.request_id = detail::next_browser_request_id();
	canonical_external_url_t canonical;
	try {
		canonical = canonicalize_external_url(url);
	} catch (...) {
		output.result = browser_open_result_t::invalid_url;
		detail::invoke_completion_noexcept(completion,
			browser_open_completion_t{output.result, output.request_id, 0});
		try { output.reject_reason = "url_canonicalization_exception"; } catch (...) {}
		return output;
	}
	if (!canonical.accepted) {
		output.result = browser_open_result_t::invalid_url;
		detail::invoke_completion_noexcept(completion,
			browser_open_completion_t{output.result, output.request_id, 0});
		try { output.reject_reason = canonical.reason; } catch (...) {}
		return output;
    }
    std::shared_ptr<detail::async_browser_open_state_t> state;
    try {
        if (detail::consume_browser_fixture_failure(1))
            throw std::bad_alloc();
        state = std::make_shared<detail::async_browser_open_state_t>();
        state->request_id = output.request_id;
        state->submitted_ms = aida::infra::executor::now_ms();
        state->deadline_ms = absolute_deadline_ms == 0
            ? detail::bounded_deadline(state->submitted_ms, kBrowserExternalOperationDeadlineMs)
            : absolute_deadline_ms;
        state->completion = std::move(completion);
	} catch (...) {
		output.result = browser_open_result_t::queue_rejected;
		detail::invoke_completion_noexcept(completion,
			browser_open_completion_t{output.result, output.request_id, 0});
		try { output.reject_reason = "browser_state_allocation_failed"; } catch (...) {}
		return output;
    }
    if (!detail::try_acquire_physical_capacity()) {
		output.result = browser_open_result_t::queue_rejected;
		state->physical_released.store(true, std::memory_order_release);
		detail::publish_browser_completion(state, output.result, 0);
		try { output.reject_reason = "browser_capacity_exhausted"; } catch (...) {}
		return output;
    }
    try {
        if (detail::consume_browser_fixture_failure(2))
            throw std::runtime_error("fixture_submission_failure");
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "auth_browser";
        sub.label = "auth.browser.camoufox_open";
        sub.thread_class = "external_tool";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 2;
        sub.deadline_ms = state->deadline_ms;
        sub.capacity_lease = state->request_id;
        sub.no_capacity_reason = "browser_capacity_exhausted";
        sub.lease_token = state->request_id;
        sub.generation = state->request_id;
        sub.ui_access_policy = "none";
        sub.failure_policy = "publish_typed_failure";
        sub.shutdown_policy = "cancel_pending";
        sub.cancel_hook = [state]() noexcept { detail::cancel_async_state(state); };
        sub.body = [state, canonical_url = canonical.value]() noexcept {
            detail::async_phase_t expected = detail::async_phase_t::queued;
            if (!state->phase.compare_exchange_strong(expected, detail::async_phase_t::running,
                std::memory_order_acq_rel, std::memory_order_acquire)) return;
            detail::physical_state_guard_t guard{state};
            const browser_open_completion_t value = detail::execute_browser_open(canonical_url,
                state->request_id, state->deadline_ms, &state->cancelled);
            state->phase.store(detail::async_phase_t::finished, std::memory_order_release);
            detail::publish_browser_completion(state, value.result, value.elapsed_ms);
        };
        const aida::infra::executor::submit_result_t submitted =
            aida::infra::executor::submit(std::move(sub));
        output.submitted = submitted.submitted;
        output.task_id = submitted.task_id;
		if (!submitted.submitted) {
			state->phase.store(detail::async_phase_t::rejected, std::memory_order_release);
			detail::release_state_capacity(state);
			output.result = browser_open_result_t::queue_rejected;
			detail::publish_browser_completion(state, output.result, 0);
			try {
				output.reject_reason = submitted.reject_reason.empty()
					? std::string("executor_rejected") : submitted.reject_reason;
			} catch (...) {
			}
			return output;
        }
    } catch (...) {
        state->phase.store(detail::async_phase_t::rejected, std::memory_order_release);
		detail::release_state_capacity(state);
		output.result = browser_open_result_t::queue_rejected;
		detail::publish_browser_completion(state, output.result, 0);
		try { output.reject_reason = "executor_submission_exception"; } catch (...) {}
		return output;
    }
	output.result = browser_open_result_t::queued;
	try {
		detail::browser_log_noexcept("CAMOUFOX-OPEN-QUEUE-ACCEPT request_id="
			+ std::to_string(output.request_id) + " task_id=" + std::to_string(output.task_id)
			+ " physical_in_flight=" + std::to_string(browser_physical_in_flight()));
	} catch (...) {
	}
	return output;
}

inline browser_open_submission_t submit_open_url_external(std::string url,
    browser_open_completion_handler_t completion = {})
{
    return submit_open_url_external_until(std::move(url), 0, std::move(completion));
}

inline bool cancel_open_url_external(std::uint64_t task_id) noexcept
{
    try {
        return task_id != 0 && aida::infra::executor::cancel(task_id);
    } catch (...) {
        return false;
    }
}

#if defined(AIDA_C03_AUTH_BROWSER_FIXTURE)
inline void install_browser_operation_fixture(detail::browser_operation_adapter_t adapter)
{
    std::lock_guard<std::mutex> lock(detail::browser_adapter_mutex());
    detail::browser_adapter_ref() = std::move(adapter);
}

inline void reset_browser_operation_fixture()
{
    std::lock_guard<std::mutex> lock(detail::browser_adapter_mutex());
    detail::browser_adapter_ref() = detail::production_browser_operation_adapter();
}

inline void inject_browser_fixture_failure(unsigned failure)
{
    detail::g_browser_fixture_failure.store(failure, std::memory_order_release);
}
#endif

}
}
