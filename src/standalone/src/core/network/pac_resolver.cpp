#include "pac_resolver.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <regex>
#include <sstream>

namespace mitm_proxy {
namespace pac_resolver {

namespace {

std::string trim(const std::string& s)
{
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a])))
        ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1])))
        --b;
    return s.substr(a, b - a);
}

std::string lower_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

bool parse_host_port(const std::string& in, std::string& host, uint16_t& port)
{
    std::string v = trim(in);
    if (v.empty())
        return false;
    if (v.front() == '[') {
        size_t rb = v.find(']');
        if (rb == std::string::npos || rb + 2 > v.size() || v[rb + 1] != ':')
            return false;
        host = v.substr(1, rb - 1);
        std::string p = v.substr(rb + 2);
        unsigned long n = std::strtoul(p.c_str(), nullptr, 10);
        if (n == 0 || n > 65535)
            return false;
        port = static_cast<uint16_t>(n);
        return true;
    }
    size_t colon = v.rfind(':');
    if (colon == std::string::npos)
        return false;
    host = trim(v.substr(0, colon));
    std::string p = trim(v.substr(colon + 1));
    if (host.empty() || p.empty())
        return false;
    unsigned long n = std::strtoul(p.c_str(), nullptr, 10);
    if (n == 0 || n > 65535)
        return false;
    port = static_cast<uint16_t>(n);
    return true;
}

std::string wildcard_to_regex(const std::string& pattern)
{
    std::string out;
    out.reserve(pattern.size() * 2 + 2);
    out.push_back('^');
    for (char ch : pattern) {
        switch (ch) {
        case '*': out += ".*"; break;
        case '?': out.push_back('.'); break;
        case '.': case '\\': case '+': case '(': case ')': case '[': case ']':
        case '{': case '}': case '^': case '$': case '|':
            out.push_back('\\');
            out.push_back(ch);
            break;
        default:
            out.push_back(ch);
            break;
        }
    }
    out.push_back('$');
    return out;
}

bool dns_domain_is(const std::string& host, const std::string& domain)
{
    std::string h = lower_ascii(host);
    std::string d = lower_ascii(domain);
    if (d.empty())
        return false;
    if (h == d)
        return true;
    if (d.front() != '.')
        d.insert(d.begin(), '.');
    return h.size() > d.size() && h.compare(h.size() - d.size(), d.size(), d) == 0;
}

bool sh_exp_match(const std::string& value, const std::string& pattern)
{
    try {
        return std::regex_match(value, std::regex(wildcard_to_regex(pattern), std::regex::icase));
    } catch (...) {
        return false;
    }
}

bool evaluate_condition(const std::string& condition, const std::string& url, const std::string& host)
{
    std::smatch m;
    static const std::regex sh_url(R"(shExpMatch\s*\(\s*url\s*,\s*["']([^"']+)["']\s*\))", std::regex::icase);
    static const std::regex sh_host(R"(shExpMatch\s*\(\s*host\s*,\s*["']([^"']+)["']\s*\))", std::regex::icase);
    static const std::regex dns_domain(R"(dnsDomainIs\s*\(\s*host\s*,\s*["']([^"']+)["']\s*\))", std::regex::icase);
    static const std::regex plain_host(R"(isPlainHostName\s*\(\s*host\s*\))", std::regex::icase);
    if (std::regex_search(condition, m, sh_url))
        return sh_exp_match(url, m[1].str());
    if (std::regex_search(condition, m, sh_host))
        return sh_exp_match(host, m[1].str());
    if (std::regex_search(condition, m, dns_domain))
        return dns_domain_is(host, m[1].str());
    if (std::regex_search(condition, plain_host))
        return host.find('.') == std::string::npos && host.find(':') == std::string::npos;
    return false;
}

pac_result make_failure(const std::string& error, bool fail_closed)
{
    pac_result r;
    r.supported = false;
    r.fail_closed = fail_closed;
    r.error = error;
    if (!fail_closed)
        r.entries.push_back(proxy_entry{proxy_entry_type::direct, {}, 0, "DIRECT"});
    return r;
}

}

const char* to_string(proxy_entry_type type)
{
    switch (type) {
    case proxy_entry_type::direct: return "DIRECT";
    case proxy_entry_type::http: return "PROXY";
    case proxy_entry_type::socks4: return "SOCKS4";
    case proxy_entry_type::socks5: return "SOCKS5";
    }
    return "UNKNOWN";
}

std::vector<proxy_entry> parse_proxy_list(const std::string& proxy_list, std::string* error)
{
    std::vector<proxy_entry> out;
    std::stringstream ss(proxy_list);
    std::string part;
    while (std::getline(ss, part, ';')) {
        std::string item = trim(part);
        if (item.empty())
            continue;
        std::string low = lower_ascii(item);
        if (low == "direct") {
            out.push_back(proxy_entry{proxy_entry_type::direct, {}, 0, item});
            continue;
        }
        proxy_entry entry;
        std::string endpoint;
        if (low.rfind("proxy ", 0) == 0 || low.rfind("http ", 0) == 0 || low.rfind("https ", 0) == 0) {
            entry.type = proxy_entry_type::http;
            endpoint = item.substr(item.find(' ') + 1);
        } else if (low.rfind("socks5 ", 0) == 0) {
            entry.type = proxy_entry_type::socks5;
            endpoint = item.substr(7);
        } else if (low.rfind("socks4 ", 0) == 0) {
            entry.type = proxy_entry_type::socks4;
            endpoint = item.substr(7);
        } else if (low.rfind("socks ", 0) == 0) {
            entry.type = proxy_entry_type::socks5;
            endpoint = item.substr(6);
        } else {
            if (error)
                *error = "unsupported PAC proxy token: " + item;
            out.clear();
            return out;
        }
        entry.raw = item;
        if (!parse_host_port(endpoint, entry.host, entry.port)) {
            if (error)
                *error = "invalid PAC proxy endpoint: " + item;
            out.clear();
            return out;
        }
        out.push_back(std::move(entry));
    }
    if (out.empty() && error)
        *error = "PAC proxy list is empty";
    return out;
}

pac_result resolve(const std::string& pac_script,
                   const std::string& url,
                   const std::string& host,
                   uint16_t,
                   bool fail_closed)
{
    if (pac_script.empty())
        return make_failure("PAC script is empty", fail_closed);

    pac_result result;
    result.fail_closed = fail_closed;

    std::smatch m;
    static const std::regex if_return(R"(if\s*\(([^)]*(?:\)[^)]*)?)\)\s*\{?\s*return\s+["']([^"']+)["']\s*;)", std::regex::icase);
    auto begin = std::sregex_iterator(pac_script.begin(), pac_script.end(), if_return);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        const std::string condition = (*it)[1].str();
        const std::string proxy_list = (*it)[2].str();
        if (!evaluate_condition(condition, url, host))
            continue;
        std::string error;
        auto entries = parse_proxy_list(proxy_list, &error);
        if (entries.empty())
            return make_failure(error, fail_closed);
        result.supported = true;
        result.matched = true;
        result.matched_rule = trim(condition);
        result.entries = std::move(entries);
        return result;
    }

    static const std::regex return_stmt(R"(return\s+["']([^"']+)["']\s*;)", std::regex::icase);
    std::string last_return;
    auto rb = std::sregex_iterator(pac_script.begin(), pac_script.end(), return_stmt);
    for (auto it = rb; it != end; ++it)
        last_return = (*it)[1].str();
    if (!last_return.empty()) {
        std::string error;
        auto entries = parse_proxy_list(last_return, &error);
        if (entries.empty())
            return make_failure(error, fail_closed);
        result.supported = true;
        result.matched = true;
        result.matched_rule = "default";
        result.entries = std::move(entries);
        return result;
    }

    return make_failure("PAC script has no supported return rule", fail_closed);
}

}
}
