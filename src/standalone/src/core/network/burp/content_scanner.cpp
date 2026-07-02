#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#ifdef small
#undef small
#endif

#include "content_scanner.hpp"

#include "audit_http.hpp"
#include "findings_db.hpp"
#include "issue.hpp"
#include "scope.hpp"
#include "site_map.hpp"

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")

namespace aida {
namespace burp {
namespace content_scanner {

namespace {

using json = nlohmann::json;

constexpr std::size_t kMaxBodyScanBytes = 2ull * 1024ull * 1024ull;
constexpr std::size_t kMaxFindingsPerExchange = 200;
constexpr std::size_t kMaxFindingsPerPattern = 40;

std::string lower_ascii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string trim_copy(std::string value)
{
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
        value.erase(value.begin());
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
        value.pop_back();
    return value;
}

std::string redact_url(std::string url)
{
    const std::size_t scheme = url.find("://");
    const std::size_t authority_start = scheme == std::string::npos ? 0 : scheme + 3;
    const std::size_t path_start = url.find_first_of("/?#", authority_start);
    const std::size_t authority_end = path_start == std::string::npos ? url.size() : path_start;
    const std::size_t at = url.find('@', authority_start);
    if (at != std::string::npos && at < authority_end)
        url.replace(authority_start, at - authority_start, "[REDACTED]");
    const std::size_t query = url.find('?', authority_start);
    if (query != std::string::npos)
        url.erase(query + 1).append("[REDACTED]");
    const std::size_t fragment = url.find('#', authority_start);
    if (fragment != std::string::npos)
        url.erase(fragment + 1).append("[REDACTED]");
    return url;
}

std::uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<std::uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::uint64_t fnv1a64(const void* data, std::size_t size)
{
    const auto* bytes = static_cast<const unsigned char*>(data);
    std::uint64_t h = 1469598103934665603ull;
    for (std::size_t i = 0; i < size; ++i) {
        h ^= bytes[i];
        h *= 1099511628211ull;
    }
    return h;
}

std::string hex_bytes(const std::vector<unsigned char>& bytes)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char b : bytes) {
        out.push_back(kHex[(b >> 4) & 0x0f]);
        out.push_back(kHex[b & 0x0f]);
    }
    return out;
}

std::string hex64(std::uint64_t value)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = kHex[value & 0x0f];
        value >>= 4;
    }
    return out;
}

std::string sha256_hex(const std::string& value)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_len = 0;
    DWORD hash_len = 0;
    DWORD cb = 0;
    std::vector<unsigned char> object;
    std::vector<unsigned char> digest;
    std::string out;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0) {
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_len), sizeof(object_len), &cb, 0) >= 0 &&
            BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &cb, 0) >= 0) {
            object.resize(object_len);
            digest.resize(hash_len);
            if (BCryptCreateHash(alg, &hash, object.data(), object_len, nullptr, 0, 0) >= 0 &&
                BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(value.data())), static_cast<ULONG>(value.size()), 0) >= 0 &&
                BCryptFinishHash(hash, digest.data(), hash_len, 0) >= 0) {
                out = hex_bytes(digest);
            }
        }
    }
    if (hash)
        BCryptDestroyHash(hash);
    if (alg)
        BCryptCloseAlgorithmProvider(alg, 0);
    if (out.empty())
        out = hex64(fnv1a64(value.data(), value.size()));
    return out;
}

std::string printable_context(std::string value)
{
    for (char& c : value) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7f)
            c = ' ';
    }
    return value;
}

std::string regex_replace_safe(const std::string& value, const std::regex& re, const std::string& replacement)
{
    try {
        return std::regex_replace(value, re, replacement);
    } catch (...) {
        return value;
    }
}

std::string scrub_sensitive_context(std::string value)
{
    value = regex_replace_safe(value, std::regex(R"((AKIA|ASIA)[0-9A-Z]{16})", std::regex::icase), "[REDACTED:AWS_KEY]");
    value = regex_replace_safe(value, std::regex(R"(AIza[0-9A-Za-z\-_]{20,})"), "[REDACTED:GOOGLE_KEY]");
    value = regex_replace_safe(value, std::regex(R"(gh[pousr]_[A-Za-z0-9_]{20,})"), "[REDACTED:GITHUB_TOKEN]");
    value = regex_replace_safe(value, std::regex(R"(sk_live_[0-9A-Za-z]{12,})"), "[REDACTED:STRIPE_SECRET]");
    value = regex_replace_safe(value, std::regex(R"(xox[baprs]-[0-9A-Za-z-]{10,})"), "[REDACTED:SLACK_TOKEN]");
    value = regex_replace_safe(value, std::regex(R"(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"), "[REDACTED:JWT]");
    value = regex_replace_safe(value, std::regex(R"(([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,}))", std::regex::icase), "[REDACTED:EMAIL]");
    value = regex_replace_safe(value, std::regex(R"((\d[ -]*){13,19})"), "[REDACTED:PAYMENT_CARD]");
    value = regex_replace_safe(value, std::regex(R"(\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)"), "[REDACTED:INTERNAL_IP]");
    value = regex_replace_safe(value, std::regex(R"((password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*["']?[^"'\s&;<>]{8,})", std::regex::icase), "$1=[REDACTED]");
    value = regex_replace_safe(value, std::regex(R"((Bearer|Basic)\s+[A-Za-z0-9+\/._\-:=]{10,})", std::regex::icase), "$1 [REDACTED]");
    return value;
}

std::string safe_context(const std::string& text, std::size_t offset, std::size_t length)
{
    const std::size_t left = offset > 64 ? offset - 64 : 0;
    const std::size_t right = std::min(text.size(), offset + length + 64);
    std::string before = text.substr(left, offset - left);
    std::string after = text.substr(offset + length, right - (offset + length));
    return scrub_sensitive_context(printable_context(before)) + "[REDACTED]" + scrub_sensitive_context(printable_context(after));
}

std::string redaction_label(const std::string& category, const std::string& type, std::size_t length)
{
    return "[REDACTED:" + category + ":" + type + ":len=" + std::to_string(length) + "]";
}

std::string bytes_to_text(const std::vector<std::uint8_t>& body, bool& truncated)
{
    truncated = body.size() > kMaxBodyScanBytes;
    const std::size_t n = std::min<std::size_t>(body.size(), kMaxBodyScanBytes);
    std::string out;
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        const unsigned char c = body[i];
        out.push_back(c == 0 ? ' ' : static_cast<char>(c));
    }
    return out;
}

std::string content_type_of(const exchange_observed_t& exchange)
{
    for (const auto& h : exchange.resp_headers) {
        if (lower_ascii(h.first) == "content-type")
            return h.second;
    }
    return {};
}

std::string target_of(const exchange_observed_t& exchange)
{
    std::string url = exchange.scheme.empty() ? (exchange.port == 443 ? "https" : "http") : exchange.scheme;
    url += "://";
    url += exchange.host;
    const bool default_port = (url.rfind("https://", 0) == 0 && exchange.port == 443) ||
        (url.rfind("http://", 0) == 0 && exchange.port == 80);
    if (exchange.port != 0 && !default_port)
        url += ":" + std::to_string(exchange.port);
    url += exchange.path.empty() ? "/" : exchange.path;
    if (!exchange.query.empty())
        url += "?[REDACTED]";
    return redact_url(url);
}

std::set<std::string> category_set(const std::vector<std::string>& categories)
{
    static const char* kAll[] = {
        "pii", "credit_cards", "api_keys", "internal_ips", "error_messages",
        "debug_endpoints", "backup_files", "source_code", "directory_listing",
        "secrets", "comments_leak"
    };
    std::set<std::string> out;
    if (categories.empty()) {
        for (const char* item : kAll)
            out.insert(item);
        return out;
    }
    for (auto item : categories)
        out.insert(lower_ascii(std::move(item)));
    return out;
}

bool enabled(const std::set<std::string>& categories, const std::string& category)
{
    return categories.find(category) != categories.end();
}

bool luhn_valid(const std::string& raw)
{
    std::string digits;
    for (char c : raw) {
        if (std::isdigit(static_cast<unsigned char>(c)))
            digits.push_back(c);
    }
    if (digits.size() < 13 || digits.size() > 19)
        return false;
    int sum = 0;
    bool dbl = false;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        int d = *it - '0';
        if (dbl) {
            d *= 2;
            if (d > 9)
                d -= 9;
        }
        sum += d;
        dbl = !dbl;
    }
    return sum % 10 == 0;
}

severity_t severity_from_string(const std::string& severity)
{
    if (severity == "critical")
        return severity_t::critical;
    if (severity == "high")
        return severity_t::high;
    if (severity == "medium")
        return severity_t::medium;
    if (severity == "low")
        return severity_t::low;
    return severity_t::info;
}

std::string remediation_for(const std::string& category)
{
    if (category == "api_keys" || category == "secrets")
        return "Remove exposed secret material, rotate affected credentials, and move secrets to server-side storage.";
    if (category == "credit_cards")
        return "Remove payment card data from responses and verify PCI-scoped data is never rendered to clients unnecessarily.";
    if (category == "pii")
        return "Reduce exposed personal data, mask identifiers, and require authenticated least-privilege access.";
    if (category == "internal_ips")
        return "Avoid exposing internal network addresses and infrastructure topology in client-visible responses.";
    if (category == "error_messages")
        return "Return generic error responses and keep stack traces or SQL diagnostics in server-side logs only.";
    if (category == "debug_endpoints")
        return "Disable debug endpoints in production or require strong administrative authentication and network restrictions.";
    if (category == "backup_files")
        return "Remove backup artifacts from the web root and block direct access to archive, dump, and editor-swap files.";
    if (category == "source_code")
        return "Remove source files and repository metadata from the web root and harden deployment packaging.";
    if (category == "directory_listing")
        return "Disable directory listing and provide explicit index resources for browsable paths.";
    if (category == "comments_leak")
        return "Remove sensitive operational notes from client-side comments before deployment.";
    return "Review and remove sensitive client-visible evidence.";
}

void persist_finding(const json& finding, const exchange_observed_t& exchange)
{
    issue_t issue;
    const std::string category = finding.value("category", "content");
    const std::string type = finding.value("type", "match");
    issue.type_key = "defensive.content." + category + "." + type;
    issue.name = "Defensive content disclosure";
    issue.description = category + " evidence was found in a client-visible response";
    issue.remediation = remediation_for(category);
    issue.severity = severity_from_string(finding.value("severity", "info"));
    issue.confidence = confidence_t::firm;
    issue.scheme = exchange.scheme;
    issue.host = exchange.host;
    issue.port = exchange.port;
    issue.path = exchange.path.empty() ? "/" : exchange.path;
    issue.parameter = finding.value("hash_sha256", std::string());
    issue.src_exchange_id = exchange.id;
    issue.seen_ms = now_ms();
    evidence_t evidence;
    json marker;
    marker["category"] = category;
    marker["type"] = type;
    marker["hash_sha256"] = finding.value("hash_sha256", std::string());
    marker["length"] = finding.value("length", 0ull);
    marker["context"] = finding.value("context", std::string());
    evidence.marker = marker.dump();
    evidence.response_raw = evidence.marker;
    issue.evidence.push_back(std::move(evidence));
    issue_t db_issue = issue;
    db_issue.id = 0;
    findings_db::upsert(std::move(db_issue));
    issue_store::add(std::move(issue));
}

void add_finding(json& findings,
                 std::set<std::string>& dedupe,
                 const std::string& category,
                 const std::string& type,
                 const std::string& severity,
                 const std::string& matched,
                 std::size_t offset,
                 const std::string& text,
                 const std::string& target,
                 std::uint64_t exchange_id)
{
    if (findings.size() >= kMaxFindingsPerExchange)
        return;
    const std::string hash = sha256_hex(matched);
    const std::string key = category + "|" + type + "|" + hash + "|" + std::to_string(offset);
    if (!dedupe.insert(key).second)
        return;
    json finding;
    finding["category"] = category;
    finding["type"] = type;
    finding["severity"] = severity;
    finding["target"] = target;
    finding["exchange_id"] = exchange_id;
    finding["offset"] = static_cast<std::uint64_t>(offset);
    finding["length"] = static_cast<std::uint64_t>(matched.size());
    finding["hash_sha256"] = hash;
    finding["redacted"] = redaction_label(category, type, matched.size());
    finding["context"] = safe_context(text, offset, matched.size());
    findings.push_back(std::move(finding));
}

void scan_regex(json& findings,
                std::set<std::string>& dedupe,
                const std::string& text,
                const std::string& target,
                std::uint64_t exchange_id,
                const std::string& category,
                const std::string& type,
                const std::string& severity,
                const std::regex& re,
                bool validate_card)
{
    std::size_t count = 0;
    try {
        for (std::sregex_iterator it(text.begin(), text.end(), re), end; it != end && count < kMaxFindingsPerPattern; ++it) {
            const std::string match = it->str();
            if (validate_card && !luhn_valid(match))
                continue;
            add_finding(findings, dedupe, category, type, severity, match,
                        static_cast<std::size_t>(it->position()), text, target, exchange_id);
            ++count;
        }
    } catch (...) {
    }
}

void scan_comments(json& findings,
                   std::set<std::string>& dedupe,
                   const std::string& text,
                   const std::string& target,
                   std::uint64_t exchange_id)
{
    const std::regex comment_re(R"(<!--[^>]{0,600}-->)", std::regex::icase);
    const std::regex leak_re(R"((password|passwd|secret|token|api[_-]?key|internal|debug|todo|fixme|staging|prod|admin))", std::regex::icase);
    std::size_t count = 0;
    try {
        for (std::sregex_iterator it(text.begin(), text.end(), comment_re), end; it != end && count < kMaxFindingsPerPattern; ++it) {
            const std::string match = it->str();
            if (!std::regex_search(match, leak_re))
                continue;
            add_finding(findings, dedupe, "comments_leak", "html_comment", "low", match,
                        static_cast<std::size_t>(it->position()), text, target, exchange_id);
            ++count;
        }
    } catch (...) {
    }
}

json summarize_findings(const json& findings)
{
    std::map<std::string, std::uint64_t> by_category;
    std::map<std::string, std::uint64_t> by_severity;
    for (const auto& finding : findings) {
        ++by_category[finding.value("category", "unknown")];
        ++by_severity[finding.value("severity", "info")];
    }
    json summary;
    summary["total"] = static_cast<std::uint64_t>(findings.size());
    summary["by_category"] = json::object();
    summary["by_severity"] = json::object();
    for (const auto& item : by_category)
        summary["by_category"][item.first] = item.second;
    for (const auto& item : by_severity)
        summary["by_severity"][item.first] = item.second;
    return summary;
}

json scan_text_exchange(const exchange_observed_t& exchange,
                        const std::vector<std::string>& requested_categories,
                        bool persist_findings)
{
    bool truncated = false;
    const std::string text = bytes_to_text(exchange.resp_body, truncated);
    const std::string target = target_of(exchange);
    const auto categories = category_set(requested_categories);
    json findings = json::array();
    std::set<std::string> dedupe;

    if (enabled(categories, "pii")) {
        scan_regex(findings, dedupe, text, target, exchange.id, "pii", "email", "medium",
                   std::regex(R"([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})", std::regex::icase), false);
        scan_regex(findings, dedupe, text, target, exchange.id, "pii", "ssn", "high",
                   std::regex(R"(\b\d{3}-\d{2}-\d{4}\b)"), false);
        scan_regex(findings, dedupe, text, target, exchange.id, "pii", "phone", "low",
                   std::regex(R"(\b(\+?1[ .\-]?)?(\(?\d{3}\)?[ .\-]?)\d{3}[ .\-]?\d{4}\b)"), false);
    }
    if (enabled(categories, "credit_cards")) {
        scan_regex(findings, dedupe, text, target, exchange.id, "credit_cards", "luhn_card", "high",
                   std::regex(R"(\b(\d[ -]*){13,19}\b)"), true);
    }
    if (enabled(categories, "api_keys") || enabled(categories, "secrets")) {
        const std::string category = enabled(categories, "api_keys") ? "api_keys" : "secrets";
        scan_regex(findings, dedupe, text, target, exchange.id, category, "aws_access_key", "critical",
                   std::regex(R"(\b(AKIA|ASIA)[0-9A-Z]{16}\b)", std::regex::icase), false);
        scan_regex(findings, dedupe, text, target, exchange.id, category, "google_api_key", "high",
                   std::regex(R"(AIza[0-9A-Za-z\-_]{30,})"), false);
        scan_regex(findings, dedupe, text, target, exchange.id, category, "github_token", "critical",
                   std::regex(R"(gh[pousr]_[A-Za-z0-9_]{30,})"), false);
        scan_regex(findings, dedupe, text, target, exchange.id, category, "stripe_secret", "critical",
                   std::regex(R"(sk_live_[0-9A-Za-z]{16,})"), false);
        scan_regex(findings, dedupe, text, target, exchange.id, category, "slack_token", "critical",
                   std::regex(R"(xox[baprs]-[0-9A-Za-z-]{10,})"), false);
        scan_regex(findings, dedupe, text, target, exchange.id, category, "jwt", "high",
                   std::regex(R"(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"), false);
        scan_regex(findings, dedupe, text, target, exchange.id, "secrets", "named_secret", "high",
                   std::regex(R"((api[_-]?key|secret|token|password|passwd|pwd|authorization)\s*[:=]\s*["']?[A-Za-z0-9+\/._\-:=]{12,})", std::regex::icase), false);
        scan_regex(findings, dedupe, text, target, exchange.id, "secrets", "private_key_marker", "critical",
                   std::regex(R"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)", std::regex::icase), false);
    }
    if (enabled(categories, "internal_ips")) {
        scan_regex(findings, dedupe, text, target, exchange.id, "internal_ips", "private_ipv4", "low",
                   std::regex(R"(\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)"), false);
    }
    if (enabled(categories, "error_messages")) {
        scan_regex(findings, dedupe, text, target, exchange.id, "error_messages", "stack_or_sql_error", "medium",
                   std::regex(R"((Traceback \(most recent call last\)|SQL syntax.*MySQL|Warning:\s+mysql_|ORA-\d{5}|ODBC SQL Server Driver|System\.[A-Za-z]+Exception|java\.lang\.[A-Za-z]+Exception|Fatal error:|stack trace|at\s+[A-Za-z0-9_.$<>]+\([^)]*:\d+\)))", std::regex::icase), false);
    }
    if (enabled(categories, "debug_endpoints")) {
        scan_regex(findings, dedupe, text, target, exchange.id, "debug_endpoints", "debug_link", "medium",
                   std::regex(R"((href|src|action)\s*=\s*["'][^"']*(/debug|/swagger|/actuator|/phpinfo|/graphql|/adminer|/server-status|/metrics)[^"']*["'])", std::regex::icase), false);
    }
    if (enabled(categories, "backup_files")) {
        scan_regex(findings, dedupe, text, target, exchange.id, "backup_files", "backup_reference", "medium",
                   std::regex(R"((href|src)\s*=\s*["'][^"']*\.(bak|backup|old|orig|save|swp|zip|tar|gz|sql)(\?[^"']*)?["'])", std::regex::icase), false);
        if (std::regex_search(target, std::regex(R"(\.(bak|backup|old|orig|save|swp|zip|tar|gz|sql)(\?|$))", std::regex::icase)))
            add_finding(findings, dedupe, "backup_files", "backup_url", "high", target, 0, target, target, exchange.id);
    }
    if (enabled(categories, "source_code")) {
        scan_regex(findings, dedupe, text, target, exchange.id, "source_code", "source_marker", "high",
                   std::regex(R"((<\?php|\bnamespace\s+[A-Za-z0-9_\\]+;|\bpackage\s+[A-Za-z0-9_.]+;|\bdef\s+[A-Za-z_][A-Za-z0-9_]*\s*\(|\bclass\s+[A-Za-z_][A-Za-z0-9_]*\s*[:{]|\[core\]\s+repositoryformatversion|sourceMappingURL=))", std::regex::icase), false);
    }
    if (enabled(categories, "directory_listing")) {
        scan_regex(findings, dedupe, text, target, exchange.id, "directory_listing", "index_listing", "medium",
                   std::regex(R"((<title>\s*Index of\s*/|Index of\s*/|Parent Directory</a>|Directory Listing For))", std::regex::icase), false);
    }
    if (enabled(categories, "comments_leak"))
        scan_comments(findings, dedupe, text, target, exchange.id);

    if (persist_findings) {
        for (const auto& finding : findings)
            persist_finding(finding, exchange);
    }

    json out;
    out["target"] = target;
    out["exchange_id"] = exchange.id;
    out["status_code"] = exchange.status_code;
    out["content_type"] = content_type_of(exchange);
    out["body_bytes"] = static_cast<std::uint64_t>(exchange.resp_body.size());
    out["scanned_bytes"] = static_cast<std::uint64_t>(text.size());
    out["truncated"] = truncated;
    out["findings"] = findings;
    out["summary"] = summarize_findings(findings);
    return out;
}

std::vector<std::uint8_t> build_request(const std::string& method, const std::string& host, std::uint16_t port, bool tls, const std::string& path, bool range)
{
    const bool default_port = (tls && port == 443) || (!tls && port == 80);
    std::string authority = host;
    if (!default_port)
        authority += ":" + std::to_string(port);
    std::string raw;
    raw += method;
    raw += " ";
    raw += path.empty() ? "/" : path;
    raw += " HTTP/1.1\r\nHost: ";
    raw += authority;
    raw += "\r\nUser-Agent: AiDA-Defensive/1.0\r\nAccept: */*\r\n";
    if (range)
        raw += "Range: bytes=0-65535\r\n";
    raw += "Connection: close\r\n\r\n";
    return std::vector<std::uint8_t>(raw.begin(), raw.end());
}

bool fetch_url(const std::string& url, const std::string& method, bool range, exchange_observed_t& out, std::string& error)
{
    std::string scheme;
    std::string host;
    std::string path;
    std::uint16_t port = 0;
    if (!audit_http::parse_url(url, scheme, host, port, path)) {
        error = "invalid_url";
        return false;
    }
    if (!scope::in_scope_components(scheme, host, port, path)) {
        error = "blocked_by_scope";
        return false;
    }
    const bool tls = scheme == "https";
    audit_http::send_options_t opt;
    opt.timeout_ms = 9000;
    opt.follow_redirects = false;
    opt.max_redirects = 0;
    opt.enforce_scope = true;
    opt.publish_exchange = false;
    opt.exchange_source = "defensive";
    auto request = build_request(method, host, port, tls, path, range);
    auto response = audit_http::send(request, host, port, tls, opt);
    if (!response.has_value() && method == "HEAD") {
        request = build_request("GET", host, port, tls, path, true);
        response = audit_http::send(request, host, port, tls, opt);
    }
    if (!response.has_value()) {
        error = audit_http::last_error();
        return false;
    }
    out = std::move(*response);
    return true;
}

std::string url_for_path(const std::string& scheme, const std::string& host, std::uint16_t port, const std::string& path)
{
    const bool tls = scheme == "https";
    const bool default_port = (tls && port == 443) || (!tls && port == 80);
    std::string url = scheme + "://" + host;
    if (!default_port)
        url += ":" + std::to_string(port);
    if (path.empty() || path.front() != '/')
        url += "/";
    url += path;
    return url;
}

std::string directory_of(std::string path)
{
    if (path.empty() || path.front() != '/')
        return "/";
    if (path.back() == '/')
        return path;
    const std::size_t slash = path.rfind('/');
    if (slash == std::string::npos || slash == 0)
        return "/";
    return path.substr(0, slash + 1);
}

void add_unique(std::vector<std::string>& values, const std::string& value)
{
    if (value.empty())
        return;
    if (std::find(values.begin(), values.end(), value) == values.end())
        values.push_back(value);
}

std::uint32_t bounded_probe_count(std::uint32_t value, std::uint32_t fallback)
{
    if (value == 0)
        value = fallback;
    return std::max<std::uint32_t>(1, std::min<std::uint32_t>(64, value));
}

bool backup_status_hit(int status)
{
    return status == 200 || status == 206 || status == 401 || status == 403;
}

bool source_status_hit(int status)
{
    return status == 200 || status == 206 || status == 401 || status == 403;
}

void persist_probe_issue(const std::string& type_key,
                         const std::string& name,
                         const std::string& description,
                         const std::string& remediation,
                         severity_t severity,
                         const exchange_observed_t& exchange,
                         const std::string& marker)
{
    issue_t issue;
    issue.type_key = type_key;
    issue.name = name;
    issue.description = description;
    issue.remediation = remediation;
    issue.severity = severity;
    issue.confidence = confidence_t::firm;
    issue.scheme = exchange.scheme;
    issue.host = exchange.host;
    issue.port = exchange.port;
    issue.path = exchange.path.empty() ? "/" : exchange.path;
    issue.src_exchange_id = exchange.id;
    issue.parameter = sha256_hex(marker);
    issue.seen_ms = now_ms();
    evidence_t evidence;
    evidence.marker = marker;
    evidence.response_raw = marker;
    issue.evidence.push_back(std::move(evidence));
    issue_t db_issue = issue;
    db_issue.id = 0;
    findings_db::upsert(std::move(db_issue));
    issue_store::add(std::move(issue));
}

}

nlohmann::json scan_exchange(const exchange_observed_t& exchange,
                             const std::vector<std::string>& categories,
                             bool persist_findings)
{
    diag::log_tagged_fmt("defensive", "content_scan exchange id=%llu host=%s body=%zu",
        static_cast<unsigned long long>(exchange.id), exchange.host.c_str(), exchange.resp_body.size());
    return scan_text_exchange(exchange, categories, persist_findings);
}

nlohmann::json scan_url(const std::string& target_url,
                        const std::vector<std::string>& categories,
                        bool persist_findings,
                        std::string& error)
{
    diag::log_tagged_fmt("defensive", "content_scan url=%s", redact_url(target_url).c_str());
    exchange_observed_t exchange;
    if (!fetch_url(target_url, "GET", true, exchange, error))
        return json::object();
    return scan_text_exchange(exchange, categories, persist_findings);
}

nlohmann::json scan_captured(const std::string& host_filter,
                             const std::vector<std::string>& categories,
                             bool persist_findings)
{
    diag::log_tagged_fmt("defensive", "content_scan captured host_filter=%s", host_filter.c_str());
    const std::string filter = lower_ascii(host_filter);
    auto exchanges = sitemap::list_all_exchanges();
    json scans = json::array();
    json all_findings = json::array();
    std::uint64_t scanned = 0;
    for (const auto& exchange : exchanges) {
        if (!filter.empty() && lower_ascii(exchange.host).find(filter) == std::string::npos)
            continue;
        if (scanned >= 250)
            break;
        json result = scan_text_exchange(exchange, categories, persist_findings);
        for (const auto& finding : result["findings"])
            all_findings.push_back(finding);
        json scan_summary;
        scan_summary["exchange_id"] = exchange.id;
        scan_summary["target"] = result["target"];
        scan_summary["finding_count"] = result["summary"].value("total", 0ull);
        scan_summary["truncated"] = result["truncated"];
        scans.push_back(std::move(scan_summary));
        ++scanned;
    }
    json out;
    out["target"] = filter.empty() ? "captured" : filter;
    out["scan_all_captured"] = true;
    out["scanned_exchanges"] = scanned;
    out["scans"] = scans;
    out["findings"] = all_findings;
    out["summary"] = summarize_findings(all_findings);
    return out;
}

nlohmann::json detect_backups(const std::string& target_url,
                              std::uint32_t max_probes,
                              bool persist_findings,
                              std::string& error)
{
    diag::log_tagged_fmt("defensive", "backup_detect url=%s max_probes=%u", redact_url(target_url).c_str(), max_probes);
    std::string scheme;
    std::string host;
    std::string path;
    std::uint16_t port = 0;
    if (!audit_http::parse_url(target_url, scheme, host, port, path)) {
        error = "invalid_url";
        return json::object();
    }
    if (!scope::in_scope_components(scheme, host, port, path)) {
        error = "blocked_by_scope";
        return json::object();
    }

    const std::uint32_t limit = bounded_probe_count(max_probes, 32);
    std::vector<std::string> candidates;
    const std::string dir = directory_of(path);
    const std::vector<std::string> suffixes = {"~", ".bak", ".backup", ".old", ".orig", ".save", ".swp"};
    for (const auto& suffix : suffixes)
        add_unique(candidates, path + suffix);
    const std::vector<std::string> dir_files = {
        "backup.zip", "backup.tar.gz", "site.zip", "www.zip", "db.sql", "dump.sql",
        "backup.sql", "web.config.bak", "config.php.bak", ".env", ".env.bak"
    };
    for (const auto& item : dir_files)
        add_unique(candidates, dir + item);
    const std::vector<std::string> root_files = {
        "/backup.zip", "/backup.tar.gz", "/site.zip", "/www.zip", "/db.sql",
        "/dump.sql", "/backup.sql", "/database.sql", "/.env", "/.env.bak",
        "/web.config.bak", "/wp-config.php.bak"
    };
    for (const auto& item : root_files)
        add_unique(candidates, item);

    json probes = json::array();
    json hits = json::array();
    std::uint32_t attempted = 0;
    for (const auto& candidate : candidates) {
        if (attempted >= limit)
            break;
        const std::string url = url_for_path(scheme, host, port, candidate);
        json probe;
        probe["url"] = url;
        if (!scope::in_scope_components(scheme, host, port, candidate)) {
            probe["status"] = "blocked_by_scope";
            probes.push_back(std::move(probe));
            continue;
        }
        ++attempted;
        exchange_observed_t exchange;
        std::string send_error;
        if (!fetch_url(url, "HEAD", false, exchange, send_error)) {
            probe["status"] = "send_failed";
            probe["error"] = send_error;
            probes.push_back(std::move(probe));
            continue;
        }
        probe["status"] = "ok";
        probe["http_status"] = exchange.status_code;
        probe["exchange_id"] = exchange.id;
        if (backup_status_hit(exchange.status_code)) {
            json hit;
            hit["url"] = url;
            hit["status_code"] = exchange.status_code;
            hit["severity"] = exchange.status_code == 200 || exchange.status_code == 206 ? "high" : "medium";
            hit["evidence"] = "HTTP " + std::to_string(exchange.status_code) + " for backup/source artifact path";
            hit["exchange_id"] = exchange.id;
            hits.push_back(hit);
            if (persist_findings) {
                persist_probe_issue("defensive.content.backup_files.probe",
                                    "Backup file exposure",
                                    "A backup or dump artifact path returned an existence indicator",
                                    remediation_for("backup_files"),
                                    hit["severity"].get<std::string>() == "high" ? severity_t::high : severity_t::medium,
                                    exchange,
                                    "backup_probe:" + url + ":status=" + std::to_string(exchange.status_code));
            }
        }
        probes.push_back(std::move(probe));
    }

    json out;
    out["target_url"] = redact_url(target_url);
    out["scope_enforced"] = true;
    out["max_probes"] = limit;
    out["attempted"] = attempted;
    out["hits"] = hits;
    out["hit_count"] = static_cast<std::uint64_t>(hits.size());
    out["probes"] = probes;
    return out;
}

nlohmann::json detect_source_exposure(const std::string& target_url,
                                      std::uint32_t max_probes,
                                      bool persist_findings,
                                      std::string& error)
{
    diag::log_tagged_fmt("defensive", "source_exposure url=%s max_probes=%u", redact_url(target_url).c_str(), max_probes);
    std::string scheme;
    std::string host;
    std::string path;
    std::uint16_t port = 0;
    if (!audit_http::parse_url(target_url, scheme, host, port, path)) {
        error = "invalid_url";
        return json::object();
    }
    if (!scope::in_scope_components(scheme, host, port, path)) {
        error = "blocked_by_scope";
        return json::object();
    }

    const std::uint32_t limit = bounded_probe_count(max_probes, 32);
    std::vector<std::string> candidates;
    const std::string dir = directory_of(path);
    const std::vector<std::string> root = {
        "/.git/config", "/.svn/entries", "/.hg/hgrc", "/.env", "/composer.json",
        "/package.json", "/package-lock.json", "/yarn.lock", "/server.js",
        "/app.js", "/config.php", "/wp-config.php", "/WEB-INF/web.xml",
        "/WEB-INF/classes/", "/src/", "/app/", "/application.properties"
    };
    for (const auto& item : root)
        add_unique(candidates, item);
    const std::vector<std::string> local = {
        ".git/config", ".env", "composer.json", "package.json", "server.js",
        "app.js", "config.php", "application.properties", "web.config"
    };
    for (const auto& item : local)
        add_unique(candidates, dir + item);

    json probes = json::array();
    json hits = json::array();
    json nested_findings = json::array();
    std::uint32_t attempted = 0;
    const std::vector<std::string> categories = {"source_code", "secrets", "directory_listing", "api_keys", "error_messages"};
    for (const auto& candidate : candidates) {
        if (attempted >= limit)
            break;
        const std::string url = url_for_path(scheme, host, port, candidate);
        json probe;
        probe["url"] = url;
        if (!scope::in_scope_components(scheme, host, port, candidate)) {
            probe["status"] = "blocked_by_scope";
            probes.push_back(std::move(probe));
            continue;
        }
        ++attempted;
        exchange_observed_t exchange;
        std::string send_error;
        if (!fetch_url(url, "GET", true, exchange, send_error)) {
            probe["status"] = "send_failed";
            probe["error"] = send_error;
            probes.push_back(std::move(probe));
            continue;
        }
        probe["status"] = "ok";
        probe["http_status"] = exchange.status_code;
        probe["exchange_id"] = exchange.id;
        json scan = scan_text_exchange(exchange, categories, persist_findings);
        const std::uint64_t finding_count = scan["summary"].value("total", 0ull);
        probe["finding_count"] = finding_count;
        if (source_status_hit(exchange.status_code) && (finding_count > 0 || exchange.status_code == 401 || exchange.status_code == 403)) {
            json hit;
            hit["url"] = url;
            hit["status_code"] = exchange.status_code;
            hit["exchange_id"] = exchange.id;
            hit["severity"] = exchange.status_code == 200 || exchange.status_code == 206 ? "high" : "medium";
            hit["evidence"] = finding_count > 0 ? "source or secret markers detected in bounded response scan" : "protected source-like path indicates deployed source surface";
            hits.push_back(hit);
            if (persist_findings) {
                persist_probe_issue("defensive.content.source_exposure.probe",
                                    "Source exposure surface",
                                    "A source or repository path returned an exposure indicator",
                                    remediation_for("source_code"),
                                    hit["severity"].get<std::string>() == "high" ? severity_t::high : severity_t::medium,
                                    exchange,
                                    "source_probe:" + url + ":status=" + std::to_string(exchange.status_code) + ":findings=" + std::to_string(finding_count));
            }
        }
        for (const auto& finding : scan["findings"])
            nested_findings.push_back(finding);
        probes.push_back(std::move(probe));
    }

    json out;
    out["target_url"] = redact_url(target_url);
    out["scope_enforced"] = true;
    out["max_probes"] = limit;
    out["attempted"] = attempted;
    out["hits"] = hits;
    out["hit_count"] = static_cast<std::uint64_t>(hits.size());
    out["findings"] = nested_findings;
    out["summary"] = summarize_findings(nested_findings);
    out["probes"] = probes;
    return out;
}

}
}
}
