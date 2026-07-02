#include "offensive_payloads.hpp"

#include "../payload_library.hpp"

#include <algorithm>
#include <cctype>
#include <set>
#include <unordered_set>

namespace aida {
namespace burp {
namespace offensive {
namespace payloads {

namespace {

std::string lower_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

bool wants_all(const std::vector<std::string>& values)
{
    if (values.empty()) return true;
    for (const auto& v : values) {
        const std::string l = lower_ascii(v);
        if (l == "all" || l == "*") return true;
    }
    return false;
}

bool contains_token(const std::vector<std::string>& values, const std::string& token)
{
    const std::string expected = lower_ascii(token);
    for (const auto& v : values) {
        if (lower_ascii(v) == expected) return true;
    }
    return false;
}

std::string replace_all(std::string text, const std::string& needle, const std::string& repl)
{
    if (needle.empty()) return text;
    size_t pos = 0;
    while ((pos = text.find(needle, pos)) != std::string::npos) {
        text.replace(pos, needle.size(), repl);
        pos += repl.size();
    }
    return text;
}

std::vector<payload_entry_t> collect_sets(const std::vector<std::pair<std::string, std::string>>& sets,
                                          std::size_t max_count)
{
    ensure_available();
    std::vector<payload_entry_t> out;
    std::unordered_set<std::string> seen;
    for (const auto& item : sets) {
        for (const auto& entry : ::aida::burp::payloads::entries(item.first)) {
            if (entry.empty()) continue;
            if (!seen.insert(entry).second) continue;
            out.push_back({entry, item.first, item.second});
            if (max_count != 0 && out.size() >= max_count) return out;
        }
    }
    return out;
}

void add_if(std::vector<std::pair<std::string, std::string>>& out, bool enabled,
            const char* id, const char* technique)
{
    if (enabled) out.emplace_back(id, technique);
}

std::string context_to_set(const std::string& context)
{
    const std::string c = lower_ascii(context);
    if (c == "html") return "xss/html_context";
    if (c == "attribute" || c == "attr") return "xss/attribute_context";
    if (c == "script" || c == "javascript" || c == "js") return "xss/script_context";
    if (c == "url" || c == "href") return "xss/url_context";
    if (c == "csp" || c == "csp_bypass") return "xss/csp_bypass";
    if (c == "waf" || c == "waf_bypass") return "xss/waf_bypass";
    return {};
}

}

bool ensure_available()
{
    return ::aida::burp::payloads::initialize();
}

std::vector<std::string> sqli_set_ids()
{
    return {
        "sqli/error_based",
        "sqli/boolean_true",
        "sqli/boolean_false",
        "sqli/union_based",
        "sqli/time_based",
        "sqli/waf_bypass",
        "sqli/db_fingerprint"
    };
}

std::vector<std::string> xss_set_ids()
{
    return {
        "xss/html_context",
        "xss/attribute_context",
        "xss/script_context",
        "xss/url_context",
        "xss/polyglot_expanded",
        "xss/csp_bypass",
        "xss/waf_bypass"
    };
}

std::vector<payload_entry_t> sqli_payloads(const std::vector<std::string>& techniques,
                                           const std::string& dbms,
                                           std::size_t max_count)
{
    const bool all = wants_all(techniques);
    std::vector<std::pair<std::string, std::string>> sets;
    add_if(sets, all || contains_token(techniques, "error"), "sqli/error_based", "error");
    add_if(sets, all || contains_token(techniques, "boolean"), "sqli/boolean_true", "boolean_true");
    add_if(sets, all || contains_token(techniques, "boolean"), "sqli/boolean_false", "boolean_false");
    add_if(sets, all || contains_token(techniques, "union"), "sqli/union_based", "union");
    add_if(sets, all || contains_token(techniques, "time"), "sqli/time_based", "time");
    add_if(sets, all || contains_token(techniques, "waf") || contains_token(techniques, "waf_bypass"), "sqli/waf_bypass", "waf_bypass");
    add_if(sets, all || contains_token(techniques, "fingerprint") || contains_token(techniques, "dbms"), "sqli/db_fingerprint", "db_fingerprint");
    std::vector<payload_entry_t> out = collect_sets(sets, max_count);
    const std::string d = lower_ascii(dbms);
    if (!d.empty() && d != "auto" && d != "any") {
        out.erase(std::remove_if(out.begin(), out.end(), [&](const payload_entry_t& e) {
            const std::string v = lower_ascii(e.value);
            if (v.find(d) != std::string::npos) return false;
            if (d == "mysql" && (v.find("sleep(") != std::string::npos || v.find("@@version") != std::string::npos || v.find("information_schema") != std::string::npos)) return false;
            if (d == "postgres" && (v.find("pg_sleep") != std::string::npos || v.find("version()") != std::string::npos || v.find("current_database") != std::string::npos)) return false;
            if (d == "mssql" && (v.find("waitfor") != std::string::npos || v.find("@@version") != std::string::npos || v.find("db_name") != std::string::npos)) return false;
            if (d == "oracle" && (v.find("dbms_") != std::string::npos || v.find("v$version") != std::string::npos || v.find("dual") != std::string::npos)) return false;
            if (d == "sqlite" && (v.find("sqlite") != std::string::npos || v.find("randomblob") != std::string::npos)) return false;
            return e.technique == "time" || e.technique == "db_fingerprint";
        }), out.end());
    }
    return out;
}

std::vector<payload_entry_t> xss_payloads(const std::string& context,
                                          const std::string& filter,
                                          const std::string& marker,
                                          std::size_t max_count)
{
    const std::string c = lower_ascii(context);
    const std::string f = lower_ascii(filter.empty() ? std::string("all") : filter);
    std::vector<std::pair<std::string, std::string>> sets;
    const std::string selected = context_to_set(c);
    if (f == "csp_bypass") {
        sets.emplace_back("xss/csp_bypass", "csp_bypass");
    } else if (f == "waf_bypass") {
        sets.emplace_back("xss/waf_bypass", "waf_bypass");
    } else if (!selected.empty()) {
        sets.emplace_back(selected, c.empty() ? std::string("unknown") : c);
        if (f == "all") sets.emplace_back("xss/polyglot_expanded", "polyglot");
    } else {
        sets.emplace_back("xss/html_context", "html");
        sets.emplace_back("xss/attribute_context", "attribute");
        sets.emplace_back("xss/script_context", "script");
        sets.emplace_back("xss/url_context", "url");
        sets.emplace_back("xss/polyglot_expanded", "polyglot");
    }
    if (f == "event_handler") {
        sets.clear();
        sets.emplace_back("xss/attribute_context", "event_handler");
        sets.emplace_back("xss/html_context", "event_handler");
    } else if (f == "script_src") {
        sets.clear();
        sets.emplace_back("xss/csp_bypass", "script_src");
        sets.emplace_back("xss/url_context", "script_src");
    }
    std::vector<payload_entry_t> out = collect_sets(sets, max_count == 0 ? 0 : max_count * 2);
    if (f == "short") {
        out.erase(std::remove_if(out.begin(), out.end(), [](const payload_entry_t& e) {
            return e.value.size() > 80;
        }), out.end());
    }
    if (max_count != 0 && out.size() > max_count) out.resize(max_count);
    const std::string effective_marker = marker.empty() ? std::string("AIDA_XSS") : marker;
    for (auto& entry : out) {
        entry.value = replace_all(entry.value, "AIDA_MARKER", effective_marker);
        entry.value = replace_all(entry.value, "AIDA_XSS_MARKER", effective_marker);
    }
    return out;
}

nlohmann::json inventory()
{
    ensure_available();
    nlohmann::json out;
    out["sqli_sets"] = nlohmann::json::array();
    for (const auto& id : sqli_set_ids()) {
        out["sqli_sets"].push_back({{"id", id}, {"entries", ::aida::burp::payloads::entries(id).size()}});
    }
    out["xss_sets"] = nlohmann::json::array();
    for (const auto& id : xss_set_ids()) {
        out["xss_sets"].push_back({{"id", id}, {"entries", ::aida::burp::payloads::entries(id).size()}});
    }
    return out;
}

}
}
}
}
