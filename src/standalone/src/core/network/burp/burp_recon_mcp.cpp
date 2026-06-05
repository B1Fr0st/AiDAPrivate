#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_recon_mcp.hpp"

#include "crawler.hpp"
#include "content_discovery.hpp"
#include "subdomain_enum.hpp"
#include "payload_library.hpp"

#include "../../settings/standalone_compat.hpp"
#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

namespace aida {
namespace burp {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

template <typename T>
T get_or(const json& j, const std::string& key, T def)
{
    if (!j.is_object() || !j.contains(key)) return def;
    try { return j.at(key).get<T>(); } catch (...) { return def; }
}

std::vector<std::string> get_string_array(const json& j, const std::string& key)
{
    std::vector<std::string> out;
    if (!j.is_object() || !j.contains(key)) return out;
    const json& a = j.at(key);
    if (!a.is_array()) return out;
    for (const auto& e : a) if (e.is_string()) out.push_back(e.get<std::string>());
    return out;
}

std::vector<int> get_int_array(const json& j, const std::string& key)
{
    std::vector<int> out;
    if (!j.is_object() || !j.contains(key)) return out;
    const json& a = j.at(key);
    if (!a.is_array()) return out;
    for (const auto& e : a) if (e.is_number_integer()) out.push_back(e.get<int>());
    return out;
}

json crawler_status_to_json(const crawler::crawl_status_t& s)
{
    json j;
    j["id"] = s.id;
    const char* phase = "unknown";
    switch (s.phase)
    {
        case crawler::crawl_status_phase_t::pending: phase = "pending"; break;
        case crawler::crawl_status_phase_t::running: phase = "running"; break;
        case crawler::crawl_status_phase_t::stopping: phase = "stopping"; break;
        case crawler::crawl_status_phase_t::complete: phase = "complete"; break;
        case crawler::crawl_status_phase_t::error: phase = "error"; break;
    }
    j["phase"] = phase;
    j["queue_depth"] = s.queue_depth;
    j["pages_visited"] = s.pages_visited;
    j["pages_failed"] = s.pages_failed;
    j["urls_found"] = s.urls_found;
    j["started_unix_ms"] = s.started_unix_ms;
    j["finished_unix_ms"] = s.finished_unix_ms;
    j["last_url"] = s.last_url;
    j["last_error"] = s.last_error;
    return j;
}

json disc_status_to_json(const content_discovery::disc_status_t& s)
{
    json j;
    j["id"] = s.id;
    const char* phase = "unknown";
    switch (s.phase)
    {
        case content_discovery::disc_phase_t::pending: phase = "pending"; break;
        case content_discovery::disc_phase_t::calibrating: phase = "calibrating"; break;
        case content_discovery::disc_phase_t::running: phase = "running"; break;
        case content_discovery::disc_phase_t::stopping: phase = "stopping"; break;
        case content_discovery::disc_phase_t::complete: phase = "complete"; break;
        case content_discovery::disc_phase_t::error: phase = "error"; break;
    }
    j["phase"] = phase;
    j["attempts"] = s.attempts;
    j["total"] = s.total;
    j["hits"] = s.hits;
    j["filtered"] = s.filtered;
    j["errors"] = s.errors;
    j["calibrated_size_lo"] = s.calibrated_size_lo;
    j["calibrated_size_hi"] = s.calibrated_size_hi;
    j["started_unix_ms"] = s.started_unix_ms;
    j["finished_unix_ms"] = s.finished_unix_ms;
    return j;
}

json sub_status_to_json(const subdomain_enum::enum_status_t& s)
{
    json j;
    j["id"] = s.id;
    const char* phase = "unknown";
    switch (s.phase)
    {
        case subdomain_enum::enum_phase_t::pending: phase = "pending"; break;
        case subdomain_enum::enum_phase_t::passive: phase = "passive"; break;
        case subdomain_enum::enum_phase_t::brute: phase = "brute"; break;
        case subdomain_enum::enum_phase_t::stopping: phase = "stopping"; break;
        case subdomain_enum::enum_phase_t::complete: phase = "complete"; break;
        case subdomain_enum::enum_phase_t::error: phase = "error"; break;
    }
    j["phase"] = phase;
    j["passive_count"] = s.passive_count;
    j["brute_attempts"] = s.brute_attempts;
    j["brute_resolved"] = s.brute_resolved;
    j["started_unix_ms"] = s.started_unix_ms;
    j["finished_unix_ms"] = s.finished_unix_ms;
    j["last_error"] = s.last_error;
    j["domain"] = s.config.domain;
    j["results_count"] = static_cast<int>(s.results.size());
    return j;
}

tool_result_t crawler_start(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "crawler_start entry start_urls_count=%zu", get_string_array(p, "start_urls").size() + (p.contains("url") && p["url"].is_string() ? 1 : 0));
    crawler::crawl_config_t cfg;
    cfg.start_urls = get_string_array(p, "start_urls");
    if (cfg.start_urls.empty() && p.contains("url") && p["url"].is_string())
        cfg.start_urls.push_back(p["url"].get<std::string>());
    if (cfg.start_urls.empty()) return tool_result_t::error("start_urls required");
    cfg.max_depth         = get_or<int>(p, "max_depth", 3);
    cfg.same_host_only    = get_or<bool>(p, "same_host_only", true);
    cfg.scope_only        = get_or<bool>(p, "scope_only", false);
    cfg.respect_robots_txt = get_or<bool>(p, "respect_robots", true);
    cfg.parse_js          = get_or<bool>(p, "parse_js", true);
    cfg.max_pages         = get_or<int>(p, "max_pages", 500);
    cfg.concurrency       = get_or<int>(p, "concurrency", 8);
    cfg.rate_per_host     = get_or<int>(p, "rate_per_host", 10);
    cfg.user_agent        = get_or<std::string>(p, "user_agent", std::string("AiDA-Crawler/1.0"));
    cfg.exclude_extensions = get_string_array(p, "exclude_extensions");
    cfg.exclude_patterns  = get_string_array(p, "exclude_patterns");
    uint64_t id = crawler::start(cfg);
    if (id == 0) { diag::log_tagged_fmt("mcp_burp", "crawler_start failed err=%s", crawler::last_error().c_str()); return tool_result_t::error(crawler::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "crawler_start ok crawl_id=%llu", static_cast<unsigned long long>(id));
    json r;
    r["crawl_id"] = id;
    return tool_result_t::ok("crawl started id=" + std::to_string(id), r);
}

tool_result_t crawler_status_(const json& p)
{
    uint64_t id = get_or<uint64_t>(p, "crawl_id", 0);
    diag::log_tagged_fmt("mcp_burp", "crawler_status crawl_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0) return tool_result_t::error("crawl_id required");
    auto s = crawler::status(id);
    if (s.id == 0) { diag::log_tagged_fmt("mcp_burp", "crawler_status not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("not found"); }
    json j = crawler_status_to_json(s);
    json urls = json::array();
    int cap = get_or<int>(p, "max_urls", 200);
    int n = 0;
    for (auto& d : s.discovered)
    {
        if (n++ >= cap) break;
        json e;
        e["url"] = d.url;
        e["status"] = d.status;
        e["body_bytes"] = d.body_bytes;
        e["content_type"] = d.content_type;
        e["depth"] = d.depth;
        urls.push_back(e);
    }
    j["urls"] = urls;
    diag::log_tagged_fmt("mcp_burp", "crawler_status ok id=%llu urls=%d", static_cast<unsigned long long>(id), n);
    return tool_result_t::ok("crawler status id=" + std::to_string(id) + " urls=" + std::to_string(urls.size()), j);
}

tool_result_t crawler_stop_(const json& p)
{
    uint64_t id = get_or<uint64_t>(p, "crawl_id", 0);
    diag::log_tagged_fmt("mcp_burp", "crawler_stop crawl_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0) return tool_result_t::error("crawl_id required");
    if (!crawler::stop(id)) { diag::log_tagged_fmt("mcp_burp", "crawler_stop failed err=%s", crawler::last_error().c_str()); return tool_result_t::error(crawler::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "crawler_stop ok id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("stop requested");
}

tool_result_t crawler_list_(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "crawler_list entry");
    auto v = crawler::list();
    json arr = json::array();
    for (auto& s : v) arr.push_back(crawler_status_to_json(s));
    json out;
    out["crawls"] = arr;
    diag::log_tagged_fmt("mcp_burp", "crawler_list ok count=%zu", v.size());
    return tool_result_t::ok("crawler list count=" + std::to_string(v.size()), out);
}

tool_result_t cd_start(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "content_discovery_start target=%s", get_or<std::string>(p, "target_url", std::string()).c_str());
    content_discovery::config_t cfg;
    cfg.target_url        = get_or<std::string>(p, "target_url", std::string());
    if (cfg.target_url.empty()) return tool_result_t::error("target_url required");
    cfg.wordlist_id       = get_or<std::string>(p, "wordlist_id", std::string());
    cfg.wordlist_file     = get_or<std::string>(p, "wordlist_file", std::string());
    if (cfg.wordlist_id.empty() && cfg.wordlist_file.empty()) {
        cfg.wordlist_id = "dirs/common-100";
        diag::log_tagged_fmt("mcp_burp", "content_discovery_start default_wordlist id=%s", cfg.wordlist_id.c_str());
    }
    cfg.extensions        = get_string_array(p, "extensions");
    cfg.concurrency       = get_or<int>(p, "concurrency", 25);
    cfg.delay_ms          = get_or<int>(p, "delay_ms", 0);
    cfg.request_timeout_ms = get_or<int>(p, "request_timeout_ms", 8000);
    cfg.match_status      = get_int_array(p, "match_status");
    cfg.filter_status     = get_int_array(p, "filter_status");
    cfg.filter_size_min   = get_or<size_t>(p, "filter_size_min", static_cast<size_t>(0));
    cfg.filter_size_max   = get_or<size_t>(p, "filter_size_max", static_cast<size_t>(0));
    cfg.filter_words_regex = get_or<std::string>(p, "filter_words_regex", std::string());
    cfg.recurse           = get_or<bool>(p, "recurse", false);
    cfg.recurse_depth     = get_or<int>(p, "recurse_depth", 1);
    cfg.method            = get_or<std::string>(p, "method", std::string("GET"));
    cfg.cookie_header     = get_or<std::string>(p, "cookie", std::string());
    cfg.user_agent        = get_or<std::string>(p, "user_agent", std::string("AiDA-ContentDiscovery/1.0"));
    cfg.follow_redirects  = get_or<bool>(p, "follow_redirects", false);
    cfg.auto_calibrate    = get_or<bool>(p, "auto_calibrate", true);

    if (p.contains("extra_headers") && p["extra_headers"].is_object())
    {
        for (auto it = p["extra_headers"].begin(); it != p["extra_headers"].end(); ++it)
            if (it.value().is_string()) cfg.extra_headers.emplace_back(it.key(), it.value().get<std::string>());
    }
    uint64_t id = content_discovery::start(cfg);
    if (id == 0) { diag::log_tagged_fmt("mcp_burp", "content_discovery_start failed err=%s", content_discovery::last_error().c_str()); return tool_result_t::error(content_discovery::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "content_discovery_start ok disc_id=%llu", static_cast<unsigned long long>(id));
    json r;
    r["disc_id"] = id;
    return tool_result_t::ok("discovery started id=" + std::to_string(id), r);
}

tool_result_t cd_status_(const json& p)
{
    uint64_t id = get_or<uint64_t>(p, "disc_id", 0);
    diag::log_tagged_fmt("mcp_burp", "content_discovery_status disc_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0) return tool_result_t::error("disc_id required");
    auto s = content_discovery::status(id);
    if (s.id == 0) { diag::log_tagged_fmt("mcp_burp", "content_discovery_status not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("not found"); }
    diag::log_tagged_fmt("mcp_burp", "content_discovery_status ok id=%llu hits=%zu", static_cast<unsigned long long>(id), s.hits);
    return tool_result_t::ok("discovery status id=" + std::to_string(id) + " hits=" + std::to_string(s.hits) + " attempts=" + std::to_string(s.attempts), disc_status_to_json(s));
}

tool_result_t cd_results_(const json& p)
{
    uint64_t id = get_or<uint64_t>(p, "disc_id", 0);
    diag::log_tagged_fmt("mcp_burp", "content_discovery_results disc_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0) return tool_result_t::error("disc_id required");
    int cap = get_or<int>(p, "max_results", 500);
    auto hits = content_discovery::results(id);
    json arr = json::array();
    int n = 0;
    for (auto& h : hits)
    {
        if (n++ >= cap) break;
        json e;
        e["url"] = h.url;
        e["payload"] = h.payload;
        e["status"] = h.status;
        e["body_bytes"] = h.body_bytes;
        e["latency_ms"] = h.latency_ms;
        e["content_type"] = h.content_type;
        e["redirect_to"] = h.redirect_to;
        e["depth"] = h.depth;
        arr.push_back(e);
    }
    json out;
    out["hits"] = arr;
    out["total"] = static_cast<int>(hits.size());
    out["returned"] = n;
    diag::log_tagged_fmt("mcp_burp", "content_discovery_results ok id=%llu returned=%d", static_cast<unsigned long long>(id), n);
    return tool_result_t::ok("discovery results returned=" + std::to_string(n) + " total=" + std::to_string(hits.size()), out);
}

tool_result_t cd_stop_(const json& p)
{
    uint64_t id = get_or<uint64_t>(p, "disc_id", 0);
    diag::log_tagged_fmt("mcp_burp", "content_discovery_stop disc_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0) return tool_result_t::error("disc_id required");
    if (!content_discovery::stop(id)) { diag::log_tagged_fmt("mcp_burp", "content_discovery_stop failed err=%s", content_discovery::last_error().c_str()); return tool_result_t::error(content_discovery::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "content_discovery_stop ok id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("stop requested");
}

tool_result_t sub_start(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "subdomain_enum_start domain=%s", get_or<std::string>(p, "domain", std::string()).c_str());
    subdomain_enum::config_t cfg;
    cfg.domain                = get_or<std::string>(p, "domain", std::string());
    if (cfg.domain.empty()) return tool_result_t::error("domain required");
    cfg.brute_wordlist_id     = get_or<std::string>(p, "brute_wordlist_id", std::string("subdomains/top1000"));
    cfg.brute_wordlist_file   = get_or<std::string>(p, "brute_wordlist_file", std::string());
    cfg.resolver_concurrency  = get_or<int>(p, "concurrency", 32);
    cfg.request_timeout_ms    = get_or<int>(p, "request_timeout_ms", 6000);
    cfg.run_passive           = get_or<bool>(p, "run_passive", true);
    cfg.run_brute             = get_or<bool>(p, "run_brute", true);
    cfg.bypass_dns_cache      = get_or<bool>(p, "bypass_dns_cache", true);
    cfg.user_agent            = get_or<std::string>(p, "user_agent", std::string("AiDA-SubdomainEnum/1.0"));
    cfg.passive_sources       = get_string_array(p, "sources");
    uint64_t id = subdomain_enum::start(cfg);
    if (id == 0) { diag::log_tagged_fmt("mcp_burp", "subdomain_enum_start failed err=%s", subdomain_enum::last_error().c_str()); return tool_result_t::error(subdomain_enum::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "subdomain_enum_start ok sub_id=%llu", static_cast<unsigned long long>(id));
    json r;
    r["sub_id"] = id;
    return tool_result_t::ok("enum started id=" + std::to_string(id), r);
}

tool_result_t sub_status_(const json& p)
{
    uint64_t id = get_or<uint64_t>(p, "sub_id", 0);
    diag::log_tagged_fmt("mcp_burp", "subdomain_enum_status sub_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0) return tool_result_t::error("sub_id required");
    auto s = subdomain_enum::status(id);
    if (s.id == 0) { diag::log_tagged_fmt("mcp_burp", "subdomain_enum_status not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("not found"); }
    diag::log_tagged_fmt("mcp_burp", "subdomain_enum_status ok id=%llu passive=%zu brute_resolved=%zu", static_cast<unsigned long long>(id), s.passive_count, s.brute_resolved);
    return tool_result_t::ok("subdomain status id=" + std::to_string(id) + " results=" + std::to_string(s.results.size()) + " resolved=" + std::to_string(s.brute_resolved), sub_status_to_json(s));
}

tool_result_t sub_results_(const json& p)
{
    uint64_t id = get_or<uint64_t>(p, "sub_id", 0);
    diag::log_tagged_fmt("mcp_burp", "subdomain_enum_results sub_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0) return tool_result_t::error("sub_id required");
    int cap = get_or<int>(p, "max_results", 1000);
    auto v = subdomain_enum::results(id);
    json arr = json::array();
    int n = 0;
    for (auto& s : v)
    {
        if (n++ >= cap) break;
        json e;
        e["fqdn"] = s.fqdn;
        e["resolves"] = s.resolves;
        e["ips"] = s.ips;
        e["sources"] = s.sources;
        arr.push_back(e);
    }
    json out;
    out["subdomains"] = arr;
    out["total"] = static_cast<int>(v.size());
    out["returned"] = n;
    diag::log_tagged_fmt("mcp_burp", "subdomain_enum_results ok id=%llu returned=%d", static_cast<unsigned long long>(id), n);
    return tool_result_t::ok("subdomain results returned=" + std::to_string(n) + " total=" + std::to_string(v.size()), out);
}

tool_result_t payloads_list(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "payloads_list entry");
    auto v = payloads::list_summaries();
    json arr = json::array();
    for (auto& p : v)
    {
        const auto* full = payloads::get(p.id);
        size_t cnt = full ? full->entries.size() : 0;
        json e;
        e["id"] = p.id;
        e["label"] = p.label;
        e["description"] = p.description;
        e["builtin"] = p.builtin;
        e["entry_count"] = cnt;
        arr.push_back(e);
    }
    json out;
    out["sets"] = arr;
    diag::log_tagged_fmt("mcp_burp", "payloads_list ok count=%zu", v.size());
    return tool_result_t::ok("payload sets count=" + std::to_string(v.size()), out);
}

tool_result_t payloads_get_(const json& p)
{
    std::string id = get_or<std::string>(p, "set_id", std::string());
    diag::log_tagged_fmt("mcp_burp", "payloads_get set_id=%s", id.c_str());
    if (id.empty()) return tool_result_t::error("set_id required");
    int cap = get_or<int>(p, "max", 500);
    auto v = payloads::entries(id, static_cast<size_t>(std::max(0, cap)));
    const auto* full = payloads::get(id);
    if (!full) { diag::log_tagged_fmt("mcp_burp", "payloads_get not_found set_id=%s", id.c_str()); return tool_result_t::error("not found"); }
    json out;
    out["id"] = id;
    out["total"] = static_cast<int>(full->entries.size());
    out["returned"] = static_cast<int>(v.size());
    out["entries"] = v;
    diag::log_tagged_fmt("mcp_burp", "payloads_get ok set_id=%s returned=%zu", id.c_str(), v.size());
    return tool_result_t::ok("payload entries count=" + std::to_string(v.size()), out);
}

tool_result_t payloads_search_(const json& p)
{
    std::string q = get_or<std::string>(p, "query", std::string());
    diag::log_tagged_fmt("mcp_burp", "payloads_search query=%s", q.c_str());
    if (q.empty()) return tool_result_t::error("query required");
    std::string set_id = get_or<std::string>(p, "set_id", std::string());
    int cap = get_or<int>(p, "max", 200);
    auto v = payloads::search(q, set_id);
    if (cap > 0 && static_cast<int>(v.size()) > cap) v.resize(cap);
    json out;
    out["matches"] = v;
    out["returned"] = static_cast<int>(v.size());
    diag::log_tagged_fmt("mcp_burp", "payloads_search ok query=%s returned=%zu", q.c_str(), v.size());
    return tool_result_t::ok("payload search results count=" + std::to_string(v.size()), out);
}

tool_result_t payloads_add_(const json& p)
{
    std::string id = get_or<std::string>(p, "set_id", std::string());
    diag::log_tagged_fmt("mcp_burp", "payloads_add_custom set_id=%s", id.c_str());
    if (id.empty()) return tool_result_t::error("set_id required");
    std::string label = get_or<std::string>(p, "label", std::string());
    std::string desc  = get_or<std::string>(p, "description", std::string());
    auto entries = get_string_array(p, "entries");
    if (entries.empty()) return tool_result_t::error("entries required");
    if (!payloads::add_custom_set(id, label, desc, entries)) { diag::log_tagged_fmt("mcp_burp", "payloads_add_custom failed err=%s", payloads::last_error().c_str()); return tool_result_t::error(payloads::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "payloads_add_custom ok set_id=%s count=%zu", id.c_str(), entries.size());
    json out;
    out["set_id"] = id;
    out["count"] = static_cast<int>(entries.size());
    return tool_result_t::ok("custom set added", out);
}

}

void register_recon_tools(mcp_standalone::server_t& srv)
{
    crawler::initialize();
    content_discovery::initialize();
    subdomain_enum::initialize();
    payloads::initialize();

    register_compat(srv, {
        "burp_crawler_start", "burp",
        "Start a recursive web crawler that ingests pages, extracts links from HTML and JS, "
        "and publishes each fetched exchange to the Burp event bus.",
        {
            {"start_urls", "array", "Seed URLs (strings).", true},
            {"max_depth", "number", "Max crawl depth (default 3).", false},
            {"same_host_only", "boolean", "Restrict to seed host (default true).", false},
            {"scope_only", "boolean", "Restrict to URLs inside Burp scope (default false).", false},
            {"parse_js", "boolean", "Extract URLs from JS regex pass (default true).", false},
            {"max_pages", "number", "Stop after N pages (default 500).", false},
            {"concurrency", "number", "Parallel workers (default 8).", false},
            {"rate_per_host", "number", "Per-host RPS cap (default 10).", false},
            {"respect_robots", "boolean", "Honour robots.txt (default true).", false},
            {"user_agent", "string", "User-Agent header.", false},
            {"exclude_extensions", "array", "Skip URLs ending with any of these strings.", false},
            {"exclude_patterns", "array", "Skip URLs matching any regex.", false},
        },
        crawler_start, false
    });

    register_compat(srv, {
        "burp_crawler_status", "burp",
        "Return progress and discovered URLs for a running or finished crawl.",
        {
            {"crawl_id", "number", "ID returned by burp_crawler_start.", true},
            {"max_urls", "number", "Cap urls included (default 200).", false},
        },
        crawler_status_, true
    });

    register_compat(srv, {
        "burp_crawler_stop", "burp",
        "Request graceful shutdown of an active crawl.",
        {{"crawl_id", "number", "ID returned by burp_crawler_start.", true}},
        crawler_stop_, false
    });

    register_compat(srv, {
        "burp_crawler_list", "burp",
        "List all active and recent crawls.",
        {},
        crawler_list_, true
    });

    register_compat(srv, {
        "burp_content_discovery_start", "burp",
        "ffuf-style directory and file brute force. Replaces the FUZZ marker in target_url with each "
        "wordlist entry and reports hits.",
        {
            {"target_url", "string", "URL with FUZZ marker (path, query, header).", true},
            {"wordlist_id", "string", "Payload library set id (default dirs/common-100).", false},
            {"wordlist_file", "string", "Path to wordlist file (newline-separated).", false},
            {"extensions", "array", "Extensions to append (.php, .bak, ...).", false},
            {"concurrency", "number", "Parallel requests (default 25).", false},
            {"delay_ms", "number", "Inter-request delay per worker.", false},
            {"match_status", "array", "Status codes counted as hits (default 200,201,204,301,302,401,403,500).", false},
            {"filter_status", "array", "Status codes ignored.", false},
            {"filter_size_min", "number", "Filter response bodies whose size >= this.", false},
            {"filter_size_max", "number", "Filter response bodies whose size <= this.", false},
            {"filter_words_regex", "string", "Regex on body; matched responses filtered.", false},
            {"recurse", "boolean", "Recurse into hits as new bases.", false},
            {"recurse_depth", "number", "Max recursion depth (default 1).", false},
            {"method", "string", "HTTP method (default GET).", false},
            {"cookie", "string", "Cookie header value.", false},
            {"user_agent", "string", "User-Agent header.", false},
            {"follow_redirects", "boolean", "Follow Location: redirects.", false},
            {"auto_calibrate", "boolean", "Detect and filter soft-404 page size (default true).", false},
            {"extra_headers", "object", "Additional headers (name -> value).", false},
        },
        cd_start, false
    });

    register_compat(srv, {
        "burp_content_discovery_status", "burp",
        "Return counters and calibration data for a discovery run.",
        {{"disc_id", "number", "ID returned by burp_content_discovery_start.", true}},
        cd_status_, true
    });

    register_compat(srv, {
        "burp_content_discovery_results", "burp",
        "Return discovered hits (filtered by match/filter status and size range).",
        {
            {"disc_id", "number", "ID returned by burp_content_discovery_start.", true},
            {"max_results", "number", "Cap returned hits (default 500).", false},
        },
        cd_results_, true
    });

    register_compat(srv, {
        "burp_content_discovery_stop", "burp",
        "Request graceful shutdown of an active discovery run.",
        {{"disc_id", "number", "ID returned by burp_content_discovery_start.", true}},
        cd_stop_, false
    });

    register_compat(srv, {
        "burp_subdomain_enum_start", "burp",
        "Run passive subdomain sources (crt.sh, bufferover, hackertarget) and optional brute-force DNS resolution.",
        {
            {"domain", "string", "Apex domain (example.com).", true},
            {"brute_wordlist_id", "string", "Payload library set id (default subdomains/top1000).", false},
            {"brute_wordlist_file", "string", "Path to wordlist file.", false},
            {"sources", "array", "Passive sources to use (crt.sh, bufferover, hackertarget).", false},
            {"run_passive", "boolean", "Enable passive sources (default true).", false},
            {"run_brute", "boolean", "Enable brute resolution (default true).", false},
            {"concurrency", "number", "Resolver concurrency (default 32).", false},
            {"bypass_dns_cache", "boolean", "Use DNS_QUERY_BYPASS_CACHE (default true).", false},
            {"user_agent", "string", "User-Agent for passive HTTP calls.", false},
        },
        sub_start, false
    });

    register_compat(srv, {
        "burp_subdomain_enum_status", "burp",
        "Return counters for a subdomain enumeration run.",
        {{"sub_id", "number", "ID returned by burp_subdomain_enum_start.", true}},
        sub_status_, true
    });

    register_compat(srv, {
        "burp_subdomain_enum_results", "burp",
        "Return discovered subdomains with sources and resolved IPs.",
        {
            {"sub_id", "number", "ID returned by burp_subdomain_enum_start.", true},
            {"max_results", "number", "Cap returned entries (default 1000).", false},
        },
        sub_results_, true
    });

    register_compat(srv, {
        "burp_payloads_list", "burp",
        "List available payload sets (id, label, entry count).",
        {},
        payloads_list, true
    });

    register_compat(srv, {
        "burp_payloads_get", "burp",
        "Return entries from a payload set (capped).",
        {
            {"set_id", "string", "Payload set id (e.g. xss/polyglot).", true},
            {"max", "number", "Max entries returned (default 500).", false},
        },
        payloads_get_, true
    });

    register_compat(srv, {
        "burp_payloads_search", "burp",
        "Substring search across payload sets.",
        {
            {"query", "string", "Substring to search for.", true},
            {"set_id", "string", "Restrict to one set (optional).", false},
            {"max", "number", "Cap returned matches (default 200).", false},
        },
        payloads_search_, true
    });

    register_compat(srv, {
        "burp_payloads_add_custom", "burp",
        "Create or replace a custom payload set (persisted to %APPDATA%/AiDA/Standalone/burp/payloads/).",
        {
            {"set_id", "string", "Set id (must not collide with a builtin).", true},
            {"label", "string", "Friendly label.", false},
            {"description", "string", "Description.", false},
            {"entries", "array", "Array of payload strings.", true},
        },
        payloads_add_, false
    });
}

}
}
