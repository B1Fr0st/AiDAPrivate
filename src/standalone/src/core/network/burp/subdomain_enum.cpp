#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>

#ifdef small
#undef small
#endif

#pragma comment(lib, "Dnsapi.lib")
#pragma comment(lib, "Ws2_32.lib")

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include "subdomain_enum.hpp"
#include "payload_library.hpp"

#include "helpers/diag_log.hpp"
#include "../../infra/work_queue.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <memory>
#include <mutex>
#include <regex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace aida {
namespace burp {
namespace subdomain_enum {

namespace {

struct enum_t
{
    uint64_t                                                   id = 0;
    config_t                                                   config;
    std::mutex                                                 mtx;
    std::atomic<bool>                                          stop_flag{false};
    std::atomic<bool>                                          finished{false};
    enum_phase_t                                               phase = enum_phase_t::pending;
    std::unordered_map<std::string, subdomain_t>               results;
    std::atomic<int>                                           passive_count{0};
    std::atomic<int>                                           brute_attempts{0};
    std::atomic<int>                                           brute_resolved{0};
    std::atomic<int>                                           in_flight{0};
    uint64_t                                                   started_unix_ms = 0;
    uint64_t                                                   finished_unix_ms = 0;
    std::string                                                last_error;
};

struct registry_t
{
    std::mutex                                                 mtx;
    std::unordered_map<uint64_t, std::shared_ptr<enum_t>>      by_id;
    std::atomic<uint64_t>                                      next_id{1};
    std::atomic<bool>                                          init_done{false};
    std::mutex                                                 err_mtx;
    std::string                                                last_err;
};

registry_t& reg() { static registry_t r; return r; }

uint64_t now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

void set_err(const std::string& m)
{
    auto& r = reg();
    std::lock_guard<std::mutex> lk(r.err_mtx);
    r.last_err = m;
}

std::string to_lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string sockaddr_to_str(const sockaddr* sa)
{
    char buf[INET6_ADDRSTRLEN] = {};
    if (sa->sa_family == AF_INET)
    {
        const sockaddr_in* s = reinterpret_cast<const sockaddr_in*>(sa);
        InetNtopA(AF_INET, const_cast<IN_ADDR*>(&s->sin_addr), buf, sizeof(buf));
    }
    else if (sa->sa_family == AF_INET6)
    {
        const sockaddr_in6* s = reinterpret_cast<const sockaddr_in6*>(sa);
        InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&s->sin6_addr), buf, sizeof(buf));
    }
    return std::string(buf);
}

bool ensure_winsock()
{
    static std::atomic<int> rc{-1};
    int v = rc.load();
    if (v >= 0) return v == 0;
    WSADATA d{};
    int r = WSAStartup(MAKEWORD(2, 2), &d);
    int prev = -1;
    if (!rc.compare_exchange_strong(prev, r)) return rc.load() == 0;
    return r == 0;
}

bool resolve_fqdn(const std::string& fqdn, bool bypass_cache, std::vector<std::string>& out_ips)
{
    ensure_winsock();
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    int rc = getaddrinfo(fqdn.c_str(), nullptr, &hints, &res);
    if (rc == 0 && res)
    {
        for (auto* it = res; it; it = it->ai_next)
        {
            std::string ip = sockaddr_to_str(it->ai_addr);
            if (!ip.empty() && std::find(out_ips.begin(), out_ips.end(), ip) == out_ips.end())
                out_ips.push_back(ip);
        }
        freeaddrinfo(res);
    }
    if (!out_ips.empty() && !bypass_cache) return true;

    DWORD flags = DNS_QUERY_STANDARD;
    if (bypass_cache) flags |= DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE;
    PDNS_RECORD recs = nullptr;
    DNS_STATUS st = DnsQuery_UTF8(fqdn.c_str(), DNS_TYPE_A, flags, nullptr, &recs, nullptr);
    if (st == 0 && recs)
    {
        for (PDNS_RECORD r = recs; r; r = r->pNext)
        {
            if (r->wType == DNS_TYPE_A)
            {
                in_addr a{};
                a.S_un.S_addr = r->Data.A.IpAddress;
                char buf[INET_ADDRSTRLEN] = {};
                InetNtopA(AF_INET, &a, buf, sizeof(buf));
                std::string ip(buf);
                if (!ip.empty() && std::find(out_ips.begin(), out_ips.end(), ip) == out_ips.end())
                    out_ips.push_back(ip);
            }
        }
        DnsRecordListFree(recs, DnsFreeRecordList);
    }
    PDNS_RECORD recs6 = nullptr;
    DNS_STATUS st6 = DnsQuery_UTF8(fqdn.c_str(), DNS_TYPE_AAAA, flags, nullptr, &recs6, nullptr);
    if (st6 == 0 && recs6)
    {
        for (PDNS_RECORD r = recs6; r; r = r->pNext)
        {
            if (r->wType == DNS_TYPE_AAAA)
            {
                in6_addr a{};
                memcpy(&a, &r->Data.AAAA.Ip6Address, sizeof(a));
                char buf[INET6_ADDRSTRLEN] = {};
                InetNtopA(AF_INET6, &a, buf, sizeof(buf));
                std::string ip(buf);
                if (!ip.empty() && std::find(out_ips.begin(), out_ips.end(), ip) == out_ips.end())
                    out_ips.push_back(ip);
            }
        }
        DnsRecordListFree(recs6, DnsFreeRecordList);
    }
    return !out_ips.empty();
}

bool https_fetch(const std::string& full_url, const std::string& user_agent, int timeout_ms, std::string& out_body)
{
    out_body.clear();
    std::string work = full_url;
    bool tls = true;
    if (work.rfind("https://", 0) == 0) work = work.substr(8);
    else if (work.rfind("http://", 0) == 0) { work = work.substr(7); tls = false; }
    else return false;
    auto slash = work.find('/');
    std::string host_part;
    std::string path = "/";
    if (slash != std::string::npos) { host_part = work.substr(0, slash); path = work.substr(slash); }
    else host_part = work;
    int port = tls ? 443 : 80;
    auto pc = host_part.find(':');
    if (pc != std::string::npos)
    {
        try { port = std::stoi(host_part.substr(pc + 1)); host_part = host_part.substr(0, pc); }
        catch (...) { return false; }
    }
    std::string base = (tls ? "https://" : "http://") + host_part + ":" + std::to_string(port);
    httplib::Client cli(base);
    cli.set_connection_timeout(std::chrono::milliseconds(timeout_ms));
    cli.set_read_timeout(std::chrono::milliseconds(timeout_ms));
    cli.set_write_timeout(std::chrono::milliseconds(timeout_ms));
    cli.set_follow_location(true);
    cli.enable_server_certificate_verification(false);
    httplib::Headers h;
    h.emplace("User-Agent", user_agent);
    h.emplace("Accept", "application/json,text/plain,*/*");
    auto res = cli.Get(path.c_str(), h);
    if (!res) return false;
    if (res->status < 200 || res->status >= 300) return false;
    out_body = res->body;
    return true;
}

void merge_subdomain(enum_t& e, const std::string& fqdn, const std::string& source, const std::vector<std::string>& ips, bool resolves)
{
    std::string clean = to_lower(fqdn);
    while (!clean.empty() && (clean.back() == '.' || clean.back() == ' ')) clean.pop_back();
    while (!clean.empty() && (clean.front() == '.' || clean.front() == ' ' || clean.front() == '*')) clean.erase(clean.begin());
    if (clean.empty()) return;
    if (clean.find('*') != std::string::npos) return;
    if (clean.find(' ') != std::string::npos) return;
    std::lock_guard<std::mutex> lk(e.mtx);
    auto& rec = e.results[clean];
    if (rec.fqdn.empty())
    {
        rec.fqdn = clean;
        rec.discovered_unix_ms = now_ms();
    }
    if (!source.empty())
    {
        if (std::find(rec.sources.begin(), rec.sources.end(), source) == rec.sources.end())
            rec.sources.push_back(source);
    }
    for (auto& ip : ips)
    {
        if (std::find(rec.ips.begin(), rec.ips.end(), ip) == rec.ips.end())
            rec.ips.push_back(ip);
    }
    if (resolves) rec.resolves = true;
}

void passive_crtsh(std::shared_ptr<enum_t> ctx)
{
    diag::log_tagged_fmt("subdomain_enum", "passive_crtsh id=%llu domain=%s", static_cast<unsigned long long>(ctx->id), ctx->config.domain.c_str());
    if (ctx->stop_flag.load()) {
        diag::log_tagged_fmt("subdomain_enum", "passive_crtsh id=%llu stopped", static_cast<unsigned long long>(ctx->id));
        return;
    }
    std::string url = "https://crt.sh/?q=%25." + ctx->config.domain + "&output=json";
    std::string body;
    if (!https_fetch(url, ctx->config.user_agent, ctx->config.request_timeout_ms, body))
    {
        diag::log_tagged_fmt("burp.subdomain_enum", "crtsh_failed domain=%s", ctx->config.domain.c_str());
        return;
    }
    diag::log_tagged_fmt("subdomain_enum", "passive_crtsh id=%llu body_bytes=%zu", static_cast<unsigned long long>(ctx->id), body.size());
    nlohmann::json j = nlohmann::json::parse(body, nullptr, false);
    if (j.is_discarded() || !j.is_array())
    {
        diag::log_tagged_fmt("burp.subdomain_enum", "crtsh_parse_failed domain=%s body_bytes=%zu", ctx->config.domain.c_str(), body.size());
        return;
    }
    int added = 0;
    for (auto& entry : j)
    {
        if (!entry.is_object()) continue;
        std::string name_value;
        if (entry.contains("name_value") && entry["name_value"].is_string()) name_value = entry["name_value"].get<std::string>();
        if (name_value.empty()) continue;
        std::istringstream iss(name_value);
        std::string line;
        while (std::getline(iss, line))
        {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
            if (line.empty()) continue;
            if (line.find(ctx->config.domain) == std::string::npos) continue;
            merge_subdomain(*ctx, line, "crt.sh", {}, false);
            added++;
        }
    }
    ctx->passive_count.fetch_add(added);
    diag::log_tagged_fmt("subdomain_enum", "passive_crtsh id=%llu added=%d", static_cast<unsigned long long>(ctx->id), added);
}

void passive_bufferover(std::shared_ptr<enum_t> ctx)
{
    diag::log_tagged_fmt("subdomain_enum", "passive_bufferover id=%llu domain=%s", static_cast<unsigned long long>(ctx->id), ctx->config.domain.c_str());
    if (ctx->stop_flag.load()) return;
    std::string url = "https://dns.bufferover.run/dns?q=" + ctx->config.domain;
    std::string body;
    if (!https_fetch(url, ctx->config.user_agent, ctx->config.request_timeout_ms, body)) return;
    nlohmann::json j = nlohmann::json::parse(body, nullptr, false);
    if (j.is_discarded()) return;
    int added = 0;
    auto handle_array = [&](const nlohmann::json& arr) {
        if (!arr.is_array()) return;
        for (auto& s : arr)
        {
            if (!s.is_string()) continue;
            std::string line = s.get<std::string>();
            auto comma = line.find(',');
            std::string host = (comma == std::string::npos) ? line : line.substr(comma + 1);
            std::string ip = (comma == std::string::npos) ? std::string() : line.substr(0, comma);
            if (host.find(ctx->config.domain) == std::string::npos) continue;
            std::vector<std::string> ips;
            if (!ip.empty()) ips.push_back(ip);
            merge_subdomain(*ctx, host, "bufferover.run", ips, false);
            added++;
        }
    };
    if (j.contains("FDNS_A")) handle_array(j["FDNS_A"]);
    if (j.contains("RDNS")) handle_array(j["RDNS"]);
    ctx->passive_count.fetch_add(added);
    diag::log_tagged_fmt("subdomain_enum", "passive_bufferover id=%llu added=%d", static_cast<unsigned long long>(ctx->id), added);
}

void passive_hackertarget(std::shared_ptr<enum_t> ctx)
{
    diag::log_tagged_fmt("subdomain_enum", "passive_hackertarget id=%llu domain=%s", static_cast<unsigned long long>(ctx->id), ctx->config.domain.c_str());
    if (ctx->stop_flag.load()) return;
    std::string url = "https://api.hackertarget.com/hostsearch/?q=" + ctx->config.domain;
    std::string body;
    if (!https_fetch(url, ctx->config.user_agent, ctx->config.request_timeout_ms, body)) return;
    if (body.find("error") != std::string::npos && body.size() < 256) return;
    int added = 0;
    std::istringstream iss(body);
    std::string line;
    while (std::getline(iss, line))
    {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.empty()) continue;
        auto comma = line.find(',');
        std::string host = (comma == std::string::npos) ? line : line.substr(0, comma);
        std::string ip = (comma == std::string::npos) ? std::string() : line.substr(comma + 1);
        if (host.find(ctx->config.domain) == std::string::npos) continue;
        std::vector<std::string> ips;
        if (!ip.empty()) ips.push_back(ip);
        merge_subdomain(*ctx, host, "hackertarget", ips, false);
        added++;
    }
    ctx->passive_count.fetch_add(added);
    diag::log_tagged_fmt("subdomain_enum", "passive_hackertarget id=%llu added=%d", static_cast<unsigned long long>(ctx->id), added);
}

std::vector<std::string> load_brute_words(const config_t& cfg)
{
    if (!cfg.brute_wordlist_file.empty())
    {
        std::vector<std::string> v;
        std::ifstream f(cfg.brute_wordlist_file, std::ios::binary);
        if (!f) return v;
        std::string l;
        while (std::getline(f, l))
        {
            while (!l.empty() && (l.back() == '\r' || l.back() == '\n')) l.pop_back();
            if (!l.empty()) v.push_back(l);
        }
        return v;
    }
    return payloads::entries(cfg.brute_wordlist_id, 0);
}

void brute_one(std::shared_ptr<enum_t> ctx, const std::string& word)
{
    ctx->in_flight.fetch_add(1);
    ctx->brute_attempts.fetch_add(1);
    std::string fqdn = word + "." + ctx->config.domain;
    diag::log_tagged_fmt("subdomain_enum", "brute_one id=%llu fqdn=%s", static_cast<unsigned long long>(ctx->id), fqdn.c_str());
    if (!ctx->stop_flag.load())
    {
        std::vector<std::string> ips;
        bool ok = resolve_fqdn(fqdn, ctx->config.bypass_dns_cache, ips);
        if (ok)
        {
            ctx->brute_resolved.fetch_add(1);
            std::string ip_list;
            for (size_t i = 0; i < ips.size(); ++i) { if (i) ip_list += ","; ip_list += ips[i]; }
            diag::log_tagged_fmt("subdomain_enum", "brute_one resolved id=%llu fqdn=%s ips=%s", static_cast<unsigned long long>(ctx->id), fqdn.c_str(), ip_list.c_str());
            merge_subdomain(*ctx, fqdn, "brute", ips, true);
        } else {
            diag::log_tagged_fmt("subdomain_enum", "brute_one nxdomain id=%llu fqdn=%s", static_cast<unsigned long long>(ctx->id), fqdn.c_str());
        }
    }
    ctx->in_flight.fetch_sub(1);
}

void resolve_known_passive(std::shared_ptr<enum_t> ctx)
{
    std::vector<std::string> fqdns;
    {
        std::lock_guard<std::mutex> lk(ctx->mtx);
        fqdns.reserve(ctx->results.size());
        for (auto& kv : ctx->results) if (!kv.second.resolves) fqdns.push_back(kv.first);
    }
    diag::log_tagged_fmt("subdomain_enum", "resolve_known_passive id=%llu fqdns_to_resolve=%zu", static_cast<unsigned long long>(ctx->id), fqdns.size());
    int resolved = 0;
    for (auto& f : fqdns)
    {
        if (ctx->stop_flag.load()) {
            diag::log_tagged_fmt("subdomain_enum", "resolve_known_passive id=%llu stopped resolved_so_far=%d", static_cast<unsigned long long>(ctx->id), resolved);
            break;
        }
        std::vector<std::string> ips;
        if (resolve_fqdn(f, ctx->config.bypass_dns_cache, ips)) {
            merge_subdomain(*ctx, f, std::string(), ips, true);
            resolved++;
            diag::log_tagged_fmt("subdomain_enum", "resolve_known_passive resolved id=%llu fqdn=%s ip_count=%zu", static_cast<unsigned long long>(ctx->id), f.c_str(), ips.size());
        }
    }
    diag::log_tagged_fmt("subdomain_enum", "resolve_known_passive done id=%llu resolved=%d of %zu", static_cast<unsigned long long>(ctx->id), resolved, fqdns.size());
}

void finalize(std::shared_ptr<enum_t> ctx)
{
    {
        std::lock_guard<std::mutex> lk(ctx->mtx);
        if (ctx->phase != enum_phase_t::complete)
        {
            ctx->phase = enum_phase_t::complete;
            ctx->finished_unix_ms = now_ms();
        }
    }
    ctx->finished.store(true);
    diag::log_tagged_fmt("burp.subdomain_enum", "enum_finished id=%llu total=%zu passive=%d brute_ok=%d",
        static_cast<unsigned long long>(ctx->id),
        ctx->results.size(), ctx->passive_count.load(), ctx->brute_resolved.load());
}

void run_enum(std::shared_ptr<enum_t> ctx)
{
    diag::log_tagged_fmt("subdomain_enum", "run_enum id=%llu domain=%s run_passive=%d run_brute=%d",
        static_cast<unsigned long long>(ctx->id), ctx->config.domain.c_str(),
        ctx->config.run_passive ? 1 : 0, ctx->config.run_brute ? 1 : 0);
    {
        std::lock_guard<std::mutex> lk(ctx->mtx);
        ctx->phase = enum_phase_t::passive;
    }
    if (ctx->config.run_passive && !ctx->stop_flag.load())
    {
        diag::log_tagged_fmt("subdomain_enum", "run_enum passive_phase id=%llu", static_cast<unsigned long long>(ctx->id));
        std::vector<std::string> sources = ctx->config.passive_sources;
        if (sources.empty()) sources = {"crt.sh", "bufferover", "hackertarget"};
        for (auto& src : sources)
        {
            if (ctx->stop_flag.load()) break;
            diag::log_tagged_fmt("subdomain_enum", "run_enum passive_source id=%llu src=%s", static_cast<unsigned long long>(ctx->id), src.c_str());
            std::string ls = to_lower(src);
            if (ls.find("crt") != std::string::npos) passive_crtsh(ctx);
            else if (ls.find("bufferover") != std::string::npos) passive_bufferover(ctx);
            else if (ls.find("hackertarget") != std::string::npos) passive_hackertarget(ctx);
        }
        resolve_known_passive(ctx);
    }

    if (ctx->config.run_brute && !ctx->stop_flag.load())
    {
        {
            std::lock_guard<std::mutex> lk(ctx->mtx);
            ctx->phase = enum_phase_t::brute;
        }
        std::vector<std::string> words = load_brute_words(ctx->config);
        diag::log_tagged_fmt("subdomain_enum", "run_enum brute_phase id=%llu wordlist_size=%zu conc=%d",
            static_cast<unsigned long long>(ctx->id), words.size(), ctx->config.resolver_concurrency);
        if (words.empty())
        {
            diag::log_tagged_fmt("burp.subdomain_enum", "brute_empty_wordlist id=%llu wl=%s",
                static_cast<unsigned long long>(ctx->id), ctx->config.brute_wordlist_id.c_str());
        }

        const int target = std::max(1, std::min(ctx->config.resolver_concurrency, 128));
        auto running = std::make_shared<std::atomic<int>>(0);
        size_t i = 0;
        while (i < words.size() && !ctx->stop_flag.load())
        {
            while (running->load() >= target && !ctx->stop_flag.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            if (ctx->stop_flag.load()) break;
            const std::string w = words[i++];
            running->fetch_add(1);
            work_queue::post([ctx, w, running]() {
                brute_one(ctx, w);
                running->fetch_sub(1);
            });
        }
        while (running->load() > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    finalize(ctx);
}

}

bool initialize()
{
    diag::log_tagged_fmt("subdomain_enum", "initialize called");
    auto& r = reg();
    bool expected = false;
    if (!r.init_done.compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("subdomain_enum", "initialize already_done");
        return true;
    }
    payloads::initialize();
    ensure_winsock();
    diag::log_tagged_fmt("subdomain_enum", "initialize success");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("subdomain_enum", "shutdown called");
    auto& r = reg();
    if (!r.init_done.exchange(false)) {
        diag::log_tagged_fmt("subdomain_enum", "shutdown skipped not_initialized");
        return;
    }
    std::vector<std::shared_ptr<enum_t>> snaps;
    {
        std::lock_guard<std::mutex> lk(r.mtx);
        snaps.reserve(r.by_id.size());
        for (auto& kv : r.by_id) { kv.second->stop_flag.store(true); snaps.push_back(kv.second); }
    }
    diag::log_tagged_fmt("subdomain_enum", "shutdown stopping %zu jobs", snaps.size());
    for (int i = 0; i < 60; ++i)
    {
        bool done = true;
        for (auto& c : snaps) if (!c->finished.load() || c->in_flight.load() > 0) { done = false; break; }
        if (done) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    {
        std::lock_guard<std::mutex> lk(r.mtx);
        r.by_id.clear();
    }
    diag::log_tagged_fmt("subdomain_enum", "shutdown complete");
}

uint64_t start(const config_t& cfg)
{
    if (!reg().init_done.load()) initialize();
    if (cfg.domain.empty()) { set_err("empty domain"); return 0; }
    auto ctx = std::make_shared<enum_t>();
    ctx->id = reg().next_id.fetch_add(1);
    ctx->config = cfg;
    ctx->phase = enum_phase_t::pending;
    ctx->started_unix_ms = now_ms();
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        reg().by_id[ctx->id] = ctx;
    }
    diag::log_tagged_fmt("burp.subdomain_enum", "enum_start id=%llu domain=%s passive=%d brute=%d",
        static_cast<unsigned long long>(ctx->id), cfg.domain.c_str(), cfg.run_passive ? 1 : 0, cfg.run_brute ? 1 : 0);
    work_queue::post([ctx] { run_enum(ctx); });
    return ctx->id;
}

bool stop(uint64_t id)
{
    diag::log_tagged_fmt("subdomain_enum", "stop id=%llu", static_cast<unsigned long long>(id));
    std::shared_ptr<enum_t> ctx;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().by_id.find(id);
        if (it == reg().by_id.end()) {
            diag::log_tagged_fmt("subdomain_enum", "stop id=%llu not_found", static_cast<unsigned long long>(id));
            set_err("not found");
            return false;
        }
        ctx = it->second;
    }
    ctx->stop_flag.store(true);
    {
        std::lock_guard<std::mutex> lk(ctx->mtx);
        if (ctx->phase != enum_phase_t::complete) ctx->phase = enum_phase_t::stopping;
    }
    diag::log_tagged_fmt("burp.subdomain_enum", "enum_stop id=%llu", static_cast<unsigned long long>(id));
    return true;
}

enum_status_t status(uint64_t id)
{
    enum_status_t out;
    std::shared_ptr<enum_t> ctx;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().by_id.find(id);
        if (it == reg().by_id.end()) return out;
        ctx = it->second;
    }
    std::lock_guard<std::mutex> lk(ctx->mtx);
    out.id = ctx->id;
    out.phase = ctx->phase;
    out.passive_count = ctx->passive_count.load();
    out.brute_attempts = ctx->brute_attempts.load();
    out.brute_resolved = ctx->brute_resolved.load();
    out.started_unix_ms = ctx->started_unix_ms;
    out.finished_unix_ms = ctx->finished_unix_ms;
    out.last_error = ctx->last_error;
    out.config = ctx->config;
    out.results.reserve(ctx->results.size());
    for (auto& kv : ctx->results) out.results.push_back(kv.second);
    std::sort(out.results.begin(), out.results.end(), [](const subdomain_t& a, const subdomain_t& b){ return a.fqdn < b.fqdn; });
    return out;
}

std::vector<enum_status_t> list()
{
    std::vector<uint64_t> ids;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        ids.reserve(reg().by_id.size());
        for (auto& kv : reg().by_id) ids.push_back(kv.first);
    }
    std::sort(ids.begin(), ids.end());
    std::vector<enum_status_t> out;
    out.reserve(ids.size());
    for (auto i : ids) out.push_back(status(i));
    return out;
}

std::vector<subdomain_t> results(uint64_t id)
{
    return status(id).results;
}

bool remove(uint64_t id)
{
    std::shared_ptr<enum_t> ctx;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().by_id.find(id);
        if (it == reg().by_id.end()) { set_err("not found"); return false; }
        ctx = it->second;
    }
    ctx->stop_flag.store(true);
    for (int i = 0; i < 60; ++i)
    {
        if (ctx->finished.load() && ctx->in_flight.load() == 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        reg().by_id.erase(id);
    }
    return true;
}

std::string export_csv(uint64_t id)
{
    auto results_vec = results(id);
    std::ostringstream os;
    os << "fqdn,resolves,ips,sources\n";
    for (auto& r : results_vec)
    {
        std::string ips;
        for (size_t i = 0; i < r.ips.size(); ++i)
        {
            if (i) ips += "|";
            ips += r.ips[i];
        }
        std::string srcs;
        for (size_t i = 0; i < r.sources.size(); ++i)
        {
            if (i) srcs += "|";
            srcs += r.sources[i];
        }
        os << r.fqdn << "," << (r.resolves ? "yes" : "no") << "," << ips << "," << srcs << "\n";
    }
    return os.str();
}

std::string last_error()
{
    auto& r = reg();
    std::lock_guard<std::mutex> lk(r.err_mtx);
    return r.last_err;
}

}
}
}
