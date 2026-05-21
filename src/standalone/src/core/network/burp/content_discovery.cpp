#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include "content_discovery.hpp"
#include "payload_library.hpp"
#include "burp_events.hpp"
#include "site_map.hpp"

#include "helpers/diag_log.hpp"
#include "../../infra/event_bus.hpp"
#include "../../infra/work_queue.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <memory>
#include <mutex>
#include <random>
#include <regex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace aida {
namespace burp {
namespace content_discovery {

namespace {

struct candidate_t
{
    std::string url;
    std::string payload;
    int         depth = 0;
};

struct disc_t
{
    uint64_t                            id = 0;
    config_t                            config;
    std::mutex                          mtx;
    std::atomic<bool>                   stop_flag{false};
    std::atomic<bool>                   finished{false};
    disc_phase_t                        phase = disc_phase_t::pending;
    std::vector<candidate_t>            queue;
    std::unordered_set<std::string>     seen;
    std::vector<hit_t>                  hits_list;
    std::atomic<int>                    attempts{0};
    std::atomic<int>                    errors{0};
    std::atomic<int>                    filtered{0};
    std::atomic<int>                    in_flight{0};
    int                                 total = 0;
    uint64_t                            started_unix_ms = 0;
    uint64_t                            finished_unix_ms = 0;
    size_t                              calibrated_lo = 0;
    size_t                              calibrated_hi = 0;
    std::string                         last_error;
    std::string                         last_url;
    std::regex                          compiled_filter_words;
    bool                                has_filter_words = false;
};

struct registry_t
{
    std::mutex                                           mtx;
    std::unordered_map<uint64_t, std::shared_ptr<disc_t>> by_id;
    std::atomic<uint64_t>                                next_id{1};
    std::atomic<bool>                                    init_done{false};
    std::mutex                                           err_mtx;
    std::string                                          last_err;
};

registry_t& reg() { static registry_t r; return r; }

void set_err(const std::string& m)
{
    auto& r = reg();
    std::lock_guard<std::mutex> lk(r.err_mtx);
    r.last_err = m;
}

uint64_t now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string to_lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

struct parsed_t { std::string scheme; std::string host; uint16_t port = 0; std::string path; std::string query; bool valid=false; };

parsed_t parse_url(const std::string& url)
{
    parsed_t p;
    std::string work = url;
    auto colon = work.find("://");
    if (colon == std::string::npos) return p;
    p.scheme = to_lower(work.substr(0, colon));
    work = work.substr(colon + 3);
    auto q = work.find('?');
    if (q != std::string::npos) { p.query = work.substr(q + 1); work = work.substr(0, q); }
    auto slash = work.find('/');
    std::string host_part;
    if (slash != std::string::npos) { host_part = work.substr(0, slash); p.path = work.substr(slash); }
    else { host_part = work; p.path = "/"; }
    auto pc = host_part.find(':');
    if (pc != std::string::npos)
    {
        try { p.port = static_cast<uint16_t>(std::stoi(host_part.substr(pc + 1))); host_part = host_part.substr(0, pc); }
        catch (...) { return p; }
    }
    else p.port = (p.scheme == "https") ? 443 : 80;
    p.host = to_lower(host_part);
    if (p.scheme != "http" && p.scheme != "https") return p;
    if (p.host.empty()) return p;
    p.valid = true;
    return p;
}

std::vector<std::string> load_wordlist(const config_t& cfg, std::string& err)
{
    std::vector<std::string> out;
    if (!cfg.wordlist_id.empty())
    {
        auto v = payloads::entries(cfg.wordlist_id, 0);
        if (v.empty())
        {
            err = "wordlist id not found: " + cfg.wordlist_id;
            return {};
        }
        return v;
    }
    if (!cfg.wordlist_file.empty())
    {
        std::ifstream f(cfg.wordlist_file, std::ios::binary);
        if (!f) { err = "wordlist file open failed"; return {}; }
        std::string line;
        while (std::getline(f, line))
        {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
            if (!line.empty()) out.push_back(line);
        }
        if (out.empty()) err = "wordlist file empty";
        return out;
    }
    err = "no wordlist provided";
    return {};
}

std::string build_target_url(const std::string& base_template, const std::string& payload)
{
    std::string out;
    out.reserve(base_template.size() + payload.size());
    const std::string marker = "FUZZ";
    size_t pos = 0;
    while (pos < base_template.size())
    {
        size_t found = base_template.find(marker, pos);
        if (found == std::string::npos) { out.append(base_template, pos, std::string::npos); break; }
        out.append(base_template, pos, found - pos);
        out.append(payload);
        pos = found + marker.size();
    }
    return out;
}

bool perform_request(const std::string& url, const config_t& cfg,
                     int& out_status, size_t& out_body_bytes, std::string& out_body,
                     std::string& out_content_type, std::string& out_redirect,
                     std::vector<std::pair<std::string,std::string>>& out_resp_headers,
                     uint64_t& out_latency_ms, std::string& out_err)
{
    out_status = 0;
    out_body_bytes = 0;
    out_body.clear();
    out_content_type.clear();
    out_redirect.clear();
    out_resp_headers.clear();
    out_latency_ms = 0;

    parsed_t p = parse_url(url);
    if (!p.valid) { out_err = "invalid url"; return false; }

    const std::string base = p.scheme + "://" + p.host + ":" + std::to_string(p.port);
    httplib::Client cli(base);
    cli.set_connection_timeout(std::chrono::milliseconds(cfg.request_timeout_ms));
    cli.set_read_timeout(std::chrono::milliseconds(cfg.request_timeout_ms));
    cli.set_write_timeout(std::chrono::milliseconds(cfg.request_timeout_ms));
    cli.set_follow_location(cfg.follow_redirects);
    cli.enable_server_certificate_verification(false);

    httplib::Headers headers;
    headers.emplace("User-Agent", cfg.user_agent);
    headers.emplace("Accept", "*/*");
    headers.emplace("Accept-Encoding", "identity");
    if (!cfg.cookie_header.empty()) headers.emplace("Cookie", cfg.cookie_header);
    for (auto& h : cfg.extra_headers) headers.emplace(h.first, h.second);

    std::string path_with_query = p.path;
    if (!p.query.empty()) path_with_query += "?" + p.query;

    auto t0 = std::chrono::steady_clock::now();
    httplib::Result res;
    const std::string method = to_lower(cfg.method);
    if (method == "post") res = cli.Post(path_with_query.c_str(), headers, std::string(), "application/x-www-form-urlencoded");
    else if (method == "head") res = cli.Head(path_with_query.c_str(), headers);
    else if (method == "put") res = cli.Put(path_with_query.c_str(), headers, std::string(), "application/octet-stream");
    else if (method == "delete") res = cli.Delete(path_with_query.c_str(), headers);
    else if (method == "options") res = cli.Options(path_with_query.c_str(), headers);
    else res = cli.Get(path_with_query.c_str(), headers);
    auto t1 = std::chrono::steady_clock::now();
    out_latency_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

    if (!res) { out_err = "transport error"; return false; }
    out_status = res->status;
    out_body = res->body;
    out_body_bytes = res->body.size();
    for (auto& h : res->headers)
    {
        out_resp_headers.emplace_back(h.first, h.second);
        std::string ln = to_lower(h.first);
        if (ln == "content-type") out_content_type = h.second;
        else if (ln == "location") out_redirect = h.second;
    }
    return true;
}

bool status_in_set(int status, const std::vector<int>& set)
{
    for (int v : set) if (v == status) return true;
    return false;
}

void publish_exchange(const std::string& url, int status, const std::string& body,
                      const std::string& content_type,
                      const std::vector<std::pair<std::string,std::string>>& resp_headers,
                      const config_t& cfg, uint64_t latency)
{
    parsed_t p = parse_url(url);
    if (!p.valid) return;
    exchange_observed_t ev;
    ev.id = static_cast<uint64_t>(now_ms());
    ev.timestamp_ms = now_ms();
    ev.method = cfg.method;
    ev.scheme = p.scheme;
    ev.host = p.host;
    ev.port = p.port;
    ev.path = p.path;
    ev.query = p.query;
    ev.req_headers.emplace_back("Host", p.host);
    ev.req_headers.emplace_back("User-Agent", cfg.user_agent);
    if (!cfg.cookie_header.empty()) ev.req_headers.emplace_back("Cookie", cfg.cookie_header);
    for (auto& h : cfg.extra_headers) ev.req_headers.emplace_back(h.first, h.second);
    ev.status_code = status;
    ev.resp_headers = resp_headers;
    ev.resp_body.assign(body.begin(), body.end());
    ev.latency_ms = latency;
    if (!content_type.empty())
    {
        bool have = false;
        for (auto& h : ev.resp_headers) if (to_lower(h.first) == "content-type") { have = true; break; }
        if (!have) ev.resp_headers.emplace_back("Content-Type", content_type);
    }
    aida::events::publish(kExchangeObservedEvent, ev);
    sitemap::ingest_exchange(ev);
}

void run_disc(std::shared_ptr<disc_t> ctx);

void worker_one(std::shared_ptr<disc_t> ctx, candidate_t cand)
{
    diag::log_tagged_fmt("content_discovery", "worker_one id=%llu url=%s depth=%d",
        static_cast<unsigned long long>(ctx->id), cand.url.c_str(), cand.depth);
    auto& d = *ctx;
    d.in_flight.fetch_add(1);

    int status = 0;
    size_t body_bytes = 0;
    std::string body, content_type, redirect, err;
    std::vector<std::pair<std::string,std::string>> hdr;
    uint64_t lat = 0;
    bool ok = perform_request(cand.url, d.config, status, body_bytes, body, content_type, redirect, hdr, lat, err);
    diag::log_tagged_fmt("content_discovery", "worker_one result id=%llu url=%s ok=%d status=%d body=%zu lat=%llu err=%s",
        static_cast<unsigned long long>(ctx->id), cand.url.c_str(), ok ? 1 : 0,
        status, body_bytes, static_cast<unsigned long long>(lat), err.c_str());

    d.attempts.fetch_add(1);
    if (!ok) {
        d.errors.fetch_add(1);
        diag::log_tagged_fmt("content_discovery", "worker_one error id=%llu url=%s err=%s", static_cast<unsigned long long>(ctx->id), cand.url.c_str(), err.c_str());
    }
    else
    {
        {
            std::lock_guard<std::mutex> lk(d.mtx);
            d.last_url = cand.url;
        }
        bool match = status_in_set(status, d.config.match_status);
        if (status_in_set(status, d.config.filter_status)) match = false;
        diag::log_tagged_fmt("content_discovery", "worker_one filter_check id=%llu url=%s status=%d match=%d", static_cast<unsigned long long>(ctx->id), cand.url.c_str(), status, match ? 1 : 0);
        if (match && d.config.filter_size_max > 0)
        {
            if (body_bytes >= d.config.filter_size_min && body_bytes <= d.config.filter_size_max) match = false;
        }
        if (match && d.calibrated_lo > 0 && d.calibrated_hi > 0)
        {
            if (body_bytes >= d.calibrated_lo && body_bytes <= d.calibrated_hi) match = false;
        }
        if (match && d.has_filter_words)
        {
            if (std::regex_search(body, d.compiled_filter_words)) match = false;
        }

        if (match)
        {
            diag::log_tagged_fmt("content_discovery", "worker_one hit id=%llu url=%s status=%d body=%zu payload=%s",
                static_cast<unsigned long long>(ctx->id), cand.url.c_str(), status, body_bytes, cand.payload.c_str());
            hit_t h;
            h.url = cand.url;
            h.payload = cand.payload;
            h.status = status;
            h.body_bytes = body_bytes;
            h.latency_ms = lat;
            h.content_type = content_type;
            h.redirect_to = redirect;
            h.depth = cand.depth;
            {
                std::lock_guard<std::mutex> lk(d.mtx);
                d.hits_list.push_back(std::move(h));
            }
            publish_exchange(cand.url, status, body, content_type, hdr, d.config, lat);

            if (d.config.recurse && cand.depth < d.config.recurse_depth && status >= 200 && status < 300)
            {
                std::string next_base = cand.url;
                if (next_base.back() != '/') next_base += "/";
                next_base += "FUZZ";
                {
                    std::lock_guard<std::mutex> lk(d.mtx);
                    auto wl_err = std::string();
                    auto entries = load_wordlist(d.config, wl_err);
                    if (!entries.empty())
                    {
                        for (auto& e : entries)
                        {
                            if (d.config.extensions.empty())
                            {
                                std::string nu = build_target_url(next_base, e);
                                if (d.seen.insert(nu).second)
                                {
                                    candidate_t c; c.url = nu; c.payload = e; c.depth = cand.depth + 1;
                                    d.queue.push_back(std::move(c));
                                }
                            }
                            else
                            {
                                for (auto& x : d.config.extensions)
                                {
                                    std::string nu = build_target_url(next_base, e + x);
                                    if (d.seen.insert(nu).second)
                                    {
                                        candidate_t c; c.url = nu; c.payload = e + x; c.depth = cand.depth + 1;
                                        d.queue.push_back(std::move(c));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        else
        {
            d.filtered.fetch_add(1);
        }
    }

    if (d.config.delay_ms > 0 && !d.stop_flag.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(d.config.delay_ms));

    d.in_flight.fetch_sub(1);
    work_queue::post([ctx] { run_disc(ctx); });
}

void run_disc(std::shared_ptr<disc_t> ctx)
{
    auto& d = *ctx;
    if (d.finished.load()) return;
    if (d.stop_flag.load())
    {
        std::lock_guard<std::mutex> lk(d.mtx);
        d.queue.clear();
    }
    candidate_t next;
    bool has = false;
    {
        std::lock_guard<std::mutex> lk(d.mtx);
        if (!d.queue.empty())
        {
            next = std::move(d.queue.back());
            d.queue.pop_back();
            has = true;
        }
    }
    if (has)
    {
        worker_one(ctx, next);
        return;
    }
    if (d.in_flight.load() == 0)
    {
        if (d.finished.exchange(true)) return;
        std::lock_guard<std::mutex> lk(d.mtx);
        d.phase = disc_phase_t::complete;
        d.finished_unix_ms = now_ms();
        diag::log_tagged_fmt("burp.content_discovery", "disc_finished id=%llu attempts=%d hits=%d errors=%d filtered=%d",
            static_cast<unsigned long long>(d.id), d.attempts.load(), static_cast<int>(d.hits_list.size()), d.errors.load(), d.filtered.load());
        return;
    }
    work_queue::post([ctx] { std::this_thread::sleep_for(std::chrono::milliseconds(50)); run_disc(ctx); });
}

bool auto_calibrate(disc_t& d)
{
    diag::log_tagged_fmt("content_discovery", "auto_calibrate id=%llu target=%s", static_cast<unsigned long long>(d.id), d.config.target_url.c_str());
    static const char* k = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::mt19937 rng(static_cast<uint32_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<int> dist(0, 35);
    std::vector<size_t> sizes;
    for (int i = 0; i < 3 && !d.stop_flag.load(); ++i)
    {
        std::string junk;
        for (int j = 0; j < 16; ++j) junk.push_back(k[dist(rng)]);
        std::string url = build_target_url(d.config.target_url, junk + "_aida_calib");
        int status = 0;
        size_t body_bytes = 0;
        std::string body, ct, redir, err;
        std::vector<std::pair<std::string,std::string>> hdr;
        uint64_t lat = 0;
        if (perform_request(url, d.config, status, body_bytes, body, ct, redir, hdr, lat, err)) {
            diag::log_tagged_fmt("content_discovery", "auto_calibrate probe id=%llu url=%s status=%d body=%zu", static_cast<unsigned long long>(d.id), url.c_str(), status, body_bytes);
            sizes.push_back(body_bytes);
        } else {
            diag::log_tagged_fmt("content_discovery", "auto_calibrate probe_failed id=%llu url=%s err=%s", static_cast<unsigned long long>(d.id), url.c_str(), err.c_str());
        }
    }
    if (sizes.empty()) {
        diag::log_tagged_fmt("content_discovery", "auto_calibrate failed id=%llu no_samples", static_cast<unsigned long long>(d.id));
        return false;
    }
    std::sort(sizes.begin(), sizes.end());
    size_t lo = sizes.front();
    size_t hi = sizes.back();
    if (hi > 0) hi += hi / 20 + 8;
    if (lo > 8) lo -= 8;
    d.calibrated_lo = lo;
    d.calibrated_hi = hi;
    diag::log_tagged_fmt("content_discovery", "auto_calibrate result id=%llu lo=%zu hi=%zu samples=%zu",
        static_cast<unsigned long long>(d.id), lo, hi, sizes.size());
    return true;
}

}

bool initialize()
{
    diag::log_tagged_fmt("content_discovery", "initialize called");
    auto& r = reg();
    bool expected = false;
    if (!r.init_done.compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("content_discovery", "initialize already_done");
        return true;
    }
    payloads::initialize();
    diag::log_tagged_fmt("content_discovery", "initialize success");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("content_discovery", "shutdown called");
    auto& r = reg();
    if (!r.init_done.exchange(false)) {
        diag::log_tagged_fmt("content_discovery", "shutdown skipped not_initialized");
        return;
    }
    std::vector<std::shared_ptr<disc_t>> snaps;
    {
        std::lock_guard<std::mutex> lk(r.mtx);
        snaps.reserve(r.by_id.size());
        for (auto& kv : r.by_id) { kv.second->stop_flag.store(true); snaps.push_back(kv.second); }
    }
    diag::log_tagged_fmt("content_discovery", "shutdown stopping %zu jobs", snaps.size());
    for (int i = 0; i < 40; ++i)
    {
        bool done = true;
        for (auto& d : snaps) if (!d->finished.load() || d->in_flight.load() > 0) { done = false; break; }
        if (done) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    {
        std::lock_guard<std::mutex> lk(r.mtx);
        r.by_id.clear();
    }
    diag::log_tagged_fmt("content_discovery", "shutdown complete");
}

uint64_t start(const config_t& cfg)
{
    if (!reg().init_done.load()) initialize();
    if (cfg.target_url.empty() || cfg.target_url.find("FUZZ") == std::string::npos)
    {
        set_err("target_url must contain FUZZ marker");
        return 0;
    }
    std::string err;
    auto entries = load_wordlist(cfg, err);
    if (entries.empty())
    {
        set_err(err.empty() ? "wordlist empty" : err);
        return 0;
    }
    auto ctx = std::make_shared<disc_t>();
    ctx->id = reg().next_id.fetch_add(1);
    ctx->config = cfg;
    if (ctx->config.match_status.empty()) ctx->config.match_status = {200, 201, 204, 301, 302, 401, 403, 500};
    if (!cfg.filter_words_regex.empty())
    {
        try { ctx->compiled_filter_words = std::regex(cfg.filter_words_regex); ctx->has_filter_words = true; }
        catch (...) { ctx->has_filter_words = false; }
    }
    ctx->phase = disc_phase_t::calibrating;
    ctx->started_unix_ms = now_ms();

    {
        std::lock_guard<std::mutex> lk(ctx->mtx);
        for (auto& e : entries)
        {
            if (cfg.extensions.empty())
            {
                std::string url = build_target_url(cfg.target_url, e);
                if (ctx->seen.insert(url).second)
                {
                    candidate_t c; c.url = url; c.payload = e; c.depth = 0;
                    ctx->queue.push_back(std::move(c));
                }
            }
            else
            {
                for (auto& x : cfg.extensions)
                {
                    std::string url = build_target_url(cfg.target_url, e + x);
                    if (ctx->seen.insert(url).second)
                    {
                        candidate_t c; c.url = url; c.payload = e + x; c.depth = 0;
                        ctx->queue.push_back(std::move(c));
                    }
                }
            }
        }
        ctx->total = static_cast<int>(ctx->queue.size());
    }

    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        reg().by_id[ctx->id] = ctx;
    }
    diag::log_tagged_fmt("burp.content_discovery", "disc_start id=%llu target=%s total=%d conc=%d delay=%d",
        static_cast<unsigned long long>(ctx->id), cfg.target_url.c_str(), ctx->total, cfg.concurrency, cfg.delay_ms);

    work_queue::post([ctx] {
        if (ctx->config.auto_calibrate) auto_calibrate(*ctx);
        {
            std::lock_guard<std::mutex> lk(ctx->mtx);
            ctx->phase = disc_phase_t::running;
        }
        int kick = std::max(1, std::min(ctx->config.concurrency, 64));
        for (int i = 0; i < kick; ++i)
            work_queue::post([ctx] { run_disc(ctx); });
    });

    return ctx->id;
}

bool stop(uint64_t id)
{
    diag::log_tagged_fmt("content_discovery", "stop id=%llu", static_cast<unsigned long long>(id));
    std::shared_ptr<disc_t> ctx;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().by_id.find(id);
        if (it == reg().by_id.end()) {
            diag::log_tagged_fmt("content_discovery", "stop id=%llu not_found", static_cast<unsigned long long>(id));
            set_err("not found");
            return false;
        }
        ctx = it->second;
    }
    ctx->stop_flag.store(true);
    {
        std::lock_guard<std::mutex> lk(ctx->mtx);
        if (ctx->phase != disc_phase_t::complete) ctx->phase = disc_phase_t::stopping;
    }
    diag::log_tagged_fmt("burp.content_discovery", "disc_stop id=%llu", static_cast<unsigned long long>(id));
    return true;
}

disc_status_t status(uint64_t id)
{
    disc_status_t out;
    std::shared_ptr<disc_t> ctx;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().by_id.find(id);
        if (it == reg().by_id.end()) return out;
        ctx = it->second;
    }
    std::lock_guard<std::mutex> lk(ctx->mtx);
    out.id = ctx->id;
    out.phase = ctx->phase;
    out.attempts = ctx->attempts.load();
    out.total = ctx->total;
    out.hits = static_cast<int>(ctx->hits_list.size());
    out.filtered = ctx->filtered.load();
    out.errors = ctx->errors.load();
    out.started_unix_ms = ctx->started_unix_ms;
    out.finished_unix_ms = ctx->finished_unix_ms;
    out.calibrated_size_lo = ctx->calibrated_lo;
    out.calibrated_size_hi = ctx->calibrated_hi;
    out.last_error = ctx->last_error;
    out.last_url = ctx->last_url;
    out.config = ctx->config;
    out.hits_list = ctx->hits_list;
    return out;
}

std::vector<disc_status_t> list()
{
    std::vector<uint64_t> ids;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        ids.reserve(reg().by_id.size());
        for (auto& kv : reg().by_id) ids.push_back(kv.first);
    }
    std::sort(ids.begin(), ids.end());
    std::vector<disc_status_t> out;
    out.reserve(ids.size());
    for (auto id : ids) out.push_back(status(id));
    return out;
}

std::vector<hit_t> results(uint64_t id)
{
    std::shared_ptr<disc_t> ctx;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().by_id.find(id);
        if (it == reg().by_id.end()) return {};
        ctx = it->second;
    }
    std::lock_guard<std::mutex> lk(ctx->mtx);
    return ctx->hits_list;
}

bool remove(uint64_t id)
{
    diag::log_tagged_fmt("content_discovery", "remove id=%llu", static_cast<unsigned long long>(id));
    std::shared_ptr<disc_t> ctx;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().by_id.find(id);
        if (it == reg().by_id.end()) {
            diag::log_tagged_fmt("content_discovery", "remove id=%llu not_found", static_cast<unsigned long long>(id));
            set_err("not found");
            return false;
        }
        ctx = it->second;
    }
    ctx->stop_flag.store(true);
    for (int i = 0; i < 40; ++i)
    {
        if (ctx->finished.load() && ctx->in_flight.load() == 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        reg().by_id.erase(id);
    }
    diag::log_tagged_fmt("content_discovery", "remove id=%llu complete", static_cast<unsigned long long>(id));
    return true;
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
