#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include "crawler.hpp"
#include "scope.hpp"
#include "burp_events.hpp"
#include "site_map.hpp"

#include "helpers/diag_log.hpp"
#include "../../infra/event_bus.hpp"
#include "../../infra/work_queue.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace aida {
namespace burp {
namespace crawler {

namespace {

struct queue_item_t
{
    std::string url;
    int         depth = 0;
    std::string parent;
};

struct host_rate_t
{
    std::mutex                            mtx;
    std::deque<std::chrono::steady_clock::time_point> stamps;
    std::vector<std::string>              robots_disallow;
    bool                                  robots_fetched = false;
};

struct crawl_t
{
    uint64_t                            id = 0;
    crawl_config_t                      config;
    std::mutex                          mtx;
    std::atomic<bool>                   stop_flag{false};
    std::atomic<bool>                   finished{false};
    crawl_status_phase_t                phase = crawl_status_phase_t::pending;
    std::deque<queue_item_t>            queue;
    std::unordered_set<std::string>     seen;
    std::vector<discovered_url_t>       discovered;
    std::vector<std::string>            log;
    std::unordered_map<std::string, std::shared_ptr<host_rate_t>> host_rates;
    int                                 pages_visited = 0;
    int                                 pages_failed = 0;
    std::string                         last_url;
    std::string                         last_error;
    uint64_t                            started_unix_ms = 0;
    uint64_t                            finished_unix_ms = 0;
    std::atomic<int>                    in_flight{0};
    std::atomic<uint64_t>               next_request_seq{1};
};

struct registry_t
{
    std::mutex                                            mtx;
    std::unordered_map<uint64_t, std::shared_ptr<crawl_t>> by_id;
    std::atomic<uint64_t>                                 next_id{1};
    std::atomic<bool>                                     init_done{false};
    std::mutex                                            err_mtx;
    std::string                                           last_err;
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

struct parsed_url_t
{
    std::string scheme;
    std::string host;
    uint16_t    port = 0;
    std::string path;
    std::string query;
    std::string fragment;
    bool        valid = false;
};

parsed_url_t parse_url(const std::string& url)
{
    parsed_url_t p;
    std::string work = url;
    auto colon = work.find("://");
    if (colon == std::string::npos) return p;
    p.scheme = to_lower(work.substr(0, colon));
    work = work.substr(colon + 3);
    auto frag = work.find('#');
    if (frag != std::string::npos)
    {
        p.fragment = work.substr(frag + 1);
        work = work.substr(0, frag);
    }
    auto q = work.find('?');
    if (q != std::string::npos)
    {
        p.query = work.substr(q + 1);
        work = work.substr(0, q);
    }
    auto slash = work.find('/');
    std::string host_part;
    if (slash != std::string::npos)
    {
        host_part = work.substr(0, slash);
        p.path = work.substr(slash);
    }
    else
    {
        host_part = work;
        p.path = "/";
    }
    auto pcolon = host_part.find(':');
    if (pcolon != std::string::npos)
    {
        try
        {
            p.port = static_cast<uint16_t>(std::stoi(host_part.substr(pcolon + 1)));
            host_part = host_part.substr(0, pcolon);
        }
        catch (...)
        {
            return p;
        }
    }
    else
    {
        p.port = (p.scheme == "https") ? 443 : 80;
    }
    p.host = to_lower(host_part);
    if (p.scheme != "http" && p.scheme != "https") return p;
    if (p.host.empty()) return p;
    p.valid = true;
    return p;
}

std::string canonicalize(const parsed_url_t& p)
{
    if (!p.valid) return std::string();
    std::ostringstream os;
    os << p.scheme << "://" << p.host;
    const uint16_t default_port = (p.scheme == "https") ? 443 : 80;
    if (p.port != default_port) os << ':' << p.port;
    os << (p.path.empty() ? std::string("/") : p.path);
    if (!p.query.empty()) os << '?' << p.query;
    return os.str();
}

std::string resolve_relative(const std::string& base_url, const std::string& href)
{
    if (href.empty()) return std::string();
    if (href.find("://") != std::string::npos) return href;
    if (href[0] == '#') return std::string();
    if (href.rfind("javascript:", 0) == 0) return std::string();
    if (href.rfind("mailto:", 0) == 0) return std::string();
    if (href.rfind("tel:", 0) == 0) return std::string();
    if (href.rfind("data:", 0) == 0) return std::string();

    parsed_url_t b = parse_url(base_url);
    if (!b.valid) return std::string();

    if (href.rfind("//", 0) == 0)
    {
        return b.scheme + ":" + href;
    }
    if (!href.empty() && href[0] == '/')
    {
        std::ostringstream os;
        os << b.scheme << "://" << b.host;
        const uint16_t default_port = (b.scheme == "https") ? 443 : 80;
        if (b.port != default_port) os << ':' << b.port;
        os << href;
        return os.str();
    }

    std::string base_dir = b.path;
    auto last_slash = base_dir.find_last_of('/');
    if (last_slash != std::string::npos) base_dir = base_dir.substr(0, last_slash + 1);
    else base_dir = "/";

    std::string combined = base_dir + href;

    std::vector<std::string> segments;
    std::string cur;
    for (char c : combined)
    {
        if (c == '/') { if (!cur.empty()) { segments.push_back(cur); cur.clear(); } segments.push_back("/"); }
        else cur.push_back(c);
    }
    if (!cur.empty()) segments.push_back(cur);

    std::vector<std::string> resolved;
    for (auto& s : segments)
    {
        if (s == "/") { if (resolved.empty() || resolved.back() != "/") resolved.push_back("/"); }
        else if (s == ".") { }
        else if (s == "..")
        {
            if (!resolved.empty()) { resolved.pop_back(); if (!resolved.empty() && resolved.back() == "/") resolved.pop_back(); }
        }
        else { resolved.push_back(s); }
    }

    std::string final_path;
    for (auto& s : resolved) final_path += s;
    if (final_path.empty()) final_path = "/";

    std::ostringstream os;
    os << b.scheme << "://" << b.host;
    const uint16_t default_port = (b.scheme == "https") ? 443 : 80;
    if (b.port != default_port) os << ':' << b.port;
    os << final_path;
    return os.str();
}

bool extract_html_links(const std::string& base_url, const std::string& body, std::vector<std::string>& out)
{
    static const std::regex href_re(R"((?:href|src|action|data-src|data-url)\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s>'\"]+)))", std::regex::icase);
    auto begin = std::sregex_iterator(body.begin(), body.end(), href_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it)
    {
        std::string match;
        if (!(*it)[1].str().empty()) match = (*it)[1].str();
        else if (!(*it)[2].str().empty()) match = (*it)[2].str();
        else if (!(*it)[3].str().empty()) match = (*it)[3].str();
        if (match.empty()) continue;
        std::string resolved = resolve_relative(base_url, match);
        if (!resolved.empty()) out.push_back(std::move(resolved));
    }

    static const std::regex meta_re(R"(<meta[^>]+http-equiv\s*=\s*[\"']refresh[\"'][^>]+content\s*=\s*[\"'][^\"']*url\s*=\s*([^\"']+)[\"'])", std::regex::icase);
    auto m_begin = std::sregex_iterator(body.begin(), body.end(), meta_re);
    for (auto it = m_begin; it != end; ++it)
    {
        std::string match = (*it)[1].str();
        if (match.empty()) continue;
        std::string resolved = resolve_relative(base_url, match);
        if (!resolved.empty()) out.push_back(std::move(resolved));
    }
    return true;
}

bool extract_js_urls(const std::string& base_url, const std::string& body, std::vector<std::string>& out)
{
    static const std::regex js_re(R"([\"']((?:https?:\/\/[^\"'<>\s]+)|(?:\/[a-zA-Z0-9_\-\./%\?=&]+))[\"'])");
    auto begin = std::sregex_iterator(body.begin(), body.end(), js_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it)
    {
        std::string match = (*it)[1].str();
        if (match.empty()) continue;
        if (match.size() < 2) continue;
        std::string resolved = resolve_relative(base_url, match);
        if (!resolved.empty()) out.push_back(std::move(resolved));
    }
    return true;
}

bool parse_robots_txt(const std::string& body, std::vector<std::string>& disallows)
{
    std::istringstream iss(body);
    std::string line;
    bool current_applies = false;
    while (std::getline(iss, line))
    {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string key = to_lower(line.substr(0, pos));
        std::string val = line.substr(pos + 1);
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.erase(val.begin());
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t')) val.pop_back();
        if (key == "user-agent")
        {
            current_applies = (val == "*");
        }
        else if (key == "disallow" && current_applies)
        {
            if (!val.empty()) disallows.push_back(val);
        }
    }
    return true;
}

bool path_disallowed(const std::vector<std::string>& disallows, const std::string& path)
{
    for (const auto& d : disallows)
    {
        if (path.rfind(d, 0) == 0) return true;
    }
    return false;
}

bool fetch_url(const std::string& url, const std::string& user_agent, int timeout_ms,
               int& out_status, std::string& out_body, std::string& out_content_type,
               std::vector<std::pair<std::string,std::string>>& out_resp_headers,
               uint64_t& out_latency_ms,
               std::string& out_err)
{
    out_status = 0;
    out_body.clear();
    out_content_type.clear();
    out_resp_headers.clear();
    out_latency_ms = 0;

    parsed_url_t p = parse_url(url);
    if (!p.valid) { out_err = "invalid url"; return false; }

    const std::string base = p.scheme + "://" + p.host + ":" + std::to_string(p.port);
    httplib::Client cli(base);
    cli.set_connection_timeout(std::chrono::milliseconds(timeout_ms));
    cli.set_read_timeout(std::chrono::milliseconds(timeout_ms));
    cli.set_write_timeout(std::chrono::milliseconds(timeout_ms));
    cli.set_follow_location(false);
    cli.enable_server_certificate_verification(false);

    httplib::Headers headers;
    headers.emplace("User-Agent", user_agent);
    headers.emplace("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    headers.emplace("Accept-Encoding", "identity");

    std::string path_with_query = p.path;
    if (!p.query.empty()) path_with_query += "?" + p.query;

    auto t0 = std::chrono::steady_clock::now();
    auto res = cli.Get(path_with_query.c_str(), headers);
    auto t1 = std::chrono::steady_clock::now();
    out_latency_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

    if (!res)
    {
        out_err = "transport error";
        return false;
    }
    out_status = res->status;
    out_body = res->body;
    for (auto& h : res->headers)
    {
        out_resp_headers.emplace_back(h.first, h.second);
        if (to_lower(h.first) == "content-type") out_content_type = h.second;
    }
    return true;
}

void push_event_for_url(const std::string& url, int status, uint64_t latency, const std::string& body,
                        const std::string& content_type,
                        const std::vector<std::pair<std::string,std::string>>& resp_headers,
                        const std::string& user_agent)
{
    parsed_url_t p = parse_url(url);
    if (!p.valid) return;
    exchange_observed_t ev;
    ev.id = static_cast<uint64_t>(now_ms());
    ev.timestamp_ms = now_ms();
    ev.method = "GET";
    ev.scheme = p.scheme;
    ev.host = p.host;
    ev.port = p.port;
    ev.path = p.path;
    ev.query = p.query;
    ev.req_headers.emplace_back("User-Agent", user_agent);
    ev.req_headers.emplace_back("Host", p.host);
    ev.status_code = status;
    ev.resp_headers = resp_headers;
    ev.resp_body.assign(body.begin(), body.end());
    ev.latency_ms = latency;
    ev.is_h2 = false;
    ev.is_websocket = false;
    if (!content_type.empty())
    {
        bool have_ct = false;
        for (auto& h : ev.resp_headers) { if (to_lower(h.first) == "content-type") { have_ct = true; break; } }
        if (!have_ct) ev.resp_headers.emplace_back("Content-Type", content_type);
    }
    aida::events::publish(kExchangeObservedEvent, ev);
    sitemap::ingest_exchange(ev);
}

bool host_rate_acquire(host_rate_t& hr, int rate_per_host, std::atomic<bool>& stop_flag)
{
    while (!stop_flag.load())
    {
        auto now = std::chrono::steady_clock::now();
        std::unique_lock<std::mutex> lk(hr.mtx);
        while (!hr.stamps.empty() && (now - hr.stamps.front()) > std::chrono::seconds(1))
            hr.stamps.pop_front();
        if (static_cast<int>(hr.stamps.size()) < rate_per_host)
        {
            hr.stamps.push_back(now);
            return true;
        }
        lk.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

void log_line(crawl_t& c, const std::string& line)
{
    std::lock_guard<std::mutex> lk(c.mtx);
    if (c.log.size() >= 4000) c.log.erase(c.log.begin(), c.log.begin() + 1000);
    c.log.push_back(line);
}

bool should_skip_extension(const std::string& path, const std::vector<std::string>& exts)
{
    if (exts.empty()) return false;
    std::string lower = to_lower(path);
    for (auto& e : exts)
    {
        std::string el = to_lower(e);
        if (lower.size() >= el.size() && lower.compare(lower.size() - el.size(), el.size(), el) == 0)
            return true;
    }
    return false;
}

bool matches_any_pattern(const std::string& url, const std::vector<std::string>& patterns)
{
    for (const auto& p : patterns)
    {
        if (p.empty()) continue;
        try { std::regex r(p); if (std::regex_search(url, r)) return true; } catch (...) {}
    }
    return false;
}

void run_crawl(std::shared_ptr<crawl_t> ctx);

void enqueue_url(crawl_t& c, const std::string& url, int depth, const std::string& parent)
{
    if (static_cast<int>(c.discovered.size()) >= c.config.max_pages) {
        diag::log_tagged_fmt("crawler", "enqueue_url id=%llu max_pages_reached url=%s", static_cast<unsigned long long>(c.id), url.c_str());
        return;
    }
    parsed_url_t p = parse_url(url);
    if (!p.valid) {
        diag::log_tagged_fmt("crawler", "enqueue_url id=%llu invalid_url=%s", static_cast<unsigned long long>(c.id), url.c_str());
        return;
    }
    std::string canonical = canonicalize(p);
    if (canonical.empty()) return;
    if (c.seen.find(canonical) != c.seen.end()) return;
    if (c.config.same_host_only && !c.config.start_urls.empty())
    {
        bool host_ok = false;
        for (const auto& s : c.config.start_urls)
        {
            parsed_url_t sp = parse_url(s);
            if (sp.valid && sp.host == p.host) { host_ok = true; break; }
        }
        if (!host_ok) {
            diag::log_tagged_fmt("crawler", "enqueue_url id=%llu same_host_filter blocked url=%s", static_cast<unsigned long long>(c.id), canonical.c_str());
            return;
        }
    }
    if (c.config.scope_only)
    {
        if (!aida::burp::scope::in_scope_components(p.scheme, p.host, p.port, p.path)) {
            diag::log_tagged_fmt("crawler", "enqueue_url id=%llu scope_filter blocked url=%s", static_cast<unsigned long long>(c.id), canonical.c_str());
            return;
        }
    }
    if (should_skip_extension(p.path, c.config.exclude_extensions)) {
        diag::log_tagged_fmt("crawler", "enqueue_url id=%llu ext_filter blocked url=%s", static_cast<unsigned long long>(c.id), canonical.c_str());
        return;
    }
    if (matches_any_pattern(canonical, c.config.exclude_patterns)) {
        diag::log_tagged_fmt("crawler", "enqueue_url id=%llu pattern_filter blocked url=%s", static_cast<unsigned long long>(c.id), canonical.c_str());
        return;
    }

    c.seen.insert(canonical);
    queue_item_t q;
    q.url = canonical;
    q.depth = depth;
    q.parent = parent;
    c.queue.push_back(std::move(q));
    diag::log_tagged_fmt("crawler", "enqueue_url id=%llu queued url=%s depth=%d queue_size=%zu",
        static_cast<unsigned long long>(c.id), canonical.c_str(), depth, c.queue.size());
}

void worker_step(std::shared_ptr<crawl_t> ctx, queue_item_t item)
{
    diag::log_tagged_fmt("crawler", "worker_step id=%llu url=%s depth=%d",
        static_cast<unsigned long long>(ctx->id), item.url.c_str(), item.depth);
    ctx->in_flight.fetch_add(1);
    auto& c = *ctx;
    if (c.stop_flag.load()) {
        diag::log_tagged_fmt("crawler", "worker_step id=%llu stopped url=%s", static_cast<unsigned long long>(ctx->id), item.url.c_str());
        ctx->in_flight.fetch_sub(1);
        return;
    }

    parsed_url_t p = parse_url(item.url);
    if (!p.valid) { ctx->in_flight.fetch_sub(1); return; }

    std::shared_ptr<host_rate_t> hr;
    {
        std::lock_guard<std::mutex> lk(c.mtx);
        auto it = c.host_rates.find(p.host);
        if (it == c.host_rates.end())
        {
            hr = std::make_shared<host_rate_t>();
            c.host_rates[p.host] = hr;
        }
        else hr = it->second;
    }

    if (c.config.respect_robots_txt)
    {
        bool need_fetch_robots = false;
        {
            std::lock_guard<std::mutex> lk(hr->mtx);
            if (!hr->robots_fetched) need_fetch_robots = true;
        }
        if (need_fetch_robots)
        {
            std::string robots_url = p.scheme + "://" + p.host + ":" + std::to_string(p.port) + "/robots.txt";
            int rs = 0;
            std::string rbody, rct, rerr;
            std::vector<std::pair<std::string,std::string>> rhdr;
            uint64_t rlat = 0;
            fetch_url(robots_url, c.config.user_agent, c.config.request_timeout_ms, rs, rbody, rct, rhdr, rlat, rerr);
            std::vector<std::string> disallows;
            if (rs >= 200 && rs < 300) parse_robots_txt(rbody, disallows);
            {
                std::lock_guard<std::mutex> lk(hr->mtx);
                hr->robots_fetched = true;
                hr->robots_disallow = std::move(disallows);
            }
        }
        bool blocked = false;
        {
            std::lock_guard<std::mutex> lk(hr->mtx);
            blocked = path_disallowed(hr->robots_disallow, p.path);
        }
        if (blocked)
        {
            log_line(c, "robots-blocked: " + item.url);
            ctx->in_flight.fetch_sub(1);
            return;
        }
    }

    if (!host_rate_acquire(*hr, std::max(1, c.config.rate_per_host), c.stop_flag))
    {
        ctx->in_flight.fetch_sub(1);
        return;
    }

    int status = 0;
    std::string body, content_type, err;
    std::vector<std::pair<std::string,std::string>> resp_headers;
    uint64_t lat = 0;
    diag::log_tagged_fmt("crawler", "worker_step fetching id=%llu url=%s timeout=%d",
        static_cast<unsigned long long>(ctx->id), item.url.c_str(), c.config.request_timeout_ms);
    bool ok = fetch_url(item.url, c.config.user_agent, c.config.request_timeout_ms,
                        status, body, content_type, resp_headers, lat, err);
    diag::log_tagged_fmt("crawler", "worker_step fetch_result id=%llu url=%s ok=%d status=%d body=%zu lat=%llu err=%s",
        static_cast<unsigned long long>(ctx->id), item.url.c_str(), ok ? 1 : 0,
        status, body.size(), static_cast<unsigned long long>(lat), err.c_str());

    discovered_url_t d;
    d.url = item.url;
    d.status = status;
    d.body_bytes = body.size();
    d.content_type = content_type;
    d.depth = item.depth;
    d.source_url = item.parent;
    d.fetched_unix_ms = now_ms();

    {
        std::lock_guard<std::mutex> lk(c.mtx);
        c.discovered.push_back(d);
        c.last_url = item.url;
        if (!ok)
        {
            c.pages_failed++;
            c.last_error = err;
        }
        else
        {
            c.pages_visited++;
        }
    }

    if (ok)
    {
        push_event_for_url(item.url, status, lat, body, content_type, resp_headers, c.config.user_agent);

        if (status >= 300 && status < 400)
        {
            for (auto& h : resp_headers)
            {
                if (to_lower(h.first) == "location")
                {
                    std::string next = resolve_relative(item.url, h.second);
                    if (!next.empty() && item.depth + 1 <= c.config.max_depth)
                    {
                        std::lock_guard<std::mutex> lk(c.mtx);
                        enqueue_url(c, next, item.depth + 1, item.url);
                    }
                }
            }
        }

        if (status >= 200 && status < 300 && item.depth < c.config.max_depth)
        {
            std::vector<std::string> links;
            std::string lower_ct = to_lower(content_type);
            if (lower_ct.find("html") != std::string::npos || lower_ct.find("xml") != std::string::npos || lower_ct.empty())
                extract_html_links(item.url, body, links);
            if (c.config.parse_js)
            {
                if (lower_ct.find("javascript") != std::string::npos || lower_ct.find("json") != std::string::npos
                    || lower_ct.find("html") != std::string::npos)
                    extract_js_urls(item.url, body, links);
            }

            std::lock_guard<std::mutex> lk(c.mtx);
            for (auto& url : links) enqueue_url(c, url, item.depth + 1, item.url);
        }
    }
    else
    {
        log_line(c, std::string("fetch_failed url=") + item.url + " err=" + err);
    }

    ctx->in_flight.fetch_sub(1);
    work_queue::post([ctx] { run_crawl(ctx); });
}

void run_crawl(std::shared_ptr<crawl_t> ctx)
{
    auto& c = *ctx;
    if (c.finished.load()) return;
    if (c.stop_flag.load())
    {
        std::lock_guard<std::mutex> lk(c.mtx);
        if (!c.queue.empty()) c.queue.clear();
    }

    queue_item_t next;
    bool has = false;
    {
        std::lock_guard<std::mutex> lk(c.mtx);
        if (!c.queue.empty())
        {
            next = std::move(c.queue.front());
            c.queue.pop_front();
            has = true;
        }
    }
    if (has)
    {
        worker_step(ctx, next);
        return;
    }

    if (ctx->in_flight.load() == 0)
    {
        bool already = false;
        {
            std::lock_guard<std::mutex> lk(c.mtx);
            if (c.phase == crawl_status_phase_t::complete) already = true;
            else
            {
                c.phase = c.stop_flag.load() ? crawl_status_phase_t::complete : crawl_status_phase_t::complete;
                c.finished_unix_ms = now_ms();
            }
        }
        if (!already)
        {
            c.finished.store(true);
            diag::log_tagged_fmt("burp.crawler", "crawl_finished id=%llu visited=%d failed=%d found=%d",
                static_cast<unsigned long long>(c.id), c.pages_visited, c.pages_failed, static_cast<int>(c.discovered.size()));
        }
        return;
    }

    work_queue::post([ctx] {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        run_crawl(ctx);
    });
}

}

bool initialize()
{
    diag::log_tagged_fmt("crawler", "initialize called");
    auto& r = reg();
    bool expected = false;
    if (!r.init_done.compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("crawler", "initialize already_done");
        return true;
    }
    diag::log_tagged_fmt("crawler", "initialize success");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("crawler", "shutdown called");
    auto& r = reg();
    if (!r.init_done.exchange(false)) {
        diag::log_tagged_fmt("crawler", "shutdown skipped not_initialized");
        return;
    }
    std::vector<std::shared_ptr<crawl_t>> snapshots;
    {
        std::lock_guard<std::mutex> lk(r.mtx);
        snapshots.reserve(r.by_id.size());
        for (auto& kv : r.by_id) { kv.second->stop_flag.store(true); snapshots.push_back(kv.second); }
    }
    diag::log_tagged_fmt("crawler", "shutdown stopping %zu crawls", snapshots.size());
    for (int i = 0; i < 40; ++i)
    {
        bool all_done = true;
        for (auto& c : snapshots) if (!c->finished.load() || c->in_flight.load() > 0) { all_done = false; break; }
        if (all_done) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    {
        std::lock_guard<std::mutex> lk(r.mtx);
        r.by_id.clear();
    }
    diag::log_tagged_fmt("crawler", "shutdown complete");
}

uint64_t start(const crawl_config_t& config)
{
    if (!reg().init_done.load()) initialize();
    if (config.start_urls.empty()) { set_err("no start urls"); return 0; }
    auto ctx = std::make_shared<crawl_t>();
    ctx->id = reg().next_id.fetch_add(1);
    ctx->config = config;
    ctx->phase = crawl_status_phase_t::running;
    ctx->started_unix_ms = now_ms();
    for (auto& u : config.start_urls)
    {
        parsed_url_t p = parse_url(u);
        if (!p.valid) continue;
        std::string canon = canonicalize(p);
        if (canon.empty()) continue;
        if (ctx->seen.insert(canon).second)
        {
            queue_item_t q; q.url = canon; q.depth = 0; q.parent = std::string();
            ctx->queue.push_back(std::move(q));
        }
    }
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        reg().by_id[ctx->id] = ctx;
    }
    diag::log_tagged_fmt("burp.crawler", "crawl_start id=%llu seeds=%zu max_depth=%d max_pages=%d",
        static_cast<unsigned long long>(ctx->id), config.start_urls.size(), config.max_depth, config.max_pages);

    int kick = std::max(1, std::min(config.concurrency, 32));
    for (int i = 0; i < kick; ++i)
        work_queue::post([ctx] { run_crawl(ctx); });
    return ctx->id;
}

bool stop(uint64_t crawl_id)
{
    diag::log_tagged_fmt("crawler", "stop id=%llu", static_cast<unsigned long long>(crawl_id));
    std::shared_ptr<crawl_t> ctx;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().by_id.find(crawl_id);
        if (it == reg().by_id.end()) {
            diag::log_tagged_fmt("crawler", "stop id=%llu not_found", static_cast<unsigned long long>(crawl_id));
            set_err("not found");
            return false;
        }
        ctx = it->second;
    }
    ctx->stop_flag.store(true);
    {
        std::lock_guard<std::mutex> lk(ctx->mtx);
        if (ctx->phase == crawl_status_phase_t::running) ctx->phase = crawl_status_phase_t::stopping;
    }
    diag::log_tagged_fmt("burp.crawler", "crawl_stop id=%llu", static_cast<unsigned long long>(crawl_id));
    return true;
}

crawl_status_t status(uint64_t crawl_id)
{
    crawl_status_t out;
    std::shared_ptr<crawl_t> ctx;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().by_id.find(crawl_id);
        if (it == reg().by_id.end()) return out;
        ctx = it->second;
    }
    std::lock_guard<std::mutex> lk(ctx->mtx);
    out.id = ctx->id;
    out.phase = ctx->phase;
    out.queue_depth = static_cast<int>(ctx->queue.size());
    out.pages_visited = ctx->pages_visited;
    out.pages_failed = ctx->pages_failed;
    out.urls_found = static_cast<int>(ctx->discovered.size());
    out.started_unix_ms = ctx->started_unix_ms;
    out.finished_unix_ms = ctx->finished_unix_ms;
    out.last_url = ctx->last_url;
    out.last_error = ctx->last_error;
    out.config = ctx->config;
    out.discovered = ctx->discovered;
    out.log = ctx->log;
    return out;
}

std::vector<crawl_status_t> list()
{
    std::vector<uint64_t> ids;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        ids.reserve(reg().by_id.size());
        for (auto& kv : reg().by_id) ids.push_back(kv.first);
    }
    std::sort(ids.begin(), ids.end());
    std::vector<crawl_status_t> out;
    out.reserve(ids.size());
    for (auto id : ids) out.push_back(status(id));
    return out;
}

bool remove(uint64_t crawl_id)
{
    diag::log_tagged_fmt("crawler", "remove id=%llu", static_cast<unsigned long long>(crawl_id));
    std::shared_ptr<crawl_t> ctx;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().by_id.find(crawl_id);
        if (it == reg().by_id.end()) {
            diag::log_tagged_fmt("crawler", "remove id=%llu not_found", static_cast<unsigned long long>(crawl_id));
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
        reg().by_id.erase(crawl_id);
    }
    diag::log_tagged_fmt("crawler", "remove id=%llu complete", static_cast<unsigned long long>(crawl_id));
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
