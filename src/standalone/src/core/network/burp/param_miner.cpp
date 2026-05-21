#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "param_miner.hpp"
#include "audit_http.hpp"
#include "issue.hpp"
#include "payload_library.hpp"

#include "../../../helpers/diag_log.hpp"
#include "../../infra/work_queue.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace aida {
namespace burp {
namespace param_miner {

namespace {

static std::mutex&  err_mtx() { static std::mutex m; return m; }
static std::string& err_slot() { static std::string s; return s; }

void set_err(const std::string& s)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = s;
}

struct job_t
{
    uint64_t                       id = 0;
    config_t                       cfg;
    std::atomic<bool>              running{false};
    std::atomic<bool>              cancel{false};
    std::atomic<size_t>            total{0};
    std::atomic<size_t>            tried{0};
    std::atomic<size_t>            hits_count{0};
    std::mutex                     hits_mtx;
    std::vector<hit_t>             hits;
    std::atomic<uint64_t>          next_hit_id{1};
};

struct registry_t
{
    std::mutex                                              mtx;
    std::unordered_map<uint64_t, std::shared_ptr<job_t>>    jobs;
    std::atomic<uint64_t>                                   next_id{1};
};

static registry_t& reg() { static registry_t r; return r; }

static std::string ascii_lower(const std::string& v)
{
    std::string r; r.reserve(v.size());
    for (char c : v) r.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c);
    return r;
}

static std::string url_encode(const std::string& s)
{
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        bool unreserved = (c >= 'A' && c <= 'Z')
                       || (c >= 'a' && c <= 'z')
                       || (c >= '0' && c <= '9')
                       || c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0xF]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

static std::string random_value()
{
    static std::atomic<uint64_t> ctr{0};
    uint64_t v = ctr.fetch_add(1) + static_cast<uint64_t>(GetTickCount64());
    char buf[32];
    snprintf(buf, sizeof(buf), "aida%08llx", static_cast<unsigned long long>(v & 0xFFFFFFFFull));
    return buf;
}

static std::string find_header_ci(const std::vector<std::pair<std::string, std::string>>& headers,
                                  const std::string& name)
{
    std::string lname = ascii_lower(name);
    for (auto& h : headers) {
        if (ascii_lower(h.first) == lname) return h.second;
    }
    return {};
}

static std::vector<uint8_t> build_request_h1(const std::string& method,
                                             const std::string& path_with_query,
                                             const std::string& host,
                                             const std::vector<std::pair<std::string, std::string>>& extra_headers,
                                             const std::string& body,
                                             const std::string& content_type)
{
    std::string out;
    out.reserve(256 + body.size());
    out += method; out += ' '; out += path_with_query; out += " HTTP/1.1\r\n";
    out += "Host: "; out += host; out += "\r\n";
    out += "User-Agent: AiDA-ParamMiner/1.0\r\n";
    out += "Accept: */*\r\n";
    out += "Connection: close\r\n";
    if (!content_type.empty()) {
        out += "Content-Type: "; out += content_type; out += "\r\n";
    }
    if (!body.empty()) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Content-Length: %zu\r\n", body.size());
        out += buf;
    }
    for (auto& h : extra_headers) {
        out += h.first; out += ": "; out += h.second; out += "\r\n";
    }
    out += "\r\n";
    if (!body.empty()) out += body;
    return std::vector<uint8_t>(out.begin(), out.end());
}

static std::vector<std::string> resolve_wordlist(const config_t& cfg)
{
    std::vector<std::string> base;
    if (!cfg.custom_words.empty()) base = cfg.custom_words;
    if (base.empty() && !cfg.wordlist_id.empty()) {
        base = payloads::entries(cfg.wordlist_id, 0);
    }
    if (base.empty()) {
        base = payloads::entries("params/common", 0);
    }
    if (base.empty()) {
        base = {
            "id","name","page","action","cmd","callback","jsonp","redirect","return",
            "user","username","email","token","auth","api_key","apikey","key","session",
            "debug","test","admin","role","type","mode","format","include","file","path",
            "url","next","prev","limit","offset","sort","order","filter","query","q",
            "search","s","lang","locale","theme","ref","referer","source","src","dest",
            "destination","method","method_override","_method","callback_url","redirect_uri"
        };
    }
    std::unordered_set<std::string> dedupe;
    std::vector<std::string> out;
    out.reserve(base.size());
    for (auto& w : base) {
        std::string trimmed;
        for (char c : w) if (c != '\r' && c != '\n') trimmed.push_back(c);
        if (trimmed.empty()) continue;
        if (dedupe.insert(trimmed).second) out.push_back(std::move(trimmed));
    }
    return out;
}

static double mean_of(const std::vector<double>& v)
{
    if (v.empty()) return 0.0;
    double s = 0.0;
    for (double x : v) s += x;
    return s / static_cast<double>(v.size());
}

static double stddev_of(const std::vector<double>& v, double m)
{
    if (v.size() < 2) return 0.0;
    double sum = 0.0;
    for (double x : v) { double d = x - m; sum += d * d; }
    return std::sqrt(sum / static_cast<double>(v.size() - 1));
}

static bool parse_url(const std::string& url, std::string& scheme, std::string& host,
                      uint16_t& port, std::string& path)
{
    return audit_http::parse_url(url, scheme, host, port, path);
}

static void record_hit(job_t& job, hit_t h)
{
    h.id = job.next_hit_id.fetch_add(1);
    if (job.cfg.report_as_issues) {
        issue_t iss;
        iss.type_key = "burp.param_miner.hidden_param";
        iss.name = std::string("Hidden parameter: ") + h.param_name;
        iss.description = "ParamMiner detected a parameter (" + h.param_name +
                          ") in location '" + h.location_label +
                          "' whose presence changes the response in a measurable way.";
        iss.remediation = "Audit this parameter and ensure it is documented, validated, and not bypassing security controls.";
        iss.severity = severity_t::info;
        iss.confidence = (h.cache_diff || h.echoed || h.header_echoed) ? confidence_t::firm : confidence_t::tentative;
        iss.parameter = h.param_name;
        iss.insertion_point = h.location_label;
        evidence_t ev;
        ev.marker = h.evidence;
        iss.evidence.push_back(std::move(ev));
        iss.seen_ms = static_cast<uint64_t>(GetTickCount64());
        issue_store::add(std::move(iss));
    }
    {
        std::lock_guard<std::mutex> lk(job.hits_mtx);
        job.hits.push_back(std::move(h));
    }
    job.hits_count.fetch_add(1);
}

static std::string build_path_with_query(const std::string& base_path, const std::string& extra_qs)
{
    if (extra_qs.empty()) return base_path;
    if (base_path.find('?') != std::string::npos) {
        return base_path + "&" + extra_qs;
    }
    return base_path + "?" + extra_qs;
}

static void miner_main(std::shared_ptr<job_t> job)
{
    diag::log_tagged_fmt("param_miner", "miner_main start job_id=%llu url=%s location=%s concurrency=%zu",
        static_cast<unsigned long long>(job->id),
        job->cfg.target_url.c_str(),
        location_name(job->cfg.location),
        job->cfg.concurrency);
    job->running.store(true);

    std::string scheme, host, path;
    uint16_t port = 0;
    if (!parse_url(job->cfg.target_url, scheme, host, port, path)) {
        diag::log_tagged_fmt("param_miner", "miner_main invalid_url url=%s", job->cfg.target_url.c_str());
        set_err("param_miner: invalid target_url");
        job->running.store(false);
        return;
    }
    if (path.empty()) path = "/";
    bool tls = (scheme == "https");
    diag::log_tagged_fmt("param_miner", "miner_main url_parsed host=%s port=%u tls=%d path=%s",
        host.c_str(), static_cast<unsigned>(port), tls ? 1 : 0, path.c_str());

    std::vector<std::string> words = resolve_wordlist(job->cfg);
    job->total.store(words.size());
    diag::log_tagged_fmt("param_miner", "miner_main wordlist_size=%zu", words.size());

    audit_http::send_options_t sopts;
    sopts.timeout_ms = job->cfg.timeout_ms;
    sopts.follow_redirects = false;
    sopts.enforce_scope = false;

    diag::log_tagged_fmt("param_miner", "miner_main collecting_baseline count=%zu", job->cfg.baseline_count);
    std::vector<double> baseline_sizes;
    baseline_sizes.reserve(job->cfg.baseline_count);
    int baseline_status = 0;
    std::vector<std::pair<std::string, std::string>> baseline_resp_headers;
    for (size_t i = 0; i < job->cfg.baseline_count && !job->cancel.load(); ++i) {
        auto req = build_request_h1("GET", path, host, {}, "", "");
        auto ex = audit_http::send(req, host, port, tls, sopts);
        if (!ex) {
            diag::log_tagged_fmt("param_miner", "miner_main baseline_probe_failed idx=%zu", i);
            continue;
        }
        diag::log_tagged_fmt("param_miner", "miner_main baseline_probe idx=%zu status=%d size=%zu latency_ms=%llu",
            i, ex->status_code, ex->resp_body.size(), static_cast<unsigned long long>(ex->latency_ms));
        baseline_sizes.push_back(static_cast<double>(ex->resp_body.size()));
        baseline_status = ex->status_code;
        baseline_resp_headers = ex->resp_headers;
        if (job->cfg.throttle_ms > 0) std::this_thread::sleep_for(std::chrono::milliseconds(job->cfg.throttle_ms));
    }
    if (baseline_sizes.empty()) {
        diag::log_tagged("param_miner", "miner_main baseline_failed no_samples");
        set_err("param_miner: failed to collect baseline");
        job->running.store(false);
        return;
    }
    double bmean = mean_of(baseline_sizes);
    double bstd = stddev_of(baseline_sizes, bmean);
    if (bstd < 1.0) bstd = 1.0;
    diag::log_tagged_fmt("param_miner", "miner_main baseline_ok samples=%zu bmean=%.1f bstd=%.2f baseline_status=%d",
        baseline_sizes.size(), bmean, bstd, baseline_status);

    std::string baseline_cache_status = ascii_lower(find_header_ci(baseline_resp_headers, "X-Cache"));
    if (baseline_cache_status.empty()) baseline_cache_status = ascii_lower(find_header_ci(baseline_resp_headers, "CF-Cache-Status"));
    if (baseline_cache_status.empty()) baseline_cache_status = ascii_lower(find_header_ci(baseline_resp_headers, "Age"));

    size_t concurrency = job->cfg.concurrency > 0 ? job->cfg.concurrency : 4;
    if (concurrency > 16) concurrency = 16;
    diag::log_tagged_fmt("param_miner", "miner_main launching_workers concurrency=%zu words=%zu", concurrency, words.size());

    std::mutex feed_mtx;
    size_t feed_pos = 0;

    auto worker = [&]() {
        audit_http::send_options_t sopts_local;
        sopts_local.timeout_ms = job->cfg.timeout_ms;
        sopts_local.follow_redirects = false;
        sopts_local.enforce_scope = false;
        while (!job->cancel.load()) {
            size_t idx;
            {
                std::lock_guard<std::mutex> lk(feed_mtx);
                if (feed_pos >= words.size()) return;
                idx = feed_pos++;
            }
            std::string param = words[idx];
            std::string value = random_value();
            diag::log_tagged_fmt("param_miner", "testing param=%s location=%s idx=%zu", param.c_str(), location_name(job->cfg.location), idx);
            std::vector<std::pair<std::string, std::string>> extra_headers;
            std::string body;
            std::string ct;
            std::string url_path = path;
            std::string method = "GET";

            switch (job->cfg.location) {
                case location_t::query: {
                    std::string qs = url_encode(param) + "=" + url_encode(value);
                    url_path = build_path_with_query(path, qs);
                    break;
                }
                case location_t::body_form: {
                    method = "POST";
                    body = url_encode(param) + "=" + url_encode(value);
                    ct = "application/x-www-form-urlencoded";
                    break;
                }
                case location_t::json_body: {
                    method = "POST";
                    body = std::string("{\"") + param + "\":\"" + value + "\"}";
                    ct = "application/json";
                    break;
                }
                case location_t::header: {
                    extra_headers.push_back({ "X-" + param, value });
                    break;
                }
                case location_t::cookie: {
                    extra_headers.push_back({ "Cookie", url_encode(param) + "=" + url_encode(value) });
                    break;
                }
            }

            auto req = build_request_h1(method, url_path, host, extra_headers, body, ct);
            auto ex = audit_http::send(req, host, port, tls, sopts_local);
            job->tried.fetch_add(1);
            if (job->cfg.throttle_ms > 0) std::this_thread::sleep_for(std::chrono::milliseconds(job->cfg.throttle_ms));
            if (!ex) {
                diag::log_tagged_fmt("param_miner", "param_send_failed param=%s", param.c_str());
                continue;
            }

            double sz = static_cast<double>(ex->resp_body.size());
            double sigma = (sz - bmean) / bstd;
            double absig = sigma < 0.0 ? -sigma : sigma;
            bool size_significant = absig >= job->cfg.diff_sigma_threshold;
            bool status_diff = ex->status_code != baseline_status;
            std::string cache_status = ascii_lower(find_header_ci(ex->resp_headers, "X-Cache"));
            if (cache_status.empty()) cache_status = ascii_lower(find_header_ci(ex->resp_headers, "CF-Cache-Status"));
            if (cache_status.empty()) cache_status = ascii_lower(find_header_ci(ex->resp_headers, "Age"));
            bool cache_diff = !cache_status.empty() && cache_status != baseline_cache_status;
            bool echoed = false;
            std::string body_view(reinterpret_cast<const char*>(ex->resp_body.data()),
                                  std::min(ex->resp_body.size(), static_cast<size_t>(65536)));
            if (!value.empty() && body_view.find(value) != std::string::npos) echoed = true;
            bool header_echoed = false;
            for (auto& h : ex->resp_headers) {
                if (h.second.find(value) != std::string::npos) { header_echoed = true; break; }
            }

            diag::log_tagged_fmt("param_miner", "param_result param=%s status=%d size=%zu sigma=%.2f status_diff=%d cache_diff=%d echoed=%d header_echoed=%d",
                param.c_str(), ex->status_code, ex->resp_body.size(), sigma,
                status_diff ? 1 : 0, cache_diff ? 1 : 0, echoed ? 1 : 0, header_echoed ? 1 : 0);

            if (size_significant || status_diff || cache_diff || echoed || header_echoed) {
                diag::log_tagged_fmt("param_miner", "hit_found param=%s location=%s sigma=%.2f status_diff=%d cache_diff=%d echoed=%d header_echoed=%d",
                    param.c_str(), location_name(job->cfg.location), sigma,
                    status_diff ? 1 : 0, cache_diff ? 1 : 0, echoed ? 1 : 0, header_echoed ? 1 : 0);
                hit_t h;
                h.param_name = param;
                h.location_label = location_name(job->cfg.location);
                h.status_code = ex->status_code;
                h.response_size = ex->resp_body.size();
                h.size_diff_sigma = sigma;
                h.cache_diff = cache_diff;
                h.echoed = echoed;
                h.header_echoed = header_echoed;
                char ev[512];
                snprintf(ev, sizeof(ev),
                         "param=%s value=%s status=%d (baseline=%d) size=%zu (baseline=%.0f sigma=%.2f) cache_diff=%d echoed=%d header_echoed=%d",
                         param.c_str(), value.c_str(), ex->status_code, baseline_status,
                         ex->resp_body.size(), bmean, sigma,
                         cache_diff ? 1 : 0, echoed ? 1 : 0, header_echoed ? 1 : 0);
                h.evidence = ev;
                record_hit(*job, std::move(h));
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(concurrency);
    for (size_t i = 0; i < concurrency; ++i) threads.emplace_back(worker);
    for (auto& t : threads) if (t.joinable()) t.join();

    job->running.store(false);
    diag::log_tagged_fmt("param_miner", "miner_main done job_id=%llu tried=%zu hits=%zu",
        static_cast<unsigned long long>(job->id), job->tried.load(), job->hits_count.load());
}

}

uint64_t start(config_t cfg)
{
    diag::log_tagged_fmt("param_miner", "start url=%s location=%s concurrency=%zu baseline_count=%zu sigma=%.1f",
        cfg.target_url.c_str(), location_name(cfg.location), cfg.concurrency, cfg.baseline_count, cfg.diff_sigma_threshold);
    if (cfg.target_url.empty()) {
        diag::log_tagged("param_miner", "start rejected empty_target_url");
        set_err("param_miner: target_url empty");
        return 0;
    }
    if (cfg.concurrency == 0) cfg.concurrency = 4;
    if (cfg.timeout_ms <= 0) cfg.timeout_ms = 12000;
    if (cfg.baseline_count == 0) cfg.baseline_count = 5;
    if (cfg.diff_sigma_threshold < 1.0) cfg.diff_sigma_threshold = 3.0;

    auto job = std::make_shared<job_t>();
    job->id = reg().next_id.fetch_add(1);
    job->cfg = std::move(cfg);
    job->running.store(true);
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        reg().jobs[job->id] = job;
    }
    diag::log_tagged_fmt("param_miner", "start job_id=%llu concurrency=%zu timeout_ms=%d sigma=%.1f",
        static_cast<unsigned long long>(job->id), job->cfg.concurrency, job->cfg.timeout_ms, job->cfg.diff_sigma_threshold);
    std::thread([job]() { miner_main(job); }).detach();
    return job->id;
}

bool stop(uint64_t id)
{
    diag::log_tagged_fmt("param_miner", "stop job_id=%llu", static_cast<unsigned long long>(id));
    std::shared_ptr<job_t> job;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().jobs.find(id);
        if (it == reg().jobs.end()) {
            diag::log_tagged_fmt("param_miner", "stop not_found job_id=%llu", static_cast<unsigned long long>(id));
            return false;
        }
        job = it->second;
    }
    job->cancel.store(true);
    diag::log_tagged_fmt("param_miner", "stop cancel_set job_id=%llu", static_cast<unsigned long long>(id));
    return true;
}

status_t status(uint64_t id)
{
    diag::log_tagged_fmt("param_miner", "status job_id=%llu", static_cast<unsigned long long>(id));
    status_t s;
    std::shared_ptr<job_t> job;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().jobs.find(id);
        if (it == reg().jobs.end()) {
            diag::log_tagged_fmt("param_miner", "status not_found job_id=%llu", static_cast<unsigned long long>(id));
            return s;
        }
        job = it->second;
    }
    s.job_id = job->id;
    s.total = job->total.load();
    s.tried = job->tried.load();
    s.hits  = job->hits_count.load();
    s.running = job->running.load();
    diag::log_tagged_fmt("param_miner", "status result job_id=%llu running=%d tried=%zu total=%zu hits=%zu",
        static_cast<unsigned long long>(id), s.running ? 1 : 0, s.tried, s.total, s.hits);
    return s;
}

std::vector<hit_t> results(uint64_t id)
{
    diag::log_tagged_fmt("param_miner", "results job_id=%llu", static_cast<unsigned long long>(id));
    std::vector<hit_t> out;
    std::shared_ptr<job_t> job;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().jobs.find(id);
        if (it == reg().jobs.end()) {
            diag::log_tagged_fmt("param_miner", "results not_found job_id=%llu", static_cast<unsigned long long>(id));
            return out;
        }
        job = it->second;
    }
    std::lock_guard<std::mutex> lk(job->hits_mtx);
    out = job->hits;
    diag::log_tagged_fmt("param_miner", "results returning %zu hits job_id=%llu", out.size(), static_cast<unsigned long long>(id));
    return out;
}

bool clear(uint64_t id)
{
    diag::log_tagged_fmt("param_miner", "clear job_id=%llu", static_cast<unsigned long long>(id));
    std::lock_guard<std::mutex> lk(reg().mtx);
    auto it = reg().jobs.find(id);
    if (it == reg().jobs.end()) {
        diag::log_tagged_fmt("param_miner", "clear not_found job_id=%llu", static_cast<unsigned long long>(id));
        return false;
    }
    if (it->second->running.load()) {
        it->second->cancel.store(true);
        diag::log_tagged_fmt("param_miner", "clear cancel_running job_id=%llu", static_cast<unsigned long long>(id));
    }
    reg().jobs.erase(it);
    diag::log_tagged_fmt("param_miner", "clear erased job_id=%llu", static_cast<unsigned long long>(id));
    return true;
}

std::vector<status_t> list_jobs()
{
    std::vector<status_t> out;
    std::vector<std::shared_ptr<job_t>> snap;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        snap.reserve(reg().jobs.size());
        for (auto& kv : reg().jobs) snap.push_back(kv.second);
    }
    diag::log_tagged_fmt("param_miner", "list_jobs count=%zu", snap.size());
    out.reserve(snap.size());
    for (auto& j : snap) out.push_back(status(j->id));
    return out;
}

bool parse_location(const std::string& v, location_t& out)
{
    diag::log_tagged_fmt("param_miner", "parse_location input=%s", v.c_str());
    std::string lc = v;
    for (char& c : lc) if (c >= 'A' && c <= 'Z') c += 32;
    if (lc == "query")     { out = location_t::query;     diag::log_tagged("param_miner", "parse_location result=query"); return true; }
    if (lc == "body_form" || lc == "form") { out = location_t::body_form; diag::log_tagged("param_miner", "parse_location result=body_form"); return true; }
    if (lc == "json_body" || lc == "json") { out = location_t::json_body; diag::log_tagged("param_miner", "parse_location result=json_body"); return true; }
    if (lc == "header")    { out = location_t::header;    diag::log_tagged("param_miner", "parse_location result=header"); return true; }
    if (lc == "cookie")    { out = location_t::cookie;    diag::log_tagged("param_miner", "parse_location result=cookie"); return true; }
    diag::log_tagged_fmt("param_miner", "parse_location unknown=%s", v.c_str());
    return false;
}

const char* location_name(location_t v)
{
    switch (v) {
        case location_t::query:     return "query";
        case location_t::body_form: return "body_form";
        case location_t::json_body: return "json_body";
        case location_t::header:    return "header";
        case location_t::cookie:    return "cookie";
    }
    return "unknown";
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    std::string e = err_slot();
    diag::log_tagged_fmt("param_miner", "last_error=%s", e.c_str());
    return e;
}

}
}
}
