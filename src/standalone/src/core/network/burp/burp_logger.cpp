#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_logger.hpp"

#include "../../../helpers/diag_log.hpp"
#include "../../infra/event_bus.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <regex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace logger {

namespace {

std::mutex& err_mtx()  { static std::mutex m; return m; }
std::string& err_slot() { static std::string s; return s; }

void set_err(const std::string& m)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = m;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

struct ring_t
{
    std::mutex                                   mtx;
    std::vector<log_row_t>                       rows;
    size_t                                       write_idx = 0;
    size_t                                       count = 0;
    size_t                                       cap = 100000;
    std::atomic<uint64_t>                        next_id{1};
    std::atomic<bool>                            initialized{false};
    aida::events::subscription_handle_t          sub;
};

ring_t& ring()
{
    static ring_t r;
    return r;
}

void push_locked(ring_t& r, log_row_t row)
{
    if (r.rows.size() < r.cap) {
        r.rows.push_back(std::move(row));
        r.count = r.rows.size();
        r.write_idx = r.count % r.cap;
    } else {
        r.rows[r.write_idx] = std::move(row);
        r.write_idx = (r.write_idx + 1) % r.cap;
        r.count = r.cap;
    }
}

std::vector<log_row_t> snapshot_chronological()
{
    auto& r = ring();
    std::lock_guard<std::mutex> lk(r.mtx);
    std::vector<log_row_t> out;
    if (r.count == 0) return out;
    out.reserve(r.count);
    if (r.rows.size() < r.cap || r.count < r.cap) {
        out.insert(out.end(), r.rows.begin(), r.rows.begin() + static_cast<ptrdiff_t>(r.count));
    } else {
        out.insert(out.end(), r.rows.begin() + static_cast<ptrdiff_t>(r.write_idx), r.rows.end());
        out.insert(out.end(), r.rows.begin(), r.rows.begin() + static_cast<ptrdiff_t>(r.write_idx));
    }
    return out;
}

std::string mime_from_headers(const std::vector<std::pair<std::string, std::string>>& hs)
{
    for (const auto& h : hs) {
        std::string k = h.first;
        std::transform(k.begin(), k.end(), k.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (k == "content-type") {
            auto semi = h.second.find(';');
            return (semi == std::string::npos) ? h.second : h.second.substr(0, semi);
        }
    }
    return std::string();
}

std::string build_url_from_exchange(const exchange_observed_t& ex)
{
    std::string url = ex.scheme.empty() ? std::string("http") : ex.scheme;
    url += "://";
    url += ex.host;
    if ((ex.scheme == "https" && ex.port != 443) || (ex.scheme == "http" && ex.port != 80) || ex.scheme.empty())
        url += ":" + std::to_string(ex.port);
    url += ex.path;
    if (!ex.query.empty()) {
        if (ex.path.find('?') == std::string::npos) url += "?";
        url += ex.query;
    }
    return url;
}

std::string csv_quote(const std::string& s)
{
    bool needs = false;
    for (char c : s) if (c == ',' || c == '"' || c == '\n' || c == '\r') { needs = true; break; }
    if (!needs) return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += "\"";
    return out;
}

bool row_matches(const log_row_t& r, const log_filter_t& f)
{
    if (!f.method.empty() && r.method != f.method) return false;
    if (r.status < f.status_min || r.status > f.status_max) return false;
    if (!f.source.empty()) {
        source_t src = source_t::manual;
        if (parse_source(f.source, src)) { if (r.source != src) return false; }
    }
    if (f.time_from_ms > 0 && r.ts_ms < f.time_from_ms) return false;
    if (f.time_to_ms   > 0 && r.ts_ms > f.time_to_ms)   return false;
    if (!f.mime_type.empty() && r.mime_type != f.mime_type) return false;
    if (!f.host_regex.empty()) {
        try {
            std::regex re(f.host_regex, std::regex::ECMAScript | std::regex::icase);
            if (!std::regex_search(r.host, re)) return false;
        } catch (...) {
            if (r.host.find(f.host_regex) == std::string::npos) return false;
        }
    }
    if (!f.url_regex.empty()) {
        try {
            std::regex re(f.url_regex, std::regex::ECMAScript | std::regex::icase);
            if (!std::regex_search(r.url, re)) return false;
        } catch (...) {
            if (r.url.find(f.url_regex) == std::string::npos) return false;
        }
    }
    return true;
}

}

const char* source_label(source_t s)
{
    switch (s) {
        case source_t::proxy:    return "proxy";
        case source_t::repeater: return "repeater";
        case source_t::scanner:  return "scanner";
        case source_t::intruder: return "intruder";
        case source_t::crawler:  return "crawler";
        case source_t::manual:   return "manual";
        case source_t::api:      return "api";
        case source_t::fuzzer:   return "fuzzer";
    }
    return "manual";
}

bool parse_source(const std::string& s, source_t& out)
{
    std::string l = s;
    std::transform(l.begin(), l.end(), l.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (l == "proxy")    { out = source_t::proxy;    return true; }
    if (l == "repeater") { out = source_t::repeater; return true; }
    if (l == "scanner")  { out = source_t::scanner;  return true; }
    if (l == "intruder") { out = source_t::intruder; return true; }
    if (l == "crawler")  { out = source_t::crawler;  return true; }
    if (l == "manual")   { out = source_t::manual;   return true; }
    if (l == "api")      { out = source_t::api;      return true; }
    if (l == "fuzzer")   { out = source_t::fuzzer;   return true; }
    return false;
}

bool initialize()
{
    diag::log_tagged_fmt("logger", "initialize entry");
    auto& r = ring();
    bool expected = false;
    if (!r.initialized.compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("logger", "initialize already_initialized");
        return true;
    }
    r.sub = aida::events::subscribe(kExchangeObservedEvent,
        [](const exchange_observed_t& ex) {
            record(source_t::proxy, ex);
        });
    diag::log_tagged_fmt("logger", "initialize done subscribed cap=%zu", r.cap);
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("logger", "shutdown entry");
    auto& r = ring();
    if (r.initialized.load()) {
        aida::events::unsubscribe(r.sub);
        r.initialized.store(false);
        diag::log_tagged_fmt("logger", "shutdown unsubscribed");
    } else {
        diag::log_tagged_fmt("logger", "shutdown not_initialized skipping");
    }
    std::lock_guard<std::mutex> lk(r.mtx);
    size_t n = r.count;
    r.rows.clear();
    r.count = 0;
    r.write_idx = 0;
    diag::log_tagged_fmt("logger", "shutdown done cleared=%zu", n);
}

uint64_t record(source_t src, const exchange_observed_t& ex)
{
    auto& r = ring();
    log_row_t row;
    row.id              = r.next_id.fetch_add(1);
    row.ts_ms           = (ex.timestamp_ms != 0) ? ex.timestamp_ms : now_ms();
    row.method          = ex.method;
    row.host            = ex.host;
    row.port            = ex.port;
    row.url             = build_url_from_exchange(ex);
    row.status          = ex.status_code;
    row.request_length  = ex.req_body.size();
    row.response_length = ex.resp_body.size();
    row.latency_ms      = ex.latency_ms;
    row.mime_type       = mime_from_headers(ex.resp_headers);
    row.source          = src;
    row.exchange_id     = ex.id;
    uint64_t id = row.id;
    diag::log_tagged_fmt("logger", "record id=%llu method=%s host=%s status=%d latency_ms=%llu src=%s",
        static_cast<unsigned long long>(id), row.method.c_str(), row.host.c_str(),
        row.status, static_cast<unsigned long long>(row.latency_ms), source_label(src));
    std::lock_guard<std::mutex> lk(r.mtx);
    push_locked(r, std::move(row));
    return id;
}

std::vector<log_row_t> query(const log_filter_t& f, size_t limit)
{
    diag::log_tagged_fmt("logger", "query entry limit=%zu method=%s status_min=%d status_max=%d",
        limit, f.method.c_str(), f.status_min, f.status_max);
    std::vector<log_row_t> all = snapshot_chronological();
    std::vector<log_row_t> out;
    out.reserve(all.size());
    for (auto it = all.rbegin(); it != all.rend(); ++it) {
        if (row_matches(*it, f)) {
            out.push_back(*it);
            if (limit > 0 && out.size() >= limit) break;
        }
    }
    diag::log_tagged_fmt("logger", "query result total=%zu matching=%zu", all.size(), out.size());
    return out;
}

size_t total_rows()
{
    auto& r = ring();
    std::lock_guard<std::mutex> lk(r.mtx);
    size_t n = r.count;
    diag::log_tagged_fmt("logger", "total_rows result=%zu", n);
    return n;
}

void clear()
{
    diag::log_tagged_fmt("logger", "clear entry");
    auto& r = ring();
    std::lock_guard<std::mutex> lk(r.mtx);
    size_t n = r.count;
    r.rows.clear();
    r.count = 0;
    r.write_idx = 0;
    diag::log_tagged_fmt("logger", "clear done cleared=%zu", n);
}

bool export_csv(const std::string& path, const log_filter_t& f)
{
    diag::log_tagged_fmt("logger", "export_csv entry path=%s", path.c_str());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        diag::log_tagged_fmt("logger", "export_csv open_failed path=%s", path.c_str());
        set_err("burp_logger.export_csv: cannot open output");
        return false;
    }
    out << "id,ts_ms,method,url,host,port,status,req_len,resp_len,latency_ms,mime,source\r\n";
    auto rows = query(f, 0);
    diag::log_tagged_fmt("logger", "export_csv writing rows=%zu", rows.size());
    for (const auto& r : rows) {
        out << r.id << ',' << r.ts_ms << ','
            << csv_quote(r.method) << ',' << csv_quote(r.url) << ','
            << csv_quote(r.host) << ',' << r.port << ',' << r.status << ','
            << r.request_length << ',' << r.response_length << ','
            << r.latency_ms << ','
            << csv_quote(r.mime_type) << ','
            << csv_quote(source_label(r.source)) << "\r\n";
    }
    diag::log_tagged_fmt("logger", "export_csv done path=%s rows=%zu", path.c_str(), rows.size());
    return true;
}

void set_capacity(size_t rows)
{
    diag::log_tagged_fmt("logger", "set_capacity entry rows=%zu", rows);
    if (rows < 16) rows = 16;
    auto& r = ring();
    std::lock_guard<std::mutex> lk(r.mtx);
    if (rows == r.cap) {
        diag::log_tagged_fmt("logger", "set_capacity unchanged cap=%zu", r.cap);
        return;
    }
    size_t old_cap = r.cap;
    auto chronological = std::vector<log_row_t>();
    if (r.count > 0) {
        if (r.rows.size() < r.cap || r.count < r.cap) {
            chronological.insert(chronological.end(), r.rows.begin(), r.rows.begin() + static_cast<ptrdiff_t>(r.count));
        } else {
            chronological.insert(chronological.end(), r.rows.begin() + static_cast<ptrdiff_t>(r.write_idx), r.rows.end());
            chronological.insert(chronological.end(), r.rows.begin(), r.rows.begin() + static_cast<ptrdiff_t>(r.write_idx));
        }
    }
    r.cap = rows;
    if (chronological.size() > rows) {
        chronological.erase(chronological.begin(), chronological.begin() + static_cast<ptrdiff_t>(chronological.size() - rows));
    }
    r.rows = std::move(chronological);
    r.count = r.rows.size();
    r.write_idx = r.count % r.cap;
    diag::log_tagged_fmt("logger", "set_capacity done old=%zu new=%zu current_count=%zu", old_cap, rows, r.count);
}

size_t capacity()
{
    auto& r = ring();
    std::lock_guard<std::mutex> lk(r.mtx);
    size_t cap = r.cap;
    diag::log_tagged_fmt("logger", "capacity result=%zu", cap);
    return cap;
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    std::string e = err_slot();
    diag::log_tagged_fmt("logger", "last_error queried val=%s", e.c_str());
    return e;
}

}
}
}
