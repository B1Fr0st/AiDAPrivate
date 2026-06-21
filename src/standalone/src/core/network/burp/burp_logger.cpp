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
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <regex>
#include <string>
#include <system_error>
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

struct prepared_filter_t
{
    const log_filter_t& filter;
    logger::source_t source_value = logger::source_t::manual;
    bool source_filtered = false;
    bool host_regex_ready = false;
    bool url_regex_ready = false;
    std::regex host_regex;
    std::regex url_regex;

    explicit prepared_filter_t(const log_filter_t& f) : filter(f)
    {
        source_filtered = !f.source.empty() && parse_source(f.source, source_value);
        if (!f.host_regex.empty() && f.host_regex.size() <= 512)
        {
            try
            {
                host_regex = std::regex(f.host_regex, std::regex::ECMAScript | std::regex::icase);
                host_regex_ready = true;
            }
            catch (...) { host_regex_ready = false; }
        }
        if (!f.url_regex.empty() && f.url_regex.size() <= 512)
        {
            try
            {
                url_regex = std::regex(f.url_regex, std::regex::ECMAScript | std::regex::icase);
                url_regex_ready = true;
            }
            catch (...) { url_regex_ready = false; }
        }
    }
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

bool row_matches(const log_row_t& r, const prepared_filter_t& pf)
{
    const log_filter_t& f = pf.filter;
    if (!f.method.empty() && r.method != f.method) return false;
    if (r.status < f.status_min || r.status > f.status_max) return false;
    if (pf.source_filtered && r.source != pf.source_value) return false;
    if (f.time_from_ms > 0 && r.ts_ms < f.time_from_ms) return false;
    if (f.time_to_ms   > 0 && r.ts_ms > f.time_to_ms)   return false;
    if (!f.mime_type.empty() && r.mime_type != f.mime_type) return false;
    if (!f.host_regex.empty()) {
        if (pf.host_regex_ready) {
            if (!std::regex_search(r.host, pf.host_regex)) return false;
        } else {
            if (r.host.find(f.host_regex) == std::string::npos) return false;
        }
    }
    if (!f.url_regex.empty()) {
        if (pf.url_regex_ready) {
            if (!std::regex_search(r.url, pf.url_regex)) return false;
        } else {
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
            source_t src = source_t::proxy;
            if (!ex.source.empty())
                parse_source(ex.source, src);
            record(src, ex);
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
    prepared_filter_t pf(f);
    for (auto it = all.rbegin(); it != all.rend(); ++it) {
        if (row_matches(*it, pf)) {
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
    if (path.empty()) {
        diag::log_tagged_fmt("logger", "export_csv invalid_path path_empty=1 errno=%d gle=%lu", EINVAL, static_cast<unsigned long>(ERROR_INVALID_PARAMETER));
        set_err("burp_logger.export_csv path_empty=1 errno=22 gle=87");
        return false;
    }
    const std::filesystem::path fs_path(path);
    const std::filesystem::path parent = fs_path.parent_path();
    if (!parent.empty()) {
        std::error_code parent_ec;
        const bool parent_exists = std::filesystem::exists(parent, parent_ec);
        if (parent_ec) {
            diag::log_tagged_fmt("logger",
                "export_csv parent_exists_failed path=%s parent=%s ec=%d message=%s errno=%d gle=%lu",
                path.c_str(),
                parent.string().c_str(),
                parent_ec.value(),
                parent_ec.message().c_str(),
                errno,
                static_cast<unsigned long>(GetLastError()));
            set_err("burp_logger.export_csv parent_exists_failed path=" + path + " parent=" + parent.string() + " ec=" + std::to_string(parent_ec.value()) + " errno=" + std::to_string(errno) + " gle=" + std::to_string(GetLastError()));
            return false;
        }
        if (!parent_exists) {
            errno = 0;
            SetLastError(ERROR_SUCCESS);
            std::error_code mkdir_ec;
            const bool created = std::filesystem::create_directories(parent, mkdir_ec);
            const int mkdir_errno = errno;
            const DWORD mkdir_gle = GetLastError();
            diag::log_tagged_fmt("logger",
                "export_csv parent_create path=%s parent=%s created=%d ec=%d message=%s errno=%d gle=%lu",
                path.c_str(),
                parent.string().c_str(),
                created ? 1 : 0,
                mkdir_ec.value(),
                mkdir_ec.message().c_str(),
                mkdir_errno,
                static_cast<unsigned long>(mkdir_gle));
            if (mkdir_ec) {
                set_err("burp_logger.export_csv parent_create_failed path=" + path + " parent=" + parent.string() + " ec=" + std::to_string(mkdir_ec.value()) + " errno=" + std::to_string(mkdir_errno) + " gle=" + std::to_string(mkdir_gle));
                return false;
            }
        } else {
            diag::log_tagged_fmt("logger", "export_csv parent_ready path=%s parent=%s", path.c_str(), parent.string().c_str());
        }
    }
    errno = 0;
    SetLastError(ERROR_SUCCESS);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    const int open_errno = errno;
    const DWORD open_gle = GetLastError();
    if (!out.is_open()) {
        diag::log_tagged_fmt("logger",
            "export_csv open_failed path=%s parent=%s errno=%d gle=%lu",
            path.c_str(),
            parent.empty() ? "" : parent.string().c_str(),
            open_errno,
            static_cast<unsigned long>(open_gle));
        set_err("burp_logger.export_csv open_failed path=" + path + " parent=" + (parent.empty() ? std::string() : parent.string()) + " errno=" + std::to_string(open_errno) + " gle=" + std::to_string(open_gle));
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
    errno = 0;
    SetLastError(ERROR_SUCCESS);
    out.flush();
    const bool flush_ok = out.good();
    const int flush_errno = errno;
    const DWORD flush_gle = GetLastError();
    errno = 0;
    SetLastError(ERROR_SUCCESS);
    out.close();
    const bool close_ok = !out.fail();
    const int close_errno = errno;
    const DWORD close_gle = GetLastError();
    std::error_code size_ec;
    const auto final_size = std::filesystem::file_size(fs_path, size_ec);
    diag::log_tagged_fmt("logger",
        "export_csv done path=%s rows=%zu flush_ok=%d flush_errno=%d flush_gle=%lu close_ok=%d close_errno=%d close_gle=%lu file_size=%llu size_ec=%d size_message=%s",
        path.c_str(),
        rows.size(),
        flush_ok ? 1 : 0,
        flush_errno,
        static_cast<unsigned long>(flush_gle),
        close_ok ? 1 : 0,
        close_errno,
        static_cast<unsigned long>(close_gle),
        static_cast<unsigned long long>(size_ec ? 0 : final_size),
        size_ec.value(),
        size_ec.message().c_str());
    if (!flush_ok || !close_ok || size_ec) {
        set_err("burp_logger.export_csv write_verify_failed path=" + path +
            " flush_ok=" + std::to_string(flush_ok ? 1 : 0) +
            " flush_errno=" + std::to_string(flush_errno) +
            " flush_gle=" + std::to_string(flush_gle) +
            " close_ok=" + std::to_string(close_ok ? 1 : 0) +
            " close_errno=" + std::to_string(close_errno) +
            " close_gle=" + std::to_string(close_gle) +
            " size_ec=" + std::to_string(size_ec.value()));
        return false;
    }
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
