#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "repeater.hpp"
#include "audit_http.hpp"
#include "burp_logger.hpp"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <cstring>

namespace aida {
namespace burp {
namespace repeater {

namespace {

std::mutex                    g_mutex;
std::vector<repeater_tab_t>   g_tabs;
std::atomic<uint64_t>         g_next_id{1};
bool                          g_initialized = false;

uint64_t now_ms()
{
    return static_cast<uint64_t>(GetTickCount64());
}

repeater_tab_t* find_tab_locked(uint64_t tab_id)
{
    for (auto& t : g_tabs)
        if (t.id == tab_id)
            return &t;
    return nullptr;
}

send_result_t exchange_to_result(const exchange_observed_t& ex)
{
    send_result_t r;
    r.success      = (ex.status_code > 0);
    r.status_code  = ex.status_code;
    r.raw_response = ex.resp_body;
    r.response_headers = ex.resp_headers;
    r.latency_ms   = ex.latency_ms;
    return r;
}

send_result_t do_send(const std::vector<uint8_t>& raw_request,
                      const std::string& host,
                      uint16_t port,
                      bool tls,
                      const audit_http::send_options_t& opts)
{
    send_result_t result;
    if (raw_request.empty())
    {
        result.error = "empty request";
        return result;
    }
    if (host.empty())
    {
        result.error = "empty host";
        return result;
    }

    diag::log_tagged_fmt("repeater", "send host=%s port=%u tls=%d req_len=%zu timeout=%d follow=%d",
        host.c_str(), static_cast<unsigned>(port), static_cast<int>(tls),
        raw_request.size(), opts.timeout_ms, static_cast<int>(opts.follow_redirects));

    auto observed = audit_http::send(raw_request, host, port, tls, opts);

    if (!observed)
    {
        std::string err = audit_http::last_error();
        if (err.empty()) err = "send failed";
        diag::log_tagged_fmt("repeater", "send failed host=%s err=%s", host.c_str(), err.c_str());
        result.error = std::move(err);
        return result;
    }

    diag::log_tagged_fmt("repeater", "send ok host=%s status=%d latency=%llu resp_len=%zu",
        host.c_str(), observed->status_code,
        static_cast<unsigned long long>(observed->latency_ms),
        observed->resp_body.size());

    logger::record(logger::source_t::repeater, *observed);

    result = exchange_to_result(*observed);
    return result;
}

}

bool initialize()
{
    std::lock_guard<std::mutex> lk(g_mutex);
    g_tabs.clear();
    g_next_id.store(1);
    g_initialized = true;
    diag::log_tagged_fmt("repeater", "initialized");
    return true;
}

void shutdown()
{
    std::lock_guard<std::mutex> lk(g_mutex);
    g_tabs.clear();
    g_initialized = false;
    diag::log_tagged_fmt("repeater", "shutdown");
}

uint64_t create_tab(const std::string& host, uint16_t port, bool use_tls,
                    const std::vector<uint8_t>& raw_request, const std::string& name)
{
    std::lock_guard<std::mutex> lk(g_mutex);
    repeater_tab_t tab;
    tab.id           = g_next_id.fetch_add(1);
    tab.name         = name.empty() ? ("Tab " + std::to_string(tab.id)) : name;
    tab.host         = host;
    tab.port         = port;
    tab.use_tls      = use_tls;
    tab.raw_request  = raw_request;
    tab.created_ms   = now_ms();
    g_tabs.push_back(std::move(tab));
    diag::log_tagged_fmt("repeater", "create_tab id=%llu host=%s port=%u tls=%d name=%s",
        static_cast<unsigned long long>(g_tabs.back().id),
        host.c_str(), static_cast<unsigned>(port), static_cast<int>(use_tls),
        g_tabs.back().name.c_str());
    return g_tabs.back().id;
}

bool close_tab(uint64_t tab_id)
{
    std::lock_guard<std::mutex> lk(g_mutex);
    for (auto it = g_tabs.begin(); it != g_tabs.end(); ++it)
    {
        if (it->id == tab_id)
        {
            diag::log_tagged_fmt("repeater", "close_tab id=%llu", static_cast<unsigned long long>(tab_id));
            g_tabs.erase(it);
            return true;
        }
    }
    diag::log_tagged_fmt("repeater", "close_tab not_found id=%llu", static_cast<unsigned long long>(tab_id));
    return false;
}

std::vector<repeater_tab_t> list_tabs()
{
    std::lock_guard<std::mutex> lk(g_mutex);
    return g_tabs;
}

bool get_tab(uint64_t tab_id, repeater_tab_t& out)
{
    std::lock_guard<std::mutex> lk(g_mutex);
    auto* tab = find_tab_locked(tab_id);
    if (!tab)
    {
        diag::log_tagged_fmt("repeater", "get_tab not_found id=%llu", static_cast<unsigned long long>(tab_id));
        return false;
    }
    out = *tab;
    return true;
}

send_result_t send(uint64_t tab_id)
{
    std::vector<uint8_t> raw_request;
    std::string host;
    uint16_t port = 0;
    bool tls = true;

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        auto* tab = find_tab_locked(tab_id);
        if (!tab)
        {
            diag::log_tagged_fmt("repeater", "send tab_not_found id=%llu", static_cast<unsigned long long>(tab_id));
            send_result_t r;
            r.error = "tab not found";
            return r;
        }
        raw_request = tab->raw_request;
        host        = tab->host;
        port        = tab->port;
        tls         = tab->use_tls;
    }

    audit_http::send_options_t opts;
    opts.timeout_ms       = 15000;
    opts.follow_redirects = false;
    opts.publish_exchange = false;
    opts.exchange_source  = "repeater";

    send_result_t result = do_send(raw_request, host, port, tls, opts);

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        auto* tab = find_tab_locked(tab_id);
        if (tab)
        {
            tab->raw_response  = result.raw_response;
            tab->status_code   = result.status_code;
            tab->latency_ms    = result.latency_ms;
            tab->error         = result.error;
            tab->has_response  = result.success;
            tab->last_sent_ms  = now_ms();
        }
    }

    return result;
}

send_result_t send_raw(const std::string& host, uint16_t port, bool use_tls,
                       const std::vector<uint8_t>& raw_request,
                       int timeout_ms, bool follow_redirects)
{
    audit_http::send_options_t opts;
    opts.timeout_ms       = timeout_ms;
    opts.follow_redirects = follow_redirects;
    opts.publish_exchange = false;
    opts.exchange_source  = "repeater";

    return do_send(raw_request, host, port, use_tls, opts);
}

bool update_tab_request(uint64_t tab_id, const std::vector<uint8_t>& raw_request)
{
    std::lock_guard<std::mutex> lk(g_mutex);
    auto* tab = find_tab_locked(tab_id);
    if (!tab)
    {
        diag::log_tagged_fmt("repeater", "update_tab_request not_found id=%llu", static_cast<unsigned long long>(tab_id));
        return false;
    }
    tab->raw_request  = raw_request;
    tab->has_response = false;
    tab->raw_response.clear();
    tab->status_code  = 0;
    tab->error.clear();
    diag::log_tagged_fmt("repeater", "update_tab_request ok id=%llu req_len=%zu",
        static_cast<unsigned long long>(tab_id), raw_request.size());
    return true;
}

bool update_tab_target(uint64_t tab_id, const std::string& host, uint16_t port, bool use_tls)
{
    std::lock_guard<std::mutex> lk(g_mutex);
    auto* tab = find_tab_locked(tab_id);
    if (!tab)
    {
        diag::log_tagged_fmt("repeater", "update_tab_target not_found id=%llu", static_cast<unsigned long long>(tab_id));
        return false;
    }
    tab->host    = host;
    tab->port    = port;
    tab->use_tls = use_tls;
    diag::log_tagged_fmt("repeater", "update_tab_target ok id=%llu host=%s port=%u tls=%d",
        static_cast<unsigned long long>(tab_id), host.c_str(),
        static_cast<unsigned>(port), static_cast<int>(use_tls));
    return true;
}

size_t tab_count()
{
    std::lock_guard<std::mutex> lk(g_mutex);
    return g_tabs.size();
}

void clear_all()
{
    std::lock_guard<std::mutex> lk(g_mutex);
    size_t n = g_tabs.size();
    g_tabs.clear();
    diag::log_tagged_fmt("repeater", "clear_all cleared=%zu", n);
}

}
}
}
