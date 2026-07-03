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

std::string base64_encode(const std::vector<uint8_t>& data)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 2 < data.size()) {
        const uint32_t v = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8) | static_cast<uint32_t>(data[i + 2]);
        out.push_back(tbl[(v >> 18) & 0x3f]);
        out.push_back(tbl[(v >> 12) & 0x3f]);
        out.push_back(tbl[(v >> 6) & 0x3f]);
        out.push_back(tbl[v & 0x3f]);
        i += 3;
    }
    if (i < data.size()) {
        const size_t rem = data.size() - i;
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        if (rem > 1)
            v |= static_cast<uint32_t>(data[i + 1]) << 8;
        out.push_back(tbl[(v >> 18) & 0x3f]);
        out.push_back(tbl[(v >> 12) & 0x3f]);
        out.push_back(rem > 1 ? tbl[(v >> 6) & 0x3f] : '=');
        out.push_back('=');
    }
    return out;
}

std::vector<uint8_t> base64_decode(const std::string& s)
{
    static const int8_t tbl[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() * 3 / 4);
    uint32_t buf = 0;
    int bits = 0;
    for (unsigned char c : s) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
            continue;
        int v = tbl[c];
        if (v == -1)
            return {};
        if (v == -2)
            break;
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xff));
        }
    }
    return out;
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

nlohmann::json export_json()
{
    std::lock_guard<std::mutex> lk(g_mutex);
    nlohmann::json tabs = nlohmann::json::array();
    for (const auto& tab : g_tabs) {
        tabs.push_back({
            {"id", tab.id},
            {"name", tab.name},
            {"host", tab.host},
            {"port", tab.port},
            {"use_tls", tab.use_tls},
            {"raw_request_b64", base64_encode(tab.raw_request)},
            {"raw_response_b64", base64_encode(tab.raw_response)},
            {"status_code", tab.status_code},
            {"latency_ms", tab.latency_ms},
            {"error", tab.error},
            {"created_ms", tab.created_ms},
            {"last_sent_ms", tab.last_sent_ms},
            {"has_response", tab.has_response}
        });
    }
    return {{"tabs", std::move(tabs)}};
}

bool import_json(const nlohmann::json& doc, bool replace_existing)
{
    nlohmann::json tabs_doc = doc;
    if (doc.is_object())
        tabs_doc = doc.value("tabs", nlohmann::json::array());
    if (!tabs_doc.is_array())
        return false;
    std::vector<repeater_tab_t> loaded;
    uint64_t max_id = 0;
    for (const auto& item : tabs_doc) {
        if (!item.is_object())
            continue;
        repeater_tab_t tab;
        tab.id = item.value("id", static_cast<uint64_t>(0));
        tab.name = item.value("name", std::string());
        tab.host = item.value("host", std::string());
        tab.port = static_cast<uint16_t>(std::min(item.value("port", 443), 65535));
        tab.use_tls = item.value("use_tls", true);
        tab.raw_request = base64_decode(item.value("raw_request_b64", std::string()));
        tab.raw_response = base64_decode(item.value("raw_response_b64", std::string()));
        tab.status_code = item.value("status_code", 0);
        tab.latency_ms = item.value("latency_ms", static_cast<uint64_t>(0));
        tab.error = item.value("error", std::string());
        tab.created_ms = item.value("created_ms", static_cast<uint64_t>(0));
        tab.last_sent_ms = item.value("last_sent_ms", static_cast<uint64_t>(0));
        tab.has_response = item.value("has_response", !tab.raw_response.empty());
        if (tab.host.empty() || tab.raw_request.empty())
            continue;
        max_id = std::max(max_id, tab.id);
        loaded.push_back(std::move(tab));
    }
    std::lock_guard<std::mutex> lk(g_mutex);
    if (replace_existing)
        g_tabs.clear();
    for (auto& tab : loaded) {
        if (tab.id == 0)
            tab.id = g_next_id.fetch_add(1);
        max_id = std::max(max_id, tab.id);
        if (tab.name.empty())
            tab.name = "Tab " + std::to_string(tab.id);
        if (tab.created_ms == 0)
            tab.created_ms = now_ms();
        g_tabs.push_back(std::move(tab));
    }
    if (max_id >= g_next_id.load())
        g_next_id.store(max_id + 1);
    return true;
}

}
}
}
