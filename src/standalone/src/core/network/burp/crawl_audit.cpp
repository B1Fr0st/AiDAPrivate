#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "crawl_audit.hpp"
#include "crawler.hpp"
#include "active_scanner.hpp"
#include "audit_http.hpp"
#include "helpers/diag_log.hpp"

#include <atomic>
#include <algorithm>
#include <chrono>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <vector>

namespace aida {
namespace burp {
namespace crawl_audit {

namespace {

struct pipeline_entry_t
{
    pipeline_status_t                  status;
    std::shared_ptr<std::atomic<bool>> cancel_flag;
    std::thread                        worker;
    bool                               imported_snapshot = false;
};

std::mutex                                   g_mutex;
std::vector<std::unique_ptr<pipeline_entry_t>> g_pipelines;
std::atomic<uint64_t>                        g_next_id{1};
bool                                         g_initialized = false;

std::vector<uint8_t> build_raw_get(const std::string& host,
                                   uint16_t port,
                                   const std::string& path,
                                   bool tls)
{
    std::ostringstream ss;
    ss << "GET " << (path.empty() ? "/" : path) << " HTTP/1.1\r\n";
    if ((port == 80 && !tls) || (port == 443 && tls) || port == 0)
        ss << "Host: " << host << "\r\n";
    else
        ss << "Host: " << host << ":" << port << "\r\n";
    ss << "User-Agent: AiDA-Audit/1.0\r\n";
    ss << "Connection: close\r\n";
    ss << "\r\n";
    std::string raw = ss.str();
    return std::vector<uint8_t>(raw.begin(), raw.end());
}

void pipeline_worker(uint64_t pipeline_id,
                     uint64_t crawl_id,
                     std::shared_ptr<std::atomic<bool>> cancel_flag,
                     pipeline_config_t config)
{
    diag::log_tagged_fmt("crawl_audit", "worker_start pipeline_id=%llu crawl_id=%llu",
        static_cast<unsigned long long>(pipeline_id),
        static_cast<unsigned long long>(crawl_id));

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        for (auto& e : g_pipelines)
        {
            if (e->status.id == pipeline_id)
            {
                e->status.phase = "crawling";
                break;
            }
        }
    }

    bool crawl_error = false;
    std::string crawl_err_msg;
    crawler::crawl_status_t cs;

    for (;;)
    {
        if (cancel_flag->load(std::memory_order_acquire))
        {
            diag::log_tagged_fmt("crawl_audit", "worker_cancelled_during_crawl pipeline_id=%llu",
                static_cast<unsigned long long>(pipeline_id));
            break;
        }

        cs = crawler::status(crawl_id);

        if (cs.phase == crawler::crawl_status_phase_t::complete ||
            cs.phase == crawler::crawl_status_phase_t::error)
        {
            if (cs.phase == crawler::crawl_status_phase_t::error)
            {
                crawl_error = true;
                crawl_err_msg = cs.last_error;
            }
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    if (cancel_flag->load(std::memory_order_acquire))
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        for (auto& e : g_pipelines)
        {
            if (e->status.id == pipeline_id)
            {
                e->status.phase = "stopped";
                e->status.finished_ms = static_cast<uint64_t>(GetTickCount64());
                break;
            }
        }
        diag::log_tagged_fmt("crawl_audit", "worker_exit_stopped pipeline_id=%llu",
            static_cast<unsigned long long>(pipeline_id));
        return;
    }

    if (crawl_error)
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        for (auto& e : g_pipelines)
        {
            if (e->status.id == pipeline_id)
            {
                e->status.phase = "error";
                e->status.last_error = crawl_err_msg;
                e->status.finished_ms = static_cast<uint64_t>(GetTickCount64());
                break;
            }
        }
        diag::log_tagged_fmt("crawl_audit", "worker_exit_crawl_error pipeline_id=%llu err=%s",
            static_cast<unsigned long long>(pipeline_id), crawl_err_msg.c_str());
        return;
    }

    int pages_discovered = static_cast<int>(cs.discovered.size());

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        for (auto& e : g_pipelines)
        {
            if (e->status.id == pipeline_id)
            {
                e->status.pages_discovered = pages_discovered;
                break;
            }
        }
    }

    diag::log_tagged_fmt("crawl_audit", "crawl_complete pipeline_id=%llu pages_discovered=%d",
        static_cast<unsigned long long>(pipeline_id), pages_discovered);

    if (!config.audit_after_crawl)
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        for (auto& e : g_pipelines)
        {
            if (e->status.id == pipeline_id)
            {
                e->status.phase = "complete";
                e->status.finished_ms = static_cast<uint64_t>(GetTickCount64());
                break;
            }
        }
        diag::log_tagged_fmt("crawl_audit", "worker_exit_no_audit pipeline_id=%llu",
            static_cast<unsigned long long>(pipeline_id));
        return;
    }

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        for (auto& e : g_pipelines)
        {
            if (e->status.id == pipeline_id)
            {
                e->status.phase = "auditing";
                break;
            }
        }
    }

    active_scanner::audit_config_t audit_cfg;
    audit_cfg.session_id = config.session_id;
    audit_cfg.scan_id = config.scan_id;
    audit_cfg.scope_only = config.scope_only;
    audit_cfg.enabled_modules = config.enabled_modules;
    audit_cfg.max_concurrent_requests = static_cast<size_t>(config.max_concurrent);
    audit_cfg.request_throttle_ms = static_cast<size_t>(config.throttle_ms);

    std::vector<uint64_t> audit_ids;
    int audits_started = 0;

    for (const auto& du : cs.discovered)
    {
        if (cancel_flag->load(std::memory_order_acquire))
            break;

        std::string scheme, host, path;
        uint16_t port = 0;
        if (!audit_http::parse_url(du.url, scheme, host, port, path))
        {
            diag::log_tagged_fmt("crawl_audit", "parse_url_failed pipeline_id=%llu url=%s",
                static_cast<unsigned long long>(pipeline_id), du.url.c_str());
            continue;
        }

        bool tls = (scheme == "https");
        std::vector<uint8_t> raw_req = build_raw_get(host, port, path, tls);

        uint64_t audit_id = active_scanner::enqueue_target(raw_req, du.url, audit_cfg);
        if (audit_id == 0)
        {
            diag::log_tagged_fmt("crawl_audit", "enqueue_failed pipeline_id=%llu url=%s err=%s",
                static_cast<unsigned long long>(pipeline_id), du.url.c_str(),
                active_scanner::last_error().c_str());
            continue;
        }

        audit_ids.push_back(audit_id);
        audits_started++;
        diag::log_tagged_fmt("crawl_audit", "enqueued pipeline_id=%llu audit_id=%llu url=%s",
            static_cast<unsigned long long>(pipeline_id),
            static_cast<unsigned long long>(audit_id), du.url.c_str());
    }

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        for (auto& e : g_pipelines)
        {
            if (e->status.id == pipeline_id)
            {
                e->status.audit_ids = audit_ids;
                e->status.audits_started = audits_started;
                break;
            }
        }
    }

    diag::log_tagged_fmt("crawl_audit", "audits_enqueued pipeline_id=%llu count=%d",
        static_cast<unsigned long long>(pipeline_id), audits_started);

    if (!audit_ids.empty())
    {
        for (;;)
        {
            if (cancel_flag->load(std::memory_order_acquire))
                break;

            bool all_done = true;
            int total_issues = 0;

            for (uint64_t aid : audit_ids)
            {
                active_scanner::audit_status_t as;
                if (active_scanner::get_status(aid, as))
                {
                    total_issues += static_cast<int>(as.issues_found);
                    if (as.running && !as.cancelled && !as.drained)
                        all_done = false;
                }
            }

            {
                std::lock_guard<std::mutex> lk(g_mutex);
                for (auto& e : g_pipelines)
                {
                    if (e->status.id == pipeline_id)
                    {
                        e->status.issues_found = total_issues;
                        break;
                    }
                }
            }

            if (all_done)
                break;

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    int final_issues = 0;
    for (uint64_t aid : audit_ids)
    {
        active_scanner::audit_status_t as;
        if (active_scanner::get_status(aid, as))
            final_issues += static_cast<int>(as.issues_found);
    }

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        for (auto& e : g_pipelines)
        {
            if (e->status.id == pipeline_id)
            {
                e->status.issues_found = final_issues;
                if (cancel_flag->load(std::memory_order_acquire))
                    e->status.phase = "stopped";
                else
                    e->status.phase = "complete";
                e->status.finished_ms = static_cast<uint64_t>(GetTickCount64());
                break;
            }
        }
    }

    diag::log_tagged_fmt("crawl_audit", "worker_exit_complete pipeline_id=%llu issues=%d phase=%s",
        static_cast<unsigned long long>(pipeline_id), final_issues,
        cancel_flag->load(std::memory_order_acquire) ? "stopped" : "complete");
}

pipeline_entry_t* find_entry(uint64_t pipeline_id)
{
    for (auto& e : g_pipelines)
        if (e->status.id == pipeline_id)
            return e.get();
    return nullptr;
}

nlohmann::json status_to_json(const pipeline_status_t& s, bool imported_snapshot)
{
    nlohmann::json audit_ids = nlohmann::json::array();
    for (uint64_t id : s.audit_ids)
        audit_ids.push_back(id);

    nlohmann::json j;
    j["id"] = s.id;
    j["crawl_id"] = s.crawl_id;
    j["audit_ids"] = std::move(audit_ids);
    j["pages_discovered"] = s.pages_discovered;
    j["audits_started"] = s.audits_started;
    j["issues_found"] = s.issues_found;
    j["phase"] = s.phase;
    j["started_ms"] = s.started_ms;
    j["finished_ms"] = s.finished_ms;
    j["last_error"] = s.last_error;
    j["imported_snapshot"] = imported_snapshot;
    return j;
}

std::vector<uint64_t> read_u64_array(const nlohmann::json& value)
{
    std::vector<uint64_t> out;
    if (!value.is_array())
        return out;
    out.reserve(value.size());
    for (const auto& item : value)
    {
        if (item.is_number_unsigned())
            out.push_back(item.get<uint64_t>());
        else if (item.is_number_integer() && item.get<int64_t>() >= 0)
            out.push_back(static_cast<uint64_t>(item.get<int64_t>()));
    }
    return out;
}

bool parse_status_json(const nlohmann::json& value, pipeline_status_t& s)
{
    if (!value.is_object())
        return false;

    const uint64_t id = value.value("id", static_cast<uint64_t>(0));
    if (id == 0)
        return false;

    s.id = id;
    s.crawl_id = value.value("crawl_id", static_cast<uint64_t>(0));
    s.audit_ids = read_u64_array(value.value("audit_ids", nlohmann::json::array()));
    s.pages_discovered = value.value("pages_discovered", 0);
    s.audits_started = value.value("audits_started", 0);
    s.issues_found = value.value("issues_found", 0);
    s.phase = value.value("phase", std::string("snapshot"));
    s.started_ms = value.value("started_ms", static_cast<uint64_t>(0));
    s.finished_ms = value.value("finished_ms", static_cast<uint64_t>(0));
    s.last_error = value.value("last_error", std::string());

    if (s.phase == "pending" || s.phase == "crawling" || s.phase == "auditing")
    {
        if (s.last_error.empty())
            s.last_error = "pipeline was active when the project snapshot was saved";
        s.phase = "imported_snapshot";
    }
    if (s.phase.empty())
        s.phase = "snapshot";

    return true;
}

void stop_entries(std::vector<std::unique_ptr<pipeline_entry_t>>& entries)
{
    for (auto& e : entries)
    {
        if (!e || e->imported_snapshot)
            continue;
        if (e->cancel_flag)
            e->cancel_flag->store(true, std::memory_order_release);
        if (e->status.crawl_id != 0)
            crawler::stop(e->status.crawl_id);
        for (uint64_t aid : e->status.audit_ids)
            active_scanner::cancel_audit(aid);
    }

    for (auto& e : entries)
    {
        if (e && e->worker.joinable())
            e->worker.join();
    }
}

uint64_t next_import_id_locked(const std::unordered_set<uint64_t>& used)
{
    uint64_t candidate = g_next_id.fetch_add(1);
    while (candidate == 0 || used.find(candidate) != used.end())
        candidate = g_next_id.fetch_add(1);
    return candidate;
}

}

bool initialize()
{
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_initialized) return true;
    g_initialized = true;
    g_next_id.store(1);
    diag::log_tagged_fmt("crawl_audit", "initialized");
    return true;
}

void shutdown()
{
    std::vector<std::unique_ptr<pipeline_entry_t>> entries_to_join;

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        if (!g_initialized) return;
        entries_to_join.swap(g_pipelines);
        g_initialized = false;
    }

    stop_entries(entries_to_join);

    diag::log_tagged_fmt("crawl_audit", "shutdown");
}

uint64_t start(const pipeline_config_t& config)
{
    if (config.start_urls.empty())
    {
        diag::log_tagged_fmt("crawl_audit", "start_rejected_no_urls");
        return 0;
    }

    std::lock_guard<std::mutex> lk(g_mutex);
    if (!g_initialized)
    {
        diag::log_tagged_fmt("crawl_audit", "start_rejected_not_initialized");
        return 0;
    }

    uint64_t pipeline_id = g_next_id.fetch_add(1);

    crawler::crawl_config_t crawl_cfg;
    crawl_cfg.start_urls = config.start_urls;
    crawl_cfg.max_depth = config.max_depth;
    crawl_cfg.max_pages = config.max_pages;
    crawl_cfg.same_host_only = config.same_host_only;
    crawl_cfg.scope_only = config.scope_only;
    crawl_cfg.concurrency = config.max_concurrent;

    uint64_t crawl_id = crawler::start(crawl_cfg);
    if (crawl_id == 0)
    {
        diag::log_tagged_fmt("crawl_audit", "start_crawler_failed err=%s", crawler::last_error().c_str());
        return 0;
    }

    auto entry = std::make_unique<pipeline_entry_t>();
    entry->status.id = pipeline_id;
    entry->status.crawl_id = crawl_id;
    entry->status.phase = "pending";
    entry->status.started_ms = static_cast<uint64_t>(GetTickCount64());
    entry->cancel_flag = std::make_shared<std::atomic<bool>>(false);

    auto cf = entry->cancel_flag;
    auto cfg_copy = config;

    entry->worker = std::thread([pipeline_id, crawl_id, cf, cfg_copy]() {
        pipeline_worker(pipeline_id, crawl_id, cf, cfg_copy);
    });

    g_pipelines.push_back(std::move(entry));

    diag::log_tagged_fmt("crawl_audit", "started pipeline_id=%llu crawl_id=%llu urls=%zu depth=%d max_pages=%d",
        static_cast<unsigned long long>(pipeline_id),
        static_cast<unsigned long long>(crawl_id),
        config.start_urls.size(), config.max_depth, config.max_pages);

    return pipeline_id;
}

bool stop(uint64_t pipeline_id)
{
    std::shared_ptr<std::atomic<bool>> cf;
    uint64_t crawl_id = 0;
    std::vector<uint64_t> audit_ids;

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        pipeline_entry_t* e = find_entry(pipeline_id);
        if (!e)
        {
            diag::log_tagged_fmt("crawl_audit", "stop_not_found pipeline_id=%llu",
                static_cast<unsigned long long>(pipeline_id));
            return false;
        }
        cf = e->cancel_flag;
        crawl_id = e->status.crawl_id;
        audit_ids = e->status.audit_ids;
        e->status.phase = "stopped";
        if (e->imported_snapshot)
        {
            e->status.finished_ms = static_cast<uint64_t>(GetTickCount64());
            diag::log_tagged_fmt("crawl_audit", "stop_imported_snapshot pipeline_id=%llu",
                static_cast<unsigned long long>(pipeline_id));
            return true;
        }
    }

    if (cf)
        cf->store(true, std::memory_order_release);

    if (crawl_id != 0)
        crawler::stop(crawl_id);

    for (uint64_t aid : audit_ids)
        active_scanner::cancel_audit(aid);

    diag::log_tagged_fmt("crawl_audit", "stopped pipeline_id=%llu crawl_id=%llu audits=%zu",
        static_cast<unsigned long long>(pipeline_id),
        static_cast<unsigned long long>(crawl_id),
        audit_ids.size());

    return true;
}

pipeline_status_t status(uint64_t pipeline_id)
{
    std::lock_guard<std::mutex> lk(g_mutex);
    pipeline_entry_t* e = find_entry(pipeline_id);
    if (!e)
    {
        pipeline_status_t empty;
        empty.last_error = "pipeline not found";
        return empty;
    }

    if (!e->imported_snapshot)
    {
        int total_issues = 0;
        for (uint64_t aid : e->status.audit_ids)
        {
            active_scanner::audit_status_t as;
            if (active_scanner::get_status(aid, as))
                total_issues += static_cast<int>(as.issues_found);
        }
        e->status.issues_found = total_issues;
    }

    return e->status;
}

std::vector<pipeline_status_t> list()
{
    std::vector<pipeline_status_t> result;

    std::lock_guard<std::mutex> lk(g_mutex);
    result.reserve(g_pipelines.size());
    for (auto& e : g_pipelines)
    {
        if (!e->imported_snapshot)
        {
            int total_issues = 0;
            for (uint64_t aid : e->status.audit_ids)
            {
                active_scanner::audit_status_t as;
                if (active_scanner::get_status(aid, as))
                    total_issues += static_cast<int>(as.issues_found);
            }
            e->status.issues_found = total_issues;
        }
        result.push_back(e->status);
    }

    return result;
}

nlohmann::json export_json()
{
    nlohmann::json pipelines = nlohmann::json::array();
    uint64_t next_id = g_next_id.load(std::memory_order_acquire);

    std::lock_guard<std::mutex> lk(g_mutex);
    for (auto& e : g_pipelines)
    {
        if (!e)
            continue;
        if (!e->imported_snapshot)
        {
            int total_issues = 0;
            for (uint64_t aid : e->status.audit_ids)
            {
                active_scanner::audit_status_t as;
                if (active_scanner::get_status(aid, as))
                    total_issues += static_cast<int>(as.issues_found);
            }
            e->status.issues_found = total_issues;
        }
        pipelines.push_back(status_to_json(e->status, e->imported_snapshot));
    }

    nlohmann::json root;
    root["version"] = 1;
    root["initialized"] = g_initialized;
    root["next_id"] = next_id;
    root["pipelines"] = std::move(pipelines);
    return root;
}

bool import_json(const nlohmann::json& doc, bool replace_existing)
{
    if (!doc.is_object() || doc.value("version", 0) < 1 || !doc.contains("pipelines") || !doc["pipelines"].is_array())
    {
        diag::log_tagged_fmt("crawl_audit", "import_rejected_invalid_schema");
        return false;
    }

    std::vector<std::unique_ptr<pipeline_entry_t>> imported;
    imported.reserve(doc["pipelines"].size());
    std::unordered_set<uint64_t> imported_ids;
    uint64_t max_id = 0;

    for (const auto& item : doc["pipelines"])
    {
        pipeline_status_t s;
        if (!parse_status_json(item, s))
        {
            diag::log_tagged_fmt("crawl_audit", "import_rejected_invalid_pipeline");
            return false;
        }
        if (imported_ids.find(s.id) != imported_ids.end())
        {
            diag::log_tagged_fmt("crawl_audit", "import_rejected_duplicate_pipeline id=%llu",
                static_cast<unsigned long long>(s.id));
            return false;
        }
        imported_ids.insert(s.id);
        max_id = std::max(max_id, s.id);

        auto entry = std::make_unique<pipeline_entry_t>();
        entry->status = std::move(s);
        entry->imported_snapshot = true;
        imported.push_back(std::move(entry));
    }

    std::vector<std::unique_ptr<pipeline_entry_t>> entries_to_join;
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        if (replace_existing)
            entries_to_join.swap(g_pipelines);
        g_initialized = true;

        std::unordered_set<uint64_t> used;
        for (const auto& e : g_pipelines)
        {
            if (e)
                used.insert(e->status.id);
        }

        for (auto& entry : imported)
        {
            if (!replace_existing && used.find(entry->status.id) != used.end())
                entry->status.id = next_import_id_locked(used);
            used.insert(entry->status.id);
            max_id = std::max(max_id, entry->status.id);
            g_pipelines.push_back(std::move(entry));
        }

        const uint64_t requested_next = doc.value("next_id", static_cast<uint64_t>(0));
        uint64_t desired_next = std::max(max_id + 1, requested_next);
        if (desired_next == 0)
            desired_next = 1;
        uint64_t current = g_next_id.load(std::memory_order_acquire);
        while (current < desired_next && !g_next_id.compare_exchange_weak(current, desired_next))
        {
        }
    }

    stop_entries(entries_to_join);

    diag::log_tagged_fmt("crawl_audit", "imported pipelines=%zu replace=%d",
        imported_ids.size(), replace_existing ? 1 : 0);
    return true;
}

}
}
}
