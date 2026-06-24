#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#pragma comment(lib, "bcrypt.lib")
#include <shlobj.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#include "mcp_standalone.hpp"
#include "standalone_driver.hpp"
#include "standalone_license.hpp"
#include "../anti-tamper/mcp_posture.hpp"
#include "arc/arc.h"
#include "zydis_disasm.hpp"
#include "sandbox.hpp"
#include "../infra/critical_work_queue.hpp"
#include "../infra/work_queue.hpp"
#include "../runtime/manual_map_tls.hpp"
#include "../session/analysis_session.hpp"
#include "../../helpers/diag_log.hpp"
#include <httplib.h>
#include <sstream>
#include <fstream>
#include <random>
#include <set>
#include <queue>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <future>
#include <limits>
#include <memory>
#include <map>
#include <shared_mutex>
#include <thread>

namespace mcp_standalone
{
namespace
{
    std::atomic<bool> g_ide_lifecycle_ready{false};
    constexpr std::uint64_t kMcpDefaultToolTimeoutMs = 45000;
    constexpr std::uint64_t kMcpMinToolTimeoutMs = 500;
    constexpr std::uint64_t kMcpMaxToolTimeoutMs = 120000;
    constexpr std::uint64_t kMcpBrowserToolMaxTimeoutMs = 300000;
    constexpr std::uint64_t kMcpBrowserLongActionTimeoutMs = 180000;
    constexpr std::uint64_t kMcpBrowserCleanupGraceMs = 30000;
    constexpr std::uint64_t kMcpBatchWaitTimeoutMs = 60000;
    constexpr std::uint64_t kMcpPolicyLockMaxWaitMs = 5000;
    constexpr std::uint64_t kMcpPolicyLockPollMs = 25;
    constexpr std::uint64_t kMcpPolicyLockLogEveryMs = 500;
    constexpr std::size_t kMcpMaxBatchItems = 4096;
    constexpr std::size_t kMcpPayloadMaxLength = 64u * 1024u * 1024u;
    constexpr std::size_t kSseMaxQueuedEvents = 4096;
    constexpr DWORD kSseSessionMaxAgeMs = 60u * 60u * 1000u;
    std::atomic<std::uint64_t> g_http_request_seq{0};
    std::atomic<int> g_active_http_requests{0};
    std::atomic<std::uint64_t> g_mcp_batch_seq{0};
    std::atomic<std::uint64_t> g_tool_call_seq{0};
    std::atomic<std::uint64_t> g_stream_seq{0};
    std::atomic<int> g_active_streams{0};
    std::atomic<size_t> g_cached_external_tool_count{0};
    std::atomic<bool> g_cached_health_ready{false};
    thread_local std::uint64_t tls_http_request_id = 0;
    thread_local std::uint64_t tls_http_request_start_tick = 0;
    thread_local std::string tls_current_call_diag_id;
    thread_local std::string tls_current_call_tool_name;
    thread_local std::uint64_t tls_current_call_deadline_ms = 0;

    struct server_worker_lifetime_t {
        aida::infra::win_thread::joinable_thread_t thread;
        std::atomic<bool> queued_worker{false};
        std::mutex mtx;
        std::condition_variable cv;
        bool start_completed = false;
        bool start_succeeded = false;
    };

    std::mutex g_server_worker_lifetime_mtx;
    std::map<server_t*, std::shared_ptr<server_worker_lifetime_t>> g_server_worker_lifetimes;

    static std::shared_ptr<server_worker_lifetime_t> find_server_worker_lifetime(server_t* owner)
    {
        std::lock_guard<std::mutex> lk(g_server_worker_lifetime_mtx);
        auto it = g_server_worker_lifetimes.find(owner);
        return it == g_server_worker_lifetimes.end() ? nullptr : it->second;
    }

    static bool install_server_worker_lifetime(server_t* owner, const std::shared_ptr<server_worker_lifetime_t>& state)
    {
        std::lock_guard<std::mutex> lk(g_server_worker_lifetime_mtx);
        auto inserted = g_server_worker_lifetimes.emplace(owner, state);
        return inserted.second;
    }

    static void erase_server_worker_lifetime(server_t* owner, const std::shared_ptr<server_worker_lifetime_t>& state)
    {
        std::lock_guard<std::mutex> lk(g_server_worker_lifetime_mtx);
        auto it = g_server_worker_lifetimes.find(owner);
        if (it != g_server_worker_lifetimes.end() && it->second == state)
            g_server_worker_lifetimes.erase(it);
    }

    static void mark_server_worker_start(const std::shared_ptr<server_worker_lifetime_t>& state, bool succeeded)
    {
        if (!state)
            return;
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            state->start_succeeded = succeeded;
            state->start_completed = true;
        }
        state->cv.notify_all();
    }

    static bool wait_server_worker_start(const std::shared_ptr<server_worker_lifetime_t>& state)
    {
        if (!state)
            return false;
        std::unique_lock<std::mutex> lk(state->mtx);
        state->cv.wait(lk, [state]() { return state->start_completed; });
        return state->start_succeeded;
    }

    static std::uint64_t mcp_now_ms()
    {
        return static_cast<std::uint64_t>(GetTickCount64());
    }

    struct mcp_concurrency_config_t
    {
        std::size_t http_worker_threads = 16;
        std::size_t http_max_queued_requests = 4096;
        std::size_t batch_worker_threads = 8;
        std::size_t batch_max_queued_requests = 4096;
        std::size_t tool_worker_threads = 8;
        std::size_t tool_max_queued_requests = 4096;
        std::size_t max_concurrent_streams = 16;
        std::size_t hardware_threads = 16;
    };

    static std::size_t mcp_hardware_threads()
    {
        const unsigned n = std::thread::hardware_concurrency();
        return n == 0 ? std::size_t{16} : static_cast<std::size_t>(n);
    }

    static std::size_t clamp_size_value(std::uint64_t value, std::size_t min_value, std::size_t max_value)
    {
        if (max_value < min_value)
            max_value = min_value;
        if (value < static_cast<std::uint64_t>(min_value))
            return min_value;
        if (value > static_cast<std::uint64_t>(max_value))
            return max_value;
        return static_cast<std::size_t>(value);
    }

    static std::size_t scaled_worker_count(std::size_t floor_value, std::size_t per_core, std::size_t cap_value)
    {
        const std::size_t hw = mcp_hardware_threads();
        std::size_t scaled = cap_value;
        if (per_core != 0 && hw <= cap_value / per_core)
            scaled = hw * per_core;
        return clamp_size_value((std::max)(floor_value, scaled), floor_value, cap_value);
    }

    static std::size_t read_size_env_or_default(const char* name, std::size_t fallback, std::size_t min_value, std::size_t max_value)
    {
        if (!name || !name[0])
            return clamp_size_value(fallback, min_value, max_value);
        char buf[64] = {};
        const DWORD n = GetEnvironmentVariableA(name, buf, static_cast<DWORD>(sizeof(buf)));
        if (n == 0 || n >= static_cast<DWORD>(sizeof(buf)))
            return clamp_size_value(fallback, min_value, max_value);
        try {
            const std::uint64_t parsed = static_cast<std::uint64_t>(std::stoull(std::string(buf), nullptr, 0));
            return clamp_size_value(parsed, min_value, max_value);
        } catch (...) {
            return clamp_size_value(fallback, min_value, max_value);
        }
    }

    static mcp_concurrency_config_t build_mcp_concurrency_config()
    {
        mcp_concurrency_config_t cfg;
        cfg.hardware_threads = mcp_hardware_threads();
        cfg.http_worker_threads = read_size_env_or_default("AIDA_MCP_HTTP_WORKERS", scaled_worker_count(8, 2, 32), 1, 1024);
        cfg.http_max_queued_requests = read_size_env_or_default("AIDA_MCP_HTTP_QUEUE", 4096, 64, 262144);
        cfg.batch_worker_threads = read_size_env_or_default("AIDA_MCP_BATCH_WORKERS", scaled_worker_count(4, 1, 16), 1, 768);
        cfg.batch_max_queued_requests = read_size_env_or_default("AIDA_MCP_BATCH_QUEUE", 4096, 64, 262144);
        cfg.tool_worker_threads = read_size_env_or_default("AIDA_MCP_TOOL_WORKERS", scaled_worker_count(4, 1, 16), 1, 768);
        cfg.tool_max_queued_requests = read_size_env_or_default("AIDA_MCP_TOOL_QUEUE", 4096, 64, 262144);
        const std::size_t stream_cap = (std::max)(std::size_t{16}, (std::min)(std::size_t{512}, cfg.http_worker_threads));
        const std::size_t stream_floor = (std::min)(std::size_t{16}, stream_cap);
        const std::size_t stream_scaled = cfg.hardware_threads <= stream_cap / 2 ? cfg.hardware_threads * 2 : stream_cap;
        const std::size_t stream_fallback = clamp_size_value((std::max)(stream_floor, stream_scaled), 1, stream_cap);
        cfg.max_concurrent_streams = read_size_env_or_default("AIDA_MCP_MAX_STREAMS", stream_fallback, 1, stream_cap);
        return cfg;
    }

    static const mcp_concurrency_config_t& mcp_concurrency_config()
    {
        static const mcp_concurrency_config_t cfg = build_mcp_concurrency_config();
        return cfg;
    }

    static void log_work_queue_stats(const char* context)
    {
        const auto general = work_queue::stats();
        diag::log_tagged_fmt("mcp_srv",
            "%s work_queue alive=%d shutting_down=%d pool_size=%d workers=%zu pending=%zu active=%u post_attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu",
            context ? context : "work_queue",
            general.alive ? 1 : 0,
            general.shutting_down ? 1 : 0,
            general.pool_size,
            general.workers,
            general.pending,
            static_cast<unsigned>(general.active),
            static_cast<unsigned long long>(general.post_attempts),
            static_cast<unsigned long long>(general.posted),
            static_cast<unsigned long long>(general.rejected),
            static_cast<unsigned long long>(general.started),
            static_cast<unsigned long long>(general.finished));
        const auto st = critical_work_queue::stats();
        diag::log_tagged_fmt("mcp_srv",
            "%s critical_queue alive=%d shutting_down=%d pool_size=%d workers=%zu pending=%zu active=%u post_attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu",
            context ? context : "critical_queue",
            st.alive ? 1 : 0,
            st.shutting_down ? 1 : 0,
            st.pool_size,
            st.workers,
            st.pending,
            static_cast<unsigned>(st.active),
            static_cast<unsigned long long>(st.post_attempts),
            static_cast<unsigned long long>(st.posted),
            static_cast<unsigned long long>(st.rejected),
            static_cast<unsigned long long>(st.started),
            static_cast<unsigned long long>(st.finished));
        const auto svc = work_queue::service_stats();
        diag::log_tagged_fmt("mcp_srv",
            "%s service_queue alive=%d shutting_down=%d pool_size=%d workers=%zu pending=%zu active=%u post_attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu",
            context ? context : "service_queue",
            svc.alive ? 1 : 0,
            svc.shutting_down ? 1 : 0,
            svc.pool_size,
            svc.workers,
            svc.pending,
            static_cast<unsigned>(svc.active),
            static_cast<unsigned long long>(svc.post_attempts),
            static_cast<unsigned long long>(svc.posted),
            static_cast<unsigned long long>(svc.rejected),
            static_cast<unsigned long long>(svc.started),
            static_cast<unsigned long long>(svc.finished));
    }

    struct mcp_executor_task_meta_t
    {
        mutable std::mutex mtx;
        std::uint64_t executor_seq = 0;
        std::uint64_t queued_at = 0;
        std::uint64_t active_at = 0;
        std::uint64_t deadline_ms = 0;
        std::uint64_t queue_wait_ms = 0;
        DWORD worker_tid = 0;
        std::string request_id;
        std::string method;
        std::string tool;
        std::string domain;
        std::string lane;
        std::string payload_shape;
        std::string route;
        cancel_token_ptr_t cancel_token;
    };

    class mcp_owned_executor_t;

    std::mutex g_mcp_executor_registry_mtx;
    std::vector<mcp_owned_executor_t*> g_mcp_executor_registry;
    thread_local mcp_executor_task_meta_t* tls_executor_task_meta = nullptr;

    static void register_mcp_executor(mcp_owned_executor_t* executor)
    {
        std::lock_guard<std::mutex> lk(g_mcp_executor_registry_mtx);
        g_mcp_executor_registry.push_back(executor);
    }

    static void unregister_mcp_executor(mcp_owned_executor_t* executor)
    {
        std::lock_guard<std::mutex> lk(g_mcp_executor_registry_mtx);
        g_mcp_executor_registry.erase(
            std::remove(g_mcp_executor_registry.begin(), g_mcp_executor_registry.end(), executor),
            g_mcp_executor_registry.end());
    }

    static std::shared_ptr<mcp_executor_task_meta_t> make_executor_task_meta()
    {
        return std::make_shared<mcp_executor_task_meta_t>();
    }

    static void update_current_executor_task_http(std::uint64_t request_id, const std::string& method, const std::string& route)
    {
        auto* meta = tls_executor_task_meta;
        if (!meta)
            return;
        std::lock_guard<std::mutex> lk(meta->mtx);
        meta->request_id = std::to_string(request_id);
        meta->method = method;
        meta->route = route;
        if (meta->lane.empty())
            meta->lane = "http_request";
    }

    static void update_executor_task_lane(const std::shared_ptr<mcp_executor_task_meta_t>& meta, const std::string& lane)
    {
        if (!meta)
            return;
        std::lock_guard<std::mutex> lk(meta->mtx);
        meta->lane = lane;
    }

    class mcp_owned_executor_t
    {
    public:
        mcp_owned_executor_t(const char* name, std::size_t worker_count, std::size_t max_queued_requests)
            : _name(name ? name : "mcp_executor")
            , _worker_count(worker_count)
            , _max_queued_requests(max_queued_requests)
        {
            register_mcp_executor(this);
            diag::log_tagged_fmt("mcp_srv",
                "mcp_executor_config name=%s workers=%zu max_queue=%zu",
                _name.c_str(),
                _worker_count,
                _max_queued_requests);
            start_workers();
        }

        mcp_owned_executor_t(const mcp_owned_executor_t&) = delete;
        mcp_owned_executor_t& operator=(const mcp_owned_executor_t&) = delete;

        ~mcp_owned_executor_t()
        {
            shutdown();
            unregister_mcp_executor(this);
        }

        bool enqueue(std::function<void()> fn, std::shared_ptr<mcp_executor_task_meta_t> meta = nullptr)
        {
            if (!fn) {
                _rejected.fetch_add(1u, std::memory_order_acq_rel);
                return false;
            }

            task_t task;
            task.fn = std::move(fn);
            task.meta = meta ? std::move(meta) : make_executor_task_meta();
            const std::uint64_t queued_at = mcp_now_ms();
            const std::uint64_t seq = _enqueued.fetch_add(1u, std::memory_order_acq_rel) + 1u;
            {
                std::lock_guard<std::mutex> meta_lk(task.meta->mtx);
                task.meta->queued_at = queued_at;
                task.meta->executor_seq = seq;
            }

            {
                std::lock_guard<std::mutex> lk(_mtx);
                if (_shutdown.load(std::memory_order_acquire) || _workers.empty()) {
                    _rejected.fetch_add(1u, std::memory_order_acq_rel);
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_enqueue_rejected name=%s reason=%s workers=%zu queued=%zu active=%u",
                        _name.c_str(),
                        _shutdown.load(std::memory_order_acquire) ? "shutdown" : "no_workers",
                        _workers.size(),
                        _jobs.size(),
                        static_cast<unsigned>(_active.load(std::memory_order_acquire)));
                    return false;
                }
                if (_max_queued_requests > 0 && _jobs.size() >= _max_queued_requests) {
                    _rejected.fetch_add(1u, std::memory_order_acq_rel);
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_enqueue_rejected name=%s reason=full queued=%zu max=%zu active=%u",
                        _name.c_str(),
                        _jobs.size(),
                        _max_queued_requests,
                        static_cast<unsigned>(_active.load(std::memory_order_acquire)));
                    return false;
                }
                try {
                    _jobs.push(std::move(task));
                } catch (...) {
                    _rejected.fetch_add(1u, std::memory_order_acq_rel);
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_enqueue_rejected name=%s reason=exception queued=%zu active=%u",
                        _name.c_str(),
                        _jobs.size(),
                        static_cast<unsigned>(_active.load(std::memory_order_acquire)));
                    return false;
                }
            }
            _cv.notify_one();
            return true;
        }

        json snapshot_json()
        {
            const std::uint64_t now = mcp_now_ms();
            std::vector<std::shared_ptr<mcp_executor_task_meta_t>> active_tasks;
            std::size_t queued = 0;
            std::size_t workers = 0;
            {
                std::lock_guard<std::mutex> lk(_mtx);
                queued = _jobs.size();
                workers = _workers.size();
                active_tasks = _active_tasks;
            }

            json active = json::array();
            for (const auto& meta : active_tasks) {
                if (!meta)
                    continue;
                json item;
                {
                    std::lock_guard<std::mutex> lk(meta->mtx);
                    item["executor_seq"] = meta->executor_seq;
                    item["request_id"] = meta->request_id;
                    item["method"] = meta->method;
                    item["tool"] = meta->tool;
                    item["domain"] = meta->domain;
                    item["lane"] = meta->lane;
                    item["route"] = meta->route;
                    item["worker_tid"] = static_cast<std::uint32_t>(meta->worker_tid);
                    item["queued_age_ms"] = meta->queued_at != 0 && now >= meta->queued_at ? now - meta->queued_at : 0;
                    item["active_age_ms"] = meta->active_at != 0 && now >= meta->active_at ? now - meta->active_at : 0;
                    item["deadline_ms"] = meta->deadline_ms;
                    item["deadline_remaining_ms"] = meta->deadline_ms != 0 && now < meta->deadline_ms ? meta->deadline_ms - now : 0;
                    item["cancelled"] = meta->cancel_token && meta->cancel_token->load(std::memory_order_acquire);
                    if (!meta->payload_shape.empty())
                        item["payload_shape"] = meta->payload_shape;
                }
                active.push_back(std::move(item));
            }

            json out;
            out["name"] = _name;
            out["workers"] = workers;
            out["max_queue"] = _max_queued_requests;
            out["queued"] = queued;
            out["active"] = _active.load(std::memory_order_acquire);
            out["enqueued"] = _enqueued.load(std::memory_order_acquire);
            out["started"] = _started.load(std::memory_order_acquire);
            out["finished"] = _finished.load(std::memory_order_acquire);
            out["rejected"] = _rejected.load(std::memory_order_acquire);
            out["worker_failures"] = _worker_failures.load(std::memory_order_acquire);
            out["tls_failures"] = _tls_failures.load(std::memory_order_acquire);
            out["active_tasks"] = std::move(active);
            return out;
        }

        void shutdown()
        {
            bool expected = false;
            if (!_shutdown.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
                return;

            const std::uint64_t begin = mcp_now_ms();
            std::vector<aida::infra::win_thread::joinable_thread_t> workers;
            std::vector<unsigned> worker_ids;
            std::size_t queued = 0;
            {
                std::lock_guard<std::mutex> lk(_mtx);
                queued = _jobs.size();
                worker_ids.reserve(_workers.size());
                for (const auto& worker : _workers)
                    worker_ids.push_back(worker.id());
                workers = std::move(_workers);
                _workers.clear();
            }
            diag::log_tagged_fmt("mcp_srv",
                "mcp_executor_shutdown_begin name=%s workers=%zu queued=%zu active=%u enqueued=%llu finished=%llu rejected=%llu",
                _name.c_str(),
                workers.size(),
                queued,
                static_cast<unsigned>(_active.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(_enqueued.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(_finished.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(_rejected.load(std::memory_order_acquire)));
            _cv.notify_all();

            const DWORD current_tid = GetCurrentThreadId();
            for (std::size_t i = 0; i < workers.size(); ++i) {
                auto& worker = workers[i];
                const unsigned tid = i < worker_ids.size() ? worker_ids[i] : worker.id();
                if (!worker.joinable())
                    continue;
                if (tid == current_tid) {
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_shutdown_self_join_skipped name=%s worker_index=%zu tid=%u",
                        _name.c_str(),
                        i,
                        tid);
                    worker.detach();
                    continue;
                }
                if (!worker.join_for(10000)) {
                    std::size_t remaining_queued = 0;
                    {
                        std::lock_guard<std::mutex> lk(_mtx);
                        remaining_queued = _jobs.size();
                    }
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_shutdown_join_timeout name=%s worker_index=%zu tid=%u elapsed_ms=%llu queued=%zu active=%u finished=%llu",
                        _name.c_str(),
                        i,
                        tid,
                        static_cast<unsigned long long>(mcp_now_ms() - begin),
                        remaining_queued,
                        static_cast<unsigned>(_active.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(_finished.load(std::memory_order_acquire)));
                    worker.detach();
                }
            }

            diag::log_tagged_fmt("mcp_srv",
                "mcp_executor_shutdown_done name=%s elapsed_ms=%llu enqueued=%llu started=%llu finished=%llu rejected=%llu tls_failures=%llu",
                _name.c_str(),
                static_cast<unsigned long long>(mcp_now_ms() - begin),
                static_cast<unsigned long long>(_enqueued.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(_started.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(_finished.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(_rejected.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(_tls_failures.load(std::memory_order_acquire)));
        }

    private:
        struct task_t {
            std::function<void()> fn;
            std::shared_ptr<mcp_executor_task_meta_t> meta;
        };

        void start_workers()
        {
            std::lock_guard<std::mutex> lk(_mtx);
            _workers.reserve(_worker_count);
            _active_tasks.resize(_worker_count);
            for (std::size_t i = 0; i < _worker_count; ++i) {
                aida::infra::win_thread::joinable_thread_t worker;
                std::string err;
                const bool started = worker.start([this, i]() {
                    worker_loop(i);
                }, &err, aida::infra::win_thread::default_stack_reserve, _name.c_str());
                if (started) {
                    _workers.emplace_back(std::move(worker));
                    continue;
                }
                _worker_failures.fetch_add(1u, std::memory_order_acq_rel);
                diag::log_tagged_fmt("mcp_srv",
                    "mcp_executor_worker_start_failed name=%s worker_index=%zu err='%s'",
                    _name.c_str(),
                    i,
                    err.empty() ? "<none>" : err.c_str());
            }
            diag::log_tagged_fmt("mcp_srv",
                "mcp_executor_workers_ready name=%s requested=%zu active_workers=%zu failures=%llu",
                _name.c_str(),
                _worker_count,
                _workers.size(),
                static_cast<unsigned long long>(_worker_failures.load(std::memory_order_acquire)));
        }

        void worker_loop(std::size_t worker_index)
        {
            bool thread_tls_ready = aida::manual_map_tls::ensure_current_thread();
            if (!thread_tls_ready) {
                _tls_failures.fetch_add(1u, std::memory_order_acq_rel);
                diag::log_tagged_fmt("mcp_srv",
                    "mcp_executor_tls_unavailable name=%s phase=worker_start worker_index=%zu tid=%lu",
                    _name.c_str(),
                    worker_index,
                    static_cast<unsigned long>(GetCurrentThreadId()));
            }

            for (;;) {
                task_t task;
                std::size_t queued_after_pop = 0;
                {
                    std::unique_lock<std::mutex> lk(_mtx);
                    _cv.wait(lk, [this]() {
                        return _shutdown.load(std::memory_order_acquire) || !_jobs.empty();
                    });
                    if (_shutdown.load(std::memory_order_acquire) && _jobs.empty())
                        break;
                    task = std::move(_jobs.front());
                    _jobs.pop();
                    queued_after_pop = _jobs.size();
                }

                if (!task.meta)
                    task.meta = make_executor_task_meta();
                _active.fetch_add(1u, std::memory_order_acq_rel);
                _started.fetch_add(1u, std::memory_order_acq_rel);
                const std::uint64_t now = mcp_now_ms();
                std::uint64_t wait_ms = 0;
                std::uint64_t seq = 0;
                std::string method;
                std::string tool;
                std::string lane;
                {
                    std::lock_guard<std::mutex> meta_lk(task.meta->mtx);
                    wait_ms = task.meta->queued_at != 0 && now >= task.meta->queued_at ? now - task.meta->queued_at : 0;
                    task.meta->queue_wait_ms = wait_ms;
                    task.meta->active_at = now;
                    task.meta->worker_tid = GetCurrentThreadId();
                    seq = task.meta->executor_seq;
                    method = task.meta->method;
                    tool = task.meta->tool;
                    lane = task.meta->lane;
                }
                {
                    std::lock_guard<std::mutex> lk(_mtx);
                    if (worker_index < _active_tasks.size())
                        _active_tasks[worker_index] = task.meta;
                }
                if (wait_ms > 100) {
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_dispatch_delay name=%s worker_index=%zu seq=%llu wait_ms=%llu queued=%zu active=%u method='%s' tool='%s' lane='%s'",
                        _name.c_str(),
                        worker_index,
                        static_cast<unsigned long long>(seq),
                        static_cast<unsigned long long>(wait_ms),
                        queued_after_pop,
                        static_cast<unsigned>(_active.load(std::memory_order_acquire)),
                        method.c_str(),
                        tool.c_str(),
                        lane.c_str());
                }

                const bool task_tls_ready = aida::manual_map_tls::ensure_current_thread();
                if (!task_tls_ready) {
                    _tls_failures.fetch_add(1u, std::memory_order_acq_rel);
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_tls_unavailable name=%s phase=task_start worker_index=%zu seq=%llu tid=%lu",
                        _name.c_str(),
                        worker_index,
                        static_cast<unsigned long long>(seq),
                        static_cast<unsigned long>(GetCurrentThreadId()));
                }

                tls_executor_task_meta = task.meta.get();
                DWORD task_seh = 0;
                try {
                    task_seh = aida::infra::win_thread::run_function_seh_guarded(task.fn);
                } catch (const std::exception& ex) {
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_task_exception name=%s worker_index=%zu seq=%llu err='%s'",
                        _name.c_str(),
                        worker_index,
                        static_cast<unsigned long long>(seq),
                        ex.what());
                } catch (...) {
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_task_exception name=%s worker_index=%zu seq=%llu err='<unknown>'",
                        _name.c_str(),
                        worker_index,
                        static_cast<unsigned long long>(seq));
                }
                if (task_seh != 0) {
                    const std::uint64_t task_now = mcp_now_ms();
                    std::uint64_t active_age_ms = 0;
                    std::uint64_t deadline_snapshot = 0;
                    {
                        std::lock_guard<std::mutex> meta_lk(task.meta->mtx);
                        active_age_ms = task.meta->active_at != 0 && task_now >= task.meta->active_at ? task_now - task.meta->active_at : 0;
                        deadline_snapshot = task.meta->deadline_ms;
                        method = task.meta->method;
                        tool = task.meta->tool;
                        lane = task.meta->lane;
                    }
                    diag::log_tagged_fmt("mcp_srv",
                        "mcp_executor_task_seh name=%s worker_index=%zu seq=%llu tid=%lu code=0x%08lX active_age_ms=%llu queued_after_pop=%zu active=%u started=%llu finished=%llu method='%s' tool='%s' lane='%s' deadline_ms=%llu shutdown=%d",
                        _name.c_str(),
                        worker_index,
                        static_cast<unsigned long long>(seq),
                        static_cast<unsigned long>(GetCurrentThreadId()),
                        static_cast<unsigned long>(task_seh),
                        static_cast<unsigned long long>(active_age_ms),
                        queued_after_pop,
                        static_cast<unsigned>(_active.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(_started.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(_finished.load(std::memory_order_acquire)),
                        method.c_str(),
                        tool.c_str(),
                        lane.c_str(),
                        static_cast<unsigned long long>(deadline_snapshot),
                        _shutdown.load(std::memory_order_acquire) ? 1 : 0);
                }
                tls_executor_task_meta = nullptr;
                {
                    std::lock_guard<std::mutex> lk(_mtx);
                    if (worker_index < _active_tasks.size())
                        _active_tasks[worker_index].reset();
                }
                _finished.fetch_add(1u, std::memory_order_acq_rel);
                _active.fetch_sub(1u, std::memory_order_acq_rel);
            }
        }

        const std::string _name;
        const std::size_t _worker_count;
        const std::size_t _max_queued_requests;
        std::vector<aida::infra::win_thread::joinable_thread_t> _workers;
        std::queue<task_t> _jobs;
        std::vector<std::shared_ptr<mcp_executor_task_meta_t>> _active_tasks;
        std::mutex _mtx;
        std::condition_variable _cv;
        std::atomic<bool> _shutdown{false};
        std::atomic<std::uint32_t> _active{0};
        std::atomic<std::uint64_t> _enqueued{0};
        std::atomic<std::uint64_t> _rejected{0};
        std::atomic<std::uint64_t> _started{0};
        std::atomic<std::uint64_t> _finished{0};
        std::atomic<std::uint64_t> _worker_failures{0};
        std::atomic<std::uint64_t> _tls_failures{0};
    };

    static json mcp_executor_health_snapshot()
    {
        std::vector<mcp_owned_executor_t*> executors;
        {
            std::lock_guard<std::mutex> lk(g_mcp_executor_registry_mtx);
            executors = g_mcp_executor_registry;
        }
        json arr = json::array();
        for (auto* executor : executors) {
            if (executor)
                arr.push_back(executor->snapshot_json());
        }
        return arr;
    }

    class mcp_request_task_queue final : public httplib::TaskQueue
    {
    public:
        mcp_request_task_queue()
            : _executor("mcp_http_requests", mcp_concurrency_config().http_worker_threads, mcp_concurrency_config().http_max_queued_requests)
        {
        }

        bool enqueue(std::function<void()> fn) override
        {
            return _executor.enqueue(std::move(fn));
        }

        void shutdown() override
        {
            _executor.shutdown();
        }

    private:
        mcp_owned_executor_t _executor;
    };

    static mcp_owned_executor_t& mcp_batch_executor()
    {
        static mcp_owned_executor_t executor("mcp_jsonrpc_batch", mcp_concurrency_config().batch_worker_threads, mcp_concurrency_config().batch_max_queued_requests);
        return executor;
    }

    static mcp_owned_executor_t& mcp_tool_executor()
    {
        static mcp_owned_executor_t executor("mcp_tool_calls", mcp_concurrency_config().tool_worker_threads, mcp_concurrency_config().tool_max_queued_requests);
        return executor;
    }

    static std::string normalized_domain_key(const std::string& domain)
    {
        return domain.empty() ? std::string("misc") : domain;
    }

    static bool is_exclusive_domain_lane(const std::string& lane)
    {
        return lane.rfind("exclusive_domain_", 0) == 0;
    }

    static mcp_owned_executor_t& mcp_domain_tool_executor(const std::string& domain)
    {
        static std::mutex mtx;
        static std::map<std::string, std::shared_ptr<mcp_owned_executor_t>> executors;
        const std::string key = normalized_domain_key(domain);
        std::lock_guard<std::mutex> lk(mtx);
        auto it = executors.find(key);
        if (it != executors.end() && it->second)
            return *it->second;
        const std::string name = "mcp_domain_" + key;
        auto executor = std::make_shared<mcp_owned_executor_t>(name.c_str(), 1, mcp_concurrency_config().tool_max_queued_requests);
        auto* ptr = executor.get();
        executors.emplace(key, std::move(executor));
        return *ptr;
    }

    static std::string remote_endpoint(const httplib::Request& req)
    {
        std::string endpoint = req.remote_addr.empty() ? "<unknown>" : req.remote_addr;
        endpoint += ":";
        endpoint += std::to_string(req.remote_port);
        return endpoint;
    }

    static bool request_connection_closed(const httplib::Request& req)
    {
        try {
            return req.is_connection_closed ? req.is_connection_closed() : false;
        } catch (...) {
            return false;
        }
    }

    static bool connection_closed_now(const std::function<bool()>& fn)
    {
        try {
            return fn ? fn() : false;
        } catch (...) {
            return false;
        }
    }

    struct mcp_stream_state_t
    {
        std::uint64_t id = 0;
        const char* route = "";
        std::string remote;
        std::uint64_t opened_tick = 0;
        std::atomic<bool> released{false};
        std::atomic<bool> done_called{false};
    };

    static std::shared_ptr<mcp_stream_state_t> acquire_stream_slot(const char* route, const httplib::Request& req, httplib::Response& res)
    {
        const int max_streams = static_cast<int>(mcp_concurrency_config().max_concurrent_streams);
        int cur = g_active_streams.load(std::memory_order_acquire);
        while (cur < max_streams) {
            if (g_active_streams.compare_exchange_weak(cur, cur + 1, std::memory_order_acq_rel, std::memory_order_acquire)) {
                auto state = std::make_shared<mcp_stream_state_t>();
                state->id = g_stream_seq.fetch_add(1, std::memory_order_acq_rel) + 1;
                state->route = route ? route : "<unknown>";
                state->remote = remote_endpoint(req);
                state->opened_tick = mcp_now_ms();
                diag::log_tagged_fmt("mcp_srv",
                    "stream_open id=%llu route=%s remote=%s pid=%lu tid=%lu active_streams=%d active_requests=%d",
                    static_cast<unsigned long long>(state->id),
                    state->route,
                    state->remote.c_str(),
                    static_cast<unsigned long>(GetCurrentProcessId()),
                    static_cast<unsigned long>(GetCurrentThreadId()),
                    cur + 1,
                    g_active_http_requests.load(std::memory_order_acquire));
                return state;
            }
        }

        diag::log_tagged_fmt("mcp_srv",
            "stream_reject route=%s remote=%s pid=%lu tid=%lu active_streams=%d max_streams=%d active_requests=%d",
            route ? route : "<unknown>",
            remote_endpoint(req).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            cur,
            max_streams,
            g_active_http_requests.load(std::memory_order_acquire));
        res.status = 503;
        res.set_header("Retry-After", "2");
        res.set_content("{\"error\":\"mcp stream capacity exhausted\"}", "application/json");
        return {};
    }

    static void release_stream_slot(const std::shared_ptr<mcp_stream_state_t>& state, bool success, const char* reason)
    {
        if (!state)
            return;
        if (state->released.exchange(true, std::memory_order_acq_rel))
            return;
        const std::uint64_t now = mcp_now_ms();
        const std::uint64_t elapsed = now >= state->opened_tick ? now - state->opened_tick : 0;
        int active_after = g_active_streams.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (active_after < 0) {
            g_active_streams.store(0, std::memory_order_release);
            active_after = 0;
        }
        diag::log_tagged_fmt("mcp_srv",
            "stream_close id=%llu route=%s remote=%s success=%d reason=%s elapsed_ms=%llu pid=%lu tid=%lu active_streams=%d active_requests=%d",
            static_cast<unsigned long long>(state->id),
            state->route ? state->route : "<unknown>",
            state->remote.c_str(),
            success ? 1 : 0,
            reason ? reason : "",
            static_cast<unsigned long long>(elapsed),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            active_after,
            g_active_http_requests.load(std::memory_order_acquire));
    }

    static void finish_stream_cleanly(mcp_stream_state_t* state, httplib::DataSink& sink, const char* reason)
    {
        if (!state || state->done_called.exchange(true, std::memory_order_acq_rel))
            return;
        diag::log_tagged_fmt("mcp_srv",
            "stream_done id=%llu route=%s reason=%s remote=%s pid=%lu tid=%lu",
            static_cast<unsigned long long>(state->id),
            state->route ? state->route : "<unknown>",
            reason ? reason : "",
            state->remote.c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        if (sink.done)
            sink.done();
    }

    static void finish_stream_cleanly(const std::shared_ptr<mcp_stream_state_t>& state, httplib::DataSink& sink, const char* reason)
    {
        finish_stream_cleanly(state.get(), sink, reason);
    }
}

static std::string json_dump_safe(const json& j, int indent = -1)
{
    try { return j.dump(indent); }
    catch (...) { return "{}"; }
}

struct mcp_auth_snapshot_t
{
    bool ide_ready = false;
    bool posture_trusted = false;
    bool license_valid = false;
    bool arc_loaded = false;
    bool arc_loading = false;
    bool arc_transfer = false;
    bool exports_ok = false;
    bool driver_loaded = false;
    bool driver_kernel = false;
    bool driver_available = false;
    std::string missing_exports;
    std::string driver_reason;
};

static mcp_auth_snapshot_t capture_mcp_auth_snapshot(bool include_driver)
{
    mcp_auth_snapshot_t snap{};
    snap.ide_ready = g_ide_lifecycle_ready.load(std::memory_order_acquire);
    snap.posture_trusted = anti_tamper::mcp_posture::is_current_posture_trusted();
    snap.license_valid = standalone_license::is_valid();
    snap.arc_loaded = standalone_license::is_arc_loaded();
    snap.arc_loading = standalone_license::is_arc_download_in_progress();
    snap.arc_transfer = standalone_license::is_arc_transfer_in_progress();
    if (snap.arc_loaded)
        snap.exports_ok = standalone_license::validate_arc_required_exports(snap.missing_exports);
    else
        snap.missing_exports = "arc_not_loaded";
    if (include_driver) {
        snap.driver_loaded = driver_bridge::is_loaded();
        snap.driver_kernel = driver_bridge::using_kernel_driver();
        snap.driver_available = driver_bridge::kernel_session_available(&snap.driver_reason);
    }
    return snap;
}

[[noreturn]] static void mcp_auth_fastfail(const char* where)
{
    const mcp_auth_snapshot_t snap = capture_mcp_auth_snapshot(true);
    diag::log_tagged_fmt("mcp_srv",
        "auth_fastfail where=%s ide=%d posture=%d valid=%d arc=%d loading=%d transfer=%d exports=%d missing='%.160s' driver_loaded=%d driver_kernel=%d driver_available=%d driver_reason='%.160s'",
        where ? where : "<null>",
        snap.ide_ready ? 1 : 0,
        snap.posture_trusted ? 1 : 0,
        snap.license_valid ? 1 : 0,
        snap.arc_loaded ? 1 : 0,
        snap.arc_loading ? 1 : 0,
        snap.arc_transfer ? 1 : 0,
        snap.exports_ok ? 1 : 0,
        snap.missing_exports.c_str(),
        snap.driver_loaded ? 1 : 0,
        snap.driver_kernel ? 1 : 0,
        snap.driver_available ? 1 : 0,
        snap.driver_reason.c_str());
    __fastfail(0xA1DA4D43u);
}

static bool mcp_runtime_authorized()
{
    const mcp_auth_snapshot_t snap = capture_mcp_auth_snapshot(false);
    return snap.ide_ready &&
           snap.posture_trusted &&
           snap.license_valid &&
           snap.arc_loaded &&
           snap.exports_ok;
}

static void require_mcp_runtime_authorized(const char* where)
{
    if (!mcp_runtime_authorized())
        mcp_auth_fastfail(where);
}

void set_ide_lifecycle_ready(bool ready) noexcept
{
    g_ide_lifecycle_ready.store(ready, std::memory_order_release);
}

bool lifecycle_authorized(std::string* reason)
{
    const mcp_auth_snapshot_t snap = capture_mcp_auth_snapshot(false);
    if (!snap.ide_ready) {
        if (reason) *reason = "ide_not_ready";
        return false;
    }
    if (!snap.license_valid) {
        if (reason) *reason = "license_invalid";
        return false;
    }
    if (!snap.arc_loaded) {
        if (reason)
            *reason = snap.arc_loading ? "arc_loading" : "arc_not_loaded";
        return false;
    }
    if (!snap.exports_ok) {
        if (reason) *reason = snap.missing_exports.empty() ? "arc_exports_missing" : ("arc_exports_missing:" + snap.missing_exports);
        return false;
    }
    if (reason) *reason = "authorized";
    return true;
}

static std::string generate_session_id()
{

    unsigned char rnd[16] = {};
    NTSTATUS st = BCryptGenRandom(nullptr, rnd, sizeof(rnd),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) {

        auto t = std::chrono::steady_clock::now().time_since_epoch().count();
        for (size_t i = 0; i < sizeof(rnd); ++i)
            rnd[i] = static_cast<unsigned char>((t >> (i * 8)) ^ i);
    }
    char buf[48];
    snprintf(buf, sizeof(buf),
             "sa-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7],
             rnd[8], rnd[9], rnd[10], rnd[11], rnd[12], rnd[13], rnd[14], rnd[15]);
    return buf;
}

static std::string read_env_var(const char* name)
{
    char* value = nullptr;
    size_t len = 0;
    if (_dupenv_s(&value, &len, name) != 0 || !value)
        return {};
    std::string result(value);
    free(value);
    return result;
}

static std::string sanitize_utf8(const std::string& input)
{
    std::string result;
    result.reserve(input.size());
    for (size_t i = 0; i < input.size(); )
    {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c < 0x80) {
            result += static_cast<char>(c);
            ++i;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < input.size()) {
            result += input[i]; result += input[i+1]; i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < input.size()) {
            result += input[i]; result += input[i+1]; result += input[i+2]; i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < input.size()) {
            result += input[i]; result += input[i+1]; result += input[i+2]; result += input[i+3]; i += 4;
        } else {
            result += "\xEF\xBF\xBD";
            ++i;
        }
    }
    return result;
}

static std::string snake_to_title(const std::string& name)
{
    std::string result;
    bool cap = true;
    for (char c : name) {
        if (c == '_') {
            result += ' ';
            cap = true;
        } else {
            result += cap ? static_cast<char>(toupper(c)) : c;
            cap = false;
        }
    }
    return result;
}

static std::string lower_ascii(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

static bool json_bool_param(const json& params, const char* name)
{
    if (!params.is_object() || !params.contains(name))
        return false;
    const auto& value = params[name];
    if (value.is_boolean())
        return value.get<bool>();
    if (value.is_string()) {
        const std::string v = lower_ascii(value.get<std::string>());
        return v == "1" || v == "true" || v == "yes" || v == "full";
    }
    return false;
}

static bool wants_full_tool_list(const json& params)
{
    if (!params.is_object())
        return false;
    if (json_bool_param(params, "full") ||
        json_bool_param(params, "includeDescriptions") ||
        json_bool_param(params, "include_descriptions") ||
        json_bool_param(params, "includeSchema") ||
        json_bool_param(params, "include_schema")) {
        return true;
    }
    if (params.contains("detail") && params["detail"].is_string()) {
        const std::string detail = lower_ascii(params["detail"].get<std::string>());
        return detail == "full" || detail == "description" ||
               detail == "descriptions" || detail == "schema" ||
               detail == "schemas";
    }
    return false;
}

static bool schema_enum_char(unsigned char c)
{
    return std::isalnum(c) || c == '_' || c == '-' || c == '|';
}

static std::string trim_schema_token(std::string token)
{
    while (!token.empty() && !schema_enum_char(static_cast<unsigned char>(token.front())))
        token.erase(token.begin());
    while (!token.empty() && !schema_enum_char(static_cast<unsigned char>(token.back())))
        token.pop_back();
    return token;
}

static json enum_values_from_description(const std::string& description)
{
    json out = json::array();
    const size_t pipe = description.find('|');
    if (pipe == std::string::npos)
        return out;

    size_t start = pipe;
    while (start > 0 && schema_enum_char(static_cast<unsigned char>(description[start - 1])))
        --start;
    size_t end = pipe + 1;
    while (end < description.size() && schema_enum_char(static_cast<unsigned char>(description[end])))
        ++end;

    std::string segment = description.substr(start, end - start);
    std::vector<std::string> values;
    size_t cursor = 0;
    while (cursor <= segment.size()) {
        const size_t next = segment.find('|', cursor);
        std::string token = trim_schema_token(segment.substr(cursor, next == std::string::npos ? std::string::npos : next - cursor));
        if (token.empty() || token.size() > 64)
            return json::array();
        values.push_back(std::move(token));
        if (next == std::string::npos)
            break;
        cursor = next + 1;
    }

    if (values.size() < 2 || values.size() > 64)
        return json::array();
    for (const auto& value : values)
        out.push_back(value);
    return out;
}

static json build_input_schema(const tool_def_t& tool)
{
    json input_schema;
    input_schema["type"] = "object";
    json properties = json::object();
    json required_arr = json::array();

    for (const auto& p : tool.params) {
        json desc;
        desc["description"] = p.description;
        if (p.type.find('|') != std::string::npos) {
            json one_of = json::array();
            size_t start = 0;
            while (start <= p.type.size()) {
                size_t end = p.type.find('|', start);
                if (end == std::string::npos)
                    end = p.type.size();
                std::string type_name = p.type.substr(start, end - start);
                if (!type_name.empty())
                    one_of.push_back(json{{"type", type_name}});
                if (end == p.type.size())
                    break;
                start = end + 1;
            }
            desc["oneOf"] = std::move(one_of);
        } else {
            desc["type"] = p.type;
        }
        json enum_values = enum_values_from_description(p.description);
        if (!enum_values.empty())
            desc["enum"] = std::move(enum_values);
        properties[p.name] = desc;
        if (p.required)
            required_arr.push_back(p.name);
    }

    input_schema["properties"] = properties;
    if (!required_arr.empty())
        input_schema["required"] = required_arr;
    return input_schema;
}

static const char* visibility_name(tool_visibility_t visibility)
{
    switch (visibility) {
    case tool_visibility_t::external_visible:
        return "external_visible";
    case tool_visibility_t::internal_only:
        return "internal_only";
    case tool_visibility_t::ide_chat_only:
        return "ide_chat_only";
    default:
        return "unknown";
    }
}

static bool is_camoufox_browser_tool_name(const std::string& name);

static std::string infer_tool_domain(const std::string& name)
{
    if (name.rfind("browser_", 0) == 0)
        return "browser";
    if (name == "burp_scanner_manage")
        return "scanner";
    if (name.rfind("burp_", 0) == 0)
        return "burp";
    if (name.rfind("network_", 0) == 0)
        return "network";
    if (name.rfind("net_security_", 0) == 0)
        return "network_security";
    if (name.rfind("net_proto_", 0) == 0)
        return "network_protocol";
    const size_t underscore = name.find('_');
    if (underscore == std::string::npos || underscore == 0)
        return {};
    return name.substr(0, underscore);
}

static bool tool_group_noise_token(const std::string& token)
{
    static const char* const noise[] = {
        "aida", "aidastandalone", "all", "complete", "description", "descriptions",
        "every", "full", "group", "groups", "mcp", "pack", "packs", "schema",
        "schemas", "standalone", "tool", "tools"
    };
    for (const char* n : noise) {
        if (token == n)
            return true;
    }
    return false;
}

static std::string normalize_tool_group_name(const std::string& text)
{
    std::string lowered = lower_ascii(text);
    std::vector<std::string> tokens;
    std::string current;
    for (char c : lowered) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (std::isalnum(uc)) {
            current.push_back(static_cast<char>(uc));
        } else {
            if (!current.empty()) {
                if (!tool_group_noise_token(current))
                    tokens.push_back(current);
                current.clear();
            }
        }
    }
    if (!current.empty() && !tool_group_noise_token(current))
        tokens.push_back(current);

    if (tokens.size() == 1) {
        const std::string& token = tokens[0];
        if (token == "browser" || token == "browsers" || token == "camoufox")
            return "browser";
        if (token == "network" || token == "networks" || token == "networking")
            return "network";
        if (token == "burp" || token == "burpsuite")
            return "burp";
    }
    if (tokens.size() == 2 && tokens[0] == "burp" && tokens[1] == "suite")
        return "burp";
    return {};
}

static bool tool_matches_description_group(const tool_def_t& tool, const std::string& group)
{
    const std::string name_l = lower_ascii(tool.name);
    const std::string desc_l = lower_ascii(tool.description);
    const std::string domain = infer_tool_domain(tool.name);

    if (group == "browser") {
        return domain == "browser" ||
               is_camoufox_browser_tool_name(tool.name) ||
               name_l.find("browser") != std::string::npos ||
               name_l.find("camoufox") != std::string::npos ||
               desc_l.find("browser") != std::string::npos ||
               desc_l.find("camoufox") != std::string::npos;
    }
    if (group == "network") {
        return domain == "network" ||
               domain == "network_security" ||
               domain == "network_protocol" ||
               name_l.rfind("network_", 0) == 0 ||
               name_l.rfind("net_security_", 0) == 0 ||
               name_l.rfind("net_proto_", 0) == 0 ||
               name_l.find("_network") != std::string::npos;
    }
    if (group == "burp") {
        return domain == "burp" ||
               tool.name == "burp_scanner_manage" ||
               name_l.rfind("burp_", 0) == 0 ||
               desc_l.find("burp") != std::string::npos;
    }
    return false;
}

static const char* json_type_label(const json& value)
{
    if (value.is_object()) return "object";
    if (value.is_array()) return "array";
    if (value.is_string()) return "string";
    if (value.is_boolean()) return "boolean";
    if (value.is_number_integer()) return "integer";
    if (value.is_number_unsigned()) return "unsigned";
    if (value.is_number_float()) return "float";
    if (value.is_null()) return "null";
    return "unknown";
}

static std::string payload_shape_summary(const json& value)
{
    std::ostringstream oss;
    if (!value.is_object()) {
        oss << json_type_label(value);
        if (value.is_array())
            oss << "[len=" << value.size() << "]";
        if (value.is_string())
            oss << "[chars=" << value.get_ref<const std::string&>().size() << "]";
        return oss.str();
    }
    oss << "object[keys=" << value.size() << "]";
    std::size_t emitted = 0;
    for (auto it = value.begin(); it != value.end() && emitted < 16; ++it, ++emitted) {
        oss << (emitted == 0 ? ":" : ",") << it.key() << "=" << json_type_label(it.value());
        if (it.value().is_array())
            oss << "[" << it.value().size() << "]";
        else if (it.value().is_object())
            oss << "{" << it.value().size() << "}";
        else if (it.value().is_string())
            oss << "(" << it.value().get_ref<const std::string&>().size() << ")";
    }
    if (value.size() > emitted)
        oss << ",...";
    std::string out = oss.str();
    if (out.size() > 384)
        out.resize(384);
    return out;
}

static std::string request_id_string(const json& id)
{
    if (id.is_null())
        return "null";
    if (id.is_string())
        return id.get<std::string>();
    if (id.is_number_integer())
        return std::to_string(id.get<std::int64_t>());
    if (id.is_number_unsigned())
        return std::to_string(id.get<std::uint64_t>());
    std::string dumped = json_dump_safe(id);
    if (dumped.size() > 160)
        dumped.resize(160);
    return dumped;
}

static std::uint32_t target_pid_from_args(const json& args)
{
    if (!args.is_object())
        return 0;
    for (const char* key : {"target_pid", "process_id", "pid"}) {
        if (!args.contains(key))
            continue;
        const auto& v = args[key];
        try {
            if (v.is_number_unsigned())
                return static_cast<std::uint32_t>(v.get<std::uint64_t>());
            if (v.is_number_integer()) {
                const auto s = v.get<std::int64_t>();
                return s > 0 ? static_cast<std::uint32_t>(s) : 0;
            }
            if (v.is_string()) {
                const std::string s = v.get<std::string>();
                if (!s.empty())
                    return static_cast<std::uint32_t>(std::stoul(s, nullptr, 0));
            }
        } catch (...) {
            return 0;
        }
    }
    return 0;
}

struct tool_timeout_resolution_t
{
    std::uint64_t requested_ms = kMcpDefaultToolTimeoutMs;
    std::uint64_t effective_ms = kMcpDefaultToolTimeoutMs;
    std::uint64_t default_ms = kMcpDefaultToolTimeoutMs;
    std::uint64_t max_ms = kMcpMaxToolTimeoutMs;
    bool explicit_timeout = false;
    bool action_aware = false;
    std::string action;
    std::string source = "default";
};

static bool json_positive_u64(const json& v, std::uint64_t& out)
{
    try {
        if (v.is_number_unsigned()) {
            const auto n = v.get<std::uint64_t>();
            if (n > 0) {
                out = n;
                return true;
            }
        } else if (v.is_number_integer()) {
            const auto n = v.get<std::int64_t>();
            if (n > 0) {
                out = static_cast<std::uint64_t>(n);
                return true;
            }
        } else if (v.is_string()) {
            const std::string s = v.get<std::string>();
            if (!s.empty()) {
                const auto n = static_cast<std::uint64_t>(std::stoull(s, nullptr, 0));
                if (n > 0) {
                    out = n;
                    return true;
                }
            }
        }
    } catch (...) {
    }
    return false;
}

static bool json_positive_u64_field(const json& obj, const char* key, std::uint64_t& out)
{
    if (!obj.is_object() || !obj.contains(key))
        return false;
    return json_positive_u64(obj[key], out);
}

static const json* payload_object(const json& args)
{
    if (!args.is_object() || !args.contains("payload") || !args["payload"].is_object())
        return nullptr;
    return &args["payload"];
}

static std::string browser_action_from_args(const json& args)
{
    if (args.is_object()) {
        for (const char* key : {"action", "operation"}) {
            if (args.contains(key) && args[key].is_string())
                return lower_ascii(args[key].get<std::string>());
        }
    }
    if (const json* payload = payload_object(args)) {
        for (const char* key : {"action", "operation"}) {
            if (payload->contains(key) && (*payload)[key].is_string())
                return lower_ascii((*payload)[key].get<std::string>());
        }
    }
    return {};
}

static bool browser_arg_timeout_ms(const json& args, const char* key, std::uint64_t& out)
{
    if (json_positive_u64_field(args, key, out))
        return true;
    if (const json* payload = payload_object(args))
        return json_positive_u64_field(*payload, key, out);
    return false;
}

static bool browser_long_action(const std::string& tool_name, const std::string& action)
{
    if (tool_name == "browser_lifecycle")
        return action == "launch";
    if (tool_name == "browser_navigation")
        return action == "navigate" || action == "diagnose" || action == "matrix";
    return false;
}

static std::uint64_t browser_timeout_with_grace(std::uint64_t timeout_ms)
{
    if (timeout_ms > kMcpBrowserToolMaxTimeoutMs - kMcpBrowserCleanupGraceMs)
        return kMcpBrowserToolMaxTimeoutMs;
    return timeout_ms + kMcpBrowserCleanupGraceMs;
}

static std::uint64_t browser_duration_timeout_with_grace(std::uint64_t duration_s)
{
    const std::uint64_t max_seconds = (kMcpBrowserToolMaxTimeoutMs - kMcpBrowserCleanupGraceMs) / 1000ULL;
    if (duration_s > max_seconds)
        return kMcpBrowserToolMaxTimeoutMs;
    return duration_s * 1000ULL + kMcpBrowserCleanupGraceMs;
}

static tool_timeout_resolution_t resolve_tool_timeout(const std::string& tool_name, const json& args)
{
    tool_timeout_resolution_t r;
    const bool browser_tool = is_camoufox_browser_tool_name(tool_name);
    if (browser_tool) {
        r.max_ms = kMcpBrowserToolMaxTimeoutMs;
        r.action = browser_action_from_args(args);
        if (browser_long_action(tool_name, r.action)) {
            r.default_ms = kMcpBrowserLongActionTimeoutMs + kMcpBrowserCleanupGraceMs;
            r.action_aware = true;
            r.source = "browser_action_default";
        } else if (tool_name == "compare_env") {
            r.default_ms = 95000;
            r.action_aware = true;
            r.source = "browser_probe_default";
        } else if (tool_name == "browser_instrumentation" && r.action == "trace") {
            r.default_ms = 150000;
            r.action_aware = true;
            r.source = "browser_trace_default";
        }
    }
    r.requested_ms = r.default_ms;
    const char* const timeout_keys[] = {"tool_timeout_ms", "timeout_ms", "deadline_ms"};
    for (const char* key : timeout_keys) {
        std::uint64_t parsed = 0;
        if (json_positive_u64_field(args, key, parsed)) {
            r.requested_ms = parsed;
            r.explicit_timeout = true;
            r.source = std::string("explicit_") + key;
            break;
        }
    }
    if (browser_tool && !r.explicit_timeout) {
        std::uint64_t parsed = 0;
        if (browser_arg_timeout_ms(args, "call_timeout_ms", parsed)) {
            r.requested_ms = parsed;
            r.explicit_timeout = true;
            r.source = "explicit_call_timeout_ms";
        }
    }
    if (browser_tool) {
        std::uint64_t operation_timeout = 0;
        if (browser_arg_timeout_ms(args, "launch_timeout_ms", operation_timeout) ||
            browser_arg_timeout_ms(args, "timeout", operation_timeout)) {
            r.requested_ms = (std::max)(r.requested_ms, browser_timeout_with_grace(operation_timeout));
            r.action_aware = true;
            if (!r.explicit_timeout)
                r.source = "browser_operation_timeout";
        }
        std::uint64_t duration_s = 0;
        if (browser_arg_timeout_ms(args, "duration", duration_s)) {
            r.requested_ms = (std::max)(r.requested_ms, browser_duration_timeout_with_grace(duration_s));
            r.action_aware = true;
            if (!r.explicit_timeout)
                r.source = "browser_duration";
        }
        if (r.action_aware && r.requested_ms < r.default_ms) {
            r.requested_ms = r.default_ms;
            r.source += "_action_floor";
        }
    }
    r.effective_ms = std::clamp<std::uint64_t>(r.requested_ms, kMcpMinToolTimeoutMs, r.max_ms);
    return r;
}

static std::uint64_t saturated_deadline_ms(std::uint64_t start_ms, std::uint64_t timeout_ms)
{
    const std::uint64_t max_value = (std::numeric_limits<std::uint64_t>::max)();
    if (timeout_ms > max_value - start_ms)
        return max_value;
    return start_ms + timeout_ms;
}

static std::string format_sse_event(const std::string& event_type, const std::string& data)
{
    std::string result;
    if (!event_type.empty())
        result += "event: " + event_type + "\n";
    std::istringstream iss(data);
    std::string line;
    while (std::getline(iss, line))
        result += "data: " + line + "\n";
    result += "\n";
    return result;
}

struct sse_session_t
{
    std::string id;
    std::mutex  mtx;
    std::queue<std::string> events;
    std::atomic<bool> closed{false};
    std::uint64_t opened_tick = mcp_now_ms();
    std::atomic<std::uint64_t> last_activity_tick{0};

    void push_event(const std::string& event)
    {
        last_activity_tick.store(mcp_now_ms(), std::memory_order_release);
        std::lock_guard<std::mutex> lk(mtx);
        if (events.size() >= kSseMaxQueuedEvents) {
            diag::log_tagged_fmt("mcp_srv",
                "sse_session_queue_trim session=%s queued=%zu max=%zu",
                id.c_str(),
                events.size(),
                kSseMaxQueuedEvents);
            events.pop();
        }
        events.push(event);
    }

    bool wait_event(std::string& out, int timeout_ms)
    {
        const DWORD start_tick = GetTickCount();
        const DWORD timeout = static_cast<DWORD>(timeout_ms < 0 ? 0 : timeout_ms);
        for (;;)
        {
            {
                std::lock_guard<std::mutex> lk(mtx);
                if (closed.load(std::memory_order_acquire))
                    return false;
                if (!events.empty()) {
                    out = std::move(events.front());
                    events.pop();
                    last_activity_tick.store(mcp_now_ms(), std::memory_order_release);
                    return true;
                }
            }
            const DWORD elapsed = GetTickCount() - start_tick;
            if (elapsed >= timeout)
                return false;
            const DWORD remaining = timeout - elapsed;
            Sleep(remaining < 50u ? remaining : 50u);
        }
    }

    void close() { closed.store(true, std::memory_order_release); }
};

static bool sse_provider_step_impl(
    sse_session_t* session,
    httplib::DataSink* sink,
    size_t offset,
    std::atomic<bool>* stop_requested,
    mcp_stream_state_t* stream_state,
    const std::function<bool()>& connection_closed)
{
    if (offset == 0) {
        std::string evt = format_sse_event("endpoint",
            "/message?sessionId=" + session->id);
        if (!sink->write(evt.c_str(), evt.size())) {
            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=endpoint",
                stream_state ? static_cast<unsigned long long>(stream_state->id) : 0ULL,
                stream_state && stream_state->route ? stream_state->route : "<unknown>");
            session->close();
            return false;
        }
    }
    if (connection_closed_now(connection_closed)) {
        session->close();
        finish_stream_cleanly(stream_state, *sink, "connection_closed");
        return true;
    }
    std::string event;
    if (session->wait_event(event, 2000)) {
        if (!sink->write(event.c_str(), event.size())) {
            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=event",
                stream_state ? static_cast<unsigned long long>(stream_state->id) : 0ULL,
                stream_state && stream_state->route ? stream_state->route : "<unknown>");
            session->close();
            return false;
        }
    } else if (session->closed.load(std::memory_order_acquire)) {
        finish_stream_cleanly(stream_state, *sink, "session_closed");
        return true;
    } else if (stop_requested && stop_requested->load(std::memory_order_acquire)) {
        session->close();
        finish_stream_cleanly(stream_state, *sink, "server_stop");
        return true;
    } else {
        const char ka[] = ": keepalive\n\n";
        if (sink->is_writable && !sink->is_writable()) {
            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=writable",
                stream_state ? static_cast<unsigned long long>(stream_state->id) : 0ULL,
                stream_state && stream_state->route ? stream_state->route : "<unknown>");
            session->close();
            return false;
        }
        if (!sink->write(ka, sizeof(ka) - 1u)) {
            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=keepalive",
                stream_state ? static_cast<unsigned long long>(stream_state->id) : 0ULL,
                stream_state && stream_state->route ? stream_state->route : "<unknown>");
            session->close();
            return false;
        }
    }
    return !session->closed.load(std::memory_order_acquire);
}

__declspec(noinline) static DWORD seh_sse_provider_step(
    sse_session_t* session,
    httplib::DataSink* sink,
    size_t offset,
    std::atomic<bool>* stop_requested,
    mcp_stream_state_t* stream_state,
    const std::function<bool()>& connection_closed,
    bool* out_continue)
{
    *out_continue = false;
    __try {
        *out_continue = sse_provider_step_impl(session, sink, offset, stop_requested, stream_state, connection_closed);
        return 0;
    } __except (aida::infra::win_thread::non_cpp_seh_filter(GetExceptionCode())) {
        return GetExceptionCode();
    }
}

namespace
{
    std::mutex                                                       g_in_flight_mutex;
    std::map<std::string, cancel_token_ptr_t>                        g_in_flight_cancels;
    thread_local std::atomic<bool>*                                  tls_current_cancel_token = nullptr;

    std::string cancel_key_for_id(const json& id)
    {
        if (id.is_null())              return std::string{"\1null"};
        if (id.is_string())            return std::string{"s:"} + id.get<std::string>();
        if (id.is_number_integer())    return std::string{"i:"} + std::to_string(id.get<long long>());
        if (id.is_number_unsigned())   return std::string{"u:"} + std::to_string(id.get<unsigned long long>());
        if (id.is_number_float())      return std::string{"f:"} + std::to_string(id.get<double>());
        return std::string{"j:"} + id.dump();
    }

    cancel_token_ptr_t register_in_flight_call(const json& id)
    {
        auto token = make_call_cancel_token(false);
        std::lock_guard<std::mutex> lk(g_in_flight_mutex);
        g_in_flight_cancels[cancel_key_for_id(id)] = token;
        return token;
    }

    void unregister_in_flight_call(const json& id)
    {
        std::lock_guard<std::mutex> lk(g_in_flight_mutex);
        g_in_flight_cancels.erase(cancel_key_for_id(id));
    }

    bool signal_in_flight_cancel(const json& id)
    {
        cancel_token_ptr_t token;
        {
            std::lock_guard<std::mutex> lk(g_in_flight_mutex);
            auto it = g_in_flight_cancels.find(cancel_key_for_id(id));
            if (it == g_in_flight_cancels.end()) return false;
            token = it->second;
        }
        signal_call_cancel_token(token);
        return true;
    }

    struct cancel_scope_t
    {
        json               id;
        cancel_token_ptr_t token;
        scoped_call_cancel_t scoped;

        cancel_scope_t(const json& request_id)
            : id(request_id)
            , token(register_in_flight_call(id))
            , scoped(token)
        {
        }

        cancel_scope_t(const cancel_scope_t&) = delete;
        cancel_scope_t& operator=(const cancel_scope_t&) = delete;

        ~cancel_scope_t()
        {
            unregister_in_flight_call(id);
        }
    };

    struct registered_call_scope_t
    {
        json id;
        cancel_token_ptr_t token;
        bool active = false;

        explicit registered_call_scope_t(const json& request_id)
            : id(request_id)
            , token(register_in_flight_call(id))
            , active(true)
        {
        }

        registered_call_scope_t(const registered_call_scope_t&) = delete;
        registered_call_scope_t& operator=(const registered_call_scope_t&) = delete;

        ~registered_call_scope_t()
        {
            release();
        }

        void cancel() const noexcept
        {
            signal_call_cancel_token(token);
        }

        void release() noexcept
        {
            if (!active)
                return;
            unregister_in_flight_call(id);
            active = false;
        }
    };

}

cancel_token_ptr_t make_call_cancel_token(bool cancelled)
{
    auto token = std::make_shared<std::atomic<bool>>(cancelled);
    return token;
}

void signal_call_cancel_token(const cancel_token_ptr_t& token) noexcept
{
    if (token)
        token->store(true, std::memory_order_release);
}

std::atomic<bool>* current_cancel_token() noexcept
{
    return tls_current_cancel_token;
}

bool current_call_cancelled() noexcept
{
    std::atomic<bool>* tok = tls_current_cancel_token;
    return tok && tok->load(std::memory_order_acquire);
}

const char* current_call_diag_id() noexcept
{
    return tls_current_call_diag_id.c_str();
}

const char* current_call_tool_name() noexcept
{
    return tls_current_call_tool_name.c_str();
}

std::uint64_t current_call_deadline_ms() noexcept
{
    return tls_current_call_deadline_ms;
}

scoped_call_metadata_t::scoped_call_metadata_t(const std::string& diag_id, const std::string& tool_name, std::uint64_t deadline_ms)
    : _prev_diag(tls_current_call_diag_id)
    , _prev_tool(tls_current_call_tool_name)
    , _prev_deadline(tls_current_call_deadline_ms)
    , _active(true)
{
    tls_current_call_diag_id = diag_id;
    tls_current_call_tool_name = tool_name;
    tls_current_call_deadline_ms = deadline_ms;
}

scoped_call_metadata_t::~scoped_call_metadata_t()
{
    if (!_active)
        return;
    tls_current_call_diag_id = std::move(_prev_diag);
    tls_current_call_tool_name = std::move(_prev_tool);
    tls_current_call_deadline_ms = _prev_deadline;
    _active = false;
}

scoped_call_cancel_t::scoped_call_cancel_t(cancel_token_ptr_t token)
    : _token(std::move(token))
{
    if (_token) {
        _previous = tls_current_cancel_token;
        tls_current_cancel_token = _token.get();
        _active = true;
    }
}

scoped_call_cancel_t::~scoped_call_cancel_t()
{
    release();
}

scoped_call_cancel_t::scoped_call_cancel_t(scoped_call_cancel_t&& other) noexcept
    : _token(std::move(other._token))
    , _previous(other._previous)
    , _active(other._active)
{
    other._previous = nullptr;
    other._active = false;
}

scoped_call_cancel_t& scoped_call_cancel_t::operator=(scoped_call_cancel_t&& other) noexcept
{
    if (this != &other) {
        release();
        _token = std::move(other._token);
        _previous = other._previous;
        _active = other._active;
        other._previous = nullptr;
        other._active = false;
    }
    return *this;
}

void scoped_call_cancel_t::cancel() noexcept
{
    signal_call_cancel_token(_token);
}

void scoped_call_cancel_t::release() noexcept
{
    if (!_active)
        return;
    tls_current_cancel_token = _previous;
    _previous = nullptr;
    _active = false;
}

server_t::server_t()  = default;
server_t::~server_t() { stop(); }

static bool is_camoufox_reverse_tool_name(const std::string& name)
{
    static const char* const names[] = {
        "browser_lifecycle", "browser_navigation", "browser_interaction", "browser_inspect", "browser_state",
        "browser_network", "browser_hooks", "browser_instrumentation",
        "get_console_logs", "scripts", "search_code", "compare_env",
        "verify_signer_offline", "analyze_cookie_sources"
    };
    for (const char* n : names)
    {
        if (name == n)
            return true;
    }
    return false;
}

static bool is_camoufox_browser_tool_name(const std::string& name)
{
    return is_camoufox_reverse_tool_name(name);
}

static bool is_standalone_internal_only_tool_name(const std::string& name)
{
    static const char* const names[] = {
        "apply_diff", "apply_patch", "codebase_search", "read_command_output",
        "search_workspace", "run_command", "cancel_command", "list_commands"
    };
    for (const char* n : names)
    {
        if (name == n)
            return true;
    }
    return false;
}

static bool is_standalone_ide_chat_only_tool_name(const std::string& name)
{
    static const char* const names[] = {
        "switch_agent", "plan_enter", "plan_exit", "list_agents", "ask_followup_question",
        "attempt_completion", "update_todo_list", "save_checkpoint", "restore_checkpoint",
        "list_checkpoints", "checkpoint_list", "skill", "run_slash_command", "get_context",
        "workflow_status", "task"
    };
    for (const char* n : names)
    {
        if (name == n)
            return true;
    }
    return false;
}

static bool is_external_mcp_tool(const tool_def_t& tool)
{
    return tool.visibility == tool_visibility_t::external_visible &&
           !is_standalone_ide_chat_only_tool_name(tool.name) &&
           !is_standalone_internal_only_tool_name(tool.name);
}

static bool is_driver_bridge_dependent_tool(const tool_def_t& tool)
{
    const std::string name = lower_ascii(tool.name);
    if (name.rfind("driver_", 0) != 0)
        return false;
    const std::string desc = lower_ascii(tool.description);
    if (desc.find("does not require the kernel driver") != std::string::npos ||
        desc.find("purely from usermode") != std::string::npos)
        return false;
    static const char* const driver_needles[] = {
        "requires driver connected",
        "requires kernel driver",
        "requires driver",
        "via kernel driver",
        "using kernel memory",
        "kernel memory reads",
        "kernel-level",
        "dtb solved",
        "kernel driver backend"
    };
    for (const char* needle : driver_needles) {
        if (desc.find(needle) != std::string::npos)
            return true;
    }
    return false;
}

static std::shared_mutex& active_session_tool_mutex()
{
    static std::shared_mutex m;
    return m;
}

static std::string sanitize_owner_field(const std::string& value, std::size_t max_len = 160)
{
    std::string clean = sanitize_utf8(value);
    std::string out;
    out.reserve(std::min(clean.size(), max_len));
    for (char ch : clean) {
        unsigned char c = static_cast<unsigned char>(ch);
        out.push_back((c < 0x20 || c == 0x7f) ? '_' : ch);
        if (out.size() >= max_len)
            break;
    }
    return out;
}

static std::string hex32_string(DWORD code)
{
    char buf[16];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%08lX", static_cast<unsigned long>(code));
    return buf;
}

struct active_session_owner_record_t
{
    bool active = false;
    bool exclusive = false;
    bool read_only = false;
    bool explicit_target = false;
    bool cancelled = false;
    std::uint64_t token = 0;
    std::uint64_t acquired_ms = 0;
    std::uint64_t deadline_ms = 0;
    DWORD pid = 0;
    DWORD tid = 0;
    std::string tool;
    std::string lane;
    std::string diag_id;
    std::string phase;
};

struct active_session_owner_snapshot_t
{
    bool present = false;
    bool exclusive = false;
    bool cancelled = false;
    bool read_only = false;
    bool explicit_target = false;
    std::size_t shared_owner_count = 0;
    std::uint64_t token = 0;
    std::uint64_t acquired_ms = 0;
    std::uint64_t owner_age_ms = 0;
    std::uint64_t deadline_ms = 0;
    DWORD pid = 0;
    DWORD tid = 0;
    std::string tool;
    std::string lane;
    std::string diag_id;
    std::string phase;
};

static std::mutex& active_session_owner_mutex()
{
    static std::mutex m;
    return m;
}

static active_session_owner_record_t& active_session_exclusive_owner()
{
    static active_session_owner_record_t owner;
    return owner;
}

static std::vector<active_session_owner_record_t>& active_session_shared_owners()
{
    static std::vector<active_session_owner_record_t> owners;
    return owners;
}

static std::atomic<std::uint64_t>& active_session_owner_token_source()
{
    static std::atomic<std::uint64_t> source{0};
    return source;
}

static active_session_owner_snapshot_t active_session_owner_snapshot_from_record(const active_session_owner_record_t& record, std::size_t shared_count, std::uint64_t now)
{
    active_session_owner_snapshot_t snap;
    snap.present = record.active;
    snap.exclusive = record.exclusive;
    snap.cancelled = record.cancelled;
    snap.read_only = record.read_only;
    snap.explicit_target = record.explicit_target;
    snap.shared_owner_count = shared_count;
    snap.token = record.token;
    snap.acquired_ms = record.acquired_ms;
    snap.owner_age_ms = record.acquired_ms != 0 && now >= record.acquired_ms ? now - record.acquired_ms : 0;
    snap.deadline_ms = record.deadline_ms;
    snap.pid = record.pid;
    snap.tid = record.tid;
    snap.tool = sanitize_owner_field(record.tool);
    snap.lane = sanitize_owner_field(record.lane);
    snap.diag_id = sanitize_owner_field(record.diag_id);
    snap.phase = sanitize_owner_field(record.phase);
    return snap;
}

static active_session_owner_snapshot_t active_session_owner_snapshot()
{
    const std::uint64_t now = mcp_now_ms();
    std::lock_guard<std::mutex> lk(active_session_owner_mutex());
    auto& exclusive_owner = active_session_exclusive_owner();
    auto& shared_owners = active_session_shared_owners();
    if (exclusive_owner.active)
        return active_session_owner_snapshot_from_record(exclusive_owner, shared_owners.size(), now);
    const active_session_owner_record_t* oldest = nullptr;
    for (const auto& owner : shared_owners) {
        if (!owner.active)
            continue;
        if (!oldest || owner.acquired_ms < oldest->acquired_ms)
            oldest = &owner;
    }
    if (oldest)
        return active_session_owner_snapshot_from_record(*oldest, shared_owners.size(), now);
    active_session_owner_snapshot_t snap;
    snap.shared_owner_count = shared_owners.size();
    return snap;
}

static void append_active_session_owner_fields(json& details, const active_session_owner_snapshot_t& owner)
{
    details["owner_present"] = owner.present;
    details["owner_mode"] = owner.present ? (owner.exclusive ? "exclusive" : "shared") : "";
    details["owner_tool"] = owner.present ? owner.tool : "";
    details["owner_diag_id"] = owner.present ? owner.diag_id : "";
    details["owner_lane"] = owner.present ? owner.lane : "";
    details["owner_pid"] = owner.present ? owner.pid : 0;
    details["owner_tid"] = owner.present ? owner.tid : 0;
    details["owner_age_ms"] = owner.present ? owner.owner_age_ms : 0;
    details["owner_deadline_ms"] = owner.present ? owner.deadline_ms : 0;
    details["owner_cancelled"] = owner.present ? owner.cancelled : false;
    details["owner_phase"] = owner.present ? owner.phase : "";
    details["owner_read_only"] = owner.present ? owner.read_only : false;
    details["owner_explicit_target"] = owner.present ? owner.explicit_target : false;
    details["shared_owner_count"] = owner.shared_owner_count;
    details["exclusive_owner"] = owner.present && owner.exclusive;
}

static void log_active_session_owner_stale_if_needed(const active_session_owner_snapshot_t& owner,
                                                     const char* reason,
                                                     const std::string& waiter_tool,
                                                     const char* waiter_lane,
                                                     std::uint64_t waiter_wait_ms,
                                                     std::uint64_t waiter_budget_ms)
{
    if (!owner.present)
        return;
    const std::uint64_t now = mcp_now_ms();
    const bool deadline_expired = owner.deadline_ms != 0 && now >= owner.deadline_ms;
    const bool budget_exceeded = waiter_budget_ms != 0 && waiter_wait_ms >= waiter_budget_ms;
    if (!deadline_expired && !budget_exceeded)
        return;
    diag::log_tagged_fmt("mcp_srv",
        "tool_policy_lock_owner_stale reason=%s waiter_tool='%s' waiter_lane=%s waiter_wait_ms=%llu waiter_budget_ms=%llu owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_mode=%s owner_pid=%lu owner_tid=%lu owner_age_ms=%llu owner_deadline_ms=%llu owner_cancelled=%d owner_phase=%s shared_owner_count=%zu",
        reason ? reason : "",
        waiter_tool.c_str(),
        waiter_lane ? waiter_lane : "",
        static_cast<unsigned long long>(waiter_wait_ms),
        static_cast<unsigned long long>(waiter_budget_ms),
        owner.tool.c_str(),
        owner.lane.c_str(),
        owner.diag_id.c_str(),
        owner.exclusive ? "exclusive" : "shared",
        static_cast<unsigned long>(owner.pid),
        static_cast<unsigned long>(owner.tid),
        static_cast<unsigned long long>(owner.owner_age_ms),
        static_cast<unsigned long long>(owner.deadline_ms),
        owner.cancelled ? 1 : 0,
        owner.phase.c_str(),
        owner.shared_owner_count);
}

class active_session_owner_guard_t
{
public:
    active_session_owner_guard_t(const std::string& tool_name,
                                 const char* lane,
                                 bool exclusive,
                                 bool read_only,
                                 bool explicit_target)
        : tool_(sanitize_owner_field(tool_name))
        , lane_(sanitize_owner_field(lane ? lane : ""))
        , diag_id_(sanitize_owner_field(current_call_diag_id() ? current_call_diag_id() : ""))
        , exclusive_(exclusive)
        , read_only_(read_only)
        , explicit_target_(explicit_target)
        , token_(active_session_owner_token_source().fetch_add(1u, std::memory_order_acq_rel) + 1u)
        , acquired_ms_(mcp_now_ms())
        , deadline_ms_(current_call_deadline_ms())
        , pid_(GetCurrentProcessId())
        , tid_(GetCurrentThreadId())
    {
        record("acquired");
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lock_hold_begin tool='%s' lane=%s mode=%s diag_id=%s pid=%lu tid=%lu deadline_ms=%llu cancelled=%d shared_owner_count=%zu token=%llu",
            tool_.c_str(),
            lane_.c_str(),
            exclusive_ ? "exclusive" : "shared",
            diag_id_.c_str(),
            static_cast<unsigned long>(pid_),
            static_cast<unsigned long>(tid_),
            static_cast<unsigned long long>(deadline_ms_),
            current_call_cancelled() ? 1 : 0,
            active_session_owner_snapshot().shared_owner_count,
            static_cast<unsigned long long>(token_));
    }

    active_session_owner_guard_t(const active_session_owner_guard_t&) = delete;
    active_session_owner_guard_t& operator=(const active_session_owner_guard_t&) = delete;

    ~active_session_owner_guard_t()
    {
        release("scope_exit");
    }

    void set_phase(const char* phase)
    {
        if (!active_)
            return;
        phase_ = sanitize_owner_field(phase ? phase : "");
        std::lock_guard<std::mutex> lk(active_session_owner_mutex());
        if (exclusive_) {
            auto& owner = active_session_exclusive_owner();
            if (owner.active && owner.token == token_) {
                owner.phase = phase_;
                owner.cancelled = current_call_cancelled();
            }
            return;
        }
        auto& shared_owners = active_session_shared_owners();
        for (auto& owner : shared_owners) {
            if (owner.active && owner.token == token_) {
                owner.phase = phase_;
                owner.cancelled = current_call_cancelled();
                return;
            }
        }
    }

    void set_lane(const char* lane)
    {
        if (!active_)
            return;
        lane_ = sanitize_owner_field(lane ? lane : "");
        std::lock_guard<std::mutex> lk(active_session_owner_mutex());
        if (exclusive_) {
            auto& owner = active_session_exclusive_owner();
            if (owner.active && owner.token == token_)
                owner.lane = lane_;
            return;
        }
        auto& shared_owners = active_session_shared_owners();
        for (auto& owner : shared_owners) {
            if (owner.active && owner.token == token_) {
                owner.lane = lane_;
                return;
            }
        }
    }

    void note_seh(DWORD code, std::uint64_t elapsed_ms)
    {
        if (!active_)
            return;
        set_phase("handler_seh");
        const active_session_owner_snapshot_t owner = active_session_owner_snapshot();
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lock_hold_seh tool='%s' lane=%s mode=%s diag_id=%s code=0x%08lX elapsed_ms=%llu pid=%lu tid=%lu deadline_ms=%llu cancelled=%d owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_pid=%lu owner_tid=%lu owner_age_ms=%llu owner_phase=%s shared_owner_count=%zu token=%llu",
            tool_.c_str(),
            lane_.c_str(),
            exclusive_ ? "exclusive" : "shared",
            diag_id_.c_str(),
            static_cast<unsigned long>(code),
            static_cast<unsigned long long>(elapsed_ms),
            static_cast<unsigned long>(pid_),
            static_cast<unsigned long>(tid_),
            static_cast<unsigned long long>(deadline_ms_),
            current_call_cancelled() ? 1 : 0,
            owner.tool.c_str(),
            owner.lane.c_str(),
            owner.diag_id.c_str(),
            static_cast<unsigned long>(owner.pid),
            static_cast<unsigned long>(owner.tid),
            static_cast<unsigned long long>(owner.owner_age_ms),
            owner.phase.c_str(),
            owner.shared_owner_count,
            static_cast<unsigned long long>(token_));
    }

    void release(const char* reason)
    {
        if (!active_)
            return;
        const std::uint64_t elapsed_ms = mcp_now_ms() >= acquired_ms_ ? mcp_now_ms() - acquired_ms_ : 0;
        std::size_t shared_count = 0;
        bool exclusive_active = false;
        {
            std::lock_guard<std::mutex> lk(active_session_owner_mutex());
            if (exclusive_) {
                auto& owner = active_session_exclusive_owner();
                if (owner.active && owner.token == token_)
                    owner = {};
            } else {
                auto& shared_owners = active_session_shared_owners();
                shared_owners.erase(std::remove_if(shared_owners.begin(), shared_owners.end(),
                    [this](const active_session_owner_record_t& owner) {
                        return owner.token == token_;
                    }), shared_owners.end());
            }
            shared_count = active_session_shared_owners().size();
            exclusive_active = active_session_exclusive_owner().active;
        }
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lock_hold_end tool='%s' lane=%s mode=%s diag_id=%s reason=%s elapsed_ms=%llu pid=%lu tid=%lu deadline_ms=%llu cancelled=%d phase=%s shared_owner_count=%zu exclusive_owner=%d token=%llu",
            tool_.c_str(),
            lane_.c_str(),
            exclusive_ ? "exclusive" : "shared",
            diag_id_.c_str(),
            reason ? reason : "",
            static_cast<unsigned long long>(elapsed_ms),
            static_cast<unsigned long>(pid_),
            static_cast<unsigned long>(tid_),
            static_cast<unsigned long long>(deadline_ms_),
            current_call_cancelled() ? 1 : 0,
            phase_.c_str(),
            shared_count,
            exclusive_active ? 1 : 0,
            static_cast<unsigned long long>(token_));
        active_ = false;
    }

private:
    void record(const char* phase)
    {
        phase_ = sanitize_owner_field(phase ? phase : "");
        active_session_owner_record_t record;
        record.active = true;
        record.exclusive = exclusive_;
        record.read_only = read_only_;
        record.explicit_target = explicit_target_;
        record.cancelled = current_call_cancelled();
        record.token = token_;
        record.acquired_ms = acquired_ms_;
        record.deadline_ms = deadline_ms_;
        record.pid = pid_;
        record.tid = tid_;
        record.tool = tool_;
        record.lane = lane_;
        record.diag_id = diag_id_;
        record.phase = phase_;
        std::lock_guard<std::mutex> lk(active_session_owner_mutex());
        if (exclusive_) {
            active_session_exclusive_owner() = std::move(record);
        } else {
            auto& shared_owners = active_session_shared_owners();
            if (shared_owners.size() < 64u) {
                shared_owners.push_back(std::move(record));
            } else {
                diag::log_tagged_fmt("mcp_srv",
                    "tool_policy_lock_owner_shared_overflow tool='%s' lane=%s diag_id=%s tid=%lu shared_owner_count=%zu",
                    tool_.c_str(),
                    lane_.c_str(),
                    diag_id_.c_str(),
                    static_cast<unsigned long>(tid_),
                    shared_owners.size());
            }
        }
        active_ = true;
    }

    std::string tool_;
    std::string lane_;
    std::string diag_id_;
    std::string phase_;
    bool exclusive_ = false;
    bool read_only_ = false;
    bool explicit_target_ = false;
    bool active_ = false;
    std::uint64_t token_ = 0;
    std::uint64_t acquired_ms_ = 0;
    std::uint64_t deadline_ms_ = 0;
    DWORD pid_ = 0;
    DWORD tid_ = 0;
};

static std::mutex& domain_lane_mutex(const std::string& domain)
{
    static std::mutex map_mutex;
    static std::map<std::string, std::shared_ptr<std::mutex>> lanes;
    const std::string key = domain.empty() ? std::string("misc") : domain;
    std::lock_guard<std::mutex> lk(map_mutex);
    auto it = lanes.find(key);
    if (it != lanes.end())
        return *it->second;
    auto lane = std::make_shared<std::mutex>();
    auto* ptr = lane.get();
    lanes.emplace(key, std::move(lane));
    return *ptr;
}

struct tool_invocation_metrics_t
{
    std::string lane;
    std::uint64_t lock_wait_ms = 0;
    std::uint64_t handler_elapsed_ms = 0;
    bool resolved_target = false;
};

static void set_tool_metrics_lane(tool_invocation_metrics_t* metrics, const std::string& lane, std::uint64_t lock_wait_ms)
{
    if (!metrics)
        return;
    metrics->lane = lane;
    metrics->lock_wait_ms += lock_wait_ms;
}

enum class policy_lock_status_t
{
    acquired,
    cancelled,
    busy
};

struct policy_lock_wait_t
{
    policy_lock_status_t status = policy_lock_status_t::busy;
    std::uint64_t wait_ms = 0;
};

static std::uint64_t policy_lock_wait_budget_ms()
{
    const std::uint64_t now = mcp_now_ms();
    const std::uint64_t deadline = current_call_deadline_ms();
    if (deadline != 0 && deadline > now)
        return std::min<std::uint64_t>(kMcpPolicyLockMaxWaitMs, deadline - now);
    if (deadline != 0 && deadline <= now)
        return 0;
    return kMcpPolicyLockMaxWaitMs;
}

template <typename Lock, typename TryLockFn>
static policy_lock_wait_t wait_policy_lock(Lock& lock,
                                           TryLockFn&& try_lock,
                                           const std::string& tool_name,
                                           const char* lane,
                                           const char* mode,
                                           bool read_only,
                                           bool explicit_target)
{
    const std::uint64_t started = mcp_now_ms();
    const std::uint64_t budget = policy_lock_wait_budget_ms();
    std::uint64_t last_log = started;
    diag::log_tagged_fmt("mcp_srv",
        "tool_policy_lock_wait_begin tool='%s' lane=%s mode=%s read_only=%d explicit_target=%d budget_ms=%llu diag_id=%s",
        tool_name.c_str(),
        lane ? lane : "",
        mode ? mode : "",
        read_only ? 1 : 0,
        explicit_target ? 1 : 0,
        static_cast<unsigned long long>(budget),
        current_call_diag_id());

    for (;;)
    {
        if (try_lock(lock))
        {
            const std::uint64_t waited = mcp_now_ms() - started;
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_lock_wait_acquired tool='%s' lane=%s mode=%s wait_ms=%llu diag_id=%s",
                tool_name.c_str(),
                lane ? lane : "",
                mode ? mode : "",
                static_cast<unsigned long long>(waited),
                current_call_diag_id());
            return {policy_lock_status_t::acquired, waited};
        }

        const std::uint64_t now = mcp_now_ms();
        const std::uint64_t waited = now >= started ? now - started : 0;
        if (current_call_cancelled())
        {
            const active_session_owner_snapshot_t owner = active_session_owner_snapshot();
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_lock_wait_cancelled tool='%s' lane=%s mode=%s wait_ms=%llu diag_id=%s owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_mode=%s owner_pid=%lu owner_tid=%lu owner_age_ms=%llu owner_phase=%s shared_owner_count=%zu",
                tool_name.c_str(),
                lane ? lane : "",
                mode ? mode : "",
                static_cast<unsigned long long>(waited),
                current_call_diag_id(),
                owner.tool.c_str(),
                owner.lane.c_str(),
                owner.diag_id.c_str(),
                owner.present ? (owner.exclusive ? "exclusive" : "shared") : "",
                static_cast<unsigned long>(owner.pid),
                static_cast<unsigned long>(owner.tid),
                static_cast<unsigned long long>(owner.owner_age_ms),
                owner.phase.c_str(),
                owner.shared_owner_count);
            return {policy_lock_status_t::cancelled, waited};
        }

        const std::uint64_t deadline = current_call_deadline_ms();
        if ((budget == 0 || waited >= budget) || (deadline != 0 && now >= deadline))
        {
            const active_session_owner_snapshot_t owner = active_session_owner_snapshot();
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_lock_wait_busy tool='%s' lane=%s mode=%s wait_ms=%llu budget_ms=%llu diag_id=%s owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_mode=%s owner_pid=%lu owner_tid=%lu owner_age_ms=%llu owner_deadline_ms=%llu owner_cancelled=%d owner_phase=%s shared_owner_count=%zu",
                tool_name.c_str(),
                lane ? lane : "",
                mode ? mode : "",
                static_cast<unsigned long long>(waited),
                static_cast<unsigned long long>(budget),
                current_call_diag_id(),
                owner.tool.c_str(),
                owner.lane.c_str(),
                owner.diag_id.c_str(),
                owner.present ? (owner.exclusive ? "exclusive" : "shared") : "",
                static_cast<unsigned long>(owner.pid),
                static_cast<unsigned long>(owner.tid),
                static_cast<unsigned long long>(owner.owner_age_ms),
                static_cast<unsigned long long>(owner.deadline_ms),
                owner.cancelled ? 1 : 0,
                owner.phase.c_str(),
                owner.shared_owner_count);
            log_active_session_owner_stale_if_needed(owner, "wait_busy", tool_name, lane, waited, budget);
            return {policy_lock_status_t::busy, waited};
        }

        if (now - last_log >= kMcpPolicyLockLogEveryMs)
        {
            last_log = now;
            const active_session_owner_snapshot_t owner = active_session_owner_snapshot();
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_lock_wait_state tool='%s' lane=%s mode=%s wait_ms=%llu cancelled=%d diag_id=%s owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_mode=%s owner_pid=%lu owner_tid=%lu owner_age_ms=%llu owner_deadline_ms=%llu owner_cancelled=%d owner_phase=%s shared_owner_count=%zu",
                tool_name.c_str(),
                lane ? lane : "",
                mode ? mode : "",
                static_cast<unsigned long long>(waited),
                current_call_cancelled() ? 1 : 0,
                current_call_diag_id(),
                owner.tool.c_str(),
                owner.lane.c_str(),
                owner.diag_id.c_str(),
                owner.present ? (owner.exclusive ? "exclusive" : "shared") : "",
                static_cast<unsigned long>(owner.pid),
                static_cast<unsigned long>(owner.tid),
                static_cast<unsigned long long>(owner.owner_age_ms),
                static_cast<unsigned long long>(owner.deadline_ms),
                owner.cancelled ? 1 : 0,
                owner.phase.c_str(),
                owner.shared_owner_count);
            log_active_session_owner_stale_if_needed(owner, "wait_state", tool_name, lane, waited, budget);
        }
        Sleep(static_cast<DWORD>(kMcpPolicyLockPollMs));
    }
}

static policy_lock_wait_t acquire_policy_unique_lock(std::unique_lock<std::shared_mutex>& lock,
                                                     const std::string& tool_name,
                                                     const char* lane,
                                                     bool read_only,
                                                     bool explicit_target)
{
    return wait_policy_lock(lock,
        [](std::unique_lock<std::shared_mutex>& l) { return l.try_lock(); },
        tool_name,
        lane,
        "exclusive",
        read_only,
        explicit_target);
}

static policy_lock_wait_t acquire_policy_shared_lock(std::shared_lock<std::shared_mutex>& lock,
                                                     const std::string& tool_name,
                                                     const char* lane,
                                                     bool explicit_target)
{
    return wait_policy_lock(lock,
        [](std::shared_lock<std::shared_mutex>& l) { return l.try_lock(); },
        tool_name,
        lane,
        "shared",
        true,
        explicit_target);
}

static tool_result_t policy_lock_error_result(const std::string& tool_name,
                                              const char* lane,
                                              const policy_lock_wait_t& wait)
{
    json details = {
        {"tool", tool_name},
        {"lane", lane ? lane : ""},
        {"lock_wait_ms", wait.wait_ms},
        {"diagnostic_id", current_call_diag_id()},
        {"cancelled", wait.status == policy_lock_status_t::cancelled},
        {"busy", wait.status == policy_lock_status_t::busy}
    };
    append_active_session_owner_fields(details, active_session_owner_snapshot());
    if (wait.status == policy_lock_status_t::cancelled)
        return tool_result_t::error("MCP tool call cancelled while waiting for active-session policy lock.", "cancelled", details);
    return tool_result_t::error("MCP active-session policy lock is busy; a prior tool is still draining.", "busy", details);
}

static bool tool_args_select_session_target(const json& args)
{
    if (!args.is_object())
        return false;
    static const char* const keys[] = {
        "binary_id", "session_id", "file_path", "target_pid", "process_id", "pid"
    };
    for (const char* key : keys) {
        if (args.contains(key) && !args[key].is_null())
            return true;
    }
    return false;
}

static bool tool_declares_param_named(const tool_def_t& tool, const char* name)
{
    for (const auto& param : tool.params) {
        if (param.name == name)
            return true;
    }
    return false;
}

static const json& target_resolution_args_for_tool(const tool_def_t& tool, const json& arguments, json& storage, bool emit_log)
{
    if (!arguments.is_object() ||
        !tool_declares_param_named(tool, "session_id") ||
        !arguments.contains("session_id") ||
        arguments.contains("binary_id")) {
        return arguments;
    }

    std::size_t session_id_len = 0;
    const auto it = arguments.find("session_id");
    if (it != arguments.end() && it->is_string())
        session_id_len = it->get<std::string>().size();

    storage = arguments;
    storage.erase("session_id");
    if (emit_log) {
        diag::log_tagged_fmt("mcp_srv",
            "tool_target_args local_session_id tool='%s' session_id_len=%zu binary_id_present=0",
            tool.name.c_str(),
            session_id_len);
    }
    return storage;
}

struct target_probe_t
{
    bool ok = true;
    bool resolved = false;
    size_t active_idx = static_cast<size_t>(-1);
    size_t target_idx = static_cast<size_t>(-1);
    std::string resolved_id;
    std::uint32_t pid = 0;
    std::string err;
};

static target_probe_t probe_target_without_switch(const json& args)
{
    target_probe_t probe;
    probe.active_idx = analysis_session::active_session_idx();

    if (args.is_null() || !args.is_object())
        return probe;

    std::string binary_id;
    if (args.contains("binary_id") && args["binary_id"].is_string()) {
        binary_id = args["binary_id"].get<std::string>();
    } else if (args.contains("session_id") && args["session_id"].is_string()) {
        binary_id = args["session_id"].get<std::string>();
    }

    std::string file_path;
    if (binary_id.empty() && args.contains("file_path") && args["file_path"].is_string())
        file_path = args["file_path"].get<std::string>();

    uint32_t target_pid = 0;
    if (binary_id.empty() && file_path.empty()) {
        for (const char* key : {"target_pid", "process_id", "pid"}) {
            if (!args.contains(key))
                continue;
            const auto& v = args[key];
            if (v.is_number_unsigned()) {
                target_pid = static_cast<uint32_t>(v.get<uint64_t>());
            } else if (v.is_number_integer()) {
                int64_t s = v.get<int64_t>();
                if (s > 0)
                    target_pid = static_cast<uint32_t>(s);
            } else if (v.is_string()) {
                std::string s = v.get<std::string>();
                if (!s.empty()) {
                    try { target_pid = static_cast<uint32_t>(std::stoul(s, nullptr, 0)); }
                    catch (...) { target_pid = 0; }
                }
            }
            if (target_pid != 0)
                break;
        }
    }

    size_t resolved_idx = static_cast<size_t>(-1);
    if (!binary_id.empty()) {
        size_t idx = 0;
        if (analysis_session::find_session_by_id(binary_id, &idx)) {
            resolved_idx = idx;
        } else {
            probe.ok = false;
            probe.err = "binary_id '" + binary_id + "' not found in active sessions";
            diag::log_tagged_fmt("mcp_standalone",
                "probe_target binary_id='%s' not_found",
                binary_id.c_str());
            return probe;
        }
    } else if (!file_path.empty()) {
        size_t idx = 0;
        if (analysis_session::find_session_by_path(file_path, &idx)) {
            resolved_idx = idx;
        } else {
            probe.ok = false;
            probe.err = "file_path '" + file_path + "' not found in active sessions";
            return probe;
        }
    } else if (target_pid != 0) {
        size_t idx = 0;
        if (analysis_session::find_session_by_pid(target_pid, &idx))
            resolved_idx = idx;
    }

    if (resolved_idx == static_cast<size_t>(-1))
        return probe;

    probe.resolved = true;
    probe.target_idx = resolved_idx;
    auto sum = analysis_session::summarize_session_at(resolved_idx);
    probe.resolved_id = sum.id;
    probe.pid = sum.pid;
    return probe;
}

static bool tool_args_have_explicit_pid(const json& args)
{
    if (!args.is_object())
        return false;
    for (const char* key : {"target_pid", "process_id", "pid"}) {
        if (args.contains(key) && !args[key].is_null())
            return true;
    }
    return false;
}

static json add_process_id_for_handler_if_supported(const tool_def_t& tool, const json& arguments, std::uint32_t pid, bool* added)
{
    if (added)
        *added = false;
    if (pid == 0 || !arguments.is_object())
        return arguments;
    if (tool_args_have_explicit_pid(arguments))
        return arguments;
    const char* key = nullptr;
    if (tool_declares_param_named(tool, "process_id"))
        key = "process_id";
    else if (tool_declares_param_named(tool, "target_pid"))
        key = "target_pid";
    else if (tool_declares_param_named(tool, "pid"))
        key = "pid";
    if (!key)
        return arguments;
    json copy = arguments;
    copy[key] = pid;
    if (added)
        *added = true;
    return copy;
}

static bool is_analysis_session_management_tool(const std::string& name)
{
    return name.rfind("sessions_", 0) == 0;
}

static bool is_active_session_independent_tool(const std::string& name)
{
    if (name == "get_tool_descriptions" ||
        name == "vm_bridge_manage" ||
        name == "list_processes" ||
        name == "disassemble_file" ||
        name == "sandbox_execute" ||
        is_camoufox_browser_tool_name(name)) {
        return true;
    }
    if (name.rfind("burp_", 0) == 0 ||
        name.rfind("browser_", 0) == 0 ||
        name.rfind("gameproto_", 0) == 0 ||
        name.rfind("net_proto_", 0) == 0 ||
        name.rfind("net_security_", 0) == 0 ||
        name.rfind("workflow_", 0) == 0) {
        return true;
    }
    return false;
}

static std::string predicted_tool_lane(const tool_def_t& tool, const json& arguments)
{
    const bool session_manager = is_analysis_session_management_tool(tool.name);
    const bool session_independent = is_active_session_independent_tool(tool.name);
    json target_arguments_storage;
    const json& target_arguments = target_resolution_args_for_tool(tool, arguments, target_arguments_storage, false);
    const bool explicit_target = tool_args_select_session_target(target_arguments);
    if (session_independent && tool.read_only && !session_manager)
        return "independent_unlocked";
    if (session_independent && !tool.read_only && !session_manager) {
        const std::string domain = infer_tool_domain(tool.name);
        return "exclusive_domain_" + (domain.empty() ? std::string("misc") : domain);
    }
    if (session_manager)
        return "exclusive_session_manager";
    if (!tool.read_only)
        return "exclusive_mutating";
    if (!explicit_target)
        return "shared_active";
    return "shared_explicit_or_target_switch";
}

static tool_result_t invoke_tool_handler_unlocked(
    const std::string& tool_name,
    const json& arguments,
    const std::function<tool_result_t(const json&)>& handler,
    tool_invocation_metrics_t* metrics = nullptr)
{
    const std::uint64_t start = mcp_now_ms();
    try {
        tool_result_t result = handler(arguments);
        if (metrics)
            metrics->handler_elapsed_ms += mcp_now_ms() - start;
        return result;
    } catch (const std::exception& e) {
        if (metrics)
            metrics->handler_elapsed_ms += mcp_now_ms() - start;
        diag::log_tagged_fmt("mcp_srv", "handle_tools_call exception tool='%s' what='%s'",
            tool_name.c_str(), e.what());
        return tool_result_t::error(std::string("Tool threw exception: ") + e.what());
    } catch (...) {
        if (metrics)
            metrics->handler_elapsed_ms += mcp_now_ms() - start;
        diag::log_tagged_fmt("mcp_srv", "handle_tools_call unknown_exception tool='%s'", tool_name.c_str());
        return tool_result_t::error("Tool threw unknown exception");
    }
}

static tool_result_t invoke_tool_handler_guarded(
    const std::string& tool_name,
    const json& arguments,
    const std::function<tool_result_t(const json&)>& handler,
    tool_invocation_metrics_t* metrics,
    const char* lane,
    active_session_owner_guard_t* owner_guard = nullptr)
{
    const std::uint64_t start = mcp_now_ms();
    tool_result_t result;
    bool completed = false;
    if (owner_guard)
        owner_guard->set_phase("handler_enter");
    std::function<void()> guarded = [&]() {
        result = invoke_tool_handler_unlocked(tool_name, arguments, handler, metrics);
        completed = true;
    };
    const DWORD seh_code = aida::infra::win_thread::run_function_seh_guarded(guarded);
    if (seh_code != 0) {
        const std::uint64_t elapsed_ms = mcp_now_ms() >= start ? mcp_now_ms() - start : 0;
        if (metrics)
            metrics->handler_elapsed_ms += elapsed_ms;
        if (owner_guard)
            owner_guard->note_seh(seh_code, elapsed_ms);
        json details = {
            {"tool", tool_name},
            {"lane", lane ? lane : ""},
            {"diagnostic_id", current_call_diag_id()},
            {"seh_code", static_cast<std::uint32_t>(seh_code)},
            {"seh_code_hex", hex32_string(seh_code)},
            {"pid", GetCurrentProcessId()},
            {"tid", GetCurrentThreadId()},
            {"handler_elapsed_ms", elapsed_ms},
            {"deadline_ms", current_call_deadline_ms()},
            {"cancelled", current_call_cancelled()},
            {"completed", completed}
        };
        const active_session_owner_snapshot_t owner = active_session_owner_snapshot();
        append_active_session_owner_fields(details, owner);
        diag::log_tagged_fmt("mcp_srv",
            "handle_tools_call_seh tool='%s' lane=%s diag_id=%s code=0x%08lX elapsed_ms=%llu pid=%lu tid=%lu deadline_ms=%llu cancelled=%d owner_tool='%s' owner_lane=%s owner_diag_id=%s owner_pid=%lu owner_tid=%lu owner_age_ms=%llu owner_phase=%s shared_owner_count=%zu completed=%d",
            tool_name.c_str(),
            lane ? lane : "",
            current_call_diag_id(),
            static_cast<unsigned long>(seh_code),
            static_cast<unsigned long long>(elapsed_ms),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(current_call_deadline_ms()),
            current_call_cancelled() ? 1 : 0,
            owner.tool.c_str(),
            owner.lane.c_str(),
            owner.diag_id.c_str(),
            static_cast<unsigned long>(owner.pid),
            static_cast<unsigned long>(owner.tid),
            static_cast<unsigned long long>(owner.owner_age_ms),
            owner.phase.c_str(),
            owner.shared_owner_count,
            completed ? 1 : 0);
        return tool_result_t::error("Tool handler raised a structured exception and was contained fail-closed.", "tool_handler_seh", details);
    }
    if (owner_guard)
        owner_guard->set_phase("handler_exit");
    return result;
}

static tool_result_t invoke_tool_with_concurrency_policy(
    const tool_def_t& tool,
    const json& arguments,
    const std::function<tool_result_t(const json&)>& handler,
    tool_invocation_metrics_t* metrics = nullptr)
{
    const bool session_manager = is_analysis_session_management_tool(tool.name);
    const bool session_independent = is_active_session_independent_tool(tool.name);
    json target_arguments_storage;
    const json& target_arguments = target_resolution_args_for_tool(tool, arguments, target_arguments_storage, true);
    const bool explicit_target = tool_args_select_session_target(target_arguments);
    const std::string domain = infer_tool_domain(tool.name);

    if (session_independent && tool.read_only && !session_manager) {
        set_tool_metrics_lane(metrics, "independent_unlocked", 0);
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lane tool='%s' lane=independent_unlocked read_only=1 explicit_target=%d lock_wait_ms=0",
            tool.name.c_str(),
            explicit_target ? 1 : 0);
        return invoke_tool_handler_guarded(tool.name, arguments, handler, metrics, "independent_unlocked");
    }

    if (session_independent && !tool.read_only && !session_manager) {
        const std::uint64_t wait_start = mcp_now_ms();
        std::unique_lock<std::mutex> lk(domain_lane_mutex(domain));
        const std::uint64_t wait_ms = mcp_now_ms() - wait_start;
        const std::string lane = "exclusive_domain_" + (domain.empty() ? std::string("misc") : domain);
        set_tool_metrics_lane(metrics, lane, wait_ms);
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lane tool='%s' lane=%s read_only=0 explicit_target=%d lock_wait_ms=%llu",
            tool.name.c_str(),
            lane.c_str(),
            explicit_target ? 1 : 0,
            static_cast<unsigned long long>(wait_ms));
        return invoke_tool_handler_guarded(tool.name, arguments, handler, metrics, lane.c_str());
    }

    if (session_manager || !tool.read_only) {
        const char* lane = session_manager ? "exclusive_session_manager" :
            (session_independent ? "exclusive_independent_mutating" : "exclusive_mutating");
        std::unique_lock<std::shared_mutex> lk(active_session_tool_mutex(), std::defer_lock);
        const policy_lock_wait_t wait = acquire_policy_unique_lock(lk, tool.name, lane, tool.read_only, explicit_target);
        if (wait.status != policy_lock_status_t::acquired) {
            set_tool_metrics_lane(metrics, lane, wait.wait_ms);
            return policy_lock_error_result(tool.name, lane, wait);
        }
        const std::uint64_t wait_ms = wait.wait_ms;
        set_tool_metrics_lane(metrics, lane, wait_ms);
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lane tool='%s' lane=%s read_only=%d explicit_target=%d lock_wait_ms=%llu",
            tool.name.c_str(),
            lane,
            tool.read_only ? 1 : 0,
            explicit_target ? 1 : 0,
            static_cast<unsigned long long>(wait_ms));
        active_session_owner_guard_t owner_guard(tool.name, lane, true, tool.read_only, explicit_target);
        if (!session_manager && !session_independent) {
            owner_guard.set_phase("target_resolve");
            std::string scope_err;
            target_scope_t scope = resolve_target(target_arguments, &scope_err);
            if (!scope.ok) {
                owner_guard.set_phase("target_resolve_failed");
                return tool_result_t::error(scope_err.empty() ? std::string("Unable to resolve target session") : scope_err);
            }
            if (metrics)
                metrics->resolved_target = true;
            return invoke_tool_handler_guarded(tool.name, arguments, handler, metrics, lane, &owner_guard);
        }
        return invoke_tool_handler_guarded(tool.name, arguments, handler, metrics, lane, &owner_guard);
    }

    if (!explicit_target) {
        std::shared_lock<std::shared_mutex> lk(active_session_tool_mutex(), std::defer_lock);
        const policy_lock_wait_t wait = acquire_policy_shared_lock(lk, tool.name, "shared_active", false);
        if (wait.status != policy_lock_status_t::acquired) {
            set_tool_metrics_lane(metrics, "shared_active", wait.wait_ms);
            return policy_lock_error_result(tool.name, "shared_active", wait);
        }
        const std::uint64_t wait_ms = wait.wait_ms;
        set_tool_metrics_lane(metrics, "shared_active", wait_ms);
        diag::log_tagged_fmt("mcp_srv",
            "tool_policy_lane tool='%s' lane=shared_active read_only=1 explicit_target=0 lock_wait_ms=%llu",
            tool.name.c_str(),
            static_cast<unsigned long long>(wait_ms));
        active_session_owner_guard_t owner_guard(tool.name, "shared_active", false, true, false);
        owner_guard.set_phase("target_resolve");
        std::string scope_err;
        target_scope_t scope = resolve_target(target_arguments, &scope_err);
        if (!scope.ok) {
            owner_guard.set_phase("target_resolve_failed");
            return tool_result_t::error(scope_err.empty() ? std::string("Unable to resolve target session") : scope_err);
        }
        if (metrics)
            metrics->resolved_target = true;
        return invoke_tool_handler_guarded(tool.name, arguments, handler, metrics, "shared_active", &owner_guard);
    }

    target_probe_t probe;
    std::uint64_t probe_wait_ms = 0;
    {
        std::shared_lock<std::shared_mutex> lk(active_session_tool_mutex(), std::defer_lock);
        const policy_lock_wait_t wait = acquire_policy_shared_lock(lk, tool.name, "shared_target_probe", true);
        if (wait.status != policy_lock_status_t::acquired) {
            set_tool_metrics_lane(metrics, "shared_target_probe", wait.wait_ms);
            return policy_lock_error_result(tool.name, "shared_target_probe", wait);
        }
        active_session_owner_guard_t owner_guard(tool.name, "shared_target_probe", false, true, true);
        owner_guard.set_phase("target_probe");
        probe_wait_ms = wait.wait_ms;
        probe = probe_target_without_switch(target_arguments);
        if (!probe.ok) {
            set_tool_metrics_lane(metrics, "shared_target_reject", probe_wait_ms);
            owner_guard.set_lane("shared_target_reject");
            owner_guard.set_phase("target_probe_failed");
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_lane tool='%s' lane=shared_target_reject read_only=1 explicit_target=1 lock_wait_ms=%llu err='%.160s'",
                tool.name.c_str(),
                static_cast<unsigned long long>(probe_wait_ms),
                probe.err.c_str());
            return tool_result_t::error(probe.err.empty() ? std::string("Unable to resolve target session") : probe.err);
        }
        if (!probe.resolved || probe.target_idx == probe.active_idx) {
            set_tool_metrics_lane(metrics, "shared_explicit_no_switch", probe_wait_ms);
            owner_guard.set_lane("shared_explicit_no_switch");
            diag::log_tagged_fmt("mcp_srv",
                "tool_policy_lane tool='%s' lane=shared_explicit_no_switch read_only=1 resolved=%d active_idx=%llu target_idx=%llu lock_wait_ms=%llu",
                tool.name.c_str(),
                probe.resolved ? 1 : 0,
                static_cast<unsigned long long>(probe.active_idx),
                static_cast<unsigned long long>(probe.target_idx),
                static_cast<unsigned long long>(probe_wait_ms));
            owner_guard.set_phase("target_resolve");
            std::string scope_err;
            target_scope_t scope = resolve_target(target_arguments, &scope_err);
            if (!scope.ok) {
                owner_guard.set_phase("target_resolve_failed");
                return tool_result_t::error(scope_err.empty() ? std::string("Unable to resolve target session") : scope_err);
            }
            if (metrics)
                metrics->resolved_target = true;
            bool added_pid = false;
            json handler_arguments = add_process_id_for_handler_if_supported(tool, arguments, probe.pid, &added_pid);
            if (probe.resolved && probe.pid != 0 && (tool_args_have_explicit_pid(arguments) || added_pid)) {
                diag::log_tagged_fmt("mcp_srv",
                    "tool_policy_lock_held_for_handler tool='%s' lane=shared_explicit_no_switch pid=%u added_pid=%d lock_wait_ms=%llu",
                    tool.name.c_str(),
                    probe.pid,
                    added_pid ? 1 : 0,
                    static_cast<unsigned long long>(probe_wait_ms));
            }
            return invoke_tool_handler_guarded(tool.name,
                handler_arguments,
                handler,
                metrics,
                "shared_explicit_no_switch",
                &owner_guard);
        }
    }

    std::unique_lock<std::shared_mutex> lk(active_session_tool_mutex(), std::defer_lock);
    const policy_lock_wait_t wait = acquire_policy_unique_lock(lk, tool.name, "exclusive_target_switch", true, true);
    if (wait.status != policy_lock_status_t::acquired) {
        set_tool_metrics_lane(metrics, "exclusive_target_switch", probe_wait_ms + wait.wait_ms);
        return policy_lock_error_result(tool.name, "exclusive_target_switch", wait);
    }
    const std::uint64_t wait_ms = wait.wait_ms;
    set_tool_metrics_lane(metrics, "exclusive_target_switch", probe_wait_ms + wait_ms);
    diag::log_tagged_fmt("mcp_srv",
        "tool_policy_lane tool='%s' lane=exclusive_target_switch read_only=1 active_idx=%llu target_idx=%llu probe_wait_ms=%llu lock_wait_ms=%llu",
        tool.name.c_str(),
        static_cast<unsigned long long>(probe.active_idx),
        static_cast<unsigned long long>(probe.target_idx),
        static_cast<unsigned long long>(probe_wait_ms),
        static_cast<unsigned long long>(wait_ms));
    active_session_owner_guard_t owner_guard(tool.name, "exclusive_target_switch", true, true, true);
    owner_guard.set_phase("target_resolve");
    std::string scope_err;
    target_scope_t scope = resolve_target(target_arguments, &scope_err);
    if (!scope.ok) {
        owner_guard.set_phase("target_resolve_failed");
        return tool_result_t::error(scope_err.empty() ? std::string("Unable to resolve target session") : scope_err);
    }
    if (metrics)
        metrics->resolved_target = true;
    return invoke_tool_handler_guarded(tool.name, arguments, handler, metrics, "exclusive_target_switch", &owner_guard);
}

bool server_t::register_tool(tool_def_t tool)
{
    if (is_standalone_ide_chat_only_tool_name(tool.name))
        tool.visibility = tool_visibility_t::ide_chat_only;
    else if (is_standalone_internal_only_tool_name(tool.name))
        tool.visibility = tool_visibility_t::internal_only;

    bool already_has_binary_id = false;
    for (const auto& p : tool.params) {
        if (p.name == "binary_id") { already_has_binary_id = true; break; }
    }
    bool is_targetless_tool = tool.name.rfind("sessions_", 0) == 0 ||
                              tool.name == "get_tool_descriptions" ||
                              is_camoufox_browser_tool_name(tool.name);
    if (!already_has_binary_id && !is_targetless_tool) {
        tool.params.push_back(tool_param_t{
            "binary_id",
            "string",
            "Optional session id to target (returned by `sessions_manage` action=list). When omitted the active session is used.",
            false
        });
    }
    std::lock_guard<std::mutex> lk(_tools_mtx);
    auto dup = std::find_if(_tools.begin(), _tools.end(), [&](const tool_def_t& existing) {
        return existing.name == tool.name;
    });
    if (dup != _tools.end()) {
        if (tool.name == "decompile_function" &&
            dup->visibility == tool_visibility_t::external_visible &&
            tool.visibility == tool_visibility_t::external_visible) {
            diag::log_tagged_fmt("mcp_srv",
                "register_tool updated name='%s' visibility=%d",
                tool.name.c_str(), static_cast<int>(tool.visibility));
            *dup = std::move(tool);
            return true;
        }
        diag::log_tagged_fmt("mcp_srv",
            "register_tool duplicate skipped name='%s' existing_visibility=%d new_visibility=%d",
            tool.name.c_str(), static_cast<int>(dup->visibility), static_cast<int>(tool.visibility));
        return false;
    }
    _tools.push_back(std::move(tool));
    return true;
}

tool_result_t server_t::call_registered_tool(const std::string& name, const json& arguments, bool external_visible_only)
{
    if (name.empty())
        return tool_result_t::error("Missing tool name");

    tool_def_t found;
    bool found_tool = false;
    std::function<tool_result_t(const json&)> handler_copy;
    {
        std::lock_guard<std::mutex> lk(_tools_mtx);
        for (const auto& t : _tools) {
            if (t.name != name)
                continue;
            if (external_visible_only && !is_external_mcp_tool(t))
                return tool_result_t::error("Unknown tool: " + name);
            found = t;
            handler_copy = t.handler;
            found_tool = true;
            break;
        }
    }

    if (!found_tool)
        return tool_result_t::error("Unknown tool: " + name);
    if (!handler_copy)
        return tool_result_t::error("Tool has no handler: " + name);
    tool_invocation_metrics_t metrics;
    return invoke_tool_with_concurrency_policy(found, arguments, handler_copy, &metrics);
}

json server_t::make_result(const json& id, const json& result)
{
    json r;
    r["jsonrpc"] = "2.0";
    r["id"]      = id;
    r["result"]  = result;
    return r;
}

json server_t::make_error(const json& id, int code, const std::string& msg)
{
    json r;
    r["jsonrpc"]          = "2.0";
    r["id"]               = id;
    r["error"]["code"]    = code;
    r["error"]["message"] = msg;
    return r;
}

json server_t::tool_schema(const tool_def_t& tool, bool compact) const
{
    json input_schema = build_input_schema(tool);
    json annotations;
    annotations["title"]           = snake_to_title(tool.name);
    annotations["readOnlyHint"]    = tool.read_only;
    annotations["destructiveHint"] = (!tool.read_only);
    annotations["idempotentHint"]  = tool.read_only;
    annotations["openWorldHint"]   = (tool.name == "sandbox_execute");

    if (compact && tool.name != "get_tool_descriptions") {
        json t;
        t["name"]        = tool.name;
        t["description"] = tool.description;
        t["inputSchema"] = input_schema;
        t["read_only"]   = tool.read_only;
        t["visibility"]  = visibility_name(tool.visibility);
        const std::string domain = infer_tool_domain(tool.name);
        if (!domain.empty())
            t["domain"] = domain;
        t["annotations"] = json{
            {"readOnlyHint", tool.read_only},
            {"destructiveHint", !tool.read_only}
        };
        return t;
    }

    json t;
    t["name"]        = tool.name;
    t["description"] = tool.description;
    t["inputSchema"] = input_schema;
    t["annotations"] = annotations;
    t["read_only"]   = tool.read_only;
    t["visibility"]  = visibility_name(tool.visibility);
    const std::string domain = infer_tool_domain(tool.name);
    if (!domain.empty())
        t["domain"] = domain;
    return t;
}

static bool has_structured_tool_error(const tool_result_t& tr)
{
    return !tr.success && (!tr.error_code.empty() || (!tr.error_details.is_null() && !tr.error_details.empty()));
}

static json structured_tool_error(const tool_result_t& tr)
{
    json err = json::object();
    err["message"] = tr.text;
    if (!tr.error_code.empty())
        err["code"] = tr.error_code;
    if (!tr.error_details.is_null() && !tr.error_details.empty())
        err["details"] = tr.error_details;
    return err;
}

static json tool_diagnostics_json(
    std::uint64_t seq,
    const std::string& diag_id,
    const std::string& request_id,
    const std::string& tool_name,
    const std::string& domain,
    bool read_only,
    std::uint32_t target_pid,
    std::uint64_t timeout_ms,
    std::uint64_t deadline_ms,
    const std::string& payload_shape,
    const std::string& validation_status,
    const std::string& dependency_status,
    const tool_invocation_metrics_t& metrics,
    const std::shared_ptr<mcp_executor_task_meta_t>& meta,
    bool cancelled)
{
    std::uint64_t queue_wait_ms = 0;
    std::uint64_t queued_age_ms = 0;
    std::uint64_t active_age_ms = 0;
    const std::uint64_t now = mcp_now_ms();
    if (meta) {
        std::lock_guard<std::mutex> lk(meta->mtx);
        queue_wait_ms = meta->queue_wait_ms;
        queued_age_ms = meta->queued_at != 0 && now >= meta->queued_at ? now - meta->queued_at : 0;
        active_age_ms = meta->active_at != 0 && now >= meta->active_at ? now - meta->active_at : 0;
    }
    json d;
    d["seq"] = seq;
    d["diagnostic_id"] = diag_id;
    d["request_id"] = request_id;
    d["method"] = "tools/call";
    d["tool"] = tool_name;
    d["domain"] = domain;
    d["lane"] = metrics.lane;
    d["read_only"] = read_only;
    d["target_pid"] = target_pid;
    d["queue_wait_ms"] = queue_wait_ms;
    d["queued_age_ms"] = queued_age_ms;
    d["active_age_ms"] = active_age_ms;
    d["lock_wait_ms"] = metrics.lock_wait_ms;
    d["handler_elapsed_ms"] = metrics.handler_elapsed_ms;
    d["timeout_ms"] = timeout_ms;
    d["deadline_ms"] = deadline_ms;
    d["deadline_remaining_ms"] = deadline_ms != 0 && now < deadline_ms ? deadline_ms - now : 0;
    d["cancelled"] = cancelled;
    d["payload_shape"] = payload_shape;
    d["validation_status"] = validation_status;
    d["dependency_status"] = dependency_status;
    d["resolved_target"] = metrics.resolved_target;
    return d;
}

tool_result_t server_t::describe_tools(const json& params)
{
    const std::uint64_t begin_ms = mcp_now_ms();
    std::vector<std::string> names;
    if (params.is_object()) {
        if (params.contains("names") && params["names"].is_array()) {
            for (const auto& n : params["names"]) {
                if (n.is_string())
                    names.push_back(n.get<std::string>());
            }
        } else if (params.contains("names") && params["names"].is_string()) {
            names.push_back(params["names"].get<std::string>());
        }
        if (params.contains("name") && params["name"].is_string())
            names.push_back(params["name"].get<std::string>());
    }

    std::string prefix;
    std::string query;
    std::string group;
    std::string group_source;
    bool include_schema = true;
    int limit = 40;
    bool explicit_limit = false;
    if (params.is_object()) {
        if (params.contains("prefix") && params["prefix"].is_string())
            prefix = params["prefix"].get<std::string>();
        if (params.contains("query") && params["query"].is_string())
            query = params["query"].get<std::string>();
        if (params.contains("group") && params["group"].is_string()) {
            group_source = params["group"].get<std::string>();
            group = normalize_tool_group_name(group_source);
        }
        if (params.contains("include_schema") && params["include_schema"].is_boolean())
            include_schema = params["include_schema"].get<bool>();
        if (params.contains("limit") && params["limit"].is_number_integer()) {
            limit = params["limit"].get<int>();
            explicit_limit = true;
        }
    }
    if (names.empty() && prefix.empty() && group.empty() && !query.empty()) {
        const std::string query_group = normalize_tool_group_name(query);
        if (!query_group.empty()) {
            group = query_group;
            group_source = query;
        }
    }
    if (!group.empty() && !explicit_limit)
        limit = 100;
    limit = (std::max)(1, (std::min)(limit, 100));

    std::vector<tool_def_t> matches;
    {
        std::lock_guard<std::mutex> lk(_tools_mtx);
        if (!names.empty()) {
            for (const auto& wanted : names) {
                for (const auto& tool : _tools) {
                    if (!is_external_mcp_tool(tool))
                        continue;
                    if (tool.name == wanted) {
                        auto dup = std::find_if(matches.begin(), matches.end(),
                            [&](const tool_def_t& existing) { return existing.name == tool.name; });
                        if (dup == matches.end())
                            matches.push_back(tool);
                        break;
                    }
                }
            }
        } else if (!group.empty()) {
            for (const auto& tool : _tools) {
                if (current_call_cancelled())
                    return tool_result_t::error("Tool description query cancelled.");
                if (!is_external_mcp_tool(tool))
                    continue;
                if (tool_matches_description_group(tool, group))
                    matches.push_back(tool);
            }
            std::sort(matches.begin(), matches.end(), [](const tool_def_t& a, const tool_def_t& b) {
                return a.name < b.name;
            });
        } else if (!prefix.empty() || !query.empty()) {
            const std::string prefix_l = lower_ascii(prefix);
            const std::string query_l = lower_ascii(query);
            for (const auto& tool : _tools) {
                if (current_call_cancelled())
                    return tool_result_t::error("Tool description query cancelled.");
                if (!is_external_mcp_tool(tool))
                    continue;
                const std::string name_l = lower_ascii(tool.name);
                const std::string desc_l = lower_ascii(tool.description);
                bool ok = true;
                if (!prefix_l.empty())
                    ok = name_l.rfind(prefix_l, 0) == 0;
                if (ok && !query_l.empty())
                    ok = name_l.find(query_l) != std::string::npos ||
                         desc_l.find(query_l) != std::string::npos;
                if (ok)
                    matches.push_back(tool);
            }
        }
    }

    if (names.empty() && prefix.empty() && query.empty() && group.empty())
        return tool_result_t::ok("Pass `names`, `name`, `prefix`, `query`, or `group` to retrieve full tool descriptions.");

    if (matches.empty()) {
        json data;
        data["tools"] = json::array();
        data["matched_count"] = 0;
        data["returned_count"] = 0;
        data["limit"] = limit;
        if (!group.empty()) {
            const std::uint64_t elapsed_ms = mcp_now_ms() - begin_ms;
            data["group"] = group;
            data["diagnostics"] = {
                {"group", group},
                {"matched_before_limit", 0},
                {"matched_after_limit", 0},
                {"limit", limit},
                {"elapsed_ms", elapsed_ms}
            };
            diag::log_tagged_fmt("mcp_srv",
                "tool_descriptions_group group='%s' source_len=%zu matched_before_limit=0 matched_after_limit=0 limit=%d elapsed_ms=%llu",
                group.c_str(),
                group_source.size(),
                limit,
                static_cast<unsigned long long>(elapsed_ms));
        }
        return tool_result_t::ok("No matching tools found.", data);
    }

    const size_t shown = (std::min)(matches.size(), static_cast<size_t>(limit));
    json data;
    data["tools"] = json::array();
    data["matched_count"] = matches.size();
    data["returned_count"] = shown;
    data["limit"] = limit;
    data["include_schema"] = include_schema;
    if (!group.empty())
        data["group"] = group;
    for (size_t i = 0; i < shown; ++i) {
        if (current_call_cancelled())
            return tool_result_t::error("Tool description query cancelled.");
        const auto& tool = matches[i];
        if (include_schema) {
            data["tools"].push_back(tool_schema(tool, false));
        } else {
            json t;
            t["name"] = tool.name;
            t["description"] = tool.description;
            t["read_only"] = tool.read_only;
            t["visibility"] = visibility_name(tool.visibility);
            const std::string domain = infer_tool_domain(tool.name);
            if (!domain.empty())
                t["domain"] = domain;
            data["tools"].push_back(std::move(t));
        }
    }
    if (!group.empty()) {
        const std::uint64_t elapsed_ms = mcp_now_ms() - begin_ms;
        data["diagnostics"] = {
            {"group", group},
            {"matched_before_limit", matches.size()},
            {"matched_after_limit", shown},
            {"limit", limit},
            {"elapsed_ms", elapsed_ms}
        };
        diag::log_tagged_fmt("mcp_srv",
            "tool_descriptions_group group='%s' source_len=%zu matched_before_limit=%zu matched_after_limit=%zu limit=%d elapsed_ms=%llu",
            group.c_str(),
            group_source.size(),
            matches.size(),
            shown,
            limit,
            static_cast<unsigned long long>(elapsed_ms));
    }

    std::string result;
    result.reserve(shown * 256);
    if (matches.size() > shown) {
        result += "Showing " + std::to_string(shown) + " of " +
                  std::to_string(matches.size()) +
                  " matching tools. Refine with `name`, `names`, `prefix`, `query`, or `group`.\n\n";
    }
    if (!group.empty()) {
        result += "Group: " + group + "\n";
        result += "Matched: " + std::to_string(matches.size()) + ", returned: " + std::to_string(shown) + ", limit: " + std::to_string(limit) + "\n\n";
    }
    for (size_t i = 0; i < shown; ++i) {
        if (current_call_cancelled())
            return tool_result_t::error("Tool description query cancelled.");
        const auto& tool = matches[i];
        result += "### " + tool.name + "\n";
        if (!tool.description.empty())
            result += tool.description + "\n";
        result += std::string("Read-only: ") + (tool.read_only ? "true" : "false") + "\n";
        if (include_schema) {
            if (tool.params.empty()) {
                result += "Parameters: none\n";
            } else {
                result += "Parameters:\n";
                for (const auto& p : tool.params) {
                    result += "- `" + p.name + "` (" + p.type;
                    if (p.required)
                        result += ", required";
                    result += ")";
                    if (!p.description.empty())
                        result += ": " + p.description;
                    result += "\n";
                }
            }
        }
        result += "\n";
    }
    return tool_result_t::ok(result, data);
}

json server_t::handle_initialize(const json& id, const json&)
{
    diag::log_tagged_fmt("mcp_srv", "handle_initialize entry");
    json capabilities;
    capabilities["tools"]     = {{"listChanged", true}};
    capabilities["resources"] = {{"listChanged", true}};
    capabilities["prompts"]   = {{"listChanged", true}};
    capabilities["logging"]   = json::object();

    json server_info;
    server_info["name"]    = SERVER_NAME;
    server_info["version"] = SERVER_VERSION;

    static const char* instructions =
        "AiDAStandalone MCP is self-describing. Do not expect external markdown files such as TOOLS.md; shipped users normally receive only AiDAStandalone.exe and AiDA.dll. Learn the available surface from this initialize response, `tools/list`, and targeted `get_tool_descriptions` calls.\n\n"
        "You are connected to AiDAStandalone, a reverse-engineering assistant "
        "for standalone static binary sessions, live process/runtime inspection, "
        "kernel-backed debugger/memory workflows, Windows Sandbox sample execution, "
        "and browser/network reversing through bundled Camoufox MCP tools.\n\n"
        "## Capabilities\n"
        "- Open and analyze PE/ELF/Mach-O/SYS files as standalone static sessions\n"
        "- Read live process memory from an attached process\n"
        "- Disassemble x64 code at live addresses or from files\n"
        "- Attach to or detach from running processes when runtime access is required\n"
        "- Execute untrusted binaries in Windows Sandbox when explicitly requested\n"
        "- Convert integers, endian bytes, ASCII, signed/unsigned views, IEEE-754 values, alignment, VA, RVA, module-relative, and PE file-offset references\n"
        "- Use bundled Camoufox reverse-engineering browser tools through grouped actions exposed as `browser_lifecycle`, `browser_navigation`, `browser_interaction`, `browser_inspect`, `browser_state`, `browser_network`, `browser_hooks`, and `browser_instrumentation`\n\n"
        "## First-use workflow\n"
        "- Use `get_tool_descriptions` with `names`, `prefix`, or `query` for only the tools you plan to call; do not spam broad discovery calls\n"
        "- For standalone static binaries, use `sessions_manage` action `open_file`, then `analysis_query` action `binary_map_overview` or `disasm_get_section_info`, `disasm_list_functions`, and targeted disassembly/decompilation tools\n"
        "- For live runtime work, use `sessions_manage` action `attach_pid` for session attachment, then memory/disassembly tools.\n"
        "- When a VM bridge is active, pass `target: \"guest\"` or `target: \"host\"` explicitly whenever host/VM memory matters\n"
        "- Use `vm_bridge_manage` to activate and inspect custom VMware, VirtualBox, QEMU, Hyper-V, or manually managed Windows VM bridges\n"
        "- Custom VM workflows use a private shared-folder bridge: keep AiDAStandalone.exe on the host and run only the sample plus AiDAGuestAgent.exe in the guest\n"
        "- Do not bind AiDA's MCP endpoint directly to a guest, LAN, or untrusted adapter; use `vm_bridge_manage` plus the file-backed bridge instead\n"
        "- Cache session IDs, binary IDs, module bases, function bounds, xrefs, scan state, and decompiler output; avoid duplicate calls with identical parameters\n"
        "- Prefer batch or paginated tools over repeated one-off calls; set limits before large scans\n\n"
        "## Address and conversion rules\n"
        "- Prefer hex strings such as `0x140001000`\n"
        "- Live/debugger addresses are process VAs; stable references should include module+RVA when module context is known\n"
        "- Static file tools may return image base, section RVA, and raw file-offset context; carry that context forward\n"
        "- Use `convert_number` for all number, byte, signedness, float, VA/RVA, module-base, and PE file-offset conversions; never hand-convert offsets or byte values\n\n"
        "## Safety and mutation rules\n"
        "- `read_only=true` tools inspect state; `read_only=false` tools may mutate process memory, debugger state, files, browser state, proxy state, sandbox state, or analysis/session state\n"
        "- Only call mutating tools when the user asked for that action and the target is clear\n"
        "- Runtime, debugger, sandbox, browser interception, and filesystem tools are local trust-boundary tools even though the server binds to localhost\n\n"
        "## Browser/runtime shortcuts\n"
        "- For browser tasks, call `browser_lifecycle` with `action=launch` first when no Camoufox session is running, then call `browser_navigation` with `action=navigate` and a fully-qualified URL\n"
        "- Do not call session/driver attach or list helpers before browser-only work unless the user asks for diagnostics or runtime access\n"
        "- For runtime inspection, open or verify the process target with `sessions_manage` (`action=list` or `action=attach_pid`) and then use `query_memory`, `read_memory`, or `disassemble_zydis` as needed\n"
        "- Use `list_processes` if you need PID and process context before `sessions_manage` attachment\n"
        "- Use `disassemble_zydis` for live memory; `disassemble_file` for PE files\n"
        "- Use `sandbox_execute` for running untrusted binaries safely when the user requests execution\n";

    json result;
    result["protocolVersion"] = PROTOCOL_VERSION;
    result["capabilities"]    = capabilities;
    result["serverInfo"]      = server_info;
    result["instructions"]    = instructions;
    return make_result(id, result);
}

json server_t::handle_ping(const json& id, const json&)
{
    return make_result(id, json::object());
}

json server_t::handle_tools_list(const json& id, const json& params)
{
    json tools_arr = json::array();
    const bool compact = !wants_full_tool_list(params);
    {
        std::lock_guard<std::mutex> lk(_tools_mtx);
        for (const auto& t : _tools) {
            if (!is_external_mcp_tool(t)) continue;
            tools_arr.push_back(tool_schema(t, compact));
        }
    }
    diag::log_tagged_fmt("mcp_srv", "handle_tools_list compact=%d count=%zu",
        compact ? 1 : 0, tools_arr.size());
    json result;
    result["tools"] = tools_arr;
    result["_meta"] = {
        {"aidaToolListMode", compact ? "compact" : "full"},
        {"aidaToolDetailTool", "get_tool_descriptions"}
    };
    return make_result(id, result);
}

json server_t::handle_tools_call(const json& id, const json& params)
{
    const std::uint64_t seq = g_tool_call_seq.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    const std::string request_id = request_id_string(id);
    const std::string diag_id = "mcp-tool-" + std::to_string(seq);
    const std::uint64_t call_begin = mcp_now_ms();

    if (!params.contains("name") || !params["name"].is_string()) {
        diag::log_tagged_fmt("mcp_srv",
            "tool_call_validation_failed seq=%llu diag_id=%s request_id='%s' reason=missing_name payload_shape='%s'",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            request_id.c_str(),
            payload_shape_summary(params).c_str());
        return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'name'");
    }

    const std::string early_name = params["name"].get<std::string>();
    diag::log_tagged_fmt("mcp_srv",
        "handle_tools_call seq=%llu diag_id=%s request_id='%s' tool='%s'",
        static_cast<unsigned long long>(seq),
        diag_id.c_str(),
        request_id.c_str(),
        early_name.c_str());

    require_mcp_runtime_authorized("tools_call");

    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_mcp_tool_exec);
        if (!standalone_license::verify_tool_runtime(
                standalone_license::gate_mcp_tool_exec, gt, early_name)) {
            std::string error_text = standalone_license::decode_status_string(
                standalone_license::str_session_revoked);
            if (standalone_license::is_valid() && !standalone_license::is_arc_loaded()) {
                error_text = standalone_license::is_arc_download_in_progress()
                    ? "AiDA protected runtime is still loading. Try the tool again after activation finishes."
                    : "AiDA protected runtime is not loaded. Open AiDAStandalone.exe, activate the license, and wait for ARC initialization to complete.";
                const std::string last = standalone_license::last_error();
                if (!last.empty())
                    error_text += " Last license status: " + last;
            }
            diag::log_tagged_fmt("mcp_srv",
                "tool_call_validation_failed seq=%llu diag_id=%s tool='%s' reason=runtime_gate elapsed_ms=%llu",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                early_name.c_str(),
                static_cast<unsigned long long>(mcp_now_ms() - call_begin));
            return make_error(id, -32000, error_text);
        }
    }

    std::string tool_name = early_name;
    json arguments = params.contains("arguments") && params["arguments"].is_object()
                   ? params["arguments"] : json::object();
    const std::string payload_shape = payload_shape_summary(arguments);
    const std::uint32_t target_pid = target_pid_from_args(arguments);
    const tool_timeout_resolution_t timeout_resolution = resolve_tool_timeout(tool_name, arguments);
    const std::uint64_t timeout_ms = timeout_resolution.effective_ms;
    const std::uint64_t requested_deadline_ms = saturated_deadline_ms(call_begin, timeout_resolution.requested_ms);
    const std::uint64_t deadline_ms = saturated_deadline_ms(call_begin, timeout_ms);
    std::string validation_status = "params_ok";
    std::string dependency_status = "not_checked";

    if (is_standalone_ide_chat_only_tool_name(tool_name) || is_standalone_internal_only_tool_name(tool_name)) {
        diag::log_tagged_fmt("mcp_srv",
            "tool_call_validation_failed seq=%llu diag_id=%s tool='%s' reason=not_external payload_shape='%s'",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            tool_name.c_str(),
            payload_shape.c_str());
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + tool_name);
    }

    tool_def_t found;
    bool found_tool = false;
    std::function<tool_result_t(const json&)> handler_copy;
    {
        std::lock_guard<std::mutex> lk(_tools_mtx);
        for (const auto& t : _tools) {
            if (t.name == tool_name) {
                if (!is_external_mcp_tool(t)) {
                    return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + tool_name);
                }
                found = t;
                handler_copy = t.handler;
                found_tool = true;
                break;
            }
        }
    }

    if (!found_tool)
    {
        validation_status = "unknown_tool";
        diag::log_tagged_fmt("mcp_srv",
            "handle_tools_call unknown_tool='%s' seq=%llu diag_id=%s payload_shape='%s'",
            tool_name.c_str(),
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            payload_shape.c_str());
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + tool_name);
    }
    if (!handler_copy) {
        validation_status = "handler_missing";
        diag::log_tagged_fmt("mcp_srv",
            "tool_call_validation_failed seq=%llu diag_id=%s tool='%s' reason=handler_missing",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            tool_name.c_str());
        return make_error(id, JSONRPC_INTERNAL_ERROR, "Tool has no handler: " + tool_name);
    }

    if (is_driver_bridge_dependent_tool(found)) {
        std::string driver_reason;
        if (!driver_bridge::kernel_session_available(&driver_reason)) {
            dependency_status = "driver_unavailable";
            std::string detail = driver_bridge::last_error();
            if (detail.empty())
                detail = driver_bridge::status();
            diag::log_tagged_fmt("mcp_srv",
                "tool_driver_unavailable seq=%llu diag_id=%s tool='%s' reason='%s' detail='%.160s' license_valid=%d arc=%d",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                tool_name.c_str(),
                driver_reason.empty() ? "<empty>" : driver_reason.c_str(),
                detail.c_str(),
                standalone_license::is_valid() ? 1 : 0,
                standalone_license::is_arc_loaded() ? 1 : 0);
            std::string message = "Kernel driver bridge unavailable for tool '" + tool_name + "'";
            if (!driver_reason.empty())
                message += " (" + driver_reason + ")";
            message += ". App license and ARC authorization remain active; driver-backed capabilities are degraded while reconnect is pending.";
            if (!detail.empty())
                message += " Driver status: " + detail;
            json err = make_error(id, -32051, message);
            err["error"]["data"] = {
                {"diagnostic_id", diag_id},
                {"seq", seq},
                {"tool", tool_name},
                {"dependency_status", dependency_status},
                {"driver_reason", driver_reason},
                {"target_pid", target_pid},
                {"payload_shape", payload_shape}
            };
            return err;
        }
        dependency_status = "driver_ok";
    } else {
        dependency_status = "not_driver_dependent";
    }

    const std::string domain = infer_tool_domain(tool_name);
    tool_invocation_metrics_t dispatch_metrics;
    dispatch_metrics.lane = predicted_tool_lane(found, arguments);
    registered_call_scope_t call_scope(id);
    auto meta = make_executor_task_meta();
    {
        std::lock_guard<std::mutex> lk(meta->mtx);
        meta->request_id = request_id;
        meta->method = "tools/call";
        meta->tool = tool_name;
        meta->domain = domain;
        meta->lane = dispatch_metrics.lane;
        meta->deadline_ms = deadline_ms;
        meta->payload_shape = payload_shape;
        meta->cancel_token = call_scope.token;
    }
    const bool use_domain_executor = is_exclusive_domain_lane(dispatch_metrics.lane);
    const std::string queue_owner = use_domain_executor
        ? std::string("domain_executor_") + normalized_domain_key(domain)
        : std::string("tool_executor");
    const std::string queue_full_status = use_domain_executor
        ? std::string("domain_executor_queue_full")
        : std::string("tool_executor_queue_full");
    mcp_owned_executor_t& selected_executor = use_domain_executor
        ? mcp_domain_tool_executor(domain)
        : mcp_tool_executor();

    struct async_tool_call_state_t
    {
        std::promise<tool_result_t> promise;
        std::atomic<bool> started{false};
        std::atomic<bool> finished{false};
        std::atomic<bool> timed_out{false};
        std::mutex mtx;
        tool_invocation_metrics_t metrics;
    };

    auto state = std::make_shared<async_tool_call_state_t>();
    auto future = state->promise.get_future();
    diag::log_tagged_fmt("mcp_srv",
        "tool_call_enqueue seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' domain='%s' lane='%s' queue_owner=%s read_only=%d target_pid=%u requested_timeout_ms=%llu effective_timeout_ms=%llu requested_deadline_ms=%llu effective_deadline_ms=%llu timeout_source=%s timeout_max_ms=%llu action_aware=%d payload_shape='%s' validation=%s dependency=%s",
        static_cast<unsigned long long>(seq),
        diag_id.c_str(),
        request_id.c_str(),
        tool_name.c_str(),
        timeout_resolution.action.c_str(),
        domain.c_str(),
        dispatch_metrics.lane.c_str(),
        queue_owner.c_str(),
        found.read_only ? 1 : 0,
        target_pid,
        static_cast<unsigned long long>(timeout_resolution.requested_ms),
        static_cast<unsigned long long>(timeout_ms),
        static_cast<unsigned long long>(requested_deadline_ms),
        static_cast<unsigned long long>(deadline_ms),
        timeout_resolution.source.c_str(),
        static_cast<unsigned long long>(timeout_resolution.max_ms),
        timeout_resolution.action_aware ? 1 : 0,
        payload_shape.c_str(),
        validation_status.c_str(),
        dependency_status.c_str());

    auto task = [state, meta, call_token = call_scope.token, found, arguments, handler_copy, seq, diag_id, request_id, tool_name, domain, queue_owner, timeout_ms, deadline_ms, requested_timeout_ms = timeout_resolution.requested_ms, requested_deadline_ms, timeout_action = timeout_resolution.action, timeout_source = timeout_resolution.source, timeout_max_ms = timeout_resolution.max_ms, timeout_action_aware = timeout_resolution.action_aware, payload_shape, validation_status, dependency_status, target_pid, call_begin]() mutable {
        state->started.store(true, std::memory_order_release);
        scoped_call_cancel_t scoped_cancel(call_token);
        scoped_call_metadata_t scoped_metadata(diag_id, tool_name, deadline_ms);
        tool_invocation_metrics_t metrics;
        {
            std::lock_guard<std::mutex> lk(meta->mtx);
            metrics.lane = meta->lane;
        }
        diag::log_tagged_fmt("mcp_srv",
            "tool_call_handler_begin seq=%llu diag_id=%s request_id='%s' tool='%s' domain='%s' lane='%s' deadline_ms=%llu cancelled=%d",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            request_id.c_str(),
            tool_name.c_str(),
            domain.c_str(),
            metrics.lane.c_str(),
            static_cast<unsigned long long>(deadline_ms),
            call_token && call_token->load(std::memory_order_acquire) ? 1 : 0);
        const bool cancelled_before_dispatch = call_token && call_token->load(std::memory_order_acquire);
        const std::uint64_t dispatch_ms = mcp_now_ms();
        const bool expired_before_dispatch = deadline_ms != 0 && dispatch_ms >= deadline_ms;
        tool_result_t tr;
        if (cancelled_before_dispatch || expired_before_dispatch) {
            json stale;
            stale["diagnostic_id"] = diag_id;
            stale["request_id"] = request_id;
            stale["tool"] = tool_name;
            stale["action"] = timeout_action;
            stale["domain"] = domain;
            stale["lane"] = metrics.lane;
            stale["queue_owner"] = queue_owner;
            stale["requested_timeout_ms"] = requested_timeout_ms;
            stale["effective_timeout_ms"] = timeout_ms;
            stale["requested_deadline_ms"] = requested_deadline_ms;
            stale["effective_deadline_ms"] = deadline_ms;
            stale["dispatch_ms"] = dispatch_ms;
            stale["expired_before_dispatch"] = expired_before_dispatch;
            stale["cancelled_before_dispatch"] = cancelled_before_dispatch;
            stale["timeout_source"] = timeout_source;
            stale["timeout_max_ms"] = timeout_max_ms;
            stale["action_aware_timeout"] = timeout_action_aware;
            const char* stale_code = expired_before_dispatch ? "tool_dispatch_deadline_expired" : "tool_dispatch_cancelled";
            tr = tool_result_t::error(expired_before_dispatch
                ? std::string("Tool call expired before handler dispatch.")
                : std::string("Tool call was cancelled before handler dispatch."),
                stale_code,
                stale);
            state->timed_out.store(true, std::memory_order_release);
            diag::log_tagged_fmt("mcp_srv",
                "tool_call_handler_skip seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' domain='%s' lane='%s' queue_owner=%s expired=%d cancelled=%d dispatch_delay_ms=%llu elapsed_ms=%llu",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                request_id.c_str(),
                tool_name.c_str(),
                timeout_action.c_str(),
                domain.c_str(),
                metrics.lane.c_str(),
                queue_owner.c_str(),
                expired_before_dispatch ? 1 : 0,
                cancelled_before_dispatch ? 1 : 0,
                static_cast<unsigned long long>(dispatch_ms >= call_begin ? dispatch_ms - call_begin : 0),
                static_cast<unsigned long long>(mcp_now_ms() - call_begin));
        } else {
            tr = invoke_tool_with_concurrency_policy(found, arguments, handler_copy, &metrics);
        }
        update_executor_task_lane(meta, metrics.lane);
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            state->metrics = metrics;
        }
        state->finished.store(true, std::memory_order_release);
        const bool timed_out = state->timed_out.load(std::memory_order_acquire);
        diag::log_tagged_fmt("mcp_srv",
            "tool_call_handler_done seq=%llu diag_id=%s tool='%s' action='%s' success=%d lane='%s' queue_owner=%s lock_wait_ms=%llu handler_elapsed_ms=%llu cancelled=%d timed_out=%d elapsed_ms=%llu",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            tool_name.c_str(),
            timeout_action.c_str(),
            tr.success ? 1 : 0,
            metrics.lane.c_str(),
            queue_owner.c_str(),
            static_cast<unsigned long long>(metrics.lock_wait_ms),
            static_cast<unsigned long long>(metrics.handler_elapsed_ms),
            call_token && call_token->load(std::memory_order_acquire) ? 1 : 0,
            timed_out ? 1 : 0,
            static_cast<unsigned long long>(mcp_now_ms() - call_begin));
        if (timed_out && is_camoufox_browser_tool_name(tool_name))
        {
            diag::log_tagged_fmt("mcp_srv",
                "browser_tool_late_result_disposition seq=%llu diag_id=%s request_id='%s' queue_owner=%s tool='%s' action='%s' lane='%s' success=%d requested_timeout_ms=%llu effective_timeout_ms=%llu requested_deadline_ms=%llu effective_deadline_ms=%llu timeout_source=%s timeout_max_ms=%llu action_aware=%d elapsed_ms=%llu cancelled=%d disposition=discarded_after_timeout",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                request_id.c_str(),
                queue_owner.c_str(),
                tool_name.c_str(),
                timeout_action.c_str(),
                metrics.lane.c_str(),
                tr.success ? 1 : 0,
                static_cast<unsigned long long>(requested_timeout_ms),
                static_cast<unsigned long long>(timeout_ms),
                static_cast<unsigned long long>(requested_deadline_ms),
                static_cast<unsigned long long>(deadline_ms),
                timeout_source.c_str(),
                static_cast<unsigned long long>(timeout_max_ms),
                timeout_action_aware ? 1 : 0,
                static_cast<unsigned long long>(mcp_now_ms() - call_begin),
                call_token && call_token->load(std::memory_order_acquire) ? 1 : 0);
        }
        try {
            state->promise.set_value(std::move(tr));
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt("mcp_srv",
                "tool_call_promise_set_failed seq=%llu diag_id=%s tool='%s' err='%s'",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                tool_name.c_str(),
                ex.what());
        } catch (...) {
            diag::log_tagged_fmt("mcp_srv",
                "tool_call_promise_set_failed seq=%llu diag_id=%s tool='%s' err='<unknown>'",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                tool_name.c_str());
        }
    };

    if (!selected_executor.enqueue(std::move(task), meta)) {
        call_scope.cancel();
        dispatch_metrics.lane = predicted_tool_lane(found, arguments);
        json err = make_error(id, -32072, "MCP executor queue is full; tool was not started.");
        err["error"]["data"] = tool_diagnostics_json(
            seq, diag_id, request_id, tool_name, domain, found.read_only, target_pid,
            timeout_ms, deadline_ms, payload_shape, validation_status, queue_full_status,
            dispatch_metrics, meta, true);
        err["error"]["data"]["action"] = timeout_resolution.action;
        err["error"]["data"]["queue_owner"] = queue_owner;
        err["error"]["data"]["requested_timeout_ms"] = timeout_resolution.requested_ms;
        err["error"]["data"]["effective_timeout_ms"] = timeout_ms;
        err["error"]["data"]["requested_deadline_ms"] = requested_deadline_ms;
        err["error"]["data"]["effective_deadline_ms"] = deadline_ms;
        err["error"]["data"]["timeout_source"] = timeout_resolution.source;
        err["error"]["data"]["timeout_max_ms"] = timeout_resolution.max_ms;
        err["error"]["data"]["action_aware_timeout"] = timeout_resolution.action_aware;
        err["error"]["data"]["explicit_timeout"] = timeout_resolution.explicit_timeout;
        err["error"]["data"]["late_result_disposition"] = "not_started";
        diag::log_tagged_fmt("mcp_srv",
            "tool_call_enqueue_failed seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' queue_owner=%s reason=%s requested_timeout_ms=%llu effective_timeout_ms=%llu elapsed_ms=%llu late_result_disposition=not_started",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            request_id.c_str(),
            tool_name.c_str(),
            timeout_resolution.action.c_str(),
            queue_owner.c_str(),
            queue_full_status.c_str(),
            static_cast<unsigned long long>(timeout_resolution.requested_ms),
            static_cast<unsigned long long>(timeout_ms),
            static_cast<unsigned long long>(mcp_now_ms() - call_begin));
        return err;
    }

    const auto wait_status = future.wait_for(std::chrono::milliseconds(timeout_ms));
    if (wait_status != std::future_status::ready) {
        state->timed_out.store(true, std::memory_order_release);
        call_scope.cancel();
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            dispatch_metrics = state->metrics;
            if (dispatch_metrics.lane.empty())
                dispatch_metrics.lane = predicted_tool_lane(found, arguments);
        }
        json diag = tool_diagnostics_json(
            seq, diag_id, request_id, tool_name, domain, found.read_only, target_pid,
            timeout_ms, deadline_ms, payload_shape, validation_status, dependency_status,
            dispatch_metrics, meta, true);
        diag["started"] = state->started.load(std::memory_order_acquire);
        diag["finished"] = state->finished.load(std::memory_order_acquire);
        diag["action"] = timeout_resolution.action;
        diag["queue_owner"] = queue_owner;
        diag["requested_timeout_ms"] = timeout_resolution.requested_ms;
        diag["effective_timeout_ms"] = timeout_ms;
        diag["requested_deadline_ms"] = requested_deadline_ms;
        diag["effective_deadline_ms"] = deadline_ms;
        diag["timeout_source"] = timeout_resolution.source;
        diag["timeout_max_ms"] = timeout_resolution.max_ms;
        diag["action_aware_timeout"] = timeout_resolution.action_aware;
        diag["explicit_timeout"] = timeout_resolution.explicit_timeout;
        diag["late_result_disposition"] = "pending_cooperative_drain";
        diag["residual"] = "cooperative cancellation requested; a stuck native call may continue until it returns";
        diag::log_tagged_fmt("mcp_srv",
            "tool_call_timeout seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' domain='%s' lane='%s' queue_owner=%s timeout_ms=%llu requested_timeout_ms=%llu requested_deadline_ms=%llu effective_deadline_ms=%llu queue_wait_ms=%llu lock_wait_ms=%llu handler_elapsed_ms=%llu started=%d finished=%d cancelled=1 elapsed_ms=%llu late_result_disposition=pending_cooperative_drain",
            static_cast<unsigned long long>(seq),
            diag_id.c_str(),
            request_id.c_str(),
            tool_name.c_str(),
            timeout_resolution.action.c_str(),
            domain.c_str(),
            dispatch_metrics.lane.c_str(),
            queue_owner.c_str(),
            static_cast<unsigned long long>(timeout_ms),
            static_cast<unsigned long long>(timeout_resolution.requested_ms),
            static_cast<unsigned long long>(requested_deadline_ms),
            static_cast<unsigned long long>(deadline_ms),
            static_cast<unsigned long long>(diag.value("queue_wait_ms", 0ull)),
            static_cast<unsigned long long>(dispatch_metrics.lock_wait_ms),
            static_cast<unsigned long long>(dispatch_metrics.handler_elapsed_ms),
            state->started.load(std::memory_order_acquire) ? 1 : 0,
            state->finished.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(mcp_now_ms() - call_begin));
        if (is_camoufox_browser_tool_name(tool_name))
        {
            diag::log_tagged_fmt("mcp_srv",
                "browser_tool_timeout seq=%llu diag_id=%s request_id='%s' queue_owner=%s tool='%s' action='%s' domain='%s' lane='%s' requested_timeout_ms=%llu effective_timeout_ms=%llu requested_deadline_ms=%llu effective_deadline_ms=%llu timeout_source=%s timeout_max_ms=%llu action_aware=%d explicit_timeout=%d queue_wait_ms=%llu lock_wait_ms=%llu handler_elapsed_ms=%llu started=%d finished=%d cancel_state=signalled elapsed_ms=%llu late_result_disposition=pending_cooperative_drain",
                static_cast<unsigned long long>(seq),
                diag_id.c_str(),
                request_id.c_str(),
                queue_owner.c_str(),
                tool_name.c_str(),
                timeout_resolution.action.c_str(),
                domain.c_str(),
                dispatch_metrics.lane.c_str(),
                static_cast<unsigned long long>(timeout_resolution.requested_ms),
                static_cast<unsigned long long>(timeout_ms),
                static_cast<unsigned long long>(requested_deadline_ms),
                static_cast<unsigned long long>(deadline_ms),
                timeout_resolution.source.c_str(),
                static_cast<unsigned long long>(timeout_resolution.max_ms),
                timeout_resolution.action_aware ? 1 : 0,
                timeout_resolution.explicit_timeout ? 1 : 0,
                static_cast<unsigned long long>(diag.value("queue_wait_ms", 0ull)),
                static_cast<unsigned long long>(dispatch_metrics.lock_wait_ms),
                static_cast<unsigned long long>(dispatch_metrics.handler_elapsed_ms),
                state->started.load(std::memory_order_acquire) ? 1 : 0,
                state->finished.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned long long>(mcp_now_ms() - call_begin));
        }
        json err = make_error(id, -32070, "MCP tool call timed out; cancellation was signalled for cooperative drain. Diagnostic id: " + diag_id);
        err["error"]["data"] = std::move(diag);
        return err;
    }

    tool_result_t tr = future.get();
    {
        std::lock_guard<std::mutex> lk(state->mtx);
        dispatch_metrics = state->metrics;
        if (dispatch_metrics.lane.empty())
            dispatch_metrics.lane = predicted_tool_lane(found, arguments);
    }
    const bool cancelled = call_scope.token && call_scope.token->load(std::memory_order_acquire);
    json diagnostics = tool_diagnostics_json(
        seq, diag_id, request_id, tool_name, domain, found.read_only, target_pid,
        timeout_ms, deadline_ms, payload_shape, validation_status, dependency_status,
        dispatch_metrics, meta, cancelled);
    diagnostics["action"] = timeout_resolution.action;
    diagnostics["queue_owner"] = queue_owner;
    diagnostics["requested_timeout_ms"] = timeout_resolution.requested_ms;
    diagnostics["effective_timeout_ms"] = timeout_ms;
    diagnostics["requested_deadline_ms"] = requested_deadline_ms;
    diagnostics["effective_deadline_ms"] = deadline_ms;
    diagnostics["timeout_source"] = timeout_resolution.source;
    diagnostics["timeout_max_ms"] = timeout_resolution.max_ms;
    diagnostics["action_aware_timeout"] = timeout_resolution.action_aware;
    diagnostics["explicit_timeout"] = timeout_resolution.explicit_timeout;
    diagnostics["late_result_disposition"] = cancelled ? "cancelled_before_delivery" : "delivered";
    diag::log_tagged_fmt("mcp_srv",
        "handle_tools_call result seq=%llu diag_id=%s request_id='%s' tool='%s' action='%s' success=%d domain='%s' lane='%s' queue_owner=%s read_only=%d target_pid=%u requested_timeout_ms=%llu effective_timeout_ms=%llu requested_deadline_ms=%llu effective_deadline_ms=%llu queue_wait_ms=%llu lock_wait_ms=%llu handler_elapsed_ms=%llu cancelled=%d elapsed_ms=%llu late_result_disposition=%s",
        static_cast<unsigned long long>(seq),
        diag_id.c_str(),
        request_id.c_str(),
        tool_name.c_str(),
        timeout_resolution.action.c_str(),
        tr.success ? 1 : 0,
        domain.c_str(),
        dispatch_metrics.lane.c_str(),
        queue_owner.c_str(),
        found.read_only ? 1 : 0,
        target_pid,
        static_cast<unsigned long long>(timeout_resolution.requested_ms),
        static_cast<unsigned long long>(timeout_ms),
        static_cast<unsigned long long>(requested_deadline_ms),
        static_cast<unsigned long long>(deadline_ms),
        static_cast<unsigned long long>(diagnostics.value("queue_wait_ms", 0ull)),
        static_cast<unsigned long long>(dispatch_metrics.lock_wait_ms),
        static_cast<unsigned long long>(dispatch_metrics.handler_elapsed_ms),
        cancelled ? 1 : 0,
        static_cast<unsigned long long>(mcp_now_ms() - call_begin),
        cancelled ? "cancelled_before_delivery" : "delivered");

    if (cancelled) {
        json cancel_result;
        cancel_result["content"] = json::array({
            json{{"type", "text"}, {"text", "Tool call cancelled by client request."}}
        });
        cancel_result["isError"] = true;
        cancel_result["_meta"]["diagnostics"] = diagnostics;
        return make_result(id, cancel_result);
    }

    json content = json::array();
    if (!tr.text.empty()) {
        content.push_back({{"type", "text"}, {"text", sanitize_utf8(tr.text)}});
    }
    if (!tr.data.is_null() && !tr.data.empty()) {
        content.push_back({{"type", "text"}, {"text", sanitize_utf8(json_dump_safe(tr.data, 2))}});
    }
    if (content.empty()) {
        content.push_back({{"type", "text"}, {"text", tr.success
            ? "Tool executed successfully (no output)."
            : "Tool execution failed (no details)."}});
    }

    json result;
    result["content"] = content;
    if (!tr.success) {
        result["isError"] = true;
        if (has_structured_tool_error(tr)) {
            json err = structured_tool_error(tr);
            result["_meta"]["error"] = err;
            result["structuredContent"]["error"] = std::move(err);
        }
    }
    result["_meta"]["diagnostics"] = diagnostics;
    return make_result(id, result);
}

json server_t::handle_resources_list(const json& id, const json&)
{
    json resources = json::array();

    resources.push_back({
        {"uri",         "standalone://driver-status"},
        {"name",        "Driver Status"},
        {"description", "Current driver and process attachment state"},
        {"mimeType",    "application/json"}
    });

    resources.push_back({
        {"uri",         "standalone://loaded-file"},
        {"name",        "Loaded File Info"},
        {"description", "Information about the currently loaded PE file"},
        {"mimeType",    "application/json"}
    });

    json result;
    result["resources"] = resources;
    return make_result(id, result);
}

json server_t::handle_resources_read(const json& id, const json& params)
{
    if (!params.contains("uri") || !params["uri"].is_string())
        return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'uri'");

    std::string uri = params["uri"].get<std::string>();
    json text_content;

    if (uri == "standalone://driver-status") {
        json status;
        status["ready"]       = driver_bridge::is_loaded();
        status["attached_pid"]= driver_bridge::attached_pid();
        status["status"]      = driver_bridge::status();
        text_content = status;
    }
    else if (uri == "standalone://loaded-file") {
        text_content = json{{"info", "Use disassemble_file tool to load and inspect PE files."}};
    }
    else {
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown resource URI: " + uri);
    }

    json contents = json::array();
    contents.push_back({
        {"uri",      uri},
        {"mimeType", "application/json"},
        {"text",     json_dump_safe(text_content, 2)}
    });

    json result;
    result["contents"] = contents;
    return make_result(id, result);
}

json server_t::handle_prompts_list(const json& id, const json&)
{
    json prompts = json::array();

    prompts.push_back({
        {"name",        "analyze_memory"},
        {"description", "Read and analyze memory at an address in the attached process"},
        {"arguments",   json::array({
            {{"name", "address"}, {"description", "Hex address to analyze"}, {"required", true}},
            {{"name", "size"},    {"description", "Number of bytes to read (default 256)"}, {"required", false}}
        })}
    });

    prompts.push_back({
        {"name",        "disassemble_region"},
        {"description", "Disassemble code at an address in the attached process"},
        {"arguments",   json::array({
            {{"name", "address"}, {"description", "Hex address to disassemble"}, {"required", true}},
            {{"name", "count"},   {"description", "Max instructions (default 50)"}, {"required", false}}
        })}
    });

    prompts.push_back({
        {"name",        "sandbox_analysis"},
        {"description", "Run a binary in Windows Sandbox and analyze its output"},
        {"arguments",   json::array({
            {{"name", "path"}, {"description", "Path to the executable to analyze"}, {"required", true}}
        })}
    });

    json result;
    result["prompts"] = prompts;
    return make_result(id, result);
}

json server_t::handle_prompts_get(const json& id, const json& params)
{
    if (!params.contains("name") || !params["name"].is_string())
        return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'name'");

    std::string name = params["name"].get<std::string>();
    json arguments = params.value("arguments", json::object());

    json messages = json::array();

    if (name == "analyze_memory") {
        std::string addr = arguments.value("address", "");
        if (addr.empty())
            return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'address'");

        std::string prompt =
            "Read and analyze the memory at address " + addr + " in the attached process.\n"
            "Use the read_memory tool to fetch the bytes, then:\n"
            "1. Show a hex dump of the data\n"
            "2. Identify any strings or recognizable patterns\n"
            "3. Disassemble if the region appears to contain code\n"
            "4. Note any pointers or interesting values\n";

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", prompt}}}
        });
    }
    else if (name == "disassemble_region") {
        std::string addr = arguments.value("address", "");
        if (addr.empty())
            return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'address'");

        std::string prompt =
            "Disassemble the code at address " + addr + " in the attached process.\n"
            "Use the disassemble_zydis tool, then:\n"
            "1. Identify the function's purpose\n"
            "2. Analyze control flow (branches, loops, calls)\n"
            "3. Note any system calls, API calls, or string references\n"
            "4. Look for security-relevant patterns\n";

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", prompt}}}
        });
    }
    else if (name == "sandbox_analysis") {
        std::string path = arguments.value("path", "");
        if (path.empty())
            return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'path'");

        std::string prompt =
            "Execute the binary at '" + path + "' in Windows Sandbox.\n"
            "Use the sandbox_execute tool, then:\n"
            "1. Examine the stdout/stderr output\n"
            "2. Check if the process timed out or was killed\n"
            "3. Note the peak memory usage\n"
            "4. Investigate any suspicious behavior indicators\n";

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", prompt}}}
        });
    }
    else {
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown prompt: " + name);
    }

    json result;
    result["description"] = name;
    result["messages"]    = messages;
    return make_result(id, result);
}

json server_t::route_request(const json& msg)
{
    require_mcp_runtime_authorized("route_request");

    if (!msg.is_object())
        return make_error(nullptr, JSONRPC_INVALID_REQUEST, "Request must be a JSON object");

    std::string method = msg.value("method", "");
    diag::log_tagged_fmt("mcp_srv", "route_request method='%s'", method.c_str());
    if (method.empty())
        return make_error(msg.value("id", json(nullptr)), JSONRPC_INVALID_REQUEST, "Missing 'method' field");

    json id     = msg.contains("id") ? msg["id"] : json(nullptr);
    json params = msg.value("params", json::object());
    bool is_notification = !msg.contains("id");

    if (method == "initialize")               return handle_initialize(id, params);
    if (method == "notifications/initialized") return json();
    if (method == "ping")                     return handle_ping(id, params);
    if (method == "tools/list")               return handle_tools_list(id, params);
    if (method == "tools/call")               return handle_tools_call(id, params);
    if (method == "resources/list")           return handle_resources_list(id, params);
    if (method == "resources/read")           return handle_resources_read(id, params);
    if (method == "prompts/list")             return handle_prompts_list(id, params);
    if (method == "prompts/get")              return handle_prompts_get(id, params);
    if (method == "notifications/cancelled") {
        if (params.is_object() && params.contains("requestId"))
            signal_in_flight_cancel(params["requestId"]);
        return json();
    }
    if (method == "logging/setLevel")
        return json();
    if (is_notification)                      return json();

    return make_error(id, JSONRPC_METHOD_NOT_FOUND, "Unknown method: " + method);
}

std::string handle_body(server_t* self, const std::string& body)
{
    json parsed;
    try { parsed = json::parse(body); }
    catch (const json::parse_error& e) {
        return json_dump_safe(self->make_error(nullptr, JSONRPC_PARSE_ERROR,
            std::string("JSON parse error: ") + e.what()));
    }

    if (parsed.is_array()) {
        if (parsed.empty())
            return json_dump_safe(self->make_error(nullptr, JSONRPC_INVALID_REQUEST, "Empty batch"));

        const std::uint64_t batch_id = g_mcp_batch_seq.fetch_add(1u, std::memory_order_acq_rel) + 1u;
        const std::size_t batch_size = parsed.size();
        if (batch_size > kMcpMaxBatchItems) {
            json err = self->make_error(nullptr, -32073, "JSON-RPC batch item limit exceeded.");
            err["error"]["data"] = {
                {"batch_id", batch_id},
                {"items", batch_size},
                {"max_items", kMcpMaxBatchItems}
            };
            diag::log_tagged_fmt("mcp_srv",
                "jsonrpc_batch_rejected batch=%llu items=%zu max_items=%zu reason=item_limit",
                static_cast<unsigned long long>(batch_id),
                batch_size,
                kMcpMaxBatchItems);
            return json_dump_safe(err);
        }
        const std::uint64_t batch_start = mcp_now_ms();
        const auto& mcp_cfg = mcp_concurrency_config();
        diag::log_tagged_fmt("mcp_srv",
            "jsonrpc_batch_begin batch=%llu items=%zu workers=%zu max_queue=%zu",
            static_cast<unsigned long long>(batch_id),
            batch_size,
            mcp_cfg.batch_worker_threads,
            mcp_cfg.batch_max_queued_requests);

        struct batch_state_t {
            std::vector<json> responses;
            std::vector<unsigned char> has_response;
            std::vector<unsigned char> completed_items;
            std::size_t completed = 0;
            std::mutex mtx;
            std::condition_variable cv;
        };

        auto state = std::make_shared<batch_state_t>();
        state->responses.resize(batch_size);
        state->has_response.resize(batch_size, 0);
        state->completed_items.resize(batch_size, 0);
        std::atomic<std::size_t> overload_count{0};

        auto complete_item = [state](std::size_t index, json response) {
            {
                std::lock_guard<std::mutex> lk(state->mtx);
                if (index >= state->completed_items.size() || state->completed_items[index])
                    return;
                state->completed_items[index] = 1;
                if (!response.is_null()) {
                    state->responses[index] = std::move(response);
                    state->has_response[index] = 1;
                }
                ++state->completed;
            }
            state->cv.notify_one();
        };

        auto execute_item = [self, complete_item, batch_id](std::size_t index, json item) {
            try {
                json response = self->route_request(item);
                complete_item(index, std::move(response));
            } catch (const std::exception& ex) {
                diag::log_tagged_fmt("mcp_srv",
                    "jsonrpc_batch_item_exception batch=%llu index=%zu err='%s'",
                    static_cast<unsigned long long>(batch_id),
                    index,
                    ex.what());
                json id = item.is_object() && item.contains("id") ? item["id"] : json(nullptr);
                complete_item(index, self->make_error(id, JSONRPC_INTERNAL_ERROR, std::string("Request failed: ") + ex.what()));
            } catch (...) {
                diag::log_tagged_fmt("mcp_srv",
                    "jsonrpc_batch_item_exception batch=%llu index=%zu err='<unknown>'",
                    static_cast<unsigned long long>(batch_id),
                    index);
                json id = item.is_object() && item.contains("id") ? item["id"] : json(nullptr);
                complete_item(index, self->make_error(id, JSONRPC_INTERNAL_ERROR, "Request failed"));
            }
        };

        auto& executor = mcp_batch_executor();
        for (std::size_t i = 0; i < batch_size; ++i) {
            json item = parsed[i];
            auto meta = make_executor_task_meta();
            {
                std::lock_guard<std::mutex> lk(meta->mtx);
                meta->request_id = item.is_object() && item.contains("id") ? request_id_string(item["id"]) : "notification";
                meta->method = item.is_object() ? item.value("method", std::string()) : std::string("invalid");
                if (item.is_object() && item.value("method", std::string()) == "tools/call" &&
                    item.contains("params") && item["params"].is_object() &&
                    item["params"].contains("name") && item["params"]["name"].is_string()) {
                    meta->tool = item["params"]["name"].get<std::string>();
                    meta->domain = infer_tool_domain(meta->tool);
                    if (item["params"].contains("arguments"))
                        meta->payload_shape = payload_shape_summary(item["params"]["arguments"]);
                }
                meta->lane = "jsonrpc_batch_item";
                meta->deadline_ms = batch_start + kMcpBatchWaitTimeoutMs;
            }
            json item_id = item.is_object() && item.contains("id") ? item["id"] : json(nullptr);
            const std::string item_method = item.is_object() ? item.value("method", std::string()) : std::string("invalid");
            const std::string item_tool = item.is_object() && item.value("method", std::string()) == "tools/call" && item.contains("params") && item["params"].is_object() && item["params"].contains("name") && item["params"]["name"].is_string() ? item["params"]["name"].get<std::string>() : std::string();
            if (!executor.enqueue([execute_item, i, item = std::move(item)]() mutable {
                execute_item(i, std::move(item));
            }, meta)) {
                overload_count.fetch_add(1u, std::memory_order_acq_rel);
                diag::log_tagged_fmt("mcp_srv",
                    "jsonrpc_batch_enqueue_rejected batch=%llu index=%zu items=%zu disposition=item_error",
                    static_cast<unsigned long long>(batch_id),
                    i,
                    batch_size);
                json err = self->make_error(item_id, -32074, "JSON-RPC batch executor queue is full; item was not started.");
                err["error"]["data"] = {
                    {"batch_id", batch_id},
                    {"index", i},
                    {"items", batch_size},
                    {"method", item_method},
                    {"tool", item_tool},
                    {"queue_owner", "mcp_jsonrpc_batch"},
                    {"disposition", "not_started"}
                };
                complete_item(i, std::move(err));
            }
        }

        bool batch_complete = false;
        {
            std::unique_lock<std::mutex> lk(state->mtx);
            batch_complete = state->cv.wait_for(lk, std::chrono::milliseconds(kMcpBatchWaitTimeoutMs), [state, batch_size]() {
                return state->completed >= batch_size;
            });
            if (!batch_complete) {
                for (std::size_t i = 0; i < batch_size; ++i) {
                    if (state->completed_items[i])
                        continue;
                    const json& item = parsed[i];
                    json item_id = item.is_object() && item.contains("id") ? item["id"] : json(nullptr);
                    json err = self->make_error(item_id, -32071, "JSON-RPC batch item timed out before producing a response.");
                    err["error"]["data"] = {
                        {"batch_id", batch_id},
                        {"index", i},
                        {"timeout_ms", kMcpBatchWaitTimeoutMs},
                        {"elapsed_ms", mcp_now_ms() - batch_start},
                        {"method", item.is_object() ? item.value("method", std::string()) : std::string("invalid")},
                        {"tool", item.is_object() && item.value("method", std::string()) == "tools/call" && item.contains("params") && item["params"].is_object() && item["params"].contains("name") && item["params"]["name"].is_string() ? item["params"]["name"].get<std::string>() : std::string()}
                    };
                    state->responses[i] = std::move(err);
                    state->has_response[i] = 1;
                    state->completed_items[i] = 1;
                    ++state->completed;
                }
            }
        }

        json responses = json::array();
        for (std::size_t i = 0; i < batch_size; ++i) {
            if (state->has_response[i])
                responses.push_back(std::move(state->responses[i]));
        }
        diag::log_tagged_fmt("mcp_srv",
            "jsonrpc_batch_done batch=%llu items=%zu responses=%zu overload=%zu complete=%d elapsed_ms=%llu",
            static_cast<unsigned long long>(batch_id),
            batch_size,
            responses.size(),
            overload_count.load(std::memory_order_acquire),
            batch_complete ? 1 : 0,
            static_cast<unsigned long long>(mcp_now_ms() - batch_start));
        if (responses.empty()) return "";
        return json_dump_safe(responses);
    }

    json response = self->route_request(parsed);
    if (response.is_null()) return "";
    return json_dump_safe(response);
}

bool server_t::start(int port)
{
    diag::log_tagged_fmt("mcp_srv", "start entry port=%d", port);
    if (!mcp_runtime_authorized())
    {
        std::string missing_exports;
        const bool exports_ok = standalone_license::is_arc_loaded()
            && standalone_license::validate_arc_required_exports(missing_exports);
        diag::log_tagged_fmt("mcp_srv",
            "start_blocked_unauthorized ide=%d valid=%d arc=%d loading=%d exports=%d missing='%.160s'",
            g_ide_lifecycle_ready.load(std::memory_order_acquire) ? 1 : 0,
            standalone_license::is_valid() ? 1 : 0,
            standalone_license::is_arc_loaded() ? 1 : 0,
            standalone_license::is_arc_download_in_progress() ? 1 : 0,
            exports_ok ? 1 : 0,
            missing_exports.c_str());
        return false;
    }
    if (_running.load())
    {
        diag::log_tagged_fmt("mcp_srv", "start already running port=%d", port);
        return true;
    }

    if (auto prior = find_server_worker_lifetime(this)) {
        if (!_server_done.load(std::memory_order_acquire)) {
            diag::log_tagged_fmt("mcp_srv", "start rejected server worker already starting port=%d", port);
            return false;
        }
        if (prior->thread.joinable() && !prior->thread.join_for(10000)) {
            diag::log_tagged_fmt("mcp_srv", "start prior worker join timeout worker_tid=%u running=%d",
                static_cast<unsigned>(_server_worker_tid.load(std::memory_order_acquire)),
                _running.load(std::memory_order_acquire) ? 1 : 0);
            prior->thread.join();
        }
        erase_server_worker_lifetime(this, prior);
    }

    _stop_requested = false;
    _port = 0;

    if (!_server_done.load(std::memory_order_acquire)) {
        diag::log_tagged_fmt("mcp_srv", "start rejected server worker already starting port=%d", port);
        log_work_queue_stats("start rejected");
        return false;
    }

    auto worker_lifetime = std::make_shared<server_worker_lifetime_t>();
    _server_done.store(false, std::memory_order_release);
    if (!install_server_worker_lifetime(this, worker_lifetime)) {
        _server_done.store(true, std::memory_order_release);
        diag::log_tagged_fmt("mcp_srv", "start rejected server worker lifetime already installed port=%d", port);
        return false;
    }

    auto worker_body = [this, port]() {
        const DWORD tid = GetCurrentThreadId();
        _server_worker_tid.store(static_cast<std::uint32_t>(tid), std::memory_order_release);
        diag::log_tagged_fmt("mcp_srv", "server_worker starting port=%d tid=%lu", port, static_cast<unsigned long>(tid));
        log_work_queue_stats("server_worker entry");
        if (_stop_requested.load(std::memory_order_acquire)) {
            diag::log_tagged_fmt("mcp_srv", "server_worker cancelled before listen port=%d tid=%lu", port, static_cast<unsigned long>(tid));
            _server_worker_tid.store(0, std::memory_order_release);
            _server_done.store(true, std::memory_order_release);
            return;
        }
        try {
            server_thread_func(port);
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt("mcp_srv", "server_worker exception port=%d err='%s'", port, ex.what());
            _running.store(false, std::memory_order_release);
        } catch (...) {
            diag::log_tagged_fmt("mcp_srv", "server_worker exception port=%d err='<unknown>'", port);
            _running.store(false, std::memory_order_release);
        }
        diag::log_tagged_fmt("mcp_srv", "server_worker exited port=%d tid=%lu", port, static_cast<unsigned long>(GetCurrentThreadId()));
        _server_worker_tid.store(0, std::memory_order_release);
        _server_done.store(true, std::memory_order_release);
    };
    auto post_service_worker = [&](const char* source) -> bool {
        worker_lifetime->queued_worker.store(true, std::memory_order_release);
        const bool posted = work_queue::post_service(worker_body);
        if (posted) {
            diag::log_tagged_fmt("mcp_srv", "start server worker service queue posted port=%d source=%s", port, source ? source : "unknown");
        } else {
            diag::log_tagged_fmt("mcp_srv", "start server worker service queue failed port=%d source=%s", port, source ? source : "unknown");
            log_work_queue_stats("start service_queue_fallback_failed");
        }
        return posted;
    };

    char fileless_debug_path[MAX_PATH] = {};
    const bool fileless_host = diag::env_flag_enabled("AIDA_FILELESS_LAUNCH") ||
        diag::env_value_present("AIDA_FILELESS_DEBUG_LOG_PATH", fileless_debug_path, static_cast<DWORD>(sizeof(fileless_debug_path)));
    std::string worker_err;
    bool started = false;
    if (fileless_host) {
        diag::log_tagged_fmt("mcp_srv", "start server worker service queue selected port=%d fileless=1", port);
        started = post_service_worker("fileless");
    } else {
        started = worker_lifetime->thread.start(worker_body, &worker_err, aida::infra::win_thread::default_stack_reserve, "mcp_server_worker");
        if (!started) {
            diag::log_tagged_fmt("mcp_srv", "start server worker native start failed err='%s'", worker_err.empty() ? "<none>" : worker_err.c_str());
            log_work_queue_stats("start native_worker_failed");
            started = post_service_worker("native_fallback");
        }
    }
    if (!started) {
        mark_server_worker_start(worker_lifetime, false);
        erase_server_worker_lifetime(this, worker_lifetime);
        _server_done.store(true, std::memory_order_release);
        return false;
    }
    mark_server_worker_start(worker_lifetime, true);
    diag::log_tagged_fmt("mcp_srv", "start server worker accepted port=%d queued=%d", port, worker_lifetime->queued_worker.load(std::memory_order_acquire) ? 1 : 0);

    for (int i = 0; i < 500 && !_running.load() && !_server_done.load(std::memory_order_acquire) && !_stop_requested.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

    diag::log_tagged_fmt("mcp_srv", "start result running=%d port=%d",
        (int)_running.load(), _port);
    return _running.load();
}

void server_t::stop()
{
    diag::log_tagged_fmt("mcp_srv", "stop entry running=%d", (int)_running.load());
    const bool on_server_worker = _server_worker_tid.load(std::memory_order_acquire) == static_cast<std::uint32_t>(GetCurrentThreadId());
    if (!_running.load() && _server_done.load(std::memory_order_acquire))
    {
        if (auto worker_lifetime = find_server_worker_lifetime(this)) {
            if (worker_lifetime->thread.joinable() && !worker_lifetime->thread.join_for(10000)) {
                diag::log_tagged_fmt("mcp_srv", "stop already_stopped join timeout worker_tid=%u running=%d",
                    static_cast<unsigned>(_server_worker_tid.load(std::memory_order_acquire)),
                    _running.load(std::memory_order_acquire) ? 1 : 0);
                worker_lifetime->thread.join();
            }
            erase_server_worker_lifetime(this, worker_lifetime);
        }
        diag::log_tagged_fmt("mcp_srv", "stop already stopped");
        return;
    }
    _stop_requested = true;
    {
        std::lock_guard<std::mutex> lk(_server_mtx);
        if (_active_server)
            static_cast<httplib::Server*>(_active_server)->stop();
    }
    auto worker_lifetime = find_server_worker_lifetime(this);
    if (!worker_lifetime) {
        const std::uint64_t wait_start = mcp_now_ms();
        while (!_server_done.load(std::memory_order_acquire)) {
            const std::uint64_t elapsed = mcp_now_ms() - wait_start;
            if ((elapsed % 10000) < 2) {
                diag::log_tagged_fmt("mcp_srv", "stop waiting_no_worker elapsed_ms=%llu worker_tid=%u running=%d",
                    static_cast<unsigned long long>(elapsed),
                    static_cast<unsigned>(_server_worker_tid.load(std::memory_order_acquire)),
                    _running.load(std::memory_order_acquire) ? 1 : 0);
                log_work_queue_stats("stop waiting_no_worker");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        diag::log_tagged_fmt("mcp_srv", "stop done");
        return;
    }
    const bool started = wait_server_worker_start(worker_lifetime);
    if (!started) {
        erase_server_worker_lifetime(this, worker_lifetime);
        diag::log_tagged_fmt("mcp_srv", "stop done worker_not_started");
        return;
    }
    if (worker_lifetime->queued_worker.load(std::memory_order_acquire)) {
        const std::uint64_t wait_start = mcp_now_ms();
        while (!_server_done.load(std::memory_order_acquire) && !on_server_worker) {
            const std::uint64_t elapsed = mcp_now_ms() - wait_start;
            if ((elapsed % 10000) < 2) {
                diag::log_tagged_fmt("mcp_srv", "stop queued_worker waiting elapsed_ms=%llu worker_tid=%u running=%d",
                    static_cast<unsigned long long>(elapsed),
                    static_cast<unsigned>(_server_worker_tid.load(std::memory_order_acquire)),
                    _running.load(std::memory_order_acquire) ? 1 : 0);
                log_work_queue_stats("stop queued_worker waiting");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        erase_server_worker_lifetime(this, worker_lifetime);
    } else if (!on_server_worker && worker_lifetime->thread.joinable()) {
        if (!worker_lifetime->thread.join_for(10000)) {
            diag::log_tagged_fmt("mcp_srv", "stop join timeout worker_tid=%u running=%d",
                static_cast<unsigned>(_server_worker_tid.load(std::memory_order_acquire)),
                _running.load(std::memory_order_acquire) ? 1 : 0);
            log_work_queue_stats("stop join timeout");
            worker_lifetime->thread.join();
        }
        erase_server_worker_lifetime(this, worker_lifetime);
    }
    diag::log_tagged_fmt("mcp_srv", "stop done");
}

void server_t::server_thread_func(int port)
{
    diag::log_tagged_fmt("mcp_srv", "server_thread_func entry port=%d", port);
    const auto& mcp_cfg = mcp_concurrency_config();
    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func concurrency_config hardware_threads=%zu http_workers=%zu http_queue=%zu batch_workers=%zu batch_queue=%zu tool_workers=%zu tool_queue=%zu max_streams=%zu env_names=AIDA_MCP_HTTP_WORKERS,AIDA_MCP_HTTP_QUEUE,AIDA_MCP_BATCH_WORKERS,AIDA_MCP_BATCH_QUEUE,AIDA_MCP_TOOL_WORKERS,AIDA_MCP_TOOL_QUEUE,AIDA_MCP_MAX_STREAMS",
        mcp_cfg.hardware_threads,
        mcp_cfg.http_worker_threads,
        mcp_cfg.http_max_queued_requests,
        mcp_cfg.batch_worker_threads,
        mcp_cfg.batch_max_queued_requests,
        mcp_cfg.tool_worker_threads,
        mcp_cfg.tool_max_queued_requests,
        mcp_cfg.max_concurrent_streams);
    g_cached_health_ready.store(false, std::memory_order_release);
    g_cached_external_tool_count.store(0, std::memory_order_release);
    httplib::Server svr;
    svr.new_task_queue = [] {
        return new mcp_request_task_queue();
    };
    svr.set_payload_max_length(kMcpPayloadMaxLength);
    (void)mcp_batch_executor();
    (void)mcp_tool_executor();
    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func executors_prewarmed batch_workers=%zu tool_workers=%zu",
        mcp_cfg.batch_worker_threads,
        mcp_cfg.tool_worker_threads);
    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func mcp_owned_http_dispatch workers=%zu max_queue=%zu",
        mcp_cfg.http_worker_threads,
        mcp_cfg.http_max_queued_requests);
    svr.set_keep_alive_max_count(64);
    svr.set_keep_alive_timeout(2);
    svr.set_read_timeout(5, 0);
    svr.set_write_timeout(10, 0);
    svr.set_idle_interval(0, 100000);
    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func http_limits keep_alive_max=64 keep_alive_timeout_sec=2 read_timeout_sec=5 write_timeout_sec=10 idle_interval_us=100000 max_streams=%zu payload_max=%zu batch_max_items=%zu sse_max_events=%zu",
        mcp_cfg.max_concurrent_streams,
        kMcpPayloadMaxLength,
        kMcpMaxBatchItems,
        kSseMaxQueuedEvents);
    {
        std::lock_guard<std::mutex> lk(_server_mtx);
        _active_server = &svr;
    }

    std::string session_id = generate_session_id();
    diag::log_tagged_fmt("mcp_srv", "server_thread_func session_id='%s'", session_id.c_str());

    svr.set_default_headers({
        {"Access-Control-Allow-Origin",  "*"},
        {"Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id, MCP-Protocol-Version, Accept, Authorization, Last-Event-ID"},
        {"Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Protocol-Version"}
    });

    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response&) {
        tls_http_request_id = g_http_request_seq.fetch_add(1, std::memory_order_acq_rel) + 1;
        tls_http_request_start_tick = mcp_now_ms();
        update_current_executor_task_http(tls_http_request_id, req.method, req.path);
        const int active = g_active_http_requests.fetch_add(1, std::memory_order_acq_rel) + 1;
        diag::log_tagged_fmt("mcp_srv",
            "request_entry id=%llu method=%s path=%s matched=%s remote=%s pid=%lu tid=%lu active_requests=%d active_streams=%d body_len=%zu conn_closed=%d",
            static_cast<unsigned long long>(tls_http_request_id),
            req.method.c_str(),
            req.path.c_str(),
            req.matched_route.c_str(),
            remote_endpoint(req).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            active,
            g_active_streams.load(std::memory_order_acquire),
            req.body.size(),
            request_connection_closed(req) ? 1 : 0);
        return httplib::Server::HandlerResponse::Unhandled;
    });

    svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
        const std::uint64_t now = mcp_now_ms();
        const std::uint64_t elapsed = (tls_http_request_start_tick != 0 && now >= tls_http_request_start_tick) ? (now - tls_http_request_start_tick) : 0;
        int active_after = g_active_http_requests.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (active_after < 0) {
            g_active_http_requests.store(0, std::memory_order_release);
            active_after = 0;
        }
        diag::log_tagged_fmt("mcp_srv",
            "request_exit id=%llu method=%s path=%s matched=%s status=%d elapsed_ms=%llu remote=%s pid=%lu tid=%lu active_requests=%d active_streams=%d body_len=%zu conn_closed=%d",
            static_cast<unsigned long long>(tls_http_request_id),
            req.method.c_str(),
            req.path.c_str(),
            req.matched_route.c_str(),
            res.status,
            static_cast<unsigned long long>(elapsed),
            remote_endpoint(req).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            active_after,
            g_active_streams.load(std::memory_order_acquire),
            req.body.size(),
            request_connection_closed(req) ? 1 : 0);
        tls_http_request_id = 0;
        tls_http_request_start_tick = 0;
    });

    svr.Options(".*", [](const httplib::Request& req, httplib::Response& res) {
        diag::log_tagged_fmt("mcp_srv",
            "OPTIONS path=%s acrm=%s acrh=%s",
            req.path.c_str(),
            req.get_header_value("Access-Control-Request-Method").c_str(),
            req.get_header_value("Access-Control-Request-Headers").c_str());
        res.status = 204;
    });

    svr.Post("/mcp", [this, &session_id](const httplib::Request& req, httplib::Response& res) {
        require_mcp_runtime_authorized("http_post_mcp");
        diag::log_tagged_fmt("mcp_srv",
            "POST /mcp body_len=%zu accept=%s content_type=%s protocol=%s session=%s",
            req.body.size(),
            req.get_header_value("Accept").c_str(),
            req.get_header_value("Content-Type").c_str(),
            req.get_header_value("MCP-Protocol-Version").c_str(),
            req.get_header_value("Mcp-Session-Id").c_str());
        std::string response_body = handle_body(this, req.body);
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        if (response_body.empty())
            res.status = 202;
        else
            res.set_content(response_body, "application/json");
    });

    svr.Get("/mcp", [this, &session_id](const httplib::Request& req, httplib::Response& res) {
        require_mcp_runtime_authorized("http_get_mcp");
        diag::log_tagged_fmt("mcp_srv",
            "GET /mcp accept=%s protocol=%s session=%s",
            req.get_header_value("Accept").c_str(),
            req.get_header_value("MCP-Protocol-Version").c_str(),
            req.get_header_value("Mcp-Session-Id").c_str());
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        std::string accept = req.get_header_value("Accept");
        bool wants_sse = accept.find("text/event-stream") != std::string::npos;

        if (wants_sse) {
            auto stream_state = acquire_stream_slot("GET /mcp", req, res);
            if (!stream_state)
                return;
            auto connection_closed = req.is_connection_closed;
            res.set_header("Cache-Control", "no-cache");
            res.set_chunked_content_provider(
                "text/event-stream",
                [this, stream_state, connection_closed](size_t offset, httplib::DataSink& sink) -> bool {
                    if (connection_closed_now(connection_closed)) {
                        finish_stream_cleanly(stream_state, sink, "connection_closed");
                        return true;
                    }
                    if (offset == 0) {
                        const char connected[] = ": connected\n\n";
                        if (!sink.write(connected, sizeof(connected) - 1u)) {
                            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=connected",
                                static_cast<unsigned long long>(stream_state->id),
                                stream_state->route ? stream_state->route : "<unknown>");
                            return false;
                        }
                    }
                    const char ka[] = ": keepalive\n\n";
                    for (int i = 0; i < 6; ++i) {
                        for (int slice = 0; slice < 50; ++slice) {
                            if (_stop_requested.load(std::memory_order_acquire)) {
                                finish_stream_cleanly(stream_state, sink, "server_stop");
                                return true;
                            }
                            if (connection_closed_now(connection_closed)) {
                                finish_stream_cleanly(stream_state, sink, "connection_closed");
                                return true;
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        }
                        if (_stop_requested.load(std::memory_order_acquire)) {
                            finish_stream_cleanly(stream_state, sink, "server_stop");
                            return true;
                        }
                        if (connection_closed_now(connection_closed)) {
                            finish_stream_cleanly(stream_state, sink, "connection_closed");
                            return true;
                        }
                        if (sink.is_writable && !sink.is_writable()) {
                            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=writable",
                                static_cast<unsigned long long>(stream_state->id),
                                stream_state->route ? stream_state->route : "<unknown>");
                            return false;
                        }
                        if (!sink.write(ka, sizeof(ka) - 1u)) {
                            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=keepalive",
                                static_cast<unsigned long long>(stream_state->id),
                                stream_state->route ? stream_state->route : "<unknown>");
                            return false;
                        }
                    }
                    return true;
                },
                [stream_state](bool success) {
                    release_stream_slot(stream_state, success, success ? "provider_complete" : "provider_failed");
                });
        } else {
            res.set_content("event: endpoint\ndata: /mcp\n\n", "text/event-stream");
        }
    });

    svr.Delete("/mcp", [&session_id](const httplib::Request&, httplib::Response& res) {
        require_mcp_runtime_authorized("http_delete_mcp");
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        res.status = 200;
        res.set_content("{}", "application/json");
    });

    svr.Post("/ida-plugin-auth", [this](const httplib::Request& req, httplib::Response& res) {
        const std::uint64_t t0 = mcp_now_ms();
        diag::log_tagged_fmt("mcp_srv",
            "ida_plugin_auth_entry remote=%s pid=%lu tid=%lu body_len=%zu",
            remote_endpoint(req).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            req.body.size());

        json request = json::parse(req.body, nullptr, false);
        if (request.is_discarded() || !request.is_object())
        {
            res.status = 400;
            res.set_content(R"({"status":"error","reason":"invalid_json"})", "application/json");
            return;
        }

        uint32_t plugin_pid = 0;
        if (request.contains("plugin_pid") && request["plugin_pid"].is_number_unsigned())
            plugin_pid = request["plugin_pid"].get<uint32_t>();
        else if (request.contains("plugin_pid") && request["plugin_pid"].is_number_integer())
        {
            int64_t signed_pid = request["plugin_pid"].get<int64_t>();
            if (signed_pid > 0 && signed_pid <= 0xFFFFFFFFll)
                plugin_pid = static_cast<uint32_t>(signed_pid);
        }

        std::string reason;
        const bool lifecycle_ready = lifecycle_authorized(&reason);
        std::string missing_exports;
        const bool exports_ok = standalone_license::is_arc_loaded()
            && standalone_license::validate_arc_required_exports(missing_exports);
        if (!lifecycle_ready || !exports_ok)
        {
            json deny;
            deny["status"] = "error";
            deny["reason"] = !reason.empty() ? reason : (missing_exports.empty() ? "runtime_not_authorized" : missing_exports);
            deny["validated"] = standalone_license::is_valid();
            deny["arc_loaded"] = standalone_license::is_arc_loaded();
            deny["lifecycle_ready"] = g_ide_lifecycle_ready.load(std::memory_order_acquire);
            deny["exports_verified"] = exports_ok;
            res.status = 403;
            res.set_content(json_dump_safe(deny), "application/json");
            diag::log_tagged_fmt("mcp_srv",
                "ida_plugin_auth_denied reason=%.160s elapsed_ms=%llu",
                deny.value("reason", std::string()).c_str(),
                static_cast<unsigned long long>(mcp_now_ms() - t0));
            return;
        }

        std::string proof_json;
        std::string proof_error;
        if (!standalone_license::build_ida_plugin_auth_proof(
                request.value("challenge", std::string()),
                plugin_pid,
                static_cast<uint32_t>(_port),
                g_ide_lifecycle_ready.load(std::memory_order_acquire),
                exports_ok,
                proof_json,
                proof_error))
        {
            json deny;
            deny["status"] = "error";
            deny["reason"] = proof_error.empty() ? "proof_unavailable" : proof_error;
            res.status = 403;
            res.set_content(json_dump_safe(deny), "application/json");
            diag::log_tagged_fmt("mcp_srv",
                "ida_plugin_auth_proof_failed reason=%.160s elapsed_ms=%llu",
                deny.value("reason", std::string()).c_str(),
                static_cast<unsigned long long>(mcp_now_ms() - t0));
            return;
        }

        res.status = 200;
        res.set_content(proof_json, "application/json");
        diag::log_tagged_fmt("mcp_srv",
            "ida_plugin_auth_exit status=%d elapsed_ms=%llu remote=%s",
            res.status,
            static_cast<unsigned long long>(mcp_now_ms() - t0),
            remote_endpoint(req).c_str());
    });

    svr.Get("/health", [this](const httplib::Request& req, httplib::Response& res) {
        const std::uint64_t t0 = mcp_now_ms();
        diag::log_tagged_fmt("mcp_srv",
            "health_entry remote=%s pid=%lu tid=%lu active_requests=%d active_streams=%d",
            remote_endpoint(req).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            g_active_http_requests.load(std::memory_order_acquire),
            g_active_streams.load(std::memory_order_acquire));
        json health;
        std::string missing_exports;
        const bool exports_ok = standalone_license::is_arc_loaded()
            && standalone_license::validate_arc_required_exports(missing_exports);
        const bool runtime_ok = g_ide_lifecycle_ready.load(std::memory_order_acquire)
            && standalone_license::is_valid()
            && standalone_license::is_arc_loaded()
            && exports_ok;
        health["status"]      = "ok";
        health["server"]      = SERVER_NAME;
        health["version"]     = SERVER_VERSION;
        health["pid"]         = static_cast<std::uint32_t>(GetCurrentProcessId());
        health["port"]        = _port;
        health["authenticated"] = runtime_ok;
        health["validated"] = standalone_license::is_valid();
        health["arc_loaded"] = standalone_license::is_arc_loaded();
        health["lifecycle_ready"] = g_ide_lifecycle_ready.load(std::memory_order_acquire);
        health["exports_verified"] = exports_ok;
        health["tools_count"] = g_cached_external_tool_count.load(std::memory_order_acquire);
        health["cache_ready"] = g_cached_health_ready.load(std::memory_order_acquire);
        health["active_requests"] = g_active_http_requests.load(std::memory_order_acquire);
        health["active_streams"] = g_active_streams.load(std::memory_order_acquire);
        const auto& health_mcp_cfg = mcp_concurrency_config();
        health["stream_limit"] = health_mcp_cfg.max_concurrent_streams;
        health["concurrency"]["hardware_threads"] = health_mcp_cfg.hardware_threads;
        health["concurrency"]["http_workers"] = health_mcp_cfg.http_worker_threads;
        health["concurrency"]["http_queue"] = health_mcp_cfg.http_max_queued_requests;
        health["concurrency"]["batch_workers"] = health_mcp_cfg.batch_worker_threads;
        health["concurrency"]["batch_queue"] = health_mcp_cfg.batch_max_queued_requests;
        health["concurrency"]["tool_workers"] = health_mcp_cfg.tool_worker_threads;
        health["concurrency"]["tool_queue"] = health_mcp_cfg.tool_max_queued_requests;
        health["concurrency"]["max_streams"] = health_mcp_cfg.max_concurrent_streams;
        health["limits"]["payload_max_bytes"] = kMcpPayloadMaxLength;
        health["limits"]["batch_max_items"] = kMcpMaxBatchItems;
        health["limits"]["sse_max_queued_events"] = kSseMaxQueuedEvents;
        health["executors"] = mcp_executor_health_snapshot();
        res.status = 200;
        res.set_content(json_dump_safe(health), "application/json");
        const std::uint64_t elapsed = mcp_now_ms() - t0;
        diag::log_tagged_fmt("mcp_srv",
            "health_exit status=%d elapsed_ms=%llu remote=%s active_requests=%d active_streams=%d executors=%zu",
            res.status,
            static_cast<unsigned long long>(elapsed),
            remote_endpoint(req).c_str(),
            g_active_http_requests.load(std::memory_order_acquire),
            g_active_streams.load(std::memory_order_acquire),
            health["executors"].size());
    });

    svr.Get("/", [this](const httplib::Request&, httplib::Response& res) {
        json health;
        health["status"] = "ok";
        health["server"] = SERVER_NAME;
        health["mcp"] = "/mcp";
        health["sse"] = "/sse";
        health["health"] = "/health";
        size_t external_tools = 0;
        { std::lock_guard<std::mutex> lk(_tools_mtx);
          for (const auto& t : _tools)
              if (is_external_mcp_tool(t)) ++external_tools; }
        health["tools_count"] = external_tools;
        res.set_content(json_dump_safe(health), "application/json");
    });

    svr.Get("/api/tools", [this](const httplib::Request&, httplib::Response& res) {
        require_mcp_runtime_authorized("api_tools_list");
        json tools_arr = json::array();
        { std::lock_guard<std::mutex> lk(_tools_mtx);
          for (const auto& t : _tools) {
              if (!is_external_mcp_tool(t)) continue;
              tools_arr.push_back(tool_schema(t, false));
          } }
        res.set_content(json_dump_safe(tools_arr, 2), "application/json");
    });

    svr.Post("/api/tools/call", [this](const httplib::Request& req, httplib::Response& res) {
        require_mcp_runtime_authorized("api_tools_call");
        diag::log_tagged_fmt("mcp_srv", "POST /api/tools/call body_len=%zu", req.body.size());
        json body;
        try { body = json::parse(req.body); }
        catch (const json::parse_error& e) {
            res.status = 400;
            res.set_content(json_dump_safe({{"error", e.what()}}), "application/json");
            return;
        }

        std::string tool_name = body.value("name", "");
        json arguments = body.value("arguments", json::object());

        if (tool_name.empty()) {
            res.status = 400;
            res.set_content(json_dump_safe({{"error", "Missing 'name' field"}}), "application/json");
            return;
        }

        tool_def_t found;
        bool found_tool = false;
        std::function<tool_result_t(const json&)> handler_copy;
        { std::lock_guard<std::mutex> lk(_tools_mtx);
          for (const auto& t : _tools) {
              if (t.name == tool_name) {
                  if (!is_external_mcp_tool(t)) {
                      res.status = 404;
                      res.set_content(json_dump_safe({{"error", "Unknown tool: " + tool_name}}), "application/json");
                      return;
                  }
                  found = t;
                  handler_copy = t.handler;
                  found_tool = true;
                  break;
              }
          } }

        if (!found_tool) {
            res.status = 404;
            res.set_content(json_dump_safe({{"error", "Unknown tool: " + tool_name}}), "application/json");
            return;
        }

        tool_invocation_metrics_t api_metrics;
        tool_result_t tr = invoke_tool_with_concurrency_policy(found, arguments, handler_copy, &api_metrics);

        json resp;
        resp["success"] = tr.success;
        resp["output"]  = sanitize_utf8(tr.text);
        resp["diagnostics"] = {
            {"lane", api_metrics.lane},
            {"lock_wait_ms", api_metrics.lock_wait_ms},
            {"handler_elapsed_ms", api_metrics.handler_elapsed_ms}
        };
        if (!tr.data.is_null() && !tr.data.empty()) resp["data"] = tr.data;
        if (has_structured_tool_error(tr)) {
            json err = structured_tool_error(tr);
            resp["error"] = err;
            if (err.contains("code"))
                resp["error_code"] = err["code"];
            if (err.contains("details"))
                resp["error_details"] = err["details"];
        }
        res.set_content(json_dump_safe(resp, 2), "application/json");
    });

    std::map<std::string, std::shared_ptr<sse_session_t>> sse_sessions;
    std::mutex sse_mtx;

    auto cleanup_sse_sessions = [&sse_sessions, &sse_mtx](const char* reason) {
        const std::uint64_t now = mcp_now_ms();
        size_t removed = 0;
        {
            std::lock_guard<std::mutex> lk(sse_mtx);
            for (auto it = sse_sessions.begin(); it != sse_sessions.end(); ) {
                const auto& session = it->second;
                const bool aged = session && now >= session->opened_tick && (now - session->opened_tick) > kSseSessionMaxAgeMs;
                if (!session || session->closed.load(std::memory_order_acquire) || aged) {
                    if (session)
                        session->close();
                    it = sse_sessions.erase(it);
                    ++removed;
                } else {
                    ++it;
                }
            }
        }
        if (removed != 0) {
            diag::log_tagged_fmt("mcp_srv",
                "sse_session_cleanup reason=%s removed=%zu active_streams=%d active_requests=%d",
                reason ? reason : "",
                removed,
                g_active_streams.load(std::memory_order_acquire),
                g_active_http_requests.load(std::memory_order_acquire));
        }
    };

    svr.Get("/sse", [this, &sse_sessions, &sse_mtx, &cleanup_sse_sessions](const httplib::Request& req, httplib::Response& res) {
        require_mcp_runtime_authorized("http_get_sse");
        cleanup_sse_sessions("before_open");
        auto session = std::make_shared<sse_session_t>();
        session->id = generate_session_id();
        auto stream_state = acquire_stream_slot("GET /sse", req, res);
        if (!stream_state)
            return;
        auto connection_closed = req.is_connection_closed;
        size_t session_count = 0;
        {
            std::lock_guard<std::mutex> lk(sse_mtx);
            sse_sessions[session->id] = session;
            session_count = sse_sessions.size();
        }
        diag::log_tagged_fmt("mcp_srv",
            "sse_session_open session=%s stream_id=%llu remote=%s sessions=%zu",
            session->id.c_str(),
            static_cast<unsigned long long>(stream_state->id),
            stream_state->remote.c_str(),
            session_count);

        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");
        res.set_header("X-Accel-Buffering", "no");

        std::atomic<bool>* stop_ptr = &_stop_requested;
        res.set_chunked_content_provider(
            "text/event-stream",
            [session, stop_ptr, stream_state, connection_closed](size_t offset, httplib::DataSink& sink) -> bool {
                bool cont = false;
                DWORD seh = 0;
                try {
                    seh = seh_sse_provider_step(session.get(), &sink, offset, stop_ptr, stream_state.get(), connection_closed, &cont);
                } catch (const std::exception& ex) {
                    diag::log_tagged_fmt("mcp_srv",
                        "stream_provider_exception id=%llu route=%s err='%s'",
                        static_cast<unsigned long long>(stream_state->id),
                        stream_state->route ? stream_state->route : "<unknown>",
                        ex.what());
                    session->close();
                    return false;
                } catch (...) {
                    diag::log_tagged_fmt("mcp_srv",
                        "stream_provider_exception id=%llu route=%s err='<unknown>'",
                        static_cast<unsigned long long>(stream_state->id),
                        stream_state->route ? stream_state->route : "<unknown>");
                    session->close();
                    return false;
                }
                if (seh != 0) {
                    diag::log_tagged_fmt("mcp_srv",
                        "stream_provider_seh id=%llu route=%s code=0x%08lX",
                        static_cast<unsigned long long>(stream_state->id),
                        stream_state->route ? stream_state->route : "<unknown>",
                        static_cast<unsigned long>(seh));
                    session->close();
                    return false;
                }
                return cont;
            },
            [session, &sse_sessions, &sse_mtx, stream_state](bool success) {
                session->close();
                size_t remaining = 0;
                {
                    std::lock_guard<std::mutex> lk(sse_mtx);
                    sse_sessions.erase(session->id);
                    remaining = sse_sessions.size();
                }
                diag::log_tagged_fmt("mcp_srv",
                    "sse_session_close session=%s stream_id=%llu success=%d remaining=%zu",
                    session->id.c_str(),
                    static_cast<unsigned long long>(stream_state->id),
                    success ? 1 : 0,
                    remaining);
                release_stream_slot(stream_state, success, success ? "provider_complete" : "provider_failed");
            });
    });

    svr.Post("/message", [this, &sse_sessions, &sse_mtx, &cleanup_sse_sessions](const httplib::Request& req, httplib::Response& res) {
        require_mcp_runtime_authorized("http_post_message");
        cleanup_sse_sessions("before_message");
        std::string sid = req.get_param_value("sessionId");
        if (sid.empty()) {
            res.status = 400;
            res.set_content(json_dump_safe(make_error(nullptr,
                JSONRPC_INVALID_REQUEST, "Missing sessionId query parameter")), "application/json");
            return;
        }

        std::shared_ptr<sse_session_t> session;
        { std::lock_guard<std::mutex> lk(sse_mtx);
          auto it = sse_sessions.find(sid);
          if (it == sse_sessions.end() || !it->second || it->second->closed.load(std::memory_order_acquire)) {
              if (it != sse_sessions.end())
                  sse_sessions.erase(it);
              res.status = 404;
              res.set_content(json_dump_safe(make_error(nullptr,
                  JSONRPC_INVALID_REQUEST, "Unknown or expired session: " + sid)), "application/json");
              return;
          }
          session = it->second;
        }

        std::string response_body = handle_body(this, req.body);
        if (!response_body.empty()) {
            std::string event = format_sse_event("message", response_body);
            session->push_event(event);
        }
        res.status = 202;
        res.set_content("Accepted", "text/plain");
    });

    svr.Post("/sse", [this, &session_id](const httplib::Request& req, httplib::Response& res) {
        require_mcp_runtime_authorized("http_post_sse");
        diag::log_tagged_fmt("mcp_srv",
            "POST /sse body_len=%zu accept=%s protocol=%s session=%s",
            req.body.size(),
            req.get_header_value("Accept").c_str(),
            req.get_header_value("MCP-Protocol-Version").c_str(),
            req.get_header_value("Mcp-Session-Id").c_str());
        std::string response_body = handle_body(this, req.body);
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        if (response_body.empty()) res.status = 202;
        else res.set_content(response_body, "application/json");
    });

    svr.Delete("/sse", [&session_id](const httplib::Request&, httplib::Response& res) {
        require_mcp_runtime_authorized("http_delete_sse");
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        res.status = 200;
        res.set_content("{}", "application/json");
    });

    svr.set_socket_options([](socket_t sock) {
        int yes = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&yes), sizeof(yes));
    });

    int bound_port = 0;
    if (port > 0 && svr.bind_to_port("127.0.0.1", port))
        bound_port = port;
    if (bound_port <= 0)
        bound_port = svr.bind_to_any_port("127.0.0.1");

    if (bound_port <= 0) {
        diag::log_tagged_fmt("mcp_srv", "server_thread_func bind fail port=%d", port);
        std::lock_guard<std::mutex> lk(_server_mtx);
        _active_server = nullptr;
        _stop_requested = true;
        return;
    }

    _port = bound_port;
    _running = true;
    size_t external_tools = 0;
    { std::lock_guard<std::mutex> lk(_tools_mtx);
      for (const auto& t : _tools)
          if (is_external_mcp_tool(t)) ++external_tools; }
    g_cached_external_tool_count.store(external_tools, std::memory_order_release);
    g_cached_health_ready.store(true, std::memory_order_release);
    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func listening bound_port=%d endpoints=/mcp,/sse,/health external_tools=%zu",
        bound_port, external_tools);

    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func listen_after_bind_enter port=%d pid=%lu tid=%lu",
        bound_port,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));

    svr.listen_after_bind();

    diag::log_tagged_fmt("mcp_srv", "server_thread_func listen_after_bind returned port=%d", bound_port);
    g_cached_health_ready.store(false, std::memory_order_release);
    _running = false;
    { std::lock_guard<std::mutex> lk(_server_mtx); _active_server = nullptr; }
}

static std::string get_home_dir()
{
    std::string env_home = read_env_var("USERPROFILE");
    if (!env_home.empty())
        return env_home;
    char buf[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, buf)))
        return buf;
    return "";
}

static std::string get_appdata_dir()
{
    std::string env_appdata = read_env_var("APPDATA");
    if (!env_appdata.empty())
        return env_appdata;
    char buf[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, buf)))
        return buf;
    return "";
}

static std::string expand_path(const char* tmpl)
{
    if (!tmpl || !*tmpl) return "";
    std::string path(tmpl);

    if (path.size() >= 1 && path[0] == '~') {
        std::string home = get_home_dir();
        if (home.empty()) return "";
        if (path.size() >= 2 && (path[1] == '/' || path[1] == '\\'))
            path = home + path.substr(1);
        else if (path.size() == 1)
            path = home;
    }

    size_t pos = path.find("%APPDATA%");
    if (pos != std::string::npos) {
        std::string appdata = get_appdata_dir();
        if (appdata.empty()) return "";
        path.replace(pos, 9, appdata);
    }

    for (auto& c : path) if (c == '/') c = '\\';
    return path;
}

static bool ensure_dir(const std::string& dir)
{
    if (dir.empty()) return false;
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return std::filesystem::is_directory(dir, ec);
}

static bool ensure_parent_dir(const std::string& path)
{
    auto p = std::filesystem::path(path).parent_path();
    if (p.empty()) return true;
    return ensure_dir(p.string());
}

static bool read_file_to_string(const std::string& path, std::string& out)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    out.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
    return true;
}

static bool write_string_to_file(const std::string& path, const std::string& content)
{
    if (!ensure_parent_dir(path)) return false;
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs << content;
    return ofs.good();
}

static std::string strip_jsonc(const std::string& input)
{
    std::string result;
    result.reserve(input.size());
    bool in_string = false, in_line = false, in_block = false;

    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        if (in_line)  { if (c == '\n') { in_line = false; result += '\n'; } continue; }
        if (in_block) { if (c == '*' && i+1 < input.size() && input[i+1] == '/') { in_block = false; ++i; } continue; }
        if (in_string) { result += c; if (c == '\\' && i+1 < input.size()) result += input[++i]; else if (c == '"') in_string = false; continue; }
        if (c == '"') { in_string = true; result += c; continue; }
        if (c == '/' && i+1 < input.size()) {
            if (input[i+1] == '/') { in_line = true; ++i; continue; }
            if (input[i+1] == '*') { in_block = true; ++i; continue; }
        }
        if (c == ',') {
            size_t j = i+1;
            while (j < input.size() && (input[j]==' '||input[j]=='\t'||input[j]=='\n'||input[j]=='\r')) ++j;
            if (j < input.size() && (input[j] == '}' || input[j] == ']')) continue;
        }
        result += c;
    }
    return result;
}

static bool parse_json_file(const std::string& path, json& out, bool allow_jsonc)
{
    std::string raw;
    if (!read_file_to_string(path, raw)) return false;
    try { out = json::parse(raw); return true; }
    catch (const json::parse_error&) {
        if (!allow_jsonc) return false;
    }
    try { out = json::parse(strip_jsonc(raw)); return true; }
    catch (const json::parse_error&) { return false; }
}

static bool write_json_file(const std::string& path, const json& data)
{
    return write_string_to_file(path, json_dump_safe(data, 2) + "\n");
}

static const char* MCP_NAME = "aida-standalone-mcp";

struct client_cfg_t {
    const char* name;
    enum { URL, SERVERURL, OPENCODE, VSCODE, VSCODE_JSON, CLINE, ZED, CODEX, CLAUDE_CODE } format;
    const char* win_path;
};

static const client_cfg_t g_clients[] = {
    { "Cline",           client_cfg_t::CLINE,        "%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" },
    { "Roo Code",        client_cfg_t::CLINE,        "%APPDATA%/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json" },
    { "Kilo Code",       client_cfg_t::CLINE,        "%APPDATA%/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json" },
    { "Claude",          client_cfg_t::URL,          "%APPDATA%/Claude/claude_desktop_config.json" },
    { "Cursor",          client_cfg_t::URL,          "~/.cursor/mcp.json" },
    { "Windsurf",        client_cfg_t::URL,          "~/.codeium/windsurf/mcp_config.json" },
    { "Claude Code",     client_cfg_t::CLAUDE_CODE,  "~/.claude.json" },
    { "LM Studio",       client_cfg_t::URL,          "~/.lmstudio/mcp.json" },
    { "Codex",           client_cfg_t::CODEX,        "~/.codex/config.toml" },
    { "Zed",             client_cfg_t::ZED,          "%APPDATA%/Zed/settings.json" },
    { "Gemini CLI",      client_cfg_t::URL,          "~/.gemini/settings.json" },
    { "Qwen Coder",      client_cfg_t::URL,          "~/.qwen/settings.json" },
    { "Copilot CLI",     client_cfg_t::URL,          "~/.copilot/mcp-config.json" },
    { "Crush",           client_cfg_t::URL,          "~/crush.json" },
    { "Augment Code",    client_cfg_t::VSCODE,       "%APPDATA%/Code/User/settings.json" },
    { "Qodo Gen",        client_cfg_t::VSCODE,       "%APPDATA%/Code/User/settings.json" },
    { "Antigravity IDE", client_cfg_t::SERVERURL,    "~/.gemini/antigravity/mcp_config.json" },
    { "Warp",            client_cfg_t::URL,          "~/.warp/mcp_config.json" },
    { "Amazon Q",        client_cfg_t::URL,          "~/.aws/amazonq/mcp_config.json" },
    { "Opencode",        client_cfg_t::OPENCODE,     "~/.config/opencode/opencode.json" },
    { "Kiro",            client_cfg_t::URL,          "~/.kiro/settings/mcp.json" },
    { "Kiro Legacy",     client_cfg_t::URL,          "~/.kiro/mcp_config.json" },
    { "Trae",            client_cfg_t::URL,          "~/.trae/mcp_config.json" },
    { "VS Code",         client_cfg_t::VSCODE,       "%APPDATA%/Code/User/settings.json" },
    { "VS Code Insiders",client_cfg_t::VSCODE,       "%APPDATA%/Code - Insiders/User/settings.json" },
    { "VS Code (mcp.json)", client_cfg_t::VSCODE_JSON, "%APPDATA%/Code/User/mcp.json" },
    { "VS Code Insiders (mcp.json)", client_cfg_t::VSCODE_JSON, "%APPDATA%/Code - Insiders/User/mcp.json" },
};

static bool is_managed_key(const std::string& key)
{
    return key == MCP_NAME ||
           key == "AiDA-Pro-MCP" ||
           key == "aida-pro-mcp" ||
           key == "aida-standalone-mcp" ||
           key == "camoufox-reverse-mcp" ||
           key == "camoufox_reverse_mcp" ||
           key == "camoufox-reverse";
}

static void erase_managed_keys(json& root)
{
    if (!root.is_object())
        return;
    std::vector<std::string> keys;
    for (auto it = root.begin(); it != root.end(); ++it) {
        if (is_managed_key(it.key()))
            keys.push_back(it.key());
    }
    for (const auto& key : keys)
        root.erase(key);
}

static bool write_mcpservers(const std::string& path, const std::string& url, const char* key)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, false);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();
    erase_managed_keys(config["mcpServers"]);
    config["mcpServers"][MCP_NAME] = json::object();
    config["mcpServers"][MCP_NAME]["type"] = "http";
    config["mcpServers"][MCP_NAME][key] = url;
    return write_json_file(path, config);
}

static bool write_opencode(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcp") || !config["mcp"].is_object())
        config["mcp"] = json::object();
    erase_managed_keys(config["mcp"]);
    config["mcp"][MCP_NAME] = {{"type", "remote"}, {"url", url}};
    return write_json_file(path, config);
}

static bool write_vscode(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcp") || !config["mcp"].is_object()) config["mcp"] = json::object();
    if (!config["mcp"].contains("servers") || !config["mcp"]["servers"].is_object())
        config["mcp"]["servers"] = json::object();
    erase_managed_keys(config["mcp"]["servers"]);
    config["mcp"]["servers"][MCP_NAME] = {{"type", "http"}, {"url", url}};
    return write_json_file(path, config);
}

static bool write_vscode_json(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("servers") || !config["servers"].is_object())
        config["servers"] = json::object();
    erase_managed_keys(config["servers"]);
    config["servers"][MCP_NAME] = {{"type", "http"}, {"url", url}};
    return write_json_file(path, config);
}

static bool write_cline(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, false);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();
    erase_managed_keys(config["mcpServers"]);
    json entry;
    entry["type"] = "http";
    entry["url"] = url;
    config["mcpServers"][MCP_NAME] = entry;
    return write_json_file(path, config);
}

static bool write_zed(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("context_servers") || !config["context_servers"].is_object())
        config["context_servers"] = json::object();
    erase_managed_keys(config["context_servers"]);
    config["context_servers"][MCP_NAME] = {{"settings", {{"url", url}}}};
    return write_json_file(path, config);
}

static bool write_codex(const std::string& path, const std::string& url)
{
    std::string content;
    if (std::filesystem::exists(path)) read_file_to_string(path, content);
    auto strip_section = [](std::string& doc, const std::string& marker) {
        size_t pos = doc.find(marker);
        while (pos != std::string::npos) {
            size_t end = doc.find("\n[", pos + marker.size());
            if (end == std::string::npos) end = doc.size(); else end += 1;
            doc.erase(pos, end - pos);
            pos = doc.find(marker);
        }
    };
    strip_section(content, "[mcp_servers.aida-standalone-mcp]");
    strip_section(content, "[mcp_servers.aida-pro-mcp]");
    strip_section(content, "[mcp_servers.AiDA-Pro-MCP]");
    strip_section(content, "[mcp_servers.camoufox-reverse-mcp]");
    strip_section(content, "[mcp_servers.camoufox_reverse_mcp]");
    strip_section(content, "[mcp_servers.camoufox-reverse]");
    strip_section(content, std::string("[mcp_servers.") + MCP_NAME + "]");
    if (!content.empty() && content.back() != '\n') {
        content += "\n";
    }
    content += "\n[mcp_servers." + std::string(MCP_NAME) + "]\nurl = \"" + url + "\"\n";
    return write_string_to_file(path, content);
}

static bool write_claude_code(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, false);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();
    erase_managed_keys(config["mcpServers"]);
    config["mcpServers"][MCP_NAME] = {{"type", "http"}, {"url", url}};
    return write_json_file(path, config);
}

void server_t::write_client_configs() const
{
    if (!mcp_runtime_authorized())
    {
        std::string missing_exports;
        const bool exports_ok = standalone_license::is_arc_loaded()
            && standalone_license::validate_arc_required_exports(missing_exports);
        diag::log_tagged_fmt("mcp_config",
            "write_client_configs_blocked_unauthorized ide=%d valid=%d arc=%d exports=%d missing='%.160s'",
            g_ide_lifecycle_ready.load(std::memory_order_acquire) ? 1 : 0,
            standalone_license::is_valid() ? 1 : 0,
            standalone_license::is_arc_loaded() ? 1 : 0,
            exports_ok ? 1 : 0,
            missing_exports.c_str());
        return;
    }
    if (!_running.load()) {
        diag::log_tagged("mcp_config", "write_client_configs_skipped_not_running");
        return;
    }

    std::string port_str = std::to_string(_port);
    std::string http_url = "http://127.0.0.1:" + port_str + "/mcp";
    std::string sse_url = "http://127.0.0.1:" + port_str + "/sse";
    diag::log_tagged_fmt("mcp_config", "write_client_configs_start url='%s' sse='%s'", http_url.c_str(), sse_url.c_str());

    std::set<std::string> written;
    int ok = 0, skip = 0, fail = 0;

    for (const auto& def : g_clients) {
        try {
            std::string path = expand_path(def.win_path);
            if (path.empty()) {
                diag::log_tagged_fmt("mcp_config", "client_skip_empty name='%s'", def.name);
                ++skip;
                continue;
            }
            if (written.count(path)) {
                diag::log_tagged_fmt("mcp_config", "client_skip_duplicate name='%s' path='%s'", def.name, path.c_str());
                continue;
            }

            if (path.find("globalStorage") != std::string::npos) {
                auto parent = std::filesystem::path(path).parent_path();
                std::error_code ec;
                if (!std::filesystem::is_directory(parent, ec)) {
                    diag::log_tagged_fmt("mcp_config", "client_optional_storage_absent name='%s' path='%s'", def.name, path.c_str());
                    ++skip;
                    continue;
                }
            }

            diag::log_tagged_fmt("mcp_config", "client_write_start name='%s' path='%s'", def.name, path.c_str());
            bool success = false;
            switch (def.format) {
            case client_cfg_t::URL:          success = write_mcpservers(path, http_url, "url"); break;
            case client_cfg_t::SERVERURL:    success = write_mcpservers(path, http_url, "serverUrl"); break;
            case client_cfg_t::OPENCODE:     success = write_opencode(path, http_url); break;
            case client_cfg_t::VSCODE:       success = write_vscode(path, http_url); break;
            case client_cfg_t::VSCODE_JSON:  success = write_vscode_json(path, http_url); break;
            case client_cfg_t::CLINE:        success = write_cline(path, http_url); break;
            case client_cfg_t::ZED:          success = write_zed(path, http_url); break;
            case client_cfg_t::CODEX:        success = write_codex(path, http_url); break;
            case client_cfg_t::CLAUDE_CODE:  success = write_claude_code(path, http_url); break;
            }

            if (success) {
                diag::log_tagged_fmt("mcp_config", "client_write_ok name='%s' path='%s'", def.name, path.c_str());
                written.insert(path);
                ++ok;
            }
            else {
                diag::log_tagged_fmt("mcp_config", "client_write_fail name='%s' path='%s'", def.name, path.c_str());
                ++fail;
            }
        } catch (const std::exception& e) {
            diag::log_tagged_fmt("mcp_config", "client_write_exception name='%s' what='%.180s'", def.name, e.what());
            ++fail;
        } catch (...) {
            diag::log_tagged_fmt("mcp_config", "client_write_exception name='%s' what='<unknown>'", def.name);
            ++fail;
        }
    }
    diag::log_tagged_fmt("mcp_config", "write_client_configs_done ok=%d skip=%d fail=%d", ok, skip, fail);
}


target_scope_t::target_scope_t(target_scope_t&& other) noexcept
    : ok(other.ok),
      swapped(other.swapped),
      resolved(other.resolved),
      prev_active_idx(other.prev_active_idx),
      target_idx(other.target_idx),
      resolved_id(std::move(other.resolved_id)),
      err(std::move(other.err))
{
    other.ok = false;
    other.swapped = false;
    other.resolved = false;
    other.prev_active_idx = static_cast<size_t>(-1);
    other.target_idx = static_cast<size_t>(-1);
}

target_scope_t& target_scope_t::operator=(target_scope_t&& other) noexcept
{
    if (this != &other) {
        ok = other.ok;
        swapped = other.swapped;
        resolved = other.resolved;
        prev_active_idx = other.prev_active_idx;
        target_idx = other.target_idx;
        resolved_id = std::move(other.resolved_id);
        err = std::move(other.err);
        other.ok = false;
        other.swapped = false;
        other.resolved = false;
        other.prev_active_idx = static_cast<size_t>(-1);
        other.target_idx = static_cast<size_t>(-1);
    }
    return *this;
}

target_scope_t::~target_scope_t()
{
    if (!ok) return;
    if (!swapped) return;
    if (prev_active_idx == static_cast<size_t>(-1)) return;
    if (prev_active_idx >= analysis_session::session_count()) return;
    (void)analysis_session::switch_session(prev_active_idx);
    diag::log_tagged_fmt("mcp_standalone",
        "target_scope_restore restored_idx=%llu",
        static_cast<unsigned long long>(prev_active_idx));
}

target_scope_t resolve_target(const json& args, std::string* out_err)
{
    target_scope_t scope;
    scope.ok = true;
    scope.resolved = false;

    if (args.is_null() || !args.is_object()) {
        return scope;
    }

    std::string binary_id;
    if (args.contains("binary_id") && args["binary_id"].is_string()) {
        binary_id = args["binary_id"].get<std::string>();
    } else if (args.contains("session_id") && args["session_id"].is_string()) {
        binary_id = args["session_id"].get<std::string>();
    }

    std::string file_path;
    if (binary_id.empty() && args.contains("file_path") && args["file_path"].is_string()) {
        file_path = args["file_path"].get<std::string>();
    }

    uint32_t target_pid = 0;
    if (binary_id.empty() && file_path.empty()) {
        for (const char* key : {"target_pid", "process_id", "pid"}) {
            if (!args.contains(key)) continue;
            const auto& v = args[key];
            if (v.is_number_unsigned()) {
                target_pid = static_cast<uint32_t>(v.get<uint64_t>());
            } else if (v.is_number_integer()) {
                int64_t s = v.get<int64_t>();
                if (s > 0) target_pid = static_cast<uint32_t>(s);
            } else if (v.is_string()) {
                std::string s = v.get<std::string>();
                if (!s.empty()) {
                    try { target_pid = static_cast<uint32_t>(std::stoul(s, nullptr, 0)); }
                    catch (...) { target_pid = 0; }
                }
            }
            if (target_pid != 0) break;
        }
    }

    size_t resolved_idx = static_cast<size_t>(-1);
    if (!binary_id.empty()) {
        size_t idx = 0;
        if (analysis_session::find_session_by_id(binary_id, &idx)) {
            resolved_idx = idx;
        } else {
            scope.ok = false;
            scope.err = "binary_id '" + binary_id + "' not found in active sessions";
            if (out_err) *out_err = scope.err;
            diag::log_tagged_fmt("mcp_standalone",
                "resolve_target binary_id='%s' not_found", binary_id.c_str());
            return scope;
        }
    } else if (!file_path.empty()) {
        size_t idx = 0;
        if (analysis_session::find_session_by_path(file_path, &idx)) {
            resolved_idx = idx;
        } else {
            scope.ok = false;
            scope.err = "file_path '" + file_path + "' not found in active sessions";
            if (out_err) *out_err = scope.err;
            return scope;
        }
    } else if (target_pid != 0) {
        size_t idx = 0;
        if (analysis_session::find_session_by_pid(target_pid, &idx)) {
            resolved_idx = idx;
        }
    }

    if (resolved_idx == static_cast<size_t>(-1)) {
        return scope;
    }

    size_t cur = analysis_session::active_session_idx();
    scope.prev_active_idx = cur;
    scope.target_idx = resolved_idx;
    scope.resolved = true;

    auto sum = analysis_session::summarize_session_at(resolved_idx);
    scope.resolved_id = sum.id;

    if (cur == resolved_idx) {
        diag::log_tagged_fmt("mcp_standalone",
            "resolve_target id='%s' idx=%llu already_active",
            scope.resolved_id.c_str(),
            static_cast<unsigned long long>(resolved_idx));
        return scope;
    }

    if (!analysis_session::switch_session(resolved_idx)) {
        scope.ok = false;
        scope.err = std::string("switch_session failed: ") + analysis_session::last_error();
        if (out_err) *out_err = scope.err;
        diag::log_tagged_fmt("mcp_standalone",
            "resolve_target switch_failed target_idx=%llu err='%s'",
            static_cast<unsigned long long>(resolved_idx), scope.err.c_str());
        return scope;
    }

    scope.swapped = true;
    diag::log_tagged_fmt("mcp_standalone",
        "resolve_target id='%s' resolved_idx=%llu swapped=1 prev_idx=%llu",
        scope.resolved_id.c_str(),
        static_cast<unsigned long long>(resolved_idx),
        static_cast<unsigned long long>(cur));
    return scope;
}


}
