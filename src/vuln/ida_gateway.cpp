#include "ida_gateway.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <unordered_set>

#include <nalt.hpp>

#include "chain_state_contracts.hpp"

namespace aida
{
namespace vuln
{
namespace
{

std::uint64_t monotonic_ms()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::string bytes_to_hex(const uchar* bytes, std::size_t count)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < count; ++i)
        oss << std::setw(2) << static_cast<unsigned>(bytes[i]);
    return oss.str();
}

bool cancel_requested(const std::shared_ptr<std::atomic_bool>& flag)
{
    return flag && flag->load(std::memory_order_acquire);
}

}

struct ida_gateway_t::impl_t
{
    std::atomic_bool active{false};
    std::atomic_bool stopping{false};
    std::atomic<std::uint64_t> next_request_id{1};
    std::atomic<std::uint64_t> idb_generation_value{1};
    std::atomic<std::uint64_t> hexrays_generation_value{1};
    std::atomic<std::uint64_t> total_requests{0};
    std::atomic<std::uint64_t> completed_requests{0};
    std::atomic<std::uint64_t> cancelled_requests{0};
    std::atomic<std::uint64_t> deferred_requests{0};
    std::atomic<std::uint64_t> exception_requests{0};
    mutable std::mutex mutex;
    std::unordered_set<std::uint64_t> pending;
    std::unordered_set<std::uint64_t> cancelled;

    bool is_cancelled(std::uint64_t request_id) const
    {
        std::lock_guard<std::mutex> lock(mutex);
        return cancelled.find(request_id) != cancelled.end();
    }

    void add_pending(std::uint64_t request_id)
    {
        std::lock_guard<std::mutex> lock(mutex);
        pending.insert(request_id);
    }

    void remove_pending(std::uint64_t request_id)
    {
        std::lock_guard<std::mutex> lock(mutex);
        pending.erase(request_id);
        cancelled.erase(request_id);
    }
};

const char* gateway_domain_name(ida_gateway_domain_t domain)
{
    switch (domain)
    {
    case ida_gateway_domain_t::idb: return "idb";
    case ida_gateway_domain_t::hexrays: return "hexrays";
    case ida_gateway_domain_t::ui: return "ui";
    case ida_gateway_domain_t::netnode: return "netnode";
    case ida_gateway_domain_t::xref: return "xref";
    case ida_gateway_domain_t::function: return "function";
    case ida_gateway_domain_t::segment: return "segment";
    case ida_gateway_domain_t::type: return "type";
    default: return "mixed";
    }
}

ida_gateway_t::ida_gateway_t()
    : m_impl(std::make_unique<impl_t>())
{
}

ida_gateway_t::~ida_gateway_t()
{
    stop();
}

void ida_gateway_t::start()
{
    m_impl->stopping.store(false, std::memory_order_release);
    m_impl->active.store(true, std::memory_order_release);
}

void ida_gateway_t::stop()
{
    m_impl->stopping.store(true, std::memory_order_release);
    m_impl->active.store(false, std::memory_order_release);
    cancel_all();
}

void ida_gateway_t::cancel_all()
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    for (std::uint64_t request_id : m_impl->pending)
        m_impl->cancelled.insert(request_id);
}

bool ida_gateway_t::cancel_request(std::uint64_t request_id)
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    if (m_impl->pending.find(request_id) == m_impl->pending.end())
        return false;
    m_impl->cancelled.insert(request_id);
    return true;
}

ida_gateway_result_t ida_gateway_t::execute(
    const ida_gateway_request_t& request,
    const std::function<nlohmann::json(const ida_gateway_context_t&)>& body)
{
    ida_gateway_result_t result;
    result.request_id = m_impl->next_request_id.fetch_add(1, std::memory_order_acq_rel);
    result.idb_generation = m_impl->idb_generation_value.load(std::memory_order_acquire);
    result.hexrays_generation = m_impl->hexrays_generation_value.load(std::memory_order_acquire);
    result.phase = request.phase;
    result.operation = request.operation;
    const std::uint64_t submitted_ms = monotonic_ms();
    m_impl->total_requests.fetch_add(1, std::memory_order_acq_rel);

    if (!m_impl->active.load(std::memory_order_acquire) || m_impl->stopping.load(std::memory_order_acquire))
    {
        result.cancelled = true;
        result.error = "gateway_stopping";
        m_impl->cancelled_requests.fetch_add(1, std::memory_order_acq_rel);
        return result;
    }

    if (cancel_requested(request.cancellation))
    {
        result.cancelled = true;
        result.error = "request_cancelled_before_enqueue";
        m_impl->cancelled_requests.fetch_add(1, std::memory_order_acq_rel);
        return result;
    }

    if (request.expected_idb_generation != 0 && request.expected_idb_generation != result.idb_generation)
    {
        result.stale_generation = true;
        result.error = "idb_generation_changed_before_enqueue";
        return result;
    }

    if (request.expected_hexrays_generation != 0 && request.expected_hexrays_generation != result.hexrays_generation)
    {
        result.stale_generation = true;
        result.error = "hexrays_generation_changed_before_enqueue";
        return result;
    }

    if (!is_main_thread()
        && request.modal_policy == ida_gateway_modal_policy_t::defer_if_modal
        && (request.mff_flags & MFF_WRITE) != 0)
    {
        struct modal_probe_t final : exec_request_t
        {
            bool active_modal = false;
            ssize_t idaapi execute() override
            {
                active_modal = get_active_modal_widget() != nullptr;
                return 1;
            }
        };
        modal_probe_t probe;
        if (execute_sync(probe, MFF_FAST) > 0 && probe.active_modal)
        {
            result.deferred = true;
            result.error = "modal_widget_active";
            m_impl->deferred_requests.fetch_add(1, std::memory_order_acq_rel);
            return result;
        }
    }

    struct sync_request_t final : exec_request_t
    {
        impl_t* impl = nullptr;
        ida_gateway_request_t request;
        ida_gateway_result_t* result = nullptr;
        std::function<nlohmann::json(const ida_gateway_context_t&)> body;
        std::uint64_t submitted_ms = 0;

        ssize_t idaapi execute() override
        {
            const std::uint64_t started_ms = monotonic_ms();
            result->queue_wait_ms = started_ms >= submitted_ms ? started_ms - submitted_ms : 0;
            try
            {
                if (impl->stopping.load(std::memory_order_acquire) || impl->is_cancelled(result->request_id) || cancel_requested(request.cancellation))
                {
                    result->cancelled = true;
                    result->error = "request_cancelled";
                    return 0;
                }

                if (request.deadline_ms != 0 && result->queue_wait_ms >= request.deadline_ms)
                {
                    result->timed_out = true;
                    result->error = "deadline_expired_before_execution";
                    return 0;
                }

                if (request.modal_policy == ida_gateway_modal_policy_t::defer_if_modal && get_active_modal_widget() != nullptr)
                {
                    result->deferred = true;
                    result->error = "modal_widget_active";
                    return 0;
                }

                const std::uint64_t current_idb_generation = impl->idb_generation_value.load(std::memory_order_acquire);
                const std::uint64_t current_hexrays_generation = impl->hexrays_generation_value.load(std::memory_order_acquire);
                if (request.expected_idb_generation != 0 && request.expected_idb_generation != current_idb_generation)
                {
                    result->stale_generation = true;
                    result->error = "idb_generation_changed_before_execution";
                    return 0;
                }
                if (request.expected_hexrays_generation != 0 && request.expected_hexrays_generation != current_hexrays_generation)
                {
                    result->stale_generation = true;
                    result->error = "hexrays_generation_changed_before_execution";
                    return 0;
                }

                ida_gateway_context_t ctx;
                ctx.request_id = result->request_id;
                ctx.idb_generation = current_idb_generation;
                ctx.hexrays_generation = current_hexrays_generation;
                ctx.cancellation_requested = cancel_requested(request.cancellation);
                result->data = body(ctx);
                result->ok = true;
                return 1;
            }
            catch (const std::exception& ex)
            {
                result->exception = true;
                result->error = ex.what();
                return 0;
            }
            catch (...)
            {
                result->exception = true;
                result->error = "unknown_exception";
                return 0;
            }
        }
    };

    sync_request_t sync_request;
    sync_request.impl = m_impl.get();
    sync_request.request = request;
    sync_request.result = &result;
    sync_request.body = body;
    sync_request.submitted_ms = submitted_ms;

    m_impl->add_pending(result.request_id);
    ssize_t rc = 0;
    if (is_main_thread())
        rc = sync_request.execute();
    else
        rc = execute_sync(sync_request, request.mff_flags);
    const std::uint64_t finished_ms = monotonic_ms();
    m_impl->remove_pending(result.request_id);
    result.elapsed_ms = finished_ms >= submitted_ms ? finished_ms - submitted_ms : 0;

    if (request.deadline_ms != 0 && result.elapsed_ms > request.deadline_ms && !result.cancelled && !result.deferred && !result.stale_generation)
    {
        result.timed_out = true;
        if (result.error.empty())
            result.error = result.ok ? "deadline_exceeded_after_execution" : "deadline_exceeded";
        result.ok = false;
    }

    if (rc <= 0 && result.error.empty())
        result.error = "execute_sync_failed";

    if (result.cancelled)
        m_impl->cancelled_requests.fetch_add(1, std::memory_order_acq_rel);
    if (result.deferred)
        m_impl->deferred_requests.fetch_add(1, std::memory_order_acq_rel);
    if (result.exception)
        m_impl->exception_requests.fetch_add(1, std::memory_order_acq_rel);
    if (result.ok)
        m_impl->completed_requests.fetch_add(1, std::memory_order_acq_rel);

    return result;
}

ida_gateway_result_t ida_gateway_t::capture_idb_snapshot(
    const std::shared_ptr<std::atomic_bool>& cancellation,
    std::uint32_t deadline_ms)
{
    ida_gateway_request_t request;
    request.domain = ida_gateway_domain_t::idb;
    request.phase = "snapshot";
    request.operation = "capture_current_idb_snapshot";
    request.mff_flags = MFF_READ;
    request.deadline_ms = deadline_ms;
    request.cancellation = cancellation;
    request.expected_idb_generation = idb_generation();
    return execute(request, [](const ida_gateway_context_t&) {
        ida_gateway_snapshot_t snapshot;
        char root[MAXSTR] = {};
        char path[QMAXPATH] = {};
        char proc[IDAINFO_PROCNAME_SIZE] = {};
        get_root_filename(root, sizeof(root));
        get_input_file_path(path, sizeof(path));
        inf_get_procname(proc, sizeof(proc));
        uchar sha[32] = {};
        snapshot.root_filename = root;
        snapshot.input_path = path;
        snapshot.sha256 = retrieve_input_file_sha256(sha) ? bytes_to_hex(sha, sizeof(sha)) : std::string();
        snapshot.image_base = static_cast<std::uint64_t>(get_imagebase());
        snapshot.min_ea = static_cast<std::uint64_t>(inf_get_min_ea());
        snapshot.max_ea = static_cast<std::uint64_t>(inf_get_max_ea());
        snapshot.pointer_width_bits = inf_is_64bit() ? 64u : (inf_is_32bit_exactly() ? 32u : 16u);
        snapshot.processor = proc;
        snapshot.endianness = inf_is_be() ? "big" : "little";
        snapshot.dll = inf_is_dll();
        snapshot.kernel_mode = inf_is_kernel_mode();
        snapshot.valid = true;
        snapshot.snapshot_id = "idb_" + chain::stable_hash_hex(snapshot.root_filename + snapshot.sha256 +
            std::to_string(snapshot.image_base) + std::to_string(snapshot.min_ea) + std::to_string(snapshot.max_ea));
        return to_json(snapshot);
    });
}

std::uint64_t ida_gateway_t::bump_idb_generation(const char*)
{
    return m_impl->idb_generation_value.fetch_add(1, std::memory_order_acq_rel) + 1;
}

std::uint64_t ida_gateway_t::bump_hexrays_generation(const char*)
{
    return m_impl->hexrays_generation_value.fetch_add(1, std::memory_order_acq_rel) + 1;
}

std::uint64_t ida_gateway_t::idb_generation() const
{
    return m_impl->idb_generation_value.load(std::memory_order_acquire);
}

std::uint64_t ida_gateway_t::hexrays_generation() const
{
    return m_impl->hexrays_generation_value.load(std::memory_order_acquire);
}

std::vector<std::uint64_t> ida_gateway_t::pending_request_ids() const
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    return std::vector<std::uint64_t>(m_impl->pending.begin(), m_impl->pending.end());
}

nlohmann::json ida_gateway_t::metrics_json() const
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    return nlohmann::json{
        {"active", m_impl->active.load(std::memory_order_acquire)},
        {"stopping", m_impl->stopping.load(std::memory_order_acquire)},
        {"idb_generation", m_impl->idb_generation_value.load(std::memory_order_acquire)},
        {"hexrays_generation", m_impl->hexrays_generation_value.load(std::memory_order_acquire)},
        {"pending_requests", m_impl->pending.size()},
        {"total_requests", m_impl->total_requests.load(std::memory_order_acquire)},
        {"completed_requests", m_impl->completed_requests.load(std::memory_order_acquire)},
        {"cancelled_requests", m_impl->cancelled_requests.load(std::memory_order_acquire)},
        {"deferred_requests", m_impl->deferred_requests.load(std::memory_order_acquire)},
        {"exception_requests", m_impl->exception_requests.load(std::memory_order_acquire)}
    };
}

nlohmann::json to_json(const ida_gateway_snapshot_t& snapshot)
{
    return nlohmann::json{
        {"snapshot_id", snapshot.snapshot_id},
        {"root_filename", snapshot.root_filename},
        {"input_path", snapshot.input_path},
        {"sha256", snapshot.sha256},
        {"image_base", snapshot.image_base},
        {"min_ea", snapshot.min_ea},
        {"max_ea", snapshot.max_ea},
        {"pointer_width_bits", snapshot.pointer_width_bits},
        {"processor", snapshot.processor},
        {"endianness", snapshot.endianness},
        {"dll", snapshot.dll},
        {"kernel_mode", snapshot.kernel_mode},
        {"valid", snapshot.valid},
        {"error", snapshot.error}
    };
}

}
}
