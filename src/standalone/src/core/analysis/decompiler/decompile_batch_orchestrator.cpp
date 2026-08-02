#include "decompile_batch_orchestrator.hpp"

#include "api_prototype_table.hpp"
#include "decompiler_service.hpp"
#include "decompiler_ui_integration.hpp"
#include "generation_snapshot_store.hpp"
#include "native_worker_host.hpp"

#include "../builtin_typelib.hpp"
#include "../flirt/static_recognition_service.hpp"
#include "../../disasm/ghidra_adapters/aida_arch_map.hpp"
#include "../../disasm/ghidra_adapters/aida_load_image.hpp"
#include "../../infra/executor.hpp"
#include "../../mcp/downstream_producer_governor.hpp"
#include "../../../helpers/diag_log.hpp"
#include "../../../../workers/native_decompiler/snapshot_sidecar.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::size_t k_max_pending_items = 2'000'000;
constexpr std::uint64_t k_batch_deadline_floor_ms = 2'000;
constexpr std::uint64_t k_batch_deadline_cap_ms = 60'000;
constexpr std::uint64_t k_interactive_deadline_cap_ms = 15'000;
constexpr std::uint64_t k_deadline_scaled_log_threshold_ms = 15'000;
constexpr std::uint64_t k_worker_rss_fallback_bytes = 500ULL << 20;
constexpr std::uint64_t k_worker_rss_allowance_bytes = 64ULL << 20;
constexpr std::uint64_t k_batch_job_memory_headroom_bytes = 256ULL << 20;
constexpr std::uint64_t k_memory_budget_floor_bytes = 4ULL << 30;
constexpr std::uint64_t k_memory_budget_cap_bytes = 32ULL << 30;
constexpr std::size_t k_absolute_slot_cap = 64;
constexpr std::uint64_t k_batch_snapshot_absolute_cap = 1024ULL << 20;
constexpr std::uint64_t k_worker_snapshot_cap = 1024ULL << 20;
constexpr std::uint64_t k_snapshot_header_floor = 1ULL << 20;
constexpr std::uint64_t k_snapshot_read_quantum = 4ULL << 20;
constexpr std::uint64_t k_snapshot_sidecar_absolute_cap = 64ULL << 20;

struct batch_work_item_t {
    std::uint64_t function_id = 0;
    std::uint64_t entry_rva = 0;
    std::uint64_t byte_size = 0;
    std::uint32_t depth = 0;
    std::uint8_t lane = 0;
    std::uint8_t attempt = 0;
};

std::uint64_t rva_of(const address_t& address, std::uint64_t image_base) noexcept
{
    if (address.space == address_space_id_t::relative_virtual)
        return address.value;
    if ((address.space == address_space_id_t::virtual_address ||
         address.space == address_space_id_t::live_virtual) && address.value >= image_base)
        return address.value - image_base;
    return address.value;
}

std::string sidecar_hex_text(std::uint64_t value)
{
    static constexpr char k_hex[] = "0123456789abcdef";
    char digits[16];
    std::size_t count = 0;
    do {
        digits[count++] = k_hex[value & 0xFULL];
        value >>= 4U;
    } while (value != 0 && count < 16);
    std::string text;
    text.reserve(count);
    while (count != 0)
        text.push_back(digits[--count]);
    return text;
}

std::uint64_t average_instruction_bytes(architecture_id_t architecture) noexcept
{
    switch (architecture) {
    case architecture_id_t::x86:
    case architecture_id_t::x86_64:
    case architecture_id_t::arm:
    case architecture_id_t::aarch64:
    case architecture_id_t::arm64ec:
    case architecture_id_t::mips:
    case architecture_id_t::mips64:
    case architecture_id_t::ppc:
    case architecture_id_t::ppc64:
    case architecture_id_t::riscv:
    case architecture_id_t::riscv32:
    case architecture_id_t::riscv64:
        return 4;
    default:
        return 4;
    }
}

std::uint64_t estimate_instructions(std::uint64_t byte_size, architecture_id_t architecture) noexcept
{
    const std::uint64_t average = average_instruction_bytes(architecture);
    return byte_size / average + ((byte_size % average) != 0 ? 1 : 0);
}

const char* pipeline_status_name(decompiler_pipeline_status_t status) noexcept
{
    switch (status) {
    case decompiler_pipeline_status_t::completed: return "completed";
    case decompiler_pipeline_status_t::invalid_request: return "invalid_request";
    case decompiler_pipeline_status_t::explicit_request_required: return "explicit_request_required";
    case decompiler_pipeline_status_t::provider_unavailable: return "provider_unavailable";
    case decompiler_pipeline_status_t::provider_failed: return "provider_failed";
    case decompiler_pipeline_status_t::provider_crashed: return "provider_crashed";
    case decompiler_pipeline_status_t::deadline_exceeded: return "deadline_exceeded";
    case decompiler_pipeline_status_t::cancelled: return "cancelled";
    case decompiler_pipeline_status_t::resource_limit: return "resource_limit";
    case decompiler_pipeline_status_t::stale_generation: return "stale_generation";
    case decompiler_pipeline_status_t::normalization_failed: return "normalization_failed";
    case decompiler_pipeline_status_t::rendering_failed: return "rendering_failed";
    case decompiler_pipeline_status_t::cache_integrity_failure: return "cache_integrity_failure";
    case decompiler_pipeline_status_t::service_stopped: return "service_stopped";
    }
    return "unknown";
}

bool result_retryable(const decompiler_pipeline_result_t& result) noexcept
{
    if (result.status == decompiler_pipeline_status_t::provider_crashed ||
        result.status == decompiler_pipeline_status_t::resource_limit)
        return true;
    return std::any_of(result.diagnostics.begin(), result.diagnostics.end(),
        [](const decompiler_diagnostic_t& diagnostic) { return diagnostic.retryable; });
}

std::uint64_t resolve_memory_budget_bytes() noexcept
{
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    std::uint64_t derived = 0;
    if (GlobalMemoryStatusEx(&status) && status.ullTotalPhys != 0)
        derived = status.ullTotalPhys / 4;
    if (derived < k_memory_budget_floor_bytes)
        return k_memory_budget_floor_bytes;
    if (derived > k_memory_budget_cap_bytes)
        return k_memory_budget_cap_bytes;
    return derived;
}

}

struct decompile_batch_orchestrator_t::state_t {
    std::weak_ptr<analysis_workspace_t> workspace;
    std::shared_ptr<analysis_metrics_t> metrics;
    std::uint64_t memory_budget_bytes = 0;

    mutable std::mutex mutex;
    std::condition_variable wake;
    std::shared_ptr<const analysis_publication_t> pending_publication;
    bool publish_pending = false;
    bool control_exit = false;
    bool control_started = false;
    std::uint64_t control_task_id = 0;

    std::shared_ptr<const analysis_publication_t> run_publication;
    std::shared_ptr<decompiler_pipeline_service_t> service;
    std::shared_ptr<const decompiler_provider_context_t> provider_context;
    std::unordered_map<std::uint64_t, const function_record_t*> functions_by_id;
    cancellation_source_t run_cancel;
    bool run_active = false;
    bool run_starting = false;
    bool run_finishing = false;
    bool run_draining = false;
    std::atomic<bool> run_cancelling{false};
    std::atomic<std::uint64_t> cancel_epoch{0};
    std::uint64_t run_generation = 0;
    std::uint64_t run_revision = 0;
    std::uint64_t run_overlay_revision = 0;
    std::uint64_t run_image_base = 0;
    std::uint64_t run_snapshot_bytes = 0;
    std::chrono::steady_clock::time_point run_started;
    std::uint64_t total = 0;
    std::uint64_t completed = 0;
    std::uint64_t failed = 0;
    std::uint64_t cancelled = 0;
    std::uint64_t mem_hits = 0;
    std::uint64_t disk_hits = 0;
    std::uint64_t wall_ns = 0;
    std::uint64_t lane_completed[4] = {};
    std::uint64_t lane_failed[4] = {};
    std::atomic<std::uint64_t> in_flight{0};
    std::uint64_t progress_log_mark = 0;
    std::uint64_t ema_last_completed = 0;
    std::chrono::steady_clock::time_point ema_last_time;
    double rate_ema = 0.0;
    std::uint64_t governor_rejected_baseline = 0;
    mcp_standalone::downstream::scoped_admission_t admission;
    std::size_t slots_total = 0;
    std::size_t slots_done = 0;
    std::atomic<std::size_t> slots_effective{0};
    std::vector<batch_work_item_t> worklist;
    std::atomic<std::uint64_t> worklist_cursor{0};
    std::deque<batch_work_item_t> retry_queue;
    std::deque<batch_work_item_t> interactive_queue;
    std::vector<aida::infra::taskflow_runtime::job_handle_t> slot_handles;
    mutable std::mutex ids_mutex;
    std::unordered_set<std::uint64_t> queued_ids;
    std::unordered_set<std::uint64_t> in_flight_ids;
    std::uint64_t last_started_generation = 0;
    std::uint64_t last_started_revision = 0;
};

decompile_batch_orchestrator_t::decompile_batch_orchestrator_t(std::shared_ptr<state_t> state)
    : state_(std::move(state))
{
}

decompile_batch_orchestrator_t::~decompile_batch_orchestrator_t()
{
    request_cancel();
    (void)drain(std::chrono::steady_clock::now() + std::chrono::seconds(2));
    if (state_) {
        {
            std::lock_guard lock(state_->mutex);
            state_->control_exit = true;
            state_->wake.notify_all();
        }
        if (state_->control_started && state_->control_task_id != 0) {
            const auto waited = aida::infra::executor::wait_for(
                state_->control_task_id, 2000);
            if (!waited.completed)
                (void)aida::infra::executor::cancel(state_->control_task_id);
        }
    }
}

namespace {

void metrics_add(const std::shared_ptr<analysis_metrics_t>& metrics, analysis_metric_t metric,
                 std::uint64_t value = 1) noexcept
{
    if (metrics)
        metrics->add(metric, value);
}

void metrics_set_max(const std::shared_ptr<analysis_metrics_t>& metrics, analysis_metric_t metric,
                     std::uint64_t value) noexcept
{
    if (metrics)
        metrics->set_max(metric, value);
}

std::uint64_t function_byte_size(const analysis_snapshot_t& snapshot,
                                 const function_record_t& function) noexcept
{
    std::uint64_t total = 0;
    for (const auto& chunk : function.chunks) {
        if (chunk.rva_end > chunk.rva_start)
            total += chunk.rva_end - chunk.rva_start;
    }
    if (total == 0 && function.chunk_count != 0 &&
        function.first_chunk <= snapshot.function_chunks.size() &&
        function.chunk_count <= snapshot.function_chunks.size() - function.first_chunk) {
        for (std::uint32_t index = 0; index < function.chunk_count; ++index) {
            const auto& chunk = snapshot.function_chunks[function.first_chunk + index];
            if (chunk.end.value >= chunk.start.value)
                total += chunk.end.value - chunk.start.value;
        }
    }
    if (total == 0 && function.end.value >= function.start.value)
        total = function.end.value - function.start.value;
    return total;
}

std::size_t pending_queue_depth(const decompile_batch_orchestrator_t::state_t& state) noexcept
{
    const std::uint64_t cursor = state.worklist_cursor.load(std::memory_order_acquire);
    const std::uint64_t pending_worklist = cursor < state.worklist.size()
        ? state.worklist.size() - cursor : 0;
    return static_cast<std::size_t>(pending_worklist) +
        state.retry_queue.size() + state.interactive_queue.size();
}

void cancel_run_locked(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state)
{
    state->cancel_epoch.fetch_add(1, std::memory_order_acq_rel);
    state->run_cancel.request_cancel();
    state->run_cancelling.store(true, std::memory_order_release);
    const std::uint64_t queued = pending_queue_depth(*state);
    if (queued != 0) {
        state->cancelled += queued;
        metrics_add(state->metrics, analysis_metric_t::decompile_batch_cancelled, queued);
        state->worklist_cursor.store(state->worklist.size(), std::memory_order_release);
        state->retry_queue.clear();
        state->interactive_queue.clear();
        std::lock_guard ids_lock(state->ids_mutex);
        state->queued_ids.clear();
    }
    state->wake.notify_all();
}

void start_run(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state,
               const std::shared_ptr<const analysis_publication_t>& publication);
void monitor_run(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state);
void finish_run(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state);
void slot_main(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state,
               std::size_t slot_index);
void process_item(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state,
                  batch_work_item_t item);
void process_item_core(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state,
                       batch_work_item_t item);

struct in_flight_lease_t {
    in_flight_lease_t(
        const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& leased_state,
        std::uint64_t leased_function_id) noexcept
        : state(leased_state), function_id(leased_function_id) {}
    in_flight_lease_t(const in_flight_lease_t&) = delete;
    in_flight_lease_t& operator=(const in_flight_lease_t&) = delete;
    ~in_flight_lease_t()
    {
        if (!state)
            return;
        try {
            {
                std::lock_guard ids_lock(state->ids_mutex);
                state->in_flight_ids.erase(function_id);
            }
            state->in_flight.fetch_sub(1, std::memory_order_acq_rel);
            state->wake.notify_all();
        } catch (...) {
        }
    }
    std::shared_ptr<decompile_batch_orchestrator_t::state_t> state;
    std::uint64_t function_id = 0;
};

void control_main(std::shared_ptr<decompile_batch_orchestrator_t::state_t> state)
{
    std::unique_lock lock(state->mutex);
    while (true) {
        state->wake.wait(lock, [&state] {
            return state->publish_pending || state->control_exit;
        });
        if (state->control_exit)
            return;
        auto publication = state->pending_publication;
        state->publish_pending = false;
        state->pending_publication.reset();
        if (!publication)
            continue;
        lock.unlock();
        start_run(state, publication);
        monitor_run(state);
        lock.lock();
    }
}

void start_run(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state,
               const std::shared_ptr<const analysis_publication_t>& publication)
{
    auto workspace = state->workspace.lock();
    if (!workspace || workspace->closing() || workspace->closed())
        return;
    const auto snapshot = publication->snapshot;
    if (!snapshot || !snapshot->baseline_complete || !snapshot->normalized_image ||
        publication->analysis_revision == 0 ||
        !publication->coherent_with(workspace->identity()))
        return;
    const std::uint64_t cancel_epoch_at_entry =
        state->cancel_epoch.load(std::memory_order_acquire);
    cancellation_token_t run_token;
    bool start_cancelled = false;
    {
        std::lock_guard lock(state->mutex);
        if (publication->generation == state->last_started_generation &&
            publication->analysis_revision == state->last_started_revision)
            return;
        start_cancelled = state->run_cancelling.load(std::memory_order_acquire);
        if (!start_cancelled) {
            state->run_cancel = cancellation_source_t();
            state->run_starting = true;
            run_token = state->run_cancel.token();
        }
    }
    auto abort_start = [&state](const char* reason) {
        std::lock_guard lock(state->mutex);
        state->run_starting = false;
        state->run_active = false;
        state->wake.notify_all();
        diag::log_tagged_fmt("dec_batch", "run_aborted reason=%s", reason);
    };
    if (start_cancelled) {
        abort_start("cancelled");
        return;
    }
    if (snapshot->functions.empty()) {
        abort_start("no_functions");
        return;
    }
    if (snapshot->functions.size() > k_max_pending_items) {
        diag::log_tagged_fmt("dec_batch",
            "run_refused reason=pending_items functions=%zu limit=%zu",
            snapshot->functions.size(), k_max_pending_items);
        abort_start("pending_items");
        return;
    }
    auto language = ghidra_adapter::resolve_ghidra_language(*snapshot->normalized_image, {});
    if (!language) {
        diag::log_tagged_fmt("dec_batch", "run_deferred reason=no_native_language");
        abort_start("no_native_language");
        return;
    }
    auto integration = decompiler_ui_integration_t::production_for_workspace(workspace);
    if (!integration || !integration.value() || !integration.value()->service()) {
        abort_start("pipeline_service_unavailable");
        return;
    }
    if (run_token.stop_requested()) {
        abort_start("cancelled");
        return;
    }
    const auto service = integration.value()->service();
    mcp_standalone::downstream::producer_identity_t identity;
    identity.kind = mcp_standalone::downstream::producer_kind_t::decompiler;
    identity.tool_name = "decompile_batch_orchestrator";
    identity.principal_id = workspace->identity().binary_id().to_hex();
    identity.target_id = identity.principal_id;
    identity.generation = publication->generation;
    auto admission = mcp_standalone::downstream::scoped_admission_t::acquire(identity);
    if (!admission.active()) {
        auto rejected = mcp_standalone::downstream::governor_t::instance().try_admit(identity);
        diag::log_tagged_fmt("dec_batch",
            "FEATURE-WORKER-GROUP-REJECT decompile_batch_orchestrator reason=%s quota=%s observed=%zu limit=%zu",
            rejected.reason.c_str(), rejected.quota_name.c_str(), rejected.observed, rejected.limit);
        abort_start("governor_rejected");
        return;
    }
    diag::log_tagged_fmt("dec_batch",
        "FEATURE-WORKER-GROUP-ADMIT decompile_batch_orchestrator token=%llu",
        static_cast<unsigned long long>(admission.token()));
    auto context = decompile_batch_orchestrator_t::capture_generation_provider_context(
        workspace, publication, run_token);
    if (!context) {
        admission.release("capture_failed");
        abort_start(context.error().code == workspace_error_code_t::cancelled ||
            context.error().code == workspace_error_code_t::deadline_exceeded
            ? "cancelled" : "snapshot_capture_failed");
        return;
    }
    const auto& context_bytes = std::dynamic_pointer_cast<const ghidra_native_provider_context_t>(
        context.value());
    const std::uint64_t snapshot_bytes = context_bytes && context_bytes->snapshot()
        ? context_bytes->snapshot()->size() : 0;
    const auto& quotas = mcp_standalone::downstream::governor_t::instance().quotas();
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const std::uint32_t fabric_capacity =
        aida::infra::taskflow_runtime::analysis_compute_capacity();
#else
    const std::uint32_t fabric_capacity = (std::max)(2u, std::thread::hardware_concurrency());
#endif
    const std::size_t slots_desired = (std::max<std::size_t>)(2,
        (std::min<std::size_t>)(k_absolute_slot_cap,
            static_cast<std::size_t>(fabric_capacity >= 3 ? fabric_capacity - 1 : 2)));
    const std::uint64_t memory_admission_budget = state->memory_budget_bytes != 0
        ? state->memory_budget_bytes : k_memory_budget_floor_bytes;
    const std::uint64_t measured_rss = native_worker::native_worker_measured_private_bytes();
    const std::uint64_t rss_samples = native_worker::native_worker_measured_private_samples();
    const bool rss_measured = rss_samples >= 4 && measured_rss != 0;
    const std::uint64_t per_slot_bytes = rss_measured
        ? measured_rss + k_worker_rss_allowance_bytes
        : k_worker_rss_fallback_bytes;
    const auto admission_bytes_for = [snapshot_bytes, per_slot_bytes](std::size_t slot_count,
        std::uint64_t& snapshot_term, std::uint64_t& slot_term) noexcept -> std::uint64_t {
        snapshot_term = 0;
        slot_term = 0;
        if (static_cast<std::uint64_t>(slot_count) >
            (std::numeric_limits<std::uint64_t>::max)() / per_slot_bytes)
            return (std::numeric_limits<std::uint64_t>::max)();
        snapshot_term = snapshot_bytes;
        slot_term = static_cast<std::uint64_t>(slot_count) * per_slot_bytes;
        if (snapshot_term > (std::numeric_limits<std::uint64_t>::max)() - slot_term)
            return (std::numeric_limits<std::uint64_t>::max)();
        return snapshot_term + slot_term;
    };
    if (slots_desired < 2) {
        admission.release("slot_floor");
        diag::log_tagged_fmt("dec_batch",
            "run_deferred reason=slot_floor desired=%zu quota=%zu",
            slots_desired, quotas.decompiler_worker_group_size);
        abort_start("slot_floor");
        return;
    }
    std::size_t slots = slots_desired;
    std::uint64_t snapshot_mapping_bytes = 0;
    std::uint64_t worker_resident_bytes = 0;
    std::uint64_t memory_admission_bytes = admission_bytes_for(
        slots, snapshot_mapping_bytes, worker_resident_bytes);
    while (slots > 2 && memory_admission_bytes > memory_admission_budget) {
        --slots;
        memory_admission_bytes = admission_bytes_for(
            slots, snapshot_mapping_bytes, worker_resident_bytes);
    }
    if (slots != slots_desired) {
        diag::log_tagged_fmt("dec_batch",
            "slots_trimmed from=%zu to=%zu reason=memory_admission",
            slots_desired, slots);
    }
    diag::log_tagged_fmt("dec_batch",
        "budget_decision type=memory_admission formula=1*snapshot_bytes+slots*per_slot_rss shared_mapping=1 desired=%zu slots=%zu fabric_capacity=%u snapshot_bytes=%llu snapshot_term=%llu resident_term=%llu total=%llu budget=%llu per_slot=%llu measured_rss=%llu rss_samples=%llu rss_source=%s decision=%s",
        slots_desired,
        slots,
        fabric_capacity,
        static_cast<unsigned long long>(snapshot_bytes),
        static_cast<unsigned long long>(snapshot_mapping_bytes),
        static_cast<unsigned long long>(worker_resident_bytes),
        static_cast<unsigned long long>(memory_admission_bytes),
        static_cast<unsigned long long>(memory_admission_budget),
        static_cast<unsigned long long>(per_slot_bytes),
        static_cast<unsigned long long>(measured_rss),
        static_cast<unsigned long long>(rss_samples),
        rss_measured ? "measured" : "fallback",
        memory_admission_bytes > memory_admission_budget ? "defer" : "admit");
    const auto floor_policy = default_decompiler_profile_policy();
    const std::uint64_t job_memory_floor_bytes = snapshot_bytes != 0
        ? snapshot_bytes + k_batch_job_memory_headroom_bytes : 0;
    diag::log_tagged_fmt("dec_batch",
        "budget_decision type=memory_floor snapshot_bytes=%llu floor_bytes=%llu fast_ceiling=%llu balanced_ceiling=%llu thorough_ceiling=%llu escalate_fast=%d escalate_balanced=%d escalate_thorough=%d session_envelope_bytes=%llu",
        static_cast<unsigned long long>(snapshot_bytes),
        static_cast<unsigned long long>(job_memory_floor_bytes),
        static_cast<unsigned long long>(floor_policy.fast.max_memory_bytes),
        static_cast<unsigned long long>(floor_policy.balanced.max_memory_bytes),
        static_cast<unsigned long long>(floor_policy.thorough.max_memory_bytes),
        job_memory_floor_bytes != 0 &&
            floor_policy.fast.max_memory_bytes < job_memory_floor_bytes ? 1 : 0,
        job_memory_floor_bytes != 0 &&
            floor_policy.balanced.max_memory_bytes < job_memory_floor_bytes ? 1 : 0,
        job_memory_floor_bytes != 0 &&
            floor_policy.thorough.max_memory_bytes < job_memory_floor_bytes ? 1 : 0,
        static_cast<unsigned long long>(floor_policy.thorough.max_memory_bytes));
    if (memory_admission_bytes > memory_admission_budget) {
        admission.release("memory_admission");
        diag::log_tagged_fmt("dec_batch",
            "run_deferred reason=memory_admission slots=%zu snapshot_bytes=%llu",
            slots, static_cast<unsigned long long>(snapshot_bytes));
        abort_start("memory_admission");
        return;
    }
    std::unordered_map<std::uint64_t, const function_record_t*> functions_by_id;
    functions_by_id.reserve(snapshot->functions.size());
    const std::uint64_t image_base = snapshot->normalized_image->image_base;
    std::map<std::uint64_t, const function_record_t*> functions_by_start;
    for (const auto& function : snapshot->functions) {
        functions_by_id.emplace(function.id, &function);
        functions_by_start.emplace(rva_of(function.start, image_base), &function);
    }
    std::unordered_set<std::uint64_t> lane1_ids;
    for (const auto& symbol : snapshot->symbols) {
        if (symbol.kind != symbol_kind_t::export_symbol)
            continue;
        const auto found = functions_by_start.find(rva_of(symbol.address, image_base));
        if (found != functions_by_start.end() && found->second)
            lane1_ids.insert(found->second->id);
    }
    for (const auto& entry : snapshot->normalized_image->entry_points) {
        const std::uint64_t entry_rva = rva_of(entry.address, image_base);
        auto candidate = functions_by_start.upper_bound(entry_rva);
        if (candidate == functions_by_start.begin())
            continue;
        --candidate;
        const auto& function = *candidate->second;
        if (entry_rva >= rva_of(function.start, image_base) &&
            entry_rva < rva_of(function.end, image_base))
            lane1_ids.insert(function.id);
    }
    std::unordered_map<std::uint64_t, std::uint32_t> depths;
    depths.reserve(snapshot->functions.size());
    const bool call_edges_available = !snapshot->call_graph.edges.empty();
    if (!call_edges_available)
        diag::log_tagged_fmt("dec_batch", "run_lanes note=no_call_edges lane2=collapsed");
    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> adjacency;
    if (call_edges_available) {
        adjacency.reserve(snapshot->call_graph.edges.size());
        for (const auto& edge : snapshot->call_graph.edges) {
            if (edge.resolution != call_graph_resolution_t::direct ||
                !edge.target_function_id ||
                functions_by_id.count(edge.source_function_id) == 0 ||
                functions_by_id.count(*edge.target_function_id) == 0)
                continue;
            adjacency[edge.source_function_id].push_back(*edge.target_function_id);
        }
    }
    std::vector<std::uint64_t> lane1_ordered(lane1_ids.begin(), lane1_ids.end());
    std::sort(lane1_ordered.begin(), lane1_ordered.end());
    std::deque<std::uint64_t> bfs;
    for (const auto& id : lane1_ordered) {
        depths[id] = 0;
        bfs.push_back(id);
    }
    while (!bfs.empty()) {
        const std::uint64_t current = bfs.front();
        bfs.pop_front();
        const std::uint32_t depth = depths[current];
        const auto found = adjacency.find(current);
        if (found == adjacency.end())
            continue;
        for (const auto& target : found->second) {
            if (!depths.emplace(target, depth + 1).second)
                continue;
            bfs.push_back(target);
        }
    }
    std::vector<batch_work_item_t> worklist;
    worklist.reserve(snapshot->functions.size());
    for (const auto& function : snapshot->functions) {
        batch_work_item_t item;
        item.function_id = function.id;
        item.entry_rva = rva_of(function.start, image_base);
        item.byte_size = function_byte_size(*snapshot, function);
        if (lane1_ids.count(function.id)) {
            item.lane = 1;
            item.depth = 0;
        } else if (const auto found = depths.find(function.id); found != depths.end()) {
            item.lane = 2;
            item.depth = found->second;
        } else {
            item.lane = 3;
            item.depth = (std::numeric_limits<std::uint32_t>::max)();
        }
        worklist.push_back(item);
    }
    std::sort(worklist.begin(), worklist.end(), [](const batch_work_item_t& left,
                                                   const batch_work_item_t& right) {
        if (left.lane != right.lane)
            return left.lane < right.lane;
        if (left.depth != right.depth)
            return left.depth < right.depth;
        if (left.entry_rva != right.entry_rva)
            return left.entry_rva < right.entry_rva;
        return left.function_id < right.function_id;
    });
    if (run_token.stop_requested()) {
        admission.release("cancelled");
        abort_start("cancelled");
        return;
    }
    bool commit_cancelled = false;
    {
        std::lock_guard lock(state->mutex);
        if (state->cancel_epoch.load(std::memory_order_acquire) != cancel_epoch_at_entry) {
            commit_cancelled = true;
        } else {
            state->run_publication = publication;
            state->service = service;
            state->provider_context = context.value();
            state->functions_by_id = std::move(functions_by_id);
            state->run_generation = publication->generation;
            state->run_revision = publication->analysis_revision;
            state->run_overlay_revision = publication->overlay_revision;
            state->run_image_base = image_base;
            state->run_snapshot_bytes = snapshot_bytes;
            state->run_started = std::chrono::steady_clock::now();
            state->total = static_cast<std::uint64_t>(worklist.size());
            state->completed = 0;
            state->failed = 0;
            state->cancelled = 0;
            state->mem_hits = 0;
            state->disk_hits = 0;
            state->wall_ns = 0;
            std::memset(state->lane_completed, 0, sizeof(state->lane_completed));
            std::memset(state->lane_failed, 0, sizeof(state->lane_failed));
            state->in_flight.store(0, std::memory_order_release);
            state->progress_log_mark = 0;
            state->ema_last_completed = 0;
            state->ema_last_time = state->run_started;
            state->rate_ema = 0.0;
            state->governor_rejected_baseline = 0;
            state->worklist = std::move(worklist);
            state->worklist_cursor.store(0, std::memory_order_release);
            state->retry_queue.clear();
            state->interactive_queue.clear();
            state->slot_handles.clear();
            {
                std::lock_guard ids_lock(state->ids_mutex);
                state->in_flight_ids.clear();
                state->queued_ids.clear();
                state->queued_ids.reserve(state->worklist.size());
                for (const auto& item : state->worklist)
                    state->queued_ids.insert(item.function_id);
            }
            state->admission = std::move(admission);
            state->slots_total = slots;
            state->slots_done = 0;
            state->slots_effective.store(slots, std::memory_order_release);
            state->run_finishing = false;
            state->run_draining = false;
            state->run_starting = false;
            state->run_active = true;
            state->last_started_generation = publication->generation;
            state->last_started_revision = publication->analysis_revision;
        }
    }
    if (commit_cancelled) {
        admission.release("cancelled");
        abort_start("cancelled");
        return;
    }
    metrics_add(state->metrics, analysis_metric_t::decompile_batch_calls, 1);
    metrics_set_max(state->metrics, analysis_metric_t::decompile_batch_queue_depth_peak,
        static_cast<std::uint64_t>(state->worklist.size()));
    diag::log_tagged_fmt("dec_batch",
        "run_start generation=%llu analysis_revision=%llu functions=%zu lanes=interactive,exports,depth,linear slots=%zu quota=%zu snapshot_bytes=%llu profile=lane_graduated deadlines=size_aware",
        static_cast<unsigned long long>(publication->generation),
        static_cast<unsigned long long>(publication->analysis_revision),
        state->worklist.size(), slots, quotas.decompiler_worker_group_size,
        static_cast<unsigned long long>(snapshot_bytes));
    std::size_t submitted = 0;
    std::vector<aida::infra::taskflow_runtime::job_handle_t> spawned_handles;
    spawned_handles.reserve(slots);
    for (std::size_t index = 0; index < slots; ++index) {
        aida::infra::taskflow_runtime::task_descriptor_t slot_submission;
        slot_submission.owner_subsystem = "decompiler";
        slot_submission.label = "decompile.batch_slot";
        slot_submission.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
        slot_submission.priority = 3;
        slot_submission.lease_token = state->admission.token();
        slot_submission.generation = publication->generation;
        slot_submission.shutdown_policy = "drain";
        slot_submission.cancel_hook = [state] {
            try {
                state->run_cancel.request_cancel();
                state->wake.notify_all();
            } catch (...) {
            }
        };
        slot_submission.cancellable_body =
            [state, index](const aida::infra::taskflow_runtime::cancellation_token_t&) {
                slot_main(state, index);
            };
        auto slot_result = aida::infra::taskflow_runtime::submit(std::move(slot_submission));
        if (!slot_result.submitted || !slot_result.handle.valid()) {
            diag::log_tagged_fmt("dec_batch",
                "slot_post_failed index=%zu reason=%s",
                index,
                slot_result.reject_reason.empty() ? "unknown" : slot_result.reject_reason.c_str());
            continue;
        }
        spawned_handles.push_back(slot_result.handle);
        ++submitted;
    }
    {
        std::lock_guard lock(state->mutex);
        state->slot_handles = std::move(spawned_handles);
    }
    if (submitted == 0) {
        diag::log_tagged_fmt("dec_batch", "run_aborted reason=slot_submit_failed");
        {
            std::lock_guard lock(state->mutex);
            cancel_run_locked(state);
        }
        finish_run(state);
        return;
    }
    if (submitted != slots) {
        std::lock_guard lock(state->mutex);
        state->slots_total = submitted;
        state->slots_effective.store(submitted, std::memory_order_release);
    }
}

void monitor_run(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state)
{
    std::unique_lock lock(state->mutex);
    if (!state->run_active)
        return;
    while (state->run_active) {
        state->wake.wait_for(lock, std::chrono::milliseconds(250), [&state] {
            return !state->run_active || state->control_exit ||
                (state->publish_pending && !state->run_draining);
        });
        if (state->control_exit && !state->run_cancelling.load(std::memory_order_acquire))
            cancel_run_locked(state);
        if (state->publish_pending && !state->run_draining &&
            !state->run_cancelling.load(std::memory_order_acquire)) {
            const auto pending = state->pending_publication;
            const bool same_identity = pending && state->run_publication &&
                pending->generation == state->run_generation &&
                pending->analysis_revision == state->run_revision &&
                pending->snapshot.get() == state->run_publication->snapshot.get();
            if (same_identity) {
                state->publish_pending = false;
                state->pending_publication.reset();
                diag::log_tagged_fmt("dec_batch",
                    "republish_noop_ignored generation=%llu in_flight=%llu",
                    static_cast<unsigned long long>(state->run_generation),
                    static_cast<unsigned long long>(state->in_flight.load(std::memory_order_acquire)));
            } else {
                state->publish_pending = false;
                state->run_draining = true;
                diag::log_tagged_fmt("dec_batch",
                    "run_drain generation=%llu in_flight=%llu queued=%zu",
                    static_cast<unsigned long long>(state->run_generation),
                    static_cast<unsigned long long>(state->in_flight.load(std::memory_order_acquire)),
                    pending_queue_depth(*state));
            }
            state->wake.notify_all();
        }
        if (!state->run_active)
            break;
        const std::uint64_t processed = state->completed + state->failed + state->cancelled;
        const auto now = std::chrono::steady_clock::now();
        const double elapsed_s = std::chrono::duration<double>(now - state->ema_last_time).count();
        if (elapsed_s > 0.0) {
            const double instant =
                static_cast<double>(state->completed - state->ema_last_completed) / elapsed_s;
            const double alpha = (std::min)(1.0, elapsed_s / 60.0);
            state->rate_ema += (instant - state->rate_ema) * alpha;
            state->ema_last_completed = state->completed;
            state->ema_last_time = now;
        }
        if (processed / 250 != state->progress_log_mark) {
            state->progress_log_mark = processed / 250;
            const std::uint64_t remaining = state->total > processed ? state->total - processed : 0;
            const double eta = state->rate_ema > 0.0 ? remaining / state->rate_ema : 0.0;
            diag::log_tagged_fmt("dec_batch",
                "progress completed=%llu failed=%llu cancelled=%llu mem_hits=%llu disk_hits=%llu rate_funcs_s=%.2f eta_s=%.0f queue_depth=%zu",
                static_cast<unsigned long long>(state->completed),
                static_cast<unsigned long long>(state->failed),
                static_cast<unsigned long long>(state->cancelled),
                static_cast<unsigned long long>(state->mem_hits),
                static_cast<unsigned long long>(state->disk_hits),
                state->rate_ema, eta, pending_queue_depth(*state));
        }
        const auto governor_snapshot =
            mcp_standalone::downstream::governor_t::instance().snapshot();
        std::uint64_t decompiler_rejected = 0;
        const auto kind_found = governor_snapshot.by_kind.find("decompiler");
        if (kind_found != governor_snapshot.by_kind.end())
            decompiler_rejected = kind_found->second.total_rejected;
        const std::size_t effective = state->slots_effective.load(std::memory_order_acquire);
        if (effective > 2 && decompiler_rejected > state->governor_rejected_baseline + 16) {
            const std::size_t reduced = (std::max<std::size_t>)(2, effective / 2);
            state->slots_effective.store(reduced, std::memory_order_release);
            state->governor_rejected_baseline = decompiler_rejected;
            diag::log_tagged_fmt("dec_batch",
                "scale_down slots=%zu to=%zu reason=governor_rejections",
                effective, reduced);
        }
        if (!state->run_finishing) {
            if (state->run_draining) {
                if (state->retry_queue.empty() && state->interactive_queue.empty() &&
                    state->in_flight.load(std::memory_order_acquire) == 0) {
                    const std::uint64_t cursor = state->worklist_cursor.load(std::memory_order_acquire);
                    const std::uint64_t remaining = cursor < state->worklist.size()
                        ? state->worklist.size() - cursor : 0;
                    if (remaining != 0) {
                        state->cancelled += remaining;
                        metrics_add(state->metrics, analysis_metric_t::decompile_batch_cancelled,
                            remaining);
                        state->worklist_cursor.store(state->worklist.size(),
                            std::memory_order_release);
                        std::lock_guard ids_lock(state->ids_mutex);
                        for (std::uint64_t index = cursor; index < state->worklist.size(); ++index)
                            state->queued_ids.erase(
                                state->worklist[static_cast<std::size_t>(index)].function_id);
                    }
                    if (state->pending_publication)
                        state->publish_pending = true;
                    state->run_finishing = true;
                    state->wake.notify_all();
                }
            } else if (state->worklist_cursor.load(std::memory_order_acquire) >= state->worklist.size() &&
                state->retry_queue.empty() && state->interactive_queue.empty() &&
                state->in_flight.load(std::memory_order_acquire) == 0) {
                state->run_finishing = true;
                state->wake.notify_all();
            }
        }
        if (state->run_finishing && state->slots_done >= state->slots_total)
            break;
    }
    lock.unlock();
    finish_run(state);
}

void finish_run(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state)
{
    std::unique_lock lock(state->mutex);
    const std::uint64_t wall_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - state->run_started).count();
    const double busy_s = state->wall_ns / 1e9;
    const double funcs_s = busy_s > 0.0 ? state->completed / busy_s : 0.0;
    const double hit_rate = state->completed != 0
        ? static_cast<double>(state->mem_hits + state->disk_hits) / state->completed
        : 0.0;
    const bool reconciled = state->completed + state->failed + state->cancelled == state->total;
    diag::log_tagged_fmt("dec_batch",
        "run_complete generation=%llu wall_s=%llu funcs_s=%.2f hit_rate=%.3f eta=0 completed=%llu failed=%llu cancelled=%llu total=%llu reconciled=%d",
        static_cast<unsigned long long>(state->run_generation),
        static_cast<unsigned long long>(wall_ms / 1000), funcs_s, hit_rate,
        static_cast<unsigned long long>(state->completed),
        static_cast<unsigned long long>(state->failed),
        static_cast<unsigned long long>(state->cancelled),
        static_cast<unsigned long long>(state->total),
        reconciled ? 1 : 0);
    if (!reconciled) {
        diag::log_tagged_fmt("dec_batch",
            "run_reconciliation_mismatch completed=%llu failed=%llu cancelled=%llu total=%llu",
            static_cast<unsigned long long>(state->completed),
            static_cast<unsigned long long>(state->failed),
            static_cast<unsigned long long>(state->cancelled),
            static_cast<unsigned long long>(state->total));
    }
    diag::log_tagged_fmt("dec_batch",
        "run_lanes lane0_completed=%llu lane1_completed=%llu lane2_completed=%llu lane3_completed=%llu lane0_failed=%llu lane1_failed=%llu lane2_failed=%llu lane3_failed=%llu",
        static_cast<unsigned long long>(state->lane_completed[0]),
        static_cast<unsigned long long>(state->lane_completed[1]),
        static_cast<unsigned long long>(state->lane_completed[2]),
        static_cast<unsigned long long>(state->lane_completed[3]),
        static_cast<unsigned long long>(state->lane_failed[0]),
        static_cast<unsigned long long>(state->lane_failed[1]),
        static_cast<unsigned long long>(state->lane_failed[2]),
        static_cast<unsigned long long>(state->lane_failed[3]));
    if (state->admission.active()) {
        diag::log_tagged_fmt("dec_batch",
            "FEATURE-WORKER-GROUP-RELEASE decompile_batch_orchestrator token=%llu reason=completed",
            static_cast<unsigned long long>(state->admission.token()));
        state->admission.release("completed");
    }
    state->run_active = false;
    state->run_starting = false;
    state->run_finishing = false;
    state->run_draining = false;
    state->run_cancelling.store(false, std::memory_order_release);
    state->service.reset();
    state->provider_context.reset();
    state->functions_by_id.clear();
    state->worklist.clear();
    state->worklist_cursor.store(0, std::memory_order_release);
    state->retry_queue.clear();
    state->interactive_queue.clear();
    {
        std::lock_guard ids_lock(state->ids_mutex);
        state->queued_ids.clear();
        state->in_flight_ids.clear();
    }
    state->wake.notify_all();
    lock.unlock();
    namespace rt = aida::infra::taskflow_runtime;
    std::vector<rt::job_handle_t> handles = std::move(state->slot_handles);
    state->slot_handles.clear();
    for (auto& handle : handles) {
        if (!handle.valid())
            continue;
        const auto waited = rt::wait_for(handle, 5000);
        if (!waited.completed) {
            diag::log_tagged_fmt("dec_batch",
                "slot_join_timeout task_id=%llu timeout_ms=5000",
                static_cast<unsigned long long>(handle.id));
            (void)rt::cancel(handle);
        }
    }
}

void slot_main(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state,
               std::size_t slot_index)
{
    try {
        diag::log_tagged_fmt("dec_batch", "slot_enter index=%zu tid=%lu",
            slot_index, static_cast<unsigned long>(GetCurrentThreadId()));
        while (true) {
            batch_work_item_t item;
            bool have_item = false;
            bool draining = false;
            {
                std::unique_lock lock(state->mutex);
                draining = state->run_draining;
                if (!draining) {
                    if (!state->interactive_queue.empty()) {
                        item = state->interactive_queue.front();
                        state->interactive_queue.pop_front();
                        have_item = true;
                    } else if (!state->retry_queue.empty()) {
                        item = state->retry_queue.front();
                        state->retry_queue.pop_front();
                        have_item = true;
                    }
                }
            }
            if (!have_item && !draining &&
                slot_index < state->slots_effective.load(std::memory_order_acquire)) {
                const std::uint64_t cursor = state->worklist_cursor.fetch_add(1,
                    std::memory_order_acq_rel);
                if (cursor < state->worklist.size()) {
                    item = state->worklist[static_cast<std::size_t>(cursor)];
                    have_item = true;
                }
            }
            if (have_item) {
                {
                    std::lock_guard ids_lock(state->ids_mutex);
                    state->queued_ids.erase(item.function_id);
                    state->in_flight_ids.insert(item.function_id);
                }
                state->in_flight.fetch_add(1, std::memory_order_acq_rel);
                in_flight_lease_t in_flight_lease(state, item.function_id);
                process_item(state, item);
                continue;
            }
            {
                std::unique_lock lock(state->mutex);
                if (state->run_draining)
                    break;
                if (slot_index >= state->slots_effective.load(std::memory_order_acquire))
                    break;
                const bool exhausted =
                    state->worklist_cursor.load(std::memory_order_acquire) >= state->worklist.size() &&
                    state->retry_queue.empty() && state->interactive_queue.empty();
                if (exhausted && (state->run_finishing || state->control_exit ||
                    state->run_cancelling.load(std::memory_order_acquire)))
                    break;
                state->wake.wait_for(lock, std::chrono::milliseconds(100), [&state] {
                    return !state->retry_queue.empty() || !state->interactive_queue.empty() ||
                        state->run_draining || state->run_finishing || state->control_exit ||
                        state->run_cancelling.load(std::memory_order_acquire);
                });
            }
        }
    } catch (...) {
        diag::log_tagged_fmt("dec_batch", "slot_exception index=%zu", slot_index);
    }
    {
        std::lock_guard lock(state->mutex);
        ++state->slots_done;
        state->wake.notify_all();
    }
    diag::log_tagged_fmt("dec_batch", "slot_exit index=%zu", slot_index);
}

void process_item_core(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state,
                       batch_work_item_t item)
{
    auto workspace = state->workspace.lock();
    if (!workspace) {
        std::lock_guard lock(state->mutex);
        ++state->cancelled;
        metrics_add(state->metrics, analysis_metric_t::decompile_batch_cancelled, 1);
        return;
    }
    const auto publication = state->run_publication;
    const auto service = state->service;
    const auto cancel = state->run_cancel.token();
    const auto found = state->functions_by_id.find(item.function_id);
    if (!service || !publication || found == state->functions_by_id.end() || !found->second) {
        std::lock_guard lock(state->mutex);
        ++state->failed;
        metrics_add(state->metrics, analysis_metric_t::decompile_batch_failed, 1);
        diag::log_tagged_fmt("dec_batch", "item_failed function_id=%llu status=stale_worklist",
            static_cast<unsigned long long>(item.function_id));
        return;
    }
    const auto& function = *found->second;
    if (workspace->analysis_revision() != state->run_revision ||
        workspace->overlay_revision() != state->run_overlay_revision) {
        std::lock_guard lock(state->mutex);
        ++state->cancelled;
        metrics_add(state->metrics, analysis_metric_t::decompile_batch_cancelled, 1);
        diag::log_tagged_fmt("dec_batch", "item_cancelled reason=stale_revision function_rva=0x%llx",
            static_cast<unsigned long long>(item.entry_rva));
        return;
    }
    if (cancel.stop_requested()) {
        std::lock_guard lock(state->mutex);
        ++state->cancelled;
        metrics_add(state->metrics, analysis_metric_t::decompile_batch_cancelled, 1);
        return;
    }
    const auto architecture = publication->snapshot->normalized_image->architecture;
    const std::uint64_t size_aware_ms = decompile_batch_orchestrator_t::compute_size_aware_deadline(
        item.byte_size, architecture, decompile_deadline_lane_t::batch);
    if (size_aware_ms > k_deadline_scaled_log_threshold_ms) {
        diag::log_tagged_fmt("dec_batch",
            "deadline_scaled function_rva=0x%llx byte_size=%llu est_insns=%llu deadline_ms=%llu",
            static_cast<unsigned long long>(item.entry_rva),
            static_cast<unsigned long long>(item.byte_size),
            static_cast<unsigned long long>(estimate_instructions(item.byte_size, architecture)),
            static_cast<unsigned long long>(size_aware_ms));
    }
    const auto policy = default_decompiler_profile_policy();
    const decompiler_profile_id_t lane_profile = item.lane == 1
        ? decompiler_profile_id_t::thorough
        : item.lane == 2
            ? decompiler_profile_id_t::balanced
            : decompiler_profile_id_t::fast;
    const decompiler_profile_budget_t* request_defaults =
        lane_profile == decompiler_profile_id_t::thorough
            ? &policy.thorough
            : lane_profile == decompiler_profile_id_t::balanced ? &policy.balanced : &policy.fast;
    decompiler_profile_id_t request_profile = lane_profile;
    const std::uint64_t memory_floor_bytes = state->run_snapshot_bytes != 0
        ? state->run_snapshot_bytes + k_batch_job_memory_headroom_bytes : 0;
    if (memory_floor_bytes != 0 && request_defaults->max_memory_bytes < memory_floor_bytes) {
        if (policy.balanced.max_memory_bytes >= memory_floor_bytes &&
            policy.balanced.max_memory_bytes > request_defaults->max_memory_bytes) {
            request_profile = decompiler_profile_id_t::balanced;
            request_defaults = &policy.balanced;
        }
        if (request_defaults->max_memory_bytes < memory_floor_bytes &&
            policy.thorough.max_memory_bytes > request_defaults->max_memory_bytes) {
            request_profile = decompiler_profile_id_t::thorough;
            request_defaults = &policy.thorough;
        }
    }
    const std::uint64_t deadline_ms = (std::min)(
        (std::max<std::uint64_t>)((std::min)(request_defaults->max_wall_clock_ms, size_aware_ms),
            k_batch_deadline_floor_ms),
        request_defaults->max_wall_clock_ms);
    auto budget = *request_defaults;
    budget.max_wall_clock_ms = deadline_ms;
    budget.max_cpu_ms = (std::min)(request_defaults->max_cpu_ms,
        (std::max<std::uint64_t>)(1000, deadline_ms / 2));
    if (memory_floor_bytes != 0) {
        budget.max_memory_bytes = (std::min)(
            (std::max<std::uint64_t>)((std::max)(request_defaults->max_memory_bytes,
                memory_floor_bytes), 1ULL << 20),
            policy.thorough.max_memory_bytes);
    }
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(deadline_ms);
    auto built = make_native_pipeline_request(*workspace, publication, function,
        decompiler_pipeline_invocation_t::background_batch,
        decompiler_pipeline_cache_mode_t::read_write,
        request_profile, budget, deadline, state->provider_context, cancel);
    if (!built) {
        std::lock_guard lock(state->mutex);
        ++state->failed;
        ++state->lane_failed[item.lane <= 3 ? item.lane : 3];
        metrics_add(state->metrics, analysis_metric_t::decompile_batch_failed, 1);
        diag::log_tagged_fmt("dec_batch", "item_failed function_rva=0x%llx status=request_build code=%s",
            static_cast<unsigned long long>(item.entry_rva),
            built.error().stable_code().c_str());
        return;
    }
    auto pipeline_request = std::move(built.value());
    const auto probe = service->probe_rendered_cache(pipeline_request);
    if (probe.hit_stage != decompiler_rendered_probe_stage_t::none) {
        const bool persistent = probe.hit_stage ==
            decompiler_rendered_probe_stage_t::persistent_rendered;
        std::lock_guard lock(state->mutex);
        ++state->completed;
        ++state->lane_completed[item.lane <= 3 ? item.lane : 3];
        if (persistent) {
            ++state->disk_hits;
            metrics_add(state->metrics, analysis_metric_t::decompile_persistent_cache_hits, 1);
        } else {
            ++state->mem_hits;
            metrics_add(state->metrics, analysis_metric_t::decompile_memory_cache_hits, 1);
        }
        metrics_add(state->metrics, analysis_metric_t::decompile_batch_completed, 1);
        return;
    }
    const auto dispatch_started = std::chrono::steady_clock::now();
    auto result = service->decompile(pipeline_request, cancel);
    const std::uint64_t busy_ns = static_cast<std::uint64_t>((std::max<std::int64_t>)(0,
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - dispatch_started).count()));
    if (result.succeeded()) {
        std::lock_guard lock(state->mutex);
        ++state->completed;
        ++state->lane_completed[item.lane <= 3 ? item.lane : 3];
        state->wall_ns += busy_ns;
        metrics_add(state->metrics, analysis_metric_t::decompile_batch_completed, 1);
        metrics_add(state->metrics, analysis_metric_t::decompile_batch_wall_ns, busy_ns);
        return;
    }
    if (result.status == decompiler_pipeline_status_t::cancelled) {
        if (cancel.stop_requested() || state->run_cancelling.load(std::memory_order_acquire)) {
            std::lock_guard lock(state->mutex);
            ++state->cancelled;
            metrics_add(state->metrics, analysis_metric_t::decompile_batch_cancelled, 1);
            return;
        }
        {
            std::lock_guard lock(state->mutex);
            if (state->run_draining) {
                ++state->cancelled;
                metrics_add(state->metrics, analysis_metric_t::decompile_batch_cancelled, 1);
                diag::log_tagged_fmt("dec_batch",
                    "item_cancelled reason=run_drain function_rva=0x%llx",
                    static_cast<unsigned long long>(item.entry_rva));
                return;
            }
        }
        {
            std::lock_guard ids_lock(state->ids_mutex);
            state->in_flight_ids.erase(item.function_id);
            state->queued_ids.insert(item.function_id);
        }
        {
            std::lock_guard lock(state->mutex);
            if (item.lane == 0)
                state->interactive_queue.push_front(item);
            else
                state->retry_queue.push_front(item);
            metrics_set_max(state->metrics, analysis_metric_t::decompile_batch_queue_depth_peak,
                static_cast<std::uint64_t>(pending_queue_depth(*state)));
            state->wake.notify_one();
        }
        return;
    }
    if (result_retryable(result) && item.attempt < 1) {
        {
            std::lock_guard lock(state->mutex);
            if (state->run_draining) {
                ++state->cancelled;
                metrics_add(state->metrics, analysis_metric_t::decompile_batch_cancelled, 1);
                diag::log_tagged_fmt("dec_batch",
                    "item_cancelled reason=run_drain function_rva=0x%llx",
                    static_cast<unsigned long long>(item.entry_rva));
                return;
            }
        }
        item.attempt = static_cast<std::uint8_t>(item.attempt + 1);
        {
            std::lock_guard ids_lock(state->ids_mutex);
            state->in_flight_ids.erase(item.function_id);
            state->queued_ids.insert(item.function_id);
        }
        {
            std::lock_guard lock(state->mutex);
            if (item.lane == 0)
                state->interactive_queue.push_back(item);
            else
                state->retry_queue.push_back(item);
            metrics_set_max(state->metrics, analysis_metric_t::decompile_batch_queue_depth_peak,
                static_cast<std::uint64_t>(pending_queue_depth(*state)));
            state->wake.notify_one();
        }
        diag::log_tagged_fmt("dec_batch",
            "worker_retry function_rva=0x%llx attempt=2 reason=%s",
            static_cast<unsigned long long>(item.entry_rva),
            pipeline_status_name(result.status));
        return;
    }
    if (result.status == decompiler_pipeline_status_t::resource_limit) {
        const std::size_t effective = state->slots_effective.load(std::memory_order_acquire);
        if (effective > 2) {
            const std::size_t reduced = (std::max<std::size_t>)(2, effective / 2);
            state->slots_effective.store(reduced, std::memory_order_release);
            diag::log_tagged_fmt("dec_batch",
                "scale_down slots=%zu to=%zu reason=resource_limit", effective, reduced);
        }
    }
    std::lock_guard lock(state->mutex);
    ++state->failed;
    ++state->lane_failed[item.lane <= 3 ? item.lane : 3];
    state->wall_ns += busy_ns;
    metrics_add(state->metrics, analysis_metric_t::decompile_batch_failed, 1);
    metrics_add(state->metrics, analysis_metric_t::decompile_batch_wall_ns, busy_ns);
    std::string diagnostics_head;
    if (!result.diagnostics.empty()) {
        diagnostics_head = result.diagnostics.front().localization_key;
        if (diagnostics_head.size() > 96)
            diagnostics_head.resize(96);
    }
    diag::log_tagged_fmt("dec_batch",
        "item_failed function_rva=0x%llx status=%s diagnostics_head=%s",
        static_cast<unsigned long long>(item.entry_rva),
        pipeline_status_name(result.status),
        diagnostics_head.c_str());
}

void process_item(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state,
                  batch_work_item_t item)
{
    try {
        process_item_core(state, std::move(item));
    } catch (...) {
        try {
            std::lock_guard lock(state->mutex);
            ++state->failed;
            metrics_add(state->metrics, analysis_metric_t::decompile_batch_failed, 1);
        } catch (...) {
        }
        diag::log_tagged_fmt("dec_batch", "item_failed function_rva=0x%llx status=exception",
            static_cast<unsigned long long>(item.entry_rva));
    }
}

}

workspace_result_t<std::shared_ptr<decompile_batch_orchestrator_t>>
decompile_batch_orchestrator_t::create(
    std::shared_ptr<analysis_workspace_t> workspace,
    std::shared_ptr<analysis_metrics_t> metrics)
{
    if (!workspace) {
        return workspace_result_t<std::shared_ptr<decompile_batch_orchestrator_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "decompile batch orchestrator requires a workspace", "decompile_batch.create"));
    }
    auto state = std::make_shared<state_t>();
    state->workspace = workspace;
    state->metrics = std::move(metrics);
    state->memory_budget_bytes = resolve_memory_budget_bytes();
    diag::log_tagged_fmt("dec_batch",
        "memory_budget_resolved budget=%llu source=physical_ram_quarter floor=%llu cap=%llu",
        static_cast<unsigned long long>(state->memory_budget_bytes),
        static_cast<unsigned long long>(k_memory_budget_floor_bytes),
        static_cast<unsigned long long>(k_memory_budget_cap_bytes));
    auto orchestrator = std::shared_ptr<decompile_batch_orchestrator_t>(
        new decompile_batch_orchestrator_t(std::move(state)));
    auto attach_failure = [&orchestrator](workspace_error_t error) {
        orchestrator->request_cancel();
        (void)orchestrator->drain(std::chrono::steady_clock::now() + std::chrono::seconds(2));
        return workspace_result_t<std::shared_ptr<decompile_batch_orchestrator_t>>::failure(
            std::move(error));
    };
    auto control_state = orchestrator->state_;
    aida::infra::executor::submission_t control_submission;
    control_submission.owner_subsystem = "decompiler";
    control_submission.label = "decompile.batch_control";
    control_submission.thread_class = "long_running";
    control_submission.domain = aida::infra::executor::domain_t::long_running;
    control_submission.priority = 4;
    control_submission.shutdown_policy = "cancel_pending";
    control_submission.cancel_hook = [control_state] {
        try {
            std::lock_guard lock(control_state->mutex);
            control_state->control_exit = true;
            control_state->wake.notify_all();
        } catch (...) {
        }
    };
    control_submission.body = [control_state] { control_main(control_state); };
    const auto control_result = aida::infra::executor::submit(std::move(control_submission));
    if (!control_result.submitted || control_result.task_id == 0) {
        diag::log_tagged_fmt("dec_batch",
            "control_post_failed reason=%s",
            control_result.reject_reason.empty() ? "unknown" : control_result.reject_reason.c_str());
        return workspace_result_t<std::shared_ptr<decompile_batch_orchestrator_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "decompile batch orchestrator control job could not be started",
                "decompile_batch.create"));
    }
    orchestrator->state_->control_task_id = control_result.task_id;
    orchestrator->state_->control_started = true;
    auto observed = workspace->register_baseline_publish_observer(orchestrator);
    if (!observed)
        return attach_failure(observed.error());
    auto registered = workspace->register_lifecycle_participant(orchestrator);
    if (!registered)
        return attach_failure(registered.error());
    auto installed = workspace->install_background_decompile(orchestrator);
    if (!installed)
        return attach_failure(installed.error());
    return workspace_result_t<std::shared_ptr<decompile_batch_orchestrator_t>>::success(
        std::move(orchestrator));
}

void decompile_batch_orchestrator_t::on_baseline_published(
    const std::shared_ptr<const analysis_publication_t>& publication) noexcept
{
    try {
        if (!state_ || !publication)
            return;
        std::lock_guard lock(state_->mutex);
        state_->pending_publication = publication;
        state_->publish_pending = true;
        state_->wake.notify_one();
    } catch (...) {
        diag::log_tagged_fmt("dec_batch", "publish_observer_error");
    }
}

void decompile_batch_orchestrator_t::request_cancel() noexcept
{
    try {
        if (!state_)
            return;
        std::uint64_t in_flight = 0;
        std::uint64_t queued = 0;
        {
            std::lock_guard lock(state_->mutex);
            queued = static_cast<std::uint64_t>(pending_queue_depth(*state_));
            in_flight = state_->in_flight.load(std::memory_order_acquire);
            cancel_run_locked(state_);
        }
        diag::log_tagged_fmt("dec_batch", "run_cancel in_flight=%llu queued=%llu",
            static_cast<unsigned long long>(in_flight),
            static_cast<unsigned long long>(queued));
    } catch (...) {
    }
}

workspace_result_t<void> decompile_batch_orchestrator_t::drain(
    std::chrono::steady_clock::time_point deadline)
{
    if (!state_)
        return workspace_result_t<void>::success();
    const auto started = std::chrono::steady_clock::now();
    std::unique_lock lock(state_->mutex);
    state_->cancel_epoch.fetch_add(1, std::memory_order_acq_rel);
    state_->run_cancel.request_cancel();
    state_->run_cancelling.store(true, std::memory_order_release);
    state_->wake.notify_all();
    while (state_->run_active || state_->run_starting) {
        if (state_->wake.wait_until(lock, deadline) == std::cv_status::timeout &&
            (state_->run_active || state_->run_starting)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::deadline_exceeded,
                "decompile batch orchestrator did not drain before the deadline",
                "decompile_batch.drain"));
        }
    }
    diag::log_tagged_fmt("dec_batch", "run_drained elapsed_ms=%llu",
        static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count()));
    return workspace_result_t<void>::success();
}

namespace {

bool enqueue_interactive_item(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state,
                              const decompiler_entity_key_t& entity, bool priority)
{
    if (!state || entity.kind != decompiler_entity_kind_t::native_function)
        return false;
    const auto* native = std::get_if<native_decompiler_entity_identity_t>(&entity.identity);
    if (!native)
        return false;
    batch_work_item_t item;
    std::unique_lock lock(state->mutex);
    if (!state->run_active || state->run_finishing || state->run_draining ||
        state->run_cancelling.load(std::memory_order_acquire) || !state->run_publication ||
        !state->run_publication->snapshot)
        return false;
    const auto found = state->functions_by_id.find(native->function_id);
    if (found == state->functions_by_id.end() || !found->second)
        return false;
    item.function_id = native->function_id;
    item.entry_rva = rva_of(found->second->start, state->run_image_base);
    item.byte_size = function_byte_size(*state->run_publication->snapshot, *found->second);
    item.lane = 0;
    item.depth = 0;
    lock.unlock();
    {
        std::lock_guard ids_lock(state->ids_mutex);
        if (state->in_flight_ids.count(native->function_id) != 0)
            return false;
        if (!state->queued_ids.insert(native->function_id).second)
            return false;
    }
    lock.lock();
    if (!state->run_active || state->run_finishing || state->run_draining ||
        state->run_cancelling.load(std::memory_order_acquire)) {
        std::lock_guard ids_lock(state->ids_mutex);
        state->queued_ids.erase(native->function_id);
        return false;
    }
    if (priority)
        state->interactive_queue.push_front(item);
    else
        state->interactive_queue.push_back(item);
    ++state->total;
    metrics_set_max(state->metrics, analysis_metric_t::decompile_batch_queue_depth_peak,
        static_cast<std::uint64_t>(pending_queue_depth(*state)));
    state->wake.notify_one();
    lock.unlock();
    if (priority) {
        diag::log_tagged_fmt("dec_batch",
            "interactive_priority_admitted function_rva=0x%llx",
            static_cast<unsigned long long>(item.entry_rva));
    }
    return true;
}

}

void decompile_batch_orchestrator_t::notify_interactive_request(const decompiler_entity_key_t& entity)
{
    (void)enqueue_interactive_item(state_, entity, false);
}

bool decompile_batch_orchestrator_t::admit_interactive_priority(const decompiler_entity_key_t& entity)
{
    return enqueue_interactive_item(state_, entity, true);
}

decompile_batch_orchestrator_t::run_snapshot_t decompile_batch_orchestrator_t::run_snapshot() const
{
    run_snapshot_t snapshot;
    if (!state_)
        return snapshot;
    std::lock_guard lock(state_->mutex);
    snapshot.active = state_->run_active;
    snapshot.generation = state_->run_generation;
    snapshot.analysis_revision = state_->run_revision;
    snapshot.total = state_->total;
    snapshot.completed = state_->completed;
    snapshot.failed = state_->failed;
    snapshot.cancelled = state_->cancelled;
    snapshot.queue_depth = pending_queue_depth(*state_);
    {
        std::lock_guard ids_lock(state_->ids_mutex);
        snapshot.interactive_pending = static_cast<std::uint64_t>(state_->interactive_queue.size());
    }
    snapshot.slots = state_->slots_total;
    snapshot.slots_effective = state_->slots_effective.load(std::memory_order_acquire);
    snapshot.rate_funcs_s = state_->rate_ema;
    const std::uint64_t processed = state_->completed + state_->failed + state_->cancelled;
    const std::uint64_t remaining = state_->total > processed ? state_->total - processed : 0;
    snapshot.eta_s = state_->rate_ema > 0.0 ? remaining / state_->rate_ema : 0.0;
    return snapshot;
}

std::uint64_t decompile_batch_orchestrator_t::compute_size_aware_deadline(
    std::uint64_t function_byte_size_value,
    architecture_id_t architecture,
    decompile_deadline_lane_t lane) noexcept
{
    const std::uint64_t est = estimate_instructions(function_byte_size_value, architecture);
    const std::uint64_t scaled = est > ((std::numeric_limits<std::uint64_t>::max)() - 500ULL) / 2ULL
        ? (std::numeric_limits<std::uint64_t>::max)()
        : 500ULL + est * 2ULL;
    const std::uint64_t cap = lane == decompile_deadline_lane_t::interactive
        ? k_interactive_deadline_cap_ms
        : k_batch_deadline_cap_ms;
    return (std::min)((std::max)(scaled, k_batch_deadline_floor_ms), cap);
}

workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>
decompile_batch_orchestrator_t::capture_generation_provider_context(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const std::shared_ptr<const analysis_publication_t>& publication,
    const cancellation_token_t& cancel) try
{
    using result_t = workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>;
    if (!workspace || !publication || !publication->snapshot ||
        !publication->snapshot->normalized_image ||
        publication->snapshot->normalized_image->image_size == 0) {
        return result_t::failure(make_workspace_error(workspace_error_code_t::invalid_argument,
            "batch decompile provider capture requires a coherent normalized image",
            "decompile_batch.capture"));
    }
    if (cancel.stop_requested()) {
        return result_t::failure(make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "batch decompile provider capture was cancelled", "decompile_batch.capture"));
    }
    const auto image = publication->snapshot->normalized_image;
    auto language = ghidra_adapter::resolve_ghidra_language(*image, cancel);
    if (!language)
        return result_t::failure(language.error());
    auto revision = ghidra_adapter::make_ghidra_adapter_revision(
        workspace->identity(), *publication->snapshot, cancel);
    if (!revision)
        return result_t::failure(revision.error());
    auto load_image = ghidra_adapter::ghidra_load_image_t::create(
        workspace->provider_handle(), image, language.value(), revision.value(), {}, cancel);
    if (!load_image)
        return result_t::failure(load_image.error());
    const auto thorough = default_decompiler_profile_policy().thorough;
    const std::uint64_t snapshot_limit = (std::min<std::uint64_t>)(k_batch_snapshot_absolute_cap,
        (std::min<std::uint64_t>)(k_worker_snapshot_cap,
            thorough.max_memory_bytes != 0 ? thorough.max_memory_bytes / 2 : k_batch_snapshot_absolute_cap));
    diag::log_tagged_fmt("dec_batch",
        "budget_decision type=snapshot_cap absolute_cap=%llu worker_cap=%llu profile_half_bytes=%llu effective_limit=%llu",
        static_cast<unsigned long long>(k_batch_snapshot_absolute_cap),
        static_cast<unsigned long long>(k_worker_snapshot_cap),
        static_cast<unsigned long long>(
            thorough.max_memory_bytes != 0 ? thorough.max_memory_bytes / 2 : 0),
        static_cast<unsigned long long>(snapshot_limit));
    const auto analysis_snapshot = publication->snapshot;
    std::vector<std::uint64_t> import_rvas;
    import_rvas.reserve(image->imports.size());
    for (const auto& item : image->imports) {
        const std::uint64_t iat_rva = rva_of(item.address, image->image_base);
        if (iat_rva != 0 && iat_rva < image->image_size)
            import_rvas.push_back(iat_rva);
    }
    std::sort(import_rvas.begin(), import_rvas.end());
    import_rvas.erase(std::unique(import_rvas.begin(), import_rvas.end()), import_rvas.end());
    const auto section_contains_import = [&import_rvas](const image_section_t& section) {
        if (section.virtual_size == 0)
            return false;
        const std::uint64_t end = section.virtual_address +
            (section.virtual_size > (std::numeric_limits<std::uint64_t>::max)() - section.virtual_address
                ? (std::numeric_limits<std::uint64_t>::max)() - section.virtual_address
                : section.virtual_size);
        const auto found = std::lower_bound(import_rvas.begin(), import_rvas.end(),
            section.virtual_address);
        return found != import_rvas.end() && *found < end;
    };
    const auto section_name_is = [](const std::string& name, const char* prefix) {
        const std::size_t length = std::strlen(prefix);
        if (name.size() < length)
            return false;
        for (std::size_t index = 0; index < length; ++index) {
            char left = name[index];
            if (left >= 'A' && left <= 'Z')
                left = static_cast<char>(left - 'A' + 'a');
            if (left != prefix[index])
                return false;
        }
        return true;
    };
    std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
    ranges.emplace_back(0, (std::min<std::uint64_t>)(image->image_size,
        (std::max<std::uint64_t>)(image->header_size, k_snapshot_header_floor)));
    std::uint64_t exec_bytes = 0;
    for (const auto& section : image->sections) {
        if ((section.permissions & image_permission_execute) == 0 ||
            section.virtual_address >= image->image_size || section.virtual_size == 0)
            continue;
        const std::uint64_t end = (std::min<std::uint64_t>)(image->image_size,
            section.virtual_address + section.virtual_size);
        ranges.emplace_back(section.virtual_address, end);
        exec_bytes += end - section.virtual_address;
    }
    std::uint64_t requested_bytes = exec_bytes;
    if (exec_bytes > snapshot_limit) {
        return result_t::failure(make_workspace_error(workspace_error_code_t::limit_exceeded,
            "batch decompile generation snapshot exceeds its memory bound",
            "decompile_batch.capture"));
    }
    std::vector<const image_section_t*> import_sections;
    std::vector<const image_section_t*> rdata_sections;
    std::vector<const image_section_t*> data_sections;
    std::vector<const image_section_t*> other_data_sections;
    for (const auto& section : image->sections) {
        if ((section.permissions & image_permission_execute) != 0 ||
            (section.permissions & image_permission_read) == 0 ||
            (section.permissions & image_permission_discardable) != 0 ||
            section.virtual_address >= image->image_size || section.virtual_size == 0)
            continue;
        if (section_contains_import(section)) {
            if (import_sections.size() < 8)
                import_sections.push_back(&section);
            continue;
        }
        if (section_name_is(section.name, ".rdata") || section_name_is(section.name, ".idata")) {
            rdata_sections.push_back(&section);
            continue;
        }
        if (section_name_is(section.name, ".data")) {
            data_sections.push_back(&section);
            continue;
        }
        other_data_sections.push_back(&section);
    }
    std::uint64_t data_bytes = 0;
    std::uint64_t skipped_data_bytes = 0;
    std::uint64_t included_data_sections = 0;
    const auto include_data_sections = [&](const std::vector<const image_section_t*>& sections,
                                           bool mandatory) {
        for (const auto* section : sections) {
            const std::uint64_t end = (std::min<std::uint64_t>)(image->image_size,
                section->virtual_address + section->virtual_size);
            const std::uint64_t size = end - section->virtual_address;
            if (size == 0)
                continue;
            if (size > snapshot_limit - requested_bytes) {
                skipped_data_bytes += size;
                if (mandatory) {
                    diag::log_tagged_fmt("dec_batch",
                        "snapshot_data_section_skipped name=%s rva=0x%llx size=%llu reason=cap mandatory=%d",
                        section->name.c_str(),
                        static_cast<unsigned long long>(section->virtual_address),
                        static_cast<unsigned long long>(size), mandatory ? 1 : 0);
                }
                continue;
            }
            ranges.emplace_back(section->virtual_address, end);
            requested_bytes += size;
            data_bytes += size;
            ++included_data_sections;
        }
    };
    include_data_sections(import_sections, true);
    include_data_sections(rdata_sections, false);
    include_data_sections(data_sections, false);
    include_data_sections(other_data_sections, false);
    const bool import_data_degraded = import_rvas.empty() ? false : (import_sections.empty() ||
        std::any_of(import_sections.begin(), import_sections.end(), [&ranges](const image_section_t* section) {
            for (const auto& range : ranges) {
                if (section->virtual_address >= range.first && section->virtual_address < range.second)
                    return false;
            }
            return true;
        }));
    diag::log_tagged_fmt("dec_batch",
        "snapshot_layout exec_bytes=%llu data_bytes=%llu data_sections=%llu skipped_data_bytes=%llu import_data_degraded=%d ranges=%zu",
        static_cast<unsigned long long>(exec_bytes),
        static_cast<unsigned long long>(data_bytes),
        static_cast<unsigned long long>(included_data_sections),
        static_cast<unsigned long long>(skipped_data_bytes),
        import_data_degraded ? 1 : 0, ranges.size());
    std::sort(ranges.begin(), ranges.end());
    std::vector<std::pair<std::uint64_t, std::uint64_t>> merged;
    for (const auto& range : ranges) {
        if (range.first >= range.second || range.second > image->image_size)
            continue;
        if (!merged.empty() && range.first <= merged.back().second)
            merged.back().second = (std::max)(merged.back().second, range.second);
        else
            merged.push_back(range);
    }
    requested_bytes = 0;
    for (const auto& range : merged) {
        const std::uint64_t size = range.second - range.first;
        if (size > snapshot_limit - requested_bytes) {
            return result_t::failure(make_workspace_error(workspace_error_code_t::limit_exceeded,
                "batch decompile generation snapshot exceeds its memory bound",
                "decompile_batch.capture"));
        }
        requested_bytes += size;
    }
    native_worker::native_provider_snapshot_t snapshot;
    snapshot.image_base = image->image_base;
    snapshot.image_size = image->image_size;
    snapshot.ranges.reserve(merged.size());
    for (const auto& range : merged) {
        if (cancel.stop_requested()) {
            return result_t::failure(make_workspace_error(
                cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                           : workspace_error_code_t::cancelled,
                "batch decompile provider capture was cancelled", "decompile_batch.capture"));
        }
        native_worker::native_provider_snapshot_range_t captured;
        captured.relative_virtual_address = range.first;
        captured.bytes.reserve(static_cast<std::size_t>(range.second - range.first));
        for (std::uint64_t cursor = range.first; cursor < range.second;) {
            if (cancel.stop_requested()) {
                return result_t::failure(make_workspace_error(
                    cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                               : workspace_error_code_t::cancelled,
                    "batch decompile provider capture was cancelled", "decompile_batch.capture"));
            }
            const std::uint64_t amount = (std::min)(k_snapshot_read_quantum, range.second - cursor);
            const address_t start{address_space_id_t::relative_virtual, cursor,
                image->architecture, image->architecture_mode};
            auto read = load_image.value()->read(start, amount, cancel);
            if (!read)
                return result_t::failure(read.error());
            if (read.value().bytes.size() != amount) {
                return result_t::failure(make_workspace_error(workspace_error_code_t::integrity_failure,
                    "batch decompile generation snapshot is truncated",
                    "decompile_batch.capture"));
            }
            captured.bytes.insert(captured.bytes.end(),
                read.value().bytes.begin(), read.value().bytes.end());
            cursor += amount;
        }
        snapshot.ranges.push_back(std::move(captured));
    }
    namespace sidecar_ns = native_worker::snapshot_sidecar;
    sidecar_ns::sidecar_t sidecar;
    sidecar.is_64bit = image->address_width_bits >= 64;
    std::uint64_t sidecar_estimate_bytes = 4096;
    const auto sidecar_budget_remaining = [&sidecar_estimate_bytes]() {
        return sidecar_estimate_bytes < k_snapshot_sidecar_absolute_cap
            ? k_snapshot_sidecar_absolute_cap - sidecar_estimate_bytes : 0;
    };
    const auto sidecar_charge = [&sidecar_estimate_bytes](std::uint64_t bytes) {
        sidecar_estimate_bytes += bytes;
    };
    std::unordered_set<std::uint64_t> prototype_rvas;
    prototype_rvas.reserve(image->imports.size());
    for (const auto& item : image->imports) {
        const std::uint64_t iat_rva = rva_of(item.address, image->image_base);
        if (iat_rva == 0 || iat_rva >= image->image_size)
            continue;
        sidecar_ns::import_record_t record;
        record.iat_rva = iat_rva;
        record.ordinal = item.ordinal ? static_cast<std::uint32_t>(*item.ordinal & 0xFFFFFFFFULL) : 0;
        record.delayed = item.delayed;
        record.module = item.library;
        record.name = item.name.value_or(std::string());
        if (!record.name.empty()) {
            if (const auto prototype = api_prototypes::find(record.module, record.name)) {
                sidecar_ns::prototype_record_t prototype_record;
                prototype_record.rva = iat_rva;
                prototype_record.confidence = 255;
                prototype_record.is_noreturn = prototype->is_noreturn;
                prototype_record.name = record.name;
                prototype_record.prototype = prototype->signature;
                prototype_rvas.insert(iat_rva);
                sidecar_charge(24 + prototype_record.name.size() + prototype_record.prototype.size());
                sidecar.prototypes.push_back(std::move(prototype_record));
            }
        }
        sidecar_charge(32 + record.module.size() + record.name.size());
        sidecar.imports.push_back(std::move(record));
    }
    if (analysis_snapshot) {
        for (const auto& candidate : analysis_snapshot->rich_facts.type_candidates) {
            if (candidate.kind != symbol_type_candidate_kind_t::function_prototype &&
                candidate.kind != symbol_type_candidate_kind_t::import_prototype)
                continue;
            if (!candidate.address || sidecar.prototypes.size() >= 65536)
                continue;
            const std::uint64_t rva = rva_of(*candidate.address, image->image_base);
            if (rva == 0 || rva >= image->image_size || prototype_rvas.count(rva) != 0)
                continue;
            const std::string* text = nullptr;
            if (candidate.display_name.find('(') != std::string::npos)
                text = &candidate.display_name;
            else if (candidate.canonical_type.find('(') != std::string::npos)
                text = &candidate.canonical_type;
            if (!text || text->empty() || text->size() > 4096)
                continue;
            sidecar_ns::prototype_record_t prototype_record;
            prototype_record.rva = rva;
            prototype_record.confidence = candidate.confidence;
            prototype_record.prototype = *text;
            prototype_rvas.insert(rva);
            sidecar_charge(24 + prototype_record.prototype.size());
            sidecar.prototypes.push_back(std::move(prototype_record));
        }
        for (const auto& item : analysis_snapshot->symbols) {
            if (item.name.empty() || item.name.size() > sidecar_ns::k_max_name_bytes ||
                sidecar.names.size() >= sidecar_ns::k_max_records)
                continue;
            const std::uint64_t rva = rva_of(item.address, image->image_base);
            if (rva == 0 || rva >= image->image_size)
                continue;
            const std::uint64_t charge = 16 + item.name.size();
            if (charge > sidecar_budget_remaining())
                break;
            sidecar_ns::name_record_t record;
            record.rva = rva;
            switch (item.kind) {
            case symbol_kind_t::function:
            case symbol_kind_t::debug_symbol:
            case symbol_kind_t::metadata:
                record.kind = sidecar_ns::name_kind_t::function;
                break;
            case symbol_kind_t::import_symbol:
                record.kind = sidecar_ns::name_kind_t::import;
                break;
            case symbol_kind_t::export_symbol:
                record.kind = sidecar_ns::name_kind_t::export_;
                break;
            default:
                record.kind = sidecar_ns::name_kind_t::data;
                break;
            }
            record.name = item.name;
            sidecar_charge(charge);
            sidecar.names.push_back(std::move(record));
        }
        for (const auto& function : analysis_snapshot->functions) {
            if (!function.noreturn || sidecar.noreturn.size() >= sidecar_ns::k_max_records)
                continue;
            const std::uint64_t rva = rva_of(function.start, image->image_base);
            if (rva == 0 || rva >= image->image_size)
                continue;
            if (sidecar_budget_remaining() < 8)
                break;
            sidecar_charge(8);
            sidecar.noreturn.push_back(rva);
        }
    }
    if (analysis_snapshot && !analysis_snapshot->strings.empty()) {
        std::unordered_set<std::uint64_t> xref_targets;
        xref_targets.reserve(analysis_snapshot->xrefs.size());
        for (const auto& xref : analysis_snapshot->xrefs)
            xref_targets.insert(rva_of(xref.target, image->image_base));
        std::vector<std::pair<std::uint64_t, const string_record_t*>> referenced;
        std::vector<std::pair<std::uint64_t, const string_record_t*>> unreferenced;
        referenced.reserve(analysis_snapshot->strings.size());
        unreferenced.reserve(analysis_snapshot->strings.size());
        for (const auto& record : analysis_snapshot->strings) {
            const std::uint64_t rva = rva_of(record.address, image->image_base);
            if (rva == 0 || rva >= image->image_size || record.value.empty())
                continue;
            if (xref_targets.count(rva) != 0)
                referenced.emplace_back(rva, &record);
            else
                unreferenced.emplace_back(rva, &record);
        }
        const auto by_rva = [](const auto& left, const auto& right) {
            return left.first < right.first;
        };
        std::sort(referenced.begin(), referenced.end(), by_rva);
        std::sort(unreferenced.begin(), unreferenced.end(), by_rva);
        const auto append_string_record = [&](const std::pair<std::uint64_t, const string_record_t*>& entry) {
            if (sidecar.strings.size() >= sidecar_ns::k_max_string_records)
                return false;
            const string_record_t& source = *entry.second;
            std::string content = source.value;
            bool truncated = false;
            if (content.size() > sidecar_ns::k_max_string_content_bytes) {
                std::size_t boundary = sidecar_ns::k_max_string_content_bytes;
                while (boundary != 0 &&
                       (static_cast<std::uint8_t>(content[boundary - 1]) & 0xC0U) == 0x80U)
                    --boundary;
                if (boundary == 0)
                    boundary = sidecar_ns::k_max_string_content_bytes;
                content.resize(boundary);
                truncated = true;
            }
            if (content.empty())
                return true;
            const std::uint64_t charge = 20 + content.size();
            if (charge > sidecar_budget_remaining())
                return false;
            sidecar_ns::string_record_t record;
            record.rva = entry.first;
            if (source.encoding == string_encoding_t::utf16_le)
                record.flags |= sidecar_ns::k_string_flag_is_wide;
            if (truncated)
                record.flags |= sidecar_ns::k_string_flag_truncated;
            record.confidence = source.confidence;
            record.original_byte_length = source.byte_length >
                    (std::numeric_limits<std::uint32_t>::max)()
                ? (std::numeric_limits<std::uint32_t>::max)()
                : static_cast<std::uint32_t>(source.byte_length);
            record.content = std::move(content);
            sidecar_charge(charge);
            sidecar.strings.push_back(std::move(record));
            return true;
        };
        for (const auto& entry : referenced) {
            if (!append_string_record(entry))
                break;
        }
        for (const auto& entry : unreferenced) {
            if (!append_string_record(entry))
                break;
        }
    }
    if (analysis_snapshot && !analysis_snapshot->rich_facts.data_candidates.empty()) {
        std::unordered_set<std::uint64_t> scalar_rvas;
        const auto section_non_writable = [&image](std::uint64_t rva, std::uint64_t size) {
            for (const auto& section : image->sections) {
                if (section.virtual_size == 0)
                    continue;
                const std::uint64_t end = section.virtual_address +
                    (section.virtual_size > (std::numeric_limits<std::uint64_t>::max)() - section.virtual_address
                        ? (std::numeric_limits<std::uint64_t>::max)() - section.virtual_address
                        : section.virtual_size);
                if (rva >= section.virtual_address && rva < end && size <= end - rva)
                    return (section.permissions & image_permission_write) == 0;
            }
            return false;
        };
        const auto read_captured = [&snapshot](std::uint64_t rva, std::uint64_t size,
                                                std::uint64_t& value) {
            for (const auto& range : snapshot.ranges) {
                if (rva < range.relative_virtual_address ||
                    rva - range.relative_virtual_address >= range.bytes.size())
                    continue;
                const std::uint64_t offset = rva - range.relative_virtual_address;
                if (size > range.bytes.size() - offset)
                    continue;
                std::uint64_t parsed = 0;
                std::memcpy(&parsed, range.bytes.data() + offset,
                    static_cast<std::size_t>(size));
                value = parsed;
                return true;
            }
            return false;
        };
        for (const auto& candidate : analysis_snapshot->rich_facts.data_candidates) {
            if (sidecar.global_scalars.size() >= sidecar_ns::k_max_global_scalar_records)
                break;
            const std::uint64_t rva = rva_of(candidate.address, image->image_base);
            const std::uint64_t size = candidate.size;
            if (rva == 0 || rva >= image->image_size ||
                (size != 1 && size != 2 && size != 4 && size != 8) ||
                !scalar_rvas.insert(rva).second || !section_non_writable(rva, size))
                continue;
            std::uint64_t value = 0;
            if (!read_captured(rva, size, value))
                continue;
            if (sidecar_budget_remaining() < 24)
                break;
            sidecar_ns::global_scalar_record_t record;
            record.rva = rva;
            record.size_log2 = size == 8 ? 3U : size == 4 ? 2U : size == 2 ? 1U : 0U;
            record.value = value;
            sidecar_charge(24);
            sidecar.global_scalars.push_back(record);
        }
    }
    if (analysis_snapshot && !analysis_snapshot->rich_facts.type_candidates.empty()) {
        std::unordered_set<std::uint64_t> emitted_members;
        const auto member_key = [](const char* canonical, std::uint64_t offset) {
            std::uint64_t hash = 14695981039346656037ULL;
            for (const char* cursor = canonical; *cursor != '\0'; ++cursor) {
                hash ^= static_cast<std::uint8_t>(*cursor);
                hash *= 1099511628211ULL;
            }
            hash ^= offset;
            hash *= 1099511628211ULL;
            return hash;
        };
        for (const auto& candidate : analysis_snapshot->rich_facts.type_candidates) {
            if (sidecar.members.size() >= sidecar_ns::k_max_member_records)
                break;
            if (candidate.kind != symbol_type_candidate_kind_t::global_object &&
                candidate.kind != symbol_type_candidate_kind_t::pointer_object &&
                candidate.kind != symbol_type_candidate_kind_t::type_information)
                continue;
            if (candidate.canonical_type.empty() ||
                candidate.canonical_type.size() > sidecar_ns::k_max_canonical_bytes)
                continue;
            const builtin_typelib::struct_desc_t* structure = nullptr;
            for (const auto& entry : builtin_typelib::kBuiltinStructs) {
                if (entry.name == nullptr)
                    continue;
                if (candidate.canonical_type == entry.name ||
                    (candidate.canonical_type.size() > 7 &&
                     candidate.canonical_type.compare(0, 7, "struct ") == 0 &&
                     candidate.canonical_type.compare(7, std::string::npos, entry.name) == 0)) {
                    structure = &entry;
                    break;
                }
            }
            if (structure == nullptr || structure->members == nullptr)
                continue;
            for (std::size_t index = 0; index < structure->member_count; ++index) {
                if (sidecar.members.size() >= sidecar_ns::k_max_member_records)
                    break;
                const auto& member = structure->members[index];
                if (member.name == nullptr || member.name[0] == '\0')
                    continue;
                if (!emitted_members.insert(member_key(structure->name, member.offset)).second)
                    continue;
                const std::uint64_t charge =
                    24 + std::strlen(structure->name) + std::strlen(member.name);
                if (charge > sidecar_budget_remaining())
                    break;
                sidecar_ns::member_record_t record;
                record.object_type_canonical = structure->name;
                record.byte_offset = member.offset;
                record.field_name = member.name;
                record.confidence = candidate.confidence;
                sidecar_charge(charge);
                sidecar.members.push_back(std::move(record));
            }
        }
        const std::uint64_t pointer_size = image->address_width_bits >= 64 ? 8ULL : 4ULL;
        struct vtable_slot_ref_t {
            std::uint64_t slot_rva;
            std::uint64_t target_rva;
            std::uint8_t confidence;
        };
        std::vector<vtable_slot_ref_t> slot_refs;
        slot_refs.reserve(analysis_snapshot->rich_facts.type_references.size());
        for (const auto& reference : analysis_snapshot->rich_facts.type_references) {
            if (reference.kind != type_reference_kind_t::virtual_table_slot ||
                !reference.source || !reference.target)
                continue;
            const std::uint64_t slot_rva = rva_of(*reference.source, image->image_base);
            const std::uint64_t target_rva = rva_of(*reference.target, image->image_base);
            if (slot_rva == 0 || target_rva == 0 || slot_rva >= image->image_size)
                continue;
            slot_refs.push_back(vtable_slot_ref_t{slot_rva, target_rva, reference.confidence});
        }
        if (!slot_refs.empty()) {
            std::sort(slot_refs.begin(), slot_refs.end(), [](const auto& left, const auto& right) {
                return left.slot_rva < right.slot_rva;
            });
            std::unordered_map<std::uint64_t, const std::string*> method_names;
            method_names.reserve(analysis_snapshot->symbols.size());
            for (const auto& symbol : analysis_snapshot->symbols) {
                if (symbol.name.empty())
                    continue;
                const std::uint64_t rva = rva_of(symbol.address, image->image_base);
                if (rva != 0)
                    method_names.emplace(rva, &symbol.name);
            }
            std::vector<const symbol_type_candidate_record_t*> vtable_candidates;
            for (const auto& candidate : analysis_snapshot->rich_facts.type_candidates) {
                if (candidate.kind != symbol_type_candidate_kind_t::virtual_table ||
                    !candidate.address)
                    continue;
                const std::uint64_t vtable_rva = rva_of(*candidate.address, image->image_base);
                if (vtable_rva == 0 || vtable_rva >= image->image_size)
                    continue;
                vtable_candidates.push_back(&candidate);
            }
            std::sort(vtable_candidates.begin(), vtable_candidates.end(),
                [image_base = image->image_base](const auto* left, const auto* right) {
                    return rva_of(*left->address, image_base) < rva_of(*right->address, image_base);
                });
            for (std::size_t candidate_index = 0; candidate_index < vtable_candidates.size();
                 ++candidate_index) {
                if (sidecar.vtables.size() >= sidecar_ns::k_max_vtable_records)
                    break;
                const auto& candidate = *vtable_candidates[candidate_index];
                const std::uint64_t vtable_rva = rva_of(*candidate.address, image->image_base);
                if (candidate_index != 0 &&
                    vtable_rva == rva_of(*vtable_candidates[candidate_index - 1]->address,
                        image->image_base))
                    continue;
                const std::uint64_t vtable_end = candidate_index + 1 < vtable_candidates.size()
                    ? rva_of(*vtable_candidates[candidate_index + 1]->address, image->image_base)
                    : (std::numeric_limits<std::uint64_t>::max)();
                const auto first = std::lower_bound(slot_refs.begin(), slot_refs.end(), vtable_rva,
                    [](const vtable_slot_ref_t& entry, std::uint64_t value) {
                        return entry.slot_rva < value;
                    });
                for (auto slot = first; slot != slot_refs.end(); ++slot) {
                    if (sidecar.vtables.size() >= sidecar_ns::k_max_vtable_records)
                        break;
                    if (slot->slot_rva >= vtable_end)
                        break;
                    if (slot->slot_rva < vtable_rva || slot->slot_rva - vtable_rva > (4096ULL * pointer_size))
                        break;
                    if ((slot->slot_rva - vtable_rva) % pointer_size != 0)
                        continue;
                    const std::uint64_t slot_index = (slot->slot_rva - vtable_rva) / pointer_size;
                    std::string method_name;
                    if (const auto named = method_names.find(slot->target_rva);
                        named != method_names.end() && named->second != nullptr) {
                        method_name = *named->second;
                    } else {
                        method_name = (candidate.display_name.empty()
                                ? "vtable_" + sidecar_hex_text(vtable_rva)
                                : candidate.display_name) +
                            "::method_" + std::to_string(slot_index);
                    }
                    if (method_name.empty())
                        continue;
                    if (method_name.size() > sidecar_ns::k_max_name_bytes)
                        method_name.resize(sidecar_ns::k_max_name_bytes);
                    const std::uint64_t charge = 24 + method_name.size();
                    if (charge > sidecar_budget_remaining())
                        break;
                    sidecar_ns::vtable_record_t record;
                    record.vtable_rva = vtable_rva;
                    record.slot_index = slot_index;
                    record.method_name = std::move(method_name);
                    record.confidence = slot->confidence;
                    sidecar_charge(charge);
                    sidecar.vtables.push_back(std::move(record));
                }
            }
        }
    }
    if (publication->overlay_presentation) {
        for (const auto& entry : publication->overlay_presentation->comments) {
            if (sidecar.comments.size() >= sidecar_ns::k_max_comment_records)
                break;
            const std::uint64_t rva = rva_of(entry.address, image->image_base);
            if (rva == 0 || rva >= image->image_size || entry.text.empty())
                continue;
            std::string text;
            text.reserve((std::min)(entry.text.size(),
                static_cast<std::size_t>(sidecar_ns::k_max_comment_bytes)));
            for (const char value : entry.text) {
                if (text.size() >= sidecar_ns::k_max_comment_bytes)
                    break;
                if ((static_cast<std::uint8_t>(value) < 0x20U && value != '\t') || value == 0x7f)
                    continue;
                text.push_back(value);
            }
            if (text.empty())
                continue;
            const std::uint64_t charge = 16 + text.size();
            if (charge > sidecar_budget_remaining())
                break;
            sidecar_ns::comment_record_t record;
            record.rva = rva;
            record.text = std::move(text);
            sidecar_charge(charge);
            sidecar.comments.push_back(std::move(record));
        }
    }
    if (const auto recognition = static_recognition::records_for(workspace)) {
        std::unordered_set<std::uint64_t> name_rvas;
        name_rvas.reserve(sidecar.names.size() + recognition->names.size());
        for (const auto& record : sidecar.names)
            name_rvas.insert(record.rva);
        for (const auto& record : recognition->names) {
            if (sidecar.names.size() >= sidecar_ns::k_max_records)
                break;
            if (record.rva == 0 || record.rva >= image->image_size || record.name.empty() ||
                record.name.size() > sidecar_ns::k_max_name_bytes ||
                !name_rvas.insert(record.rva).second)
                continue;
            const std::uint64_t charge = 16 + record.name.size();
            if (charge > sidecar_budget_remaining())
                break;
            sidecar_ns::name_record_t out;
            out.rva = record.rva;
            out.kind = record.kind == "function"
                ? sidecar_ns::name_kind_t::function
                : sidecar_ns::name_kind_t::data;
            out.name = record.name;
            sidecar_charge(charge);
            sidecar.names.push_back(std::move(out));
        }
        for (const auto& record : recognition->prototypes) {
            if (sidecar.prototypes.size() >= 65536)
                break;
            if (record.rva == 0 || record.rva >= image->image_size ||
                prototype_rvas.count(record.rva) != 0 ||
                record.prototype_text.empty() ||
                record.prototype_text.size() > sidecar_ns::k_max_prototype_bytes ||
                record.name.size() > sidecar_ns::k_max_name_bytes)
                continue;
            const std::uint64_t charge = 24 + record.name.size() + record.prototype_text.size();
            if (charge > sidecar_budget_remaining())
                break;
            sidecar_ns::prototype_record_t out;
            out.rva = record.rva;
            out.confidence = record.confidence > 100 ? 100 : record.confidence;
            out.is_noreturn = record.is_noreturn;
            out.name = record.name;
            out.prototype = record.prototype_text;
            prototype_rvas.insert(record.rva);
            sidecar_charge(charge);
            sidecar.prototypes.push_back(std::move(out));
        }
    }
    const auto sidecar_bytes = sidecar_ns::encode(sidecar);
    if (sidecar_bytes.empty()) {
        diag::log_tagged_fmt("dec_batch",
            "snapshot_sidecar_encode_failed names=%zu imports=%zu prototypes=%zu noreturn=%zu strings=%zu scalars=%zu members=%zu vtables=%zu comments=%zu estimate_bytes=%llu",
            sidecar.names.size(), sidecar.imports.size(), sidecar.prototypes.size(),
            sidecar.noreturn.size(), sidecar.strings.size(), sidecar.global_scalars.size(),
            sidecar.members.size(), sidecar.vtables.size(), sidecar.comments.size(),
            static_cast<unsigned long long>(sidecar_estimate_bytes));
    }
    if (requested_bytes + sidecar_bytes.size() > k_batch_snapshot_absolute_cap) {
        return result_t::failure(make_workspace_error(workspace_error_code_t::limit_exceeded,
            "batch decompile generation snapshot exceeds its absolute memory bound",
            "decompile_batch.capture"));
    }
    const auto serialized = native_worker::serialize_native_provider_snapshot_v3(
        snapshot, sidecar_bytes);
    if (serialized.empty()) {
        return result_t::failure(make_workspace_error(workspace_error_code_t::limit_exceeded,
            "batch decompile generation snapshot serialization failed",
            "decompile_batch.capture"));
    }
    diag::log_tagged_fmt("dec_batch",
        "snapshot_serialized version=3 snapshot_bytes=%llu ranges=%zu sidecar_bytes=%llu sidecar_names=%zu sidecar_imports=%zu sidecar_prototypes=%zu sidecar_noreturn=%zu sidecar_strings=%zu sidecar_scalars=%zu sidecar_members=%zu sidecar_vtables=%zu sidecar_comments=%zu",
        static_cast<unsigned long long>(serialized.size()), snapshot.ranges.size(),
        static_cast<unsigned long long>(sidecar_bytes.size()),
        sidecar.names.size(), sidecar.imports.size(), sidecar.prototypes.size(),
        sidecar.noreturn.size(), sidecar.strings.size(), sidecar.global_scalars.size(),
        sidecar.members.size(), sidecar.vtables.size(), sidecar.comments.size());
    std::vector<std::uint8_t> serialized_bytes(serialized.begin(), serialized.end());
    auto shared_snapshot = std::make_shared<const std::vector<std::uint8_t>>(
        std::move(serialized_bytes));
    const auto snapshot_hash = stable_serialization_hash(serialized);
    const auto published = generation_snapshot_store_t::instance().publish(
        publication->generation, snapshot_hash, shared_snapshot);
    diag::log_tagged_fmt("dec_batch",
        "generation_snapshot_store_publish generation=%llu snapshot_bytes=%llu published=%d",
        static_cast<unsigned long long>(publication->generation),
        static_cast<unsigned long long>(shared_snapshot->size()),
        published ? 1 : 0);
    std::shared_ptr<const decompiler_provider_context_t> context =
        std::make_shared<ghidra_native_provider_context_t>(
            std::move(shared_snapshot), snapshot_hash);
    return result_t::success(std::move(context));
} catch (const std::bad_alloc&) {
    return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
        make_workspace_error(workspace_error_code_t::limit_exceeded,
            "batch decompile provider capture allocation failed", "decompile_batch.capture"));
} catch (...) {
    return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
        make_workspace_error(workspace_error_code_t::integrity_failure,
            "batch decompile provider capture failed", "decompile_batch.capture"));
}

}
