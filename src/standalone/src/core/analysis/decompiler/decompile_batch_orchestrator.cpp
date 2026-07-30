#include "decompile_batch_orchestrator.hpp"

#include "decompiler_service.hpp"
#include "decompiler_ui_integration.hpp"
#include "native_worker_host.hpp"

#include "../../disasm/ghidra_adapters/aida_arch_map.hpp"
#include "../../disasm/ghidra_adapters/aida_load_image.hpp"
#include "../../infra/executor.hpp"
#include "../../mcp/downstream_producer_governor.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
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
constexpr std::uint64_t k_expected_worker_rss_bytes = 400ULL << 20;
constexpr std::uint64_t k_analysis_memory_budget_bytes = 16ULL << 30;
constexpr std::uint64_t k_batch_snapshot_absolute_cap = 256ULL << 20;
constexpr std::uint64_t k_worker_snapshot_cap = 256ULL << 20;
constexpr std::uint64_t k_snapshot_header_floor = 1ULL << 20;
constexpr std::uint64_t k_snapshot_read_quantum = 4ULL << 20;

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

}

struct decompile_batch_orchestrator_t::state_t {
    std::weak_ptr<analysis_workspace_t> workspace;
    std::shared_ptr<analysis_metrics_t> metrics;

    mutable std::mutex mutex;
    std::condition_variable wake;
    std::shared_ptr<const analysis_publication_t> pending_publication;
    bool publish_pending = false;
    bool control_exit = false;
    bool control_started = false;
    std::thread control_thread;

    std::shared_ptr<const analysis_publication_t> run_publication;
    std::shared_ptr<decompiler_pipeline_service_t> service;
    std::shared_ptr<const decompiler_provider_context_t> provider_context;
    std::unordered_map<std::uint64_t, const function_record_t*> functions_by_id;
    cancellation_source_t run_cancel;
    bool run_active = false;
    bool run_starting = false;
    bool run_finishing = false;
    std::atomic<bool> run_cancelling{false};
    std::atomic<std::uint64_t> cancel_epoch{0};
    std::uint64_t run_generation = 0;
    std::uint64_t run_revision = 0;
    std::uint64_t run_overlay_revision = 0;
    std::uint64_t run_image_base = 0;
    std::chrono::steady_clock::time_point run_started;
    std::uint64_t total = 0;
    std::uint64_t completed = 0;
    std::uint64_t failed = 0;
    std::uint64_t cancelled = 0;
    std::uint64_t mem_hits = 0;
    std::uint64_t disk_hits = 0;
    std::uint64_t wall_ns = 0;
    std::uint64_t in_flight = 0;
    std::uint64_t progress_log_mark = 0;
    std::uint64_t ema_last_completed = 0;
    std::chrono::steady_clock::time_point ema_last_time;
    double rate_ema = 0.0;
    std::uint64_t governor_rejected_baseline = 0;
    mcp_standalone::downstream::scoped_admission_t admission;
    std::size_t slots_total = 0;
    std::size_t slots_done = 0;
    std::atomic<std::size_t> slots_effective{0};
    std::deque<batch_work_item_t> queue;
    std::deque<batch_work_item_t> interactive_queue;
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
        if (state_->control_started && state_->control_thread.joinable())
            state_->control_thread.join();
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

void cancel_run_locked(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state)
{
    state->cancel_epoch.fetch_add(1, std::memory_order_acq_rel);
    state->run_cancel.request_cancel();
    state->run_cancelling.store(true, std::memory_order_release);
    const std::uint64_t queued = static_cast<std::uint64_t>(
        state->queue.size() + state->interactive_queue.size());
    if (queued != 0) {
        state->cancelled += queued;
        metrics_add(state->metrics, analysis_metric_t::decompile_batch_cancelled, queued);
        state->queue.clear();
        state->interactive_queue.clear();
        state->queued_ids.clear();
    }
    state->wake.notify_all();
}

std::size_t pending_queue_depth(const decompile_batch_orchestrator_t::state_t& state) noexcept
{
    return state.queue.size() + state.interactive_queue.size();
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
            std::lock_guard lock(state->mutex);
            --state->in_flight;
            state->in_flight_ids.erase(function_id);
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
    const unsigned int logical_cores = (std::max)(2u, std::thread::hardware_concurrency());
    const std::size_t slots = (std::min<std::size_t>)(8,
        (std::min<std::size_t>)(quotas.decompiler_worker_group_size,
            (std::max<std::size_t>)(2, logical_cores / 2)));
    const std::uint64_t snapshot_mapping_bytes =
        static_cast<std::uint64_t>(slots + 1) * snapshot_bytes;
    const std::uint64_t worker_rss_bytes =
        static_cast<std::uint64_t>(slots) * k_expected_worker_rss_bytes;
    const std::uint64_t memory_admission_bytes = snapshot_mapping_bytes + worker_rss_bytes;
    const std::uint64_t memory_admission_budget = k_analysis_memory_budget_bytes / 4;
    diag::log_tagged_fmt("dec_batch",
        "budget_decision type=memory_admission formula=(slots+1)*snapshot_bytes+slots*expected_rss slots=%zu snapshot_bytes=%llu snapshot_term=%llu rss_term=%llu total=%llu budget=%llu decision=%s",
        slots,
        static_cast<unsigned long long>(snapshot_bytes),
        static_cast<unsigned long long>(snapshot_mapping_bytes),
        static_cast<unsigned long long>(worker_rss_bytes),
        static_cast<unsigned long long>(memory_admission_bytes),
        static_cast<unsigned long long>(memory_admission_budget),
        memory_admission_bytes > memory_admission_budget ? "defer" : "admit");
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
            state->run_started = std::chrono::steady_clock::now();
            state->total = static_cast<std::uint64_t>(worklist.size());
            state->completed = 0;
            state->failed = 0;
            state->cancelled = 0;
            state->mem_hits = 0;
            state->disk_hits = 0;
            state->wall_ns = 0;
            state->in_flight = 0;
            state->progress_log_mark = 0;
            state->ema_last_completed = 0;
            state->ema_last_time = state->run_started;
            state->rate_ema = 0.0;
            state->governor_rejected_baseline = 0;
            state->queue.assign(worklist.begin(), worklist.end());
            state->interactive_queue.clear();
            state->queued_ids.clear();
            state->in_flight_ids.clear();
            state->queued_ids.reserve(worklist.size());
            for (const auto& item : worklist)
                state->queued_ids.insert(item.function_id);
            state->admission = std::move(admission);
            state->slots_total = slots;
            state->slots_done = 0;
            state->slots_effective.store(slots, std::memory_order_release);
            state->run_finishing = false;
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
        static_cast<std::uint64_t>(worklist.size()));
    diag::log_tagged_fmt("dec_batch",
        "run_start generation=%llu analysis_revision=%llu functions=%zu lanes=interactive,exports,depth,linear slots=%zu quota=%zu snapshot_bytes=%llu profile=thorough deadlines=size_aware",
        static_cast<unsigned long long>(publication->generation),
        static_cast<unsigned long long>(publication->analysis_revision),
        worklist.size(), slots, quotas.decompiler_worker_group_size,
        static_cast<unsigned long long>(snapshot_bytes));
    std::size_t submitted = 0;
    for (std::size_t index = 0; index < slots; ++index) {
        aida::infra::executor::submission_t submission;
        submission.owner_subsystem = "decompiler";
        submission.label = "decompile.batch_slot";
        submission.thread_class = "external_tool";
        submission.domain = aida::infra::executor::domain_t::external_tool;
        submission.priority = 2;
        submission.shutdown_policy = "drain";
        submission.body = [state, index] { slot_main(state, index); };
        if (aida::infra::executor::submit(std::move(submission)).submitted)
            ++submitted;
        else
            diag::log_tagged_fmt("dec_batch", "slot_post_failed index=%zu", index);
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
            return !state->run_active || state->control_exit || state->publish_pending;
        });
        if (state->control_exit && !state->run_cancelling.load(std::memory_order_acquire))
            cancel_run_locked(state);
        if (state->publish_pending && !state->run_cancelling.load(std::memory_order_acquire)) {
            const std::uint64_t in_flight = state->in_flight;
            diag::log_tagged_fmt("dec_batch", "run_cancel reason=superseded in_flight=%llu queued=%zu",
                static_cast<unsigned long long>(in_flight), pending_queue_depth(*state));
            cancel_run_locked(state);
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
        if (state->queue.empty() && state->interactive_queue.empty() &&
            state->in_flight == 0 && !state->run_finishing) {
            state->run_finishing = true;
            state->wake.notify_all();
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
    if (state->admission.active()) {
        diag::log_tagged_fmt("dec_batch",
            "FEATURE-WORKER-GROUP-RELEASE decompile_batch_orchestrator token=%llu reason=completed",
            static_cast<unsigned long long>(state->admission.token()));
        state->admission.release("completed");
    }
    state->run_active = false;
    state->run_starting = false;
    state->run_finishing = false;
    state->run_cancelling.store(false, std::memory_order_release);
    state->service.reset();
    state->provider_context.reset();
    state->functions_by_id.clear();
    state->queue.clear();
    state->interactive_queue.clear();
    state->queued_ids.clear();
    state->in_flight_ids.clear();
    state->wake.notify_all();
    lock.unlock();
}

void slot_main(const std::shared_ptr<decompile_batch_orchestrator_t::state_t>& state,
               std::size_t slot_index)
{
    try {
        diag::log_tagged_fmt("dec_batch", "slot_enter index=%zu tid=%lu",
            slot_index, static_cast<unsigned long>(GetCurrentThreadId()));
        while (true) {
            batch_work_item_t item;
            {
                std::unique_lock lock(state->mutex);
                state->wake.wait_for(lock, std::chrono::milliseconds(100), [&state] {
                    return !state->queue.empty() || !state->interactive_queue.empty() ||
                        state->run_finishing || state->control_exit ||
                        state->run_cancelling.load(std::memory_order_acquire);
                });
                if (slot_index >= state->slots_effective.load(std::memory_order_acquire))
                    break;
                if (state->queue.empty() && state->interactive_queue.empty()) {
                    if (state->run_finishing || state->control_exit ||
                        state->run_cancelling.load(std::memory_order_acquire))
                        break;
                    continue;
                }
                if (!state->interactive_queue.empty()) {
                    item = state->interactive_queue.front();
                    state->interactive_queue.pop_front();
                } else {
                    item = state->queue.front();
                    state->queue.pop_front();
                }
                state->queued_ids.erase(item.function_id);
                state->in_flight_ids.insert(item.function_id);
                ++state->in_flight;
            }
            in_flight_lease_t in_flight_lease(state, item.function_id);
            process_item(state, item);
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
    const std::uint64_t deadline_ms = decompile_batch_orchestrator_t::compute_size_aware_deadline(
        item.byte_size, architecture, decompile_deadline_lane_t::batch);
    if (deadline_ms > k_deadline_scaled_log_threshold_ms) {
        diag::log_tagged_fmt("dec_batch",
            "deadline_scaled function_rva=0x%llx byte_size=%llu est_insns=%llu deadline_ms=%llu",
            static_cast<unsigned long long>(item.entry_rva),
            static_cast<unsigned long long>(item.byte_size),
            static_cast<unsigned long long>(estimate_instructions(item.byte_size, architecture)),
            static_cast<unsigned long long>(deadline_ms));
    }
    auto budget = default_decompiler_profile_policy().thorough;
    budget.max_wall_clock_ms = deadline_ms;
    budget.max_cpu_ms = (std::max<std::uint64_t>)(1000, deadline_ms / 2);
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(deadline_ms);
    auto built = make_native_pipeline_request(*workspace, publication, function,
        decompiler_pipeline_invocation_t::background_batch,
        decompiler_pipeline_cache_mode_t::read_write,
        decompiler_profile_id_t::thorough, budget, deadline, state->provider_context, cancel);
    if (!built) {
        std::lock_guard lock(state->mutex);
        ++state->failed;
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
        std::lock_guard lock(state->mutex);
        state->in_flight_ids.erase(item.function_id);
        state->queued_ids.insert(item.function_id);
        if (item.lane == 0)
            state->interactive_queue.push_front(item);
        else
            state->queue.push_front(item);
        metrics_set_max(state->metrics, analysis_metric_t::decompile_batch_queue_depth_peak,
            static_cast<std::uint64_t>(pending_queue_depth(*state)));
        state->wake.notify_one();
        return;
    }
    if (result_retryable(result) && item.attempt < 1) {
        item.attempt = static_cast<std::uint8_t>(item.attempt + 1);
        std::lock_guard lock(state->mutex);
        state->in_flight_ids.erase(item.function_id);
        state->queued_ids.insert(item.function_id);
        if (item.lane == 0)
            state->interactive_queue.push_back(item);
        else
            state->queue.push_back(item);
        metrics_set_max(state->metrics, analysis_metric_t::decompile_batch_queue_depth_peak,
            static_cast<std::uint64_t>(pending_queue_depth(*state)));
        state->wake.notify_one();
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
    auto orchestrator = std::shared_ptr<decompile_batch_orchestrator_t>(
        new decompile_batch_orchestrator_t(std::move(state)));
    auto attach_failure = [&orchestrator](workspace_error_t error) {
        orchestrator->request_cancel();
        (void)orchestrator->drain(std::chrono::steady_clock::now() + std::chrono::seconds(2));
        return workspace_result_t<std::shared_ptr<decompile_batch_orchestrator_t>>::failure(
            std::move(error));
    };
    try {
        orchestrator->state_->control_thread = std::thread(control_main, orchestrator->state_);
        orchestrator->state_->control_started = true;
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<decompile_batch_orchestrator_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "decompile batch orchestrator control thread allocation failed",
                "decompile_batch.create"));
    } catch (...) {
        return workspace_result_t<std::shared_ptr<decompile_batch_orchestrator_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "decompile batch orchestrator control thread could not be started",
                "decompile_batch.create"));
    }
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
            in_flight = state_->in_flight;
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

void decompile_batch_orchestrator_t::notify_interactive_request(const decompiler_entity_key_t& entity)
{
    if (!state_ || entity.kind != decompiler_entity_kind_t::native_function)
        return;
    const auto* native = std::get_if<native_decompiler_entity_identity_t>(&entity.identity);
    if (!native)
        return;
    std::lock_guard lock(state_->mutex);
    if (!state_->run_active || state_->run_finishing ||
        state_->run_cancelling.load(std::memory_order_acquire) || !state_->run_publication ||
        !state_->run_publication->snapshot)
        return;
    const auto found = state_->functions_by_id.find(native->function_id);
    if (found == state_->functions_by_id.end() || !found->second)
        return;
    if (state_->in_flight_ids.count(native->function_id) != 0)
        return;
    if (!state_->queued_ids.insert(native->function_id).second)
        return;
    batch_work_item_t item;
    item.function_id = native->function_id;
    item.entry_rva = rva_of(found->second->start, state_->run_image_base);
    item.byte_size = function_byte_size(*state_->run_publication->snapshot, *found->second);
    item.lane = 0;
    item.depth = 0;
    state_->interactive_queue.push_back(item);
    ++state_->total;
    metrics_set_max(state_->metrics, analysis_metric_t::decompile_batch_queue_depth_peak,
        static_cast<std::uint64_t>(pending_queue_depth(*state_)));
    state_->wake.notify_one();
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
    std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
    ranges.emplace_back(0, (std::min<std::uint64_t>)(image->image_size,
        (std::max<std::uint64_t>)(image->header_size, k_snapshot_header_floor)));
    for (const auto& section : image->sections) {
        if ((section.permissions & image_permission_execute) == 0 ||
            section.virtual_address >= image->image_size || section.virtual_size == 0)
            continue;
        ranges.emplace_back(section.virtual_address,
            (std::min<std::uint64_t>)(image->image_size,
                section.virtual_address + section.virtual_size));
    }
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
    std::uint64_t requested_bytes = 0;
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
    const auto serialized = native_worker::serialize_native_provider_snapshot(snapshot);
    if (serialized.empty()) {
        return result_t::failure(make_workspace_error(workspace_error_code_t::limit_exceeded,
            "batch decompile generation snapshot serialization failed",
            "decompile_batch.capture"));
    }
    std::vector<std::uint8_t> serialized_bytes(serialized.begin(), serialized.end());
    auto shared_snapshot = std::make_shared<const std::vector<std::uint8_t>>(
        std::move(serialized_bytes));
    std::shared_ptr<const decompiler_provider_context_t> context =
        std::make_shared<ghidra_native_provider_context_t>(
            std::move(shared_snapshot), stable_serialization_hash(serialized));
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
