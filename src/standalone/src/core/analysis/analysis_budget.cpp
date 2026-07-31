#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "analysis_budget.hpp"

#include <limits>

namespace aida::analysis {
namespace {

analysis_resource_error_t make_resource_error(analysis_resource_error_code_t code,
                                              analysis_resource_kind_t kind = analysis_resource_kind_t::none,
                                              std::uint64_t limit = 0,
                                              std::uint64_t requested = 0,
                                              std::uint64_t in_use = 0) noexcept
{
    return {code, kind, analysis_resource_error_code_name(code), limit, requested, in_use};
}

bool add_checked(std::uint64_t current, std::uint64_t increment, std::uint64_t& result) noexcept
{
    if (increment > std::numeric_limits<std::uint64_t>::max() - current)
        return false;
    result = current + increment;
    return true;
}

analysis_resource_error_t validate_increment(std::uint64_t current,
                                             std::uint64_t increment,
                                             std::uint64_t limit,
                                             analysis_resource_kind_t kind,
                                             analysis_resource_error_code_t exhausted_code) noexcept
{
    std::uint64_t total = 0;
    if (!add_checked(current, increment, total)) {
        return make_resource_error(analysis_resource_error_code_t::arithmetic_overflow, kind, limit, increment,
                                   current);
    }
    if (total > limit)
        return make_resource_error(exhausted_code, kind, limit, increment, current);
    return {};
}

analysis_resource_error_t validate_demand(const analysis_budget_t& budget,
                                          const analysis_resource_usage_t& usage,
                                          const analysis_resource_demand_t& demand) noexcept
{
    const auto private_error = validate_increment(usage.private_bytes, demand.private_bytes,
                                                  budget.max_private_bytes,
                                                  analysis_resource_kind_t::private_bytes,
                                                  analysis_resource_error_code_t::private_bytes_exhausted);
    if (!private_error.ok())
        return private_error;

    const auto mapped_error = validate_increment(usage.mapped_window_bytes, demand.mapped_window_bytes,
                                                 budget.max_mapped_window_bytes,
                                                 analysis_resource_kind_t::mapped_window_bytes,
                                                 analysis_resource_error_code_t::mapped_window_bytes_exhausted);
    if (!mapped_error.ok())
        return mapped_error;

    const auto spill_error = validate_increment(usage.spill_bytes, demand.spill_bytes, budget.max_spill_bytes,
                                                analysis_resource_kind_t::spill_bytes,
                                                analysis_resource_error_code_t::spill_bytes_exhausted);
    if (!spill_error.ok())
        return spill_error;

    return validate_increment(usage.cache_bytes, demand.cache_bytes, budget.max_cache_bytes,
                              analysis_resource_kind_t::cache_bytes,
                              analysis_resource_error_code_t::cache_bytes_exhausted);
}

void add_usage(analysis_resource_usage_t& usage, const analysis_resource_demand_t& demand) noexcept
{
    usage.private_bytes += demand.private_bytes;
    usage.mapped_window_bytes += demand.mapped_window_bytes;
    usage.spill_bytes += demand.spill_bytes;
    usage.cache_bytes += demand.cache_bytes;
}

void subtract_usage(analysis_resource_usage_t& usage, const analysis_resource_demand_t& demand) noexcept
{
    usage.private_bytes -= demand.private_bytes;
    usage.mapped_window_bytes -= demand.mapped_window_bytes;
    usage.spill_bytes -= demand.spill_bytes;
    usage.cache_bytes -= demand.cache_bytes;
}

constexpr std::uint64_t clamp_u64(std::uint64_t value, std::uint64_t floor_value,
                                  std::uint64_t ceiling_value) noexcept
{
    return value < floor_value ? floor_value : value > ceiling_value ? ceiling_value : value;
}

constexpr std::uint64_t kReserveOsFloorBytes = 4ULL * analysis_gibibyte;
constexpr std::uint64_t kReserveOsCeilingBytes = 16ULL * analysis_gibibyte;
constexpr std::uint64_t kMaxAnalysisMemoryFloorBytes = 8ULL * analysis_gibibyte;
constexpr std::uint64_t kMaxAnalysisMemoryCeilingBytes = 48ULL * analysis_gibibyte;
constexpr std::uint64_t kStagingFloorBytes = 512ULL * analysis_mebibyte;
constexpr std::uint64_t kStagingCeilingBytes = 4ULL * analysis_gibibyte;
constexpr std::uint64_t kQuotaFloorBytes = 8ULL * analysis_gibibyte;
constexpr std::uint64_t kQuotaCeilingBytes = 16ULL * analysis_gibibyte;
constexpr std::uint64_t kWindowCachePerFileFloorBytes = 256ULL * analysis_mebibyte;
constexpr std::uint64_t kWindowCachePerFileCeilingBytes = 2ULL * analysis_gibibyte;
constexpr std::uint64_t kWindowCacheGlobalFloorBytes = analysis_gibibyte;
constexpr std::uint64_t kWindowCacheGlobalCeilingBytes = 4ULL * analysis_gibibyte;
constexpr std::uint64_t kPdbPersistFloorBytes = 256ULL * analysis_mebibyte;
constexpr std::uint64_t kPdbPersistCeilingBytes = analysis_gibibyte;
constexpr std::uint64_t kReopenRangeFloorBytes = analysis_gibibyte;
constexpr std::uint64_t kReopenRangeCeilingBytes = 8ULL * analysis_gibibyte;
constexpr std::uint64_t kLowMemoryThresholdBytes = 24ULL * analysis_gibibyte;
constexpr std::uint64_t kFallbackTotalPhysBytes = 16ULL * analysis_gibibyte;
constexpr std::uint64_t kGovernorMappedFloorBytes = analysis_gibibyte;
constexpr std::uint64_t kGovernorMappedCeilingBytes = 4ULL * analysis_gibibyte;
constexpr std::uint64_t kGovernorPageCacheFloorBytes = analysis_gibibyte;
constexpr std::uint64_t kGovernorPageCacheCeilingBytes = 4ULL * analysis_gibibyte;
constexpr std::uint64_t kGovernorResidentFloorBytes = 8ULL * analysis_gibibyte;
constexpr std::uint64_t kGovernorResidentCeilingBytes = 48ULL * analysis_gibibyte;
constexpr std::uint64_t kGovernorStagingFloorBytes = 512ULL * analysis_mebibyte;
constexpr std::uint64_t kGovernorStagingCeilingBytes = 4ULL * analysis_gibibyte;
constexpr std::uint64_t kGovernorDecodeFloorBytes = 4ULL * analysis_gibibyte;
constexpr std::uint64_t kGovernorDecodeCeilingBytes = 16ULL * analysis_gibibyte;
constexpr std::uint64_t kGovernorSearchFloorBytes = 2ULL * analysis_gibibyte;
constexpr std::uint64_t kGovernorSearchCeilingBytes = 8ULL * analysis_gibibyte;
constexpr std::uint64_t kGovernorDecompilerFloorBytes = 128ULL * analysis_mebibyte;
constexpr std::uint64_t kGovernorDecompilerCeilingBytes = 512ULL * analysis_mebibyte;
constexpr std::uint64_t kGovernorWorkerFloorBytes = 256ULL * analysis_mebibyte;
constexpr std::uint64_t kGovernorWorkerCeilingBytes = analysis_gibibyte;
constexpr std::uint64_t kGovernorXrefFloorBytes = 256ULL * analysis_mebibyte;
constexpr std::uint64_t kGovernorXrefCeilingBytes = analysis_gibibyte;
constexpr std::uint64_t kGovernorSqliteCachesBytes = 512ULL * analysis_mebibyte;
constexpr std::uint64_t kGovernorUiMiscBytes = analysis_gibibyte;

}

std::string_view analysis_resource_kind_name(analysis_resource_kind_t kind) noexcept
{
    switch (kind) {
    case analysis_resource_kind_t::none:
        return "none";
    case analysis_resource_kind_t::queue_slots:
        return "queue_slots";
    case analysis_resource_kind_t::worker_slots:
        return "worker_slots";
    case analysis_resource_kind_t::private_bytes:
        return "private_bytes";
    case analysis_resource_kind_t::mapped_window_bytes:
        return "mapped_window_bytes";
    case analysis_resource_kind_t::spill_bytes:
        return "spill_bytes";
    case analysis_resource_kind_t::cache_bytes:
        return "cache_bytes";
    case analysis_resource_kind_t::cancellation_checkpoint:
        return "cancellation_checkpoint";
    }
    return "unknown";
}

std::string_view analysis_resource_error_code_name(analysis_resource_error_code_t code) noexcept
{
    switch (code) {
    case analysis_resource_error_code_t::none:
        return "ok";
    case analysis_resource_error_code_t::invalid_budget:
        return "invalid_budget";
    case analysis_resource_error_code_t::invalid_task_id:
        return "invalid_task_id";
    case analysis_resource_error_code_t::duplicate_reservation:
        return "duplicate_reservation";
    case analysis_resource_error_code_t::queue_capacity_exhausted:
        return "queue_capacity_exhausted";
    case analysis_resource_error_code_t::worker_capacity_exhausted:
        return "worker_capacity_exhausted";
    case analysis_resource_error_code_t::reserved_control_capacity_exhausted:
        return "reserved_control_capacity_exhausted";
    case analysis_resource_error_code_t::private_bytes_exhausted:
        return "private_bytes_exhausted";
    case analysis_resource_error_code_t::mapped_window_bytes_exhausted:
        return "mapped_window_bytes_exhausted";
    case analysis_resource_error_code_t::spill_bytes_exhausted:
        return "spill_bytes_exhausted";
    case analysis_resource_error_code_t::cache_bytes_exhausted:
        return "cache_bytes_exhausted";
    case analysis_resource_error_code_t::arithmetic_overflow:
        return "arithmetic_overflow";
    case analysis_resource_error_code_t::reservation_not_found:
        return "reservation_not_found";
    case analysis_resource_error_code_t::invalid_reservation_state:
        return "invalid_reservation_state";
    }
    return "unknown_resource_error";
}

analysis_resource_error_t validate_analysis_budget(const analysis_budget_t& budget) noexcept
{
    if (budget.max_queued_tasks == 0) {
        return make_resource_error(analysis_resource_error_code_t::invalid_budget,
                                   analysis_resource_kind_t::queue_slots, 1, 0, 0);
    }
    if (budget.max_worker_slots == 0) {
        return make_resource_error(analysis_resource_error_code_t::invalid_budget,
                                   analysis_resource_kind_t::worker_slots, 1, 0, 0);
    }
    if (budget.reserved_control_worker_slots == 0 ||
        budget.reserved_control_worker_slots > budget.max_worker_slots) {
        return make_resource_error(analysis_resource_error_code_t::invalid_budget,
                                   analysis_resource_kind_t::worker_slots, budget.max_worker_slots,
                                   budget.reserved_control_worker_slots, 0);
    }
    if (budget.cancellation_checkpoint_milliseconds == 0 ||
        budget.cancellation_checkpoint_milliseconds > max_analysis_cancellation_checkpoint_milliseconds) {
        return make_resource_error(analysis_resource_error_code_t::invalid_budget,
                                   analysis_resource_kind_t::cancellation_checkpoint,
                                   max_analysis_cancellation_checkpoint_milliseconds,
                                   budget.cancellation_checkpoint_milliseconds, 0);
    }
    if (budget.max_private_bytes == 0) {
        return make_resource_error(analysis_resource_error_code_t::invalid_budget,
                                   analysis_resource_kind_t::private_bytes, 1, 0, 0);
    }
    if (budget.max_mapped_window_bytes == 0) {
        return make_resource_error(analysis_resource_error_code_t::invalid_budget,
                                   analysis_resource_kind_t::mapped_window_bytes, 1, 0, 0);
    }
    if (budget.max_spill_bytes == 0) {
        return make_resource_error(analysis_resource_error_code_t::invalid_budget,
                                   analysis_resource_kind_t::spill_bytes, 1, 0, 0);
    }
    if (budget.max_cache_bytes == 0) {
        return make_resource_error(analysis_resource_error_code_t::invalid_budget,
                                   analysis_resource_kind_t::cache_bytes, 1, 0, 0);
    }
    return {};
}

analysis_budget_ledger_t::analysis_budget_ledger_t(analysis_budget_t budget) : budget_(budget)
{
}

analysis_resource_error_t analysis_budget_ledger_t::reserve(analysis_task_id_t task_id,
                                                             const analysis_resource_demand_t& demand)
{
    const auto budget_error = validate_analysis_budget(budget_);
    if (!budget_error.ok())
        return budget_error;
    if (task_id == 0)
        return make_resource_error(analysis_resource_error_code_t::invalid_task_id);
    if (reservations_.find(task_id) != reservations_.end())
        return make_resource_error(analysis_resource_error_code_t::duplicate_reservation);
    if (queued_tasks_ >= budget_.max_queued_tasks) {
        return make_resource_error(analysis_resource_error_code_t::queue_capacity_exhausted,
                                   analysis_resource_kind_t::queue_slots, budget_.max_queued_tasks, 1,
                                   queued_tasks_);
    }
    const auto demand_error = validate_demand(budget_, usage_, demand);
    if (!demand_error.ok())
        return demand_error;

    reservations_.emplace(task_id, reservation_entry_t{demand, analysis_reservation_state_t::queued, false});
    add_usage(usage_, demand);
    ++queued_tasks_;
    return {};
}

analysis_resource_error_t analysis_budget_ledger_t::activate(analysis_task_id_t task_id,
                                                              bool control_task) noexcept
{
    const auto entry = reservations_.find(task_id);
    if (entry == reservations_.end())
        return make_resource_error(analysis_resource_error_code_t::reservation_not_found);
    if (entry->second.state != analysis_reservation_state_t::queued) {
        return make_resource_error(analysis_resource_error_code_t::invalid_reservation_state,
                                   analysis_resource_kind_t::queue_slots);
    }
    if (active_workers_ >= budget_.max_worker_slots) {
        return make_resource_error(analysis_resource_error_code_t::worker_capacity_exhausted,
                                   analysis_resource_kind_t::worker_slots, budget_.max_worker_slots, 1,
                                   active_workers_);
    }
    if (!control_task) {
        const auto non_control_limit = budget_.max_worker_slots - budget_.reserved_control_worker_slots;
        if (active_non_control_workers_ >= non_control_limit) {
            return make_resource_error(analysis_resource_error_code_t::reserved_control_capacity_exhausted,
                                       analysis_resource_kind_t::worker_slots, non_control_limit, 1,
                                       active_non_control_workers_);
        }
    }

    entry->second.state = analysis_reservation_state_t::active;
    entry->second.control_task = control_task;
    --queued_tasks_;
    ++active_workers_;
    if (control_task)
        ++active_control_workers_;
    else
        ++active_non_control_workers_;
    return {};
}

analysis_resource_error_t analysis_budget_ledger_t::requeue(analysis_task_id_t task_id) noexcept
{
    const auto entry = reservations_.find(task_id);
    if (entry == reservations_.end())
        return make_resource_error(analysis_resource_error_code_t::reservation_not_found);
    if (entry->second.state != analysis_reservation_state_t::active) {
        return make_resource_error(analysis_resource_error_code_t::invalid_reservation_state,
                                   analysis_resource_kind_t::worker_slots);
    }
    if (queued_tasks_ >= budget_.max_queued_tasks) {
        return make_resource_error(analysis_resource_error_code_t::queue_capacity_exhausted,
                                   analysis_resource_kind_t::queue_slots, budget_.max_queued_tasks, 1,
                                   queued_tasks_);
    }

    entry->second.state = analysis_reservation_state_t::queued;
    if (entry->second.control_task)
        --active_control_workers_;
    else
        --active_non_control_workers_;
    entry->second.control_task = false;
    --active_workers_;
    ++queued_tasks_;
    return {};
}

analysis_resource_error_t analysis_budget_ledger_t::release_queued(analysis_task_id_t task_id) noexcept
{
    return release(task_id, analysis_reservation_state_t::queued);
}

analysis_resource_error_t analysis_budget_ledger_t::release_active(analysis_task_id_t task_id) noexcept
{
    return release(task_id, analysis_reservation_state_t::active);
}

analysis_resource_error_t analysis_budget_ledger_t::release(analysis_task_id_t task_id,
                                                             analysis_reservation_state_t expected_state) noexcept
{
    const auto entry = reservations_.find(task_id);
    if (entry == reservations_.end())
        return make_resource_error(analysis_resource_error_code_t::reservation_not_found);
    if (entry->second.state != expected_state) {
        return make_resource_error(analysis_resource_error_code_t::invalid_reservation_state,
                                   expected_state == analysis_reservation_state_t::queued
                                       ? analysis_resource_kind_t::queue_slots
                                       : analysis_resource_kind_t::worker_slots);
    }

    if (expected_state == analysis_reservation_state_t::queued) {
        --queued_tasks_;
    } else {
        --active_workers_;
        if (entry->second.control_task)
            --active_control_workers_;
        else
            --active_non_control_workers_;
    }
    subtract_usage(usage_, entry->second.demand);
    reservations_.erase(entry);
    return {};
}

analysis_budget_snapshot_t analysis_budget_ledger_t::snapshot() const noexcept
{
    const auto control_available = active_workers_ <= budget_.max_worker_slots
                                       ? budget_.max_worker_slots - active_workers_
                                       : 0;
    const auto non_control_limit = budget_.reserved_control_worker_slots <= budget_.max_worker_slots
                                       ? budget_.max_worker_slots - budget_.reserved_control_worker_slots
                                       : 0;
    const auto non_control_quota_available = active_non_control_workers_ <= non_control_limit
                                                 ? non_control_limit - active_non_control_workers_
                                                 : 0;
    const auto non_control_available = control_available < non_control_quota_available
                                           ? control_available
                                           : non_control_quota_available;
    return {budget_, usage_, queued_tasks_, active_workers_, active_control_workers_, active_non_control_workers_,
            control_available, non_control_available};
}

const analysis_budget_t& analysis_budget_ledger_t::budget() const noexcept
{
    return budget_;
}

host_memory_envelope_t host_memory_envelope() noexcept
{
    host_memory_envelope_t envelope;
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    if (!GlobalMemoryStatusEx(&status)) {
        envelope.total_phys = kFallbackTotalPhysBytes;
        envelope.avail_phys = 0;
    } else {
        envelope.total_phys = static_cast<std::uint64_t>(status.ullTotalPhys);
        envelope.avail_phys = static_cast<std::uint64_t>(status.ullAvailPhys);
    }
    envelope.reserve_os_bytes = clamp_u64(envelope.total_phys / 4ULL, kReserveOsFloorBytes,
                                          kReserveOsCeilingBytes);
    envelope.usable_bytes = envelope.total_phys > envelope.reserve_os_bytes
        ? envelope.total_phys - envelope.reserve_os_bytes : 0;
    return envelope;
}

adaptive_analysis_budget_fields_t adaptive_analysis_budget_fields(
    const host_memory_envelope_t& envelope) noexcept
{
    adaptive_analysis_budget_fields_t fields;
    const std::uint64_t usable = envelope.usable_bytes;
    fields.max_analysis_memory_bytes = clamp_u64(usable / 2ULL, kMaxAnalysisMemoryFloorBytes,
                                                 kMaxAnalysisMemoryCeilingBytes);
    fields.packed_staging_memory_budget_bytes = clamp_u64(usable / 16ULL, kStagingFloorBytes,
                                                          kStagingCeilingBytes);
    fields.packed_generation_quota_bytes = clamp_u64(usable / 2ULL, kQuotaFloorBytes,
                                                     kQuotaCeilingBytes);
    fields.window_cache_per_file_bytes = clamp_u64(usable / 32ULL, kWindowCachePerFileFloorBytes,
                                                   kWindowCachePerFileCeilingBytes);
    fields.window_cache_global_bytes = clamp_u64(usable / 16ULL, kWindowCacheGlobalFloorBytes,
                                                 kWindowCacheGlobalCeilingBytes);
    fields.pdb_persistence_total_bytes = clamp_u64(usable / 32ULL, kPdbPersistFloorBytes,
                                                   kPdbPersistCeilingBytes);
    fields.reopen_range_budget_bytes = clamp_u64(usable / 8ULL, kReopenRangeFloorBytes,
                                                  kReopenRangeCeilingBytes);
    fields.low_memory = envelope.total_phys < kLowMemoryThresholdBytes;
    return fields;
}

governor_subsystem_budget_fields_t governor_subsystem_budget_fields(
    const host_memory_envelope_t& envelope) noexcept
{
    governor_subsystem_budget_fields_t fields;
    const std::uint64_t usable = envelope.usable_bytes;
    fields.mapped_windows_bytes = clamp_u64(usable / 16ULL, kGovernorMappedFloorBytes,
                                            kGovernorMappedCeilingBytes);
    fields.fact_page_cache_bytes = clamp_u64(usable / 12ULL, kGovernorPageCacheFloorBytes,
                                             kGovernorPageCacheCeilingBytes);
    fields.resident_facts_bytes = clamp_u64(usable / 2ULL, kGovernorResidentFloorBytes,
                                            kGovernorResidentCeilingBytes);
    fields.persistence_staging_bytes = clamp_u64(usable / 16ULL, kGovernorStagingFloorBytes,
                                                 kGovernorStagingCeilingBytes);
    fields.decode_transient_bytes = clamp_u64(usable / 3ULL, kGovernorDecodeFloorBytes,
                                              kGovernorDecodeCeilingBytes);
    fields.search_index_bytes = clamp_u64(usable / 8ULL, kGovernorSearchFloorBytes,
                                          kGovernorSearchCeilingBytes);
    fields.decompiler_memory_bytes = clamp_u64(usable / 64ULL, kGovernorDecompilerFloorBytes,
                                               kGovernorDecompilerCeilingBytes);
    fields.worker_snapshots_bytes = clamp_u64(usable / 32ULL, kGovernorWorkerFloorBytes,
                                              kGovernorWorkerCeilingBytes);
    fields.xref_arenas_bytes = clamp_u64(usable / 48ULL, kGovernorXrefFloorBytes,
                                         kGovernorXrefCeilingBytes);
    fields.sqlite_caches_bytes = kGovernorSqliteCachesBytes;
    fields.ui_misc_bytes = kGovernorUiMiscBytes;
    fields.process_budget_bytes = usable;
    return fields;
}

}
