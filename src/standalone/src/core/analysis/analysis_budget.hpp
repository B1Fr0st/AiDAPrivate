#pragma once

#include <cstdint>
#include <map>
#include <string_view>

namespace aida::analysis {

using analysis_task_id_t = std::uint64_t;

inline constexpr std::uint64_t analysis_kibibyte = 1024ULL;
inline constexpr std::uint64_t analysis_mebibyte = 1024ULL * analysis_kibibyte;
inline constexpr std::uint64_t analysis_gibibyte = 1024ULL * analysis_mebibyte;
inline constexpr std::uint64_t max_analysis_cancellation_checkpoint_milliseconds = 250ULL;

enum class analysis_resource_kind_t : std::uint8_t {
    none = 0,
    queue_slots = 1,
    worker_slots = 2,
    private_bytes = 3,
    mapped_window_bytes = 4,
    spill_bytes = 5,
    cache_bytes = 6,
    cancellation_checkpoint = 7
};

enum class analysis_resource_error_code_t : std::uint16_t {
    none = 0,
    invalid_budget = 1,
    invalid_task_id = 2,
    duplicate_reservation = 3,
    queue_capacity_exhausted = 4,
    worker_capacity_exhausted = 5,
    reserved_control_capacity_exhausted = 6,
    private_bytes_exhausted = 7,
    mapped_window_bytes_exhausted = 8,
    spill_bytes_exhausted = 9,
    cache_bytes_exhausted = 10,
    arithmetic_overflow = 11,
    reservation_not_found = 12,
    invalid_reservation_state = 13
};

struct analysis_resource_error_t final {
    analysis_resource_error_code_t code = analysis_resource_error_code_t::none;
    analysis_resource_kind_t kind = analysis_resource_kind_t::none;
    std::string_view stable_code = "ok";
    std::uint64_t limit = 0;
    std::uint64_t requested = 0;
    std::uint64_t in_use = 0;

    constexpr bool ok() const noexcept { return code == analysis_resource_error_code_t::none; }
    constexpr explicit operator bool() const noexcept { return ok(); }
};

std::string_view analysis_resource_kind_name(analysis_resource_kind_t kind) noexcept;
std::string_view analysis_resource_error_code_name(analysis_resource_error_code_t code) noexcept;

struct analysis_resource_demand_t final {
    std::uint64_t private_bytes = 0;
    std::uint64_t mapped_window_bytes = 0;
    std::uint64_t spill_bytes = 0;
    std::uint64_t cache_bytes = 0;

    constexpr bool empty() const noexcept
    {
        return private_bytes == 0 && mapped_window_bytes == 0 && spill_bytes == 0 && cache_bytes == 0;
    }
};

struct analysis_resource_usage_t final {
    std::uint64_t private_bytes = 0;
    std::uint64_t mapped_window_bytes = 0;
    std::uint64_t spill_bytes = 0;
    std::uint64_t cache_bytes = 0;
};

struct analysis_budget_t final {
    std::uint32_t max_queued_tasks = 1024;
    std::uint32_t max_worker_slots = 4;
    std::uint32_t reserved_control_worker_slots = 1;
    std::uint32_t cancellation_checkpoint_milliseconds =
        static_cast<std::uint32_t>(max_analysis_cancellation_checkpoint_milliseconds);
    std::uint64_t max_private_bytes = 8ULL * analysis_gibibyte;
    std::uint64_t max_mapped_window_bytes = analysis_gibibyte;
    std::uint64_t max_spill_bytes = analysis_gibibyte;
    std::uint64_t max_cache_bytes = analysis_gibibyte;
};

struct host_memory_envelope_t final {
    std::uint64_t total_phys = 0;
    std::uint64_t avail_phys = 0;
    std::uint64_t reserve_os_bytes = 0;
    std::uint64_t usable_bytes = 0;
};

host_memory_envelope_t host_memory_envelope() noexcept;

struct adaptive_analysis_budget_fields_t final {
    std::uint64_t max_analysis_memory_bytes = 8ULL * analysis_gibibyte;
    std::uint64_t packed_staging_memory_budget_bytes = 768ULL * analysis_mebibyte;
    std::uint64_t packed_generation_quota_bytes = 8ULL * analysis_gibibyte;
    std::uint64_t window_cache_per_file_bytes = 384ULL * analysis_mebibyte;
    std::uint64_t window_cache_global_bytes = analysis_gibibyte;
    std::uint64_t pdb_persistence_total_bytes = 384ULL * analysis_mebibyte;
    std::uint64_t reopen_range_budget_bytes = 1536ULL * analysis_mebibyte;
    bool low_memory = false;
};

adaptive_analysis_budget_fields_t adaptive_analysis_budget_fields(
    const host_memory_envelope_t& envelope) noexcept;

struct governor_subsystem_budget_fields_t final {
    std::uint64_t mapped_windows_bytes = analysis_gibibyte;
    std::uint64_t fact_page_cache_bytes = analysis_gibibyte;
    std::uint64_t resident_facts_bytes = 8ULL * analysis_gibibyte;
    std::uint64_t persistence_staging_bytes = 768ULL * analysis_mebibyte;
    std::uint64_t decode_transient_bytes = 4ULL * analysis_gibibyte;
    std::uint64_t search_index_bytes = 2ULL * analysis_gibibyte;
    std::uint64_t decompiler_memory_bytes = 128ULL * analysis_mebibyte;
    std::uint64_t worker_snapshots_bytes = 256ULL * analysis_mebibyte;
    std::uint64_t xref_arenas_bytes = 256ULL * analysis_mebibyte;
    std::uint64_t sqlite_caches_bytes = 512ULL * analysis_mebibyte;
    std::uint64_t ui_misc_bytes = analysis_gibibyte;
    std::uint64_t process_budget_bytes = 0;
};

governor_subsystem_budget_fields_t governor_subsystem_budget_fields(
    const host_memory_envelope_t& envelope) noexcept;

enum class analysis_reservation_state_t : std::uint8_t {
    queued = 1,
    active = 2
};

struct analysis_budget_snapshot_t final {
    analysis_budget_t budget;
    analysis_resource_usage_t usage;
    std::uint32_t queued_tasks = 0;
    std::uint32_t active_workers = 0;
    std::uint32_t active_control_workers = 0;
    std::uint32_t active_non_control_workers = 0;
    std::uint32_t available_control_worker_slots = 0;
    std::uint32_t available_non_control_worker_slots = 0;
};

analysis_resource_error_t validate_analysis_budget(const analysis_budget_t& budget) noexcept;

class analysis_budget_ledger_t final {
public:
    explicit analysis_budget_ledger_t(analysis_budget_t budget);

    analysis_resource_error_t reserve(analysis_task_id_t task_id, const analysis_resource_demand_t& demand);
    analysis_resource_error_t activate(analysis_task_id_t task_id, bool control_task) noexcept;
    analysis_resource_error_t requeue(analysis_task_id_t task_id) noexcept;
    analysis_resource_error_t release_queued(analysis_task_id_t task_id) noexcept;
    analysis_resource_error_t release_active(analysis_task_id_t task_id) noexcept;
    analysis_budget_snapshot_t snapshot() const noexcept;
    const analysis_budget_t& budget() const noexcept;

private:
    struct reservation_entry_t final {
        analysis_resource_demand_t demand;
        analysis_reservation_state_t state = analysis_reservation_state_t::queued;
        bool control_task = false;
    };

    analysis_resource_error_t release(analysis_task_id_t task_id,
                                      analysis_reservation_state_t expected_state) noexcept;

    analysis_budget_t budget_;
    analysis_resource_usage_t usage_;
    std::uint32_t queued_tasks_ = 0;
    std::uint32_t active_workers_ = 0;
    std::uint32_t active_control_workers_ = 0;
    std::uint32_t active_non_control_workers_ = 0;
    std::map<analysis_task_id_t, reservation_entry_t> reservations_;
};

}
