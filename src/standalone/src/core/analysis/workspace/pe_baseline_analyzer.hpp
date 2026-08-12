#pragma once

#include "analysis_metrics.hpp"
#include "analysis_workspace.hpp"
#include "arch_decoder.hpp"
#include "data_discovery.hpp"
#include "function_recovery.hpp"
#include "search_index.hpp"
#include "string_discovery.hpp"
#include "symbol_type_candidates.hpp"
#include "workspace_types.hpp"
#include "xref_builder.hpp"
#include "../call_graph_builder.hpp"
#include "../tile_decode_orchestrator.hpp"

#include <chrono>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace aida::analysis {

struct baseline_analysis_settings_t {
    pe_parse_limits_t pe_limits;
    tile_decode_orchestrator_limits_t tile_decode_limits;
    function_recovery_limits_t function_limits;
    call_graph_builder_limits_t call_graph_limits;
    data_discovery_limits_t data_limits;
    xref_build_limits_t xref_limits;
    string_discovery_limits_t string_limits;
    symbol_type_candidate_limits_t symbol_type_limits;
    search_index_limits_t search_limits;
    std::uint64_t max_seed_count = 1ULL << 26;
    std::uint64_t max_decode_queue = 1ULL << 26;
    std::uint64_t max_decoded_instructions = 1ULL << 28;
    std::uint64_t max_coverage_spans = 1ULL << 28;
    std::uint64_t max_analysis_memory_bytes = 16ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t decode_read_window_bytes = 4ULL * 1024ULL * 1024ULL;
    std::uint64_t string_read_window_bytes = 4ULL * 1024ULL * 1024ULL;
    std::uint64_t max_string_scan_bytes = 1ULL << 36;
    std::uint64_t max_string_value_bytes = 1ULL << 20;
    std::uint64_t max_strings = 1ULL << 25;
    std::uint32_t decode_worker_lanes = 0;
    std::uint32_t fact_pass_worker_budget = 0;
    std::uint32_t max_trace_instructions = 1U << 20;
    std::uint32_t cancellation_check_interval = 256;
    std::uint32_t string_cancellation_interval_bytes = 64U * 1024U;
    std::uint32_t minimum_string_length = 4;
    bool scan_utf8 = true;
    bool scan_utf16 = true;
    int task_priority = 3;
    bool enable_parallel_fact_passes = true;
    bool overlap_strings_with_decode = true;

    workspace_result_t<void> validate() const;
    std::string canonical_json() const;
};

class pe_baseline_analyzer_t final : public std::enable_shared_from_this<pe_baseline_analyzer_t> {
public:
    static workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>> create(
        std::shared_ptr<analysis_workspace_t> workspace,
        baseline_analysis_settings_t settings,
        std::uint64_t expected_generation,
        std::uint64_t expected_analysis_revision,
        std::optional<std::chrono::steady_clock::time_point> deadline);

    ~pe_baseline_analyzer_t();
    pe_baseline_analyzer_t(const pe_baseline_analyzer_t&) = delete;
    pe_baseline_analyzer_t& operator=(const pe_baseline_analyzer_t&) = delete;

    std::uint32_t decode_worker_budget() const noexcept;
    std::uint64_t expected_generation() const noexcept;
    std::shared_ptr<analysis_metrics_t> metrics() const noexcept;
    workspace_result_t<void> parse_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> seed_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> decode_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> decode_merge_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> data_image_scan_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> data_discovery_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> function_recovery_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> functions_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> cfg_calls_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> xrefs_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> publish_xrefs_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> strings_data_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> metadata_symbols_types_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> search_index_instructions_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> search_index_entities_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> search_index_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> persistence_stage_decode_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> persistence_stage_functions_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> persistence_stage_metadata_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> persistence_submit_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> persistence_commit_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    workspace_result_t<void> publish_ready_phase(
        const std::atomic<bool>& runtime_cancel_requested);
    void request_cancel() noexcept;
    void report_failure(const workspace_error_t& error) noexcept;

    struct impl_t;

private:
    explicit pe_baseline_analyzer_t(std::unique_ptr<impl_t> impl);
    std::unique_ptr<impl_t> impl_;
};

}
