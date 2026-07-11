#pragma once

#include "analysis_workspace.hpp"
#include "decompiler_feedback.hpp"
#include "workspace_database.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis {

struct decompiler_service_limits_t {
    std::size_t max_parallel_contexts = 2;
    std::size_t max_memory_cache_entries = 128;
    std::uint64_t max_memory_cache_bytes = 64ULL << 20;
    std::uint64_t max_function_bytes = 64ULL << 20;
    std::uint64_t max_pseudocode_bytes = 8ULL << 20;
    std::size_t max_annotations = 1U << 20;
    std::size_t max_history_entries = 256;
    std::uint64_t max_result_bytes = 16ULL << 20;
    std::size_t max_cache_key_bytes = 4096;
    std::size_t max_workspace_id_bytes = 256;
};

struct decompiler_request_context_t {
    std::string workspace_id;
    entity_id_t function_id = 0;
    address_t function_address;
    std::optional<address_space_id_t> address_space;
    std::optional<std::uint64_t> generation;
    std::optional<std::uint64_t> overlay_revision;
    std::optional<std::uint64_t> type_revision;
};

struct decompiler_request_t {
    bool use_memory_cache = true;
    bool use_persistent_cache = true;
    std::optional<std::chrono::steady_clock::time_point> deadline;
    std::optional<decompiler_request_context_t> context;
    bool publish_feedback = true;
};

struct decompiler_annotation_t {
    std::uint8_t kind = 0;
    std::size_t start = 0;
    std::size_t end = 0;
    std::uint64_t address = 0;
    std::string name;
};

struct decompiler_result_t {
    binary_id_t binary_id;
    entity_id_t function_id = 0;
    address_t function_address;
    std::string function_name;
    std::string pseudocode;
    std::vector<decompiler_annotation_t> annotations;
    std::vector<std::pair<int, std::uint64_t>> line_to_address;
    std::vector<std::pair<std::string, std::uint64_t>> callees;
    std::string sleigh_id;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    double elapsed_ms = 0.0;
    bool cache_hit = false;
    bool persistent_cache_hit = false;
    std::optional<decompiler_request_context_t> context;
    std::optional<decompiler_feedback_publication_result_t> feedback;
};

struct decompiler_history_entry_t {
    entity_id_t function_id = 0;
    address_t function_address;
    std::string function_name;
    std::uint64_t generation = 0;
    std::uint64_t overlay_revision = 0;
    std::uint64_t completed_utc_ms = 0;
};

struct decompiler_service_snapshot_t {
    std::uint64_t requests = 0;
    std::uint64_t completed = 0;
    std::uint64_t failed = 0;
    std::uint64_t cancelled = 0;
    std::uint64_t memory_cache_hits = 0;
    std::uint64_t persistent_cache_hits = 0;
    std::uint64_t cache_misses = 0;
    std::uint64_t evictions = 0;
    std::uint64_t memory_cache_bytes = 0;
    std::size_t memory_cache_entries = 0;
    std::size_t active_contexts = 0;
    bool accepting = false;
    std::uint64_t feedback_publications = 0;
    std::uint64_t feedback_rejections = 0;
    std::uint64_t feedback_no_change = 0;
};

class decompiler_service_t final : public workspace_lifecycle_participant_t,
                                   public std::enable_shared_from_this<decompiler_service_t> {
public:
    struct state_t;

    static workspace_result_t<std::shared_ptr<decompiler_service_t>> create(
        std::shared_ptr<analysis_workspace_t> workspace,
        std::shared_ptr<workspace_database_t> database,
        workspace_database_versions_t versions,
        decompiler_service_limits_t limits = {});
    static workspace_result_t<std::shared_ptr<decompiler_service_t>> create(
        std::shared_ptr<analysis_workspace_t> workspace,
        std::shared_ptr<workspace_database_t> database,
        workspace_database_versions_t versions,
        std::shared_ptr<decompiler_feedback_model_t> feedback,
        decompiler_service_limits_t limits);

    ~decompiler_service_t() override;
    decompiler_service_t(const decompiler_service_t&) = delete;
    decompiler_service_t& operator=(const decompiler_service_t&) = delete;

    workspace_result_t<decompiler_result_t> decompile(
        const address_t& address,
        decompiler_request_t request = {},
        const cancellation_token_t& cancel = {});
    workspace_result_t<decompiler_result_t> decompile(
        const decompiler_request_t& request,
        const cancellation_token_t& cancel = {});
    workspace_result_t<void> invalidate(
        std::optional<address_t> function = {},
        const cancellation_token_t& cancel = {});

    decompiler_service_snapshot_t snapshot() const;
    std::vector<decompiler_history_entry_t> history() const;
    std::shared_ptr<decompiler_feedback_model_t> feedback_model() const;

    void request_cancel() noexcept override;
    workspace_result_t<void> drain(
        std::chrono::steady_clock::time_point deadline) override;

private:
    explicit decompiler_service_t(std::shared_ptr<state_t> state);
    std::shared_ptr<state_t> state_;
};

}
