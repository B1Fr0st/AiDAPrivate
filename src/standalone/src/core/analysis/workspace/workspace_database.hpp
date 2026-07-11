#pragma once

#include "analysis_metrics.hpp"
#include "analysis_workspace.hpp"
#include "persistence_queue.hpp"
#include "search_index.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace aida::analysis {

inline constexpr std::uint32_t workspace_database_schema_version = 8;
inline constexpr std::uint32_t workspace_instruction_blob_version = 2;
inline constexpr std::uint64_t workspace_decompiler_cache_record_limit = 64ULL << 20;
inline constexpr std::uint64_t workspace_search_blob_limit = 512ULL << 20;

struct workspace_database_versions_t {
    std::string engine_version;
    std::string specification_version;
    std::string analysis_settings_hash;
};

struct workspace_database_options_t {
    std::shared_ptr<const workspace_identity_t> identity;
    workspace_database_versions_t versions;
    persistence_queue_limits_t queue_limits;
    std::uint32_t busy_timeout_ms = 2500;
    std::uint32_t candidate_operation_timeout_ms = 5000;
    std::uint32_t passive_checkpoint_pages = 4096;
    std::uint64_t instruction_chunk_records = 4096;
    std::uint64_t max_persisted_fact_records = 200000000;
};

struct decompiler_cache_key_t {
    binary_id_t binary_id;
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t architecture_mode = architecture_mode_t::unknown;
    abi_id_t abi = abi_id_t::unknown;
    endian_t endian = endian_t::little;
    std::string engine_version;
    std::uint32_t schema_version = workspace_database_schema_version;
    std::string specification_version;
    std::string analysis_settings_hash;
    entity_id_t function_id = 0;
    std::uint64_t function_rva = 0;
    sha256_digest_t function_content_hash;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::uint64_t generation = 0;

    std::string canonical() const;
};

struct decompiler_cache_record_t {
    decompiler_cache_key_t key;
    std::string function_name;
    std::string result_json;
    std::uint64_t created_utc_ms = 0;
    std::uint64_t last_access_utc_ms = 0;
    std::uint64_t result_bytes = 0;
};

struct workspace_database_snapshot_t {
    std::string path;
    std::uint32_t schema_version = 0;
    std::uint64_t persisted_generation = 0;
    std::uint64_t persisted_analysis_revision = 0;
    std::uint64_t persisted_overlay_revision = 0;
    std::uint64_t cache_invalidations = 0;
    std::uint64_t database_bytes = 0;
    std::uint64_t wal_bytes = 0;
    std::uint64_t last_commit_logical_bytes = 0;
    std::uint64_t cumulative_logical_bytes = 0;
    std::uint64_t last_commit_rows = 0;
    std::uint64_t cumulative_rows = 0;
    std::uint64_t last_commit_page_write_bytes = 0;
    std::uint64_t cumulative_page_write_bytes = 0;
    std::uint64_t last_commit_elapsed_us = 0;
    std::uint64_t candidate_generation = 0;
    std::uint64_t candidate_analysis_revision = 0;
    std::uint64_t candidate_overlay_revision = 0;
    bool candidate_pending = false;
    bool open = false;
};

struct persisted_search_products_t {
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::vector<data_candidate_record_t> data_candidates;
    std::vector<switch_record_t> switches;
    std::vector<type_candidate_record_t> types;
    std::uint32_t search_index_blob_version = 0;
    std::vector<std::uint8_t> search_index_blob;
};

class workspace_database_t;

class workspace_persistence_candidate_t final {
public:
    const std::string& token() const noexcept;
    std::uint64_t generation() const noexcept;
    std::uint64_t analysis_revision() const noexcept;
    std::uint64_t overlay_revision() const noexcept;

    workspace_result_t<void> finalize(
        const cancellation_token_t& cancel = {}) const;
    workspace_result_t<void> discard(
        const cancellation_token_t& cancel = {}) const;

private:
    workspace_persistence_candidate_t(
        std::weak_ptr<workspace_database_t> database,
        std::string token,
        std::uint64_t generation,
        std::uint64_t analysis_revision,
        std::uint64_t overlay_revision);

    std::weak_ptr<workspace_database_t> database_;
    std::string token_;
    std::uint64_t generation_ = 0;
    std::uint64_t analysis_revision_ = 0;
    std::uint64_t overlay_revision_ = 0;

    friend class workspace_database_t;
};

class workspace_database_t final : public workspace_lifecycle_participant_t,
                                   public std::enable_shared_from_this<workspace_database_t> {
public:
    struct connection_state_t;

    static workspace_result_t<std::shared_ptr<workspace_database_t>>
        open(workspace_database_options_t options);

    ~workspace_database_t() override;
    workspace_database_t(const workspace_database_t&) = delete;
    workspace_database_t& operator=(const workspace_database_t&) = delete;

    const std::string& path() const noexcept;
    const workspace_database_options_t& options() const noexcept;
    std::shared_ptr<persistence_queue_t> queue() const noexcept;

    persistence_ticket_t persist_snapshot(
        std::shared_ptr<const analysis_snapshot_t> snapshot,
        std::string analysis_settings_json,
        std::string analysis_metrics_json,
        cancellation_token_t cancel = {});
    persistence_ticket_t persist_snapshot(
        std::shared_ptr<const analysis_snapshot_t> snapshot,
        persisted_search_products_t search_products,
        std::string analysis_settings_json,
        std::string analysis_metrics_json,
        cancellation_token_t cancel = {});

    workspace_result_t<std::shared_ptr<const analysis_snapshot_t>> load_snapshot(
        std::shared_ptr<const pe_image_t> image,
        const cancellation_token_t& cancel = {}) const;
    workspace_result_t<std::shared_ptr<const analysis_snapshot_t>> load_snapshot(
        std::shared_ptr<const workspace_image_t> image,
        std::shared_ptr<const pe_image_t> pe_adapter,
        const cancellation_token_t& cancel = {}) const;
    workspace_result_t<persisted_search_products_t> load_search_products(
        std::uint64_t expected_generation,
        std::uint64_t expected_analysis_revision,
        std::uint64_t expected_overlay_revision,
        const cancellation_token_t& cancel = {}) const;

    persistence_ticket_t store_decompiler_cache(
        decompiler_cache_record_t record,
        cancellation_token_t cancel = {});
    workspace_result_t<std::optional<decompiler_cache_record_t>>
        load_decompiler_cache(const decompiler_cache_key_t& key,
                              const cancellation_token_t& cancel = {}) const;
    persistence_ticket_t invalidate_decompiler_cache(
        std::optional<std::uint64_t> function_rva,
        std::optional<std::uint64_t> minimum_overlay_revision,
        cancellation_token_t cancel = {});
    persistence_ticket_t checkpoint(bool truncate, cancellation_token_t cancel = {});

    workspace_database_snapshot_t snapshot() const;

    void request_cancel() noexcept override;
    workspace_result_t<void>
        drain(std::chrono::steady_clock::time_point deadline) override;

private:
    using writer_operation_t =
        std::function<workspace_result_t<void>(sqlite3*, const cancellation_token_t&)>;
    using reader_operation_t = std::function<workspace_result_t<void>(sqlite3*)>;

    workspace_database_t(workspace_database_options_t options,
                         std::shared_ptr<connection_state_t> state,
                         std::shared_ptr<persistence_queue_t> queue);

    persistence_ticket_t enqueue_write(std::string label, writer_operation_t operation,
                                       cancellation_token_t cancel);
    workspace_result_t<void> with_reader(const reader_operation_t& operation) const;
    workspace_result_t<void> finalize_candidate(
        const workspace_persistence_candidate_t& candidate,
        const cancellation_token_t& cancel);
    workspace_result_t<void> discard_candidate(
        const workspace_persistence_candidate_t& candidate,
        const cancellation_token_t& cancel);

    workspace_database_options_t options_;
    std::shared_ptr<connection_state_t> state_;
    std::shared_ptr<persistence_queue_t> queue_;

    friend class overlay_journal_t;
    friend class workspace_persistence_candidate_t;
};

}
