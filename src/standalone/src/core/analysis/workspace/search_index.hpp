#pragma once

#include "analysis_metrics.hpp"
#include "compact_ir.hpp"
#include "function_recovery.hpp"
#include "workspace_types.hpp"
#include "xref_builder.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <functional>

namespace aida::analysis {

using search_deadline_t = std::optional<std::chrono::steady_clock::time_point>;

enum class search_entity_kind_t : std::uint8_t {
    function = 0,
    symbol,
    string,
    instruction,
    data_candidate,
    switch_dispatch,
    type_candidate,
    byte_sequence
};

enum class type_candidate_kind_t : std::uint8_t {
    function_prototype = 0,
    import_prototype,
    global_object,
    pointer_object
};

struct type_candidate_record_t {
    entity_id_t id = 0;
    address_t address;
    type_candidate_kind_t kind = type_candidate_kind_t::function_prototype;
    std::string display_name;
    std::string canonical_type;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    bool explicitly_unknown = true;
};

struct search_index_limits_t {
    std::uint64_t max_entries = 1ULL << 27;
    std::uint64_t max_trigram_postings = 1ULL << 30;
    std::uint64_t max_indexed_text_bytes = 1ULL << 34;
    std::uint64_t max_index_bytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint32_t max_query_bytes = 1U << 20;
    std::uint32_t max_results_per_query = 100000;
    std::uint32_t cancellation_check_interval = 4096;
};

struct search_generation_identity_t {
    binary_id_t binary_id;
    sha256_digest_t load_profile_hash;
    std::optional<sha256_digest_t> provider_content_hash;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::uint64_t provider_size = 0;

    bool valid() const noexcept;
    friend bool operator==(const search_generation_identity_t& lhs,
                           const search_generation_identity_t& rhs) noexcept;
    friend bool operator!=(const search_generation_identity_t& lhs,
                           const search_generation_identity_t& rhs) noexcept;
};

struct search_index_size_t {
    std::uint64_t memory_bytes = 0;
    std::uint64_t source_text_bytes = 0;
    std::uint64_t referenced_text_bytes = 0;
    std::uint64_t unique_text_bytes = 0;
    std::uint64_t record_count = 0;
    std::uint64_t text_reference_count = 0;
    std::uint64_t address_reference_count = 0;
    std::uint64_t entity_reference_count = 0;
    std::uint64_t trigram_count = 0;
    std::uint64_t trigram_posting_count = 0;
    std::uint64_t string_count = 0;
};

struct search_record_view_t {
    search_entity_kind_t kind = search_entity_kind_t::symbol;
    entity_id_t entity_id = 0;
    address_t address;
    std::string_view text;
    std::uint64_t numeric_value = 0;
    std::uint32_t auxiliary_flags = 0;
};

struct search_hit_t {
    search_entity_kind_t kind = search_entity_kind_t::symbol;
    entity_id_t entity_id = 0;
    address_t address;
    std::string text;
    std::uint64_t numeric_value = 0;
};

struct search_page_t {
    std::vector<search_hit_t> hits;
    std::uint64_t total = 0;
    std::uint64_t next_offset = 0;
    std::uint64_t candidates_examined = 0;
    std::uint64_t cancellation_checks = 0;
    bool truncated = false;
};

struct search_instruction_filter_t {
    std::optional<std::uint32_t> opcode_id;
    std::optional<std::uint64_t> immediate;
    std::uint32_t required_flow_flags = 0;
    std::uint32_t forbidden_flow_flags = 0;
    std::optional<address_t> begin;
    std::optional<address_t> end;
};

struct search_entity_filter_t {
    std::optional<search_entity_kind_t> kind;
    std::optional<entity_id_t> entity_id;
};

class search_index_t;
class query_index_t;

class search_generation_handle_t final {
public:
    search_generation_handle_t() = default;

    bool valid() const noexcept;
    explicit operator bool() const noexcept;
    const search_generation_identity_t& identity() const noexcept;
    const search_index_t* get() const noexcept;
    const std::shared_ptr<const search_index_t>& shared_index() const noexcept;

private:
    search_generation_handle_t(search_generation_identity_t identity,
                               std::shared_ptr<const search_index_t> index);

    search_generation_identity_t identity_;
    std::shared_ptr<const search_index_t> index_;

    friend class search_index_t;
};

class search_index_t final : public std::enable_shared_from_this<search_index_t> {
public:
    using serialized_sink_t = std::function<workspace_result_t<void>(
        const std::uint8_t*, std::size_t)>;
    static constexpr std::uint32_t serialized_version = 1;

    static workspace_result_t<std::shared_ptr<search_index_t>> build(
        std::shared_ptr<const analysis_snapshot_t> snapshot,
        std::vector<data_candidate_record_t> data_candidates,
        std::vector<switch_record_t> switches,
        std::vector<type_candidate_record_t> types,
        std::shared_ptr<analysis_metrics_t> metrics,
        const search_index_limits_t& limits,
        const cancellation_token_t& cancel);

    static workspace_result_t<std::shared_ptr<search_index_t>> restore(
        std::shared_ptr<const analysis_snapshot_t> snapshot,
        std::vector<data_candidate_record_t> data_candidates,
        std::vector<switch_record_t> switches,
        std::vector<type_candidate_record_t> types,
        std::shared_ptr<analysis_metrics_t> metrics,
        const search_index_limits_t& limits,
        const std::vector<std::uint8_t>& serialized,
        const cancellation_token_t& cancel);

    ~search_index_t();
    search_index_t(const search_index_t&) = delete;
    search_index_t& operator=(const search_index_t&) = delete;

    search_generation_identity_t identity() const noexcept;
    search_generation_handle_t generation_handle() const;
    std::uint64_t generation() const noexcept;
    const binary_id_t& binary_id() const noexcept;
    const sha256_digest_t& load_profile_hash() const noexcept;
    std::uint64_t analysis_revision() const noexcept;
    std::uint64_t overlay_revision() const noexcept;
    bool matches(const std::shared_ptr<const analysis_snapshot_t>& snapshot) const noexcept;
    bool matches(std::uint64_t generation, std::uint64_t analysis_revision,
                 std::uint64_t overlay_revision) const noexcept;
    bool matches(const binary_id_t& binary_id, const sha256_digest_t& load_profile_hash,
                 std::uint64_t generation, std::uint64_t analysis_revision,
                 std::uint64_t overlay_revision) const noexcept;
    workspace_result_t<void> verify_identity(const binary_id_t& expected_binary_id,
        const sha256_digest_t& expected_load_profile_hash) const;
    const search_index_limits_t& limits() const noexcept;
    const std::vector<data_candidate_record_t>& data_candidates() const noexcept;
    const std::vector<switch_record_t>& switches() const noexcept;
    const std::vector<type_candidate_record_t>& types() const noexcept;
    std::uint64_t memory_bytes() const noexcept;
    workspace_result_t<std::uint64_t> serialized_size(
        const cancellation_token_t& cancel = {}) const;
    workspace_result_t<void> serialize_to(
        const serialized_sink_t& sink,
        const cancellation_token_t& cancel = {}) const;
    search_index_size_t size_accounting() const noexcept;
    analysis_metrics_snapshot_t metrics() const noexcept;
    std::size_t record_count() const noexcept;
    std::size_t text_record_count() const noexcept;
    address_t file_offset_address(std::uint64_t offset) const noexcept;
    std::optional<search_record_view_t> record(std::size_t index) const noexcept;
    std::optional<search_record_view_t> text_record(std::size_t index) const noexcept;
    workspace_result_t<search_page_t> find_text(const std::string& text,
        std::uint64_t offset, std::uint32_t limit,
        const cancellation_token_t& cancel, search_deadline_t deadline = {}) const;
    workspace_result_t<search_page_t> find_opcode(std::uint32_t opcode_id,
        std::uint64_t offset, std::uint32_t limit,
        const cancellation_token_t& cancel, search_deadline_t deadline = {}) const;
    workspace_result_t<search_page_t> find_immediate(std::uint64_t value,
        std::uint64_t offset, std::uint32_t limit,
        const cancellation_token_t& cancel, search_deadline_t deadline = {}) const;
    workspace_result_t<search_page_t> find_instruction(
        const search_instruction_filter_t& filter, std::uint64_t offset,
        std::uint32_t limit, const cancellation_token_t& cancel,
        search_deadline_t deadline = {}) const;
    workspace_result_t<search_page_t> find_entity(
        const search_entity_filter_t& filter, std::uint64_t offset,
        std::uint32_t limit, const cancellation_token_t& cancel,
        search_deadline_t deadline = {}) const;
    workspace_result_t<search_page_t> find_address_range(const address_t& begin,
        const address_t& end, std::uint64_t offset, std::uint32_t limit,
        const cancellation_token_t& cancel, search_deadline_t deadline = {}) const;

private:
    struct impl_t;
    explicit search_index_t(std::unique_ptr<impl_t> impl);
    const std::array<std::uint64_t, 2>& cursor_integrity_key() const noexcept;
    std::unique_ptr<impl_t> impl_;

    friend class query_index_t;
};

}
