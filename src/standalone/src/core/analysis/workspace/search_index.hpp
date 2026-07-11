#pragma once

#include "analysis_metrics.hpp"
#include "compact_ir.hpp"
#include "function_recovery.hpp"
#include "workspace_types.hpp"
#include "xref_builder.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

enum class search_entity_kind_t : std::uint8_t {
    function = 0,
    symbol,
    string,
    instruction,
    data_candidate,
    switch_dispatch,
    type_candidate
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
    bool truncated = false;
};

class search_index_t final {
public:
    static workspace_result_t<std::shared_ptr<search_index_t>> build(
        std::shared_ptr<const analysis_snapshot_t> snapshot,
        std::vector<data_candidate_record_t> data_candidates,
        std::vector<switch_record_t> switches,
        std::vector<type_candidate_record_t> types,
        std::shared_ptr<analysis_metrics_t> metrics,
        const search_index_limits_t& limits,
        const cancellation_token_t& cancel);

    ~search_index_t();
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
    const std::vector<data_candidate_record_t>& data_candidates() const noexcept;
    const std::vector<switch_record_t>& switches() const noexcept;
    const std::vector<type_candidate_record_t>& types() const noexcept;
    std::uint64_t memory_bytes() const noexcept;
    analysis_metrics_snapshot_t metrics() const noexcept;
    workspace_result_t<search_page_t> find_text(const std::string& text,
        std::uint64_t offset, std::uint32_t limit,
        const cancellation_token_t& cancel) const;
    workspace_result_t<search_page_t> find_opcode(std::uint32_t opcode_id,
        std::uint64_t offset, std::uint32_t limit,
        const cancellation_token_t& cancel) const;
    workspace_result_t<search_page_t> find_immediate(std::uint64_t value,
        std::uint64_t offset, std::uint32_t limit,
        const cancellation_token_t& cancel) const;
    workspace_result_t<search_page_t> find_address_range(const address_t& begin,
        const address_t& end, std::uint64_t offset, std::uint32_t limit,
        const cancellation_token_t& cancel) const;

private:
    struct impl_t;
    explicit search_index_t(std::unique_ptr<impl_t> impl);
    std::unique_ptr<impl_t> impl_;
};

}
