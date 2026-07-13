#pragma once

#include "../workbench_contracts.h"
#include "../../analysis/decompiler/decompiler_contracts.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aida {
namespace workbench {
namespace pseudocode_document {

inline constexpr std::uint32_t k_pseudocode_document_schema_version = 1;
inline constexpr std::uint32_t k_pseudocode_document_max_line_length = 4096;
inline constexpr std::uint32_t k_pseudocode_document_max_diagnostics = 256;
inline constexpr std::uint32_t k_pseudocode_document_max_cached_documents = 128;
inline constexpr std::uint64_t k_pseudocode_document_default_timeout_ms = 30'000;

enum class pseudocode_error_code_t : std::uint16_t {
    none = 0,
    invalid_argument,
    stale_generation,
    adapter_rejected,
    no_active_request,
    request_in_progress,
    request_cancelled,
    worker_failure,
    cache_miss,
    cache_full,
    stale_result,
    address_not_mapped,
    token_not_mapped,
    resource_exhausted,
    cancelled
};

struct pseudocode_error_t {
    pseudocode_error_code_t code = pseudocode_error_code_t::none;
    std::uint64_t subject = 0;

    constexpr bool ok() const noexcept { return code == pseudocode_error_code_t::none; }
    constexpr explicit operator bool() const noexcept { return ok(); }
};

enum class pseudocode_cache_state_t : std::uint8_t {
    empty = 0,
    requesting = 1,
    cached = 2,
    stale = 3,
    failed = 4,
    cancelled = 5
};

struct pseudocode_request_t {
    aida::analysis::decompiler_entity_key_t entity;
    aida::analysis::decompiler_profile_id_t profile =
        aida::analysis::decompiler_profile_id_t::balanced;
    std::uint64_t workspace_generation = 0;
    std::uint64_t timeout_ms = k_pseudocode_document_default_timeout_ms;
};

struct pseudocode_token_view_t {
    aida::analysis::decompiler_document_token_kind_t kind =
        aida::analysis::decompiler_document_token_kind_t::unknown;
    aida::analysis::decompiler_token_range_t range;
    std::uint64_t ast_node_id = 0;
    std::string_view text;
};

struct pseudocode_line_view_t {
    std::uint32_t line_number = 0;
    std::string_view text;
    std::uint32_t first_token = 0;
    std::uint32_t token_count = 0;
};

struct pseudocode_diagnostic_view_t {
    aida::analysis::decompiler_diagnostic_severity_t severity =
        aida::analysis::decompiler_diagnostic_severity_t::error;
    aida::analysis::decompiler_diagnostic_code_t code =
        aida::analysis::decompiler_diagnostic_code_t::invalid_contract;
    std::string_view localization_key;
    std::string_view message;
    bool has_line = false;
    std::uint32_t line = 0;
    bool retryable = false;
};

struct pseudocode_source_map_view_t {
    std::uint32_t token_begin = 0;
    std::uint32_t token_end = 0;
    std::uint32_t source_line = 0;
    std::string_view source_path;
};

struct pseudocode_address_map_entry_t {
    std::uint64_t address = 0;
    std::uint32_t token_begin = 0;
    std::uint32_t token_end = 0;
    std::uint32_t line_number = 0;
};

struct pseudocode_page_request_t {
    std::uint32_t first_line = 0;
    std::uint32_t line_count = 0;
};

struct pseudocode_page_t {
    std::uint64_t workspace_generation = 0;
    pseudocode_cache_state_t cache_state = pseudocode_cache_state_t::empty;
    std::uint32_t total_lines = 0;
    std::uint32_t first_line = 0;
    std::vector<pseudocode_line_view_t> lines;
    std::vector<pseudocode_token_view_t> tokens;
};

struct pseudocode_selection_t {
    selection_kind_t kind = selection_kind_t::none;
    bool has_address = false;
    std::uint64_t address = 0;
    std::uint32_t token_begin = 0;
    std::uint32_t token_end = 0;
    std::uint32_t line_number = 0;
};

struct pseudocode_profile_info_t {
    aida::analysis::decompiler_profile_id_t profile =
        aida::analysis::decompiler_profile_id_t::balanced;
    std::uint64_t max_wall_clock_ms = 0;
    std::uint64_t max_cpu_ms = 0;
    std::uint64_t max_memory_bytes = 0;
    std::uint64_t elapsed_ms = 0;
};

class pseudocode_cancellation_t {
public:
    virtual ~pseudocode_cancellation_t() = default;
    virtual bool cancelled() const noexcept = 0;
};

class pseudocode_source_adapter_t {
public:
    virtual ~pseudocode_source_adapter_t() = default;
    virtual std::uint64_t current_generation() const noexcept = 0;
    virtual bool generation_current(std::uint64_t generation) const noexcept = 0;
    virtual workbench_error_t request_decompilation(
        const pseudocode_request_t& request,
        std::uint64_t job_id) = 0;
    virtual workbench_error_t cancel_decompilation(std::uint64_t job_id) = 0;
    virtual bool poll_result(std::uint64_t job_id,
                             aida::analysis::decompiler_document_t& output) = 0;
    virtual bool poll_failure(std::uint64_t job_id,
                              std::vector<aida::analysis::decompiler_diagnostic_t>& output) = 0;
    virtual bool job_active(std::uint64_t job_id) const noexcept = 0;
    virtual aida::analysis::decompiler_profile_budget_t profile_budget(
        aida::analysis::decompiler_profile_id_t profile) const noexcept = 0;
};

class pseudocode_navigation_adapter_t {
public:
    virtual ~pseudocode_navigation_adapter_t() = default;
    virtual workbench_error_t resolve_address_to_token(
        std::uint64_t address,
        const aida::analysis::decompiler_document_t& document,
        pseudocode_address_map_entry_t& output) const = 0;
    virtual workbench_error_t resolve_token_to_address(
        std::uint32_t token_begin,
        const aida::analysis::decompiler_document_t& document,
        pseudocode_address_map_entry_t& output) const = 0;
};

struct pseudocode_cached_document_t {
    aida::analysis::decompiler_entity_key_t entity;
    std::uint64_t workspace_generation = 0;
    pseudocode_cache_state_t state = pseudocode_cache_state_t::empty;
    std::uint64_t job_id = 0;
    std::shared_ptr<aida::analysis::decompiler_document_t> document;
    std::vector<aida::analysis::decompiler_diagnostic_t> failure_diagnostics;
    pseudocode_profile_info_t profile_info;
    std::vector<pseudocode_address_map_entry_t> address_map;
    std::uint64_t cached_at_ms = 0;
};

enum class pseudocode_command_kind_t : std::uint8_t {
    request = 0,
    cancel = 1,
    poll = 2,
    page = 3,
    select = 4,
    clear_selection = 5,
    refresh = 6,
    resolve_address = 7,
    resolve_token = 8
};

struct pseudocode_command_t {
    pseudocode_command_kind_t kind = pseudocode_command_kind_t::request;
    std::uint64_t expected_generation = 0;
    pseudocode_request_t request;
    std::uint64_t job_id = 0;
    pseudocode_page_request_t page_request;
    pseudocode_selection_t selection;
    std::uint64_t resolve_address = 0;
    std::uint32_t resolve_token = 0;
};

struct pseudocode_command_result_t {
    pseudocode_error_t error;
    pseudocode_cache_state_t cache_state = pseudocode_cache_state_t::empty;
    pseudocode_page_t page;
    pseudocode_selection_t selection;
    pseudocode_address_map_entry_t address_map_entry;
    std::uint64_t job_id = 0;
    bool changed = false;
};

class pseudocode_document_model_t final {
public:
    explicit pseudocode_document_model_t(
        const pseudocode_source_adapter_t& source,
        const pseudocode_navigation_adapter_t* navigation = nullptr) noexcept;

    pseudocode_error_t request(const pseudocode_request_t& request);
    pseudocode_error_t cancel(std::uint64_t job_id);
    pseudocode_error_t poll(std::uint64_t job_id);
    pseudocode_error_t page(const pseudocode_page_request_t& request,
                            pseudocode_page_t& output) const;
    pseudocode_error_t select(const pseudocode_selection_t& selection);
    void clear_selection() noexcept;
    pseudocode_error_t resolve_address(
        std::uint64_t address,
        pseudocode_address_map_entry_t& output) const;
    pseudocode_error_t resolve_token(
        std::uint32_t token_begin,
        pseudocode_address_map_entry_t& output) const;
    void refresh() noexcept;

    pseudocode_command_result_t execute(const pseudocode_command_t& command);

    pseudocode_cache_state_t cache_state() const noexcept;
    const pseudocode_cached_document_t* cached_document() const noexcept;
    std::uint64_t current_generation() const noexcept;
    bool generation_current(std::uint64_t generation) const noexcept;
    bool is_stale() const noexcept;
    std::uint32_t cached_document_count() const noexcept;
    const pseudocode_selection_t& selection() const noexcept;
    const pseudocode_profile_info_t& profile_info() const noexcept;
    std::vector<pseudocode_diagnostic_view_t> diagnostics() const;

private:
    pseudocode_error_t fail(pseudocode_error_code_t code,
                            std::uint64_t subject = 0) noexcept;
    pseudocode_error_t stale() noexcept;
    void rebuild_address_map();
    void split_lines();
    pseudocode_cached_document_t* find_cached(
        const aida::analysis::decompiler_entity_key_t& entity);
    const pseudocode_cached_document_t* find_cached(
        const aida::analysis::decompiler_entity_key_t& entity) const;
    void evict_oldest();

    const pseudocode_source_adapter_t* source_;
    const pseudocode_navigation_adapter_t* navigation_;
    std::uint64_t bound_generation_;
    std::vector<pseudocode_cached_document_t> cache_;
    std::uint64_t next_job_id_;
    pseudocode_cached_document_t* active_;
    pseudocode_selection_t selection_;
    pseudocode_profile_info_t profile_info_;
    std::vector<std::string> line_storage_;
    std::vector<pseudocode_line_view_t> line_views_;
};

bool pseudocode_page_request_valid(const pseudocode_page_request_t& request) noexcept;
bool pseudocode_selection_valid(const pseudocode_selection_t& selection) noexcept;
bool pseudocode_request_valid(const pseudocode_request_t& request) noexcept;
std::uint32_t count_lines(const std::string& text) noexcept;

}
}
}
