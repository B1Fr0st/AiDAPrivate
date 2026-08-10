#pragma once

#include "../workbench_contracts.h"
#include "../../analysis/decompiler/decompiler_contracts.hpp"
#include "../../analysis/decompiler/managed_entity_binding.hpp"

#include <cstdint>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace aida {
namespace workbench {
namespace pseudocode_document {

inline constexpr std::uint32_t k_pseudocode_document_schema_version = 2;
inline constexpr std::uint32_t k_pseudocode_document_max_line_length = 4096;
inline constexpr std::uint32_t k_pseudocode_document_max_page_lines = 1024;
inline constexpr std::uint32_t k_pseudocode_document_max_diagnostics = 256;
inline constexpr std::uint32_t k_pseudocode_document_max_cached_documents = 128;
inline constexpr std::uint32_t k_pseudocode_document_max_tokens = 1U << 20;
inline constexpr std::uint32_t k_pseudocode_document_max_source_maps = 1U << 20;
inline constexpr std::uint32_t k_pseudocode_document_max_ast_nodes = 1U << 20;
inline constexpr std::uint32_t k_pseudocode_document_max_lines = 1U << 20;
inline constexpr std::uint64_t k_pseudocode_document_max_rendered_bytes = 64ULL << 20;
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
    std::optional<aida::analysis::generation_bound_decompiler_entity_t> binding;
    aida::analysis::decompiler_profile_id_t profile =
        aida::analysis::decompiler_profile_id_t::balanced;
    std::uint64_t workspace_generation = 0;
    std::uint64_t timeout_ms = k_pseudocode_document_default_timeout_ms;
};

struct pseudocode_token_view_t {
    aida::analysis::decompiler_document_token_kind_t kind =
        aida::analysis::decompiler_document_token_kind_t::unknown;
    std::uint32_t token_index = 0;
    aida::analysis::decompiler_token_range_t range;
    std::uint64_t ast_node_id = 0;
    std::string text;
};

struct pseudocode_line_view_t {
    std::uint32_t line_number = 0;
    std::uint32_t text_begin = 0;
    std::uint32_t text_end = 0;
    std::string text;
    std::uint32_t first_token = 0;
    std::uint32_t token_count = 0;
};

struct pseudocode_diagnostic_view_t {
    aida::analysis::decompiler_diagnostic_severity_t severity =
        aida::analysis::decompiler_diagnostic_severity_t::error;
    aida::analysis::decompiler_diagnostic_code_t code =
        aida::analysis::decompiler_diagnostic_code_t::invalid_contract;
    std::string localization_key;
    std::string message;
    std::optional<aida::analysis::source_coordinate_t> coordinate;
    bool has_line = false;
    std::uint32_t line = 0;
    std::uint8_t confidence = 0;
    bool retryable = false;
    std::uint32_t ordinal = 0;
};

struct pseudocode_source_map_view_t {
    std::uint32_t token_begin = 0;
    std::uint32_t token_end = 0;
    bool has_address = false;
    std::uint64_t address = 0;
    std::uint64_t address_extent = 0;
    std::optional<aida::analysis::decompiler_address_range_t> address_range;
    aida::analysis::source_coordinate_t coordinate;
    bool has_source = false;
    std::uint32_t source_line = 0;
    std::uint32_t source_column = 0;
    std::uint32_t source_last_line = 0;
    std::uint32_t source_last_column = 0;
    std::string source_path;
};

struct pseudocode_address_map_entry_t {
    std::uint64_t address = 0;
    std::uint64_t extent = 0;
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
    std::vector<pseudocode_source_map_view_t> source_maps;
    std::vector<pseudocode_diagnostic_view_t> diagnostics;
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

struct pseudocode_render_evidence_bundle_t {
    std::shared_ptr<const aida::analysis::decompiler_render_evidence_t> evidence;
    std::shared_ptr<const aida::analysis::type_graph_t> type_graph;
};

struct pseudocode_resolve_result_t {
    workbench_error_t error{};
    pseudocode_request_t request{};
};

class pseudocode_source_adapter_t {
public:
    virtual ~pseudocode_source_adapter_t() = default;
    virtual std::uint64_t current_generation() const noexcept = 0;
    virtual bool generation_current(std::uint64_t generation) const noexcept = 0;
    virtual bool binding_current(
        const std::optional<aida::analysis::generation_bound_decompiler_entity_t>&
            binding) const noexcept
    {
        return !binding || generation_current(binding->generation);
    }
    virtual pseudocode_render_evidence_bundle_t render_evidence(
        const pseudocode_request_t& request) const
    {
        static_cast<void>(request);
        return {};
    }
    virtual workbench_error_t resolve_request(
        std::uint64_t function_address,
        aida::analysis::decompiler_profile_id_t profile,
        std::uint64_t timeout_ms,
        pseudocode_request_t& output) const
    {
        static_cast<void>(profile);
        static_cast<void>(timeout_ms);
        output = {};
        return {workbench_error_code_t::adapter_rejected, function_address};
    }
    virtual workbench_error_t resolve_request(
        const aida::analysis::decompiler_entity_locator_t& locator,
        aida::analysis::decompiler_profile_id_t profile,
        std::uint64_t timeout_ms,
        pseudocode_request_t& output) const
    {
        if (!locator.address || locator.token || locator.artifact_ordinal ||
            locator.expected_kind) {
            output = {};
            return {workbench_error_code_t::adapter_rejected, 0};
        }
        return resolve_request(*locator.address, profile, timeout_ms, output);
    }
    virtual bool resolve_request_async_supported() const noexcept { return false; }
    virtual workbench_error_t submit_resolve_request(
        aida::analysis::decompiler_entity_locator_t locator,
        aida::analysis::decompiler_profile_id_t profile,
        std::uint64_t timeout_ms, std::uint64_t resolve_ticket,
        bool force_refresh)
    {
        static_cast<void>(locator);
        static_cast<void>(profile);
        static_cast<void>(timeout_ms);
        static_cast<void>(force_refresh);
        return {workbench_error_code_t::adapter_rejected, resolve_ticket};
    }
    virtual bool poll_resolve_request(std::uint64_t resolve_ticket,
                                      pseudocode_resolve_result_t& output)
    {
        static_cast<void>(resolve_ticket);
        static_cast<void>(output);
        return false;
    }
    virtual void cancel_resolve_request(std::uint64_t resolve_ticket) noexcept
    {
        static_cast<void>(resolve_ticket);
    }
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
    std::optional<aida::analysis::generation_bound_decompiler_entity_t> binding;
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
    resolve_token = 8,
    rename_local = 9
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
    std::string rename_old_name;
    std::string rename_new_name;
};

struct pseudocode_command_result_t {
    pseudocode_error_t error;
    pseudocode_cache_state_t cache_state = pseudocode_cache_state_t::empty;
    pseudocode_page_t page;
    pseudocode_selection_t selection;
    pseudocode_address_map_entry_t address_map_entry;
    std::uint64_t job_id = 0;
    std::uint64_t nodes_renamed = 0;
    bool changed = false;
};

class pseudocode_document_model_t final {
public:
    struct pending_resolution_t {
        std::uint64_t ticket = 0;
        aida::analysis::decompiler_entity_locator_t locator;
        aida::analysis::decompiler_profile_id_t profile =
            aida::analysis::decompiler_profile_id_t::balanced;
        std::uint64_t timeout_ms = 0;
        std::uint64_t workspace_generation = 0;
        bool force_refresh = false;
    };

    struct resolution_outcome_t {
        std::uint64_t ticket = 0;
        bool submitted_request = false;
        pseudocode_error_t error{};
        pseudocode_request_t request{};
    };

    explicit pseudocode_document_model_t(
        pseudocode_source_adapter_t& source,
        const pseudocode_navigation_adapter_t* navigation = nullptr) noexcept;

    pseudocode_error_t request_async(
        const aida::analysis::decompiler_entity_locator_t& locator,
        aida::analysis::decompiler_profile_id_t profile,
        std::uint64_t timeout_ms, bool force_refresh,
        std::uint64_t& ticket_out);
    std::vector<resolution_outcome_t> drain_resolutions();
    bool resolution_pending(std::uint64_t ticket) const noexcept;
    pseudocode_error_t cancel_resolution(std::uint64_t ticket);

    pseudocode_error_t resolve_request(
        std::uint64_t function_address,
        aida::analysis::decompiler_profile_id_t profile,
        std::uint64_t timeout_ms,
        pseudocode_request_t& output) const;
    pseudocode_error_t resolve_request(
        const aida::analysis::decompiler_entity_locator_t& locator,
        aida::analysis::decompiler_profile_id_t profile,
        std::uint64_t timeout_ms,
        pseudocode_request_t& output) const;
    pseudocode_error_t request(const pseudocode_request_t& request);
    pseudocode_error_t request(const pseudocode_request_t& request,
                               bool force_refresh);
    pseudocode_error_t activate(
        const aida::analysis::decompiler_entity_key_t& entity);
    pseudocode_error_t activate(const pseudocode_request_t& request);
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
    pseudocode_error_t apply_local_rename(
        const std::string& old_name,
        const std::string& new_name,
        std::uint64_t& nodes_renamed);
    void refresh() noexcept;

    pseudocode_command_result_t execute(const pseudocode_command_t& command);

    pseudocode_cache_state_t cache_state() const noexcept;
    const pseudocode_cached_document_t* cached_document() const noexcept;
    const pseudocode_cached_document_t* cached_document(
        const aida::analysis::decompiler_entity_key_t& entity) const noexcept;
    const pseudocode_cached_document_t* cached_document(
        const pseudocode_request_t& request) const noexcept;
    std::uint64_t current_generation() const noexcept;
    bool generation_current(std::uint64_t generation) const noexcept;
    bool is_stale() const noexcept;
    bool has_pending_requests() const noexcept;
    std::uint32_t cached_document_count() const noexcept;
    const pseudocode_selection_t& selection() const noexcept;
    const pseudocode_profile_info_t& profile_info() const noexcept;
    std::vector<pseudocode_diagnostic_view_t> diagnostics() const;
    std::vector<pseudocode_source_map_view_t> source_maps() const;

private:
    pseudocode_error_t fail(pseudocode_error_code_t code,
                            std::uint64_t subject = 0) const noexcept;
    pseudocode_error_t stale() const noexcept;
    bool lease_current(std::uint64_t generation) const noexcept;
    bool entry_current(
        const pseudocode_cached_document_t& entry) const noexcept;
    pseudocode_error_t validate_document(
        const aida::analysis::decompiler_document_t& document,
        const pseudocode_cached_document_t& cache_entry) const;
    void rebuild_address_map();
    void split_lines();
    void ensure_active_views_current();
    void invalidate_line_views() noexcept;
    void bump_diagnostics_revision() noexcept;
    pseudocode_cached_document_t* find_cached(
        const aida::analysis::decompiler_entity_key_t& entity);
    const pseudocode_cached_document_t* find_cached(
        const aida::analysis::decompiler_entity_key_t& entity) const;
    pseudocode_cached_document_t* find_cached(
        const pseudocode_request_t& request);
    const pseudocode_cached_document_t* find_cached(
        const pseudocode_request_t& request) const;
    bool evict_oldest();

    pseudocode_source_adapter_t* source_;
    const pseudocode_navigation_adapter_t* navigation_;
    std::uint64_t bound_generation_;
    std::list<pseudocode_cached_document_t> cache_;
    std::uint64_t next_job_id_;
    pseudocode_cached_document_t* active_;
    pseudocode_selection_t selection_;
    std::vector<pseudocode_line_view_t> line_views_;
    const void* line_views_key_ = nullptr;
    const pseudocode_cached_document_t* line_views_owner_ = nullptr;
    std::uint64_t diagnostics_revision_ = 0;
    struct diagnostics_cache_key_t {
        const pseudocode_cached_document_t* owner = nullptr;
        pseudocode_cache_state_t state = pseudocode_cache_state_t::empty;
        const void* document = nullptr;
        std::uint64_t revision = 0;
    };
    mutable diagnostics_cache_key_t diagnostics_key_{};
    mutable std::vector<pseudocode_diagnostic_view_t> diagnostics_cache_;
    std::vector<pending_resolution_t> pending_resolutions_;
    std::unordered_map<std::uint64_t, pseudocode_resolve_result_t> completed_resolutions_;
    std::uint64_t next_resolve_ticket_ = 1;
    bool has_pending_resolutions_ = false;
};

bool pseudocode_page_request_valid(const pseudocode_page_request_t& request) noexcept;
bool pseudocode_selection_valid(const pseudocode_selection_t& selection) noexcept;
bool pseudocode_request_valid(const pseudocode_request_t& request);
std::optional<aida::analysis::decompiler_entity_locator_t>
parse_pseudocode_entity_locator(std::string_view value) noexcept;
std::optional<std::string> canonical_pseudocode_entity_locator(
    const aida::analysis::decompiler_entity_locator_t& locator);

}
}
}
