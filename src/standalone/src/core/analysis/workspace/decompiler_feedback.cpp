#include "decompiler_feedback.hpp"

#include <algorithm>
#include <exception>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <tuple>
#include <type_traits>
#include <utility>

namespace aida::analysis {
namespace {

using clock_t = std::chrono::steady_clock;

struct scope_state_t {
    std::map<std::string, decompiler_feedback_fact_t> facts;
    decompiler_feedback_fixed_point_state_t fixed_point;
};

struct ranked_fact_t {
    std::size_t input_index = 0;
    const decompiler_feedback_fact_t* fact = nullptr;
    std::string canonical;
};

struct mutation_t {
    std::optional<decompiler_feedback_fact_t> original;
    decompiler_feedback_fact_t current;
};

bool checked_add(std::uint64_t left, std::uint64_t right, std::uint64_t& out) noexcept {
    if (right > std::numeric_limits<std::uint64_t>::max() - left)
        return false;
    out = left + right;
    return true;
}

bool nonempty_text(const std::string& value, std::size_t maximum) noexcept {
    return !value.empty() && value.size() <= maximum && value.find('\0') == std::string::npos;
}

bool bounded_text(const std::string& value, std::size_t maximum) noexcept {
    return value.size() <= maximum && value.find('\0') == std::string::npos;
}

bool limits_valid(const decompiler_feedback_limits_t& limits) noexcept {
    return limits.max_facts_per_publication != 0 &&
           limits.max_active_facts_per_scope != 0 &&
           limits.max_identifier_bytes != 0 &&
           limits.max_payload_bytes != 0 &&
           limits.max_publication_payload_bytes != 0 &&
           limits.max_cfg_blocks != 0 &&
           limits.max_cfg_edges != 0 &&
           limits.max_switch_cases != 0 &&
           limits.max_affected_ranges != 0 &&
           limits.max_affected_bytes != 0 &&
           limits.max_cache_invalidation_keys != 0 &&
           limits.max_fixed_point_rounds != 0 &&
           limits.convergence_rounds != 0 &&
           limits.poll_interval != 0;
}

decompiler_feedback_validation_result_t valid_result() {
    return {true, {}, {}};
}

decompiler_feedback_validation_result_t invalid_result(std::string code, std::string message) {
    return {false, std::move(code), std::move(message)};
}

bool range_nonempty_and_contained(const decompiler_feedback_range_t& outer,
                                  const decompiler_feedback_range_t& inner) noexcept {
    return inner.size != 0 && outer.contains(inner);
}

std::size_t text_size(const std::string& value) noexcept {
    return value.size();
}

bool checked_size_add(std::size_t left, std::size_t right, std::size_t& out) noexcept {
    if (right > std::numeric_limits<std::size_t>::max() - left)
        return false;
    out = left + right;
    return true;
}

template <typename T>
bool add_vector_size(std::size_t& total, const std::vector<T>& values) noexcept {
    if (values.size() > std::numeric_limits<std::size_t>::max() / sizeof(T))
        return false;
    const auto bytes = values.size() * sizeof(T);
    return checked_size_add(total, bytes, total);
}

bool known_validation_grade(decompiler_feedback_validation_grade_t grade) noexcept {
    switch (grade) {
    case decompiler_feedback_validation_grade_t::unverified:
    case decompiler_feedback_validation_grade_t::validated:
    case decompiler_feedback_validation_grade_t::proven:
        return true;
    }
    return false;
}

bool known_authority(decompiler_feedback_authority_t authority) noexcept {
    switch (authority) {
    case decompiler_feedback_authority_t::imported:
    case decompiler_feedback_authority_t::decompiler:
    case decompiler_feedback_authority_t::baseline_graph:
    case decompiler_feedback_authority_t::trusted_recovery:
        return true;
    }
    return false;
}

bool known_abstention_reason(decompiler_feedback_abstention_reason_t reason) noexcept {
    switch (reason) {
    case decompiler_feedback_abstention_reason_t::unsupported_architecture:
    case decompiler_feedback_abstention_reason_t::unsupported_encoding:
    case decompiler_feedback_abstention_reason_t::opaque_control_flow:
    case decompiler_feedback_abstention_reason_t::insufficient_bytes:
    case decompiler_feedback_abstention_reason_t::contradictory_evidence:
    case decompiler_feedback_abstention_reason_t::resource_budget:
    case decompiler_feedback_abstention_reason_t::cancelled:
    case decompiler_feedback_abstention_reason_t::deadline_exceeded:
        return true;
    }
    return false;
}

bool known_error_class(decompiler_feedback_error_class_t error_class) noexcept {
    switch (error_class) {
    case decompiler_feedback_error_class_t::decoder:
    case decompiler_feedback_error_class_t::ir_lift:
    case decompiler_feedback_error_class_t::cfg_reconstruction:
    case decompiler_feedback_error_class_t::type_recovery:
    case decompiler_feedback_error_class_t::source_mapping:
    case decompiler_feedback_error_class_t::persistence:
    case decompiler_feedback_error_class_t::integration:
        return true;
    }
    return false;
}

bool payload_size(const decompiler_feedback_payload_t& payload, std::size_t& out) noexcept {
    out = 0;
    if (payload.valueless_by_exception())
        return false;
    return std::visit([&out](const auto& value) noexcept {
        using value_t = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<value_t, decompiler_feedback_function_boundary_t>) {
            out = sizeof(value);
            return true;
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_cfg_t>) {
            return add_vector_size(out, value.blocks) && add_vector_size(out, value.edges);
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_switch_t>) {
            return add_vector_size(out, value.cases);
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_prototype_t>) {
            return checked_size_add(text_size(value.declaration), text_size(value.calling_convention), out);
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_storage_t>) {
            return checked_size_add(text_size(value.identifier), text_size(value.type_name), out);
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_type_assignment_t>) {
            out = text_size(value.type_name);
            return true;
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_name_t>) {
            out = text_size(value.identifier);
            return true;
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_comment_t>) {
            out = text_size(value.text);
            return true;
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_source_mapping_t>) {
            out = text_size(value.source_path);
            return true;
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_abstention_t>) {
            out = text_size(value.detail);
            return true;
        } else {
            out = text_size(value.detail);
            return true;
        }
    }, payload);
}

bool expected_payload(decompiler_feedback_fact_kind_t kind,
                      const decompiler_feedback_payload_t& payload) noexcept {
    switch (kind) {
    case decompiler_feedback_fact_kind_t::function_boundary:
        return std::holds_alternative<decompiler_feedback_function_boundary_t>(payload);
    case decompiler_feedback_fact_kind_t::cfg:
        return std::holds_alternative<decompiler_feedback_cfg_t>(payload);
    case decompiler_feedback_fact_kind_t::switch_table:
        return std::holds_alternative<decompiler_feedback_switch_t>(payload);
    case decompiler_feedback_fact_kind_t::prototype:
        return std::holds_alternative<decompiler_feedback_prototype_t>(payload);
    case decompiler_feedback_fact_kind_t::stack_variable:
    case decompiler_feedback_fact_kind_t::local_variable:
    case decompiler_feedback_fact_kind_t::global_reference:
        return std::holds_alternative<decompiler_feedback_storage_t>(payload);
    case decompiler_feedback_fact_kind_t::type_assignment:
        return std::holds_alternative<decompiler_feedback_type_assignment_t>(payload);
    case decompiler_feedback_fact_kind_t::name:
        return std::holds_alternative<decompiler_feedback_name_t>(payload);
    case decompiler_feedback_fact_kind_t::comment:
        return std::holds_alternative<decompiler_feedback_comment_t>(payload);
    case decompiler_feedback_fact_kind_t::source_mapping:
        return std::holds_alternative<decompiler_feedback_source_mapping_t>(payload);
    case decompiler_feedback_fact_kind_t::abstention:
        return std::holds_alternative<decompiler_feedback_abstention_t>(payload);
    case decompiler_feedback_fact_kind_t::error:
        return std::holds_alternative<decompiler_feedback_error_t>(payload);
    }
    return false;
}

bool is_assertive(decompiler_feedback_fact_kind_t kind) noexcept {
    return kind != decompiler_feedback_fact_kind_t::abstention &&
           kind != decompiler_feedback_fact_kind_t::error;
}

bool kind_requires_nonempty_range(decompiler_feedback_fact_kind_t kind) noexcept {
    return is_assertive(kind);
}

bool valid_source_location(const decompiler_feedback_source_mapping_t& source) noexcept {
    if (source.first_line == 0 || source.last_line == 0)
        return false;
    if (source.last_line < source.first_line)
        return false;
    if (source.last_line == source.first_line && source.last_column < source.first_column)
        return false;
    return true;
}

bool cfg_blocks_valid(const decompiler_feedback_cfg_t& cfg,
                      const decompiler_feedback_range_t& affected,
                      const decompiler_feedback_limits_t& limits) noexcept {
    if (cfg.blocks.empty() || cfg.blocks.size() > limits.max_cfg_blocks ||
        cfg.edges.size() > limits.max_cfg_edges)
        return false;
    std::vector<decompiler_feedback_range_t> blocks;
    blocks.reserve(cfg.blocks.size());
    for (const auto& block : cfg.blocks) {
        if (!range_nonempty_and_contained(affected, block.range))
            return false;
        blocks.push_back(block.range);
    }
    std::sort(blocks.begin(), blocks.end());
    for (std::size_t index = 1; index < blocks.size(); ++index) {
        if (blocks[index - 1].overlaps(blocks[index]))
            return false;
    }
    std::set<std::pair<std::uint64_t, std::uint64_t>> edges;
    for (const auto& edge : cfg.edges) {
        if (!affected.contains(edge.source) || !edges.emplace(edge.source, edge.target).second)
            return false;
    }
    return true;
}

void append_number(std::string& destination, std::uint64_t value) {
    destination += std::to_string(value);
    destination.push_back('|');
}

void append_signed_number(std::string& destination, std::int64_t value) {
    destination += std::to_string(value);
    destination.push_back('|');
}

void append_text(std::string& destination, const std::string& value) {
    append_number(destination, static_cast<std::uint64_t>(value.size()));
    destination += value;
    destination.push_back('|');
}

void append_range(std::string& destination, const decompiler_feedback_range_t& range) {
    append_number(destination, range.begin);
    append_number(destination, range.size);
}

void append_payload(std::string& destination, const decompiler_feedback_function_boundary_t& value) {
    append_number(destination, value.entry);
    append_number(destination, value.end);
}

void append_payload(std::string& destination, const decompiler_feedback_cfg_t& value) {
    append_number(destination, static_cast<std::uint64_t>(value.blocks.size()));
    for (const auto& block : value.blocks) {
        append_range(destination, block.range);
        append_number(destination, block.terminal ? 1 : 0);
    }
    append_number(destination, static_cast<std::uint64_t>(value.edges.size()));
    for (const auto& edge : value.edges) {
        append_number(destination, edge.source);
        append_number(destination, edge.target);
    }
}

void append_payload(std::string& destination, const decompiler_feedback_switch_t& value) {
    append_number(destination, value.dispatch);
    append_number(destination, static_cast<std::uint64_t>(value.cases.size()));
    for (const auto& entry : value.cases) {
        append_signed_number(destination, entry.value);
        append_number(destination, entry.target);
    }
    append_number(destination, value.default_target.has_value() ? 1 : 0);
    if (value.default_target)
        append_number(destination, *value.default_target);
}

void append_payload(std::string& destination, const decompiler_feedback_prototype_t& value) {
    append_number(destination, value.function);
    append_text(destination, value.declaration);
    append_text(destination, value.calling_convention);
}

void append_payload(std::string& destination, const decompiler_feedback_storage_t& value) {
    append_number(destination, value.address);
    append_signed_number(destination, value.stack_offset);
    append_number(destination, value.byte_size);
    append_text(destination, value.identifier);
    append_text(destination, value.type_name);
}

void append_payload(std::string& destination, const decompiler_feedback_type_assignment_t& value) {
    append_number(destination, value.address);
    append_text(destination, value.type_name);
}

void append_payload(std::string& destination, const decompiler_feedback_name_t& value) {
    append_number(destination, value.address);
    append_text(destination, value.identifier);
}

void append_payload(std::string& destination, const decompiler_feedback_comment_t& value) {
    append_number(destination, value.address);
    append_text(destination, value.text);
}

void append_payload(std::string& destination, const decompiler_feedback_source_mapping_t& value) {
    append_range(destination, value.mapped_range);
    append_text(destination, value.source_path);
    append_number(destination, value.first_line);
    append_number(destination, value.first_column);
    append_number(destination, value.last_line);
    append_number(destination, value.last_column);
}

void append_payload(std::string& destination, const decompiler_feedback_abstention_t& value) {
    append_number(destination, static_cast<std::uint64_t>(value.reason));
    append_text(destination, value.detail);
}

void append_payload(std::string& destination, const decompiler_feedback_error_t& value) {
    append_number(destination, static_cast<std::uint64_t>(value.error_class));
    append_text(destination, value.detail);
    append_number(destination, value.retryable ? 1 : 0);
}

std::string canonical_fact(const decompiler_feedback_fact_t& fact) {
    std::string result;
    result.reserve(fact.fact_id.size() + fact.logical_key.size() + fact.publisher_id.size() + 192);
    append_text(result, fact.fact_id);
    append_text(result, fact.logical_key);
    append_text(result, fact.publisher_id);
    append_number(result, static_cast<std::uint64_t>(fact.kind));
    append_number(result, static_cast<std::uint64_t>(fact.authority));
    append_number(result, static_cast<std::uint64_t>(fact.validation.grade));
    append_text(result, fact.validation.validator_id);
    append_text(result, fact.validation.evidence_id);
    append_number(result, fact.validation.evidence_revision);
    append_number(result, fact.source_revision);
    append_range(result, fact.affected_range);
    std::visit([&result](const auto& value) { append_payload(result, value); }, fact.payload);
    return result;
}

std::string canonical_content(const decompiler_feedback_fact_t& fact) {
    std::string result;
    result.reserve(128);
    append_number(result, static_cast<std::uint64_t>(fact.kind));
    append_range(result, fact.affected_range);
    std::visit([&result](const auto& value) { append_payload(result, value); }, fact.payload);
    return result;
}

int compare_precedence(const decompiler_feedback_fact_t& left,
                       const std::string& left_canonical,
                       const decompiler_feedback_fact_t& right,
                       const std::string& right_canonical) {
    const auto left_rank = std::make_tuple(
        static_cast<std::uint8_t>(left.validation.grade),
        static_cast<std::uint8_t>(left.authority),
        left.validation.evidence_revision,
        left.source_revision,
        left.publisher_id,
        left.fact_id,
        left_canonical);
    const auto right_rank = std::make_tuple(
        static_cast<std::uint8_t>(right.validation.grade),
        static_cast<std::uint8_t>(right.authority),
        right.validation.evidence_revision,
        right.source_revision,
        right.publisher_id,
        right.fact_id,
        right_canonical);
    if (left_rank < right_rank)
        return -1;
    if (right_rank < left_rank)
        return 1;
    return 0;
}

std::vector<decompiler_feedback_cache_domain_t> cache_domains(
    decompiler_feedback_fact_kind_t kind) {
    switch (kind) {
    case decompiler_feedback_fact_kind_t::function_boundary:
        return {decompiler_feedback_cache_domain_t::function_boundaries,
                decompiler_feedback_cache_domain_t::decompiler_output,
                decompiler_feedback_cache_domain_t::baseline_graph};
    case decompiler_feedback_fact_kind_t::cfg:
        return {decompiler_feedback_cache_domain_t::control_flow,
                decompiler_feedback_cache_domain_t::decompiler_output,
                decompiler_feedback_cache_domain_t::baseline_graph};
    case decompiler_feedback_fact_kind_t::switch_table:
        return {decompiler_feedback_cache_domain_t::control_flow,
                decompiler_feedback_cache_domain_t::switch_metadata,
                decompiler_feedback_cache_domain_t::decompiler_output};
    case decompiler_feedback_fact_kind_t::prototype:
        return {decompiler_feedback_cache_domain_t::prototype,
                decompiler_feedback_cache_domain_t::type_graph,
                decompiler_feedback_cache_domain_t::decompiler_output};
    case decompiler_feedback_fact_kind_t::stack_variable:
    case decompiler_feedback_fact_kind_t::local_variable:
    case decompiler_feedback_fact_kind_t::global_reference:
        return {decompiler_feedback_cache_domain_t::storage_layout,
                decompiler_feedback_cache_domain_t::type_graph,
                decompiler_feedback_cache_domain_t::decompiler_output};
    case decompiler_feedback_fact_kind_t::type_assignment:
        return {decompiler_feedback_cache_domain_t::type_graph,
                decompiler_feedback_cache_domain_t::decompiler_output,
                decompiler_feedback_cache_domain_t::baseline_graph};
    case decompiler_feedback_fact_kind_t::name:
        return {decompiler_feedback_cache_domain_t::symbols,
                decompiler_feedback_cache_domain_t::decompiler_output};
    case decompiler_feedback_fact_kind_t::comment:
        return {decompiler_feedback_cache_domain_t::annotations,
                decompiler_feedback_cache_domain_t::decompiler_output};
    case decompiler_feedback_fact_kind_t::source_mapping:
        return {decompiler_feedback_cache_domain_t::source_map,
                decompiler_feedback_cache_domain_t::decompiler_output};
    case decompiler_feedback_fact_kind_t::abstention:
    case decompiler_feedback_fact_kind_t::error:
        return {};
    }
    return {};
}

std::uint64_t fact_anchor(const decompiler_feedback_fact_t& fact) noexcept {
    return std::visit([](const auto& value) noexcept -> std::uint64_t {
        using value_t = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<value_t, decompiler_feedback_function_boundary_t>) {
            return value.entry;
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_switch_t>) {
            return value.dispatch;
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_prototype_t>) {
            return value.function;
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_storage_t>) {
            return value.address;
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_type_assignment_t>) {
            return value.address;
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_name_t>) {
            return value.address;
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_comment_t>) {
            return value.address;
        } else if constexpr (std::is_same_v<value_t, decompiler_feedback_source_mapping_t>) {
            return value.mapped_range.begin;
        } else {
            return 0;
        }
    }, fact.payload);
}

std::vector<decompiler_feedback_fact_t> mutation_facts(
    const std::map<std::string, mutation_t>& mutations) {
    std::vector<decompiler_feedback_fact_t> facts;
    facts.reserve(mutations.size() * 2);
    for (const auto& [logical_key, mutation] : mutations) {
        if (mutation.original)
            facts.push_back(*mutation.original);
        facts.push_back(mutation.current);
    }
    return facts;
}

std::vector<decompiler_feedback_range_t> mutation_ranges(
    const std::map<std::string, mutation_t>& mutations) {
    std::vector<decompiler_feedback_range_t> ranges;
    ranges.reserve(mutations.size() * 2);
    for (const auto& [logical_key, mutation] : mutations) {
        if (mutation.original)
            ranges.push_back(mutation.original->affected_range);
        ranges.push_back(mutation.current.affected_range);
    }
    return ranges;
}

decompiler_feedback_publication_result_t stopped_result(
    decompiler_feedback_publication_status_t status,
    const decompiler_feedback_fixed_point_state_t& state) {
    decompiler_feedback_publication_result_t result;
    result.status = status;
    result.fixed_point = state;
    result.fixed_point.status = status == decompiler_feedback_publication_status_t::cancelled
        ? decompiler_feedback_fixed_point_status_t::cancelled
        : decompiler_feedback_fixed_point_status_t::deadline_exceeded;
    result.code = status == decompiler_feedback_publication_status_t::cancelled
        ? "cancelled"
        : "deadline_exceeded";
    result.message = status == decompiler_feedback_publication_status_t::cancelled
        ? "feedback publication was cancelled before commit"
        : "feedback publication exceeded its deadline before commit";
    return result;
}

}

struct decompiler_feedback_model_t::state_t {
    mutable std::mutex mutex;
    std::map<decompiler_feedback_scope_key_t, scope_state_t> scopes;
};

bool decompiler_feedback_scope_key_t::operator==(const decompiler_feedback_scope_key_t& other) const noexcept {
    return workspace_id == other.workspace_id &&
           binary_id == other.binary_id &&
           address_space_id == other.address_space_id &&
           architecture_id == other.architecture_id &&
           generation == other.generation &&
           overlay_revision == other.overlay_revision &&
           type_revision == other.type_revision;
}

bool decompiler_feedback_scope_key_t::operator<(const decompiler_feedback_scope_key_t& other) const noexcept {
    return std::tie(workspace_id, binary_id, address_space_id, architecture_id, generation,
                    overlay_revision, type_revision) <
           std::tie(other.workspace_id, other.binary_id, other.address_space_id, other.architecture_id,
                    other.generation, other.overlay_revision, other.type_revision);
}

bool decompiler_feedback_range_t::end(std::uint64_t& out) const noexcept {
    return checked_add(begin, size, out);
}

bool decompiler_feedback_range_t::valid() const noexcept {
    std::uint64_t ignored = 0;
    return end(ignored);
}

bool decompiler_feedback_range_t::contains(std::uint64_t address) const noexcept {
    std::uint64_t finish = 0;
    return end(finish) && address >= begin && address < finish;
}

bool decompiler_feedback_range_t::contains(const decompiler_feedback_range_t& other) const noexcept {
    std::uint64_t finish = 0;
    std::uint64_t other_finish = 0;
    return end(finish) && other.end(other_finish) && other.begin >= begin && other_finish <= finish;
}

bool decompiler_feedback_range_t::overlaps(const decompiler_feedback_range_t& other) const noexcept {
    std::uint64_t finish = 0;
    std::uint64_t other_finish = 0;
    return end(finish) && other.end(other_finish) && begin < other_finish && other.begin < finish;
}

bool decompiler_feedback_range_t::operator==(const decompiler_feedback_range_t& other) const noexcept {
    return begin == other.begin && size == other.size;
}

bool decompiler_feedback_range_t::operator<(const decompiler_feedback_range_t& other) const noexcept {
    return std::tie(begin, size) < std::tie(other.begin, other.size);
}

bool decompiler_feedback_cache_invalidation_key_t::operator==(
    const decompiler_feedback_cache_invalidation_key_t& other) const noexcept {
    return scope == other.scope && domain == other.domain && range == other.range &&
           anchor_address == other.anchor_address;
}

bool decompiler_feedback_cache_invalidation_key_t::operator<(
    const decompiler_feedback_cache_invalidation_key_t& other) const noexcept {
    return std::tie(scope, domain, range, anchor_address) <
           std::tie(other.scope, other.domain, other.range, other.anchor_address);
}

decompiler_feedback_model_t::decompiler_feedback_model_t(decompiler_feedback_limits_t limits)
    : limits_(std::move(limits)), state_(std::make_unique<state_t>()) {
}

decompiler_feedback_model_t::~decompiler_feedback_model_t() = default;

const decompiler_feedback_limits_t& decompiler_feedback_model_t::limits() const noexcept {
    return limits_;
}

decompiler_feedback_validation_result_t decompiler_feedback_model_t::validate_scope(
    const decompiler_feedback_scope_key_t& scope,
    const decompiler_feedback_limits_t& limits) {
    if (!limits_valid(limits))
        return invalid_result("invalid_limits", "feedback limits must be nonzero and bounded");
    if (!nonempty_text(scope.workspace_id, limits.max_identifier_bytes) ||
        !nonempty_text(scope.binary_id, limits.max_identifier_bytes) ||
        !nonempty_text(scope.address_space_id, limits.max_identifier_bytes) ||
        !nonempty_text(scope.architecture_id, limits.max_identifier_bytes)) {
        return invalid_result("invalid_scope_key", "workspace, binary, address-space, and architecture keys are required");
    }
    return valid_result();
}

decompiler_feedback_validation_result_t decompiler_feedback_model_t::validate_fact(
    const decompiler_feedback_fact_t& fact,
    const decompiler_feedback_limits_t& limits) {
    if (!limits_valid(limits))
        return invalid_result("invalid_limits", "feedback limits must be nonzero and bounded");
    if (!nonempty_text(fact.fact_id, limits.max_identifier_bytes) ||
        !nonempty_text(fact.logical_key, limits.max_identifier_bytes) ||
        !nonempty_text(fact.publisher_id, limits.max_identifier_bytes)) {
        return invalid_result("invalid_identity", "fact, logical, and publisher identities are required");
    }
    if (!known_validation_grade(fact.validation.grade) || !known_authority(fact.authority))
        return invalid_result("invalid_fact_enum", "feedback authority or validation grade is unknown");
    if (!nonempty_text(fact.validation.validator_id, limits.max_identifier_bytes) ||
        !nonempty_text(fact.validation.evidence_id, limits.max_identifier_bytes) ||
        fact.validation.evidence_revision == 0 || fact.source_revision == 0) {
        return invalid_result("unverifiable_fact", "fact provenance must include validator, evidence, and nonzero revisions");
    }
    if (is_assertive(fact.kind) &&
        fact.validation.grade != decompiler_feedback_validation_grade_t::proven) {
        return invalid_result("unproven_fact", "assertive feedback facts require proven validation");
    }
    if (!is_assertive(fact.kind) &&
        fact.validation.grade == decompiler_feedback_validation_grade_t::unverified) {
        return invalid_result("unvalidated_terminal_fact", "abstention and error facts require validated provenance");
    }
    if (!fact.affected_range.valid() ||
        (kind_requires_nonempty_range(fact.kind) && fact.affected_range.size == 0)) {
        return invalid_result("invalid_affected_range", "feedback affected range is invalid or empty");
    }
    if (!expected_payload(fact.kind, fact.payload))
        return invalid_result("payload_kind_mismatch", "feedback payload does not match its declared kind");

    std::size_t size = 0;
    if (!payload_size(fact.payload, size) || size > limits.max_payload_bytes)
        return invalid_result("payload_too_large", "feedback payload exceeds the configured publication bound");

    switch (fact.kind) {
    case decompiler_feedback_fact_kind_t::function_boundary: {
        const auto& value = std::get<decompiler_feedback_function_boundary_t>(fact.payload);
        std::uint64_t finish = 0;
        if (!fact.affected_range.end(finish) || value.entry != fact.affected_range.begin ||
            value.end != finish || value.end <= value.entry) {
            return invalid_result("invalid_function_boundary", "function boundary must exactly match its affected range");
        }
        break;
    }
    case decompiler_feedback_fact_kind_t::cfg: {
        const auto& value = std::get<decompiler_feedback_cfg_t>(fact.payload);
        if (!cfg_blocks_valid(value, fact.affected_range, limits))
            return invalid_result("invalid_cfg", "CFG blocks or edges are outside the function range or not canonical");
        break;
    }
    case decompiler_feedback_fact_kind_t::switch_table: {
        const auto& value = std::get<decompiler_feedback_switch_t>(fact.payload);
        if (!fact.affected_range.contains(value.dispatch) || value.cases.size() > limits.max_switch_cases)
            return invalid_result("invalid_switch", "switch dispatch or case count is outside configured bounds");
        std::set<std::int64_t> values;
        for (const auto& entry : value.cases) {
            if (!values.emplace(entry.value).second)
                return invalid_result("duplicate_switch_case", "switch case values must be unique");
        }
        break;
    }
    case decompiler_feedback_fact_kind_t::prototype: {
        const auto& value = std::get<decompiler_feedback_prototype_t>(fact.payload);
        if (!fact.affected_range.contains(value.function) ||
            !nonempty_text(value.declaration, limits.max_payload_bytes) ||
            !nonempty_text(value.calling_convention, limits.max_identifier_bytes)) {
            return invalid_result("invalid_prototype", "prototype requires an in-range function, declaration, and calling convention");
        }
        break;
    }
    case decompiler_feedback_fact_kind_t::stack_variable:
    case decompiler_feedback_fact_kind_t::local_variable:
    case decompiler_feedback_fact_kind_t::global_reference: {
        const auto& value = std::get<decompiler_feedback_storage_t>(fact.payload);
        if (!fact.affected_range.contains(value.address) || value.byte_size == 0 ||
            !nonempty_text(value.identifier, limits.max_identifier_bytes) ||
            !nonempty_text(value.type_name, limits.max_identifier_bytes)) {
            return invalid_result("invalid_storage", "storage feedback requires an in-range address, nonzero size, name, and type");
        }
        break;
    }
    case decompiler_feedback_fact_kind_t::type_assignment: {
        const auto& value = std::get<decompiler_feedback_type_assignment_t>(fact.payload);
        if (!fact.affected_range.contains(value.address) ||
            !nonempty_text(value.type_name, limits.max_identifier_bytes)) {
            return invalid_result("invalid_type_assignment", "type feedback requires an in-range address and type name");
        }
        break;
    }
    case decompiler_feedback_fact_kind_t::name: {
        const auto& value = std::get<decompiler_feedback_name_t>(fact.payload);
        if (!fact.affected_range.contains(value.address) ||
            !nonempty_text(value.identifier, limits.max_identifier_bytes)) {
            return invalid_result("invalid_name", "name feedback requires an in-range address and identifier");
        }
        break;
    }
    case decompiler_feedback_fact_kind_t::comment: {
        const auto& value = std::get<decompiler_feedback_comment_t>(fact.payload);
        if (!fact.affected_range.contains(value.address) ||
            !nonempty_text(value.text, limits.max_payload_bytes)) {
            return invalid_result("invalid_comment", "comment feedback requires an in-range address and nonempty text");
        }
        break;
    }
    case decompiler_feedback_fact_kind_t::source_mapping: {
        const auto& value = std::get<decompiler_feedback_source_mapping_t>(fact.payload);
        if (!range_nonempty_and_contained(fact.affected_range, value.mapped_range) ||
            !nonempty_text(value.source_path, limits.max_payload_bytes) ||
            !valid_source_location(value)) {
            return invalid_result("invalid_source_mapping", "source mapping must be bounded, named, and line ordered");
        }
        break;
    }
    case decompiler_feedback_fact_kind_t::abstention: {
        const auto& value = std::get<decompiler_feedback_abstention_t>(fact.payload);
        if (!known_abstention_reason(value.reason) ||
            !nonempty_text(value.detail, limits.max_payload_bytes))
            return invalid_result("invalid_abstention", "abstention feedback requires an explanatory detail");
        break;
    }
    case decompiler_feedback_fact_kind_t::error: {
        const auto& value = std::get<decompiler_feedback_error_t>(fact.payload);
        if (!known_error_class(value.error_class) ||
            !nonempty_text(value.detail, limits.max_payload_bytes))
            return invalid_result("invalid_error", "error feedback requires an explanatory detail");
        break;
    }
    }
    return valid_result();
}

decompiler_feedback_conflict_resolution_t decompiler_feedback_model_t::resolve_conflict(
    const decompiler_feedback_fact_t& incumbent,
    const decompiler_feedback_fact_t& candidate) {
    decompiler_feedback_conflict_resolution_t result;
    if (incumbent.logical_key != candidate.logical_key || incumbent.kind != candidate.kind) {
        result.decision = decompiler_feedback_conflict_decision_t::incompatible;
        result.reason = "logical keys or fact kinds differ";
        return result;
    }
    if (incumbent.payload.valueless_by_exception() || candidate.payload.valueless_by_exception()) {
        result.decision = decompiler_feedback_conflict_decision_t::incompatible;
        result.reason = "one or both conflict payloads are valueless";
        return result;
    }
    const auto incumbent_content = canonical_content(incumbent);
    const auto candidate_content = canonical_content(candidate);
    if (incumbent_content == candidate_content) {
        result.decision = decompiler_feedback_conflict_decision_t::duplicate;
        result.winner_fact_id = incumbent.fact_id;
        result.loser_fact_id = candidate.fact_id;
        result.reason = "canonical fact content is identical";
        return result;
    }
    const auto incumbent_canonical = canonical_fact(incumbent);
    const auto candidate_canonical = canonical_fact(candidate);
    if (compare_precedence(candidate, candidate_canonical, incumbent, incumbent_canonical) > 0) {
        result.decision = decompiler_feedback_conflict_decision_t::candidate_replaces_incumbent;
        result.winner_fact_id = candidate.fact_id;
        result.loser_fact_id = incumbent.fact_id;
        result.reason = "candidate has higher deterministic precedence";
        return result;
    }
    result.decision = decompiler_feedback_conflict_decision_t::incumbent_retained;
    result.winner_fact_id = incumbent.fact_id;
    result.loser_fact_id = candidate.fact_id;
    result.reason = "incumbent has higher deterministic precedence";
    return result;
}

decompiler_feedback_range_plan_t decompiler_feedback_model_t::compose_affected_ranges(
    std::vector<decompiler_feedback_range_t> ranges,
    const decompiler_feedback_limits_t& limits) {
    decompiler_feedback_range_plan_t result;
    if (!limits_valid(limits)) {
        result.code = "invalid_limits";
        result.message = "feedback limits must be nonzero and bounded";
        return result;
    }
    ranges.erase(std::remove_if(ranges.begin(), ranges.end(), [](const auto& range) {
        return range.size == 0;
    }), ranges.end());
    for (const auto& range : ranges) {
        if (!range.valid()) {
            result.code = "invalid_range";
            result.message = "affected range overflows the address space";
            return result;
        }
    }
    std::sort(ranges.begin(), ranges.end());
    for (const auto& range : ranges) {
        if (result.ranges.empty()) {
            result.ranges.push_back(range);
            continue;
        }
        auto& prior = result.ranges.back();
        std::uint64_t prior_end = 0;
        if (!prior.end(prior_end)) {
            result.code = "invalid_range";
            result.message = "affected range overflows the address space";
            return result;
        }
        if (range.begin <= prior_end) {
            std::uint64_t range_end = 0;
            if (!range.end(range_end)) {
                result.code = "invalid_range";
                result.message = "affected range overflows the address space";
                return result;
            }
            if (range_end > prior_end)
                prior.size = range_end - prior.begin;
        } else {
            result.ranges.push_back(range);
        }
    }
    if (result.ranges.size() > limits.max_affected_ranges) {
        result.ranges.clear();
        result.code = "affected_range_count_exceeded";
        result.message = "affected range count exceeds the configured publication bound";
        return result;
    }
    for (const auto& range : result.ranges) {
        std::uint64_t total = 0;
        if (!checked_add(result.total_bytes, range.size, total) || total > limits.max_affected_bytes) {
            result.ranges.clear();
            result.total_bytes = 0;
            result.code = "affected_range_bytes_exceeded";
            result.message = "affected range bytes exceed the configured publication bound";
            return result;
        }
        result.total_bytes = total;
    }
    result.bounded = true;
    return result;
}

decompiler_feedback_cache_plan_t decompiler_feedback_model_t::derive_cache_invalidations(
    const decompiler_feedback_scope_key_t& scope,
    const std::vector<decompiler_feedback_fact_t>& facts,
    const decompiler_feedback_limits_t& limits) {
    decompiler_feedback_cache_plan_t result;
    if (!validate_scope(scope, limits).valid) {
        result.code = "invalid_scope";
        result.message = "cache invalidation requires a valid feedback scope";
        return result;
    }
    for (const auto& fact : facts) {
        if (fact.payload.valueless_by_exception() || !fact.affected_range.valid()) {
            result.code = "invalid_range";
            result.message = "cache invalidation requires valid payloads and non-overflowing ranges";
            return result;
        }
        const auto domains = cache_domains(fact.kind);
        const auto anchor = fact_anchor(fact);
        for (const auto domain : domains)
            result.keys.push_back({scope, domain, fact.affected_range, anchor});
    }
    std::sort(result.keys.begin(), result.keys.end());
    result.keys.erase(std::unique(result.keys.begin(), result.keys.end()), result.keys.end());
    if (result.keys.size() > limits.max_cache_invalidation_keys) {
        result.keys.clear();
        result.code = "cache_invalidation_count_exceeded";
        result.message = "cache invalidation key count exceeds the configured publication bound";
        return result;
    }
    result.bounded = true;
    return result;
}

bool decompiler_feedback_model_t::should_stop(
    const decompiler_feedback_publication_request_t& request,
    decompiler_feedback_publication_status_t& status) noexcept {
    try {
        if (request.is_cancelled && request.is_cancelled()) {
            status = decompiler_feedback_publication_status_t::cancelled;
            return true;
        }
    } catch (...) {
        status = decompiler_feedback_publication_status_t::cancelled;
        return true;
    }
    if (request.deadline && clock_t::now() >= *request.deadline) {
        status = decompiler_feedback_publication_status_t::deadline_exceeded;
        return true;
    }
    return false;
}

decompiler_feedback_scope_snapshot_t decompiler_feedback_model_t::snapshot(
    const decompiler_feedback_scope_key_t& scope) const {
    decompiler_feedback_scope_snapshot_t result;
    std::lock_guard<std::mutex> lock(state_->mutex);
    const auto found = state_->scopes.find(scope);
    if (found == state_->scopes.end())
        return result;
    result.exists = true;
    result.fixed_point = found->second.fixed_point;
    result.facts.reserve(found->second.facts.size());
    for (const auto& [logical_key, fact] : found->second.facts)
        result.facts.push_back(fact);
    return result;
}

decompiler_feedback_publication_result_t decompiler_feedback_model_t::publish(
    const decompiler_feedback_publication_request_t& request) {
    const auto scope_validation = validate_scope(request.scope, limits_);
    if (!scope_validation.valid) {
        decompiler_feedback_publication_result_t result;
        result.status = decompiler_feedback_publication_status_t::invalid_scope;
        result.code = scope_validation.code;
        result.message = scope_validation.message;
        return result;
    }
    if (request.facts.size() > limits_.max_facts_per_publication) {
        decompiler_feedback_publication_result_t result;
        result.status = decompiler_feedback_publication_status_t::publication_capacity;
        result.code = "publication_fact_count_exceeded";
        result.message = "publication fact count exceeds the configured bound";
        return result;
    }
    std::size_t publication_payload_bytes = 0;
    for (const auto& fact : request.facts) {
        std::size_t fact_payload_bytes = 0;
        if (!payload_size(fact.payload, fact_payload_bytes) ||
            !checked_size_add(publication_payload_bytes, fact_payload_bytes, publication_payload_bytes) ||
            publication_payload_bytes > limits_.max_publication_payload_bytes) {
            decompiler_feedback_publication_result_t result;
            result.status = decompiler_feedback_publication_status_t::publication_capacity;
            result.code = "publication_payload_bytes_exceeded";
            result.message = "publication payload bytes exceed the configured bound";
            return result;
        }
    }
    decompiler_feedback_publication_status_t stop_status = decompiler_feedback_publication_status_t::no_change;
    if (should_stop(request, stop_status))
        return stopped_result(stop_status, {});

    try {
        std::lock_guard<std::mutex> lock(state_->mutex);
        const auto existing = state_->scopes.find(request.scope);
        scope_state_t staged = existing == state_->scopes.end() ? scope_state_t{} : existing->second;
        if (staged.fixed_point.status != decompiler_feedback_fixed_point_status_t::active ||
            staged.fixed_point.rounds >= limits_.max_fixed_point_rounds) {
            if (staged.fixed_point.rounds >= limits_.max_fixed_point_rounds)
                staged.fixed_point.status = decompiler_feedback_fixed_point_status_t::round_budget_exhausted;
            if (existing != state_->scopes.end())
                state_->scopes[request.scope] = staged;
            decompiler_feedback_publication_result_t result;
            result.status = decompiler_feedback_publication_status_t::fixed_point_closed;
            result.fixed_point = staged.fixed_point;
            result.code = "fixed_point_closed";
            result.message = "feedback scope requires a new revision key before further publication";
            return result;
        }

        std::vector<ranked_fact_t> ranked;
        ranked.reserve(request.facts.size());
        decompiler_feedback_publication_result_t result;
        for (std::size_t index = 0; index < request.facts.size(); ++index) {
            if (index % limits_.poll_interval == 0 && should_stop(request, stop_status))
                return stopped_result(stop_status, staged.fixed_point);
            const auto& fact = request.facts[index];
            try {
                const auto validation = validate_fact(fact, limits_);
                if (!validation.valid) {
                    result.rejections.push_back({index, fact.fact_id,
                                                 decompiler_feedback_rejection_reason_t::invalid_fact,
                                                 validation.code, validation.message});
                    continue;
                }
                ranked.push_back({index, &fact, canonical_fact(fact)});
            } catch (const std::exception& error) {
                result.rejections.push_back({index, fact.fact_id,
                                             decompiler_feedback_rejection_reason_t::isolated_failure,
                                             "fact_preparation_exception", error.what()});
            } catch (...) {
                result.rejections.push_back({index, fact.fact_id,
                                             decompiler_feedback_rejection_reason_t::isolated_failure,
                                             "fact_preparation_exception", "fact preparation raised a nonstandard exception"});
            }
        }
        std::sort(ranked.begin(), ranked.end(), [](const auto& left, const auto& right) {
            return std::tie(left.fact->logical_key, left.fact->kind, left.fact->fact_id,
                            left.fact->publisher_id, left.fact->source_revision, left.canonical) <
                   std::tie(right.fact->logical_key, right.fact->kind, right.fact->fact_id,
                            right.fact->publisher_id, right.fact->source_revision, right.canonical);
        });

        std::map<std::string, mutation_t> mutations;
        for (std::size_t rank = 0; rank < ranked.size(); ++rank) {
            if (rank % limits_.poll_interval == 0 && should_stop(request, stop_status))
                return stopped_result(stop_status, staged.fixed_point);
            const auto& ranked_fact = ranked[rank];
            const auto& candidate = *ranked_fact.fact;
            try {
                const auto incumbent = staged.facts.find(candidate.logical_key);
                if (incumbent != staged.facts.end()) {
                    const auto resolution = resolve_conflict(incumbent->second, candidate);
                    if (resolution.decision == decompiler_feedback_conflict_decision_t::duplicate)
                        continue;
                    result.conflicts.push_back({candidate.logical_key, incumbent->second.fact_id,
                                                candidate.fact_id, resolution});
                    if (resolution.decision == decompiler_feedback_conflict_decision_t::incompatible) {
                        result.rejections.push_back({ranked_fact.input_index, candidate.fact_id,
                                                     decompiler_feedback_rejection_reason_t::incompatible_conflict,
                                                     "incompatible_conflict", resolution.reason});
                        continue;
                    }
                    if (resolution.decision == decompiler_feedback_conflict_decision_t::incumbent_retained) {
                        result.rejections.push_back({ranked_fact.input_index, candidate.fact_id,
                                                     decompiler_feedback_rejection_reason_t::conflict_lost,
                                                     "conflict_lost", resolution.reason});
                        continue;
                    }
                } else if (staged.facts.size() >= limits_.max_active_facts_per_scope) {
                    result.rejections.push_back({ranked_fact.input_index, candidate.fact_id,
                                                 decompiler_feedback_rejection_reason_t::active_capacity,
                                                 "active_fact_capacity_exceeded",
                                                 "active feedback facts exceed the configured scope bound"});
                    continue;
                }

                auto prospective = mutations;
                const auto mutation = prospective.find(candidate.logical_key);
                if (mutation == prospective.end()) {
                    mutation_t change;
                    if (incumbent != staged.facts.end())
                        change.original = incumbent->second;
                    change.current = candidate;
                    prospective.emplace(candidate.logical_key, std::move(change));
                } else {
                    mutation->second.current = candidate;
                }
                const auto range_plan = compose_affected_ranges(mutation_ranges(prospective), limits_);
                if (!range_plan.bounded) {
                    result.rejections.push_back({ranked_fact.input_index, candidate.fact_id,
                                                 decompiler_feedback_rejection_reason_t::affected_range_capacity,
                                                 range_plan.code, range_plan.message});
                    continue;
                }
                const auto cache_plan = derive_cache_invalidations(request.scope, mutation_facts(prospective), limits_);
                if (!cache_plan.bounded) {
                    result.rejections.push_back({ranked_fact.input_index, candidate.fact_id,
                                                 decompiler_feedback_rejection_reason_t::cache_invalidation_capacity,
                                                 cache_plan.code, cache_plan.message});
                    continue;
                }
                mutations = std::move(prospective);
                staged.facts[candidate.logical_key] = candidate;
            } catch (const std::exception& error) {
                result.rejections.push_back({ranked_fact.input_index, candidate.fact_id,
                                             decompiler_feedback_rejection_reason_t::isolated_failure,
                                             "fact_publication_exception", error.what()});
            } catch (...) {
                result.rejections.push_back({ranked_fact.input_index, candidate.fact_id,
                                             decompiler_feedback_rejection_reason_t::isolated_failure,
                                             "fact_publication_exception", "fact publication raised a nonstandard exception"});
            }
        }

        if (should_stop(request, stop_status))
            return stopped_result(stop_status, staged.fixed_point);
        result.affected_ranges = compose_affected_ranges(mutation_ranges(mutations), limits_);
        result.cache_invalidations = derive_cache_invalidations(request.scope, mutation_facts(mutations), limits_);
        if (!result.affected_ranges.bounded || !result.cache_invalidations.bounded) {
            result.status = decompiler_feedback_publication_status_t::internal_failure;
            result.fixed_point = existing == state_->scopes.end()
                ? decompiler_feedback_fixed_point_state_t{}
                : existing->second.fixed_point;
            result.code = "final_plan_failure";
            result.message = "staged feedback could not produce bounded publication plans";
            return result;
        }

        ++staged.fixed_point.rounds;
        staged.fixed_point.rejected_facts += result.rejections.size();
        staged.fixed_point.conflict_count += result.conflicts.size();
        if (mutations.empty()) {
            ++staged.fixed_point.stable_rounds;
        } else {
            staged.fixed_point.stable_rounds = 0;
            staged.fixed_point.accepted_facts += mutations.size();
            result.accepted_fact_ids.reserve(mutations.size());
            for (const auto& [logical_key, mutation] : mutations)
                result.accepted_fact_ids.push_back(mutation.current.fact_id);
        }
        if (staged.fixed_point.stable_rounds >= limits_.convergence_rounds) {
            staged.fixed_point.status = decompiler_feedback_fixed_point_status_t::converged;
        } else if (staged.fixed_point.rounds >= limits_.max_fixed_point_rounds) {
            staged.fixed_point.status = decompiler_feedback_fixed_point_status_t::round_budget_exhausted;
        }
        state_->scopes[request.scope] = staged;
        result.fixed_point = staged.fixed_point;
        result.status = mutations.empty() ? decompiler_feedback_publication_status_t::no_change
                                          : decompiler_feedback_publication_status_t::published;
        result.code = mutations.empty() ? "no_new_proven_facts" : "published";
        result.message = mutations.empty() ? "publication produced no stronger proven feedback facts"
                                           : "proven feedback facts were staged and published";
        return result;
    } catch (const std::exception& error) {
        decompiler_feedback_publication_result_t result;
        result.status = decompiler_feedback_publication_status_t::internal_failure;
        result.code = "publication_exception";
        result.message = error.what();
        return result;
    } catch (...) {
        decompiler_feedback_publication_result_t result;
        result.status = decompiler_feedback_publication_status_t::internal_failure;
        result.code = "publication_exception";
        result.message = "feedback publication raised a nonstandard exception";
        return result;
    }
}

}
