#include "semantic_fusion.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <tuple>
#include <type_traits>
#include <utility>

namespace aida::analysis {

namespace {

constexpr std::uint64_t k_fnv_offset = 1469598103934665603ULL;
constexpr std::uint64_t k_fnv_prime = 1099511628211ULL;

class fingerprint_builder_t final {
public:
    void add_byte(std::uint8_t value) noexcept {
        value_ ^= value;
        value_ *= k_fnv_prime;
    }

    template <typename T>
    void add_integral(T value) noexcept {
        if constexpr (std::is_same_v<std::remove_cv_t<T>, bool>) {
            add_byte(value ? 1U : 0U);
        } else {
            using unsigned_t = std::make_unsigned_t<T>;
            auto bits = static_cast<unsigned_t>(value);
            for (std::size_t i = 0; i < sizeof(bits); ++i) {
                add_byte(static_cast<std::uint8_t>(bits & 0xffU));
                bits >>= 8U;
            }
        }
    }

    void add_string(const std::string& value) noexcept {
        add_integral<std::uint64_t>(value.size());
        for (unsigned char ch : value)
            add_byte(ch);
    }

    std::uint64_t finish() const noexcept { return value_; }

private:
    std::uint64_t value_ = k_fnv_offset;
};

std::string number(std::uint64_t value) {
    return std::to_string(value);
}

std::string signed_number(std::int64_t value) {
    return std::to_string(value);
}

void append_field(std::string& target, const std::string& value) {
    target.append(number(value.size()));
    target.push_back(':');
    target.append(value);
    target.push_back('|');
}

template <typename T>
void append_field(std::string& target, T value) {
    append_field(target, number(static_cast<std::uint64_t>(value)));
}

void append_signed_field(std::string& target, std::int64_t value) {
    append_field(target, signed_number(value));
}

std::string canonical_address(const address_t& address) {
    std::string value;
    append_field(value, static_cast<std::uint8_t>(address.space));
    append_field(value, address.value);
    append_field(value, static_cast<std::uint8_t>(address.architecture));
    append_field(value, static_cast<std::uint8_t>(address.mode));
    return value;
}

std::string canonical_location(const semantic_location_t& location) {
    std::string value;
    append_field(value, static_cast<std::uint8_t>(location.kind));
    append_field(value, static_cast<std::uint8_t>(location.address_space));
    append_field(value, location.register_id);
    append_signed_field(value, location.stack_offset);
    append_field(value, location.global_address);
    append_field(value, location.temporary_id);
    append_field(value, location.version);
    append_field(value, location.bit_width);
    append_field(value, location.is_signed);
    return value;
}

std::string canonical_subject(const semantic_subject_t& subject) {
    std::string value;
    append_field(value, static_cast<std::uint8_t>(subject.kind));
    append_field(value, subject.function_id);
    append_field(value, subject.instruction_id);
    append_field(value, canonical_address(subject.address));
    append_field(value, canonical_location(subject.location));
    append_field(value, subject.ordinal);
    return value;
}

std::string canonical_type(const semantic_type_descriptor_t& type) {
    std::string value;
    append_field(value, static_cast<std::uint8_t>(type.kind));
    append_field(value, type.bit_width);
    append_field(value, type.pointer_depth);
    append_field(value, type.type_id);
    append_field(value, type.is_signed);
    append_field(value, type.is_const);
    append_field(value, type.display_name);
    return value;
}

std::string canonical_provenance(const semantic_provenance_t& provenance) {
    std::string value;
    append_field(value, static_cast<std::uint8_t>(provenance.origin));
    append_field(value, static_cast<std::uint8_t>(provenance.source));
    append_field(value, provenance.source_entity_id);
    append_field(value, canonical_address(provenance.source_address));
    append_field(value, provenance.stable_source_id);
    append_field(value, provenance.source_generation);
    append_field(value, provenance.source_analysis_revision);
    append_field(value, provenance.source_overlay_revision);
    append_field(value, provenance.independently_validated);
    return value;
}

std::string canonical_payload(const constant_value_t& value) {
    std::string result;
    append_field(result, static_cast<std::uint8_t>(value.kind));
    append_field(result, value.value);
    append_field(result, value.bit_width);
    append_field(result, value.known);
    append_field(result, value.symbolic);
    append_field(result, value.is_signed);
    append_field(result, value.definition_rva);
    return result;
}

std::string canonical_payload(const value_range_t& value) {
    std::string result;
    append_field(result, value.min);
    append_field(result, value.max);
    append_field(result, value.bit_width);
    append_field(result, value.bounded);
    append_field(result, value.is_signed);
    append_field(result, value.wraps);
    return result;
}

std::string canonical_payload(const simplified_expression_t& value) {
    std::string result;
    append_field(result, value.instruction_id);
    append_field(result, canonical_address(value.address));
    append_field(result, static_cast<std::uint8_t>(value.kind));
    append_field(result, canonical_location(value.result));
    append_field(result, value.left_value);
    append_field(result, value.right_value);
    append_field(result, value.result_value);
    append_field(result, value.folded);
    return result;
}

std::string canonical_payload(const control_flow_evidence_t& value) {
    std::string result;
    append_field(result, static_cast<std::uint8_t>(value.kind));
    append_field(result, value.source_instruction_id);
    append_field(result, value.target_function_id);
    append_field(result, canonical_address(value.source));
    append_field(result, canonical_address(value.target));
    append_field(result, value.switch_value);
    append_field(result, value.switch_index);
    append_field(result, value.direct);
    append_field(result, value.external);
    append_field(result, value.noreturn);
    append_field(result, value.resolved);
    return result;
}

std::string canonical_payload(const location_access_evidence_t& value) {
    std::string result;
    append_field(result, canonical_location(value.location));
    append_field(result, value.instruction_id);
    append_field(result, canonical_address(value.address));
    append_field(result, value.access_width_bits);
    append_field(result, value.access_count);
    append_field(result, value.access);
    append_field(result, value.volatile_access);
    return result;
}

std::string canonical_definition(const definition_site_t& value) {
    std::string result;
    append_field(result, value.instruction_id);
    append_field(result, canonical_address(value.address));
    append_field(result, canonical_location(value.location));
    return result;
}

std::string canonical_payload(const use_def_evidence_t& value) {
    std::string result;
    append_field(result, canonical_location(value.location));
    append_field(result, canonical_definition(value.definition));
    append_field(result, value.use_instruction_id);
    append_field(result, canonical_address(value.use_address));
    append_field(result, value.definite);
    return result;
}

std::string canonical_payload(const liveness_evidence_t& value) {
    const auto& range = value.range;
    std::string result;
    append_field(result, canonical_location(range.location));
    append_field(result, range.definition_instruction);
    append_field(result, range.last_use_instruction);
    append_field(result, canonical_address(range.definition_address));
    append_field(result, canonical_address(range.last_use_address));
    append_field(result, range.live_in);
    append_field(result, range.live_out);
    append_field(result, value.exact);
    return result;
}

std::string canonical_payload(const alias_evidence_t& value) {
    std::string result;
    append_field(result, canonical_location(value.left));
    append_field(result, canonical_location(value.right));
    append_field(result, static_cast<std::uint8_t>(value.relation));
    append_field(result, value.access_width_bits);
    return result;
}

std::string canonical_payload(const prototype_evidence_t& value) {
    std::string result;
    append_field(result, canonical_address(value.function));
    append_field(result, static_cast<std::uint8_t>(value.abi));
    append_field(result, value.arguments.size());
    for (const auto& argument : value.arguments)
        append_field(result, canonical_type(argument));
    append_field(result, canonical_type(value.return_type));
    append_field(result, value.variadic);
    append_field(result, value.noreturn);
    return result;
}

std::string canonical_payload(const calling_convention_evidence_t& value) {
    std::string result;
    append_field(result, canonical_address(value.function));
    append_field(result, static_cast<std::uint8_t>(value.abi));
    append_field(result, value.stack_pointer_register);
    append_field(result, value.frame_pointer_register);
    append_field(result, value.return_register);
    append_field(result, value.stack_alignment);
    append_field(result, value.shadow_space_size);
    append_field(result, value.uses_frame_pointer);
    append_field(result, value.variadic);
    return result;
}

std::string canonical_payload(const type_evidence_t& value) {
    std::string result;
    append_field(result, canonical_location(value.location));
    append_field(result, canonical_type(value.type));
    append_field(result, value.instruction_id);
    append_field(result, canonical_address(value.address));
    return result;
}

std::string canonical_payload(const metadata_evidence_t& value) {
    std::string result;
    append_field(result, static_cast<std::uint8_t>(value.kind));
    append_field(result, canonical_address(value.address));
    append_field(result, value.value);
    append_field(result, value.name);
    append_field(result, value.authoritative);
    return result;
}

std::string canonical_payload(const idiom_evidence_t& value) {
    std::string result;
    append_field(result, static_cast<std::uint8_t>(value.idiom));
    append_field(result, static_cast<std::uint8_t>(value.intrinsic));
    append_field(result, static_cast<std::uint8_t>(value.runtime));
    append_field(result, value.instruction_id);
    append_field(result, canonical_address(value.address));
    append_field(result, value.name);
    return result;
}

std::string canonical_payload(const branch_feasibility_evidence_t& value) {
    std::string result;
    append_field(result, value.instruction_id);
    append_field(result, canonical_address(value.branch));
    append_field(result, canonical_address(value.target));
    append_field(result, static_cast<std::uint8_t>(value.feasibility));
    append_field(result, value.condition_known);
    return result;
}

std::string canonical_payload(const semantic_fact_payload_t& payload) {
    return std::visit([](const auto& value) { return canonical_payload(value); }, payload);
}

std::string canonical_evidence(const semantic_evidence_t& evidence) {
    std::string result;
    append_field(result, evidence.evidence_id);
    append_field(result, static_cast<std::uint8_t>(evidence.kind));
    append_field(result, canonical_subject(evidence.subject));
    append_field(result, canonical_payload(evidence.payload));
    append_field(result, canonical_provenance(evidence.provenance));
    append_field(result, static_cast<std::uint8_t>(evidence.validation));
    append_field(result, evidence.confidence);
    return result;
}

bool payload_matches_kind(const semantic_evidence_t& evidence) noexcept {
    switch (evidence.kind) {
        case semantic_fact_kind_t::value:
            return std::holds_alternative<constant_value_t>(evidence.payload);
        case semantic_fact_kind_t::value_range:
            return std::holds_alternative<value_range_t>(evidence.payload);
        case semantic_fact_kind_t::expression_simplification:
            return std::holds_alternative<simplified_expression_t>(evidence.payload);
        case semantic_fact_kind_t::control_flow:
            return std::holds_alternative<control_flow_evidence_t>(evidence.payload);
        case semantic_fact_kind_t::location_access:
            return std::holds_alternative<location_access_evidence_t>(evidence.payload);
        case semantic_fact_kind_t::use_def:
            return std::holds_alternative<use_def_evidence_t>(evidence.payload);
        case semantic_fact_kind_t::liveness:
            return std::holds_alternative<liveness_evidence_t>(evidence.payload);
        case semantic_fact_kind_t::alias:
            return std::holds_alternative<alias_evidence_t>(evidence.payload);
        case semantic_fact_kind_t::prototype:
            return std::holds_alternative<prototype_evidence_t>(evidence.payload);
        case semantic_fact_kind_t::calling_convention:
            return std::holds_alternative<calling_convention_evidence_t>(evidence.payload);
        case semantic_fact_kind_t::type:
            return std::holds_alternative<type_evidence_t>(evidence.payload);
        case semantic_fact_kind_t::metadata:
            return std::holds_alternative<metadata_evidence_t>(evidence.payload);
        case semantic_fact_kind_t::idiom:
            return std::holds_alternative<idiom_evidence_t>(evidence.payload);
        case semantic_fact_kind_t::branch_feasibility:
            return std::holds_alternative<branch_feasibility_evidence_t>(evidence.payload);
    }
    return false;
}

bool address_matches_scope(const address_t& address,
                           const semantic_scope_key_t& scope) noexcept {
    if (address.architecture != architecture_id_t::unknown &&
        scope.architecture != architecture_id_t::unknown &&
        address.architecture != scope.architecture)
        return false;
    if (address.mode != architecture_mode_t::unknown &&
        scope.architecture_mode != architecture_mode_t::unknown &&
        address.mode != scope.architecture_mode)
        return false;
    return true;
}

bool evidence_matches_scope(const semantic_evidence_t& evidence,
                            const semantic_scope_key_t& scope) noexcept {
    const semantic_provenance_t& provenance = evidence.provenance;
    if (!address_matches_scope(evidence.subject.address, scope) ||
        !address_matches_scope(provenance.source_address, scope))
        return false;
    if (provenance.source_generation != 0 && scope.generation != 0 &&
        provenance.source_generation != scope.generation)
        return false;
    if (provenance.source_analysis_revision != 0 && scope.analysis_revision != 0 &&
        provenance.source_analysis_revision != scope.analysis_revision)
        return false;
    if (provenance.source_overlay_revision != 0 && scope.overlay_revision != 0 &&
        provenance.source_overlay_revision != scope.overlay_revision)
        return false;
    return true;
}

std::string canonical_source(const semantic_evidence_t& evidence,
                             std::uint64_t fallback) {
    std::string result = canonical_provenance(evidence.provenance);
    if (evidence.provenance.source_entity_id == 0 &&
        evidence.provenance.stable_source_id == 0 &&
        evidence.provenance.source_address.value == 0) {
        append_field(result, evidence.evidence_id == 0 ? fallback : evidence.evidence_id);
    }
    return result;
}

bool is_terminal(const cancellation_token_t& cancel,
                 semantic_fusion_result_t& result) {
    if (cancel.deadline_exceeded()) {
        result.deadline_exceeded = true;
        result.cancelled = true;
        return true;
    }
    if (cancel.cancellation_requested() || cancel.stop_requested()) {
        result.cancelled = true;
        return true;
    }
    return false;
}

semantic_validation_t best_validation(semantic_validation_t lhs,
                                      semantic_validation_t rhs) noexcept {
    if (lhs == semantic_validation_t::validated || rhs == semantic_validation_t::validated)
        return semantic_validation_t::validated;
    if (lhs == semantic_validation_t::derived || rhs == semantic_validation_t::derived)
        return semantic_validation_t::derived;
    if (lhs == semantic_validation_t::unvalidated || rhs == semantic_validation_t::unvalidated)
        return semantic_validation_t::unvalidated;
    if (lhs == semantic_validation_t::abstained || rhs == semantic_validation_t::abstained)
        return semantic_validation_t::abstained;
    return semantic_validation_t::rejected;
}

std::uint8_t validation_rank(semantic_validation_t value) noexcept {
    switch (value) {
        case semantic_validation_t::rejected: return 0;
        case semantic_validation_t::unvalidated: return 1;
        case semantic_validation_t::derived: return 2;
        case semantic_validation_t::validated: return 3;
        case semantic_validation_t::abstained: return 0;
    }
    return 0;
}

std::uint16_t evidence_strength(const semantic_evidence_t& evidence) noexcept {
    if (evidence.validation == semantic_validation_t::rejected ||
        evidence.validation == semantic_validation_t::abstained)
        return 0;
    std::uint16_t score = evidence.confidence;
    score += static_cast<std::uint16_t>(provenance_rank(evidence.provenance.source)) * 4U;
    score += static_cast<std::uint16_t>(evidence.provenance.origin) * 8U;
    score += static_cast<std::uint16_t>(validation_rank(evidence.validation)) * 32U;
    if (evidence.provenance.independently_validated)
        score += 32U;
    return score;
}

std::uint8_t aggregate_confidence(const std::vector<const semantic_evidence_t*>& evidence) noexcept {
    std::uint16_t maximum = 0;
    std::uint16_t count = 0;
    for (const auto* item : evidence) {
        maximum = std::max<std::uint16_t>(maximum, item->confidence);
        if (count != std::numeric_limits<std::uint16_t>::max())
            ++count;
    }
    const std::uint16_t bonus = std::min<std::uint16_t>(48U, count > 0 ? count - 1U : 0U);
    return static_cast<std::uint8_t>(std::min<std::uint16_t>(255U, maximum + bonus));
}

void append_abstention(semantic_fusion_result_t& result,
                       const semantic_merge_budget_t& budget,
                       semantic_fact_kind_t kind,
                       const semantic_subject_t& subject,
                       semantic_abstention_reason_t reason,
                       std::vector<std::uint64_t> evidence_ids = {}) {
    if (result.abstentions.size() >= budget.max_abstentions) {
        result.bounded = true;
        return;
    }
    std::sort(evidence_ids.begin(), evidence_ids.end());
    evidence_ids.erase(std::unique(evidence_ids.begin(), evidence_ids.end()), evidence_ids.end());
    semantic_abstention_t abstention;
    abstention.kind = kind;
    abstention.subject = subject;
    abstention.reason = reason;
    abstention.evidence_ids = std::move(evidence_ids);
    result.abstentions.push_back(std::move(abstention));
}

void append_conflict(semantic_fusion_result_t& result,
                     const semantic_merge_budget_t& budget,
                     semantic_fact_kind_t kind,
                     const semantic_subject_t& subject,
                     std::vector<std::uint64_t> selected,
                     std::vector<std::uint64_t> conflicting,
                     semantic_resolution_t resolution,
                     std::uint16_t selected_strength,
                     std::uint16_t conflicting_strength) {
    if (result.conflicts.size() >= budget.max_conflicts) {
        result.bounded = true;
        return;
    }
    std::sort(selected.begin(), selected.end());
    selected.erase(std::unique(selected.begin(), selected.end()), selected.end());
    std::sort(conflicting.begin(), conflicting.end());
    conflicting.erase(std::unique(conflicting.begin(), conflicting.end()), conflicting.end());
    semantic_conflict_t conflict;
    conflict.kind = kind;
    conflict.subject = subject;
    conflict.selected_evidence_ids = std::move(selected);
    conflict.conflicting_evidence_ids = std::move(conflicting);
    conflict.resolution = resolution;
    conflict.selected_strength = selected_strength;
    conflict.conflicting_strength = conflicting_strength;
    result.conflicts.push_back(std::move(conflict));
}

bool provenance_less(const semantic_provenance_t& lhs,
                     const semantic_provenance_t& rhs) {
    return canonical_provenance(lhs) < canonical_provenance(rhs);
}

struct candidate_t {
    std::string payload_key;
    std::vector<const semantic_evidence_t*> evidence;
    std::uint16_t strength = 0;
    std::size_t independent_sources = 0;
    semantic_validation_t validation = semantic_validation_t::rejected;
    bool independently_validated = false;
};

bool candidate_better(const candidate_t& lhs, const candidate_t& rhs) {
    if (lhs.strength != rhs.strength)
        return lhs.strength > rhs.strength;
    if (validation_rank(lhs.validation) != validation_rank(rhs.validation))
        return validation_rank(lhs.validation) > validation_rank(rhs.validation);
    if (lhs.independent_sources != rhs.independent_sources)
        return lhs.independent_sources > rhs.independent_sources;
    return lhs.payload_key < rhs.payload_key;
}

std::uint64_t canonical_id(const semantic_evidence_t& evidence,
                           std::uint64_t fallback) noexcept {
    return evidence.evidence_id == 0 ? fallback : evidence.evidence_id;
}

semantic_abstention_reason_t abstention_reason_from_evidence(
    const semantic_evidence_t& evidence) {
    if (const auto* branch = std::get_if<branch_feasibility_evidence_t>(&evidence.payload)) {
        if (branch->feasibility == branch_feasibility_t::unknown || !branch->condition_known)
            return semantic_abstention_reason_t::unknown_branch_condition;
    }
    if (const auto* control_flow = std::get_if<control_flow_evidence_t>(&evidence.payload)) {
        if (control_flow->kind == control_flow_kind_t::indirect_jump || !control_flow->resolved)
            return semantic_abstention_reason_t::unresolved_indirect_target;
    }
    return semantic_abstention_reason_t::insufficient_evidence;
}

semantic_location_t location_from_operand(const operand_fact_t& operand) {
    semantic_location_t location;
    location.address_space = operand.address_resolution == target_resolution_t::external_virtual
                                 ? address_space_id_t::virtual_address
                                 : address_space_id_t::relative_virtual;
    location.bit_width = operand.bit_width == 0 ? operand.access_width_bits : operand.bit_width;
    location.is_signed = operand.signed_value;
    if (operand.kind == operand_kind_t::reg) {
        location.kind = semantic_location_kind_t::register_value;
        location.register_id = operand.reg;
    } else if (operand.kind == operand_kind_t::immediate) {
        location.kind = semantic_location_kind_t::immediate_value;
        location.temporary_id = operand.operand_index;
    } else if (operand.kind == operand_kind_t::memory) {
        if (operand.address_expression == address_expression_kind_t::instruction_relative &&
            operand.has_resolved_expression_value) {
            location.kind = semantic_location_kind_t::global_address;
            location.global_address = operand.resolved_expression_value;
        } else {
            location.kind = semantic_location_kind_t::memory_address;
            location.register_id = operand.base_reg;
            location.stack_offset = operand.displacement;
            location.temporary_id = operand.index_reg;
        }
    }
    return location;
}

semantic_provenance_t provenance_from_instruction(const analysis_snapshot_t& snapshot,
                                                  const instruction_record_t& instruction,
                                                  semantic_origin_t origin) {
    semantic_provenance_t provenance;
    provenance.origin = origin;
    provenance.source = instruction.provenance;
    provenance.source_entity_id = instruction.id;
    provenance.source_address = instruction.address;
    provenance.stable_source_id = instruction.stable_source_id;
    provenance.source_generation = snapshot.generation;
    provenance.source_analysis_revision = snapshot.analysis_revision;
    provenance.source_overlay_revision = snapshot.overlay_revision;
    return provenance;
}

semantic_validation_t validation_from_instruction(const instruction_record_t& instruction) noexcept {
    return instruction.confidence >= 128 ? semantic_validation_t::derived
                                         : semantic_validation_t::unvalidated;
}

std::uint8_t max_confidence(std::uint8_t lhs, std::uint8_t rhs) noexcept {
    return lhs > rhs ? lhs : rhs;
}

control_flow_kind_t control_flow_kind_from_target(target_kind_record_t kind,
                                                  const instruction_record_t& instruction) noexcept {
    if (kind == target_kind_record_t::call)
        return (instruction.flow_flags & flow_branch) != 0 ? control_flow_kind_t::tail_call
                                                            : control_flow_kind_t::call;
    if (kind == target_kind_record_t::fallthrough || kind == target_kind_record_t::data)
        return control_flow_kind_t::unknown;
    if ((instruction.flow_flags & flow_indirect) != 0)
        return control_flow_kind_t::indirect_jump;
    if ((instruction.flow_flags & flow_conditional) != 0)
        return control_flow_kind_t::conditional_jump;
    return control_flow_kind_t::unconditional_jump;
}

struct workspace_collection_t {
    std::vector<semantic_evidence_t> evidence;
    std::vector<semantic_abstention_t> abstentions;
    std::uint64_t collected = 0;
    bool bounded = false;
    bool cancelled = false;
    bool deadline_exceeded = false;
};

void collection_abstain(workspace_collection_t& collection,
                        const semantic_merge_budget_t& budget,
                        semantic_fact_kind_t kind,
                        const semantic_subject_t& subject,
                        semantic_abstention_reason_t reason) {
    if (collection.abstentions.size() >= budget.max_abstentions) {
        collection.bounded = true;
        return;
    }
    semantic_abstention_t abstention;
    abstention.kind = kind;
    abstention.subject = subject;
    abstention.reason = reason;
    collection.abstentions.push_back(std::move(abstention));
}

workspace_collection_t collect_workspace_evidence(const analysis_workspace_t& workspace,
                                                   const analysis_snapshot_t& snapshot,
                                                   const semantic_scope_key_t& scope,
                                                   const semantic_fusion_request_t& request,
                                                   const cancellation_token_t& cancel) {
    workspace_collection_t collection;
    const function_record_t* function = nullptr;
    const std::uint64_t expected_address = request.function_address ? request.function_address->value
                                                                     : request.function_rva;
    for (const auto& candidate : snapshot.functions) {
        if (candidate.start.value == expected_address &&
            (!request.function_address || candidate.start == *request.function_address)) {
            function = &candidate;
            break;
        }
    }
    if (!function) {
        semantic_subject_t subject;
        subject.kind = semantic_subject_kind_t::function;
        subject.address = scope.function_address;
        collection_abstain(collection, request.budget, semantic_fact_kind_t::metadata, subject,
                           semantic_abstention_reason_t::target_not_found);
        return collection;
    }

    std::vector<const basic_block_record_t*> blocks;
    for (const auto& block : snapshot.blocks) {
        if (block.function_id == function->id)
            blocks.push_back(&block);
    }
    std::sort(blocks.begin(), blocks.end(), [](const auto* lhs, const auto* rhs) {
        if (lhs->start != rhs->start)
            return lhs->start < rhs->start;
        return lhs->id < rhs->id;
    });

    std::vector<const instruction_record_t*> instructions;
    for (const auto* block : blocks) {
        for (std::uint32_t offset = 0; offset < block->instruction_count; ++offset) {
            const std::uint64_t index = static_cast<std::uint64_t>(block->first_instruction) + offset;
            if (index < snapshot.instructions.size())
                instructions.push_back(&snapshot.instructions[static_cast<std::size_t>(index)]);
        }
    }
    std::sort(instructions.begin(), instructions.end(), [](const auto* lhs, const auto* rhs) {
        if (lhs->address != rhs->address)
            return lhs->address < rhs->address;
        return lhs->id < rhs->id;
    });
    instructions.erase(std::unique(instructions.begin(), instructions.end(),
                                   [](const auto* lhs, const auto* rhs) { return lhs->id == rhs->id; }),
                       instructions.end());

    if (instructions.size() > request.budget.max_workspace_instructions) {
        instructions.resize(request.budget.max_workspace_instructions);
        collection.bounded = true;
    }

    std::map<std::uint16_t, definition_site_t> last_register_definition;
    std::map<std::string, semantic_location_t> first_global_access;
    std::uint64_t next_evidence_id = 1;
    const std::size_t poll_interval = std::max<std::size_t>(1, request.budget.cancellation_poll_interval);

    auto append = [&](semantic_evidence_t evidence) {
        if (collection.evidence.size() >= request.budget.max_evidence_records) {
            collection.bounded = true;
            return;
        }
        evidence.evidence_id = next_evidence_id++;
        collection.evidence.push_back(std::move(evidence));
        ++collection.collected;
    };

    for (std::size_t instruction_index = 0; instruction_index < instructions.size(); ++instruction_index) {
        if ((instruction_index % poll_interval) == 0) {
            if (cancel.deadline_exceeded()) {
                collection.cancelled = true;
                collection.deadline_exceeded = true;
                return collection;
            }
            if (cancel.cancellation_requested() || cancel.stop_requested()) {
                collection.cancelled = true;
                return collection;
            }
        }

        const instruction_record_t& instruction = *instructions[instruction_index];
        const semantic_provenance_t provenance = provenance_from_instruction(
            snapshot, instruction, semantic_origin_t::workspace_decode);
        const semantic_validation_t instruction_validation = validation_from_instruction(instruction);
        std::vector<std::uint16_t> read_registers;
        std::vector<std::uint16_t> written_registers;

        for (std::uint16_t operand_offset = 0;
             operand_offset < instruction.operand_fact_count;
             ++operand_offset) {
            const std::uint64_t operand_index =
                static_cast<std::uint64_t>(instruction.operand_fact_begin) + operand_offset;
            if (operand_index >= snapshot.operand_facts.size())
                break;
            const operand_fact_t& operand = snapshot.operand_facts[static_cast<std::size_t>(operand_index)];
            const semantic_location_t location = location_from_operand(operand);

            if (operand.kind == operand_kind_t::reg) {
                if ((operand.access & 1U) != 0)
                    read_registers.push_back(operand.reg);
                if ((operand.access & 2U) != 0)
                    written_registers.push_back(operand.reg);
            }

            if (location.kind != semantic_location_kind_t::unknown &&
                operand.kind != operand_kind_t::immediate) {
                semantic_evidence_t access;
                access.kind = semantic_fact_kind_t::location_access;
                access.subject.kind = semantic_subject_kind_t::location;
                access.subject.function_id = function->id;
                access.subject.instruction_id = instruction.id;
                access.subject.address = instruction.address;
                access.subject.location = location;
                access.subject.ordinal = operand.operand_index;
                location_access_evidence_t payload;
                payload.location = location;
                payload.instruction_id = instruction.id;
                payload.address = instruction.address;
                payload.access_width_bits = operand.access_width_bits;
                payload.access_count = operand.access_count;
                payload.access = operand.access;
                access.payload = std::move(payload);
                access.provenance = provenance;
                access.validation = instruction_validation;
                access.confidence = instruction.confidence;
                append(std::move(access));
            }

            if (operand.kind == operand_kind_t::immediate) {
                semantic_evidence_t value;
                value.kind = semantic_fact_kind_t::value;
                value.subject.kind = semantic_subject_kind_t::location;
                value.subject.function_id = function->id;
                value.subject.instruction_id = instruction.id;
                value.subject.address = instruction.address;
                value.subject.location = location;
                value.subject.ordinal = operand.operand_index;
                constant_value_t payload;
                payload.kind = semantic_value_kind_t::constant;
                payload.value = operand.immediate;
                payload.bit_width = operand.bit_width;
                payload.known = true;
                payload.is_signed = operand.signed_value;
                payload.definition_rva = instruction.address.value;
                value.payload = payload;
                value.provenance = provenance;
                value.validation = instruction_validation;
                value.confidence = instruction.confidence;
                append(std::move(value));

                semantic_evidence_t range;
                range.kind = semantic_fact_kind_t::value_range;
                range.subject.kind = semantic_subject_kind_t::location;
                range.subject.function_id = function->id;
                range.subject.instruction_id = instruction.id;
                range.subject.address = instruction.address;
                range.subject.location = location;
                range.subject.ordinal = operand.operand_index;
                value_range_t range_payload;
                range_payload.min = operand.immediate;
                range_payload.max = operand.immediate;
                range_payload.bit_width = operand.bit_width;
                range_payload.bounded = true;
                range_payload.is_signed = operand.signed_value;
                range.payload = range_payload;
                range.provenance = provenance;
                range.validation = instruction_validation;
                range.confidence = instruction.confidence;
                append(std::move(range));
            }

            if (location.kind == semantic_location_kind_t::global_address) {
                const std::string location_key = canonical_location(location);
                const auto existing = first_global_access.find(location_key);
                if (existing == first_global_access.end()) {
                    first_global_access.emplace(location_key, location);
                } else {
                    semantic_evidence_t alias;
                    alias.kind = semantic_fact_kind_t::alias;
                    alias.subject.kind = semantic_subject_kind_t::location;
                    alias.subject.function_id = function->id;
                    alias.subject.instruction_id = instruction.id;
                    alias.subject.address = instruction.address;
                    alias.subject.location = location;
                    alias.subject.ordinal = operand.operand_index;
                    alias_evidence_t payload;
                    payload.left = existing->second;
                    payload.right = location;
                    payload.relation = alias_relation_t::must_alias;
                    payload.access_width_bits = operand.access_width_bits;
                    alias.payload = payload;
                    alias.provenance = provenance;
                    alias.validation = instruction_validation;
                    alias.confidence = instruction.confidence;
                    append(std::move(alias));
                }
            }
        }

        std::sort(read_registers.begin(), read_registers.end());
        read_registers.erase(std::unique(read_registers.begin(), read_registers.end()), read_registers.end());
        std::sort(written_registers.begin(), written_registers.end());
        written_registers.erase(std::unique(written_registers.begin(), written_registers.end()), written_registers.end());

        for (std::uint16_t register_id : read_registers) {
            const auto definition = last_register_definition.find(register_id);
            if (definition == last_register_definition.end())
                continue;
            semantic_evidence_t use_def;
            use_def.kind = semantic_fact_kind_t::use_def;
            use_def.subject.kind = semantic_subject_kind_t::location;
            use_def.subject.function_id = function->id;
            use_def.subject.instruction_id = instruction.id;
            use_def.subject.address = instruction.address;
            use_def.subject.location.kind = semantic_location_kind_t::register_value;
            use_def.subject.location.register_id = register_id;
            use_def.subject.ordinal = definition->second.instruction_id;
            use_def_evidence_t payload;
            payload.location = use_def.subject.location;
            payload.definition = definition->second;
            payload.use_instruction_id = instruction.id;
            payload.use_address = instruction.address;
            payload.definite = false;
            use_def.payload = std::move(payload);
            use_def.provenance = provenance;
            use_def.validation = semantic_validation_t::unvalidated;
            use_def.confidence = instruction.confidence;
            append(std::move(use_def));
        }

        for (std::uint16_t register_id : written_registers) {
            definition_site_t definition;
            definition.instruction_id = instruction.id;
            definition.address = instruction.address;
            definition.location.kind = semantic_location_kind_t::register_value;
            definition.location.register_id = register_id;
            last_register_definition[register_id] = std::move(definition);
        }

        for (std::uint16_t target_offset = 0;
             target_offset < instruction.target_fact_count;
             ++target_offset) {
            const std::uint64_t target_index =
                static_cast<std::uint64_t>(instruction.target_fact_begin) + target_offset;
            if (target_index >= snapshot.target_facts.size())
                break;
            const target_fact_t& target = snapshot.target_facts[static_cast<std::size_t>(target_index)];
            if (target.kind == target_kind_record_t::data ||
                target.kind == target_kind_record_t::fallthrough)
                continue;
            semantic_evidence_t control_flow;
            control_flow.kind = semantic_fact_kind_t::control_flow;
            control_flow.subject.kind = target.kind == target_kind_record_t::call
                                            ? semantic_subject_kind_t::call_target
                                            : semantic_subject_kind_t::edge;
            control_flow.subject.function_id = function->id;
            control_flow.subject.instruction_id = instruction.id;
            control_flow.subject.address = instruction.address;
            control_flow.subject.ordinal = target_offset;
            control_flow_evidence_t payload;
            payload.kind = control_flow_kind_from_target(target.kind, instruction);
            payload.source_instruction_id = instruction.id;
            payload.source = instruction.address;
            payload.target = target.target;
            payload.direct = target.direct;
            payload.external = target.is_external;
            payload.resolved = target.resolution != target_resolution_t::unresolved_indirect;
            control_flow.payload = std::move(payload);
            control_flow.provenance = provenance;
            control_flow.validation = target.direct && control_flow.provenance.source != fact_provenance_t::unknown
                                          ? semantic_validation_t::validated
                                          : instruction_validation;
            control_flow.confidence = max_confidence(instruction.confidence, 128U);
            append(std::move(control_flow));
        }

        if ((instruction.flow_flags & flow_conditional) != 0) {
            semantic_evidence_t branch;
            branch.kind = semantic_fact_kind_t::branch_feasibility;
            branch.subject.kind = semantic_subject_kind_t::instruction;
            branch.subject.function_id = function->id;
            branch.subject.instruction_id = instruction.id;
            branch.subject.address = instruction.address;
            branch_feasibility_evidence_t payload;
            payload.instruction_id = instruction.id;
            payload.branch = instruction.address;
            payload.feasibility = branch_feasibility_t::unknown;
            payload.condition_known = false;
            branch.payload = std::move(payload);
            branch.provenance = provenance;
            branch.validation = semantic_validation_t::abstained;
            branch.confidence = instruction.confidence;
            append(std::move(branch));
        }

        if ((instruction.flow_flags & flow_indirect) != 0) {
            semantic_evidence_t indirect;
            indirect.kind = semantic_fact_kind_t::control_flow;
            indirect.subject.kind = semantic_subject_kind_t::instruction;
            indirect.subject.function_id = function->id;
            indirect.subject.instruction_id = instruction.id;
            indirect.subject.address = instruction.address;
            control_flow_evidence_t payload;
            payload.kind = control_flow_kind_t::indirect_jump;
            payload.source_instruction_id = instruction.id;
            payload.source = instruction.address;
            indirect.payload = std::move(payload);
            indirect.provenance = provenance;
            indirect.validation = semantic_validation_t::abstained;
            indirect.confidence = instruction.confidence;
            append(std::move(indirect));
        }
    }

    semantic_evidence_t prototype;
    prototype.kind = semantic_fact_kind_t::prototype;
    prototype.subject.kind = semantic_subject_kind_t::function;
    prototype.subject.function_id = function->id;
    prototype.subject.address = function->start;
    prototype_evidence_t prototype_payload;
    prototype_payload.function = function->start;
    prototype_payload.abi = workspace.identity().abi();
    prototype.payload = std::move(prototype_payload);
    prototype.provenance.origin = semantic_origin_t::workspace_cfg;
    prototype.provenance.source = function->provenance;
    prototype.provenance.source_entity_id = function->id;
    prototype.provenance.source_address = function->start;
    prototype.provenance.source_generation = snapshot.generation;
    prototype.provenance.source_analysis_revision = snapshot.analysis_revision;
    prototype.provenance.source_overlay_revision = snapshot.overlay_revision;
    prototype.validation = semantic_validation_t::abstained;
    prototype.confidence = function->confidence;
    append(std::move(prototype));

    semantic_evidence_t convention;
    convention.kind = semantic_fact_kind_t::calling_convention;
    convention.subject.kind = semantic_subject_kind_t::function;
    convention.subject.function_id = function->id;
    convention.subject.address = function->start;
    calling_convention_evidence_t convention_payload;
    convention_payload.function = function->start;
    convention_payload.abi = workspace.identity().abi();
    convention.payload = std::move(convention_payload);
    convention.provenance.origin = semantic_origin_t::workspace_cfg;
    convention.provenance.source = function->provenance;
    convention.provenance.source_entity_id = function->id;
    convention.provenance.source_address = function->start;
    convention.provenance.source_generation = snapshot.generation;
    convention.provenance.source_analysis_revision = snapshot.analysis_revision;
    convention.provenance.source_overlay_revision = snapshot.overlay_revision;
    convention.validation = semantic_validation_t::abstained;
    convention.confidence = function->confidence;
    append(std::move(convention));

    if (function->thunk) {
        semantic_evidence_t thunk;
        thunk.kind = semantic_fact_kind_t::control_flow;
        thunk.subject.kind = semantic_subject_kind_t::function;
        thunk.subject.function_id = function->id;
        thunk.subject.address = function->start;
        control_flow_evidence_t thunk_payload;
        thunk_payload.kind = control_flow_kind_t::thunk;
        thunk_payload.source = function->start;
        thunk.payload = std::move(thunk_payload);
        thunk.provenance.origin = semantic_origin_t::workspace_metadata;
        thunk.provenance.source = function->provenance;
        thunk.provenance.source_entity_id = function->id;
        thunk.provenance.source_address = function->start;
        thunk.provenance.source_generation = snapshot.generation;
        thunk.provenance.source_analysis_revision = snapshot.analysis_revision;
        thunk.provenance.source_overlay_revision = snapshot.overlay_revision;
        thunk.validation = semantic_validation_t::derived;
        thunk.confidence = function->confidence;
        append(std::move(thunk));
    }

    return collection;
}

void append_collection_abstentions(semantic_fusion_result_t& result,
                                  const workspace_collection_t& collection,
                                  const semantic_merge_budget_t& budget) {
    for (const auto& abstention : collection.abstentions) {
        append_abstention(result, budget, abstention.kind, abstention.subject,
                          abstention.reason, abstention.evidence_ids);
    }
}

}

bool operator==(const semantic_location_t& lhs, const semantic_location_t& rhs) noexcept {
    return lhs.kind == rhs.kind && lhs.address_space == rhs.address_space &&
           lhs.register_id == rhs.register_id && lhs.stack_offset == rhs.stack_offset &&
           lhs.global_address == rhs.global_address && lhs.temporary_id == rhs.temporary_id &&
           lhs.version == rhs.version && lhs.bit_width == rhs.bit_width &&
           lhs.is_signed == rhs.is_signed;
}

bool operator<(const semantic_location_t& lhs, const semantic_location_t& rhs) noexcept {
    return std::tie(lhs.kind, lhs.address_space, lhs.register_id, lhs.stack_offset,
                    lhs.global_address, lhs.temporary_id, lhs.version, lhs.bit_width,
                    lhs.is_signed) <
           std::tie(rhs.kind, rhs.address_space, rhs.register_id, rhs.stack_offset,
                    rhs.global_address, rhs.temporary_id, rhs.version, rhs.bit_width,
                    rhs.is_signed);
}

bool operator==(const semantic_scope_key_t& lhs, const semantic_scope_key_t& rhs) noexcept {
    return lhs.binary_id == rhs.binary_id && lhs.load_profile_hash == rhs.load_profile_hash &&
           lhs.function_address == rhs.function_address && lhs.architecture == rhs.architecture &&
           lhs.architecture_mode == rhs.architecture_mode && lhs.abi == rhs.abi &&
           lhs.address_space == rhs.address_space && lhs.generation == rhs.generation &&
           lhs.analysis_revision == rhs.analysis_revision &&
           lhs.overlay_revision == rhs.overlay_revision;
}

bool operator<(const semantic_scope_key_t& lhs, const semantic_scope_key_t& rhs) noexcept {
    return std::tie(lhs.binary_id, lhs.load_profile_hash, lhs.function_address, lhs.architecture,
                    lhs.architecture_mode, lhs.abi, lhs.address_space, lhs.generation,
                    lhs.analysis_revision, lhs.overlay_revision) <
           std::tie(rhs.binary_id, rhs.load_profile_hash, rhs.function_address, rhs.architecture,
                    rhs.architecture_mode, rhs.abi, rhs.address_space, rhs.generation,
                    rhs.analysis_revision, rhs.overlay_revision);
}

bool operator==(const semantic_subject_t& lhs, const semantic_subject_t& rhs) noexcept {
    return lhs.kind == rhs.kind && lhs.function_id == rhs.function_id &&
           lhs.instruction_id == rhs.instruction_id && lhs.address == rhs.address &&
           lhs.location == rhs.location && lhs.ordinal == rhs.ordinal;
}

bool operator<(const semantic_subject_t& lhs, const semantic_subject_t& rhs) noexcept {
    return std::tie(lhs.kind, lhs.function_id, lhs.instruction_id, lhs.address,
                    lhs.location, lhs.ordinal) <
           std::tie(rhs.kind, rhs.function_id, rhs.instruction_id, rhs.address,
                    rhs.location, rhs.ordinal);
}

bool semantic_location_less(const semantic_location_t& lhs,
                            const semantic_location_t& rhs) noexcept {
    return lhs < rhs;
}

bool semantic_subject_less(const semantic_subject_t& lhs,
                           const semantic_subject_t& rhs) noexcept {
    return lhs < rhs;
}

bool semantic_evidence_less(const semantic_evidence_t& lhs,
                            const semantic_evidence_t& rhs) {
    if (lhs.kind != rhs.kind)
        return lhs.kind < rhs.kind;
    if (!(lhs.subject == rhs.subject))
        return lhs.subject < rhs.subject;
    const std::string lhs_payload = canonical_payload(lhs.payload);
    const std::string rhs_payload = canonical_payload(rhs.payload);
    if (lhs_payload != rhs_payload)
        return lhs_payload < rhs_payload;
    const std::string lhs_provenance = canonical_provenance(lhs.provenance);
    const std::string rhs_provenance = canonical_provenance(rhs.provenance);
    if (lhs_provenance != rhs_provenance)
        return lhs_provenance < rhs_provenance;
    if (lhs.validation != rhs.validation)
        return lhs.validation < rhs.validation;
    if (lhs.confidence != rhs.confidence)
        return lhs.confidence < rhs.confidence;
    return lhs.evidence_id < rhs.evidence_id;
}

std::uint64_t semantic_evidence_fingerprint(const semantic_evidence_t& evidence) {
    fingerprint_builder_t builder;
    builder.add_string(canonical_evidence(evidence));
    return builder.finish();
}

semantic_cache_key_material_t make_semantic_cache_key_material(
    const semantic_scope_key_t& scope,
    const semantic_merge_budget_t& budget,
    const semantic_validation_policy_t& validation,
    const std::vector<semantic_evidence_t>& evidence) {
    semantic_cache_key_material_t material;
    material.scope = scope;
    fingerprint_builder_t policy_builder;
    policy_builder.add_integral(validation.minimum_confidence);
    policy_builder.add_integral<std::uint64_t>(validation.minimum_independent_sources);
    policy_builder.add_integral(static_cast<std::uint8_t>(validation.minimum_validation));
    policy_builder.add_integral(validation.conflict_margin);
    policy_builder.add_integral(validation.require_independent_validation);
    policy_builder.add_integral(validation.permit_dominant_conflict_resolution);
    material.policy_fingerprint = policy_builder.finish();

    fingerprint_builder_t budget_builder;
    budget_builder.add_integral<std::uint64_t>(budget.max_workspace_instructions);
    budget_builder.add_integral<std::uint64_t>(budget.max_evidence_records);
    budget_builder.add_integral<std::uint64_t>(budget.max_evidence_per_subject);
    budget_builder.add_integral<std::uint64_t>(budget.max_fused_facts);
    budget_builder.add_integral<std::uint64_t>(budget.max_conflicts);
    budget_builder.add_integral<std::uint64_t>(budget.max_abstentions);
    budget_builder.add_integral<std::uint64_t>(budget.max_provenance_per_fact);
    budget_builder.add_integral<std::uint64_t>(budget.cancellation_poll_interval);
    material.budget_fingerprint = budget_builder.finish();

    std::vector<semantic_evidence_t> sorted = evidence;
    std::sort(sorted.begin(), sorted.end(), semantic_evidence_less);
    fingerprint_builder_t evidence_builder;
    evidence_builder.add_integral<std::uint64_t>(sorted.size());
    for (const auto& item : sorted)
        evidence_builder.add_integral(semantic_evidence_fingerprint(item));
    material.evidence_fingerprint = evidence_builder.finish();
    return material;
}

semantic_scope_key_t make_semantic_scope_key(const analysis_workspace_t& workspace,
                                             const analysis_snapshot_t* snapshot,
                                             std::uint64_t function_rva,
                                             std::optional<address_t> function_address) {
    semantic_scope_key_t scope;
    scope.binary_id = workspace.identity().binary_id();
    scope.load_profile_hash = workspace.identity().load_profile_hash();
    scope.architecture = workspace.identity().architecture();
    scope.architecture_mode = workspace.identity().architecture_mode();
    scope.abi = workspace.identity().abi();
    scope.address_space = address_space_id_t::relative_virtual;
    scope.function_address.space = scope.address_space;
    scope.function_address.value = function_rva;
    scope.function_address.architecture = scope.architecture;
    scope.function_address.mode = scope.architecture_mode;
    if (function_address)
        scope.function_address = *function_address;
    scope.address_space = scope.function_address.space;
    if (snapshot) {
        scope.binary_id = snapshot->binary_id;
        scope.load_profile_hash = snapshot->load_profile_hash;
        scope.generation = snapshot->generation;
        scope.analysis_revision = snapshot->analysis_revision;
        scope.overlay_revision = snapshot->overlay_revision;
        for (const auto& function : snapshot->functions) {
            if (function.start.value == scope.function_address.value &&
                (!function_address || function.start == *function_address)) {
                scope.function_address = function.start;
                scope.address_space = function.start.space;
                if (function.start.architecture != architecture_id_t::unknown)
                    scope.architecture = function.start.architecture;
                if (function.start.mode != architecture_mode_t::unknown)
                    scope.architecture_mode = function.start.mode;
                break;
            }
        }
    }
    return scope;
}

workspace_result_t<semantic_fusion_result_t> reduce_semantic_evidence(
    const semantic_scope_key_t& scope,
    std::vector<semantic_evidence_t> evidence,
    const semantic_merge_budget_t& budget,
    const semantic_validation_policy_t& validation,
    const cancellation_token_t& cancel) {
    semantic_fusion_result_t result;
    result.scope = scope;
    result.cache_key = make_semantic_cache_key_material(scope, budget, validation, evidence);
    const std::size_t poll_interval = std::max<std::size_t>(1, budget.cancellation_poll_interval);

    for (auto& item : evidence) {
        if (!payload_matches_kind(item) || !evidence_matches_scope(item, scope)) {
            item.validation = semantic_validation_t::rejected;
            ++result.evidence_dropped;
        }
    }

    std::sort(evidence.begin(), evidence.end(), semantic_evidence_less);
    std::set<std::uint64_t> assigned_ids;
    for (const auto& item : evidence) {
        if (item.evidence_id != 0)
            assigned_ids.insert(item.evidence_id);
    }
    std::uint64_t generated_id = std::numeric_limits<std::uint64_t>::max();
    for (auto& item : evidence) {
        if (item.evidence_id != 0)
            continue;
        while (assigned_ids.count(generated_id) != 0 && generated_id != 0)
            --generated_id;
        if (generated_id == 0) {
            result.bounded = true;
            ++result.evidence_dropped;
            item.validation = semantic_validation_t::rejected;
            continue;
        }
        item.evidence_id = generated_id;
        assigned_ids.insert(generated_id);
        --generated_id;
    }
    if (evidence.size() > budget.max_evidence_records) {
        result.evidence_dropped = evidence.size() - budget.max_evidence_records;
        evidence.resize(budget.max_evidence_records);
        result.bounded = true;
    }

    std::size_t group_begin = 0;
    while (group_begin < evidence.size()) {
        if ((group_begin % poll_interval) == 0 && is_terminal(cancel, result)) {
            append_abstention(result, budget, semantic_fact_kind_t::value, semantic_subject_t{},
                              result.deadline_exceeded
                                  ? semantic_abstention_reason_t::deadline_exceeded
                                  : semantic_abstention_reason_t::cancellation_requested);
            break;
        }

        std::size_t group_end = group_begin + 1;
        while (group_end < evidence.size() && evidence[group_end].kind == evidence[group_begin].kind &&
               evidence[group_end].subject == evidence[group_begin].subject) {
            ++group_end;
        }
        ++result.merged_subjects;
        const std::size_t bounded_end = std::min(group_end, group_begin + budget.max_evidence_per_subject);
        if (bounded_end != group_end) {
            result.evidence_dropped += group_end - bounded_end;
            result.bounded = true;
        }

        std::vector<std::uint64_t> abstained_ids;
        std::vector<candidate_t> candidates;
        std::size_t candidate_begin = group_begin;
        while (candidate_begin < bounded_end) {
            const std::string payload_key = canonical_payload(evidence[candidate_begin].payload);
            std::size_t candidate_end = candidate_begin + 1;
            while (candidate_end < bounded_end &&
                   canonical_payload(evidence[candidate_end].payload) == payload_key) {
                ++candidate_end;
            }

            candidate_t candidate;
            candidate.payload_key = payload_key;
            std::set<std::string> sources;
            for (std::size_t index = candidate_begin; index < candidate_end; ++index) {
                const semantic_evidence_t& item = evidence[index];
                const std::uint64_t item_id = canonical_id(item, index + 1U);
                if (item.validation == semantic_validation_t::abstained) {
                    abstained_ids.push_back(item_id);
                    continue;
                }
                if (item.validation == semantic_validation_t::rejected)
                    continue;
                candidate.evidence.push_back(&item);
                candidate.validation = best_validation(candidate.validation, item.validation);
                candidate.independently_validated |= item.provenance.independently_validated;
                sources.insert(canonical_source(item, item_id));
                const std::uint32_t expanded_strength =
                    static_cast<std::uint32_t>(candidate.strength) + evidence_strength(item);
                candidate.strength = static_cast<std::uint16_t>(std::min<std::uint32_t>(
                    expanded_strength, std::numeric_limits<std::uint16_t>::max()));
            }
            candidate.independent_sources = sources.size();
            if (!candidate.evidence.empty())
                candidates.push_back(std::move(candidate));
            candidate_begin = candidate_end;
        }

        const semantic_fact_kind_t kind = evidence[group_begin].kind;
        const semantic_subject_t subject = evidence[group_begin].subject;
        if (candidates.empty()) {
            append_abstention(result, budget, kind, subject,
                              abstained_ids.empty()
                                  ? semantic_abstention_reason_t::insufficient_evidence
                                  : abstention_reason_from_evidence(evidence[group_begin]),
                              std::move(abstained_ids));
            group_begin = group_end;
            continue;
        }

        std::sort(candidates.begin(), candidates.end(), candidate_better);
        candidate_t& selected = candidates.front();
        const std::uint8_t confidence = aggregate_confidence(selected.evidence);
        const bool validation_sufficient =
            validation_rank(selected.validation) >= validation_rank(validation.minimum_validation);
        const bool sources_sufficient =
            selected.independent_sources >= validation.minimum_independent_sources;
        const bool independent_validation_sufficient =
            !validation.require_independent_validation || selected.independently_validated;
        if (!validation_sufficient || !sources_sufficient || !independent_validation_sufficient ||
            confidence < validation.minimum_confidence) {
            std::vector<std::uint64_t> ids = std::move(abstained_ids);
            for (const auto* item : selected.evidence)
                ids.push_back(canonical_id(*item, 0));
            append_abstention(result, budget, kind, subject,
                              semantic_abstention_reason_t::validation_requirement, std::move(ids));
            group_begin = group_end;
            continue;
        }

        bool conflict_resolved = true;
        if (candidates.size() > 1) {
            const candidate_t& conflicting = candidates[1];
            const std::uint32_t threshold = static_cast<std::uint32_t>(conflicting.strength) +
                                            validation.conflict_margin;
            conflict_resolved = validation.permit_dominant_conflict_resolution &&
                                static_cast<std::uint32_t>(selected.strength) >= threshold &&
                                validation_rank(selected.validation) >= validation_rank(conflicting.validation);
            std::vector<std::uint64_t> selected_ids;
            std::vector<std::uint64_t> conflicting_ids;
            for (const auto* item : selected.evidence)
                selected_ids.push_back(canonical_id(*item, 0));
            for (const auto* item : conflicting.evidence)
                conflicting_ids.push_back(canonical_id(*item, 0));
            append_conflict(result, budget, kind, subject, std::move(selected_ids),
                            std::move(conflicting_ids),
                            conflict_resolved ? semantic_resolution_t::accepted
                                              : semantic_resolution_t::conflict,
                            selected.strength, conflicting.strength);
        }
        if (!conflict_resolved) {
            std::vector<std::uint64_t> ids = std::move(abstained_ids);
            for (const auto& candidate : candidates) {
                for (const auto* item : candidate.evidence)
                    ids.push_back(canonical_id(*item, 0));
            }
            append_abstention(result, budget, kind, subject,
                              semantic_abstention_reason_t::conflicting_evidence, std::move(ids));
            group_begin = group_end;
            continue;
        }

        if (result.facts.size() >= budget.max_fused_facts) {
            result.bounded = true;
            std::vector<std::uint64_t> ids;
            for (const auto* item : selected.evidence)
                ids.push_back(canonical_id(*item, 0));
            append_abstention(result, budget, kind, subject,
                              semantic_abstention_reason_t::merge_budget_exhausted, std::move(ids));
            group_begin = group_end;
            continue;
        }

        semantic_fact_t fact;
        fact.kind = kind;
        fact.subject = subject;
        fact.payload = selected.evidence.front()->payload;
        fact.validation = selected.validation;
        fact.resolution = semantic_resolution_t::accepted;
        fact.confidence = confidence;
        for (const auto* item : selected.evidence) {
            fact.contributing_evidence_ids.push_back(canonical_id(*item, 0));
            fact.provenance.push_back(item->provenance);
        }
        std::sort(fact.contributing_evidence_ids.begin(), fact.contributing_evidence_ids.end());
        fact.contributing_evidence_ids.erase(
            std::unique(fact.contributing_evidence_ids.begin(), fact.contributing_evidence_ids.end()),
            fact.contributing_evidence_ids.end());
        std::sort(fact.provenance.begin(), fact.provenance.end(), provenance_less);
        fact.provenance.erase(std::unique(fact.provenance.begin(), fact.provenance.end(),
                                          [](const auto& lhs, const auto& rhs) {
                                              return canonical_provenance(lhs) == canonical_provenance(rhs);
                                          }),
                              fact.provenance.end());
        if (fact.provenance.size() > budget.max_provenance_per_fact) {
            fact.provenance.resize(budget.max_provenance_per_fact);
            result.bounded = true;
        }
        result.facts.push_back(std::move(fact));
        group_begin = group_end;
    }

    result.evidence_considered = evidence.size();
    result.fused_fact_count = result.facts.size();
    return workspace_result_t<semantic_fusion_result_t>::success(std::move(result));
}

workspace_result_t<semantic_fusion_result_t> fuse_semantic_evidence(
    const analysis_workspace_t& workspace,
    const semantic_fusion_request_t& request,
    const cancellation_token_t& cancel) {
    const auto snapshot = workspace.snapshot();
    const std::uint64_t function_rva = request.function_address ? request.function_address->value
                                                                : request.function_rva;
    const semantic_scope_key_t scope = make_semantic_scope_key(
        workspace, snapshot.get(), function_rva, request.function_address);

    std::vector<semantic_evidence_t> evidence = request.decompiler_evidence;
    workspace_collection_t collection;
    if (request.derive_workspace_evidence) {
        if (snapshot) {
            collection = collect_workspace_evidence(workspace, *snapshot, scope, request, cancel);
            evidence.insert(evidence.end(), collection.evidence.begin(), collection.evidence.end());
        } else {
            semantic_subject_t subject;
            subject.kind = semantic_subject_kind_t::function;
            subject.address = scope.function_address;
            collection_abstain(collection, request.budget, semantic_fact_kind_t::metadata, subject,
                               semantic_abstention_reason_t::missing_metadata);
        }
    }

    auto reduced = reduce_semantic_evidence(scope, std::move(evidence), request.budget,
                                            request.validation, cancel);
    if (!reduced)
        return reduced;
    semantic_fusion_result_t result = reduced.take_value();
    result.workspace_evidence_collected = collection.collected;
    result.bounded |= collection.bounded;
    result.cancelled |= collection.cancelled;
    result.deadline_exceeded |= collection.deadline_exceeded;
    append_collection_abstentions(result, collection, request.budget);
    if (collection.cancelled) {
        append_abstention(result, request.budget, semantic_fact_kind_t::value, semantic_subject_t{},
                          collection.deadline_exceeded
                              ? semantic_abstention_reason_t::deadline_exceeded
                              : semantic_abstention_reason_t::cancellation_requested);
    }
    return workspace_result_t<semantic_fusion_result_t>::success(std::move(result));
}

workspace_result_t<semantic_fusion_result_t> run_semantic_fusion(
    const analysis_workspace_t& workspace,
    std::uint64_t function_rva,
    const cancellation_token_t& cancel) {
    semantic_fusion_request_t request;
    request.function_rva = function_rva;
    return fuse_semantic_evidence(workspace, request, cancel);
}

}
