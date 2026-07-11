#include "type_recovery.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>

namespace aida::analysis {

namespace {

struct function_view_t {
    const function_record_t* function = nullptr;
    std::vector<const instruction_record_t*> instructions;
    std::vector<std::uint64_t> call_targets;
};

struct call_record_t {
    std::uint64_t call_site_rva = 0;
    std::uint64_t target_function_rva = 0;
    bool indirect = false;
};

class recovery_poller_t final {
public:
    recovery_poller_t(const cancellation_token_t& cancel, type_recovery_result_t& result)
        : cancel_(cancel), result_(result) {}

    bool poll() {
        if ((visits_++ & 127U) != 0)
            return false;
        return poll_now();
    }

    bool poll_now() {
        if (!cancel_.stop_requested())
            return false;
        result_.cancelled = !cancel_.deadline_exceeded();
        result_.deadline_exceeded = cancel_.deadline_exceeded();
        result_.status = result_.deadline_exceeded
            ? type_recovery_status_t::deadline_exceeded
            : type_recovery_status_t::cancelled;
        return true;
    }

private:
    const cancellation_token_t& cancel_;
    type_recovery_result_t& result_;
    std::uint64_t visits_ = 0;
};

struct collector_t {
    type_recovery_result_t& result;
    const type_recovery_limits_t& limits;
    recovery_poller_t& poller;
    bool stopped = false;
    bool work_limited = false;
    std::uint64_t work_units = 0;

    bool consume_work_unit() {
        if (work_units >= limits.max_constraints) {
            result.bounded = true;
            work_limited = true;
            return false;
        }
        ++work_units;
        return true;
    }

    bool append_evidence(type_recovery_evidence_t evidence) {
        if (stopped || poller.poll()) {
            stopped = true;
            return false;
        }
        if (result.evidence.size() >= limits.max_evidence) {
            result.bounded = true;
            work_limited = true;
            return false;
        }
        result.evidence.push_back(std::move(evidence));
        return true;
    }

    bool append_constraint(type_constraint_t constraint) {
        if (stopped || poller.poll()) {
            stopped = true;
            return false;
        }
        if (result.constraints.size() >= limits.max_constraints) {
            result.bounded = true;
            work_limited = true;
            return false;
        }
        result.constraints.push_back(std::move(constraint));
        return true;
    }
};

std::uint64_t stable_hash(std::string_view text) noexcept {
    std::uint64_t value = 1469598103934665603ULL;
    for (const unsigned char ch : text) {
        value ^= static_cast<std::uint64_t>(ch);
        value *= 1099511628211ULL;
    }
    value ^= value >> 33;
    value *= 0xff51afd7ed558ccdULL;
    value ^= value >> 33;
    value *= 0xc4ceb9fe1a85ec53ULL;
    return value ^ (value >> 33);
}

void append_key_component(std::string& text, std::string_view name, std::uint64_t value) {
    text.append(name);
    text.push_back('=');
    text.append(std::to_string(value));
    text.push_back(';');
}

void append_key_component(std::string& text, std::string_view name, std::uint32_t value) {
    append_key_component(text, name, static_cast<std::uint64_t>(value));
}

void append_key_component(std::string& text, std::string_view name, std::uint16_t value) {
    append_key_component(text, name, static_cast<std::uint64_t>(value));
}

void append_key_component(std::string& text, std::string_view name, std::uint8_t value) {
    append_key_component(text, name, static_cast<std::uint64_t>(value));
}

void append_key_component(std::string& text, std::string_view name, std::int64_t value) {
    text.append(name);
    text.push_back('=');
    text.append(std::to_string(value));
    text.push_back(';');
}

void append_key_component(std::string& text, std::string_view name, std::string_view value) {
    text.append(name);
    text.push_back('=');
    text.append(std::to_string(value.size()));
    text.push_back(':');
    text.append(value);
    text.push_back(';');
}

std::string subject_material(const type_subject_t& subject) {
    std::string material;
    material.reserve(subject.stable_name.size() + 160);
    append_key_component(material, "k", static_cast<std::uint64_t>(subject.kind));
    append_key_component(material, "as", static_cast<std::uint64_t>(subject.address.space));
    append_key_component(material, "av", subject.address.value);
    append_key_component(material, "aa", static_cast<std::uint64_t>(subject.address.architecture));
    append_key_component(material, "am", static_cast<std::uint64_t>(subject.address.mode));
    append_key_component(material, "fn", subject.function_rva);
    append_key_component(material, "so", subject.stack_offset);
    append_key_component(material, "o", subject.ordinal);
    append_key_component(material, "r", subject.reg);
    switch (subject.kind) {
        case type_subject_kind_t::local:
        case type_subject_kind_t::register_value:
        case type_subject_kind_t::stack_slot:
        case type_subject_kind_t::field:
        case type_subject_kind_t::array_element:
            append_key_component(material, "id", subject.entity_id);
            append_key_component(material, "cid", subject.container_id);
            break;
        default:
            break;
    }
    if (subject.address.value == 0 && subject.function_rva == 0)
        append_key_component(material, "n", subject.stable_name);
    return material;
}

std::string descriptor_material(const type_descriptor_t& descriptor) {
    std::string material;
    material.reserve(descriptor.declared_name.size() + descriptor.referenced_type_name.size() + 128);
    append_key_component(material, "k", static_cast<std::uint64_t>(descriptor.kind));
    append_key_component(material, "s", static_cast<std::uint64_t>(descriptor.signedness));
    append_key_component(material, "l", static_cast<std::uint64_t>(descriptor.language));
    append_key_component(material, "w", descriptor.bit_width);
    append_key_component(material, "ew", descriptor.element_bit_width);
    append_key_component(material, "ec", descriptor.element_count);
    append_key_component(material, "rid", descriptor.referenced_type_id);
    append_key_component(material, "dn", descriptor.declared_name);
    append_key_component(material, "rn", descriptor.referenced_type_name);
    append_key_component(material, "nl", descriptor.nullable ? 1U : 0U);
    append_key_component(material, "va", descriptor.variadic ? 1U : 0U);
    append_key_component(material, "nr", descriptor.noreturn ? 1U : 0U);
    return material;
}

std::string evidence_material(const type_recovery_evidence_t& evidence) {
    std::string material = subject_material(evidence.subject);
    append_key_component(material, "candidate", descriptor_material(evidence.candidate));
    append_key_component(material, "provenance", static_cast<std::uint64_t>(evidence.provenance));
    append_key_component(material, "kind", static_cast<std::uint64_t>(evidence.kind));
    append_key_component(material, "sas", static_cast<std::uint64_t>(evidence.source_address.space));
    append_key_component(material, "sav", evidence.source_address.value);
    append_key_component(material, "saa", static_cast<std::uint64_t>(evidence.source_address.architecture));
    append_key_component(material, "sam", static_cast<std::uint64_t>(evidence.source_address.mode));
    append_key_component(material, "sid", evidence.source_entity_id);
    append_key_component(material, "confidence", evidence.confidence);
    append_key_component(material, "hops", evidence.propagation_hops);
    append_key_component(material, "hard", evidence.hard_constraint ? 1U : 0U);
    append_key_component(material, "propagated", evidence.propagated ? 1U : 0U);
    if (evidence.related_subject)
        append_key_component(material, "related", subject_material(*evidence.related_subject));
    append_key_component(material, "detail", evidence.detail);
    return material;
}

bool evidence_less(const type_recovery_evidence_t& lhs, const type_recovery_evidence_t& rhs) {
    const auto lhs_material = evidence_material(lhs);
    const auto rhs_material = evidence_material(rhs);
    if (lhs_material != rhs_material)
        return lhs_material < rhs_material;
    return lhs.evidence_id < rhs.evidence_id;
}

bool constraint_less(const type_constraint_t& lhs, const type_constraint_t& rhs) {
    const auto lhs_source = subject_material(lhs.source);
    const auto rhs_source = subject_material(rhs.source);
    if (lhs_source != rhs_source)
        return lhs_source < rhs_source;
    const auto lhs_target = lhs.target ? subject_material(*lhs.target) : std::string{};
    const auto rhs_target = rhs.target ? subject_material(*rhs.target) : std::string{};
    return std::tie(lhs.kind, lhs.relation, lhs_target, lhs.instruction_rva, lhs.source_instruction_id,
                    lhs.target_entity_id, lhs.propagation_hops) <
           std::tie(rhs.kind, rhs.relation, rhs_target, rhs.instruction_rva, rhs.source_instruction_id,
                    rhs.target_entity_id, rhs.propagation_hops);
}

std::string lower_ascii(std::string value) {
    for (char& ch : value) {
        if (ch >= 'A' && ch <= 'Z')
            ch = static_cast<char>(ch - 'A' + 'a');
    }
    return value;
}

bool contains_token(const std::string& value, const char* token) {
    return value.find(token) != std::string::npos;
}

type_descriptor_t unknown_descriptor(std::string name = {}) {
    type_descriptor_t descriptor;
    descriptor.declared_name = std::move(name);
    return descriptor;
}

type_descriptor_t width_constraint_descriptor(std::uint16_t width) {
    type_descriptor_t descriptor;
    descriptor.bit_width = width;
    return descriptor;
}

type_descriptor_t integer_descriptor(std::uint16_t width, bool signed_value) {
    type_descriptor_t descriptor;
    descriptor.kind = width == 1 ? recovered_type_kind_t::boolean : recovered_type_kind_t::integer;
    descriptor.bit_width = width;
    descriptor.signedness = width == 1
        ? type_signedness_t::not_applicable
        : (signed_value ? type_signedness_t::signed_value : type_signedness_t::unknown);
    return descriptor;
}

type_descriptor_t pointer_descriptor(std::uint16_t width) {
    type_descriptor_t descriptor;
    descriptor.kind = recovered_type_kind_t::pointer;
    descriptor.bit_width = width;
    descriptor.signedness = type_signedness_t::not_applicable;
    descriptor.nullable = true;
    return descriptor;
}

type_descriptor_t array_descriptor(std::uint16_t element_width, std::uint16_t count) {
    type_descriptor_t descriptor;
    descriptor.kind = recovered_type_kind_t::array;
    descriptor.element_bit_width = element_width;
    descriptor.element_count = count;
    descriptor.bit_width = static_cast<std::uint16_t>(
        std::min<std::uint64_t>(static_cast<std::uint64_t>(element_width) * count,
                                (std::numeric_limits<std::uint16_t>::max)()));
    descriptor.signedness = type_signedness_t::not_applicable;
    return descriptor;
}

std::uint16_t pointer_width(const analysis_workspace_t& workspace) {
    const auto image = workspace.normalized_image();
    if (image && image->address_width_bits != 0)
        return image->address_width_bits;
    switch (workspace.identity().architecture()) {
        case architecture_id_t::x86:
        case architecture_id_t::arm:
        case architecture_id_t::mips:
        case architecture_id_t::ppc:
        case architecture_id_t::riscv32:
            return 32;
        case architecture_id_t::x86_64:
        case architecture_id_t::aarch64:
        case architecture_id_t::arm64ec:
        case architecture_id_t::mips64:
        case architecture_id_t::ppc64:
        case architecture_id_t::riscv64:
            return 64;
        default:
            return 0;
    }
}

address_t make_address(const analysis_workspace_t& workspace,
                       address_space_id_t space, std::uint64_t value) {
    address_t address;
    address.space = space;
    address.value = value;
    address.architecture = workspace.identity().architecture();
    address.mode = workspace.identity().architecture_mode();
    return address;
}

type_subject_t make_function_subject(const analysis_workspace_t& workspace,
                                     const function_record_t& function) {
    type_subject_t subject;
    subject.kind = type_subject_kind_t::function;
    subject.address = function.start;
    subject.entity_id = function.id;
    subject.function_rva = function.start.value;
    subject.stable_name = "function";
    if (subject.address.architecture == architecture_id_t::unknown)
        subject.address = make_address(workspace, address_space_id_t::relative_virtual,
                                       function.start.value);
    return subject;
}

type_subject_t make_local_subject(const analysis_workspace_t& workspace,
                                  const function_record_t& function, std::uint16_t reg) {
    type_subject_t subject;
    subject.kind = type_subject_kind_t::local;
    subject.address = function.start;
    subject.entity_id = function.id;
    subject.function_rva = function.start.value;
    subject.reg = reg;
    subject.stable_name = "register";
    if (subject.address.architecture == architecture_id_t::unknown)
        subject.address = make_address(workspace, address_space_id_t::relative_virtual,
                                       function.start.value);
    return subject;
}

type_subject_t make_stack_subject(const analysis_workspace_t& workspace,
                                  const function_record_t& function,
                                  std::uint16_t reg, std::int64_t offset) {
    auto subject = make_local_subject(workspace, function, reg);
    subject.kind = type_subject_kind_t::stack_slot;
    subject.stack_offset = offset;
    subject.stable_name = "stack";
    return subject;
}

type_subject_t make_field_subject(const analysis_workspace_t& workspace,
                                  const function_record_t& function,
                                  std::uint16_t base_reg, std::int64_t offset) {
    auto subject = make_local_subject(workspace, function, base_reg);
    subject.kind = type_subject_kind_t::field;
    subject.container_id = base_reg;
    subject.stack_offset = offset;
    subject.stable_name = "field";
    return subject;
}

type_subject_t make_parameter_subject(const analysis_workspace_t& workspace,
                                      std::uint64_t function_rva, std::uint32_t ordinal) {
    type_subject_t subject;
    subject.kind = type_subject_kind_t::parameter;
    subject.address = make_address(workspace, address_space_id_t::relative_virtual, function_rva);
    subject.function_rva = function_rva;
    subject.ordinal = ordinal;
    subject.stable_name = "parameter";
    return subject;
}

type_subject_t make_return_subject(const analysis_workspace_t& workspace,
                                   std::uint64_t function_rva) {
    type_subject_t subject;
    subject.kind = type_subject_kind_t::return_value;
    subject.address = make_address(workspace, address_space_id_t::relative_virtual, function_rva);
    subject.function_rva = function_rva;
    subject.stable_name = "return";
    return subject;
}

type_evidence_provenance_t provenance_from_fact(fact_provenance_t provenance) {
    switch (provenance) {
        case fact_provenance_t::debug_symbol:
            return type_evidence_provenance_t::debug_info;
        case fact_provenance_t::user_definition:
            return type_evidence_provenance_t::user_definition;
        case fact_provenance_t::decompiler_feedback:
            return type_evidence_provenance_t::decompiler;
        case fact_provenance_t::call_target:
            return type_evidence_provenance_t::control_flow;
        default:
            return type_evidence_provenance_t::instruction_semantics;
    }
}

bool operand_is_read(const operand_fact_t& operand) {
    return (operand.access & 1U) != 0;
}

bool operand_is_written(const operand_fact_t& operand) {
    return (operand.access & 2U) != 0;
}

bool is_stack_expression(const operand_fact_t& operand) {
    return operand.base_reg != 0 &&
           (operand.address_expression == address_expression_kind_t::base_displacement ||
            operand.address_expression == address_expression_kind_t::base_index_displacement ||
            operand.address_expression == address_expression_kind_t::segment_relative);
}

bool is_direct_memory_expression(const operand_fact_t& operand) {
    return operand.has_resolved_expression_value &&
           (operand.address_expression == address_expression_kind_t::absolute ||
            operand.address_expression == address_expression_kind_t::instruction_relative ||
            operand.address_resolution != target_resolution_t::unresolved_indirect);
}

function_view_t extract_function_view(const analysis_snapshot_t& snapshot,
                                      const function_record_t& function) {
    function_view_t view;
    view.function = &function;
    std::vector<const basic_block_record_t*> blocks;
    for (const auto& block : snapshot.blocks) {
        if (block.function_id == function.id)
            blocks.push_back(&block);
    }
    std::sort(blocks.begin(), blocks.end(), [](const auto* lhs, const auto* rhs) {
        return std::tie(lhs->start, lhs->id) < std::tie(rhs->start, rhs->id);
    });
    for (const auto* block : blocks) {
        for (std::uint32_t index = 0; index < block->instruction_count; ++index) {
            const auto instruction_index = static_cast<std::uint64_t>(block->first_instruction) + index;
            if (instruction_index < snapshot.instructions.size())
                view.instructions.push_back(&snapshot.instructions[static_cast<std::size_t>(instruction_index)]);
        }
    }
    std::sort(view.instructions.begin(), view.instructions.end(), [](const auto* lhs, const auto* rhs) {
        return std::tie(lhs->address, lhs->id) < std::tie(rhs->address, rhs->id);
    });
    view.instructions.erase(std::unique(view.instructions.begin(), view.instructions.end(),
        [](const auto* lhs, const auto* rhs) { return lhs->id == rhs->id; }), view.instructions.end());
    for (const auto* instruction : view.instructions) {
        if ((instruction->flow_flags & flow_call) == 0)
            continue;
        const auto target_end = std::min<std::uint64_t>(
            static_cast<std::uint64_t>(instruction->target_fact_begin) + instruction->target_fact_count,
            snapshot.target_facts.size());
        for (std::uint64_t index = instruction->target_fact_begin; index < target_end; ++index) {
            const auto& target = snapshot.target_facts[static_cast<std::size_t>(index)];
            if (target.kind == target_kind_record_t::call)
                view.call_targets.push_back(target.target.value);
        }
    }
    std::sort(view.call_targets.begin(), view.call_targets.end());
    view.call_targets.erase(std::unique(view.call_targets.begin(), view.call_targets.end()),
                            view.call_targets.end());
    return view;
}

const function_record_t* find_function(const std::vector<const function_record_t*>& functions,
                                       std::uint64_t rva) {
    const auto it = std::lower_bound(functions.begin(), functions.end(), rva,
        [](const function_record_t* function, std::uint64_t value) {
            return function->start.value < value;
        });
    if (it == functions.end() || (*it)->start.value != rva)
        return nullptr;
    return *it;
}

type_recovery_limits_t normalized_limits(type_recovery_limits_t limits) {
    const auto clamp = [](std::uint64_t value, std::uint64_t maximum) {
        return std::max<std::uint64_t>(1, std::min(value, maximum));
    };
    limits.max_evidence = clamp(limits.max_evidence, type_recovery_max_evidence);
    limits.max_constraints = clamp(limits.max_constraints, type_recovery_max_constraints);
    limits.max_results = clamp(limits.max_results, type_recovery_max_results);
    limits.max_fields_per_aggregate = clamp(limits.max_fields_per_aggregate, 4096);
    limits.max_aggregates = clamp(limits.max_aggregates, 4096);
    limits.max_vtables = clamp(limits.max_vtables, 4096);
    limits.max_prototypes = clamp(limits.max_prototypes, 8192);
    limits.max_interprocedural_functions = clamp(limits.max_interprocedural_functions, 256);
    limits.max_interprocedural_depth = std::min<std::uint32_t>(limits.max_interprocedural_depth, 16);
    limits.max_propagation_iterations = std::max<std::uint32_t>(1,
        std::min<std::uint32_t>(limits.max_propagation_iterations,
                                static_cast<std::uint32_t>(type_recovery_max_iterations)));
    limits.minimum_confidence = std::min<std::uint8_t>(limits.minimum_confidence, 100);
    limits.conflict_margin = std::min<std::uint8_t>(limits.conflict_margin, 100);
    return limits;
}

calling_convention_cache_key_t expected_calling_convention_cache_key(
    const analysis_workspace_t& workspace, const type_recovery_request_t& request) {
    calling_convention_cache_key_t key;
    key.binary_id = workspace.identity().binary_id();
    key.function = make_address(workspace, request.address_space, request.function_rva);
    key.architecture = workspace.identity().architecture();
    key.architecture_mode = workspace.identity().architecture_mode();
    key.declared_abi = workspace.identity().abi();
    key.generation = workspace.generation();
    key.analysis_revision = workspace.analysis_revision();
    key.overlay_revision = workspace.overlay_revision();
    return key;
}

void append_calling_convention_key_material(std::string& material,
                                            const calling_convention_cache_key_t& key) {
    append_key_component(material, "cc_binary", key.binary_id.to_hex());
    append_key_component(material, "cc_space", static_cast<std::uint64_t>(key.function.space));
    append_key_component(material, "cc_address", key.function.value);
    append_key_component(material, "cc_root_arch",
                         static_cast<std::uint64_t>(key.function.architecture));
    append_key_component(material, "cc_root_mode",
                         static_cast<std::uint64_t>(key.function.mode));
    append_key_component(material, "cc_arch", static_cast<std::uint64_t>(key.architecture));
    append_key_component(material, "cc_mode", static_cast<std::uint64_t>(key.architecture_mode));
    append_key_component(material, "cc_abi", static_cast<std::uint64_t>(key.declared_abi));
    append_key_component(material, "cc_generation", key.generation);
    append_key_component(material, "cc_analysis", key.analysis_revision);
    append_key_component(material, "cc_overlay", key.overlay_revision);
    append_key_component(material, "cc_rules", key.rules_revision);
}

std::uint64_t calling_convention_result_fingerprint(const cc_analysis_result_t& analysis) {
    std::string material;
    material.reserve(256 + analysis.arguments.size() * 96);
    append_calling_convention_key_material(material, analysis.cache_key);
    append_key_component(material, "cc_function_rva", analysis.function_rva);
    append_key_component(material, "cc_result_abi", static_cast<std::uint64_t>(analysis.abi));
    append_key_component(material, "cc_state", static_cast<std::uint64_t>(analysis.state));
    append_key_component(material, "cc_arguments_state",
                         static_cast<std::uint64_t>(analysis.arguments_state));
    append_key_component(material, "cc_return_state",
                         static_cast<std::uint64_t>(analysis.return_value.state));
    append_key_component(material, "cc_variadic_state",
                         static_cast<std::uint64_t>(analysis.variadic_state));
    append_key_component(material, "cc_return_reg", analysis.return_reg);
    append_key_component(material, "cc_return_width", analysis.return_value.bit_width);
    append_key_component(material, "cc_return_confidence", analysis.return_value.confidence);
    append_key_component(material, "cc_return_float", analysis.return_value.is_float ? 1U : 0U);
    append_key_component(material, "cc_return_vector", analysis.return_value.is_vector ? 1U : 0U);
    append_key_component(material, "cc_variadic", analysis.is_variadic ? 1U : 0U);
    append_key_component(material, "cc_noreturn", analysis.is_noreturn ? 1U : 0U);
    append_key_component(material, "cc_native", analysis.native_abi ? 1U : 0U);
    append_key_component(material, "cc_confidence", analysis.confidence);
    append_key_component(material, "cc_bounded", analysis.bounded ? 1U : 0U);
    std::vector<const argument_info_t*> arguments;
    arguments.reserve(analysis.arguments.size());
    for (const auto& argument : analysis.arguments)
        arguments.push_back(&argument);
    std::sort(arguments.begin(), arguments.end(), [](const auto* lhs, const auto* rhs) {
        return std::tie(lhs->index, lhs->abi_slot, lhs->location, lhs->reg, lhs->stack_offset,
                        lhs->bit_width, lhs->is_float, lhs->is_vector, lhs->used,
                        lhs->conflicted, lhs->confidence) <
               std::tie(rhs->index, rhs->abi_slot, rhs->location, rhs->reg, rhs->stack_offset,
                        rhs->bit_width, rhs->is_float, rhs->is_vector, rhs->used,
                        rhs->conflicted, rhs->confidence);
    });
    for (const auto* argument : arguments) {
        append_key_component(material, "cc_arg_index", argument->index);
        append_key_component(material, "cc_arg_slot", argument->abi_slot);
        append_key_component(material, "cc_arg_reg", argument->reg);
        append_key_component(material, "cc_arg_stack", argument->stack_offset);
        append_key_component(material, "cc_arg_width", argument->bit_width);
        append_key_component(material, "cc_arg_location",
                             static_cast<std::uint64_t>(argument->location));
        append_key_component(material, "cc_arg_float", argument->is_float ? 1U : 0U);
        append_key_component(material, "cc_arg_vector", argument->is_vector ? 1U : 0U);
        append_key_component(material, "cc_arg_used", argument->used ? 1U : 0U);
        append_key_component(material, "cc_arg_conflicted", argument->conflicted ? 1U : 0U);
        append_key_component(material, "cc_arg_confidence", argument->confidence);
    }
    return stable_hash(material);
}

std::uint64_t options_fingerprint(const type_recovery_request_t& request,
                                  const type_recovery_limits_t& limits) {
    std::string material;
    append_key_component(material, "space", static_cast<std::uint64_t>(request.address_space));
    append_key_component(material, "metadata", request.include_image_metadata ? 1U : 0U);
    append_key_component(material, "interprocedural", request.include_interprocedural ? 1U : 0U);
    append_key_component(material, "evidence", limits.max_evidence);
    append_key_component(material, "constraints", limits.max_constraints);
    append_key_component(material, "results", limits.max_results);
    append_key_component(material, "fields", limits.max_fields_per_aggregate);
    append_key_component(material, "aggregates", limits.max_aggregates);
    append_key_component(material, "vtables", limits.max_vtables);
    append_key_component(material, "prototypes", limits.max_prototypes);
    append_key_component(material, "functions", limits.max_interprocedural_functions);
    append_key_component(material, "depth", limits.max_interprocedural_depth);
    append_key_component(material, "iterations", limits.max_propagation_iterations);
    append_key_component(material, "confidence", limits.minimum_confidence);
    append_key_component(material, "margin", limits.conflict_margin);
    append_key_component(material, "semantic", request.semantic_result ? 1U : 0U);
    append_key_component(material, "consume_semantic", request.consume_semantic_facts ? 1U : 0U);
    if (request.semantic_result) {
        const auto& cache = request.semantic_result->cache_key;
        append_key_component(material, "semantic_model", cache.model_revision);
        append_key_component(material, "semantic_policy", cache.policy_fingerprint);
        append_key_component(material, "semantic_budget", cache.budget_fingerprint);
        append_key_component(material, "semantic_evidence", cache.evidence_fingerprint);
        append_key_component(material, "semantic_generation", cache.scope.generation);
        append_key_component(material, "semantic_analysis", cache.scope.analysis_revision);
        append_key_component(material, "semantic_overlay", cache.scope.overlay_revision);
    }
    append_key_component(material, "cfg", request.cfg_result ? 1U : 0U);
    append_key_component(material, "consume_cfg", request.consume_cfg_facts ? 1U : 0U);
    if (request.cfg_result) {
        const auto& cfg = *request.cfg_result;
        append_key_component(material, "cfg_function", cfg.key.function_address.value);
        append_key_component(material, "cfg_generation", cfg.key.generation);
        append_key_component(material, "cfg_analysis", cfg.key.analysis_revision);
        append_key_component(material, "cfg_overlay", cfg.key.overlay_revision);
        append_key_component(material, "cfg_blocks", cfg.block_count);
        append_key_component(material, "cfg_edges", cfg.edge_count);
        append_key_component(material, "cfg_calls", cfg.callgraph_edges_found);
        append_key_component(material, "cfg_thunks", cfg.thunks_found);
        append_key_component(material, "cfg_tail_calls", cfg.tail_calls_found);
        append_key_component(material, "cfg_bounded", cfg.bounded ? 1U : 0U);
    }
    append_key_component(material, "calling_convention",
                         request.calling_convention_result ? 1U : 0U);
    append_key_component(material, "consume_calling_convention",
                         request.consume_calling_convention_facts ? 1U : 0U);
    if (request.consume_calling_convention_facts && request.calling_convention_result) {
        append_key_component(material, "calling_convention_fingerprint",
                             calling_convention_result_fingerprint(
                                 *request.calling_convention_result));
    }
    return stable_hash(material);
}

void canonicalize_evidence(type_recovery_result_t& result) {
    std::sort(result.evidence.begin(), result.evidence.end(), evidence_less);
    for (std::size_t index = 0; index < result.evidence.size(); ++index)
        result.evidence[index].evidence_id = static_cast<std::uint64_t>(index) + 1;
    std::sort(result.constraints.begin(), result.constraints.end(), constraint_less);
    result.evidence_collected = result.evidence.size();
    result.constraints_collected = result.constraints.size();
}

std::uint8_t provenance_strength(type_evidence_provenance_t provenance) {
    switch (provenance) {
        case type_evidence_provenance_t::user_definition: return 24;
        case type_evidence_provenance_t::debug_info: return 22;
        case type_evidence_provenance_t::source_symbol: return 18;
        case type_evidence_provenance_t::rtti:
        case type_evidence_provenance_t::objc_metadata:
        case type_evidence_provenance_t::swift_metadata:
        case type_evidence_provenance_t::managed_metadata: return 16;
        case type_evidence_provenance_t::import_symbol:
        case type_evidence_provenance_t::export_symbol: return 14;
        case type_evidence_provenance_t::decompiler: return 10;
        case type_evidence_provenance_t::vtable: return 8;
        case type_evidence_provenance_t::interprocedural: return 6;
        case type_evidence_provenance_t::calling_convention: return 6;
        case type_evidence_provenance_t::control_flow: return 4;
        case type_evidence_provenance_t::instruction_semantics: return 2;
        default: return 0;
    }
}

std::string display_name(const type_descriptor_t& descriptor) {
    if (!descriptor.declared_name.empty())
        return descriptor.declared_name;
    switch (descriptor.kind) {
        case recovered_type_kind_t::void_type: return "void";
        case recovered_type_kind_t::boolean: return "bool";
        case recovered_type_kind_t::integer:
            return descriptor.signedness == type_signedness_t::unsigned_value
                ? "uint" + std::to_string(descriptor.bit_width) + "_t"
                : "int" + std::to_string(descriptor.bit_width) + "_t";
        case recovered_type_kind_t::floating_point:
            return descriptor.bit_width == 32 ? "float" :
                   descriptor.bit_width == 64 ? "double" : "long double";
        case recovered_type_kind_t::pointer:
            return descriptor.referenced_type_name.empty()
                ? "void*" : descriptor.referenced_type_name + "*";
        case recovered_type_kind_t::reference:
            return descriptor.referenced_type_name.empty()
                ? "void&" : descriptor.referenced_type_name + "&";
        case recovered_type_kind_t::array:
            return (descriptor.referenced_type_name.empty() ? "uint" +
                    std::to_string(descriptor.element_bit_width) + "_t" :
                    descriptor.referenced_type_name) + "[" +
                    std::to_string(descriptor.element_count) + "]";
        case recovered_type_kind_t::function_type: return "function";
        case recovered_type_kind_t::function_pointer: return "function*";
        case recovered_type_kind_t::struct_type: return "struct";
        case recovered_type_kind_t::union_type: return "union";
        case recovered_type_kind_t::class_type: return "class";
        case recovered_type_kind_t::enum_type: return "enum";
        case recovered_type_kind_t::objc_object: return "id";
        case recovered_type_kind_t::swift_value: return "Swift.Value";
        case recovered_type_kind_t::managed_object: return "System.Object";
        case recovered_type_kind_t::opaque_handle: return "opaque_handle";
        case recovered_type_kind_t::unknown: return "unknown";
    }
    return "unknown";
}

struct candidate_score_t {
    type_descriptor_t descriptor;
    std::vector<std::uint64_t> evidence_ids;
    std::uint64_t score = 0;
    std::uint8_t strongest_confidence = 0;
    bool hard = false;
};

struct width_constraint_score_t {
    std::vector<std::uint64_t> evidence_ids;
    std::uint64_t score = 0;
    std::uint8_t strongest_confidence = 0;
};

bool resolve_evidence(type_recovery_result_t& result, const type_recovery_limits_t& limits,
                      recovery_poller_t& poller) {
    result.types.clear();
    result.conflicts.clear();
    result.abstentions.clear();
    std::size_t begin = 0;
    while (begin < result.evidence.size()) {
        if (poller.poll())
            return false;
        const auto subject_key = subject_material(result.evidence[begin].subject);
        std::size_t end = begin + 1;
        while (end < result.evidence.size() &&
               subject_material(result.evidence[end].subject) == subject_key) {
            ++end;
        }
        std::map<std::string, candidate_score_t> candidates;
        std::map<std::uint16_t, width_constraint_score_t> width_constraints;
        std::vector<std::uint64_t> all_evidence;
        for (std::size_t index = begin; index < end; ++index) {
            const auto& evidence = result.evidence[index];
            all_evidence.push_back(evidence.evidence_id);
            const std::uint64_t weight = evidence.confidence +
                provenance_strength(evidence.provenance) + (evidence.hard_constraint ? 64U : 0U);
            if (evidence.candidate.kind == recovered_type_kind_t::unknown) {
                if (evidence.candidate.bit_width == 0)
                    continue;
                auto& constraint = width_constraints[evidence.candidate.bit_width];
                constraint.score += weight;
                constraint.strongest_confidence = std::max(constraint.strongest_confidence,
                                                           evidence.confidence);
                constraint.evidence_ids.push_back(evidence.evidence_id);
                continue;
            }
            const auto key = descriptor_material(evidence.candidate);
            auto& candidate = candidates[key];
            if (candidate.evidence_ids.empty())
                candidate.descriptor = evidence.candidate;
            candidate.score += weight;
            candidate.strongest_confidence = std::max(candidate.strongest_confidence,
                                                       evidence.confidence);
            candidate.hard = candidate.hard || evidence.hard_constraint;
            candidate.evidence_ids.push_back(evidence.evidence_id);
        }
        if (result.types.size() >= limits.max_results) {
            result.bounded = true;
            break;
        }
        recovered_type_t recovered;
        recovered.subject = result.evidence[begin].subject;
        recovered.reg = recovered.subject.reg;
        recovered.stack_offset = recovered.subject.stack_offset;
        recovered.is_stack = recovered.subject.kind == type_subject_kind_t::stack_slot;
        if (candidates.empty()) {
            recovered.state = type_resolution_state_t::abstained;
            recovered.display_name = "unknown";
            recovered.supporting_evidence_ids = all_evidence;
            result.types.push_back(std::move(recovered));
            if (result.abstentions.size() < limits.max_results) {
                result.abstentions.push_back({result.evidence[begin].subject,
                    type_abstention_reason_t::no_evidence, all_evidence});
            }
            begin = end;
            continue;
        }
        std::vector<candidate_score_t> ranked;
        ranked.reserve(candidates.size());
        for (auto& [_, candidate] : candidates)
            ranked.push_back(std::move(candidate));
        std::sort(ranked.begin(), ranked.end(), [](const auto& lhs, const auto& rhs) {
            if (lhs.score != rhs.score)
                return lhs.score > rhs.score;
            if (lhs.hard != rhs.hard)
                return lhs.hard;
            return descriptor_material(lhs.descriptor) < descriptor_material(rhs.descriptor);
        });
        const auto& winner = ranked.front();
        const auto runner_score = ranked.size() > 1 ? ranked[1].score : 0;
        std::uint16_t selected_width = 0;
        const width_constraint_score_t* selected_width_constraint = nullptr;
        for (const auto& [width, constraint] : width_constraints) {
            if (!selected_width_constraint || constraint.score > selected_width_constraint->score ||
                (constraint.score == selected_width_constraint->score &&
                 constraint.strongest_confidence > selected_width_constraint->strongest_confidence) ||
                (constraint.score == selected_width_constraint->score &&
                 constraint.strongest_confidence == selected_width_constraint->strongest_confidence &&
                 width < selected_width)) {
                selected_width = width;
                selected_width_constraint = &constraint;
            }
        }
        const bool hard_conflict = ranked.size() > 1 && winner.hard && ranked[1].hard &&
            descriptor_material(winner.descriptor) != descriptor_material(ranked[1].descriptor);
        const bool close_conflict = ranked.size() > 1 &&
            winner.score <= runner_score + limits.conflict_margin;
        bool conflicting_width_constraints = false;
        if (selected_width_constraint) {
            for (const auto& [width, constraint] : width_constraints) {
                if (width == selected_width)
                    continue;
                if (constraint.strongest_confidence >= limits.minimum_confidence &&
                    constraint.score + limits.conflict_margin >= selected_width_constraint->score) {
                    conflicting_width_constraints = true;
                    break;
                }
            }
        }
        const bool width_conflict = selected_width_constraint && winner.descriptor.bit_width != 0 &&
            ((winner.descriptor.bit_width != selected_width &&
              selected_width_constraint->strongest_confidence >= limits.minimum_confidence &&
              selected_width_constraint->score + limits.conflict_margin >= winner.score) ||
             conflicting_width_constraints);
        const bool insufficient = winner.strongest_confidence < limits.minimum_confidence;
        recovered.descriptor = winner.descriptor;
        recovered.kind = winner.descriptor.kind;
        recovered.bit_width = winner.descriptor.bit_width;
        recovered.is_signed = winner.descriptor.signedness == type_signedness_t::signed_value;
        recovered.confidence = winner.strongest_confidence;
        recovered.supporting_evidence_ids = winner.evidence_ids;
        if (selected_width_constraint && winner.descriptor.bit_width == selected_width) {
            recovered.supporting_evidence_ids.insert(recovered.supporting_evidence_ids.end(),
                                                     selected_width_constraint->evidence_ids.begin(),
                                                     selected_width_constraint->evidence_ids.end());
        }
        recovered.display_name = display_name(winner.descriptor);
        if (hard_conflict || close_conflict || width_conflict) {
            recovered.state = type_resolution_state_t::conflicted;
            recovered.kind = recovered_type_kind_t::unknown;
            recovered.descriptor = unknown_descriptor();
            recovered.display_name = "unknown";
            for (const auto& candidate : ranked) {
                recovered.conflicting_evidence_ids.insert(recovered.conflicting_evidence_ids.end(),
                                                          candidate.evidence_ids.begin(),
                                                          candidate.evidence_ids.end());
            }
            if (width_conflict) {
                for (const auto& [_, constraint] : width_constraints) {
                    recovered.conflicting_evidence_ids.insert(
                        recovered.conflicting_evidence_ids.end(), constraint.evidence_ids.begin(),
                        constraint.evidence_ids.end());
                }
            }
            type_conflict_t conflict;
            conflict.subject = recovered.subject;
            conflict.winning_confidence = winner.strongest_confidence;
            conflict.hard_conflict = hard_conflict;
            for (const auto& candidate : ranked) {
                conflict.candidates.push_back(candidate.descriptor);
                conflict.evidence_ids.insert(conflict.evidence_ids.end(), candidate.evidence_ids.begin(),
                                             candidate.evidence_ids.end());
            }
            if (width_conflict) {
                for (const auto& [_, constraint] : width_constraints) {
                    conflict.evidence_ids.insert(conflict.evidence_ids.end(),
                                                 constraint.evidence_ids.begin(),
                                                 constraint.evidence_ids.end());
                }
            }
            result.conflicts.push_back(std::move(conflict));
        } else if (insufficient) {
            recovered.state = type_resolution_state_t::abstained;
            recovered.kind = recovered_type_kind_t::unknown;
            recovered.descriptor = unknown_descriptor();
            recovered.display_name = "unknown";
            if (result.abstentions.size() < limits.max_results) {
                result.abstentions.push_back({recovered.subject,
                    type_abstention_reason_t::insufficient_confidence, all_evidence});
            }
        } else {
            recovered.state = type_resolution_state_t::resolved;
        }
        result.types.push_back(std::move(recovered));
        begin = end;
    }
    std::sort(result.types.begin(), result.types.end(), [](const auto& lhs, const auto& rhs) {
        return subject_material(lhs.subject) < subject_material(rhs.subject);
    });
    std::sort(result.conflicts.begin(), result.conflicts.end(), [](const auto& lhs, const auto& rhs) {
        return subject_material(lhs.subject) < subject_material(rhs.subject);
    });
    std::sort(result.abstentions.begin(), result.abstentions.end(), [](const auto& lhs, const auto& rhs) {
        return subject_material(lhs.subject) < subject_material(rhs.subject);
    });
    result.types_recovered = std::count_if(result.types.begin(), result.types.end(), [](const auto& type) {
        return type.state == type_resolution_state_t::resolved;
    });
    return true;
}

bool propagate_constraints(type_recovery_result_t& result, const type_recovery_limits_t& limits,
                           collector_t& collector, recovery_poller_t& poller) {
    std::map<std::string, const recovered_type_t*> resolved;
    for (const auto& type : result.types) {
        if (type.state == type_resolution_state_t::resolved)
            resolved.emplace(subject_material(type.subject), &type);
    }
    std::set<std::string> known;
    for (const auto& evidence : result.evidence) {
        known.insert(subject_material(evidence.subject) + descriptor_material(evidence.candidate));
    }
    bool changed = false;
    for (const auto& constraint : result.constraints) {
        if (poller.poll())
            return false;
        if (!constraint.propagate || !constraint.target ||
            constraint.propagation_hops >= limits.max_interprocedural_depth)
            continue;
        const auto source = resolved.find(subject_material(constraint.source));
        if (source == resolved.end())
            continue;
        const auto target_key = subject_material(*constraint.target) +
                                descriptor_material(source->second->descriptor);
        if (!known.insert(target_key).second)
            continue;
        type_recovery_evidence_t evidence;
        evidence.subject = *constraint.target;
        evidence.related_subject = constraint.source;
        evidence.candidate = source->second->descriptor;
        evidence.provenance = (constraint.kind == type_constraint_kind_t::call_argument ||
                               constraint.kind == type_constraint_kind_t::call_return)
            ? type_evidence_provenance_t::interprocedural
            : type_evidence_provenance_t::instruction_semantics;
        evidence.kind = (constraint.kind == type_constraint_kind_t::call_argument)
            ? type_evidence_kind_t::call_argument
            : (constraint.kind == type_constraint_kind_t::call_return)
                ? type_evidence_kind_t::call_return : type_evidence_kind_t::assignment;
        evidence.source_address = constraint.source.address;
        evidence.source_entity_id = constraint.source.entity_id;
        const auto penalty = static_cast<std::uint32_t>(constraint.propagation_hops + 1U) * 8U;
        evidence.confidence = source->second->confidence > penalty
            ? static_cast<std::uint8_t>(source->second->confidence - penalty) : 0;
        evidence.propagation_hops = constraint.propagation_hops + 1;
        evidence.propagated = true;
        evidence.detail = "propagated";
        if (collector.append_evidence(std::move(evidence)))
            changed = true;
        if (collector.stopped)
            return false;
    }
    return changed;
}

struct metadata_match_t {
    recovered_type_kind_t kind = recovered_type_kind_t::unknown;
    type_language_t language = type_language_t::unknown;
    type_subject_kind_t subject_kind = type_subject_kind_t::metadata_type;
    type_evidence_provenance_t provenance = type_evidence_provenance_t::binary_metadata;
    type_evidence_kind_t evidence_kind = type_evidence_kind_t::metadata_hint;
};

metadata_match_t classify_metadata_name(const std::string& name) {
    const auto lower = lower_ascii(name);
    if (contains_token(name, "OBJC_CLASS_$_") || contains_token(lower, "objc_class")) {
        return {recovered_type_kind_t::objc_object, type_language_t::objective_c,
                type_subject_kind_t::objc_class, type_evidence_provenance_t::objc_metadata,
                type_evidence_kind_t::objc_descriptor};
    }
    if (contains_token(lower, "swift") || contains_token(lower, "nominal type descriptor")) {
        return {recovered_type_kind_t::swift_value, type_language_t::swift,
                type_subject_kind_t::swift_type, type_evidence_provenance_t::swift_metadata,
                type_evidence_kind_t::swift_descriptor};
    }
    if (contains_token(lower, "system.") || contains_token(lower, "mscorlib") ||
        contains_token(lower, "typedef") || contains_token(lower, "managed")) {
        return {recovered_type_kind_t::managed_object, type_language_t::csharp,
                type_subject_kind_t::managed_type, type_evidence_provenance_t::managed_metadata,
                type_evidence_kind_t::managed_descriptor};
    }
    if (contains_token(name, "??_R") || contains_token(name, "_ZTI") ||
        contains_token(lower, "typeinfo")) {
        return {recovered_type_kind_t::class_type, type_language_t::cpp,
                type_subject_kind_t::rtti_type, type_evidence_provenance_t::rtti,
                type_evidence_kind_t::rtti_descriptor};
    }
    if (contains_token(name, "??_7") || contains_token(name, "_ZTV") ||
        contains_token(lower, "vtable")) {
        return {recovered_type_kind_t::class_type, type_language_t::cpp,
                type_subject_kind_t::virtual_table, type_evidence_provenance_t::vtable,
                type_evidence_kind_t::vtable_descriptor};
    }
    if (contains_token(lower, "enum"))
        return {recovered_type_kind_t::enum_type, type_language_t::cpp,
                type_subject_kind_t::metadata_type, type_evidence_provenance_t::binary_metadata,
                type_evidence_kind_t::metadata_hint};
    if (contains_token(lower, "union"))
        return {recovered_type_kind_t::union_type, type_language_t::cpp,
                type_subject_kind_t::metadata_type, type_evidence_provenance_t::binary_metadata,
                type_evidence_kind_t::metadata_hint};
    if (contains_token(lower, "struct"))
        return {recovered_type_kind_t::struct_type, type_language_t::cpp,
                type_subject_kind_t::metadata_type, type_evidence_provenance_t::binary_metadata,
                type_evidence_kind_t::metadata_hint};
    if (contains_token(lower, "class"))
        return {recovered_type_kind_t::class_type, type_language_t::cpp,
                type_subject_kind_t::metadata_type, type_evidence_provenance_t::binary_metadata,
                type_evidence_kind_t::metadata_hint};
    return {};
}

void collect_image_metadata(const analysis_workspace_t& workspace, collector_t& collector) {
    const auto image = workspace.normalized_image();
    if (!image)
        return;
    for (const auto& symbol : image->symbols) {
        if (collector.poller.poll()) {
            collector.stopped = true;
            return;
        }
        if (!collector.consume_work_unit())
            return;
        type_subject_t subject;
        subject.address = symbol.address;
        subject.entity_id = symbol.ordinal;
        subject.stable_name = symbol.name;
        type_recovery_evidence_t evidence;
        evidence.source_address = symbol.address;
        evidence.source_entity_id = symbol.ordinal;
        evidence.detail = symbol.name;
        evidence.candidate = unknown_descriptor(symbol.name);
        evidence.confidence = symbol.kind == image_symbol_kind_t::debug_symbol ? 92 : 58;
        evidence.provenance = symbol.kind == image_symbol_kind_t::debug_symbol
            ? type_evidence_provenance_t::debug_info : type_evidence_provenance_t::source_symbol;
        evidence.kind = symbol.kind == image_symbol_kind_t::debug_symbol
            ? type_evidence_kind_t::debug_symbol : type_evidence_kind_t::source_symbol;
        if (symbol.kind == image_symbol_kind_t::function) {
            subject.kind = type_subject_kind_t::function;
            subject.function_rva = symbol.address.value;
            evidence.candidate.kind = recovered_type_kind_t::function_type;
            evidence.candidate.signedness = type_signedness_t::not_applicable;
        } else if (symbol.kind == image_symbol_kind_t::object) {
            subject.kind = type_subject_kind_t::global;
        } else {
            subject.kind = type_subject_kind_t::metadata_type;
        }
        const auto match = classify_metadata_name(symbol.name);
        if (match.kind != recovered_type_kind_t::unknown) {
            subject.kind = match.subject_kind;
            evidence.candidate.kind = match.kind;
            evidence.candidate.language = match.language;
            evidence.provenance = match.provenance;
            evidence.kind = match.evidence_kind;
            evidence.confidence = std::max<std::uint8_t>(evidence.confidence, 82);
        }
        evidence.subject = std::move(subject);
        collector.append_evidence(std::move(evidence));
        if (collector.stopped || collector.work_limited)
            return;
    }
    for (const auto& imported : image->imports) {
        if (collector.poller.poll()) {
            collector.stopped = true;
            return;
        }
        if (!collector.consume_work_unit())
            return;
        type_recovery_evidence_t evidence;
        evidence.subject.kind = type_subject_kind_t::imported_symbol;
        evidence.subject.address = imported.address;
        evidence.subject.stable_name = imported.library + "!" +
            (imported.name ? *imported.name : std::to_string(imported.ordinal.value_or(0)));
        evidence.candidate.kind = recovered_type_kind_t::function_pointer;
        evidence.candidate.signedness = type_signedness_t::not_applicable;
        evidence.candidate.declared_name = evidence.subject.stable_name;
        evidence.provenance = type_evidence_provenance_t::import_symbol;
        evidence.kind = type_evidence_kind_t::import_symbol;
        evidence.source_address = imported.address;
        evidence.confidence = 86;
        evidence.detail = imported.delayed ? "delayed_import" : "import";
        collector.append_evidence(std::move(evidence));
        if (collector.stopped || collector.work_limited)
            return;
    }
    for (const auto& exported : image->exports) {
        if (collector.poller.poll()) {
            collector.stopped = true;
            return;
        }
        if (!collector.consume_work_unit())
            return;
        type_recovery_evidence_t evidence;
        evidence.subject.kind = type_subject_kind_t::exported_symbol;
        evidence.subject.address = exported.address;
        evidence.subject.function_rva = exported.address.value;
        evidence.subject.entity_id = exported.ordinal;
        evidence.subject.stable_name = exported.name.value_or(std::to_string(exported.ordinal));
        evidence.candidate.kind = recovered_type_kind_t::function_type;
        evidence.candidate.signedness = type_signedness_t::not_applicable;
        evidence.candidate.declared_name = evidence.subject.stable_name;
        evidence.provenance = type_evidence_provenance_t::export_symbol;
        evidence.kind = type_evidence_kind_t::export_symbol;
        evidence.source_address = exported.address;
        evidence.confidence = 84;
        evidence.detail = exported.forwarder.value_or("export");
        collector.append_evidence(std::move(evidence));
        if (collector.stopped || collector.work_limited)
            return;
    }
}

type_descriptor_t descriptor_from_semantic(const semantic_type_descriptor_t& semantic) {
    type_descriptor_t descriptor;
    descriptor.bit_width = semantic.bit_width;
    descriptor.referenced_type_id = semantic.type_id;
    descriptor.declared_name = semantic.display_name;
    descriptor.signedness = semantic.is_signed ? type_signedness_t::signed_value
                                                : type_signedness_t::unknown;
    switch (semantic.kind) {
        case semantic_type_kind_t::void_type:
            descriptor.kind = recovered_type_kind_t::void_type;
            descriptor.signedness = type_signedness_t::not_applicable;
            break;
        case semantic_type_kind_t::boolean:
            descriptor.kind = recovered_type_kind_t::boolean;
            descriptor.signedness = type_signedness_t::not_applicable;
            break;
        case semantic_type_kind_t::integer:
            descriptor.kind = recovered_type_kind_t::integer;
            break;
        case semantic_type_kind_t::floating_point:
            descriptor.kind = recovered_type_kind_t::floating_point;
            descriptor.signedness = type_signedness_t::not_applicable;
            break;
        case semantic_type_kind_t::pointer:
            descriptor.kind = recovered_type_kind_t::pointer;
            descriptor.signedness = type_signedness_t::not_applicable;
            descriptor.nullable = true;
            break;
        case semantic_type_kind_t::array:
            descriptor.kind = recovered_type_kind_t::array;
            descriptor.signedness = type_signedness_t::not_applicable;
            break;
        case semantic_type_kind_t::structure:
            descriptor.kind = recovered_type_kind_t::struct_type;
            descriptor.signedness = type_signedness_t::not_applicable;
            break;
        case semantic_type_kind_t::union_type:
            descriptor.kind = recovered_type_kind_t::union_type;
            descriptor.signedness = type_signedness_t::not_applicable;
            break;
        case semantic_type_kind_t::enumeration:
            descriptor.kind = recovered_type_kind_t::enum_type;
            break;
        case semantic_type_kind_t::function:
            descriptor.kind = semantic.pointer_depth == 0
                ? recovered_type_kind_t::function_type : recovered_type_kind_t::function_pointer;
            descriptor.signedness = type_signedness_t::not_applicable;
            break;
        case semantic_type_kind_t::reference:
            descriptor.kind = recovered_type_kind_t::reference;
            descriptor.signedness = type_signedness_t::not_applicable;
            break;
        case semantic_type_kind_t::managed_reference:
            descriptor.kind = recovered_type_kind_t::managed_object;
            descriptor.language = type_language_t::csharp;
            descriptor.signedness = type_signedness_t::not_applicable;
            break;
        case semantic_type_kind_t::unknown:
            break;
    }
    if (semantic.pointer_depth > 0 && descriptor.kind != recovered_type_kind_t::function_pointer &&
        descriptor.kind != recovered_type_kind_t::pointer) {
        descriptor.referenced_type_name = descriptor.declared_name;
        descriptor.declared_name.clear();
        descriptor.kind = recovered_type_kind_t::pointer;
        descriptor.signedness = type_signedness_t::not_applicable;
        descriptor.nullable = true;
    }
    return descriptor;
}

type_evidence_provenance_t provenance_from_semantic(const semantic_provenance_t* provenance) {
    if (!provenance)
        return type_evidence_provenance_t::decompiler;
    if (provenance->source != fact_provenance_t::unknown) {
        const auto mapped = provenance_from_fact(provenance->source);
        if (mapped != type_evidence_provenance_t::instruction_semantics)
            return mapped;
    }
    switch (provenance->origin) {
        case semantic_origin_t::workspace_decode:
            return type_evidence_provenance_t::instruction_semantics;
        case semantic_origin_t::workspace_cfg:
            return type_evidence_provenance_t::control_flow;
        case semantic_origin_t::workspace_metadata:
            return type_evidence_provenance_t::binary_metadata;
        case semantic_origin_t::decompiler_ir:
        case semantic_origin_t::decompiler_type_recovery:
        case semantic_origin_t::decompiler_simplifier:
            return type_evidence_provenance_t::decompiler;
        case semantic_origin_t::user_annotation:
            return type_evidence_provenance_t::user_definition;
        case semantic_origin_t::external_validator:
            return type_evidence_provenance_t::binary_metadata;
        case semantic_origin_t::unknown:
            return type_evidence_provenance_t::unknown;
    }
    return type_evidence_provenance_t::unknown;
}

address_t semantic_address(const analysis_workspace_t& workspace, const address_t& supplied,
                           std::uint64_t function_rva) {
    if (supplied.architecture != architecture_id_t::unknown)
        return supplied;
    const auto value = supplied.value != 0 ? supplied.value : function_rva;
    return make_address(workspace, supplied.space, value);
}

type_subject_t subject_from_semantic(const analysis_workspace_t& workspace,
                                     const semantic_scope_key_t& scope,
                                     const semantic_subject_t& semantic_subject,
                                     const semantic_location_t& location,
                                     const address_t& source_address) {
    type_subject_t subject;
    subject.entity_id = semantic_subject.function_id;
    subject.container_id = semantic_subject.instruction_id;
    subject.function_rva = scope.function_address.value;
    subject.address = semantic_address(workspace,
        semantic_subject.address.value != 0 ? semantic_subject.address : source_address,
        subject.function_rva);
    subject.reg = location.register_id;
    subject.stack_offset = location.stack_offset;
    subject.ordinal = static_cast<std::uint32_t>(semantic_subject.ordinal);
    switch (location.kind) {
        case semantic_location_kind_t::register_value:
            subject.kind = type_subject_kind_t::local;
            subject.stable_name = "semantic_register";
            break;
        case semantic_location_kind_t::stack_slot:
            subject.kind = type_subject_kind_t::stack_slot;
            subject.stable_name = "semantic_stack";
            break;
        case semantic_location_kind_t::global_address:
            subject.kind = type_subject_kind_t::global;
            subject.address = make_address(workspace, location.address_space, location.global_address);
            subject.stable_name = "semantic_global";
            break;
        case semantic_location_kind_t::memory_address:
            subject.kind = type_subject_kind_t::memory_location;
            subject.address = make_address(workspace, location.address_space, location.global_address);
            subject.stable_name = "semantic_memory";
            break;
        case semantic_location_kind_t::function_return:
            subject.kind = type_subject_kind_t::return_value;
            subject.stable_name = "semantic_return";
            break;
        case semantic_location_kind_t::function_argument:
            subject.kind = type_subject_kind_t::parameter;
            subject.stable_name = "semantic_parameter";
            break;
        case semantic_location_kind_t::immediate_value:
            subject.kind = type_subject_kind_t::local;
            subject.stable_name = "semantic_immediate";
            break;
        case semantic_location_kind_t::temporary:
            subject.kind = type_subject_kind_t::local;
            subject.entity_id = location.temporary_id;
            subject.stable_name = "semantic_temporary";
            break;
        case semantic_location_kind_t::unknown:
            subject.kind = semantic_subject.kind == semantic_subject_kind_t::function
                ? type_subject_kind_t::function : type_subject_kind_t::metadata_type;
            subject.stable_name = "semantic_unknown";
            break;
    }
    return subject;
}

bool semantic_scope_matches(const type_recovery_cache_key_t& key,
                            const semantic_fusion_result_t& semantic) {
    const auto& scope = semantic.scope;
    return scope.binary_id == key.binary_id && scope.function_address == key.root_address &&
           scope.architecture == key.architecture &&
           scope.architecture_mode == key.architecture_mode && scope.abi == key.abi &&
           scope.address_space == key.root_address.space && scope.generation == key.generation &&
           scope.analysis_revision == key.analysis_revision &&
           scope.overlay_revision == key.overlay_revision;
}

bool calling_convention_scope_matches(const type_recovery_cache_key_t& key,
                                      const cc_analysis_result_t& calling_convention) {
    return calling_convention.cache_key == key.calling_convention_key &&
           calling_convention.function_rva == key.root_address.value;
}

void collect_calling_convention_facts(const analysis_workspace_t& workspace,
                                      const cc_analysis_result_t& calling_convention,
                                      collector_t& collector) {
    if (calling_convention.bounded)
        collector.result.bounded = true;
    if (!collector.consume_work_unit())
        return;
    type_recovery_evidence_t function;
    function.subject.kind = type_subject_kind_t::function;
    function.subject.address = calling_convention.cache_key.function;
    function.subject.function_rva = calling_convention.function_rva;
    function.subject.stable_name = "calling_convention_function";
    if (calling_convention.state == cc_inference_state_t::inferred &&
        !calling_convention.bounded) {
        function.candidate.kind = recovered_type_kind_t::function_type;
        function.candidate.signedness = type_signedness_t::not_applicable;
        function.candidate.noreturn = calling_convention.is_noreturn;
    }
    function.provenance = type_evidence_provenance_t::calling_convention;
    function.kind = type_evidence_kind_t::calling_convention_function;
    function.source_address = calling_convention.cache_key.function;
    function.source_entity_id = calling_convention.function_rva;
    function.confidence = calling_convention.confidence;
    function.detail = calling_convention.state == cc_inference_state_t::conflicted
        ? "calling_convention_conflicted"
        : calling_convention.state == cc_inference_state_t::abstained
            ? "calling_convention_abstained" : "calling_convention";
    collector.append_evidence(std::move(function));
    if (collector.work_limited || collector.stopped || calling_convention.bounded ||
        calling_convention.state != cc_inference_state_t::inferred) {
        return;
    }

    if (calling_convention.arguments_state == cc_value_state_t::inferred) {
        std::vector<const argument_info_t*> arguments;
        arguments.reserve(calling_convention.arguments.size());
        for (const auto& argument : calling_convention.arguments)
            if (argument.used)
                arguments.push_back(&argument);
        std::sort(arguments.begin(), arguments.end(), [](const auto* lhs, const auto* rhs) {
            return std::tie(lhs->index, lhs->abi_slot, lhs->location, lhs->reg, lhs->stack_offset,
                            lhs->bit_width, lhs->is_float, lhs->is_vector, lhs->conflicted,
                            lhs->confidence) <
                   std::tie(rhs->index, rhs->abi_slot, rhs->location, rhs->reg, rhs->stack_offset,
                            rhs->bit_width, rhs->is_float, rhs->is_vector, rhs->conflicted,
                            rhs->confidence);
        });
        for (const auto* argument : arguments) {
            if (collector.poller.poll()) {
                collector.stopped = true;
                return;
            }
            if (!collector.consume_work_unit())
                return;
            type_recovery_evidence_t evidence;
            evidence.subject = make_parameter_subject(workspace, calling_convention.function_rva,
                                                      argument->index);
            if (!argument->conflicted && argument->bit_width != 0)
                evidence.candidate = width_constraint_descriptor(argument->bit_width);
            evidence.provenance = type_evidence_provenance_t::calling_convention;
            evidence.kind = type_evidence_kind_t::calling_convention_argument;
            evidence.source_address = calling_convention.cache_key.function;
            evidence.source_entity_id = argument->abi_slot;
            evidence.confidence = argument->confidence;
            evidence.detail = argument->conflicted ? "calling_convention_argument_conflicted"
                                                   : "calling_convention_argument";
            collector.append_evidence(evidence);
            if (collector.work_limited || collector.stopped)
                return;

            type_constraint_t constraint;
            constraint.kind = type_constraint_kind_t::calling_convention_argument;
            constraint.relation = type_constraint_relation_t::call_argument_to;
            constraint.source = evidence.subject;
            constraint.candidate = evidence.candidate;
            constraint.reg = argument->reg;
            constraint.stack_offset = argument->stack_offset;
            constraint.bit_width = argument->bit_width;
            constraint.instruction_rva = calling_convention.function_rva;
            constraint.target_entity_id = argument->abi_slot;
            constraint.provenance = type_evidence_provenance_t::calling_convention;
            constraint.confidence = argument->confidence;
            collector.append_constraint(std::move(constraint));
            if (collector.work_limited || collector.stopped)
                return;
        }
    }

    if (calling_convention.return_value.state == cc_value_state_t::unknown)
        return;
    if (collector.poller.poll()) {
        collector.stopped = true;
        return;
    }
    if (!collector.consume_work_unit())
        return;
    type_recovery_evidence_t returned;
    returned.subject = make_return_subject(workspace, calling_convention.function_rva);
    if (calling_convention.return_value.state == cc_value_state_t::inferred &&
        calling_convention.return_value.bit_width != 0) {
        returned.candidate = width_constraint_descriptor(calling_convention.return_value.bit_width);
    }
    returned.provenance = type_evidence_provenance_t::calling_convention;
    returned.kind = type_evidence_kind_t::calling_convention_return;
    returned.source_address = calling_convention.cache_key.function;
    returned.source_entity_id = calling_convention.return_reg;
    returned.confidence = calling_convention.return_value.confidence;
    returned.detail = calling_convention.return_value.state == cc_value_state_t::conflicted
        ? "calling_convention_return_conflicted"
        : calling_convention.return_value.state == cc_value_state_t::abstained
            ? "calling_convention_return_abstained" : "calling_convention_return";
    collector.append_evidence(returned);
    if (collector.work_limited || collector.stopped)
        return;

    type_constraint_t constraint;
    constraint.kind = type_constraint_kind_t::calling_convention_return;
    constraint.relation = type_constraint_relation_t::call_return_from;
    constraint.source = returned.subject;
    constraint.candidate = returned.candidate;
    constraint.reg = calling_convention.return_reg;
    constraint.bit_width = calling_convention.return_value.bit_width;
    constraint.instruction_rva = calling_convention.function_rva;
    constraint.provenance = type_evidence_provenance_t::calling_convention;
    constraint.confidence = calling_convention.return_value.confidence;
    collector.append_constraint(std::move(constraint));
}

void collect_semantic_facts(const analysis_workspace_t& workspace,
                            const semantic_fusion_result_t& semantic,
                            collector_t& collector) {
    for (const auto& fact : semantic.facts) {
        if (collector.poller.poll()) {
            collector.stopped = true;
            return;
        }
        if (!collector.consume_work_unit())
            return;
        if (fact.resolution == semantic_resolution_t::rejected)
            continue;
        const semantic_provenance_t* provenance = fact.provenance.empty()
            ? nullptr : &fact.provenance.front();
        const auto mapped_provenance = provenance_from_semantic(provenance);
        const auto hard = fact.validation == semantic_validation_t::validated &&
            fact.resolution == semantic_resolution_t::accepted;
        const auto confidence = fact.confidence;
        if (fact.kind == semantic_fact_kind_t::type) {
            const auto* payload = std::get_if<::aida::analysis::type_evidence_t>(&fact.payload);
            if (!payload)
                continue;
            type_recovery_evidence_t evidence;
            evidence.subject = subject_from_semantic(workspace, semantic.scope, fact.subject,
                                                     payload->location, payload->address);
            evidence.candidate = descriptor_from_semantic(payload->type);
            if (fact.resolution == semantic_resolution_t::abstained ||
                fact.resolution == semantic_resolution_t::conflict) {
                evidence.candidate = unknown_descriptor();
            }
            evidence.provenance = mapped_provenance;
            evidence.kind = type_evidence_kind_t::direct_declaration;
            evidence.source_address = semantic_address(workspace, payload->address,
                                                       semantic.scope.function_address.value);
            evidence.source_entity_id = payload->instruction_id;
            evidence.confidence = confidence;
            evidence.hard_constraint = hard;
            evidence.detail = fact.resolution == semantic_resolution_t::conflict
                ? "semantic_conflict" : fact.resolution == semantic_resolution_t::abstained
                    ? "semantic_abstention" : "semantic_type";
            collector.append_evidence(std::move(evidence));
        } else if (fact.kind == semantic_fact_kind_t::prototype) {
            const auto* payload = std::get_if<prototype_evidence_t>(&fact.payload);
            if (!payload)
                continue;
            for (std::size_t index = 0; index < payload->arguments.size(); ++index) {
                type_recovery_evidence_t argument;
                argument.subject = make_parameter_subject(workspace, payload->function.value,
                    static_cast<std::uint32_t>(index));
                argument.candidate = descriptor_from_semantic(payload->arguments[index]);
                argument.provenance = mapped_provenance;
                argument.kind = type_evidence_kind_t::call_argument;
                argument.source_address = semantic_address(workspace, payload->function,
                                                            semantic.scope.function_address.value);
                argument.source_entity_id = fact.subject.instruction_id;
                argument.confidence = confidence;
                argument.hard_constraint = hard;
                argument.detail = "semantic_prototype_argument";
                collector.append_evidence(std::move(argument));
                if (collector.work_limited || collector.stopped)
                    return;
            }
            type_recovery_evidence_t returned;
            returned.subject = make_return_subject(workspace, payload->function.value);
            returned.candidate = descriptor_from_semantic(payload->return_type);
            returned.candidate.variadic = payload->variadic;
            returned.candidate.noreturn = payload->noreturn;
            returned.provenance = mapped_provenance;
            returned.kind = type_evidence_kind_t::call_return;
            returned.source_address = semantic_address(workspace, payload->function,
                                                        semantic.scope.function_address.value);
            returned.source_entity_id = fact.subject.instruction_id;
            returned.confidence = confidence;
            returned.hard_constraint = hard;
            returned.detail = "semantic_prototype_return";
            collector.append_evidence(std::move(returned));
        } else if (fact.kind == semantic_fact_kind_t::metadata) {
            const auto* payload = std::get_if<metadata_evidence_t>(&fact.payload);
            if (!payload)
                continue;
            auto match = classify_metadata_name(payload->name);
            if (match.kind == recovered_type_kind_t::unknown) {
                switch (payload->kind) {
                    case metadata_kind_t::rtti:
                        match = {recovered_type_kind_t::class_type, type_language_t::cpp,
                                 type_subject_kind_t::rtti_type, type_evidence_provenance_t::rtti,
                                 type_evidence_kind_t::rtti_descriptor};
                        break;
                    case metadata_kind_t::vtable:
                        match = {recovered_type_kind_t::class_type, type_language_t::cpp,
                                 type_subject_kind_t::virtual_table, type_evidence_provenance_t::vtable,
                                 type_evidence_kind_t::vtable_descriptor};
                        break;
                    case metadata_kind_t::import:
                        match = {recovered_type_kind_t::function_pointer, type_language_t::unknown,
                                 type_subject_kind_t::imported_symbol,
                                 type_evidence_provenance_t::import_symbol,
                                 type_evidence_kind_t::import_symbol};
                        break;
                    case metadata_kind_t::export_symbol:
                        match = {recovered_type_kind_t::function_type, type_language_t::unknown,
                                 type_subject_kind_t::exported_symbol,
                                 type_evidence_provenance_t::export_symbol,
                                 type_evidence_kind_t::export_symbol};
                        break;
                    case metadata_kind_t::debug:
                        match = {recovered_type_kind_t::unknown, type_language_t::unknown,
                                 type_subject_kind_t::metadata_type,
                                 type_evidence_provenance_t::debug_info,
                                 type_evidence_kind_t::debug_symbol};
                        break;
                    default:
                        break;
                }
            }
            type_recovery_evidence_t evidence;
            semantic_location_t location;
            location.kind = semantic_location_kind_t::global_address;
            location.address_space = payload->address.space;
            location.global_address = payload->address.value;
            evidence.subject = subject_from_semantic(workspace, semantic.scope, fact.subject,
                                                     location, payload->address);
            evidence.subject.kind = match.subject_kind;
            evidence.subject.stable_name = payload->name;
            evidence.candidate.kind = match.kind;
            evidence.candidate.language = match.language;
            evidence.candidate.declared_name = payload->name;
            evidence.candidate.referenced_type_id = payload->value;
            evidence.provenance = match.kind == recovered_type_kind_t::unknown
                ? mapped_provenance : match.provenance;
            evidence.kind = match.evidence_kind;
            evidence.source_address = semantic_address(workspace, payload->address,
                                                       semantic.scope.function_address.value);
            evidence.source_entity_id = fact.subject.instruction_id;
            evidence.confidence = payload->authoritative ? std::max<std::uint8_t>(confidence, 90)
                                                          : confidence;
            evidence.hard_constraint = hard || payload->authoritative;
            evidence.detail = "semantic_metadata";
            collector.append_evidence(std::move(evidence));
        }
        if (collector.work_limited || collector.stopped)
            return;
    }
}

bool cfg_scope_matches(const type_recovery_cache_key_t& key, const cfg_analysis_result_t& cfg) {
    const auto& cfg_key = cfg.key;
    return cfg_key.binary_id == key.binary_id && cfg_key.function_address == key.root_address &&
           cfg_key.architecture == key.architecture &&
           cfg_key.architecture_mode == key.architecture_mode &&
           cfg_key.address_space == key.root_address.space &&
           cfg_key.generation == key.generation &&
           cfg_key.analysis_revision == key.analysis_revision &&
           cfg_key.overlay_revision == key.overlay_revision;
}

type_evidence_provenance_t provenance_from_cfg_quality(const advanced_cfg_quality_t& quality) {
    if (quality.provenance == fact_provenance_t::unknown)
        return type_evidence_provenance_t::control_flow;
    const auto provenance = provenance_from_fact(quality.provenance);
    return provenance == type_evidence_provenance_t::instruction_semantics
        ? type_evidence_provenance_t::control_flow : provenance;
}

type_subject_t make_cfg_function_subject(const analysis_workspace_t& workspace,
                                         std::uint64_t function_rva, entity_id_t function_id) {
    type_subject_t subject;
    subject.kind = type_subject_kind_t::function;
    subject.address = make_address(workspace, address_space_id_t::relative_virtual, function_rva);
    subject.entity_id = function_id;
    subject.function_rva = function_rva;
    subject.stable_name = "cfg_function";
    return subject;
}

void collect_cfg_facts(const analysis_workspace_t& workspace, const cfg_analysis_result_t& cfg,
                       collector_t& collector, std::vector<call_record_t>& calls) {
    if (cfg.bounded)
        collector.result.bounded = true;
    if (cfg.function_noreturn) {
        type_recovery_evidence_t function;
        function.subject = make_cfg_function_subject(workspace, cfg.function_rva, 0);
        function.candidate.kind = recovered_type_kind_t::function_type;
        function.candidate.signedness = type_signedness_t::not_applicable;
        function.candidate.noreturn = true;
        function.provenance = type_evidence_provenance_t::control_flow;
        function.kind = type_evidence_kind_t::function_target;
        function.source_address = function.subject.address;
        function.confidence = 82;
        function.hard_constraint = !cfg.bounded;
        function.detail = "cfg_function_noreturn";
        collector.append_evidence(std::move(function));
        if (collector.work_limited || collector.stopped)
            return;
    }
    for (const auto& edge : cfg.callgraph_edges) {
        if (collector.poller.poll()) {
            collector.stopped = true;
            return;
        }
        if (!collector.consume_work_unit())
            return;
        type_recovery_evidence_t target;
        if (edge.target_rva == 0 && (edge.is_indirect || edge.external_target)) {
            target.subject.kind = type_subject_kind_t::function_pointer;
            target.subject.address = make_address(workspace, address_space_id_t::relative_virtual,
                                                  edge.call_site_rva);
            target.subject.entity_id = edge.source_block_id;
            target.subject.function_rva = cfg.function_rva;
            target.subject.stable_name = "cfg_indirect_target";
            target.candidate.kind = recovered_type_kind_t::function_pointer;
        } else {
            target.subject = make_cfg_function_subject(workspace, edge.target_rva,
                                                       edge.target_function_id.value_or(0));
            target.candidate.kind = edge.is_indirect ? recovered_type_kind_t::function_pointer
                                                      : recovered_type_kind_t::function_type;
        }
        target.candidate.signedness = type_signedness_t::not_applicable;
        target.candidate.noreturn = edge.target_noreturn;
        target.provenance = provenance_from_cfg_quality(edge.quality);
        target.kind = type_evidence_kind_t::function_target;
        target.source_address = make_address(workspace, address_space_id_t::relative_virtual,
                                             edge.call_site_rva);
        target.source_entity_id = edge.source_block_id;
        target.confidence = std::max<std::uint8_t>(edge.quality.confidence,
                                                   edge.is_indirect ? 35 : 64);
        target.hard_constraint = !edge.quality.conflicted && !edge.is_indirect;
        target.detail = edge.is_tail_call ? "cfg_tail_call" :
                        edge.is_indirect ? "cfg_indirect_call" : "cfg_call";
        collector.append_evidence(std::move(target));
        calls.push_back({edge.call_site_rva, edge.target_rva, edge.is_indirect});
        if (collector.work_limited || collector.stopped)
            return;
    }
    for (const auto& thunk : cfg.thunks) {
        if (collector.poller.poll()) {
            collector.stopped = true;
            return;
        }
        if (!collector.consume_work_unit())
            return;
        type_recovery_evidence_t target;
        target.subject = make_cfg_function_subject(workspace, thunk.target_rva, thunk.target_function_id);
        target.candidate.kind = recovered_type_kind_t::function_type;
        target.candidate.signedness = type_signedness_t::not_applicable;
        target.provenance = provenance_from_cfg_quality(thunk.quality);
        target.kind = type_evidence_kind_t::function_target;
        target.source_address = make_address(workspace, address_space_id_t::relative_virtual,
                                             thunk.thunk_rva);
        target.source_entity_id = thunk.target_function_id;
        target.confidence = std::max<std::uint8_t>(thunk.quality.confidence, 68);
        target.hard_constraint = !thunk.quality.conflicted;
        target.detail = thunk.is_import_thunk ? "cfg_import_thunk" : "cfg_thunk";
        collector.append_evidence(std::move(target));
        calls.push_back({thunk.thunk_rva, thunk.target_rva, false});
        if (collector.work_limited || collector.stopped)
            return;
    }
    for (const auto& effect : cfg.noreturn_effects) {
        if (collector.poller.poll()) {
            collector.stopped = true;
            return;
        }
        if (!collector.consume_work_unit())
            return;
        type_recovery_evidence_t target;
        target.subject = make_cfg_function_subject(workspace, effect.target_rva,
                                                   effect.target_function_id);
        target.candidate.kind = recovered_type_kind_t::function_type;
        target.candidate.signedness = type_signedness_t::not_applicable;
        target.candidate.noreturn = true;
        target.provenance = provenance_from_cfg_quality(effect.quality);
        target.kind = type_evidence_kind_t::function_target;
        target.source_address = make_address(workspace, address_space_id_t::relative_virtual,
                                             effect.call_site_rva);
        target.source_entity_id = effect.source_block_id;
        target.confidence = std::max<std::uint8_t>(effect.quality.confidence,
                                                   effect.suppresses_fallthrough ? 76 : 48);
        target.hard_constraint = effect.suppresses_fallthrough && !effect.quality.conflicted;
        target.detail = "cfg_noreturn";
        collector.append_evidence(std::move(target));
        if (collector.work_limited || collector.stopped)
            return;
    }
}

void append_local_width_evidence(const analysis_workspace_t& workspace,
                                 const function_record_t& function,
                                 const instruction_record_t& instruction,
                                 const operand_fact_t& operand,
                                 collector_t& collector) {
    if (operand.reg == 0 || operand.bit_width == 0)
        return;
    type_recovery_evidence_t evidence;
    evidence.subject = make_local_subject(workspace, function, operand.reg);
    evidence.candidate = integer_descriptor(operand.bit_width, operand.signed_value);
    evidence.provenance = provenance_from_fact(instruction.provenance);
    evidence.kind = type_evidence_kind_t::value_width;
    evidence.source_address = instruction.address;
    evidence.source_entity_id = instruction.id;
    evidence.confidence = operand.bit_width == 1 ? 48 : 36;
    evidence.detail = operand_is_written(operand) ? "register_write" : "register_read";
    collector.append_evidence(std::move(evidence));

    type_constraint_t constraint;
    constraint.kind = type_constraint_kind_t::register_width;
    constraint.relation = type_constraint_relation_t::compatible;
    constraint.source = make_local_subject(workspace, function, operand.reg);
    constraint.candidate = integer_descriptor(operand.bit_width, operand.signed_value);
    constraint.reg = operand.reg;
    constraint.bit_width = operand.bit_width;
    constraint.instruction_rva = instruction.address.value;
    constraint.source_instruction_id = instruction.id;
    constraint.inferred_kind = constraint.candidate.kind;
    constraint.provenance = provenance_from_fact(instruction.provenance);
    constraint.confidence = 36;
    collector.append_constraint(std::move(constraint));
}

void append_memory_evidence(const analysis_workspace_t& workspace,
                            const function_record_t& function,
                            const instruction_record_t& instruction,
                            const operand_fact_t& operand,
                            std::uint16_t pointer_bits,
                            collector_t& collector) {
    const auto width = operand.access_width_bits != 0 ? operand.access_width_bits : operand.bit_width;
    if (operand.base_reg != 0) {
        type_recovery_evidence_t pointer;
        pointer.subject = make_local_subject(workspace, function, operand.base_reg);
        pointer.candidate = pointer_descriptor(pointer_bits);
        pointer.provenance = provenance_from_fact(instruction.provenance);
        pointer.kind = type_evidence_kind_t::pointer_dereference;
        pointer.source_address = instruction.address;
        pointer.source_entity_id = instruction.id;
        pointer.confidence = 72;
        pointer.detail = "memory_base";
        collector.append_evidence(std::move(pointer));

        type_constraint_t pointer_constraint;
        pointer_constraint.kind = type_constraint_kind_t::pointer_dereference;
        pointer_constraint.relation = type_constraint_relation_t::points_to;
        pointer_constraint.source = make_local_subject(workspace, function, operand.base_reg);
        pointer_constraint.candidate = pointer_descriptor(pointer_bits);
        pointer_constraint.reg = operand.base_reg;
        pointer_constraint.bit_width = pointer_bits;
        pointer_constraint.instruction_rva = instruction.address.value;
        pointer_constraint.source_instruction_id = instruction.id;
        pointer_constraint.inferred_kind = recovered_type_kind_t::pointer;
        pointer_constraint.provenance = provenance_from_fact(instruction.provenance);
        pointer_constraint.confidence = 72;
        collector.append_constraint(std::move(pointer_constraint));
    }
    type_descriptor_t value = operand.element_count > 1
        ? array_descriptor(operand.element_width_bits != 0 ? operand.element_width_bits : width,
                           operand.element_count)
        : integer_descriptor(width, operand.signed_value);
    if (is_stack_expression(operand)) {
        type_recovery_evidence_t local;
        local.subject = make_stack_subject(workspace, function, operand.base_reg, operand.displacement);
        local.candidate = value;
        local.provenance = provenance_from_fact(instruction.provenance);
        local.kind = type_evidence_kind_t::memory_access;
        local.source_address = instruction.address;
        local.source_entity_id = instruction.id;
        local.confidence = 48;
        local.detail = operand_is_written(operand) ? "stack_store" : "stack_load";
        collector.append_evidence(std::move(local));
    }
    if (operand.base_reg != 0 && !is_direct_memory_expression(operand)) {
        type_recovery_evidence_t field;
        field.subject = make_field_subject(workspace, function, operand.base_reg, operand.displacement);
        field.candidate = value;
        field.provenance = provenance_from_fact(instruction.provenance);
        field.kind = type_evidence_kind_t::field_offset;
        field.source_address = instruction.address;
        field.source_entity_id = instruction.id;
        field.confidence = 52;
        field.detail = operand_is_written(operand) ? "field_store" : "field_load";
        collector.append_evidence(std::move(field));

        type_constraint_t membership;
        membership.kind = type_constraint_kind_t::field_access;
        membership.relation = type_constraint_relation_t::member_of;
        membership.source = make_local_subject(workspace, function, operand.base_reg);
        membership.target = make_field_subject(workspace, function, operand.base_reg,
                                               operand.displacement);
        membership.candidate = value;
        membership.reg = operand.base_reg;
        membership.stack_offset = operand.displacement;
        membership.bit_width = width;
        membership.instruction_rva = instruction.address.value;
        membership.source_instruction_id = instruction.id;
        membership.inferred_kind = value.kind;
        membership.provenance = provenance_from_fact(instruction.provenance);
        membership.confidence = 52;
        collector.append_constraint(std::move(membership));
    }
    if (is_direct_memory_expression(operand)) {
        type_recovery_evidence_t global;
        global.subject.kind = type_subject_kind_t::global;
        global.subject.address = make_address(workspace, address_space_id_t::relative_virtual,
                                              operand.resolved_expression_value);
        global.subject.stable_name = "memory";
        global.candidate = value;
        global.provenance = provenance_from_fact(instruction.provenance);
        global.kind = type_evidence_kind_t::memory_access;
        global.source_address = instruction.address;
        global.source_entity_id = instruction.id;
        global.confidence = 46;
        global.detail = operand_is_written(operand) ? "global_store" : "global_load";
        collector.append_evidence(std::move(global));
    }
}

void collect_function_evidence(const analysis_workspace_t& workspace,
                               const analysis_snapshot_t& snapshot,
                               const function_view_t& view,
                               std::uint16_t pointer_bits,
                               collector_t& collector,
                               std::vector<call_record_t>& calls) {
    if (!view.function)
        return;
    for (const auto* instruction : view.instructions) {
        if (collector.poller.poll()) {
            collector.stopped = true;
            return;
        }
        if (!collector.consume_work_unit())
            return;
        std::vector<type_subject_t> reads;
        std::vector<type_subject_t> writes;
        bool has_immediate = false;
        type_descriptor_t immediate = unknown_descriptor();
        const auto operand_end = std::min<std::uint64_t>(
            static_cast<std::uint64_t>(instruction->operand_fact_begin) + instruction->operand_fact_count,
            snapshot.operand_facts.size());
        for (std::uint64_t index = instruction->operand_fact_begin; index < operand_end; ++index) {
            const auto& operand = snapshot.operand_facts[static_cast<std::size_t>(index)];
            if (operand.kind == operand_kind_t::reg) {
                append_local_width_evidence(workspace, *view.function, *instruction, operand, collector);
                const auto subject = make_local_subject(workspace, *view.function, operand.reg);
                if (operand_is_read(operand))
                    reads.push_back(subject);
                if (operand_is_written(operand))
                    writes.push_back(subject);
            } else if (operand.kind == operand_kind_t::memory) {
                append_memory_evidence(workspace, *view.function, *instruction, operand,
                                       pointer_bits, collector);
            } else if (operand.kind == operand_kind_t::immediate && operand.bit_width != 0) {
                has_immediate = true;
                immediate = integer_descriptor(operand.bit_width, operand.signed_value);
                if (operand.immediate <= 1) {
                    immediate.kind = recovered_type_kind_t::boolean;
                    immediate.signedness = type_signedness_t::not_applicable;
                }
            }
            if (collector.stopped)
                return;
        }
        std::sort(reads.begin(), reads.end(), [](const auto& lhs, const auto& rhs) {
            return subject_material(lhs) < subject_material(rhs);
        });
        reads.erase(std::unique(reads.begin(), reads.end(), [](const auto& lhs, const auto& rhs) {
            return subject_material(lhs) == subject_material(rhs);
        }), reads.end());
        std::sort(writes.begin(), writes.end(), [](const auto& lhs, const auto& rhs) {
            return subject_material(lhs) < subject_material(rhs);
        });
        writes.erase(std::unique(writes.begin(), writes.end(), [](const auto& lhs, const auto& rhs) {
            return subject_material(lhs) == subject_material(rhs);
        }), writes.end());
        for (const auto& write : writes) {
            if (has_immediate) {
                type_recovery_evidence_t evidence;
                evidence.subject = write;
                evidence.candidate = immediate;
                evidence.provenance = provenance_from_fact(instruction->provenance);
                evidence.kind = type_evidence_kind_t::assignment;
                evidence.source_address = instruction->address;
                evidence.source_entity_id = instruction->id;
                evidence.confidence = 58;
                evidence.detail = "immediate_assignment";
                collector.append_evidence(std::move(evidence));
            }
            for (const auto& read : reads) {
                type_constraint_t assignment;
                assignment.kind = type_constraint_kind_t::assignment;
                assignment.relation = type_constraint_relation_t::assignment;
                assignment.source = read;
                assignment.target = write;
                assignment.instruction_rva = instruction->address.value;
                assignment.source_instruction_id = instruction->id;
                assignment.provenance = provenance_from_fact(instruction->provenance);
                assignment.confidence = 48;
                assignment.propagate = true;
                collector.append_constraint(std::move(assignment));
            }
            if (collector.stopped)
                return;
        }
        if ((instruction->flow_flags & flow_call) == 0)
            continue;
        std::vector<std::uint64_t> targets;
        const auto target_end = std::min<std::uint64_t>(
            static_cast<std::uint64_t>(instruction->target_fact_begin) + instruction->target_fact_count,
            snapshot.target_facts.size());
        for (std::uint64_t index = instruction->target_fact_begin; index < target_end; ++index) {
            const auto& target = snapshot.target_facts[static_cast<std::size_t>(index)];
            if (target.kind == target_kind_record_t::call)
                targets.push_back(target.target.value);
        }
        std::sort(targets.begin(), targets.end());
        targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
        if (targets.empty()) {
            type_recovery_evidence_t target;
            target.subject.kind = type_subject_kind_t::function_pointer;
            target.subject.address = instruction->address;
            target.subject.entity_id = instruction->id;
            target.subject.function_rva = view.function->start.value;
            target.subject.stable_name = "indirect_call";
            target.candidate.kind = recovered_type_kind_t::function_pointer;
            target.candidate.bit_width = pointer_bits;
            target.candidate.signedness = type_signedness_t::not_applicable;
            target.provenance = provenance_from_fact(instruction->provenance);
            target.kind = type_evidence_kind_t::function_target;
            target.source_address = instruction->address;
            target.source_entity_id = instruction->id;
            target.confidence = 62;
            target.detail = "indirect_call";
            collector.append_evidence(std::move(target));
            calls.push_back({instruction->address.value, 0, true});
            continue;
        }
        for (const auto target_rva : targets) {
            type_recovery_evidence_t target;
            target.subject.kind = type_subject_kind_t::function;
            target.subject.address = make_address(workspace, address_space_id_t::relative_virtual, target_rva);
            target.subject.function_rva = target_rva;
            target.subject.stable_name = "call_target";
            target.candidate.kind = recovered_type_kind_t::function_type;
            target.candidate.signedness = type_signedness_t::not_applicable;
            target.provenance = provenance_from_fact(instruction->provenance);
            target.kind = type_evidence_kind_t::function_target;
            target.source_address = instruction->address;
            target.source_entity_id = instruction->id;
            target.confidence = 64;
            target.detail = "direct_call";
            collector.append_evidence(std::move(target));
            calls.push_back({instruction->address.value, target_rva, false});
            for (std::size_t ordinal = 0; ordinal < reads.size(); ++ordinal) {
                type_constraint_t argument;
                argument.kind = type_constraint_kind_t::call_argument;
                argument.relation = type_constraint_relation_t::call_argument_to;
                argument.source = reads[ordinal];
                argument.target = make_parameter_subject(workspace, target_rva,
                                                         static_cast<std::uint32_t>(ordinal));
                argument.instruction_rva = instruction->address.value;
                argument.source_instruction_id = instruction->id;
                argument.target_entity_id = target_rva;
                argument.provenance = type_evidence_provenance_t::interprocedural;
                argument.confidence = 58;
                argument.propagate = true;
                collector.append_constraint(std::move(argument));
            }
            for (const auto& write : writes) {
                type_constraint_t returned;
                returned.kind = type_constraint_kind_t::call_return;
                returned.relation = type_constraint_relation_t::call_return_from;
                returned.source = make_return_subject(workspace, target_rva);
                returned.target = write;
                returned.instruction_rva = instruction->address.value;
                returned.source_instruction_id = instruction->id;
                returned.target_entity_id = target_rva;
                returned.provenance = type_evidence_provenance_t::interprocedural;
                returned.confidence = 58;
                returned.propagate = true;
                collector.append_constraint(std::move(returned));
            }
            if (collector.stopped)
                return;
        }
    }
}

void build_aggregates(type_recovery_result_t& result, const type_recovery_limits_t& limits,
                      recovery_poller_t& poller) {
    std::map<std::pair<std::uint64_t, std::uint64_t>, std::vector<const recovered_type_t*>> groups;
    for (const auto& type : result.types) {
        if (poller.poll())
            return;
        if (type.state != type_resolution_state_t::resolved ||
            type.subject.kind != type_subject_kind_t::field || type.subject.stack_offset < 0)
            continue;
        groups[{type.subject.function_rva, type.subject.container_id}].push_back(&type);
    }
    for (const auto& [identity, fields] : groups) {
        if (poller.poll())
            return;
        if (fields.size() < 2)
            continue;
        if (result.structs.size() >= limits.max_aggregates) {
            result.bounded = true;
            return;
        }
        recovered_struct_t aggregate;
        aggregate.rva = identity.first;
        aggregate.kind = recovered_type_kind_t::struct_type;
        aggregate.name = "struct_" + std::to_string(identity.first) + "_" +
                         std::to_string(identity.second);
        aggregate.type_id = stable_hash(aggregate.name);
        std::uint64_t confidence_sum = 0;
        for (const auto* field_type : fields) {
            if (aggregate.fields.size() >= limits.max_fields_per_aggregate) {
                result.bounded = true;
                break;
            }
            struct_field_t field;
            field.offset = static_cast<std::uint64_t>(field_type->subject.stack_offset);
            field.kind = field_type->kind;
            field.bit_width = field_type->bit_width;
            field.name = "field_" + std::to_string(field.offset);
            field.is_pointer = field.kind == recovered_type_kind_t::pointer ||
                               field.kind == recovered_type_kind_t::function_pointer;
            field.state = field_type->state;
            field.confidence = field_type->confidence;
            field.evidence_ids = field_type->supporting_evidence_ids;
            const auto byte_width = static_cast<std::uint64_t>((field.bit_width + 7U) / 8U);
            if (field.offset <= (std::numeric_limits<std::uint64_t>::max)() - byte_width)
                aggregate.estimated_size = std::max(aggregate.estimated_size, field.offset + byte_width);
            confidence_sum += field.confidence;
            aggregate.fields.push_back(std::move(field));
        }
        std::sort(aggregate.fields.begin(), aggregate.fields.end(), [](const auto& lhs, const auto& rhs) {
            return std::tie(lhs.offset, lhs.name) < std::tie(rhs.offset, rhs.name);
        });
        aggregate.confidence = aggregate.fields.empty() ? 0 : static_cast<std::uint8_t>(
            confidence_sum / aggregate.fields.size());
        result.structs.push_back(std::move(aggregate));
    }
    std::sort(result.structs.begin(), result.structs.end(), [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.rva, lhs.name, lhs.type_id) < std::tie(rhs.rva, rhs.name, rhs.type_id);
    });
    result.structs_recovered = result.structs.size();
}

void build_runtime_metadata(type_recovery_result_t& result, const type_recovery_limits_t& limits,
                            recovery_poller_t& poller) {
    std::map<std::string, std::vector<std::uint64_t>> inheritance;
    for (const auto& evidence : result.evidence) {
        if (poller.poll())
            return;
        if (evidence.kind == type_evidence_kind_t::inheritance && evidence.related_subject) {
            inheritance[subject_material(evidence.subject)].push_back(
                evidence.related_subject->address.value);
        }
    }
    std::set<std::string> seen_classes;
    for (const auto& evidence : result.evidence) {
        if (poller.poll())
            return;
        const bool class_evidence = evidence.subject.kind == type_subject_kind_t::rtti_type ||
            evidence.subject.kind == type_subject_kind_t::objc_class ||
            evidence.subject.kind == type_subject_kind_t::swift_type ||
            evidence.subject.kind == type_subject_kind_t::managed_type;
        if (!class_evidence || evidence.candidate.kind == recovered_type_kind_t::unknown)
            continue;
        const auto key = subject_material(evidence.subject);
        if (!seen_classes.insert(key).second)
            continue;
        if (result.rtti_classes.size() >= limits.max_aggregates) {
            result.bounded = true;
            break;
        }
        rtti_class_info_t info;
        info.type_descriptor_rva = evidence.subject.address.value;
        info.class_descriptor_rva = evidence.source_address.value;
        info.class_name = evidence.candidate.declared_name.empty()
            ? evidence.subject.stable_name : evidence.candidate.declared_name;
        info.language = evidence.candidate.language;
        info.confidence = evidence.confidence;
        info.base_class_rvas = inheritance[key];
        std::sort(info.base_class_rvas.begin(), info.base_class_rvas.end());
        info.base_class_rvas.erase(std::unique(info.base_class_rvas.begin(), info.base_class_rvas.end()),
                                   info.base_class_rvas.end());
        result.rtti_classes.push_back(std::move(info));
    }
    std::map<std::uint64_t, recovered_vtable_t> tables;
    for (const auto& evidence : result.evidence) {
        if (poller.poll())
            return;
        if (evidence.subject.kind != type_subject_kind_t::virtual_table &&
            evidence.kind != type_evidence_kind_t::vtable_descriptor)
            continue;
        const auto rva = evidence.subject.address.value;
        auto& table = tables[rva];
        table.vtable_rva = rva;
        table.name = evidence.candidate.declared_name.empty()
            ? evidence.subject.stable_name : evidence.candidate.declared_name;
        table.language = evidence.candidate.language == type_language_t::unknown
            ? type_language_t::cpp : evidence.candidate.language;
        table.confidence = std::max(table.confidence, evidence.confidence);
    }
    for (const auto& evidence : result.evidence) {
        if (poller.poll())
            return;
        if (evidence.subject.kind != type_subject_kind_t::virtual_slot ||
            !evidence.related_subject ||
            evidence.related_subject->kind != type_subject_kind_t::virtual_table)
            continue;
        const auto table_it = tables.find(evidence.related_subject->address.value);
        if (table_it == tables.end())
            continue;
        vtable_entry_t entry;
        entry.entry_rva = evidence.subject.address.value;
        entry.function_rva = evidence.candidate.referenced_type_id;
        entry.slot_index = evidence.subject.ordinal;
        entry.state = evidence.candidate.kind == recovered_type_kind_t::function_pointer
            ? type_resolution_state_t::resolved : type_resolution_state_t::abstained;
        entry.confidence = evidence.confidence;
        table_it->second.entries.push_back(entry);
    }
    for (auto& [_, table] : tables) {
        if (result.vtables.size() >= limits.max_vtables) {
            result.bounded = true;
            break;
        }
        std::sort(table.entries.begin(), table.entries.end(), [](const auto& lhs, const auto& rhs) {
            return std::tie(lhs.slot_index, lhs.entry_rva, lhs.function_rva) <
                   std::tie(rhs.slot_index, rhs.entry_rva, rhs.function_rva);
        });
        table.entries.erase(std::unique(table.entries.begin(), table.entries.end(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.slot_index == rhs.slot_index && lhs.entry_rva == rhs.entry_rva &&
                       lhs.function_rva == rhs.function_rva;
            }), table.entries.end());
        table.entry_count = table.entries.size();
        result.vtables.push_back(std::move(table));
    }
    std::sort(result.rtti_classes.begin(), result.rtti_classes.end(), [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.type_descriptor_rva, lhs.class_name) <
               std::tie(rhs.type_descriptor_rva, rhs.class_name);
    });
    std::sort(result.vtables.begin(), result.vtables.end(), [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.vtable_rva, lhs.name) < std::tie(rhs.vtable_rva, rhs.name);
    });
    result.vtables_recovered = result.vtables.size();
}

void build_prototypes(type_recovery_result_t& result, const type_recovery_limits_t& limits,
                      const std::vector<call_record_t>& calls,
                      const cc_analysis_result_t* calling_convention,
                      recovery_poller_t& poller) {
    std::map<std::string, const recovered_type_t*> resolved;
    std::map<std::uint64_t, bool> noreturn_functions;
    for (const auto& type : result.types) {
        if (type.state == type_resolution_state_t::resolved) {
            resolved.emplace(subject_material(type.subject), &type);
            if (type.subject.kind == type_subject_kind_t::function && type.descriptor.noreturn)
                noreturn_functions[type.subject.function_rva] = true;
        }
    }
    if (calling_convention) {
        if (poller.poll())
            return;
        if (result.prototypes.size() >= limits.max_prototypes) {
            result.bounded = true;
            return;
        }
        prototype_info_t prototype;
        prototype.target_function_rva = calling_convention->function_rva;
        prototype.calling_convention = calling_convention->abi;
        prototype.calling_convention_state = calling_convention->state;
        prototype.arguments_state = calling_convention->arguments_state;
        prototype.return_value_state = calling_convention->return_value.state;
        prototype.variadic_state = calling_convention->variadic_state;
        const bool usable = calling_convention->state == cc_inference_state_t::inferred &&
                            !calling_convention->bounded;
        prototype.is_variadic = calling_convention->variadic_state == cc_value_state_t::inferred &&
                                calling_convention->is_variadic;
        prototype.is_noreturn = usable && calling_convention->is_noreturn;
        std::uint64_t confidence_sum = usable ? calling_convention->confidence : 0;
        std::size_t confidence_count = usable && calling_convention->confidence != 0 ? 1 : 0;
        if (usable && calling_convention->arguments_state == cc_value_state_t::inferred) {
            std::vector<const argument_info_t*> arguments;
            arguments.reserve(calling_convention->arguments.size());
            for (const auto& argument : calling_convention->arguments)
                if (argument.used)
                    arguments.push_back(&argument);
            std::sort(arguments.begin(), arguments.end(), [](const auto* lhs, const auto* rhs) {
                return std::tie(lhs->index, lhs->abi_slot, lhs->location, lhs->reg,
                                lhs->stack_offset, lhs->bit_width, lhs->is_float,
                                lhs->is_vector, lhs->conflicted, lhs->confidence) <
                       std::tie(rhs->index, rhs->abi_slot, rhs->location, rhs->reg,
                                rhs->stack_offset, rhs->bit_width, rhs->is_float,
                                rhs->is_vector, rhs->conflicted, rhs->confidence);
            });
            std::set<std::uint32_t> seen_ordinals;
            for (const auto* argument : arguments) {
                if (argument->index >= calling_convention_max_arguments) {
                    result.bounded = true;
                    continue;
                }
                if (!seen_ordinals.insert(argument->index).second) {
                    prototype.arguments_state = cc_value_state_t::conflicted;
                    continue;
                }
                if (prototype.argument_types.size() <= argument->index) {
                    prototype.argument_types.resize(argument->index + 1,
                                                    recovered_type_kind_t::unknown);
                    prototype.argument_bit_widths.resize(argument->index + 1, 0);
                }
                prototype.argument_bit_widths[argument->index] = argument->bit_width;
                if (argument->conflicted) {
                    prototype.arguments_state = cc_value_state_t::conflicted;
                    continue;
                }
                type_subject_t parameter;
                parameter.kind = type_subject_kind_t::parameter;
                parameter.address = calling_convention->cache_key.function;
                parameter.function_rva = calling_convention->function_rva;
                parameter.ordinal = argument->index;
                parameter.stable_name = "parameter";
                const auto found = resolved.find(subject_material(parameter));
                if (found == resolved.end())
                    continue;
                prototype.argument_types[argument->index] = found->second->kind;
                if (prototype.argument_bit_widths[argument->index] == 0)
                    prototype.argument_bit_widths[argument->index] = found->second->bit_width;
                confidence_sum += found->second->confidence;
                ++confidence_count;
            }
        }
        if (calling_convention->return_value.state == cc_value_state_t::inferred && usable) {
            type_subject_t returned;
            returned.kind = type_subject_kind_t::return_value;
            returned.address = calling_convention->cache_key.function;
            returned.function_rva = calling_convention->function_rva;
            returned.stable_name = "return";
            prototype.return_bit_width = calling_convention->return_value.bit_width;
            prototype.return_state = type_resolution_state_t::abstained;
            const auto found = resolved.find(subject_material(returned));
            if (found != resolved.end()) {
                prototype.return_type = found->second->kind;
                prototype.return_state = found->second->state;
                if (prototype.return_bit_width == 0)
                    prototype.return_bit_width = found->second->bit_width;
                confidence_sum += found->second->confidence;
                ++confidence_count;
            }
        } else if (calling_convention->return_value.state == cc_value_state_t::conflicted) {
            prototype.return_state = type_resolution_state_t::conflicted;
        } else if (calling_convention->return_value.state == cc_value_state_t::abstained ||
                   calling_convention->bounded) {
            prototype.return_state = type_resolution_state_t::abstained;
        }
        prototype.confidence = confidence_count == 0 ? 0 : static_cast<std::uint8_t>(
            confidence_sum / confidence_count);
        result.prototypes.push_back(std::move(prototype));
    }
    std::vector<call_record_t> ordered_calls = calls;
    std::sort(ordered_calls.begin(), ordered_calls.end(), [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.call_site_rva, lhs.target_function_rva, lhs.indirect) <
               std::tie(rhs.call_site_rva, rhs.target_function_rva, rhs.indirect);
    });
    ordered_calls.erase(std::unique(ordered_calls.begin(), ordered_calls.end(),
        [](const auto& lhs, const auto& rhs) {
            return lhs.call_site_rva == rhs.call_site_rva &&
                   lhs.target_function_rva == rhs.target_function_rva && lhs.indirect == rhs.indirect;
        }), ordered_calls.end());
    for (const auto& call : ordered_calls) {
        if (poller.poll())
            return;
        if (result.prototypes.size() >= limits.max_prototypes) {
            result.bounded = true;
            return;
        }
        prototype_info_t prototype;
        prototype.call_site_rva = call.call_site_rva;
        prototype.target_function_rva = call.target_function_rva;
        prototype.indirect = call.indirect;
        prototype.is_noreturn = noreturn_functions[call.target_function_rva];
        std::uint8_t confidence_sum = 0;
        std::size_t confidence_count = 0;
        for (const auto& constraint : result.constraints) {
            if (constraint.kind != type_constraint_kind_t::call_argument ||
                constraint.instruction_rva != call.call_site_rva || !constraint.target ||
                constraint.target->function_rva != call.target_function_rva)
                continue;
            const auto ordinal = constraint.target->ordinal;
            if (prototype.argument_types.size() <= ordinal) {
                prototype.argument_types.resize(ordinal + 1, recovered_type_kind_t::unknown);
                prototype.argument_bit_widths.resize(ordinal + 1, 0);
            }
            const auto found = resolved.find(subject_material(*constraint.target));
            if (found == resolved.end())
                continue;
            prototype.argument_types[ordinal] = found->second->kind;
            prototype.argument_bit_widths[ordinal] = found->second->bit_width;
            confidence_sum = static_cast<std::uint8_t>(std::min<std::uint16_t>(
                static_cast<std::uint16_t>(confidence_sum) + found->second->confidence, 255));
            ++confidence_count;
        }
        if (call.target_function_rva != 0) {
            type_subject_t returned;
            returned.kind = type_subject_kind_t::return_value;
            returned.function_rva = call.target_function_rva;
            returned.address.value = call.target_function_rva;
            returned.address.space = address_space_id_t::relative_virtual;
            returned.stable_name = "return";
            const auto found = resolved.find(subject_material(returned));
            if (found != resolved.end()) {
                prototype.return_type = found->second->kind;
                prototype.return_bit_width = found->second->bit_width;
                prototype.return_state = found->second->state;
                confidence_sum = static_cast<std::uint8_t>(std::min<std::uint16_t>(
                    static_cast<std::uint16_t>(confidence_sum) + found->second->confidence, 255));
                ++confidence_count;
            }
        }
        prototype.confidence = confidence_count == 0 ? 0 : static_cast<std::uint8_t>(
            confidence_sum / confidence_count);
        result.prototypes.push_back(std::move(prototype));
    }
    std::sort(result.prototypes.begin(), result.prototypes.end(), [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.call_site_rva, lhs.target_function_rva, lhs.indirect) <
               std::tie(rhs.call_site_rva, rhs.target_function_rva, rhs.indirect);
    });
}

}

bool operator==(const type_recovery_cache_key_t& lhs,
                const type_recovery_cache_key_t& rhs) noexcept {
    return lhs.binary_id == rhs.binary_id && lhs.root_address == rhs.root_address &&
           lhs.format == rhs.format && lhs.architecture == rhs.architecture &&
           lhs.architecture_mode == rhs.architecture_mode && lhs.abi == rhs.abi &&
           lhs.target_kind == rhs.target_kind && lhs.generation == rhs.generation &&
           lhs.analysis_revision == rhs.analysis_revision &&
           lhs.overlay_revision == rhs.overlay_revision &&
           lhs.calling_convention_key == rhs.calling_convention_key &&
           lhs.calling_convention_fingerprint == rhs.calling_convention_fingerprint &&
           lhs.options_fingerprint == rhs.options_fingerprint;
}

bool operator!=(const type_recovery_cache_key_t& lhs,
                const type_recovery_cache_key_t& rhs) noexcept {
    return !(lhs == rhs);
}

std::string stable_type_recovery_cache_key_material(const type_recovery_cache_key_t& key) {
    std::string material;
    material.reserve(512);
    append_key_component(material, "binary", key.binary_id.to_hex());
    append_key_component(material, "space", static_cast<std::uint64_t>(key.root_address.space));
    append_key_component(material, "address", key.root_address.value);
    append_key_component(material, "root_arch", static_cast<std::uint64_t>(key.root_address.architecture));
    append_key_component(material, "root_mode", static_cast<std::uint64_t>(key.root_address.mode));
    append_key_component(material, "format", static_cast<std::uint64_t>(key.format));
    append_key_component(material, "arch", static_cast<std::uint64_t>(key.architecture));
    append_key_component(material, "mode", static_cast<std::uint64_t>(key.architecture_mode));
    append_key_component(material, "abi", static_cast<std::uint64_t>(key.abi));
    append_key_component(material, "target", static_cast<std::uint64_t>(key.target_kind));
    append_key_component(material, "generation", key.generation);
    append_key_component(material, "analysis", key.analysis_revision);
    append_key_component(material, "overlay", key.overlay_revision);
    append_calling_convention_key_material(material, key.calling_convention_key);
    append_key_component(material, "calling_convention_fingerprint",
                         key.calling_convention_fingerprint);
    append_key_component(material, "options", key.options_fingerprint);
    return material;
}

type_recovery_cache_key_t make_type_recovery_cache_key(
    const analysis_workspace_t& workspace, const type_recovery_request_t& request) {
    const auto limits = normalized_limits(request.limits);
    type_recovery_cache_key_t key;
    key.binary_id = workspace.identity().binary_id();
    key.root_address = make_address(workspace, request.address_space, request.function_rva);
    key.format = workspace.identity().format();
    key.architecture = workspace.identity().architecture();
    key.architecture_mode = workspace.identity().architecture_mode();
    key.abi = workspace.identity().abi();
    key.target_kind = workspace.identity().target_kind();
    key.generation = workspace.generation();
    key.analysis_revision = workspace.analysis_revision();
    key.overlay_revision = workspace.overlay_revision();
    key.calling_convention_key = expected_calling_convention_cache_key(workspace, request);
    if (request.consume_calling_convention_facts && request.calling_convention_result) {
        key.calling_convention_fingerprint = calling_convention_result_fingerprint(
            *request.calling_convention_result);
    }
    key.options_fingerprint = options_fingerprint(request, limits);
    return key;
}

workspace_result_t<type_recovery_result_t>
    recover_types(const analysis_workspace_t& workspace,
                  const type_recovery_request_t& request,
                  const cancellation_token_t& cancel) {
    type_recovery_result_t result;
    result.function_rva = request.function_rva;
    result.cache_key = make_type_recovery_cache_key(workspace, request);
    const auto limits = normalized_limits(request.limits);
    recovery_poller_t poller(cancel, result);
    collector_t collector{result, limits, poller};
    std::vector<call_record_t> calls;
    const auto* calling_convention = request.consume_calling_convention_facts
        ? request.calling_convention_result : nullptr;
    if (poller.poll_now())
        return workspace_result_t<type_recovery_result_t>::success(std::move(result));
    if (request.consume_semantic_facts && request.semantic_result &&
        !semantic_scope_matches(result.cache_key, *request.semantic_result)) {
        return workspace_result_t<type_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "semantic fusion result does not match the type recovery scope", "type_recovery"));
    }
    if (request.consume_cfg_facts && request.cfg_result &&
        !cfg_scope_matches(result.cache_key, *request.cfg_result)) {
        return workspace_result_t<type_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "advanced CFG result does not match the type recovery scope", "type_recovery"));
    }
    if (calling_convention &&
        !calling_convention_scope_matches(result.cache_key, *calling_convention)) {
        return workspace_result_t<type_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "calling convention result does not match the type recovery scope", "type_recovery"));
    }

    auto injected = request.injected_evidence;
    std::sort(injected.begin(), injected.end(), evidence_less);
    for (auto& evidence : injected) {
        collector.append_evidence(std::move(evidence));
        if (collector.stopped)
            return workspace_result_t<type_recovery_result_t>::success(std::move(result));
        if (collector.work_limited)
            break;
    }
    if (!collector.work_limited && calling_convention)
        collect_calling_convention_facts(workspace, *calling_convention, collector);
    if (collector.stopped)
        return workspace_result_t<type_recovery_result_t>::success(std::move(result));
    if (!collector.work_limited && request.consume_semantic_facts && request.semantic_result)
        collect_semantic_facts(workspace, *request.semantic_result, collector);
    if (collector.stopped)
        return workspace_result_t<type_recovery_result_t>::success(std::move(result));
    if (!collector.work_limited && request.consume_cfg_facts && request.cfg_result)
        collect_cfg_facts(workspace, *request.cfg_result, collector, calls);
    if (collector.stopped)
        return workspace_result_t<type_recovery_result_t>::success(std::move(result));
    if (!collector.work_limited && request.include_image_metadata)
        collect_image_metadata(workspace, collector);
    if (collector.stopped)
        return workspace_result_t<type_recovery_result_t>::success(std::move(result));
    if (collector.work_limited) {
        canonicalize_evidence(result);
        if (resolve_evidence(result, limits, poller)) {
            build_aggregates(result, limits, poller);
            build_runtime_metadata(result, limits, poller);
            build_prototypes(result, limits, calls, calling_convention, poller);
        }
        if (!result.cancelled && !result.deadline_exceeded)
            result.status = type_recovery_status_t::result_limited;
        return workspace_result_t<type_recovery_result_t>::success(std::move(result));
    }

    const auto snapshot = workspace.snapshot();
    if (!snapshot) {
        canonicalize_evidence(result);
        if (!result.evidence.empty() && resolve_evidence(result, limits, poller)) {
            build_prototypes(result, limits, calls, calling_convention, poller);
            result.status = result.bounded ? type_recovery_status_t::result_limited
                                            : type_recovery_status_t::complete;
        }
        return workspace_result_t<type_recovery_result_t>::success(std::move(result));
    }
    std::vector<const function_record_t*> functions;
    functions.reserve(snapshot->functions.size());
    for (const auto& function : snapshot->functions)
        functions.push_back(&function);
    std::sort(functions.begin(), functions.end(), [](const auto* lhs, const auto* rhs) {
        return std::tie(lhs->start.value, lhs->id) < std::tie(rhs->start.value, rhs->id);
    });
    const auto root = find_function(functions, request.function_rva);
    if (!root) {
        canonicalize_evidence(result);
        if (!result.evidence.empty() && resolve_evidence(result, limits, poller)) {
            build_prototypes(result, limits, calls, calling_convention, poller);
            result.status = result.bounded ? type_recovery_status_t::result_limited
                                            : type_recovery_status_t::partial;
        }
        return workspace_result_t<type_recovery_result_t>::success(std::move(result));
    }

    struct pending_function_t {
        const function_record_t* function = nullptr;
        std::uint32_t depth = 0;
    };
    std::vector<pending_function_t> pending{{root, 0}};
    std::set<std::uint64_t> visited;
    const auto pointer_bits = pointer_width(workspace);
    for (std::size_t index = 0; index < pending.size(); ++index) {
        if (poller.poll())
            return workspace_result_t<type_recovery_result_t>::success(std::move(result));
        const auto item = pending[index];
        if (!item.function || !visited.insert(item.function->start.value).second)
            continue;
        if (result.interprocedural_functions >= limits.max_interprocedural_functions) {
            result.bounded = true;
            break;
        }
        const auto view = extract_function_view(*snapshot, *item.function);
        collect_function_evidence(workspace, *snapshot, view, pointer_bits, collector, calls);
        ++result.interprocedural_functions;
        if (collector.stopped)
            return workspace_result_t<type_recovery_result_t>::success(std::move(result));
        if (collector.work_limited)
            break;
        if (!request.include_interprocedural || item.depth >= limits.max_interprocedural_depth)
            continue;
        for (const auto target : view.call_targets) {
            if (const auto* function = find_function(functions, target))
                pending.push_back({function, item.depth + 1});
        }
    }
    canonicalize_evidence(result);
    if (!resolve_evidence(result, limits, poller))
        return workspace_result_t<type_recovery_result_t>::success(std::move(result));
    for (std::uint32_t iteration = 0; iteration < limits.max_propagation_iterations; ++iteration) {
        if (poller.poll())
            return workspace_result_t<type_recovery_result_t>::success(std::move(result));
        const auto changed = propagate_constraints(result, limits, collector, poller);
        if (collector.stopped || result.cancelled || result.deadline_exceeded)
            return workspace_result_t<type_recovery_result_t>::success(std::move(result));
        if (!changed)
            break;
        ++result.propagation_iterations;
        canonicalize_evidence(result);
        if (!resolve_evidence(result, limits, poller))
            return workspace_result_t<type_recovery_result_t>::success(std::move(result));
    }
    result.iterations = result.propagation_iterations;
    build_aggregates(result, limits, poller);
    if (result.cancelled || result.deadline_exceeded)
        return workspace_result_t<type_recovery_result_t>::success(std::move(result));
    build_runtime_metadata(result, limits, poller);
    if (result.cancelled || result.deadline_exceeded)
        return workspace_result_t<type_recovery_result_t>::success(std::move(result));
    build_prototypes(result, limits, calls, calling_convention, poller);
    if (result.cancelled || result.deadline_exceeded)
        return workspace_result_t<type_recovery_result_t>::success(std::move(result));
    result.status = result.evidence.empty() ? type_recovery_status_t::no_evidence
        : result.bounded ? type_recovery_status_t::result_limited
        : type_recovery_status_t::complete;
    return workspace_result_t<type_recovery_result_t>::success(std::move(result));
}

workspace_result_t<type_recovery_result_t>
    recover_types(const analysis_workspace_t& workspace,
                  std::uint64_t function_rva,
                  const cancellation_token_t& cancel) {
    type_recovery_request_t request;
    request.function_rva = function_rva;
    return recover_types(workspace, request, cancel);
}

}
