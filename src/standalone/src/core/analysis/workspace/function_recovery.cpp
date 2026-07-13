#include "function_recovery.hpp"

#include "checked_range.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::uint64_t kBlockEntityTag = 2ULL << 56;
constexpr std::uint64_t kFunctionEntityTag = 3ULL << 56;
constexpr std::uint64_t kEdgeEntityTag = 4ULL << 56;
constexpr std::uint64_t kFunctionChunkEntityTag = 11ULL << 56;
constexpr std::uint32_t kControlFlowMask =
    flow_branch | flow_call | flow_return | flow_interrupt | flow_terminal;

workspace_error_t stop_error(const cancellation_token_t& cancel, const char* phase)
{
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "baseline analysis deadline exceeded", phase);
        error.deadline = true;
        error.cancellation = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "baseline analysis cancelled", phase);
    error.cancellation = true;
    return error;
}

bool valid_limits(const function_recovery_limits_t& limits) noexcept
{
    return limits.max_blocks != 0 && limits.max_functions != 0 &&
        limits.max_function_memberships != 0 && limits.max_edges != 0 &&
        limits.max_switches != 0 && limits.max_seed_candidates != 0 &&
        limits.max_conflicts != 0 && limits.max_result_bytes != 0 &&
        limits.max_switch_cases != 0 && limits.max_blocks_per_function != 0 &&
        limits.cancellation_check_interval != 0;
}

address_t rva_address(const workspace_image_t& image, std::uint64_t rva) noexcept
{
    return {address_space_id_t::relative_virtual, rva, image.architecture,
        image.architecture_mode};
}

std::optional<std::uint64_t> to_rva(const workspace_image_t& image,
                                    const address_t& address) noexcept
{
    if (address.architecture != image.architecture ||
        address.mode != image.architecture_mode)
        return std::nullopt;
    if (address.space == address_space_id_t::relative_virtual)
        return address.value < image.image_size ? std::optional<std::uint64_t>(address.value)
                                                : std::nullopt;
    if ((address.space == address_space_id_t::virtual_address ||
         address.space == address_space_id_t::live_virtual) &&
        address.value >= image.image_base) {
        const auto rva = address.value - image.image_base;
        return rva < image.image_size ? std::optional<std::uint64_t>(rva) : std::nullopt;
    }
    return std::nullopt;
}

bool executable_rva(const workspace_image_t& image, std::uint64_t rva) noexcept
{
    const auto contains = [rva](const auto& region) noexcept {
        const auto extent = std::max(region.virtual_size, region.file_size);
        return extent != 0 && rva >= region.virtual_address &&
            workspace_image_span_within(rva - region.virtual_address, 1, extent);
    };
    for (const auto& section : image.sections) {
        if ((section.permissions & image_permission_execute) != 0 && contains(section))
            return true;
    }
    for (const auto& segment : image.segments) {
        if ((segment.permissions & image_permission_execute) != 0 && contains(segment))
            return true;
    }
    return false;
}

std::optional<std::uint64_t> to_rva_endpoint(const workspace_image_t& image,
                                             const address_t& address) noexcept
{
    if (address.architecture != image.architecture ||
        address.mode != image.architecture_mode)
        return std::nullopt;
    if (address.space == address_space_id_t::relative_virtual)
        return address.value <= image.image_size
            ? std::optional<std::uint64_t>(address.value) : std::nullopt;
    if ((address.space == address_space_id_t::virtual_address ||
         address.space == address_space_id_t::live_virtual) &&
        address.value >= image.image_base) {
        const auto rva = address.value - image.image_base;
        return rva <= image.image_size ? std::optional<std::uint64_t>(rva)
                                       : std::nullopt;
    }
    return std::nullopt;
}

std::uint64_t stable_mix(std::uint64_t lhs, std::uint64_t rhs) noexcept
{
    auto value = lhs ^ (rhs + 0x9e3779b97f4a7c15ULL + (lhs << 6) + (lhs >> 2));
    value ^= value >> 30;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31;
    return value == 0 ? 1 : value;
}

std::uint64_t stable_seed_source(function_seed_kind_t kind, std::uint64_t rva,
                                 std::uint64_t discriminator) noexcept
{
    return stable_mix(static_cast<std::uint64_t>(kind) + 1,
                      stable_mix(rva, discriminator));
}

std::uint64_t stable_text(std::string_view value) noexcept
{
    std::uint64_t result = 0xcbf29ce484222325ULL;
    for (const auto character : value) {
        result ^= static_cast<unsigned char>(character);
        result *= 0x100000001b3ULL;
    }
    return result == 0 ? 1 : result;
}

bool contains_ascii(std::string_view value, std::string_view needle) noexcept
{
    if (needle.empty() || needle.size() > value.size())
        return false;
    for (std::size_t offset = 0; offset <= value.size() - needle.size(); ++offset) {
        bool equal = true;
        for (std::size_t index = 0; index < needle.size(); ++index) {
            auto character = static_cast<unsigned char>(value[offset + index]);
            if (character >= 'A' && character <= 'Z')
                character = static_cast<unsigned char>(character - 'A' + 'a');
            if (character != static_cast<unsigned char>(needle[index])) {
                equal = false;
                break;
            }
        }
        if (equal)
            return true;
    }
    return false;
}

function_seed_kind_t entry_seed_kind(std::string_view provenance) noexcept
{
    if (contains_ascii(provenance, "tls"))
        return function_seed_kind_t::tls_callback;
    if (contains_ascii(provenance, "unwind"))
        return function_seed_kind_t::unwind_range;
    if (contains_ascii(provenance, "export"))
        return function_seed_kind_t::export_entry;
    if (contains_ascii(provenance, "cfg") ||
        contains_ascii(provenance, "safe_seh") ||
        contains_ascii(provenance, "load_config"))
        return function_seed_kind_t::load_config_entry;
    return function_seed_kind_t::image_entry;
}

std::uint8_t seed_confidence(function_seed_kind_t kind) noexcept
{
    switch (kind) {
        case function_seed_kind_t::image_entry:
        case function_seed_kind_t::tls_callback:
        case function_seed_kind_t::export_entry:
            return 100;
        case function_seed_kind_t::unwind_range:
            return 98;
        case function_seed_kind_t::debug_symbol:
            return 95;
        case function_seed_kind_t::load_config_entry:
            return 94;
        case function_seed_kind_t::direct_call_target:
            return 90;
        case function_seed_kind_t::relocation_target:
        case function_seed_kind_t::pointer_target:
            return 75;
        case function_seed_kind_t::validated_gap_target:
            return 65;
    }
    return 0;
}

std::uint64_t instruction_end(const instruction_record_t& instruction) noexcept
{
    std::uint64_t end = 0;
    return checked_add_u64(instruction.address.value, instruction.length, end)
        ? end : (std::numeric_limits<std::uint64_t>::max)();
}

fact_provenance_t default_seed_provenance(function_seed_kind_t kind) noexcept
{
    switch (kind) {
        case function_seed_kind_t::image_entry:
        case function_seed_kind_t::load_config_entry:
            return fact_provenance_t::image_entry;
        case function_seed_kind_t::tls_callback:
            return fact_provenance_t::tls_entry;
        case function_seed_kind_t::export_entry:
            return fact_provenance_t::export_entry;
        case function_seed_kind_t::unwind_range:
            return fact_provenance_t::unwind_metadata;
        case function_seed_kind_t::debug_symbol:
            return fact_provenance_t::debug_symbol;
        case function_seed_kind_t::relocation_target:
        case function_seed_kind_t::pointer_target:
            return fact_provenance_t::relocation;
        case function_seed_kind_t::direct_call_target:
            return fact_provenance_t::call_target;
        case function_seed_kind_t::validated_gap_target:
            return fact_provenance_t::gap_recovery;
    }
    return fact_provenance_t::unknown;
}

function_seed_t normalize_seed(function_seed_t seed, function_seed_kind_t kind)
{
    seed.kind = kind;
    if (seed.provenance == fact_provenance_t::unknown)
        seed.provenance = default_seed_provenance(kind);
    return seed;
}

bool stronger_seed(const function_seed_t& lhs, const function_seed_t& rhs) noexcept
{
    const auto lhs_rank = provenance_rank(lhs.provenance);
    const auto rhs_rank = provenance_rank(rhs.provenance);
    if (lhs_rank != rhs_rank)
        return lhs_rank > rhs_rank;
    if (lhs.confidence != rhs.confidence)
        return lhs.confidence > rhs.confidence;
    if (lhs.stable_source_id != rhs.stable_source_id)
        return lhs.stable_source_id < rhs.stable_source_id;
    return lhs.kind < rhs.kind;
}

std::uint64_t seed_end_value(const function_seed_t& seed) noexcept
{
    return seed.known_end ? seed.known_end->value : (std::numeric_limits<std::uint64_t>::max)();
}

bool seed_canonical_less(const function_seed_t& lhs, const function_seed_t& rhs) noexcept
{
    if (lhs.address != rhs.address)
        return lhs.address < rhs.address;
    if (stronger_seed(lhs, rhs))
        return true;
    if (stronger_seed(rhs, lhs))
        return false;
    if (lhs.known_end.has_value() != rhs.known_end.has_value())
        return lhs.known_end.has_value();
    if (seed_end_value(lhs) != seed_end_value(rhs))
        return seed_end_value(lhs) < seed_end_value(rhs);
    if (lhs.noreturn != rhs.noreturn)
        return lhs.noreturn > rhs.noreturn;
    return lhs.name < rhs.name;
}

bool seed_exact_equal(const function_seed_t& lhs, const function_seed_t& rhs) noexcept
{
    return lhs.address == rhs.address && lhs.known_end == rhs.known_end &&
        lhs.kind == rhs.kind && lhs.provenance == rhs.provenance &&
        lhs.confidence == rhs.confidence &&
        lhs.stable_source_id == rhs.stable_source_id &&
        lhs.name == rhs.name && lhs.noreturn == rhs.noreturn;
}

workspace_result_t<void> validate_instruction_stream(
    const workspace_image_t& image,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<target_fact_t>& targets,
    const std::vector<std::uint8_t>& delay_slot_counts)
{
    if (!delay_slot_counts.empty() && delay_slot_counts.size() != instructions.size()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "delay-slot column does not align with the instruction stream", "blocks"));
    }
    if (instructions.size() > (std::numeric_limits<std::uint32_t>::max)()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "instruction stream exceeds compact block indexing", "blocks"));
    }
    std::uint64_t previous_end = 0;
    for (std::size_t index = 0; index < instructions.size(); ++index) {
        const auto& instruction = instructions[index];
        if (instruction.id == 0 ||
            instruction.address.space != address_space_id_t::relative_virtual ||
            instruction.address.architecture != image.architecture ||
            instruction.address.mode != image.architecture_mode ||
            instruction.length == 0 ||
            !workspace_image_span_within(instruction.address.value, instruction.length,
                                         image.image_size)) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                "instruction stream contains an invalid normalized record", "blocks");
            error.address = instruction.address;
            return workspace_result_t<void>::failure(std::move(error));
        }
        std::uint64_t target_end = 0;
        if (!checked_add_u64(instruction.target_fact_begin,
                instruction.target_fact_count, target_end) || target_end > targets.size()) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                "instruction target-fact range is invalid", "blocks");
            error.address = instruction.address;
            return workspace_result_t<void>::failure(std::move(error));
        }
        const auto end = instruction_end(instruction);
        if (end == (std::numeric_limits<std::uint64_t>::max)() ||
            (index != 0 && instruction.address.value < previous_end)) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                "instruction stream is unsorted or overlapping", "blocks");
            error.address = instruction.address;
            return workspace_result_t<void>::failure(std::move(error));
        }
        previous_end = end;
        const auto delay_count = delay_slot_counts.empty() ? 0U : delay_slot_counts[index];
        if (delay_count == 0)
            continue;
        if ((instruction.flow_flags & kControlFlowMask) == 0 ||
            delay_count > 2 || index + delay_count >= instructions.size()) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                "delay-slot metadata is invalid for its transfer instruction", "blocks");
            error.address = instruction.address;
            return workspace_result_t<void>::failure(std::move(error));
        }
        auto expected = end;
        for (std::size_t offset = 1; offset <= delay_count; ++offset) {
            const auto& slot = instructions[index + offset];
            if (slot.address.value != expected ||
                (slot.flow_flags & kControlFlowMask) != 0) {
                auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                    "delay-slot instruction sequence is malformed", "blocks");
                error.address = slot.address;
                return workspace_result_t<void>::failure(std::move(error));
            }
            expected = instruction_end(slot);
        }
    }
    return workspace_result_t<void>::success();
}

template <typename T>
workspace_result_t<void> append_bounded(std::vector<T>& values, T value,
    std::uint64_t maximum_count, std::uint64_t maximum_bytes,
    std::uint64_t& storage_bytes, const char* phase, const char* message)
{
    if (values.size() >= maximum_count) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded, message, phase));
    }
    if (values.size() == values.capacity()) {
        const auto current = static_cast<std::uint64_t>(values.capacity());
        std::uint64_t desired = current == 0 ? std::min<std::uint64_t>(4096, maximum_count) : 0;
        if (current != 0 && !checked_add_u64(current, current / 2ULL, desired)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow, message, phase));
        }
        std::uint64_t minimum = 0;
        if (!checked_add_u64(current, 1, minimum)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow, message, phase));
        }
        desired = std::min(std::max(desired, minimum), maximum_count);
        std::uint64_t new_allocation = 0;
        std::uint64_t retained_delta = 0;
        std::uint64_t peak = 0;
        if (desired <= current || !checked_mul_u64(desired, sizeof(T), new_allocation) ||
            !checked_mul_u64(desired - current, sizeof(T), retained_delta) ||
            !checked_add_u64(storage_bytes, new_allocation, peak) || peak > maximum_bytes) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded, message, phase));
        }
        values.reserve(static_cast<std::size_t>(desired));
        if (!checked_add_u64(storage_bytes, retained_delta, storage_bytes)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow, message, phase));
        }
    }
    values.push_back(std::move(value));
    return workspace_result_t<void>::success();
}

bool edge_less(const edge_record_t& lhs, const edge_record_t& rhs) noexcept
{
    if (lhs.source != rhs.source)
        return lhs.source < rhs.source;
    if (lhs.target != rhs.target)
        return lhs.target < rhs.target;
    if (lhs.kind != rhs.kind)
        return lhs.kind < rhs.kind;
    if (lhs.provenance != rhs.provenance)
        return provenance_rank(lhs.provenance) > provenance_rank(rhs.provenance);
    if (lhs.confidence != rhs.confidence)
        return lhs.confidence > rhs.confidence;
    if (lhs.source_entity != rhs.source_entity)
        return lhs.source_entity < rhs.source_entity;
    return lhs.target_entity.value_or(0) < rhs.target_entity.value_or(0);
}

bool edge_equal(const edge_record_t& lhs, const edge_record_t& rhs) noexcept
{
    return lhs.source_entity == rhs.source_entity && lhs.source == rhs.source &&
        lhs.target == rhs.target && lhs.kind == rhs.kind;
}

const instruction_record_t* transfer_instruction(
    std::size_t block_index,
    const std::vector<basic_block_record_t>& blocks,
    const std::vector<std::uint32_t>& terminators,
    const std::vector<instruction_record_t>& instructions) noexcept
{
    if (block_index >= blocks.size())
        return nullptr;
    const auto& block = blocks[block_index];
    if (block.instruction_count == 0)
        return nullptr;
    const auto first = static_cast<std::size_t>(block.first_instruction);
    const auto end = first + block.instruction_count;
    if (end > instructions.size())
        return nullptr;
    if (terminators.size() == blocks.size()) {
        const auto index = static_cast<std::size_t>(terminators[block_index]);
        if (index >= first && index < end)
            return &instructions[index];
    }
    for (std::size_t index = end; index > first; --index) {
        if ((instructions[index - 1].flow_flags & kControlFlowMask) != 0)
            return &instructions[index - 1];
    }
    return &instructions[end - 1];
}

bool ascii_equal(std::string_view lhs, std::string_view rhs) noexcept
{
    if (lhs.size() != rhs.size())
        return false;
    for (std::size_t index = 0; index < lhs.size(); ++index) {
        auto left = static_cast<unsigned char>(lhs[index]);
        auto right = static_cast<unsigned char>(rhs[index]);
        if (left >= 'A' && left <= 'Z')
            left = static_cast<unsigned char>(left + ('a' - 'A'));
        if (right >= 'A' && right <= 'Z')
            right = static_cast<unsigned char>(right + ('a' - 'A'));
        if (left != right)
            return false;
    }
    return true;
}

bool ascii_starts_with(std::string_view value, std::string_view prefix) noexcept
{
    return value.size() >= prefix.size() && ascii_equal(value.substr(0, prefix.size()), prefix);
}

bool known_noreturn_name(std::string_view input) noexcept
{
    const auto separator = input.find_last_of("!:");
    const auto name = separator != std::string_view::npos && separator + 1 < input.size()
        ? input.substr(separator + 1) : input;
    static constexpr std::array<const char*, 31> exact = {
        "_invoke_watson", "_invalid_parameter", "_invalid_parameter_noinfo",
        "_invalid_parameter_noinfo_noreturn", "_cxxthrowexception",
        "__report_gsfailure", "__report_rangecheckfailure",
        "__report_securityfailure", "__report_securityfailureex",
        "__std_terminate", "terminate", "abort", "_abort", "exit", "_exit",
        "_purecall", "_unrecoverable_error", "raiseexception",
        "raisefailfastexception", "exitprocess", "exitthread",
        "terminateprocess", "terminatethread", "fatalappexit", "fatalappexita",
        "fatalappexitw", "fatalexit", "__fastfail", "longjmp", "_longjmp",
        "__cxa_throw"
    };
    for (const auto candidate : exact) {
        if (ascii_equal(name, candidate))
            return true;
    }
    return ascii_starts_with(name, "_invalid_parameter") ||
        ascii_starts_with(name, "__report");
}

bool conflict_less(const function_recovery_conflict_t& lhs,
                   const function_recovery_conflict_t& rhs) noexcept
{
    if (lhs.kind != rhs.kind)
        return lhs.kind < rhs.kind;
    if (lhs.rva != rhs.rva)
        return lhs.rva < rhs.rva;
    if (lhs.related_rva != rhs.related_rva)
        return lhs.related_rva < rhs.related_rva;
    if (lhs.selected_function_id != rhs.selected_function_id)
        return lhs.selected_function_id < rhs.selected_function_id;
    if (lhs.competing_function_id != rhs.competing_function_id)
        return lhs.competing_function_id < rhs.competing_function_id;
    if (lhs.selected_source_id != rhs.selected_source_id)
        return lhs.selected_source_id < rhs.selected_source_id;
    if (lhs.competing_source_id != rhs.competing_source_id)
        return lhs.competing_source_id < rhs.competing_source_id;
    if (lhs.selected_seed_kind != rhs.selected_seed_kind)
        return lhs.selected_seed_kind < rhs.selected_seed_kind;
    return lhs.competing_seed_kind < rhs.competing_seed_kind;
}

bool conflict_equal(const function_recovery_conflict_t& lhs,
                    const function_recovery_conflict_t& rhs) noexcept
{
    return !conflict_less(lhs, rhs) && !conflict_less(rhs, lhs);
}

workspace_result_t<void> append_conflict(function_recovery_result_t& result,
    function_recovery_conflict_t conflict, const function_recovery_limits_t& limits)
{
    return append_bounded(result.conflicts, std::move(conflict), limits.max_conflicts,
        limits.max_result_bytes, result.storage_bytes, "functions",
        "function recovery conflict storage exceeds analysis budget");
}

workspace_result_t<void> validate_block_result(
    const workspace_image_t& image,
    const std::vector<instruction_record_t>& instructions,
    const block_recovery_result_t& result,
    const function_recovery_limits_t& limits)
{
    if (result.blocks.size() > limits.max_blocks || result.edges.size() > limits.max_edges) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "block recovery input exceeds function recovery limits", "functions"));
    }
    if (!result.terminator_instruction_indices.empty() &&
        result.terminator_instruction_indices.size() != result.blocks.size()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "block terminator column is not aligned", "functions"));
    }
    std::map<entity_id_t, std::size_t> ids;
    for (std::size_t index = 0; index < result.blocks.size(); ++index) {
        const auto& block = result.blocks[index];
        const auto first = static_cast<std::uint64_t>(block.first_instruction);
        std::uint64_t end = 0;
        if (block.id == 0 || block.start.space != address_space_id_t::relative_virtual ||
            block.end.space != address_space_id_t::relative_virtual ||
            block.start.architecture != image.architecture ||
            block.end.architecture != image.architecture ||
            block.start.mode != image.architecture_mode ||
            block.end.mode != image.architecture_mode ||
            block.start.value >= block.end.value ||
            !workspace_image_span_within(block.start.value,
                block.end.value - block.start.value, image.image_size) ||
            block.instruction_count == 0 ||
            !checked_add_u64(first, block.instruction_count, end) ||
            end > instructions.size() || !ids.emplace(block.id, index).second) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "basic block record is malformed", "functions"));
        }
        if (instructions[static_cast<std::size_t>(first)].address != block.start ||
            instruction_end(instructions[static_cast<std::size_t>(end - 1)]) !=
                block.end.value) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "basic block instruction range is inconsistent", "functions"));
        }
        for (std::uint64_t instruction = first + 1; instruction < end; ++instruction) {
            if (instructions[static_cast<std::size_t>(instruction)].address.value !=
                instruction_end(instructions[static_cast<std::size_t>(instruction - 1)])) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "basic block contains a discontinuous instruction range", "functions"));
            }
        }
        if (index != 0) {
            const auto& previous = result.blocks[index - 1];
            if (block.start.value < previous.end.value) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "basic block ranges overlap", "functions"));
            }
        }
        if (!result.terminator_instruction_indices.empty()) {
            const auto terminator = result.terminator_instruction_indices[index];
            if (terminator < first || terminator >= end) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "basic block terminator reference is invalid", "functions"));
            }
        }
    }
    for (const auto& edge : result.edges) {
        if (ids.find(edge.source_entity) == ids.end()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "CFG edge references an unknown source block", "functions"));
        }
    }
    return workspace_result_t<void>::success();
}

struct selected_seed_t {
    function_seed_t seed;
    std::uint64_t start = 0;
    std::optional<std::uint64_t> end;
};

bool selected_seed_less(const selected_seed_t& lhs, const selected_seed_t& rhs) noexcept
{
    if (lhs.start != rhs.start)
        return lhs.start < rhs.start;
    return seed_canonical_less(lhs.seed, rhs.seed);
}

struct function_candidate_t {
    selected_seed_t selection;
    std::vector<std::size_t> blocks;
    entity_id_t function_id = 0;
    bool synthetic_gap = false;
};

bool candidate_less(const function_candidate_t& lhs,
                    const function_candidate_t& rhs) noexcept
{
    if (selected_seed_less(lhs.selection, rhs.selection))
        return true;
    if (selected_seed_less(rhs.selection, lhs.selection))
        return false;
    return lhs.synthetic_gap < rhs.synthetic_gap;
}

bool candidate_preferred(const function_candidate_t& lhs,
                         const function_candidate_t& rhs) noexcept
{
    if (stronger_seed(lhs.selection.seed, rhs.selection.seed))
        return true;
    if (stronger_seed(rhs.selection.seed, lhs.selection.seed))
        return false;
    if (lhs.selection.start != rhs.selection.start)
        return lhs.selection.start < rhs.selection.start;
    return lhs.function_id < rhs.function_id;
}

bool compact_thunk(const function_candidate_t& candidate,
                   const std::vector<basic_block_record_t>& blocks,
                   const std::vector<std::uint32_t>& terminators,
                   const std::vector<instruction_record_t>& instructions) noexcept
{
    if (candidate.blocks.size() != 1)
        return false;
    const auto block_index = candidate.blocks.front();
    if (block_index >= blocks.size() || blocks[block_index].instruction_count > 3)
        return false;
    const auto* transfer = transfer_instruction(block_index, blocks, terminators, instructions);
    return transfer != nullptr &&
        (transfer->flow_flags & (flow_branch | flow_call)) != 0 &&
        (transfer->flow_flags & (flow_conditional | flow_return)) == 0;
}

}

workspace_result_t<std::vector<function_seed_t>> function_recovery_t::combine_seed_sources(
    const function_seed_sources_t& sources,
    const function_recovery_limits_t& limits,
    const cancellation_token_t& cancel)
{
    if (!valid_limits(limits)) {
        return workspace_result_t<std::vector<function_seed_t>>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "function recovery limits are invalid", "seed_combine"));
    }
    if (cancel.stop_requested()) {
        return workspace_result_t<std::vector<function_seed_t>>::failure(
            stop_error(cancel, "seed_combine"));
    }
    const std::array<std::pair<const std::vector<function_seed_t>*,
                               function_seed_kind_t>, 10> groups{{
        {&sources.image_entries, function_seed_kind_t::image_entry},
        {&sources.tls_callbacks, function_seed_kind_t::tls_callback},
        {&sources.symbols, function_seed_kind_t::debug_symbol},
        {&sources.exports, function_seed_kind_t::export_entry},
        {&sources.unwind_ranges, function_seed_kind_t::unwind_range},
        {&sources.load_config_entries, function_seed_kind_t::load_config_entry},
        {&sources.relocation_targets, function_seed_kind_t::relocation_target},
        {&sources.call_targets, function_seed_kind_t::direct_call_target},
        {&sources.pointer_targets, function_seed_kind_t::pointer_target},
        {&sources.validated_gap_targets, function_seed_kind_t::validated_gap_target}
    }};
    std::uint64_t count = 0;
    for (const auto& group : groups) {
        if (!checked_add_u64(count, group.first->size(), count) ||
            count > limits.max_seed_candidates) {
            return workspace_result_t<std::vector<function_seed_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "combined function seeds exceed analysis budget", "seed_combine"));
        }
    }
    std::vector<function_seed_t> combined;
    combined.reserve(static_cast<std::size_t>(count));
    std::uint64_t checks = 0;
    const auto append = [&](const std::vector<function_seed_t>& values,
                            function_seed_kind_t kind) -> workspace_result_t<void> {
        for (const auto& value : values) {
            if (++checks >= limits.cancellation_check_interval) {
                checks = 0;
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(stop_error(cancel, "seed_combine"));
            }
            combined.push_back(normalize_seed(value, kind));
        }
        return workspace_result_t<void>::success();
    };
    for (const auto& group : groups) {
        auto appended = append(*group.first, group.second);
        if (!appended) {
            return workspace_result_t<std::vector<function_seed_t>>::failure(
                appended.error());
        }
    }
    std::sort(combined.begin(), combined.end(), seed_canonical_less);
    combined.erase(std::unique(combined.begin(), combined.end(), seed_exact_equal),
                   combined.end());
    return workspace_result_t<std::vector<function_seed_t>>::success(std::move(combined));
}

workspace_result_t<std::vector<function_seed_t>> function_recovery_t::converge_seed_sources(
    const workspace_image_t& image,
    const std::vector<target_fact_t>& targets,
    const function_seed_evidence_t& evidence,
    const function_recovery_limits_t& limits,
    const cancellation_token_t& cancel)
{
    if (!valid_limits(limits)) {
        return workspace_result_t<std::vector<function_seed_t>>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "function recovery limits are invalid", "seed_converge"));
    }
    if (cancel.stop_requested())
        return workspace_result_t<std::vector<function_seed_t>>::failure(
            stop_error(cancel, "seed_converge"));
    try {
        function_seed_sources_t sources;
        std::uint64_t source_count = 0;
        std::uint64_t seed_storage_bytes = 0;
        std::uint64_t visits = 0;
        const auto inspect_source = [&]() -> workspace_result_t<void> {
            if (++visits >= limits.cancellation_check_interval) {
                visits = 0;
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(
                        stop_error(cancel, "seed_converge"));
            }
            if (source_count >= limits.max_seed_candidates) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "function seed evidence exceeds analysis budget", "seed_converge"));
            }
            ++source_count;
            return workspace_result_t<void>::success();
        };
        const auto select_group = [&](function_seed_kind_t kind)
            -> std::vector<function_seed_t>& {
            switch (kind) {
                case function_seed_kind_t::image_entry: return sources.image_entries;
                case function_seed_kind_t::tls_callback: return sources.tls_callbacks;
                case function_seed_kind_t::export_entry: return sources.exports;
                case function_seed_kind_t::unwind_range: return sources.unwind_ranges;
                case function_seed_kind_t::debug_symbol: return sources.symbols;
                case function_seed_kind_t::load_config_entry:
                    return sources.load_config_entries;
                case function_seed_kind_t::relocation_target:
                    return sources.relocation_targets;
                case function_seed_kind_t::direct_call_target:
                    return sources.call_targets;
                case function_seed_kind_t::validated_gap_target:
                    return sources.validated_gap_targets;
                case function_seed_kind_t::pointer_target:
                    return sources.pointer_targets;
            }
            return sources.validated_gap_targets;
        };
        const auto append_seed = [&](function_seed_t seed, function_seed_kind_t kind,
                                     std::uint64_t source_discriminator)
            -> workspace_result_t<void> {
            const auto rva = to_rva(image, seed.address);
            if (!rva || !executable_rva(image, *rva))
                return workspace_result_t<void>::success();
            seed.address = rva_address(image, *rva);
            if (seed.known_end) {
                const auto end = to_rva_endpoint(image, *seed.known_end);
                if (end && *end > *rva)
                    seed.known_end = rva_address(image, *end);
                else
                    seed.known_end.reset();
            }
            seed.kind = kind;
            if (seed.provenance == fact_provenance_t::unknown)
                seed.provenance = default_seed_provenance(kind);
            if (seed.confidence == 0)
                seed.confidence = seed_confidence(kind);
            if (seed.provenance > fact_provenance_t::decompiler_feedback ||
                seed.confidence > 100) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "function seed provenance or confidence is invalid", "seed_converge"));
            }
            if (seed.stable_source_id == 0) {
                auto discriminator = seed.known_end ? seed.known_end->value : 0;
                discriminator = stable_mix(discriminator,
                    static_cast<std::uint64_t>(seed.provenance));
                discriminator = stable_mix(discriminator, seed.confidence);
                discriminator = stable_mix(discriminator, stable_text(seed.name));
                discriminator = stable_mix(discriminator, seed.noreturn ? 1 : 0);
                discriminator = stable_mix(discriminator, source_discriminator);
                seed.stable_source_id = stable_seed_source(kind, *rva, discriminator);
            }
            std::uint64_t seed_bytes = 0;
            if (!checked_add_u64(sizeof(function_seed_t), seed.name.size(), seed_bytes) ||
                !checked_add_u64(seed_storage_bytes, seed_bytes, seed_storage_bytes) ||
                seed_storage_bytes > limits.max_result_bytes) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "converged function seed storage exceeds analysis budget",
                    "seed_converge"));
            }
            select_group(kind).push_back(std::move(seed));
            return workspace_result_t<void>::success();
        };
        if (evidence.additional_sources) {
            const std::array<std::pair<const std::vector<function_seed_t>*,
                                       function_seed_kind_t>, 10> groups{{
                {&evidence.additional_sources->image_entries,
                    function_seed_kind_t::image_entry},
                {&evidence.additional_sources->tls_callbacks,
                    function_seed_kind_t::tls_callback},
                {&evidence.additional_sources->symbols,
                    function_seed_kind_t::debug_symbol},
                {&evidence.additional_sources->exports,
                    function_seed_kind_t::export_entry},
                {&evidence.additional_sources->unwind_ranges,
                    function_seed_kind_t::unwind_range},
                {&evidence.additional_sources->load_config_entries,
                    function_seed_kind_t::load_config_entry},
                {&evidence.additional_sources->relocation_targets,
                    function_seed_kind_t::relocation_target},
                {&evidence.additional_sources->call_targets,
                    function_seed_kind_t::direct_call_target},
                {&evidence.additional_sources->pointer_targets,
                    function_seed_kind_t::pointer_target},
                {&evidence.additional_sources->validated_gap_targets,
                    function_seed_kind_t::validated_gap_target}
            }};
            for (const auto& group : groups) {
                for (const auto& seed : *group.first) {
                    auto inspected = inspect_source();
                    if (!inspected) {
                        return workspace_result_t<std::vector<function_seed_t>>::failure(
                            inspected.error());
                    }
                    auto appended = append_seed(seed, group.second, 0);
                    if (!appended)
                        return workspace_result_t<std::vector<function_seed_t>>::failure(
                            appended.error());
                }
            }
        }
        for (const auto& entry : image.entry_points) {
            auto inspected = inspect_source();
            if (!inspected)
                return workspace_result_t<std::vector<function_seed_t>>::failure(
                    inspected.error());
            const auto kind = entry_seed_kind(entry.provenance);
            function_seed_t seed;
            seed.address = entry.address;
            seed.name = entry.provenance;
            const auto source_discriminator = stable_mix(
                stable_text(entry.provenance), static_cast<std::uint64_t>(kind));
            auto appended = append_seed(std::move(seed), kind, source_discriminator);
            if (!appended)
                return workspace_result_t<std::vector<function_seed_t>>::failure(
                    appended.error());
        }
        for (const auto& exported : image.exports) {
            auto inspected = inspect_source();
            if (!inspected)
                return workspace_result_t<std::vector<function_seed_t>>::failure(
                    inspected.error());
            if (exported.forwarder)
                continue;
            function_seed_t seed;
            seed.address = exported.address;
            seed.name = exported.name.value_or(std::string{});
            const auto source_discriminator = stable_mix(
                exported.ordinal, stable_text(seed.name));
            auto appended = append_seed(std::move(seed),
                function_seed_kind_t::export_entry, source_discriminator);
            if (!appended)
                return workspace_result_t<std::vector<function_seed_t>>::failure(
                    appended.error());
        }
        for (const auto& symbol : image.symbols) {
            auto inspected = inspect_source();
            if (!inspected)
                return workspace_result_t<std::vector<function_seed_t>>::failure(
                    inspected.error());
            if (!symbol.defined ||
                (symbol.kind != image_symbol_kind_t::function &&
                 symbol.kind != image_symbol_kind_t::debug_symbol &&
                 symbol.kind != image_symbol_kind_t::export_symbol))
                continue;
            function_seed_t seed;
            seed.address = symbol.address;
            seed.name = symbol.name;
            const auto kind = symbol.kind == image_symbol_kind_t::export_symbol
                ? function_seed_kind_t::export_entry
                : function_seed_kind_t::debug_symbol;
            seed.confidence = symbol.kind == image_symbol_kind_t::function ? 96 : 95;
            const auto source_discriminator = stable_mix(
                symbol.ordinal, stable_text(symbol.name));
            auto appended = append_seed(std::move(seed), kind, source_discriminator);
            if (!appended)
                return workspace_result_t<std::vector<function_seed_t>>::failure(
                    appended.error());
        }
        if (evidence.symbols) {
            for (const auto& symbol : *evidence.symbols) {
                auto inspected = inspect_source();
                if (!inspected)
                    return workspace_result_t<std::vector<function_seed_t>>::failure(
                        inspected.error());
                if (symbol.kind != symbol_kind_t::function &&
                    symbol.kind != symbol_kind_t::debug_symbol &&
                    symbol.kind != symbol_kind_t::export_symbol)
                    continue;
                function_seed_t seed;
                seed.address = symbol.address;
                seed.name = symbol.name;
                seed.provenance = symbol.provenance;
                seed.confidence = symbol.confidence;
                seed.stable_source_id = symbol.id;
                const auto kind = symbol.kind == symbol_kind_t::export_symbol
                    ? function_seed_kind_t::export_entry
                    : function_seed_kind_t::debug_symbol;
                auto appended = append_seed(std::move(seed), kind,
                    stable_text(symbol.name));
                if (!appended)
                    return workspace_result_t<std::vector<function_seed_t>>::failure(
                        appended.error());
            }
        }
        if (evidence.unwind_ranges) {
            for (const auto& unwind : *evidence.unwind_ranges) {
                auto inspected = inspect_source();
                if (!inspected)
                    return workspace_result_t<std::vector<function_seed_t>>::failure(
                        inspected.error());
                function_seed_t seed;
                seed.address = rva_address(image, unwind.function_rva);
                if (unwind.end_rva > unwind.function_rva)
                    seed.known_end = rva_address(image, unwind.end_rva);
                const auto source_discriminator = stable_mix(
                    unwind.end_rva, unwind.unwind_info_rva);
                auto appended = append_seed(std::move(seed),
                    function_seed_kind_t::unwind_range, source_discriminator);
                if (!appended)
                    return workspace_result_t<std::vector<function_seed_t>>::failure(
                        appended.error());
            }
        }
        for (const auto& target : targets) {
            auto inspected = inspect_source();
            if (!inspected)
                return workspace_result_t<std::vector<function_seed_t>>::failure(
                    inspected.error());
            if (target.kind != target_kind_record_t::call || !target.direct ||
                target.is_external)
                continue;
            function_seed_t seed;
            seed.address = target.target;
            const auto source_discriminator = stable_mix(target.instruction_id,
                stable_mix(target.operand_fact_id, target.address_expression_id));
            auto appended = append_seed(std::move(seed),
                function_seed_kind_t::direct_call_target, source_discriminator);
            if (!appended)
                return workspace_result_t<std::vector<function_seed_t>>::failure(
                    appended.error());
        }
        for (const auto& relocation : image.relocations) {
            auto inspected = inspect_source();
            if (!inspected)
                return workspace_result_t<std::vector<function_seed_t>>::failure(
                    inspected.error());
            if (!relocation.target)
                continue;
            function_seed_t seed;
            seed.address = *relocation.target;
            const auto slot_rva = to_rva(image, relocation.address);
            const auto source_discriminator = stable_mix(
                slot_rva.value_or(relocation.address.value), relocation.type);
            auto appended = append_seed(std::move(seed),
                function_seed_kind_t::relocation_target, source_discriminator);
            if (!appended)
                return workspace_result_t<std::vector<function_seed_t>>::failure(
                    appended.error());
        }
        if (evidence.pointer_facts) {
            for (const auto& pointer : *evidence.pointer_facts) {
                auto inspected = inspect_source();
                if (!inspected)
                    return workspace_result_t<std::vector<function_seed_t>>::failure(
                        inspected.error());
                function_seed_t seed;
                seed.address = pointer.target;
                seed.provenance = pointer.provenance;
                seed.confidence = pointer.confidence;
                seed.stable_source_id = pointer.id;
                const auto slot_rva = to_rva(image, pointer.slot);
                auto appended = append_seed(std::move(seed),
                    function_seed_kind_t::pointer_target,
                    slot_rva.value_or(pointer.slot.value));
                if (!appended)
                    return workspace_result_t<std::vector<function_seed_t>>::failure(
                        appended.error());
            }
        }
        return combine_seed_sources(sources, limits, cancel);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::vector<function_seed_t>>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "function seed convergence exhausted memory", "seed_converge"));
    } catch (const std::length_error&) {
        return workspace_result_t<std::vector<function_seed_t>>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "function seed convergence exceeded container capacity", "seed_converge"));
    }
}

workspace_result_t<function_recovery_result_t> function_recovery_t::recover(
    const workspace_image_t& image,
    const byte_provider_t& provider,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<operand_fact_t>& operands,
    const std::vector<target_fact_t>& targets,
    const function_seed_evidence_t& evidence,
    const std::vector<std::uint8_t>& delay_slot_counts,
    const function_recovery_limits_t& limits,
    const cancellation_token_t& cancel)
{
    auto seeds = converge_seed_sources(image, targets, evidence, limits, cancel);
    if (!seeds)
        return workspace_result_t<function_recovery_result_t>::failure(seeds.error());
    const auto converged_seed_count = static_cast<std::uint64_t>(seeds.value().size());
    auto blocks = build_blocks(image, instructions, targets, seeds.value(),
        delay_slot_counts, limits, cancel);
    if (!blocks)
        return workspace_result_t<function_recovery_result_t>::failure(blocks.error());
    auto functions = recover_functions(image, instructions, seeds.value(),
        blocks.take_value(), limits, cancel);
    if (!functions)
        return workspace_result_t<function_recovery_result_t>::failure(functions.error());
    auto finalized = finalize_cfg_calls(image, provider, instructions, operands, targets,
        functions.take_value(), limits, cancel);
    if (!finalized)
        return finalized;
    finalized.value().converged_seed_count = converged_seed_count;
    finalized.value().delay_slot_transfer_count = static_cast<std::uint64_t>(
        std::count_if(delay_slot_counts.begin(), delay_slot_counts.end(),
            [](std::uint8_t count) { return count != 0; }));
    return finalized;
}

workspace_result_t<block_recovery_result_t> function_recovery_t::build_blocks(
    const workspace_image_t& image,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<target_fact_t>& targets,
    const std::vector<function_seed_t>& seeds,
    const function_recovery_limits_t& limits,
    const cancellation_token_t& cancel)
{
    static const std::vector<std::uint8_t> no_delay_slots;
    return build_blocks(image, instructions, targets, seeds, no_delay_slots, limits, cancel);
}

workspace_result_t<block_recovery_result_t> function_recovery_t::build_blocks(
    const workspace_image_t& image,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<target_fact_t>& targets,
    const std::vector<function_seed_t>& seeds,
    const std::vector<std::uint8_t>& delay_slot_counts,
    const function_recovery_limits_t& limits,
    const cancellation_token_t& cancel)
{
    if (!valid_limits(limits)) {
        return workspace_result_t<block_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "function recovery limits are invalid", "blocks"));
    }
    if (seeds.size() > limits.max_seed_candidates) {
        return workspace_result_t<block_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "function seed candidates exceed analysis budget", "blocks"));
    }
    auto valid = validate_instruction_stream(image, instructions, targets, delay_slot_counts);
    if (!valid)
        return workspace_result_t<block_recovery_result_t>::failure(valid.error());
    block_recovery_result_t result;
    if (instructions.empty())
        return workspace_result_t<block_recovery_result_t>::success(std::move(result));
    std::vector<bool> leaders(instructions.size(), false);
    leaders.front() = true;
    std::map<std::uint64_t, std::size_t> instruction_index;
    for (std::size_t index = 0; index < instructions.size(); ++index)
        instruction_index.emplace(instructions[index].address.value, index);
    std::uint64_t checks = 0;
    for (const auto& seed : seeds) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<block_recovery_result_t>::failure(
                    stop_error(cancel, "blocks"));
        }
        const auto rva = to_rva(image, seed.address);
        const auto found = rva ? instruction_index.find(*rva) : instruction_index.end();
        if (found != instruction_index.end())
            leaders[found->second] = true;
        if (seed.known_end) {
            const auto end_rva = to_rva_endpoint(image, *seed.known_end);
            const auto end_found = end_rva ? instruction_index.find(*end_rva)
                                           : instruction_index.end();
            if (end_found != instruction_index.end())
                leaders[end_found->second] = true;
        }
    }
    for (std::size_t index = 0; index < instructions.size(); ++index) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<block_recovery_result_t>::failure(
                    stop_error(cancel, "blocks"));
        }
        const auto& instruction = instructions[index];
        const auto target_end = static_cast<std::uint64_t>(instruction.target_fact_begin) +
            instruction.target_fact_count;
        for (std::uint64_t target_index = instruction.target_fact_begin;
             target_index < target_end; ++target_index) {
            const auto& target = targets[static_cast<std::size_t>(target_index)];
            if (target.kind != target_kind_record_t::branch &&
                target.kind != target_kind_record_t::call)
                continue;
            const auto rva = to_rva(image, target.target);
            const auto found = rva ? instruction_index.find(*rva) : instruction_index.end();
            if (found != instruction_index.end())
                leaders[found->second] = true;
        }
        const auto delay_count = delay_slot_counts.empty() ? 0U : delay_slot_counts[index];
        const auto transfer_end = index + delay_count;
        if ((instruction.flow_flags & kControlFlowMask) != 0 &&
            transfer_end + 1 < instructions.size()) {
            leaders[transfer_end + 1] = true;
        }
        if (index + 1 < instructions.size() &&
            instruction_end(instruction) != instructions[index + 1].address.value)
            leaders[index + 1] = true;
    }
    if (!delay_slot_counts.empty()) {
        for (std::size_t index = 0; index < delay_slot_counts.size(); ++index) {
            for (std::size_t offset = 1; offset <= delay_slot_counts[index]; ++offset) {
                if (leaders[index + offset]) {
                    auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                        "delay-slot instruction is also a basic-block leader", "blocks");
                    error.address = instructions[index + offset].address;
                    return workspace_result_t<block_recovery_result_t>::failure(
                        std::move(error));
                }
            }
        }
    }
    for (std::size_t first = 0; first < instructions.size();) {
        if (cancel.stop_requested())
            return workspace_result_t<block_recovery_result_t>::failure(
                stop_error(cancel, "blocks"));
        std::size_t end = first + 1;
        while (end < instructions.size() && !leaders[end])
            ++end;
        std::size_t terminator = end - 1;
        for (std::size_t index = first; index < end; ++index) {
            const auto delay_count = delay_slot_counts.empty() ? 0U : delay_slot_counts[index];
            if ((instructions[index].flow_flags & kControlFlowMask) != 0 &&
                index + delay_count == end - 1) {
                terminator = index;
                break;
            }
        }
        basic_block_record_t block;
        block.id = kBlockEntityTag | static_cast<std::uint64_t>(result.blocks.size() + 1);
        block.start = instructions[first].address;
        block.end = rva_address(image, instruction_end(instructions[end - 1]));
        block.first_instruction = static_cast<std::uint32_t>(first);
        block.instruction_count = static_cast<std::uint32_t>(end - first);
        block.provenance = instructions[first].provenance;
        block.confidence = instructions[first].confidence;
        for (std::size_t index = first + 1; index < end; ++index) {
            if (provenance_rank(instructions[index].provenance) >
                    provenance_rank(block.provenance) ||
                (instructions[index].provenance == block.provenance &&
                 instructions[index].confidence > block.confidence)) {
                block.provenance = instructions[index].provenance;
                block.confidence = instructions[index].confidence;
            }
        }
        auto appended = append_bounded(result.blocks, std::move(block), limits.max_blocks,
            limits.max_result_bytes, result.storage_bytes, "blocks",
            "basic block storage exceeds analysis budget");
        if (!appended)
            return workspace_result_t<block_recovery_result_t>::failure(appended.error());
        appended = append_bounded(result.terminator_instruction_indices,
            static_cast<std::uint32_t>(terminator), limits.max_blocks,
            limits.max_result_bytes, result.storage_bytes, "blocks",
            "basic block terminator storage exceeds analysis budget");
        if (!appended)
            return workspace_result_t<block_recovery_result_t>::failure(appended.error());
        first = end;
    }
    std::map<std::uint64_t, std::size_t> blocks_by_start;
    for (std::size_t index = 0; index < result.blocks.size(); ++index)
        blocks_by_start.emplace(result.blocks[index].start.value, index);
    for (std::size_t block_index = 0; block_index < result.blocks.size(); ++block_index) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<block_recovery_result_t>::failure(
                    stop_error(cancel, "blocks"));
        }
        const auto& block = result.blocks[block_index];
        const auto* transfer = transfer_instruction(block_index, result.blocks,
            result.terminator_instruction_indices, instructions);
        if (!transfer)
            continue;
        const auto append_edge = [&](const address_t& target, edge_kind_t kind)
            -> workspace_result_t<void> {
            edge_record_t edge;
            edge.source_entity = block.id;
            edge.source = transfer->address;
            edge.target = target;
            edge.kind = kind;
            edge.provenance = transfer->provenance;
            edge.confidence = transfer->confidence;
            return append_bounded(result.edges, std::move(edge), limits.max_edges,
                limits.max_result_bytes, result.storage_bytes, "blocks",
                "CFG edge storage exceeds analysis budget");
        };
        const auto target_end = static_cast<std::uint64_t>(transfer->target_fact_begin) +
            transfer->target_fact_count;
        for (std::uint64_t target_index = transfer->target_fact_begin;
             target_index < target_end; ++target_index) {
            const auto& target = targets[static_cast<std::size_t>(target_index)];
            if (target.kind != target_kind_record_t::branch &&
                target.kind != target_kind_record_t::call)
                continue;
            const auto rva = to_rva(image, target.target);
            if (!rva || !executable_rva(image, *rva) ||
                blocks_by_start.find(*rva) == blocks_by_start.end())
                continue;
            edge_kind_t kind = edge_kind_t::call;
            if (target.kind == target_kind_record_t::branch) {
                if (!target.direct || (transfer->flow_flags & flow_indirect) != 0)
                    kind = edge_kind_t::indirect;
                else if ((transfer->flow_flags & flow_conditional) != 0)
                    kind = edge_kind_t::conditional_taken;
                else
                    kind = edge_kind_t::unconditional;
            }
            auto appended = append_edge(target.target, kind);
            if (!appended)
                return workspace_result_t<block_recovery_result_t>::failure(appended.error());
        }
        if ((transfer->flow_flags & flow_fallthrough) != 0) {
            const auto found = blocks_by_start.find(block.end.value);
            if (found != blocks_by_start.end()) {
                auto appended = append_edge(result.blocks[found->second].start,
                                            edge_kind_t::fallthrough);
                if (!appended)
                    return workspace_result_t<block_recovery_result_t>::failure(
                        appended.error());
            }
        }
    }
    std::sort(result.edges.begin(), result.edges.end(), edge_less);
    result.edges.erase(std::unique(result.edges.begin(), result.edges.end(), edge_equal),
        result.edges.end());
    for (std::size_t index = 0; index < result.edges.size(); ++index)
        result.edges[index].id = kEdgeEntityTag | static_cast<std::uint64_t>(index + 1);
    return workspace_result_t<block_recovery_result_t>::success(std::move(result));
}

workspace_result_t<function_recovery_result_t> function_recovery_t::recover_functions(
    const workspace_image_t& image,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<function_seed_t>& seeds,
    block_recovery_result_t block_result,
    const function_recovery_limits_t& limits,
    const cancellation_token_t& cancel)
{
    if (!valid_limits(limits)) {
        return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "function recovery limits are invalid", "functions"));
    }
    if (seeds.size() > limits.max_seed_candidates) {
        return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "function seed candidates exceed analysis budget", "functions"));
    }
    auto valid_blocks = validate_block_result(image, instructions, block_result, limits);
    if (!valid_blocks)
        return workspace_result_t<function_recovery_result_t>::failure(valid_blocks.error());
    function_recovery_result_t result;
    result.blocks = std::move(block_result.blocks);
    result.terminator_instruction_indices =
        std::move(block_result.terminator_instruction_indices);
    result.edges = std::move(block_result.edges);
    result.storage_bytes = block_result.storage_bytes;
    std::map<std::uint64_t, std::size_t> block_by_start;
    std::map<entity_id_t, std::size_t> block_by_id;
    std::map<std::uint64_t, bool> block_boundaries;
    for (std::size_t index = 0; index < result.blocks.size(); ++index) {
        block_by_start.emplace(result.blocks[index].start.value, index);
        block_by_id.emplace(result.blocks[index].id, index);
        block_boundaries.emplace(result.blocks[index].start.value, true);
        block_boundaries.emplace(result.blocks[index].end.value, true);
    }
    std::vector<selected_seed_t> selected;
    selected.reserve(std::min<std::size_t>(seeds.size(),
        static_cast<std::size_t>(limits.max_functions)));
    for (const auto& seed : seeds) {
        if (cancel.stop_requested())
            return workspace_result_t<function_recovery_result_t>::failure(
                stop_error(cancel, "functions"));
        const auto start = to_rva(image, seed.address);
        if (!start) {
            function_recovery_conflict_t conflict;
            conflict.kind = function_recovery_conflict_kind_t::invalid_seed_address;
            conflict.rva = seed.address.value;
            conflict.competing_seed_kind = seed.kind;
            conflict.competing_source_id = seed.stable_source_id;
            auto appended = append_conflict(result, std::move(conflict), limits);
            if (!appended)
                return workspace_result_t<function_recovery_result_t>::failure(
                    appended.error());
            continue;
        }
        const auto block = block_by_start.find(*start);
        if (block == block_by_start.end()) {
            function_recovery_conflict_t conflict;
            conflict.kind = function_recovery_conflict_kind_t::seed_without_block;
            conflict.rva = *start;
            conflict.competing_seed_kind = seed.kind;
            conflict.competing_source_id = seed.stable_source_id;
            auto appended = append_conflict(result, std::move(conflict), limits);
            if (!appended)
                return workspace_result_t<function_recovery_result_t>::failure(
                    appended.error());
            continue;
        }
        std::optional<std::uint64_t> end;
        if (seed.known_end) {
            end = to_rva_endpoint(image, *seed.known_end);
            if (!end || *end <= *start ||
                block_boundaries.find(*end) == block_boundaries.end()) {
                function_recovery_conflict_t conflict;
                conflict.kind = function_recovery_conflict_kind_t::invalid_seed_range;
                conflict.rva = *start;
                conflict.related_rva = seed.known_end->value;
                conflict.competing_seed_kind = seed.kind;
                conflict.competing_source_id = seed.stable_source_id;
                auto appended = append_conflict(result, std::move(conflict), limits);
                if (!appended)
                    return workspace_result_t<function_recovery_result_t>::failure(
                        appended.error());
                end.reset();
            }
        }
        selected.push_back({seed, *start, end});
    }
    std::sort(selected.begin(), selected.end(), selected_seed_less);
    std::vector<selected_seed_t> canonical;
    canonical.reserve(selected.size());
    for (std::size_t first = 0; first < selected.size();) {
        std::size_t end = first + 1;
        while (end < selected.size() && selected[end].start == selected[first].start)
            ++end;
        auto winner = selected[first];
        for (std::size_t index = first + 1; index < end; ++index) {
            winner.seed.noreturn = winner.seed.noreturn || selected[index].seed.noreturn;
            if (winner.seed.name.empty() && !selected[index].seed.name.empty())
                winner.seed.name = selected[index].seed.name;
            if (!winner.end && selected[index].end)
                winner.end = selected[index].end;
            function_recovery_conflict_t conflict;
            conflict.kind = function_recovery_conflict_kind_t::duplicate_seed;
            conflict.rva = winner.start;
            conflict.related_rva = selected[index].end.value_or(0);
            conflict.selected_seed_kind = winner.seed.kind;
            conflict.competing_seed_kind = selected[index].seed.kind;
            conflict.selected_source_id = winner.seed.stable_source_id;
            conflict.competing_source_id = selected[index].seed.stable_source_id;
            auto appended = append_conflict(result, std::move(conflict), limits);
            if (!appended)
                return workspace_result_t<function_recovery_result_t>::failure(
                    appended.error());
        }
        canonical.push_back(std::move(winner));
        first = end;
    }
    if (canonical.size() > limits.max_functions) {
        return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "canonical function seeds exceed analysis budget", "functions"));
    }
    std::optional<std::size_t> active_range;
    std::uint64_t active_end = 0;
    for (std::size_t index = 0; index < canonical.size(); ++index) {
        if (!canonical[index].end)
            continue;
        if (!active_range || canonical[index].start >= active_end) {
            active_range = index;
            active_end = *canonical[index].end;
            continue;
        }
        const auto& active = canonical[*active_range];
        const bool current_wins = stronger_seed(canonical[index].seed, active.seed);
        function_recovery_conflict_t conflict;
        conflict.kind = function_recovery_conflict_kind_t::overlapping_seed_ranges;
        conflict.rva = canonical[index].start;
        conflict.related_rva = std::min(active_end, *canonical[index].end);
        conflict.selected_seed_kind = current_wins ? canonical[index].seed.kind
                                                   : active.seed.kind;
        conflict.competing_seed_kind = current_wins ? active.seed.kind
                                                    : canonical[index].seed.kind;
        conflict.selected_source_id = current_wins
            ? canonical[index].seed.stable_source_id : active.seed.stable_source_id;
        conflict.competing_source_id = current_wins
            ? active.seed.stable_source_id : canonical[index].seed.stable_source_id;
        auto appended = append_conflict(result, std::move(conflict), limits);
        if (!appended)
            return workspace_result_t<function_recovery_result_t>::failure(
                appended.error());
        if (*canonical[index].end > active_end) {
            active_range = index;
            active_end = *canonical[index].end;
        }
    }
    std::vector<std::vector<std::size_t>> successors(result.blocks.size());
    for (const auto& edge : result.edges) {
        if (edge.kind == edge_kind_t::call || edge.kind == edge_kind_t::tail_call ||
            edge.kind == edge_kind_t::return_edge)
            continue;
        const auto source = block_by_id.find(edge.source_entity);
        const auto target = to_rva(image, edge.target);
        const auto found = target ? block_by_start.find(*target) : block_by_start.end();
        if (source == block_by_id.end() || found == block_by_start.end())
            continue;
        successors[source->second].push_back(found->second);
    }
    for (auto& values : successors) {
        std::sort(values.begin(), values.end());
        values.erase(std::unique(values.begin(), values.end()), values.end());
    }
    std::map<std::size_t, std::size_t> seeded_blocks;
    for (std::size_t index = 0; index < canonical.size(); ++index)
        seeded_blocks.emplace(block_by_start[canonical[index].start], index);
    std::vector<std::uint32_t> visit_marks(result.blocks.size(), 0);
    result.reachability_mark_slots = visit_marks.size();
    std::uint32_t generation = 0;
    std::uint64_t total_memberships = 0;
    std::vector<std::uint32_t> claim_counts(result.blocks.size(), 0);
    const auto next_generation = [&]() {
        ++generation;
        if (generation == 0) {
            std::fill(visit_marks.begin(), visit_marks.end(), 0);
            generation = 1;
        }
        ++result.reachability_passes;
        return generation;
    };
    const auto traverse = [&](const selected_seed_t& selection, bool unclaimed_only)
        -> workspace_result_t<std::vector<std::size_t>> {
        const auto start = block_by_start.find(selection.start);
        if (start == block_by_start.end())
            return workspace_result_t<std::vector<std::size_t>>::success({});
        const auto mark = next_generation();
        std::vector<std::size_t> pending;
        std::vector<std::size_t> reached;
        pending.push_back(start->second);
        while (!pending.empty()) {
            if (cancel.stop_requested())
                return workspace_result_t<std::vector<std::size_t>>::failure(
                    stop_error(cancel, "functions"));
            const auto block_index = pending.back();
            pending.pop_back();
            if (visit_marks[block_index] == mark)
                continue;
            visit_marks[block_index] = mark;
            const auto& block = result.blocks[block_index];
            if (block.start.value < selection.start ||
                (selection.end && block.end.value > *selection.end))
                continue;
            const auto barrier = seeded_blocks.find(block_index);
            if (barrier != seeded_blocks.end() &&
                block.start.value != selection.start)
                continue;
            if (unclaimed_only && claim_counts[block_index] != 0)
                continue;
            if (reached.size() >= limits.max_blocks_per_function ||
                total_memberships >= limits.max_function_memberships) {
                return workspace_result_t<std::vector<std::size_t>>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                        "function reachability exceeds analysis budget", "functions"));
            }
            reached.push_back(block_index);
            ++total_memberships;
            for (auto iterator = successors[block_index].rbegin();
                 iterator != successors[block_index].rend(); ++iterator) {
                if (visit_marks[*iterator] != mark)
                    pending.push_back(*iterator);
            }
        }
        std::sort(reached.begin(), reached.end());
        return workspace_result_t<std::vector<std::size_t>>::success(std::move(reached));
    };
    std::vector<function_candidate_t> candidates;
    candidates.reserve(canonical.size());
    for (const auto& selection : canonical) {
        auto reached = traverse(selection, false);
        if (!reached)
            return workspace_result_t<function_recovery_result_t>::failure(reached.error());
        if (reached.value().empty()) {
            function_recovery_conflict_t conflict;
            conflict.kind = function_recovery_conflict_kind_t::seed_without_block;
            conflict.rva = selection.start;
            conflict.competing_seed_kind = selection.seed.kind;
            conflict.competing_source_id = selection.seed.stable_source_id;
            auto appended = append_conflict(result, std::move(conflict), limits);
            if (!appended)
                return workspace_result_t<function_recovery_result_t>::failure(
                    appended.error());
            continue;
        }
        function_candidate_t candidate;
        candidate.selection = selection;
        candidate.blocks = reached.take_value();
        for (const auto block : candidate.blocks)
            ++claim_counts[block];
        candidates.push_back(std::move(candidate));
    }
    for (std::size_t block_index = 0; block_index < result.blocks.size(); ++block_index) {
        if (claim_counts[block_index] != 0)
            continue;
        if (candidates.size() >= limits.max_functions) {
            return workspace_result_t<function_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "gap function recovery exceeds analysis budget", "functions"));
        }
        selected_seed_t gap;
        gap.start = result.blocks[block_index].start.value;
        gap.seed.address = result.blocks[block_index].start;
        gap.seed.kind = function_seed_kind_t::validated_gap_target;
        gap.seed.provenance = fact_provenance_t::gap_recovery;
        gap.seed.confidence = result.blocks[block_index].confidence;
        gap.seed.stable_source_id = result.blocks[block_index].id ^ gap.start;
        auto reached = traverse(gap, true);
        if (!reached)
            return workspace_result_t<function_recovery_result_t>::failure(reached.error());
        if (reached.value().empty())
            continue;
        function_candidate_t candidate;
        candidate.selection = gap;
        candidate.blocks = reached.take_value();
        candidate.synthetic_gap = true;
        for (const auto block : candidate.blocks)
            ++claim_counts[block];
        function_recovery_conflict_t conflict;
        conflict.kind = function_recovery_conflict_kind_t::gap_component_seeded;
        conflict.rva = gap.start;
        conflict.selected_seed_kind = gap.seed.kind;
        conflict.selected_source_id = gap.seed.stable_source_id;
        auto appended = append_conflict(result, std::move(conflict), limits);
        if (!appended)
            return workspace_result_t<function_recovery_result_t>::failure(
                appended.error());
        ++result.synthetic_gap_functions;
        candidates.push_back(std::move(candidate));
    }
    std::sort(candidates.begin(), candidates.end(), candidate_less);
    for (std::size_t index = 0; index < candidates.size(); ++index)
        candidates[index].function_id =
            kFunctionEntityTag | static_cast<std::uint64_t>(index + 1);
    const auto no_owner = (std::numeric_limits<std::size_t>::max)();
    std::vector<std::size_t> owners(result.blocks.size(), no_owner);
    for (std::size_t candidate_index = 0;
         candidate_index < candidates.size(); ++candidate_index) {
        for (const auto block_index : candidates[candidate_index].blocks) {
            if (owners[block_index] == no_owner ||
                candidate_preferred(candidates[candidate_index],
                                    candidates[owners[block_index]])) {
                owners[block_index] = candidate_index;
            }
        }
    }
    for (std::size_t block_index = 0; block_index < result.blocks.size(); ++block_index) {
        if (owners[block_index] == no_owner) {
            return workspace_result_t<function_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "decoded block has no recovered function owner", "functions"));
        }
        result.blocks[block_index].function_id =
            candidates[owners[block_index]].function_id;
    }
    for (std::size_t candidate_index = 0;
         candidate_index < candidates.size(); ++candidate_index) {
        for (const auto block_index : candidates[candidate_index].blocks) {
            if (owners[block_index] == candidate_index)
                continue;
            function_recovery_conflict_t conflict;
            conflict.kind =
                function_recovery_conflict_kind_t::competing_block_ownership;
            conflict.rva = result.blocks[block_index].start.value;
            conflict.related_rva = result.blocks[block_index].end.value;
            conflict.selected_seed_kind =
                candidates[owners[block_index]].selection.seed.kind;
            conflict.competing_seed_kind =
                candidates[candidate_index].selection.seed.kind;
            conflict.selected_source_id =
                candidates[owners[block_index]].selection.seed.stable_source_id;
            conflict.competing_source_id =
                candidates[candidate_index].selection.seed.stable_source_id;
            conflict.selected_function_id =
                candidates[owners[block_index]].function_id;
            conflict.competing_function_id =
                candidates[candidate_index].function_id;
            auto appended = append_conflict(result, std::move(conflict), limits);
            if (!appended)
                return workspace_result_t<function_recovery_result_t>::failure(
                    appended.error());
        }
    }
    struct chunk_run_t {
        std::size_t first_member = 0;
        std::size_t member_count = 0;
        bool shared = false;
    };
    for (std::size_t candidate_index = 0;
         candidate_index < candidates.size(); ++candidate_index) {
        auto& candidate = candidates[candidate_index];
        if (candidate.blocks.empty())
            continue;
        std::vector<chunk_run_t> runs;
        std::size_t run_begin = 0;
        while (run_begin < candidate.blocks.size()) {
            const bool shared = owners[candidate.blocks[run_begin]] != candidate_index;
            std::size_t run_end = run_begin + 1;
            while (run_end < candidate.blocks.size()) {
                const auto previous = candidate.blocks[run_end - 1];
                const auto current = candidate.blocks[run_end];
                if (current != previous + 1 ||
                    result.blocks[previous].end != result.blocks[current].start ||
                    (owners[current] != candidate_index) != shared)
                    break;
                ++run_end;
            }
            runs.push_back({run_begin, run_end - run_begin, shared});
            run_begin = run_end;
        }
        const auto entry_block = block_by_start.find(candidate.selection.start);
        if (entry_block == block_by_start.end()) {
            return workspace_result_t<function_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "function entry block disappeared during recovery", "functions"));
        }
        const auto primary = std::find_if(runs.begin(), runs.end(),
            [&](const chunk_run_t& run) {
                for (std::size_t offset = 0; offset < run.member_count; ++offset) {
                    if (candidate.blocks[run.first_member + offset] ==
                        entry_block->second)
                        return true;
                }
                return false;
            });
        if (primary == runs.end() || primary->shared) {
            return workspace_result_t<function_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "function entry has no deterministic primary ownership", "functions"));
        }
        if (primary != runs.begin())
            std::rotate(runs.begin(), primary, primary + 1);
        function_record_t function;
        function.id = candidate.function_id;
        function.start = rva_address(image, candidate.selection.start);
        function.provenance = candidate.selection.seed.provenance;
        function.confidence = candidate.selection.seed.confidence;
        function.noreturn = candidate.selection.seed.noreturn ||
            known_noreturn_name(candidate.selection.seed.name);
        function.thunk = compact_thunk(candidate, result.blocks,
            result.terminator_instruction_indices, instructions);
        function.first_chunk =
            static_cast<std::uint32_t>(result.function_chunks.size());
        function.first_block_membership = static_cast<std::uint32_t>(
            result.function_block_memberships.size());
        std::uint64_t range_bytes = 0;
        std::uint64_t range_peak = 0;
        if (!checked_mul_u64(runs.size(), sizeof(address_range_t), range_bytes) ||
            !checked_add_u64(result.storage_bytes, range_bytes, range_peak) ||
            range_peak > limits.max_result_bytes) {
            return workspace_result_t<function_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "function range storage exceeds analysis budget", "functions"));
        }
        result.storage_bytes = range_peak;
        function.chunks.reserve(runs.size());
        std::uint32_t membership_ordinal = 0;
        std::uint64_t maximum_end = function.start.value;
        for (std::size_t run_index = 0; run_index < runs.size(); ++run_index) {
            const auto& run = runs[run_index];
            const auto first_block = candidate.blocks[run.first_member];
            const auto last_block =
                candidate.blocks[run.first_member + run.member_count - 1];
            function_chunk_record_t chunk;
            chunk.id = kFunctionChunkEntityTag |
                static_cast<std::uint64_t>(result.function_chunks.size() + 1);
            chunk.function_id = function.id;
            chunk.start = result.blocks[first_block].start;
            chunk.end = result.blocks[last_block].end;
            chunk.first_block = static_cast<std::uint32_t>(first_block);
            chunk.block_count = static_cast<std::uint32_t>(run.member_count);
            chunk.provenance = function.provenance;
            chunk.confidence = function.confidence;
            chunk.cold = run_index != 0 && !run.shared;
            chunk.shared = run.shared;
            const auto chunk_id = chunk.id;
            auto appended_chunk = append_bounded(result.function_chunks,
                std::move(chunk), limits.max_function_memberships,
                limits.max_result_bytes, result.storage_bytes, "functions",
                "function chunk storage exceeds analysis budget");
            if (!appended_chunk)
                return workspace_result_t<function_recovery_result_t>::failure(
                    appended_chunk.error());
            address_range_t range;
            range.rva_start = result.blocks[first_block].start.value;
            range.rva_end = result.blocks[last_block].end.value;
            range.chunk_kind = static_cast<std::uint8_t>(
                (run.shared ? function_chunk_shared : function_chunk_none) |
                ((run_index != 0 && !run.shared) ? function_chunk_cold
                                                  : function_chunk_none));
            function.chunks.push_back(range);
            if (run_index == 0) {
                function.first_block = static_cast<std::uint32_t>(first_block);
                function.block_count = static_cast<std::uint32_t>(run.member_count);
            }
            maximum_end = std::max(maximum_end, range.rva_end);
            for (std::size_t offset = 0; offset < run.member_count; ++offset) {
                const auto block_index = candidate.blocks[run.first_member + offset];
                function_block_membership_record_t membership;
                membership.function_id = function.id;
                membership.chunk_id = chunk_id;
                membership.block_id = result.blocks[block_index].id;
                membership.block_index = static_cast<std::uint32_t>(block_index);
                membership.ordinal = membership_ordinal++;
                membership.shared = owners[block_index] != candidate_index;
                auto appended_membership = append_bounded(
                    result.function_block_memberships, std::move(membership),
                    limits.max_function_memberships, limits.max_result_bytes,
                    result.storage_bytes, "functions",
                    "function membership storage exceeds analysis budget");
                if (!appended_membership) {
                    return workspace_result_t<function_recovery_result_t>::failure(
                        appended_membership.error());
                }
            }
        }
        function.end = rva_address(image, maximum_end);
        function.chunk_count = static_cast<std::uint32_t>(
            result.function_chunks.size() - function.first_chunk);
        function.block_membership_count = static_cast<std::uint32_t>(
            result.function_block_memberships.size() -
            function.first_block_membership);
        auto appended_function = append_bounded(result.functions,
            std::move(function), limits.max_functions, limits.max_result_bytes,
            result.storage_bytes, "functions",
            "function storage exceeds analysis budget");
        if (!appended_function)
            return workspace_result_t<function_recovery_result_t>::failure(
                appended_function.error());
    }
    std::sort(result.conflicts.begin(), result.conflicts.end(), conflict_less);
    result.conflicts.erase(std::unique(result.conflicts.begin(),
        result.conflicts.end(), conflict_equal), result.conflicts.end());
    return workspace_result_t<function_recovery_result_t>::success(std::move(result));
}

workspace_result_t<function_recovery_result_t> function_recovery_t::finalize_cfg_calls(
    const workspace_image_t& image,
    const byte_provider_t&,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<operand_fact_t>&,
    const std::vector<target_fact_t>& targets,
    function_recovery_result_t result,
    const function_recovery_limits_t& limits,
    const cancellation_token_t& cancel)
{
    if (!valid_limits(limits)) {
        return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "function recovery limits are invalid", "cfg_calls"));
    }
    std::map<std::uint64_t, const function_record_t*> functions_by_start;
    std::map<std::uint64_t, const basic_block_record_t*> blocks_by_start;
    std::map<std::uint64_t, const image_import_t*> imports_by_slot;
    std::map<entity_id_t, std::size_t> block_indices;
    for (const auto& function : result.functions)
        functions_by_start.emplace(function.start.value, &function);
    for (std::size_t index = 0; index < result.blocks.size(); ++index) {
        blocks_by_start.emplace(result.blocks[index].start.value, &result.blocks[index]);
        block_indices.emplace(result.blocks[index].id, index);
    }
    for (const auto& imported : image.imports) {
        const auto slot = to_rva(image, imported.address);
        if (slot)
            imports_by_slot.emplace(*slot, &imported);
    }
    std::vector<std::uint8_t> noreturn_sources(result.blocks.size(), 0);
    for (auto& edge : result.edges) {
        if (cancel.stop_requested())
            return workspace_result_t<function_recovery_result_t>::failure(
                stop_error(cancel, "cfg_calls"));
        const auto target = to_rva(image, edge.target);
        if (!target)
            continue;
        const auto function = functions_by_start.find(*target);
        const auto source = block_indices.find(edge.source_entity);
        if (edge.kind == edge_kind_t::unconditional &&
            function != functions_by_start.end() &&
            source != block_indices.end() &&
            result.blocks[source->second].function_id != function->second->id) {
            edge.kind = edge_kind_t::tail_call;
            edge.target_entity = function->second->id;
        } else if ((edge.kind == edge_kind_t::call ||
                    edge.kind == edge_kind_t::tail_call) &&
                   function != functions_by_start.end()) {
            edge.target_entity = function->second->id;
        } else {
            const auto block = blocks_by_start.find(*target);
            if (block != blocks_by_start.end())
                edge.target_entity = block->second->id;
        }
        if (source != block_indices.end() && edge.target_entity &&
            ((*edge.target_entity & 0xFF00000000000000ULL) ==
             kFunctionEntityTag)) {
            const auto ordinal =
                *edge.target_entity & 0x00FFFFFFFFFFFFFFULL;
            if (ordinal != 0 && ordinal <= result.functions.size() &&
                result.functions[static_cast<std::size_t>(ordinal - 1)].noreturn)
                noreturn_sources[source->second] = 1;
        }
    }
    for (std::size_t index = 0; index < result.blocks.size(); ++index) {
        if (cancel.stop_requested())
            return workspace_result_t<function_recovery_result_t>::failure(
                stop_error(cancel, "cfg_calls"));
        const auto* call = transfer_instruction(index, result.blocks,
            result.terminator_instruction_indices, instructions);
        if (!call || (call->flow_flags & flow_call) == 0)
            continue;
        std::uint64_t target_end = 0;
        if (!checked_add_u64(call->target_fact_begin,
                call->target_fact_count, target_end) || target_end > targets.size()) {
            return workspace_result_t<function_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "call target-fact range is invalid", "cfg_calls"));
        }
        for (std::uint64_t target_index = call->target_fact_begin;
             target_index < target_end; ++target_index) {
            const auto& target = targets[static_cast<std::size_t>(target_index)];
            if (target.kind != target_kind_record_t::data &&
                target.kind != target_kind_record_t::call)
                continue;
            const auto slot = to_rva(image, target.target);
            const auto imported = slot ? imports_by_slot.find(*slot)
                                       : imports_by_slot.end();
            if (imported == imports_by_slot.end())
                continue;
            edge_record_t edge;
            edge.source_entity = result.blocks[index].id;
            edge.source = call->address;
            edge.target = target.target;
            edge.kind = edge_kind_t::call;
            edge.provenance = fact_provenance_t::relocation;
            edge.confidence = std::min<std::uint8_t>(call->confidence, 95);
            auto appended = append_bounded(result.edges, std::move(edge),
                limits.max_edges, limits.max_result_bytes, result.storage_bytes,
                "cfg_calls", "import call edge storage exceeds analysis budget");
            if (!appended)
                return workspace_result_t<function_recovery_result_t>::failure(
                    appended.error());
            if (imported->second->name &&
                known_noreturn_name(*imported->second->name))
                noreturn_sources[index] = 1;
            break;
        }
    }
    std::size_t output = 0;
    for (std::size_t index = 0; index < result.edges.size(); ++index) {
        if (cancel.stop_requested())
            return workspace_result_t<function_recovery_result_t>::failure(
                stop_error(cancel, "cfg_calls"));
        const auto source = block_indices.find(result.edges[index].source_entity);
        const bool remove = result.edges[index].kind == edge_kind_t::fallthrough &&
            source != block_indices.end() &&
            noreturn_sources[source->second] != 0;
        if (!remove) {
            if (output != index)
                result.edges[output] = std::move(result.edges[index]);
            ++output;
        }
    }
    result.edges.resize(output);
    std::sort(result.edges.begin(), result.edges.end(), edge_less);
    result.edges.erase(std::unique(result.edges.begin(), result.edges.end(),
                                   edge_equal), result.edges.end());
    for (std::size_t index = 0; index < result.edges.size(); ++index)
        result.edges[index].id =
            kEdgeEntityTag | static_cast<std::uint64_t>(index + 1);
    return workspace_result_t<function_recovery_result_t>::success(std::move(result));
}

}
