#include "function_recovery.hpp"

#include "checked_range.hpp"
#include "parallel_pass.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <stdexcept>
#include <string_view>
#include <thread>
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

std::optional<std::uint64_t> executable_region_end(
    const workspace_image_t& image, std::uint64_t rva) noexcept
{
    std::optional<std::uint64_t> result;
    const auto consider = [&](const auto& region) noexcept {
        if ((region.permissions & image_permission_execute) == 0)
            return;
        const auto extent = region.virtual_size == 0
            ? region.file_size
            : std::min(region.virtual_size, region.file_size);
        std::uint64_t end = 0;
        if (extent == 0 || !checked_add_u64(region.virtual_address, extent, end) ||
            end > image.image_size || rva < region.virtual_address || rva >= end)
            return;
        if (!result || end < *result)
            result = end;
    };
    if (!image.sections.empty()) {
        for (const auto& section : image.sections)
            consider(section);
    } else {
        for (const auto& segment : image.segments)
            consider(segment);
    }
    return result;
}

bool authoritative_loader_seed(function_seed_kind_t kind) noexcept
{
    return kind == function_seed_kind_t::image_entry ||
        kind == function_seed_kind_t::export_entry ||
        kind == function_seed_kind_t::unwind_range ||
        kind == function_seed_kind_t::debug_symbol ||
        kind == function_seed_kind_t::load_config_entry;
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
    bool loader_only = false;
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

constexpr std::uint32_t kCancellationStride = 256;
constexpr std::size_t kIndexShardFloor = 65536;
constexpr std::size_t kSeedShardFloor = 4096;

std::size_t pass_shard_count(std::size_t items, std::size_t floor) noexcept {
    if (items == 0 || floor == 0)
        return 0;
    const unsigned hardware = std::thread::hardware_concurrency();
    const std::size_t maximum = (std::max)(std::size_t{1},
        static_cast<std::size_t>(hardware == 0 ? 1u : 4u * hardware));
    const std::size_t wanted = (items + floor - 1) / floor;
    return (std::max)(std::size_t{1}, (std::min)(wanted, maximum));
}

struct shard_range_t {
    std::size_t begin = 0;
    std::size_t end = 0;
};

std::vector<shard_range_t> partition_shards(std::size_t items, std::size_t count) {
    std::vector<shard_range_t> shards;
    shards.reserve(count);
    const std::size_t base = count == 0 ? 0 : items / count;
    const std::size_t extra = count == 0 ? 0 : items % count;
    std::size_t cursor = 0;
    for (std::size_t index = 0; index < count; ++index) {
        const std::size_t size = base + (index < extra ? 1 : 0);
        shards.push_back({cursor, cursor + size});
        cursor += size;
    }
    return shards;
}

struct shard_failure_t {
    std::atomic<bool> failed{false};
    std::mutex mutex;
    std::size_t lowest_shard = (std::numeric_limits<std::size_t>::max)();
    workspace_error_t error{};

    void report(std::size_t shard, workspace_error_t value) {
        failed.store(true, std::memory_order_release);
        std::lock_guard<std::mutex> lock(mutex);
        if (shard < lowest_shard) {
            lowest_shard = shard;
            error = std::move(value);
        }
    }

    workspace_error_t take_error() {
        std::lock_guard<std::mutex> lock(mutex);
        return std::move(error);
    }
};

struct shard_poll_t {
    const cancellation_token_t* cancel = nullptr;
    shard_failure_t* failure = nullptr;
    std::size_t shard = 0;
    const char* phase = nullptr;

    bool stopped(std::size_t iteration) const {
        if ((iteration & (kCancellationStride - 1)) != 0)
            return false;
        if (failure->failed.load(std::memory_order_relaxed))
            return true;
        if (cancel->stop_requested()) {
            failure->report(shard, stop_error(*cancel, phase));
            return true;
        }
        return false;
    }
};

template <typename Fn>
void guarded_shard(shard_failure_t& failure, std::size_t shard,
                   const char* alloc_message, const char* phase, Fn&& fn) {
    try {
        fn();
    } catch (const std::bad_alloc&) {
        failure.report(shard, make_workspace_error(
            workspace_error_code_t::limit_exceeded, alloc_message, phase));
    } catch (const std::length_error&) {
        failure.report(shard, make_workspace_error(
            workspace_error_code_t::limit_exceeded, alloc_message, phase));
    }
}

template <typename Fn>
void guarded_shard_dual(shard_failure_t& failure, std::size_t shard,
                        const char* alloc_message, const char* length_message,
                        const char* phase, Fn&& fn) {
    try {
        fn();
    } catch (const std::bad_alloc&) {
        failure.report(shard, make_workspace_error(
            workspace_error_code_t::limit_exceeded, alloc_message, phase));
    } catch (const std::length_error&) {
        failure.report(shard, make_workspace_error(
            workspace_error_code_t::limit_exceeded, length_message, phase));
    }
}

template <typename Fn>
void run_sharded(std::size_t shard_total, Fn&& shard_fn) {
    parallel_executor_t::run(shard_total, parallel_worker_count(),
        "analysis.function_recovery", std::forward<Fn>(shard_fn));
}

template <typename Local, typename Fn>
void run_sharded_local(std::size_t shard_total, Fn&& shard_fn) {
    parallel_executor_t::run_local<Local>(shard_total, parallel_worker_count(),
        "analysis.function_recovery", std::forward<Fn>(shard_fn));
}

template <typename T, typename Equal>
void parallel_unique_erase(std::vector<T>& values, Equal&& equal) {
    if (values.size() < 2)
        return;
    const std::size_t count = values.size();
    const auto shards = partition_shards(count,
        pass_shard_count(count, kIndexShardFloor));
    std::vector<std::uint8_t> keep(count, 0);
    std::vector<std::uint64_t> shard_keeps(shards.size(), 0);
    run_sharded(shards.size(), [&](std::size_t shard) {
        const auto range = shards[shard];
        std::uint64_t kept = 0;
        for (std::size_t index = range.begin; index < range.end; ++index) {
            const auto flagged = index == 0 || !equal(values[index - 1], values[index]);
            keep[index] = flagged ? static_cast<std::uint8_t>(1)
                                  : static_cast<std::uint8_t>(0);
            kept += flagged ? 1ULL : 0ULL;
        }
        shard_keeps[shard] = kept;
    });
    std::uint64_t total = 0;
    for (auto& base : shard_keeps) {
        const auto offset = total;
        total += base;
        base = offset;
    }
    std::vector<T> compacted(static_cast<std::size_t>(total));
    run_sharded(shards.size(), [&](std::size_t shard) {
        const auto range = shards[shard];
        auto cursor = shard_keeps[shard];
        for (std::size_t index = range.begin; index < range.end; ++index) {
            if (keep[index] != 0)
                compacted[static_cast<std::size_t>(cursor++)] = std::move(values[index]);
        }
    });
    values = std::move(compacted);
}

struct pass_budget_t {
    std::atomic<std::uint64_t> committed{0};
    std::uint64_t ceiling = 0;

    bool try_grant(std::uint64_t bytes) noexcept {
        std::uint64_t observed = committed.load(std::memory_order_relaxed);
        for (;;) {
            if (observed > ceiling || bytes > ceiling - observed)
                return false;
            if (committed.compare_exchange_weak(observed, observed + bytes,
                    std::memory_order_relaxed))
                return true;
        }
    }
};

workspace_result_t<void> account_bytes(std::uint64_t& storage_bytes, std::uint64_t bytes,
    std::uint64_t maximum_bytes, const char* phase, const char* message) {
    std::uint64_t peak = 0;
    if (!checked_add_u64(storage_bytes, bytes, peak)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow, message, phase));
    }
    if (peak > maximum_bytes) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded, message, phase));
    }
    storage_bytes = peak;
    return workspace_result_t<void>::success();
}

template <typename T>
struct shard_vector_t {
    std::vector<T> values;

    workspace_result_t<void> reserve_grant(std::size_t count, pass_budget_t& budget,
        const char* phase, const char* message) {
        if (count <= values.capacity())
            return workspace_result_t<void>::success();
        std::uint64_t bytes = 0;
        if (!checked_mul_u64(static_cast<std::uint64_t>(count), sizeof(T), bytes) ||
            !budget.try_grant(bytes)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded, message, phase));
        }
        values.reserve(count);
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> append(T value, std::uint64_t maximum_count,
        pass_budget_t& budget, const char* phase, const char* message) {
        if (values.size() >= maximum_count) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded, message, phase));
        }
        if (values.size() == values.capacity()) {
            const auto current = static_cast<std::uint64_t>(values.capacity());
            std::uint64_t desired = current == 0
                ? (std::min<std::uint64_t>)(4096, maximum_count) : 0;
            if (current != 0 && !checked_add_u64(current, current / 2ULL, desired)) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow, message, phase));
            }
            std::uint64_t minimum = 0;
            if (!checked_add_u64(current, 1, minimum)) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow, message, phase));
            }
            desired = (std::min)((std::max)(desired, minimum), maximum_count);
            if (desired <= current) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded, message, phase));
            }
            std::uint64_t delta = 0;
            if (!checked_mul_u64(desired - current, sizeof(T), delta) ||
                !budget.try_grant(delta)) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded, message, phase));
            }
            values.reserve(static_cast<std::size_t>(desired));
        }
        values.push_back(std::move(value));
        return workspace_result_t<void>::success();
    }
};

struct merge_clock_t {
    std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();

    std::uint64_t elapsed_ns() const {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<
            std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - started).count());
    }
};

std::optional<std::size_t> instruction_index_by_rva(
    const std::vector<instruction_record_t>& instructions, std::uint64_t rva) noexcept {
    const auto found = std::lower_bound(instructions.begin(), instructions.end(), rva,
        [](const instruction_record_t& instruction, std::uint64_t value) {
            return instruction.address.value < value;
        });
    if (found != instructions.end() && found->address.value == rva)
        return static_cast<std::size_t>(found - instructions.begin());
    return std::nullopt;
}

std::optional<std::size_t> block_index_by_start(
    const std::vector<basic_block_record_t>& blocks, std::uint64_t rva) noexcept {
    const auto found = std::lower_bound(blocks.begin(), blocks.end(), rva,
        [](const basic_block_record_t& block, std::uint64_t value) {
            return block.start.value < value;
        });
    if (found != blocks.end() && found->start.value == rva)
        return static_cast<std::size_t>(found - blocks.begin());
    return std::nullopt;
}

template <typename Record>
struct start_rva_lookup_t {
    const std::vector<Record>* records = nullptr;
    std::vector<std::pair<std::uint64_t, std::uint32_t>> fallback;

    std::optional<std::size_t> find(std::uint64_t rva) const noexcept {
        if (records != nullptr) {
            const auto found = std::lower_bound(records->begin(), records->end(), rva,
                [](const Record& record, std::uint64_t value) {
                    return record.start.value < value;
                });
            if (found != records->end() && found->start.value == rva)
                return static_cast<std::size_t>(found - records->begin());
            return std::nullopt;
        }
        const auto found = std::lower_bound(fallback.begin(), fallback.end(), rva,
            [](const std::pair<std::uint64_t, std::uint32_t>& entry, std::uint64_t value) {
                return entry.first < value;
            });
        if (found != fallback.end() && found->first == rva)
            return static_cast<std::size_t>(found->second);
        return std::nullopt;
    }
};

template <typename Record>
start_rva_lookup_t<Record> make_start_rva_lookup(const std::vector<Record>& records) {
    start_rva_lookup_t<Record> lookup;
    bool sorted = true;
    for (std::size_t index = 1; index < records.size(); ++index) {
        if (!(records[index - 1].start.value < records[index].start.value)) {
            sorted = false;
            break;
        }
    }
    if (sorted) {
        lookup.records = &records;
        return lookup;
    }
    lookup.fallback.reserve(records.size());
    for (std::size_t index = 0; index < records.size(); ++index)
        lookup.fallback.emplace_back(records[index].start.value,
            static_cast<std::uint32_t>(index));
    std::stable_sort(lookup.fallback.begin(), lookup.fallback.end(),
        [](const std::pair<std::uint64_t, std::uint32_t>& lhs,
           const std::pair<std::uint64_t, std::uint32_t>& rhs) {
            return lhs.first < rhs.first;
        });
    return lookup;
}

struct block_id_index_t {
    std::size_t count = 0;
    bool identity = false;
    std::vector<std::uint32_t> ordinal_plus_one;
    std::vector<std::pair<std::uint64_t, std::uint32_t>> sorted_entries;

    std::optional<std::size_t> find(entity_id_t id) const noexcept {
        if (identity) {
            if ((id & 0xFF00000000000000ULL) != kBlockEntityTag)
                return std::nullopt;
            const auto ordinal = id & entity_ordinal_mask;
            if (ordinal == 0 || ordinal > count)
                return std::nullopt;
            return static_cast<std::size_t>(ordinal - 1);
        }
        if (!ordinal_plus_one.empty()) {
            if ((id & 0xFF00000000000000ULL) != kBlockEntityTag)
                return std::nullopt;
            const auto ordinal = id & entity_ordinal_mask;
            if (ordinal == 0 || ordinal > ordinal_plus_one.size())
                return std::nullopt;
            const auto slot = ordinal_plus_one[static_cast<std::size_t>(ordinal - 1)];
            if (slot == 0)
                return std::nullopt;
            return static_cast<std::size_t>(slot - 1);
        }
        const auto found = std::lower_bound(sorted_entries.begin(), sorted_entries.end(), id,
            [](const std::pair<std::uint64_t, std::uint32_t>& entry, std::uint64_t value) {
                return entry.first < value;
            });
        if (found != sorted_entries.end() && found->first == id)
            return static_cast<std::size_t>(found->second);
        return std::nullopt;
    }
};

block_id_index_t build_block_id_index(const std::vector<basic_block_record_t>& blocks,
                                      const cancellation_token_t& cancel) {
    block_id_index_t index;
    index.count = blocks.size();
    if (blocks.empty()) {
        index.identity = true;
        return index;
    }
    const auto shards = partition_shards(blocks.size(),
        pass_shard_count(blocks.size(), kIndexShardFloor));
    std::vector<std::uint8_t> shard_identity(shards.size(), 1);
    std::vector<std::uint8_t> shard_tag_dense(shards.size(), 1);
    run_sharded(shards.size(), [&](std::size_t shard) {
        const auto range = shards[shard];
        bool identity = true;
        bool tag_dense = true;
        for (std::size_t row = range.begin; row < range.end; ++row) {
            if (((row - range.begin) & (kCancellationStride - 1)) == 0 &&
                cancel.stop_requested()) {
                identity = false;
                tag_dense = false;
                break;
            }
            const auto id = blocks[row].id;
            const auto ordinal = id & entity_ordinal_mask;
            identity = identity && id == (kBlockEntityTag | (row + 1));
            tag_dense = tag_dense && (id & 0xFF00000000000000ULL) == kBlockEntityTag &&
                ordinal >= 1 && ordinal <= blocks.size();
        }
        shard_identity[shard] = identity ? 1 : 0;
        shard_tag_dense[shard] = tag_dense ? 1 : 0;
    });
    const auto all_identity = std::all_of(shard_identity.begin(), shard_identity.end(),
        [](std::uint8_t value) { return value != 0; });
    if (all_identity) {
        index.identity = true;
        return index;
    }
    const auto all_tag_dense = std::all_of(shard_tag_dense.begin(), shard_tag_dense.end(),
        [](std::uint8_t value) { return value != 0; });
    if (all_tag_dense) {
        std::vector<std::atomic<std::uint32_t>> slots(blocks.size());
        run_sharded(shards.size(), [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t row = range.begin; row < range.end; ++row)
                slots[row].store(0, std::memory_order_relaxed);
        });
        run_sharded(shards.size(), [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t row = range.begin; row < range.end; ++row) {
                const auto ordinal = blocks[row].id & entity_ordinal_mask;
                auto& slot = slots[static_cast<std::size_t>(ordinal - 1)];
                const auto desired = static_cast<std::uint32_t>(row + 1);
                std::uint32_t observed = slot.load(std::memory_order_relaxed);
                while (observed == 0 || desired < observed) {
                    if (slot.compare_exchange_weak(observed, desired,
                            std::memory_order_relaxed))
                        break;
                }
            }
        });
        index.ordinal_plus_one.resize(blocks.size());
        run_sharded(shards.size(), [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t row = range.begin; row < range.end; ++row)
                index.ordinal_plus_one[row] = slots[row].load(std::memory_order_relaxed);
        });
        return index;
    }
    index.sorted_entries.reserve(blocks.size());
    for (std::size_t row = 0; row < blocks.size(); ++row)
        index.sorted_entries.emplace_back(blocks[row].id, static_cast<std::uint32_t>(row));
    std::stable_sort(index.sorted_entries.begin(), index.sorted_entries.end(),
        [](const std::pair<std::uint64_t, std::uint32_t>& lhs,
           const std::pair<std::uint64_t, std::uint32_t>& rhs) {
            return lhs.first < rhs.first;
        });
    return index;
}

struct traverse_scratch_t {
    std::vector<std::uint8_t> marks;
    std::uint8_t generation = 0;
    std::vector<std::size_t> pending;
    std::vector<std::size_t> reached;
};

struct emit_run_t {
    std::uint32_t first_member = 0;
    std::uint32_t member_count = 0;
    std::uint32_t first_block = 0;
    std::uint32_t last_block = 0;
    bool shared = false;
    bool cold = false;
};

struct candidate_emit_t {
    function_record_t function;
    std::vector<emit_run_t> runs;
    std::uint64_t range_bytes = 0;
    std::uint64_t membership_total = 0;
    bool loader_record = false;
};

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
    parallel_sort(combined.begin(), combined.end(), seed_canonical_less);
    parallel_unique_erase(combined, seed_exact_equal);
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
        constexpr std::array<function_seed_kind_t, 10> group_kinds{{
            function_seed_kind_t::image_entry,
            function_seed_kind_t::tls_callback,
            function_seed_kind_t::debug_symbol,
            function_seed_kind_t::export_entry,
            function_seed_kind_t::unwind_range,
            function_seed_kind_t::load_config_entry,
            function_seed_kind_t::relocation_target,
            function_seed_kind_t::direct_call_target,
            function_seed_kind_t::pointer_target,
            function_seed_kind_t::validated_gap_target
        }};
        const auto group_index_of = [](function_seed_kind_t kind) noexcept {
            switch (kind) {
                case function_seed_kind_t::image_entry: return std::size_t{0};
                case function_seed_kind_t::tls_callback: return std::size_t{1};
                case function_seed_kind_t::debug_symbol: return std::size_t{2};
                case function_seed_kind_t::export_entry: return std::size_t{3};
                case function_seed_kind_t::unwind_range: return std::size_t{4};
                case function_seed_kind_t::load_config_entry: return std::size_t{5};
                case function_seed_kind_t::relocation_target: return std::size_t{6};
                case function_seed_kind_t::direct_call_target: return std::size_t{7};
                case function_seed_kind_t::pointer_target: return std::size_t{8};
                case function_seed_kind_t::validated_gap_target: return std::size_t{9};
            }
            return std::size_t{9};
        };
        const auto group_at = [](function_seed_sources_t& sources, std::size_t group)
            -> std::vector<function_seed_t>& {
            switch (group) {
                case 0: return sources.image_entries;
                case 1: return sources.tls_callbacks;
                case 2: return sources.symbols;
                case 3: return sources.exports;
                case 4: return sources.unwind_ranges;
                case 5: return sources.load_config_entries;
                case 6: return sources.relocation_targets;
                case 7: return sources.call_targets;
                case 8: return sources.pointer_targets;
                default: return sources.validated_gap_targets;
            }
        };
        std::array<std::uint64_t, 18> unit_sizes{};
        if (evidence.additional_sources) {
            unit_sizes[0] = evidence.additional_sources->image_entries.size();
            unit_sizes[1] = evidence.additional_sources->tls_callbacks.size();
            unit_sizes[2] = evidence.additional_sources->symbols.size();
            unit_sizes[3] = evidence.additional_sources->exports.size();
            unit_sizes[4] = evidence.additional_sources->unwind_ranges.size();
            unit_sizes[5] = evidence.additional_sources->load_config_entries.size();
            unit_sizes[6] = evidence.additional_sources->relocation_targets.size();
            unit_sizes[7] = evidence.additional_sources->call_targets.size();
            unit_sizes[8] = evidence.additional_sources->pointer_targets.size();
            unit_sizes[9] = evidence.additional_sources->validated_gap_targets.size();
        }
        unit_sizes[10] = image.entry_points.size();
        unit_sizes[11] = image.exports.size();
        unit_sizes[12] = image.symbols.size();
        unit_sizes[13] = evidence.symbols ? evidence.symbols->size() : 0;
        unit_sizes[14] = evidence.unwind_ranges ? evidence.unwind_ranges->size() : 0;
        unit_sizes[15] = targets.size();
        unit_sizes[16] = image.relocations.size();
        unit_sizes[17] = evidence.pointer_facts ? evidence.pointer_facts->size() : 0;
        std::uint64_t total_visits = 0;
        std::array<std::uint64_t, 18> unit_bases{};
        for (std::size_t unit = 0; unit < unit_sizes.size(); ++unit) {
            unit_bases[unit] = total_visits;
            total_visits += unit_sizes[unit];
        }
        const std::uint64_t effective_visits =
            (std::min)(total_visits, limits.max_seed_candidates);
        struct converge_range_t {
            std::uint32_t tag = 0;
            std::uint64_t begin = 0;
            std::uint64_t end = 0;
        };
        std::vector<converge_range_t> converge_ranges;
        for (std::size_t unit = 0; unit < unit_sizes.size(); ++unit) {
            if (unit_bases[unit] >= effective_visits)
                break;
            const auto clipped = static_cast<std::size_t>(
                (std::min)(unit_sizes[unit], effective_visits - unit_bases[unit]));
            if (clipped == 0)
                continue;
            const auto shard_total = pass_shard_count(clipped, kSeedShardFloor);
            const auto ranges = partition_shards(clipped, shard_total);
            for (const auto& range : ranges) {
                converge_ranges.push_back({static_cast<std::uint32_t>(unit),
                    static_cast<std::uint64_t>(range.begin),
                    static_cast<std::uint64_t>(range.end)});
            }
        }
        struct converge_shard_state_t {
            function_seed_sources_t sources;
            std::uint64_t storage_bytes = 0;
        };
        std::vector<converge_shard_state_t> states(converge_ranges.size());
        shard_failure_t failure;
        run_sharded(converge_ranges.size(), [&](std::size_t shard) {
            guarded_shard_dual(failure, shard,
                "function seed convergence exhausted memory",
                "function seed convergence exceeded container capacity",
                "seed_converge", [&]() {
                auto& state = states[shard];
                const auto& range = converge_ranges[shard];
                shard_poll_t poll{&cancel, &failure, shard, "seed_converge"};
                const auto append_seed = [&](function_seed_t seed,
                                             function_seed_kind_t kind,
                                             std::uint64_t source_discriminator) {
                    const auto rva = to_rva(image, seed.address);
                    if (!rva || !executable_rva(image, *rva))
                        return true;
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
                        failure.report(shard, make_workspace_error(
                            workspace_error_code_t::integrity_failure,
                            "function seed provenance or confidence is invalid",
                            "seed_converge"));
                        return false;
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
                    if (!checked_add_u64(sizeof(function_seed_t), seed.name.size(),
                            seed_bytes) ||
                        !checked_add_u64(state.storage_bytes, seed_bytes,
                            state.storage_bytes) ||
                        state.storage_bytes > limits.max_result_bytes) {
                        failure.report(shard, make_workspace_error(
                            workspace_error_code_t::limit_exceeded,
                            "converged function seed storage exceeds analysis budget",
                            "seed_converge"));
                        return false;
                    }
                    group_at(state.sources, group_index_of(kind)).push_back(std::move(seed));
                    return true;
                };
                const auto additional = evidence.additional_sources;
                for (std::uint64_t item = range.begin; item < range.end; ++item) {
                    if (poll.stopped(static_cast<std::size_t>(item - range.begin)))
                        return;
                    const auto row = static_cast<std::size_t>(item);
                    bool live = true;
                    switch (range.tag) {
                        case 0: case 1: case 2: case 3: case 4:
                        case 5: case 6: case 7: case 8: case 9: {
                            const std::vector<function_seed_t>* values = nullptr;
                            switch (range.tag) {
                                case 0: values = &additional->image_entries; break;
                                case 1: values = &additional->tls_callbacks; break;
                                case 2: values = &additional->symbols; break;
                                case 3: values = &additional->exports; break;
                                case 4: values = &additional->unwind_ranges; break;
                                case 5: values = &additional->load_config_entries; break;
                                case 6: values = &additional->relocation_targets; break;
                                case 7: values = &additional->call_targets; break;
                                case 8: values = &additional->pointer_targets; break;
                                default:
                                    values = &additional->validated_gap_targets;
                                    break;
                            }
                            live = append_seed((*values)[row], group_kinds[range.tag], 0);
                            break;
                        }
                        case 10: {
                            const auto& entry = image.entry_points[row];
                            const auto kind = entry_seed_kind(entry.provenance);
                            function_seed_t seed;
                            seed.address = entry.address;
                            seed.name = entry.provenance;
                            const auto source_discriminator = stable_mix(
                                stable_text(entry.provenance),
                                static_cast<std::uint64_t>(kind));
                            live = append_seed(std::move(seed), kind, source_discriminator);
                            break;
                        }
                        case 11: {
                            const auto& exported = image.exports[row];
                            if (exported.forwarder)
                                break;
                            function_seed_t seed;
                            seed.address = exported.address;
                            seed.name = exported.name.value_or(std::string{});
                            const auto source_discriminator = stable_mix(
                                exported.ordinal, stable_text(seed.name));
                            live = append_seed(std::move(seed),
                                function_seed_kind_t::export_entry, source_discriminator);
                            break;
                        }
                        case 12: {
                            const auto& symbol = image.symbols[row];
                            if (!symbol.defined ||
                                (symbol.kind != image_symbol_kind_t::function &&
                                 symbol.kind != image_symbol_kind_t::debug_symbol &&
                                 symbol.kind != image_symbol_kind_t::export_symbol))
                                break;
                            function_seed_t seed;
                            seed.address = symbol.address;
                            seed.name = symbol.name;
                            const auto kind = symbol.kind == image_symbol_kind_t::export_symbol
                                ? function_seed_kind_t::export_entry
                                : function_seed_kind_t::debug_symbol;
                            seed.confidence = symbol.kind == image_symbol_kind_t::function
                                ? 96 : 95;
                            const auto source_discriminator = stable_mix(
                                symbol.ordinal, stable_text(symbol.name));
                            live = append_seed(std::move(seed), kind, source_discriminator);
                            break;
                        }
                        case 13: {
                            const auto& symbol = (*evidence.symbols)[row];
                            if (symbol.kind != symbol_kind_t::function &&
                                symbol.kind != symbol_kind_t::debug_symbol &&
                                symbol.kind != symbol_kind_t::export_symbol)
                                break;
                            function_seed_t seed;
                            seed.address = symbol.address;
                            seed.name = symbol.name;
                            seed.provenance = symbol.provenance;
                            seed.confidence = symbol.confidence;
                            seed.stable_source_id = symbol.id;
                            const auto kind = symbol.kind == symbol_kind_t::export_symbol
                                ? function_seed_kind_t::export_entry
                                : function_seed_kind_t::debug_symbol;
                            live = append_seed(std::move(seed), kind,
                                stable_text(symbol.name));
                            break;
                        }
                        case 14: {
                            const auto& unwind = (*evidence.unwind_ranges)[row];
                            function_seed_t seed;
                            seed.address = rva_address(image, unwind.function_rva);
                            if (unwind.end_rva > unwind.function_rva)
                                seed.known_end = rva_address(image, unwind.end_rva);
                            const auto source_discriminator = stable_mix(
                                unwind.end_rva, unwind.unwind_info_rva);
                            live = append_seed(std::move(seed),
                                function_seed_kind_t::unwind_range, source_discriminator);
                            break;
                        }
                        case 15: {
                            const auto& target = targets[row];
                            if (target.kind != target_kind_record_t::call || !target.direct ||
                                target.is_external)
                                break;
                            function_seed_t seed;
                            seed.address = target.target;
                            const auto source_discriminator = stable_mix(
                                target.instruction_id,
                                stable_mix(target.operand_fact_id,
                                    target.address_expression_id));
                            live = append_seed(std::move(seed),
                                function_seed_kind_t::direct_call_target,
                                source_discriminator);
                            break;
                        }
                        case 16: {
                            const auto& relocation = image.relocations[row];
                            if (!relocation.target)
                                break;
                            function_seed_t seed;
                            seed.address = *relocation.target;
                            const auto slot_rva = to_rva(image, relocation.address);
                            const auto source_discriminator = stable_mix(
                                slot_rva.value_or(relocation.address.value),
                                relocation.type);
                            live = append_seed(std::move(seed),
                                function_seed_kind_t::relocation_target,
                                source_discriminator);
                            break;
                        }
                        default: {
                            const auto& pointer = (*evidence.pointer_facts)[row];
                            function_seed_t seed;
                            seed.address = pointer.target;
                            seed.provenance = pointer.provenance;
                            seed.confidence = pointer.confidence;
                            seed.stable_source_id = pointer.id;
                            const auto slot_rva = to_rva(image, pointer.slot);
                            live = append_seed(std::move(seed),
                                function_seed_kind_t::pointer_target,
                                slot_rva.value_or(pointer.slot.value));
                            break;
                        }
                    }
                    if (!live)
                        return;
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed)) {
            return workspace_result_t<std::vector<function_seed_t>>::failure(
                failure.take_error());
        }
        function_seed_sources_t sources;
        for (std::size_t group = 0; group < group_kinds.size(); ++group) {
            std::uint64_t total = 0;
            for (auto& state : states)
                total += group_at(state.sources, group).size();
            auto& destination = group_at(sources, group);
            destination.reserve(static_cast<std::size_t>(total));
            for (auto& state : states) {
                auto& values = group_at(state.sources, group);
                for (auto& seed : values)
                    destination.push_back(std::move(seed));
            }
        }
        std::uint64_t seed_storage_bytes = 0;
        for (const auto& state : states) {
            if (!checked_add_u64(seed_storage_bytes, state.storage_bytes,
                    seed_storage_bytes) ||
                seed_storage_bytes > limits.max_result_bytes) {
                return workspace_result_t<std::vector<function_seed_t>>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                        "converged function seed storage exceeds analysis budget",
                        "seed_converge"));
            }
        }
        if (total_visits > limits.max_seed_candidates) {
            return workspace_result_t<std::vector<function_seed_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "function seed evidence exceeds analysis budget", "seed_converge"));
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
    std::vector<std::uint8_t> leaders(instructions.size(), 0);
    leaders.front() = 1;
    shard_failure_t failure;
    {
        const auto shards = partition_shards(seeds.size(),
            pass_shard_count(seeds.size(), kSeedShardFloor));
        run_sharded(shards.size(), [&](std::size_t shard) {
            guarded_shard(failure, shard, "basic block storage exceeds analysis budget",
                "blocks", [&]() {
                const auto range = shards[shard];
                shard_poll_t poll{&cancel, &failure, shard, "blocks"};
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (poll.stopped(index - range.begin))
                        return;
                    const auto& seed = seeds[index];
                    const auto rva = to_rva(image, seed.address);
                    const auto found = rva ? instruction_index_by_rva(instructions, *rva)
                                           : std::nullopt;
                    if (found)
                        leaders[*found] = 1;
                    if (seed.known_end) {
                        const auto end_rva = to_rva_endpoint(image, *seed.known_end);
                        const auto end_found = end_rva
                            ? instruction_index_by_rva(instructions, *end_rva)
                            : std::nullopt;
                        if (end_found)
                            leaders[*end_found] = 1;
                    }
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<block_recovery_result_t>::failure(
                failure.take_error());
    }
    {
        const auto shards = partition_shards(instructions.size(),
            pass_shard_count(instructions.size(), kIndexShardFloor));
        run_sharded(shards.size(), [&](std::size_t shard) {
            guarded_shard(failure, shard, "basic block storage exceeds analysis budget",
                "blocks", [&]() {
                const auto range = shards[shard];
                shard_poll_t poll{&cancel, &failure, shard, "blocks"};
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (poll.stopped(index - range.begin))
                        return;
                    const auto& instruction = instructions[index];
                    const auto target_end =
                        static_cast<std::uint64_t>(instruction.target_fact_begin) +
                        instruction.target_fact_count;
                    for (std::uint64_t target_index = instruction.target_fact_begin;
                         target_index < target_end; ++target_index) {
                        const auto& target = targets[static_cast<std::size_t>(target_index)];
                        if (target.kind != target_kind_record_t::branch &&
                            target.kind != target_kind_record_t::call)
                            continue;
                        const auto rva = to_rva(image, target.target);
                        const auto found = rva
                            ? instruction_index_by_rva(instructions, *rva)
                            : std::nullopt;
                        if (found)
                            leaders[*found] = 1;
                    }
                    const auto delay_count =
                        delay_slot_counts.empty() ? 0U : delay_slot_counts[index];
                    const auto transfer_end = index + delay_count;
                    if ((instruction.flow_flags & kControlFlowMask) != 0 &&
                        transfer_end + 1 < instructions.size()) {
                        leaders[transfer_end + 1] = 1;
                    }
                    if (index + 1 < instructions.size() &&
                        instruction_end(instruction) != instructions[index + 1].address.value)
                        leaders[index + 1] = 1;
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<block_recovery_result_t>::failure(
                failure.take_error());
    }
    if (!delay_slot_counts.empty()) {
        const auto shards = partition_shards(delay_slot_counts.size(),
            pass_shard_count(delay_slot_counts.size(), kIndexShardFloor));
        run_sharded(shards.size(), [&](std::size_t shard) {
            guarded_shard(failure, shard, "basic block storage exceeds analysis budget",
                "blocks", [&]() {
                const auto range = shards[shard];
                shard_poll_t poll{&cancel, &failure, shard, "blocks"};
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (poll.stopped(index - range.begin))
                        return;
                    for (std::size_t offset = 1; offset <= delay_slot_counts[index];
                         ++offset) {
                        if (leaders[index + offset] == 0)
                            continue;
                        auto error = make_workspace_error(
                            workspace_error_code_t::integrity_failure,
                            "delay-slot instruction is also a basic-block leader", "blocks");
                        error.address = instructions[index + offset].address;
                        failure.report(shard, std::move(error));
                        return;
                    }
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<block_recovery_result_t>::failure(
                failure.take_error());
    }
    const auto leader_shards = partition_shards(instructions.size(),
        pass_shard_count(instructions.size(), kIndexShardFloor));
    std::vector<std::uint64_t> shard_leader_bases(leader_shards.size(), 0);
    run_sharded(leader_shards.size(), [&](std::size_t shard) {
        const auto range = leader_shards[shard];
        std::uint64_t count = 0;
        for (std::size_t index = range.begin; index < range.end; ++index)
            count += leaders[index];
        shard_leader_bases[shard] = count;
    });
    std::uint64_t block_count = 0;
    for (auto& base : shard_leader_bases) {
        const auto offset = block_count;
        if (!checked_add_u64(block_count, base, block_count)) {
            return workspace_result_t<block_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                    "basic block storage exceeds analysis budget", "blocks"));
        }
        base = offset;
    }
    if (block_count > limits.max_blocks) {
        return workspace_result_t<block_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "basic block storage exceeds analysis budget", "blocks"));
    }
    std::uint64_t block_bytes = 0;
    if (!checked_mul_u64(block_count, sizeof(basic_block_record_t), block_bytes)) {
        return workspace_result_t<block_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "basic block storage exceeds analysis budget", "blocks"));
    }
    auto accounted = account_bytes(result.storage_bytes, block_bytes,
        limits.max_result_bytes, "blocks", "basic block storage exceeds analysis budget");
    if (!accounted)
        return workspace_result_t<block_recovery_result_t>::failure(accounted.error());
    std::uint64_t terminator_bytes = 0;
    if (!checked_mul_u64(block_count, sizeof(std::uint32_t), terminator_bytes)) {
        return workspace_result_t<block_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "basic block terminator storage exceeds analysis budget", "blocks"));
    }
    accounted = account_bytes(result.storage_bytes, terminator_bytes,
        limits.max_result_bytes, "blocks",
        "basic block terminator storage exceeds analysis budget");
    if (!accounted)
        return workspace_result_t<block_recovery_result_t>::failure(accounted.error());
    std::vector<std::uint32_t> leader_indices(static_cast<std::size_t>(block_count));
    run_sharded(leader_shards.size(), [&](std::size_t shard) {
        const auto range = leader_shards[shard];
        std::uint64_t cursor = shard_leader_bases[shard];
        for (std::size_t index = range.begin; index < range.end; ++index) {
            if (leaders[index] != 0) {
                leader_indices[static_cast<std::size_t>(cursor)] =
                    static_cast<std::uint32_t>(index);
                ++cursor;
            }
        }
    });
    result.blocks.resize(static_cast<std::size_t>(block_count));
    result.terminator_instruction_indices.resize(static_cast<std::size_t>(block_count));
    const auto block_shards = partition_shards(static_cast<std::size_t>(block_count),
        pass_shard_count(static_cast<std::size_t>(block_count), kIndexShardFloor));
    run_sharded(block_shards.size(), [&](std::size_t shard) {
        guarded_shard(failure, shard, "basic block storage exceeds analysis budget",
            "blocks", [&]() {
            const auto range = block_shards[shard];
            shard_poll_t poll{&cancel, &failure, shard, "blocks"};
            for (std::size_t block_ordinal = range.begin; block_ordinal < range.end;
                 ++block_ordinal) {
                if (poll.stopped(block_ordinal - range.begin))
                    return;
                const auto first =
                    static_cast<std::size_t>(leader_indices[block_ordinal]);
                const auto end = block_ordinal + 1 < block_count
                    ? static_cast<std::size_t>(leader_indices[block_ordinal + 1])
                    : instructions.size();
                std::size_t terminator = end - 1;
                for (std::size_t index = first; index < end; ++index) {
                    const auto delay_count =
                        delay_slot_counts.empty() ? 0U : delay_slot_counts[index];
                    if ((instructions[index].flow_flags & kControlFlowMask) != 0 &&
                        index + delay_count == end - 1) {
                        terminator = index;
                        break;
                    }
                }
                basic_block_record_t block;
                block.id = kBlockEntityTag | static_cast<std::uint64_t>(block_ordinal + 1);
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
                result.blocks[block_ordinal] = block;
                result.terminator_instruction_indices[block_ordinal] =
                    static_cast<std::uint32_t>(terminator);
            }
        });
    });
    if (failure.failed.load(std::memory_order_relaxed))
        return workspace_result_t<block_recovery_result_t>::failure(failure.take_error());
    pass_budget_t edge_budget;
    edge_budget.ceiling = limits.max_result_bytes - result.storage_bytes;
    std::vector<shard_vector_t<edge_record_t>> shard_edges(block_shards.size());
    run_sharded(block_shards.size(), [&](std::size_t shard) {
        guarded_shard(failure, shard, "CFG edge storage exceeds analysis budget",
            "blocks", [&]() {
            const auto range = block_shards[shard];
            auto& edges = shard_edges[shard];
            std::uint64_t reserve_count = 0;
            if (!checked_add_u64(
                    2ULL * static_cast<std::uint64_t>(range.end - range.begin), 8ULL,
                    reserve_count)) {
                failure.report(shard, make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "CFG edge storage exceeds analysis budget", "blocks"));
                return;
            }
            reserve_count = (std::min)(limits.max_edges / block_shards.size(),
                reserve_count);
            auto reserved = edges.reserve_grant(static_cast<std::size_t>(reserve_count),
                edge_budget, "blocks", "CFG edge storage exceeds analysis budget");
            if (!reserved) {
                failure.report(shard, reserved.error());
                return;
            }
            shard_poll_t poll{&cancel, &failure, shard, "blocks"};
            for (std::size_t block_index = range.begin; block_index < range.end;
                 ++block_index) {
                if (poll.stopped(block_index - range.begin))
                    return;
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
                    return edges.append(std::move(edge), limits.max_edges, edge_budget,
                        "blocks", "CFG edge storage exceeds analysis budget");
                };
                const auto target_end =
                    static_cast<std::uint64_t>(transfer->target_fact_begin) +
                    transfer->target_fact_count;
                bool stopped = false;
                for (std::uint64_t target_index = transfer->target_fact_begin;
                     target_index < target_end && !stopped; ++target_index) {
                    const auto& target = targets[static_cast<std::size_t>(target_index)];
                    if (target.kind != target_kind_record_t::branch &&
                        target.kind != target_kind_record_t::call)
                        continue;
                    const auto rva = to_rva(image, target.target);
                    if (!rva || !executable_rva(image, *rva) ||
                        !block_index_by_start(result.blocks, *rva))
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
                    if (!appended) {
                        failure.report(shard, appended.error());
                        stopped = true;
                    }
                }
                if (stopped)
                    return;
                if ((transfer->flow_flags & flow_fallthrough) != 0) {
                    const auto found = block_index_by_start(result.blocks, block.end.value);
                    if (found) {
                        auto appended = append_edge(result.blocks[*found].start,
                            edge_kind_t::fallthrough);
                        if (!appended) {
                            failure.report(shard, appended.error());
                            return;
                        }
                    }
                }
            }
        });
    });
    if (failure.failed.load(std::memory_order_relaxed))
        return workspace_result_t<block_recovery_result_t>::failure(failure.take_error());
    merge_clock_t merge_clock;
    std::uint64_t edge_total = 0;
    for (const auto& edges : shard_edges) {
        if (!checked_add_u64(edge_total, edges.values.size(), edge_total)) {
            return workspace_result_t<block_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                    "CFG edge storage exceeds analysis budget", "blocks"));
        }
    }
    if (edge_total > limits.max_edges) {
        return workspace_result_t<block_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "CFG edge storage exceeds analysis budget", "blocks"));
    }
    std::uint64_t edge_bytes = 0;
    if (!checked_mul_u64(edge_total, sizeof(edge_record_t), edge_bytes)) {
        return workspace_result_t<block_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "CFG edge storage exceeds analysis budget", "blocks"));
    }
    accounted = account_bytes(result.storage_bytes, edge_bytes, limits.max_result_bytes,
        "blocks", "CFG edge storage exceeds analysis budget");
    if (!accounted)
        return workspace_result_t<block_recovery_result_t>::failure(accounted.error());
    result.edges.reserve(static_cast<std::size_t>(edge_total));
    for (auto& edges : shard_edges) {
        for (auto& edge : edges.values)
            result.edges.push_back(std::move(edge));
    }
    parallel_sort(result.edges.begin(), result.edges.end(), edge_less);
    parallel_unique_erase(result.edges, edge_equal);
    for (std::size_t index = 0; index < result.edges.size(); ++index)
        result.edges[index].id = kEdgeEntityTag | static_cast<std::uint64_t>(index + 1);
    result.shard_merge_ns += merge_clock.elapsed_ns();
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
    result.shard_merge_ns = block_result.shard_merge_ns;
    shard_failure_t failure;
    std::vector<std::uint64_t> block_boundaries(result.blocks.size() * 2);
    {
        const auto shards = partition_shards(result.blocks.size(),
            pass_shard_count(result.blocks.size(), kIndexShardFloor));
        run_sharded(shards.size(), [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index) {
                block_boundaries[index * 2] = result.blocks[index].start.value;
                block_boundaries[index * 2 + 1] = result.blocks[index].end.value;
            }
        });
        merge_clock_t boundary_clock;
        parallel_sort(block_boundaries.begin(), block_boundaries.end(),
            [](std::uint64_t lhs, std::uint64_t rhs) { return lhs < rhs; });
        parallel_unique_erase(block_boundaries,
            [](std::uint64_t lhs, std::uint64_t rhs) { return lhs == rhs; });
        result.shard_merge_ns += boundary_clock.elapsed_ns();
    }
    const auto boundary_contains = [&](std::uint64_t rva) {
        return std::binary_search(block_boundaries.begin(), block_boundaries.end(), rva);
    };
    struct seed_shard_output_t {
        std::vector<selected_seed_t> selected;
        std::vector<function_recovery_conflict_t> conflicts;
    };
    const auto seed_shards = partition_shards(seeds.size(),
        pass_shard_count(seeds.size(), kSeedShardFloor));
    std::vector<seed_shard_output_t> seed_outputs(seed_shards.size());
    run_sharded(seed_shards.size(), [&](std::size_t shard) {
        guarded_shard(failure, shard,
            "function recovery conflict storage exceeds analysis budget", "functions",
            [&]() {
            auto& output = seed_outputs[shard];
            const auto range = seed_shards[shard];
            output.selected.reserve(range.end - range.begin);
            shard_poll_t poll{&cancel, &failure, shard, "functions"};
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if (poll.stopped(index - range.begin))
                    return;
                const auto& seed = seeds[index];
                const auto start = to_rva(image, seed.address);
                if (!start) {
                    function_recovery_conflict_t conflict;
                    conflict.kind = function_recovery_conflict_kind_t::invalid_seed_address;
                    conflict.rva = seed.address.value;
                    conflict.competing_seed_kind = seed.kind;
                    conflict.competing_source_id = seed.stable_source_id;
                    output.conflicts.push_back(std::move(conflict));
                    continue;
                }
                const auto block = block_index_by_start(result.blocks, *start);
                const bool loader_only = !block &&
                    authoritative_loader_seed(seed.kind) && executable_rva(image, *start) &&
                    executable_region_end(image, *start).has_value();
                if (!block) {
                    function_recovery_conflict_t conflict;
                    conflict.kind = function_recovery_conflict_kind_t::seed_without_block;
                    conflict.rva = *start;
                    conflict.competing_seed_kind = seed.kind;
                    conflict.competing_source_id = seed.stable_source_id;
                    output.conflicts.push_back(std::move(conflict));
                    if (!loader_only)
                        continue;
                }
                std::optional<std::uint64_t> end;
                if (seed.known_end) {
                    end = to_rva_endpoint(image, *seed.known_end);
                    const auto executable_end = executable_region_end(image, *start);
                    const bool valid_end = end && *end > *start &&
                        (loader_only
                            ? executable_end && *end <= *executable_end
                            : boundary_contains(*end));
                    if (!valid_end) {
                        function_recovery_conflict_t conflict;
                        conflict.kind =
                            function_recovery_conflict_kind_t::invalid_seed_range;
                        conflict.rva = *start;
                        conflict.related_rva = seed.known_end->value;
                        conflict.competing_seed_kind = seed.kind;
                        conflict.competing_source_id = seed.stable_source_id;
                        output.conflicts.push_back(std::move(conflict));
                        end.reset();
                    }
                }
                output.selected.push_back({seed, *start, end, loader_only});
            }
        });
    });
    if (failure.failed.load(std::memory_order_relaxed))
        return workspace_result_t<function_recovery_result_t>::failure(failure.take_error());
    std::vector<selected_seed_t> selected;
    {
        merge_clock_t seed_clock;
        std::uint64_t selected_total = 0;
        std::uint64_t conflict_total = 0;
        for (const auto& output : seed_outputs) {
            if (!checked_add_u64(selected_total, output.selected.size(), selected_total) ||
                !checked_add_u64(conflict_total, output.conflicts.size(), conflict_total)) {
                return workspace_result_t<function_recovery_result_t>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                        "function recovery conflict storage exceeds analysis budget",
                        "functions"));
            }
        }
        if (conflict_total > limits.max_conflicts) {
            return workspace_result_t<function_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "function recovery conflict storage exceeds analysis budget",
                    "functions"));
        }
        std::uint64_t conflict_bytes = 0;
        if (!checked_mul_u64(conflict_total, sizeof(function_recovery_conflict_t),
                conflict_bytes)) {
            return workspace_result_t<function_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                    "function recovery conflict storage exceeds analysis budget",
                    "functions"));
        }
        auto accounted = account_bytes(result.storage_bytes, conflict_bytes,
            limits.max_result_bytes, "functions",
            "function recovery conflict storage exceeds analysis budget");
        if (!accounted)
            return workspace_result_t<function_recovery_result_t>::failure(
                accounted.error());
        selected.reserve(static_cast<std::size_t>(selected_total));
        result.conflicts.reserve(static_cast<std::size_t>(conflict_total));
        for (auto& output : seed_outputs) {
            for (auto& selection : output.selected)
                selected.push_back(std::move(selection));
            for (auto& conflict : output.conflicts)
                result.conflicts.push_back(std::move(conflict));
        }
        result.shard_merge_ns += seed_clock.elapsed_ns();
    }
    parallel_sort(selected.begin(), selected.end(), selected_seed_less);
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
            winner.loader_only = winner.loader_only || selected[index].loader_only;
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
    for (std::size_t index = 0; index < canonical.size(); ++index) {
        if (!canonical[index].loader_only || canonical[index].end)
            continue;
        const auto region_end = executable_region_end(image, canonical[index].start);
        if (!region_end || *region_end <= canonical[index].start)
            continue;
        std::uint64_t end = *region_end;
        for (std::size_t next = index + 1; next < canonical.size(); ++next) {
            if (canonical[next].start >= end)
                break;
            if (canonical[next].start > canonical[index].start &&
                authoritative_loader_seed(canonical[next].seed.kind)) {
                end = canonical[next].start;
                break;
            }
        }
        canonical[index].end = end;
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
    const auto block_ids = build_block_id_index(result.blocks, cancel);
    if (cancel.stop_requested())
        return workspace_result_t<function_recovery_result_t>::failure(
            stop_error(cancel, "functions"));
    std::vector<std::vector<std::size_t>> successors(result.blocks.size());
    {
        struct successor_pair_t {
            std::uint32_t source = 0;
            std::uint32_t target = 0;
        };
        const auto edge_shards = partition_shards(result.edges.size(),
            pass_shard_count(result.edges.size(), kIndexShardFloor));
        std::vector<std::vector<successor_pair_t>> shard_pairs(edge_shards.size());
        run_sharded(edge_shards.size(), [&](std::size_t shard) {
            guarded_shard(failure, shard, "function storage exceeds analysis budget",
                "functions", [&]() {
                auto& pairs = shard_pairs[shard];
                const auto range = edge_shards[shard];
                shard_poll_t poll{&cancel, &failure, shard, "functions"};
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (poll.stopped(index - range.begin))
                        return;
                    const auto& edge = result.edges[index];
                    if (edge.kind == edge_kind_t::call ||
                        edge.kind == edge_kind_t::tail_call ||
                        edge.kind == edge_kind_t::return_edge)
                        continue;
                    const auto source = block_ids.find(edge.source_entity);
                    const auto target = to_rva(image, edge.target);
                    const auto found = target
                        ? block_index_by_start(result.blocks, *target) : std::nullopt;
                    if (!source || !found)
                        continue;
                    pairs.push_back({static_cast<std::uint32_t>(*source),
                        static_cast<std::uint32_t>(*found)});
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<function_recovery_result_t>::failure(
                failure.take_error());
        merge_clock_t successor_clock;
        for (auto& pairs : shard_pairs) {
            for (const auto& pair : pairs)
                successors[pair.source].push_back(pair.target);
        }
        result.shard_merge_ns += successor_clock.elapsed_ns();
    }
    {
        const auto block_shards = partition_shards(result.blocks.size(),
            pass_shard_count(result.blocks.size(), kIndexShardFloor));
        run_sharded(block_shards.size(), [&](std::size_t shard) {
            const auto range = block_shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index) {
                auto& values = successors[index];
                std::sort(values.begin(), values.end());
                values.erase(std::unique(values.begin(), values.end()), values.end());
            }
        });
    }
    std::vector<std::pair<std::uint32_t, std::uint32_t>> seeded_blocks;
    seeded_blocks.reserve(canonical.size());
    for (std::size_t index = 0; index < canonical.size(); ++index) {
        const auto block = block_index_by_start(result.blocks, canonical[index].start);
        if (block) {
            seeded_blocks.emplace_back(static_cast<std::uint32_t>(*block),
                static_cast<std::uint32_t>(index));
        }
    }
    std::vector<std::atomic<std::uint32_t>> claim_counts(result.blocks.size());
    {
        const auto block_shards = partition_shards(result.blocks.size(),
            pass_shard_count(result.blocks.size(), kIndexShardFloor));
        run_sharded(block_shards.size(), [&](std::size_t shard) {
            const auto range = block_shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index)
                claim_counts[index].store(0, std::memory_order_relaxed);
        });
    }
    result.reachability_mark_slots = result.blocks.size();
    std::uint64_t total_memberships = 0;
    const auto traverse_one = [&](traverse_scratch_t& scratch,
                                  const selected_seed_t& selection, bool unclaimed_only,
                                  std::uint64_t& memberships, std::uint64_t& passes)
        -> workspace_result_t<void> {
        scratch.reached.clear();
        const auto start = block_index_by_start(result.blocks, selection.start);
        if (!start)
            return workspace_result_t<void>::success();
        if (scratch.marks.size() != result.blocks.size())
            scratch.marks.resize(result.blocks.size(), 0);
        ++scratch.generation;
        if (scratch.generation == 0) {
            std::fill(scratch.marks.begin(), scratch.marks.end(), 0);
            scratch.generation = 1;
        }
        ++passes;
        const auto mark = scratch.generation;
        scratch.pending.clear();
        scratch.pending.push_back(*start);
        std::size_t visits = 0;
        while (!scratch.pending.empty()) {
            if ((visits++ & (kCancellationStride - 1)) == 0 && cancel.stop_requested())
                return workspace_result_t<void>::failure(stop_error(cancel, "functions"));
            const auto block_index = scratch.pending.back();
            scratch.pending.pop_back();
            if (scratch.marks[block_index] == mark)
                continue;
            scratch.marks[block_index] = mark;
            const auto& block = result.blocks[block_index];
            if (block.start.value < selection.start ||
                (selection.end && block.end.value > *selection.end))
                continue;
            const auto barrier = std::lower_bound(seeded_blocks.begin(),
                seeded_blocks.end(), static_cast<std::uint32_t>(block_index),
                [](const std::pair<std::uint32_t, std::uint32_t>& entry,
                   std::uint32_t value) {
                    return entry.first < value;
                });
            if (barrier != seeded_blocks.end() &&
                barrier->first == static_cast<std::uint32_t>(block_index) &&
                block.start.value != selection.start)
                continue;
            if (unclaimed_only &&
                claim_counts[block_index].load(std::memory_order_relaxed) != 0)
                continue;
            if (scratch.reached.size() >= limits.max_blocks_per_function ||
                memberships >= limits.max_function_memberships) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "function reachability exceeds analysis budget", "functions"));
            }
            scratch.reached.push_back(block_index);
            ++memberships;
            for (auto iterator = successors[block_index].rbegin();
                 iterator != successors[block_index].rend(); ++iterator) {
                if (scratch.marks[*iterator] != mark)
                    scratch.pending.push_back(*iterator);
            }
        }
        std::sort(scratch.reached.begin(), scratch.reached.end());
        return workspace_result_t<void>::success();
    };
    struct traverse_shard_output_t {
        std::vector<function_candidate_t> candidates;
        std::vector<function_recovery_conflict_t> conflicts;
        std::uint64_t memberships = 0;
        std::uint64_t passes = 0;
        bool reachability_failed = false;
    };
    std::vector<function_candidate_t> candidates;
    const auto canonical_shards = partition_shards(canonical.size(),
        pass_shard_count(canonical.size(), kSeedShardFloor));
    std::vector<traverse_shard_output_t> traverse_outputs(canonical_shards.size());
    run_sharded_local<traverse_scratch_t>(canonical_shards.size(),
        [&](std::size_t shard, traverse_scratch_t& scratch) {
        guarded_shard(failure, shard, "function storage exceeds analysis budget",
            "functions", [&]() {
            auto& output = traverse_outputs[shard];
            const auto range = canonical_shards[shard];
            shard_poll_t poll{&cancel, &failure, shard, "functions"};
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if (poll.stopped(index - range.begin) || output.reachability_failed)
                    return;
                const auto& selection = canonical[index];
                if (selection.loader_only) {
                    if (!selection.end || *selection.end <= selection.start)
                        continue;
                    function_candidate_t candidate;
                    candidate.selection = selection;
                    output.candidates.push_back(std::move(candidate));
                    continue;
                }
                auto traversed = traverse_one(scratch, selection, false,
                    output.memberships, output.passes);
                if (!traversed) {
                    const auto code = traversed.error().code;
                    if (code == workspace_error_code_t::cancelled ||
                        code == workspace_error_code_t::deadline_exceeded) {
                        failure.report(shard, traversed.error());
                        return;
                    }
                    output.reachability_failed = true;
                    return;
                }
                if (scratch.reached.empty()) {
                    function_recovery_conflict_t conflict;
                    conflict.kind = function_recovery_conflict_kind_t::seed_without_block;
                    conflict.rva = selection.start;
                    conflict.competing_seed_kind = selection.seed.kind;
                    conflict.competing_source_id = selection.seed.stable_source_id;
                    output.conflicts.push_back(std::move(conflict));
                    continue;
                }
                function_candidate_t candidate;
                candidate.selection = selection;
                candidate.blocks = std::move(scratch.reached);
                scratch.reached.clear();
                for (const auto block : candidate.blocks)
                    claim_counts[block].fetch_add(1, std::memory_order_relaxed);
                output.candidates.push_back(std::move(candidate));
            }
        });
    });
    if (failure.failed.load(std::memory_order_relaxed))
        return workspace_result_t<function_recovery_result_t>::failure(failure.take_error());
    bool reachability_failed = false;
    std::uint64_t traverse_conflict_total = 0;
    std::uint64_t candidate_total = 0;
    for (const auto& output : traverse_outputs) {
        reachability_failed = reachability_failed || output.reachability_failed;
        total_memberships += output.memberships;
        result.reachability_passes += output.passes;
        traverse_conflict_total += output.conflicts.size();
        candidate_total += output.candidates.size();
    }
    if (reachability_failed || total_memberships >= limits.max_function_memberships) {
        return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "function reachability exceeds analysis budget", "functions"));
    }
    if (traverse_conflict_total > limits.max_conflicts) {
        return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "function recovery conflict storage exceeds analysis budget", "functions"));
    }
    {
        merge_clock_t traverse_clock;
        std::uint64_t conflict_bytes = 0;
        if (!checked_mul_u64(traverse_conflict_total,
                sizeof(function_recovery_conflict_t), conflict_bytes)) {
            return workspace_result_t<function_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                    "function recovery conflict storage exceeds analysis budget",
                    "functions"));
        }
        auto accounted = account_bytes(result.storage_bytes, conflict_bytes,
            limits.max_result_bytes, "functions",
            "function recovery conflict storage exceeds analysis budget");
        if (!accounted)
            return workspace_result_t<function_recovery_result_t>::failure(
                accounted.error());
        candidates.reserve(candidate_total);
        for (auto& output : traverse_outputs) {
            for (auto& candidate : output.candidates)
                candidates.push_back(std::move(candidate));
            for (auto& conflict : output.conflicts)
                result.conflicts.push_back(std::move(conflict));
        }
        result.shard_merge_ns += traverse_clock.elapsed_ns();
    }
    const std::size_t gap_block_total = result.blocks.size();
    std::vector<std::uint32_t> unclaimed_blocks;
    {
        const auto unclaimed_shards = partition_shards(gap_block_total,
            pass_shard_count(gap_block_total, kIndexShardFloor));
        std::vector<std::uint64_t> shard_unclaimed(unclaimed_shards.size(), 0);
        run_sharded(unclaimed_shards.size(), [&](std::size_t shard) {
            const auto range = unclaimed_shards[shard];
            std::uint64_t count = 0;
            for (std::size_t index = range.begin; index < range.end; ++index) {
                count += claim_counts[index].load(std::memory_order_relaxed) == 0
                    ? 1ULL : 0ULL;
            }
            shard_unclaimed[shard] = count;
        });
        std::uint64_t unclaimed_total = 0;
        for (auto& base : shard_unclaimed) {
            const auto offset = unclaimed_total;
            unclaimed_total += base;
            base = offset;
        }
        unclaimed_blocks.resize(static_cast<std::size_t>(unclaimed_total));
        run_sharded(unclaimed_shards.size(), [&](std::size_t shard) {
            const auto range = unclaimed_shards[shard];
            auto cursor = shard_unclaimed[shard];
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if (claim_counts[index].load(std::memory_order_relaxed) == 0) {
                    unclaimed_blocks[static_cast<std::size_t>(cursor++)] =
                        static_cast<std::uint32_t>(index);
                }
            }
        });
    }
    struct gap_member_t {
        std::uint32_t leader = 0;
        std::uint32_t block = 0;
    };
    struct gap_shard_output_t {
        std::vector<function_candidate_t> candidates;
        std::vector<function_recovery_conflict_t> conflicts;
        std::uint64_t memberships = 0;
        std::uint64_t passes = 0;
        std::uint64_t synthetic = 0;
        bool reachability_failed = false;
    };
    std::vector<gap_member_t> gap_members;
    std::vector<std::uint64_t> gap_group_starts;
    if (!unclaimed_blocks.empty()) {
        std::vector<std::atomic<std::uint32_t>> component_parent(gap_block_total);
        {
            const auto init_shards = partition_shards(gap_block_total,
                pass_shard_count(gap_block_total, kIndexShardFloor));
            run_sharded(init_shards.size(), [&](std::size_t shard) {
                const auto range = init_shards[shard];
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    component_parent[index].store(static_cast<std::uint32_t>(index),
                        std::memory_order_relaxed);
                }
            });
        }
        const auto component_find = [&](std::uint32_t value) {
            for (;;) {
                const auto parent =
                    component_parent[value].load(std::memory_order_relaxed);
                if (parent == value)
                    return value;
                const auto grand =
                    component_parent[parent].load(std::memory_order_relaxed);
                if (grand != parent) {
                    auto expected = parent;
                    component_parent[value].compare_exchange_weak(expected, grand,
                        std::memory_order_relaxed);
                }
                value = grand;
            }
        };
        const auto component_union = [&](std::uint32_t first, std::uint32_t second) {
            for (;;) {
                first = component_find(first);
                second = component_find(second);
                if (first == second)
                    return;
                if (first > second)
                    std::swap(first, second);
                auto expected = second;
                if (component_parent[second].compare_exchange_strong(expected, first,
                        std::memory_order_relaxed))
                    return;
            }
        };
        {
            const auto member_shards = partition_shards(unclaimed_blocks.size(),
                pass_shard_count(unclaimed_blocks.size(), kIndexShardFloor));
            run_sharded(member_shards.size(), [&](std::size_t shard) {
                const auto range = member_shards[shard];
                shard_poll_t poll{&cancel, &failure, shard, "functions"};
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (poll.stopped(index - range.begin))
                        return;
                    const auto block = unclaimed_blocks[index];
                    for (const auto successor : successors[block]) {
                        if (claim_counts[successor].load(
                                std::memory_order_relaxed) == 0) {
                            component_union(block,
                                static_cast<std::uint32_t>(successor));
                        }
                    }
                }
            });
            if (failure.failed.load(std::memory_order_relaxed))
                return workspace_result_t<function_recovery_result_t>::failure(
                    failure.take_error());
        }
        gap_members.resize(unclaimed_blocks.size());
        {
            const auto member_shards = partition_shards(unclaimed_blocks.size(),
                pass_shard_count(unclaimed_blocks.size(), kIndexShardFloor));
            run_sharded(member_shards.size(), [&](std::size_t shard) {
                const auto range = member_shards[shard];
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    const auto block = unclaimed_blocks[index];
                    gap_members[index] =
                        gap_member_t{component_find(block), block};
                }
            });
        }
        parallel_sort(gap_members.begin(), gap_members.end(),
            [](const gap_member_t& lhs, const gap_member_t& rhs) {
                if (lhs.leader != rhs.leader)
                    return lhs.leader < rhs.leader;
                return lhs.block < rhs.block;
            });
        {
            const auto group_shards = partition_shards(gap_members.size(),
                pass_shard_count(gap_members.size(), kIndexShardFloor));
            std::vector<std::uint64_t> shard_groups(group_shards.size(), 0);
            run_sharded(group_shards.size(), [&](std::size_t shard) {
                const auto range = group_shards[shard];
                std::uint64_t count = 0;
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    count += (index == 0 ||
                        gap_members[index].leader != gap_members[index - 1].leader)
                        ? 1ULL : 0ULL;
                }
                shard_groups[shard] = count;
            });
            std::uint64_t group_total = 0;
            for (auto& base : shard_groups) {
                const auto offset = group_total;
                group_total += base;
                base = offset;
            }
            gap_group_starts.resize(static_cast<std::size_t>(group_total));
            run_sharded(group_shards.size(), [&](std::size_t shard) {
                const auto range = group_shards[shard];
                auto cursor = shard_groups[shard];
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (index == 0 ||
                        gap_members[index].leader != gap_members[index - 1].leader) {
                        gap_group_starts[static_cast<std::size_t>(cursor++)] =
                            static_cast<std::uint64_t>(index);
                    }
                }
            });
        }
    }
    std::uint64_t gap_candidate_total = 0;
    std::uint64_t gap_conflict_total = 0;
    {
        const auto group_total = gap_group_starts.size();
        const auto group_shards = partition_shards(group_total,
            pass_shard_count(group_total, kSeedShardFloor));
        std::vector<gap_shard_output_t> gap_outputs(group_shards.size());
        run_sharded_local<traverse_scratch_t>(group_shards.size(),
            [&](std::size_t shard, traverse_scratch_t& scratch) {
            guarded_shard(failure, shard, "function storage exceeds analysis budget",
                "functions", [&]() {
                auto& output = gap_outputs[shard];
                const auto range = group_shards[shard];
                shard_poll_t poll{&cancel, &failure, shard, "functions"};
                for (std::size_t group = range.begin; group < range.end; ++group) {
                    if (poll.stopped(group - range.begin) || output.reachability_failed)
                        return;
                    const auto member_begin =
                        static_cast<std::size_t>(gap_group_starts[group]);
                    const auto member_end = group + 1 < group_total
                        ? static_cast<std::size_t>(gap_group_starts[group + 1])
                        : gap_members.size();
                    for (std::size_t member = member_begin; member < member_end;
                         ++member) {
                        const auto block_index =
                            static_cast<std::size_t>(gap_members[member].block);
                        if (claim_counts[block_index].load(
                                std::memory_order_relaxed) != 0)
                            continue;
                        selected_seed_t gap;
                        gap.start = result.blocks[block_index].start.value;
                        gap.seed.address = result.blocks[block_index].start;
                        gap.seed.kind = function_seed_kind_t::validated_gap_target;
                        gap.seed.provenance = fact_provenance_t::gap_recovery;
                        gap.seed.confidence = result.blocks[block_index].confidence;
                        gap.seed.stable_source_id =
                            result.blocks[block_index].id ^ gap.start;
                        auto traversed = traverse_one(scratch, gap, true,
                            output.memberships, output.passes);
                        if (!traversed) {
                            const auto code = traversed.error().code;
                            if (code == workspace_error_code_t::cancelled ||
                                code == workspace_error_code_t::deadline_exceeded) {
                                failure.report(shard, traversed.error());
                                return;
                            }
                            output.reachability_failed = true;
                            return;
                        }
                        if (scratch.reached.empty())
                            continue;
                        function_candidate_t candidate;
                        candidate.selection = gap;
                        candidate.blocks = std::move(scratch.reached);
                        scratch.reached.clear();
                        candidate.synthetic_gap = true;
                        for (const auto block : candidate.blocks)
                            claim_counts[block].fetch_add(1, std::memory_order_relaxed);
                        function_recovery_conflict_t conflict;
                        conflict.kind =
                            function_recovery_conflict_kind_t::gap_component_seeded;
                        conflict.rva = gap.start;
                        conflict.selected_seed_kind = gap.seed.kind;
                        conflict.selected_source_id = gap.seed.stable_source_id;
                        output.conflicts.push_back(std::move(conflict));
                        ++output.synthetic;
                        output.candidates.push_back(std::move(candidate));
                    }
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<function_recovery_result_t>::failure(
                failure.take_error());
        bool gap_reachability_failed = false;
        for (const auto& output : gap_outputs) {
            gap_reachability_failed =
                gap_reachability_failed || output.reachability_failed;
            total_memberships += output.memberships;
            result.reachability_passes += output.passes;
            gap_conflict_total += output.conflicts.size();
            gap_candidate_total += output.candidates.size();
            result.synthetic_gap_functions += output.synthetic;
        }
        if (gap_reachability_failed ||
            total_memberships >= limits.max_function_memberships) {
            return workspace_result_t<function_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "function reachability exceeds analysis budget", "functions"));
        }
        if (result.conflicts.size() > limits.max_conflicts ||
            gap_conflict_total > limits.max_conflicts - result.conflicts.size()) {
            return workspace_result_t<function_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "function recovery conflict storage exceeds analysis budget",
                    "functions"));
        }
        if (gap_candidate_total > limits.max_functions - candidates.size()) {
            return workspace_result_t<function_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "gap function recovery exceeds analysis budget", "functions"));
        }
        {
            merge_clock_t gap_clock;
            std::uint64_t conflict_bytes = 0;
            if (!checked_mul_u64(gap_conflict_total,
                    sizeof(function_recovery_conflict_t), conflict_bytes)) {
                return workspace_result_t<function_recovery_result_t>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                        "function recovery conflict storage exceeds analysis budget",
                        "functions"));
            }
            auto accounted = account_bytes(result.storage_bytes, conflict_bytes,
                limits.max_result_bytes, "functions",
                "function recovery conflict storage exceeds analysis budget");
            if (!accounted)
                return workspace_result_t<function_recovery_result_t>::failure(
                    accounted.error());
            std::vector<std::uint64_t> candidate_bases(gap_outputs.size(), 0);
            std::vector<std::uint64_t> conflict_bases(gap_outputs.size(), 0);
            std::uint64_t candidate_cursor = candidates.size();
            std::uint64_t conflict_cursor = result.conflicts.size();
            for (std::size_t index = 0; index < gap_outputs.size(); ++index) {
                candidate_bases[index] = candidate_cursor;
                conflict_bases[index] = conflict_cursor;
                candidate_cursor += gap_outputs[index].candidates.size();
                conflict_cursor += gap_outputs[index].conflicts.size();
            }
            candidates.resize(static_cast<std::size_t>(candidate_cursor));
            result.conflicts.resize(static_cast<std::size_t>(conflict_cursor));
            run_sharded(gap_outputs.size(), [&](std::size_t shard) {
                auto& output = gap_outputs[shard];
                auto candidate_slot = candidate_bases[shard];
                for (auto& candidate : output.candidates) {
                    candidates[static_cast<std::size_t>(candidate_slot++)] =
                        std::move(candidate);
                }
                auto conflict_slot = conflict_bases[shard];
                for (auto& conflict : output.conflicts) {
                    result.conflicts[static_cast<std::size_t>(conflict_slot++)] =
                        std::move(conflict);
                }
            });
            result.shard_merge_ns += gap_clock.elapsed_ns();
        }
    }
    parallel_sort(candidates.begin(), candidates.end(), candidate_less);
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
    std::vector<candidate_emit_t> emissions(candidates.size());
    const auto emit_shards = partition_shards(candidates.size(),
        pass_shard_count(candidates.size(), kSeedShardFloor));
    run_sharded(emit_shards.size(), [&](std::size_t shard) {
        guarded_shard(failure, shard, "function storage exceeds analysis budget",
            "functions", [&]() {
            const auto range = emit_shards[shard];
            shard_poll_t poll{&cancel, &failure, shard, "functions"};
            for (std::size_t candidate_index = range.begin; candidate_index < range.end;
                 ++candidate_index) {
                if (poll.stopped(candidate_index - range.begin))
                    return;
                const auto& candidate = candidates[candidate_index];
                auto& emission = emissions[candidate_index];
                if (candidate.blocks.empty()) {
                    if (!candidate.selection.loader_only || !candidate.selection.end ||
                        *candidate.selection.end <= candidate.selection.start) {
                        failure.report(shard, make_workspace_error(
                            workspace_error_code_t::integrity_failure,
                            "loader-backed function range is invalid", "functions"));
                        return;
                    }
                    auto& function = emission.function;
                    function.id = candidate.function_id;
                    function.start = rva_address(image, candidate.selection.start);
                    function.end = rva_address(image, *candidate.selection.end);
                    function.provenance = candidate.selection.seed.provenance;
                    function.confidence = candidate.selection.seed.confidence;
                    function.noreturn = candidate.selection.seed.noreturn ||
                        known_noreturn_name(candidate.selection.seed.name);
                    emission.loader_record = true;
                    continue;
                }
                std::size_t run_begin = 0;
                while (run_begin < candidate.blocks.size()) {
                    const bool shared =
                        owners[candidate.blocks[run_begin]] != candidate_index;
                    std::size_t run_end = run_begin + 1;
                    while (run_end < candidate.blocks.size()) {
                        const auto previous = candidate.blocks[run_end - 1];
                        const auto current = candidate.blocks[run_end];
                        if (current != previous + 1 ||
                            result.blocks[previous].end !=
                                result.blocks[current].start ||
                            (owners[current] != candidate_index) != shared)
                            break;
                        ++run_end;
                    }
                    emit_run_t run;
                    run.first_member = static_cast<std::uint32_t>(run_begin);
                    run.member_count = static_cast<std::uint32_t>(run_end - run_begin);
                    run.shared = shared;
                    emission.runs.push_back(run);
                    run_begin = run_end;
                }
                const auto entry_block = block_index_by_start(result.blocks,
                    candidate.selection.start);
                if (!entry_block) {
                    failure.report(shard, make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "function entry block disappeared during recovery", "functions"));
                    return;
                }
                const auto primary = std::find_if(emission.runs.begin(),
                    emission.runs.end(), [&](const emit_run_t& run) {
                        for (std::size_t offset = 0; offset < run.member_count; ++offset) {
                            if (candidate.blocks[run.first_member + offset] == *entry_block)
                                return true;
                        }
                        return false;
                    });
                if (primary == emission.runs.end() || primary->shared) {
                    failure.report(shard, make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "function entry has no deterministic primary ownership",
                        "functions"));
                    return;
                }
                if (primary != emission.runs.begin())
                    std::rotate(emission.runs.begin(), primary, primary + 1);
                auto& function = emission.function;
                function.id = candidate.function_id;
                function.start = rva_address(image, candidate.selection.start);
                function.provenance = candidate.selection.seed.provenance;
                function.confidence = candidate.selection.seed.confidence;
                function.noreturn = candidate.selection.seed.noreturn ||
                    known_noreturn_name(candidate.selection.seed.name);
                function.thunk = compact_thunk(candidate, result.blocks,
                    result.terminator_instruction_indices, instructions);
                function.chunks.reserve(emission.runs.size());
                std::uint64_t maximum_end = function.start.value;
                for (std::size_t run_index = 0; run_index < emission.runs.size();
                     ++run_index) {
                    auto& run = emission.runs[run_index];
                    const auto first_block = candidate.blocks[run.first_member];
                    const auto last_block =
                        candidate.blocks[run.first_member + run.member_count - 1];
                    run.first_block = static_cast<std::uint32_t>(first_block);
                    run.last_block = static_cast<std::uint32_t>(last_block);
                    run.cold = run_index != 0 && !run.shared;
                    address_range_t range_record;
                    range_record.rva_start = result.blocks[first_block].start.value;
                    range_record.rva_end = result.blocks[last_block].end.value;
                    range_record.chunk_kind = static_cast<std::uint8_t>(
                        (run.shared ? function_chunk_shared : function_chunk_none) |
                        (run.cold ? function_chunk_cold : function_chunk_none));
                    function.chunks.push_back(range_record);
                    if (run_index == 0) {
                        function.first_block = static_cast<std::uint32_t>(first_block);
                        function.block_count = run.member_count;
                    }
                    maximum_end = (std::max)(maximum_end, range_record.rva_end);
                    emission.membership_total += run.member_count;
                }
                function.end = rva_address(image, maximum_end);
                if (!checked_mul_u64(static_cast<std::uint64_t>(emission.runs.size()),
                        sizeof(address_range_t), emission.range_bytes)) {
                    failure.report(shard, make_workspace_error(
                        workspace_error_code_t::limit_exceeded,
                        "function range storage exceeds analysis budget", "functions"));
                    return;
                }
            }
        });
    });
    if (failure.failed.load(std::memory_order_relaxed))
        return workspace_result_t<function_recovery_result_t>::failure(failure.take_error());
    std::uint64_t first_chunk = 0;
    std::uint64_t first_membership = 0;
    {
        merge_clock_t ledger_clock;
        for (std::size_t candidate_index = 0; candidate_index < candidates.size();
             ++candidate_index) {
            auto& emission = emissions[candidate_index];
            const auto run_count = static_cast<std::uint64_t>(emission.runs.size());
            if (!emission.loader_record) {
                auto accounted = account_bytes(result.storage_bytes, emission.range_bytes,
                    limits.max_result_bytes, "functions",
                    "function range storage exceeds analysis budget");
                if (!accounted)
                    return workspace_result_t<function_recovery_result_t>::failure(
                        accounted.error());
                if (first_chunk + run_count > limits.max_function_memberships) {
                    return workspace_result_t<function_recovery_result_t>::failure(
                        make_workspace_error(workspace_error_code_t::limit_exceeded,
                            "function chunk storage exceeds analysis budget", "functions"));
                }
                std::uint64_t chunk_bytes = 0;
                if (!checked_mul_u64(run_count, sizeof(function_chunk_record_t),
                        chunk_bytes)) {
                    return workspace_result_t<function_recovery_result_t>::failure(
                        make_workspace_error(workspace_error_code_t::range_overflow,
                            "function chunk storage exceeds analysis budget", "functions"));
                }
                accounted = account_bytes(result.storage_bytes, chunk_bytes,
                    limits.max_result_bytes, "functions",
                    "function chunk storage exceeds analysis budget");
                if (!accounted)
                    return workspace_result_t<function_recovery_result_t>::failure(
                        accounted.error());
                if (first_membership + emission.membership_total >
                    limits.max_function_memberships) {
                    return workspace_result_t<function_recovery_result_t>::failure(
                        make_workspace_error(workspace_error_code_t::limit_exceeded,
                            "function membership storage exceeds analysis budget",
                            "functions"));
                }
                std::uint64_t membership_bytes = 0;
                if (!checked_mul_u64(emission.membership_total,
                        sizeof(function_block_membership_record_t), membership_bytes)) {
                    return workspace_result_t<function_recovery_result_t>::failure(
                        make_workspace_error(workspace_error_code_t::range_overflow,
                            "function membership storage exceeds analysis budget",
                            "functions"));
                }
                accounted = account_bytes(result.storage_bytes, membership_bytes,
                    limits.max_result_bytes, "functions",
                    "function membership storage exceeds analysis budget");
                if (!accounted)
                    return workspace_result_t<function_recovery_result_t>::failure(
                        accounted.error());
                emission.function.first_chunk = static_cast<std::uint32_t>(first_chunk);
                emission.function.first_block_membership =
                    static_cast<std::uint32_t>(first_membership);
                emission.function.chunk_count = static_cast<std::uint32_t>(run_count);
                emission.function.block_membership_count =
                    static_cast<std::uint32_t>(emission.membership_total);
            }
            if (candidate_index + 1 > limits.max_functions) {
                return workspace_result_t<function_recovery_result_t>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                        "function storage exceeds analysis budget", "functions"));
            }
            auto accounted = account_bytes(result.storage_bytes,
                sizeof(function_record_t), limits.max_result_bytes, "functions",
                "function storage exceeds analysis budget");
            if (!accounted)
                return workspace_result_t<function_recovery_result_t>::failure(
                    accounted.error());
            first_chunk += run_count;
            first_membership += emission.membership_total;
        }
        result.shard_merge_ns += ledger_clock.elapsed_ns();
    }
    result.function_chunks.resize(static_cast<std::size_t>(first_chunk));
    result.function_block_memberships.resize(static_cast<std::size_t>(first_membership));
    result.functions.resize(candidates.size());
    run_sharded(emit_shards.size(), [&](std::size_t shard) {
        guarded_shard(failure, shard, "function storage exceeds analysis budget",
            "functions", [&]() {
            const auto range = emit_shards[shard];
            shard_poll_t poll{&cancel, &failure, shard, "functions"};
            for (std::size_t candidate_index = range.begin; candidate_index < range.end;
                 ++candidate_index) {
                if (poll.stopped(candidate_index - range.begin))
                    return;
                const auto& candidate = candidates[candidate_index];
                auto& emission = emissions[candidate_index];
                const auto function_id = emission.function.id;
                std::uint32_t membership_ordinal = 0;
                std::uint64_t membership_cursor = emission.function.first_block_membership;
                for (std::size_t run_index = 0; run_index < emission.runs.size();
                     ++run_index) {
                    const auto& run = emission.runs[run_index];
                    const auto chunk_ordinal =
                        static_cast<std::uint64_t>(emission.function.first_chunk) +
                        run_index;
                    function_chunk_record_t chunk;
                    chunk.id = kFunctionChunkEntityTag | (chunk_ordinal + 1);
                    chunk.function_id = function_id;
                    chunk.start = result.blocks[run.first_block].start;
                    chunk.end = result.blocks[run.last_block].end;
                    chunk.first_block = run.first_block;
                    chunk.block_count = run.member_count;
                    chunk.provenance = emission.function.provenance;
                    chunk.confidence = emission.function.confidence;
                    chunk.cold = run.cold;
                    chunk.shared = run.shared;
                    result.function_chunks[static_cast<std::size_t>(chunk_ordinal)] = chunk;
                    const auto chunk_id = chunk.id;
                    for (std::size_t offset = 0; offset < run.member_count; ++offset) {
                        const auto block_index =
                            candidate.blocks[run.first_member + offset];
                        function_block_membership_record_t membership;
                        membership.function_id = function_id;
                        membership.chunk_id = chunk_id;
                        membership.block_id = result.blocks[block_index].id;
                        membership.block_index = static_cast<std::uint32_t>(block_index);
                        membership.ordinal = membership_ordinal++;
                        membership.shared = owners[block_index] != candidate_index;
                        result.function_block_memberships[
                            static_cast<std::size_t>(membership_cursor)] = membership;
                        ++membership_cursor;
                    }
                }
                result.functions[candidate_index] = std::move(emission.function);
            }
        });
    });
    if (failure.failed.load(std::memory_order_relaxed))
        return workspace_result_t<function_recovery_result_t>::failure(failure.take_error());
    merge_clock_t final_clock;
    parallel_sort(result.conflicts.begin(), result.conflicts.end(), conflict_less);
    parallel_unique_erase(result.conflicts, conflict_equal);
    result.shard_merge_ns += final_clock.elapsed_ns();
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
    shard_failure_t failure;
    const auto function_lookup = make_start_rva_lookup(result.functions);
    const auto block_lookup = make_start_rva_lookup(result.blocks);
    const auto block_ids = build_block_id_index(result.blocks, cancel);
    std::vector<std::pair<std::uint64_t, std::uint32_t>> imports_by_slot;
    imports_by_slot.reserve(image.imports.size());
    for (std::size_t index = 0; index < image.imports.size(); ++index) {
        const auto slot = to_rva(image, image.imports[index].address);
        if (slot)
            imports_by_slot.emplace_back(*slot, static_cast<std::uint32_t>(index));
    }
    std::stable_sort(imports_by_slot.begin(), imports_by_slot.end(),
        [](const std::pair<std::uint64_t, std::uint32_t>& lhs,
           const std::pair<std::uint64_t, std::uint32_t>& rhs) {
            return lhs.first < rhs.first;
        });
    const auto import_at = [&](std::uint64_t slot) -> const image_import_t* {
        const auto found = std::lower_bound(imports_by_slot.begin(),
            imports_by_slot.end(), slot,
            [](const std::pair<std::uint64_t, std::uint32_t>& entry, std::uint64_t value) {
                return entry.first < value;
            });
        if (found != imports_by_slot.end() && found->first == slot)
            return &image.imports[found->second];
        return nullptr;
    };
    if (cancel.stop_requested())
        return workspace_result_t<function_recovery_result_t>::failure(
            stop_error(cancel, "cfg_calls"));
    std::vector<std::uint8_t> noreturn_sources(result.blocks.size(), 0);
    {
        const auto edge_shards = partition_shards(result.edges.size(),
            pass_shard_count(result.edges.size(), kIndexShardFloor));
        run_sharded(edge_shards.size(), [&](std::size_t shard) {
            guarded_shard(failure, shard, "import call edge storage exceeds analysis budget",
                "cfg_calls", [&]() {
                const auto range = edge_shards[shard];
                shard_poll_t poll{&cancel, &failure, shard, "cfg_calls"};
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (poll.stopped(index - range.begin))
                        return;
                    auto& edge = result.edges[index];
                    const auto target = to_rva(image, edge.target);
                    if (!target)
                        continue;
                    const auto function = function_lookup.find(*target);
                    const auto source = block_ids.find(edge.source_entity);
                    if (edge.kind == edge_kind_t::unconditional && function && source &&
                        result.blocks[*source].function_id !=
                            result.functions[*function].id) {
                        edge.kind = edge_kind_t::tail_call;
                        edge.target_entity = result.functions[*function].id;
                    } else if ((edge.kind == edge_kind_t::call ||
                                edge.kind == edge_kind_t::tail_call) && function) {
                        edge.target_entity = result.functions[*function].id;
                    } else {
                        const auto block = block_lookup.find(*target);
                        if (block)
                            edge.target_entity = result.blocks[*block].id;
                    }
                    if (source && edge.target_entity &&
                        ((*edge.target_entity & 0xFF00000000000000ULL) ==
                         kFunctionEntityTag)) {
                        const auto ordinal = *edge.target_entity & 0x00FFFFFFFFFFFFFFULL;
                        if (ordinal != 0 && ordinal <= result.functions.size() &&
                            result.functions[static_cast<std::size_t>(ordinal - 1)].noreturn)
                            noreturn_sources[*source] = 1;
                    }
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<function_recovery_result_t>::failure(
                failure.take_error());
    }
    pass_budget_t import_budget;
    import_budget.ceiling = limits.max_result_bytes - result.storage_bytes;
    const auto block_shards = partition_shards(result.blocks.size(),
        pass_shard_count(result.blocks.size(), kIndexShardFloor));
    std::vector<shard_vector_t<edge_record_t>> shard_import_edges(block_shards.size());
    run_sharded(block_shards.size(), [&](std::size_t shard) {
        guarded_shard(failure, shard, "import call edge storage exceeds analysis budget",
            "cfg_calls", [&]() {
            const auto range = block_shards[shard];
            auto& edges = shard_import_edges[shard];
            shard_poll_t poll{&cancel, &failure, shard, "cfg_calls"};
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if (poll.stopped(index - range.begin))
                    return;
                const auto* call = transfer_instruction(index, result.blocks,
                    result.terminator_instruction_indices, instructions);
                if (!call || (call->flow_flags & flow_call) == 0)
                    continue;
                std::uint64_t target_end = 0;
                if (!checked_add_u64(call->target_fact_begin,
                        call->target_fact_count, target_end) ||
                    target_end > targets.size()) {
                    failure.report(shard, make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "call target-fact range is invalid", "cfg_calls"));
                    return;
                }
                for (std::uint64_t target_index = call->target_fact_begin;
                     target_index < target_end; ++target_index) {
                    const auto& target = targets[static_cast<std::size_t>(target_index)];
                    if (target.kind != target_kind_record_t::data &&
                        target.kind != target_kind_record_t::call)
                        continue;
                    const auto slot = to_rva(image, target.target);
                    const auto imported = slot ? import_at(*slot) : nullptr;
                    if (!imported)
                        continue;
                    edge_record_t edge;
                    edge.source_entity = result.blocks[index].id;
                    edge.source = call->address;
                    edge.target = target.target;
                    edge.kind = edge_kind_t::call;
                    edge.provenance = fact_provenance_t::relocation;
                    edge.confidence = (std::min<std::uint8_t>)(call->confidence, 95);
                    auto appended = edges.append(std::move(edge), limits.max_edges,
                        import_budget, "cfg_calls",
                        "import call edge storage exceeds analysis budget");
                    if (!appended) {
                        failure.report(shard, appended.error());
                        return;
                    }
                    if (imported->name && known_noreturn_name(*imported->name))
                        noreturn_sources[index] = 1;
                    break;
                }
            }
        });
    });
    if (failure.failed.load(std::memory_order_relaxed))
        return workspace_result_t<function_recovery_result_t>::failure(failure.take_error());
    merge_clock_t merge_clock;
    std::uint64_t import_total = 0;
    for (const auto& edges : shard_import_edges) {
        if (!checked_add_u64(import_total, edges.values.size(), import_total)) {
            return workspace_result_t<function_recovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                    "import call edge storage exceeds analysis budget", "cfg_calls"));
        }
    }
    if (import_total > limits.max_edges ||
        result.edges.size() > limits.max_edges - import_total) {
        return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "import call edge storage exceeds analysis budget", "cfg_calls"));
    }
    std::uint64_t import_bytes = 0;
    if (!checked_mul_u64(import_total, sizeof(edge_record_t), import_bytes)) {
        return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "import call edge storage exceeds analysis budget", "cfg_calls"));
    }
    auto accounted = account_bytes(result.storage_bytes, import_bytes,
        limits.max_result_bytes, "cfg_calls",
        "import call edge storage exceeds analysis budget");
    if (!accounted)
        return workspace_result_t<function_recovery_result_t>::failure(accounted.error());
    result.edges.reserve(result.edges.size() + static_cast<std::size_t>(import_total));
    for (auto& edges : shard_import_edges) {
        for (auto& edge : edges.values)
            result.edges.push_back(std::move(edge));
    }
    std::vector<std::uint8_t> keep_flags(result.edges.size(), 0);
    {
        const auto edge_shards = partition_shards(result.edges.size(),
            pass_shard_count(result.edges.size(), kIndexShardFloor));
        run_sharded(edge_shards.size(), [&](std::size_t shard) {
            const auto range = edge_shards[shard];
            shard_poll_t poll{&cancel, &failure, shard, "cfg_calls"};
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if (poll.stopped(index - range.begin))
                    return;
                const auto source = block_ids.find(result.edges[index].source_entity);
                const bool remove = result.edges[index].kind == edge_kind_t::fallthrough &&
                    source && noreturn_sources[*source] != 0;
                keep_flags[index] = remove ? 0 : 1;
            }
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<function_recovery_result_t>::failure(
                failure.take_error());
    }
    {
        const auto keep_shards = partition_shards(result.edges.size(),
            pass_shard_count(result.edges.size(), kIndexShardFloor));
        std::vector<std::uint64_t> shard_kept(keep_shards.size(), 0);
        run_sharded(keep_shards.size(), [&](std::size_t shard) {
            const auto range = keep_shards[shard];
            std::uint64_t kept = 0;
            for (std::size_t index = range.begin; index < range.end; ++index)
                kept += keep_flags[index] != 0 ? 1ULL : 0ULL;
            shard_kept[shard] = kept;
        });
        std::uint64_t kept_total = 0;
        for (auto& base : shard_kept) {
            const auto offset = kept_total;
            kept_total += base;
            base = offset;
        }
        std::vector<edge_record_t> kept_edges(static_cast<std::size_t>(kept_total));
        run_sharded(keep_shards.size(), [&](std::size_t shard) {
            const auto range = keep_shards[shard];
            auto cursor = shard_kept[shard];
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if (keep_flags[index] != 0) {
                    kept_edges[static_cast<std::size_t>(cursor++)] =
                        std::move(result.edges[index]);
                }
            }
        });
        result.edges = std::move(kept_edges);
    }
    parallel_sort(result.edges.begin(), result.edges.end(), edge_less);
    parallel_unique_erase(result.edges, edge_equal);
    for (std::size_t index = 0; index < result.edges.size(); ++index)
        result.edges[index].id =
            kEdgeEntityTag | static_cast<std::uint64_t>(index + 1);
    result.shard_merge_ns += merge_clock.elapsed_ns();
    return workspace_result_t<function_recovery_result_t>::success(std::move(result));
}

}
