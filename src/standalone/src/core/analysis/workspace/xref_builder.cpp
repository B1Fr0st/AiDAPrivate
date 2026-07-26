#include "xref_builder.hpp"

#include "checked_range.hpp"

#include <algorithm>
#include <new>
#include <stdexcept>
#include <tuple>
#include <unordered_set>
#include <utility>

namespace aida::analysis {
namespace {

constexpr std::uint64_t kXrefEntityTag = 5ULL << 56;
constexpr std::uint64_t kTypeXrefEntityTag = 9ULL << 56;

workspace_error_t stop_error(const cancellation_token_t& cancel) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "xref analysis deadline exceeded", "xrefs");
        error.deadline = true;
        error.cancellation = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "xref analysis cancelled", "xrefs");
    error.cancellation = true;
    return error;
}

std::optional<std::uint64_t> to_rva(const workspace_image_t& image,
                                    const address_t& address) noexcept {
    if (address.architecture != image.architecture || address.mode != image.architecture_mode)
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

bool valid_address(const address_t& address) noexcept {
    return address.space <= address_space_id_t::live_virtual &&
           workspace_architecture_mode_matches(address.architecture, address.mode);
}

std::uint8_t operand_access(const instruction_record_t& instruction,
                            const target_fact_t& target,
                            const std::vector<operand_fact_t>& operands) noexcept {
    std::uint64_t end = 0;
    if (!checked_add_u64(instruction.operand_fact_begin,
            instruction.operand_fact_count, end) || end > operands.size())
        return 0;
    const operand_fact_t* by_index = nullptr;
    for (std::uint64_t index = instruction.operand_fact_begin; index < end; ++index) {
        const auto& operand = operands[static_cast<std::size_t>(index)];
        if (target.operand_fact_id != 0 && operand.id == target.operand_fact_id)
            return operand.access;
        if (operand.operand_index == target.operand_index)
            by_index = &operand;
    }
    return by_index ? by_index->access : 0;
}

bool stronger(const xref_record_t& lhs, const xref_record_t& rhs) noexcept {
    if (provenance_rank(lhs.provenance) != provenance_rank(rhs.provenance))
        return provenance_rank(lhs.provenance) > provenance_rank(rhs.provenance);
    return lhs.confidence > rhs.confidence;
}

bool stronger(const type_reference_fact_t& lhs,
              const type_reference_fact_t& rhs) noexcept {
    if (metadata_provenance_rank(lhs.provenance) !=
        metadata_provenance_rank(rhs.provenance))
        return metadata_provenance_rank(lhs.provenance) >
               metadata_provenance_rank(rhs.provenance);
    if (lhs.confidence != rhs.confidence)
        return lhs.confidence > rhs.confidence;
    return lhs.source_key < rhs.source_key;
}

bool same_type_reference(const type_reference_fact_t& lhs,
                         const type_reference_fact_t& rhs) noexcept {
    return lhs.source == rhs.source && lhs.target == rhs.target &&
           lhs.source_entity == rhs.source_entity &&
           lhs.target_entity == rhs.target_entity && lhs.kind == rhs.kind;
}

workspace_result_t<xref_build_result_t> build_impl(
    const workspace_image_t& image,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<operand_fact_t>& operands,
    const std::vector<target_fact_t>& targets,
    data_discovery_result_t data,
    std::vector<type_reference_fact_t> type_references,
    const xref_build_limits_t& limits,
    const cancellation_token_t& cancel) {
    if (limits.max_xrefs == 0 || limits.max_type_xrefs == 0 ||
        limits.max_data_candidates == 0 || limits.max_pointer_facts == 0 ||
        limits.max_data_conflicts == 0 || limits.max_result_bytes == 0 ||
        limits.cancellation_check_interval == 0 ||
        data.candidates.size() > limits.max_data_candidates ||
        data.pointer_facts.size() > limits.max_pointer_facts ||
        data.conflicts.size() > limits.max_data_conflicts ||
        type_references.size() > limits.max_type_xrefs) {
        return workspace_result_t<xref_build_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "xref build inputs or limits are invalid", "xrefs"));
    }
    xref_build_result_t result;
    result.bytes_scanned = data.bytes_scanned;
    result.mapped_bytes = data.mapped_bytes;
    result.provider_leases = data.provider_leases;
    result.invalid_pointer_values = data.invalid_pointer_values;
    std::uint64_t storage_bytes = 0;
    const auto charge_existing = [&](std::uint64_t count, std::uint64_t width) -> bool {
        std::uint64_t bytes = 0;
        return checked_mul_u64(count, width, bytes) &&
               checked_add_u64(storage_bytes, bytes, storage_bytes) &&
               storage_bytes <= limits.max_result_bytes;
    };
    if (!charge_existing(data.candidates.size(), sizeof(data_candidate_record_t)) ||
        !charge_existing(data.pointer_facts.size(), sizeof(data_pointer_fact_t)) ||
        !charge_existing(data.conflicts.size(), sizeof(data_candidate_conflict_t)) ||
        !charge_existing(type_references.size(), sizeof(type_reference_fact_t))) {
        return workspace_result_t<xref_build_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "xref input storage exceeds its memory bound", "xrefs"));
    }
    const auto append_xref = [&](xref_record_t value) -> workspace_result_t<void> {
        if (result.xrefs.size() >= limits.max_xrefs ||
            storage_bytes > limits.max_result_bytes - sizeof(xref_record_t)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "xref storage exceeds its memory bound", "xrefs"));
        }
        storage_bytes += sizeof(xref_record_t);
        result.xrefs.push_back(std::move(value));
        return workspace_result_t<void>::success();
    };
    std::unordered_set<std::uint64_t> import_rvas;
    import_rvas.reserve(image.imports.size());
    for (const auto& imported : image.imports) {
        const auto import_rva = to_rva(image, imported.address);
        if (import_rva)
            import_rvas.insert(*import_rva);
    }
    struct chunk_output_t {
        std::vector<xref_record_t> xrefs;
        std::optional<workspace_error_t> error;
    };
    auto process_chunk = [&](std::size_t begin, std::size_t end) -> chunk_output_t {
        chunk_output_t output;
        std::uint64_t checks = 0;
        for (std::size_t i = begin; i < end; ++i) {
            const auto& instruction = instructions[i];
            if (++checks >= limits.cancellation_check_interval) {
                checks = 0;
                if (cancel.stop_requested()) {
                    output.error = stop_error(cancel);
                    return output;
                }
            }
            std::uint64_t operand_end = 0;
            std::uint64_t target_end = 0;
            if (!checked_add_u64(instruction.operand_fact_begin,
                    instruction.operand_fact_count, operand_end) || operand_end > operands.size() ||
                !checked_add_u64(instruction.target_fact_begin,
                    instruction.target_fact_count, target_end) || target_end > targets.size()) {
                output.error = make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "instruction fact range is invalid", "xrefs");
                return output;
            }
            for (std::uint64_t index = instruction.target_fact_begin; index < target_end; ++index) {
                const auto& target = targets[static_cast<std::size_t>(index)];
                if (!valid_address(instruction.address) || !valid_address(target.target) ||
                    (target.instruction_id != 0 && target.instruction_id != instruction.id)) {
                    output.error = make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "xref target fact is invalid", "xrefs");
                    return output;
                }
                const auto target_rva = to_rva(image, target.target);
                const bool imported_call = target.kind == target_kind_record_t::call &&
                    target_rva && import_rvas.count(*target_rva) > 0;
                auto make_xref = [&](xref_kind_t kind) {
                    xref_record_t xref;
                    xref.source = instruction.address;
                    xref.target = target.target;
                    xref.kind = kind;
                    xref.provenance = imported_call
                        ? fact_provenance_t::relocation : instruction.provenance;
                    xref.confidence = imported_call
                        ? (std::min)(instruction.confidence, static_cast<std::uint8_t>(95))
                        : instruction.confidence;
                    return xref;
                };
                if (target.kind == target_kind_record_t::call) {
                    output.xrefs.push_back(make_xref(xref_kind_t::call));
                } else if (target.kind == target_kind_record_t::branch ||
                           target.kind == target_kind_record_t::fallthrough) {
                    output.xrefs.push_back(make_xref(xref_kind_t::code));
                } else {
                    const auto access = operand_access(instruction, target, operands);
                    if ((access & 1U) != 0)
                        output.xrefs.push_back(make_xref(xref_kind_t::read));
                    if ((access & 2U) != 0) {
                        output.xrefs.push_back(make_xref(xref_kind_t::write));
                    } else if ((access & 1U) == 0) {
                        output.xrefs.push_back(make_xref(xref_kind_t::address));
                    }
                }
            }
        }
        return output;
    };
    auto chunk_output = process_chunk(0, instructions.size());
    if (chunk_output.error)
        return workspace_result_t<xref_build_result_t>::failure(*chunk_output.error);
    for (auto& xref : chunk_output.xrefs) {
        auto appended = append_xref(std::move(xref));
        if (!appended)
            return workspace_result_t<xref_build_result_t>::failure(appended.error());
    }
    std::uint64_t checks = 0;
    for (const auto& pointer : data.pointer_facts) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<xref_build_result_t>::failure(stop_error(cancel));
        }
        if (!valid_address(pointer.slot) || !valid_address(pointer.target) ||
            pointer.confidence > 100) {
            return workspace_result_t<xref_build_result_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "data pointer fact is invalid", "xrefs"));
        }
        xref_record_t xref;
        xref.source = pointer.slot;
        xref.target = pointer.target;
        xref.kind = pointer.candidate_kind == data_candidate_kind_t::relocation_slot
            ? xref_kind_t::relocation : xref_kind_t::address;
        xref.provenance = pointer.provenance;
        xref.confidence = pointer.confidence;
        auto appended = append_xref(std::move(xref));
        if (!appended)
            return workspace_result_t<xref_build_result_t>::failure(appended.error());
    }
    if (cancel.stop_requested())
        return workspace_result_t<xref_build_result_t>::failure(stop_error(cancel));
    std::sort(result.xrefs.begin(), result.xrefs.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.source != rhs.source)
            return lhs.source < rhs.source;
        if (lhs.target != rhs.target)
            return lhs.target < rhs.target;
        if (lhs.kind != rhs.kind)
            return lhs.kind < rhs.kind;
        if (stronger(lhs, rhs))
            return true;
        if (stronger(rhs, lhs))
            return false;
        return false;
    });
    const auto xref_end = std::unique(result.xrefs.begin(), result.xrefs.end(),
        [](const auto& lhs, const auto& rhs) {
            return lhs.source == rhs.source && lhs.target == rhs.target &&
                   lhs.kind == rhs.kind;
        });
    result.duplicate_xrefs = static_cast<std::uint64_t>(
        std::distance(xref_end, result.xrefs.end()));
    result.xrefs.erase(xref_end, result.xrefs.end());
    for (std::size_t index = 0; index < result.xrefs.size(); ++index)
        result.xrefs[index].id = kXrefEntityTag | static_cast<std::uint64_t>(index + 1);
    for (const auto& reference : type_references) {
        if (reference.confidence > 100 ||
            reference.provenance > metadata_provenance_t::managed_metadata ||
            reference.kind > type_reference_kind_t::managed_reference ||
            (!reference.source && !reference.target && reference.source_entity == 0 &&
             reference.target_entity == 0) ||
            (reference.source && !valid_address(*reference.source)) ||
            (reference.target && !valid_address(*reference.target))) {
            return workspace_result_t<xref_build_result_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "type reference fact is invalid", "xrefs"));
        }
    }
    std::sort(type_references.begin(), type_references.end(), [](const auto& lhs,
                                                                 const auto& rhs) {
        if (lhs.source != rhs.source)
            return lhs.source < rhs.source;
        if (lhs.target != rhs.target)
            return lhs.target < rhs.target;
        if (lhs.source_entity != rhs.source_entity)
            return lhs.source_entity < rhs.source_entity;
        if (lhs.target_entity != rhs.target_entity)
            return lhs.target_entity < rhs.target_entity;
        if (lhs.kind != rhs.kind)
            return lhs.kind < rhs.kind;
        if (stronger(lhs, rhs))
            return true;
        if (stronger(rhs, lhs))
            return false;
        return lhs.source_key < rhs.source_key;
    });
    const auto type_end = std::unique(type_references.begin(), type_references.end(),
        same_type_reference);
    result.duplicate_type_xrefs = static_cast<std::uint64_t>(
        std::distance(type_end, type_references.end()));
    type_references.erase(type_end, type_references.end());
    for (std::size_t index = 0; index < type_references.size(); ++index)
        type_references[index].id = kTypeXrefEntityTag |
            static_cast<std::uint64_t>(index + 1);
    result.type_xrefs = std::move(type_references);
    result.data_candidates = std::move(data.candidates);
    result.data_pointer_facts = std::move(data.pointer_facts);
    result.data_conflicts = std::move(data.conflicts);
    return workspace_result_t<xref_build_result_t>::success(std::move(result));
}

}

workspace_result_t<xref_build_result_t> xref_builder_t::build(
    const workspace_image_t& image, const byte_provider_t& provider,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<operand_fact_t>& operands,
    const std::vector<target_fact_t>& targets,
    const xref_build_limits_t& limits, const cancellation_token_t& cancel) {
    return build(image, provider, instructions, operands, targets, {}, {}, limits, cancel);
}

workspace_result_t<xref_build_result_t> xref_builder_t::build(
    const workspace_image_t& image, const byte_provider_t& provider,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<operand_fact_t>& operands,
    const std::vector<target_fact_t>& targets,
    const std::vector<data_pointer_seed_t>& pointer_seeds,
    const std::vector<type_reference_fact_t>& type_references,
    const xref_build_limits_t& limits, const cancellation_token_t& cancel) {
    data_discovery_limits_t data_limits;
    data_limits.max_candidates = limits.max_data_candidates;
    data_limits.max_pointer_facts = limits.max_pointer_facts;
    data_limits.max_conflicts = limits.max_data_conflicts;
    data_limits.max_pointer_seeds = (std::max<std::uint64_t>)(1, pointer_seeds.size());
    data_limits.max_pointer_scan_bytes = limits.max_pointer_scan_bytes;
    data_limits.max_result_bytes = limits.max_result_bytes;
    data_limits.read_window_bytes = limits.read_window_bytes;
    data_limits.cancellation_check_interval = limits.cancellation_check_interval;
    auto data = data_discovery_t::discover(image, provider, instructions, targets,
        pointer_seeds, data_limits, cancel);
    if (!data)
        return workspace_result_t<xref_build_result_t>::failure(data.error());
    return build(image, instructions, operands, targets, data.take_value(),
        type_references, limits, cancel);
}

workspace_result_t<xref_build_result_t> xref_builder_t::build(
    const workspace_image_t& image,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<operand_fact_t>& operands,
    const std::vector<target_fact_t>& targets,
    data_discovery_result_t data,
    std::vector<type_reference_fact_t> type_references,
    const xref_build_limits_t& limits, const cancellation_token_t& cancel) {
    try {
        return build_impl(image, instructions, operands, targets, std::move(data),
            std::move(type_references), limits, cancel);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<xref_build_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "xref analysis allocation failed", "xrefs"));
    } catch (const std::length_error&) {
        return workspace_result_t<xref_build_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "xref analysis allocation length is unsupported", "xrefs"));
    }
}

workspace_result_t<void> xref_builder_t::publish(
    analysis_snapshot_t& snapshot,
    xref_build_result_t xrefs,
    string_discovery_result_t strings,
    symbol_type_candidate_result_t symbols,
    const cancellation_token_t& cancel)
{
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(stop_error(cancel));
    const auto same_reference = [](const type_reference_fact_t& lhs,
                                   const type_reference_fact_t& rhs) noexcept {
        return lhs.id == rhs.id && lhs.source == rhs.source && lhs.target == rhs.target &&
            lhs.source_entity == rhs.source_entity &&
            lhs.target_entity == rhs.target_entity && lhs.kind == rhs.kind &&
            lhs.provenance == rhs.provenance && lhs.confidence == rhs.confidence &&
            lhs.source_key == rhs.source_key;
    };
    if (!xrefs.type_xrefs.empty() && !symbols.type_references.empty()) {
        if (xrefs.type_xrefs.size() != symbols.type_references.size() ||
            !std::equal(xrefs.type_xrefs.begin(), xrefs.type_xrefs.end(),
                symbols.type_references.begin(), same_reference)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "xref and symbol pipelines produced different type references",
                "analysis_discovery_publish"));
        }
    } else if (xrefs.type_xrefs.empty()) {
        xrefs.type_xrefs = std::move(symbols.type_references);
    }
    for (std::size_t index = 0; index < xrefs.xrefs.size(); ++index) {
        const auto& xref = xrefs.xrefs[index];
        if (entity_domain(xref.id) != 5 || entity_ordinal(xref.id) != index + 1 ||
            !valid_address(xref.source) || !valid_address(xref.target) ||
            xref.kind > xref_kind_t::relocation ||
            xref.provenance > fact_provenance_t::decompiler_feedback ||
            xref.confidence > 100) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "xref publication contains an invalid fact", "analysis_discovery_publish"));
        }
    }
    for (std::size_t index = 0; index < strings.strings.size(); ++index) {
        const auto& string = strings.strings[index];
        if (entity_domain(string.id) != 6 || entity_ordinal(string.id) != index + 1 ||
            !valid_address(string.address) || string.byte_length == 0 ||
            string.encoding > string_encoding_t::utf16_le || string.value.empty() ||
            string.provenance > fact_provenance_t::decompiler_feedback ||
            string.confidence > 100) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "string publication contains an invalid fact", "analysis_discovery_publish"));
        }
    }
    for (std::size_t index = 0; index < symbols.symbols.size(); ++index) {
        const auto& symbol = symbols.symbols[index];
        if (entity_domain(symbol.id) != 7 || entity_ordinal(symbol.id) != index + 1 ||
            !valid_address(symbol.address) || symbol.name.empty() ||
            symbol.kind > symbol_kind_t::metadata ||
            symbol.provenance > fact_provenance_t::decompiler_feedback ||
            symbol.confidence > 100) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "symbol publication contains an invalid fact", "analysis_discovery_publish"));
        }
    }
    analysis_rich_fact_publication_t rich;
    rich.data_candidates = std::move(xrefs.data_candidates);
    rich.data_pointer_facts = std::move(xrefs.data_pointer_facts);
    rich.data_conflicts = std::move(xrefs.data_conflicts);
    rich.type_candidates = std::move(symbols.type_candidates);
    rich.type_references = std::move(xrefs.type_xrefs);
    rich.metadata_conflicts = std::move(symbols.conflicts);
    auto validated = validate_rich_fact_publication(snapshot, rich, cancel);
    if (!validated)
        return validated;
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(stop_error(cancel));
    snapshot.xrefs = std::move(xrefs.xrefs);
    snapshot.strings = std::move(strings.strings);
    snapshot.symbols = std::move(symbols.symbols);
    snapshot.rich_facts = std::move(rich);
    return workspace_result_t<void>::success();
}

}
