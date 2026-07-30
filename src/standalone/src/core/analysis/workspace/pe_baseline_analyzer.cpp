#include "pe_baseline_analyzer.hpp"

#include "checked_range.hpp"
#include "decode_materializer.hpp"
#include "parallel_pass.hpp"
#include "persistence_queue.hpp"
#include "workspace_database.hpp"
#include "../mapped_window_cache.hpp"
#include "../decompiler/managed_entity_binding.hpp"
#include "../../../helpers/diag_log.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::uint64_t kInstructionEntityTag = 1ULL << 56;
constexpr std::uint64_t kTypeEntityTag = 10ULL << 56;

class phase_completion_guard_t final {
public:
    phase_completion_guard_t(analysis_metrics_t& metrics, phase_measurement_t& measurement) noexcept
        : metrics_(metrics), measurement_(measurement) {}

    ~phase_completion_guard_t() {
        if (measurement_.active)
            metrics_.end_phase(measurement_, 0, 0, 0, 0, true);
    }

private:
    analysis_metrics_t& metrics_;
    phase_measurement_t& measurement_;
};

struct image_range_t {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    std::uint32_t permissions = image_permission_none;
};

bool stronger_seed_evidence(fact_provenance_t lhs_provenance,
    std::uint8_t lhs_confidence, std::uint64_t lhs_source,
    fact_provenance_t rhs_provenance, std::uint8_t rhs_confidence,
    std::uint64_t rhs_source) noexcept {
    if (provenance_rank(lhs_provenance) != provenance_rank(rhs_provenance))
        return provenance_rank(lhs_provenance) > provenance_rank(rhs_provenance);
    if (lhs_confidence != rhs_confidence)
        return lhs_confidence > rhs_confidence;
    return lhs_source < rhs_source;
}

address_t rva_address(const workspace_image_t& image, std::uint64_t rva) noexcept {
    return {address_space_id_t::relative_virtual, rva, image.architecture,
        image.architecture_mode};
}

std::optional<std::uint64_t> to_rva(const workspace_image_t& image,
                                    const address_t& address) noexcept {
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

std::optional<std::uint64_t> to_rva_endpoint(const workspace_image_t& image,
                                             const address_t& address) noexcept {
    if (address.architecture != image.architecture ||
        address.mode != image.architecture_mode)
        return std::nullopt;
    if (address.space == address_space_id_t::relative_virtual)
        return address.value <= image.image_size ? std::optional<std::uint64_t>(address.value)
                                                 : std::nullopt;
    if ((address.space == address_space_id_t::virtual_address ||
         address.space == address_space_id_t::live_virtual) &&
        address.value >= image.image_base) {
        const auto rva = address.value - image.image_base;
        return rva <= image.image_size ? std::optional<std::uint64_t>(rva) : std::nullopt;
    }
    return std::nullopt;
}

std::vector<image_range_t> image_ranges(const workspace_image_t& image) {
    std::vector<image_range_t> ranges;
    const auto append = [&ranges, &image](const auto& region) {
        const auto extent = std::max(region.virtual_size, region.file_size);
        std::uint64_t end = 0;
        if (extent == 0 || !checked_add_u64(region.virtual_address, extent, end) ||
            end > image.image_size)
            return;
        ranges.push_back({region.virtual_address, end, region.permissions});
    };
    if (!image.sections.empty()) {
        for (const auto& section : image.sections)
            append(section);
    } else {
        for (const auto& segment : image.segments)
            append(segment);
    }
    std::sort(ranges.begin(), ranges.end(), [](const image_range_t& lhs, const image_range_t& rhs) {
        if (lhs.start != rhs.start)
            return lhs.start < rhs.start;
        if (lhs.end != rhs.end)
            return lhs.end < rhs.end;
        return lhs.permissions < rhs.permissions;
    });
    return ranges;
}

std::vector<image_range_t> executable_ranges(const workspace_image_t& image) {
    auto ranges = image_ranges(image);
    ranges.erase(std::remove_if(ranges.begin(), ranges.end(), [](const image_range_t& range) {
        return (range.permissions & image_permission_execute) == 0;
    }), ranges.end());
    return ranges;
}

bool managed_bytecode_only_image(const workspace_image_t& image) noexcept {
    const auto jvm = image.format == format_id_t::classfile &&
        image.architecture == architecture_id_t::jvm_bytecode &&
        image.architecture_mode == architecture_mode_t::jvm &&
        image.abi == abi_id_t::jvm;
    const auto dalvik_format = image.format == format_id_t::dex ||
        image.format == format_id_t::oat || image.format == format_id_t::vdex;
    const auto dalvik = dalvik_format &&
        image.architecture == architecture_id_t::dalvik_bytecode &&
        image.architecture_mode == architecture_mode_t::dalvik &&
        image.abi == abi_id_t::dalvik;
    return jvm || dalvik;
}

workspace_error_t cancellation_error(const cancellation_token_t& local,
    const cancellation_token_t& workspace, const char* phase);

workspace_result_t<std::vector<coverage_span_t>> build_managed_bytecode_coverage(
    const workspace_image_t& image, std::uint64_t maximum_spans,
    const cancellation_token_t& cancel) {
    std::vector<coverage_span_t> coverage;
    const auto ranges = executable_ranges(image);
    coverage.reserve((std::min)(maximum_spans,
        static_cast<std::uint64_t>(ranges.size())));
    for (const auto& range : ranges) {
        if (cancel.stop_requested()) {
            return workspace_result_t<std::vector<coverage_span_t>>::failure(
                cancellation_error(cancel, cancel, "decode_merge"));
        }
        if (coverage.size() >= maximum_spans) {
            return workspace_result_t<std::vector<coverage_span_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "managed bytecode coverage exceeds analysis budget", "decode_merge"));
        }
        coverage_span_t span;
        span.start = rva_address(image, range.start);
        span.size = range.end - range.start;
        span.reason = coverage_reason_t::excluded_by_metadata;
        span.provenance = fact_provenance_t::linear_validation;
        span.confidence = 100;
        coverage.push_back(std::move(span));
    }
    return workspace_result_t<std::vector<coverage_span_t>>::success(std::move(coverage));
}

bool executable_rva(const workspace_image_t& image, std::uint64_t rva) {
    const auto ranges = executable_ranges(image);
    const auto found = std::upper_bound(ranges.begin(), ranges.end(), rva,
        [](std::uint64_t value, const image_range_t& range) { return value < range.start; });
    if (found == ranges.begin())
        return false;
    const auto& range = *std::prev(found);
    return rva >= range.start && rva < range.end;
}

bool supports_x86_tile_decode(const arch_decoder_registration_t& registration) noexcept {
    const auto& key = registration.key;
    if (key.architecture == architecture_id_t::x86 &&
        (key.mode == architecture_mode_t::x86_16 || key.mode == architecture_mode_t::x86_32))
        return registration.implementation_id == "zydis.x86";
    return key.architecture == architecture_id_t::x86_64 &&
           key.mode == architecture_mode_t::x86_64 &&
           registration.implementation_id == "zydis.x86_64";
}

workspace_error_t cancellation_error(const cancellation_token_t& local,
    const cancellation_token_t& workspace, const char* phase) {
    if (local.deadline_exceeded() || workspace.deadline_exceeded()) {
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

workspace_result_t<void> validate_coverage_linear_cancellable(
    const analysis_snapshot_t& snapshot, const cancellation_token_t& cancel) {
    if (!snapshot.normalized_image) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "coverage validation requires a normalized image", "search_index"));
    }
    const auto ranges = executable_ranges(*snapshot.normalized_image);
    if (ranges.empty())
        return workspace_result_t<void>::success();
    const auto& spans = snapshot.coverage;
    const auto rva_begin = std::partition_point(spans.begin(), spans.end(),
        [](const coverage_span_t& span) {
            return span.start.space < address_space_id_t::relative_virtual;
        });
    const auto rva_end = std::partition_point(spans.begin(), spans.end(),
        [](const coverage_span_t& span) {
            return span.start.space <= address_space_id_t::relative_virtual;
        });
    const auto shards = parallel_shards(ranges.size(), 0);
    return parallel_validate_shards(shards, 1,
        [&](std::size_t, const parallel_shard_t& shard) -> ordered_error_t {
            ordered_error_t result;
            std::uint64_t visits = 0;
            for (std::size_t range_index = shard.begin; range_index < shard.end;
                 ++range_index) {
                if ((visits++ & 255U) == 0 && cancel.stop_requested())
                    return ordered_error_t{static_cast<std::uint64_t>(range_index),
                        cancellation_error(cancel, cancel, "search_index")};
                const auto& range = ranges[range_index];
                std::uint64_t cursor = range.start;
                const auto first = std::partition_point(rva_begin, rva_end,
                    [&](const coverage_span_t& span) {
                        return span.start.value <= range.start &&
                            span.size <= range.start - span.start.value;
                    });
                for (auto it = first; it != rva_end; ++it) {
                    if ((visits++ & 255U) == 0 && cancel.stop_requested())
                        return ordered_error_t{static_cast<std::uint64_t>(range_index),
                            cancellation_error(cancel, cancel, "search_index")};
                    const auto& span = *it;
                    if (span.start.space != address_space_id_t::relative_virtual)
                        continue;
                    std::uint64_t end = 0;
                    if (!checked_add_u64(span.start.value, span.size, end))
                        return ordered_error_t{static_cast<std::uint64_t>(range_index),
                            make_workspace_error(workspace_error_code_t::integrity_failure,
                                "coverage span overflows during validation", "search_index")};
                    if (end <= range.start)
                        continue;
                    if (span.start.value >= range.end)
                        break;
                    if (span.start.value != cursor || end > range.end || span.size == 0 ||
                        span.reason == coverage_reason_t::pending)
                        return ordered_error_t{static_cast<std::uint64_t>(range_index),
                            make_workspace_error(workspace_error_code_t::integrity_failure,
                                "executable coverage contains a gap, overlap, or pending span",
                                "search_index")};
                    cursor = end;
                }
                if (cursor != range.end)
                    return ordered_error_t{static_cast<std::uint64_t>(range_index),
                        make_workspace_error(workspace_error_code_t::integrity_failure,
                            "executable coverage is incomplete", "search_index")};
            }
            return result;
        }, cancel);
}

workspace_result_t<image_layout_index_t> build_baseline_image_layout(
    const workspace_image_t& image, const provider_snapshot_t& provider,
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<image_layout_index_t>::failure(
            cancellation_error(cancel, cancel, "parse"));
    image_layout_definition_t definition;
    definition.identity.content_id = image.workspace_binary_id;
    definition.identity.format = image.format;
    definition.identity.endian = image.endian;
    definition.identity.address_width_bits = image.address_width_bits;
    definition.identity.image_base = image.image_base;
    definition.identity.provider_size = provider.size();
    definition.identity.member = image.member;
    if (image.member) {
        definition.members.push_back({0U, image.member->normalized_member_path, 0U,
            provider.size()});
    }
    std::uint32_t mapping_id = 0;
    const auto append_region = [&](const auto& region, bool section)
        -> workspace_result_t<void> {
        const auto virtual_size = (std::max)(region.virtual_size, region.file_size);
        if (virtual_size == 0)
            return workspace_result_t<void>::success();
        std::uint64_t virtual_address = 0;
        if (!checked_add_u64(image.image_base, region.virtual_address, virtual_address) ||
            (region.file_size != 0 &&
             (region.file_offset > provider.size() ||
              region.file_size > provider.size() - region.file_offset))) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "normalized image region exceeds the immutable provider", "parse"));
        }
        image_layout_mapping_t mapping;
        mapping.id = mapping_id++;
        mapping.rva = region.virtual_address;
        mapping.virtual_address = virtual_address;
        mapping.virtual_size = virtual_size;
        mapping.file_offset = region.file_offset;
        mapping.file_size = region.file_size;
        mapping.permissions = region.permissions;
        if (section) {
            mapping.section_id = region.index;
            definition.sections.push_back({region.index, region.name,
                region.virtual_address, virtual_size, region.file_offset,
                region.file_size, region.permissions});
        } else {
            mapping.segment_id = region.index;
            definition.segments.push_back({region.index, region.name,
                region.virtual_address, virtual_size, region.file_offset,
                region.file_size, region.permissions});
        }
        if (image.member)
            mapping.member_id = 0U;
        definition.mappings.push_back(std::move(mapping));
        return workspace_result_t<void>::success();
    };
    if (!image.sections.empty()) {
        for (const auto& section : image.sections) {
            if (cancel.stop_requested())
                return workspace_result_t<image_layout_index_t>::failure(
                    cancellation_error(cancel, cancel, "parse"));
            auto appended = append_region(section, true);
            if (!appended)
                return workspace_result_t<image_layout_index_t>::failure(appended.error());
        }
    } else if (!image.segments.empty()) {
        for (const auto& segment : image.segments) {
            if (cancel.stop_requested())
                return workspace_result_t<image_layout_index_t>::failure(
                    cancellation_error(cancel, cancel, "parse"));
            auto appended = append_region(segment, false);
            if (!appended)
                return workspace_result_t<image_layout_index_t>::failure(appended.error());
        }
    } else {
        for (const auto& source : image.address_mappings) {
            if (source.source_space != address_space_id_t::file_offset ||
                source.target_space != address_space_id_t::relative_virtual ||
                source.size == 0)
                continue;
            std::uint64_t virtual_address = 0;
            if (!checked_add_u64(image.image_base, source.target_start, virtual_address) ||
                source.source_start > provider.size() ||
                source.size > provider.size() - source.source_start) {
                return workspace_result_t<image_layout_index_t>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "normalized image mapping exceeds the immutable provider", "parse"));
            }
            image_layout_mapping_t mapping;
            mapping.id = mapping_id++;
            mapping.rva = source.target_start;
            mapping.virtual_address = virtual_address;
            mapping.virtual_size = source.size;
            mapping.file_offset = source.source_start;
            mapping.file_size = source.size;
            mapping.permissions = source.permissions;
            if (image.member)
                mapping.member_id = 0U;
            definition.mappings.push_back(std::move(mapping));
        }
    }
    return image_layout_index_t::build(std::move(definition));
}

workspace_result_t<std::vector<coverage_span_t>> build_canonical_decode_coverage(
    const workspace_image_t& image, const image_layout_index_t& layout,
    const std::vector<instruction_record_t>& instructions, std::uint64_t maximum_spans,
    const cancellation_token_t& cancel) {
    std::vector<coverage_span_t> coverage;
    const auto append = [&](std::uint64_t start, std::uint64_t size,
                            coverage_reason_t reason, fact_provenance_t provenance,
                            std::uint8_t confidence, tile_coverage_detail_t detail)
        -> workspace_result_t<void> {
        if (size == 0)
            return workspace_result_t<void>::success();
        if (coverage.size() >= maximum_spans) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "canonical decode coverage exceeds analysis budget", "decode_merge"));
        }
        coverage_span_t span;
        span.start = rva_address(image, start);
        span.size = size;
        span.reason = reason;
        span.provenance = provenance;
        span.confidence = confidence;
        span.detail_code = static_cast<std::uint32_t>(detail);
        coverage.push_back(std::move(span));
        return workspace_result_t<void>::success();
    };
    for (const auto& mapping : layout.mappings()) {
        if ((mapping.permissions & image_permission_execute) == 0 ||
            mapping.virtual_size == 0)
            continue;
        if (cancel.stop_requested())
            return workspace_result_t<std::vector<coverage_span_t>>::failure(
                cancellation_error(cancel, cancel, "decode_merge"));
        const auto initialized = (std::min)(mapping.file_size, mapping.virtual_size);
        std::uint64_t initialized_end = 0;
        std::uint64_t mapping_end = 0;
        if (!checked_add_u64(mapping.rva, initialized, initialized_end) ||
            !checked_add_u64(mapping.rva, mapping.virtual_size, mapping_end)) {
            return workspace_result_t<std::vector<coverage_span_t>>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                    "canonical decode coverage range overflowed", "decode_merge"));
        }
        auto found = std::lower_bound(instructions.begin(), instructions.end(), mapping.rva,
            [](const instruction_record_t& instruction, std::uint64_t rva) {
                return instruction.address.value < rva;
            });
        std::uint64_t cursor = mapping.rva;
        while (found != instructions.end() && found->address.value < initialized_end) {
            std::uint64_t instruction_end = 0;
            if (!checked_add_u64(found->address.value, found->length, instruction_end) ||
                found->address.value < cursor || instruction_end > initialized_end) {
                return workspace_result_t<std::vector<coverage_span_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "tile decode instruction crosses canonical mapping ownership",
                        "decode_merge"));
            }
            auto gap = append(cursor, found->address.value - cursor,
                coverage_reason_t::undecodable, fact_provenance_t::gap_recovery, 25,
                tile_coverage_detail_t::undecodable_gap);
            if (!gap)
                return workspace_result_t<std::vector<coverage_span_t>>::failure(gap.error());
            auto accepted = append(found->address.value, found->length,
                coverage_reason_t::decoded, found->provenance, found->confidence,
                tile_coverage_detail_t::none);
            if (!accepted)
                return workspace_result_t<std::vector<coverage_span_t>>::failure(
                    accepted.error());
            cursor = instruction_end;
            ++found;
        }
        auto tail = append(cursor, initialized_end - cursor,
            coverage_reason_t::undecodable, fact_provenance_t::gap_recovery, 25,
            tile_coverage_detail_t::undecodable_gap);
        if (!tail)
            return workspace_result_t<std::vector<coverage_span_t>>::failure(tail.error());
        auto zero_fill = append(initialized_end, mapping_end - initialized_end,
            coverage_reason_t::undecodable, fact_provenance_t::linear_validation, 100,
            tile_coverage_detail_t::zero_fill);
        if (!zero_fill)
            return workspace_result_t<std::vector<coverage_span_t>>::failure(
                zero_fill.error());
    }
    return workspace_result_t<std::vector<coverage_span_t>>::success(std::move(coverage));
}

function_seed_sources_t group_function_seeds(const std::vector<function_seed_t>& seeds) {
    function_seed_sources_t sources;
    for (const auto& seed : seeds) {
        switch (seed.kind) {
            case function_seed_kind_t::image_entry:
                sources.image_entries.push_back(seed);
                break;
            case function_seed_kind_t::tls_callback:
                sources.tls_callbacks.push_back(seed);
                break;
            case function_seed_kind_t::export_entry:
                sources.exports.push_back(seed);
                break;
            case function_seed_kind_t::unwind_range:
                sources.unwind_ranges.push_back(seed);
                break;
            case function_seed_kind_t::debug_symbol:
                sources.symbols.push_back(seed);
                break;
            case function_seed_kind_t::load_config_entry:
                sources.load_config_entries.push_back(seed);
                break;
            case function_seed_kind_t::relocation_target:
                sources.relocation_targets.push_back(seed);
                break;
            case function_seed_kind_t::direct_call_target:
                sources.call_targets.push_back(seed);
                break;
            case function_seed_kind_t::validated_gap_target:
                sources.validated_gap_targets.push_back(seed);
                break;
            case function_seed_kind_t::pointer_target:
                sources.pointer_targets.push_back(seed);
                break;
        }
    }
    return sources;
}

workspace_result_t<std::vector<indirect_call_candidate_t>>
build_indirect_call_candidates(
    const std::vector<instruction_record_t>& instructions,
    const std::vector<target_fact_t>& targets,
    const std::vector<data_pointer_fact_t>& pointers,
    std::uint64_t maximum_candidates,
    std::uint32_t cancellation_check_interval,
    const cancellation_token_t& cancel)
{
    if (maximum_candidates == 0 || cancellation_check_interval == 0) {
        return workspace_result_t<std::vector<indirect_call_candidate_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "indirect call candidate limits are invalid", "call_graph_evidence"));
    }
    if (!std::is_sorted(pointers.begin(), pointers.end(),
            [](const data_pointer_fact_t& lhs, const data_pointer_fact_t& rhs) {
                return lhs.slot < rhs.slot;
            })) {
        return workspace_result_t<std::vector<indirect_call_candidate_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "data pointer facts are not ordered by slot", "call_graph_evidence"));
    }
    std::vector<indirect_call_candidate_t> candidates;
    std::uint64_t checks = 0;
    for (const auto& instruction : instructions) {
        if (++checks >= cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested()) {
                return workspace_result_t<
                    std::vector<indirect_call_candidate_t>>::failure(
                    cancellation_error(cancel, cancel, "call_graph_evidence"));
            }
        }
        if ((instruction.flow_flags & flow_indirect) == 0 ||
            (instruction.flow_flags & (flow_call | flow_branch)) == 0)
            continue;
        std::uint64_t target_end = 0;
        if (!checked_add_u64(instruction.target_fact_begin,
                instruction.target_fact_count, target_end) ||
            target_end > targets.size()) {
            return workspace_result_t<
                std::vector<indirect_call_candidate_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "indirect call target range is invalid", "call_graph_evidence"));
        }
        for (std::uint64_t target_index = instruction.target_fact_begin;
             target_index < target_end; ++target_index) {
            const auto& target = targets[static_cast<std::size_t>(target_index)];
            if (target.instruction_id != 0 &&
                target.instruction_id != instruction.id) {
                return workspace_result_t<
                    std::vector<indirect_call_candidate_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "indirect call target owner is invalid",
                        "call_graph_evidence"));
            }
            if (target.kind != target_kind_record_t::data)
                continue;
            auto pointer = std::lower_bound(pointers.begin(), pointers.end(),
                target.target,
                [](const data_pointer_fact_t& fact, const address_t& slot) {
                    return fact.slot < slot;
                });
            for (; pointer != pointers.end() && pointer->slot == target.target;
                 ++pointer) {
                if (++checks >= cancellation_check_interval) {
                    checks = 0;
                    if (cancel.stop_requested()) {
                        return workspace_result_t<
                            std::vector<indirect_call_candidate_t>>::failure(
                            cancellation_error(
                                cancel, cancel, "call_graph_evidence"));
                    }
                }
                if (candidates.size() >= maximum_candidates) {
                    return workspace_result_t<
                        std::vector<indirect_call_candidate_t>>::failure(
                        make_workspace_error(workspace_error_code_t::limit_exceeded,
                            "indirect call candidate storage exceeds analysis budget",
                            "call_graph_evidence"));
                }
                indirect_call_candidate_t candidate;
                candidate.instruction_id = instruction.id;
                candidate.call_site = instruction.address;
                candidate.target = pointer->target;
                candidate.kind =
                    pointer->candidate_kind == data_candidate_kind_t::relocation_slot
                        ? indirect_call_candidate_kind_t::relocation
                        : pointer->candidate_kind ==
                                data_candidate_kind_t::import_address_slot
                            ? indirect_call_candidate_kind_t::import_slot
                            : indirect_call_candidate_kind_t::pointer_scan;
                candidate.provenance = pointer->provenance;
                candidate.confidence = pointer->confidence;
                candidate.stable_source_id = pointer->id;
                candidates.push_back(std::move(candidate));
            }
        }
    }
    return workspace_result_t<std::vector<indirect_call_candidate_t>>::success(
        std::move(candidates));
}

fact_provenance_t legacy_type_provenance(metadata_provenance_t provenance) noexcept {
    switch (provenance) {
        case metadata_provenance_t::decoded:
            return fact_provenance_t::recursive_decode;
        case metadata_provenance_t::relocation:
        case metadata_provenance_t::import_metadata:
            return fact_provenance_t::relocation;
        case metadata_provenance_t::export_metadata:
            return fact_provenance_t::export_entry;
        case metadata_provenance_t::loader_symbol:
        case metadata_provenance_t::debug_metadata:
            return fact_provenance_t::debug_symbol;
        case metadata_provenance_t::rtti:
        case metadata_provenance_t::vtable_validation:
        case metadata_provenance_t::objective_c_metadata:
        case metadata_provenance_t::swift_metadata:
        case metadata_provenance_t::managed_metadata:
            return fact_provenance_t::linear_validation;
        case metadata_provenance_t::unknown:
            return fact_provenance_t::unknown;
    }
    return fact_provenance_t::unknown;
}

workspace_result_t<std::uint64_t> tile_decode_memory_bytes(
    const tile_decode_orchestration_result_t& result)
{
    if (!result.packed_store) {
        return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "tile decode packed publication is unavailable", "memory_budget"));
    }
    std::uint64_t total = sizeof(result);
    if (!checked_add_u64(total, sizeof(packed_analysis_store_t), total) ||
        !checked_add_u64(total,
            result.packed_store->size_accounting().reserved_bytes, total)) {
        return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "tile decode memory accounting overflows", "memory_budget"));
    }
    const auto add = [&total](std::uint64_t count, std::uint64_t width)
        -> workspace_result_t<void> {
        std::uint64_t bytes = 0;
        if (!checked_mul_u64(count, width, bytes) ||
            !checked_add_u64(total, bytes, total)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "tile decode memory accounting overflows", "memory_budget"));
        }
        return workspace_result_t<void>::success();
    };
    const std::pair<std::uint64_t, std::uint64_t> allocations[] = {
        {result.delay_slot_counts.capacity(), sizeof(std::uint8_t)},
        {result.coverage.capacity(), sizeof(coverage_span_t)},
        {result.cross_tile_edges.capacity(), sizeof(tile_decode_cross_tile_edge_t)},
        {result.shards.capacity(), sizeof(tile_decode_shard_summary_t)}};
    for (const auto& allocation : allocations) {
        auto added = add(allocation.first, allocation.second);
        if (!added)
            return workspace_result_t<std::uint64_t>::failure(added.error());
    }
    return workspace_result_t<std::uint64_t>::success(total);
}

std::uint64_t saturated_product(std::uint64_t lhs, std::uint64_t rhs,
                                std::uint64_t ceiling) noexcept {
    std::uint64_t value = 0;
    return checked_mul_u64(lhs, rhs, value) && value < ceiling ? value : ceiling;
}

std::uint64_t saturated_double_u64(std::uint64_t value) noexcept {
    std::uint64_t doubled = 0;
    return checked_add_u64(value, value, doubled)
        ? doubled : (std::numeric_limits<std::uint64_t>::max)();
}

class lane_seed_exchange_t final : public decode_lane_seed_exchange_t {
public:
    void configure(std::uint64_t tile_count, std::uint32_t lane_count) noexcept {
        tile_count_ = tile_count;
        lane_count_ = (std::min)(lane_count, kMaxLanes);
        for (std::uint32_t lane = 0; lane < lane_count_; ++lane)
            lane_active_[lane].store(true, std::memory_order_release);
        active_lanes_.store(lane_count_, std::memory_order_release);
    }

    void forward_seed(std::uint32_t,
                      decode_lane_seed_envelope_t envelope) override {
        const auto target = lane_of_tile(envelope.seed.tile_id);
        auto& mailbox = mailboxes_[target];
        std::lock_guard<std::mutex> lock(mailbox.mutex);
        if (!lane_active_[target].exchange(true, std::memory_order_acq_rel))
            active_lanes_.fetch_add(1, std::memory_order_acq_rel);
        mailbox.envelopes.push_back(std::move(envelope));
    }

    std::size_t drain_seeds(std::uint32_t lane_id,
        std::vector<decode_lane_seed_envelope_t>& out) override {
        if (lane_id >= kMaxLanes)
            return 0;
        auto& mailbox = mailboxes_[lane_id];
        std::lock_guard<std::mutex> lock(mailbox.mutex);
        const auto count = mailbox.envelopes.size();
        if (count != 0) {
            if (!lane_active_[lane_id].exchange(true, std::memory_order_acq_rel))
                active_lanes_.fetch_add(1, std::memory_order_acq_rel);
            out.insert(out.end(),
                std::make_move_iterator(mailbox.envelopes.begin()),
                std::make_move_iterator(mailbox.envelopes.end()));
            mailbox.envelopes.clear();
        }
        return count;
    }

    void note_recursive_activity(std::uint32_t lane_id, bool active) override {
        if (lane_id >= kMaxLanes)
            return;
        if (active) {
            if (!lane_active_[lane_id].exchange(true, std::memory_order_acq_rel))
                active_lanes_.fetch_add(1, std::memory_order_acq_rel);
        } else {
            auto& mailbox = mailboxes_[lane_id];
            std::lock_guard<std::mutex> lock(mailbox.mutex);
            if (!mailbox.envelopes.empty())
                return;
            if (lane_active_[lane_id].exchange(false, std::memory_order_acq_rel))
                active_lanes_.fetch_sub(1, std::memory_order_acq_rel);
        }
    }

    bool drained(std::uint32_t lane_id) override {
        if (lane_id >= kMaxLanes)
            return active_lanes_.load(std::memory_order_acquire) == 0;
        if (active_lanes_.load(std::memory_order_acquire) != 0)
            return false;
        const auto lanes = (std::min)(lane_count_, kMaxLanes);
        for (std::uint32_t lane = 0; lane < lanes; ++lane) {
            auto& mailbox = mailboxes_[lane];
            std::lock_guard<std::mutex> lock(mailbox.mutex);
            if (!mailbox.envelopes.empty())
                return false;
        }
        return active_lanes_.load(std::memory_order_acquire) == 0;
    }

private:
    static constexpr std::uint32_t kMaxLanes = 64;

    struct mailbox_t {
        std::mutex mutex;
        std::vector<decode_lane_seed_envelope_t> envelopes;
    };

    std::uint32_t lane_of_tile(decode_tile_id_t tile_id) const noexcept {
        if (tile_count_ == 0 || lane_count_ <= 1)
            return 0;
        const auto lane = (static_cast<std::uint64_t>(tile_id) *
            static_cast<std::uint64_t>(lane_count_)) / tile_count_;
        return static_cast<std::uint32_t>((std::min<std::uint64_t>)(lane,
            static_cast<std::uint64_t>(lane_count_ - 1U)));
    }

    std::array<mailbox_t, kMaxLanes> mailboxes_;
    std::array<std::atomic<bool>, kMaxLanes> lane_active_{};
    std::atomic<std::uint32_t> active_lanes_{0};
    std::uint64_t tile_count_ = 0;
    std::uint32_t lane_count_ = 0;
};

enum class baseline_progress_slot_t : std::size_t {
    parse = 0,
    seed,
    strings,
    decode,
    decode_merge,
    data,
    function_recovery,
    call_graph,
    cfg_calls,
    xrefs,
    metadata,
    search,
    persistence_submit,
    persistence_commit,
    publish,
    count
};

constexpr std::size_t kProgressSlotCount =
    static_cast<std::size_t>(baseline_progress_slot_t::count);

constexpr std::uint64_t kProgressSlotWeights[kProgressSlotCount] = {
    2, 2, 5, 45, 3, 6, 10, 7, 2, 7, 5, 3, 1, 1, 1};

constexpr const char* kProgressSlotNames[kProgressSlotCount] = {
    "parse", "seed", "strings_data", "decode", "decode_merge", "data_discovery",
    "function_recovery", "functions", "cfg_calls", "xrefs",
    "metadata_symbols_types", "search_index", "persistence", "persistence",
    "publish_ready"};

constexpr const char* kNodeWindowNames[kProgressSlotCount] = {
    "parse", "seed", "strings_data", "decode", "decode_merge", "data_discovery",
    "function_recovery", "functions", "cfg_calls", "xrefs",
    "metadata_symbols_types", "search_index", "persistence_submit",
    "persistence_commit", "publish_ready"};

constexpr std::uint64_t kNodeSoftBudgetMs[kProgressSlotCount] = {
    5000, 5000, 30000, 135000, 10000, 20000, 30000, 20000, 5000, 25000, 15000,
    15000, 5000, 25000, 2000};

struct progress_slot_state_t {
    std::atomic<std::uint64_t> complete{0};
    std::atomic<std::uint64_t> total{0};
    std::atomic<std::uint64_t> complete_bytes{0};
    std::atomic<std::uint64_t> total_bytes{0};
    std::atomic<std::uint32_t> active{0};
};

} 

workspace_result_t<void> baseline_analysis_settings_t::validate() const {
    if (max_seed_count == 0 || max_decode_queue == 0 || max_decoded_instructions == 0 ||
        max_coverage_spans == 0 || max_analysis_memory_bytes == 0 ||
        decode_read_window_bytes == 0 || decode_read_window_bytes > 64ULL * 1024ULL * 1024ULL ||
        string_read_window_bytes == 0 || string_read_window_bytes > 64ULL * 1024ULL * 1024ULL ||
        max_string_scan_bytes == 0 || max_string_value_bytes < minimum_string_length ||
        max_strings == 0 || max_trace_instructions == 0 || cancellation_check_interval == 0 ||
        string_cancellation_interval_bytes == 0 || minimum_string_length == 0 ||
        decode_worker_lanes > 64 || task_priority < 0 || task_priority > 7 ||
        tile_decode_limits.target_tile_bytes == 0 || tile_decode_limits.maximum_tiles == 0 ||
        tile_decode_limits.maximum_frontier_seeds == 0 ||
        tile_decode_limits.maximum_frontier_wave == 0 ||
        tile_decode_limits.maximum_decode_requests == 0 ||
        tile_decode_limits.maximum_instructions == 0 ||
        tile_decode_limits.maximum_operand_facts == 0 ||
        tile_decode_limits.maximum_target_facts == 0 ||
        tile_decode_limits.maximum_edges == 0 ||
        tile_decode_limits.maximum_coverage_spans == 0 ||
        tile_decode_limits.invalid_run_policy.maximum_gap_resynchronization_bytes == 0 ||
        tile_decode_limits.invalid_run_policy.maximum_invalid_bytes_per_tile == 0 ||
        tile_decode_limits.invalid_run_policy.maximum_invalid_runs_per_tile == 0 ||
        function_limits.max_blocks == 0 || function_limits.max_functions == 0 ||
        function_limits.max_function_memberships == 0 || function_limits.max_edges == 0 ||
        function_limits.max_switches == 0 || function_limits.max_seed_candidates == 0 ||
        function_limits.max_conflicts == 0 || function_limits.max_result_bytes == 0 ||
        function_limits.max_result_bytes > max_analysis_memory_bytes ||
        function_limits.max_blocks_per_function == 0 ||
        function_limits.cancellation_check_interval == 0 ||
        call_graph_limits.max_nodes == 0 || call_graph_limits.max_sites == 0 ||
        call_graph_limits.max_edges == 0 || call_graph_limits.max_candidates == 0 ||
        call_graph_limits.max_conflicts == 0 || call_graph_limits.max_result_bytes == 0 ||
        call_graph_limits.max_result_bytes > max_analysis_memory_bytes ||
        call_graph_limits.max_candidates_per_site == 0 ||
        call_graph_limits.cancellation_check_interval == 0 ||
        data_limits.max_candidates == 0 || data_limits.max_pointer_facts == 0 ||
        data_limits.max_conflicts == 0 || data_limits.max_pointer_seeds == 0 ||
        data_limits.max_pointer_scan_bytes == 0 || data_limits.max_result_bytes == 0 ||
        data_limits.max_result_bytes > max_analysis_memory_bytes ||
        data_limits.read_window_bytes == 0 ||
        data_limits.read_window_bytes > 64ULL * 1024ULL * 1024ULL ||
        data_limits.cancellation_check_interval == 0 || xref_limits.max_xrefs == 0 ||
        xref_limits.max_type_xrefs == 0 || xref_limits.max_data_candidates == 0 ||
        xref_limits.max_pointer_facts == 0 || xref_limits.max_data_conflicts == 0 ||
        xref_limits.max_result_bytes == 0 ||
        xref_limits.max_result_bytes > max_analysis_memory_bytes ||
        xref_limits.read_window_bytes == 0 ||
        xref_limits.read_window_bytes > 64ULL * 1024ULL * 1024ULL ||
        xref_limits.cancellation_check_interval == 0 ||
        string_limits.max_strings == 0 || string_limits.max_scan_bytes == 0 ||
        string_limits.max_result_bytes == 0 ||
        string_limits.max_result_bytes > max_analysis_memory_bytes ||
        string_limits.max_string_bytes == 0 || string_limits.max_string_value_bytes == 0 ||
        string_limits.read_window_bytes == 0 ||
        string_limits.read_window_bytes > 64ULL * 1024ULL * 1024ULL ||
        string_limits.minimum_code_points == 0 ||
        string_limits.cancellation_check_interval == 0 ||
        symbol_type_limits.max_symbols == 0 ||
        symbol_type_limits.max_type_candidates == 0 ||
        symbol_type_limits.max_type_references == 0 ||
        symbol_type_limits.max_conflicts == 0 || symbol_type_limits.max_string_bytes == 0 ||
        symbol_type_limits.max_result_bytes == 0 ||
        symbol_type_limits.max_result_bytes > max_analysis_memory_bytes ||
        symbol_type_limits.minimum_vtable_entries == 0 ||
        symbol_type_limits.maximum_vtable_entries < symbol_type_limits.minimum_vtable_entries ||
        symbol_type_limits.cancellation_check_interval == 0 || search_limits.max_entries == 0 ||
        search_limits.max_index_bytes == 0 || search_limits.max_index_bytes > max_analysis_memory_bytes ||
        search_limits.max_query_bytes == 0 || search_limits.max_results_per_query == 0 ||
        search_limits.cancellation_check_interval == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "baseline analysis settings are outside supported safety bounds", "settings"));
    }
    const auto check_memory_product = [](std::uint64_t count, std::uint64_t size,
        const char* field, std::uint64_t limit) -> workspace_result_t<void> {
        std::uint64_t product = 0;
        if (!checked_mul_u64(count, size, product) || product > limit) {
            auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                "baseline analysis settings memory product exceeds the analysis memory budget",
                "settings");
            error.details.emplace_back("field", field);
            error.details.emplace_back("count", std::to_string(count));
            error.details.emplace_back("element_bytes", std::to_string(size));
            error.details.emplace_back("product", std::to_string(product));
            error.details.emplace_back("limit", std::to_string(limit));
            return workspace_result_t<void>::failure(std::move(error));
        }
        return workspace_result_t<void>::success();
    };
    const struct {
        std::uint64_t count;
        std::uint64_t size;
        const char* field;
    } memory_products[] = {
        {max_decoded_instructions, sizeof(instruction_record_t), "max_decoded_instructions"},
        {tile_decode_limits.maximum_instructions, sizeof(instruction_record_t),
            "tile_decode_limits.maximum_instructions"},
        {tile_decode_limits.maximum_operand_facts, sizeof(operand_fact_t),
            "tile_decode_limits.maximum_operand_facts"},
        {tile_decode_limits.maximum_target_facts, sizeof(target_fact_t),
            "tile_decode_limits.maximum_target_facts"},
        {tile_decode_limits.maximum_edges, sizeof(edge_record_t),
            "tile_decode_limits.maximum_edges"},
        {tile_decode_limits.maximum_coverage_spans, sizeof(coverage_span_t),
            "tile_decode_limits.maximum_coverage_spans"},
        {max_coverage_spans, sizeof(coverage_span_t), "max_coverage_spans"},
        {xref_limits.max_xrefs, sizeof(xref_record_t), "xref_limits.max_xrefs"},
        {max_strings, sizeof(string_record_t), "max_strings"}};
    for (const auto& entry : memory_products) {
        auto checked = check_memory_product(entry.count, entry.size, entry.field,
            max_analysis_memory_bytes);
        if (!checked)
            return checked;
    }
    return workspace_result_t<void>::success();
}

std::string baseline_analysis_settings_t::canonical_json() const {
    std::ostringstream out;
    out << "{\"version\":3"
        << ",\"max_seed_count\":" << max_seed_count
        << ",\"max_decode_queue\":" << max_decode_queue
        << ",\"max_decoded_instructions\":" << max_decoded_instructions
        << ",\"max_coverage_spans\":" << max_coverage_spans
        << ",\"max_analysis_memory_bytes\":" << max_analysis_memory_bytes
        << ",\"decode_read_window_bytes\":" << decode_read_window_bytes
        << ",\"string_read_window_bytes\":" << string_read_window_bytes
        << ",\"max_string_scan_bytes\":" << max_string_scan_bytes
        << ",\"max_string_value_bytes\":" << max_string_value_bytes
        << ",\"max_strings\":" << max_strings
        << ",\"decode_worker_lanes\":" << decode_worker_lanes
        << ",\"max_trace_instructions\":" << max_trace_instructions
        << ",\"cancellation_check_interval\":" << cancellation_check_interval
        << ",\"string_cancellation_interval_bytes\":" << string_cancellation_interval_bytes
        << ",\"minimum_string_length\":" << minimum_string_length
        << ",\"scan_utf8\":" << (scan_utf8 ? "true" : "false")
        << ",\"scan_utf16\":" << (scan_utf16 ? "true" : "false")
        << ",\"task_priority\":" << task_priority
        << ",\"pe_profile\":{\"max_sections\":" << pe_limits.max_sections
        << ",\"max_imports\":" << pe_limits.max_imports
        << ",\"max_exports\":" << pe_limits.max_exports
        << ",\"max_relocations\":" << pe_limits.max_relocations << "}"
        << ",\"tile_decode\":{\"target_tile_bytes\":" << tile_decode_limits.target_tile_bytes
        << ",\"maximum_tiles\":" << tile_decode_limits.maximum_tiles
        << ",\"maximum_frontier_seeds\":" << tile_decode_limits.maximum_frontier_seeds
        << ",\"maximum_frontier_wave\":" << tile_decode_limits.maximum_frontier_wave
        << ",\"maximum_decode_requests\":" << tile_decode_limits.maximum_decode_requests
        << ",\"maximum_instructions\":" << tile_decode_limits.maximum_instructions
        << ",\"maximum_operand_facts\":" << tile_decode_limits.maximum_operand_facts
        << ",\"maximum_target_facts\":" << tile_decode_limits.maximum_target_facts
        << ",\"maximum_edges\":" << tile_decode_limits.maximum_edges
        << ",\"maximum_coverage_spans\":" << tile_decode_limits.maximum_coverage_spans
        << ",\"seed_executable_range_starts\":"
        << (tile_decode_limits.seed_executable_range_starts ? "true" : "false")
        << ",\"maximum_gap_resynchronization_bytes\":"
        << tile_decode_limits.invalid_run_policy.maximum_gap_resynchronization_bytes
        << ",\"maximum_invalid_bytes_per_tile\":"
        << tile_decode_limits.invalid_run_policy.maximum_invalid_bytes_per_tile
        << ",\"maximum_invalid_runs_per_tile\":"
        << tile_decode_limits.invalid_run_policy.maximum_invalid_runs_per_tile << "}"
        << ",\"function\":{\"max_blocks\":" << function_limits.max_blocks
        << ",\"max_functions\":" << function_limits.max_functions
        << ",\"max_function_memberships\":" << function_limits.max_function_memberships
        << ",\"max_edges\":" << function_limits.max_edges
        << ",\"max_switches\":" << function_limits.max_switches
        << ",\"max_seed_candidates\":" << function_limits.max_seed_candidates
        << ",\"max_conflicts\":" << function_limits.max_conflicts
        << ",\"max_switch_cases\":" << function_limits.max_switch_cases
        << ",\"max_blocks_per_function\":" << function_limits.max_blocks_per_function
        << ",\"cancellation_check_interval\":" << function_limits.cancellation_check_interval
        << ",\"max_result_bytes\":" << function_limits.max_result_bytes << "}"
        << ",\"call_graph\":{\"max_nodes\":" << call_graph_limits.max_nodes
        << ",\"max_sites\":" << call_graph_limits.max_sites
        << ",\"max_edges\":" << call_graph_limits.max_edges
        << ",\"max_candidates\":" << call_graph_limits.max_candidates
        << ",\"max_conflicts\":" << call_graph_limits.max_conflicts
        << ",\"max_result_bytes\":" << call_graph_limits.max_result_bytes
        << ",\"max_candidates_per_site\":" << call_graph_limits.max_candidates_per_site
        << ",\"cancellation_check_interval\":" << call_graph_limits.cancellation_check_interval
        << "}"
        << ",\"data\":{\"max_candidates\":" << data_limits.max_candidates
        << ",\"max_pointer_facts\":" << data_limits.max_pointer_facts
        << ",\"max_conflicts\":" << data_limits.max_conflicts
        << ",\"max_pointer_seeds\":" << data_limits.max_pointer_seeds
        << ",\"max_pointer_scan_bytes\":" << data_limits.max_pointer_scan_bytes
        << ",\"max_result_bytes\":" << data_limits.max_result_bytes
        << ",\"read_window_bytes\":" << data_limits.read_window_bytes
        << ",\"cancellation_check_interval\":" << data_limits.cancellation_check_interval
        << ",\"scan_executable_regions\":"
        << (data_limits.scan_executable_regions ? "true" : "false")
        << ",\"scan_unaligned_pointers\":"
        << (data_limits.scan_unaligned_pointers ? "true" : "false") << "}"
        << ",\"xref\":{\"max_xrefs\":" << xref_limits.max_xrefs
        << ",\"max_type_xrefs\":" << xref_limits.max_type_xrefs
        << ",\"max_data_candidates\":" << xref_limits.max_data_candidates
        << ",\"max_pointer_facts\":" << xref_limits.max_pointer_facts
        << ",\"max_data_conflicts\":" << xref_limits.max_data_conflicts
        << ",\"max_pointer_scan_bytes\":" << xref_limits.max_pointer_scan_bytes
        << ",\"max_result_bytes\":" << xref_limits.max_result_bytes
        << ",\"read_window_bytes\":" << xref_limits.read_window_bytes
        << ",\"cancellation_check_interval\":" << xref_limits.cancellation_check_interval
        << "}"
        << ",\"string\":{\"max_strings\":" << string_limits.max_strings
        << ",\"max_scan_bytes\":" << string_limits.max_scan_bytes
        << ",\"max_result_bytes\":" << string_limits.max_result_bytes
        << ",\"max_string_bytes\":" << string_limits.max_string_bytes
        << ",\"max_string_value_bytes\":" << string_limits.max_string_value_bytes
        << ",\"read_window_bytes\":" << string_limits.read_window_bytes
        << ",\"minimum_code_points\":" << string_limits.minimum_code_points
        << ",\"cancellation_check_interval\":" << string_limits.cancellation_check_interval
        << ",\"scan_ascii\":" << (string_limits.scan_ascii ? "true" : "false")
        << ",\"scan_utf8\":" << (string_limits.scan_utf8 ? "true" : "false")
        << ",\"scan_utf16_le\":" << (string_limits.scan_utf16_le ? "true" : "false")
        << ",\"scan_executable_regions\":"
        << (string_limits.scan_executable_regions ? "true" : "false")
        << ",\"require_null_terminator\":"
        << (string_limits.require_null_terminator ? "true" : "false") << "}"
        << ",\"symbol_type\":{\"max_symbols\":" << symbol_type_limits.max_symbols
        << ",\"max_type_candidates\":" << symbol_type_limits.max_type_candidates
        << ",\"max_type_references\":" << symbol_type_limits.max_type_references
        << ",\"max_conflicts\":" << symbol_type_limits.max_conflicts
        << ",\"max_string_bytes\":" << symbol_type_limits.max_string_bytes
        << ",\"max_result_bytes\":" << symbol_type_limits.max_result_bytes
        << ",\"minimum_vtable_entries\":" << symbol_type_limits.minimum_vtable_entries
        << ",\"maximum_vtable_entries\":" << symbol_type_limits.maximum_vtable_entries
        << ",\"cancellation_check_interval\":"
        << symbol_type_limits.cancellation_check_interval
        << "}"
        << ",\"search\":{\"max_entries\":" << search_limits.max_entries
        << ",\"max_trigram_postings\":" << search_limits.max_trigram_postings
        << ",\"max_indexed_text_bytes\":" << search_limits.max_indexed_text_bytes
        << ",\"max_index_bytes\":" << search_limits.max_index_bytes
        << ",\"max_query_bytes\":" << search_limits.max_query_bytes
        << ",\"max_results_per_query\":" << search_limits.max_results_per_query
        << ",\"cancellation_check_interval\":"
        << search_limits.cancellation_check_interval << "}}";
    return out.str();
}

struct pe_baseline_analyzer_t::impl_t {
    std::shared_ptr<analysis_workspace_t> workspace;
    baseline_analysis_settings_t settings;
    std::uint64_t expected_generation = 0;
    std::uint64_t expected_analysis_revision = 0;
    cancellation_source_t cancellation;
    std::shared_ptr<analysis_metrics_t> metrics;
    std::shared_ptr<const workspace_image_t> image;
    std::shared_ptr<provider_snapshot_t> provider_snapshot;
    std::optional<image_layout_index_t> image_layout;
    arch_decoder_key_t decoder_key;
    bool native_decode_applicable = true;
    std::shared_ptr<analysis_snapshot_t> draft;
    std::shared_ptr<const analysis_snapshot_t> final_snapshot;
    std::vector<function_seed_t> seeds;
    std::vector<tile_decode_orchestration_result_t> tile_results;
    lane_seed_exchange_t lane_seed_exchange;
    std::once_flag decode_lane_once;
    std::optional<executable_decode_partition_t> decode_partition;
    std::optional<workspace_error_t> decode_lane_error;
    std::uint32_t decode_workers = 1;
    std::shared_ptr<const data_discovery_result_t> data_result;
    function_recovery_result_t function_result;
    call_graph_result_t call_graph_result;
    xref_build_result_t xref_result;
    string_discovery_result_t string_result;
    symbol_type_candidate_result_t symbol_type_result;
    std::vector<type_candidate_record_t> type_candidates;
    std::shared_ptr<search_index_t> search;
    persistence_ticket_t persistence_ticket;
    std::uint64_t strings_budget_bytes = 0;
    std::uint64_t data_budget_bytes = 0;
    std::uint64_t function_budget_bytes = 0;
    std::uint64_t call_graph_budget_bytes = 0;
    std::uint64_t xref_budget_bytes = 0;
    std::uint64_t symbol_type_budget_bytes = 0;
    std::array<progress_slot_state_t, kProgressSlotCount> progress_slots;
    std::array<std::atomic<std::uint64_t>, kProgressSlotCount> node_start_ns{};
    std::array<std::atomic<std::uint64_t>, kProgressSlotCount> node_end_ns{};
    std::mutex failure_mutex;
    std::optional<workspace_error_t> first_failure;

    impl_t(std::shared_ptr<analysis_workspace_t> value, baseline_analysis_settings_t configured,
        std::uint64_t generation, std::uint64_t analysis_revision,
        std::optional<std::chrono::steady_clock::time_point> deadline)
        : workspace(std::move(value)), settings(std::move(configured)),
          expected_generation(generation), expected_analysis_revision(analysis_revision),
          cancellation(deadline), metrics(std::make_shared<analysis_metrics_t>(generation)) {
        auto lanes = settings.decode_worker_lanes;
        if (lanes == 0) {
            const auto hardware = std::max(1U, std::thread::hardware_concurrency());
            lanes = std::min(16U, std::max(2U, hardware));
        }
        decode_workers = lanes;
    }

    std::uint32_t lane_total() const noexcept {
        const auto executable = executable_bytes();
        const auto target = (std::max)(1ULL, settings.tile_decode_limits.target_tile_bytes);
        const auto estimated_tiles = (std::max<std::uint64_t>)(1ULL, executable / target);
        return static_cast<std::uint32_t>((std::min<std::uint64_t>)(decode_workers,
            estimated_tiles));
    }

    workspace_result_t<void> ensure_decode_lane_state(
        const tile_decode_executor_capabilities_t& capabilities,
        const tile_decode_orchestrator_limits_t& limits) {
        std::call_once(decode_lane_once, [&] {
            auto partition = partition_executable_decode_ranges(*image_layout,
                capabilities, limits, cancellation.token());
            if (!partition) {
                decode_lane_error = partition.error();
                return;
            }
            decode_partition = partition.take_value();
            const auto lanes = lane_total();
            tile_results.resize(lanes);
            lane_seed_exchange.configure(
                static_cast<std::uint64_t>(decode_partition->tiles.size()), lanes);
        });
        if (decode_lane_error)
            return workspace_result_t<void>::failure(*decode_lane_error);
        return workspace_result_t<void>::success();
    }

    decode_tile_range_t decode_lane_range(std::uint32_t lane) const noexcept {
        const auto lanes = (std::max)(1U, lane_total());
        const auto tiles = decode_partition
            ? static_cast<std::uint64_t>(decode_partition->tiles.size()) : 0ULL;
        decode_tile_range_t range;
        range.begin = static_cast<decode_tile_id_t>(
            (tiles * static_cast<std::uint64_t>(lane)) / lanes);
        range.end = static_cast<decode_tile_id_t>(
            (tiles * (static_cast<std::uint64_t>(lane) + 1ULL)) / lanes);
        return range;
    }

    workspace_result_t<void> ensure_active(const std::atomic<bool>& runtime_cancel,
        const char* phase) {
        if (workspace->generation() != expected_generation) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::stale_generation,
                "workspace generation changed during baseline analysis", phase));
        }
        if (runtime_cancel.load(std::memory_order_acquire) ||
            workspace->cancellation_token().stop_requested())
            cancellation.request_cancel();
        const auto local = cancellation.token();
        const auto workspace_token = workspace->cancellation_token();
        if (local.stop_requested() || workspace_token.stop_requested())
            return workspace_result_t<void>::failure(cancellation_error(local, workspace_token, phase));
        if (workspace->closing() || workspace->closed()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::workspace_closing, "workspace is closing", phase));
        }
        return workspace_result_t<void>::success();
    }

    void node_begin(baseline_progress_slot_t slot) noexcept {
        const auto index = static_cast<std::size_t>(slot);
        progress_slots[index].active.fetch_add(1, std::memory_order_acq_rel);
        node_start_ns[index].store(analysis_metrics_t::steady_now_ns(),
            std::memory_order_release);
    }

    void node_end(baseline_progress_slot_t slot) noexcept {
        const auto index = static_cast<std::size_t>(slot);
        const auto end = analysis_metrics_t::steady_now_ns();
        node_end_ns[index].store(end, std::memory_order_release);
        progress_slots[index].active.fetch_sub(1, std::memory_order_acq_rel);
        const auto begin = node_start_ns[index].load(std::memory_order_acquire);
        if (end > begin) {
            const auto wall_ms = (end - begin) / 1000000ULL;
            const auto budget_ms = kNodeSoftBudgetMs[index];
            if (wall_ms > budget_ms) {
                ::diag::log_tagged_fmt("baseline_pipeline",
                    "baseline_node_over_budget node=%s wall_ms=%llu budget_ms=%llu",
                    kNodeWindowNames[index],
                    static_cast<unsigned long long>(wall_ms),
                    static_cast<unsigned long long>(budget_ms));
            }
        }
    }

    struct node_window_guard_t final {
        impl_t* owner = nullptr;
        baseline_progress_slot_t slot = baseline_progress_slot_t::parse;
        ~node_window_guard_t() { finish(); }
        void finish() noexcept {
            if (owner) {
                owner->node_end(slot);
                owner = nullptr;
            }
        }
    };

    node_window_guard_t node_guard(baseline_progress_slot_t slot) noexcept {
        node_begin(slot);
        return node_window_guard_t{this, slot};
    }

    workspace_result_t<void> update_progress_slot(baseline_progress_slot_t slot,
        const char* phase_name, std::uint64_t complete, std::uint64_t total,
        std::uint64_t complete_bytes, std::uint64_t total_bytes,
        workspace_readiness_t readiness = workspace_readiness_t::analyzing) {
        const auto slot_index = static_cast<std::size_t>(slot);
        progress_slots[slot_index].complete.store(complete, std::memory_order_release);
        progress_slots[slot_index].total.store(total, std::memory_order_release);
        progress_slots[slot_index].complete_bytes.store(complete_bytes,
            std::memory_order_release);
        progress_slots[slot_index].total_bytes.store(total_bytes,
            std::memory_order_release);
        std::uint64_t completed_units = 0;
        std::uint64_t total_units = 0;
        std::uint64_t completed_bytes_rollup = 0;
        std::uint64_t total_bytes_rollup = 0;
        std::string phase_label;
        for (std::size_t index = 0; index < kProgressSlotCount; ++index) {
            const auto weight = kProgressSlotWeights[index];
            total_units += weight;
            const auto slot_complete = progress_slots[index].complete.load(
                std::memory_order_acquire);
            const auto slot_total = progress_slots[index].total.load(
                std::memory_order_acquire);
            completed_units += (weight * (std::min)(slot_complete, slot_total)) /
                (slot_total == 0 ? 1ULL : slot_total);
            completed_bytes_rollup += progress_slots[index].complete_bytes.load(
                std::memory_order_acquire);
            total_bytes_rollup += progress_slots[index].total_bytes.load(
                std::memory_order_acquire);
            if (progress_slots[index].active.load(std::memory_order_acquire) != 0) {
                if (!phase_label.empty())
                    phase_label += '+';
                phase_label += kProgressSlotNames[index];
            }
        }
        if (phase_label.empty())
            phase_label = phase_name;
        workspace_progress_t progress;
        progress.readiness = readiness;
        progress.phase = std::move(phase_label);
        progress.completed_units = completed_units;
        progress.total_units = total_units;
        progress.completed_bytes = completed_bytes_rollup;
        progress.total_bytes = total_bytes_rollup;
        progress.cancellation_requested = cancellation.token().stop_requested();
        return workspace->update_progress(expected_generation, std::move(progress));
    }

    void discard_persistence_candidate() noexcept {
        const auto candidate = persistence_ticket.snapshot_candidate;
        if (!candidate)
            return;
        try {
            (void)candidate->discard();
        } catch (...) {
        }
    }

    std::uint64_t executable_bytes() const noexcept {
        const auto source = image ? image : workspace->normalized_image();
        if (!source)
            return 0;
        std::uint64_t total = 0;
        for (const auto& range : executable_ranges(*source)) {
            std::uint64_t updated = 0;
            if (!checked_add_u64(total, range.end - range.start, updated))
                return std::numeric_limits<std::uint64_t>::max();
            total = updated;
        }
        return total;
    }
};

pe_baseline_analyzer_t::pe_baseline_analyzer_t(std::unique_ptr<impl_t> impl) : impl_(std::move(impl)) {
    provider_metrics_relay::attach_analysis_metrics(impl_->metrics.get());
}
pe_baseline_analyzer_t::~pe_baseline_analyzer_t() {
    provider_metrics_relay::detach_analysis_metrics(impl_->metrics.get());
}

workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>> pe_baseline_analyzer_t::create(
    std::shared_ptr<analysis_workspace_t> workspace, baseline_analysis_settings_t settings,
    std::uint64_t expected_generation, std::uint64_t expected_analysis_revision,
    std::optional<std::chrono::steady_clock::time_point> deadline) {
    if (!workspace) {
        return workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument, "baseline analyzer requires a workspace", "create"));
    }
    auto valid = settings.validate();
    if (!valid)
        return workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>>::failure(valid.error());
    if (workspace->target_kind() != target_kind_t::static_file) {
        return workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>>::failure(make_workspace_error(
            workspace_error_code_t::live_target_bulk_analysis_unsupported,
            "bulk baseline analysis is not supported for live targets", "create"));
    }
    if (workspace->generation() != expected_generation) {
        return workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>>::failure(make_workspace_error(
            workspace_error_code_t::stale_generation,
            "workspace generation changed before analysis submission", "create"));
    }
    if (workspace->analysis_revision() != expected_analysis_revision ||
        expected_analysis_revision == std::numeric_limits<std::uint64_t>::max()) {
        return workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "workspace analysis revision changed before submission", "create"));
    }
    return workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>>::success(
        std::shared_ptr<pe_baseline_analyzer_t>(new pe_baseline_analyzer_t(
            std::make_unique<impl_t>(std::move(workspace), std::move(settings),
                expected_generation, expected_analysis_revision, deadline))));
}

std::uint32_t pe_baseline_analyzer_t::decode_lane_count() const noexcept {
    return impl_->lane_total();
}

std::uint64_t pe_baseline_analyzer_t::expected_generation() const noexcept {
    return impl_->expected_generation;
}

std::shared_ptr<analysis_metrics_t> pe_baseline_analyzer_t::metrics() const noexcept {
    return impl_->metrics;
}

workspace_result_t<void> pe_baseline_analyzer_t::parse_phase(const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::parse);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::parse);
    auto active = impl_->ensure_active(runtime_cancel, "parse");
    if (!active) {
        impl_->metrics->end_phase(measurement, 0, 0, 0, 1, true);
        return active;
    }
    impl_->image = impl_->workspace->normalized_image();
    if (!impl_->image) {
        impl_->metrics->end_phase(measurement, 0, 0, 0, 1, true);
        auto error = make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "baseline analysis requires a registry-admitted normalized image", "parse");
        error.details.emplace_back("missing_parser_symbol",
            "workspace_registry_t::admit_verified_provider");
        error.details.emplace_back("missing_parser_file", "workspace_registry.hpp");
        return workspace_result_t<void>::failure(std::move(error));
    }
    auto validated = validate_workspace_image(*impl_->image, {}, true, impl_->cancellation.token());
    if (!validated) {
        impl_->metrics->end_phase(measurement, impl_->workspace->provider().size(), 0, 1, 1, true);
        return validated;
    }
    impl_->native_decode_applicable = !managed_bytecode_only_image(*impl_->image);
    if (impl_->native_decode_applicable) {
        impl_->decoder_key = make_arch_decoder_key(*impl_->image);
        auto decoder = default_arch_decoder_registry().resolve(impl_->decoder_key);
        if (!decoder) {
            auto error = decoder.error();
            if (error.code == workspace_error_code_t::unsupported_format) {
                error.details.emplace_back("missing_registry_symbol",
                    "arch_decoder_registry_t::register_decoder");
                error.details.emplace_back("missing_registry_file", "arch_decoder.hpp");
            }
            impl_->metrics->end_phase(measurement, impl_->workspace->provider().size(), 0, 1, 1, true);
            return workspace_result_t<void>::failure(std::move(error));
        }
    }
    const auto& provider = impl_->workspace->provider_handle();
    provider_snapshot_options_t snapshot_options;
    snapshot_options.max_materialized_bytes = (std::min)(
        snapshot_options.max_materialized_bytes,
        impl_->settings.max_analysis_memory_bytes);
    snapshot_options.copy_chunk_bytes = (std::min)({
        snapshot_options.copy_chunk_bytes,
        impl_->settings.decode_read_window_bytes,
        snapshot_options.max_materialized_bytes});
    workspace_result_t<std::shared_ptr<provider_snapshot_t>> captured =
        provider->identity().immutable_snapshot
            ? provider_snapshot_t::capture(provider, impl_->expected_generation,
                impl_->cancellation.token())
            : provider_snapshot_t::materialize(provider, snapshot_options,
                impl_->cancellation.token());
    if (!captured) {
        impl_->metrics->end_phase(measurement, provider->size(), 0, 1, 1, true);
        return workspace_result_t<void>::failure(captured.error());
    }
    impl_->provider_snapshot = captured.take_value();
    auto layout = build_baseline_image_layout(*impl_->image, *impl_->provider_snapshot,
        impl_->cancellation.token());
    if (!layout) {
        impl_->metrics->end_phase(measurement, provider->size(), 0, 1, 1, true);
        return workspace_result_t<void>::failure(layout.error());
    }
    impl_->image_layout = layout.take_value();
    impl_->draft = std::make_shared<analysis_snapshot_t>();
    impl_->draft->binary_id = impl_->workspace->identity().binary_id();
    impl_->draft->load_profile_hash = impl_->workspace->identity().load_profile_hash();
    impl_->draft->generation = impl_->expected_generation;
    impl_->draft->analysis_revision = impl_->expected_analysis_revision + 1;
    impl_->draft->overlay_revision = impl_->workspace->overlay_revision();
    impl_->draft->normalized_image = impl_->image;
    impl_->draft->image = impl_->workspace->image();
    auto shell = snapshot_memory_accounted_bytes(*impl_->draft);
    if (!shell) {
        impl_->metrics->end_phase(measurement, impl_->workspace->provider().size(),
            0, 1, 1, true);
        return workspace_result_t<void>::failure(shell.error());
    }
    impl_->strings_budget_bytes = shell.value() >= impl_->settings.max_analysis_memory_bytes
        ? 0ULL
        : (impl_->settings.max_analysis_memory_bytes - shell.value()) / 8ULL;
    impl_->metrics->set(analysis_metric_t::file_bytes, impl_->workspace->provider().size());
    impl_->metrics->set(analysis_metric_t::executable_bytes, impl_->executable_bytes());
    impl_->metrics->add(analysis_metric_t::provider_revalidations);
    auto progress = impl_->update_progress_slot(baseline_progress_slot_t::parse,
        "parse", 1, 1, impl_->workspace->provider().size(),
        impl_->workspace->provider().size(), workspace_readiness_t::parsed);
    impl_->metrics->end_phase(measurement, impl_->workspace->provider().size(),
        impl_->image->image_size, 1, 1, !progress.has_value());
    return progress;
}

workspace_result_t<void> pe_baseline_analyzer_t::seed_phase(const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::seed);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::seed);
    auto active = impl_->ensure_active(runtime_cancel, "seed");
    if (!active) {
        impl_->metrics->end_phase(measurement, 0, 0, 0, 1, true);
        return active;
    }
    if (!impl_->image || !impl_->draft) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "parse phase did not retain a normalized image", "seed"));
    }
    if (!impl_->native_decode_applicable) {
        impl_->seeds.clear();
        const auto executable_bytes = impl_->executable_bytes();
        auto progress = impl_->update_progress_slot(baseline_progress_slot_t::seed,
            "seed", 0, 0, executable_bytes, executable_bytes);
        impl_->metrics->end_phase(measurement, 0, 0, 0, 1, !progress.has_value());
        return progress;
    }
    std::map<std::pair<std::uint64_t, std::uint8_t>, function_seed_t> candidates;
    const auto add = [&](const address_t& address, function_seed_kind_t kind,
        fact_provenance_t provenance, std::uint8_t confidence, std::uint64_t source,
        std::optional<address_t> known_end, std::string name, bool noreturn)
        -> workspace_result_t<void> {
        const auto rva = to_rva(*impl_->image, address);
        if (!rva || !executable_rva(*impl_->image, *rva))
            return workspace_result_t<void>::success();
        function_seed_t seed;
        seed.address = rva_address(*impl_->image, *rva);
        if (known_end) {
            const auto end = to_rva_endpoint(*impl_->image, *known_end);
            if (end && *end > *rva)
                seed.known_end = rva_address(*impl_->image, *end);
        }
        seed.kind = kind;
        seed.provenance = provenance;
        seed.confidence = confidence;
        seed.stable_source_id = source;
        seed.name = std::move(name);
        seed.noreturn = noreturn;
        const auto key = std::make_pair(*rva, static_cast<std::uint8_t>(kind));
        const auto found = candidates.find(key);
        if (found == candidates.end() || stronger_seed_evidence(seed.provenance,
                seed.confidence, seed.stable_source_id, found->second.provenance,
                found->second.confidence, found->second.stable_source_id))
            candidates[key] = std::move(seed);
        if (candidates.size() > impl_->settings.max_seed_count) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "function seed count exceeds analysis budget", "seed"));
        }
        return workspace_result_t<void>::success();
    };
    std::uint64_t source = 1;
    for (const auto& entry : impl_->image->entry_points) {
        auto added = add(entry.address, function_seed_kind_t::image_entry,
            fact_provenance_t::image_entry, 100, source++, std::nullopt, entry.provenance, false);
        if (!added)
            return added;
    }
    if (const auto pe_image = impl_->workspace->image()) {
        std::uint32_t checks = 0;
        for (const auto& runtime_function : pe_image->runtime_functions()) {
            if (++checks >= impl_->settings.cancellation_check_interval) {
                checks = 0;
                const auto token = impl_->cancellation.token();
                if (token.stop_requested()) {
                    return workspace_result_t<void>::failure(
                        cancellation_error(token, token, "seed"));
                }
            }
            if (runtime_function.end_rva <= runtime_function.begin_rva) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "PE runtime function range is invalid", "seed"));
            }
            auto added = add(rva_address(*impl_->image,
                    runtime_function.begin_rva),
                function_seed_kind_t::unwind_range,
                fact_provenance_t::unwind_metadata, 98, source++,
                std::optional<address_t>{rva_address(*impl_->image,
                    runtime_function.end_rva)}, {}, false);
            if (!added)
                return added;
        }
    }
    for (const auto& exported : impl_->image->exports) {
        if (exported.forwarder)
            continue;
        auto added = add(exported.address, function_seed_kind_t::export_entry,
            fact_provenance_t::export_entry, 100, source++, std::nullopt,
            exported.name.value_or(std::string{}), false);
        if (!added)
            return added;
    }
    for (const auto& symbol : impl_->image->symbols) {
        if (!symbol.defined || (symbol.kind != image_symbol_kind_t::function &&
            symbol.kind != image_symbol_kind_t::debug_symbol))
            continue;
        std::optional<address_t> known_end;
        if (symbol.size != 0) {
            const auto start = to_rva(*impl_->image, symbol.address);
            std::uint64_t end = 0;
            if (start && checked_add_u64(*start, symbol.size, end))
                known_end = rva_address(*impl_->image, end);
        }
        auto added = add(symbol.address, function_seed_kind_t::debug_symbol,
            fact_provenance_t::debug_symbol, 95, source++, known_end, symbol.name, false);
        if (!added)
            return added;
    }
    for (const auto& relocation : impl_->image->relocations) {
        if (!relocation.target)
            continue;
        auto added = add(*relocation.target, function_seed_kind_t::relocation_target,
            fact_provenance_t::relocation, 70, source++, std::nullopt, {}, false);
        if (!added)
            return added;
    }
    const auto prior = impl_->workspace->snapshot();
    if (prior && prior->generation == impl_->expected_generation) {
        for (const auto& symbol : prior->symbols) {
            if (symbol.kind != symbol_kind_t::function && symbol.kind != symbol_kind_t::debug_symbol)
                continue;
            auto added = add(symbol.address, function_seed_kind_t::debug_symbol,
                symbol.provenance, symbol.confidence, source++, std::nullopt, symbol.name, false);
            if (!added)
                return added;
        }
    }
    impl_->seeds.clear();
    impl_->seeds.reserve(candidates.size());
    for (auto& candidate : candidates)
        impl_->seeds.push_back(std::move(candidate.second));
    auto progress = impl_->update_progress_slot(baseline_progress_slot_t::seed,
        "seed", impl_->seeds.size(), impl_->seeds.size(), 0,
        impl_->executable_bytes());
    impl_->metrics->end_phase(measurement, 0, impl_->seeds.size() * sizeof(function_seed_t),
        impl_->seeds.size(), 1, !progress.has_value());
    return progress;
}

workspace_result_t<void> pe_baseline_analyzer_t::decode_lane_phase(std::uint32_t lane,
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::decode);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::decode);
    auto active = impl_->ensure_active(runtime_cancel, "decode");
    if (!active)
        return active;
    if (!impl_->provider_snapshot || !impl_->image_layout || !impl_->draft) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "tile decode prerequisites are unavailable", "decode"));
    }
    if (!impl_->native_decode_applicable) {
        const auto executable_bytes = impl_->executable_bytes();
        auto progress = impl_->update_progress_slot(baseline_progress_slot_t::decode,
            "decode", 0, 0, executable_bytes, executable_bytes);
        impl_->metrics->end_phase(measurement, 0, 0, 0, 1, !progress.has_value());
        return progress;
    }
    auto registration = default_arch_decoder_registry().resolve(impl_->decoder_key);
    if (!registration)
        return workspace_result_t<void>::failure(registration.error());

    const auto executor_queue_limit = (std::min)(
        impl_->settings.max_decode_queue,
        static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)()));
    auto limits = impl_->settings.tile_decode_limits;
    limits.maximum_frontier_seeds = (std::min)({
        limits.maximum_frontier_seeds,
        impl_->settings.max_seed_count,
        impl_->settings.max_decode_queue});
    limits.maximum_frontier_wave = (std::min)(
        limits.maximum_frontier_wave, executor_queue_limit);
    limits.maximum_decode_requests = (std::min)(
        limits.maximum_decode_requests, impl_->settings.max_decode_queue);
    limits.maximum_instructions = (std::min)(
        limits.maximum_instructions, impl_->settings.max_decoded_instructions);
    limits.maximum_coverage_spans = (std::min)(
        limits.maximum_coverage_spans, impl_->settings.max_coverage_spans);
    auto orchestrator = tile_decode_orchestrator_t::create(limits);
    if (!orchestrator)
        return workspace_result_t<void>::failure(orchestrator.error());

    const auto lane_total = (std::max)(1U, impl_->lane_total());
    const auto lane_workers = (std::max)(1U, impl_->decode_workers / lane_total);
    production_tile_decode_executor_options_t options;
    options.decoder_key = impl_->decoder_key;
    options.worker_count = lane_workers;
    options.maximum_frontier_wave = limits.maximum_frontier_wave;
    options.analysis_budget.max_queued_tasks =
        static_cast<std::uint32_t>(executor_queue_limit);
    options.analysis_budget.max_worker_slots = lane_workers + 1U;
    options.analysis_budget.reserved_control_worker_slots = 1;
    options.analysis_budget.max_private_bytes = impl_->settings.max_analysis_memory_bytes;
    options.analysis_budget.max_mapped_window_bytes =
        impl_->settings.max_analysis_memory_bytes;
    options.analysis_budget.max_spill_bytes = impl_->settings.max_analysis_memory_bytes;
    options.analysis_budget.max_cache_bytes = impl_->settings.max_analysis_memory_bytes;

    const auto trace_limit = static_cast<std::uint64_t>(
        impl_->settings.max_trace_instructions);
    options.x86_limits.maximum_window_bytes = (std::min)(
        impl_->settings.decode_read_window_bytes,
        decode::x86_tile_decode_limits_t::hard_maximum_window_bytes);
    options.x86_limits.maximum_decode_attempts = (std::min)(
        trace_limit, decode::x86_tile_decode_limits_t::hard_maximum_decode_attempts);
    options.x86_limits.maximum_instructions = (std::min)(
        trace_limit, decode::x86_tile_decode_limits_t::hard_maximum_instructions);
    options.x86_limits.maximum_operand_facts = saturated_product(
        options.x86_limits.maximum_instructions,
        arch_decode_result_t::operand_capacity,
        decode::x86_tile_decode_limits_t::hard_maximum_operand_facts);
    options.x86_limits.maximum_target_facts = saturated_product(
        options.x86_limits.maximum_instructions,
        arch_decode_result_t::target_capacity,
        decode::x86_tile_decode_limits_t::hard_maximum_target_facts);
    options.x86_limits.maximum_invalid_bytes = options.x86_limits.maximum_window_bytes;
    options.x86_limits.maximum_coverage_spans = (std::min)(
        options.x86_limits.maximum_instructions,
        decode::x86_tile_decode_limits_t::hard_maximum_coverage_spans);

    options.capstone_options.worker_budget.max_decode_attempts = (std::min)(
        impl_->settings.max_decoded_instructions,
        arch_decode_budget_t::hard_max_decode_attempts);
    options.capstone_options.worker_budget.max_input_bytes = (std::min)(
        impl_->settings.max_analysis_memory_bytes,
        arch_decode_budget_t::hard_max_input_bytes);
    options.capstone_options.worker_budget.max_instructions = (std::min)(
        impl_->settings.max_decoded_instructions,
        arch_decode_budget_t::hard_max_instructions);
    options.capstone_options.worker_budget.max_operand_facts = (std::min)(
        limits.maximum_operand_facts,
        arch_decode_budget_t::hard_max_operand_facts);
    options.capstone_options.worker_budget.max_target_facts = (std::min)(
        limits.maximum_target_facts,
        arch_decode_budget_t::hard_max_target_facts);
    options.capstone_options.tile_limits.maximum_tile_bytes = (std::min)(
        limits.target_tile_bytes,
        decode::capstone_tile_decode_limits_t::hard_maximum_tile_bytes);
    options.capstone_options.tile_limits.maximum_instruction_records = (std::min)(
        trace_limit,
        decode::capstone_tile_decode_limits_t::hard_maximum_instruction_records);
    options.capstone_options.tile_limits.maximum_operand_facts = saturated_product(
        options.capstone_options.tile_limits.maximum_instruction_records,
        arch_decode_result_t::operand_capacity,
        decode::capstone_tile_decode_limits_t::hard_maximum_operand_facts);
    options.capstone_options.tile_limits.maximum_target_facts = saturated_product(
        options.capstone_options.tile_limits.maximum_instruction_records,
        arch_decode_result_t::target_capacity,
        decode::capstone_tile_decode_limits_t::hard_maximum_target_facts);
    options.capstone_options.tile_limits.maximum_coverage_spans =
        options.capstone_options.tile_limits.maximum_instruction_records;
    options.capstone_options.tile_limits.maximum_consecutive_undecodable_bytes =
        (std::min)(limits.invalid_run_policy.maximum_gap_resynchronization_bytes,
            options.capstone_options.tile_limits.maximum_tile_bytes);

    auto executor = create_production_tile_decode_executor(
        std::move(options), impl_->cancellation.token());
    if (!executor)
        return workspace_result_t<void>::failure(executor.error());

    auto lane_state = impl_->ensure_decode_lane_state(executor.value()->capabilities(),
        limits);
    if (!lane_state)
        return lane_state;
    const auto lane_range = impl_->decode_lane_range(lane);

    std::vector<tile_decode_seed_t> decode_seeds;
    decode_seeds.reserve(impl_->seeds.size());
    for (const auto& seed : impl_->seeds) {
        decode_seeds.push_back(
            {seed.address, seed.provenance, seed.confidence, seed.stable_source_id});
    }
    auto decoded = orchestrator.value().run(*impl_->provider_snapshot,
        *impl_->image_layout, std::move(decode_seeds), *executor.value(),
        impl_->cancellation.token(),
        lane_total > 1U ? &lane_range : nullptr,
        lane_total > 1U ? &impl_->lane_seed_exchange : nullptr, lane);
    if (!decoded)
        return workspace_result_t<void>::failure(decoded.error());
    auto result = decoded.take_value();
    if (!result.packed_store) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "tile decode omitted its packed publication", "decode"));
    }
    auto retained = tile_decode_memory_bytes(result);
    if (!retained || retained.value() > impl_->settings.max_analysis_memory_bytes) {
        return workspace_result_t<void>::failure(retained
            ? make_workspace_error(workspace_error_code_t::limit_exceeded,
                "tile decode publication exceeds analysis memory budget", "decode")
            : retained.error());
    }
    const auto decoded_count = result.statistics.accepted_instructions;
    const auto initialized_bytes = result.statistics.initialized_executable_bytes;
    const auto lane_wall_ns = result.statistics.lane_wall_ns;
    impl_->tile_results[lane] = std::move(result);
    impl_->metrics->set_max(analysis_metric_t::decode_lane_wall_ns_max, lane_wall_ns);
    impl_->metrics->end_phase(measurement, initialized_bytes, retained.value(),
        decoded_count, 1, false);
    return impl_->update_progress_slot(baseline_progress_slot_t::decode, "decode",
        decoded_count, decoded_count, initialized_bytes, impl_->executable_bytes());
}
workspace_result_t<void> pe_baseline_analyzer_t::decode_merge_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::decode_merge);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::decode_merge);
    auto active = impl_->ensure_active(runtime_cancel, "decode_merge");
    if (!active)
        return active;
    if (!impl_->image_layout || !impl_->image || !impl_->draft) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "tile decode merge prerequisites are unavailable", "decode_merge"));
    }
    std::uint64_t merge_ns = 0;
    if (impl_->native_decode_applicable) {
        const auto merge_start = std::chrono::steady_clock::now();
        const auto lane_total = impl_->tile_results.size();
        if (lane_total == 0) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "tile decode merge publication is unavailable", "decode_merge"));
        }
        auto current = snapshot_memory_accounted_bytes(*impl_->draft);
        if (!current)
            return workspace_result_t<void>::failure(current.error());
        const auto r0 = current.value() >= impl_->settings.max_analysis_memory_bytes
            ? 0ULL
            : impl_->settings.max_analysis_memory_bytes - current.value();
        if (lane_total == 1) {
            if (!impl_->tile_results[0].packed_store) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "tile decode merge publication is unavailable", "decode_merge"));
            }
            auto materialized = decode_materializer::materialize(
                impl_->tile_results[0], *impl_->draft, r0,
                impl_->cancellation.token());
            if (!materialized)
                return materialized;
        } else {
            std::uint64_t instruction_total = 0;
            std::uint64_t operand_total = 0;
            std::uint64_t target_total = 0;
            std::uint64_t delay_total = 0;
            for (const auto& lane_result : impl_->tile_results) {
                if (!lane_result.packed_store) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "tile decode merge publication is unavailable", "decode_merge"));
                }
                if (!checked_add_u64(instruction_total,
                        static_cast<std::uint64_t>(
                            lane_result.packed_store->instruction_count()),
                        instruction_total) ||
                    !checked_add_u64(operand_total,
                        static_cast<std::uint64_t>(
                            lane_result.packed_store->operand_count()),
                        operand_total) ||
                    !checked_add_u64(target_total,
                        static_cast<std::uint64_t>(
                            lane_result.packed_store->target_fact_count()),
                        target_total) ||
                    !checked_add_u64(delay_total,
                        static_cast<std::uint64_t>(
                            lane_result.delay_slot_counts.size()),
                        delay_total)) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::range_overflow,
                        "tile decode merge accounting overflows", "decode_merge"));
                }
            }
            impl_->draft->instructions.reserve(
                static_cast<std::size_t>(instruction_total));
            impl_->draft->operand_facts.reserve(static_cast<std::size_t>(operand_total));
            impl_->draft->target_facts.reserve(static_cast<std::size_t>(target_total));
            impl_->draft->delay_slot_counts.reserve(static_cast<std::size_t>(delay_total));
            std::uint64_t instruction_offset = 0;
            std::uint64_t operand_offset = 0;
            std::uint64_t target_offset = 0;
            for (auto& lane_result : impl_->tile_results) {
                analysis_snapshot_t lane_snapshot;
                auto materialized = decode_materializer::materialize(lane_result,
                    lane_snapshot, r0, impl_->cancellation.token());
                if (!materialized)
                    return materialized;
                for (auto& instruction : lane_snapshot.instructions) {
                    instruction.id += instruction_offset;
                    std::uint64_t operand_begin = 0;
                    std::uint64_t target_begin = 0;
                    if (!checked_add_u64(
                            static_cast<std::uint64_t>(instruction.operand_fact_begin),
                            operand_offset, operand_begin) ||
                        operand_begin >
                            (std::numeric_limits<std::uint32_t>::max)()) {
                        return workspace_result_t<void>::failure(make_workspace_error(
                            workspace_error_code_t::limit_exceeded,
                            "tile decode operand table exceeds Compact IR capacity",
                            "decode_merge"));
                    }
                    if (!checked_add_u64(
                            static_cast<std::uint64_t>(instruction.target_fact_begin),
                            target_offset, target_begin) ||
                        target_begin >
                            (std::numeric_limits<std::uint32_t>::max)()) {
                        return workspace_result_t<void>::failure(make_workspace_error(
                            workspace_error_code_t::limit_exceeded,
                            "tile decode target table exceeds Compact IR capacity",
                            "decode_merge"));
                    }
                    instruction.operand_fact_begin =
                        static_cast<std::uint32_t>(operand_begin);
                    instruction.target_fact_begin =
                        static_cast<std::uint32_t>(target_begin);
                    impl_->draft->instructions.push_back(std::move(instruction));
                }
                for (auto& operand : lane_snapshot.operand_facts) {
                    operand.instruction_id += instruction_offset;
                    impl_->draft->operand_facts.push_back(std::move(operand));
                }
                for (auto& target : lane_snapshot.target_facts) {
                    target.instruction_id += instruction_offset;
                    impl_->draft->target_facts.push_back(std::move(target));
                }
                impl_->draft->delay_slot_counts.insert(
                    impl_->draft->delay_slot_counts.end(),
                    std::make_move_iterator(lane_snapshot.delay_slot_counts.begin()),
                    std::make_move_iterator(lane_snapshot.delay_slot_counts.end()));
                instruction_offset += static_cast<std::uint64_t>(
                    lane_snapshot.instructions.size());
                operand_offset += static_cast<std::uint64_t>(
                    lane_snapshot.operand_facts.size());
                target_offset += static_cast<std::uint64_t>(
                    lane_snapshot.target_facts.size());
            }
        }
        auto coverage = build_canonical_decode_coverage(*impl_->image, *impl_->image_layout,
            impl_->draft->instructions, impl_->settings.max_coverage_spans,
            impl_->cancellation.token());
        if (!coverage)
            return workspace_result_t<void>::failure(coverage.error());
        impl_->draft->coverage = coverage.take_value();
        merge_ns = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - merge_start).count());
        tile_decode_orchestrator_statistics_t decode_stats;
        for (const auto& lane_result : impl_->tile_results) {
            const auto& stats = lane_result.statistics;
            decode_stats.recursive_requests += stats.recursive_requests;
            decode_stats.gap_requests += stats.gap_requests;
            decode_stats.accepted_tiles += stats.accepted_tiles;
            decode_stats.frontier_waves += stats.frontier_waves;
            decode_stats.attempted_bytes += stats.attempted_bytes;
            decode_stats.cross_tile_edges += stats.cross_tile_edges;
            decode_stats.invalid_bytes += stats.invalid_bytes;
            decode_stats.invalid_runs += stats.invalid_runs;
            decode_stats.duplicate_instruction_candidates +=
                stats.duplicate_instruction_candidates;
            decode_stats.overlap_instruction_candidates +=
                stats.overlap_instruction_candidates;
            decode_stats.frontier.unique_seed_count += stats.frontier.unique_seed_count;
        }
        impl_->metrics->add(analysis_metric_t::decode_tiles,
            decode_stats.accepted_tiles);
        impl_->metrics->add(analysis_metric_t::decode_requests,
            decode_stats.recursive_requests + decode_stats.gap_requests);
        impl_->metrics->add(analysis_metric_t::decode_frontier_seeds,
            decode_stats.frontier.unique_seed_count);
        impl_->metrics->add(analysis_metric_t::decode_waves,
            decode_stats.frontier_waves);
        impl_->metrics->add(analysis_metric_t::decode_cross_tile_edges,
            decode_stats.cross_tile_edges);
        impl_->metrics->add(analysis_metric_t::decode_invalid_bytes,
            decode_stats.invalid_bytes);
        impl_->metrics->add(analysis_metric_t::decode_invalid_runs,
            decode_stats.invalid_runs);
        impl_->metrics->add(analysis_metric_t::decode_duplicate_instructions,
            decode_stats.duplicate_instruction_candidates +
                decode_stats.overlap_instruction_candidates);
        impl_->metrics->add(analysis_metric_t::decode_bytes_attempted,
            decode_stats.attempted_bytes);
        impl_->metrics->add(analysis_metric_t::decode_merge_ns, merge_ns);
    } else {
        auto coverage = build_managed_bytecode_coverage(*impl_->image,
            impl_->settings.max_coverage_spans, impl_->cancellation.token());
        if (!coverage)
            return workspace_result_t<void>::failure(coverage.error());
        impl_->draft->coverage = coverage.take_value();
    }
    impl_->tile_results.clear();
    impl_->decode_partition.reset();

    impl_->metrics->set(analysis_metric_t::instructions, impl_->draft->instructions.size());
    for (const auto& span : impl_->draft->coverage) {
        const auto metric = span.reason == coverage_reason_t::decoded
            ? analysis_metric_t::coverage_decoded_bytes
            : span.reason == coverage_reason_t::proven_data
                ? analysis_metric_t::coverage_data_bytes
                : span.reason == coverage_reason_t::padding
                    ? analysis_metric_t::coverage_padding_bytes
                    : span.reason == coverage_reason_t::conflict
                        ? analysis_metric_t::coverage_conflict_bytes
                        : analysis_metric_t::coverage_undecodable_bytes;
        impl_->metrics->add(metric, span.size);
    }
    auto retained = snapshot_memory_accounted_bytes(*impl_->draft);
    if (!retained || retained.value() > impl_->settings.max_analysis_memory_bytes) {
        return workspace_result_t<void>::failure(retained
            ? make_workspace_error(workspace_error_code_t::limit_exceeded,
                "decoded snapshot exceeds analysis memory budget", "decode_merge")
            : retained.error());
    }
    const auto remaining = impl_->settings.max_analysis_memory_bytes - retained.value();
    impl_->data_budget_bytes = remaining / 8ULL;
    impl_->function_budget_bytes = remaining / 4ULL;
    impl_->call_graph_budget_bytes = remaining / 4ULL;
    impl_->xref_budget_bytes = remaining / 4ULL;
    impl_->symbol_type_budget_bytes = remaining / 4ULL;
    impl_->metrics->end_phase(measurement, 0, retained.value(),
        impl_->draft->instructions.size(), 1, false);
    const auto completed_bytes = impl_->native_decode_applicable
        ? impl_->metrics->snapshot().value(analysis_metric_t::coverage_decoded_bytes)
        : impl_->executable_bytes();
    return impl_->update_progress_slot(baseline_progress_slot_t::decode_merge,
        "decode_merge", impl_->draft->instructions.size(),
        impl_->draft->instructions.size(),
        completed_bytes, impl_->executable_bytes());
}
workspace_result_t<void> pe_baseline_analyzer_t::data_discovery_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::blocks);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::data);
    auto active = impl_->ensure_active(runtime_cancel, "data_discovery");
    if (!active)
        return active;
    if (!impl_->image || !impl_->provider_snapshot || !impl_->draft) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "recovery prerequisites are unavailable", "data_discovery"));
    }
    if (impl_->data_budget_bytes == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "recovery module memory budget is exhausted", "data_discovery"));
    }

    auto data_limits = impl_->settings.data_limits;
    data_limits.max_result_bytes = (std::min)(data_limits.max_result_bytes,
        impl_->data_budget_bytes);
    data_limits.max_pointer_scan_bytes = (std::min)(
        data_limits.max_pointer_scan_bytes,
        impl_->settings.xref_limits.max_pointer_scan_bytes);
    data_limits.max_pointer_scan_bytes = (std::min)(
        data_limits.max_pointer_scan_bytes,
        saturated_double_u64(impl_->provider_snapshot->size()));
    data_limits.read_window_bytes = (std::min)(
        data_limits.read_window_bytes, impl_->settings.xref_limits.read_window_bytes);
    data_limits.cancellation_check_interval = (std::min)(
        data_limits.cancellation_check_interval,
        impl_->settings.cancellation_check_interval);
    auto data = data_discovery_t::discover(*impl_->image, *impl_->provider_snapshot,
        impl_->draft->instructions, impl_->draft->target_facts, data_limits,
        impl_->cancellation.token());
    if (!data)
        return workspace_result_t<void>::failure(data.error());
    impl_->data_result = std::shared_ptr<const data_discovery_result_t>(
        new data_discovery_result_t(data.take_value()));

    impl_->metrics->set(analysis_metric_t::data_candidates,
        impl_->data_result->candidates.size());
    impl_->metrics->add(analysis_metric_t::provider_leases,
        impl_->data_result->provider_leases);
    impl_->metrics->add(analysis_metric_t::mapped_bytes,
        impl_->data_result->mapped_bytes);
    impl_->metrics->add(analysis_metric_t::read_bytes,
        impl_->data_result->bytes_scanned);
    impl_->metrics->add(analysis_metric_t::pass_merge_ns,
        impl_->data_result->shard_merge_ns);
    impl_->metrics->end_phase(measurement,
        impl_->draft->instructions.size() * sizeof(instruction_record_t),
        0, impl_->data_result->candidates.size(), 1, false);
    return impl_->update_progress_slot(baseline_progress_slot_t::data,
        "data_discovery", impl_->data_result->candidates.size(),
        impl_->data_result->candidates.size(), impl_->data_result->bytes_scanned,
        impl_->data_result->bytes_scanned);
}
workspace_result_t<void> pe_baseline_analyzer_t::function_recovery_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::blocks);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::function_recovery);
    auto active = impl_->ensure_active(runtime_cancel, "function_recovery");
    if (!active)
        return active;
    if (!impl_->image || !impl_->provider_snapshot || !impl_->draft ||
        !impl_->data_result) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "recovery prerequisites are unavailable", "function_recovery"));
    }

    if (!impl_->native_decode_applicable) {
        impl_->function_result = {};
        impl_->metrics->set(analysis_metric_t::blocks, 0);
        impl_->metrics->end_phase(measurement,
            impl_->draft->instructions.size() * sizeof(instruction_record_t),
            0, 0, 1, false);
        const auto executable_bytes = impl_->executable_bytes();
        return impl_->update_progress_slot(
            baseline_progress_slot_t::function_recovery, "function_recovery", 0, 0,
            executable_bytes, executable_bytes);
    }
    if (impl_->function_budget_bytes == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "recovery module memory budget is exhausted", "function_recovery"));
    }

    auto function_limits = impl_->settings.function_limits;
    function_limits.max_seed_candidates = (std::min)(
        function_limits.max_seed_candidates, impl_->settings.max_seed_count);
    function_limits.max_result_bytes = (std::min)(
        function_limits.max_result_bytes, impl_->function_budget_bytes);
    function_limits.cancellation_check_interval = (std::min)(
        function_limits.cancellation_check_interval,
        impl_->settings.cancellation_check_interval);
    auto sources = group_function_seeds(impl_->seeds);
    function_seed_evidence_t evidence;
    evidence.pointer_facts = &impl_->data_result->pointer_facts;
    evidence.additional_sources = &sources;
    auto recovered = function_recovery_t::recover(*impl_->image,
        *impl_->provider_snapshot, impl_->draft->instructions,
        impl_->draft->operand_facts, impl_->draft->target_facts, evidence,
        impl_->draft->delay_slot_counts, function_limits,
        impl_->cancellation.token());
    if (!recovered)
        return workspace_result_t<void>::failure(recovered.error());
    impl_->function_result = recovered.take_value();

    impl_->metrics->add(analysis_metric_t::provider_leases,
        impl_->function_result.provider_leases);
    impl_->metrics->add(analysis_metric_t::mapped_bytes,
        impl_->function_result.mapped_bytes);
    impl_->metrics->add(analysis_metric_t::read_bytes,
        impl_->function_result.bytes_read);
    impl_->metrics->set(analysis_metric_t::blocks,
        impl_->function_result.blocks.size());
    impl_->metrics->add(analysis_metric_t::blocks_split,
        impl_->function_result.blocks.size());
    impl_->metrics->add(analysis_metric_t::pass_merge_ns,
        impl_->function_result.shard_merge_ns);
    impl_->metrics->end_phase(measurement,
        impl_->draft->instructions.size() * sizeof(instruction_record_t),
        impl_->function_result.storage_bytes,
        impl_->function_result.blocks.size(), 1, false);
    return impl_->update_progress_slot(baseline_progress_slot_t::function_recovery,
        "function_recovery", impl_->function_result.blocks.size(),
        impl_->function_result.blocks.size(), impl_->function_result.bytes_read,
        impl_->executable_bytes());
}
workspace_result_t<void> pe_baseline_analyzer_t::functions_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::functions);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::call_graph);
    auto active = impl_->ensure_active(runtime_cancel, "functions");
    if (!active)
        return active;
    if (!impl_->native_decode_applicable) {
        impl_->call_graph_result = {};
        impl_->metrics->set(analysis_metric_t::functions, 0);
        impl_->metrics->set(analysis_metric_t::thunks, 0);
        impl_->metrics->set(analysis_metric_t::noreturn_functions, 0);
        impl_->metrics->end_phase(measurement, 0, 0, 0, 1, false);
        const auto executable_bytes = impl_->executable_bytes();
        return impl_->update_progress_slot(baseline_progress_slot_t::call_graph,
            "functions", 0, 0, executable_bytes, executable_bytes);
    }
    if (!impl_->draft || !impl_->data_result) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "call graph prerequisites are unavailable", "functions"));
    }
    if (impl_->call_graph_budget_bytes == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "call graph memory budget is exhausted", "functions"));
    }
    auto limits = impl_->settings.call_graph_limits;
    limits.max_result_bytes = (std::min)(limits.max_result_bytes,
        impl_->call_graph_budget_bytes);
    limits.cancellation_check_interval = (std::min)(
        limits.cancellation_check_interval,
        impl_->settings.cancellation_check_interval);
    const auto maximum_indirect_candidates = (std::min)(
        limits.max_candidates,
        limits.max_result_bytes / sizeof(indirect_call_candidate_t));
    auto indirect_candidates = build_indirect_call_candidates(
        impl_->draft->instructions, impl_->draft->target_facts,
        impl_->data_result->pointer_facts, maximum_indirect_candidates,
        limits.cancellation_check_interval, impl_->cancellation.token());
    if (!indirect_candidates)
        return workspace_result_t<void>::failure(indirect_candidates.error());
    auto graph = call_graph_builder_t::build(impl_->draft->instructions,
        impl_->draft->target_facts, impl_->function_result,
        indirect_candidates.value(), limits, impl_->cancellation.token());
    if (!graph)
        return workspace_result_t<void>::failure(graph.error());
    impl_->call_graph_result = graph.take_value();
    impl_->metrics->add(analysis_metric_t::pass_merge_ns,
        impl_->call_graph_result.shard_merge_ns);
    impl_->metrics->add(analysis_metric_t::cfg_indirect_sites,
        impl_->call_graph_result.indirect_site_count);

    impl_->metrics->set(analysis_metric_t::functions,
        impl_->function_result.functions.size());
    impl_->metrics->set(analysis_metric_t::thunks,
        static_cast<std::uint64_t>(std::count_if(
            impl_->function_result.functions.begin(),
            impl_->function_result.functions.end(),
            [](const function_record_t& function) { return function.thunk; })));
    impl_->metrics->set(analysis_metric_t::noreturn_functions,
        static_cast<std::uint64_t>(std::count_if(
            impl_->function_result.functions.begin(),
            impl_->function_result.functions.end(),
            [](const function_record_t& function) { return function.noreturn; })));
    impl_->metrics->add(analysis_metric_t::function_seeds_processed,
        impl_->function_result.converged_seed_count);
    impl_->metrics->end_phase(measurement,
        impl_->function_result.converged_seed_count * sizeof(function_seed_t),
        impl_->call_graph_result.storage_bytes,
        impl_->function_result.functions.size(), 1, false);
    return impl_->update_progress_slot(baseline_progress_slot_t::call_graph,
        "functions", impl_->function_result.functions.size(),
        impl_->function_result.functions.size(), 0, impl_->executable_bytes());
}
workspace_result_t<void> pe_baseline_analyzer_t::cfg_calls_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::cfg_calls);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::cfg_calls);
    auto active = impl_->ensure_active(runtime_cancel, "cfg_calls");
    if (!active)
        return active;
    impl_->draft->blocks = std::move(impl_->function_result.blocks);
    impl_->draft->functions = std::move(impl_->function_result.functions);
    impl_->draft->function_chunks = std::move(impl_->function_result.function_chunks);
    impl_->draft->function_block_memberships =
        std::move(impl_->function_result.function_block_memberships);
    impl_->draft->edges = std::move(impl_->function_result.edges);
    std::uint64_t function_chunk_bytes = 0;
    for (const auto& function : impl_->draft->functions) {
        std::uint64_t bytes = 0;
        std::uint64_t updated = 0;
        if (!checked_mul_u64(
                static_cast<std::uint64_t>(function.chunks.capacity()),
                static_cast<std::uint64_t>(sizeof(address_range_t)), bytes) ||
            !checked_add_u64(function_chunk_bytes, bytes, updated)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "analysis memory accounting overflows", "memory_budget"));
        }
        function_chunk_bytes = updated;
    }
    impl_->draft->function_chunk_bytes = function_chunk_bytes;
    auto published = call_graph_builder_t::publish(
        *impl_->draft, std::move(impl_->call_graph_result),
        impl_->cancellation.token());
    if (!published)
        return published;

    impl_->metrics->set(analysis_metric_t::cfg_edges,
        static_cast<std::uint64_t>(std::count_if(
            impl_->draft->edges.begin(), impl_->draft->edges.end(),
            [](const edge_record_t& edge) {
                return edge.kind != edge_kind_t::call &&
                    edge.kind != edge_kind_t::tail_call;
            })));
    impl_->metrics->set(analysis_metric_t::call_edges,
        impl_->draft->call_graph.edges.size());
    impl_->metrics->set(analysis_metric_t::switches,
        impl_->function_result.switches.size());
    auto retained = snapshot_memory_accounted_bytes(*impl_->draft);
    if (!retained || retained.value() > impl_->settings.max_analysis_memory_bytes) {
        return workspace_result_t<void>::failure(retained
            ? make_workspace_error(workspace_error_code_t::limit_exceeded,
                "recovery publication exceeds analysis memory budget", "cfg_calls")
            : retained.error());
    }
    const auto work_items = impl_->draft->edges.size() +
        impl_->draft->call_graph.call_sites.size() +
        impl_->draft->call_graph.candidates.size();
    impl_->metrics->end_phase(measurement,
        impl_->draft->instructions.size() * sizeof(instruction_record_t),
        retained.value(), work_items, 1, false);
    return impl_->update_progress_slot(baseline_progress_slot_t::cfg_calls,
        "cfg_calls", work_items, work_items, 0, impl_->executable_bytes());
}
workspace_result_t<void> pe_baseline_analyzer_t::xrefs_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::xrefs);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::xrefs);
    auto active = impl_->ensure_active(runtime_cancel, "xrefs");
    if (!active)
        return active;
    if (!impl_->draft || !impl_->provider_snapshot) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "xref prerequisites are unavailable", "xrefs"));
    }
    if (impl_->xref_budget_bytes == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "xref result memory budget is exhausted", "xrefs"));
    }
    auto limits = impl_->settings.xref_limits;
    limits.max_result_bytes = (std::min)(limits.max_result_bytes,
        impl_->xref_budget_bytes);
    limits.max_data_candidates = (std::min)(
        limits.max_data_candidates, impl_->settings.data_limits.max_candidates);
    limits.max_pointer_facts = (std::min)(
        limits.max_pointer_facts, impl_->settings.data_limits.max_pointer_facts);
    limits.max_data_conflicts = (std::min)(
        limits.max_data_conflicts, impl_->settings.data_limits.max_conflicts);
    limits.max_pointer_scan_bytes = (std::min)(
        limits.max_pointer_scan_bytes,
        saturated_double_u64(impl_->provider_snapshot->size()));
    limits.read_window_bytes = (std::min)(
        limits.read_window_bytes, impl_->settings.data_limits.read_window_bytes);
    limits.cancellation_check_interval = (std::min)(
        limits.cancellation_check_interval,
        impl_->settings.cancellation_check_interval);
    auto built = xref_builder_t::build(*impl_->image, impl_->draft->instructions,
        impl_->draft->operand_facts, impl_->draft->target_facts, impl_->data_result,
        std::vector<type_reference_fact_t>{}, limits, impl_->cancellation.token());
    if (!built)
        return workspace_result_t<void>::failure(built.error());
    impl_->xref_result = built.take_value();

    impl_->metrics->set(analysis_metric_t::xrefs, impl_->xref_result.xrefs.size());
    impl_->metrics->set(analysis_metric_t::data_candidates,
        impl_->xref_result.data_candidates.size());
    impl_->metrics->add(analysis_metric_t::xref_candidates,
        impl_->xref_result.xrefs.size() + impl_->xref_result.duplicate_xrefs);
    impl_->metrics->add(analysis_metric_t::pass_merge_ns,
        impl_->xref_result.shard_merge_ns);
    impl_->metrics->end_phase(measurement, impl_->xref_result.bytes_scanned,
        limits.max_result_bytes, impl_->xref_result.xrefs.size(), 1, false);
    return impl_->update_progress_slot(baseline_progress_slot_t::xrefs, "xrefs",
        impl_->xref_result.xrefs.size(), impl_->xref_result.xrefs.size(),
        impl_->xref_result.bytes_scanned, impl_->xref_result.bytes_scanned);
}
workspace_result_t<void> pe_baseline_analyzer_t::strings_data_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::strings_data);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::strings);
    auto active = impl_->ensure_active(runtime_cancel, "strings_data");
    if (!active)
        return active;
    if (!impl_->image || !impl_->provider_snapshot || !impl_->draft) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "string discovery prerequisites are unavailable", "strings_data"));
    }
    if (impl_->strings_budget_bytes == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "string result memory budget is exhausted", "strings_data"));
    }
    auto limits = impl_->settings.string_limits;
    limits.max_strings = (std::min)(limits.max_strings, impl_->settings.max_strings);
    limits.max_scan_bytes = (std::min)({
        limits.max_scan_bytes,
        impl_->settings.max_string_scan_bytes,
        saturated_double_u64(impl_->provider_snapshot->size())});
    limits.max_result_bytes = (std::min)(limits.max_result_bytes,
        impl_->strings_budget_bytes);
    limits.max_string_value_bytes = (std::min)(
        limits.max_string_value_bytes, impl_->settings.max_string_value_bytes);
    limits.read_window_bytes = (std::min)(
        limits.read_window_bytes, impl_->settings.string_read_window_bytes);
    limits.minimum_code_points = (std::max)(
        limits.minimum_code_points, impl_->settings.minimum_string_length);
    limits.cancellation_check_interval = (std::min)({
        limits.cancellation_check_interval,
        impl_->settings.cancellation_check_interval,
        impl_->settings.string_cancellation_interval_bytes});
    limits.scan_ascii = limits.scan_ascii && impl_->settings.scan_utf8;
    limits.scan_utf8 = limits.scan_utf8 && impl_->settings.scan_utf8;
    limits.scan_utf16_le = limits.scan_utf16_le && impl_->settings.scan_utf16;
    auto discovered = string_discovery_t::discover(*impl_->image,
        *impl_->provider_snapshot, limits, impl_->cancellation.token());
    if (!discovered)
        return workspace_result_t<void>::failure(discovered.error());
    impl_->string_result = discovered.take_value();

    impl_->metrics->set(analysis_metric_t::strings,
        impl_->string_result.strings.size());
    impl_->metrics->add(analysis_metric_t::provider_leases,
        impl_->string_result.provider_leases);
    impl_->metrics->add(analysis_metric_t::mapped_bytes,
        impl_->string_result.mapped_bytes);
    impl_->metrics->add(analysis_metric_t::read_bytes,
        impl_->string_result.bytes_scanned);
    impl_->metrics->add(analysis_metric_t::strings_scanned_bytes,
        impl_->string_result.bytes_scanned);
    impl_->metrics->add(analysis_metric_t::pass_merge_ns,
        impl_->string_result.shard_merge_ns);
    impl_->metrics->end_phase(measurement, impl_->string_result.bytes_scanned,
        limits.max_result_bytes, impl_->string_result.strings.size(), 1, false);
    return impl_->update_progress_slot(baseline_progress_slot_t::strings,
        "strings_data", impl_->string_result.strings.size(),
        impl_->string_result.strings.size(),
        impl_->string_result.bytes_scanned,
        impl_->string_result.bytes_scanned);
}
workspace_result_t<void> pe_baseline_analyzer_t::metadata_symbols_types_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(
        baseline_phase_t::metadata_symbols_types);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::metadata);
    auto active = impl_->ensure_active(runtime_cancel, "metadata_symbols_types");
    if (!active)
        return active;
    if (impl_->symbol_type_budget_bytes == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "metadata result memory budget is exhausted",
            "metadata_symbols_types"));
    }
    auto limits = impl_->settings.symbol_type_limits;
    limits.max_result_bytes = (std::min)(limits.max_result_bytes,
        impl_->symbol_type_budget_bytes);
    limits.cancellation_check_interval = (std::min)(
        limits.cancellation_check_interval,
        impl_->settings.cancellation_check_interval);
    symbol_type_metadata_sources_t metadata;
    auto built = symbol_type_candidate_builder_t::build(*impl_->image,
        impl_->draft->functions, impl_->xref_result.data_candidates,
        metadata, limits, impl_->cancellation.token());
    if (!built)
        return workspace_result_t<void>::failure(built.error());
    impl_->symbol_type_result = built.take_value();
    impl_->metrics->add(analysis_metric_t::type_candidates_evaluated,
        impl_->symbol_type_result.type_candidates.size() +
            impl_->symbol_type_result.duplicate_type_candidates);

    impl_->type_candidates.clear();
    impl_->type_candidates.reserve(
        impl_->symbol_type_result.type_candidates.size());
    for (const auto& candidate : impl_->symbol_type_result.type_candidates) {
        if (!candidate.address)
            continue;
        type_candidate_record_t legacy;
        switch (candidate.kind) {
            case symbol_type_candidate_kind_t::function_prototype:
                legacy.kind = type_candidate_kind_t::function_prototype;
                break;
            case symbol_type_candidate_kind_t::import_prototype:
                legacy.kind = type_candidate_kind_t::import_prototype;
                break;
            case symbol_type_candidate_kind_t::global_object:
                legacy.kind = type_candidate_kind_t::global_object;
                break;
            case symbol_type_candidate_kind_t::pointer_object:
                legacy.kind = type_candidate_kind_t::pointer_object;
                break;
            default:
                continue;
        }
        legacy.address = *candidate.address;
        legacy.display_name = candidate.display_name;
        legacy.canonical_type = candidate.canonical_type;
        legacy.provenance = legacy_type_provenance(candidate.provenance);
        legacy.confidence = candidate.confidence;
        legacy.explicitly_unknown = candidate.explicitly_unknown;
        impl_->type_candidates.push_back(std::move(legacy));
    }
    for (std::size_t index = 0; index < impl_->type_candidates.size(); ++index) {
        impl_->type_candidates[index].id =
            kTypeEntityTag | static_cast<std::uint64_t>(index + 1);
    }

    auto published = xref_builder_t::publish(*impl_->draft,
        std::move(impl_->xref_result), std::move(impl_->string_result),
        std::move(impl_->symbol_type_result), impl_->cancellation.token());
    if (!published)
        return published;
    std::unordered_map<std::uint64_t, std::size_t> function_symbol_by_value;
    for (std::size_t index = 0; index < impl_->draft->symbols.size(); ++index) {
        const auto& symbol = impl_->draft->symbols[index];
        if (symbol.kind == symbol_kind_t::function)
            function_symbol_by_value.emplace(symbol.address.value, index);
    }
    for (auto& function : impl_->draft->functions) {
        const auto found = function_symbol_by_value.find(function.start.value);
        if (found != function_symbol_by_value.end()) {
            const auto& symbol = impl_->draft->symbols[found->second];
            if (symbol.address == function.start)
                function.symbol_id = symbol.id;
        }
    }

    impl_->metrics->set(analysis_metric_t::xrefs, impl_->draft->xrefs.size());
    impl_->metrics->set(analysis_metric_t::strings, impl_->draft->strings.size());
    impl_->metrics->set(analysis_metric_t::symbols, impl_->draft->symbols.size());
    impl_->metrics->set(analysis_metric_t::types,
        impl_->draft->rich_facts.type_candidates.size());
    auto retained = snapshot_memory_accounted_bytes(*impl_->draft);
    if (!retained || retained.value() > impl_->settings.max_analysis_memory_bytes) {
        return workspace_result_t<void>::failure(retained
            ? make_workspace_error(workspace_error_code_t::limit_exceeded,
                "rich fact publication exceeds analysis memory budget",
                "metadata_symbols_types")
            : retained.error());
    }
    const auto work_items = impl_->draft->xrefs.size() +
        impl_->draft->strings.size() + impl_->draft->symbols.size() +
        impl_->draft->rich_facts.data_candidates.size() +
        impl_->draft->rich_facts.type_candidates.size();
    impl_->metrics->end_phase(measurement,
        impl_->image->symbols.size() + impl_->image->imports.size() +
            impl_->image->exports.size(),
        retained.value(), work_items, 1, false);
    return impl_->update_progress_slot(baseline_progress_slot_t::metadata,
        "metadata_symbols_types", work_items, work_items, 0,
        impl_->executable_bytes());
}

workspace_result_t<void> pe_baseline_analyzer_t::search_index_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::search_index);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::search);
    auto active = impl_->ensure_active(runtime_cancel, "search_index");
    if (!active)
        return active;
    if (!impl_->provider_snapshot) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "baseline provider snapshot is unavailable", "search_index"));
    }
    auto source_valid = impl_->provider_snapshot->validate_source();
    if (!source_valid)
        return source_valid;
    impl_->draft->baseline_complete = true;
    auto coverage = validate_coverage_linear_cancellable(*impl_->draft, impl_->cancellation.token());
    if (!coverage)
        return coverage;
    auto validated = validate_analysis_snapshot(*impl_->draft, true, impl_->cancellation.token());
    if (!validated)
        return validated;
    impl_->final_snapshot = impl_->draft;
    impl_->draft.reset();
    auto bytes = snapshot_memory_accounted_bytes(*impl_->final_snapshot);
    if (!bytes || bytes.value() >= impl_->settings.max_analysis_memory_bytes) {
        return workspace_result_t<void>::failure(bytes ? make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "analysis snapshot exhausts the retained memory budget", "search_index") : bytes.error());
    }
    auto limits = impl_->settings.search_limits;
    limits.max_index_bytes = std::min(limits.max_index_bytes,
        impl_->settings.max_analysis_memory_bytes - bytes.value());
    auto index = search_index_t::build(impl_->final_snapshot,
        impl_->final_snapshot->rich_facts.data_candidates,
        std::move(impl_->function_result.switches),
        std::move(impl_->type_candidates), impl_->metrics, limits, impl_->cancellation.token());
    if (!index)
        return workspace_result_t<void>::failure(index.error());
    impl_->search = index.take_value();
    std::uint64_t retained = 0;
    if (!checked_add_u64(bytes.value(), impl_->search->memory_bytes(), retained) ||
        retained > impl_->settings.max_analysis_memory_bytes) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "retained baseline state exceeds analysis memory budget", "search_index"));
    }
    const auto count = impl_->final_snapshot->instructions.size() + impl_->final_snapshot->symbols.size() +
        impl_->final_snapshot->strings.size() + impl_->search->data_candidates().size() +
        impl_->search->switches().size() + impl_->search->types().size();
    impl_->metrics->end_phase(measurement, count, retained, count, 1, false);
    return impl_->update_progress_slot(baseline_progress_slot_t::search,
        "search_index", count, count,
        impl_->metrics->snapshot().value(analysis_metric_t::indexed_bytes),
        impl_->metrics->snapshot().value(analysis_metric_t::indexed_bytes));
}

workspace_result_t<void> pe_baseline_analyzer_t::persistence_submit_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::persistence);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::persistence_submit);
    auto active = impl_->ensure_active(runtime_cancel, "persistence");
    if (!active)
        return active;
    const auto database = impl_->workspace->database();
    if (!database || !impl_->final_snapshot || !impl_->search) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::persistence_failure,
            "baseline persistence prerequisites are unavailable", "persistence"));
    }
    persisted_search_products_t products;
    products.generation = impl_->final_snapshot->generation;
    products.analysis_revision = impl_->final_snapshot->analysis_revision;
    products.overlay_revision = impl_->final_snapshot->overlay_revision;
    products.live_index = impl_->search;
    const auto cancel = impl_->cancellation.token();
    active = impl_->ensure_active(runtime_cancel, "persistence");
    if (!active)
        return active;
    std::shared_ptr<const managed_artifact_publication_t> managed_publication;
    const auto current_publication = impl_->workspace->analysis_publication();
    if (!current_publication || !current_publication->provider) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "workspace publication is unavailable before persistence",
            "persistence"));
    }
    if (current_publication->managed_artifacts) {
        auto rebound = rebind_managed_artifact_publication(
            *current_publication->managed_artifacts,
            impl_->workspace->identity(), *current_publication->provider,
            impl_->final_snapshot->image, impl_->final_snapshot->generation,
            impl_->final_snapshot->analysis_revision,
            impl_->final_snapshot->overlay_revision, cancel);
        if (!rebound)
            return workspace_result_t<void>::failure(rebound.error());
        managed_publication = rebound.take_value();
    }
    impl_->persistence_ticket = database->persist_snapshot(
        impl_->final_snapshot, std::move(products), std::move(managed_publication),
        impl_->settings.canonical_json(), impl_->metrics->snapshot().to_json(), cancel);
    if (!impl_->persistence_ticket.accepted || !impl_->persistence_ticket.completion.valid() ||
        !impl_->persistence_ticket.snapshot_candidate) {
        impl_->discard_persistence_candidate();
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::persistence_failure,
            "workspace persistence queue rejected the baseline snapshot", "persistence"));
    }
    impl_->metrics->end_phase(measurement, 0, 0, 1, 1, false);
    return impl_->update_progress_slot(baseline_progress_slot_t::persistence_submit,
        "persistence", 1, 1, 0, 0);
}

workspace_result_t<void> pe_baseline_analyzer_t::persistence_commit_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::persistence);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::persistence_commit);
    auto active = impl_->ensure_active(runtime_cancel, "persistence");
    if (!active)
        return active;
    const auto database = impl_->workspace->database();
    if (!database || !impl_->persistence_ticket.accepted ||
        !impl_->persistence_ticket.completion.valid() ||
        !impl_->persistence_ticket.snapshot_candidate) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "baseline persistence ticket is unavailable", "persistence"));
    }
    impl_->persistence_ticket.completion.wait();
    active = impl_->ensure_active(runtime_cancel, "persistence");
    if (!active) {
        impl_->discard_persistence_candidate();
        return active;
    }
    const auto& completed = impl_->persistence_ticket.completion.get();
    if (!completed) {
        impl_->discard_persistence_candidate();
        return workspace_result_t<void>::failure(completed.error());
    }
    const auto snapshot_metrics = impl_->persistence_ticket.commit_metrics;
    const auto candidate = impl_->persistence_ticket.snapshot_candidate;
    if (!snapshot_metrics || !candidate->packed_generation_required()) {
        impl_->discard_persistence_candidate();
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "packed snapshot persistence omitted candidate or commit metrics",
            "persistence"));
    }

    const auto database_state = database->snapshot();
    std::uint64_t footprint = 0;
    std::uint64_t logical_bytes = 0;
    std::uint64_t page_write_bytes = 0;
    std::uint64_t rows = 0;
    std::uint64_t elapsed_us = 0;
    std::uint64_t elapsed = 0;
    if (!checked_add_u64(database_state.database_bytes, database_state.wal_bytes, footprint) ||
        !checked_add_u64(0, snapshot_metrics->logical_bytes, logical_bytes) ||
        !checked_add_u64(0, snapshot_metrics->page_write_bytes, page_write_bytes) ||
        !checked_add_u64(0, snapshot_metrics->rows, rows) ||
        !checked_add_u64(0, snapshot_metrics->elapsed_us, elapsed_us) ||
        !checked_mul_u64(elapsed_us, 1000ULL, elapsed)) {
        impl_->discard_persistence_candidate();
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "persistence metric accounting overflows", "persistence"));
    }
    impl_->metrics->set(analysis_metric_t::database_bytes, footprint);
    impl_->metrics->add(analysis_metric_t::database_bytes_written, page_write_bytes);
    impl_->metrics->add(analysis_metric_t::database_logical_bytes, logical_bytes);
    impl_->metrics->add(analysis_metric_t::database_rows, rows);
    impl_->metrics->add(analysis_metric_t::database_commit_elapsed_ns, elapsed);
    impl_->metrics->add(analysis_metric_t::persistence_batches, 1);
    if (const auto queue = database->queue()) {
        const auto queue_state = queue->snapshot();
        impl_->metrics->add(analysis_metric_t::persist_queue_wait_ns,
            queue_state.total_wait_ns);
        impl_->metrics->set_max(analysis_metric_t::persist_queue_depth_peak,
            queue_state.pending_depth_peak);
    }
    impl_->metrics->add(analysis_metric_t::persist_pages_written,
        database_state.cumulative_pages_written);
    impl_->metrics->set_max(analysis_metric_t::persist_wal_bytes_peak,
        database_state.wal_bytes_peak);
    impl_->metrics->end_phase(measurement, logical_bytes, page_write_bytes,
        rows, 1, false);
    return impl_->update_progress_slot(baseline_progress_slot_t::persistence_commit,
        "persistence", 1, 1, footprint, footprint);
}

workspace_result_t<void> pe_baseline_analyzer_t::publish_ready_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::publish_ready);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto node_window = impl_->node_guard(baseline_progress_slot_t::publish);
    auto active = impl_->ensure_active(runtime_cancel, "publish_ready");
    if (!active)
        return active;
    if (!impl_->final_snapshot || !impl_->search || !impl_->search->matches(
            impl_->final_snapshot->generation, impl_->final_snapshot->analysis_revision,
            impl_->final_snapshot->overlay_revision) || !impl_->persistence_ticket.snapshot_candidate) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "immutable baseline products are incomplete", "publish_ready"));
    }
    const auto candidate = impl_->persistence_ticket.snapshot_candidate;
    auto published = impl_->workspace->publish_analysis_bundle(impl_->expected_generation,
        impl_->expected_analysis_revision, impl_->final_snapshot, impl_->search, true,
        [candidate] { return candidate->finalize(); });
    if (!published) {
        impl_->discard_persistence_candidate();
        return published;
    }
    node_window.finish();
    std::string windows;
    for (std::size_t index = 0; index < kProgressSlotCount; ++index) {
        if (index != 0)
            windows += ' ';
        windows += kNodeWindowNames[index];
        windows += "=[";
        windows += std::to_string(
            impl_->node_start_ns[index].load(std::memory_order_acquire));
        windows += ',';
        windows += std::to_string(
            impl_->node_end_ns[index].load(std::memory_order_acquire));
        windows += ']';
    }
    ::diag::log_tagged_fmt("baseline_pipeline", "baseline_node_windows %s",
        windows.c_str());
    impl_->metrics->end_phase(measurement, 0, 0, 1, 1, false);
    impl_->metrics->mark_finished();
    return workspace_result_t<void>::success();
}

void pe_baseline_analyzer_t::request_cancel() noexcept {
    impl_->metrics->record_cancellation_request();
    impl_->cancellation.request_cancel();
}

void pe_baseline_analyzer_t::report_failure(const workspace_error_t& error) noexcept {
    bool publish = false;
    {
        std::lock_guard<std::mutex> lock(impl_->failure_mutex);
        if (!impl_->first_failure) {
            impl_->first_failure = error;
            publish = true;
        }
    }
    if (error.cancellation)
        impl_->metrics->record_cancellation_completion();
    impl_->discard_persistence_candidate();
    impl_->metrics->mark_finished();
    if (publish) {
        (void)impl_->workspace->record_analysis_attempt_failure(
            impl_->expected_generation, impl_->expected_analysis_revision, error);
    }
}

}
