#include "xref_builder.hpp"

#include "checked_range.hpp"

#include <algorithm>
#include <map>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::uint64_t kXrefEntityTag = 5ULL << 56;
constexpr std::uint64_t kDataEntityTag = 8ULL << 56;

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

bool image_contains_rva(const workspace_image_t& image, std::uint64_t rva) noexcept {
    return workspace_image_contains(image, rva_address(image, rva));
}

xref_kind_t data_xref_kind(const instruction_record_t& instruction,
                           const std::vector<operand_fact_t>& operands) noexcept {
    const auto end = static_cast<std::uint64_t>(instruction.operand_fact_begin) +
        instruction.operand_fact_count;
    if (end > operands.size())
        return xref_kind_t::address;
    bool reads = false;
    bool writes = false;
    for (std::uint64_t index = instruction.operand_fact_begin; index < end; ++index) {
        const auto access = operands[static_cast<std::size_t>(index)].access;
        reads = reads || (access & 1U) != 0;
        writes = writes || (access & 2U) != 0;
    }
    return writes ? xref_kind_t::write : reads ? xref_kind_t::read : xref_kind_t::address;
}

std::uint64_t target_access_bytes(const target_fact_t& target) noexcept {
    if (target.access_width_bits == 0)
        return 0;
    return (static_cast<std::uint64_t>(target.access_width_bits) + 7ULL) / 8ULL;
}

bool xref_less(const xref_record_t& lhs, const xref_record_t& rhs) noexcept {
    if (lhs.source != rhs.source)
        return lhs.source < rhs.source;
    if (lhs.target != rhs.target)
        return lhs.target < rhs.target;
    if (lhs.kind != rhs.kind)
        return lhs.kind < rhs.kind;
    if (lhs.provenance != rhs.provenance)
        return provenance_rank(lhs.provenance) > provenance_rank(rhs.provenance);
    return lhs.confidence > rhs.confidence;
}

bool xref_equal(const xref_record_t& lhs, const xref_record_t& rhs) noexcept {
    return lhs.source == rhs.source && lhs.target == rhs.target && lhs.kind == rhs.kind;
}

bool data_less(const data_candidate_record_t& lhs,
               const data_candidate_record_t& rhs) noexcept {
    if (lhs.address != rhs.address)
        return lhs.address < rhs.address;
    if (lhs.kind != rhs.kind)
        return lhs.kind < rhs.kind;
    if (lhs.target != rhs.target)
        return lhs.target < rhs.target;
    if (lhs.provenance != rhs.provenance)
        return provenance_rank(lhs.provenance) > provenance_rank(rhs.provenance);
    return lhs.confidence > rhs.confidence;
}

bool data_equal(const data_candidate_record_t& lhs,
                const data_candidate_record_t& rhs) noexcept {
    return lhs.address == rhs.address && lhs.kind == rhs.kind && lhs.target == rhs.target;
}

std::uint64_t read_integer(const std::uint8_t* data, std::uint8_t size,
                           endian_t endian) noexcept {
    std::uint64_t value = 0;
    if (endian == endian_t::little) {
        for (std::uint8_t index = 0; index < size; ++index)
            value |= static_cast<std::uint64_t>(data[index]) << (index * 8U);
    } else {
        for (std::uint8_t index = 0; index < size; ++index)
            value = (value << 8U) | data[index];
    }
    return value;
}

template <typename T>
workspace_result_t<void> append_bounded(std::vector<T>& values, T value,
    std::uint64_t maximum_count, std::uint64_t maximum_bytes,
    std::uint64_t& storage_bytes, const char* message) {
    if (values.size() >= maximum_count) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded, message, "xrefs"));
    }
    if (values.size() == values.capacity()) {
        const auto current = static_cast<std::uint64_t>(values.capacity());
        std::uint64_t desired = current == 0 ? std::min<std::uint64_t>(4096, maximum_count) : 0;
        if (current != 0 && !checked_add_u64(current, current / 2ULL, desired)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow, message, "xrefs"));
        }
        std::uint64_t minimum = 0;
        if (!checked_add_u64(current, 1, minimum)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow, message, "xrefs"));
        }
        desired = std::min(std::max(desired, minimum), maximum_count);
        std::uint64_t allocation = 0;
        std::uint64_t peak = 0;
        std::uint64_t retained = 0;
        if (desired <= current || !checked_mul_u64(desired, sizeof(T), allocation) ||
            !checked_add_u64(storage_bytes, allocation, peak) || peak > maximum_bytes ||
            !checked_mul_u64(desired - current, sizeof(T), retained)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded, message, "xrefs"));
        }
        values.reserve(static_cast<std::size_t>(desired));
        if (!checked_add_u64(storage_bytes, retained, storage_bytes)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow, message, "xrefs"));
        }
    }
    values.push_back(std::move(value));
    return workspace_result_t<void>::success();
}

} 

workspace_result_t<xref_build_result_t> xref_builder_t::build(
    const workspace_image_t& image,
    const byte_provider_t& provider,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<operand_fact_t>& operands,
    const std::vector<target_fact_t>& targets,
    const xref_build_limits_t& limits,
    const cancellation_token_t& cancel) {
    if (limits.max_xrefs == 0 || limits.max_data_candidates == 0 ||
        limits.max_result_bytes == 0 || limits.read_window_bytes == 0 ||
        limits.cancellation_check_interval == 0) {
        return workspace_result_t<xref_build_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument, "xref build limits are invalid", "xrefs"));
    }
    xref_build_result_t result;
    std::uint64_t storage_bytes = 0;
    const auto append_xref = [&](xref_record_t value) {
        return append_bounded(result.xrefs, std::move(value), limits.max_xrefs,
            limits.max_result_bytes, storage_bytes, "xref storage exceeds analysis memory budget");
    };
    const auto append_data = [&](data_candidate_record_t value) {
        return append_bounded(result.data_candidates, std::move(value), limits.max_data_candidates,
            limits.max_result_bytes, storage_bytes,
            "data-candidate storage exceeds analysis memory budget");
    };
    std::map<std::uint64_t, const image_import_t*> import_slots;
    for (const auto& imported : image.imports) {
        const auto rva = to_rva(image, imported.address);
        if (rva)
            import_slots.emplace(*rva, &imported);
    }
    std::uint64_t checks = 0;
    for (const auto& instruction : instructions) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<xref_build_result_t>::failure(stop_error(cancel));
        }
        const auto target_end = static_cast<std::uint64_t>(instruction.target_fact_begin) +
            instruction.target_fact_count;
        if (target_end > targets.size()) {
            return workspace_result_t<xref_build_result_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "instruction target-fact range is invalid", "xrefs"));
        }
        for (std::uint64_t index = instruction.target_fact_begin; index < target_end; ++index) {
            const auto& target = targets[static_cast<std::size_t>(index)];
            const auto target_rva = to_rva(image, target.target);
            const bool import_call = (instruction.flow_flags & flow_call) != 0 &&
                target_rva && import_slots.find(*target_rva) != import_slots.end();
            xref_record_t xref;
            xref.source = instruction.address;
            xref.target = target.target;
            xref.kind = target.kind == target_kind_record_t::call || import_call ? xref_kind_t::call :
                target.kind == target_kind_record_t::branch ? xref_kind_t::code :
                data_xref_kind(instruction, operands);
            xref.provenance = import_call ? fact_provenance_t::relocation : instruction.provenance;
            xref.confidence = import_call ? std::min<std::uint8_t>(instruction.confidence, 95)
                                          : instruction.confidence;
            auto appended_xref = append_xref(std::move(xref));
            if (!appended_xref)
                return workspace_result_t<xref_build_result_t>::failure(appended_xref.error());
            if (target.kind == target_kind_record_t::data) {
                data_candidate_record_t data;
                data.address = target.target;
                data.size = target_access_bytes(target);
                data.kind = target.resolution == target_resolution_t::segment_relative
                    ? data_candidate_kind_t::thread_local_storage
                    : data_candidate_kind_t::referenced_storage;
                data.provenance = instruction.provenance;
                data.confidence = instruction.confidence;
                auto appended_data = append_data(std::move(data));
                if (!appended_data)
                    return workspace_result_t<xref_build_result_t>::failure(appended_data.error());
            }
        }
    }
    for (const auto& relocation : image.relocations) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<xref_build_result_t>::failure(stop_error(cancel));
        }
        if (!workspace_image_contains(image, relocation.address))
            continue;
        data_candidate_record_t data;
        data.address = relocation.address;
        data.size = image.address_width_bits / 8U;
        data.kind = data_candidate_kind_t::relocation_slot;
        data.target = relocation.target;
        data.provenance = fact_provenance_t::relocation;
        data.confidence = 100;
        auto appended_data = append_data(data);
        if (!appended_data)
            return workspace_result_t<xref_build_result_t>::failure(appended_data.error());
        if (relocation.target) {
            xref_record_t xref;
            xref.source = relocation.address;
            xref.target = *relocation.target;
            xref.kind = xref_kind_t::relocation;
            xref.provenance = data.provenance;
            xref.confidence = data.confidence;
            auto appended_xref = append_xref(std::move(xref));
            if (!appended_xref)
                return workspace_result_t<xref_build_result_t>::failure(appended_xref.error());
        }
    }
    for (const auto& imported : image.imports) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<xref_build_result_t>::failure(stop_error(cancel));
        }
        if (!workspace_image_contains(image, imported.address))
            continue;
        data_candidate_record_t data;
        data.address = imported.address;
        data.size = image.address_width_bits / 8U;
        data.kind = data_candidate_kind_t::import_address_slot;
        data.provenance = fact_provenance_t::relocation;
        data.confidence = 100;
        auto appended_data = append_data(std::move(data));
        if (!appended_data)
            return workspace_result_t<xref_build_result_t>::failure(appended_data.error());
    }
    const auto pointer_size = image.address_width_bits == 64 ? 8U :
        image.address_width_bits == 32 ? 4U : 0U;
    if (pointer_size != 0) {
        const auto scan_regions = [&](const auto& regions) -> workspace_result_t<void> {
            for (const auto& region : regions) {
                if ((region.permissions & image_permission_read) == 0 ||
                    (region.permissions & image_permission_execute) != 0 ||
                    region.file_size < pointer_size)
                    continue;
                std::uint64_t updated_scan = 0;
                if (!checked_add_u64(result.bytes_scanned, region.file_size, updated_scan) ||
                    updated_scan > limits.max_pointer_scan_bytes) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::limit_exceeded,
                        "pointer-scan byte budget exceeded", "xrefs"));
                }
                result.bytes_scanned = updated_scan;
                std::uint64_t cursor = 0;
                while (cursor <= region.file_size - pointer_size) {
                    if (cancel.stop_requested())
                        return workspace_result_t<void>::failure(stop_error(cancel));
                    const auto remaining = region.file_size - cursor;
                    auto window = std::min<std::uint64_t>(remaining,
                        std::max<std::uint64_t>(pointer_size, limits.read_window_bytes));
                    window -= window % pointer_size;
                    if (window == 0)
                        break;
                    std::uint64_t provider_offset = 0;
                    if (!checked_add_u64(region.file_offset, cursor, provider_offset)) {
                        return workspace_result_t<void>::failure(make_workspace_error(
                            workspace_error_code_t::range_overflow,
                            "pointer-scan provider offset overflows", "xrefs"));
                    }
                    auto lease = provider.lease(provider_offset, window, cancel);
                    if (!lease)
                        return workspace_result_t<void>::failure(lease.error());
                    ++result.provider_leases;
                    std::uint64_t mapped_bytes = 0;
                    if (!checked_add_u64(result.mapped_bytes, window, mapped_bytes)) {
                        return workspace_result_t<void>::failure(make_workspace_error(
                            workspace_error_code_t::range_overflow,
                            "pointer-scan mapped-byte accounting overflows", "xrefs"));
                    }
                    result.mapped_bytes = mapped_bytes;
                    for (std::uint64_t offset = 0; offset + pointer_size <= window;
                         offset += pointer_size) {
                        if (++checks >= limits.cancellation_check_interval) {
                            checks = 0;
                            if (cancel.stop_requested())
                                return workspace_result_t<void>::failure(stop_error(cancel));
                        }
                        const auto value = read_integer(lease.value().data() + offset,
                            static_cast<std::uint8_t>(pointer_size), image.endian);
                        if (value < image.image_base || value - image.image_base >= image.image_size)
                            continue;
                        const auto target_rva = value - image.image_base;
                        if (!image_contains_rva(image, target_rva))
                            continue;
                        std::uint64_t slot_rva = 0;
                        std::uint64_t region_offset = 0;
                        if (!checked_add_u64(cursor, offset, region_offset) ||
                            !checked_add_u64(region.virtual_address, region_offset, slot_rva)) {
                            return workspace_result_t<void>::failure(make_workspace_error(
                                workspace_error_code_t::range_overflow,
                                "pointer slot RVA overflows", "xrefs"));
                        }
                        data_candidate_record_t data;
                        data.address = rva_address(image, slot_rva);
                        data.size = pointer_size;
                        data.kind = data_candidate_kind_t::in_image_pointer;
                        data.target = rva_address(image, target_rva);
                        data.provenance = fact_provenance_t::linear_validation;
                        data.confidence = 70;
                        auto appended_data = append_data(data);
                        if (!appended_data)
                            return appended_data;
                        xref_record_t xref;
                        xref.source = data.address;
                        xref.target = *data.target;
                        xref.kind = xref_kind_t::address;
                        xref.provenance = data.provenance;
                        xref.confidence = data.confidence;
                        auto appended_xref = append_xref(std::move(xref));
                        if (!appended_xref)
                            return appended_xref;
                    }
                    cursor += window;
                }
            }
            return workspace_result_t<void>::success();
        };
        auto scanned = image.sections.empty() ? scan_regions(image.segments) : scan_regions(image.sections);
        if (!scanned)
            return workspace_result_t<xref_build_result_t>::failure(scanned.error());
    }
    if (cancel.stop_requested())
        return workspace_result_t<xref_build_result_t>::failure(stop_error(cancel));
    std::sort(result.xrefs.begin(), result.xrefs.end(), xref_less);
    result.xrefs.erase(std::unique(result.xrefs.begin(), result.xrefs.end(), xref_equal),
        result.xrefs.end());
    for (std::size_t index = 0; index < result.xrefs.size(); ++index)
        result.xrefs[index].id = kXrefEntityTag | static_cast<std::uint64_t>(index + 1);
    std::sort(result.data_candidates.begin(), result.data_candidates.end(), data_less);
    result.data_candidates.erase(std::unique(result.data_candidates.begin(),
        result.data_candidates.end(), data_equal), result.data_candidates.end());
    for (std::size_t index = 0; index < result.data_candidates.size(); ++index)
        result.data_candidates[index].id = kDataEntityTag | static_cast<std::uint64_t>(index + 1);
    return workspace_result_t<xref_build_result_t>::success(std::move(result));
}

}
