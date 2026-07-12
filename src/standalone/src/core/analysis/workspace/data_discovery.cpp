#include "data_discovery.hpp"

#include "checked_range.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <tuple>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::uint64_t kDataEntityTag = 8ULL << 56;
constexpr std::uint64_t kPointerFactEntityTag = 12ULL << 56;
constexpr std::uint64_t kDataConflictEntityTag = 13ULL << 56;

struct mapped_region_t {
    std::uint64_t rva = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t size = 0;
    std::uint32_t permissions = image_permission_none;
};

workspace_error_t stop_error(const cancellation_token_t& cancel) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "data discovery deadline exceeded", "data_discovery");
        error.deadline = true;
        error.cancellation = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "data discovery cancelled", "data_discovery");
    error.cancellation = true;
    return error;
}

address_t rva_address(const workspace_image_t& image, std::uint64_t rva) noexcept {
    return {address_space_id_t::relative_virtual, rva, image.architecture,
        image.architecture_mode};
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

std::optional<address_t> canonical_address(const workspace_image_t& image,
                                           const address_t& address) noexcept {
    const auto rva = to_rva(image, address);
    if (!rva || !workspace_image_contains(image, rva_address(image, *rva)))
        return std::nullopt;
    return rva_address(image, *rva);
}

std::uint32_t permissions_at(const workspace_image_t& image, std::uint64_t rva) noexcept {
    const auto find = [rva](const auto& regions) noexcept {
        for (const auto& region : regions) {
            const auto extent = (std::max)(region.virtual_size, region.file_size);
            if (rva >= region.virtual_address && rva - region.virtual_address < extent)
                return region.permissions;
        }
        return static_cast<std::uint32_t>(image_permission_none);
    };
    auto permissions = find(image.sections);
    return permissions != image_permission_none ? permissions : find(image.segments);
}

bool append_region(std::vector<mapped_region_t>& regions, const workspace_image_t& image,
                   const byte_provider_t& provider, std::uint64_t rva,
                   std::uint64_t file_offset, std::uint64_t size,
                   std::uint32_t permissions) {
    if (size == 0 || rva >= image.image_size || file_offset >= provider.size())
        return false;
    size = (std::min)(size, image.image_size - rva);
    size = (std::min)(size, provider.size() - file_offset);
    if (size == 0)
        return false;
    if (permissions == image_permission_none)
        permissions = permissions_at(image, rva);
    regions.push_back({rva, file_offset, size, permissions});
    return true;
}

workspace_result_t<std::vector<mapped_region_t>> mapped_regions(
    const workspace_image_t& image, const byte_provider_t& provider) {
    std::vector<mapped_region_t> regions;
    for (const auto& mapping : image.address_mappings) {
        if (mapping.source_space == address_space_id_t::file_offset &&
            mapping.target_space == address_space_id_t::relative_virtual) {
            append_region(regions, image, provider, mapping.target_start,
                mapping.source_start, mapping.size, mapping.permissions);
        } else if (mapping.source_space == address_space_id_t::relative_virtual &&
                   mapping.target_space == address_space_id_t::file_offset) {
            append_region(regions, image, provider, mapping.source_start,
                mapping.target_start, mapping.size, mapping.permissions);
        }
    }
    if (regions.empty()) {
        const auto append = [&](const auto& source) {
            for (const auto& region : source)
                append_region(regions, image, provider, region.virtual_address,
                    region.file_offset, region.file_size, region.permissions);
        };
        if (!image.sections.empty())
            append(image.sections);
        else
            append(image.segments);
    }
    std::sort(regions.begin(), regions.end(), [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.rva, lhs.file_offset, lhs.size, lhs.permissions) <
               std::tie(rhs.rva, rhs.file_offset, rhs.size, rhs.permissions);
    });
    std::vector<mapped_region_t> canonical;
    canonical.reserve(regions.size());
    std::uint64_t covered_end = 0;
    for (auto region : regions) {
        std::uint64_t end = 0;
        if (!checked_add_u64(region.rva, region.size, end)) {
            return workspace_result_t<std::vector<mapped_region_t>>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                    "mapped data region overflows", "data_discovery"));
        }
        if (!canonical.empty() && region.rva < covered_end) {
            if (end <= covered_end)
                continue;
            const auto trim = covered_end - region.rva;
            if (!checked_add_u64(region.file_offset, trim, region.file_offset)) {
                return workspace_result_t<std::vector<mapped_region_t>>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                        "mapped data region trim overflows", "data_discovery"));
            }
            region.rva = covered_end;
            region.size = end - covered_end;
        }
        canonical.push_back(region);
        covered_end = end;
    }
    return workspace_result_t<std::vector<mapped_region_t>>::success(std::move(canonical));
}

std::optional<std::uint64_t> file_offset_for_rva(const std::vector<mapped_region_t>& regions,
                                                  std::uint64_t rva,
                                                  std::uint64_t size) noexcept {
    const auto found = std::upper_bound(regions.begin(), regions.end(), rva,
        [](std::uint64_t value, const mapped_region_t& region) { return value < region.rva; });
    if (found == regions.begin())
        return std::nullopt;
    const auto& region = *std::prev(found);
    if (rva < region.rva || rva - region.rva > region.size ||
        size > region.size - (rva - region.rva))
        return std::nullopt;
    std::uint64_t offset = 0;
    if (!checked_add_u64(region.file_offset, rva - region.rva, offset))
        return std::nullopt;
    return offset;
}

std::uint64_t read_unsigned(const std::uint8_t* data, std::uint8_t width,
                            endian_t endian) noexcept {
    std::uint64_t value = 0;
    if (endian == endian_t::little) {
        for (std::uint8_t index = 0; index < width; ++index)
            value |= static_cast<std::uint64_t>(data[index]) << (index * 8U);
    } else {
        for (std::uint8_t index = 0; index < width; ++index)
            value = (value << 8U) | data[index];
    }
    return value;
}

std::int64_t sign_extend(std::uint64_t value, std::uint8_t width) noexcept {
    if (width >= 8)
        return static_cast<std::int64_t>(value);
    const auto bits = static_cast<unsigned>(width) * 8U;
    const auto sign = 1ULL << (bits - 1U);
    return static_cast<std::int64_t>((value ^ sign) - sign);
}

bool add_signed(std::uint64_t base, std::int64_t displacement,
                std::int64_t addend, std::uint64_t& result) noexcept {
    if (addend > 0 && displacement > (std::numeric_limits<std::int64_t>::max)() - addend)
        return false;
    if (addend < 0 && displacement < (std::numeric_limits<std::int64_t>::min)() - addend)
        return false;
    const auto delta = displacement + addend;
    if (delta >= 0)
        return checked_add_u64(base, static_cast<std::uint64_t>(delta), result);
    const auto magnitude = static_cast<std::uint64_t>(-(delta + 1)) + 1ULL;
    if (magnitude > base)
        return false;
    result = base - magnitude;
    return true;
}

struct resolved_pointer_t {
    address_t target;
    data_pointer_encoding_t encoding = data_pointer_encoding_t::absolute_virtual;
    std::uint8_t confidence = 0;
};

std::optional<resolved_pointer_t> resolve_raw_pointer(const workspace_image_t& image,
                                                       std::uint64_t value) noexcept {
    if (value >= image.image_base) {
        const auto rva = value - image.image_base;
        const auto target = rva_address(image, rva);
        if (rva < image.image_size && workspace_image_contains(image, target))
            return resolved_pointer_t{target, data_pointer_encoding_t::absolute_virtual, 70};
    }
    if (value < image.image_size) {
        const auto target = rva_address(image, value);
        if (workspace_image_contains(image, target))
            return resolved_pointer_t{target, data_pointer_encoding_t::image_relative, 62};
    }
    return std::nullopt;
}

std::optional<resolved_pointer_t> resolve_seed_value(const workspace_image_t& image,
    const data_pointer_seed_t& seed, std::uint64_t slot_rva, std::uint64_t raw) noexcept {
    if (seed.encoding == data_pointer_encoding_t::absolute_virtual ||
        seed.encoding == data_pointer_encoding_t::image_relative ||
        seed.encoding == data_pointer_encoding_t::relocation_target) {
        auto resolved = resolve_raw_pointer(image, raw);
        if (!resolved)
            return std::nullopt;
        resolved->encoding = seed.encoding;
        return resolved;
    }
    const auto displacement = sign_extend(raw, seed.width_bytes);
    std::uint64_t base = slot_rva;
    if (seed.encoding == data_pointer_encoding_t::signed_relative_to_next &&
        !checked_add_u64(base, seed.width_bytes, base))
        return std::nullopt;
    std::uint64_t target_rva = 0;
    if (!add_signed(base, displacement, seed.addend, target_rva) ||
        target_rva >= image.image_size)
        return std::nullopt;
    const auto target = rva_address(image, target_rva);
    if (!workspace_image_contains(image, target))
        return std::nullopt;
    return resolved_pointer_t{target, seed.encoding, 0};
}

std::uint64_t access_bytes(const target_fact_t& target) noexcept {
    return target.access_width_bits == 0 ? 0 :
        (static_cast<std::uint64_t>(target.access_width_bits) + 7ULL) / 8ULL;
}

bool stronger(const data_candidate_record_t& lhs,
              const data_candidate_record_t& rhs) noexcept {
    if (provenance_rank(lhs.provenance) != provenance_rank(rhs.provenance))
        return provenance_rank(lhs.provenance) > provenance_rank(rhs.provenance);
    if (lhs.confidence != rhs.confidence)
        return lhs.confidence > rhs.confidence;
    if (lhs.target != rhs.target)
        return lhs.target < rhs.target;
    return lhs.size > rhs.size;
}

bool stronger(const data_pointer_fact_t& lhs,
              const data_pointer_fact_t& rhs) noexcept {
    if (provenance_rank(lhs.provenance) != provenance_rank(rhs.provenance))
        return provenance_rank(lhs.provenance) > provenance_rank(rhs.provenance);
    if (lhs.confidence != rhs.confidence)
        return lhs.confidence > rhs.confidence;
    if (lhs.encoding != rhs.encoding)
        return lhs.encoding < rhs.encoding;
    return lhs.width_bytes > rhs.width_bytes;
}

workspace_result_t<data_discovery_result_t> discover_impl(
    const workspace_image_t& image, const byte_provider_t& provider,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<target_fact_t>& targets,
    const std::vector<data_pointer_seed_t>& pointer_seeds,
    const data_discovery_limits_t& limits, const cancellation_token_t& cancel) {
    if (limits.max_candidates == 0 || limits.max_pointer_facts == 0 ||
        limits.max_conflicts == 0 || limits.max_pointer_seeds == 0 ||
        limits.max_result_bytes == 0 || limits.cancellation_check_interval == 0 ||
        (limits.max_pointer_scan_bytes != 0 && limits.read_window_bytes == 0) ||
        pointer_seeds.size() > limits.max_pointer_seeds) {
        return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "data discovery limits or pointer seeds are invalid", "data_discovery"));
    }
    if (image.address_width_bits != 32 && image.address_width_bits != 64) {
        return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "data discovery requires a 32-bit or 64-bit address model", "data_discovery"));
    }
    auto regions_result = mapped_regions(image, provider);
    if (!regions_result)
        return workspace_result_t<data_discovery_result_t>::failure(regions_result.error());
    const auto& regions = regions_result.value();
    data_discovery_result_t result;
    std::uint64_t result_bytes = 0;
    const auto charge = [&](std::uint64_t bytes) -> bool {
        return checked_add_u64(result_bytes, bytes, result_bytes) &&
               result_bytes <= limits.max_result_bytes;
    };
    const auto append_candidate = [&](data_candidate_record_t value)
        -> workspace_result_t<void> {
        if (result.candidates.size() >= limits.max_candidates ||
            !charge(sizeof(data_candidate_record_t))) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "data candidate storage exceeds its bound", "data_discovery"));
        }
        result.candidates.push_back(std::move(value));
        return workspace_result_t<void>::success();
    };
    const auto append_pointer = [&](data_pointer_fact_t value)
        -> workspace_result_t<void> {
        if (result.pointer_facts.size() >= limits.max_pointer_facts ||
            !charge(sizeof(data_pointer_fact_t))) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "pointer fact storage exceeds its bound", "data_discovery"));
        }
        result.pointer_facts.push_back(std::move(value));
        return workspace_result_t<void>::success();
    };
    const auto append_fact = [&](const address_t& slot, const address_t& target,
        data_candidate_kind_t kind, data_pointer_encoding_t encoding,
        std::uint8_t width, fact_provenance_t provenance, std::uint8_t confidence)
        -> workspace_result_t<void> {
        data_candidate_record_t candidate;
        candidate.address = slot;
        candidate.size = width;
        candidate.kind = kind;
        candidate.target = target;
        candidate.provenance = provenance;
        candidate.confidence = confidence;
        auto appended = append_candidate(std::move(candidate));
        if (!appended)
            return appended;
        data_pointer_fact_t pointer;
        pointer.slot = slot;
        pointer.target = target;
        pointer.candidate_kind = kind;
        pointer.encoding = encoding;
        pointer.width_bytes = width;
        pointer.provenance = provenance;
        pointer.confidence = confidence;
        return append_pointer(std::move(pointer));
    };
    std::uint64_t checks = 0;
    for (const auto& instruction : instructions) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<data_discovery_result_t>::failure(stop_error(cancel));
        }
        std::uint64_t end = 0;
        if (!checked_add_u64(instruction.target_fact_begin,
                instruction.target_fact_count, end) || end > targets.size()) {
            return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "instruction target range is invalid", "data_discovery"));
        }
        for (std::uint64_t index = instruction.target_fact_begin; index < end; ++index) {
            const auto& target = targets[static_cast<std::size_t>(index)];
            if (target.kind != target_kind_record_t::data)
                continue;
            const auto address = canonical_address(image, target.target);
            if (!address)
                continue;
            data_candidate_record_t candidate;
            candidate.address = *address;
            candidate.size = access_bytes(target);
            candidate.kind = target.resolution == target_resolution_t::segment_relative
                ? data_candidate_kind_t::thread_local_storage
                : data_candidate_kind_t::referenced_storage;
            candidate.provenance = instruction.provenance;
            candidate.confidence = instruction.confidence;
            auto appended = append_candidate(std::move(candidate));
            if (!appended)
                return workspace_result_t<data_discovery_result_t>::failure(appended.error());
        }
    }
    std::vector<std::uint64_t> relocation_slots;
    std::vector<std::uint64_t> authoritative_relocations;
    relocation_slots.reserve(image.relocations.size());
    authoritative_relocations.reserve(image.relocations.size());
    for (const auto& relocation : image.relocations) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<data_discovery_result_t>::failure(stop_error(cancel));
        }
        const auto slot = canonical_address(image, relocation.address);
        if (!slot)
            continue;
        relocation_slots.push_back(slot->value);
        data_candidate_record_t candidate;
        candidate.address = *slot;
        candidate.size = image.address_width_bits / 8U;
        candidate.kind = data_candidate_kind_t::relocation_slot;
        candidate.provenance = fact_provenance_t::relocation;
        candidate.confidence = 100;
        if (relocation.target) {
            candidate.target = canonical_address(image, *relocation.target);
            if (candidate.target) {
                authoritative_relocations.push_back(slot->value);
            } else {
                ++result.invalid_pointer_values;
            }
        }
        auto appended = append_candidate(candidate);
        if (!appended)
            return workspace_result_t<data_discovery_result_t>::failure(appended.error());
        if (candidate.target) {
            auto pointer = append_fact(candidate.address, *candidate.target, candidate.kind,
                data_pointer_encoding_t::relocation_target,
                static_cast<std::uint8_t>(candidate.size), candidate.provenance,
                candidate.confidence);
            if (!pointer)
                return workspace_result_t<data_discovery_result_t>::failure(pointer.error());
        }
    }
    std::vector<std::uint64_t> import_slots;
    import_slots.reserve(image.imports.size());
    for (const auto& imported : image.imports) {
        const auto slot = canonical_address(image, imported.address);
        if (!slot)
            continue;
        import_slots.push_back(slot->value);
        data_candidate_record_t candidate;
        candidate.address = *slot;
        candidate.size = image.address_width_bits / 8U;
        candidate.kind = data_candidate_kind_t::import_address_slot;
        candidate.provenance = fact_provenance_t::relocation;
        candidate.confidence = 100;
        auto appended = append_candidate(std::move(candidate));
        if (!appended)
            return workspace_result_t<data_discovery_result_t>::failure(appended.error());
    }
    std::sort(relocation_slots.begin(), relocation_slots.end());
    relocation_slots.erase(std::unique(relocation_slots.begin(), relocation_slots.end()),
        relocation_slots.end());
    std::sort(authoritative_relocations.begin(), authoritative_relocations.end());
    authoritative_relocations.erase(std::unique(authoritative_relocations.begin(),
        authoritative_relocations.end()), authoritative_relocations.end());
    std::sort(import_slots.begin(), import_slots.end());
    import_slots.erase(std::unique(import_slots.begin(), import_slots.end()), import_slots.end());
    for (const auto& seed : pointer_seeds) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<data_discovery_result_t>::failure(stop_error(cancel));
        }
        const auto slot = canonical_address(image, seed.slot);
        const auto width = seed.width_bytes == 0
            ? static_cast<std::uint8_t>(image.address_width_bits / 8U) : seed.width_bytes;
        if (!slot || (width != 1 && width != 2 && width != 4 && width != 8) ||
            seed.confidence > 100) {
            return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "data pointer seed is invalid", "data_discovery"));
        }
        std::optional<address_t> target;
        data_pointer_encoding_t encoding = seed.encoding;
        if (seed.target) {
            target = canonical_address(image, *seed.target);
            if (!target)
                ++result.invalid_pointer_values;
        } else if (seed.read_target_from_image) {
            const auto file_offset = file_offset_for_rva(regions, slot->value, width);
            if (!file_offset) {
                ++result.invalid_pointer_values;
            } else {
                auto lease = provider.lease(*file_offset, width, cancel);
                if (!lease)
                    return workspace_result_t<data_discovery_result_t>::failure(lease.error());
                ++result.provider_leases;
                result.mapped_bytes += width;
                result.bytes_scanned += width;
                const auto raw = read_unsigned(lease.value().data(), width, image.endian);
                const auto resolved = resolve_seed_value(image, seed, slot->value, raw);
                if (resolved) {
                    target = resolved->target;
                    encoding = resolved->encoding;
                } else if (raw != 0) {
                    ++result.invalid_pointer_values;
                }
            }
        }
        if (target) {
            auto appended = append_fact(*slot, *target, seed.kind, encoding, width,
                seed.provenance, seed.confidence);
            if (!appended)
                return workspace_result_t<data_discovery_result_t>::failure(appended.error());
        } else {
            data_candidate_record_t candidate;
            candidate.address = *slot;
            candidate.size = width;
            candidate.kind = seed.kind;
            candidate.provenance = seed.provenance;
            candidate.confidence = seed.confidence;
            auto appended = append_candidate(std::move(candidate));
            if (!appended)
                return workspace_result_t<data_discovery_result_t>::failure(appended.error());
        }
    }
    const auto pointer_width = static_cast<std::uint8_t>(image.address_width_bits / 8U);
    if (limits.max_pointer_scan_bytes != 0) {
        for (const auto& region : regions) {
            if ((region.permissions & image_permission_read) == 0 ||
                (!limits.scan_executable_regions &&
                 (region.permissions & image_permission_execute) != 0) ||
                region.size < pointer_width)
                continue;
            std::uint64_t start = 0;
            if (!limits.scan_unaligned_pointers) {
                const auto remainder = region.rva % pointer_width;
                start = remainder == 0 ? 0 : pointer_width - remainder;
            }
            if (start > region.size || region.size - start < pointer_width)
                continue;
            std::uint64_t cursor = start;
            while (cursor <= region.size - pointer_width) {
                if (cancel.stop_requested())
                    return workspace_result_t<data_discovery_result_t>::failure(stop_error(cancel));
                const auto remaining = region.size - cursor;
                auto window = (std::min)(remaining, limits.read_window_bytes);
                window = (std::min)(window,
                    provider.maximum_contiguous_lease(region.file_offset + cursor));
                if (!limits.scan_unaligned_pointers)
                    window -= window % pointer_width;
                if (window < pointer_width)
                    break;
                if (window > limits.max_pointer_scan_bytes -
                    (std::min)(result.bytes_scanned, limits.max_pointer_scan_bytes)) {
                    return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
                        workspace_error_code_t::limit_exceeded,
                        "pointer scan byte budget exceeded", "data_discovery"));
                }
                std::uint64_t provider_offset = 0;
                if (!checked_add_u64(region.file_offset, cursor, provider_offset)) {
                    return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
                        workspace_error_code_t::range_overflow,
                        "pointer scan offset overflows", "data_discovery"));
                }
                auto lease = provider.lease(provider_offset, window, cancel);
                if (!lease)
                    return workspace_result_t<data_discovery_result_t>::failure(lease.error());
                ++result.provider_leases;
                result.bytes_scanned += window;
                result.mapped_bytes += window;
                const auto stride = limits.scan_unaligned_pointers ? 1ULL : pointer_width;
                for (std::uint64_t offset = 0; offset + pointer_width <= window;
                     offset += stride) {
                    if (++checks >= limits.cancellation_check_interval) {
                        checks = 0;
                        if (cancel.stop_requested())
                            return workspace_result_t<data_discovery_result_t>::failure(
                                stop_error(cancel));
                    }
                    std::uint64_t slot_rva = 0;
                    if (!checked_add_u64(region.rva, cursor, slot_rva) ||
                        !checked_add_u64(slot_rva, offset, slot_rva)) {
                        return workspace_result_t<data_discovery_result_t>::failure(
                            make_workspace_error(workspace_error_code_t::range_overflow,
                                "pointer slot address overflows", "data_discovery"));
                    }
                    if (std::binary_search(authoritative_relocations.begin(),
                            authoritative_relocations.end(), slot_rva))
                        continue;
                    const auto raw = read_unsigned(lease.value().data() + offset,
                        pointer_width, image.endian);
                    const auto resolved = resolve_raw_pointer(image, raw);
                    if (!resolved) {
                        if (raw != 0)
                            ++result.invalid_pointer_values;
                        continue;
                    }
                    const bool relocation = std::binary_search(relocation_slots.begin(),
                        relocation_slots.end(), slot_rva);
                    const bool imported = std::binary_search(import_slots.begin(),
                        import_slots.end(), slot_rva);
                    const auto kind = relocation ? data_candidate_kind_t::relocation_slot :
                        imported ? data_candidate_kind_t::import_address_slot :
                        data_candidate_kind_t::in_image_pointer;
                    const auto provenance = relocation ? fact_provenance_t::relocation :
                        fact_provenance_t::linear_validation;
                    const auto confidence = relocation ? static_cast<std::uint8_t>(85) :
                        resolved->confidence;
                    auto appended = append_fact(rva_address(image, slot_rva), resolved->target,
                        kind, resolved->encoding, pointer_width, provenance, confidence);
                    if (!appended)
                        return workspace_result_t<data_discovery_result_t>::failure(appended.error());
                }
                cursor += window;
            }
        }
    }
    std::sort(result.candidates.begin(), result.candidates.end(), [](const auto& lhs,
                                                                     const auto& rhs) {
        if (lhs.address != rhs.address)
            return lhs.address < rhs.address;
        if (lhs.kind != rhs.kind)
            return lhs.kind < rhs.kind;
        if (stronger(lhs, rhs))
            return true;
        if (stronger(rhs, lhs))
            return false;
        return std::tie(lhs.size, lhs.target) < std::tie(rhs.size, rhs.target);
    });
    std::vector<data_candidate_record_t> candidates;
    candidates.reserve(result.candidates.size());
    for (const auto& candidate : result.candidates) {
        if (candidates.empty() || candidates.back().address != candidate.address ||
            candidates.back().kind != candidate.kind) {
            candidates.push_back(candidate);
            continue;
        }
        ++result.duplicate_candidates;
        const auto& selected = candidates.back();
        if (selected.target == candidate.target)
            continue;
        if (result.conflicts.size() >= limits.max_conflicts ||
            !charge(sizeof(data_candidate_conflict_t))) {
            return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "data conflict storage exceeds its bound", "data_discovery"));
        }
        data_candidate_conflict_t conflict;
        conflict.address = selected.address;
        conflict.kind = selected.kind;
        conflict.selected_target = selected.target;
        conflict.rejected_target = candidate.target;
        conflict.selected_provenance = selected.provenance;
        conflict.rejected_provenance = candidate.provenance;
        conflict.selected_confidence = selected.confidence;
        conflict.rejected_confidence = candidate.confidence;
        result.conflicts.push_back(std::move(conflict));
    }
    result.candidates = std::move(candidates);
    for (std::size_t index = 0; index < result.candidates.size(); ++index)
        result.candidates[index].id = kDataEntityTag | static_cast<std::uint64_t>(index + 1);
    std::sort(result.pointer_facts.begin(), result.pointer_facts.end(), [](const auto& lhs,
                                                                          const auto& rhs) {
        if (lhs.slot != rhs.slot)
            return lhs.slot < rhs.slot;
        if (lhs.target != rhs.target)
            return lhs.target < rhs.target;
        if (lhs.candidate_kind != rhs.candidate_kind)
            return lhs.candidate_kind < rhs.candidate_kind;
        if (stronger(lhs, rhs))
            return true;
        if (stronger(rhs, lhs))
            return false;
        return lhs.encoding < rhs.encoding;
    });
    const auto pointer_end = std::unique(result.pointer_facts.begin(),
        result.pointer_facts.end(), [](const auto& lhs, const auto& rhs) {
            return lhs.slot == rhs.slot && lhs.target == rhs.target &&
                   lhs.candidate_kind == rhs.candidate_kind;
        });
    result.duplicate_pointer_facts = static_cast<std::uint64_t>(
        std::distance(pointer_end, result.pointer_facts.end()));
    result.pointer_facts.erase(pointer_end, result.pointer_facts.end());
    for (std::size_t index = 0; index < result.pointer_facts.size(); ++index)
        result.pointer_facts[index].id = kPointerFactEntityTag |
            static_cast<std::uint64_t>(index + 1);
    std::sort(result.conflicts.begin(), result.conflicts.end(), [](const auto& lhs,
                                                                   const auto& rhs) {
        return std::tie(lhs.address, lhs.kind, lhs.selected_target, lhs.rejected_target,
                   lhs.selected_provenance, lhs.rejected_provenance,
                   lhs.selected_confidence, lhs.rejected_confidence) <
               std::tie(rhs.address, rhs.kind, rhs.selected_target, rhs.rejected_target,
                   rhs.selected_provenance, rhs.rejected_provenance,
                   rhs.selected_confidence, rhs.rejected_confidence);
    });
    result.conflicts.erase(std::unique(result.conflicts.begin(), result.conflicts.end(),
        [](const auto& lhs, const auto& rhs) {
            return lhs.address == rhs.address && lhs.kind == rhs.kind &&
                   lhs.selected_target == rhs.selected_target &&
                   lhs.rejected_target == rhs.rejected_target &&
                   lhs.selected_provenance == rhs.selected_provenance &&
                   lhs.rejected_provenance == rhs.rejected_provenance &&
                   lhs.selected_confidence == rhs.selected_confidence &&
                   lhs.rejected_confidence == rhs.rejected_confidence;
        }), result.conflicts.end());
    for (std::size_t index = 0; index < result.conflicts.size(); ++index)
        result.conflicts[index].id = kDataConflictEntityTag |
            static_cast<std::uint64_t>(index + 1);
    return workspace_result_t<data_discovery_result_t>::success(std::move(result));
}

}

workspace_result_t<data_discovery_result_t> data_discovery_t::discover(
    const workspace_image_t& image, const byte_provider_t& provider,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<target_fact_t>& targets,
    const std::vector<data_pointer_seed_t>& pointer_seeds,
    const data_discovery_limits_t& limits, const cancellation_token_t& cancel) {
    try {
        return discover_impl(image, provider, instructions, targets, pointer_seeds, limits, cancel);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "data discovery allocation failed", "data_discovery"));
    } catch (const std::length_error&) {
        return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "data discovery allocation length is unsupported", "data_discovery"));
    }
}

workspace_result_t<data_discovery_result_t> data_discovery_t::discover(
    const workspace_image_t& image, const byte_provider_t& provider,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<target_fact_t>& targets,
    const data_discovery_limits_t& limits, const cancellation_token_t& cancel) {
    return discover(image, provider, instructions, targets, {}, limits, cancel);
}

}
