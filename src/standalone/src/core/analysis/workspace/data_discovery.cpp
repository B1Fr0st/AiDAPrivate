#include "data_discovery.hpp"

#include "checked_range.hpp"
#include "parallel_pass.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <limits>
#include <new>
#include <optional>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::uint64_t kDataEntityTag = 8ULL << 56;
constexpr std::uint64_t kPointerFactEntityTag = 12ULL << 56;
constexpr std::uint64_t kDataConflictEntityTag = 13ULL << 56;
constexpr std::uint32_t kShardCancellationStride = 256;
constexpr std::size_t kInstructionShardFloor = 65536;
constexpr std::size_t kSeedShardFloor = 4096;
constexpr std::size_t kHarvestShardThreshold = 1ULL << 20;
constexpr std::uint64_t kScanShardFloorBytes = 4ULL * 1024ULL * 1024ULL;

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

std::uint64_t elapsed_ns(std::chrono::steady_clock::time_point begin) {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<
        std::chrono::nanoseconds>(std::chrono::steady_clock::now() - begin).count());
}

std::size_t pass_shard_count(std::size_t items, std::size_t items_per_shard) {
    if (items == 0)
        return 0;
    const auto hardware = std::thread::hardware_concurrency();
    const std::uint64_t cap = 4ULL * static_cast<std::uint64_t>(hardware == 0 ? 1U : hardware);
    const std::uint64_t wanted = (static_cast<std::uint64_t>(items) +
        static_cast<std::uint64_t>(items_per_shard) - 1ULL) /
        static_cast<std::uint64_t>(items_per_shard);
    return static_cast<std::size_t>((std::min)((std::max)(wanted, 1ULL), cap));
}

template <typename Fn>
void run_merge_shards(std::size_t shard_total, Fn&& shard_fn) {
    parallel_executor_t::run(shard_total, parallel_worker_count(),
        "analysis.data_discovery", std::forward<Fn>(shard_fn));
}

template <typename T, typename Equal>
void parallel_unique_erase(std::vector<T>& values, Equal&& equal) {
    if (values.size() < 2)
        return;
    const std::size_t count = values.size();
    const auto shards = parallel_shards(count, static_cast<std::uint32_t>(
        pass_shard_count(count, kInstructionShardFloor)));
    std::vector<std::uint8_t> keep(count, 0);
    std::vector<std::uint64_t> shard_keeps(shards.size(), 0);
    run_merge_shards(shards.size(), [&](std::size_t shard) {
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
    run_merge_shards(shards.size(), [&](std::size_t shard) {
        const auto range = shards[shard];
        auto cursor = shard_keeps[shard];
        for (std::size_t index = range.begin; index < range.end; ++index) {
            if (keep[index] != 0)
                compacted[static_cast<std::size_t>(cursor++)] = std::move(values[index]);
        }
    });
    values = std::move(compacted);
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

struct scan_counters_t {
    std::uint64_t bytes_scanned = 0;
    std::uint64_t mapped_bytes = 0;
    std::uint64_t provider_leases = 0;
    std::uint64_t invalid_pointer_values = 0;
};

struct emission_shard_t {
    std::vector<data_candidate_record_t> candidates;
    std::vector<data_pointer_fact_t> facts;
    std::vector<std::uint8_t> candidate_has_fact;
    scan_counters_t counters;
    std::vector<std::uint64_t> relocation_slots;
    std::vector<std::uint64_t> authoritative_relocations;
    std::vector<std::uint64_t> import_slots;
};

struct scan_slice_t {
    std::size_t region_index = 0;
    std::uint64_t slot_begin = 0;
    std::uint64_t slot_end = 0;
    std::uint64_t read_end = 0;
    std::uint64_t owned_end = 0;
};

struct scan_budget_state_t {
    std::atomic<std::uint64_t> granted{0};
    std::atomic<bool> exceeded{false};
};

workspace_result_t<void> harvest_instruction_refs(
    const workspace_image_t& image,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<target_fact_t>& targets,
    std::vector<emission_shard_t>& outputs,
    const cancellation_token_t& cancel) {
    const auto shards = parallel_shards(instructions.size(), static_cast<std::uint32_t>(
        pass_shard_count(instructions.size(), kInstructionShardFloor)));
    outputs.resize(shards.size());
    const auto fn = [&](std::size_t index, parallel_shard_t shard)
        -> workspace_result_t<void> {
        auto& output = outputs[index];
        std::uint32_t checks = 0;
        for (std::size_t i = shard.begin; i < shard.end; ++i) {
            if (++checks >= kShardCancellationStride) {
                checks = 0;
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(stop_error(cancel));
            }
            const auto& instruction = instructions[i];
            std::uint64_t end = 0;
            if (!checked_add_u64(instruction.target_fact_begin,
                    instruction.target_fact_count, end) || end > targets.size()) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "instruction target range is invalid", "data_discovery"));
            }
            for (std::uint64_t fact = instruction.target_fact_begin; fact < end; ++fact) {
                const auto& target = targets[static_cast<std::size_t>(fact)];
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
                output.candidates.push_back(candidate);
            }
        }
        return workspace_result_t<void>::success();
    };
    return parallel_run_shards(shards, fn, cancel);
}

workspace_result_t<void> harvest_relocations(
    const workspace_image_t& image,
    std::vector<emission_shard_t>& outputs,
    const cancellation_token_t& cancel) {
    const auto count = image.relocations.size();
    const auto shard_total = count >= kHarvestShardThreshold
        ? pass_shard_count(count, kSeedShardFloor) : (count == 0 ? 0 : 1);
    const auto shards = parallel_shards(count, static_cast<std::uint32_t>(shard_total));
    outputs.resize(shards.size());
    const auto fn = [&](std::size_t index, parallel_shard_t shard)
        -> workspace_result_t<void> {
        auto& output = outputs[index];
        std::uint32_t checks = 0;
        for (std::size_t i = shard.begin; i < shard.end; ++i) {
            if (++checks >= kShardCancellationStride) {
                checks = 0;
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(stop_error(cancel));
            }
            const auto& relocation = image.relocations[i];
            const auto slot = canonical_address(image, relocation.address);
            if (!slot)
                continue;
            output.relocation_slots.push_back(slot->value);
            data_candidate_record_t candidate;
            candidate.address = *slot;
            candidate.size = image.address_width_bits / 8U;
            candidate.kind = data_candidate_kind_t::relocation_slot;
            candidate.provenance = fact_provenance_t::relocation;
            candidate.confidence = 100;
            if (relocation.target) {
                candidate.target = canonical_address(image, *relocation.target);
                if (candidate.target) {
                    output.authoritative_relocations.push_back(slot->value);
                } else {
                    ++output.counters.invalid_pointer_values;
                }
            }
            output.candidates.push_back(candidate);
            output.candidate_has_fact.push_back(0);
            if (candidate.target) {
                data_candidate_record_t paired;
                paired.address = candidate.address;
                paired.size = candidate.size;
                paired.kind = candidate.kind;
                paired.target = candidate.target;
                paired.provenance = candidate.provenance;
                paired.confidence = candidate.confidence;
                data_pointer_fact_t fact;
                fact.slot = paired.address;
                fact.target = *paired.target;
                fact.candidate_kind = paired.kind;
                fact.encoding = data_pointer_encoding_t::relocation_target;
                fact.width_bytes = static_cast<std::uint8_t>(paired.size);
                fact.provenance = paired.provenance;
                fact.confidence = paired.confidence;
                output.candidates.push_back(paired);
                output.candidate_has_fact.push_back(1);
                output.facts.push_back(fact);
            }
        }
        return workspace_result_t<void>::success();
    };
    return parallel_run_shards(shards, fn, cancel);
}

workspace_result_t<void> harvest_imports(
    const workspace_image_t& image,
    std::vector<emission_shard_t>& outputs,
    const cancellation_token_t& cancel) {
    const auto count = image.imports.size();
    const auto shard_total = count >= kHarvestShardThreshold
        ? pass_shard_count(count, kSeedShardFloor) : (count == 0 ? 0 : 1);
    const auto shards = parallel_shards(count, static_cast<std::uint32_t>(shard_total));
    outputs.resize(shards.size());
    const auto fn = [&](std::size_t index, parallel_shard_t shard)
        -> workspace_result_t<void> {
        auto& output = outputs[index];
        std::uint32_t checks = 0;
        for (std::size_t i = shard.begin; i < shard.end; ++i) {
            if (++checks >= kShardCancellationStride) {
                checks = 0;
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(stop_error(cancel));
            }
            const auto& imported = image.imports[i];
            const auto slot = canonical_address(image, imported.address);
            if (!slot)
                continue;
            output.import_slots.push_back(slot->value);
            data_candidate_record_t candidate;
            candidate.address = *slot;
            candidate.size = image.address_width_bits / 8U;
            candidate.kind = data_candidate_kind_t::import_address_slot;
            candidate.provenance = fact_provenance_t::relocation;
            candidate.confidence = 100;
            output.candidates.push_back(candidate);
        }
        return workspace_result_t<void>::success();
    };
    return parallel_run_shards(shards, fn, cancel);
}

void merge_slot_vectors(
    std::vector<emission_shard_t>& relocation_outputs,
    std::vector<emission_shard_t>& import_outputs,
    std::vector<std::uint64_t>& relocation_slots,
    std::vector<std::uint64_t>& authoritative_relocations,
    std::vector<std::uint64_t>& import_slots) {
    std::uint64_t total_relocation_slots = 0;
    std::uint64_t total_authoritative = 0;
    std::uint64_t total_import_slots = 0;
    for (const auto& output : relocation_outputs) {
        total_relocation_slots += output.relocation_slots.size();
        total_authoritative += output.authoritative_relocations.size();
    }
    for (const auto& output : import_outputs)
        total_import_slots += output.import_slots.size();
    relocation_slots.reserve(static_cast<std::size_t>(total_relocation_slots));
    authoritative_relocations.reserve(static_cast<std::size_t>(total_authoritative));
    import_slots.reserve(static_cast<std::size_t>(total_import_slots));
    for (const auto& output : relocation_outputs) {
        relocation_slots.insert(relocation_slots.end(), output.relocation_slots.begin(),
            output.relocation_slots.end());
        authoritative_relocations.insert(authoritative_relocations.end(),
            output.authoritative_relocations.begin(), output.authoritative_relocations.end());
    }
    for (const auto& output : import_outputs) {
        import_slots.insert(import_slots.end(), output.import_slots.begin(),
            output.import_slots.end());
    }
    const auto uint64_less = [](std::uint64_t lhs, std::uint64_t rhs) {
        return lhs < rhs;
    };
    const auto uint64_equal = [](std::uint64_t lhs, std::uint64_t rhs) {
        return lhs == rhs;
    };
    parallel_sort(relocation_slots.begin(), relocation_slots.end(), uint64_less);
    parallel_unique_erase(relocation_slots, uint64_equal);
    parallel_sort(authoritative_relocations.begin(), authoritative_relocations.end(),
        uint64_less);
    parallel_unique_erase(authoritative_relocations, uint64_equal);
    parallel_sort(import_slots.begin(), import_slots.end(), uint64_less);
    parallel_unique_erase(import_slots, uint64_equal);
}

workspace_result_t<void> harvest_pointer_seeds(
    const workspace_image_t& image, const byte_provider_t& provider,
    const std::vector<mapped_region_t>& regions,
    const std::vector<data_pointer_seed_t>& pointer_seeds,
    std::vector<emission_shard_t>& outputs,
    const cancellation_token_t& cancel) {
    const auto shards = parallel_shards(pointer_seeds.size(), static_cast<std::uint32_t>(
        pass_shard_count(pointer_seeds.size(), kSeedShardFloor)));
    outputs.resize(shards.size());
    const auto fn = [&](std::size_t index, parallel_shard_t shard)
        -> workspace_result_t<void> {
        auto& output = outputs[index];
        std::uint32_t checks = 0;
        for (std::size_t i = shard.begin; i < shard.end; ++i) {
            if (++checks >= kShardCancellationStride) {
                checks = 0;
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(stop_error(cancel));
            }
            const auto& seed = pointer_seeds[i];
            const auto slot = canonical_address(image, seed.slot);
            const auto width = seed.width_bytes == 0
                ? static_cast<std::uint8_t>(image.address_width_bits / 8U) : seed.width_bytes;
            if (!slot || (width != 1 && width != 2 && width != 4 && width != 8) ||
                seed.confidence > 100) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::invalid_argument,
                    "data pointer seed is invalid", "data_discovery"));
            }
            std::optional<address_t> target;
            data_pointer_encoding_t encoding = seed.encoding;
            if (seed.target) {
                target = canonical_address(image, *seed.target);
                if (!target)
                    ++output.counters.invalid_pointer_values;
            } else if (seed.read_target_from_image) {
                const auto file_offset = file_offset_for_rva(regions, slot->value, width);
                if (!file_offset) {
                    ++output.counters.invalid_pointer_values;
                } else {
                    auto lease = provider.lease(*file_offset, width, cancel);
                    if (!lease)
                        return workspace_result_t<void>::failure(lease.error());
                    ++output.counters.provider_leases;
                    output.counters.mapped_bytes += width;
                    output.counters.bytes_scanned += width;
                    const auto raw = read_unsigned(lease.value().data(), width, image.endian);
                    const auto resolved = resolve_seed_value(image, seed, slot->value, raw);
                    if (resolved) {
                        target = resolved->target;
                        encoding = resolved->encoding;
                    } else if (raw != 0) {
                        ++output.counters.invalid_pointer_values;
                    }
                }
            }
            data_candidate_record_t candidate;
            candidate.address = *slot;
            candidate.size = width;
            candidate.kind = seed.kind;
            candidate.provenance = seed.provenance;
            candidate.confidence = seed.confidence;
            if (target) {
                candidate.target = target;
                output.candidates.push_back(candidate);
                output.candidate_has_fact.push_back(1);
                data_pointer_fact_t fact;
                fact.slot = *slot;
                fact.target = *target;
                fact.candidate_kind = seed.kind;
                fact.encoding = encoding;
                fact.width_bytes = width;
                fact.provenance = seed.provenance;
                fact.confidence = seed.confidence;
                output.facts.push_back(fact);
            } else {
                output.candidates.push_back(candidate);
                output.candidate_has_fact.push_back(0);
            }
        }
        return workspace_result_t<void>::success();
    };
    return parallel_run_shards(shards, fn, cancel);
}

std::vector<scan_slice_t> build_scan_slices(
    const std::vector<mapped_region_t>& regions, std::uint8_t pointer_width,
    bool scan_executable, bool scan_unaligned) {
    struct region_span_t {
        std::size_t region_index = 0;
        std::uint64_t start = 0;
        std::uint64_t slot_limit = 0;
        std::uint64_t read_limit = 0;
        std::uint64_t owned_limit = 0;
    };
    std::vector<region_span_t> spans;
    spans.reserve(regions.size());
    for (std::size_t index = 0; index < regions.size(); ++index) {
        const auto& region = regions[index];
        if ((region.permissions & image_permission_read) == 0 ||
            (!scan_executable && (region.permissions & image_permission_execute) != 0) ||
            region.size < pointer_width)
            continue;
        std::uint64_t start = 0;
        if (!scan_unaligned) {
            const auto remainder = region.rva % pointer_width;
            start = remainder == 0 ? 0 : pointer_width - remainder;
        }
        if (start > region.size || region.size - start < pointer_width)
            continue;
        region_span_t span;
        span.region_index = index;
        span.start = start;
        if (scan_unaligned) {
            span.slot_limit = region.size - pointer_width + 1;
            span.read_limit = region.size;
            span.owned_limit = region.size;
        } else {
            span.slot_limit = start +
                (region.size - start) / pointer_width * pointer_width;
            span.read_limit = span.slot_limit;
            span.owned_limit = span.slot_limit;
        }
        spans.push_back(span);
    }
    std::vector<scan_slice_t> slices;
    if (spans.empty())
        return slices;
    const std::uint64_t slice_extent = scan_unaligned
        ? kScanShardFloorBytes
        : (std::max<std::uint64_t>)(static_cast<std::uint64_t>(pointer_width),
            kScanShardFloorBytes / static_cast<std::uint64_t>(pointer_width) *
                static_cast<std::uint64_t>(pointer_width));
    for (const auto& span : spans) {
        std::uint64_t cursor = span.start;
        while (cursor < span.slot_limit) {
            scan_slice_t slice;
            slice.region_index = span.region_index;
            slice.slot_begin = cursor;
            slice.slot_end = (std::min)(cursor + slice_extent, span.slot_limit);
            slice.read_end = scan_unaligned
                ? (std::min)(slice.slot_end + static_cast<std::uint64_t>(pointer_width) - 1ULL,
                    span.read_limit)
                : slice.slot_end;
            slice.owned_end = scan_unaligned
                ? (slice.slot_end == span.slot_limit ? span.owned_limit : slice.slot_end)
                : slice.slot_end;
            slices.push_back(slice);
            cursor = slice.slot_end;
        }
    }
    return slices;
}

workspace_result_t<void> scan_regions(
    const workspace_image_t& image, const byte_provider_t& provider,
    const std::vector<mapped_region_t>& regions,
    const std::vector<std::uint64_t>& relocation_slots,
    const std::vector<std::uint64_t>& authoritative_relocations,
    const std::vector<std::uint64_t>& import_slots,
    const data_discovery_limits_t& limits, std::uint8_t pointer_width,
    std::vector<emission_shard_t>& outputs,
    const cancellation_token_t& cancel) {
    const auto slices = build_scan_slices(regions, pointer_width,
        limits.scan_executable_regions, limits.scan_unaligned_pointers);
    if (slices.empty())
        return workspace_result_t<void>::success();
    const auto shards = parallel_shards(slices.size(), static_cast<std::uint32_t>(
        pass_shard_count(slices.size(), 1)));
    outputs.resize(shards.size());
    scan_budget_state_t budget;
    const auto fn = [&](std::size_t index, parallel_shard_t shard)
        -> workspace_result_t<void> {
        auto& output = outputs[index];
        std::uint32_t checks = 0;
        for (std::size_t s = shard.begin; s < shard.end; ++s) {
            const auto& slice = slices[s];
            const auto& region = regions[slice.region_index];
            std::uint64_t cursor = slice.slot_begin;
            while (cursor < slice.slot_end) {
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(stop_error(cancel));
                if (budget.exceeded.load(std::memory_order_relaxed))
                    return workspace_result_t<void>::success();
                const auto read_remaining = slice.read_end - cursor;
                auto window = (std::min)(read_remaining, limits.read_window_bytes);
                window = (std::min)(window,
                    provider.maximum_contiguous_lease(region.file_offset + cursor));
                if (!limits.scan_unaligned_pointers)
                    window -= window % pointer_width;
                if (window < pointer_width)
                    break;
                const auto advance = limits.scan_unaligned_pointers &&
                        cursor + window < slice.read_end
                    ? window - (static_cast<std::uint64_t>(pointer_width) - 1ULL)
                    : window;
                const auto owned_window =
                    (std::min)(cursor + advance, slice.owned_end) - cursor;
                const auto granted = budget.granted.fetch_add(owned_window,
                    std::memory_order_relaxed);
                if (granted + owned_window > limits.max_pointer_scan_bytes) {
                    budget.exceeded.store(true, std::memory_order_relaxed);
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::limit_exceeded,
                        "pointer scan byte budget exceeded", "data_discovery"));
                }
                std::uint64_t provider_offset = 0;
                if (!checked_add_u64(region.file_offset, cursor, provider_offset)) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::range_overflow,
                        "pointer scan offset overflows", "data_discovery"));
                }
                auto lease = provider.lease(provider_offset, window, cancel);
                if (!lease)
                    return workspace_result_t<void>::failure(lease.error());
                ++output.counters.provider_leases;
                output.counters.bytes_scanned += owned_window;
                output.counters.mapped_bytes += owned_window;
                const auto stride = limits.scan_unaligned_pointers
                    ? 1ULL : static_cast<std::uint64_t>(pointer_width);
                for (std::uint64_t offset = 0;
                     offset + pointer_width <= window && cursor + offset < slice.slot_end;
                     offset += stride) {
                    if (++checks >= kShardCancellationStride) {
                        checks = 0;
                        if (cancel.stop_requested())
                            return workspace_result_t<void>::failure(stop_error(cancel));
                        if (budget.exceeded.load(std::memory_order_relaxed))
                            return workspace_result_t<void>::success();
                    }
                    std::uint64_t slot_rva = 0;
                    if (!checked_add_u64(region.rva, cursor, slot_rva) ||
                        !checked_add_u64(slot_rva, offset, slot_rva)) {
                        return workspace_result_t<void>::failure(
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
                            ++output.counters.invalid_pointer_values;
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
                    data_candidate_record_t candidate;
                    candidate.address = rva_address(image, slot_rva);
                    candidate.size = pointer_width;
                    candidate.kind = kind;
                    candidate.target = resolved->target;
                    candidate.provenance = provenance;
                    candidate.confidence = confidence;
                    data_pointer_fact_t fact;
                    fact.slot = candidate.address;
                    fact.target = resolved->target;
                    fact.candidate_kind = kind;
                    fact.encoding = resolved->encoding;
                    fact.width_bytes = pointer_width;
                    fact.provenance = provenance;
                    fact.confidence = confidence;
                    output.candidates.push_back(candidate);
                    output.facts.push_back(fact);
                }
                cursor += advance;
            }
        }
        return workspace_result_t<void>::success();
    };
    return parallel_run_shards(shards, fn, cancel);
}

workspace_result_t<void> validate_discovery_limits(const workspace_image_t& image,
    const data_discovery_limits_t& limits, std::uint64_t pointer_seed_count) {
    if (limits.max_candidates == 0 || limits.max_pointer_facts == 0 ||
        limits.max_conflicts == 0 || limits.max_pointer_seeds == 0 ||
        limits.max_result_bytes == 0 || limits.cancellation_check_interval == 0 ||
        (limits.max_pointer_scan_bytes != 0 && limits.read_window_bytes == 0) ||
        pointer_seed_count > limits.max_pointer_seeds) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "data discovery limits or pointer seeds are invalid", "data_discovery"));
    }
    if (image.address_width_bits != 32 && image.address_width_bits != 64) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "data discovery requires a 32-bit or 64-bit address model", "data_discovery"));
    }
    return workspace_result_t<void>::success();
}

void absorb_emission_counters(data_discovery_result_t& result,
    const std::vector<emission_shard_t>& groups) {
    for (const auto& group : groups) {
        result.bytes_scanned += group.counters.bytes_scanned;
        result.mapped_bytes += group.counters.mapped_bytes;
        result.provider_leases += group.counters.provider_leases;
        result.invalid_pointer_values += group.counters.invalid_pointer_values;
    }
}

void scatter_emission_groups(
    const std::vector<emission_shard_t>& groups,
    std::vector<data_candidate_record_t>& candidates,
    std::vector<data_pointer_fact_t>& facts, std::uint64_t& candidate_base,
    std::uint64_t& fact_base, std::atomic<bool>& merge_cancelled,
    const cancellation_token_t& cancel) {
    std::vector<std::uint64_t> candidate_bases(groups.size(), 0);
    std::vector<std::uint64_t> fact_bases(groups.size(), 0);
    auto candidate_cursor = candidate_base;
    auto fact_cursor = fact_base;
    for (std::size_t index = 0; index < groups.size(); ++index) {
        candidate_bases[index] = candidate_cursor;
        fact_bases[index] = fact_cursor;
        candidate_cursor += groups[index].candidates.size();
        fact_cursor += groups[index].facts.size();
    }
    candidate_base = candidate_cursor;
    fact_base = fact_cursor;
    run_merge_shards(groups.size(), [&](std::size_t shard) {
        const auto& group = groups[shard];
        auto candidate_slot = candidate_bases[shard];
        auto fact_slot = fact_bases[shard];
        std::uint32_t checks = 0;
        const auto poll = [&]() {
            if (++checks >= kShardCancellationStride) {
                checks = 0;
                if (cancel.stop_requested()) {
                    merge_cancelled.store(true, std::memory_order_relaxed);
                    return true;
                }
            }
            return false;
        };
        for (std::size_t index = 0; index < group.candidates.size(); ++index) {
            if (poll())
                return;
            candidates[static_cast<std::size_t>(candidate_slot++)] =
                group.candidates[index];
        }
        for (std::size_t index = 0; index < group.facts.size(); ++index) {
            if (poll())
                return;
            facts[static_cast<std::size_t>(fact_slot++)] = group.facts[index];
        }
    });
}

workspace_result_t<data_discovery_result_t> produce_instruction_driven(
    const workspace_image_t& image,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<target_fact_t>& targets,
    const cancellation_token_t& cancel) {
    data_discovery_result_t raw;
    std::vector<emission_shard_t> instruction_outputs;
    auto harvested = harvest_instruction_refs(image, instructions, targets,
        instruction_outputs, cancel);
    if (!harvested)
        return workspace_result_t<data_discovery_result_t>::failure(harvested.error());
    const auto merge_begin = std::chrono::steady_clock::now();
    std::uint64_t total_candidates = 0;
    for (const auto& group : instruction_outputs) {
        if (!checked_add_u64(total_candidates, group.candidates.size(),
                total_candidates)) {
            return workspace_result_t<data_discovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "data candidate storage exceeds its bound", "data_discovery"));
        }
    }
    raw.candidates.resize(static_cast<std::size_t>(total_candidates));
    std::uint64_t candidate_base = 0;
    std::uint64_t fact_base = 0;
    std::atomic<bool> merge_cancelled{false};
    scatter_emission_groups(instruction_outputs, raw.candidates, raw.pointer_facts,
        candidate_base, fact_base, merge_cancelled, cancel);
    if (merge_cancelled.load(std::memory_order_relaxed))
        return workspace_result_t<data_discovery_result_t>::failure(stop_error(cancel));
    raw.shard_merge_ns += elapsed_ns(merge_begin);
    return workspace_result_t<data_discovery_result_t>::success(std::move(raw));
}

workspace_result_t<data_discovery_result_t> produce_image_driven(
    const workspace_image_t& image, const byte_provider_t& provider,
    const std::vector<mapped_region_t>& regions,
    const std::vector<data_pointer_seed_t>& pointer_seeds,
    const data_discovery_limits_t& limits, const cancellation_token_t& cancel) {
    data_discovery_result_t raw;
    std::vector<emission_shard_t> relocation_outputs;
    auto harvested = harvest_relocations(image, relocation_outputs, cancel);
    if (!harvested)
        return workspace_result_t<data_discovery_result_t>::failure(harvested.error());
    std::vector<emission_shard_t> import_outputs;
    harvested = harvest_imports(image, import_outputs, cancel);
    if (!harvested)
        return workspace_result_t<data_discovery_result_t>::failure(harvested.error());
    const auto slot_merge_begin = std::chrono::steady_clock::now();
    std::vector<std::uint64_t> relocation_slots;
    std::vector<std::uint64_t> authoritative_relocations;
    std::vector<std::uint64_t> import_slots;
    merge_slot_vectors(relocation_outputs, import_outputs,
        relocation_slots, authoritative_relocations, import_slots);
    raw.shard_merge_ns += elapsed_ns(slot_merge_begin);
    std::vector<emission_shard_t> seed_outputs;
    harvested = harvest_pointer_seeds(image, provider, regions, pointer_seeds,
        seed_outputs, cancel);
    if (!harvested)
        return workspace_result_t<data_discovery_result_t>::failure(harvested.error());
    const auto pointer_width = static_cast<std::uint8_t>(image.address_width_bits / 8U);
    std::vector<emission_shard_t> scan_outputs;
    if (limits.max_pointer_scan_bytes != 0) {
        harvested = scan_regions(image, provider, regions, relocation_slots,
            authoritative_relocations, import_slots, limits, pointer_width,
            scan_outputs, cancel);
        if (!harvested)
            return workspace_result_t<data_discovery_result_t>::failure(harvested.error());
    }
    const auto merge_begin = std::chrono::steady_clock::now();
    std::uint64_t total_candidates = 0;
    std::uint64_t total_facts = 0;
    const auto count_groups = [&](const std::vector<emission_shard_t>& groups) -> bool {
        for (const auto& group : groups) {
            if (!checked_add_u64(total_candidates, group.candidates.size(),
                    total_candidates) ||
                !checked_add_u64(total_facts, group.facts.size(), total_facts))
                return false;
        }
        return true;
    };
    if (!count_groups(relocation_outputs) || !count_groups(import_outputs) ||
        !count_groups(seed_outputs) || !count_groups(scan_outputs)) {
        return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "data candidate storage exceeds its bound", "data_discovery"));
    }
    raw.candidates.resize(static_cast<std::size_t>(total_candidates));
    raw.pointer_facts.resize(static_cast<std::size_t>(total_facts));
    std::uint64_t candidate_base = 0;
    std::uint64_t fact_base = 0;
    std::atomic<bool> merge_cancelled{false};
    scatter_emission_groups(relocation_outputs, raw.candidates, raw.pointer_facts,
        candidate_base, fact_base, merge_cancelled, cancel);
    scatter_emission_groups(import_outputs, raw.candidates, raw.pointer_facts,
        candidate_base, fact_base, merge_cancelled, cancel);
    scatter_emission_groups(seed_outputs, raw.candidates, raw.pointer_facts,
        candidate_base, fact_base, merge_cancelled, cancel);
    scatter_emission_groups(scan_outputs, raw.candidates, raw.pointer_facts,
        candidate_base, fact_base, merge_cancelled, cancel);
    if (merge_cancelled.load(std::memory_order_relaxed))
        return workspace_result_t<data_discovery_result_t>::failure(stop_error(cancel));
    absorb_emission_counters(raw, relocation_outputs);
    absorb_emission_counters(raw, seed_outputs);
    absorb_emission_counters(raw, scan_outputs);
    raw.shard_merge_ns += elapsed_ns(merge_begin);
    return workspace_result_t<data_discovery_result_t>::success(std::move(raw));
}

workspace_result_t<data_discovery_result_t> finalize_discovery(
    const data_discovery_limits_t& limits,
    data_discovery_result_t instruction_driven,
    data_discovery_result_t image_driven,
    const cancellation_token_t& cancel) {
    data_discovery_result_t result;
    result.bytes_scanned = instruction_driven.bytes_scanned + image_driven.bytes_scanned;
    result.mapped_bytes = instruction_driven.mapped_bytes + image_driven.mapped_bytes;
    result.provider_leases =
        instruction_driven.provider_leases + image_driven.provider_leases;
    result.invalid_pointer_values =
        instruction_driven.invalid_pointer_values + image_driven.invalid_pointer_values;
    result.shard_merge_ns =
        instruction_driven.shard_merge_ns + image_driven.shard_merge_ns;
    const auto merge_begin = std::chrono::steady_clock::now();
    std::uint64_t total_candidates = 0;
    std::uint64_t total_facts = 0;
    if (!checked_add_u64(total_candidates, instruction_driven.candidates.size(),
            total_candidates) ||
        !checked_add_u64(total_candidates, image_driven.candidates.size(),
            total_candidates) ||
        !checked_add_u64(total_facts, instruction_driven.pointer_facts.size(),
            total_facts) ||
        !checked_add_u64(total_facts, image_driven.pointer_facts.size(), total_facts) ||
        total_candidates > limits.max_candidates) {
        return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "data candidate storage exceeds its bound", "data_discovery"));
    }
    if (total_facts > limits.max_pointer_facts) {
        return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "pointer fact storage exceeds its bound", "data_discovery"));
    }
    std::uint64_t result_bytes = 0;
    std::uint64_t candidate_bytes = 0;
    if (!checked_mul_u64(total_candidates, sizeof(data_candidate_record_t),
            candidate_bytes) ||
        !checked_add_u64(result_bytes, candidate_bytes, result_bytes) ||
        result_bytes > limits.max_result_bytes) {
        return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "data candidate storage exceeds its bound", "data_discovery"));
    }
    std::uint64_t fact_bytes = 0;
    if (!checked_mul_u64(total_facts, sizeof(data_pointer_fact_t), fact_bytes) ||
        !checked_add_u64(result_bytes, fact_bytes, result_bytes) ||
        result_bytes > limits.max_result_bytes) {
        return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "pointer fact storage exceeds its bound", "data_discovery"));
    }
    result.candidates.resize(static_cast<std::size_t>(total_candidates));
    result.pointer_facts.resize(static_cast<std::size_t>(total_facts));
    {
        std::atomic<bool> merge_cancelled{false};
        const auto scatter_half = [&](data_discovery_result_t& source,
                                      std::uint64_t candidate_base,
                                      std::uint64_t fact_base) {
            const auto candidate_shards = parallel_shards(source.candidates.size(),
                static_cast<std::uint32_t>(pass_shard_count(source.candidates.size(),
                    kInstructionShardFloor)));
            run_merge_shards(candidate_shards.size(), [&](std::size_t shard) {
                const auto range = candidate_shards[shard];
                std::uint32_t checks = 0;
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (++checks >= kShardCancellationStride) {
                        checks = 0;
                        if (cancel.stop_requested()) {
                            merge_cancelled.store(true, std::memory_order_relaxed);
                            return;
                        }
                    }
                    result.candidates[static_cast<std::size_t>(candidate_base + index)] =
                        std::move(source.candidates[index]);
                }
            });
            const auto fact_shards = parallel_shards(source.pointer_facts.size(),
                static_cast<std::uint32_t>(pass_shard_count(source.pointer_facts.size(),
                    kInstructionShardFloor)));
            run_merge_shards(fact_shards.size(), [&](std::size_t shard) {
                const auto range = fact_shards[shard];
                std::uint32_t checks = 0;
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (++checks >= kShardCancellationStride) {
                        checks = 0;
                        if (cancel.stop_requested()) {
                            merge_cancelled.store(true, std::memory_order_relaxed);
                            return;
                        }
                    }
                    result.pointer_facts[static_cast<std::size_t>(fact_base + index)] =
                        std::move(source.pointer_facts[index]);
                }
            });
        };
        scatter_half(instruction_driven, 0, 0);
        scatter_half(image_driven, instruction_driven.candidates.size(),
            instruction_driven.pointer_facts.size());
        if (merge_cancelled.load(std::memory_order_relaxed))
            return workspace_result_t<data_discovery_result_t>::failure(stop_error(cancel));
    }
    result.shard_merge_ns += elapsed_ns(merge_begin);
    parallel_sort(result.candidates.begin(), result.candidates.end(),
        [](const auto& lhs, const auto& rhs) {
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
    {
        const auto same_run = [](const data_candidate_record_t& lhs,
                                 const data_candidate_record_t& rhs) {
            return lhs.address == rhs.address && lhs.kind == rhs.kind;
        };
        auto shards = parallel_shards(result.candidates.size(),
            static_cast<std::uint32_t>(pass_shard_count(result.candidates.size(),
                kCandidateShardFloor)));
        for (std::size_t index = 1; index < shards.size(); ++index) {
            auto begin = shards[index].begin;
            while (begin < result.candidates.size() &&
                   same_run(result.candidates[begin - 1], result.candidates[begin]))
                ++begin;
            shards[index].begin = begin;
            shards[index - 1].end = begin;
        }
        struct dedup_slot_t {
            std::vector<data_candidate_record_t> kept;
            std::vector<data_candidate_conflict_t> conflicts;
            std::uint64_t duplicates = 0;
            bool cancelled = false;
        };
        std::vector<dedup_slot_t> slots(shards.size());
        run_merge_shards(shards.size(), [&](std::size_t slot) {
            const auto shard = shards[slot];
            auto& out = slots[slot];
            std::uint32_t checks = 0;
            for (std::size_t index = shard.begin; index < shard.end; ++index) {
                if (++checks >= kShardCancellationStride) {
                    checks = 0;
                    if (cancel.stop_requested()) {
                        out.cancelled = true;
                        return;
                    }
                }
                const auto& candidate = result.candidates[index];
                if (index == shard.begin || !same_run(result.candidates[index - 1],
                        candidate)) {
                    out.kept.push_back(candidate);
                    continue;
                }
                ++out.duplicates;
                const auto& selected = out.kept.back();
                if (selected.target == candidate.target)
                    continue;
                data_candidate_conflict_t conflict;
                conflict.address = selected.address;
                conflict.kind = selected.kind;
                conflict.selected_target = selected.target;
                conflict.rejected_target = candidate.target;
                conflict.selected_provenance = selected.provenance;
                conflict.rejected_provenance = candidate.provenance;
                conflict.selected_confidence = selected.confidence;
                conflict.rejected_confidence = candidate.confidence;
                out.conflicts.push_back(std::move(conflict));
            }
        });
        for (const auto& slot : slots) {
            if (slot.cancelled)
                return workspace_result_t<data_discovery_result_t>::failure(
                    stop_error(cancel));
        }
        std::uint64_t kept_total = 0;
        std::uint64_t conflict_total = 0;
        for (const auto& slot : slots) {
            if (!checked_add_u64(kept_total, slot.kept.size(), kept_total) ||
                !checked_add_u64(conflict_total, slot.conflicts.size(), conflict_total)) {
                return workspace_result_t<data_discovery_result_t>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                        "data conflict storage exceeds its bound", "data_discovery"));
            }
            result.duplicate_candidates += slot.duplicates;
        }
        std::uint64_t conflict_bytes = 0;
        if (conflict_total > limits.max_conflicts ||
            !checked_mul_u64(conflict_total, sizeof(data_candidate_conflict_t),
                conflict_bytes) ||
            !checked_add_u64(result_bytes, conflict_bytes, result_bytes) ||
            result_bytes > limits.max_result_bytes) {
            return workspace_result_t<data_discovery_result_t>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "data conflict storage exceeds its bound", "data_discovery"));
        }
        std::vector<data_candidate_record_t> candidates(
            static_cast<std::size_t>(kept_total));
        result.conflicts.resize(static_cast<std::size_t>(conflict_total));
        std::vector<std::uint64_t> kept_bases(slots.size(), 0);
        std::vector<std::uint64_t> conflict_bases(slots.size(), 0);
        std::uint64_t kept_cursor = 0;
        std::uint64_t conflict_cursor = 0;
        for (std::size_t index = 0; index < slots.size(); ++index) {
            kept_bases[index] = kept_cursor;
            conflict_bases[index] = conflict_cursor;
            kept_cursor += slots[index].kept.size();
            conflict_cursor += slots[index].conflicts.size();
        }
        run_merge_shards(slots.size(), [&](std::size_t slot) {
            auto& out = slots[slot];
            auto kept_slot = kept_bases[slot];
            for (auto& candidate : out.kept)
                candidates[static_cast<std::size_t>(kept_slot++)] =
                    std::move(candidate);
            auto conflict_slot = conflict_bases[slot];
            for (auto& conflict : out.conflicts)
                result.conflicts[static_cast<std::size_t>(conflict_slot++)] =
                    std::move(conflict);
        });
        result.candidates = std::move(candidates);
    }
    for (std::size_t index = 0; index < result.candidates.size(); ++index)
        result.candidates[index].id = kDataEntityTag | static_cast<std::uint64_t>(index + 1);
    parallel_sort(result.pointer_facts.begin(), result.pointer_facts.end(),
        [](const auto& lhs, const auto& rhs) {
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
    const auto facts_before_dedup = result.pointer_facts.size();
    parallel_unique_erase(result.pointer_facts, [](const auto& lhs, const auto& rhs) {
        return lhs.slot == rhs.slot && lhs.target == rhs.target &&
               lhs.candidate_kind == rhs.candidate_kind;
    });
    result.duplicate_pointer_facts = static_cast<std::uint64_t>(
        facts_before_dedup - result.pointer_facts.size());
    for (std::size_t index = 0; index < result.pointer_facts.size(); ++index)
        result.pointer_facts[index].id = kPointerFactEntityTag |
            static_cast<std::uint64_t>(index + 1);
    parallel_sort(result.conflicts.begin(), result.conflicts.end(),
        [](const auto& lhs, const auto& rhs) {
            return std::tie(lhs.address, lhs.kind, lhs.selected_target, lhs.rejected_target,
                       lhs.selected_provenance, lhs.rejected_provenance,
                       lhs.selected_confidence, lhs.rejected_confidence) <
                   std::tie(rhs.address, rhs.kind, rhs.selected_target, rhs.rejected_target,
                       rhs.selected_provenance, rhs.rejected_provenance,
                       rhs.selected_confidence, rhs.rejected_confidence);
        });
    parallel_unique_erase(result.conflicts, [](const auto& lhs, const auto& rhs) {
        return lhs.address == rhs.address && lhs.kind == rhs.kind &&
               lhs.selected_target == rhs.selected_target &&
               lhs.rejected_target == rhs.rejected_target &&
               lhs.selected_provenance == rhs.selected_provenance &&
               lhs.rejected_provenance == rhs.rejected_provenance &&
               lhs.selected_confidence == rhs.selected_confidence &&
               lhs.rejected_confidence == rhs.rejected_confidence;
    });
    for (std::size_t index = 0; index < result.conflicts.size(); ++index)
        result.conflicts[index].id = kDataConflictEntityTag |
            static_cast<std::uint64_t>(index + 1);
    return workspace_result_t<data_discovery_result_t>::success(std::move(result));
}

workspace_result_t<data_discovery_result_t> discover_impl(
    const workspace_image_t& image, const byte_provider_t& provider,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<target_fact_t>& targets,
    const std::vector<data_pointer_seed_t>& pointer_seeds,
    const data_discovery_limits_t& limits, const cancellation_token_t& cancel) {
    auto valid = validate_discovery_limits(image, limits, pointer_seeds.size());
    if (!valid)
        return workspace_result_t<data_discovery_result_t>::failure(valid.error());
    auto regions_result = mapped_regions(image, provider);
    if (!regions_result)
        return workspace_result_t<data_discovery_result_t>::failure(regions_result.error());
    auto instruction_driven = produce_instruction_driven(image, instructions, targets,
        cancel);
    if (!instruction_driven)
        return workspace_result_t<data_discovery_result_t>::failure(
            instruction_driven.error());
    auto image_driven = produce_image_driven(image, provider, regions_result.value(),
        pointer_seeds, limits, cancel);
    if (!image_driven)
        return workspace_result_t<data_discovery_result_t>::failure(image_driven.error());
    return finalize_discovery(limits, instruction_driven.take_value(),
        image_driven.take_value(), cancel);
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

workspace_result_t<data_discovery_result_t> data_discovery_t::discover_image_driven(
    const workspace_image_t& image, const byte_provider_t& provider,
    const data_discovery_limits_t& limits, const cancellation_token_t& cancel) {
    try {
        auto valid = validate_discovery_limits(image, limits, 0);
        if (!valid)
            return workspace_result_t<data_discovery_result_t>::failure(valid.error());
        auto regions_result = mapped_regions(image, provider);
        if (!regions_result) {
            return workspace_result_t<data_discovery_result_t>::failure(
                regions_result.error());
        }
        static const std::vector<data_pointer_seed_t> no_seeds;
        return produce_image_driven(image, provider, regions_result.value(), no_seeds,
            limits, cancel);
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

workspace_result_t<data_discovery_result_t> data_discovery_t::discover_instruction_driven(
    const workspace_image_t& image, const byte_provider_t&,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<target_fact_t>& targets,
    const data_discovery_limits_t& limits, const cancellation_token_t& cancel) {
    try {
        auto valid = validate_discovery_limits(image, limits, 0);
        if (!valid)
            return workspace_result_t<data_discovery_result_t>::failure(valid.error());
        return produce_instruction_driven(image, instructions, targets, cancel);
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

workspace_result_t<data_discovery_result_t> data_discovery_t::combine_results(
    const data_discovery_limits_t& limits,
    data_discovery_result_t instruction_driven,
    data_discovery_result_t image_driven,
    const cancellation_token_t& cancel) {
    try {
        if (limits.max_candidates == 0 || limits.max_pointer_facts == 0 ||
            limits.max_conflicts == 0 || limits.max_result_bytes == 0 ||
            limits.cancellation_check_interval == 0) {
            return workspace_result_t<data_discovery_result_t>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "data discovery limits or pointer seeds are invalid",
                    "data_discovery"));
        }
        return finalize_discovery(limits, std::move(instruction_driven),
            std::move(image_driven), cancel);
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

}
