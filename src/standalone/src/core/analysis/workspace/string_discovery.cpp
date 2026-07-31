#include "string_discovery.hpp"

#include "checked_range.hpp"
#include "parallel_pass.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <limits>
#include <new>
#include <optional>
#include <stdexcept>
#include <tuple>
#include <utility>
#include <vector>

#if defined(_M_X64) || defined(_M_IX86)
#include <emmintrin.h>
#include <intrin.h>
#define AIDA_STRING_DISCOVERY_SIMD_X86 1
#endif

namespace aida::analysis {

namespace string_simd {

std::size_t ascii_run_avx2(const std::uint8_t* data, std::size_t size) noexcept;
std::size_t utf16_ascii_unit_run_avx2(const std::uint8_t* data, std::size_t size) noexcept;
std::int32_t current_level() noexcept;

}

namespace {

constexpr std::uint64_t kStringEntityTag = 6ULL << 56;
constexpr std::uint64_t kMinShardBytes = 4ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kMaxShardBytes = 64ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kCancellationStride = 256;

struct mapped_region_t {
    std::uint64_t rva = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t size = 0;
    std::uint32_t permissions = image_permission_none;
};

workspace_error_t stop_error(const cancellation_token_t& cancel) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "string discovery deadline exceeded", "string_discovery");
        error.deadline = true;
        error.cancellation = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "string discovery cancelled", "string_discovery");
    error.cancellation = true;
    return error;
}

address_t rva_address(const workspace_image_t& image, std::uint64_t rva) noexcept {
    return {address_space_id_t::relative_virtual, rva, image.architecture,
        image.architecture_mode};
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
    const auto section = find(image.sections);
    return section != image_permission_none ? section : find(image.segments);
}

void append_region(std::vector<mapped_region_t>& regions, const workspace_image_t& image,
                   const byte_provider_t& provider, std::uint64_t rva,
                   std::uint64_t file_offset, std::uint64_t size,
                   std::uint32_t permissions) {
    if (size == 0 || rva >= image.image_size || file_offset >= provider.size())
        return;
    size = (std::min)(size, image.image_size - rva);
    size = (std::min)(size, provider.size() - file_offset);
    if (size == 0)
        return;
    if (permissions == image_permission_none)
        permissions = permissions_at(image, rva);
    regions.push_back({rva, file_offset, size, permissions});
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
                    "mapped string region overflows", "string_discovery"));
        }
        if (!canonical.empty() && region.rva < covered_end) {
            if (end <= covered_end)
                continue;
            const auto trim = covered_end - region.rva;
            if (!checked_add_u64(region.file_offset, trim, region.file_offset)) {
                return workspace_result_t<std::vector<mapped_region_t>>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                        "mapped string region trim overflows", "string_discovery"));
            }
            region.rva = covered_end;
            region.size = end - covered_end;
        }
        canonical.push_back(region);
        covered_end = end;
    }
    return workspace_result_t<std::vector<mapped_region_t>>::success(std::move(canonical));
}

bool unicode_scalar_printable(std::uint32_t value) noexcept {
    if (value >= 0x20U && value <= 0x7eU)
        return true;
    if (value < 0xa0U || value > 0x10ffffU ||
        (value >= 0xd800U && value <= 0xdfffU) ||
        (value >= 0xfdd0U && value <= 0xfdefU) ||
        (value & 0xffffU) == 0xfffeU || (value & 0xffffU) == 0xffffU)
        return false;
    return true;
}

void append_utf8(std::string& output, std::uint32_t value) {
    if (value <= 0x7fU) {
        output.push_back(static_cast<char>(value));
    } else if (value <= 0x7ffU) {
        output.push_back(static_cast<char>(0xc0U | (value >> 6U)));
        output.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
    } else if (value <= 0xffffU) {
        output.push_back(static_cast<char>(0xe0U | (value >> 12U)));
        output.push_back(static_cast<char>(0x80U | ((value >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
    } else {
        output.push_back(static_cast<char>(0xf0U | (value >> 18U)));
        output.push_back(static_cast<char>(0x80U | ((value >> 12U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | ((value >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
    }
}

struct ascii_state_t {
    bool active = false;
    bool oversized = false;
    std::uint64_t start = 0;
    std::uint64_t bytes = 0;
    std::string value;
};

struct utf8_state_t {
    bool active = false;
    bool oversized = false;
    bool has_non_ascii = false;
    std::uint64_t start = 0;
    std::uint64_t bytes = 0;
    std::uint64_t sequence_bytes_before = 0;
    std::size_t sequence_value_before = 0;
    std::uint32_t code_points = 0;
    std::uint32_t code_point = 0;
    std::uint32_t minimum_code_point = 0;
    std::uint8_t remaining = 0;
    std::string value;
};

struct utf16_state_t {
    bool active = false;
    bool oversized = false;
    bool has_surrogate = false;
    bool has_pending_high = false;
    bool has_pending_byte = false;
    std::uint16_t pending_high = 0;
    std::uint8_t pending_byte = 0;
    std::uint64_t pending_high_address = 0;
    std::uint64_t pending_byte_address = 0;
    std::uint64_t start = 0;
    std::uint64_t bytes = 0;
    std::uint32_t code_points = 0;
    std::uint32_t zero_high_units = 0;
    std::string value;
};

std::size_t ascii_run_scalar(const std::uint8_t* data, std::size_t size) noexcept {
    std::size_t index = 0;
    while (index < size && data[index] >= 0x20U && data[index] <= 0x7eU)
        ++index;
    return index;
}

std::size_t utf16_ascii_unit_run_scalar(const std::uint8_t* data, std::size_t size) noexcept {
    std::size_t units = 0;
    const std::size_t limit = size & ~static_cast<std::size_t>(1);
    while ((units + 1) * 2 <= limit && data[units * 2] >= 0x20U &&
           data[units * 2] <= 0x7eU && data[units * 2 + 1] == 0)
        ++units;
    return units;
}

#if defined(AIDA_STRING_DISCOVERY_SIMD_X86)

std::size_t ascii_run_sse2(const std::uint8_t* data, std::size_t size) noexcept {
    std::size_t index = 0;
    const auto lower = _mm_set1_epi8(0x1f);
    const auto upper = _mm_set1_epi8(0x7f);
    while (index + 16 <= size) {
        const auto value = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + index));
        const auto printable = _mm_and_si128(_mm_cmpgt_epi8(value, lower),
            _mm_cmpgt_epi8(upper, value));
        const auto mask = static_cast<std::uint32_t>(_mm_movemask_epi8(printable));
        if (mask != 0xffffU) {
            auto inverse = ~mask;
            std::size_t run = 0;
            while ((inverse & 1U) != 0U) {
                ++run;
                inverse >>= 1U;
            }
            return index + run;
        }
        index += 16;
    }
    while (index < size && data[index] >= 0x20U && data[index] <= 0x7eU)
        ++index;
    return index;
}

std::size_t utf16_ascii_unit_run_sse2(const std::uint8_t* data, std::size_t size) noexcept {
    std::size_t units = 0;
    const std::size_t limit = size & ~static_cast<std::size_t>(1);
    const auto lower = _mm_set1_epi8(0x1f);
    const auto upper = _mm_set1_epi8(0x7f);
    const auto zero = _mm_setzero_si128();
    while ((units + 8) * 2 <= limit) {
        const auto value = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + units * 2));
        const auto printable = _mm_and_si128(_mm_cmpgt_epi8(value, lower),
            _mm_cmpgt_epi8(upper, value));
        const auto is_zero = _mm_cmpeq_epi8(value, zero);
        const auto printable_mask =
            static_cast<std::uint32_t>(_mm_movemask_epi8(printable));
        const auto zero_mask = static_cast<std::uint32_t>(_mm_movemask_epi8(is_zero));
        const auto unit_ok = (printable_mask & 0x5555U) & ((zero_mask & 0xaaaaU) >> 1U);
        if (unit_ok != 0x5555U) {
            auto inverse = (~unit_ok) & 0x5555U;
            while ((inverse & 1U) == 0U) {
                ++units;
                inverse >>= 2U;
            }
            return units;
        }
        units += 8;
    }
    while ((units + 1) * 2 <= limit && data[units * 2] >= 0x20U &&
           data[units * 2] <= 0x7eU && data[units * 2 + 1] == 0)
        ++units;
    return units;
}

bool cpu_supports_avx2() noexcept {
    int info[4] = {0, 0, 0, 0};
    __cpuid(info, 0);
    if (info[0] < 7)
        return false;
    __cpuid(info, 1);
    const bool osxsave = (info[2] & (1 << 27)) != 0;
    const bool avx = (info[2] & (1 << 28)) != 0;
    if (!osxsave || !avx)
        return false;
    if ((_xgetbv(0) & 0x6ULL) != 0x6ULL)
        return false;
    __cpuid(info, 7);
    return (info[1] & (1 << 5)) != 0;
}

#endif

std::int32_t supported_simd_level() noexcept {
#if defined(AIDA_STRING_DISCOVERY_SIMD_X86)
    static const std::int32_t level = cpu_supports_avx2() ? 2 : 1;
    return level;
#else
    return 0;
#endif
}

std::atomic<std::int32_t> g_simd_level_override{-1};

struct scan_kernels_t {
    std::size_t (*ascii_run)(const std::uint8_t*, std::size_t) noexcept;
    std::size_t (*utf16_ascii_unit_run)(const std::uint8_t*, std::size_t) noexcept;
};

scan_kernels_t resolve_scan_kernels() noexcept {
#if defined(AIDA_STRING_DISCOVERY_SIMD_X86)
    const auto level = string_simd::current_level();
    if (level >= 2)
        return {&string_simd::ascii_run_avx2, &string_simd::utf16_ascii_unit_run_avx2};
    if (level >= 1)
        return {&ascii_run_sse2, &utf16_ascii_unit_run_sse2};
#endif
    return {&ascii_run_scalar, &utf16_ascii_unit_run_scalar};
}

struct scan_unit_t {
    std::size_t region_index = 0;
    std::uint64_t owned_lo = 0;
    std::uint64_t owned_hi = 0;
};

struct scan_shard_t {
    std::size_t unit_begin = 0;
    std::size_t unit_end = 0;
};

std::uint64_t align_up_even(std::uint64_t value) noexcept {
    return (value + 1ULL) & ~1ULL;
}

std::vector<scan_unit_t> build_scan_units(const std::vector<mapped_region_t>& regions,
    const string_discovery_limits_t& limits) {
    std::vector<scan_unit_t> units;
    for (std::size_t index = 0; index < regions.size(); ++index) {
        const auto& region = regions[index];
        if ((region.permissions & image_permission_read) == 0 ||
            (!limits.scan_executable_regions &&
             (region.permissions & image_permission_execute) != 0))
            continue;
        const std::uint64_t end = region.rva + region.size;
        if (region.size <= kMaxShardBytes) {
            units.push_back({index, region.rva, end});
            continue;
        }
        const std::uint64_t slices = (region.size + kMaxShardBytes - 1ULL) / kMaxShardBytes;
        std::uint64_t step = (region.size + slices - 1ULL) / slices;
        step = (std::max<std::uint64_t>)(2ULL, align_up_even(step));
        std::uint64_t cursor = region.rva;
        while (cursor < end) {
            std::uint64_t next = align_up_even(cursor + step);
            if (next <= cursor || next >= end)
                next = end;
            units.push_back({index, cursor, next});
            cursor = next;
        }
    }
    return units;
}

std::vector<scan_shard_t> build_scan_shards(const std::vector<scan_unit_t>& units) {
    std::vector<scan_shard_t> shards;
    std::size_t begin = 0;
    std::uint64_t bytes = 0;
    for (std::size_t index = 0; index < units.size(); ++index) {
        const auto unit_bytes = units[index].owned_hi - units[index].owned_lo;
        if (index > begin && bytes >= kMinShardBytes &&
            bytes + unit_bytes > kMaxShardBytes) {
            shards.push_back({begin, index});
            begin = index;
            bytes = 0;
        }
        bytes += unit_bytes;
    }
    if (begin < units.size())
        shards.push_back({begin, units.size()});
    return shards;
}

struct scan_shared_state_t {
    std::atomic<std::uint64_t> scan_byte_grant{0};
    std::atomic<std::uint64_t> string_count_grant{0};
    std::atomic<std::uint64_t> result_byte_grant{0};
    std::atomic<bool> stop_scheduling{false};
};

struct shard_scan_output_t {
    std::vector<string_record_t> strings;
    std::uint64_t bytes_scanned = 0;
    std::uint64_t mapped_bytes = 0;
    std::uint64_t provider_leases = 0;
    std::uint64_t rejected_invalid_sequences = 0;
    std::uint64_t rejected_oversized_strings = 0;
    std::uint64_t rejected_unterminated_strings = 0;
};

class shard_scanner_t final {
public:
    shard_scanner_t(const workspace_image_t& image, const byte_provider_t& provider,
                    const string_discovery_limits_t& limits,
                    const cancellation_token_t& cancel, scan_shared_state_t& shared,
                    const scan_kernels_t& kernels, shard_scan_output_t& output) noexcept
        : image_(image), provider_(provider), limits_(limits), cancel_(cancel),
          shared_(shared), kernels_(kernels), output_(output) {}

    workspace_result_t<void> scan_unit(const mapped_region_t& region,
                                       const scan_unit_t& unit) {
        owned_lo_ = unit.owned_lo;
        owned_hi_ = unit.owned_hi;
        ascii_ = {};
        utf8_ = {};
        utf16_ = {};
        std::uint64_t margin = (std::numeric_limits<std::uint64_t>::max)() & ~1ULL;
        if (limits_.max_string_bytes <=
            (std::numeric_limits<std::uint64_t>::max)() - 4ULL)
            margin = align_up_even(limits_.max_string_bytes + 2ULL);
        const std::uint64_t region_end = region.rva + region.size;
        const std::uint64_t window_lo =
            unit.owned_lo - (std::min)(margin, unit.owned_lo - region.rva);
        const std::uint64_t window_hi =
            unit.owned_hi + (std::min)(margin, region_end - unit.owned_hi);
        std::uint64_t cancel_bytes = 0;
        std::uint64_t cursor = window_lo;
        while (cursor < window_hi) {
            if (cancel_.stop_requested())
                return workspace_result_t<void>::failure(stop_error(cancel_));
            auto window = (std::min)(window_hi - cursor, limits_.read_window_bytes);
            std::uint64_t provider_offset = 0;
            if (!checked_add_u64(region.file_offset, cursor - region.rva,
                                 provider_offset)) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "string scan provider offset overflows", "string_discovery"));
            }
            window = (std::min)(window, provider_.maximum_contiguous_lease(provider_offset));
            if (window == 0) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::provider_unavailable,
                    "string scan provider cannot lease the mapped range", "string_discovery"));
            }
            const std::uint64_t owned_begin = (std::max)(cursor, unit.owned_lo);
            const std::uint64_t owned_end = (std::min)(cursor + window, unit.owned_hi);
            const std::uint64_t owned =
                owned_end > owned_begin ? owned_end - owned_begin : 0;
            if (owned != 0) {
                const auto prior =
                    shared_.scan_byte_grant.fetch_add(owned, std::memory_order_relaxed);
                if (owned > limits_.max_scan_bytes -
                    (std::min)(prior, limits_.max_scan_bytes)) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::limit_exceeded,
                        "string scan byte budget exceeded", "string_discovery"));
                }
            }
            auto lease = provider_.lease(provider_offset, window, cancel_);
            if (!lease)
                return workspace_result_t<void>::failure(lease.error());
            ++output_.provider_leases;
            output_.bytes_scanned += owned;
            output_.mapped_bytes += owned;
            std::uint64_t window_end_rva = 0;
            if (!checked_add_u64(cursor, window, window_end_rva)) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "string scan address overflows", "string_discovery"));
            }
            static_cast<void>(window_end_rva);
            const auto* data = lease.value().data();
            const auto extent = static_cast<std::size_t>(window);
            if (limits_.scan_ascii) {
                auto scanned = scan_ascii_pass(data, extent, cursor, cancel_bytes);
                if (!scanned)
                    return scanned;
            }
            if (limits_.scan_utf8) {
                auto scanned = scan_utf8_pass(data, extent, cursor, cancel_bytes);
                if (!scanned)
                    return scanned;
            }
            if (limits_.scan_utf16_le) {
                auto scanned = scan_utf16_pass(data, extent, cursor, cancel_bytes);
                if (!scanned)
                    return scanned;
            }
            cursor += window;
        }
        auto finished = finish_ascii(ascii_, false);
        if (!finished)
            return finished;
        finished = finish_utf8(utf8_, false);
        if (!finished)
            return finished;
        finished = finish_utf16(utf16_, false);
        if (!finished)
            return finished;
        return workspace_result_t<void>::success();
    }

private:
    bool owns(std::uint64_t rva) const noexcept {
        return rva >= owned_lo_ && rva < owned_hi_;
    }

    workspace_result_t<void> poll_cancel(std::uint64_t& cancel_bytes,
                                         std::uint64_t processed) {
        cancel_bytes += processed;
        if (cancel_bytes < kCancellationStride)
            return workspace_result_t<void>::success();
        cancel_bytes = 0;
        if (cancel_.stop_requested())
            return workspace_result_t<void>::failure(stop_error(cancel_));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> emit(std::uint64_t start, std::uint64_t byte_length,
        string_encoding_t encoding, std::string value, std::uint8_t confidence) {
        if (!owns(start))
            return workspace_result_t<void>::success();
        const auto granted =
            shared_.string_count_grant.fetch_add(1, std::memory_order_relaxed) + 1;
        if (granted > limits_.max_strings) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "string count exceeds its bound", "string_discovery"));
        }
        std::uint64_t record_bytes = 0;
        if (!checked_add_u64(sizeof(string_record_t), value.size(), record_bytes)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "string result storage exceeds its bound", "string_discovery"));
        }
        const auto granted_bytes =
            shared_.result_byte_grant.fetch_add(record_bytes, std::memory_order_relaxed) +
            record_bytes;
        if (granted_bytes > limits_.max_result_bytes) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "string result storage exceeds its bound", "string_discovery"));
        }
        string_record_t record;
        record.address = rva_address(image_, start);
        record.byte_length = byte_length;
        record.encoding = encoding;
        record.value = std::move(value);
        record.provenance = fact_provenance_t::linear_validation;
        record.confidence = confidence;
        output_.strings.push_back(std::move(record));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> finish_ascii(ascii_state_t& state, bool terminated) {
        if (!state.active)
            return workspace_result_t<void>::success();
        workspace_result_t<void> emitted = workspace_result_t<void>::success();
        const bool owned = owns(state.start);
        if (state.oversized) {
            if (owned)
                ++output_.rejected_oversized_strings;
        } else if (limits_.require_null_terminator && !terminated) {
            if (owned)
                ++output_.rejected_unterminated_strings;
        } else if (state.value.size() >= limits_.minimum_code_points) {
            emitted = emit(state.start, state.bytes, string_encoding_t::ascii,
                std::move(state.value), terminated ? 96 : 82);
        }
        state = {};
        return emitted;
    }

    workspace_result_t<void> finish_utf8(utf8_state_t& state, bool terminated) {
        if (!state.active)
            return workspace_result_t<void>::success();
        const bool owned = owns(state.start);
        if (state.remaining != 0 && !state.oversized) {
            state.bytes = state.sequence_bytes_before;
            state.value.resize(state.sequence_value_before);
            state.remaining = 0;
            if (owned)
                ++output_.rejected_invalid_sequences;
        }
        workspace_result_t<void> emitted = workspace_result_t<void>::success();
        if (state.oversized) {
            if (owned)
                ++output_.rejected_oversized_strings;
        } else if (limits_.require_null_terminator && !terminated) {
            if (owned)
                ++output_.rejected_unterminated_strings;
        } else if (state.has_non_ascii && state.code_points >= limits_.minimum_code_points) {
            emitted = emit(state.start, state.bytes, string_encoding_t::utf8,
                std::move(state.value), terminated ? 98 : 84);
        }
        state = {};
        return emitted;
    }

    workspace_result_t<void> finish_utf16(utf16_state_t& state, bool terminated) {
        if (!state.active && !state.has_pending_high) {
            state.has_pending_byte = false;
            return workspace_result_t<void>::success();
        }
        const bool owned = owns(state.start);
        const bool event_owned =
            state.active ? owned : owns(state.pending_high_address);
        if (state.has_pending_high) {
            state.has_pending_high = false;
            if (event_owned)
                ++output_.rejected_invalid_sequences;
        }
        workspace_result_t<void> emitted = workspace_result_t<void>::success();
        const bool credible = terminated || state.has_surrogate ||
            (state.code_points != 0 &&
             static_cast<std::uint64_t>(state.zero_high_units) * 2ULL >= state.code_points);
        if (state.oversized) {
            if (event_owned)
                ++output_.rejected_oversized_strings;
        } else if (limits_.require_null_terminator && !terminated) {
            if (event_owned)
                ++output_.rejected_unterminated_strings;
        } else if (credible && state.code_points >= limits_.minimum_code_points) {
            emitted = emit(state.start, state.bytes, string_encoding_t::utf16_le,
                std::move(state.value), terminated ? 97 : 83);
        }
        state = {};
        return emitted;
    }

    workspace_result_t<void> consume_ascii(std::uint8_t byte, std::uint64_t rva) {
        if (byte >= 0x20U && byte <= 0x7eU) {
            if (!ascii_.active) {
                ascii_.active = true;
                ascii_.start = rva;
            }
            ++ascii_.bytes;
            if (!ascii_.oversized &&
                (ascii_.bytes > limits_.max_string_bytes ||
                 ascii_.value.size() >= limits_.max_string_value_bytes)) {
                ascii_.oversized = true;
                ascii_.value.clear();
            } else if (!ascii_.oversized) {
                ascii_.value.push_back(static_cast<char>(byte));
            }
            return workspace_result_t<void>::success();
        }
        return finish_ascii(ascii_, byte == 0);
    }

    workspace_result_t<void> start_utf8_byte(std::uint8_t byte, std::uint64_t rva) {
        if (byte >= 0x20U && byte <= 0x7eU) {
            if (!utf8_.active) {
                utf8_.active = true;
                utf8_.start = rva;
            }
            ++utf8_.bytes;
            ++utf8_.code_points;
            if (!utf8_.oversized &&
                (utf8_.bytes > limits_.max_string_bytes ||
                 utf8_.value.size() >= limits_.max_string_value_bytes)) {
                utf8_.oversized = true;
                utf8_.value.clear();
            } else if (!utf8_.oversized) {
                utf8_.value.push_back(static_cast<char>(byte));
            }
            return workspace_result_t<void>::success();
        }
        std::uint8_t remaining = 0;
        std::uint32_t code_point = 0;
        std::uint32_t minimum = 0;
        if (byte >= 0xc2U && byte <= 0xdfU) {
            remaining = 1;
            code_point = byte & 0x1fU;
            minimum = 0x80U;
        } else if (byte >= 0xe0U && byte <= 0xefU) {
            remaining = 2;
            code_point = byte & 0x0fU;
            minimum = 0x800U;
        } else if (byte >= 0xf0U && byte <= 0xf4U) {
            remaining = 3;
            code_point = byte & 0x07U;
            minimum = 0x10000U;
        } else {
            return finish_utf8(utf8_, byte == 0);
        }
        if (!utf8_.active) {
            utf8_.active = true;
            utf8_.start = rva;
        }
        utf8_.sequence_bytes_before = utf8_.bytes;
        utf8_.sequence_value_before = utf8_.value.size();
        utf8_.remaining = remaining;
        utf8_.code_point = code_point;
        utf8_.minimum_code_point = minimum;
        ++utf8_.bytes;
        if (!utf8_.oversized &&
            (utf8_.bytes > limits_.max_string_bytes ||
             utf8_.value.size() >= limits_.max_string_value_bytes)) {
            utf8_.oversized = true;
            utf8_.value.clear();
        } else if (!utf8_.oversized) {
            utf8_.value.push_back(static_cast<char>(byte));
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> consume_utf8(std::uint8_t byte, std::uint64_t rva) {
        if (utf8_.remaining == 0)
            return start_utf8_byte(byte, rva);
        if ((byte & 0xc0U) != 0x80U) {
            if (!utf8_.oversized) {
                utf8_.bytes = utf8_.sequence_bytes_before;
                utf8_.value.resize(utf8_.sequence_value_before);
                if (owns(rva))
                    ++output_.rejected_invalid_sequences;
            }
            utf8_.remaining = 0;
            auto finished = finish_utf8(utf8_, false);
            if (!finished)
                return finished;
            return start_utf8_byte(byte, rva);
        }
        ++utf8_.bytes;
        utf8_.code_point = (utf8_.code_point << 6U) | (byte & 0x3fU);
        if (!utf8_.oversized &&
            (utf8_.bytes > limits_.max_string_bytes ||
             utf8_.value.size() >= limits_.max_string_value_bytes)) {
            utf8_.oversized = true;
            utf8_.value.clear();
        } else if (!utf8_.oversized) {
            utf8_.value.push_back(static_cast<char>(byte));
        }
        --utf8_.remaining;
        if (utf8_.remaining != 0)
            return workspace_result_t<void>::success();
        if (utf8_.code_point < utf8_.minimum_code_point ||
            !unicode_scalar_printable(utf8_.code_point)) {
            if (!utf8_.oversized) {
                utf8_.bytes = utf8_.sequence_bytes_before;
                utf8_.value.resize(utf8_.sequence_value_before);
                if (owns(rva))
                    ++output_.rejected_invalid_sequences;
            }
            return finish_utf8(utf8_, false);
        }
        ++utf8_.code_points;
        utf8_.has_non_ascii = true;
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> append_utf16_scalar(std::uint32_t value, std::uint64_t start,
                                                 std::uint64_t source_bytes,
                                                 bool surrogate) {
        if (!unicode_scalar_printable(value))
            return finish_utf16(utf16_, false);
        if (!utf16_.active) {
            utf16_.active = true;
            utf16_.start = start;
        }
        if (utf16_.bytes > (std::numeric_limits<std::uint64_t>::max)() - source_bytes) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "UTF-16 string length overflows", "string_discovery"));
        }
        utf16_.bytes += source_bytes;
        ++utf16_.code_points;
        utf16_.has_surrogate = utf16_.has_surrogate || surrogate;
        const auto encoded = value <= 0x7fU ? 1ULL : value <= 0x7ffU ? 2ULL :
            value <= 0xffffU ? 3ULL : 4ULL;
        if (!utf16_.oversized &&
            (utf16_.bytes > limits_.max_string_bytes ||
             encoded > limits_.max_string_value_bytes -
                 (std::min<std::uint64_t>)(utf16_.value.size(),
                     limits_.max_string_value_bytes))) {
            utf16_.oversized = true;
            utf16_.value.clear();
        } else if (!utf16_.oversized) {
            append_utf8(utf16_.value, value);
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> consume_utf16_unit(std::uint16_t unit, std::uint64_t rva) {
        if (utf16_.has_pending_high) {
            const auto high = utf16_.pending_high;
            const auto high_address = utf16_.pending_high_address;
            utf16_.has_pending_high = false;
            if (unit >= 0xdc00U && unit <= 0xdfffU) {
                const auto scalar = 0x10000U +
                    ((static_cast<std::uint32_t>(high) - 0xd800U) << 10U) +
                    (static_cast<std::uint32_t>(unit) - 0xdc00U);
                return append_utf16_scalar(scalar, high_address, 4, true);
            }
            if (owns(rva))
                ++output_.rejected_invalid_sequences;
            auto finished = finish_utf16(utf16_, false);
            if (!finished)
                return finished;
        }
        if (unit == 0)
            return finish_utf16(utf16_, true);
        if (unit >= 0xd800U && unit <= 0xdbffU) {
            utf16_.has_pending_high = true;
            utf16_.pending_high = unit;
            utf16_.pending_high_address = rva;
            return workspace_result_t<void>::success();
        }
        if (unit >= 0xdc00U && unit <= 0xdfffU) {
            if (owns(rva))
                ++output_.rejected_invalid_sequences;
            return finish_utf16(utf16_, false);
        }
        if ((unit >> 8U) == 0)
            ++utf16_.zero_high_units;
        return append_utf16_scalar(unit, rva, 2, false);
    }

    workspace_result_t<void> consume_utf16_byte(std::uint8_t byte, std::uint64_t rva) {
        if (!utf16_.has_pending_byte) {
            if ((rva & 1ULL) != 0)
                return workspace_result_t<void>::success();
            utf16_.has_pending_byte = true;
            utf16_.pending_byte = byte;
            utf16_.pending_byte_address = rva;
            return workspace_result_t<void>::success();
        }
        if (rva != utf16_.pending_byte_address + 1ULL) {
            utf16_.has_pending_byte = false;
            auto finished = finish_utf16(utf16_, false);
            if (!finished)
                return finished;
            if ((rva & 1ULL) == 0) {
                utf16_.has_pending_byte = true;
                utf16_.pending_byte = byte;
                utf16_.pending_byte_address = rva;
            }
            return workspace_result_t<void>::success();
        }
        const auto unit = static_cast<std::uint16_t>(utf16_.pending_byte) |
            (static_cast<std::uint16_t>(byte) << 8U);
        const auto unit_address = utf16_.pending_byte_address;
        utf16_.has_pending_byte = false;
        return consume_utf16_unit(unit, unit_address);
    }

    void absorb_ascii_run(const std::uint8_t* data, std::size_t length, std::uint64_t rva) {
        if (length == 0)
            return;
        if (!ascii_.active) {
            ascii_.active = true;
            ascii_.start = rva;
        }
        if (ascii_.oversized) {
            ascii_.bytes += length;
            return;
        }
        const std::uint64_t room_bytes = limits_.max_string_bytes - ascii_.bytes;
        const std::uint64_t room_value =
            limits_.max_string_value_bytes - ascii_.value.size();
        const std::uint64_t room = (std::min)(room_bytes, room_value);
        const auto absorb =
            static_cast<std::size_t>((std::min<std::uint64_t>)(length, room));
        if (absorb != 0) {
            ascii_.bytes += absorb;
            ascii_.value.append(reinterpret_cast<const char*>(data), absorb);
        }
        if (absorb < length) {
            ascii_.oversized = true;
            ascii_.value.clear();
            ascii_.bytes += length - absorb;
        }
    }

    void absorb_utf8_run(const std::uint8_t* data, std::size_t length, std::uint64_t rva) {
        if (length == 0)
            return;
        if (!utf8_.active) {
            utf8_.active = true;
            utf8_.start = rva;
        }
        if (utf8_.oversized) {
            utf8_.bytes += length;
            utf8_.code_points += static_cast<std::uint32_t>(length);
            return;
        }
        const std::uint64_t room_bytes = limits_.max_string_bytes - utf8_.bytes;
        const std::uint64_t room_value =
            limits_.max_string_value_bytes - utf8_.value.size();
        const std::uint64_t room = (std::min)(room_bytes, room_value);
        const auto absorb =
            static_cast<std::size_t>((std::min<std::uint64_t>)(length, room));
        if (absorb != 0) {
            utf8_.bytes += absorb;
            utf8_.code_points += static_cast<std::uint32_t>(absorb);
            utf8_.value.append(reinterpret_cast<const char*>(data), absorb);
        }
        if (absorb < length) {
            utf8_.oversized = true;
            utf8_.value.clear();
            utf8_.bytes += length - absorb;
            utf8_.code_points += static_cast<std::uint32_t>(length - absorb);
        }
    }

    void absorb_utf16_units(const std::uint8_t* data, std::size_t units,
                            std::uint64_t rva) {
        if (units == 0)
            return;
        if (!utf16_.active) {
            utf16_.active = true;
            utf16_.start = rva;
        }
        const auto absorb_tail = [&](std::size_t count) {
            utf16_.bytes += static_cast<std::uint64_t>(count) * 2ULL;
            utf16_.code_points += static_cast<std::uint32_t>(count);
            utf16_.zero_high_units += static_cast<std::uint32_t>(count);
        };
        if (utf16_.oversized) {
            absorb_tail(units);
            return;
        }
        const std::uint64_t room_bytes =
            (limits_.max_string_bytes - utf16_.bytes) / 2ULL;
        const std::uint64_t room_value =
            limits_.max_string_value_bytes - utf16_.value.size();
        const std::uint64_t room = (std::min)(room_bytes, room_value);
        const auto absorb =
            static_cast<std::size_t>((std::min<std::uint64_t>)(units, room));
        for (std::size_t index = 0; index < absorb; ++index)
            utf16_.value.push_back(static_cast<char>(data[index * 2]));
        absorb_tail(absorb);
        if (absorb < units) {
            utf16_.oversized = true;
            utf16_.value.clear();
            absorb_tail(units - absorb);
        }
    }

    workspace_result_t<void> scan_ascii_pass(const std::uint8_t* data, std::size_t extent,
        std::uint64_t base_rva, std::uint64_t& cancel_bytes) {
        std::size_t index = 0;
        while (index < extent) {
            const auto run = kernels_.ascii_run(data + index, extent - index);
            if (run != 0) {
                absorb_ascii_run(data + index, run, base_rva + index);
                index += run;
                auto polled = poll_cancel(cancel_bytes, run);
                if (!polled)
                    return polled;
            }
            if (index >= extent)
                break;
            auto consumed = consume_ascii(data[index], base_rva + index);
            if (!consumed)
                return consumed;
            ++index;
            auto polled = poll_cancel(cancel_bytes, 1);
            if (!polled)
                return polled;
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> scan_utf8_pass(const std::uint8_t* data, std::size_t extent,
        std::uint64_t base_rva, std::uint64_t& cancel_bytes) {
        std::size_t index = 0;
        while (index < extent) {
            if (utf8_.remaining == 0) {
                const auto run = kernels_.ascii_run(data + index, extent - index);
                if (run != 0) {
                    absorb_utf8_run(data + index, run, base_rva + index);
                    index += run;
                    auto polled = poll_cancel(cancel_bytes, run);
                    if (!polled)
                        return polled;
                }
                if (index >= extent)
                    break;
            }
            auto consumed = consume_utf8(data[index], base_rva + index);
            if (!consumed)
                return consumed;
            ++index;
            auto polled = poll_cancel(cancel_bytes, 1);
            if (!polled)
                return polled;
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> scan_utf16_pass(const std::uint8_t* data, std::size_t extent,
        std::uint64_t base_rva, std::uint64_t& cancel_bytes) {
        std::size_t index = 0;
        while (index < extent) {
            const std::uint64_t rva = base_rva + index;
            if (utf16_.has_pending_byte || (rva & 1ULL) != 0 || utf16_.has_pending_high) {
                auto consumed = consume_utf16_byte(data[index], rva);
                if (!consumed)
                    return consumed;
                ++index;
                auto polled = poll_cancel(cancel_bytes, 1);
                if (!polled)
                    return polled;
                continue;
            }
            const auto units = kernels_.utf16_ascii_unit_run(data + index, extent - index);
            if (units != 0) {
                absorb_utf16_units(data + index, units, rva);
                index += units * 2;
                auto polled = poll_cancel(cancel_bytes, units * 2);
                if (!polled)
                    return polled;
                continue;
            }
            auto consumed = consume_utf16_byte(data[index], rva);
            if (!consumed)
                return consumed;
            ++index;
            auto polled = poll_cancel(cancel_bytes, 1);
            if (!polled)
                return polled;
        }
        return workspace_result_t<void>::success();
    }

    const workspace_image_t& image_;
    const byte_provider_t& provider_;
    const string_discovery_limits_t& limits_;
    const cancellation_token_t& cancel_;
    scan_shared_state_t& shared_;
    const scan_kernels_t& kernels_;
    shard_scan_output_t& output_;
    std::uint64_t owned_lo_ = 0;
    std::uint64_t owned_hi_ = 0;
    ascii_state_t ascii_;
    utf8_state_t utf8_;
    utf16_state_t utf16_;
};

std::size_t merge_shard_count(std::size_t items, std::size_t items_per_shard) {
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
        "analysis.string_discovery", std::forward<Fn>(shard_fn));
}

template <typename T, typename Equal>
void parallel_unique_erase(std::vector<T>& values, Equal&& equal) {
    if (values.size() < 2)
        return;
    const std::size_t count = values.size();
    const auto shards = parallel_shards(count, static_cast<std::uint32_t>(
        merge_shard_count(count, 65536)));
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

struct shard_slot_t {
    std::optional<workspace_error_t> error;
    std::exception_ptr exception;
};

template <typename F>
workspace_result_t<void> run_scan_shards(std::size_t shard_count,
    scan_shared_state_t& shared, F&& shard_fn) {
    if (shard_count == 0)
        return workspace_result_t<void>::success();
    std::vector<shard_slot_t> slots(shard_count);
    const auto schedule_gate = [&shared] {
        return !shared.stop_scheduling.load(std::memory_order_acquire);
    };
    parallel_executor_t::run_gated(shard_count, parallel_worker_count(),
        "analysis.string_discovery", schedule_gate, [&](std::size_t index) {
            try {
                auto result = shard_fn(index);
                if (!result) {
                    slots[index].error = std::move(result.error());
                    shared.stop_scheduling.store(true, std::memory_order_release);
                }
            } catch (...) {
                slots[index].exception = std::current_exception();
                shared.stop_scheduling.store(true, std::memory_order_release);
            }
        });
    for (auto& slot : slots) {
        if (slot.exception)
            std::rethrow_exception(slot.exception);
        if (slot.error)
            return workspace_result_t<void>::failure(std::move(*slot.error));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<string_discovery_result_t> discover_impl(
    const workspace_image_t& image, const byte_provider_t& provider,
    const string_discovery_limits_t& limits, const cancellation_token_t& cancel) {
    if (limits.max_strings == 0 || limits.max_scan_bytes == 0 ||
        limits.max_result_bytes == 0 || limits.max_string_bytes == 0 ||
        limits.max_string_value_bytes == 0 || limits.read_window_bytes == 0 ||
        limits.minimum_code_points == 0 || limits.cancellation_check_interval == 0 ||
        (!limits.scan_ascii && !limits.scan_utf8 && !limits.scan_utf16_le)) {
        return workspace_result_t<string_discovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "string discovery limits are invalid", "string_discovery"));
    }
    auto regions_result = mapped_regions(image, provider);
    if (!regions_result)
        return workspace_result_t<string_discovery_result_t>::failure(regions_result.error());
    const auto& regions = regions_result.value();
    const auto units = build_scan_units(regions, limits);
    const auto shards = build_scan_shards(units);
    const auto kernels = resolve_scan_kernels();
    scan_shared_state_t shared;
    std::vector<shard_scan_output_t> outputs(shards.size());
    const auto shard_fn = [&](std::size_t shard_index) -> workspace_result_t<void> {
        const auto& shard = shards[shard_index];
        shard_scanner_t scanner(image, provider, limits, cancel, shared, kernels,
            outputs[shard_index]);
        for (std::size_t unit_index = shard.unit_begin; unit_index < shard.unit_end;
             ++unit_index) {
            const auto& unit = units[unit_index];
            auto scanned = scanner.scan_unit(regions[unit.region_index], unit);
            if (!scanned)
                return scanned;
        }
        return workspace_result_t<void>::success();
    };
    auto scanned = run_scan_shards(shards.size(), shared, shard_fn);
    if (!scanned)
        return workspace_result_t<string_discovery_result_t>::failure(scanned.error());
    const auto merge_begin = std::chrono::steady_clock::now();
    string_discovery_result_t result;
    std::size_t total_strings = 0;
    for (const auto& output : outputs) {
        total_strings += output.strings.size();
        result.bytes_scanned += output.bytes_scanned;
        result.mapped_bytes += output.mapped_bytes;
        result.provider_leases += output.provider_leases;
        result.rejected_invalid_sequences += output.rejected_invalid_sequences;
        result.rejected_oversized_strings += output.rejected_oversized_strings;
        result.rejected_unterminated_strings += output.rejected_unterminated_strings;
    }
    std::vector<std::uint64_t> output_bases(outputs.size(), 0);
    {
        std::uint64_t cursor = 0;
        for (std::size_t index = 0; index < outputs.size(); ++index) {
            output_bases[index] = cursor;
            cursor += outputs[index].strings.size();
        }
    }
    result.strings.resize(total_strings);
    run_merge_shards(outputs.size(), [&](std::size_t shard) {
        auto& strings = outputs[shard].strings;
        auto cursor = output_bases[shard];
        for (std::size_t index = 0; index < strings.size(); ++index)
            result.strings[static_cast<std::size_t>(cursor++)] =
                std::move(strings[index]);
    });
    outputs.clear();
    parallel_sort(result.strings.begin(), result.strings.end(),
        [](const auto& lhs, const auto& rhs) {
            if (lhs.address != rhs.address)
                return lhs.address < rhs.address;
            if (lhs.encoding != rhs.encoding)
                return lhs.encoding < rhs.encoding;
            if (lhs.byte_length != rhs.byte_length)
                return lhs.byte_length < rhs.byte_length;
            if (lhs.value != rhs.value)
                return lhs.value < rhs.value;
            if (provenance_rank(lhs.provenance) != provenance_rank(rhs.provenance))
                return provenance_rank(lhs.provenance) > provenance_rank(rhs.provenance);
            return lhs.confidence > rhs.confidence;
        });
    const auto strings_before_dedup = result.strings.size();
    parallel_unique_erase(result.strings, [](const auto& lhs, const auto& rhs) {
        return lhs.address == rhs.address && lhs.encoding == rhs.encoding &&
               lhs.byte_length == rhs.byte_length && lhs.value == rhs.value;
    });
    result.duplicate_strings = static_cast<std::uint64_t>(
        strings_before_dedup - result.strings.size());
    for (std::size_t index = 0; index < result.strings.size(); ++index)
        result.strings[index].id = kStringEntityTag | static_cast<std::uint64_t>(index + 1);
    const auto merge_end = std::chrono::steady_clock::now();
    result.shard_merge_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(merge_end - merge_begin).count());
    return workspace_result_t<string_discovery_result_t>::success(std::move(result));
}

}

namespace string_simd {

void override_level_for_testing(std::int32_t level) noexcept {
    g_simd_level_override.store(level < 0 ? -1 : level, std::memory_order_release);
}

std::int32_t current_level() noexcept {
    const auto override_level = g_simd_level_override.load(std::memory_order_acquire);
    if (override_level >= 0)
        return (std::min)(override_level, supported_simd_level());
    return supported_simd_level();
}

}

workspace_result_t<string_discovery_result_t> string_discovery_t::discover(
    const workspace_image_t& image, const byte_provider_t& provider,
    const string_discovery_limits_t& limits, const cancellation_token_t& cancel) {
    try {
        return discover_impl(image, provider, limits, cancel);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<string_discovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "string discovery allocation failed", "string_discovery"));
    } catch (const std::length_error&) {
        return workspace_result_t<string_discovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "string discovery allocation length is unsupported", "string_discovery"));
    }
}

}
