#include "string_discovery.hpp"

#include "checked_range.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace aida::analysis {
namespace {

constexpr std::uint64_t kStringEntityTag = 6ULL << 56;

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
    string_discovery_result_t result;
    std::uint64_t result_bytes = 0;
    const auto emit = [&](std::uint64_t start, std::uint64_t byte_length,
        string_encoding_t encoding, std::string value, std::uint8_t confidence)
        -> workspace_result_t<void> {
        if (result.strings.size() >= limits.max_strings) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "string count exceeds its bound", "string_discovery"));
        }
        std::uint64_t record_bytes = 0;
        if (!checked_add_u64(sizeof(string_record_t), value.size(), record_bytes) ||
            !checked_add_u64(result_bytes, record_bytes, result_bytes) ||
            result_bytes > limits.max_result_bytes) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "string result storage exceeds its bound", "string_discovery"));
        }
        string_record_t record;
        record.address = rva_address(image, start);
        record.byte_length = byte_length;
        record.encoding = encoding;
        record.value = std::move(value);
        record.provenance = fact_provenance_t::linear_validation;
        record.confidence = confidence;
        result.strings.push_back(std::move(record));
        return workspace_result_t<void>::success();
    };
    const auto finish_ascii = [&](ascii_state_t& state, bool terminated)
        -> workspace_result_t<void> {
        if (!state.active)
            return workspace_result_t<void>::success();
        workspace_result_t<void> emitted = workspace_result_t<void>::success();
        if (state.oversized) {
            ++result.rejected_oversized_strings;
        } else if (limits.require_null_terminator && !terminated) {
            ++result.rejected_unterminated_strings;
        } else if (state.value.size() >= limits.minimum_code_points) {
            emitted = emit(state.start, state.bytes, string_encoding_t::ascii,
                std::move(state.value), terminated ? 96 : 82);
        }
        state = {};
        return emitted;
    };
    const auto finish_utf8 = [&](utf8_state_t& state, bool terminated)
        -> workspace_result_t<void> {
        if (!state.active)
            return workspace_result_t<void>::success();
        if (state.remaining != 0 && !state.oversized) {
            state.bytes = state.sequence_bytes_before;
            state.value.resize(state.sequence_value_before);
            state.remaining = 0;
            ++result.rejected_invalid_sequences;
        }
        workspace_result_t<void> emitted = workspace_result_t<void>::success();
        if (state.oversized) {
            ++result.rejected_oversized_strings;
        } else if (limits.require_null_terminator && !terminated) {
            ++result.rejected_unterminated_strings;
        } else if (state.has_non_ascii && state.code_points >= limits.minimum_code_points) {
            emitted = emit(state.start, state.bytes, string_encoding_t::utf8,
                std::move(state.value), terminated ? 98 : 84);
        }
        state = {};
        return emitted;
    };
    const auto finish_utf16 = [&](utf16_state_t& state, bool terminated)
        -> workspace_result_t<void> {
        if (!state.active && !state.has_pending_high) {
            state.has_pending_byte = false;
            return workspace_result_t<void>::success();
        }
        if (state.has_pending_high) {
            state.has_pending_high = false;
            ++result.rejected_invalid_sequences;
        }
        workspace_result_t<void> emitted = workspace_result_t<void>::success();
        const bool credible = terminated || state.has_surrogate ||
            (state.code_points != 0 &&
             static_cast<std::uint64_t>(state.zero_high_units) * 2ULL >= state.code_points);
        if (state.oversized) {
            ++result.rejected_oversized_strings;
        } else if (limits.require_null_terminator && !terminated) {
            ++result.rejected_unterminated_strings;
        } else if (credible && state.code_points >= limits.minimum_code_points) {
            emitted = emit(state.start, state.bytes, string_encoding_t::utf16_le,
                std::move(state.value), terminated ? 97 : 83);
        }
        state = {};
        return emitted;
    };
    std::uint64_t checks = 0;
    for (const auto& region : regions_result.value()) {
        if ((region.permissions & image_permission_read) == 0 ||
            (!limits.scan_executable_regions &&
             (region.permissions & image_permission_execute) != 0))
            continue;
        ascii_state_t ascii;
        utf8_state_t utf8;
        utf16_state_t utf16;
        const auto consume_ascii = [&](std::uint8_t byte, std::uint64_t rva)
            -> workspace_result_t<void> {
            if (byte >= 0x20U && byte <= 0x7eU) {
                if (!ascii.active) {
                    ascii.active = true;
                    ascii.start = rva;
                }
                ++ascii.bytes;
                if (!ascii.oversized &&
                    (ascii.bytes > limits.max_string_bytes ||
                     ascii.value.size() >= limits.max_string_value_bytes)) {
                    ascii.oversized = true;
                    ascii.value.clear();
                } else if (!ascii.oversized) {
                    ascii.value.push_back(static_cast<char>(byte));
                }
                return workspace_result_t<void>::success();
            }
            return finish_ascii(ascii, byte == 0);
        };
        const auto start_utf8_byte = [&](std::uint8_t byte, std::uint64_t rva)
            -> workspace_result_t<void> {
            if (byte >= 0x20U && byte <= 0x7eU) {
                if (!utf8.active) {
                    utf8.active = true;
                    utf8.start = rva;
                }
                ++utf8.bytes;
                ++utf8.code_points;
                if (!utf8.oversized &&
                    (utf8.bytes > limits.max_string_bytes ||
                     utf8.value.size() >= limits.max_string_value_bytes)) {
                    utf8.oversized = true;
                    utf8.value.clear();
                } else if (!utf8.oversized) {
                    utf8.value.push_back(static_cast<char>(byte));
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
                return finish_utf8(utf8, byte == 0);
            }
            if (!utf8.active) {
                utf8.active = true;
                utf8.start = rva;
            }
            utf8.sequence_bytes_before = utf8.bytes;
            utf8.sequence_value_before = utf8.value.size();
            utf8.remaining = remaining;
            utf8.code_point = code_point;
            utf8.minimum_code_point = minimum;
            ++utf8.bytes;
            if (!utf8.oversized &&
                (utf8.bytes > limits.max_string_bytes ||
                 utf8.value.size() >= limits.max_string_value_bytes)) {
                utf8.oversized = true;
                utf8.value.clear();
            } else if (!utf8.oversized) {
                utf8.value.push_back(static_cast<char>(byte));
            }
            return workspace_result_t<void>::success();
        };
        const auto consume_utf8 = [&](std::uint8_t byte, std::uint64_t rva)
            -> workspace_result_t<void> {
            if (utf8.remaining == 0)
                return start_utf8_byte(byte, rva);
            if ((byte & 0xc0U) != 0x80U) {
                if (!utf8.oversized) {
                    utf8.bytes = utf8.sequence_bytes_before;
                    utf8.value.resize(utf8.sequence_value_before);
                    ++result.rejected_invalid_sequences;
                }
                utf8.remaining = 0;
                auto finished = finish_utf8(utf8, false);
                if (!finished)
                    return finished;
                return start_utf8_byte(byte, rva);
            }
            ++utf8.bytes;
            utf8.code_point = (utf8.code_point << 6U) | (byte & 0x3fU);
            if (!utf8.oversized &&
                (utf8.bytes > limits.max_string_bytes ||
                 utf8.value.size() >= limits.max_string_value_bytes)) {
                utf8.oversized = true;
                utf8.value.clear();
            } else if (!utf8.oversized) {
                utf8.value.push_back(static_cast<char>(byte));
            }
            --utf8.remaining;
            if (utf8.remaining != 0)
                return workspace_result_t<void>::success();
            if (utf8.code_point < utf8.minimum_code_point ||
                !unicode_scalar_printable(utf8.code_point)) {
                if (!utf8.oversized) {
                    utf8.bytes = utf8.sequence_bytes_before;
                    utf8.value.resize(utf8.sequence_value_before);
                    ++result.rejected_invalid_sequences;
                }
                return finish_utf8(utf8, false);
            }
            ++utf8.code_points;
            utf8.has_non_ascii = true;
            return workspace_result_t<void>::success();
        };
        const auto append_utf16_scalar = [&](std::uint32_t value, std::uint64_t start,
                                              std::uint64_t source_bytes,
                                              bool surrogate) -> workspace_result_t<void> {
            if (!unicode_scalar_printable(value))
                return finish_utf16(utf16, false);
            if (!utf16.active) {
                utf16.active = true;
                utf16.start = start;
            }
            if (utf16.bytes > (std::numeric_limits<std::uint64_t>::max)() - source_bytes) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "UTF-16 string length overflows", "string_discovery"));
            }
            utf16.bytes += source_bytes;
            ++utf16.code_points;
            utf16.has_surrogate = utf16.has_surrogate || surrogate;
            const auto encoded = value <= 0x7fU ? 1ULL : value <= 0x7ffU ? 2ULL :
                value <= 0xffffU ? 3ULL : 4ULL;
            if (!utf16.oversized &&
                (utf16.bytes > limits.max_string_bytes ||
                 encoded > limits.max_string_value_bytes -
                     (std::min<std::uint64_t>)(utf16.value.size(),
                         limits.max_string_value_bytes))) {
                utf16.oversized = true;
                utf16.value.clear();
            } else if (!utf16.oversized) {
                append_utf8(utf16.value, value);
            }
            return workspace_result_t<void>::success();
        };
        const auto consume_utf16_unit = [&](std::uint16_t unit, std::uint64_t rva)
            -> workspace_result_t<void> {
            if (utf16.has_pending_high) {
                const auto high = utf16.pending_high;
                const auto high_address = utf16.pending_high_address;
                utf16.has_pending_high = false;
                if (unit >= 0xdc00U && unit <= 0xdfffU) {
                    const auto scalar = 0x10000U +
                        ((static_cast<std::uint32_t>(high) - 0xd800U) << 10U) +
                        (static_cast<std::uint32_t>(unit) - 0xdc00U);
                    return append_utf16_scalar(scalar, high_address, 4, true);
                }
                ++result.rejected_invalid_sequences;
                auto finished = finish_utf16(utf16, false);
                if (!finished)
                    return finished;
            }
            if (unit == 0)
                return finish_utf16(utf16, true);
            if (unit >= 0xd800U && unit <= 0xdbffU) {
                utf16.has_pending_high = true;
                utf16.pending_high = unit;
                utf16.pending_high_address = rva;
                return workspace_result_t<void>::success();
            }
            if (unit >= 0xdc00U && unit <= 0xdfffU) {
                ++result.rejected_invalid_sequences;
                return finish_utf16(utf16, false);
            }
            if ((unit >> 8U) == 0)
                ++utf16.zero_high_units;
            return append_utf16_scalar(unit, rva, 2, false);
        };
        const auto consume_utf16_byte = [&](std::uint8_t byte, std::uint64_t rva)
            -> workspace_result_t<void> {
            if (!utf16.has_pending_byte) {
                if ((rva & 1ULL) != 0)
                    return workspace_result_t<void>::success();
                utf16.has_pending_byte = true;
                utf16.pending_byte = byte;
                utf16.pending_byte_address = rva;
                return workspace_result_t<void>::success();
            }
            if (rva != utf16.pending_byte_address + 1ULL) {
                utf16.has_pending_byte = false;
                auto finished = finish_utf16(utf16, false);
                if (!finished)
                    return finished;
                if ((rva & 1ULL) == 0) {
                    utf16.has_pending_byte = true;
                    utf16.pending_byte = byte;
                    utf16.pending_byte_address = rva;
                }
                return workspace_result_t<void>::success();
            }
            const auto unit = static_cast<std::uint16_t>(utf16.pending_byte) |
                (static_cast<std::uint16_t>(byte) << 8U);
            const auto unit_address = utf16.pending_byte_address;
            utf16.has_pending_byte = false;
            return consume_utf16_unit(unit, unit_address);
        };
        std::uint64_t cursor = 0;
        while (cursor < region.size) {
            if (cancel.stop_requested())
                return workspace_result_t<string_discovery_result_t>::failure(stop_error(cancel));
            auto window = (std::min)(region.size - cursor, limits.read_window_bytes);
            std::uint64_t provider_offset = 0;
            if (!checked_add_u64(region.file_offset, cursor, provider_offset)) {
                return workspace_result_t<string_discovery_result_t>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                        "string scan provider offset overflows", "string_discovery"));
            }
            window = (std::min)(window, provider.maximum_contiguous_lease(provider_offset));
            if (window == 0) {
                return workspace_result_t<string_discovery_result_t>::failure(
                    make_workspace_error(workspace_error_code_t::provider_unavailable,
                        "string scan provider cannot lease the mapped range", "string_discovery"));
            }
            if (window > limits.max_scan_bytes -
                (std::min)(result.bytes_scanned, limits.max_scan_bytes)) {
                return workspace_result_t<string_discovery_result_t>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                        "string scan byte budget exceeded", "string_discovery"));
            }
            auto lease = provider.lease(provider_offset, window, cancel);
            if (!lease)
                return workspace_result_t<string_discovery_result_t>::failure(lease.error());
            ++result.provider_leases;
            result.bytes_scanned += window;
            result.mapped_bytes += window;
            for (std::uint64_t index = 0; index < window; ++index) {
                if (++checks >= limits.cancellation_check_interval) {
                    checks = 0;
                    if (cancel.stop_requested())
                        return workspace_result_t<string_discovery_result_t>::failure(
                            stop_error(cancel));
                }
                std::uint64_t rva = 0;
                if (!checked_add_u64(region.rva, cursor, rva) ||
                    !checked_add_u64(rva, index, rva)) {
                    return workspace_result_t<string_discovery_result_t>::failure(
                        make_workspace_error(workspace_error_code_t::range_overflow,
                            "string scan address overflows", "string_discovery"));
                }
                const auto byte = lease.value()[static_cast<std::size_t>(index)];
                if (limits.scan_ascii) {
                    auto consumed = consume_ascii(byte, rva);
                    if (!consumed)
                        return workspace_result_t<string_discovery_result_t>::failure(
                            consumed.error());
                }
                if (limits.scan_utf8) {
                    auto consumed = consume_utf8(byte, rva);
                    if (!consumed)
                        return workspace_result_t<string_discovery_result_t>::failure(
                            consumed.error());
                }
                if (limits.scan_utf16_le) {
                    auto consumed = consume_utf16_byte(byte, rva);
                    if (!consumed)
                        return workspace_result_t<string_discovery_result_t>::failure(
                            consumed.error());
                }
            }
            cursor += window;
        }
        auto finished = finish_ascii(ascii, false);
        if (!finished)
            return workspace_result_t<string_discovery_result_t>::failure(finished.error());
        finished = finish_utf8(utf8, false);
        if (!finished)
            return workspace_result_t<string_discovery_result_t>::failure(finished.error());
        finished = finish_utf16(utf16, false);
        if (!finished)
            return workspace_result_t<string_discovery_result_t>::failure(finished.error());
    }
    std::sort(result.strings.begin(), result.strings.end(), [](const auto& lhs,
                                                               const auto& rhs) {
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
    const auto end = std::unique(result.strings.begin(), result.strings.end(),
        [](const auto& lhs, const auto& rhs) {
            return lhs.address == rhs.address && lhs.encoding == rhs.encoding &&
                   lhs.byte_length == rhs.byte_length && lhs.value == rhs.value;
        });
    result.duplicate_strings = static_cast<std::uint64_t>(
        std::distance(end, result.strings.end()));
    result.strings.erase(end, result.strings.end());
    for (std::size_t index = 0; index < result.strings.size(); ++index)
        result.strings[index].id = kStringEntityTag | static_cast<std::uint64_t>(index + 1);
    return workspace_result_t<string_discovery_result_t>::success(std::move(result));
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
