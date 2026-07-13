#include "packed_page_codec.hpp"

#include "checked_range.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <map>
#include <unordered_set>
#include <utility>

namespace aida::analysis {

namespace {

constexpr std::uint32_t kCrc32cPoly = 0x82F63B78U;
constexpr std::size_t kCancellationStride = 4096;

const std::array<std::uint32_t, 256>& crc32c_table() noexcept {
    static const std::array<std::uint32_t, 256> table = [] {
        std::array<std::uint32_t, 256> result{};
        for (std::size_t index = 0; index < result.size(); ++index) {
            std::uint32_t crc = static_cast<std::uint32_t>(index);
            for (int bit = 0; bit < 8; ++bit)
                crc = (crc & 1U) ? (crc >> 1U) ^ kCrc32cPoly : crc >> 1U;
            result[index] = crc;
        }
        return result;
    }();
    return table;
}

void append_u32_le(std::vector<std::uint8_t>& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 24U));
}

std::uint32_t read_u32_le(const std::uint8_t* data) noexcept {
    return static_cast<std::uint32_t>(data[0]) |
           (static_cast<std::uint32_t>(data[1]) << 8U) |
           (static_cast<std::uint32_t>(data[2]) << 16U) |
           (static_cast<std::uint32_t>(data[3]) << 24U);
}

std::uint64_t read_u64_le(const std::uint8_t* data) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index)
        value |= static_cast<std::uint64_t>(data[index]) << (index * 8);
    return value;
}

std::uint32_t compute_page_checksum(const packed_page_header_t& header,
                                     const std::vector<std::uint8_t>& payload) noexcept {
    const auto& table = crc32c_table();
    std::uint32_t crc = 0xFFFFFFFFU;
    const auto encoded = header.encode();
    for (std::size_t index = 0; index < 48; ++index) {
        crc = table[(crc ^ encoded[index]) & 0xFFU] ^ (crc >> 8U);
    }
    for (std::size_t index = 0; index < payload.size(); ++index) {
        crc = table[(crc ^ payload[index]) & 0xFFU] ^ (crc >> 8U);
    }
    return crc ^ 0xFFFFFFFFU;
}

bool valid_page_type(std::uint32_t value) noexcept {
    return (value >= static_cast<std::uint32_t>(packed_page_type_t::instructions) &&
            value <= static_cast<std::uint32_t>(packed_page_last_data_type)) ||
           value == packed_page_checkpoint_type;
}

bool codec_stop_requested(const packed_stop_predicate_t& stop_requested) noexcept {
    if (!stop_requested)
        return false;
    try {
        return stop_requested();
    } catch (...) {
        return true;
    }
}

workspace_error_t codec_cancelled_error(const char* phase) {
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "packed page operation was cancelled",
                                      phase);
    error.cancellation = true;
    return error;
}

workspace_result_t<std::uint32_t> compute_page_checksum_cancellable(
    const packed_page_header_t& header,
    const std::vector<std::uint8_t>& payload,
    const packed_stop_predicate_t& stop_requested) {
    if (codec_stop_requested(stop_requested))
        return workspace_result_t<std::uint32_t>::failure(
            codec_cancelled_error("packed_page_codec.verify_page"));
    const auto& table = crc32c_table();
    std::uint32_t crc = 0xFFFFFFFFU;
    const auto encoded = header.encode();
    for (std::size_t index = 0; index < 48; ++index)
        crc = table[(crc ^ encoded[index]) & 0xFFU] ^ (crc >> 8U);
    for (std::size_t offset = 0; offset < payload.size();) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<std::uint32_t>::failure(
                codec_cancelled_error("packed_page_codec.verify_page"));
        const auto end = (std::min)(payload.size(), offset + kCancellationStride);
        for (; offset < end; ++offset)
            crc = table[(crc ^ payload[offset]) & 0xFFU] ^ (crc >> 8U);
    }
    if (codec_stop_requested(stop_requested))
        return workspace_result_t<std::uint32_t>::failure(
            codec_cancelled_error("packed_page_codec.verify_page"));
    return workspace_result_t<std::uint32_t>::success(crc ^ 0xFFFFFFFFU);
}

workspace_result_t<std::uint32_t> checksum_headers_cancellable(
    const packed_page_batch_t& batch,
    const packed_stop_predicate_t& stop_requested) {
    const auto& table = crc32c_table();
    std::uint32_t crc = 0xFFFFFFFFU;
    for (const auto& page : batch.pages) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<std::uint32_t>::failure(
                codec_cancelled_error("packed_page_codec.verify_batch"));
        const auto value = page.header.checksum;
        for (unsigned shift = 0; shift < 32; shift += 8) {
            const auto byte = static_cast<std::uint8_t>(value >> shift);
            crc = table[(crc ^ byte) & 0xFFU] ^ (crc >> 8U);
        }
    }
    return workspace_result_t<std::uint32_t>::success(crc ^ 0xFFFFFFFFU);
}

}

std::uint32_t crc32c(const std::uint8_t* data, std::size_t size) noexcept {
    if (!data && size != 0)
        return 0;
    const auto& table = crc32c_table();
    std::uint32_t crc = 0xFFFFFFFFU;
    for (std::size_t index = 0; index < size; ++index) {
        crc = table[(crc ^ data[index]) & 0xFFU] ^ (crc >> 8U);
    }
    return crc ^ 0xFFFFFFFFU;
}

workspace_result_t<std::uint32_t> crc32c_cancellable(
    const std::uint8_t* data, std::size_t size,
    const packed_stop_predicate_t& stop_requested) {
    if (!data && size != 0) {
        return workspace_result_t<std::uint32_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "CRC32C input is null with a non-zero size",
            "packed_page_codec.crc32c"));
    }
    if (codec_stop_requested(stop_requested))
        return workspace_result_t<std::uint32_t>::failure(
            codec_cancelled_error("packed_page_codec.crc32c"));
    const auto& table = crc32c_table();
    std::uint32_t crc = 0xFFFFFFFFU;
    for (std::size_t offset = 0; offset < size;) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<std::uint32_t>::failure(
                codec_cancelled_error("packed_page_codec.crc32c"));
        const auto end = (std::min)(size, offset + kCancellationStride);
        for (; offset < end; ++offset)
            crc = table[(crc ^ data[offset]) & 0xFFU] ^ (crc >> 8U);
    }
    if (codec_stop_requested(stop_requested))
        return workspace_result_t<std::uint32_t>::failure(
            codec_cancelled_error("packed_page_codec.crc32c"));
    return workspace_result_t<std::uint32_t>::success(crc ^ 0xFFFFFFFFU);
}

std::array<std::uint8_t, packed_page_header_size> packed_page_header_t::encode() const noexcept {
    std::array<std::uint8_t, packed_page_header_size> output{};
    auto* cursor = output.data();
    auto write_u32 = [&](std::uint32_t value) {
        cursor[0] = static_cast<std::uint8_t>(value);
        cursor[1] = static_cast<std::uint8_t>(value >> 8U);
        cursor[2] = static_cast<std::uint8_t>(value >> 16U);
        cursor[3] = static_cast<std::uint8_t>(value >> 24U);
        cursor += 4;
    };
    auto write_u64 = [&](std::uint64_t value) {
        for (unsigned shift = 0; shift < 64; shift += 8)
            *cursor++ = static_cast<std::uint8_t>(value >> shift);
    };
    write_u32(magic);
    write_u32(version);
    write_u32(page_type);
    write_u32(page_index);
    write_u32(page_count);
    write_u64(generation);
    write_u64(analysis_revision);
    write_u64(overlay_revision);
    write_u32(payload_length);
    write_u32(checksum);
    for (std::size_t index = 0; index < reserved.size(); ++index)
        *cursor++ = reserved[index];
    return output;
}

std::optional<packed_page_header_t> packed_page_header_t::decode(
    const std::uint8_t* data, std::size_t size) noexcept {
    if (!data || size < encoded_size)
        return std::nullopt;
    packed_page_header_t header;
    header.magic = read_u32_le(data + 0);
    header.version = read_u32_le(data + 4);
    header.page_type = read_u32_le(data + 8);
    header.page_index = read_u32_le(data + 12);
    header.page_count = read_u32_le(data + 16);
    header.generation = read_u64_le(data + 20);
    header.analysis_revision = read_u64_le(data + 28);
    header.overlay_revision = read_u64_le(data + 36);
    header.payload_length = read_u32_le(data + 44);
    header.checksum = read_u32_le(data + 48);
    for (std::size_t index = 0; index < 12; ++index)
        header.reserved[index] = data[52 + index];
    return header;
}

std::array<std::uint8_t, 28> packed_page_checkpoint_t::encode() const noexcept {
    std::array<std::uint8_t, 28> output{};
    auto* cursor = output.data();
    cursor[0] = static_cast<std::uint8_t>(batch_checksum);
    cursor[1] = static_cast<std::uint8_t>(batch_checksum >> 8U);
    cursor[2] = static_cast<std::uint8_t>(batch_checksum >> 16U);
    cursor[3] = static_cast<std::uint8_t>(batch_checksum >> 24U);
    cursor += 4;
    for (unsigned shift = 0; shift < 64; shift += 8)
        *cursor++ = static_cast<std::uint8_t>(total_records >> shift);
    for (unsigned shift = 0; shift < 64; shift += 8)
        *cursor++ = static_cast<std::uint8_t>(total_payload_bytes >> shift);
    for (unsigned shift = 0; shift < 64; shift += 8)
        *cursor++ = static_cast<std::uint8_t>(created_utc_ms >> shift);
    return output;
}

std::optional<packed_page_checkpoint_t> packed_page_checkpoint_t::decode(
    const std::uint8_t* data, std::size_t size) noexcept {
    if (!data || size != 28)
        return std::nullopt;
    packed_page_checkpoint_t checkpoint;
    checkpoint.batch_checksum = read_u32_le(data + 0);
    checkpoint.total_records = read_u64_le(data + 4);
    checkpoint.total_payload_bytes = read_u64_le(data + 12);
    checkpoint.created_utc_ms = read_u64_le(data + 20);
    return checkpoint;
}

workspace_result_t<packed_page_batch_t> packed_page_codec_t::encode_batch(
    packed_page_type_t page_type,
    const std::vector<std::uint8_t>& data,
    const packed_page_encode_options_t& options,
    const packed_stop_predicate_t& stop_requested) {
    if (codec_stop_requested(stop_requested))
        return workspace_result_t<packed_page_batch_t>::failure(
            codec_cancelled_error("packed_page_codec.encode_batch"));
    if (options.page_size < packed_page_header_size + 16 ||
        options.page_size > packed_page_max_payload + packed_page_header_size) {
        return workspace_result_t<packed_page_batch_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "page size is outside the valid range",
                                 "packed_page_codec.encode_batch"));
    }
    if (options.generation == 0) {
        return workspace_result_t<packed_page_batch_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "generation must be non-zero",
                                 "packed_page_codec.encode_batch"));
    }
    const auto encoded_page_type = static_cast<std::uint32_t>(page_type);
    if (!valid_page_type(encoded_page_type) ||
        encoded_page_type == packed_page_checkpoint_type) {
        return workspace_result_t<packed_page_batch_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "page type is not a data domain",
                                 "packed_page_codec.encode_batch"));
    }
    if (data.size() > packed_generation_max_payload_bytes) {
        return workspace_result_t<packed_page_batch_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "encoded payload exceeds the generation byte limit",
                                 "packed_page_codec.encode_batch"));
    }
    const std::uint32_t payload_capacity = options.page_size - packed_page_header_size;
    const std::uint64_t page_count_64 = data.empty() ? 1ULL :
        1ULL + (static_cast<std::uint64_t>(data.size()) - 1ULL) / payload_capacity;
    if (page_count_64 == 0 || page_count_64 > packed_generation_max_pages) {
        return workspace_result_t<packed_page_batch_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "page count exceeds the maximum batch size",
                                 "packed_page_codec.encode_batch"));
    }
    const auto page_count = static_cast<std::uint32_t>(page_count_64);
    packed_page_batch_t batch;
    batch.generation = options.generation;
    batch.analysis_revision = options.analysis_revision;
    batch.overlay_revision = options.overlay_revision;
    batch.pages.reserve(page_count);
    std::uint64_t total_payload_bytes = 0;
    for (std::uint32_t page_index = 0; page_index < page_count; ++page_index) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<packed_page_batch_t>::failure(
                codec_cancelled_error("packed_page_codec.encode_batch"));
        packed_page_t page;
        page.header.magic = packed_page_magic;
        page.header.version = packed_page_blob_version;
        page.header.page_type = encoded_page_type;
        page.header.page_index = page_index;
        page.header.page_count = page_count;
        page.header.generation = options.generation;
        page.header.analysis_revision = options.analysis_revision;
        page.header.overlay_revision = options.overlay_revision;
        const std::size_t begin = static_cast<std::size_t>(page_index) * payload_capacity;
        const std::size_t end = (std::min)(data.size(), begin + payload_capacity);
        page.payload.assign(data.begin() + begin, data.begin() + end);
        page.header.payload_length = static_cast<std::uint32_t>(page.payload.size());
        auto checksum = compute_page_checksum_cancellable(
            page.header, page.payload, stop_requested);
        if (!checksum)
            return workspace_result_t<packed_page_batch_t>::failure(checksum.error());
        page.header.checksum = checksum.value();
        total_payload_bytes += page.payload.size();
        batch.pages.push_back(std::move(page));
    }
    std::vector<std::uint8_t> checksum_concat;
    checksum_concat.reserve(batch.pages.size() * 4);
    for (const auto& page : batch.pages)
        append_u32_le(checksum_concat, page.header.checksum);
    auto batch_checksum = crc32c_cancellable(
        checksum_concat.data(), checksum_concat.size(), stop_requested);
    if (!batch_checksum)
        return workspace_result_t<packed_page_batch_t>::failure(batch_checksum.error());
    batch.checkpoint.batch_checksum = batch_checksum.value();
    batch.checkpoint.total_records = page_count;
    batch.checkpoint.total_payload_bytes = total_payload_bytes;
    batch.checkpoint.created_utc_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    return workspace_result_t<packed_page_batch_t>::success(std::move(batch));
}

workspace_result_t<std::vector<std::uint8_t>> packed_page_codec_t::decode_batch(
    const packed_page_batch_t& batch,
    const packed_stop_predicate_t& stop_requested) {
    if (codec_stop_requested(stop_requested))
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            codec_cancelled_error("packed_page_codec.decode_batch"));
    if (batch.pages.empty()) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "batch contains no pages",
                                 "packed_page_codec.decode_batch"));
    }
    auto verified = verify_batch(batch, stop_requested);
    if (!verified)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(verified.error());
    std::vector<std::uint8_t> output;
    std::uint64_t estimated_size = 0;
    for (const auto& page : batch.pages) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                codec_cancelled_error("packed_page_codec.decode_batch"));
        if (!checked_add_u64(estimated_size, page.payload.size(), estimated_size) ||
            estimated_size > packed_generation_max_payload_bytes) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                                     "total decoded payload exceeds its bounded limit",
                                     "packed_page_codec.decode_batch"));
        }
    }
    if (estimated_size > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            make_workspace_error(workspace_error_code_t::range_overflow,
                                 "decoded payload does not fit in addressable memory",
                                 "packed_page_codec.decode_batch"));
    }
    output.reserve(static_cast<std::size_t>(estimated_size));
    for (std::size_t expected_index = 0; expected_index < batch.pages.size(); ++expected_index) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                codec_cancelled_error("packed_page_codec.decode_batch"));
        const auto& page = batch.pages[expected_index];
        if (page.header.page_index != static_cast<std::uint32_t>(expected_index)) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "page index sequence is broken",
                                     "packed_page_codec.decode_batch"));
        }
        for (std::size_t offset = 0; offset < page.payload.size();
             offset += kCancellationStride) {
            if (codec_stop_requested(stop_requested))
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    codec_cancelled_error("packed_page_codec.decode_batch"));
            const auto end =
                (std::min)(page.payload.size(), offset + kCancellationStride);
            output.insert(output.end(), page.payload.data() + offset,
                          page.payload.data() + end);
        }
    }
    if (codec_stop_requested(stop_requested))
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            codec_cancelled_error("packed_page_codec.decode_batch"));
    return workspace_result_t<std::vector<std::uint8_t>>::success(std::move(output));
}

workspace_result_t<void> packed_page_codec_t::verify_page(
    const packed_page_t& page,
    const packed_stop_predicate_t& stop_requested) {
    if (codec_stop_requested(stop_requested))
        return workspace_result_t<void>::failure(
            codec_cancelled_error("packed_page_codec.verify_page"));
    if (page.header.magic != packed_page_magic) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "page magic is invalid",
                                 "packed_page_codec.verify_page"));
    }
    if (page.header.version != packed_page_blob_version) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "page version is unsupported",
                                 "packed_page_codec.verify_page"));
    }
    if (!valid_page_type(page.header.page_type) || page.header.generation == 0 ||
        page.header.page_count == 0 ||
        page.header.page_count > packed_generation_max_pages ||
        page.header.page_index >= page.header.page_count ||
        std::any_of(page.header.reserved.begin(), page.header.reserved.end(),
                    [](std::uint8_t value) { return value != 0; })) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "page header invariants are invalid",
                                 "packed_page_codec.verify_page"));
    }
    if (page.payload.size() > packed_page_max_payload ||
        page.header.payload_length != page.payload.size()) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "page payload length does not match header",
                                 "packed_page_codec.verify_page"));
    }
    auto expected_checksum = compute_page_checksum_cancellable(
        page.header, page.payload, stop_requested);
    if (!expected_checksum)
        return workspace_result_t<void>::failure(expected_checksum.error());
    if (expected_checksum.value() != page.header.checksum) {
        auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                          "page checksum verification failed",
                                          "packed_page_codec.verify_page");
        error.details.emplace_back("expected_checksum",
                                   std::to_string(expected_checksum.value()));
        error.details.emplace_back("actual_checksum", std::to_string(page.header.checksum));
        return workspace_result_t<void>::failure(std::move(error));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> packed_page_codec_t::verify_batch(
    const packed_page_batch_t& batch,
    const packed_stop_predicate_t& stop_requested) {
    if (codec_stop_requested(stop_requested))
        return workspace_result_t<void>::failure(
            codec_cancelled_error("packed_page_codec.verify_batch"));
    if (batch.pages.empty()) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "batch contains no pages",
                                 "packed_page_codec.verify_batch"));
    }
    if (batch.pages.size() > packed_generation_max_pages) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "batch page count exceeds the bounded limit",
                                 "packed_page_codec.verify_batch"));
    }
    const std::uint32_t declared_page_count = batch.pages[0].header.page_count;
    if (declared_page_count != batch.pages.size()) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "batch page count does not match declared count",
                                 "packed_page_codec.verify_batch"));
    }
    const std::uint64_t declared_generation = batch.pages[0].header.generation;
    const std::uint64_t declared_analysis_revision = batch.pages[0].header.analysis_revision;
    const std::uint64_t declared_overlay_revision = batch.pages[0].header.overlay_revision;
    if (batch.generation != declared_generation ||
        batch.analysis_revision != declared_analysis_revision ||
        batch.overlay_revision != declared_overlay_revision) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "batch metadata does not match its page headers",
                                 "packed_page_codec.verify_batch"));
    }
    std::uint64_t total_payload_bytes = 0;
    for (std::size_t index = 0; index < batch.pages.size(); ++index) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<void>::failure(
                codec_cancelled_error("packed_page_codec.verify_batch"));
        const auto& page = batch.pages[index];
        if (page.header.generation != declared_generation ||
            page.header.analysis_revision != declared_analysis_revision ||
            page.header.overlay_revision != declared_overlay_revision ||
            page.header.page_type == packed_page_checkpoint_type ||
            page.header.page_count != declared_page_count ||
            page.header.page_index != static_cast<std::uint32_t>(index)) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "batch page sequence or metadata is inconsistent",
                                     "packed_page_codec.verify_batch"));
        }
        auto verified = verify_page(page, stop_requested);
        if (!verified)
            return verified;
        if (!checked_add_u64(total_payload_bytes, page.payload.size(), total_payload_bytes) ||
            total_payload_bytes > packed_generation_max_payload_bytes) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                                     "batch payload exceeds the bounded byte limit",
                                     "packed_page_codec.verify_batch"));
        }
    }
    if (batch.checkpoint.total_records != batch.pages.size() ||
        batch.checkpoint.total_payload_bytes != total_payload_bytes) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "batch checkpoint totals do not match the pages",
                                 "packed_page_codec.verify_batch"));
    }
    auto computed_batch_checksum = checksum_headers_cancellable(batch, stop_requested);
    if (!computed_batch_checksum)
        return workspace_result_t<void>::failure(computed_batch_checksum.error());
    if (computed_batch_checksum.value() != batch.checkpoint.batch_checksum) {
        auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                          "batch checkpoint checksum verification failed",
                                          "packed_page_codec.verify_batch");
        error.details.emplace_back("expected",
                                   std::to_string(computed_batch_checksum.value()));
        error.details.emplace_back("actual", std::to_string(batch.checkpoint.batch_checksum));
        return workspace_result_t<void>::failure(std::move(error));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::vector<packed_page_index_entry_t>>
packed_page_codec_t::build_warm_open_index(
    const packed_page_batch_t& batch,
    const packed_stop_predicate_t& stop_requested) {
    auto verified = verify_batch(batch, stop_requested);
    if (!verified)
        return workspace_result_t<std::vector<packed_page_index_entry_t>>::failure(verified.error());
    std::vector<packed_page_index_entry_t> entries;
    entries.reserve(batch.pages.size());
    std::uint64_t ordinal_begin = 0;
    for (const auto& page : batch.pages) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<std::vector<packed_page_index_entry_t>>::failure(
                codec_cancelled_error("packed_page_codec.build_warm_open_index"));
        packed_page_index_entry_t entry;
        entry.domain = static_cast<std::uint16_t>(page.header.page_type);
        entry.page_index = page.header.page_index;
        if (ordinal_begin > (std::numeric_limits<std::uint32_t>::max)()) {
            return workspace_result_t<std::vector<packed_page_index_entry_t>>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                                     "warm-open ordinal exceeds the index representation",
                                     "packed_page_codec.build_warm_open_index"));
        }
        entry.ordinal_begin = static_cast<std::uint32_t>(ordinal_begin);
        entry.count = page.header.payload_length;
        if (page.payload.size() >= sizeof(std::uint64_t)) {
            const auto first_address = read_u64_le(page.payload.data());
            const std::size_t last_offset = page.payload.size() - sizeof(std::uint64_t);
            const auto last_address = read_u64_le(page.payload.data() + last_offset);
            entry.address_value_min = (std::min)(first_address, last_address);
            entry.address_value_max = (std::max)(first_address, last_address);
        }
        entries.push_back(entry);
        if (!checked_add_u64(ordinal_begin, page.payload.size(), ordinal_begin)) {
            return workspace_result_t<std::vector<packed_page_index_entry_t>>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                                     "warm-open ordinal accumulation overflowed",
                                     "packed_page_codec.build_warm_open_index"));
        }
    }
    return workspace_result_t<std::vector<packed_page_index_entry_t>>::success(std::move(entries));
}

workspace_result_t<packed_page_t> packed_page_codec_t::encode_checkpoint_page(
    std::uint64_t generation,
    std::uint64_t analysis_revision,
    std::uint64_t overlay_revision,
    const packed_page_checkpoint_t& checkpoint) {
    if (generation == 0) {
        return workspace_result_t<packed_page_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "checkpoint generation must be non-zero",
                                 "packed_page_codec.encode_checkpoint_page"));
    }
    packed_page_t page;
    page.header.magic = packed_page_magic;
    page.header.version = packed_page_blob_version;
    page.header.page_type = packed_page_checkpoint_type;
    page.header.page_index = 0;
    page.header.page_count = 1;
    page.header.generation = generation;
    page.header.analysis_revision = analysis_revision;
    page.header.overlay_revision = overlay_revision;
    const auto encoded = checkpoint.encode();
    page.payload.assign(encoded.begin(), encoded.end());
    page.header.payload_length = static_cast<std::uint32_t>(page.payload.size());
    page.header.checksum = compute_page_checksum(page.header, page.payload);
    return workspace_result_t<packed_page_t>::success(std::move(page));
}

workspace_result_t<packed_page_checkpoint_t>
packed_page_codec_t::decode_checkpoint_page(const packed_page_t& page) {
    if (page.header.page_type != packed_page_checkpoint_type) {
        return workspace_result_t<packed_page_checkpoint_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "page is not a checkpoint page",
                                 "packed_page_codec.decode_checkpoint_page"));
    }
    auto verified = verify_page(page);
    if (!verified)
        return workspace_result_t<packed_page_checkpoint_t>::failure(verified.error());
    auto decoded = packed_page_checkpoint_t::decode(page.payload.data(), page.payload.size());
    if (!decoded) {
        return workspace_result_t<packed_page_checkpoint_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "checkpoint payload is not the canonical 28-byte form",
                                 "packed_page_codec.decode_checkpoint_page"));
    }
    return workspace_result_t<packed_page_checkpoint_t>::success(*decoded);
}

std::vector<std::uint8_t> packed_page_codec_t::encode_fixed_width_address(
    const address_t& address) noexcept {
    std::vector<std::uint8_t> output(fixed_width_address_size, 0);
    output[0] = static_cast<std::uint8_t>(address.space);
    output[1] = static_cast<std::uint8_t>(address.architecture);
    output[2] = static_cast<std::uint8_t>(address.mode);
    for (unsigned shift = 0; shift < 64; shift += 8)
        output[8 + shift / 8] = static_cast<std::uint8_t>(address.value >> shift);
    return output;
}

address_t packed_page_codec_t::decode_fixed_width_address(
    const std::uint8_t* data, std::size_t size) noexcept {
    address_t address;
    if (!data || size < fixed_width_address_size)
        return address;
    address.space = static_cast<address_space_id_t>(data[0]);
    address.architecture = static_cast<architecture_id_t>(data[1]);
    address.mode = static_cast<architecture_mode_t>(data[2]);
    address.value = read_u64_le(data + 8);
    return address;
}

workspace_result_t<packed_page_batch_t> packed_page_codec_t::encode_multi_domain_batch(
    const std::vector<std::pair<packed_page_type_t, std::vector<std::uint8_t>>>& domains,
    const packed_page_encode_options_t& options,
    const packed_stop_predicate_t& stop_requested) {
    if (codec_stop_requested(stop_requested))
        return workspace_result_t<packed_page_batch_t>::failure(
            codec_cancelled_error("packed_page_codec.encode_multi_domain_batch"));
    if (domains.empty()) {
        return workspace_result_t<packed_page_batch_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "multi-domain batch contains no domains",
                                 "packed_page_codec.encode_multi_domain_batch"));
    }
    packed_page_batch_t combined;
    combined.generation = options.generation;
    combined.analysis_revision = options.analysis_revision;
    combined.overlay_revision = options.overlay_revision;
    std::uint32_t global_page_index = 0;
    std::uint64_t total_payload_bytes = 0;
    std::unordered_set<std::uint32_t> encoded_domains;
    for (const auto& [domain_type, domain_data] : domains) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<packed_page_batch_t>::failure(
                codec_cancelled_error("packed_page_codec.encode_multi_domain_batch"));
        const auto encoded_domain = static_cast<std::uint32_t>(domain_type);
        if (!encoded_domains.insert(encoded_domain).second) {
            return workspace_result_t<packed_page_batch_t>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                                     "multi-domain batch contains a duplicate domain",
                                     "packed_page_codec.encode_multi_domain_batch"));
        }
        auto domain_batch = encode_batch(
            domain_type, domain_data, options, stop_requested);
        if (!domain_batch)
            return domain_batch;
        for (auto& page : domain_batch.value().pages) {
            if (codec_stop_requested(stop_requested))
                return workspace_result_t<packed_page_batch_t>::failure(
                    codec_cancelled_error("packed_page_codec.encode_multi_domain_batch"));
            if (global_page_index >= packed_generation_max_pages ||
                !checked_add_u64(total_payload_bytes, page.payload.size(),
                                 total_payload_bytes) ||
                total_payload_bytes > packed_generation_max_payload_bytes) {
                return workspace_result_t<packed_page_batch_t>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                                         "combined batch exceeds its bounded limits",
                                         "packed_page_codec.encode_multi_domain_batch"));
            }
            page.header.page_index = global_page_index++;
            combined.pages.push_back(std::move(page));
        }
    }
    std::vector<std::uint8_t> checksum_concat;
    checksum_concat.reserve(combined.pages.size() * sizeof(std::uint32_t));
    for (auto& page : combined.pages) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<packed_page_batch_t>::failure(
                codec_cancelled_error("packed_page_codec.encode_multi_domain_batch"));
        page.header.page_count = global_page_index;
        auto checksum = compute_page_checksum_cancellable(
            page.header, page.payload, stop_requested);
        if (!checksum)
            return workspace_result_t<packed_page_batch_t>::failure(checksum.error());
        page.header.checksum = checksum.value();
        append_u32_le(checksum_concat, page.header.checksum);
    }
    auto batch_checksum = crc32c_cancellable(
        checksum_concat.data(), checksum_concat.size(), stop_requested);
    if (!batch_checksum)
        return workspace_result_t<packed_page_batch_t>::failure(batch_checksum.error());
    combined.checkpoint.batch_checksum = batch_checksum.value();
    combined.checkpoint.total_records = global_page_index;
    combined.checkpoint.total_payload_bytes = total_payload_bytes;
    combined.checkpoint.created_utc_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    return workspace_result_t<packed_page_batch_t>::success(std::move(combined));
}

workspace_result_t<packed_generation_publication_t>
packed_page_codec_t::build_publication(
    const packed_page_batch_t& batch,
    std::vector<std::uint8_t> metadata,
    const packed_stop_predicate_t& stop_requested) {
    if (metadata.size() > packed_generation_max_metadata_bytes) {
        return workspace_result_t<packed_generation_publication_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "packed generation metadata exceeds its bounded limit",
                                 "packed_page_codec.build_publication"));
    }
    auto verified = verify_batch(batch, stop_requested);
    if (!verified)
        return workspace_result_t<packed_generation_publication_t>::failure(
            verified.error());
    auto warm_index = build_warm_open_index(batch, stop_requested);
    if (!warm_index)
        return workspace_result_t<packed_generation_publication_t>::failure(
            warm_index.error());

    std::unordered_set<std::uint32_t> domains;
    for (const auto& page : batch.pages) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<packed_generation_publication_t>::failure(
                codec_cancelled_error("packed_page_codec.build_publication"));
        domains.insert(page.header.page_type);
    }
    if (domains.empty() ||
        domains.size() > static_cast<std::size_t>(packed_page_last_data_type)) {
        return workspace_result_t<packed_generation_publication_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "packed generation domain count is invalid",
                                 "packed_page_codec.build_publication"));
    }

    packed_generation_publication_t publication;
    publication.generation.generation = batch.generation;
    publication.generation.analysis_revision = batch.analysis_revision;
    publication.generation.overlay_revision = batch.overlay_revision;
    publication.generation.shard_count =
        static_cast<std::uint16_t>(domains.size());
    publication.generation.total_payload_bytes =
        batch.checkpoint.total_payload_bytes;
    publication.generation.total_records = batch.checkpoint.total_records;
    publication.generation.batch_checksum = batch.checkpoint.batch_checksum;
    publication.generation.created_utc_ms = batch.checkpoint.created_utc_ms;
    publication.generation.committed = false;
    publication.generation.payload_blob = std::move(metadata);
    publication.pages.reserve(batch.pages.size());
    for (const auto& page : batch.pages) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<packed_generation_publication_t>::failure(
                codec_cancelled_error("packed_page_codec.build_publication"));
        packed_page_row_t row;
        row.generation = page.header.generation;
        row.page_index = page.header.page_index;
        row.page_count = page.header.page_count;
        row.page_type = page.header.page_type;
        row.payload_length = page.header.payload_length;
        row.checksum = page.header.checksum;
        row.payload.reserve(page.payload.size());
        for (std::size_t offset = 0; offset < page.payload.size();) {
            if (codec_stop_requested(stop_requested))
                return workspace_result_t<packed_generation_publication_t>::failure(
                    codec_cancelled_error("packed_page_codec.build_publication"));
            const auto end = (std::min)(page.payload.size(),
                                        offset + kCancellationStride);
            row.payload.insert(row.payload.end(), page.payload.data() + offset,
                               page.payload.data() + end);
            offset = end;
        }
        publication.pages.push_back(std::move(row));
    }
    publication.index.reserve(warm_index.value().size());
    for (const auto& entry : warm_index.value()) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<packed_generation_publication_t>::failure(
                codec_cancelled_error("packed_page_codec.build_publication"));
        packed_page_index_row_t row;
        row.generation = batch.generation;
        row.domain = entry.domain;
        row.ordinal_begin = entry.ordinal_begin;
        row.count = entry.count;
        row.page_index = entry.page_index;
        row.address_value_min = entry.address_value_min;
        row.address_value_max = entry.address_value_max;
        publication.index.push_back(row);
    }
    return workspace_result_t<packed_generation_publication_t>::success(
        std::move(publication));
}

workspace_result_t<packed_page_batch_t>
packed_page_codec_t::restore_publication(
    const packed_generation_publication_t& publication,
    const packed_stop_predicate_t& stop_requested) {
    const auto& generation = publication.generation;
    if (generation.generation == 0 || publication.pages.empty() ||
        publication.pages.size() > packed_generation_max_pages ||
        publication.index.size() != publication.pages.size() ||
        publication.index.size() > packed_generation_max_index_rows ||
        generation.payload_blob.size() > packed_generation_max_metadata_bytes) {
        return workspace_result_t<packed_page_batch_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "packed publication shape is invalid",
                                 "packed_page_codec.restore_publication"));
    }

    packed_page_batch_t batch;
    batch.generation = generation.generation;
    batch.analysis_revision = generation.analysis_revision;
    batch.overlay_revision = generation.overlay_revision;
    batch.checkpoint.batch_checksum = generation.batch_checksum;
    batch.checkpoint.total_records = generation.total_records;
    batch.checkpoint.total_payload_bytes = generation.total_payload_bytes;
    batch.checkpoint.created_utc_ms = generation.created_utc_ms;
    batch.pages.reserve(publication.pages.size());
    for (const auto& row : publication.pages) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<packed_page_batch_t>::failure(
                codec_cancelled_error("packed_page_codec.restore_publication"));
        packed_page_t page;
        page.header.generation = row.generation;
        page.header.analysis_revision = generation.analysis_revision;
        page.header.overlay_revision = generation.overlay_revision;
        page.header.page_type = row.page_type;
        page.header.page_index = row.page_index;
        page.header.page_count = row.page_count;
        page.header.payload_length = row.payload_length;
        page.header.checksum = row.checksum;
        page.payload.reserve(row.payload.size());
        for (std::size_t offset = 0; offset < row.payload.size();) {
            if (codec_stop_requested(stop_requested))
                return workspace_result_t<packed_page_batch_t>::failure(
                    codec_cancelled_error("packed_page_codec.restore_publication"));
            const auto end = (std::min)(row.payload.size(),
                                        offset + kCancellationStride);
            page.payload.insert(page.payload.end(), row.payload.data() + offset,
                                row.payload.data() + end);
            offset = end;
        }
        batch.pages.push_back(std::move(page));
    }
    auto verified = verify_batch(batch, stop_requested);
    if (!verified)
        return workspace_result_t<packed_page_batch_t>::failure(verified.error());
    auto computed_index = build_warm_open_index(batch, stop_requested);
    if (!computed_index)
        return workspace_result_t<packed_page_batch_t>::failure(
            computed_index.error());

    std::vector<const packed_page_index_row_t*> persisted_by_page(
        publication.pages.size(), nullptr);
    std::unordered_set<std::uint16_t> domains;
    for (const auto& row : publication.index) {
        if (codec_stop_requested(stop_requested))
            return workspace_result_t<packed_page_batch_t>::failure(
                codec_cancelled_error("packed_page_codec.restore_publication"));
        if (row.generation != generation.generation ||
            static_cast<std::size_t>(row.page_index) >= persisted_by_page.size() ||
            persisted_by_page[row.page_index]) {
            return workspace_result_t<packed_page_batch_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "packed warm-open index ownership is invalid",
                                     "packed_page_codec.restore_publication"));
        }
        persisted_by_page[row.page_index] = &row;
        domains.insert(row.domain);
    }
    if (domains.size() != generation.shard_count) {
        return workspace_result_t<packed_page_batch_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "packed warm-open index domain count is inconsistent",
                                 "packed_page_codec.restore_publication"));
    }
    for (std::size_t index = 0; index < computed_index.value().size(); ++index) {
        const auto* persisted = persisted_by_page[index];
        const auto& computed = computed_index.value()[index];
        if (!persisted || persisted->domain != computed.domain ||
            persisted->page_index != computed.page_index ||
            persisted->ordinal_begin != computed.ordinal_begin ||
            persisted->count != computed.count ||
            persisted->address_value_min != computed.address_value_min ||
            persisted->address_value_max != computed.address_value_max) {
            return workspace_result_t<packed_page_batch_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "packed warm-open index does not match its pages",
                                     "packed_page_codec.restore_publication"));
        }
    }
    return workspace_result_t<packed_page_batch_t>::success(std::move(batch));
}

workspace_result_t<
    std::vector<std::pair<packed_page_type_t, std::vector<std::uint8_t>>>>
packed_page_codec_t::decode_multi_domain_publication(
    const packed_generation_publication_t& publication,
    const packed_stop_predicate_t& stop_requested) {
    auto restored = restore_publication(publication, stop_requested);
    if (!restored) {
        return workspace_result_t<
            std::vector<std::pair<packed_page_type_t, std::vector<std::uint8_t>>>>::failure(
                restored.error());
    }

    std::vector<const packed_page_index_row_t*> index_by_page(
        publication.pages.size(), nullptr);
    for (const auto& row : publication.index)
        index_by_page[row.page_index] = &row;
    std::map<packed_page_type_t, std::vector<std::uint8_t>> decoded;
    for (std::size_t page_index = 0; page_index < restored.value().pages.size();
         ++page_index) {
        if (codec_stop_requested(stop_requested)) {
            return workspace_result_t<
                std::vector<std::pair<packed_page_type_t, std::vector<std::uint8_t>>>>::failure(
                    codec_cancelled_error(
                        "packed_page_codec.decode_multi_domain_publication"));
        }
        const auto* index = index_by_page[page_index];
        const auto& page = restored.value().pages[page_index];
        if (!index || index->domain != page.header.page_type) {
            return workspace_result_t<
                std::vector<std::pair<packed_page_type_t, std::vector<std::uint8_t>>>>::failure(
                    make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "packed page is not reachable through the warm-open index",
                        "packed_page_codec.decode_multi_domain_publication"));
        }
        auto& output = decoded[static_cast<packed_page_type_t>(index->domain)];
        std::uint64_t updated_size = 0;
        if (!checked_add_u64(output.size(), page.payload.size(), updated_size) ||
            updated_size > packed_generation_max_payload_bytes ||
            updated_size > static_cast<std::uint64_t>(
                (std::numeric_limits<std::size_t>::max)())) {
            return workspace_result_t<
                std::vector<std::pair<packed_page_type_t, std::vector<std::uint8_t>>>>::failure(
                    make_workspace_error(
                        workspace_error_code_t::limit_exceeded,
                        "decoded packed domain exceeds its bounded limit",
                        "packed_page_codec.decode_multi_domain_publication"));
        }
        output.reserve(static_cast<std::size_t>(updated_size));
        for (std::size_t offset = 0; offset < page.payload.size();) {
            if (codec_stop_requested(stop_requested)) {
                return workspace_result_t<
                    std::vector<std::pair<packed_page_type_t, std::vector<std::uint8_t>>>>::failure(
                        codec_cancelled_error(
                            "packed_page_codec.decode_multi_domain_publication"));
            }
            const auto end = (std::min)(page.payload.size(),
                                        offset + kCancellationStride);
            output.insert(output.end(), page.payload.data() + offset,
                          page.payload.data() + end);
            offset = end;
        }
    }
    std::vector<std::pair<packed_page_type_t, std::vector<std::uint8_t>>> output;
    output.reserve(decoded.size());
    for (auto& entry : decoded)
        output.emplace_back(entry.first, std::move(entry.second));
    return workspace_result_t<
        std::vector<std::pair<packed_page_type_t, std::vector<std::uint8_t>>>>::success(
            std::move(output));
}

fixed_width_address_t fixed_width_address_t::encode(const address_t& address) noexcept {
    fixed_width_address_t result;
    result.bytes[0] = static_cast<std::uint8_t>(address.space);
    result.bytes[1] = static_cast<std::uint8_t>(address.architecture);
    result.bytes[2] = static_cast<std::uint8_t>(address.mode);
    for (unsigned shift = 0; shift < 64; shift += 8)
        result.bytes[8 + shift / 8] = static_cast<std::uint8_t>(address.value >> shift);
    return result;
}

address_t fixed_width_address_t::decode() const noexcept {
    address_t address;
    address.space = static_cast<address_space_id_t>(bytes[0]);
    address.architecture = static_cast<architecture_id_t>(bytes[1]);
    address.mode = static_cast<architecture_mode_t>(bytes[2]);
    address.value = read_u64_le(bytes.data() + 8);
    return address;
}

std::string fixed_width_address_t::hex() const {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.resize(bytes.size() * 2);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        result[index * 2] = digits[bytes[index] >> 4];
        result[index * 2 + 1] = digits[bytes[index] & 0x0fU];
    }
    return result;
}

std::optional<fixed_width_address_t> fixed_width_address_t::from_hex(
    const std::string& text) noexcept {
    if (text.size() != bytes.size() * 2)
        return std::nullopt;
    fixed_width_address_t result;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        auto hex_val = [](char c) -> std::optional<std::uint8_t> {
            if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
            return std::nullopt;
        };
        auto hi = hex_val(text[index * 2]);
        auto lo = hex_val(text[index * 2 + 1]);
        if (!hi || !lo)
            return std::nullopt;
        result.bytes[index] = static_cast<std::uint8_t>((*hi << 4) | *lo);
    }
    return result;
}

}
