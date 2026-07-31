#pragma once

#include "workspace_schema_v9.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis {

inline constexpr std::uint32_t packed_page_blob_version_v4 = 4;
inline constexpr std::uint32_t packed_page_codec_zstd_seeded = 2;
inline constexpr std::uint32_t packed_page_v4_max_dictionary_bytes = 64U * 1024U;
inline constexpr std::uint32_t packed_page_v4_window_log = 18;
inline constexpr std::uint32_t packed_page_v4_dictionary_length_size = 4;

struct packed_page_header_t {
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::uint32_t magic = packed_page_magic;
    std::uint32_t version = packed_page_blob_version;
    std::uint32_t page_type = 0;
    std::uint32_t page_index = 0;
    std::uint32_t page_count = 0;
    std::uint32_t payload_length = 0;
    std::uint32_t checksum = 0;
    std::array<std::uint8_t, 12> reserved{};

    static constexpr std::size_t encoded_size = packed_page_header_size;

    std::array<std::uint8_t, encoded_size> encode() const noexcept;
    static std::optional<packed_page_header_t> decode(
        const std::uint8_t* data, std::size_t size) noexcept;
};

static_assert(sizeof(packed_page_header_t) == packed_page_header_size);

struct packed_page_t {
    packed_page_header_t header;
    std::vector<std::uint8_t> payload;
};

struct packed_page_checkpoint_t {
    std::uint32_t batch_checksum = 0;
    std::uint64_t total_records = 0;
    std::uint64_t total_payload_bytes = 0;
    std::uint64_t created_utc_ms = 0;

    std::array<std::uint8_t, 28> encode() const noexcept;
    static std::optional<packed_page_checkpoint_t> decode(
        const std::uint8_t* data, std::size_t size) noexcept;
};

struct packed_page_batch_t {
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::vector<packed_page_t> pages;
    packed_page_checkpoint_t checkpoint;
};

struct packed_page_index_entry_t {
    std::uint16_t domain = 0;
    std::uint32_t page_index = 0;
    std::uint32_t ordinal_begin = 0;
    std::uint32_t count = 0;
    std::uint64_t address_value_min = 0;
    std::uint64_t address_value_max = 0;
};

struct packed_page_encode_options_t {
    std::uint32_t page_size = packed_page_default_size;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
};

std::uint32_t crc32c(const std::uint8_t* data, std::size_t size) noexcept;
workspace_result_t<std::uint32_t> crc32c_cancellable(
    const std::uint8_t* data, std::size_t size,
    const packed_stop_predicate_t& stop_requested);

class packed_page_codec_t final {
public:
    static workspace_result_t<void> seal_page(
        packed_page_t& page,
        const packed_stop_predicate_t& stop_requested = {});

    static workspace_result_t<void> seal_page_v3(
        packed_page_t& page, int compression_level,
        const packed_stop_predicate_t& stop_requested = {});

    static workspace_result_t<void> seal_page_v4(
        packed_page_t& page, int compression_level,
        const std::vector<std::uint8_t>& dictionary_seed,
        const packed_stop_predicate_t& stop_requested = {});

    static std::vector<std::uint8_t> build_v4_dictionary_seed(
        const std::vector<std::uint8_t>& decoded_previous_domain_page);

    static workspace_result_t<packed_record_page_prefix_t> record_prefix(
        const packed_page_t& page,
        const packed_stop_predicate_t& stop_requested = {});

    static workspace_result_t<std::vector<std::uint8_t>> record_payload(
        const packed_page_t& page,
        const packed_stop_predicate_t& stop_requested = {});

    static workspace_result_t<std::vector<std::uint8_t>> decode_page_content(
        const packed_page_t& page,
        const packed_stop_predicate_t& stop_requested = {});

    static workspace_result_t<packed_page_batch_t> encode_batch(
        packed_page_type_t page_type,
        const std::vector<std::uint8_t>& data,
        const packed_page_encode_options_t& options,
        const packed_stop_predicate_t& stop_requested = {});

    static workspace_result_t<std::vector<std::uint8_t>> decode_batch(
        const packed_page_batch_t& batch,
        const packed_stop_predicate_t& stop_requested = {});

    static workspace_result_t<void> verify_page(
        const packed_page_t& page,
        const packed_stop_predicate_t& stop_requested = {});

    static workspace_result_t<void> verify_batch(
        const packed_page_batch_t& batch,
        const packed_stop_predicate_t& stop_requested = {});

    static workspace_result_t<std::vector<packed_page_index_entry_t>>
        build_warm_open_index(
            const packed_page_batch_t& batch,
            const packed_stop_predicate_t& stop_requested = {});

    static workspace_result_t<packed_page_t> encode_checkpoint_page(
        std::uint64_t generation,
        std::uint64_t analysis_revision,
        std::uint64_t overlay_revision,
        const packed_page_checkpoint_t& checkpoint);

    static workspace_result_t<packed_page_checkpoint_t>
        decode_checkpoint_page(const packed_page_t& page);

    static std::vector<std::uint8_t> encode_fixed_width_address(
        const address_t& address) noexcept;

    static address_t decode_fixed_width_address(
        const std::uint8_t* data, std::size_t size) noexcept;

    static workspace_result_t<packed_page_batch_t> encode_multi_domain_batch(
        const std::vector<std::pair<packed_page_type_t, std::vector<std::uint8_t>>>& domains,
        const packed_page_encode_options_t& options,
        const packed_stop_predicate_t& stop_requested = {});

    static workspace_result_t<packed_generation_publication_t> build_publication(
        const packed_page_batch_t& batch,
        std::vector<std::uint8_t> metadata = {},
        const packed_stop_predicate_t& stop_requested = {});

    static workspace_result_t<packed_page_batch_t> restore_publication(
        const packed_generation_publication_t& publication,
        const packed_stop_predicate_t& stop_requested = {});

    static workspace_result_t<
        std::vector<std::pair<packed_page_type_t, std::vector<std::uint8_t>>>>
        decode_multi_domain_publication(
            const packed_generation_publication_t& publication,
            const packed_stop_predicate_t& stop_requested = {});
};

}
