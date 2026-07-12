#include "container_stream_harness.hpp"

#include "../../src/core/analysis/container/streaming_member_provider.hpp"
#include "../../src/core/analysis/mapped_window_cache.hpp"
#include "../../src/core/analysis/workspace/zip_container.hpp"

#include <zlib.h>
#include <zstd.h>
#include <lzma.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace aida::analysis::c03 {
namespace {

enum class fixture_compression : std::uint8_t {
    none = 0,
    deflate = 1,
    zstd = 2,
    lzma = 3
};

struct zip_fixture_member_t final {
    std::string path;
    std::vector<std::uint8_t> bytes;
    fixture_compression compression = fixture_compression::none;
};

struct deflate_ender_t final {
    void operator()(z_stream* value) const noexcept {
        if (value)
            deflateEnd(value);
    }
};

template <typename value_t>
value_t require_value(workspace_result_t<value_t> result, const char* message) {
    if (!result)
        throw std::runtime_error(std::string(message) + ":" + result.error().stable_code());
    return result.take_value();
}

void require(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(message);
}

template <typename value_t>
void require_error(workspace_result_t<value_t> result, workspace_error_code_t code,
                   const char* message) {
    if (result || result.error().code != code)
        throw std::runtime_error(message);
}

void append_u16(std::vector<std::uint8_t>& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
}

void append_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    for (std::uint32_t shift = 0; shift != 32; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (std::uint32_t shift = 0; shift != 64; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

std::uint32_t crc_of(const std::vector<std::uint8_t>& bytes) {
    uLong crc = crc32(0L, Z_NULL, 0);
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto amount = static_cast<uInt>((std::min)(
            bytes.size() - offset, static_cast<std::size_t>((std::numeric_limits<uInt>::max)())));
        crc = crc32(crc, reinterpret_cast<const Bytef*>(bytes.data() + offset), amount);
        offset += amount;
    }
    return static_cast<std::uint32_t>(crc);
}

std::vector<std::uint8_t> raw_deflate(const std::vector<std::uint8_t>& bytes) {
    z_stream stream{};
    if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK)
        throw std::runtime_error("raw deflate initialization failed");
    const std::unique_ptr<z_stream, deflate_ender_t> cleanup(&stream);
    stream.next_in = bytes.empty() ? nullptr : const_cast<Bytef*>(
        reinterpret_cast<const Bytef*>(bytes.data()));
    stream.avail_in = static_cast<uInt>(bytes.size());
    std::vector<std::uint8_t> output;
    std::array<std::uint8_t, 16384> chunk{};
    for (;;) {
        stream.next_out = reinterpret_cast<Bytef*>(chunk.data());
        stream.avail_out = static_cast<uInt>(chunk.size());
        const int status = deflate(&stream, Z_FINISH);
        if (status != Z_OK && status != Z_STREAM_END)
            throw std::runtime_error("raw deflate failed");
        output.insert(output.end(), chunk.begin(), chunk.begin() + (chunk.size() - stream.avail_out));
        if (status == Z_STREAM_END)
            break;
    }
    return output;
}

std::vector<std::uint8_t> zstd_compress(const std::vector<std::uint8_t>& bytes) {
    const size_t bound = ZSTD_compressBound(bytes.size());
    if (ZSTD_isError(bound))
        throw std::runtime_error("zstd compressBound failed");
    std::vector<std::uint8_t> output(bound);
    const size_t actual = ZSTD_compress(
        output.data(), bound,
        bytes.empty() ? nullptr : bytes.data(), bytes.size(), 3);
    if (ZSTD_isError(actual))
        throw std::runtime_error("zstd compress failed");
    output.resize(actual);
    return output;
}

std::vector<std::uint8_t> lzma_compress(const std::vector<std::uint8_t>& bytes) {
    lzma_options_lzma opt;
    if (lzma_lzma_preset(&opt, LZMA_PRESET_DEFAULT))
        throw std::runtime_error("lzma preset failed");
    lzma_filter filters[2];
    filters[0].id = LZMA_FILTER_LZMA1;
    filters[0].options = &opt;
    filters[1].id = LZMA_VLI_UNKNOWN;
    filters[1].options = nullptr;
    uint32_t prop_size = 0;
    if (lzma_properties_size(&prop_size, &filters[0]) != LZMA_OK)
        throw std::runtime_error("lzma properties_size failed");
    std::vector<std::uint8_t> props(prop_size);
    if (lzma_properties_encode(&filters[0], props.data()) != LZMA_OK)
        throw std::runtime_error("lzma properties_encode failed");
    lzma_stream strm = LZMA_STREAM_INIT;
    if (lzma_raw_encoder(&strm, filters) != LZMA_OK)
        throw std::runtime_error("lzma raw encoder init failed");
    std::vector<std::uint8_t> compressed;
    std::array<std::uint8_t, 16384> chunk{};
    strm.next_in = bytes.empty() ? nullptr : const_cast<uint8_t*>(bytes.data());
    strm.avail_in = bytes.size();
    for (;;) {
        strm.next_out = chunk.data();
        strm.avail_out = chunk.size();
        const lzma_ret status = lzma_code(&strm, LZMA_FINISH);
        const size_t produced = chunk.size() - strm.avail_out;
        compressed.insert(compressed.end(), chunk.begin(), chunk.begin() + produced);
        if (status == LZMA_STREAM_END)
            break;
        if (status != LZMA_OK)
            throw std::runtime_error("lzma encode failed");
    }
    lzma_end(&strm);
    std::vector<std::uint8_t> output;
    output.reserve(4 + props.size() + compressed.size());
    output.push_back(static_cast<std::uint8_t>(0x00));
    output.push_back(static_cast<std::uint8_t>(0x03));
    output.push_back(static_cast<std::uint8_t>(prop_size & 0xff));
    output.push_back(static_cast<std::uint8_t>((prop_size >> 8) & 0xff));
    output.insert(output.end(), props.begin(), props.end());
    output.insert(output.end(), compressed.begin(), compressed.end());
    return output;
}

std::vector<std::uint8_t> build_zip(const std::vector<zip_fixture_member_t>& members,
                                    bool zip64 = false) {
    struct record_t final {
        std::string path;
        std::vector<std::uint8_t> compressed;
        std::uint32_t crc = 0;
        std::uint64_t local_offset = 0;
        std::uint64_t uncompressed_size = 0;
        std::uint16_t method = 0;
    };
    std::vector<std::uint8_t> output;
    std::vector<record_t> records;
    records.reserve(members.size());
    for (const auto& member : members) {
        record_t record;
        record.path = member.path;
        switch (member.compression) {
        case fixture_compression::none:
            record.compressed = member.bytes;
            record.method = 0U;
            break;
        case fixture_compression::deflate:
            record.compressed = raw_deflate(member.bytes);
            record.method = 8U;
            break;
        case fixture_compression::zstd:
            record.compressed = zstd_compress(member.bytes);
            record.method = 93U;
            break;
        case fixture_compression::lzma:
            record.compressed = lzma_compress(member.bytes);
            record.method = 14U;
            break;
        }
        record.crc = crc_of(member.bytes);
        record.local_offset = output.size();
        record.uncompressed_size = member.bytes.size();
        const std::uint16_t extra_size = zip64 ? 20U : 0U;
        append_u32(output, 0x04034b50U);
        append_u16(output, zip64 ? 45U : 20U);
        append_u16(output, 0);
        append_u16(output, record.method);
        append_u16(output, 0);
        append_u16(output, 0);
        append_u32(output, record.crc);
        append_u32(output, zip64 ? 0xffffffffU : static_cast<std::uint32_t>(record.compressed.size()));
        append_u32(output, zip64 ? 0xffffffffU : static_cast<std::uint32_t>(record.uncompressed_size));
        append_u16(output, static_cast<std::uint16_t>(record.path.size()));
        append_u16(output, extra_size);
        output.insert(output.end(), record.path.begin(), record.path.end());
        if (zip64) {
            append_u16(output, 1U);
            append_u16(output, 16U);
            append_u64(output, record.uncompressed_size);
            append_u64(output, record.compressed.size());
        }
        output.insert(output.end(), record.compressed.begin(), record.compressed.end());
        records.push_back(std::move(record));
    }
    const std::uint64_t central_offset = output.size();
    for (const auto& record : records) {
        const std::uint16_t extra_size = zip64 ? 28U : 0U;
        append_u32(output, 0x02014b50U);
        append_u16(output, zip64 ? 45U : 20U);
        append_u16(output, zip64 ? 45U : 20U);
        append_u16(output, 0);
        append_u16(output, record.method);
        append_u16(output, 0);
        append_u16(output, 0);
        append_u32(output, record.crc);
        append_u32(output, zip64 ? 0xffffffffU : static_cast<std::uint32_t>(record.compressed.size()));
        append_u32(output, zip64 ? 0xffffffffU : static_cast<std::uint32_t>(record.uncompressed_size));
        append_u16(output, static_cast<std::uint16_t>(record.path.size()));
        append_u16(output, extra_size);
        append_u16(output, 0);
        append_u16(output, 0);
        append_u16(output, 0);
        append_u32(output, 0);
        append_u32(output, zip64 ? 0xffffffffU : static_cast<std::uint32_t>(record.local_offset));
        output.insert(output.end(), record.path.begin(), record.path.end());
        if (zip64) {
            append_u16(output, 1U);
            append_u16(output, 24U);
            append_u64(output, record.uncompressed_size);
            append_u64(output, record.compressed.size());
            append_u64(output, record.local_offset);
        }
    }
    const std::uint64_t central_size = output.size() - central_offset;
    if (zip64) {
        const std::uint64_t zip64_eocd_offset = output.size();
        append_u32(output, 0x06064b50U);
        append_u64(output, 44U);
        append_u16(output, 45U);
        append_u16(output, 45U);
        append_u32(output, 0);
        append_u32(output, 0);
        append_u64(output, records.size());
        append_u64(output, records.size());
        append_u64(output, central_size);
        append_u64(output, central_offset);
        append_u32(output, 0x07064b50U);
        append_u32(output, 0);
        append_u64(output, zip64_eocd_offset);
        append_u32(output, 1U);
    }
    append_u32(output, 0x06054b50U);
    append_u16(output, 0);
    append_u16(output, 0);
    append_u16(output, zip64 ? 0xffffU : static_cast<std::uint16_t>(records.size()));
    append_u16(output, zip64 ? 0xffffU : static_cast<std::uint16_t>(records.size()));
    append_u32(output, zip64 ? 0xffffffffU : static_cast<std::uint32_t>(central_size));
    append_u32(output, zip64 ? 0xffffffffU : static_cast<std::uint32_t>(central_offset));
    append_u16(output, 0);
    return output;
}

void write_fixture(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output)
        throw std::runtime_error("fixture file open failed");
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!output)
        throw std::runtime_error("fixture file write failed");
}

std::shared_ptr<mapped_window_cache_t> open_fixture(const std::filesystem::path& path) {
    mapped_window_cache_options_t options;
    options.immutable_source = true;
    return require_value(mapped_window_cache_t::open(path.u8string(), options),
                         "fixture provider open failed");
}

std::shared_ptr<zip_container_t> open_zip(const std::filesystem::path& path,
                                          zip_container_limits_t limits = {}) {
    auto source = open_fixture(path);
    return require_value(zip_container_t::open(source, limits), "ZIP fixture open failed");
}

void verify_streaming_paths(const std::filesystem::path& root) {
    std::vector<std::uint8_t> large_stored(65ULL * 1024ULL * 1024ULL + 37ULL);
    for (std::size_t index = 0; index < large_stored.size(); ++index)
        large_stored[index] = static_cast<std::uint8_t>((index * 29U + 11U) & 0xffU);
    std::vector<std::uint8_t> deflated(65536, 0x5aU);
    const auto archive_bytes = build_zip({
        {"classes.dex", large_stored, fixture_compression::none},
        {"base/dex/classes2.dex", deflated, fixture_compression::deflate},
        {"Payload/App.app/App", {0xcf, 0xfa, 0xed, 0xfe}, fixture_compression::none},
        {"com/example/Main.class", {0xca, 0xfe, 0xba, 0xbe}, fixture_compression::deflate},
    });
    const auto path = root / "streaming.zip";
    write_fixture(path, archive_bytes);
    auto zip = open_zip(path);
    auto stored = require_value(zip->open_member_provider("classes.dex"),
                                "stored member open failed");
    auto stored_stream = std::dynamic_pointer_cast<streaming_member_provider_t>(stored);
    require(stored_stream && stored_stream->is_subrange_backed() &&
            !stored_stream->is_spill_backed(),
            "stored member was not retained as a zero-copy subrange");
    require(stored->identity().content_sha256.has_value(),
            "stored member has no streamed SHA-256 identity");
    std::array<std::uint8_t, 4> first{};
    std::array<std::uint8_t, 4> last{};
    require_value(stored->read_exact(0, first.data(), first.size()), "stored prefix read failed");
    require_value(stored->read_exact(stored->size() - last.size(), last.data(), last.size()),
                  "stored suffix read failed");
    require(std::equal(first.begin(), first.end(), large_stored.begin()) &&
            std::equal(last.begin(), last.end(), large_stored.end() - last.size()),
            "stored subrange bytes diverged");
    auto deflated_provider = require_value(zip->open_member_provider("base/dex/classes2.dex"),
                                           "deflated member open failed");
    auto deflated_stream = std::dynamic_pointer_cast<streaming_member_provider_t>(deflated_provider);
    require(deflated_stream && deflated_stream->is_spill_backed() &&
            !deflated_stream->is_subrange_backed(),
            "deflated member was not materialized through spill storage");
    auto deflated_bytes = require_value(deflated_provider->read_vector(
        0, deflated_provider->size(), deflated_provider->size()), "deflated readback failed");
    require(deflated_bytes == deflated, "deflated stream bytes diverged");
    require_value(zip->open_member_provider("Payload/App.app/App"), "IPA executable member open failed");
    require_value(zip->open_member_provider("com/example/Main.class"), "JAR class member open failed");
    require(zip->integrity_verified(), "streaming ZIP integrity state was not retained");
}

void verify_zip64_and_rejections(const std::filesystem::path& root) {
    const auto zip64_path = root / "zip64.zip";
    write_fixture(zip64_path, build_zip({{"classes.dex", {1, 2, 3, 4}, fixture_compression::none}}, true));
    auto zip64 = open_zip(zip64_path);
    require(zip64->uses_zip64(), "ZIP64 archive was not recognized");
    require_value(zip64->open_member_provider("classes.dex"), "ZIP64 member open failed");

    auto truncated = build_zip({{"classes.dex", {1, 2, 3}, fixture_compression::none}});
    truncated.pop_back();
    const auto truncated_path = root / "truncated.zip";
    write_fixture(truncated_path, truncated);
    require(!zip_container_t::open(open_fixture(truncated_path)), "truncated ZIP was accepted");

    const auto duplicate_path = root / "duplicate.zip";
    write_fixture(duplicate_path, build_zip({
        {"classes.dex", {1}, fixture_compression::none}, {"classes.dex", {2}, fixture_compression::none}}));
    require(!zip_container_t::open(open_fixture(duplicate_path)), "duplicate ZIP path was accepted");

    const auto traversal_path = root / "traversal.zip";
    write_fixture(traversal_path, build_zip({{"../classes.dex", {1}, fixture_compression::none}}));
    require(!zip_container_t::open(open_fixture(traversal_path)), "traversal ZIP path was accepted");

    std::vector<std::uint8_t> bomb_bytes(262144, 0);
    const auto bomb_path = root / "bomb.zip";
    write_fixture(bomb_path, build_zip({{"classes.dex", bomb_bytes, fixture_compression::deflate}}));
    zip_container_limits_t bomb_limits;
    bomb_limits.max_expansion_ratio = 4;
    require(!zip_container_t::open(open_fixture(bomb_path), bomb_limits),
            "expansion-ratio ZIP bomb was accepted");
}

void verify_crc_hash_nesting_and_cancellation(const std::filesystem::path& root) {
    auto bad_crc = build_zip({{"classes.dex", {1, 2, 3, 4}, fixture_compression::none}});
    const std::uint32_t incorrect_crc = 0x7f3a2c19U;
    const std::array<std::uint8_t, 4> crc_bytes{{
        static_cast<std::uint8_t>(incorrect_crc),
        static_cast<std::uint8_t>(incorrect_crc >> 8U),
        static_cast<std::uint8_t>(incorrect_crc >> 16U),
        static_cast<std::uint8_t>(incorrect_crc >> 24U)}};
    std::copy(crc_bytes.begin(), crc_bytes.end(), bad_crc.begin() + 14);
    const std::array<std::uint8_t, 4> central_signature{{0x50, 0x4b, 0x01, 0x02}};
    const auto central = std::search(bad_crc.begin(), bad_crc.end(),
                                     central_signature.begin(), central_signature.end());
    require(central != bad_crc.end(), "central directory fixture marker was missing");
    std::copy(crc_bytes.begin(), crc_bytes.end(), central + 16);
    const auto bad_crc_path = root / "bad-crc.zip";
    write_fixture(bad_crc_path, bad_crc);
    auto bad_crc_zip = open_zip(bad_crc_path);
    require_error(bad_crc_zip->open_member_provider("classes.dex"),
                  workspace_error_code_t::integrity_failure,
                  "bad ZIP CRC was accepted");

    const auto hash_path = root / "bad-hash.bin";
    const std::vector<std::uint8_t> hash_bytes{9, 8, 7, 6};
    write_fixture(hash_path, hash_bytes);
    container_stream_member_request_t hash_request;
    hash_request.source = open_fixture(hash_path);
    hash_request.normalized_path = "classes.dex";
    hash_request.provenance = {"classes.dex", 0, hash_bytes.size(), hash_bytes.size(), 0, 1,
                               crc_of(hash_bytes), false};
    hash_request.compressed_size = hash_bytes.size();
    hash_request.uncompressed_size = hash_bytes.size();
    hash_request.crc32 = crc_of(hash_bytes);
    hash_request.expected_content_sha256 = sha256_digest_t{};
    require_error(streaming_member_provider_t::open(std::move(hash_request)),
                  workspace_error_code_t::integrity_failure,
                  "incorrect member SHA-256 was accepted");

    const auto nested_bytes = build_zip({{"Inner.class", {0xca, 0xfe, 0xba, 0xbe}, fixture_compression::none}});
    const auto nested_path = root / "nested.zip";
    write_fixture(nested_path, build_zip({{"nested.jar", nested_bytes, fixture_compression::none}}));
    zip_container_limits_t nested_limits;
    nested_limits.max_nesting_depth = 1;
    auto outer = open_zip(nested_path, nested_limits);
    auto inner_source = require_value(outer->open_member_provider("nested.jar"),
                                      "nested container provider open failed");
    require_error(zip_container_t::open(inner_source, nested_limits),
                  workspace_error_code_t::limit_exceeded,
                  "nested ZIP depth limit was accepted");

    const auto cancellation_path = root / "cancellation.zip";
    write_fixture(cancellation_path, build_zip({{"classes.dex", {1, 2, 3, 4}, fixture_compression::deflate}}));
    auto cancelled_zip = open_zip(cancellation_path);
    cancellation_source_t cancellation;
    cancellation.request_cancel();
    require_error(cancelled_zip->open_member_provider("classes.dex", cancellation.token()),
                  workspace_error_code_t::cancelled,
                   "cancelled member stream was accepted");
}

void verify_zstd_and_lzma_streaming(const std::filesystem::path& root) {
    std::vector<std::uint8_t> zstd_payload(65536, 0x5aU);
    for (std::size_t i = 0; i < zstd_payload.size(); ++i)
        zstd_payload[i] = static_cast<std::uint8_t>((i * 37U + 7U) & 0xffU);
    std::vector<std::uint8_t> lzma_payload(32768);
    for (std::size_t i = 0; i < lzma_payload.size(); ++i)
        lzma_payload[i] = static_cast<std::uint8_t>((i * 53U + 31U) & 0xffU);
    const auto archive_bytes = build_zip({
        {"zstd/data.bin", zstd_payload, fixture_compression::zstd},
        {"lzmd/data.bin", lzma_payload, fixture_compression::lzma},
        {"stored/raw.bin", {0x00, 0x01, 0x02, 0x03}, fixture_compression::none},
    });
    const auto path = root / "zstd-lzma.zip";
    write_fixture(path, archive_bytes);
    auto zip = open_zip(path);
    auto zstd_provider = require_value(zip->open_member_provider("zstd/data.bin"),
                                       "zstd member open failed");
    auto zstd_stream = std::dynamic_pointer_cast<streaming_member_provider_t>(zstd_provider);
    require(zstd_stream && zstd_stream->is_spill_backed() &&
            !zstd_stream->is_subrange_backed(),
            "zstd member was not materialized through spill storage");
    auto zstd_bytes = require_value(zstd_provider->read_vector(
        0, zstd_provider->size(), zstd_provider->size()), "zstd readback failed");
    require(zstd_bytes == zstd_payload, "zstd stream bytes diverged");
    require(zstd_provider->identity().content_sha256.has_value(),
            "zstd member has no streamed SHA-256 identity");
    auto lzma_provider = require_value(zip->open_member_provider("lzmd/data.bin"),
                                       "LZMA member open failed");
    auto lzma_stream = std::dynamic_pointer_cast<streaming_member_provider_t>(lzma_provider);
    require(lzma_stream && lzma_stream->is_spill_backed() &&
            !lzma_stream->is_subrange_backed(),
            "LZMA member was not materialized through spill storage");
    auto lzma_bytes = require_value(lzma_provider->read_vector(
        0, lzma_provider->size(), lzma_provider->size()), "LZMA readback failed");
    require(lzma_bytes == lzma_payload, "LZMA stream bytes diverged");
    require(lzma_provider->identity().content_sha256.has_value(),
            "LZMA member has no streamed SHA-256 identity");
    require_value(zip->open_member_provider("stored/raw.bin"),
                  "stored member alongside zstd/lzma open failed");
    require(zip->integrity_verified(),
            "zstd/lzma streaming ZIP integrity state was not retained");
    auto bad_zstd_crc = build_zip({
        {"zstd/data.bin", zstd_payload, fixture_compression::zstd},
        {"lzmd/data.bin", lzma_payload, fixture_compression::lzma},
    });
    const std::uint32_t incorrect_crc = 0x7f3a2c19U;
    const std::array<std::uint8_t, 4> crc_bytes{{
        static_cast<std::uint8_t>(incorrect_crc),
        static_cast<std::uint8_t>(incorrect_crc >> 8U),
        static_cast<std::uint8_t>(incorrect_crc >> 16U),
        static_cast<std::uint8_t>(incorrect_crc >> 24U)}};
    std::copy(crc_bytes.begin(), crc_bytes.end(), bad_zstd_crc.begin() + 14);
    const std::array<std::uint8_t, 4> central_signature{{0x50, 0x4b, 0x01, 0x02}};
    const auto central = std::search(bad_zstd_crc.begin(), bad_zstd_crc.end(),
                                     central_signature.begin(), central_signature.end());
    require(central != bad_zstd_crc.end(), "zstd CRC fixture central marker was missing");
    std::copy(crc_bytes.begin(), crc_bytes.end(), central + 16);
    const auto bad_zstd_path = root / "bad-zstd-crc.zip";
    write_fixture(bad_zstd_path, bad_zstd_crc);
    auto bad_zstd_zip = open_zip(bad_zstd_path);
    require_error(bad_zstd_zip->open_member_provider("zstd/data.bin"),
                  workspace_error_code_t::integrity_failure,
                  "bad zstd CRC was accepted");
}

}

void run_container_stream_harness(const std::filesystem::path& root) {
    std::filesystem::create_directories(root);
    try {
        verify_streaming_paths(root);
        verify_zip64_and_rejections(root);
        verify_crc_hash_nesting_and_cancellation(root);
        verify_zstd_and_lzma_streaming(root);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

}

int main() {
    std::filesystem::path root;
    std::error_code ignored;
    try {
        root = std::filesystem::temp_directory_path() / "aida-c03-container-stream";
        std::filesystem::remove_all(root, ignored);
        aida::analysis::c03::run_container_stream_harness(root);
        std::cout << "container_stream_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        std::filesystem::remove_all(root, ignored);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
