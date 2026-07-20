#pragma once

#include "compact_ir.hpp"
#include "workspace_types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace aida::analysis {

inline constexpr std::uint32_t workspace_schema_v9_version = 9;
inline constexpr std::uint32_t packed_page_magic = 0x5041434BU;
inline constexpr std::uint32_t packed_page_blob_version = 2;
inline constexpr std::uint32_t packed_page_header_size = 64;
inline constexpr std::uint32_t packed_page_max_payload = 1U << 20;
inline constexpr std::uint64_t packed_generation_max_payload_bytes = 16ULL << 30;
inline constexpr std::uint64_t packed_generation_default_quota_bytes = 8ULL << 30;
inline constexpr std::uint64_t packed_generation_max_records = 200000000ULL;
inline constexpr std::uint32_t packed_generation_max_pages = 131072;
inline constexpr std::uint32_t packed_generation_max_index_rows = 131072;
inline constexpr std::uint64_t packed_generation_max_metadata_bytes = 16ULL << 20;
inline constexpr std::uint32_t packed_page_checkpoint_type = 0xFFFFFFFFU;
inline constexpr std::uint32_t packed_page_default_size = 4096;
inline constexpr std::uint32_t packed_record_page_magic = 0x58495052U;
inline constexpr std::uint16_t packed_record_page_version = 1;
inline constexpr std::uint32_t packed_record_page_prefix_size = 32;
inline constexpr std::uint32_t decompiler_cache_v9_key_version = 1;
inline constexpr std::uint32_t fixed_width_address_size = 16;
inline constexpr std::uint64_t workbench_state_max_payload_bytes = 16ULL << 20;
inline constexpr std::uint32_t managed_publication_domain_magic = 0x504d4941U;
inline constexpr std::uint16_t managed_publication_domain_version = 1;
inline constexpr std::uint64_t managed_publication_max_payload_bytes = 512ULL << 20;
inline constexpr std::uint64_t managed_publication_max_string_bytes = 256ULL << 20;
inline constexpr std::uint32_t managed_publication_max_artifacts = 65536;
inline constexpr std::uint32_t managed_publication_max_methods = 1U << 24;
inline constexpr std::uint32_t managed_publication_max_strings = 1U << 25;
inline constexpr std::uint32_t managed_publication_max_single_string_bytes = 16U << 20;

enum class packed_page_type_t : std::uint32_t {
    instructions = 1,
    operands = 2,
    target_facts = 3,
    edges = 4,
    strings = 5,
    symbols = 6,
    address_expressions = 7,
    basic_blocks = 8,
    functions = 9,
    function_chunks = 10,
    xrefs = 11,
    coverage = 12,
    search_index = 13,
    call_graph = 14,
    pointer_facts = 15,
    type_references = 16,
    metadata_conflicts = 17,
    symbol_type_candidates = 18,
    managed_publication = 19,
    checkpoint = 0xFFFFFFFFU
};

inline constexpr auto packed_page_baseline_last_data_type =
    packed_page_type_t::symbol_type_candidates;
inline constexpr auto packed_page_last_data_type =
    packed_page_type_t::managed_publication;

struct packed_generation_record_t {
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::uint16_t shard_count = 0;
    std::uint64_t total_payload_bytes = 0;
    std::uint64_t total_records = 0;
    std::uint32_t batch_checksum = 0;
    std::uint64_t created_utc_ms = 0;
    bool committed = false;
    std::vector<std::uint8_t> payload_blob;
};

struct packed_page_row_t {
    std::uint64_t generation = 0;
    std::uint32_t page_index = 0;
    std::uint32_t page_count = 0;
    std::uint32_t page_type = 0;
    std::uint32_t payload_length = 0;
    std::uint32_t checksum = 0;
    std::vector<std::uint8_t> payload;
};

struct packed_page_index_row_t {
    std::uint64_t generation = 0;
    std::uint16_t domain = 0;
    std::uint32_t ordinal_begin = 0;
    std::uint32_t count = 0;
    std::uint32_t page_index = 0;
    std::uint64_t address_value_min = 0;
    std::uint64_t address_value_max = 0;
};

struct packed_record_page_prefix_t {
    std::uint32_t magic = packed_record_page_magic;
    std::uint16_t version = packed_record_page_version;
    std::uint16_t flags = 0;
    std::uint32_t ordinal_begin = 0;
    std::uint32_t record_count = 0;
    std::uint64_t address_value_min = 0;
    std::uint64_t address_value_max = 0;

    std::array<std::uint8_t, packed_record_page_prefix_size> encode() const noexcept;
    static std::optional<packed_record_page_prefix_t> decode(
        const std::uint8_t* data, std::size_t size) noexcept;
};

static_assert(sizeof(packed_record_page_prefix_t) == packed_record_page_prefix_size);

struct packed_generation_publication_t {
    packed_generation_record_t generation;
    std::vector<packed_page_row_t> pages;
    std::vector<packed_page_index_row_t> index;
};

using packed_stop_predicate_t = std::function<bool()>;
using packed_publish_stop_predicate_t = packed_stop_predicate_t;
using packed_page_stream_sink_t = std::function<workspace_result_t<void>(
    packed_page_row_t, packed_page_index_row_t)>;
using packed_page_stream_producer_t = std::function<workspace_result_t<void>(
    const packed_page_stream_sink_t&, const packed_publish_stop_predicate_t&)>;

struct packed_generation_stream_descriptor_t {
    packed_generation_record_t generation;
    std::uint32_t page_count = 0;
    std::uint64_t payload_quota_bytes = packed_generation_default_quota_bytes;
};

struct workbench_state_record_t {
    std::uint64_t workspace_id = 0;
    std::uint32_t contract_schema_version = 0;
    std::uint64_t revision = 0;
    std::uint64_t fingerprint = 0;
    std::string payload_json;
    std::uint64_t updated_utc_ms = 0;
};

struct decompiler_cache_v9_record_t {
    std::string cache_key;
    binary_id_t binary_id;
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t architecture_mode = architecture_mode_t::unknown;
    abi_id_t abi = abi_id_t::unknown;
    endian_t endian = endian_t::little;
    std::string engine_version;
    std::uint32_t schema_version = workspace_schema_v9_version;
    std::string specification_version;
    std::string settings_hash;
    entity_id_t function_id = 0;
    std::uint64_t function_rva = 0;
    address_t function_rva_address;
    sha256_digest_t function_content_hash;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::uint64_t generation = 0;
    std::string function_name;
    std::string result_json;
    std::uint64_t created_utc_ms = 0;
    std::uint64_t last_access_utc_ms = 0;
    std::uint64_t result_bytes = 0;
    std::uint32_t cache_key_version = decompiler_cache_v9_key_version;
};

struct overlay_v9_state_record_t {
    std::array<std::uint8_t, 32> target_image_hash{};
    std::array<std::uint8_t, 32> target_provenance_hash{};
    std::uint64_t target_image_base = 0;
    std::uint64_t target_image_size = 0;
    std::uint64_t target_generation = 0;
    std::uint8_t target_kind = 0;
    std::uint8_t target_architecture = 0;
    std::uint8_t target_address_width = 0;
    std::uint64_t revision = 0;
    std::uint64_t next_transaction_id = 1;
    std::uint64_t history_cursor = 0;
    std::uint64_t history_epoch = 1;
    std::uint64_t updated_utc_ms = 0;
};

struct fixed_width_address_t {
    std::array<std::uint8_t, fixed_width_address_size> bytes{};

    static fixed_width_address_t encode(const address_t& address) noexcept;
    address_t decode() const noexcept;
    std::string hex() const;
    static std::optional<fixed_width_address_t> from_hex(const std::string& text) noexcept;
};

workspace_result_t<void> create_schema_v9(sqlite3* database);
workspace_result_t<void> ensure_managed_overlay_identity_schema_v9(
    sqlite3* database);

workspace_result_t<void> write_packed_generation(
    sqlite3* database, const packed_generation_record_t& record);

workspace_result_t<std::optional<packed_generation_record_t>>
    read_packed_generation(sqlite3* database, std::uint64_t generation,
                           bool committed_only = true,
                           const packed_stop_predicate_t& stop_requested = {});

workspace_result_t<void> write_packed_page(
    sqlite3* database, const packed_page_row_t& row);

workspace_result_t<std::vector<packed_page_row_t>>
    read_packed_pages(sqlite3* database, std::uint64_t generation,
                      bool committed_only = true,
                      const packed_stop_predicate_t& stop_requested = {});

workspace_result_t<void> write_packed_page_index(
    sqlite3* database, const packed_page_index_row_t& row);

workspace_result_t<std::vector<packed_page_index_row_t>>
    read_packed_page_index(sqlite3* database, std::uint64_t generation,
                           bool committed_only = true,
                           const packed_stop_predicate_t& stop_requested = {});

workspace_result_t<void> publish_packed_generation_atomic(
    sqlite3* database, const packed_generation_publication_t& publication,
    const packed_publish_stop_predicate_t& stop_requested = {});

workspace_result_t<void> stage_packed_generation_atomic(
    sqlite3* database, const packed_generation_publication_t& publication,
    const std::string& candidate_token,
    const packed_publish_stop_predicate_t& stop_requested = {});

workspace_result_t<void> stage_packed_generation_stream_atomic(
    sqlite3* database,
    const packed_generation_stream_descriptor_t& descriptor,
    const std::string& candidate_token,
    const packed_page_stream_producer_t& producer,
    const packed_publish_stop_predicate_t& stop_requested = {});

using packed_domain_page_visitor_t = std::function<workspace_result_t<void>(
    const packed_page_row_t&, const packed_page_index_row_t&)>;

workspace_result_t<void> visit_packed_domain_pages(
    sqlite3* database, std::uint64_t generation, packed_page_type_t domain,
    const packed_domain_page_visitor_t& visitor,
    const packed_stop_predicate_t& stop_requested = {},
    bool require_domain = true,
    bool* domain_present = nullptr);

workspace_result_t<std::optional<packed_generation_publication_t>>
    read_packed_generation_publication(sqlite3* database,
                                       std::uint64_t generation,
                                       const packed_stop_predicate_t& stop_requested = {});

workspace_result_t<void> write_workbench_state(
    sqlite3* database, const workbench_state_record_t& record);

workspace_result_t<std::optional<workbench_state_record_t>>
    read_workbench_state(sqlite3* database);

workspace_result_t<void> write_decompiler_cache_v9(
    sqlite3* database, const decompiler_cache_v9_record_t& record);

workspace_result_t<std::optional<decompiler_cache_v9_record_t>>
    read_decompiler_cache_v9(sqlite3* database, const std::string& cache_key);

workspace_result_t<void> write_overlay_v9_state(
    sqlite3* database, const overlay_v9_state_record_t& record);

workspace_result_t<std::optional<overlay_v9_state_record_t>>
    read_overlay_v9_state(sqlite3* database);

workspace_result_t<void> publish_packed_generation(
    sqlite3* database, std::uint64_t generation,
    const packed_stop_predicate_t& stop_requested = {});

workspace_result_t<void> rollback_packed_generation(
    sqlite3* database, std::uint64_t generation);

}
