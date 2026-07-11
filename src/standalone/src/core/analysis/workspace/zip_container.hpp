#pragma once

#include "byte_provider.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace aida::analysis {

enum class zip_member_kind_t : std::uint8_t {
    regular_file = 0,
    directory = 1,
    symbolic_link = 2
};

struct zip_container_limits_t {
    std::uint64_t max_archive_size = 16ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_member_count = 1000000;
    std::uint64_t max_central_directory_size = 512ULL * 1024ULL * 1024ULL;
    std::uint64_t max_member_compressed_size = 2ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_member_uncompressed_size = 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_aggregate_compressed_size = 8ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_aggregate_uncompressed_size = 4ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_expansion_ratio = 1000;
    std::uint64_t max_single_sparse_gap = 256ULL * 1024ULL * 1024ULL;
    std::uint64_t max_aggregate_sparse_size = 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_eocd_search_size = 65557;
    std::uint64_t max_zip64_eocd_size = 1024ULL * 1024ULL;
    std::uint64_t max_work_bytes = 16ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_io_chunk_size = 1024ULL * 1024ULL;
    std::uint64_t cancellation_poll_bytes = 64ULL * 1024ULL;
    std::uint32_t cancellation_poll_records = 128;
    std::uint32_t max_nesting_depth = 16;
    std::uint32_t max_path_components = 256;
    std::uint64_t max_normalized_path_size = 32768;
    std::chrono::milliseconds max_elapsed{60000};
};

struct zip_member_t {
    std::string normalized_path;
    std::uint64_t ordinal = 0;
    std::uint64_t central_directory_offset = 0;
    std::uint64_t local_header_offset = 0;
    std::uint64_t data_offset = 0;
    std::uint64_t record_end_offset = 0;
    std::uint64_t compressed_size = 0;
    std::uint64_t uncompressed_size = 0;
    std::uint32_t crc32 = 0;
    std::uint32_t external_attributes = 0;
    std::uint32_t path_component_count = 0;
    std::uint32_t archive_depth = 0;
    std::uint16_t version_needed = 0;
    std::uint16_t flags = 0;
    std::uint16_t compression_method = 0;
    zip_member_kind_t kind = zip_member_kind_t::regular_file;
    bool uses_zip64 = false;
    bool uses_data_descriptor = false;
    bool utf8_name = false;
    provider_member_metadata_t provenance;
};

class zip_container_t final {
public:
    static workspace_result_t<std::shared_ptr<zip_container_t>>
        open(std::shared_ptr<const byte_provider_t> provider,
             zip_container_limits_t limits = {},
             const cancellation_token_t& cancel = {});

    const byte_provider_identity_t& source_identity() const noexcept;
    const std::shared_ptr<const byte_provider_t>& source_provider() const noexcept;
    const zip_container_limits_t& limits() const noexcept;
    const std::vector<zip_member_t>& members() const noexcept;
    const zip_member_t* find_member(std::string_view normalized_path) const;

    bool uses_zip64() const noexcept;
    std::uint32_t archive_depth() const noexcept;
    std::uint64_t central_directory_offset() const noexcept;
    std::uint64_t central_directory_size() const noexcept;
    std::uint64_t aggregate_compressed_size() const noexcept;
    std::uint64_t aggregate_uncompressed_size() const noexcept;
    std::uint64_t aggregate_sparse_size() const noexcept;

    workspace_result_t<std::shared_ptr<byte_provider_t>>
        open_member_provider(std::size_t member_index,
                             const cancellation_token_t& cancel = {}) const;
    workspace_result_t<std::shared_ptr<byte_provider_t>>
        open_member_provider(std::string_view normalized_path,
                             const cancellation_token_t& cancel = {}) const;
    workspace_result_t<void>
        verify_integrity(const cancellation_token_t& cancel = {}) const;
    bool integrity_verified() const;

private:
    struct state_t;
    explicit zip_container_t(std::shared_ptr<state_t> state);

    std::shared_ptr<state_t> state_;
};

}
