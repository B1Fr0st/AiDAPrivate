#pragma once

#include "../workspace/byte_provider.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace aida::analysis {

enum class container_stream_codec_t : std::uint8_t {
    stored = 0,
    raw_deflate = 1,
    zstd = 2,
    lzma = 3
};

struct container_stream_limits_t final {
    std::uint64_t max_compressed_size = 2ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_uncompressed_size = 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_expansion_ratio = 1000;
    std::uint64_t max_spill_bytes = 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_work_bytes = 16ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_io_chunk_size = 1024ULL * 1024ULL;
    std::uint64_t cancellation_poll_bytes = 64ULL * 1024ULL;
    std::chrono::milliseconds max_elapsed{60000};
};

struct container_stream_member_request_t final {
    std::shared_ptr<const byte_provider_t> source;
    std::string normalized_path;
    provider_member_metadata_t provenance;
    std::uint64_t data_offset = 0;
    std::uint64_t compressed_size = 0;
    std::uint64_t uncompressed_size = 0;
    std::uint32_t crc32 = 0;
    container_stream_codec_t codec = container_stream_codec_t::stored;
    std::optional<sha256_digest_t> expected_content_sha256;
};

using container_stream_charge_t = std::function<workspace_result_t<void>(std::uint64_t)>;

class streaming_member_provider_t final : public byte_provider_t {
public:
    static workspace_result_t<std::shared_ptr<streaming_member_provider_t>>
        open(container_stream_member_request_t request,
             container_stream_limits_t limits = {},
             const cancellation_token_t& cancel = {},
             container_stream_charge_t additional_charge = {});

    const byte_provider_identity_t& identity() const noexcept override;
    std::uint64_t size() const noexcept override;
    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override;
    workspace_result_t<byte_view_t> lease(std::uint64_t offset, std::uint64_t size,
                                          const cancellation_token_t& cancel = {}) const override;

    bool is_subrange_backed() const noexcept;
    bool is_spill_backed() const noexcept;

private:
    streaming_member_provider_t(std::shared_ptr<const byte_provider_t> source,
                                std::shared_ptr<byte_provider_t> backing,
                                byte_provider_identity_t identity,
                                bool subrange_backed);

    std::shared_ptr<const byte_provider_t> source_;
    std::shared_ptr<byte_provider_t> backing_;
    byte_provider_identity_t identity_;
    bool subrange_backed_ = false;
};

}
