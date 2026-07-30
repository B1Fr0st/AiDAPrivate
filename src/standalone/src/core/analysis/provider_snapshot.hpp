#pragma once

#include "workspace/byte_provider.hpp"

#include <cstdint>
#include <memory>

namespace aida::analysis {

struct provider_snapshot_options_t final {
    std::uint64_t max_materialized_bytes = 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t copy_chunk_bytes = 4ULL * 1024ULL * 1024ULL;
};

struct provider_snapshot_metrics_t final {
    std::uint64_t elapsed_ns = 0;
    std::uint64_t bytes = 0;
    std::uint64_t hash_bytes = 0;
    std::uint64_t hash_ns = 0;
    bool materialized = false;
    bool hash_recomputed = false;
};

class provider_snapshot_t final : public byte_provider_t {
public:
    static workspace_result_t<std::shared_ptr<provider_snapshot_t>>
        capture(std::shared_ptr<const byte_provider_t> source, std::uint64_t generation = 0,
                const cancellation_token_t& cancel = {});
    static workspace_result_t<std::shared_ptr<provider_snapshot_t>>
        materialize(std::shared_ptr<const byte_provider_t> source,
                    provider_snapshot_options_t options = {},
                    const cancellation_token_t& cancel = {});

    const byte_provider_identity_t& identity() const noexcept override { return identity_; }
    std::uint64_t size() const noexcept override { return identity_.size; }
    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override;
    workspace_result_t<byte_view_t> lease(std::uint64_t offset, std::uint64_t size,
                                          const cancellation_token_t& cancel = {}) const override;
    bool content_pin_active() const noexcept override;
    std::optional<mapped_window_cache_statistics_t>
        window_cache_statistics() const noexcept override;
    workspace_result_t<void> validate_source() const;
    workspace_result_t<void> verify_content(
        const cancellation_token_t& cancel = {}) const;

    std::uint64_t generation() const noexcept { return generation_; }
    const byte_provider_identity_t& source_identity() const noexcept { return source_identity_; }
    const std::shared_ptr<const byte_provider_t>& source() const noexcept { return source_; }
    const provider_snapshot_metrics_t& metrics() const noexcept { return metrics_; }

private:
    provider_snapshot_t(std::shared_ptr<const byte_provider_t> source,
                        byte_provider_identity_t source_identity,
                        byte_provider_identity_t identity,
                        std::uint64_t generation);

    std::shared_ptr<const byte_provider_t> source_;
    byte_provider_identity_t source_identity_;
    byte_provider_identity_t identity_;
    std::uint64_t generation_ = 0;
    provider_snapshot_metrics_t metrics_;
};

}
