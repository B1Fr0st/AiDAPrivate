#pragma once

#include "workspace/byte_provider.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace aida::analysis {

struct mapped_window_cache_options_t final {
    std::uint64_t window_bytes = 4ULL * 1024ULL * 1024ULL;
    std::uint64_t max_lease_bytes = 4ULL * 1024ULL * 1024ULL;
    std::uint64_t max_cached_window_bytes = 256ULL * 1024ULL * 1024ULL;
    std::uint64_t max_global_mapped_window_bytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint32_t shard_count = 16;
    bool immutable_source = false;
};

struct mapped_window_cache_statistics_t final {
    std::uint64_t source_bytes = 0;
    std::uint64_t cached_window_bytes = 0;
    std::uint64_t reserved_window_bytes = 0;
    std::uint64_t global_mapped_window_bytes = 0;
    std::uint64_t global_reserved_window_bytes = 0;
    std::uint64_t global_admitted_window_bytes = 0;
    std::uint64_t mapped_windows = 0;
    std::uint64_t cache_hits = 0;
    std::uint64_t cache_misses = 0;
    std::uint64_t evictions = 0;
    std::uint64_t pinned_windows = 0;
};

class mapped_window_cache_t final : public byte_provider_t {
public:
    static workspace_result_t<std::shared_ptr<mapped_window_cache_t>>
        open(const std::string& utf8_path, mapped_window_cache_options_t options = {});

    ~mapped_window_cache_t() override;
    mapped_window_cache_t(const mapped_window_cache_t&) = delete;
    mapped_window_cache_t& operator=(const mapped_window_cache_t&) = delete;

    const byte_provider_identity_t& identity() const noexcept override;
    std::uint64_t size() const noexcept override;
    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override;
    workspace_result_t<byte_view_t> lease(std::uint64_t offset, std::uint64_t size,
                                          const cancellation_token_t& cancel = {}) const override;
    workspace_result_t<void> revalidate() const;
    workspace_result_t<void> trim();
    mapped_window_cache_statistics_t statistics() const noexcept;

private:
    struct state_t;

    explicit mapped_window_cache_t(std::shared_ptr<state_t> state);

    std::shared_ptr<state_t> state_;
};

}
