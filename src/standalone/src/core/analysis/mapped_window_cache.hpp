#pragma once

#include "workspace/analysis_metrics.hpp"
#include "workspace/byte_provider.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace aida::analysis {

struct mapped_window_cache_options_t final {
    std::uint64_t window_bytes = 4ULL * 1024ULL * 1024ULL;
    std::uint64_t max_lease_bytes = 4ULL * 1024ULL * 1024ULL;
    std::uint64_t max_cached_window_bytes = 256ULL * 1024ULL * 1024ULL;
    std::uint64_t max_global_mapped_window_bytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint32_t shard_count = 64;
    bool immutable_source = false;
};

namespace provider_metrics_relay {

void attach_analysis_metrics(analysis_metrics_t* metrics) noexcept;
void detach_analysis_metrics(const analysis_metrics_t* metrics) noexcept;
void record_mapped_window_bytes(std::uint64_t bytes) noexcept;
void record_global_mapped_window_bytes(std::uint64_t bytes) noexcept;
void record_spill_high_water(std::uint64_t bytes) noexcept;
void record_spill_write(std::uint64_t bytes) noexcept;
void record_spill_read(std::uint64_t bytes) noexcept;
void record_budget_rejection() noexcept;
void record_memory_pressure_event() noexcept;

}

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
    bool content_pin_active() const noexcept override;
    std::optional<mapped_window_cache_statistics_t>
        window_cache_statistics() const noexcept override;
    workspace_result_t<void> revalidate() const;
    workspace_result_t<void> trim();
    mapped_window_cache_statistics_t statistics() const noexcept;

private:
    struct state_t;

    explicit mapped_window_cache_t(std::shared_ptr<state_t> state);

    std::shared_ptr<state_t> state_;
};

}
