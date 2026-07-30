#pragma once

#include "mapped_window_cache.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace aida::analysis {

struct spill_provider_options_t final {
    std::uint64_t max_spill_bytes = 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t write_chunk_bytes = 1024ULL * 1024ULL;
    mapped_window_cache_options_t mapped_window_cache{};
};

using spill_stream_reader_t = std::function<workspace_result_t<std::size_t>(
    std::uint8_t* destination, std::size_t capacity, const cancellation_token_t& cancel)>;

class spill_provider_t;

class spill_sink_t final {
public:
    static workspace_result_t<std::shared_ptr<spill_sink_t>>
        create(std::string source_label, spill_provider_options_t options = {});

    ~spill_sink_t();
    spill_sink_t(const spill_sink_t&) = delete;
    spill_sink_t& operator=(const spill_sink_t&) = delete;

    workspace_result_t<void> append(const std::uint8_t* data, std::uint64_t size,
                                    const cancellation_token_t& cancel = {});
    workspace_result_t<std::shared_ptr<spill_provider_t>>
        finalize(const cancellation_token_t& cancel = {});
    std::uint64_t appended_bytes() const noexcept;
    std::uint64_t capacity_bytes() const noexcept;

private:
    struct state_t;

    explicit spill_sink_t(std::shared_ptr<state_t> state);

    std::shared_ptr<state_t> state_;
};

class spill_provider_t final : public byte_provider_t {
public:
    static workspace_result_t<std::shared_ptr<spill_provider_t>>
        from_stream(std::string source_label, spill_stream_reader_t reader,
                    spill_provider_options_t options = {},
                    const cancellation_token_t& cancel = {});

    const byte_provider_identity_t& identity() const noexcept override { return identity_; }
    std::uint64_t size() const noexcept override { return identity_.size; }
    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override;
    workspace_result_t<byte_view_t> lease(std::uint64_t offset, std::uint64_t size,
                                          const cancellation_token_t& cancel = {}) const override;
    bool content_pin_active() const noexcept override;
    std::optional<mapped_window_cache_statistics_t>
        window_cache_statistics() const noexcept override;
    workspace_result_t<void> revalidate() const;
    workspace_result_t<void> verify_content(
        const cancellation_token_t& cancel = {}) const;

private:
    friend class spill_sink_t;
    struct state_t;

    spill_provider_t(std::shared_ptr<state_t> state, byte_provider_identity_t identity);

    std::shared_ptr<state_t> state_;
    byte_provider_identity_t identity_;
};

}
