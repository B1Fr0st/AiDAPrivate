#pragma once

#include "checked_range.hpp"
#include "workspace_types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace aida::analysis {

class mapped_window_cache_t;
class subrange_provider_t;

struct byte_provider_identity_t {
    std::string normalized_source;
    std::uint64_t size = 0;
    std::uint64_t volume_serial = 0;
    std::array<std::uint8_t, 16> file_id{};
    std::uint64_t last_write_time_100ns = 0;
    bool immutable_snapshot = false;
    std::optional<sha256_digest_t> content_sha256;
    std::optional<provider_member_metadata_t> member;
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
    std::uint64_t capacity_bytes = 0;
    std::uint64_t lease_count = 0;
    std::uint64_t lease_wait_ns = 0;
    std::uint64_t shard_lock_contention = 0;
    std::uint64_t admission_steals = 0;
    std::uint64_t duplicate_map_races = 0;
    std::uint64_t map_calls = 0;
    std::uint64_t prefetch_warm_issued = 0;
};

struct byte_span_storage_t final {
    static constexpr std::size_t kMaxSegments = 16;
    std::uint32_t segment_count = 0;
    std::size_t total_bytes = 0;
    std::array<std::shared_ptr<const void>, kMaxSegments> owners{};
    std::array<const std::uint8_t*, kMaxSegments> bases{};
    std::array<std::size_t, kMaxSegments> sizes{};
};

class byte_view_t final {
public:
    byte_view_t() = default;

    const std::uint8_t* data() const noexcept { return data_; }
    std::size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    bool is_span() const noexcept { return static_cast<bool>(span_); }
    bool contiguous() const noexcept { return !span_; }
    std::size_t segment_count() const noexcept {
        return span_ ? static_cast<std::size_t>(span_->segment_count)
                     : static_cast<std::size_t>(1);
    }
    const std::uint8_t* segment_data(std::size_t index) const {
        if (span_) {
            if (index >= span_->segment_count)
                throw std::out_of_range("byte view segment exceeds its lease");
            return span_->bases[index];
        }
        if (index != 0)
            throw std::out_of_range("byte view segment exceeds its lease");
        return data_;
    }
    std::size_t segment_size(std::size_t index) const {
        if (span_) {
            if (index >= span_->segment_count)
                throw std::out_of_range("byte view segment exceeds its lease");
            return span_->sizes[index];
        }
        if (index != 0)
            throw std::out_of_range("byte view segment exceeds its lease");
        return size_;
    }
    template <typename Fn>
    void for_each_segment(Fn&& fn) const {
        if (span_) {
            std::size_t stream_offset = 0;
            for (std::uint32_t index = 0; index < span_->segment_count; ++index) {
                fn(span_->bases[index], span_->sizes[index], stream_offset);
                stream_offset += span_->sizes[index];
            }
            return;
        }
        fn(data_, size_, 0);
    }
    void copy_to(void* destination, std::size_t capacity) const {
        if (!destination && size_ != 0)
            throw std::invalid_argument("byte view copy destination is null");
        if (capacity < size_)
            throw std::out_of_range("byte view copy destination is too small");
        auto* output = static_cast<std::uint8_t*>(destination);
        for_each_segment([&](const std::uint8_t* bytes, std::size_t amount,
                             std::size_t stream_offset) {
            if (amount != 0)
                std::memcpy(output + stream_offset, bytes, amount);
        });
    }
    const std::uint8_t& operator[](std::size_t index) const {
        if (span_)
            throw std::logic_error("byte view span does not expose contiguous element access");
        if (index >= size_)
            throw std::out_of_range("byte view index exceeds its lease");
        return data_[index];
    }
    const std::uint8_t* begin() const noexcept { return data_; }
    const std::uint8_t* end() const noexcept { return size_ == 0 ? data_ : data_ + size_; }

private:
    byte_view_t(std::shared_ptr<const void> lifetime, const std::uint8_t* data, std::size_t size)
        : lifetime_(std::move(lifetime)), data_(data), size_(size) {}
    explicit byte_view_t(std::shared_ptr<const byte_span_storage_t> span)
        : data_(nullptr), size_(span ? span->total_bytes : 0), span_(std::move(span)) {}

    std::shared_ptr<const void> lifetime_;
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::shared_ptr<const byte_span_storage_t> span_;

    friend class mapped_file_provider_t;
    friend class mapped_window_cache_t;
    friend class subrange_provider_t;
    friend class live_snapshot_provider_t;
    friend class memory_provider_t;
};

class byte_provider_t {
public:
    virtual ~byte_provider_t() = default;

    virtual const byte_provider_identity_t& identity() const noexcept = 0;
    virtual std::uint64_t size() const noexcept = 0;
    virtual std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept {
        static_cast<void>(offset);
        return (std::numeric_limits<std::uint64_t>::max)();
    }
    virtual workspace_result_t<byte_view_t> lease(std::uint64_t offset, std::uint64_t size,
                                                  const cancellation_token_t& cancel = {}) const = 0;

    const std::optional<provider_member_metadata_t>& member_metadata() const noexcept {
        return identity().member;
    }

    virtual bool content_pin_active() const noexcept { return false; }
    virtual std::optional<mapped_window_cache_statistics_t>
        window_cache_statistics() const noexcept {
        return std::nullopt;
    }

    workspace_result_t<void> read_exact(std::uint64_t offset, void* destination, std::uint64_t size,
                                        const cancellation_token_t& cancel = {}) const;
    workspace_result_t<std::size_t> read_some(std::uint64_t offset, void* destination,
                                              std::size_t capacity,
                                              const cancellation_token_t& cancel = {}) const;
    workspace_result_t<std::vector<std::uint8_t>> read_vector(std::uint64_t offset,
                                                              std::uint64_t size,
                                                              std::uint64_t hard_limit,
                                                              const cancellation_token_t& cancel = {}) const;
    workspace_result_t<sha256_digest_t> compute_content_sha256(
        const cancellation_token_t& cancel = {},
        std::uint64_t chunk_limit = 4ULL * 1024ULL * 1024ULL) const;
};

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
class memory_provider_t final : public byte_provider_t {
public:
    static std::shared_ptr<memory_provider_t> create(
        std::string normalized_source, std::vector<std::uint8_t> bytes,
        sha256_digest_t content_hash);

    const byte_provider_identity_t& identity() const noexcept override;
    std::uint64_t size() const noexcept override;
    workspace_result_t<byte_view_t> lease(
        std::uint64_t offset, std::uint64_t size,
        const cancellation_token_t& cancel = {}) const override;
    bool content_pin_active() const noexcept override { return true; }

private:
    memory_provider_t(std::shared_ptr<const std::vector<std::uint8_t>> bytes,
                      byte_provider_identity_t identity);

    std::shared_ptr<const std::vector<std::uint8_t>> bytes_;
    byte_provider_identity_t identity_;
};
#endif

struct mapped_file_provider_options_t {
    std::uint64_t max_lease_size = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t read_chunk_size = 4ULL * 1024ULL * 1024ULL;
    bool pin_local_file_snapshot = true;
    bool pin_sections = true;
    bool defer_content_hash = false;
};

struct provider_pin_range_t final {
    std::uint64_t file_offset = 0;
    std::uint64_t size = 0;
    std::uint32_t max_windows = 0;
};

std::vector<provider_pin_range_t> compute_admission_pin_ranges(
    const workspace_image_t& image);

class mapped_file_provider_t final : public byte_provider_t {
public:
    static workspace_result_t<std::shared_ptr<mapped_file_provider_t>>
        open(const std::string& utf8_path, mapped_file_provider_options_t options = {});

    ~mapped_file_provider_t() override;
    mapped_file_provider_t(const mapped_file_provider_t&) = delete;
    mapped_file_provider_t& operator=(const mapped_file_provider_t&) = delete;

    const byte_provider_identity_t& identity() const noexcept override;
    std::uint64_t size() const noexcept override;
    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override;
    workspace_result_t<byte_view_t> lease(std::uint64_t offset, std::uint64_t size,
                                          const cancellation_token_t& cancel = {}) const override;
    bool content_pin_active() const noexcept override;
    std::optional<mapped_window_cache_statistics_t>
        window_cache_statistics() const noexcept override;
    workspace_result_t<void> revalidate() const;
    workspace_result_t<void> pin_ranges(
        const std::vector<provider_pin_range_t>& ranges) const;
    bool content_hash_ready() const noexcept;
    workspace_result_t<sha256_digest_t> await_content_hash(
        const cancellation_token_t& cancel = {}) const;

private:
    struct state_t;
    explicit mapped_file_provider_t(std::shared_ptr<state_t> state);

    std::shared_ptr<state_t> state_;
    friend class byte_provider_t;
};

}

#include "../subrange_provider.hpp"
