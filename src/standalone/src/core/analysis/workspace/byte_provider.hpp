#pragma once

#include "checked_range.hpp"
#include "workspace_types.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace aida::analysis {

struct byte_provider_identity_t {
    std::string normalized_source;
    std::uint64_t size = 0;
    std::uint64_t volume_serial = 0;
    std::array<std::uint8_t, 16> file_id{};
    std::uint64_t last_write_time_100ns = 0;
    bool immutable_snapshot = false;
    std::optional<provider_member_metadata_t> member;
};

class byte_view_t final {
public:
    byte_view_t() = default;

    const std::uint8_t* data() const noexcept { return data_; }
    std::size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    const std::uint8_t& operator[](std::size_t index) const {
        if (index >= size_)
            throw std::out_of_range("byte view index exceeds its lease");
        return data_[index];
    }
    const std::uint8_t* begin() const noexcept { return data_; }
    const std::uint8_t* end() const noexcept { return size_ == 0 ? data_ : data_ + size_; }

private:
    byte_view_t(std::shared_ptr<const void> lifetime, const std::uint8_t* data, std::size_t size)
        : lifetime_(std::move(lifetime)), data_(data), size_(size) {}

    std::shared_ptr<const void> lifetime_;
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;

    friend class mapped_file_provider_t;
    friend class subrange_provider_t;
    friend class live_snapshot_provider_t;
    friend class memory_provider_t;
};

class byte_provider_t {
public:
    virtual ~byte_provider_t() = default;

    virtual const byte_provider_identity_t& identity() const noexcept = 0;
    virtual std::uint64_t size() const noexcept = 0;
    virtual workspace_result_t<byte_view_t> lease(std::uint64_t offset, std::uint64_t size,
                                                  const cancellation_token_t& cancel = {}) const = 0;

    const std::optional<provider_member_metadata_t>& member_metadata() const noexcept {
        return identity().member;
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
};

struct mapped_file_provider_options_t {
    std::uint64_t max_lease_size = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t read_chunk_size = 4ULL * 1024ULL * 1024ULL;
};

class mapped_file_provider_t final : public byte_provider_t {
public:
    static workspace_result_t<std::shared_ptr<mapped_file_provider_t>>
        open(const std::string& utf8_path, mapped_file_provider_options_t options = {});

    ~mapped_file_provider_t() override;
    mapped_file_provider_t(const mapped_file_provider_t&) = delete;
    mapped_file_provider_t& operator=(const mapped_file_provider_t&) = delete;

    const byte_provider_identity_t& identity() const noexcept override;
    std::uint64_t size() const noexcept override;
    workspace_result_t<byte_view_t> lease(std::uint64_t offset, std::uint64_t size,
                                          const cancellation_token_t& cancel = {}) const override;
    workspace_result_t<void> revalidate() const;

private:
    struct state_t;
    explicit mapped_file_provider_t(std::shared_ptr<state_t> state);

    std::shared_ptr<state_t> state_;
    friend class byte_provider_t;
};

class subrange_provider_t final : public byte_provider_t {
public:
    static workspace_result_t<std::shared_ptr<subrange_provider_t>>
        create(std::shared_ptr<const byte_provider_t> parent, std::uint64_t base,
               std::uint64_t length, std::string identity_suffix);
    static workspace_result_t<std::shared_ptr<subrange_provider_t>>
        create_member(std::shared_ptr<const byte_provider_t> parent, std::uint64_t base,
                      std::uint64_t length, provider_member_metadata_t member);

    const byte_provider_identity_t& identity() const noexcept override { return identity_; }
    std::uint64_t size() const noexcept override { return length_; }
    workspace_result_t<byte_view_t> lease(std::uint64_t offset, std::uint64_t size,
                                          const cancellation_token_t& cancel = {}) const override;

    std::uint64_t parent_base() const noexcept { return base_; }
    const std::shared_ptr<const byte_provider_t>& parent() const noexcept { return parent_; }

private:
    subrange_provider_t(std::shared_ptr<const byte_provider_t> parent, std::uint64_t base,
                        std::uint64_t length, byte_provider_identity_t identity);

    std::shared_ptr<const byte_provider_t> parent_;
    std::uint64_t base_ = 0;
    std::uint64_t length_ = 0;
    byte_provider_identity_t identity_;
};

}
