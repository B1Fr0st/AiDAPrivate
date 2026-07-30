#pragma once

#include "workspace/byte_provider.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace aida::analysis {

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
    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override;
    workspace_result_t<byte_view_t> lease(std::uint64_t offset, std::uint64_t size,
                                          const cancellation_token_t& cancel = {}) const override;
    bool content_pin_active() const noexcept override;
    std::optional<mapped_window_cache_statistics_t>
        window_cache_statistics() const noexcept override;

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
