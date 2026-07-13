#pragma once

#include "../../src/core/analysis/workspace/byte_provider.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis {

class memory_provider_t final : public byte_provider_t {
public:
    explicit memory_provider_t(std::vector<std::uint8_t> bytes,
                               std::string source = "c03-memory")
        : bytes_(std::make_shared<const std::vector<std::uint8_t>>(std::move(bytes)))
    {
        identity_.normalized_source = std::move(source);
        identity_.size = bytes_->size();
        identity_.immutable_snapshot = true;
    }

    const byte_provider_identity_t& identity() const noexcept override
    {
        return identity_;
    }

    std::uint64_t size() const noexcept override
    {
        return bytes_->size();
    }

    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override
    {
        return offset <= bytes_->size() ? bytes_->size() - offset : 0;
    }

    workspace_result_t<byte_view_t> lease(
        std::uint64_t offset, std::uint64_t size_value,
        const cancellation_token_t& cancel = {}) const override
    {
        if (cancel.stop_requested()) {
            auto error = make_workspace_error(
                cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                           : workspace_error_code_t::cancelled,
                "memory provider lease cancelled", "c03_memory_provider");
            error.deadline = cancel.deadline_exceeded();
            error.cancellation = true;
            return workspace_result_t<byte_view_t>::failure(std::move(error));
        }
        if (offset > bytes_->size() || size_value > bytes_->size() - offset ||
            size_value > static_cast<std::uint64_t>(
                (std::numeric_limits<std::size_t>::max)())) {
            return workspace_result_t<byte_view_t>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "memory provider lease exceeds its immutable bytes",
                "c03_memory_provider"));
        }
        const auto begin = size_value == 0 ? bytes_->data()
            : bytes_->data() + static_cast<std::size_t>(offset);
        return workspace_result_t<byte_view_t>::success(byte_view_t(
            bytes_, begin, static_cast<std::size_t>(size_value)));
    }

private:
    std::shared_ptr<const std::vector<std::uint8_t>> bytes_;
    byte_provider_identity_t identity_;
};

}
