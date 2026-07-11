#pragma once

#include "byte_provider.hpp"
#include "workspace_identity.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace aida::analysis {

struct live_snapshot_request_t {
    std::uint32_t pid = 0;
    std::uint64_t module_base = 0;
    std::uint64_t module_size = 0;
    std::string module_name;
    std::string module_path;
    address_t capture_address;
    std::uint64_t capture_size = 0;
    std::uint64_t maximum_capture_size = 64ULL * 1024ULL * 1024ULL;
};

struct live_function_snapshot_request_t {
    std::uint32_t pid = 0;
    std::uint64_t function_va = 0;
    std::uint64_t function_size = 0;
    std::uint64_t module_base = 0;
    std::uint64_t module_size = 0;
    std::string module_name;
    std::string module_path;
    std::uint64_t maximum_capture_size = 4ULL * 1024ULL * 1024ULL;
};

struct live_snapshot_metadata_t {
    process_identity_t process;
    module_identity_t module;
    std::uint64_t capture_address = 0;
    std::uint64_t capture_size = 0;
    std::uint64_t capture_time_100ns = 0;
    sha256_digest_t capture_hash;
};

class live_snapshot_provider_t final : public byte_provider_t {
public:
    static workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>
        capture(const live_snapshot_request_t& request,
                const cancellation_token_t& cancel = {});

    static workspace_result_t<std::shared_ptr<live_snapshot_provider_t>>
        capture_function(const live_function_snapshot_request_t& request,
                         const cancellation_token_t& cancel = {});

    const byte_provider_identity_t& identity() const noexcept override { return identity_; }
    std::uint64_t size() const noexcept override { return metadata_.capture_size; }
    workspace_result_t<byte_view_t> lease(std::uint64_t offset, std::uint64_t size,
                                          const cancellation_token_t& cancel = {}) const override;

    const live_snapshot_metadata_t& metadata() const noexcept { return metadata_; }
    workspace_result_t<void> validate_current_identity() const;

private:
    live_snapshot_provider_t(live_snapshot_metadata_t metadata,
                             byte_provider_identity_t identity,
                             std::shared_ptr<const std::vector<std::uint8_t>> bytes);

    live_snapshot_metadata_t metadata_;
    byte_provider_identity_t identity_;
    std::shared_ptr<const std::vector<std::uint8_t>> bytes_;
};

}
