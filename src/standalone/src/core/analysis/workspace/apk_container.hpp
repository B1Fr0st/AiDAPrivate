#pragma once

#include "dex_image.hpp"
#include "zip_container.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

enum class apk_container_kind_t : std::uint8_t {
    unknown = 0,
    apk = 1,
    aab = 2,
    apk_set = 3
};

enum class apk_member_role_t : std::uint8_t {
    dex = 0,
    native_library = 1,
    runtime_artifact = 2,
    nested_container = 3
};

enum class apk_code_kind_t : std::uint8_t {
    dex = 0,
    compact_dex = 1,
    oat = 2,
    vdex = 3,
    elf = 4,
    apk = 5,
    aab = 6,
    zip = 7
};

struct apk_module_identity_t {
    std::string name;
    std::string normalized_path;
    bool is_base = false;
    bool is_split = false;
};

struct apk_code_member_t {
    std::string normalized_path;
    std::string container_path;
    std::string provenance_path;
    apk_member_role_t role = apk_member_role_t::dex;
    apk_code_kind_t code_kind = apk_code_kind_t::dex;
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t architecture_mode = architecture_mode_t::unknown;
    abi_id_t abi = abi_id_t::unknown;
    std::string abi_name;
    std::string execution_profile;
    apk_module_identity_t module;
    std::uint64_t size = 0;
    std::uint16_t machine = 0;
    std::uint32_t format_version = 0;
    std::optional<dex_container_info_t> dex_container;
    provider_member_metadata_t provider_metadata;
    std::vector<provider_member_metadata_t> provenance;
};

struct apk_dex_member_record_t {
    apk_code_member_t member;
    dex_image_t image;
    std::shared_ptr<byte_provider_t> provider;
};

struct apk_container_limits_t {
    zip_container_limits_t zip{};
    dex_parse_limits_t dex{};
    std::uint64_t max_total_archives = 4096;
    std::uint64_t max_total_members = 1000000;
    std::uint64_t max_code_members = 262144;
    std::uint64_t max_total_compressed_size = 16ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_total_uncompressed_size = 8ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_probe_bytes = 4ULL * 1024ULL * 1024ULL * 1024ULL;
    std::chrono::milliseconds max_elapsed{60000};
};

class apk_container_t final {
public:
    static workspace_result_t<std::shared_ptr<apk_container_t>>
        open(std::shared_ptr<const byte_provider_t> provider,
             apk_container_limits_t limits = {},
             const cancellation_token_t& cancel = {});

    const byte_provider_identity_t& source_identity() const noexcept;
    const std::shared_ptr<const byte_provider_t>& source_provider() const noexcept;
    const apk_container_limits_t& limits() const noexcept;
    apk_container_kind_t kind() const noexcept;
    const std::vector<apk_code_member_t>& members() const noexcept;

    workspace_result_t<std::shared_ptr<byte_provider_t>>
        open_member_provider(std::size_t member_index,
                             const cancellation_token_t& cancel = {}) const;
    workspace_result_t<apk_dex_member_record_t>
        parse_dex_member(std::size_t member_index,
                         const cancellation_token_t& cancel = {}) const;
    workspace_result_t<void>
        verify_integrity(const cancellation_token_t& cancel = {}) const;
    bool integrity_verified() const;

private:
    struct state_t;
    explicit apk_container_t(std::shared_ptr<state_t> state);

    std::shared_ptr<state_t> state_;
};

}
