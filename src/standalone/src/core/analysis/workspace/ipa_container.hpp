#pragma once

#include "macho_image.hpp"
#include "zip_container.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace aida::analysis {

enum class ipa_member_role_t : std::uint8_t {
    app_executable = 0,
    framework_executable = 1,
    app_extension_executable = 2,
    dynamic_library = 3,
    bundle_executable = 4,
    debug_companion = 5
};

struct ipa_macho_slice_provenance_t {
    std::uint32_t ordinal = 0;
    std::int32_t cpu_type = 0;
    std::int32_t cpu_subtype = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint32_t alignment = 0;
    architecture_id_t architecture = architecture_id_t::unknown;
    bool cpu_type_available = false;
};

struct ipa_member_t {
    std::string normalized_path;
    std::string bundle_path_hint;
    std::string bundle_name_hint;
    std::string enclosing_app_bundle_path;
    provider_member_metadata_t provider_metadata;
    std::size_t zip_member_index = 0;
    ipa_member_role_t role = ipa_member_role_t::app_executable;
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    bool fat_macho = false;
    std::vector<ipa_macho_slice_provenance_t> slices;
};

struct ipa_container_limits_t {
    zip_container_limits_t zip{};
    macho_parse_limits_t macho{};
    std::uint64_t max_macho_candidate_members = 16384;
    std::uint64_t max_macho_candidate_aggregate_uncompressed_size =
        4ULL * 1024ULL * 1024ULL * 1024ULL;
};

class ipa_container_t final {
public:
    static workspace_result_t<std::shared_ptr<ipa_container_t>>
        open(std::shared_ptr<const byte_provider_t> provider,
             ipa_container_limits_t limits = {},
             const cancellation_token_t& cancel = {});

    const byte_provider_identity_t& source_identity() const noexcept;
    const std::shared_ptr<const byte_provider_t>& source_provider() const noexcept;
    const ipa_container_limits_t& limits() const noexcept;
    const std::vector<ipa_member_t>& members() const noexcept;
    const ipa_member_t* find_member(std::string_view normalized_path) const;

    workspace_result_t<std::shared_ptr<byte_provider_t>>
        open_member_provider(std::size_t member_index,
                             const cancellation_token_t& cancel = {}) const;
    workspace_result_t<std::shared_ptr<byte_provider_t>>
        open_member_provider(std::string_view normalized_path,
                             const cancellation_token_t& cancel = {}) const;

private:
    struct state_t;
    explicit ipa_container_t(std::shared_ptr<const state_t> state);

    std::shared_ptr<const state_t> state_;
};

}
