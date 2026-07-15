#pragma once

#include "workspace_types.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace aida::analysis {

class byte_provider_t;

struct workspace_identity_input_t {
    std::string bin_name;
    std::string source_path;
    std::optional<std::string> member_path;
    sha256_digest_t content_hash;
    sha256_digest_t load_profile_hash;
    target_kind_t target_kind = target_kind_t::static_file;
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t architecture_mode = architecture_mode_t::unknown;
    abi_id_t abi = abi_id_t::unknown;
    endian_t endian = endian_t::little;
    std::uint64_t image_base = 0;
    std::optional<process_identity_t> process;
    std::optional<module_identity_t> module;
};

class workspace_identity_t final {
public:
    workspace_identity_t(const workspace_identity_t&) = default;
    workspace_identity_t(workspace_identity_t&&) noexcept = default;
    workspace_identity_t& operator=(const workspace_identity_t&) = delete;
    workspace_identity_t& operator=(workspace_identity_t&&) = delete;

    const binary_id_t& binary_id() const noexcept { return binary_id_; }
    const std::string& bin_name() const noexcept { return bin_name_; }
    const std::string& normalized_source_path() const noexcept { return normalized_source_path_; }
    const std::optional<std::string>& normalized_member_path() const noexcept { return normalized_member_path_; }
    const sha256_digest_t& content_hash() const noexcept { return content_hash_; }
    const sha256_digest_t& load_profile_hash() const noexcept { return load_profile_hash_; }
    target_kind_t target_kind() const noexcept { return target_kind_; }
    format_id_t format() const noexcept { return format_; }
    architecture_id_t architecture() const noexcept { return architecture_; }
    architecture_mode_t architecture_mode() const noexcept { return architecture_mode_; }
    abi_id_t abi() const noexcept { return abi_; }
    endian_t endian() const noexcept { return endian_; }
    std::uint64_t image_base() const noexcept { return image_base_; }
    const std::optional<process_identity_t>& process() const noexcept { return process_; }
    const std::optional<module_identity_t>& module() const noexcept { return module_; }

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static std::shared_ptr<const workspace_identity_t> create_preview(
        binary_id_t binary_id, workspace_identity_input_t input);
#endif

private:
    workspace_identity_t(binary_id_t binary_id, workspace_identity_input_t input,
                         std::string normalized_source_path,
                         std::optional<std::string> normalized_member_path,
                         std::string normalized_bin_name);

    binary_id_t binary_id_;
    std::string bin_name_;
    std::string normalized_source_path_;
    std::optional<std::string> normalized_member_path_;
    sha256_digest_t content_hash_;
    sha256_digest_t load_profile_hash_;
    target_kind_t target_kind_;
    format_id_t format_;
    architecture_id_t architecture_;
    architecture_mode_t architecture_mode_;
    abi_id_t abi_;
    endian_t endian_;
    std::uint64_t image_base_;
    std::optional<process_identity_t> process_;
    std::optional<module_identity_t> module_;

    friend workspace_result_t<std::shared_ptr<const workspace_identity_t>>
        make_workspace_identity(workspace_identity_input_t input);
};

workspace_result_t<std::shared_ptr<const workspace_identity_t>>
make_workspace_identity(workspace_identity_input_t input);

workspace_result_t<sha256_digest_t> sha256_bytes(const void* data, std::size_t size,
                                                const cancellation_token_t& cancel = {});
workspace_result_t<sha256_digest_t> sha256_text(const std::string& text,
                                               const cancellation_token_t& cancel = {});
workspace_result_t<sha256_digest_t> sha256_provider(const byte_provider_t& provider,
                                                   const cancellation_token_t& cancel = {},
                                                   std::uint64_t chunk_size = 4ULL * 1024ULL * 1024ULL);

workspace_result_t<std::string> normalize_utf8_path(const std::string& path,
                                                    bool require_existing);
std::string normalize_target_name(std::string name);

}
