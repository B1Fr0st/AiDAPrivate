#pragma once

#include "classfile_parser.hpp"
#include "zip_container.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

struct jar_member_token_t {
    std::uint64_t ordinal = 0;
    std::uint64_t local_header_offset = 0;
    std::uint64_t data_offset = 0;
    std::uint64_t uncompressed_size = 0;
    std::uint32_t crc32 = 0;

    friend bool operator==(const jar_member_token_t& lhs,
                           const jar_member_token_t& rhs) noexcept {
        return lhs.ordinal == rhs.ordinal &&
               lhs.local_header_offset == rhs.local_header_offset &&
               lhs.data_offset == rhs.data_offset &&
               lhs.uncompressed_size == rhs.uncompressed_size &&
               lhs.crc32 == rhs.crc32;
    }
};

struct managed_class_identity_t {
    std::string internal_name;
    std::string binary_name;
    std::uint16_t major_version = 0;
    std::uint16_t minor_version = 0;
    jar_member_token_t token;
    provider_member_metadata_t provenance;
    bool entry_name_matches_internal_name = false;
};

struct container_member_t {
    std::string name;
    jar_member_token_t token;
    provider_member_metadata_t provenance;
    std::uint64_t compressed_size = 0;
    std::uint64_t uncompressed_size = 0;
    std::uint16_t compression_method = 0;
    std::uint32_t crc32 = 0;
    std::uint32_t external_attributes = 0;
    std::uint32_t multi_release_version = 0;
    bool is_directory = false;
    bool is_code = false;
    bool is_class = false;
    bool is_nested_class = false;
    bool is_nested_container = false;
    bool is_multi_release_layout = false;
    bool is_active_multi_release_entry = false;
    format_id_t format_hint = format_id_t::unknown;
    architecture_id_t architecture_hint = architecture_id_t::unknown;
};

struct managed_class_record_t {
    container_member_t member;
    managed_class_identity_t identity;
    classfile_image_t classfile;
    std::shared_ptr<byte_provider_t> provider;
};

struct jar_parse_limits_t {
    zip_container_limits_t zip;
    classfile_parse_limits_t classfile;
    std::uint64_t max_class_members = 1000000;
    std::uint64_t max_nested_code_members = 100000;
    std::uint64_t max_manifest_bytes = 1024ULL * 1024ULL;
};

class jar_container_t final {
public:
    static workspace_result_t<std::shared_ptr<jar_container_t>>
        open(std::shared_ptr<const byte_provider_t> provider,
             jar_parse_limits_t limits = {},
             const cancellation_token_t& cancel = {});

    const byte_provider_identity_t& source_identity() const noexcept;
    const std::shared_ptr<const byte_provider_t>& source_provider() const noexcept;
    const std::shared_ptr<zip_container_t>& zip() const noexcept;
    const jar_parse_limits_t& limits() const noexcept;
    const std::vector<container_member_t>& members() const noexcept;
    const container_member_t* find_member(const jar_member_token_t& token) const noexcept;
    const container_member_t* find_member(const std::string& normalized_path) const noexcept;
    bool is_multi_release() const noexcept;

    workspace_result_t<std::shared_ptr<byte_provider_t>>
        open_member_provider(const jar_member_token_t& token,
                             const cancellation_token_t& cancel = {}) const;
    workspace_result_t<std::shared_ptr<byte_provider_t>>
        open_member_provider(const std::string& normalized_path,
                             const cancellation_token_t& cancel = {}) const;
    workspace_result_t<std::shared_ptr<jar_container_t>>
        open_nested_container(const jar_member_token_t& token,
                              const cancellation_token_t& cancel = {}) const;
    workspace_result_t<std::shared_ptr<jar_container_t>>
        open_nested_container(const std::string& normalized_path,
                              const cancellation_token_t& cancel = {}) const;
    workspace_result_t<managed_class_record_t>
        parse_class_member(const jar_member_token_t& token,
                           const cancellation_token_t& cancel = {}) const;
    workspace_result_t<managed_class_record_t>
        parse_class_member(const std::string& normalized_path,
                           const cancellation_token_t& cancel = {}) const;

private:
    jar_container_t(std::shared_ptr<const byte_provider_t> provider,
                    std::shared_ptr<zip_container_t> zip,
                    jar_parse_limits_t limits,
                    std::vector<container_member_t> members,
                    bool multi_release);

    std::shared_ptr<const byte_provider_t> provider_;
    std::shared_ptr<zip_container_t> zip_;
    jar_parse_limits_t limits_;
    std::vector<container_member_t> members_;
    bool multi_release_ = false;
};

workspace_result_t<std::vector<container_member_t>>
enumerate_jar_members(const byte_provider_t& provider,
                      const cancellation_token_t& cancel = {});

workspace_result_t<std::vector<container_member_t>>
enumerate_jar_members(const byte_provider_t& provider,
                      const jar_parse_limits_t& limits,
                      const cancellation_token_t& cancel = {});

workspace_result_t<std::shared_ptr<byte_provider_t>>
extract_jar_member(const byte_provider_t& provider,
                   const container_member_t& member,
                   const cancellation_token_t& cancel = {});

bool jar_is_multi_release(const byte_provider_t& provider,
                          const cancellation_token_t& cancel = {});

}
