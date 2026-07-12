#pragma once

#include "workspace/workspace_types.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

enum class image_layout_region_kind_t : std::uint8_t {
    section = 0,
    segment = 1,
    member = 2
};

struct image_layout_identity_t {
    binary_id_t content_id;
    format_id_t format = format_id_t::unknown;
    endian_t endian = endian_t::little;
    std::uint8_t address_width_bits = 0;
    std::uint64_t image_base = 0;
    std::uint64_t provider_size = 0;
    std::optional<provider_member_metadata_t> member;

    bool operator==(const image_layout_identity_t& other) const noexcept;
    bool operator!=(const image_layout_identity_t& other) const noexcept;
    std::vector<std::uint8_t> canonical_bytes() const;
    std::uint64_t canonical_hash() const;
};

struct image_layout_mapping_t {
    std::uint32_t id = 0;
    std::uint64_t rva = 0;
    std::uint64_t virtual_address = 0;
    std::uint64_t virtual_size = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
    std::uint32_t permissions = image_permission_none;
    std::optional<std::uint32_t> section_id;
    std::optional<std::uint32_t> segment_id;
    std::optional<std::uint32_t> member_id;
};

struct image_layout_section_range_t {
    std::uint32_t id = 0;
    std::string name;
    std::uint64_t rva = 0;
    std::uint64_t virtual_size = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
    std::uint32_t permissions = image_permission_none;
};

struct image_layout_segment_range_t {
    std::uint32_t id = 0;
    std::string name;
    std::uint64_t rva = 0;
    std::uint64_t virtual_size = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
    std::uint32_t permissions = image_permission_none;
};

struct image_layout_member_range_t {
    std::uint32_t id = 0;
    std::string name;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
};

struct image_layout_definition_t {
    image_layout_identity_t identity;
    std::vector<image_layout_mapping_t> mappings;
    std::vector<image_layout_section_range_t> sections;
    std::vector<image_layout_segment_range_t> segments;
    std::vector<image_layout_member_range_t> members;
};

struct image_layout_lookup_t {
    address_space_id_t queried_space = address_space_id_t::relative_virtual;
    std::uint64_t queried_value = 0;
    std::uint32_t mapping_id = 0;
    std::uint64_t rva = 0;
    std::uint64_t virtual_address = 0;
    std::optional<std::uint64_t> file_offset;
    std::uint32_t permissions = image_permission_none;
    bool zero_fill = false;
    bool ambiguous = false;
    std::vector<std::uint32_t> section_ids;
    std::vector<std::uint32_t> segment_ids;
    std::vector<std::uint32_t> member_ids;
};

struct image_layout_interval_slice_t {
    std::uint64_t start = 0;
    std::uint64_t size = 0;
    std::optional<image_layout_lookup_t> lookup;
};

struct image_layout_interval_lookup_t {
    address_space_id_t queried_space = address_space_id_t::relative_virtual;
    std::uint64_t start = 0;
    std::uint64_t size = 0;
    bool complete = false;
    bool ambiguous = false;
    std::vector<image_layout_interval_slice_t> slices;
};

struct image_layout_query_counters_t {
    std::uint64_t queries = 0;
    std::uint64_t point_queries = 0;
    std::uint64_t interval_queries = 0;
    std::uint64_t va_queries = 0;
    std::uint64_t rva_queries = 0;
    std::uint64_t file_queries = 0;
    std::uint64_t mapping_binary_search_steps = 0;
    std::uint64_t mapping_candidate_checks = 0;
    std::uint64_t metadata_binary_search_steps = 0;
    std::uint64_t metadata_matches = 0;
};

class image_layout_index_t {
public:
    struct state_t;

    static workspace_result_t<image_layout_index_t> build(image_layout_definition_t definition);

    image_layout_index_t(const image_layout_index_t&) = default;
    image_layout_index_t(image_layout_index_t&&) noexcept = default;
    image_layout_index_t& operator=(const image_layout_index_t&) = default;
    image_layout_index_t& operator=(image_layout_index_t&&) noexcept = default;
    ~image_layout_index_t();

    const image_layout_identity_t& identity() const noexcept;
    const std::vector<image_layout_mapping_t>& mappings() const noexcept;
    const std::vector<image_layout_section_range_t>& sections() const noexcept;
    const std::vector<image_layout_segment_range_t>& segments() const noexcept;
    const std::vector<image_layout_member_range_t>& members() const noexcept;

    workspace_result_t<std::optional<image_layout_lookup_t>> lookup(address_space_id_t space,
                                                                      std::uint64_t value) const;
    workspace_result_t<std::optional<image_layout_lookup_t>> lookup_va(std::uint64_t value) const;
    workspace_result_t<std::optional<image_layout_lookup_t>> lookup_rva(std::uint64_t value) const;
    workspace_result_t<std::optional<image_layout_lookup_t>> lookup_file_offset(std::uint64_t value) const;
    workspace_result_t<image_layout_interval_lookup_t> lookup_interval(address_space_id_t space,
                                                                         std::uint64_t start,
                                                                         std::uint64_t size) const;
    image_layout_query_counters_t query_counters() const noexcept;

private:
    explicit image_layout_index_t(std::shared_ptr<const state_t> state) noexcept;

    std::shared_ptr<const state_t> state_;
};

}
