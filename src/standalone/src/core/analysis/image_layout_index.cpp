#include "image_layout_index.hpp"

#include "workspace/checked_range.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <limits>
#include <memory>
#include <unordered_set>
#include <utility>

namespace aida::analysis {
namespace {

constexpr std::uint32_t k_known_permissions = image_permission_read |
                                             image_permission_write |
                                             image_permission_execute |
                                             image_permission_discardable;

struct interval_entry_t {
    std::uint64_t first = 0;
    std::uint64_t last = 0;
    std::size_t mapping_index = 0;
};

struct metadata_interval_t {
    std::uint64_t first = 0;
    std::uint64_t last = 0;
    std::uint32_t id = 0;
};

struct metadata_tree_node_t {
    std::uint64_t center = 0;
    std::vector<metadata_interval_t> by_start;
    std::vector<metadata_interval_t> by_end;
    std::unique_ptr<metadata_tree_node_t> left;
    std::unique_ptr<metadata_tree_node_t> right;
};

struct metadata_tree_t {
    std::unique_ptr<metadata_tree_node_t> root;
};

struct atomic_query_counters_t {
    std::atomic<std::uint64_t> queries{0};
    std::atomic<std::uint64_t> point_queries{0};
    std::atomic<std::uint64_t> interval_queries{0};
    std::atomic<std::uint64_t> va_queries{0};
    std::atomic<std::uint64_t> rva_queries{0};
    std::atomic<std::uint64_t> file_queries{0};
    std::atomic<std::uint64_t> mapping_binary_search_steps{0};
    std::atomic<std::uint64_t> mapping_candidate_checks{0};
    std::atomic<std::uint64_t> metadata_binary_search_steps{0};
    std::atomic<std::uint64_t> metadata_matches{0};
};

workspace_error_t layout_error(workspace_error_code_t code, std::string message,
                               std::string phase, std::optional<std::uint64_t> offset = std::nullopt,
                               std::optional<std::uint64_t> size = std::nullopt) {
    workspace_error_t error;
    error.code = code;
    error.message = std::move(message);
    error.phase = std::move(phase);
    error.offset = offset;
    error.size = size;
    return error;
}

template <typename T>
workspace_result_t<T> layout_failure(workspace_error_code_t code, std::string message,
                                     std::string phase, std::optional<std::uint64_t> offset = std::nullopt,
                                     std::optional<std::uint64_t> size = std::nullopt) {
    return workspace_result_t<T>::failure(layout_error(code, std::move(message), std::move(phase), offset, size));
}

bool is_layout_space(address_space_id_t space) noexcept {
    return space == address_space_id_t::relative_virtual ||
           space == address_space_id_t::virtual_address ||
           space == address_space_id_t::file_offset;
}

bool permissions_valid(std::uint32_t permissions) noexcept {
    return (permissions & ~k_known_permissions) == 0;
}

bool fits_address_width(std::uint64_t value, std::uint64_t size,
                        std::uint8_t width_bits) noexcept {
    std::uint64_t end = 0;
    if (!checked_add_u64(value, size, end))
        return false;
    if (width_bits == 64)
        return true;
    const std::uint64_t limit = std::uint64_t{1} << 32U;
    return value < limit && end <= limit;
}

workspace_result_t<std::uint64_t> checked_range_end(std::uint64_t start, std::uint64_t size,
                                                     const char* phase) {
    std::uint64_t end = 0;
    if (!checked_add_u64(start, size, end))
        return layout_failure<std::uint64_t>(workspace_error_code_t::range_overflow,
                                             "image layout range exceeds 64-bit space", phase,
                                             start, size);
    return workspace_result_t<std::uint64_t>::success(end);
}

template <typename T>
bool ids_are_unique(const std::vector<T>& ranges) {
    std::unordered_set<std::uint32_t> ids;
    ids.reserve(ranges.size());
    for (const auto& range : ranges) {
        if (!ids.insert(range.id).second)
            return false;
    }
    return true;
}

template <typename T>
std::unordered_set<std::uint32_t> collect_ids(const std::vector<T>& ranges) {
    std::unordered_set<std::uint32_t> ids;
    ids.reserve(ranges.size());
    for (const auto& range : ranges)
        ids.insert(range.id);
    return ids;
}

std::unique_ptr<metadata_tree_node_t> build_metadata_node(std::vector<metadata_interval_t> intervals) {
    if (intervals.empty())
        return {};

    std::vector<std::uint64_t> endpoints;
    endpoints.reserve(intervals.size() * 2U);
    for (const auto& interval : intervals) {
        endpoints.push_back(interval.first);
        endpoints.push_back(interval.last);
    }
    std::sort(endpoints.begin(), endpoints.end());
    const std::uint64_t center = endpoints[(endpoints.size() - 1U) / 2U];

    std::vector<metadata_interval_t> left;
    std::vector<metadata_interval_t> right;
    std::vector<metadata_interval_t> overlaps;
    left.reserve(intervals.size());
    right.reserve(intervals.size());
    overlaps.reserve(intervals.size());
    for (auto& interval : intervals) {
        if (interval.last <= center)
            left.push_back(std::move(interval));
        else if (interval.first > center)
            right.push_back(std::move(interval));
        else
            overlaps.push_back(std::move(interval));
    }

    auto node = std::make_unique<metadata_tree_node_t>();
    node->center = center;
    node->by_start = overlaps;
    node->by_end = std::move(overlaps);
    std::sort(node->by_start.begin(), node->by_start.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.first != rhs.first)
            return lhs.first < rhs.first;
        if (lhs.last != rhs.last)
            return lhs.last < rhs.last;
        return lhs.id < rhs.id;
    });
    std::sort(node->by_end.begin(), node->by_end.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.last != rhs.last)
            return lhs.last > rhs.last;
        if (lhs.first != rhs.first)
            return lhs.first < rhs.first;
        return lhs.id < rhs.id;
    });
    node->left = build_metadata_node(std::move(left));
    node->right = build_metadata_node(std::move(right));
    return node;
}

metadata_tree_t build_metadata_tree(std::vector<metadata_interval_t> intervals) {
    metadata_tree_t tree;
    tree.root = build_metadata_node(std::move(intervals));
    return tree;
}

std::size_t count_starts_at_most(const std::vector<metadata_interval_t>& intervals,
                                 std::uint64_t value, atomic_query_counters_t& counters) noexcept {
    std::size_t first = 0;
    std::size_t last = intervals.size();
    while (first < last) {
        counters.metadata_binary_search_steps.fetch_add(1, std::memory_order_relaxed);
        const std::size_t middle = first + (last - first) / 2U;
        if (intervals[middle].first <= value)
            first = middle + 1U;
        else
            last = middle;
    }
    return first;
}

std::size_t count_ends_after(const std::vector<metadata_interval_t>& intervals,
                             std::uint64_t value, atomic_query_counters_t& counters) noexcept {
    std::size_t first = 0;
    std::size_t last = intervals.size();
    while (first < last) {
        counters.metadata_binary_search_steps.fetch_add(1, std::memory_order_relaxed);
        const std::size_t middle = first + (last - first) / 2U;
        if (intervals[middle].last > value)
            first = middle + 1U;
        else
            last = middle;
    }
    return first;
}

void collect_metadata_matches(const metadata_tree_node_t* node, std::uint64_t value,
                              atomic_query_counters_t& counters, std::vector<std::uint32_t>& ids) {
    if (node == nullptr)
        return;
    if (value < node->center) {
        const auto count = count_starts_at_most(node->by_start, value, counters);
        for (std::size_t index = 0; index < count; ++index)
            ids.push_back(node->by_start[index].id);
        collect_metadata_matches(node->left.get(), value, counters, ids);
        return;
    }
    if (value > node->center) {
        const auto count = count_ends_after(node->by_end, value, counters);
        for (std::size_t index = 0; index < count; ++index)
            ids.push_back(node->by_end[index].id);
        collect_metadata_matches(node->right.get(), value, counters, ids);
        return;
    }
    for (const auto& interval : node->by_start)
        ids.push_back(interval.id);
}

void normalize_ids(std::vector<std::uint32_t>& ids, atomic_query_counters_t& counters) {
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    counters.metadata_matches.fetch_add(ids.size(), std::memory_order_relaxed);
}

std::optional<std::size_t> find_mapping(const std::vector<interval_entry_t>& intervals,
                                        std::uint64_t value, atomic_query_counters_t& counters) noexcept {
    std::size_t first = 0;
    std::size_t last = intervals.size();
    while (first < last) {
        counters.mapping_binary_search_steps.fetch_add(1, std::memory_order_relaxed);
        const std::size_t middle = first + (last - first) / 2U;
        if (intervals[middle].first <= value)
            first = middle + 1U;
        else
            last = middle;
    }
    if (first == 0)
        return std::nullopt;
    const auto& candidate = intervals[first - 1U];
    counters.mapping_candidate_checks.fetch_add(1, std::memory_order_relaxed);
    if (value < candidate.last)
        return candidate.mapping_index;
    return std::nullopt;
}

std::optional<std::uint64_t> next_mapping_start(const std::vector<interval_entry_t>& intervals,
                                                 std::uint64_t value,
                                                 atomic_query_counters_t& counters) noexcept {
    std::size_t first = 0;
    std::size_t last = intervals.size();
    while (first < last) {
        counters.mapping_binary_search_steps.fetch_add(1, std::memory_order_relaxed);
        const std::size_t middle = first + (last - first) / 2U;
        if (intervals[middle].first <= value)
            first = middle + 1U;
        else
            last = middle;
    }
    if (first == intervals.size())
        return std::nullopt;
    return intervals[first].first;
}

template <typename T>
workspace_result_t<void> validate_named_virtual_ranges(const std::vector<T>& ranges,
                                                        const image_layout_identity_t& identity,
                                                        const char* phase) {
    if (!ids_are_unique(ranges))
        return workspace_result_t<void>::failure(layout_error(workspace_error_code_t::malformed_image,
                                                               "image layout range identifiers must be unique", phase));
    for (const auto& range : ranges) {
        if (range.virtual_size == 0)
            return workspace_result_t<void>::failure(layout_error(workspace_error_code_t::malformed_image,
                                                                   "image layout virtual ranges must be non-empty", phase));
        const auto rva_end = checked_range_end(range.rva, range.virtual_size, phase);
        if (!rva_end)
            return workspace_result_t<void>::failure(rva_end.error());
        if (!fits_address_width(range.rva, range.virtual_size, identity.address_width_bits))
            return workspace_result_t<void>::failure(layout_error(workspace_error_code_t::range_overflow,
                                                                   "image layout virtual range exceeds address width", phase,
                                                                   range.rva, range.virtual_size));
        std::uint64_t virtual_address = 0;
        if (!checked_add_u64(identity.image_base, range.rva, virtual_address))
            return workspace_result_t<void>::failure(layout_error(
                workspace_error_code_t::range_overflow,
                "image layout image base plus range RVA exceeds 64-bit address space", phase,
                identity.image_base, range.rva));
        if (!fits_address_width(virtual_address, range.virtual_size, identity.address_width_bits))
            return workspace_result_t<void>::failure(layout_error(
                workspace_error_code_t::range_overflow,
                "image layout named virtual range exceeds address width", phase,
                virtual_address, range.virtual_size));
        const auto file_end = checked_range_end(range.file_offset, range.file_size, phase);
        if (!file_end)
            return workspace_result_t<void>::failure(file_end.error());
        if (identity.provider_size != 0 && file_end.value() > identity.provider_size)
            return workspace_result_t<void>::failure(layout_error(workspace_error_code_t::out_of_range,
                                                                   "image layout file range exceeds provider size", phase,
                                                                   range.file_offset, range.file_size));
        if (!permissions_valid(range.permissions))
            return workspace_result_t<void>::failure(layout_error(workspace_error_code_t::malformed_image,
                                                                   "image layout range has unknown permissions", phase));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_members(const std::vector<image_layout_member_range_t>& members,
                                          const image_layout_identity_t& identity) {
    if (!ids_are_unique(members))
        return workspace_result_t<void>::failure(layout_error(workspace_error_code_t::malformed_image,
                                                               "image layout member identifiers must be unique", "members"));
    for (const auto& member : members) {
        if (member.file_size == 0)
            return workspace_result_t<void>::failure(layout_error(workspace_error_code_t::malformed_image,
                                                                   "image layout member ranges must be non-empty", "members"));
        const auto file_end = checked_range_end(member.file_offset, member.file_size, "members");
        if (!file_end)
            return workspace_result_t<void>::failure(file_end.error());
        if (identity.provider_size != 0 && file_end.value() > identity.provider_size)
            return workspace_result_t<void>::failure(layout_error(workspace_error_code_t::out_of_range,
                                                                   "image layout member range exceeds provider size", "members",
                                                                   member.file_offset, member.file_size));
    }
    return workspace_result_t<void>::success();
}

}

struct image_layout_index_t::state_t {
    image_layout_definition_t definition;
    std::vector<interval_entry_t> rva_intervals;
    std::vector<interval_entry_t> va_intervals;
    std::vector<interval_entry_t> file_intervals;
    metadata_tree_t section_rva_tree;
    metadata_tree_t section_file_tree;
    metadata_tree_t segment_rva_tree;
    metadata_tree_t segment_file_tree;
    metadata_tree_t member_file_tree;
    mutable atomic_query_counters_t counters;
};

namespace {

const std::vector<interval_entry_t>& intervals_for(const image_layout_index_t::state_t& state,
                                                    address_space_id_t space) {
    if (space == address_space_id_t::relative_virtual)
        return state.rva_intervals;
    if (space == address_space_id_t::virtual_address)
        return state.va_intervals;
    return state.file_intervals;
}

void append_matches(const metadata_tree_t& tree, std::uint64_t value,
                    atomic_query_counters_t& counters, std::vector<std::uint32_t>& ids) {
    collect_metadata_matches(tree.root.get(), value, counters, ids);
}

void populate_metadata(const image_layout_index_t::state_t& state,
                       const image_layout_mapping_t& mapping, image_layout_lookup_t& lookup) {
    append_matches(state.section_rva_tree, lookup.rva, state.counters, lookup.section_ids);
    append_matches(state.segment_rva_tree, lookup.rva, state.counters, lookup.segment_ids);
    if (lookup.file_offset) {
        append_matches(state.section_file_tree, *lookup.file_offset, state.counters, lookup.section_ids);
        append_matches(state.segment_file_tree, *lookup.file_offset, state.counters, lookup.segment_ids);
        append_matches(state.member_file_tree, *lookup.file_offset, state.counters, lookup.member_ids);
    }
    if (mapping.section_id)
        lookup.section_ids.push_back(*mapping.section_id);
    if (mapping.segment_id)
        lookup.segment_ids.push_back(*mapping.segment_id);
    if (mapping.member_id)
        lookup.member_ids.push_back(*mapping.member_id);
    normalize_ids(lookup.section_ids, state.counters);
    normalize_ids(lookup.segment_ids, state.counters);
    normalize_ids(lookup.member_ids, state.counters);
    lookup.ambiguous = lookup.section_ids.size() > 1U || lookup.segment_ids.size() > 1U ||
                       lookup.member_ids.size() > 1U;
}

workspace_result_t<std::optional<image_layout_lookup_t>> lookup_impl(
    const image_layout_index_t::state_t& state, address_space_id_t space, std::uint64_t value) {
    const auto& intervals = intervals_for(state, space);
    const auto mapping_index = find_mapping(intervals, value, state.counters);
    if (!mapping_index)
        return workspace_result_t<std::optional<image_layout_lookup_t>>::success(std::nullopt);

    const auto& mapping = state.definition.mappings[*mapping_index];
    std::uint64_t delta = 0;
    if (space == address_space_id_t::relative_virtual)
        delta = value - mapping.rva;
    else if (space == address_space_id_t::virtual_address)
        delta = value - mapping.virtual_address;
    else
        delta = value - mapping.file_offset;

    image_layout_lookup_t lookup;
    lookup.queried_space = space;
    lookup.queried_value = value;
    lookup.mapping_id = mapping.id;
    lookup.rva = mapping.rva + delta;
    lookup.virtual_address = mapping.virtual_address + delta;
    lookup.permissions = mapping.permissions;
    if (space == address_space_id_t::file_offset || delta < mapping.file_size)
        lookup.file_offset = mapping.file_offset + delta;
    lookup.zero_fill = space != address_space_id_t::file_offset && delta >= mapping.file_size;
    populate_metadata(state, mapping, lookup);
    return workspace_result_t<std::optional<image_layout_lookup_t>>::success(std::move(lookup));
}

void increment_space_query_counter(atomic_query_counters_t& counters, address_space_id_t space) noexcept {
    if (space == address_space_id_t::virtual_address)
        counters.va_queries.fetch_add(1, std::memory_order_relaxed);
    else if (space == address_space_id_t::relative_virtual)
        counters.rva_queries.fetch_add(1, std::memory_order_relaxed);
    else
        counters.file_queries.fetch_add(1, std::memory_order_relaxed);
}

void increment_point_query_counter(atomic_query_counters_t& counters, address_space_id_t space) noexcept {
    counters.queries.fetch_add(1, std::memory_order_relaxed);
    counters.point_queries.fetch_add(1, std::memory_order_relaxed);
    increment_space_query_counter(counters, space);
}

void increment_interval_query_counter(atomic_query_counters_t& counters, address_space_id_t space) noexcept {
    counters.queries.fetch_add(1, std::memory_order_relaxed);
    counters.interval_queries.fetch_add(1, std::memory_order_relaxed);
    increment_space_query_counter(counters, space);
}

}

bool image_layout_identity_t::operator==(const image_layout_identity_t& other) const noexcept {
    return content_id.bytes == other.content_id.bytes && format == other.format && endian == other.endian &&
           address_width_bits == other.address_width_bits && image_base == other.image_base &&
           provider_size == other.provider_size && member == other.member;
}

bool image_layout_identity_t::operator!=(const image_layout_identity_t& other) const noexcept {
    return !(*this == other);
}

std::vector<std::uint8_t> image_layout_identity_t::canonical_bytes() const {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(96U + (member ? member->normalized_member_path.size() : 0U));
    const auto append_u8 = [&bytes](std::uint8_t value) {
        bytes.push_back(value);
    };
    const auto append_u32 = [&append_u8](std::uint32_t value) {
        append_u8(static_cast<std::uint8_t>(value >> 24U));
        append_u8(static_cast<std::uint8_t>(value >> 16U));
        append_u8(static_cast<std::uint8_t>(value >> 8U));
        append_u8(static_cast<std::uint8_t>(value));
    };
    const auto append_u64 = [&append_u8](std::uint64_t value) {
        for (std::uint32_t shift = 56U;; shift -= 8U) {
            append_u8(static_cast<std::uint8_t>(value >> shift));
            if (shift == 0)
                break;
        }
    };
    append_u32(1U);
    bytes.insert(bytes.end(), content_id.bytes.begin(), content_id.bytes.end());
    append_u8(static_cast<std::uint8_t>(format));
    append_u8(static_cast<std::uint8_t>(endian));
    append_u8(address_width_bits);
    append_u64(image_base);
    append_u64(provider_size);
    append_u8(member ? 1U : 0U);
    if (member) {
        append_u64(member->container_offset);
        append_u64(member->compressed_size);
        append_u64(member->uncompressed_size);
        append_u64(member->ordinal);
        append_u32(member->depth);
        append_u32(member->crc32);
        append_u8(member->compressed ? 1U : 0U);
        append_u64(member->normalized_member_path.size());
        bytes.insert(bytes.end(), member->normalized_member_path.begin(), member->normalized_member_path.end());
    }
    return bytes;
}

std::uint64_t image_layout_identity_t::canonical_hash() const {
    std::uint64_t hash = 14695981039346656037ULL;
    for (const auto byte : canonical_bytes()) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

image_layout_index_t::image_layout_index_t(std::shared_ptr<const state_t> state) noexcept
    : state_(std::move(state)) {
}

image_layout_index_t::~image_layout_index_t() = default;

workspace_result_t<image_layout_index_t> image_layout_index_t::build(image_layout_definition_t definition) {
    const auto& identity = definition.identity;
    if (std::all_of(identity.content_id.bytes.begin(), identity.content_id.bytes.end(),
                    [](std::uint8_t value) { return value == 0; }))
        return layout_failure<image_layout_index_t>(workspace_error_code_t::invalid_argument,
                                                    "image layout identity requires a content identifier", "identity");
    if (identity.address_width_bits != 32U && identity.address_width_bits != 64U)
        return layout_failure<image_layout_index_t>(workspace_error_code_t::invalid_argument,
                                                    "image layout identity address width must be 32 or 64", "identity");
    if (!fits_address_width(identity.image_base, 1U, identity.address_width_bits))
        return layout_failure<image_layout_index_t>(workspace_error_code_t::range_overflow,
                                                    "image layout image base exceeds address width", "identity",
                                                    identity.image_base, 1U);
    if (!ids_are_unique(definition.mappings))
        return layout_failure<image_layout_index_t>(workspace_error_code_t::malformed_image,
                                                    "image layout mapping identifiers must be unique", "mappings");

    const auto section_status = validate_named_virtual_ranges(definition.sections, identity, "sections");
    if (!section_status)
        return layout_failure<image_layout_index_t>(section_status.error().code, section_status.error().message,
                                                    section_status.error().phase, section_status.error().offset,
                                                    section_status.error().size);
    const auto segment_status = validate_named_virtual_ranges(definition.segments, identity, "segments");
    if (!segment_status)
        return layout_failure<image_layout_index_t>(segment_status.error().code, segment_status.error().message,
                                                    segment_status.error().phase, segment_status.error().offset,
                                                    segment_status.error().size);
    const auto member_status = validate_members(definition.members, identity);
    if (!member_status)
        return layout_failure<image_layout_index_t>(member_status.error().code, member_status.error().message,
                                                    member_status.error().phase, member_status.error().offset,
                                                    member_status.error().size);

    const auto section_ids = collect_ids(definition.sections);
    const auto segment_ids = collect_ids(definition.segments);
    const auto member_ids = collect_ids(definition.members);
    auto state = std::make_shared<state_t>();
    state->definition = std::move(definition);
    state->rva_intervals.reserve(state->definition.mappings.size());
    state->va_intervals.reserve(state->definition.mappings.size());
    state->file_intervals.reserve(state->definition.mappings.size());

    for (std::size_t index = 0; index < state->definition.mappings.size(); ++index) {
        const auto& mapping = state->definition.mappings[index];
        if (mapping.virtual_size == 0)
            return layout_failure<image_layout_index_t>(workspace_error_code_t::malformed_image,
                                                        "image layout mappings must have non-empty virtual ranges", "mappings");
        if (mapping.file_size > mapping.virtual_size)
            return layout_failure<image_layout_index_t>(workspace_error_code_t::malformed_image,
                                                        "image layout mapping file range exceeds virtual range", "mappings",
                                                        mapping.file_offset, mapping.file_size);
        if (!permissions_valid(mapping.permissions))
            return layout_failure<image_layout_index_t>(workspace_error_code_t::malformed_image,
                                                        "image layout mapping has unknown permissions", "mappings");
        if (mapping.section_id && section_ids.find(*mapping.section_id) == section_ids.end())
            return layout_failure<image_layout_index_t>(workspace_error_code_t::malformed_image,
                                                        "image layout mapping references an unknown section", "mappings");
        if (mapping.segment_id && segment_ids.find(*mapping.segment_id) == segment_ids.end())
            return layout_failure<image_layout_index_t>(workspace_error_code_t::malformed_image,
                                                        "image layout mapping references an unknown segment", "mappings");
        if (mapping.member_id && member_ids.find(*mapping.member_id) == member_ids.end())
            return layout_failure<image_layout_index_t>(workspace_error_code_t::malformed_image,
                                                        "image layout mapping references an unknown member", "mappings");
        const auto rva_end = checked_range_end(mapping.rva, mapping.virtual_size, "mappings");
        if (!rva_end)
            return layout_failure<image_layout_index_t>(rva_end.error().code, rva_end.error().message,
                                                        rva_end.error().phase, rva_end.error().offset,
                                                        rva_end.error().size);
        const auto va_end = checked_range_end(mapping.virtual_address, mapping.virtual_size, "mappings");
        if (!va_end)
            return layout_failure<image_layout_index_t>(va_end.error().code, va_end.error().message,
                                                        va_end.error().phase, va_end.error().offset,
                                                        va_end.error().size);
        const auto file_end = checked_range_end(mapping.file_offset, mapping.file_size, "mappings");
        if (!file_end)
            return layout_failure<image_layout_index_t>(file_end.error().code, file_end.error().message,
                                                        file_end.error().phase, file_end.error().offset,
                                                        file_end.error().size);
        std::uint64_t expected_va = 0;
        if (!checked_add_u64(identity.image_base, mapping.rva, expected_va))
            return layout_failure<image_layout_index_t>(workspace_error_code_t::range_overflow,
                                                        "image layout image base plus RVA exceeds 64-bit address space", "mappings",
                                                        identity.image_base, mapping.rva);
        if (expected_va != mapping.virtual_address)
            return layout_failure<image_layout_index_t>(workspace_error_code_t::malformed_image,
                                                        "image layout virtual address does not match image base plus RVA", "mappings",
                                                        mapping.virtual_address, mapping.virtual_size);
        if (!fits_address_width(mapping.rva, mapping.virtual_size, identity.address_width_bits) ||
            !fits_address_width(mapping.virtual_address, mapping.virtual_size, identity.address_width_bits))
            return layout_failure<image_layout_index_t>(workspace_error_code_t::range_overflow,
                                                        "image layout mapping exceeds address width", "mappings",
                                                        mapping.virtual_address, mapping.virtual_size);
        if (identity.provider_size != 0 && file_end.value() > identity.provider_size)
            return layout_failure<image_layout_index_t>(workspace_error_code_t::out_of_range,
                                                        "image layout mapping file range exceeds provider size", "mappings",
                                                        mapping.file_offset, mapping.file_size);
        state->rva_intervals.push_back({mapping.rva, rva_end.value(), index});
        state->va_intervals.push_back({mapping.virtual_address, va_end.value(), index});
        if (mapping.file_size != 0)
            state->file_intervals.push_back({mapping.file_offset, file_end.value(), index});
    }

    const auto interval_order = [](const interval_entry_t& lhs, const interval_entry_t& rhs) {
        if (lhs.first != rhs.first)
            return lhs.first < rhs.first;
        if (lhs.last != rhs.last)
            return lhs.last < rhs.last;
        return lhs.mapping_index < rhs.mapping_index;
    };
    const auto validate_intervals = [&interval_order](std::vector<interval_entry_t>& intervals,
                                                       const char* phase) -> workspace_result_t<void> {
        std::sort(intervals.begin(), intervals.end(), interval_order);
        for (std::size_t index = 1; index < intervals.size(); ++index) {
            if (intervals[index].first < intervals[index - 1U].last)
                return workspace_result_t<void>::failure(layout_error(workspace_error_code_t::malformed_image,
                                                                       "image layout translation intervals overlap", phase,
                                                                       intervals[index].first,
                                                                       intervals[index].last - intervals[index].first));
        }
        return workspace_result_t<void>::success();
    };
    for (const auto& interval_set : std::array<std::pair<std::vector<interval_entry_t>*, const char*>, 3>{
             std::make_pair(&state->rva_intervals, "rva"),
             std::make_pair(&state->va_intervals, "va"),
             std::make_pair(&state->file_intervals, "file")}) {
        const auto status = validate_intervals(*interval_set.first, interval_set.second);
        if (!status)
            return layout_failure<image_layout_index_t>(status.error().code, status.error().message,
                                                        status.error().phase, status.error().offset,
                                                        status.error().size);
    }

    std::vector<metadata_interval_t> section_rva_intervals;
    std::vector<metadata_interval_t> section_file_intervals;
    section_rva_intervals.reserve(state->definition.sections.size());
    section_file_intervals.reserve(state->definition.sections.size());
    for (const auto& section : state->definition.sections) {
        const auto rva_end = checked_range_end(section.rva, section.virtual_size, "sections");
        section_rva_intervals.push_back({section.rva, rva_end.value(), section.id});
        if (section.file_size != 0) {
            const auto file_end = checked_range_end(section.file_offset, section.file_size, "sections");
            section_file_intervals.push_back({section.file_offset, file_end.value(), section.id});
        }
    }
    std::vector<metadata_interval_t> segment_rva_intervals;
    std::vector<metadata_interval_t> segment_file_intervals;
    segment_rva_intervals.reserve(state->definition.segments.size());
    segment_file_intervals.reserve(state->definition.segments.size());
    for (const auto& segment : state->definition.segments) {
        const auto rva_end = checked_range_end(segment.rva, segment.virtual_size, "segments");
        segment_rva_intervals.push_back({segment.rva, rva_end.value(), segment.id});
        if (segment.file_size != 0) {
            const auto file_end = checked_range_end(segment.file_offset, segment.file_size, "segments");
            segment_file_intervals.push_back({segment.file_offset, file_end.value(), segment.id});
        }
    }
    std::vector<metadata_interval_t> member_file_intervals;
    member_file_intervals.reserve(state->definition.members.size());
    for (const auto& member : state->definition.members) {
        const auto file_end = checked_range_end(member.file_offset, member.file_size, "members");
        member_file_intervals.push_back({member.file_offset, file_end.value(), member.id});
    }
    state->section_rva_tree = build_metadata_tree(std::move(section_rva_intervals));
    state->section_file_tree = build_metadata_tree(std::move(section_file_intervals));
    state->segment_rva_tree = build_metadata_tree(std::move(segment_rva_intervals));
    state->segment_file_tree = build_metadata_tree(std::move(segment_file_intervals));
    state->member_file_tree = build_metadata_tree(std::move(member_file_intervals));
    return workspace_result_t<image_layout_index_t>::success(image_layout_index_t(std::move(state)));
}

const image_layout_identity_t& image_layout_index_t::identity() const noexcept {
    return state_->definition.identity;
}

const std::vector<image_layout_mapping_t>& image_layout_index_t::mappings() const noexcept {
    return state_->definition.mappings;
}

const std::vector<image_layout_section_range_t>& image_layout_index_t::sections() const noexcept {
    return state_->definition.sections;
}

const std::vector<image_layout_segment_range_t>& image_layout_index_t::segments() const noexcept {
    return state_->definition.segments;
}

const std::vector<image_layout_member_range_t>& image_layout_index_t::members() const noexcept {
    return state_->definition.members;
}

workspace_result_t<std::optional<image_layout_lookup_t>> image_layout_index_t::lookup(
    address_space_id_t space, std::uint64_t value) const {
    if (!state_)
        return layout_failure<std::optional<image_layout_lookup_t>>(workspace_error_code_t::integrity_failure,
                                                                     "image layout index has no state", "lookup");
    if (!is_layout_space(space))
        return layout_failure<std::optional<image_layout_lookup_t>>(workspace_error_code_t::unsupported_address_space,
                                                                     "image layout index does not support this address space", "lookup");
    increment_point_query_counter(state_->counters, space);
    return lookup_impl(*state_, space, value);
}

workspace_result_t<std::optional<image_layout_lookup_t>> image_layout_index_t::lookup_va(std::uint64_t value) const {
    return lookup(address_space_id_t::virtual_address, value);
}

workspace_result_t<std::optional<image_layout_lookup_t>> image_layout_index_t::lookup_rva(std::uint64_t value) const {
    return lookup(address_space_id_t::relative_virtual, value);
}

workspace_result_t<std::optional<image_layout_lookup_t>> image_layout_index_t::lookup_file_offset(
    std::uint64_t value) const {
    return lookup(address_space_id_t::file_offset, value);
}

workspace_result_t<image_layout_interval_lookup_t> image_layout_index_t::lookup_interval(
    address_space_id_t space, std::uint64_t start, std::uint64_t size) const {
    if (!state_)
        return layout_failure<image_layout_interval_lookup_t>(workspace_error_code_t::integrity_failure,
                                                              "image layout index has no state", "interval");
    if (!is_layout_space(space))
        return layout_failure<image_layout_interval_lookup_t>(workspace_error_code_t::unsupported_address_space,
                                                              "image layout index does not support this address space", "interval");
    if (size == 0)
        return layout_failure<image_layout_interval_lookup_t>(workspace_error_code_t::invalid_argument,
                                                              "image layout interval size must be non-zero", "interval",
                                                              start, size);
    const auto end = checked_range_end(start, size, "interval");
    if (!end)
        return layout_failure<image_layout_interval_lookup_t>(end.error().code, end.error().message,
                                                              end.error().phase, end.error().offset, end.error().size);

    increment_interval_query_counter(state_->counters, space);
    image_layout_interval_lookup_t result;
    result.queried_space = space;
    result.start = start;
    result.size = size;
    result.complete = true;
    std::uint64_t cursor = start;
    const auto& intervals = intervals_for(*state_, space);
    while (cursor < end.value()) {
        const auto point = lookup_impl(*state_, space, cursor);
        if (!point)
            return layout_failure<image_layout_interval_lookup_t>(point.error().code, point.error().message,
                                                                  point.error().phase, point.error().offset,
                                                                  point.error().size);
        image_layout_interval_slice_t slice;
        slice.start = cursor;
        if (point.value()) {
            slice.lookup = *point.value();
            const auto& mapping = state_->definition.mappings[find_mapping(intervals, cursor, state_->counters).value()];
            std::uint64_t mapping_end = 0;
            std::uint64_t initialized_end = 0;
            if (space == address_space_id_t::relative_virtual) {
                mapping_end = mapping.rva + mapping.virtual_size;
                initialized_end = mapping.rva + mapping.file_size;
            } else if (space == address_space_id_t::virtual_address) {
                mapping_end = mapping.virtual_address + mapping.virtual_size;
                initialized_end = mapping.virtual_address + mapping.file_size;
            } else {
                mapping_end = mapping.file_offset + mapping.file_size;
                initialized_end = mapping_end;
            }
            std::uint64_t slice_end = std::min(end.value(), mapping_end);
            if (space != address_space_id_t::file_offset && cursor < initialized_end && initialized_end < slice_end)
                slice_end = initialized_end;
            slice.size = slice_end - cursor;
            result.ambiguous = result.ambiguous || slice.lookup->ambiguous;
        } else {
            result.complete = false;
            const auto next = next_mapping_start(intervals, cursor, state_->counters);
            const std::uint64_t slice_end = next ? std::min(end.value(), *next) : end.value();
            slice.size = slice_end - cursor;
        }
        result.slices.push_back(std::move(slice));
        cursor += result.slices.back().size;
    }
    return workspace_result_t<image_layout_interval_lookup_t>::success(std::move(result));
}

image_layout_query_counters_t image_layout_index_t::query_counters() const noexcept {
    if (!state_)
        return {};
    const auto& counters = state_->counters;
    image_layout_query_counters_t snapshot;
    snapshot.queries = counters.queries.load(std::memory_order_relaxed);
    snapshot.point_queries = counters.point_queries.load(std::memory_order_relaxed);
    snapshot.interval_queries = counters.interval_queries.load(std::memory_order_relaxed);
    snapshot.va_queries = counters.va_queries.load(std::memory_order_relaxed);
    snapshot.rva_queries = counters.rva_queries.load(std::memory_order_relaxed);
    snapshot.file_queries = counters.file_queries.load(std::memory_order_relaxed);
    snapshot.mapping_binary_search_steps = counters.mapping_binary_search_steps.load(std::memory_order_relaxed);
    snapshot.mapping_candidate_checks = counters.mapping_candidate_checks.load(std::memory_order_relaxed);
    snapshot.metadata_binary_search_steps = counters.metadata_binary_search_steps.load(std::memory_order_relaxed);
    snapshot.metadata_matches = counters.metadata_matches.load(std::memory_order_relaxed);
    return snapshot;
}

}
