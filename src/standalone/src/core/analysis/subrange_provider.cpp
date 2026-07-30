#include "subrange_provider.hpp"

#include "workspace/checked_range.hpp"

#include <algorithm>
#include <utility>

namespace aida::analysis {

workspace_result_t<std::shared_ptr<subrange_provider_t>> subrange_provider_t::create(
    std::shared_ptr<const byte_provider_t> parent, std::uint64_t base,
    std::uint64_t length, std::string identity_suffix) {
    if (!parent)
        return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "subrange parent is null", "subrange_create"));
    if (identity_suffix.empty() || identity_suffix.size() > 32768 ||
        identity_suffix.find('\0') != std::string::npos)
        return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "subrange identity suffix is invalid", "subrange_create"));
    auto range_result = validate_span(base, length, parent->size(), "subrange_create");
    if (!range_result)
        return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(range_result.error());
    byte_provider_identity_t identity = parent->identity();
    identity.normalized_source += "#" + identity_suffix;
    identity.size = length;
    if (base != 0 || length != parent->size())
        identity.content_sha256.reset();
    return workspace_result_t<std::shared_ptr<subrange_provider_t>>::success(
        std::shared_ptr<subrange_provider_t>(new subrange_provider_t(
            std::move(parent), base, length, std::move(identity))));
}

workspace_result_t<std::shared_ptr<subrange_provider_t>> subrange_provider_t::create_member(
    std::shared_ptr<const byte_provider_t> parent, std::uint64_t base,
    std::uint64_t length, provider_member_metadata_t member) {
    if (!parent)
        return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "member provider parent is null", "subrange_member_create"));
    if (member.normalized_member_path.empty() ||
        member.normalized_member_path.size() > 32768 ||
        member.normalized_member_path.front() == '/' ||
        member.normalized_member_path.find('\\') != std::string::npos ||
        member.normalized_member_path.find('\0') != std::string::npos ||
        member.compressed || member.container_offset != base ||
        member.uncompressed_size != length || member.compressed_size != length ||
        member.depth == 0 || member.depth > 64) {
        return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "member provider metadata is invalid", "subrange_member_create"));
    }
    const auto& parent_member = parent->member_metadata();
    if ((!parent_member && member.depth != 1) ||
        (parent_member &&
         (parent_member->depth >= 64 || member.depth != parent_member->depth + 1))) {
        return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "member provider depth is inconsistent with its parent",
                                 "subrange_member_create"));
    }
    std::size_t component_start = 0;
    while (component_start < member.normalized_member_path.size()) {
        const auto separator = member.normalized_member_path.find('/', component_start);
        const auto component_length = (separator == std::string::npos
            ? member.normalized_member_path.size() : separator) - component_start;
        if (component_length == 0 ||
            (component_length == 1 && member.normalized_member_path[component_start] == '.') ||
            (component_length == 2 && member.normalized_member_path[component_start] == '.' &&
             member.normalized_member_path[component_start + 1] == '.')) {
            return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                                     "member provider path is not normalized",
                                     "subrange_member_create"));
        }
        if (separator == std::string::npos)
            break;
        component_start = separator + 1;
    }
    auto range_result = validate_span(base, length, parent->size(), "subrange_member_create");
    if (!range_result)
        return workspace_result_t<std::shared_ptr<subrange_provider_t>>::failure(range_result.error());
    byte_provider_identity_t identity = parent->identity();
    identity.normalized_source += "#member:" + member.normalized_member_path;
    identity.size = length;
    if (base != 0 || length != parent->size())
        identity.content_sha256.reset();
    identity.member = std::move(member);
    return workspace_result_t<std::shared_ptr<subrange_provider_t>>::success(
        std::shared_ptr<subrange_provider_t>(new subrange_provider_t(
            std::move(parent), base, length, std::move(identity))));
}

subrange_provider_t::subrange_provider_t(std::shared_ptr<const byte_provider_t> parent,
                                         std::uint64_t base, std::uint64_t length,
                                         byte_provider_identity_t identity)
    : parent_(std::move(parent)), base_(base), length_(length), identity_(std::move(identity)) {}

std::uint64_t subrange_provider_t::maximum_contiguous_lease(std::uint64_t offset) const noexcept {
    if (offset > length_)
        return 0;
    std::uint64_t parent_offset = 0;
    if (!checked_add_u64(base_, offset, parent_offset))
        return 0;
    const std::uint64_t parent_capacity = parent_->maximum_contiguous_lease(parent_offset);
    return (std::min)(length_ - offset, parent_capacity);
}

bool subrange_provider_t::content_pin_active() const noexcept {
    return parent_->content_pin_active();
}

std::optional<mapped_window_cache_statistics_t>
subrange_provider_t::window_cache_statistics() const noexcept {
    return parent_->window_cache_statistics();
}

workspace_result_t<byte_view_t> subrange_provider_t::lease(
    std::uint64_t offset, std::uint64_t size_value,
    const cancellation_token_t& cancel) const {
    auto range_result = validate_span(offset, size_value, length_, "subrange_lease");
    if (!range_result)
        return workspace_result_t<byte_view_t>::failure(range_result.error());
    std::uint64_t parent_offset = 0;
    if (!checked_add_u64(base_, offset, parent_offset)) {
        auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                          "subrange parent offset overflowed", "subrange_lease");
        error.offset = offset;
        error.size = size_value;
        return workspace_result_t<byte_view_t>::failure(std::move(error));
    }
    if (size_value > maximum_contiguous_lease(offset)) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                          "subrange lease crosses its parent contiguous window",
                                          "subrange_lease");
        error.offset = offset;
        error.size = size_value;
        return workspace_result_t<byte_view_t>::failure(std::move(error));
    }
    auto parent_result = parent_->lease(parent_offset, size_value, cancel);
    if (!parent_result)
        return workspace_result_t<byte_view_t>::failure(parent_result.error());
    auto parent_view = parent_result.take_value();
    return workspace_result_t<byte_view_t>::success(
        byte_view_t(std::move(parent_view.lifetime_), parent_view.data_, parent_view.size_));
}

}
