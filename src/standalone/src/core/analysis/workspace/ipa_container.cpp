#include "ipa_container.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

workspace_error_t ipa_error(workspace_error_code_t code, std::string message,
                            std::string phase) {
    return make_workspace_error(code, std::move(message), std::move(phase));
}

workspace_error_t ipa_stop_error(const cancellation_token_t& cancel,
                                 std::string phase) {
    const bool deadline = cancel.deadline_exceeded();
    auto error = ipa_error(deadline ? workspace_error_code_t::deadline_exceeded
                                    : workspace_error_code_t::cancelled,
                           deadline ? "IPA processing deadline exceeded"
                                    : "IPA processing cancelled",
                           std::move(phase));
    error.deadline = deadline;
    error.cancellation = !deadline;
    return error;
}

workspace_error_t ipa_member_error(workspace_error_t error,
                                   std::string_view member_path) {
    error.details.emplace_back("ipa_member", std::string(member_path));
    return error;
}

bool has_suffix(std::string_view value, std::string_view suffix) noexcept {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string_view remove_suffix(std::string_view value,
                               std::string_view suffix) noexcept {
    return has_suffix(value, suffix)
        ? value.substr(0, value.size() - suffix.size()) : std::string_view{};
}

std::vector<std::string_view> split_normalized_path(std::string_view value) {
    std::vector<std::string_view> result;
    std::size_t offset = 0;
    while (offset < value.size()) {
        const std::size_t separator = value.find('/', offset);
        const std::size_t end = separator == std::string_view::npos
            ? value.size() : separator;
        if (end == offset)
            return {};
        result.push_back(value.substr(offset, end - offset));
        if (separator == std::string_view::npos)
            break;
        offset = separator + 1;
    }
    return result;
}

std::string join_path(const std::vector<std::string_view>& components,
                      std::size_t inclusive_index) {
    std::size_t size = 0;
    for (std::size_t index = 0; index <= inclusive_index; ++index)
        size += components[index].size() + (index == 0 ? 0 : 1);
    std::string result;
    result.reserve(size);
    for (std::size_t index = 0; index <= inclusive_index; ++index) {
        if (index != 0)
            result.push_back('/');
        result.append(components[index].data(), components[index].size());
    }
    return result;
}

enum class macho_magic_kind_t : std::uint8_t {
    none = 0,
    thin = 1,
    fat = 2
};

workspace_result_t<macho_magic_kind_t> probe_macho_magic(
    const byte_provider_t& provider, const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<macho_magic_kind_t>::failure(
            ipa_stop_error(cancel, "ipa.macho_probe"));
    if (provider.size() < 4)
        return workspace_result_t<macho_magic_kind_t>::success(macho_magic_kind_t::none);
    auto lease_result = provider.lease(0, 4, cancel);
    if (!lease_result)
        return workspace_result_t<macho_magic_kind_t>::failure(
            std::move(lease_result.error()));
    const auto& view = lease_result.value();
    const std::array<std::uint8_t, 4> bytes{
        view[0], view[1], view[2], view[3]};
    constexpr std::array<std::array<std::uint8_t, 4>, 4> thin_magics{{
        {{0xfeU, 0xedU, 0xfaU, 0xceU}},
        {{0xceU, 0xfaU, 0xedU, 0xfeU}},
        {{0xfeU, 0xedU, 0xfaU, 0xcfU}},
        {{0xcfU, 0xfaU, 0xedU, 0xfeU}}
    }};
    constexpr std::array<std::array<std::uint8_t, 4>, 4> fat_magics{{
        {{0xcaU, 0xfeU, 0xbaU, 0xbeU}},
        {{0xbeU, 0xbaU, 0xfeU, 0xcaU}},
        {{0xcaU, 0xfeU, 0xbaU, 0xbfU}},
        {{0xbfU, 0xbaU, 0xfeU, 0xcaU}}
    }};
    if (std::find(thin_magics.begin(), thin_magics.end(), bytes) != thin_magics.end())
        return workspace_result_t<macho_magic_kind_t>::success(macho_magic_kind_t::thin);
    if (std::find(fat_magics.begin(), fat_magics.end(), bytes) != fat_magics.end())
        return workspace_result_t<macho_magic_kind_t>::success(macho_magic_kind_t::fat);
    return workspace_result_t<macho_magic_kind_t>::success(macho_magic_kind_t::none);
}

struct ipa_path_classification_t {
    ipa_member_role_t role = ipa_member_role_t::app_executable;
    std::string bundle_path_hint;
    std::string bundle_name_hint;
    std::string enclosing_app_bundle_path;
};

std::optional<ipa_path_classification_t> classify_ipa_path(
    std::string_view normalized_path) {
    const auto components = split_normalized_path(normalized_path);
    if (components.size() < 3 || components[0] != "Payload" ||
        !has_suffix(components[1], ".app"))
        return std::nullopt;

    const std::string enclosing_app = join_path(components, 1);
    const auto make_classification = [&](ipa_member_role_t role, std::size_t bundle_index,
                                         std::string_view suffix) {
        ipa_path_classification_t result;
        result.role = role;
        result.bundle_path_hint = join_path(components, bundle_index);
        result.bundle_name_hint = std::string(remove_suffix(components[bundle_index], suffix));
        result.enclosing_app_bundle_path = enclosing_app;
        return result;
    };

    for (std::size_t index = 2; index + 4 < components.size(); ++index) {
        if (!has_suffix(components[index], ".dSYM"))
            continue;
        if (components[index + 1] == "Contents" &&
            components[index + 2] == "Resources" &&
            components[index + 3] == "DWARF") {
            return make_classification(ipa_member_role_t::debug_companion, index, ".dSYM");
        }
    }

    for (std::size_t cursor = components.size() - 1; cursor > 1; --cursor) {
        const std::size_t index = cursor - 1;
        if (!has_suffix(components[index], ".framework"))
            continue;
        const std::string_view framework_name = remove_suffix(components[index], ".framework");
        if (components.back() == framework_name)
            return make_classification(ipa_member_role_t::framework_executable,
                                       index, ".framework");
        break;
    }

    if (has_suffix(components.back(), ".dylib")) {
        std::size_t dylib_bundle_index = 1;
        for (std::size_t index = components.size() - 1; index > 1; --index) {
            if (has_suffix(components[index - 1], ".app") ||
                has_suffix(components[index - 1], ".appex") ||
                has_suffix(components[index - 1], ".bundle")) {
                dylib_bundle_index = index - 1;
                break;
            }
        }
        return make_classification(ipa_member_role_t::dynamic_library,
                                   dylib_bundle_index,
                                   has_suffix(components[dylib_bundle_index], ".appex")
                                       ? ".appex"
                                       : has_suffix(components[dylib_bundle_index], ".bundle")
                                           ? ".bundle"
                                           : ".app");
    }

    if (components.size() == 3)
        return make_classification(ipa_member_role_t::app_executable, 1, ".app");

    const std::size_t parent_index = components.size() - 2;
    if (has_suffix(components[parent_index], ".appex"))
        return make_classification(ipa_member_role_t::app_extension_executable,
                                   parent_index, ".appex");
    if (has_suffix(components[parent_index], ".bundle"))
        return make_classification(ipa_member_role_t::bundle_executable,
                                   parent_index, ".bundle");
    if (has_suffix(components[parent_index], ".app"))
        return make_classification(ipa_member_role_t::app_executable,
                                   parent_index, ".app");
    return std::nullopt;
}

workspace_result_t<void> validate_limits(const ipa_container_limits_t& limits) {
    if (limits.max_macho_candidate_members == 0 ||
        limits.max_macho_candidate_aggregate_uncompressed_size == 0) {
        return workspace_result_t<void>::failure(ipa_error(
            workspace_error_code_t::invalid_argument,
            "IPA Mach-O candidate limits are invalid", "ipa.open"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> consume_macho_candidate_budget(
    const ipa_container_limits_t& limits, const zip_member_t& member,
    std::uint64_t& candidate_count, std::uint64_t& candidate_size) {
    if (candidate_count == limits.max_macho_candidate_members) {
        auto error = ipa_error(workspace_error_code_t::limit_exceeded,
                               "IPA Mach-O candidate count exceeds its budget",
                               "ipa.enumerate");
        error.details.emplace_back("limit",
                                   std::to_string(limits.max_macho_candidate_members));
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (member.uncompressed_size >
        limits.max_macho_candidate_aggregate_uncompressed_size - candidate_size) {
        auto error = ipa_error(workspace_error_code_t::limit_exceeded,
                               "IPA Mach-O candidate bytes exceed their budget",
                               "ipa.enumerate");
        error.size = member.uncompressed_size;
        error.details.emplace_back(
            "limit", std::to_string(limits.max_macho_candidate_aggregate_uncompressed_size));
        return workspace_result_t<void>::failure(std::move(error));
    }
    ++candidate_count;
    candidate_size += member.uncompressed_size;
    return workspace_result_t<void>::success();
}

workspace_result_t<ipa_member_t> parse_ipa_member(
    const zip_container_t& zip, std::size_t zip_member_index,
    const ipa_path_classification_t& classification,
    const ipa_container_limits_t& limits, const cancellation_token_t& cancel) {
    const auto& zip_member = zip.members()[zip_member_index];
    auto provider_result = zip.open_member_provider(zip_member_index, cancel);
    if (!provider_result)
        return workspace_result_t<ipa_member_t>::failure(
            ipa_member_error(std::move(provider_result.error()), zip_member.normalized_path));
    auto provider = provider_result.take_value();
    auto magic_result = probe_macho_magic(*provider, cancel);
    if (!magic_result)
        return workspace_result_t<ipa_member_t>::failure(
            ipa_member_error(std::move(magic_result.error()), zip_member.normalized_path));
    if (magic_result.value() == macho_magic_kind_t::none) {
        return workspace_result_t<ipa_member_t>::failure(ipa_error(
            workspace_error_code_t::unsupported_format,
            "IPA member is not a Mach-O image", "ipa.macho_probe"));
    }

    ipa_member_t result;
    result.normalized_path = zip_member.normalized_path;
    result.bundle_path_hint = classification.bundle_path_hint;
    result.bundle_name_hint = classification.bundle_name_hint;
    result.enclosing_app_bundle_path = classification.enclosing_app_bundle_path;
    result.provider_metadata = zip_member.provenance;
    result.zip_member_index = zip_member_index;
    result.role = classification.role;

    if (magic_result.value() == macho_magic_kind_t::thin) {
        auto image_result = parse_macho(*provider, limits.macho, cancel);
        if (!image_result)
            return workspace_result_t<ipa_member_t>::failure(
                ipa_member_error(std::move(image_result.error()), zip_member.normalized_path));
        const auto& image = image_result.value();
        if (!image || image->format != format_id_t::macho ||
            image->architecture == architecture_id_t::unknown) {
            return workspace_result_t<ipa_member_t>::failure(ipa_error(
                workspace_error_code_t::malformed_image,
                "IPA thin Mach-O normalization is invalid", "ipa.macho_parse"));
        }
        result.format = format_id_t::macho;
        result.architecture = image->architecture;
        ipa_macho_slice_provenance_t slice;
        slice.offset = 0;
        slice.size = provider->size();
        slice.architecture = image->architecture;
        result.slices.push_back(slice);
        return workspace_result_t<ipa_member_t>::success(std::move(result));
    }

    auto fat_result = parse_fat_macho(*provider, limits.macho, cancel);
    if (!fat_result)
        return workspace_result_t<ipa_member_t>::failure(
            ipa_member_error(std::move(fat_result.error()), zip_member.normalized_path));
    const auto& fat = fat_result.value();
    if (fat.slices.empty()) {
        return workspace_result_t<ipa_member_t>::failure(ipa_error(
            workspace_error_code_t::malformed_image,
            "IPA fat Mach-O contains no slices", "ipa.macho_parse"));
    }
    result.format = format_id_t::macho_fat;
    result.fat_macho = true;
    result.slices.reserve(fat.slices.size());
    for (std::size_t index = 0; index < fat.slices.size(); ++index) {
        if (cancel.stop_requested())
            return workspace_result_t<ipa_member_t>::failure(
                ipa_stop_error(cancel, "ipa.macho_parse"));
        const auto& source_slice = fat.slices[index];
        if (!source_slice.image ||
            source_slice.architecture == architecture_id_t::unknown) {
            return workspace_result_t<ipa_member_t>::failure(ipa_error(
                workspace_error_code_t::malformed_image,
                "IPA fat Mach-O slice normalization is invalid", "ipa.macho_parse"));
        }
        ipa_macho_slice_provenance_t slice;
        slice.ordinal = static_cast<std::uint32_t>(index);
        slice.cpu_type = source_slice.cputype;
        slice.cpu_subtype = source_slice.cpusubtype;
        slice.offset = source_slice.offset;
        slice.size = source_slice.size;
        slice.alignment = source_slice.align;
        slice.architecture = source_slice.architecture;
        slice.cpu_type_available = true;
        result.slices.push_back(std::move(slice));
    }
    return workspace_result_t<ipa_member_t>::success(std::move(result));
}

bool is_not_macho_probe_failure(const workspace_error_t& error) noexcept {
    return error.code == workspace_error_code_t::unsupported_format &&
           error.phase == "ipa.macho_probe";
}

}

struct ipa_container_t::state_t {
    state_t(std::shared_ptr<zip_container_t> zip_value, ipa_container_limits_t limits_value,
            std::vector<ipa_member_t> members_value,
            std::unordered_map<std::string, std::size_t> member_by_path_value)
        : zip(std::move(zip_value)), limits(std::move(limits_value)),
          members(std::move(members_value)),
          member_by_path(std::move(member_by_path_value)) {}

    std::shared_ptr<zip_container_t> zip;
    ipa_container_limits_t limits;
    std::vector<ipa_member_t> members;
    std::unordered_map<std::string, std::size_t> member_by_path;
};

ipa_container_t::ipa_container_t(std::shared_ptr<const state_t> state)
    : state_(std::move(state)) {}

workspace_result_t<std::shared_ptr<ipa_container_t>> ipa_container_t::open(
    std::shared_ptr<const byte_provider_t> provider, ipa_container_limits_t limits,
    const cancellation_token_t& cancel) {
    if (!provider) {
        return workspace_result_t<std::shared_ptr<ipa_container_t>>::failure(ipa_error(
            workspace_error_code_t::invalid_argument, "IPA source provider is null",
            "ipa.open"));
    }
    if (cancel.stop_requested()) {
        return workspace_result_t<std::shared_ptr<ipa_container_t>>::failure(
            ipa_stop_error(cancel, "ipa.open"));
    }
    auto limits_result = validate_limits(limits);
    if (!limits_result)
        return workspace_result_t<std::shared_ptr<ipa_container_t>>::failure(
            std::move(limits_result.error()));
    try {
        auto zip_result = zip_container_t::open(std::move(provider), limits.zip, cancel);
        if (!zip_result)
            return workspace_result_t<std::shared_ptr<ipa_container_t>>::failure(
                std::move(zip_result.error()));
        auto zip = zip_result.take_value();
        std::vector<ipa_member_t> members;
        std::uint64_t candidate_count = 0;
        std::uint64_t candidate_size = 0;
        const auto& zip_members = zip->members();
        for (std::size_t index = 0; index < zip_members.size(); ++index) {
            if ((index & 127U) == 0U && cancel.stop_requested()) {
                return workspace_result_t<std::shared_ptr<ipa_container_t>>::failure(
                    ipa_stop_error(cancel, "ipa.enumerate"));
            }
            const auto& zip_member = zip_members[index];
            if (zip_member.kind != zip_member_kind_t::regular_file)
                continue;
            auto classification = classify_ipa_path(zip_member.normalized_path);
            if (!classification)
                continue;
            auto budget_result = consume_macho_candidate_budget(
                limits, zip_member, candidate_count, candidate_size);
            if (!budget_result) {
                return workspace_result_t<std::shared_ptr<ipa_container_t>>::failure(
                    ipa_member_error(std::move(budget_result.error()),
                                     zip_member.normalized_path));
            }
            auto member_result = parse_ipa_member(*zip, index, *classification,
                                                  limits, cancel);
            if (!member_result) {
                if (is_not_macho_probe_failure(member_result.error()))
                    continue;
                return workspace_result_t<std::shared_ptr<ipa_container_t>>::failure(
                    std::move(member_result.error()));
            }
            members.push_back(member_result.take_value());
        }
        if (members.empty()) {
            return workspace_result_t<std::shared_ptr<ipa_container_t>>::failure(ipa_error(
                workspace_error_code_t::unsupported_format,
                "IPA contains no code-bearing Mach-O members", "ipa.enumerate"));
        }
        std::sort(members.begin(), members.end(),
                  [](const ipa_member_t& lhs, const ipa_member_t& rhs) {
                      if (lhs.normalized_path != rhs.normalized_path)
                          return lhs.normalized_path < rhs.normalized_path;
                      return lhs.provider_metadata.ordinal < rhs.provider_metadata.ordinal;
                  });
        std::unordered_map<std::string, std::size_t> member_by_path;
        member_by_path.reserve(members.size());
        for (std::size_t index = 0; index < members.size(); ++index) {
            const auto inserted = member_by_path.emplace(members[index].normalized_path, index);
            if (!inserted.second) {
                auto error = ipa_error(workspace_error_code_t::integrity_failure,
                                       "IPA code member paths are not unique",
                                       "ipa.enumerate");
                error.details.emplace_back("member", members[index].normalized_path);
                return workspace_result_t<std::shared_ptr<ipa_container_t>>::failure(
                    std::move(error));
            }
        }
        auto state = std::make_shared<state_t>(std::move(zip), std::move(limits),
                                               std::move(members),
                                               std::move(member_by_path));
        return workspace_result_t<std::shared_ptr<ipa_container_t>>::success(
            std::shared_ptr<ipa_container_t>(new ipa_container_t(std::move(state))));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<ipa_container_t>>::failure(ipa_error(
            workspace_error_code_t::limit_exceeded,
            "IPA processing allocation failed", "ipa.open"));
    } catch (const std::length_error&) {
        return workspace_result_t<std::shared_ptr<ipa_container_t>>::failure(ipa_error(
            workspace_error_code_t::limit_exceeded,
            "IPA processing allocation length is unsupported", "ipa.open"));
    }
}

const byte_provider_identity_t& ipa_container_t::source_identity() const noexcept {
    return state_->zip->source_identity();
}

const std::shared_ptr<const byte_provider_t>&
ipa_container_t::source_provider() const noexcept {
    return state_->zip->source_provider();
}

const ipa_container_limits_t& ipa_container_t::limits() const noexcept {
    return state_->limits;
}

const std::vector<ipa_member_t>& ipa_container_t::members() const noexcept {
    return state_->members;
}

const ipa_member_t* ipa_container_t::find_member(
    std::string_view normalized_path) const {
    if (normalized_path.empty() ||
        normalized_path.size() > state_->limits.zip.max_normalized_path_size)
        return nullptr;
    const auto found = state_->member_by_path.find(std::string(normalized_path));
    return found == state_->member_by_path.end() ? nullptr : &state_->members[found->second];
}

workspace_result_t<std::shared_ptr<byte_provider_t>>
ipa_container_t::open_member_provider(
    std::size_t member_index, const cancellation_token_t& cancel) const {
    if (member_index >= state_->members.size()) {
        auto error = ipa_error(workspace_error_code_t::out_of_range,
                               "IPA member index is out of range",
                               "ipa.member_open");
        error.offset = member_index;
        error.details.emplace_back("member_count", std::to_string(state_->members.size()));
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            std::move(error));
    }
    if (cancel.stop_requested()) {
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            ipa_stop_error(cancel, "ipa.member_open"));
    }
    const auto& member = state_->members[member_index];
    auto provider_result = state_->zip->open_member_provider(member.zip_member_index, cancel);
    if (!provider_result)
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            ipa_member_error(std::move(provider_result.error()), member.normalized_path));
    auto provider = provider_result.take_value();
    if (!provider || !provider->member_metadata() ||
        *provider->member_metadata() != member.provider_metadata) {
        auto error = ipa_error(workspace_error_code_t::provider_binding_mismatch,
                               "IPA member provider provenance does not match",
                               "ipa.member_open");
        error.details.emplace_back("ipa_member", member.normalized_path);
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            std::move(error));
    }
    return workspace_result_t<std::shared_ptr<byte_provider_t>>::success(std::move(provider));
}

workspace_result_t<std::shared_ptr<byte_provider_t>>
ipa_container_t::open_member_provider(
    std::string_view normalized_path, const cancellation_token_t& cancel) const {
    if (normalized_path.empty() ||
        normalized_path.size() > state_->limits.zip.max_normalized_path_size) {
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(ipa_error(
            workspace_error_code_t::invalid_argument,
            "IPA normalized member path is invalid", "ipa.member_open"));
    }
    try {
        const auto found = state_->member_by_path.find(std::string(normalized_path));
        if (found == state_->member_by_path.end()) {
            auto error = ipa_error(workspace_error_code_t::target_not_found,
                                   "IPA code member was not found", "ipa.member_open");
            error.details.emplace_back("member", std::string(normalized_path));
            return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
                std::move(error));
        }
        return open_member_provider(found->second, cancel);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(ipa_error(
            workspace_error_code_t::limit_exceeded,
            "IPA member lookup allocation failed", "ipa.member_open"));
    } catch (const std::length_error&) {
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(ipa_error(
            workspace_error_code_t::limit_exceeded,
            "IPA member lookup allocation length is unsupported", "ipa.member_open"));
    }
}

}
