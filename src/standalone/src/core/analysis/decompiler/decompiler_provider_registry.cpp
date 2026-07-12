#include "decompiler_provider_registry.hpp"

#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <utility>

namespace aida::analysis {
namespace {

bool valid_profile_id(const decompiler_profile_id_t profile) noexcept
{
    return profile == decompiler_profile_id_t::fast ||
           profile == decompiler_profile_id_t::balanced ||
           profile == decompiler_profile_id_t::thorough;
}

bool valid_registration_id(const std::string& value) noexcept
{
    return !value.empty() && value.size() <= 256 &&
           std::all_of(value.begin(), value.end(), [](const unsigned char character) {
               return character >= 0x21U && character <= 0x7eU;
           });
}

bool valid_provider_identity(const decompiler_provider_identity_t& value) noexcept
{
    return decompiler_provider_registry_t::expected_entity_kind(value.provider).has_value() &&
           !value.provider_name.empty() && !value.provider_version.empty() &&
           !value.provider_binary_hash.empty() && !value.worker_build_id.empty() &&
           !value.worker_build_hash.empty();
}

bool valid_language_identity(
    const decompiler_language_identity_t& language,
    const decompiler_entity_key_t& entity) noexcept
{
    return !language.language_id.empty() && !language.language_version.empty() &&
           !language.compiler_spec_id.empty() && !language.language_spec_hash.empty() &&
           language.architecture == entity.architecture && language.mode == entity.mode &&
           language.endian == entity.endian;
}

workspace_error_t registry_error(
    const workspace_error_code_t code,
    std::string message,
    std::string detail = {})
{
    auto error = make_workspace_error(code, std::move(message), "decompiler.provider_registry");
    if (!detail.empty())
        error.details.emplace_back("detail", std::move(detail));
    return error;
}

bool descriptor_order(
    const decompiler_provider_descriptor_t& left,
    const decompiler_provider_descriptor_t& right) noexcept
{
    if (left.entity_kind != right.entity_kind)
        return left.entity_kind < right.entity_kind;
    if (left.priority != right.priority)
        return left.priority > right.priority;
    return left.registration_id < right.registration_id;
}

workspace_result_t<decompiler_provider_descriptor_t> canonical_descriptor(
    const std::shared_ptr<decompiler_provider_t>& provider)
{
    if (!provider) {
        return workspace_result_t<decompiler_provider_descriptor_t>::failure(
            registry_error(workspace_error_code_t::invalid_argument, "provider is null"));
    }

    decompiler_provider_descriptor_t descriptor;
    try {
        descriptor = provider->descriptor();
    } catch (...) {
        return workspace_result_t<decompiler_provider_descriptor_t>::failure(
            registry_error(workspace_error_code_t::provider_unavailable, "provider descriptor failed"));
    }

    const auto expected = decompiler_provider_registry_t::expected_provider(descriptor.entity_kind);
    if (!valid_registration_id(descriptor.registration_id) || !valid_provider_identity(descriptor.identity) ||
        !expected || descriptor.identity.provider != *expected || descriptor.profiles.empty()) {
        return workspace_result_t<decompiler_provider_descriptor_t>::failure(
            registry_error(workspace_error_code_t::provider_binding_mismatch,
                           "provider descriptor is invalid", descriptor.registration_id));
    }

    std::sort(descriptor.profiles.begin(), descriptor.profiles.end());
    if (!std::all_of(descriptor.profiles.begin(), descriptor.profiles.end(), valid_profile_id) ||
        std::adjacent_find(descriptor.profiles.begin(), descriptor.profiles.end()) != descriptor.profiles.end()) {
        return workspace_result_t<decompiler_provider_descriptor_t>::failure(
            registry_error(workspace_error_code_t::provider_binding_mismatch,
                           "provider profile set is invalid", descriptor.registration_id));
    }

    return workspace_result_t<decompiler_provider_descriptor_t>::success(std::move(descriptor));
}

}

struct decompiler_provider_registry_t::state_t {
    struct entry_t {
        decompiler_provider_descriptor_t descriptor;
        std::shared_ptr<decompiler_provider_t> provider;
    };

    mutable std::shared_mutex mutex;
    std::vector<entry_t> entries;
    std::uint64_t revision = 0;
};

bool decompiler_provider_result_t::succeeded() const noexcept
{
    return status == decompiler_provider_execution_status_t::completed && artifacts.has_value();
}

decompiler_provider_registry_t::decompiler_provider_registry_t()
    : state_(std::make_shared<state_t>())
{
}

decompiler_provider_registry_t::~decompiler_provider_registry_t() = default;

workspace_result_t<void> decompiler_provider_registry_t::register_provider(
    std::shared_ptr<decompiler_provider_t> provider,
    const bool replace_existing)
{
    auto descriptor_result = canonical_descriptor(provider);
    if (!descriptor_result)
        return workspace_result_t<void>::failure(descriptor_result.error());
    auto descriptor = std::move(descriptor_result.value());

    std::unique_lock lock(state_->mutex);
    const auto existing = std::find_if(state_->entries.begin(), state_->entries.end(),
        [&descriptor](const state_t::entry_t& entry) {
            return entry.descriptor.registration_id == descriptor.registration_id;
        });
    if (existing != state_->entries.end() && !replace_existing) {
        return workspace_result_t<void>::failure(
            registry_error(workspace_error_code_t::service_conflict,
                           "provider registration already exists", descriptor.registration_id));
    }
    if (existing != state_->entries.end()) {
        existing->descriptor = std::move(descriptor);
        existing->provider = std::move(provider);
    } else {
        state_->entries.push_back({std::move(descriptor), std::move(provider)});
    }
    std::sort(state_->entries.begin(), state_->entries.end(),
        [](const state_t::entry_t& left, const state_t::entry_t& right) {
            return descriptor_order(left.descriptor, right.descriptor);
        });
    ++state_->revision;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> decompiler_provider_registry_t::unregister_provider(
    const std::string& registration_id)
{
    if (!valid_registration_id(registration_id)) {
        return workspace_result_t<void>::failure(
            registry_error(workspace_error_code_t::invalid_argument, "provider registration id is invalid"));
    }

    std::unique_lock lock(state_->mutex);
    const auto existing = std::find_if(state_->entries.begin(), state_->entries.end(),
        [&registration_id](const state_t::entry_t& entry) {
            return entry.descriptor.registration_id == registration_id;
        });
    if (existing == state_->entries.end()) {
        return workspace_result_t<void>::failure(
            registry_error(workspace_error_code_t::target_not_found,
                           "provider registration was not found", registration_id));
    }
    state_->entries.erase(existing);
    ++state_->revision;
    return workspace_result_t<void>::success();
}

workspace_result_t<decompiler_provider_route_t> decompiler_provider_registry_t::resolve(
    const decompiler_entity_key_t& entity,
    const decompiler_language_identity_t& language,
    const decompiler_profile_budget_t& profile,
    const std::optional<std::string>& registration_id) const
{
    if (!validate_decompiler_entity_key(entity).valid() ||
        !validate_decompiler_profile(profile).valid() ||
        !valid_language_identity(language, entity) ||
        (registration_id && !valid_registration_id(*registration_id))) {
        return workspace_result_t<decompiler_provider_route_t>::failure(
            registry_error(workspace_error_code_t::invalid_argument, "provider route request is invalid"));
    }

    const auto expected = expected_provider(entity.kind);
    if (!expected) {
        return workspace_result_t<decompiler_provider_route_t>::failure(
            registry_error(workspace_error_code_t::provider_binding_mismatch,
                           "entity kind has no provider route"));
    }

    std::shared_lock lock(state_->mutex);
    for (const auto& entry : state_->entries) {
        if (entry.descriptor.entity_kind != entity.kind || entry.descriptor.identity.provider != *expected)
            continue;
        if (registration_id && entry.descriptor.registration_id != *registration_id)
            continue;
        if (!std::binary_search(entry.descriptor.profiles.begin(), entry.descriptor.profiles.end(), profile.profile))
            continue;
        if (!entry.provider->supports_language(language))
            continue;
        return workspace_result_t<decompiler_provider_route_t>::success(
            decompiler_provider_route_t{entry.descriptor, entry.provider});
    }

    auto error = registry_error(workspace_error_code_t::provider_unavailable,
                                "no provider supports the requested entity, profile, and language");
    error.details.emplace_back("entity_kind", std::to_string(static_cast<unsigned>(entity.kind)));
    error.details.emplace_back("profile", std::to_string(static_cast<unsigned>(profile.profile)));
    if (registration_id)
        error.details.emplace_back("registration_id", *registration_id);
    return workspace_result_t<decompiler_provider_route_t>::failure(std::move(error));
}

decompiler_provider_registry_snapshot_t decompiler_provider_registry_t::snapshot() const
{
    decompiler_provider_registry_snapshot_t result;
    std::shared_lock lock(state_->mutex);
    result.revision = state_->revision;
    result.providers.reserve(state_->entries.size());
    for (const auto& entry : state_->entries)
        result.providers.push_back(entry.descriptor);
    return result;
}

std::optional<decompiler_provider_id_t> decompiler_provider_registry_t::expected_provider(
    const decompiler_entity_kind_t entity_kind) noexcept
{
    switch (entity_kind) {
    case decompiler_entity_kind_t::native_function:
        return decompiler_provider_id_t::ghidra_native;
    case decompiler_entity_kind_t::cli_method:
        return decompiler_provider_id_t::ilspy_cli;
    case decompiler_entity_kind_t::jvm_method:
        return decompiler_provider_id_t::jvm_ssa;
    case decompiler_entity_kind_t::dalvik_method:
        return decompiler_provider_id_t::dalvik_ssa;
    }
    return std::nullopt;
}

std::optional<decompiler_entity_kind_t> decompiler_provider_registry_t::expected_entity_kind(
    const decompiler_provider_id_t provider) noexcept
{
    switch (provider) {
    case decompiler_provider_id_t::ghidra_native:
        return decompiler_entity_kind_t::native_function;
    case decompiler_provider_id_t::ilspy_cli:
        return decompiler_entity_kind_t::cli_method;
    case decompiler_provider_id_t::jvm_ssa:
        return decompiler_entity_kind_t::jvm_method;
    case decompiler_provider_id_t::dalvik_ssa:
        return decompiler_entity_kind_t::dalvik_method;
    }
    return std::nullopt;
}

}
