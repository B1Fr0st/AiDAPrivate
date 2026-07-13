#include "decompiler_provider_registry.hpp"

#include <algorithm>
#include <chrono>
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
    if (language.language_id.empty() || language.language_version.empty() ||
        language.compiler_spec_id.empty() || language.language_spec_hash.empty())
        return false;
    switch (entity.kind) {
    case decompiler_entity_kind_t::native_function:
        return language.architecture == entity.architecture && language.mode == entity.mode &&
               language.endian == entity.endian;
    case decompiler_entity_kind_t::cli_method: {
        const bool neutral = language.architecture == architecture_id_t::unknown &&
                             language.mode == architecture_mode_t::unknown;
        const bool exact = entity.architecture != architecture_id_t::unknown &&
                           entity.mode != architecture_mode_t::unknown &&
                           language.architecture == entity.architecture &&
                           language.mode == entity.mode && language.endian == entity.endian;
        return neutral || exact;
    }
    case decompiler_entity_kind_t::jvm_method:
        return language.architecture == architecture_id_t::jvm_bytecode &&
               language.mode == architecture_mode_t::jvm;
    case decompiler_entity_kind_t::dalvik_method:
        return language.architecture == architecture_id_t::dalvik_bytecode &&
               language.mode == architecture_mode_t::dalvik;
    }
    return false;
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

decompiler_diagnostic_t provider_diagnostic(
    const decompiler_diagnostic_code_t code,
    std::string key,
    const bool retryable = false)
{
    decompiler_diagnostic_t diagnostic;
    diagnostic.severity = decompiler_diagnostic_severity_t::error;
    diagnostic.code = code;
    diagnostic.localization_key = std::move(key);
    diagnostic.ordinal = 1;
    diagnostic.retryable = retryable;
    return diagnostic;
}

decompiler_provider_result_t stopped_provider_result(
    const cancellation_token_t& cancel,
    const std::chrono::steady_clock::time_point deadline)
{
    decompiler_provider_result_t result;
    const bool timed_out = cancel.deadline_exceeded() ||
        std::chrono::steady_clock::now() >= deadline;
    result.status = timed_out ? decompiler_provider_execution_status_t::timed_out
                              : decompiler_provider_execution_status_t::cancelled;
    result.diagnostics.push_back(provider_diagnostic(
        timed_out ? decompiler_diagnostic_code_t::deadline_exceeded
                  : decompiler_diagnostic_code_t::cancelled,
        timed_out ? "decompiler.provider.deadline" : "decompiler.provider.cancelled"));
    return result;
}

decompiler_provider_result_t isolated_provider_result(
    const cancellation_token_t& cancel,
    const std::chrono::steady_clock::time_point deadline,
    std::string key)
{
    if (cancel.stop_requested() || std::chrono::steady_clock::now() >= deadline)
        return stopped_provider_result(cancel, deadline);
    decompiler_provider_result_t result;
    result.status = decompiler_provider_execution_status_t::failed;
    result.diagnostics.push_back(provider_diagnostic(
        decompiler_diagnostic_code_t::worker_protocol_failure, std::move(key)));
    return result;
}

decompiler_provider_descriptor_t builtin_descriptor(
    std::string registration_id,
    const decompiler_entity_kind_t entity_kind,
    const decompiler_builtin_provider_registration_t& registration)
{
    decompiler_provider_descriptor_t descriptor;
    descriptor.registration_id = std::move(registration_id);
    descriptor.identity = registration.identity;
    descriptor.entity_kind = entity_kind;
    descriptor.profiles = registration.profiles;
    descriptor.priority = registration.priority;
    descriptor.isolated = registration.isolated;
    return descriptor;
}

class ghidra_native_provider_t final : public decompiler_provider_t {
public:
    explicit ghidra_native_provider_t(decompiler_builtin_provider_registration_t registration)
        : descriptor_(builtin_descriptor("aida.decompiler.native.ghidra",
              decompiler_entity_kind_t::native_function, registration))
    {
    }

    decompiler_provider_descriptor_t descriptor() const override { return descriptor_; }

    bool supports_language(const decompiler_language_identity_t& language) const noexcept override
    {
        return !language.language_id.empty() && !language.language_version.empty() &&
               !language.compiler_spec_id.empty() && !language.language_spec_hash.empty() &&
               workspace_architecture_mode_matches(language.architecture, language.mode) &&
               language.architecture != architecture_id_t::jvm_bytecode &&
               language.architecture != architecture_id_t::dalvik_bytecode;
    }

    decompiler_provider_result_t decompile(
        const decompiler_provider_request_t& request,
        const cancellation_token_t& cancel) override
    {
        return isolated_provider_result(cancel, request.deadline,
            "decompiler.provider.native.isolated_execution_required");
    }

private:
    decompiler_provider_descriptor_t descriptor_;
};

class managed_cli_decompiler_provider_t final : public decompiler_provider_t {
public:
    explicit managed_cli_decompiler_provider_t(decompiler_builtin_provider_registration_t registration)
        : descriptor_(builtin_descriptor("aida.decompiler.managed.cli",
              decompiler_entity_kind_t::cli_method, registration))
    {
        language_.language_id = "cli-il";
        language_.language_version = "ecma-335";
        language_.compiler_spec_id = "managed-cli";
        language_.language_spec_hash = stable_serialization_hash(
            std::string("cli-il|ecma-335|") + descriptor_.identity.provider_version);
    }

    decompiler_provider_descriptor_t descriptor() const override { return descriptor_; }

    bool supports_language(const decompiler_language_identity_t& language) const noexcept override
    {
        const bool architecture_valid =
            (language.architecture == architecture_id_t::unknown &&
             language.mode == architecture_mode_t::unknown) ||
            (workspace_architecture_mode_matches(language.architecture, language.mode) &&
             language.architecture != architecture_id_t::jvm_bytecode &&
             language.architecture != architecture_id_t::dalvik_bytecode);
        return language.language_id == language_.language_id &&
               language.language_version == language_.language_version &&
               language.compiler_spec_id == language_.compiler_spec_id &&
               language.language_spec_hash == language_.language_spec_hash &&
               language.endian == language_.endian && architecture_valid;
    }

    decompiler_provider_result_t decompile(
        const decompiler_provider_request_t& request,
        const cancellation_token_t& cancel) override
    {
        return isolated_provider_result(cancel, request.deadline,
            "decompiler.provider.cli.isolated_execution_required");
    }

private:
    decompiler_provider_descriptor_t descriptor_;
    decompiler_language_identity_t language_;
};

class jvm_ssa_decompiler_provider_t final : public decompiler_provider_t {
public:
    explicit jvm_ssa_decompiler_provider_t(decompiler_builtin_provider_registration_t registration)
        : descriptor_(builtin_descriptor("aida.decompiler.jvm.ssa",
              decompiler_entity_kind_t::jvm_method, registration))
    {
    }

    decompiler_provider_descriptor_t descriptor() const override { return descriptor_; }

    bool supports_language(const decompiler_language_identity_t& language) const noexcept override
    {
        return !language.language_id.empty() && !language.language_version.empty() &&
               !language.compiler_spec_id.empty() && !language.language_spec_hash.empty() &&
               language.architecture == architecture_id_t::jvm_bytecode &&
               language.mode == architecture_mode_t::jvm;
    }

    decompiler_provider_result_t decompile(
        const decompiler_provider_request_t& request,
        const cancellation_token_t& cancel) override
    {
        return isolated_provider_result(cancel, request.deadline,
            "decompiler.provider.jvm.isolated_execution_required");
    }

private:
    decompiler_provider_descriptor_t descriptor_;
};

class dalvik_ssa_decompiler_provider_t final : public decompiler_provider_t {
public:
    explicit dalvik_ssa_decompiler_provider_t(decompiler_builtin_provider_registration_t registration)
        : descriptor_(builtin_descriptor("aida.decompiler.dalvik.ssa",
              decompiler_entity_kind_t::dalvik_method, registration))
    {
    }

    decompiler_provider_descriptor_t descriptor() const override { return descriptor_; }

    bool supports_language(const decompiler_language_identity_t& language) const noexcept override
    {
        return !language.language_id.empty() && !language.language_version.empty() &&
               !language.compiler_spec_id.empty() && !language.language_spec_hash.empty() &&
               language.architecture == architecture_id_t::dalvik_bytecode &&
               language.mode == architecture_mode_t::dalvik;
    }

    decompiler_provider_result_t decompile(
        const decompiler_provider_request_t& request,
        const cancellation_token_t& cancel) override
    {
        return isolated_provider_result(cancel, request.deadline,
            "decompiler.provider.dalvik.isolated_execution_required");
    }

private:
    decompiler_provider_descriptor_t descriptor_;
};

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

ghidra_native_provider_context_t::ghidra_native_provider_context_t(
    std::shared_ptr<const std::vector<std::uint8_t>> snapshot,
    sha256_digest_t snapshot_hash)
    : snapshot_(std::move(snapshot)), snapshot_hash_(snapshot_hash)
{
}

const std::shared_ptr<const std::vector<std::uint8_t>>&
ghidra_native_provider_context_t::snapshot() const noexcept
{
    return snapshot_;
}

const sha256_digest_t& ghidra_native_provider_context_t::snapshot_hash() const noexcept
{
    return snapshot_hash_;
}

managed_cli_provider_context_t::managed_cli_provider_context_t(
    std::shared_ptr<const managed_cli::request_t> request)
    : request_(std::move(request))
{
}

const std::shared_ptr<const managed_cli::request_t>&
managed_cli_provider_context_t::request() const noexcept
{
    return request_;
}

jvm_ssa_provider_context_t::jvm_ssa_provider_context_t(
    std::shared_ptr<const jvm_ssa::jvm_method_input_t> input)
    : input_(std::move(input))
{
}

const std::shared_ptr<const jvm_ssa::jvm_method_input_t>&
jvm_ssa_provider_context_t::input() const noexcept
{
    return input_;
}

dalvik_ssa_provider_context_t::dalvik_ssa_provider_context_t(
    std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t> capture)
    : capture_(std::move(capture))
{
}

const std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>&
dalvik_ssa_provider_context_t::capture() const noexcept
{
    return capture_;
}

decompiler_builtin_provider_config_t::decompiler_builtin_provider_config_t()
{
    native.isolated = true;
    cli.isolated = true;
    jvm.isolated = true;
    dalvik.isolated = true;
}

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
    try {
        std::vector<std::shared_ptr<decompiler_provider_t>> providers;
        providers.push_back(std::move(provider));
        return register_providers(std::move(providers), replace_existing);
    } catch (...) {
        return workspace_result_t<void>::failure(
            registry_error(workspace_error_code_t::limit_exceeded,
                           "provider registration allocation failed"));
    }
}

workspace_result_t<void> decompiler_provider_registry_t::register_providers(
    std::vector<std::shared_ptr<decompiler_provider_t>> providers,
    const bool replace_existing)
{
    if (providers.empty()) {
        return workspace_result_t<void>::failure(
            registry_error(workspace_error_code_t::invalid_argument,
                           "provider registration batch is empty"));
    }
    try {
        std::vector<state_t::entry_t> incoming;
        incoming.reserve(providers.size());
        for (auto& provider : providers) {
            auto descriptor = canonical_descriptor(provider);
            if (!descriptor)
                return workspace_result_t<void>::failure(descriptor.error());
            incoming.push_back({std::move(descriptor.value()), std::move(provider)});
        }
        std::sort(incoming.begin(), incoming.end(),
            [](const state_t::entry_t& left, const state_t::entry_t& right) {
                return left.descriptor.registration_id < right.descriptor.registration_id;
            });
        if (std::adjacent_find(incoming.begin(), incoming.end(),
                [](const state_t::entry_t& left, const state_t::entry_t& right) {
                    return left.descriptor.registration_id == right.descriptor.registration_id;
                }) != incoming.end()) {
            return workspace_result_t<void>::failure(
                registry_error(workspace_error_code_t::service_conflict,
                               "provider registration batch contains duplicate identifiers"));
        }

        std::unique_lock lock(state_->mutex);
        auto candidate = state_->entries;
        for (auto& entry : incoming) {
            const auto existing = std::find_if(candidate.begin(), candidate.end(),
                [&entry](const state_t::entry_t& current) {
                    return current.descriptor.registration_id == entry.descriptor.registration_id;
                });
            if (existing != candidate.end() && !replace_existing) {
                return workspace_result_t<void>::failure(
                    registry_error(workspace_error_code_t::service_conflict,
                                   "provider registration already exists",
                                   entry.descriptor.registration_id));
            }
            if (existing != candidate.end())
                *existing = std::move(entry);
            else
                candidate.push_back(std::move(entry));
        }
        std::sort(candidate.begin(), candidate.end(),
            [](const state_t::entry_t& left, const state_t::entry_t& right) {
                return descriptor_order(left.descriptor, right.descriptor);
            });
        state_->entries.swap(candidate);
        ++state_->revision;
        return workspace_result_t<void>::success();
    } catch (...) {
        return workspace_result_t<void>::failure(
            registry_error(workspace_error_code_t::limit_exceeded,
                           "provider registration batch allocation failed"));
    }
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

workspace_result_t<void> register_builtin_decompiler_providers(
    decompiler_provider_registry_t& registry,
    const decompiler_builtin_provider_config_t& config,
    const bool replace_existing)
{
    try {
        std::vector<std::shared_ptr<decompiler_provider_t>> providers;
        providers.reserve(4);
        providers.push_back(std::make_shared<ghidra_native_provider_t>(config.native));
        providers.push_back(std::make_shared<managed_cli_decompiler_provider_t>(config.cli));
        providers.push_back(std::make_shared<jvm_ssa_decompiler_provider_t>(config.jvm));
        providers.push_back(std::make_shared<dalvik_ssa_decompiler_provider_t>(config.dalvik));
        return registry.register_providers(std::move(providers), replace_existing);
    } catch (...) {
        return workspace_result_t<void>::failure(
            registry_error(workspace_error_code_t::limit_exceeded,
                           "built-in provider allocation failed"));
    }
}

}
