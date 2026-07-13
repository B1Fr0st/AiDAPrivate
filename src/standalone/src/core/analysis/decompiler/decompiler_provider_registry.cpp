#include "decompiler_provider_registry.hpp"

#include "providers/cli_provider.hpp"
#include "providers/dalvik_ssa.hpp"
#include "providers/ghidra_ir_adapter.hpp"
#include "providers/jvm_ssa.hpp"

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

bool equal_provider_identity(
    const decompiler_provider_identity_t& left,
    const decompiler_provider_identity_t& right) noexcept
{
    return left.provider == right.provider && left.provider_name == right.provider_name &&
           left.provider_version == right.provider_version &&
           left.provider_binary_hash == right.provider_binary_hash &&
           left.worker_build_id == right.worker_build_id &&
           left.worker_build_hash == right.worker_build_hash;
}

bool equal_language_identity(
    const decompiler_language_identity_t& left,
    const decompiler_language_identity_t& right) noexcept
{
    return left.language_id == right.language_id &&
           left.language_version == right.language_version &&
           left.compiler_spec_id == right.compiler_spec_id &&
           left.language_spec_hash == right.language_spec_hash &&
           left.architecture == right.architecture && left.mode == right.mode &&
           left.endian == right.endian;
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

decompiler_provider_result_t rejected_provider_result(std::string key)
{
    decompiler_provider_result_t result;
    result.status = decompiler_provider_execution_status_t::failed;
    result.diagnostics.push_back(provider_diagnostic(
        decompiler_diagnostic_code_t::invalid_contract, std::move(key)));
    return result;
}

decompiler_provider_result_t unsupported_provider_result(std::string key)
{
    decompiler_provider_result_t result;
    result.status = decompiler_provider_execution_status_t::unsupported;
    result.diagnostics.push_back(provider_diagnostic(
        decompiler_diagnostic_code_t::unsupported_architecture, std::move(key)));
    return result;
}

void ensure_failure_diagnostic(
    decompiler_provider_result_t& result,
    std::string key)
{
    if (result.diagnostics.empty()) {
        result.diagnostics.push_back(provider_diagnostic(
            decompiler_diagnostic_code_t::provider_failure, std::move(key), true));
    }
}

bool request_matches_descriptor(
    const decompiler_provider_request_t& request,
    const decompiler_provider_descriptor_t& descriptor)
{
    return request.cache_key.stage == decompiler_cache_stage_t::provider_ir &&
           request.cache_key.entity.kind == descriptor.entity_kind &&
           equal_provider_identity(request.cache_key.provider, descriptor.identity) &&
           validate_decompiler_pipeline_cache_key(request.cache_key).valid();
}

void finish_provider_result(
    decompiler_provider_result_t& result,
    const std::chrono::steady_clock::time_point started,
    const cancellation_token_t& cancel,
    const std::chrono::steady_clock::time_point deadline)
{
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();
    result.elapsed_wall_clock_ms = static_cast<std::uint64_t>((std::max<std::int64_t>)(elapsed, 0));
    if (cancel.stop_requested() || std::chrono::steady_clock::now() >= deadline) {
        auto stopped = stopped_provider_result(cancel, deadline);
        stopped.elapsed_wall_clock_ms = result.elapsed_wall_clock_ms;
        result = std::move(stopped);
    }
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
        const auto started = std::chrono::steady_clock::now();
        if (cancel.stop_requested() || started >= request.deadline)
            return stopped_provider_result(cancel, request.deadline);
        if (!request_matches_descriptor(request, descriptor_))
            return rejected_provider_result("decompiler.provider.native.request");
        if (!supports_language(request.cache_key.language))
            return unsupported_provider_result("decompiler.provider.native.language_unsupported");
        const auto context = std::dynamic_pointer_cast<const ghidra_native_provider_context_t>(request.context);
        if (!context || !context->artifacts())
            return rejected_provider_result("decompiler.provider.native.context");
        const auto& source = *context->artifacts();
        decompiler_provider_result_t result;
        result.diagnostics = source.provider_ir.diagnostics;
        if (!validate_provider_ir(source.provider_ir).valid() ||
            !validate_hir_function(source.hir).valid() ||
            !validate_type_graph(source.type_graph).valid() ||
            source.provider_ir.entity != request.cache_key.entity ||
            source.hir.entity != request.cache_key.entity ||
            source.type_graph.entity != request.cache_key.entity ||
            !equal_provider_identity(source.provider_ir.provider, descriptor_.identity) ||
            !equal_language_identity(source.provider_ir.language, request.cache_key.language) ||
            source.hir.provider_ir_hash != stable_serialization_hash(source.provider_ir) ||
            source.hir.type_graph_revision != request.cache_key.type_graph_revision ||
            source.type_graph.revision != request.cache_key.type_graph_revision ||
            source.hir.return_type_id == 0) {
            return rejected_provider_result("decompiler.provider.native.artifacts");
        }
        decompiler_provider_artifacts_t artifacts;
        artifacts.provider_ir = source.provider_ir;
        artifacts.hir = source.hir;
        artifacts.type_graph = source.type_graph;
        artifacts.return_type_id = source.hir.return_type_id;
        result.artifacts = std::move(artifacts);
        result.status = decompiler_provider_execution_status_t::completed;
        finish_provider_result(result, started, cancel, request.deadline);
        return result;
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
        const auto started = std::chrono::steady_clock::now();
        if (cancel.stop_requested() || started >= request.deadline)
            return stopped_provider_result(cancel, request.deadline);
        if (!request_matches_descriptor(request, descriptor_))
            return rejected_provider_result("decompiler.provider.cli.request");
        if (!supports_language(request.cache_key.language))
            return unsupported_provider_result("decompiler.provider.cli.language_unsupported");
        const auto context = std::dynamic_pointer_cast<const managed_cli_provider_context_t>(request.context);
        if (!context || !context->analysis() || context->return_type_id() == 0)
            return rejected_provider_result("decompiler.provider.cli.context");
        const auto& source = *context->analysis();
        if (!validate_provider_ir(source.provider_ir).valid() ||
            !validate_type_graph(source.type_graph).valid() ||
            source.provider_ir.entity != request.cache_key.entity ||
            source.type_graph.entity != request.cache_key.entity ||
            !equal_provider_identity(source.provider_ir.provider, descriptor_.identity) ||
            !equal_language_identity(source.provider_ir.language, request.cache_key.language) ||
            source.type_graph.revision != request.cache_key.type_graph_revision ||
            std::none_of(source.type_graph.nodes.begin(), source.type_graph.nodes.end(),
                [context](const decompiler_type_node_t& node) {
                    return node.id == context->return_type_id();
                })) {
            return rejected_provider_result("decompiler.provider.cli.artifacts");
        }
        decompiler_provider_result_t result;
        result.diagnostics = source.diagnostics;
        decompiler_provider_artifacts_t artifacts;
        artifacts.provider_ir = source.provider_ir;
        artifacts.provider_ir.language = request.cache_key.language;
        artifacts.type_graph = source.type_graph;
        artifacts.return_type_id = context->return_type_id();
        result.artifacts = std::move(artifacts);
        result.status = decompiler_provider_execution_status_t::completed;
        finish_provider_result(result, started, cancel, request.deadline);
        return result;
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
        const auto started = std::chrono::steady_clock::now();
        if (cancel.stop_requested() || started >= request.deadline)
            return stopped_provider_result(cancel, request.deadline);
        if (!request_matches_descriptor(request, descriptor_))
            return rejected_provider_result("decompiler.provider.jvm.request");
        if (!supports_language(request.cache_key.language))
            return unsupported_provider_result("decompiler.provider.jvm.language_unsupported");
        const auto context = std::dynamic_pointer_cast<const jvm_ssa_provider_context_t>(request.context);
        if (!context || !context->input())
            return rejected_provider_result("decompiler.provider.jvm.context");
        const auto& input = *context->input();
        if (input.entity != request.cache_key.entity ||
            !equal_provider_identity(input.provider, descriptor_.identity) ||
            !equal_language_identity(input.language, request.cache_key.language) ||
            input.workspace_generation != request.cache_key.workspace_generation ||
            input.type_graph_revision != request.cache_key.type_graph_revision) {
            return rejected_provider_result("decompiler.provider.jvm.binding");
        }
        const auto source = jvm_ssa::decompile_method(input);
        decompiler_provider_result_t result;
        result.diagnostics = source.diagnostics;
        if (!source.succeeded() || !source.provider_ir || !source.hir || !source.type_graph ||
            !validate_provider_ir(*source.provider_ir).valid() ||
            !validate_hir_function(*source.hir).valid() ||
            !validate_type_graph(*source.type_graph).valid() ||
            source.provider_ir->entity != request.cache_key.entity ||
            source.hir->entity != request.cache_key.entity ||
            source.type_graph->entity != request.cache_key.entity ||
            !equal_provider_identity(source.provider_ir->provider, descriptor_.identity) ||
            !equal_language_identity(source.provider_ir->language, request.cache_key.language) ||
            source.hir->provider_ir_hash != stable_serialization_hash(*source.provider_ir) ||
            source.hir->type_graph_revision != request.cache_key.type_graph_revision ||
            source.type_graph->revision != request.cache_key.type_graph_revision ||
            source.hir->return_type_id == 0) {
            result.status = decompiler_provider_execution_status_t::failed;
            ensure_failure_diagnostic(result, "decompiler.provider.jvm.output_rejected");
            finish_provider_result(result, started, cancel, request.deadline);
            return result;
        }
        decompiler_provider_artifacts_t artifacts;
        artifacts.provider_ir = *source.provider_ir;
        artifacts.hir = *source.hir;
        artifacts.type_graph = *source.type_graph;
        artifacts.return_type_id = source.hir->return_type_id;
        result.artifacts = std::move(artifacts);
        result.status = decompiler_provider_execution_status_t::completed;
        finish_provider_result(result, started, cancel, request.deadline);
        return result;
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
        const auto started = std::chrono::steady_clock::now();
        if (cancel.stop_requested() || started >= request.deadline)
            return stopped_provider_result(cancel, request.deadline);
        if (!request_matches_descriptor(request, descriptor_))
            return rejected_provider_result("decompiler.provider.dalvik.request");
        if (!supports_language(request.cache_key.language))
            return unsupported_provider_result("decompiler.provider.dalvik.language_unsupported");
        const auto context = std::dynamic_pointer_cast<const dalvik_ssa_provider_context_t>(request.context);
        if (!context || !context->capture())
            return rejected_provider_result("decompiler.provider.dalvik.context");
        const auto& capture = *context->capture();
        if (capture.request.entity != request.cache_key.entity ||
            !equal_provider_identity(capture.request.provider, descriptor_.identity) ||
            !equal_language_identity(capture.request.language, request.cache_key.language) ||
            capture.request.workspace_generation != request.cache_key.workspace_generation ||
            capture.request.type_graph_revision != request.cache_key.type_graph_revision) {
            return rejected_provider_result("decompiler.provider.dalvik.binding");
        }
        const auto source = dalvik_ssa::normalize(capture);
        decompiler_provider_result_t result;
        result.diagnostics = source.diagnostics;
        if (!source.succeeded() || !source.artifacts ||
            !validate_provider_ir(source.artifacts->provider_ir).valid() ||
            !validate_hir_function(source.artifacts->hir).valid() ||
            !validate_type_graph(source.artifacts->type_graph).valid() ||
            source.artifacts->provider_ir.entity != request.cache_key.entity ||
            source.artifacts->hir.entity != request.cache_key.entity ||
            source.artifacts->type_graph.entity != request.cache_key.entity ||
            !equal_provider_identity(source.artifacts->provider_ir.provider, descriptor_.identity) ||
            !equal_language_identity(source.artifacts->provider_ir.language, request.cache_key.language) ||
            source.artifacts->hir.provider_ir_hash !=
                stable_serialization_hash(source.artifacts->provider_ir) ||
            source.artifacts->hir.type_graph_revision != request.cache_key.type_graph_revision ||
            source.artifacts->type_graph.revision != request.cache_key.type_graph_revision ||
            source.artifacts->hir.return_type_id == 0) {
            result.status = decompiler_provider_execution_status_t::failed;
            ensure_failure_diagnostic(result, "decompiler.provider.dalvik.output_rejected");
            finish_provider_result(result, started, cancel, request.deadline);
            return result;
        }
        decompiler_provider_artifacts_t artifacts;
        artifacts.provider_ir = source.artifacts->provider_ir;
        artifacts.hir = source.artifacts->hir;
        artifacts.type_graph = source.artifacts->type_graph;
        artifacts.return_type_id = source.artifacts->hir.return_type_id;
        result.artifacts = std::move(artifacts);
        result.status = decompiler_provider_execution_status_t::completed;
        finish_provider_result(result, started, cancel, request.deadline);
        return result;
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
    std::shared_ptr<const ghidra_ir_adapter::typed_artifacts_t> artifacts)
    : artifacts_(std::move(artifacts))
{
}

const std::shared_ptr<const ghidra_ir_adapter::typed_artifacts_t>&
ghidra_native_provider_context_t::artifacts() const noexcept
{
    return artifacts_;
}

managed_cli_provider_context_t::managed_cli_provider_context_t(
    std::shared_ptr<const managed_cli::analysis_t> analysis,
    const std::uint64_t return_type_id)
    : analysis_(std::move(analysis)), return_type_id_(return_type_id)
{
}

const std::shared_ptr<const managed_cli::analysis_t>&
managed_cli_provider_context_t::analysis() const noexcept
{
    return analysis_;
}

std::uint64_t managed_cli_provider_context_t::return_type_id() const noexcept
{
    return return_type_id_;
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
    cli.isolated = false;
    jvm.isolated = false;
    dalvik.isolated = false;
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
