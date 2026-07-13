#include "mcp_server_integration.hpp"

#include "effect_policy.hpp"
#include "target_resolver.hpp"
#include "../mcp_standalone.hpp"
#include "../schema_validator.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace aida::standalone::mcp::integration {
namespace {

struct integration_state_t final {
    mcp_standalone::server_t* server = nullptr;
    server_integration_config_t config;
    protocol::schema_runtime_t schemas;
    compat::effect_lock_manager_t lock_manager;
    compat::target_resolver_t target_resolver;
    mutable std::mutex metrics_mutex;
    server_integration_metrics_t metrics;
    std::unordered_map<std::string, compat::contract_descriptor_t> descriptor_index;
    std::unordered_map<std::string, protocol::tool_contract_t> contract_index;
    std::unordered_map<std::string, std::size_t> name_to_ordinal;
    std::vector<std::string> union_names;
    std::atomic<std::uint64_t> invocation_counter{0};

    integration_state_t(mcp_standalone::server_t& srv,
                        server_integration_config_t cfg)
        : server(&srv), config(std::move(cfg)),
          schemas(config.schema_cache_capacity) {}
};

std::string_view effect_name_from_descriptor(
    const compat::contract_descriptor_t& descriptor) noexcept {
    return compat::contract_effect_t(descriptor.effect) ==
        compat::contract_effect_t::workspace_read ? "workspace_read" :
        compat::contract_effect_t(descriptor.effect) ==
        compat::contract_effect_t::workspace_checkpoint ? "workspace_checkpoint" :
        compat::contract_effect_t(descriptor.effect) ==
        compat::contract_effect_t::workspace_overlay_mutation ? "workspace_overlay_mutation" :
        compat::contract_effect_t(descriptor.effect) ==
        compat::contract_effect_t::debugger_read ? "debugger_read" :
        compat::contract_effect_t(descriptor.effect) ==
        compat::contract_effect_t::debugger_control ? "debugger_control" :
        compat::contract_effect_t(descriptor.effect) ==
        compat::contract_effect_t::debugger_write ? "debugger_write" :
        compat::contract_effect_t(descriptor.effect) ==
        compat::contract_effect_t::isolated_python ? "isolated_python" :
        "registry_read";
}

std::string_view lock_name_from_descriptor(
    const compat::contract_descriptor_t& descriptor) noexcept {
    return compat::contract_lock_t(descriptor.lock) ==
        compat::contract_lock_t::workspace_shared ? "workspace_shared" :
        compat::contract_lock_t(descriptor.lock) ==
        compat::contract_lock_t::workspace_checkpoint ? "workspace_checkpoint" :
        compat::contract_lock_t(descriptor.lock) ==
        compat::contract_lock_t::workspace_overlay_transaction ? "workspace_overlay_transaction" :
        compat::contract_lock_t(descriptor.lock) ==
        compat::contract_lock_t::debugger_lane ? "debugger_lane" :
        compat::contract_lock_t(descriptor.lock) ==
        compat::contract_lock_t::python_worker ? "python_worker" :
        "registry_read";
}

protocol::tool_effect_t map_effect(
    compat::contract_effect_t effect) noexcept {
    switch (effect) {
    case compat::contract_effect_t::workspace_read:
        return protocol::tool_effect_t::workspace_read;
    case compat::contract_effect_t::workspace_checkpoint:
        return protocol::tool_effect_t::workspace_checkpoint;
    case compat::contract_effect_t::workspace_overlay_mutation:
        return protocol::tool_effect_t::workspace_overlay_mutation;
    case compat::contract_effect_t::debugger_read:
        return protocol::tool_effect_t::debugger_read;
    case compat::contract_effect_t::debugger_control:
        return protocol::tool_effect_t::debugger_control;
    case compat::contract_effect_t::debugger_write:
        return protocol::tool_effect_t::debugger_write;
    case compat::contract_effect_t::isolated_python:
        return protocol::tool_effect_t::isolated_python;
    case compat::contract_effect_t::registry_read:
        return protocol::tool_effect_t::registry_read;
    default:
        return protocol::tool_effect_t::unspecified;
    }
}

protocol::effect_lock_t map_lock(
    compat::contract_lock_t lock) noexcept {
    switch (lock) {
    case compat::contract_lock_t::workspace_shared:
        return protocol::effect_lock_t::workspace_shared;
    case compat::contract_lock_t::workspace_checkpoint:
        return protocol::effect_lock_t::workspace_checkpoint;
    case compat::contract_lock_t::workspace_overlay_transaction:
        return protocol::effect_lock_t::workspace_overlay_transaction;
    case compat::contract_lock_t::debugger_lane:
        return protocol::effect_lock_t::debugger_lane;
    case compat::contract_lock_t::python_worker:
        return protocol::effect_lock_t::python_worker;
    case compat::contract_lock_t::registry_read:
        return protocol::effect_lock_t::registry_read;
    default:
        return protocol::effect_lock_t::unspecified;
    }
}

}

struct mcp_server_integration_t::impl_t {
    integration_state_t state;

    explicit impl_t(mcp_standalone::server_t& srv,
                    server_integration_config_t cfg)
        : state(srv, std::move(cfg)) {}

    void increment_metric(
        std::uint64_t server_integration_metrics_t::*field,
        std::uint64_t delta = 1) noexcept {
        std::lock_guard<std::mutex> lock(state.metrics_mutex);
        state.metrics.*field += delta;
    }

    void index_generated_contracts() {
        const auto* contracts = compat::contracts();
        const auto count = compat::contract_count();
        for (std::size_t i = 0; i < count; ++i) {
            const auto& descriptor = contracts[i];
            std::string name(descriptor.name);
            state.descriptor_index[name] = descriptor;
            auto contract = descriptor_to_contract(descriptor);
            state.contract_index[name] = contract;
            state.name_to_ordinal[name] = state.union_names.size();
            state.union_names.push_back(name);
        }
        increment_metric(&server_integration_metrics_t::tools_from_generated, count);
    }

    void index_extension_tools() {
        for (std::size_t i = 0; i < compat::k_aida_extension_count; ++i) {
            std::string name(compat::k_aida_extension_names[i]);
            if (state.descriptor_index.find(name) != state.descriptor_index.end())
                continue;
            compat::contract_descriptor_t descriptor;
            descriptor.name = compat::k_aida_extension_names[i];
            descriptor.description = "AiDA extension tool";
            descriptor.effect = compat::contract_effect_t::workspace_read;
            descriptor.lock = compat::contract_lock_t::workspace_shared;
            descriptor.read_only = true;
            descriptor.unsafe = false;
            descriptor.archive_backed = false;
            descriptor.target_dependent = false;
            descriptor.accepts_pid = false;
            descriptor.accepts_bin_name = false;
            state.descriptor_index[name] = descriptor;
            auto contract = descriptor_to_contract(descriptor);
            state.contract_index[name] = contract;
            state.name_to_ordinal[name] = state.union_names.size();
            state.union_names.push_back(name);
        }
        increment_metric(&server_integration_metrics_t::tools_from_extension,
            static_cast<std::uint64_t>(compat::k_aida_extension_count));
    }

    void register_all_tools() {
        index_generated_contracts();
        index_extension_tools();
        for (const auto& [name, contract] : state.contract_index) {
            auto tool_def = contract_to_tool_def(contract);
            state.server->register_tool(std::move(tool_def));
        }
        {
            std::lock_guard<std::mutex> lock(state.metrics_mutex);
            state.metrics.tools_registered = state.union_names.size();
        }
    }
};

json tool_provenance_metadata_t::to_json() const {
    json result;
    result["contract_name"] = contract_name;
    result["source_path"] = source_path;
    result["source_line"] = source_line;
    result["effect"] = effect_name;
    result["lock"] = lock_name;
    result["archive_backed"] = archive_backed;
    result["read_only"] = read_only;
    result["unsafe"] = unsafe;
    return result;
}

mcp_server_integration_t::mcp_server_integration_t(
    std::unique_ptr<impl_t> impl)
    : impl_(std::move(impl)) {}

mcp_server_integration_t::~mcp_server_integration_t() = default;

std::shared_ptr<mcp_server_integration_t>
mcp_server_integration_t::create(
    mcp_standalone::server_t& server,
    server_integration_config_t config) {
    auto impl = std::make_unique<impl_t>(server, config);
    return std::shared_ptr<mcp_server_integration_t>(
        new mcp_server_integration_t(std::move(impl)));
}

void mcp_server_integration_t::register_generated_tools() {
    if (!impl_)
        return;
    impl_->index_generated_contracts();
    for (const auto& [name, contract] : impl_->state.contract_index) {
        auto tool_def = contract_to_tool_def(contract);
        impl_->state.server->register_tool(std::move(tool_def));
    }
    {
        std::lock_guard<std::mutex> lock(impl_->state.metrics_mutex);
        impl_->state.metrics.tools_registered = impl_->state.union_names.size();
    }
}

void mcp_server_integration_t::register_extension_tools() {
    if (!impl_)
        return;
    impl_->index_extension_tools();
    for (std::size_t i = 0; i < compat::k_aida_extension_count; ++i) {
        std::string name(compat::k_aida_extension_names[i]);
        if (impl_->state.contract_index.find(name) == impl_->state.contract_index.end())
            continue;
        auto tool_def = contract_to_tool_def(impl_->state.contract_index[name]);
        impl_->state.server->register_tool(std::move(tool_def));
    }
    {
        std::lock_guard<std::mutex> lock(impl_->state.metrics_mutex);
        impl_->state.metrics.tools_registered = impl_->state.union_names.size();
    }
}

std::size_t mcp_server_integration_t::registered_tool_count() const noexcept {
    if (!impl_)
        return 0;
    return impl_->state.union_names.size();
}

std::size_t mcp_server_integration_t::union_tool_count() const noexcept {
    if (!impl_)
        return 0;
    return impl_->state.union_names.size();
}

std::vector<std::string> mcp_server_integration_t::union_tool_names() const {
    if (!impl_)
        return {};
    return impl_->state.union_names;
}

server_integration_metrics_t
mcp_server_integration_t::metrics() const noexcept {
    if (!impl_)
        return {};
    std::lock_guard<std::mutex> lock(impl_->state.metrics_mutex);
    return impl_->state.metrics;
}

protocol::mcp_result_t
mcp_server_integration_t::invoke_tool(
    const std::string& tool_name,
    const json& arguments,
    const protocol::cancellation_token_t& cancellation) {
    if (!impl_)
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::internal_error,
            "MCP server integration is not initialized");
    impl_->state.invocation_counter.fetch_add(1, std::memory_order_acq_rel);
    impl_->increment_metric(&server_integration_metrics_t::total_invocations);
    const auto contract_it = impl_->state.contract_index.find(tool_name);
    if (contract_it == impl_->state.contract_index.end()) {
        impl_->increment_metric(&server_integration_metrics_t::contract_lookup_misses);
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_contract,
            "tool contract not found: " + tool_name);
    }
    impl_->increment_metric(&server_integration_metrics_t::contract_lookup_hits);
    const auto& contract = contract_it->second;
    const auto descriptor_it = impl_->state.descriptor_index.find(tool_name);
    if (descriptor_it == impl_->state.descriptor_index.end()) {
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_contract,
            "tool descriptor not found: " + tool_name);
    }
    const auto& descriptor = descriptor_it->second;
    if (impl_->state.config.enforce_input_validation) {
        auto validation = protocol::validate_tool_contract(contract, impl_->state.schemas);
        if (!validation.valid) {
            impl_->increment_metric(&server_integration_metrics_t::input_validation_failures);
            impl_->increment_metric(&server_integration_metrics_t::total_errors);
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_input,
                "input validation failed: " + validation.reason,
                validation.details);
        }
        impl_->increment_metric(&server_integration_metrics_t::input_validation_passes);
    }
    auto effect_policy = descriptor_to_effect_policy(descriptor);
    compat::effect_lock_policy_t lock_policy;
    lock_policy.effect = descriptor.effect;
    lock_policy.contract_lock = descriptor.lock;
    lock_policy.mode = compat::effect_lock_mode_t::shared;
    lock_policy.target_required = descriptor.target_dependent;
    lock_policy.mutates_workspace = !descriptor.read_only;
    auto lease = impl_->state.lock_manager.acquire(lock_policy, 0);
    if (!lease) {
        impl_->increment_metric(&server_integration_metrics_t::effect_policy_rejections);
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::effect_policy_rejected,
            "effect policy acquisition failed for tool: " + tool_name);
    }
    impl_->increment_metric(&server_integration_metrics_t::effect_policy_acquisitions);
    json aida_metadata;
    if (impl_->state.config.move_provenance_to_top_level) {
        auto provenance = descriptor_to_provenance(descriptor);
        aida_metadata = provenance.to_json();
        impl_->increment_metric(&server_integration_metrics_t::provenance_metadata_emitted);
    }
    auto result = impl_->state.server->call_registered_tool(tool_name, arguments, false);
    if (!result.success) {
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::handler_failed,
            result.text,
            result.error_details,
            aida_metadata);
    }
    if (impl_->state.config.enforce_output_validation && contract.output_schema.is_object()) {
        auto output_validation = impl_->state.schemas.validate(
            contract.output_schema, result.data);
        if (!output_validation.valid) {
            impl_->increment_metric(&server_integration_metrics_t::output_validation_failures);
            impl_->increment_metric(&server_integration_metrics_t::total_errors);
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_output,
                "output validation failed: " + output_validation.summary(),
                output_validation.diagnostics(),
                aida_metadata);
        }
        impl_->increment_metric(&server_integration_metrics_t::output_validation_passes);
    }
    return protocol::mcp_result_t::success(
        result.text, result.data, aida_metadata);
}

protocol::tool_contract_t
mcp_server_integration_t::descriptor_to_contract(
    const compat::contract_descriptor_t& descriptor) {
    protocol::tool_contract_t contract;
    contract.name = std::string(descriptor.name);
    contract.description = std::string(descriptor.description);
    if (!descriptor.input_schema_json.empty()) {
        auto parsed = json::parse(descriptor.input_schema_json, nullptr, false);
        if (!parsed.is_discarded())
            contract.input_schema = parsed;
    }
    if (!descriptor.output_schema_json.empty()) {
        auto parsed = json::parse(descriptor.output_schema_json, nullptr, false);
        if (!parsed.is_discarded())
            contract.output_schema = parsed;
    }
    if (!descriptor.annotations_json.empty()) {
        auto parsed = json::parse(descriptor.annotations_json, nullptr, false);
        if (!parsed.is_discarded())
            contract.annotations = parsed;
    }
    contract.target_policy = descriptor_to_target_policy(descriptor);
    contract.effect_policy = descriptor_to_effect_policy(descriptor);
    return contract;
}

mcp_standalone::tool_def_t
mcp_server_integration_t::contract_to_tool_def(
    const protocol::tool_contract_t& contract) {
    mcp_standalone::tool_def_t tool_def;
    tool_def.name = contract.name;
    tool_def.description = contract.description;
    tool_def.read_only = contract.effect_policy.read_only;
    tool_def.input_schema = contract.input_schema;
    tool_def.visibility = mcp_standalone::tool_visibility_t::external_visible;
    tool_def.handler = [contract](const json& params) -> mcp_standalone::tool_result_t {
        return mcp_standalone::tool_result_t::ok(
            "tool " + contract.name + " invoked",
            params);
    };
    return tool_def;
}

tool_provenance_metadata_t
mcp_server_integration_t::descriptor_to_provenance(
    const compat::contract_descriptor_t& descriptor) {
    tool_provenance_metadata_t provenance;
    provenance.contract_name = std::string(descriptor.name);
    provenance.source_path = std::string(descriptor.source_path);
    provenance.source_line = descriptor.source_line;
    provenance.effect_name = std::string(effect_name_from_descriptor(descriptor));
    provenance.lock_name = std::string(lock_name_from_descriptor(descriptor));
    provenance.archive_backed = descriptor.archive_backed;
    provenance.read_only = descriptor.read_only;
    provenance.unsafe = descriptor.unsafe;
    return provenance;
}

protocol::effect_policy_t
mcp_server_integration_t::descriptor_to_effect_policy(
    const compat::contract_descriptor_t& descriptor) {
    protocol::effect_policy_t policy;
    policy.effect = map_effect(descriptor.effect);
    policy.lock = map_lock(descriptor.lock);
    policy.read_only = descriptor.read_only;
    policy.unsafe = descriptor.unsafe;
    return policy;
}

protocol::target_policy_t
mcp_server_integration_t::descriptor_to_target_policy(
    const compat::contract_descriptor_t& descriptor) {
    protocol::target_policy_t policy;
    policy.requirement = descriptor.target_dependent
        ? protocol::target_requirement_t::required
        : protocol::target_requirement_t::independent;
    policy.accepts_pid = descriptor.accepts_pid;
    policy.accepts_bin_name = descriptor.accepts_bin_name;
    return policy;
}

bool mcp_server_integration_t::validate_union_count() noexcept {
    return compat::k_union_tool_count == 92;
}

}
