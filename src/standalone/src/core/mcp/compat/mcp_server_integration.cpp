#include "mcp_server_integration.hpp"

#include "effect_policy.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace aida::standalone::mcp::integration {
namespace {

struct registered_contract_t final {
    protocol::tool_contract_t contract;
    std::optional<compat::contract_descriptor_t> descriptor;
    std::string adapter_symbol;
    tool_provenance_metadata_t provenance;
    bool generated = false;
    bool registered = false;
};

struct integration_state_t final {
    mcp_standalone::server_t* server = nullptr;
    server_integration_config_t config;
    protocol::schema_runtime_t schemas;
    compat::effect_lock_manager_t lock_manager;
    mutable std::mutex metrics_mutex;
    server_integration_metrics_t metrics;
    std::unordered_map<std::string, registered_contract_t> contracts;
    std::vector<std::string> union_names;
    std::size_t registered_count = 0;
    bool generated_indexed = false;
    bool extensions_indexed = false;

    integration_state_t(mcp_standalone::server_t& srv,
                        server_integration_config_t cfg)
        : server(&srv), config(std::move(cfg)),
          schemas(config.schema_cache_capacity) {}
};

std::string_view effect_name_from_descriptor(
    const compat::contract_descriptor_t& descriptor) noexcept {
    switch (descriptor.effect) {
    case compat::contract_effect_t::workspace_read:
        return "workspace_read";
    case compat::contract_effect_t::workspace_checkpoint:
        return "workspace_checkpoint";
    case compat::contract_effect_t::workspace_overlay_mutation:
        return "workspace_overlay_mutation";
    case compat::contract_effect_t::debugger_read:
        return "debugger_read";
    case compat::contract_effect_t::debugger_control:
        return "debugger_control";
    case compat::contract_effect_t::debugger_write:
        return "debugger_write";
    case compat::contract_effect_t::isolated_python:
        return "isolated_python";
    case compat::contract_effect_t::registry_read:
        return "registry_read";
    }
    return "unknown";
}

std::string_view lock_name_from_descriptor(
    const compat::contract_descriptor_t& descriptor) noexcept {
    switch (descriptor.lock) {
    case compat::contract_lock_t::workspace_shared:
        return "workspace_shared";
    case compat::contract_lock_t::workspace_checkpoint:
        return "workspace_checkpoint";
    case compat::contract_lock_t::workspace_overlay_transaction:
        return "workspace_overlay_transaction";
    case compat::contract_lock_t::debugger_lane:
        return "debugger_lane";
    case compat::contract_lock_t::python_worker:
        return "python_worker";
    case compat::contract_lock_t::registry_read:
        return "registry_read";
    }
    return "unknown";
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
    }
    return protocol::tool_effect_t::unspecified;
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
    }
    return protocol::effect_lock_t::unspecified;
}

std::optional<compat::contract_effect_t> map_effect(
    protocol::tool_effect_t effect) noexcept {
    switch (effect) {
    case protocol::tool_effect_t::workspace_read:
        return compat::contract_effect_t::workspace_read;
    case protocol::tool_effect_t::workspace_checkpoint:
        return compat::contract_effect_t::workspace_checkpoint;
    case protocol::tool_effect_t::workspace_overlay_mutation:
        return compat::contract_effect_t::workspace_overlay_mutation;
    case protocol::tool_effect_t::debugger_read:
        return compat::contract_effect_t::debugger_read;
    case protocol::tool_effect_t::debugger_control:
        return compat::contract_effect_t::debugger_control;
    case protocol::tool_effect_t::debugger_write:
        return compat::contract_effect_t::debugger_write;
    case protocol::tool_effect_t::isolated_python:
        return compat::contract_effect_t::isolated_python;
    case protocol::tool_effect_t::registry_read:
        return compat::contract_effect_t::registry_read;
    case protocol::tool_effect_t::unspecified:
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<compat::contract_lock_t> map_lock(
    protocol::effect_lock_t lock) noexcept {
    switch (lock) {
    case protocol::effect_lock_t::workspace_shared:
        return compat::contract_lock_t::workspace_shared;
    case protocol::effect_lock_t::workspace_checkpoint:
        return compat::contract_lock_t::workspace_checkpoint;
    case protocol::effect_lock_t::workspace_overlay_transaction:
        return compat::contract_lock_t::workspace_overlay_transaction;
    case protocol::effect_lock_t::debugger_lane:
        return compat::contract_lock_t::debugger_lane;
    case protocol::effect_lock_t::python_worker:
        return compat::contract_lock_t::python_worker;
    case protocol::effect_lock_t::registry_read:
        return compat::contract_lock_t::registry_read;
    case protocol::effect_lock_t::unspecified:
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<compat::effect_lock_policy_t> extension_effect_policy(
    const protocol::tool_contract_t& contract) noexcept {
    const auto effect = map_effect(contract.effect_policy.effect);
    const auto lock = map_lock(contract.effect_policy.lock);
    if (!effect || !lock)
        return std::nullopt;
    compat::effect_lock_policy_t policy;
    policy.effect = *effect;
    policy.contract_lock = *lock;
    policy.target_required =
        contract.target_policy.requirement != protocol::target_requirement_t::independent;
    policy.mutates_workspace =
        *effect == compat::contract_effect_t::workspace_checkpoint ||
        *effect == compat::contract_effect_t::workspace_overlay_mutation;
    if (*lock == compat::contract_lock_t::workspace_checkpoint ||
        *lock == compat::contract_lock_t::workspace_overlay_transaction) {
        policy.mode = compat::effect_lock_mode_t::unique;
    } else if (*lock == compat::contract_lock_t::debugger_lane ||
               *lock == compat::contract_lock_t::python_worker) {
        policy.mode = compat::effect_lock_mode_t::effect;
    } else {
        policy.mode = compat::effect_lock_mode_t::shared;
    }
    return policy;
}

protocol::cancellation_token_t cancellation_from(
    std::atomic<bool>* state) {
    if (!state)
        return protocol::cancellation_token_t::create();
    return protocol::cancellation_token_t(
        std::shared_ptr<std::atomic_bool>(state, [](std::atomic_bool*) {}));
}

mcp_standalone::tool_result_t to_standalone_result(
    const protocol::mcp_result_t& result) {
    json metadata = result.aida_metadata();
    if (result.is_error()) {
        json details = result.structured_content();
        if (!details.is_object())
            details = json::object();
        if (!metadata.empty())
            details["_meta"]["aida_contract"] = std::move(metadata);
        return mcp_standalone::tool_result_t::error(
            std::string(result.text()), std::string(result.error_code()), details);
    }
    json data = result.structured_content();
    if (!data.is_object())
        data = json::object();
    if (!metadata.empty())
        data["_meta"]["aida_contract"] = std::move(metadata);
    return mcp_standalone::tool_result_t::ok(std::string(result.text()), data);
}

bool server_has_tool(const mcp_standalone::server_t& server,
                     std::string_view name) {
    const auto& tools = server.get_tools();
    return std::any_of(tools.begin(), tools.end(), [name](const auto& tool) {
        return tool.name == name;
    });
}

std::uint64_t workspace_target_id(
    const mcp_standalone::workspace_request_context_t* workspace) noexcept {
    if (!workspace || !workspace->workspace)
        return 0;
    const auto value = reinterpret_cast<std::uintptr_t>(workspace->workspace.get());
    return value == 0 ? 1 : static_cast<std::uint64_t>(value);
}

tool_provenance_metadata_t extension_provenance(
    const extension_tool_binding_t& binding) {
    tool_provenance_metadata_t provenance;
    provenance.contract_name = binding.contract.name;
    provenance.source_path = "aida-extension";
    provenance.effect_name =
        std::string(protocol::tool_effect_name(binding.contract.effect_policy.effect));
    provenance.lock_name =
        std::string(protocol::effect_lock_name(binding.contract.effect_policy.lock));
    provenance.read_only = binding.contract.effect_policy.read_only;
    provenance.unsafe = binding.contract.effect_policy.unsafe;
    return provenance;
}

json nonnegative_integer_schema() {
    return json{{"type", "integer"}, {"minimum", 0}};
}

json query_cursor_schema() {
    return json{
        {"type", "object"},
        {"properties", json{
            {"binary_id", json{{"type", "string"}, {"minLength", 64}, {"maxLength", 64}}},
            {"load_profile_hash", json{{"type", "string"}, {"minLength", 64}, {"maxLength", 64}}},
            {"provider_content_hash", json{{"anyOf", json::array({
                json{{"type", "string"}, {"minLength", 64}, {"maxLength", 64}},
                json{{"type", "null"}},
            })}}},
            {"generation", nonnegative_integer_schema()},
            {"analysis_revision", nonnegative_integer_schema()},
            {"overlay_revision", nonnegative_integer_schema()},
            {"provider_size", nonnegative_integer_schema()},
            {"query_fingerprint", nonnegative_integer_schema()},
            {"position", nonnegative_integer_schema()},
            {"matches_consumed", nonnegative_integer_schema()},
            {"integrity_tag", nonnegative_integer_schema()},
        }},
        {"required", json::array({
            "binary_id", "load_profile_hash", "provider_content_hash", "generation",
            "analysis_revision", "overlay_revision", "provider_size",
            "query_fingerprint", "position", "matches_consumed", "integrity_tag",
        })},
        {"additionalProperties", false},
    };
}

void merge_query_cursor_schema(json& schema) {
    if (!schema.is_object())
        return;
    if (auto properties = schema.find("properties");
        properties != schema.end() && properties->is_object()) {
        if (auto cursor = properties->find("cursor");
            cursor != properties->end() && cursor->is_object()) {
            const auto production = query_cursor_schema();
            auto& cursor_properties = (*cursor)["properties"];
            if (!cursor_properties.is_object())
                cursor_properties = json::object();
            for (const auto& entry : production.at("properties").items())
                cursor_properties[entry.key()] = entry.value();
            (*cursor)["additionalProperties"] = false;
        }
        for (auto& entry : properties->items())
            merge_query_cursor_schema(entry.value());
    }
    if (auto items = schema.find("items"); items != schema.end())
        merge_query_cursor_schema(*items);
    for (const char* keyword : {"anyOf", "allOf", "oneOf"}) {
        if (auto branches = schema.find(keyword);
            branches != schema.end() && branches->is_array()) {
            for (auto& branch : *branches)
                merge_query_cursor_schema(branch);
        }
    }
}

void enrich_query_contract(protocol::tool_contract_t& contract) {
    if (contract.name != "find" && contract.name != "find_bytes" &&
        contract.name != "find_regex" && contract.name != "search_text")
        return;
    if (!contract.input_schema.is_object())
        contract.input_schema = json{{"type", "object"}};
    auto& properties = contract.input_schema["properties"];
    if (!properties.is_object())
        properties = json::object();
    properties["cursor"] = query_cursor_schema();
    merge_query_cursor_schema(contract.output_schema);
}

void enrich_list_instances_contract(protocol::tool_contract_t& contract) {
    if (contract.name != "list_instances")
        return;
    contract.input_schema = json{
        {"type", "object"},
        {"properties", json{
            {"filter", json{{"type", "string"}}},
            {"include_retired", json{{"type", "boolean"}}},
        }},
        {"additionalProperties", false},
    };
    const json instance_schema{
        {"type", "object"},
        {"properties", json{
            {"target_id", nonnegative_integer_schema()},
            {"pid", nonnegative_integer_schema()},
            {"bin_name", json{{"type", "string"}}},
            {"generation", nonnegative_integer_schema()},
            {"attach_generation", nonnegative_integer_schema()},
            {"live", json{{"type", "boolean"}}},
            {"retired", json{{"type", "boolean"}}},
            {"snapshot_stale", json{{"type", "boolean"}}},
            {"process_creation_identity", nonnegative_integer_schema()},
            {"revision", nonnegative_integer_schema()},
        }},
        {"required", json::array({
            "target_id", "pid", "bin_name", "generation", "attach_generation",
            "live", "retired", "snapshot_stale", "process_creation_identity", "revision",
        })},
        {"additionalProperties", false},
    };
    contract.output_schema = json{
        {"type", "object"},
        {"properties", json{
            {"instances", json{{"type", "array"}, {"items", instance_schema}}},
            {"count", nonnegative_integer_schema()},
        }},
        {"required", json::array({"instances", "count"})},
        {"additionalProperties", false},
    };
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
        if (state.generated_indexed)
            return;
        if (compat::contract_count() != compat::k_archive_tool_count)
            throw std::runtime_error("generated MCP contract cardinality is invalid");
        const auto* descriptors = compat::contracts();
        if (!descriptors)
            throw std::runtime_error("generated MCP contract table is unavailable");
        for (std::size_t index = 0; index < compat::contract_count(); ++index) {
            const auto& descriptor = descriptors[index];
            const std::string name(descriptor.name);
            if (name.empty() || state.contracts.find(name) != state.contracts.end())
                throw std::runtime_error("generated MCP contract name is empty or duplicated");
            registered_contract_t entry;
            entry.contract = descriptor_to_contract(descriptor);
            const auto validation = protocol::validate_tool_contract(entry.contract, state.schemas);
            if (!validation.valid)
                throw std::runtime_error(
                    "generated MCP contract validation failed for " + name + ": " +
                    validation.reason);
            entry.descriptor = descriptor;
            entry.adapter_symbol.assign(
                descriptor.adapter_symbol.data(), descriptor.adapter_symbol.size());
            if (entry.adapter_symbol.empty())
                throw std::runtime_error("generated MCP adapter symbol is empty for " + name);
            entry.provenance = descriptor_to_provenance(descriptor);
            entry.generated = true;
            state.contracts.emplace(name, std::move(entry));
            state.union_names.push_back(name);
        }
        state.generated_indexed = true;
        increment_metric(
            &server_integration_metrics_t::tools_from_generated,
            static_cast<std::uint64_t>(compat::contract_count()));
    }

    void index_extension_tools() {
        if (state.extensions_indexed)
            return;
        if (!state.config.extension_binding_provider)
            throw std::runtime_error("MCP extension binding provider is unavailable");
        for (const auto name_view : compat::k_aida_extension_names) {
            const std::string name(name_view);
            if (state.contracts.find(name) != state.contracts.end())
                throw std::runtime_error("MCP extension duplicates a generated tool: " + name);
            auto binding = state.config.extension_binding_provider(name_view);
            if (!binding || binding->contract.name != name || binding->adapter_symbol.empty())
                throw std::runtime_error("MCP extension binding is invalid for " + name);
            const auto validation = protocol::validate_tool_contract(
                binding->contract, state.schemas);
            if (!validation.valid)
                throw std::runtime_error(
                    "MCP extension contract validation failed for " + name + ": " +
                    validation.reason);
            registered_contract_t entry;
            entry.provenance = extension_provenance(*binding);
            entry.contract = std::move(binding->contract);
            entry.adapter_symbol = std::move(binding->adapter_symbol);
            state.contracts.emplace(name, std::move(entry));
            state.union_names.push_back(name);
        }
        state.extensions_indexed = true;
        increment_metric(
            &server_integration_metrics_t::tools_from_extension,
            static_cast<std::uint64_t>(compat::k_aida_extension_count));
    }

    void register_entry(
        const std::shared_ptr<mcp_server_integration_t>& owner,
        const std::string& name) {
        auto found = state.contracts.find(name);
        if (found == state.contracts.end() || found->second.registered)
            return;
        auto& entry = found->second;
        if (server_has_tool(*state.server, name))
            throw std::runtime_error("MCP tool registration collision: " + name);

        auto tool = contract_to_tool_def(entry.contract);
        const bool target_dependent =
            entry.contract.target_policy.requirement !=
            protocol::target_requirement_t::independent;
        if (target_dependent) {
            tool.workspace_handler = [owner, name](
                const json& arguments,
                const mcp_standalone::workspace_request_context_t& workspace) {
                auto cancellation = cancellation_from(workspace.cancellation);
                return to_standalone_result(owner->invoke_tool(
                    name, arguments, cancellation, &workspace));
            };
        } else {
            tool.handler = [owner, name](const json& arguments) {
                auto cancellation = cancellation_from(
                    mcp_standalone::current_cancel_token());
                return to_standalone_result(owner->invoke_tool(
                    name, arguments, cancellation, nullptr));
            };
        }
        if (!state.server->register_tool(std::move(tool)))
            throw std::runtime_error("MCP tool registration failed: " + name);
        entry.registered = true;
        ++state.registered_count;
        increment_metric(&server_integration_metrics_t::tools_registered);
    }
};

json tool_provenance_metadata_t::to_json() const {
    return json{
        {"contract_name", contract_name},
        {"source_path", source_path},
        {"source_line", source_line},
        {"effect", effect_name},
        {"lock", lock_name},
        {"archive_backed", archive_backed},
        {"read_only", read_only},
        {"unsafe", unsafe},
    };
}

mcp_server_integration_t::mcp_server_integration_t(
    std::unique_ptr<impl_t> impl)
    : impl_(std::move(impl)) {}

mcp_server_integration_t::~mcp_server_integration_t() = default;

std::shared_ptr<mcp_server_integration_t>
mcp_server_integration_t::create(
    mcp_standalone::server_t& server,
    server_integration_config_t config) {
    if (!config.enforce_input_validation || !config.enforce_output_validation ||
        !config.move_provenance_to_top_level ||
        !config.replace_hand_drifted_registration ||
        !config.use_generated_descriptors || config.schema_cache_capacity == 0 ||
        config.effect_lock_timeout <= std::chrono::milliseconds::zero() ||
        !config.adapter_dispatcher) {
        throw std::invalid_argument(
            "MCP server integration requires strict generated validation and a real adapter dispatcher");
    }
    auto impl = std::make_unique<impl_t>(server, std::move(config));
    return std::shared_ptr<mcp_server_integration_t>(
        new mcp_server_integration_t(std::move(impl)));
}

void mcp_server_integration_t::register_generated_tools() {
    if (!impl_)
        throw std::logic_error("MCP server integration is not initialized");
    impl_->index_generated_contracts();
    const auto owner = shared_from_this();
    for (const auto& name : impl_->state.union_names) {
        const auto found = impl_->state.contracts.find(name);
        if (found != impl_->state.contracts.end() && found->second.generated)
            impl_->register_entry(owner, name);
    }
}

void mcp_server_integration_t::register_extension_tools() {
    if (!impl_)
        throw std::logic_error("MCP server integration is not initialized");
    impl_->index_generated_contracts();
    impl_->index_extension_tools();
    const auto owner = shared_from_this();
    for (const auto name : compat::k_aida_extension_names)
        impl_->register_entry(owner, std::string(name));
    if (impl_->state.union_names.size() != compat::k_union_tool_count ||
        impl_->state.registered_count != compat::k_union_tool_count)
        throw std::runtime_error("MCP union registration cardinality is invalid");
}

std::size_t mcp_server_integration_t::registered_tool_count() const noexcept {
    return impl_ ? impl_->state.registered_count : 0;
}

std::size_t mcp_server_integration_t::union_tool_count() const noexcept {
    return impl_ ? impl_->state.union_names.size() : 0;
}

std::vector<std::string> mcp_server_integration_t::union_tool_names() const {
    return impl_ ? impl_->state.union_names : std::vector<std::string>{};
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
    const protocol::cancellation_token_t& cancellation,
    const mcp_standalone::workspace_request_context_t* workspace) {
    if (!impl_)
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::internal_error,
            "MCP server integration is not initialized.");
    impl_->increment_metric(&server_integration_metrics_t::total_invocations);

    const auto found = impl_->state.contracts.find(tool_name);
    if (found == impl_->state.contracts.end()) {
        impl_->increment_metric(&server_integration_metrics_t::contract_lookup_misses);
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_contract,
            "Tool contract was not found.", json{{"tool", tool_name}});
    }
    impl_->increment_metric(&server_integration_metrics_t::contract_lookup_hits);
    const auto& entry = found->second;
    const auto& contract = entry.contract;
    json provenance = entry.provenance.to_json();
    provenance["adapter_symbol"] = entry.adapter_symbol;
    provenance["contract_source"] = entry.generated ? "generated" : "extension";
    impl_->increment_metric(&server_integration_metrics_t::provenance_metadata_emitted);

    if (cancellation.cancelled()) {
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Tool invocation was cancelled before validation.",
            json{{"phase", "pre_validation"}}, provenance);
    }
    const auto target_validation = protocol::validate_target_policy(contract, arguments);
    if (!target_validation.valid) {
        impl_->increment_metric(&server_integration_metrics_t::input_validation_failures);
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return protocol::mcp_result_t::failure(
            arguments.is_object()
                ? protocol::result_error_code_t::target_policy_rejected
                : protocol::result_error_code_t::invalid_input,
            "Tool target policy rejected the arguments.",
            target_validation.diagnostics(), provenance);
    }
    const auto input_validation = impl_->state.schemas.validate(
        contract.input_schema, arguments);
    if (!input_validation.valid) {
        impl_->increment_metric(&server_integration_metrics_t::input_validation_failures);
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Tool arguments do not satisfy the generated input schema.",
            json{{"schema", input_validation.diagnostics()}}, provenance);
    }
    impl_->increment_metric(&server_integration_metrics_t::input_validation_passes);

    std::optional<compat::effect_lock_policy_t> lock_policy;
    if (entry.descriptor) {
        const auto resolved = compat::effect_policy_for(*entry.descriptor);
        if (resolved)
            lock_policy = resolved.value();
    } else {
        lock_policy = extension_effect_policy(contract);
    }
    if (!lock_policy) {
        impl_->increment_metric(&server_integration_metrics_t::effect_policy_rejections);
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::effect_policy_rejected,
            "Tool effect policy could not be resolved.",
            json{{"tool", tool_name}}, provenance);
    }
    const std::uint64_t target_id = workspace_target_id(workspace);
    const auto lock_deadline = std::chrono::steady_clock::now() +
        impl_->state.config.effect_lock_timeout;
    auto lease = impl_->state.lock_manager.acquire(
        *lock_policy, target_id, lock_deadline);
    if (!lease) {
        impl_->increment_metric(&server_integration_metrics_t::effect_policy_rejections);
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::effect_policy_rejected,
            "Tool effect lock could not be acquired.",
            json{{"tool", tool_name},
                 {"stable_code", std::string(lease.error.stable_code)}},
            provenance);
    }
    impl_->increment_metric(&server_integration_metrics_t::effect_policy_acquisitions);

    adapter_invocation_t invocation;
    invocation.tool_name = tool_name;
    invocation.adapter_symbol = entry.adapter_symbol;
    invocation.descriptor = entry.descriptor ? &*entry.descriptor : nullptr;
    invocation.contract = &contract;
    invocation.arguments = &arguments;
    invocation.workspace = workspace;
    invocation.cancellation = &cancellation;
    invocation.aida_metadata = provenance;

    protocol::mcp_result_t result = protocol::mcp_result_t::failure(
        protocol::result_error_code_t::handler_failed,
        "Tool adapter dispatch failed.", json{{"tool", tool_name}}, provenance);
    try {
        result = impl_->state.config.adapter_dispatcher(invocation);
    } catch (const std::exception&) {
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return result;
    } catch (...) {
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return result;
    }
    if (result.is_error()) {
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return result.with_aida_metadata(provenance);
    }
    if (cancellation.cancelled()) {
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Tool invocation was cancelled before result delivery.",
            json{{"phase", "post_dispatch"}}, provenance);
    }
    const auto output_validation = impl_->state.schemas.validate(
        contract.output_schema, result.structured_content());
    if (!output_validation.valid) {
        impl_->increment_metric(&server_integration_metrics_t::output_validation_failures);
        impl_->increment_metric(&server_integration_metrics_t::total_errors);
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Tool result does not satisfy the generated output schema.",
            json{{"schema", output_validation.diagnostics()}}, provenance);
    }
    impl_->increment_metric(&server_integration_metrics_t::output_validation_passes);
    return result.with_aida_metadata(provenance);
}

protocol::tool_contract_t
mcp_server_integration_t::descriptor_to_contract(
    const compat::contract_descriptor_t& descriptor) {
    protocol::tool_contract_t contract;
    contract.name.assign(descriptor.name.data(), descriptor.name.size());
    contract.description.assign(
        descriptor.description.data(), descriptor.description.size());
    contract.input_schema = json::parse(
        descriptor.input_schema_json.begin(), descriptor.input_schema_json.end());
    contract.output_schema = json::parse(
        descriptor.output_schema_json.begin(), descriptor.output_schema_json.end());
    contract.annotations = json::parse(
        descriptor.annotations_json.begin(), descriptor.annotations_json.end());
    contract.target_policy = descriptor_to_target_policy(descriptor);
    contract.effect_policy = descriptor_to_effect_policy(descriptor);
    enrich_query_contract(contract);
    enrich_list_instances_contract(contract);
    return contract;
}

mcp_standalone::tool_def_t
mcp_server_integration_t::contract_to_tool_def(
    const protocol::tool_contract_t& contract) {
    mcp_standalone::tool_def_t tool;
    tool.name = contract.name;
    tool.description = contract.description;
    tool.read_only = contract.effect_policy.read_only;
    tool.visibility = mcp_standalone::tool_visibility_t::external_visible;
    tool.input_schema = contract.input_schema;
    return tool;
}

tool_provenance_metadata_t
mcp_server_integration_t::descriptor_to_provenance(
    const compat::contract_descriptor_t& descriptor) {
    tool_provenance_metadata_t provenance;
    provenance.contract_name.assign(descriptor.name.data(), descriptor.name.size());
    provenance.source_path.assign(
        descriptor.source_path.data(), descriptor.source_path.size());
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
        ? protocol::target_requirement_t::optional
        : protocol::target_requirement_t::independent;
    policy.accepts_pid = descriptor.accepts_pid;
    policy.accepts_bin_name = descriptor.accepts_bin_name;
    return policy;
}

bool mcp_server_integration_t::validate_union_count() noexcept {
    return compat::contract_count() == compat::k_archive_tool_count &&
        compat::k_archive_tool_count + compat::k_aida_extension_count ==
            compat::k_union_tool_count;
}

}
