#pragma once

#include "../mcp_standalone.hpp"
#include "../protocol/mcp_result.hpp"
#include "../protocol/mcp_tool_contract.hpp"
#include "../protocol/schema_runtime.hpp"
#include "../compat/ida_contracts_generated.hpp"
#include "../compat/effect_policy.hpp"
#include "../compat/workspace_adapter.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aida::standalone::mcp::integration {

using json = nlohmann::json;

struct adapter_invocation_t final {
    std::string_view tool_name;
    std::string_view adapter_symbol;
    const compat::contract_descriptor_t* descriptor = nullptr;
    const protocol::tool_contract_t* contract = nullptr;
    const json* arguments = nullptr;
    const mcp_standalone::workspace_request_context_t* workspace = nullptr;
    const protocol::cancellation_token_t* cancellation = nullptr;
    json aida_metadata = json::object();
};

using adapter_dispatcher_t = std::function<protocol::mcp_result_t(
    const adapter_invocation_t& invocation)>;

struct extension_tool_binding_t final {
    protocol::tool_contract_t contract;
    std::string adapter_symbol;
};

using extension_binding_provider_t = std::function<std::optional<extension_tool_binding_t>(
    std::string_view tool_name)>;

struct server_integration_config_t {
    bool enforce_input_validation = true;
    bool enforce_output_validation = true;
    bool move_provenance_to_top_level = true;
    bool replace_hand_drifted_registration = true;
    bool use_generated_descriptors = true;
    std::size_t schema_cache_capacity = 256;
    std::chrono::milliseconds effect_lock_timeout{5000};
    adapter_dispatcher_t adapter_dispatcher;
    extension_binding_provider_t extension_binding_provider;
};

struct server_integration_metrics_t {
    std::uint64_t tools_registered = 0;
    std::uint64_t tools_from_generated = 0;
    std::uint64_t tools_from_extension = 0;
    std::uint64_t input_validation_passes = 0;
    std::uint64_t input_validation_failures = 0;
    std::uint64_t output_validation_passes = 0;
    std::uint64_t output_validation_failures = 0;
    std::uint64_t provenance_metadata_emitted = 0;
    std::uint64_t contract_lookup_hits = 0;
    std::uint64_t contract_lookup_misses = 0;
    std::uint64_t effect_policy_acquisitions = 0;
    std::uint64_t effect_policy_rejections = 0;
    std::uint64_t total_invocations = 0;
    std::uint64_t total_errors = 0;
};

struct tool_provenance_metadata_t {
    std::string contract_name;
    std::string source_path;
    std::uint32_t source_line = 0;
    std::string effect_name;
    std::string lock_name;
    bool archive_backed = false;
    bool read_only = true;
    bool unsafe = false;
    json to_json() const;
};

class mcp_server_integration_t final
    : public std::enable_shared_from_this<mcp_server_integration_t> {
public:
    static std::shared_ptr<mcp_server_integration_t>
        create(mcp_standalone::server_t& server,
               server_integration_config_t config = {});

    ~mcp_server_integration_t();
    mcp_server_integration_t(const mcp_server_integration_t&) = delete;
    mcp_server_integration_t& operator=(const mcp_server_integration_t&) = delete;

    void register_generated_tools();

    void register_extension_tools();

    std::size_t registered_tool_count() const noexcept;

    std::size_t union_tool_count() const noexcept;

    std::vector<std::string> union_tool_names() const;

    server_integration_metrics_t metrics() const noexcept;

    protocol::mcp_result_t invoke_tool(
        const std::string& tool_name,
        const json& arguments,
        const protocol::cancellation_token_t& cancellation = {},
        const mcp_standalone::workspace_request_context_t* workspace = nullptr);

    static protocol::tool_contract_t
        descriptor_to_contract(const compat::contract_descriptor_t& descriptor);

    static mcp_standalone::tool_def_t
        contract_to_tool_def(const protocol::tool_contract_t& contract);

    static tool_provenance_metadata_t
        descriptor_to_provenance(const compat::contract_descriptor_t& descriptor);

    static protocol::effect_policy_t
        descriptor_to_effect_policy(const compat::contract_descriptor_t& descriptor);

    static protocol::target_policy_t
        descriptor_to_target_policy(const compat::contract_descriptor_t& descriptor);

    static bool validate_union_count() noexcept;

    static constexpr std::size_t expected_union_count() noexcept {
        return compat::k_union_tool_count;
    }

private:
    struct impl_t;
    explicit mcp_server_integration_t(std::unique_ptr<impl_t> impl);
    std::unique_ptr<impl_t> impl_;
};

}
