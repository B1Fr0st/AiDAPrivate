#pragma once

#include "mcp_result.hpp"
#include "schema_runtime.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace aida::standalone::mcp::protocol {

enum class target_requirement_t {
    independent,
    optional,
    required,
};

struct target_policy_t {
    target_requirement_t requirement = target_requirement_t::independent;
    bool accepts_pid = false;
    bool accepts_bin_name = false;
};

enum class tool_effect_t {
    unspecified,
    workspace_read,
    workspace_checkpoint,
    workspace_overlay_mutation,
    debugger_read,
    debugger_control,
    debugger_write,
    isolated_python,
    registry_read,
};

enum class effect_lock_t {
    unspecified,
    workspace_shared,
    workspace_checkpoint,
    workspace_overlay_transaction,
    debugger_lane,
    python_worker,
    registry_read,
};

struct effect_policy_t {
    tool_effect_t effect = tool_effect_t::unspecified;
    effect_lock_t lock = effect_lock_t::unspecified;
    bool read_only = true;
    bool unsafe = false;
};

std::string_view target_requirement_name(target_requirement_t requirement) noexcept;
std::string_view tool_effect_name(tool_effect_t effect) noexcept;
std::string_view effect_lock_name(effect_lock_t lock) noexcept;

class cancellation_token_t {
public:
    cancellation_token_t();
    explicit cancellation_token_t(std::shared_ptr<std::atomic_bool> state);

    static cancellation_token_t create(bool cancelled = false);
    bool cancelled() const noexcept;
    void cancel() noexcept;
    std::shared_ptr<std::atomic_bool> state() const noexcept;

private:
    std::shared_ptr<std::atomic_bool> state_;
};

struct tool_contract_t {
    std::string name;
    std::string description;
    json input_schema;
    json output_schema;
    json annotations;
    target_policy_t target_policy;
    effect_policy_t effect_policy;

    json tool_list_entry() const;
};

struct contract_validation_t {
    bool valid = true;
    result_error_code_t error_code = result_error_code_t::invalid_contract;
    std::string reason;
    json details = json::object();

    json diagnostics() const;
};

contract_validation_t validate_target_policy(
    const tool_contract_t& contract,
    const json& arguments);

contract_validation_t validate_effect_policy(const tool_contract_t& contract);
contract_validation_t validate_tool_contract(
    const tool_contract_t& contract,
    schema_runtime_t& schemas);

using tool_handler_t = std::function<mcp_result_t(
    const json& arguments,
    const cancellation_token_t& cancellation)>;

mcp_result_t invoke_tool_contract(
    const tool_contract_t& contract,
    const json& arguments,
    const tool_handler_t& handler,
    schema_runtime_t& schemas,
    const cancellation_token_t& cancellation,
    const json& aida_metadata = json::object());

mcp_result_t invoke_tool_contract(
    const tool_contract_t& contract,
    const json& arguments,
    const tool_handler_t& handler,
    schema_runtime_t& schemas,
    const json& aida_metadata = json::object());

}
