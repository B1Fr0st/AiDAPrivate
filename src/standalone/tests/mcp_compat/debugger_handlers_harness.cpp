#include "debugger_handlers_harness.hpp"

#include "../../src/core/mcp/compat/handlers/debugger.hpp"
#include "../../src/core/mcp/compat/debugger_lane.hpp"
#include "../../src/core/mcp/compat/workspace_adapter.hpp"
#include "../../src/core/mcp/compat/target_resolver.hpp"
#include "../../src/core/mcp/compat/effect_policy.hpp"
#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"
#include "../../src/core/mcp/protocol/mcp_tool_contract.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida::standalone::tests::mcp_compat {

namespace {

using namespace aida::standalone::mcp::compat;
using namespace aida::standalone::mcp::compat::handlers;
using protocol::cancellation_token_t;
using protocol::json;

void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void require_fixture(bool condition, std::string_view tool, std::string_view category,
                     std::string_view detail) {
    if (!condition) {
        throw std::runtime_error(
            std::string(tool) + " " + std::string(category) + " fixture: " +
            std::string(detail));
    }
}

json schema_instance(const json& schema) {
    if (!schema.is_object()) {
        return nullptr;
    }
    if (const auto constant = schema.find("const"); constant != schema.end()) {
        return *constant;
    }
    if (const auto enumeration = schema.find("enum");
        enumeration != schema.end() && enumeration->is_array() && !enumeration->empty()) {
        return (*enumeration)[0];
    }
    for (const char* keyword : {"anyOf", "oneOf"}) {
        const auto alternatives = schema.find(keyword);
        if (alternatives != schema.end() && alternatives->is_array() && !alternatives->empty()) {
            return schema_instance((*alternatives)[0]);
        }
    }
    const auto all_of = schema.find("allOf");
    if (all_of != schema.end() && all_of->is_array() && !all_of->empty()) {
        json merged = json::object();
        for (const auto& component : *all_of) {
            json instance = schema_instance(component);
            if (!instance.is_object()) {
                return instance;
            }
            merged.update(instance);
        }
        return merged;
    }
    std::string type;
    const auto type_field = schema.find("type");
    if (type_field != schema.end() && type_field->is_string()) {
        type = type_field->get<std::string>();
    } else if (type_field != schema.end() && type_field->is_array()) {
        for (const auto& candidate : *type_field) {
            if (candidate.is_string() && candidate.get_ref<const std::string&>() != "null") {
                type = candidate.get<std::string>();
                break;
            }
        }
    } else if (schema.contains("properties")) {
        type = "object";
    }
    if (type == "object") {
        json result = json::object();
        const auto required = schema.find("required");
        const auto properties = schema.find("properties");
        if (required != schema.end() && required->is_array()) {
            for (const auto& name : *required) {
                if (!name.is_string() || properties == schema.end() || !properties->is_object()) {
                    throw std::runtime_error("generated output schema has an unresolved required property");
                }
                const auto property = properties->find(name.get_ref<const std::string&>());
                if (property == properties->end()) {
                    throw std::runtime_error("generated output schema required property is absent");
                }
                result[name.get_ref<const std::string&>()] = schema_instance(*property);
            }
        }
        return result;
    }
    if (type == "array") {
        json result = json::array();
        std::size_t count = 0;
        if (const auto minimum = schema.find("minItems");
            minimum != schema.end() && minimum->is_number_unsigned()) {
            count = minimum->get<std::size_t>();
        }
        const auto items = schema.find("items");
        for (std::size_t index = 0; index < count; ++index) {
            result.push_back(items == schema.end() ? json(nullptr) : schema_instance(*items));
        }
        return result;
    }
    if (type == "string") {
        std::size_t length = 1;
        if (const auto minimum = schema.find("minLength");
            minimum != schema.end() && minimum->is_number_unsigned()) {
            length = (std::max)(length, minimum->get<std::size_t>());
        }
        return std::string(length, 'x');
    }
    if (type == "integer") {
        if (const auto minimum = schema.find("minimum");
            minimum != schema.end() && minimum->is_number_integer()) {
            return *minimum;
        }
        return 0;
    }
    if (type == "number") {
        return 0.0;
    }
    if (type == "boolean") {
        return false;
    }
    return nullptr;
}

struct fake_debugger_state_t final {
    std::uint32_t pid = 5301;
    std::uint64_t process_creation_identity = 0xC10ULL;
    std::uint64_t module_base = 0x140000000ULL;
    std::uint64_t module_size = 0x10000ULL;
    std::uint64_t attach_generation = 0x200ULL;
    bool attached = true;
    bool detach_after = false;
    bool lose_attach = false;
    bool stale_pid = false;
    std::uint32_t stale_pid_value = 9999;
    std::atomic_size_t calls{0};
    std::atomic_size_t active_executions{0};
    std::atomic_size_t peak_executions{0};
    std::atomic_int execution_delay_ms{0};
    std::atomic<debugger_adapter_error_code_t> next_error{
        debugger_adapter_error_code_t::none};
    mutable std::mutex last_tool_mutex;
    std::string last_tool;
    bool invalid_output = false;
    std::shared_ptr<std::atomic_bool> cancel_during_dispatch;

    debugger_target_identity_t current_identity() const noexcept {
        return {
            lose_attach ? 0U : (stale_pid ? stale_pid_value : pid),
            lose_attach ? 0ULL : process_creation_identity,
            lose_attach ? 0ULL : module_base,
            lose_attach ? 0ULL : module_size,
            lose_attach ? 0ULL : attach_generation,
            lose_attach ? false : attached,
        };
    }

    void set_last_tool(std::string value) {
        std::lock_guard<std::mutex> lock(last_tool_mutex);
        last_tool = std::move(value);
    }

    std::string get_last_tool() const {
        std::lock_guard<std::mutex> lock(last_tool_mutex);
        return last_tool;
    }
};

class active_execution_guard_t final {
public:
    explicit active_execution_guard_t(fake_debugger_state_t& state) noexcept
        : state_(state) {
        const std::size_t active =
            state_.active_executions.fetch_add(1, std::memory_order_acq_rel) + 1U;
        std::size_t peak = state_.peak_executions.load(std::memory_order_acquire);
        while (peak < active &&
               !state_.peak_executions.compare_exchange_weak(
                   peak, active, std::memory_order_acq_rel,
                   std::memory_order_acquire)) {
        }
    }

    ~active_execution_guard_t() noexcept {
        state_.active_executions.fetch_sub(1, std::memory_order_acq_rel);
    }

    active_execution_guard_t(const active_execution_guard_t&) = delete;
    active_execution_guard_t& operator=(const active_execution_guard_t&) = delete;

private:
    fake_debugger_state_t& state_;
};

class fake_debugger_adapter_t final : public debugger_adapter_t {
public:
    explicit fake_debugger_adapter_t(fake_debugger_state_t& state) : state_(state) {}

    debugger_adapter_result_t<debugger_target_identity_t> identity(
        const protocol::cancellation_token_t& cancellation,
        std::chrono::steady_clock::time_point deadline) override {
        if (cancellation.cancelled()) {
            return debugger_adapter_result_t<debugger_target_identity_t>::failure(
                debugger_adapter_error_code_t::cancelled);
        }
        if (std::chrono::steady_clock::now() > deadline) {
            return debugger_adapter_result_t<debugger_target_identity_t>::failure(
                debugger_adapter_error_code_t::deadline_exceeded);
        }
        if (state_.lose_attach) {
            return debugger_adapter_result_t<debugger_target_identity_t>::failure(
                debugger_adapter_error_code_t::attach_lost);
        }
        return debugger_adapter_result_t<debugger_target_identity_t>::success(
            state_.current_identity());
    }

    debugger_adapter_result_t<debugger_adapter_response_t> execute(
        const debugger_adapter_request_t& request) override {
        active_execution_guard_t active_guard(state_);
        state_.calls.fetch_add(1, std::memory_order_acq_rel);
        state_.set_last_tool(request.tool_name);
        const int delay = state_.execution_delay_ms.load(std::memory_order_acquire);
        if (delay > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        }
        if (state_.cancel_during_dispatch) {
            state_.cancel_during_dispatch->store(true, std::memory_order_release);
        }
        const auto error = state_.next_error.exchange(
            debugger_adapter_error_code_t::none, std::memory_order_acq_rel);
        if (error != debugger_adapter_error_code_t::none) {
            return debugger_adapter_result_t<debugger_adapter_response_t>::failure(error);
        }
        json output;
        if (state_.invalid_output) {
            output = json{{"__schema_violation", true}};
        } else if (const auto* descriptor = find_contract(request.tool_name)) {
            const json schema = json::parse(
                descriptor->output_schema_json.begin(),
                descriptor->output_schema_json.end());
            output = schema_instance(schema);
        } else {
            output = json::object();
        }
        if (request.tool_name == "dbg_exit") {
            state_.detach_after = true;
            state_.attached = false;
        }
        debugger_adapter_response_t response;
        response.structured = output;
        response.truncated = false;
        return debugger_adapter_result_t<debugger_adapter_response_t>::success(
            std::move(response));
    }

private:
    fake_debugger_state_t& state_;
};

target_record_t make_debug_target(std::uint64_t target_id, std::uint32_t pid,
                                  std::uint64_t creation_identity, std::string name) {
    target_record_t target;
    target.target_id = target_id;
    target.pid = pid;
    target.process_creation_identity = creation_identity;
    target.bin_name = std::move(name);
    target.generation = 1;
    target.attach_generation = 0x200ULL;
    target.live = true;
    target.live_capture_base = 0x140000000ULL;
    target.live_capture_size = 0x10000ULL;
    target.live_snapshot_permitted = true;
    target.live_snapshot_maximum_bytes = 0x10000ULL;
    target.revision = 1;
    return target;
}

const adapters::debugger_adapter_handler_t k_debugger_adapters[k_debugger_tool_count] = {
    &adapters::dbg_add_bp,
    &adapters::dbg_bps,
    &adapters::dbg_continue,
    &adapters::dbg_delete_bp,
    &adapters::dbg_exit,
    &adapters::dbg_gpregs,
    &adapters::dbg_gpregs_remote,
    &adapters::dbg_read,
    &adapters::dbg_regs,
    &adapters::dbg_regs_all,
    &adapters::dbg_regs_named,
    &adapters::dbg_regs_named_remote,
    &adapters::dbg_regs_remote,
    &adapters::dbg_run_to,
    &adapters::dbg_set_bp_condition,
    &adapters::dbg_stacktrace,
    &adapters::dbg_start,
    &adapters::dbg_status,
    &adapters::dbg_step_into,
    &adapters::dbg_step_over,
    &adapters::dbg_toggle_bp,
    &adapters::dbg_write,
};

json routed(json arguments) {
    arguments["pid"] = 5301;
    return arguments;
}

json make_valid_args(std::string_view tool) {
    if (tool == "dbg_add_bp" || tool == "dbg_delete_bp") {
        return routed({{"addrs", "0x140001000"}});
    }
    if (tool == "dbg_bps" || tool == "dbg_continue" || tool == "dbg_exit" ||
        tool == "dbg_gpregs" || tool == "dbg_regs" || tool == "dbg_regs_all" ||
        tool == "dbg_stacktrace" || tool == "dbg_start" || tool == "dbg_status" ||
        tool == "dbg_step_into" || tool == "dbg_step_over") {
        return routed(json::object());
    }
    if (tool == "dbg_gpregs_remote" || tool == "dbg_regs_remote") {
        return routed({{"tids", 100}});
    }
    if (tool == "dbg_read") {
        return routed({{"regions", json{{"addr", "0x140001000"}, {"size", 64}}}});
    }
    if (tool == "dbg_regs_named") {
        return routed({{"register_names", "RAX, RBX, RCX"}});
    }
    if (tool == "dbg_regs_named_remote") {
        return routed({{"thread_id", 100}, {"register_names", "RAX, RBX"}});
    }
    if (tool == "dbg_run_to") {
        return routed({{"addr", "0x140001000"}});
    }
    if (tool == "dbg_set_bp_condition") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"condition", "RAX==0"}}}});
    }
    if (tool == "dbg_toggle_bp") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"enabled", true}}}});
    }
    if (tool == "dbg_write") {
        return routed({{"regions", json{{"addr", "0x140001000"}, {"data", "90 90 90 90"}}}});
    }
    return routed(json::object());
}

std::string hex_payload(std::size_t byte_count) {
    std::string payload;
    if (byte_count != 0) {
        payload.reserve(byte_count * 3U - 1U);
    }
    for (std::size_t index = 0; index < byte_count; ++index) {
        if (index != 0) {
            payload.push_back(' ');
        }
        payload.append("A5");
    }
    return payload;
}

std::optional<json> make_boundary_args(
    std::string_view tool, const debugger_handler_limits_t& limits) {
    if (tool == "dbg_add_bp" || tool == "dbg_delete_bp") {
        json addrs = json::array();
        for (std::size_t i = 0; i < limits.max_breakpoints; ++i) {
            addrs.push_back("0x" + std::to_string(i));
        }
        return routed({{"addrs", std::move(addrs)}});
    }
    if (tool == "dbg_read") {
        return routed({{"regions", json{{"addr", "0x140001000"},
                                          {"size", limits.max_read_bytes_per_region}}}});
    }
    if (tool == "dbg_write") {
        return routed({{"regions", json{{"addr", "0x140001000"},
                                          {"data", hex_payload(
                                              limits.max_write_bytes_per_region)}}}});
    }
    if (tool == "dbg_set_bp_condition") {
        return routed({{"items", json{{"addr", "0x140001000"},
                                         {"condition", std::string(
                                             limits.max_condition_bytes, 'c')}}}});
    }
    if (tool == "dbg_toggle_bp") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_breakpoints; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"enabled", true}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "dbg_gpregs_remote" || tool == "dbg_regs_remote") {
        json tids = json::array();
        for (std::size_t i = 0; i < limits.max_threads; ++i) {
            tids.push_back(static_cast<std::int64_t>(i + 1));
        }
        return routed({{"tids", std::move(tids)}});
    }
    return std::nullopt;
}

std::optional<json> make_invalid_args(
    std::string_view tool, const debugger_handler_limits_t& limits) {
    if (tool == "dbg_add_bp" || tool == "dbg_delete_bp") {
        json addrs = json::array();
        for (std::size_t i = 0; i < limits.max_breakpoints + 1; ++i) {
            addrs.push_back("0x" + std::to_string(i));
        }
        return routed({{"addrs", std::move(addrs)}});
    }
    if (tool == "dbg_read") {
        return routed({{"regions", json{{"addr", "0x140001000"}, {"size", limits.max_read_bytes_per_region + 1}}}});
    }
    if (tool == "dbg_write") {
        return routed({{"regions", json{{"addr", "0x140001000"},
                                          {"data", hex_payload(
                                              limits.max_write_bytes_per_region + 1U)}}}});
    }
    if (tool == "dbg_set_bp_condition") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"condition", std::string(limits.max_condition_bytes + 1, 'c')}}}});
    }
    if (tool == "dbg_toggle_bp") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_breakpoints + 1; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"enabled", true}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "dbg_gpregs_remote" || tool == "dbg_regs_remote") {
        json tids = json::array();
        for (std::size_t i = 0; i < limits.max_threads + 1; ++i) {
            tids.push_back(static_cast<std::int64_t>(i + 1));
        }
        return routed({{"tids", std::move(tids)}});
    }
    if (tool == "dbg_run_to") {
        return routed({{"addr", ""}});
    }
    if (tool == "dbg_regs_named") {
        return routed({{"register_names", ""}});
    }
    return std::nullopt;
}

bool tool_requires_approval(std::string_view tool) noexcept {
    return tool == "dbg_add_bp" || tool == "dbg_continue" || tool == "dbg_delete_bp" ||
           tool == "dbg_exit" || tool == "dbg_run_to" || tool == "dbg_set_bp_condition" ||
           tool == "dbg_start" || tool == "dbg_step_into" || tool == "dbg_step_over" ||
           tool == "dbg_toggle_bp" || tool == "dbg_write";
}

void verify_contracts(const debugger_handlers_t& handlers,
                      protocol::schema_runtime_t& schemas) {
    require(handlers.size() == k_debugger_tool_count,
            "debugger handler contract count is not exactly twenty-two");
    require(debugger_tool_names().size() == k_debugger_tool_count,
            "debugger name ledger count is not exactly twenty-two");
    std::unordered_set<std::string> unique_names;
    for (std::size_t index = 0; index < k_debugger_tool_count; ++index) {
        const auto name = debugger_tool_names()[index];
        const auto* descriptor = aida::standalone::mcp::compat::find_contract(name);
        const auto& contract = handlers.contract_at(index);
        require(descriptor != nullptr, "debugger generated descriptor is missing");
        require(contract.name == name && handlers.find(name) == &contract,
                "debugger handler lookup differs from the exact name ledger");
        require(unique_names.emplace(contract.name).second,
                "debugger handler name ledger contains a duplicate");
        require(descriptor->adapter_symbol ==
                    "aida::standalone::mcp::compat::adapters::" + std::string(name),
                "debugger generated adapter symbol differs from the linked function name");
        require(contract.description == descriptor->description,
                "debugger generated description was not preserved");
        require(contract.input_schema == json::parse(
                    descriptor->input_schema_json.begin(), descriptor->input_schema_json.end()) &&
                    contract.output_schema == json::parse(
                    descriptor->output_schema_json.begin(), descriptor->output_schema_json.end()) &&
                    contract.annotations == json::parse(
                    descriptor->annotations_json.begin(), descriptor->annotations_json.end()),
                "debugger generated schema or annotations were not preserved");
        require(contract.target_policy.requirement == protocol::target_requirement_t::required &&
                    contract.target_policy.accepts_pid &&
                    contract.target_policy.accepts_bin_name,
                "debugger target routing policy is not the generated required selector policy");
        require(contract.effect_policy.lock == protocol::effect_lock_t::debugger_lane,
                "debugger effect lock is not debugger_lane");
        require(contract.effect_policy.unsafe,
                "debugger effect policy is not marked unsafe");
        if (name == "dbg_write") {
            require(contract.effect_policy.effect == protocol::tool_effect_t::debugger_write,
                    "dbg_write must have debugger_write effect");
            require(!contract.effect_policy.read_only,
                    "dbg_write must not be read_only");
        } else if (tool_requires_approval(name)) {
            require(contract.effect_policy.effect == protocol::tool_effect_t::debugger_control,
                    "debugger control tool must have debugger_control effect");
            require(!contract.effect_policy.read_only,
                    "debugger control tool must not be read_only");
        } else {
            require(contract.effect_policy.effect == protocol::tool_effect_t::debugger_read,
                    "debugger read tool must have debugger_read effect");
            require(contract.effect_policy.read_only,
                    "debugger read tool must be read_only");
        }
        require(protocol::validate_tool_contract(contract, schemas).valid,
                "debugger generated contract does not validate through the schema runtime");
        const json list_entry = contract.tool_list_entry();
        require(list_entry.at("inputSchema") == contract.input_schema &&
                    list_entry.at("outputSchema") == contract.output_schema &&
                    !list_entry.contains("_meta"),
                "debugger tool list entry altered schema or embedded provenance");
    }
}

void verify_fixture(std::string_view tool_name,
                    adapters::debugger_adapter_handler_t adapter,
                    const debugger_handlers_t& handlers,
                    fake_debugger_state_t& state,
                    std::size_t& completed) {
    const json metadata{{"fixture_tool", std::string(tool_name)}};
    const debugger_effect_approval_t approved{true, 42, "harness"};
    const debugger_effect_approval_t denied{false, 0, ""};

    json valid_args = make_valid_args(tool_name);
    std::size_t before = state.calls.load(std::memory_order_acquire);
    protocol::mcp_result_t result = protocol::mcp_result_t::failure(
        protocol::result_error_code_t::internal_error, "fixture_not_executed");

    if (tool_requires_approval(tool_name)) {
        before = state.calls.load(std::memory_order_acquire);
        result = adapter(handlers, valid_args, cancellation_token_t::create(), denied, metadata);
        require_fixture(result.is_error() &&
                            result.error_code() == "MCP_TOOL_EFFECT_POLICY_REJECTED",
                        tool_name, "approval_denied",
                        "non-read tool without approval was not rejected canonically");
        require_fixture(state.calls.load(std::memory_order_acquire) == before,
                        tool_name, "approval_denied",
                        "denied approval reached the backend");
        ++completed;

        const debugger_effect_approval_t unidentified{true, 0, ""};
        result = adapter(
            handlers, valid_args, cancellation_token_t::create(), unidentified, metadata);
        require_fixture(result.is_error() &&
                            result.error_code() == "MCP_TOOL_EFFECT_POLICY_REJECTED" &&
                            state.calls.load(std::memory_order_acquire) == before,
                        tool_name, "approval_identity",
                        "unidentified approval reached the backend");
        ++completed;
    }

    before = state.calls.load(std::memory_order_acquire);
    result = adapter(handlers, valid_args, cancellation_token_t::create(), approved, metadata);
    require_fixture(!result.is_error(), tool_name, "valid", result.text());
    require_fixture(state.calls.load(std::memory_order_acquire) == before + 1U,
                    tool_name, "valid",
                    "backend was not invoked exactly once");
    require_fixture(state.get_last_tool() == tool_name, tool_name, "valid",
                    "request reached the wrong tool in backend");
    require_fixture(result.structured_content().is_object() &&
                        !result.structured_content().contains("_meta"),
                    tool_name, "valid", "structured output or metadata separation changed");
    require_fixture(result.aida_metadata().value("tool", std::string()) == tool_name,
                    tool_name, "valid", "provenance metadata is incomplete");
    ++completed;
    if (tool_name == "dbg_exit") {
        state.attached = true;
    }

    const auto boundary_args = make_boundary_args(tool_name, handlers.limits());
    if (boundary_args) {
        before = state.calls.load(std::memory_order_acquire);
        result = adapter(
            handlers, *boundary_args, cancellation_token_t::create(), approved, metadata);
        require_fixture(!result.is_error(), tool_name, "boundary", result.text());
        require_fixture(state.calls.load(std::memory_order_acquire) == before + 1U,
                        tool_name, "boundary",
                        "pinned maximum was not admitted by the backend lane");
        ++completed;
    }

    const auto invalid_args = make_invalid_args(tool_name, handlers.limits());
    if (invalid_args) {
        before = state.calls.load(std::memory_order_acquire);
        result = adapter(
            handlers, *invalid_args, cancellation_token_t::create(), approved, metadata);
        require_fixture(result.is_error() &&
                            result.error_code() == "MCP_TOOL_INPUT_INVALID",
                        tool_name, "invalid", "out-of-policy input was not rejected canonically");
        require_fixture(state.calls.load(std::memory_order_acquire) == before,
                        tool_name, "invalid",
                        "invalid input reached the backend");
        require_fixture(
            result.structured_content().at("error").at("details").value(
                "policy", std::string()) == "bounded_debugger_adapter",
            tool_name, "invalid", "bounded policy diagnostics are absent");
        ++completed;
    }

    auto cancellation = cancellation_token_t::create();
    state.cancel_during_dispatch = cancellation.state();
    before = state.calls.load(std::memory_order_acquire);
    result = adapter(handlers, valid_args, cancellation, approved, metadata);
    state.cancel_during_dispatch.reset();
    require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                    tool_name, "cancellation",
                    "in-flight cancellation was not observed canonically");
    ++completed;
    if (tool_name == "dbg_exit") {
        state.attached = true;
    }

    state.invalid_output = true;
    result = adapter(handlers, valid_args, cancellation_token_t::create(), approved, metadata);
    state.invalid_output = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    tool_name, "output_validation",
                    "schema-invalid structured output was not rejected canonically");
    ++completed;
    if (tool_name == "dbg_exit") {
        state.attached = true;
    }
}

void verify_attach_loss(const debugger_handlers_t& handlers,
                        fake_debugger_state_t& state,
                        std::size_t& completed) {
    const debugger_effect_approval_t approved{true, 42, "harness"};
    state.lose_attach = true;
    auto result = adapters::dbg_status(handlers, routed(json::object()),
                                        cancellation_token_t::create(), approved);
    state.lose_attach = false;
    require_fixture(result.is_error(), "dbg_status", "attach_loss",
                    "attach loss was not surfaced as an error");
    require_fixture(result.structured_content().at("error").at("details").value(
                        "adapter_code", std::string()) == "debugger_attach_lost",
                    "dbg_status", "attach_loss",
                    "attach loss error code was not propagated");
    ++completed;
}

void verify_stale_pid(const debugger_handlers_t& handlers,
                      fake_debugger_state_t& state,
                      std::size_t& completed) {
    const debugger_effect_approval_t approved{true, 42, "harness"};
    state.stale_pid = true;
    state.stale_pid_value = 8888;
    auto result = adapters::dbg_status(handlers, routed(json::object()),
                                        cancellation_token_t::create(), approved);
    state.stale_pid = false;
    require_fixture(result.is_error(), "dbg_status", "stale_pid",
                    "stale PID was not surfaced as an error");
    require_fixture(result.structured_content().at("error").at("details").value(
                        "adapter_code", std::string()) == "debugger_pid_reused",
                    "dbg_status", "stale_pid",
                    "pid reuse error code was not propagated");
    ++completed;
}

void verify_adapter_failure_classification(
    const debugger_handlers_t& handlers,
    fake_debugger_state_t& state,
    std::size_t& completed) {
    const debugger_effect_approval_t approved{true, 42, "harness"};
    const auto verify_error = [&handlers, &state, &approved, &completed](
        adapters::debugger_adapter_handler_t adapter,
        std::string_view tool,
        debugger_adapter_error_code_t injected,
        std::string_view expected_code) {
        state.next_error.store(injected, std::memory_order_release);
        const auto result = adapter(
            handlers, make_valid_args(tool), cancellation_token_t::create(), approved,
            json{{"fixture", std::string(expected_code)}});
        require_fixture(result.is_error(), tool, expected_code,
                        "injected adapter failure was not surfaced");
        require_fixture(
            result.structured_content().at("error").at("details").value(
                "adapter_code", std::string()) == expected_code,
            tool, expected_code, "stable adapter failure code was not preserved");
        ++completed;
    };

    verify_error(&adapters::dbg_add_bp, "dbg_add_bp",
                 debugger_adapter_error_code_t::breakpoint_conflict,
                 "debugger_breakpoint_conflict");
    verify_error(&adapters::dbg_read, "dbg_read",
                 debugger_adapter_error_code_t::partial_read,
                 "debugger_partial_read");
    verify_error(&adapters::dbg_write, "dbg_write",
                 debugger_adapter_error_code_t::partial_write,
                 "debugger_partial_write");
}

void verify_aggregate_io_bounds(
    workspace_adapter_t& workspace,
    debugger_lane_t& lane,
    protocol::schema_runtime_t& schemas,
    fake_debugger_state_t& state,
    std::size_t& completed) {
    debugger_handler_limits_t limits;
    limits.max_read_regions = 4U;
    limits.max_read_bytes_per_region = 8U;
    limits.max_read_bytes_total = 16U;
    limits.max_write_regions = 4U;
    limits.max_write_bytes_per_region = 4U;
    limits.max_write_bytes_total = 8U;
    debugger_handlers_t bounded(workspace, lane, schemas, limits);
    const debugger_effect_approval_t approved{true, 42, "harness"};

    json valid_reads = json::array();
    json overflow_reads = json::array();
    for (std::size_t index = 0; index < 3U; ++index) {
        const json region{{"addr", "0x140001000"}, {"size", 8U}};
        overflow_reads.push_back(region);
        if (index < 2U) {
            valid_reads.push_back(region);
        }
    }
    std::size_t before = state.calls.load(std::memory_order_acquire);
    auto result = adapters::dbg_read(
        bounded, routed({{"regions", valid_reads}}),
        cancellation_token_t::create(), approved);
    require_fixture(!result.is_error() &&
                        state.calls.load(std::memory_order_acquire) == before + 1U,
                    "dbg_read", "aggregate_boundary",
                    "exact aggregate read cap was not admitted");
    ++completed;

    before = state.calls.load(std::memory_order_acquire);
    result = adapters::dbg_read(
        bounded, routed({{"regions", overflow_reads}}),
        cancellation_token_t::create(), approved);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID" &&
                        state.calls.load(std::memory_order_acquire) == before &&
                        result.structured_content().at("error").at("details").value(
                            "field", std::string()) == "aggregate_read_bytes",
                    "dbg_read", "aggregate_overflow",
                    "aggregate read overflow reached the backend");
    ++completed;

    json valid_writes = json::array();
    json overflow_writes = json::array();
    for (std::size_t index = 0; index < 3U; ++index) {
        const json region{{"addr", "0x140001000"},
                          {"data", "A0 A1 A2 A3"}};
        overflow_writes.push_back(region);
        if (index < 2U) {
            valid_writes.push_back(region);
        }
    }
    before = state.calls.load(std::memory_order_acquire);
    result = adapters::dbg_write(
        bounded, routed({{"regions", valid_writes}}),
        cancellation_token_t::create(), approved);
    require_fixture(!result.is_error() &&
                        state.calls.load(std::memory_order_acquire) == before + 1U,
                    "dbg_write", "aggregate_boundary",
                    "exact aggregate write cap was not admitted");
    ++completed;

    before = state.calls.load(std::memory_order_acquire);
    result = adapters::dbg_write(
        bounded, routed({{"regions", overflow_writes}}),
        cancellation_token_t::create(), approved);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID" &&
                        state.calls.load(std::memory_order_acquire) == before &&
                        result.structured_content().at("error").at("details").value(
                            "field", std::string()) == "aggregate_write_bytes",
                    "dbg_write", "aggregate_overflow",
                    "aggregate write overflow reached the backend");
    ++completed;

    result = adapters::dbg_write(
        bounded,
        routed({{"regions", json{{"addr", "0x140001000"}, {"data", "A"}}}}),
        cancellation_token_t::create(), approved);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID" &&
                        result.structured_content().at("error").at("details").value(
                            "reason", std::string()) == "incomplete_hex_byte",
                    "dbg_write", "hex_validation",
                    "incomplete write byte was accepted");
    ++completed;
}

void verify_concurrent_serialization(
    const debugger_handlers_t& handlers,
    debugger_lane_t& lane,
    fake_debugger_state_t& state,
    std::size_t& completed) {
    const debugger_effect_approval_t approved{true, 42, "harness"};
    std::atomic_uint32_t ready{0};
    std::atomic_bool start{false};
    std::optional<protocol::mcp_result_t> first;
    std::optional<protocol::mcp_result_t> second;
    state.active_executions.store(0, std::memory_order_release);
    state.peak_executions.store(0, std::memory_order_release);
    state.execution_delay_ms.store(25, std::memory_order_release);
    const std::size_t calls_before = state.calls.load(std::memory_order_acquire);
    const std::uint64_t completed_before = lane.completed_requests();

    const auto worker = [&handlers, &approved, &ready, &start](
        std::optional<protocol::mcp_result_t>& result) {
        ready.fetch_add(1, std::memory_order_acq_rel);
        while (!start.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        result.emplace(adapters::dbg_status(
            handlers, routed(json::object()), cancellation_token_t::create(), approved));
    };
    std::thread first_thread(worker, std::ref(first));
    std::thread second_thread(worker, std::ref(second));
    while (ready.load(std::memory_order_acquire) != 2U) {
        std::this_thread::yield();
    }
    start.store(true, std::memory_order_release);
    first_thread.join();
    second_thread.join();
    state.execution_delay_ms.store(0, std::memory_order_release);

    require_fixture(first && second && !first->is_error() && !second->is_error(),
                    "debugger_lane", "concurrent_results",
                    "concurrent debugger requests did not both complete");
    require_fixture(state.calls.load(std::memory_order_acquire) == calls_before + 2U &&
                        lane.completed_requests() == completed_before + 2U,
                    "debugger_lane", "concurrent_completion",
                    "concurrent request accounting is incomplete");
    require_fixture(state.peak_executions.load(std::memory_order_acquire) == 1U &&
                        lane.peak_concurrency() == 1U,
                    "debugger_lane", "global_serialization",
                    "debugger adapter executions overlapped");
    ++completed;
}

void verify_dbg_exit_detach(const debugger_handlers_t& handlers,
                            fake_debugger_state_t& state,
                            std::size_t& completed) {
    const debugger_effect_approval_t approved{true, 42, "harness"};
    state.attached = true;
    state.detach_after = false;
    auto result = adapters::dbg_exit(handlers, routed(json::object()),
                                      cancellation_token_t::create(), approved);
    require_fixture(!result.is_error() && state.detach_after && !state.attached,
                    "dbg_exit", "detach",
                    "dbg_exit should succeed even when the adapter detaches after execution");
    ++completed;
    state.attached = true;
}

void verify_dbg_write_sole_writer(const debugger_handlers_t& handlers,
                                  std::size_t& completed) {
    for (std::size_t index = 0; index < k_debugger_tool_count; ++index) {
        const auto name = debugger_tool_names()[index];
        const auto& contract = handlers.contract_at(index);
        if (name == "dbg_write") {
            require(contract.effect_policy.effect == protocol::tool_effect_t::debugger_write,
                    "dbg_write must be the sole debugger_write tool");
        } else {
            require(contract.effect_policy.effect != protocol::tool_effect_t::debugger_write,
                    "non-dbg_write tool must not have debugger_write effect");
        }
    }
    ++completed;
}

void verify_debugger_handlers() {
    target_resolver_t resolver;
    effect_lock_manager_t locks;
    require(static_cast<bool>(resolver.publish(
                make_debug_target(1, 5301, 0xC10ULL, "fixture-debug.exe"))),
            "debugger handler target publication failed");

    fake_debugger_state_t state;
    fake_debugger_adapter_t fake_adapter(state);
    debugger_lane_t lane(fake_adapter);

    workspace_adapter_handlers_t workspace_handlers;
    workspace_handlers.debugger = lane.workspace_handler();
    workspace_adapter_t workspace(resolver, locks, std::move(workspace_handlers));
    protocol::schema_runtime_t schemas(64);
    debugger_handlers_t handlers(workspace, lane, schemas);

    verify_contracts(handlers, schemas);

    std::size_t completed = 0;
    for (std::size_t index = 0; index < k_debugger_tool_count; ++index) {
        const auto name = debugger_tool_names()[index];
        verify_fixture(name, k_debugger_adapters[index], handlers, state, completed);
    }

    verify_attach_loss(handlers, state, completed);
    verify_stale_pid(handlers, state, completed);
    verify_adapter_failure_classification(handlers, state, completed);
    verify_aggregate_io_bounds(workspace, lane, schemas, state, completed);
    verify_concurrent_serialization(handlers, lane, state, completed);
    verify_dbg_exit_detach(handlers, state, completed);
    verify_dbg_write_sole_writer(handlers, completed);

    require(completed > k_debugger_tool_count * 4U,
            "debugger handler harness did not execute sufficient fixture families");
}

}

bool run_debugger_handlers_harness(std::string& failure) {
    try {
        verify_debugger_handlers();
    } catch (const std::exception& error) {
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
