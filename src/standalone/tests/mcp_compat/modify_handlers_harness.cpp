#include "modify_handlers_harness.hpp"
#include "../c03/assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/mcp/compat/handlers/modify.hpp"
#include "../../src/core/mcp/compat/workspace_adapter.hpp"
#include "../../src/core/mcp/compat/target_resolver.hpp"
#include "../../src/core/mcp/compat/effect_policy.hpp"
#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"
#include "../../src/core/mcp/protocol/mcp_tool_contract.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
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
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void require_fixture(bool condition, std::string_view tool, std::string_view category,
                     std::string_view detail) {
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, detail, __FILE__, __LINE__);
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

const adapters::modify_adapter_t k_modify_adapters[k_modify_tool_count] = {
    &adapters::add_bookmark,
    &adapters::set_comments,
    &adapters::append_comments,
    &adapters::rename,
    &adapters::define_code,
    &adapters::define_func,
    &adapters::undefine,
    &adapters::make_data,
    &adapters::patch_asm,
    &adapters::force_recompile,
    &adapters::set_op_type,
};

struct backend_state_t final {
    std::size_t calls = 0;
    bool invalid_output = false;
    std::string last_contract;
    std::string last_lane;
    json last_arguments = json::object();
    std::uint32_t last_pid = 0;
    std::optional<std::uint64_t> last_expected_generation;
    bool saw_deadline = false;
    std::shared_ptr<std::atomic_bool> cancel_during_dispatch;
    bool receipt_live_write = false;
    bool receipt_target_file_write = false;
    bool receipt_non_overlapping = true;
    std::uint64_t revision = 1;
    std::uint64_t transaction_id = 0;
    std::size_t live_writes = 0;
    std::size_t target_file_writes = 0;
    bool track_overlay = false;
    std::unordered_map<std::string, json> overlay;
    std::vector<std::unordered_map<std::string, json>> history;

    static std::vector<json> collection(const json& value) {
        if (!value.is_array()) {
            return {value};
        }
        return std::vector<json>(value.begin(), value.end());
    }

    static std::vector<std::string> operation_keys(std::string_view tool,
                                                   const json& arguments) {
        std::vector<std::string> keys;
        if (tool == "add_bookmark") {
            keys.push_back("bookmark:" + arguments.value("addr", std::string()));
            return keys;
        }
        if (tool == "rename") {
            const auto batch = arguments.find("batch");
            if (batch == arguments.end() || !batch->is_object()) {
                return keys;
            }
            for (const char* field : {"func", "data", "local", "stack"}) {
                const auto found = batch->find(field);
                if (found == batch->end()) {
                    continue;
                }
                for (const auto& item : collection(*found)) {
                    const std::string identity = std::string_view(field) == "func"
                        ? item.value("addr", std::string())
                        : item.value("func_addr", std::string()) + ":" +
                              item.value("old", std::string());
                    keys.push_back("rename:" + std::string(field) + ":" + identity);
                }
            }
            return keys;
        }
        const auto items = arguments.find("items");
        if (items == arguments.end() ||
            (tool == "force_recompile" && items->is_array() && items->empty())) {
            keys.push_back(std::string(tool) + ":all");
            return keys;
        }
        for (const auto& item : collection(*items)) {
            std::string key = std::string(tool) + ":" +
                item.value("addr", std::string());
            if (tool == "set_op_type") {
                key += ":" + std::to_string(item.value("op_n", 0));
            }
            keys.push_back(std::move(key));
        }
        return keys;
    }

    bool undo_last_overlay() {
        if (history.empty()) {
            return false;
        }
        overlay = std::move(history.back());
        history.pop_back();
        ++revision;
        return true;
    }

    void reset_overlay() {
        overlay.clear();
        history.clear();
        revision = 1;
        transaction_id = 0;
        receipt_live_write = false;
        receipt_target_file_write = false;
        receipt_non_overlapping = true;
        live_writes = 0;
        target_file_writes = 0;
        track_overlay = true;
    }

    adapter_result_t<adapter_response_t> respond(
        const char* lane_name, const adapter_call_context_t& context,
        const adapter_request_t& request) {
        ++calls;
        last_lane = lane_name;
        last_contract = context.contract == nullptr ? std::string() : std::string(context.contract->name);
        last_pid = context.target ? context.target->target().pid : 0;
        last_expected_generation = request.expected_generation;
        saw_deadline = request.deadline.has_value() &&
            *request.deadline > std::chrono::steady_clock::now();
        last_arguments = json::parse(request.payload, nullptr, false);
        if (cancel_during_dispatch) {
            cancel_during_dispatch->store(true, std::memory_order_release);
        }
        if (invalid_output) {
            return adapter_result_t<adapter_response_t>::success(
                {json::array({"invalid"}).dump(), false});
        }
        if (context.contract == nullptr) {
            return adapter_result_t<adapter_response_t>::failure(
                {adapter_error_code_t::backend_rejected, "fixture_contract_missing", 0, 0});
        }
        const json schema = json::parse(
            context.contract->output_schema_json.begin(),
            context.contract->output_schema_json.end());
        json output = schema_instance(schema);
        const auto keys = operation_keys(context.contract->name, last_arguments);
        std::unordered_set<std::string> unique_keys;
        for (const auto& key : keys) {
            if (!unique_keys.emplace(key).second) {
                return adapter_result_t<adapter_response_t>::failure(
                    {adapter_error_code_t::backend_rejected,
                     "fixture_overlay_overlap", keys.size(), unique_keys.size()});
            }
        }
        const bool dry_run = context.contract->name == "rename" &&
            last_arguments.contains("batch") && last_arguments["batch"].is_object() &&
            last_arguments["batch"].value("dry_run", false);
        const std::uint64_t revision_before = revision;
        if (!dry_run) {
            if (track_overlay) {
                history.push_back(overlay);
                for (const auto& key : keys) {
                    overlay[key] = json{{"tool", last_contract}};
                }
            }
            ++revision;
        }
        ++transaction_id;
        output["_aida_overlay"] = {
            {"tool", std::string(context.contract->name)},
            {"mode", "reversible_overlay"},
            {"committed", !dry_run},
            {"transaction_id", transaction_id},
            {"revision_before", revision_before},
            {"revision_after", revision},
            {"operations", keys.size()},
            {"live_write", receipt_live_write},
            {"target_file_write", receipt_target_file_write},
            {"ui_switched", false},
            {"non_overlapping", receipt_non_overlapping},
        };
        return adapter_result_t<adapter_response_t>::success({output.dump(), false});
    }
};

target_record_t make_target(std::uint64_t target_id, std::uint32_t pid,
                            std::uint64_t creation_identity, std::string name) {
    target_record_t target;
    target.target_id = target_id;
    target.pid = pid;
    target.process_creation_identity = creation_identity;
    target.bin_name = std::move(name);
    target.generation = 9;
    target.attach_generation = 0x109ULL;
    target.revision = 1;
    return target;
}

json routed(json arguments) {
    arguments["pid"] = 4101;
    return arguments;
}

std::string fixture_addr(std::size_t index) {
    return std::to_string(0x140001000ULL + static_cast<std::uint64_t>(index) * 0x10ULL);
}

json make_valid_args(std::string_view tool) {
    if (tool == "add_bookmark") {
        return routed({{"addr", "0x140001000"}, {"name", "entry"}});
    }
    if (tool == "set_comments") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"comment", "test comment"}}}});
    }
    if (tool == "append_comments") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"comment", "appended"}}}});
    }
    if (tool == "rename") {
        return routed({{"batch", json{{"func", json{{"addr", "0x140001000"}, {"name", "my_func"}}}}}});
    }
    if (tool == "define_code") {
        return routed({{"items", json{{"addr", "0x140001000"}}}});
    }
    if (tool == "define_func") {
        return routed({{"items", json{{"addr", "0x140001000"}}}});
    }
    if (tool == "undefine") {
        return routed({{"items", json{{"addr", "0x140001000"}}}});
    }
    if (tool == "make_data") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"type", "int"}, {"name", "g_var"}}}});
    }
    if (tool == "patch_asm") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"asm", "nop"}}}});
    }
    if (tool == "force_recompile") {
        return routed({{"items", json{{"addr", "0x140001000"}}}});
    }
    if (tool == "set_op_type") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"kind", "offset"}, {"op_n", 0}}}});
    }
    return routed(json::object());
}

json make_boundary_args(std::string_view tool, const modify_handler_limits_t& limits) {
    if (tool == "add_bookmark") {
        return routed({
            {"addr", std::string(limits.max_address_bytes, 'a')},
            {"name", std::string(limits.max_name_bytes, 'n')},
            {"prefix", std::string(limits.max_comment_bytes, 'p')},
        });
    }
    if (tool == "set_comments" || tool == "append_comments") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", fixture_addr(i)}, {"comment", "c"}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "define_code" || tool == "define_func") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", fixture_addr(i)}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "undefine") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", fixture_addr(i)}, {"size", limits.max_data_bytes}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "make_data") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", fixture_addr(i)}, {"type", "int"}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "patch_asm") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", fixture_addr(i)}, {"asm", "nop"}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "force_recompile") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", fixture_addr(i)}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "set_op_type") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", fixture_addr(i)}, {"kind", "offset"}, {"op_n", 0}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "rename") {
        json funcs = json::array();
        for (std::size_t i = 0; i < limits.max_rename_batch_items; ++i) {
            funcs.push_back({{"addr", fixture_addr(i)}, {"name", "n" + std::to_string(i)}});
        }
        return routed({{"batch", json{{"func", std::move(funcs)}}}});
    }
    return routed(json::object());
}

json make_invalid_args(std::string_view tool, const modify_handler_limits_t& limits) {
    if (tool == "add_bookmark") {
        return routed({
            {"addr", "0x140001000"},
            {"name", std::string(limits.max_name_bytes + 1U, 'n')},
        });
    }
    if (tool == "set_comments" || tool == "append_comments") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items + 1; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"comment", "x"}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "define_code" || tool == "define_func") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items + 1; ++i) {
            items.push_back({{"addr", "0x140001000"}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "undefine") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"size", limits.max_data_bytes + 1}}}});
    }
    if (tool == "make_data") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"type", std::string(limits.max_type_bytes + 1, 't')}}}});
    }
    if (tool == "patch_asm") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"asm", std::string(limits.max_asm_bytes + 1, 'n')}}}});
    }
    if (tool == "set_op_type") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items + 1; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"kind", "offset"}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "rename") {
        json funcs = json::array();
        for (std::size_t i = 0; i < limits.max_rename_batch_items + 1U; ++i) {
            funcs.push_back({{"addr", fixture_addr(i)}, {"name", "renamed"}});
        }
        return routed({{"batch", json{{"func", std::move(funcs)}}}});
    }
    if (tool == "force_recompile") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items + 1U; ++i) {
            items.push_back({{"addr", "0x140001000"}});
        }
        return routed({{"items", std::move(items)}});
    }
    return routed(json::object());
}

void verify_contracts(const modify_handlers_t& handlers,
                      protocol::schema_runtime_t& schemas) {
    require(handlers.size() == k_modify_tool_count,
            "modify handler contract count is not exactly eleven");
    require(modify_tool_names().size() == k_modify_tool_count,
            "modify name ledger count is not exactly eleven");
    std::unordered_set<std::string> unique_names;
    for (std::size_t index = 0; index < k_modify_tool_count; ++index) {
        const auto name = modify_tool_names()[index];
        const auto* descriptor = aida::standalone::mcp::compat::find_contract(name);
        const auto& contract = handlers.contract_at(index);
        require(descriptor != nullptr, "modify generated descriptor is missing");
        require(contract.name == name && handlers.find(name) == &contract,
                "modify handler lookup differs from the exact name ledger");
        require(unique_names.emplace(contract.name).second,
                "modify handler name ledger contains a duplicate");
        require(descriptor->adapter_symbol ==
                    "aida::standalone::mcp::compat::adapters::" + std::string(name),
                "modify generated adapter symbol differs from the linked function name");
        require(contract.description == descriptor->description,
                "modify generated description was not preserved");
        require(contract.input_schema == json::parse(
                    descriptor->input_schema_json.begin(), descriptor->input_schema_json.end()) &&
                    contract.output_schema == json::parse(
                    descriptor->output_schema_json.begin(), descriptor->output_schema_json.end()) &&
                    contract.annotations == json::parse(
                    descriptor->annotations_json.begin(), descriptor->annotations_json.end()),
                "modify generated schema or annotations were not preserved");
        require(contract.target_policy.requirement == protocol::target_requirement_t::optional &&
                    contract.target_policy.accepts_pid &&
                    contract.target_policy.accepts_bin_name,
                "modify target routing policy is not the generated optional selector policy");
        require(contract.effect_policy.effect == protocol::tool_effect_t::workspace_overlay_mutation &&
                    contract.effect_policy.lock == protocol::effect_lock_t::workspace_overlay_transaction &&
                    !contract.effect_policy.read_only && !contract.effect_policy.unsafe,
                "modify effect policy is not generated overlay mutation transaction");
        require(protocol::validate_tool_contract(contract, schemas).valid,
                "modify generated contract does not validate through the schema runtime");
        const json list_entry = contract.tool_list_entry();
        require(list_entry.at("inputSchema") == contract.input_schema &&
                    list_entry.at("outputSchema") == contract.output_schema &&
                    !list_entry.contains("_meta"),
                "modify tool list entry altered schema or embedded provenance");
    }
}

void verify_fixture(std::string_view tool_name,
                    adapters::modify_adapter_t adapter,
                    const modify_handlers_t& handlers,
                    backend_state_t& backend,
                    std::size_t& completed) {
    const json metadata{{"fixture_tool", std::string(tool_name)}};
    modify_invocation_options_t options;
    options.expected_generation = 9;
    const auto invoke = [&](const json& args, const cancellation_token_t& token) {
        return adapter(handlers, args, token, options, metadata);
    };

    json valid = make_valid_args(tool_name);
    std::size_t before = backend.calls;
    auto result = invoke(valid, cancellation_token_t::create());
    require_fixture(!result.is_error(), tool_name, "valid", result.text());
    require_fixture(backend.calls == before + 1, tool_name, "valid",
                    "backend was not invoked exactly once");
    require_fixture(backend.last_contract == tool_name, tool_name, "valid",
                    "request reached the wrong tool in backend");
    require_fixture(backend.last_lane == "overlay", tool_name, "valid",
                    "modify request escaped the reversible overlay lane");
    require_fixture(backend.last_pid == 4101 && backend.saw_deadline &&
                        backend.last_expected_generation == options.expected_generation,
                    tool_name, "valid",
                    "target binding, generation, or deadline was not propagated");
    json expected_args = valid;
    expected_args.erase("pid");
    expected_args.erase("bin_name");
    require_fixture(backend.last_arguments == expected_args, tool_name, "valid",
                    "routing selectors leaked into backend arguments");
    require_fixture(result.structured_content().is_object() &&
                        !result.structured_content().contains("_meta"),
                    tool_name, "valid", "structured output or metadata separation changed");
    require_fixture(result.aida_metadata().value("tool", std::string()) == tool_name,
                    tool_name, "valid", "provenance metadata is incomplete");
    const auto receipt = result.aida_metadata().find("overlay_receipt");
    require_fixture(receipt != result.aida_metadata().end() && receipt->is_object() &&
                        receipt->value("mode", std::string()) == "reversible_overlay" &&
                        receipt->value("non_overlapping", false) &&
                        !receipt->value("live_write", true) &&
                        !receipt->value("target_file_write", true),
                    tool_name, "valid",
                    "verified reversible-overlay receipt is absent");
    ++completed;

    json boundary = make_boundary_args(tool_name, handlers.limits());
    if (boundary.size() > 1 || (boundary.is_object() && boundary.contains("pid"))) {
        before = backend.calls;
        result = invoke(boundary, cancellation_token_t::create());
        require_fixture(!result.is_error(), tool_name, "boundary", result.text());
        require_fixture(backend.calls == before + 1, tool_name, "boundary",
                        "pinned maximum was not admitted by the backend lane");
        ++completed;
    }

    json invalid = make_invalid_args(tool_name, handlers.limits());
    before = backend.calls;
    result = invoke(invalid, cancellation_token_t::create());
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    tool_name, "invalid", "out-of-policy input was not rejected canonically");
    require_fixture(backend.calls == before, tool_name, "invalid",
                    "invalid input reached the backend");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "policy", std::string()) == "bounded_modify_adapter",
        tool_name, "invalid", "bounded policy diagnostics are absent");
    ++completed;

    json ambiguous = valid;
    ambiguous.erase("pid");
    ambiguous["bin_name"] = "fixture";
    before = backend.calls;
    result = invoke(ambiguous, cancellation_token_t::create());
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED",
                    tool_name, "ambiguous_target",
                    "ambiguous binary selector was not rejected canonically");
    require_fixture(backend.calls == before, tool_name, "ambiguous_target",
                    "ambiguous target reached the backend");
    ++completed;

    auto cancellation = cancellation_token_t::create();
    backend.cancel_during_dispatch = cancellation.state();
    before = backend.calls;
    result = invoke(valid, cancellation);
    backend.cancel_during_dispatch.reset();
    require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                    tool_name, "cancellation",
                    "in-flight cancellation was not observed canonically");
    require_fixture(backend.calls == before + 1U, tool_name, "cancellation",
                    "cancellation did not exercise the backend window");
    ++completed;

    backend.invalid_output = true;
    before = backend.calls;
    result = invoke(valid, cancellation_token_t::create());
    backend.invalid_output = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    tool_name, "output_validation",
                    "schema-invalid structured output was not rejected canonically");
    require_fixture(backend.calls == before + 1U, tool_name, "output_validation",
                    "invalid-output fixture did not reach the backend");
    ++completed;
}

void verify_generated_union_inputs(modify_handlers_t& handlers,
                                   backend_state_t& backend,
                                   std::size_t& completed) {
    const json metadata{{"fixture_tool", "generated_union_inputs"}};
    modify_invocation_options_t options;
    options.expected_generation = 9;

    for (const json& arguments : {
             routed(json::object()),
             routed({{"items", json::array()}}),
             routed({{"items", json{{"addr", "0x140001000"}}}})}) {
        const std::size_t before = backend.calls;
        auto result = adapters::force_recompile(
            handlers, arguments, cancellation_token_t::create(), options, metadata);
        require_fixture(!result.is_error(), "force_recompile", "optional_inputs",
                        result.text());
        require_fixture(backend.calls == before + 1,
                        "force_recompile", "optional_inputs",
                        "optional or singleton input did not reach the backend");
        ++completed;
    }

    const std::array<json, 3> rename_batches{{
        json{{"data", json{{"old", "g_old"}, {"new", "g_new"}}}},
        json{{"local", json{{"func_addr", "0x140001000"},
                              {"old", "v1"}, {"new", "counter"}}}},
        json{{"stack", json{{"func_addr", "0x140001000"},
                              {"old", "var_20"}, {"new", "buffer"}}}},
    }};
    for (const auto& batch : rename_batches) {
        const std::size_t before = backend.calls;
        auto result = adapters::rename(
            handlers, routed({{"batch", batch}}), cancellation_token_t::create(),
            options, metadata);
        require_fixture(!result.is_error(), "rename", "singleton_union", result.text());
        require_fixture(backend.calls == before + 1, "rename", "singleton_union",
                        "schema-valid singleton rename did not reach the backend");
        ++completed;
    }
}

void verify_expected_generation(modify_handlers_t& handlers,
                                backend_state_t& backend,
                                std::size_t& completed) {
    const json arguments = routed({{"addr", "0x140002000"}, {"name", "generation"}});
    const json metadata{{"fixture_tool", "add_bookmark"}};
    modify_invocation_options_t matching;
    matching.expected_generation = 9;
    std::size_t before = backend.calls;
    auto result = adapters::add_bookmark(
        handlers, arguments, cancellation_token_t::create(), matching, metadata);
    require_fixture(!result.is_error(), "add_bookmark", "matching_generation",
                    result.text());
    require_fixture(backend.calls == before + 1 &&
                        backend.last_expected_generation == matching.expected_generation,
                    "add_bookmark", "matching_generation",
                    "matching expected_generation was not forwarded");
    ++completed;

    modify_invocation_options_t stale;
    stale.expected_generation = 8;
    before = backend.calls;
    result = adapters::add_bookmark(
        handlers, arguments, cancellation_token_t::create(), stale, metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED",
                    "add_bookmark", "stale_generation",
                    "stale expected_generation was not rejected by handler routing");
    require_fixture(backend.calls == before,
                    "add_bookmark", "stale_generation",
                    "stale generation reached the overlay backend");
    const auto& details = result.structured_content().at("error").at("details");
    require_fixture(details.value("expected", 0ULL) == 8ULL &&
                        details.value("actual", 0ULL) == 9ULL,
                    "add_bookmark", "stale_generation",
                    "stale generation diagnostics lost expected/actual values");
    ++completed;
}

void verify_reversible_overlay(modify_handlers_t& handlers,
                               backend_state_t& backend,
                               std::size_t& completed) {
    backend.reset_overlay();
    modify_invocation_options_t options;
    options.expected_generation = 9;
    const json metadata{{"fixture_tool", "reversible_overlay"}};

    auto result = adapters::add_bookmark(
        handlers,
        routed({{"addr", "0x140003000"}, {"name", "undo_me"}}),
        cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error(), "add_bookmark", "overlay_apply", result.text());
    require_fixture(backend.overlay.size() == 1 && backend.history.size() == 1,
                    "add_bookmark", "overlay_apply",
                    "overlay mutation was not journaled reversibly");
    require_fixture(!result.structured_content().contains("_aida_overlay") &&
                        !result.structured_content().contains("_meta"),
                    "add_bookmark", "overlay_apply",
                    "backend receipt leaked into generated structured output");
    ++completed;

    require_fixture(backend.undo_last_overlay(), "add_bookmark", "overlay_undo",
                    "overlay undo was unavailable");
    require_fixture(backend.overlay.empty() && backend.history.empty(),
                    "add_bookmark", "overlay_undo",
                    "overlay undo did not restore the prior state");
    ++completed;

    const json non_overlapping = routed({{"items", json::array({
        json{{"addr", "0x140004000"}, {"asm", "nop"}},
        json{{"addr", "0x140004010"}, {"asm", "ret"}},
    })}});
    result = adapters::patch_asm(
        handlers, non_overlapping, cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error(), "patch_asm", "non_overlap", result.text());
    require_fixture(backend.overlay.size() == 2,
                    "patch_asm", "non_overlap",
                    "non-overlapping overlay operations were not committed together");
    require_fixture(backend.live_writes == 0 && backend.target_file_writes == 0,
                    "patch_asm", "write_isolation",
                    "overlay fixture performed a live or target-file write");
    ++completed;

    require_fixture(backend.undo_last_overlay(), "patch_asm", "batch_undo",
                    "batch overlay undo was unavailable");
    require_fixture(backend.overlay.empty(), "patch_asm", "batch_undo",
                    "batch undo did not restore the empty overlay");
    ++completed;

    const json overlapping = routed({{"items", json::array({
        json{{"addr", "0x140005000"}, {"asm", "nop"}},
        json{{"addr", "0x140005000"}, {"asm", "ret"}},
    })}});
    const std::size_t before = backend.calls;
    result = adapters::patch_asm(
        handlers, overlapping, cancellation_token_t::create(), options, metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_HANDLER_FAILED",
                    "patch_asm", "overlap_rejection",
                    "overlapping overlay operations were not rejected");
    require_fixture(backend.calls == before + 1 && backend.overlay.empty(),
                    "patch_asm", "overlap_rejection",
                    "overlap rejection changed overlay state");
    ++completed;

    const json dry_run = routed({{"batch", json{
        {"dry_run", true},
        {"func", json{{"addr", "0x140006000"}, {"name", "dry_name"}}},
    }}});
    backend.receipt_live_write = true;
    result = adapters::rename(
        handlers, dry_run, cancellation_token_t::create(), options, metadata);
    backend.receipt_live_write = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    "rename", "receipt_live_write",
                    "live-write receipt was not rejected fail-closed");
    require_fixture(backend.overlay.empty(), "rename", "receipt_live_write",
                    "dry-run receipt rejection changed overlay state");
    ++completed;

    backend.receipt_target_file_write = true;
    result = adapters::rename(
        handlers, dry_run, cancellation_token_t::create(), options, metadata);
    backend.receipt_target_file_write = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    "rename", "receipt_file_write",
                    "target-file-write receipt was not rejected fail-closed");
    require_fixture(backend.overlay.empty(), "rename", "receipt_file_write",
                    "file-write receipt rejection changed overlay state");
    ++completed;
}

void verify_modify_handlers() {
    target_resolver_t resolver;
    effect_lock_manager_t locks;
    require(static_cast<bool>(resolver.publish(
                make_target(1, 4101, 0xA101ULL, "fixture-alpha.exe"))),
            "first modify handler target publication failed");
    require(static_cast<bool>(resolver.publish(
                make_target(2, 4102, 0xA102ULL, "fixture-beta.exe"))),
            "second modify handler target publication failed");

    backend_state_t backend;
    workspace_adapter_handlers_t workspace_handlers;
    workspace_handlers.overlay = [&backend](const adapter_call_context_t& context,
                                            const adapter_request_t& request) {
        return backend.respond("overlay", context, request);
    };
    workspace_adapter_t workspace(resolver, locks, std::move(workspace_handlers));
    protocol::schema_runtime_t schemas(64);
    modify_handlers_t handlers(workspace, schemas);

    verify_contracts(handlers, schemas);

    std::size_t completed = 0;
    for (std::size_t index = 0; index < k_modify_tool_count; ++index) {
        const auto name = modify_tool_names()[index];
        require(k_modify_adapters[index] != nullptr,
                "modify adapter function is not linked");
        verify_fixture(name, k_modify_adapters[index], handlers, backend, completed);
    }

    require(completed == k_modify_tool_count * 6U,
            "modify standard fixture count differs from the exact inventory");

    verify_generated_union_inputs(handlers, backend, completed);
    verify_expected_generation(handlers, backend, completed);
    verify_reversible_overlay(handlers, backend, completed);

    require(completed == 81U,
            "modify C13 fixture count differs from the exact verified inventory");
}

}

bool run_modify_handlers_harness(std::string& failure) {
    try {
        verify_modify_handlers();
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
