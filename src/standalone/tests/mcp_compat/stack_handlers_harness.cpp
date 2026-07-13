#include "stack_handlers_harness.hpp"

#include "../../src/core/mcp/compat/handlers/stack.hpp"
#include "../../src/core/mcp/compat/workspace_adapter.hpp"
#include "../../src/core/mcp/compat/target_resolver.hpp"
#include "../../src/core/mcp/compat/effect_policy.hpp"
#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"
#include "../../src/core/mcp/protocol/mcp_tool_contract.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
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

struct stack_var_t final {
    std::string name;
    std::string offset;
    std::string size;
    std::string type;
    std::string source;
    double confidence = 1.0;
};

struct frame_entry_t final {
    std::vector<stack_var_t> vars;
};

struct overlay_record_t final {
    std::string addr;
    std::string name;
    std::string offset;
    std::string type;
    enum class kind_t : std::uint8_t { declare, remove } kind;
};

class stack_frame_store_t final {
public:
    json query_frame(const json& args) {
        json results = json::array();
        std::vector<std::string> addrs;
        if (args.contains("addrs")) {
            const auto& a = args["addrs"];
            if (a.is_string()) {
                addrs.push_back(a.get<std::string>());
            } else if (a.is_array()) {
                for (const auto& item : a) {
                    if (item.is_string()) {
                        addrs.push_back(item.get<std::string>());
                    }
                }
            }
        }
        for (const auto& addr : addrs) {
            const auto it = frames_.find(addr);
            if (it == frames_.end() || it->second.vars.empty()) {
                results.push_back({{"addr", addr}, {"vars", nullptr}});
            } else {
                json vars_array = json::array();
                for (const auto& var : it->second.vars) {
                    vars_array.push_back({
                        {"name", var.name},
                        {"offset", var.offset},
                        {"size", var.size},
                        {"type", var.type},
                    });
                }
                results.push_back({{"addr", addr}, {"vars", std::move(vars_array)}});
            }
        }
        return {{"result", std::move(results)}};
    }

    json declare_vars(const json& args) {
        json results = json::array();
        std::vector<json> items;
        if (args.contains("items")) {
            const auto& it = args["items"];
            if (it.is_object()) {
                items.push_back(it);
            } else if (it.is_array()) {
                for (const auto& item : it) {
                    items.push_back(item);
                }
            }
        }
        for (const auto& item : items) {
            const std::string addr = item.value("addr", "");
            const std::string name = item.value("name", "");
            const std::string offset = item.value("offset", "");
            const std::string ty = item.value("ty", "");
            auto& frame = frames_[addr];
            bool conflict = false;
            std::string error_reason;
            for (const auto& existing : frame.vars) {
                if (existing.offset == offset && existing.name != name) {
                    conflict = true;
                    error_reason = "offset_overlap_conflict";
                    break;
                }
                if (existing.name == name && existing.type != ty) {
                    conflict = true;
                    error_reason = "type_conflict";
                    break;
                }
            }
            if (conflict) {
                results.push_back({{"addr", addr}, {"name", name}, {"error", error_reason}});
            } else {
                bool updated = false;
                for (auto& existing : frame.vars) {
                    if (existing.name == name) {
                        existing.offset = offset;
                        existing.type = ty;
                        existing.size = estimate_size(ty);
                        existing.source = "declare_stack";
                        existing.confidence = 1.0;
                        updated = true;
                        break;
                    }
                }
                if (!updated) {
                    frame.vars.push_back({
                        name, offset, estimate_size(ty), ty, "declare_stack", 1.0,
                    });
                }
                overlay_log_.push_back({addr, name, offset, ty, overlay_record_t::kind_t::declare});
                ++generation_;
                results.push_back({{"addr", addr}, {"name", name}});
            }
        }
        return {{"result", std::move(results)}};
    }

    json delete_vars(const json& args) {
        json results = json::array();
        std::vector<json> items;
        if (args.contains("items")) {
            const auto& it = args["items"];
            if (it.is_object()) {
                items.push_back(it);
            } else if (it.is_array()) {
                for (const auto& item : it) {
                    items.push_back(item);
                }
            }
        }
        for (const auto& item : items) {
            const std::string addr = item.value("addr", "");
            const std::string name = item.value("name", "");
            auto frame_it = frames_.find(addr);
            if (frame_it == frames_.end()) {
                results.push_back({{"addr", addr}, {"name", name}, {"error", "frame_not_found"}});
                continue;
            }
            auto& vars = frame_it->second.vars;
            auto var_it = std::find_if(vars.begin(), vars.end(),
                [&](const stack_var_t& v) { return v.name == name; });
            if (var_it == vars.end()) {
                results.push_back({{"addr", addr}, {"name", name}, {"error", "variable_not_found"}});
            } else {
                overlay_log_.push_back({addr, name, var_it->offset, var_it->type,
                                        overlay_record_t::kind_t::remove});
                vars.erase(var_it);
                ++generation_;
                results.push_back({{"addr", addr}, {"name", name}});
            }
        }
        return {{"result", std::move(results)}};
    }

    void undo_last_overlay() {
        if (overlay_log_.empty()) {
            return;
        }
        auto record = std::move(overlay_log_.back());
        overlay_log_.pop_back();
        auto& frame = frames_[record.addr];
        if (record.kind == overlay_record_t::kind_t::declare) {
            auto it = std::find_if(frame.vars.begin(), frame.vars.end(),
                [&](const stack_var_t& v) { return v.name == record.name; });
            if (it != frame.vars.end()) {
                frame.vars.erase(it);
            }
        } else {
            frame.vars.push_back({
                record.name, record.offset, estimate_size(record.type),
                record.type, "undo", 1.0,
            });
        }
        ++generation_;
    }

    bool has_frame(const std::string& addr) const {
        const auto it = frames_.find(addr);
        return it != frames_.end() && !it->second.vars.empty();
    }

    const frame_entry_t* get_frame(const std::string& addr) const {
        const auto it = frames_.find(addr);
        return it == frames_.end() ? nullptr : &it->second;
    }

    std::size_t overlay_count() const noexcept { return overlay_log_.size(); }
    std::uint64_t generation() const noexcept { return generation_; }

    void seed_frame(const std::string& addr, std::vector<stack_var_t> vars) {
        frames_[addr].vars = std::move(vars);
    }

    void clear() {
        frames_.clear();
        overlay_log_.clear();
        generation_ = 1;
    }

private:
    static std::string estimate_size(std::string_view type_name) {
        if (type_name == "int" || type_name == "unsigned int" || type_name == "uint32_t") {
            return "4";
        }
        if (type_name == "long" || type_name == "unsigned long" || type_name == "uint64_t" ||
            type_name == "long long" || type_name == "unsigned long long") {
            return "8";
        }
        if (type_name == "short" || type_name == "unsigned short" || type_name == "uint16_t") {
            return "2";
        }
        if (type_name == "char" || type_name == "unsigned char" || type_name == "uint8_t" ||
            type_name == "bool") {
            return "1";
        }
        if (type_name == "void*") {
            return "8";
        }
        return "8";
    }

    std::unordered_map<std::string, frame_entry_t> frames_;
    std::vector<overlay_record_t> overlay_log_;
    std::uint64_t generation_ = 1;
};

const adapters::stack_adapter_t k_stack_adapters[k_stack_tool_count] = {
    &adapters::stack_frame,
    &adapters::declare_stack,
    &adapters::delete_stack,
};

struct backend_state_t final {
    std::size_t query_calls = 0;
    std::size_t overlay_calls = 0;
    bool invalid_output = false;
    bool simulate = false;
    std::string last_contract;
    std::string last_lane;
    json last_arguments = json::object();
    std::uint32_t last_pid = 0;
    bool saw_deadline = false;
    std::shared_ptr<std::atomic_bool> cancel_during_dispatch;
    stack_frame_store_t store;

    adapter_result_t<adapter_response_t> respond(
        const char* lane_name, const adapter_call_context_t& context,
        const adapter_request_t& request) {
        if (std::string(lane_name) == "query") {
            ++query_calls;
        } else {
            ++overlay_calls;
        }
        last_lane = lane_name;
        last_contract = context.contract == nullptr ? std::string() : std::string(context.contract->name);
        last_pid = context.target ? context.target->target().pid : 0;
        saw_deadline = request.deadline.has_value() &&
            *request.deadline > std::chrono::steady_clock::now();
        last_arguments = json::parse(request.payload, nullptr, false);
        if (cancel_during_dispatch) {
            cancel_during_dispatch->store(true, std::memory_order_release);
        }
        json output;
        if (invalid_output) {
            output = json{{"__schema_violation", true}};
        } else if (simulate && context.contract != nullptr) {
            const auto name = context.contract->name;
            if (name == "stack_frame") {
                output = store.query_frame(last_arguments);
            } else if (name == "declare_stack") {
                output = store.declare_vars(last_arguments);
            } else if (name == "delete_stack") {
                output = store.delete_vars(last_arguments);
            } else {
                return adapter_result_t<adapter_response_t>::failure(
                    {adapter_error_code_t::backend_rejected, "fixture_contract_unknown", 0, 0});
            }
        } else {
            if (context.contract == nullptr) {
                return adapter_result_t<adapter_response_t>::failure(
                    {adapter_error_code_t::backend_rejected, "fixture_contract_missing", 0, 0});
            }
            const json schema = json::parse(
                context.contract->output_schema_json.begin(),
                context.contract->output_schema_json.end());
            output = schema_instance(schema);
        }
        return adapter_result_t<adapter_response_t>::success({output.dump(), false});
    }
};

target_record_t make_target(std::uint64_t target_id, std::uint32_t pid,
                            std::uint64_t creation_identity, std::string name,
                            std::uint64_t generation = 9) {
    target_record_t target;
    target.target_id = target_id;
    target.pid = pid;
    target.process_creation_identity = creation_identity;
    target.bin_name = std::move(name);
    target.generation = generation;
    target.attach_generation = 0x109ULL;
    target.revision = 1;
    return target;
}

json routed(json arguments) {
    arguments["pid"] = 4101;
    return arguments;
}

json make_valid_args(std::string_view tool) {
    if (tool == "stack_frame") {
        return routed({{"addrs", "0x140001000"}});
    }
    if (tool == "declare_stack") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"offset", "-0x20"}, {"name", "var_20"}, {"ty", "int"}}}});
    }
    if (tool == "delete_stack") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"name", "var_20"}}}});
    }
    return routed(json::object());
}

json make_boundary_args(std::string_view tool, const stack_handler_limits_t& limits) {
    if (tool == "stack_frame") {
        json addrs = json::array();
        for (std::size_t i = 0; i < limits.max_addrs; ++i) {
            addrs.push_back("0x140001000");
        }
        return routed({{"addrs", std::move(addrs)}});
    }
    if (tool == "declare_stack") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"offset", "-0x10"}, {"name", "v" + std::to_string(i)}, {"ty", "int"}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "delete_stack") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"name", "v" + std::to_string(i)}});
        }
        return routed({{"items", std::move(items)}});
    }
    return routed(json::object());
}

json make_invalid_args(std::string_view tool, const stack_handler_limits_t& limits) {
    if (tool == "stack_frame") {
        json addrs = json::array();
        for (std::size_t i = 0; i < limits.max_addrs + 1; ++i) {
            addrs.push_back("0x140001000");
        }
        return routed({{"addrs", std::move(addrs)}});
    }
    if (tool == "declare_stack") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items + 1; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"offset", "-0x10"}, {"name", "v"}, {"ty", "int"}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "delete_stack") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items + 1; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"name", "v"}});
        }
        return routed({{"items", std::move(items)}});
    }
    return routed(json::object());
}

void verify_contracts(const stack_handlers_t& handlers,
                      protocol::schema_runtime_t& schemas) {
    require(handlers.size() == k_stack_tool_count,
            "stack handler contract count is not exactly three");
    require(stack_tool_names().size() == k_stack_tool_count,
            "stack name ledger count is not exactly three");
    std::unordered_set<std::string> unique_names;
    for (std::size_t index = 0; index < k_stack_tool_count; ++index) {
        const auto name = stack_tool_names()[index];
        const auto* descriptor = aida::standalone::mcp::compat::find_contract(name);
        const auto& contract = handlers.contract_at(index);
        require(descriptor != nullptr, "stack generated descriptor is missing");
        require(contract.name == name && handlers.find(name) == &contract,
                "stack handler lookup differs from the exact name ledger");
        require(unique_names.emplace(contract.name).second,
                "stack handler name ledger contains a duplicate");
        require(descriptor->adapter_symbol ==
                    "aida::standalone::mcp::compat::adapters::" + std::string(name),
                "stack generated adapter symbol differs from the linked function name");
        require(contract.description == descriptor->description,
                "stack generated description was not preserved");
        require(contract.input_schema == json::parse(
                    descriptor->input_schema_json.begin(), descriptor->input_schema_json.end()) &&
                    contract.output_schema == json::parse(
                    descriptor->output_schema_json.begin(), descriptor->output_schema_json.end()) &&
                    contract.annotations == json::parse(
                    descriptor->annotations_json.begin(), descriptor->annotations_json.end()),
                "stack generated schema or annotations were not preserved");
        require(contract.target_policy.requirement == protocol::target_requirement_t::optional &&
                    contract.target_policy.accepts_pid &&
                    contract.target_policy.accepts_bin_name,
                "stack target routing policy is not the generated optional selector policy");
        if (name == "stack_frame") {
            require(contract.effect_policy.effect == protocol::tool_effect_t::workspace_read &&
                        contract.effect_policy.lock == protocol::effect_lock_t::workspace_shared &&
                        contract.effect_policy.read_only && !contract.effect_policy.unsafe,
                        "stack_frame effect policy is not generated workspace read shared");
        } else {
            require(contract.effect_policy.effect == protocol::tool_effect_t::workspace_overlay_mutation &&
                        contract.effect_policy.lock == protocol::effect_lock_t::workspace_overlay_transaction &&
                        !contract.effect_policy.read_only && !contract.effect_policy.unsafe,
                        "stack mutation effect policy is not generated overlay mutation transaction");
        }
        require(protocol::validate_tool_contract(contract, schemas).valid,
                "stack generated contract does not validate through the schema runtime");
        const json list_entry = contract.tool_list_entry();
        require(list_entry.at("inputSchema") == contract.input_schema &&
                    list_entry.at("outputSchema") == contract.output_schema &&
                    !list_entry.contains("_meta"),
                "stack tool list entry altered schema or embedded provenance");
    }
}

std::size_t total_backend_calls(const backend_state_t& backend) {
    return backend.query_calls + backend.overlay_calls;
}

void verify_fixture(std::string_view tool_name,
                    adapters::stack_adapter_t adapter,
                    const stack_handlers_t& handlers,
                    backend_state_t& backend,
                    std::size_t& completed) {
    const json metadata{{"fixture_tool", std::string(tool_name)}};

    json valid = make_valid_args(tool_name);
    std::size_t before = total_backend_calls(backend);
    auto result = adapter(handlers, valid, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), tool_name, "valid", result.text());
    require_fixture(total_backend_calls(backend) == before + 1, tool_name, "valid",
                    "backend was not invoked exactly once");
    require_fixture(backend.last_contract == tool_name, tool_name, "valid",
                    "request reached the wrong tool in backend");
    require_fixture(backend.last_pid == 4101 && backend.saw_deadline, tool_name, "valid",
                    "target binding or deadline was not propagated");
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
    ++completed;

    json boundary = make_boundary_args(tool_name, handlers.limits());
    if (boundary.size() > 1 || (boundary.is_object() && boundary.contains("pid"))) {
        before = total_backend_calls(backend);
        result = adapter(handlers, boundary, cancellation_token_t::create(), metadata);
        require_fixture(!result.is_error(), tool_name, "boundary", result.text());
        require_fixture(total_backend_calls(backend) == before + 1, tool_name, "boundary",
                        "pinned maximum was not admitted by the backend lane");
        ++completed;
    }

    json invalid = make_invalid_args(tool_name, handlers.limits());
    before = total_backend_calls(backend);
    result = adapter(handlers, invalid, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    tool_name, "invalid", "out-of-policy input was not rejected canonically");
    require_fixture(total_backend_calls(backend) == before, tool_name, "invalid",
                    "invalid input reached the backend");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "policy", std::string()) == "bounded_stack_adapter",
        tool_name, "invalid", "bounded policy diagnostics are absent");
    ++completed;

    json ambiguous = valid;
    ambiguous.erase("pid");
    ambiguous["bin_name"] = "fixture";
    before = total_backend_calls(backend);
    result = adapter(handlers, ambiguous, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED",
                    tool_name, "ambiguous_target",
                    "ambiguous binary selector was not rejected canonically");
    require_fixture(total_backend_calls(backend) == before, tool_name, "ambiguous_target",
                    "ambiguous target reached the backend");
    ++completed;

    auto cancellation = cancellation_token_t::create();
    backend.cancel_during_dispatch = cancellation.state();
    before = total_backend_calls(backend);
    result = adapter(handlers, valid, cancellation, metadata);
    backend.cancel_during_dispatch.reset();
    require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                    tool_name, "cancellation",
                    "in-flight cancellation was not observed canonically");
    ++completed;

    backend.invalid_output = true;
    before = total_backend_calls(backend);
    result = adapter(handlers, valid, cancellation_token_t::create(), metadata);
    backend.invalid_output = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    tool_name, "output_validation",
                    "schema-invalid structured output was not rejected canonically");
    ++completed;
}

void verify_absent_frames_fixture(stack_handlers_t& handlers,
                                  backend_state_t& backend,
                                  std::size_t& completed) {
    backend.simulate = true;
    backend.store.clear();

    const json metadata{{"fixture_tool", "stack_frame"}};

    json args = routed({{"addrs", json::array({"0x140002000", "0x140003000", "0x140004000"})}});
    std::size_t before = backend.query_calls;
    auto result = adapters::stack_frame(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "stack_frame", "absent_frames", result.text());
    require_fixture(backend.query_calls == before + 1, "stack_frame", "absent_frames",
                    "query backend was not invoked exactly once");
    const json& structured = result.structured_content();
    require_fixture(structured.contains("result") && structured["result"].is_array(),
                    "stack_frame", "absent_frames", "result array is absent");
    require_fixture(structured["result"].size() == 3, "stack_frame", "absent_frames",
                    "result array does not contain exactly three entries");
    for (std::size_t i = 0; i < 3; ++i) {
        const auto& entry = structured["result"][i];
        require_fixture(entry.contains("addr") && entry["addr"].is_string(),
                        "stack_frame", "absent_frames", "addr field is missing or wrong type");
        require_fixture(entry.contains("vars") && entry["vars"].is_null(),
                        "stack_frame", "absent_frames",
                        "vars should be null for absent frame");
    }
    ++completed;

    backend.store.seed_frame("0x140002000", {
        {"saved_rbp", "-0x8", "8", "void*", "seed", 1.0},
        {"local_buf", "-0x40", "32", "char[32]", "seed", 1.0},
    });
    before = backend.query_calls;
    result = adapters::stack_frame(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "stack_frame", "absent_frames_mixed", result.text());
    require_fixture(backend.query_calls == before + 1, "stack_frame", "absent_frames_mixed",
                    "query backend was not invoked for mixed fixture");
    const auto& mixed = result.structured_content()["result"];
    require_fixture(mixed[0]["vars"].is_array() && mixed[0]["vars"].size() == 2,
                    "stack_frame", "absent_frames_mixed",
                    "seeded frame should return two variables");
    require_fixture(mixed[0]["vars"][0]["name"] == "saved_rbp",
                    "stack_frame", "absent_frames_mixed",
                    "first variable name does not match seeded value");
    require_fixture(mixed[0]["vars"][0]["offset"] == "-0x8",
                    "stack_frame", "absent_frames_mixed",
                    "first variable offset does not match seeded value");
    require_fixture(mixed[0]["vars"][0]["size"] == "8",
                    "stack_frame", "absent_frames_mixed",
                    "first variable size does not match seeded value");
    require_fixture(mixed[0]["vars"][0]["type"] == "void*",
                    "stack_frame", "absent_frames_mixed",
                    "first variable type does not match seeded value");
    require_fixture(mixed[1]["vars"].is_null(),
                    "stack_frame", "absent_frames_mixed",
                    "second address should still have null vars");
    require_fixture(mixed[2]["vars"].is_null(),
                    "stack_frame", "absent_frames_mixed",
                    "third address should still have null vars");
    ++completed;

    backend.store.clear();
    backend.simulate = false;
}

void verify_overlap_conflict_fixture(stack_handlers_t& handlers,
                                     backend_state_t& backend,
                                     std::size_t& completed) {
    backend.simulate = true;
    backend.store.clear();

    const json metadata{{"fixture_tool", "declare_stack"}};

    json first_batch = routed({{"items", json::array({
        {{"addr", "0x140005000"}, {"offset", "-0x10"}, {"name", "var_a"}, {"ty", "int"}},
        {{"addr", "0x140005000"}, {"offset", "-0x10"}, {"name", "var_b"}, {"ty", "int"}},
    })}});
    std::size_t before = backend.overlay_calls;
    auto result = adapters::declare_stack(handlers, first_batch, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "declare_stack", "overlap_conflict", result.text());
    require_fixture(backend.overlay_calls == before + 1, "declare_stack", "overlap_conflict",
                    "overlay backend was not invoked exactly once");
    const auto& results = result.structured_content()["result"];
    require_fixture(results.size() == 2, "declare_stack", "overlap_conflict",
                    "declare_stack should return two results for two items");
    require_fixture(!results[0].contains("error"),
                    "declare_stack", "overlap_conflict",
                    "first declaration should succeed without error");
    require_fixture(results[0]["name"] == "var_a",
                    "declare_stack", "overlap_conflict",
                    "first result name should be var_a");
    require_fixture(results[1].contains("error") &&
                        results[1]["error"] == "offset_overlap_conflict",
                    "declare_stack", "overlap_conflict",
                    "second declaration should report offset_overlap_conflict");
    ++completed;

    json type_conflict_batch = routed({{"items", json::array({
        {{"addr", "0x140006000"}, {"offset", "-0x20"}, {"name", "var_c"}, {"ty", "int"}},
        {{"addr", "0x140006000"}, {"offset", "-0x30"}, {"name", "var_c"}, {"ty", "char*"}},
    })}});
    before = backend.overlay_calls;
    result = adapters::declare_stack(handlers, type_conflict_batch, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "declare_stack", "type_conflict", result.text());
    require_fixture(backend.overlay_calls == before + 1, "declare_stack", "type_conflict",
                    "overlay backend was not invoked for type conflict");
    const auto& tc_results = result.structured_content()["result"];
    require_fixture(!tc_results[0].contains("error"),
                    "declare_stack", "type_conflict",
                    "first type-conflict declaration should succeed");
    require_fixture(tc_results[1].contains("error") &&
                        tc_results[1]["error"] == "type_conflict",
                    "declare_stack", "type_conflict",
                    "second declaration should report type_conflict");
    ++completed;

    json same_name_same_type = routed({{"items", json::array({
        {{"addr", "0x140007000"}, {"offset", "-0x40"}, {"name", "var_d"}, {"ty", "int"}},
        {{"addr", "0x140007000"}, {"offset", "-0x48"}, {"name", "var_d"}, {"ty", "int"}},
    })}});
    before = backend.overlay_calls;
    result = adapters::declare_stack(handlers, same_name_same_type, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "declare_stack", "update_same_name", result.text());
    const auto& upd_results = result.structured_content()["result"];
    require_fixture(!upd_results[0].contains("error"),
                    "declare_stack", "update_same_name",
                    "first update declaration should succeed");
    require_fixture(!upd_results[1].contains("error"),
                    "declare_stack", "update_same_name",
                    "second update with same name and type should succeed as update");
    const auto* frame = backend.store.get_frame("0x140007000");
    require_fixture(frame != nullptr && frame->vars.size() == 1,
                    "declare_stack", "update_same_name",
                    "frame should contain exactly one variable after in-place update");
    require_fixture(frame->vars[0].offset == "-0x48",
                    "declare_stack", "update_same_name",
                    "updated variable offset should reflect the second declaration");
    ++completed;

    backend.store.clear();
    backend.simulate = false;
}

void verify_undo_fixture(stack_handlers_t& handlers,
                         backend_state_t& backend,
                         std::size_t& completed) {
    backend.simulate = true;
    backend.store.clear();

    const json metadata{{"fixture_tool", "delete_stack"}};

    json declare_args = routed({{"items", json::array({
        {{"addr", "0x140008000"}, {"offset", "-0x10"}, {"name", "undo_var"}, {"ty", "int"}},
        {{"addr", "0x140008000"}, {"offset", "-0x20"}, {"name", "keep_var"}, {"ty", "long"}},
    })}});
    auto result = adapters::declare_stack(handlers, declare_args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "delete_stack", "undo_declare", result.text());
    const auto* frame = backend.store.get_frame("0x140008000");
    require_fixture(frame != nullptr && frame->vars.size() == 2,
                    "delete_stack", "undo_declare",
                    "frame should contain two variables after declaration");
    require_fixture(backend.store.overlay_count() == 2,
                    "delete_stack", "undo_declare",
                    "overlay log should contain two records");
    ++completed;

    json delete_args = routed({{"items", json{{"addr", "0x140008000"}, {"name", "undo_var"}}}});
    std::size_t before = backend.overlay_calls;
    result = adapters::delete_stack(handlers, delete_args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "delete_stack", "undo_delete", result.text());
    require_fixture(backend.overlay_calls == before + 1, "delete_stack", "undo_delete",
                    "overlay backend was not invoked for delete");
    const auto& del_results = result.structured_content()["result"];
    require_fixture(del_results.size() == 1, "delete_stack", "undo_delete",
                    "delete_stack should return one result");
    require_fixture(!del_results[0].contains("error"),
                    "delete_stack", "undo_delete",
                    "delete should succeed without error");
    require_fixture(del_results[0]["name"] == "undo_var",
                    "delete_stack", "undo_delete",
                    "delete result name should match");
    frame = backend.store.get_frame("0x140008000");
    require_fixture(frame != nullptr && frame->vars.size() == 1,
                    "delete_stack", "undo_delete",
                    "frame should contain one variable after deletion");
    require_fixture(frame->vars[0].name == "keep_var",
                    "delete_stack", "undo_delete",
                    "remaining variable should be keep_var");
    require_fixture(backend.store.overlay_count() == 3,
                    "delete_stack", "undo_delete",
                    "overlay log should contain three records after delete");
    ++completed;

    backend.store.undo_last_overlay();
    frame = backend.store.get_frame("0x140008000");
    require_fixture(frame != nullptr && frame->vars.size() == 2,
                    "delete_stack", "undo_reversal",
                    "frame should contain two variables after undo reversal");
    require_fixture(frame->vars[0].name == "keep_var" && frame->vars[1].name == "undo_var",
                    "delete_stack", "undo_reversal",
                    "undo should have restored undo_var");
    require_fixture(backend.store.overlay_count() == 2,
                    "delete_stack", "undo_reversal",
                    "overlay log should contain two records after undo");
    ++completed;

    json delete_missing = routed({{"items", json{{"addr", "0x140009000"}, {"name", "nonexistent"}}}});
    before = backend.overlay_calls;
    result = adapters::delete_stack(handlers, delete_missing, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "delete_stack", "undo_missing_frame", result.text());
    require_fixture(backend.overlay_calls == before + 1, "delete_stack", "undo_missing_frame",
                    "overlay backend was not invoked for missing frame delete");
    const auto& missing_results = result.structured_content()["result"];
    require_fixture(missing_results[0].contains("error") &&
                        missing_results[0]["error"] == "frame_not_found",
                    "delete_stack", "undo_missing_frame",
                    "deleting from absent frame should report frame_not_found");
    ++completed;

    json delete_missing_var = routed({{"items", json{{"addr", "0x140008000"}, {"name", "ghost"}}}});
    result = adapters::delete_stack(handlers, delete_missing_var, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "delete_stack", "undo_missing_var", result.text());
    const auto& ghost_results = result.structured_content()["result"];
    require_fixture(ghost_results[0].contains("error") &&
                        ghost_results[0]["error"] == "variable_not_found",
                    "delete_stack", "undo_missing_var",
                    "deleting nonexistent variable should report variable_not_found");
    ++completed;

    backend.store.clear();
    backend.simulate = false;
}

void verify_stale_generation_fixture(target_resolver_t& resolver,
                                     std::size_t& completed) {
    require(static_cast<bool>(resolver.publish(
                make_target(10, 4201, 0xB201ULL, "stale-alpha.exe", 1))),
            "stale generation first target publication failed");
    require(static_cast<bool>(resolver.publish(
                make_target(11, 4202, 0xB202ULL, "stale-beta.exe", 2))),
            "stale generation second target publication failed");

    target_selector_t selector;
    selector.pid = 4201;
    auto resolution = resolver.resolve(selector, 1);
    require_fixture(static_cast<bool>(resolution), "resolver", "stale_generation",
                    "resolve with matching generation should succeed");
    require_fixture(resolution.value().target().generation == 1,
                    "resolver", "stale_generation",
                    "resolved target generation should be 1");
    ++completed;

    resolution = resolver.resolve(selector, 2);
    require_fixture(!static_cast<bool>(resolution), "resolver", "stale_generation",
                    "resolve with stale generation should fail");
    require_fixture(resolution.error().code == target_resolution_error_code_t::target_generation_stale,
                    "resolver", "stale_generation",
                    "stale generation error code should be target_generation_stale");
    require_fixture(resolution.error().expected == 2 && resolution.error().actual == 1,
                    "resolver", "stale_generation",
                    "stale generation error should carry expected=2 actual=1");
    ++completed;

    resolution = resolver.resolve(selector);
    require_fixture(static_cast<bool>(resolution), "resolver", "stale_generation",
                    "resolve without expected generation should succeed");
    ++completed;

    require(static_cast<bool>(resolver.retire(10)), "resolver", "stale_generation",
            "retiring stale target should succeed");
    resolution = resolver.resolve(selector, 1);
    require_fixture(!static_cast<bool>(resolution), "resolver", "stale_generation",
                    "resolve against retired target should fail");
    require_fixture(resolution.error().code == target_resolution_error_code_t::target_retired,
                    "resolver", "stale_generation",
                    "retired target error code should be target_retired");
    ++completed;

    require(static_cast<bool>(resolver.publish(
                make_target(12, 4201, 0xB203ULL, "stale-alpha.exe", 3))),
            "re-publishing target with new generation should succeed");
    resolution = resolver.resolve(selector, 1);
    require_fixture(!static_cast<bool>(resolution), "resolver", "stale_generation",
                    "resolve with old generation against re-published target should fail");
    require_fixture(resolution.error().code == target_resolution_error_code_t::target_generation_stale,
                    "resolver", "stale_generation",
                    "re-published stale generation should still report target_generation_stale");
    require_fixture(resolution.error().actual == 3,
                    "resolver", "stale_generation",
                    "re-published target actual generation should be 3");
    ++completed;

    require(static_cast<bool>(resolver.retire(11)), "resolver", "stale_generation",
            "cleanup retire of second stale target should succeed");
    require(static_cast<bool>(resolver.retire(12)), "resolver", "stale_generation",
            "cleanup retire of third stale target should succeed");
}

void verify_exact_output_fixture(stack_handlers_t& handlers,
                                 backend_state_t& backend,
                                 std::size_t& completed) {
    backend.simulate = true;
    backend.store.clear();

    const json metadata{{"fixture_tool", "stack_frame"}};

    backend.store.seed_frame("0x14000A000", {
        {"rbp_save", "-0x8", "8", "void*", "seed", 1.0},
        {"counter", "-0x4", "4", "int", "seed", 1.0},
        {"buffer", "-0x100", "256", "char[256]", "seed", 1.0},
    });

    json query_args = routed({{"addrs", "0x14000A000"}});
    auto result = adapters::stack_frame(handlers, query_args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "stack_frame", "exact_output", result.text());
    const json expected = {
        {"result", json::array({
            {{"addr", "0x14000A000"}, {"vars", json::array({
                {{"name", "rbp_save"}, {"offset", "-0x8"}, {"size", "8"}, {"type", "void*"}},
                {{"name", "counter"}, {"offset", "-0x4"}, {"size", "4"}, {"type", "int"}},
                {{"name", "buffer"}, {"offset", "-0x100"}, {"size", "256"}, {"type", "char[256]"}},
            })}},
        })},
    };
    require_fixture(result.structured_content() == expected,
                    "stack_frame", "exact_output",
                    "structured output does not match the exact expected JSON");
    ++completed;

    json declare_args = routed({{"items", json::array({
        {{"addr", "0x14000B000"}, {"offset", "-0x10"}, {"name", "new_var"}, {"ty", "int"}},
    })}});
    result = adapters::declare_stack(handlers, declare_args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "declare_stack", "exact_output", result.text());
    const json expected_declare = {
        {"result", json::array({
            {{"addr", "0x14000B000"}, {"name", "new_var"}},
        })},
    };
    require_fixture(result.structured_content() == expected_declare,
                    "declare_stack", "exact_output",
                    "declare structured output does not match exact expected JSON");
    ++completed;

    json delete_args = routed({{"items", json::array({
        {{"addr", "0x14000B000"}, {"name", "new_var"}},
    })}});
    result = adapters::delete_stack(handlers, delete_args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "delete_stack", "exact_output", result.text());
    const json expected_delete = {
        {"result", json::array({
            {{"addr", "0x14000B000"}, {"name", "new_var"}},
        })},
    };
    require_fixture(result.structured_content() == expected_delete,
                    "delete_stack", "exact_output",
                    "delete structured output does not match exact expected JSON");
    ++completed;

    json batch_query = routed({{"addrs", json::array({"0x14000A000", "0x14000C000"})}});
    result = adapters::stack_frame(handlers, batch_query, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "stack_frame", "exact_output_batch", result.text());
    const auto& batch_result = result.structured_content()["result"];
    require_fixture(batch_result.size() == 2,
                    "stack_frame", "exact_output_batch",
                    "batch query should return two results");
    require_fixture(batch_result[0]["vars"].is_array() && batch_result[0]["vars"].size() == 3,
                    "stack_frame", "exact_output_batch",
                    "first address should return three variables");
    require_fixture(batch_result[1]["vars"].is_null(),
                    "stack_frame", "exact_output_batch",
                    "second address should return null vars");
    ++completed;

    backend.store.clear();
    backend.simulate = false;
}

void verify_stack_handlers() {
    target_resolver_t resolver;
    effect_lock_manager_t locks;
    require(static_cast<bool>(resolver.publish(
                make_target(1, 4101, 0xA101ULL, "fixture-alpha.exe"))),
            "first stack handler target publication failed");
    require(static_cast<bool>(resolver.publish(
                make_target(2, 4102, 0xA102ULL, "fixture-beta.exe"))),
            "second stack handler target publication failed");

    backend_state_t backend;
    workspace_adapter_handlers_t workspace_handlers;
    workspace_handlers.query = [&backend](const adapter_call_context_t& context,
                                          const adapter_request_t& request) {
        return backend.respond("query", context, request);
    };
    workspace_handlers.overlay = [&backend](const adapter_call_context_t& context,
                                            const adapter_request_t& request) {
        return backend.respond("overlay", context, request);
    };
    workspace_adapter_t workspace(resolver, locks, std::move(workspace_handlers));
    protocol::schema_runtime_t schemas(64);
    stack_handlers_t handlers(workspace, schemas);

    verify_contracts(handlers, schemas);

    std::size_t completed = 0;
    for (std::size_t index = 0; index < k_stack_tool_count; ++index) {
        const auto name = stack_tool_names()[index];
        require(k_stack_adapters[index] != nullptr,
                "stack adapter function is not linked");
        verify_fixture(name, k_stack_adapters[index], handlers, backend, completed);
    }

    require(completed >= k_stack_tool_count * 5U,
            "stack handler harness did not execute all standard fixture families");

    verify_absent_frames_fixture(handlers, backend, completed);
    verify_overlap_conflict_fixture(handlers, backend, completed);
    verify_undo_fixture(handlers, backend, completed);
    verify_stale_generation_fixture(resolver, completed);
    verify_exact_output_fixture(handlers, backend, completed);

    require(completed >= k_stack_tool_count * 5U + 14U,
            "stack handler harness did not execute all stack-specific fixture families");
}

}

bool run_stack_handlers_harness(std::string& failure) {
    try {
        verify_stack_handlers();
    } catch (const std::exception& error) {
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
