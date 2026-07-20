#include "memory_handlers_harness.hpp"
#include "../c03/assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/mcp/compat/handlers/memory.h"
#include "../../src/core/mcp/compat/workspace_adapter.hpp"
#include "../../src/core/mcp/compat/target_resolver.hpp"
#include "../../src/core/mcp/compat/effect_policy.hpp"
#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"
#include "../../src/core/mcp/protocol/mcp_tool_contract.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
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
namespace protocol = aida::standalone::mcp::protocol;
using protocol::cancellation_token_t;
using protocol::json;

constexpr std::array<std::string_view, k_memory_tool_count> k_memory_names{{
    "get_bytes",
    "get_int",
    "get_string",
    "get_global_value",
    "patch",
    "put_int",
}};

void require(bool condition, std::string_view message) {
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void require_fixture(bool condition, std::string_view fixture,
                     std::string_view detail) {
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, detail, __FILE__, __LINE__);
    if (!condition) {
        throw std::runtime_error(
            std::string(fixture) + " fixture: " + std::string(detail));
    }
}

int hex_nibble(char value) noexcept {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

std::vector<std::uint8_t> parse_hex(std::string_view text) {
    std::vector<std::uint8_t> bytes;
    int high = -1;
    for (char value : text) {
        if (std::isspace(static_cast<unsigned char>(value)) != 0 ||
            value == ',' || value == ':' || value == '_') {
            if (high != -1) {
                throw std::runtime_error("fixture hex byte is incomplete");
            }
            continue;
        }
        const int nibble = hex_nibble(value);
        if (nibble < 0) {
            throw std::runtime_error("fixture hex byte is invalid");
        }
        if (high < 0) {
            high = nibble;
        } else {
            bytes.push_back(static_cast<std::uint8_t>((high << 4) | nibble));
            high = -1;
        }
    }
    if (high != -1 || bytes.empty()) {
        throw std::runtime_error("fixture hex sequence is empty or incomplete");
    }
    return bytes;
}

std::string format_hex(const std::vector<std::uint8_t>& bytes) {
    static constexpr char k_hex[] = "0123456789ABCDEF";
    std::string output;
    if (!bytes.empty()) {
        output.reserve(bytes.size() * 3U - 1U);
    }
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0) {
            output.push_back(' ');
        }
        output.push_back(k_hex[(bytes[index] >> 4U) & 0x0FU]);
        output.push_back(k_hex[bytes[index] & 0x0FU]);
    }
    return output;
}

json as_array(const json& value) {
    return value.is_array() ? value : json::array({value});
}

bool is_overlay(std::string_view name) noexcept {
    return name == "patch" || name == "put_int";
}

target_record_t make_target(std::uint64_t target_id, std::uint32_t pid,
                            std::uint64_t creation_identity, std::string name,
                            bool live = false) {
    target_record_t target;
    target.target_id = target_id;
    target.pid = pid;
    target.process_creation_identity = creation_identity;
    target.bin_name = std::move(name);
    target.generation = live ? 11U : 9U;
    target.attach_generation = live ? 0x311ULL : 0x109ULL;
    target.live = live;
    target.live_capture_base = live ? 0x140000000ULL : 0ULL;
    target.live_capture_size = live ? 0x20000ULL : 0ULL;
    target.live_snapshot_permitted = live;
    target.live_snapshot_maximum_bytes = live ? 0x20000ULL : 0ULL;
    target.revision = 1;
    return target;
}

json routed(json arguments, std::uint32_t pid = 4101U) {
    arguments["pid"] = pid;
    return arguments;
}

json valid_arguments(std::string_view tool) {
    if (tool == "get_bytes") {
        return routed({{"regions", json{{"addr", "0x140001000"}, {"size", 8}}}});
    }
    if (tool == "get_int") {
        return routed({{"queries", json{{"addr", "0x140001000"}, {"ty", "u32le"}}}});
    }
    if (tool == "get_string") {
        return routed({{"addrs", "0x140001000"}});
    }
    if (tool == "get_global_value") {
        return routed({{"queries", "g_main"}});
    }
    if (tool == "patch") {
        return routed({{"patches", json{{"addr", "0x140001000"},
                                         {"data", "90 90 90 90"}}}});
    }
    if (tool == "put_int") {
        return routed({{"items", json{{"addr", "0x140001000"},
                                       {"ty", "u32le"}, {"value", "42"}}}});
    }
    return routed(json::object());
}

json invalid_arguments(std::string_view tool,
                       const memory_handler_limits_t& limits) {
    if (tool == "get_bytes") {
        return routed({{"regions", json{{"addr", "0x140001000"},
                                          {"size", limits.maximum_read_bytes_per_item + 1U}}}});
    }
    if (tool == "get_int") {
        return routed({{"queries", json{{"addr", "0x140001000"}, {"ty", "u24"}}}});
    }
    if (tool == "get_string") {
        return routed({{"addrs", "not-an-address"}});
    }
    if (tool == "get_global_value") {
        return routed({{"queries", ""}});
    }
    if (tool == "patch") {
        return routed({{"patches", json{{"addr", "0x140001000"}, {"data", "9"}}}});
    }
    if (tool == "put_int") {
        return routed({{"items", json{{"addr", "0x140001000"},
                                       {"ty", "i8"}, {"value", "128"}}}});
    }
    return routed(json::object());
}

struct byte_change_t final {
    std::uint64_t address = 0;
    std::vector<std::uint8_t> before;
};

struct backend_state_t final {
    std::size_t calls = 0;
    std::string last_contract;
    std::string last_lane;
    json last_arguments = json::object();
    std::uint32_t last_pid = 0;
    bool saw_deadline = false;
    bool invalid_output = false;
    bool stale_response_generation = false;
    bool short_successful_read = false;
    bool force_live_write_receipt = false;
    std::string global_value = "fixture-global";
    std::shared_ptr<std::atomic_bool> cancel_during_dispatch;
    std::unordered_map<std::uint64_t, std::uint8_t> overlay_bytes;
    std::vector<byte_change_t> last_changes;
    std::uint64_t overlay_revision = 1;

    void seed(std::uint64_t address, const std::vector<std::uint8_t>& bytes) {
        for (std::size_t index = 0; index < bytes.size(); ++index) {
            overlay_bytes[address + index] = bytes[index];
        }
    }

    std::vector<std::uint8_t> read_overlay(
        std::uint64_t address, std::size_t size) const {
        std::vector<std::uint8_t> bytes(size, 0);
        for (std::size_t index = 0; index < size; ++index) {
            const auto found = overlay_bytes.find(address + index);
            if (found != overlay_bytes.end()) {
                bytes[index] = found->second;
            }
        }
        return bytes;
    }

    bool undo_last_transaction() {
        if (last_changes.empty()) {
            return false;
        }
        for (auto change = last_changes.rbegin(); change != last_changes.rend(); ++change) {
            for (std::size_t index = 0; index < change->before.size(); ++index) {
                overlay_bytes[change->address + index] = change->before[index];
            }
        }
        last_changes.clear();
        ++overlay_revision;
        return true;
    }

    adapter_result_t<adapter_response_t> respond(
        const char* lane_name, const adapter_call_context_t& context,
        const adapter_request_t& request) {
        ++calls;
        last_lane = lane_name;
        last_contract = context.contract == nullptr
            ? std::string()
            : std::string(context.contract->name);
        last_pid = context.target ? context.target->target().pid : 0;
        saw_deadline = request.deadline.has_value() &&
            *request.deadline > std::chrono::steady_clock::now();
        last_arguments = json::parse(request.payload, nullptr, false);
        if (cancel_during_dispatch) {
            cancel_during_dispatch->store(true, std::memory_order_release);
        }
        if (invalid_output) {
            return adapter_result_t<adapter_response_t>::success(
                {json{{"__schema_violation", true}}.dump(), false});
        }
        if (context.contract == nullptr || !context.target ||
            last_arguments.is_discarded() || !last_arguments.is_object()) {
            return adapter_result_t<adapter_response_t>::failure(
                {adapter_error_code_t::backend_rejected,
                 "fixture_context_invalid", 0, 0});
        }
        const auto memory = last_arguments.find("_aida_memory");
        if (memory == last_arguments.end() || !memory->is_object()) {
            return adapter_result_t<adapter_response_t>::failure(
                {adapter_error_code_t::backend_rejected,
                 "fixture_memory_intent_missing", 0, 0});
        }
        const auto& target = context.target->target();
        const auto operation = memory->value("operation", std::string());
        if (operation == "read") {
            return read_response(target, *memory);
        }
        if (operation == "overlay_transaction") {
            if (target.live || !memory->value("static_target_only", false) ||
                memory->value("live_write_permitted", true)) {
                return adapter_result_t<adapter_response_t>::failure(
                    {adapter_error_code_t::operation_not_permitted,
                     "fixture_live_overlay_denied", 0, 0});
            }
            return overlay_response(target, *memory);
        }
        return adapter_result_t<adapter_response_t>::failure(
            {adapter_error_code_t::backend_rejected,
             "fixture_memory_operation_invalid", 0, 0});
    }

private:
    adapter_result_t<adapter_response_t> read_response(
        const target_record_t& target, const json& intent) {
        json result = json::array();
        std::uint64_t bytes_read = 0;
        const auto tool = intent.value("tool", std::string());
        if (tool == "get_bytes") {
            for (const auto& range : intent.at("ranges")) {
                std::size_t size = range.at("size").get<std::size_t>();
                if (short_successful_read && size > 1U) {
                    --size;
                }
                std::vector<std::uint8_t> bytes(size);
                for (std::size_t index = 0; index < size; ++index) {
                    bytes[index] = static_cast<std::uint8_t>(index & 0xFFU);
                }
                bytes_read += size;
                result.push_back({{"addr", range.at("addr")},
                                  {"data", format_hex(bytes)}});
            }
        } else if (tool == "get_int") {
            for (const auto& range : intent.at("ranges")) {
                const auto integer_type = range.at("integer_type").get<std::string>();
                std::vector<std::uint8_t> bytes;
                if (integer_type == "u32be") {
                    bytes = {0x12U, 0x34U, 0x56U, 0x78U};
                } else if (integer_type == "i16le") {
                    bytes = {0xFEU, 0xFFU};
                } else {
                    bytes.assign(range.at("size").get<std::size_t>(), 0U);
                }
                bytes_read += bytes.size();
                result.push_back({{"addr", range.at("addr")},
                                  {"data", format_hex(bytes)}});
            }
        } else if (tool == "get_string") {
            for (const auto& range : intent.at("ranges")) {
                const std::string value = "fixture-string";
                bytes_read += value.size();
                result.push_back({{"addr", range.at("addr")}, {"value", value}});
            }
        } else if (tool == "get_global_value") {
            for (const auto& query : as_array(last_arguments.at("queries"))) {
                bytes_read += global_value.size();
                result.push_back({{"query", query}, {"value", global_value}});
            }
        } else {
            return adapter_result_t<adapter_response_t>::failure(
                {adapter_error_code_t::backend_rejected,
                 "fixture_read_tool_invalid", 0, 0});
        }

        const std::uint64_t generation = stale_response_generation
            ? target.generation + 1U
            : target.generation;
        json snapshot{
            {"generation", generation},
            {"bytes_read", bytes_read},
            {"read_only", true},
        };
        if (target.live) {
            snapshot["source"] = "bounded_live_snapshot";
            snapshot["module_boundary_validated"] = true;
            snapshot["identity_revalidated"] = true;
            snapshot["target_id"] = target.target_id;
            snapshot["pid"] = target.pid;
            snapshot["process_creation_identity"] = target.process_creation_identity;
            snapshot["module_base"] = target.live_capture_base;
            snapshot["module_size"] = target.live_capture_size;
            snapshot["attach_generation"] = target.attach_generation;
        } else {
            snapshot["source"] = "immutable_workspace_snapshot";
            snapshot["immutable"] = true;
        }
        json output{
            {"result", std::move(result)},
            {"_aida_memory", json{{"snapshot", std::move(snapshot)}}},
        };
        return adapter_result_t<adapter_response_t>::success(
            {output.dump(), false});
    }

    adapter_result_t<adapter_response_t> overlay_response(
        const target_record_t& target, const json& intent) {
        const auto revision_before = overlay_revision;
        const auto revision_after = ++overlay_revision;
        last_changes.clear();
        json receipts = json::array();
        for (const auto& operation : intent.at("operations")) {
            const auto address = operation.at("address").get<std::uint64_t>();
            const auto after = parse_hex(operation.at("after").get<std::string>());
            const auto before = read_overlay(address, after.size());
            last_changes.push_back({address, before});
            for (std::size_t index = 0; index < after.size(); ++index) {
                overlay_bytes[address + index] = after[index];
            }
            receipts.push_back({
                {"index", operation.at("index")},
                {"kind", operation.at("kind")},
                {"addr", operation.at("addr")},
                {"size", after.size()},
                {"before", format_hex(before)},
                {"after", format_hex(after)},
            });
        }
        const std::string suffix = std::to_string(calls);
        json transaction{
            {"transaction_id", "fixture-tx-" + suffix},
            {"committed", true},
            {"reversible", true},
            {"undo_supported", true},
            {"undo_token", "fixture-undo-" + suffix},
            {"live_write_performed", force_live_write_receipt},
            {"generation", stale_response_generation
                ? target.generation + 1U
                : target.generation},
            {"overlay_revision_before", revision_before},
            {"overlay_revision_after", revision_after},
            {"operations", std::move(receipts)},
        };
        json output{
            {"result", json::array()},
            {"_aida_memory", json{{"transaction", std::move(transaction)}}},
        };
        return adapter_result_t<adapter_response_t>::success(
            {output.dump(), false});
    }
};

void verify_contracts(const memory_handlers_t& handlers,
                      protocol::schema_runtime_t& schemas) {
    require(handlers.size() == k_memory_tool_count,
            "memory handler contract count is not exactly six");
    require(memory_tool_names() == k_memory_names,
            "memory handler name ledger differs from the C12 ledger");
    std::unordered_set<std::string> unique_names;
    for (std::size_t index = 0; index < k_memory_tool_count; ++index) {
        const auto name = k_memory_names[index];
        const auto* descriptor = find_contract(name);
        const auto& contract = handlers.contract_at(index);
        require(descriptor != nullptr, "memory generated descriptor is missing");
        require(contract.name == name && handlers.find(name) == &contract,
                "memory handler lookup differs from the exact name ledger");
        require(unique_names.emplace(contract.name).second,
                "memory handler name ledger contains a duplicate");
        require(descriptor->adapter_symbol ==
                    "aida::standalone::mcp::compat::adapters::" + std::string(name),
                "memory generated adapter symbol differs from the linked function name");
        require(contract.input_schema == json::parse(
                    descriptor->input_schema_json.begin(), descriptor->input_schema_json.end()) &&
                    contract.output_schema == json::parse(
                    descriptor->output_schema_json.begin(), descriptor->output_schema_json.end()),
                "memory generated schemas were not preserved");
        require(contract.target_policy.requirement ==
                    protocol::target_requirement_t::optional &&
                    contract.target_policy.accepts_pid &&
                    contract.target_policy.accepts_bin_name,
                "memory target routing policy differs from the generated policy");
        if (is_overlay(name)) {
            require(contract.effect_policy.effect ==
                        protocol::tool_effect_t::workspace_overlay_mutation &&
                        contract.effect_policy.lock ==
                        protocol::effect_lock_t::workspace_overlay_transaction &&
                        !contract.effect_policy.read_only,
                    "memory overlay effect classification is invalid");
        } else {
            require(contract.effect_policy.effect ==
                        protocol::tool_effect_t::workspace_read &&
                        contract.effect_policy.lock ==
                        protocol::effect_lock_t::workspace_shared &&
                        contract.effect_policy.read_only,
                    "memory read effect classification is invalid");
        }
        require(!contract.effect_policy.unsafe,
                "memory tool must not be marked unsafe");
        require(protocol::validate_tool_contract(contract, schemas).valid,
                "memory generated contract fails schema runtime validation");
    }
}

void verify_all_tool_dispatch(memory_handlers_t& handlers,
                              backend_state_t& backend) {
    std::size_t completed = 0;
    for (const auto name : k_memory_names) {
        const std::size_t before = backend.calls;
        auto result = handlers.invoke(
            name, valid_arguments(name), cancellation_token_t::create());
        require_fixture(!result.is_error(), name, result.text());
        require_fixture(backend.calls == before + 1U, name,
                        "backend was not invoked exactly once");
        require_fixture(backend.last_contract == name && backend.last_pid == 4101U &&
                            backend.last_lane == (is_overlay(name) ? "overlay" : "query") &&
                            backend.saw_deadline,
                        name, "routing identity or deadline was not preserved");
        require_fixture(!backend.last_arguments.contains("pid") &&
                            !backend.last_arguments.contains("bin_name") &&
                            backend.last_arguments.contains("_aida_memory"),
                        name, "C12 intent was not active in backend dispatch");
        require_fixture(result.structured_content().is_object() &&
                            result.structured_content().contains("result"),
                        name, "normalized structured result is absent");
        if (is_overlay(name)) {
            require_fixture(result.aida_metadata().value("reversible", false),
                            name, "reversible transaction metadata is absent");
            require_fixture(backend.undo_last_transaction(), name,
                            "fixture overlay could not be undone");
        } else {
            require_fixture(result.aida_metadata().contains("memory_snapshot"),
                            name, "snapshot receipt metadata is absent");
        }
        ++completed;

        const auto invalid = invalid_arguments(name, handlers.limits());
        const std::size_t invalid_before = backend.calls;
        result = handlers.invoke(name, invalid, cancellation_token_t::create());
        require_fixture(result.is_error() &&
                            result.error_code() == "MCP_TOOL_INPUT_INVALID",
                        name, "invalid bounded input was not rejected");
        require_fixture(backend.calls == invalid_before, name,
                        "invalid bounded input reached the backend");
        require_fixture(result.structured_content().at("error").at("details").value(
                            "policy", std::string()) == "bounded_memory_adapter",
                        name, "bounded memory diagnostics are absent");
        ++completed;
    }
    require(completed == k_memory_tool_count * 2U,
            "memory handler fixture matrix did not cover every tool");
}

void verify_static_and_live_snapshots(memory_handlers_t& handlers) {
    auto static_result = handlers.get_bytes(
        valid_arguments("get_bytes"), cancellation_token_t::create());
    require_fixture(!static_result.is_error(), "static_snapshot", static_result.text());
    const auto& static_receipt = static_result.aida_metadata().at("memory_snapshot");
    require_fixture(static_receipt.value("source", std::string()) ==
                        "immutable_workspace_snapshot" &&
                        static_receipt.value("immutable", false) &&
                        static_receipt.value("read_only", false),
                    "static_snapshot", "immutable read receipt is incomplete");

    auto live_args = valid_arguments("get_bytes");
    live_args["pid"] = 4103U;
    memory_invocation_t live_invocation;
    live_invocation.expected_generation = 11U;
    live_invocation.expected_live_identity = live_memory_identity_t{
        3U, 4103U, 0xA103ULL, 0x140000000ULL, 0x20000ULL, 0x311ULL};
    auto live_result = handlers.get_bytes(
        live_args, cancellation_token_t::create(), live_invocation);
    require_fixture(!live_result.is_error(), "live_snapshot", live_result.text());
    const auto& live_receipt = live_result.aida_metadata().at("memory_snapshot");
    require_fixture(live_receipt.value("source", std::string()) ==
                        "bounded_live_snapshot" &&
                        live_receipt.value("module_boundary_validated", false) &&
                        live_receipt.value("identity_revalidated", false) &&
                        live_receipt.value("target_id", 0ULL) == 3U &&
                        live_receipt.value("pid", 0U) == 4103U &&
                        live_receipt.value("process_creation_identity", 0ULL) == 0xA103ULL &&
                        live_receipt.value("module_base", 0ULL) == 0x140000000ULL &&
                        live_receipt.value("module_size", 0ULL) == 0x20000ULL &&
                        live_receipt.value("attach_generation", 0ULL) == 0x311ULL &&
                        live_receipt.value("read_only", false),
                    "live_snapshot", "bounded live-read receipt is incomplete");

    auto mismatched_invocation = live_invocation;
    mismatched_invocation.expected_live_identity->module_size = 0x20001ULL;
    const auto mismatched = handlers.get_bytes(
        live_args, cancellation_token_t::create(), mismatched_invocation);
    require_fixture(mismatched.is_error() &&
                        mismatched.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    "live_snapshot", "live identity mismatch was not rejected");
}

void verify_complete_read_contract(memory_handlers_t& handlers,
                                   backend_state_t& backend) {
    backend.short_successful_read = true;
    const auto result = handlers.get_bytes(
        valid_arguments("get_bytes"), cancellation_token_t::create());
    backend.short_successful_read = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID" &&
                        result.structured_content().at("error").at("details").value(
                            "reason", std::string()) ==
                            "complete_read_or_explicit_error_required",
                    "complete_read_contract",
                    "short successful read was accepted without an explicit error");
}

void verify_stale_generation(memory_handlers_t& handlers,
                             backend_state_t& backend) {
    memory_invocation_t stale_request;
    stale_request.expected_generation = 8U;
    const std::size_t before = backend.calls;
    auto result = handlers.get_bytes(
        valid_arguments("get_bytes"), cancellation_token_t::create(), stale_request);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED" &&
                        backend.calls == before,
                    "stale_request_generation",
                    "stale request generation reached the backend");

    memory_invocation_t bound_request;
    bound_request.expected_generation = 9U;
    backend.stale_response_generation = true;
    result = handlers.get_bytes(
        valid_arguments("get_bytes"), cancellation_token_t::create(), bound_request);
    backend.stale_response_generation = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    "stale_response_generation",
                    "stale snapshot receipt was accepted");
}

void verify_aggregate_bounds(workspace_adapter_t& workspace,
                             protocol::schema_runtime_t& schemas,
                             backend_state_t& backend) {
    memory_handler_limits_t limits;
    limits.maximum_batch_items = 8U;
    limits.maximum_read_bytes_per_item = 8U;
    limits.maximum_read_bytes_per_call = 16U;
    limits.maximum_string_bytes = 8U;
    memory_handlers_t bounded(workspace, schemas, limits);

    json regions = json::array();
    for (std::size_t index = 0; index < 3U; ++index) {
        regions.push_back({{"addr", "0x140001000"}, {"size", 8U}});
    }
    json integer_queries = json::array();
    for (std::size_t index = 0; index < 5U; ++index) {
        integer_queries.push_back({{"addr", "0x140001000"}, {"ty", "u32"}});
    }
    json addresses = json::array({"0x140001000", "0x140001008", "0x140001010"});
    json patches = json::array();
    for (std::size_t index = 0; index < 3U; ++index) {
        patches.push_back({{"addr", "0x140001000"},
                           {"data", "00 01 02 03 04 05 06 07"}});
    }

    const std::array<std::pair<std::string_view, json>, 5> overflow_cases{{
        {"get_bytes", routed({{"regions", regions}})},
        {"get_int", routed({{"queries", integer_queries}})},
        {"get_string", routed({{"addrs", addresses}})},
        {"patch", routed({{"patches", patches}})},
        {"put_int", routed({{"items", integer_queries}})},
    }};
    for (const auto& [name, arguments] : overflow_cases) {
        json request = arguments;
        if (name == "put_int") {
            for (auto& item : request["items"]) {
                item["value"] = "1";
            }
        }
        const std::size_t before = backend.calls;
        const auto result = bounded.invoke(
            name, request, cancellation_token_t::create());
        require_fixture(result.is_error() &&
                            result.error_code() == "MCP_TOOL_INPUT_INVALID" &&
                            backend.calls == before,
                        std::string(name) + "_aggregate_overflow",
                        "aggregate overflow reached the backend");
    }

    backend.global_value.assign(9U, 'x');
    const auto result = bounded.get_global_value(
        valid_arguments("get_global_value"), cancellation_token_t::create());
    backend.global_value = "fixture-global";
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    "global_response_bound",
                    "oversized global value response was accepted");
}

void verify_integer_width_and_endian(memory_handlers_t& handlers,
                                     backend_state_t& backend) {
    const json queries = json::array({
        json{{"addr", "0x140001000"}, {"ty", "u32be"}},
        json{{"addr", "0x140001010"}, {"ty", "i16le"}},
    });
    const auto result = handlers.get_int(
        routed({{"queries", queries}}), cancellation_token_t::create());
    require_fixture(!result.is_error(), "integer_endian", result.text());
    const auto& values = result.structured_content().at("result");
    require_fixture(values.size() == 2U &&
                        values[0].at("value").get<std::uint64_t>() == 0x12345678ULL &&
                        values[1].at("value").get<std::int64_t>() == -2,
                    "integer_endian", "explicit endian decoding is incorrect");
    const auto& ranges = backend.last_arguments.at("_aida_memory").at("ranges");
    require_fixture(ranges[0].at("endian") == "big" &&
                        ranges[0].at("size") == 4U &&
                        ranges[1].at("endian") == "little" &&
                        ranges[1].at("size") == 2U,
                    "integer_endian", "width/endian intent is incomplete");
}

void verify_reversible_overlays(memory_handlers_t& handlers,
                                backend_state_t& backend) {
    constexpr std::uint64_t patch_address = 0x140001000ULL;
    const std::vector<std::uint8_t> original_patch{0xDEU, 0xADU, 0xBEU, 0xEFU};
    backend.seed(patch_address, original_patch);
    auto result = handlers.patch(
        routed({{"patches", json{{"addr", "0x140001000"},
                                   {"data", "90 91 92 93"}}}}),
        cancellation_token_t::create());
    require_fixture(!result.is_error() &&
                        result.aida_metadata().value("reversible", false) &&
                        !result.aida_metadata().value("undo_token", std::string()).empty(),
                    "reversible_patch", result.text());
    require_fixture(backend.read_overlay(patch_address, 4U) ==
                        std::vector<std::uint8_t>({0x90U, 0x91U, 0x92U, 0x93U}),
                    "reversible_patch", "patch bytes were not applied to the overlay");
    require_fixture(backend.undo_last_transaction() &&
                        backend.read_overlay(patch_address, 4U) == original_patch,
                    "reversible_patch", "patch undo did not restore prior bytes");

    constexpr std::uint64_t big_address = 0x140001020ULL;
    constexpr std::uint64_t little_address = 0x140001030ULL;
    const std::vector<std::uint8_t> original_big{1U, 2U, 3U, 4U};
    const std::vector<std::uint8_t> original_little{5U, 6U};
    backend.seed(big_address, original_big);
    backend.seed(little_address, original_little);
    const json items = json::array({
        json{{"addr", "0x140001020"}, {"ty", "u32be"},
             {"value", "0x12345678"}},
        json{{"addr", "0x140001030"}, {"ty", "i16le"}, {"value", "-2"}},
    });
    result = handlers.put_int(
        routed({{"items", items}}), cancellation_token_t::create());
    require_fixture(!result.is_error(), "reversible_put_int", result.text());
    const auto& intent = backend.last_arguments.at("_aida_memory");
    require_fixture(intent.value("live_write_permitted", true) == false &&
                        intent.value("reversible", false) &&
                        intent.at("operations")[0].at("after") == "12 34 56 78" &&
                        intent.at("operations")[1].at("after") == "FE FF",
                    "reversible_put_int",
                    "encoded integer overlay intent is incorrect");
    require_fixture(backend.undo_last_transaction() &&
                        backend.read_overlay(big_address, 4U) == original_big &&
                        backend.read_overlay(little_address, 2U) == original_little,
                    "reversible_put_int", "integer overlay undo did not restore bytes");
}

void verify_live_write_denial(memory_handlers_t& handlers,
                              backend_state_t& backend) {
    auto live_patch = valid_arguments("patch");
    live_patch["pid"] = 4103U;
    const auto before_live = backend.read_overlay(0x140001000ULL, 4U);
    auto result = handlers.patch(
        live_patch, cancellation_token_t::create());
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_EFFECT_POLICY_REJECTED" &&
                        backend.read_overlay(0x140001000ULL, 4U) == before_live,
                    "live_overlay_denial",
                    "live target obtained a workspace overlay write");

    backend.force_live_write_receipt = true;
    result = handlers.patch(
        valid_arguments("patch"), cancellation_token_t::create());
    backend.force_live_write_receipt = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID" &&
                        backend.last_arguments.at("_aida_memory").value(
                            "live_write_permitted", true) == false,
                    "live_write_receipt_denial",
                    "backend live-write receipt was accepted");
    require_fixture(backend.undo_last_transaction(),
                    "live_write_receipt_denial",
                    "fixture transaction cleanup failed");
}

void verify_routing_and_failure_shapes(memory_handlers_t& handlers,
                                       backend_state_t& backend) {
    auto ambiguous = valid_arguments("get_bytes");
    ambiguous.erase("pid");
    ambiguous["bin_name"] = "fixture";
    std::size_t before = backend.calls;
    auto result = handlers.get_bytes(
        ambiguous, cancellation_token_t::create());
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED" &&
                        backend.calls == before,
                    "ambiguous_target", "ambiguous selector reached the backend");

    auto cancellation = cancellation_token_t::create();
    backend.cancel_during_dispatch = cancellation.state();
    result = handlers.get_bytes(valid_arguments("get_bytes"), cancellation);
    backend.cancel_during_dispatch.reset();
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_CANCELLED",
                    "memory_cancellation", "in-flight cancellation was not observed");

    backend.invalid_output = true;
    result = handlers.get_bytes(
        valid_arguments("get_bytes"), cancellation_token_t::create());
    backend.invalid_output = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    "memory_output_validation",
                    "response without a C12 snapshot receipt was accepted");
}

void verify_memory_handlers() {
    target_resolver_t resolver;
    effect_lock_manager_t locks;
    require(static_cast<bool>(resolver.publish(
                make_target(1U, 4101U, 0xA101ULL, "fixture-alpha.exe"))),
            "first memory handler target publication failed");
    require(static_cast<bool>(resolver.publish(
                make_target(2U, 4102U, 0xA102ULL, "fixture-beta.exe"))),
            "second memory handler target publication failed");
    require(static_cast<bool>(resolver.publish(
                make_target(3U, 4103U, 0xA103ULL, "fixture-live.exe", true))),
            "live memory handler target publication failed");

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
    protocol::schema_runtime_t schemas(64U);
    memory_handlers_t handlers(workspace, schemas);

    verify_contracts(handlers, schemas);
    verify_all_tool_dispatch(handlers, backend);
    verify_static_and_live_snapshots(handlers);
    verify_complete_read_contract(handlers, backend);
    verify_stale_generation(handlers, backend);
    verify_aggregate_bounds(workspace, schemas, backend);
    verify_integer_width_and_endian(handlers, backend);
    verify_reversible_overlays(handlers, backend);
    verify_live_write_denial(handlers, backend);
    verify_routing_and_failure_shapes(handlers, backend);
}

}

bool run_memory_handlers_harness(std::string& failure) {
    try {
        verify_memory_handlers();
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
