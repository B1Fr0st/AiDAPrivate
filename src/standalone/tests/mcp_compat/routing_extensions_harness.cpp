#include "routing_extensions_harness.hpp"

#include "../../src/core/mcp/compat/handlers/routing_extensions.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida::standalone::tests::mcp_compat {

namespace {

using namespace aida::standalone::mcp::compat;
using namespace aida::standalone::mcp::compat::handlers;
using protocol::cancellation_token_t;
using protocol::json;

struct backend_state_t final {
    std::size_t query_calls = 0;
    std::size_t analyze_calls = 0;
    std::size_t overlay_calls = 0;
    bool invalid_output = false;
    bool empty_output = false;
    bool oversized_output = false;
    std::size_t oversized_size = 0;
    std::string last_contract;
    json last_arguments = json::object();
    std::uint32_t last_pid = 0;
    std::string last_bin_name;
    bool saw_deadline = false;
    std::uint64_t last_generation = 0;
    std::shared_ptr<std::atomic_bool> cancel_during_dispatch;
    json custom_output;

    adapter_result_t<adapter_response_t> respond(
        const adapter_call_context_t& context,
        const adapter_request_t& request) {
        last_contract = context.contract == nullptr ? std::string() : std::string(context.contract->name);
        last_pid = context.target ? context.target->target().pid : 0;
        last_bin_name = context.target ? context.target->target().bin_name : std::string();
        last_generation = context.target ? context.target->target().generation : 0;
        saw_deadline = request.deadline.has_value() &&
            *request.deadline > std::chrono::steady_clock::now();
        last_arguments = json::parse(request.payload, nullptr, false);
        if (cancel_during_dispatch) {
            cancel_during_dispatch->store(true, std::memory_order_release);
        }

        if (empty_output) {
            return adapter_result_t<adapter_response_t>::success({{}, false});
        }
        if (oversized_output) {
            std::string huge(oversized_size > 0 ? oversized_size : 17 * 1024 * 1024, 'Z');
            return adapter_result_t<adapter_response_t>::success({std::move(huge), false});
        }
        if (!custom_output.is_null()) {
            return adapter_result_t<adapter_response_t>::success({custom_output.dump(), false});
        }

        if (invalid_output) {
            return adapter_result_t<adapter_response_t>::success({"not_json", false});
        }

        json output;
        if (context.contract != nullptr && context.contract->name == "analyze_funcs") {
            output = json{{"results", json::array({json{{"addr", "0x140001000"}, {"name", "main"}}})}};
        } else if (context.contract != nullptr && context.contract->name == "find_insns") {
            output = json{{"matches", json::array({json{{"addr", "0x140001000"}, {"mnem", "mov"}}})}};
        } else {
            output = json{{"result", "ok"}};
        }
        return adapter_result_t<adapter_response_t>::success({output.dump(), false});
    }

    std::size_t total_calls() const noexcept { return query_calls + analyze_calls + overlay_calls; }
};

void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void require_fixture(bool condition, std::string_view tool, std::string_view category,
                     std::string_view detail) {
    if (!condition) {
        throw std::runtime_error(
            std::string(tool) + " " + std::string(category) + " fixture: " + std::string(detail));
    }
}

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

void verify_routing_metadata_inventory() {
    const auto& inventory = routing_metadata_inventory();
    require(routing_metadata_count() == k_union_tool_count,
            "routing metadata count is not 92");
    require(inventory.size() == k_union_tool_count,
            "routing metadata inventory size is not 92");

    std::unordered_set<std::string> seen_names;
    for (const auto& meta : inventory) {
        require(!meta.name.empty(), "routing metadata has an empty name");
        const auto [iter, inserted] = seen_names.insert(meta.name);
        require(inserted, "routing metadata has a duplicate name");
    }

    const auto* archive = aida::standalone::mcp::compat::contracts();
    const std::size_t archive_count = aida::standalone::mcp::compat::contract_count();
    require(archive_count == k_archive_tool_count,
            "archive contract count does not match pinned constant");
    require(archive_count + k_aida_extension_count == k_union_tool_count,
            "archive count plus extension count does not equal union count");

    for (std::size_t index = 0; index < archive_count; ++index) {
        const auto& descriptor = archive[index];
        const auto* meta = find_routing_metadata(descriptor.name);
        require(meta != nullptr, "routing metadata is missing an archive tool name");
        require(meta->archive_backed, "routing metadata for archive tool is not archive_backed");
        require(!meta->is_extension, "routing metadata for archive tool is marked as extension");
        require(meta->accepts_pid == descriptor.accepts_pid,
                "routing metadata accepts_pid mismatch for archive tool");
        require(meta->accepts_bin_name == descriptor.accepts_bin_name,
                "routing metadata accepts_bin_name mismatch for archive tool");
        require(meta->read_only == descriptor.read_only,
                "routing metadata read_only mismatch for archive tool");
        require(meta->unsafe == descriptor.unsafe,
                "routing metadata unsafe mismatch for archive tool");
    }

    for (const auto ext_name : k_aida_extension_names) {
        const auto* meta = find_routing_metadata(ext_name);
        require(meta != nullptr, "routing metadata is missing an extension tool name");
        require(!meta->archive_backed, "routing metadata for extension tool is archive_backed");
        require(meta->is_extension, "routing metadata for extension tool is not marked as extension");
        require(meta->read_only, "routing metadata for extension tool is not read_only");
        require(!meta->unsafe, "routing metadata for extension tool is unsafe");
    }

    require(find_routing_metadata("nonexistent_tool_name") == nullptr,
            "find_routing_metadata should return nullptr for unknown name");
}

void verify_extension_contracts(const routing_extensions_t& extensions,
                                protocol::schema_runtime_t& schemas) {
    require(extensions.size() == k_routing_extension_tool_count,
            "routing extension contract count is not five");
    require(routing_extension_tool_names().size() == k_routing_extension_tool_count,
            "routing extension name ledger count is not five");

    for (std::size_t index = 0; index < k_routing_extension_tool_count; ++index) {
        const auto name = routing_extension_tool_names()[index];
        const auto& contract = extensions.contract_at(index);
        require(contract.name == name && extensions.find(name) == &contract,
                "routing extension lookup differs from the exact name ledger");
        require(!contract.effect_policy.unsafe,
                "routing extension effect policy must not be unsafe");
        require(protocol::validate_tool_contract(contract, schemas).valid,
                "routing extension contract does not validate through the schema runtime");
        const json list_entry = contract.tool_list_entry();
        require(list_entry.at("inputSchema") == contract.input_schema &&
                    list_entry.at("outputSchema") == contract.output_schema &&
                    !list_entry.contains("_meta"),
                "routing extension tool list entry altered schema or embedded provenance");
    }

    const auto& li_contract = *extensions.find("list_instances");
    require(li_contract.target_policy.requirement == protocol::target_requirement_t::independent,
            "list_instances target policy is not independent");
    require(li_contract.effect_policy.effect == protocol::tool_effect_t::registry_read,
            "list_instances effect is not registry_read");
    require(li_contract.effect_policy.read_only,
            "list_instances is not read_only");

    const auto& af_contract = *extensions.find("analyze_funcs");
    require(af_contract.target_policy.requirement == protocol::target_requirement_t::optional,
            "analyze_funcs target policy is not optional");
    require(af_contract.target_policy.accepts_pid,
            "analyze_funcs does not accept pid");
    require(af_contract.effect_policy.read_only,
            "analyze_funcs is not read_only");

    const auto& fi_contract = *extensions.find("find_insns");
    require(fi_contract.target_policy.requirement == protocol::target_requirement_t::optional,
            "find_insns target policy is not optional");
    require(fi_contract.target_policy.accepts_pid,
            "find_insns does not accept pid");
    require(fi_contract.effect_policy.read_only,
            "find_insns is not read_only");

    for (const auto calc_name : {"calculator", "calculate"}) {
        const auto& calc_contract = *extensions.find(calc_name);
        require(calc_contract.target_policy.requirement == protocol::target_requirement_t::independent,
                "calculator target policy is not independent");
        require(calc_contract.effect_policy.read_only,
                "calculator is not read_only");
    }
}

void verify_list_instances(routing_extensions_t& extensions, target_resolver_t& resolver,
                           std::size_t& completed) {
    const json metadata{{"fixture_tool", "list_instances"}};
    json args = json::object();

    auto result = adapters::list_instances(extensions, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "list_instances", "valid", result.text());
    require_fixture(result.structured_content().contains("instances"),
                    "list_instances", "valid", "output missing instances array");
    require_fixture(result.structured_content().contains("count"),
                    "list_instances", "valid", "output missing count field");
    const auto count = result.structured_content().at("count").get<std::size_t>();
    const auto instances = result.structured_content().at("instances");
    require_fixture(instances.size() == 2, "list_instances", "valid",
                    "instance count does not match published targets");
    require_fixture(count == 2, "list_instances", "valid",
                    "count field does not match instance array size");
    ++completed;
}

void verify_list_instances_filter(routing_extensions_t& extensions,
                                  std::size_t& completed) {
    const json metadata{{"fixture_tool", "list_instances"}};
    json args = json::object();
    args["filter"] = "beta";

    auto result = adapters::list_instances(extensions, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "list_instances", "filter", result.text());
    const auto instances = result.structured_content().at("instances");
    require_fixture(instances.size() == 1, "list_instances", "filter",
                    "filter did not narrow to one target");
    require_fixture(instances[0].at("bin_name").get<std::string>() == "fixture-beta.exe",
                    "list_instances", "filter", "filtered target is not fixture-beta.exe");
    ++completed;
}

void verify_analyze_funcs(routing_extensions_t& extensions, backend_state_t& backend,
                          std::size_t& completed) {
    const json metadata{{"fixture_tool", "analyze_funcs"}};
    json args = json::object();
    args["addrs"] = json::array({"0x140001000"});
    args["pid"] = 4101;

    const std::size_t before = backend.total_calls();
    auto result = adapters::analyze_funcs(extensions, args, cancellation_token_t::create(), {}, metadata);
    require_fixture(!result.is_error(), "analyze_funcs", "valid", result.text());
    require_fixture(backend.analyze_calls == 1, "analyze_funcs", "valid",
                    "analyze backend was not invoked exactly once");
    require_fixture(backend.last_contract == "analyze_funcs",
                    "analyze_funcs", "valid", "request reached the wrong contract");
    require_fixture(backend.last_pid == 4101,
                    "analyze_funcs", "valid", "target pid was not propagated");
    require_fixture(result.structured_content().contains("results"),
                    "analyze_funcs", "valid", "output missing results array");
    require_fixture(result.aida_metadata().value("tool", std::string()) == "analyze_funcs",
                    "analyze_funcs", "valid", "tool provenance is absent");
    ++completed;
}

void verify_find_insns(routing_extensions_t& extensions, backend_state_t& backend,
                       std::size_t& completed) {
    const json metadata{{"fixture_tool", "find_insns"}};
    json args = json::object();
    args["mnem"] = "mov";
    args["pid"] = 4101;
    args["limit"] = 100;

    const std::size_t before = backend.total_calls();
    auto result = adapters::find_insns(extensions, args, cancellation_token_t::create(), {}, metadata);
    require_fixture(!result.is_error(), "find_insns", "valid", result.text());
    require_fixture(backend.query_calls >= 1, "find_insns", "valid",
                    "query backend was not invoked");
    require_fixture(backend.last_contract == "find_insns",
                    "find_insns", "valid", "request reached the wrong contract");
    require_fixture(result.structured_content().contains("matches"),
                    "find_insns", "valid", "output missing matches array");
    ++completed;
}

void verify_calculator(routing_extensions_t& extensions, std::size_t& completed) {
    const json metadata{{"fixture_tool", "calculator"}};
    json args = json::object();

    {
        args["expression"] = "0x1000 + 0x200";
        auto result = adapters::calculator(extensions, args, cancellation_token_t::create(), metadata);
        require_fixture(!result.is_error(), "calculator", "hex_add", result.text());
        const auto& sc = result.structured_content();
        require_fixture(sc.at("result").is_string(), "calculator", "hex_add",
                        "result is not a string");
        require_fixture(sc.at("decimal").get<std::string>() == "4608",
                        "calculator", "hex_add", "decimal result is wrong for 0x1000+0x200");
        require_fixture(sc.at("hex").get<std::string>() == "0x1200",
                        "calculator", "hex_add", "hex result is wrong for 0x1000+0x200");
    }
    {
        args["expression"] = "256 * 4 - 16";
        auto result = adapters::calculator(extensions, args, cancellation_token_t::create(), metadata);
        require_fixture(!result.is_error(), "calculator", "arith", result.text());
        require_fixture(result.structured_content().at("result").get<std::string>() == "1008",
                        "calculator", "arith", "result is wrong for 256*4-16");
    }
    {
        args["expression"] = "(0xFF & 0x0F) | (0xF0 << 4)";
        auto result = adapters::calculator(extensions, args, cancellation_token_t::create(), metadata);
        require_fixture(!result.is_error(), "calculator", "bitwise", result.text());
        require_fixture(result.structured_content().at("hex").get<std::string>() == "0xf0f",
                        "calculator", "bitwise", "hex result is wrong for bitwise expression");
    }
    {
        args["expression"] = "0b1010 ^ 0b0101";
        auto result = adapters::calculator(extensions, args, cancellation_token_t::create(), metadata);
        require_fixture(!result.is_error(), "calculator", "binary", result.text());
        require_fixture(result.structured_content().at("decimal").get<std::string>() == "15",
                        "calculator", "binary", "decimal result is wrong for 0b1010^0b0101");
    }
    {
        args["expression"] = "~0";
        auto result = adapters::calculator(extensions, args, cancellation_token_t::create(), metadata);
        require_fixture(!result.is_error(), "calculator", "not", result.text());
        require_fixture(result.structured_content().at("hex").get<std::string>() ==
                        "0xffffffffffffffff",
                        "calculator", "not", "hex result is wrong for ~0");
    }
    ++completed;
}

void verify_calculate(routing_extensions_t& extensions, std::size_t& completed) {
    const json metadata{{"fixture_tool", "calculate"}};
    json args = json::object();
    args["expression"] = "1024 / 8";

    auto result = adapters::calculate(extensions, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "calculate", "valid", result.text());
    require_fixture(result.structured_content().at("result").get<std::string>() == "128",
                    "calculate", "valid", "result is wrong for 1024/8");
    require_fixture(result.aida_metadata().value("tool", std::string()) == "calculate",
                    "calculate", "valid", "tool provenance is absent");
    require_fixture(result.aida_metadata().value("local_computation", false) == true,
                    "calculate", "valid", "local_computation metadata is absent");
    ++completed;
}

void verify_calculator_division_by_zero(routing_extensions_t& extensions,
                                        std::size_t& completed) {
    const json metadata{{"fixture_tool", "calculator"}};
    json args = json::object();
    args["expression"] = "1 / 0";

    auto result = adapters::calculator(extensions, args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "calculator", "div_zero", "division by zero was not rejected");
    require_fixture(result.structured_content().at("error").at("details").value(
                        "phase", std::string()) == "calculator_eval",
                    "calculator", "div_zero", "phase evidence is absent");
    ++completed;
}

void verify_calculator_empty_expression(routing_extensions_t& extensions,
                                        std::size_t& completed) {
    const json metadata{{"fixture_tool", "calculator"}};
    json args = json::object();
    args["expression"] = "";

    auto result = adapters::calculator(extensions, args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "calculator", "empty_expr", "empty expression was not rejected");
    ++completed;
}

void verify_analyze_funcs_missing_addrs(routing_extensions_t& extensions,
                                        backend_state_t& backend,
                                        std::size_t& completed) {
    const json metadata{{"fixture_tool", "analyze_funcs"}};
    json args = json::object();
    args["pid"] = 4101;

    const std::size_t before = backend.total_calls();
    auto result = adapters::analyze_funcs(extensions, args, cancellation_token_t::create(), {}, metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "analyze_funcs", "missing_addrs", "missing addrs was not rejected");
    require_fixture(backend.total_calls() == before, "analyze_funcs", "missing_addrs",
                    "missing addrs reached the backend");
    ++completed;
}

void verify_find_insns_missing_mnem(routing_extensions_t& extensions,
                                    backend_state_t& backend,
                                    std::size_t& completed) {
    const json metadata{{"fixture_tool", "find_insns"}};
    json args = json::object();
    args["pid"] = 4101;

    const std::size_t before = backend.total_calls();
    auto result = adapters::find_insns(extensions, args, cancellation_token_t::create(), {}, metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "find_insns", "missing_mnem", "missing mnem was not rejected");
    require_fixture(backend.total_calls() == before, "find_insns", "missing_mnem",
                    "missing mnem reached the backend");
    ++completed;
}

void verify_cancellation_list_instances(routing_extensions_t& extensions,
                                        std::size_t& completed) {
    const json metadata{{"fixture_tool", "list_instances"}};
    auto cancellation = cancellation_token_t::create();
    cancellation.cancel();

    auto result = adapters::list_instances(extensions, json::object(), cancellation, metadata);
    require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                    "list_instances", "cancellation",
                    "pre-dispatch cancellation was not observed canonically");
    ++completed;
}

void verify_cancellation_calculator(routing_extensions_t& extensions,
                                    std::size_t& completed) {
    const json metadata{{"fixture_tool", "calculator"}};
    auto cancellation = cancellation_token_t::create();
    cancellation.cancel();

    json args = json::object();
    args["expression"] = "1+1";
    auto result = adapters::calculator(extensions, args, cancellation, metadata);
    require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                    "calculator", "cancellation",
                    "pre-eval cancellation was not observed canonically");
    ++completed;
}

void verify_cancellation_analyze_funcs(routing_extensions_t& extensions,
                                       std::size_t& completed) {
    const json metadata{{"fixture_tool", "analyze_funcs"}};
    auto cancellation = cancellation_token_t::create();
    cancellation.cancel();

    json args = json::object();
    args["addrs"] = json::array({"0x140001000"});
    args["pid"] = 4101;
    auto result = adapters::analyze_funcs(extensions, args, cancellation, {}, metadata);
    require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                    "analyze_funcs", "cancellation",
                    "pre-dispatch cancellation was not observed canonically");
    ++completed;
}

void verify_extension_metadata_lanes() {
    const auto* af_meta = find_routing_metadata("analyze_funcs");
    require(af_meta != nullptr, "routing metadata for analyze_funcs is missing");
    require(af_meta->lane == extension_lane_t::workspace_analysis,
            "analyze_funcs lane is not workspace_analysis");

    const auto* fi_meta = find_routing_metadata("find_insns");
    require(fi_meta != nullptr, "routing metadata for find_insns is missing");
    require(fi_meta->lane == extension_lane_t::workspace_instruction_scan,
            "find_insns lane is not workspace_instruction_scan");

    const auto* calc_meta = find_routing_metadata("calculator");
    require(calc_meta != nullptr, "routing metadata for calculator is missing");
    require(calc_meta->lane == extension_lane_t::local_calculator,
            "calculator lane is not local_calculator");

    const auto* calc2_meta = find_routing_metadata("calculate");
    require(calc2_meta != nullptr, "routing metadata for calculate is missing");
    require(calc2_meta->lane == extension_lane_t::local_calculator,
            "calculate lane is not local_calculator");
}

void verify_routing_extensions() {
    verify_routing_metadata_inventory();
    verify_extension_metadata_lanes();

    target_resolver_t resolver;
    effect_lock_manager_t locks;
    require(static_cast<bool>(resolver.publish(
                make_target(1, 4101, 0xA101ULL, "fixture-routing.exe"))),
            "first routing extension target publication failed");
    require(static_cast<bool>(resolver.publish(
                make_target(2, 4102, 0xA102ULL, "fixture-beta.exe"))),
            "second routing extension target publication failed");

    backend_state_t backend;
    workspace_adapter_handlers_t workspace_handlers;
    workspace_handlers.query = [&backend](const adapter_call_context_t& context,
                                          const adapter_request_t& request) {
        ++backend.query_calls;
        return backend.respond(context, request);
    };
    workspace_handlers.analyze = [&backend](const adapter_call_context_t& context,
                                            const adapter_request_t& request) {
        ++backend.analyze_calls;
        return backend.respond(context, request);
    };
    workspace_handlers.overlay = [&backend](const adapter_call_context_t& context,
                                            const adapter_request_t& request) {
        ++backend.overlay_calls;
        return backend.respond(context, request);
    };
    workspace_adapter_t workspace(resolver, locks, std::move(workspace_handlers));
    protocol::schema_runtime_t schemas(64);
    routing_extensions_t extensions(resolver, workspace, schemas);

    verify_extension_contracts(extensions, schemas);

    std::size_t completed = 0;

    verify_list_instances(extensions, resolver, completed);
    verify_list_instances_filter(extensions, completed);
    verify_analyze_funcs(extensions, backend, completed);
    verify_find_insns(extensions, backend, completed);
    verify_calculator(extensions, completed);
    verify_calculate(extensions, completed);
    verify_calculator_division_by_zero(extensions, completed);
    verify_calculator_empty_expression(extensions, completed);
    verify_analyze_funcs_missing_addrs(extensions, backend, completed);
    verify_find_insns_missing_mnem(extensions, backend, completed);
    verify_cancellation_list_instances(extensions, completed);
    verify_cancellation_calculator(extensions, completed);
    verify_cancellation_analyze_funcs(extensions, completed);

    require(completed == 13,
            "routing extensions harness did not execute all thirteen fixture families");
}

}

bool run_routing_extensions_harness(std::string& failure) {
    try {
        verify_routing_extensions();
    } catch (const std::exception& error) {
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
