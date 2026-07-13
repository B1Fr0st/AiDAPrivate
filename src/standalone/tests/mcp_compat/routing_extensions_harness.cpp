#include "routing_extensions_harness.hpp"

#include "../../src/core/mcp/compat/handlers/routing_extensions.hpp"
#include "../../src/core/mcp/ida_compat_schemas.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace aida::standalone::tests::mcp_compat {

namespace {

using namespace aida::standalone::mcp::compat;
using namespace aida::standalone::mcp::compat::handlers;
using protocol::cancellation_token_t;
using protocol::json;

struct backend_state_t final {
    std::size_t query_calls = 0;
    std::size_t analyze_calls = 0;
    std::string last_contract;
    json last_arguments = json::object();
    std::uint32_t last_pid = 0;
    std::uint64_t last_target_id = 0;
    std::string last_bin_name;
    bool saw_deadline = false;
    std::uint64_t last_generation = 0;

    adapter_result_t<adapter_response_t> respond(
        const adapter_call_context_t& context,
        const adapter_request_t& request) {
        last_contract = context.contract == nullptr ? std::string() : std::string(context.contract->name);
        last_pid = context.target ? context.target->target().pid : 0;
        last_target_id = context.target ? context.target->target().target_id : 0;
        last_bin_name = context.target ? context.target->target().bin_name : std::string();
        last_generation = context.target ? context.target->target().generation : 0;
        saw_deadline = request.deadline.has_value() &&
            *request.deadline > std::chrono::steady_clock::now();
        last_arguments = json::parse(request.payload, nullptr, false);

        json output;
        if (context.contract != nullptr && context.contract->name == "analyze_funcs") {
            output = json{{"results", json::array({json{{"addr", "0x140001000"}, {"name", "main"}}})}};
        } else if (context.contract != nullptr && context.contract->name == "find_insns") {
            output = json{{"results", json::array({json{{"address", "0x140001000"}, {"text", "mov rax, [rbx]"}}})}};
        } else {
            output = json{{"result", "ok"}};
        }
        return adapter_result_t<adapter_response_t>::success({output.dump(), false});
    }

    std::size_t total_calls() const noexcept { return query_calls + analyze_calls; }
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
    const auto& names = routing_metadata_names();
    require(routing_metadata_count() == k_union_tool_count,
            "routing metadata count is not 92");
    require(inventory.size() == k_union_tool_count,
            "routing metadata inventory size is not 92");
    require(names.size() == k_union_tool_count,
            "routing metadata name ledger size is not 92");

    std::unordered_set<std::string> seen_names;
    for (std::size_t index = 0; index < inventory.size(); ++index) {
        const auto& meta = inventory[index];
        require(!meta.name.empty(), "routing metadata has an empty name");
        require(names[index] == meta.name,
                "routing metadata name ledger order differs from inventory");
        require(find_routing_metadata(names[index]) == &meta,
                "routing metadata name lookup is not inventory-stable");
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
        require(meta->read_only == (ext_name != "analyze_funcs"),
                "routing metadata extension mutability differs from retained behavior");
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

    for (const auto name : {std::string_view("calculator"), std::string_view("calculate")}) {
        const auto& contract = *extensions.find(name);
        require(contract.target_policy.requirement ==
                    protocol::target_requirement_t::independent &&
                    contract.effect_policy.effect == protocol::tool_effect_t::registry_read &&
                    contract.effect_policy.lock == protocol::effect_lock_t::registry_read &&
                    contract.effect_policy.read_only,
                "calculator extension effect policy is not registry_read");
    }

    const auto& af_contract = *extensions.find("analyze_funcs");
    require(af_contract.target_policy.requirement == protocol::target_requirement_t::optional,
            "analyze_funcs target policy is not optional");
    require(af_contract.target_policy.accepts_pid,
            "analyze_funcs does not accept pid");
    require(af_contract.effect_policy.effect ==
                protocol::tool_effect_t::workspace_overlay_mutation &&
            af_contract.effect_policy.lock ==
                protocol::effect_lock_t::workspace_overlay_transaction &&
            !af_contract.effect_policy.read_only,
            "analyze_funcs is not a retained workspace mutation");

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

    const auto* canonical_analyze = mcp_standalone::ida_compat::find_schema("analyze_funcs");
    const auto* canonical_find = mcp_standalone::ida_compat::find_schema("find_insns");
    const auto* canonical_calculate = mcp_standalone::ida_compat::find_schema("calculate");
    require(canonical_analyze != nullptr && canonical_find != nullptr &&
                canonical_calculate != nullptr,
            "canonical retained schemas are unavailable");
    require(af_contract.input_schema == *canonical_analyze,
            "analyze_funcs schema differs from the retained handler schema");
    require(fi_contract.input_schema == *canonical_find,
            "find_insns schema differs from the retained handler schema");
    require(extensions.find("calculator")->input_schema == *canonical_calculate &&
                extensions.find("calculate")->input_schema == *canonical_calculate,
            "calculator aliases differ from the retained calculate schema");
}

void verify_list_instances(routing_extensions_t& extensions, std::size_t& completed) {
    const json metadata{{"fixture_tool", "list_instances"}};
    json args = json::object();

    auto result = adapters::list_instances(extensions, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "list_instances", "valid", result.text());
    require_fixture(result.structured_content().contains("instances"),
                    "list_instances", "valid", "output missing instances array");
    const auto instances = result.structured_content().at("instances");
    require_fixture(instances.size() == 2, "list_instances", "valid",
                    "instance count does not match published targets");
    require_fixture(!result.structured_content().contains("count") &&
                        std::all_of(instances.begin(), instances.end(),
                            [](const auto& instance) {
                                return instance.is_object() && instance.size() == 2 &&
                                    instance.contains("pid") && instance.contains("bin_name");
                            }),
                    "list_instances", "valid",
                    "generated instance output contains extension fields");
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
    args["items"] = "0x140001000";
    args["dry_run"] = true;
    args["pid"] = 4101;

    auto result = adapters::analyze_funcs(extensions, args, cancellation_token_t::create(), {}, metadata);
    require_fixture(!result.is_error(), "analyze_funcs", "valid", result.text());
    require_fixture(backend.analyze_calls == 1, "analyze_funcs", "valid",
                    "analyze backend was not invoked exactly once");
    require_fixture(backend.last_contract == "analyze_funcs",
                    "analyze_funcs", "valid", "request reached the wrong contract");
    require_fixture(backend.last_pid == 4101,
                    "analyze_funcs", "valid", "target pid was not propagated");
    require_fixture(backend.last_bin_name == "fixture-routing.exe" &&
                        backend.last_generation == 9 && backend.saw_deadline,
                    "analyze_funcs", "valid",
                    "resolved target identity or bounded deadline was not propagated");
    require_fixture(backend.last_arguments == args,
                    "analyze_funcs", "valid", "canonical arguments were altered in routing");
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
    args["mnemonic"] = "mov";
    args["operand_pattern"] = "r*, [r*]";
    args["pid"] = 4101;
    args["limit"] = 100;

    auto result = adapters::find_insns(extensions, args, cancellation_token_t::create(), {}, metadata);
    require_fixture(!result.is_error(), "find_insns", "valid", result.text());
    require_fixture(backend.query_calls >= 1, "find_insns", "valid",
                    "query backend was not invoked");
    require_fixture(backend.last_contract == "find_insns",
                    "find_insns", "valid", "request reached the wrong contract");
    require_fixture(backend.last_arguments == args,
                    "find_insns", "valid", "canonical arguments were altered in routing");
    require_fixture(result.structured_content().contains("results"),
                    "find_insns", "valid", "output missing results array");
    ++completed;
}

void verify_calculator(routing_extensions_t& extensions, std::size_t& completed) {
    const json metadata{{"fixture_tool", "calculator"}};
    json args{{"format", "all"}};

    {
        args["expression"] = "0x1000 + 0x200";
        auto result = adapters::calculator(extensions, args, cancellation_token_t::create(), metadata);
        require_fixture(!result.is_error(), "calculator", "hex_add", result.text());
        const auto& sc = result.structured_content();
        require_fixture(sc.at("value").get<std::string>() == "0x1200",
                        "calculator", "hex_add", "canonical value is wrong");
        require_fixture(sc.at("decimal").get<std::string>() == "4608",
                        "calculator", "hex_add", "decimal result is wrong for 0x1000+0x200");
        require_fixture(sc.at("hex").get<std::string>() == "0x1200",
                        "calculator", "hex_add", "hex result is wrong for 0x1000+0x200");
    }
    {
        args["expression"] = "256 * 4 - 16";
        auto result = adapters::calculator(extensions, args, cancellation_token_t::create(), metadata);
        require_fixture(!result.is_error(), "calculator", "arith", result.text());
        require_fixture(result.structured_content().at("decimal").get<std::string>() == "1008",
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
        args["bits"] = 64;
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
    args["format"] = "decimal";

    auto result = adapters::calculate(extensions, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "calculate", "valid", result.text());
    require_fixture(result.structured_content().at("value").get<std::string>() == "128",
                    "calculate", "valid", "result is wrong for 1024/8");
    require_fixture(result.aida_metadata().value("tool", std::string()) == "calculate",
                    "calculate", "valid", "tool provenance is absent");
    require_fixture(result.aida_metadata().value("retained_handler", std::string()) ==
                        "mcp_standalone::ida_compat::tool_calculate",
                    "calculate", "valid", "retained handler provenance is absent");
    ++completed;
}

void verify_calculator_boundaries(routing_extensions_t& extensions,
                                  std::size_t& completed) {
    const json metadata{{"fixture_tool", "calculator"}};
    auto arbitrary_precision = adapters::calculator(
        extensions,
        json{{"expression", "(1 << 65) + 3"}, {"format", "decimal"}},
        cancellation_token_t::create(), metadata);
    require_fixture(!arbitrary_precision.is_error(),
                    "calculator", "arbitrary_precision", arbitrary_precision.text());
    require_fixture(arbitrary_precision.structured_content().at("value").get<std::string>() ==
                        "36893488147419103235",
                    "calculator", "arbitrary_precision",
                    "arbitrary-precision result was narrowed");

    auto scalar_item = adapters::calculate(
        extensions,
        json{{"items", json{{"id", "scalar"}, {"expression", "2 + 3"},
                             {"format", "decimal"}}}},
        cancellation_token_t::create(), metadata);
    require_fixture(!scalar_item.is_error(),
                    "calculate", "scalar_item", scalar_item.text());
    const auto& scalar_results = scalar_item.structured_content().at("results");
    require_fixture(scalar_results.size() == 1 &&
                        scalar_results[0].at("success").get<bool>() &&
                        scalar_results[0].at("id").get<std::string>() == "scalar" &&
                        scalar_results[0].at("result").at("value").get<std::string>() == "5",
                    "calculate", "scalar_item",
                    "scalar item did not retain the canonical batch envelope");

    json items = json::array();
    for (std::size_t index = 0; index < 128; ++index) {
        items.push_back(json{{"id", std::to_string(index)},
                             {"expression", "1 + 1"},
                             {"format", "decimal"}});
    }
    auto at_limit = adapters::calculator(
        extensions, json{{"items", items}}, cancellation_token_t::create(), metadata);
    require_fixture(!at_limit.is_error() &&
                        at_limit.structured_content().at("count").get<std::size_t>() == 128 &&
                        at_limit.structured_content().at("results").size() == 128,
                    "calculator", "items_128",
                    "canonical 128-item boundary was rejected");

    items.push_back(json{{"expression", "1 + 1"}, {"format", "decimal"}});
    auto over_limit = adapters::calculator(
        extensions, json{{"items", std::move(items)}},
        cancellation_token_t::create(), metadata);
    require_fixture(over_limit.is_error() &&
                        over_limit.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "calculator", "items_129",
                    "129-item boundary was not rejected canonically");
    ++completed;
}

void verify_calculator_alias_equivalence(routing_extensions_t& extensions,
                                         std::size_t& completed) {
    const json args{{"expression", "42 * 2"}, {"format", "decimal"}};
    auto calculator = adapters::calculator(
        extensions, args, cancellation_token_t::create());
    auto calculate = adapters::calculate(
        extensions, args, cancellation_token_t::create());
    require_fixture(!calculator.is_error() && !calculate.is_error(),
                    "calculator", "alias", "one calculator alias failed");
    require_fixture(calculator.structured_content() == calculate.structured_content() &&
                        calculator.structured_content().at("value").get<std::string>() == "84",
                    "calculator", "alias",
                    "calculator and calculate no longer preserve identical behavior");
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
                        "phase", std::string()) == "retained_calculator",
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

void verify_analyze_funcs_legacy_addrs_rejected(routing_extensions_t& extensions,
                                                backend_state_t& backend,
                                                std::size_t& completed) {
    const json metadata{{"fixture_tool", "analyze_funcs"}};
    json args{{"addrs", json::array({"0x140001000"})}, {"pid", 4101}};

    const std::size_t before = backend.total_calls();
    auto result = adapters::analyze_funcs(extensions, args, cancellation_token_t::create(), {}, metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "analyze_funcs", "legacy_addrs", "legacy addrs was not rejected");
    require_fixture(backend.total_calls() == before, "analyze_funcs", "legacy_addrs",
                    "legacy addrs reached the backend");
    ++completed;
}

void verify_find_insns_missing_mnemonic(routing_extensions_t& extensions,
                                        backend_state_t& backend,
                                        std::size_t& completed) {
    const json metadata{{"fixture_tool", "find_insns"}};
    json args = json::object();
    args["pid"] = 4101;

    const std::size_t before = backend.total_calls();
    auto result = adapters::find_insns(extensions, args, cancellation_token_t::create(), {}, metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "find_insns", "missing_mnemonic", "missing mnemonic was not rejected");
    require_fixture(backend.total_calls() == before, "find_insns", "missing_mnemonic",
                    "missing mnemonic reached the backend");
    ++completed;
}

void verify_no_ui_switch_routing(routing_extensions_t& extensions,
                                 backend_state_t& backend,
                                 std::size_t& completed) {
    const std::uint64_t ui_selected_target_id = 1;
    const json args{
        {"mnemonic", "call"},
        {"limit", 10},
        {"pid", 4102},
    };
    auto result = adapters::find_insns(
        extensions, args, cancellation_token_t::create());
    require_fixture(!result.is_error(), "find_insns", "no_ui_switch", result.text());
    require_fixture(backend.last_target_id == 2 && backend.last_pid == 4102 &&
                        backend.last_target_id != ui_selected_target_id &&
                        backend.last_arguments == args,
                    "find_insns", "no_ui_switch",
                    "explicit target routing depended on the UI-selected target");
    ++completed;
}

void verify_list_instances_retired_semantics(routing_extensions_t& extensions,
                                             target_resolver_t& resolver,
                                             std::size_t& completed) {
    require(static_cast<bool>(resolver.publish(
                make_target(3, 4103, 0xA103ULL, "retired-fixture.exe"))),
            "retired routing extension target publication failed");
    auto captured = adapters::list_instances(
        extensions, json::object(), cancellation_token_t::create());
    require_fixture(!captured.is_error() &&
                        captured.structured_content().at("instances").size() == 3,
                    "list_instances", "retired_capture",
                    "new target was not captured before retirement");
    require(static_cast<bool>(resolver.retire(3)),
            "routing extension target retirement failed");

    auto active_only = adapters::list_instances(
        extensions, json::object(), cancellation_token_t::create());
    require_fixture(!active_only.is_error() &&
                        active_only.structured_content().at("instances").size() == 2,
                    "list_instances", "retired_default",
                    "retired target leaked into the default listing");

    auto including_retired = adapters::list_instances(
        extensions, json{{"include_retired", true}}, cancellation_token_t::create());
    require_fixture(!including_retired.is_error() &&
                        including_retired.structured_content().at("instances").size() == 3,
                    "list_instances", "retired_included",
                    "include_retired did not restore the retired identity");
    bool found_retired = false;
    for (const auto& instance :
         including_retired.aida_metadata().at("instance_identities")) {
        if (instance.at("target_id").get<std::uint64_t>() == 3) {
            found_retired = instance.at("retired").get<bool>() &&
                instance.at("pid").get<std::uint32_t>() == 4103;
        }
    }
    require_fixture(found_retired &&
                        including_retired.aida_metadata().value("include_retired", false),
                    "list_instances", "retired_included",
                    "retired target identity or provenance is inconsistent");
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
    args["items"] = "0x140001000";
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
    routing_extension_workspace_handlers_t workspace_handlers;
    workspace_handlers.analyze_funcs = [&backend](const adapter_call_context_t& context,
                                                  const adapter_request_t& request) {
        ++backend.analyze_calls;
        return backend.respond(context, request);
    };
    workspace_handlers.find_insns = [&backend](const adapter_call_context_t& context,
                                               const adapter_request_t& request) {
        ++backend.query_calls;
        return backend.respond(context, request);
    };
    protocol::schema_runtime_t schemas(64);
    routing_extensions_t extensions(
        resolver, locks, std::move(workspace_handlers), schemas);

    verify_extension_contracts(extensions, schemas);

    std::size_t completed = 0;

    verify_list_instances(extensions, completed);
    verify_list_instances_filter(extensions, completed);
    verify_analyze_funcs(extensions, backend, completed);
    verify_find_insns(extensions, backend, completed);
    verify_no_ui_switch_routing(extensions, backend, completed);
    verify_calculator(extensions, completed);
    verify_calculate(extensions, completed);
    verify_calculator_boundaries(extensions, completed);
    verify_calculator_alias_equivalence(extensions, completed);
    verify_calculator_division_by_zero(extensions, completed);
    verify_calculator_empty_expression(extensions, completed);
    verify_analyze_funcs_legacy_addrs_rejected(extensions, backend, completed);
    verify_find_insns_missing_mnemonic(extensions, backend, completed);
    verify_cancellation_list_instances(extensions, completed);
    verify_cancellation_calculator(extensions, completed);
    verify_cancellation_analyze_funcs(extensions, completed);
    verify_list_instances_retired_semantics(extensions, resolver, completed);

    require(completed == 17,
            "routing extensions harness did not execute all seventeen fixture families");
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
