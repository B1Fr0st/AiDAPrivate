#include "type_handlers_harness.hpp"

#include "../../src/core/mcp/compat/handlers/types.hpp"

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

json routed(json arguments) {
    arguments["pid"] = 4101;
    return arguments;
}

struct test_env_t {
    target_resolver_t resolver;
    effect_lock_manager_t locks;
    types_overlay_store_t overlay_store;
    workspace_adapter_handlers_t workspace_handlers;
    std::unique_ptr<workspace_adapter_t> workspace;
    std::unique_ptr<protocol::schema_runtime_t> schemas;
    std::unique_ptr<types_handlers_t> handlers;

    test_env_t() {
        require(static_cast<bool>(resolver.publish(
                    make_target(1, 4101, 0xA101ULL, "fixture-types.exe"))),
                "first types handler target publication failed");
        require(static_cast<bool>(resolver.publish(
                    make_target(2, 4102, 0xA102ULL, "fixture-beta.exe"))),
                "second types handler target publication failed");

        workspace_handlers.query = [this](const adapter_call_context_t& context,
                                           const adapter_request_t& request) {
            return overlay_store.handle_query(context, request);
        };
        workspace_handlers.overlay = [this](const adapter_call_context_t& context,
                                            const adapter_request_t& request) {
            return overlay_store.handle_overlay(context, request);
        };
        workspace = std::make_unique<workspace_adapter_t>(
            resolver, locks, std::move(workspace_handlers));
        schemas = std::make_unique<protocol::schema_runtime_t>(64);
        handlers = std::make_unique<types_handlers_t>(*workspace, *schemas);
    }
};

void verify_contracts(const types_handlers_t& handlers,
                      protocol::schema_runtime_t& schemas) {
    require(handlers.size() == k_types_tool_count,
            "types handler contract count is not exactly nine");
    require(types_tool_names().size() == k_types_tool_count,
            "types name ledger count is not exactly nine");
    for (std::size_t index = 0; index < k_types_tool_count; ++index) {
        const auto name = types_tool_names()[index];
        const auto* descriptor = aida::standalone::mcp::compat::find_contract(name);
        const auto& contract = handlers.contract_at(index);
        require(descriptor != nullptr, "types generated descriptor is missing");
        require(contract.name == name && handlers.find(name) == &contract,
                "types handler lookup differs from the exact name ledger");
        require(descriptor->adapter_symbol ==
                    "aida::standalone::mcp::compat::adapters::" + std::string(name),
                "types generated adapter symbol differs from the linked function name");
        require(contract.description == descriptor->description,
                "types generated description was not preserved");
        require(contract.input_schema == json::parse(
                    descriptor->input_schema_json.begin(), descriptor->input_schema_json.end()) &&
                    contract.output_schema == json::parse(
                    descriptor->output_schema_json.begin(), descriptor->output_schema_json.end()) &&
                    contract.annotations == json::parse(
                    descriptor->annotations_json.begin(), descriptor->annotations_json.end()),
                "types generated schema or annotations were not preserved");
        require(contract.target_policy.requirement == protocol::target_requirement_t::optional &&
                    contract.target_policy.accepts_pid &&
                    contract.target_policy.accepts_bin_name,
                "types target routing policy is not the generated optional selector policy");
        require(!contract.effect_policy.unsafe,
                "types effect policy must not be unsafe");
        require(protocol::validate_tool_contract(contract, schemas).valid,
                "types generated contract does not validate through the schema runtime");
        const json list_entry = contract.tool_list_entry();
        require(list_entry.at("inputSchema") == contract.input_schema &&
                    list_entry.at("outputSchema") == contract.output_schema &&
                    !list_entry.contains("_meta"),
                "types tool list entry altered schema or embedded provenance");
    }
}

void verify_lane_policies(const types_handlers_t& handlers) {
    for (std::size_t index = 0; index < k_types_tool_count; ++index) {
        const auto name = types_tool_names()[index];
        const auto& contract = handlers.contract_at(index);
        if (name == "read_struct" || name == "search_structs" ||
            name == "type_query" || name == "type_inspect" || name == "infer_types") {
            require(contract.effect_policy.effect == protocol::tool_effect_t::workspace_read &&
                        contract.effect_policy.lock == protocol::effect_lock_t::workspace_shared &&
                        contract.effect_policy.read_only,
                    "types read tool effect policy is not generated shared workspace read");
        } else {
            require(contract.effect_policy.effect == protocol::tool_effect_t::workspace_overlay_mutation &&
                        contract.effect_policy.lock == protocol::effect_lock_t::workspace_overlay_transaction &&
                        !contract.effect_policy.read_only,
                    "types mutation tool effect policy is not generated overlay transaction");
        }
    }
}

void fixture_recursive_type(test_env_t& env, std::size_t& completed) {
    const json metadata{{"fixture_tool", "declare_type"}};
    const std::string decl = "struct LIST_NODE { int data; LIST_NODE* next; };";
    json args = routed({{"decls", json::array({decl})}});

    auto result = adapters::declare_type(*env.handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "declare_type", "recursive_type", result.text());
    const auto& sc = result.structured_content();
    require_fixture(sc.contains("result"), "declare_type", "recursive_type", "result array missing");
    require_fixture(sc["result"].size() == 1, "declare_type", "recursive_type", "result array size");
    require_fixture(sc["result"][0].value("error", "x") == "", "declare_type", "recursive_type", "parse error");

    require_fixture(env.overlay_store.has_type("LIST_NODE"), "declare_type", "recursive_type",
                    "LIST_NODE not in overlay store");
    const auto* type = env.overlay_store.find_type("LIST_NODE");
    require_fixture(type != nullptr, "declare_type", "recursive_type", "find_type returned null");
    require_fixture(type->is_udt, "declare_type", "recursive_type", "not marked as UDT");
    require_fixture(type->members.size() == 2, "declare_type", "recursive_type",
                    "member count should be 2");
    require_fixture(type->members[0].name == "data", "declare_type", "recursive_type",
                    "first member name should be data");
    require_fixture(type->members[0].offset == 0, "declare_type", "recursive_type",
                    "data offset should be 0");
    require_fixture(type->members[0].size == 4, "declare_type", "recursive_type",
                    "data size should be 4");
    require_fixture(type->members[1].name == "next", "declare_type", "recursive_type",
                    "second member name should be next");
    require_fixture(type->members[1].offset == 8, "declare_type", "recursive_type",
                    "next offset should be 8 (pointer alignment)");
    require_fixture(type->members[1].size == 8, "declare_type", "recursive_type",
                    "next size should be 8");
    require_fixture(type->size == 16, "declare_type", "recursive_type",
                    "struct size should be 16");
    ++completed;
}

void fixture_conflicting_type(test_env_t& env, std::size_t& completed) {
    const json metadata{{"fixture_tool", "declare_type"}};
    const std::string decl1 = "struct CONFLICT { DWORD a; DWORD b; };";
    const std::string decl2 = "struct CONFLICT { PVOID a; PVOID b; PVOID c; };";

    auto r1 = adapters::declare_type(*env.handlers, routed({{"decls", json::array({decl1})}}),
                                      cancellation_token_t::create(), metadata);
    require_fixture(!r1.is_error(), "declare_type", "conflicting_type", "first declare failed");
    const auto* type1 = env.overlay_store.find_type("CONFLICT");
    require_fixture(type1 != nullptr && type1->size == 8, "declare_type", "conflicting_type",
                    "first CONFLICT size should be 8");

    auto r2 = adapters::declare_type(*env.handlers, routed({{"decls", json::array({decl2})}}),
                                      cancellation_token_t::create(), metadata);
    require_fixture(!r2.is_error(), "declare_type", "conflicting_type", "second declare failed");
    const auto* type2 = env.overlay_store.find_type("CONFLICT");
    require_fixture(type2 != nullptr && type2->size == 24, "declare_type", "conflicting_type",
                    "second CONFLICT size should be 24 (3 pointers)");
    require_fixture(type2->members.size() == 3, "declare_type", "conflicting_type",
                    "second CONFLICT should have 3 members");
    require_fixture(type2->members[0].name == "a", "declare_type", "conflicting_type",
                    "first member should be a");
    require_fixture(type2->members[0].size == 8, "declare_type", "conflicting_type",
                    "first member size should be 8 (PVOID)");
    ++completed;
}

void fixture_invalid_declaration(test_env_t& env, std::size_t& completed) {
    const json metadata{{"fixture_tool", "declare_type"}};
    const std::string bad_decl = "this is not a valid C declaration";
    auto result = adapters::declare_type(*env.handlers, routed({{"decls", json::array({bad_decl})}}),
                                          cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "declare_type", "invalid_decl", "tool should not error");
    const auto& sc = result.structured_content();
    require_fixture(sc["result"][0].value("error", "") != "", "declare_type", "invalid_decl",
                    "parse error should be non-empty for invalid declaration");
    require_fixture(sc["result"][0].value("decl", "") == bad_decl, "declare_type", "invalid_decl",
                    "decl should be echoed back");

    const std::string empty_decl = "";
    auto r2 = adapters::declare_type(*env.handlers, routed({{"decls", json::array({empty_decl})}}),
                                      cancellation_token_t::create(), metadata);
    require_fixture(!r2.is_error(), "declare_type", "invalid_decl", "empty decl tool should not error");
    require_fixture(r2.structured_content()["result"][0].value("error", "") != "",
                    "declare_type", "invalid_decl", "empty decl should have error");
    ++completed;
}

void fixture_batch_rollback(test_env_t& env, std::size_t& completed) {
    const std::uint64_t rev_before = env.overlay_store.revision();
    const json metadata{{"fixture_tool", "type_apply_batch"}};

    json batch = json::object();
    batch["stop_on_error"] = true;
    batch["edits"] = json::array({
        json{{"addr", "0x140001000"}, {"ty", "DWORD"}},
        json{{"addr", "0x140001001"}, {"ty", ""}, {"signature", ""}, {"name", ""}, {"variable", ""}},
        json{{"addr", "0x140002000"}, {"ty", "PVOID"}},
    });

    auto result = adapters::type_apply_batch(*env.handlers, routed({{"batch", batch}}),
                                              cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "type_apply_batch", "rollback", result.text());
    const auto& sc = result.structured_content();
    require_fixture(sc.value("ok", true) == false, "type_apply_batch", "rollback",
                    "ok should be false when batch had errors");
    require_fixture(sc.value("stopped", false) == true, "type_apply_batch", "rollback",
                    "stopped should be true");
    require_fixture(sc.value("applied", 99) == 0, "type_apply_batch", "rollback",
                    "applied should be 0 after rollback");
    require_fixture(sc.value("failed", 0) == 3, "type_apply_batch", "rollback",
                    "failed should be 3");
    require_fixture(sc["results"].size() == 3, "type_apply_batch", "rollback",
                    "results array should have 3 entries");
    require_fixture(sc["results"][0].value("ok", true) == false, "type_apply_batch", "rollback",
                    "first edit should be rolled back (ok=false)");
    require_fixture(sc["results"][1].value("ok", true) == false, "type_apply_batch", "rollback",
                    "second edit should fail (ok=false)");
    require_fixture(sc["results"][2].value("ok", true) == false, "type_apply_batch", "rollback",
                    "third edit should be skipped (ok=false)");

    require_fixture(!env.overlay_store.has_application("0x140001000"),
                    "type_apply_batch", "rollback",
                    "first application should be rolled back");
    require_fixture(!env.overlay_store.has_application("0x140002000"),
                    "type_apply_batch", "rollback",
                    "third application should not exist");
    require_fixture(env.overlay_store.revision() == rev_before, "type_apply_batch", "rollback",
                    "revision should be unchanged after rollback");
    ++completed;
}

void fixture_undo(test_env_t& env, std::size_t& completed) {
    const std::uint64_t rev_before = env.overlay_store.revision();
    const json metadata{{"fixture_tool", "declare_type"}};

    const std::string decl = "struct UNDO_TEST { int x; char y; };";
    auto result = adapters::declare_type(*env.handlers, routed({{"decls", json::array({decl})}}),
                                          cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "declare_type", "undo", "declare failed");
    require_fixture(env.overlay_store.has_type("UNDO_TEST"), "declare_type", "undo",
                    "UNDO_TEST should exist after declare");
    require_fixture(env.overlay_store.revision() == rev_before + 1, "declare_type", "undo",
                    "revision should increment after declare");

    const bool undone = env.overlay_store.undo();
    require_fixture(undone, "declare_type", "undo", "undo should return true");
    require_fixture(!env.overlay_store.has_type("UNDO_TEST"), "declare_type", "undo",
                    "UNDO_TEST should not exist after undo");
    require_fixture(env.overlay_store.revision() == rev_before, "declare_type", "undo",
                    "revision should be restored after undo");

    const bool undone2 = env.overlay_store.undo();
    require_fixture(!undone2, "declare_type", "undo", "undo on empty stack should return false");
    ++completed;
}

void fixture_deterministic_output(test_env_t& env, std::size_t& completed) {
    const json metadata{{"fixture_tool", "declare_type"}};
    const std::string decl = "struct DETERM { DWORD a; PVOID b; };";

    auto r1 = adapters::declare_type(*env.handlers, routed({{"decls", json::array({decl})}}),
                                      cancellation_token_t::create(), metadata);
    require_fixture(!r1.is_error(), "declare_type", "deterministic", "first declare failed");
    const std::string out1 = r1.structured_content().dump();

    env.overlay_store.clear();
    auto r2 = adapters::declare_type(*env.handlers, routed({{"decls", json::array({decl})}}),
                                      cancellation_token_t::create(), metadata);
    require_fixture(!r2.is_error(), "declare_type", "deterministic", "second declare failed");
    const std::string out2 = r2.structured_content().dump();

    require_fixture(out1 == out2, "declare_type", "deterministic",
                    "output should be identical for same input");

    auto search1 = adapters::search_structs(*env.handlers, routed({{"filter", "DETERM"}}),
                                             cancellation_token_t::create(), metadata);
    auto search2 = adapters::search_structs(*env.handlers, routed({{"filter", "DETERM"}}),
                                             cancellation_token_t::create(), metadata);
    require_fixture(search1.structured_content().dump() == search2.structured_content().dump(),
                    "search_structs", "deterministic",
                    "search output should be identical for same input");
    ++completed;
}

void fixture_type_graph_queries(test_env_t& env, std::size_t& completed) {
    const json metadata{{"fixture_tool", "read_struct"}};
    const std::string decl = "struct GRAPH_TEST { DWORD field1; PVOID field2; USHORT field3; };";
    auto decl_result = adapters::declare_type(*env.handlers, routed({{"decls", json::array({decl})}}),
                                               cancellation_token_t::create(), metadata);
    require_fixture(!decl_result.is_error(), "read_struct", "graph_query", "declare failed");

    auto read_result = adapters::read_struct(*env.handlers,
        routed({{"queries", json{{"addr", "0x140001000"}, {"struct", "GRAPH_TEST"}}}}),
        cancellation_token_t::create(), metadata);
    require_fixture(!read_result.is_error(), "read_struct", "graph_query", read_result.text());
    const auto& read_sc = read_result.structured_content();
    require_fixture(read_sc["result"].size() == 1, "read_struct", "graph_query",
                    "result array size");
    require_fixture(read_sc["result"][0].value("struct", "") == "GRAPH_TEST",
                    "read_struct", "graph_query", "struct name mismatch");
    require_fixture(read_sc["result"][0]["members"].is_array(), "read_struct", "graph_query",
                    "members should be array");
    require_fixture(read_sc["result"][0]["members"].size() == 3, "read_struct", "graph_query",
                    "should have 3 members");
    require_fixture(read_sc["result"][0]["members"][0].value("name", "") == "field1",
                    "read_struct", "graph_query", "first member name");
    require_fixture(read_sc["result"][0]["members"][0].value("offset", "") == "0x0",
                    "read_struct", "graph_query", "first member offset");
    require_fixture(read_sc["result"][0]["members"][0].value("size", 0) == 4,
                    "read_struct", "graph_query", "first member size");

    auto query_result = adapters::type_query(*env.handlers,
        routed({{"queries", json{{"filter", "GRAPH"}, {"kind", "struct"}, {"include_members", true}}}}),
        cancellation_token_t::create(), metadata);
    require_fixture(!query_result.is_error(), "type_query", "graph_query", query_result.text());
    const auto& query_sc = query_result.structured_content();
    require_fixture(query_sc["result"].size() == 1, "type_query", "graph_query",
                    "result array size");
    require_fixture(query_sc["result"][0].value("kind", "") == "struct", "type_query", "graph_query",
                    "kind should be struct");
    require_fixture(query_sc["result"][0].value("total", 0) == 1, "type_query", "graph_query",
                    "total should be 1");
    require_fixture(query_sc["result"][0]["data"].size() == 1, "type_query", "graph_query",
                    "data array size");
    require_fixture(query_sc["result"][0]["data"][0].value("name", "") == "GRAPH_TEST",
                    "type_query", "graph_query", "data name mismatch");
    require_fixture(query_sc["result"][0]["data"][0]["members"].is_array(),
                    "type_query", "graph_query", "members should be included");

    auto inspect_result = adapters::type_inspect(*env.handlers,
        routed({{"queries", json{{"name", "GRAPH_TEST"}, {"include_members", true}}}}),
        cancellation_token_t::create(), metadata);
    require_fixture(!inspect_result.is_error(), "type_inspect", "graph_query", inspect_result.text());
    const auto& insp_sc = inspect_result.structured_content();
    require_fixture(insp_sc["result"].size() == 1, "type_inspect", "graph_query",
                    "result array size");
    require_fixture(insp_sc["result"][0].value("exists", false) == true,
                    "type_inspect", "graph_query", "exists should be true");
    require_fixture(insp_sc["result"][0].value("is_udt", false) == true,
                    "type_inspect", "graph_query", "is_udt should be true");
    require_fixture(insp_sc["result"][0].value("size", 0) == 16,
                    "type_inspect", "graph_query", "size should be 16");
    require_fixture(insp_sc["result"][0].value("member_count", 0) == 3,
                    "type_inspect", "graph_query", "member_count should be 3");

    auto search_result = adapters::search_structs(*env.handlers,
        routed({{"filter", "GRAPH"}}),
        cancellation_token_t::create(), metadata);
    require_fixture(!search_result.is_error(), "search_structs", "graph_query", search_result.text());
    const auto& search_sc = search_result.structured_content();
    require_fixture(search_sc["result"].size() == 1, "search_structs", "graph_query",
                    "result array size");
    require_fixture(search_sc["result"][0].value("name", "") == "GRAPH_TEST",
                    "search_structs", "graph_query", "name mismatch");
    require_fixture(search_sc["result"][0].value("is_union", true) == false,
                    "search_structs", "graph_query", "is_union should be false");
    require_fixture(search_sc["result"][0].value("cardinality", 0) == 3,
                    "search_structs", "graph_query", "cardinality should be 3");
    ++completed;
}

void fixture_enum_upsert(test_env_t& env, std::size_t& completed) {
    const json metadata{{"fixture_tool", "enum_upsert"}};
    const json create_args = routed({{"queries", json::array({
        json{{"name", "COLOR"}, {"members", json::array({
            json{{"name", "RED"}, {"value", 0}},
            json{{"name", "GREEN"}, {"value", 1}},
            json{{"name", "BLUE"}, {"value", 2}},
        })}},
    })}});

    auto create_result = adapters::enum_upsert(*env.handlers, create_args,
                                                cancellation_token_t::create(), metadata);
    require_fixture(!create_result.is_error(), "enum_upsert", "create", create_result.text());
    const auto& create_sc = create_result.structured_content();
    require_fixture(create_sc["result"].size() == 1, "enum_upsert", "create", "result size");
    require_fixture(create_sc["result"][0].value("created", false) == true,
                    "enum_upsert", "create", "created should be true");
    require_fixture(create_sc["result"][0]["members"].size() == 3, "enum_upsert", "create",
                    "should have 3 members");
    const auto& summary = create_sc["result"][0]["summary"];
    require_fixture(summary.value("created", 0) == 3, "enum_upsert", "create",
                    "summary created should be 3");
    require_fixture(summary.value("skipped", 99) == 0, "enum_upsert", "create",
                    "summary skipped should be 0");
    require_fixture(summary.value("conflicts", 99) == 0, "enum_upsert", "create",
                    "summary conflicts should be 0");

    const auto* type = env.overlay_store.find_type("COLOR");
    require_fixture(type != nullptr, "enum_upsert", "create", "COLOR not in store");
    require_fixture(type->is_enum, "enum_upsert", "create", "should be enum");
    require_fixture(type->enumerators.size() == 3, "enum_upsert", "create",
                    "should have 3 enumerators");
    require_fixture(type->enumerators[0].name == "RED", "enum_upsert", "create",
                    "first enumerator should be RED");
    require_fixture(type->enumerators[0].value == 0, "enum_upsert", "create",
                    "RED value should be 0");

    const json update_args = routed({{"queries", json::array({
        json{{"name", "COLOR"}, {"members", json::array({
            json{{"name", "RED"}, {"value", 0}},
            json{{"name", "YELLOW"}, {"value", 3}},
        })}},
    })}});
    auto update_result = adapters::enum_upsert(*env.handlers, update_args,
                                                cancellation_token_t::create(), metadata);
    require_fixture(!update_result.is_error(), "enum_upsert", "update", update_result.text());
    const auto& update_sc = update_result.structured_content();
    require_fixture(update_sc["result"][0].value("created", true) == false,
                    "enum_upsert", "update", "created should be false for update");
    const auto& upd_summary = update_sc["result"][0]["summary"];
    require_fixture(upd_summary.value("created", 0) == 1, "enum_upsert", "update",
                    "summary created should be 1 (YELLOW)");
    require_fixture(upd_summary.value("skipped", 99) == 1, "enum_upsert", "update",
                    "summary skipped should be 1 (RED)");
    const auto* type2 = env.overlay_store.find_type("COLOR");
    require_fixture(type2->enumerators.size() == 4, "enum_upsert", "update",
                    "should have 4 enumerators after upsert");
    ++completed;
}

void fixture_inference_confidence(test_env_t& env, std::size_t& completed) {
    const json metadata{{"fixture_tool", "infer_types"}};
    const std::string decl = "struct INFER_TARGET { DWORD value; INFER_TARGET* self; };";
    auto decl_result = adapters::declare_type(*env.handlers, routed({{"decls", json::array({decl})}}),
                                               cancellation_token_t::create(), metadata);
    require_fixture(!decl_result.is_error(), "infer_types", "confidence", "declare failed");

    const json set_args = routed({{"edits", json{{"addr", "0x140005000"}, {"ty", "INFER_TARGET*"}}}});
    auto set_result = adapters::set_type(*env.handlers, set_args,
                                          cancellation_token_t::create(), metadata);
    require_fixture(!set_result.is_error(), "infer_types", "confidence", "set_type failed");

    auto infer_result = adapters::infer_types(*env.handlers,
        routed({{"addrs", json::array({"0x140005000", "0x140006000"})}}),
        cancellation_token_t::create(), metadata);
    require_fixture(!infer_result.is_error(), "infer_types", "confidence", infer_result.text());
    const auto& sc = infer_result.structured_content();
    require_fixture(sc["result"].size() == 2, "infer_types", "confidence",
                    "should have 2 results");

    require_fixture(sc["result"][0].value("addr", "") == "0x140005000", "infer_types", "confidence",
                    "first addr mismatch");
    require_fixture(sc["result"][0]["inferred_type"].is_string(), "infer_types", "confidence",
                    "first inferred_type should be string");
    require_fixture(sc["result"][0].value("inferred_type", "") == "INFER_TARGET*",
                    "infer_types", "confidence", "first inferred_type mismatch");
    require_fixture(sc["result"][0].value("confidence", "") == "high", "infer_types", "confidence",
                    "first confidence should be high (existing type application)");
    require_fixture(sc["result"][0].value("method", "") == "existing_type_application",
                    "infer_types", "confidence", "first method should be existing_type_application");

    require_fixture(sc["result"][1].value("addr", "") == "0x140006000", "infer_types", "confidence",
                    "second addr mismatch");
    require_fixture(sc["result"][1].value("confidence", "") == "low", "infer_types", "confidence",
                    "second confidence should be low or medium (no prior application)");
    require_fixture(!sc["result"][1]["method"].is_null(), "infer_types", "confidence",
                    "second method should not be null when a type is inferred");
    ++completed;
}

void fixture_set_type_and_batch_success(test_env_t& env, std::size_t& completed) {
    const json metadata{{"fixture_tool", "set_type"}};
    const json set_args = routed({{"edits", json::array({
        json{{"addr", "0x14001000"}, {"ty", "DWORD"}, {"kind", "data"}},
        json{{"addr", "0x14002000"}, {"ty", "PVOID"}, {"kind", "data"}},
    })}});

    auto set_result = adapters::set_type(*env.handlers, set_args,
                                          cancellation_token_t::create(), metadata);
    require_fixture(!set_result.is_error(), "set_type", "batch_success", set_result.text());
    const auto& sc = set_result.structured_content();
    require_fixture(sc["result"].size() == 2, "set_type", "batch_success", "result size");
    require_fixture(sc["result"][0].value("ok", false) == true, "set_type", "batch_success",
                    "first edit should succeed");
    require_fixture(sc["result"][1].value("ok", false) == true, "set_type", "batch_success",
                    "second edit should succeed");
    require_fixture(env.overlay_store.has_application("0x14001000"), "set_type", "batch_success",
                    "first application should exist");
    require_fixture(env.overlay_store.has_application("0x14002000"), "set_type", "batch_success",
                    "second application should exist");

    const auto* app = env.overlay_store.find_application("0x14001000");
    require_fixture(app != nullptr, "set_type", "batch_success", "application not found");
    require_fixture(app->ty == "DWORD", "set_type", "batch_success", "type mismatch");
    require_fixture(app->kind == "data", "set_type", "batch_success", "kind mismatch");

    const json batch_args = routed({{"batch", json{
        {"stop_on_error", false},
        {"edits", json::array({
            json{{"addr", "0x14003000"}, {"ty", "USHORT"}},
            json{{"addr", "0x14004000"}, {"ty", "ULONG"}},
        })},
    }}}));
    auto batch_result = adapters::type_apply_batch(*env.handlers, batch_args,
                                                     cancellation_token_t::create(), metadata);
    require_fixture(!batch_result.is_error(), "type_apply_batch", "batch_success", batch_result.text());
    const auto& bsc = batch_result.structured_content();
    require_fixture(bsc.value("ok", false) == true, "type_apply_batch", "batch_success",
                    "ok should be true");
    require_fixture(bsc.value("applied", 0) == 2, "type_apply_batch", "batch_success",
                    "applied should be 2");
    require_fixture(bsc.value("failed", 99) == 0, "type_apply_batch", "batch_success",
                    "failed should be 0");
    require_fixture(bsc.value("stopped", true) == false, "type_apply_batch", "batch_success",
                    "stopped should be false");
    require_fixture(bsc["results"].size() == 2, "type_apply_batch", "batch_success",
                    "results size");
    require_fixture(bsc["results"][0].value("ok", false) == true, "type_apply_batch", "batch_success",
                    "first batch edit should succeed");
    require_fixture(bsc["results"][1].value("ok", false) == true, "type_apply_batch", "batch_success",
                    "second batch edit should succeed");
    ++completed;
}

void fixture_invalid_pid(test_env_t& env, std::size_t& completed) {
    const json metadata{{"fixture_tool", "read_struct"}};
    json args = json::object();
    args["pid"] = 0;
    args["queries"] = json::array({json{{"addr", "0x140001000"}}});

    auto result = adapters::read_struct(*env.handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "read_struct", "invalid_pid", "zero pid was not rejected canonically");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "field", std::string()) == "pid",
        "read_struct", "invalid_pid", "pid field is absent from diagnostics");
    ++completed;
}

void fixture_cancellation(test_env_t& env, std::size_t& completed) {
    const json metadata{{"fixture_tool", "read_struct"}};
    auto cancellation = cancellation_token_t::create();
    cancellation.cancel();

    auto result = adapters::read_struct(*env.handlers,
        routed({{"queries", json{{"addr", "0x140001000"}}}}),
        cancellation, metadata);
    require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                    "read_struct", "cancellation",
                    "pre-dispatch cancellation was not observed canonically");
    ++completed;
}

void fixture_collection_routing(test_env_t& env, std::size_t& completed) {
    const json metadata{{"fixture_tool", "search_structs"}};
    json args = json::object();
    args["pid"] = 4102;
    args["filter"] = "TEST";

    auto result = adapters::search_structs(*env.handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "search_structs", "collection_routing", result.text());
    ++completed;
}

void verify_type_handlers() {
    test_env_t env;
    verify_contracts(*env.handlers, *env.schemas);
    verify_lane_policies(*env.handlers);

    std::size_t completed = 0;

    fixture_recursive_type(env, completed);
    fixture_conflicting_type(env, completed);
    fixture_invalid_declaration(env, completed);
    fixture_batch_rollback(env, completed);
    fixture_undo(env, completed);
    fixture_deterministic_output(env, completed);
    fixture_type_graph_queries(env, completed);
    fixture_enum_upsert(env, completed);
    fixture_inference_confidence(env, completed);
    fixture_set_type_and_batch_success(env, completed);
    fixture_invalid_pid(env, completed);
    fixture_cancellation(env, completed);
    fixture_collection_routing(env, completed);

    require(completed == 13,
            "types handler harness did not execute all thirteen fixture families");
}

}

bool run_type_handlers_harness(std::string& failure) {
    try {
        verify_type_handlers();
    } catch (const std::exception& error) {
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
