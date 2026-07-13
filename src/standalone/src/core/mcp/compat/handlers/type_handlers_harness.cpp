#include "type_handlers_harness.hpp"

#include <chrono>
#include <stdexcept>
#include <string>
#include <utility>

namespace aida::standalone::mcp::compat::handlers::test {

namespace {

using protocol::json;

bool json_has(const json& obj, const std::string& key) {
    return obj.is_object() && obj.contains(key);
}

bool json_is_array(const json& obj, const std::string& key) {
    return json_has(obj, key) && obj[key].is_array();
}

bool json_is_string(const json& obj, const std::string& key) {
    return json_has(obj, key) && obj[key].is_string();
}

bool json_is_int(const json& obj, const std::string& key) {
    return json_has(obj, key) && obj[key].is_number_integer();
}

std::string json_string(const json& obj, const std::string& key) {
    if (!json_is_string(obj, key)) return {};
    return obj[key].get<std::string>();
}

std::int64_t json_int(const json& obj, const std::string& key) {
    if (!json_is_int(obj, key)) return 0;
    return obj[key].get<std::int64_t>();
}

bool json_bool(const json& obj, const std::string& key) {
    if (!json_has(obj, key) || !obj[key].is_boolean()) return false;
    return obj[key].get<bool>();
}

const json& json_array(const json& obj, const std::string& key) {
    static const json empty = json::array();
    if (!json_is_array(obj, key)) return empty;
    return obj[key];
}

}

types_test_fixture_t::types_test_fixture_t()
    : overlay_store_() {
    default_target_.target_id = 0xA101ULL;
    default_target_.pid = 4101;
    default_target_.process_creation_identity = 0xB101ULL;
    default_target_.bin_name = "fixture-types.exe";
    default_target_.generation = 1;
    default_target_.attach_generation = 1;
    default_target_.revision = 1;
    if (!resolver_.publish(default_target_)) {
        throw std::runtime_error("failed to publish default types fixture target");
    }
    default_scope_ = overlay_store_.target_scope(default_target_);
    workspace_adapter_handlers_t handlers;
    handlers.query = [this](const adapter_call_context_t& context,
                            const adapter_request_t& request) {
        return overlay_store_.handle_query(context, request);
    };
    handlers.overlay = [this](const adapter_call_context_t& context,
                              const adapter_request_t& request) {
        return overlay_store_.handle_overlay(context, request);
    };
    workspace_ = std::make_unique<workspace_adapter_t>(
        resolver_, lock_manager_, std::move(handlers));
}

types_test_fixture_t::~types_test_fixture_t() = default;

types_overlay_store_t& types_test_fixture_t::overlay_store() noexcept {
    return *default_scope_;
}

target_resolver_t& types_test_fixture_t::resolver() noexcept {
    return resolver_;
}

effect_lock_manager_t& types_test_fixture_t::lock_manager() noexcept {
    return lock_manager_;
}

protocol::schema_runtime_t& types_test_fixture_t::schemas() noexcept {
    return schemas_;
}

adapter_request_t types_test_fixture_t::make_request(const protocol::json& args) {
    adapter_request_t request;
    request.target.pid = default_target_.pid;
    request.payload = args.dump();
    return request;
}

adapter_result_t<adapter_response_t> types_test_fixture_t::call_query(
    std::string_view tool_name, const protocol::json& args) {
    auto req = make_request(args);
    return workspace_->query(tool_name, req);
}

adapter_result_t<adapter_response_t> types_test_fixture_t::call_overlay(
    std::string_view tool_name, const protocol::json& args) {
    auto req = make_request(args);
    return workspace_->overlay(tool_name, req);
}

adapter_result_t<adapter_response_t> types_test_fixture_t::call_query_for(
    std::uint32_t pid, std::string_view tool_name, const protocol::json& args) {
    auto req = make_request(args);
    req.target.pid = pid;
    return workspace_->query(tool_name, req);
}

adapter_result_t<adapter_response_t> types_test_fixture_t::call_overlay_for(
    std::uint32_t pid, std::string_view tool_name, const protocol::json& args) {
    auto req = make_request(args);
    req.target.pid = pid;
    return workspace_->overlay(tool_name, req);
}

protocol::json types_test_fixture_t::call_query_json(
    std::string_view tool_name, const protocol::json& args) {
    auto result = call_query(tool_name, args);
    if (!result) {
        throw std::runtime_error("query adapter failed: " + std::string(result.error().stable_code));
    }
    return json::parse(result.value().payload, nullptr, false);
}

protocol::json types_test_fixture_t::call_overlay_json(
    std::string_view tool_name, const protocol::json& args) {
    auto result = call_overlay(tool_name, args);
    if (!result) {
        throw std::runtime_error("overlay adapter failed: " + std::string(result.error().stable_code));
    }
    return json::parse(result.value().payload, nullptr, false);
}

protocol::json types_test_fixture_t::call_query_json_for(
    std::uint32_t pid, std::string_view tool_name, const protocol::json& args) {
    auto result = call_query_for(pid, tool_name, args);
    if (!result) {
        throw std::runtime_error("query adapter failed: " + std::string(result.error().stable_code));
    }
    return json::parse(result.value().payload, nullptr, false);
}

protocol::json types_test_fixture_t::call_overlay_json_for(
    std::uint32_t pid, std::string_view tool_name, const protocol::json& args) {
    auto result = call_overlay_for(pid, tool_name, args);
    if (!result) {
        throw std::runtime_error("overlay adapter failed: " + std::string(result.error().stable_code));
    }
    return json::parse(result.value().payload, nullptr, false);
}

void types_test_fixture_t::publish_test_target(std::uint32_t pid, const std::string& bin_name) {
    target_record_t record;
    record.target_id = static_cast<std::uint64_t>(pid) * 17 + 1;
    record.pid = pid;
    record.process_creation_identity = static_cast<std::uint64_t>(pid) * 31 + 7;
    record.bin_name = bin_name;
    record.generation = 1;
    record.attach_generation = 1;
    record.live = false;
    record.revision = 1;
    if (!resolver_.publish(record)) {
        throw std::runtime_error("failed to publish types fixture target");
    }
}

void types_test_fixture_t::reset() {
    overlay_store_.clear();
}

void type_test_harness_t::register_test(
    const std::string& name, std::function<type_test_result_t()> test) {
    tests_.emplace_back(name, std::move(test));
}

type_test_summary_t type_test_harness_t::run_all() {
    type_test_summary_t summary;
    summary.total = tests_.size();
    for (const auto& [name, test] : tests_) {
        type_test_result_t result;
        const auto start = std::chrono::steady_clock::now();
        try {
            result = test();
        } catch (const std::exception& e) {
            result.passed = false;
            result.message = std::string("exception: ") + e.what();
        }
        const auto end = std::chrono::steady_clock::now();
        result.test_name = name;
        result.elapsed_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
        if (result.passed) ++summary.passed;
        else ++summary.failed;
        summary.results.push_back(std::move(result));
    }
    return summary;
}

type_test_summary_t type_test_harness_t::run_by_name(const std::string& name) {
    type_test_summary_t summary;
    for (const auto& [test_name, test] : tests_) {
        if (test_name != name) continue;
        ++summary.total;
        type_test_result_t result;
        const auto start = std::chrono::steady_clock::now();
        try {
            result = test();
        } catch (const std::exception& e) {
            result.passed = false;
            result.message = std::string("exception: ") + e.what();
        }
        const auto end = std::chrono::steady_clock::now();
        result.test_name = test_name;
        result.elapsed_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
        if (result.passed) ++summary.passed;
        else ++summary.failed;
        summary.results.push_back(std::move(result));
    }
    return summary;
}

std::size_t type_test_harness_t::test_count() const noexcept {
    return tests_.size();
}

type_test_result_t test_declare_struct_basic() {
    type_test_result_t r{"declare_struct_basic", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("declare_type", json{
        {"decls", "struct MY_STRUCT { int field1; char field2; long long field3; };"}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results returned"; return r; }
    if (json_string(results[0], "error") != "") { r.message = "unexpected error: " + json_string(results[0], "error"); return r; }
    if (!fx.overlay_store().has_type("MY_STRUCT")) { r.message = "type not registered"; return r; }
    const auto* type = fx.overlay_store().find_type("MY_STRUCT");
    if (!type) { r.message = "find_type returned null"; return r; }
    if (!type->is_udt) { r.message = "type is not UDT"; return r; }
    if (type->is_union) { r.message = "type is union, expected struct"; return r; }
    if (type->members.size() != 3) { r.message = "expected 3 members, got " + std::to_string(type->members.size()); return r; }
    if (type->members[0].name != "field1") { r.message = "member 0 name mismatch"; return r; }
    if (type->members[0].offset != 0) { r.message = "member 0 offset should be 0"; return r; }
    if (type->members[0].size != 4) { r.message = "member 0 size should be 4"; return r; }
    if (type->members[1].name != "field2") { r.message = "member 1 name mismatch"; return r; }
    if (type->members[1].offset != 4) { r.message = "member 1 offset should be 4"; return r; }
    if (type->members[2].name != "field3") { r.message = "member 2 name mismatch"; return r; }
    if (type->members[2].offset != 8) { r.message = "member 2 offset should be 8, got " + std::to_string(type->members[2].offset); return r; }
    if (type->members[2].size != 8) { r.message = "member 2 size should be 8"; return r; }
    if (type->size < 16) { r.message = "struct size should be at least 16"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_declare_union_basic() {
    type_test_result_t r{"declare_union_basic", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("declare_type", json{
        {"decls", "union MY_UNION { int a; double b; char c[16]; };"}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_string(results[0], "error") != "") { r.message = "error: " + json_string(results[0], "error"); return r; }
    const auto* type = fx.overlay_store().find_type("MY_UNION");
    if (!type) { r.message = "type not found"; return r; }
    if (!type->is_union) { r.message = "type is not union"; return r; }
    if (type->members.size() != 3) { r.message = "expected 3 members"; return r; }
    for (const auto& m : type->members) {
        if (m.offset != 0) { r.message = "union member offset should be 0"; return r; }
    }
    if (type->size < 16) { r.message = "union size should be at least 16 (largest member)"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_declare_enum_basic() {
    type_test_result_t r{"declare_enum_basic", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("declare_type", json{
        {"decls", "enum COLOR { RED = 0, GREEN = 1, BLUE = 2 };"}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_string(results[0], "error") != "") { r.message = "error: " + json_string(results[0], "error"); return r; }
    const auto* type = fx.overlay_store().find_type("COLOR");
    if (!type) { r.message = "enum not found"; return r; }
    if (!type->is_enum) { r.message = "type is not enum"; return r; }
    if (type->enumerators.size() != 3) { r.message = "expected 3 enumerators, got " + std::to_string(type->enumerators.size()); return r; }
    if (type->enumerators[0].name != "RED" || type->enumerators[0].value != 0) { r.message = "enumerator 0 mismatch"; return r; }
    if (type->enumerators[1].name != "GREEN" || type->enumerators[1].value != 1) { r.message = "enumerator 1 mismatch"; return r; }
    if (type->enumerators[2].name != "BLUE" || type->enumerators[2].value != 2) { r.message = "enumerator 2 mismatch"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_declare_typedef_basic() {
    type_test_result_t r{"declare_typedef_basic", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("declare_type", json{
        {"decls", "typedef unsigned long long QWORD_PTR;"}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_string(results[0], "error") != "") { r.message = "error: " + json_string(results[0], "error"); return r; }
    const auto* type = fx.overlay_store().find_type("QWORD_PTR");
    if (!type) { r.message = "typedef not found"; return r; }
    if (!type->is_typedef) { r.message = "type is not typedef"; return r; }
    if (type->size != 8) { r.message = "typedef size should be 8"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_declare_multiple_types() {
    type_test_result_t r{"declare_multiple_types", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("declare_type", json{
        {"decls", json::array({
            "struct A { int x; };",
            "struct B { int y; int z; };",
            "enum E { VAL1 = 10, VAL2 = 20 };",
        })}
    });
    auto results = json_array(output, "result");
    if (results.size() != 3) { r.message = "expected 3 results, got " + std::to_string(results.size()); return r; }
    for (std::size_t i = 0; i < results.size(); ++i) {
        if (json_string(results[i], "error") != "") { r.message = "result " + std::to_string(i) + " has error"; return r; }
    }
    if (fx.overlay_store().type_count() != 3) { r.message = "expected 3 types in store"; return r; }
    if (!fx.overlay_store().has_type("A")) { r.message = "type A missing"; return r; }
    if (!fx.overlay_store().has_type("B")) { r.message = "type B missing"; return r; }
    if (!fx.overlay_store().has_type("E")) { r.message = "type E missing"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_declare_invalid_declaration() {
    type_test_result_t r{"declare_invalid_declaration", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("declare_type", json{
        {"decls", "this is not a valid type declaration"}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_string(results[0], "error") == "") { r.message = "expected error for invalid declaration"; return r; }
    if (fx.overlay_store().type_count() != 0) { r.message = "store should be empty"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_enum_upsert_create_new() {
    type_test_result_t r{"enum_upsert_create_new", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("enum_upsert", json{
        {"queries", json::object({
            {"name", "FLAGS"},
            {"members", json::array({
                json::object({{"name", "FLAG_A"}, {"value", 1}}),
                json::object({{"name", "FLAG_B"}, {"value", 2}}),
                json::object({{"name", "FLAG_C"}, {"value", 4}}),
            })}
        })}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (!json_bool(results[0], "created")) { r.message = "expected created=true"; return r; }
    if (json_string(results[0], "error") != "") { r.message = "unexpected error"; return r; }
    auto summary = results[0].value("summary", json::object());
    if (json_int(summary, "created") != 3) { r.message = "expected 3 created"; return r; }
    const auto* type = fx.overlay_store().find_type("FLAGS");
    if (!type || !type->is_enum) { r.message = "enum not found"; return r; }
    if (type->enumerators.size() != 3) { r.message = "expected 3 enumerators"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_enum_upsert_add_members() {
    type_test_result_t r{"enum_upsert_add_members", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("enum_upsert", json{
        {"queries", json::object({{"name", "STATES"}, {"members", json::array({
            json::object({{"name", "IDLE"}, {"value", 0}}),
        })}})}
    });
    auto output = fx.call_overlay_json("enum_upsert", json{
        {"queries", json::object({{"name", "STATES"}, {"members", json::array({
            json::object({{"name", "RUNNING"}, {"value", 1}}),
            json::object({{"name", "STOPPED"}, {"value", 2}}),
        })}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_bool(results[0], "created")) { r.message = "expected created=false for existing enum"; return r; }
    auto summary = results[0].value("summary", json::object());
    if (json_int(summary, "created") != 2) { r.message = "expected 2 new members created"; return r; }
    const auto* type = fx.overlay_store().find_type("STATES");
    if (!type) { r.message = "enum not found"; return r; }
    if (type->enumerators.size() != 3) { r.message = "expected 3 enumerators total, got " + std::to_string(type->enumerators.size()); return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_enum_upsert_conflict_value() {
    type_test_result_t r{"enum_upsert_conflict_value", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("enum_upsert", json{
        {"queries", json::object({{"name", "LEVELS"}, {"members", json::array({
            json::object({{"name", "LOW"}, {"value", 1}}),
        })}})}
    });
    auto output = fx.call_overlay_json("enum_upsert", json{
        {"queries", json::object({{"name", "LEVELS"}, {"members", json::array({
            json::object({{"name", "LOW"}, {"value", 99}}),
        })}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    auto summary = results[0].value("summary", json::object());
    if (json_int(summary, "conflicts") != 1) { r.message = "expected 1 conflict"; return r; }
    const auto* type = fx.overlay_store().find_type("LEVELS");
    if (!type) { r.message = "enum not found"; return r; }
    bool found_updated = false;
    for (const auto& e : type->enumerators) {
        if (e.name == "LOW" && e.value == 99) { found_updated = true; break; }
    }
    if (!found_updated) { r.message = "conflicting value was not updated"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_enum_upsert_skip_existing() {
    type_test_result_t r{"enum_upsert_skip_existing", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("enum_upsert", json{
        {"queries", json::object({{"name", "MODES"}, {"members", json::array({
            json::object({{"name", "READ"}, {"value", 1}}),
        })}})}
    });
    auto output = fx.call_overlay_json("enum_upsert", json{
        {"queries", json::object({{"name", "MODES"}, {"members", json::array({
            json::object({{"name", "READ"}, {"value", 1}}),
        })}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    auto members = json_array(results[0], "members");
    if (members.empty()) { r.message = "no member results"; return r; }
    if (!json_bool(members[0], "skipped")) { r.message = "expected skipped=true for same value"; return r; }
    auto summary = results[0].value("summary", json::object());
    if (json_int(summary, "skipped") != 1) { r.message = "expected 1 skipped"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_enum_upsert_bitfield_flag() {
    type_test_result_t r{"enum_upsert_bitfield_flag", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("enum_upsert", json{
        {"queries", json::object({
            {"name", "BITS"},
            {"bitfield", true},
            {"members", json::array({
                json::object({{"name", "B0"}, {"value", 1}}),
            })}
        })}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (!json_bool(results[0], "bitfield")) { r.message = "expected bitfield=true in result"; return r; }
    const auto* type = fx.overlay_store().find_type("BITS");
    if (!type) { r.message = "enum not found"; return r; }
    if (!type->bitfield) { r.message = "enum bitfield flag not set"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_read_struct_with_explicit_type() {
    type_test_result_t r{"read_struct_with_explicit_type", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct POINT { int x; int y; };"}
    });
    auto output = fx.call_query_json("read_struct", json{
        {"queries", json::object({{"addr", "0x1000"}, {"struct", "POINT"}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_string(results[0], "error") != "") { r.message = "error: " + json_string(results[0], "error"); return r; }
    if (json_string(results[0], "struct") != "POINT") { r.message = "struct name mismatch"; return r; }
    auto members = json_array(results[0], "members");
    if (members.size() != 2) { r.message = "expected 2 members"; return r; }
    if (json_string(members[0], "name") != "x") { r.message = "member 0 name mismatch"; return r; }
    if (json_string(members[1], "name") != "y") { r.message = "member 1 name mismatch"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_read_struct_via_application() {
    type_test_result_t r{"read_struct_via_application", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct VEC3 { float x; float y; float z; };"}
    });
    fx.call_overlay_json("set_type", json{
        {"edits", json::object({{"addr", "0x2000"}, {"ty", "VEC3"}, {"kind", "data"}})}
    });
    auto output = fx.call_query_json("read_struct", json{
        {"queries", json::object({{"addr", "0x2000"}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_string(results[0], "error") != "") { r.message = "error: " + json_string(results[0], "error"); return r; }
    if (json_string(results[0], "struct") != "VEC3") { r.message = "struct should be resolved from application"; return r; }
    auto members = json_array(results[0], "members");
    if (members.size() != 3) { r.message = "expected 3 members"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_read_struct_missing_address() {
    type_test_result_t r{"read_struct_missing_address", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct DUMMY { int a; };"}
    });
    auto output = fx.call_query_json("read_struct", json{
        {"queries", json::object({{"struct", "DUMMY"}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_string(results[0], "error") != "address is required") { r.message = "expected 'address is required' error, got: " + json_string(results[0], "error"); return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_read_struct_undeclared_type() {
    type_test_result_t r{"read_struct_undeclared_type", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_query_json("read_struct", json{
        {"queries", json::object({{"addr", "0x3000"}, {"struct", "UNDECLARED"}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_string(results[0], "error").find("not declared") == std::string::npos) { r.message = "expected 'not declared' error, got: " + json_string(results[0], "error"); return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_read_struct_non_udt_type() {
    type_test_result_t r{"read_struct_non_udt_type", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "enum NOT_STRUCT { A = 0, B = 1 };"}
    });
    auto output = fx.call_query_json("read_struct", json{
        {"queries", json::object({{"addr", "0x4000"}, {"struct", "NOT_STRUCT"}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_string(results[0], "error").find("not a struct") == std::string::npos) { r.message = "expected 'not a struct/union' error"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_search_structs_with_filter() {
    type_test_result_t r{"search_structs_with_filter", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", json::array({
            "struct HEADER { int magic; int size; };",
            "struct FOOTER { int crc; };",
            "struct BODY { int data[16]; };",
        })}
    });
    auto output = fx.call_query_json("search_structs", json{
        {"filter", "HEAD"}
    });
    auto results = json_array(output, "result");
    if (results.size() != 1) { r.message = "expected 1 match, got " + std::to_string(results.size()); return r; }
    if (json_string(results[0], "name") != "HEADER") { r.message = "expected HEADER"; return r; }
    if (json_int(results[0], "cardinality") != 2) { r.message = "expected 2 members"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_search_structs_empty_filter() {
    type_test_result_t r{"search_structs_empty_filter", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", json::array({
            "struct ALPHA { int a; };",
            "struct BETA { int b; };",
        })}
    });
    auto output = fx.call_query_json("search_structs", json{
        {"filter", ""}
    });
    auto results = json_array(output, "result");
    if (results.size() != 2) { r.message = "expected 2 results with empty filter, got " + std::to_string(results.size()); return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_search_structs_no_matches() {
    type_test_result_t r{"search_structs_no_matches", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct REAL { int x; };"}
    });
    auto output = fx.call_query_json("search_structs", json{
        {"filter", "NONEXISTENT"}
    });
    auto results = json_array(output, "result");
    if (!results.empty()) { r.message = "expected 0 results"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_query_by_kind_struct() {
    type_test_result_t r{"type_query_by_kind_struct", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", json::array({
            "struct S1 { int a; };",
            "enum E1 { X = 0 };",
            "typedef int MY_INT;",
        })}
    });
    auto output = fx.call_query_json("type_query", json{
        {"queries", json::object({{"kind", "struct"}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    auto data = json_array(results[0], "data");
    if (data.size() != 1) { r.message = "expected 1 struct, got " + std::to_string(data.size()); return r; }
    if (json_string(data[0], "name") != "S1") { r.message = "expected S1"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_query_by_kind_enum() {
    type_test_result_t r{"type_query_by_kind_enum", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", json::array({
            "struct S1 { int a; };",
            "enum E1 { X = 0 };",
            "enum E2 { Y = 1 };",
        })}
    });
    auto output = fx.call_query_json("type_query", json{
        {"queries", json::object({{"kind", "enum"}})}
    });
    auto results = json_array(output, "result");
    auto data = json_array(results[0], "data");
    if (data.size() != 2) { r.message = "expected 2 enums, got " + std::to_string(data.size()); return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_query_pagination() {
    type_test_result_t r{"type_query_pagination", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", json::array({
            "struct AAA { int a; };",
            "struct BBB { int b; };",
            "struct CCC { int c; };",
            "struct DDD { int d; };",
            "struct EEE { int e; };",
        })}
    });
    auto output = fx.call_query_json("type_query", json{
        {"queries", json::object({{"count", 2}, {"offset", 1}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    auto data = json_array(results[0], "data");
    if (data.size() != 2) { r.message = "expected 2 items on page, got " + std::to_string(data.size()); return r; }
    if (json_int(results[0], "total") != 5) { r.message = "expected total=5"; return r; }
    if (!results[0].contains("next_offset") || results[0]["next_offset"].is_null()) { r.message = "expected non-null next_offset"; return r; }
    if (results[0]["next_offset"].get<int>() != 3) { r.message = "expected next_offset=3"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_query_include_members() {
    type_test_result_t r{"type_query_include_members", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct WITH_MEMBERS { int a; int b; int c; };"}
    });
    auto output = fx.call_query_json("type_query", json{
        {"queries", json::object({{"include_members", true}})}
    });
    auto results = json_array(output, "result");
    auto data = json_array(results[0], "data");
    if (data.empty()) { r.message = "no data"; return r; }
    if (!data[0].contains("members")) { r.message = "members not included"; return r; }
    auto members = json_array(data[0], "members");
    if (members.size() != 3) { r.message = "expected 3 members, got " + std::to_string(members.size()); return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_query_include_relationships() {
    type_test_result_t r{"type_query_include_relationships", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", json::array({
            "struct OUTER { struct INNER* ptr; };",
            "struct INNER { int value; };",
        })}
    });
    auto output = fx.call_query_json("type_query", json{
        {"queries", json::object({{"include_relationships", true}})}
    });
    auto results = json_array(output, "result");
    auto data = json_array(results[0], "data");
    if (data.empty()) { r.message = "no data"; return r; }
    bool found_relationship = false;
    for (const auto& entry : data) {
        auto related = json_array(entry, "related_types");
        if (!related.empty()) { found_relationship = true; break; }
    }
    if (!found_relationship) { r.message = "expected at least one related type"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_query_sort_by_size() {
    type_test_result_t r{"type_query_sort_by_size", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", json::array({
            "struct SMALL { char a; };",
            "struct LARGE { long long a; long long b; long long c; long long d; };",
            "struct MEDIUM { int a; int b; };",
        })}
    });
    auto output = fx.call_query_json("type_query", json{
        {"queries", json::object({{"sort_by", "size"}})}
    });
    auto results = json_array(output, "result");
    auto data = json_array(results[0], "data");
    if (data.size() != 3) { r.message = "expected 3 results"; return r; }
    if (json_int(data[0], "size") > json_int(data[1], "size")) { r.message = "results not sorted by size ascending"; return r; }
    if (json_int(data[1], "size") > json_int(data[2], "size")) { r.message = "results not sorted by size ascending"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_query_sort_by_name_descending() {
    type_test_result_t r{"type_query_sort_by_name_descending", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", json::array({
            "struct ALPHA { int a; };",
            "struct BETA { int b; };",
            "struct GAMMA { int c; };",
        })}
    });
    auto output = fx.call_query_json("type_query", json{
        {"queries", json::object({{"sort_by", "name"}, {"descending", true}})}
    });
    auto results = json_array(output, "result");
    auto data = json_array(results[0], "data");
    if (data.size() != 3) { r.message = "expected 3 results"; return r; }
    if (json_string(data[0], "name") != "GAMMA") { r.message = "expected GAMMA first (descending), got " + json_string(data[0], "name"); return r; }
    if (json_string(data[2], "name") != "ALPHA") { r.message = "expected ALPHA last"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_query_next_offset() {
    type_test_result_t r{"type_query_next_offset", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", json::array({
            "struct A { int a; };", "struct B { int b; };", "struct C { int c; };",
        })}
    });
    auto output = fx.call_query_json("type_query", json{
        {"queries", json::object({{"count", 2}, {"offset", 0}})}
    });
    auto results = json_array(output, "result");
    if (!results[0].contains("next_offset") || results[0]["next_offset"].is_null()) { r.message = "expected non-null next_offset"; return r; }
    if (results[0]["next_offset"].get<int>() != 2) { r.message = "expected next_offset=2"; return r; }
    auto output2 = fx.call_query_json("type_query", json{
        {"queries", json::object({{"count", 2}, {"offset", 2}})}
    });
    auto results2 = json_array(output2, "result");
    if (!results2[0]["next_offset"].is_null()) { r.message = "expected null next_offset on last page"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_query_include_declaration() {
    type_test_result_t r{"type_query_include_declaration", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct DECL_TEST { int x; };"}
    });
    auto output = fx.call_query_json("type_query", json{
        {"queries", json::object({{"include_decl", true}, {"filter", "DECL_TEST"}})}
    });
    auto results = json_array(output, "result");
    auto data = json_array(results[0], "data");
    if (data.empty()) { r.message = "no data"; return r; }
    if (!data[0].contains("declaration")) { r.message = "declaration not included"; return r; }
    if (json_string(data[0], "declaration").find("DECL_TEST") == std::string::npos) { r.message = "declaration doesn't contain type name"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_inspect_existing_struct() {
    type_test_result_t r{"type_inspect_existing_struct", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct INSPECT_ME { int field_a; char field_b; };"}
    });
    auto output = fx.call_query_json("type_inspect", json{
        {"queries", json::object({{"name", "INSPECT_ME"}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (!json_bool(results[0], "exists")) { r.message = "expected exists=true"; return r; }
    if (json_string(results[0], "error") != "") { r.message = "unexpected error"; return r; }
    if (!json_bool(results[0], "is_udt")) { r.message = "expected is_udt=true"; return r; }
    if (json_int(results[0], "member_count") != 2) { r.message = "expected 2 members"; return r; }
    auto members = json_array(results[0], "members");
    if (members.size() != 2) { r.message = "expected 2 members in array"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_inspect_missing_type() {
    type_test_result_t r{"type_inspect_missing_type", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_query_json("type_inspect", json{
        {"queries", json::object({{"name", "DOES_NOT_EXIST"}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_bool(results[0], "exists")) { r.message = "expected exists=false"; return r; }
    if (json_string(results[0], "error").find("does not exist") == std::string::npos) { r.message = "expected 'does not exist' error"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_inspect_enum_type() {
    type_test_result_t r{"type_inspect_enum_type", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "enum INSPECT_ENUM { VAL_A = 10, VAL_B = 20, VAL_C = 30 };"}
    });
    auto output = fx.call_query_json("type_inspect", json{
        {"queries", json::object({{"name", "INSPECT_ENUM"}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (!json_bool(results[0], "is_enum")) { r.message = "expected is_enum=true"; return r; }
    auto members = json_array(results[0], "members");
    if (members.size() != 3) { r.message = "expected 3 enumerators in members"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_inspect_typedef() {
    type_test_result_t r{"type_inspect_typedef", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "typedef int* PTR_INT;"}
    });
    auto output = fx.call_query_json("type_inspect", json{
        {"queries", json::object({{"name", "PTR_INT"}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (!json_bool(results[0], "exists")) { r.message = "expected exists=true"; return r; }
    if (json_string(results[0], "declaration").find("typedef") == std::string::npos) { r.message = "declaration should contain 'typedef'"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_inspect_empty_name() {
    type_test_result_t r{"type_inspect_empty_name", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_query_json("type_inspect", json{
        {"queries", json::object({{"name", ""}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_string(results[0], "error") != "type name is required") { r.message = "expected 'type name is required' error"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_set_type_data_kind() {
    type_test_result_t r{"set_type_data_kind", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("set_type", json{
        {"edits", json::object({{"addr", "0x5000"}, {"ty", "int"}, {"kind", "data"}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (!json_bool(results[0], "ok")) { r.message = "expected ok=true"; return r; }
    if (json_string(results[0], "kind") != "data") { r.message = "expected kind=data"; return r; }
    if (!fx.overlay_store().has_application("0x5000")) { r.message = "application not stored"; return r; }
    const auto* app = fx.overlay_store().find_application("0x5000");
    if (!app) { r.message = "find_application returned null"; return r; }
    if (app->ty != "int") { r.message = "application type mismatch"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_set_type_function_kind() {
    type_test_result_t r{"set_type_function_kind", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("set_type", json{
        {"edits", json::object({
            {"addr", "0x6000"},
            {"signature", "int main(int argc, char** argv)"},
            {"name", "main"},
            {"kind", "function"}
        })}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (!json_bool(results[0], "ok")) { r.message = "expected ok=true"; return r; }
    if (json_string(results[0], "kind") != "function") { r.message = "expected kind=function"; return r; }
    const auto* app = fx.overlay_store().find_application("0x6000");
    if (!app) { r.message = "application not found"; return r; }
    if (app->signature != "int main(int argc, char** argv)") { r.message = "signature mismatch"; return r; }
    if (app->name != "main") { r.message = "name mismatch"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_set_type_overwrite_existing() {
    type_test_result_t r{"set_type_overwrite_existing", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("set_type", json{
        {"edits", json::object({{"addr", "0x7000"}, {"ty", "int"}, {"kind", "data"}})}
    });
    auto output = fx.call_overlay_json("set_type", json{
        {"edits", json::object({{"addr", "0x7000"}, {"ty", "long"}, {"kind", "data"}})}
    });
    auto results = json_array(output, "result");
    if (!json_bool(results[0], "ok")) { r.message = "expected ok=true for overwrite"; return r; }
    const auto* app = fx.overlay_store().find_application("0x7000");
    if (!app) { r.message = "application not found"; return r; }
    if (app->ty != "long") { r.message = "expected updated type 'long', got '" + app->ty + "'"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_set_type_missing_address() {
    type_test_result_t r{"set_type_missing_address", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("set_type", json{
        {"edits", json::object({{"ty", "int"}, {"kind", "data"}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_bool(results[0], "ok")) { r.message = "expected ok=false for missing address"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_set_type_no_type_info() {
    type_test_result_t r{"set_type_no_type_info", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("set_type", json{
        {"edits", json::object({{"addr", "0x8000"}, {"kind", "data"}})}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_bool(results[0], "ok")) { r.message = "expected ok=false when no type info provided"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_apply_batch_all_success() {
    type_test_result_t r{"type_apply_batch_all_success", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("type_apply_batch", json{
        {"batch", json::object({
            {"edits", json::array({
                json::object({{"addr", "0x9000"}, {"ty", "int"}, {"kind", "data"}}),
                json::object({{"addr", "0x9004"}, {"ty", "int"}, {"kind", "data"}}),
                json::object({{"addr", "0x9008"}, {"ty", "int"}, {"kind", "data"}}),
            })}
        })}
    });
    if (!json_bool(output, "ok")) { r.message = "expected ok=true"; return r; }
    if (json_int(output, "applied") != 3) { r.message = "expected 3 applied"; return r; }
    if (json_int(output, "failed") != 0) { r.message = "expected 0 failed"; return r; }
    if (json_bool(output, "stopped")) { r.message = "expected stopped=false"; return r; }
    if (fx.overlay_store().application_count() != 3) { r.message = "expected 3 applications stored"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_apply_batch_partial_failure() {
    type_test_result_t r{"type_apply_batch_partial_failure", false, ""};
    types_test_fixture_t fx;
    const auto revision = fx.overlay_store().revision();
    auto output = fx.call_overlay_json("type_apply_batch", json{
        {"batch", json::object({
            {"edits", json::array({
                json::object({{"addr", "0xA000"}, {"ty", "int"}, {"kind", "data"}}),
                json::object({{"kind", "data"}}),
                json::object({{"addr", "0xA004"}, {"ty", "int"}, {"kind", "data"}}),
            })},
            {"stop_on_error", false}
        })}
    });
    if (json_bool(output, "ok")) { r.message = "expected ok=false with failures"; return r; }
    if (json_int(output, "applied") != 0) { r.message = "expected atomic rollback"; return r; }
    if (json_int(output, "failed") != 3) { r.message = "expected all edits to fail atomically"; return r; }
    if (json_bool(output, "stopped")) { r.message = "expected stopped=false"; return r; }
    if (fx.overlay_store().has_application("0xA000") ||
        fx.overlay_store().has_application("0xA004")) {
        r.message = "failed batch retained a partial application";
        return r;
    }
    if (fx.overlay_store().revision() != revision) {
        r.message = "failed batch changed the overlay revision";
        return r;
    }
    r.passed = true;
    return r;
}

type_test_result_t test_type_apply_batch_rollback_on_error() {
    type_test_result_t r{"type_apply_batch_rollback_on_error", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("type_apply_batch", json{
        {"batch", json::object({
            {"edits", json::array({
                json::object({{"addr", "0xB000"}, {"ty", "int"}, {"kind", "data"}}),
                json::object({{"addr", "0xB004"}, {"ty", "int"}, {"kind", "data"}}),
                json::object({{"kind", "data"}}),
            })},
            {"stop_on_error", true}
        })}
    });
    if (json_bool(output, "ok")) { r.message = "expected ok=false after rollback"; return r; }
    if (json_bool(output, "stopped")) { r.message = "expected stopped=true"; return r; }
    if (fx.overlay_store().application_count() != 0) {
        r.message = "expected 0 applications after rollback, got " + std::to_string(fx.overlay_store().application_count());
        return r;
    }
    r.passed = true;
    return r;
}

type_test_result_t test_type_apply_batch_empty_edits() {
    type_test_result_t r{"type_apply_batch_empty_edits", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_overlay_json("type_apply_batch", json{
        {"batch", json::object({{"edits", json::array()}})}
    });
    if (!json_bool(output, "ok")) { r.message = "expected ok=true for empty batch"; return r; }
    if (json_int(output, "applied") != 0) { r.message = "expected 0 applied"; return r; }
    if (json_int(output, "failed") != 0) { r.message = "expected 0 failed"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_infer_types_existing_application() {
    type_test_result_t r{"infer_types_existing_application", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("set_type", json{
        {"edits", json::object({{"addr", "0xC000"}, {"ty", "MY_STRUCT"}, {"kind", "data"}})}
    });
    auto output = fx.call_query_json("infer_types", json{
        {"addrs", "0xC000"}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_string(results[0], "inferred_type") != "MY_STRUCT") { r.message = "inferred type mismatch"; return r; }
    if (json_string(results[0], "confidence") != "high") { r.message = "expected high confidence"; return r; }
    if (json_string(results[0], "method") != "existing_type_application") { r.message = "expected existing_type_application method"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_infer_types_no_data() {
    type_test_result_t r{"infer_types_no_data", false, ""};
    types_test_fixture_t fx;
    auto output = fx.call_query_json("infer_types", json{
        {"addrs", "0xDEAD"}
    });
    auto results = json_array(output, "result");
    if (results.empty()) { r.message = "no results"; return r; }
    if (json_string(results[0], "confidence") != "low") { r.message = "expected low confidence"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_infer_types_multiple_addresses() {
    type_test_result_t r{"infer_types_multiple_addresses", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct MEDIUM_INFER { int value; MEDIUM_INFER* next; };"}
    });
    fx.call_overlay_json("set_type", json{
        {"edits", json::array({
            json::object({{"addr", "0xD000"}, {"ty", "int"}, {"kind", "data"}}),
            json::object({{"addr", "0xD004"}, {"ty", "long"}, {"kind", "data"}}),
            json::object({{"addr", "0xD008"}, {"signature", "MEDIUM_INFER* candidate"}, {"kind", "data"}}),
        })}
    });
    auto output = fx.call_query_json("infer_types", json{
        {"addrs", json::array({"0xD000", "0xD004", "0xD008", "0xDEAD"})}
    });
    auto results = json_array(output, "result");
    if (results.size() != 4) { r.message = "expected 4 results, got " + std::to_string(results.size()); return r; }
    if (json_string(results[0], "inferred_type") != "int") { r.message = "addr 0 result mismatch"; return r; }
    if (json_string(results[1], "inferred_type") != "long") { r.message = "addr 1 result mismatch"; return r; }
    if (json_string(results[2], "inferred_type") != "MEDIUM_INFER*" ||
        json_string(results[2], "confidence") != "medium" ||
        json_string(results[2], "method") != "xref_analysis") {
        r.message = "addr 2 did not reach deterministic medium-confidence inference";
        return r;
    }
    if (json_string(results[3], "confidence") != "low") { r.message = "addr 3 should be low confidence"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_undo_declare_type() {
    type_test_result_t r{"undo_declare_type", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct UNDO_ME { int x; };"}
    });
    if (!fx.overlay_store().has_type("UNDO_ME")) { r.message = "type should exist before undo"; return r; }
    if (!fx.overlay_store().undo()) { r.message = "undo returned false"; return r; }
    if (fx.overlay_store().has_type("UNDO_ME")) { r.message = "type should not exist after undo"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_undo_set_type() {
    type_test_result_t r{"undo_set_type", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("set_type", json{
        {"edits", json::object({{"addr", "0xE000"}, {"ty", "int"}, {"kind", "data"}})}
    });
    if (!fx.overlay_store().has_application("0xE000")) { r.message = "application should exist"; return r; }
    if (!fx.overlay_store().undo()) { r.message = "undo returned false"; return r; }
    if (fx.overlay_store().has_application("0xE000")) { r.message = "application should not exist after undo"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_undo_empty_stack() {
    type_test_result_t r{"undo_empty_stack", false, ""};
    types_test_fixture_t fx;
    if (fx.overlay_store().undo()) { r.message = "undo on empty stack should return false"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_overlay_revision_tracking() {
    type_test_result_t r{"overlay_revision_tracking", false, ""};
    types_test_fixture_t fx;
    const std::uint64_t initial = fx.overlay_store().revision();
    if (initial != 0) { r.message = "initial revision should be 0"; return r; }
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct REV1 { int a; };"}
    });
    if (fx.overlay_store().revision() != 1) { r.message = "revision should be 1 after declare"; return r; }
    fx.call_overlay_json("set_type", json{
        {"edits", json::object({{"addr", "0xF000"}, {"ty", "int"}, {"kind", "data"}})}
    });
    if (fx.overlay_store().revision() != 2) { r.message = "revision should be 2 after set_type"; return r; }
    fx.call_overlay_json("enum_upsert", json{
        {"queries", json::object({{"name", "REV_ENUM"}, {"members", json::array({
            json::object({{"name", "VAL"}, {"value", 0}}),
        })}})}
    });
    if (fx.overlay_store().revision() != 3) { r.message = "revision should be 3 after enum_upsert"; return r; }
    fx.overlay_store().undo();
    if (fx.overlay_store().revision() != 2) { r.message = "revision should be 2 after undo"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_overlay_store_clear() {
    type_test_result_t r{"overlay_store_clear", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", json::array({
            "struct CLR1 { int a; };",
            "struct CLR2 { int b; };",
        })}
    });
    fx.call_overlay_json("set_type", json{
        {"edits", json::object({{"addr", "0x10000"}, {"ty", "int"}, {"kind", "data"}})}
    });
    if (fx.overlay_store().type_count() != 2) { r.message = "expected 2 types before clear"; return r; }
    if (fx.overlay_store().application_count() != 1) { r.message = "expected 1 application before clear"; return r; }
    fx.overlay_store().clear();
    if (fx.overlay_store().type_count() != 0) { r.message = "expected 0 types after clear"; return r; }
    if (fx.overlay_store().application_count() != 0) { r.message = "expected 0 applications after clear"; return r; }
    if (fx.overlay_store().revision() != 0) { r.message = "expected revision 0 after clear"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_overlay_store_type_count() {
    type_test_result_t r{"overlay_store_type_count", false, ""};
    types_test_fixture_t fx;
    if (fx.overlay_store().type_count() != 0) { r.message = "initial count should be 0"; return r; }
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct COUNT_A { int a; };"}
    });
    if (fx.overlay_store().type_count() != 1) { r.message = "count should be 1"; return r; }
    fx.call_overlay_json("declare_type", json{
        {"decls", json::array({"struct COUNT_B { int b; };", "enum COUNT_C { X = 0 };"})}
    });
    if (fx.overlay_store().type_count() != 3) { r.message = "count should be 3"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_overlay_store_application_count() {
    type_test_result_t r{"overlay_store_application_count", false, ""};
    types_test_fixture_t fx;
    if (fx.overlay_store().application_count() != 0) { r.message = "initial count should be 0"; return r; }
    fx.call_overlay_json("set_type", json{
        {"edits", json::array({
            json::object({{"addr", "0x11000"}, {"ty", "int"}, {"kind", "data"}}),
            json::object({{"addr", "0x11004"}, {"ty", "int"}, {"kind", "data"}}),
        })}
    });
    if (fx.overlay_store().application_count() != 2) { r.message = "expected 2 applications"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_overlay_store_all_type_names_sorted() {
    type_test_result_t r{"overlay_store_all_type_names_sorted", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", json::array({
            "struct ZEBRA { int z; };",
            "struct ALPHA { int a; };",
            "struct MIKE { int m; };",
        })}
    });
    auto names = fx.overlay_store().all_type_names();
    if (names.size() != 3) { r.message = "expected 3 names"; return r; }
    if (names[0] != "ALPHA") { r.message = "expected ALPHA first"; return r; }
    if (names[1] != "MIKE") { r.message = "expected MIKE second"; return r; }
    if (names[2] != "ZEBRA") { r.message = "expected ZEBRA third"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_overlay_store_has_type() {
    type_test_result_t r{"overlay_store_has_type", false, ""};
    types_test_fixture_t fx;
    if (fx.overlay_store().has_type("NONE")) { r.message = "should not have type before declaration"; return r; }
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct EXISTS { int a; };"}
    });
    if (!fx.overlay_store().has_type("EXISTS")) { r.message = "should have type after declaration"; return r; }
    if (fx.overlay_store().has_type("MISSING")) { r.message = "should not have MISSING"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_overlay_store_has_application() {
    type_test_result_t r{"overlay_store_has_application", false, ""};
    types_test_fixture_t fx;
    if (fx.overlay_store().has_application("0x12000")) { r.message = "should not have application"; return r; }
    fx.call_overlay_json("set_type", json{
        {"edits", json::object({{"addr", "0x12000"}, {"ty", "int"}, {"kind", "data"}})}
    });
    if (!fx.overlay_store().has_application("0x12000")) { r.message = "should have application"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_overlay_store_find_type() {
    type_test_result_t r{"overlay_store_find_type", false, ""};
    types_test_fixture_t fx;
    if (fx.overlay_store().find_type("GHOST") != nullptr) { r.message = "find_type should return null for missing"; return r; }
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct FOUND { int x; int y; };"}
    });
    const auto* type = fx.overlay_store().find_type("FOUND");
    if (!type) { r.message = "find_type returned null"; return r; }
    if (type->name != "FOUND") { r.message = "name mismatch"; return r; }
    if (type->members.size() != 2) { r.message = "member count mismatch"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_overlay_store_find_application() {
    type_test_result_t r{"overlay_store_find_application", false, ""};
    types_test_fixture_t fx;
    if (fx.overlay_store().find_application("0x13000") != nullptr) { r.message = "find_application should return null"; return r; }
    fx.call_overlay_json("set_type", json{
        {"edits", json::object({{"addr", "0x13000"}, {"ty", "long"}, {"name", "var1"}, {"kind", "data"}})}
    });
    const auto* app = fx.overlay_store().find_application("0x13000");
    if (!app) { r.message = "find_application returned null"; return r; }
    if (app->ty != "long") { r.message = "type mismatch"; return r; }
    if (app->name != "var1") { r.message = "name mismatch"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_struct_member_offset_alignment() {
    type_test_result_t r{"struct_member_offset_alignment", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct ALIGNED { char a; long long b; };"}
    });
    const auto* type = fx.overlay_store().find_type("ALIGNED");
    if (!type) { r.message = "type not found"; return r; }
    if (type->members[0].name != "a") { r.message = "member 0 name mismatch"; return r; }
    if (type->members[0].offset != 0) { r.message = "char should be at offset 0"; return r; }
    if (type->members[1].name != "b") { r.message = "member 1 name mismatch"; return r; }
    if (type->members[1].offset != 8) { r.message = "long long should be at offset 8 (aligned), got " + std::to_string(type->members[1].offset); return r; }
    if (type->members[1].size != 8) { r.message = "long long size should be 8"; return r; }
    if (type->size < 16) { r.message = "struct size should be at least 16 (8 padding + 8 data)"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_builtin_type_size_lookup() {
    type_test_result_t r{"builtin_type_size_lookup", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", json::array({
            "struct BUILTINS { "
            "  int a; "
            "  short b; "
            "  char c; "
            "  long long d; "
            "  void* e; "
            "  DWORD f; "
            "  HANDLE g; "
            "  LIST_ENTRY h; "
            "  GUID i; "
            "  UNICODE_STRING j; "
            "  uint8_t k; "
            "  uint16_t l; "
            "  uint32_t m; "
            "  uint64_t n; "
            "  size_t o; "
            "};",
        })}
    });
    const auto* type = fx.overlay_store().find_type("BUILTINS");
    if (!type) { r.message = "type not found"; return r; }
    if (type->members.size() != 15) { r.message = "expected 15 members, got " + std::to_string(type->members.size()); return r; }
    auto check_member = [&](std::size_t idx, const char* name, std::uint64_t expected_size) -> bool {
        if (idx >= type->members.size()) return false;
        return type->members[idx].name == name && type->members[idx].size == expected_size;
    };
    if (!check_member(0, "a", 4)) { r.message = "int size mismatch"; return r; }
    if (!check_member(1, "b", 2)) { r.message = "short size mismatch"; return r; }
    if (!check_member(2, "c", 1)) { r.message = "char size mismatch"; return r; }
    if (!check_member(3, "d", 8)) { r.message = "long long size mismatch"; return r; }
    if (!check_member(4, "e", 8)) { r.message = "void* size mismatch"; return r; }
    if (!check_member(5, "f", 4)) { r.message = "DWORD size mismatch"; return r; }
    if (!check_member(6, "g", 8)) { r.message = "HANDLE size mismatch"; return r; }
    if (!check_member(7, "h", 16)) { r.message = "LIST_ENTRY size mismatch"; return r; }
    if (!check_member(8, "i", 16)) { r.message = "GUID size mismatch"; return r; }
    if (!check_member(9, "j", 16)) { r.message = "UNICODE_STRING size mismatch"; return r; }
    if (!check_member(10, "k", 1)) { r.message = "uint8_t size mismatch"; return r; }
    if (!check_member(11, "l", 2)) { r.message = "uint16_t size mismatch"; return r; }
    if (!check_member(12, "m", 4)) { r.message = "uint32_t size mismatch"; return r; }
    if (!check_member(13, "n", 8)) { r.message = "uint64_t size mismatch"; return r; }
    if (!check_member(14, "o", 8)) { r.message = "size_t size mismatch"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_struct_with_array_member() {
    type_test_result_t r{"struct_struct_with_array_member", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct WITH_ARRAY { int count; char data[256]; };"}
    });
    const auto* type = fx.overlay_store().find_type("WITH_ARRAY");
    if (!type) { r.message = "type not found"; return r; }
    if (type->members.size() != 2) { r.message = "expected 2 members"; return r; }
    if (type->members[1].name != "data") { r.message = "member 1 name should be 'data'"; return r; }
    if (type->members[1].size != 256) { r.message = "array member size should be 256"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_struct_with_pointer_member() {
    type_test_result_t r{"struct_with_pointer_member", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct WITH_PTR { int count; int* values; };"}
    });
    const auto* type = fx.overlay_store().find_type("WITH_PTR");
    if (!type) { r.message = "type not found"; return r; }
    if (type->members[1].name != "values") { r.message = "member 1 name mismatch"; return r; }
    if (type->members[1].size != 8) { r.message = "pointer member size should be 8"; return r; }
    if (type->members[1].offset != 8) { r.message = "pointer should be at offset 8"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_enum_auto_increment_values() {
    type_test_result_t r{"enum_auto_increment_values", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "enum AUTO { FIRST, SECOND, THIRD, FOURTH };"}
    });
    const auto* type = fx.overlay_store().find_type("AUTO");
    if (!type) { r.message = "enum not found"; return r; }
    if (type->enumerators.size() != 4) { r.message = "expected 4 enumerators"; return r; }
    if (type->enumerators[0].value != 0) { r.message = "FIRST should be 0"; return r; }
    if (type->enumerators[1].value != 1) { r.message = "SECOND should be 1"; return r; }
    if (type->enumerators[2].value != 2) { r.message = "THIRD should be 2"; return r; }
    if (type->enumerators[3].value != 3) { r.message = "FOURTH should be 3"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_enum_hex_values() {
    type_test_result_t r{"enum_hex_values", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "enum HEXVALS { A = 0x10, B = 0x20, C = 0xFF };"}
    });
    const auto* type = fx.overlay_store().find_type("HEXVALS");
    if (!type) { r.message = "enum not found"; return r; }
    if (type->enumerators[0].value != 0x10) { r.message = "A should be 0x10"; return r; }
    if (type->enumerators[1].value != 0x20) { r.message = "B should be 0x20"; return r; }
    if (type->enumerators[2].value != 0xFF) { r.message = "C should be 0xFF"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_query_filter_substring() {
    type_test_result_t r{"type_query_filter_substring", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", json::array({
            "struct MY_TYPE_A { int a; };",
            "struct MY_TYPE_B { int b; };",
            "struct OTHER_TYPE { int c; };",
        })}
    });
    auto output = fx.call_query_json("type_query", json{
        {"queries", json::object({{"filter", "MY_TYPE"}})}
    });
    auto results = json_array(output, "result");
    auto data = json_array(results[0], "data");
    if (data.size() != 2) { r.message = "expected 2 results matching 'MY_TYPE', got " + std::to_string(data.size()); return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_inspect_max_members_limit() {
    type_test_result_t r{"type_inspect_max_members_limit", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct BIG { int a; int b; int c; int d; int e; int f; };"}
    });
    auto output = fx.call_query_json("type_inspect", json{
        {"queries", json::object({{"name", "BIG"}, {"max_members", 3}})}
    });
    auto results = json_array(output, "result");
    auto members = json_array(results[0], "members");
    if (members.size() != 3) { r.message = "expected 3 members (limited), got " + std::to_string(members.size()); return r; }
    if (json_int(results[0], "member_count") != 6) { r.message = "member_count should still be 6"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_query_max_members_limit() {
    type_test_result_t r{"type_query_max_members_limit", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct QUERY_BIG { int a; int b; int c; int d; };"}
    });
    auto output = fx.call_query_json("type_query", json{
        {"queries", json::object({{"include_members", true}, {"max_members", 2}, {"filter", "QUERY_BIG"}})}
    });
    auto results = json_array(output, "result");
    auto data = json_array(results[0], "data");
    if (data.empty()) { r.message = "no data"; return r; }
    auto members = json_array(data[0], "members");
    if (members.size() != 2) { r.message = "expected 2 members (limited), got " + std::to_string(members.size()); return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_type_apply_batch_multiple_kinds() {
    type_test_result_t r{"type_apply_batch_multiple_kinds", false, ""};
    types_test_fixture_t fx;
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct BATCH_STRUCT { int x; };"}
    });
    auto output = fx.call_overlay_json("type_apply_batch", json{
        {"batch", json::object({
            {"edits", json::array({
                json::object({{"addr", "0x14000"}, {"ty", "BATCH_STRUCT"}, {"kind", "data"}}),
                json::object({{"addr", "0x15000"}, {"signature", "void func()"}, {"name", "func"}, {"kind", "function"}}),
                json::object({{"addr", "0x16000"}, {"variable", "global_var"}, {"ty", "int"}, {"kind", "data"}}),
            })}
        })}
    });
    if (!json_bool(output, "ok")) { r.message = "expected ok=true"; return r; }
    if (json_int(output, "applied") != 3) { r.message = "expected 3 applied"; return r; }
    const auto* app1 = fx.overlay_store().find_application("0x14000");
    if (!app1 || app1->kind != "data") { r.message = "app 1 kind mismatch"; return r; }
    const auto* app2 = fx.overlay_store().find_application("0x15000");
    if (!app2 || app2->kind != "function") { r.message = "app 2 kind mismatch"; return r; }
    const auto* app3 = fx.overlay_store().find_application("0x16000");
    if (!app3 || app3->variable != "global_var") { r.message = "app 3 variable mismatch"; return r; }
    r.passed = true;
    return r;
}

type_test_result_t test_target_scoped_overlay_isolation() {
    type_test_result_t r{"target_scoped_overlay_isolation", false, ""};
    types_test_fixture_t fx;
    constexpr std::uint32_t second_pid = 4202;
    fx.publish_test_target(second_pid, "fixture-types-second.exe");
    fx.call_overlay_json("declare_type", json{
        {"decls", "struct FIRST_TARGET_ONLY { int value; };"}
    });
    fx.call_overlay_json_for(second_pid, "declare_type", json{
        {"decls", "struct SECOND_TARGET_ONLY { int value; };"}
    });
    const auto first_view = fx.call_query_json("type_inspect", json{
        {"queries", json::object({{"name", "SECOND_TARGET_ONLY"}})}
    });
    const auto second_view = fx.call_query_json_for(second_pid, "type_inspect", json{
        {"queries", json::object({{"name", "FIRST_TARGET_ONLY"}})}
    });
    const auto first_results = json_array(first_view, "result");
    const auto second_results = json_array(second_view, "result");
    if (first_results.size() != 1 || second_results.size() != 1) {
        r.message = "target-scoped queries returned unexpected result counts";
        return r;
    }
    if (json_bool(first_results[0], "exists") || json_bool(second_results[0], "exists")) {
        r.message = "type overlay state crossed resolved target identities";
        return r;
    }
    r.passed = true;
    return r;
}

void register_all_type_handler_tests(type_test_harness_t& harness) {
    harness.register_test("declare_struct_basic", test_declare_struct_basic);
    harness.register_test("declare_union_basic", test_declare_union_basic);
    harness.register_test("declare_enum_basic", test_declare_enum_basic);
    harness.register_test("declare_typedef_basic", test_declare_typedef_basic);
    harness.register_test("declare_multiple_types", test_declare_multiple_types);
    harness.register_test("declare_invalid_declaration", test_declare_invalid_declaration);
    harness.register_test("enum_upsert_create_new", test_enum_upsert_create_new);
    harness.register_test("enum_upsert_add_members", test_enum_upsert_add_members);
    harness.register_test("enum_upsert_conflict_value", test_enum_upsert_conflict_value);
    harness.register_test("enum_upsert_skip_existing", test_enum_upsert_skip_existing);
    harness.register_test("enum_upsert_bitfield_flag", test_enum_upsert_bitfield_flag);
    harness.register_test("read_struct_with_explicit_type", test_read_struct_with_explicit_type);
    harness.register_test("read_struct_via_application", test_read_struct_via_application);
    harness.register_test("read_struct_missing_address", test_read_struct_missing_address);
    harness.register_test("read_struct_undeclared_type", test_read_struct_undeclared_type);
    harness.register_test("read_struct_non_udt_type", test_read_struct_non_udt_type);
    harness.register_test("search_structs_with_filter", test_search_structs_with_filter);
    harness.register_test("search_structs_empty_filter", test_search_structs_empty_filter);
    harness.register_test("search_structs_no_matches", test_search_structs_no_matches);
    harness.register_test("type_query_by_kind_struct", test_type_query_by_kind_struct);
    harness.register_test("type_query_by_kind_enum", test_type_query_by_kind_enum);
    harness.register_test("type_query_pagination", test_type_query_pagination);
    harness.register_test("type_query_include_members", test_type_query_include_members);
    harness.register_test("type_query_include_relationships", test_type_query_include_relationships);
    harness.register_test("type_query_sort_by_size", test_type_query_sort_by_size);
    harness.register_test("type_query_sort_by_name_descending", test_type_query_sort_by_name_descending);
    harness.register_test("type_query_next_offset", test_type_query_next_offset);
    harness.register_test("type_query_include_declaration", test_type_query_include_declaration);
    harness.register_test("type_inspect_existing_struct", test_type_inspect_existing_struct);
    harness.register_test("type_inspect_missing_type", test_type_inspect_missing_type);
    harness.register_test("type_inspect_enum_type", test_type_inspect_enum_type);
    harness.register_test("type_inspect_typedef", test_type_inspect_typedef);
    harness.register_test("type_inspect_empty_name", test_type_inspect_empty_name);
    harness.register_test("set_type_data_kind", test_set_type_data_kind);
    harness.register_test("set_type_function_kind", test_set_type_function_kind);
    harness.register_test("set_type_overwrite_existing", test_set_type_overwrite_existing);
    harness.register_test("set_type_missing_address", test_set_type_missing_address);
    harness.register_test("set_type_no_type_info", test_set_type_no_type_info);
    harness.register_test("type_apply_batch_all_success", test_type_apply_batch_all_success);
    harness.register_test("type_apply_batch_partial_failure", test_type_apply_batch_partial_failure);
    harness.register_test("type_apply_batch_rollback_on_error", test_type_apply_batch_rollback_on_error);
    harness.register_test("type_apply_batch_empty_edits", test_type_apply_batch_empty_edits);
    harness.register_test("infer_types_existing_application", test_infer_types_existing_application);
    harness.register_test("infer_types_no_data", test_infer_types_no_data);
    harness.register_test("infer_types_multiple_addresses", test_infer_types_multiple_addresses);
    harness.register_test("undo_declare_type", test_undo_declare_type);
    harness.register_test("undo_set_type", test_undo_set_type);
    harness.register_test("undo_empty_stack", test_undo_empty_stack);
    harness.register_test("overlay_revision_tracking", test_overlay_revision_tracking);
    harness.register_test("overlay_store_clear", test_overlay_store_clear);
    harness.register_test("overlay_store_type_count", test_overlay_store_type_count);
    harness.register_test("overlay_store_application_count", test_overlay_store_application_count);
    harness.register_test("overlay_store_all_type_names_sorted", test_overlay_store_all_type_names_sorted);
    harness.register_test("overlay_store_has_type", test_overlay_store_has_type);
    harness.register_test("overlay_store_has_application", test_overlay_store_has_application);
    harness.register_test("overlay_store_find_type", test_overlay_store_find_type);
    harness.register_test("overlay_store_find_application", test_overlay_store_find_application);
    harness.register_test("struct_member_offset_alignment", test_struct_member_offset_alignment);
    harness.register_test("builtin_type_size_lookup", test_builtin_type_size_lookup);
    harness.register_test("struct_with_array_member", test_struct_with_array_member);
    harness.register_test("struct_with_pointer_member", test_struct_with_pointer_member);
    harness.register_test("enum_auto_increment_values", test_enum_auto_increment_values);
    harness.register_test("enum_hex_values", test_enum_hex_values);
    harness.register_test("type_query_filter_substring", test_type_query_filter_substring);
    harness.register_test("type_inspect_max_members_limit", test_type_inspect_max_members_limit);
    harness.register_test("type_query_max_members_limit", test_type_query_max_members_limit);
    harness.register_test("type_apply_batch_multiple_kinds", test_type_apply_batch_multiple_kinds);
    harness.register_test("target_scoped_overlay_isolation", test_target_scoped_overlay_isolation);
}

type_test_summary_t run_all_type_handler_tests() {
    type_test_harness_t harness;
    register_all_type_handler_tests(harness);
    return harness.run_all();
}

}
