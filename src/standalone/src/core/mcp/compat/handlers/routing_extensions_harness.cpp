#include "routing_extensions_harness.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <string>

namespace aida::standalone::mcp::compat::handlers::test {

namespace {

using protocol::json;
using protocol::mcp_result_t;
using protocol::result_error_code_t;
using protocol::cancellation_token_t;
using protocol::canonical_error_code;

thread_local routing_test_fixture_t* g_current_fixture = nullptr;

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

std::uint64_t parse_number(const std::string& text) {
    if (text.empty()) return 0;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        return std::stoull(text.substr(2), nullptr, 16);
    }
    return std::stoull(text);
}

}

adapter_result_t<adapter_response_t> routing_test_fixture_t::stub_analysis_handler(
    const adapter_call_context_t& context, const adapter_request_t& request) {
    if (g_current_fixture) {
        auto& state = g_current_fixture->analysis_state();
        state.call_count++;
        if (context.contract) {
            state.last_contract_name = std::string(context.contract->name);
        }
        state.last_payload = request.payload;
        if (state.canned_success && !state.canned_response.empty()) {
            return adapter_result_t<adapter_response_t>::success({state.canned_response, false});
        }
    }
    json response = json{{"results", json::array({json{{"addr", "0x1000"}, {"name", "func_mock"}}})}};
    return adapter_result_t<adapter_response_t>::success({response.dump(), false});
}

adapter_result_t<adapter_response_t> routing_test_fixture_t::stub_query_handler(
    const adapter_call_context_t& context, const adapter_request_t& request) {
    if (g_current_fixture) {
        auto& state = g_current_fixture->query_state();
        state.call_count++;
        if (context.contract) {
            state.last_contract_name = std::string(context.contract->name);
        }
        state.last_payload = request.payload;
        if (state.canned_success && !state.canned_response.empty()) {
            return adapter_result_t<adapter_response_t>::success({state.canned_response, false});
        }
    }
    json response = json{{"matches", json::array({json{{"addr", "0x1000"}, {"mnem", "mov"}}})}};
    return adapter_result_t<adapter_response_t>::success({response.dump(), false});
}

adapter_result_t<adapter_response_t> routing_test_fixture_t::stub_overlay_handler(
    const adapter_call_context_t&, const adapter_request_t&) {
    return adapter_result_t<adapter_response_t>::failure(
        {adapter_error_code_t::backend_unavailable, "stub_overlay", 0, 0});
}

adapter_result_t<adapter_response_t> routing_test_fixture_t::stub_checkpoint_handler(
    const adapter_call_context_t&, const adapter_request_t&) {
    return adapter_result_t<adapter_response_t>::failure(
        {adapter_error_code_t::backend_unavailable, "stub_checkpoint", 0, 0});
}

adapter_result_t<adapter_response_t> routing_test_fixture_t::stub_debugger_handler(
    const adapter_call_context_t&, const adapter_request_t&) {
    return adapter_result_t<adapter_response_t>::failure(
        {adapter_error_code_t::backend_unavailable, "stub_debugger", 0, 0});
}

adapter_result_t<adapter_response_t> routing_test_fixture_t::stub_python_handler(
    const adapter_call_context_t&, const adapter_request_t&) {
    return adapter_result_t<adapter_response_t>::failure(
        {adapter_error_code_t::backend_unavailable, "stub_python", 0, 0});
}

adapter_result_t<adapter_response_t> routing_test_fixture_t::stub_decompilation_handler(
    const adapter_call_context_t&, const adapter_request_t&) {
    return adapter_result_t<adapter_response_t>::failure(
        {adapter_error_code_t::backend_unavailable, "stub_decompilation", 0, 0});
}

adapter_result_t<bounded_live_snapshot_t> routing_test_fixture_t::stub_snapshot_handler(
    const adapter_call_context_t&, const bounded_live_snapshot_request_t&) {
    return adapter_result_t<bounded_live_snapshot_t>::failure(
        {adapter_error_code_t::live_snapshot_denied, "stub_snapshot", 0, 0});
}

routing_test_fixture_t::routing_test_fixture_t() {
    g_current_fixture = this;
    handlers_.analysis = [](const adapter_call_context_t& ctx, const adapter_request_t& req) {
        return stub_analysis_handler(ctx, req);
    };
    handlers_.query = [](const adapter_call_context_t& ctx, const adapter_request_t& req) {
        return stub_query_handler(ctx, req);
    };
    handlers_.overlay = [](const adapter_call_context_t& ctx, const adapter_request_t& req) {
        return stub_overlay_handler(ctx, req);
    };
    handlers_.checkpoint = [](const adapter_call_context_t& ctx, const adapter_request_t& req) {
        return stub_checkpoint_handler(ctx, req);
    };
    handlers_.debugger = [](const adapter_call_context_t& ctx, const adapter_request_t& req) {
        return stub_debugger_handler(ctx, req);
    };
    handlers_.isolated_python = [](const adapter_call_context_t& ctx, const adapter_request_t& req) {
        return stub_python_handler(ctx, req);
    };
    handlers_.decompilation = [](const adapter_call_context_t& ctx, const adapter_request_t& req) {
        return stub_decompilation_handler(ctx, req);
    };
    handlers_.live_snapshot = [](const adapter_call_context_t& ctx, const bounded_live_snapshot_request_t& req) {
        return stub_snapshot_handler(ctx, req);
    };
    workspace_ = std::make_unique<workspace_adapter_t>(resolver_, lock_manager_, handlers_);
    routing_ = std::make_unique<routing_extensions_t>(resolver_, *workspace_, schemas_);
}

routing_test_fixture_t::~routing_test_fixture_t() {
    routing_.reset();
    workspace_.reset();
    g_current_fixture = nullptr;
}

target_resolver_t& routing_test_fixture_t::resolver() noexcept { return resolver_; }
effect_lock_manager_t& routing_test_fixture_t::lock_manager() noexcept { return lock_manager_; }
workspace_adapter_t& routing_test_fixture_t::workspace() noexcept { return *workspace_; }
protocol::schema_runtime_t& routing_test_fixture_t::schemas() noexcept { return schemas_; }
routing_extensions_t& routing_test_fixture_t::routing() noexcept { return *routing_; }
stub_handler_state_t& routing_test_fixture_t::analysis_state() noexcept { return analysis_state_; }
stub_handler_state_t& routing_test_fixture_t::query_state() noexcept { return query_state_; }

void routing_test_fixture_t::publish_target(std::uint32_t pid, const std::string& bin_name, bool live) {
    target_record_t record;
    record.target_id = static_cast<std::uint64_t>(pid) * 17 + 1;
    record.pid = pid;
    record.process_creation_identity = static_cast<std::uint64_t>(pid) * 31 + 7;
    record.bin_name = bin_name;
    record.generation = 1;
    record.attach_generation = 1;
    record.live = live;
    record.revision = 1;
    resolver_.publish(record);
}

void routing_test_fixture_t::set_analysis_response(const std::string& json_payload) {
    analysis_state_.canned_response = json_payload;
    analysis_state_.canned_success = true;
}

void routing_test_fixture_t::set_query_response(const std::string& json_payload) {
    query_state_.canned_response = json_payload;
    query_state_.canned_success = true;
}

cancellation_token_t routing_test_fixture_t::make_cancellation(bool cancelled) {
    return cancellation_token_t::create(cancelled);
}

void routing_test_harness_t::register_test(
    const std::string& name, std::function<routing_test_result_t()> test) {
    tests_.emplace_back(name, std::move(test));
}

routing_test_summary_t routing_test_harness_t::run_all() {
    routing_test_summary_t summary;
    summary.total = tests_.size();
    for (const auto& [name, test] : tests_) {
        routing_test_result_t result;
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

routing_test_summary_t routing_test_harness_t::run_by_name(const std::string& name) {
    routing_test_summary_t summary;
    for (const auto& [test_name, test] : tests_) {
        if (test_name != name) continue;
        ++summary.total;
        routing_test_result_t result;
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

std::size_t routing_test_harness_t::test_count() const noexcept {
    return tests_.size();
}

routing_test_result_t test_metadata_inventory_count() {
    routing_test_result_t r{"metadata_inventory_count", false, ""};
    const auto& inventory = routing_metadata_inventory();
    if (inventory.size() != k_union_tool_count) {
        r.message = "expected " + std::to_string(k_union_tool_count) + " entries, got " + std::to_string(inventory.size());
        return r;
    }
    r.passed = true;
    return r;
}

routing_test_result_t test_metadata_find_all_extensions() {
    routing_test_result_t r{"metadata_find_all_extensions", false, ""};
    for (const auto ext_name : k_aida_extension_names) {
        const auto* meta = find_routing_metadata(ext_name);
        if (!meta) { r.message = "missing metadata for extension: " + std::string(ext_name); return r; }
        if (meta->name != ext_name) { r.message = "name mismatch for " + std::string(ext_name); return r; }
        if (!meta->is_extension) { r.message = std::string(ext_name) + " should have is_extension=true"; return r; }
    }
    r.passed = true;
    return r;
}

routing_test_result_t test_metadata_find_archive_tool() {
    routing_test_result_t r{"metadata_find_archive_tool", false, ""};
    const auto* archive = aida::standalone::mcp::compat::contracts();
    if (!archive || aida::standalone::mcp::compat::contract_count() == 0) {
        r.message = "no archive contracts available";
        return r;
    }
    const auto* meta = find_routing_metadata(archive[0].name);
    if (!meta) { r.message = "missing metadata for archive tool: " + std::string(archive[0].name); return r; }
    if (meta->is_extension) { r.message = "archive tool should have is_extension=false"; return r; }
    if (!meta->archive_backed) { r.message = "archive tool should have archive_backed=true"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_metadata_find_missing_returns_null() {
    routing_test_result_t r{"metadata_find_missing_returns_null", false, ""};
    const auto* meta = find_routing_metadata("THIS_TOOL_DOES_NOT_EXIST_12345");
    if (meta != nullptr) { r.message = "expected null for missing tool name"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_metadata_effect_fields_for_extensions() {
    routing_test_result_t r{"metadata_effect_fields_for_extensions", false, ""};
    const auto* analyze_meta = find_routing_metadata("analyze_funcs");
    if (!analyze_meta) { r.message = "missing analyze_funcs metadata"; return r; }
    if (analyze_meta->effect != protocol::tool_effect_t::workspace_read) { r.message = "analyze_funcs effect should be workspace_read"; return r; }
    if (analyze_meta->lock != protocol::effect_lock_t::workspace_shared) { r.message = "analyze_funcs lock should be workspace_shared"; return r; }
    if (!analyze_meta->read_only) { r.message = "analyze_funcs should be read_only"; return r; }

    const auto* find_meta = find_routing_metadata("find_insns");
    if (!find_meta) { r.message = "missing find_insns metadata"; return r; }
    if (find_meta->effect != protocol::tool_effect_t::workspace_read) { r.message = "find_insns effect should be workspace_read"; return r; }
    if (!find_meta->read_only) { r.message = "find_insns should be read_only"; return r; }

    const auto* calc_meta = find_routing_metadata("calculator");
    if (!calc_meta) { r.message = "missing calculator metadata"; return r; }
    if (calc_meta->effect != protocol::tool_effect_t::unspecified) { r.message = "calculator effect should be unspecified"; return r; }
    if (!calc_meta->read_only) { r.message = "calculator should be read_only"; return r; }

    const auto* calc2_meta = find_routing_metadata("calculate");
    if (!calc2_meta) { r.message = "missing calculate metadata"; return r; }
    if (calc2_meta->effect != protocol::tool_effect_t::unspecified) { r.message = "calculate effect should be unspecified"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_metadata_lane_for_extensions() {
    routing_test_result_t r{"metadata_lane_for_extensions", false, ""};
    const auto* analyze_meta = find_routing_metadata("analyze_funcs");
    if (!analyze_meta) { r.message = "missing analyze_funcs metadata"; return r; }
    if (analyze_meta->lane != extension_lane_t::workspace_analysis) { r.message = "analyze_funcs lane should be workspace_analysis"; return r; }

    const auto* find_meta = find_routing_metadata("find_insns");
    if (!find_meta) { r.message = "missing find_insns metadata"; return r; }
    if (find_meta->lane != extension_lane_t::workspace_instruction_scan) { r.message = "find_insns lane should be workspace_instruction_scan"; return r; }

    const auto* calc_meta = find_routing_metadata("calculator");
    if (!calc_meta) { r.message = "missing calculator metadata"; return r; }
    if (calc_meta->lane != extension_lane_t::local_calculator) { r.message = "calculator lane should be local_calculator"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_metadata_archive_backed_flag() {
    routing_test_result_t r{"metadata_archive_backed_flag", false, ""};
    for (const auto ext_name : k_aida_extension_names) {
        const auto* meta = find_routing_metadata(ext_name);
        if (!meta) { r.message = "missing metadata for " + std::string(ext_name); return r; }
        if (meta->archive_backed) { r.message = std::string(ext_name) + " should have archive_backed=false"; return r; }
    }
    const auto* archive = aida::standalone::mcp::compat::contracts();
    if (archive && aida::standalone::mcp::compat::contract_count() > 0) {
        const auto* meta = find_routing_metadata(archive[0].name);
        if (!meta) { r.message = "missing metadata for archive tool"; return r; }
        if (!meta->archive_backed) { r.message = "archive tool should have archive_backed=true"; return r; }
    }
    r.passed = true;
    return r;
}

routing_test_result_t test_metadata_is_extension_flag() {
    routing_test_result_t r{"metadata_is_extension_flag", false, ""};
    for (const auto ext_name : k_aida_extension_names) {
        const auto* meta = find_routing_metadata(ext_name);
        if (!meta) { r.message = "missing metadata for " + std::string(ext_name); return r; }
        if (!meta->is_extension) { r.message = std::string(ext_name) + " should have is_extension=true"; return r; }
    }
    r.passed = true;
    return r;
}

routing_test_result_t test_metadata_target_requirement_for_extensions() {
    routing_test_result_t r{"metadata_target_requirement_for_extensions", false, ""};
    const auto* analyze_meta = find_routing_metadata("analyze_funcs");
    if (!analyze_meta) { r.message = "missing analyze_funcs metadata"; return r; }
    if (analyze_meta->target_requirement != protocol::target_requirement_t::optional) { r.message = "analyze_funcs should be optional target"; return r; }
    if (!analyze_meta->accepts_pid) { r.message = "analyze_funcs should accept pid"; return r; }
    if (!analyze_meta->accepts_bin_name) { r.message = "analyze_funcs should accept bin_name"; return r; }

    const auto* calc_meta = find_routing_metadata("calculator");
    if (!calc_meta) { r.message = "missing calculator metadata"; return r; }
    if (calc_meta->target_requirement != protocol::target_requirement_t::independent) { r.message = "calculator should be independent target"; return r; }
    if (calc_meta->accepts_pid) { r.message = "calculator should not accept pid"; return r; }
    if (calc_meta->accepts_bin_name) { r.message = "calculator should not accept bin_name"; return r; }

    const auto* list_meta = find_routing_metadata("list_instances");
    if (!list_meta) { r.message = "missing list_instances metadata"; return r; }
    if (list_meta->target_requirement != protocol::target_requirement_t::independent) { r.message = "list_instances should be independent target"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_metadata_count_function() {
    routing_test_result_t r{"metadata_count_function", false, ""};
    const std::size_t count = routing_metadata_count();
    if (count != k_union_tool_count) {
        r.message = "expected " + std::to_string(k_union_tool_count) + ", got " + std::to_string(count);
        return r;
    }
    r.passed = true;
    return r;
}

routing_test_result_t test_extension_tool_count() {
    routing_test_result_t r{"extension_tool_count", false, ""};
    if (k_routing_extension_tool_count != 5) {
        r.message = "expected 5 extension tools, got " + std::to_string(k_routing_extension_tool_count);
        return r;
    }
    r.passed = true;
    return r;
}

routing_test_result_t test_extension_tool_names_match_constants() {
    routing_test_result_t r{"extension_tool_names_match_constants", false, ""};
    const auto& names = routing_extension_tool_names();
    if (names.size() != 5) { r.message = "expected 5 names"; return r; }
    if (names[0] != "list_instances") { r.message = "name 0 mismatch"; return r; }
    if (names[1] != "analyze_funcs") { r.message = "name 1 mismatch"; return r; }
    if (names[2] != "find_insns") { r.message = "name 2 mismatch"; return r; }
    if (names[3] != "calculator") { r.message = "name 3 mismatch"; return r; }
    if (names[4] != "calculate") { r.message = "name 4 mismatch"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_union_tool_count_is_92() {
    routing_test_result_t r{"union_tool_count_is_92", false, ""};
    if (k_union_tool_count != 92) {
        r.message = "expected k_union_tool_count=92, got " + std::to_string(k_union_tool_count);
        return r;
    }
    r.passed = true;
    return r;
}

routing_test_result_t test_archive_tool_count_is_88() {
    routing_test_result_t r{"archive_tool_count_is_88", false, ""};
    if (k_archive_tool_count != 88) {
        r.message = "expected k_archive_tool_count=88, got " + std::to_string(k_archive_tool_count);
        return r;
    }
    if (k_compatibility_tool_count != 88) {
        r.message = "expected k_compatibility_tool_count=88, got " + std::to_string(k_compatibility_tool_count);
        return r;
    }
    r.passed = true;
    return r;
}

routing_test_result_t test_extension_count_is_4() {
    routing_test_result_t r{"extension_count_is_4", false, ""};
    if (k_aida_extension_count != 4) {
        r.message = "expected k_aida_extension_count=4, got " + std::to_string(k_aida_extension_count);
        return r;
    }
    if (k_union_tool_count != k_archive_tool_count + k_aida_extension_count) {
        r.message = "union count should equal archive + extension count";
        return r;
    }
    r.passed = true;
    return r;
}

routing_test_result_t test_list_instances_empty_resolver() {
    routing_test_result_t r{"list_instances_empty_resolver", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "list_instances", json::object(), fx.make_cancellation());
    if (result.is_error()) { r.message = "list_instances failed on empty resolver"; return r; }
    const auto& structured = result.structured_content();
    auto instances = json_array(structured, "instances");
    if (!instances.empty()) { r.message = "expected empty instances array"; return r; }
    if (json_int(structured, "count") != 0) { r.message = "expected count=0"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_list_instances_with_published_target() {
    routing_test_result_t r{"list_instances_with_published_target", false, ""};
    routing_test_fixture_t fx;
    fx.publish_target(1234, "test_binary.exe");
    auto result = fx.routing().invoke(
        "list_instances", json::object(), fx.make_cancellation());
    if (result.is_error()) { r.message = "list_instances failed"; return r; }
    const auto& structured = result.structured_content();
    auto instances = json_array(structured, "instances");
    if (instances.size() != 1) { r.message = "expected 1 instance, got " + std::to_string(instances.size()); return r; }
    if (json_int(instances[0], "pid") != 1234) { r.message = "pid mismatch"; return r; }
    if (json_string(instances[0], "bin_name") != "test_binary.exe") { r.message = "bin_name mismatch"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_list_instances_with_filter() {
    routing_test_result_t r{"list_instances_with_filter", false, ""};
    routing_test_fixture_t fx;
    fx.publish_target(100, "app.exe");
    fx.publish_target(200, "other.dll");
    fx.publish_target(300, "app_helper.exe");
    auto result = fx.routing().invoke(
        "list_instances", json{{"filter", "app"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "list_instances failed"; return r; }
    const auto& structured = result.structured_content();
    auto instances = json_array(structured, "instances");
    if (instances.size() != 2) { r.message = "expected 2 instances matching 'app', got " + std::to_string(instances.size()); return r; }
    for (const auto& inst : instances) {
        const auto name = json_string(inst, "bin_name");
        if (name.find("app") == std::string::npos) { r.message = "instance doesn't match filter: " + name; return r; }
    }
    r.passed = true;
    return r;
}

routing_test_result_t test_list_instances_multiple_targets() {
    routing_test_result_t r{"list_instances_multiple_targets", false, ""};
    routing_test_fixture_t fx;
    for (std::uint32_t i = 1; i <= 10; ++i) {
        fx.publish_target(i, "proc_" + std::to_string(i) + ".exe");
    }
    auto result = fx.routing().invoke(
        "list_instances", json::object(), fx.make_cancellation());
    if (result.is_error()) { r.message = "list_instances failed"; return r; }
    const auto& structured = result.structured_content();
    auto instances = json_array(structured, "instances");
    if (instances.size() != 10) { r.message = "expected 10 instances, got " + std::to_string(instances.size()); return r; }
    if (json_int(structured, "count") != 10) { r.message = "expected count=10"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_list_instances_include_retired_flag() {
    routing_test_result_t r{"list_instances_include_retired_flag", false, ""};
    routing_test_fixture_t fx;
    fx.publish_target(42, "retire_test.exe");
    auto result = fx.routing().invoke(
        "list_instances", json{{"include_retired", true}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "list_instances with include_retired failed"; return r; }
    const auto& structured = result.structured_content();
    auto instances = json_array(structured, "instances");
    if (instances.empty()) { r.message = "expected at least 1 instance"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_addition() {
    routing_test_result_t r{"calculator_addition", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "1 + 2"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed: " + std::string(result.text()); return r; }
    const auto& structured = result.structured_content();
    if (json_string(structured, "result") != "3") { r.message = "expected result=3, got " + json_string(structured, "result"); return r; }
    if (json_string(structured, "decimal") != "3") { r.message = "decimal mismatch"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_subtraction() {
    routing_test_result_t r{"calculator_subtraction", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "100 - 37"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed"; return r; }
    const auto& structured = result.structured_content();
    if (json_string(structured, "result") != "63") { r.message = "expected 63, got " + json_string(structured, "result"); return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_multiplication() {
    routing_test_result_t r{"calculator_multiplication", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "7 * 8"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed"; return r; }
    const auto& structured = result.structured_content();
    if (json_string(structured, "result") != "56") { r.message = "expected 56, got " + json_string(structured, "result"); return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_division() {
    routing_test_result_t r{"calculator_division", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "144 / 12"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed"; return r; }
    const auto& structured = result.structured_content();
    if (json_string(structured, "result") != "12") { r.message = "expected 12, got " + json_string(structured, "result"); return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_modulo() {
    routing_test_result_t r{"calculator_modulo", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "17 % 5"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed"; return r; }
    const auto& structured = result.structured_content();
    if (json_string(structured, "result") != "2") { r.message = "expected 2, got " + json_string(structured, "result"); return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_hex_literal() {
    routing_test_result_t r{"calculator_hex_literal", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "0xFF + 1"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed"; return r; }
    const auto& structured = result.structured_content();
    if (json_string(structured, "result") != "256") { r.message = "expected 256, got " + json_string(structured, "result"); return r; }
    if (json_string(structured, "hex") != "0x100") { r.message = "expected hex=0x100, got " + json_string(structured, "hex"); return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_binary_literal() {
    routing_test_result_t r{"calculator_binary_literal", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "0b1010 + 0b0101"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed"; return r; }
    const auto& structured = result.structured_content();
    if (json_string(structured, "result") != "15") { r.message = "expected 15, got " + json_string(structured, "result"); return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_bitwise_and() {
    routing_test_result_t r{"calculator_bitwise_and", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "0xFF & 0x0F"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed"; return r; }
    const auto& structured = result.structured_content();
    if (json_string(structured, "result") != "15") { r.message = "expected 15, got " + json_string(structured, "result"); return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_bitwise_or() {
    routing_test_result_t r{"calculator_bitwise_or", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "0xF0 | 0x0F"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed"; return r; }
    const auto& structured = result.structured_content();
    if (json_string(structured, "result") != "255") { r.message = "expected 255, got " + json_string(structured, "result"); return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_bitwise_xor() {
    routing_test_result_t r{"calculator_bitwise_xor", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "0xAA ^ 0xFF"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed"; return r; }
    const auto& structured = result.structured_content();
    if (json_string(structured, "result") != "85") { r.message = "expected 85, got " + json_string(structured, "result"); return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_bitwise_not() {
    routing_test_result_t r{"calculator_bitwise_not", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "~0"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed"; return r; }
    const auto& structured = result.structured_content();
    const auto val = parse_number(json_string(structured, "result"));
    if (val != 0xFFFFFFFFFFFFFFFFULL) { r.message = "expected all 1s, got " + json_string(structured, "result"); return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_shift_left() {
    routing_test_result_t r{"calculator_shift_left", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "1 << 8"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed"; return r; }
    const auto& structured = result.structured_content();
    if (json_string(structured, "result") != "256") { r.message = "expected 256, got " + json_string(structured, "result"); return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_shift_right() {
    routing_test_result_t r{"calculator_shift_right", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "256 >> 4"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed"; return r; }
    const auto& structured = result.structured_content();
    if (json_string(structured, "result") != "16") { r.message = "expected 16, got " + json_string(structured, "result"); return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_parentheses() {
    routing_test_result_t r{"calculator_parentheses", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "(2 + 3) * 4"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed"; return r; }
    const auto& structured = result.structured_content();
    if (json_string(structured, "result") != "20") { r.message = "expected 20, got " + json_string(structured, "result"); return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_division_by_zero() {
    routing_test_result_t r{"calculator_division_by_zero", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "1 / 0"}}, fx.make_cancellation());
    if (!result.is_error()) { r.message = "expected error for division by zero"; return r; }
    if (result.error_code() != std::string_view(canonical_error_code(result_error_code_t::invalid_input))) {
        r.message = "expected invalid_input error code";
        return r;
    }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_empty_expression() {
    routing_test_result_t r{"calculator_empty_expression", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", ""}}, fx.make_cancellation());
    if (!result.is_error()) { r.message = "expected error for empty expression"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_trailing_tokens() {
    routing_test_result_t r{"calculator_trailing_tokens", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "1 + 2 3"}}, fx.make_cancellation());
    if (!result.is_error()) { r.message = "expected error for trailing tokens"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculator_complex_expression() {
    routing_test_result_t r{"calculator_complex_expression", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculator", json{{"expression", "((0x100 + 0x200) * 2) - 0x50"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculator failed"; return r; }
    const auto& structured = result.structured_content();
    const auto expected = ((0x100 + 0x200) * 2) - 0x50;
    if (parse_number(json_string(structured, "result")) != expected) {
        r.message = "expected " + std::to_string(expected) + ", got " + json_string(structured, "result");
        return r;
    }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculate_alias_matches_calculator() {
    routing_test_result_t r{"calculate_alias_matches_calculator", false, ""};
    routing_test_fixture_t fx;
    auto result_calc = fx.routing().invoke(
        "calculator", json{{"expression", "42 * 2"}}, fx.make_cancellation());
    auto result_calculate = fx.routing().invoke(
        "calculate", json{{"expression", "42 * 2"}}, fx.make_cancellation());
    if (result_calc.is_error()) { r.message = "calculator failed"; return r; }
    if (result_calculate.is_error()) { r.message = "calculate failed"; return r; }
    if (json_string(result_calc.structured_content(), "result") !=
        json_string(result_calculate.structured_content(), "result")) {
        r.message = "calculator and calculate should return same result";
        return r;
    }
    if (json_string(result_calculate.structured_content(), "result") != "84") {
        r.message = "expected 84, got " + json_string(result_calculate.structured_content(), "result");
        return r;
    }
    r.passed = true;
    return r;
}

routing_test_result_t test_calculate_hex_output() {
    routing_test_result_t r{"calculate_hex_output", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "calculate", json{{"expression", "255"}}, fx.make_cancellation());
    if (result.is_error()) { r.message = "calculate failed"; return r; }
    const auto& structured = result.structured_content();
    if (json_string(structured, "decimal") != "255") { r.message = "decimal mismatch"; return r; }
    if (json_string(structured, "hex") != "0xff") { r.message = "expected hex=0xff, got " + json_string(structured, "hex"); return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_analyze_funcs_missing_addrs() {
    routing_test_result_t r{"analyze_funcs_missing_addrs", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "analyze_funcs", json::object(), fx.make_cancellation());
    if (!result.is_error()) { r.message = "expected error when addrs is missing"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_find_insns_missing_mnemonic() {
    routing_test_result_t r{"find_insns_missing_mnemonic", false, ""};
    routing_test_fixture_t fx;
    auto result = fx.routing().invoke(
        "find_insns", json::object(), fx.make_cancellation());
    if (!result.is_error()) { r.message = "expected error when mnem is missing"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_routing_extension_size() {
    routing_test_result_t r{"routing_extension_size", false, ""};
    routing_test_fixture_t fx;
    if (fx.routing().size() != k_routing_extension_tool_count) {
        r.message = "expected " + std::to_string(k_routing_extension_tool_count) + " tools, got " + std::to_string(fx.routing().size());
        return r;
    }
    r.passed = true;
    return r;
}

routing_test_result_t test_routing_extension_find_existing() {
    routing_test_result_t r{"routing_extension_find_existing", false, ""};
    routing_test_fixture_t fx;
    const auto* contract = fx.routing().find("calculator");
    if (!contract) { r.message = "find(calculator) returned null"; return r; }
    if (contract->name != "calculator") { r.message = "contract name mismatch"; return r; }
    const auto* contract2 = fx.routing().find("list_instances");
    if (!contract2) { r.message = "find(list_instances) returned null"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_routing_extension_find_missing() {
    routing_test_result_t r{"routing_extension_find_missing", false, ""};
    routing_test_fixture_t fx;
    const auto* contract = fx.routing().find("nonexistent_tool_999");
    if (contract != nullptr) { r.message = "expected null for missing tool"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_routing_extension_limits_defaults() {
    routing_test_result_t r{"routing_extension_limits_defaults", false, ""};
    routing_test_fixture_t fx;
    const auto& limits = fx.routing().limits();
    if (limits.max_request_bytes != 1024U * 1024U) { r.message = "max_request_bytes mismatch"; return r; }
    if (limits.max_response_bytes != 16U * 1024U * 1024U) { r.message = "max_response_bytes mismatch"; return r; }
    if (limits.max_expression_bytes != 16384U) { r.message = "max_expression_bytes mismatch"; return r; }
    if (limits.max_function_addresses != 256U) { r.message = "max_function_addresses mismatch"; return r; }
    if (limits.max_instruction_results != 5000U) { r.message = "max_instruction_results mismatch"; return r; }
    if (limits.max_execution_time.count() != 120000) { r.message = "max_execution_time mismatch"; return r; }
    r.passed = true;
    return r;
}

routing_test_result_t test_list_instances_metadata_fields() {
    routing_test_result_t r{"list_instances_metadata_fields", false, ""};
    routing_test_fixture_t fx;
    fx.publish_target(999, "metadata_test.exe");
    auto result = fx.routing().invoke(
        "list_instances", json::object(), fx.make_cancellation());
    if (result.is_error()) { r.message = "list_instances failed"; return r; }
    const auto& structured = result.structured_content();
    auto instances = json_array(structured, "instances");
    if (instances.empty()) { r.message = "expected 1 instance"; return r; }
    const auto& inst = instances[0];
    if (!inst.contains("target_id")) { r.message = "missing target_id field"; return r; }
    if (!inst.contains("pid")) { r.message = "missing pid field"; return r; }
    if (!inst.contains("bin_name")) { r.message = "missing bin_name field"; return r; }
    if (!inst.contains("generation")) { r.message = "missing generation field"; return r; }
    if (!inst.contains("attach_generation")) { r.message = "missing attach_generation field"; return r; }
    if (!inst.contains("live")) { r.message = "missing live field"; return r; }
    if (!inst.contains("process_creation_identity")) { r.message = "missing process_creation_identity field"; return r; }
    if (!inst.contains("revision")) { r.message = "missing revision field"; return r; }
    if (json_int(inst, "pid") != 999) { r.message = "pid mismatch"; return r; }
    if (json_string(inst, "bin_name") != "metadata_test.exe") { r.message = "bin_name mismatch"; return r; }
    const auto& meta = result.aida_metadata();
    if (!meta.contains("resolver_target_count")) { r.message = "missing resolver_target_count in metadata"; return r; }
    if (json_int(meta, "resolver_target_count") != 1) { r.message = "resolver_target_count should be 1"; return r; }
    r.passed = true;
    return r;
}

void register_all_routing_extension_tests(routing_test_harness_t& harness) {
    harness.register_test("metadata_inventory_count", test_metadata_inventory_count);
    harness.register_test("metadata_find_all_extensions", test_metadata_find_all_extensions);
    harness.register_test("metadata_find_archive_tool", test_metadata_find_archive_tool);
    harness.register_test("metadata_find_missing_returns_null", test_metadata_find_missing_returns_null);
    harness.register_test("metadata_effect_fields_for_extensions", test_metadata_effect_fields_for_extensions);
    harness.register_test("metadata_lane_for_extensions", test_metadata_lane_for_extensions);
    harness.register_test("metadata_archive_backed_flag", test_metadata_archive_backed_flag);
    harness.register_test("metadata_is_extension_flag", test_metadata_is_extension_flag);
    harness.register_test("metadata_target_requirement_for_extensions", test_metadata_target_requirement_for_extensions);
    harness.register_test("metadata_count_function", test_metadata_count_function);
    harness.register_test("extension_tool_count", test_extension_tool_count);
    harness.register_test("extension_tool_names_match_constants", test_extension_tool_names_match_constants);
    harness.register_test("union_tool_count_is_92", test_union_tool_count_is_92);
    harness.register_test("archive_tool_count_is_88", test_archive_tool_count_is_88);
    harness.register_test("extension_count_is_4", test_extension_count_is_4);
    harness.register_test("list_instances_empty_resolver", test_list_instances_empty_resolver);
    harness.register_test("list_instances_with_published_target", test_list_instances_with_published_target);
    harness.register_test("list_instances_with_filter", test_list_instances_with_filter);
    harness.register_test("list_instances_multiple_targets", test_list_instances_multiple_targets);
    harness.register_test("list_instances_include_retired_flag", test_list_instances_include_retired_flag);
    harness.register_test("calculator_addition", test_calculator_addition);
    harness.register_test("calculator_subtraction", test_calculator_subtraction);
    harness.register_test("calculator_multiplication", test_calculator_multiplication);
    harness.register_test("calculator_division", test_calculator_division);
    harness.register_test("calculator_modulo", test_calculator_modulo);
    harness.register_test("calculator_hex_literal", test_calculator_hex_literal);
    harness.register_test("calculator_binary_literal", test_calculator_binary_literal);
    harness.register_test("calculator_bitwise_and", test_calculator_bitwise_and);
    harness.register_test("calculator_bitwise_or", test_calculator_bitwise_or);
    harness.register_test("calculator_bitwise_xor", test_calculator_bitwise_xor);
    harness.register_test("calculator_bitwise_not", test_calculator_bitwise_not);
    harness.register_test("calculator_shift_left", test_calculator_shift_left);
    harness.register_test("calculator_shift_right", test_calculator_shift_right);
    harness.register_test("calculator_parentheses", test_calculator_parentheses);
    harness.register_test("calculator_division_by_zero", test_calculator_division_by_zero);
    harness.register_test("calculator_empty_expression", test_calculator_empty_expression);
    harness.register_test("calculator_trailing_tokens", test_calculator_trailing_tokens);
    harness.register_test("calculator_complex_expression", test_calculator_complex_expression);
    harness.register_test("calculate_alias_matches_calculator", test_calculate_alias_matches_calculator);
    harness.register_test("calculate_hex_output", test_calculate_hex_output);
    harness.register_test("analyze_funcs_missing_addrs", test_analyze_funcs_missing_addrs);
    harness.register_test("find_insns_missing_mnemonic", test_find_insns_missing_mnemonic);
    harness.register_test("routing_extension_size", test_routing_extension_size);
    harness.register_test("routing_extension_find_existing", test_routing_extension_find_existing);
    harness.register_test("routing_extension_find_missing", test_routing_extension_find_missing);
    harness.register_test("routing_extension_limits_defaults", test_routing_extension_limits_defaults);
    harness.register_test("list_instances_metadata_fields", test_list_instances_metadata_fields);
}

routing_test_summary_t run_all_routing_extension_tests() {
    routing_test_harness_t harness;
    register_all_routing_extension_tests(harness);
    return harness.run_all();
}

}
