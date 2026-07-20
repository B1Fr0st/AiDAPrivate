#include "survey_handler_harness.hpp"
#include "../c03/assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/workspace/compact_ir.hpp"
#include "../../src/core/mcp/compat/handlers/survey.hpp"
#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::standalone::tests::mcp_compat {

namespace {

using namespace aida::standalone::mcp::compat;
using namespace aida::standalone::mcp::compat::handlers;
namespace protocol = aida::standalone::mcp::protocol;
using protocol::cancellation_token_t;
using protocol::json;

void require(bool condition, std::string_view message) {
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void require_fixture(bool condition, std::string_view category, std::string_view detail) {
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, detail, __FILE__, __LINE__);
    if (!condition) {
        throw std::runtime_error(
            "survey_binary " + std::string(category) + " fixture: " + std::string(detail));
    }
}

aida::analysis::address_t address(std::uint64_t value) {
    aida::analysis::address_t result;
    result.space = aida::analysis::address_space_id_t::virtual_address;
    result.value = value;
    result.architecture = aida::analysis::architecture_id_t::x86_64;
    result.mode = aida::analysis::architecture_mode_t::x86_64;
    return result;
}

struct generation_fixture_t final {
    std::shared_ptr<aida::analysis::workspace_image_t> image;
    std::shared_ptr<aida::analysis::analysis_snapshot_t> analysis;
};

void append_import(aida::analysis::workspace_image_t& image,
                   std::string library,
                   std::string name,
                   std::uint64_t value) {
    aida::analysis::image_import_t item;
    item.library = std::move(library);
    item.name = std::move(name);
    item.lookup_address = address(value - 8);
    item.address = address(value);
    image.imports.push_back(std::move(item));
}

generation_fixture_t make_generation(std::uint64_t generation,
                                     std::uint64_t provider_size) {
    generation_fixture_t fixture;
    fixture.image = std::make_shared<aida::analysis::workspace_image_t>();
    auto& image = *fixture.image;
    image.architecture = aida::analysis::architecture_id_t::x86_64;
    image.architecture_mode = aida::analysis::architecture_mode_t::x86_64;
    image.address_width_bits = 64;
    image.image_base = 0x140000000ULL;
    image.image_size = 0x20000ULL;
    image.provider_source = "C:\\fixtures\\survey\\fixture.exe";
    image.provider_size = provider_size;
    image.provider_content_hash.bytes.fill(0xAAU);
    image.provider_binding_verified = true;

    for (std::uint32_t index = 0; index < 5; ++index) {
        aida::analysis::image_segment_t segment;
        segment.index = index;
        segment.name = ".segment" + std::to_string(index);
        segment.virtual_address = 0x1000ULL * (index + 1ULL);
        segment.virtual_size = 0x800ULL;
        segment.file_offset = 0x100ULL * index;
        segment.file_size = 0x100ULL;
        segment.permissions = aida::analysis::image_permission_read |
            (index == 0 ? aida::analysis::image_permission_execute : 0U);
        image.segments.push_back(std::move(segment));

        aida::analysis::image_entry_point_t entry;
        entry.address = address(image.image_base + 0x1000ULL * (index + 1ULL));
        entry.provenance = "fixture_entry_" + std::to_string(index);
        image.entry_points.push_back(std::move(entry));

        aida::analysis::image_symbol_t symbol;
        symbol.ordinal = index + 1ULL;
        symbol.name = "entry_symbol_" + std::to_string(index);
        symbol.address = address(image.image_base + 0x1000ULL * (index + 1ULL));
        symbol.size = 0x100ULL;
        symbol.kind = aida::analysis::image_symbol_kind_t::function;
        symbol.binding = aida::analysis::image_symbol_binding_t::global;
        symbol.defined = true;
        image.symbols.push_back(std::move(symbol));
    }

    for (std::uint64_t index = 0; index < 4; ++index) {
        append_import(image, "bcrypt.dll", "BCryptHashData" + std::to_string(index),
                      image.image_base + 0x9000ULL + index * 8ULL);
        append_import(image, "ws2_32.dll", "send" + std::to_string(index),
                      image.image_base + 0x9100ULL + index * 8ULL);
    }
    append_import(image, "kernel32.dll", "CreateFileW", image.image_base + 0x9200ULL);
    append_import(image, "kernel32.dll", "CreateProcessW", image.image_base + 0x9210ULL);
    append_import(image, "advapi32.dll", "RegOpenKeyExW", image.image_base + 0x9220ULL);
    append_import(image, "user32.dll", "MessageBoxW", image.image_base + 0x9230ULL);

    fixture.analysis = std::make_shared<aida::analysis::analysis_snapshot_t>();
    auto& analysis = *fixture.analysis;
    analysis.generation = generation;
    analysis.analysis_revision = generation + 100ULL;
    analysis.overlay_revision = generation + 200ULL;
    analysis.baseline_complete = true;
    analysis.normalized_image = fixture.image;

    for (std::uint64_t index = 0; index < 5; ++index) {
        const std::uint64_t function_address = image.image_base + 0x1000ULL * (index + 1ULL);
        aida::analysis::symbol_record_t symbol;
        symbol.id = 100ULL + index;
        symbol.address = address(function_address);
        symbol.name = index == 4 ? "sub_140005000" : "fixture_function_" + std::to_string(index);
        symbol.kind = index == 3
            ? aida::analysis::symbol_kind_t::import_symbol
            : aida::analysis::symbol_kind_t::function;
        analysis.symbols.push_back(std::move(symbol));

        aida::analysis::function_record_t function;
        function.id = index + 1ULL;
        function.start = address(function_address);
        function.end = address(function_address + 0x100ULL);
        function.block_count = static_cast<std::uint32_t>(index + 1ULL);
        function.symbol_id = 100ULL + index;
        function.thunk = index == 3;
        analysis.functions.push_back(std::move(function));

        aida::analysis::string_record_t string;
        string.id = 200ULL + index;
        string.address = address(image.image_base + 0xA000ULL + index * 0x100ULL);
        string.byte_length = 16;
        string.value = "fixture_string_" + std::to_string(index);
        analysis.strings.push_back(std::move(string));
    }

    std::uint64_t xref_id = 300;
    for (std::size_t target = 0; target < analysis.functions.size(); ++target) {
        for (std::size_t rank = target; rank < analysis.functions.size(); ++rank) {
            aida::analysis::xref_record_t xref;
            xref.id = xref_id++;
            xref.source = address(image.image_base + 0xB000ULL + xref.id);
            xref.target = analysis.functions[target].start;
            xref.kind = aida::analysis::xref_kind_t::call;
            analysis.xrefs.push_back(std::move(xref));
        }
        aida::analysis::xref_record_t string_xref;
        string_xref.id = xref_id++;
        string_xref.source = address(image.image_base + 0xC000ULL + string_xref.id);
        string_xref.target = analysis.strings[target].address;
        string_xref.kind = aida::analysis::xref_kind_t::read;
        analysis.xrefs.push_back(std::move(string_xref));
    }

    aida::analysis::edge_record_t edge;
    edge.id = 500;
    edge.source_entity = analysis.functions[0].id;
    edge.target_entity = analysis.functions[1].id;
    edge.source = address(analysis.functions[0].start.value + 8ULL);
    edge.target = analysis.functions[1].start;
    edge.kind = aida::analysis::edge_kind_t::call;
    analysis.edges.push_back(std::move(edge));
    return fixture;
}

survey_generation_lease_t make_lease(std::uint32_t pid,
                                     std::string workspace_id,
                                     std::string bin_name,
                                     const generation_fixture_t& fixture,
                                     bool live = false,
                                     bool live_current = true) {
    survey_generation_lease_t lease;
    lease.owner = std::make_shared<std::uint64_t>(fixture.analysis->generation);
    lease.identity.workspace_id = std::move(workspace_id);
    lease.identity.pid = pid;
    lease.identity.bin_name = std::move(bin_name);
    lease.identity.normalized_source_path =
        "C:\\fixtures\\survey\\" + lease.identity.bin_name;
    lease.identity.sha256.assign(64, 'a');
    lease.identity.md5 = std::string(32, 'b');
    lease.identity.generation = fixture.analysis->generation;
    lease.identity.analysis_revision = fixture.analysis->analysis_revision;
    lease.identity.overlay_revision = fixture.analysis->overlay_revision;
    lease.identity.live = live;
    lease.identity.live_snapshot_current = live_current;
    lease.image = fixture.image;
    lease.analysis = fixture.analysis;
    return lease;
}

survey_generation_lease_t make_metadata_only_lease(std::uint32_t pid,
                                                   std::uint64_t generation) {
    survey_generation_lease_t lease;
    lease.owner = std::make_shared<std::uint64_t>(generation);
    lease.identity.workspace_id = "workspace-metadata-only";
    lease.identity.pid = pid;
    lease.identity.bin_name = "metadata-only.exe";
    lease.identity.normalized_source_path = "C:\\fixtures\\metadata-only.exe";
    lease.identity.sha256.assign(64, 'c');
    lease.identity.generation = generation;
    lease.identity.analysis_revision = generation + 100ULL;
    lease.identity.overlay_revision = generation + 200ULL;
    return lease;
}

struct lease_state_t final {
    std::vector<survey_generation_lease_t> leases;
    std::size_t calls = 0;
    target_selector_t last_selector;

    adapter_result_t<survey_generation_lease_t> acquire(
        const target_selector_t& selector,
        std::optional<std::chrono::steady_clock::time_point> deadline) {
        ++calls;
        last_selector = selector;
        if (!deadline || *deadline <= std::chrono::steady_clock::now()) {
            return adapter_result_t<survey_generation_lease_t>::failure({
                adapter_error_code_t::backend_unavailable,
                "fixture_deadline_invalid", 1, 0});
        }
        const survey_generation_lease_t* match = nullptr;
        for (const auto& lease : leases) {
            const bool pid_match = !selector.pid || lease.identity.pid == selector.pid;
            const bool name_match = !selector.bin_name ||
                lease.identity.bin_name.find(*selector.bin_name) != std::string::npos;
            if (!pid_match || !name_match) {
                continue;
            }
            if (match != nullptr) {
                return adapter_result_t<survey_generation_lease_t>::failure({
                    adapter_error_code_t::target_resolution_failed,
                    "fixture_target_ambiguous", 1, 2});
            }
            match = &lease;
        }
        if (match == nullptr) {
            return adapter_result_t<survey_generation_lease_t>::failure({
                adapter_error_code_t::target_resolution_failed,
                "fixture_target_not_found", 1, 0});
        }
        return adapter_result_t<survey_generation_lease_t>::success(*match);
    }
};

survey_generation_acquire_t acquire_from(lease_state_t& state) {
    return [&state](const target_selector_t& selector,
                    std::optional<std::chrono::steady_clock::time_point> deadline) {
        return state.acquire(selector, deadline);
    };
}

survey_handler_limits_t fixture_limits() {
    survey_handler_limits_t limits;
    limits.max_static_items = 3;
    limits.max_collection_items = 2;
    limits.max_live_items = 1;
    limits.max_text_bytes = 64;
    limits.max_analysis_index_items = 32;
    limits.max_analysis_scan_items = 128;
    limits.max_live_snapshot_bytes = 4096;
    return limits;
}

bool has_diagnostic(const protocol::mcp_result_t& result,
                    std::string_view code,
                    std::string_view section = {}) {
    const auto diagnostics = result.aida_metadata().find("diagnostics");
    if (diagnostics == result.aida_metadata().end() || !diagnostics->is_array()) {
        return false;
    }
    for (const auto& diagnostic : *diagnostics) {
        if (diagnostic.value("code", std::string()) == std::string(code) &&
            (section.empty() ||
             diagnostic.value("section", std::string()) == std::string(section))) {
            return true;
        }
    }
    return false;
}

void require_generated_output(const survey_handlers_t& handlers,
                              protocol::schema_runtime_t& schemas,
                              const protocol::mcp_result_t& result,
                              std::string_view category) {
    require_fixture(!result.is_error(), category, result.text());
    require_fixture(
        schemas.validate(handlers.contract_at(0).output_schema,
                         result.structured_content()).valid,
        category, "result does not satisfy the generated output schema");
    require_fixture(
        result.aida_metadata().value("output_schema_source", std::string()) == "generated" &&
            result.aida_metadata().value("output_schema_validation", std::string()) == "passed",
        category, "generated output-validation metadata is absent");
}

void verify_generated_contract(const survey_handlers_t& handlers,
                               protocol::schema_runtime_t& schemas,
                               std::size_t& completed) {
    require_fixture(handlers.size() == 1 && survey_tool_names().size() == 1 &&
                        survey_tool_names()[0] == "survey_binary",
                    "generated_contract", "tool inventory is not an exact singleton");
    const auto* descriptor = find_contract("survey_binary");
    require_fixture(descriptor != nullptr,
                    "generated_contract", "generated descriptor is absent");
    require_fixture(descriptor->adapter_symbol ==
                        "aida::standalone::mcp::compat::adapters::survey_binary" &&
                        descriptor->target_dependent && descriptor->accepts_pid &&
                        descriptor->accepts_bin_name && descriptor->read_only &&
                        !descriptor->unsafe,
                    "generated_contract", "generated survey adapter policy is incorrect");
    const auto& contract = handlers.contract_at(0);
    require_fixture(contract.input_schema == json::parse(
                        descriptor->input_schema_json.begin(),
                        descriptor->input_schema_json.end()) &&
                        contract.output_schema == json::parse(
                            descriptor->output_schema_json.begin(),
                            descriptor->output_schema_json.end()) &&
                        contract.annotations == json::parse(
                            descriptor->annotations_json.begin(),
                            descriptor->annotations_json.end()),
                    "generated_contract", "handler contract differs from generated JSON");
    require_fixture(contract.target_policy.requirement ==
                        protocol::target_requirement_t::optional &&
                        contract.target_policy.accepts_pid &&
                        contract.target_policy.accepts_bin_name,
                    "generated_contract", "generated target policy was not preserved");
    require_fixture(contract.effect_policy.effect == protocol::tool_effect_t::workspace_read &&
                        contract.effect_policy.lock == protocol::effect_lock_t::workspace_shared &&
                        contract.effect_policy.read_only && !contract.effect_policy.unsafe,
                    "generated_contract", "generated effect policy was not preserved");
    require_fixture(protocol::validate_tool_contract(contract, schemas).valid,
                    "generated_contract", "generated contract does not compile");
    const auto& properties = contract.output_schema.at("properties");
    for (const char* name : {
            "_note", "metadata", "segments", "entrypoints", "imports_by_category",
            "statistics", "interesting_functions", "interesting_strings",
            "call_graph_summary"}) {
        require_fixture(properties.contains(name),
                        "generated_contract", "generated output property is absent");
    }
    ++completed;
}

void verify_static_and_collection_caps(survey_handlers_t& handlers,
                                       lease_state_t& state,
                                       protocol::schema_runtime_t& schemas,
                                       std::size_t& completed) {
    const json metadata{{"fixture", "immutable_static"}};
    auto result = adapters::survey_binary(
        handlers, json{{"pid", 4101}, {"detail_level", "standard"}},
        cancellation_token_t::create(), metadata);
    require_generated_output(handlers, schemas, result, "static_collection_caps");
    const auto& output = result.structured_content();
    require_fixture(output.at("segments").size() == 3 &&
                        output.at("entrypoints").size() == 3,
                    "static_collection_caps", "static summary caps were not exact");
    require_fixture(output.at("interesting_functions").size() == 2 &&
                        output.at("interesting_strings").size() == 2 &&
                        output.at("imports_by_category").at("crypto").size() == 2 &&
                        output.at("imports_by_category").at("network").size() == 2 &&
                        output.at("call_graph_summary").at("root_functions").size() == 2,
                    "static_collection_caps", "collection caps were not exact");
    require_fixture(output.at("statistics").at("total_functions") == 5 &&
                        output.at("statistics").at("total_strings") == 5 &&
                        output.at("statistics").at("total_segments") == 5,
                    "static_collection_caps", "uncapped generation totals are incorrect");
    require_fixture(has_diagnostic(result, "static_cap_applied", "segments") &&
                        has_diagnostic(result, "collection_cap_applied", "interesting_functions") &&
                        has_diagnostic(result, "collection_cap_applied", "interesting_strings") &&
                        result.aida_metadata().value("partial", false),
                    "static_collection_caps", "partial cap diagnostics are absent");
    require_fixture(result.aida_metadata().at("workspace_id") == "workspace-static" &&
                        result.aida_metadata().at("generation") == 41 &&
                        result.aida_metadata().at("generation_lease") == "local_immutable" &&
                        result.aida_metadata().at("fixture") == "immutable_static" &&
                        state.last_selector.pid == std::optional<std::uint32_t>(4101),
                    "static_collection_caps", "immutable generation provenance is absent");
    ++completed;
}

void verify_target_routing_and_partial_image(survey_handlers_t& handlers,
                                             lease_state_t& state,
                                             protocol::schema_runtime_t& schemas,
                                             std::size_t& completed) {
    auto result = adapters::survey_binary(
        handlers, json{{"bin_name", "beta.exe"}}, cancellation_token_t::create());
    require_generated_output(handlers, schemas, result, "target_partial");
    require_fixture(result.structured_content().contains("metadata") &&
                        !result.structured_content().contains("statistics") &&
                        has_diagnostic(result, "analysis_unavailable", "analysis") &&
                        state.last_selector.bin_name == std::optional<std::string>("beta.exe") &&
                        result.aida_metadata().at("workspace_id") == "workspace-beta",
                    "target_partial", "bin_name route did not return a local partial summary");
    ++completed;
}

void verify_live_caps(survey_handlers_t& handlers,
                      protocol::schema_runtime_t& schemas,
                      std::size_t& completed) {
    auto current = adapters::survey_binary(
        handlers, json{{"pid", 4103}}, cancellation_token_t::create());
    require_generated_output(handlers, schemas, current, "live_caps");
    const auto& output = current.structured_content();
    require_fixture(output.at("segments").size() == 1 &&
                        output.at("entrypoints").size() == 1 &&
                        output.at("interesting_functions").size() == 1 &&
                        output.at("interesting_strings").size() == 1 &&
                        output.at("imports_by_category").at("crypto").size() == 1 &&
                        current.aida_metadata().at("target_kind") == "live_snapshot",
                    "live_caps", "live item cap was not applied across summary sections");

    auto stale = adapters::survey_binary(
        handlers, json{{"pid", 4104}}, cancellation_token_t::create());
    require_generated_output(handlers, schemas, stale, "live_caps");
    require_fixture(!stale.structured_content().contains("statistics") &&
                        !stale.structured_content().contains("interesting_functions") &&
                        has_diagnostic(stale, "live_snapshot_stale", "live") &&
                        has_diagnostic(stale, "live_snapshot_cap", "live"),
                    "live_caps", "stale oversized live snapshot was not partially summarized");
    ++completed;
}

void verify_missing_generation_sections(survey_handlers_t& handlers,
                                        protocol::schema_runtime_t& schemas,
                                        std::size_t& completed) {
    auto result = adapters::survey_binary(
        handlers, json{{"pid", 4105}}, cancellation_token_t::create());
    require_generated_output(handlers, schemas, result, "missing_sections");
    require_fixture(result.structured_content().size() == 1 &&
                        result.structured_content().contains("_note") &&
                        has_diagnostic(result, "metadata_unavailable", "image") &&
                        has_diagnostic(result, "analysis_unavailable", "analysis"),
                    "missing_sections", "metadata-only generation did not return diagnostics-only output");
    ++completed;
}

void verify_source_scan_cap(const survey_generation_lease_t& lease,
                            protocol::schema_runtime_t& schemas,
                            std::size_t& completed) {
    lease_state_t state;
    state.leases.push_back(lease);
    auto limits = fixture_limits();
    limits.max_analysis_scan_items = 2;
    survey_handlers_t handlers(acquire_from(state), schemas, limits);
    auto result = adapters::survey_binary(
        handlers, json{{"pid", 4101}}, cancellation_token_t::create());
    require_generated_output(handlers, schemas, result, "source_scan_cap");
    require_fixture(result.structured_content().at("segments").size() == 2 &&
                        result.structured_content().at("entrypoints").size() == 2 &&
                        has_diagnostic(result, "source_scan_cap", "segments") &&
                        has_diagnostic(result, "source_scan_cap", "entrypoints") &&
                        has_diagnostic(result, "source_scan_cap", "imports") &&
                        has_diagnostic(result, "analysis_scan_cap", "xrefs") &&
                        !result.structured_content().contains("statistics"),
                    "source_scan_cap", "bounded source scan did not emit partial diagnostics");
    ++completed;
}

void verify_analysis_index_cap(const survey_generation_lease_t& lease,
                               protocol::schema_runtime_t& schemas,
                               std::size_t& completed) {
    lease_state_t state;
    state.leases.push_back(lease);
    auto limits = fixture_limits();
    limits.max_analysis_index_items = 4;
    survey_handlers_t handlers(acquire_from(state), schemas, limits);
    auto result = adapters::survey_binary(
        handlers, json{{"pid", 4101}}, cancellation_token_t::create());
    require_generated_output(handlers, schemas, result, "analysis_index_cap");
    require_fixture(has_diagnostic(result, "analysis_index_cap", "functions") &&
                        has_diagnostic(result, "analysis_index_cap", "image_symbols") &&
                        !result.structured_content().contains("statistics"),
                    "analysis_index_cap", "oversized analysis index was not omitted");
    ++completed;
}

void verify_response_cap(const survey_generation_lease_t& lease,
                         protocol::schema_runtime_t& schemas,
                         std::size_t& completed) {
    lease_state_t state;
    state.leases.push_back(lease);
    auto limits = fixture_limits();
    limits.max_response_bytes = 512;
    survey_handlers_t handlers(acquire_from(state), schemas, limits);
    auto result = adapters::survey_binary(
        handlers, json{{"pid", 4101}}, cancellation_token_t::create());
    require_generated_output(handlers, schemas, result, "response_cap");
    require_fixture(result.structured_content().size() == 1 &&
                        result.structured_content().contains("_note") &&
                        has_diagnostic(result, "response_cap", "output") &&
                        result.aida_metadata().at("output_bytes").get<std::size_t>() <=
                            limits.max_response_bytes,
                    "response_cap", "response cap did not reduce output to diagnostics");
    ++completed;
}

void verify_invalid_lease(const survey_generation_lease_t& valid,
                          protocol::schema_runtime_t& schemas,
                          std::size_t& completed) {
    lease_state_t state;
    auto invalid = valid;
    invalid.identity.generation += 1;
    state.leases.push_back(std::move(invalid));
    survey_handlers_t handlers(acquire_from(state), schemas, fixture_limits());
    auto result = adapters::survey_binary(
        handlers, json{{"pid", 4101}}, cancellation_token_t::create());
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_HANDLER_FAILED" &&
                        result.structured_content().at("error").at("details").at("reason") ==
                            "immutable_generation_mismatch",
                    "invalid_lease", "mismatched immutable generation was accepted");
    ++completed;
}

void verify_input_routing_and_cancellation(survey_handlers_t& handlers,
                                           lease_state_t& state,
                                           std::size_t& completed) {
    const std::size_t before = state.calls;
    auto ambiguous_selector = adapters::survey_binary(
        handlers, json{{"pid", 4101}, {"bin_name", "fixture.exe"}},
        cancellation_token_t::create());
    auto invalid_detail = adapters::survey_binary(
        handlers, json{{"pid", 4101}, {"detail_level", "full"}},
        cancellation_token_t::create());
    auto cancelled = adapters::survey_binary(
        handlers, json{{"pid", 4101}}, cancellation_token_t::create(true));
    require_fixture(ambiguous_selector.is_error() &&
                        ambiguous_selector.error_code() == "MCP_TOOL_INPUT_INVALID" &&
                        invalid_detail.is_error() &&
                        invalid_detail.error_code() == "MCP_TOOL_INPUT_INVALID" &&
                        cancelled.is_error() &&
                        cancelled.error_code() == "MCP_TOOL_CANCELLED" &&
                        state.calls == before,
                    "input_cancellation", "invalid or cancelled input reached lease acquisition");

    auto ambiguous_target = adapters::survey_binary(
        handlers, json::object(), cancellation_token_t::create());
    require_fixture(ambiguous_target.is_error() &&
                        ambiguous_target.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED" &&
                        ambiguous_target.structured_content().at("error").at("details").at(
                            "adapter_code") == "fixture_target_ambiguous",
                    "input_cancellation", "ambiguous default target was not rejected");
    auto invalid_metadata = adapters::survey_binary(
        handlers, json{{"pid", 4101}}, cancellation_token_t::create(), json::array());
    require_fixture(invalid_metadata.is_error() &&
                        invalid_metadata.error_code() == "MCP_TOOL_INTERNAL_ERROR",
                    "input_cancellation", "non-object provenance metadata was accepted");
    ++completed;
}

void verify_survey_handler() {
    protocol::schema_runtime_t schemas(64);
    const auto static_generation = make_generation(41, 2048);
    const auto beta_generation = make_generation(51, 2048);
    const auto live_generation = make_generation(61, 2048);
    const auto stale_live_generation = make_generation(71, 8192);

    lease_state_t state;
    state.leases.push_back(make_lease(
        4101, "workspace-static", "fixture.exe", static_generation));
    auto beta = make_lease(
        4102, "workspace-beta", "beta.exe", beta_generation);
    beta.analysis.reset();
    state.leases.push_back(std::move(beta));
    state.leases.push_back(make_lease(
        4103, "workspace-live", "live.exe", live_generation, true, true));
    state.leases.push_back(make_lease(
        4104, "workspace-stale-live", "stale-live.exe",
        stale_live_generation, true, false));
    state.leases.push_back(make_metadata_only_lease(4105, 81));

    survey_handlers_t handlers(acquire_from(state), schemas, fixture_limits());
    std::size_t completed = 0;
    verify_generated_contract(handlers, schemas, completed);
    verify_static_and_collection_caps(handlers, state, schemas, completed);
    verify_target_routing_and_partial_image(handlers, state, schemas, completed);
    verify_live_caps(handlers, schemas, completed);
    verify_missing_generation_sections(handlers, schemas, completed);
    verify_source_scan_cap(state.leases[0], schemas, completed);
    verify_analysis_index_cap(state.leases[0], schemas, completed);
    verify_response_cap(state.leases[0], schemas, completed);
    verify_invalid_lease(state.leases[0], schemas, completed);
    verify_input_routing_and_cancellation(handlers, state, completed);
    require(completed == 10,
            "survey handler harness did not execute all ten fixture families");
}

}

bool run_survey_handler_harness(std::string& failure) {
    try {
        verify_survey_handler();
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
