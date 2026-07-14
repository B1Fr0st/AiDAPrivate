#include "workbench_shell_lifecycle_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/workspace/analysis_metrics.hpp"
#include "../../src/core/analysis/workspace/analysis_workspace.hpp"
#include "../../src/core/analysis/workspace/byte_provider.hpp"
#include "../../src/core/analysis/workspace/overlay_journal.hpp"
#include "../../src/core/analysis/workspace/search_index.hpp"
#include "../../src/core/analysis/workspace/workspace_database.hpp"
#include "../../src/core/workbench/workbench_shell_integration.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace aida::workbench {
namespace {

void require(bool condition, const char* message)
{
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

void require(bool condition, const std::string& message)
{
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

void verify_managed_entity_locators()
{
    struct case_t final {
        const char* encoded;
        analysis::decompiler_entity_kind_t kind;
        std::uint32_t token;
        std::uint32_t artifact;
    };
    const case_t valid[] = {
        {"cli:0@0", analysis::decompiler_entity_kind_t::cli_method, 0, 0},
        {"jvm:1@2", analysis::decompiler_entity_kind_t::jvm_method, 1, 2},
        {"dalvik:4294967295@4294967295",
         analysis::decompiler_entity_kind_t::dalvik_method,
         0xFFFFFFFFU, 0xFFFFFFFFU},
    };
    for (const auto& item : valid) {
        const auto parsed = pseudocode_document::parse_pseudocode_entity_locator(
            item.encoded);
        require(parsed && parsed->token == item.token &&
                    parsed->artifact_ordinal == item.artifact &&
                    parsed->expected_kind == item.kind && !parsed->address,
                "managed pseudocode locator parse changed identity");
        const auto canonical =
            pseudocode_document::canonical_pseudocode_entity_locator(*parsed);
        require(canonical && *canonical == item.encoded,
                "managed pseudocode locator did not round-trip canonically");
    }
    for (const char* invalid : {
             "", "CLI:1@0", "cli:1", "cli:@0", "cli:1@", "cli:1@0@0",
             "cli:-1@0", "cli:+1@0", "cli:01@0", "jvm:1@02",
             "dalvik:4294967296@0", "native:1@0", "cli:1@0 "})
        require(!pseudocode_document::parse_pseudocode_entity_locator(invalid),
                "malformed managed pseudocode locator was accepted");

    analysis::decompiler_entity_locator_t mixed;
    mixed.address = 0x1000;
    mixed.token = 1;
    mixed.artifact_ordinal = 0;
    mixed.expected_kind = analysis::decompiler_entity_kind_t::cli_method;
    require(!pseudocode_document::canonical_pseudocode_entity_locator(mixed),
            "mixed native/managed pseudocode locator was canonicalized");
}

class cancellation_t final
    : public disasm_document::disasm_cancellation_t,
      public hex_document::hex_cancellation_t,
      public graph_document::graph_layout_cancellation_t,
      public diff_document::diff_cancellation_t,
      public navigator::navigator_cancellation_t {
public:
    explicit cancellation_t(bool cancelled = false) noexcept
        : cancelled_(cancelled)
    {
    }

    bool cancelled() const noexcept override { return cancelled_; }

private:
    bool cancelled_ = false;
};

std::filesystem::path unique_path(const char* stem, const char* extension)
{
    static std::atomic<std::uint64_t> sequence{1};
    const auto ordinal = sequence.fetch_add(1, std::memory_order_relaxed);
    const auto tick = static_cast<std::uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    return std::filesystem::temp_directory_path() /
        (std::string(stem) + "-" + std::to_string(tick) + "-" +
         std::to_string(ordinal) + extension);
}

void remove_database_files(const std::string& path) noexcept
{
    if (path.empty())
        return;
    std::error_code error;
    const auto database = std::filesystem::u8path(path);
    std::filesystem::remove(database, error);
    error.clear();
    std::filesystem::remove(std::filesystem::u8path(path + "-wal"), error);
    error.clear();
    std::filesystem::remove(std::filesystem::u8path(path + "-shm"), error);
}

struct fixture_asset_t final {
    std::filesystem::path source_path;
    std::string database_path;

    ~fixture_asset_t()
    {
        remove_database_files(database_path);
        if (!source_path.empty()) {
            std::error_code error;
            std::filesystem::remove(source_path, error);
        }
    }
};

struct workspace_handle_t final {
    std::shared_ptr<const analysis::workspace_identity_t> identity;
    std::shared_ptr<analysis::mapped_file_provider_t> provider;
    std::shared_ptr<analysis::analysis_workspace_t> workspace;
    std::shared_ptr<analysis::workspace_database_t> database;
    std::shared_ptr<analysis::overlay_journal_t> overlay;
};

analysis::address_t rva(std::uint64_t value)
{
    return {analysis::address_space_id_t::relative_virtual, value,
            analysis::architecture_id_t::x86_64,
            analysis::architecture_mode_t::x86_64};
}

std::shared_ptr<const analysis::workspace_image_t> image_template(
    std::uint64_t provider_size)
{
    auto image = std::make_shared<analysis::workspace_image_t>();
    image->format = analysis::format_id_t::pe32_plus;
    image->architecture = analysis::architecture_id_t::x86_64;
    image->architecture_mode = analysis::architecture_mode_t::x86_64;
    image->abi = analysis::abi_id_t::windows_x64;
    image->endian = analysis::endian_t::little;
    image->address_width_bits = 64;
    image->image_base = 0x140000000ULL;
    image->image_size = 0x2000;
    image->header_size = 0;
    image->format_name = "PE32+ lifecycle fixture";
    image->provider_size = provider_size;

    analysis::image_address_mapping_t mapping;
    mapping.source_space = analysis::address_space_id_t::file_offset;
    mapping.target_space = analysis::address_space_id_t::relative_virtual;
    mapping.source_start = 0;
    mapping.target_start = 0x1000;
    mapping.size = provider_size;
    mapping.permissions = analysis::image_permission_read |
                          analysis::image_permission_execute;
    image->address_mappings.push_back(mapping);

    analysis::image_section_t section;
    section.index = 0;
    section.name = ".text";
    section.virtual_address = 0x1000;
    section.virtual_size = provider_size;
    section.file_offset = 0;
    section.file_size = provider_size;
    section.permissions = analysis::image_permission_read |
                          analysis::image_permission_execute;
    image->sections.push_back(section);

    analysis::image_entry_point_t entry;
    entry.address = rva(0x1000);
    entry.provenance = "fixture";
    image->entry_points.push_back(entry);

    analysis::image_import_t imported;
    imported.library = "kernel32.dll";
    imported.name = "ExitProcess";
    imported.lookup_address = rva(0x1018);
    imported.address = rva(0x1018);
    image->imports.push_back(imported);

    analysis::image_export_t exported;
    exported.name = "fixture_entry";
    exported.ordinal = 1;
    exported.address = rva(0x1000);
    image->exports.push_back(exported);
    return image;
}

std::shared_ptr<analysis::analysis_snapshot_t> make_snapshot(
    const workspace_handle_t& handle, std::uint64_t generation,
    std::uint64_t analysis_revision, std::string symbol_name,
    std::string string_value)
{
    auto snapshot = std::make_shared<analysis::analysis_snapshot_t>();
    snapshot->binary_id = handle.identity->binary_id();
    snapshot->load_profile_hash = handle.identity->load_profile_hash();
    snapshot->generation = generation;
    snapshot->analysis_revision = analysis_revision;
    snapshot->overlay_revision = handle.workspace->overlay_revision();
    snapshot->baseline_complete = false;
    snapshot->normalized_image = handle.workspace->normalized_image();

    analysis::instruction_record_t first_instruction;
    first_instruction.id = 0x1001;
    first_instruction.address = rva(0x1000);
    first_instruction.length = 1;
    first_instruction.mnemonic_id = 1;
    first_instruction.opcode_id = 1;
    first_instruction.flow_flags = analysis::flow_fallthrough;
    first_instruction.provenance = analysis::fact_provenance_t::recursive_decode;
    first_instruction.confidence = 100;
    first_instruction.coverage = analysis::coverage_reason_t::decoded;
    first_instruction.stable_source_id = 0x1000;
    snapshot->instructions.push_back(first_instruction);

    analysis::instruction_record_t second_instruction;
    second_instruction.id = 0x1002;
    second_instruction.address = rva(0x1001);
    second_instruction.length = 1;
    second_instruction.mnemonic_id = 2;
    second_instruction.opcode_id = 2;
    second_instruction.flow_flags = analysis::flow_return |
                                    analysis::flow_terminal;
    second_instruction.provenance = analysis::fact_provenance_t::recursive_decode;
    second_instruction.confidence = 100;
    second_instruction.coverage = analysis::coverage_reason_t::decoded;
    second_instruction.stable_source_id = 0x1001;
    snapshot->instructions.push_back(second_instruction);

    analysis::basic_block_record_t first_block;
    first_block.id = 0x2001;
    first_block.function_id = 0x3001;
    first_block.start = rva(0x1000);
    first_block.end = rva(0x1001);
    first_block.first_instruction = 0;
    first_block.instruction_count = 1;
    first_block.provenance = analysis::fact_provenance_t::recursive_decode;
    first_block.confidence = 100;
    snapshot->blocks.push_back(first_block);

    analysis::basic_block_record_t second_block;
    second_block.id = 0x2002;
    second_block.function_id = 0x3001;
    second_block.start = rva(0x1001);
    second_block.end = rva(0x1002);
    second_block.first_instruction = 1;
    second_block.instruction_count = 1;
    second_block.provenance = analysis::fact_provenance_t::recursive_decode;
    second_block.confidence = 100;
    snapshot->blocks.push_back(second_block);

    analysis::function_record_t function;
    function.id = 0x3001;
    function.start = rva(0x1000);
    function.end = rva(0x1002);
    function.first_block = 0;
    function.block_count = 2;
    function.symbol_id = 0x5001;
    function.provenance = analysis::fact_provenance_t::recursive_decode;
    function.confidence = 100;
    snapshot->functions.push_back(function);

    analysis::edge_record_t edge;
    edge.id = 0x4001;
    edge.source_entity = first_block.id;
    edge.target_entity = second_block.id;
    edge.source = first_block.start;
    edge.target = second_block.start;
    edge.kind = analysis::edge_kind_t::fallthrough;
    edge.provenance = analysis::fact_provenance_t::recursive_decode;
    edge.confidence = 100;
    snapshot->edges.push_back(edge);

    analysis::call_graph_node_record_t call_node;
    call_node.function_id = function.id;
    call_node.address = function.start;
    snapshot->call_graph.nodes.push_back(call_node);
    snapshot->call_graph.bounded = true;

    analysis::symbol_record_t symbol;
    symbol.id = 0x5001;
    symbol.address = function.start;
    symbol.name = std::move(symbol_name);
    symbol.kind = analysis::symbol_kind_t::function;
    symbol.provenance = analysis::fact_provenance_t::debug_symbol;
    symbol.confidence = 100;
    snapshot->symbols.push_back(std::move(symbol));

    analysis::string_record_t string_record;
    string_record.id = 0x6001;
    string_record.address = rva(0x1008);
    string_record.byte_length = string_value.size();
    string_record.encoding = analysis::string_encoding_t::ascii;
    string_record.value = std::move(string_value);
    string_record.provenance = analysis::fact_provenance_t::linear_validation;
    string_record.confidence = 100;
    snapshot->strings.push_back(std::move(string_record));
    return snapshot;
}

void publish_snapshot(workspace_handle_t& handle, std::string symbol_name,
                      std::string string_value)
{
    const auto generation = handle.workspace->generation();
    const auto expected_revision = handle.workspace->analysis_revision();
    auto snapshot = make_snapshot(handle, generation, expected_revision + 1,
                                  std::move(symbol_name),
                                  std::move(string_value));
    auto metrics = std::make_shared<analysis::analysis_metrics_t>(generation);
    auto index = analysis::search_index_t::build(
        std::shared_ptr<const analysis::analysis_snapshot_t>(snapshot), {}, {}, {},
        metrics, {}, {});
    if (!index)
        throw std::runtime_error(std::string("search index build failed: ") +
                                 index.error().message);
    auto published = handle.workspace->publish_analysis_bundle(
        generation, expected_revision,
        std::shared_ptr<const analysis::analysis_snapshot_t>(snapshot),
        index.take_value(), false);
    if (!published)
        throw std::runtime_error(std::string("analysis publication failed: ") +
                                 published.error().message);
}

workspace_handle_t open_workspace(fixture_asset_t& asset,
                                  const std::string& fixture_name)
{
    workspace_handle_t handle;
    auto provider = analysis::mapped_file_provider_t::open(
        asset.source_path.u8string());
    if (!provider)
        throw std::runtime_error(std::string("provider open failed: ") +
                                 provider.error().message);
    handle.provider = provider.take_value();
    auto content_hash = handle.provider->compute_content_sha256();
    auto profile_hash = analysis::sha256_text(
        "workbench-shell-lifecycle:" + fixture_name + ":" +
        asset.source_path.u8string());
    require(content_hash.has_value() && profile_hash.has_value(),
            "workspace hashes were not created");

    analysis::workspace_identity_input_t identity_input;
    identity_input.bin_name = fixture_name + ".bin";
    identity_input.source_path = handle.provider->identity().normalized_source;
    identity_input.content_hash = content_hash.take_value();
    identity_input.load_profile_hash = profile_hash.take_value();
    identity_input.target_kind = analysis::target_kind_t::static_file;
    identity_input.format = analysis::format_id_t::pe32_plus;
    identity_input.architecture = analysis::architecture_id_t::x86_64;
    identity_input.architecture_mode = analysis::architecture_mode_t::x86_64;
    identity_input.abi = analysis::abi_id_t::windows_x64;
    identity_input.endian = analysis::endian_t::little;
    identity_input.image_base = 0x140000000ULL;
    auto identity = analysis::make_workspace_identity(std::move(identity_input));
    if (!identity)
        throw std::runtime_error(std::string("workspace identity failed: ") +
                                 identity.error().message);
    handle.identity = identity.take_value();

    auto workspace = analysis::analysis_workspace_t::create_normalized(
        handle.identity,
        std::static_pointer_cast<const analysis::byte_provider_t>(handle.provider),
        image_template(handle.provider->size()));
    if (!workspace)
        throw std::runtime_error(std::string("workspace creation failed: ") +
                                 workspace.error().message);
    handle.workspace = workspace.take_value();

    analysis::workspace_database_options_t options;
    options.identity = handle.identity;
    options.versions.engine_version = "workbench-shell-lifecycle-harness";
    options.versions.specification_version = "schema-v9";
    options.versions.analysis_settings_hash =
        handle.identity->load_profile_hash().to_hex();
    options.candidate_operation_timeout_ms = 10000;
    auto database = analysis::workspace_database_t::open(std::move(options));
    if (!database)
        throw std::runtime_error(std::string("workspace database failed: ") +
                                 database.error().message);
    handle.database = database.take_value();
    asset.database_path = handle.database->path();
    auto registered = handle.workspace->register_lifecycle_participant(
        handle.database);
    require(registered.has_value(), "database lifecycle registration failed");
    auto installed = handle.workspace->install_database(handle.database);
    require(installed.has_value(), "database installation failed");
    if (const auto queue = handle.database->queue()) {
        registered = handle.workspace->register_lifecycle_participant(queue);
        require(registered.has_value(), "persistence queue registration failed");
        installed = handle.workspace->install_persistence_queue(queue);
        require(installed.has_value(), "persistence queue installation failed");
    }
    auto overlay = analysis::overlay_journal_t::open(
        handle.workspace, handle.database);
    if (!overlay)
        throw std::runtime_error(std::string("overlay open failed: ") +
                                 overlay.error().message);
    handle.overlay = overlay.take_value();
    return handle;
}

void close_workspace(workspace_handle_t& handle, bool close_shell = true)
{
    if (close_shell && handle.workspace) {
        const auto closed = workbench_shell_runtime_t::instance()
            .close_analysis_workspace(handle.workspace);
        require(closed.ok(), "workbench shell close did not persist state");
    }
    if (handle.workspace) {
        const auto closed = handle.workspace->close(
            std::chrono::steady_clock::now() + std::chrono::seconds(10));
        if (!closed)
            throw std::runtime_error(std::string("workspace close failed: ") +
                                     closed.error().message);
    }
    handle.overlay.reset();
    handle.database.reset();
    handle.workspace.reset();
    handle.provider.reset();
    handle.identity.reset();
}

void create_asset(fixture_asset_t& asset, std::uint8_t seed)
{
    asset.source_path = unique_path("aida-c03-workbench-shell", ".bin");
    std::vector<std::uint8_t> bytes(32);
    for (std::size_t index = 0; index < bytes.size(); ++index)
        bytes[index] = static_cast<std::uint8_t>(seed + index);
    std::ofstream output(asset.source_path,
                         std::ios::binary | std::ios::trunc);
    require(output.good(), "source fixture could not be created");
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    require(output.good(), "source fixture bytes could not be written");
}

const document_persistence_dto_t* active_document(
    const workbench_shell_workspace_context_t& context)
{
    const auto found = std::find_if(
        context.persistence.documents.begin(), context.persistence.documents.end(),
        [&context](const document_persistence_dto_t& document) {
            return document.id == context.persistence.active_document;
        });
    return found == context.persistence.documents.end() ? nullptr : &*found;
}

void verify_shell_models(workspace_handle_t& first,
                         workbench_shell_workspace_context_t& context)
{
    require(context.analysis_workspace == first.workspace &&
                context.navigator_tree && context.navigator_query &&
                context.navigator_nav && context.document_host &&
                context.inspector_session && context.document_registry &&
                context.disassembly_document && context.hex_document &&
                context.pseudocode_document && context.graph_document &&
                context.diff_document && context.document_bridge &&
                context.lifetime,
            "production shell context omitted a required model");

    cancellation_t live;
    navigator::navigator_tree_request_t navigator_request;
    navigator_request.domain = navigator::navigator_domain_t::functions;
    navigator_request.page.limit = 64;
    navigator::navigator_tree_page_t navigator_page;
    auto navigator_error = context.navigator_tree->page(
        navigator_request, &live, navigator_page);
    require(navigator_error.ok() && navigator_page.rows.size() == 1 &&
                navigator_page.rows.front().has_address &&
                navigator_page.rows.front().address == 0x1000 &&
                navigator_page.rows.front().label == "fixture_generation_one",
            "production navigator did not expose the packed function row");

    cancellation_t cancelled(true);
    navigator_page = {};
    navigator_error = context.navigator_tree->page(
        navigator_request, &cancelled, navigator_page);
    require(navigator_error.code == navigator::navigator_error_code_t::cancelled,
            "production navigator ignored cancellation");

    disasm_document::disasm_page_t disassembly;
    const auto disassembly_error = context.disassembly_document->page(
        {0, 64}, &live, disassembly);
    require(disassembly_error.ok() && disassembly.rows.size() == 2 &&
                disassembly.rows.front().address == 0x1000,
            "production disassembly document did not consume the snapshot");
    disassembly = {};
    require(context.disassembly_document->page({0, 64}, &cancelled, disassembly).code ==
                disasm_document::disasm_error_code_t::cancelled,
            "production disassembly document ignored cancellation");

    hex_document::hex_page_t hex;
    const auto hex_error = context.hex_document->page({0, 64}, &live, hex);
    require(hex_error.ok() && !hex.rows.empty() &&
                hex.rows.front().address == 0x1000,
            "production hex document did not consume provider mappings");
    hex = {};
    require(context.hex_document->page({0, 64}, &cancelled, hex).code ==
                hex_document::hex_error_code_t::cancelled,
            "production hex document ignored cancellation");

    pseudocode_document::pseudocode_request_t pseudocode_request;
    const auto pseudocode_error = context.pseudocode_document->resolve_request(
        0x1001, analysis::decompiler_profile_id_t::balanced, 1000,
        pseudocode_request);
    const auto* pseudocode_identity =
        std::get_if<analysis::native_decompiler_entity_identity_t>(
            &pseudocode_request.entity.identity);
    require(pseudocode_error.ok() && pseudocode_identity &&
                pseudocode_request.binding &&
                pseudocode_request.binding->entity ==
                    pseudocode_request.entity &&
                pseudocode_request.binding->generation ==
                    pseudocode_request.workspace_generation &&
                pseudocode_request.entity.kind ==
                    analysis::decompiler_entity_kind_t::native_function &&
                pseudocode_identity->function_id == 0x3001 &&
                pseudocode_identity->entry.value == 0x1000,
            "production F5 resolver did not canonicalize an interior instruction");
    analysis::decompiler_entity_locator_t native_locator;
    native_locator.address = 0x1001;
    native_locator.expected_kind =
        analysis::decompiler_entity_kind_t::native_function;
    pseudocode_document::pseudocode_request_t located_request;
    require(context.pseudocode_document->resolve_request(
                native_locator, analysis::decompiler_profile_id_t::fast,
                1000, located_request).ok() &&
                located_request.binding &&
                located_request.entity == pseudocode_request.entity,
            "production locator-based F5 resolver changed native identity");

    graph_document::graph_page_request_t cfg_request;
    cfg_request.limit = 64;
    cfg_request.graph_kind = graph_document::graph_kind_t::cfg;
    cfg_request.function_address = 0x1000;
    graph_document::graph_page_t cfg_first;
    graph_document::graph_page_t cfg_second;
    auto graph_error = context.graph_document->page(
        cfg_request, &live, cfg_first);
    require(graph_error.ok() && cfg_first.nodes.size() == 2,
            "production CFG document did not expose both blocks");
    graph_error = context.graph_document->page(
        cfg_request, &live, cfg_second);
    require(graph_error.ok() && cfg_second.nodes.size() == cfg_first.nodes.size() &&
                cfg_second.nodes[0].id == cfg_first.nodes[0].id &&
                cfg_second.nodes[1].id == cfg_first.nodes[1].id,
            "production CFG materialization was not deterministic");
    graph_document::graph_page_t cancelled_graph;
    require(context.graph_document->page(
                cfg_request, &cancelled, cancelled_graph).code ==
                graph_document::graph_error_code_t::cancelled,
            "production CFG materialization ignored cancellation");

    graph_document::graph_page_request_t call_request;
    call_request.limit = 64;
    call_request.graph_kind = graph_document::graph_kind_t::call_graph;
    graph_document::graph_page_t call_graph;
    graph_error = context.graph_document->page(
        call_request, &live, call_graph);
    require(graph_error.ok() && call_graph.nodes.size() == 1 &&
                call_graph.nodes.front().address == 0x1000,
            "production call graph document did not expose its function node");
}

void verify_host_and_navigation(
    workspace_handle_t& first,
    workbench_shell_workspace_context_t& context)
{
    workbench_command_result_t command_result;
    document_host::document_host_dispatch_t split;
    split.kind = document_host::document_host_dispatch_kind_t::toolbar;
    split.toolbar_action =
        document_host::document_host_toolbar_action_t::split_horizontal;
    split.ratio_basis_points = 4300;
    auto dispatched = workbench_shell_runtime_t::instance().dispatch_host_command(
        first.workspace, split, command_result, context);
    require(dispatched.ok() && command_result.changed &&
                context.persistence.views.size() == 2,
            "production horizontal split did not commit");

    auto activated = workbench_shell_runtime_t::instance().activate_document(
        first.workspace, document_kind_t::graph, std::nullopt, context);
    require(activated.ok() && active_document(context) &&
                active_document(context)->identity.kind == document_kind_t::graph,
            "production graph document did not activate");
    split = {};
    split.kind = document_host::document_host_dispatch_kind_t::toolbar;
    split.toolbar_action =
        document_host::document_host_toolbar_action_t::split_vertical;
    split.ratio_basis_points = 5700;
    dispatched = workbench_shell_runtime_t::instance().dispatch_host_command(
        first.workspace, split, command_result, context);
    require(dispatched.ok() && command_result.changed &&
                context.persistence.views.size() == 3,
            "production vertical split did not commit");

    activated = workbench_shell_runtime_t::instance().activate_document(
        first.workspace, document_kind_t::hex, std::nullopt, context);
    require(activated.ok() && active_document(context) &&
                active_document(context)->identity.kind == document_kind_t::hex,
            "production hex document did not activate");

    document_host::document_host_layout_request_t layout;
    layout.client_extent = {1600, 1000};
    layout.dpi = 144;
    layout.average_character_width_pixels = 9;
    document_host::document_host_chrome_t chrome;
    const auto composed = context.document_host->compose(
        context.workspace, layout, chrome);
    require(composed.ok() &&
                document_host::validate_document_host_chrome(chrome).ok() &&
                chrome.leaves.size() == 3 &&
                chrome.navigator_bounds.width != 0 &&
                chrome.inspector_bounds.width != 0 &&
                std::all_of(chrome.source_assertions.begin(),
                            chrome.source_assertions.end(),
                            [](const auto& assertion) { return assertion.passed; }),
            "production document host violated split/chrome source assertions");

    selection_context_t selection;
    selection.kind = selection_kind_t::range;
    selection.has_address = true;
    selection.address = 0x1001;
    selection.extent = 1;
    selection.entity_key = "instruction:4097";
    document_local_cursor_t cursor;
    cursor.has_position = true;
    cursor.position = 0x1001;
    const auto navigated = workbench_shell_runtime_t::instance().navigate_document(
        first.workspace, document_kind_t::disassembly, std::nullopt,
        selection, cursor, context);
    const auto* selected = active_document(context);
    const auto* inspected = context.inspector_session
        ? context.inspector_session->active_context() : nullptr;
    require(navigated.ok() && selected &&
                selected->identity.kind == document_kind_t::disassembly &&
                selected->local_state.selection.address == 0x1001 &&
                !context.persistence.history.back.empty() && inspected &&
                inspected->selection.address == 0x1001,
            "production navigation did not synchronize document/history/inspector state");

    document_host::document_host_dispatch_t stale;
    stale.kind = document_host::document_host_dispatch_kind_t::split_horizontal;
    stale.workspace = context.workspace;
    stale.expected_revision = workspace_revision_t{
        context.persistence.revision.value - 1U};
    const auto stale_result = context.document_host->dispatch(stale);
    require(stale_result.error.code == workbench_error_code_t::revision_mismatch &&
                !stale_result.changed,
            "production document host accepted a stale revision");

    constexpr const char* first_entity = "cli:100663297@0";
    constexpr const char* second_entity = "jvm:1@0";
    auto entity_result = workbench_shell_runtime_t::instance()
        .activate_entity_document(first.workspace, document_kind_t::pseudocode,
            first_entity, context);
    require(entity_result.ok() && active_document(context) &&
                active_document(context)->identity.provider_key == first_entity &&
                !active_document(context)->identity.has_address,
            "first managed pseudocode document did not activate by entity identity");
    entity_result = workbench_shell_runtime_t::instance()
        .activate_entity_document(first.workspace, document_kind_t::pseudocode,
            second_entity, context);
    const auto managed_count = std::count_if(
        context.persistence.documents.begin(), context.persistence.documents.end(),
        [](const auto& document) {
            return document.identity.kind == document_kind_t::pseudocode &&
                !document.identity.has_address &&
                document.identity.provider_key != "analysis";
        });
    require(entity_result.ok() && managed_count == 2 &&
                active_document(context) &&
                active_document(context)->identity.provider_key == second_entity,
            "managed pseudocode documents collided in the workbench registry");
    entity_result = workbench_shell_runtime_t::instance()
        .close_entity_document(first.workspace, document_kind_t::pseudocode,
            first_entity, context);
    require(entity_result.ok() &&
                std::none_of(context.persistence.documents.begin(),
                    context.persistence.documents.end(), [first_entity](const auto& document) {
                        return document.identity.provider_key == first_entity;
                    }) &&
                std::any_of(context.persistence.documents.begin(),
                    context.persistence.documents.end(), [second_entity](const auto& document) {
                        return document.identity.provider_key == second_entity;
                    }),
            "closing one managed pseudocode document affected a peer identity");
    selection_context_t entity_selection;
    entity_selection.kind = selection_kind_t::entity;
    entity_selection.entity_key = second_entity;
    document_local_cursor_t entity_cursor;
    entity_cursor.has_position = true;
    entity_cursor.position = 7;
    entity_result = workbench_shell_runtime_t::instance()
        .navigate_entity_document(first.workspace, document_kind_t::pseudocode,
            second_entity, entity_selection, entity_cursor, context);
    require(entity_result.ok() && active_document(context) &&
                active_document(context)->identity.provider_key == second_entity &&
                active_document(context)->local_state.selection.entity_key ==
                    second_entity &&
                active_document(context)->local_state.cursor.position == 7,
            "managed pseudocode entity navigation did not persist local state");
    workbench_shell_workspace_context_t rejected;
    require(!workbench_shell_runtime_t::instance()
                 .activate_entity_document(first.workspace,
                     document_kind_t::pseudocode, "CLI:1@0", rejected)
                 .ok(),
            "noncanonical managed pseudocode document identity was accepted");
}

void verify_diff_models(
    workspace_handle_t& first, workspace_handle_t& second,
    workbench_shell_workspace_context_t& first_context,
    const workbench_shell_workspace_context_t& second_context)
{
    cancellation_t live;
    diff_document::diff_page_request_t request;
    request.limit = 64;

    diff_document::diff_scope_t generation_scope;
    generation_scope.kind = diff_document::diff_kind_t::generation;
    generation_scope.before.workspace_id = first_context.workspace.value;
    generation_scope.before.generation = 1;
    generation_scope.after.workspace_id = first_context.workspace.value;
    generation_scope.after.generation = first.workspace->generation();
    diff_document::diff_page_t generation_page;
    auto error = first_context.diff_document->page(
        request, first_context.analysis_generation, generation_scope,
        &live, generation_page);
    require(error.ok() && !generation_page.entries.empty(),
            "production generation diff did not compare retained snapshots");

    diff_document::diff_page_t generation_repeat;
    error = first_context.diff_document->page(
        request, first_context.analysis_generation, generation_scope,
        &live, generation_repeat);
    require(error.ok() && generation_repeat.entries.size() ==
                generation_page.entries.size() &&
                generation_repeat.entries.front().entity_key ==
                    generation_page.entries.front().entity_key,
            "production generation diff was not deterministic");

    diff_document::diff_scope_t workspace_scope;
    workspace_scope.kind = diff_document::diff_kind_t::workspace;
    workspace_scope.before.workspace_id = first_context.workspace.value;
    workspace_scope.before.generation = first_context.analysis_generation;
    workspace_scope.after.workspace_id = second_context.workspace.value;
    workspace_scope.after.generation = second_context.analysis_generation;
    diff_document::diff_page_t workspace_page;
    error = first_context.diff_document->page(
        request, first_context.analysis_generation, workspace_scope,
        &live, workspace_page);
    require(error.ok() && !workspace_page.entries.empty(),
            "production workspace diff did not isolate two analysis workspaces");

    analysis::overlay_operation_t operation;
    operation.kind = analysis::overlay_operation_kind_t::name;
    operation.address = rva(0x1000);
    operation.name = "overlay_renamed_entry";
    analysis::overlay_transaction_request_t transaction;
    transaction.expected_revision = first.workspace->overlay_revision();
    transaction.operations.push_back(std::move(operation));
    const auto committed = first.overlay->transact(transaction);
    require(committed.has_value() && committed.value().committed &&
                committed.value().revision == 1,
            "production overlay transaction did not commit revision one");
    const auto refreshed = workbench_shell_runtime_t::instance().workspace_context(
        first.workspace, first_context);
    require(refreshed.ok() && first_context.overlay_revision == 1,
            "production shell did not refresh after overlay publication");

    diff_document::diff_scope_t overlay_scope;
    overlay_scope.kind = diff_document::diff_kind_t::overlay;
    overlay_scope.before.workspace_id = first_context.workspace.value;
    overlay_scope.before.generation = first_context.analysis_generation;
    overlay_scope.before.overlay_revision = 0;
    overlay_scope.after.workspace_id = first_context.workspace.value;
    overlay_scope.after.generation = first_context.analysis_generation;
    overlay_scope.after.overlay_revision = 1;
    diff_document::diff_page_t overlay_page;
    error = first_context.diff_document->page(
        request, first_context.analysis_generation, overlay_scope,
        &live, overlay_page);
    require(error.ok() && overlay_page.entries.size() == 1 &&
                overlay_page.entries.front().domain ==
                    diff_document::diff_domain_t::overlay,
            "production overlay diff did not compare retained revisions");

    cancellation_t cancelled(true);
    diff_document::diff_page_t cancelled_page;
    error = first_context.diff_document->page(
        request, first_context.analysis_generation, overlay_scope,
        &cancelled, cancelled_page);
    require(error.code == diff_document::diff_error_code_t::cancelled,
            "production diff materialization ignored cancellation");
}

void verify_persist_close_reopen(
    fixture_asset_t& asset, workspace_handle_t& first,
    const workbench_shell_workspace_context_t& before_close)
{
    const auto expected_active = active_document(before_close);
    require(expected_active != nullptr, "pre-close workbench had no active document");
    const auto expected_kind = expected_active->identity.kind;
    const auto expected_provider_key = expected_active->identity.provider_key;
    const auto expected_has_address = expected_active->identity.has_address;
    const auto expected_address = expected_active->identity.address;
    const auto expected_view_count = before_close.persistence.views.size();
    const auto expected_history_count = before_close.persistence.history.back.size();
    const auto expected_revision = before_close.persistence.revision.value;

    close_workspace(first);
    auto reopened = open_workspace(asset, "first");
    publish_snapshot(reopened, "fixture_reopened", "reopened-string");
    workbench_shell_workspace_context_t restored;
    const auto attached = workbench_shell_runtime_t::instance()
        .attach_analysis_workspace(reopened.workspace, restored);
    const auto* restored_active = active_document(restored);
    require(attached.ok() && restored_active &&
                restored_active->identity.kind == expected_kind &&
                restored_active->identity.provider_key == expected_provider_key &&
                restored_active->identity.has_address == expected_has_address &&
                restored_active->identity.address == expected_address &&
                restored.persistence.views.size() == expected_view_count &&
                restored.persistence.history.back.size() == expected_history_count &&
                restored.persistence.revision.value >= expected_revision,
            "production close/reopen did not restore workbench state");

    document_host::document_host_chrome_t chrome;
    const auto composed = restored.document_host->compose(
        restored.workspace, {{1600, 1000}, 96, 8}, chrome);
    require(composed.ok() && chrome.leaves.size() == expected_view_count &&
                std::all_of(chrome.source_assertions.begin(),
                            chrome.source_assertions.end(),
                            [](const auto& assertion) { return assertion.passed; }),
            "restored workbench split layout was not executable");
    close_workspace(reopened);
}

void verify_lifecycle()
{
    verify_managed_entity_locators();
    fixture_asset_t first_asset;
    fixture_asset_t second_asset;
    create_asset(first_asset, 0x10);
    create_asset(second_asset, 0x80);

    auto first = open_workspace(first_asset, "first");
    publish_snapshot(first, "fixture_generation_one", "generation-one");
    workbench_shell_workspace_context_t first_context;
    auto attached = workbench_shell_runtime_t::instance()
        .attach_analysis_workspace(first.workspace, first_context);
    require(attached.ok(), "first production workspace did not attach");
    verify_shell_models(first, first_context);
    verify_host_and_navigation(first, first_context);

    const auto next_generation = first.workspace->begin_new_generation();
    require(next_generation.has_value() && next_generation.value() == 2,
            "workspace generation did not advance deterministically");
    publish_snapshot(first, "fixture_generation_two", "generation-two");
    attached = workbench_shell_runtime_t::instance().workspace_context(
        first.workspace, first_context);
    require(attached.ok() && first_context.analysis_generation == 2,
            "shell did not refresh its generation-bound document bundle");

    auto second = open_workspace(second_asset, "second");
    publish_snapshot(second, "fixture_second_workspace", "workspace-two");
    workbench_shell_workspace_context_t second_context;
    attached = workbench_shell_runtime_t::instance().attach_analysis_workspace(
        second.workspace, second_context);
    require(attached.ok() && second_context.workspace != first_context.workspace,
            "second production workspace did not remain isolated");
    const auto live_workspaces = workbench_shell_runtime_t::instance()
        .analysis_workspaces();
    require(live_workspaces.size() >= 2 &&
                std::find(live_workspaces.begin(), live_workspaces.end(),
                          first.workspace) != live_workspaces.end() &&
                std::find(live_workspaces.begin(), live_workspaces.end(),
                          second.workspace) != live_workspaces.end(),
            "runtime workspace enumeration omitted an attached workspace");

    verify_diff_models(first, second, first_context, second_context);
    workbench_shell_workspace_context_t persisted_context;
    persisted_context.persistence = first_context.persistence;
    const auto second_workspace = second.workspace;
    close_workspace(second);
    const auto after_second_close = workbench_shell_runtime_t::instance()
        .analysis_workspaces();
    require(std::find(after_second_close.begin(), after_second_close.end(),
                      second_workspace) == after_second_close.end() &&
                std::find(after_second_close.begin(), after_second_close.end(),
                          first.workspace) != after_second_close.end(),
            "runtime retained a closed workspace or dropped a live peer");
    verify_persist_close_reopen(first_asset, first, persisted_context);
    require(workbench_shell_runtime_t::instance().analysis_workspaces().empty(),
            "runtime retained a workspace after lifecycle teardown");
}

}

bool run_workbench_shell_lifecycle_harness(std::string& failure)
{
    try {
        verify_lifecycle();
        failure.clear();
        return true;
    } catch (const std::exception& exception) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(exception.what());
        failure = exception.what();
        return false;
    }
}

}

int main()
{
    std::string failure;
    if (!aida::workbench::run_workbench_shell_lifecycle_harness(failure)) {
        std::cerr << "workbench_shell_lifecycle_harness failed: "
                  << failure << '\n';
        return 1;
    }
    std::cout << "workbench_shell_lifecycle_harness source contract satisfied\n";
    return 0;
}
