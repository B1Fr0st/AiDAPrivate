#include "managed_decompiler_consumers_harness.hpp"

#include "../../../src/core/analysis/decompiler/managed_entity_binding.hpp"
#include "../../../src/core/analysis/workspace/overlay_journal.hpp"
#include "../../../src/core/mcp/compat/c03_compatibility_registration.hpp"
#include "../../../src/core/mcp/registry/tool_registry.hpp"
#include "../../../src/core/workbench/workbench_shell_integration.hpp"
#include "../assertion_telemetry/assertion_telemetry.hpp"
#include "../../analysis_workspace/workspace_fixture_builder.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace aida::analysis::c03::managed_decompiler_consumers {
namespace {

using test_fixture::close_workspace;
using test_fixture::fixture_error_t;
using test_fixture::install_services;
using test_fixture::open_workspace;
using workbench::pseudocode_document::pseudocode_cache_state_t;
using workbench::pseudocode_document::pseudocode_error_code_t;
using workbench::pseudocode_document::pseudocode_page_t;
using workbench::pseudocode_document::pseudocode_request_t;

struct arguments_t final {
    std::filesystem::path cli_fixture;
    std::filesystem::path class_fixture;
    std::filesystem::path dex_fixture;
};

struct fixture_case_t final {
    std::string label;
    std::filesystem::path path;
    std::string bin_name;
    decompiler_entity_kind_t kind = decompiler_entity_kind_t::cli_method;
    std::shared_ptr<analysis_workspace_t> workspace;
    std::shared_ptr<const managed_artifact_publication_t> discovery;
    decompiler_entity_locator_t locator;
    std::string canonical_locator;
    workbench::workbench_shell_workspace_context_t workbench;
    pseudocode_request_t balanced_request;
    bool shell_attached = false;
};

void require(bool condition, const std::string& message)
{
    aida::analysis::c03_test::assertion_telemetry::record_assertion(
        condition, message, __FILE__, __LINE__);
    if (!condition)
        throw fixture_error_t(message);
}

arguments_t parse_arguments(int argc, char** argv)
{
    require(argc > 1 && ((argc - 1) % 2) == 0,
            "managed consumer harness arguments must be key/value pairs");
    arguments_t output;
    for (int index = 1; index + 1 < argc; index += 2) {
        const std::string key = argv[index];
        const auto value = std::filesystem::u8path(argv[index + 1]);
        if (key == "--cli-fixture")
            output.cli_fixture = value;
        else if (key == "--class-fixture")
            output.class_fixture = value;
        else if (key == "--dex-fixture")
            output.dex_fixture = value;
        else
            throw fixture_error_t("unknown managed consumer harness argument: " + key);
    }
    const auto validate_fixture = [](const char* label,
                                     const std::filesystem::path& path) {
        std::error_code error;
        require(!path.empty() && std::filesystem::is_regular_file(path, error) &&
                    !error,
                std::string(label) + " managed fixture is unavailable");
    };
    validate_fixture("CLI", output.cli_fixture);
    validate_fixture("JVM", output.class_fixture);
    validate_fixture("Dalvik", output.dex_fixture);
    return output;
}

std::shared_ptr<const managed_artifact_publication_t> discover(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    const auto publication = workspace ? workspace->analysis_publication() : nullptr;
    require(publication && publication->snapshot && publication->provider,
            "managed fixture lacks an immutable analysis publication");
    const auto target_revision = (std::max)(
        std::uint64_t{1}, publication->analysis_revision);
    auto built = build_managed_artifact_publication(
        workspace->identity(), *publication->provider, publication->snapshot->image,
        publication->generation, target_revision, publication->overlay_revision);
    require(built.has_value() && built.value() &&
                !built.value()->artifacts().empty() &&
                !built.value()->methods().empty(),
            "managed fixture did not produce a bounded artifact publication");
    return built.take_value();
}

std::vector<decompiler_entity_locator_t> method_locators(
    const managed_artifact_publication_t& publication,
    decompiler_entity_kind_t expected_kind)
{
    std::vector<decompiler_entity_locator_t> output;
    for (const auto& method : publication.methods()) {
        if (!method.has_body || method.entity.kind != expected_kind ||
            method.artifact_index >= publication.artifacts().size())
            continue;
        const auto& artifact = publication.artifacts()[method.artifact_index];
        decompiler_entity_locator_t locator;
        locator.token = method.entity_token;
        locator.artifact_ordinal = artifact.artifact_ordinal;
        locator.expected_kind = expected_kind;
        output.push_back(locator);
    }
    require(!output.empty(), "managed fixture contains no decompilable method body");
    return output;
}

std::string canonical_locator(const decompiler_entity_locator_t& locator)
{
    const auto encoded = workbench::pseudocode_document::
        canonical_pseudocode_entity_locator(locator);
    require(encoded.has_value(), "managed entity locator was not canonicalizable");
    const auto parsed = workbench::pseudocode_document::
        parse_pseudocode_entity_locator(*encoded);
    require(parsed && parsed->token == locator.token &&
                parsed->artifact_ordinal == locator.artifact_ordinal &&
                parsed->expected_kind == locator.expected_kind &&
                !parsed->address,
            "managed entity locator did not round-trip exactly");
    return *encoded;
}

const workbench::pseudocode_document::pseudocode_cached_document_t&
wait_for_document(workbench::pseudocode_document::pseudocode_document_model_t& model,
                  const pseudocode_request_t& request)
{
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::seconds(20);
    while (std::chrono::steady_clock::now() < deadline) {
        auto activated = model.activate(request);
        require(activated.ok(), "exact managed pseudocode cache activation failed");
        const auto* cached = model.cached_document(request);
        require(cached != nullptr, "exact managed pseudocode cache entry disappeared");
        if (cached->state != pseudocode_cache_state_t::requesting) {
            require(cached->state == pseudocode_cache_state_t::cached &&
                        cached->document &&
                        !cached->document->rendered_text.empty() &&
                        cached->document->entity == request.entity &&
                        cached->document->profile == request.profile,
                    "managed decompilation did not produce a typed terminal document");
            return *cached;
        }
        const auto job_id = cached->job_id;
        static_cast<void>(model.poll(job_id));
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    throw fixture_error_t("managed pseudocode request exceeded its harness deadline");
}

pseudocode_request_t request_document(
    workbench::pseudocode_document::pseudocode_document_model_t& model,
    const decompiler_entity_locator_t& locator,
    decompiler_profile_id_t profile, std::uint64_t timeout_ms,
    bool force_refresh)
{
    pseudocode_request_t request;
    auto result = model.resolve_request(locator, profile, timeout_ms, request);
    require(result.ok() && request.binding &&
                request.binding->entity == request.entity &&
                request.binding->generation == request.workspace_generation &&
                request.binding->analysis_revision != 0 &&
                request.binding->entity.kind == *locator.expected_kind,
            "managed pseudocode request did not retain its exact publication binding");
    result = model.request(request, force_refresh);
    require(result.ok() ||
                result.code == pseudocode_error_code_t::request_in_progress,
            "managed pseudocode request was rejected by the production adapter");
    const auto& cached = wait_for_document(model, request);
    require(cached.binding &&
                cached.binding->binary_id == request.binding->binary_id &&
                cached.binding->provider_hash == request.binding->provider_hash &&
                cached.binding->artifact_hash == request.binding->artifact_hash &&
                cached.binding->analysis_revision ==
                    request.binding->analysis_revision &&
                cached.binding->overlay_revision ==
                    request.binding->overlay_revision,
            "managed pseudocode cache lost its full publication identity");
    pseudocode_page_t page;
    const auto paged = model.page({0, 128}, page);
    require(paged.ok() && page.cache_state == pseudocode_cache_state_t::cached &&
                !page.lines.empty() && !page.tokens.empty() &&
                !cached.document->ast.nodes.empty() &&
                cached.document->ast.root_node_id != 0 &&
                cached.document->ast.body_node_id != 0 &&
                !cached.document->source_maps.empty() &&
                std::all_of(cached.document->source_maps.begin(),
                    cached.document->source_maps.end(), [](const auto& mapping) {
                        return !mapping.coordinates.empty();
                    }),
            "managed pseudocode document omitted typed AST, tokens, or source maps");
    return request;
}

void verify_document_lifecycle(fixture_case_t& fixture)
{
    auto attached = workbench::workbench_shell_runtime_t::instance()
        .attach_analysis_workspace(fixture.workspace, fixture.workbench);
    require(attached.ok() && fixture.workbench.pseudocode_document,
            fixture.label + " workbench did not attach its pseudocode model");
    fixture.shell_attached = true;
    auto activated = workbench::workbench_shell_runtime_t::instance()
        .activate_entity_document(fixture.workspace,
            workbench::document_kind_t::pseudocode,
            fixture.canonical_locator, fixture.workbench);
    require(activated.ok() && fixture.workbench.pseudocode_document,
            fixture.label + " entity document did not activate");
    fixture.balanced_request = request_document(
        *fixture.workbench.pseudocode_document, fixture.locator,
        decompiler_profile_id_t::balanced, 5000, false);
    const auto balanced_document =
        fixture.workbench.pseudocode_document
            ->cached_document(fixture.balanced_request)->document;
    const auto fast_request = request_document(
        *fixture.workbench.pseudocode_document, fixture.locator,
        decompiler_profile_id_t::fast, 1500, false);
    const auto* fast_cached = fixture.workbench.pseudocode_document
        ->cached_document(fast_request);
    const auto* balanced_cached = fixture.workbench.pseudocode_document
        ->cached_document(fixture.balanced_request);
    require(fast_cached && balanced_cached &&
                fast_cached != balanced_cached &&
                fast_cached->profile_info.profile ==
                    decompiler_profile_id_t::fast &&
                balanced_cached->profile_info.profile ==
                    decompiler_profile_id_t::balanced &&
                balanced_cached->document == balanced_document &&
                fixture.workbench.pseudocode_document->cached_document_count() >= 2,
            "managed pseudocode cache collapsed distinct profile identities");

    pseudocode_request_t thorough;
    auto resolved = fixture.workbench.pseudocode_document->resolve_request(
        fixture.locator, decompiler_profile_id_t::thorough, 15000, thorough);
    require(resolved.ok(), "managed thorough-profile request did not resolve");
    auto requested = fixture.workbench.pseudocode_document->request(thorough, true);
    require(requested.ok(), "managed thorough-profile refresh did not start");
    const auto* pending = fixture.workbench.pseudocode_document
        ->cached_document(thorough);
    require(pending && pending->state == pseudocode_cache_state_t::requesting,
            "managed cancellation fixture did not create an in-flight request");
    const auto cancelled = fixture.workbench.pseudocode_document
        ->cancel(pending->job_id);
    const auto* terminal = fixture.workbench.pseudocode_document
        ->cached_document(thorough);
    require(cancelled.ok() && terminal &&
                terminal->state == pseudocode_cache_state_t::cancelled &&
                !fixture.workbench.pseudocode_document->has_pending_requests(),
            "managed cancellation did not terminalize the exact request");
}

void verify_entity_document_persistence(fixture_case_t& fixture)
{
    const auto locators = method_locators(*fixture.discovery, fixture.kind);
    require(locators.size() >= 2,
            "JVM persistence fixture requires two real method identities");
    const auto second = canonical_locator(locators[1]);
    auto activated = workbench::workbench_shell_runtime_t::instance()
        .activate_entity_document(fixture.workspace,
            workbench::document_kind_t::pseudocode, second, fixture.workbench);
    require(activated.ok(), "second managed entity document did not activate");
    const auto contains = [&fixture](std::string_view key) {
        return std::any_of(fixture.workbench.persistence.documents.begin(),
            fixture.workbench.persistence.documents.end(), [key](const auto& document) {
                return document.identity.kind ==
                        workbench::document_kind_t::pseudocode &&
                    !document.identity.has_address &&
                    document.identity.provider_key == key;
            });
    };
    require(contains(fixture.canonical_locator) && contains(second),
            "managed entity documents collided before persistence");
    const auto closed = workbench::workbench_shell_runtime_t::instance()
        .close_analysis_workspace(fixture.workspace);
    require(closed.ok(), "managed entity documents did not persist on shell close");
    fixture.shell_attached = false;
    fixture.workbench = {};
    activated = workbench::workbench_shell_runtime_t::instance()
        .attach_analysis_workspace(fixture.workspace, fixture.workbench);
    require(activated.ok(), "managed entity workbench did not reattach");
    fixture.shell_attached = true;
    require(contains(fixture.canonical_locator) && contains(second),
            "managed entity documents did not survive workbench restoration");
}

mcp_standalone::tool_result_t require_tool(
    mcp_standalone::tool_registry_t& registry, std::string_view name,
    const mcp_standalone::json& arguments)
{
    auto result = registry.call_registered_tool(std::string(name), arguments);
    require(result.success,
            std::string(name) + " failed: " + result.error_code + ":" +
                result.text);
    return result;
}

void verify_mcp_consumers(mcp_standalone::tool_registry_t& registry,
                          std::vector<fixture_case_t>& fixtures)
{
    const auto unresolved = registry.call_registered_tool(
        "decompile",
        mcp_standalone::json{{"addr", fixtures.front().canonical_locator}});
    require(!unresolved.success &&
                (unresolved.error_code == "TARGET_REQUIRED" ||
                 unresolved.error_code == "TARGET_AMBIGUOUS"),
            "multi-workspace managed decompile did not require an explicit target");

    std::vector<workbench::persistence_fingerprint_t> fingerprints;
    std::vector<workbench::workspace_revision_t> revisions;
    fingerprints.reserve(fixtures.size());
    revisions.reserve(fixtures.size());
    for (auto& fixture : fixtures) {
        auto refreshed = workbench::workbench_shell_runtime_t::instance()
            .workspace_context(fixture.workspace, fixture.workbench);
        require(refreshed.ok(), "managed workbench did not refresh before MCP reads");
        fingerprints.push_back(fixture.workbench.persistence.fingerprint());
        revisions.push_back(fixture.workbench.persistence.revision);

        const mcp_standalone::json route{
            {"bin_name", fixture.bin_name},
            {"addr", fixture.canonical_locator},
            {"include_addresses", false},
        };
        const auto decompiled = require_tool(registry, "decompile", route);
        require(decompiled.data.is_object() &&
                    decompiled.data.value("addr", std::string()) ==
                        fixture.canonical_locator &&
                    decompiled.data.contains("code") &&
                    decompiled.data["code"].is_string() &&
                    !decompiled.data["code"].get<std::string>().empty() &&
                    decompiled.data["code"].get<std::string>().find("/*0x") ==
                        std::string::npos,
                fixture.label + " MCP decompile lost canonical identity or code");
        const auto round_trip = workbench::pseudocode_document::
            parse_pseudocode_entity_locator(
                decompiled.data["addr"].get<std::string>());
        require(round_trip && round_trip->token == fixture.locator.token &&
                    round_trip->artifact_ordinal ==
                        fixture.locator.artifact_ordinal &&
                    round_trip->expected_kind == fixture.locator.expected_kind,
                fixture.label + " MCP address did not round-trip to the entity");

        const auto batch = require_tool(registry, "analyze_batch",
            mcp_standalone::json{
                {"bin_name", fixture.bin_name},
                {"queries", mcp_standalone::json{
                    {"addr", fixture.canonical_locator},
                    {"include_decompile", true},
                    {"include_proto", true}}}});
        require(batch.data.contains("result") &&
                    batch.data["result"].is_array() &&
                    batch.data["result"].size() == 1 &&
                    batch.data["result"][0].contains("analysis") &&
                    batch.data["result"][0]["analysis"].is_object() &&
                    batch.data["result"][0]["analysis"].contains("decompile") &&
                    batch.data["result"][0]["analysis"]["decompile"].is_string() &&
                    !batch.data["result"][0]["analysis"]["decompile"]
                         .get<std::string>().empty(),
                fixture.label + " analyze_batch did not consume typed decompilation");

        const auto exported = require_tool(registry, "export_funcs",
            mcp_standalone::json{
                {"bin_name", fixture.bin_name},
                {"addrs", fixture.canonical_locator},
                {"format", "json"}});
        require(exported.data.value("format", std::string()) == "json" &&
                    exported.data.contains("functions") &&
                    exported.data["functions"].is_array() &&
                    exported.data["functions"].size() == 1 &&
                    exported.data["functions"][0].value(
                        "addr", std::string()) == fixture.canonical_locator &&
                    exported.data["functions"][0].contains("code") &&
                    exported.data["functions"][0]["code"].is_string() &&
                    !exported.data["functions"][0]["code"]
                         .get<std::string>().empty(),
                fixture.label + " export_funcs did not export managed code");

        const auto composite = require_tool(registry, "analyze_function",
            mcp_standalone::json{
                {"bin_name", fixture.bin_name},
                {"addr", fixture.canonical_locator},
                {"include_asm", false}});
        require(composite.data.is_object() &&
                    composite.data.value("addr", std::string()) ==
                        fixture.canonical_locator &&
                    composite.data.contains("decompiled") &&
                    composite.data["decompiled"].is_string() &&
                    !composite.data["decompiled"].get<std::string>().empty(),
                fixture.label + " analyze_function did not consume managed code");
    }

    const auto& mutation_fixture = fixtures[1];
    auto overlay_revision = mutation_fixture.workspace->overlay_revision();
    const auto apply_action = [&](std::string_view action,
                                  mcp_standalone::json action_arguments) {
        const auto result = require_tool(registry, "diff_before_after",
            mcp_standalone::json{
                {"bin_name", mutation_fixture.bin_name},
                {"addr", mutation_fixture.canonical_locator},
                {"action", action},
                {"action_args", std::move(action_arguments)}});
        require(result.data.is_object() &&
                    result.data.value("action_applied", std::string()) == action &&
                    mutation_fixture.workspace->overlay_revision() >
                        overlay_revision,
                "managed diff_before_after did not commit the requested overlay action");
        overlay_revision = mutation_fixture.workspace->overlay_revision();
    };
    apply_action("set_comment", {{"comment", "managed comment"}});
    require(mutation_fixture.workspace->overlay()->snapshot().items.size() == 1 &&
                mutation_fixture.workspace->overlay()->snapshot().items.front()
                    .second.managed_locator &&
                mutation_fixture.workspace->overlay()->snapshot().items.front()
                    .second.text == "managed comment",
            "managed comment did not bind to one address-free entity identity");
    apply_action("set_comment", {{"comment", "managed comment update"}});
    require(mutation_fixture.workspace->overlay()->snapshot().items.size() == 1 &&
                mutation_fixture.workspace->overlay()->snapshot().items.front()
                    .second.text == "managed comment update",
            "managed comment update created a duplicate semantic entity");
    apply_action("rename_func", {{"name", "managed_method_name"}});
    apply_action("set_type", {{"type", "System.Int32()"}});
    apply_action("set_type", {{"type", "System.Int64()"}});
    const auto managed_snapshot =
        mutation_fixture.workspace->overlay()->snapshot();
    require(managed_snapshot.items.size() == 3 &&
                std::all_of(managed_snapshot.items.begin(),
                    managed_snapshot.items.end(), [](const auto& item) {
                        return item.second.managed_locator.has_value() &&
                            item.second.target_discriminator ==
                                overlay_target_discriminator_v9_t::managed_entity &&
                            !item.second.end;
                    }),
            "managed overlay actions did not remain address-free and domain-isolated");

    const auto rejected_revision =
        mutation_fixture.workspace->overlay_revision();
    const auto rejected = registry.call_registered_tool(
        "diff_before_after",
        mcp_standalone::json{
            {"bin_name", mutation_fixture.bin_name},
            {"addr", mutation_fixture.canonical_locator},
            {"action", "patch"},
            {"action_args", mcp_standalone::json{{"bytes", "90"}}}});
    require(!rejected.success &&
                mutation_fixture.workspace->overlay_revision() ==
                    rejected_revision,
            "unsupported managed overlay action mutated the journal");

    mcp_standalone::direct_dispatch_options_t cancelled_options;
    cancelled_options.cancellation =
        mcp_standalone::make_call_cancel_token(true);
    const auto cancelled = registry.call_registered_tool(
        "diff_before_after",
        mcp_standalone::json{
            {"bin_name", mutation_fixture.bin_name},
            {"addr", mutation_fixture.canonical_locator},
            {"action", "set_comment"},
            {"action_args", mcp_standalone::json{{"comment", "cancelled"}}}},
        std::move(cancelled_options));
    require(!cancelled.success &&
                cancelled.error_code == "MCP_TOOL_CANCELLED" &&
                mutation_fixture.workspace->overlay_revision() ==
                    rejected_revision,
            "cancelled managed overlay action did not fail closed");

    mcp_standalone::direct_dispatch_options_t deadline_options;
    deadline_options.deadline_ms = 1;
    const auto expired = registry.call_registered_tool(
        "diff_before_after",
        mcp_standalone::json{
            {"bin_name", mutation_fixture.bin_name},
            {"addr", mutation_fixture.canonical_locator},
            {"action", "set_comment"},
            {"action_args", mcp_standalone::json{{"comment", "expired"}}}},
        std::move(deadline_options));
    require(!expired.success &&
                expired.error_code == "MCP_TOOL_DEADLINE_EXPIRED" &&
                mutation_fixture.workspace->overlay_revision() ==
                    rejected_revision,
            "expired managed overlay action did not fail closed");

    const auto conflict = registry.call_registered_tool("decompile",
        mcp_standalone::json{
            {"bin_name", fixtures.front().bin_name},
            {"pid", 1},
            {"addr", fixtures.front().canonical_locator}});
    require(!conflict.success && conflict.error_code == "TARGET_CONFLICT",
            "managed decompile accepted conflicting target selectors");

    for (std::size_t index = 0; index < fixtures.size(); ++index) {
        auto refreshed = workbench::workbench_shell_runtime_t::instance()
            .workspace_context(fixtures[index].workspace,
                               fixtures[index].workbench);
        require(refreshed.ok() &&
                    fixtures[index].workbench.persistence.fingerprint() ==
                        fingerprints[index] &&
                    fixtures[index].workbench.persistence.revision ==
                        revisions[index],
                fixtures[index].label +
                    " MCP read mutated workbench persistence or active state");
    }
}

void verify_same_generation_stale_read(fixture_case_t& fixture)
{
    const auto old_generation = fixture.workspace->generation();
    const auto image = fixture.workspace->normalized_image();
    require(image && !image->address_mappings.empty(),
            "managed stale-read fixture lacks a mapped image range");
    const auto mapping = std::find_if(image->address_mappings.begin(),
        image->address_mappings.end(), [](const auto& candidate) {
            return candidate.size != 0 &&
                (candidate.target_space ==
                     address_space_id_t::relative_virtual ||
                 candidate.target_space ==
                     address_space_id_t::virtual_address);
        });
    require(mapping != image->address_mappings.end(),
            "managed stale-read fixture lacks an overlay address range");
    overlay_transaction_request_t transaction;
    transaction.expected_revision = fixture.workspace->overlay_revision();
    transaction.idempotency_key = "managed-consumer-stale-publication";
    overlay_operation_t operation;
    operation.kind = overlay_operation_kind_t::comment;
    operation.address.space = mapping->target_space;
    operation.address.value = mapping->target_start;
    operation.address.architecture = fixture.workspace->identity().architecture();
    operation.address.mode = fixture.workspace->identity().architecture_mode();
    operation.text = "managed publication revision transition";
    transaction.operations.push_back(std::move(operation));
    const auto committed = fixture.workspace->overlay()->transact(transaction);
    require(committed && committed.value().committed &&
                fixture.workspace->generation() == old_generation &&
                fixture.workspace->overlay_revision() !=
                    fixture.balanced_request.binding->overlay_revision,
            "managed stale-read fixture did not publish a same-generation revision");
    const auto activated = fixture.workbench.pseudocode_document
        ->activate(fixture.balanced_request);
    pseudocode_page_t stale_page;
    const auto paged = fixture.workbench.pseudocode_document
        ->page({0, 32}, stale_page);
    require(!activated.ok() &&
                (activated.code == pseudocode_error_code_t::stale_generation ||
                 activated.code == pseudocode_error_code_t::stale_result) &&
                !paged.ok() && stale_page.lines.empty() &&
                stale_page.tokens.empty() && stale_page.source_maps.empty(),
            "same-generation managed cache served a stale publication");
}

void close_fixture(fixture_case_t& fixture, bool suppress_errors)
{
    try {
        if (fixture.shell_attached && fixture.workspace) {
            const auto closed = workbench::workbench_shell_runtime_t::instance()
                .close_analysis_workspace(fixture.workspace);
            if (!closed.ok() && !suppress_errors)
                throw fixture_error_t("managed workbench close failed");
            fixture.shell_attached = false;
        }
        if (fixture.workspace) {
            close_workspace(fixture.workspace, true);
            fixture.workspace.reset();
        }
    } catch (...) {
        if (!suppress_errors)
            throw;
    }
}

}

int run(int argc, char** argv)
{
    std::vector<fixture_case_t> fixtures;
    try {
        const auto arguments = parse_arguments(argc, argv);
        fixtures = {
            {"CLI", arguments.cli_fixture, "c03-managed-cli.dll",
             decompiler_entity_kind_t::cli_method},
            {"JVM", arguments.class_fixture, "c03-managed-jvm.class",
             decompiler_entity_kind_t::jvm_method},
            {"Dalvik", arguments.dex_fixture, "c03-managed-dalvik.dex",
             decompiler_entity_kind_t::dalvik_method},
        };
        for (auto& fixture : fixtures) {
            fixture.workspace = open_workspace(fixture.path, fixture.bin_name);
            install_services(fixture.workspace);
            fixture.discovery = discover(fixture.workspace);
            fixture.locator = method_locators(
                *fixture.discovery, fixture.kind).front();
            fixture.canonical_locator = canonical_locator(fixture.locator);
            verify_document_lifecycle(fixture);
        }
        require(fixtures[0].balanced_request.binding->binary_id !=
                    fixtures[1].balanced_request.binding->binary_id &&
                    fixtures[1].balanced_request.binding->binary_id !=
                        fixtures[2].balanced_request.binding->binary_id &&
                    fixtures[0].balanced_request.binding->binary_id !=
                        fixtures[2].balanced_request.binding->binary_id,
                "managed decompiler cache identities crossed workspace boundaries");

        mcp_standalone::tool_registry_t registry;
        mcp_standalone::register_c03_compatibility_tools(registry);
        verify_mcp_consumers(registry, fixtures);
        verify_same_generation_stale_read(fixtures.front());
        verify_entity_document_persistence(fixtures[1]);

        for (auto& fixture : fixtures)
            close_fixture(fixture, false);
        std::cout << "managed_decompiler_consumers_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        aida::analysis::c03_test::assertion_telemetry::record_exception(
            error.what());
        for (auto& fixture : fixtures)
            close_fixture(fixture, true);
        std::cerr << "managed_decompiler_consumers_harness failed: "
                  << error.what() << '\n';
        return 1;
    }
}

}
