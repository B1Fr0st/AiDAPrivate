#include "workbench_persistence_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/workspace/workspace_database.hpp"
#include "../../src/core/analysis/workspace/workspace_identity.hpp"
#include "../../src/core/infra/taskflow_runtime.hpp"
#include "../../src/core/workbench/workbench_model.h"
#include "../../src/core/workbench/workbench_persistence.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <future>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace aida {
namespace workbench {
namespace {

using json = nlohmann::json;

void require(bool condition, const char* message)
{
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

document_identity_t make_identity(workspace_id_t workspace, std::uint64_t object_id)
{
    document_identity_t identity;
    identity.workspace = workspace;
    identity.kind = document_kind_t::disassembly;
    identity.object_id = object_id;
    identity.variant_id = object_id + 1000U;
    identity.provider_key = "persistence-codec-" + std::to_string(object_id);
    identity.has_address = true;
    identity.address = 0x401000U + object_id;
    return identity;
}

document_persistence_dto_t make_document_record(
    workspace_id_t workspace, std::uint64_t document_id,
    std::uint64_t object_id, std::string title, std::string state_token)
{
    document_persistence_dto_t document;
    document.id = {document_id};
    document.identity = make_identity(workspace, object_id);
    document.title = std::move(title);
    document.state_token = std::move(state_token);
    return document;
}

selection_context_t make_address_selection(std::uint64_t address,
                                           std::uint64_t extent = 0)
{
    selection_context_t selection;
    selection.kind = extent == 0 ? selection_kind_t::address
                                 : selection_kind_t::range;
    selection.has_address = true;
    selection.address = address;
    selection.extent = extent;
    return selection;
}

navigation_event_t make_navigation_event(
    workspace_id_t workspace, navigation_event_id_t id,
    std::uint64_t sequence, document_id_t source_document,
    view_id_t source_view, document_identity_t target_document,
    std::uint64_t source_address, std::uint64_t target_address)
{
    navigation_event_t event;
    event.id = id;
    event.workspace = workspace;
    event.has_source = true;
    event.source.workspace = workspace;
    event.source.document = source_document;
    event.source.view = source_view;
    event.source.selection = make_address_selection(source_address);
    event.source.cursor = {true, source_address};
    event.target.document = std::move(target_document);
    event.target.selection = make_address_selection(target_address, 16);
    event.target.cursor = {true, target_address};
    event.origin = navigation_origin_t::history;
    event.sequence = sequence;
    event.request_focus = true;
    return event;
}

workbench_persistence_dto_t make_workspace(workspace_id_t workspace)
{
    workbench_persistence_dto_t dto;
    dto.workspace = workspace;
    dto.revision = {1};
    dto.history.workspace = workspace;

    auto first = make_document_record(
        workspace, 1, 1, "primary", "primary-state");
    first.title.append("\xE2\x82\xAC", 3);
    first.local_state.cursor = {true, 0x401011U};
    first.local_state.selection = make_address_selection(0x401010U, 24);
    first.pinned = true;
    first.closeable = false;

    auto second = make_document_record(
        workspace, 2, 2, "secondary", "secondary-state");
    second.local_state.cursor = {true, 0x402022U};
    second.local_state.selection.kind = selection_kind_t::entity;
    second.local_state.selection.entity_key = "function:secondary";

    dto.documents = {first, second};
    dto.active_document = first.id;

    view_persistence_dto_t first_view;
    first_view.id = {11};
    first_view.workspace = workspace;
    first_view.document = first.id;
    first_view.focused = true;

    view_persistence_dto_t second_view;
    second_view.id = {12};
    second_view.workspace = workspace;
    second_view.document = second.id;
    second_view.role = view_role_t::secondary;
    second_view.synchronization_group = 71;
    second_view.synchronization_policy =
        view_synchronization_policy_t::cursor_and_selection;

    dto.views = {first_view, second_view};

    panel_state_dto_t panel;
    panel.id = {401};
    panel.workspace = workspace;
    panel.kind = panel_kind_t::navigator;
    panel.revision = dto.revision;
    panel.selected_document = first.id;
    panel.pinned = true;
    panel.state_token = "navigator:expanded=imports";

    panel_state_dto_t inspector;
    inspector.id = {402};
    inspector.workspace = workspace;
    inspector.kind = panel_kind_t::inspector;
    inspector.visible = false;
    inspector.selected_document = second.id;
    inspector.state_token = "inspector:tab=types";
    inspector.revision = dto.revision;
    dto.panels = {panel, inspector};

    dto.history.capacity = 8;
    dto.history.back.push_back(make_navigation_event(
        workspace, {501}, 1001, first.id, first_view.id,
        second.identity, 0x401010U, 0x402020U));
    auto forward = make_navigation_event(
        workspace, {502}, 1002, second.id, second_view.id,
        first.identity, 0x402020U, 0x401030U);
    forward.source.synchronization_group = second_view.synchronization_group;
    forward.source.synchronization_policy = second_view.synchronization_policy;
    forward.origin = navigation_origin_t::adapter;
    forward.request_focus = false;
    dto.history.forward.push_back(std::move(forward));
    return dto;
}

class persistence_catalog_t final : public document_catalog_adapter_t {
public:
    explicit persistence_catalog_t(const workbench_persistence_dto_t& persistence)
        : persistence_(persistence)
    {
    }

    workbench_error_t describe(const document_identity_t& identity,
                               document_descriptor_t& output) const override
    {
        const auto found = std::find_if(
            persistence_.documents.begin(), persistence_.documents.end(),
            [&identity](const auto& document) {
                return document_identity_equal(document.identity, identity);
            });
        if (found == persistence_.documents.end())
            return {workbench_error_code_t::invalid_document, identity.object_id};
        output.identity = found->identity;
        output.title = found->title;
        output.can_open = true;
        return {};
    }

private:
    const workbench_persistence_dto_t& persistence_;
};

std::filesystem::path unique_fixture_path(const char* suffix)
{
    std::error_code error;
    auto root = std::filesystem::temp_directory_path(error);
    require(!error, "adapter: temporary directory lookup failed");
    root /= "AiDA";
    root /= "workbench_persistence_v10";
    std::filesystem::create_directories(root, error);
    require(!error, "adapter: temporary directory creation failed");
    static std::atomic<std::uint64_t> counter{1};
    const auto serial = counter.fetch_add(1, std::memory_order_relaxed);
    return root / ("workbench_" + std::to_string(serial) + suffix);
}

void remove_database_files(const std::string& path) noexcept
{
    std::error_code error;
    std::filesystem::remove(std::filesystem::u8path(path), error);
    error.clear();
    std::filesystem::remove(std::filesystem::u8path(path + "-wal"), error);
    error.clear();
    std::filesystem::remove(std::filesystem::u8path(path + "-shm"), error);
}

struct database_fixture_t final {
    std::shared_ptr<analysis::workspace_database_t> database;
    std::string database_path;
    std::filesystem::path source_path;

    ~database_fixture_t()
    {
        close();
    }

    void close() noexcept
    {
        if (database) {
            database->request_cancel();
            static_cast<void>(database->drain(
                std::chrono::steady_clock::now() + std::chrono::seconds(10)));
            database.reset();
        }
        if (!database_path.empty()) {
            remove_database_files(database_path);
            database_path.clear();
        }
        if (!source_path.empty()) {
            std::error_code error;
            std::filesystem::remove(source_path, error);
            source_path.clear();
        }
    }
};

void open_database_fixture(database_fixture_t& fixture)
{
    fixture.source_path = unique_fixture_path(".bin");
    {
        std::ofstream source(fixture.source_path,
                             std::ios::binary | std::ios::trunc);
        require(source.good(), "adapter: source fixture open failed");
        const std::string bytes = "AiDA workbench persistence schema v10";
        source.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        require(source.good(), "adapter: source fixture write failed");
    }

    const auto source_utf8 = fixture.source_path.u8string();
    auto content_hash = analysis::sha256_text("content:" + source_utf8);
    auto profile_hash = analysis::sha256_text("profile:" + source_utf8);
    require(content_hash.has_value() && profile_hash.has_value(),
            "adapter: identity hash creation failed");

    analysis::workspace_identity_input_t identity_input;
    identity_input.bin_name = fixture.source_path.filename().u8string();
    identity_input.source_path = source_utf8;
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
    require(identity.has_value(), "adapter: workspace identity creation failed");

    analysis::workspace_database_options_t options;
    options.identity = identity.take_value();
    options.versions.engine_version = "workbench-persistence-harness";
    options.versions.specification_version = "schema-v10";
    options.versions.analysis_settings_hash = "workbench-persistence-settings";
    options.candidate_operation_timeout_ms = 10000;
    auto opened = analysis::workspace_database_t::open(std::move(options));
    require(opened.has_value(), "adapter: workspace database open failed");
    fixture.database = opened.take_value();
    fixture.database_path = fixture.database->path();
}

std::string make_v9_payload(workspace_id_t workspace)
{
    auto dto = make_workspace(workspace);
    std::string current_encoded;
    const auto encode_result = workbench_persistence_codec_t::encode(dto, current_encoded);
    if (!encode_result.ok())
        throw std::runtime_error("v9 fixture: failed to encode source DTO");

    auto current = json::parse(current_encoded.begin(), current_encoded.end(), nullptr, false);
    if (current.is_discarded() || !current.is_object())
        throw std::runtime_error("v9 fixture: failed to parse current envelope");

    auto payload = std::move(current["payload"]);
    payload["schema_version"] = "2";
    payload["layout"] = json{
        {"left_rail_pixels", "52"}, {"navigator_pixels", "280"},
        {"inspector_pixels", "360"}, {"bottom_panel_pixels", "240"},
        {"tab_strip_pixels", "32"}, {"toolbar_pixels", "36"},
        {"splitter_pixels", "6"}, {"minimum_document_width_pixels", "320"},
        {"minimum_document_height_pixels", "200"}
    };
    payload["split_tree"] = json{
        {"root", "103"},
        {"nodes", json::array({
            json{{"id", "103"}, {"kind", 1}, {"orientation", 1},
                 {"ratio_basis_points", "6200"}, {"view", "0"},
                 {"first", "102"}, {"second", "101"}},
            json{{"id", "101"}, {"kind", 0}, {"orientation", 0},
                 {"ratio_basis_points", "5000"}, {"view", "11"},
                 {"first", "0"}, {"second", "0"}},
            json{{"id", "102"}, {"kind", 0}, {"orientation", 0},
                 {"ratio_basis_points", "5000"}, {"view", "12"},
                 {"first", "0"}, {"second", "0"}}
        })}
    };
    for (auto& panel : payload["panels"])
        panel["extent_pixels"] = panel["kind"] == 0 ? "280" : "360";
    return json{{"schema", k_persistence_codec_schema_v9},
                {"kind", k_persistence_codec_kind_v9},
                {"payload", std::move(payload)}}.dump();
}

std::string make_v8_payload(workspace_id_t workspace)
{
    const auto v9_encoded = make_v9_payload(workspace);
    auto v9 = json::parse(v9_encoded.begin(), v9_encoded.end(), nullptr, false);
    if (v9.is_discarded() || !v9.is_object())
        throw std::runtime_error("v8 fixture: failed to parse v9 envelope");
    auto payload = std::move(v9["payload"]);
    payload.erase("panels");
    payload.erase("split_tree");

    auto& layout = payload["layout"];
    layout.erase("splitter_pixels");
    layout.erase("minimum_document_width_pixels");
    layout.erase("minimum_document_height_pixels");

    json v8_envelope = json{
        {"schema", k_persistence_codec_schema_v8},
        {"payload", std::move(payload)}
    };
    return v8_envelope.dump();
}

std::string inject_unknown_kind(const std::string& encoded, int doc_index)
{
    auto envelope = json::parse(encoded.begin(), encoded.end(), nullptr, false);
    if (envelope.is_discarded() || !envelope.is_object())
        throw std::runtime_error("inject: failed to parse persistence envelope");

    auto& documents = envelope["payload"]["documents"];
    if (doc_index < 0) {
        for (auto& doc : documents)
            doc["identity"]["kind"] = static_cast<std::uint8_t>(document_kind_t::unknown);
    } else {
        const auto idx = static_cast<std::size_t>(doc_index);
        if (idx >= documents.size())
            throw std::runtime_error("inject: document index out of range");
        documents[idx]["identity"]["kind"] = static_cast<std::uint8_t>(document_kind_t::unknown);
    }
    return envelope.dump();
}

void verify_golden_round_trips()
{
    const workspace_id_t workspace{5001};
    auto dto = make_workspace(workspace);
    require(dto.validate().ok(), "golden: DTO member validation must succeed");
    const auto member_fingerprint = dto.fingerprint();
    require(member_fingerprint.value != 0,
            "golden: DTO member fingerprint must be non-zero");

    std::string encoded;
    auto encode_result = workbench_persistence_codec_t::encode(dto, encoded);
    require(encode_result.ok(), "golden: encode must succeed");
    require(encode_result.fingerprint.value != 0,
            "golden: encode fingerprint must be non-zero");
    require(encode_result.decoded_schema == k_persistence_codec_schema_v10,
            "golden: encode schema must be v10");
    require(!encoded.empty(), "golden: encoded output must not be empty");

    workbench_persistence_dto_t decoded;
    auto decode_result = workbench_persistence_codec_t::decode(encoded, workspace, decoded);
    require(decode_result.ok(), "golden: decode must succeed");
    require(decode_result.fingerprint.value != 0,
            "golden: decode fingerprint must be non-zero");
    require(decode_result.fingerprint == encode_result.fingerprint,
            "golden: encode and decode fingerprints must match");
    require(member_fingerprint == encode_result.fingerprint,
            "golden: DTO member fingerprint must match encoded fingerprint");
    require(decode_result.decoded_schema == k_persistence_codec_schema_v10,
            "golden: decode schema must be v10");

    require(persistence_dto_equal(dto, decoded),
            "golden: DTOs must be equal after round trip");
    require(dto.equivalent(decoded),
            "golden: DTO member equivalence must survive round trip");
    require(decoded.workspace == workspace, "golden: workspace must match");
    require(decoded.revision == dto.revision, "golden: revision must match");
    require(decoded.documents.size() == dto.documents.size(),
            "golden: document count must match");
    require(decoded.views.size() == dto.views.size(),
            "golden: view count must match");
    require(decoded.panels.size() == dto.panels.size(),
            "golden: panel count must match");
    require(decoded.views[0].id == dto.views[0].id && decoded.views[1].id == dto.views[1].id,
            "golden: flat logical view order must survive round trip");
    require(decoded.documents.front().local_state.cursor.has_position &&
                decoded.documents.front().local_state.selection.extent == 24,
            "golden: document local state must survive round trip");
    require(decoded.panels.size() == 2 && !decoded.panels.back().visible &&
                decoded.panels.back().state_token == "inspector:tab=types",
            "golden: complete panel state must survive round trip");
    require(decoded.history.back.size() == 1 &&
                decoded.history.forward.size() == 1 &&
                decoded.history.back.front().target.selection.extent == 16 &&
                decoded.history.forward.front().source.synchronization_group == 71 &&
                !decoded.history.forward.front().request_focus,
            "golden: navigation history must survive round trip");

    auto member_normalized = dto;
    std::reverse(member_normalized.documents.begin(),
                 member_normalized.documents.end());
    std::reverse(member_normalized.views.begin(), member_normalized.views.end());
    require(member_normalized.normalize().ok(),
            "golden: DTO member normalization must succeed");
    require(member_normalized.equivalent(dto),
            "golden: member normalization must preserve DTO equivalence");

    persistence_fingerprint_t rt_encode_fp;
    persistence_fingerprint_t rt_decode_fp;
    auto rt_result = workbench_persistence_codec_t::round_trip(
        dto, rt_encode_fp, rt_decode_fp);
    require(rt_result.ok(), "golden: round_trip method must succeed");
    require(rt_encode_fp == rt_decode_fp,
            "golden: round_trip fingerprints must match");
    require(rt_encode_fp == encode_result.fingerprint,
            "golden: round_trip fingerprint must match direct encode");

    auto dto2 = make_workspace({5002});
    std::string encoded2;
    require(workbench_persistence_codec_t::encode(dto2, encoded2).ok(),
            "golden: second workspace encode must succeed");
    workbench_persistence_dto_t decoded2;
    require(workbench_persistence_codec_t::decode(
                encoded2, {5002}, decoded2, {}).ok(),
            "golden: second workspace decode must succeed");
    require(decoded2.workspace == workspace_id_t{5002},
            "golden: second workspace must be isolated from first");
    require(persistence_dto_equal(dto2, decoded2),
            "golden: second workspace round trip must be equal");
}

void verify_untrusted_collection_bounds()
{
    const workspace_id_t workspace{5025};
    auto dto = make_workspace(workspace);
    std::string encoded;
    require(workbench_persistence_codec_t::encode(dto, encoded).ok(),
            "bounds: source DTO must encode");

    const auto source = json::parse(encoded.begin(), encoded.end(), nullptr, false);
    require(!source.is_discarded(), "bounds: source envelope must parse");
    const auto decode_fixture = [&](json envelope,
                                    persistence_codec_code_t expected_code,
                                    const char* message) {
        workbench_persistence_dto_t decoded;
        const auto payload = envelope.dump();
        const auto result = workbench_persistence_codec_t::decode(
            payload, workspace, decoded);
        require(result.code == expected_code, message);
    };

    auto excessive_documents = source;
    excessive_documents["payload"]["documents"] = json::array();
    for (std::size_t index = 0;
         index <= static_cast<std::size_t>(k_max_documents_per_workspace);
         ++index)
        excessive_documents["payload"]["documents"].push_back(json::object());
    decode_fixture(std::move(excessive_documents),
                   persistence_codec_code_t::corrupt_payload,
                   "bounds: document count must be rejected before reserve");

    auto excessive_views = source;
    excessive_views["payload"]["views"] = json::array();
    for (std::size_t index = 0;
         index <= static_cast<std::size_t>(k_max_views_per_workspace);
         ++index)
        excessive_views["payload"]["views"].push_back(json::object());
    decode_fixture(std::move(excessive_views),
                   persistence_codec_code_t::corrupt_payload,
                   "bounds: view count must be rejected before reserve");

    auto excessive_panels = source;
    excessive_panels["payload"]["panels"] = json::array();
    for (std::size_t index = 0;
         index <= static_cast<std::size_t>(k_max_panels_per_workspace);
         ++index)
        excessive_panels["payload"]["panels"].push_back(json::object());
    decode_fixture(std::move(excessive_panels),
                   persistence_codec_code_t::corrupt_payload,
                   "bounds: panel count must be rejected before reserve");

    auto excessive_aggregate = source;
    for (const char* field : {"array_budget_a", "array_budget_b",
                              "array_budget_c"}) {
        excessive_aggregate[field] = json::array();
        for (std::size_t index = 0;
             index < 8191U;
             ++index)
            excessive_aggregate[field].push_back(0);
    }
    decode_fixture(std::move(excessive_aggregate),
                   persistence_codec_code_t::oversized_payload,
                   "bounds: aggregate collection count must be rejected before DOM allocation");

    auto excessive_history = source;
    excessive_history["payload"]["history"]["capacity"] =
        std::to_string(k_max_history_capacity);
    excessive_history["payload"]["history"]["back"] = json::array();
    excessive_history["payload"]["history"]["forward"] = json::array();
    for (std::size_t index = 0;
         index <= static_cast<std::size_t>(k_max_history_capacity);
         ++index) {
        excessive_history["payload"]["history"]["back"].push_back(
            json::object());
    }
    decode_fixture(std::move(excessive_history),
                   persistence_codec_code_t::corrupt_payload,
                   "bounds: history count must be rejected before reserve");

    persistence_codec_limits_t inflated_limits;
    inflated_limits.max_serialized_bytes =
        k_persistence_codec_max_serialized_bytes + 1U;
    workbench_persistence_dto_t decoded;
    auto inflated_result = workbench_persistence_codec_t::decode(
        encoded, workspace, decoded, inflated_limits);
    require(inflated_result.code == persistence_codec_code_t::oversized_payload,
            "bounds: caller must not raise hard serialized-byte limit");
}

void verify_corrupt_and_oversized_payloads()
{
    require(workbench_persistence_codec_t::is_corrupt(""),
            "corrupt: empty string must be corrupt");
    require(workbench_persistence_codec_t::is_corrupt("not json"),
            "corrupt: non-JSON must be corrupt");
    require(workbench_persistence_codec_t::is_corrupt("[]"),
            "corrupt: JSON array must be corrupt");
    require(workbench_persistence_codec_t::is_corrupt("{}"),
            "corrupt: empty object must be corrupt");
    require(workbench_persistence_codec_t::is_corrupt(
                "{\"schema\":7,\"payload\":{}}"),
            "corrupt: wrong schema must be corrupt");
    require(workbench_persistence_codec_t::is_corrupt(
                "{\"schema\":4294967305,\"payload\":{}}"),
            "corrupt: narrowing-equivalent schema must be corrupt");
    require(workbench_persistence_codec_t::is_corrupt(
                "{\"schema\":\"9\",\"payload\":{}}"),
            "corrupt: non-numeric schema must be corrupt");
    require(workbench_persistence_codec_t::is_corrupt(
                "{\"schema\":9,\"kind\":\"x\",\"payload\":\"notobj\"}"),
            "corrupt: non-object payload must be corrupt");

    auto dto = make_workspace({5020});
    std::string encoded;
    require(workbench_persistence_codec_t::encode(dto, encoded).ok(),
            "corrupt: valid DTO must encode");
    require(!workbench_persistence_codec_t::is_corrupt(encoded),
            "corrupt: valid v10 envelope must not be corrupt");

    std::string v8_payload = make_v8_payload({5021});
    require(!workbench_persistence_codec_t::is_corrupt(v8_payload),
            "corrupt: valid v8 envelope must not be corrupt");

    require(!workbench_persistence_codec_t::is_oversized(encoded),
            "oversized: normal payload must not be oversized");

    persistence_codec_limits_t byte_limits;
    byte_limits.max_serialized_bytes = encoded.size() - 1;
    require(workbench_persistence_codec_t::is_oversized(encoded, byte_limits),
            "oversized: payload exceeding byte limit must be oversized");

    persistence_codec_limits_t field_limits;
    field_limits.max_field_count = 5;
    require(workbench_persistence_codec_t::is_oversized(encoded, field_limits),
            "oversized: payload exceeding field count must be oversized");

    workbench_persistence_dto_t decoded;
    auto oversized_result = workbench_persistence_codec_t::decode(
        encoded, {5020}, decoded, byte_limits);
    require(oversized_result.code == persistence_codec_code_t::oversized_payload,
            "oversized: decode must reject oversized payload");

    auto invalid_json_result = workbench_persistence_codec_t::decode(
        "not json", {5020}, decoded);
    require(invalid_json_result.code == persistence_codec_code_t::invalid_json,
            "corrupt: decode must reject invalid JSON");

    auto empty_result = workbench_persistence_codec_t::decode(
        "", {5020}, decoded);
    require(empty_result.code == persistence_codec_code_t::empty_input,
            "corrupt: decode must reject empty input");

    auto wrong_schema_result = workbench_persistence_codec_t::decode(
        "{\"schema\":7,\"kind\":\"workbench_persistence_v9\",\"payload\":{}}",
        {5020}, decoded);
    require(wrong_schema_result.code == persistence_codec_code_t::schema_mismatch,
            "corrupt: decode must reject wrong schema");

    auto narrowing_schema_result = workbench_persistence_codec_t::decode(
        "{\"schema\":4294967305,\"kind\":\"workbench_persistence_v9\",\"payload\":{}}",
        {5020}, decoded);
    require(narrowing_schema_result.code ==
                persistence_codec_code_t::schema_mismatch,
            "corrupt: decode must reject narrowing-equivalent schema");

    auto oversized_ordinal = json::parse(
        encoded.begin(), encoded.end(), nullptr, false);
    oversized_ordinal["payload"]["documents"][0]["identity"]["kind"] = 271;
    auto oversized_ordinal_payload = oversized_ordinal.dump();
    auto oversized_ordinal_result = workbench_persistence_codec_t::decode(
        oversized_ordinal_payload, {5020}, decoded);
    require(oversized_ordinal_result.code ==
                persistence_codec_code_t::corrupt_payload,
            "corrupt: decode must reject narrowing-equivalent enum ordinal");

    auto wrong_kind_result = workbench_persistence_codec_t::decode(
        "{\"schema\":9,\"kind\":\"wrong_kind\",\"payload\":{}}",
        {5020}, decoded);
    require(wrong_kind_result.code == persistence_codec_code_t::unknown_kind,
            "corrupt: decode must reject unknown kind");

    auto corrupt_payload_result = workbench_persistence_codec_t::decode(
        "{\"schema\":9,\"kind\":\"workbench_persistence_v9\",\"payload\":\"notobj\"}",
        {5020}, decoded);
    require(corrupt_payload_result.code == persistence_codec_code_t::corrupt_payload,
            "corrupt: decode must reject non-object payload");

    persistence_codec_limits_t depth_limits;
    depth_limits.max_json_depth = 1;
    auto depth_result = workbench_persistence_codec_t::decode(
        encoded, {5020}, decoded, depth_limits);
    require(depth_result.code == persistence_codec_code_t::oversized_payload,
            "corrupt: decode must reject excessive JSON depth");

    persistence_codec_limits_t tight_field_limits;
    tight_field_limits.max_field_count = 1;
    auto field_result = workbench_persistence_codec_t::decode(
        encoded, {5020}, decoded, tight_field_limits);
    require(field_result.code == persistence_codec_code_t::field_count_exceeded,
            "corrupt: decode must reject excessive field count");
}

void verify_v8_default_creation()
{
    const workspace_id_t workspace{5030};
    std::string v8_payload = make_v8_payload(workspace);

    workbench_persistence_dto_t decoded;
    auto result = workbench_persistence_codec_t::decode_v8_default(
        v8_payload, workspace, decoded);
    require(result.ok(), "v8: decode_v8_default must succeed");
    require(result.decoded_schema == k_persistence_codec_schema_v8,
            "v8: decoded schema must report v8");
    require(result.fingerprint.value != 0,
            "v8: fingerprint must be non-zero");
    require(decoded.workspace == workspace,
            "v8: workspace must match");
    require(decoded.schema_version == k_workbench_contract_schema_version,
            "v8: schema_version must be upgraded to contract version");
    require(decoded.panels.empty(),
            "v8: panels must be empty after upgrade");
    require(!decoded.documents.empty(),
            "v8: documents must not be empty after upgrade");
    require(!decoded.views.empty(),
            "v8: views must not be empty after upgrade");
    require(decoded.active_document.valid(),
            "v8: active_document must be valid after upgrade");
    require(decoded.history.workspace == workspace,
            "v8: history workspace must be set");

    for (const auto& view : decoded.views)
        require(view.workspace == workspace,
                "v8: all views must have workspace set after upgrade");

    workbench_persistence_dto_t wrong_ws_decoded;
    auto wrong_ws_result = workbench_persistence_codec_t::decode_v8_default(
        v8_payload, {9999}, wrong_ws_decoded);
    require(wrong_ws_result.code ==
            persistence_codec_code_t::workspace_isolation_violation,
            "v8: wrong workspace must be rejected");

    auto v8_empty_result = workbench_persistence_codec_t::decode_v8_default(
        "", workspace, wrong_ws_decoded);
    require(v8_empty_result.code == persistence_codec_code_t::empty_input,
            "v8: empty input must be rejected");

    auto v8_bad_json_result = workbench_persistence_codec_t::decode_v8_default(
        "not json", workspace, wrong_ws_decoded);
    require(v8_bad_json_result.code == persistence_codec_code_t::invalid_json,
            "v8: invalid JSON must be rejected");

    auto v8_corrupt_result = workbench_persistence_codec_t::decode_v8_default(
        "{\"schema\":8,\"payload\":\"notobj\"}", workspace, wrong_ws_decoded);
    require(v8_corrupt_result.code == persistence_codec_code_t::corrupt_payload,
            "v8: corrupt payload must be rejected");

    auto v8_wrong_schema_result = workbench_persistence_codec_t::decode_v8_default(
        "{\"schema\":7,\"payload\":{}}", workspace, wrong_ws_decoded);
    require(v8_wrong_schema_result.code ==
            persistence_codec_code_t::v8_legacy_unsupported,
            "v8: wrong schema must be rejected with v8_legacy_unsupported");

    auto v8_extra_fields_result = workbench_persistence_codec_t::decode_v8_default(
        "{\"schema\":8,\"payload\":{},\"extra\":true}", workspace,
        wrong_ws_decoded);
    require(!v8_extra_fields_result.ok(),
            "v8: envelope with extra fields must be rejected");
}

void verify_v9_geometry_migration()
{
    const workspace_id_t workspace{5031};
    const auto legacy = make_v9_payload(workspace);
    workbench_persistence_dto_t decoded;
    const auto result = workbench_persistence_codec_t::decode(legacy, workspace, decoded);
    require(result.ok() && result.decoded_schema == k_persistence_codec_schema_v9,
            "v9 migration: bounded legacy envelope must decode");
    require(decoded.schema_version == k_workbench_contract_schema_version &&
                decoded.views.size() == 2 && decoded.views[0].id == view_id_t{12} &&
                decoded.views[1].id == view_id_t{11},
            "v9 migration: legacy leaf traversal must become stable logical view order");
    require(decoded.active_document == document_id_t{1} && decoded.views[1].focused,
            "v9 migration: active document and focused logical surface must survive");
    std::string migrated;
    require(workbench_persistence_codec_t::encode(decoded, migrated).ok(),
            "v9 migration: migrated state must encode in the current schema");
    const auto current = json::parse(migrated.begin(), migrated.end(), nullptr, false);
    require(!current.is_discarded() && current["schema"] == k_persistence_codec_schema_v10 &&
                !current["payload"].contains("split_tree") &&
                !current["payload"].contains("layout"),
            "v9 migration: obsolete geometry must never be written again");
    for (const auto& panel : current["payload"]["panels"])
        require(!panel.contains("extent_pixels"),
                "v9 migration: panel pixel geometry must be discarded");
}

void verify_deterministic_normalization()
{
    const workspace_id_t workspace{5040};
    auto dto = make_workspace(workspace);

    persistence_codec_result_t result1;
    std::string encoded1 = workbench_persistence_codec_t::normalize_and_encode(
        dto, result1);
    require(result1.ok(), "deterministic: first encode must succeed");

    persistence_codec_result_t result2;
    std::string encoded2 = workbench_persistence_codec_t::normalize_and_encode(
        dto, result2);
    require(result2.ok(), "deterministic: second encode must succeed");
    require(encoded1 == encoded2,
            "deterministic: identical DTOs must produce identical encoded output");
    require(result1.fingerprint == result2.fingerprint,
            "deterministic: identical DTOs must produce identical fingerprints");

    auto shuffled = dto;
    std::reverse(shuffled.documents.begin(), shuffled.documents.end());
    std::reverse(shuffled.panels.begin(), shuffled.panels.end());

    persistence_codec_result_t result3;
    std::string encoded3 = workbench_persistence_codec_t::normalize_and_encode(
        shuffled, result3);
    require(result3.ok(), "deterministic: shuffled encode must succeed");
    require(encoded3 == encoded1,
            "deterministic: shuffled DTO must produce identical output after normalization");
    require(result3.fingerprint == result1.fingerprint,
            "deterministic: shuffled DTO must produce identical fingerprint");

    auto reordered_views = dto;
    std::reverse(reordered_views.views.begin(), reordered_views.views.end());
    persistence_codec_result_t reordered_result;
    const auto reordered_encoded = workbench_persistence_codec_t::normalize_and_encode(
        reordered_views, reordered_result);
    require(reordered_result.ok() && reordered_encoded != encoded1 &&
                reordered_result.fingerprint != result1.fingerprint,
            "deterministic: logical view order must remain persisted identity");

    workbench_persistence_dto_t decoded;
    persistence_fingerprint_t decode_fp;
    auto decode_result = workbench_persistence_codec_t::decode_and_normalize(
        encoded1, workspace, decoded, decode_fp);
    require(decode_result.ok(),
            "deterministic: decode_and_normalize must succeed");
    require(decode_fp == result1.fingerprint,
            "deterministic: decode fingerprint must match encode fingerprint");
    require(persistence_dto_equal(dto, decoded),
            "deterministic: decoded DTO must equal original after normalization");

    std::string re_encoded;
    auto re_encode_result = workbench_persistence_codec_t::encode(
        decoded, re_encoded);
    require(re_encode_result.ok(),
            "deterministic: re-encode of decoded must succeed");
    require(re_encoded == encoded1,
            "deterministic: re-encode of decoded must produce identical output");
    require(re_encode_result.fingerprint == result1.fingerprint,
            "deterministic: re-encode fingerprint must match original");
}

void verify_workspace_isolation()
{
    const workspace_id_t workspace{5050};
    auto dto = make_workspace(workspace);
    std::string encoded;
    require(workbench_persistence_codec_t::encode(dto, encoded).ok(),
            "isolation: encode must succeed");

    workbench_persistence_dto_t decoded;
    auto correct_result = workbench_persistence_codec_t::decode(
        encoded, workspace, decoded);
    require(correct_result.ok(),
            "isolation: decode with correct workspace must succeed");

    auto wrong_result = workbench_persistence_codec_t::decode(
        encoded, {9999}, decoded);
    require(wrong_result.code ==
            persistence_codec_code_t::workspace_isolation_violation,
            "isolation: decode with wrong workspace must fail");

    auto zero_result = workbench_persistence_codec_t::decode(
        encoded, {0}, decoded);
    require(zero_result.code ==
            persistence_codec_code_t::workspace_isolation_violation,
            "isolation: decode with zero workspace must fail");

    auto dto_a = make_workspace({5051});
    auto dto_b = make_workspace({5052});
    std::string encoded_a;
    std::string encoded_b;
    require(workbench_persistence_codec_t::encode(dto_a, encoded_a).ok(),
            "isolation: workspace A encode must succeed");
    require(workbench_persistence_codec_t::encode(dto_b, encoded_b).ok(),
            "isolation: workspace B encode must succeed");

    workbench_persistence_dto_t decoded_a;
    workbench_persistence_dto_t decoded_b;
    require(workbench_persistence_codec_t::decode(
                encoded_a, {5051}, decoded_a).ok(),
            "isolation: workspace A decode must succeed");
    require(workbench_persistence_codec_t::decode(
                encoded_b, {5052}, decoded_b).ok(),
            "isolation: workspace B decode must succeed");
    require(decoded_a.workspace == workspace_id_t{5051},
            "isolation: workspace A must remain isolated");
    require(decoded_b.workspace == workspace_id_t{5052},
            "isolation: workspace B must remain isolated");
    require(!persistence_dto_equal(decoded_a, decoded_b),
            "isolation: different workspaces must not be equal");

    auto cross_result = workbench_persistence_codec_t::decode(
        encoded_a, {5052}, decoded);
    require(cross_result.code ==
            persistence_codec_code_t::workspace_isolation_violation,
            "isolation: cross-workspace decode must fail");
}

void verify_unknown_document_recovery()
{
    const workspace_id_t workspace{5060};
    auto dto = make_workspace(workspace);
    std::string encoded;
    require(workbench_persistence_codec_t::encode(dto, encoded).ok(),
            "recovery: source encode must succeed");

    std::string unknown_payload = inject_unknown_kind(encoded, 0);
    require(!unknown_payload.empty(),
            "recovery: unknown-kind payload must be constructed");

    workbench_persistence_dto_t rejected;
    auto reject_result = workbench_persistence_codec_t::decode_with_recovery(
        unknown_payload, workspace, {},
        unknown_document_recovery_t::reject, rejected);
    require(!reject_result.ok(),
            "recovery: reject policy must fail on unknown kind");

    workbench_persistence_dto_t upgraded;
    auto upgrade_result = workbench_persistence_codec_t::decode_with_recovery(
        unknown_payload, workspace, {},
        unknown_document_recovery_t::upgrade, upgraded);
    require(upgrade_result.ok(),
            "recovery: upgrade policy must succeed");
    require(upgraded.documents.size() == dto.documents.size(),
            "recovery: upgrade must retain all documents");
    bool found_custom = false;
    for (const auto& doc : upgraded.documents) {
        if (doc.identity.kind == document_kind_t::custom)
            found_custom = true;
    }
    require(found_custom,
            "recovery: upgrade must change unknown kind to custom");
    require(upgrade_result.fingerprint.value != 0,
            "recovery: upgrade fingerprint must be non-zero");
    require(!upgrade_result.detail.empty(),
            "recovery: upgrade must report recovery detail");

    workbench_persistence_dto_t omitted;
    auto omit_result = workbench_persistence_codec_t::decode_with_recovery(
        unknown_payload, workspace, {},
        unknown_document_recovery_t::omit, omitted);
    require(omit_result.ok(),
            "recovery: omit policy must succeed");
    require(omitted.documents.size() == dto.documents.size() - 1,
            "recovery: omit must remove one document");
    require(omitted.active_document.valid(),
            "recovery: omit must retain valid active_document");
    require(omit_result.fingerprint.value != 0,
            "recovery: omit fingerprint must be non-zero");
    for (const auto& doc : omitted.documents)
        require(doc.identity.kind != document_kind_t::unknown,
                "recovery: omit must leave no unknown-kind documents");
    for (const auto& view : omitted.views)
        require(view.workspace == workspace,
                "recovery: omit must preserve workspace isolation for views");

    std::string all_unknown_payload = inject_unknown_kind(encoded, -1);
    workbench_persistence_dto_t all_omitted;
    auto exhausted_result = workbench_persistence_codec_t::decode_with_recovery(
        all_unknown_payload, workspace, {},
        unknown_document_recovery_t::omit, all_omitted);
    require(exhausted_result.code ==
            persistence_codec_code_t::recovery_exhausted,
            "recovery: all-unknown omit must fail with recovery_exhausted");

    workbench_persistence_dto_t all_upgraded;
    auto all_upgrade_result = workbench_persistence_codec_t::decode_with_recovery(
        all_unknown_payload, workspace, {},
        unknown_document_recovery_t::upgrade, all_upgraded);
    require(all_upgrade_result.ok(),
            "recovery: all-unknown upgrade must succeed");
    require(all_upgraded.documents.size() == dto.documents.size(),
            "recovery: all-unknown upgrade must retain all documents");

    workbench_persistence_dto_t clean;
    auto clean_result = workbench_persistence_codec_t::decode_with_recovery(
        encoded, workspace, {},
        unknown_document_recovery_t::reject, clean);
    require(clean_result.ok(),
            "recovery: reject on clean payload must succeed");
    require(clean_result.detail.empty(),
            "recovery: clean payload must have empty recovery detail");

    auto clean_omit_result = workbench_persistence_codec_t::decode_with_recovery(
        encoded, workspace, {},
        unknown_document_recovery_t::omit, clean);
    require(clean_omit_result.ok(),
            "recovery: omit on clean payload must succeed");
    require(clean_omit_result.detail.empty(),
            "recovery: omit on clean payload must have empty detail");

    std::string second_unknown = inject_unknown_kind(encoded, 1);
    workbench_persistence_dto_t second_omitted;
    auto second_omit_result = workbench_persistence_codec_t::decode_with_recovery(
        second_unknown, workspace, {},
        unknown_document_recovery_t::omit, second_omitted);
    require(second_omit_result.ok(),
            "recovery: omit on second unknown document must succeed");
    require(second_omitted.documents.size() == dto.documents.size() - 1,
            "recovery: omit must remove the second unknown document");
    require(second_omitted.active_document.valid(),
            "recovery: omit must fix active_document when needed");
    for (const auto& panel : second_omitted.panels) {
        if (panel.selected_document.valid())
            require(panel.selected_document != document_id_t{2},
                    "recovery: omit must clear panel selected_document for removed doc");
    }
}

void verify_workspace_revision_conflicts()
{
    const workspace_id_t workspace{5070};
    auto dto = make_workspace(workspace);
    dto.revision = {42};
    std::string encoded;
    require(workbench_persistence_codec_t::encode(dto, encoded).ok(),
            "revision: encode must succeed");

    workbench_persistence_dto_t decoded;
    auto match_result = workbench_persistence_codec_t::decode_with_recovery(
        encoded, workspace, {42},
        unknown_document_recovery_t::reject, decoded);
    require(match_result.ok(),
            "revision: matching revision must succeed");

    auto mismatch_result = workbench_persistence_codec_t::decode_with_recovery(
        encoded, workspace, {99},
        unknown_document_recovery_t::reject, decoded);
    require(mismatch_result.code ==
            persistence_codec_code_t::revision_conflict,
            "revision: mismatched revision must fail with revision_conflict");

    auto skip_result = workbench_persistence_codec_t::decode_with_recovery(
        encoded, workspace, {0},
        unknown_document_recovery_t::reject, decoded);
    require(skip_result.ok(),
            "revision: zero expected revision must skip check and succeed");

    auto conflict_ok = workbench_persistence_codec_t::check_revision_conflict(
        {42}, {42});
    require(conflict_ok.ok(),
            "revision: check_revision_conflict matching must succeed");

    auto conflict_mismatch = workbench_persistence_codec_t::check_revision_conflict(
        {42}, {43});
    require(conflict_mismatch.code ==
            persistence_codec_code_t::revision_conflict,
            "revision: check_revision_conflict mismatch must fail");

    auto conflict_skip = workbench_persistence_codec_t::check_revision_conflict(
        {0}, {43});
    require(conflict_skip.ok(),
            "revision: check_revision_conflict with invalid expected must skip");

    auto conflict_observed_invalid =
        workbench_persistence_codec_t::check_revision_conflict({42}, {0});
    require(conflict_observed_invalid.code ==
            persistence_codec_code_t::revision_conflict,
            "revision: check_revision_conflict with invalid observed must fail");

    auto conflict_both_invalid =
        workbench_persistence_codec_t::check_revision_conflict({0}, {0});
    require(conflict_both_invalid.ok(),
            "revision: check_revision_conflict with both invalid must skip");

    std::string unknown_payload = inject_unknown_kind(encoded, 0);
    workbench_persistence_dto_t recovered;
    auto combined_result = workbench_persistence_codec_t::decode_with_recovery(
        unknown_payload, workspace, {42},
        unknown_document_recovery_t::omit, recovered);
    require(combined_result.ok(),
            "revision: revision check with recovery must succeed");
    require(recovered.documents.size() == dto.documents.size() - 1,
            "revision: recovery with revision check must remove unknown doc");

    auto combined_conflict = workbench_persistence_codec_t::decode_with_recovery(
        unknown_payload, workspace, {99},
        unknown_document_recovery_t::omit, recovered);
    require(combined_conflict.code ==
            persistence_codec_code_t::revision_conflict,
            "revision: revision conflict must take precedence over recovery");
}

void verify_envelope_peeking_and_edge_cases()
{
    auto dto = make_workspace({5080});
    std::string encoded;
    require(workbench_persistence_codec_t::encode(dto, encoded).ok(),
            "peek: encode must succeed");

    auto envelope = workbench_persistence_codec_t::peek_envelope(encoded);
    require(envelope.has_value(),
            "peek: valid envelope must be detected");
    require(envelope->schema == k_persistence_codec_schema_v10,
            "peek: v10 schema must be detected");
    require(envelope->kind == k_persistence_codec_kind_v10,
            "peek: v10 kind must be detected");
    require(!envelope->is_v8_legacy,
            "peek: v10 must not be v8 legacy");
    require(!envelope->is_v9_legacy,
            "peek: v10 must not be v9 legacy");

    const auto v9_payload = make_v9_payload({5082});
    const auto v9_envelope = workbench_persistence_codec_t::peek_envelope(v9_payload);
    require(v9_envelope.has_value() && v9_envelope->is_v9_legacy &&
                v9_envelope->schema == k_persistence_codec_schema_v9,
            "peek: v9 must be flagged as legacy");

    std::string v8_payload = make_v8_payload({5081});
    auto v8_envelope = workbench_persistence_codec_t::peek_envelope(v8_payload);
    require(v8_envelope.has_value(),
            "peek: v8 envelope must be detected");
    require(v8_envelope->schema == k_persistence_codec_schema_v8,
            "peek: v8 schema must be detected");
    require(v8_envelope->is_v8_legacy,
            "peek: v8 must be flagged as legacy");

    auto empty_envelope = workbench_persistence_codec_t::peek_envelope("");
    require(!empty_envelope.has_value(),
            "peek: empty input must return nullopt");

    auto invalid_envelope = workbench_persistence_codec_t::peek_envelope(
        "not json");
    require(!invalid_envelope.has_value(),
            "peek: invalid JSON must return nullopt");

    std::string large_input(k_persistence_codec_max_envelope_bytes + 1, 'x');
    auto large_envelope = workbench_persistence_codec_t::peek_envelope(
        large_input);
    require(!large_envelope.has_value(),
            "peek: oversized input must return nullopt");

    auto no_schema_envelope = workbench_persistence_codec_t::peek_envelope(
        "{\"kind\":\"x\",\"payload\":{}}");
    require(!no_schema_envelope.has_value(),
            "peek: missing schema must return nullopt");

    auto non_numeric_schema = workbench_persistence_codec_t::peek_envelope(
        "{\"schema\":\"9\",\"payload\":{}}");
    require(!non_numeric_schema.has_value(),
            "peek: non-numeric schema must return nullopt");

    auto no_kind_envelope = workbench_persistence_codec_t::peek_envelope(
        "{\"schema\":9,\"payload\":{}}");
    require(no_kind_envelope.has_value(),
            "peek: envelope without kind must still be detected");
    require(no_kind_envelope->kind.empty(),
            "peek: missing kind must produce empty kind string");
    require(!no_kind_envelope->is_v8_legacy,
            "peek: schema 9 without kind must not be v8 legacy");

    auto v8_no_kind_envelope = workbench_persistence_codec_t::peek_envelope(
        "{\"schema\":8,\"payload\":{}}");
    require(v8_no_kind_envelope.has_value(),
            "peek: v8 envelope without kind must be detected");
    require(v8_no_kind_envelope->is_v8_legacy,
            "peek: v8 schema must flag as legacy even without kind");

    const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
    auto max_revision_dto = make_workspace({5090});
    max_revision_dto.revision = {maximum};
    for (auto& panel : max_revision_dto.panels)
        panel.revision = {maximum};
    std::string max_encoded;
    auto max_encode_result = workbench_persistence_codec_t::encode(
        max_revision_dto, max_encoded);
    require(max_encode_result.ok(),
            "edge: maximum revision DTO must encode");
    workbench_persistence_dto_t max_decoded;
    auto max_decode_result = workbench_persistence_codec_t::decode(
        max_encoded, {5090}, max_decoded);
    require(max_decode_result.ok(),
            "edge: maximum revision DTO must decode");
    require(max_decoded.revision == workspace_revision_t{maximum},
            "edge: maximum revision must survive round trip");
    require(persistence_dto_equal(max_revision_dto, max_decoded),
            "edge: maximum revision DTO must be equal after round trip");

    auto max_conflict = workbench_persistence_codec_t::check_revision_conflict(
        {maximum}, {maximum});
    require(max_conflict.ok(),
            "edge: maximum revision self-conflict check must pass");

    auto max_mismatch = workbench_persistence_codec_t::check_revision_conflict(
        {maximum}, {maximum - 1U});
    require(max_mismatch.code == persistence_codec_code_t::revision_conflict,
            "edge: maximum revision mismatch must be detected");
}

void verify_database_adapter_queue_and_close()
{
    infra::taskflow_runtime::initialize();
    database_fixture_t fixture;
    open_database_fixture(fixture);

    const workspace_id_t workspace{5100};
    workspace_database_workbench_persistence_adapter_t adapter(
        fixture.database, workspace);
    workbench_persistence_dto_t missing;
    auto missing_result = adapter.load(workspace, missing);
    require(missing_result.code == workbench_error_code_t::adapter_rejected,
            "adapter: empty database load must be rejected");

    auto first = make_workspace(workspace);
    require(adapter.store(first).ok(),
            "adapter: queued first revision store must succeed");
    workbench_persistence_dto_t loaded_first;
    require(adapter.load(workspace, loaded_first).ok(),
            "adapter: first revision load must succeed");
    require(first.equivalent(loaded_first),
            "adapter: first revision must retain complete DTO state");
    require(first.fingerprint() == loaded_first.fingerprint(),
            "adapter: first revision fingerprint must survive storage");

    auto second = first;
    second.revision = {2};
    second.documents.front().state_token = "primary-state-revision-2";
    second.documents.back().local_state.cursor = {true, 0x402099U};
    second.panels.back().visible = true;
    second.panels.back().state_token = "inspector:tab=decompiler";
    for (auto& panel : second.panels)
        panel.revision = second.revision;
    require(second.validate().ok(),
            "adapter: second revision DTO must validate");
    require(adapter.store(second).ok(),
            "adapter: queued second revision store must succeed");

    workbench_persistence_dto_t loaded_second;
    require(adapter.load(workspace, loaded_second).ok(),
            "adapter: second revision load must succeed");
    require(second.equivalent(loaded_second),
            "adapter: split, document, panel, and history DTO state must persist");
    require(loaded_second.revision == workspace_revision_t{2},
            "adapter: second revision must replace first revision atomically");

    auto stale = first;
    auto stale_result = adapter.store(stale);
    require(stale_result.code == workbench_error_code_t::revision_mismatch,
            "adapter: stale queued revision must be rejected");

    workspace_revision_t expected_revision = second.revision;
    for (std::uint64_t cycle = 0; cycle < 3; ++cycle) {
        workbench_persistence_dto_t persisted;
        require(adapter.load(workspace, persisted).ok() &&
                    persisted.revision == expected_revision,
                "adapter: reopen cycle must load the exact committed revision");
        persistence_catalog_t catalog(persisted);
        workbench_model_t model;
        workbench_snapshot_ptr_t initial;
        require(model.create_workspace(make_workspace(workspace), initial).ok(),
                "adapter: reopen cycle model must initialize");
        const auto restored = model.restore_workspace(
            workspace, initial->revision(), adapter, catalog,
            missing_document_policy_t::reject);
        require(restored.error.ok() && restored.changed && restored.snapshot &&
                    restored.snapshot->revision() == expected_revision &&
                    persistence_dto_equal(restored.snapshot->persistence(), persisted),
                "adapter: restored model must adopt the committed revision baseline");

        const auto no_op = model.restore_workspace(
            workspace, restored.snapshot->revision(), persisted, catalog,
            missing_document_policy_t::reject);
        require(no_op.error.ok() && !no_op.changed &&
                    no_op.snapshot == restored.snapshot,
                "adapter: exact repeated restore must be a snapshot-preserving no-op");

        workbench_command_t focus;
        focus.kind = workbench_command_kind_t::focus_view;
        focus.workspace = workspace;
        focus.expected_revision = restored.snapshot->revision();
        focus.view = cycle % 2U == 0 ? view_id_t{12} : view_id_t{11};
        const auto mutated = model.execute(focus);
        require(mutated.error.ok() && mutated.changed && mutated.snapshot &&
                    mutated.snapshot->revision().value == expected_revision.value + 1U &&
                    restored.snapshot->revision() == expected_revision,
                "adapter: post-reopen mutation must advance exactly one revision");
        require(adapter.store(mutated.snapshot->persistence()).ok(),
                "adapter: strict database must accept the next restored-model revision");
        const auto stale_cycle_store = adapter.store(persisted);
        require(stale_cycle_store.code == workbench_error_code_t::revision_mismatch,
                "adapter: prior reopen generation must become stale after commit");
        expected_revision = mutated.snapshot->revision();
    }

    std::vector<std::future<bool>> concurrent_reads;
    concurrent_reads.reserve(12);
    for (std::size_t index = 0; index < 12; ++index) {
        concurrent_reads.push_back(std::async(
            std::launch::async, [&adapter, workspace, expected_revision] {
                workbench_persistence_dto_t loaded;
                return adapter.load(workspace, loaded).ok() &&
                    loaded.revision == expected_revision;
            }));
    }
    for (auto& read : concurrent_reads)
        require(read.get(),
                "adapter: concurrent reads must observe the same committed revision");

    workbench_persistence_dto_t wrong_workspace;
    auto isolation_result = adapter.load({5101}, wrong_workspace);
    require(isolation_result.code == workbench_error_code_t::workspace_mismatch,
            "adapter: cross-workspace load must be rejected");

    fixture.database->request_cancel();
    workbench_persistence_dto_t after_close;
    auto closed_result = adapter.load(workspace, after_close);
    require(closed_result.code == workbench_error_code_t::adapter_rejected,
            "adapter: closed database must reject new reads");
    fixture.close();
}

}

bool run_workbench_persistence_harness(std::string& failure)
{
    try {
        verify_golden_round_trips();
        verify_corrupt_and_oversized_payloads();
        verify_untrusted_collection_bounds();
        verify_v8_default_creation();
        verify_v9_geometry_migration();
        verify_deterministic_normalization();
        verify_workspace_isolation();
        verify_unknown_document_recovery();
        verify_workspace_revision_conflicts();
        verify_envelope_peeking_and_edge_cases();
        verify_database_adapter_queue_and_close();
        failure.clear();
        return true;
    } catch (const std::exception& exception) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(exception.what());
        failure = exception.what();
        return false;
    }
}

}
}

int main()
{
    std::string failure;
    if (!aida::workbench::run_workbench_persistence_harness(failure)) {
        std::cerr << "workbench_persistence_harness failed: " << failure << '\n';
        return 1;
    }
    std::cout << "workbench_persistence_harness source contract satisfied\n";
    return 0;
}
