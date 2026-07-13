#include "workbench_persistence_harness.hpp"

#include "../../src/core/workbench/workbench_persistence.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace aida {
namespace workbench {
namespace {

using json = nlohmann::json;

void require(bool condition, const char* message)
{
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

document_persistence_dto_t make_document_record(workspace_id_t workspace,
                                                 std::uint64_t document_id,
                                                 std::uint64_t object_id)
{
    document_persistence_dto_t document;
    document.id = {document_id};
    document.identity = make_identity(workspace, object_id);
    document.title = "doc-" + std::to_string(document_id);
    document.state_token = "state-" + std::to_string(document_id);
    return document;
}

workbench_persistence_dto_t make_workspace(workspace_id_t workspace)
{
    workbench_persistence_dto_t dto;
    dto.workspace = workspace;
    dto.revision = {1};
    dto.history.workspace = workspace;

    document_persistence_dto_t first;
    first.id = {1};
    first.identity = make_identity(workspace, 1);
    first.title = "primary";
    first.state_token = "primary-state";

    document_persistence_dto_t second;
    second.id = {2};
    second.identity = make_identity(workspace, 2);
    second.title = "secondary";
    second.state_token = "secondary-state";

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

    dto.views = {first_view, second_view};

    split_node_dto_t first_leaf;
    first_leaf.id = {101};
    first_leaf.kind = split_node_kind_t::leaf;
    first_leaf.view = first_view.id;

    split_node_dto_t second_leaf;
    second_leaf.id = {102};
    second_leaf.kind = split_node_kind_t::leaf;
    second_leaf.view = second_view.id;

    split_node_dto_t root;
    root.id = {103};
    root.kind = split_node_kind_t::branch;
    root.orientation = split_orientation_t::horizontal;
    root.ratio_basis_points = k_split_ratio_default_basis_points;
    root.first = first_leaf.id;
    root.second = second_leaf.id;

    dto.split_tree.root = root.id;
    dto.split_tree.nodes = {root, second_leaf, first_leaf};

    panel_state_dto_t panel;
    panel.id = {401};
    panel.workspace = workspace;
    panel.kind = panel_kind_t::navigator;
    panel.extent_pixels = dto.layout.navigator_pixels;
    panel.revision = dto.revision;
    panel.selected_document = first.id;
    dto.panels = {panel};
    return dto;
}

std::string make_v8_payload(workspace_id_t workspace)
{
    auto dto = make_workspace(workspace);
    std::string v9_encoded;
    const auto encode_result = workbench_persistence_codec_t::encode(dto, v9_encoded);
    if (!encode_result.ok())
        throw std::runtime_error("v8 fixture: failed to encode source v9 DTO");

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

std::string inject_unknown_kind(const std::string& v9_encoded, int doc_index)
{
    auto envelope = json::parse(v9_encoded.begin(), v9_encoded.end(), nullptr, false);
    if (envelope.is_discarded() || !envelope.is_object())
        throw std::runtime_error("inject: failed to parse v9 envelope");

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

    std::string encoded;
    auto encode_result = workbench_persistence_codec_t::encode(dto, encoded);
    require(encode_result.ok(), "golden: encode must succeed");
    require(encode_result.fingerprint.value != 0,
            "golden: encode fingerprint must be non-zero");
    require(encode_result.decoded_schema == k_persistence_codec_schema_v9,
            "golden: encode schema must be v9");
    require(!encoded.empty(), "golden: encoded output must not be empty");

    workbench_persistence_dto_t decoded;
    auto decode_result = workbench_persistence_codec_t::decode(encoded, workspace, decoded);
    require(decode_result.ok(), "golden: decode must succeed");
    require(decode_result.fingerprint.value != 0,
            "golden: decode fingerprint must be non-zero");
    require(decode_result.fingerprint == encode_result.fingerprint,
            "golden: encode and decode fingerprints must match");
    require(decode_result.decoded_schema == k_persistence_codec_schema_v9,
            "golden: decode schema must be v9");

    require(persistence_dto_equal(dto, decoded),
            "golden: DTOs must be equal after round trip");
    require(decoded.workspace == workspace, "golden: workspace must match");
    require(decoded.revision == dto.revision, "golden: revision must match");
    require(decoded.documents.size() == dto.documents.size(),
            "golden: document count must match");
    require(decoded.views.size() == dto.views.size(),
            "golden: view count must match");
    require(decoded.panels.size() == dto.panels.size(),
            "golden: panel count must match");
    require(decoded.split_tree.nodes.size() == dto.split_tree.nodes.size(),
            "golden: split tree node count must match");

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
    persistence_fingerprint_t fp2;
    workbench_persistence_dto_t decoded2;
    require(workbench_persistence_codec_t::decode(
                encoded2, {5002}, decoded2, {}).ok(),
            "golden: second workspace decode must succeed");
    require(decoded2.workspace == workspace_id_t{5002},
            "golden: second workspace must be isolated from first");
    require(persistence_dto_equal(dto2, decoded2),
            "golden: second workspace round trip must be equal");
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
            "corrupt: valid v9 envelope must not be corrupt");

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
    require(decoded.split_tree.nodes.empty(),
            "v8: split tree must be empty after upgrade");
    require(decoded.panels.empty(),
            "v8: panels must be empty after upgrade");
    require(decoded.layout.splitter_pixels > 0,
            "v8: layout must have normalized splitter_pixels");
    require(decoded.layout.minimum_document_width_pixels > 0,
            "v8: layout must have normalized minimum_document_width_pixels");
    require(decoded.layout.minimum_document_height_pixels > 0,
            "v8: layout must have normalized minimum_document_height_pixels");
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
    std::reverse(shuffled.views.begin(), shuffled.views.end());
    std::reverse(shuffled.split_tree.nodes.begin(),
                 shuffled.split_tree.nodes.end());
    std::reverse(shuffled.panels.begin(), shuffled.panels.end());

    persistence_codec_result_t result3;
    std::string encoded3 = workbench_persistence_codec_t::normalize_and_encode(
        shuffled, result3);
    require(result3.ok(), "deterministic: shuffled encode must succeed");
    require(encoded3 == encoded1,
            "deterministic: shuffled DTO must produce identical output after normalization");
    require(result3.fingerprint == result1.fingerprint,
            "deterministic: shuffled DTO must produce identical fingerprint");

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
    require(envelope->schema == k_persistence_codec_schema_v9,
            "peek: v9 schema must be detected");
    require(envelope->kind == k_persistence_codec_kind_v9,
            "peek: v9 kind must be detected");
    require(!envelope->is_v8_legacy,
            "peek: v9 must not be v8 legacy");

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

}

bool run_workbench_persistence_harness(std::string& failure)
{
    try {
        verify_golden_round_trips();
        verify_corrupt_and_oversized_payloads();
        verify_v8_default_creation();
        verify_deterministic_normalization();
        verify_workspace_isolation();
        verify_unknown_document_recovery();
        verify_workspace_revision_conflicts();
        verify_envelope_peeking_and_edge_cases();
        failure.clear();
        return true;
    } catch (const std::exception& exception) {
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
