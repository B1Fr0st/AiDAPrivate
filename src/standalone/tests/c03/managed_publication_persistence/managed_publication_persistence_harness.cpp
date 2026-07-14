#include "managed_publication_persistence_harness.hpp"

#include "../assertion_telemetry/assertion_telemetry.hpp"
#include "../analysis_memory_provider.hpp"
#include "../../../src/core/analysis/decompiler/managed_entity_binding.hpp"
#include "../../../src/core/analysis/workspace/overlay_journal.hpp"
#include "../../../src/core/analysis/workspace/workspace_database.hpp"
#include "../../analysis_workspace/workspace_fixture_builder.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <future>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis {

namespace {

using readers::managed::managed_artifact_kind_t;
using test_fixture::close_workspace;
using test_fixture::fixture_error_t;
using test_fixture::fixture_root_t;
using test_fixture::install_services;
using test_fixture::open_workspace;
using test_fixture::write_bytes_fixture;

void require(bool condition, const std::string& message) {
    c03_test::assertion_telemetry::record_assertion(
        condition, message, __FILE__, __LINE__);
    if (!condition)
        throw fixture_error_t(message);
}

void require_success(const workspace_result_t<void>& result,
                     const std::string& phase) {
    c03_test::assertion_telemetry::record_assertion(
        static_cast<bool>(result), phase, __FILE__, __LINE__);
    if (!result)
        throw fixture_error_t(
            phase + ":" + result.error().stable_code() + ":" +
            result.error().message);
}

void wait_ticket(const persistence_ticket_t& ticket) {
    require(ticket.accepted && ticket.completion.valid() &&
                ticket.snapshot_candidate,
            "managed persistence candidate was not accepted");
    require(ticket.completion.wait_for(std::chrono::seconds(10)) ==
                std::future_status::ready,
            "managed persistence candidate did not reach a terminal state");
    const auto& completed = ticket.completion.get();
    require_success(completed, "managed.persistence");
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& bytes,
                       std::size_t offset) {
    require(offset <= bytes.size() && bytes.size() - offset >= 4,
            "managed fixture u32 read exceeds its domain");
    return static_cast<std::uint32_t>(bytes[offset]) |
        (static_cast<std::uint32_t>(bytes[offset + 1]) << 8U) |
        (static_cast<std::uint32_t>(bytes[offset + 2]) << 16U) |
        (static_cast<std::uint32_t>(bytes[offset + 3]) << 24U);
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& bytes,
                       std::size_t offset) {
    require(offset <= bytes.size() && bytes.size() - offset >= 8,
            "managed fixture u64 read exceeds its domain");
    std::uint64_t value = 0;
    for (unsigned shift = 0; shift < 64; shift += 8)
        value |= static_cast<std::uint64_t>(bytes[offset + shift / 8U]) << shift;
    return value;
}

void write_u32(std::vector<std::uint8_t>& bytes, std::size_t offset,
               std::uint32_t value) {
    require(offset <= bytes.size() && bytes.size() - offset >= 4,
            "managed fixture u32 write exceeds its domain");
    for (unsigned shift = 0; shift < 32; shift += 8)
        bytes[offset + shift / 8U] =
            static_cast<std::uint8_t>(value >> shift);
}

void write_u64(std::vector<std::uint8_t>& bytes, std::size_t offset,
               std::uint64_t value) {
    require(offset <= bytes.size() && bytes.size() - offset >= 8,
            "managed fixture u64 write exceeds its domain");
    for (unsigned shift = 0; shift < 64; shift += 8)
        bytes[offset + shift / 8U] =
            static_cast<std::uint8_t>(value >> shift);
}

void reseal(std::vector<std::uint8_t>& bytes) {
    require(bytes.size() >= 4, "managed fixture domain is truncated");
    write_u32(bytes, bytes.size() - 4,
              crc32c(bytes.data(), bytes.size() - 4));
}

std::shared_ptr<const workspace_identity_t> make_identity(
    const std::filesystem::path& path,
    const std::vector<std::uint8_t>& bytes,
    format_id_t format,
    architecture_id_t architecture,
    architecture_mode_t mode,
    abi_id_t abi,
    endian_t endian) {
    auto content = sha256_bytes(bytes.data(), bytes.size());
    auto load = sha256_text(path.u8string() + ":managed-persistence");
    require(content && load, "managed fixture identity hashing failed");
    workspace_identity_input_t input;
    input.bin_name = path.filename().u8string();
    input.source_path = path.u8string();
    input.content_hash = content.value();
    input.load_profile_hash = load.value();
    input.format = format;
    input.architecture = architecture;
    input.architecture_mode = mode;
    input.abi = abi;
    input.endian = endian;
    auto identity = make_workspace_identity(std::move(input));
    require(static_cast<bool>(identity),
            "managed fixture workspace identity was rejected");
    return identity.take_value();
}

decompiler_entity_key_t entity_for(
    managed_artifact_kind_t kind,
    const workspace_identity_t& identity,
    const sha256_digest_t& artifact_hash,
    std::uint32_t ordinal) {
    decompiler_entity_key_t entity;
    entity.format = identity.format();
    entity.architecture = identity.architecture();
    entity.mode = identity.architecture_mode();
    entity.endian = identity.endian();
    switch (kind) {
    case managed_artifact_kind_t::cli_metadata: {
        cli_decompiler_entity_identity_t value;
        value.module_hash = artifact_hash;
        value.assembly_identity = "ManagedFixture, Version=1.0.0.0";
        value.module_name = "ManagedFixture.dll";
        value.metadata_token = 0x06000001U + ordinal;
        value.declaring_type = "ManagedFixture.Program";
        value.method_name = "Method" + std::to_string(ordinal);
        value.method_signature = "int32()";
        entity.kind = decompiler_entity_kind_t::cli_method;
        entity.identity = std::move(value);
        break;
    }
    case managed_artifact_kind_t::java_classfile: {
        jvm_decompiler_entity_identity_t value;
        value.class_artifact_hash = artifact_hash;
        value.class_internal_name = "fixture/Program" +
            std::to_string(ordinal);
        value.method_name = "run";
        value.method_descriptor = "()I";
        value.method_index = 0;
        value.code_offset = 0;
        entity.kind = decompiler_entity_kind_t::jvm_method;
        entity.identity = std::move(value);
        break;
    }
    case managed_artifact_kind_t::dex:
    case managed_artifact_kind_t::oat:
    case managed_artifact_kind_t::vdex:
    case managed_artifact_kind_t::multidex_container: {
        dalvik_decompiler_entity_identity_t value;
        value.dex_hash = artifact_hash;
        value.dex_ordinal = ordinal;
        value.class_descriptor = "Lfixture/Program" +
            std::to_string(ordinal) + ";";
        value.method_name = "run";
        value.prototype = "()I";
        value.method_id = 0;
        value.code_item_offset = 0;
        entity.kind = decompiler_entity_kind_t::dalvik_method;
        entity.identity = std::move(value);
        break;
    }
    }
    require(validate_decompiler_entity_key(entity).valid(),
            "managed fixture entity is invalid");
    return entity;
}

std::shared_ptr<const managed_artifact_publication_t> make_publication(
    const workspace_identity_t& identity,
    const byte_provider_t& provider,
    managed_artifact_kind_t kind,
    std::uint64_t generation,
    std::uint64_t analysis_revision,
    std::uint64_t overlay_revision,
    std::uint32_t artifact_count) {
    require(artifact_count != 0 && provider.size() >= artifact_count,
            "managed fixture artifact partition is invalid");
    auto provider_hash = sha256_provider(provider);
    require(static_cast<bool>(provider_hash),
            "managed fixture provider hashing failed");
    auto publication = std::make_shared<managed_artifact_publication_t>();
    publication->binary_id = identity.binary_id();
    publication->load_profile_hash = identity.load_profile_hash();
    publication->provider_hash = provider_hash.value();
    publication->provider_source = provider.identity().normalized_source;
    publication->provider_size = provider.size();
    publication->generation = generation;
    publication->analysis_revision = analysis_revision;
    publication->overlay_revision = overlay_revision;
    auto records = std::make_shared<managed_artifact_record_index_t>();
    const auto base_size = provider.size() / artifact_count;
    std::uint64_t offset = 0;
    for (std::uint32_t ordinal = 0; ordinal < artifact_count; ++ordinal) {
        const auto size = ordinal + 1U == artifact_count
            ? provider.size() - offset : base_size;
        auto bytes = provider.lease(offset, size);
        require(static_cast<bool>(bytes),
                "managed fixture artifact lease failed");
        auto artifact_hash = sha256_bytes(
            bytes.value().data(), bytes.value().size());
        require(static_cast<bool>(artifact_hash),
                "managed fixture artifact hashing failed");
        managed_artifact_binding_record_t artifact;
        artifact.kind = kind;
        artifact.artifact_hash = artifact_hash.value();
        artifact.provider_offset = offset;
        artifact.provider_size = size;
        artifact.artifact_ordinal = ordinal;
        artifact.assembly_identity = "ManagedFixture, Version=1.0.0.0";
        artifact.module_name = "managed-" + std::to_string(ordinal);
        artifact.version = "1.0.0";
        artifact.first_method = ordinal;
        artifact.method_count = 1;
        records->artifacts.push_back(artifact);
        managed_method_binding_record_t method;
        method.artifact_index = ordinal;
        method.entity_token = 0x06000001U + ordinal;
        method.method_index = 0;
        method.provider_code_offset = offset;
        method.code_size = 1;
        method.entity = entity_for(
            kind, identity, artifact_hash.value(), ordinal);
        method.has_body = true;
        records->methods.push_back(std::move(method));
        offset += size;
    }
    publication->records = std::static_pointer_cast<
        const managed_artifact_record_index_t>(records);
    require(publication->coherent_with(
                identity, provider, generation, analysis_revision,
                overlay_revision),
            "managed fixture publication is incoherent");
    return std::static_pointer_cast<const managed_artifact_publication_t>(
        publication);
}

void verify_codec_corpus(const std::filesystem::path& root) {
    struct corpus_row_t final {
        const char* name;
        format_id_t format;
        architecture_id_t architecture;
        architecture_mode_t mode;
        abi_id_t abi;
        endian_t endian;
        managed_artifact_kind_t kind;
    };
    const std::array<corpus_row_t, 3> corpus{{
        {"cli.bin", format_id_t::pe32_plus, architecture_id_t::x86_64,
         architecture_mode_t::x86_64, abi_id_t::windows_x64,
         endian_t::little, managed_artifact_kind_t::cli_metadata},
        {"jvm.class", format_id_t::classfile,
         architecture_id_t::jvm_bytecode, architecture_mode_t::jvm,
         abi_id_t::jvm, endian_t::big,
         managed_artifact_kind_t::java_classfile},
        {"dalvik.dex", format_id_t::dex,
         architecture_id_t::dalvik_bytecode, architecture_mode_t::dalvik,
         abi_id_t::dalvik, endian_t::little,
         managed_artifact_kind_t::dex}
    }};
    std::vector<std::uint8_t> retained_domain;
    std::shared_ptr<const workspace_identity_t> retained_identity;
    std::shared_ptr<memory_provider_t> retained_provider;
    for (std::size_t row_index = 0; row_index < corpus.size(); ++row_index) {
        std::vector<std::uint8_t> bytes(512);
        for (std::size_t index = 0; index < bytes.size(); ++index)
            bytes[index] = static_cast<std::uint8_t>(
                index * 17U + row_index * 31U + 1U);
        const auto path = write_bytes_fixture(root / corpus[row_index].name,
                                              bytes);
        auto identity = make_identity(
            path, bytes, corpus[row_index].format,
            corpus[row_index].architecture, corpus[row_index].mode,
            corpus[row_index].abi, corpus[row_index].endian);
        auto normalized = normalize_utf8_path(path.u8string(), true);
        require(static_cast<bool>(normalized),
                "managed fixture provider path normalization failed");
        auto provider = std::make_shared<memory_provider_t>(
            bytes, normalized.value());
        auto publication = make_publication(
            *identity, *provider, corpus[row_index].kind, 7, 3, 2, 2);
        auto encoded = encode_managed_publication_domain(*publication);
        auto repeated = encode_managed_publication_domain(*publication);
        require(encoded && repeated && encoded.value() == repeated.value(),
                "managed publication encoding is nondeterministic");
        auto decoded = decode_managed_publication_domain(
            encoded.value(), *identity, *provider, 7, 3, 2);
        require(decoded && decoded.value()->artifacts().size() == 2 &&
                    decoded.value()->methods().size() == 2,
                "managed publication corpus round-trip failed");
        if (row_index == 0) {
            retained_domain = encoded.value();
            retained_identity = identity;
            retained_provider = provider;
            require(std::search(
                        retained_domain.begin(), retained_domain.end(),
                        bytes.begin(), bytes.end()) == retained_domain.end(),
                    "managed publication persisted a source-file mirror");
        } else {
            auto cross_workspace = decode_managed_publication_domain(
                retained_domain, *identity, *provider, 7, 3, 2);
            require(!cross_workspace,
                    "managed publication crossed workspace identity boundaries");
        }
    }
    require(retained_identity && retained_provider && !retained_domain.empty(),
            "managed corruption corpus was not retained");
    const auto require_rejected = [&](std::vector<std::uint8_t> payload,
                                      const std::string& label,
                                      bool seal) {
        if (seal)
            reseal(payload);
        auto decoded = decode_managed_publication_domain(
            payload, *retained_identity, *retained_provider, 7, 3, 2);
        require(!decoded, label + " was accepted");
    };
    auto corrupted = retained_domain;
    corrupted.back() ^= 0x80U;
    require_rejected(std::move(corrupted), "managed checksum corruption", false);
    corrupted = retained_domain;
    corrupted.pop_back();
    require_rejected(std::move(corrupted), "managed truncation", false);
    corrupted = retained_domain;
    corrupted[12] = 0xFFU;
    corrupted[13] = 0x7FU;
    require_rejected(std::move(corrupted), "managed unknown version", true);
    corrupted = retained_domain;
    write_u32(corrupted, 224, 0);
    require_rejected(std::move(corrupted), "managed bad string count", true);
    corrupted = retained_domain;
    write_u64(corrupted, 208, 4);
    require_rejected(std::move(corrupted), "managed stale analysis revision", true);
    corrupted = retained_domain;
    corrupted[160] ^= 0x01U;
    require_rejected(std::move(corrupted), "managed stale provider hash", true);
    corrupted = retained_domain;
    const auto string_count = read_u32(corrupted, 224);
    std::size_t cursor = 228;
    for (std::uint32_t index = 0; index < string_count; ++index) {
        const auto length = read_u64(corrupted, cursor);
        require(length <= corrupted.size() - cursor - 8,
                "managed fixture string table is malformed");
        cursor += 8 + static_cast<std::size_t>(length);
    }
    write_u32(corrupted, cursor, 0xFFFFFFFFU);
    require_rejected(std::move(corrupted), "managed bad string reference", true);
    corrupted = retained_domain;
    cursor = 228;
    for (std::uint32_t index = 0; index < string_count; ++index) {
        const auto length = read_u64(corrupted, cursor);
        require(length <= corrupted.size() - cursor - 8,
                "managed fixture string table is malformed");
        cursor += 8 + static_cast<std::size_t>(length);
    }
    cursor += 4;
    const auto artifact_count = read_u32(corrupted, cursor);
    cursor += 8;
    cursor += artifact_count;
    cursor += static_cast<std::size_t>(artifact_count) * 32U;
    write_u64(corrupted, cursor,
              (std::numeric_limits<std::uint64_t>::max)());
    require_rejected(std::move(corrupted), "managed bad artifact range", true);
    auto quota = decode_managed_publication_domain(
        retained_domain, *retained_identity, *retained_provider, 7, 3, 2,
        retained_domain.size() - 1U);
    require(!quota, "managed reopen quota was not enforced");
    cancellation_source_t cancelled;
    cancelled.request_cancel();
    auto stopped = decode_managed_publication_domain(
        retained_domain, *retained_identity, *retained_provider, 7, 3, 2,
        managed_publication_max_payload_bytes, cancelled.token());
    require(!stopped && stopped.error().cancellation,
            "managed reopen cancellation was not enforced");
    cancellation_source_t expired(
        std::chrono::steady_clock::now() - std::chrono::milliseconds(1));
    auto deadline = decode_managed_publication_domain(
        retained_domain, *retained_identity, *retained_provider, 7, 3, 2,
        managed_publication_max_payload_bytes, expired.token());
    require(!deadline && deadline.error().deadline,
            "managed reopen deadline was not enforced");
}

void verify_database_publication(const std::filesystem::path& root) {
    const auto path = write_bytes_fixture(
        root / "workspace" / "managed.exe",
        test_fixture::minimal_pe64(0x5A));
    auto workspace = open_workspace(path, "managed.exe");
    std::shared_ptr<analysis_workspace_t> reopened;
    try {
        install_services(workspace);
        const auto source_snapshot = workspace->snapshot();
        const auto source_publication = workspace->analysis_publication();
        require(source_snapshot && source_publication &&
                    source_publication->provider,
                "managed database fixture lacks a source publication");
        auto snapshot = std::make_shared<analysis_snapshot_t>(*source_snapshot);
        snapshot->analysis_revision = 1;
        snapshot->baseline_complete = false;
        auto managed = make_publication(
            workspace->identity(), *source_publication->provider,
            managed_artifact_kind_t::cli_metadata,
            snapshot->generation, snapshot->analysis_revision,
            snapshot->overlay_revision, 2);

        auto legacy = workspace->database()->persist_snapshot(
            snapshot, "{}", "{}");
        wait_ticket(legacy);
        require_success(legacy.snapshot_candidate->finalize(),
                        "managed.legacy.finalize");
        auto absent = workspace->database()->load_managed_publication(
            source_publication->provider, snapshot->generation,
            snapshot->analysis_revision, snapshot->overlay_revision);
        require(absent && !absent.value(),
                "legacy schema-v9 workspace fabricated managed data");

        auto pending_snapshot =
            std::make_shared<analysis_snapshot_t>(*snapshot);
        pending_snapshot->generation = snapshot->generation + 1ULL;
        auto pending_managed = make_publication(
            workspace->identity(), *source_publication->provider,
            managed_artifact_kind_t::cli_metadata,
            pending_snapshot->generation,
            pending_snapshot->analysis_revision,
            pending_snapshot->overlay_revision, 2);
        auto pending = workspace->database()->persist_snapshot(
            pending_snapshot, pending_managed, "{}", "{}");
        wait_ticket(pending);
        require(workspace->database()->snapshot().candidate_pending &&
                    workspace->database()->snapshot().persisted_generation ==
                        snapshot->generation,
                "unpublished managed candidate replaced the prior generation");
        auto prior = workspace->database()->load_managed_publication(
            source_publication->provider, snapshot->generation,
            snapshot->analysis_revision, snapshot->overlay_revision);
        require(prior && !prior.value(),
                "managed candidate became visible before promotion");
        require_success(pending.snapshot_candidate->discard(),
                        "managed.candidate.discard");

        auto persisted = workspace->database()->persist_snapshot(
            snapshot, managed, "{}", "{}");
        wait_ticket(persisted);
        require(persisted.snapshot_candidate->packed_generation_required(),
                "managed persistence did not require packed promotion");
        require_success(persisted.snapshot_candidate->finalize(),
                        "managed.finalize");
        auto loaded_snapshot = workspace->database()->load_snapshot(
            workspace->normalized_image(), workspace->image());
        require(loaded_snapshot && loaded_snapshot.value() &&
                    !loaded_snapshot.value()->baseline_complete,
                "managed partial snapshot did not reopen");
        auto loaded_managed = workspace->database()->load_managed_publication(
            source_publication->provider, snapshot->generation,
            snapshot->analysis_revision, snapshot->overlay_revision);
        require(loaded_managed && loaded_managed.value() &&
                    loaded_managed.value()->methods().size() == 2,
                "managed publication did not reopen from schema v9");

        auto admitted = workspace->publish_managed_artifacts(
            workspace->generation(), workspace->analysis_revision(),
            loaded_managed.value(), true);
        require_success(admitted, "managed.workspace.publish");
        overlay_transaction_request_t request;
        request.expected_revision = workspace->overlay_revision();
        request.idempotency_key = "managed-publication-overlay";
        overlay_operation_t operation;
        operation.kind = overlay_operation_kind_t::comment;
        operation.address.space = address_space_id_t::relative_virtual;
        operation.address.value = 0x1000;
        operation.address.architecture = workspace->identity().architecture();
        operation.address.mode = workspace->identity().architecture_mode();
        operation.text = "managed persistence overlay";
        request.operations.push_back(std::move(operation));
        auto committed = workspace->overlay()->transact(request);
        require(committed && committed.value().committed &&
                    workspace->analysis_publication()->managed_artifacts,
                "overlay commit dropped the managed publication");
        auto undone = workspace->overlay()->undo(workspace->overlay_revision());
        require(undone && undone.value().committed &&
                    workspace->analysis_publication()->managed_artifacts,
                "overlay undo dropped the managed publication");
        auto redone = workspace->overlay()->redo(workspace->overlay_revision());
        require(redone && redone.value().committed &&
                    workspace->analysis_publication()->managed_artifacts,
                "overlay redo dropped the managed publication");
        const auto final_generation = workspace->generation();
        const auto final_analysis_revision = workspace->analysis_revision();
        const auto final_overlay_revision = workspace->overlay_revision();
        close_workspace(workspace);
        workspace.reset();

        reopened = open_workspace(path, "managed.exe");
        install_services(reopened);
        auto warm_snapshot = reopened->database()->load_snapshot(
            reopened->normalized_image(), reopened->image());
        require(warm_snapshot && warm_snapshot.value() &&
                    warm_snapshot.value()->generation == final_generation &&
                    warm_snapshot.value()->analysis_revision ==
                        final_analysis_revision &&
                    warm_snapshot.value()->overlay_revision ==
                        final_overlay_revision,
                "managed overlay generation did not survive reopen");
        const auto warm_publication = reopened->analysis_publication();
        require(warm_publication && warm_publication->provider,
                "reopened managed workspace lacks its provider");
        auto warm_managed = reopened->database()->load_managed_publication(
            warm_publication->provider, final_generation,
            final_analysis_revision, final_overlay_revision);
        require(warm_managed && warm_managed.value() &&
                    warm_managed.value()->overlay_revision ==
                        final_overlay_revision,
                "managed overlay publication did not survive reopen");
        close_workspace(reopened, true);
        reopened.reset();
    } catch (...) {
        if (reopened)
            close_workspace(reopened, true);
        else if (workspace)
            close_workspace(workspace, true);
        throw;
    }
}

}

schema_v9_fixture_result_t run_managed_publication_persistence() {
    schema_v9_fixture_result_t result;
    result.name = "managed_publication_persistence";
    const auto started = std::chrono::steady_clock::now();
    try {
        fixture_root_t root("managed_publication_persistence");
        verify_codec_corpus(root.path() / "codec");
        verify_database_publication(root.path());
        result.passed = true;
        result.message = "managed publication schema-v9 persistence passed";
    } catch (const std::exception& error) {
        result.message = error.what();
    }
    result.elapsed_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count());
    c03_test::assertion_telemetry::record_assertion(
        result.passed, result.message, __FILE__, __LINE__);
    return result;
}

}
