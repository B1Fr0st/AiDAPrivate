#include "managed_overlay_identity_harness.hpp"

#include "../../../src/core/analysis/decompiler/managed_entity_binding.hpp"
#include "../../../src/core/analysis/incremental_reanalysis.hpp"
#include "../../../src/core/analysis/overlay_apply_engine.hpp"
#include "../../../src/core/analysis/overlay_projection.hpp"
#include "../../../src/core/analysis/workspace/overlay_journal.hpp"
#include "../../../src/core/analysis/workspace/workspace_schema_v9.hpp"
#include "../../analysis_workspace/workspace_fixture_builder.hpp"
#include "../assertion_telemetry/assertion_telemetry.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace aida::analysis::c03_test {

namespace {

using readers::managed::managed_artifact_kind_t;
using namespace test_fixture;

void require(bool condition, const std::string& message)
{
    assertion_telemetry::record_assertion(
        condition, message, __FILE__, __LINE__);
    if (!condition)
        throw fixture_error_t(message);
}

sha256_digest_t digest(const std::string& value)
{
    return stable_serialization_hash(value);
}

decompiler_entity_key_t cli_entity()
{
    cli_decompiler_entity_identity_t identity;
    identity.module_hash = digest("managed-overlay-cli-artifact");
    identity.assembly_identity = "ManagedOverlay, Version=1.0.0.0";
    identity.module_name = "ManagedOverlay.dll";
    identity.metadata_token = 0x06000001U;
    identity.declaring_type = "ManagedOverlay.Program";
    identity.method_name = "Run";
    identity.method_signature = "int32()";
    decompiler_entity_key_t entity;
    entity.kind = decompiler_entity_kind_t::cli_method;
    entity.format = format_id_t::pe32_plus;
    entity.architecture = architecture_id_t::x86_64;
    entity.mode = architecture_mode_t::x86_64;
    entity.identity = std::move(identity);
    require(validate_decompiler_entity_key(entity).valid(),
            "CLI managed overlay entity is invalid");
    return entity;
}

decompiler_entity_key_t jvm_entity()
{
    jvm_decompiler_entity_identity_t identity;
    identity.class_artifact_hash = digest("managed-overlay-jvm-artifact");
    identity.class_internal_name = "managed/overlay/Program";
    identity.method_name = "run";
    identity.method_descriptor = "()I";
    identity.method_index = 3;
    identity.code_offset = 64;
    decompiler_entity_key_t entity;
    entity.kind = decompiler_entity_kind_t::jvm_method;
    entity.format = format_id_t::classfile;
    entity.architecture = architecture_id_t::jvm_bytecode;
    entity.mode = architecture_mode_t::jvm;
    entity.endian = endian_t::big;
    entity.identity = std::move(identity);
    require(validate_decompiler_entity_key(entity).valid(),
            "JVM managed overlay entity is invalid");
    return entity;
}

decompiler_entity_key_t dalvik_entity()
{
    dalvik_decompiler_entity_identity_t identity;
    identity.dex_hash = digest("managed-overlay-dalvik-artifact");
    identity.dex_ordinal = 2;
    identity.class_descriptor = "Lmanaged/overlay/Program;";
    identity.method_name = "run";
    identity.prototype = "()I";
    identity.method_id = 7;
    identity.code_item_offset = 128;
    decompiler_entity_key_t entity;
    entity.kind = decompiler_entity_kind_t::dalvik_method;
    entity.format = format_id_t::dex;
    entity.architecture = architecture_id_t::dalvik_bytecode;
    entity.mode = architecture_mode_t::dalvik;
    entity.identity = std::move(identity);
    require(validate_decompiler_entity_key(entity).valid(),
            "Dalvik managed overlay entity is invalid");
    return entity;
}

std::array<std::uint8_t, 32> artifact_hash_for(
    const decompiler_entity_key_t& entity)
{
    if (const auto* cli = std::get_if<cli_decompiler_entity_identity_t>(
            &entity.identity))
        return cli->module_hash.bytes;
    if (const auto* jvm = std::get_if<jvm_decompiler_entity_identity_t>(
            &entity.identity))
        return jvm->class_artifact_hash.bytes;
    if (const auto* dalvik = std::get_if<dalvik_decompiler_entity_identity_t>(
            &entity.identity))
        return dalvik->dex_hash.bytes;
    throw fixture_error_t("managed overlay entity has no artifact identity");
}

overlay_target_identity_v9_t target(std::uint64_t generation = 7)
{
    overlay_target_identity_v9_t value;
    value.image_hash.fill(0x31);
    value.provenance_hash.fill(0x62);
    value.image_base = 0x140000000ULL;
    value.image_size = 0x4000;
    value.generation = generation;
    value.kind = overlay_target_kind_v9_t::static_image;
    value.architecture = overlay_architecture_v9_t::x86_64;
    value.address_width = 8;
    return value;
}

overlay_managed_entity_locator_v9_t locator_for(
    const decompiler_entity_key_t& entity, std::uint64_t generation = 7,
    std::uint8_t workspace_discriminator = 0x91)
{
    overlay_managed_entity_locator_v9_t locator;
    locator.workspace_id.fill(workspace_discriminator);
    locator.provider_hash = target(generation).image_hash;
    locator.artifact_hash = artifact_hash_for(entity);
    locator.provider_size = 0x3000;
    locator.generation = generation;
    locator.serialized_entity = serialize_decompiler_entity_key(entity);
    locator.entity_hash = stable_serialization_hash(
        locator.serialized_entity).bytes;
    require(locator.valid(), "managed overlay locator is invalid");
    return locator;
}

overlay_operation_v9_t managed_operation(
    overlay_operation_kind_v9_t kind,
    const overlay_managed_entity_locator_v9_t& locator)
{
    overlay_operation_v9_t operation;
    operation.kind = kind;
    operation.target_discriminator =
        overlay_target_discriminator_v9_t::managed_entity;
    operation.managed_locator = locator;
    switch (kind) {
    case overlay_operation_kind_v9_t::comment:
        operation.payload.text = "managed comment";
        break;
    case overlay_operation_kind_v9_t::comment_update:
        operation.payload.text = "managed comment update";
        break;
    case overlay_operation_kind_v9_t::name:
        operation.payload.name = "managed_name";
        break;
    case overlay_operation_kind_v9_t::type_application:
        operation.payload.variable = "managed_local";
        operation.payload.type = "System.Int32";
        break;
    case overlay_operation_kind_v9_t::type_update:
        operation.payload.variable = "managed_local";
        operation.payload.type = "System.Int64";
        break;
    default:
        operation.payload.text = "rejected";
        break;
    }
    return operation;
}

bool record_rejected(const overlay_target_identity_v9_t& identity,
                     const overlay_operation_v9_t& operation)
{
    try {
        static_cast<void>(serialize_overlay_operation_record_v9(
            {identity, operation}));
        return false;
    } catch (...) {
        return true;
    }
}

void verify_locator_and_serialization_contract()
{
    const std::array<decompiler_entity_key_t, 3> entities{
        cli_entity(), jvm_entity(), dalvik_entity()};
    for (const auto& entity : entities) {
        const auto locator = locator_for(entity);
        auto operation = managed_operation(
            overlay_operation_kind_v9_t::comment, locator);
        const auto serialized = serialize_overlay_operation_record_v9(
            {target(), operation});
        const auto decoded = deserialize_overlay_operation_record_v9(
            serialized);
        require(decoded && decoded->operation == operation,
                "managed operation record did not round-trip");
        require(serialized.find("\"managed_locator\"") != std::string::npos &&
                    serialized.find("\"target_discriminator\":1") !=
                        std::string::npos &&
                    serialized.find("\"range\"") == std::string::npos &&
                    serialized.find("\"address\"") == std::string::npos,
                "managed operation serialization contains a fake address range");
    }

    const auto base = locator_for(cli_entity());
    auto next_generation = base;
    next_generation.generation += 1;
    require(base != next_generation &&
                base.stable_identity_equal(next_generation) &&
                !base.stable_identity_less(next_generation) &&
                !next_generation.stable_identity_less(base),
            "managed stable identity did not isolate generation provenance");
    auto other_workspace = base;
    other_workspace.workspace_id[0] ^= 0x01U;
    require(other_workspace.valid() &&
                !base.stable_identity_equal(other_workspace),
            "managed stable identity crossed workspace boundaries");
    auto other_provider = base;
    other_provider.provider_hash[0] ^= 0x01U;
    require(other_provider.valid() &&
                !base.stable_identity_equal(other_provider),
            "managed stable identity crossed provider boundaries");
    auto corrupt_artifact = base;
    corrupt_artifact.artifact_hash[0] ^= 0x01U;
    require(!corrupt_artifact.valid(),
            "managed locator accepted an artifact mismatch");
    auto corrupt_entity = base;
    corrupt_entity.serialized_entity[0] ^= 0x01;
    require(!corrupt_entity.valid(),
            "managed locator accepted noncanonical entity serialization");
    auto corrupt_hash = base;
    corrupt_hash.entity_hash[0] ^= 0x01U;
    require(!corrupt_hash.valid(),
            "managed locator accepted an entity hash mismatch");
    auto oversized = base;
    oversized.serialized_entity.assign(
        k_overlay_managed_entity_serialization_limit + 1U, 'x');
    oversized.entity_hash = stable_serialization_hash(
        oversized.serialized_entity).bytes;
    require(!oversized.valid(),
            "managed locator accepted an oversized entity key");

    overlay_operation_v9_t native;
    native.kind = overlay_operation_kind_v9_t::comment;
    native.range = {0x120, 1};
    native.payload.text = "fixture comment";
    const std::string expected =
        "{\"operation\":{\"kind\":0,\"payload\":{\"assembly\":\"\",\"bytes\":\"\","
        "\"integer_type\":\"\",\"integer_value\":\"\",\"name\":\"\",\"reanalysis_flags\":0,"
        "\"signature\":\"\",\"stack_offset\":\"0\",\"text\":\"fixture comment\",\"type\":\"\","
        "\"variable\":\"\"},\"range\":{\"offset\":\"288\",\"size\":\"1\"},\"remove\":false},"
        "\"schema\":9,\"target\":{\"address_width\":8,\"architecture\":2,\"generation\":\"7\","
        "\"image_base\":\"5368709120\",\"image_hash\":\"3131313131313131313131313131313131313131313131313131313131313131\","
        "\"image_size\":\"16384\",\"kind\":1,\"provenance_hash\":\"6262626262626262626262626262626262626262626262626262626262626262\","
        "\"reserved\":0,\"schema\":9}}";
    require(serialize_overlay_operation_record_v9({target(), native}) ==
                expected,
            "native schema-v9 serialization changed");
}

void verify_allowlist_history_projection_and_reanalysis()
{
    const auto locator = locator_for(cli_entity());
    const std::array<overlay_operation_kind_v9_t, 5> allowed{{
        overlay_operation_kind_v9_t::comment,
        overlay_operation_kind_v9_t::comment_update,
        overlay_operation_kind_v9_t::name,
        overlay_operation_kind_v9_t::type_application,
        overlay_operation_kind_v9_t::type_update}};
    for (std::uint8_t ordinal = 0; ordinal <= 17; ++ordinal) {
        const auto kind = static_cast<overlay_operation_kind_v9_t>(ordinal);
        const bool expected = std::find(allowed.begin(), allowed.end(), kind) !=
            allowed.end();
        require(managed_overlay_operation_kind_v9(kind) == expected,
                "managed operation allowlist drifted");
        auto operation = managed_operation(kind, locator);
        require(record_rejected(target(), operation) != expected,
                "managed operation allowlist serialization result drifted");
        overlay_static_state_v9_t state;
        require(overlay_apply_engine_v9_t::initialize(state, target()).ok(),
                "managed allowlist state initialization failed");
        overlay_transaction_v9_t transaction;
        transaction.target = target();
        transaction.operations.push_back(std::move(operation));
        require(overlay_apply_engine_v9_t::apply(state, transaction).ok() ==
                    expected,
                "managed operation allowlist apply result drifted");
    }

    auto stale = managed_operation(
        overlay_operation_kind_v9_t::comment, locator);
    stale.managed_locator->generation -= 1;
    require(record_rejected(target(), stale),
            "stale managed generation was accepted");
    auto wrong_provider = managed_operation(
        overlay_operation_kind_v9_t::comment, locator);
    wrong_provider.managed_locator->provider_hash[0] ^= 1U;
    require(record_rejected(target(), wrong_provider),
            "cross-provider managed operation was accepted");
    auto ranged = managed_operation(
        overlay_operation_kind_v9_t::comment, locator);
    ranged.range = {0x100, 1};
    require(record_rejected(target(), ranged),
            "managed operation accepted an address range");
    auto patched = managed_operation(
        overlay_operation_kind_v9_t::comment, locator);
    patched.payload.bytes = {0x90};
    require(record_rejected(target(), patched),
            "managed semantic operation accepted patch bytes");
    auto signed_payload = managed_operation(
        overlay_operation_kind_v9_t::name, locator);
    signed_payload.payload.signature = "void()";
    require(record_rejected(target(), signed_payload),
            "managed semantic operation accepted an unrelated signature");
    auto ambiguous_type = managed_operation(
        overlay_operation_kind_v9_t::type_application, locator);
    ambiguous_type.payload.name = "managed_local";
    require(record_rejected(target(), ambiguous_type),
            "managed type operation accepted ambiguous qualifiers");

    for (const bool entity_budget : {true, false}) {
        overlay_static_state_v9_t limited_state;
        require(overlay_apply_engine_v9_t::initialize(
                    limited_state, target()).ok(),
                "managed quota state initialization failed");
        overlay_transaction_v9_t limited_transaction;
        limited_transaction.target = target();
        limited_transaction.operations = {managed_operation(
            overlay_operation_kind_v9_t::comment, locator)};
        overlay_apply_limits_v9_t limits;
        if (entity_budget) {
            limits.max_managed_entity_bytes =
                locator.serialized_entity.size() - 1U;
        } else {
            limits.max_transaction_payload_bytes =
                locator.serialized_entity.size() - 1U;
        }
        require(overlay_apply_engine_v9_t::apply(
                    limited_state, limited_transaction, limits).code ==
                    overlay_apply_code_v9_t::limit_exceeded,
                "managed overlay quota did not fail with a bounded diagnostic");
    }

    overlay_static_state_v9_t state;
    require(overlay_apply_engine_v9_t::initialize(state, target()).ok(),
            "managed update state initialization failed");
    overlay_transaction_v9_t first;
    first.target = target();
    first.operations = {managed_operation(
        overlay_operation_kind_v9_t::comment, locator)};
    const auto inserted = overlay_apply_engine_v9_t::apply(state, first);
    require(inserted.ok() && inserted.changes.size() == 1 &&
                state.items.size() == 1,
            "managed comment insertion failed");
    overlay_transaction_v9_t stale_revision;
    stale_revision.target = target();
    stale_revision.operations = {managed_operation(
        overlay_operation_kind_v9_t::comment_update, locator)};
    require(overlay_apply_engine_v9_t::apply(state, stale_revision).code ==
                overlay_apply_code_v9_t::revision_conflict,
            "managed overlay accepted a stale expected revision");
    overlay_transaction_v9_t update;
    update.target = target();
    update.expected_revision = state.revision;
    update.operations = {managed_operation(
        overlay_operation_kind_v9_t::comment_update, locator)};
    const auto updated = overlay_apply_engine_v9_t::apply(state, update);
    require(updated.ok() && updated.changes.size() == 1 &&
                updated.changes.front().before &&
                updated.changes.front().after && state.items.size() == 1,
            "managed comment update did not preserve one semantic entity");
    const auto invalidation = overlay_projection_t::compute_invalidation(
        updated.changes, state.target.image_size);
    require(invalidation.affected_ranges.empty() &&
                invalidation.affected_entities.size() == 1 &&
                invalidation.total_patched_bytes == 0 &&
                invalidation.decompiler_cache.required() &&
                !invalidation.decompiler_cache.invalidate_workspace &&
                invalidation.packed_index.affected_ranges.empty(),
            "managed comment produced address-wide invalidation");
    const auto scope = incremental_reanalysis_t::compute_scope(
        updated.changes, state, state.target.generation);
    require(scope && scope.scope.ranges.empty() &&
                scope.scope.entities.size() == 1 &&
                !scope.scope.requires_full_reanalysis,
            "managed comment produced address-range reanalysis");
    for (const auto kind : {overlay_operation_kind_v9_t::name,
                            overlay_operation_kind_v9_t::type_application}) {
        overlay_static_state_v9_t semantic_state;
        require(overlay_apply_engine_v9_t::initialize(
                    semantic_state, target()).ok(),
                "managed semantic state initialization failed");
        overlay_transaction_v9_t semantic_transaction;
        semantic_transaction.target = target();
        semantic_transaction.operations = {managed_operation(kind, locator)};
        const auto semantic = overlay_apply_engine_v9_t::apply(
            semantic_state, semantic_transaction);
        require(semantic.ok(), "managed semantic transaction failed");
        const auto semantic_invalidation =
            overlay_projection_t::compute_invalidation(
                semantic.changes, semantic_state.target.image_size);
        require(semantic_invalidation.affected_ranges.empty() &&
                    semantic_invalidation.affected_entities.size() == 1 &&
                    semantic_invalidation.decompiler_cache.required() &&
                    !semantic_invalidation.decompiler_cache.invalidate_workspace &&
                    (kind != overlay_operation_kind_v9_t::name ||
                     stage_test(semantic_invalidation.invalidated_stages,
                                projection_stage_flag_t::symbol_table)) &&
                    (kind != overlay_operation_kind_v9_t::type_application ||
                     stage_test(semantic_invalidation.invalidated_stages,
                                projection_stage_flag_t::type_table)),
                "managed semantic invalidation lost its precise domain");
    }
    const auto undone = overlay_apply_engine_v9_t::undo(
        state, target(), state.revision);
    require(undone.ok() && undone.changes.size() == 1 &&
                incremental_reanalysis_t::validate_undo_redo_identity(
                    updated.changes.front(), undone.changes.front())
                    .identity_preserved(),
            "managed undo lost semantic identity");
    const auto redone = overlay_apply_engine_v9_t::redo(
        state, target(), state.revision);
    require(redone.ok() && state.items.size() == 1,
            "managed redo lost semantic identity");

    auto generation_rebound = locator;
    generation_rebound.generation += 1;
    const auto old_key = overlay_entity_key_for_operation_v9(
        managed_operation(overlay_operation_kind_v9_t::comment, locator));
    const auto rebound_key = overlay_entity_key_for_operation_v9(
        managed_operation(overlay_operation_kind_v9_t::comment,
                          generation_rebound));
    require(old_key == rebound_key,
            "managed update identity changed across publication generations");
    auto isolated = locator;
    isolated.workspace_id[0] ^= 0x01U;
    const auto isolated_key = overlay_entity_key_for_operation_v9(
        managed_operation(overlay_operation_kind_v9_t::comment, isolated));
    require(old_key != isolated_key,
            "managed entity key crossed workspace identity boundaries");
}

class database_t final {
public:
    database_t()
    {
        require(sqlite3_open(":memory:", &value_) == SQLITE_OK && value_,
                "unable to open managed overlay schema database");
        require(sqlite3_extended_result_codes(value_, 1) == SQLITE_OK,
                "unable to enable SQLite extended result codes");
    }

    ~database_t()
    {
        if (value_)
            sqlite3_close(value_);
    }

    sqlite3* get() const noexcept { return value_; }

private:
    sqlite3* value_ = nullptr;
};

void execute(sqlite3* database, const std::string& sql)
{
    char* detail = nullptr;
    const int status = sqlite3_exec(database, sql.c_str(), nullptr, nullptr,
                                    &detail);
    const std::string message = detail ? detail : "SQLite execution failed";
    sqlite3_free(detail);
    require(status == SQLITE_OK, message);
}

bool execute_rejected(sqlite3* database, const std::string& sql)
{
    char* detail = nullptr;
    const int status = sqlite3_exec(database, sql.c_str(), nullptr, nullptr,
                                    &detail);
    sqlite3_free(detail);
    return status != SQLITE_OK;
}

bool column_exists(sqlite3* database, const char* table, const char* column)
{
    sqlite3_stmt* statement = nullptr;
    const std::string sql = std::string("PRAGMA table_info(") + table + ")";
    require(sqlite3_prepare_v2(database, sql.c_str(), -1, &statement,
                               nullptr) == SQLITE_OK,
            "unable to inspect managed overlay schema columns");
    bool found = false;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const auto* name = sqlite3_column_text(statement, 1);
        if (name && std::strcmp(
                reinterpret_cast<const char*>(name), column) == 0) {
            found = true;
            break;
        }
    }
    sqlite3_finalize(statement);
    return found;
}

std::int64_t scalar_int(sqlite3* database, const std::string& sql)
{
    sqlite3_stmt* statement = nullptr;
    require(sqlite3_prepare_v2(database, sql.c_str(), -1, &statement,
                               nullptr) == SQLITE_OK,
            "unable to prepare managed overlay scalar query");
    require(sqlite3_step(statement) == SQLITE_ROW,
            "managed overlay scalar query returned no row");
    const auto value = sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);
    return value;
}

void insert_managed_item(sqlite3* database,
                         const overlay_managed_entity_locator_v9_t& locator)
{
    sqlite3_stmt* statement = nullptr;
    const char* sql =
        "INSERT INTO overlay_items(entity_key,kind,target_discriminator,address_space,address_value,address_arch,address_mode,managed_workspace_id,managed_provider_hash,managed_provider_size,managed_artifact_hash,managed_generation,managed_entity_hash,managed_entity_key,payload_json,updated_revision) VALUES('managed:fixture',0,1,NULL,NULL,NULL,NULL,?1,?2,?3,?4,?5,?6,?7,'{}',2)";
    require(sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) ==
                SQLITE_OK,
            "unable to prepare managed overlay item insertion");
    require(sqlite3_bind_blob(statement, 1, locator.workspace_id.data(), 32,
                              SQLITE_TRANSIENT) == SQLITE_OK &&
                sqlite3_bind_blob(statement, 2, locator.provider_hash.data(),
                                  32, SQLITE_TRANSIENT) == SQLITE_OK &&
                sqlite3_bind_int64(statement, 3,
                                   static_cast<sqlite3_int64>(
                                       locator.provider_size)) == SQLITE_OK &&
                sqlite3_bind_blob(statement, 4, locator.artifact_hash.data(),
                                  32, SQLITE_TRANSIENT) == SQLITE_OK &&
                sqlite3_bind_int64(statement, 5,
                                   static_cast<sqlite3_int64>(
                                       locator.generation)) == SQLITE_OK &&
                sqlite3_bind_blob(statement, 6, locator.entity_hash.data(), 32,
                                  SQLITE_TRANSIENT) == SQLITE_OK &&
                sqlite3_bind_blob(statement, 7,
                                  locator.serialized_entity.data(),
                                  static_cast<int>(
                                      locator.serialized_entity.size()),
                                  SQLITE_TRANSIENT) == SQLITE_OK,
            "unable to bind managed overlay item identity");
    require(sqlite3_step(statement) == SQLITE_DONE,
            "managed overlay item insertion failed");
    sqlite3_finalize(statement);
}

void verify_schema_migration_and_corruption_guards()
{
    database_t database;
    execute(database.get(),
        "PRAGMA foreign_keys=ON;"
        "CREATE TABLE overlay_transactions(transaction_id INTEGER PRIMARY KEY);"
        "INSERT INTO overlay_transactions VALUES(1);"
        "CREATE TABLE overlay_operations(transaction_id INTEGER NOT NULL,operation_index INTEGER NOT NULL,kind INTEGER NOT NULL,entity_key TEXT NOT NULL,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,before_json TEXT,after_json TEXT NOT NULL,PRIMARY KEY(transaction_id,operation_index),FOREIGN KEY(transaction_id) REFERENCES overlay_transactions(transaction_id) ON DELETE CASCADE);"
        "CREATE INDEX overlay_operations_entity ON overlay_operations(entity_key,transaction_id);"
        "CREATE TABLE overlay_items(entity_key TEXT PRIMARY KEY NOT NULL,kind INTEGER NOT NULL,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,payload_json TEXT NOT NULL,updated_revision INTEGER NOT NULL);"
        "CREATE INDEX overlay_items_address ON overlay_items(address_space,address_value,address_arch,address_mode,kind);"
        "INSERT INTO overlay_operations VALUES(1,0,0,'comment:fixture',2,4096,2,2,NULL,'{\"native\":true}');"
        "INSERT INTO overlay_items VALUES('comment:fixture',0,2,4096,2,2,'{\"native\":true}',1);");
    const auto migrated = ensure_managed_overlay_identity_schema_v9(
        database.get());
    require(static_cast<bool>(migrated),
            "managed overlay schema migration failed");
    require(column_exists(database.get(), "overlay_operations",
                          "target_discriminator") &&
                column_exists(database.get(), "overlay_operations",
                              "managed_entity_key") &&
                column_exists(database.get(), "overlay_items",
                              "target_discriminator") &&
                scalar_int(database.get(),
                    "SELECT target_discriminator FROM overlay_operations WHERE transaction_id=1") == 0 &&
                scalar_int(database.get(),
                    "SELECT address_value FROM overlay_items WHERE entity_key='comment:fixture'") == 4096 &&
                scalar_int(database.get(),
                    "SELECT COUNT(*) FROM overlay_operations WHERE managed_workspace_id IS NULL") == 1 &&
                scalar_int(database.get(),
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('overlay_operations_native_address','overlay_operations_managed_entity','overlay_items_address','overlay_items_managed_entity')") == 4,
            "native overlay rows changed during managed schema migration");

    const auto locator = locator_for(cli_entity());
    insert_managed_item(database.get(), locator);
    require(scalar_int(database.get(),
                "SELECT COUNT(*) FROM overlay_items WHERE target_discriminator=1 AND address_space IS NULL AND address_value IS NULL AND address_arch IS NULL AND address_mode IS NULL") == 1,
            "managed overlay item persisted a fake address");
    require(execute_rejected(database.get(),
        "INSERT INTO overlay_items(entity_key,kind,target_discriminator,address_space,address_value,address_arch,address_mode,managed_workspace_id,managed_provider_hash,managed_provider_size,managed_artifact_hash,managed_generation,managed_entity_hash,managed_entity_key,payload_json,updated_revision) VALUES('bad-address',0,1,0,0,0,0,zeroblob(32),zeroblob(32),1,zeroblob(32),1,zeroblob(32),x'01','{}',1)"),
            "managed schema accepted fake address columns");
    require(execute_rejected(database.get(),
        "INSERT INTO overlay_items(entity_key,kind,target_discriminator,address_space,address_value,address_arch,address_mode,managed_workspace_id,managed_provider_hash,managed_provider_size,managed_artifact_hash,managed_generation,managed_entity_hash,managed_entity_key,payload_json,updated_revision) VALUES('bad-type',0,1,NULL,NULL,NULL,NULL,'12345678901234567890123456789012',zeroblob(32),1,zeroblob(32),1,zeroblob(32),x'01','{}',1)"),
            "managed schema accepted a text identity blob");
    require(execute_rejected(database.get(),
        "INSERT INTO overlay_items(entity_key,kind,target_discriminator,address_space,address_value,address_arch,address_mode,managed_workspace_id,managed_provider_hash,managed_provider_size,managed_artifact_hash,managed_generation,managed_entity_hash,managed_entity_key,payload_json,updated_revision) VALUES('bad-native',0,0,0,0,0,0,zeroblob(32),NULL,NULL,NULL,NULL,NULL,NULL,'{}',1)"),
            "native schema accepted managed identity columns");
    const auto repeated = ensure_managed_overlay_identity_schema_v9(
        database.get());
    require(static_cast<bool>(repeated) &&
                scalar_int(database.get(),
                    "SELECT COUNT(*) FROM overlay_items") == 2,
            "managed overlay schema migration was not idempotent");

    database_t corrupt;
    execute(corrupt.get(),
        "CREATE TABLE overlay_transactions(transaction_id INTEGER PRIMARY KEY);"
        "INSERT INTO overlay_transactions VALUES(1);"
        "CREATE TABLE overlay_operations(transaction_id INTEGER NOT NULL,operation_index INTEGER NOT NULL,kind INTEGER NOT NULL,entity_key TEXT NOT NULL,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,before_json TEXT,after_json TEXT NOT NULL,PRIMARY KEY(transaction_id,operation_index));"
        "CREATE TABLE overlay_items(entity_key TEXT PRIMARY KEY NOT NULL,kind INTEGER NOT NULL,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,payload_json TEXT NOT NULL,updated_revision INTEGER NOT NULL);"
        "INSERT INTO overlay_operations VALUES(1,0,0,'corrupt','not-an-integer',1,1,1,NULL,'{}');");
    const auto rejected = ensure_managed_overlay_identity_schema_v9(
        corrupt.get());
    require(!rejected &&
                !column_exists(corrupt.get(), "overlay_operations",
                               "target_discriminator") &&
                scalar_int(corrupt.get(),
                    "SELECT COUNT(*) FROM overlay_operations") == 1,
            "failed managed schema migration did not roll back exactly");
}

decompiler_entity_key_t workspace_cli_entity(
    const sha256_digest_t& artifact_hash)
{
    auto entity = cli_entity();
    auto& identity = std::get<cli_decompiler_entity_identity_t>(
        entity.identity);
    identity.module_hash = artifact_hash;
    return entity;
}

std::shared_ptr<const managed_artifact_publication_t>
make_workspace_managed_publication(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    auto provider_hash = sha256_provider(workspace->provider());
    require(static_cast<bool>(provider_hash),
            "unable to hash managed overlay workspace provider");
    auto publication = std::make_shared<managed_artifact_publication_t>();
    publication->binary_id = workspace->identity().binary_id();
    publication->load_profile_hash = workspace->identity().load_profile_hash();
    publication->provider_hash = provider_hash.value();
    publication->provider_source =
        workspace->provider().identity().normalized_source;
    publication->provider_size = workspace->provider().size();
    publication->generation = workspace->generation();
    publication->analysis_revision = workspace->analysis_revision();
    publication->overlay_revision = workspace->overlay_revision();
    auto artifact_hash = sha256_provider(workspace->provider());
    require(static_cast<bool>(artifact_hash),
            "unable to hash managed overlay artifact");
    auto records = std::make_shared<managed_artifact_record_index_t>();
    managed_artifact_binding_record_t artifact;
    artifact.kind = managed_artifact_kind_t::cli_metadata;
    artifact.artifact_hash = artifact_hash.value();
    artifact.provider_size = workspace->provider().size();
    artifact.assembly_identity = "ManagedOverlay, Version=1.0.0.0";
    artifact.module_name = "ManagedOverlay.dll";
    artifact.version = "1.0.0";
    artifact.method_count = 1;
    records->artifacts.push_back(artifact);
    managed_method_binding_record_t method;
    method.entity_token = 0x06000001U;
    method.code_size = 1;
    method.entity = workspace_cli_entity(artifact_hash.value());
    method.has_body = true;
    records->methods.push_back(method);
    publication->records = std::static_pointer_cast<
        const managed_artifact_record_index_t>(records);
    require(publication->coherent_with(
                workspace->identity(), workspace->provider(),
                workspace->generation(), workspace->analysis_revision(),
                workspace->overlay_revision()),
            "managed overlay workspace publication is incoherent");
    return std::static_pointer_cast<const managed_artifact_publication_t>(
        publication);
}

generation_bound_decompiler_entity_t current_binding(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    const auto publication = workspace->analysis_publication();
    require(publication && publication->managed_artifacts &&
                publication->managed_artifacts->methods().size() == 1 &&
                publication->managed_artifacts->artifacts().size() == 1,
            "managed overlay workspace publication is unavailable");
    generation_bound_decompiler_entity_t binding;
    binding.binary_id = publication->binary_id;
    binding.load_profile_hash = publication->load_profile_hash;
    binding.provider_hash = publication->managed_artifacts->provider_hash;
    binding.artifact_hash =
        publication->managed_artifacts->artifacts().front().artifact_hash;
    binding.provider_size = publication->provider->size();
    binding.generation = publication->generation;
    binding.analysis_revision = publication->analysis_revision;
    binding.overlay_revision = publication->overlay_revision;
    binding.type_graph_revision = publication->analysis_revision;
    binding.reader_schema_version =
        publication->managed_artifacts->reader_schema_version;
    binding.artifact_index = 0;
    binding.method_index = 0;
    binding.entity = publication->managed_artifacts->methods().front().entity;
    return binding;
}

overlay_operation_t journal_comment(
    overlay_operation_kind_t kind,
    const overlay_managed_entity_locator_v9_t& locator,
    std::string text)
{
    overlay_operation_t operation;
    operation.kind = kind;
    operation.target_discriminator =
        overlay_target_discriminator_v9_t::managed_entity;
    operation.managed_locator = locator;
    operation.text = std::move(text);
    return operation;
}

void verify_journal_storage_identity(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    sqlite3* reader_handle = nullptr;
    const auto open_status = sqlite3_open_v2(
        workspace->database()->path().c_str(), &reader_handle,
        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_URI, nullptr);
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> reader(
        reader_handle, sqlite3_close);
    require(open_status == SQLITE_OK && static_cast<bool>(reader),
            "unable to open managed overlay journal for inspection");
    require(sqlite3_extended_result_codes(reader.get(), 1) == SQLITE_OK,
            "unable to enable managed overlay journal extended result codes");
    require(sqlite3_busy_timeout(
                reader.get(),
                static_cast<int>((std::min<std::uint32_t>)(
                    workspace->database()->options().busy_timeout_ms, 60000U))) ==
                SQLITE_OK,
            "unable to configure managed overlay journal read timeout");
    execute(reader.get(),
            "PRAGMA foreign_keys=ON;PRAGMA trusted_schema=OFF;PRAGMA query_only=ON;BEGIN");
    const auto checked = [](sqlite3* database) -> workspace_result_t<void> {
            sqlite3_stmt* statement = nullptr;
            const char* operation_sql =
                "SELECT target_discriminator,address_space,address_value,address_arch,address_mode,length(managed_workspace_id),length(managed_provider_hash),managed_provider_size,length(managed_artifact_hash),managed_generation,length(managed_entity_hash),length(managed_entity_key),after_json FROM overlay_operations ORDER BY transaction_id DESC,operation_index DESC LIMIT 1";
            if (sqlite3_prepare_v2(database, operation_sql, -1, &statement,
                                   nullptr) != SQLITE_OK) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(
                        workspace_error_code_t::persistence_failure,
                        "unable to inspect managed overlay operation storage",
                        "managed_overlay_identity_harness"));
            }
            const int status = sqlite3_step(statement);
            const auto* payload = status == SQLITE_ROW
                ? sqlite3_column_text(statement, 12) : nullptr;
            const std::string serialized = payload
                ? reinterpret_cast<const char*>(payload) : std::string{};
            const bool operation_valid = status == SQLITE_ROW &&
                sqlite3_column_int(statement, 0) == 1 &&
                sqlite3_column_type(statement, 1) == SQLITE_NULL &&
                sqlite3_column_type(statement, 2) == SQLITE_NULL &&
                sqlite3_column_type(statement, 3) == SQLITE_NULL &&
                sqlite3_column_type(statement, 4) == SQLITE_NULL &&
                sqlite3_column_int(statement, 5) == 32 &&
                sqlite3_column_int(statement, 6) == 32 &&
                sqlite3_column_int64(statement, 7) > 0 &&
                sqlite3_column_int(statement, 8) == 32 &&
                sqlite3_column_int64(statement, 9) > 0 &&
                sqlite3_column_int(statement, 10) == 32 &&
                sqlite3_column_int(statement, 11) > 0 &&
                serialized.find("\"address\":") == std::string::npos &&
                serialized.find("\"end\":") == std::string::npos &&
                serialized.find("\"range\":") == std::string::npos;
            sqlite3_finalize(statement);
            if (!operation_valid) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "managed overlay operation storage identity is not exact",
                        "managed_overlay_identity_harness"));
            }
            const char* item_sql =
                "SELECT target_discriminator,address_space,address_value,address_arch,address_mode,length(managed_workspace_id),length(managed_provider_hash),managed_provider_size,length(managed_artifact_hash),managed_generation,length(managed_entity_hash),length(managed_entity_key),payload_json FROM overlay_items LIMIT 1";
            statement = nullptr;
            if (sqlite3_prepare_v2(database, item_sql, -1, &statement,
                                   nullptr) != SQLITE_OK) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(
                        workspace_error_code_t::persistence_failure,
                        "unable to inspect managed overlay item storage",
                        "managed_overlay_identity_harness"));
            }
            const int item_status = sqlite3_step(statement);
            payload = item_status == SQLITE_ROW
                ? sqlite3_column_text(statement, 12) : nullptr;
            const std::string item_serialized = payload
                ? reinterpret_cast<const char*>(payload) : std::string{};
            const bool item_valid = item_status == SQLITE_ROW &&
                sqlite3_column_int(statement, 0) == 1 &&
                sqlite3_column_type(statement, 1) == SQLITE_NULL &&
                sqlite3_column_type(statement, 2) == SQLITE_NULL &&
                sqlite3_column_type(statement, 3) == SQLITE_NULL &&
                sqlite3_column_type(statement, 4) == SQLITE_NULL &&
                sqlite3_column_int(statement, 5) == 32 &&
                sqlite3_column_int(statement, 6) == 32 &&
                sqlite3_column_int64(statement, 7) > 0 &&
                sqlite3_column_int(statement, 8) == 32 &&
                sqlite3_column_int64(statement, 9) > 0 &&
                sqlite3_column_int(statement, 10) == 32 &&
                sqlite3_column_int(statement, 11) > 0 &&
                item_serialized.find("\"address\":") ==
                    std::string::npos &&
                item_serialized.find("\"end\":") == std::string::npos &&
                item_serialized.find("\"range\":") == std::string::npos;
            sqlite3_finalize(statement);
            if (!item_valid) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "managed overlay item storage identity is not exact",
                        "managed_overlay_identity_harness"));
            }
            return workspace_result_t<void>::success();
        }(reader.get());
    execute(reader.get(), checked ? "COMMIT" : "ROLLBACK");
    require(static_cast<bool>(checked),
            checked ? std::string{}
                    : checked.error().stable_code() + ":" +
                        checked.error().message);
}

void verify_journal_idempotency_recovery_and_isolation()
{
    fixture_root_t root("managed_overlay_identity");
    const auto first_path = write_bytes_fixture(
        root.path() / "first" / "managed.exe",
        analysis_contract_pe64(0x71));
    const auto second_path = write_bytes_fixture(
        root.path() / "second" / "managed.exe",
        analysis_contract_pe64(0x72));
    std::shared_ptr<analysis_workspace_t> first;
    std::shared_ptr<analysis_workspace_t> second;
    std::shared_ptr<analysis_workspace_t> reopened;
    try {
        first = open_workspace(first_path, "managed-overlay-first.exe");
        second = open_workspace(second_path, "managed-overlay-second.exe");
        install_services(first);
        install_services(second);
        analyze_workspace(first, 1);
        analyze_workspace(second, 1);
        const auto managed = make_workspace_managed_publication(first);
        const auto published = first->publish_managed_artifacts(
            first->generation(), first->analysis_revision(), managed, false);
        require(static_cast<bool>(published),
                "unable to publish managed overlay fixture records");
        const auto binding = current_binding(first);
        const auto locator = bind_managed_overlay_entity_v9(*first, binding);
        require(static_cast<bool>(locator) && locator.value().valid(),
                "managed overlay journal binding failed");

        overlay_transaction_request_t request;
        request.expected_revision = first->overlay_revision();
        request.idempotency_key = "managed-overlay-idempotency";
        request.operations.push_back(journal_comment(
            overlay_operation_kind_t::comment, locator.value(), "first"));
        const auto committed = first->overlay()->transact(request);
        require(committed && committed.value().committed &&
                    first->overlay()->snapshot().items.size() == 1,
                "managed overlay journal transaction failed");
        const auto committed_generation = first->generation();
        const auto committed_revision = first->overlay_revision();
        const auto replayed = first->overlay()->transact(request);
        require(replayed && replayed.value().idempotent_replay &&
                    replayed.value().transaction_id ==
                        committed.value().transaction_id &&
                    first->generation() == committed_generation &&
                    first->overlay_revision() == committed_revision,
                "managed overlay idempotent replay mutated publication state");

        const auto rebound_binding = current_binding(first);
        const auto rebound_locator = bind_managed_overlay_entity_v9(
            *first, rebound_binding);
        require(static_cast<bool>(rebound_locator),
                "managed overlay replay rebind failed");
        auto rebound_request = request;
        rebound_request.operations.front().managed_locator =
            rebound_locator.value();
        const auto rebound_replay = first->overlay()->transact(
            rebound_request);
        require(rebound_replay &&
                    rebound_replay.value().idempotent_replay &&
                    rebound_replay.value().transaction_id ==
                        committed.value().transaction_id &&
                    first->generation() == committed_generation &&
                    first->overlay_revision() == committed_revision,
                "managed overlay generation-normalized replay failed");

        auto stale_without_idempotency = request;
        stale_without_idempotency.idempotency_key.reset();
        stale_without_idempotency.expected_revision =
            first->overlay_revision();
        const auto stale = first->overlay()->transact(
            stale_without_idempotency);
        require(!stale,
                "managed overlay accepted stale generation without replay authority");

        const auto update_binding = current_binding(first);
        const auto update_locator = bind_managed_overlay_entity_v9(
            *first, update_binding);
        require(static_cast<bool>(update_locator),
                "managed overlay update binding failed");
        overlay_transaction_request_t update;
        update.expected_revision = first->overlay_revision();
        update.idempotency_key = "managed-overlay-update";
        update.operations.push_back(journal_comment(
            overlay_operation_kind_t::comment_update,
            update_locator.value(), "second"));
        const auto updated = first->overlay()->transact(update);
        require(updated && updated.value().committed &&
                    first->overlay()->snapshot().items.size() == 1 &&
                    first->overlay()->snapshot().items.front().second.text ==
                        "second",
                "managed overlay update did not replace one semantic entity");
        const auto undone = first->overlay()->undo(
            first->overlay_revision());
        require(undone && undone.value().committed &&
                    first->overlay()->snapshot().items.size() == 1 &&
                    first->overlay()->snapshot().items.front().second.text ==
                        "first",
                "managed overlay undo did not restore exact prior payload");
        const auto redone = first->overlay()->redo(
            first->overlay_revision());
        require(redone && redone.value().committed &&
                    first->overlay()->snapshot().items.size() == 1 &&
                    first->overlay()->snapshot().items.front().second.text ==
                        "second",
                "managed overlay redo did not restore exact updated payload");
        verify_journal_storage_identity(first);

        overlay_transaction_request_t cross_workspace;
        cross_workspace.expected_revision = second->overlay_revision();
        cross_workspace.operations.push_back(journal_comment(
            overlay_operation_kind_t::comment,
            update_locator.value(), "cross-workspace"));
        require(!second->overlay()->transact(cross_workspace),
                "managed overlay crossed workspace isolation boundaries");

        const auto cancellation_binding = current_binding(first);
        const auto cancellation_locator = bind_managed_overlay_entity_v9(
            *first, cancellation_binding);
        require(static_cast<bool>(cancellation_locator),
                "managed overlay cancellation binding failed");
        overlay_transaction_request_t cancelled_request;
        cancelled_request.expected_revision = first->overlay_revision();
        cancelled_request.operations.push_back(journal_comment(
            overlay_operation_kind_t::comment,
            cancellation_locator.value(), "cancelled"));
        cancellation_source_t cancellation;
        cancellation.request_cancel();
        const auto cancelled = first->overlay()->transact(
            cancelled_request, cancellation.token());
        require(!cancelled &&
                    (cancelled.error().code ==
                         workspace_error_code_t::cancelled ||
                     cancelled.error().code ==
                         workspace_error_code_t::deadline_exceeded),
                "managed overlay cancellation did not fail closed");
        cancellation_source_t deadline(std::chrono::steady_clock::now());
        const auto expired = first->overlay()->transact(
            cancelled_request, deadline.token());
        require(!expired &&
                    expired.error().code ==
                        workspace_error_code_t::deadline_exceeded,
                "managed overlay deadline did not fail closed");

        const auto persisted_generation = first->generation();
        const auto persisted_revision = first->overlay_revision();
        close_workspace(first);
        first.reset();
        reopened = open_workspace(first_path, "managed-overlay-first.exe");
        install_services(reopened);
        const auto reopened_snapshot = reopened->overlay()->snapshot();
        require(reopened->generation() == persisted_generation &&
                    reopened->overlay_revision() == persisted_revision &&
                    reopened_snapshot.items.size() == 1 &&
                    reopened_snapshot.items.front().second.text == "second" &&
                    reopened_snapshot.items.front().second.managed_locator &&
                    reopened_snapshot.items.front().second.managed_locator
                        ->valid(),
                "managed overlay identity did not survive warm reopen");
        close_workspace(reopened, true);
        reopened.reset();
        close_workspace(second, true);
        second.reset();
    } catch (...) {
        if (reopened)
            close_workspace(reopened, true);
        if (first)
            close_workspace(first, true);
        if (second)
            close_workspace(second, true);
        throw;
    }
}

}

int run_managed_overlay_identity_harness()
{
    try {
        verify_locator_and_serialization_contract();
        verify_allowlist_history_projection_and_reanalysis();
        verify_schema_migration_and_corruption_guards();
        verify_journal_idempotency_recovery_and_isolation();
        std::cout << "managed overlay identity harness passed\n";
        return 0;
    } catch (const std::exception& error) {
        assertion_telemetry::record_exception(error.what());
        std::cerr << "managed overlay identity harness failed: "
                  << error.what() << '\n';
        return 1;
    }
}

}
