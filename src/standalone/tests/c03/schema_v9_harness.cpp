#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "schema_v9_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"
#include "managed_publication_persistence/managed_publication_persistence_harness.hpp"

#include "workspace_schema_v9.hpp"
#include "packed_page_codec.hpp"
#include "workspace_database.hpp"
#include "workspace_identity.hpp"
#include "../../src/core/infra/taskflow_runtime.hpp"
#include "../analysis_workspace/workspace_fixture_builder.hpp"

#include <windows.h>

#include <sqlite3.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <future>
#include <iterator>
#include <limits>
#include <memory>
#include <numeric>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>

namespace aida::analysis {

namespace {

class harness_statement_t final {
public:
    harness_statement_t() = default;
    ~harness_statement_t() {
        if (stmt_)
            sqlite3_finalize(stmt_);
    }
    harness_statement_t(const harness_statement_t&) = delete;
    harness_statement_t& operator=(const harness_statement_t&) = delete;

    bool prepare(sqlite3* db, const char* sql) {
        if (stmt_) {
            sqlite3_finalize(stmt_);
            stmt_ = nullptr;
        }
        return sqlite3_prepare_v3(db, sql, -1, SQLITE_PREPARE_PERSISTENT, &stmt_, nullptr) == SQLITE_OK;
    }

    sqlite3_stmt* get() const noexcept { return stmt_; }

    bool bind_text(int index, const std::string& value) {
        return sqlite3_bind_text(stmt_, index, value.data(),
                                 static_cast<int>(value.size()),
                                 SQLITE_TRANSIENT) == SQLITE_OK;
    }

    int step_row() {
        return sqlite3_step(stmt_);
    }

private:
    sqlite3_stmt* stmt_ = nullptr;
};

std::string temp_db_path(const char* tag) {
    wchar_t temp_dir[MAX_PATH];
    const DWORD length = GetTempPathW(MAX_PATH, temp_dir);
    if (length == 0 || length >= MAX_PATH) {
        return std::string("aida_v9_test_") + tag + std::string(".db");
    }
    std::filesystem::path root(temp_dir);
    root /= L"AiDA";
    root /= L"v9_tests";
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    static std::atomic<std::uint64_t> counter{1};
    const auto seq = counter.fetch_add(1, std::memory_order_relaxed);
    std::ostringstream name;
    name << "aida_v9_" << tag << "_" << seq << ".db";
    root /= std::filesystem::u8path(name.str());
    return root.u8string();
}

bool exec_sql(sqlite3* db, const char* sql) {
    char* err = nullptr;
    const int status = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (err)
        sqlite3_free(err);
    return status == SQLITE_OK;
}

bool table_exists(sqlite3* db, const char* table_name) {
    harness_statement_t stmt;
    if (!stmt.prepare(db, "SELECT name FROM sqlite_master WHERE type='table' AND name=?1"))
        return false;
    if (!stmt.bind_text(1, std::string(table_name)))
        return false;
    return stmt.step_row() == SQLITE_ROW;
}

bool index_exists(sqlite3* db, const char* index_name) {
    harness_statement_t stmt;
    if (!stmt.prepare(db, "SELECT name FROM sqlite_master WHERE type='index' AND name=?1"))
        return false;
    if (!stmt.bind_text(1, std::string(index_name)))
        return false;
    return stmt.step_row() == SQLITE_ROW;
}

std::uint32_t user_version(sqlite3* db) {
    harness_statement_t stmt;
    if (!stmt.prepare(db, "PRAGMA user_version") || stmt.step_row() != SQLITE_ROW)
        return (std::numeric_limits<std::uint32_t>::max)();
    return static_cast<std::uint32_t>(sqlite3_column_int64(stmt.get(), 0));
}

int deny_user_version_write(void*, int action, const char* name,
                            const char* value, const char*, const char*) {
    if (action == SQLITE_PRAGMA && name && value &&
        std::strcmp(name, "user_version") == 0)
        return SQLITE_DENY;
    return SQLITE_OK;
}

bool create_v8_schema(sqlite3* db) {
    if (!exec_sql(db, R"SQL(
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY NOT NULL,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS workspace_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),binary_id BLOB NOT NULL UNIQUE,bin_name TEXT NOT NULL,source_path TEXT NOT NULL,member_path TEXT,content_hash BLOB NOT NULL,load_profile_hash BLOB NOT NULL,target_kind INTEGER NOT NULL,format INTEGER NOT NULL,architecture INTEGER NOT NULL,architecture_mode INTEGER NOT NULL DEFAULT 0,abi INTEGER NOT NULL,endian INTEGER NOT NULL,image_base INTEGER NOT NULL,process_pid INTEGER,process_creation INTEGER,process_path TEXT,module_base INTEGER,module_size INTEGER,module_name TEXT,module_path TEXT,module_hash BLOB);
CREATE TABLE IF NOT EXISTS analysis_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL,analysis_revision INTEGER NOT NULL,overlay_revision INTEGER NOT NULL,baseline_complete INTEGER NOT NULL,settings_json TEXT NOT NULL,metrics_json TEXT NOT NULL,updated_utc_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS segments(segment_id INTEGER PRIMARY KEY,name TEXT NOT NULL,virtual_address INTEGER NOT NULL,virtual_size INTEGER NOT NULL,raw_offset INTEGER NOT NULL,raw_size INTEGER NOT NULL,characteristics INTEGER NOT NULL,readable INTEGER NOT NULL,writable INTEGER NOT NULL,executable INTEGER NOT NULL,discardable INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS instruction_chunks(chunk_id INTEGER PRIMARY KEY,start_value INTEGER NOT NULL,end_value INTEGER NOT NULL,record_count INTEGER NOT NULL,blob_version INTEGER NOT NULL,payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS operand_facts(instruction_id INTEGER NOT NULL,operand_index INTEGER NOT NULL,kind INTEGER NOT NULL,access INTEGER NOT NULL,bit_width INTEGER NOT NULL,reg INTEGER NOT NULL,base_reg INTEGER NOT NULL,index_reg INTEGER NOT NULL,scale INTEGER NOT NULL,relative INTEGER NOT NULL,signed_value INTEGER NOT NULL,displacement INTEGER NOT NULL,immediate INTEGER NOT NULL,segment_reg INTEGER NOT NULL DEFAULT 0,entity_id INTEGER NOT NULL DEFAULT 0,address_expression_id INTEGER NOT NULL DEFAULT 0,decoder_operand_id INTEGER NOT NULL DEFAULT 0,visibility INTEGER NOT NULL DEFAULT 0,encoding INTEGER NOT NULL DEFAULT 0,memory_type INTEGER NOT NULL DEFAULT 0,access_width INTEGER NOT NULL DEFAULT 0,access_width_bits INTEGER NOT NULL DEFAULT 0,access_count INTEGER NOT NULL DEFAULT 0,element_width_bits INTEGER NOT NULL DEFAULT 0,element_count INTEGER NOT NULL DEFAULT 0,address_width_bits INTEGER NOT NULL DEFAULT 0,has_displacement INTEGER NOT NULL DEFAULT 0,has_resolved_expression_value INTEGER NOT NULL DEFAULT 0,resolved_expression_value INTEGER NOT NULL DEFAULT 0,address_components INTEGER NOT NULL DEFAULT 0,address_expression INTEGER NOT NULL DEFAULT 0,address_resolution INTEGER NOT NULL DEFAULT 4,PRIMARY KEY(instruction_id,operand_index));
CREATE TABLE IF NOT EXISTS target_facts(instruction_id INTEGER NOT NULL,target_index INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,direct INTEGER NOT NULL,operand_fact_id INTEGER NOT NULL DEFAULT 0,address_expression_id INTEGER NOT NULL DEFAULT 0,resolution INTEGER NOT NULL DEFAULT 4,operand_index INTEGER NOT NULL DEFAULT 255,access_width_bits INTEGER NOT NULL DEFAULT 0,access_count INTEGER NOT NULL DEFAULT 0,is_external INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(instruction_id,target_index));
CREATE TABLE IF NOT EXISTS functions(entity_id INTEGER PRIMARY KEY,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_block INTEGER NOT NULL,block_count INTEGER NOT NULL,symbol_id INTEGER,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,thunk INTEGER NOT NULL,noreturn INTEGER NOT NULL,first_chunk INTEGER NOT NULL DEFAULT 0,chunk_count INTEGER NOT NULL DEFAULT 0,first_block_membership INTEGER NOT NULL DEFAULT 0,block_membership_count INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS blocks(entity_id INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_instruction INTEGER NOT NULL,instruction_count INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS edges(entity_id INTEGER PRIMARY KEY,source_entity INTEGER NOT NULL,target_entity INTEGER,source_space INTEGER NOT NULL,source_value INTEGER NOT NULL,source_arch INTEGER NOT NULL,source_mode INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS xrefs(entity_id INTEGER PRIMARY KEY,source_space INTEGER NOT NULL,source_value INTEGER NOT NULL,source_arch INTEGER NOT NULL,source_mode INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS strings(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,byte_length INTEGER NOT NULL,encoding INTEGER NOT NULL,value TEXT NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS symbols(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,name TEXT NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS coverage(span_id INTEGER PRIMARY KEY,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,size INTEGER NOT NULL,reason INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,detail_code INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS overlay_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision INTEGER NOT NULL,history_cursor INTEGER NOT NULL,next_transaction_id INTEGER NOT NULL,history_epoch INTEGER NOT NULL,updated_utc_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS overlay_transactions(transaction_id INTEGER PRIMARY KEY,revision INTEGER NOT NULL,history_epoch INTEGER NOT NULL,history_ordinal INTEGER NOT NULL,idempotency_key TEXT,request_hash TEXT NOT NULL,committed_utc_ms INTEGER NOT NULL,applied INTEGER NOT NULL,abandoned INTEGER NOT NULL,result_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS overlay_operations(transaction_id INTEGER NOT NULL,operation_index INTEGER NOT NULL,kind INTEGER NOT NULL,entity_key TEXT NOT NULL,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,before_json TEXT,after_json TEXT NOT NULL,PRIMARY KEY(transaction_id,operation_index));
CREATE TABLE IF NOT EXISTS overlay_items(entity_key TEXT PRIMARY KEY NOT NULL,kind INTEGER NOT NULL,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,payload_json TEXT NOT NULL,updated_revision INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS overlay_history_events(event_id INTEGER PRIMARY KEY AUTOINCREMENT,event_kind INTEGER NOT NULL,source_transaction_id INTEGER NOT NULL,resulting_revision INTEGER NOT NULL,history_epoch INTEGER NOT NULL,history_cursor INTEGER NOT NULL,created_utc_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS overlay_idempotency(idempotency_key TEXT PRIMARY KEY NOT NULL,request_hash TEXT NOT NULL,result_json TEXT NOT NULL,transaction_id INTEGER NOT NULL,created_utc_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS decompiler_cache(cache_key TEXT PRIMARY KEY NOT NULL,binary_id BLOB NOT NULL,format INTEGER NOT NULL,architecture INTEGER NOT NULL,architecture_mode INTEGER NOT NULL DEFAULT 0,abi INTEGER NOT NULL,endian INTEGER NOT NULL DEFAULT 0,engine_version TEXT NOT NULL,schema_version INTEGER NOT NULL,specification_version TEXT NOT NULL,settings_hash TEXT NOT NULL,function_id INTEGER NOT NULL,function_rva INTEGER NOT NULL,function_content_hash BLOB NOT NULL,overlay_revision INTEGER NOT NULL,generation INTEGER NOT NULL,function_name TEXT NOT NULL,result_json TEXT NOT NULL,created_utc_ms INTEGER NOT NULL,last_access_utc_ms INTEGER NOT NULL,result_bytes INTEGER NOT NULL,analysis_revision INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS data_candidates(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,size INTEGER NOT NULL,kind INTEGER NOT NULL,target_space INTEGER,target_value INTEGER,target_arch INTEGER,target_mode INTEGER,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS switches(entity_id INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,dispatch_space INTEGER NOT NULL,dispatch_value INTEGER NOT NULL,dispatch_arch INTEGER NOT NULL,dispatch_mode INTEGER NOT NULL,table_space INTEGER NOT NULL,table_value INTEGER NOT NULL,table_arch INTEGER NOT NULL,table_mode INTEGER NOT NULL,default_space INTEGER,default_value INTEGER,default_arch INTEGER,default_mode INTEGER,entry_size INTEGER NOT NULL,relative_entries INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS switch_cases(switch_id INTEGER NOT NULL,case_index INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,PRIMARY KEY(switch_id,case_index));
CREATE TABLE IF NOT EXISTS type_candidates(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,kind INTEGER NOT NULL,display_name TEXT NOT NULL,canonical_type TEXT NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,explicitly_unknown INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS search_index_blob(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL,analysis_revision INTEGER NOT NULL,overlay_revision INTEGER NOT NULL,blob_version INTEGER NOT NULL,payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS workspace_commit_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),active_slot INTEGER NOT NULL CHECK(active_slot IN (0,1)),committed_token TEXT NOT NULL,committed_generation INTEGER NOT NULL,committed_analysis_revision INTEGER NOT NULL,committed_overlay_revision INTEGER NOT NULL,candidate_slot INTEGER CHECK(candidate_slot IN (0,1)),candidate_token TEXT,candidate_generation INTEGER,candidate_analysis_revision INTEGER,candidate_overlay_revision INTEGER,candidate_ready INTEGER NOT NULL CHECK(candidate_ready IN (0,1)),updated_utc_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_analysis_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL,analysis_revision INTEGER NOT NULL,overlay_revision INTEGER NOT NULL,baseline_complete INTEGER NOT NULL,settings_json TEXT NOT NULL,metrics_json TEXT NOT NULL,updated_utc_ms INTEGER NOT NULL,commit_token TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_segments(segment_id INTEGER PRIMARY KEY,name TEXT NOT NULL,virtual_address INTEGER NOT NULL,virtual_size INTEGER NOT NULL,raw_offset INTEGER NOT NULL,raw_size INTEGER NOT NULL,characteristics INTEGER NOT NULL,readable INTEGER NOT NULL,writable INTEGER NOT NULL,executable INTEGER NOT NULL,discardable INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_instruction_chunks(chunk_id INTEGER PRIMARY KEY,start_value INTEGER NOT NULL,end_value INTEGER NOT NULL,record_count INTEGER NOT NULL,blob_version INTEGER NOT NULL,payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_operand_facts(instruction_id INTEGER NOT NULL,operand_index INTEGER NOT NULL,kind INTEGER NOT NULL,access INTEGER NOT NULL,bit_width INTEGER NOT NULL,reg INTEGER NOT NULL,segment_reg INTEGER NOT NULL,base_reg INTEGER NOT NULL,index_reg INTEGER NOT NULL,scale INTEGER NOT NULL,relative INTEGER NOT NULL,signed_value INTEGER NOT NULL,displacement INTEGER NOT NULL,immediate INTEGER NOT NULL,entity_id INTEGER NOT NULL DEFAULT 0,address_expression_id INTEGER NOT NULL DEFAULT 0,decoder_operand_id INTEGER NOT NULL DEFAULT 0,visibility INTEGER NOT NULL DEFAULT 0,encoding INTEGER NOT NULL DEFAULT 0,memory_type INTEGER NOT NULL DEFAULT 0,access_width INTEGER NOT NULL DEFAULT 0,access_width_bits INTEGER NOT NULL DEFAULT 0,access_count INTEGER NOT NULL DEFAULT 0,element_width_bits INTEGER NOT NULL DEFAULT 0,element_count INTEGER NOT NULL DEFAULT 0,address_width_bits INTEGER NOT NULL DEFAULT 0,has_displacement INTEGER NOT NULL DEFAULT 0,has_resolved_expression_value INTEGER NOT NULL DEFAULT 0,resolved_expression_value INTEGER NOT NULL DEFAULT 0,address_components INTEGER NOT NULL DEFAULT 0,address_expression INTEGER NOT NULL DEFAULT 0,address_resolution INTEGER NOT NULL DEFAULT 4,PRIMARY KEY(instruction_id,operand_index));
CREATE TABLE IF NOT EXISTS alternate_target_facts(instruction_id INTEGER NOT NULL,target_index INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,direct INTEGER NOT NULL,operand_fact_id INTEGER NOT NULL DEFAULT 0,address_expression_id INTEGER NOT NULL DEFAULT 0,resolution INTEGER NOT NULL DEFAULT 4,operand_index INTEGER NOT NULL DEFAULT 255,access_width_bits INTEGER NOT NULL DEFAULT 0,access_count INTEGER NOT NULL DEFAULT 0,is_external INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(instruction_id,target_index));
CREATE TABLE IF NOT EXISTS alternate_functions(entity_id INTEGER PRIMARY KEY,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_block INTEGER NOT NULL,block_count INTEGER NOT NULL,symbol_id INTEGER,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,thunk INTEGER NOT NULL,noreturn INTEGER NOT NULL,first_chunk INTEGER NOT NULL DEFAULT 0,chunk_count INTEGER NOT NULL DEFAULT 0,first_block_membership INTEGER NOT NULL DEFAULT 0,block_membership_count INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS alternate_blocks(entity_id INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_instruction INTEGER NOT NULL,instruction_count INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_edges(entity_id INTEGER PRIMARY KEY,source_entity INTEGER NOT NULL,target_entity INTEGER,source_space INTEGER NOT NULL,source_value INTEGER NOT NULL,source_arch INTEGER NOT NULL,source_mode INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_xrefs(entity_id INTEGER PRIMARY KEY,source_space INTEGER NOT NULL,source_value INTEGER NOT NULL,source_arch INTEGER NOT NULL,source_mode INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_strings(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,byte_length INTEGER NOT NULL,encoding INTEGER NOT NULL,value TEXT NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_symbols(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,name TEXT NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_coverage(span_id INTEGER PRIMARY KEY,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,size INTEGER NOT NULL,reason INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,detail_code INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_data_candidates(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,size INTEGER NOT NULL,kind INTEGER NOT NULL,target_space INTEGER,target_value INTEGER,target_arch INTEGER,target_mode INTEGER,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_switches(entity_id INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,dispatch_space INTEGER NOT NULL,dispatch_value INTEGER NOT NULL,dispatch_arch INTEGER NOT NULL,dispatch_mode INTEGER NOT NULL,table_space INTEGER NOT NULL,table_value INTEGER NOT NULL,table_arch INTEGER NOT NULL,table_mode INTEGER NOT NULL,default_space INTEGER,default_value INTEGER,default_arch INTEGER,default_mode INTEGER,entry_size INTEGER NOT NULL,relative_entries INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_switch_cases(switch_id INTEGER NOT NULL,case_index INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,PRIMARY KEY(switch_id,case_index));
CREATE TABLE IF NOT EXISTS alternate_type_candidates(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,kind INTEGER NOT NULL,display_name TEXT NOT NULL,canonical_type TEXT NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,explicitly_unknown INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_search_index_blob(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL,analysis_revision INTEGER NOT NULL,overlay_revision INTEGER NOT NULL,blob_version INTEGER NOT NULL,payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS function_chunks(chunk_index INTEGER PRIMARY KEY,entity_id INTEGER NOT NULL UNIQUE,function_id INTEGER NOT NULL,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_block INTEGER NOT NULL,block_count INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,cold INTEGER NOT NULL,shared INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS function_block_memberships(membership_index INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,chunk_id INTEGER NOT NULL,block_id INTEGER NOT NULL,block_index INTEGER NOT NULL,ordinal INTEGER NOT NULL,shared INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_function_chunks(chunk_index INTEGER PRIMARY KEY,entity_id INTEGER NOT NULL UNIQUE,function_id INTEGER NOT NULL,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_block INTEGER NOT NULL,block_count INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,cold INTEGER NOT NULL,shared INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_function_block_memberships(membership_index INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,chunk_id INTEGER NOT NULL,block_id INTEGER NOT NULL,block_index INTEGER NOT NULL,ordinal INTEGER NOT NULL,shared INTEGER NOT NULL);
PRAGMA user_version=8;
)SQL"))
        return false;
    return true;
}

bool open_db(const std::string& path, sqlite3** db) {
    return sqlite3_open_v2(path.c_str(), db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_URI,
        nullptr) == SQLITE_OK;
}

bool configure_wal(sqlite3* db) {
    if (!exec_sql(db, "PRAGMA journal_mode=WAL;"))
        return false;
    if (!exec_sql(db, "PRAGMA synchronous=FULL;"))
        return false;
    if (!exec_sql(db, "PRAGMA foreign_keys=ON;"))
        return false;
    return true;
}

void cleanup_db(const std::string& path) {
    std::error_code ec;
    std::filesystem::remove(std::filesystem::u8path(path), ec);
    std::filesystem::remove(std::filesystem::u8path(path + "-wal"), ec);
    std::filesystem::remove(std::filesystem::u8path(path + "-shm"), ec);
}

template <typename Fn>
std::uint64_t measure_us(Fn&& fn) {
    const auto start = std::chrono::steady_clock::now();
    fn();
    const auto end = std::chrono::steady_clock::now();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        end - start).count());
}

workspace_result_t<packed_generation_publication_t> publication_from_batch(
    const packed_page_batch_t& batch) {
    auto warm_index = packed_page_codec_t::build_warm_open_index(batch);
    if (!warm_index)
        return workspace_result_t<packed_generation_publication_t>::failure(
            warm_index.error());
    packed_generation_publication_t publication;
    publication.generation.generation = batch.generation;
    publication.generation.analysis_revision = batch.analysis_revision;
    publication.generation.overlay_revision = batch.overlay_revision;
    publication.generation.total_payload_bytes = batch.checkpoint.total_payload_bytes;
    publication.generation.total_records = batch.checkpoint.total_records;
    publication.generation.batch_checksum = batch.checkpoint.batch_checksum;
    publication.generation.created_utc_ms = batch.checkpoint.created_utc_ms;
    publication.generation.committed = false;
    const auto checkpoint = batch.checkpoint.encode();
    publication.generation.payload_blob.assign(checkpoint.begin(), checkpoint.end());
    std::unordered_set<std::uint16_t> domains;
    publication.pages.reserve(batch.pages.size());
    for (const auto& page : batch.pages) {
        packed_page_row_t row;
        row.generation = page.header.generation;
        row.page_index = page.header.page_index;
        row.page_count = page.header.page_count;
        row.page_type = page.header.page_type;
        row.payload_length = page.header.payload_length;
        row.checksum = page.header.checksum;
        row.payload = page.payload;
        domains.insert(static_cast<std::uint16_t>(row.page_type));
        publication.pages.push_back(std::move(row));
    }
    publication.generation.shard_count =
        static_cast<std::uint16_t>(domains.size());
    publication.index.reserve(warm_index.value().size());
    for (const auto& entry : warm_index.value()) {
        packed_page_index_row_t row;
        row.generation = batch.generation;
        row.domain = entry.domain;
        row.ordinal_begin = entry.ordinal_begin;
        row.count = entry.count;
        row.page_index = entry.page_index;
        row.address_value_min = entry.address_value_min;
        row.address_value_max = entry.address_value_max;
        publication.index.push_back(std::move(row));
    }
    return workspace_result_t<packed_generation_publication_t>::success(
        std::move(publication));
}

}

schema_v9_fixture_result_t run_golden_v8_migration() {
    schema_v9_fixture_result_t result;
    result.name = "golden_v8_migration";
    const auto path = temp_db_path("golden_v8");
    sqlite3* db = nullptr;
    std::uint64_t elapsed = 0;

    auto run = [&]() {
        if (!open_db(path, &db)) {
            result.message = "failed to open database";
            return;
        }
        if (!configure_wal(db)) {
            result.message = "failed to configure WAL";
            return;
        }
        if (!create_v8_schema(db)) {
            result.message = "failed to create v8 schema";
            return;
        }
        if (!exec_sql(db, R"SQL(
INSERT INTO workspace_identity(singleton,binary_id,bin_name,source_path,member_path,content_hash,load_profile_hash,target_kind,format,architecture,architecture_mode,abi,endian,image_base,process_pid,process_creation,process_path,module_base,module_size,module_name,module_path,module_hash)
VALUES(1,zeroblob(32),'golden.bin','C:/golden.bin',NULL,zeroblob(32),zeroblob(32),1,1,2,3,1,0,4194304,NULL,NULL,NULL,NULL,8192,NULL,NULL,NULL);
INSERT INTO analysis_state(singleton,generation,analysis_revision,overlay_revision,baseline_complete,settings_json,metrics_json,updated_utc_ms)
VALUES(1,11,9,7,1,'{}','{}',1000);
INSERT INTO overlay_state(singleton,revision,history_cursor,next_transaction_id,history_epoch,updated_utc_ms)
VALUES(1,7,3,12,2,1001);
INSERT INTO decompiler_cache(cache_key,binary_id,format,architecture,architecture_mode,abi,endian,engine_version,schema_version,specification_version,settings_hash,function_id,function_rva,function_content_hash,overlay_revision,generation,function_name,result_json,created_utc_ms,last_access_utc_ms,result_bytes,analysis_revision)
VALUES('legacy-key',zeroblob(32),1,2,3,1,0,'engine',8,'spec','settings',5,4096,zeroblob(32),7,11,'f','{}',1002,1003,2,9);
INSERT INTO data_candidates(entity_id,address_space,address_value,address_arch,address_mode,size,kind,target_space,target_value,target_arch,target_mode,provenance,confidence)
VALUES(576460752303423489,1,4096,2,3,8,5,1,8192,2,3,4,91);
INSERT INTO type_candidates(entity_id,address_space,address_value,address_arch,address_mode,kind,display_name,canonical_type,provenance,confidence,explicitly_unknown)
VALUES(720575940379279361,1,4096,2,3,0,'legacy_type','void()',10,88,0),
      (720575940379279362,1,8192,2,3,0,'legacy_export','int()',6,87,0);
)SQL")) {
            result.message = "failed to seed v8 backfill records";
            return;
        }
        bool invalidate_derived_facts = false;
        auto migrated = migrate_workspace_database_schema(
            db, invalidate_derived_facts);
        if (!migrated) {
            result.message = std::string("v9 migration failed: ") + migrated.error().message;
            return;
        }
        if (invalidate_derived_facts || user_version(db) != workspace_schema_v9_version) {
            result.message = "v8->v9 migration did not atomically advance user_version";
            return;
        }
        const std::array<const char*, 30> v9_tables = {
            "packed_generations", "packed_pages", "packed_page_index",
            "workbench_state", "decompiler_cache_v9", "overlay_v9_state",
            "call_graph_state", "call_graph_nodes", "call_sites",
            "call_candidates", "call_graph_edges", "call_graph_conflicts",
            "rich_data_candidates", "data_pointer_facts", "data_conflicts",
            "symbol_type_candidates", "type_references", "metadata_conflicts",
            "alternate_call_graph_state", "alternate_call_graph_nodes",
            "alternate_call_sites", "alternate_call_candidates",
            "alternate_call_graph_edges", "alternate_call_graph_conflicts",
            "alternate_rich_data_candidates", "alternate_data_pointer_facts",
            "alternate_data_conflicts", "alternate_symbol_type_candidates",
            "alternate_type_references", "alternate_metadata_conflicts"
        };
        for (const char* table : v9_tables) {
            if (!table_exists(db, table)) {
                result.message = std::string("missing v9 table: ") + table;
                return;
            }
        }
        const std::array<const char*, 7> v9_indexes = {
            "packed_generations_generation", "packed_generations_revisions",
            "packed_pages_generation", "packed_pages_type",
            "packed_page_index_generation_domain", "packed_page_index_address",
            "decompiler_cache_v9_function"
        };
        for (const char* idx : v9_indexes) {
            if (!index_exists(db, idx)) {
                result.message = std::string("missing v9 index: ") + idx;
                return;
            }
        }
        auto cache = read_decompiler_cache_v9(db, "legacy-key");
        if (!cache || !cache.value() || cache.value()->analysis_revision != 9 ||
            cache.value()->overlay_revision != 7 || cache.value()->generation != 11) {
            result.message = "v8 decompiler cache row was not backfilled into schema v9";
            return;
        }
        auto overlay = read_overlay_v9_state(db);
        if (!overlay || !overlay.value() || overlay.value()->revision != 7 ||
            overlay.value()->history_cursor != 3 ||
            overlay.value()->next_transaction_id != 12 ||
            overlay.value()->target_generation != 11 ||
            overlay.value()->target_image_base != 4194304 ||
            overlay.value()->target_image_size != 8192) {
            result.message = "v8 overlay and target identity were not backfilled into schema v9";
            return;
        }
        harness_statement_t rich_data;
        if (!rich_data.prepare(db,
                "SELECT target_value,provenance,confidence FROM rich_data_candidates WHERE entity_id=576460752303423489") ||
            rich_data.step_row() != SQLITE_ROW ||
            sqlite3_column_int64(rich_data.get(), 0) != 8192 ||
            sqlite3_column_int(rich_data.get(), 1) != 4 ||
            sqlite3_column_int(rich_data.get(), 2) != 91) {
            result.message = "v8 data candidate was not backfilled into rich facts";
            return;
        }
        harness_statement_t rich_type;
        if (!rich_type.prepare(db,
                "SELECT source_key,provenance,confidence FROM symbol_type_candidates WHERE entity_id=720575940379279361") ||
            rich_type.step_row() != SQLITE_ROW) {
            result.message = "v8 type candidate was not backfilled into rich facts";
            return;
        }
        const auto* source_key = sqlite3_column_text(rich_type.get(), 0);
        if (!source_key || std::strlen(reinterpret_cast<const char*>(source_key)) == 0 ||
            sqlite3_column_int(rich_type.get(), 1) != 6 ||
            sqlite3_column_int(rich_type.get(), 2) != 88) {
            result.message = "v8 type-candidate provenance backfill is incomplete";
            return;
        }
        harness_statement_t export_type;
        if (!export_type.prepare(db,
                "SELECT source_key,provenance,confidence FROM symbol_type_candidates WHERE entity_id=720575940379279362") ||
            export_type.step_row() != SQLITE_ROW) {
            result.message = "v8 export type candidate was not backfilled into rich facts";
            return;
        }
        const auto* export_source_key = sqlite3_column_text(export_type.get(), 0);
        if (!export_source_key ||
            std::strlen(reinterpret_cast<const char*>(export_source_key)) == 0 ||
            sqlite3_column_int(export_type.get(), 1) != 5 ||
            sqlite3_column_int(export_type.get(), 2) != 87) {
            result.message = "v8 export provenance backfill is incomplete";
            return;
        }
        if (!exec_sql(db, R"SQL(
DELETE FROM overlay_state;
INSERT INTO overlay_state(singleton,revision,history_cursor,next_transaction_id,history_epoch,updated_utc_ms)
VALUES(1,8,4,13,3,1004);
UPDATE analysis_state SET generation=12 WHERE singleton=1;
)SQL")) {
            result.message = "failed to exercise legacy-to-v9 synchronization triggers";
            return;
        }
        auto synchronized = read_overlay_v9_state(db);
        if (!synchronized || !synchronized.value() ||
            synchronized.value()->revision != 8 ||
            synchronized.value()->history_cursor != 4 ||
            synchronized.value()->next_transaction_id != 13 ||
            synchronized.value()->history_epoch != 3 ||
            synchronized.value()->target_generation != 12) {
            result.message = "legacy overlay/analysis writes did not synchronize schema-v9 state";
            return;
        }
        if (!exec_sql(db, "DELETE FROM analysis_state WHERE singleton=1")) {
            result.message = "failed to exercise analysis-state deletion trigger";
            return;
        }
        auto cleared_generation = read_overlay_v9_state(db);
        if (!cleared_generation || !cleared_generation.value() ||
            cleared_generation.value()->target_generation != 0) {
            result.message = "analysis-state deletion left a stale v9 target generation";
            return;
        }
        result.passed = true;
        result.message = "v8->v9 migration, backfill, and legacy synchronization verified";
    };
    elapsed = measure_us(run);
    result.elapsed_us = elapsed;
    if (db)
        sqlite3_close_v2(db);
    cleanup_db(path);
    return result;
}

schema_v9_fixture_result_t run_partial_v9_repair() {
    schema_v9_fixture_result_t result;
    result.name = "partial_v9_repair";
    const auto path = temp_db_path("partial_v9");
    sqlite3* db = nullptr;

    auto run = [&]() {
        if (!open_db(path, &db) || !configure_wal(db)) {
            result.message = "failed to open partial v9 database";
            return;
        }
        if (!exec_sql(db, R"SQL(
CREATE TABLE packed_generations(
    generation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL CHECK(generation<>0),
    analysis_revision INTEGER NOT NULL,
    overlay_revision INTEGER NOT NULL,
    shard_count INTEGER NOT NULL CHECK(shard_count BETWEEN 1 AND 13),
    total_payload_bytes INTEGER NOT NULL CHECK(total_payload_bytes BETWEEN 0 AND 536870912),
    total_records INTEGER NOT NULL CHECK(total_records BETWEEN 1 AND 131072),
    batch_checksum INTEGER NOT NULL,
    created_utc_ms INTEGER NOT NULL,
    committed INTEGER NOT NULL CHECK(committed IN (0,1)),
    payload_blob BLOB NOT NULL CHECK(length(payload_blob)<=16777216),
    UNIQUE(generation)
);
CREATE TABLE packed_pages(
    page_id INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL,
    page_index INTEGER NOT NULL CHECK(page_index BETWEEN 0 AND 131071),
    page_count INTEGER NOT NULL CHECK(page_count BETWEEN 1 AND 131072),
    page_type INTEGER NOT NULL CHECK(page_type BETWEEN 1 AND 13),
    payload_length INTEGER NOT NULL CHECK(payload_length BETWEEN 0 AND 1048576),
    checksum INTEGER NOT NULL,
    payload BLOB NOT NULL CHECK(length(payload)=payload_length),
    UNIQUE(generation,page_index),
    FOREIGN KEY(generation) REFERENCES packed_generations(generation) ON DELETE CASCADE
);
CREATE TABLE packed_page_index(
    index_id INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL,
    domain INTEGER NOT NULL CHECK(domain BETWEEN 1 AND 13),
    ordinal_begin INTEGER NOT NULL CHECK(ordinal_begin BETWEEN 0 AND 4294967295),
    count INTEGER NOT NULL CHECK(count BETWEEN 0 AND 1048576),
    page_index INTEGER NOT NULL CHECK(page_index BETWEEN 0 AND 131071),
    address_value_min INTEGER NOT NULL,
    address_value_max INTEGER NOT NULL,
    UNIQUE(generation,domain,page_index),
    FOREIGN KEY(generation) REFERENCES packed_generations(generation) ON DELETE CASCADE
);
PRAGMA user_version=9;
)SQL")) {
            result.message = "failed to create partial v9 packed schema";
            return;
        }
        bool invalidate_derived_facts = false;
        auto migrated = migrate_workspace_database_schema(
            db, invalidate_derived_facts);
        if (!migrated || invalidate_derived_facts ||
            user_version(db) != workspace_schema_v9_version) {
            result.message = "production migration did not repair partial schema v9";
            return;
        }
        packed_page_encode_options_t options;
        options.generation = 109;
        options.analysis_revision = 19;
        options.overlay_revision = 7;
        options.page_size = packed_page_default_size;
        auto batch = packed_page_codec_t::encode_batch(
            packed_page_type_t::managed_publication,
            std::vector<std::uint8_t>(fixed_width_address_size, 0x5AU),
            options);
        if (!batch) {
            result.message = "repaired v9 schema could not encode the new packed domain";
            return;
        }
        auto publication = publication_from_batch(batch.value());
        if (!publication ||
            !publish_packed_generation_atomic(db, publication.value())) {
            result.message = "repaired v9 schema rejected the new packed domain";
            return;
        }
        auto loaded = read_packed_generation_publication(db, options.generation);
        if (!loaded || !loaded.value() || loaded.value()->pages.size() != 1 ||
            loaded.value()->pages.front().page_type !=
                static_cast<std::uint32_t>(
                    packed_page_type_t::managed_publication)) {
            result.message = "repaired v9 packed domain did not round-trip";
            return;
        }
        result.passed = true;
        result.message = "partial schema-v9 packed domain was repaired in production migration";
    };
    result.elapsed_us = measure_us(run);
    if (db)
        sqlite3_close_v2(db);
    cleanup_db(path);
    return result;
}

schema_v9_fixture_result_t run_interrupted_commit() {
    schema_v9_fixture_result_t result;
    result.name = "interrupted_commit";
    const auto path = temp_db_path("interrupted");
    sqlite3* db = nullptr;

    auto run = [&]() {
        if (!open_db(path, &db) || !configure_wal(db)) {
            result.message = "failed to open/configure database";
            return;
        }
        auto migrated = create_schema_v9(db);
        if (!migrated) {
            result.message = "v9 migration failed";
            return;
        }
        packed_page_encode_options_t options;
        options.generation = 42;
        options.analysis_revision = 1;
        options.overlay_revision = 0;
        options.page_size = 256;
        std::vector<std::uint8_t> data(512, 0xAB);
        auto batch = packed_page_codec_t::encode_batch(
            packed_page_type_t::instructions, data, options);
        if (!batch) {
            result.message = "failed to encode batch";
            return;
        }
        auto publication = publication_from_batch(batch.value());
        if (!publication) {
            result.message = "failed to construct publication";
            return;
        }
        auto written = write_packed_generation(db, publication.value().generation);
        if (!written) {
            result.message = "failed to stage generation";
            return;
        }
        for (const auto& page : publication.value().pages) {
            written = write_packed_page(db, page);
            if (!written) {
                result.message = "failed to stage page";
                return;
            }
        }
        for (const auto& index : publication.value().index) {
            written = write_packed_page_index(db, index);
            if (!written) {
                result.message = "failed to stage page index";
                return;
            }
        }
        sqlite3_close_v2(db);
        db = nullptr;
        if (!open_db(path, &db) || !configure_wal(db)) {
            result.message = "failed to reopen database";
            return;
        }
        auto committed_manifest = read_packed_generation(db, 42);
        auto committed_pages = read_packed_pages(db, 42);
        auto committed_index = read_packed_page_index(db, 42);
        if (!committed_manifest || !committed_pages || !committed_index ||
            committed_manifest.value() || !committed_pages.value().empty() ||
            !committed_index.value().empty()) {
            result.message = "read-committed path exposed an interrupted publication";
            return;
        }
        auto staged_manifest = read_packed_generation(db, 42, false);
        auto staged_pages = read_packed_pages(db, 42, false);
        auto staged_index = read_packed_page_index(db, 42, false);
        if (!staged_manifest || !staged_manifest.value() ||
            !staged_pages || staged_pages.value().size() != batch.value().pages.size() ||
            !staged_index || staged_index.value().size() != batch.value().pages.size()) {
            result.message = "diagnostic staging path did not preserve interrupted rows";
            return;
        }
        auto publish = publish_packed_generation(db, 42);
        if (!publish) {
            result.message = std::string("failed to validate and publish staged generation: ") +
                             publish.error().message;
            return;
        }
        auto committed = read_packed_generation_publication(db, 42);
        if (!committed || !committed.value() ||
            !committed.value()->generation.committed ||
            committed.value()->pages.size() != batch.value().pages.size()) {
            result.message = "committed publication did not become atomically visible";
            return;
        }
        if (publish_packed_generation(db, 42)) {
            result.message = "double publish should fail";
            return;
        }
        result.passed = true;
        result.message = "interrupted staging stayed hidden and validated publish became visible";
    };
    result.elapsed_us = measure_us(run);
    if (db)
        sqlite3_close_v2(db);
    cleanup_db(path);
    return result;
}

schema_v9_fixture_result_t run_corruption_detection() {
    schema_v9_fixture_result_t result;
    result.name = "corruption_detection";

    auto run = [&]() {
        packed_page_encode_options_t options;
        options.generation = 7;
        options.analysis_revision = 2;
        options.overlay_revision = 1;
        options.page_size = 128;
        std::vector<std::uint8_t> data(300, 0x55);
        auto batch = packed_page_codec_t::encode_batch(
            packed_page_type_t::functions, data, options);
        if (!batch) {
            result.message = "failed to encode batch";
            return;
        }
        auto verified = packed_page_codec_t::verify_batch(batch.value());
        if (!verified) {
            result.message = "clean batch verification failed";
            return;
        }
        auto& pages = batch.value().pages;
        if (pages.size() < 2) {
            result.message = "batch has too few pages for corruption test";
            return;
        }
        pages[1].payload[5] ^= 0xFF;
        auto corrupted = packed_page_codec_t::verify_batch(batch.value());
        if (corrupted) {
            result.message = "corrupted batch passed verification";
            return;
        }
        if (corrupted.error().code != workspace_error_code_t::integrity_failure) {
            result.message = std::string("corruption detected with wrong error code: ") +
                             corrupted.error().stable_code();
            return;
        }
        pages[1].payload[5] ^= 0xFF;
        auto restored = packed_page_codec_t::verify_batch(batch.value());
        if (!restored) {
            result.message = "restored batch verification failed";
            return;
        }
        pages[0].header.checksum ^= 0x80000000U;
        auto header_corrupted = packed_page_codec_t::verify_page(pages[0]);
        if (header_corrupted) {
            result.message = "header-corrupted page passed verification";
            return;
        }
        pages[0].header.checksum ^= 0x80000000U;
        batch.value().checkpoint.batch_checksum ^= 1U;
        auto checkpoint_corrupted = packed_page_codec_t::verify_batch(batch.value());
        if (checkpoint_corrupted) {
            result.message = "corrupted checkpoint passed batch verification";
            return;
        }
        packed_page_checkpoint_t checkpoint;
        checkpoint.batch_checksum = 0xAABBCCDDu;
        checkpoint.total_records = 0x0102030405060708ull;
        checkpoint.total_payload_bytes = 0x1112131415161718ull;
        checkpoint.created_utc_ms = 0x2122232425262728ull;
        auto checkpoint_page = packed_page_codec_t::encode_checkpoint_page(
            7, 2, 1, checkpoint);
        if (!checkpoint_page) {
            result.message = "checkpoint page encoding failed";
            return;
        }
        if (checkpoint_page.value().payload.size() != 28 ||
            checkpoint_page.value().header.payload_length != 28) {
            result.message = "checkpoint payload size is not the complete 28-byte encoding";
            return;
        }
        auto decoded_checkpoint = packed_page_codec_t::decode_checkpoint_page(
            checkpoint_page.value());
        if (!decoded_checkpoint ||
            decoded_checkpoint.value().batch_checksum != checkpoint.batch_checksum ||
            decoded_checkpoint.value().total_records != checkpoint.total_records ||
            decoded_checkpoint.value().total_payload_bytes != checkpoint.total_payload_bytes ||
            decoded_checkpoint.value().created_utc_ms != checkpoint.created_utc_ms) {
            result.message = "checkpoint page did not round-trip all fields";
            return;
        }
        auto direct_truncated_checkpoint = packed_page_checkpoint_t::decode(
            checkpoint_page.value().payload.data(), 27);
        if (direct_truncated_checkpoint) {
            result.message = "direct checkpoint decoder accepted a 27-byte payload";
            return;
        }
        auto truncated_checkpoint = checkpoint_page.value();
        truncated_checkpoint.payload.pop_back();
        truncated_checkpoint.header.payload_length =
            static_cast<std::uint32_t>(truncated_checkpoint.payload.size());
        truncated_checkpoint.header.checksum = pages[0].header.checksum;
        auto truncated_decoded = packed_page_codec_t::decode_checkpoint_page(
            truncated_checkpoint);
        if (truncated_decoded) {
            result.message = "truncated checkpoint payload decoded successfully";
            return;
        }
        packed_page_encode_options_t short_options;
        short_options.generation = 8;
        short_options.analysis_revision = 2;
        short_options.overlay_revision = 1;
        short_options.page_size = 128;
        std::vector<std::uint8_t> short_payload{1, 2, 3, 4};
        auto short_batch = packed_page_codec_t::encode_batch(
            packed_page_type_t::strings, short_payload, short_options);
        if (!short_batch) {
            result.message = "failed to encode short payload batch";
            return;
        }
        auto short_index = packed_page_codec_t::build_warm_open_index(
            short_batch.value());
        if (!short_index || short_index.value().empty() ||
            short_index.value()[0].address_value_min != 0 ||
            short_index.value()[0].address_value_max != 0) {
            result.message = "short payload warm-open index read beyond fixed-width address data";
            return;
        }
        result.passed = true;
        result.message = "payload, header, checkpoint, and short warm-index corruption cases were detected";
    };
    result.elapsed_us = measure_us(run);
    return result;
}

schema_v9_fixture_result_t run_rollback_after_failed_migration() {
    schema_v9_fixture_result_t result;
    result.name = "rollback_after_failed_migration";
    const auto path = temp_db_path("rollback");
    sqlite3* db = nullptr;

    auto run = [&]() {
        if (!open_db(path, &db) || !configure_wal(db)) {
            result.message = "failed to open database";
            return;
        }
        if (!create_v8_schema(db)) {
            result.message = "failed to create v8 schema";
            return;
        }
        if (sqlite3_set_authorizer(db, deny_user_version_write, nullptr) != SQLITE_OK) {
            result.message = "failed to install migration failure hook";
            return;
        }
        bool invalidate_derived_facts = false;
        auto denied = migrate_workspace_database_schema(
            db, invalidate_derived_facts);
        sqlite3_set_authorizer(db, nullptr, nullptr);
        if (denied) {
            result.message = "migration unexpectedly ignored denied user_version write";
            return;
        }
        if (user_version(db) != 8 || table_exists(db, "packed_generations") ||
            table_exists(db, "workbench_state") ||
            !table_exists(db, "metadata") ||
            !table_exists(db, "decompiler_cache")) {
            result.message = "failed migration did not roll schema and user_version back to v8";
            return;
        }
        auto migrated = migrate_workspace_database_schema(
            db, invalidate_derived_facts);
        if (!migrated) {
            result.message = std::string("migration after rollback failed: ") +
                             migrated.error().message;
            return;
        }
        if (user_version(db) != workspace_schema_v9_version ||
            !table_exists(db, "packed_generations") ||
            !table_exists(db, "workbench_state")) {
            result.message = "clean retry did not commit schema v9";
            return;
        }
        result.passed = true;
        result.message = "denied version write rolled all v9 DDL back and clean retry committed";
    };
    result.elapsed_us = measure_us(run);
    if (db)
        sqlite3_close_v2(db);
    cleanup_db(path);
    return result;
}

schema_v9_fixture_result_t run_fixed_width_address() {
    schema_v9_fixture_result_t result;
    result.name = "fixed_width_address";

    auto run = [&]() {
        const std::array<address_t, 8> test_addresses = {{
            {address_space_id_t::file_offset, 0, architecture_id_t::x86, architecture_mode_t::x86_32},
            {address_space_id_t::relative_virtual, 0x1000, architecture_id_t::x86_64, architecture_mode_t::x86_64},
            {address_space_id_t::virtual_address, 0x7FFE0000, architecture_id_t::aarch64, architecture_mode_t::aarch64},
            {address_space_id_t::live_virtual, 0xFFFFFFFFFFFFFFFFULL, architecture_id_t::mips, architecture_mode_t::unknown},
            {address_space_id_t::relative_virtual, 0x180100000ULL, architecture_id_t::ppc, architecture_mode_t::unknown},
            {address_space_id_t::file_offset, 1, architecture_id_t::riscv, architecture_mode_t::unknown},
            {address_space_id_t::virtual_address, 0, architecture_id_t::unknown, architecture_mode_t::unknown},
            {address_space_id_t::relative_virtual, 0x400000, architecture_id_t::x86_64, architecture_mode_t::x86_64}
        }};
        for (std::size_t index = 0; index < test_addresses.size(); ++index) {
            const auto& original = test_addresses[index];
            auto encoded = packed_page_codec_t::encode_fixed_width_address(original);
            if (encoded.size() != fixed_width_address_size) {
                result.message = std::string("encoded size mismatch for address #") + std::to_string(index);
                return;
            }
            auto decoded = packed_page_codec_t::decode_fixed_width_address(encoded.data(), encoded.size());
            if (decoded != original) {
                result.message = std::string("round-trip mismatch for address #") + std::to_string(index);
                return;
            }
            auto fw = fixed_width_address_t::encode(original);
            auto fw_decoded = fw.decode();
            if (fw_decoded != original) {
                result.message = std::string("fixed_width_address_t round-trip mismatch for address #") + std::to_string(index);
                return;
            }
            auto hex_str = fw.hex();
            auto from_hex = fixed_width_address_t::from_hex(hex_str);
            if (!from_hex) {
                result.message = std::string("from_hex failed for address #") + std::to_string(index);
                return;
            }
            if (from_hex.value().decode() != original) {
                result.message = std::string("hex round-trip mismatch for address #") + std::to_string(index);
                return;
            }
            auto bad_hex = fixed_width_address_t::from_hex("xyz");
            if (bad_hex) {
                result.message = "from_hex accepted invalid input";
                return;
            }
        }
        auto empty_decoded = packed_page_codec_t::decode_fixed_width_address(nullptr, 0);
        if (empty_decoded.value != 0 || empty_decoded.space != address_space_id_t::relative_virtual) {
            result.message = "decode of empty buffer did not return default address";
            return;
        }
        result.passed = true;
        result.message = "8 address variants round-tripped through 16-byte fixed-width encoding";
    };
    result.elapsed_us = measure_us(run);
    return result;
}

schema_v9_fixture_result_t run_concurrent_reader() {
    schema_v9_fixture_result_t result;
    result.name = "concurrent_reader";
    const auto path = temp_db_path("concurrent");
    sqlite3* writer = nullptr;
    sqlite3* reader = nullptr;

    auto run = [&]() {
        if (!open_db(path, &writer) || !configure_wal(writer)) {
            result.message = "failed to open writer";
            return;
        }
        auto migrated = create_schema_v9(writer);
        if (!migrated) {
            result.message = "v9 migration failed";
            return;
        }
        packed_page_encode_options_t options;
        options.page_size = 256;
        options.generation = 10;
        options.analysis_revision = 1;
        auto batch1 = packed_page_codec_t::encode_batch(
            packed_page_type_t::instructions,
            std::vector<std::uint8_t>(128, 0xAA), options);
        if (!batch1) {
            result.message = "failed to encode generation 10";
            return;
        }
        auto publication1 = publication_from_batch(batch1.value());
        if (!publication1 ||
            !publish_packed_generation_atomic(writer, publication1.value())) {
            result.message = "failed to publish generation 10";
            return;
        }
        if (sqlite3_open_v2(path.c_str(), &reader,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_URI,
            nullptr) != SQLITE_OK) {
            result.message = "failed to open reader";
            return;
        }
        exec_sql(reader, "PRAGMA journal_mode=WAL;");
        exec_sql(reader, "BEGIN");
        auto read1 = read_packed_generation(reader, 10);
        if (!read1 || !read1.value()) {
            result.message = "reader cannot see initial committed generation";
            return;
        }
        options.generation = 11;
        options.analysis_revision = 2;
        options.overlay_revision = 1;
        auto batch2 = packed_page_codec_t::encode_batch(
            packed_page_type_t::instructions,
            std::vector<std::uint8_t>(128, 0xBB), options);
        if (!batch2) {
            result.message = "failed to encode generation 11";
            return;
        }
        auto publication2 = publication_from_batch(batch2.value());
        if (!publication2 ||
            !publish_packed_generation_atomic(writer, publication2.value())) {
            result.message = "failed to publish generation 11";
            return;
        }
        auto read2_inside = read_packed_generation(reader, 11);
        if (!read2_inside || read2_inside.value()) {
            result.message = "reader snapshot observed a later committed generation";
            return;
        }
        if (!exec_sql(reader, "COMMIT")) {
            result.message = "failed to close reader snapshot";
            return;
        }
        auto read2_after = read_packed_generation(reader, 11);
        if (!read2_after || !read2_after.value() ||
            read2_after.value()->generation != 11) {
            result.message = "reader cannot see generation 11 after snapshot commit";
            return;
        }
        result.passed = true;
        result.message = "WAL reader retained one committed snapshot and advanced after commit";
    };
    result.elapsed_us = measure_us(run);
    if (reader)
        sqlite3_close_v2(reader);
    if (writer)
        sqlite3_close_v2(writer);
    cleanup_db(path);
    return result;
}

schema_v9_fixture_result_t run_cache_key_round_trip() {
    schema_v9_fixture_result_t result;
    result.name = "cache_key_round_trip";
    const auto path = temp_db_path("cache_key");
    sqlite3* db = nullptr;

    auto run = [&]() {
        if (!open_db(path, &db) || !configure_wal(db)) {
            result.message = "failed to open database";
            return;
        }
        auto migrated = create_schema_v9(db);
        if (!migrated) {
            result.message = "v9 migration failed";
            return;
        }
        decompiler_cache_v9_record_t record;
        record.cache_key = "test_binary|x86_64|pe32_plus|windows_x64|v1.0|9|spec_v2|hash_abc|42|0x401000|content_hash_xyz|3|7|5|func_main|{\"result\":\"test\"}";
        record.binary_id.bytes.fill(0xAB);
        record.format = format_id_t::pe32_plus;
        record.architecture = architecture_id_t::x86_64;
        record.architecture_mode = architecture_mode_t::x86_64;
        record.abi = abi_id_t::windows_x64;
        record.endian = endian_t::little;
        record.engine_version = "v1.0";
        record.schema_version = 9;
        record.specification_version = "spec_v2";
        record.settings_hash = "hash_abc";
        record.function_id = 42;
        record.function_rva = 0x401000;
        record.function_rva_address = {address_space_id_t::relative_virtual, 0x401000,
                                        architecture_id_t::x86_64, architecture_mode_t::x86_64};
        record.function_content_hash.bytes.fill(0xCD);
        record.analysis_revision = 3;
        record.overlay_revision = 7;
        record.generation = 5;
        record.function_name = "func_main";
        record.result_json = "{\"result\":\"test\",\"nested\":{\"key\":\"value\"}}";
        record.created_utc_ms = 1234567890;
        record.last_access_utc_ms = 1234567891;
        record.result_bytes = record.result_json.size();
        record.cache_key_version = 1;
        auto written = write_decompiler_cache_v9(db, record);
        if (!written) {
            result.message = std::string("failed to write cache record: ") + written.error().message;
            return;
        }
        auto read = read_decompiler_cache_v9(db, record.cache_key);
        if (!read) {
            result.message = std::string("failed to read cache record: ") + read.error().message;
            return;
        }
        if (!read.value()) {
            result.message = "cache record not found";
            return;
        }
        const auto& found = *read.value();
        if (found.cache_key != record.cache_key ||
            found.format != record.format ||
            found.architecture != record.architecture ||
            found.architecture_mode != record.architecture_mode ||
            found.abi != record.abi ||
            found.endian != record.endian ||
            found.engine_version != record.engine_version ||
            found.schema_version != record.schema_version ||
            found.specification_version != record.specification_version ||
            found.settings_hash != record.settings_hash ||
            found.function_id != record.function_id ||
            found.function_rva != record.function_rva ||
            found.function_rva_address != record.function_rva_address ||
            found.analysis_revision != record.analysis_revision ||
            found.overlay_revision != record.overlay_revision ||
            found.generation != record.generation ||
            found.function_name != record.function_name ||
            found.result_json != record.result_json ||
            found.result_bytes != record.result_bytes ||
            found.cache_key_version != record.cache_key_version) {
            result.message = "cache record field mismatch after round-trip";
            return;
        }
        if (found.function_content_hash != record.function_content_hash) {
            result.message = "function_content_hash mismatch";
            return;
        }
        if (found.binary_id != record.binary_id) {
            result.message = "binary_id mismatch";
            return;
        }
        auto collision = record;
        ++collision.function_id;
        auto collision_write = write_decompiler_cache_v9(db, collision);
        if (collision_write ||
            collision_write.error().code != workspace_error_code_t::target_conflict) {
            result.message = "canonical cache key accepted conflicting identity metadata";
            return;
        }
        auto preserved = read_decompiler_cache_v9(db, record.cache_key);
        if (!preserved || !preserved.value() ||
            preserved.value()->function_id != record.function_id ||
            preserved.value()->result_json != record.result_json) {
            result.message = "cache identity collision modified the stored record";
            return;
        }
        auto empty_key = read_decompiler_cache_v9(db, "nonexistent_key");
        if (!empty_key || empty_key.value()) {
            result.message = "nonexistent cache key should return nullopt";
            return;
        }
        result.passed = true;
        result.message = "decompiler cache v9 record with fixed-width address key round-tripped successfully";
    };
    result.elapsed_us = measure_us(run);
    if (db)
        sqlite3_close_v2(db);
    cleanup_db(path);
    return result;
}

schema_v9_fixture_result_t run_workbench_round_trip() {
    schema_v9_fixture_result_t result;
    result.name = "workbench_round_trip";
    const auto path = temp_db_path("workbench");
    sqlite3* db = nullptr;

    auto run = [&]() {
        if (!open_db(path, &db) || !configure_wal(db)) {
            result.message = "failed to open database";
            return;
        }
        auto migrated = create_schema_v9(db);
        if (!migrated) {
            result.message = "v9 migration failed";
            return;
        }
        workbench_state_record_t record;
        record.workspace_id = 17;
        record.contract_schema_version = 2;
        record.revision = 42;
        record.fingerprint = 0x1020304050607080ULL;
        record.payload_json =
            R"JSON({"schema":9,"kind":"workbench_persistence_v9","payload":{"split_tree":{"nodes":[]},"documents":[{"id":"1"}],"panels":[{"id":"2"}],"history":{"back":[],"forward":[]}}})JSON";
        auto written = write_workbench_state(db, record);
        if (!written) {
            result.message = std::string("failed to write workbench DTO envelope: ") +
                             written.error().message;
            return;
        }
        if (!write_workbench_state(db, record)) {
            result.message = "identical workbench revision was not idempotent";
            return;
        }
        auto read = read_workbench_state(db);
        if (!read || !read.value()) {
            result.message = "failed to read workbench DTO envelope";
            return;
        }
        if (read.value()->workspace_id != record.workspace_id ||
            read.value()->contract_schema_version != record.contract_schema_version ||
            read.value()->revision != record.revision ||
            read.value()->fingerprint != record.fingerprint ||
            read.value()->payload_json != record.payload_json) {
            result.message = "workbench DTO metadata changed during storage";
            return;
        }
        auto conflicting = record;
        conflicting.payload_json.push_back(' ');
        conflicting.fingerprint ^= 1;
        if (write_workbench_state(db, conflicting)) {
            result.message = "same-revision workbench conflict was accepted";
            return;
        }
        auto update = record;
        update.revision = 43;
        update.fingerprint ^= 0x55;
        update.payload_json = R"JSON({"schema":9,"kind":"workbench_persistence_v9","payload":{"split_tree":{"nodes":[{"id":"3"}]},"documents":[],"panels":[],"history":{"back":[],"forward":[]}}})JSON";
        if (!write_workbench_state(db, update)) {
            result.message = "higher-revision workbench update was rejected";
            return;
        }
        auto read2 = read_workbench_state(db);
        if (!read2 || !read2.value() || read2.value()->revision != 43 ||
            read2.value()->fingerprint != update.fingerprint ||
            read2.value()->payload_json != update.payload_json) {
            result.message = "higher-revision workbench update was not durable";
            return;
        }
        auto high_revision = update;
        high_revision.revision = 0x8000000000000000ULL;
        high_revision.fingerprint ^= 0x100;
        high_revision.payload_json.push_back(' ');
        if (!write_workbench_state(db, high_revision)) {
            result.message = "unsigned high-bit workbench revision was rejected";
            return;
        }
        auto maximum_revision = high_revision;
        maximum_revision.revision = (std::numeric_limits<std::uint64_t>::max)();
        maximum_revision.fingerprint ^= 0x200;
        maximum_revision.payload_json.push_back(' ');
        if (!write_workbench_state(db, maximum_revision)) {
            result.message = "maximum workbench revision was rejected";
            return;
        }
        auto read_maximum = read_workbench_state(db);
        if (!read_maximum || !read_maximum.value() ||
            read_maximum.value()->revision != maximum_revision.revision ||
            read_maximum.value()->payload_json != maximum_revision.payload_json) {
            result.message = "maximum workbench revision did not round-trip";
            return;
        }
        if (write_workbench_state(db, record)) {
            result.message = "stale workbench revision was accepted";
            return;
        }
        result.passed = true;
        result.message = "canonical DTO envelope, idempotency, and revision conflicts verified";
    };
    result.elapsed_us = measure_us(run);
    if (db)
        sqlite3_close_v2(db);
    cleanup_db(path);
    return result;
}

schema_v9_fixture_result_t run_generation_atomicity() {
    schema_v9_fixture_result_t result;
    result.name = "generation_atomicity";
    const auto path = temp_db_path("atomicity");
    sqlite3* db = nullptr;

    auto run = [&]() {
        if (!open_db(path, &db) || !configure_wal(db)) {
            result.message = "failed to open database";
            return;
        }
        auto migrated = create_schema_v9(db);
        if (!migrated) {
            result.message = "v9 migration failed";
            return;
        }
        packed_page_encode_options_t options;
        options.generation = 99;
        options.analysis_revision = 5;
        options.overlay_revision = 3;
        options.page_size = 512;
        std::vector<std::pair<packed_page_type_t, std::vector<std::uint8_t>>> domains;
        std::vector<std::uint8_t> instruction_data(1024);
        std::iota(instruction_data.begin(), instruction_data.end(),
                  static_cast<std::uint8_t>(0));
        domains.emplace_back(packed_page_type_t::instructions,
                             std::move(instruction_data));
        domains.emplace_back(packed_page_type_t::functions,
                             std::vector<std::uint8_t>(256, 0x77));
        domains.emplace_back(packed_page_type_t::edges,
                             std::vector<std::uint8_t>(128, 0x33));
        domains.emplace_back(packed_page_type_t::symbol_type_candidates,
                             std::vector<std::uint8_t>(192, 0x55));
        auto batch = packed_page_codec_t::encode_multi_domain_batch(domains, options);
        if (!batch) {
            result.message = std::string("failed to encode multi-domain batch: ") +
                             batch.error().message;
            return;
        }
        auto publication = publication_from_batch(batch.value());
        if (!publication) {
            result.message = "failed to construct multi-domain publication";
            return;
        }
        std::size_t transaction_cancellation_checks = 0;
        auto cancelled = publish_packed_generation_atomic(
            db, publication.value(), [db, &transaction_cancellation_checks] {
                if (sqlite3_get_autocommit(db) != 0)
                    return false;
                ++transaction_cancellation_checks;
                return transaction_cancellation_checks == 5;
            });
        if (cancelled ||
            cancelled.error().code != workspace_error_code_t::cancelled ||
            transaction_cancellation_checks != 5) {
            result.message = "bulk publication cancellation did not fail closed";
            return;
        }
        auto cancelled_manifest = read_packed_generation(db, 99, false);
        auto cancelled_pages = read_packed_pages(db, 99, false);
        auto cancelled_index = read_packed_page_index(db, 99, false);
        if (!cancelled_manifest || cancelled_manifest.value() ||
            !cancelled_pages || !cancelled_pages.value().empty() ||
            !cancelled_index || !cancelled_index.value().empty()) {
            result.message = "cancelled bulk publication left partial rows";
            return;
        }
        auto published = publish_packed_generation_atomic(db, publication.value());
        if (!published) {
            result.message = std::string("atomic bulk publication failed: ") +
                             published.error().message;
            return;
        }
        auto visible = read_packed_generation_publication(db, 99);
        if (!visible || !visible.value() ||
            visible.value()->pages.size() != batch.value().pages.size() ||
            visible.value()->index.size() != batch.value().pages.size() ||
            visible.value()->generation.shard_count != domains.size()) {
            result.message = "committed multi-domain publication is incomplete";
            return;
        }
        std::size_t checksum_cancellation_checks = 0;
        auto checksum_cancelled = packed_page_codec_t::verify_page(
            batch.value().pages.front(), [&checksum_cancellation_checks] {
                ++checksum_cancellation_checks;
                return checksum_cancellation_checks > 2;
            });
        if (checksum_cancelled ||
            checksum_cancelled.error().code != workspace_error_code_t::cancelled) {
            result.message = "packed checksum validation ignored cancellation";
            return;
        }
        std::size_t read_cancellation_checks = 0;
        auto read_cancelled = read_packed_pages(
            db, 99, true, [&read_cancellation_checks] {
                ++read_cancellation_checks;
                return read_cancellation_checks > 2;
            });
        if (read_cancelled ||
            read_cancelled.error().code != workspace_error_code_t::cancelled) {
            result.message = "packed page read ignored cancellation";
            return;
        }
        if (write_packed_generation(db, publication.value().generation) ||
            write_packed_page(db, publication.value().pages.front()) ||
            write_packed_page_index(db, publication.value().index.front())) {
            result.message = "committed generation accepted staged-row mutation";
            return;
        }
        auto rollback_committed = rollback_packed_generation(db, 99);
        if (!rollback_committed) {
            result.message = "committed generation rollback probe failed";
            return;
        }
        auto preserved = read_packed_generation_publication(db, 99);
        if (!preserved || !preserved.value()) {
            result.message = "rollback removed an already committed generation";
            return;
        }
        result.passed = true;
        result.message = "bulk cancel rolled back fully and one committed generation became visible";
    };
    result.elapsed_us = measure_us(run);
    if (db)
        sqlite3_close_v2(db);
    cleanup_db(path);
    return result;
}

schema_v9_fixture_result_t run_database_open_queue_path() {
    schema_v9_fixture_result_t result;
    result.name = "database_open_queue_path";
    const auto source_path = temp_db_path("queue_source");
    const std::string source_bytes = "AiDA schema v9 queued publication";
    std::string database_path;
    std::shared_ptr<workspace_database_t> database;

    auto run = [&]() {
        aida::infra::taskflow_runtime::initialize();
        {
            std::ofstream source(source_path, std::ios::binary | std::ios::trunc);
            if (!source) {
                result.message = "failed to create queue source fixture";
                return;
            }
            source.write(source_bytes.data(),
                         static_cast<std::streamsize>(source_bytes.size()));
            if (!source) {
                result.message = "failed to write queue source fixture";
                return;
            }
        }

        auto content_hash = sha256_text("content:" + source_path);
        auto profile_hash = sha256_text("profile:" + source_path);
        if (!content_hash || !profile_hash) {
            result.message = "failed to hash queue workspace identity";
            return;
        }
        workspace_identity_input_t identity_input;
        identity_input.bin_name = "schema-v9-queue.bin";
        identity_input.source_path = source_path;
        identity_input.content_hash = content_hash.take_value();
        identity_input.load_profile_hash = profile_hash.take_value();
        identity_input.target_kind = target_kind_t::static_file;
        identity_input.format = format_id_t::pe32_plus;
        identity_input.architecture = architecture_id_t::x86_64;
        identity_input.architecture_mode = architecture_mode_t::x86_64;
        identity_input.abi = abi_id_t::windows_x64;
        identity_input.endian = endian_t::little;
        identity_input.image_base = 0x140000000ULL;
        auto identity = make_workspace_identity(std::move(identity_input));
        if (!identity) {
            result.message = "failed to create queue workspace identity";
            return;
        }

        const auto workspace_identity = identity.take_value();
        workspace_database_options_t database_options;
        database_options.identity = workspace_identity;
        database_options.versions.engine_version = "schema-v9-harness";
        database_options.versions.specification_version = "schema-v9";
        database_options.versions.analysis_settings_hash = "queue-path-settings";
        database_options.candidate_operation_timeout_ms = 10000;
        auto opened = workspace_database_t::open(std::move(database_options));
        if (!opened) {
            result.message = std::string("workspace database open failed: ") +
                opened.error().message;
            return;
        }
        database = opened.take_value();
        database_path = database->path();
        const auto initial_snapshot = database->snapshot();
        if (!initial_snapshot.open ||
            initial_snapshot.schema_version != workspace_schema_v9_version) {
            result.message = "opened workspace database did not expose schema v9";
            return;
        }

        auto normalized = std::make_shared<workspace_image_t>();
        normalized->format = format_id_t::pe32_plus;
        normalized->architecture = architecture_id_t::x86_64;
        normalized->architecture_mode = architecture_mode_t::x86_64;
        normalized->abi = abi_id_t::windows_x64;
        normalized->endian = endian_t::little;
        normalized->address_width_bits = 64;
        normalized->image_base = 0x140000000ULL;
        normalized->image_size = 16384;
        normalized->format_name = "PE32+";
        normalized->workspace_binary_id = workspace_identity->binary_id();
        normalized->provider_content_hash = workspace_identity->content_hash();
        normalized->provider_source = source_path;
        normalized->provider_size = std::filesystem::file_size(
            std::filesystem::u8path(source_path));
        normalized->provider_binding_verified = true;

        auto snapshot = std::make_shared<analysis_snapshot_t>();
        snapshot->binary_id = workspace_identity->binary_id();
        snapshot->load_profile_hash = workspace_identity->load_profile_hash();
        snapshot->generation = 5001;
        snapshot->analysis_revision = 71;
        snapshot->overlay_revision = 12;
        snapshot->baseline_complete = true;
        snapshot->normalized_image = normalized;
        const address_t instruction_address{address_space_id_t::relative_virtual,
            4096, architecture_id_t::x86_64, architecture_mode_t::x86_64};

        instruction_record_t instruction;
        instruction.id = 0x5001;
        instruction.address = instruction_address;
        instruction.length = 1;
        instruction.flow_flags = flow_call | flow_indirect;
        instruction.coverage = coverage_reason_t::decoded;
        instruction.provenance = fact_provenance_t::recursive_decode;
        instruction.confidence = 95;
        instruction.stable_source_id = 4096;
        snapshot->instructions.push_back(instruction);

        basic_block_record_t block;
        block.id = 0x2001;
        block.function_id = 0x3001;
        block.start = instruction_address;
        block.end = instruction_address;
        block.end.value = 4097;
        block.first_instruction = 0;
        block.instruction_count = 1;
        block.provenance = fact_provenance_t::recursive_decode;
        block.confidence = 95;
        snapshot->blocks.push_back(block);

        function_record_t function;
        function.id = block.function_id;
        function.start = block.start;
        function.end = block.end;
        function.first_block = 0;
        function.block_count = 1;
        function.provenance = fact_provenance_t::recursive_decode;
        function.confidence = 95;
        snapshot->functions.push_back(function);

        call_graph_node_record_t node;
        node.function_id = function.id;
        node.address = function.start;
        node.outgoing_edges = 1;
        node.indirect_edges = 1;
        node.unresolved_sites = 1;
        snapshot->call_graph.nodes.push_back(node);

        recovered_call_site_t call_site;
        call_site.id = 1080863910568919041ULL;
        call_site.source_function_id = function.id;
        call_site.source_block_id = block.id;
        call_site.instruction_id = instruction.id;
        call_site.address = instruction.address;
        call_site.indirect = true;
        call_site.unresolved = true;
        snapshot->call_graph.call_sites.push_back(call_site);

        call_graph_edge_record_t call_edge;
        call_edge.id = 1224979098644774913ULL;
        call_edge.call_site_id = call_site.id;
        call_edge.source_function_id = function.id;
        call_edge.source_block_id = block.id;
        call_edge.call_site = call_site.address;
        call_edge.target = instruction.address;
        call_edge.target.value = 0;
        call_edge.resolution = call_graph_resolution_t::unresolved;
        call_edge.quality.provenance = fact_provenance_t::recursive_decode;
        call_edge.quality.confidence = 80;
        call_edge.quality.contributor_count = 1;
        snapshot->call_graph.edges.push_back(call_edge);
        snapshot->call_graph.indirect_site_count = 1;
        snapshot->call_graph.unresolved_site_count = 1;
        snapshot->call_graph.bounded = true;

        data_candidate_record_t data_candidate;
        data_candidate.id = 576460752303423489ULL;
        data_candidate.address = instruction.address;
        data_candidate.address.value = 4352;
        data_candidate.size = 8;
        data_candidate.kind = data_candidate_kind_t::in_image_pointer;
        data_candidate.target = instruction.address;
        data_candidate.target->value = 4608;
        data_candidate.provenance = fact_provenance_t::relocation;
        data_candidate.confidence = 92;
        snapshot->rich_facts.data_candidates.push_back(data_candidate);

        data_pointer_fact_t pointer;
        pointer.id = 864691128455135233ULL;
        pointer.slot = instruction.address;
        pointer.slot.value = 4368;
        pointer.target = instruction.address;
        pointer.target.value = 4608;
        pointer.candidate_kind = data_candidate_kind_t::in_image_pointer;
        pointer.encoding = data_pointer_encoding_t::absolute_virtual;
        pointer.width_bytes = 8;
        pointer.provenance = fact_provenance_t::relocation;
        pointer.confidence = 93;
        snapshot->rich_facts.data_pointer_facts.push_back(pointer);

        data_candidate_conflict_t data_conflict;
        data_conflict.id = 936748722493063169ULL;
        data_conflict.address = pointer.slot;
        data_conflict.kind = data_candidate_kind_t::in_image_pointer;
        data_conflict.selected_target = instruction.address;
        data_conflict.selected_target->value = 4624;
        data_conflict.rejected_target = instruction.address;
        data_conflict.rejected_target->value = 4640;
        data_conflict.selected_provenance = fact_provenance_t::relocation;
        data_conflict.rejected_provenance = fact_provenance_t::linear_validation;
        data_conflict.selected_confidence = 90;
        data_conflict.rejected_confidence = 70;
        snapshot->rich_facts.data_conflicts.push_back(data_conflict);

        symbol_type_candidate_record_t type_candidate;
        type_candidate.id = 720575940379279361ULL;
        type_candidate.address = instruction.address;
        type_candidate.kind = symbol_type_candidate_kind_t::function_prototype;
        type_candidate.display_name = "queued_type";
        type_candidate.canonical_type = "void()";
        type_candidate.source_key = "schema-v9-harness:type";
        type_candidate.provenance = metadata_provenance_t::debug_metadata;
        type_candidate.confidence = 94;
        type_candidate.explicitly_unknown = false;
        snapshot->rich_facts.type_candidates.push_back(type_candidate);

        type_reference_fact_t type_reference;
        type_reference.id = 648518346341351425ULL;
        type_reference.source = instruction.address;
        type_reference.target = data_candidate.address;
        type_reference.source_entity = type_candidate.id;
        type_reference.kind = type_reference_kind_t::metadata_reference;
        type_reference.provenance = metadata_provenance_t::debug_metadata;
        type_reference.confidence = 89;
        type_reference.source_key = "schema-v9-harness:reference";
        snapshot->rich_facts.type_references.push_back(type_reference);

        metadata_conflict_record_t metadata_conflict;
        metadata_conflict.id = 1008806316530991105ULL;
        metadata_conflict.address = instruction.address;
        metadata_conflict.identity = "queued_type";
        metadata_conflict.kind = metadata_conflict_kind_t::canonical_type;
        metadata_conflict.selected_value = "void()";
        metadata_conflict.rejected_value = "int()";
        metadata_conflict.selected_provenance = metadata_provenance_t::debug_metadata;
        metadata_conflict.rejected_provenance = metadata_provenance_t::decoded;
        metadata_conflict.selected_confidence = 94;
        metadata_conflict.rejected_confidence = 60;
        snapshot->rich_facts.metadata_conflicts.push_back(metadata_conflict);

        persisted_search_products_t search_products;
        search_products.generation = snapshot->generation;
        search_products.analysis_revision = snapshot->analysis_revision;
        search_products.overlay_revision = snapshot->overlay_revision;
        auto search_index = search_index_t::build(
            std::shared_ptr<const analysis_snapshot_t>(snapshot),
            std::vector<data_candidate_record_t>{data_candidate}, {}, {},
            std::make_shared<analysis_metrics_t>(snapshot->generation), {}, {});
        if (!search_index) {
            result.message = std::string("failed to build packed search fixture: ") +
                search_index.error().message;
            return;
        }
        search_products.live_index = search_index.take_value();

        auto snapshot_ticket = database->persist_snapshot(
            snapshot, std::move(search_products), "{}", "{}");
        if (!snapshot_ticket.accepted || !snapshot_ticket.completion.valid() ||
            !snapshot_ticket.snapshot_candidate) {
            result.message = "workspace queue rejected rich snapshot persistence";
            return;
        }
        if (snapshot_ticket.completion.wait_for(std::chrono::seconds(10)) !=
            std::future_status::ready) {
            result.message = "queued rich snapshot persistence did not complete";
            return;
        }
        try {
            const auto& completion = snapshot_ticket.completion.get();
            if (!completion) {
                result.message = std::string("queued rich snapshot failed: ") +
                    completion.error().message;
                return;
            }
        } catch (const std::exception& exception) {
            result.message = std::string("queued rich snapshot future failed: ") +
                exception.what();
            return;
        }
        if (!snapshot_ticket.snapshot_candidate->packed_generation_required()) {
            result.message = "packed baseline did not bind to the snapshot candidate";
            return;
        }
        auto hidden_snapshot = database->load_snapshot(normalized, {});
        if (!hidden_snapshot || hidden_snapshot.value()) {
            result.message = "unpromoted packed baseline became visible";
            return;
        }
        auto finalized = snapshot_ticket.snapshot_candidate->finalize();
        if (!finalized) {
            result.message = std::string("rich snapshot promotion failed: ") +
                finalized.error().message;
            return;
        }
        auto reopened_snapshot = database->load_snapshot(normalized, {});
        if (!reopened_snapshot || !reopened_snapshot.value() ||
            reopened_snapshot.value()->call_graph.nodes.size() != 1 ||
            reopened_snapshot.value()->call_graph.call_sites.size() != 1 ||
            reopened_snapshot.value()->call_graph.edges.size() != 1 ||
            reopened_snapshot.value()->call_graph.unresolved_site_count != 1 ||
            reopened_snapshot.value()->rich_facts.data_candidates.size() != 1 ||
            reopened_snapshot.value()->rich_facts.data_pointer_facts.size() != 1 ||
            reopened_snapshot.value()->rich_facts.data_conflicts.size() != 1 ||
            reopened_snapshot.value()->rich_facts.type_candidates.size() != 1 ||
            reopened_snapshot.value()->rich_facts.type_references.size() != 1 ||
            reopened_snapshot.value()->rich_facts.metadata_conflicts.size() != 1 ||
            reopened_snapshot.value()->rich_facts.type_candidates.front().source_key !=
                type_candidate.source_key) {
            result.message = "production snapshot reopen lost call-graph or rich facts";
            return;
        }
        auto reopened_search = database->load_search_products(
            snapshot->generation, snapshot->analysis_revision,
            snapshot->overlay_revision);
        if (!reopened_search || reopened_search.value().data_candidates.size() != 1 ||
            reopened_search.value().data_candidates.front().id != data_candidate.id ||
            reopened_search.value().search_index_blob_version !=
                search_index_t::serialized_version ||
            reopened_search.value().search_index_blob.empty()) {
            result.message = "packed search-product reopen lost candidate data";
            return;
        }
        auto restored_search = restore_persisted_search_index(
            reopened_snapshot.value(), reopened_search.take_value(),
            std::make_shared<analysis_metrics_t>(snapshot->generation));
        if (!restored_search ||
            !restored_search.value()->matches(reopened_snapshot.value()) ||
            restored_search.value()->data_candidates().size() != 1 ||
            restored_search.value()->data_candidates().front().id !=
                data_candidate.id) {
            result.message = "packed warm reopen did not restore the persisted search index";
            return;
        }

        std::ifstream source_after(source_path, std::ios::binary);
        const std::string observed_source(
            std::istreambuf_iterator<char>(source_after),
            std::istreambuf_iterator<char>());
        if (!source_after.is_open() || observed_source != source_bytes) {
            result.message = "packed persistence modified its source fixture";
            return;
        }

        database->request_cancel();
        auto closed_read = database->load_snapshot(normalized, {});
        if (closed_read ||
            closed_read.error().code != workspace_error_code_t::workspace_closing) {
            result.message = "closed database accepted a new packed snapshot read";
            return;
        }
        auto drained = database->drain(
            std::chrono::steady_clock::now() + std::chrono::seconds(10));
        if (!drained) {
            result.message = "workspace database did not drain before invalidation reopen";
            return;
        }
        database.reset();
        workspace_database_options_t reopened_options;
        reopened_options.identity = workspace_identity;
        reopened_options.versions.engine_version = "schema-v9-harness-updated";
        reopened_options.versions.specification_version = "schema-v9";
        reopened_options.versions.analysis_settings_hash = "queue-path-settings";
        reopened_options.candidate_operation_timeout_ms = 10000;
        auto reopened_database = workspace_database_t::open(
            std::move(reopened_options));
        if (!reopened_database) {
            result.message = "workspace invalidation reopen failed";
            return;
        }
        database = reopened_database.take_value();
        auto invalidated_snapshot = database->load_snapshot(normalized, {});
        if (!invalidated_snapshot || invalidated_snapshot.value()) {
            result.message = "derived-data invalidation retained a packed generation";
            return;
        }
        result.passed = true;
        result.message = "candidate-bound packed persistence, warm reopen, close gate, and invalidation passed";
    };

    result.elapsed_us = measure_us(run);
    if (database) {
        database->request_cancel();
        static_cast<void>(database->drain(
            std::chrono::steady_clock::now() + std::chrono::seconds(10)));
        database.reset();
    }
    if (!database_path.empty())
        cleanup_db(database_path);
    cleanup_db(source_path);
    return result;
}

schema_v9_fixture_result_t run_baseline_persistence_entry_path() {
    schema_v9_fixture_result_t result;
    result.name = "baseline_persistence_entry_path";
    const auto started = std::chrono::steady_clock::now();
    using namespace test_fixture;
    fixture_root_t root("c03_baseline_persistence");
    std::shared_ptr<analysis_workspace_t> workspace;
    std::string database_path;
    try {
        const auto source_path = write_bytes_fixture(
            root.path() / "baseline" / "persisted.exe", minimal_pe64(0xC5));
        workspace = open_workspace(source_path, "persisted.exe");
        install_services(workspace);
        analyze_workspace(workspace, 2);
        const auto published = workspace->snapshot();
        const auto normalized = workspace->normalized_image();
        const auto image = workspace->image();
        const auto database = workspace->database();
        if (!published || !published->baseline_complete || !normalized || !database) {
            throw fixture_error_t(
                "production baseline service did not publish a complete persisted generation");
        }
        database_path = database->path();
        const auto expected_binary = published->binary_id;
        const auto expected_profile = published->load_profile_hash;
        const auto expected_generation = published->generation;
        const auto expected_analysis_revision = published->analysis_revision;
        const auto expected_overlay_revision = published->overlay_revision;
        auto loaded = database->load_snapshot(normalized, image,
            workspace->cancellation_token());
        if (!loaded || !loaded.value() || !loaded.value()->baseline_complete ||
            loaded.value()->binary_id != expected_binary ||
            loaded.value()->load_profile_hash != expected_profile ||
            loaded.value()->generation != expected_generation ||
            loaded.value()->analysis_revision != expected_analysis_revision ||
            loaded.value()->overlay_revision != expected_overlay_revision) {
            throw fixture_error_t(loaded
                ? "production baseline persistence did not reopen its exact generation"
                : loaded.error().stable_code() + ":" + loaded.error().message);
        }
        auto products = database->load_search_products(expected_generation,
            expected_analysis_revision, expected_overlay_revision,
            workspace->cancellation_token());
        if (!products || products.value().search_index_blob_version !=
                search_index_t::serialized_version ||
            products.value().search_index_blob.empty()) {
            throw fixture_error_t(products
                ? "production baseline persistence omitted its packed search index"
                : products.error().stable_code() + ":" + products.error().message);
        }
        auto restored = restore_persisted_search_index(
            loaded.value(), products.take_value(),
            std::make_shared<analysis_metrics_t>(expected_generation), {},
            workspace->cancellation_token());
        if (!restored || !restored.value()->matches(loaded.value())) {
            throw fixture_error_t(restored
                ? "production baseline search generation identity diverged after restore"
                : restored.error().stable_code() + ":" + restored.error().message);
        }

        close_workspace(workspace);
        workspace.reset();
        workspace = open_workspace(source_path, "persisted.exe");
        install_services(workspace);
        const auto cold_snapshot = workspace->snapshot();
        if (!workspace->database() || workspace->database()->path() != database_path ||
            !cold_snapshot || cold_snapshot->baseline_complete ||
            cold_snapshot->analysis_revision != 0) {
            throw fixture_error_t(
                "reopened workspace did not bind the original durable generation store");
        }
        auto warm_snapshot = workspace->database()->load_snapshot(
            workspace->normalized_image(), workspace->image(),
            workspace->cancellation_token());
        if (!warm_snapshot || !warm_snapshot.value() ||
            warm_snapshot.value()->generation != expected_generation ||
            warm_snapshot.value()->binary_id != expected_binary ||
            warm_snapshot.value()->load_profile_hash != expected_profile) {
            throw fixture_error_t(warm_snapshot
                ? "warm workspace reopen did not recover the exact packed generation"
                : warm_snapshot.error().stable_code() + ":" +
                    warm_snapshot.error().message);
        }
        auto warm_products = workspace->database()->load_search_products(
            expected_generation, expected_analysis_revision,
            expected_overlay_revision, workspace->cancellation_token());
        if (!warm_products) {
            throw fixture_error_t(warm_products.error().stable_code() + ":" +
                warm_products.error().message);
        }
        auto warm_index = restore_persisted_search_index(
            warm_snapshot.value(), warm_products.take_value(),
            std::make_shared<analysis_metrics_t>(expected_generation), {},
            workspace->cancellation_token());
        if (!warm_index || !warm_index.value()->matches(warm_snapshot.value())) {
            throw fixture_error_t(warm_index
                ? "warm packed search generation identity diverged"
                : warm_index.error().stable_code() + ":" + warm_index.error().message);
        }
        close_workspace(workspace, true);
        workspace.reset();
        database_path.clear();
        result.passed = true;
        result.message =
            "production baseline entry persisted and warm-restored one packed generation";
    } catch (const std::exception& error) {
        result.message = error.what();
        if (workspace && !workspace->closed()) {
            try {
                close_workspace(workspace);
            } catch (...) {
            }
        }
        if (!database_path.empty()) {
            try {
                remove_database_artifacts(database_path);
            } catch (...) {
            }
        }
    }
    result.elapsed_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count());
    return result;
}

schema_v9_harness_summary_t run_all_schema_v9_fixtures() {
    schema_v9_harness_summary_t summary;
    std::vector<schema_v9_fixture_result_t> results;
    results.push_back(run_golden_v8_migration());
    results.push_back(run_partial_v9_repair());
    results.push_back(run_interrupted_commit());
    results.push_back(run_corruption_detection());
    results.push_back(run_rollback_after_failed_migration());
    results.push_back(run_fixed_width_address());
    results.push_back(run_concurrent_reader());
    results.push_back(run_cache_key_round_trip());
    results.push_back(run_workbench_round_trip());
    results.push_back(run_generation_atomicity());
    results.push_back(run_database_open_queue_path());
    results.push_back(run_baseline_persistence_entry_path());
    results.push_back(run_managed_publication_persistence());
    summary.total = results.size();
    for (const auto& r : results) {
		c03_test::assertion_telemetry::record_assertion(r.passed,
			r.passed ? std::string_view(r.name) : std::string_view(r.message),
			__FILE__, __LINE__);
        if (r.passed)
            ++summary.passed;
        else
            ++summary.failed;
    }
    summary.results = std::move(results);
    return summary;
}

}
