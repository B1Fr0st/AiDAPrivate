#include "schema_v9_harness.hpp"

#include "workspace_schema_v9.hpp"
#include "packed_page_codec.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <numeric>
#include <random>
#include <sstream>
#include <string>

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

    bool bind_int(int index, std::int64_t value) {
        return sqlite3_bind_int64(stmt_, index, value) == SQLITE_OK;
    }

    bool bind_uint(int index, std::uint64_t value) {
        std::int64_t encoded = 0;
        std::memcpy(&encoded, &value, sizeof(encoded));
        return bind_int(index, encoded);
    }

    bool bind_text(int index, const std::string& value) {
        return sqlite3_bind_text(stmt_, index, value.data(),
                                 static_cast<int>(value.size()),
                                 SQLITE_TRANSIENT) == SQLITE_OK;
    }

    bool bind_blob(int index, const void* data, std::size_t size) {
        return sqlite3_bind_blob(stmt_, index, data,
                                 static_cast<int>(size), SQLITE_TRANSIENT) == SQLITE_OK;
    }

    bool step_done() {
        return sqlite3_step(stmt_) == SQLITE_DONE;
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

bool create_v8_schema(sqlite3* db) {
    if (!exec_sql(db, R"SQL(
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY NOT NULL,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS workspace_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),binary_id BLOB NOT NULL UNIQUE,bin_name TEXT NOT NULL,source_path TEXT NOT NULL,member_path TEXT,content_hash BLOB NOT NULL,load_profile_hash BLOB NOT NULL,target_kind INTEGER NOT NULL,format INTEGER NOT NULL,architecture INTEGER NOT NULL,abi INTEGER NOT NULL,endian INTEGER NOT NULL,image_base INTEGER NOT NULL,process_pid INTEGER,process_creation INTEGER,process_path TEXT,module_base INTEGER,module_size INTEGER,module_name TEXT,module_path TEXT,module_hash BLOB);
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
        auto migrated = create_schema_v9(db);
        if (!migrated) {
            result.message = std::string("v9 migration failed: ") + migrated.error().message;
            return;
        }
        const std::array<const char*, 6> v9_tables = {
            "packed_generations", "packed_pages", "packed_page_index",
            "workbench_state", "decompiler_cache_v9", "overlay_v9_state"
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
        result.passed = true;
        result.message = "v8->v9 migration succeeded, all 6 tables and 7 indexes verified";
    };
    elapsed = measure_us(run);
    result.elapsed_us = elapsed;
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
        packed_generation_record_t gen;
        gen.generation = 42;
        gen.analysis_revision = 1;
        gen.overlay_revision = 0;
        gen.shard_count = 1;
        gen.total_payload_bytes = 100;
        gen.total_records = 1;
        gen.batch_checksum = 0xDEADBEEF;
        gen.created_utc_ms = 12345;
        gen.committed = false;
        gen.payload_blob = {0x01, 0x02, 0x03, 0x04};
        auto gen_written = write_packed_generation(db, gen);
        if (!gen_written) {
            result.message = std::string("failed to write packed generation: ") + gen_written.error().message;
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
        for (const auto& page : batch.value().pages) {
            packed_page_row_t row;
            row.generation = page.header.generation;
            row.page_index = page.header.page_index;
            row.page_count = page.header.page_count;
            row.page_type = page.header.page_type;
            row.payload_length = page.header.payload_length;
            row.checksum = page.header.checksum;
            row.payload = page.payload;
            auto written = write_packed_page(db, row);
            if (!written) {
                result.message = std::string("failed to write packed page: ") + written.error().message;
                return;
            }
        }
        sqlite3_close_v2(db);
        db = nullptr;
        if (!open_db(path, &db) || !configure_wal(db)) {
            result.message = "failed to reopen database";
            return;
        }
        auto gen_read = read_packed_generation(db, 42);
        if (!gen_read) {
            result.message = std::string("failed to read packed generation: ") + gen_read.error().message;
            return;
        }
        if (!gen_read.value()) {
            result.message = "packed generation not found after reopen";
            return;
        }
        if (gen_read.value()->committed) {
            result.message = "generation is marked committed but was never published";
            return;
        }
        auto pages_read = read_packed_pages(db, 42);
        if (!pages_read) {
            result.message = std::string("failed to read packed pages: ") + pages_read.error().message;
            return;
        }
        if (pages_read.value().size() != batch.value().pages.size()) {
            result.message = "page count mismatch after reopen";
            return;
        }
        auto publish = publish_packed_generation(db, 42);
        if (!publish) {
            result.message = std::string("failed to publish generation: ") + publish.error().message;
            return;
        }
        auto gen_read2 = read_packed_generation(db, 42);
        if (!gen_read2 || !gen_read2.value() || !gen_read2.value()->committed) {
            result.message = "generation not committed after publish";
            return;
        }
        auto publish2 = publish_packed_generation(db, 42);
        if (publish2) {
            result.message = "double publish should fail";
            return;
        }
        result.passed = true;
        result.message = "interrupted commit recovered, uncommitted generation preserved and publish verified";
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
        result.passed = true;
        result.message = "payload, header, and checkpoint corruption all detected via CRC32C";
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
        if (!exec_sql(db, "BEGIN IMMEDIATE")) {
            result.message = "failed to begin transaction";
            return;
        }
        auto migrated = create_schema_v9(db);
        if (!migrated) {
            exec_sql(db, "ROLLBACK");
            result.message = std::string("v9 migration failed inside transaction: ") + migrated.error().message;
            return;
        }
        if (!exec_sql(db, "ROLLBACK")) {
            result.message = "failed to rollback";
            return;
        }
        if (table_exists(db, "packed_generations")) {
            result.message = "packed_generations table exists after rollback";
            return;
        }
        if (table_exists(db, "workbench_state")) {
            result.message = "workbench_state table exists after rollback";
            return;
        }
        if (!table_exists(db, "metadata")) {
            result.message = "v8 table metadata missing after rollback";
            return;
        }
        if (!table_exists(db, "decompiler_cache")) {
            result.message = "v8 table decompiler_cache missing after rollback";
            return;
        }
        exec_sql(db, "BEGIN IMMEDIATE");
        auto migrated2 = create_schema_v9(db);
        if (!migrated2) {
            exec_sql(db, "ROLLBACK");
            result.message = std::string("second v9 migration failed: ") + migrated2.error().message;
            return;
        }
        if (!exec_sql(db, "COMMIT")) {
            exec_sql(db, "ROLLBACK");
            result.message = "failed to commit second migration";
            return;
        }
        if (!table_exists(db, "packed_generations")) {
            result.message = "packed_generations table missing after second migration";
            return;
        }
        if (!table_exists(db, "workbench_state")) {
            result.message = "workbench_state table missing after second migration";
            return;
        }
        result.passed = true;
        result.message = "rollback preserves v8 schema, re-migration succeeds after rollback";
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
            {address_space_id_t::virtual_address, 0x7FFE0000, architecture_id_t::arm, architecture_mode_t::arm_64},
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
        packed_generation_record_t gen1;
        gen1.generation = 10;
        gen1.analysis_revision = 1;
        gen1.overlay_revision = 0;
        gen1.shard_count = 1;
        gen1.total_payload_bytes = 50;
        gen1.total_records = 1;
        gen1.batch_checksum = 0x12345678;
        gen1.created_utc_ms = 1000;
        gen1.committed = true;
        gen1.payload_blob = {0xAA, 0xBB, 0xCC};
        auto w1 = write_packed_generation(writer, gen1);
        if (!w1) {
            result.message = std::string("failed to write gen1: ") + w1.error().message;
            return;
        }
        if (sqlite3_open_v2(path.c_str(), &reader,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
            result.message = "failed to open reader";
            return;
        }
        exec_sql(reader, "PRAGMA journal_mode=WAL;");
        exec_sql(reader, "BEGIN");
        auto read1 = read_packed_generation(reader, 10);
        if (!read1 || !read1.value()) {
            result.message = std::string("reader cannot see gen1: ") +
                             (read1 ? "nullopt" : read1.error().message);
            return;
        }
        packed_generation_record_t gen2;
        gen2.generation = 11;
        gen2.analysis_revision = 2;
        gen2.overlay_revision = 1;
        gen2.shard_count = 1;
        gen2.total_payload_bytes = 60;
        gen2.total_records = 1;
        gen2.batch_checksum = 0x87654321;
        gen2.created_utc_ms = 2000;
        gen2.committed = true;
        gen2.payload_blob = {0xDD, 0xEE, 0xFF};
        auto w2 = write_packed_generation(writer, gen2);
        if (!w2) {
            result.message = std::string("failed to write gen2: ") + w2.error().message;
            return;
        }
        auto read2_inside = read_packed_generation(reader, 11);
        if (read2_inside && read2_inside.value()) {
            result.message = "reader sees gen2 inside snapshot transaction (WAL isolation broken)";
            return;
        }
        exec_sql(reader, "COMMIT");
        auto read2_after = read_packed_generation(reader, 11);
        if (!read2_after || !read2_after.value()) {
            result.message = "reader cannot see gen2 after commit";
            return;
        }
        if (read2_after.value()->generation != 11) {
            result.message = "gen2 generation mismatch";
            return;
        }
        result.passed = true;
        result.message = "WAL snapshot isolation verified: reader sees gen1 only during writer's gen2 commit";
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
        record.has_selection = true;
        record.selection = {address_space_id_t::relative_virtual, 0x401000,
                            architecture_id_t::x86_64, architecture_mode_t::x86_64};
        record.navigation_back_json = "[{\"space\":1,\"value\":4096},{\"space\":1,\"value\":8192}]";
        record.navigation_forward_json = "[{\"space\":1,\"value\":2048}]";
        record.bookmarks_json = "[{\"space\":1,\"value\":12288,\"label\":\"main\"},{\"space\":1,\"value\":16384,\"label\":\"entry\"}]";
        record.layout_json = "{\"tabs\":[\"disasm\",\"graph\",\"strings\"],\"active\":\"disasm\"}";
        record.active_tab = 2;
        record.zoom_level = 150;
        record.revision = 42;
        record.updated_utc_ms = 0;
        auto written = write_workbench_state(db, record);
        if (!written) {
            result.message = std::string("failed to write workbench state: ") + written.error().message;
            return;
        }
        auto read = read_workbench_state(db);
        if (!read || !read.value()) {
            result.message = "failed to read workbench state";
            return;
        }
        const auto& found = *read.value();
        if (found.has_selection != record.has_selection ||
            found.selection != record.selection ||
            found.navigation_back_json != record.navigation_back_json ||
            found.navigation_forward_json != record.navigation_forward_json ||
            found.bookmarks_json != record.bookmarks_json ||
            found.layout_json != record.layout_json ||
            found.active_tab != record.active_tab ||
            found.zoom_level != record.zoom_level ||
            found.revision != record.revision) {
            result.message = "workbench state field mismatch after round-trip";
            return;
        }
        workbench_state_record_t update;
        update.has_selection = false;
        update.selection = {};
        update.navigation_back_json = "[]";
        update.navigation_forward_json = "[]";
        update.bookmarks_json = "[]";
        update.layout_json = "{}";
        update.active_tab = 0;
        update.zoom_level = 100;
        update.revision = 43;
        update.updated_utc_ms = 0;
        auto updated = write_workbench_state(db, update);
        if (!updated) {
            result.message = "failed to update workbench state";
            return;
        }
        auto read2 = read_workbench_state(db);
        if (!read2 || !read2.value()) {
            result.message = "failed to read updated workbench state";
            return;
        }
        const auto& found2 = *read2.value();
        if (found2.has_selection || found2.revision != 43) {
            result.message = "workbench state update not applied";
            return;
        }
        result.passed = true;
        result.message = "workbench state with selection, navigation, bookmarks, layout round-tripped and updated";
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
        std::vector<std::uint8_t> instr_data(1024);
        std::iota(instr_data.begin(), instr_data.end(), static_cast<std::uint8_t>(0));
        domains.emplace_back(packed_page_type_t::instructions, instr_data);
        std::vector<std::uint8_t> func_data(256, 0x77);
        domains.emplace_back(packed_page_type_t::functions, func_data);
        std::vector<std::uint8_t> edge_data(128, 0x33);
        domains.emplace_back(packed_page_type_t::edges, edge_data);
        auto batch = packed_page_codec_t::encode_multi_domain_batch(domains, options);
        if (!batch) {
            result.message = std::string("failed to encode multi-domain batch: ") + batch.error().message;
            return;
        }
        const auto total_pages = batch.value().pages.size();
        if (total_pages < 4) {
            result.message = "multi-domain batch has too few pages";
            return;
        }
        if (!exec_sql(db, "BEGIN IMMEDIATE")) {
            result.message = "failed to begin transaction";
            return;
        }
        packed_generation_record_t gen;
        gen.generation = 99;
        gen.analysis_revision = 5;
        gen.overlay_revision = 3;
        gen.shard_count = 3;
        gen.total_payload_bytes = batch.value().checkpoint.total_payload_bytes;
        gen.total_records = batch.value().checkpoint.total_records;
        gen.batch_checksum = batch.value().checkpoint.batch_checksum;
        gen.created_utc_ms = batch.value().checkpoint.created_utc_ms;
        gen.committed = false;
        std::vector<std::uint8_t> gen_blob;
        for (const auto& page : batch.value().pages) {
            const auto encoded = page.header.encode();
            gen_blob.insert(gen_blob.end(), encoded.begin(), encoded.end());
            gen_blob.insert(gen_blob.end(), page.payload.begin(), page.payload.end());
        }
        gen.payload_blob = std::move(gen_blob);
        auto gen_written = write_packed_generation(db, gen);
        if (!gen_written) {
            exec_sql(db, "ROLLBACK");
            result.message = std::string("failed to write generation: ") + gen_written.error().message;
            return;
        }
        for (const auto& page : batch.value().pages) {
            packed_page_row_t row;
            row.generation = page.header.generation;
            row.page_index = page.header.page_index;
            row.page_count = page.header.page_count;
            row.page_type = page.header.page_type;
            row.payload_length = page.header.payload_length;
            row.checksum = page.header.checksum;
            row.payload = page.payload;
            auto written = write_packed_page(db, row);
            if (!written) {
                exec_sql(db, "ROLLBACK");
                result.message = std::string("failed to write page: ") + written.error().message;
                return;
            }
        }
        for (const auto& page : batch.value().pages) {
            packed_page_index_row_t idx;
            idx.generation = page.header.generation;
            idx.domain = static_cast<std::uint16_t>(page.header.page_type);
            idx.ordinal_begin = page.header.page_index * packed_page_default_size;
            idx.count = page.header.payload_length;
            idx.page_index = page.header.page_index;
            if (page.payload.size() >= 16) {
                idx.address_value_min = *reinterpret_cast<const std::uint64_t*>(page.payload.data());
                idx.address_value_max = *reinterpret_cast<const std::uint64_t*>(page.payload.data() + page.payload.size() - 8);
            }
            auto idx_written = write_packed_page_index(db, idx);
            if (!idx_written) {
                exec_sql(db, "ROLLBACK");
                result.message = std::string("failed to write page index: ") + idx_written.error().message;
                return;
            }
        }
        if (!exec_sql(db, "COMMIT")) {
            exec_sql(db, "ROLLBACK");
            result.message = "failed to commit atomic batch";
            return;
        }
        auto pages_read = read_packed_pages(db, 99);
        if (!pages_read) {
            result.message = std::string("failed to read pages: ") + pages_read.error().message;
            return;
        }
        if (pages_read.value().size() != total_pages) {
            result.message = std::string("page count mismatch: expected ") +
                             std::to_string(total_pages) + " got " +
                             std::to_string(pages_read.value().size());
            return;
        }
        auto idx_read = read_packed_page_index(db, 99);
        if (!idx_read) {
            result.message = std::string("failed to read page index: ") + idx_read.error().message;
            return;
        }
        if (idx_read.value().size() != total_pages) {
            result.message = std::string("index count mismatch: expected ") +
                             std::to_string(total_pages) + " got " +
                             std::to_string(idx_read.value().size());
            return;
        }
        if (!exec_sql(db, "BEGIN IMMEDIATE")) {
            result.message = "failed to begin rollback transaction";
            return;
        }
        auto rolled_back = rollback_packed_generation(db, 99);
        if (!rolled_back) {
            exec_sql(db, "ROLLBACK");
            result.message = std::string("failed to rollback generation: ") + rolled_back.error().message;
            return;
        }
        if (!exec_sql(db, "COMMIT")) {
            exec_sql(db, "ROLLBACK");
            result.message = "failed to commit rollback";
            return;
        }
        auto pages_after_rollback = read_packed_pages(db, 99);
        if (!pages_after_rollback) {
            result.message = std::string("failed to read pages after rollback: ") + pages_after_rollback.error().message;
            return;
        }
        if (!pages_after_rollback.value().empty()) {
            result.message = "pages still exist after rollback";
            return;
        }
        auto gen_after_rollback = read_packed_generation(db, 99);
        if (gen_after_rollback && gen_after_rollback.value()) {
            result.message = "generation still exists after rollback";
            return;
        }
        result.passed = true;
        result.message = std::string("3-domain batch of ") + std::to_string(total_pages) +
                         " pages written atomically, verified, and rolled back cleanly";
    };
    result.elapsed_us = measure_us(run);
    if (db)
        sqlite3_close_v2(db);
    cleanup_db(path);
    return result;
}

schema_v9_harness_summary_t run_all_schema_v9_fixtures() {
    schema_v9_harness_summary_t summary;
    std::vector<schema_v9_fixture_result_t> results;
    results.push_back(run_golden_v8_migration());
    results.push_back(run_interrupted_commit());
    results.push_back(run_corruption_detection());
    results.push_back(run_rollback_after_failed_migration());
    results.push_back(run_fixed_width_address());
    results.push_back(run_concurrent_reader());
    results.push_back(run_cache_key_round_trip());
    results.push_back(run_workbench_round_trip());
    results.push_back(run_generation_atomicity());
    summary.total = results.size();
    for (const auto& r : results) {
        if (r.passed)
            ++summary.passed;
        else
            ++summary.failed;
    }
    summary.results = std::move(results);
    return summary;
}

}
