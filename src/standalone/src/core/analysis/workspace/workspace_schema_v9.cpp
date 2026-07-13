#include "workspace_schema_v9.hpp"

#include "checked_range.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <sstream>

#include <nlohmann/json.hpp>

namespace aida::analysis {

namespace {

workspace_error_t schema_v9_error(sqlite3* database, int status,
                                   std::string message, const char* phase) {
    auto error = make_workspace_error(workspace_error_code_t::persistence_failure,
                                       std::move(message), phase);
    error.sqlite_status = status;
    if (database) {
        error.details.emplace_back("sqlite_primary_status",
                                    std::to_string(sqlite3_errcode(database)));
        error.details.emplace_back("sqlite_extended_status",
                                    std::to_string(sqlite3_extended_errcode(database)));
        const char* detail = sqlite3_errmsg(database);
        if (detail && *detail)
            error.details.emplace_back("sqlite_message", detail);
    }
    return error;
}

workspace_result_t<void> exec_sql_v9(sqlite3* database, const char* sql,
                                      const char* phase) {
    char* detail = nullptr;
    const int status = sqlite3_exec(database, sql, nullptr, nullptr, &detail);
    if (status == SQLITE_OK) {
        sqlite3_free(detail);
        return workspace_result_t<void>::success();
    }
    std::string message = "SQLite v9 statement failed";
    if (detail && *detail)
        message += std::string(": ") + detail;
    sqlite3_free(detail);
    return workspace_result_t<void>::failure(
        schema_v9_error(database, status, std::move(message), phase));
}

class v9_statement_t final {
public:
    v9_statement_t() = default;
    ~v9_statement_t() {
        if (statement_)
            sqlite3_finalize(statement_);
    }
    v9_statement_t(const v9_statement_t&) = delete;
    v9_statement_t& operator=(const v9_statement_t&) = delete;

    workspace_result_t<void> prepare(sqlite3* database, const char* sql,
                                     const char* phase) {
        if (statement_) {
            sqlite3_finalize(statement_);
            statement_ = nullptr;
        }
        const int status = sqlite3_prepare_v3(database, sql, -1,
                                              SQLITE_PREPARE_PERSISTENT,
                                              &statement_, nullptr);
        if (status != SQLITE_OK) {
            return workspace_result_t<void>::failure(
                schema_v9_error(database, status,
                                "failed to prepare v9 SQLite statement", phase));
        }
        database_ = database;
        phase_ = phase;
        return workspace_result_t<void>::success();
    }

    sqlite3_stmt* get() const noexcept { return statement_; }

    workspace_result_t<void> bind_int(int index, std::int64_t value) {
        const int status = sqlite3_bind_int64(statement_, index, value);
        if (status != SQLITE_OK)
            return workspace_result_t<void>::failure(
                schema_v9_error(database_, status, "v9 bind_int failed", phase_));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> bind_uint(int index, std::uint64_t value) {
        std::int64_t encoded = 0;
        static_assert(sizeof(encoded) == sizeof(value));
        std::memcpy(&encoded, &value, sizeof(encoded));
        return bind_int(index, encoded);
    }

    workspace_result_t<void> bind_text(int index, const std::string& value) {
        if (value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
            return workspace_result_t<void>::failure(
                schema_v9_error(database_, SQLITE_TOOBIG,
                                "v9 text value exceeds SQLite limit", phase_));
        }
        const int status = sqlite3_bind_text(statement_, index, value.data(),
                                              static_cast<int>(value.size()),
                                              SQLITE_TRANSIENT);
        if (status != SQLITE_OK)
            return workspace_result_t<void>::failure(
                schema_v9_error(database_, status, "v9 bind_text failed", phase_));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> bind_blob(int index, const void* data, std::size_t size) {
        if (size > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
            return workspace_result_t<void>::failure(
                schema_v9_error(database_, SQLITE_TOOBIG,
                                "v9 blob value exceeds SQLite limit", phase_));
        }
        const int status = sqlite3_bind_blob(statement_, index, data,
                                              static_cast<int>(size), SQLITE_TRANSIENT);
        if (status != SQLITE_OK)
            return workspace_result_t<void>::failure(
                schema_v9_error(database_, status, "v9 bind_blob failed", phase_));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> bind_null(int index) {
        const int status = sqlite3_bind_null(statement_, index);
        if (status != SQLITE_OK)
            return workspace_result_t<void>::failure(
                schema_v9_error(database_, status, "v9 bind_null failed", phase_));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> step_done() {
        const int status = sqlite3_step(statement_);
        if (status != SQLITE_DONE) {
            return workspace_result_t<void>::failure(
                schema_v9_error(database_, status, "v9 step did not complete", phase_));
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> reset() {
        int status = sqlite3_reset(statement_);
        if (status == SQLITE_OK)
            status = sqlite3_clear_bindings(statement_);
        if (status != SQLITE_OK)
            return workspace_result_t<void>::failure(
                schema_v9_error(database_, status, "v9 reset failed", phase_));
        return workspace_result_t<void>::success();
    }

private:
    sqlite3* database_ = nullptr;
    sqlite3_stmt* statement_ = nullptr;
    const char* phase_ = "workspace_schema_v9";
};

std::string column_text_v9(sqlite3_stmt* statement, int index) {
    const unsigned char* value = sqlite3_column_text(statement, index);
    const int bytes = sqlite3_column_bytes(statement, index);
    if (!value || bytes <= 0)
        return {};
    return std::string(reinterpret_cast<const char*>(value),
                        static_cast<std::size_t>(bytes));
}

std::uint64_t utc_ms_v9() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

}

workspace_result_t<void> create_schema_v9(sqlite3* database) {
    return exec_sql_v9(database, R"SQL(
CREATE TABLE IF NOT EXISTS packed_generations(
    generation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL,
    analysis_revision INTEGER NOT NULL,
    overlay_revision INTEGER NOT NULL,
    shard_count INTEGER NOT NULL,
    total_payload_bytes INTEGER NOT NULL,
    total_records INTEGER NOT NULL,
    batch_checksum INTEGER NOT NULL,
    created_utc_ms INTEGER NOT NULL,
    committed INTEGER NOT NULL CHECK(committed IN (0,1)),
    payload_blob BLOB NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS packed_generations_generation ON packed_generations(generation);
CREATE INDEX IF NOT EXISTS packed_generations_revisions ON packed_generations(analysis_revision,overlay_revision);
CREATE TABLE IF NOT EXISTS packed_pages(
    page_id INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL,
    page_index INTEGER NOT NULL,
    page_count INTEGER NOT NULL,
    page_type INTEGER NOT NULL,
    payload_length INTEGER NOT NULL,
    checksum INTEGER NOT NULL,
    payload BLOB NOT NULL,
    UNIQUE(generation,page_index)
);
CREATE INDEX IF NOT EXISTS packed_pages_generation ON packed_pages(generation,page_index);
CREATE INDEX IF NOT EXISTS packed_pages_type ON packed_pages(generation,page_type);
CREATE TABLE IF NOT EXISTS packed_page_index(
    index_id INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL,
    domain INTEGER NOT NULL,
    ordinal_begin INTEGER NOT NULL,
    count INTEGER NOT NULL,
    page_index INTEGER NOT NULL,
    address_value_min INTEGER NOT NULL,
    address_value_max INTEGER NOT NULL,
    UNIQUE(generation,domain,page_index)
);
CREATE INDEX IF NOT EXISTS packed_page_index_generation_domain ON packed_page_index(generation,domain,ordinal_begin);
CREATE INDEX IF NOT EXISTS packed_page_index_address ON packed_page_index(generation,address_value_min,address_value_max);
CREATE TABLE IF NOT EXISTS workbench_state(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    has_selection INTEGER NOT NULL CHECK(has_selection IN (0,1)),
    selection_space INTEGER NOT NULL DEFAULT 0,
    selection_value INTEGER NOT NULL DEFAULT 0,
    selection_arch INTEGER NOT NULL DEFAULT 0,
    selection_mode INTEGER NOT NULL DEFAULT 0,
    navigation_back_json TEXT NOT NULL DEFAULT '[]',
    navigation_forward_json TEXT NOT NULL DEFAULT '[]',
    bookmarks_json TEXT NOT NULL DEFAULT '[]',
    layout_json TEXT NOT NULL DEFAULT '{}',
    active_tab INTEGER NOT NULL DEFAULT 0,
    zoom_level INTEGER NOT NULL DEFAULT 100,
    revision INTEGER NOT NULL DEFAULT 0,
    updated_utc_ms INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO workbench_state(singleton,has_selection,selection_space,selection_value,selection_arch,selection_mode,navigation_back_json,navigation_forward_json,bookmarks_json,layout_json,active_tab,zoom_level,revision,updated_utc_ms) VALUES(1,0,0,0,0,0,'[]','[]','[]','{}',0,100,0,0);
CREATE TABLE IF NOT EXISTS decompiler_cache_v9(
    cache_key TEXT PRIMARY KEY NOT NULL,
    binary_id BLOB NOT NULL,
    format INTEGER NOT NULL,
    architecture INTEGER NOT NULL,
    architecture_mode INTEGER NOT NULL,
    abi INTEGER NOT NULL,
    endian INTEGER NOT NULL,
    engine_version TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    specification_version TEXT NOT NULL,
    settings_hash TEXT NOT NULL,
    function_id INTEGER NOT NULL,
    function_rva INTEGER NOT NULL,
    function_rva_space INTEGER NOT NULL DEFAULT 0,
    function_rva_arch INTEGER NOT NULL DEFAULT 0,
    function_rva_mode INTEGER NOT NULL DEFAULT 0,
    function_content_hash BLOB NOT NULL,
    analysis_revision INTEGER NOT NULL,
    overlay_revision INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    function_name TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_utc_ms INTEGER NOT NULL,
    last_access_utc_ms INTEGER NOT NULL,
    result_bytes INTEGER NOT NULL,
    cache_key_version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS decompiler_cache_v9_function ON decompiler_cache_v9(function_rva,overlay_revision,generation);
CREATE INDEX IF NOT EXISTS decompiler_cache_v9_binary ON decompiler_cache_v9(binary_id,analysis_revision);
CREATE TABLE IF NOT EXISTS overlay_v9_state(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    target_image_hash BLOB NOT NULL,
    target_provenance_hash BLOB NOT NULL,
    target_image_base INTEGER NOT NULL,
    target_image_size INTEGER NOT NULL,
    target_generation INTEGER NOT NULL,
    target_kind INTEGER NOT NULL,
    target_architecture INTEGER NOT NULL,
    target_address_width INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    next_transaction_id INTEGER NOT NULL,
    history_cursor INTEGER NOT NULL,
    history_epoch INTEGER NOT NULL,
    updated_utc_ms INTEGER NOT NULL
);
INSERT OR IGNORE INTO overlay_v9_state(singleton,target_image_hash,target_provenance_hash,target_image_base,target_image_size,target_generation,target_kind,target_architecture,target_address_width,revision,next_transaction_id,history_cursor,history_epoch,updated_utc_ms) VALUES(1,X'0000000000000000000000000000000000000000000000000000000000000000',X'0000000000000000000000000000000000000000000000000000000000000000',0,0,0,0,0,0,0,1,0,1,0);
)SQL", "workspace_schema_v9.migrate");
}

workspace_result_t<void> write_packed_generation(
    sqlite3* database, const packed_generation_record_t& record) {
    if (record.generation == 0) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "packed generation must be non-zero",
                                 "workspace_schema_v9.write_packed_generation"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO packed_generations(generation,analysis_revision,overlay_revision,shard_count,total_payload_bytes,total_records,batch_checksum,created_utc_ms,committed,payload_blob)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
ON CONFLICT(generation) DO UPDATE SET analysis_revision=excluded.analysis_revision,overlay_revision=excluded.overlay_revision,shard_count=excluded.shard_count,total_payload_bytes=excluded.total_payload_bytes,total_records=excluded.total_records,batch_checksum=excluded.batch_checksum,created_utc_ms=excluded.created_utc_ms,committed=excluded.committed,payload_blob=excluded.payload_blob
)SQL", "workspace_schema_v9.write_packed_generation");
    if (!result) return result;
    result = statement.bind_uint(1, record.generation); if (!result) return result;
    result = statement.bind_uint(2, record.analysis_revision); if (!result) return result;
    result = statement.bind_uint(3, record.overlay_revision); if (!result) return result;
    result = statement.bind_int(4, static_cast<std::int64_t>(record.shard_count)); if (!result) return result;
    result = statement.bind_uint(5, record.total_payload_bytes); if (!result) return result;
    result = statement.bind_uint(6, record.total_records); if (!result) return result;
    result = statement.bind_int(7, static_cast<std::int64_t>(static_cast<std::uint32_t>(record.batch_checksum))); if (!result) return result;
    result = statement.bind_uint(8, record.created_utc_ms); if (!result) return result;
    result = statement.bind_int(9, record.committed ? 1 : 0); if (!result) return result;
    result = statement.bind_blob(10, record.payload_blob.data(), record.payload_blob.size()); if (!result) return result;
    return statement.step_done();
}

workspace_result_t<std::optional<packed_generation_record_t>>
    read_packed_generation(sqlite3* database, std::uint64_t generation) {
    v9_statement_t statement;
    auto result = statement.prepare(database,
        "SELECT generation,analysis_revision,overlay_revision,shard_count,total_payload_bytes,total_records,batch_checksum,created_utc_ms,committed,length(payload_blob),payload_blob FROM packed_generations WHERE generation=?1",
        "workspace_schema_v9.read_packed_generation");
    if (!result)
        return workspace_result_t<std::optional<packed_generation_record_t>>::failure(result.error());
    result = statement.bind_uint(1, generation);
    if (!result)
        return workspace_result_t<std::optional<packed_generation_record_t>>::failure(result.error());
    const int status = sqlite3_step(statement.get());
    if (status == SQLITE_DONE)
        return workspace_result_t<std::optional<packed_generation_record_t>>::success(std::nullopt);
    if (status != SQLITE_ROW) {
        return workspace_result_t<std::optional<packed_generation_record_t>>::failure(
            schema_v9_error(database, status, "unable to read packed generation",
                            "workspace_schema_v9.read_packed_generation"));
    }
    packed_generation_record_t record;
    record.generation = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
    record.analysis_revision = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
    record.overlay_revision = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2));
    record.shard_count = static_cast<std::uint16_t>(sqlite3_column_int(statement.get(), 3));
    record.total_payload_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 4));
    record.total_records = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 5));
    record.batch_checksum = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 6));
    record.created_utc_ms = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 7));
    record.committed = sqlite3_column_int(statement.get(), 8) != 0;
    const auto declared_blob_length = sqlite3_column_int64(statement.get(), 9);
    const void* payload = sqlite3_column_blob(statement.get(), 10);
    const int payload_bytes = sqlite3_column_bytes(statement.get(), 10);
    if (declared_blob_length < 0 || payload_bytes < 0 ||
        static_cast<std::uint64_t>(payload_bytes) != static_cast<std::uint64_t>(declared_blob_length) ||
        (payload_bytes > 0 && !payload)) {
        return workspace_result_t<std::optional<packed_generation_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "packed generation payload blob is malformed",
                                 "workspace_schema_v9.read_packed_generation"));
    }
    if (payload_bytes > 0) {
        const auto* begin = static_cast<const std::uint8_t*>(payload);
        record.payload_blob.assign(begin, begin + payload_bytes);
    }
    return workspace_result_t<std::optional<packed_generation_record_t>>::success(
        std::optional<packed_generation_record_t>(std::move(record)));
}

workspace_result_t<void> write_packed_page(
    sqlite3* database, const packed_page_row_t& row) {
    if (row.generation == 0) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "packed page generation must be non-zero",
                                 "workspace_schema_v9.write_packed_page"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO packed_pages(generation,page_index,page_count,page_type,payload_length,checksum,payload)
VALUES(?1,?2,?3,?4,?5,?6,?7)
ON CONFLICT(generation,page_index) DO UPDATE SET page_count=excluded.page_count,page_type=excluded.page_type,payload_length=excluded.payload_length,checksum=excluded.checksum,payload=excluded.payload
)SQL", "workspace_schema_v9.write_packed_page");
    if (!result) return result;
    result = statement.bind_uint(1, row.generation); if (!result) return result;
    result = statement.bind_int(2, static_cast<std::int64_t>(row.page_index)); if (!result) return result;
    result = statement.bind_int(3, static_cast<std::int64_t>(row.page_count)); if (!result) return result;
    result = statement.bind_int(4, static_cast<std::int64_t>(row.page_type)); if (!result) return result;
    result = statement.bind_int(5, static_cast<std::int64_t>(row.payload_length)); if (!result) return result;
    result = statement.bind_int(6, static_cast<std::int64_t>(row.checksum)); if (!result) return result;
    result = statement.bind_blob(7, row.payload.data(), row.payload.size()); if (!result) return result;
    return statement.step_done();
}

workspace_result_t<std::vector<packed_page_row_t>>
    read_packed_pages(sqlite3* database, std::uint64_t generation) {
    v9_statement_t statement;
    auto result = statement.prepare(database,
        "SELECT generation,page_index,page_count,page_type,payload_length,checksum,length(payload),payload FROM packed_pages WHERE generation=?1 ORDER BY page_index",
        "workspace_schema_v9.read_packed_pages");
    if (!result)
        return workspace_result_t<std::vector<packed_page_row_t>>::failure(result.error());
    result = statement.bind_uint(1, generation);
    if (!result)
        return workspace_result_t<std::vector<packed_page_row_t>>::failure(result.error());
    std::vector<packed_page_row_t> rows;
    for (;;) {
        const int status = sqlite3_step(statement.get());
        if (status == SQLITE_DONE)
            break;
        if (status != SQLITE_ROW) {
            return workspace_result_t<std::vector<packed_page_row_t>>::failure(
                schema_v9_error(database, status, "unable to read packed page row",
                                "workspace_schema_v9.read_packed_pages"));
        }
        packed_page_row_t row;
        row.generation = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
        row.page_index = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 1));
        row.page_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 2));
        row.page_type = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 3));
        row.payload_length = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 4));
        row.checksum = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 5));
        const auto declared_length = sqlite3_column_int64(statement.get(), 6);
        const void* payload = sqlite3_column_blob(statement.get(), 7);
        const int payload_bytes = sqlite3_column_bytes(statement.get(), 7);
        if (declared_length < 0 || payload_bytes < 0 ||
            static_cast<std::uint64_t>(payload_bytes) != static_cast<std::uint64_t>(declared_length) ||
            static_cast<std::uint32_t>(payload_bytes) != row.payload_length ||
            (payload_bytes > 0 && !payload)) {
            return workspace_result_t<std::vector<packed_page_row_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "packed page payload is malformed",
                                     "workspace_schema_v9.read_packed_pages"));
        }
        if (payload_bytes > 0) {
            const auto* begin = static_cast<const std::uint8_t*>(payload);
            row.payload.assign(begin, begin + payload_bytes);
        }
        rows.push_back(std::move(row));
    }
    return workspace_result_t<std::vector<packed_page_row_t>>::success(std::move(rows));
}

workspace_result_t<void> write_packed_page_index(
    sqlite3* database, const packed_page_index_row_t& row) {
    if (row.generation == 0) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "packed page index generation must be non-zero",
                                 "workspace_schema_v9.write_packed_page_index"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO packed_page_index(generation,domain,ordinal_begin,count,page_index,address_value_min,address_value_max)
VALUES(?1,?2,?3,?4,?5,?6,?7)
ON CONFLICT(generation,domain,page_index) DO UPDATE SET ordinal_begin=excluded.ordinal_begin,count=excluded.count,address_value_min=excluded.address_value_min,address_value_max=excluded.address_value_max
)SQL", "workspace_schema_v9.write_packed_page_index");
    if (!result) return result;
    result = statement.bind_uint(1, row.generation); if (!result) return result;
    result = statement.bind_int(2, static_cast<std::int64_t>(row.domain)); if (!result) return result;
    result = statement.bind_int(3, static_cast<std::int64_t>(row.ordinal_begin)); if (!result) return result;
    result = statement.bind_int(4, static_cast<std::int64_t>(row.count)); if (!result) return result;
    result = statement.bind_int(5, static_cast<std::int64_t>(row.page_index)); if (!result) return result;
    result = statement.bind_uint(6, row.address_value_min); if (!result) return result;
    result = statement.bind_uint(7, row.address_value_max); if (!result) return result;
    return statement.step_done();
}

workspace_result_t<std::vector<packed_page_index_row_t>>
    read_packed_page_index(sqlite3* database, std::uint64_t generation) {
    v9_statement_t statement;
    auto result = statement.prepare(database,
        "SELECT generation,domain,ordinal_begin,count,page_index,address_value_min,address_value_max FROM packed_page_index WHERE generation=?1 ORDER BY domain,ordinal_begin",
        "workspace_schema_v9.read_packed_page_index");
    if (!result)
        return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(result.error());
    result = statement.bind_uint(1, generation);
    if (!result)
        return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(result.error());
    std::vector<packed_page_index_row_t> rows;
    for (;;) {
        const int status = sqlite3_step(statement.get());
        if (status == SQLITE_DONE)
            break;
        if (status != SQLITE_ROW) {
            return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(
                schema_v9_error(database, status, "unable to read packed page index row",
                                "workspace_schema_v9.read_packed_page_index"));
        }
        packed_page_index_row_t row;
        row.generation = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
        row.domain = static_cast<std::uint16_t>(sqlite3_column_int(statement.get(), 1));
        row.ordinal_begin = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 2));
        row.count = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 3));
        row.page_index = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 4));
        row.address_value_min = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 5));
        row.address_value_max = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 6));
        rows.push_back(std::move(row));
    }
    return workspace_result_t<std::vector<packed_page_index_row_t>>::success(std::move(rows));
}

workspace_result_t<void> write_workbench_state(
    sqlite3* database, const workbench_state_record_t& record) {
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO workbench_state(singleton,has_selection,selection_space,selection_value,selection_arch,selection_mode,navigation_back_json,navigation_forward_json,bookmarks_json,layout_json,active_tab,zoom_level,revision,updated_utc_ms)
VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
ON CONFLICT(singleton) DO UPDATE SET has_selection=excluded.has_selection,selection_space=excluded.selection_space,selection_value=excluded.selection_value,selection_arch=excluded.selection_arch,selection_mode=excluded.selection_mode,navigation_back_json=excluded.navigation_back_json,navigation_forward_json=excluded.navigation_forward_json,bookmarks_json=excluded.bookmarks_json,layout_json=excluded.layout_json,active_tab=excluded.active_tab,zoom_level=excluded.zoom_level,revision=excluded.revision,updated_utc_ms=excluded.updated_utc_ms
)SQL", "workspace_schema_v9.write_workbench_state");
    if (!result) return result;
    result = statement.bind_int(1, record.has_selection ? 1 : 0); if (!result) return result;
    result = statement.bind_int(2, static_cast<std::int64_t>(record.selection.space)); if (!result) return result;
    result = statement.bind_uint(3, record.selection.value); if (!result) return result;
    result = statement.bind_int(4, static_cast<std::int64_t>(record.selection.architecture)); if (!result) return result;
    result = statement.bind_int(5, static_cast<std::int64_t>(record.selection.mode)); if (!result) return result;
    result = statement.bind_text(6, record.navigation_back_json); if (!result) return result;
    result = statement.bind_text(7, record.navigation_forward_json); if (!result) return result;
    result = statement.bind_text(8, record.bookmarks_json); if (!result) return result;
    result = statement.bind_text(9, record.layout_json); if (!result) return result;
    result = statement.bind_int(10, static_cast<std::int64_t>(record.active_tab)); if (!result) return result;
    result = statement.bind_int(11, static_cast<std::int64_t>(record.zoom_level)); if (!result) return result;
    result = statement.bind_uint(12, record.revision); if (!result) return result;
    result = statement.bind_uint(13, record.updated_utc_ms > 0 ? record.updated_utc_ms : utc_ms_v9()); if (!result) return result;
    return statement.step_done();
}

workspace_result_t<std::optional<workbench_state_record_t>>
    read_workbench_state(sqlite3* database) {
    v9_statement_t statement;
    auto result = statement.prepare(database,
        "SELECT has_selection,selection_space,selection_value,selection_arch,selection_mode,navigation_back_json,navigation_forward_json,bookmarks_json,layout_json,active_tab,zoom_level,revision,updated_utc_ms FROM workbench_state WHERE singleton=1",
        "workspace_schema_v9.read_workbench_state");
    if (!result)
        return workspace_result_t<std::optional<workbench_state_record_t>>::failure(result.error());
    const int status = sqlite3_step(statement.get());
    if (status == SQLITE_DONE)
        return workspace_result_t<std::optional<workbench_state_record_t>>::success(std::nullopt);
    if (status != SQLITE_ROW) {
        return workspace_result_t<std::optional<workbench_state_record_t>>::failure(
            schema_v9_error(database, status, "unable to read workbench state",
                            "workspace_schema_v9.read_workbench_state"));
    }
    workbench_state_record_t record;
    record.has_selection = sqlite3_column_int(statement.get(), 0) != 0;
    record.selection.space = static_cast<address_space_id_t>(sqlite3_column_int(statement.get(), 1));
    record.selection.value = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2));
    record.selection.architecture = static_cast<architecture_id_t>(sqlite3_column_int(statement.get(), 3));
    record.selection.mode = static_cast<architecture_mode_t>(sqlite3_column_int(statement.get(), 4));
    record.navigation_back_json = column_text_v9(statement.get(), 5);
    record.navigation_forward_json = column_text_v9(statement.get(), 6);
    record.bookmarks_json = column_text_v9(statement.get(), 7);
    record.layout_json = column_text_v9(statement.get(), 8);
    record.active_tab = static_cast<std::int32_t>(sqlite3_column_int(statement.get(), 9));
    record.zoom_level = static_cast<std::int32_t>(sqlite3_column_int(statement.get(), 10));
    record.revision = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 11));
    record.updated_utc_ms = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 12));
    return workspace_result_t<std::optional<workbench_state_record_t>>::success(
        std::optional<workbench_state_record_t>(std::move(record)));
}

workspace_result_t<void> write_decompiler_cache_v9(
    sqlite3* database, const decompiler_cache_v9_record_t& record) {
    if (record.cache_key.empty() || record.cache_key.size() > 16384) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "decompiler cache v9 key is empty or too long",
                                 "workspace_schema_v9.write_decompiler_cache_v9"));
    }
    if (record.result_json.empty() || record.result_bytes != record.result_json.size()) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "decompiler cache v9 result json is empty or size mismatch",
                                 "workspace_schema_v9.write_decompiler_cache_v9"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO decompiler_cache_v9(cache_key,binary_id,format,architecture,architecture_mode,abi,endian,engine_version,schema_version,specification_version,settings_hash,function_id,function_rva,function_rva_space,function_rva_arch,function_rva_mode,function_content_hash,analysis_revision,overlay_revision,generation,function_name,result_json,created_utc_ms,last_access_utc_ms,result_bytes,cache_key_version)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26)
ON CONFLICT(cache_key) DO UPDATE SET function_name=excluded.function_name,result_json=excluded.result_json,last_access_utc_ms=excluded.last_access_utc_ms,result_bytes=excluded.result_bytes,analysis_revision=excluded.analysis_revision,overlay_revision=excluded.overlay_revision,generation=excluded.generation
)SQL", "workspace_schema_v9.write_decompiler_cache_v9");
    if (!result) return result;
    result = statement.bind_text(1, record.cache_key); if (!result) return result;
    result = statement.bind_blob(2, record.binary_id.bytes.data(), record.binary_id.bytes.size()); if (!result) return result;
    result = statement.bind_int(3, static_cast<std::int64_t>(record.format)); if (!result) return result;
    result = statement.bind_int(4, static_cast<std::int64_t>(record.architecture)); if (!result) return result;
    result = statement.bind_int(5, static_cast<std::int64_t>(record.architecture_mode)); if (!result) return result;
    result = statement.bind_int(6, static_cast<std::int64_t>(record.abi)); if (!result) return result;
    result = statement.bind_int(7, static_cast<std::int64_t>(record.endian)); if (!result) return result;
    result = statement.bind_text(8, record.engine_version); if (!result) return result;
    result = statement.bind_int(9, static_cast<std::int64_t>(record.schema_version)); if (!result) return result;
    result = statement.bind_text(10, record.specification_version); if (!result) return result;
    result = statement.bind_text(11, record.settings_hash); if (!result) return result;
    result = statement.bind_uint(12, record.function_id); if (!result) return result;
    result = statement.bind_uint(13, record.function_rva); if (!result) return result;
    result = statement.bind_int(14, static_cast<std::int64_t>(record.function_rva_address.space)); if (!result) return result;
    result = statement.bind_int(15, static_cast<std::int64_t>(record.function_rva_address.architecture)); if (!result) return result;
    result = statement.bind_int(16, static_cast<std::int64_t>(record.function_rva_address.mode)); if (!result) return result;
    result = statement.bind_blob(17, record.function_content_hash.bytes.data(), record.function_content_hash.bytes.size()); if (!result) return result;
    result = statement.bind_uint(18, record.analysis_revision); if (!result) return result;
    result = statement.bind_uint(19, record.overlay_revision); if (!result) return result;
    result = statement.bind_uint(20, record.generation); if (!result) return result;
    result = statement.bind_text(21, record.function_name); if (!result) return result;
    result = statement.bind_text(22, record.result_json); if (!result) return result;
    result = statement.bind_uint(23, record.created_utc_ms); if (!result) return result;
    result = statement.bind_uint(24, record.last_access_utc_ms); if (!result) return result;
    result = statement.bind_uint(25, record.result_bytes); if (!result) return result;
    result = statement.bind_int(26, static_cast<std::int64_t>(record.cache_key_version)); if (!result) return result;
    return statement.step_done();
}

workspace_result_t<std::optional<decompiler_cache_v9_record_t>>
    read_decompiler_cache_v9(sqlite3* database, const std::string& cache_key) {
    v9_statement_t statement;
    auto result = statement.prepare(database,
        "SELECT cache_key,binary_id,format,architecture,architecture_mode,abi,endian,engine_version,schema_version,specification_version,settings_hash,function_id,function_rva,function_rva_space,function_rva_arch,function_rva_mode,function_content_hash,analysis_revision,overlay_revision,generation,function_name,length(result_json),result_json,created_utc_ms,last_access_utc_ms,result_bytes,cache_key_version FROM decompiler_cache_v9 WHERE cache_key=?1",
        "workspace_schema_v9.read_decompiler_cache_v9");
    if (!result)
        return workspace_result_t<std::optional<decompiler_cache_v9_record_t>>::failure(result.error());
    result = statement.bind_text(1, cache_key);
    if (!result)
        return workspace_result_t<std::optional<decompiler_cache_v9_record_t>>::failure(result.error());
    const int status = sqlite3_step(statement.get());
    if (status == SQLITE_DONE)
        return workspace_result_t<std::optional<decompiler_cache_v9_record_t>>::success(std::nullopt);
    if (status != SQLITE_ROW) {
        return workspace_result_t<std::optional<decompiler_cache_v9_record_t>>::failure(
            schema_v9_error(database, status, "unable to read decompiler cache v9",
                            "workspace_schema_v9.read_decompiler_cache_v9"));
    }
    decompiler_cache_v9_record_t record;
    record.cache_key = column_text_v9(statement.get(), 0);
    const void* binary_blob = sqlite3_column_blob(statement.get(), 1);
    const int binary_bytes = sqlite3_column_bytes(statement.get(), 1);
    if (binary_blob && binary_bytes == static_cast<int>(record.binary_id.bytes.size())) {
        std::memcpy(record.binary_id.bytes.data(), binary_blob, record.binary_id.bytes.size());
    }
    record.format = static_cast<format_id_t>(sqlite3_column_int(statement.get(), 2));
    record.architecture = static_cast<architecture_id_t>(sqlite3_column_int(statement.get(), 3));
    record.architecture_mode = static_cast<architecture_mode_t>(sqlite3_column_int(statement.get(), 4));
    record.abi = static_cast<abi_id_t>(sqlite3_column_int(statement.get(), 5));
    record.endian = static_cast<endian_t>(sqlite3_column_int(statement.get(), 6));
    record.engine_version = column_text_v9(statement.get(), 7);
    record.schema_version = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 8));
    record.specification_version = column_text_v9(statement.get(), 9);
    record.settings_hash = column_text_v9(statement.get(), 10);
    record.function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement.get(), 11));
    record.function_rva = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 12));
    record.function_rva_address.space = static_cast<address_space_id_t>(sqlite3_column_int(statement.get(), 13));
    record.function_rva_address.architecture = static_cast<architecture_id_t>(sqlite3_column_int(statement.get(), 14));
    record.function_rva_address.mode = static_cast<architecture_mode_t>(sqlite3_column_int(statement.get(), 15));
    const void* content_hash_blob = sqlite3_column_blob(statement.get(), 16);
    const int content_hash_bytes = sqlite3_column_bytes(statement.get(), 16);
    if (content_hash_blob && content_hash_bytes == static_cast<int>(record.function_content_hash.bytes.size())) {
        std::memcpy(record.function_content_hash.bytes.data(), content_hash_blob,
                    record.function_content_hash.bytes.size());
    }
    record.analysis_revision = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 17));
    record.overlay_revision = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 18));
    record.generation = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 19));
    record.function_name = column_text_v9(statement.get(), 20);
    const auto declared_length = sqlite3_column_int64(statement.get(), 21);
    record.result_json = column_text_v9(statement.get(), 22);
    record.created_utc_ms = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 23));
    record.last_access_utc_ms = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 24));
    record.result_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 25));
    record.cache_key_version = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 26));
    if (declared_length <= 0 ||
        static_cast<std::uint64_t>(declared_length) != record.result_json.size() ||
        record.result_bytes != record.result_json.size()) {
        return workspace_result_t<std::optional<decompiler_cache_v9_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "decompiler cache v9 result length is inconsistent",
                                 "workspace_schema_v9.read_decompiler_cache_v9"));
    }
    return workspace_result_t<std::optional<decompiler_cache_v9_record_t>>::success(
        std::optional<decompiler_cache_v9_record_t>(std::move(record)));
}

workspace_result_t<void> write_overlay_v9_state(
    sqlite3* database, const overlay_v9_state_record_t& record) {
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO overlay_v9_state(singleton,target_image_hash,target_provenance_hash,target_image_base,target_image_size,target_generation,target_kind,target_architecture,target_address_width,revision,next_transaction_id,history_cursor,history_epoch,updated_utc_ms)
VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
ON CONFLICT(singleton) DO UPDATE SET target_image_hash=excluded.target_image_hash,target_provenance_hash=excluded.target_provenance_hash,target_image_base=excluded.target_image_base,target_image_size=excluded.target_image_size,target_generation=excluded.target_generation,target_kind=excluded.target_kind,target_architecture=excluded.target_architecture,target_address_width=excluded.target_address_width,revision=excluded.revision,next_transaction_id=excluded.next_transaction_id,history_cursor=excluded.history_cursor,history_epoch=excluded.history_epoch,updated_utc_ms=excluded.updated_utc_ms
)SQL", "workspace_schema_v9.write_overlay_v9_state");
    if (!result) return result;
    result = statement.bind_blob(1, record.target_image_hash.data(), record.target_image_hash.size()); if (!result) return result;
    result = statement.bind_blob(2, record.target_provenance_hash.data(), record.target_provenance_hash.size()); if (!result) return result;
    result = statement.bind_uint(3, record.target_image_base); if (!result) return result;
    result = statement.bind_uint(4, record.target_image_size); if (!result) return result;
    result = statement.bind_uint(5, record.target_generation); if (!result) return result;
    result = statement.bind_int(6, static_cast<std::int64_t>(record.target_kind)); if (!result) return result;
    result = statement.bind_int(7, static_cast<std::int64_t>(record.target_architecture)); if (!result) return result;
    result = statement.bind_int(8, static_cast<std::int64_t>(record.target_address_width)); if (!result) return result;
    result = statement.bind_uint(9, record.revision); if (!result) return result;
    result = statement.bind_uint(10, record.next_transaction_id); if (!result) return result;
    result = statement.bind_uint(11, record.history_cursor); if (!result) return result;
    result = statement.bind_uint(12, record.history_epoch); if (!result) return result;
    result = statement.bind_uint(13, record.updated_utc_ms > 0 ? record.updated_utc_ms : utc_ms_v9()); if (!result) return result;
    return statement.step_done();
}

workspace_result_t<std::optional<overlay_v9_state_record_t>>
    read_overlay_v9_state(sqlite3* database) {
    v9_statement_t statement;
    auto result = statement.prepare(database,
        "SELECT target_image_hash,target_provenance_hash,target_image_base,target_image_size,target_generation,target_kind,target_architecture,target_address_width,revision,next_transaction_id,history_cursor,history_epoch,updated_utc_ms FROM overlay_v9_state WHERE singleton=1",
        "workspace_schema_v9.read_overlay_v9_state");
    if (!result)
        return workspace_result_t<std::optional<overlay_v9_state_record_t>>::failure(result.error());
    const int status = sqlite3_step(statement.get());
    if (status == SQLITE_DONE)
        return workspace_result_t<std::optional<overlay_v9_state_record_t>>::success(std::nullopt);
    if (status != SQLITE_ROW) {
        return workspace_result_t<std::optional<overlay_v9_state_record_t>>::failure(
            schema_v9_error(database, status, "unable to read overlay v9 state",
                            "workspace_schema_v9.read_overlay_v9_state"));
    }
    overlay_v9_state_record_t record;
    const void* image_hash_blob = sqlite3_column_blob(statement.get(), 0);
    const int image_hash_bytes = sqlite3_column_bytes(statement.get(), 0);
    if (image_hash_blob && image_hash_bytes == static_cast<int>(record.target_image_hash.size())) {
        std::memcpy(record.target_image_hash.data(), image_hash_blob, record.target_image_hash.size());
    }
    const void* provenance_hash_blob = sqlite3_column_blob(statement.get(), 1);
    const int provenance_hash_bytes = sqlite3_column_bytes(statement.get(), 1);
    if (provenance_hash_blob && provenance_hash_bytes == static_cast<int>(record.target_provenance_hash.size())) {
        std::memcpy(record.target_provenance_hash.data(), provenance_hash_blob,
                    record.target_provenance_hash.size());
    }
    record.target_image_base = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2));
    record.target_image_size = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 3));
    record.target_generation = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 4));
    record.target_kind = static_cast<std::uint8_t>(sqlite3_column_int(statement.get(), 5));
    record.target_architecture = static_cast<std::uint8_t>(sqlite3_column_int(statement.get(), 6));
    record.target_address_width = static_cast<std::uint8_t>(sqlite3_column_int(statement.get(), 7));
    record.revision = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 8));
    record.next_transaction_id = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 9));
    record.history_cursor = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 10));
    record.history_epoch = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 11));
    record.updated_utc_ms = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 12));
    return workspace_result_t<std::optional<overlay_v9_state_record_t>>::success(
        std::optional<overlay_v9_state_record_t>(std::move(record)));
}

workspace_result_t<void> publish_packed_generation(
    sqlite3* database, std::uint64_t generation) {
    v9_statement_t statement;
    auto result = statement.prepare(database,
        "UPDATE packed_generations SET committed=1 WHERE generation=?1 AND committed=0",
        "workspace_schema_v9.publish_packed_generation");
    if (!result) return result;
    result = statement.bind_uint(1, generation); if (!result) return result;
    result = statement.step_done(); if (!result) return result;
    if (sqlite3_changes(database) == 0) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                                 "packed generation not found or already committed",
                                 "workspace_schema_v9.publish_packed_generation"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> rollback_packed_generation(
    sqlite3* database, std::uint64_t generation) {
    v9_statement_t pages;
    auto result = pages.prepare(database,
        "DELETE FROM packed_pages WHERE generation=?1",
        "workspace_schema_v9.rollback_packed_generation.pages");
    if (!result) return result;
    result = pages.bind_uint(1, generation); if (!result) return result;
    result = pages.step_done(); if (!result) return result;
    v9_statement_t index;
    result = index.prepare(database,
        "DELETE FROM packed_page_index WHERE generation=?1",
        "workspace_schema_v9.rollback_packed_generation.index");
    if (!result) return result;
    result = index.bind_uint(1, generation); if (!result) return result;
    result = index.step_done(); if (!result) return result;
    v9_statement_t gen;
    result = gen.prepare(database,
        "DELETE FROM packed_generations WHERE generation=?1 AND committed=0",
        "workspace_schema_v9.rollback_packed_generation.gen");
    if (!result) return result;
    result = gen.bind_uint(1, generation); if (!result) return result;
    return gen.step_done();
}

}
