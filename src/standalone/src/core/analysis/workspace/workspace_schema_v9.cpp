#include "workspace_schema_v9.hpp"

#include "checked_range.hpp"
#include "packed_page_codec.hpp"
#include "sqlite_statement_cache.hpp"

#include <sqlite3.h>

#include <zstd.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <unordered_set>
#include <utility>

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
        release_current();
    }
    v9_statement_t(const v9_statement_t&) = delete;
    v9_statement_t& operator=(const v9_statement_t&) = delete;

    workspace_result_t<void> prepare(sqlite3* database, const char* sql,
                                     const char* phase) {
        release_current();
        std::shared_ptr<sqlite_statement_cache_t> cache;
        try {
            cache = sqlite_statement_cache_lookup(database);
        } catch (...) {
            cache.reset();
        }
        if (cache) {
            int status = SQLITE_OK;
            sqlite3_stmt* cached = nullptr;
            try {
                cached = cache->acquire(database, sql, status);
            } catch (...) {
                cached = nullptr;
                status = SQLITE_OK;
            }
            if (cached) {
                std::string sql_key;
                try {
                    sql_key = sql;
                } catch (...) {
                    sqlite3_finalize(cached);
                    cached = nullptr;
                }
                if (cached) {
                    statement_ = cached;
                    cache_ = std::move(cache);
                    cache_sql_ = std::move(sql_key);
                    database_ = database;
                    phase_ = phase;
                    return workspace_result_t<void>::success();
                }
            }
            if (status != SQLITE_OK) {
                return workspace_result_t<void>::failure(
                    schema_v9_error(database, status,
                                    "failed to prepare v9 SQLite statement", phase));
            }
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
        if (size != 0 && !data) {
            return workspace_result_t<void>::failure(
                schema_v9_error(database_, SQLITE_MISUSE,
                                "v9 blob value is null with a non-zero size", phase_));
        }
        const int status = size == 0
            ? sqlite3_bind_zeroblob(statement_, index, 0)
            : sqlite3_bind_blob(statement_, index, data,
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
    void release_current() noexcept {
        if (!statement_)
            return;
        if (cache_) {
            try {
                cache_->release(cache_sql_, statement_);
                statement_ = nullptr;
            } catch (...) {
                sqlite3_finalize(statement_);
                statement_ = nullptr;
            }
            cache_.reset();
            cache_sql_.clear();
        } else {
            sqlite3_finalize(statement_);
            statement_ = nullptr;
        }
    }

    sqlite3* database_ = nullptr;
    sqlite3_stmt* statement_ = nullptr;
    const char* phase_ = "workspace_schema_v9";
    std::shared_ptr<sqlite_statement_cache_t> cache_;
    std::string cache_sql_;
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

void append_u32_le_v9(std::vector<std::uint8_t>& output,
                      std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 24U));
}

workspace_result_t<bool> table_exists_v9(sqlite3* database,
                                         const std::string& table) {
    v9_statement_t statement;
    auto result = statement.prepare(database,
        "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1",
        "workspace_schema_v9.table_exists");
    if (!result)
        return workspace_result_t<bool>::failure(result.error());
    result = statement.bind_text(1, table);
    if (!result)
        return workspace_result_t<bool>::failure(result.error());
    const int status = sqlite3_step(statement.get());
    if (status == SQLITE_ROW)
        return workspace_result_t<bool>::success(true);
    if (status == SQLITE_DONE)
        return workspace_result_t<bool>::success(false);
    return workspace_result_t<bool>::failure(schema_v9_error(
        database, status, "unable to inspect v9 migration source table",
        "workspace_schema_v9.table_exists"));
}

workspace_result_t<bool> packed_domain_upgrade_required_v9(sqlite3* database) {
    const auto table_sql = [&](const char* table)
        -> workspace_result_t<std::string> {
        v9_statement_t statement;
        auto result = statement.prepare(database,
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
            "workspace_schema_v9.inspect_packed_domain");
        if (!result)
            return workspace_result_t<std::string>::failure(result.error());
        result = statement.bind_text(1, table);
        if (!result)
            return workspace_result_t<std::string>::failure(result.error());
        const int status = sqlite3_step(statement.get());
        if (status == SQLITE_DONE)
            return workspace_result_t<std::string>::success({});
        if (status != SQLITE_ROW)
            return workspace_result_t<std::string>::failure(schema_v9_error(
                database, status, "unable to inspect packed-domain schema",
                "workspace_schema_v9.inspect_packed_domain"));
        return workspace_result_t<std::string>::success(
            column_text_v9(statement.get(), 0));
    };
    auto generations = table_sql("packed_generations");
    if (!generations)
        return workspace_result_t<bool>::failure(generations.error());
    auto pages = table_sql("packed_pages");
    if (!pages)
        return workspace_result_t<bool>::failure(pages.error());
    auto index = table_sql("packed_page_index");
    if (!index)
        return workspace_result_t<bool>::failure(index.error());
    if (generations.value().empty() && pages.value().empty() &&
        index.value().empty())
        return workspace_result_t<bool>::success(false);
    return workspace_result_t<bool>::success(
        generations.value().empty() || pages.value().empty() ||
        index.value().empty() ||
        generations.value().find("BETWEEN 1 AND 19") == std::string::npos ||
        generations.value().find("17179869184") == std::string::npos ||
        generations.value().find("BETWEEN 0 AND 200000000") ==
            std::string::npos ||
        pages.value().find("BETWEEN 1 AND 19") == std::string::npos ||
        pages.value().find("BETWEEN 32 AND 1048576") == std::string::npos ||
        index.value().find("BETWEEN 1 AND 19") == std::string::npos);
}

workspace_result_t<void> upgrade_packed_domain_schema_v9(sqlite3* database) {
    auto required = packed_domain_upgrade_required_v9(database);
    if (!required)
        return workspace_result_t<void>::failure(required.error());
    if (!required.value())
        return workspace_result_t<void>::success();
    auto result = exec_sql_v9(database,
        "SAVEPOINT aida_packed_domain_upgrade_v9",
        "workspace_schema_v9.upgrade_packed_domain.begin");
    if (!result)
        return result;
    result = exec_sql_v9(database, R"SQL(
DROP TABLE IF EXISTS packed_page_index_v9_upgrade;
DROP TABLE IF EXISTS packed_pages_v9_upgrade;
DROP TABLE IF EXISTS packed_generations_v9_upgrade;
CREATE TABLE packed_generations_v9_upgrade(
    generation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL CHECK(generation<>0),
    analysis_revision INTEGER NOT NULL,
    overlay_revision INTEGER NOT NULL,
    shard_count INTEGER NOT NULL CHECK(shard_count BETWEEN 1 AND 19),
    total_payload_bytes INTEGER NOT NULL CHECK(total_payload_bytes BETWEEN 0 AND 17179869184),
    total_records INTEGER NOT NULL CHECK(total_records BETWEEN 0 AND 200000000),
    batch_checksum INTEGER NOT NULL,
    created_utc_ms INTEGER NOT NULL,
    committed INTEGER NOT NULL CHECK(committed IN (0,1)),
    payload_blob BLOB NOT NULL CHECK(length(payload_blob)<=16777216),
    UNIQUE(generation)
);
CREATE TABLE packed_pages_v9_upgrade(
    page_id INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL,
    page_index INTEGER NOT NULL CHECK(page_index BETWEEN 0 AND 131071),
    page_count INTEGER NOT NULL CHECK(page_count BETWEEN 1 AND 131072),
    page_type INTEGER NOT NULL CHECK(page_type BETWEEN 1 AND 19),
    payload_length INTEGER NOT NULL CHECK(payload_length BETWEEN 32 AND 1048576),
    checksum INTEGER NOT NULL,
    payload BLOB NOT NULL CHECK(length(payload)=payload_length),
    UNIQUE(generation,page_index),
    FOREIGN KEY(generation) REFERENCES packed_generations_v9_upgrade(generation) ON DELETE CASCADE
);
CREATE TABLE packed_page_index_v9_upgrade(
    index_id INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL,
    domain INTEGER NOT NULL CHECK(domain BETWEEN 1 AND 19),
    ordinal_begin INTEGER NOT NULL CHECK(ordinal_begin BETWEEN 0 AND 4294967295),
    count INTEGER NOT NULL CHECK(count BETWEEN 0 AND 1048576),
    page_index INTEGER NOT NULL CHECK(page_index BETWEEN 0 AND 131071),
    address_value_min INTEGER NOT NULL,
    address_value_max INTEGER NOT NULL,
    UNIQUE(generation,domain,page_index),
    FOREIGN KEY(generation) REFERENCES packed_generations_v9_upgrade(generation) ON DELETE CASCADE
);
DROP TABLE packed_page_index;
DROP TABLE packed_pages;
DROP TABLE packed_generations;
ALTER TABLE packed_generations_v9_upgrade RENAME TO packed_generations;
ALTER TABLE packed_pages_v9_upgrade RENAME TO packed_pages;
ALTER TABLE packed_page_index_v9_upgrade RENAME TO packed_page_index;
)SQL", "workspace_schema_v9.upgrade_packed_domain");
    if (!result) {
        exec_sql_v9(database, "ROLLBACK TO aida_packed_domain_upgrade_v9",
                    "workspace_schema_v9.upgrade_packed_domain.rollback");
        exec_sql_v9(database, "RELEASE aida_packed_domain_upgrade_v9",
                    "workspace_schema_v9.upgrade_packed_domain.release");
        return result;
    }
    result = exec_sql_v9(database,
        "RELEASE aida_packed_domain_upgrade_v9",
        "workspace_schema_v9.upgrade_packed_domain.commit");
    return result;
}

workspace_result_t<void> cancelled_publish_error() {
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "packed generation publication was cancelled",
                                      "workspace_schema_v9.publish_atomic");
    error.cancellation = true;
    return workspace_result_t<void>::failure(std::move(error));
}

bool publish_stop_requested_v9(
    const packed_publish_stop_predicate_t& stop_requested) noexcept {
    if (!stop_requested)
        return false;
    try {
        return stop_requested();
    } catch (...) {
        return true;
    }
}

bool valid_candidate_token_v9(const std::string& token) noexcept {
    return token.size() == 32 &&
        std::all_of(token.begin(), token.end(), [](unsigned char value) {
            return (value >= '0' && value <= '9') ||
                   (value >= 'a' && value <= 'f');
        });
}

workspace_error_t cancelled_read_error_v9(const char* phase) {
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "packed generation read was cancelled",
                                      phase);
    error.cancellation = true;
    return error;
}

workspace_result_t<void> copy_blob_v9(
    std::vector<std::uint8_t>& output, const std::uint8_t* input,
    std::size_t size, const packed_stop_predicate_t& stop_requested,
    const char* phase) {
    try {
        output.clear();
        output.reserve(size);
        constexpr std::size_t chunk_size = 4096;
        for (std::size_t offset = 0; offset < size;) {
            if (publish_stop_requested_v9(stop_requested))
                return workspace_result_t<void>::failure(
                    cancelled_read_error_v9(phase));
            const auto end = (std::min)(size, offset + chunk_size);
            output.insert(output.end(), input + offset, input + end);
            offset = end;
        }
    } catch (const std::bad_alloc&) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "packed generation blob allocation failed",
                                 phase));
    }
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<void>::failure(cancelled_read_error_v9(phase));
    return workspace_result_t<void>::success();
}

std::uint32_t read_u32_le_v9(const std::uint8_t* data) noexcept {
    return static_cast<std::uint32_t>(data[0]) |
           (static_cast<std::uint32_t>(data[1]) << 8U) |
           (static_cast<std::uint32_t>(data[2]) << 16U) |
           (static_cast<std::uint32_t>(data[3]) << 24U);
}

std::uint64_t read_u64_le_v9(const std::uint8_t* data) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index)
        value |= static_cast<std::uint64_t>(data[index]) << (index * 8);
    return value;
}

void append_u64_le_v9(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

workspace_error_t cancelled_pdb_error_v10(const char* phase) {
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "pdb symbol module operation was cancelled",
                                      phase);
    error.cancellation = true;
    return error;
}

workspace_result_t<bool> column_exists_v9(sqlite3* database, const char* table,
                                          const char* column) {
    const std::string sql = std::string("PRAGMA table_info(") + table + ")";
    v9_statement_t statement;
    auto result = statement.prepare(database, sql.c_str(),
                                    "workspace_schema_v10.column_exists");
    if (!result)
        return workspace_result_t<bool>::failure(result.error());
    for (;;) {
        const int status = sqlite3_step(statement.get());
        if (status == SQLITE_DONE)
            return workspace_result_t<bool>::success(false);
        if (status != SQLITE_ROW) {
            return workspace_result_t<bool>::failure(schema_v9_error(
                database, status, "unable to inspect table columns",
                "workspace_schema_v10.column_exists"));
        }
        if (column_text_v9(statement.get(), 1) == column)
            return workspace_result_t<bool>::success(true);
    }
}

std::optional<std::uint64_t> packed_page_frame_content_length_v9(
    const std::uint8_t* payload, std::size_t size) noexcept {
    if (!payload ||
        size < packed_record_page_prefix_size + packed_page_frame_header_size)
        return std::nullopt;
    const std::uint32_t magic =
        read_u32_le_v9(payload + packed_record_page_prefix_size);
    const std::uint32_t codec =
        read_u32_le_v9(payload + packed_record_page_prefix_size + 4);
    if (magic != packed_page_frame_magic || codec != packed_page_codec_zstd)
        return std::nullopt;
    return read_u64_le_v9(payload + packed_record_page_prefix_size + 8);
}

class zstd_cctx_v10_t final {
public:
    zstd_cctx_v10_t() = default;
    ~zstd_cctx_v10_t() {
        if (context_)
            ZSTD_freeCCtx(context_);
    }
    zstd_cctx_v10_t(const zstd_cctx_v10_t&) = delete;
    zstd_cctx_v10_t& operator=(const zstd_cctx_v10_t&) = delete;

    workspace_result_t<void> initialize(int level, const char* phase) {
        context_ = ZSTD_createCCtx();
        if (!context_) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "unable to allocate a zstd compression context", phase));
        }
        size_t status = ZSTD_CCtx_setParameter(
            context_, ZSTD_c_compressionLevel, level);
        if (ZSTD_isError(status)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "zstd compression level is unsupported", phase));
        }
        status = ZSTD_CCtx_setParameter(context_, ZSTD_c_checksumFlag, 1);
        if (ZSTD_isError(status)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::persistence_failure,
                "unable to enable the zstd frame checksum", phase));
        }
        status = ZSTD_CCtx_setParameter(context_, ZSTD_c_nbWorkers, 0);
        if (ZSTD_isError(status)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::persistence_failure,
                "unable to pin zstd to single-threaded compression", phase));
        }
        return workspace_result_t<void>::success();
    }

    ZSTD_CCtx* get() noexcept { return context_; }

private:
    ZSTD_CCtx* context_ = nullptr;
};

workspace_result_t<std::vector<std::uint8_t>> seal_pdb_payload_v10(
    const std::uint8_t* content, std::size_t content_size, std::uint32_t& codec,
    const packed_stop_predicate_t& stop_requested) {
    codec = packed_page_codec_raw;
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            cancelled_pdb_error_v10("workspace_schema_v10.seal_pdb_payload"));
    if (!content && content_size != 0) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "pdb payload content is null with a non-zero size",
                                 "workspace_schema_v10.seal_pdb_payload"));
    }
    std::vector<std::uint8_t> stored;
    if (content_size >= packed_page_compress_min_content_bytes) {
        zstd_cctx_v10_t context;
        auto initialized = context.initialize(
            static_cast<int>(packed_page_zstd_level_default),
            "workspace_schema_v10.seal_pdb_payload");
        if (!initialized)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                initialized.error());
        const std::size_t bound = ZSTD_compressBound(content_size);
        if (ZSTD_isError(bound)) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "pdb payload compression bound could not be computed",
                                     "workspace_schema_v10.seal_pdb_payload"));
        }
        std::vector<std::uint8_t> compressed;
        try {
            compressed.resize(bound);
        } catch (const std::bad_alloc&) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                                     "pdb payload compression allocation failed",
                                     "workspace_schema_v10.seal_pdb_payload"));
        }
        const std::size_t produced = ZSTD_compress2(
            context.get(), compressed.data(), compressed.size(),
            content, content_size);
        if (ZSTD_isError(produced)) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "pdb payload compression failed",
                                     "workspace_schema_v10.seal_pdb_payload"));
        }
        if (produced + packed_page_frame_header_size < content_size) {
            codec = packed_page_codec_zstd;
            compressed.resize(produced);
            stored = std::move(compressed);
        }
    }
    if (codec == packed_page_codec_raw && content_size != 0)
        stored.assign(content, content + content_size);
    std::vector<std::uint8_t> framed;
    try {
        framed.reserve(packed_page_frame_header_size + stored.size() +
                       sizeof(std::uint32_t));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "pdb payload frame allocation failed",
                                 "workspace_schema_v10.seal_pdb_payload"));
    }
    append_u32_le_v9(framed, packed_page_frame_magic);
    append_u32_le_v9(framed, codec);
    append_u64_le_v9(framed, static_cast<std::uint64_t>(content_size));
    framed.insert(framed.end(), stored.begin(), stored.end());
    auto checksum = crc32c_cancellable(framed.data(), framed.size(), stop_requested);
    if (!checksum)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            checksum.error());
    append_u32_le_v9(framed, checksum.value());
    return workspace_result_t<std::vector<std::uint8_t>>::success(
        std::move(framed));
}

workspace_result_t<std::vector<std::uint8_t>> open_pdb_payload_v10(
    const std::uint8_t* blob, std::size_t blob_size,
    std::uint32_t expected_codec, std::uint64_t expected_uncompressed_bytes,
    const packed_stop_predicate_t& stop_requested) {
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            cancelled_pdb_error_v10("workspace_schema_v10.open_pdb_payload"));
    static const std::uint64_t maximum_stored_bytes =
        packed_page_frame_header_size +
        ZSTD_compressBound(pdb_symbol_module_max_uncompressed_bytes) +
        sizeof(std::uint32_t);
    if (!blob ||
        blob_size < packed_page_frame_header_size + sizeof(std::uint32_t) ||
        static_cast<std::uint64_t>(blob_size) > maximum_stored_bytes) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "pdb payload blob shape is invalid",
                                 "workspace_schema_v10.open_pdb_payload"));
    }
    const std::uint32_t magic = read_u32_le_v9(blob);
    const std::uint32_t codec = read_u32_le_v9(blob + 4);
    const std::uint64_t content_length = read_u64_le_v9(blob + 8);
    if (magic != packed_page_frame_magic || codec != expected_codec ||
        (codec != packed_page_codec_raw && codec != packed_page_codec_zstd) ||
        content_length != expected_uncompressed_bytes ||
        content_length > pdb_symbol_module_max_uncompressed_bytes ||
        (codec == packed_page_codec_zstd && content_length == 0)) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "pdb payload frame header is invalid",
                                 "workspace_schema_v10.open_pdb_payload"));
    }
    if ((codec == packed_page_codec_raw &&
         blob_size != packed_page_frame_header_size +
             static_cast<std::size_t>(content_length) + sizeof(std::uint32_t)) ||
        (codec == packed_page_codec_zstd &&
         static_cast<std::uint64_t>(blob_size) >
             packed_page_frame_header_size + ZSTD_compressBound(content_length) +
                 sizeof(std::uint32_t))) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "pdb payload stored length is inconsistent",
                                 "workspace_schema_v10.open_pdb_payload"));
    }
    const std::uint32_t expected_checksum =
        read_u32_le_v9(blob + blob_size - sizeof(std::uint32_t));
    auto computed_checksum = crc32c_cancellable(
        blob, blob_size - sizeof(std::uint32_t), stop_requested);
    if (!computed_checksum)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            computed_checksum.error());
    if (computed_checksum.value() != expected_checksum) {
        auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                          "pdb payload checksum verification failed",
                                          "workspace_schema_v10.open_pdb_payload");
        error.details.emplace_back("expected_checksum",
                                   std::to_string(computed_checksum.value()));
        error.details.emplace_back("actual_checksum",
                                   std::to_string(expected_checksum));
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            std::move(error));
    }
    const std::uint8_t* stored = blob + packed_page_frame_header_size;
    const std::size_t stored_size =
        blob_size - packed_page_frame_header_size - sizeof(std::uint32_t);
    if (codec == packed_page_codec_raw) {
        return workspace_result_t<std::vector<std::uint8_t>>::success(
            std::vector<std::uint8_t>(stored, stored + stored_size));
    }
    std::vector<std::uint8_t> output;
    try {
        output.resize(static_cast<std::size_t>(content_length));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "pdb payload decompression allocation failed",
                                 "workspace_schema_v10.open_pdb_payload"));
    }
    const std::size_t produced = ZSTD_decompress(
        output.data(), output.size(), stored, stored_size);
    if (ZSTD_isError(produced) || produced != content_length) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "pdb payload decompression failed verification",
                                 "workspace_schema_v10.open_pdb_payload"));
    }
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            cancelled_pdb_error_v10("workspace_schema_v10.open_pdb_payload"));
    return workspace_result_t<std::vector<std::uint8_t>>::success(
        std::move(output));
}

workspace_result_t<void> create_snapshot_extension_slot_v9(
    sqlite3* database, const std::string& prefix) {
    const auto table = [&](const char* suffix) { return prefix + suffix; };
    std::string sql;
    sql.reserve(16384);
    sql += "CREATE TABLE IF NOT EXISTS " + table("call_graph_state") +
        "(singleton INTEGER PRIMARY KEY CHECK(singleton=1),indirect_site_count INTEGER NOT NULL,unresolved_site_count INTEGER NOT NULL,bounded INTEGER NOT NULL CHECK(bounded IN (0,1)));";
    sql += "CREATE TABLE IF NOT EXISTS " + table("call_graph_nodes") +
        "(function_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,incoming_edges INTEGER NOT NULL,outgoing_edges INTEGER NOT NULL,indirect_edges INTEGER NOT NULL,unresolved_sites INTEGER NOT NULL);";
    sql += "CREATE INDEX IF NOT EXISTS " + table("call_graph_nodes_address") +
        " ON " + table("call_graph_nodes") +
        "(address_space,address_value,address_arch,address_mode);";
    sql += "CREATE TABLE IF NOT EXISTS " + table("call_sites") +
        "(entity_id INTEGER PRIMARY KEY,source_function_id INTEGER NOT NULL,source_block_id INTEGER NOT NULL,instruction_id INTEGER NOT NULL,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,first_candidate INTEGER NOT NULL,candidate_count INTEGER NOT NULL,indirect INTEGER NOT NULL CHECK(indirect IN (0,1)),tail_call INTEGER NOT NULL CHECK(tail_call IN (0,1)),unresolved INTEGER NOT NULL CHECK(unresolved IN (0,1)));";
    sql += "CREATE INDEX IF NOT EXISTS " + table("call_sites_source") +
        " ON " + table("call_sites") +
        "(source_function_id,address_value);";
    sql += "CREATE TABLE IF NOT EXISTS " + table("call_candidates") +
        "(entity_id INTEGER PRIMARY KEY,call_site_id INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,target_function_id INTEGER,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,contributor_count INTEGER NOT NULL,conflicted INTEGER NOT NULL CHECK(conflicted IN (0,1)),stable_source_id INTEGER NOT NULL,rank INTEGER NOT NULL,external_target INTEGER NOT NULL CHECK(external_target IN (0,1)));";
    sql += "CREATE INDEX IF NOT EXISTS " + table("call_candidates_site") +
        " ON " + table("call_candidates") + "(call_site_id,rank);";
    sql += "CREATE TABLE IF NOT EXISTS " + table("call_graph_edges") +
        "(entity_id INTEGER PRIMARY KEY,call_site_id INTEGER NOT NULL,source_function_id INTEGER NOT NULL,source_block_id INTEGER NOT NULL,target_function_id INTEGER,call_site_space INTEGER NOT NULL,call_site_value INTEGER NOT NULL,call_site_arch INTEGER NOT NULL,call_site_mode INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,resolution INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,contributor_count INTEGER NOT NULL,conflicted INTEGER NOT NULL CHECK(conflicted IN (0,1)),candidate_rank INTEGER NOT NULL,external_target INTEGER NOT NULL CHECK(external_target IN (0,1)),target_noreturn INTEGER NOT NULL CHECK(target_noreturn IN (0,1)));";
    sql += "CREATE INDEX IF NOT EXISTS " + table("call_graph_edges_source") +
        " ON " + table("call_graph_edges") +
        "(source_function_id,call_site_value);";
    sql += "CREATE INDEX IF NOT EXISTS " + table("call_graph_edges_target") +
        " ON " + table("call_graph_edges") +
        "(target_function_id,target_value);";
    sql += "CREATE TABLE IF NOT EXISTS " + table("call_graph_conflicts") +
        "(entity_id INTEGER PRIMARY KEY,kind INTEGER NOT NULL,instruction_id INTEGER NOT NULL,source_function_id INTEGER NOT NULL,call_site_rva INTEGER NOT NULL,selected_target_rva INTEGER NOT NULL,competing_target_rva INTEGER NOT NULL,selected_target_function_id INTEGER NOT NULL,competing_target_function_id INTEGER NOT NULL);";
    sql += "CREATE TABLE IF NOT EXISTS " + table("rich_data_candidates") +
        "(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,size INTEGER NOT NULL,kind INTEGER NOT NULL,target_space INTEGER,target_value INTEGER,target_arch INTEGER,target_mode INTEGER,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,CHECK((target_space IS NULL AND target_value IS NULL AND target_arch IS NULL AND target_mode IS NULL) OR (target_space IS NOT NULL AND target_value IS NOT NULL AND target_arch IS NOT NULL AND target_mode IS NOT NULL)));";
    sql += "CREATE INDEX IF NOT EXISTS " + table("rich_data_candidates_address") +
        " ON " + table("rich_data_candidates") +
        "(address_space,address_value,address_arch,address_mode);";
    sql += "CREATE TABLE IF NOT EXISTS " + table("data_pointer_facts") +
        "(entity_id INTEGER PRIMARY KEY,slot_space INTEGER NOT NULL,slot_value INTEGER NOT NULL,slot_arch INTEGER NOT NULL,slot_mode INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,candidate_kind INTEGER NOT NULL,encoding INTEGER NOT NULL,width_bytes INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);";
    sql += "CREATE INDEX IF NOT EXISTS " + table("data_pointer_facts_slot") +
        " ON " + table("data_pointer_facts") +
        "(slot_space,slot_value,slot_arch,slot_mode);";
    sql += "CREATE TABLE IF NOT EXISTS " + table("data_conflicts") +
        "(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,kind INTEGER NOT NULL,selected_target_space INTEGER,selected_target_value INTEGER,selected_target_arch INTEGER,selected_target_mode INTEGER,rejected_target_space INTEGER,rejected_target_value INTEGER,rejected_target_arch INTEGER,rejected_target_mode INTEGER,selected_provenance INTEGER NOT NULL,rejected_provenance INTEGER NOT NULL,selected_confidence INTEGER NOT NULL,rejected_confidence INTEGER NOT NULL,CHECK((selected_target_space IS NULL AND selected_target_value IS NULL AND selected_target_arch IS NULL AND selected_target_mode IS NULL) OR (selected_target_space IS NOT NULL AND selected_target_value IS NOT NULL AND selected_target_arch IS NOT NULL AND selected_target_mode IS NOT NULL)),CHECK((rejected_target_space IS NULL AND rejected_target_value IS NULL AND rejected_target_arch IS NULL AND rejected_target_mode IS NULL) OR (rejected_target_space IS NOT NULL AND rejected_target_value IS NOT NULL AND rejected_target_arch IS NOT NULL AND rejected_target_mode IS NOT NULL)));";
    sql += "CREATE TABLE IF NOT EXISTS " + table("symbol_type_candidates") +
        "(entity_id INTEGER PRIMARY KEY,address_space INTEGER,address_value INTEGER,address_arch INTEGER,address_mode INTEGER,related_space INTEGER,related_value INTEGER,related_arch INTEGER,related_mode INTEGER,kind INTEGER NOT NULL,display_name TEXT NOT NULL,canonical_type TEXT NOT NULL,source_key TEXT NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,explicitly_unknown INTEGER NOT NULL CHECK(explicitly_unknown IN (0,1)),CHECK((address_space IS NULL AND address_value IS NULL AND address_arch IS NULL AND address_mode IS NULL) OR (address_space IS NOT NULL AND address_value IS NOT NULL AND address_arch IS NOT NULL AND address_mode IS NOT NULL)),CHECK((related_space IS NULL AND related_value IS NULL AND related_arch IS NULL AND related_mode IS NULL) OR (related_space IS NOT NULL AND related_value IS NOT NULL AND related_arch IS NOT NULL AND related_mode IS NOT NULL)));";
    sql += "CREATE INDEX IF NOT EXISTS " + table("symbol_type_candidates_address") +
        " ON " + table("symbol_type_candidates") +
        "(address_space,address_value,address_arch,address_mode);";
    sql += "CREATE TABLE IF NOT EXISTS " + table("type_references") +
        "(entity_id INTEGER PRIMARY KEY,source_space INTEGER,source_value INTEGER,source_arch INTEGER,source_mode INTEGER,target_space INTEGER,target_value INTEGER,target_arch INTEGER,target_mode INTEGER,source_entity INTEGER NOT NULL,target_entity INTEGER NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,source_key TEXT NOT NULL,CHECK((source_space IS NULL AND source_value IS NULL AND source_arch IS NULL AND source_mode IS NULL) OR (source_space IS NOT NULL AND source_value IS NOT NULL AND source_arch IS NOT NULL AND source_mode IS NOT NULL)),CHECK((target_space IS NULL AND target_value IS NULL AND target_arch IS NULL AND target_mode IS NULL) OR (target_space IS NOT NULL AND target_value IS NOT NULL AND target_arch IS NOT NULL AND target_mode IS NOT NULL)));";
    sql += "CREATE INDEX IF NOT EXISTS " + table("type_references_entities") +
        " ON " + table("type_references") +
        "(source_entity,target_entity,kind);";
    sql += "CREATE TABLE IF NOT EXISTS " + table("metadata_conflicts") +
        "(entity_id INTEGER PRIMARY KEY,address_space INTEGER,address_value INTEGER,address_arch INTEGER,address_mode INTEGER,identity TEXT NOT NULL,kind INTEGER NOT NULL,selected_value TEXT NOT NULL,rejected_value TEXT NOT NULL,selected_provenance INTEGER NOT NULL,rejected_provenance INTEGER NOT NULL,selected_confidence INTEGER NOT NULL,rejected_confidence INTEGER NOT NULL,CHECK((address_space IS NULL AND address_value IS NULL AND address_arch IS NULL AND address_mode IS NULL) OR (address_space IS NOT NULL AND address_value IS NOT NULL AND address_arch IS NOT NULL AND address_mode IS NOT NULL)));";
    sql += "CREATE INDEX IF NOT EXISTS " + table("metadata_conflicts_identity") +
        " ON " + table("metadata_conflicts") + "(identity,kind);";
    return exec_sql_v9(database, sql.c_str(),
                       "workspace_schema_v9.snapshot_extensions");
}

workspace_result_t<void> backfill_snapshot_extension_slot_v9(
    sqlite3* database, const std::string& prefix) {
    const auto table = [&](const char* suffix) { return prefix + suffix; };
    auto data_source = table_exists_v9(database, table("data_candidates"));
    if (!data_source)
        return workspace_result_t<void>::failure(data_source.error());
    if (data_source.value()) {
        const std::string sql =
            "INSERT OR IGNORE INTO " + table("rich_data_candidates") +
            "(entity_id,address_space,address_value,address_arch,address_mode,size,kind,target_space,target_value,target_arch,target_mode,provenance,confidence) "
            "SELECT entity_id,address_space,address_value,address_arch,address_mode,size,kind,target_space,target_value,target_arch,target_mode,provenance,confidence FROM " +
            table("data_candidates") + ";";
        auto result = exec_sql_v9(database, sql.c_str(),
                                  "workspace_schema_v9.backfill_rich_data");
        if (!result)
            return result;
    }
    auto type_source = table_exists_v9(database, table("type_candidates"));
    if (!type_source)
        return workspace_result_t<void>::failure(type_source.error());
    if (type_source.value()) {
        const std::string sql =
            "INSERT OR IGNORE INTO " + table("symbol_type_candidates") +
            "(entity_id,address_space,address_value,address_arch,address_mode,related_space,related_value,related_arch,related_mode,kind,display_name,canonical_type,source_key,provenance,confidence,explicitly_unknown) "
            "SELECT entity_id,address_space,address_value,address_arch,address_mode,NULL,NULL,NULL,NULL,kind,display_name,canonical_type,'schema-v8:'||CAST(entity_id AS TEXT),CASE provenance WHEN 4 THEN 2 WHEN 6 THEN 5 WHEN 10 THEN 6 WHEN 1 THEN 1 WHEN 3 THEN 1 WHEN 5 THEN 1 ELSE 3 END,confidence,explicitly_unknown FROM " +
            table("type_candidates") + ";";
        auto result = exec_sql_v9(database, sql.c_str(),
                                  "workspace_schema_v9.backfill_symbol_types");
        if (!result)
            return result;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<bool> rich_backfill_complete_v9(sqlite3* database) {
    auto metadata = table_exists_v9(database, "metadata");
    if (!metadata)
        return workspace_result_t<bool>::failure(metadata.error());
    if (!metadata.value())
        return workspace_result_t<bool>::success(false);
    v9_statement_t statement;
    auto result = statement.prepare(database,
        "SELECT 1 FROM metadata WHERE key='schema_v9_rich_backfill_complete' AND value='1'",
        "workspace_schema_v9.rich_backfill_state");
    if (!result)
        return workspace_result_t<bool>::failure(result.error());
    const int status = sqlite3_step(statement.get());
    if (status == SQLITE_ROW)
        return workspace_result_t<bool>::success(true);
    if (status == SQLITE_DONE)
        return workspace_result_t<bool>::success(false);
    return workspace_result_t<bool>::failure(schema_v9_error(
        database, status, "unable to inspect rich-fact backfill state",
        "workspace_schema_v9.rich_backfill_state"));
}

workspace_result_t<void> mark_rich_backfill_complete_v9(sqlite3* database) {
    auto metadata = table_exists_v9(database, "metadata");
    if (!metadata)
        return workspace_result_t<void>::failure(metadata.error());
    if (!metadata.value())
        return workspace_result_t<void>::success();
    return exec_sql_v9(database,
        "INSERT INTO metadata(key,value) VALUES('schema_v9_rich_backfill_complete','1') ON CONFLICT(key) DO UPDATE SET value='1'",
        "workspace_schema_v9.rich_backfill_state");
}

workspace_result_t<void> validate_publication_v9(
    const packed_generation_publication_t& publication,
    const packed_publish_stop_predicate_t& stop_requested = {}) {
    const auto& generation = publication.generation;
    if (generation.generation == 0 || generation.committed ||
        generation.shard_count == 0 ||
        generation.shard_count >
            static_cast<std::uint16_t>(packed_page_last_data_type) ||
        publication.pages.empty() ||
        publication.pages.size() > packed_generation_max_pages ||
        publication.index.size() != publication.pages.size() ||
        publication.index.size() > packed_generation_max_index_rows ||
        generation.payload_blob.size() > packed_generation_max_metadata_bytes) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "packed publication shape exceeds its bounded invariants",
                                 "workspace_schema_v9.publish_atomic"));
    }
    std::uint64_t total_payload_bytes = 0;
    std::uint64_t total_records = 0;
    std::vector<packed_record_page_prefix_t> prefixes;
    prefixes.reserve(publication.pages.size());
    std::array<std::uint64_t,
               static_cast<std::size_t>(packed_page_last_data_type) + 1U>
        next_domain_ordinals{};
    std::vector<std::uint8_t> checksum_bytes;
    checksum_bytes.reserve(publication.pages.size() * sizeof(std::uint32_t));
    for (std::size_t page_index = 0;
         page_index < publication.pages.size(); ++page_index) {
        if (publish_stop_requested_v9(stop_requested))
            return cancelled_publish_error();
        const auto& row = publication.pages[page_index];
        const auto expected_page_index = static_cast<std::uint32_t>(page_index);
        const auto expected_page_count =
            static_cast<std::uint32_t>(publication.pages.size());
        if (row.generation != generation.generation ||
            row.page_index != expected_page_index ||
            row.page_count != expected_page_count ||
            row.page_type < static_cast<std::uint32_t>(packed_page_type_t::instructions) ||
            row.page_type > static_cast<std::uint32_t>(packed_page_last_data_type) ||
            row.payload.size() > packed_page_max_payload ||
            row.payload_length != row.payload.size()) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "packed page does not belong to the publication",
                                     "workspace_schema_v9.publish_atomic"));
        }
        packed_page_t page;
        page.header.page_type = row.page_type;
        page.header.page_index = row.page_index;
        page.header.page_count = row.page_count;
        page.header.generation = row.generation;
        page.header.analysis_revision = generation.analysis_revision;
        page.header.overlay_revision = generation.overlay_revision;
        page.header.payload_length = row.payload_length;
        page.header.checksum = row.checksum;
        auto copied = copy_blob_v9(page.payload, row.payload.data(),
                                   row.payload.size(), stop_requested,
                                   "workspace_schema_v9.publish_atomic");
        if (!copied)
            return copied;
        auto verified = packed_page_codec_t::verify_page(page, stop_requested);
        if (!verified)
            return verified;
        auto prefix = packed_record_page_prefix_t::decode(
            page.payload.data(), page.payload.size());
        const auto domain_index = static_cast<std::size_t>(row.page_type);
        std::uint64_t next_domain_ordinal = 0;
        if (!prefix || !checked_add_u64(total_records, prefix->record_count,
                                        total_records) ||
            total_records > packed_generation_max_records ||
            prefix->ordinal_begin != next_domain_ordinals[domain_index] ||
            !checked_add_u64(next_domain_ordinals[domain_index],
                             prefix->record_count, next_domain_ordinal)) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "packed publication record metadata is invalid",
                                     "workspace_schema_v9.publish_atomic"));
        }
        next_domain_ordinals[domain_index] = next_domain_ordinal;
        prefixes.push_back(*prefix);
        if (!checked_add_u64(total_payload_bytes, row.payload.size(),
                             total_payload_bytes) ||
            total_payload_bytes > packed_generation_max_payload_bytes) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                                     "packed publication payload exceeds its bounded byte limit",
                                     "workspace_schema_v9.publish_atomic"));
        }
        append_u32_le_v9(checksum_bytes, row.checksum);
    }
    if (publish_stop_requested_v9(stop_requested))
        return cancelled_publish_error();
    auto observed_batch_checksum = crc32c_cancellable(
        checksum_bytes.data(), checksum_bytes.size(), stop_requested);
    if (!observed_batch_checksum)
        return workspace_result_t<void>::failure(observed_batch_checksum.error());
    if (generation.total_records != total_records ||
        generation.total_payload_bytes != total_payload_bytes ||
        generation.batch_checksum != observed_batch_checksum.value()) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "packed publication checkpoint does not match its pages",
                                 "workspace_schema_v9.publish_atomic"));
    }

    std::unordered_set<std::uint16_t> domains;
    std::vector<bool> indexed(publication.pages.size(), false);
    for (const auto& row : publication.index) {
        if (publish_stop_requested_v9(stop_requested))
            return cancelled_publish_error();
        if (row.generation != generation.generation ||
            static_cast<std::size_t>(row.page_index) >= publication.pages.size() ||
            indexed[row.page_index]) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "packed page index ownership or uniqueness is invalid",
                                     "workspace_schema_v9.publish_atomic"));
        }
        const auto& page = publication.pages[row.page_index];
        const auto& prefix = prefixes[row.page_index];
        if (row.domain != static_cast<std::uint16_t>(page.page_type) ||
            row.count != prefix.record_count ||
            row.ordinal_begin != prefix.ordinal_begin ||
            row.address_value_min != prefix.address_value_min ||
            row.address_value_max != prefix.address_value_max) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "packed page index does not describe its page",
                                     "workspace_schema_v9.publish_atomic"));
        }
        indexed[row.page_index] = true;
        domains.insert(row.domain);
    }
    if (domains.size() != static_cast<std::size_t>(generation.shard_count)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "packed publication shard count is inconsistent",
                                 "workspace_schema_v9.publish_atomic"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_staged_generation_v9(
    sqlite3* database,
    const packed_generation_record_t& generation,
    const packed_publish_stop_predicate_t& stop_requested) {
    if (!database || generation.generation == 0 || generation.committed ||
        generation.shard_count == 0 ||
        generation.shard_count >
            static_cast<std::uint16_t>(packed_page_last_data_type) ||
        generation.total_payload_bytes > packed_generation_max_payload_bytes ||
        generation.total_records > packed_generation_max_records) {
        return workspace_result_t<void>::failure(
            make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "staged packed generation metadata is invalid",
                "workspace_schema_v9.publish_packed_generation"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
SELECT p.generation,p.page_index,p.page_count,p.page_type,p.payload_length,p.checksum,p.payload,
       i.domain,i.ordinal_begin,i.count,i.address_value_min,i.address_value_max,p.logical_length
FROM packed_pages p
JOIN packed_page_index i ON i.generation=p.generation AND i.page_index=p.page_index
WHERE p.generation=?1
ORDER BY p.page_index
)SQL", "workspace_schema_v9.publish_packed_generation.validate");
    if (!result)
        return result;
    result = statement.bind_uint(1, generation.generation);
    if (!result)
        return result;

    std::uint32_t expected_page_count = 0;
    std::uint32_t next_page_index = 0;
    std::uint64_t observed_payload_bytes = 0;
    std::uint64_t observed_records = 0;
    std::unordered_set<std::uint16_t> domains;
    std::array<std::uint64_t,
               static_cast<std::size_t>(packed_page_last_data_type) + 1U>
        next_domain_ordinals{};
    std::vector<std::uint8_t> checksum_bytes;
    for (;;) {
        if (publish_stop_requested_v9(stop_requested))
            return cancelled_publish_error();
        const int status = sqlite3_step(statement.get());
        if (status == SQLITE_DONE)
            break;
        if (status != SQLITE_ROW) {
            return workspace_result_t<void>::failure(
                schema_v9_error(
                    database, status,
                    "unable to validate staged packed generation",
                    "workspace_schema_v9.publish_packed_generation"));
        }
        const auto page_generation = static_cast<std::uint64_t>(
            sqlite3_column_int64(statement.get(), 0));
        const auto page_index = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 1));
        const auto page_count = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 2));
        const auto page_type = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 3));
        const auto payload_length = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 4));
        const auto page_checksum = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 5));
        const auto domain = static_cast<std::uint16_t>(
            sqlite3_column_int(statement.get(), 7));
        const auto ordinal_begin = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 8));
        const auto record_count = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 9));
        const auto address_value_min = static_cast<std::uint64_t>(
            sqlite3_column_int64(statement.get(), 10));
        const auto address_value_max = static_cast<std::uint64_t>(
            sqlite3_column_int64(statement.get(), 11));
        std::uint32_t logical_length = 0;
        if (sqlite3_column_type(statement.get(), 12) != SQLITE_NULL) {
            const auto declared_logical_length =
                sqlite3_column_int64(statement.get(), 12);
            if (declared_logical_length <
                    static_cast<std::int64_t>(packed_record_page_prefix_size) ||
                declared_logical_length >
                    static_cast<std::int64_t>(packed_page_max_payload)) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "staged packed page logical length is invalid",
                        "workspace_schema_v9.publish_packed_generation"));
            }
            logical_length = static_cast<std::uint32_t>(declared_logical_length);
        }
        const void* blob = sqlite3_column_blob(statement.get(), 6);
        const int blob_size = sqlite3_column_bytes(statement.get(), 6);
        if (page_generation != generation.generation ||
            page_index != next_page_index || page_count == 0 ||
            page_count > packed_generation_max_pages ||
            (expected_page_count != 0 && page_count != expected_page_count) ||
            page_type < static_cast<std::uint32_t>(
                packed_page_type_t::instructions) ||
            page_type > static_cast<std::uint32_t>(packed_page_last_data_type) ||
            domain != static_cast<std::uint16_t>(page_type) ||
            blob_size < static_cast<int>(packed_record_page_prefix_size) ||
            blob_size > static_cast<int>(packed_page_max_payload) || !blob ||
            payload_length != static_cast<std::uint32_t>(blob_size)) {
            return workspace_result_t<void>::failure(
                make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "staged packed page identity or shape is invalid",
                    "workspace_schema_v9.publish_packed_generation"));
        }
        expected_page_count = page_count;
        packed_page_t page;
        page.header.generation = page_generation;
        page.header.analysis_revision = generation.analysis_revision;
        page.header.overlay_revision = generation.overlay_revision;
        page.header.version = logical_length != 0
            ? packed_page_blob_version_v3 : packed_page_blob_version;
        page.header.page_type = page_type;
        page.header.page_index = page_index;
        page.header.page_count = page_count;
        page.header.payload_length = payload_length;
        page.header.checksum = page_checksum;
        auto copied = copy_blob_v9(
            page.payload, static_cast<const std::uint8_t*>(blob),
            static_cast<std::size_t>(blob_size), stop_requested,
            "workspace_schema_v9.publish_packed_generation");
        if (!copied)
            return copied;
        auto verified = packed_page_codec_t::verify_page(page, stop_requested);
        if (!verified)
            return verified;
        if (logical_length != 0) {
            const auto frame_content_length = packed_page_frame_content_length_v9(
                page.payload.data(), page.payload.size());
            if (!frame_content_length ||
                *frame_content_length + packed_record_page_prefix_size !=
                    logical_length) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "staged packed page logical length does not match its frame",
                        "workspace_schema_v9.publish_packed_generation"));
            }
        }
        auto prefix = packed_record_page_prefix_t::decode(
            page.payload.data(), page.payload.size());
        const auto domain_index = static_cast<std::size_t>(page_type);
        std::uint64_t next_domain_ordinal = 0;
        const std::uint64_t logical_bytes = logical_length != 0
            ? static_cast<std::uint64_t>(logical_length)
            : static_cast<std::uint64_t>(page.payload.size());
        if (!prefix || ordinal_begin != prefix->ordinal_begin ||
            record_count != prefix->record_count ||
            address_value_min != prefix->address_value_min ||
            address_value_max != prefix->address_value_max ||
            prefix->ordinal_begin != next_domain_ordinals[domain_index] ||
            !checked_add_u64(next_domain_ordinals[domain_index],
                             prefix->record_count, next_domain_ordinal) ||
            !checked_add_u64(observed_payload_bytes, logical_bytes,
                             observed_payload_bytes) ||
            observed_payload_bytes > packed_generation_max_payload_bytes ||
            !checked_add_u64(observed_records, prefix->record_count,
                             observed_records) ||
            observed_records > packed_generation_max_records) {
            return workspace_result_t<void>::failure(
                make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "staged packed page metadata is inconsistent",
                    "workspace_schema_v9.publish_packed_generation"));
        }
        next_domain_ordinals[domain_index] = next_domain_ordinal;
        append_u32_le_v9(checksum_bytes, page_checksum);
        domains.insert(domain);
        ++next_page_index;
    }
    if (next_page_index == 0 || next_page_index != expected_page_count ||
        domains.size() != generation.shard_count ||
        observed_payload_bytes != generation.total_payload_bytes ||
        observed_records != generation.total_records) {
        return workspace_result_t<void>::failure(
            make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "staged packed generation totals are inconsistent",
                "workspace_schema_v9.publish_packed_generation"));
    }
    auto checksum = crc32c_cancellable(
        checksum_bytes.data(), checksum_bytes.size(), stop_requested);
    if (!checksum)
        return workspace_result_t<void>::failure(checksum.error());
    if (checksum.value() != generation.batch_checksum) {
        return workspace_result_t<void>::failure(
            make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "staged packed generation checksum is inconsistent",
                "workspace_schema_v9.publish_packed_generation"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> delete_uncommitted_rows_v9(sqlite3* database,
                                                     std::uint64_t generation) {
    v9_statement_t pages;
    auto result = pages.prepare(database,
        "DELETE FROM packed_pages WHERE generation=?1 AND EXISTS(SELECT 1 FROM packed_generations g WHERE g.generation=?1 AND g.committed=0)",
        "workspace_schema_v9.rollback.pages");
    if (!result) return result;
    result = pages.bind_uint(1, generation); if (!result) return result;
    result = pages.step_done(); if (!result) return result;
    v9_statement_t index;
    result = index.prepare(database,
        "DELETE FROM packed_page_index WHERE generation=?1 AND EXISTS(SELECT 1 FROM packed_generations g WHERE g.generation=?1 AND g.committed=0)",
        "workspace_schema_v9.rollback.index");
    if (!result) return result;
    result = index.bind_uint(1, generation); if (!result) return result;
    result = index.step_done(); if (!result) return result;
    v9_statement_t manifest;
    result = manifest.prepare(database,
        "DELETE FROM packed_generations WHERE generation=?1 AND committed=0",
        "workspace_schema_v9.rollback.generation");
    if (!result) return result;
    result = manifest.bind_uint(1, generation); if (!result) return result;
    return manifest.step_done();
}

}

workspace_result_t<void> ensure_managed_overlay_identity_schema_v9(
    sqlite3* database) {
    if (!database) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "managed overlay schema migration requires an open database",
            "workspace_schema_v9.managed_overlay"));
    }
    auto savepoint = exec_sql_v9(
        database, "SAVEPOINT aida_managed_overlay_schema_v9",
        "workspace_schema_v9.managed_overlay.begin");
    if (!savepoint)
        return savepoint;
    auto migrated = [&]() -> workspace_result_t<void> {
    const auto has_column = [database](const char* table,
                                       const char* column)
        -> workspace_result_t<bool> {
        const std::string sql = std::string("PRAGMA table_info(") + table + ")";
        v9_statement_t statement;
        auto result = statement.prepare(
            database, sql.c_str(), "workspace_schema_v9.managed_overlay");
        if (!result)
            return workspace_result_t<bool>::failure(result.error());
        for (;;) {
            const int status = sqlite3_step(statement.get());
            if (status == SQLITE_DONE)
                return workspace_result_t<bool>::success(false);
            if (status != SQLITE_ROW) {
                return workspace_result_t<bool>::failure(schema_v9_error(
                    database, status,
                    "unable to inspect managed overlay schema",
                    "workspace_schema_v9.managed_overlay"));
            }
            if (column_text_v9(statement.get(), 1) == column)
                return workspace_result_t<bool>::success(true);
        }
    };
    auto operations = has_column(
        "overlay_operations", "target_discriminator");
    if (!operations)
        return workspace_result_t<void>::failure(operations.error());
    if (!operations.value()) {
        auto result = exec_sql_v9(database, R"SQL(
DROP TABLE IF EXISTS overlay_operations_managed_v9_upgrade;
CREATE TABLE overlay_operations_managed_v9_upgrade(
    transaction_id INTEGER NOT NULL,
    operation_index INTEGER NOT NULL,
    kind INTEGER NOT NULL,
    entity_key TEXT NOT NULL,
    target_discriminator INTEGER NOT NULL CHECK(
        typeof(target_discriminator)='integer' AND
        target_discriminator IN (0,1)),
    address_space INTEGER,
    address_value INTEGER,
    address_arch INTEGER,
    address_mode INTEGER,
    managed_workspace_id BLOB,
    managed_provider_hash BLOB,
    managed_provider_size INTEGER,
    managed_artifact_hash BLOB,
    managed_generation INTEGER,
    managed_entity_hash BLOB,
    managed_entity_key BLOB,
    before_json TEXT,
    after_json TEXT NOT NULL,
    PRIMARY KEY(transaction_id,operation_index),
    FOREIGN KEY(transaction_id) REFERENCES overlay_transactions(transaction_id) ON DELETE CASCADE,
    CHECK(
        (target_discriminator=0 AND typeof(address_space)='integer' AND
         typeof(address_value)='integer' AND typeof(address_arch)='integer' AND
         typeof(address_mode)='integer' AND managed_workspace_id IS NULL AND
         managed_provider_hash IS NULL AND managed_provider_size IS NULL AND
         managed_artifact_hash IS NULL AND managed_generation IS NULL AND
         managed_entity_hash IS NULL AND managed_entity_key IS NULL) OR
        (target_discriminator=1 AND address_space IS NULL AND
         address_value IS NULL AND address_arch IS NULL AND
         address_mode IS NULL AND typeof(managed_workspace_id)='blob' AND
         length(managed_workspace_id)=32 AND
         typeof(managed_provider_hash)='blob' AND
         length(managed_provider_hash)=32 AND
         typeof(managed_provider_size)='integer' AND
         managed_provider_size>0 AND
         typeof(managed_artifact_hash)='blob' AND
         length(managed_artifact_hash)=32 AND
         typeof(managed_generation)='integer' AND managed_generation>0 AND
         typeof(managed_entity_hash)='blob' AND
         length(managed_entity_hash)=32 AND
         typeof(managed_entity_key)='blob' AND
         length(managed_entity_key) BETWEEN 1 AND 16384)
    )
);
INSERT INTO overlay_operations_managed_v9_upgrade(
    transaction_id,operation_index,kind,entity_key,target_discriminator,
    address_space,address_value,address_arch,address_mode,
    managed_workspace_id,managed_provider_hash,managed_provider_size,
    managed_artifact_hash,managed_generation,managed_entity_hash,
    managed_entity_key,before_json,after_json)
SELECT transaction_id,operation_index,kind,entity_key,0,
       address_space,address_value,address_arch,address_mode,
       NULL,NULL,NULL,NULL,NULL,NULL,NULL,before_json,after_json
FROM overlay_operations;
DROP TABLE overlay_operations;
ALTER TABLE overlay_operations_managed_v9_upgrade RENAME TO overlay_operations;
CREATE INDEX overlay_operations_entity ON overlay_operations(entity_key,transaction_id);
CREATE INDEX overlay_operations_native_address ON overlay_operations(
    address_space,address_value,address_arch,address_mode,kind,transaction_id)
    WHERE target_discriminator=0;
CREATE INDEX overlay_operations_managed_entity ON overlay_operations(
    managed_workspace_id,managed_provider_hash,managed_artifact_hash,
    managed_entity_hash,managed_generation,kind,transaction_id)
    WHERE target_discriminator=1;
)SQL", "workspace_schema_v9.managed_overlay.operations");
        if (!result)
            return result;
    }
    auto items = has_column("overlay_items", "target_discriminator");
    if (!items)
        return workspace_result_t<void>::failure(items.error());
    if (!items.value()) {
        auto result = exec_sql_v9(database, R"SQL(
DROP TABLE IF EXISTS overlay_items_managed_v9_upgrade;
CREATE TABLE overlay_items_managed_v9_upgrade(
    entity_key TEXT PRIMARY KEY NOT NULL,
    kind INTEGER NOT NULL,
    target_discriminator INTEGER NOT NULL CHECK(
        typeof(target_discriminator)='integer' AND
        target_discriminator IN (0,1)),
    address_space INTEGER,
    address_value INTEGER,
    address_arch INTEGER,
    address_mode INTEGER,
    managed_workspace_id BLOB,
    managed_provider_hash BLOB,
    managed_provider_size INTEGER,
    managed_artifact_hash BLOB,
    managed_generation INTEGER,
    managed_entity_hash BLOB,
    managed_entity_key BLOB,
    payload_json TEXT NOT NULL,
    updated_revision INTEGER NOT NULL,
    CHECK(
        (target_discriminator=0 AND typeof(address_space)='integer' AND
         typeof(address_value)='integer' AND typeof(address_arch)='integer' AND
         typeof(address_mode)='integer' AND managed_workspace_id IS NULL AND
         managed_provider_hash IS NULL AND managed_provider_size IS NULL AND
         managed_artifact_hash IS NULL AND managed_generation IS NULL AND
         managed_entity_hash IS NULL AND managed_entity_key IS NULL) OR
        (target_discriminator=1 AND address_space IS NULL AND
         address_value IS NULL AND address_arch IS NULL AND
         address_mode IS NULL AND typeof(managed_workspace_id)='blob' AND
         length(managed_workspace_id)=32 AND
         typeof(managed_provider_hash)='blob' AND
         length(managed_provider_hash)=32 AND
         typeof(managed_provider_size)='integer' AND
         managed_provider_size>0 AND
         typeof(managed_artifact_hash)='blob' AND
         length(managed_artifact_hash)=32 AND
         typeof(managed_generation)='integer' AND managed_generation>0 AND
         typeof(managed_entity_hash)='blob' AND
         length(managed_entity_hash)=32 AND
         typeof(managed_entity_key)='blob' AND
         length(managed_entity_key) BETWEEN 1 AND 16384)
    )
);
INSERT INTO overlay_items_managed_v9_upgrade(
    entity_key,kind,target_discriminator,address_space,address_value,
    address_arch,address_mode,managed_workspace_id,managed_provider_hash,
    managed_provider_size,managed_artifact_hash,managed_generation,
    managed_entity_hash,managed_entity_key,payload_json,updated_revision)
SELECT entity_key,kind,0,address_space,address_value,address_arch,address_mode,
       NULL,NULL,NULL,NULL,NULL,NULL,NULL,payload_json,updated_revision
FROM overlay_items;
DROP TABLE overlay_items;
ALTER TABLE overlay_items_managed_v9_upgrade RENAME TO overlay_items;
CREATE INDEX overlay_items_address ON overlay_items(
    address_space,address_value,address_arch,address_mode,kind)
    WHERE target_discriminator=0;
CREATE INDEX overlay_items_managed_entity ON overlay_items(
    managed_workspace_id,managed_provider_hash,managed_artifact_hash,
    managed_entity_hash,managed_generation,kind)
    WHERE target_discriminator=1;
)SQL", "workspace_schema_v9.managed_overlay.items");
        if (!result)
            return result;
    }
    return exec_sql_v9(database, R"SQL(
CREATE INDEX IF NOT EXISTS overlay_operations_entity ON overlay_operations(entity_key,transaction_id);
CREATE INDEX IF NOT EXISTS overlay_operations_native_address ON overlay_operations(
    address_space,address_value,address_arch,address_mode,kind,transaction_id)
    WHERE target_discriminator=0;
CREATE INDEX IF NOT EXISTS overlay_operations_managed_entity ON overlay_operations(
    managed_workspace_id,managed_provider_hash,managed_artifact_hash,
    managed_entity_hash,managed_generation,kind,transaction_id)
    WHERE target_discriminator=1;
CREATE INDEX IF NOT EXISTS overlay_items_address ON overlay_items(
    address_space,address_value,address_arch,address_mode,kind)
    WHERE target_discriminator=0;
CREATE INDEX IF NOT EXISTS overlay_items_managed_entity ON overlay_items(
    managed_workspace_id,managed_provider_hash,managed_artifact_hash,
    managed_entity_hash,managed_generation,kind)
    WHERE target_discriminator=1;
)SQL", "workspace_schema_v9.managed_overlay.indexes");
    }();
    if (!migrated) {
        auto rolled_back = exec_sql_v9(
            database, "ROLLBACK TO aida_managed_overlay_schema_v9",
            "workspace_schema_v9.managed_overlay.rollback");
        auto released = exec_sql_v9(
            database, "RELEASE aida_managed_overlay_schema_v9",
            "workspace_schema_v9.managed_overlay.release");
        if (!rolled_back)
            return rolled_back;
        if (!released)
            return released;
        return migrated;
    }
    return exec_sql_v9(
        database, "RELEASE aida_managed_overlay_schema_v9",
        "workspace_schema_v9.managed_overlay.commit");
}

workspace_result_t<void> create_schema_v9(sqlite3* database) {
    auto result = upgrade_packed_domain_schema_v9(database);
    if (!result)
        return result;
    result = exec_sql_v9(database, R"SQL(
CREATE TABLE IF NOT EXISTS packed_generations(
    generation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL CHECK(generation<>0),
    analysis_revision INTEGER NOT NULL,
    overlay_revision INTEGER NOT NULL,
    shard_count INTEGER NOT NULL CHECK(shard_count BETWEEN 1 AND 19),
    total_payload_bytes INTEGER NOT NULL CHECK(total_payload_bytes BETWEEN 0 AND 17179869184),
    total_records INTEGER NOT NULL CHECK(total_records BETWEEN 0 AND 200000000),
    batch_checksum INTEGER NOT NULL,
    created_utc_ms INTEGER NOT NULL,
    committed INTEGER NOT NULL CHECK(committed IN (0,1)),
    payload_blob BLOB NOT NULL CHECK(length(payload_blob)<=16777216)
);
CREATE UNIQUE INDEX IF NOT EXISTS packed_generations_generation ON packed_generations(generation);
CREATE INDEX IF NOT EXISTS packed_generations_revisions ON packed_generations(analysis_revision,overlay_revision);
CREATE TABLE IF NOT EXISTS packed_pages(
    page_id INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL,
    page_index INTEGER NOT NULL CHECK(page_index BETWEEN 0 AND 131071),
    page_count INTEGER NOT NULL CHECK(page_count BETWEEN 1 AND 131072),
    page_type INTEGER NOT NULL CHECK(page_type BETWEEN 1 AND 19),
    payload_length INTEGER NOT NULL CHECK(payload_length BETWEEN 32 AND 1048576),
    checksum INTEGER NOT NULL,
    payload BLOB NOT NULL CHECK(length(payload)=payload_length),
    UNIQUE(generation,page_index),
    FOREIGN KEY(generation) REFERENCES packed_generations(generation) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS packed_pages_generation ON packed_pages(generation,page_index);
CREATE INDEX IF NOT EXISTS packed_pages_type ON packed_pages(generation,page_type);
CREATE TABLE IF NOT EXISTS packed_page_index(
    index_id INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL,
    domain INTEGER NOT NULL CHECK(domain BETWEEN 1 AND 19),
    ordinal_begin INTEGER NOT NULL CHECK(ordinal_begin BETWEEN 0 AND 4294967295),
    count INTEGER NOT NULL CHECK(count BETWEEN 0 AND 1048576),
    page_index INTEGER NOT NULL CHECK(page_index BETWEEN 0 AND 131071),
    address_value_min INTEGER NOT NULL,
    address_value_max INTEGER NOT NULL,
    UNIQUE(generation,domain,page_index),
    FOREIGN KEY(generation) REFERENCES packed_generations(generation) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS packed_page_index_generation_domain ON packed_page_index(generation,domain,ordinal_begin);
CREATE INDEX IF NOT EXISTS packed_page_index_address ON packed_page_index(generation,address_value_min,address_value_max);
CREATE TABLE IF NOT EXISTS workbench_state(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    workspace_id INTEGER NOT NULL CHECK(workspace_id<>0),
    contract_schema_version INTEGER NOT NULL CHECK(contract_schema_version>0),
    revision INTEGER NOT NULL CHECK(revision<>0),
    fingerprint INTEGER NOT NULL CHECK(fingerprint<>0),
    payload_json TEXT NOT NULL CHECK(length(CAST(payload_json AS BLOB)) BETWEEN 1 AND 16777216),
    updated_utc_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS decompiler_cache_v9(
    cache_key TEXT PRIMARY KEY NOT NULL CHECK(length(CAST(cache_key AS BLOB)) BETWEEN 1 AND 16384),
    binary_id BLOB NOT NULL CHECK(length(binary_id)=32),
    format INTEGER NOT NULL,
    architecture INTEGER NOT NULL,
    architecture_mode INTEGER NOT NULL,
    abi INTEGER NOT NULL,
    endian INTEGER NOT NULL,
    engine_version TEXT NOT NULL CHECK(length(CAST(engine_version AS BLOB))<=65536),
    schema_version INTEGER NOT NULL CHECK(schema_version>0),
    specification_version TEXT NOT NULL CHECK(length(CAST(specification_version AS BLOB))<=65536),
    settings_hash TEXT NOT NULL CHECK(length(CAST(settings_hash AS BLOB))<=65536),
    function_id INTEGER NOT NULL,
    function_rva INTEGER NOT NULL,
    function_rva_space INTEGER NOT NULL DEFAULT 1,
    function_rva_arch INTEGER NOT NULL DEFAULT 0,
    function_rva_mode INTEGER NOT NULL DEFAULT 0,
    function_content_hash BLOB NOT NULL CHECK(length(function_content_hash)=32),
    analysis_revision INTEGER NOT NULL,
    overlay_revision INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    function_name TEXT NOT NULL CHECK(length(CAST(function_name AS BLOB))<=4096),
    result_json TEXT NOT NULL CHECK(length(CAST(result_json AS BLOB)) BETWEEN 1 AND 67108864),
    created_utc_ms INTEGER NOT NULL,
    last_access_utc_ms INTEGER NOT NULL,
    result_bytes INTEGER NOT NULL CHECK(result_bytes=length(CAST(result_json AS BLOB))),
    cache_key_version INTEGER NOT NULL DEFAULT 1 CHECK(cache_key_version=1)
);
CREATE INDEX IF NOT EXISTS decompiler_cache_v9_function ON decompiler_cache_v9(function_rva,overlay_revision,generation);
CREATE INDEX IF NOT EXISTS decompiler_cache_v9_binary ON decompiler_cache_v9(binary_id,analysis_revision);
CREATE TABLE IF NOT EXISTS overlay_v9_state(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    target_image_hash BLOB NOT NULL CHECK(length(target_image_hash)=32),
    target_provenance_hash BLOB NOT NULL CHECK(length(target_provenance_hash)=32),
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
INSERT OR IGNORE INTO overlay_v9_state(singleton,target_image_hash,target_provenance_hash,target_image_base,target_image_size,target_generation,target_kind,target_architecture,target_address_width,revision,next_transaction_id,history_cursor,history_epoch,updated_utc_ms) VALUES(1,zeroblob(32),zeroblob(32),0,0,0,0,0,0,0,1,0,1,0);
CREATE TABLE IF NOT EXISTS packed_generation_staging(
    generation INTEGER NOT NULL,
    domain INTEGER NOT NULL CHECK(domain BETWEEN 1 AND 19),
    domain_page_index INTEGER NOT NULL,
    ordinal_begin INTEGER NOT NULL,
    record_count INTEGER NOT NULL,
    address_value_min INTEGER NOT NULL,
    address_value_max INTEGER NOT NULL,
    payload BLOB NOT NULL CHECK(length(payload) BETWEEN 32 AND 1048576),
    PRIMARY KEY(generation,domain,domain_page_index)
);
CREATE TABLE IF NOT EXISTS decompiler_pipeline_cache_v1(
    cache_key BLOB PRIMARY KEY,
    stage INTEGER NOT NULL,
    workspace_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    analysis_revision INTEGER NOT NULL,
    overlay_revision INTEGER NOT NULL,
    function_rva INTEGER NOT NULL,
    value BLOB NOT NULL,
    diagnostics BLOB NOT NULL,
    created_utc_ms INTEGER NOT NULL,
    last_access_utc_ms INTEGER NOT NULL,
    value_bytes INTEGER NOT NULL CHECK(value_bytes=length(CAST(value AS BLOB)))
);
CREATE INDEX IF NOT EXISTS decompiler_pipeline_cache_v1_workspace ON decompiler_pipeline_cache_v1(workspace_id,generation,stage);
CREATE INDEX IF NOT EXISTS decompiler_pipeline_cache_v1_function ON decompiler_pipeline_cache_v1(function_rva,overlay_revision,generation);
)SQL", "workspace_schema_v9.migrate");
    if (!result)
        return result;

    result = ensure_managed_overlay_identity_schema_v9(database);
    if (!result)
        return result;

    result = create_snapshot_extension_slot_v9(database, {});
    if (!result)
        return result;
    result = create_snapshot_extension_slot_v9(database, "alternate_");
    if (!result)
        return result;
    auto backfill_complete = rich_backfill_complete_v9(database);
    if (!backfill_complete)
        return workspace_result_t<void>::failure(backfill_complete.error());
    if (!backfill_complete.value()) {
        result = backfill_snapshot_extension_slot_v9(database, {});
        if (!result)
            return result;
        result = backfill_snapshot_extension_slot_v9(database, "alternate_");
        if (!result)
            return result;
        result = mark_rich_backfill_complete_v9(database);
        if (!result)
            return result;
    }

    auto legacy_cache = table_exists_v9(database, "decompiler_cache");
    if (!legacy_cache)
        return workspace_result_t<void>::failure(legacy_cache.error());
    if (legacy_cache.value()) {
        result = exec_sql_v9(database, R"SQL(
INSERT OR IGNORE INTO decompiler_cache_v9(
    cache_key,binary_id,format,architecture,architecture_mode,abi,endian,
    engine_version,schema_version,specification_version,settings_hash,
    function_id,function_rva,function_rva_space,function_rva_arch,function_rva_mode,
    function_content_hash,analysis_revision,overlay_revision,generation,function_name,
    result_json,created_utc_ms,last_access_utc_ms,result_bytes,cache_key_version)
SELECT cache_key,binary_id,format,architecture,architecture_mode,abi,endian,
       engine_version,schema_version,specification_version,settings_hash,
       function_id,function_rva,1,architecture,architecture_mode,
       function_content_hash,analysis_revision,overlay_revision,generation,function_name,
       result_json,created_utc_ms,last_access_utc_ms,result_bytes,1
FROM decompiler_cache
WHERE length(cache_key) BETWEEN 1 AND 16384
  AND length(binary_id)=32
  AND length(function_content_hash)=32
  AND length(CAST(result_json AS BLOB))=result_bytes
  AND result_bytes BETWEEN 1 AND 67108864;
)SQL", "workspace_schema_v9.backfill_cache");
        if (!result)
            return result;
    }

    auto identity = table_exists_v9(database, "workspace_identity");
    if (!identity)
        return workspace_result_t<void>::failure(identity.error());
    auto analysis_state = table_exists_v9(database, "analysis_state");
    if (!analysis_state)
        return workspace_result_t<void>::failure(analysis_state.error());
    auto overlay_state = table_exists_v9(database, "overlay_state");
    if (!overlay_state)
        return workspace_result_t<void>::failure(overlay_state.error());
    if (identity.value() && analysis_state.value() && overlay_state.value()) {
        result = exec_sql_v9(database, R"SQL(
INSERT INTO overlay_v9_state(
    singleton,target_image_hash,target_provenance_hash,target_image_base,target_image_size,
    target_generation,target_kind,target_architecture,target_address_width,revision,
    next_transaction_id,history_cursor,history_epoch,updated_utc_ms)
SELECT 1,wi.content_hash,wi.load_profile_hash,COALESCE(wi.module_base,wi.image_base),
       COALESCE(wi.module_size,0),COALESCE(ast.generation,0),wi.target_kind,wi.architecture,
       CASE wi.architecture_mode WHEN 1 THEN 16 WHEN 2 THEN 32 WHEN 3 THEN 64
            WHEN 4 THEN 32 WHEN 5 THEN 32 WHEN 6 THEN 64 WHEN 7 THEN 32
            WHEN 8 THEN 64 WHEN 9 THEN 32 WHEN 10 THEN 64 WHEN 11 THEN 32
            WHEN 12 THEN 64 WHEN 13 THEN 32 WHEN 14 THEN 32 ELSE 0 END,
       os.revision,os.next_transaction_id,os.history_cursor,os.history_epoch,os.updated_utc_ms
FROM workspace_identity wi
CROSS JOIN overlay_state os
LEFT JOIN analysis_state ast ON ast.singleton=1
WHERE wi.singleton=1 AND os.singleton=1
ON CONFLICT(singleton) DO UPDATE SET
    target_image_hash=excluded.target_image_hash,
    target_provenance_hash=excluded.target_provenance_hash,
    target_image_base=excluded.target_image_base,
    target_image_size=excluded.target_image_size,
    target_generation=excluded.target_generation,
    target_kind=excluded.target_kind,
    target_architecture=excluded.target_architecture,
    target_address_width=excluded.target_address_width,
    revision=excluded.revision,
    next_transaction_id=excluded.next_transaction_id,
    history_cursor=excluded.history_cursor,
    history_epoch=excluded.history_epoch,
    updated_utc_ms=excluded.updated_utc_ms;
CREATE TRIGGER IF NOT EXISTS overlay_state_v9_sync_update
AFTER UPDATE ON overlay_state
BEGIN
    UPDATE overlay_v9_state SET revision=NEW.revision,
        next_transaction_id=NEW.next_transaction_id,
        history_cursor=NEW.history_cursor,
        history_epoch=NEW.history_epoch,
        updated_utc_ms=NEW.updated_utc_ms
    WHERE singleton=1;
END;
CREATE TRIGGER IF NOT EXISTS overlay_state_v9_sync_insert
AFTER INSERT ON overlay_state
BEGIN
    UPDATE overlay_v9_state SET revision=NEW.revision,
        next_transaction_id=NEW.next_transaction_id,
        history_cursor=NEW.history_cursor,
        history_epoch=NEW.history_epoch,
        updated_utc_ms=NEW.updated_utc_ms
    WHERE singleton=1;
END;
CREATE TRIGGER IF NOT EXISTS analysis_state_v9_sync_insert
AFTER INSERT ON analysis_state
BEGIN
    UPDATE overlay_v9_state SET target_generation=NEW.generation WHERE singleton=1;
END;
CREATE TRIGGER IF NOT EXISTS analysis_state_v9_sync_update
AFTER UPDATE OF generation ON analysis_state
BEGIN
    UPDATE overlay_v9_state SET target_generation=NEW.generation WHERE singleton=1;
END;
CREATE TRIGGER IF NOT EXISTS analysis_state_v9_sync_delete
AFTER DELETE ON analysis_state
BEGIN
    UPDATE overlay_v9_state SET target_generation=0 WHERE singleton=1;
END;
CREATE TRIGGER IF NOT EXISTS workspace_identity_v9_sync_insert
AFTER INSERT ON workspace_identity
BEGIN
    UPDATE overlay_v9_state SET
        target_image_hash=NEW.content_hash,
        target_provenance_hash=NEW.load_profile_hash,
        target_image_base=COALESCE(NEW.module_base,NEW.image_base),
        target_image_size=COALESCE(NEW.module_size,0),
        target_kind=NEW.target_kind,
        target_architecture=NEW.architecture,
        target_address_width=CASE NEW.architecture_mode
            WHEN 1 THEN 16 WHEN 2 THEN 32 WHEN 3 THEN 64 WHEN 4 THEN 32
            WHEN 5 THEN 32 WHEN 6 THEN 64 WHEN 7 THEN 32 WHEN 8 THEN 64
            WHEN 9 THEN 32 WHEN 10 THEN 64 WHEN 11 THEN 32 WHEN 12 THEN 64
            WHEN 13 THEN 32 WHEN 14 THEN 32 ELSE 0 END
    WHERE singleton=1;
END;
CREATE TRIGGER IF NOT EXISTS workspace_identity_v9_sync_update
AFTER UPDATE ON workspace_identity
BEGIN
    UPDATE overlay_v9_state SET
        target_image_hash=NEW.content_hash,
        target_provenance_hash=NEW.load_profile_hash,
        target_image_base=COALESCE(NEW.module_base,NEW.image_base),
        target_image_size=COALESCE(NEW.module_size,0),
        target_kind=NEW.target_kind,
        target_architecture=NEW.architecture,
        target_address_width=CASE NEW.architecture_mode
            WHEN 1 THEN 16 WHEN 2 THEN 32 WHEN 3 THEN 64 WHEN 4 THEN 32
            WHEN 5 THEN 32 WHEN 6 THEN 64 WHEN 7 THEN 32 WHEN 8 THEN 64
            WHEN 9 THEN 32 WHEN 10 THEN 64 WHEN 11 THEN 32 WHEN 12 THEN 64
            WHEN 13 THEN 32 WHEN 14 THEN 32 ELSE 0 END
    WHERE singleton=1;
END;
)SQL", "workspace_schema_v9.backfill_overlay");
        if (!result)
            return result;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> create_schema_v10(sqlite3* database) {
    if (!database) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "schema v10 migration requires an open database",
            "workspace_schema_v10.migrate"));
    }
    auto base = create_schema_v9(database);
    if (!base)
        return base;
    auto has_logical_length = column_exists_v9(
        database, "packed_pages", "logical_length");
    if (!has_logical_length)
        return workspace_result_t<void>::failure(has_logical_length.error());
    if (!has_logical_length.value()) {
        auto altered = exec_sql_v9(database,
            "ALTER TABLE packed_pages ADD COLUMN logical_length INTEGER",
            "workspace_schema_v10.logical_length");
        if (!altered)
            return altered;
    }
    auto created = exec_sql_v9(database, R"SQL(
CREATE TABLE IF NOT EXISTS pdb_symbol_modules(
    module_key TEXT PRIMARY KEY,
    module_name TEXT NOT NULL,
    base INTEGER NOT NULL CHECK(base >= 0),
    size INTEGER NOT NULL CHECK(size > 0),
    pdb_guid BLOB NOT NULL CHECK(length(pdb_guid) = 16),
    pdb_age INTEGER NOT NULL CHECK(pdb_age >= 0),
    pdb_path TEXT NOT NULL,
    pdb_file_size INTEGER,
    pdb_volume_serial INTEGER,
    pdb_file_id BLOB,
    pdb_last_write_100ns INTEGER,
    symbol_count INTEGER NOT NULL CHECK(symbol_count BETWEEN 0 AND 4194304),
    struct_count INTEGER NOT NULL CHECK(struct_count BETWEEN 0 AND 1048576),
    enum_count INTEGER NOT NULL CHECK(enum_count BETWEEN 0 AND 1048576),
    payload_codec INTEGER NOT NULL CHECK(payload_codec IN (0,1)),
    payload_uncompressed_bytes INTEGER NOT NULL CHECK(payload_uncompressed_bytes BETWEEN 0 AND 268435456),
    payload BLOB NOT NULL,
    source_lines_codec INTEGER CHECK(source_lines_codec IS NULL OR source_lines_codec IN (0,1)),
    source_lines_uncompressed_bytes INTEGER CHECK(source_lines_uncompressed_bytes IS NULL OR source_lines_uncompressed_bytes BETWEEN 0 AND 268435456),
    source_lines BLOB,
    created_utc_ms INTEGER NOT NULL,
    updated_utc_ms INTEGER NOT NULL
);
)SQL", "workspace_schema_v10.pdb_symbol_modules");
    if (!created)
        return created;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> write_packed_generation(
    sqlite3* database, const packed_generation_record_t& record) {
    if (record.generation == 0 || record.committed || record.shard_count == 0 ||
        record.shard_count > static_cast<std::uint16_t>(packed_page_last_data_type) ||
        record.total_records > packed_generation_max_records ||
        record.total_payload_bytes > packed_generation_max_payload_bytes ||
        record.payload_blob.size() > packed_generation_max_metadata_bytes) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "packed generation metadata exceeds its bounded invariants",
                                 "workspace_schema_v9.write_packed_generation"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO packed_generations(generation,analysis_revision,overlay_revision,shard_count,total_payload_bytes,total_records,batch_checksum,created_utc_ms,committed,payload_blob)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
ON CONFLICT(generation) DO UPDATE SET analysis_revision=excluded.analysis_revision,overlay_revision=excluded.overlay_revision,shard_count=excluded.shard_count,total_payload_bytes=excluded.total_payload_bytes,total_records=excluded.total_records,batch_checksum=excluded.batch_checksum,created_utc_ms=excluded.created_utc_ms,committed=excluded.committed,payload_blob=excluded.payload_blob
WHERE packed_generations.committed=0
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
    result = statement.step_done();
    if (!result)
        return result;
    if (sqlite3_changes(database) != 1) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::target_conflict,
                                 "committed packed generation cannot be restaged",
                                 "workspace_schema_v9.write_packed_generation"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::optional<packed_generation_record_t>>
    read_packed_generation(sqlite3* database, std::uint64_t generation,
                           bool committed_only,
                           const packed_stop_predicate_t& stop_requested) {
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::optional<packed_generation_record_t>>::failure(
            cancelled_read_error_v9("workspace_schema_v9.read_packed_generation"));
    v9_statement_t statement;
    auto result = statement.prepare(database,
        committed_only
            ? "SELECT generation,analysis_revision,overlay_revision,shard_count,total_payload_bytes,total_records,batch_checksum,created_utc_ms,committed,length(payload_blob),payload_blob FROM packed_generations WHERE generation=?1 AND committed=1"
            : "SELECT generation,analysis_revision,overlay_revision,shard_count,total_payload_bytes,total_records,batch_checksum,created_utc_ms,committed,length(payload_blob),payload_blob FROM packed_generations WHERE generation=?1",
        "workspace_schema_v9.read_packed_generation");
    if (!result)
        return workspace_result_t<std::optional<packed_generation_record_t>>::failure(result.error());
    result = statement.bind_uint(1, generation);
    if (!result)
        return workspace_result_t<std::optional<packed_generation_record_t>>::failure(result.error());
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::optional<packed_generation_record_t>>::failure(
            cancelled_read_error_v9("workspace_schema_v9.read_packed_generation"));
    const int status = sqlite3_step(statement.get());
    if (status == SQLITE_INTERRUPT && publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::optional<packed_generation_record_t>>::failure(
            cancelled_read_error_v9("workspace_schema_v9.read_packed_generation"));
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
    if (declared_blob_length < 0 ||
        static_cast<std::uint64_t>(declared_blob_length) >
            packed_generation_max_metadata_bytes ||
        record.shard_count == 0 ||
        record.shard_count > static_cast<std::uint16_t>(packed_page_last_data_type) ||
        record.total_records > packed_generation_max_records ||
        record.total_payload_bytes > packed_generation_max_payload_bytes ||
        payload_bytes < 0 ||
        static_cast<std::uint64_t>(payload_bytes) != static_cast<std::uint64_t>(declared_blob_length) ||
        (payload_bytes > 0 && !payload)) {
        return workspace_result_t<std::optional<packed_generation_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "packed generation payload blob is malformed",
                                 "workspace_schema_v9.read_packed_generation"));
    }
    if (payload_bytes > 0) {
        const auto* begin = static_cast<const std::uint8_t*>(payload);
        auto copied = copy_blob_v9(record.payload_blob, begin,
            static_cast<std::size_t>(payload_bytes), stop_requested,
            "workspace_schema_v9.read_packed_generation");
        if (!copied)
            return workspace_result_t<std::optional<packed_generation_record_t>>::failure(
                copied.error());
    }
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::optional<packed_generation_record_t>>::failure(
            cancelled_read_error_v9("workspace_schema_v9.read_packed_generation"));
    return workspace_result_t<std::optional<packed_generation_record_t>>::success(
        std::optional<packed_generation_record_t>(std::move(record)));
}

workspace_result_t<void> write_packed_page(
    sqlite3* database, const packed_page_row_t& row) {
    if (row.generation == 0 || row.page_count == 0 ||
        row.page_count > packed_generation_max_pages ||
        row.page_index >= row.page_count ||
        row.page_type < static_cast<std::uint32_t>(packed_page_type_t::instructions) ||
        row.page_type > static_cast<std::uint32_t>(packed_page_last_data_type) ||
        row.payload.size() < packed_record_page_prefix_size ||
        row.payload.size() > packed_page_max_payload ||
        row.payload_length != row.payload.size() ||
        row.logical_length != 0) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "packed page metadata exceeds its bounded invariants",
                                 "workspace_schema_v9.write_packed_page"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO packed_pages(generation,page_index,page_count,page_type,payload_length,checksum,payload)
SELECT ?1,?2,?3,?4,?5,?6,?7
WHERE EXISTS(SELECT 1 FROM packed_generations WHERE generation=?1 AND committed=0)
ON CONFLICT(generation,page_index) DO UPDATE SET page_count=excluded.page_count,page_type=excluded.page_type,payload_length=excluded.payload_length,checksum=excluded.checksum,payload=excluded.payload
WHERE EXISTS(SELECT 1 FROM packed_generations WHERE generation=?1 AND committed=0)
)SQL", "workspace_schema_v9.write_packed_page");
    if (!result) return result;
    result = statement.bind_uint(1, row.generation); if (!result) return result;
    result = statement.bind_int(2, static_cast<std::int64_t>(row.page_index)); if (!result) return result;
    result = statement.bind_int(3, static_cast<std::int64_t>(row.page_count)); if (!result) return result;
    result = statement.bind_int(4, static_cast<std::int64_t>(row.page_type)); if (!result) return result;
    result = statement.bind_int(5, static_cast<std::int64_t>(row.payload_length)); if (!result) return result;
    result = statement.bind_int(6, static_cast<std::int64_t>(row.checksum)); if (!result) return result;
    result = statement.bind_blob(7, row.payload.data(), row.payload.size()); if (!result) return result;
    result = statement.step_done();
    if (!result)
        return result;
    if (sqlite3_changes(database) != 1) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::target_conflict,
                                 "packed page requires an uncommitted generation",
                                 "workspace_schema_v9.write_packed_page"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::vector<packed_page_row_t>>
    read_packed_pages(sqlite3* database, std::uint64_t generation,
                      bool committed_only,
                      const packed_stop_predicate_t& stop_requested) {
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::vector<packed_page_row_t>>::failure(
            cancelled_read_error_v9("workspace_schema_v9.read_packed_pages"));
    const char* count_sql = committed_only
        ? "SELECT COUNT(*),COALESCE(SUM(length(p.payload)),0) FROM packed_pages p JOIN packed_generations g ON g.generation=p.generation AND g.committed=1 WHERE p.generation=?1"
        : "SELECT COUNT(*),COALESCE(SUM(length(payload)),0) FROM packed_pages WHERE generation=?1";
    v9_statement_t count_statement;
    auto result = count_statement.prepare(database, count_sql,
        "workspace_schema_v9.read_packed_pages.count");
    if (!result)
        return workspace_result_t<std::vector<packed_page_row_t>>::failure(result.error());
    result = count_statement.bind_uint(1, generation);
    if (!result)
        return workspace_result_t<std::vector<packed_page_row_t>>::failure(result.error());
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::vector<packed_page_row_t>>::failure(
            cancelled_read_error_v9("workspace_schema_v9.read_packed_pages.count"));
    const int count_status = sqlite3_step(count_statement.get());
    if (count_status == SQLITE_INTERRUPT && publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::vector<packed_page_row_t>>::failure(
            cancelled_read_error_v9("workspace_schema_v9.read_packed_pages.count"));
    if (count_status != SQLITE_ROW) {
        return workspace_result_t<std::vector<packed_page_row_t>>::failure(
            schema_v9_error(database, count_status, "unable to bound packed page rows",
                            "workspace_schema_v9.read_packed_pages.count"));
    }
    const auto row_count = sqlite3_column_int64(count_statement.get(), 0);
    const auto total_payload_bytes = sqlite3_column_int64(count_statement.get(), 1);
    if (row_count < 0 || total_payload_bytes < 0 ||
        static_cast<std::uint64_t>(row_count) > packed_generation_max_pages ||
        static_cast<std::uint64_t>(total_payload_bytes) >
            packed_generation_max_payload_bytes) {
        return workspace_result_t<std::vector<packed_page_row_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "persisted packed pages exceed bounded decode limits",
                                 "workspace_schema_v9.read_packed_pages"));
    }
    v9_statement_t statement;
    result = statement.prepare(database, committed_only
        ? "SELECT p.generation,p.page_index,p.page_count,p.page_type,p.payload_length,p.checksum,length(p.payload),p.payload,p.logical_length FROM packed_pages p JOIN packed_generations g ON g.generation=p.generation AND g.committed=1 WHERE p.generation=?1 ORDER BY p.page_index"
        : "SELECT generation,page_index,page_count,page_type,payload_length,checksum,length(payload),payload,logical_length FROM packed_pages WHERE generation=?1 ORDER BY page_index",
        "workspace_schema_v9.read_packed_pages");
    if (!result)
        return workspace_result_t<std::vector<packed_page_row_t>>::failure(result.error());
    result = statement.bind_uint(1, generation);
    if (!result)
        return workspace_result_t<std::vector<packed_page_row_t>>::failure(result.error());
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::vector<packed_page_row_t>>::failure(
            cancelled_read_error_v9("workspace_schema_v9.read_packed_pages"));
    std::vector<packed_page_row_t> rows;
    rows.reserve(static_cast<std::size_t>(row_count));
    std::uint64_t observed_payload_bytes = 0;
    for (;;) {
        if (publish_stop_requested_v9(stop_requested))
            return workspace_result_t<std::vector<packed_page_row_t>>::failure(
                cancelled_read_error_v9("workspace_schema_v9.read_packed_pages"));
        const int status = sqlite3_step(statement.get());
        if (status == SQLITE_DONE)
            break;
        if (status == SQLITE_INTERRUPT &&
            publish_stop_requested_v9(stop_requested)) {
            return workspace_result_t<std::vector<packed_page_row_t>>::failure(
                cancelled_read_error_v9("workspace_schema_v9.read_packed_pages"));
        }
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
        std::uint32_t logical_length = 0;
        if (sqlite3_column_type(statement.get(), 8) != SQLITE_NULL) {
            const auto declared_logical_length =
                sqlite3_column_int64(statement.get(), 8);
            if (declared_logical_length <
                    static_cast<std::int64_t>(packed_record_page_prefix_size) ||
                declared_logical_length >
                    static_cast<std::int64_t>(packed_page_max_payload)) {
                return workspace_result_t<std::vector<packed_page_row_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                                         "packed page logical length is malformed",
                                         "workspace_schema_v9.read_packed_pages"));
            }
            logical_length = static_cast<std::uint32_t>(declared_logical_length);
        }
        row.logical_length = logical_length;
        if (rows.size() >= packed_generation_max_pages ||
            declared_length < 0 || payload_bytes < 0 ||
            static_cast<std::uint64_t>(declared_length) > packed_page_max_payload ||
            static_cast<std::uint64_t>(payload_bytes) != static_cast<std::uint64_t>(declared_length) ||
            static_cast<std::uint32_t>(payload_bytes) != row.payload_length ||
            row.page_count == 0 || row.page_count > packed_generation_max_pages ||
            row.page_index >= row.page_count ||
            row.page_type < static_cast<std::uint32_t>(packed_page_type_t::instructions) ||
            row.page_type > static_cast<std::uint32_t>(packed_page_last_data_type) ||
            (payload_bytes > 0 && !payload)) {
            return workspace_result_t<std::vector<packed_page_row_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "packed page payload is malformed",
                                     "workspace_schema_v9.read_packed_pages"));
        }
        if (!checked_add_u64(observed_payload_bytes,
                             static_cast<std::uint64_t>(payload_bytes),
                             observed_payload_bytes) ||
            observed_payload_bytes > packed_generation_max_payload_bytes) {
            return workspace_result_t<std::vector<packed_page_row_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                                     "packed page payload exceeds its aggregate byte limit",
                                     "workspace_schema_v9.read_packed_pages"));
        }
        if (payload_bytes > 0) {
            const auto* begin = static_cast<const std::uint8_t*>(payload);
            auto copied = copy_blob_v9(row.payload, begin,
                static_cast<std::size_t>(payload_bytes), stop_requested,
                "workspace_schema_v9.read_packed_pages");
            if (!copied)
                return workspace_result_t<std::vector<packed_page_row_t>>::failure(
                    copied.error());
        }
        rows.push_back(std::move(row));
    }
    if (rows.size() != static_cast<std::size_t>(row_count) ||
        observed_payload_bytes != static_cast<std::uint64_t>(total_payload_bytes)) {
        return workspace_result_t<std::vector<packed_page_row_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "packed page rows changed across the bounded read snapshot",
                                 "workspace_schema_v9.read_packed_pages"));
    }
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::vector<packed_page_row_t>>::failure(
            cancelled_read_error_v9("workspace_schema_v9.read_packed_pages"));
    return workspace_result_t<std::vector<packed_page_row_t>>::success(std::move(rows));
}

workspace_result_t<void> write_packed_page_index(
    sqlite3* database, const packed_page_index_row_t& row) {
    if (row.generation == 0 || row.domain == 0 ||
        row.domain > static_cast<std::uint16_t>(packed_page_last_data_type) ||
        row.page_index >= packed_generation_max_pages ||
        row.count > packed_page_max_payload ||
        row.address_value_min > row.address_value_max) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "packed page index metadata exceeds its bounded invariants",
                                 "workspace_schema_v9.write_packed_page_index"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO packed_page_index(generation,domain,ordinal_begin,count,page_index,address_value_min,address_value_max)
SELECT ?1,?2,?3,?4,?5,?6,?7
WHERE EXISTS(SELECT 1 FROM packed_generations WHERE generation=?1 AND committed=0)
ON CONFLICT(generation,domain,page_index) DO UPDATE SET ordinal_begin=excluded.ordinal_begin,count=excluded.count,address_value_min=excluded.address_value_min,address_value_max=excluded.address_value_max
WHERE EXISTS(SELECT 1 FROM packed_generations WHERE generation=?1 AND committed=0)
)SQL", "workspace_schema_v9.write_packed_page_index");
    if (!result) return result;
    result = statement.bind_uint(1, row.generation); if (!result) return result;
    result = statement.bind_int(2, static_cast<std::int64_t>(row.domain)); if (!result) return result;
    result = statement.bind_int(3, static_cast<std::int64_t>(row.ordinal_begin)); if (!result) return result;
    result = statement.bind_int(4, static_cast<std::int64_t>(row.count)); if (!result) return result;
    result = statement.bind_int(5, static_cast<std::int64_t>(row.page_index)); if (!result) return result;
    result = statement.bind_uint(6, row.address_value_min); if (!result) return result;
    result = statement.bind_uint(7, row.address_value_max); if (!result) return result;
    result = statement.step_done();
    if (!result)
        return result;
    if (sqlite3_changes(database) != 1) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::target_conflict,
                                 "packed page index requires an uncommitted generation",
                                 "workspace_schema_v9.write_packed_page_index"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::vector<packed_page_index_row_t>>
    read_packed_page_index(sqlite3* database, std::uint64_t generation,
                           bool committed_only,
                           const packed_stop_predicate_t& stop_requested) {
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(
            cancelled_read_error_v9("workspace_schema_v9.read_packed_page_index"));
    v9_statement_t count_statement;
    auto result = count_statement.prepare(database, committed_only
        ? "SELECT COUNT(*) FROM packed_page_index i JOIN packed_generations g ON g.generation=i.generation AND g.committed=1 WHERE i.generation=?1"
        : "SELECT COUNT(*) FROM packed_page_index WHERE generation=?1",
        "workspace_schema_v9.read_packed_page_index.count");
    if (!result)
        return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(result.error());
    result = count_statement.bind_uint(1, generation);
    if (!result)
        return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(result.error());
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(
            cancelled_read_error_v9("workspace_schema_v9.read_packed_page_index.count"));
    const int count_status = sqlite3_step(count_statement.get());
    if (count_status == SQLITE_INTERRUPT && publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(
            cancelled_read_error_v9("workspace_schema_v9.read_packed_page_index.count"));
    if (count_status != SQLITE_ROW) {
        return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(
            schema_v9_error(database, count_status, "unable to bound packed index rows",
                            "workspace_schema_v9.read_packed_page_index.count"));
    }
    const auto row_count = sqlite3_column_int64(count_statement.get(), 0);
    if (row_count < 0 ||
        static_cast<std::uint64_t>(row_count) > packed_generation_max_index_rows) {
        return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "persisted packed index exceeds its bounded row limit",
                                 "workspace_schema_v9.read_packed_page_index"));
    }
    v9_statement_t statement;
    result = statement.prepare(database, committed_only
        ? "SELECT i.generation,i.domain,i.ordinal_begin,i.count,i.page_index,i.address_value_min,i.address_value_max FROM packed_page_index i JOIN packed_generations g ON g.generation=i.generation AND g.committed=1 WHERE i.generation=?1 ORDER BY i.domain,i.ordinal_begin"
        : "SELECT generation,domain,ordinal_begin,count,page_index,address_value_min,address_value_max FROM packed_page_index WHERE generation=?1 ORDER BY domain,ordinal_begin",
        "workspace_schema_v9.read_packed_page_index");
    if (!result)
        return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(result.error());
    result = statement.bind_uint(1, generation);
    if (!result)
        return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(result.error());
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(
            cancelled_read_error_v9("workspace_schema_v9.read_packed_page_index"));
    std::vector<packed_page_index_row_t> rows;
    rows.reserve(static_cast<std::size_t>(row_count));
    for (;;) {
        if (publish_stop_requested_v9(stop_requested))
            return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(
                cancelled_read_error_v9("workspace_schema_v9.read_packed_page_index"));
        const int status = sqlite3_step(statement.get());
        if (status == SQLITE_DONE)
            break;
        if (status == SQLITE_INTERRUPT &&
            publish_stop_requested_v9(stop_requested)) {
            return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(
                cancelled_read_error_v9(
                    "workspace_schema_v9.read_packed_page_index"));
        }
        if (status != SQLITE_ROW) {
            return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(
                schema_v9_error(database, status, "unable to read packed page index row",
                                "workspace_schema_v9.read_packed_page_index"));
        }
        if (rows.size() >= packed_generation_max_index_rows) {
            return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                                     "packed page index exceeds its aggregate row limit",
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
        if (row.domain == 0 ||
            row.domain > static_cast<std::uint16_t>(packed_page_last_data_type) ||
            row.page_index >= packed_generation_max_pages ||
            row.count > packed_page_max_payload ||
            row.address_value_min > row.address_value_max) {
            return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "packed page index row is malformed",
                                     "workspace_schema_v9.read_packed_page_index"));
        }
        rows.push_back(std::move(row));
    }
    if (rows.size() != static_cast<std::size_t>(row_count)) {
        return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "packed page index changed across the bounded read snapshot",
                                 "workspace_schema_v9.read_packed_page_index"));
    }
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::vector<packed_page_index_row_t>>::failure(
            cancelled_read_error_v9("workspace_schema_v9.read_packed_page_index"));
    return workspace_result_t<std::vector<packed_page_index_row_t>>::success(std::move(rows));
}

workspace_result_t<void> write_workbench_state(
    sqlite3* database, const workbench_state_record_t& record) {
    if (record.workspace_id == 0 || record.contract_schema_version == 0 ||
        record.revision == 0 || record.fingerprint == 0 ||
        record.payload_json.empty() ||
        record.payload_json.size() > workbench_state_max_payload_bytes) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "workbench state metadata exceeds its bounded invariants",
                                 "workspace_schema_v9.write_workbench_state"));
    }
    const auto updated_utc_ms = record.updated_utc_ms > 0
        ? record.updated_utc_ms : utc_ms_v9();
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO workbench_state(singleton,workspace_id,contract_schema_version,revision,fingerprint,payload_json,updated_utc_ms)
VALUES(1,?1,?2,?3,?4,?5,?6)
ON CONFLICT(singleton) DO UPDATE SET
    workspace_id=excluded.workspace_id,
    contract_schema_version=excluded.contract_schema_version,
    revision=excluded.revision,
    fingerprint=excluded.fingerprint,
    payload_json=excluded.payload_json,
    updated_utc_ms=excluded.updated_utc_ms
WHERE workbench_state.workspace_id=excluded.workspace_id
  AND (
      (excluded.revision<0 AND workbench_state.revision>=0)
      OR (((excluded.revision<0)=(workbench_state.revision<0))
          AND excluded.revision>workbench_state.revision)
  )
)SQL", "workspace_schema_v9.write_workbench_state");
    if (!result) return result;
    result = statement.bind_uint(1, record.workspace_id); if (!result) return result;
    result = statement.bind_int(2, static_cast<std::int64_t>(record.contract_schema_version)); if (!result) return result;
    result = statement.bind_uint(3, record.revision); if (!result) return result;
    result = statement.bind_uint(4, record.fingerprint); if (!result) return result;
    result = statement.bind_text(5, record.payload_json); if (!result) return result;
    result = statement.bind_uint(6, updated_utc_ms); if (!result) return result;
    result = statement.step_done();
    if (!result)
        return result;
    if (sqlite3_changes(database) == 1)
        return workspace_result_t<void>::success();
    auto existing = read_workbench_state(database);
    if (!existing)
        return workspace_result_t<void>::failure(existing.error());
    if (existing.value()) {
        const auto& current = *existing.value();
        if (current.workspace_id == record.workspace_id &&
            current.contract_schema_version == record.contract_schema_version &&
            current.revision == record.revision &&
            current.fingerprint == record.fingerprint &&
            current.payload_json == record.payload_json)
            return workspace_result_t<void>::success();
    }
    return workspace_result_t<void>::failure(
        make_workspace_error(workspace_error_code_t::target_conflict,
                             "workbench persistence revision conflicts with stored state",
                             "workspace_schema_v9.write_workbench_state"));
}

workspace_result_t<std::optional<workbench_state_record_t>>
    read_workbench_state(sqlite3* database) {
    v9_statement_t statement;
    auto result = statement.prepare(database,
        "SELECT workspace_id,contract_schema_version,revision,fingerprint,length(CAST(payload_json AS BLOB)),payload_json,updated_utc_ms FROM workbench_state WHERE singleton=1",
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
    record.workspace_id = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
    record.contract_schema_version = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 1));
    record.revision = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2));
    record.fingerprint = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 3));
    const auto declared_length = sqlite3_column_int64(statement.get(), 4);
    if (declared_length <= 0 ||
        static_cast<std::uint64_t>(declared_length) > workbench_state_max_payload_bytes) {
        return workspace_result_t<std::optional<workbench_state_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "persisted workbench state exceeds its bounded byte limit",
                                 "workspace_schema_v9.read_workbench_state"));
    }
    record.payload_json = column_text_v9(statement.get(), 5);
    record.updated_utc_ms = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 6));
    if (record.workspace_id == 0 || record.contract_schema_version == 0 ||
        record.revision == 0 || record.fingerprint == 0 ||
        record.payload_json.size() != static_cast<std::size_t>(declared_length)) {
        return workspace_result_t<std::optional<workbench_state_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "persisted workbench state metadata is inconsistent",
                                 "workspace_schema_v9.read_workbench_state"));
    }
    return workspace_result_t<std::optional<workbench_state_record_t>>::success(
        std::optional<workbench_state_record_t>(std::move(record)));
}

workspace_result_t<void> write_decompiler_cache_v9(
    sqlite3* database, const decompiler_cache_v9_record_t& record) {
    if (record.cache_key.empty() || record.cache_key.size() > 16384 ||
        record.binary_id.empty() || record.function_content_hash.empty() ||
        record.engine_version.size() > 65536 ||
        record.specification_version.size() > 65536 ||
        record.settings_hash.size() > 65536 || record.schema_version == 0 ||
        record.cache_key_version != decompiler_cache_v9_key_version ||
        record.function_rva_address.space != address_space_id_t::relative_virtual ||
        record.function_rva_address.value != record.function_rva ||
        record.function_rva_address.architecture != record.architecture ||
        record.function_rva_address.mode != record.architecture_mode) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "decompiler cache v9 key is empty or too long",
                                 "workspace_schema_v9.write_decompiler_cache_v9"));
    }
    if (record.result_json.empty() ||
        record.result_json.size() > (64ULL << 20) ||
        record.result_bytes != record.result_json.size() ||
        record.function_name.size() > 4096) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "decompiler cache v9 result json is empty or size mismatch",
                                 "workspace_schema_v9.write_decompiler_cache_v9"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO decompiler_cache_v9(cache_key,binary_id,format,architecture,architecture_mode,abi,endian,engine_version,schema_version,specification_version,settings_hash,function_id,function_rva,function_rva_space,function_rva_arch,function_rva_mode,function_content_hash,analysis_revision,overlay_revision,generation,function_name,result_json,created_utc_ms,last_access_utc_ms,result_bytes,cache_key_version)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26)
ON CONFLICT(cache_key) DO UPDATE SET function_name=excluded.function_name,result_json=excluded.result_json,last_access_utc_ms=excluded.last_access_utc_ms,result_bytes=excluded.result_bytes
WHERE decompiler_cache_v9.binary_id=excluded.binary_id
  AND decompiler_cache_v9.format=excluded.format
  AND decompiler_cache_v9.architecture=excluded.architecture
  AND decompiler_cache_v9.architecture_mode=excluded.architecture_mode
  AND decompiler_cache_v9.abi=excluded.abi
  AND decompiler_cache_v9.endian=excluded.endian
  AND decompiler_cache_v9.engine_version=excluded.engine_version
  AND decompiler_cache_v9.schema_version=excluded.schema_version
  AND decompiler_cache_v9.specification_version=excluded.specification_version
  AND decompiler_cache_v9.settings_hash=excluded.settings_hash
  AND decompiler_cache_v9.function_id=excluded.function_id
  AND decompiler_cache_v9.function_rva=excluded.function_rva
  AND decompiler_cache_v9.function_rva_space=excluded.function_rva_space
  AND decompiler_cache_v9.function_rva_arch=excluded.function_rva_arch
  AND decompiler_cache_v9.function_rva_mode=excluded.function_rva_mode
  AND decompiler_cache_v9.function_content_hash=excluded.function_content_hash
  AND decompiler_cache_v9.analysis_revision=excluded.analysis_revision
  AND decompiler_cache_v9.overlay_revision=excluded.overlay_revision
  AND decompiler_cache_v9.generation=excluded.generation
  AND decompiler_cache_v9.cache_key_version=excluded.cache_key_version
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
    result = statement.step_done();
    if (!result)
        return result;
    if (sqlite3_changes(database) != 1) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::target_conflict,
                                 "decompiler cache key conflicts with stored identity metadata",
                                 "workspace_schema_v9.write_decompiler_cache_v9"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::optional<decompiler_cache_v9_record_t>>
    read_decompiler_cache_v9(sqlite3* database, const std::string& cache_key) {
    if (cache_key.empty() || cache_key.size() > 16384) {
        return workspace_result_t<std::optional<decompiler_cache_v9_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "decompiler cache v9 lookup key is empty or too long",
                                 "workspace_schema_v9.read_decompiler_cache_v9"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database,
        "SELECT cache_key,binary_id,format,architecture,architecture_mode,abi,endian,engine_version,schema_version,specification_version,settings_hash,function_id,function_rva,function_rva_space,function_rva_arch,function_rva_mode,function_content_hash,analysis_revision,overlay_revision,generation,length(CAST(function_name AS BLOB)),function_name,length(CAST(result_json AS BLOB)),result_json,created_utc_ms,last_access_utc_ms,result_bytes,cache_key_version FROM decompiler_cache_v9 WHERE cache_key=?1",
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
    const int cache_key_bytes = sqlite3_column_bytes(statement.get(), 0);
    const int engine_version_bytes = sqlite3_column_bytes(statement.get(), 7);
    const int specification_version_bytes = sqlite3_column_bytes(statement.get(), 9);
    const int settings_hash_bytes = sqlite3_column_bytes(statement.get(), 10);
    if (cache_key_bytes <= 0 || cache_key_bytes > 16384 ||
        engine_version_bytes < 0 || engine_version_bytes > 65536 ||
        specification_version_bytes < 0 || specification_version_bytes > 65536 ||
        settings_hash_bytes < 0 || settings_hash_bytes > 65536) {
        return workspace_result_t<std::optional<decompiler_cache_v9_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "decompiler cache v9 metadata exceeds its bounded byte limit",
                                 "workspace_schema_v9.read_decompiler_cache_v9"));
    }
    decompiler_cache_v9_record_t record;
    record.cache_key = column_text_v9(statement.get(), 0);
    const void* binary_blob = sqlite3_column_blob(statement.get(), 1);
    const int binary_bytes = sqlite3_column_bytes(statement.get(), 1);
    if (!binary_blob || binary_bytes != static_cast<int>(record.binary_id.bytes.size()))
        return workspace_result_t<std::optional<decompiler_cache_v9_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "decompiler cache v9 binary identity is malformed",
                                 "workspace_schema_v9.read_decompiler_cache_v9"));
    std::memcpy(record.binary_id.bytes.data(), binary_blob, record.binary_id.bytes.size());
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
    record.function_rva_address.value = record.function_rva;
    const void* content_hash_blob = sqlite3_column_blob(statement.get(), 16);
    const int content_hash_bytes = sqlite3_column_bytes(statement.get(), 16);
    if (!content_hash_blob ||
        content_hash_bytes != static_cast<int>(record.function_content_hash.bytes.size()))
        return workspace_result_t<std::optional<decompiler_cache_v9_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "decompiler cache v9 content identity is malformed",
                                 "workspace_schema_v9.read_decompiler_cache_v9"));
    std::memcpy(record.function_content_hash.bytes.data(), content_hash_blob,
                record.function_content_hash.bytes.size());
    record.analysis_revision = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 17));
    record.overlay_revision = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 18));
    record.generation = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 19));
    const auto function_name_length = sqlite3_column_int64(statement.get(), 20);
    const auto declared_length = sqlite3_column_int64(statement.get(), 22);
    if (function_name_length < 0 || function_name_length > 4096 ||
        declared_length <= 0 || declared_length > (64LL << 20)) {
        return workspace_result_t<std::optional<decompiler_cache_v9_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "decompiler cache v9 text exceeds its bounded byte limit",
                                 "workspace_schema_v9.read_decompiler_cache_v9"));
    }
    record.function_name = column_text_v9(statement.get(), 21);
    record.result_json = column_text_v9(statement.get(), 23);
    record.created_utc_ms = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 24));
    record.last_access_utc_ms = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 25));
    record.result_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 26));
    record.cache_key_version = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 27));
    if (record.cache_key != cache_key ||
        record.cache_key_version != decompiler_cache_v9_key_version ||
        record.function_rva_address.space != address_space_id_t::relative_virtual ||
        record.function_rva_address.architecture != record.architecture ||
        record.function_rva_address.mode != record.architecture_mode ||
        static_cast<std::uint64_t>(function_name_length) != record.function_name.size() ||
        static_cast<std::uint64_t>(declared_length) != record.result_json.size() ||
        record.result_bytes != record.result_json.size() ||
        record.function_name.size() > 4096) {
        return workspace_result_t<std::optional<decompiler_cache_v9_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "decompiler cache v9 result length is inconsistent",
                                 "workspace_schema_v9.read_decompiler_cache_v9"));
    }
    return workspace_result_t<std::optional<decompiler_cache_v9_record_t>>::success(
        std::optional<decompiler_cache_v9_record_t>(std::move(record)));
}

workspace_result_t<std::uint64_t> delete_decompiler_cache_v9_ranges(
    sqlite3* database, const std::vector<decompiler_cache_v9_range_t>& ranges,
    std::optional<std::uint64_t> minimum_overlay_revision) {
    if (!database) {
        return workspace_result_t<std::uint64_t>::failure(schema_v9_error(
            database, SQLITE_MISUSE,
            "decompiler cache v9 range delete requires an open database",
            "workspace_schema_v9.delete_decompiler_cache_v9_ranges"));
    }
    if (ranges.empty())
        return workspace_result_t<std::uint64_t>::success(0);
    if (ranges.size() > decompiler_cache_v9_range_delete_max) {
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "decompiler cache v9 range delete exceeds its bounded range count",
                "workspace_schema_v9.delete_decompiler_cache_v9_ranges"));
    }
    std::vector<decompiler_cache_v9_range_t> normalized;
    normalized.reserve(ranges.size());
    for (const auto& range : ranges) {
        if (range.rva_begin >= range.rva_end)
            continue;
        normalized.push_back(range);
    }
    if (normalized.empty())
        return workspace_result_t<std::uint64_t>::success(0);
    constexpr std::size_t ranges_per_statement = 64;
    std::uint64_t deleted_total = 0;
    for (std::size_t chunk = 0; chunk < normalized.size();
         chunk += ranges_per_statement) {
        const std::size_t chunk_count =
            (std::min)(ranges_per_statement, normalized.size() - chunk);
        std::string sql = "DELETE FROM decompiler_cache_v9 WHERE (";
        for (std::size_t index = 0; index < chunk_count; ++index) {
            if (index != 0)
                sql += " OR ";
            sql += "(function_rva>=?" + std::to_string(index * 2 + 1) +
                   " AND function_rva<?" + std::to_string(index * 2 + 2) + ")";
        }
        sql += ")";
        if (minimum_overlay_revision) {
            sql += " AND overlay_revision>=?" +
                   std::to_string(chunk_count * 2 + 1);
        }
        v9_statement_t statement;
        auto result = statement.prepare(
            database, sql.c_str(),
            "workspace_schema_v9.delete_decompiler_cache_v9_ranges");
        if (!result)
            return workspace_result_t<std::uint64_t>::failure(result.error());
        for (std::size_t index = 0; index < chunk_count; ++index) {
            result = statement.bind_uint(
                static_cast<int>(index * 2 + 1), normalized[chunk + index].rva_begin);
            if (!result)
                return workspace_result_t<std::uint64_t>::failure(result.error());
            result = statement.bind_uint(
                static_cast<int>(index * 2 + 2), normalized[chunk + index].rva_end);
            if (!result)
                return workspace_result_t<std::uint64_t>::failure(result.error());
        }
        if (minimum_overlay_revision) {
            result = statement.bind_uint(
                static_cast<int>(chunk_count * 2 + 1), *minimum_overlay_revision);
            if (!result)
                return workspace_result_t<std::uint64_t>::failure(result.error());
        }
        result = statement.step_done();
        if (!result)
            return workspace_result_t<std::uint64_t>::failure(result.error());
        const int deleted = sqlite3_changes(database);
        if (deleted > 0)
            deleted_total += static_cast<std::uint64_t>(deleted);
    }
    return workspace_result_t<std::uint64_t>::success(deleted_total);
}

workspace_result_t<std::optional<paged_domain_revision_tag_t>>
    read_paged_domain_revision_tag(sqlite3* database, std::uint64_t generation) {
    if (!database) {
        return workspace_result_t<std::optional<paged_domain_revision_tag_t>>::failure(
            schema_v9_error(database, SQLITE_MISUSE,
                            "paged-domain revision tag read requires an open database",
                            "workspace_schema_v9.read_paged_domain_revision_tag"));
    }
    if (generation == 0) {
        return workspace_result_t<std::optional<paged_domain_revision_tag_t>>::failure(
            make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "paged-domain revision tag requires a non-zero generation",
                "workspace_schema_v9.read_paged_domain_revision_tag"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(
        database,
        "SELECT generation,analysis_revision,overlay_revision FROM packed_generations WHERE generation=?1 AND committed=1",
        "workspace_schema_v9.read_paged_domain_revision_tag");
    if (!result)
        return workspace_result_t<std::optional<paged_domain_revision_tag_t>>::failure(
            result.error());
    result = statement.bind_uint(1, generation);
    if (!result)
        return workspace_result_t<std::optional<paged_domain_revision_tag_t>>::failure(
            result.error());
    const int status = sqlite3_step(statement.get());
    if (status == SQLITE_DONE)
        return workspace_result_t<std::optional<paged_domain_revision_tag_t>>::success(
            std::nullopt);
    if (status != SQLITE_ROW) {
        return workspace_result_t<std::optional<paged_domain_revision_tag_t>>::failure(
            schema_v9_error(database, status,
                            "unable to read paged-domain revision tag",
                            "workspace_schema_v9.read_paged_domain_revision_tag"));
    }
    paged_domain_revision_tag_t tag;
    tag.generation = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
    tag.analysis_revision =
        static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
    tag.overlay_revision =
        static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2));
    if (tag.generation != generation) {
        return workspace_result_t<std::optional<paged_domain_revision_tag_t>>::failure(
            make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "paged-domain revision tag generation is inconsistent",
                "workspace_schema_v9.read_paged_domain_revision_tag"));
    }
    return workspace_result_t<std::optional<paged_domain_revision_tag_t>>::success(
        std::optional<paged_domain_revision_tag_t>(tag));
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
    if (!image_hash_blob ||
        image_hash_bytes != static_cast<int>(record.target_image_hash.size()))
        return workspace_result_t<std::optional<overlay_v9_state_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "overlay v9 target image hash is malformed",
                                 "workspace_schema_v9.read_overlay_v9_state"));
    std::memcpy(record.target_image_hash.data(), image_hash_blob, record.target_image_hash.size());
    const void* provenance_hash_blob = sqlite3_column_blob(statement.get(), 1);
    const int provenance_hash_bytes = sqlite3_column_bytes(statement.get(), 1);
    if (!provenance_hash_blob ||
        provenance_hash_bytes != static_cast<int>(record.target_provenance_hash.size()))
        return workspace_result_t<std::optional<overlay_v9_state_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "overlay v9 target provenance hash is malformed",
                                 "workspace_schema_v9.read_overlay_v9_state"));
    std::memcpy(record.target_provenance_hash.data(), provenance_hash_blob,
                record.target_provenance_hash.size());
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

static workspace_result_t<void> write_packed_generation_atomic_v9(
    sqlite3* database, const packed_generation_publication_t& publication,
    const packed_publish_stop_predicate_t& stop_requested,
    bool mark_committed,
    const std::string* candidate_token) {
    if (candidate_token && !valid_candidate_token_v9(*candidate_token)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "packed generation candidate token is malformed",
            "workspace_schema_v9.stage_atomic"));
    }
    if (publish_stop_requested_v9(stop_requested))
        return cancelled_publish_error();
    auto result = validate_publication_v9(publication, stop_requested);
    if (!result)
        return result;
    result = exec_sql_v9(database, "BEGIN IMMEDIATE",
                         "workspace_schema_v9.publish_atomic.begin");
    if (!result)
        return result;
    const auto fail = [&](workspace_result_t<void> failure) {
        exec_sql_v9(database, "ROLLBACK", "workspace_schema_v9.publish_atomic.rollback");
        return failure;
    };
    if (candidate_token) {
        v9_statement_t candidate;
        result = candidate.prepare(database,
            "SELECT 1 FROM workspace_commit_state WHERE singleton=1 AND candidate_ready=1 AND candidate_token=?1 AND candidate_generation=?2 AND candidate_analysis_revision=?3 AND candidate_overlay_revision=?4",
            "workspace_schema_v9.stage_atomic.candidate");
        if (!result)
            return fail(std::move(result));
        result = candidate.bind_text(1, *candidate_token);
        if (!result)
            return fail(std::move(result));
        result = candidate.bind_uint(2, publication.generation.generation);
        if (!result)
            return fail(std::move(result));
        result = candidate.bind_uint(3, publication.generation.analysis_revision);
        if (!result)
            return fail(std::move(result));
        result = candidate.bind_uint(4, publication.generation.overlay_revision);
        if (!result)
            return fail(std::move(result));
        const int candidate_status = sqlite3_step(candidate.get());
        if (candidate_status != SQLITE_ROW) {
            if (candidate_status != SQLITE_DONE) {
                return fail(workspace_result_t<void>::failure(schema_v9_error(
                    database, candidate_status,
                    "unable to verify packed-generation candidate ownership",
                    "workspace_schema_v9.stage_atomic")));
            }
            return fail(workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::revision_conflict,
                                     "packed generation is not bound to the pending snapshot candidate",
                                     "workspace_schema_v9.stage_atomic")));
        }
    }
    auto existing = read_packed_generation(
        database, publication.generation.generation, false, stop_requested);
    if (!existing)
        return fail(workspace_result_t<void>::failure(existing.error()));
    if (existing.value() && existing.value()->committed) {
        return fail(workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::target_conflict,
                                 "packed generation is already committed",
                                 "workspace_schema_v9.publish_atomic")));
    }
    result = delete_uncommitted_rows_v9(database,
                                        publication.generation.generation);
    if (!result)
        return fail(std::move(result));
    if (publish_stop_requested_v9(stop_requested))
        return fail(cancelled_publish_error());

    auto manifest = publication.generation;
    manifest.committed = false;
    result = write_packed_generation(database, manifest);
    if (!result)
        return fail(std::move(result));
    v9_statement_t page_statement;
    result = page_statement.prepare(database, R"SQL(
INSERT INTO packed_pages(generation,page_index,page_count,page_type,payload_length,checksum,payload)
VALUES(?1,?2,?3,?4,?5,?6,?7)
)SQL", "workspace_schema_v9.publish_atomic.page");
    if (!result)
        return fail(std::move(result));
    for (const auto& page : publication.pages) {
        if (publish_stop_requested_v9(stop_requested))
            return fail(cancelled_publish_error());
        result = page_statement.bind_uint(1, page.generation); if (!result) return fail(std::move(result));
        result = page_statement.bind_int(2, static_cast<std::int64_t>(page.page_index)); if (!result) return fail(std::move(result));
        result = page_statement.bind_int(3, static_cast<std::int64_t>(page.page_count)); if (!result) return fail(std::move(result));
        result = page_statement.bind_int(4, static_cast<std::int64_t>(page.page_type)); if (!result) return fail(std::move(result));
        result = page_statement.bind_int(5, static_cast<std::int64_t>(page.payload_length)); if (!result) return fail(std::move(result));
        result = page_statement.bind_int(6, static_cast<std::int64_t>(page.checksum)); if (!result) return fail(std::move(result));
        result = page_statement.bind_blob(7, page.payload.data(), page.payload.size()); if (!result) return fail(std::move(result));
        result = page_statement.step_done();
        if (!result)
            return fail(std::move(result));
        result = page_statement.reset();
        if (!result)
            return fail(std::move(result));
    }
    v9_statement_t index_statement;
    result = index_statement.prepare(database, R"SQL(
INSERT INTO packed_page_index(generation,domain,ordinal_begin,count,page_index,address_value_min,address_value_max)
VALUES(?1,?2,?3,?4,?5,?6,?7)
)SQL", "workspace_schema_v9.publish_atomic.index");
    if (!result)
        return fail(std::move(result));
    for (const auto& index : publication.index) {
        if (publish_stop_requested_v9(stop_requested))
            return fail(cancelled_publish_error());
        result = index_statement.bind_uint(1, index.generation); if (!result) return fail(std::move(result));
        result = index_statement.bind_int(2, static_cast<std::int64_t>(index.domain)); if (!result) return fail(std::move(result));
        result = index_statement.bind_int(3, static_cast<std::int64_t>(index.ordinal_begin)); if (!result) return fail(std::move(result));
        result = index_statement.bind_int(4, static_cast<std::int64_t>(index.count)); if (!result) return fail(std::move(result));
        result = index_statement.bind_int(5, static_cast<std::int64_t>(index.page_index)); if (!result) return fail(std::move(result));
        result = index_statement.bind_uint(6, index.address_value_min); if (!result) return fail(std::move(result));
        result = index_statement.bind_uint(7, index.address_value_max); if (!result) return fail(std::move(result));
        result = index_statement.step_done();
        if (!result)
            return fail(std::move(result));
        result = index_statement.reset();
        if (!result)
            return fail(std::move(result));
    }
    if (mark_committed) {
        v9_statement_t commit_statement;
        result = commit_statement.prepare(database,
            "UPDATE packed_generations SET committed=1 WHERE generation=?1 AND committed=0",
            "workspace_schema_v9.publish_atomic.marker");
        if (!result)
            return fail(std::move(result));
        result = commit_statement.bind_uint(1, manifest.generation);
        if (!result)
            return fail(std::move(result));
        result = commit_statement.step_done();
        if (!result)
            return fail(std::move(result));
        if (sqlite3_changes(database) != 1) {
            return fail(workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::target_conflict,
                                     "packed generation commit marker was not staged",
                                     "workspace_schema_v9.publish_atomic")));
        }
    }
    if (publish_stop_requested_v9(stop_requested))
        return fail(cancelled_publish_error());
    result = exec_sql_v9(database, "COMMIT",
                         "workspace_schema_v9.publish_atomic.commit");
    if (!result) {
        exec_sql_v9(database, "ROLLBACK", "workspace_schema_v9.publish_atomic.rollback");
        return result;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> publish_packed_generation_atomic(
    sqlite3* database, const packed_generation_publication_t& publication,
    const packed_publish_stop_predicate_t& stop_requested) {
    return write_packed_generation_atomic_v9(
        database, publication, stop_requested, true, nullptr);
}

workspace_result_t<void> stage_packed_generation_atomic(
    sqlite3* database, const packed_generation_publication_t& publication,
    const std::string& candidate_token,
    const packed_publish_stop_predicate_t& stop_requested) {
    return write_packed_generation_atomic_v9(
        database, publication, stop_requested, false, &candidate_token);
}

workspace_result_t<void> stage_packed_generation_stream_atomic(
    sqlite3* database,
    const packed_generation_stream_descriptor_t& descriptor,
    const std::string& candidate_token,
    const packed_page_stream_producer_t& producer,
    const packed_publish_stop_predicate_t& stop_requested) {
    const auto& generation = descriptor.generation;
    if (!database || !producer || !valid_candidate_token_v9(candidate_token) ||
        generation.generation == 0 || generation.committed ||
        generation.shard_count == 0 ||
        generation.shard_count > static_cast<std::uint16_t>(packed_page_last_data_type) ||
        generation.total_records > packed_generation_max_records ||
        generation.payload_blob.size() > packed_generation_max_metadata_bytes ||
        descriptor.page_count == 0 ||
        descriptor.page_count > packed_generation_max_pages ||
        descriptor.payload_quota_bytes == 0 ||
        descriptor.payload_quota_bytes > packed_generation_max_payload_bytes ||
        generation.total_payload_bytes > descriptor.payload_quota_bytes) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "packed stream descriptor exceeds its bounded invariants",
                                 "workspace_schema_v9.stream_atomic"));
    }
    if (publish_stop_requested_v9(stop_requested))
        return cancelled_publish_error();
    auto result = exec_sql_v9(database, "BEGIN IMMEDIATE",
                              "workspace_schema_v9.stream_atomic.begin");
    if (!result)
        return result;
    const auto fail = [&](workspace_result_t<void> failure) {
        exec_sql_v9(database, "ROLLBACK",
                    "workspace_schema_v9.stream_atomic.rollback");
        return failure;
    };

    v9_statement_t candidate;
    result = candidate.prepare(database,
        "SELECT 1 FROM workspace_commit_state WHERE singleton=1 AND candidate_ready=1 AND candidate_token=?1 AND candidate_generation=?2 AND candidate_analysis_revision=?3 AND candidate_overlay_revision=?4",
        "workspace_schema_v9.stream_atomic.candidate");
    if (!result)
        return fail(std::move(result));
    result = candidate.bind_text(1, candidate_token); if (!result) return fail(std::move(result));
    result = candidate.bind_uint(2, generation.generation); if (!result) return fail(std::move(result));
    result = candidate.bind_uint(3, generation.analysis_revision); if (!result) return fail(std::move(result));
    result = candidate.bind_uint(4, generation.overlay_revision); if (!result) return fail(std::move(result));
    const int candidate_status = sqlite3_step(candidate.get());
    if (candidate_status != SQLITE_ROW) {
        return fail(workspace_result_t<void>::failure(
            candidate_status == SQLITE_DONE
                ? make_workspace_error(workspace_error_code_t::revision_conflict,
                                       "packed stream is not bound to the pending snapshot candidate",
                                       "workspace_schema_v9.stream_atomic")
                : schema_v9_error(database, candidate_status,
                                  "unable to verify packed stream candidate ownership",
                                  "workspace_schema_v9.stream_atomic")));
    }
    auto existing = read_packed_generation(
        database, generation.generation, false, stop_requested);
    if (!existing)
        return fail(workspace_result_t<void>::failure(existing.error()));
    if (existing.value() && existing.value()->committed) {
        return fail(workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::target_conflict,
                                 "packed generation is already committed",
                                 "workspace_schema_v9.stream_atomic")));
    }
    result = delete_uncommitted_rows_v9(database, generation.generation);
    if (!result)
        return fail(std::move(result));
    auto staged_generation = generation;
    staged_generation.batch_checksum = 0;
    result = write_packed_generation(database, staged_generation);
    if (!result)
        return fail(std::move(result));

    v9_statement_t page_statement;
    result = page_statement.prepare(database, R"SQL(
INSERT INTO packed_pages(generation,page_index,page_count,page_type,payload_length,checksum,payload,logical_length)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
)SQL", "workspace_schema_v9.stream_atomic.page");
    if (!result)
        return fail(std::move(result));
    v9_statement_t index_statement;
    result = index_statement.prepare(database, R"SQL(
INSERT INTO packed_page_index(generation,domain,ordinal_begin,count,page_index,address_value_min,address_value_max)
VALUES(?1,?2,?3,?4,?5,?6,?7)
)SQL", "workspace_schema_v9.stream_atomic.index");
    if (!result)
        return fail(std::move(result));

    std::uint32_t next_page = 0;
    std::uint64_t observed_payload_bytes = 0;
    std::uint64_t observed_records = 0;
    std::vector<std::uint8_t> checksum_bytes;
    checksum_bytes.reserve(static_cast<std::size_t>(descriptor.page_count) * 4U);
    std::unordered_set<std::uint16_t> domains;
    std::array<std::uint64_t,
               static_cast<std::size_t>(packed_page_last_data_type) + 1U>
        next_domain_ordinals{};
    workspace_result_t<void> sink_failure = workspace_result_t<void>::success();
    const packed_page_stream_sink_t sink =
        [&](packed_page_row_t page, packed_page_index_row_t index)
            -> workspace_result_t<void> {
        if (!sink_failure)
            return sink_failure;
        if (publish_stop_requested_v9(stop_requested)) {
            sink_failure = cancelled_publish_error();
            return sink_failure;
        }
        if (page.generation != generation.generation ||
            page.page_index != next_page || page.page_count != descriptor.page_count ||
            page.page_type < static_cast<std::uint32_t>(packed_page_type_t::instructions) ||
            page.page_type > static_cast<std::uint32_t>(packed_page_last_data_type) ||
            page.payload.size() < packed_record_page_prefix_size ||
            page.payload.size() > packed_page_max_payload ||
            page.payload_length != page.payload.size() ||
            (page.logical_length != 0 &&
             (page.logical_length < packed_record_page_prefix_size ||
              page.logical_length > packed_page_max_payload)) ||
            index.generation != generation.generation ||
            index.page_index != page.page_index ||
            index.domain != static_cast<std::uint16_t>(page.page_type)) {
            sink_failure = workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "packed stream emitted an invalid page identity",
                                     "workspace_schema_v9.stream_atomic"));
            return sink_failure;
        }
        packed_page_t verified_page;
        verified_page.header.generation = page.generation;
        verified_page.header.analysis_revision = generation.analysis_revision;
        verified_page.header.overlay_revision = generation.overlay_revision;
        verified_page.header.version = page.logical_length != 0
            ? packed_page_blob_version_v3 : packed_page_blob_version;
        verified_page.header.page_type = page.page_type;
        verified_page.header.page_index = page.page_index;
        verified_page.header.page_count = page.page_count;
        verified_page.header.payload_length = page.payload_length;
        verified_page.header.checksum = page.checksum;
        verified_page.payload = page.payload;
        auto verified = packed_page_codec_t::verify_page(
            verified_page, stop_requested);
        if (!verified) {
            sink_failure = verified;
            return sink_failure;
        }
        if (page.logical_length != 0) {
            const auto frame_content_length = packed_page_frame_content_length_v9(
                page.payload.data(), page.payload.size());
            if (!frame_content_length ||
                *frame_content_length + packed_record_page_prefix_size !=
                    page.logical_length) {
                sink_failure = workspace_result_t<void>::failure(
                    make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "packed stream page logical length does not match its frame",
                        "workspace_schema_v9.stream_atomic"));
                return sink_failure;
            }
        }
        auto prefix = packed_record_page_prefix_t::decode(
            page.payload.data(), page.payload.size());
        const auto domain_index = static_cast<std::size_t>(page.page_type);
        std::uint64_t next_domain_ordinal = 0;
        const std::uint64_t logical_bytes = page.logical_length != 0
            ? static_cast<std::uint64_t>(page.logical_length)
            : static_cast<std::uint64_t>(page.payload.size());
        if (!prefix || index.ordinal_begin != prefix->ordinal_begin ||
            index.count != prefix->record_count ||
            index.address_value_min != prefix->address_value_min ||
            index.address_value_max != prefix->address_value_max ||
            prefix->ordinal_begin != next_domain_ordinals[domain_index] ||
            !checked_add_u64(next_domain_ordinals[domain_index],
                             prefix->record_count, next_domain_ordinal) ||
            !checked_add_u64(observed_payload_bytes, logical_bytes,
                             observed_payload_bytes) ||
            observed_payload_bytes > descriptor.payload_quota_bytes ||
            !checked_add_u64(observed_records, prefix->record_count,
                             observed_records) ||
            observed_records > packed_generation_max_records) {
            sink_failure = workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "packed stream page metadata is inconsistent",
                                     "workspace_schema_v9.stream_atomic"));
            return sink_failure;
        }
        next_domain_ordinals[domain_index] = next_domain_ordinal;

        result = page_statement.bind_uint(1, page.generation); if (!result) { sink_failure = result; return sink_failure; }
        result = page_statement.bind_int(2, page.page_index); if (!result) { sink_failure = result; return sink_failure; }
        result = page_statement.bind_int(3, page.page_count); if (!result) { sink_failure = result; return sink_failure; }
        result = page_statement.bind_int(4, page.page_type); if (!result) { sink_failure = result; return sink_failure; }
        result = page_statement.bind_int(5, page.payload_length); if (!result) { sink_failure = result; return sink_failure; }
        result = page_statement.bind_int(6, static_cast<std::int64_t>(page.checksum)); if (!result) { sink_failure = result; return sink_failure; }
        result = page_statement.bind_blob(7, page.payload.data(), page.payload.size()); if (!result) { sink_failure = result; return sink_failure; }
        if (page.logical_length != 0) {
            result = page_statement.bind_int(8, static_cast<std::int64_t>(page.logical_length));
        } else {
            result = page_statement.bind_null(8);
        }
        if (!result) { sink_failure = result; return sink_failure; }
        result = page_statement.step_done(); if (!result) { sink_failure = result; return sink_failure; }
        result = page_statement.reset(); if (!result) { sink_failure = result; return sink_failure; }

        result = index_statement.bind_uint(1, index.generation); if (!result) { sink_failure = result; return sink_failure; }
        result = index_statement.bind_int(2, index.domain); if (!result) { sink_failure = result; return sink_failure; }
        result = index_statement.bind_int(3, index.ordinal_begin); if (!result) { sink_failure = result; return sink_failure; }
        result = index_statement.bind_int(4, index.count); if (!result) { sink_failure = result; return sink_failure; }
        result = index_statement.bind_int(5, index.page_index); if (!result) { sink_failure = result; return sink_failure; }
        result = index_statement.bind_uint(6, index.address_value_min); if (!result) { sink_failure = result; return sink_failure; }
        result = index_statement.bind_uint(7, index.address_value_max); if (!result) { sink_failure = result; return sink_failure; }
        result = index_statement.step_done(); if (!result) { sink_failure = result; return sink_failure; }
        result = index_statement.reset(); if (!result) { sink_failure = result; return sink_failure; }

        append_u32_le_v9(checksum_bytes, page.checksum);
        domains.insert(index.domain);
        ++next_page;
        return workspace_result_t<void>::success();
    };

    auto produced = producer(sink, stop_requested);
    if (!produced)
        return fail(std::move(produced));
    if (!sink_failure)
        return fail(std::move(sink_failure));
    if (next_page != descriptor.page_count ||
        observed_payload_bytes != generation.total_payload_bytes ||
        observed_records != generation.total_records ||
        domains.size() != generation.shard_count) {
        return fail(workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "packed stream totals do not match its descriptor",
                                 "workspace_schema_v9.stream_atomic")));
    }
    auto checksum = crc32c_cancellable(checksum_bytes.data(),
                                       checksum_bytes.size(), stop_requested);
    if (!checksum)
        return fail(workspace_result_t<void>::failure(checksum.error()));
    v9_statement_t finalize;
    result = finalize.prepare(database,
        "UPDATE packed_generations SET batch_checksum=?1 WHERE generation=?2 AND committed=0 AND total_payload_bytes=?3 AND total_records=?4",
        "workspace_schema_v9.stream_atomic.finalize");
    if (!result)
        return fail(std::move(result));
    result = finalize.bind_int(1, static_cast<std::int64_t>(checksum.value())); if (!result) return fail(std::move(result));
    result = finalize.bind_uint(2, generation.generation); if (!result) return fail(std::move(result));
    result = finalize.bind_uint(3, observed_payload_bytes); if (!result) return fail(std::move(result));
    result = finalize.bind_uint(4, observed_records); if (!result) return fail(std::move(result));
    result = finalize.step_done(); if (!result) return fail(std::move(result));
    if (sqlite3_changes(database) != 1) {
        return fail(workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "packed stream manifest was not finalized",
                                 "workspace_schema_v9.stream_atomic")));
    }
    if (publish_stop_requested_v9(stop_requested))
        return fail(cancelled_publish_error());
    result = exec_sql_v9(database, "COMMIT",
                         "workspace_schema_v9.stream_atomic.commit");
    if (!result) {
        exec_sql_v9(database, "ROLLBACK",
                    "workspace_schema_v9.stream_atomic.rollback");
        return result;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> visit_packed_domain_pages(
    sqlite3* database, std::uint64_t generation, packed_page_type_t domain,
    const packed_domain_page_visitor_t& visitor,
    const packed_stop_predicate_t& stop_requested,
    bool require_domain,
    bool* domain_present) {
    if (domain_present)
        *domain_present = false;
    const auto encoded_domain = static_cast<std::uint32_t>(domain);
    if (!database || generation == 0 || !visitor ||
        encoded_domain < static_cast<std::uint32_t>(packed_page_type_t::instructions) ||
        encoded_domain > static_cast<std::uint32_t>(packed_page_last_data_type)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "packed domain visitor identity is invalid",
                                 "workspace_schema_v9.visit_domain"));
    }
    auto manifest = read_packed_generation(database, generation, true,
                                           stop_requested);
    if (!manifest)
        return workspace_result_t<void>::failure(manifest.error());
    if (!manifest.value()) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                                 "packed generation is not committed",
                                 "workspace_schema_v9.visit_domain"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
SELECT p.generation,p.page_index,p.page_count,p.page_type,p.payload_length,p.checksum,p.payload,
       i.domain,i.ordinal_begin,i.count,i.address_value_min,i.address_value_max,p.logical_length
FROM packed_pages p
JOIN packed_page_index i ON i.generation=p.generation AND i.page_index=p.page_index
JOIN packed_generations g ON g.generation=p.generation AND g.committed=1
WHERE p.generation=?1 AND p.page_type=?2
ORDER BY p.page_index
)SQL", "workspace_schema_v9.visit_domain");
    if (!result)
        return result;
    result = statement.bind_uint(1, generation); if (!result) return result;
    result = statement.bind_int(2, encoded_domain); if (!result) return result;
    std::uint64_t visited = 0;
    for (;;) {
        if (publish_stop_requested_v9(stop_requested))
            return workspace_result_t<void>::failure(
                cancelled_read_error_v9("workspace_schema_v9.visit_domain"));
        const int status = sqlite3_step(statement.get());
        if (status == SQLITE_DONE)
            break;
        if (status != SQLITE_ROW) {
            return workspace_result_t<void>::failure(schema_v9_error(
                database, status, "unable to visit packed domain page",
                "workspace_schema_v9.visit_domain"));
        }
        packed_page_row_t page;
        page.generation = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
        page.page_index = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 1));
        page.page_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 2));
        page.page_type = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 3));
        page.payload_length = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 4));
        page.checksum = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 5));
        const void* blob = sqlite3_column_blob(statement.get(), 6);
        const int blob_size = sqlite3_column_bytes(statement.get(), 6);
        if (blob_size < static_cast<int>(packed_record_page_prefix_size) ||
            blob_size > static_cast<int>(packed_page_max_payload) || !blob ||
            page.payload_length != static_cast<std::uint32_t>(blob_size)) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "packed domain page payload is malformed",
                                     "workspace_schema_v9.visit_domain"));
        }
        auto copied = copy_blob_v9(
            page.payload, static_cast<const std::uint8_t*>(blob),
            static_cast<std::size_t>(blob_size), stop_requested,
            "workspace_schema_v9.visit_domain");
        if (!copied)
            return copied;
        packed_page_index_row_t index;
        index.generation = page.generation;
        index.domain = static_cast<std::uint16_t>(sqlite3_column_int(statement.get(), 7));
        index.ordinal_begin = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 8));
        index.count = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 9));
        index.page_index = page.page_index;
        index.address_value_min = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 10));
        index.address_value_max = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 11));
        std::uint32_t logical_length = 0;
        if (sqlite3_column_type(statement.get(), 12) != SQLITE_NULL) {
            const auto declared_logical_length =
                sqlite3_column_int64(statement.get(), 12);
            if (declared_logical_length <
                    static_cast<std::int64_t>(packed_record_page_prefix_size) ||
                declared_logical_length >
                    static_cast<std::int64_t>(packed_page_max_payload)) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                                         "packed domain page logical length is invalid",
                                         "workspace_schema_v9.visit_domain"));
            }
            logical_length = static_cast<std::uint32_t>(declared_logical_length);
        }
        page.logical_length = logical_length;
        packed_page_t verified_page;
        verified_page.header.generation = page.generation;
        verified_page.header.analysis_revision = manifest.value()->analysis_revision;
        verified_page.header.overlay_revision = manifest.value()->overlay_revision;
        verified_page.header.version = logical_length != 0
            ? packed_page_blob_version_v3 : packed_page_blob_version;
        verified_page.header.page_type = page.page_type;
        verified_page.header.page_index = page.page_index;
        verified_page.header.page_count = page.page_count;
        verified_page.header.payload_length = page.payload_length;
        verified_page.header.checksum = page.checksum;
        verified_page.payload = page.payload;
        auto verified = packed_page_codec_t::verify_page(
            verified_page, stop_requested);
        if (!verified)
            return verified;
        if (logical_length != 0) {
            const auto frame_content_length = packed_page_frame_content_length_v9(
                page.payload.data(), page.payload.size());
            if (!frame_content_length ||
                *frame_content_length + packed_record_page_prefix_size !=
                    logical_length) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "packed domain page logical length does not match its frame",
                        "workspace_schema_v9.visit_domain"));
            }
        }
        auto prefix = packed_record_page_prefix_t::decode(
            page.payload.data(), page.payload.size());
        if (!prefix || index.domain != encoded_domain ||
            index.ordinal_begin != prefix->ordinal_begin ||
            index.count != prefix->record_count ||
            index.address_value_min != prefix->address_value_min ||
            index.address_value_max != prefix->address_value_max) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "packed domain page index is inconsistent",
                                     "workspace_schema_v9.visit_domain"));
        }
        auto visited_result = visitor(page, index);
        if (!visited_result)
            return visited_result;
        ++visited;
    }
    if (domain_present)
        *domain_present = visited != 0;
    if (visited == 0 && require_domain) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "packed generation omits a required domain",
                                 "workspace_schema_v9.visit_domain"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::optional<packed_generation_publication_t>>
    read_packed_generation_publication(sqlite3* database,
                                       std::uint64_t generation,
                                       const packed_stop_predicate_t& stop_requested) {
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<std::optional<packed_generation_publication_t>>::failure(
            cancelled_read_error_v9(
                "workspace_schema_v9.read_packed_generation_publication"));
    auto manifest = read_packed_generation(database, generation, true,
                                           stop_requested);
    if (!manifest)
        return workspace_result_t<std::optional<packed_generation_publication_t>>::failure(
            manifest.error());
    if (!manifest.value())
        return workspace_result_t<std::optional<packed_generation_publication_t>>::success(
            std::nullopt);
    auto pages = read_packed_pages(database, generation, true, stop_requested);
    if (!pages)
        return workspace_result_t<std::optional<packed_generation_publication_t>>::failure(
            pages.error());
    auto index = read_packed_page_index(database, generation, true,
                                        stop_requested);
    if (!index)
        return workspace_result_t<std::optional<packed_generation_publication_t>>::failure(
            index.error());
    packed_generation_publication_t publication;
    publication.generation = std::move(*manifest.value());
    publication.pages = pages.take_value();
    publication.index = index.take_value();
    publication.generation.committed = false;
    auto validated = validate_publication_v9(publication, stop_requested);
    if (!validated)
        return workspace_result_t<std::optional<packed_generation_publication_t>>::failure(
            validated.error());
    publication.generation.committed = true;
    return workspace_result_t<std::optional<packed_generation_publication_t>>::success(
        std::optional<packed_generation_publication_t>(std::move(publication)));
}

workspace_result_t<void> publish_packed_generation(
    sqlite3* database, std::uint64_t generation,
    const packed_stop_predicate_t& stop_requested) {
    if (generation == 0) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "publish generation must be non-zero",
                                 "workspace_schema_v9.publish_packed_generation"));
    }
    auto transaction = exec_sql_v9(
        database, "SAVEPOINT aida_publish_packed_generation_v9",
        "workspace_schema_v9.publish_packed_generation.begin");
    if (!transaction)
        return transaction;
    const auto fail = [&](workspace_result_t<void> failure) {
        exec_sql_v9(database,
            "ROLLBACK TO aida_publish_packed_generation_v9",
            "workspace_schema_v9.publish_packed_generation.rollback");
        exec_sql_v9(database,
            "RELEASE aida_publish_packed_generation_v9",
            "workspace_schema_v9.publish_packed_generation.release");
        return failure;
    };
    if (publish_stop_requested_v9(stop_requested))
        return fail(cancelled_publish_error());
    auto manifest = read_packed_generation(
        database, generation, false, stop_requested);
    if (!manifest)
        return fail(workspace_result_t<void>::failure(manifest.error()));
    if (!manifest.value() || manifest.value()->committed) {
        return fail(workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                                 "packed generation not found or already committed",
                                 "workspace_schema_v9.publish_packed_generation")));
    }
    auto validated = validate_staged_generation_v9(
        database, *manifest.value(), stop_requested);
    if (!validated)
        return fail(std::move(validated));
    if (publish_stop_requested_v9(stop_requested))
        return fail(cancelled_publish_error());
    v9_statement_t statement;
    auto result = statement.prepare(database,
        "UPDATE packed_generations SET committed=1 WHERE generation=?1 AND committed=0",
        "workspace_schema_v9.publish_packed_generation");
    if (!result) return fail(std::move(result));
    result = statement.bind_uint(1, generation);
    if (!result) return fail(std::move(result));
    result = statement.step_done();
    if (!result) return fail(std::move(result));
    if (sqlite3_changes(database) == 0) {
        return fail(workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                                 "packed generation not found or already committed",
                                 "workspace_schema_v9.publish_packed_generation")));
    }
    result = exec_sql_v9(database,
        "RELEASE aida_publish_packed_generation_v9",
        "workspace_schema_v9.publish_packed_generation.commit");
    return result;
}

workspace_result_t<void> rollback_packed_generation(
    sqlite3* database, std::uint64_t generation) {
    if (generation == 0) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "rollback generation must be non-zero",
                                 "workspace_schema_v9.rollback_packed_generation"));
    }
    auto result = exec_sql_v9(database,
                              "SAVEPOINT aida_rollback_packed_generation_v9",
                              "workspace_schema_v9.rollback.begin");
    if (!result)
        return result;
    result = delete_uncommitted_rows_v9(database, generation);
    if (!result) {
        exec_sql_v9(database,
                    "ROLLBACK TO aida_rollback_packed_generation_v9",
                    "workspace_schema_v9.rollback.failure");
        exec_sql_v9(database,
                    "RELEASE aida_rollback_packed_generation_v9",
                    "workspace_schema_v9.rollback.release");
        return result;
    }
    result = exec_sql_v9(database,
                         "RELEASE aida_rollback_packed_generation_v9",
                         "workspace_schema_v9.rollback.commit");
    return result;
}

workspace_result_t<void> publish_packed_generation_metadata(
    sqlite3* database, std::uint64_t generation,
    const packed_stop_predicate_t& stop_requested) {
    if (generation == 0) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "publish generation must be non-zero",
                                 "workspace_schema_v9.publish_packed_generation_metadata"));
    }
    auto transaction = exec_sql_v9(
        database, "SAVEPOINT aida_publish_packed_generation_metadata_v9",
        "workspace_schema_v9.publish_packed_generation_metadata.begin");
    if (!transaction)
        return transaction;
    const auto fail = [&](workspace_result_t<void> failure) {
        exec_sql_v9(database,
            "ROLLBACK TO aida_publish_packed_generation_metadata_v9",
            "workspace_schema_v9.publish_packed_generation_metadata.rollback");
        exec_sql_v9(database,
            "RELEASE aida_publish_packed_generation_metadata_v9",
            "workspace_schema_v9.publish_packed_generation_metadata.release");
        return failure;
    };
    if (publish_stop_requested_v9(stop_requested))
        return fail(cancelled_publish_error());
    auto manifest = read_packed_generation(
        database, generation, false, stop_requested);
    if (!manifest)
        return fail(workspace_result_t<void>::failure(manifest.error()));
    if (!manifest.value() || manifest.value()->committed) {
        return fail(workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                                 "packed generation not found or already committed",
                                 "workspace_schema_v9.publish_packed_generation_metadata")));
    }
    if (manifest.value()->shard_count == 0 ||
        manifest.value()->shard_count >
            static_cast<std::uint16_t>(packed_page_last_data_type) ||
        manifest.value()->total_payload_bytes >
            packed_generation_max_payload_bytes ||
        manifest.value()->total_records > packed_generation_max_records) {
        return fail(workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "staged packed generation metadata is invalid",
                                 "workspace_schema_v9.publish_packed_generation_metadata")));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
SELECT p.page_index,p.page_count,p.page_type,p.checksum,p.payload_length,
       i.domain,i.ordinal_begin,i.count,p.logical_length
FROM packed_pages p
JOIN packed_page_index i ON i.generation=p.generation AND i.page_index=p.page_index
WHERE p.generation=?1
ORDER BY p.page_index
)SQL", "workspace_schema_v9.publish_packed_generation_metadata.validate");
    if (!result)
        return fail(std::move(result));
    result = statement.bind_uint(1, generation);
    if (!result)
        return fail(std::move(result));
    std::uint32_t expected_page_count = 0;
    std::uint32_t next_page_index = 0;
    std::uint64_t observed_payload_bytes = 0;
    std::uint64_t observed_records = 0;
    std::unordered_set<std::uint16_t> domains;
    std::array<std::uint64_t,
               static_cast<std::size_t>(packed_page_last_data_type) + 1U>
        next_domain_ordinals{};
    std::vector<std::uint8_t> checksum_bytes;
    for (;;) {
        if (publish_stop_requested_v9(stop_requested))
            return fail(cancelled_publish_error());
        const int status = sqlite3_step(statement.get());
        if (status == SQLITE_DONE)
            break;
        if (status != SQLITE_ROW) {
            return fail(workspace_result_t<void>::failure(
                schema_v9_error(database, status,
                                "unable to validate staged packed generation metadata",
                                "workspace_schema_v9.publish_packed_generation_metadata")));
        }
        const auto page_index = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 0));
        const auto page_count = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 1));
        const auto page_type = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 2));
        const auto page_checksum = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 3));
        const auto payload_length = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 4));
        const auto domain = static_cast<std::uint16_t>(
            sqlite3_column_int(statement.get(), 5));
        const auto ordinal_begin = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 6));
        const auto record_count = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 7));
        std::uint32_t logical_length = 0;
        if (sqlite3_column_type(statement.get(), 8) != SQLITE_NULL) {
            const auto declared_logical_length =
                sqlite3_column_int64(statement.get(), 8);
            if (declared_logical_length <
                    static_cast<std::int64_t>(packed_record_page_prefix_size) ||
                declared_logical_length >
                    static_cast<std::int64_t>(packed_page_max_payload)) {
                return fail(workspace_result_t<void>::failure(
                    make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "staged packed page logical length is invalid",
                        "workspace_schema_v9.publish_packed_generation_metadata")));
            }
            logical_length = static_cast<std::uint32_t>(declared_logical_length);
        }
        const std::uint64_t logical_bytes = logical_length != 0
            ? static_cast<std::uint64_t>(logical_length)
            : static_cast<std::uint64_t>(payload_length);
        const auto domain_index = static_cast<std::size_t>(page_type);
        std::uint64_t next_domain_ordinal = 0;
        if (page_index != next_page_index || page_count == 0 ||
            page_count > packed_generation_max_pages ||
            (expected_page_count != 0 && page_count != expected_page_count) ||
            page_type < static_cast<std::uint32_t>(
                packed_page_type_t::instructions) ||
            page_type > static_cast<std::uint32_t>(packed_page_last_data_type) ||
            domain != static_cast<std::uint16_t>(page_type) ||
            payload_length < packed_record_page_prefix_size ||
            payload_length > packed_page_max_payload ||
            (logical_length != 0 && logical_length <= payload_length) ||
            ordinal_begin != next_domain_ordinals[domain_index] ||
            !checked_add_u64(next_domain_ordinals[domain_index],
                             record_count, next_domain_ordinal) ||
            !checked_add_u64(observed_payload_bytes, logical_bytes,
                             observed_payload_bytes) ||
            observed_payload_bytes > packed_generation_max_payload_bytes ||
            !checked_add_u64(observed_records, record_count,
                             observed_records) ||
            observed_records > packed_generation_max_records) {
            return fail(workspace_result_t<void>::failure(
                make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "staged packed page metadata is inconsistent",
                    "workspace_schema_v9.publish_packed_generation_metadata")));
        }
        expected_page_count = page_count;
        next_domain_ordinals[domain_index] = next_domain_ordinal;
        append_u32_le_v9(checksum_bytes, page_checksum);
        domains.insert(domain);
        ++next_page_index;
    }
    if (next_page_index == 0 || next_page_index != expected_page_count ||
        domains.size() != manifest.value()->shard_count ||
        observed_payload_bytes != manifest.value()->total_payload_bytes ||
        observed_records != manifest.value()->total_records) {
        return fail(workspace_result_t<void>::failure(
            make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "staged packed generation metadata totals are inconsistent",
                "workspace_schema_v9.publish_packed_generation_metadata")));
    }
    auto checksum = crc32c_cancellable(
        checksum_bytes.data(), checksum_bytes.size(), stop_requested);
    if (!checksum)
        return fail(workspace_result_t<void>::failure(checksum.error()));
    if (checksum.value() != manifest.value()->batch_checksum) {
        return fail(workspace_result_t<void>::failure(
            make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "staged packed generation metadata checksum is inconsistent",
                "workspace_schema_v9.publish_packed_generation_metadata")));
    }
    if (publish_stop_requested_v9(stop_requested))
        return fail(cancelled_publish_error());
    v9_statement_t promote;
    result = promote.prepare(database,
        "UPDATE packed_generations SET committed=1 WHERE generation=?1 AND committed=0",
        "workspace_schema_v9.publish_packed_generation_metadata");
    if (!result) return fail(std::move(result));
    result = promote.bind_uint(1, generation);
    if (!result) return fail(std::move(result));
    result = promote.step_done();
    if (!result) return fail(std::move(result));
    if (sqlite3_changes(database) == 0) {
        return fail(workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                                 "packed generation not found or already committed",
                                 "workspace_schema_v9.publish_packed_generation_metadata")));
    }
    result = exec_sql_v9(database,
        "RELEASE aida_publish_packed_generation_metadata_v9",
        "workspace_schema_v9.publish_packed_generation_metadata.commit");
    return result;
}

workspace_result_t<void> write_packed_generation_staging_page(
    sqlite3* database, const packed_generation_staging_row_t& row) {
    if (!database || row.generation == 0 ||
        row.domain < static_cast<std::uint16_t>(packed_page_type_t::instructions) ||
        row.domain > static_cast<std::uint16_t>(packed_page_last_data_type) ||
        row.payload.size() < packed_record_page_prefix_size ||
        row.payload.size() > packed_page_max_payload) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "packed staging row exceeds its bounded invariants",
                                 "workspace_schema_v9.write_staging_page"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO packed_generation_staging(generation,domain,domain_page_index,ordinal_begin,record_count,address_value_min,address_value_max,payload)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
ON CONFLICT(generation,domain,domain_page_index) DO UPDATE SET ordinal_begin=excluded.ordinal_begin,record_count=excluded.record_count,address_value_min=excluded.address_value_min,address_value_max=excluded.address_value_max,payload=excluded.payload
)SQL", "workspace_schema_v9.write_staging_page");
    if (!result) return result;
    result = statement.bind_uint(1, row.generation); if (!result) return result;
    result = statement.bind_int(2, static_cast<std::int64_t>(row.domain)); if (!result) return result;
    result = statement.bind_int(3, static_cast<std::int64_t>(row.domain_page_index)); if (!result) return result;
    result = statement.bind_int(4, static_cast<std::int64_t>(row.ordinal_begin)); if (!result) return result;
    result = statement.bind_int(5, static_cast<std::int64_t>(row.record_count)); if (!result) return result;
    result = statement.bind_uint(6, row.address_value_min); if (!result) return result;
    result = statement.bind_uint(7, row.address_value_max); if (!result) return result;
    result = statement.bind_blob(8, row.payload.data(), row.payload.size()); if (!result) return result;
    return statement.step_done();
}

workspace_result_t<void> visit_packed_generation_staging(
    sqlite3* database, std::uint64_t generation, std::uint16_t domain,
    const packed_generation_staging_visitor_t& visitor,
    const packed_stop_predicate_t& stop_requested) {
    if (!database || generation == 0 || !visitor ||
        domain < static_cast<std::uint16_t>(packed_page_type_t::instructions) ||
        domain > static_cast<std::uint16_t>(packed_page_last_data_type)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "packed staging visitor identity is invalid",
                                 "workspace_schema_v9.visit_staging"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
SELECT domain_page_index,ordinal_begin,record_count,address_value_min,address_value_max,payload
FROM packed_generation_staging
WHERE generation=?1 AND domain=?2
ORDER BY domain_page_index
)SQL", "workspace_schema_v9.visit_staging");
    if (!result)
        return result;
    result = statement.bind_uint(1, generation); if (!result) return result;
    result = statement.bind_int(2, static_cast<std::int64_t>(domain)); if (!result) return result;
    std::uint32_t expected_page_index = 0;
    for (;;) {
        if (publish_stop_requested_v9(stop_requested))
            return workspace_result_t<void>::failure(
                cancelled_read_error_v9("workspace_schema_v9.visit_staging"));
        const int status = sqlite3_step(statement.get());
        if (status == SQLITE_DONE)
            break;
        if (status != SQLITE_ROW) {
            return workspace_result_t<void>::failure(schema_v9_error(
                database, status, "unable to visit packed staging row",
                "workspace_schema_v9.visit_staging"));
        }
        packed_generation_staging_row_t row;
        row.generation = generation;
        row.domain = domain;
        row.domain_page_index = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 0));
        row.ordinal_begin = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 1));
        row.record_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 2));
        row.address_value_min = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 3));
        row.address_value_max = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 4));
        const void* blob = sqlite3_column_blob(statement.get(), 5);
        const int blob_size = sqlite3_column_bytes(statement.get(), 5);
        if (row.domain_page_index != expected_page_index ||
            blob_size < static_cast<int>(packed_record_page_prefix_size) ||
            blob_size > static_cast<int>(packed_page_max_payload) || !blob) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "packed staging row identity or payload is malformed",
                                     "workspace_schema_v9.visit_staging"));
        }
        auto copied = copy_blob_v9(
            row.payload, static_cast<const std::uint8_t*>(blob),
            static_cast<std::size_t>(blob_size), stop_requested,
            "workspace_schema_v9.visit_staging");
        if (!copied)
            return copied;
        auto visited = visitor(std::move(row));
        if (!visited)
            return visited;
        ++expected_page_index;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> delete_packed_generation_staging(
    sqlite3* database, std::uint64_t generation) {
    v9_statement_t statement;
    auto result = statement.prepare(database,
        "DELETE FROM packed_generation_staging WHERE generation=?1",
        "workspace_schema_v9.delete_staging");
    if (!result) return result;
    result = statement.bind_uint(1, generation); if (!result) return result;
    return statement.step_done();
}

workspace_result_t<void> gc_packed_generation_staging(sqlite3* database) {
    return exec_sql_v9(database,
        "DELETE FROM packed_generation_staging WHERE generation NOT IN (SELECT generation FROM packed_generations WHERE committed=0)",
        "workspace_schema_v9.gc_staging");
}

workspace_result_t<void> write_pipeline_cache_v1(
    sqlite3* database, const decompiler_pipeline_cache_v1_row_t& record) {
    constexpr std::uint64_t kValueLimit = 64ULL << 20;
    if (!database || record.cache_key.empty() ||
        record.cache_key.size() > 16384 ||
        record.workspace_id.empty() || record.workspace_id.size() > 4096 ||
        record.stage < 0 || record.stage > 16 ||
        record.value.empty() || record.value.size() > kValueLimit ||
        record.diagnostics.size() > kValueLimit) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "decompiler pipeline cache record exceeds its bounded invariants",
                                 "workspace_schema_v9.write_pipeline_cache"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO decompiler_pipeline_cache_v1(cache_key,stage,workspace_id,generation,analysis_revision,overlay_revision,function_rva,value,diagnostics,created_utc_ms,last_access_utc_ms,value_bytes)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
ON CONFLICT(cache_key) DO UPDATE SET stage=excluded.stage,workspace_id=excluded.workspace_id,generation=excluded.generation,analysis_revision=excluded.analysis_revision,overlay_revision=excluded.overlay_revision,function_rva=excluded.function_rva,value=excluded.value,diagnostics=excluded.diagnostics,created_utc_ms=excluded.created_utc_ms,last_access_utc_ms=excluded.last_access_utc_ms,value_bytes=excluded.value_bytes
)SQL", "workspace_schema_v9.write_pipeline_cache");
    if (!result) return result;
    result = statement.bind_blob(1, record.cache_key.data(), record.cache_key.size()); if (!result) return result;
    result = statement.bind_int(2, record.stage); if (!result) return result;
    result = statement.bind_text(3, record.workspace_id); if (!result) return result;
    result = statement.bind_uint(4, record.generation); if (!result) return result;
    result = statement.bind_uint(5, record.analysis_revision); if (!result) return result;
    result = statement.bind_uint(6, record.overlay_revision); if (!result) return result;
    result = statement.bind_uint(7, record.function_rva); if (!result) return result;
    result = statement.bind_blob(8, record.value.data(), record.value.size()); if (!result) return result;
    result = statement.bind_blob(9, record.diagnostics.data(), record.diagnostics.size()); if (!result) return result;
    result = statement.bind_int(10, record.created_utc_ms); if (!result) return result;
    result = statement.bind_int(11, record.last_access_utc_ms); if (!result) return result;
    result = statement.bind_int(12, static_cast<std::int64_t>(record.value.size())); if (!result) return result;
    return statement.step_done();
}

workspace_result_t<std::optional<decompiler_pipeline_cache_v1_row_t>>
    read_pipeline_cache_v1(sqlite3* database,
                           const std::vector<std::uint8_t>& cache_key) {
    constexpr std::uint64_t kValueLimit = 64ULL << 20;
    if (!database || cache_key.empty() || cache_key.size() > 16384) {
        return workspace_result_t<std::optional<decompiler_pipeline_cache_v1_row_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "decompiler pipeline cache lookup key is invalid",
                                 "workspace_schema_v9.read_pipeline_cache"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
SELECT stage,workspace_id,generation,analysis_revision,overlay_revision,function_rva,value,diagnostics,created_utc_ms,last_access_utc_ms,value_bytes
FROM decompiler_pipeline_cache_v1 WHERE cache_key=?1
)SQL", "workspace_schema_v9.read_pipeline_cache");
    if (!result)
        return workspace_result_t<std::optional<decompiler_pipeline_cache_v1_row_t>>::failure(
            result.error());
    result = statement.bind_blob(1, cache_key.data(), cache_key.size());
    if (!result)
        return workspace_result_t<std::optional<decompiler_pipeline_cache_v1_row_t>>::failure(
            result.error());
    const int status = sqlite3_step(statement.get());
    if (status == SQLITE_DONE) {
        return workspace_result_t<std::optional<decompiler_pipeline_cache_v1_row_t>>::success(
            std::nullopt);
    }
    if (status != SQLITE_ROW) {
        return workspace_result_t<std::optional<decompiler_pipeline_cache_v1_row_t>>::failure(
            schema_v9_error(database, status, "unable to read decompiler pipeline cache row",
                            "workspace_schema_v9.read_pipeline_cache"));
    }
    decompiler_pipeline_cache_v1_row_t row;
    row.cache_key = cache_key;
    row.stage = sqlite3_column_int64(statement.get(), 0);
    row.workspace_id = column_text_v9(statement.get(), 1);
    row.generation = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2));
    row.analysis_revision = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 3));
    row.overlay_revision = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 4));
    row.function_rva = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 5));
    const void* value_blob = sqlite3_column_blob(statement.get(), 6);
    const int value_size = sqlite3_column_bytes(statement.get(), 6);
    const void* diagnostics_blob = sqlite3_column_blob(statement.get(), 7);
    const int diagnostics_size = sqlite3_column_bytes(statement.get(), 7);
    row.created_utc_ms = sqlite3_column_int64(statement.get(), 8);
    row.last_access_utc_ms = sqlite3_column_int64(statement.get(), 9);
    const auto declared_value_bytes = sqlite3_column_int64(statement.get(), 10);
    if (row.stage < 0 || row.stage > 16 || row.workspace_id.empty() ||
        value_size <= 0 ||
        static_cast<std::uint64_t>(value_size) > kValueLimit || !value_blob ||
        diagnostics_size < 0 ||
        static_cast<std::uint64_t>(diagnostics_size) > kValueLimit ||
        (diagnostics_size > 0 && !diagnostics_blob) ||
        declared_value_bytes != value_size) {
        return workspace_result_t<std::optional<decompiler_pipeline_cache_v1_row_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "decompiler pipeline cache row is malformed",
                                 "workspace_schema_v9.read_pipeline_cache"));
    }
    const auto* value_begin = static_cast<const std::uint8_t*>(value_blob);
    row.value.assign(value_begin, value_begin + value_size);
    if (diagnostics_size > 0) {
        const auto* diagnostics_begin = static_cast<const std::uint8_t*>(diagnostics_blob);
        row.diagnostics.assign(diagnostics_begin, diagnostics_begin + diagnostics_size);
    }
    return workspace_result_t<std::optional<decompiler_pipeline_cache_v1_row_t>>::success(
        std::optional<decompiler_pipeline_cache_v1_row_t>(std::move(row)));
}

workspace_result_t<void> delete_pipeline_cache_v1(
    sqlite3* database, const std::string& workspace_id) {
    if (!database || workspace_id.empty() || workspace_id.size() > 4096) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "decompiler pipeline cache invalidation identity is invalid",
                                 "workspace_schema_v9.delete_pipeline_cache"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database,
        "DELETE FROM decompiler_pipeline_cache_v1 WHERE workspace_id=?1",
        "workspace_schema_v9.delete_pipeline_cache");
    if (!result) return result;
    result = statement.bind_text(1, workspace_id); if (!result) return result;
    return statement.step_done();
}

workspace_result_t<void> delete_pipeline_cache_v1_functions(
    sqlite3* database, const std::string& workspace_id,
    const std::vector<std::uint64_t>& function_rvas) {
    if (!database || workspace_id.empty() || workspace_id.size() > 4096) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "decompiler pipeline cache invalidation identity is invalid",
                                 "workspace_schema_v9.delete_pipeline_cache_functions"));
    }
    if (function_rvas.empty())
        return workspace_result_t<void>::success();
    constexpr std::size_t kChunk = 256;
    for (std::size_t offset = 0; offset < function_rvas.size(); offset += kChunk) {
        const std::size_t count = (std::min)(kChunk, function_rvas.size() - offset);
        std::string sql =
            "DELETE FROM decompiler_pipeline_cache_v1 WHERE workspace_id=?1 AND function_rva IN (";
        for (std::size_t index = 0; index < count; ++index) {
            if (index != 0)
                sql += ',';
            sql += '?' + std::to_string(index + 2);
        }
        sql += ')';
        v9_statement_t statement;
        auto result = statement.prepare(database, sql.c_str(),
            "workspace_schema_v9.delete_pipeline_cache_functions");
        if (!result) return result;
        result = statement.bind_text(1, workspace_id); if (!result) return result;
        for (std::size_t index = 0; index < count; ++index) {
            result = statement.bind_uint(static_cast<int>(index + 2),
                                         function_rvas[offset + index]);
            if (!result) return result;
        }
        result = statement.step_done();
        if (!result) return result;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<bool> write_pdb_symbol_module(
    sqlite3* database, const pdb_symbol_module_record_t& record,
    const packed_stop_predicate_t& stop_requested) {
    if (!database || record.module_key.empty() ||
        record.module_key.size() > pdb_symbol_module_max_name_bytes ||
        record.module_name.empty() ||
        record.module_name.size() > pdb_symbol_module_max_name_bytes ||
        record.pdb_path.size() > pdb_symbol_module_max_path_bytes ||
        record.size == 0 ||
        record.symbol_count > pdb_symbol_module_max_symbols ||
        record.struct_count > pdb_symbol_module_max_structs ||
        record.enum_count > pdb_symbol_module_max_enums ||
        record.payload.size() > pdb_symbol_module_max_uncompressed_bytes ||
        (record.source_lines &&
         record.source_lines->size() > pdb_symbol_module_max_uncompressed_bytes)) {
        return workspace_result_t<bool>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "pdb symbol module record exceeds its bounded invariants",
            "workspace_schema_v10.write_pdb_symbol_module"));
    }
    if (publish_stop_requested_v9(stop_requested))
        return workspace_result_t<bool>::failure(
            cancelled_pdb_error_v10("workspace_schema_v10.write_pdb_symbol_module"));
    std::uint32_t payload_codec = packed_page_codec_raw;
    auto sealed_payload = seal_pdb_payload_v10(
        record.payload.data(), record.payload.size(), payload_codec,
        stop_requested);
    if (!sealed_payload)
        return workspace_result_t<bool>::failure(sealed_payload.error());
    std::uint32_t source_lines_codec = packed_page_codec_raw;
    std::vector<std::uint8_t> sealed_source_lines;
    if (record.source_lines) {
        auto sealed = seal_pdb_payload_v10(
            record.source_lines->data(), record.source_lines->size(),
            source_lines_codec, stop_requested);
        if (!sealed)
            return workspace_result_t<bool>::failure(sealed.error());
        sealed_source_lines = std::move(sealed.value());
    }
    v9_statement_t caps_statement;
    auto result = caps_statement.prepare(database,
        "SELECT COUNT(*),COALESCE(SUM(length(payload)+COALESCE(length(source_lines),0)),0) FROM pdb_symbol_modules WHERE module_key<>?1",
        "workspace_schema_v10.write_pdb_symbol_module.caps");
    if (!result)
        return workspace_result_t<bool>::failure(result.error());
    result = caps_statement.bind_text(1, record.module_key);
    if (!result)
        return workspace_result_t<bool>::failure(result.error());
    const int caps_status = sqlite3_step(caps_statement.get());
    if (caps_status == SQLITE_INTERRUPT && publish_stop_requested_v9(stop_requested))
        return workspace_result_t<bool>::failure(
            cancelled_pdb_error_v10("workspace_schema_v10.write_pdb_symbol_module"));
    if (caps_status != SQLITE_ROW) {
        return workspace_result_t<bool>::failure(schema_v9_error(
            database, caps_status, "unable to bound pdb symbol module rows",
            "workspace_schema_v10.write_pdb_symbol_module"));
    }
    const auto other_rows = sqlite3_column_int64(caps_statement.get(), 0);
    const auto other_bytes = sqlite3_column_int64(caps_statement.get(), 1);
    const std::uint64_t new_stored_bytes =
        static_cast<std::uint64_t>(sealed_payload.value().size()) +
        static_cast<std::uint64_t>(sealed_source_lines.size());
    if (other_rows < 0 || other_bytes < 0 ||
        static_cast<std::uint64_t>(other_rows) + 1ULL >
            pdb_symbol_modules_max_rows ||
        static_cast<std::uint64_t>(other_bytes) + new_stored_bytes >
            pdb_symbol_modules_max_stored_bytes) {
        return workspace_result_t<bool>::success(false);
    }
    v9_statement_t statement;
    result = statement.prepare(database, R"SQL(
INSERT INTO pdb_symbol_modules(module_key,module_name,base,size,pdb_guid,pdb_age,pdb_path,pdb_file_size,pdb_volume_serial,pdb_file_id,pdb_last_write_100ns,symbol_count,struct_count,enum_count,payload_codec,payload_uncompressed_bytes,payload,source_lines_codec,source_lines_uncompressed_bytes,source_lines,created_utc_ms,updated_utc_ms)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)
ON CONFLICT(module_key) DO UPDATE SET module_name=excluded.module_name,base=excluded.base,size=excluded.size,pdb_guid=excluded.pdb_guid,pdb_age=excluded.pdb_age,pdb_path=excluded.pdb_path,pdb_file_size=excluded.pdb_file_size,pdb_volume_serial=excluded.pdb_volume_serial,pdb_file_id=excluded.pdb_file_id,pdb_last_write_100ns=excluded.pdb_last_write_100ns,symbol_count=excluded.symbol_count,struct_count=excluded.struct_count,enum_count=excluded.enum_count,payload_codec=excluded.payload_codec,payload_uncompressed_bytes=excluded.payload_uncompressed_bytes,payload=excluded.payload,source_lines_codec=excluded.source_lines_codec,source_lines_uncompressed_bytes=excluded.source_lines_uncompressed_bytes,source_lines=excluded.source_lines,updated_utc_ms=excluded.updated_utc_ms
)SQL", "workspace_schema_v10.write_pdb_symbol_module");
    if (!result)
        return workspace_result_t<bool>::failure(result.error());
    const auto now = utc_ms_v9();
    result = statement.bind_text(1, record.module_key); if (!result) return workspace_result_t<bool>::failure(result.error());
    result = statement.bind_text(2, record.module_name); if (!result) return workspace_result_t<bool>::failure(result.error());
    result = statement.bind_uint(3, record.base); if (!result) return workspace_result_t<bool>::failure(result.error());
    result = statement.bind_uint(4, record.size); if (!result) return workspace_result_t<bool>::failure(result.error());
    result = statement.bind_blob(5, record.pdb_guid.data(), record.pdb_guid.size()); if (!result) return workspace_result_t<bool>::failure(result.error());
    result = statement.bind_int(6, static_cast<std::int64_t>(record.pdb_age)); if (!result) return workspace_result_t<bool>::failure(result.error());
    result = statement.bind_text(7, record.pdb_path); if (!result) return workspace_result_t<bool>::failure(result.error());
    if (record.pdb_file_size) {
        result = statement.bind_uint(8, *record.pdb_file_size);
    } else {
        result = statement.bind_null(8);
    }
    if (!result) return workspace_result_t<bool>::failure(result.error());
    if (record.pdb_volume_serial) {
        result = statement.bind_uint(9, *record.pdb_volume_serial);
    } else {
        result = statement.bind_null(9);
    }
    if (!result) return workspace_result_t<bool>::failure(result.error());
    if (record.pdb_file_id) {
        result = statement.bind_blob(10, record.pdb_file_id->data(), record.pdb_file_id->size());
    } else {
        result = statement.bind_null(10);
    }
    if (!result) return workspace_result_t<bool>::failure(result.error());
    if (record.pdb_last_write_100ns) {
        result = statement.bind_uint(11, *record.pdb_last_write_100ns);
    } else {
        result = statement.bind_null(11);
    }
    if (!result) return workspace_result_t<bool>::failure(result.error());
    result = statement.bind_int(12, static_cast<std::int64_t>(record.symbol_count)); if (!result) return workspace_result_t<bool>::failure(result.error());
    result = statement.bind_int(13, static_cast<std::int64_t>(record.struct_count)); if (!result) return workspace_result_t<bool>::failure(result.error());
    result = statement.bind_int(14, static_cast<std::int64_t>(record.enum_count)); if (!result) return workspace_result_t<bool>::failure(result.error());
    result = statement.bind_int(15, static_cast<std::int64_t>(payload_codec)); if (!result) return workspace_result_t<bool>::failure(result.error());
    result = statement.bind_int(16, static_cast<std::int64_t>(record.payload.size())); if (!result) return workspace_result_t<bool>::failure(result.error());
    result = statement.bind_blob(17, sealed_payload.value().data(), sealed_payload.value().size()); if (!result) return workspace_result_t<bool>::failure(result.error());
    if (record.source_lines) {
        result = statement.bind_int(18, static_cast<std::int64_t>(source_lines_codec)); if (!result) return workspace_result_t<bool>::failure(result.error());
        result = statement.bind_int(19, static_cast<std::int64_t>(record.source_lines->size())); if (!result) return workspace_result_t<bool>::failure(result.error());
        result = statement.bind_blob(20, sealed_source_lines.data(), sealed_source_lines.size()); if (!result) return workspace_result_t<bool>::failure(result.error());
    } else {
        result = statement.bind_null(18); if (!result) return workspace_result_t<bool>::failure(result.error());
        result = statement.bind_null(19); if (!result) return workspace_result_t<bool>::failure(result.error());
        result = statement.bind_null(20); if (!result) return workspace_result_t<bool>::failure(result.error());
    }
    result = statement.bind_uint(21, now); if (!result) return workspace_result_t<bool>::failure(result.error());
    result = statement.bind_uint(22, now); if (!result) return workspace_result_t<bool>::failure(result.error());
    result = statement.step_done();
    if (!result)
        return workspace_result_t<bool>::failure(result.error());
    return workspace_result_t<bool>::success(true);
}

workspace_result_t<void> visit_pdb_symbol_modules(
    sqlite3* database, const pdb_symbol_module_visitor_t& visitor,
    const packed_stop_predicate_t& stop_requested) {
    if (!database || !visitor) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "pdb symbol module visitor identity is invalid",
            "workspace_schema_v10.visit_pdb_symbol_modules"));
    }
    v9_statement_t statement;
    auto result = statement.prepare(database, R"SQL(
SELECT module_key,module_name,base,size,pdb_guid,pdb_age,pdb_path,pdb_file_size,pdb_volume_serial,pdb_file_id,pdb_last_write_100ns,symbol_count,struct_count,enum_count,payload_codec,payload_uncompressed_bytes,payload,source_lines_codec,source_lines_uncompressed_bytes,source_lines,created_utc_ms,updated_utc_ms
FROM pdb_symbol_modules
ORDER BY module_key
)SQL", "workspace_schema_v10.visit_pdb_symbol_modules");
    if (!result)
        return result;
    std::uint64_t visited = 0;
    for (;;) {
        if (publish_stop_requested_v9(stop_requested))
            return workspace_result_t<void>::failure(
                cancelled_pdb_error_v10("workspace_schema_v10.visit_pdb_symbol_modules"));
        const int status = sqlite3_step(statement.get());
        if (status == SQLITE_DONE)
            break;
        if (status != SQLITE_ROW) {
            return workspace_result_t<void>::failure(schema_v9_error(
                database, status, "unable to visit pdb symbol module row",
                "workspace_schema_v10.visit_pdb_symbol_modules"));
        }
        if (visited >= pdb_symbol_modules_max_rows) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "pdb symbol module table exceeds its bounded row count",
                                     "workspace_schema_v10.visit_pdb_symbol_modules"));
        }
        pdb_symbol_module_record_t record;
        record.module_key = column_text_v9(statement.get(), 0);
        record.module_name = column_text_v9(statement.get(), 1);
        record.base = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2));
        record.size = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 3));
        const void* guid = sqlite3_column_blob(statement.get(), 4);
        const int guid_size = sqlite3_column_bytes(statement.get(), 4);
        const auto pdb_age = sqlite3_column_int64(statement.get(), 5);
        record.pdb_path = column_text_v9(statement.get(), 6);
        const auto read_optional_u64 = [&](int index) -> std::optional<std::uint64_t> {
            if (sqlite3_column_type(statement.get(), index) == SQLITE_NULL)
                return std::nullopt;
            return static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), index));
        };
        record.pdb_file_size = read_optional_u64(7);
        record.pdb_volume_serial = read_optional_u64(8);
        const void* file_id = sqlite3_column_blob(statement.get(), 9);
        const int file_id_size = sqlite3_column_bytes(statement.get(), 9);
        record.pdb_last_write_100ns = read_optional_u64(10);
        const auto symbol_count = sqlite3_column_int64(statement.get(), 11);
        const auto struct_count = sqlite3_column_int64(statement.get(), 12);
        const auto enum_count = sqlite3_column_int64(statement.get(), 13);
        const auto payload_codec = sqlite3_column_int64(statement.get(), 14);
        const auto payload_uncompressed = sqlite3_column_int64(statement.get(), 15);
        const void* payload_blob = sqlite3_column_blob(statement.get(), 16);
        const int payload_blob_size = sqlite3_column_bytes(statement.get(), 16);
        const bool source_lines_codec_null =
            sqlite3_column_type(statement.get(), 17) == SQLITE_NULL;
        const bool source_lines_bytes_null =
            sqlite3_column_type(statement.get(), 18) == SQLITE_NULL;
        const bool source_lines_blob_null =
            sqlite3_column_type(statement.get(), 19) == SQLITE_NULL;
        const auto source_lines_codec = sqlite3_column_int64(statement.get(), 17);
        const auto source_lines_uncompressed = sqlite3_column_int64(statement.get(), 18);
        const void* source_lines_blob = sqlite3_column_blob(statement.get(), 19);
        const int source_lines_blob_size = sqlite3_column_bytes(statement.get(), 19);
        record.created_utc_ms = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 20));
        record.updated_utc_ms = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 21));
        if (record.module_key.empty() ||
            record.module_key.size() > pdb_symbol_module_max_name_bytes ||
            record.module_name.empty() ||
            record.module_name.size() > pdb_symbol_module_max_name_bytes ||
            record.pdb_path.size() > pdb_symbol_module_max_path_bytes ||
            record.size == 0 || !guid || guid_size != 16 ||
            pdb_age < 0 ||
            pdb_age > static_cast<std::int64_t>((std::numeric_limits<std::uint32_t>::max)()) ||
            symbol_count < 0 || symbol_count > pdb_symbol_module_max_symbols ||
            struct_count < 0 || struct_count > pdb_symbol_module_max_structs ||
            enum_count < 0 || enum_count > pdb_symbol_module_max_enums ||
            (payload_codec != packed_page_codec_raw &&
             payload_codec != packed_page_codec_zstd) ||
            payload_uncompressed < 0 ||
            static_cast<std::uint64_t>(payload_uncompressed) >
                pdb_symbol_module_max_uncompressed_bytes ||
            !payload_blob || payload_blob_size < 20 ||
            source_lines_codec_null != source_lines_bytes_null ||
            source_lines_bytes_null != source_lines_blob_null ||
            (!source_lines_codec_null &&
             ((source_lines_codec != packed_page_codec_raw &&
               source_lines_codec != packed_page_codec_zstd) ||
              source_lines_uncompressed < 0 ||
              static_cast<std::uint64_t>(source_lines_uncompressed) >
                  pdb_symbol_module_max_uncompressed_bytes ||
              !source_lines_blob || source_lines_blob_size < 20)) ||
            (file_id_size != 0 && (!file_id || file_id_size != 16))) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "pdb symbol module row is malformed",
                                     "workspace_schema_v10.visit_pdb_symbol_modules"));
        }
        std::memcpy(record.pdb_guid.data(), guid, record.pdb_guid.size());
        record.pdb_age = static_cast<std::uint32_t>(pdb_age);
        record.symbol_count = static_cast<std::uint32_t>(symbol_count);
        record.struct_count = static_cast<std::uint32_t>(struct_count);
        record.enum_count = static_cast<std::uint32_t>(enum_count);
        if (file_id_size == 16) {
            std::array<std::uint8_t, 16> file_id_value{};
            std::memcpy(file_id_value.data(), file_id, file_id_value.size());
            record.pdb_file_id = file_id_value;
        }
        auto payload = open_pdb_payload_v10(
            static_cast<const std::uint8_t*>(payload_blob),
            static_cast<std::size_t>(payload_blob_size),
            static_cast<std::uint32_t>(payload_codec),
            static_cast<std::uint64_t>(payload_uncompressed), stop_requested);
        if (!payload)
            return workspace_result_t<void>::failure(payload.error());
        record.payload = std::move(payload.value());
        if (!source_lines_codec_null) {
            auto source_lines = open_pdb_payload_v10(
                static_cast<const std::uint8_t*>(source_lines_blob),
                static_cast<std::size_t>(source_lines_blob_size),
                static_cast<std::uint32_t>(source_lines_codec),
                static_cast<std::uint64_t>(source_lines_uncompressed),
                stop_requested);
            if (!source_lines)
                return workspace_result_t<void>::failure(source_lines.error());
            record.source_lines = std::move(source_lines.value());
        }
        ++visited;
        auto visited_result = visitor(std::move(record));
        if (!visited_result)
            return visited_result;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::vector<pdb_symbol_module_record_t>>
    read_pdb_symbol_modules(sqlite3* database,
                            const packed_stop_predicate_t& stop_requested) {
    std::vector<pdb_symbol_module_record_t> rows;
    rows.reserve(pdb_symbol_modules_max_rows);
    std::uint64_t total_uncompressed_bytes = 0;
    auto collected = visit_pdb_symbol_modules(
        database,
        [&](pdb_symbol_module_record_t record) -> workspace_result_t<void> {
            const std::uint64_t uncompressed =
                static_cast<std::uint64_t>(record.payload.size()) +
                (record.source_lines
                     ? static_cast<std::uint64_t>(record.source_lines->size())
                     : 0ULL);
            if (!checked_add_u64(total_uncompressed_bytes, uncompressed,
                                 total_uncompressed_bytes) ||
                total_uncompressed_bytes >
                    pdb_symbol_modules_max_total_uncompressed_bytes) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                                         "pdb symbol module payloads exceed their bounded total",
                                         "workspace_schema_v10.read_pdb_symbol_modules"));
            }
            rows.push_back(std::move(record));
            return workspace_result_t<void>::success();
        },
        stop_requested);
    if (!collected)
        return workspace_result_t<std::vector<pdb_symbol_module_record_t>>::failure(
            collected.error());
    return workspace_result_t<std::vector<pdb_symbol_module_record_t>>::success(
        std::move(rows));
}

workspace_result_t<void> delete_pdb_symbol_modules(sqlite3* database) {
    if (!database) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "pdb symbol module deletion requires an open database",
            "workspace_schema_v10.delete_pdb_symbol_modules"));
    }
    return exec_sql_v9(database, "DELETE FROM pdb_symbol_modules",
                       "workspace_schema_v10.delete_pdb_symbol_modules");
}

}
