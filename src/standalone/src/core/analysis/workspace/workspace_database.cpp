#include "workspace_database.hpp"

#include "checked_range.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <bcrypt.h>

#include <sqlite3.h>

#include <algorithm>
#include <charconv>
#include <array>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <limits>
#include <mutex>
#include <sstream>
#include <system_error>
#include <type_traits>
#include <unordered_map>
#include <utility>

#include <nlohmann/json.hpp>

namespace aida::analysis {

namespace {

constexpr std::uint32_t kInstructionBlobMagic = 0x49444941U;
constexpr std::size_t kDatabaseRecordPollStride = 256;
constexpr std::size_t kDatabaseBlobCopyChunk = 4096;

workspace_error_t database_error(sqlite3* database, int status, std::string message,
                                 const char* phase) {
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

workspace_result_t<void> exec_sql(sqlite3* database, const char* sql, const char* phase) {
    char* detail = nullptr;
    const int status = sqlite3_exec(database, sql, nullptr, nullptr, &detail);
    if (status == SQLITE_OK)
        return workspace_result_t<void>::success();
    std::string message = "SQLite statement failed";
    if (detail && *detail)
        message += std::string(": ") + detail;
    sqlite3_free(detail);
    return workspace_result_t<void>::failure(
        database_error(database, status, std::move(message), phase));
}

class statement_t final {
public:
    statement_t() = default;
    ~statement_t() {
        if (statement_)
            sqlite3_finalize(statement_);
    }
    statement_t(const statement_t&) = delete;
    statement_t& operator=(const statement_t&) = delete;

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
                database_error(database, status, "failed to prepare SQLite statement", phase));
        }
        database_ = database;
        phase_ = phase;
        return workspace_result_t<void>::success();
    }

    sqlite3_stmt* get() const noexcept { return statement_; }

    workspace_result_t<void> bind_int(int index, std::int64_t value) {
        return bind_status(sqlite3_bind_int64(statement_, index, value));
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
                database_error(database_, SQLITE_TOOBIG, "text value exceeds SQLite limit", phase_));
        }
        return bind_status(sqlite3_bind_text(statement_, index, value.data(),
                                             static_cast<int>(value.size()), SQLITE_TRANSIENT));
    }

    workspace_result_t<void> bind_blob(int index, const void* data, std::size_t size) {
        if (size > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
            return workspace_result_t<void>::failure(
                database_error(database_, SQLITE_TOOBIG, "blob value exceeds SQLite limit", phase_));
        }
        if (size != 0 && !data) {
            return workspace_result_t<void>::failure(
                database_error(database_, SQLITE_MISUSE,
                               "blob value is null with a non-zero size", phase_));
        }
        return bind_status(size == 0
            ? sqlite3_bind_zeroblob(statement_, index, 0)
            : sqlite3_bind_blob(statement_, index, data,
                                static_cast<int>(size), SQLITE_TRANSIENT));
    }

    workspace_result_t<void> bind_null(int index) {
        return bind_status(sqlite3_bind_null(statement_, index));
    }

    workspace_result_t<void> step_done() {
        const int status = sqlite3_step(statement_);
        if (status != SQLITE_DONE) {
            return workspace_result_t<void>::failure(
                database_error(database_, status, "SQLite write did not complete", phase_));
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> reset() {
        int status = sqlite3_reset(statement_);
        if (status == SQLITE_OK)
            status = sqlite3_clear_bindings(statement_);
        return bind_status(status);
    }

private:
    workspace_result_t<void> bind_status(int status) {
        if (status == SQLITE_OK)
            return workspace_result_t<void>::success();
        return workspace_result_t<void>::failure(
            database_error(database_, status, "SQLite statement binding failed", phase_));
    }

    sqlite3* database_ = nullptr;
    sqlite3_stmt* statement_ = nullptr;
    const char* phase_ = "workspace_database";
};

int sqlite_cancel_progress(void* context) noexcept {
    const auto* cancel = static_cast<const cancellation_token_t*>(context);
    return cancel && cancel->stop_requested() ? 1 : 0;
}

class sqlite_progress_guard_t final {
public:
    sqlite_progress_guard_t(sqlite3* database,
                            const cancellation_token_t& cancel)
        : database_(database) {
        sqlite3_progress_handler(database_, 4096, sqlite_cancel_progress,
                                 const_cast<cancellation_token_t*>(&cancel));
    }

    ~sqlite_progress_guard_t() {
        reset();
    }

    void reset() noexcept {
        if (!database_)
            return;
        sqlite3_progress_handler(database_, 0, nullptr, nullptr);
        database_ = nullptr;
    }

    sqlite_progress_guard_t(const sqlite_progress_guard_t&) = delete;
    sqlite_progress_guard_t& operator=(const sqlite_progress_guard_t&) = delete;

private:
    sqlite3* database_ = nullptr;
};

workspace_error_t database_cancellation_error(
    const cancellation_token_t& cancel, std::string message,
    const char* phase) {
    auto error = make_workspace_error(
        cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                   : workspace_error_code_t::cancelled,
        std::move(message), phase);
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return error;
}

workspace_result_t<void> copy_blob_cancellable(
    std::vector<std::uint8_t>& output, const void* data, std::size_t size,
    const cancellation_token_t& cancel, const char* phase) {
    if (size != 0 && !data) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "persisted blob pointer is null", phase));
    }
    if (cancel.stop_requested()) {
        return workspace_result_t<void>::failure(database_cancellation_error(
            cancel, "persisted blob copy was cancelled", phase));
    }
    output.resize(size);
    const auto* input = static_cast<const std::uint8_t*>(data);
    for (std::size_t offset = 0; offset < size;
         offset += kDatabaseBlobCopyChunk) {
        if (cancel.stop_requested()) {
            output.clear();
            return workspace_result_t<void>::failure(database_cancellation_error(
                cancel, "persisted blob copy was cancelled", phase));
        }
        const std::size_t chunk =
            (std::min)(kDatabaseBlobCopyChunk, size - offset);
        std::memcpy(output.data() + offset, input + offset, chunk);
    }
    if (cancel.stop_requested()) {
        output.clear();
        return workspace_result_t<void>::failure(database_cancellation_error(
            cancel, "persisted blob copy was cancelled", phase));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> bind_address(statement_t& statement, int first,
                                      const address_t& address) {
    auto result = statement.bind_int(first, static_cast<std::int64_t>(address.space));
    if (!result) return result;
    result = statement.bind_uint(first + 1, address.value);
    if (!result) return result;
    result = statement.bind_int(first + 2, static_cast<std::int64_t>(address.architecture));
    if (!result) return result;
    return statement.bind_int(first + 3, static_cast<std::int64_t>(address.mode));
}

workspace_result_t<void> bind_optional_address(
    statement_t& statement, int first,
    const std::optional<address_t>& address) {
    if (address)
        return bind_address(statement, first, *address);
    for (int offset = 0; offset < 4; ++offset) {
        auto result = statement.bind_null(first + offset);
        if (!result)
            return result;
    }
    return workspace_result_t<void>::success();
}

address_t read_address(sqlite3_stmt* statement, int first) {
    address_t result;
    result.space = static_cast<address_space_id_t>(sqlite3_column_int(statement, first));
    result.value = static_cast<std::uint64_t>(sqlite3_column_int64(statement, first + 1));
    result.architecture = static_cast<architecture_id_t>(sqlite3_column_int(statement, first + 2));
    result.mode = static_cast<architecture_mode_t>(sqlite3_column_int(statement, first + 3));
    return result;
}

std::optional<address_t> read_optional_address(sqlite3_stmt* statement,
                                               int first) {
    if (sqlite3_column_type(statement, first) == SQLITE_NULL)
        return std::nullopt;
    return read_address(statement, first);
}

std::string column_text(sqlite3_stmt* statement, int index) {
    const unsigned char* value = sqlite3_column_text(statement, index);
    const int bytes = sqlite3_column_bytes(statement, index);
    if (!value || bytes <= 0)
        return {};
    return std::string(reinterpret_cast<const char*>(value), static_cast<std::size_t>(bytes));
}

void append_u8(std::vector<std::uint8_t>& output, std::uint8_t value) {
    output.push_back(value);
}

void append_u16(std::vector<std::uint8_t>& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8));
}

void append_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

workspace_result_t<std::uint8_t> read_u8(const std::uint8_t*& cursor,
                                         const std::uint8_t* end) {
    if (cursor == end) {
        return workspace_result_t<std::uint8_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "instruction chunk is truncated", "workspace_database"));
    }
    return workspace_result_t<std::uint8_t>::success(*cursor++);
}

template <typename T>
workspace_result_t<T> read_unsigned_le(const std::uint8_t*& cursor,
                                       const std::uint8_t* end) {
    if (static_cast<std::size_t>(end - cursor) < sizeof(T)) {
        return workspace_result_t<T>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "instruction chunk is truncated", "workspace_database"));
    }
    T result = 0;
    for (std::size_t index = 0; index < sizeof(T); ++index)
        result |= static_cast<T>(cursor[index]) << (index * 8);
    cursor += sizeof(T);
    return workspace_result_t<T>::success(result);
}

std::vector<std::uint8_t> encode_instruction_chunk(
    const std::vector<instruction_record_t>& instructions,
    std::size_t begin, std::size_t end) {
    std::vector<std::uint8_t> output;
    output.reserve(16 + (end - begin) * 52);
    append_u32(output, kInstructionBlobMagic);
    append_u32(output, workspace_instruction_blob_version);
    append_u64(output, static_cast<std::uint64_t>(end - begin));
    for (std::size_t index = begin; index < end; ++index) {
        const auto& record = instructions[index];
        append_u64(output, record.id);
        append_u8(output, static_cast<std::uint8_t>(record.address.space));
        append_u64(output, record.address.value);
        append_u8(output, static_cast<std::uint8_t>(record.address.architecture));
        append_u8(output, static_cast<std::uint8_t>(record.address.mode));
        append_u8(output, record.length);
        append_u16(output, record.mnemonic_id);
        append_u32(output, record.opcode_id);
        append_u32(output, record.flow_flags);
        append_u32(output, record.operand_fact_begin);
        append_u16(output, record.operand_fact_count);
        append_u32(output, record.target_fact_begin);
        append_u16(output, record.target_fact_count);
        append_u8(output, static_cast<std::uint8_t>(record.provenance));
        append_u8(output, record.confidence);
        append_u8(output, static_cast<std::uint8_t>(record.coverage));
        append_u64(output, record.stable_source_id);
    }
    return output;
}

workspace_result_t<void> decode_instruction_chunk(
    const void* data, std::size_t size,
    std::vector<instruction_record_t>& output,
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested()) {
        return workspace_result_t<void>::failure(database_cancellation_error(
            cancel, "instruction chunk decode was cancelled",
            "workspace_database.load.instructions"));
    }
    const auto* cursor = static_cast<const std::uint8_t*>(data);
    const auto* end = cursor + size;
    auto magic = read_unsigned_le<std::uint32_t>(cursor, end);
    if (!magic || magic.value() != kInstructionBlobMagic) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "instruction chunk magic is invalid", "workspace_database"));
    }
    auto version = read_unsigned_le<std::uint32_t>(cursor, end);
    if (!version || version.value() == 0 ||
        version.value() > workspace_instruction_blob_version) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "instruction chunk version is unsupported", "workspace_database"));
    }
    auto count_result = read_unsigned_le<std::uint64_t>(cursor, end);
    if (!count_result || count_result.value() > 1ULL << 24) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "instruction chunk record count is invalid", "workspace_database"));
    }
    const std::uint64_t count = count_result.value();
    output.reserve(output.size() + static_cast<std::size_t>(count));
    for (std::uint64_t index = 0; index < count; ++index) {
        if (index % kDatabaseRecordPollStride == 0 &&
            cancel.stop_requested()) {
            return workspace_result_t<void>::failure(database_cancellation_error(
                cancel, "instruction chunk decode was cancelled",
                "workspace_database.load.instructions"));
        }
        instruction_record_t record;
        auto id = read_unsigned_le<std::uint64_t>(cursor, end); if (!id) return workspace_result_t<void>::failure(id.error());
        auto space = read_u8(cursor, end); if (!space) return workspace_result_t<void>::failure(space.error());
        auto value = read_unsigned_le<std::uint64_t>(cursor, end); if (!value) return workspace_result_t<void>::failure(value.error());
        auto architecture = read_u8(cursor, end); if (!architecture) return workspace_result_t<void>::failure(architecture.error());
        auto mode = read_u8(cursor, end); if (!mode) return workspace_result_t<void>::failure(mode.error());
        auto length = read_u8(cursor, end); if (!length) return workspace_result_t<void>::failure(length.error());
        auto mnemonic = read_unsigned_le<std::uint16_t>(cursor, end); if (!mnemonic) return workspace_result_t<void>::failure(mnemonic.error());
        auto opcode = read_unsigned_le<std::uint32_t>(cursor, end); if (!opcode) return workspace_result_t<void>::failure(opcode.error());
        auto flow = read_unsigned_le<std::uint32_t>(cursor, end); if (!flow) return workspace_result_t<void>::failure(flow.error());
        auto operand_begin = read_unsigned_le<std::uint32_t>(cursor, end); if (!operand_begin) return workspace_result_t<void>::failure(operand_begin.error());
        auto operand_count = read_unsigned_le<std::uint16_t>(cursor, end); if (!operand_count) return workspace_result_t<void>::failure(operand_count.error());
        auto target_begin = read_unsigned_le<std::uint32_t>(cursor, end); if (!target_begin) return workspace_result_t<void>::failure(target_begin.error());
        auto target_count = read_unsigned_le<std::uint16_t>(cursor, end); if (!target_count) return workspace_result_t<void>::failure(target_count.error());
        auto provenance = read_u8(cursor, end); if (!provenance) return workspace_result_t<void>::failure(provenance.error());
        auto confidence = read_u8(cursor, end); if (!confidence) return workspace_result_t<void>::failure(confidence.error());
        auto coverage = read_u8(cursor, end); if (!coverage) return workspace_result_t<void>::failure(coverage.error());
        auto source = read_unsigned_le<std::uint64_t>(cursor, end); if (!source) return workspace_result_t<void>::failure(source.error());
        record.id = id.value();
        record.address.space = static_cast<address_space_id_t>(space.value());
        record.address.value = value.value();
        record.address.architecture = static_cast<architecture_id_t>(architecture.value());
        record.address.mode = static_cast<architecture_mode_t>(mode.value());
        record.length = length.value();
        record.mnemonic_id = mnemonic.value();
        record.opcode_id = opcode.value();
        record.flow_flags = flow.value();
        record.operand_fact_begin = operand_begin.value();
        record.operand_fact_count = operand_count.value();
        record.target_fact_begin = target_begin.value();
        record.target_fact_count = target_count.value();
        record.provenance = static_cast<fact_provenance_t>(provenance.value());
        record.confidence = confidence.value();
        record.coverage = static_cast<coverage_reason_t>(coverage.value());
        record.stable_source_id = source.value();
        output.push_back(record);
    }
    if (cancel.stop_requested()) {
        return workspace_result_t<void>::failure(database_cancellation_error(
            cancel, "instruction chunk decode was cancelled",
            "workspace_database.load.instructions"));
    }
    if (cursor != end) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "instruction chunk contains trailing data", "workspace_database"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::string> database_path_for(const workspace_identity_t& identity) {
    PWSTR raw = nullptr;
    const HRESULT status = SHGetKnownFolderPath(FOLDERID_RoamingAppData,
                                                KF_FLAG_CREATE, nullptr, &raw);
    if (FAILED(status) || !raw) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "unable to resolve roaming application data directory",
                                          "workspace_database");
        error.win32_status = static_cast<std::uint32_t>(status);
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    std::filesystem::path root(raw);
    CoTaskMemFree(raw);
    root /= L"AiDA";
    root /= L"analysis";
    root /= std::filesystem::u8path(identity.content_hash().to_hex());
    std::error_code filesystem_error;
    std::filesystem::create_directories(root, filesystem_error);
    if (filesystem_error) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "unable to create analysis database directory",
                                          "workspace_database");
        error.provider_status = filesystem_error.value();
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    root /= std::filesystem::u8path(identity.load_profile_hash().to_hex() + ".aida.db");
    return workspace_result_t<std::string>::success(root.u8string());
}

workspace_result_t<void> begin_immediate(sqlite3* database, const char* phase) {
    return exec_sql(database, "BEGIN IMMEDIATE", phase);
}

workspace_result_t<void> rollback(sqlite3* database, const char* phase) {
    return exec_sql(database, "ROLLBACK", phase);
}

workspace_result_t<void> commit(sqlite3* database, const char* phase) {
    return exec_sql(database, "COMMIT", phase);
}

workspace_result_t<void> create_schema_v1(sqlite3* database) {
    return exec_sql(database, R"SQL(
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY NOT NULL,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS workspace_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),binary_id BLOB NOT NULL UNIQUE,bin_name TEXT NOT NULL,source_path TEXT NOT NULL,member_path TEXT,content_hash BLOB NOT NULL,load_profile_hash BLOB NOT NULL,target_kind INTEGER NOT NULL,format INTEGER NOT NULL,architecture INTEGER NOT NULL,abi INTEGER NOT NULL,endian INTEGER NOT NULL,image_base INTEGER NOT NULL,process_pid INTEGER,process_creation INTEGER,process_path TEXT,module_base INTEGER,module_size INTEGER,module_name TEXT,module_path TEXT,module_hash BLOB);
CREATE TABLE IF NOT EXISTS analysis_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL,analysis_revision INTEGER NOT NULL,overlay_revision INTEGER NOT NULL,baseline_complete INTEGER NOT NULL,settings_json TEXT NOT NULL,metrics_json TEXT NOT NULL,updated_utc_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS segments(segment_id INTEGER PRIMARY KEY,name TEXT NOT NULL,virtual_address INTEGER NOT NULL,virtual_size INTEGER NOT NULL,raw_offset INTEGER NOT NULL,raw_size INTEGER NOT NULL,characteristics INTEGER NOT NULL,readable INTEGER NOT NULL,writable INTEGER NOT NULL,executable INTEGER NOT NULL,discardable INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS instruction_chunks(chunk_id INTEGER PRIMARY KEY,start_value INTEGER NOT NULL,end_value INTEGER NOT NULL,record_count INTEGER NOT NULL,blob_version INTEGER NOT NULL,payload BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS instruction_chunks_range ON instruction_chunks(start_value,end_value);
CREATE TABLE IF NOT EXISTS operand_facts(instruction_id INTEGER NOT NULL,operand_index INTEGER NOT NULL,kind INTEGER NOT NULL,access INTEGER NOT NULL,bit_width INTEGER NOT NULL,reg INTEGER NOT NULL,base_reg INTEGER NOT NULL,index_reg INTEGER NOT NULL,scale INTEGER NOT NULL,relative INTEGER NOT NULL,signed_value INTEGER NOT NULL,displacement INTEGER NOT NULL,immediate INTEGER NOT NULL,PRIMARY KEY(instruction_id,operand_index));
CREATE TABLE IF NOT EXISTS target_facts(instruction_id INTEGER NOT NULL,target_index INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,direct INTEGER NOT NULL,PRIMARY KEY(instruction_id,target_index));
CREATE INDEX IF NOT EXISTS target_facts_address ON target_facts(target_space,target_value,target_arch,target_mode);
CREATE TABLE IF NOT EXISTS functions(entity_id INTEGER PRIMARY KEY,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_block INTEGER NOT NULL,block_count INTEGER NOT NULL,symbol_id INTEGER,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,thunk INTEGER NOT NULL,noreturn INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS functions_address ON functions(start_space,start_value,start_arch,start_mode,end_value);
CREATE TABLE IF NOT EXISTS blocks(entity_id INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_instruction INTEGER NOT NULL,instruction_count INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS blocks_function ON blocks(function_id,start_value);
CREATE TABLE IF NOT EXISTS edges(entity_id INTEGER PRIMARY KEY,source_entity INTEGER NOT NULL,target_entity INTEGER,source_space INTEGER NOT NULL,source_value INTEGER NOT NULL,source_arch INTEGER NOT NULL,source_mode INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS edges_source ON edges(source_entity,kind);
CREATE INDEX IF NOT EXISTS edges_target ON edges(target_entity,kind);
CREATE TABLE IF NOT EXISTS xrefs(entity_id INTEGER PRIMARY KEY,source_space INTEGER NOT NULL,source_value INTEGER NOT NULL,source_arch INTEGER NOT NULL,source_mode INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS xrefs_source ON xrefs(source_space,source_value,source_arch,source_mode);
CREATE INDEX IF NOT EXISTS xrefs_target ON xrefs(target_space,target_value,target_arch,target_mode);
CREATE TABLE IF NOT EXISTS strings(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,byte_length INTEGER NOT NULL,encoding INTEGER NOT NULL,value TEXT NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS strings_address ON strings(address_space,address_value,address_arch,address_mode);
CREATE TABLE IF NOT EXISTS symbols(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,name TEXT NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS symbols_address ON symbols(address_space,address_value,address_arch,address_mode);
CREATE INDEX IF NOT EXISTS symbols_name ON symbols(name);
CREATE TABLE IF NOT EXISTS coverage(span_id INTEGER PRIMARY KEY,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,size INTEGER NOT NULL,reason INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,detail_code INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS coverage_range ON coverage(start_space,start_value,start_arch,start_mode);
)SQL", "workspace_database.migrate_v1");
}

workspace_result_t<void> create_schema_v2(sqlite3* database) {
    return exec_sql(database, R"SQL(
CREATE TABLE IF NOT EXISTS overlay_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision INTEGER NOT NULL,history_cursor INTEGER NOT NULL,next_transaction_id INTEGER NOT NULL,history_epoch INTEGER NOT NULL,updated_utc_ms INTEGER NOT NULL);
INSERT OR IGNORE INTO overlay_state(singleton,revision,history_cursor,next_transaction_id,history_epoch,updated_utc_ms) VALUES(1,0,0,1,1,0);
CREATE TABLE IF NOT EXISTS overlay_transactions(transaction_id INTEGER PRIMARY KEY,revision INTEGER NOT NULL,history_epoch INTEGER NOT NULL,history_ordinal INTEGER NOT NULL,idempotency_key TEXT,request_hash TEXT NOT NULL,committed_utc_ms INTEGER NOT NULL,applied INTEGER NOT NULL,abandoned INTEGER NOT NULL,result_json TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS overlay_transactions_history ON overlay_transactions(history_epoch,history_ordinal);
CREATE TABLE IF NOT EXISTS overlay_operations(transaction_id INTEGER NOT NULL,operation_index INTEGER NOT NULL,kind INTEGER NOT NULL,entity_key TEXT NOT NULL,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,before_json TEXT,after_json TEXT NOT NULL,PRIMARY KEY(transaction_id,operation_index),FOREIGN KEY(transaction_id) REFERENCES overlay_transactions(transaction_id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS overlay_operations_entity ON overlay_operations(entity_key,transaction_id);
CREATE TABLE IF NOT EXISTS overlay_items(entity_key TEXT PRIMARY KEY NOT NULL,kind INTEGER NOT NULL,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,payload_json TEXT NOT NULL,updated_revision INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS overlay_items_address ON overlay_items(address_space,address_value,address_arch,address_mode,kind);
CREATE TABLE IF NOT EXISTS overlay_history_events(event_id INTEGER PRIMARY KEY AUTOINCREMENT,event_kind INTEGER NOT NULL,source_transaction_id INTEGER NOT NULL,resulting_revision INTEGER NOT NULL,history_epoch INTEGER NOT NULL,history_cursor INTEGER NOT NULL,created_utc_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS overlay_idempotency(idempotency_key TEXT PRIMARY KEY NOT NULL,request_hash TEXT NOT NULL,result_json TEXT NOT NULL,transaction_id INTEGER NOT NULL,created_utc_ms INTEGER NOT NULL,FOREIGN KEY(transaction_id) REFERENCES overlay_transactions(transaction_id));
)SQL", "workspace_database.migrate_v2");
}

workspace_result_t<void> create_schema_v3(sqlite3* database) {
    return exec_sql(database, R"SQL(
CREATE TABLE IF NOT EXISTS decompiler_cache(cache_key TEXT PRIMARY KEY NOT NULL,binary_id BLOB NOT NULL,format INTEGER NOT NULL,architecture INTEGER NOT NULL,abi INTEGER NOT NULL,engine_version TEXT NOT NULL,schema_version INTEGER NOT NULL,specification_version TEXT NOT NULL,settings_hash TEXT NOT NULL,function_id INTEGER NOT NULL,function_rva INTEGER NOT NULL,function_content_hash BLOB NOT NULL,overlay_revision INTEGER NOT NULL,generation INTEGER NOT NULL,function_name TEXT NOT NULL,result_json TEXT NOT NULL,created_utc_ms INTEGER NOT NULL,last_access_utc_ms INTEGER NOT NULL,result_bytes INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS decompiler_cache_function ON decompiler_cache(function_rva,overlay_revision,generation);
)SQL", "workspace_database.migrate_v3");
}

workspace_result_t<void> create_schema_v4(sqlite3* database) {
    return exec_sql(database, R"SQL(
CREATE TABLE IF NOT EXISTS data_candidates(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,size INTEGER NOT NULL,kind INTEGER NOT NULL,target_space INTEGER,target_value INTEGER,target_arch INTEGER,target_mode INTEGER,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS data_candidates_address ON data_candidates(address_space,address_value,address_arch,address_mode);
CREATE TABLE IF NOT EXISTS switches(entity_id INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,dispatch_space INTEGER NOT NULL,dispatch_value INTEGER NOT NULL,dispatch_arch INTEGER NOT NULL,dispatch_mode INTEGER NOT NULL,table_space INTEGER NOT NULL,table_value INTEGER NOT NULL,table_arch INTEGER NOT NULL,table_mode INTEGER NOT NULL,default_space INTEGER,default_value INTEGER,default_arch INTEGER,default_mode INTEGER,entry_size INTEGER NOT NULL,relative_entries INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS switches_function ON switches(function_id,dispatch_value);
CREATE TABLE IF NOT EXISTS switch_cases(switch_id INTEGER NOT NULL,case_index INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,PRIMARY KEY(switch_id,case_index),FOREIGN KEY(switch_id) REFERENCES switches(entity_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS type_candidates(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,kind INTEGER NOT NULL,display_name TEXT NOT NULL,canonical_type TEXT NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,explicitly_unknown INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS type_candidates_address ON type_candidates(address_space,address_value,address_arch,address_mode);
CREATE TABLE IF NOT EXISTS search_index_blob(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL,analysis_revision INTEGER NOT NULL,overlay_revision INTEGER NOT NULL,blob_version INTEGER NOT NULL,payload BLOB NOT NULL);
)SQL", "workspace_database.migrate_v4");
}

workspace_result_t<void> create_schema_v5(sqlite3* database) {
    return exec_sql(database, R"SQL(
ALTER TABLE operand_facts ADD COLUMN segment_reg INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis_state ADD COLUMN commit_token TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS workspace_commit_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),active_slot INTEGER NOT NULL CHECK(active_slot IN (0,1)),committed_token TEXT NOT NULL,committed_generation INTEGER NOT NULL,committed_analysis_revision INTEGER NOT NULL,committed_overlay_revision INTEGER NOT NULL,candidate_slot INTEGER CHECK(candidate_slot IN (0,1)),candidate_token TEXT,candidate_generation INTEGER,candidate_analysis_revision INTEGER,candidate_overlay_revision INTEGER,candidate_ready INTEGER NOT NULL CHECK(candidate_ready IN (0,1)),updated_utc_ms INTEGER NOT NULL);
INSERT OR IGNORE INTO workspace_commit_state(singleton,active_slot,committed_token,committed_generation,committed_analysis_revision,committed_overlay_revision,candidate_slot,candidate_token,candidate_generation,candidate_analysis_revision,candidate_overlay_revision,candidate_ready,updated_utc_ms) VALUES(1,0,'',0,0,0,NULL,NULL,NULL,NULL,NULL,0,0);
CREATE TABLE IF NOT EXISTS alternate_analysis_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL,analysis_revision INTEGER NOT NULL,overlay_revision INTEGER NOT NULL,baseline_complete INTEGER NOT NULL,settings_json TEXT NOT NULL,metrics_json TEXT NOT NULL,updated_utc_ms INTEGER NOT NULL,commit_token TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_segments(segment_id INTEGER PRIMARY KEY,name TEXT NOT NULL,virtual_address INTEGER NOT NULL,virtual_size INTEGER NOT NULL,raw_offset INTEGER NOT NULL,raw_size INTEGER NOT NULL,characteristics INTEGER NOT NULL,readable INTEGER NOT NULL,writable INTEGER NOT NULL,executable INTEGER NOT NULL,discardable INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_instruction_chunks(chunk_id INTEGER PRIMARY KEY,start_value INTEGER NOT NULL,end_value INTEGER NOT NULL,record_count INTEGER NOT NULL,blob_version INTEGER NOT NULL,payload BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_instruction_chunks_range ON alternate_instruction_chunks(start_value,end_value);
CREATE TABLE IF NOT EXISTS alternate_operand_facts(instruction_id INTEGER NOT NULL,operand_index INTEGER NOT NULL,kind INTEGER NOT NULL,access INTEGER NOT NULL,bit_width INTEGER NOT NULL,reg INTEGER NOT NULL,segment_reg INTEGER NOT NULL,base_reg INTEGER NOT NULL,index_reg INTEGER NOT NULL,scale INTEGER NOT NULL,relative INTEGER NOT NULL,signed_value INTEGER NOT NULL,displacement INTEGER NOT NULL,immediate INTEGER NOT NULL,PRIMARY KEY(instruction_id,operand_index));
CREATE TABLE IF NOT EXISTS alternate_target_facts(instruction_id INTEGER NOT NULL,target_index INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,direct INTEGER NOT NULL,PRIMARY KEY(instruction_id,target_index));
CREATE INDEX IF NOT EXISTS alternate_target_facts_address ON alternate_target_facts(target_space,target_value,target_arch,target_mode);
CREATE TABLE IF NOT EXISTS alternate_functions(entity_id INTEGER PRIMARY KEY,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_block INTEGER NOT NULL,block_count INTEGER NOT NULL,symbol_id INTEGER,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,thunk INTEGER NOT NULL,noreturn INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_functions_address ON alternate_functions(start_space,start_value,start_arch,start_mode,end_value);
CREATE TABLE IF NOT EXISTS alternate_blocks(entity_id INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_instruction INTEGER NOT NULL,instruction_count INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_blocks_function ON alternate_blocks(function_id,start_value);
CREATE TABLE IF NOT EXISTS alternate_edges(entity_id INTEGER PRIMARY KEY,source_entity INTEGER NOT NULL,target_entity INTEGER,source_space INTEGER NOT NULL,source_value INTEGER NOT NULL,source_arch INTEGER NOT NULL,source_mode INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_edges_source ON alternate_edges(source_entity,kind);
CREATE INDEX IF NOT EXISTS alternate_edges_target ON alternate_edges(target_entity,kind);
CREATE TABLE IF NOT EXISTS alternate_xrefs(entity_id INTEGER PRIMARY KEY,source_space INTEGER NOT NULL,source_value INTEGER NOT NULL,source_arch INTEGER NOT NULL,source_mode INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_xrefs_source ON alternate_xrefs(source_space,source_value,source_arch,source_mode);
CREATE INDEX IF NOT EXISTS alternate_xrefs_target ON alternate_xrefs(target_space,target_value,target_arch,target_mode);
CREATE TABLE IF NOT EXISTS alternate_strings(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,byte_length INTEGER NOT NULL,encoding INTEGER NOT NULL,value TEXT NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_strings_address ON alternate_strings(address_space,address_value,address_arch,address_mode);
CREATE TABLE IF NOT EXISTS alternate_symbols(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,name TEXT NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_symbols_address ON alternate_symbols(address_space,address_value,address_arch,address_mode);
CREATE INDEX IF NOT EXISTS alternate_symbols_name ON alternate_symbols(name);
CREATE TABLE IF NOT EXISTS alternate_coverage(span_id INTEGER PRIMARY KEY,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,size INTEGER NOT NULL,reason INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,detail_code INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_coverage_range ON alternate_coverage(start_space,start_value,start_arch,start_mode);
CREATE TABLE IF NOT EXISTS alternate_data_candidates(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,size INTEGER NOT NULL,kind INTEGER NOT NULL,target_space INTEGER,target_value INTEGER,target_arch INTEGER,target_mode INTEGER,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_data_candidates_address ON alternate_data_candidates(address_space,address_value,address_arch,address_mode);
CREATE TABLE IF NOT EXISTS alternate_switches(entity_id INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,dispatch_space INTEGER NOT NULL,dispatch_value INTEGER NOT NULL,dispatch_arch INTEGER NOT NULL,dispatch_mode INTEGER NOT NULL,table_space INTEGER NOT NULL,table_value INTEGER NOT NULL,table_arch INTEGER NOT NULL,table_mode INTEGER NOT NULL,default_space INTEGER,default_value INTEGER,default_arch INTEGER,default_mode INTEGER,entry_size INTEGER NOT NULL,relative_entries INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_switches_function ON alternate_switches(function_id,dispatch_value);
CREATE TABLE IF NOT EXISTS alternate_switch_cases(switch_id INTEGER NOT NULL,case_index INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,PRIMARY KEY(switch_id,case_index),FOREIGN KEY(switch_id) REFERENCES alternate_switches(entity_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS alternate_type_candidates(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,kind INTEGER NOT NULL,display_name TEXT NOT NULL,canonical_type TEXT NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,explicitly_unknown INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_type_candidates_address ON alternate_type_candidates(address_space,address_value,address_arch,address_mode);
CREATE TABLE IF NOT EXISTS alternate_search_index_blob(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL,analysis_revision INTEGER NOT NULL,overlay_revision INTEGER NOT NULL,blob_version INTEGER NOT NULL,payload BLOB NOT NULL);
)SQL", "workspace_database.migrate_v5");
}

workspace_result_t<void> create_schema_v6(sqlite3* database) {
    return exec_sql(database, R"SQL(
ALTER TABLE workspace_identity ADD COLUMN architecture_mode INTEGER NOT NULL DEFAULT 0;
ALTER TABLE decompiler_cache ADD COLUMN architecture_mode INTEGER NOT NULL DEFAULT 0;
ALTER TABLE decompiler_cache ADD COLUMN endian INTEGER NOT NULL DEFAULT 0;
)SQL", "workspace_database.migrate_v6");
}

workspace_result_t<void> create_schema_v7(sqlite3* database) {
    return exec_sql(database, R"SQL(
ALTER TABLE operand_facts ADD COLUMN entity_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN address_expression_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN decoder_operand_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN visibility INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN encoding INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN memory_type INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN access_width INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN access_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN access_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN element_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN element_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN address_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN has_displacement INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN has_resolved_expression_value INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN resolved_expression_value INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN address_components INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN address_expression INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN address_resolution INTEGER NOT NULL DEFAULT 4;
ALTER TABLE target_facts ADD COLUMN operand_fact_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE target_facts ADD COLUMN address_expression_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE target_facts ADD COLUMN resolution INTEGER NOT NULL DEFAULT 4;
ALTER TABLE target_facts ADD COLUMN operand_index INTEGER NOT NULL DEFAULT 255;
ALTER TABLE target_facts ADD COLUMN access_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE target_facts ADD COLUMN access_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE target_facts ADD COLUMN is_external INTEGER NOT NULL DEFAULT 0;
ALTER TABLE functions ADD COLUMN first_chunk INTEGER NOT NULL DEFAULT 0;
ALTER TABLE functions ADD COLUMN chunk_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE functions ADD COLUMN first_block_membership INTEGER NOT NULL DEFAULT 0;
ALTER TABLE functions ADD COLUMN block_membership_count INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS function_chunks(chunk_index INTEGER PRIMARY KEY,entity_id INTEGER NOT NULL UNIQUE,function_id INTEGER NOT NULL,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_block INTEGER NOT NULL,block_count INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,cold INTEGER NOT NULL,shared INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS function_chunks_function ON function_chunks(function_id,chunk_index);
CREATE TABLE IF NOT EXISTS function_block_memberships(membership_index INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,chunk_id INTEGER NOT NULL,block_id INTEGER NOT NULL,block_index INTEGER NOT NULL,ordinal INTEGER NOT NULL,shared INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS function_block_memberships_function_ordinal ON function_block_memberships(function_id,ordinal);
CREATE INDEX IF NOT EXISTS function_block_memberships_chunk ON function_block_memberships(chunk_id,block_index);
ALTER TABLE alternate_operand_facts ADD COLUMN entity_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN address_expression_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN decoder_operand_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN visibility INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN encoding INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN memory_type INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN access_width INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN access_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN access_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN element_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN element_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN address_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN has_displacement INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN has_resolved_expression_value INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN resolved_expression_value INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN address_components INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN address_expression INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN address_resolution INTEGER NOT NULL DEFAULT 4;
ALTER TABLE alternate_target_facts ADD COLUMN operand_fact_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_target_facts ADD COLUMN address_expression_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_target_facts ADD COLUMN resolution INTEGER NOT NULL DEFAULT 4;
ALTER TABLE alternate_target_facts ADD COLUMN operand_index INTEGER NOT NULL DEFAULT 255;
ALTER TABLE alternate_target_facts ADD COLUMN access_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_target_facts ADD COLUMN access_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_target_facts ADD COLUMN is_external INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_functions ADD COLUMN first_chunk INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_functions ADD COLUMN chunk_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_functions ADD COLUMN first_block_membership INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_functions ADD COLUMN block_membership_count INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS alternate_function_chunks(chunk_index INTEGER PRIMARY KEY,entity_id INTEGER NOT NULL UNIQUE,function_id INTEGER NOT NULL,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_block INTEGER NOT NULL,block_count INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,cold INTEGER NOT NULL,shared INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_function_chunks_function ON alternate_function_chunks(function_id,chunk_index);
CREATE TABLE IF NOT EXISTS alternate_function_block_memberships(membership_index INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,chunk_id INTEGER NOT NULL,block_id INTEGER NOT NULL,block_index INTEGER NOT NULL,ordinal INTEGER NOT NULL,shared INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS alternate_function_block_memberships_function_ordinal ON alternate_function_block_memberships(function_id,ordinal);
CREATE INDEX IF NOT EXISTS alternate_function_block_memberships_chunk ON alternate_function_block_memberships(chunk_id,block_index);
)SQL", "workspace_database.migrate_v7");
}

workspace_result_t<void> create_schema_v8(sqlite3* database) {
    return exec_sql(database, R"SQL(
ALTER TABLE decompiler_cache ADD COLUMN analysis_revision INTEGER NOT NULL DEFAULT 0;
)SQL", "workspace_database.migrate_v8");
}

workspace_result_t<void> migrate_schema(sqlite3* database,
                                        bool& invalidate_derived_facts) {
    invalidate_derived_facts = false;
    std::uint32_t version = 0;
    {
        statement_t query;
        auto prepared = query.prepare(database, "PRAGMA user_version",
                                      "workspace_database.schema");
        if (!prepared)
            return prepared;
        const int status = sqlite3_step(query.get());
        if (status != SQLITE_ROW) {
            return workspace_result_t<void>::failure(
                database_error(database, status,
                               "unable to query workspace schema version",
                               "workspace_database.schema"));
        }
        version = static_cast<std::uint32_t>(sqlite3_column_int(query.get(), 0));
    }
    if (version > workspace_database_schema_version) {
        return workspace_result_t<void>::failure(
            database_error(database, SQLITE_MISMATCH,
                           "workspace database schema is newer than this engine",
                           "workspace_database.schema"));
    }
    const bool ensure_existing_v9 = version == workspace_database_schema_version;
    invalidate_derived_facts = version > 0 && version < 6;
    while (version < workspace_database_schema_version) {
        auto begin = begin_immediate(database, "workspace_database.schema");
        if (!begin) return begin;
        workspace_result_t<void> migrated = workspace_result_t<void>::success();
        if (version == 0) migrated = create_schema_v1(database);
        else if (version == 1) migrated = create_schema_v2(database);
        else if (version == 2) migrated = create_schema_v3(database);
        else if (version == 3) migrated = create_schema_v4(database);
        else if (version == 4) migrated = create_schema_v5(database);
        else if (version == 5) migrated = create_schema_v6(database);
        else if (version == 6) migrated = create_schema_v7(database);
        else if (version == 7) migrated = create_schema_v8(database);
        else if (version == 8) migrated = create_schema_v9(database);
        if (!migrated) {
            rollback(database, "workspace_database.schema");
            return migrated;
        }
        ++version;
        const std::string set_version = "PRAGMA user_version=" + std::to_string(version);
        auto set_result = exec_sql(database, set_version.c_str(), "workspace_database.schema");
        if (!set_result) {
            rollback(database, "workspace_database.schema");
            return set_result;
        }
        auto committed = commit(database, "workspace_database.schema");
        if (!committed) {
            rollback(database, "workspace_database.schema");
            return committed;
        }
    }
    if (ensure_existing_v9) {
        auto begin = begin_immediate(database, "workspace_database.schema");
        if (!begin)
            return begin;
        auto ensured = create_schema_v9(database);
        if (!ensured) {
            rollback(database, "workspace_database.schema");
            return ensured;
        }
        auto committed = commit(database, "workspace_database.schema");
        if (!committed) {
            rollback(database, "workspace_database.schema");
            return committed;
        }
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::optional<std::string>> metadata_value(sqlite3* database,
                                                              const std::string& key) {
    statement_t statement;
    auto result = statement.prepare(database, "SELECT value FROM metadata WHERE key=?1",
                                    "workspace_database.metadata");
    if (!result) return workspace_result_t<std::optional<std::string>>::failure(result.error());
    result = statement.bind_text(1, key);
    if (!result) return workspace_result_t<std::optional<std::string>>::failure(result.error());
    const int status = sqlite3_step(statement.get());
    if (status == SQLITE_DONE)
        return workspace_result_t<std::optional<std::string>>::success(std::nullopt);
    if (status != SQLITE_ROW) {
        return workspace_result_t<std::optional<std::string>>::failure(
            database_error(database, status, "unable to read workspace metadata",
                           "workspace_database.metadata"));
    }
    return workspace_result_t<std::optional<std::string>>::success(
        std::optional<std::string>(column_text(statement.get(), 0)));
}

workspace_result_t<void> set_metadata(sqlite3* database, const std::string& key,
                                      const std::string& value) {
    statement_t statement;
    auto result = statement.prepare(database,
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        "workspace_database.metadata");
    if (!result) return result;
    result = statement.bind_text(1, key); if (!result) return result;
    result = statement.bind_text(2, value); if (!result) return result;
    return statement.step_done();
}

workspace_result_t<void> bind_identity(sqlite3* database,
                                      const workspace_identity_t& identity) {
    statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO workspace_identity(singleton,binary_id,bin_name,source_path,member_path,content_hash,load_profile_hash,target_kind,format,architecture,architecture_mode,abi,endian,image_base,process_pid,process_creation,process_path,module_base,module_size,module_name,module_path,module_hash)
VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)
ON CONFLICT(singleton) DO UPDATE SET binary_id=excluded.binary_id,bin_name=excluded.bin_name,source_path=excluded.source_path,member_path=excluded.member_path,content_hash=excluded.content_hash,load_profile_hash=excluded.load_profile_hash,target_kind=excluded.target_kind,format=excluded.format,architecture=excluded.architecture,architecture_mode=excluded.architecture_mode,abi=excluded.abi,endian=excluded.endian,image_base=excluded.image_base,process_pid=excluded.process_pid,process_creation=excluded.process_creation,process_path=excluded.process_path,module_base=excluded.module_base,module_size=excluded.module_size,module_name=excluded.module_name,module_path=excluded.module_path,module_hash=excluded.module_hash
)SQL", "workspace_database.identity");
    if (!result) return result;
    result = statement.bind_blob(1, identity.binary_id().bytes.data(), identity.binary_id().bytes.size()); if (!result) return result;
    result = statement.bind_text(2, identity.bin_name()); if (!result) return result;
    result = statement.bind_text(3, identity.normalized_source_path()); if (!result) return result;
    if (identity.normalized_member_path()) result = statement.bind_text(4, *identity.normalized_member_path()); else result = statement.bind_null(4); if (!result) return result;
    result = statement.bind_blob(5, identity.content_hash().bytes.data(), identity.content_hash().bytes.size()); if (!result) return result;
    result = statement.bind_blob(6, identity.load_profile_hash().bytes.data(), identity.load_profile_hash().bytes.size()); if (!result) return result;
    result = statement.bind_int(7, static_cast<std::int64_t>(identity.target_kind())); if (!result) return result;
    result = statement.bind_int(8, static_cast<std::int64_t>(identity.format())); if (!result) return result;
    result = statement.bind_int(9, static_cast<std::int64_t>(identity.architecture())); if (!result) return result;
    result = statement.bind_int(10, static_cast<std::int64_t>(identity.architecture_mode())); if (!result) return result;
    result = statement.bind_int(11, static_cast<std::int64_t>(identity.abi())); if (!result) return result;
    result = statement.bind_int(12, static_cast<std::int64_t>(identity.endian())); if (!result) return result;
    result = statement.bind_uint(13, identity.image_base()); if (!result) return result;
    if (identity.process()) {
        result = statement.bind_int(14, identity.process()->pid); if (!result) return result;
        result = statement.bind_uint(15, identity.process()->creation_time_100ns); if (!result) return result;
        result = statement.bind_text(16, identity.process()->normalized_process_path); if (!result) return result;
    } else {
        result = statement.bind_null(14); if (!result) return result;
        result = statement.bind_null(15); if (!result) return result;
        result = statement.bind_null(16); if (!result) return result;
    }
    if (identity.module()) {
        result = statement.bind_uint(17, identity.module()->base); if (!result) return result;
        result = statement.bind_uint(18, identity.module()->size); if (!result) return result;
        result = statement.bind_text(19, identity.module()->normalized_name); if (!result) return result;
        result = statement.bind_text(20, identity.module()->normalized_path); if (!result) return result;
        if (identity.module()->content_hash)
            result = statement.bind_blob(21, identity.module()->content_hash->bytes.data(), identity.module()->content_hash->bytes.size());
        else result = statement.bind_null(21);
        if (!result) return result;
    } else {
        for (int index = 17; index <= 21; ++index) {
            result = statement.bind_null(index);
            if (!result) return result;
        }
    }
    return statement.step_done();
}

workspace_result_t<void> initialize_identity_and_versions(
    sqlite3* database, const workspace_database_options_t& options,
    std::uint64_t& cache_invalidations,
    bool schema_requires_invalidation) {
    auto begin = begin_immediate(database, "workspace_database.open");
    if (!begin) return begin;

    auto stored_id = metadata_value(database, "binary_id");
    if (!stored_id) {
        rollback(database, "workspace_database.open");
        return workspace_result_t<void>::failure(stored_id.error());
    }
    const std::string current_id = options.identity->binary_id().to_hex();
    if (stored_id.value() && *stored_id.value() != current_id) {
        rollback(database, "workspace_database.open");
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "database identity does not match workspace identity",
                                 "workspace_database.open"));
    }

    {
    statement_t identity_query;
    auto identity_prepared = identity_query.prepare(database,
        "SELECT binary_id,content_hash,load_profile_hash FROM workspace_identity WHERE singleton=1",
        "workspace_database.open");
    if (!identity_prepared) {
        rollback(database, "workspace_database.open");
        return identity_prepared;
    }
    const int identity_status = sqlite3_step(identity_query.get());
    if (identity_status == SQLITE_ROW) {
        const void* stored_binary = sqlite3_column_blob(identity_query.get(), 0);
        const int stored_binary_size = sqlite3_column_bytes(identity_query.get(), 0);
        const void* stored_content = sqlite3_column_blob(identity_query.get(), 1);
        const int stored_content_size = sqlite3_column_bytes(identity_query.get(), 1);
        const void* stored_profile = sqlite3_column_blob(identity_query.get(), 2);
        const int stored_profile_size = sqlite3_column_bytes(identity_query.get(), 2);
        if (!stored_binary || stored_binary_size != static_cast<int>(options.identity->binary_id().bytes.size()) ||
            !stored_content || stored_content_size != static_cast<int>(options.identity->content_hash().bytes.size()) ||
            !stored_profile || stored_profile_size != static_cast<int>(options.identity->load_profile_hash().bytes.size()) ||
            std::memcmp(stored_binary, options.identity->binary_id().bytes.data(), options.identity->binary_id().bytes.size()) != 0 ||
            std::memcmp(stored_content, options.identity->content_hash().bytes.data(), options.identity->content_hash().bytes.size()) != 0 ||
            std::memcmp(stored_profile, options.identity->load_profile_hash().bytes.data(), options.identity->load_profile_hash().bytes.size()) != 0) {
            rollback(database, "workspace_database.open");
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "persisted workspace identity row does not match the requested identity",
                "workspace_database.open"));
        }
    } else if (identity_status != SQLITE_DONE) {
        auto error = database_error(database, identity_status,
                                    "unable to read persisted workspace identity",
                                    "workspace_database.open");
        rollback(database, "workspace_database.open");
        return workspace_result_t<void>::failure(std::move(error));
    }
    }

    bool invalidate = schema_requires_invalidation;
    auto stored_schema = metadata_value(database, "schema_version");
    if (!stored_schema) {
        rollback(database, "workspace_database.open");
        return workspace_result_t<void>::failure(stored_schema.error());
    }
    if (stored_schema.value() &&
        *stored_schema.value() != std::to_string(workspace_database_schema_version) &&
        schema_requires_invalidation)
        invalidate = true;
    const std::array<std::pair<const char*, std::string>, 3> versions{{
        {"engine_version", options.versions.engine_version},
        {"specification_version", options.versions.specification_version},
        {"analysis_settings_hash", options.versions.analysis_settings_hash}
    }};
    for (const auto& version : versions) {
        auto stored = metadata_value(database, version.first);
        if (!stored) {
            rollback(database, "workspace_database.open");
            return workspace_result_t<void>::failure(stored.error());
        }
        if (stored.value() && *stored.value() != version.second)
            invalidate = true;
    }
    for (const auto& identity_value : std::array<std::pair<const char*, std::string>, 2>{{
             {"content_hash", options.identity->content_hash().to_hex()},
             {"load_profile_hash", options.identity->load_profile_hash().to_hex()}}}) {
        auto stored = metadata_value(database, identity_value.first);
        if (!stored) {
            rollback(database, "workspace_database.open");
            return workspace_result_t<void>::failure(stored.error());
        }
        if (stored.value() && *stored.value() != identity_value.second) {
            rollback(database, "workspace_database.open");
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "persisted content identity metadata is inconsistent",
                "workspace_database.open"));
        }
    }

    auto invalidation_value = metadata_value(database, "cache_invalidations");
    if (!invalidation_value) {
        rollback(database, "workspace_database.open");
        return workspace_result_t<void>::failure(invalidation_value.error());
    }
    if (invalidation_value.value()) {
        const auto& text = *invalidation_value.value();
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(),
                                            cache_invalidations, 10);
        if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
            rollback(database, "workspace_database.open");
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "cache invalidation metadata is malformed",
                "workspace_database.open"));
        }
    }

    if (invalidate) {
        auto cleared = exec_sql(database, R"SQL(
DELETE FROM call_graph_conflicts;DELETE FROM call_graph_edges;DELETE FROM call_candidates;DELETE FROM call_sites;DELETE FROM call_graph_nodes;DELETE FROM call_graph_state;DELETE FROM data_pointer_facts;DELETE FROM data_conflicts;DELETE FROM rich_data_candidates;DELETE FROM type_references;DELETE FROM metadata_conflicts;DELETE FROM symbol_type_candidates;DELETE FROM switch_cases;DELETE FROM switches;DELETE FROM segments;DELETE FROM instruction_chunks;DELETE FROM operand_facts;DELETE FROM target_facts;DELETE FROM function_block_memberships;DELETE FROM function_chunks;DELETE FROM functions;DELETE FROM blocks;DELETE FROM edges;DELETE FROM xrefs;DELETE FROM strings;DELETE FROM symbols;DELETE FROM coverage;DELETE FROM data_candidates;DELETE FROM type_candidates;DELETE FROM search_index_blob;DELETE FROM analysis_state;
DELETE FROM alternate_call_graph_conflicts;DELETE FROM alternate_call_graph_edges;DELETE FROM alternate_call_candidates;DELETE FROM alternate_call_sites;DELETE FROM alternate_call_graph_nodes;DELETE FROM alternate_call_graph_state;DELETE FROM alternate_data_pointer_facts;DELETE FROM alternate_data_conflicts;DELETE FROM alternate_rich_data_candidates;DELETE FROM alternate_type_references;DELETE FROM alternate_metadata_conflicts;DELETE FROM alternate_symbol_type_candidates;DELETE FROM alternate_switch_cases;DELETE FROM alternate_switches;DELETE FROM alternate_segments;DELETE FROM alternate_instruction_chunks;DELETE FROM alternate_operand_facts;DELETE FROM alternate_target_facts;DELETE FROM alternate_function_block_memberships;DELETE FROM alternate_function_chunks;DELETE FROM alternate_functions;DELETE FROM alternate_blocks;DELETE FROM alternate_edges;DELETE FROM alternate_xrefs;DELETE FROM alternate_strings;DELETE FROM alternate_symbols;DELETE FROM alternate_coverage;DELETE FROM alternate_data_candidates;DELETE FROM alternate_type_candidates;DELETE FROM alternate_search_index_blob;DELETE FROM alternate_analysis_state;
UPDATE workspace_commit_state SET active_slot=0,committed_token='',committed_generation=0,committed_analysis_revision=0,committed_overlay_revision=0,candidate_slot=NULL,candidate_token=NULL,candidate_generation=NULL,candidate_analysis_revision=NULL,candidate_overlay_revision=NULL,candidate_ready=0,updated_utc_ms=0 WHERE singleton=1;
DELETE FROM decompiler_cache;DELETE FROM decompiler_cache_v9;
)SQL", "workspace_database.invalidate");
        if (!cleared) {
            rollback(database, "workspace_database.open");
            return cleared;
        }
        ++cache_invalidations;
    }

    auto identity_result = bind_identity(database, *options.identity);
    if (!identity_result) {
        rollback(database, "workspace_database.open");
        return identity_result;
    }
    auto set_result = set_metadata(database, "binary_id", current_id);
    if (!set_result) { rollback(database, "workspace_database.open"); return set_result; }
    for (const auto& version : versions) {
        set_result = set_metadata(database, version.first, version.second);
        if (!set_result) { rollback(database, "workspace_database.open"); return set_result; }
    }
    set_result = set_metadata(database, "content_hash",
                              options.identity->content_hash().to_hex());
    if (!set_result) { rollback(database, "workspace_database.open"); return set_result; }
    set_result = set_metadata(database, "load_profile_hash",
                              options.identity->load_profile_hash().to_hex());
    if (!set_result) { rollback(database, "workspace_database.open"); return set_result; }
    set_result = set_metadata(database, "schema_version",
                              std::to_string(workspace_database_schema_version));
    if (!set_result) { rollback(database, "workspace_database.open"); return set_result; }
    set_result = set_metadata(database, "cache_invalidations",
                              std::to_string(cache_invalidations));
    if (!set_result) { rollback(database, "workspace_database.open"); return set_result; }
    auto committed = commit(database, "workspace_database.open");
    if (!committed) {
        rollback(database, "workspace_database.open");
        return committed;
    }
    return workspace_result_t<void>::success();
}

std::uint64_t utc_ms() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

bool image_matches_identity(const pe_image_t& image,
                            const workspace_identity_t& identity) noexcept {
    return image.format() == identity.format() &&
           image.architecture() == identity.architecture() &&
           image.architecture_mode() == identity.architecture_mode() &&
           image.abi() == identity.abi() &&
           image.endian() == identity.endian() &&
           image.image_base() == identity.image_base();
}

bool image_matches_identity(const workspace_image_t& image,
                            const workspace_identity_t& identity) {
    const auto validation = validate_workspace_image(image, {}, true);
    if (!validation || image.format != identity.format() ||
        image.architecture != identity.architecture() ||
        image.architecture_mode != identity.architecture_mode() ||
        image.abi != identity.abi() || image.endian != identity.endian() ||
        image.image_base != identity.image_base() ||
        image.workspace_binary_id != identity.binary_id() ||
        image.provider_content_hash != identity.content_hash())
        return false;
    if (identity.target_kind() != target_kind_t::static_file)
        return true;
    const auto member_separator = image.provider_source.find("#member:");
    const std::string provider_source = member_separator == std::string::npos
        ? image.provider_source : image.provider_source.substr(0, member_separator);
    return normalize_target_name(provider_source) ==
               normalize_target_name(identity.normalized_source_path()) &&
           (identity.normalized_member_path().has_value() == image.member.has_value()) &&
           (!image.member || image.member->normalized_member_path ==
                                 *identity.normalized_member_path());
}

struct commit_state_record_t {
    std::uint8_t active_slot = 0;
    std::string committed_token;
    std::uint64_t committed_generation = 0;
    std::uint64_t committed_analysis_revision = 0;
    std::uint64_t committed_overlay_revision = 0;
    std::optional<std::uint8_t> candidate_slot;
    std::optional<std::string> candidate_token;
    std::optional<std::uint64_t> candidate_generation;
    std::optional<std::uint64_t> candidate_analysis_revision;
    std::optional<std::uint64_t> candidate_overlay_revision;
    bool candidate_ready = false;
};

bool valid_candidate_token(const std::string& token) noexcept {
    if (token.size() != 32)
        return false;
    return std::all_of(token.begin(), token.end(), [](unsigned char value) {
        return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
    });
}

workspace_result_t<std::string> generate_candidate_token() {
    std::array<std::uint8_t, 16> bytes{};
    const NTSTATUS status = BCryptGenRandom(nullptr, bytes.data(),
        static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        auto error = make_workspace_error(workspace_error_code_t::persistence_failure,
            "unable to generate a persistence candidate token",
            "workspace_database.candidate");
        error.provider_status = static_cast<std::int64_t>(status);
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    static constexpr char digits[] = "0123456789abcdef";
    std::string token;
    token.resize(bytes.size() * 2);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        token[index * 2] = digits[bytes[index] >> 4];
        token[index * 2 + 1] = digits[bytes[index] & 0x0fU];
    }
    return workspace_result_t<std::string>::success(std::move(token));
}

std::string slot_table(std::uint8_t slot, const char* table) {
    return slot == 0 ? std::string(table) : std::string("alternate_") + table;
}

workspace_result_t<commit_state_record_t> read_commit_state(
    sqlite3* database, const char* phase) {
    statement_t statement;
    auto prepared = statement.prepare(database,
        "SELECT active_slot,committed_token,committed_generation,committed_analysis_revision,committed_overlay_revision,candidate_slot,candidate_token,candidate_generation,candidate_analysis_revision,candidate_overlay_revision,candidate_ready FROM workspace_commit_state WHERE singleton=1",
        phase);
    if (!prepared)
        return workspace_result_t<commit_state_record_t>::failure(prepared.error());
    const int status = sqlite3_step(statement.get());
    if (status != SQLITE_ROW) {
        return workspace_result_t<commit_state_record_t>::failure(database_error(
            database, status, "workspace commit-state row is missing", phase));
    }
    const auto active_slot = sqlite3_column_int64(statement.get(), 0);
    const auto committed_generation = sqlite3_column_int64(statement.get(), 2);
    const auto committed_analysis_revision = sqlite3_column_int64(statement.get(), 3);
    const auto committed_overlay_revision = sqlite3_column_int64(statement.get(), 4);
    const auto ready = sqlite3_column_int64(statement.get(), 10);
    if ((active_slot != 0 && active_slot != 1) || committed_generation < 0 ||
        committed_analysis_revision < 0 || committed_overlay_revision < 0 ||
        (ready != 0 && ready != 1)) {
        return workspace_result_t<commit_state_record_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "workspace commit-state values are malformed", phase));
    }
    commit_state_record_t result;
    result.active_slot = static_cast<std::uint8_t>(active_slot);
    result.committed_token = column_text(statement.get(), 1);
    result.committed_generation = static_cast<std::uint64_t>(committed_generation);
    result.committed_analysis_revision = static_cast<std::uint64_t>(committed_analysis_revision);
    result.committed_overlay_revision = static_cast<std::uint64_t>(committed_overlay_revision);
    result.candidate_ready = ready != 0;
    if ((result.committed_token.empty() &&
         (result.committed_generation != 0 ||
          result.committed_analysis_revision != 0 ||
          result.committed_overlay_revision != 0)) ||
        (!result.committed_token.empty() &&
         (!valid_candidate_token(result.committed_token) ||
          result.committed_generation == 0))) {
        return workspace_result_t<commit_state_record_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "workspace promoted commit identity is malformed", phase));
    }
    const bool candidate_columns_present =
        sqlite3_column_type(statement.get(), 5) != SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 6) != SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 7) != SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 8) != SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 9) != SQLITE_NULL;
    const bool candidate_columns_absent =
        sqlite3_column_type(statement.get(), 5) == SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 6) == SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 7) == SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 8) == SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 9) == SQLITE_NULL;
    if ((result.candidate_ready && !candidate_columns_present) ||
        (!result.candidate_ready && !candidate_columns_absent)) {
        return workspace_result_t<commit_state_record_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "workspace candidate-state columns are inconsistent", phase));
    }
    if (result.candidate_ready) {
        const auto candidate_slot = sqlite3_column_int64(statement.get(), 5);
        const auto candidate_generation = sqlite3_column_int64(statement.get(), 7);
        const auto candidate_analysis_revision = sqlite3_column_int64(statement.get(), 8);
        const auto candidate_overlay_revision = sqlite3_column_int64(statement.get(), 9);
        const std::string candidate_token = column_text(statement.get(), 6);
        if ((candidate_slot != 0 && candidate_slot != 1) ||
            candidate_slot == active_slot || candidate_generation <= 0 ||
            candidate_analysis_revision < 0 || candidate_overlay_revision < 0 ||
            !valid_candidate_token(candidate_token)) {
            return workspace_result_t<commit_state_record_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "workspace persistence candidate is malformed", phase));
        }
        result.candidate_slot = static_cast<std::uint8_t>(candidate_slot);
        result.candidate_token = candidate_token;
        result.candidate_generation = static_cast<std::uint64_t>(candidate_generation);
        result.candidate_analysis_revision =
            static_cast<std::uint64_t>(candidate_analysis_revision);
        result.candidate_overlay_revision =
            static_cast<std::uint64_t>(candidate_overlay_revision);
    }
    return workspace_result_t<commit_state_record_t>::success(std::move(result));
}

workspace_result_t<void> clear_snapshot_slot(sqlite3* database, std::uint8_t slot,
                                             const char* phase) {
    static constexpr std::array<const char*, 31> tables{{
        "call_graph_conflicts", "call_graph_edges", "call_candidates",
        "call_sites", "call_graph_nodes", "call_graph_state",
        "data_pointer_facts", "data_conflicts", "rich_data_candidates",
        "type_references", "metadata_conflicts", "symbol_type_candidates",
        "switch_cases", "switches", "segments", "instruction_chunks",
        "operand_facts", "target_facts", "function_block_memberships",
        "function_chunks", "functions", "blocks", "edges", "xrefs", "strings",
        "symbols", "coverage", "data_candidates", "type_candidates",
        "search_index_blob", "analysis_state"
    }};
    std::string sql;
    for (const char* table : tables)
        sql += "DELETE FROM " + slot_table(slot, table) + ';';
    return exec_sql(database, sql.c_str(), phase);
}

workspace_result_t<std::uint64_t> database_page_size(sqlite3* database) {
    statement_t statement;
    auto prepared = statement.prepare(database, "PRAGMA page_size",
                                      "workspace_database.metrics");
    if (!prepared)
        return workspace_result_t<std::uint64_t>::failure(prepared.error());
    const int status = sqlite3_step(statement.get());
    if (status != SQLITE_ROW) {
        return workspace_result_t<std::uint64_t>::failure(database_error(
            database, status, "unable to query SQLite page size",
            "workspace_database.metrics"));
    }
    const std::int64_t value = sqlite3_column_int64(statement.get(), 0);
    if (value <= 0) {
        return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "SQLite reported an invalid database page size",
            "workspace_database.metrics"));
    }
    return workspace_result_t<std::uint64_t>::success(
        static_cast<std::uint64_t>(value));
}

void saturating_atomic_add(std::atomic<std::uint64_t>& destination,
                           std::uint64_t increment) noexcept {
    std::uint64_t current = destination.load(std::memory_order_relaxed);
    for (;;) {
        const std::uint64_t next = increment > (std::numeric_limits<std::uint64_t>::max)() - current
            ? (std::numeric_limits<std::uint64_t>::max)()
            : current + increment;
        if (destination.compare_exchange_weak(current, next,
                                              std::memory_order_release,
                                              std::memory_order_relaxed))
            return;
    }
}

template <typename Binder>
workspace_result_t<void> insert_many(sqlite3* database, const std::string& sql,
                                     std::size_t count, Binder binder,
                                     const cancellation_token_t& cancel,
                                     const char* phase) {
    statement_t statement;
    auto result = statement.prepare(database, sql.c_str(), phase);
    if (!result) return result;
    for (std::size_t index = 0; index < count; ++index) {
        if ((index & 255U) == 0 && cancel.stop_requested()) {
            auto error = make_workspace_error(cancel.deadline_exceeded()
                                                  ? workspace_error_code_t::deadline_exceeded
                                                  : workspace_error_code_t::cancelled,
                                              "persistence batch cancelled", phase);
            error.deadline = cancel.deadline_exceeded();
            error.cancellation = !error.deadline;
            return workspace_result_t<void>::failure(std::move(error));
        }
        result = binder(statement, index);
        if (!result) return result;
        result = statement.step_done();
        if (!result) return result;
        result = statement.reset();
        if (!result) return result;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> persist_extended_snapshot_rows(
    sqlite3* database, std::uint8_t target_slot,
    const analysis_snapshot_t& snapshot,
    const cancellation_token_t& cancel) {
    statement_t call_graph_state;
    auto result = call_graph_state.prepare(database,
        ("INSERT INTO " + slot_table(target_slot, "call_graph_state") +
         "(singleton,indirect_site_count,unresolved_site_count,bounded) VALUES(1,?1,?2,?3)").c_str(),
        "workspace_database.persist.call_graph_state");
    if (!result) return result;
    result = call_graph_state.bind_uint(1, snapshot.call_graph.indirect_site_count); if (!result) return result;
    result = call_graph_state.bind_uint(2, snapshot.call_graph.unresolved_site_count); if (!result) return result;
    result = call_graph_state.bind_int(3, snapshot.call_graph.bounded ? 1 : 0); if (!result) return result;
    result = call_graph_state.step_done();
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "call_graph_nodes") +
        "(function_id,address_space,address_value,address_arch,address_mode,incoming_edges,outgoing_edges,indirect_edges,unresolved_sites) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        snapshot.call_graph.nodes.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.call_graph.nodes[index];
            auto current = statement.bind_uint(1, record.function_id); if (!current) return current;
            current = bind_address(statement, 2, record.address); if (!current) return current;
            current = statement.bind_uint(6, record.incoming_edges); if (!current) return current;
            current = statement.bind_uint(7, record.outgoing_edges); if (!current) return current;
            current = statement.bind_uint(8, record.indirect_edges); if (!current) return current;
            return statement.bind_uint(9, record.unresolved_sites);
        }, cancel, "workspace_database.persist.call_graph_nodes");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "call_sites") +
        "(entity_id,source_function_id,source_block_id,instruction_id,address_space,address_value,address_arch,address_mode,first_candidate,candidate_count,indirect,tail_call,unresolved) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        snapshot.call_graph.call_sites.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.call_graph.call_sites[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = statement.bind_uint(2, record.source_function_id); if (!current) return current;
            current = statement.bind_uint(3, record.source_block_id); if (!current) return current;
            current = statement.bind_uint(4, record.instruction_id); if (!current) return current;
            current = bind_address(statement, 5, record.address); if (!current) return current;
            current = statement.bind_int(9, static_cast<std::int64_t>(record.first_candidate)); if (!current) return current;
            current = statement.bind_int(10, static_cast<std::int64_t>(record.candidate_count)); if (!current) return current;
            current = statement.bind_int(11, record.indirect ? 1 : 0); if (!current) return current;
            current = statement.bind_int(12, record.tail_call ? 1 : 0); if (!current) return current;
            return statement.bind_int(13, record.unresolved ? 1 : 0);
        }, cancel, "workspace_database.persist.call_sites");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "call_candidates") +
        "(entity_id,call_site_id,target_space,target_value,target_arch,target_mode,target_function_id,kind,provenance,confidence,contributor_count,conflicted,stable_source_id,rank,external_target) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        snapshot.call_graph.candidates.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.call_graph.candidates[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = statement.bind_uint(2, record.call_site_id); if (!current) return current;
            current = bind_address(statement, 3, record.target); if (!current) return current;
            current = record.target_function_id
                ? statement.bind_uint(7, *record.target_function_id)
                : statement.bind_null(7);
            if (!current) return current;
            current = statement.bind_int(8, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = statement.bind_int(9, static_cast<std::int64_t>(record.quality.provenance)); if (!current) return current;
            current = statement.bind_int(10, static_cast<std::int64_t>(record.quality.confidence)); if (!current) return current;
            current = statement.bind_int(11, static_cast<std::int64_t>(record.quality.contributor_count)); if (!current) return current;
            current = statement.bind_int(12, record.quality.conflicted ? 1 : 0); if (!current) return current;
            current = statement.bind_uint(13, record.stable_source_id); if (!current) return current;
            current = statement.bind_int(14, static_cast<std::int64_t>(record.rank)); if (!current) return current;
            return statement.bind_int(15, record.external_target ? 1 : 0);
        }, cancel, "workspace_database.persist.call_candidates");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "call_graph_edges") +
        "(entity_id,call_site_id,source_function_id,source_block_id,target_function_id,call_site_space,call_site_value,call_site_arch,call_site_mode,target_space,target_value,target_arch,target_mode,resolution,provenance,confidence,contributor_count,conflicted,candidate_rank,external_target,target_noreturn) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
        snapshot.call_graph.edges.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.call_graph.edges[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = statement.bind_uint(2, record.call_site_id); if (!current) return current;
            current = statement.bind_uint(3, record.source_function_id); if (!current) return current;
            current = statement.bind_uint(4, record.source_block_id); if (!current) return current;
            current = record.target_function_id
                ? statement.bind_uint(5, *record.target_function_id)
                : statement.bind_null(5);
            if (!current) return current;
            current = bind_address(statement, 6, record.call_site); if (!current) return current;
            current = bind_address(statement, 10, record.target); if (!current) return current;
            current = statement.bind_int(14, static_cast<std::int64_t>(record.resolution)); if (!current) return current;
            current = statement.bind_int(15, static_cast<std::int64_t>(record.quality.provenance)); if (!current) return current;
            current = statement.bind_int(16, static_cast<std::int64_t>(record.quality.confidence)); if (!current) return current;
            current = statement.bind_int(17, static_cast<std::int64_t>(record.quality.contributor_count)); if (!current) return current;
            current = statement.bind_int(18, record.quality.conflicted ? 1 : 0); if (!current) return current;
            current = statement.bind_int(19, static_cast<std::int64_t>(record.candidate_rank)); if (!current) return current;
            current = statement.bind_int(20, record.external_target ? 1 : 0); if (!current) return current;
            return statement.bind_int(21, record.target_noreturn ? 1 : 0);
        }, cancel, "workspace_database.persist.call_graph_edges");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "call_graph_conflicts") +
        "(entity_id,kind,instruction_id,source_function_id,call_site_rva,selected_target_rva,competing_target_rva,selected_target_function_id,competing_target_function_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        snapshot.call_graph.conflicts.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.call_graph.conflicts[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = statement.bind_int(2, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = statement.bind_uint(3, record.instruction_id); if (!current) return current;
            current = statement.bind_uint(4, record.source_function_id); if (!current) return current;
            current = statement.bind_uint(5, record.call_site_rva); if (!current) return current;
            current = statement.bind_uint(6, record.selected_target_rva); if (!current) return current;
            current = statement.bind_uint(7, record.competing_target_rva); if (!current) return current;
            current = statement.bind_uint(8, record.selected_target_function_id); if (!current) return current;
            return statement.bind_uint(9, record.competing_target_function_id);
        }, cancel, "workspace_database.persist.call_graph_conflicts");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "rich_data_candidates") +
        "(entity_id,address_space,address_value,address_arch,address_mode,size,kind,target_space,target_value,target_arch,target_mode,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        snapshot.rich_facts.data_candidates.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.rich_facts.data_candidates[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_address(statement, 2, record.address); if (!current) return current;
            current = statement.bind_uint(6, record.size); if (!current) return current;
            current = statement.bind_int(7, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = bind_optional_address(statement, 8, record.target); if (!current) return current;
            current = statement.bind_int(12, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            return statement.bind_int(13, static_cast<std::int64_t>(record.confidence));
        }, cancel, "workspace_database.persist.rich_data_candidates");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "data_pointer_facts") +
        "(entity_id,slot_space,slot_value,slot_arch,slot_mode,target_space,target_value,target_arch,target_mode,candidate_kind,encoding,width_bytes,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        snapshot.rich_facts.data_pointer_facts.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.rich_facts.data_pointer_facts[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_address(statement, 2, record.slot); if (!current) return current;
            current = bind_address(statement, 6, record.target); if (!current) return current;
            current = statement.bind_int(10, static_cast<std::int64_t>(record.candidate_kind)); if (!current) return current;
            current = statement.bind_int(11, static_cast<std::int64_t>(record.encoding)); if (!current) return current;
            current = statement.bind_int(12, static_cast<std::int64_t>(record.width_bytes)); if (!current) return current;
            current = statement.bind_int(13, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            return statement.bind_int(14, static_cast<std::int64_t>(record.confidence));
        }, cancel, "workspace_database.persist.data_pointer_facts");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "data_conflicts") +
        "(entity_id,address_space,address_value,address_arch,address_mode,kind,selected_target_space,selected_target_value,selected_target_arch,selected_target_mode,rejected_target_space,rejected_target_value,rejected_target_arch,rejected_target_mode,selected_provenance,rejected_provenance,selected_confidence,rejected_confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
        snapshot.rich_facts.data_conflicts.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.rich_facts.data_conflicts[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_address(statement, 2, record.address); if (!current) return current;
            current = statement.bind_int(6, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = bind_optional_address(statement, 7, record.selected_target); if (!current) return current;
            current = bind_optional_address(statement, 11, record.rejected_target); if (!current) return current;
            current = statement.bind_int(15, static_cast<std::int64_t>(record.selected_provenance)); if (!current) return current;
            current = statement.bind_int(16, static_cast<std::int64_t>(record.rejected_provenance)); if (!current) return current;
            current = statement.bind_int(17, static_cast<std::int64_t>(record.selected_confidence)); if (!current) return current;
            return statement.bind_int(18, static_cast<std::int64_t>(record.rejected_confidence));
        }, cancel, "workspace_database.persist.data_conflicts");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "symbol_type_candidates") +
        "(entity_id,address_space,address_value,address_arch,address_mode,related_space,related_value,related_arch,related_mode,kind,display_name,canonical_type,source_key,provenance,confidence,explicitly_unknown) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
        snapshot.rich_facts.type_candidates.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.rich_facts.type_candidates[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_optional_address(statement, 2, record.address); if (!current) return current;
            current = bind_optional_address(statement, 6, record.related_address); if (!current) return current;
            current = statement.bind_int(10, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = statement.bind_text(11, record.display_name); if (!current) return current;
            current = statement.bind_text(12, record.canonical_type); if (!current) return current;
            current = statement.bind_text(13, record.source_key); if (!current) return current;
            current = statement.bind_int(14, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            current = statement.bind_int(15, static_cast<std::int64_t>(record.confidence)); if (!current) return current;
            return statement.bind_int(16, record.explicitly_unknown ? 1 : 0);
        }, cancel, "workspace_database.persist.symbol_type_candidates");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "type_references") +
        "(entity_id,source_space,source_value,source_arch,source_mode,target_space,target_value,target_arch,target_mode,source_entity,target_entity,kind,provenance,confidence,source_key) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        snapshot.rich_facts.type_references.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.rich_facts.type_references[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_optional_address(statement, 2, record.source); if (!current) return current;
            current = bind_optional_address(statement, 6, record.target); if (!current) return current;
            current = statement.bind_uint(10, record.source_entity); if (!current) return current;
            current = statement.bind_uint(11, record.target_entity); if (!current) return current;
            current = statement.bind_int(12, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = statement.bind_int(13, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            current = statement.bind_int(14, static_cast<std::int64_t>(record.confidence)); if (!current) return current;
            return statement.bind_text(15, record.source_key);
        }, cancel, "workspace_database.persist.type_references");
    if (!result) return result;

    return insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "metadata_conflicts") +
        "(entity_id,address_space,address_value,address_arch,address_mode,identity,kind,selected_value,rejected_value,selected_provenance,rejected_provenance,selected_confidence,rejected_confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        snapshot.rich_facts.metadata_conflicts.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.rich_facts.metadata_conflicts[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_optional_address(statement, 2, record.address); if (!current) return current;
            current = statement.bind_text(6, record.identity); if (!current) return current;
            current = statement.bind_int(7, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = statement.bind_text(8, record.selected_value); if (!current) return current;
            current = statement.bind_text(9, record.rejected_value); if (!current) return current;
            current = statement.bind_int(10, static_cast<std::int64_t>(record.selected_provenance)); if (!current) return current;
            current = statement.bind_int(11, static_cast<std::int64_t>(record.rejected_provenance)); if (!current) return current;
            current = statement.bind_int(12, static_cast<std::int64_t>(record.selected_confidence)); if (!current) return current;
            return statement.bind_int(13, static_cast<std::int64_t>(record.rejected_confidence));
        }, cancel, "workspace_database.persist.metadata_conflicts");
}

workspace_result_t<void> persist_snapshot_impl(
    sqlite3* database, const analysis_snapshot_t& snapshot,
    const persisted_search_products_t* search_products,
    const workspace_database_options_t& options,
    const std::string& settings_json, const std::string& metrics_json,
    const std::string& candidate_token,
    const cancellation_token_t& cancel,
    persistence_commit_metrics_t* commit_metrics) {
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(cancel.deadline_exceeded()
                                              ? workspace_error_code_t::deadline_exceeded
                                              : workspace_error_code_t::cancelled,
                                          "snapshot persistence cancelled",
                                          "workspace_database.persist");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (!valid_candidate_token(candidate_token)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "snapshot persistence candidate token is malformed",
            "workspace_database.persist"));
    }
    if (search_products &&
        (search_products->generation != snapshot.generation ||
         search_products->analysis_revision != snapshot.analysis_revision ||
         search_products->overlay_revision != snapshot.overlay_revision)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                                 "search products do not match snapshot generation and revisions",
                                 "workspace_database.persist"));
    }
    constexpr std::size_t json_limit = 16U << 20;
    if (settings_json.size() > json_limit || metrics_json.size() > json_limit ||
        nlohmann::json::parse(settings_json, nullptr, false).is_discarded() ||
        nlohmann::json::parse(metrics_json, nullptr, false).is_discarded()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "analysis settings or metrics JSON is invalid or exceeds its limit",
            "workspace_database.persist"));
    }
    std::uint64_t fact_records = 0;
    auto add_records = [&](std::uint64_t count) {
        if (count > options.max_persisted_fact_records - fact_records)
            return false;
        fact_records += count;
        return true;
    };
    if (!add_records(snapshot.instructions.size()) ||
        !add_records(snapshot.operand_facts.size()) ||
        !add_records(snapshot.target_facts.size()) ||
        !add_records(snapshot.function_chunks.size()) ||
        !add_records(snapshot.function_block_memberships.size()) ||
        !add_records(snapshot.functions.size()) ||
        !add_records(snapshot.blocks.size()) ||
        !add_records(snapshot.edges.size()) ||
        !add_records(snapshot.call_graph.nodes.size()) ||
        !add_records(snapshot.call_graph.call_sites.size()) ||
        !add_records(snapshot.call_graph.candidates.size()) ||
        !add_records(snapshot.call_graph.edges.size()) ||
        !add_records(snapshot.call_graph.conflicts.size()) ||
        !add_records(snapshot.xrefs.size()) ||
        !add_records(snapshot.strings.size()) ||
        !add_records(snapshot.symbols.size()) ||
        !add_records(snapshot.rich_facts.data_candidates.size()) ||
        !add_records(snapshot.rich_facts.data_pointer_facts.size()) ||
        !add_records(snapshot.rich_facts.data_conflicts.size()) ||
        !add_records(snapshot.rich_facts.type_candidates.size()) ||
        !add_records(snapshot.rich_facts.type_references.size()) ||
        !add_records(snapshot.rich_facts.metadata_conflicts.size()) ||
        !add_records(snapshot.coverage.size())) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "analysis snapshot exceeds the persisted fact-record budget",
            "workspace_database.persist"));
    }
    if (search_products) {
        if (search_products->search_index_blob.size() > workspace_search_blob_limit ||
            !add_records(search_products->data_candidates.size()) ||
            !add_records(search_products->switches.size()) ||
            !add_records(search_products->types.size())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "search products exceed the persistence budget",
                "workspace_database.persist"));
        }
        for (const auto& item : search_products->switches) {
            if (!add_records(item.case_targets.size())) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "switch cases exceed the persisted fact-record budget",
                    "workspace_database.persist"));
            }
        }
    }

    std::uint64_t logical_bytes = 0;
    auto add_logical_bytes = [&](std::uint64_t value) {
        return checked_add_u64(logical_bytes, value, logical_bytes);
    };
    auto add_vector_storage = [&](std::uint64_t count, std::uint64_t element_size) {
        std::uint64_t bytes = 0;
        return checked_mul_u64(count, element_size, bytes) && add_logical_bytes(bytes);
    };
    if (!add_logical_bytes(settings_json.size()) ||
        !add_logical_bytes(metrics_json.size()) ||
        !add_vector_storage(snapshot.instructions.size(), sizeof(instruction_record_t)) ||
        !add_vector_storage(snapshot.operand_facts.size(), sizeof(operand_fact_t)) ||
        !add_vector_storage(snapshot.target_facts.size(), sizeof(target_fact_t)) ||
        !add_vector_storage(snapshot.function_chunks.size(), sizeof(function_chunk_record_t)) ||
        !add_vector_storage(snapshot.function_block_memberships.size(),
                            sizeof(function_block_membership_record_t)) ||
        !add_vector_storage(snapshot.functions.size(), sizeof(function_record_t)) ||
        !add_vector_storage(snapshot.blocks.size(), sizeof(basic_block_record_t)) ||
        !add_vector_storage(snapshot.edges.size(), sizeof(edge_record_t)) ||
        !add_vector_storage(snapshot.call_graph.nodes.size(),
                            sizeof(call_graph_node_record_t)) ||
        !add_vector_storage(snapshot.call_graph.call_sites.size(),
                            sizeof(recovered_call_site_t)) ||
        !add_vector_storage(snapshot.call_graph.candidates.size(),
                            sizeof(recovered_call_candidate_t)) ||
        !add_vector_storage(snapshot.call_graph.edges.size(),
                            sizeof(call_graph_edge_record_t)) ||
        !add_vector_storage(snapshot.call_graph.conflicts.size(),
                            sizeof(call_graph_conflict_t)) ||
        !add_vector_storage(snapshot.xrefs.size(), sizeof(xref_record_t)) ||
        !add_vector_storage(snapshot.strings.size(), sizeof(string_record_t)) ||
        !add_vector_storage(snapshot.symbols.size(), sizeof(symbol_record_t)) ||
        !add_vector_storage(snapshot.rich_facts.data_candidates.size(),
                            sizeof(data_candidate_record_t)) ||
        !add_vector_storage(snapshot.rich_facts.data_pointer_facts.size(),
                            sizeof(data_pointer_fact_t)) ||
        !add_vector_storage(snapshot.rich_facts.data_conflicts.size(),
                            sizeof(data_candidate_conflict_t)) ||
        !add_vector_storage(snapshot.rich_facts.type_candidates.size(),
                            sizeof(symbol_type_candidate_record_t)) ||
        !add_vector_storage(snapshot.rich_facts.type_references.size(),
                            sizeof(type_reference_fact_t)) ||
        !add_vector_storage(snapshot.rich_facts.metadata_conflicts.size(),
                            sizeof(metadata_conflict_record_t)) ||
        !add_vector_storage(snapshot.coverage.size(), sizeof(coverage_span_t))) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "snapshot logical payload size overflows",
            "workspace_database.persist"));
    }
    for (const auto& record : snapshot.strings) {
        if (!add_logical_bytes(record.value.size())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "string logical payload size overflows",
                "workspace_database.persist"));
        }
    }
    for (const auto& record : snapshot.symbols) {
        if (!add_logical_bytes(record.name.size())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "symbol logical payload size overflows",
                "workspace_database.persist"));
        }
    }
    for (const auto& record : snapshot.rich_facts.type_candidates) {
        if (!add_logical_bytes(record.display_name.size()) ||
            !add_logical_bytes(record.canonical_type.size()) ||
            !add_logical_bytes(record.source_key.size())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "rich type-candidate logical payload size overflows",
                "workspace_database.persist"));
        }
    }
    for (const auto& record : snapshot.rich_facts.type_references) {
        if (!add_logical_bytes(record.source_key.size())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "type-reference logical payload size overflows",
                "workspace_database.persist"));
        }
    }
    for (const auto& record : snapshot.rich_facts.metadata_conflicts) {
        if (!add_logical_bytes(record.identity.size()) ||
            !add_logical_bytes(record.selected_value.size()) ||
            !add_logical_bytes(record.rejected_value.size())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "metadata-conflict logical payload size overflows",
                "workspace_database.persist"));
        }
    }
    std::uint64_t logical_rows = fact_records;
    const auto account_regions = [&](const auto& regions) -> workspace_result_t<void> {
        if (!add_vector_storage(regions.size(), sizeof(typename std::decay_t<decltype(regions)>::value_type)) ||
            !checked_add_u64(logical_rows, regions.size(), logical_rows)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "segment logical payload size overflows",
                "workspace_database.persist"));
        }
        for (const auto& region : regions) {
            if (!add_logical_bytes(region.name.size())) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "segment name logical payload size overflows",
                    "workspace_database.persist"));
            }
        }
        return workspace_result_t<void>::success();
    };
    const auto account_pe_sections = [&](const std::vector<pe_section_t>& sections)
        -> workspace_result_t<void> {
        if (!add_vector_storage(sections.size(), sizeof(pe_section_t)) ||
            !checked_add_u64(logical_rows, sections.size(), logical_rows)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "segment logical payload size overflows",
                "workspace_database.persist"));
        }
        for (const auto& section : sections) {
            if (!add_logical_bytes(section.name.size())) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "segment name logical payload size overflows",
                    "workspace_database.persist"));
            }
        }
        return workspace_result_t<void>::success();
    };
    if (snapshot.normalized_image) {
        auto accounted = snapshot.normalized_image->sections.empty()
            ? account_regions(snapshot.normalized_image->segments)
            : account_regions(snapshot.normalized_image->sections);
        if (!accounted)
            return accounted;
    } else if (snapshot.image) {
        auto accounted = account_pe_sections(snapshot.image->sections());
        if (!accounted)
            return accounted;
    }
    if (search_products) {
        if (!add_vector_storage(search_products->data_candidates.size(),
                                sizeof(data_candidate_record_t)) ||
            !add_vector_storage(search_products->switches.size(), sizeof(switch_record_t)) ||
            !add_vector_storage(search_products->types.size(), sizeof(type_candidate_record_t)) ||
            !add_logical_bytes(search_products->search_index_blob.size())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "search-product logical payload size overflows",
                "workspace_database.persist"));
        }
        for (const auto& record : search_products->switches) {
            if (!add_vector_storage(record.case_targets.size(), sizeof(address_t))) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "switch-case logical payload size overflows",
                    "workspace_database.persist"));
            }
        }
        for (const auto& record : search_products->types) {
            if (!add_logical_bytes(record.display_name.size()) ||
                !add_logical_bytes(record.canonical_type.size())) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "type logical payload size overflows",
                    "workspace_database.persist"));
            }
        }
        if (!search_products->search_index_blob.empty() &&
            !checked_add_u64(logical_rows, 1, logical_rows)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "search-index logical row count overflows",
                "workspace_database.persist"));
        }
    }
    if (!checked_add_u64(logical_rows, 2, logical_rows)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "snapshot state logical row count overflows",
            "workspace_database.persist"));
    }

    auto page_size_result = database_page_size(database);
    if (!page_size_result)
        return workspace_result_t<void>::failure(page_size_result.error());
    int cache_writes_before = 0;
    int ignored_highwater = 0;
    const int before_status = sqlite3_db_status(
        database, SQLITE_DBSTATUS_CACHE_WRITE, &cache_writes_before,
        &ignored_highwater, 0);
    if (before_status != SQLITE_OK) {
        return workspace_result_t<void>::failure(database_error(
            database, before_status,
            "unable to query SQLite cache-write counter",
            "workspace_database.metrics"));
    }
    const auto commit_started = std::chrono::steady_clock::now();

    auto begin = begin_immediate(database, "workspace_database.persist");
    if (!begin) return begin;
    auto commit_state = read_commit_state(database, "workspace_database.persist");
    if (!commit_state) {
        rollback(database, "workspace_database.persist");
        return workspace_result_t<void>::failure(commit_state.error());
    }
    if (commit_state.value().committed_generation > snapshot.generation ||
        (commit_state.value().committed_generation == snapshot.generation &&
         commit_state.value().committed_analysis_revision > snapshot.analysis_revision)) {
        rollback(database, "workspace_database.persist");
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::stale_generation,
            "snapshot is older than the committed analysis state",
            "workspace_database.persist"));
    }
    const std::uint8_t target_slot =
        static_cast<std::uint8_t>(1U - commit_state.value().active_slot);
    auto result = clear_snapshot_slot(database, target_slot,
                                      "workspace_database.persist");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    if (snapshot.normalized_image) {
        const auto insert_regions = [&](const auto& regions) {
            return insert_many(database,
                "INSERT INTO " + slot_table(target_slot, "segments") + "(segment_id,name,virtual_address,virtual_size,raw_offset,raw_size,characteristics,readable,writable,executable,discardable) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                regions.size(), [&regions](statement_t& statement, std::size_t index) {
                    const auto& region = regions[index];
                    auto current = statement.bind_uint(1, region.index); if (!current) return current;
                    current = statement.bind_text(2, region.name); if (!current) return current;
                    current = statement.bind_uint(3, region.virtual_address); if (!current) return current;
                    current = statement.bind_uint(4, region.virtual_size); if (!current) return current;
                    current = statement.bind_uint(5, region.file_offset); if (!current) return current;
                    current = statement.bind_uint(6, region.file_size); if (!current) return current;
                    current = statement.bind_uint(7, region.flags); if (!current) return current;
                    current = statement.bind_int(8, (region.permissions & image_permission_read) != 0 ? 1 : 0); if (!current) return current;
                    current = statement.bind_int(9, (region.permissions & image_permission_write) != 0 ? 1 : 0); if (!current) return current;
                    current = statement.bind_int(10, (region.permissions & image_permission_execute) != 0 ? 1 : 0); if (!current) return current;
                    return statement.bind_int(11, (region.permissions & image_permission_discardable) != 0 ? 1 : 0);
                }, cancel, "workspace_database.persist.segments");
        };
        result = snapshot.normalized_image->sections.empty()
            ? insert_regions(snapshot.normalized_image->segments)
            : insert_regions(snapshot.normalized_image->sections);
        if (!result) { rollback(database, "workspace_database.persist"); return result; }
    } else if (snapshot.image) {
        const auto& sections = snapshot.image->sections();
        result = insert_many(database,
            "INSERT INTO " + slot_table(target_slot, "segments") + "(segment_id,name,virtual_address,virtual_size,raw_offset,raw_size,characteristics,readable,writable,executable,discardable) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            sections.size(), [&sections](statement_t& statement, std::size_t index) {
                const auto& section = sections[index];
                auto current = statement.bind_uint(1, section.index); if (!current) return current;
                current = statement.bind_text(2, section.name); if (!current) return current;
                current = statement.bind_uint(3, section.virtual_address); if (!current) return current;
                current = statement.bind_uint(4, section.virtual_size); if (!current) return current;
                current = statement.bind_uint(5, section.raw_offset); if (!current) return current;
                current = statement.bind_uint(6, section.raw_size); if (!current) return current;
                current = statement.bind_uint(7, section.characteristics); if (!current) return current;
                current = statement.bind_int(8, section.readable ? 1 : 0); if (!current) return current;
                current = statement.bind_int(9, section.writable ? 1 : 0); if (!current) return current;
                current = statement.bind_int(10, section.executable ? 1 : 0); if (!current) return current;
                return statement.bind_int(11, section.discardable ? 1 : 0);
            }, cancel, "workspace_database.persist.segments");
        if (!result) { rollback(database, "workspace_database.persist"); return result; }
    }

    const std::size_t chunk_records = static_cast<std::size_t>((std::max<std::uint64_t>)(1, options.instruction_chunk_records));
    statement_t chunk_statement;
    const std::string chunk_insert = "INSERT INTO " +
        slot_table(target_slot, "instruction_chunks") +
        "(chunk_id,start_value,end_value,record_count,blob_version,payload) VALUES(?1,?2,?3,?4,?5,?6)";
    result = chunk_statement.prepare(database, chunk_insert.c_str(),
        "workspace_database.persist.instructions");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }
    std::uint64_t chunk_id = 1;
    for (std::size_t begin_index = 0; begin_index < snapshot.instructions.size(); begin_index += chunk_records) {
        if (cancel.stop_requested()) {
            rollback(database, "workspace_database.persist");
            auto error = make_workspace_error(cancel.deadline_exceeded()
                                                  ? workspace_error_code_t::deadline_exceeded
                                                  : workspace_error_code_t::cancelled,
                                              "instruction persistence cancelled",
                                              "workspace_database.persist.instructions");
            error.deadline = cancel.deadline_exceeded();
            error.cancellation = !error.deadline;
            return workspace_result_t<void>::failure(std::move(error));
        }
        const std::size_t end_index = (std::min)(snapshot.instructions.size(), begin_index + chunk_records);
        auto payload = encode_instruction_chunk(snapshot.instructions, begin_index, end_index);
        const std::uint64_t start_value = snapshot.instructions[begin_index].address.value;
        std::uint64_t end_value = snapshot.instructions[end_index - 1].address.value;
        if (!checked_add_u64(end_value, snapshot.instructions[end_index - 1].length, end_value)) {
            rollback(database, "workspace_database.persist");
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                                     "instruction range overflows address space",
                                     "workspace_database.persist.instructions"));
        }
        result = chunk_statement.bind_uint(1, chunk_id++); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        result = chunk_statement.bind_uint(2, start_value); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        result = chunk_statement.bind_uint(3, end_value); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        result = chunk_statement.bind_uint(4, end_index - begin_index); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        result = chunk_statement.bind_uint(5, workspace_instruction_blob_version); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        result = chunk_statement.bind_blob(6, payload.data(), payload.size()); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        result = chunk_statement.step_done(); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        result = chunk_statement.reset(); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "operand_facts") + "(instruction_id,operand_index,entity_id,address_expression_id,decoder_operand_id,kind,access,visibility,encoding,memory_type,access_width,bit_width,access_width_bits,access_count,element_width_bits,element_count,address_width_bits,reg,segment_reg,base_reg,index_reg,scale,relative,signed_value,has_displacement,has_resolved_expression_value,displacement,immediate,resolved_expression_value,address_components,address_expression,address_resolution) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32)",
        snapshot.operand_facts.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& fact = snapshot.operand_facts[index];
            auto current = statement.bind_uint(1, fact.instruction_id); if (!current) return current;
            current = statement.bind_uint(2, fact.operand_index); if (!current) return current;
            current = statement.bind_uint(3, fact.id); if (!current) return current;
            current = statement.bind_uint(4, fact.address_expression_id); if (!current) return current;
            current = statement.bind_uint(5, fact.decoder_operand_id); if (!current) return current;
            current = statement.bind_int(6, static_cast<std::int64_t>(fact.kind)); if (!current) return current;
            current = statement.bind_uint(7, fact.access); if (!current) return current;
            current = statement.bind_uint(8, fact.visibility); if (!current) return current;
            current = statement.bind_uint(9, fact.encoding); if (!current) return current;
            current = statement.bind_uint(10, fact.memory_type); if (!current) return current;
            current = statement.bind_uint(11, fact.access_width); if (!current) return current;
            current = statement.bind_uint(12, fact.bit_width); if (!current) return current;
            current = statement.bind_uint(13, fact.access_width_bits); if (!current) return current;
            current = statement.bind_uint(14, fact.access_count); if (!current) return current;
            current = statement.bind_uint(15, fact.element_width_bits); if (!current) return current;
            current = statement.bind_uint(16, fact.element_count); if (!current) return current;
            current = statement.bind_uint(17, fact.address_width_bits); if (!current) return current;
            current = statement.bind_uint(18, fact.reg); if (!current) return current;
            current = statement.bind_uint(19, fact.segment_reg); if (!current) return current;
            current = statement.bind_uint(20, fact.base_reg); if (!current) return current;
            current = statement.bind_uint(21, fact.index_reg); if (!current) return current;
            current = statement.bind_uint(22, fact.scale); if (!current) return current;
            current = statement.bind_int(23, fact.relative ? 1 : 0); if (!current) return current;
            current = statement.bind_int(24, fact.signed_value ? 1 : 0); if (!current) return current;
            current = statement.bind_int(25, fact.has_displacement ? 1 : 0); if (!current) return current;
            current = statement.bind_int(26, fact.has_resolved_expression_value ? 1 : 0); if (!current) return current;
            current = statement.bind_int(27, fact.displacement); if (!current) return current;
            current = statement.bind_uint(28, fact.immediate); if (!current) return current;
            current = statement.bind_uint(29, fact.resolved_expression_value); if (!current) return current;
            current = statement.bind_uint(30, fact.address_components); if (!current) return current;
            current = statement.bind_int(31, static_cast<std::int64_t>(fact.address_expression)); if (!current) return current;
            return statement.bind_int(32, static_cast<std::int64_t>(fact.address_resolution));
        }, cancel, "workspace_database.persist.operands");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    if (search_products) {
        result = insert_many(database,
            "INSERT INTO " + slot_table(target_slot, "data_candidates") + "(entity_id,address_space,address_value,address_arch,address_mode,size,kind,target_space,target_value,target_arch,target_mode,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            search_products->data_candidates.size(), [search_products](statement_t& statement, std::size_t index) {
                const auto& record = search_products->data_candidates[index];
                auto current = statement.bind_uint(1, record.id); if (!current) return current;
                current = bind_address(statement, 2, record.address); if (!current) return current;
                current = statement.bind_uint(6, record.size); if (!current) return current;
                current = statement.bind_int(7, static_cast<std::int64_t>(record.kind)); if (!current) return current;
                if (record.target) current = bind_address(statement, 8, *record.target);
                else {
                    for (int column = 8; column <= 11; ++column) {
                        current = statement.bind_null(column);
                        if (!current) return current;
                    }
                }
                if (!current) return current;
                current = statement.bind_int(12, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
                return statement.bind_uint(13, record.confidence);
            }, cancel, "workspace_database.persist.data_candidates");
        if (!result) { rollback(database, "workspace_database.persist"); return result; }

        result = insert_many(database,
            "INSERT INTO " + slot_table(target_slot, "switches") + "(entity_id,function_id,dispatch_space,dispatch_value,dispatch_arch,dispatch_mode,table_space,table_value,table_arch,table_mode,default_space,default_value,default_arch,default_mode,entry_size,relative_entries,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            search_products->switches.size(), [search_products](statement_t& statement, std::size_t index) {
                const auto& record = search_products->switches[index];
                auto current = statement.bind_uint(1, record.id); if (!current) return current;
                current = statement.bind_uint(2, record.function_id); if (!current) return current;
                current = bind_address(statement, 3, record.dispatch); if (!current) return current;
                current = bind_address(statement, 7, record.table); if (!current) return current;
                if (record.default_target) current = bind_address(statement, 11, *record.default_target);
                else {
                    for (int column = 11; column <= 14; ++column) {
                        current = statement.bind_null(column);
                        if (!current) return current;
                    }
                }
                if (!current) return current;
                current = statement.bind_uint(15, record.entry_size); if (!current) return current;
                current = statement.bind_int(16, record.relative_entries ? 1 : 0); if (!current) return current;
                current = statement.bind_int(17, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
                return statement.bind_uint(18, record.confidence);
            }, cancel, "workspace_database.persist.switches");
        if (!result) { rollback(database, "workspace_database.persist"); return result; }

        std::size_t switch_case_count = 0;
        for (const auto& record : search_products->switches) {
            if (record.case_targets.size() > (std::numeric_limits<std::size_t>::max)() - switch_case_count) {
                rollback(database, "workspace_database.persist");
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow, "switch case count overflows",
                    "workspace_database.persist.switch_cases"));
            }
            switch_case_count += record.case_targets.size();
        }
        statement_t case_statement;
        const std::string case_insert = "INSERT INTO " +
            slot_table(target_slot, "switch_cases") +
            "(switch_id,case_index,target_space,target_value,target_arch,target_mode) VALUES(?1,?2,?3,?4,?5,?6)";
        result = case_statement.prepare(database, case_insert.c_str(),
            "workspace_database.persist.switch_cases");
        if (!result) { rollback(database, "workspace_database.persist"); return result; }
        std::size_t inserted_cases = 0;
        for (const auto& record : search_products->switches) {
            for (std::size_t index = 0; index < record.case_targets.size(); ++index) {
                if ((inserted_cases++ & 255U) == 0 && cancel.stop_requested()) {
                    rollback(database, "workspace_database.persist");
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::cancelled, "switch persistence cancelled",
                        "workspace_database.persist.switch_cases"));
                }
                result = case_statement.bind_uint(1, record.id); if (!result) { rollback(database, "workspace_database.persist"); return result; }
                result = case_statement.bind_uint(2, index); if (!result) { rollback(database, "workspace_database.persist"); return result; }
                result = bind_address(case_statement, 3, record.case_targets[index]); if (!result) { rollback(database, "workspace_database.persist"); return result; }
                result = case_statement.step_done(); if (!result) { rollback(database, "workspace_database.persist"); return result; }
                result = case_statement.reset(); if (!result) { rollback(database, "workspace_database.persist"); return result; }
            }
        }
        if (switch_case_count > options.max_persisted_fact_records) {
            rollback(database, "workspace_database.persist");
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "switch cases exceed the persisted fact-record budget",
                "workspace_database.persist.switch_cases"));
        }

        result = insert_many(database,
            "INSERT INTO " + slot_table(target_slot, "type_candidates") + "(entity_id,address_space,address_value,address_arch,address_mode,kind,display_name,canonical_type,provenance,confidence,explicitly_unknown) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            search_products->types.size(), [search_products](statement_t& statement, std::size_t index) {
                const auto& record = search_products->types[index];
                auto current = statement.bind_uint(1, record.id); if (!current) return current;
                current = bind_address(statement, 2, record.address); if (!current) return current;
                current = statement.bind_int(6, static_cast<std::int64_t>(record.kind)); if (!current) return current;
                current = statement.bind_text(7, record.display_name); if (!current) return current;
                current = statement.bind_text(8, record.canonical_type); if (!current) return current;
                current = statement.bind_int(9, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
                current = statement.bind_uint(10, record.confidence); if (!current) return current;
                return statement.bind_int(11, record.explicitly_unknown ? 1 : 0);
            }, cancel, "workspace_database.persist.type_candidates");
        if (!result) { rollback(database, "workspace_database.persist"); return result; }

        if (!search_products->search_index_blob.empty()) {
            statement_t blob_statement;
            const std::string blob_insert = "INSERT INTO " +
                slot_table(target_slot, "search_index_blob") +
                "(singleton,generation,analysis_revision,overlay_revision,blob_version,payload) VALUES(1,?1,?2,?3,?4,?5)";
            result = blob_statement.prepare(database, blob_insert.c_str(),
                "workspace_database.persist.search_index");
            if (!result) { rollback(database, "workspace_database.persist"); return result; }
            result = blob_statement.bind_uint(1, search_products->generation); if (!result) { rollback(database, "workspace_database.persist"); return result; }
            result = blob_statement.bind_uint(2, search_products->analysis_revision); if (!result) { rollback(database, "workspace_database.persist"); return result; }
            result = blob_statement.bind_uint(3, search_products->overlay_revision); if (!result) { rollback(database, "workspace_database.persist"); return result; }
            result = blob_statement.bind_uint(4, search_products->search_index_blob_version); if (!result) { rollback(database, "workspace_database.persist"); return result; }
            result = blob_statement.bind_blob(5, search_products->search_index_blob.data(), search_products->search_index_blob.size()); if (!result) { rollback(database, "workspace_database.persist"); return result; }
            result = blob_statement.step_done(); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        }
    }

    std::unordered_map<entity_id_t, std::uint32_t> target_indexes;
    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "target_facts") + "(instruction_id,target_index,operand_fact_id,address_expression_id,target_space,target_value,target_arch,target_mode,kind,resolution,operand_index,access_width_bits,access_count,direct,is_external) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        snapshot.target_facts.size(), [&snapshot, &target_indexes](statement_t& statement, std::size_t index) {
            const auto& fact = snapshot.target_facts[index];
            const std::uint32_t target_index = target_indexes[fact.instruction_id]++;
            auto current = statement.bind_uint(1, fact.instruction_id); if (!current) return current;
            current = statement.bind_uint(2, target_index); if (!current) return current;
            current = statement.bind_uint(3, fact.operand_fact_id); if (!current) return current;
            current = statement.bind_uint(4, fact.address_expression_id); if (!current) return current;
            current = bind_address(statement, 5, fact.target); if (!current) return current;
            current = statement.bind_int(9, static_cast<std::int64_t>(fact.kind)); if (!current) return current;
            current = statement.bind_int(10, static_cast<std::int64_t>(fact.resolution)); if (!current) return current;
            current = statement.bind_uint(11, fact.operand_index); if (!current) return current;
            current = statement.bind_uint(12, fact.access_width_bits); if (!current) return current;
            current = statement.bind_uint(13, fact.access_count); if (!current) return current;
            current = statement.bind_int(14, fact.direct ? 1 : 0); if (!current) return current;
            return statement.bind_int(15, fact.is_external ? 1 : 0);
        }, cancel, "workspace_database.persist.targets");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "functions") + "(entity_id,start_space,start_value,start_arch,start_mode,end_space,end_value,end_arch,end_mode,first_block,block_count,first_chunk,chunk_count,first_block_membership,block_membership_count,symbol_id,provenance,confidence,thunk,noreturn) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
        snapshot.functions.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.functions[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_address(statement, 2, record.start); if (!current) return current;
            current = bind_address(statement, 6, record.end); if (!current) return current;
            current = statement.bind_uint(10, record.first_block); if (!current) return current;
            current = statement.bind_uint(11, record.block_count); if (!current) return current;
            current = statement.bind_uint(12, record.first_chunk); if (!current) return current;
            current = statement.bind_uint(13, record.chunk_count); if (!current) return current;
            current = statement.bind_uint(14, record.first_block_membership); if (!current) return current;
            current = statement.bind_uint(15, record.block_membership_count); if (!current) return current;
            if (record.symbol_id) current = statement.bind_uint(16, *record.symbol_id); else current = statement.bind_null(16); if (!current) return current;
            current = statement.bind_int(17, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            current = statement.bind_uint(18, record.confidence); if (!current) return current;
            current = statement.bind_int(19, record.thunk ? 1 : 0); if (!current) return current;
            return statement.bind_int(20, record.noreturn ? 1 : 0);
        }, cancel, "workspace_database.persist.functions");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "blocks") + "(entity_id,function_id,start_space,start_value,start_arch,start_mode,end_space,end_value,end_arch,end_mode,first_instruction,instruction_count,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        snapshot.blocks.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.blocks[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = statement.bind_uint(2, record.function_id); if (!current) return current;
            current = bind_address(statement, 3, record.start); if (!current) return current;
            current = bind_address(statement, 7, record.end); if (!current) return current;
            current = statement.bind_uint(11, record.first_instruction); if (!current) return current;
            current = statement.bind_uint(12, record.instruction_count); if (!current) return current;
            current = statement.bind_int(13, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            return statement.bind_uint(14, record.confidence);
        }, cancel, "workspace_database.persist.blocks");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "function_chunks") + "(chunk_index,entity_id,function_id,start_space,start_value,start_arch,start_mode,end_space,end_value,end_arch,end_mode,first_block,block_count,provenance,confidence,cold,shared) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
        snapshot.function_chunks.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.function_chunks[index];
            auto current = statement.bind_uint(1, index + 1); if (!current) return current;
            current = statement.bind_uint(2, record.id); if (!current) return current;
            current = statement.bind_uint(3, record.function_id); if (!current) return current;
            current = bind_address(statement, 4, record.start); if (!current) return current;
            current = bind_address(statement, 8, record.end); if (!current) return current;
            current = statement.bind_uint(12, record.first_block); if (!current) return current;
            current = statement.bind_uint(13, record.block_count); if (!current) return current;
            current = statement.bind_int(14, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            current = statement.bind_uint(15, record.confidence); if (!current) return current;
            current = statement.bind_int(16, record.cold ? 1 : 0); if (!current) return current;
            return statement.bind_int(17, record.shared ? 1 : 0);
        }, cancel, "workspace_database.persist.function_chunks");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "function_block_memberships") + "(membership_index,function_id,chunk_id,block_id,block_index,ordinal,shared) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        snapshot.function_block_memberships.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.function_block_memberships[index];
            auto current = statement.bind_uint(1, index + 1); if (!current) return current;
            current = statement.bind_uint(2, record.function_id); if (!current) return current;
            current = statement.bind_uint(3, record.chunk_id); if (!current) return current;
            current = statement.bind_uint(4, record.block_id); if (!current) return current;
            current = statement.bind_uint(5, record.block_index); if (!current) return current;
            current = statement.bind_uint(6, record.ordinal); if (!current) return current;
            return statement.bind_int(7, record.shared ? 1 : 0);
        }, cancel, "workspace_database.persist.function_block_memberships");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "edges") + "(entity_id,source_entity,target_entity,source_space,source_value,source_arch,source_mode,target_space,target_value,target_arch,target_mode,kind,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        snapshot.edges.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.edges[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = statement.bind_uint(2, record.source_entity); if (!current) return current;
            if (record.target_entity) current = statement.bind_uint(3, *record.target_entity); else current = statement.bind_null(3); if (!current) return current;
            current = bind_address(statement, 4, record.source); if (!current) return current;
            current = bind_address(statement, 8, record.target); if (!current) return current;
            current = statement.bind_int(12, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = statement.bind_int(13, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            return statement.bind_uint(14, record.confidence);
        }, cancel, "workspace_database.persist.edges");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "xrefs") + "(entity_id,source_space,source_value,source_arch,source_mode,target_space,target_value,target_arch,target_mode,kind,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        snapshot.xrefs.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.xrefs[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_address(statement, 2, record.source); if (!current) return current;
            current = bind_address(statement, 6, record.target); if (!current) return current;
            current = statement.bind_int(10, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = statement.bind_int(11, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            return statement.bind_uint(12, record.confidence);
        }, cancel, "workspace_database.persist.xrefs");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "strings") + "(entity_id,address_space,address_value,address_arch,address_mode,byte_length,encoding,value,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        snapshot.strings.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.strings[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_address(statement, 2, record.address); if (!current) return current;
            current = statement.bind_uint(6, record.byte_length); if (!current) return current;
            current = statement.bind_int(7, static_cast<std::int64_t>(record.encoding)); if (!current) return current;
            current = statement.bind_text(8, record.value); if (!current) return current;
            current = statement.bind_int(9, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            return statement.bind_uint(10, record.confidence);
        }, cancel, "workspace_database.persist.strings");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "symbols") + "(entity_id,address_space,address_value,address_arch,address_mode,name,kind,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        snapshot.symbols.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.symbols[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_address(statement, 2, record.address); if (!current) return current;
            current = statement.bind_text(6, record.name); if (!current) return current;
            current = statement.bind_int(7, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = statement.bind_int(8, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            return statement.bind_uint(9, record.confidence);
        }, cancel, "workspace_database.persist.symbols");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "coverage") + "(span_id,start_space,start_value,start_arch,start_mode,size,reason,provenance,confidence,detail_code) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        snapshot.coverage.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.coverage[index];
            auto current = statement.bind_uint(1, index + 1); if (!current) return current;
            current = bind_address(statement, 2, record.start); if (!current) return current;
            current = statement.bind_uint(6, record.size); if (!current) return current;
            current = statement.bind_int(7, static_cast<std::int64_t>(record.reason)); if (!current) return current;
            current = statement.bind_int(8, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            current = statement.bind_uint(9, record.confidence); if (!current) return current;
            return statement.bind_uint(10, record.detail_code);
        }, cancel, "workspace_database.persist.coverage");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = persist_extended_snapshot_rows(database, target_slot, snapshot, cancel);
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    statement_t state_statement;
    const std::string state_upsert = "INSERT INTO " +
        slot_table(target_slot, "analysis_state") +
        "(singleton,generation,analysis_revision,overlay_revision,baseline_complete,settings_json,metrics_json,updated_utc_ms,commit_token) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8) "
        "ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation,analysis_revision=excluded.analysis_revision,overlay_revision=excluded.overlay_revision,baseline_complete=excluded.baseline_complete,settings_json=excluded.settings_json,metrics_json=excluded.metrics_json,updated_utc_ms=excluded.updated_utc_ms,commit_token=excluded.commit_token";
    result = state_statement.prepare(database, state_upsert.c_str(),
                                     "workspace_database.persist.state");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_uint(1, snapshot.generation); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_uint(2, snapshot.analysis_revision); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_uint(3, snapshot.overlay_revision); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_int(4, snapshot.baseline_complete ? 1 : 0); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_text(5, settings_json); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_text(6, metrics_json); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_uint(7, utc_ms()); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_text(8, candidate_token); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.step_done(); if (!result) { rollback(database, "workspace_database.persist"); return result; }

    statement_t candidate_statement;
    result = candidate_statement.prepare(database,
        "UPDATE workspace_commit_state SET candidate_slot=?1,candidate_token=?2,candidate_generation=?3,candidate_analysis_revision=?4,candidate_overlay_revision=?5,candidate_ready=1,updated_utc_ms=?6 WHERE singleton=1 AND active_slot=?7",
        "workspace_database.persist.candidate");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.bind_uint(1, target_slot); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.bind_text(2, candidate_token); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.bind_uint(3, snapshot.generation); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.bind_uint(4, snapshot.analysis_revision); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.bind_uint(5, snapshot.overlay_revision); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.bind_uint(6, utc_ms()); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.bind_uint(7, commit_state.value().active_slot); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.step_done(); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    if (sqlite3_changes(database) != 1) {
        rollback(database, "workspace_database.persist");
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "workspace commit slot changed during candidate persistence",
            "workspace_database.persist.candidate"));
    }

    auto committed = commit(database, "workspace_database.persist");
    if (!committed) {
        rollback(database, "workspace_database.persist");
        return committed;
    }
    int log_frames = 0;
    int checkpointed_frames = 0;
    const int checkpoint_status = sqlite3_wal_checkpoint_v2(
        database, "main", SQLITE_CHECKPOINT_PASSIVE, &log_frames, &checkpointed_frames);
    if (checkpoint_status != SQLITE_OK && checkpoint_status != SQLITE_BUSY) {
        return workspace_result_t<void>::failure(
            database_error(database, checkpoint_status,
                           "snapshot committed but passive WAL checkpoint failed",
                           "workspace_database.checkpoint"));
    }
    int cache_writes_after = 0;
    const int after_status = sqlite3_db_status(
        database, SQLITE_DBSTATUS_CACHE_WRITE, &cache_writes_after,
        &ignored_highwater, 0);
    if (after_status != SQLITE_OK) {
        return workspace_result_t<void>::failure(database_error(
            database, after_status,
            "snapshot committed but SQLite cache-write accounting failed",
            "workspace_database.metrics"));
    }
    const std::uint64_t written_pages = cache_writes_after >= cache_writes_before
        ? static_cast<std::uint64_t>(cache_writes_after - cache_writes_before)
        : static_cast<std::uint64_t>(cache_writes_after);
    std::uint64_t page_write_bytes = 0;
    if (!checked_mul_u64(written_pages, page_size_result.value(), page_write_bytes)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "snapshot committed but SQLite page-write accounting overflowed",
            "workspace_database.metrics"));
    }
    if (commit_metrics) {
        commit_metrics->logical_bytes = logical_bytes;
        commit_metrics->rows = logical_rows;
        commit_metrics->page_write_bytes = page_write_bytes;
        commit_metrics->elapsed_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - commit_started).count());
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> configure_connection(sqlite3* database,
                                              const workspace_database_options_t& options,
                                              bool writer) {
    sqlite3_extended_result_codes(database, 1);
    const int busy_status = sqlite3_busy_timeout(database,
        static_cast<int>((std::min<std::uint32_t>)(options.busy_timeout_ms, 60000)));
    if (busy_status != SQLITE_OK) {
        return workspace_result_t<void>::failure(
            database_error(database, busy_status, "unable to configure bounded SQLite busy timeout",
                           "workspace_database.open"));
    }
    auto configured = exec_sql(database, "PRAGMA foreign_keys=ON;PRAGMA trusted_schema=OFF;",
                               "workspace_database.open");
    if (!configured) return configured;
    if (!writer)
        return exec_sql(database, "PRAGMA query_only=ON", "workspace_database.open_reader");
    configured = exec_sql(database,
        "PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;PRAGMA temp_store=MEMORY;",
        "workspace_database.open");
    if (!configured) return configured;
    const int checkpoint_status = sqlite3_wal_autocheckpoint(
        database, static_cast<int>((std::min<std::uint32_t>)(
            options.passive_checkpoint_pages, 1000000U)));
    if (checkpoint_status != SQLITE_OK) {
        return workspace_result_t<void>::failure(database_error(
            database, checkpoint_status,
            "unable to configure bounded WAL auto-checkpointing",
            "workspace_database.open"));
    }
    statement_t journal;
    configured = journal.prepare(database, "PRAGMA journal_mode", "workspace_database.open");
    if (!configured) return configured;
    const int status = sqlite3_step(journal.get());
    if (status != SQLITE_ROW || column_text(journal.get(), 0) != "wal") {
        return workspace_result_t<void>::failure(
            database_error(database, status, "SQLite database did not enter WAL mode",
                           "workspace_database.open"));
    }
    statement_t synchronous;
    configured = synchronous.prepare(database, "PRAGMA synchronous",
                                     "workspace_database.open");
    if (!configured) return configured;
    const int synchronous_status = sqlite3_step(synchronous.get());
    if (synchronous_status != SQLITE_ROW ||
        sqlite3_column_int(synchronous.get(), 0) != 2) {
        return workspace_result_t<void>::failure(database_error(
            database, synchronous_status,
            "SQLite database did not enter FULL synchronous mode",
            "workspace_database.open"));
    }
    return workspace_result_t<void>::success();
}

}

struct workspace_database_t::connection_state_t {
    sqlite3* writer = nullptr;
    std::string path;
    mutable std::mutex close_mutex;
    mutable std::timed_mutex writer_mutex;
    std::atomic<bool> open{false};
    std::atomic<std::uint64_t> persisted_generation{0};
    std::atomic<std::uint64_t> persisted_analysis_revision{0};
    std::atomic<std::uint64_t> persisted_overlay_revision{0};
    std::atomic<std::uint64_t> candidate_generation{0};
    std::atomic<std::uint64_t> candidate_analysis_revision{0};
    std::atomic<std::uint64_t> candidate_overlay_revision{0};
    std::atomic<bool> candidate_pending{false};
    std::atomic<std::uint64_t> cache_invalidations{0};
    std::atomic<std::uint64_t> last_commit_logical_bytes{0};
    std::atomic<std::uint64_t> cumulative_logical_bytes{0};
    std::atomic<std::uint64_t> last_commit_rows{0};
    std::atomic<std::uint64_t> cumulative_rows{0};
    std::atomic<std::uint64_t> last_commit_page_write_bytes{0};
    std::atomic<std::uint64_t> cumulative_page_write_bytes{0};
    std::atomic<std::uint64_t> last_commit_elapsed_us{0};

    ~connection_state_t() {
        std::lock_guard<std::mutex> lock(close_mutex);
        std::lock_guard<std::timed_mutex> writer_lock(writer_mutex);
        if (writer) {
            sqlite3_wal_checkpoint_v2(writer, "main", SQLITE_CHECKPOINT_PASSIVE, nullptr, nullptr);
            sqlite3_close_v2(writer);
            writer = nullptr;
        }
        open.store(false, std::memory_order_release);
    }
};

workspace_result_t<void> migrate_workspace_database_schema(
    sqlite3* database, bool& invalidate_derived_facts) {
    if (!database) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "workspace schema migration requires an open database",
                                 "workspace_database.schema"));
    }
    return migrate_schema(database, invalidate_derived_facts);
}

namespace {

void publish_commit_metrics(workspace_database_t::connection_state_t& state,
                            const persistence_commit_metrics_t& metrics) noexcept {
    state.last_commit_logical_bytes.store(metrics.logical_bytes,
                                          std::memory_order_release);
    state.last_commit_rows.store(metrics.rows, std::memory_order_release);
    state.last_commit_page_write_bytes.store(metrics.page_write_bytes,
                                             std::memory_order_release);
    state.last_commit_elapsed_us.store(metrics.elapsed_us, std::memory_order_release);
    saturating_atomic_add(state.cumulative_logical_bytes, metrics.logical_bytes);
    saturating_atomic_add(state.cumulative_rows, metrics.rows);
    saturating_atomic_add(state.cumulative_page_write_bytes, metrics.page_write_bytes);
}

}

workspace_persistence_candidate_t::workspace_persistence_candidate_t(
    std::weak_ptr<workspace_database_t> database,
    std::string token,
    std::uint64_t generation,
    std::uint64_t analysis_revision,
    std::uint64_t overlay_revision)
    : database_(std::move(database)),
      token_(std::move(token)),
      generation_(generation),
      analysis_revision_(analysis_revision),
      overlay_revision_(overlay_revision) {
}

const std::string& workspace_persistence_candidate_t::token() const noexcept {
    return token_;
}

std::uint64_t workspace_persistence_candidate_t::generation() const noexcept {
    return generation_;
}

std::uint64_t workspace_persistence_candidate_t::analysis_revision() const noexcept {
    return analysis_revision_;
}

std::uint64_t workspace_persistence_candidate_t::overlay_revision() const noexcept {
    return overlay_revision_;
}

workspace_result_t<void> workspace_persistence_candidate_t::finalize(
    const cancellation_token_t& cancel) const {
    auto database = database_.lock();
    if (!database) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "persistence database is no longer available",
            "workspace_database.candidate.finalize"));
    }
    return database->finalize_candidate(*this, cancel);
}

workspace_result_t<void> workspace_persistence_candidate_t::discard(
    const cancellation_token_t& cancel) const {
    auto database = database_.lock();
    if (!database) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "persistence database is no longer available",
            "workspace_database.candidate.discard"));
    }
    return database->discard_candidate(*this, cancel);
}

std::string decompiler_cache_key_t::canonical() const {
    std::ostringstream output;
    const bool legacy_pe = endian == endian_t::little &&
        ((format == format_id_t::pe32 && architecture == architecture_id_t::x86 &&
          (architecture_mode == architecture_mode_t::unknown ||
           architecture_mode == architecture_mode_t::x86_32) &&
          abi == abi_id_t::windows_x86) ||
         (format == format_id_t::pe32_plus && architecture == architecture_id_t::x86_64 &&
          (architecture_mode == architecture_mode_t::unknown ||
           architecture_mode == architecture_mode_t::x86_64) &&
          abi == abi_id_t::windows_x64));
    output << binary_id.to_hex() << '|'
           << static_cast<unsigned>(format) << '|'
           << static_cast<unsigned>(architecture) << '|';
    if (!legacy_pe)
        output << static_cast<unsigned>(architecture_mode) << '|';
    output << static_cast<unsigned>(abi) << '|';
    if (!legacy_pe)
        output << static_cast<unsigned>(endian) << '|';
    output
           << engine_version.size() << ':' << engine_version << '|'
           << schema_version << '|'
           << specification_version.size() << ':' << specification_version << '|'
           << analysis_settings_hash.size() << ':' << analysis_settings_hash << '|'
           << function_id << '|' << function_rva << '|'
           << function_content_hash.to_hex() << '|'
           << analysis_revision << '|'
           << overlay_revision << '|' << generation;
    return output.str();
}

workspace_result_t<std::shared_ptr<workspace_database_t>>
workspace_database_t::open(workspace_database_options_t options) {
    if (!options.identity || options.identity->binary_id().empty() ||
        options.versions.engine_version.empty() ||
        options.versions.specification_version.empty() ||
        options.versions.analysis_settings_hash.empty() ||
        options.candidate_operation_timeout_ms == 0 ||
        options.passive_checkpoint_pages == 0 ||
        options.instruction_chunk_records == 0 ||
        options.instruction_chunk_records > (1ULL << 20) ||
        options.max_persisted_fact_records == 0) {
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "database identity, versions, checkpoint, and chunk limits are required",
                                 "workspace_database.open"));
    }
    if (sqlite3_libversion_number() != SQLITE_VERSION_NUMBER ||
        SQLITE_VERSION_NUMBER != 3053003) {
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(
            make_workspace_error(workspace_error_code_t::persistence_failure,
                                 "SQLite runtime/header version does not match pinned 3.53.3",
                                 "workspace_database.open"));
    }
    auto path_result = database_path_for(*options.identity);
    if (!path_result)
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(path_result.error());

    auto state = std::make_shared<connection_state_t>();
    state->path = path_result.take_value();
    sqlite3* database = nullptr;
    const int open_status = sqlite3_open_v2(state->path.c_str(), &database,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_URI,
        nullptr);
    if (open_status != SQLITE_OK) {
        auto error = database_error(database, open_status,
                                    "unable to open workspace database",
                                    "workspace_database.open");
        if (database)
            sqlite3_close_v2(database);
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(std::move(error));
    }
    state->writer = database;
    auto configured = configure_connection(database, options, true);
    if (!configured)
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(configured.error());
    bool schema_requires_invalidation = false;
    auto migrated = migrate_workspace_database_schema(
        database, schema_requires_invalidation);
    if (!migrated)
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(migrated.error());
    std::uint64_t invalidations = 0;
    auto identity_result = initialize_identity_and_versions(
        database, options, invalidations, schema_requires_invalidation);
    if (!identity_result)
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(identity_result.error());
    auto commit_state = read_commit_state(database, "workspace_database.open");
    if (!commit_state)
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(
            commit_state.error());
    state->cache_invalidations.store(invalidations, std::memory_order_release);
    state->persisted_generation.store(commit_state.value().committed_generation,
                                      std::memory_order_release);
    state->persisted_analysis_revision.store(
        commit_state.value().committed_analysis_revision,
        std::memory_order_release);
    state->persisted_overlay_revision.store(
        commit_state.value().committed_overlay_revision,
        std::memory_order_release);
    if (commit_state.value().candidate_ready) {
        state->candidate_generation.store(*commit_state.value().candidate_generation,
                                          std::memory_order_release);
        state->candidate_analysis_revision.store(
            *commit_state.value().candidate_analysis_revision,
            std::memory_order_release);
        state->candidate_overlay_revision.store(
            *commit_state.value().candidate_overlay_revision,
            std::memory_order_release);
        state->candidate_pending.store(true, std::memory_order_release);
    }
    state->open.store(true, std::memory_order_release);

    auto queue_result = persistence_queue_t::create(options.identity->binary_id(),
                                                     options.queue_limits);
    if (!queue_result)
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(queue_result.error());
    auto queue = queue_result.take_value();
    auto result = std::shared_ptr<workspace_database_t>(
        new workspace_database_t(std::move(options), std::move(state), std::move(queue)));
    return workspace_result_t<std::shared_ptr<workspace_database_t>>::success(std::move(result));
}

workspace_database_t::workspace_database_t(workspace_database_options_t options,
                                           std::shared_ptr<connection_state_t> state,
                                           std::shared_ptr<persistence_queue_t> queue)
    : options_(std::move(options)), state_(std::move(state)), queue_(std::move(queue)) {
}

workspace_database_t::~workspace_database_t() {
    request_cancel();
}

const std::string& workspace_database_t::path() const noexcept {
    return state_->path;
}

const workspace_database_options_t& workspace_database_t::options() const noexcept {
    return options_;
}

std::shared_ptr<persistence_queue_t> workspace_database_t::queue() const noexcept {
    return queue_;
}

persistence_ticket_t workspace_database_t::enqueue_write(std::string label,
                                                         writer_operation_t operation,
                                                         cancellation_token_t cancel) {
    auto state = state_;
    return queue_->enqueue(std::move(label),
        [state, operation = std::move(operation)](const cancellation_token_t& token) mutable {
            std::lock_guard<std::timed_mutex> writer_lock(state->writer_mutex);
            if (!state->open.load(std::memory_order_acquire) || !state->writer) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::workspace_closing,
                                         "workspace database is closed",
                                         "workspace_database.write"));
            }
            sqlite_progress_guard_t progress(state->writer, token);
            auto result = operation(state->writer, token);
            if (!result && token.stop_requested()) {
                auto error = make_workspace_error(
                    token.deadline_exceeded()
                        ? workspace_error_code_t::deadline_exceeded
                        : workspace_error_code_t::cancelled,
                    "workspace database write was cancelled",
                    "workspace_database.write");
                error.deadline = token.deadline_exceeded();
                error.cancellation = !error.deadline;
                error.details.emplace_back("sqlite_write_error",
                                           result.error().stable_code());
                return workspace_result_t<void>::failure(std::move(error));
            }
            return result;
        }, std::move(cancel));
}

persistence_ticket_t workspace_database_t::persist_snapshot(
    std::shared_ptr<const analysis_snapshot_t> snapshot,
    std::string analysis_settings_json,
    std::string analysis_metrics_json,
    cancellation_token_t cancel) {
    if (!snapshot) {
        return queue_->enqueue("analysis.persistence.invalid_snapshot",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::invalid_argument,
                                         "analysis snapshot is null",
                                         "workspace_database.persist"));
            }, std::move(cancel));
    }
    if (snapshot->baseline_complete) {
        return queue_->enqueue("analysis.persistence.missing_search_products",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::invalid_argument,
                    "complete baseline persistence requires its search products",
                    "workspace_database.persist"));
            }, std::move(cancel));
    }
    const bool image_matches = snapshot->normalized_image
        ? image_matches_identity(*snapshot->normalized_image, *options_.identity)
        : snapshot->image && image_matches_identity(*snapshot->image, *options_.identity);
    if (!image_matches) {
        return queue_->enqueue("analysis.persistence.identity_conflict",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::target_conflict,
                    "analysis snapshot image identity does not match the database",
                    "workspace_database.persist"));
            }, std::move(cancel));
    }
    auto validated = validate_analysis_snapshot(*snapshot, snapshot->baseline_complete, cancel);
    if (!validated) {
        const auto error = validated.error();
        return queue_->enqueue("analysis.persistence.invalid_snapshot",
            [error](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(error);
            }, std::move(cancel));
    }
    auto candidate_token_result = generate_candidate_token();
    if (!candidate_token_result) {
        const auto error = candidate_token_result.error();
        return queue_->enqueue("analysis.persistence.candidate_token_failure",
            [error](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(error);
            }, std::move(cancel));
    }
    auto state = state_;
    auto options = options_;
    const std::uint64_t generation = snapshot->generation;
    const std::uint64_t analysis_revision = snapshot->analysis_revision;
    const std::uint64_t overlay_revision = snapshot->overlay_revision;
    const std::string candidate_token = candidate_token_result.take_value();
    auto candidate = std::shared_ptr<const workspace_persistence_candidate_t>(
        new workspace_persistence_candidate_t(weak_from_this(), candidate_token,
            generation, analysis_revision, overlay_revision));
    auto commit_measurement = std::make_shared<persistence_commit_metrics_t>();
    auto ticket = enqueue_write("analysis.persistence.snapshot",
        [state, options = std::move(options), snapshot = std::move(snapshot),
         settings = std::move(analysis_settings_json), metrics = std::move(analysis_metrics_json),
         generation, analysis_revision, overlay_revision, candidate_token,
         commit_measurement]
        (sqlite3* database, const cancellation_token_t& token) mutable {
            auto result = persist_snapshot_impl(database, *snapshot, nullptr, options,
                                                settings, metrics, candidate_token, token,
                                                commit_measurement.get());
            if (result) {
                state->candidate_generation.store(generation, std::memory_order_release);
                state->candidate_analysis_revision.store(analysis_revision, std::memory_order_release);
                state->candidate_overlay_revision.store(overlay_revision, std::memory_order_release);
                state->candidate_pending.store(true, std::memory_order_release);
                publish_commit_metrics(*state, *commit_measurement);
            }
            return result;
        }, std::move(cancel));
    ticket.commit_metrics = std::move(commit_measurement);
    ticket.snapshot_candidate = std::move(candidate);
    return ticket;
}

persistence_ticket_t workspace_database_t::persist_snapshot(
    std::shared_ptr<const analysis_snapshot_t> snapshot,
    persisted_search_products_t search_products,
    std::string analysis_settings_json,
    std::string analysis_metrics_json,
    cancellation_token_t cancel) {
    if (!snapshot) {
        return queue_->enqueue("analysis.persistence.invalid_snapshot",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::invalid_argument,
                                         "analysis snapshot is null",
                                         "workspace_database.persist"));
            }, std::move(cancel));
    }
    const bool image_matches = snapshot->normalized_image
        ? image_matches_identity(*snapshot->normalized_image, *options_.identity)
        : snapshot->image && image_matches_identity(*snapshot->image, *options_.identity);
    if (!image_matches) {
        return queue_->enqueue("analysis.persistence.identity_conflict",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::target_conflict,
                    "analysis snapshot image identity does not match the database",
                    "workspace_database.persist"));
            }, std::move(cancel));
    }
    auto validated = validate_analysis_snapshot(*snapshot, snapshot->baseline_complete, cancel);
    if (!validated) {
        const auto error = validated.error();
        return queue_->enqueue("analysis.persistence.invalid_snapshot",
            [error](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(error);
            }, std::move(cancel));
    }
    if (search_products.generation != snapshot->generation ||
        search_products.analysis_revision != snapshot->analysis_revision ||
        search_products.overlay_revision != snapshot->overlay_revision) {
        return queue_->enqueue("analysis.persistence.stale_search_products",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::stale_generation,
                                         "search products do not match the snapshot revisions",
                                         "workspace_database.persist"));
            }, std::move(cancel));
    }
    auto candidate_token_result = generate_candidate_token();
    if (!candidate_token_result) {
        const auto error = candidate_token_result.error();
        return queue_->enqueue("analysis.persistence.candidate_token_failure",
            [error](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(error);
            }, std::move(cancel));
    }
    auto state = state_;
    auto options = options_;
    const std::uint64_t generation = snapshot->generation;
    const std::uint64_t analysis_revision = snapshot->analysis_revision;
    const std::uint64_t overlay_revision = snapshot->overlay_revision;
    const std::string candidate_token = candidate_token_result.take_value();
    auto candidate = std::shared_ptr<const workspace_persistence_candidate_t>(
        new workspace_persistence_candidate_t(weak_from_this(), candidate_token,
            generation, analysis_revision, overlay_revision));
    auto commit_measurement = std::make_shared<persistence_commit_metrics_t>();
    auto ticket = enqueue_write("analysis.persistence.snapshot_products",
        [state, options = std::move(options), snapshot = std::move(snapshot),
         products = std::move(search_products), settings = std::move(analysis_settings_json),
         metrics = std::move(analysis_metrics_json), generation, analysis_revision,
         overlay_revision, candidate_token, commit_measurement]
        (sqlite3* database, const cancellation_token_t& token) mutable {
            auto result = persist_snapshot_impl(database, *snapshot, &products, options,
                                                settings, metrics, candidate_token, token,
                                                commit_measurement.get());
            if (result) {
                state->candidate_generation.store(generation, std::memory_order_release);
                state->candidate_analysis_revision.store(analysis_revision, std::memory_order_release);
                state->candidate_overlay_revision.store(overlay_revision, std::memory_order_release);
                state->candidate_pending.store(true, std::memory_order_release);
                publish_commit_metrics(*state, *commit_measurement);
            }
            return result;
        }, std::move(cancel));
    ticket.commit_metrics = std::move(commit_measurement);
    ticket.snapshot_candidate = std::move(candidate);
    return ticket;
}

workspace_result_t<void> workspace_database_t::with_reader(
    const reader_operation_t& operation,
    const cancellation_token_t& cancel) const {
    const auto cancelled = [&] {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "workspace database read was cancelled",
            "workspace_database.read");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<void>::failure(std::move(error));
    };
    if (cancel.stop_requested())
        return cancelled();
    if (!state_->open.load(std::memory_order_acquire)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace database is closed",
                                 "workspace_database.read"));
    }
    sqlite3* database = nullptr;
    const int status = sqlite3_open_v2(state_->path.c_str(), &database,
        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_URI, nullptr);
    if (status != SQLITE_OK) {
        auto error = database_error(database, status, "unable to open workspace read connection",
                                    "workspace_database.read");
        if (database)
            sqlite3_close_v2(database);
        return workspace_result_t<void>::failure(std::move(error));
    }
    auto configured = configure_connection(database, options_, false);
    if (!configured) {
        sqlite3_close_v2(database);
        return configured;
    }
    sqlite_progress_guard_t progress(database, cancel);
    auto begun = exec_sql(database, "BEGIN", "workspace_database.read");
    if (!begun) {
        progress.reset();
        sqlite3_close_v2(database);
        if (cancel.stop_requested())
            return cancelled();
        return begun;
    }
    auto result = operation(database);
    if (!result && cancel.stop_requested())
        result = cancelled();
    if (result) {
        auto committed = exec_sql(database, "COMMIT", "workspace_database.read");
        if (!committed) {
            exec_sql(database, "ROLLBACK", "workspace_database.read");
            result = cancel.stop_requested() ? cancelled() : committed;
        }
    } else {
        exec_sql(database, "ROLLBACK", "workspace_database.read");
    }
    progress.reset();
    const int close_status = sqlite3_close_v2(database);
    if (result && close_status != SQLITE_OK) {
        return workspace_result_t<void>::failure(
            database_error(database, close_status, "unable to close workspace read connection",
                           "workspace_database.read"));
    }
    return result;
}

workspace_result_t<void> workspace_database_t::finalize_candidate(
    const workspace_persistence_candidate_t& candidate,
    const cancellation_token_t& cancel) {
    if (!valid_candidate_token(candidate.token_) || candidate.generation_ == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "persistence candidate identity is malformed",
            "workspace_database.candidate.finalize"));
    }
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "persistence candidate finalization was cancelled before promotion",
            "workspace_database.candidate.finalize");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<void>::failure(std::move(error));
    }
    const auto local_deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(options_.candidate_operation_timeout_ms);
    const auto lock_deadline = cancel.deadline()
        ? (std::min)(local_deadline, *cancel.deadline()) : local_deadline;
    std::unique_lock<std::timed_mutex> writer_lock(state_->writer_mutex,
                                                   std::defer_lock);
    if (!writer_lock.try_lock_until(lock_deadline)) {
        auto error = make_workspace_error(
            cancel.cancellation_requested() ? workspace_error_code_t::cancelled
                                            : workspace_error_code_t::deadline_exceeded,
            "persistence writer was unavailable before the finalization deadline",
            "workspace_database.candidate.finalize");
        error.cancellation = cancel.cancellation_requested();
        error.deadline = !error.cancellation;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "persistence candidate finalization was cancelled before promotion",
            "workspace_database.candidate.finalize");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (!state_->open.load(std::memory_order_acquire) || !state_->writer) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "persistence database is closed",
            "workspace_database.candidate.finalize"));
    }
    sqlite3* database = state_->writer;
    auto begun = begin_immediate(database,
                                 "workspace_database.candidate.finalize");
    if (!begun)
        return begun;
    auto state = read_commit_state(database,
                                   "workspace_database.candidate.finalize");
    if (!state) {
        rollback(database, "workspace_database.candidate.finalize");
        return workspace_result_t<void>::failure(state.error());
    }
    const auto committed_matches = [&] {
        return state.value().committed_token == candidate.token_ &&
               state.value().committed_generation == candidate.generation_ &&
               state.value().committed_analysis_revision ==
                   candidate.analysis_revision_ &&
               state.value().committed_overlay_revision ==
                   candidate.overlay_revision_;
    };
    if (state.value().committed_token == candidate.token_) {
        rollback(database, "workspace_database.candidate.finalize");
        if (!committed_matches()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "promoted candidate token has inconsistent revisions",
                "workspace_database.candidate.finalize"));
        }
        state_->persisted_generation.store(candidate.generation_,
                                           std::memory_order_release);
        state_->persisted_analysis_revision.store(candidate.analysis_revision_,
                                                  std::memory_order_release);
        state_->persisted_overlay_revision.store(candidate.overlay_revision_,
                                                 std::memory_order_release);
        state_->candidate_pending.store(false, std::memory_order_release);
        state_->candidate_generation.store(0, std::memory_order_release);
        state_->candidate_analysis_revision.store(0, std::memory_order_release);
        state_->candidate_overlay_revision.store(0, std::memory_order_release);
        return workspace_result_t<void>::success();
    }
    if (!state.value().candidate_ready ||
        state.value().candidate_token != candidate.token_ ||
        state.value().candidate_generation != candidate.generation_ ||
        state.value().candidate_analysis_revision != candidate.analysis_revision_ ||
        state.value().candidate_overlay_revision != candidate.overlay_revision_ ||
        !state.value().candidate_slot) {
        rollback(database, "workspace_database.candidate.finalize");
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "persistence candidate is no longer the pending workspace candidate",
            "workspace_database.candidate.finalize"));
    }
    const std::uint8_t candidate_slot = *state.value().candidate_slot;
    statement_t slot_state;
    const std::string slot_state_select =
        "SELECT generation,analysis_revision,overlay_revision,commit_token FROM " +
        slot_table(candidate_slot, "analysis_state") + " WHERE singleton=1";
    auto current = slot_state.prepare(database, slot_state_select.c_str(),
                                      "workspace_database.candidate.finalize");
    if (!current) {
        rollback(database, "workspace_database.candidate.finalize");
        return current;
    }
    const int slot_status = sqlite3_step(slot_state.get());
    if (slot_status != SQLITE_ROW ||
        static_cast<std::uint64_t>(sqlite3_column_int64(slot_state.get(), 0)) !=
            candidate.generation_ ||
        static_cast<std::uint64_t>(sqlite3_column_int64(slot_state.get(), 1)) !=
            candidate.analysis_revision_ ||
        static_cast<std::uint64_t>(sqlite3_column_int64(slot_state.get(), 2)) !=
            candidate.overlay_revision_ ||
        column_text(slot_state.get(), 3) != candidate.token_) {
        rollback(database, "workspace_database.candidate.finalize");
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "candidate fact slot does not match its promotion marker",
            "workspace_database.candidate.finalize"));
    }
    statement_t promote;
    current = promote.prepare(database,
        "UPDATE workspace_commit_state SET active_slot=?1,committed_token=?2,committed_generation=?3,committed_analysis_revision=?4,committed_overlay_revision=?5,candidate_slot=NULL,candidate_token=NULL,candidate_generation=NULL,candidate_analysis_revision=NULL,candidate_overlay_revision=NULL,candidate_ready=0,updated_utc_ms=?6 WHERE singleton=1 AND candidate_ready=1 AND candidate_token=?2",
        "workspace_database.candidate.finalize");
    if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    current = promote.bind_uint(1, candidate_slot); if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    current = promote.bind_text(2, candidate.token_); if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    current = promote.bind_uint(3, candidate.generation_); if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    current = promote.bind_uint(4, candidate.analysis_revision_); if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    current = promote.bind_uint(5, candidate.overlay_revision_); if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    current = promote.bind_uint(6, utc_ms()); if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    current = promote.step_done(); if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    if (sqlite3_changes(database) != 1) {
        rollback(database, "workspace_database.candidate.finalize");
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "persistence candidate changed during promotion",
            "workspace_database.candidate.finalize"));
    }
    auto committed = commit(database, "workspace_database.candidate.finalize");
    if (!committed) {
        rollback(database, "workspace_database.candidate.finalize");
        return committed;
    }
    state_->persisted_generation.store(candidate.generation_,
                                       std::memory_order_release);
    state_->persisted_analysis_revision.store(candidate.analysis_revision_,
                                              std::memory_order_release);
    state_->persisted_overlay_revision.store(candidate.overlay_revision_,
                                             std::memory_order_release);
    state_->candidate_pending.store(false, std::memory_order_release);
    state_->candidate_generation.store(0, std::memory_order_release);
    state_->candidate_analysis_revision.store(0, std::memory_order_release);
    state_->candidate_overlay_revision.store(0, std::memory_order_release);
    return workspace_result_t<void>::success();
}

workspace_result_t<void> workspace_database_t::discard_candidate(
    const workspace_persistence_candidate_t& candidate,
    const cancellation_token_t& cancel) {
    if (!valid_candidate_token(candidate.token_) || candidate.generation_ == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "persistence candidate identity is malformed",
            "workspace_database.candidate.discard"));
    }
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "persistence candidate discard was cancelled before mutation",
            "workspace_database.candidate.discard");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<void>::failure(std::move(error));
    }
    const auto local_deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(options_.candidate_operation_timeout_ms);
    const auto lock_deadline = cancel.deadline()
        ? (std::min)(local_deadline, *cancel.deadline()) : local_deadline;
    std::unique_lock<std::timed_mutex> writer_lock(state_->writer_mutex,
                                                   std::defer_lock);
    if (!writer_lock.try_lock_until(lock_deadline)) {
        auto error = make_workspace_error(
            cancel.cancellation_requested() ? workspace_error_code_t::cancelled
                                            : workspace_error_code_t::deadline_exceeded,
            "persistence writer was unavailable before the discard deadline",
            "workspace_database.candidate.discard");
        error.cancellation = cancel.cancellation_requested();
        error.deadline = !error.cancellation;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "persistence candidate discard was cancelled before mutation",
            "workspace_database.candidate.discard");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (!state_->open.load(std::memory_order_acquire) || !state_->writer) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "persistence database is closed",
            "workspace_database.candidate.discard"));
    }
    sqlite3* database = state_->writer;
    auto begun = begin_immediate(database,
                                 "workspace_database.candidate.discard");
    if (!begun)
        return begun;
    auto state = read_commit_state(database,
                                   "workspace_database.candidate.discard");
    if (!state) {
        rollback(database, "workspace_database.candidate.discard");
        return workspace_result_t<void>::failure(state.error());
    }
    if (state.value().committed_token == candidate.token_) {
        const bool revisions_match =
            state.value().committed_generation == candidate.generation_ &&
            state.value().committed_analysis_revision ==
                candidate.analysis_revision_ &&
            state.value().committed_overlay_revision == candidate.overlay_revision_;
        rollback(database, "workspace_database.candidate.discard");
        if (!revisions_match) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "promoted candidate token has inconsistent revisions",
                "workspace_database.candidate.discard"));
        }
        return workspace_result_t<void>::success();
    }
    if (!state.value().candidate_ready) {
        rollback(database, "workspace_database.candidate.discard");
        return workspace_result_t<void>::success();
    }
    if (state.value().candidate_token != candidate.token_ ||
        state.value().candidate_generation != candidate.generation_ ||
        state.value().candidate_analysis_revision != candidate.analysis_revision_ ||
        state.value().candidate_overlay_revision != candidate.overlay_revision_ ||
        !state.value().candidate_slot) {
        rollback(database, "workspace_database.candidate.discard");
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "a different persistence candidate is pending",
            "workspace_database.candidate.discard"));
    }
    auto cleared = clear_snapshot_slot(database, *state.value().candidate_slot,
                                       "workspace_database.candidate.discard");
    if (!cleared) {
        rollback(database, "workspace_database.candidate.discard");
        return cleared;
    }
    statement_t discard;
    auto current = discard.prepare(database,
        "UPDATE workspace_commit_state SET candidate_slot=NULL,candidate_token=NULL,candidate_generation=NULL,candidate_analysis_revision=NULL,candidate_overlay_revision=NULL,candidate_ready=0,updated_utc_ms=?1 WHERE singleton=1 AND candidate_ready=1 AND candidate_token=?2",
        "workspace_database.candidate.discard");
    if (!current) { rollback(database, "workspace_database.candidate.discard"); return current; }
    current = discard.bind_uint(1, utc_ms()); if (!current) { rollback(database, "workspace_database.candidate.discard"); return current; }
    current = discard.bind_text(2, candidate.token_); if (!current) { rollback(database, "workspace_database.candidate.discard"); return current; }
    current = discard.step_done(); if (!current) { rollback(database, "workspace_database.candidate.discard"); return current; }
    if (sqlite3_changes(database) != 1) {
        rollback(database, "workspace_database.candidate.discard");
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "persistence candidate changed during discard",
            "workspace_database.candidate.discard"));
    }
    auto committed = commit(database, "workspace_database.candidate.discard");
    if (!committed) {
        rollback(database, "workspace_database.candidate.discard");
        return committed;
    }
    state_->candidate_pending.store(false, std::memory_order_release);
    state_->candidate_generation.store(0, std::memory_order_release);
    state_->candidate_analysis_revision.store(0, std::memory_order_release);
    state_->candidate_overlay_revision.store(0, std::memory_order_release);
    return workspace_result_t<void>::success();
}

workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>
workspace_database_t::load_snapshot(std::shared_ptr<const pe_image_t> image,
                                    const cancellation_token_t& cancel) const {
    return load_snapshot(std::shared_ptr<const workspace_image_t>{}, std::move(image), cancel);
}

workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>
workspace_database_t::load_snapshot(std::shared_ptr<const workspace_image_t> image,
                                    std::shared_ptr<const pe_image_t> pe_adapter,
                                    const cancellation_token_t& cancel) const {
    if ((image && !image_matches_identity(*image, *options_.identity)) ||
        (pe_adapter && !image_matches_identity(*pe_adapter, *options_.identity))) {
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_conflict,
                "requested image identity does not match the workspace database",
                "workspace_database.load"));
    }
    auto loaded = std::make_shared<analysis_snapshot_t>();
    loaded->binary_id = options_.identity->binary_id();
    loaded->load_profile_hash = options_.identity->load_profile_hash();
    loaded->normalized_image = std::move(image);
    loaded->image = std::move(pe_adapter);
    bool found = false;
    auto result = with_reader([&](sqlite3* database) -> workspace_result_t<void> {
        auto commit_state = read_commit_state(database, "workspace_database.load");
        if (!commit_state)
            return workspace_result_t<void>::failure(commit_state.error());
        if (commit_state.value().committed_token.empty())
            return workspace_result_t<void>::success();
        const std::uint8_t active_slot = commit_state.value().active_slot;
        statement_t state_statement;
        const std::string state_select = "SELECT generation,analysis_revision,overlay_revision,baseline_complete,commit_token FROM " +
            slot_table(active_slot, "analysis_state") + " WHERE singleton=1";
        auto current = state_statement.prepare(database, state_select.c_str(),
            "workspace_database.load");
        if (!current) return current;
        int status = sqlite3_step(state_statement.get());
        if (status == SQLITE_DONE)
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "promoted analysis slot has no state row",
                "workspace_database.load"));
        if (status != SQLITE_ROW)
            return workspace_result_t<void>::failure(database_error(database, status,
                "unable to read analysis state", "workspace_database.load"));
        found = true;
        loaded->generation = static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 0));
        loaded->analysis_revision = static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 1));
        loaded->overlay_revision = static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 2));
        loaded->baseline_complete = sqlite3_column_int(state_statement.get(), 3) != 0;
        if (column_text(state_statement.get(), 4) !=
                commit_state.value().committed_token ||
            loaded->generation != commit_state.value().committed_generation ||
            loaded->analysis_revision !=
                commit_state.value().committed_analysis_revision ||
            loaded->overlay_revision !=
                commit_state.value().committed_overlay_revision) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "active analysis slot does not match the promoted commit marker",
                "workspace_database.load"));
        }

        std::uint64_t total_rows = 0;
        auto read_rows = [&](const std::string& sql, const char* phase, auto reader) -> workspace_result_t<void> {
            statement_t statement;
            auto prepared = statement.prepare(database, sql.c_str(), phase);
            if (!prepared) return prepared;
            std::size_t row = 0;
            for (;;) {
                if ((row++ & 255U) == 0 && cancel.stop_requested()) {
                    auto error = make_workspace_error(cancel.deadline_exceeded()
                                                          ? workspace_error_code_t::deadline_exceeded
                                                          : workspace_error_code_t::cancelled,
                                                      "snapshot reopen cancelled", phase);
                    error.deadline = cancel.deadline_exceeded();
                    error.cancellation = !error.deadline;
                    return workspace_result_t<void>::failure(std::move(error));
                }
                const int step_status = sqlite3_step(statement.get());
                if (step_status == SQLITE_DONE)
                    return workspace_result_t<void>::success();
                if (step_status != SQLITE_ROW)
                    return workspace_result_t<void>::failure(database_error(database, step_status,
                        "unable to read persisted fact row", phase));
                if (++total_rows > options_.max_persisted_fact_records) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::limit_exceeded,
                        "persisted fact rows exceed the reopen budget", phase));
                }
                auto row_result = reader(statement.get());
                if (!row_result) return row_result;
            }
        };

        current = read_rows("SELECT payload FROM " + slot_table(active_slot, "instruction_chunks") + " ORDER BY chunk_id",
            "workspace_database.load.instructions", [&](sqlite3_stmt* statement) {
                const void* payload = sqlite3_column_blob(statement, 0);
                const int bytes = sqlite3_column_bytes(statement, 0);
                if (!payload || bytes <= 0)
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "persisted instruction chunk is empty", "workspace_database.load.instructions"));
                auto decoded = decode_instruction_chunk(
                    payload, static_cast<std::size_t>(bytes), loaded->instructions,
                    cancel);
                if (!decoded)
                    return decoded;
                if (loaded->instructions.size() > options_.max_persisted_fact_records) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::limit_exceeded,
                        "persisted instructions exceed the reopen budget",
                        "workspace_database.load.instructions"));
                }
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT instruction_id,operand_index,entity_id,address_expression_id,decoder_operand_id,kind,access,visibility,encoding,memory_type,access_width,bit_width,access_width_bits,access_count,element_width_bits,element_count,address_width_bits,reg,segment_reg,base_reg,index_reg,scale,relative,signed_value,has_displacement,has_resolved_expression_value,displacement,immediate,resolved_expression_value,address_components,address_expression,address_resolution FROM " + slot_table(active_slot, "operand_facts") + " ORDER BY instruction_id,operand_index",
            "workspace_database.load.operands", [&](sqlite3_stmt* statement) {
                const std::int64_t segment_register = sqlite3_column_int64(statement, 18);
                if (segment_register < 0 ||
                    segment_register > (std::numeric_limits<std::uint16_t>::max)()) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "persisted operand segment register is outside the compact IR range",
                        "workspace_database.load.operands"));
                }
                operand_fact_t fact;
                fact.instruction_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                fact.operand_index = static_cast<std::uint8_t>(sqlite3_column_int(statement, 1));
                fact.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 2));
                fact.address_expression_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 3));
                fact.decoder_operand_id = static_cast<std::uint8_t>(sqlite3_column_int(statement, 4));
                fact.kind = static_cast<operand_kind_t>(sqlite3_column_int(statement, 5));
                fact.access = static_cast<std::uint8_t>(sqlite3_column_int(statement, 6));
                fact.visibility = static_cast<std::uint8_t>(sqlite3_column_int(statement, 7));
                fact.encoding = static_cast<std::uint8_t>(sqlite3_column_int(statement, 8));
                fact.memory_type = static_cast<std::uint8_t>(sqlite3_column_int(statement, 9));
                fact.access_width = static_cast<std::uint8_t>(sqlite3_column_int(statement, 10));
                fact.bit_width = static_cast<std::uint16_t>(sqlite3_column_int(statement, 11));
                fact.access_width_bits = static_cast<std::uint16_t>(sqlite3_column_int(statement, 12));
                fact.access_count = static_cast<std::uint16_t>(sqlite3_column_int(statement, 13));
                fact.element_width_bits = static_cast<std::uint16_t>(sqlite3_column_int(statement, 14));
                fact.element_count = static_cast<std::uint16_t>(sqlite3_column_int(statement, 15));
                fact.address_width_bits = static_cast<std::uint16_t>(sqlite3_column_int(statement, 16));
                fact.reg = static_cast<std::uint16_t>(sqlite3_column_int(statement, 17));
                fact.segment_reg = static_cast<std::uint16_t>(segment_register);
                fact.base_reg = static_cast<std::uint16_t>(sqlite3_column_int(statement, 19));
                fact.index_reg = static_cast<std::uint16_t>(sqlite3_column_int(statement, 20));
                fact.scale = static_cast<std::uint8_t>(sqlite3_column_int(statement, 21));
                fact.relative = sqlite3_column_int(statement, 22) != 0;
                fact.signed_value = sqlite3_column_int(statement, 23) != 0;
                fact.has_displacement = sqlite3_column_int(statement, 24) != 0;
                fact.has_resolved_expression_value = sqlite3_column_int(statement, 25) != 0;
                fact.displacement = sqlite3_column_int64(statement, 26);
                fact.immediate = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 27));
                fact.resolved_expression_value = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 28));
                fact.address_components = static_cast<std::uint16_t>(sqlite3_column_int(statement, 29));
                fact.address_expression = static_cast<address_expression_kind_t>(sqlite3_column_int(statement, 30));
                fact.address_resolution = static_cast<target_resolution_t>(sqlite3_column_int(statement, 31));
                loaded->operand_facts.push_back(fact);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT instruction_id,operand_fact_id,address_expression_id,target_space,target_value,target_arch,target_mode,kind,resolution,operand_index,access_width_bits,access_count,direct,is_external FROM " + slot_table(active_slot, "target_facts") + " ORDER BY instruction_id,target_index",
            "workspace_database.load.targets", [&](sqlite3_stmt* statement) {
                target_fact_t fact;
                fact.instruction_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                fact.operand_fact_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
                fact.address_expression_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 2));
                fact.target = read_address(statement, 3);
                fact.kind = static_cast<target_kind_record_t>(sqlite3_column_int(statement, 7));
                fact.resolution = static_cast<target_resolution_t>(sqlite3_column_int(statement, 8));
                fact.operand_index = static_cast<std::uint8_t>(sqlite3_column_int(statement, 9));
                fact.access_width_bits = static_cast<std::uint16_t>(sqlite3_column_int(statement, 10));
                fact.access_count = static_cast<std::uint16_t>(sqlite3_column_int(statement, 11));
                fact.direct = sqlite3_column_int(statement, 12) != 0;
                fact.is_external = sqlite3_column_int(statement, 13) != 0;
                loaded->target_facts.push_back(fact);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,start_space,start_value,start_arch,start_mode,end_space,end_value,end_arch,end_mode,first_block,block_count,first_chunk,chunk_count,first_block_membership,block_membership_count,symbol_id,provenance,confidence,thunk,noreturn FROM " + slot_table(active_slot, "functions") + " ORDER BY start_value,entity_id",
            "workspace_database.load.functions", [&](sqlite3_stmt* statement) {
                function_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.start = read_address(statement, 1);
                record.end = read_address(statement, 5);
                record.first_block = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 9));
                record.block_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 10));
                record.first_chunk = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 11));
                record.chunk_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 12));
                record.first_block_membership = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 13));
                record.block_membership_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 14));
                if (sqlite3_column_type(statement, 15) != SQLITE_NULL)
                    record.symbol_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 15));
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 16));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 17));
                record.thunk = sqlite3_column_int(statement, 18) != 0;
                record.noreturn = sqlite3_column_int(statement, 19) != 0;
                loaded->functions.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,function_id,start_space,start_value,start_arch,start_mode,end_space,end_value,end_arch,end_mode,first_instruction,instruction_count,provenance,confidence FROM " + slot_table(active_slot, "blocks") + " ORDER BY start_value,entity_id",
            "workspace_database.load.blocks", [&](sqlite3_stmt* statement) {
                basic_block_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
                record.start = read_address(statement, 2);
                record.end = read_address(statement, 6);
                record.first_instruction = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 10));
                record.instruction_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 11));
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 12));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 13));
                loaded->blocks.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,function_id,start_space,start_value,start_arch,start_mode,end_space,end_value,end_arch,end_mode,first_block,block_count,provenance,confidence,cold,shared FROM " + slot_table(active_slot, "function_chunks") + " ORDER BY chunk_index",
            "workspace_database.load.function_chunks", [&](sqlite3_stmt* statement) {
                function_chunk_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
                record.start = read_address(statement, 2);
                record.end = read_address(statement, 6);
                record.first_block = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 10));
                record.block_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 11));
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 12));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 13));
                record.cold = sqlite3_column_int(statement, 14) != 0;
                record.shared = sqlite3_column_int(statement, 15) != 0;
                loaded->function_chunks.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT function_id,chunk_id,block_id,block_index,ordinal,shared FROM " + slot_table(active_slot, "function_block_memberships") + " ORDER BY membership_index",
            "workspace_database.load.function_block_memberships", [&](sqlite3_stmt* statement) {
                function_block_membership_record_t record;
                record.function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.chunk_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
                record.block_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 2));
                record.block_index = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 3));
                record.ordinal = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 4));
                record.shared = sqlite3_column_int(statement, 5) != 0;
                loaded->function_block_memberships.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,source_entity,target_entity,source_space,source_value,source_arch,source_mode,target_space,target_value,target_arch,target_mode,kind,provenance,confidence FROM " + slot_table(active_slot, "edges") + " ORDER BY source_value,target_value,entity_id",
            "workspace_database.load.edges", [&](sqlite3_stmt* statement) {
                edge_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.source_entity = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
                if (sqlite3_column_type(statement, 2) != SQLITE_NULL)
                    record.target_entity = static_cast<entity_id_t>(sqlite3_column_int64(statement, 2));
                record.source = read_address(statement, 3);
                record.target = read_address(statement, 7);
                record.kind = static_cast<edge_kind_t>(sqlite3_column_int(statement, 11));
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 12));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 13));
                loaded->edges.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        statement_t call_graph_state;
        const std::string call_graph_state_sql =
            "SELECT indirect_site_count,unresolved_site_count,bounded FROM " +
            slot_table(active_slot, "call_graph_state") + " WHERE singleton=1";
        current = call_graph_state.prepare(database, call_graph_state_sql.c_str(),
            "workspace_database.load.call_graph_state");
        if (!current) return current;
        status = sqlite3_step(call_graph_state.get());
        if (status == SQLITE_ROW) {
            loaded->call_graph.indirect_site_count = static_cast<std::uint64_t>(
                sqlite3_column_int64(call_graph_state.get(), 0));
            loaded->call_graph.unresolved_site_count = static_cast<std::uint64_t>(
                sqlite3_column_int64(call_graph_state.get(), 1));
            loaded->call_graph.bounded = sqlite3_column_int(call_graph_state.get(), 2) != 0;
        } else if (status != SQLITE_DONE) {
            return workspace_result_t<void>::failure(database_error(
                database, status, "unable to read call-graph state",
                "workspace_database.load.call_graph_state"));
        }

        current = read_rows("SELECT function_id,address_space,address_value,address_arch,address_mode,incoming_edges,outgoing_edges,indirect_edges,unresolved_sites FROM " + slot_table(active_slot, "call_graph_nodes") + " ORDER BY address_value,function_id",
            "workspace_database.load.call_graph_nodes", [&](sqlite3_stmt* statement) {
                call_graph_node_record_t record;
                record.function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.address = read_address(statement, 1);
                record.incoming_edges = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 5));
                record.outgoing_edges = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 6));
                record.indirect_edges = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 7));
                record.unresolved_sites = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 8));
                loaded->call_graph.nodes.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,source_function_id,source_block_id,instruction_id,address_space,address_value,address_arch,address_mode,first_candidate,candidate_count,indirect,tail_call,unresolved FROM " + slot_table(active_slot, "call_sites") + " ORDER BY entity_id",
            "workspace_database.load.call_sites", [&](sqlite3_stmt* statement) {
                recovered_call_site_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.source_function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
                record.source_block_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 2));
                record.instruction_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 3));
                record.address = read_address(statement, 4);
                record.first_candidate = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 8));
                record.candidate_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 9));
                record.indirect = sqlite3_column_int(statement, 10) != 0;
                record.tail_call = sqlite3_column_int(statement, 11) != 0;
                record.unresolved = sqlite3_column_int(statement, 12) != 0;
                loaded->call_graph.call_sites.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,call_site_id,target_space,target_value,target_arch,target_mode,target_function_id,kind,provenance,confidence,contributor_count,conflicted,stable_source_id,rank,external_target FROM " + slot_table(active_slot, "call_candidates") + " ORDER BY entity_id",
            "workspace_database.load.call_candidates", [&](sqlite3_stmt* statement) {
                recovered_call_candidate_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.call_site_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
                record.target = read_address(statement, 2);
                if (sqlite3_column_type(statement, 6) != SQLITE_NULL)
                    record.target_function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 6));
                record.kind = static_cast<indirect_call_candidate_kind_t>(sqlite3_column_int(statement, 7));
                record.quality.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 8));
                record.quality.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 9));
                record.quality.contributor_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 10));
                record.quality.conflicted = sqlite3_column_int(statement, 11) != 0;
                record.stable_source_id = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 12));
                record.rank = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 13));
                record.external_target = sqlite3_column_int(statement, 14) != 0;
                loaded->call_graph.candidates.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,call_site_id,source_function_id,source_block_id,target_function_id,call_site_space,call_site_value,call_site_arch,call_site_mode,target_space,target_value,target_arch,target_mode,resolution,provenance,confidence,contributor_count,conflicted,candidate_rank,external_target,target_noreturn FROM " + slot_table(active_slot, "call_graph_edges") + " ORDER BY entity_id",
            "workspace_database.load.call_graph_edges", [&](sqlite3_stmt* statement) {
                call_graph_edge_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.call_site_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
                record.source_function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 2));
                record.source_block_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 3));
                if (sqlite3_column_type(statement, 4) != SQLITE_NULL)
                    record.target_function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 4));
                record.call_site = read_address(statement, 5);
                record.target = read_address(statement, 9);
                record.resolution = static_cast<call_graph_resolution_t>(sqlite3_column_int(statement, 13));
                record.quality.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 14));
                record.quality.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 15));
                record.quality.contributor_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 16));
                record.quality.conflicted = sqlite3_column_int(statement, 17) != 0;
                record.candidate_rank = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 18));
                record.external_target = sqlite3_column_int(statement, 19) != 0;
                record.target_noreturn = sqlite3_column_int(statement, 20) != 0;
                loaded->call_graph.edges.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,kind,instruction_id,source_function_id,call_site_rva,selected_target_rva,competing_target_rva,selected_target_function_id,competing_target_function_id FROM " + slot_table(active_slot, "call_graph_conflicts") + " ORDER BY entity_id",
            "workspace_database.load.call_graph_conflicts", [&](sqlite3_stmt* statement) {
                call_graph_conflict_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.kind = static_cast<call_graph_conflict_kind_t>(sqlite3_column_int(statement, 1));
                record.instruction_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 2));
                record.source_function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 3));
                record.call_site_rva = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 4));
                record.selected_target_rva = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 5));
                record.competing_target_rva = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 6));
                record.selected_target_function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 7));
                record.competing_target_function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 8));
                loaded->call_graph.conflicts.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,source_space,source_value,source_arch,source_mode,target_space,target_value,target_arch,target_mode,kind,provenance,confidence FROM " + slot_table(active_slot, "xrefs") + " ORDER BY source_value,target_value,entity_id",
            "workspace_database.load.xrefs", [&](sqlite3_stmt* statement) {
                xref_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.source = read_address(statement, 1);
                record.target = read_address(statement, 5);
                record.kind = static_cast<xref_kind_t>(sqlite3_column_int(statement, 9));
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 10));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 11));
                loaded->xrefs.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,address_space,address_value,address_arch,address_mode,byte_length,encoding,value,provenance,confidence FROM " + slot_table(active_slot, "strings") + " ORDER BY address_value,entity_id",
            "workspace_database.load.strings", [&](sqlite3_stmt* statement) {
                string_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.address = read_address(statement, 1);
                record.byte_length = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 5));
                record.encoding = static_cast<string_encoding_t>(sqlite3_column_int(statement, 6));
                record.value = column_text(statement, 7);
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 8));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 9));
                loaded->strings.push_back(std::move(record));
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,address_space,address_value,address_arch,address_mode,name,kind,provenance,confidence FROM " + slot_table(active_slot, "symbols") + " ORDER BY address_value,name,entity_id",
            "workspace_database.load.symbols", [&](sqlite3_stmt* statement) {
                symbol_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.address = read_address(statement, 1);
                record.name = column_text(statement, 5);
                record.kind = static_cast<symbol_kind_t>(sqlite3_column_int(statement, 6));
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 7));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 8));
                loaded->symbols.push_back(std::move(record));
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,address_space,address_value,address_arch,address_mode,size,kind,target_space,target_value,target_arch,target_mode,provenance,confidence FROM " + slot_table(active_slot, "rich_data_candidates") + " ORDER BY entity_id",
            "workspace_database.load.rich_data_candidates", [&](sqlite3_stmt* statement) {
                data_candidate_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.address = read_address(statement, 1);
                record.size = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 5));
                record.kind = static_cast<data_candidate_kind_t>(sqlite3_column_int(statement, 6));
                record.target = read_optional_address(statement, 7);
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 11));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 12));
                loaded->rich_facts.data_candidates.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,slot_space,slot_value,slot_arch,slot_mode,target_space,target_value,target_arch,target_mode,candidate_kind,encoding,width_bytes,provenance,confidence FROM " + slot_table(active_slot, "data_pointer_facts") + " ORDER BY entity_id",
            "workspace_database.load.data_pointer_facts", [&](sqlite3_stmt* statement) {
                data_pointer_fact_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.slot = read_address(statement, 1);
                record.target = read_address(statement, 5);
                record.candidate_kind = static_cast<data_candidate_kind_t>(sqlite3_column_int(statement, 9));
                record.encoding = static_cast<data_pointer_encoding_t>(sqlite3_column_int(statement, 10));
                record.width_bytes = static_cast<std::uint8_t>(sqlite3_column_int(statement, 11));
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 12));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 13));
                loaded->rich_facts.data_pointer_facts.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,address_space,address_value,address_arch,address_mode,kind,selected_target_space,selected_target_value,selected_target_arch,selected_target_mode,rejected_target_space,rejected_target_value,rejected_target_arch,rejected_target_mode,selected_provenance,rejected_provenance,selected_confidence,rejected_confidence FROM " + slot_table(active_slot, "data_conflicts") + " ORDER BY entity_id",
            "workspace_database.load.data_conflicts", [&](sqlite3_stmt* statement) {
                data_candidate_conflict_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.address = read_address(statement, 1);
                record.kind = static_cast<data_candidate_kind_t>(sqlite3_column_int(statement, 5));
                record.selected_target = read_optional_address(statement, 6);
                record.rejected_target = read_optional_address(statement, 10);
                record.selected_provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 14));
                record.rejected_provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 15));
                record.selected_confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 16));
                record.rejected_confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 17));
                loaded->rich_facts.data_conflicts.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,address_space,address_value,address_arch,address_mode,related_space,related_value,related_arch,related_mode,kind,display_name,canonical_type,source_key,provenance,confidence,explicitly_unknown FROM " + slot_table(active_slot, "symbol_type_candidates") + " ORDER BY entity_id",
            "workspace_database.load.symbol_type_candidates", [&](sqlite3_stmt* statement) {
                symbol_type_candidate_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.address = read_optional_address(statement, 1);
                record.related_address = read_optional_address(statement, 5);
                record.kind = static_cast<symbol_type_candidate_kind_t>(sqlite3_column_int(statement, 9));
                record.display_name = column_text(statement, 10);
                record.canonical_type = column_text(statement, 11);
                record.source_key = column_text(statement, 12);
                record.provenance = static_cast<metadata_provenance_t>(sqlite3_column_int(statement, 13));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 14));
                record.explicitly_unknown = sqlite3_column_int(statement, 15) != 0;
                loaded->rich_facts.type_candidates.push_back(std::move(record));
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,source_space,source_value,source_arch,source_mode,target_space,target_value,target_arch,target_mode,source_entity,target_entity,kind,provenance,confidence,source_key FROM " + slot_table(active_slot, "type_references") + " ORDER BY entity_id",
            "workspace_database.load.type_references", [&](sqlite3_stmt* statement) {
                type_reference_fact_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.source = read_optional_address(statement, 1);
                record.target = read_optional_address(statement, 5);
                record.source_entity = static_cast<entity_id_t>(sqlite3_column_int64(statement, 9));
                record.target_entity = static_cast<entity_id_t>(sqlite3_column_int64(statement, 10));
                record.kind = static_cast<type_reference_kind_t>(sqlite3_column_int(statement, 11));
                record.provenance = static_cast<metadata_provenance_t>(sqlite3_column_int(statement, 12));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 13));
                record.source_key = column_text(statement, 14);
                loaded->rich_facts.type_references.push_back(std::move(record));
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,address_space,address_value,address_arch,address_mode,identity,kind,selected_value,rejected_value,selected_provenance,rejected_provenance,selected_confidence,rejected_confidence FROM " + slot_table(active_slot, "metadata_conflicts") + " ORDER BY entity_id",
            "workspace_database.load.metadata_conflicts", [&](sqlite3_stmt* statement) {
                metadata_conflict_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.address = read_optional_address(statement, 1);
                record.identity = column_text(statement, 5);
                record.kind = static_cast<metadata_conflict_kind_t>(sqlite3_column_int(statement, 6));
                record.selected_value = column_text(statement, 7);
                record.rejected_value = column_text(statement, 8);
                record.selected_provenance = static_cast<metadata_provenance_t>(sqlite3_column_int(statement, 9));
                record.rejected_provenance = static_cast<metadata_provenance_t>(sqlite3_column_int(statement, 10));
                record.selected_confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 11));
                record.rejected_confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 12));
                loaded->rich_facts.metadata_conflicts.push_back(std::move(record));
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT start_space,start_value,start_arch,start_mode,size,reason,provenance,confidence,detail_code FROM " + slot_table(active_slot, "coverage") + " ORDER BY start_value,span_id",
            "workspace_database.load.coverage", [&](sqlite3_stmt* statement) {
                coverage_span_t record;
                record.start = read_address(statement, 0);
                record.size = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 4));
                record.reason = static_cast<coverage_reason_t>(sqlite3_column_int(statement, 5));
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 6));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 7));
                record.detail_code = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 8));
                loaded->coverage.push_back(record);
                return workspace_result_t<void>::success();
            });
        return current;
    }, cancel);
    if (!result)
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(result.error());
    if (!found)
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::success({});
    auto validated = validate_analysis_snapshot(*loaded, loaded->baseline_complete, cancel);
    if (!validated)
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(validated.error());
    state_->persisted_generation.store(loaded->generation, std::memory_order_release);
    state_->persisted_analysis_revision.store(loaded->analysis_revision, std::memory_order_release);
    state_->persisted_overlay_revision.store(loaded->overlay_revision, std::memory_order_release);
    return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::success(
        std::shared_ptr<const analysis_snapshot_t>(std::move(loaded)));
}

workspace_result_t<persisted_search_products_t>
workspace_database_t::load_search_products(
    std::uint64_t expected_generation,
    std::uint64_t expected_analysis_revision,
    std::uint64_t expected_overlay_revision,
    const cancellation_token_t& cancel) const {
    persisted_search_products_t products;
    products.generation = expected_generation;
    products.analysis_revision = expected_analysis_revision;
    products.overlay_revision = expected_overlay_revision;
    auto result = with_reader([&](sqlite3* database) -> workspace_result_t<void> {
        auto commit_state = read_commit_state(database,
                                              "workspace_database.load_search");
        if (!commit_state)
            return workspace_result_t<void>::failure(commit_state.error());
        if (commit_state.value().committed_token.empty()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::target_not_found,
                "persisted analysis products are not available",
                "workspace_database.load_search"));
        }
        const std::uint8_t active_slot = commit_state.value().active_slot;
        statement_t state_statement;
        const std::string state_select = "SELECT generation,analysis_revision,overlay_revision,commit_token FROM " +
            slot_table(active_slot, "analysis_state") + " WHERE singleton=1";
        auto current = state_statement.prepare(database, state_select.c_str(),
            "workspace_database.load_search");
        if (!current) return current;
        int status = sqlite3_step(state_statement.get());
        if (status != SQLITE_ROW) {
            if (status == SQLITE_DONE) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::target_not_found,
                    "persisted analysis products are not available",
                    "workspace_database.load_search"));
            }
            return workspace_result_t<void>::failure(database_error(database, status,
                "unable to read persisted analysis product revision",
                "workspace_database.load_search"));
        }
        if (column_text(state_statement.get(), 3) !=
                commit_state.value().committed_token ||
            commit_state.value().committed_generation != expected_generation ||
            commit_state.value().committed_analysis_revision != expected_analysis_revision ||
            commit_state.value().committed_overlay_revision != expected_overlay_revision ||
            static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 0)) != expected_generation ||
            static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 1)) != expected_analysis_revision ||
            static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 2)) != expected_overlay_revision) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::stale_generation,
                "persisted analysis products do not match requested revisions",
                "workspace_database.load_search"));
        }

        std::uint64_t total_rows = 0;
        auto read_rows = [&](const std::string& sql, const char* phase, auto reader) -> workspace_result_t<void> {
            statement_t statement;
            auto prepared = statement.prepare(database, sql.c_str(), phase);
            if (!prepared) return prepared;
            std::size_t row = 0;
            for (;;) {
                if ((row++ & 255U) == 0 && cancel.stop_requested()) {
                    auto error = make_workspace_error(cancel.deadline_exceeded()
                                                          ? workspace_error_code_t::deadline_exceeded
                                                          : workspace_error_code_t::cancelled,
                                                      "search product reopen cancelled", phase);
                    error.deadline = cancel.deadline_exceeded();
                    error.cancellation = !error.deadline;
                    return workspace_result_t<void>::failure(std::move(error));
                }
                const int step_status = sqlite3_step(statement.get());
                if (step_status == SQLITE_DONE)
                    return workspace_result_t<void>::success();
                if (step_status != SQLITE_ROW)
                    return workspace_result_t<void>::failure(database_error(database, step_status,
                        "unable to read search product row", phase));
                if (++total_rows > options_.max_persisted_fact_records) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::limit_exceeded,
                        "persisted search rows exceed the reopen budget", phase));
                }
                auto row_result = reader(statement.get());
                if (!row_result) return row_result;
            }
        };

        current = read_rows("SELECT entity_id,address_space,address_value,address_arch,address_mode,size,kind,target_space,target_value,target_arch,target_mode,provenance,confidence FROM " + slot_table(active_slot, "data_candidates") + " ORDER BY address_value,entity_id",
            "workspace_database.load_search.data", [&](sqlite3_stmt* statement) {
                data_candidate_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.address = read_address(statement, 1);
                record.size = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 5));
                record.kind = static_cast<data_candidate_kind_t>(sqlite3_column_int(statement, 6));
                if (sqlite3_column_type(statement, 7) != SQLITE_NULL)
                    record.target = read_address(statement, 7);
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 11));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 12));
                products.data_candidates.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,function_id,dispatch_space,dispatch_value,dispatch_arch,dispatch_mode,table_space,table_value,table_arch,table_mode,default_space,default_value,default_arch,default_mode,entry_size,relative_entries,provenance,confidence FROM " + slot_table(active_slot, "switches") + " ORDER BY dispatch_value,entity_id",
            "workspace_database.load_search.switches", [&](sqlite3_stmt* statement) {
                switch_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
                record.dispatch = read_address(statement, 2);
                record.table = read_address(statement, 6);
                if (sqlite3_column_type(statement, 10) != SQLITE_NULL)
                    record.default_target = read_address(statement, 10);
                record.entry_size = static_cast<std::uint8_t>(sqlite3_column_int(statement, 14));
                record.relative_entries = sqlite3_column_int(statement, 15) != 0;
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 16));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 17));
                products.switches.push_back(std::move(record));
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        std::unordered_map<entity_id_t, std::size_t> switch_indexes;
        for (std::size_t index = 0; index < products.switches.size(); ++index)
            switch_indexes.emplace(products.switches[index].id, index);
        current = read_rows("SELECT switch_id,target_space,target_value,target_arch,target_mode FROM " + slot_table(active_slot, "switch_cases") + " ORDER BY switch_id,case_index",
            "workspace_database.load_search.switch_cases", [&](sqlite3_stmt* statement) {
                const entity_id_t switch_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                auto found = switch_indexes.find(switch_id);
                if (found == switch_indexes.end()) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "switch case references a missing switch",
                        "workspace_database.load_search.switch_cases"));
                }
                products.switches[found->second].case_targets.push_back(read_address(statement, 1));
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,address_space,address_value,address_arch,address_mode,kind,display_name,canonical_type,provenance,confidence,explicitly_unknown FROM " + slot_table(active_slot, "type_candidates") + " ORDER BY address_value,entity_id",
            "workspace_database.load_search.types", [&](sqlite3_stmt* statement) {
                type_candidate_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.address = read_address(statement, 1);
                record.kind = static_cast<type_candidate_kind_t>(sqlite3_column_int(statement, 5));
                record.display_name = column_text(statement, 6);
                record.canonical_type = column_text(statement, 7);
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 8));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 9));
                record.explicitly_unknown = sqlite3_column_int(statement, 10) != 0;
                products.types.push_back(std::move(record));
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        statement_t blob_statement;
        const std::string blob_select = "SELECT generation,analysis_revision,overlay_revision,blob_version,length(payload),payload FROM " +
            slot_table(active_slot, "search_index_blob") + " WHERE singleton=1";
        current = blob_statement.prepare(database, blob_select.c_str(),
            "workspace_database.load_search.blob");
        if (!current) return current;
        status = sqlite3_step(blob_statement.get());
        if (status == SQLITE_ROW) {
            if (static_cast<std::uint64_t>(sqlite3_column_int64(blob_statement.get(), 0)) != expected_generation ||
                static_cast<std::uint64_t>(sqlite3_column_int64(blob_statement.get(), 1)) != expected_analysis_revision ||
                static_cast<std::uint64_t>(sqlite3_column_int64(blob_statement.get(), 2)) != expected_overlay_revision) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::stale_generation,
                    "persisted search index blob revision is stale",
                    "workspace_database.load_search.blob"));
            }
            products.search_index_blob_version = static_cast<std::uint32_t>(sqlite3_column_int(blob_statement.get(), 3));
            const auto declared_bytes = sqlite3_column_int64(blob_statement.get(), 4);
            if (declared_bytes < 0 ||
                static_cast<std::uint64_t>(declared_bytes) > workspace_search_blob_limit) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "persisted search index blob exceeds its reopen budget",
                    "workspace_database.load_search.blob"));
            }
            const void* payload = sqlite3_column_blob(blob_statement.get(), 5);
            const int bytes = sqlite3_column_bytes(blob_statement.get(), 5);
            if (bytes < 0 || bytes != declared_bytes || (bytes > 0 && !payload)) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "persisted search index blob is malformed",
                    "workspace_database.load_search.blob"));
            }
            if (bytes > 0) {
                if (cancel.stop_requested()) {
                    auto error = make_workspace_error(
                        cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                                   : workspace_error_code_t::cancelled,
                        "search index blob read was cancelled",
                        "workspace_database.load_search.blob");
                    error.deadline = cancel.deadline_exceeded();
                    error.cancellation = !error.deadline;
                    return workspace_result_t<void>::failure(std::move(error));
                }
                auto copied = copy_blob_cancellable(
                    products.search_index_blob, payload,
                    static_cast<std::size_t>(bytes), cancel,
                    "workspace_database.load_search.blob");
                if (!copied)
                    return copied;
            }
        } else if (status != SQLITE_DONE) {
            return workspace_result_t<void>::failure(database_error(database, status,
                "unable to read search index blob", "workspace_database.load_search.blob"));
        }
        return workspace_result_t<void>::success();
    }, cancel);
    if (!result)
        return workspace_result_t<persisted_search_products_t>::failure(result.error());
    return workspace_result_t<persisted_search_products_t>::success(std::move(products));
}

persistence_ticket_t workspace_database_t::store_decompiler_cache(
    decompiler_cache_record_t record, cancellation_token_t cancel) {
    if (record.key.engine_version.size() > 65536 ||
        record.key.specification_version.size() > 65536 ||
        record.key.analysis_settings_hash.size() > 65536 ||
        record.function_name.size() > 4096 || record.result_json.empty() ||
        record.result_json.size() > workspace_decompiler_cache_record_limit ||
        record.result_bytes != record.result_json.size()) {
        return queue_->enqueue("analysis.persistence.decompiler_cache.invalid",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "decompiler cache record exceeds its integrity or size limits",
                    "workspace_database.decompiler_cache"));
            }, std::move(cancel));
    }
    const auto canonical = record.key.canonical();
    if (canonical.empty() || canonical.size() > 16384) {
        return queue_->enqueue("analysis.persistence.decompiler_cache.invalid_key",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "decompiler cache canonical key exceeds its size limit",
                    "workspace_database.decompiler_cache"));
            }, std::move(cancel));
    }
    return enqueue_write("analysis.persistence.decompiler_cache.store",
        [record = std::move(record), canonical](sqlite3* database,
                                               const cancellation_token_t& token) {
            if (token.stop_requested()) {
                auto error = make_workspace_error(token.deadline_exceeded()
                                                      ? workspace_error_code_t::deadline_exceeded
                                                      : workspace_error_code_t::cancelled,
                                                  "decompiler cache write cancelled",
                                                  "workspace_database.decompiler_cache");
                error.deadline = token.deadline_exceeded();
                error.cancellation = !error.deadline;
                return workspace_result_t<void>::failure(std::move(error));
            }
            decompiler_cache_v9_record_t persisted;
            persisted.cache_key = canonical;
            persisted.binary_id = record.key.binary_id;
            persisted.format = record.key.format;
            persisted.architecture = record.key.architecture;
            persisted.architecture_mode = record.key.architecture_mode;
            persisted.abi = record.key.abi;
            persisted.endian = record.key.endian;
            persisted.engine_version = record.key.engine_version;
            persisted.schema_version = record.key.schema_version;
            persisted.specification_version = record.key.specification_version;
            persisted.settings_hash = record.key.analysis_settings_hash;
            persisted.function_id = record.key.function_id;
            persisted.function_rva = record.key.function_rva;
            persisted.function_rva_address = {
                address_space_id_t::relative_virtual,
                record.key.function_rva,
                record.key.architecture,
                record.key.architecture_mode};
            persisted.function_content_hash = record.key.function_content_hash;
            persisted.analysis_revision = record.key.analysis_revision;
            persisted.overlay_revision = record.key.overlay_revision;
            persisted.generation = record.key.generation;
            persisted.function_name = record.function_name;
            persisted.result_json = record.result_json;
            persisted.created_utc_ms = record.created_utc_ms;
            persisted.last_access_utc_ms = record.last_access_utc_ms;
            persisted.result_bytes = record.result_bytes;
            persisted.cache_key_version = decompiler_cache_v9_key_version;
            return write_decompiler_cache_v9(database, persisted);
        }, std::move(cancel));
}

workspace_result_t<std::optional<decompiler_cache_record_t>>
workspace_database_t::load_decompiler_cache(const decompiler_cache_key_t& key,
                                            const cancellation_token_t& cancel) const {
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(cancel.deadline_exceeded()
                                              ? workspace_error_code_t::deadline_exceeded
                                              : workspace_error_code_t::cancelled,
                                          "decompiler cache read cancelled",
                                          "workspace_database.decompiler_cache");
        return workspace_result_t<std::optional<decompiler_cache_record_t>>::failure(std::move(error));
    }
    if (key.engine_version.size() > 65536 ||
        key.specification_version.size() > 65536 ||
        key.analysis_settings_hash.size() > 65536) {
        return workspace_result_t<std::optional<decompiler_cache_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "decompiler cache lookup metadata exceeds its size limit",
                                 "workspace_database.decompiler_cache"));
    }
    std::optional<decompiler_cache_record_t> record;
    const std::string canonical = key.canonical();
    if (canonical.empty() || canonical.size() > 16384) {
        return workspace_result_t<std::optional<decompiler_cache_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "decompiler cache lookup key exceeds its size limit",
                                 "workspace_database.decompiler_cache"));
    }
    auto result = with_reader([&](sqlite3* database) {
        auto persisted = read_decompiler_cache_v9(database, canonical);
        if (!persisted)
            return workspace_result_t<void>::failure(persisted.error());
        if (!persisted.value())
            return workspace_result_t<void>::success();
        const auto& stored = *persisted.value();
        const bool key_matches =
            stored.binary_id == key.binary_id &&
            stored.format == key.format &&
            stored.architecture == key.architecture &&
            stored.architecture_mode == key.architecture_mode &&
            stored.abi == key.abi && stored.endian == key.endian &&
            stored.engine_version == key.engine_version &&
            stored.schema_version == key.schema_version &&
            stored.specification_version == key.specification_version &&
            stored.settings_hash == key.analysis_settings_hash &&
            stored.function_id == key.function_id &&
            stored.function_rva == key.function_rva &&
            stored.function_rva_address.space == address_space_id_t::relative_virtual &&
            stored.function_rva_address.value == key.function_rva &&
            stored.function_rva_address.architecture == key.architecture &&
            stored.function_rva_address.mode == key.architecture_mode &&
            stored.function_content_hash == key.function_content_hash &&
            stored.analysis_revision == key.analysis_revision &&
            stored.overlay_revision == key.overlay_revision &&
            stored.generation == key.generation &&
            stored.cache_key_version == decompiler_cache_v9_key_version;
        if (!key_matches) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "persisted decompiler cache key metadata is inconsistent",
                "workspace_database.decompiler_cache"));
        }
        decompiler_cache_record_t found;
        found.key = key;
        found.function_name = stored.function_name;
        found.result_json = stored.result_json;
        found.created_utc_ms = stored.created_utc_ms;
        found.last_access_utc_ms = stored.last_access_utc_ms;
        found.result_bytes = stored.result_bytes;
        record = std::move(found);
        return workspace_result_t<void>::success();
    }, cancel);
    if (!result)
        return workspace_result_t<std::optional<decompiler_cache_record_t>>::failure(result.error());
    return workspace_result_t<std::optional<decompiler_cache_record_t>>::success(std::move(record));
}

persistence_ticket_t workspace_database_t::invalidate_decompiler_cache(
    std::optional<std::uint64_t> function_rva,
    std::optional<std::uint64_t> minimum_overlay_revision,
    cancellation_token_t cancel) {
    auto state = state_;
    return enqueue_write("analysis.persistence.decompiler_cache.invalidate",
        [state, function_rva, minimum_overlay_revision](sqlite3* database,
                                                       const cancellation_token_t&) {
            std::string sql = "DELETE FROM decompiler_cache_v9 WHERE 1=1";
            if (function_rva) sql += " AND function_rva=?1";
            if (minimum_overlay_revision) sql += function_rva
                ? " AND overlay_revision>=?2" : " AND overlay_revision>=?1";
            statement_t statement;
            auto result = statement.prepare(database, sql.c_str(),
                                            "workspace_database.decompiler_cache");
            if (!result) return result;
            int index = 1;
            if (function_rva) { result = statement.bind_uint(index++, *function_rva); if (!result) return result; }
            if (minimum_overlay_revision) { result = statement.bind_uint(index, *minimum_overlay_revision); if (!result) return result; }
            result = statement.step_done();
            if (result)
                state->cache_invalidations.fetch_add(1, std::memory_order_acq_rel);
            return result;
        }, std::move(cancel));
}

persistence_ticket_t workspace_database_t::publish_packed_generation(
    packed_generation_publication_t publication,
    cancellation_token_t cancel) {
    auto state = state_;
    return enqueue_write("analysis.persistence.packed_generation.publish",
        [state, publication = std::move(publication)](
            sqlite3* database, const cancellation_token_t& token) {
            return publish_packed_generation_atomic(database, publication,
                [&state, &token] {
                    return token.stop_requested() ||
                           !state->open.load(std::memory_order_acquire);
                });
        }, std::move(cancel));
}

workspace_result_t<std::optional<packed_generation_publication_t>>
workspace_database_t::load_packed_generation(
    std::uint64_t generation, const cancellation_token_t& cancel) const {
    if (generation == 0) {
        return workspace_result_t<std::optional<packed_generation_publication_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "packed generation must be non-zero",
                                 "workspace_database.packed_generation.read"));
    }
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "packed generation read was cancelled",
            "workspace_database.packed_generation.read");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<std::optional<packed_generation_publication_t>>::failure(
            std::move(error));
    }
    std::optional<packed_generation_publication_t> publication;
    auto result = with_reader([&](sqlite3* database) {
        auto read = read_packed_generation_publication(database, generation,
            [&] {
                return cancel.stop_requested() ||
                       !state_->open.load(std::memory_order_acquire);
            });
        if (!read)
            return workspace_result_t<void>::failure(read.error());
        publication = read.take_value();
        return workspace_result_t<void>::success();
    }, cancel);
    if (!result)
        return workspace_result_t<std::optional<packed_generation_publication_t>>::failure(
            result.error());
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "packed generation read was cancelled",
            "workspace_database.packed_generation.read");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<std::optional<packed_generation_publication_t>>::failure(
            std::move(error));
    }
    return workspace_result_t<std::optional<packed_generation_publication_t>>::success(
        std::move(publication));
}

persistence_ticket_t workspace_database_t::store_workbench_state(
    workbench_state_record_t record, cancellation_token_t cancel) {
    return enqueue_write("analysis.persistence.workbench.store",
        [record = std::move(record)](sqlite3* database,
                                     const cancellation_token_t& token) {
            if (token.stop_requested()) {
                auto error = make_workspace_error(
                    token.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                              : workspace_error_code_t::cancelled,
                    "workbench state write was cancelled",
                    "workspace_database.workbench.store");
                error.deadline = token.deadline_exceeded();
                error.cancellation = !error.deadline;
                return workspace_result_t<void>::failure(std::move(error));
            }
            return write_workbench_state(database, record);
        }, std::move(cancel));
}

workspace_result_t<std::optional<workbench_state_record_t>>
workspace_database_t::load_workbench_state(
    const cancellation_token_t& cancel) const {
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "workbench state read was cancelled",
            "workspace_database.workbench.read");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<std::optional<workbench_state_record_t>>::failure(
            std::move(error));
    }
    std::optional<workbench_state_record_t> record;
    auto result = with_reader([&](sqlite3* database) {
        auto read = read_workbench_state(database);
        if (!read)
            return workspace_result_t<void>::failure(read.error());
        record = read.take_value();
        return workspace_result_t<void>::success();
    }, cancel);
    if (!result)
        return workspace_result_t<std::optional<workbench_state_record_t>>::failure(
            result.error());
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "workbench state read was cancelled",
            "workspace_database.workbench.read");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<std::optional<workbench_state_record_t>>::failure(
            std::move(error));
    }
    return workspace_result_t<std::optional<workbench_state_record_t>>::success(
        std::move(record));
}

persistence_ticket_t workspace_database_t::checkpoint(bool truncate,
                                                       cancellation_token_t cancel) {
    return enqueue_write("analysis.persistence.checkpoint",
        [truncate](sqlite3* database, const cancellation_token_t&) {
            int log_frames = 0;
            int checkpointed_frames = 0;
            const int status = sqlite3_wal_checkpoint_v2(database, "main",
                truncate ? SQLITE_CHECKPOINT_TRUNCATE : SQLITE_CHECKPOINT_PASSIVE,
                &log_frames, &checkpointed_frames);
            if (status == SQLITE_OK || (!truncate && status == SQLITE_BUSY))
                return workspace_result_t<void>::success();
            return workspace_result_t<void>::failure(database_error(database, status,
                "WAL checkpoint failed", "workspace_database.checkpoint"));
        }, std::move(cancel));
}

workspace_database_snapshot_t workspace_database_t::snapshot() const {
    workspace_database_snapshot_t result;
    result.path = state_->path;
    result.schema_version = workspace_database_schema_version;
    result.persisted_generation = state_->persisted_generation.load(std::memory_order_acquire);
    result.persisted_analysis_revision = state_->persisted_analysis_revision.load(std::memory_order_acquire);
    result.persisted_overlay_revision = state_->persisted_overlay_revision.load(std::memory_order_acquire);
    result.cache_invalidations = state_->cache_invalidations.load(std::memory_order_acquire);
    result.last_commit_logical_bytes = state_->last_commit_logical_bytes.load(std::memory_order_acquire);
    result.cumulative_logical_bytes = state_->cumulative_logical_bytes.load(std::memory_order_acquire);
    result.last_commit_rows = state_->last_commit_rows.load(std::memory_order_acquire);
    result.cumulative_rows = state_->cumulative_rows.load(std::memory_order_acquire);
    result.last_commit_page_write_bytes = state_->last_commit_page_write_bytes.load(std::memory_order_acquire);
    result.cumulative_page_write_bytes = state_->cumulative_page_write_bytes.load(std::memory_order_acquire);
    result.last_commit_elapsed_us = state_->last_commit_elapsed_us.load(std::memory_order_acquire);
    result.candidate_generation = state_->candidate_generation.load(std::memory_order_acquire);
    result.candidate_analysis_revision = state_->candidate_analysis_revision.load(std::memory_order_acquire);
    result.candidate_overlay_revision = state_->candidate_overlay_revision.load(std::memory_order_acquire);
    result.candidate_pending = state_->candidate_pending.load(std::memory_order_acquire);
    result.open = state_->open.load(std::memory_order_acquire);
    std::error_code error;
    result.database_bytes = std::filesystem::file_size(std::filesystem::u8path(state_->path), error);
    if (error) result.database_bytes = 0;
    error.clear();
    result.wal_bytes = std::filesystem::file_size(std::filesystem::u8path(state_->path + "-wal"), error);
    if (error) result.wal_bytes = 0;
    return result;
}

void workspace_database_t::request_cancel() noexcept {
    auto state = state_;
    if (state) {
        state->open.store(false, std::memory_order_release);
        try {
            std::lock_guard<std::mutex> close_lock(state->close_mutex);
            if (state->writer)
                sqlite3_interrupt(state->writer);
        } catch (...) {
        }
    }
    if (queue_)
        queue_->request_cancel();
}

workspace_result_t<void>
workspace_database_t::drain(std::chrono::steady_clock::time_point deadline) {
    if (queue_) {
        auto result = queue_->drain(deadline);
        if (!result) return result;
    }
    std::lock_guard<std::mutex> lock(state_->close_mutex);
    std::lock_guard<std::timed_mutex> writer_lock(state_->writer_mutex);
    if (state_->writer) {
        const int checkpoint_status = sqlite3_wal_checkpoint_v2(
            state_->writer, "main", SQLITE_CHECKPOINT_PASSIVE, nullptr, nullptr);
        if (checkpoint_status != SQLITE_OK && checkpoint_status != SQLITE_BUSY) {
            return workspace_result_t<void>::failure(database_error(state_->writer,
                checkpoint_status, "final passive WAL checkpoint failed",
                "workspace_database.close"));
        }
        const int close_status = sqlite3_close_v2(state_->writer);
        if (close_status != SQLITE_OK) {
            return workspace_result_t<void>::failure(database_error(state_->writer,
                close_status, "workspace database close failed", "workspace_database.close"));
        }
        state_->writer = nullptr;
        state_->open.store(false, std::memory_order_release);
    }
    return workspace_result_t<void>::success();
}

}
