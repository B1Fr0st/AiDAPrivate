#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include "session_store.hpp"

#include <windows.h>
#include <shlobj.h>
#include <bcrypt.h>

#include <filesystem>
#include <chrono>
#include <mutex>
#include <atomic>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <charconv>
#include <iterator>
#include <limits>

#include <sqlite3.h>

#include "event_bus.hpp"
#include "../../helpers/diag_log.hpp"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Shell32.lib")


namespace aida::session {


namespace {


std::mutex   g_error_mutex;
std::string  g_last_error;
std::atomic<sqlite3*> g_db{ nullptr };
std::mutex   g_init_mutex;
std::recursive_mutex g_store_mutex;
std::atomic<bool> g_initialized{ false };


void set_last_error(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(g_error_mutex);
    g_last_error = msg;
}


void set_last_error_sqlite(sqlite3* db, const std::string& prefix)
{
    const char* m = db ? sqlite3_errmsg(db) : "no database";
    std::lock_guard<std::mutex> lk(g_error_mutex);
    g_last_error = prefix + ": " + (m ? m : "unknown");
}


int64_t now_unix_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}


bool generate_random_hex(char* out, size_t hex_chars)
{
    if (hex_chars == 0 || (hex_chars & 1u) != 0u) return false;
    const size_t bytes = hex_chars / 2u;
    std::vector<unsigned char> buf(bytes, 0);
    NTSTATUS st = BCryptGenRandom(nullptr,
                                  buf.data(),
                                  static_cast<ULONG>(bytes),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) {
        const auto t = std::chrono::steady_clock::now().time_since_epoch().count();
        for (size_t i = 0; i < bytes; ++i) {
            buf[i] = static_cast<unsigned char>((t >> ((i % 8u) * 8u)) ^ (i * 31u));
        }
    }
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < bytes; ++i) {
        out[i * 2u]      = hex[(buf[i] >> 4) & 0xFu];
        out[i * 2u + 1u] = hex[buf[i] & 0xFu];
    }
    out[hex_chars] = '\0';
    return true;
}


std::string generate_id_32()
{
    char hex[33] = {};
    generate_random_hex(hex, 32);
    return hex;
}


std::string generate_suffix_4()
{
    char hex[5] = {};
    generate_random_hex(hex, 4);
    return hex;
}


std::filesystem::path resolve_database_path()
{
    wchar_t* appdata = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
        auto dir = std::filesystem::path(appdata) / L"AiDA";
        CoTaskMemFree(appdata);
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        return dir / L"sessions.db";
    }
    auto fallback = std::filesystem::current_path() / "aida_sessions.db";
    return fallback;
}


std::string slugify_ascii(const std::string& src, size_t max_len)
{
    std::string out;
    out.reserve(src.size());
    bool prev_dash = true;
    for (char c : src) {
        unsigned char uc = static_cast<unsigned char>(c);
        char low = static_cast<char>(std::tolower(uc));
        if ((low >= 'a' && low <= 'z') || (low >= '0' && low <= '9')) {
            out.push_back(low);
            prev_dash = false;
        }
        else if (!prev_dash && !out.empty()) {
            out.push_back('-');
            prev_dash = true;
        }
        if (out.size() >= max_len) break;
    }
    while (!out.empty() && out.back() == '-') out.pop_back();
    return out;
}


std::string make_slug(const std::string& title)
{
    std::string base = slugify_ascii(title, 48u);
    if (base.empty()) {
        char hex[9] = {};
        generate_random_hex(hex, 8);
        return std::string("untitled-") + hex;
    }
    return base + "-" + generate_suffix_4();
}


std::string role_to_string(message_t::role_t r)
{
    switch (r) {
        case message_t::role_t::user:        return "user";
        case message_t::role_t::assistant:   return "assistant";
        case message_t::role_t::tool_result: return "tool_result";
    }
    return "user";
}


message_t::role_t role_from_string(const std::string& s)
{
    if (s == "assistant")   return message_t::role_t::assistant;
    if (s == "tool_result") return message_t::role_t::tool_result;
    return message_t::role_t::user;
}


std::string tool_state_to_string(part_tool_t::state_t s)
{
    switch (s) {
        case part_tool_t::state_t::pending:   return "pending";
        case part_tool_t::state_t::running:   return "running";
        case part_tool_t::state_t::completed: return "completed";
        case part_tool_t::state_t::error:     return "error";
    }
    return "pending";
}


part_tool_t::state_t tool_state_from_string(const std::string& s)
{
    if (s == "running")   return part_tool_t::state_t::running;
    if (s == "completed") return part_tool_t::state_t::completed;
    if (s == "error")     return part_tool_t::state_t::error;
    return part_tool_t::state_t::pending;
}


std::string part_kind_to_string(part_t::kind_t k)
{
    switch (k) {
        case part_t::kind_t::text:        return "text";
        case part_t::kind_t::tool:        return "tool";
        case part_t::kind_t::compaction:  return "compaction";
        case part_t::kind_t::reasoning:   return "reasoning";
        case part_t::kind_t::step_finish: return "step_finish";
        case part_t::kind_t::file:        return "file";
        case part_t::kind_t::step_start:  return "step_start";
    }
    return "text";
}


part_t::kind_t part_kind_from_string(const std::string& s)
{
    if (s == "tool")        return part_t::kind_t::tool;
    if (s == "compaction")  return part_t::kind_t::compaction;
    if (s == "reasoning")   return part_t::kind_t::reasoning;
    if (s == "step_finish") return part_t::kind_t::step_finish;
    if (s == "file")        return part_t::kind_t::file;
    if (s == "step_start" || s == "step-start") return part_t::kind_t::step_start;
    return part_t::kind_t::text;
}


nlohmann::json serialize_part(const part_t& p)
{
    nlohmann::json j = nlohmann::json::object();
    switch (p.kind) {
        case part_t::kind_t::text: {
            j["text"] = p.text.text;
            j["synthetic"] = p.text.synthetic;
            break;
        }
        case part_t::kind_t::tool: {
            j["call_id"]         = p.tool.call_id;
            j["tool_name"]       = p.tool.tool_name;
            j["state"]           = tool_state_to_string(p.tool.state);
            j["arguments"]       = p.tool.arguments;
            j["output_text"]     = p.tool.output_text;
            j["metadata"]        = p.tool.metadata;
            j["error_message"]   = p.tool.error_message;
            j["time_start_unix"] = p.tool.time_start_unix;
            j["time_end_unix"]   = p.tool.time_end_unix;
            break;
        }
        case part_t::kind_t::compaction: {
            j["summary_text"]          = p.compaction.summary_text;
            j["auto_triggered"]        = p.compaction.auto_triggered;
            j["overflow"]              = p.compaction.overflow;
            j["tail_start_message_id"] = p.compaction.tail_start_message_id;
            break;
        }
        case part_t::kind_t::reasoning: {
            j["text"]            = p.reasoning.text;
            j["time_start_unix"] = p.reasoning.time_start_unix;
            j["time_end_unix"]   = p.reasoning.time_end_unix;
            break;
        }
        case part_t::kind_t::step_finish: {
            j["cost_usd"]      = p.step_finish.cost_usd;
            j["finish_reason"] = p.step_finish.finish_reason;
            nlohmann::json tk = nlohmann::json::object();
            tk["input"]       = p.step_finish.tokens.input;
            tk["output"]      = p.step_finish.tokens.output;
            tk["reasoning"]   = p.step_finish.tokens.reasoning;
            tk["cache_read"]  = p.step_finish.tokens.cache_read;
            tk["cache_write"] = p.step_finish.tokens.cache_write;
            j["tokens"] = std::move(tk);
            break;
        }
        case part_t::kind_t::file: {
            j["mime"]            = p.file.mime;
            j["filename"]        = p.file.filename;
            j["url"]             = p.file.url;
            j["source_metadata"] = p.file.source_metadata.is_null()
                                       ? nlohmann::json::object()
                                       : p.file.source_metadata;
            break;
        }
        case part_t::kind_t::step_start: {
            j["snapshot_id"] = p.step_start.snapshot_id;
            j["agent"]       = p.step_start.agent;
            j["provider_id"] = p.step_start.provider_id;
            j["model_id"]    = p.step_start.model_id;
            break;
        }
    }
    return j;
}


part_t deserialize_part(const std::string& kind, const nlohmann::json& j)
{
    part_t p;
    p.kind = part_kind_from_string(kind);
    switch (p.kind) {
        case part_t::kind_t::text: {
            p.text.text      = j.value("text", std::string());
            p.text.synthetic = j.value("synthetic", false);
            break;
        }
        case part_t::kind_t::tool: {
            p.tool.call_id         = j.value("call_id", std::string());
            p.tool.tool_name       = j.value("tool_name", std::string());
            p.tool.state           = tool_state_from_string(j.value("state", std::string("pending")));
            p.tool.arguments       = j.value("arguments", nlohmann::json::object());
            p.tool.output_text     = j.value("output_text", std::string());
            p.tool.metadata        = j.value("metadata", nlohmann::json::object());
            p.tool.error_message   = j.value("error_message", std::string());
            p.tool.time_start_unix = j.value("time_start_unix", static_cast<int64_t>(0));
            p.tool.time_end_unix   = j.value("time_end_unix", static_cast<int64_t>(0));
            break;
        }
        case part_t::kind_t::compaction: {
            p.compaction.summary_text          = j.value("summary_text", std::string());
            p.compaction.auto_triggered        = j.value("auto_triggered", false);
            p.compaction.overflow              = j.value("overflow", false);
            p.compaction.tail_start_message_id = j.value("tail_start_message_id", std::string());
            break;
        }
        case part_t::kind_t::reasoning: {
            p.reasoning.text            = j.value("text", std::string());
            p.reasoning.time_start_unix = j.value("time_start_unix", static_cast<int64_t>(0));
            p.reasoning.time_end_unix   = j.value("time_end_unix", static_cast<int64_t>(0));
            break;
        }
        case part_t::kind_t::step_finish: {
            p.step_finish.cost_usd      = j.value("cost_usd", 0.0);
            p.step_finish.finish_reason = j.value("finish_reason", std::string());
            const auto tk = j.value("tokens", nlohmann::json::object());
            p.step_finish.tokens.input       = tk.value("input", static_cast<int64_t>(0));
            p.step_finish.tokens.output      = tk.value("output", static_cast<int64_t>(0));
            p.step_finish.tokens.reasoning   = tk.value("reasoning", static_cast<int64_t>(0));
            p.step_finish.tokens.cache_read  = tk.value("cache_read", static_cast<int64_t>(0));
            p.step_finish.tokens.cache_write = tk.value("cache_write", static_cast<int64_t>(0));
            break;
        }
        case part_t::kind_t::file: {
            p.file.mime            = j.value("mime", std::string());
            p.file.filename        = j.value("filename", std::string());
            p.file.url             = j.value("url", std::string());
            p.file.source_metadata = j.value("source_metadata", nlohmann::json::object());
            break;
        }
        case part_t::kind_t::step_start: {
            p.step_start.snapshot_id = j.value("snapshot_id", std::string());
            p.step_start.agent       = j.value("agent", std::string());
            p.step_start.provider_id = j.value("provider_id", std::string());
            p.step_start.model_id    = j.value("model_id", std::string());
            break;
        }
    }
    return p;
}


bool exec_simple(sqlite3* db, const char* sql)
{
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string e = err ? err : "exec failed";
        if (err) sqlite3_free(err);
        set_last_error(std::string("sqlite_exec: ") + e);
        return false;
    }
    return true;
}


bool bind_text(sqlite3_stmt* stmt, int idx, const std::string& s)
{
    return sqlite3_bind_text(stmt, idx, s.c_str(), static_cast<int>(s.size()), SQLITE_TRANSIENT) == SQLITE_OK;
}


bool bind_text_or_null(sqlite3_stmt* stmt, int idx, const std::string& s)
{
    if (s.empty()) {
        return sqlite3_bind_null(stmt, idx) == SQLITE_OK;
    }
    return bind_text(stmt, idx, s);
}


bool bind_int64(sqlite3_stmt* stmt, int idx, int64_t v)
{
    return sqlite3_bind_int64(stmt, idx, v) == SQLITE_OK;
}


bool bind_int64_or_null(sqlite3_stmt* stmt, int idx, int64_t v)
{
    if (v == 0) {
        return sqlite3_bind_null(stmt, idx) == SQLITE_OK;
    }
    return sqlite3_bind_int64(stmt, idx, v) == SQLITE_OK;
}


bool bind_double(sqlite3_stmt* stmt, int idx, double v)
{
    return sqlite3_bind_double(stmt, idx, v) == SQLITE_OK;
}


bool bind_int(sqlite3_stmt* stmt, int idx, int v)
{
    return sqlite3_bind_int(stmt, idx, v) == SQLITE_OK;
}


std::string column_text_or_empty(sqlite3_stmt* stmt, int col)
{
    if (sqlite3_column_type(stmt, col) == SQLITE_NULL) return std::string();
    const unsigned char* p = sqlite3_column_text(stmt, col);
    int n = sqlite3_column_bytes(stmt, col);
    if (!p || n <= 0) return std::string();
    return std::string(reinterpret_cast<const char*>(p), static_cast<size_t>(n));
}


int64_t column_int64_or_zero(sqlite3_stmt* stmt, int col)
{
    if (sqlite3_column_type(stmt, col) == SQLITE_NULL) return 0;
    return sqlite3_column_int64(stmt, col);
}


std::uint64_t column_uint64_text_or_zero(sqlite3_stmt* stmt, int col)
{
    const std::string text = column_text_or_empty(stmt, col);
    if (text.empty()) return 0;
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size()
        ? value : 0;
}

bool uint64_text_column_valid(sqlite3_stmt* stmt, int col)
{
    if (sqlite3_column_type(stmt, col) != SQLITE_TEXT) return false;
    const std::string text = column_text_or_empty(stmt, col);
    if (text.empty() || text.size() > 20U) return false;
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}


nlohmann::json column_json_or_empty(sqlite3_stmt* stmt, int col)
{
    if (sqlite3_column_type(stmt, col) == SQLITE_NULL) return nlohmann::json();
    const std::string txt = column_text_or_empty(stmt, col);
    if (txt.empty()) return nlohmann::json();
    auto parsed = nlohmann::json::parse(txt, nullptr, false);
    if (parsed.is_discarded()) return nlohmann::json();
    return parsed;
}


void hydrate_session_from_row(sqlite3_stmt* stmt, session_info_t& out)
{
    out.id                   = column_text_or_empty(stmt, 0);
    out.slug                 = column_text_or_empty(stmt, 1);
    out.project_id           = column_text_or_empty(stmt, 2);
    out.parent_id            = column_text_or_empty(stmt, 3);
    out.binary_path          = column_text_or_empty(stmt, 4);
    out.directory            = column_text_or_empty(stmt, 5);
    out.title                = column_text_or_empty(stmt, 6);
    out.version              = static_cast<int>(column_int64_or_zero(stmt, 7));
    out.summary.additions    = static_cast<int>(column_int64_or_zero(stmt, 8));
    out.summary.deletions    = static_cast<int>(column_int64_or_zero(stmt, 9));
    out.summary.files        = static_cast<int>(column_int64_or_zero(stmt, 10));
    out.time_created_unix    = column_int64_or_zero(stmt, 11);
    out.time_updated_unix    = column_int64_or_zero(stmt, 12);
    out.time_archived_unix   = column_int64_or_zero(stmt, 13);
    out.time_compacting_unix = column_int64_or_zero(stmt, 14);
    out.revert_data          = column_json_or_empty(stmt, 15);
    out.permission           = column_json_or_empty(stmt, 16);
    if (sqlite3_column_type(stmt, 17) != SQLITE_NULL) {
        out.total_cost_usd = sqlite3_column_double(stmt, 17);
    } else {
        out.total_cost_usd = 0.0;
    }
    if (out.version <= 0) out.version = 1;
}


const char* kSelectSessionFields =
    "id, slug, project_id, parent_id, binary_path, directory, title, version, "
    "summary_additions, summary_deletions, summary_files, "
    "time_created, time_updated, time_archived, time_compacting, "
    "revert_json, permission_json, total_cost";


bool recalc_session_cost_locked(sqlite3* db, const std::string& session_id)
{
    const char* sql_select_parts =
        "SELECT p.kind, p.payload_json FROM parts p "
        "JOIN messages m ON p.message_id = m.id "
        "WHERE m.session_id = ? AND p.kind = 'step_finish'";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql_select_parts, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "recalc_cost_prepare");
        return false;
    }
    if (!bind_text(stmt, 1, session_id)) {
        sqlite3_finalize(stmt);
        set_last_error("recalc_cost_bind_failed");
        return false;
    }
    double total = 0.0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const std::string kind = column_text_or_empty(stmt, 0);
        if (kind != "step_finish") continue;
        const std::string payload = column_text_or_empty(stmt, 1);
        auto j = nlohmann::json::parse(payload, nullptr, false);
        if (j.is_discarded()) continue;
        if (j.contains("cost_usd") && j["cost_usd"].is_number()) {
            total += j["cost_usd"].get<double>();
        }
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        set_last_error_sqlite(db, "recalc_cost_step");
        return false;
    }

    const char* sql_update =
        "UPDATE sessions SET total_cost = ?, time_updated = ? WHERE id = ?";
    sqlite3_stmt* upd = nullptr;
    rc = sqlite3_prepare_v2(db, sql_update, -1, &upd, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "recalc_cost_update_prepare");
        return false;
    }
    bool ok = bind_double(upd, 1, total) &&
              bind_int64(upd, 2, now_unix_ms()) &&
              bind_text(upd, 3, session_id);
    if (ok) rc = sqlite3_step(upd);
    sqlite3_finalize(upd);
    if (!ok || rc != SQLITE_DONE) {
        set_last_error_sqlite(db, "recalc_cost_update_step");
        return false;
    }
    return true;
}


bool insert_parts_locked(sqlite3* db, const std::string& message_id, const std::vector<part_t>& parts)
{
    const char* sql =
        "INSERT INTO parts(message_id, sequence, kind, payload_json) VALUES(?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "insert_parts_prepare");
        return false;
    }
    for (size_t i = 0; i < parts.size(); ++i) {
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        const auto& p = parts[i];
        const std::string kind = part_kind_to_string(p.kind);
        const std::string payload = serialize_part(p).dump();
        bool ok = bind_text(stmt, 1, message_id) &&
                  bind_int(stmt, 2, static_cast<int>(i)) &&
                  bind_text(stmt, 3, kind) &&
                  bind_text(stmt, 4, payload);
        if (!ok) {
            sqlite3_finalize(stmt);
            set_last_error("insert_parts_bind_failed");
            return false;
        }
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            set_last_error_sqlite(db, "insert_parts_step");
            return false;
        }
    }
    sqlite3_finalize(stmt);
    return true;
}


bool delete_parts_for_message_locked(sqlite3* db, const std::string& message_id)
{
    const char* sql = "DELETE FROM parts WHERE message_id = ?";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "delete_parts_prepare");
        return false;
    }
    bool ok = bind_text(stmt, 1, message_id);
    if (ok) rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (!ok || rc != SQLITE_DONE) {
        set_last_error_sqlite(db, "delete_parts_step");
        return false;
    }
    return true;
}


bool insert_session_row_locked(sqlite3* db, const session_info_t& info)
{
    const char* sql =
        "INSERT INTO sessions("
        "id, slug, project_id, parent_id, binary_path, directory, title, version, "
        "summary_additions, summary_deletions, summary_files, "
        "time_created, time_updated, time_archived, time_compacting, "
        "revert_json, permission_json, total_cost"
        ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "insert_session_prepare");
        return false;
    }
    const std::string revert_json     = info.revert_data.is_null() ? std::string() : info.revert_data.dump();
    const std::string permission_json = info.permission.is_null()  ? std::string() : info.permission.dump();
    bool ok = bind_text(stmt, 1, info.id) &&
              bind_text(stmt, 2, info.slug) &&
              bind_text(stmt, 3, info.project_id) &&
              bind_text_or_null(stmt, 4, info.parent_id) &&
              bind_text_or_null(stmt, 5, info.binary_path) &&
              bind_text_or_null(stmt, 6, info.directory) &&
              bind_text_or_null(stmt, 7, info.title) &&
              bind_int(stmt, 8, info.version > 0 ? info.version : 1) &&
              bind_int(stmt, 9, info.summary.additions) &&
              bind_int(stmt, 10, info.summary.deletions) &&
              bind_int(stmt, 11, info.summary.files) &&
              bind_int64(stmt, 12, info.time_created_unix) &&
              bind_int64(stmt, 13, info.time_updated_unix) &&
              bind_int64_or_null(stmt, 14, info.time_archived_unix) &&
              bind_int64_or_null(stmt, 15, info.time_compacting_unix) &&
              bind_text_or_null(stmt, 16, revert_json) &&
              bind_text_or_null(stmt, 17, permission_json) &&
              bind_double(stmt, 18, info.total_cost_usd);
    if (ok) rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (!ok || rc != SQLITE_DONE) {
        set_last_error_sqlite(db, "insert_session_step");
        return false;
    }
    return true;
}


bool column_exists(sqlite3* db, const char* table, const char* column)
{
    sqlite3_stmt* stmt = nullptr;
    std::string sql = std::string("PRAGMA table_info(") + table + ")";
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;
    bool found = false;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* p = sqlite3_column_text(stmt, 1);
        if (p && std::strcmp(reinterpret_cast<const char*>(p), column) == 0) {
            found = true;
            break;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

bool proposal_audit_parent_is_dedicated(sqlite3* db)
{
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(db, "PRAGMA foreign_key_list(proposal_audits)",
            -1, &statement, nullptr) != SQLITE_OK)
        return false;
    bool exact = false;
    int result = SQLITE_ROW;
    while ((result = sqlite3_step(statement)) == SQLITE_ROW) {
        const std::string table = column_text_or_empty(statement, 2);
        const std::string from = column_text_or_empty(statement, 3);
        const std::string to = column_text_or_empty(statement, 4);
        if (from == "session_id") {
            if (exact || table != "proposal_audit_sessions" ||
                to != "session_id") {
                sqlite3_finalize(statement);
                return false;
            }
            exact = true;
        }
    }
    sqlite3_finalize(statement);
    return result == SQLITE_DONE && exact;
}


bool ensure_schema(sqlite3* db)
{
    if (!exec_simple(db, "PRAGMA journal_mode=WAL")) return false;
    if (!exec_simple(db, "PRAGMA synchronous=NORMAL")) return false;
    if (!exec_simple(db, "PRAGMA foreign_keys=ON")) return false;
    if (!exec_simple(db, "PRAGMA temp_store=MEMORY")) return false;

    const char* schema =
        "CREATE TABLE IF NOT EXISTS sessions ("
        "id TEXT PRIMARY KEY,"
        "slug TEXT NOT NULL,"
        "project_id TEXT NOT NULL,"
        "parent_id TEXT,"
        "binary_path TEXT,"
        "directory TEXT,"
        "title TEXT,"
        "version INTEGER DEFAULT 1,"
        "summary_additions INTEGER DEFAULT 0,"
        "summary_deletions INTEGER DEFAULT 0,"
        "summary_files INTEGER DEFAULT 0,"
        "time_created INTEGER NOT NULL,"
        "time_updated INTEGER NOT NULL,"
        "time_archived INTEGER,"
        "time_compacting INTEGER,"
        "revert_json TEXT,"
        "permission_json TEXT,"
        "total_cost REAL DEFAULT 0.0,"
        "todos_json TEXT NOT NULL DEFAULT ''"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_sessions_binary ON sessions(binary_path);"
        "CREATE INDEX IF NOT EXISTS idx_sessions_parent ON sessions(parent_id);"
        "CREATE INDEX IF NOT EXISTS idx_sessions_archived ON sessions(time_archived);"
        "CREATE TABLE IF NOT EXISTS messages ("
        "id TEXT PRIMARY KEY,"
        "session_id TEXT NOT NULL,"
        "role TEXT NOT NULL,"
        "agent TEXT,"
        "model_provider_id TEXT,"
        "model_id TEXT,"
        "created INTEGER NOT NULL,"
        "FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, created);"
        "CREATE TABLE IF NOT EXISTS parts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "message_id TEXT NOT NULL,"
        "sequence INTEGER NOT NULL,"
        "kind TEXT NOT NULL,"
        "payload_json TEXT NOT NULL,"
        "FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_parts_message ON parts(message_id, sequence);"
        "CREATE TABLE IF NOT EXISTS schema_meta ("
        "key TEXT PRIMARY KEY,"
        "value TEXT"
        ");"
        "INSERT OR IGNORE INTO schema_meta(key, value) VALUES('version', '1');";

    if (!exec_simple(db, schema)) return false;

    if (!column_exists(db, "sessions", "todos_json")) {
        if (!exec_simple(db, "ALTER TABLE sessions ADD COLUMN todos_json TEXT NOT NULL DEFAULT ''"))
            return false;
    }

    if (!exec_simple(db, "BEGIN IMMEDIATE")) return false;
    const char* proposal_schema =
        "CREATE TABLE IF NOT EXISTS proposal_audit_sessions ("
        "session_id TEXT PRIMARY KEY,"
        "created INTEGER NOT NULL,"
        "updated INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS proposal_audits ("
        "audit_id TEXT PRIMARY KEY,"
        "proposal_id TEXT NOT NULL,"
        "family TEXT NOT NULL,"
        "kind TEXT NOT NULL,"
        "session_id TEXT NOT NULL,"
        "source_index TEXT NOT NULL,"
        "source_timestamp INTEGER NOT NULL,"
        "source_fingerprint TEXT NOT NULL,"
        "target_id TEXT NOT NULL,"
        "target_view_id TEXT NOT NULL,"
        "target_generation TEXT NOT NULL,"
        "source_revision TEXT NOT NULL,"
        "target_overlay_revision TEXT NOT NULL,"
        "before_hash TEXT NOT NULL,"
        "after_hash TEXT NOT NULL,"
        "result_hash TEXT NOT NULL,"
        "result_revision TEXT NOT NULL,"
        "provenance TEXT NOT NULL,"
        "detail TEXT NOT NULL,"
        "lifecycle_state TEXT NOT NULL,"
        "outcome TEXT NOT NULL,"
        "task_id TEXT NOT NULL,"
        "diagnostic_id TEXT NOT NULL,"
        "undo_revert_identity TEXT NOT NULL,"
        "created INTEGER NOT NULL,"
        "updated INTEGER NOT NULL,"
        "revalidation_required INTEGER NOT NULL DEFAULT 0,"
        "FOREIGN KEY(session_id) REFERENCES proposal_audit_sessions(session_id) ON DELETE CASCADE"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_proposal_audits_session_updated "
        "ON proposal_audits(session_id, updated DESC);"
        "CREATE INDEX IF NOT EXISTS idx_proposal_audits_revalidation "
        "ON proposal_audits(session_id, revalidation_required, updated DESC);"
        "CREATE TABLE IF NOT EXISTS proposal_audit_events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "audit_id TEXT NOT NULL,"
        "outcome TEXT NOT NULL,"
        "lifecycle_state TEXT NOT NULL,"
        "detail TEXT NOT NULL,"
        "event_time INTEGER NOT NULL,"
        "task_id TEXT NOT NULL,"
        "diagnostic_id TEXT NOT NULL,"
        "result_revision TEXT NOT NULL,"
        "result_hash TEXT NOT NULL,"
        "undo_revert_identity TEXT NOT NULL,"
        "FOREIGN KEY(audit_id) REFERENCES proposal_audits(audit_id) ON DELETE CASCADE"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_proposal_audit_events_audit "
        "ON proposal_audit_events(audit_id, id DESC);"
        "CREATE TABLE IF NOT EXISTS proposal_audit_hunks ("
        "audit_id TEXT NOT NULL,"
        "hunk_index INTEGER NOT NULL,"
        "old_start INTEGER NOT NULL,"
        "old_count INTEGER NOT NULL,"
        "new_start INTEGER NOT NULL,"
        "new_count INTEGER NOT NULL,"
        "decision TEXT NOT NULL,"
        "before_hash TEXT NOT NULL,"
        "after_hash TEXT NOT NULL,"
        "PRIMARY KEY(audit_id, hunk_index),"
        "FOREIGN KEY(audit_id) REFERENCES proposal_audits(audit_id) ON DELETE CASCADE"
        ");"
        "UPDATE schema_meta SET value='3' WHERE key='version' AND CAST(value AS INTEGER)<3;";
    if (!exec_simple(db, proposal_schema)) {
        exec_simple(db, "ROLLBACK");
        return false;
    }
    if (!proposal_audit_parent_is_dedicated(db)) {
        set_last_error("proposal_audit_parent_schema_mismatch");
        exec_simple(db, "ROLLBACK");
        return false;
    }
    if (!exec_simple(db, "COMMIT")) {
        exec_simple(db, "ROLLBACK");
        return false;
    }

    return true;
}


sqlite3* db_handle()
{
    return g_db.load(std::memory_order_acquire);
}


bool proposal_field_valid(const std::string& value, std::size_t maximum,
                          bool required = false)
{
    return value.size() <= maximum && (!required || !value.empty());
}

bool session_identity_valid(const std::string& value)
{
    return !value.empty() && value.size() <= 128U &&
        std::all_of(value.begin(), value.end(), [](unsigned char character) {
            return std::isalnum(character) != 0 || character == '-' ||
                character == '_';
        });
}

bool ensure_proposal_audit_session_locked(sqlite3* db,
                                          const std::string& session_id,
                                          std::int64_t timestamp)
{
    if (!db || !session_identity_valid(session_id) || timestamp <= 0) {
        set_last_error("invalid_session_identity");
        return false;
    }
    sqlite3_stmt* statement = nullptr;
    const int prepared = sqlite3_prepare_v2(db,
        "INSERT INTO proposal_audit_sessions(session_id,created,updated) "
        "VALUES(?,?,?) ON CONFLICT(session_id) DO UPDATE SET "
        "updated=excluded.updated",
        -1, &statement, nullptr);
    if (prepared != SQLITE_OK) {
        set_last_error_sqlite(db, "ensure_proposal_audit_session_prepare");
        return false;
    }
    const bool bound = bind_text(statement, 1, session_id) &&
        bind_int64(statement, 2, timestamp) &&
        bind_int64(statement, 3, timestamp);
    const int stepped = bound ? sqlite3_step(statement) : SQLITE_ERROR;
    sqlite3_finalize(statement);
    if (!bound || stepped != SQLITE_DONE) {
        set_last_error_sqlite(db, "ensure_proposal_audit_session_step");
        return false;
    }
    statement = nullptr;
    const int selected = sqlite3_prepare_v2(db,
        "SELECT session_id FROM proposal_audit_sessions WHERE session_id=? LIMIT 1",
        -1, &statement, nullptr);
    if (selected != SQLITE_OK || !bind_text(statement, 1, session_id)) {
        if (statement) sqlite3_finalize(statement);
        set_last_error_sqlite(db,
            "ensure_proposal_audit_session_verify_prepare");
        return false;
    }
    const bool exact = sqlite3_step(statement) == SQLITE_ROW &&
        column_text_or_empty(statement, 0) == session_id;
    sqlite3_finalize(statement);
    if (!exact) {
        set_last_error("ensure_proposal_audit_session_verify_failed");
        return false;
    }
    return true;
}

bool proposal_audit_session_exists_locked(sqlite3* db,
                                          const std::string& session_id)
{
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(db,
            "SELECT session_id FROM proposal_audit_sessions WHERE session_id=? LIMIT 1",
            -1, &statement, nullptr) != SQLITE_OK ||
        !bind_text(statement, 1, session_id)) {
        if (statement) sqlite3_finalize(statement);
        set_last_error_sqlite(db, "proposal_audit_session_lookup");
        return false;
    }
    const bool exact = sqlite3_step(statement) == SQLITE_ROW &&
        column_text_or_empty(statement, 0) == session_id;
    sqlite3_finalize(statement);
    return exact;
}

bool proposal_hash_valid(const std::string& value, bool required)
{
    if (value.empty()) return !required;
    return value.size() == 16U && std::all_of(value.begin(), value.end(),
        [](unsigned char character) { return std::isxdigit(character) != 0; }) &&
        std::any_of(value.begin(), value.end(),
            [](char character) { return character != '0'; });
}


bool proposal_audit_valid(const proposal_audit_record_t& record)
{
    constexpr std::int32_t maximum_hunk_coordinate = 16 * 1024 * 1024;
    if (!proposal_field_valid(record.audit_id, 192, true) ||
        !proposal_field_valid(record.proposal_id, 192, true) ||
        !proposal_field_valid(record.family, 32, true) ||
        !proposal_field_valid(record.kind, 64, true) ||
        !proposal_field_valid(record.session_id, 128, true) ||
        !proposal_field_valid(record.target_id, 512, true) ||
        !proposal_field_valid(record.target_view_id, 128) ||
        !proposal_hash_valid(record.before_hash, true) ||
        !proposal_hash_valid(record.after_hash, true) ||
        !proposal_hash_valid(record.result_hash, false) ||
        !proposal_field_valid(record.provenance, 512, true) ||
        !proposal_field_valid(record.detail, 4096, true) ||
        !proposal_field_valid(record.lifecycle_state, 64, true) ||
        !proposal_field_valid(record.outcome, 32, true) ||
        !proposal_field_valid(record.task_id, 192, true) ||
        !proposal_field_valid(record.diagnostic_id, 192) ||
        !proposal_field_valid(record.undo_revert_identity, 512) ||
        record.hunks.size() > 512)
        return false;
    if (record.family != "editor" && record.family != "reverse_engineering")
        return false;
    const bool kind_valid = record.family == "editor"
        ? record.kind == "full_content_diff"
        : record.kind == "analysis.rename" || record.kind == "analysis.comment" ||
            record.kind == "analysis.type" || record.kind == "patch.static" ||
            record.kind == "patch.live" || record.kind == "network.request_edit" ||
            record.kind == "network.replay_stage";
    if (!kind_valid) return false;
    static constexpr const char* lifecycle_states[] = {
        "validating", "pending_review", "reviewed", "applying", "rejected",
        "stale", "failure", "applied_partial", "applied", "review_staged",
        "partial"
    };
    if (std::none_of(std::begin(lifecycle_states), std::end(lifecycle_states),
            [&](const char* value) { return record.lifecycle_state == value; }))
        return false;
    static constexpr const char* outcomes[] = {
        "stage", "review", "apply", "reject", "stale", "partial",
        "rollback", "failure"
    };
    if (std::none_of(std::begin(outcomes), std::end(outcomes),
            [&](const char* value) { return record.outcome == value; }))
        return false;
    for (std::size_t index = 0; index < record.hunks.size(); ++index) {
        const auto& hunk = record.hunks[index];
        const bool decision_valid = hunk.decision == "pending" ||
            hunk.decision == "accepted" || hunk.decision == "rejected";
        const bool coordinates_valid = hunk.old_start >= 0 && hunk.old_count >= 0 &&
            hunk.new_start >= 0 && hunk.new_count >= 0 &&
            hunk.old_start <= maximum_hunk_coordinate &&
            hunk.old_count <= maximum_hunk_coordinate &&
            hunk.new_start <= maximum_hunk_coordinate &&
            hunk.new_count <= maximum_hunk_coordinate &&
            static_cast<std::int64_t>(hunk.old_start) + hunk.old_count <=
                maximum_hunk_coordinate &&
            static_cast<std::int64_t>(hunk.new_start) + hunk.new_count <=
                maximum_hunk_coordinate;
        if (hunk.index != index || !decision_valid || !coordinates_valid ||
            !proposal_hash_valid(hunk.before_hash, true) ||
            !proposal_hash_valid(hunk.after_hash, true))
            return false;
    }
    return true;
}


void hydrate_proposal_audit(sqlite3_stmt* stmt, proposal_audit_record_t& record)
{
    record = {};
    record.audit_id = column_text_or_empty(stmt, 0);
    record.proposal_id = column_text_or_empty(stmt, 1);
    record.family = column_text_or_empty(stmt, 2);
    record.kind = column_text_or_empty(stmt, 3);
    record.session_id = column_text_or_empty(stmt, 4);
    record.source_index = column_uint64_text_or_zero(stmt, 5);
    record.source_timestamp = column_int64_or_zero(stmt, 6);
    record.source_fingerprint = column_uint64_text_or_zero(stmt, 7);
    record.target_id = column_text_or_empty(stmt, 8);
    record.target_view_id = column_text_or_empty(stmt, 9);
    record.target_generation = column_uint64_text_or_zero(stmt, 10);
    record.source_revision = column_uint64_text_or_zero(stmt, 11);
    record.target_overlay_revision = column_uint64_text_or_zero(stmt, 12);
    record.before_hash = column_text_or_empty(stmt, 13);
    record.after_hash = column_text_or_empty(stmt, 14);
    record.result_hash = column_text_or_empty(stmt, 15);
    record.result_revision = column_uint64_text_or_zero(stmt, 16);
    record.provenance = column_text_or_empty(stmt, 17);
    record.detail = column_text_or_empty(stmt, 18);
    record.lifecycle_state = column_text_or_empty(stmt, 19);
    record.outcome = column_text_or_empty(stmt, 20);
    record.task_id = column_text_or_empty(stmt, 21);
    record.diagnostic_id = column_text_or_empty(stmt, 22);
    record.undo_revert_identity = column_text_or_empty(stmt, 23);
    record.created_unix = column_int64_or_zero(stmt, 24);
    record.updated_unix = column_int64_or_zero(stmt, 25);
    record.revalidation_required = column_int64_or_zero(stmt, 26) != 0;
}


constexpr const char* kSelectProposalAuditFields =
    "audit_id,proposal_id,family,kind,session_id,source_index,source_timestamp,"
    "source_fingerprint,target_id,target_view_id,target_generation,source_revision,"
    "target_overlay_revision,before_hash,after_hash,result_hash,result_revision,"
    "provenance,detail,lifecycle_state,outcome,task_id,diagnostic_id,"
    "undo_revert_identity,created,updated,revalidation_required";


bool list_with_filter(const std::string& filter_clause,
                      const std::string& bind_value,
                      std::vector<session_info_t>& out)
{
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        return false;
    }
    out.clear();

    std::string sql = std::string("SELECT ") + kSelectSessionFields + " FROM sessions";
    if (!filter_clause.empty()) {
        sql += " WHERE " + filter_clause;
    }
    sql += " ORDER BY time_updated DESC";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "list_prepare");
        return false;
    }
    if (!filter_clause.empty()) {
        if (!bind_text(stmt, 1, bind_value)) {
            sqlite3_finalize(stmt);
            set_last_error("list_bind_failed");
            return false;
        }
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        session_info_t info;
        hydrate_session_from_row(stmt, info);
        out.push_back(std::move(info));
    }
    sqlite3_finalize(stmt);
    return true;
}


}


bool initialize()
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    diag::log_tagged("session", "initialize enter");
    if (g_initialized.load(std::memory_order_acquire)) {
        diag::log_tagged("session", "initialize already_initialized");
        return true;
    }

    std::lock_guard<std::mutex> lk(g_init_mutex);
    if (g_initialized.load(std::memory_order_acquire)) return true;

    const std::filesystem::path db_path = resolve_database_path();
    diag::log_tagged_fmt("session", "initialize db_path='%s'", db_path.string().c_str());
    std::error_code ec;
    std::filesystem::create_directories(db_path.parent_path(), ec);

    sqlite3* db = nullptr;
    const auto wide_path = db_path.wstring();
    if (wide_path.empty() ||
        wide_path.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        set_last_error("invalid_database_path");
        return false;
    }
    const int wide_length = static_cast<int>(wide_path.size());
    const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        wide_path.data(), wide_length, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        set_last_error("database_path_utf8_size_failed");
        return false;
    }
    std::string utf8(static_cast<std::size_t>(needed), '\0');
    const int converted = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        wide_path.data(), wide_length, utf8.data(), needed, nullptr, nullptr);
    if (converted != needed) {
        set_last_error("database_path_utf8_conversion_failed");
        return false;
    }
    int rc = sqlite3_open_v2(
        utf8.c_str(),
        &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr);
    if (rc != SQLITE_OK) {
        if (db) {
            set_last_error_sqlite(db, "sqlite_open");
            sqlite3_close(db);
        }
        else {
            set_last_error("sqlite_open_failed");
        }
        return false;
    }
    sqlite3_busy_timeout(db, 5000);

    if (!ensure_schema(db)) {
        sqlite3_close(db);
        return false;
    }

    g_db.store(db, std::memory_order_release);
    g_initialized.store(true, std::memory_order_release);
    diag::log_tagged("session", "initialize SUCCESS db_open schema_ready");
    return true;
}


bool shutdown()
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    diag::log_tagged("session", "shutdown enter");
    std::lock_guard<std::mutex> lk(g_init_mutex);
    sqlite3* db = g_db.exchange(nullptr, std::memory_order_acq_rel);
    g_initialized.store(false, std::memory_order_release);
    if (!db) {
        diag::log_tagged("session", "shutdown no_db_handle");
        return true;
    }
    int rc = sqlite3_close_v2(db);
    if (rc != SQLITE_OK) {
        set_last_error("sqlite_close_failed");
        diag::log_tagged_fmt("session", "shutdown FAILED sqlite_close rc=%d", rc);
        return false;
    }
    diag::log_tagged("session", "shutdown SUCCESS db_closed");
    return true;
}


bool create(session_info_t& out_info,
            const std::string& project_id,
            const std::string& binary_path,
            const std::string& parent_id)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    diag::log_tagged_fmt("session", "create enter project='%s' binary='%s' parent='%s'",
        project_id.c_str(), binary_path.c_str(), parent_id.c_str());
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        diag::log_tagged("session", "create FAILED not_initialized");
        return false;
    }

    out_info = session_info_t{};
    out_info.id                = generate_id_32();
    out_info.project_id        = project_id;
    out_info.binary_path       = binary_path;
    out_info.parent_id         = parent_id;
    out_info.title             = std::string();
    out_info.slug              = make_slug(out_info.title);
    out_info.version           = 1;
    out_info.time_created_unix = now_unix_ms();
    out_info.time_updated_unix = out_info.time_created_unix;
    if (!binary_path.empty()) {
        std::error_code ec;
        const auto p = std::filesystem::path(binary_path);
        out_info.directory = p.parent_path().string();
    }

    if (!exec_simple(db, "BEGIN IMMEDIATE")) return false;
    if (!insert_session_row_locked(db, out_info)) {
        exec_simple(db, "ROLLBACK");
        return false;
    }
    if (!exec_simple(db, "COMMIT")) {
        exec_simple(db, "ROLLBACK");
        return false;
    }

    {
        aida::events::session_created_t evt;
        evt.session_id = out_info.id;
        evt.project_id = out_info.project_id;
        evt.parent_id  = out_info.parent_id;
        aida::events::publish(aida::events::event_session_created, evt);
    }

    diag::log_tagged_fmt("session", "create SUCCESS id='%s' slug='%s'",
        out_info.id.c_str(), out_info.slug.c_str());
    return true;
}


bool get(const std::string& session_id, session_info_t& out)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        return false;
    }
    std::string sql = std::string("SELECT ") + kSelectSessionFields + " FROM sessions WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "get_prepare");
        return false;
    }
    if (!bind_text(stmt, 1, session_id)) {
        sqlite3_finalize(stmt);
        set_last_error("get_bind_failed");
        return false;
    }
    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        hydrate_session_from_row(stmt, out);
        found = true;
    }
    sqlite3_finalize(stmt);
    if (!found) {
        set_last_error("session_not_found");
        return false;
    }
    return true;
}


bool update(const session_info_t& info)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        return false;
    }
    const char* sql =
        "UPDATE sessions SET "
        "slug = ?, project_id = ?, parent_id = ?, binary_path = ?, directory = ?, title = ?, "
        "version = ?, summary_additions = ?, summary_deletions = ?, summary_files = ?, "
        "time_created = ?, time_updated = ?, time_archived = ?, time_compacting = ?, "
        "revert_json = ?, permission_json = ?, total_cost = ? "
        "WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "update_prepare");
        return false;
    }
    const std::string revert_json     = info.revert_data.is_null() ? std::string() : info.revert_data.dump();
    const std::string permission_json = info.permission.is_null()  ? std::string() : info.permission.dump();
    bool ok = bind_text(stmt, 1, info.slug) &&
              bind_text(stmt, 2, info.project_id) &&
              bind_text_or_null(stmt, 3, info.parent_id) &&
              bind_text_or_null(stmt, 4, info.binary_path) &&
              bind_text_or_null(stmt, 5, info.directory) &&
              bind_text_or_null(stmt, 6, info.title) &&
              bind_int(stmt, 7, info.version > 0 ? info.version : 1) &&
              bind_int(stmt, 8, info.summary.additions) &&
              bind_int(stmt, 9, info.summary.deletions) &&
              bind_int(stmt, 10, info.summary.files) &&
              bind_int64(stmt, 11, info.time_created_unix) &&
              bind_int64(stmt, 12, info.time_updated_unix == 0 ? now_unix_ms() : info.time_updated_unix) &&
              bind_int64_or_null(stmt, 13, info.time_archived_unix) &&
              bind_int64_or_null(stmt, 14, info.time_compacting_unix) &&
              bind_text_or_null(stmt, 15, revert_json) &&
              bind_text_or_null(stmt, 16, permission_json) &&
              bind_double(stmt, 17, info.total_cost_usd) &&
              bind_text(stmt, 18, info.id);
    if (ok) rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (!ok || rc != SQLITE_DONE) {
        set_last_error_sqlite(db, "update_step");
        return false;
    }

    {
        aida::events::session_updated_t evt;
        evt.session_id     = info.id;
        evt.fields_changed = "title,binary_path,directory,version,summary,permission,revert,total_cost,archived,compacting";
        aida::events::publish(aida::events::event_session_updated, evt);
    }

    return true;
}


bool list(const std::string& binary_path_filter, std::vector<session_info_t>& out)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    if (binary_path_filter.empty()) return list_all(out);
    return list_with_filter("binary_path = ?", binary_path_filter, out);
}


bool list_all(std::vector<session_info_t>& out)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    return list_with_filter(std::string(), std::string(), out);
}


bool list_children(const std::string& parent_id, std::vector<session_info_t>& out)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    return list_with_filter("parent_id = ?", parent_id, out);
}


bool fork(const std::string& session_id,
          const std::string& fork_at_message_id,
          session_info_t& out_new)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    diag::log_tagged_fmt("session", "fork enter session='%s' fork_at='%s'",
        session_id.c_str(), fork_at_message_id.c_str());
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        diag::log_tagged("session", "fork FAILED not_initialized");
        return false;
    }

    session_info_t parent;
    if (!get(session_id, parent)) return false;

    out_new = session_info_t{};
    out_new.id                = generate_id_32();
    out_new.parent_id         = parent.id;
    out_new.project_id        = parent.project_id;
    out_new.binary_path       = parent.binary_path;
    out_new.directory         = parent.directory;
    out_new.title             = parent.title.empty() ? std::string("(fork)") : parent.title + " (fork)";
    out_new.slug              = make_slug(out_new.title);
    out_new.version           = parent.version > 0 ? parent.version : 1;
    out_new.permission        = parent.permission;
    out_new.time_created_unix = now_unix_ms();
    out_new.time_updated_unix = out_new.time_created_unix;

    if (!exec_simple(db, "BEGIN IMMEDIATE")) return false;

    if (!insert_session_row_locked(db, out_new)) {
        exec_simple(db, "ROLLBACK");
        return false;
    }

    const char* sql_select_msgs =
        "SELECT id, role, agent, model_provider_id, model_id, created "
        "FROM messages WHERE session_id = ? ORDER BY created ASC, id ASC";
    sqlite3_stmt* msg_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql_select_msgs, -1, &msg_stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "fork_select_msgs_prepare");
        exec_simple(db, "ROLLBACK");
        return false;
    }
    if (!bind_text(msg_stmt, 1, session_id)) {
        sqlite3_finalize(msg_stmt);
        exec_simple(db, "ROLLBACK");
        set_last_error("fork_select_msgs_bind_failed");
        return false;
    }

    struct copy_msg_t
    {
        std::string old_id;
        std::string role;
        std::string agent;
        std::string model_provider_id;
        std::string model_id;
        int64_t     created = 0;
    };
    std::vector<copy_msg_t> to_copy;
    bool include_until_target = !fork_at_message_id.empty();
    bool target_seen = false;
    while (sqlite3_step(msg_stmt) == SQLITE_ROW) {
        copy_msg_t m;
        m.old_id            = column_text_or_empty(msg_stmt, 0);
        m.role              = column_text_or_empty(msg_stmt, 1);
        m.agent             = column_text_or_empty(msg_stmt, 2);
        m.model_provider_id = column_text_or_empty(msg_stmt, 3);
        m.model_id          = column_text_or_empty(msg_stmt, 4);
        m.created           = column_int64_or_zero(msg_stmt, 5);
        to_copy.push_back(std::move(m));
        if (include_until_target && to_copy.back().old_id == fork_at_message_id) {
            target_seen = true;
            break;
        }
    }
    sqlite3_finalize(msg_stmt);

    if (include_until_target && !target_seen) {
        exec_simple(db, "ROLLBACK");
        set_last_error("fork_target_message_not_found");
        return false;
    }

    const char* sql_insert_msg =
        "INSERT INTO messages(id, session_id, role, agent, model_provider_id, model_id, created) "
        "VALUES(?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* ins_stmt = nullptr;
    rc = sqlite3_prepare_v2(db, sql_insert_msg, -1, &ins_stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "fork_insert_msg_prepare");
        exec_simple(db, "ROLLBACK");
        return false;
    }

    const char* sql_select_parts =
        "SELECT kind, payload_json FROM parts WHERE message_id = ? ORDER BY sequence ASC, id ASC";
    sqlite3_stmt* part_sel = nullptr;
    rc = sqlite3_prepare_v2(db, sql_select_parts, -1, &part_sel, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(ins_stmt);
        set_last_error_sqlite(db, "fork_select_parts_prepare");
        exec_simple(db, "ROLLBACK");
        return false;
    }

    bool failed = false;
    for (const auto& cm : to_copy) {
        const std::string new_id = generate_id_32();
        sqlite3_reset(ins_stmt);
        sqlite3_clear_bindings(ins_stmt);
        bool ok = bind_text(ins_stmt, 1, new_id) &&
                  bind_text(ins_stmt, 2, out_new.id) &&
                  bind_text(ins_stmt, 3, cm.role) &&
                  bind_text_or_null(ins_stmt, 4, cm.agent) &&
                  bind_text_or_null(ins_stmt, 5, cm.model_provider_id) &&
                  bind_text_or_null(ins_stmt, 6, cm.model_id) &&
                  bind_int64(ins_stmt, 7, cm.created);
        if (!ok) {
            set_last_error("fork_insert_msg_bind_failed");
            failed = true;
            break;
        }
        if (sqlite3_step(ins_stmt) != SQLITE_DONE) {
            set_last_error_sqlite(db, "fork_insert_msg_step");
            failed = true;
            break;
        }

        std::vector<std::pair<std::string, std::string>> kind_payload;
        sqlite3_reset(part_sel);
        sqlite3_clear_bindings(part_sel);
        if (!bind_text(part_sel, 1, cm.old_id)) {
            set_last_error("fork_select_parts_bind_failed");
            failed = true;
            break;
        }
        while (sqlite3_step(part_sel) == SQLITE_ROW) {
            kind_payload.emplace_back(column_text_or_empty(part_sel, 0),
                                      column_text_or_empty(part_sel, 1));
        }

        if (!kind_payload.empty()) {
            const char* sql_insert_part =
                "INSERT INTO parts(message_id, sequence, kind, payload_json) VALUES(?, ?, ?, ?)";
            sqlite3_stmt* part_ins = nullptr;
            int prc = sqlite3_prepare_v2(db, sql_insert_part, -1, &part_ins, nullptr);
            if (prc != SQLITE_OK) {
                set_last_error_sqlite(db, "fork_insert_part_prepare");
                failed = true;
                break;
            }
            for (size_t i = 0; i < kind_payload.size(); ++i) {
                sqlite3_reset(part_ins);
                sqlite3_clear_bindings(part_ins);
                bool ok2 = bind_text(part_ins, 1, new_id) &&
                           bind_int(part_ins, 2, static_cast<int>(i)) &&
                           bind_text(part_ins, 3, kind_payload[i].first) &&
                           bind_text(part_ins, 4, kind_payload[i].second);
                if (!ok2) {
                    set_last_error("fork_insert_part_bind_failed");
                    failed = true;
                    break;
                }
                if (sqlite3_step(part_ins) != SQLITE_DONE) {
                    set_last_error_sqlite(db, "fork_insert_part_step");
                    failed = true;
                    break;
                }
            }
            sqlite3_finalize(part_ins);
            if (failed) break;
        }
    }
    sqlite3_finalize(ins_stmt);
    sqlite3_finalize(part_sel);

    if (failed) {
        exec_simple(db, "ROLLBACK");
        return false;
    }

    if (!recalc_session_cost_locked(db, out_new.id)) {
        exec_simple(db, "ROLLBACK");
        return false;
    }

    if (!exec_simple(db, "COMMIT")) {
        exec_simple(db, "ROLLBACK");
        return false;
    }

    if (!get(out_new.id, out_new)) return false;
    return true;
}


bool set_archived(const std::string& session_id, int64_t archived_unix)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        return false;
    }
    const char* sql =
        "UPDATE sessions SET time_archived = ?, time_updated = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "set_archived_prepare");
        return false;
    }
    bool ok = bind_int64_or_null(stmt, 1, archived_unix) &&
              bind_int64(stmt, 2, now_unix_ms()) &&
              bind_text(stmt, 3, session_id);
    if (ok) rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (!ok || rc != SQLITE_DONE) {
        set_last_error_sqlite(db, "set_archived_step");
        return false;
    }

    {
        aida::events::session_updated_t evt;
        evt.session_id     = session_id;
        evt.fields_changed = "archived";
        aida::events::publish(aida::events::event_session_updated, evt);
    }

    return true;
}


bool set_compacting(const std::string& session_id, int64_t compacting_unix)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        return false;
    }
    if (session_id.empty()) {
        set_last_error("invalid_session_id");
        return false;
    }
    const char* sql =
        "UPDATE sessions SET time_compacting = ?, time_updated = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "set_compacting_prepare");
        return false;
    }
    bool ok = bind_int64_or_null(stmt, 1, compacting_unix) &&
              bind_int64(stmt, 2, now_unix_ms()) &&
              bind_text(stmt, 3, session_id);
    if (ok) rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    sqlite3_finalize(stmt);
    if (!ok || rc != SQLITE_DONE) {
        set_last_error_sqlite(db, "set_compacting_step");
        return false;
    }
    if (changes == 0) {
        set_last_error("session_not_found");
        return false;
    }

    {
        aida::events::session_updated_t evt;
        evt.session_id     = session_id;
        evt.fields_changed = "compacting";
        aida::events::publish(aida::events::event_session_updated, evt);
    }

    return true;
}


bool remove(const std::string& session_id)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    diag::log_tagged_fmt("session", "remove enter session='%s'", session_id.c_str());
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        diag::log_tagged("session", "remove FAILED not_initialized");
        return false;
    }
    if (!exec_simple(db, "BEGIN IMMEDIATE")) return false;

    std::vector<std::string> child_ids;
    {
        const char* sel = "SELECT id FROM sessions WHERE parent_id = ?";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db, sel, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            set_last_error_sqlite(db, "remove_select_children_prepare");
            exec_simple(db, "ROLLBACK");
            return false;
        }
        if (!bind_text(stmt, 1, session_id)) {
            sqlite3_finalize(stmt);
            exec_simple(db, "ROLLBACK");
            set_last_error("remove_select_children_bind_failed");
            return false;
        }
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            child_ids.push_back(column_text_or_empty(stmt, 0));
        }
        sqlite3_finalize(stmt);
    }

    auto delete_one = [&](const std::string& id) -> bool {
        const char* del_msgs = "DELETE FROM messages WHERE session_id = ?";
        sqlite3_stmt* m = nullptr;
        int rc = sqlite3_prepare_v2(db, del_msgs, -1, &m, nullptr);
        if (rc != SQLITE_OK) {
            set_last_error_sqlite(db, "remove_msgs_prepare");
            return false;
        }
        bool ok = bind_text(m, 1, id);
        if (ok) rc = sqlite3_step(m);
        sqlite3_finalize(m);
        if (!ok || rc != SQLITE_DONE) {
            set_last_error_sqlite(db, "remove_msgs_step");
            return false;
        }

        const char* del_session = "DELETE FROM sessions WHERE id = ?";
        sqlite3_stmt* s = nullptr;
        rc = sqlite3_prepare_v2(db, del_session, -1, &s, nullptr);
        if (rc != SQLITE_OK) {
            set_last_error_sqlite(db, "remove_session_prepare");
            return false;
        }
        ok = bind_text(s, 1, id);
        if (ok) rc = sqlite3_step(s);
        sqlite3_finalize(s);
        if (!ok || rc != SQLITE_DONE) {
            set_last_error_sqlite(db, "remove_session_step");
            return false;
        }
        return true;
    };

    for (const auto& cid : child_ids) {
        if (!delete_one(cid)) {
            exec_simple(db, "ROLLBACK");
            return false;
        }
    }
    if (!delete_one(session_id)) {
        exec_simple(db, "ROLLBACK");
        return false;
    }
    if (!exec_simple(db, "COMMIT")) {
        exec_simple(db, "ROLLBACK");
        return false;
    }

    for (const auto& cid : child_ids) {
        aida::events::session_deleted_t evt;
        evt.session_id = cid;
        aida::events::publish(aida::events::event_session_deleted, evt);
    }
    {
        aida::events::session_deleted_t evt;
        evt.session_id = session_id;
        aida::events::publish(aida::events::event_session_deleted, evt);
    }

    return true;
}


bool set_title(const std::string& session_id, const std::string& title)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    diag::log_tagged_fmt("session", "set_title session='%s' title='%s'",
        session_id.c_str(), title.c_str());
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        return false;
    }
    const char* sql =
        "UPDATE sessions SET title = ?, time_updated = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "set_title_prepare");
        return false;
    }
    bool ok = bind_text_or_null(stmt, 1, title) &&
              bind_int64(stmt, 2, now_unix_ms()) &&
              bind_text(stmt, 3, session_id);
    if (ok) rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (!ok || rc != SQLITE_DONE) {
        set_last_error_sqlite(db, "set_title_step");
        return false;
    }

    {
        aida::events::session_updated_t evt;
        evt.session_id     = session_id;
        evt.fields_changed = "title";
        aida::events::publish(aida::events::event_session_updated, evt);
    }

    return true;
}


bool append_message(const message_t& message)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    diag::log_tagged_fmt("session", "append_message enter msg_id='%s' session='%s' role=%s parts=%zu",
        message.id.c_str(), message.session_id.c_str(),
        role_to_string(message.role).c_str(), message.parts.size());
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        diag::log_tagged("session", "append_message FAILED not_initialized");
        return false;
    }
    if (message.id.empty() || message.session_id.empty()) {
        set_last_error("invalid_message_id");
        diag::log_tagged("session", "append_message FAILED invalid_message_id");
        return false;
    }

    if (!exec_simple(db, "BEGIN IMMEDIATE")) return false;

    const char* sql =
        "INSERT INTO messages(id, session_id, role, agent, model_provider_id, model_id, created) "
        "VALUES(?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "append_msg_prepare");
        exec_simple(db, "ROLLBACK");
        return false;
    }
    const int64_t created = message.created_unix == 0 ? now_unix_ms() : message.created_unix;
    bool ok = bind_text(stmt, 1, message.id) &&
              bind_text(stmt, 2, message.session_id) &&
              bind_text(stmt, 3, role_to_string(message.role)) &&
              bind_text_or_null(stmt, 4, message.agent) &&
              bind_text_or_null(stmt, 5, message.model_provider_id) &&
              bind_text_or_null(stmt, 6, message.model_id) &&
              bind_int64(stmt, 7, created);
    if (ok) rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (!ok || rc != SQLITE_DONE) {
        set_last_error_sqlite(db, "append_msg_step");
        exec_simple(db, "ROLLBACK");
        return false;
    }

    if (!insert_parts_locked(db, message.id, message.parts)) {
        exec_simple(db, "ROLLBACK");
        return false;
    }

    if (!recalc_session_cost_locked(db, message.session_id)) {
        exec_simple(db, "ROLLBACK");
        return false;
    }

    if (!exec_simple(db, "COMMIT")) {
        exec_simple(db, "ROLLBACK");
        return false;
    }

    {
        aida::events::session_updated_t evt;
        evt.session_id     = message.session_id;
        evt.fields_changed = "messages,total_cost";
        aida::events::publish(aida::events::event_session_updated, evt);
    }

    return true;
}


bool list_messages(const std::string& session_id,
                   std::vector<message_t>& out,
                   int limit)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        return false;
    }
    out.clear();

    std::string sql =
        "SELECT id, session_id, role, agent, model_provider_id, model_id, created "
        "FROM messages WHERE session_id = ? ORDER BY created ASC, id ASC";
    if (limit > 0) {
        sql += " LIMIT ";
        sql += std::to_string(limit);
    }

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "list_messages_prepare");
        return false;
    }
    if (!bind_text(stmt, 1, session_id)) {
        sqlite3_finalize(stmt);
        set_last_error("list_messages_bind_failed");
        return false;
    }

    std::vector<message_t> rows;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        message_t m;
        m.id                = column_text_or_empty(stmt, 0);
        m.session_id        = column_text_or_empty(stmt, 1);
        m.role              = role_from_string(column_text_or_empty(stmt, 2));
        m.agent             = column_text_or_empty(stmt, 3);
        m.model_provider_id = column_text_or_empty(stmt, 4);
        m.model_id          = column_text_or_empty(stmt, 5);
        m.created_unix      = column_int64_or_zero(stmt, 6);
        rows.push_back(std::move(m));
    }
    sqlite3_finalize(stmt);

    const char* sql_parts =
        "SELECT kind, payload_json FROM parts WHERE message_id = ? ORDER BY sequence ASC, id ASC";
    sqlite3_stmt* pstmt = nullptr;
    rc = sqlite3_prepare_v2(db, sql_parts, -1, &pstmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "list_parts_prepare");
        return false;
    }
    for (auto& m : rows) {
        sqlite3_reset(pstmt);
        sqlite3_clear_bindings(pstmt);
        if (!bind_text(pstmt, 1, m.id)) {
            sqlite3_finalize(pstmt);
            set_last_error("list_parts_bind_failed");
            return false;
        }
        while (sqlite3_step(pstmt) == SQLITE_ROW) {
            const std::string kind = column_text_or_empty(pstmt, 0);
            const std::string payload = column_text_or_empty(pstmt, 1);
            auto j = nlohmann::json::parse(payload, nullptr, false);
            if (j.is_discarded()) j = nlohmann::json::object();
            m.parts.push_back(deserialize_part(kind, j));
        }
    }
    sqlite3_finalize(pstmt);

    out = std::move(rows);
    return true;
}


bool update_message(const message_t& message)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        return false;
    }
    if (message.id.empty() || message.session_id.empty()) {
        set_last_error("invalid_message_id");
        return false;
    }

    if (!exec_simple(db, "BEGIN IMMEDIATE")) return false;

    const char* sql =
        "UPDATE messages SET session_id = ?, role = ?, agent = ?, "
        "model_provider_id = ?, model_id = ?, created = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "update_msg_prepare");
        exec_simple(db, "ROLLBACK");
        return false;
    }
    const int64_t created = message.created_unix == 0 ? now_unix_ms() : message.created_unix;
    bool ok = bind_text(stmt, 1, message.session_id) &&
              bind_text(stmt, 2, role_to_string(message.role)) &&
              bind_text_or_null(stmt, 3, message.agent) &&
              bind_text_or_null(stmt, 4, message.model_provider_id) &&
              bind_text_or_null(stmt, 5, message.model_id) &&
              bind_int64(stmt, 6, created) &&
              bind_text(stmt, 7, message.id);
    if (ok) rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    sqlite3_finalize(stmt);
    if (!ok || rc != SQLITE_DONE) {
        set_last_error_sqlite(db, "update_msg_step");
        exec_simple(db, "ROLLBACK");
        return false;
    }
    if (changes == 0) {
        exec_simple(db, "ROLLBACK");
        set_last_error("message_not_found");
        return false;
    }

    if (!delete_parts_for_message_locked(db, message.id)) {
        exec_simple(db, "ROLLBACK");
        return false;
    }
    if (!insert_parts_locked(db, message.id, message.parts)) {
        exec_simple(db, "ROLLBACK");
        return false;
    }
    if (!recalc_session_cost_locked(db, message.session_id)) {
        exec_simple(db, "ROLLBACK");
        return false;
    }
    if (!exec_simple(db, "COMMIT")) {
        exec_simple(db, "ROLLBACK");
        return false;
    }

    {
        aida::events::session_updated_t evt;
        evt.session_id     = message.session_id;
        evt.fields_changed = "messages,total_cost";
        aida::events::publish(aida::events::event_session_updated, evt);
    }

    return true;
}


bool remove_message(const std::string& session_id, const std::string& message_id)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        return false;
    }
    if (session_id.empty() || message_id.empty()) {
        set_last_error("invalid_message_id");
        return false;
    }

    if (!exec_simple(db, "BEGIN IMMEDIATE")) return false;

    if (!delete_parts_for_message_locked(db, message_id)) {
        exec_simple(db, "ROLLBACK");
        return false;
    }

    const char* sql_del_msg =
        "DELETE FROM messages WHERE id = ? AND session_id = ?";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql_del_msg, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "remove_message_prepare");
        exec_simple(db, "ROLLBACK");
        return false;
    }
    bool ok = bind_text(stmt, 1, message_id) &&
              bind_text(stmt, 2, session_id);
    if (ok) rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    sqlite3_finalize(stmt);
    if (!ok || rc != SQLITE_DONE) {
        set_last_error_sqlite(db, "remove_message_step");
        exec_simple(db, "ROLLBACK");
        return false;
    }
    if (changes == 0) {
        exec_simple(db, "ROLLBACK");
        set_last_error("message_not_found");
        return false;
    }

    if (!recalc_session_cost_locked(db, session_id)) {
        exec_simple(db, "ROLLBACK");
        return false;
    }

    if (!exec_simple(db, "COMMIT")) {
        exec_simple(db, "ROLLBACK");
        return false;
    }

    {
        aida::events::session_updated_t evt;
        evt.session_id     = session_id;
        evt.fields_changed = "messages,total_cost";
        aida::events::publish(aida::events::event_session_updated, evt);
    }

    return true;
}


double session_cost(const std::string& session_id)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    session_info_t info;
    if (!get(session_id, info)) return 0.0;
    return info.total_cost_usd;
}


usage_tokens_t session_tokens(const std::string& session_id)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    usage_tokens_t agg;
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        return agg;
    }
    const char* sql =
        "SELECT p.payload_json FROM parts p "
        "JOIN messages m ON p.message_id = m.id "
        "WHERE m.session_id = ? AND p.kind = 'step_finish'";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "session_tokens_prepare");
        return agg;
    }
    if (!bind_text(stmt, 1, session_id)) {
        sqlite3_finalize(stmt);
        set_last_error("session_tokens_bind_failed");
        return agg;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const std::string payload = column_text_or_empty(stmt, 0);
        auto j = nlohmann::json::parse(payload, nullptr, false);
        if (j.is_discarded()) continue;
        const auto tk = j.value("tokens", nlohmann::json::object());
        agg.input       += tk.value("input", static_cast<int64_t>(0));
        agg.output      += tk.value("output", static_cast<int64_t>(0));
        agg.reasoning   += tk.value("reasoning", static_cast<int64_t>(0));
        agg.cache_read  += tk.value("cache_read", static_cast<int64_t>(0));
        agg.cache_write += tk.value("cache_write", static_cast<int64_t>(0));
    }
    sqlite3_finalize(stmt);
    return agg;
}


bool get_session_todos(const std::string& session_id, std::string& out)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    out.clear();
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        return false;
    }
    if (session_id.empty()) {
        set_last_error("invalid_session_id");
        return false;
    }

    const char* sql = "SELECT todos_json FROM sessions WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "get_session_todos_prepare");
        return false;
    }
    if (!bind_text(stmt, 1, session_id)) {
        sqlite3_finalize(stmt);
        set_last_error("get_session_todos_bind_failed");
        return false;
    }
    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out = column_text_or_empty(stmt, 0);
        found = true;
    }
    sqlite3_finalize(stmt);
    if (!found) {
        set_last_error("session_not_found");
        return false;
    }
    return true;
}


bool set_session_todos(const std::string& session_id, const std::string& todos_text)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        return false;
    }
    if (session_id.empty()) {
        set_last_error("invalid_session_id");
        return false;
    }

    const char* sql =
        "UPDATE sessions SET todos_json = ?, time_updated = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "set_session_todos_prepare");
        return false;
    }
    bool ok = bind_text(stmt, 1, todos_text) &&
              bind_int64(stmt, 2, now_unix_ms()) &&
              bind_text(stmt, 3, session_id);
    if (ok) rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    sqlite3_finalize(stmt);
    if (!ok || rc != SQLITE_DONE) {
        set_last_error_sqlite(db, "set_session_todos_step");
        return false;
    }
    if (changes == 0) {
        set_last_error("session_not_found");
        return false;
    }

    {
        aida::events::session_updated_t evt;
        evt.session_id     = session_id;
        evt.fields_changed = "todos";
        aida::events::publish(aida::events::event_session_updated, evt);
    }

    return true;
}


bool upsert_proposal_audit(proposal_audit_record_t record)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        return false;
    }
    if (!proposal_audit_valid(record)) {
        set_last_error("invalid_proposal_audit_record");
        return false;
    }
    const std::int64_t current_time = now_unix_ms();
    if (record.created_unix <= 0) record.created_unix = current_time;
    record.updated_unix = current_time;
    if (!exec_simple(db, "BEGIN IMMEDIATE")) return false;
    auto rollback = [&] { static_cast<void>(exec_simple(db, "ROLLBACK")); };
    if (!ensure_proposal_audit_session_locked(
            db, record.session_id, current_time)) {
        rollback();
        return false;
    }

    const char* upsert_sql =
        "INSERT INTO proposal_audits("
        "audit_id,proposal_id,family,kind,session_id,source_index,source_timestamp,"
        "source_fingerprint,target_id,target_view_id,target_generation,source_revision,"
        "target_overlay_revision,before_hash,after_hash,result_hash,result_revision,"
        "provenance,detail,lifecycle_state,outcome,task_id,diagnostic_id,"
        "undo_revert_identity,created,updated,revalidation_required)"
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(audit_id) DO UPDATE SET "
        "proposal_id=excluded.proposal_id,family=excluded.family,kind=excluded.kind,"
        "session_id=excluded.session_id,source_index=excluded.source_index,"
        "source_timestamp=excluded.source_timestamp,"
        "source_fingerprint=excluded.source_fingerprint,target_id=excluded.target_id,"
        "target_view_id=excluded.target_view_id,"
        "target_generation=excluded.target_generation,source_revision=excluded.source_revision,"
        "target_overlay_revision=excluded.target_overlay_revision,"
        "before_hash=excluded.before_hash,after_hash=excluded.after_hash,"
        "result_hash=excluded.result_hash,result_revision=excluded.result_revision,"
        "provenance=excluded.provenance,detail=excluded.detail,"
        "lifecycle_state=excluded.lifecycle_state,outcome=excluded.outcome,"
        "task_id=excluded.task_id,diagnostic_id=excluded.diagnostic_id,"
        "undo_revert_identity=excluded.undo_revert_identity,updated=excluded.updated,"
        "revalidation_required=excluded.revalidation_required";
    sqlite3_stmt* upsert = nullptr;
    int rc = sqlite3_prepare_v2(db, upsert_sql, -1, &upsert, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "proposal_audit_upsert_prepare");
        rollback();
        return false;
    }
    bool ok =
        bind_text(upsert, 1, record.audit_id) &&
        bind_text(upsert, 2, record.proposal_id) &&
        bind_text(upsert, 3, record.family) &&
        bind_text(upsert, 4, record.kind) &&
        bind_text(upsert, 5, record.session_id) &&
        bind_text(upsert, 6, std::to_string(record.source_index)) &&
        bind_int64(upsert, 7, record.source_timestamp) &&
        bind_text(upsert, 8, std::to_string(record.source_fingerprint)) &&
        bind_text(upsert, 9, record.target_id) &&
        bind_text(upsert, 10, record.target_view_id) &&
        bind_text(upsert, 11, std::to_string(record.target_generation)) &&
        bind_text(upsert, 12, std::to_string(record.source_revision)) &&
        bind_text(upsert, 13, std::to_string(record.target_overlay_revision)) &&
        bind_text(upsert, 14, record.before_hash) &&
        bind_text(upsert, 15, record.after_hash) &&
        bind_text(upsert, 16, record.result_hash) &&
        bind_text(upsert, 17, std::to_string(record.result_revision)) &&
        bind_text(upsert, 18, record.provenance) &&
        bind_text(upsert, 19, record.detail) &&
        bind_text(upsert, 20, record.lifecycle_state) &&
        bind_text(upsert, 21, record.outcome) &&
        bind_text(upsert, 22, record.task_id) &&
        bind_text(upsert, 23, record.diagnostic_id) &&
        bind_text(upsert, 24, record.undo_revert_identity) &&
        bind_int64(upsert, 25, record.created_unix) &&
        bind_int64(upsert, 26, record.updated_unix) &&
        bind_int(upsert, 27, record.revalidation_required ? 1 : 0);
    if (ok) rc = sqlite3_step(upsert);
    sqlite3_finalize(upsert);
    if (!ok || rc != SQLITE_DONE) {
        set_last_error_sqlite(db, "proposal_audit_upsert_step");
        rollback();
        return false;
    }

    sqlite3_stmt* delete_hunks = nullptr;
    rc = sqlite3_prepare_v2(db,
        "DELETE FROM proposal_audit_hunks WHERE audit_id=?", -1,
        &delete_hunks, nullptr);
    if (rc != SQLITE_OK || !bind_text(delete_hunks, 1, record.audit_id) ||
        sqlite3_step(delete_hunks) != SQLITE_DONE) {
        if (delete_hunks) sqlite3_finalize(delete_hunks);
        set_last_error_sqlite(db, "proposal_audit_hunks_delete");
        rollback();
        return false;
    }
    sqlite3_finalize(delete_hunks);

    if (!record.hunks.empty()) {
        const char* hunk_sql =
            "INSERT INTO proposal_audit_hunks(audit_id,hunk_index,old_start,old_count,"
            "new_start,new_count,decision,before_hash,after_hash) VALUES(?,?,?,?,?,?,?,?,?)";
        sqlite3_stmt* hunk_stmt = nullptr;
        rc = sqlite3_prepare_v2(db, hunk_sql, -1, &hunk_stmt, nullptr);
        if (rc != SQLITE_OK) {
            set_last_error_sqlite(db, "proposal_audit_hunks_prepare");
            rollback();
            return false;
        }
        for (const auto& hunk : record.hunks) {
            sqlite3_reset(hunk_stmt);
            sqlite3_clear_bindings(hunk_stmt);
            ok = bind_text(hunk_stmt, 1, record.audit_id) &&
                bind_int64(hunk_stmt, 2, hunk.index) &&
                bind_int64(hunk_stmt, 3, hunk.old_start) &&
                bind_int64(hunk_stmt, 4, hunk.old_count) &&
                bind_int64(hunk_stmt, 5, hunk.new_start) &&
                bind_int64(hunk_stmt, 6, hunk.new_count) &&
                bind_text(hunk_stmt, 7, hunk.decision) &&
                bind_text(hunk_stmt, 8, hunk.before_hash) &&
                bind_text(hunk_stmt, 9, hunk.after_hash);
            if (!ok || sqlite3_step(hunk_stmt) != SQLITE_DONE) {
                sqlite3_finalize(hunk_stmt);
                set_last_error_sqlite(db, "proposal_audit_hunks_step");
                rollback();
                return false;
            }
        }
        sqlite3_finalize(hunk_stmt);
    }

    const char* event_sql =
        "INSERT INTO proposal_audit_events(audit_id,outcome,lifecycle_state,detail,"
        "event_time,task_id,diagnostic_id,result_revision,result_hash,"
        "undo_revert_identity) VALUES(?,?,?,?,?,?,?,?,?,?)";
    sqlite3_stmt* event_stmt = nullptr;
    rc = sqlite3_prepare_v2(db, event_sql, -1, &event_stmt, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "proposal_audit_event_prepare");
        rollback();
        return false;
    }
    ok = bind_text(event_stmt, 1, record.audit_id) &&
        bind_text(event_stmt, 2, record.outcome) &&
        bind_text(event_stmt, 3, record.lifecycle_state) &&
        bind_text(event_stmt, 4, record.detail) &&
        bind_int64(event_stmt, 5, record.updated_unix) &&
        bind_text(event_stmt, 6, record.task_id) &&
        bind_text(event_stmt, 7, record.diagnostic_id) &&
        bind_text(event_stmt, 8, std::to_string(record.result_revision)) &&
        bind_text(event_stmt, 9, record.result_hash) &&
        bind_text(event_stmt, 10, record.undo_revert_identity);
    if (ok) rc = sqlite3_step(event_stmt);
    sqlite3_finalize(event_stmt);
    if (!ok || rc != SQLITE_DONE) {
        set_last_error_sqlite(db, "proposal_audit_event_step");
        rollback();
        return false;
    }

    sqlite3_stmt* prune_events = nullptr;
    rc = sqlite3_prepare_v2(db,
        "DELETE FROM proposal_audit_events WHERE audit_id=? AND id NOT IN "
        "(SELECT id FROM proposal_audit_events WHERE audit_id=? ORDER BY id DESC LIMIT 64)",
        -1, &prune_events, nullptr);
    if (rc != SQLITE_OK || !bind_text(prune_events, 1, record.audit_id) ||
        !bind_text(prune_events, 2, record.audit_id) ||
        sqlite3_step(prune_events) != SQLITE_DONE) {
        if (prune_events) sqlite3_finalize(prune_events);
        set_last_error_sqlite(db, "proposal_audit_events_prune");
        rollback();
        return false;
    }
    sqlite3_finalize(prune_events);

    sqlite3_stmt* prune_session = nullptr;
    rc = sqlite3_prepare_v2(db,
        "DELETE FROM proposal_audits WHERE session_id=? AND audit_id NOT IN "
        "(SELECT audit_id FROM proposal_audits WHERE session_id=? "
        "ORDER BY updated DESC LIMIT 512)", -1, &prune_session, nullptr);
    if (rc != SQLITE_OK || !bind_text(prune_session, 1, record.session_id) ||
        !bind_text(prune_session, 2, record.session_id) ||
        sqlite3_step(prune_session) != SQLITE_DONE) {
        if (prune_session) sqlite3_finalize(prune_session);
        set_last_error_sqlite(db, "proposal_audit_session_prune");
        rollback();
        return false;
    }
    sqlite3_finalize(prune_session);
    if (!exec_simple(db,
        "DELETE FROM proposal_audits WHERE audit_id NOT IN "
        "(SELECT audit_id FROM proposal_audits ORDER BY updated DESC LIMIT 4096)")) {
        rollback();
        return false;
    }
    if (!exec_simple(db,
        "DELETE FROM proposal_audit_sessions WHERE session_id NOT IN "
        "(SELECT DISTINCT session_id FROM proposal_audits)")) {
        rollback();
        return false;
    }
    if (!exec_simple(db, "COMMIT")) {
        rollback();
        return false;
    }
    return true;
}


bool restore_proposal_audits(const std::string& session_id,
                             std::vector<proposal_audit_record_t>& out,
                             std::size_t limit)
{
    std::lock_guard<std::recursive_mutex> store_lock(g_store_mutex);
    out.clear();
    sqlite3* db = db_handle();
    if (!db) {
        set_last_error("not_initialized");
        return false;
    }
    if (session_id.empty() || session_id.size() > 128) {
        set_last_error("invalid_session_id");
        return false;
    }
    limit = (std::max)(std::size_t{1}, (std::min)(limit, std::size_t{64}));
    if (!exec_simple(db, "BEGIN IMMEDIATE")) return false;
    auto rollback = [&] {
        static_cast<void>(exec_simple(db, "ROLLBACK"));
        out.clear();
    };
    const std::string sql = std::string("SELECT ") + kSelectProposalAuditFields +
        " FROM proposal_audits WHERE session_id=? AND (revalidation_required=1 OR "
        "lifecycle_state IN ('validating','pending_review','reviewed','applying')) "
        "ORDER BY updated DESC LIMIT ?";
    sqlite3_stmt* select = nullptr;
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &select, nullptr);
    if (rc != SQLITE_OK || !bind_text(select, 1, session_id) ||
        !bind_int64(select, 2, static_cast<std::int64_t>(limit))) {
        if (select) sqlite3_finalize(select);
        set_last_error_sqlite(db, "proposal_audit_restore_prepare");
        rollback();
        return false;
    }
    while ((rc = sqlite3_step(select)) == SQLITE_ROW) {
        static constexpr int uint64_text_columns[] = {5, 7, 10, 11, 12, 16};
        if (std::any_of(std::begin(uint64_text_columns),
                std::end(uint64_text_columns),
                [&](int column) { return !uint64_text_column_valid(select, column); }) ||
            sqlite3_column_type(select, 6) != SQLITE_INTEGER ||
            sqlite3_column_type(select, 24) != SQLITE_INTEGER ||
            sqlite3_column_type(select, 25) != SQLITE_INTEGER ||
            sqlite3_column_type(select, 26) != SQLITE_INTEGER) {
            sqlite3_finalize(select);
            set_last_error("invalid_persisted_proposal_audit_type");
            rollback();
            return false;
        }
        proposal_audit_record_t record;
        hydrate_proposal_audit(select, record);
        if (!proposal_audit_valid(record)) {
            sqlite3_finalize(select);
            set_last_error("invalid_persisted_proposal_audit");
            rollback();
            return false;
        }
        out.push_back(std::move(record));
    }
    sqlite3_finalize(select);
    if (rc != SQLITE_DONE) {
        set_last_error_sqlite(db, "proposal_audit_restore_select");
        rollback();
        return false;
    }
    if (!out.empty() &&
        !proposal_audit_session_exists_locked(db, session_id)) {
        set_last_error("proposal_audit_parent_identity_missing");
        rollback();
        return false;
    }

    sqlite3_stmt* hunk_select = nullptr;
    rc = sqlite3_prepare_v2(db,
        "SELECT hunk_index,old_start,old_count,new_start,new_count,decision,"
        "before_hash,after_hash FROM proposal_audit_hunks WHERE audit_id=? "
        "ORDER BY hunk_index", -1, &hunk_select, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "proposal_audit_restore_hunks_prepare");
        rollback();
        return false;
    }
    for (auto& record : out) {
        sqlite3_reset(hunk_select);
        sqlite3_clear_bindings(hunk_select);
        if (!bind_text(hunk_select, 1, record.audit_id)) {
            sqlite3_finalize(hunk_select);
            set_last_error("proposal_audit_restore_hunks_bind");
            rollback();
            return false;
        }
        while ((rc = sqlite3_step(hunk_select)) == SQLITE_ROW) {
            if (record.hunks.size() >= 512U) {
                sqlite3_finalize(hunk_select);
                set_last_error("persisted_proposal_hunk_limit_exceeded");
                rollback();
                return false;
            }
            if (sqlite3_column_type(hunk_select, 0) != SQLITE_INTEGER ||
                sqlite3_column_type(hunk_select, 1) != SQLITE_INTEGER ||
                sqlite3_column_type(hunk_select, 2) != SQLITE_INTEGER ||
                sqlite3_column_type(hunk_select, 3) != SQLITE_INTEGER ||
                sqlite3_column_type(hunk_select, 4) != SQLITE_INTEGER) {
                sqlite3_finalize(hunk_select);
                set_last_error("invalid_persisted_proposal_hunk_type");
                rollback();
                return false;
            }
            const std::int64_t raw_index = column_int64_or_zero(hunk_select, 0);
            const std::int64_t raw_old_start = column_int64_or_zero(hunk_select, 1);
            const std::int64_t raw_old_count = column_int64_or_zero(hunk_select, 2);
            const std::int64_t raw_new_start = column_int64_or_zero(hunk_select, 3);
            const std::int64_t raw_new_count = column_int64_or_zero(hunk_select, 4);
            constexpr std::int64_t maximum_hunk_coordinate = 16 * 1024 * 1024;
            if (raw_index < 0 ||
                raw_index > (std::numeric_limits<std::uint32_t>::max)() ||
                raw_old_start < 0 || raw_old_start > maximum_hunk_coordinate ||
                raw_old_count < 0 || raw_old_count > maximum_hunk_coordinate ||
                raw_new_start < 0 || raw_new_start > maximum_hunk_coordinate ||
                raw_new_count < 0 || raw_new_count > maximum_hunk_coordinate ||
                raw_old_start + raw_old_count > maximum_hunk_coordinate ||
                raw_new_start + raw_new_count > maximum_hunk_coordinate) {
                sqlite3_finalize(hunk_select);
                set_last_error("invalid_persisted_proposal_hunk_range");
                rollback();
                return false;
            }
            proposal_audit_hunk_t hunk;
            hunk.index = static_cast<std::uint32_t>(raw_index);
            hunk.old_start = static_cast<std::int32_t>(raw_old_start);
            hunk.old_count = static_cast<std::int32_t>(raw_old_count);
            hunk.new_start = static_cast<std::int32_t>(raw_new_start);
            hunk.new_count = static_cast<std::int32_t>(raw_new_count);
            hunk.decision = column_text_or_empty(hunk_select, 5);
            hunk.before_hash = column_text_or_empty(hunk_select, 6);
            hunk.after_hash = column_text_or_empty(hunk_select, 7);
            record.hunks.push_back(std::move(hunk));
        }
        if (rc != SQLITE_DONE) {
            sqlite3_finalize(hunk_select);
            set_last_error_sqlite(db, "proposal_audit_restore_hunks_select");
            rollback();
            return false;
        }
        if (!proposal_audit_valid(record)) {
            sqlite3_finalize(hunk_select);
            set_last_error("invalid_persisted_proposal_hunks");
            rollback();
            return false;
        }
    }
    sqlite3_finalize(hunk_select);

    sqlite3_stmt* mark_stale = nullptr;
    rc = sqlite3_prepare_v2(db,
        "UPDATE proposal_audits SET lifecycle_state='stale',outcome='stale',"
        "detail=?,updated=?,revalidation_required=1 WHERE audit_id=? AND "
        "lifecycle_state<>'stale'", -1, &mark_stale, nullptr);
    if (rc != SQLITE_OK) {
        set_last_error_sqlite(db, "proposal_audit_restore_update_prepare");
        rollback();
        return false;
    }
    const std::int64_t restored_time = now_unix_ms();
    for (auto& record : out) {
        if (record.lifecycle_state == "stale") continue;
        record.lifecycle_state = "stale";
        record.outcome = "stale";
        record.detail = "Restored proposal review requires explicit target revalidation; no proposal was automatically applied.";
        record.updated_unix = restored_time;
        record.revalidation_required = true;
        sqlite3_reset(mark_stale);
        sqlite3_clear_bindings(mark_stale);
        if (!bind_text(mark_stale, 1, record.detail) ||
            !bind_int64(mark_stale, 2, record.updated_unix) ||
            !bind_text(mark_stale, 3, record.audit_id) ||
            sqlite3_step(mark_stale) != SQLITE_DONE) {
            sqlite3_finalize(mark_stale);
            set_last_error_sqlite(db, "proposal_audit_restore_update");
            rollback();
            return false;
        }
        sqlite3_stmt* event = nullptr;
        rc = sqlite3_prepare_v2(db,
            "INSERT INTO proposal_audit_events(audit_id,outcome,lifecycle_state,detail,"
            "event_time,task_id,diagnostic_id,result_revision,result_hash,"
            "undo_revert_identity) VALUES(?,'stale','stale',?,?,?,?,?,?,?)",
            -1, &event, nullptr);
        const bool event_ok = rc == SQLITE_OK &&
            bind_text(event, 1, record.audit_id) &&
            bind_text(event, 2, record.detail) &&
            bind_int64(event, 3, record.updated_unix) &&
            bind_text(event, 4, record.task_id) &&
            bind_text(event, 5, record.diagnostic_id) &&
            bind_text(event, 6, std::to_string(record.result_revision)) &&
            bind_text(event, 7, record.result_hash) &&
            bind_text(event, 8, record.undo_revert_identity) &&
            sqlite3_step(event) == SQLITE_DONE;
        if (event) sqlite3_finalize(event);
        if (!event_ok) {
            set_last_error_sqlite(db, "proposal_audit_restore_event");
            sqlite3_finalize(mark_stale);
            rollback();
            return false;
        }
        sqlite3_stmt* prune = nullptr;
        rc = sqlite3_prepare_v2(db,
            "DELETE FROM proposal_audit_events WHERE audit_id=? AND id NOT IN "
            "(SELECT id FROM proposal_audit_events WHERE audit_id=? "
            "ORDER BY id DESC LIMIT 64)", -1, &prune, nullptr);
        const bool prune_ok = rc == SQLITE_OK &&
            bind_text(prune, 1, record.audit_id) &&
            bind_text(prune, 2, record.audit_id) &&
            sqlite3_step(prune) == SQLITE_DONE;
        if (prune) sqlite3_finalize(prune);
        if (!prune_ok) {
            set_last_error_sqlite(db, "proposal_audit_restore_event_prune");
            sqlite3_finalize(mark_stale);
            rollback();
            return false;
        }
    }
    sqlite3_finalize(mark_stale);
    if (!exec_simple(db, "COMMIT")) {
        rollback();
        return false;
    }
    return true;
}


const std::string& last_error()
{
    std::lock_guard<std::mutex> lk(g_error_mutex);
    static thread_local std::string snapshot;
    snapshot = g_last_error;
    return snapshot;
}


}
