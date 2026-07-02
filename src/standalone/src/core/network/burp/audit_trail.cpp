#include "audit_trail.hpp"

#include "evidence_store.hpp"
#include "findings_db.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <mutex>

namespace aida {
namespace burp {
namespace audit_trail {
namespace {

std::mutex g_error_mutex;
std::string g_last_error;
std::atomic<bool> g_initialized{false};

void set_error(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(g_error_mutex);
    g_last_error = msg;
}

bool bind_text(sqlite3_stmt* stmt, int idx, const std::string& s)
{
    return sqlite3_bind_text(stmt, idx, s.c_str(), static_cast<int>(s.size()), SQLITE_TRANSIENT) == SQLITE_OK;
}

bool bind_json(sqlite3_stmt* stmt, int idx, const nlohmann::json& j)
{
    return bind_text(stmt, idx, j.dump());
}

std::string column_text(sqlite3_stmt* stmt, int col)
{
    if (sqlite3_column_type(stmt, col) == SQLITE_NULL) return std::string();
    const unsigned char* p = sqlite3_column_text(stmt, col);
    const int n = sqlite3_column_bytes(stmt, col);
    if (!p || n <= 0) return std::string();
    return std::string(reinterpret_cast<const char*>(p), static_cast<size_t>(n));
}

nlohmann::json parse_json_or(const std::string& raw, nlohmann::json fallback)
{
    if (raw.empty()) return fallback;
    try {
        return nlohmann::json::parse(raw);
    } catch (...) {
        return fallback;
    }
}

std::string lower_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool sensitive_key(const std::string& key)
{
    const std::string k = lower_copy(key);
    static const char* terms[] = {
        "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
        "access_token", "refresh_token", "authorization", "cookie", "session",
        "license", "private_key", "credential", "bearer", "auth"
    };
    for (const char* term : terms) {
        if (k.find(term) != std::string::npos) return true;
    }
    return false;
}

nlohmann::json summarize_json(const nlohmann::json& input, size_t depth = 0)
{
    if (depth > 4) return "[depth_limit]";
    if (input.is_object()) {
        nlohmann::json out = nlohmann::json::object();
        nlohmann::json keys = nlohmann::json::array();
        size_t emitted = 0;
        for (auto it = input.begin(); it != input.end(); ++it) {
            keys.push_back(it.key());
            if (emitted < 32) {
                if (sensitive_key(it.key())) {
                    out[it.key()] = "[redacted]";
                }
                else {
                    out[it.key()] = summarize_json(it.value(), depth + 1);
                }
                ++emitted;
            }
        }
        if (input.size() > emitted) out["_truncated_keys"] = input.size() - emitted;
        out["_keys"] = keys;
        return out;
    }
    if (input.is_array()) {
        nlohmann::json out = nlohmann::json::object();
        out["_array_count"] = input.size();
        out["_items"] = nlohmann::json::array();
        const size_t n = (std::min)(input.size(), static_cast<size_t>(8));
        for (size_t i = 0; i < n; ++i) out["_items"].push_back(summarize_json(input[i], depth + 1));
        return out;
    }
    if (input.is_string()) {
        return evidence_store::redact_sensitive_text(input.get<std::string>(), 512);
    }
    if (input.is_number() || input.is_boolean() || input.is_null()) return input;
    return "[unsupported]";
}

record_t row_to_record(sqlite3_stmt* stmt)
{
    record_t r;
    r.id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
    r.session_id = column_text(stmt, 1);
    r.scan_id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 2));
    r.timestamp_ms = static_cast<uint64_t>(sqlite3_column_int64(stmt, 3));
    r.tool_name = column_text(stmt, 4);
    r.parameters_preview_json = parse_json_or(column_text(stmt, 5), nlohmann::json::object());
    r.parameters_hash = column_text(stmt, 6);
    r.result_summary_json = parse_json_or(column_text(stmt, 7), nlohmann::json::object());
    r.result_hash = column_text(stmt, 8);
    r.duration_ms = static_cast<uint64_t>(sqlite3_column_int64(stmt, 9));
    r.caller = column_text(stmt, 10);
    r.success = sqlite3_column_int(stmt, 11) != 0;
    r.error_message = column_text(stmt, 12);
    return r;
}

std::string select_fields()
{
    return "id,session_id,scan_id,timestamp_ms,tool_name,parameters_json,parameters_hash,result_summary_json,result_hash,duration_ms,caller,success,error_message";
}

}

bool initialize()
{
    if (g_initialized.load(std::memory_order_acquire)) return true;
    if (!findings_db::initialize()) {
        set_error(findings_db::last_error());
        return false;
    }
    g_initialized.store(true, std::memory_order_release);
    return true;
}

void shutdown()
{
    g_initialized.store(false, std::memory_order_release);
}

bool record(const event_t& event, uint64_t* out_id)
{
    if (!initialize()) return false;
    if (event.tool_name.empty()) {
        set_error("invalid_tool_name");
        return false;
    }
    nlohmann::json params_preview = summarize_json(evidence_store::redact_sensitive_json(event.parameters_json));
    nlohmann::json result_summary = summarize_json(evidence_store::redact_sensitive_json(event.result_json));
    const std::string params_canon = params_preview.dump();
    const std::string result_canon = result_summary.dump();
    const std::string params_hash = evidence_store::sha256_hex(params_canon);
    const std::string result_hash = evidence_store::sha256_hex(result_canon);
    const uint64_t ts = event.timestamp_ms ? event.timestamp_ms : findings_db::now_ms();
    bool ok = findings_db::with_db("audit_trail_record", [&](sqlite3* db) {
        const char* sql =
            "INSERT INTO audit_trail(session_id,scan_id,timestamp_ms,tool_name,parameters_json,parameters_hash,result_summary_json,result_hash,duration_ms,caller,success,error_message) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        bind_text(stmt, 1, event.session_id);
        sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(event.scan_id));
        sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(ts));
        bind_text(stmt, 4, event.tool_name);
        bind_json(stmt, 5, params_preview);
        bind_text(stmt, 6, params_hash);
        bind_json(stmt, 7, result_summary);
        bind_text(stmt, 8, result_hash);
        sqlite3_bind_int64(stmt, 9, static_cast<sqlite3_int64>(event.duration_ms));
        bind_text(stmt, 10, evidence_store::redact_sensitive_text(event.caller, 256));
        sqlite3_bind_int(stmt, 11, event.success ? 1 : 0);
        bind_text(stmt, 12, evidence_store::redact_sensitive_text(event.error_message, 2048));
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE && out_id) *out_id = static_cast<uint64_t>(sqlite3_last_insert_rowid(db));
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    });
    if (!ok) set_error(findings_db::last_error());
    return ok;
}

std::vector<record_t> query(const query_filter_t& filter)
{
    std::vector<record_t> out;
    if (!initialize()) return out;
    findings_db::with_db("audit_trail_query", [&](sqlite3* db) {
        std::string sql = "SELECT " + select_fields() + " FROM audit_trail WHERE 1=1";
        if (!filter.session_id.empty()) sql += " AND session_id=?";
        if (filter.has_scan_id) sql += " AND scan_id=?";
        if (!filter.tool_name_substring.empty()) sql += " AND tool_name LIKE ?";
        if (filter.since_ms != 0) sql += " AND timestamp_ms>=?";
        if (filter.until_ms != 0) sql += " AND timestamp_ms<=?";
        if (filter.failures_only) sql += " AND success=0";
        sql += " ORDER BY timestamp_ms DESC,id DESC";
        if (filter.limit > 0) sql += " LIMIT ?";
        if (filter.offset > 0) sql += " OFFSET ?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return false;
        int idx = 1;
        if (!filter.session_id.empty()) bind_text(stmt, idx++, filter.session_id);
        if (filter.has_scan_id) sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.scan_id));
        if (!filter.tool_name_substring.empty()) bind_text(stmt, idx++, "%" + filter.tool_name_substring + "%");
        if (filter.since_ms != 0) sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.since_ms));
        if (filter.until_ms != 0) sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.until_ms));
        if (filter.limit > 0) sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.limit));
        if (filter.offset > 0) sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.offset));
        while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(row_to_record(stmt));
        sqlite3_finalize(stmt);
        return true;
    });
    return out;
}

nlohmann::json export_json(const query_filter_t& filter)
{
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& rec : query(filter)) arr.push_back(record_to_json(rec));
    nlohmann::json doc;
    doc["count"] = arr.size();
    doc["audit_trail"] = std::move(arr);
    return doc;
}

nlohmann::json record_to_json(const record_t& record)
{
    nlohmann::json j;
    j["id"] = record.id;
    j["session_id"] = record.session_id;
    j["scan_id"] = record.scan_id;
    j["timestamp_ms"] = record.timestamp_ms;
    j["tool_name"] = record.tool_name;
    j["parameters_hash"] = record.parameters_hash;
    j["result_hash"] = record.result_hash;
    j["parameters_preview"] = record.parameters_preview_json;
    j["result_summary"] = record.result_summary_json;
    j["duration_ms"] = record.duration_ms;
    j["caller"] = record.caller;
    j["success"] = record.success;
    j["error_message"] = record.error_message;
    return j;
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(g_error_mutex);
    return g_last_error;
}

}
}
}
