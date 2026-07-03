#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include "findings_db.hpp"

#include "evidence_store.hpp"
#include "vuln_taxonomy.hpp"
#include "../../../helpers/diag_log.hpp"

#include <windows.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <exception>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <unordered_map>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Shell32.lib")

namespace aida {
namespace burp {
namespace findings_db {
namespace {

std::mutex g_error_mutex;
std::string g_last_error;
std::atomic<sqlite3*> g_db{nullptr};
std::mutex g_init_mutex;
std::mutex g_db_mutex;
std::atomic<bool> g_initialized{false};

void set_error(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(g_error_mutex);
    g_last_error = msg;
}

void set_sqlite_error(sqlite3* db, const std::string& prefix)
{
    const char* msg = db ? sqlite3_errmsg(db) : "no database";
    set_error(prefix + ": " + (msg ? msg : "unknown"));
}

bool exec_simple(sqlite3* db, const char* sql)
{
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string e = err ? err : "sqlite_exec_failed";
        if (err) sqlite3_free(err);
        set_error("sqlite_exec: " + e);
        return false;
    }
    return true;
}

bool bind_text(sqlite3_stmt* stmt, int idx, const std::string& s)
{
    return sqlite3_bind_text(stmt, idx, s.c_str(), static_cast<int>(s.size()), SQLITE_TRANSIENT) == SQLITE_OK;
}

bool bind_nullable_text(sqlite3_stmt* stmt, int idx, const std::string& s)
{
    if (s.empty()) return sqlite3_bind_null(stmt, idx) == SQLITE_OK;
    return bind_text(stmt, idx, s);
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

std::filesystem::path resolve_database_path()
{
    wchar_t* appdata = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata)) && appdata) {
        auto dir = std::filesystem::path(appdata) / L"AiDA";
        CoTaskMemFree(appdata);
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        return dir / L"findings_db.sqlite";
    }
    return std::filesystem::current_path() / "findings_db.sqlite";
}

std::string wide_path_to_utf8(const std::filesystem::path& path)
{
    const auto wide = path.wstring();
    int needed = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) return path.string();
    std::string out;
    out.resize(static_cast<size_t>(needed - 1));
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, out.data(), needed, nullptr, nullptr);
    return out;
}

bool column_exists(sqlite3* db, const char* table, const char* column)
{
    sqlite3_stmt* stmt = nullptr;
    std::string sql = std::string("PRAGMA table_info(") + table + ")";
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return false;
    bool found = false;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (column_text(stmt, 1) == column) {
            found = true;
            break;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

bool ensure_column(sqlite3* db, const char* table, const char* column, const char* ddl)
{
    if (column_exists(db, table, column)) return true;
    return exec_simple(db, ddl);
}

bool cleanup_empty_optional_session_id(sqlite3* db, const char* table, int& total_changes)
{
    std::string sql = std::string("UPDATE ") + table + " SET session_id=NULL WHERE session_id=''";
    if (!exec_simple(db, sql.c_str())) return false;
    const int changes = sqlite3_changes(db);
    total_changes += changes;
    if (changes > 0) {
        diag::log_tagged_fmt("burp_findings", "schema_cleanup_empty_session table=%s rows=%d", table, changes);
    }
    return true;
}

bool cleanup_empty_optional_session_ids(sqlite3* db)
{
    int total_changes = 0;
    const char* tables[] = {"findings", "finding_correlations", "evidence", "scans", "audit_trail", "traffic_captures"};
    for (const char* table : tables) {
        if (!cleanup_empty_optional_session_id(db, table, total_changes)) return false;
    }
    diag::log_tagged_fmt("burp_findings", "schema_cleanup_empty_session total_rows=%d", total_changes);
    return true;
}

bool create_schema(sqlite3* db)
{
    if (!exec_simple(db, "PRAGMA journal_mode=WAL")) return false;
    if (!exec_simple(db, "PRAGMA synchronous=NORMAL")) return false;
    if (!exec_simple(db, "PRAGMA foreign_keys=ON")) return false;
    if (!exec_simple(db, "PRAGMA temp_store=MEMORY")) return false;

    const char* schema =
        "CREATE TABLE IF NOT EXISTS audit_sessions("
        "session_id TEXT PRIMARY KEY,"
        "title TEXT NOT NULL DEFAULT '',"
        "description TEXT DEFAULT '',"
        "created_ms INTEGER NOT NULL,"
        "closed_ms INTEGER DEFAULT 0,"
        "status TEXT DEFAULT 'active',"
        "scope_json TEXT DEFAULT '[]',"
        "auth_json TEXT DEFAULT '{}',"
        "notes_json TEXT DEFAULT '[]',"
        "target_count INTEGER DEFAULT 0,"
        "finding_count INTEGER DEFAULT 0,"
        "scan_count INTEGER DEFAULT 0,"
        "metadata_json TEXT DEFAULT '{}'"
        ");"
        "CREATE TABLE IF NOT EXISTS audit_targets("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "session_id TEXT NOT NULL,"
        "url TEXT NOT NULL,"
        "host TEXT NOT NULL,"
        "port INTEGER DEFAULT 0,"
        "scheme TEXT DEFAULT '',"
        "added_ms INTEGER NOT NULL,"
        "is_primary INTEGER DEFAULT 0,"
        "FOREIGN KEY(session_id) REFERENCES audit_sessions(session_id) ON DELETE CASCADE"
        ");"
        "CREATE TABLE IF NOT EXISTS findings("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "issue_store_id INTEGER DEFAULT 0,"
        "session_id TEXT,"
        "scan_id INTEGER DEFAULT 0,"
        "audit_id INTEGER DEFAULT 0,"
        "type_key TEXT NOT NULL,"
        "name TEXT NOT NULL,"
        "description TEXT DEFAULT '',"
        "remediation TEXT DEFAULT '',"
        "severity INTEGER NOT NULL DEFAULT 0,"
        "confidence INTEGER NOT NULL DEFAULT 0,"
        "scheme TEXT DEFAULT '',"
        "host TEXT NOT NULL,"
        "port INTEGER DEFAULT 0,"
        "path TEXT DEFAULT '',"
        "parameter TEXT DEFAULT '',"
        "insertion_point TEXT DEFAULT '',"
        "dedupe_key TEXT DEFAULT '',"
        "cwe_json TEXT DEFAULT '[]',"
        "cvss_score REAL DEFAULT 0.0,"
        "cvss_vector TEXT DEFAULT '',"
        "cvss_severity TEXT DEFAULT '',"
        "owasp_category TEXT DEFAULT '',"
        "source_exchange_id INTEGER DEFAULT 0,"
        "first_seen_ms INTEGER NOT NULL,"
        "last_seen_ms INTEGER NOT NULL,"
        "suppressed INTEGER DEFAULT 0,"
        "suppress_reason TEXT DEFAULT '',"
        "suppressed_by TEXT DEFAULT '',"
        "suppressed_ms INTEGER DEFAULT 0,"
        "metadata_json TEXT DEFAULT '{}',"
        "FOREIGN KEY(session_id) REFERENCES audit_sessions(session_id) ON DELETE SET NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS finding_correlations("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "session_id TEXT,"
        "pattern TEXT NOT NULL,"
        "type_key TEXT,"
        "description TEXT DEFAULT '',"
        "severity INTEGER DEFAULT 0,"
        "finding_ids_json TEXT NOT NULL,"
        "endpoints_json TEXT DEFAULT '[]',"
        "host TEXT DEFAULT '',"
        "created_ms INTEGER NOT NULL,"
        "FOREIGN KEY(session_id) REFERENCES audit_sessions(session_id) ON DELETE CASCADE"
        ");"
        "CREATE TABLE IF NOT EXISTS evidence("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "finding_id INTEGER NOT NULL,"
        "session_id TEXT,"
        "scan_id INTEGER DEFAULT 0,"
        "kind TEXT DEFAULT 'request_response',"
        "request_raw TEXT DEFAULT '',"
        "response_raw TEXT DEFAULT '',"
        "marker TEXT DEFAULT '',"
        "marker_offset_request INTEGER DEFAULT 0,"
        "marker_offset_response INTEGER DEFAULT 0,"
        "screenshot_path TEXT DEFAULT '',"
        "screenshot_blob BLOB,"
        "file_path TEXT DEFAULT '',"
        "content_sha256 TEXT DEFAULT '',"
        "timing_json TEXT DEFAULT '{}',"
        "description TEXT DEFAULT '',"
        "exchange_id INTEGER DEFAULT 0,"
        "captured_ms INTEGER NOT NULL,"
        "metadata_json TEXT DEFAULT '{}',"
        "FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE"
        ");"
        "CREATE TABLE IF NOT EXISTS scans("
        "scan_id INTEGER PRIMARY KEY,"
        "session_id TEXT,"
        "target_url TEXT NOT NULL,"
        "profile TEXT DEFAULT 'quick',"
        "status TEXT DEFAULT 'pending',"
        "total_probes INTEGER DEFAULT 0,"
        "completed_probes INTEGER DEFAULT 0,"
        "issues_found INTEGER DEFAULT 0,"
        "modules_json TEXT DEFAULT '[]',"
        "defensive_json TEXT DEFAULT '[]',"
        "config_json TEXT DEFAULT '{}',"
        "started_ms INTEGER NOT NULL,"
        "ended_ms INTEGER DEFAULT 0,"
        "error_message TEXT DEFAULT '',"
        "FOREIGN KEY(session_id) REFERENCES audit_sessions(session_id) ON DELETE SET NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS scan_module_status("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "scan_id INTEGER NOT NULL,"
        "module_id TEXT NOT NULL,"
        "status TEXT DEFAULT 'pending',"
        "probes_done INTEGER DEFAULT 0,"
        "probes_total INTEGER DEFAULT 0,"
        "issues_found INTEGER DEFAULT 0,"
        "started_ms INTEGER DEFAULT 0,"
        "ended_ms INTEGER DEFAULT 0,"
        "error_message TEXT DEFAULT '',"
        "FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE"
        ");"
        "CREATE TABLE IF NOT EXISTS defensive_check_status("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "scan_id INTEGER NOT NULL,"
        "check_name TEXT NOT NULL,"
        "status TEXT DEFAULT 'pending',"
        "findings_count INTEGER DEFAULT 0,"
        "started_ms INTEGER DEFAULT 0,"
        "ended_ms INTEGER DEFAULT 0,"
        "result_json TEXT DEFAULT '{}',"
        "FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE"
        ");"
        "CREATE TABLE IF NOT EXISTS audit_trail("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "session_id TEXT,"
        "scan_id INTEGER DEFAULT 0,"
        "timestamp_ms INTEGER NOT NULL,"
        "tool_name TEXT NOT NULL,"
        "parameters_json TEXT DEFAULT '{}',"
        "parameters_hash TEXT DEFAULT '',"
        "result_summary_json TEXT DEFAULT '{}',"
        "result_hash TEXT DEFAULT '',"
        "duration_ms INTEGER DEFAULT 0,"
        "caller TEXT DEFAULT '',"
        "success INTEGER DEFAULT 1,"
        "error_message TEXT DEFAULT '',"
        "FOREIGN KEY(session_id) REFERENCES audit_sessions(session_id) ON DELETE SET NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS scan_profiles("
        "profile_id TEXT PRIMARY KEY,"
        "name TEXT NOT NULL,"
        "description TEXT DEFAULT '',"
        "module_ids_json TEXT DEFAULT '[]',"
        "defensive_checks_json TEXT DEFAULT '[]',"
        "crawl_depth INTEGER DEFAULT 2,"
        "max_concurrent INTEGER DEFAULT 16,"
        "created_ms INTEGER NOT NULL,"
        "is_builtin INTEGER DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS suppression_rules("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "scope TEXT NOT NULL,"
        "finding_id INTEGER DEFAULT 0,"
        "type_key TEXT DEFAULT '',"
        "host TEXT DEFAULT '',"
        "reason TEXT NOT NULL,"
        "suppressed_by TEXT NOT NULL,"
        "created_ms INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS traffic_captures("
        "id INTEGER PRIMARY KEY,"
        "session_id TEXT,"
        "timestamp_ms INTEGER NOT NULL,"
        "method TEXT NOT NULL,"
        "scheme TEXT DEFAULT '',"
        "host TEXT NOT NULL,"
        "port INTEGER DEFAULT 0,"
        "path TEXT DEFAULT '',"
        "query TEXT DEFAULT '',"
        "req_headers_json TEXT DEFAULT '[]',"
        "req_body BLOB,"
        "status_code INTEGER DEFAULT 0,"
        "reason_phrase TEXT DEFAULT '',"
        "resp_headers_json TEXT DEFAULT '[]',"
        "resp_body BLOB,"
        "latency_ms INTEGER DEFAULT 0,"
        "is_websocket INTEGER DEFAULT 0,"
        "is_h2 INTEGER DEFAULT 0,"
        "tls_version TEXT DEFAULT '',"
        "alpn TEXT DEFAULT '',"
        "source TEXT DEFAULT '',"
        "FOREIGN KEY(session_id) REFERENCES audit_sessions(session_id) ON DELETE SET NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_audit_targets_session ON audit_targets(session_id);"
        "CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);"
        "CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);"
        "CREATE INDEX IF NOT EXISTS idx_findings_audit ON findings(audit_id);"
        "CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host);"
        "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);"
        "CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type_key);"
        "CREATE INDEX IF NOT EXISTS idx_findings_suppressed ON findings(suppressed);"
        "CREATE INDEX IF NOT EXISTS idx_findings_dedupe ON findings(dedupe_key);"
        "CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);"
        "CREATE INDEX IF NOT EXISTS idx_scans_session ON scans(session_id);"
        "CREATE INDEX IF NOT EXISTS idx_scan_module_scan ON scan_module_status(scan_id);"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_module_unique ON scan_module_status(scan_id,module_id);"
        "CREATE INDEX IF NOT EXISTS idx_audit_trail_session ON audit_trail(session_id);"
        "CREATE INDEX IF NOT EXISTS idx_audit_trail_tool ON audit_trail(tool_name);"
        "CREATE INDEX IF NOT EXISTS idx_traffic_session ON traffic_captures(session_id);"
        "CREATE INDEX IF NOT EXISTS idx_traffic_host ON traffic_captures(host);"
        "CREATE INDEX IF NOT EXISTS idx_traffic_path ON traffic_captures(path);"
        "CREATE VIEW IF NOT EXISTS session_targets AS SELECT id,session_id,url,host,port,scheme,added_ms,is_primary FROM audit_targets;"
        "CREATE VIEW IF NOT EXISTS scan_runs AS SELECT scan_id,session_id,target_url,profile,status,total_probes,completed_probes,issues_found,modules_json,defensive_json,config_json,started_ms,ended_ms,error_message FROM scans;"
        "CREATE VIEW IF NOT EXISTS scan_modules AS SELECT id,scan_id,module_id,status,probes_done,probes_total,issues_found,started_ms,ended_ms,error_message FROM scan_module_status;";

    if (!exec_simple(db, schema)) return false;

    if (!ensure_column(db, "findings", "issue_store_id", "ALTER TABLE findings ADD COLUMN issue_store_id INTEGER DEFAULT 0")) return false;
    if (!ensure_column(db, "findings", "session_id", "ALTER TABLE findings ADD COLUMN session_id TEXT DEFAULT ''")) return false;
    if (!ensure_column(db, "findings", "scan_id", "ALTER TABLE findings ADD COLUMN scan_id INTEGER DEFAULT 0")) return false;
    if (!ensure_column(db, "findings", "audit_id", "ALTER TABLE findings ADD COLUMN audit_id INTEGER DEFAULT 0")) return false;
    if (!ensure_column(db, "findings", "dedupe_key", "ALTER TABLE findings ADD COLUMN dedupe_key TEXT DEFAULT ''")) return false;
    if (!ensure_column(db, "findings", "cwe_json", "ALTER TABLE findings ADD COLUMN cwe_json TEXT DEFAULT '[]'")) return false;
    if (!ensure_column(db, "findings", "cvss_score", "ALTER TABLE findings ADD COLUMN cvss_score REAL DEFAULT 0.0")) return false;
    if (!ensure_column(db, "findings", "cvss_vector", "ALTER TABLE findings ADD COLUMN cvss_vector TEXT DEFAULT ''")) return false;
    if (!ensure_column(db, "findings", "cvss_severity", "ALTER TABLE findings ADD COLUMN cvss_severity TEXT DEFAULT ''")) return false;
    if (!ensure_column(db, "findings", "owasp_category", "ALTER TABLE findings ADD COLUMN owasp_category TEXT DEFAULT ''")) return false;
    if (!ensure_column(db, "findings", "suppressed", "ALTER TABLE findings ADD COLUMN suppressed INTEGER DEFAULT 0")) return false;
    if (!ensure_column(db, "findings", "suppress_reason", "ALTER TABLE findings ADD COLUMN suppress_reason TEXT DEFAULT ''")) return false;
    if (!ensure_column(db, "findings", "suppressed_by", "ALTER TABLE findings ADD COLUMN suppressed_by TEXT DEFAULT ''")) return false;
    if (!ensure_column(db, "findings", "suppressed_ms", "ALTER TABLE findings ADD COLUMN suppressed_ms INTEGER DEFAULT 0")) return false;
    if (!ensure_column(db, "evidence", "session_id", "ALTER TABLE evidence ADD COLUMN session_id TEXT DEFAULT ''")) return false;
    if (!ensure_column(db, "evidence", "scan_id", "ALTER TABLE evidence ADD COLUMN scan_id INTEGER DEFAULT 0")) return false;
    if (!ensure_column(db, "evidence", "kind", "ALTER TABLE evidence ADD COLUMN kind TEXT DEFAULT 'request_response'")) return false;
    if (!ensure_column(db, "evidence", "screenshot_path", "ALTER TABLE evidence ADD COLUMN screenshot_path TEXT DEFAULT ''")) return false;
    if (!ensure_column(db, "evidence", "file_path", "ALTER TABLE evidence ADD COLUMN file_path TEXT DEFAULT ''")) return false;
    if (!ensure_column(db, "evidence", "content_sha256", "ALTER TABLE evidence ADD COLUMN content_sha256 TEXT DEFAULT ''")) return false;
    if (!ensure_column(db, "evidence", "timing_json", "ALTER TABLE evidence ADD COLUMN timing_json TEXT DEFAULT '{}'")) return false;
    if (!ensure_column(db, "evidence", "metadata_json", "ALTER TABLE evidence ADD COLUMN metadata_json TEXT DEFAULT '{}'")) return false;
    if (!ensure_column(db, "audit_trail", "parameters_json", "ALTER TABLE audit_trail ADD COLUMN parameters_json TEXT DEFAULT '{}'")) return false;
    if (!ensure_column(db, "audit_trail", "parameters_hash", "ALTER TABLE audit_trail ADD COLUMN parameters_hash TEXT DEFAULT ''")) return false;
    if (!ensure_column(db, "audit_trail", "result_summary_json", "ALTER TABLE audit_trail ADD COLUMN result_summary_json TEXT DEFAULT '{}'")) return false;
    if (!ensure_column(db, "audit_trail", "result_hash", "ALTER TABLE audit_trail ADD COLUMN result_hash TEXT DEFAULT ''")) return false;
    if (!cleanup_empty_optional_session_ids(db)) return false;
    return true;
}

void seed_builtin_profiles(sqlite3* db)
{
    const uint64_t now = now_ms();
    scan_profile_t quick;
    quick.profile_id = "quick";
    quick.name = "Quick Scan";
    quick.description = "Passive and defensive checks";
    quick.module_ids_json = nlohmann::json::array();
    quick.defensive_checks_json = nlohmann::json::array({"security_headers", "tls_config", "content_analysis"});
    quick.crawl_depth = 1;
    quick.max_concurrent = 16;
    quick.created_ms = now;
    quick.is_builtin = true;

    scan_profile_t full;
    full.profile_id = "full";
    full.name = "Full Audit";
    full.description = "All active, passive, and defensive checks";
    full.module_ids_json = nlohmann::json::array({"xss","sqli","nosqli","cmdi","cors","csp","csrf","xxe","ssrf","ssti","path_traversal","open_redirect","idor","jwt_scan","log4j","ldap","xpath","dom_xss","host_header","smuggling","race_condition","deserial","method_override","param_miner","protopol"});
    full.defensive_checks_json = nlohmann::json::array({"security_headers","tls_config","content_analysis","info_disclosure","cookie_audit"});
    full.crawl_depth = 3;
    full.max_concurrent = 16;
    full.created_ms = now;
    full.is_builtin = true;

    auto insert_profile = [&](const scan_profile_t& p) {
        const char* sql =
            "INSERT OR IGNORE INTO scan_profiles(profile_id,name,description,module_ids_json,defensive_checks_json,crawl_depth,max_concurrent,created_ms,is_builtin) "
            "VALUES(?,?,?,?,?,?,?,?,?)";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
        bind_text(stmt, 1, p.profile_id);
        bind_text(stmt, 2, p.name);
        bind_text(stmt, 3, p.description);
        bind_json(stmt, 4, p.module_ids_json);
        bind_json(stmt, 5, p.defensive_checks_json);
        sqlite3_bind_int(stmt, 6, p.crawl_depth);
        sqlite3_bind_int(stmt, 7, p.max_concurrent);
        sqlite3_bind_int64(stmt, 8, static_cast<sqlite3_int64>(p.created_ms));
        sqlite3_bind_int(stmt, 9, p.is_builtin ? 1 : 0);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    };
    insert_profile(quick);
    insert_profile(full);
}

std::string normalize_case(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string build_dedupe_key(const issue_t& issue)
{
    std::string key;
    key.reserve(issue.session_id.size() + issue.type_key.size() + issue.host.size() + issue.path.size() + issue.parameter.size() + 64);
    key += normalize_case(issue.session_id);
    key += '|';
    key += std::to_string(issue.scan_id != 0 ? issue.scan_id : issue.audit_id);
    key += '|';
    key += normalize_case(issue.type_key);
    key += '|';
    key += normalize_case(issue.host);
    key += '|';
    key += normalize_case(issue.path);
    key += '|';
    key += normalize_case(issue.parameter);
    key += '|';
    key += normalize_case(issue.insertion_point);
    return key;
}

bool validate_issue_for_mirror(const issue_t& issue, std::string& reason)
{
    const auto blank = [](const std::string& value) {
        return std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isspace(c) != 0; });
    };
    if (blank(issue.type_key)) {
        reason = "empty_type_key";
        return false;
    }
    if (blank(issue.host)) {
        reason = "empty_host";
        return false;
    }
    reason.clear();
    return true;
}

std::string session_state_label(const std::string& session_id)
{
    if (session_id.empty()) return "null";
    const size_t h = std::hash<std::string>{}(session_id);
    std::ostringstream oss;
    oss << "len:" << session_id.size() << ":hash:" << std::hex << static_cast<unsigned long long>(h);
    return oss.str();
}

void log_finding_upsert_begin(const issue_t& issue, const char* mode, size_t evidence_count)
{
    diag::log_tagged_fmt("burp_findings",
        "finding_upsert_begin mode=%s issue_store_id=%llu finding_id=%llu session=%s scan_id=%llu audit_id=%llu type_key=%s host=%s path=%s evidence_count=%zu",
        mode ? mode : "unknown",
        static_cast<unsigned long long>(issue.id),
        static_cast<unsigned long long>(issue.id),
        session_state_label(issue.session_id).c_str(),
        static_cast<unsigned long long>(issue.scan_id),
        static_cast<unsigned long long>(issue.audit_id),
        issue.type_key.c_str(),
        evidence_store::redact_sensitive_text(issue.host, 256).c_str(),
        evidence_store::redact_sensitive_text(issue.path, 512).c_str(),
        evidence_count);
}

void log_sqlite_step(sqlite3* db, const char* operation, int rc)
{
    diag::log_tagged_fmt("burp_findings",
        "finding_upsert_step op=%s rc=%d extended_rc=%d errmsg=%s changes=%d last_insert_rowid=%lld autocommit=%d",
        operation ? operation : "unknown",
        rc,
        db ? sqlite3_extended_errcode(db) : 0,
        db ? sqlite3_errmsg(db) : "no database",
        db ? sqlite3_changes(db) : 0,
        db ? static_cast<long long>(sqlite3_last_insert_rowid(db)) : 0ll,
        db ? sqlite3_get_autocommit(db) : 0);
}

std::vector<std::string> json_to_string_vector(const nlohmann::json& j)
{
    std::vector<std::string> out;
    if (!j.is_array()) return out;
    for (const auto& item : j) {
        if (item.is_string()) out.push_back(item.get<std::string>());
    }
    return out;
}

void load_evidence_for_issue(sqlite3* db, uint64_t finding_id, issue_t& out)
{
    const char* sql = "SELECT request_raw,response_raw,marker,marker_offset_request,marker_offset_response FROM evidence WHERE finding_id=? ORDER BY captured_ms ASC,id ASC LIMIT 64";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(finding_id));
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        evidence_t ev;
        ev.request_raw = column_text(stmt, 0);
        ev.response_raw = column_text(stmt, 1);
        ev.marker = column_text(stmt, 2);
        ev.marker_offset_request = static_cast<size_t>(sqlite3_column_int64(stmt, 3));
        ev.marker_offset_response = static_cast<size_t>(sqlite3_column_int64(stmt, 4));
        out.evidence.push_back(std::move(ev));
    }
    sqlite3_finalize(stmt);
}

issue_t issue_from_row(sqlite3* db, sqlite3_stmt* stmt)
{
    issue_t issue;
    issue.id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
    issue.session_id = column_text(stmt, 1);
    issue.scan_id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 2));
    issue.audit_id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 3));
    issue.type_key = column_text(stmt, 4);
    issue.name = column_text(stmt, 5);
    issue.description = column_text(stmt, 6);
    issue.remediation = column_text(stmt, 7);
    issue.severity = static_cast<severity_t>(sqlite3_column_int(stmt, 8));
    issue.confidence = static_cast<confidence_t>(sqlite3_column_int(stmt, 9));
    issue.scheme = column_text(stmt, 10);
    issue.host = column_text(stmt, 11);
    const int port = sqlite3_column_int(stmt, 12);
    issue.port = static_cast<uint16_t>((std::max)(0, (std::min)(65535, port)));
    issue.path = column_text(stmt, 13);
    issue.parameter = column_text(stmt, 14);
    issue.insertion_point = column_text(stmt, 15);
    issue.cwe = json_to_string_vector(parse_json_or(column_text(stmt, 16), nlohmann::json::array()));
    issue.cvss_score = sqlite3_column_double(stmt, 17);
    issue.cvss_vector = column_text(stmt, 18);
    issue.cvss_severity = column_text(stmt, 19);
    issue.owasp_category = column_text(stmt, 20);
    issue.src_exchange_id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 21));
    issue.seen_ms = static_cast<uint64_t>(sqlite3_column_int64(stmt, 22));
    issue.suppressed = sqlite3_column_int(stmt, 24) != 0;
    issue.suppress_reason = column_text(stmt, 25);
    issue.suppressed_by = column_text(stmt, 26);
    issue.suppressed_ms = static_cast<uint64_t>(sqlite3_column_int64(stmt, 27));
    load_evidence_for_issue(db, issue.id, issue);
    return issue;
}

std::string select_finding_fields()
{
    return "id,session_id,scan_id,audit_id,type_key,name,description,remediation,severity,confidence,scheme,host,port,path,parameter,insertion_point,cwe_json,cvss_score,cvss_vector,cvss_severity,owasp_category,source_exchange_id,first_seen_ms,last_seen_ms,suppressed,suppress_reason,suppressed_by,suppressed_ms,metadata_json";
}

bool bind_filter(sqlite3_stmt* stmt, const finding_filter_t& filter, int& idx, bool include_limit)
{
    if (!filter.session_id.empty() && !bind_text(stmt, idx++, filter.session_id)) return false;
    if (filter.has_scan_id && sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.scan_id)) != SQLITE_OK) return false;
    if (filter.has_audit_id && sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.audit_id)) != SQLITE_OK) return false;
    if (!filter.host_substring.empty() && !bind_text(stmt, idx++, "%" + filter.host_substring + "%")) return false;
    if (!filter.type_key_substring.empty() && !bind_text(stmt, idx++, "%" + filter.type_key_substring + "%")) return false;
    if (!filter.path_substring.empty() && !bind_text(stmt, idx++, "%" + filter.path_substring + "%")) return false;
    if (filter.has_severity_min && sqlite3_bind_int(stmt, idx++, static_cast<int>(filter.severity_min)) != SQLITE_OK) return false;
    if (filter.has_confidence_min && sqlite3_bind_int(stmt, idx++, static_cast<int>(filter.confidence_min)) != SQLITE_OK) return false;
    if (!filter.include_suppressed && sqlite3_bind_int(stmt, idx++, 0) != SQLITE_OK) return false;
    if (include_limit && filter.limit > 0 && sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.limit)) != SQLITE_OK) return false;
    if (include_limit && filter.offset > 0 && sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.offset)) != SQLITE_OK) return false;
    return true;
}

std::string where_for_filter(const finding_filter_t& filter, bool include_limit)
{
    std::string sql = " WHERE 1=1";
    if (!filter.session_id.empty()) sql += " AND session_id=?";
    if (filter.has_scan_id) sql += " AND scan_id=?";
    if (filter.has_audit_id) sql += " AND audit_id=?";
    if (!filter.host_substring.empty()) sql += " AND host LIKE ?";
    if (!filter.type_key_substring.empty()) sql += " AND type_key LIKE ?";
    if (!filter.path_substring.empty()) sql += " AND path LIKE ?";
    if (filter.has_severity_min) sql += " AND severity>=?";
    if (filter.has_confidence_min) sql += " AND confidence>=?";
    if (!filter.include_suppressed) sql += " AND suppressed=?";
    if (include_limit && filter.limit > 0) sql += " LIMIT ?";
    if (include_limit && filter.offset > 0) sql += " OFFSET ?";
    return sql;
}

void refresh_session_counts(sqlite3* db, const std::string& session_id)
{
    if (session_id.empty()) return;
    const char* sql =
        "UPDATE audit_sessions SET "
        "target_count=(SELECT COUNT(*) FROM audit_targets WHERE session_id=?),"
        "finding_count=(SELECT COUNT(*) FROM findings WHERE session_id=? AND suppressed=0),"
        "scan_count=(SELECT COUNT(*) FROM scans WHERE session_id=?) "
        "WHERE session_id=?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    bind_text(stmt, 1, session_id);
    bind_text(stmt, 2, session_id);
    bind_text(stmt, 3, session_id);
    bind_text(stmt, 4, session_id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

uint64_t find_existing_id(sqlite3* db, const issue_t& issue, const std::string& dedupe_key)
{
    if (issue.id != 0) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT id FROM findings WHERE id=?", -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(issue.id));
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                uint64_t id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
                sqlite3_finalize(stmt);
                return id;
            }
            sqlite3_finalize(stmt);
        }
    }
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT id FROM findings WHERE dedupe_key=? AND suppressed=0 ORDER BY confidence DESC,severity DESC,last_seen_ms DESC LIMIT 1", -1, &stmt, nullptr) != SQLITE_OK) return 0;
    bind_text(stmt, 1, dedupe_key);
    uint64_t id = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);
    return id;
}

bool evidence_exists(sqlite3* db, uint64_t finding_id)
{
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM evidence WHERE finding_id=? LIMIT 1", -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(finding_id));
    bool found = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    return found;
}

uint64_t upsert_finding_row(sqlite3* db, const issue_t& in_issue, bool& should_insert_evidence, size_t evidence_count)
{
    issue_t issue = in_issue;
    if (issue.seen_ms == 0) issue.seen_ms = now_ms();
    if (issue.scan_id == 0 && issue.audit_id != 0) issue.scan_id = issue.audit_id;
    if (issue.host.empty()) issue.host = "unknown";
    if (issue.name.empty()) issue.name = issue.type_key.empty() ? "Finding" : issue.type_key;
    if (issue.type_key.empty()) issue.type_key = "finding.generic";
    auto mapping = vuln_taxonomy::mapping_for_type(issue.type_key);
    if (issue.owasp_category.empty()) issue.owasp_category = mapping.owasp_category;
    if (issue.cwe.empty()) issue.cwe = mapping.cwe_ids;
    if (issue.cvss_vector.empty()) issue.cvss_vector = mapping.default_cvss_vector;
    if (issue.cvss_score <= 0.0 && !issue.cvss_vector.empty()) {
        auto cvss = vuln_taxonomy::calculate_cvss31(issue.cvss_vector);
        if (cvss.valid) {
            issue.cvss_score = cvss.score;
            issue.cvss_severity = cvss.severity;
            issue.cvss_vector = cvss.vector;
        }
    }
    const std::string dedupe_key = build_dedupe_key(issue);
    const uint64_t existing_id = find_existing_id(db, issue, dedupe_key);
    const nlohmann::json cwe_json = issue.cwe;
    if (existing_id != 0) {
        log_finding_upsert_begin(issue, "update", evidence_count);
        const char* sql =
            "UPDATE findings SET "
            "issue_store_id=CASE WHEN ?!=0 THEN ? ELSE issue_store_id END,"
            "session_id=?,scan_id=?,audit_id=?,type_key=?,name=?,description=?,remediation=?,"
            "severity=CASE WHEN severity<? THEN ? ELSE severity END,"
            "confidence=CASE WHEN confidence<? THEN ? ELSE confidence END,"
            "scheme=?,host=?,port=?,path=?,parameter=?,insertion_point=?,dedupe_key=?,cwe_json=?,"
            "cvss_score=?,cvss_vector=?,cvss_severity=?,owasp_category=?,source_exchange_id=?,last_seen_ms=?,"
            "suppressed=CASE WHEN ?!=0 THEN 1 ELSE suppressed END,"
            "suppress_reason=CASE WHEN ?!=0 THEN ? ELSE suppress_reason END,"
            "suppressed_by=CASE WHEN ?!=0 THEN ? ELSE suppressed_by END,"
            "suppressed_ms=CASE WHEN ?!=0 THEN ? ELSE suppressed_ms END WHERE id=?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            set_sqlite_error(db, "finding_upsert_prepare_update");
            return 0;
        }
        int idx = 1;
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(issue.id));
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(issue.id));
        bind_nullable_text(stmt, idx++, issue.session_id);
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(issue.scan_id));
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(issue.audit_id));
        bind_text(stmt, idx++, issue.type_key);
        bind_text(stmt, idx++, issue.name);
        bind_text(stmt, idx++, issue.description);
        bind_text(stmt, idx++, issue.remediation);
        sqlite3_bind_int(stmt, idx++, static_cast<int>(issue.severity));
        sqlite3_bind_int(stmt, idx++, static_cast<int>(issue.severity));
        sqlite3_bind_int(stmt, idx++, static_cast<int>(issue.confidence));
        sqlite3_bind_int(stmt, idx++, static_cast<int>(issue.confidence));
        bind_text(stmt, idx++, issue.scheme);
        bind_text(stmt, idx++, issue.host);
        sqlite3_bind_int(stmt, idx++, static_cast<int>(issue.port));
        bind_text(stmt, idx++, issue.path);
        bind_text(stmt, idx++, issue.parameter);
        bind_text(stmt, idx++, issue.insertion_point);
        bind_text(stmt, idx++, dedupe_key);
        bind_json(stmt, idx++, cwe_json);
        sqlite3_bind_double(stmt, idx++, issue.cvss_score);
        bind_text(stmt, idx++, issue.cvss_vector);
        bind_text(stmt, idx++, issue.cvss_severity);
        bind_text(stmt, idx++, issue.owasp_category);
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(issue.src_exchange_id));
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(now_ms()));
        const int incoming_suppressed = issue.suppressed ? 1 : 0;
        sqlite3_bind_int(stmt, idx++, incoming_suppressed);
        sqlite3_bind_int(stmt, idx++, incoming_suppressed);
        bind_text(stmt, idx++, issue.suppress_reason);
        sqlite3_bind_int(stmt, idx++, incoming_suppressed);
        bind_text(stmt, idx++, issue.suppressed_by);
        sqlite3_bind_int(stmt, idx++, incoming_suppressed);
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(issue.suppressed_ms));
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(existing_id));
        const int rc = sqlite3_step(stmt);
        log_sqlite_step(db, "update", rc);
        if (rc != SQLITE_DONE) set_sqlite_error(db, "finding_upsert_update");
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return 0;
        should_insert_evidence = !evidence_exists(db, existing_id);
        refresh_session_counts(db, issue.session_id);
        return existing_id;
    }

    std::string sql =
        issue.id != 0 ?
        "INSERT INTO findings(id,issue_store_id,session_id,scan_id,audit_id,type_key,name,description,remediation,severity,confidence,scheme,host,port,path,parameter,insertion_point,dedupe_key,cwe_json,cvss_score,cvss_vector,cvss_severity,owasp_category,source_exchange_id,first_seen_ms,last_seen_ms,suppressed,suppress_reason,suppressed_by,suppressed_ms,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)" :
        "INSERT INTO findings(issue_store_id,session_id,scan_id,audit_id,type_key,name,description,remediation,severity,confidence,scheme,host,port,path,parameter,insertion_point,dedupe_key,cwe_json,cvss_score,cvss_vector,cvss_severity,owasp_category,source_exchange_id,first_seen_ms,last_seen_ms,suppressed,suppress_reason,suppressed_by,suppressed_ms,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    sqlite3_stmt* stmt = nullptr;
    log_finding_upsert_begin(issue, "insert", evidence_count);
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        set_sqlite_error(db, "finding_upsert_prepare_insert");
        return 0;
    }
    int idx = 1;
    if (issue.id != 0) sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(issue.id));
    sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(issue.id));
    bind_nullable_text(stmt, idx++, issue.session_id);
    sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(issue.scan_id));
    sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(issue.audit_id));
    bind_text(stmt, idx++, issue.type_key);
    bind_text(stmt, idx++, issue.name);
    bind_text(stmt, idx++, issue.description);
    bind_text(stmt, idx++, issue.remediation);
    sqlite3_bind_int(stmt, idx++, static_cast<int>(issue.severity));
    sqlite3_bind_int(stmt, idx++, static_cast<int>(issue.confidence));
    bind_text(stmt, idx++, issue.scheme);
    bind_text(stmt, idx++, issue.host);
    sqlite3_bind_int(stmt, idx++, static_cast<int>(issue.port));
    bind_text(stmt, idx++, issue.path);
    bind_text(stmt, idx++, issue.parameter);
    bind_text(stmt, idx++, issue.insertion_point);
    bind_text(stmt, idx++, dedupe_key);
    bind_json(stmt, idx++, cwe_json);
    sqlite3_bind_double(stmt, idx++, issue.cvss_score);
    bind_text(stmt, idx++, issue.cvss_vector);
    bind_text(stmt, idx++, issue.cvss_severity);
    bind_text(stmt, idx++, issue.owasp_category);
    sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(issue.src_exchange_id));
    sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(issue.seen_ms));
    sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(issue.seen_ms));
    sqlite3_bind_int(stmt, idx++, issue.suppressed ? 1 : 0);
    bind_text(stmt, idx++, issue.suppress_reason);
    bind_text(stmt, idx++, issue.suppressed_by);
    sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(issue.suppressed_ms));
    bind_json(stmt, idx++, nlohmann::json::object());
    const int rc = sqlite3_step(stmt);
    log_sqlite_step(db, "insert", rc);
    if (rc != SQLITE_DONE) set_sqlite_error(db, "finding_upsert_insert");
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return 0;
    const uint64_t id = issue.id != 0 ? issue.id : static_cast<uint64_t>(sqlite3_last_insert_rowid(db));
    should_insert_evidence = true;
    refresh_session_counts(db, issue.session_id);
    return id;
}

}

bool initialize()
{
    if (g_initialized.load(std::memory_order_acquire)) return true;
    std::lock_guard<std::mutex> lk(g_init_mutex);
    if (g_initialized.load(std::memory_order_acquire)) return true;

    const auto path = resolve_database_path();
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    sqlite3* db = nullptr;
    const std::string utf8 = wide_path_to_utf8(path);
    int rc = sqlite3_open_v2(utf8.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (rc != SQLITE_OK) {
        if (db) {
            set_sqlite_error(db, "sqlite_open");
            sqlite3_close(db);
        }
        else {
            set_error("sqlite_open_failed");
        }
        return false;
    }
    sqlite3_busy_timeout(db, 5000);
    if (!create_schema(db)) {
        sqlite3_close(db);
        return false;
    }
    seed_builtin_profiles(db);
    g_db.store(db, std::memory_order_release);
    g_initialized.store(true, std::memory_order_release);
    diag::log_tagged_fmt("burp_findings", "initialize ok path=%s", utf8.c_str());
    mirror_issue_store(false);
    return true;
}

bool shutdown()
{
    std::lock_guard<std::mutex> lk(g_init_mutex);
    std::lock_guard<std::mutex> db_lk(g_db_mutex);
    sqlite3* db = g_db.exchange(nullptr, std::memory_order_acq_rel);
    g_initialized.store(false, std::memory_order_release);
    if (!db) return true;
    int rc = sqlite3_close_v2(db);
    if (rc != SQLITE_OK) {
        set_error("sqlite_close_failed");
        return false;
    }
    return true;
}

bool is_initialized()
{
    return g_initialized.load(std::memory_order_acquire);
}

uint64_t upsert(issue_t issue)
{
    if (!initialize()) return 0;
    std::vector<evidence_t> evidence = issue.evidence;
    issue.evidence.clear();
    bool should_insert_evidence = false;
    uint64_t id = 0;
    bool ok = with_db("finding_upsert", [&](sqlite3* db) {
        id = upsert_finding_row(db, issue, should_insert_evidence, evidence.size());
        return id != 0;
    });
    if (!ok || id == 0) return 0;
    if (should_insert_evidence) {
        for (const auto& ev : evidence) {
            evidence_store::evidence_record_t rec;
            evidence_store::evidence_capture_t cap;
            cap.finding_id = id;
            cap.session_id = issue.session_id;
            cap.scan_id = issue.scan_id;
            cap.kind = evidence_store::evidence_kind_t::request_response;
            cap.request_raw = ev.request_raw;
            cap.response_raw = ev.response_raw;
            cap.marker = ev.marker;
            cap.marker_offset_request = static_cast<uint64_t>(ev.marker_offset_request);
            cap.marker_offset_response = static_cast<uint64_t>(ev.marker_offset_response);
            cap.exchange_id = issue.src_exchange_id;
            evidence_store::capture(cap, rec);
        }
    }
    return id;
}

bool remove(uint64_t finding_id)
{
    if (!initialize()) return false;
    std::string session_id;
    return with_db("finding_remove", [&](sqlite3* db) {
        sqlite3_stmt* sel = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT session_id FROM findings WHERE id=?", -1, &sel, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(sel, 1, static_cast<sqlite3_int64>(finding_id));
            if (sqlite3_step(sel) == SQLITE_ROW) session_id = column_text(sel, 0);
            sqlite3_finalize(sel);
        }
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, "DELETE FROM findings WHERE id=?", -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(finding_id));
        const int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        refresh_session_counts(db, session_id);
        return rc == SQLITE_DONE;
    });
}

bool get(uint64_t finding_id, issue_t& out)
{
    if (!initialize()) return false;
    bool found = false;
    bool ok = with_db("finding_get", [&](sqlite3* db) {
        std::string sql = "SELECT " + select_finding_fields() + " FROM findings WHERE id=?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(finding_id));
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            out = issue_from_row(db, stmt);
            found = true;
        }
        sqlite3_finalize(stmt);
        return true;
    });
    if (!ok) return false;
    if (!found) {
        set_error("finding_not_found");
        return false;
    }
    return true;
}

std::vector<issue_t> list(const finding_filter_t& filter)
{
    std::vector<issue_t> out;
    if (!initialize()) return out;
    with_db("finding_list", [&](sqlite3* db) {
        std::string sql = "SELECT " + select_finding_fields() + " FROM findings" + where_for_filter(filter, false) + " ORDER BY suppressed ASC,severity DESC,confidence DESC,last_seen_ms DESC,id DESC";
        if (filter.limit > 0) sql += " LIMIT ?";
        if (filter.offset > 0) sql += " OFFSET ?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return false;
        int idx = 1;
        if (!bind_filter(stmt, filter, idx, true)) {
            sqlite3_finalize(stmt);
            return false;
        }
        while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(issue_from_row(db, stmt));
        sqlite3_finalize(stmt);
        return true;
    });
    return out;
}

size_t count(const finding_filter_t& filter)
{
    if (!initialize()) return 0;
    size_t out = 0;
    with_db("finding_count", [&](sqlite3* db) {
        std::string sql = "SELECT COUNT(*) FROM findings" + where_for_filter(filter, false);
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return false;
        int idx = 1;
        if (!bind_filter(stmt, filter, idx, false)) {
            sqlite3_finalize(stmt);
            return false;
        }
        if (sqlite3_step(stmt) == SQLITE_ROW) out = static_cast<size_t>(sqlite3_column_int64(stmt, 0));
        sqlite3_finalize(stmt);
        return true;
    });
    return out;
}

bool suppress(const suppression_t& req)
{
    if (!initialize()) return false;
    if (req.finding_id == 0 || req.reason.empty() || req.suppressed_by.empty()) {
        set_error("invalid_suppression_request");
        return false;
    }
    return with_db("finding_suppress", [&](sqlite3* db) {
        issue_t current;
        std::string sql = "SELECT " + select_finding_fields() + " FROM findings WHERE id=?";
        sqlite3_stmt* sel = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &sel, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int64(sel, 1, static_cast<sqlite3_int64>(req.finding_id));
        bool found = false;
        if (sqlite3_step(sel) == SQLITE_ROW) {
            current = issue_from_row(db, sel);
            found = true;
        }
        sqlite3_finalize(sel);
        if (!found) {
            set_error("finding_not_found");
            return false;
        }
        const uint64_t ts = now_ms();
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, "UPDATE findings SET suppressed=1,suppress_reason=?,suppressed_by=?,suppressed_ms=? WHERE id=?", -1, &stmt, nullptr) != SQLITE_OK) return false;
        bind_text(stmt, 1, evidence_store::redact_sensitive_text(req.reason, 1024));
        bind_text(stmt, 2, evidence_store::redact_sensitive_text(req.suppressed_by, 256));
        sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(ts));
        sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(req.finding_id));
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return false;
        if (req.create_rule) {
            sqlite3_stmt* rule = nullptr;
            if (sqlite3_prepare_v2(db, "INSERT INTO suppression_rules(scope,finding_id,type_key,host,reason,suppressed_by,created_ms) VALUES(?,?,?,?,?,?,?)", -1, &rule, nullptr) != SQLITE_OK) return false;
            bind_text(rule, 1, req.scope.empty() ? "finding" : req.scope);
            sqlite3_bind_int64(rule, 2, static_cast<sqlite3_int64>(req.finding_id));
            bind_text(rule, 3, current.type_key);
            bind_text(rule, 4, current.host);
            bind_text(rule, 5, evidence_store::redact_sensitive_text(req.reason, 1024));
            bind_text(rule, 6, evidence_store::redact_sensitive_text(req.suppressed_by, 256));
            sqlite3_bind_int64(rule, 7, static_cast<sqlite3_int64>(ts));
            rc = sqlite3_step(rule);
            sqlite3_finalize(rule);
            if (rc != SQLITE_DONE) return false;
        }
        refresh_session_counts(db, current.session_id);
        return true;
    });
}

dedupe_result_t deduplicate(const finding_filter_t& filter, bool merge_evidence)
{
    dedupe_result_t result;
    result.before_count = count(filter);
    auto items = list(filter);
    std::map<std::string, std::vector<issue_t>> groups;
    for (const auto& item : items) groups[build_dedupe_key(item)].push_back(item);
    with_db("finding_deduplicate", [&](sqlite3* db) {
        if (!exec_simple(db, "BEGIN IMMEDIATE")) return false;
        for (const auto& kv : groups) {
            if (kv.second.size() < 2) continue;
            auto keep_it = std::max_element(kv.second.begin(), kv.second.end(), [](const issue_t& a, const issue_t& b) {
                if (a.confidence != b.confidence) return static_cast<int>(a.confidence) < static_cast<int>(b.confidence);
                if (a.severity != b.severity) return static_cast<int>(a.severity) < static_cast<int>(b.severity);
                return a.seen_ms < b.seen_ms;
            });
            if (keep_it == kv.second.end()) continue;
            const uint64_t keep_id = keep_it->id;
            for (const auto& item : kv.second) {
                if (item.id == keep_id) continue;
                if (merge_evidence) {
                    sqlite3_stmt* upd = nullptr;
                    if (sqlite3_prepare_v2(db, "UPDATE evidence SET finding_id=? WHERE finding_id=?", -1, &upd, nullptr) != SQLITE_OK) {
                        exec_simple(db, "ROLLBACK");
                        return false;
                    }
                    sqlite3_bind_int64(upd, 1, static_cast<sqlite3_int64>(keep_id));
                    sqlite3_bind_int64(upd, 2, static_cast<sqlite3_int64>(item.id));
                    sqlite3_step(upd);
                    sqlite3_finalize(upd);
                    ++result.merged;
                }
                sqlite3_stmt* del = nullptr;
                if (sqlite3_prepare_v2(db, "DELETE FROM findings WHERE id=?", -1, &del, nullptr) != SQLITE_OK) {
                    exec_simple(db, "ROLLBACK");
                    return false;
                }
                sqlite3_bind_int64(del, 1, static_cast<sqlite3_int64>(item.id));
                sqlite3_step(del);
                sqlite3_finalize(del);
                ++result.duplicates_removed;
            }
        }
        if (!exec_simple(db, "COMMIT")) {
            exec_simple(db, "ROLLBACK");
            return false;
        }
        return true;
    });
    result.after_count = count(filter);
    return result;
}

nlohmann::json correlate(const finding_filter_t& filter, bool persist)
{
    auto items = list(filter);
    nlohmann::json correlations = nlohmann::json::array();
    std::map<std::string, std::vector<issue_t>> by_type_host;
    std::map<std::string, std::set<std::string>> classes_by_host;
    for (const auto& item : items) {
        by_type_host[item.type_key + "|" + item.host].push_back(item);
        classes_by_host[item.host].insert(item.type_key);
    }
    for (const auto& kv : by_type_host) {
        std::set<std::string> endpoints;
        for (const auto& item : kv.second) endpoints.insert(item.path.empty() ? "/" : item.path);
        if (endpoints.size() >= 2) {
            const auto& first = kv.second.front();
            nlohmann::json ids = nlohmann::json::array();
            nlohmann::json eps = nlohmann::json::array();
            for (const auto& item : kv.second) ids.push_back(item.id);
            for (const auto& ep : endpoints) eps.push_back(ep);
            nlohmann::json c;
            c["pattern"] = "same_vuln_class_multiple_endpoints";
            c["type_key"] = first.type_key;
            c["host"] = first.host;
            c["finding_count"] = kv.second.size();
            c["endpoints"] = eps;
            c["finding_ids"] = ids;
            c["severity"] = severity_label(first.severity);
            c["description"] = first.type_key + " appears across " + std::to_string(endpoints.size()) + " endpoints on " + first.host;
            correlations.push_back(c);
        }
    }
    for (const auto& kv : classes_by_host) {
        bool has_access = false;
        bool has_injection = false;
        for (const auto& cls : kv.second) {
            const auto k = normalize_case(cls);
            if (k.find("idor") != std::string::npos || k.find("csrf") != std::string::npos || k.find("auth") != std::string::npos) has_access = true;
            if (k.find("xss") != std::string::npos || k.find("sqli") != std::string::npos || k.find("cmdi") != std::string::npos || k.find("ssrf") != std::string::npos) has_injection = true;
        }
        if (has_access && has_injection) {
            nlohmann::json c;
            c["pattern"] = "chained_vulnerability_candidate";
            c["host"] = kv.first;
            c["severity"] = "critical";
            c["description"] = "Access-control and injection findings coexist on the same host";
            c["classes"] = nlohmann::json::array();
            for (const auto& cls : kv.second) c["classes"].push_back(cls);
            correlations.push_back(c);
        }
    }
    if (persist) {
        with_db("finding_correlate_persist", [&](sqlite3* db) {
            for (const auto& c : correlations) {
                sqlite3_stmt* stmt = nullptr;
                if (sqlite3_prepare_v2(db, "INSERT INTO finding_correlations(session_id,pattern,type_key,description,severity,finding_ids_json,endpoints_json,host,created_ms) VALUES(?,?,?,?,?,?,?,?,?)", -1, &stmt, nullptr) != SQLITE_OK) return false;
                bind_nullable_text(stmt, 1, filter.session_id);
                bind_text(stmt, 2, c.value("pattern", std::string()));
                bind_text(stmt, 3, c.value("type_key", std::string()));
                bind_text(stmt, 4, c.value("description", std::string()));
                severity_t sev = severity_t::info;
                parse_severity(c.value("severity", std::string("info")), sev);
                sqlite3_bind_int(stmt, 5, static_cast<int>(sev));
                bind_json(stmt, 6, c.value("finding_ids", nlohmann::json::array()));
                bind_json(stmt, 7, c.value("endpoints", nlohmann::json::array()));
                bind_text(stmt, 8, c.value("host", std::string()));
                sqlite3_bind_int64(stmt, 9, static_cast<sqlite3_int64>(now_ms()));
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            return true;
        });
    }
    nlohmann::json doc;
    doc["total_patterns"] = correlations.size();
    doc["correlations"] = std::move(correlations);
    return doc;
}

nlohmann::json score(const finding_filter_t& filter, uint64_t finding_id, const std::string& cvss_vector_override, bool persist)
{
    std::vector<issue_t> items;
    if (finding_id != 0) {
        issue_t one;
        if (get(finding_id, one)) items.push_back(std::move(one));
    }
    else {
        items = list(filter);
    }
    nlohmann::json arr = nlohmann::json::array();
    for (auto& item : items) {
        nlohmann::json scored = vuln_taxonomy::score_to_json(item.type_key, cvss_vector_override.empty() ? item.cvss_vector : cvss_vector_override);
        if (!item.cwe.empty()) {
            scored["cwe_ids"] = item.cwe;
            nlohmann::json names = nlohmann::json::array();
            for (const auto& cwe : item.cwe) names.push_back(vuln_taxonomy::cwe_name(cwe));
            scored["cwe_names"] = names;
        }
        scored["finding_id"] = item.id;
        arr.push_back(scored);
        if (persist && scored.value("valid", false)) {
            with_db("finding_score_update", [&](sqlite3* db) {
                sqlite3_stmt* stmt = nullptr;
                if (sqlite3_prepare_v2(db, "UPDATE findings SET cvss_score=?,cvss_vector=?,cvss_severity=?,owasp_category=?,cwe_json=? WHERE id=?", -1, &stmt, nullptr) != SQLITE_OK) return false;
                sqlite3_bind_double(stmt, 1, scored.value("cvss_score", 0.0));
                bind_text(stmt, 2, scored.value("cvss_vector", std::string()));
                bind_text(stmt, 3, scored.value("cvss_severity", std::string()));
                bind_text(stmt, 4, scored.value("owasp_category", std::string()));
                bind_json(stmt, 5, scored.value("cwe_ids", nlohmann::json::array()));
                sqlite3_bind_int64(stmt, 6, static_cast<sqlite3_int64>(item.id));
                int rc = sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                return rc == SQLITE_DONE;
            });
        }
    }
    nlohmann::json doc;
    doc["findings"] = std::move(arr);
    doc["count"] = doc["findings"].size();
    return doc;
}

nlohmann::json export_json(const finding_filter_t& filter, bool include_evidence)
{
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& item : list(filter)) {
        nlohmann::json j = issue_store::issue_to_json(item);
        if (!include_evidence) j.erase("evidence");
        j["finding_id"] = item.id;
        arr.push_back(std::move(j));
    }
    nlohmann::json doc;
    doc["count"] = arr.size();
    doc["findings"] = std::move(arr);
    return doc;
}

bool mirror_issue_store(bool replace_existing)
{
    issue_store::initialize();
    issue_filter_t filter;
    filter.include_suppressed = true;
    auto issues = issue_store::list(filter);
    const size_t before_count = count();
    if (replace_existing) {
        if (!with_db("mirror_issue_store_clear", [](sqlite3* db) {
            return exec_simple(db, "DELETE FROM findings WHERE issue_store_id!=0");
        })) {
            diag::log_tagged_fmt("burp_findings", "mirror_issue_store_clear_failed err=%s", last_error().c_str());
            return false;
        }
    }
    size_t imported = 0;
    size_t skipped = 0;
    size_t failed = 0;
    uint64_t first_skipped_id = 0;
    uint64_t first_failed_id = 0;
    std::string first_reason;
    for (auto issue : issues) {
        std::string reason;
        if (!validate_issue_for_mirror(issue, reason)) {
            ++skipped;
            if (first_skipped_id == 0) {
                first_skipped_id = issue.id;
                first_reason = reason;
            }
            diag::log_tagged_fmt("burp_findings",
                "mirror_issue_store_skip issue_store_id=%llu type_key=%s host_present=%d session_present=%d scan_id=%llu audit_id=%llu reason=%s",
                static_cast<unsigned long long>(issue.id),
                issue.type_key.c_str(),
                issue.host.empty() ? 0 : 1,
                issue.session_id.empty() ? 0 : 1,
                static_cast<unsigned long long>(issue.scan_id),
                static_cast<unsigned long long>(issue.audit_id),
                reason.c_str());
            continue;
        }
        uint64_t id = upsert(issue);
        if (id != 0) {
            ++imported;
        } else {
            ++failed;
            if (first_failed_id == 0) first_failed_id = issue.id;
            diag::log_tagged_fmt("burp_findings",
                "mirror_issue_store_failed issue_store_id=%llu type_key=%s host=%s session=%s scan_id=%llu audit_id=%llu err=%s",
                static_cast<unsigned long long>(issue.id),
                issue.type_key.c_str(),
                evidence_store::redact_sensitive_text(issue.host, 256).c_str(),
                session_state_label(issue.session_id).c_str(),
                static_cast<unsigned long long>(issue.scan_id),
                static_cast<unsigned long long>(issue.audit_id),
                last_error().c_str());
        }
    }
    const size_t after_count = count();
    diag::log_tagged_fmt("burp_findings",
        "mirror_issue_store_summary total=%zu valid=%zu imported=%zu skipped=%zu failed=%zu first_skipped_id=%llu first_failed_id=%llu reason=%s before_count=%zu after_count=%zu replace=%d",
        issues.size(),
        issues.size() - skipped,
        imported,
        skipped,
        failed,
        static_cast<unsigned long long>(first_skipped_id),
        static_cast<unsigned long long>(first_failed_id),
        first_reason.c_str(),
        before_count,
        after_count,
        replace_existing ? 1 : 0);
    return failed == 0;
}

bool upsert_scan_run(const scan_run_t& scan)
{
    if (!initialize()) return false;
    if (scan.scan_id == 0 || scan.target_url.empty()) {
        set_error("invalid_scan_run");
        return false;
    }
    return with_db("scan_upsert", [&](sqlite3* db) {
        const char* sql =
            "INSERT INTO scans(scan_id,session_id,target_url,profile,status,total_probes,completed_probes,issues_found,modules_json,defensive_json,config_json,started_ms,ended_ms,error_message) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(scan_id) DO UPDATE SET session_id=excluded.session_id,target_url=excluded.target_url,profile=excluded.profile,status=excluded.status,total_probes=excluded.total_probes,completed_probes=excluded.completed_probes,issues_found=excluded.issues_found,modules_json=excluded.modules_json,defensive_json=excluded.defensive_json,config_json=excluded.config_json,started_ms=excluded.started_ms,ended_ms=excluded.ended_ms,error_message=excluded.error_message";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        int idx = 1;
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(scan.scan_id));
        bind_nullable_text(stmt, idx++, scan.session_id);
        bind_text(stmt, idx++, scan.target_url);
        bind_text(stmt, idx++, scan.profile);
        bind_text(stmt, idx++, scan.status);
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(scan.total_probes));
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(scan.completed_probes));
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(scan.issues_found));
        bind_json(stmt, idx++, scan.modules_json);
        bind_json(stmt, idx++, scan.defensive_json);
        bind_json(stmt, idx++, scan.config_json);
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(scan.started_ms ? scan.started_ms : now_ms()));
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(scan.ended_ms));
        bind_text(stmt, idx++, evidence_store::redact_sensitive_text(scan.error_message, 2048));
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        refresh_session_counts(db, scan.session_id);
        return rc == SQLITE_DONE;
    });
}

bool update_scan_module(const scan_module_status_t& module)
{
    if (!initialize()) return false;
    if (module.scan_id == 0 || module.module_id.empty()) {
        set_error("invalid_scan_module");
        return false;
    }
    return with_db("scan_module_upsert", [&](sqlite3* db) {
        const char* sql =
            "INSERT INTO scan_module_status(scan_id,module_id,status,probes_done,probes_total,issues_found,started_ms,ended_ms,error_message) "
            "VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(scan_id,module_id) DO UPDATE SET status=excluded.status,probes_done=excluded.probes_done,probes_total=excluded.probes_total,issues_found=excluded.issues_found,started_ms=excluded.started_ms,ended_ms=excluded.ended_ms,error_message=excluded.error_message";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        int idx = 1;
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(module.scan_id));
        bind_text(stmt, idx++, module.module_id);
        bind_text(stmt, idx++, module.status);
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(module.probes_done));
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(module.probes_total));
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(module.issues_found));
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(module.started_ms));
        sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(module.ended_ms));
        bind_text(stmt, idx++, evidence_store::redact_sensitive_text(module.error_message, 2048));
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    });
}

bool save_scan_profile(const scan_profile_t& profile)
{
    if (!initialize()) return false;
    if (profile.profile_id.empty() || profile.name.empty()) {
        set_error("invalid_scan_profile");
        return false;
    }
    return with_db("scan_profile_save", [&](sqlite3* db) {
        const char* sql =
            "INSERT INTO scan_profiles(profile_id,name,description,module_ids_json,defensive_checks_json,crawl_depth,max_concurrent,created_ms,is_builtin) "
            "VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(profile_id) DO UPDATE SET name=excluded.name,description=excluded.description,module_ids_json=excluded.module_ids_json,defensive_checks_json=excluded.defensive_checks_json,crawl_depth=excluded.crawl_depth,max_concurrent=excluded.max_concurrent,is_builtin=excluded.is_builtin";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        bind_text(stmt, 1, profile.profile_id);
        bind_text(stmt, 2, profile.name);
        bind_text(stmt, 3, evidence_store::redact_sensitive_text(profile.description, 4096));
        bind_json(stmt, 4, evidence_store::redact_sensitive_json(profile.module_ids_json));
        bind_json(stmt, 5, evidence_store::redact_sensitive_json(profile.defensive_checks_json));
        sqlite3_bind_int(stmt, 6, profile.crawl_depth);
        sqlite3_bind_int(stmt, 7, profile.max_concurrent);
        sqlite3_bind_int64(stmt, 8, static_cast<sqlite3_int64>(profile.created_ms ? profile.created_ms : now_ms()));
        sqlite3_bind_int(stmt, 9, profile.is_builtin ? 1 : 0);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    });
}

std::vector<scan_profile_t> list_scan_profiles(bool include_builtin)
{
    std::vector<scan_profile_t> out;
    if (!initialize()) return out;
    with_db("scan_profile_list", [&](sqlite3* db) {
        std::string sql = "SELECT profile_id,name,description,module_ids_json,defensive_checks_json,crawl_depth,max_concurrent,created_ms,is_builtin FROM scan_profiles";
        if (!include_builtin) sql += " WHERE is_builtin=0";
        sql += " ORDER BY is_builtin DESC,name ASC";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return false;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            scan_profile_t p;
            p.profile_id = column_text(stmt, 0);
            p.name = column_text(stmt, 1);
            p.description = column_text(stmt, 2);
            p.module_ids_json = parse_json_or(column_text(stmt, 3), nlohmann::json::array());
            p.defensive_checks_json = parse_json_or(column_text(stmt, 4), nlohmann::json::array());
            p.crawl_depth = sqlite3_column_int(stmt, 5);
            p.max_concurrent = sqlite3_column_int(stmt, 6);
            p.created_ms = static_cast<uint64_t>(sqlite3_column_int64(stmt, 7));
            p.is_builtin = sqlite3_column_int(stmt, 8) != 0;
            out.push_back(std::move(p));
        }
        sqlite3_finalize(stmt);
        return true;
    });
    return out;
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(g_error_mutex);
    return g_last_error;
}

std::string storage_path()
{
    return resolve_database_path().string();
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string generate_id(const std::string& prefix)
{
    unsigned char bytes[16] = {};
    NTSTATUS st = BCryptGenRandom(nullptr, bytes, static_cast<ULONG>(sizeof(bytes)), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) {
        uint64_t t = now_ms();
        for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = static_cast<unsigned char>((t >> ((i % 8) * 8)) ^ (i * 37u));
    }
    static const char hex[] = "0123456789abcdef";
    std::string out = prefix;
    if (!out.empty() && out.back() != '_') out.push_back('_');
    for (unsigned char b : bytes) {
        out.push_back(hex[(b >> 4) & 0xF]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

bool with_db(const char* operation, const std::function<bool(sqlite3*)>& fn)
{
    if (!g_initialized.load(std::memory_order_acquire)) {
        if (!initialize()) return false;
    }
    std::lock_guard<std::mutex> lk(g_db_mutex);
    sqlite3* db = g_db.load(std::memory_order_acquire);
    if (!db) {
        set_error("not_initialized");
        return false;
    }
    const std::string prior_error = last_error();
    bool ok = false;
    try {
        ok = fn(db);
    } catch (const std::exception& ex) {
        set_error(std::string(operation ? operation : "db_operation") + ": " + ex.what());
        return false;
    } catch (...) {
        set_error(std::string(operation ? operation : "db_operation") + ": exception");
        return false;
    }
    if (!ok) {
        if (last_error() == prior_error) set_sqlite_error(db, operation ? operation : "db_operation");
        return false;
    }
    return true;
}

}
}
}
