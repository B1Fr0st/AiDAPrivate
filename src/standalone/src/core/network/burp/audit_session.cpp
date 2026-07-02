#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include "audit_session.hpp"

#include "evidence_store.hpp"
#include "findings_db.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <mutex>

namespace aida {
namespace burp {
namespace audit_session {
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

struct parsed_target_t
{
    std::string url;
    std::string scheme;
    std::string host;
    uint16_t port = 0;
};

parsed_target_t parse_target_url(std::string url)
{
    parsed_target_t out;
    auto trim = [](std::string s) {
        size_t a = 0;
        while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
        size_t b = s.size();
        while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
        return s.substr(a, b - a);
    };
    url = trim(url);
    size_t scheme_pos = url.find("://");
    if (scheme_pos != std::string::npos) {
        out.scheme = lower_copy(url.substr(0, scheme_pos));
        url = url.substr(scheme_pos + 3);
    }
    else {
        out.scheme = "https";
    }
    size_t slash = url.find('/');
    std::string authority = slash == std::string::npos ? url : url.substr(0, slash);
    std::string path = slash == std::string::npos ? "/" : url.substr(slash);
    size_t at = authority.rfind('@');
    if (at != std::string::npos) authority = authority.substr(at + 1);
    if (!authority.empty() && authority.front() == '[') {
        size_t close = authority.find(']');
        if (close != std::string::npos) {
            out.host = authority.substr(1, close - 1);
            if (close + 1 < authority.size() && authority[close + 1] == ':') {
                int p = std::atoi(authority.substr(close + 2).c_str());
                if (p > 0 && p <= 65535) out.port = static_cast<uint16_t>(p);
            }
        }
    }
    else {
        size_t colon = authority.rfind(':');
        if (colon != std::string::npos && authority.find(':') == colon) {
            out.host = authority.substr(0, colon);
            int p = std::atoi(authority.substr(colon + 1).c_str());
            if (p > 0 && p <= 65535) out.port = static_cast<uint16_t>(p);
        }
        else {
            out.host = authority;
        }
    }
    if (out.port == 0) out.port = out.scheme == "http" ? 80 : (out.scheme == "https" ? 443 : 0);
    if (!path.empty() && path.front() != '/') path.insert(path.begin(), '/');
    out.url = out.scheme + "://" + out.host;
    if (!((out.scheme == "http" && out.port == 80) || (out.scheme == "https" && out.port == 443) || out.port == 0)) {
        out.url += ":" + std::to_string(out.port);
    }
    out.url += path.empty() ? "/" : path;
    return out;
}

void refresh_counts(sqlite3* db, const std::string& session_id)
{
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

session_t row_to_session(sqlite3_stmt* stmt)
{
    session_t s;
    s.session_id = column_text(stmt, 0);
    s.title = column_text(stmt, 1);
    s.description = column_text(stmt, 2);
    s.created_ms = static_cast<uint64_t>(sqlite3_column_int64(stmt, 3));
    s.closed_ms = static_cast<uint64_t>(sqlite3_column_int64(stmt, 4));
    s.status = column_text(stmt, 5);
    s.scope_json = parse_json_or(column_text(stmt, 6), nlohmann::json::array());
    s.auth_json = parse_json_or(column_text(stmt, 7), nlohmann::json::object());
    s.notes_json = parse_json_or(column_text(stmt, 8), nlohmann::json::array());
    s.target_count = static_cast<uint64_t>(sqlite3_column_int64(stmt, 9));
    s.finding_count = static_cast<uint64_t>(sqlite3_column_int64(stmt, 10));
    s.scan_count = static_cast<uint64_t>(sqlite3_column_int64(stmt, 11));
    s.metadata_json = parse_json_or(column_text(stmt, 12), nlohmann::json::object());
    return s;
}

audit_target_t row_to_target(sqlite3_stmt* stmt)
{
    audit_target_t t;
    t.id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
    t.session_id = column_text(stmt, 1);
    t.url = column_text(stmt, 2);
    t.host = column_text(stmt, 3);
    int port = sqlite3_column_int(stmt, 4);
    t.port = static_cast<uint16_t>((std::max)(0, (std::min)(65535, port)));
    t.scheme = column_text(stmt, 5);
    t.added_ms = static_cast<uint64_t>(sqlite3_column_int64(stmt, 6));
    t.is_primary = sqlite3_column_int(stmt, 7) != 0;
    return t;
}

std::string select_session_fields()
{
    return "session_id,title,description,created_ms,closed_ms,status,scope_json,auth_json,notes_json,target_count,finding_count,scan_count,metadata_json";
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

bool create(const create_request_t& req, session_t& out)
{
    if (!initialize()) return false;
    for (const auto& target : req.targets) {
        if (parse_target_url(target).host.empty()) {
            set_error("invalid_initial_target");
            return false;
        }
    }
    session_t session;
    session.session_id = findings_db::generate_id("audit");
    session.title = evidence_store::redact_sensitive_text(req.title.empty() ? session.session_id : req.title, 256);
    session.description = evidence_store::redact_sensitive_text(req.description, 4096);
    session.created_ms = findings_db::now_ms();
    session.closed_ms = 0;
    session.status = "active";
    session.scope_json = evidence_store::redact_sensitive_json(req.scope_json);
    session.auth_json = evidence_store::redact_sensitive_json(req.auth_json);
    session.notes_json = evidence_store::redact_sensitive_json(req.notes_json);
    session.metadata_json = evidence_store::redact_sensitive_json(req.metadata_json);
    bool ok = findings_db::with_db("audit_session_create", [&](sqlite3* db) {
        const char* sql =
            "INSERT INTO audit_sessions(session_id,title,description,created_ms,closed_ms,status,scope_json,auth_json,notes_json,target_count,finding_count,scan_count,metadata_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        bind_text(stmt, 1, session.session_id);
        bind_text(stmt, 2, session.title);
        bind_text(stmt, 3, session.description);
        sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(session.created_ms));
        sqlite3_bind_int64(stmt, 5, 0);
        bind_text(stmt, 6, session.status);
        bind_json(stmt, 7, session.scope_json);
        bind_json(stmt, 8, session.auth_json);
        bind_json(stmt, 9, session.notes_json);
        sqlite3_bind_int64(stmt, 10, 0);
        sqlite3_bind_int64(stmt, 11, 0);
        sqlite3_bind_int64(stmt, 12, 0);
        bind_json(stmt, 13, session.metadata_json);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    });
    if (!ok) {
        set_error(findings_db::last_error());
        return false;
    }
    bool primary = true;
    for (const auto& target : req.targets) {
        audit_target_t ignored;
        add_target(session.session_id, target, primary, ignored);
        primary = false;
    }
    if (!get(session.session_id, out)) out = std::move(session);
    return true;
}

std::vector<session_t> list(const list_filter_t& filter)
{
    std::vector<session_t> out;
    if (!initialize()) return out;
    findings_db::with_db("audit_session_list", [&](sqlite3* db) {
        std::string sql = "SELECT " + select_session_fields() + " FROM audit_sessions WHERE 1=1";
        if (!filter.include_closed) sql += " AND status!='closed'";
        if (!filter.status.empty()) sql += " AND status=?";
        if (!filter.title_substring.empty()) sql += " AND title LIKE ?";
        sql += " ORDER BY created_ms DESC";
        if (filter.limit > 0) sql += " LIMIT ?";
        if (filter.offset > 0) sql += " OFFSET ?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return false;
        int idx = 1;
        if (!filter.status.empty()) bind_text(stmt, idx++, filter.status);
        if (!filter.title_substring.empty()) bind_text(stmt, idx++, "%" + filter.title_substring + "%");
        if (filter.limit > 0) sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.limit));
        if (filter.offset > 0) sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.offset));
        while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(row_to_session(stmt));
        sqlite3_finalize(stmt);
        return true;
    });
    return out;
}

bool get(const std::string& session_id, session_t& out)
{
    if (!initialize()) return false;
    if (session_id.empty()) {
        set_error("invalid_session_id");
        return false;
    }
    bool found = false;
    bool ok = findings_db::with_db("audit_session_get", [&](sqlite3* db) {
        refresh_counts(db, session_id);
        std::string sql = "SELECT " + select_session_fields() + " FROM audit_sessions WHERE session_id=?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return false;
        bind_text(stmt, 1, session_id);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            out = row_to_session(stmt);
            found = true;
        }
        sqlite3_finalize(stmt);
        return true;
    });
    if (!ok) {
        set_error(findings_db::last_error());
        return false;
    }
    if (!found) {
        set_error("audit_session_not_found");
        return false;
    }
    return true;
}

bool update(const update_request_t& req, session_t& out)
{
    session_t current;
    if (!get(req.session_id, current)) return false;
    if (req.has_title) current.title = evidence_store::redact_sensitive_text(req.title, 256);
    if (req.has_description) current.description = evidence_store::redact_sensitive_text(req.description, 4096);
    if (req.has_status) current.status = evidence_store::redact_sensitive_text(req.status, 64);
    if (req.has_scope) current.scope_json = evidence_store::redact_sensitive_json(req.scope_json);
    if (req.has_auth) current.auth_json = evidence_store::redact_sensitive_json(req.auth_json);
    if (req.has_notes) current.notes_json = evidence_store::redact_sensitive_json(req.notes_json);
    if (req.has_metadata) current.metadata_json = evidence_store::redact_sensitive_json(req.metadata_json);
    bool ok = findings_db::with_db("audit_session_update", [&](sqlite3* db) {
        const char* sql =
            "UPDATE audit_sessions SET title=?,description=?,status=?,scope_json=?,auth_json=?,notes_json=?,metadata_json=? WHERE session_id=?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        bind_text(stmt, 1, current.title);
        bind_text(stmt, 2, current.description);
        bind_text(stmt, 3, current.status);
        bind_json(stmt, 4, current.scope_json);
        bind_json(stmt, 5, current.auth_json);
        bind_json(stmt, 6, current.notes_json);
        bind_json(stmt, 7, current.metadata_json);
        bind_text(stmt, 8, current.session_id);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    });
    if (!ok) {
        set_error(findings_db::last_error());
        return false;
    }
    return get(req.session_id, out);
}

bool close(const std::string& session_id, session_t& out)
{
    if (session_id.empty()) {
        set_error("invalid_session_id");
        return false;
    }
    bool ok = findings_db::with_db("audit_session_close", [&](sqlite3* db) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, "UPDATE audit_sessions SET status='closed',closed_ms=? WHERE session_id=?", -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(findings_db::now_ms()));
        bind_text(stmt, 2, session_id);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    });
    if (!ok) {
        set_error(findings_db::last_error());
        return false;
    }
    return get(session_id, out);
}

bool remove(const std::string& session_id)
{
    if (!initialize()) return false;
    if (session_id.empty()) {
        set_error("invalid_session_id");
        return false;
    }
    bool ok = findings_db::with_db("audit_session_remove", [&](sqlite3* db) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, "DELETE FROM audit_sessions WHERE session_id=?", -1, &stmt, nullptr) != SQLITE_OK) return false;
        bind_text(stmt, 1, session_id);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    });
    if (!ok) set_error(findings_db::last_error());
    return ok;
}

bool add_target(const std::string& session_id, const std::string& url, bool is_primary, audit_target_t& out)
{
    if (!initialize()) return false;
    auto parsed = parse_target_url(url);
    if (session_id.empty() || parsed.host.empty()) {
        set_error("invalid_target");
        return false;
    }
    bool ok = findings_db::with_db("audit_session_target_add", [&](sqlite3* db) {
        if (is_primary) {
            sqlite3_stmt* clear = nullptr;
            if (sqlite3_prepare_v2(db, "UPDATE audit_targets SET is_primary=0 WHERE session_id=?", -1, &clear, nullptr) == SQLITE_OK) {
                bind_text(clear, 1, session_id);
                sqlite3_step(clear);
                sqlite3_finalize(clear);
            }
        }
        const char* sql = "INSERT INTO audit_targets(session_id,url,host,port,scheme,added_ms,is_primary) VALUES(?,?,?,?,?,?,?)";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        bind_text(stmt, 1, session_id);
        bind_text(stmt, 2, parsed.url);
        bind_text(stmt, 3, parsed.host);
        sqlite3_bind_int(stmt, 4, static_cast<int>(parsed.port));
        bind_text(stmt, 5, parsed.scheme);
        sqlite3_bind_int64(stmt, 6, static_cast<sqlite3_int64>(findings_db::now_ms()));
        sqlite3_bind_int(stmt, 7, is_primary ? 1 : 0);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return false;
        out.id = static_cast<uint64_t>(sqlite3_last_insert_rowid(db));
        out.session_id = session_id;
        out.url = parsed.url;
        out.host = parsed.host;
        out.port = parsed.port;
        out.scheme = parsed.scheme;
        out.added_ms = findings_db::now_ms();
        out.is_primary = is_primary;
        refresh_counts(db, session_id);
        return true;
    });
    if (!ok) set_error(findings_db::last_error());
    return ok;
}

std::vector<audit_target_t> list_targets(const std::string& session_id)
{
    std::vector<audit_target_t> out;
    if (!initialize() || session_id.empty()) return out;
    findings_db::with_db("audit_session_target_list", [&](sqlite3* db) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT id,session_id,url,host,port,scheme,added_ms,is_primary FROM audit_targets WHERE session_id=? ORDER BY is_primary DESC,added_ms ASC,id ASC", -1, &stmt, nullptr) != SQLITE_OK) return false;
        bind_text(stmt, 1, session_id);
        while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(row_to_target(stmt));
        sqlite3_finalize(stmt);
        return true;
    });
    return out;
}

bool remove_target(const std::string& session_id, uint64_t target_id)
{
    if (!initialize()) return false;
    if (session_id.empty() || target_id == 0) {
        set_error("invalid_target");
        return false;
    }
    bool ok = findings_db::with_db("audit_session_target_remove", [&](sqlite3* db) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, "DELETE FROM audit_targets WHERE session_id=? AND id=?", -1, &stmt, nullptr) != SQLITE_OK) return false;
        bind_text(stmt, 1, session_id);
        sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(target_id));
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        refresh_counts(db, session_id);
        return rc == SQLITE_DONE;
    });
    if (!ok) set_error(findings_db::last_error());
    return ok;
}

nlohmann::json session_to_json(const session_t& session, bool include_targets)
{
    nlohmann::json j;
    j["session_id"] = session.session_id;
    j["title"] = session.title;
    j["description"] = session.description;
    j["created_ms"] = session.created_ms;
    j["closed_ms"] = session.closed_ms;
    j["status"] = session.status;
    j["scope"] = session.scope_json;
    j["auth"] = evidence_store::redact_sensitive_json(session.auth_json);
    j["notes"] = evidence_store::redact_sensitive_json(session.notes_json);
    j["target_count"] = session.target_count;
    j["finding_count"] = session.finding_count;
    j["scan_count"] = session.scan_count;
    j["metadata"] = evidence_store::redact_sensitive_json(session.metadata_json);
    if (include_targets) {
        j["targets"] = nlohmann::json::array();
        for (const auto& target : list_targets(session.session_id)) j["targets"].push_back(target_to_json(target));
    }
    return j;
}

nlohmann::json target_to_json(const audit_target_t& target)
{
    nlohmann::json j;
    j["id"] = target.id;
    j["session_id"] = target.session_id;
    j["url"] = target.url;
    j["host"] = target.host;
    j["port"] = target.port;
    j["scheme"] = target.scheme;
    j["added_ms"] = target.added_ms;
    j["is_primary"] = target.is_primary;
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
