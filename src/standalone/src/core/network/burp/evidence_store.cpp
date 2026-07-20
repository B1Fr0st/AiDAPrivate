#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "evidence_store.hpp"

#include "findings_db.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <regex>
#include <sstream>
#include <cstdio>

#pragma comment(lib, "bcrypt.lib")

namespace aida {
namespace burp {
namespace evidence_store {
namespace {

std::mutex g_error_mutex;
std::string g_last_error;
std::atomic<bool> g_initialized{false};

void set_error(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(g_error_mutex);
    g_last_error = msg;
}

std::string lower_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim_copy(const std::string& s)
{
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

bool sensitive_key(const std::string& key)
{
    const std::string k = lower_copy(key);
    static const char* exact[] = {
        "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
        "api-key", "apikey", "x-auth-token", "x-csrf-token", "x-xsrf-token",
        "private-key", "private_key", "license-key", "license_key"
    };
    for (const char* e : exact) {
        if (k == e) return true;
    }
    static const char* contains[] = {
        "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
        "access_token", "refresh_token", "sessionid", "session_id", "license",
        "privatekey", "private_key", "bearer", "credential", "auth"
    };
    for (const char* c : contains) {
        if (k.find(c) != std::string::npos) return true;
    }
    return false;
}

std::string redacted_value(const std::string& value)
{
    const std::string h = sha256_hex(value);
    return std::string("[redacted:sha256:") + h.substr(0, 16) + "]";
}

std::string redact_headers_by_line(const std::string& input)
{
    std::string out;
    out.reserve(input.size());
    size_t pos = 0;
    while (pos < input.size()) {
        size_t line_end = input.find('\n', pos);
        const bool has_lf = line_end != std::string::npos;
        size_t physical_end = has_lf ? line_end : input.size();
        std::string line = input.substr(pos, physical_end - pos);
        std::string newline;
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
            newline = "\r\n";
        }
        else if (has_lf) {
            newline = "\n";
        }
        size_t colon = line.find(':');
        if (colon != std::string::npos && colon > 0 && colon < 96) {
            std::string key = trim_copy(line.substr(0, colon));
            std::string value = trim_copy(line.substr(colon + 1));
            if (sensitive_key(key)) {
                out += key;
                out += ": ";
                out += redacted_value(value);
                out += newline;
                pos = has_lf ? line_end + 1 : input.size();
                continue;
            }
        }
        out += line;
        out += newline;
        pos = has_lf ? line_end + 1 : input.size();
    }
    return out;
}

std::string redact_key_values(const std::string& input)
{
    static const std::regex rx(R"((password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token|license[_-]?key|private[_-]?key|session[_-]?id|authorization)(["']?\s*[:=]\s*["']?)([^"'\s,&;}{\]\[]+))",
                               std::regex_constants::icase);
    std::string out;
    out.reserve(input.size());
    size_t last = 0;
    for (std::sregex_iterator it(input.begin(), input.end(), rx), end; it != end; ++it) {
        const auto& m = *it;
        out.append(input, last, static_cast<size_t>(m.position()) - last);
        out += m.str(1);
        out += m.str(2);
        out += redacted_value(m.str(3));
        last = static_cast<size_t>(m.position() + m.length());
    }
    out.append(input, last, std::string::npos);
    return out;
}

std::string redact_bearer_and_license(const std::string& input)
{
    static const std::regex bearer(R"(\b(Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{8,}))",
                                   std::regex_constants::icase);
    static const std::regex license(R"(\bAIDA-[A-Za-z0-9-]{8,}\b)",
                                    std::regex_constants::icase);
    std::string stage;
    stage.reserve(input.size());
    size_t last = 0;
    for (std::sregex_iterator it(input.begin(), input.end(), bearer), end; it != end; ++it) {
        const auto& m = *it;
        stage.append(input, last, static_cast<size_t>(m.position()) - last);
        stage += m.str(1);
        stage += " ";
        stage += redacted_value(m.str(2));
        last = static_cast<size_t>(m.position() + m.length());
    }
    stage.append(input, last, std::string::npos);
    std::string out;
    out.reserve(stage.size());
    last = 0;
    for (std::sregex_iterator it(stage.begin(), stage.end(), license), end; it != end; ++it) {
        const auto& m = *it;
        out.append(stage, last, static_cast<size_t>(m.position()) - last);
        out += redacted_value(m.str(0));
        last = static_cast<size_t>(m.position() + m.length());
    }
    out.append(stage, last, std::string::npos);
    return out;
}

bool looks_textual(const std::vector<uint8_t>& bytes)
{
    if (bytes.empty()) return true;
    size_t checked = 0;
    size_t control = 0;
    const size_t max_check = (std::min)(bytes.size(), static_cast<size_t>(4096));
    for (size_t i = 0; i < max_check; ++i) {
        unsigned char c = bytes[i];
        if (c == 0) return false;
        if (c < 0x20 && c != '\r' && c != '\n' && c != '\t') ++control;
        ++checked;
    }
    return checked == 0 || control * 20 < checked;
}

std::string safe_filename(std::string name)
{
    std::string out;
    out.reserve(name.size());
    for (char c : name) {
        unsigned char uc = static_cast<unsigned char>(c);
        if ((uc >= 'a' && uc <= 'z') || (uc >= 'A' && uc <= 'Z') || (uc >= '0' && uc <= '9') || c == '.' || c == '_' || c == '-') {
            out.push_back(c);
        }
        else {
            out.push_back('_');
        }
        if (out.size() >= 96) break;
    }
    while (!out.empty() && out.front() == '.') out.erase(out.begin());
    if (out.empty()) out = "evidence.bin";
    if (out == "." || out == "..") out = "evidence.bin";
    return out;
}

bool write_bytes_file(const std::filesystem::path& path, const std::vector<uint8_t>& bytes)
{
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    if (!bytes.empty()) {
        f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    return f.good();
}

bool read_bytes_file(const std::string& path, std::vector<uint8_t>& out)
{
    out.clear();
    std::error_code ec;
    const std::filesystem::path p(path);
    if (path.empty() || !std::filesystem::is_regular_file(p, ec))
        return false;
    const auto sz = std::filesystem::file_size(p, ec);
    if (ec || sz > 64ull * 1024ull * 1024ull)
        return false;
    std::ifstream f(p, std::ios::binary);
    if (!f.is_open())
        return false;
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return f.good() || f.eof();
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

evidence_record_t row_to_record(sqlite3_stmt* stmt)
{
    evidence_record_t r;
    r.id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
    r.finding_id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 1));
    r.session_id = column_text(stmt, 2);
    r.scan_id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 3));
    r.kind = kind_from_string(column_text(stmt, 4));
    r.request_raw = column_text(stmt, 5);
    r.response_raw = column_text(stmt, 6);
    r.marker = column_text(stmt, 7);
    r.marker_offset_request = static_cast<uint64_t>(sqlite3_column_int64(stmt, 8));
    r.marker_offset_response = static_cast<uint64_t>(sqlite3_column_int64(stmt, 9));
    r.screenshot_path = column_text(stmt, 10);
    r.file_path = column_text(stmt, 11);
    r.content_sha256 = column_text(stmt, 12);
    r.timing_json = parse_json_or(column_text(stmt, 13), nlohmann::json::object());
    r.description = column_text(stmt, 14);
    r.exchange_id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 15));
    r.captured_ms = static_cast<uint64_t>(sqlite3_column_int64(stmt, 16));
    r.metadata_json = parse_json_or(column_text(stmt, 17), nlohmann::json::object());
    return r;
}

std::string select_fields()
{
    return "id,finding_id,session_id,scan_id,kind,request_raw,response_raw,marker,marker_offset_request,marker_offset_response,screenshot_path,file_path,content_sha256,timing_json,description,exchange_id,captured_ms,metadata_json";
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

bool capture(const evidence_capture_t& capture, evidence_record_t& out)
{
    if (!initialize()) return false;
    uint64_t finding_id = capture.finding_id;
    std::string resolved_session_id = capture.session_id;
    uint64_t resolved_scan_id = capture.scan_id;
    if (finding_id == 0) {
        if (capture.session_id.empty()) {
            set_error("invalid_finding_id");
            return false;
        }
        issue_t manual;
        manual.session_id = capture.session_id;
        manual.scan_id = capture.scan_id;
        manual.type_key = "evidence.manual";
        manual.name = "Manual Evidence";
        manual.description = "Manual evidence captured for the audit session.";
        manual.remediation = "Review the captured evidence and associate it with a validated finding when triage is complete.";
        manual.severity = severity_t::info;
        manual.confidence = confidence_t::tentative;
        manual.host = "manual-evidence";
        manual.path = "/";
        manual.parameter = kind_to_string(capture.kind);
        manual.src_exchange_id = capture.exchange_id;
        manual.seen_ms = findings_db::now_ms();
        resolved_session_id = manual.session_id;
        resolved_scan_id = manual.scan_id;
        finding_id = findings_db::upsert(std::move(manual));
        if (finding_id == 0) {
            set_error(findings_db::last_error().empty() ? "manual_evidence_finding_failed" : findings_db::last_error());
            return false;
        }
    }
    else {
        issue_t existing;
        if (!findings_db::get(finding_id, existing)) {
            set_error("finding_not_found");
            return false;
        }
        if (!resolved_session_id.empty() && !existing.session_id.empty() && resolved_session_id != existing.session_id) {
            set_error("evidence_session_mismatch");
            return false;
        }
        if (resolved_session_id.empty())
            resolved_session_id = existing.session_id;
        if (resolved_scan_id == 0)
            resolved_scan_id = existing.scan_id;
    }

    evidence_record_t record;
    record.finding_id = finding_id;
    record.session_id = resolved_session_id;
    record.scan_id = resolved_scan_id;
    record.kind = capture.kind;
    record.request_raw = redact_sensitive_text(capture.request_raw);
    record.response_raw = redact_sensitive_text(capture.response_raw);
    record.marker = redact_sensitive_text(capture.marker, 512);
    record.marker_offset_request = capture.marker_offset_request;
    record.marker_offset_response = capture.marker_offset_response;
    record.description = redact_sensitive_text(capture.description, 4096);
    record.exchange_id = capture.exchange_id;
    record.captured_ms = findings_db::now_ms();
    record.timing_json = redact_sensitive_json(capture.timing_json);
    record.metadata_json = redact_sensitive_json(capture.metadata_json);

    std::vector<uint8_t> bytes_to_write = capture.bytes;
    if (bytes_to_write.empty() && !capture.source_path.empty() &&
        (capture.kind == evidence_kind_t::file || capture.kind == evidence_kind_t::screenshot)) {
        if (!read_bytes_file(capture.source_path, bytes_to_write)) {
            set_error("evidence_source_read_failed");
            return false;
        }
        record.metadata_json["source_path_sha256"] = sha256_hex(capture.source_path);
        record.metadata_json["source_path_name"] = safe_filename(std::filesystem::path(capture.source_path).filename().string());
    }
    if (bytes_to_write.empty() && (capture.kind == evidence_kind_t::file || capture.kind == evidence_kind_t::screenshot)) {
        set_error("evidence_file_bytes_required");
        return false;
    }
    if (capture.kind == evidence_kind_t::file && !bytes_to_write.empty() && looks_textual(bytes_to_write)) {
        std::string text(reinterpret_cast<const char*>(bytes_to_write.data()), bytes_to_write.size());
        text = redact_sensitive_text(text);
        bytes_to_write.assign(text.begin(), text.end());
    }

    if (!bytes_to_write.empty()) {
        record.content_sha256 = sha256_hex(bytes_to_write);
        std::filesystem::path dir(storage_dir());
        const std::string base = safe_filename(capture.file_name.empty() ? (kind_to_string(capture.kind) + ".bin") : capture.file_name);
        const std::string name = std::to_string(record.captured_ms) + "_" + record.content_sha256.substr(0, 16) + "_" + base;
        std::filesystem::path path = dir / name;
        if (!write_bytes_file(path, bytes_to_write)) {
            set_error("evidence_file_write_failed");
            return false;
        }
        if (capture.kind == evidence_kind_t::screenshot) {
            record.screenshot_path = path.string();
        }
        else {
            record.file_path = path.string();
        }
    }
    else {
        const std::string material = record.request_raw + "\n" + record.response_raw + "\n" + record.marker + "\n" + record.timing_json.dump();
        record.content_sha256 = sha256_hex(material);
    }

    bool ok = findings_db::with_db("evidence_capture", [&](sqlite3* db) {
        const char* sql =
            "INSERT INTO evidence(finding_id,session_id,scan_id,kind,request_raw,response_raw,marker,marker_offset_request,marker_offset_response,screenshot_path,file_path,content_sha256,timing_json,description,exchange_id,captured_ms,metadata_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        bool bound =
            sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(record.finding_id)) == SQLITE_OK &&
            findings_db::bind_optional_session_id(db, stmt, 2, record.session_id, "evidence") &&
            sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(record.scan_id)) == SQLITE_OK &&
            bind_text(stmt, 4, kind_to_string(record.kind)) &&
            bind_text(stmt, 5, record.request_raw) &&
            bind_text(stmt, 6, record.response_raw) &&
            bind_text(stmt, 7, record.marker) &&
            sqlite3_bind_int64(stmt, 8, static_cast<sqlite3_int64>(record.marker_offset_request)) == SQLITE_OK &&
            sqlite3_bind_int64(stmt, 9, static_cast<sqlite3_int64>(record.marker_offset_response)) == SQLITE_OK &&
            bind_text(stmt, 10, record.screenshot_path) &&
            bind_text(stmt, 11, record.file_path) &&
            bind_text(stmt, 12, record.content_sha256) &&
            bind_json(stmt, 13, record.timing_json) &&
            bind_text(stmt, 14, record.description) &&
            sqlite3_bind_int64(stmt, 15, static_cast<sqlite3_int64>(record.exchange_id)) == SQLITE_OK &&
            sqlite3_bind_int64(stmt, 16, static_cast<sqlite3_int64>(record.captured_ms)) == SQLITE_OK &&
            bind_json(stmt, 17, record.metadata_json);
        if (!bound) {
            sqlite3_finalize(stmt);
            return false;
        }
        const int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return false;
        record.id = static_cast<uint64_t>(sqlite3_last_insert_rowid(db));
        return true;
    });
    if (!ok) {
        if (!record.screenshot_path.empty()) {
            std::error_code ec;
            std::filesystem::remove(record.screenshot_path, ec);
        }
        if (!record.file_path.empty()) {
            std::error_code ec;
            std::filesystem::remove(record.file_path, ec);
        }
        set_error(findings_db::last_error().empty() ? "evidence_insert_failed" : findings_db::last_error());
        return false;
    }
    out = std::move(record);
    return true;
}

bool capture_request_response(uint64_t finding_id, const std::string& request_raw, const std::string& response_raw, evidence_record_t& out, const std::string& session_id, uint64_t scan_id)
{
    evidence_capture_t req;
    req.finding_id = finding_id;
    req.session_id = session_id;
    req.scan_id = scan_id;
    req.kind = evidence_kind_t::request_response;
    req.request_raw = request_raw;
    req.response_raw = response_raw;
    return evidence_store::capture(req, out);
}

bool capture_screenshot(uint64_t finding_id, const std::vector<uint8_t>& image_bytes, const std::string& file_name, evidence_record_t& out, const std::string& session_id)
{
    evidence_capture_t capture;
    capture.finding_id = finding_id;
    capture.session_id = session_id;
    capture.kind = evidence_kind_t::screenshot;
    capture.file_name = file_name.empty() ? "screenshot.png" : file_name;
    capture.bytes = image_bytes;
    return evidence_store::capture(capture, out);
}

bool capture_file(uint64_t finding_id, const std::vector<uint8_t>& file_bytes, const std::string& file_name, evidence_record_t& out, const std::string& session_id)
{
    evidence_capture_t capture;
    capture.finding_id = finding_id;
    capture.session_id = session_id;
    capture.kind = evidence_kind_t::file;
    capture.file_name = file_name.empty() ? "evidence.txt" : file_name;
    capture.bytes = file_bytes;
    return evidence_store::capture(capture, out);
}

bool capture_timing(uint64_t finding_id, const nlohmann::json& timing_json, evidence_record_t& out, const std::string& session_id)
{
    evidence_capture_t capture;
    capture.finding_id = finding_id;
    capture.session_id = session_id;
    capture.kind = evidence_kind_t::timing;
    capture.timing_json = timing_json;
    return evidence_store::capture(capture, out);
}

std::vector<evidence_record_t> list_for_finding(uint64_t finding_id)
{
    evidence_filter_t filter;
    filter.finding_id = finding_id;
    filter.limit = 0;
    return list(filter);
}

std::vector<evidence_record_t> list(const evidence_filter_t& filter)
{
    std::vector<evidence_record_t> out;
    if (!initialize()) return out;
    findings_db::with_db("evidence_list_filtered", [&](sqlite3* db) {
        std::string sql = "SELECT " + select_fields() + " FROM evidence WHERE 1=1";
        if (!filter.session_id.empty()) sql += " AND session_id=?";
        if (filter.finding_id != 0) sql += " AND finding_id=?";
        if (filter.exchange_id != 0) sql += " AND exchange_id=?";
        if (filter.has_kind) sql += " AND kind=?";
        sql += " ORDER BY captured_ms DESC,id DESC";
        if (filter.limit > 0) sql += " LIMIT ?";
        if (filter.offset > 0) sql += " OFFSET ?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return false;
        int idx = 1;
        if (!filter.session_id.empty()) bind_text(stmt, idx++, filter.session_id);
        if (filter.finding_id != 0) sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.finding_id));
        if (filter.exchange_id != 0) sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.exchange_id));
        if (filter.has_kind) bind_text(stmt, idx++, kind_to_string(filter.kind));
        if (filter.limit > 0) sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.limit));
        if (filter.offset > 0) sqlite3_bind_int64(stmt, idx++, static_cast<sqlite3_int64>(filter.offset));
        while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(row_to_record(stmt));
        sqlite3_finalize(stmt);
        return true;
    });
    return out;
}

bool get(uint64_t evidence_id, evidence_record_t& out)
{
    if (!initialize()) return false;
    bool found = false;
    bool ok = findings_db::with_db("evidence_get", [&](sqlite3* db) {
        std::string sql = "SELECT " + select_fields() + " FROM evidence WHERE id=?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(evidence_id));
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            out = row_to_record(stmt);
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
        set_error("evidence_not_found");
        return false;
    }
    return true;
}

nlohmann::json summary_json(const evidence_record_t& record)
{
    nlohmann::json j = nlohmann::json::object();
    auto path_summary = [](const std::string& path) {
        nlohmann::json out = nlohmann::json::object();
        if (path.empty())
            return out;
        out["stored"] = true;
        out["name"] = safe_filename(std::filesystem::path(path).filename().string());
        out["path_sha256"] = sha256_hex(path);
        return out;
    };
    j["id"] = record.id;
    j["finding_id"] = record.finding_id;
    j["session_id"] = record.session_id;
    j["scan_id"] = record.scan_id;
    j["kind"] = kind_to_string(record.kind);
    j["request_bytes"] = record.request_raw.size();
    j["response_bytes"] = record.response_raw.size();
    j["marker"] = redact_sensitive_text(record.marker, 512);
    j["marker_offset_request"] = record.marker_offset_request;
    j["marker_offset_response"] = record.marker_offset_response;
    j["screenshot"] = path_summary(record.screenshot_path);
    j["file"] = path_summary(record.file_path);
    j["screenshot_path"] = record.screenshot_path.empty() ? std::string() : std::string("[redacted:stored_path]");
    j["file_path"] = record.file_path.empty() ? std::string() : std::string("[redacted:stored_path]");
    j["content_sha256"] = record.content_sha256;
    j["timing"] = redact_sensitive_json(record.timing_json);
    j["description"] = redact_sensitive_text(record.description, 1024);
    j["exchange_id"] = record.exchange_id;
    j["captured_ms"] = record.captured_ms;
    j["metadata"] = redact_sensitive_json(record.metadata_json);
    return j;
}

nlohmann::json export_json(uint64_t finding_id)
{
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& record : list_for_finding(finding_id)) arr.push_back(summary_json(record));
    nlohmann::json doc = nlohmann::json::object();
    doc["finding_id"] = finding_id;
    doc["count"] = arr.size();
    doc["evidence"] = std::move(arr);
    return doc;
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(g_error_mutex);
    return g_last_error;
}

std::string storage_dir()
{
    const std::filesystem::path db_path(findings_db::storage_path());
    const std::filesystem::path dir = db_path.parent_path() / "evidence";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir.string();
}

std::string kind_to_string(evidence_kind_t kind)
{
    switch (kind) {
        case evidence_kind_t::request_response: return "request_response";
        case evidence_kind_t::screenshot:       return "screenshot";
        case evidence_kind_t::file:             return "file";
        case evidence_kind_t::timing:           return "timing";
    }
    return "request_response";
}

evidence_kind_t kind_from_string(const std::string& kind)
{
    if (kind == "screenshot") return evidence_kind_t::screenshot;
    if (kind == "file") return evidence_kind_t::file;
    if (kind == "timing") return evidence_kind_t::timing;
    return evidence_kind_t::request_response;
}

std::string sha256_hex(const std::string& input)
{
    std::vector<uint8_t> bytes(input.begin(), input.end());
    return sha256_hex(bytes);
}

std::string sha256_hex(const std::vector<uint8_t>& input)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    unsigned char digest[32] = {};
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (st == 0) st = BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);
    if (st == 0 && !input.empty()) {
        st = BCryptHashData(hash,
                            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(input.data())),
                            static_cast<ULONG>(input.size()),
                            0);
    }
    if (st == 0) st = BCryptFinishHash(hash, digest, static_cast<ULONG>(sizeof(digest)), 0);
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (st != 0) {
        uint64_t h = 1469598103934665603ull;
        for (uint8_t b : input) {
            h ^= b;
            h *= 1099511628211ull;
        }
        char fallback[65] = {};
        std::snprintf(fallback, sizeof(fallback), "%016llx%016llx%016llx%016llx",
                      static_cast<unsigned long long>(h),
                      static_cast<unsigned long long>(h ^ 0x9e3779b97f4a7c15ull),
                      static_cast<unsigned long long>(~h),
                      static_cast<unsigned long long>(h + input.size()));
        return fallback;
    }
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.resize(64);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        out[i * 2] = hex[(digest[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[digest[i] & 0xF];
    }
    return out;
}

std::string redact_sensitive_text(const std::string& input, size_t max_chars)
{
    std::string out = redact_headers_by_line(input);
    out = redact_key_values(out);
    out = redact_bearer_and_license(out);
    if (max_chars > 0 && out.size() > max_chars) {
        out.resize(max_chars);
        out += "... [truncated]";
    }
    return out;
}

nlohmann::json redact_sensitive_json(const nlohmann::json& input, size_t max_string_chars)
{
    if (input.is_object()) {
        nlohmann::json out = nlohmann::json::object();
        for (auto it = input.begin(); it != input.end(); ++it) {
            if (sensitive_key(it.key())) {
                if (it.value().is_string()) out[it.key()] = redacted_value(it.value().get<std::string>());
                else out[it.key()] = "[redacted]";
            }
            else {
                out[it.key()] = redact_sensitive_json(it.value(), max_string_chars);
            }
        }
        return out;
    }
    if (input.is_array()) {
        nlohmann::json out = nlohmann::json::array();
        for (const auto& item : input) out.push_back(redact_sensitive_json(item, max_string_chars));
        return out;
    }
    if (input.is_string()) {
        return redact_sensitive_text(input.get<std::string>(), max_string_chars);
    }
    return input;
}

}
}
}
