#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>

#ifdef small
#undef small
#endif

#include "audit_session_mcp.hpp"

#include "audit_http.hpp"
#include "../../settings/standalone_compat.hpp"
#include "../js_analysis_tools_standalone.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <mutex>
#include <sstream>
#include <string>
#include <system_error>
#include <utility>

namespace aida {
namespace burp {
namespace audit_session_mcp_store {

namespace {

using json = nlohmann::json;

struct state_t
{
    std::mutex                 mtx;
    std::vector<session_t>     sessions;
    std::vector<evidence_record_t> evidence;
    std::vector<suppression_t> suppressions;
    std::vector<audit_entry_t> audit;
    std::atomic<uint64_t>      next_session{1};
    std::atomic<uint64_t>      next_target{1};
    std::atomic<uint64_t>      next_evidence{1};
    std::atomic<uint64_t>      next_suppression{1};
    std::atomic<uint64_t>      next_audit{1};
    std::atomic<bool>          initialized{false};
    std::mutex                 err_mtx;
    std::string                last_err;
};

state_t& state()
{
    static state_t s;
    return s;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

void set_error(const std::string& value)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    s.last_err = value;
}

std::string lower_copy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool sensitive_key(const std::string& key)
{
    const std::string k = lower_copy(key);
    static const char* needles[] = {
        "token", "secret", "password", "passwd", "pwd", "authorization", "cookie", "session", "license", "api_key", "apikey", "private_key", "credential", "bearer", "hmac", "kms", "oauth", "refresh"
    };
    for (const char* needle : needles) {
        if (k.find(needle) != std::string::npos)
            return true;
    }
    return false;
}

std::string truncate_text(const std::string& value, size_t max_len)
{
    if (value.size() <= max_len)
        return value;
    return value.substr(0, max_len) + "...[truncated]";
}

std::string appdata_dir()
{
    PWSTR known = nullptr;
    std::string out;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &known)) && known) {
        const int needed = WideCharToMultiByte(CP_UTF8, 0, known, -1, nullptr, 0, nullptr, nullptr);
        if (needed > 1) {
            out.resize(static_cast<size_t>(needed - 1));
            WideCharToMultiByte(CP_UTF8, 0, known, -1, out.data(), needed, nullptr, nullptr);
        }
        CoTaskMemFree(known);
    }
    if (out.empty()) {
        char buf[MAX_PATH] = {};
        const DWORD len = GetEnvironmentVariableA("APPDATA", buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH)
            out.assign(buf, len);
    }
    if (out.empty())
        out = "C:\\Users\\Public";
    return out;
}

void ensure_parent(const std::string& path)
{
    std::error_code ec;
    std::filesystem::path p(path);
    if (p.has_parent_path())
        std::filesystem::create_directories(p.parent_path(), ec);
}

bool valid_status(const std::string& status)
{
    const std::string s = lower_copy(status);
    return s == "open" || s == "closed" || s == "paused";
}

std::string normalized_status(const std::string& status)
{
    const std::string s = lower_copy(status);
    if (valid_status(s))
        return s;
    return "open";
}

std::string make_session_id(uint64_t id)
{
    std::ostringstream os;
    os << "audit_" << now_ms() << "_" << id;
    return os.str();
}

std::string make_target_id(uint64_t id)
{
    std::ostringstream os;
    os << "target_" << id;
    return os.str();
}

bool target_matches_remove_id(const target_t& t, const std::string& id)
{
    return t.id == id || t.url == id || (!t.host.empty() && t.host == id);
}

json string_summary(const std::string& value, bool force_sensitive)
{
    json out;
    out["length"] = static_cast<uint64_t>(value.size());
    out["sha256"] = hash_for_output(value);
    out["redacted"] = true;
    if (!force_sensitive) {
        const std::string redacted = redact_for_output(value);
        out["preview"] = truncate_text(redacted, 512);
    }
    return out;
}

target_t target_from_json(const json& j)
{
    target_t t;
    if (!j.is_object())
        return t;
    t.id = j.value("id", std::string());
    t.label = j.value("label", std::string());
    t.url = j.value("url", std::string());
    t.scheme = j.value("scheme", std::string());
    t.host = j.value("host", std::string());
    if (j.contains("port") && j["port"].is_number_unsigned()) {
        const uint64_t port = j["port"].get<uint64_t>();
        if (port <= 65535)
            t.port = static_cast<uint16_t>(port);
    }
    t.path = j.value("path", std::string());
    t.added_ms = j.value("added_ms", 0ull);
    t.active = j.value("active", true);
    return t;
}

session_t session_from_json(const json& j)
{
    session_t s;
    if (!j.is_object())
        return s;
    s.id = j.value("id", std::string());
    s.title = j.value("title", std::string());
    s.client = j.value("client", std::string());
    s.scope_summary = j.value("scope_summary", std::string());
    s.status = normalized_status(j.value("status", std::string("open")));
    s.owner = j.value("owner", std::string());
    s.notes = j.value("notes", std::string());
    s.created_ms = j.value("created_ms", 0ull);
    s.updated_ms = j.value("updated_ms", 0ull);
    s.closed_ms = j.value("closed_ms", 0ull);
    if (j.contains("metadata") && j["metadata"].is_object())
        s.metadata = redact_json_for_output(j["metadata"]);
    if (j.contains("targets") && j["targets"].is_array()) {
        for (const auto& jt : j["targets"])
            s.targets.push_back(target_from_json(jt));
    }
    return s;
}

evidence_record_t evidence_from_json(const json& j)
{
    evidence_record_t e;
    if (!j.is_object())
        return e;
    e.id = j.value("id", 0ull);
    e.session_id = j.value("session_id", std::string());
    e.issue_id = j.value("issue_id", 0ull);
    e.exchange_id = j.value("exchange_id", 0ull);
    e.source = j.value("source", std::string());
    e.category = j.value("category", std::string());
    e.label = j.value("label", std::string());
    e.captured_ms = j.value("captured_ms", 0ull);
    e.method = j.value("method", std::string());
    e.url = j.value("url", std::string());
    e.host = j.value("host", std::string());
    if (j.contains("port") && j["port"].is_number_unsigned()) {
        const uint64_t port = j["port"].get<uint64_t>();
        if (port <= 65535)
            e.port = static_cast<uint16_t>(port);
    }
    e.path = j.value("path", std::string());
    e.status_code = j.value("status_code", 0);
    e.request_length = j.value("request_length", 0ull);
    e.response_length = j.value("response_length", 0ull);
    e.request_sha256 = j.value("request_sha256", std::string());
    e.response_sha256 = j.value("response_sha256", std::string());
    e.request_preview = j.value("request_preview", std::string());
    e.response_preview = j.value("response_preview", std::string());
    e.marker_preview = j.value("marker_preview", std::string());
    e.marker_sha256 = j.value("marker_sha256", std::string());
    e.marker_length = j.value("marker_length", 0ull);
    if (j.contains("extra") && j["extra"].is_object())
        e.extra = redact_json_for_output(j["extra"]);
    return e;
}

suppression_t suppression_from_json(const json& j)
{
    suppression_t s;
    if (!j.is_object())
        return s;
    s.id = j.value("id", 0ull);
    s.session_id = j.value("session_id", std::string());
    s.issue_id = j.value("issue_id", 0ull);
    s.scope = j.value("scope", std::string("finding"));
    s.reason = j.value("reason", std::string());
    s.actor = j.value("actor", std::string());
    s.issue_type = j.value("issue_type", std::string());
    s.host = j.value("host", std::string());
    s.path = j.value("path", std::string());
    s.created_ms = j.value("created_ms", 0ull);
    s.expires_ms = j.value("expires_ms", 0ull);
    s.active = j.value("active", true);
    return s;
}

audit_entry_t audit_from_json(const json& j)
{
    audit_entry_t e;
    if (!j.is_object())
        return e;
    e.id = j.value("id", 0ull);
    e.session_id = j.value("session_id", std::string());
    e.ts_ms = j.value("ts_ms", 0ull);
    e.actor = j.value("actor", std::string());
    e.tool = j.value("tool", std::string());
    e.action = j.value("action", std::string());
    e.read_only = j.value("read_only", true);
    e.ok = j.value("ok", true);
    e.elapsed_ms = j.value("elapsed_ms", 0ull);
    e.target = j.value("target", std::string());
    e.summary = j.value("summary", std::string());
    if (j.contains("params_summary"))
        e.params_summary = redact_json_for_output(j["params_summary"]);
    if (j.contains("result_summary"))
        e.result_summary = redact_json_for_output(j["result_summary"]);
    return e;
}

void update_next_ids_locked(state_t& st)
{
    uint64_t max_session = 0;
    uint64_t max_target = 0;
    uint64_t max_evidence = 0;
    uint64_t max_suppression = 0;
    uint64_t max_audit = 0;
    for (const auto& s : st.sessions) {
        const size_t pos = s.id.rfind('_');
        if (pos != std::string::npos) {
            try {
                max_session = (std::max)(max_session, static_cast<uint64_t>(std::stoull(s.id.substr(pos + 1))));
            } catch (...) {
            }
        }
        for (const auto& t : s.targets) {
            const size_t tpos = t.id.rfind('_');
            if (tpos != std::string::npos) {
                try {
                    max_target = (std::max)(max_target, static_cast<uint64_t>(std::stoull(t.id.substr(tpos + 1))));
                } catch (...) {
                }
            }
        }
    }
    for (const auto& e : st.evidence)
        max_evidence = (std::max)(max_evidence, e.id);
    for (const auto& s : st.suppressions)
        max_suppression = (std::max)(max_suppression, s.id);
    for (const auto& a : st.audit)
        max_audit = (std::max)(max_audit, a.id);
    st.next_session.store((std::max)(uint64_t{1}, max_session + 1));
    st.next_target.store((std::max)(uint64_t{1}, max_target + 1));
    st.next_evidence.store((std::max)(uint64_t{1}, max_evidence + 1));
    st.next_suppression.store((std::max)(uint64_t{1}, max_suppression + 1));
    st.next_audit.store((std::max)(uint64_t{1}, max_audit + 1));
}

bool session_visible(const session_t& session, const session_filter_t& filter)
{
    if (!filter.status.empty() && lower_copy(session.status) != lower_copy(filter.status))
        return false;
    if (!filter.include_closed && lower_copy(session.status) == "closed")
        return false;
    return true;
}

bool suppression_active_now(const suppression_t& s)
{
    return s.active && (s.expires_ms == 0 || s.expires_ms > now_ms());
}

void trim_audit_locked(state_t& st)
{
    constexpr size_t max_audit = 8192;
    if (st.audit.size() > max_audit)
        st.audit.erase(st.audit.begin(), st.audit.begin() + static_cast<std::ptrdiff_t>(st.audit.size() - max_audit));
}

void ensure_initialized()
{
    initialize();
}

}

std::string redact_for_output(const std::string& value)
{
    return aida::network::js_analysis_tools::redact_sensitive_values(value);
}

std::string redact_url_for_output(const std::string& value)
{
    return aida::network::js_analysis_tools::redact_url_for_output(redact_for_output(value));
}

std::string hash_for_output(const std::string& value)
{
    return aida::network::js_analysis_tools::sha256_hex(value);
}

json redact_json_for_output(const json& value)
{
    if (value.is_object()) {
        json out = json::object();
        for (auto it = value.begin(); it != value.end(); ++it) {
            if (it.value().is_string() && sensitive_key(it.key())) {
                out[it.key()] = string_summary(it.value().get<std::string>(), true);
            } else {
                out[it.key()] = redact_json_for_output(it.value());
            }
        }
        return out;
    }
    if (value.is_array()) {
        json out = json::array();
        for (const auto& item : value)
            out.push_back(redact_json_for_output(item));
        return out;
    }
    if (value.is_string()) {
        const std::string original = value.get<std::string>();
        const std::string redacted = redact_for_output(original);
        if (redacted != original)
            return string_summary(original, false);
        return truncate_text(redacted, 2048);
    }
    return value;
}

bool initialize()
{
    auto& s = state();
    bool expected = false;
    if (!s.initialized.compare_exchange_strong(expected, true))
        return true;
    const bool ok = load_from_disk();
    diag::log_tagged_fmt("audit_session", "initialize ok=%d sessions=%zu evidence=%zu audit=%zu", ok ? 1 : 0, s.sessions.size(), s.evidence.size(), s.audit.size());
    return ok;
}

void shutdown()
{
    auto& s = state();
    if (!s.initialized.exchange(false))
        return;
    save_to_disk();
}

std::string storage_path()
{
    const std::string dir = appdata_dir() + "\\AiDA\\Standalone\\burp";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir + "\\audit_sessions.json";
}

bool save_to_disk()
{
    auto& st = state();
    std::vector<session_t> sessions;
    std::vector<evidence_record_t> evidence;
    std::vector<suppression_t> suppressions;
    std::vector<audit_entry_t> audit;
    uint64_t next_session = 1;
    uint64_t next_target = 1;
    uint64_t next_evidence = 1;
    uint64_t next_suppression = 1;
    uint64_t next_audit = 1;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        sessions = st.sessions;
        evidence = st.evidence;
        suppressions = st.suppressions;
        audit = st.audit;
        next_session = st.next_session.load();
        next_target = st.next_target.load();
        next_evidence = st.next_evidence.load();
        next_suppression = st.next_suppression.load();
        next_audit = st.next_audit.load();
    }

    json doc;
    doc["version"] = 1;
    doc["next_session"] = next_session;
    doc["next_target"] = next_target;
    doc["next_evidence"] = next_evidence;
    doc["next_suppression"] = next_suppression;
    doc["next_audit"] = next_audit;
    doc["sessions"] = json::array();
    for (const auto& session : sessions)
        doc["sessions"].push_back(session_to_json(session, true));
    doc["evidence"] = json::array();
    for (const auto& record : evidence)
        doc["evidence"].push_back(evidence_to_json(record));
    doc["suppressions"] = json::array();
    for (const auto& suppression : suppressions)
        doc["suppressions"].push_back(suppression_to_json(suppression));
    doc["audit"] = json::array();
    for (const auto& entry : audit)
        doc["audit"].push_back(audit_entry_to_json(entry));

    const std::string path = storage_path();
    const std::string tmp = path + ".tmp";
    ensure_parent(tmp);
    try {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) {
            set_error("audit_session.save: open failed");
            return false;
        }
        const std::string body = doc.dump(2);
        f.write(body.data(), static_cast<std::streamsize>(body.size()));
        f.close();
        std::error_code ec;
        std::filesystem::rename(tmp, path, ec);
        if (ec) {
            std::filesystem::remove(path, ec);
            std::filesystem::rename(tmp, path, ec);
            if (ec) {
                set_error("audit_session.save: rename failed");
                return false;
            }
        }
        return true;
    } catch (...) {
        set_error("audit_session.save: exception");
        return false;
    }
}

bool load_from_disk()
{
    auto& st = state();
    const std::string path = storage_path();
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
        return save_to_disk();
    std::string raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (raw.empty()) {
        set_error("audit_session.load: empty store");
        return save_to_disk();
    }
    try {
        const json doc = json::parse(raw);
        if (!doc.is_object()) {
            set_error("audit_session.load: invalid root");
            return false;
        }
        std::vector<session_t> sessions;
        std::vector<evidence_record_t> evidence;
        std::vector<suppression_t> suppressions;
        std::vector<audit_entry_t> audit;
        if (doc.contains("sessions") && doc["sessions"].is_array()) {
            for (const auto& item : doc["sessions"]) {
                session_t session = session_from_json(item);
                if (!session.id.empty())
                    sessions.push_back(std::move(session));
            }
        }
        if (doc.contains("evidence") && doc["evidence"].is_array()) {
            for (const auto& item : doc["evidence"]) {
                evidence_record_t record = evidence_from_json(item);
                if (record.id != 0)
                    evidence.push_back(std::move(record));
            }
        }
        if (doc.contains("suppressions") && doc["suppressions"].is_array()) {
            for (const auto& item : doc["suppressions"]) {
                suppression_t suppression = suppression_from_json(item);
                if (suppression.id != 0)
                    suppressions.push_back(std::move(suppression));
            }
        }
        if (doc.contains("audit") && doc["audit"].is_array()) {
            for (const auto& item : doc["audit"]) {
                audit_entry_t entry = audit_from_json(item);
                if (entry.id != 0)
                    audit.push_back(std::move(entry));
            }
        }
        {
            std::lock_guard<std::mutex> lk(st.mtx);
            st.sessions = std::move(sessions);
            st.evidence = std::move(evidence);
            st.suppressions = std::move(suppressions);
            st.audit = std::move(audit);
            if (doc.contains("next_session") && doc["next_session"].is_number_unsigned())
                st.next_session.store((std::max)(uint64_t{1}, doc["next_session"].get<uint64_t>()));
            if (doc.contains("next_target") && doc["next_target"].is_number_unsigned())
                st.next_target.store((std::max)(uint64_t{1}, doc["next_target"].get<uint64_t>()));
            if (doc.contains("next_evidence") && doc["next_evidence"].is_number_unsigned())
                st.next_evidence.store((std::max)(uint64_t{1}, doc["next_evidence"].get<uint64_t>()));
            if (doc.contains("next_suppression") && doc["next_suppression"].is_number_unsigned())
                st.next_suppression.store((std::max)(uint64_t{1}, doc["next_suppression"].get<uint64_t>()));
            if (doc.contains("next_audit") && doc["next_audit"].is_number_unsigned())
                st.next_audit.store((std::max)(uint64_t{1}, doc["next_audit"].get<uint64_t>()));
            update_next_ids_locked(st);
        }
        return true;
    } catch (...) {
        set_error("audit_session.load: parse exception");
        return false;
    }
}

std::string last_error()
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    return s.last_err;
}

std::string create_session(const std::string& title,
                           const std::string& client,
                           const std::string& scope_summary,
                           const std::string& owner,
                           const json& metadata)
{
    ensure_initialized();
    auto& st = state();
    session_t session;
    const uint64_t id = st.next_session.fetch_add(1);
    session.id = make_session_id(id);
    session.title = redact_for_output(title.empty() ? std::string("Web Audit Session") : title);
    session.client = redact_for_output(client);
    session.scope_summary = redact_for_output(scope_summary);
    session.status = "open";
    session.owner = redact_for_output(owner);
    session.created_ms = now_ms();
    session.updated_ms = session.created_ms;
    session.metadata = metadata.is_object() ? redact_json_for_output(metadata) : json::object();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.sessions.push_back(session);
    }
    save_to_disk();
    return session.id;
}

bool get_session(const std::string& id, session_t& out)
{
    ensure_initialized();
    auto& st = state();
    std::lock_guard<std::mutex> lk(st.mtx);
    for (const auto& session : st.sessions) {
        if (session.id == id) {
            out = session;
            return true;
        }
    }
    return false;
}

std::vector<session_t> list_sessions(const session_filter_t& filter)
{
    ensure_initialized();
    auto& st = state();
    std::vector<session_t> out;
    std::lock_guard<std::mutex> lk(st.mtx);
    for (const auto& session : st.sessions) {
        if (!session_visible(session, filter))
            continue;
        out.push_back(session);
        if (filter.limit > 0 && out.size() >= filter.limit)
            break;
    }
    std::sort(out.begin(), out.end(), [](const session_t& a, const session_t& b) { return a.updated_ms > b.updated_ms; });
    return out;
}

bool update_session(const std::string& id, const session_update_t& update, session_t& out)
{
    ensure_initialized();
    bool changed = false;
    auto& st = state();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (auto& session : st.sessions) {
            if (session.id != id)
                continue;
            if (update.has_title) {
                session.title = redact_for_output(update.title);
                changed = true;
            }
            if (update.has_client) {
                session.client = redact_for_output(update.client);
                changed = true;
            }
            if (update.has_scope_summary) {
                session.scope_summary = redact_for_output(update.scope_summary);
                changed = true;
            }
            if (update.has_status && valid_status(update.status)) {
                session.status = normalized_status(update.status);
                if (session.status == "closed" && session.closed_ms == 0)
                    session.closed_ms = now_ms();
                changed = true;
            }
            if (update.has_owner) {
                session.owner = redact_for_output(update.owner);
                changed = true;
            }
            if (update.has_notes) {
                session.notes = redact_for_output(update.notes);
                changed = true;
            }
            if (update.has_metadata) {
                session.metadata = update.metadata.is_object() ? redact_json_for_output(update.metadata) : json::object();
                changed = true;
            }
            if (changed)
                session.updated_ms = now_ms();
            out = session;
            break;
        }
    }
    if (changed)
        save_to_disk();
    return changed;
}

bool close_session(const std::string& id, const std::string& reason, session_t& out)
{
    session_update_t update;
    update.has_status = true;
    update.status = "closed";
    if (!reason.empty()) {
        update.has_notes = true;
        update.notes = reason;
    }
    return update_session(id, update, out);
}

bool delete_session(const std::string& id)
{
    ensure_initialized();
    bool removed = false;
    auto& st = state();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        const auto before = st.sessions.size();
        st.sessions.erase(std::remove_if(st.sessions.begin(), st.sessions.end(), [&](const session_t& session) { return session.id == id; }), st.sessions.end());
        removed = st.sessions.size() != before;
        if (removed) {
            st.evidence.erase(std::remove_if(st.evidence.begin(), st.evidence.end(), [&](const evidence_record_t& record) { return record.session_id == id; }), st.evidence.end());
            st.suppressions.erase(std::remove_if(st.suppressions.begin(), st.suppressions.end(), [&](const suppression_t& s) { return s.session_id == id; }), st.suppressions.end());
            st.audit.erase(std::remove_if(st.audit.begin(), st.audit.end(), [&](const audit_entry_t& e) { return e.session_id == id; }), st.audit.end());
        }
    }
    if (removed)
        save_to_disk();
    return removed;
}

bool add_target(const std::string& session_id, target_t target, target_t& out)
{
    ensure_initialized();
    auto& st = state();
    bool ok = false;
    target.id = target.id.empty() ? make_target_id(st.next_target.fetch_add(1)) : target.id;
    target.label = redact_for_output(target.label);
    target.url = redact_url_for_output(target.url);
    target.path = redact_url_for_output(target.path);
    target.added_ms = target.added_ms == 0 ? now_ms() : target.added_ms;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (auto& session : st.sessions) {
            if (session.id != session_id)
                continue;
            session.targets.push_back(target);
            session.updated_ms = now_ms();
            out = target;
            ok = true;
            break;
        }
    }
    if (ok)
        save_to_disk();
    return ok;
}

std::vector<target_t> list_targets(const std::string& session_id)
{
    ensure_initialized();
    auto& st = state();
    std::lock_guard<std::mutex> lk(st.mtx);
    for (const auto& session : st.sessions) {
        if (session.id == session_id)
            return session.targets;
    }
    return {};
}

bool remove_target(const std::string& session_id, const std::string& target_id)
{
    ensure_initialized();
    bool removed = false;
    auto& st = state();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (auto& session : st.sessions) {
            if (session.id != session_id)
                continue;
            const auto before = session.targets.size();
            session.targets.erase(std::remove_if(session.targets.begin(), session.targets.end(), [&](const target_t& t) { return target_matches_remove_id(t, target_id); }), session.targets.end());
            removed = session.targets.size() != before;
            if (removed)
                session.updated_ms = now_ms();
            break;
        }
    }
    if (removed)
        save_to_disk();
    return removed;
}

uint64_t store_evidence(evidence_record_t record)
{
    ensure_initialized();
    auto& st = state();
    record.id = st.next_evidence.fetch_add(1);
    record.captured_ms = record.captured_ms == 0 ? now_ms() : record.captured_ms;
    record.url = redact_url_for_output(record.url);
    record.path = redact_url_for_output(record.path);
    record.request_preview = truncate_text(redact_for_output(record.request_preview), 4096);
    record.response_preview = truncate_text(redact_for_output(record.response_preview), 4096);
    record.marker_preview = truncate_text(redact_for_output(record.marker_preview), 512);
    record.extra = record.extra.is_object() ? redact_json_for_output(record.extra) : json::object();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.evidence.push_back(record);
        for (auto& session : st.sessions) {
            if (session.id == record.session_id) {
                session.updated_ms = now_ms();
                break;
            }
        }
    }
    save_to_disk();
    return record.id;
}

std::vector<evidence_record_t> list_evidence(const evidence_query_t& query)
{
    ensure_initialized();
    auto& st = state();
    std::vector<evidence_record_t> out;
    std::lock_guard<std::mutex> lk(st.mtx);
    for (const auto& record : st.evidence) {
        if (!query.session_id.empty() && record.session_id != query.session_id)
            continue;
        if (query.issue_id != 0 && record.issue_id != query.issue_id)
            continue;
        if (query.exchange_id != 0 && record.exchange_id != query.exchange_id)
            continue;
        out.push_back(record);
        if (query.limit > 0 && out.size() >= query.limit)
            break;
    }
    std::sort(out.begin(), out.end(), [](const evidence_record_t& a, const evidence_record_t& b) { return a.captured_ms > b.captured_ms; });
    return out;
}

size_t evidence_count_for_issue(const std::string& session_id, uint64_t issue_id)
{
    if (issue_id == 0)
        return 0;
    evidence_query_t query;
    query.session_id = session_id;
    query.issue_id = issue_id;
    query.limit = 0;
    return list_evidence(query).size();
}

uint64_t suppress_finding(suppression_t suppression)
{
    ensure_initialized();
    auto& st = state();
    suppression.id = st.next_suppression.fetch_add(1);
    suppression.created_ms = suppression.created_ms == 0 ? now_ms() : suppression.created_ms;
    suppression.scope = suppression.scope.empty() ? std::string("finding") : lower_copy(suppression.scope);
    suppression.reason = redact_for_output(suppression.reason);
    suppression.actor = redact_for_output(suppression.actor);
    suppression.issue_type = redact_for_output(suppression.issue_type);
    suppression.path = redact_url_for_output(suppression.path);
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.suppressions.push_back(suppression);
    }
    save_to_disk();
    return suppression.id;
}

bool is_suppressed(uint64_t issue_id, const std::string& session_id)
{
    if (issue_id == 0)
        return false;
    ensure_initialized();
    auto& st = state();
    std::lock_guard<std::mutex> lk(st.mtx);
    for (const auto& suppression : st.suppressions) {
        if (!suppression_active_now(suppression))
            continue;
        if (suppression.issue_id != issue_id)
            continue;
        if (!session_id.empty() && !suppression.session_id.empty() && suppression.session_id != session_id)
            continue;
        return true;
    }
    return false;
}

std::vector<suppression_t> list_suppressions(const std::string& session_id, bool active_only)
{
    ensure_initialized();
    auto& st = state();
    std::vector<suppression_t> out;
    std::lock_guard<std::mutex> lk(st.mtx);
    for (const auto& suppression : st.suppressions) {
        if (!session_id.empty() && suppression.session_id != session_id)
            continue;
        if (active_only && !suppression_active_now(suppression))
            continue;
        out.push_back(suppression);
    }
    std::sort(out.begin(), out.end(), [](const suppression_t& a, const suppression_t& b) { return a.created_ms > b.created_ms; });
    return out;
}

uint64_t append_audit(audit_entry_t entry)
{
    ensure_initialized();
    auto& st = state();
    entry.id = st.next_audit.fetch_add(1);
    entry.ts_ms = entry.ts_ms == 0 ? now_ms() : entry.ts_ms;
    entry.actor = redact_for_output(entry.actor);
    entry.tool = redact_for_output(entry.tool);
    entry.action = redact_for_output(entry.action);
    entry.target = redact_url_for_output(entry.target);
    entry.summary = truncate_text(redact_for_output(entry.summary), 1024);
    entry.params_summary = redact_json_for_output(entry.params_summary);
    entry.result_summary = redact_json_for_output(entry.result_summary);
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.audit.push_back(entry);
        trim_audit_locked(st);
    }
    save_to_disk();
    return entry.id;
}

std::vector<audit_entry_t> list_audit(const audit_query_t& query)
{
    ensure_initialized();
    auto& st = state();
    std::vector<audit_entry_t> out;
    std::lock_guard<std::mutex> lk(st.mtx);
    for (auto it = st.audit.rbegin(); it != st.audit.rend(); ++it) {
        const auto& entry = *it;
        if (!query.session_id.empty() && entry.session_id != query.session_id)
            continue;
        if (!query.tool.empty() && entry.tool.find(query.tool) == std::string::npos)
            continue;
        if (query.since_ms != 0 && entry.ts_ms < query.since_ms)
            continue;
        if (query.until_ms != 0 && entry.ts_ms > query.until_ms)
            continue;
        out.push_back(entry);
        if (query.limit > 0 && out.size() >= query.limit)
            break;
    }
    return out;
}

json target_to_json(const target_t& target)
{
    json j;
    j["id"] = target.id;
    j["label"] = redact_for_output(target.label);
    j["url"] = redact_url_for_output(target.url);
    j["scheme"] = target.scheme;
    j["host"] = target.host;
    j["port"] = target.port;
    j["path"] = redact_url_for_output(target.path);
    j["added_ms"] = target.added_ms;
    j["active"] = target.active;
    return j;
}

json session_to_json(const session_t& session, bool include_targets)
{
    json j;
    j["id"] = session.id;
    j["title"] = redact_for_output(session.title);
    j["client"] = redact_for_output(session.client);
    j["scope_summary"] = redact_for_output(session.scope_summary);
    j["status"] = session.status;
    j["owner"] = redact_for_output(session.owner);
    j["notes"] = redact_for_output(session.notes);
    j["created_ms"] = session.created_ms;
    j["updated_ms"] = session.updated_ms;
    j["closed_ms"] = session.closed_ms;
    j["target_count"] = session.targets.size();
    j["metadata"] = redact_json_for_output(session.metadata);
    if (include_targets) {
        j["targets"] = json::array();
        for (const auto& target : session.targets)
            j["targets"].push_back(target_to_json(target));
    }
    return j;
}

json evidence_to_json(const evidence_record_t& record)
{
    json j;
    j["id"] = record.id;
    j["session_id"] = record.session_id;
    j["issue_id"] = record.issue_id;
    j["exchange_id"] = record.exchange_id;
    j["source"] = record.source;
    j["category"] = record.category;
    j["label"] = redact_for_output(record.label);
    j["captured_ms"] = record.captured_ms;
    j["method"] = record.method;
    j["url"] = redact_url_for_output(record.url);
    j["host"] = record.host;
    j["port"] = record.port;
    j["path"] = redact_url_for_output(record.path);
    j["status_code"] = record.status_code;
    j["request"] = json{{"length", record.request_length}, {"sha256", record.request_sha256}, {"preview", truncate_text(redact_for_output(record.request_preview), 2048)}, {"redacted", true}};
    j["response"] = json{{"length", record.response_length}, {"sha256", record.response_sha256}, {"preview", truncate_text(redact_for_output(record.response_preview), 2048)}, {"redacted", true}};
    if (record.marker_length != 0 || !record.marker_sha256.empty() || !record.marker_preview.empty())
        j["marker"] = json{{"length", record.marker_length}, {"sha256", record.marker_sha256}, {"preview", truncate_text(redact_for_output(record.marker_preview), 256)}, {"redacted", true}};
    j["extra"] = redact_json_for_output(record.extra);
    return j;
}

json suppression_to_json(const suppression_t& suppression)
{
    json j;
    j["id"] = suppression.id;
    j["session_id"] = suppression.session_id;
    j["issue_id"] = suppression.issue_id;
    j["scope"] = suppression.scope;
    j["reason"] = redact_for_output(suppression.reason);
    j["actor"] = redact_for_output(suppression.actor);
    j["issue_type"] = redact_for_output(suppression.issue_type);
    j["host"] = suppression.host;
    j["path"] = redact_url_for_output(suppression.path);
    j["created_ms"] = suppression.created_ms;
    j["expires_ms"] = suppression.expires_ms;
    j["active"] = suppression_active_now(suppression);
    return j;
}

json audit_entry_to_json(const audit_entry_t& entry)
{
    json j;
    j["id"] = entry.id;
    j["session_id"] = entry.session_id;
    j["ts_ms"] = entry.ts_ms;
    j["actor"] = redact_for_output(entry.actor);
    j["tool"] = redact_for_output(entry.tool);
    j["action"] = redact_for_output(entry.action);
    j["read_only"] = entry.read_only;
    j["ok"] = entry.ok;
    j["elapsed_ms"] = entry.elapsed_ms;
    j["target"] = redact_url_for_output(entry.target);
    j["summary"] = truncate_text(redact_for_output(entry.summary), 1024);
    j["params_summary"] = redact_json_for_output(entry.params_summary);
    j["result_summary"] = redact_json_for_output(entry.result_summary);
    return j;
}

json report_context_json(const std::string& session_id, bool include_audit_trail, size_t audit_limit)
{
    if (session_id.empty())
        return json::object();
    session_t session;
    if (!get_session(session_id, session))
        return json::object();
    json out;
    out["session"] = session_to_json(session, true);
    evidence_query_t eq;
    eq.session_id = session_id;
    eq.limit = 256;
    const auto evidence = list_evidence(eq);
    out["evidence_count"] = evidence.size();
    out["evidence"] = json::array();
    for (const auto& record : evidence)
        out["evidence"].push_back(evidence_to_json(record));
    const auto suppressions = list_suppressions(session_id, true);
    out["suppression_count"] = suppressions.size();
    out["suppressions"] = json::array();
    for (const auto& suppression : suppressions)
        out["suppressions"].push_back(suppression_to_json(suppression));
    if (include_audit_trail) {
        audit_query_t aq;
        aq.session_id = session_id;
        aq.limit = audit_limit == 0 ? 128 : audit_limit;
        const auto audit = list_audit(aq);
        out["audit_trail_count"] = audit.size();
        out["audit_trail"] = json::array();
        for (const auto& entry : audit)
            out["audit_trail"].push_back(audit_entry_to_json(entry));
    }
    return out;
}

}

namespace {

using json = nlohmann::json;
using namespace audit_session_mcp_store;

uint64_t mcp_now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string session_id_from_params(const json& params)
{
    if (params.contains("session_id") && params["session_id"].is_string())
        return params["session_id"].get<std::string>();
    if (params.contains("id") && params["id"].is_string())
        return params["id"].get<std::string>();
    return {};
}

uint16_t port_from_params(const json& params, uint16_t fallback)
{
    if (!params.contains("port"))
        return fallback;
    const auto& value = params["port"];
    uint64_t parsed = 0;
    if (value.is_number_unsigned()) {
        parsed = value.get<uint64_t>();
    } else if (value.is_number_integer()) {
        const int64_t signed_value = value.get<int64_t>();
        if (signed_value <= 0)
            return fallback;
        parsed = static_cast<uint64_t>(signed_value);
    } else if (value.is_string()) {
        try {
            const std::string text = value.get<std::string>();
            size_t used = 0;
            parsed = std::stoull(text, &used);
            if (used != text.size())
                return fallback;
        } catch (...) {
            return fallback;
        }
    } else {
        return fallback;
    }
    if (parsed == 0 || parsed > 65535)
        return fallback;
    return static_cast<uint16_t>(parsed);
}

target_t target_from_params(const json& params)
{
    target_t target;
    target.label = params.value("label", std::string());
    target.url = params.value("target_url", params.value("url", std::string()));
    target.scheme = params.value("scheme", std::string("https"));
    target.host = params.value("host", std::string());
    target.port = port_from_params(params, static_cast<uint16_t>(target.scheme == "http" ? 80 : 443));
    target.path = params.value("path", std::string("/"));
    if (!target.url.empty()) {
        std::string parsed_scheme;
        std::string parsed_host;
        std::string parsed_path;
        uint16_t parsed_port = 0;
        if (audit_http::parse_url(target.url, parsed_scheme, parsed_host, parsed_port, parsed_path)) {
            target.scheme = parsed_scheme;
            target.host = parsed_host;
            target.port = parsed_port;
            target.path = parsed_path.empty() ? std::string("/") : parsed_path;
        }
    } else if (!target.host.empty()) {
        target.url = target.scheme + "://" + target.host;
        if ((target.scheme == "https" && target.port != 443) || (target.scheme == "http" && target.port != 80))
            target.url += ":" + std::to_string(target.port);
        target.url += target.path.empty() ? std::string("/") : target.path;
    }
    return target;
}

json invoke_with_audit(const std::string& tool_name,
                       bool read_only,
                       const json& params,
                       const std::function<mcp_standalone::tool_result_t(const json&)>& fn,
                       mcp_standalone::tool_result_t& result)
{
    const uint64_t start = mcp_now_ms();
    result = fn(params);
    audit_entry_t entry;
    entry.session_id = session_id_from_params(params);
    entry.ts_ms = start;
    entry.tool = tool_name;
    entry.action = tool_name;
    entry.read_only = read_only;
    entry.ok = result.success;
    const uint64_t end = mcp_now_ms();
    entry.elapsed_ms = end >= start ? end - start : 0;
    entry.actor = params.value("actor", std::string("mcp"));
    entry.target = params.value("target_url", params.value("url", std::string()));
    entry.summary = result.success ? std::string("ok") : result.text;
    entry.params_summary = redact_json_for_output(params);
    entry.result_summary = result.data.is_null() ? json{{"text", result.text}} : redact_json_for_output(result.data);
    append_audit(std::move(entry));
    return result.data;
}

mcp_standalone::tool_result_t audited_result(const std::string& tool_name,
                                             bool read_only,
                                             const json& params,
                                             const std::function<mcp_standalone::tool_result_t(const json&)>& fn)
{
    mcp_standalone::tool_result_t result;
    invoke_with_audit(tool_name, read_only, params, fn, result);
    return result;
}

void register_one(mcp_standalone::server_t& srv,
                  const std::string& name,
                  const std::string& description,
                  std::vector<mcp_standalone::tool_param_t> params,
                  bool read_only,
                  std::function<mcp_standalone::tool_result_t(const json&)> handler)
{
    mcp_standalone::tool_def_t t;
    t.name = name;
    t.description = description;
    t.params = std::move(params);
    t.read_only = read_only;
    t.handler = [name, read_only, handler = std::move(handler)](const json& params) -> mcp_standalone::tool_result_t {
        return audited_result(name, read_only, params, handler);
    };
    srv.register_tool(std::move(t));
}

mcp_standalone::tool_result_t tool_create(const json& params)
{
    const std::string id = create_session(
        params.value("title", params.value("name", std::string("Web Audit Session"))),
        params.value("client", std::string()),
        params.value("scope_summary", std::string()),
        params.value("owner", std::string("mcp")),
        params.contains("metadata") ? params["metadata"] : json::object());
    if (params.contains("targets") && params["targets"].is_array()) {
        for (const auto& jt : params["targets"]) {
            if (!jt.is_object())
                continue;
            target_t target = target_from_params(jt);
            if (!target.host.empty()) {
                target_t stored;
                add_target(id, target, stored);
            }
        }
    }
    session_t session;
    get_session(id, session);
    json out;
    out["session"] = session_to_json(session, true);
    out["session_id"] = id;
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_get(const json& params)
{
    session_t session;
    const std::string id = session_id_from_params(params);
    if (id.empty() || !get_session(id, session))
        return mcp_standalone::tool_result_t::error("session not found");
    json out;
    out["session"] = session_to_json(session, params.value("include_targets", true));
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_list(const json& params)
{
    session_filter_t filter;
    filter.status = params.value("status", std::string());
    filter.include_closed = params.value("include_closed", true);
    filter.limit = static_cast<size_t>(params.value("limit", 128));
    const auto sessions = list_sessions(filter);
    json out;
    out["count"] = sessions.size();
    out["sessions"] = json::array();
    for (const auto& session : sessions)
        out["sessions"].push_back(session_to_json(session, params.value("include_targets", false)));
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_update(const json& params)
{
    const std::string id = session_id_from_params(params);
    if (id.empty())
        return mcp_standalone::tool_result_t::error("session_id is required");
    session_update_t update;
    if (params.contains("title") && params["title"].is_string()) {
        update.has_title = true;
        update.title = params["title"].get<std::string>();
    }
    if (params.contains("name") && params["name"].is_string()) {
        update.has_title = true;
        update.title = params["name"].get<std::string>();
    }
    if (params.contains("client") && params["client"].is_string()) {
        update.has_client = true;
        update.client = params["client"].get<std::string>();
    }
    if (params.contains("scope_summary") && params["scope_summary"].is_string()) {
        update.has_scope_summary = true;
        update.scope_summary = params["scope_summary"].get<std::string>();
    }
    if (params.contains("status") && params["status"].is_string()) {
        update.has_status = true;
        update.status = params["status"].get<std::string>();
    }
    if (params.contains("owner") && params["owner"].is_string()) {
        update.has_owner = true;
        update.owner = params["owner"].get<std::string>();
    }
    if (params.contains("notes") && params["notes"].is_string()) {
        update.has_notes = true;
        update.notes = params["notes"].get<std::string>();
    }
    if (params.contains("metadata") && params["metadata"].is_object()) {
        update.has_metadata = true;
        update.metadata = params["metadata"];
    }
    session_t session;
    if (!update_session(id, update, session))
        return mcp_standalone::tool_result_t::error("session update failed");
    json out;
    out["session"] = session_to_json(session, true);
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_close(const json& params)
{
    const std::string id = session_id_from_params(params);
    if (id.empty())
        return mcp_standalone::tool_result_t::error("session_id is required");
    session_t session;
    if (!close_session(id, params.value("reason", std::string()), session))
        return mcp_standalone::tool_result_t::error("session close failed");
    json out;
    out["closed"] = true;
    out["session"] = session_to_json(session, true);
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_delete(const json& params)
{
    const std::string id = session_id_from_params(params);
    if (id.empty())
        return mcp_standalone::tool_result_t::error("session_id is required");
    const bool removed = delete_session(id);
    json out;
    out["deleted"] = removed;
    out["session_id"] = id;
    if (!removed)
        return mcp_standalone::tool_result_t::error("session not found", out);
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_target_add(const json& params)
{
    const std::string id = session_id_from_params(params);
    if (id.empty())
        return mcp_standalone::tool_result_t::error("session_id is required");
    target_t target = target_from_params(params);
    if (target.host.empty())
        return mcp_standalone::tool_result_t::error("target host or target_url is required");
    target_t stored;
    if (!add_target(id, target, stored))
        return mcp_standalone::tool_result_t::error("session not found");
    json out;
    out["target"] = target_to_json(stored);
    out["session_id"] = id;
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_target_list(const json& params)
{
    const std::string id = session_id_from_params(params);
    if (id.empty())
        return mcp_standalone::tool_result_t::error("session_id is required");
    const auto targets = list_targets(id);
    json out;
    out["session_id"] = id;
    out["count"] = targets.size();
    out["targets"] = json::array();
    for (const auto& target : targets)
        out["targets"].push_back(target_to_json(target));
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_target_remove(const json& params)
{
    const std::string id = session_id_from_params(params);
    const std::string target_id = params.value("target_id", params.value("url", params.value("host", std::string())));
    if (id.empty() || target_id.empty())
        return mcp_standalone::tool_result_t::error("session_id and target_id are required");
    const bool removed = remove_target(id, target_id);
    json out;
    out["session_id"] = id;
    out["target_id"] = target_id;
    out["removed"] = removed;
    if (!removed)
        return mcp_standalone::tool_result_t::error("target not found", out);
    return mcp_standalone::tool_result_t::ok(out);
}

}

namespace audit_session_mcp {

void register_audit_session_tools(mcp_standalone::server_t& srv)
{
    using p = mcp_standalone::tool_param_t;
    register_one(srv, "aida.web.session.create", "Create a web audit session with optional targets and metadata.", {
        p{"title", "string", "Session title.", false},
        p{"name", "string", "Session title alias.", false},
        p{"client", "string", "Client name.", false},
        p{"scope_summary", "string", "Scope summary.", false},
        p{"owner", "string", "Operator label.", false},
        p{"metadata", "object", "Additional redacted metadata.", false},
        p{"targets", "array", "Optional targets to add.", false}
    }, false, tool_create);
    register_one(srv, "aida.web.session.get", "Get a web audit session.", {
        p{"session_id", "string", "Session id.", true},
        p{"include_targets", "boolean", "Include targets.", false}
    }, true, tool_get);
    register_one(srv, "aida.web.session.list", "List web audit sessions.", {
        p{"status", "string", "Optional status filter: open|paused|closed.", false},
        p{"include_closed", "boolean", "Include closed sessions.", false},
        p{"include_targets", "boolean", "Include target arrays.", false},
        p{"limit", "number", "Maximum sessions.", false}
    }, true, tool_list);
    register_one(srv, "aida.web.session.update", "Update web audit session metadata.", {
        p{"session_id", "string", "Session id.", true},
        p{"title", "string", "New title.", false},
        p{"client", "string", "New client.", false},
        p{"scope_summary", "string", "New scope summary.", false},
        p{"status", "string", "open|paused|closed.", false},
        p{"owner", "string", "Owner label.", false},
        p{"notes", "string", "Redacted notes.", false},
        p{"metadata", "object", "Replacement metadata.", false}
    }, false, tool_update);
    register_one(srv, "aida.web.session.close", "Close a web audit session.", {
        p{"session_id", "string", "Session id.", true},
        p{"reason", "string", "Closure reason.", false}
    }, false, tool_close);
    register_one(srv, "aida.web.session.delete", "Delete a web audit session and its owned Plan 6 evidence, suppression, and audit records.", {
        p{"session_id", "string", "Session id.", true}
    }, false, tool_delete);
    register_one(srv, "aida.web.session.target.add", "Add a target to a web audit session.", {
        p{"session_id", "string", "Session id.", true},
        p{"target_url", "string", "Target URL.", false},
        p{"url", "string", "Target URL alias.", false},
        p{"scheme", "string", "http|https.", false},
        p{"host", "string", "Target host.", false},
        p{"port", "number", "Target port.", false},
        p{"path", "string", "Target path.", false},
        p{"label", "string", "Target label.", false}
    }, false, tool_target_add);
    register_one(srv, "aida.web.session.target.list", "List targets for a web audit session.", {
        p{"session_id", "string", "Session id.", true}
    }, true, tool_target_list);
    register_one(srv, "aida.web.session.target.remove", "Remove a target from a web audit session.", {
        p{"session_id", "string", "Session id.", true},
        p{"target_id", "string", "Target id, URL, or host.", true}
    }, false, tool_target_remove);
    diag::log_tagged("audit_session_mcp", "registered web audit session tools");
}

}
}
}
