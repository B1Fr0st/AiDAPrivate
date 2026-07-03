#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>

#ifdef small
#undef small
#endif

#include "issue.hpp"

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_set>

namespace aida {
namespace burp {

const char* severity_label(severity_t s)
{
    switch (s) {
        case severity_t::info:     return "Info";
        case severity_t::low:      return "Low";
        case severity_t::medium:   return "Medium";
        case severity_t::high:     return "High";
        case severity_t::critical: return "Critical";
    }
    return "Info";
}

const char* confidence_label(confidence_t c)
{
    switch (c) {
        case confidence_t::tentative: return "Tentative";
        case confidence_t::firm:      return "Firm";
        case confidence_t::certain:   return "Certain";
    }
    return "Tentative";
}

bool parse_severity(const std::string& s, severity_t& out)
{
    diag::log_tagged_fmt("issue", "parse_severity s=%s", s.c_str());
    std::string lc; lc.reserve(s.size());
    for (char c : s) lc.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lc == "info")     { out = severity_t::info;     diag::log_tagged_fmt("issue", "parse_severity result=info"); return true; }
    if (lc == "low")      { out = severity_t::low;      diag::log_tagged_fmt("issue", "parse_severity result=low"); return true; }
    if (lc == "medium")   { out = severity_t::medium;   diag::log_tagged_fmt("issue", "parse_severity result=medium"); return true; }
    if (lc == "high")     { out = severity_t::high;     diag::log_tagged_fmt("issue", "parse_severity result=high"); return true; }
    if (lc == "critical") { out = severity_t::critical; diag::log_tagged_fmt("issue", "parse_severity result=critical"); return true; }
    diag::log_tagged_fmt("issue", "parse_severity unknown s=%s", s.c_str());
    return false;
}

bool parse_confidence(const std::string& s, confidence_t& out)
{
    diag::log_tagged_fmt("issue", "parse_confidence s=%s", s.c_str());
    std::string lc; lc.reserve(s.size());
    for (char c : s) lc.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lc == "tentative") { out = confidence_t::tentative; diag::log_tagged_fmt("issue", "parse_confidence result=tentative"); return true; }
    if (lc == "firm")      { out = confidence_t::firm;      diag::log_tagged_fmt("issue", "parse_confidence result=firm"); return true; }
    if (lc == "certain")   { out = confidence_t::certain;   diag::log_tagged_fmt("issue", "parse_confidence result=certain"); return true; }
    diag::log_tagged_fmt("issue", "parse_confidence unknown s=%s", s.c_str());
    return false;
}

namespace issue_store {

namespace {

struct store_state_t
{
    std::mutex                              mtx;
    std::vector<issue_t>                    items;
    std::unordered_set<std::string>         dedupe_keys;
    std::atomic<uint64_t>                   next_id{1};
    std::atomic<bool>                       initialized{false};
    std::atomic<bool>                       autosave{true};
    std::atomic<uint64_t>                   last_save_ms{0};
    std::atomic<uint64_t>                   unsaved_changes{0};
    std::mutex                              err_mtx;
    std::string                             last_error;
};

store_state_t& state()
{
    static store_state_t s;
    return s;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

constexpr uint64_t kMinimumReasonableSeenMs = 1577836800000ull;

void set_err(const std::string& msg)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    s.last_error = msg;
}

bool blank_string(const std::string& value)
{
    return std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isspace(c) != 0; });
}

bool validate_loaded_issue(issue_t& issue, const char* source, std::string& reason)
{
    if (blank_string(issue.type_key)) {
        reason = "empty_type_key";
        return false;
    }
    if (blank_string(issue.host)) {
        reason = "empty_host";
        return false;
    }
    const uint64_t now = now_ms();
    if (issue.seen_ms == 0 || issue.seen_ms < kMinimumReasonableSeenMs) {
        diag::log_tagged_fmt("issue", "%s normalize_seen_ms id=%llu old=%llu new=%llu type_key=%s host=%s",
            source ? source : "issue",
            static_cast<unsigned long long>(issue.id),
            static_cast<unsigned long long>(issue.seen_ms),
            static_cast<unsigned long long>(now),
            issue.type_key.c_str(),
            issue.host.c_str());
        issue.seen_ms = now;
    }
    reason.clear();
    return true;
}

std::string resolve_appdata_dir()
{
    PWSTR known = nullptr;
    std::string out;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &known)) && known) {
        int needed = WideCharToMultiByte(CP_UTF8, 0, known, -1, nullptr, 0, nullptr, nullptr);
        if (needed > 1) {
            out.resize(static_cast<size_t>(needed - 1));
            WideCharToMultiByte(CP_UTF8, 0, known, -1, out.data(), needed, nullptr, nullptr);
        }
        CoTaskMemFree(known);
    }
    if (out.empty()) {
        char buf[MAX_PATH] = {};
        DWORD len = GetEnvironmentVariableA("APPDATA", buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) out.assign(buf, len);
    }
    if (out.empty()) out = "C:\\Users\\Public";
    return out;
}

std::string normalize_case(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string build_dedupe_key(const issue_t& i)
{
    std::string k;
    k.reserve(i.session_id.size() + i.type_key.size() + i.host.size() + i.parameter.size() + i.path.size() + 64);
    k += normalize_case(i.session_id);
    k += '|';
    k += std::to_string(i.scan_id != 0 ? i.scan_id : i.audit_id);
    k += '|';
    k += normalize_case(i.type_key);
    k += '|';
    k += normalize_case(i.host);
    k += '|';
    k += normalize_case(i.path);
    k += '|';
    k += normalize_case(i.parameter);
    k += '|';
    k += std::to_string(i.audit_id);
    return k;
}

void ensure_dir(const std::string& dir)
{
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
}

bool reset_store_after_load_failure(const std::string& path, const char* reason)
{
    auto& s = state();
    const uint64_t stamp = now_ms();
    std::string quarantine_path;
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
        quarantine_path = path + ".bad." + std::to_string(stamp);
        std::filesystem::rename(path, quarantine_path, ec);
        if (ec) {
            std::error_code copy_ec;
            std::filesystem::copy_file(path, quarantine_path, std::filesystem::copy_options::overwrite_existing, copy_ec);
            if (!copy_ec) {
                std::error_code remove_ec;
                std::filesystem::remove(path, remove_ec);
                ec = remove_ec;
            }
        }
    }
    {
        std::lock_guard<std::mutex> lk(s.mtx);
        s.items.clear();
        s.dedupe_keys.clear();
        s.next_id.store(1);
    }
    set_err(std::string("issue_store.load: ") + (reason ? reason : "invalid store"));
    diag::log_tagged_fmt("issue", "load_from_disk reset_store reason=%s quarantine=%s quarantine_err=%s",
        reason ? reason : "<null>",
        quarantine_path.empty() ? "<none>" : quarantine_path.c_str(),
        ec ? ec.message().c_str() : "<none>");
    bool saved = save_to_disk();
    diag::log_tagged_fmt("issue", "load_from_disk reset_store_saved=%d", saved ? 1 : 0);
    return saved;
}

nlohmann::json evidence_to_json(const evidence_t& e)
{
    nlohmann::json j;
    j["request_raw"]            = e.request_raw;
    j["response_raw"]           = e.response_raw;
    j["marker"]                 = e.marker;
    j["marker_offset_request"]  = e.marker_offset_request;
    j["marker_offset_response"] = e.marker_offset_response;
    return j;
}

bool evidence_from_json(const nlohmann::json& j, evidence_t& out)
{
    if (!j.is_object()) return false;
    if (j.contains("request_raw")  && j["request_raw"].is_string())  out.request_raw  = j["request_raw"].get<std::string>();
    if (j.contains("response_raw") && j["response_raw"].is_string()) out.response_raw = j["response_raw"].get<std::string>();
    if (j.contains("marker") && j["marker"].is_string())             out.marker       = j["marker"].get<std::string>();
    if (j.contains("marker_offset_request") && j["marker_offset_request"].is_number_unsigned())
        out.marker_offset_request = j["marker_offset_request"].get<size_t>();
    if (j.contains("marker_offset_response") && j["marker_offset_response"].is_number_unsigned())
        out.marker_offset_response = j["marker_offset_response"].get<size_t>();
    return true;
}

}

bool initialize()
{
    diag::log_tagged_fmt("issue", "initialize entry");
    auto& s = state();
    bool expected = false;
    if (!s.initialized.compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("issue", "initialize already_initialized");
        return true;
    }
    diag::log_tagged_fmt("issue", "initialize loading_from_disk");
    load_from_disk();
    diag::log_tagged_fmt("issue", "initialize done count=%zu", s.items.size());
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("issue", "shutdown entry");
    auto& s = state();
    if (!s.initialized.load()) {
        diag::log_tagged_fmt("issue", "shutdown not_initialized skip");
        return;
    }
    diag::log_tagged_fmt("issue", "shutdown saving count=%zu", s.items.size());
    save_to_disk();
    diag::log_tagged_fmt("issue", "shutdown done");
}

nlohmann::json issue_to_json(const issue_t& i)
{
    nlohmann::json j;
    j["id"]               = i.id;
    j["session_id"]       = i.session_id;
    j["scan_id"]          = i.scan_id;
    j["type_key"]         = i.type_key;
    j["name"]             = i.name;
    j["description"]      = i.description;
    j["remediation"]      = i.remediation;
    j["cwe"]              = i.cwe;
    j["cvss_score"]       = i.cvss_score;
    j["cvss_vector"]      = i.cvss_vector;
    j["cvss_severity"]    = i.cvss_severity;
    j["owasp_category"]   = i.owasp_category;
    j["severity"]         = severity_label(i.severity);
    j["confidence"]       = confidence_label(i.confidence);
    j["scheme"]           = i.scheme;
    j["host"]             = i.host;
    j["port"]             = i.port;
    j["path"]             = i.path;
    j["parameter"]        = i.parameter;
    j["insertion_point"]  = i.insertion_point;
    j["seen_ms"]          = i.seen_ms;
    j["src_exchange_id"]  = i.src_exchange_id;
    j["audit_id"]         = i.audit_id;
    j["suppressed"]       = i.suppressed;
    j["suppress_reason"]  = i.suppress_reason;
    j["suppressed_by"]    = i.suppressed_by;
    j["suppressed_ms"]    = i.suppressed_ms;
    nlohmann::json ev_arr = nlohmann::json::array();
    for (const auto& e : i.evidence) ev_arr.push_back(evidence_to_json(e));
    j["evidence"] = std::move(ev_arr);
    return j;
}

uint64_t add(issue_t issue)
{
    diag::log_tagged_fmt("issue", "add entry type_key=%s host=%s path=%s parameter=%s severity=%d",
        issue.type_key.c_str(), issue.host.c_str(), issue.path.c_str(), issue.parameter.c_str(), static_cast<int>(issue.severity));
    auto& s = state();
    if (!s.initialized.load()) initialize();

    std::string validation_reason;
    if (!validate_loaded_issue(issue, "add", validation_reason)) {
        set_err("issue_store.add: " + validation_reason);
        diag::log_tagged_fmt("issue",
            "add rejected reason=%s type_key=%s host_present=%d session_present=%d scan_id=%llu audit_id=%llu",
            validation_reason.c_str(),
            issue.type_key.c_str(),
            issue.host.empty() ? 0 : 1,
            issue.session_id.empty() ? 0 : 1,
            static_cast<unsigned long long>(issue.scan_id),
            static_cast<unsigned long long>(issue.audit_id));
        return 0;
    }

    const std::string key = build_dedupe_key(issue);
    diag::log_tagged_fmt("issue", "add dedupe_key=%s", key.c_str());

    {
        std::lock_guard<std::mutex> lk(s.mtx);
        if (s.dedupe_keys.find(key) != s.dedupe_keys.end()) {
            diag::log_tagged_fmt("issue", "add duplicate_found key=%s", key.c_str());
            for (auto& existing : s.items) {
                if (build_dedupe_key(existing) == key) {
                    if (!issue.evidence.empty() && existing.evidence.size() < 8) {
                        diag::log_tagged_fmt("issue", "add merging_evidence existing_id=%llu evidence_count=%zu", static_cast<unsigned long long>(existing.id), issue.evidence.size());
                        for (auto& e : issue.evidence) existing.evidence.push_back(std::move(e));
                    }
                    diag::log_tagged_fmt("issue", "add deduped existing_id=%llu", static_cast<unsigned long long>(existing.id));
                    return existing.id;
                }
            }
        }
        issue.id = s.next_id.fetch_add(1);
        s.dedupe_keys.insert(key);
        s.items.push_back(std::move(issue));
        diag::log_tagged_fmt("issue", "add inserted id=%llu total=%zu", static_cast<unsigned long long>(s.items.back().id), s.items.size());
    }

    const uint64_t dirty = s.unsaved_changes.fetch_add(1, std::memory_order_acq_rel) + 1;
    const uint64_t last_save = s.last_save_ms.load(std::memory_order_acquire);
    const uint64_t now = now_ms();
    if (s.autosave.load() && (dirty >= 32 || last_save == 0 || now - last_save >= 5000)) {
        diag::log_tagged_fmt("issue", "add autosave triggered dirty=%llu elapsed_ms=%llu",
            static_cast<unsigned long long>(dirty),
            static_cast<unsigned long long>(last_save == 0 ? 0 : now - last_save));
        save_to_disk();
    }
    uint64_t new_id = s.next_id.load() - 1;
    diag::log_tagged_fmt("issue", "add ok new_id=%llu", static_cast<unsigned long long>(new_id));
    return new_id;
}

bool remove(uint64_t id)
{
    diag::log_tagged_fmt("issue", "remove entry id=%llu", static_cast<unsigned long long>(id));
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mtx);
    for (auto it = s.items.begin(); it != s.items.end(); ++it) {
        if (it->id == id) {
            diag::log_tagged_fmt("issue", "remove found id=%llu type_key=%s", static_cast<unsigned long long>(id), it->type_key.c_str());
            s.dedupe_keys.erase(build_dedupe_key(*it));
            s.items.erase(it);
            diag::log_tagged_fmt("issue", "remove ok id=%llu remaining=%zu", static_cast<unsigned long long>(id), s.items.size());
            return true;
        }
    }
    diag::log_tagged_fmt("issue", "remove not_found id=%llu", static_cast<unsigned long long>(id));
    return false;
}

void clear()
{
    diag::log_tagged_fmt("issue", "clear entry");
    auto& s = state();
    size_t prev = 0;
    {
        std::lock_guard<std::mutex> lk(s.mtx);
        prev = s.items.size();
        s.items.clear();
        s.dedupe_keys.clear();
    }
    diag::log_tagged_fmt("issue", "clear cleared prev_count=%zu", prev);
    if (s.autosave.load()) {
        s.unsaved_changes.fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_fmt("issue", "clear autosave triggered");
        save_to_disk();
    }
    diag::log_tagged_fmt("issue", "clear done");
}

size_t count()
{
    diag::log_tagged_fmt("issue", "count entry");
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mtx);
    size_t n = s.items.size();
    diag::log_tagged_fmt("issue", "count result=%zu", n);
    return n;
}

bool get(uint64_t id, issue_t& out)
{
    diag::log_tagged_fmt("issue", "get entry id=%llu", static_cast<unsigned long long>(id));
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mtx);
    for (const auto& iss : s.items) {
        if (iss.id == id) {
            out = iss;
            diag::log_tagged_fmt("issue", "get found id=%llu type_key=%s host=%s", static_cast<unsigned long long>(id), iss.type_key.c_str(), iss.host.c_str());
            return true;
        }
    }
    diag::log_tagged_fmt("issue", "get not_found id=%llu", static_cast<unsigned long long>(id));
    return false;
}

size_t count_by_severity(severity_t sev)
{
    diag::log_tagged_fmt("issue", "count_by_severity entry sev=%d", static_cast<int>(sev));
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mtx);
    size_t c = 0;
    for (const auto& it : s.items) if (it.severity == sev) ++c;
    diag::log_tagged_fmt("issue", "count_by_severity sev=%d result=%zu", static_cast<int>(sev), c);
    return c;
}

std::vector<issue_t> list(const issue_filter_t& filter)
{
    diag::log_tagged_fmt("issue", "list entry has_severity_min=%d has_confidence_min=%d has_audit_id=%d host_sub=%s type_key_sub=%s limit=%zu",
        filter.has_severity_min ? 1 : 0, filter.has_confidence_min ? 1 : 0, filter.has_audit_id ? 1 : 0,
        filter.host_substring.c_str(), filter.type_key_substring.c_str(), filter.limit);
    auto& s = state();
    std::vector<issue_t> out;
    std::lock_guard<std::mutex> lk(s.mtx);
    out.reserve(s.items.size());
    for (const auto& it : s.items) {
        if (filter.has_severity_min && static_cast<int>(it.severity) < static_cast<int>(filter.severity_min)) continue;
        if (filter.has_confidence_min && static_cast<int>(it.confidence) < static_cast<int>(filter.confidence_min)) continue;
        if (filter.has_audit_id && it.audit_id != filter.audit_id) continue;
        if (!filter.include_suppressed && it.suppressed) continue;
        if (!filter.host_substring.empty()) {
            std::string lh = normalize_case(it.host);
            std::string sub = normalize_case(filter.host_substring);
            if (lh.find(sub) == std::string::npos) continue;
        }
        if (!filter.type_key_substring.empty()) {
            std::string tk = normalize_case(it.type_key);
            std::string sub = normalize_case(filter.type_key_substring);
            if (tk.find(sub) == std::string::npos) continue;
        }
        out.push_back(it);
        if (filter.limit > 0 && out.size() >= filter.limit) break;
    }
    std::sort(out.begin(), out.end(), [](const issue_t& a, const issue_t& b) {
        if (a.severity != b.severity) return static_cast<int>(a.severity) > static_cast<int>(b.severity);
        return a.seen_ms > b.seen_ms;
    });
    diag::log_tagged_fmt("issue", "list result=%zu total_in_store=%zu", out.size(), s.items.size());
    return out;
}

nlohmann::json export_json(const issue_filter_t& filter)
{
    diag::log_tagged_fmt("issue", "export_json entry");
    auto items = list(filter);
    diag::log_tagged_fmt("issue", "export_json serializing count=%zu", items.size());
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& it : items) arr.push_back(issue_to_json(it));
    nlohmann::json doc;
    doc["count"]  = arr.size();
    doc["issues"] = std::move(arr);
    diag::log_tagged_fmt("issue", "export_json done count=%zu", items.size());
    return doc;
}

bool import_json(const nlohmann::json& doc, bool replace_existing)
{
    diag::log_tagged_fmt("issue", "import_json entry replace=%d", replace_existing ? 1 : 0);
    auto issues_doc = doc;
    if (doc.is_object())
        issues_doc = doc.value("issues", nlohmann::json::array());
    if (!issues_doc.is_array()) {
        set_err("issue_store.import: issues must be an array");
        return false;
    }
    std::vector<issue_t> loaded;
    std::unordered_set<std::string> keys;
    uint64_t max_id = 0;
    for (const auto& j : issues_doc) {
        if (!j.is_object())
            continue;
        issue_t it;
        if (j.contains("id") && j["id"].is_number_unsigned()) it.id = j["id"].get<uint64_t>();
        if (j.contains("session_id") && j["session_id"].is_string()) it.session_id = j["session_id"].get<std::string>();
        if (j.contains("scan_id") && j["scan_id"].is_number_unsigned()) it.scan_id = j["scan_id"].get<uint64_t>();
        if (j.contains("type_key") && j["type_key"].is_string()) it.type_key = j["type_key"].get<std::string>();
        if (j.contains("name") && j["name"].is_string()) it.name = j["name"].get<std::string>();
        if (j.contains("description") && j["description"].is_string()) it.description = j["description"].get<std::string>();
        if (j.contains("remediation") && j["remediation"].is_string()) it.remediation = j["remediation"].get<std::string>();
        if (j.contains("cwe") && j["cwe"].is_array()) {
            for (const auto& c : j["cwe"])
                if (c.is_string())
                    it.cwe.push_back(c.get<std::string>());
        }
        if (j.contains("cvss_score") && j["cvss_score"].is_number()) it.cvss_score = j["cvss_score"].get<double>();
        if (j.contains("cvss_vector") && j["cvss_vector"].is_string()) it.cvss_vector = j["cvss_vector"].get<std::string>();
        if (j.contains("cvss_severity") && j["cvss_severity"].is_string()) it.cvss_severity = j["cvss_severity"].get<std::string>();
        if (j.contains("owasp_category") && j["owasp_category"].is_string()) it.owasp_category = j["owasp_category"].get<std::string>();
        if (j.contains("severity") && j["severity"].is_string()) parse_severity(j["severity"].get<std::string>(), it.severity);
        if (j.contains("confidence") && j["confidence"].is_string()) parse_confidence(j["confidence"].get<std::string>(), it.confidence);
        if (j.contains("scheme") && j["scheme"].is_string()) it.scheme = j["scheme"].get<std::string>();
        if (j.contains("host") && j["host"].is_string()) it.host = j["host"].get<std::string>();
        if (j.contains("port") && j["port"].is_number_unsigned()) {
            const auto port = j["port"].get<uint64_t>();
            if (port <= 65535ull)
                it.port = static_cast<uint16_t>(port);
        }
        if (j.contains("path") && j["path"].is_string()) it.path = j["path"].get<std::string>();
        if (j.contains("parameter") && j["parameter"].is_string()) it.parameter = j["parameter"].get<std::string>();
        if (j.contains("insertion_point") && j["insertion_point"].is_string()) it.insertion_point = j["insertion_point"].get<std::string>();
        if (j.contains("seen_ms") && j["seen_ms"].is_number_unsigned()) it.seen_ms = j["seen_ms"].get<uint64_t>();
        if (j.contains("src_exchange_id") && j["src_exchange_id"].is_number_unsigned()) it.src_exchange_id = j["src_exchange_id"].get<uint64_t>();
        if (j.contains("audit_id") && j["audit_id"].is_number_unsigned()) it.audit_id = j["audit_id"].get<uint64_t>();
        if (j.contains("suppressed") && j["suppressed"].is_boolean()) it.suppressed = j["suppressed"].get<bool>();
        if (j.contains("suppress_reason") && j["suppress_reason"].is_string()) it.suppress_reason = j["suppress_reason"].get<std::string>();
        if (j.contains("suppressed_by") && j["suppressed_by"].is_string()) it.suppressed_by = j["suppressed_by"].get<std::string>();
        if (j.contains("suppressed_ms") && j["suppressed_ms"].is_number_unsigned()) it.suppressed_ms = j["suppressed_ms"].get<uint64_t>();
        if (j.contains("evidence") && j["evidence"].is_array()) {
            for (const auto& je : j["evidence"]) {
                evidence_t ev;
                if (evidence_from_json(je, ev))
                    it.evidence.push_back(std::move(ev));
            }
        }
        std::string validation_reason;
        if (!validate_loaded_issue(it, "import_json", validation_reason)) {
            diag::log_tagged_fmt("issue",
                "import_json issue_skipped id=%llu reason=%s type_key=%s host_present=%d session_present=%d scan_id=%llu audit_id=%llu",
                static_cast<unsigned long long>(it.id),
                validation_reason.c_str(),
                it.type_key.c_str(),
                it.host.empty() ? 0 : 1,
                it.session_id.empty() ? 0 : 1,
                static_cast<unsigned long long>(it.scan_id),
                static_cast<unsigned long long>(it.audit_id));
            continue;
        }
        if (it.id > max_id)
            max_id = it.id;
        const std::string key = build_dedupe_key(it);
        if (keys.insert(key).second)
            loaded.push_back(std::move(it));
    }
    auto& s = state();
    if (!s.initialized.load())
        initialize();
    {
        std::lock_guard<std::mutex> lk(s.mtx);
        if (replace_existing) {
            s.items.clear();
            s.dedupe_keys.clear();
            keys.clear();
        } else {
            keys = s.dedupe_keys;
        }
        for (auto& it : loaded) {
            const std::string key = build_dedupe_key(it);
            if (keys.find(key) != keys.end())
                continue;
            if (it.id == 0)
                it.id = s.next_id.fetch_add(1);
            max_id = std::max(max_id, it.id);
            keys.insert(key);
            s.items.push_back(std::move(it));
        }
        s.dedupe_keys = std::move(keys);
        if (max_id >= s.next_id.load())
            s.next_id.store(max_id + 1);
        s.unsaved_changes.fetch_add(1, std::memory_order_acq_rel);
    }
    if (s.autosave.load())
        save_to_disk();
    return true;
}

std::string storage_path()
{
    diag::log_tagged_fmt("issue", "storage_path entry");
    std::string dir = resolve_appdata_dir() + "\\AiDA\\Standalone\\burp";
    ensure_dir(dir);
    std::string path = dir + "\\issues.json";
    diag::log_tagged_fmt("issue", "storage_path result=%s", path.c_str());
    return path;
}

bool save_to_disk()
{
    diag::log_tagged_fmt("issue", "save_to_disk entry");
    auto& s = state();
    std::vector<issue_t> snapshot;
    const uint64_t dirty_at_start = s.unsaved_changes.load(std::memory_order_acquire);
    {
        std::lock_guard<std::mutex> lk(s.mtx);
        snapshot = s.items;
    }
    diag::log_tagged_fmt("issue", "save_to_disk snapshot_count=%zu next_id=%llu", snapshot.size(), static_cast<unsigned long long>(s.next_id.load()));
    const std::string path = storage_path();
    const std::string tmp_path = path + ".tmp";
    nlohmann::json doc;
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& iss : snapshot) arr.push_back(issue_to_json(iss));
    doc["version"]  = 1;
    doc["next_id"]  = s.next_id.load();
    doc["issues"]   = std::move(arr);
    try {
        std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) {
            diag::log_tagged_fmt("issue", "save_to_disk open_failed path=%s", tmp_path.c_str());
            set_err("issue_store.save: open failed");
            return false;
        }
        const std::string out = doc.dump(2);
        f.write(out.data(), static_cast<std::streamsize>(out.size()));
        f.close();
        diag::log_tagged_fmt("issue", "save_to_disk written bytes=%zu", out.size());
        const std::wstring tmp_w = std::filesystem::path(tmp_path).wstring();
        const std::wstring path_w = std::filesystem::path(path).wstring();
        if (!MoveFileExW(tmp_w.c_str(), path_w.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            const DWORD gle = GetLastError();
            diag::log_tagged_fmt("issue", "save_to_disk replace_failed gle=%lu tmp=%s path=%s",
                static_cast<unsigned long>(gle), tmp_path.c_str(), path.c_str());
            set_err("issue_store.save: replace failed");
            std::error_code ec;
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
        diag::log_tagged_fmt("issue", "save_to_disk ok path=%s", path.c_str());
        s.last_save_ms.store(now_ms(), std::memory_order_release);
        uint64_t cur = s.unsaved_changes.load(std::memory_order_acquire);
        while (cur != 0) {
            const uint64_t next = cur > dirty_at_start ? cur - dirty_at_start : 0;
            if (s.unsaved_changes.compare_exchange_weak(cur, next, std::memory_order_acq_rel, std::memory_order_acquire))
                break;
        }
        return true;
    } catch (...) {
        diag::log_tagged_fmt("issue", "save_to_disk exception");
        set_err("issue_store.save: serialization exception");
        return false;
    }
}

bool load_from_disk()
{
    diag::log_tagged_fmt("issue", "load_from_disk entry");
    auto& s = state();
    const std::string path = storage_path();
    diag::log_tagged_fmt("issue", "load_from_disk path=%s", path.c_str());
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        diag::log_tagged_fmt("issue", "load_from_disk new_store path=%s", path.c_str());
        save_to_disk();
        return true;
    }
    std::string raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();
    if (raw.empty()) {
        diag::log_tagged_fmt("issue", "load_from_disk file_empty");
        return reset_store_after_load_failure(path, "empty file");
    }
    diag::log_tagged_fmt("issue", "load_from_disk raw_bytes=%zu", raw.size());
    try {
        nlohmann::json doc = nlohmann::json::parse(raw);
        if (!doc.is_object() || !doc.contains("issues") || !doc["issues"].is_array()) {
            diag::log_tagged_fmt("issue", "load_from_disk invalid_schema");
            return reset_store_after_load_failure(path, "invalid schema");
        }
        std::vector<issue_t> loaded;
        std::unordered_set<std::string> keys;
        size_t skipped = 0;
        for (const auto& j : doc["issues"]) {
            if (!j.is_object()) {
                ++skipped;
                continue;
            }
            try {
                issue_t it;
                if (j.contains("id") && j["id"].is_number_unsigned()) it.id = j["id"].get<uint64_t>();
                if (j.contains("session_id") && j["session_id"].is_string()) it.session_id = j["session_id"].get<std::string>();
                if (j.contains("scan_id") && j["scan_id"].is_number_unsigned()) it.scan_id = j["scan_id"].get<uint64_t>();
                if (j.contains("type_key") && j["type_key"].is_string()) it.type_key = j["type_key"].get<std::string>();
                if (j.contains("name") && j["name"].is_string()) it.name = j["name"].get<std::string>();
                if (j.contains("description") && j["description"].is_string()) it.description = j["description"].get<std::string>();
                if (j.contains("remediation") && j["remediation"].is_string()) it.remediation = j["remediation"].get<std::string>();
                if (j.contains("cwe") && j["cwe"].is_array()) {
                    for (const auto& c : j["cwe"]) if (c.is_string()) it.cwe.push_back(c.get<std::string>());
                }
                if (j.contains("cvss_score") && j["cvss_score"].is_number()) it.cvss_score = j["cvss_score"].get<double>();
                if (j.contains("cvss_vector") && j["cvss_vector"].is_string()) it.cvss_vector = j["cvss_vector"].get<std::string>();
                if (j.contains("cvss_severity") && j["cvss_severity"].is_string()) it.cvss_severity = j["cvss_severity"].get<std::string>();
                if (j.contains("owasp_category") && j["owasp_category"].is_string()) it.owasp_category = j["owasp_category"].get<std::string>();
                if (j.contains("severity")   && j["severity"].is_string())   parse_severity(j["severity"].get<std::string>(), it.severity);
                if (j.contains("confidence") && j["confidence"].is_string()) parse_confidence(j["confidence"].get<std::string>(), it.confidence);
                if (j.contains("scheme") && j["scheme"].is_string()) it.scheme = j["scheme"].get<std::string>();
                if (j.contains("host")   && j["host"].is_string())   it.host   = j["host"].get<std::string>();
                if (j.contains("port")   && j["port"].is_number_unsigned()) {
                    const auto port = j["port"].get<uint64_t>();
                    if (port <= 65535ull) it.port = static_cast<uint16_t>(port);
                }
                if (j.contains("path")   && j["path"].is_string()) it.path = j["path"].get<std::string>();
                if (j.contains("parameter")       && j["parameter"].is_string())       it.parameter       = j["parameter"].get<std::string>();
                if (j.contains("insertion_point") && j["insertion_point"].is_string()) it.insertion_point = j["insertion_point"].get<std::string>();
                if (j.contains("seen_ms")         && j["seen_ms"].is_number_unsigned()) it.seen_ms        = j["seen_ms"].get<uint64_t>();
                if (j.contains("src_exchange_id") && j["src_exchange_id"].is_number_unsigned()) it.src_exchange_id = j["src_exchange_id"].get<uint64_t>();
                if (j.contains("audit_id")        && j["audit_id"].is_number_unsigned()) it.audit_id = j["audit_id"].get<uint64_t>();
                if (j.contains("suppressed")      && j["suppressed"].is_boolean()) it.suppressed = j["suppressed"].get<bool>();
                if (j.contains("suppress_reason") && j["suppress_reason"].is_string()) it.suppress_reason = j["suppress_reason"].get<std::string>();
                if (j.contains("suppressed_by")   && j["suppressed_by"].is_string()) it.suppressed_by = j["suppressed_by"].get<std::string>();
                if (j.contains("suppressed_ms")   && j["suppressed_ms"].is_number_unsigned()) it.suppressed_ms = j["suppressed_ms"].get<uint64_t>();
                if (j.contains("evidence") && j["evidence"].is_array()) {
                    for (const auto& je : j["evidence"]) {
                        evidence_t ev;
                        try {
                            if (evidence_from_json(je, ev)) it.evidence.push_back(std::move(ev));
                        } catch (...) {
                            diag::log_tagged_fmt("issue", "load_from_disk evidence_skipped");
                        }
                    }
                }
                std::string validation_reason;
                if (!validate_loaded_issue(it, "load_from_disk", validation_reason)) {
                    ++skipped;
                    diag::log_tagged_fmt("issue",
                        "load_from_disk issue_skipped id=%llu reason=%s type_key=%s host_present=%d session_present=%d scan_id=%llu audit_id=%llu",
                        static_cast<unsigned long long>(it.id),
                        validation_reason.c_str(),
                        it.type_key.c_str(),
                        it.host.empty() ? 0 : 1,
                        it.session_id.empty() ? 0 : 1,
                        static_cast<unsigned long long>(it.scan_id),
                        static_cast<unsigned long long>(it.audit_id));
                    continue;
                }
                keys.insert(build_dedupe_key(it));
                loaded.push_back(std::move(it));
            } catch (const std::exception& ex) {
                ++skipped;
                diag::log_tagged_fmt("issue", "load_from_disk issue_skipped exception=%s", ex.what());
            } catch (...) {
                ++skipped;
                diag::log_tagged_fmt("issue", "load_from_disk issue_skipped exception=unknown");
            }
        }
        uint64_t next = 1;
        if (doc.contains("next_id") && doc["next_id"].is_number_unsigned()) next = doc["next_id"].get<uint64_t>();
        for (const auto& it : loaded) if (it.id >= next) next = it.id + 1;
        diag::log_tagged_fmt("issue", "load_from_disk parsed_count=%zu skipped=%zu next_id=%llu", loaded.size(), skipped, static_cast<unsigned long long>(next));
        {
            std::lock_guard<std::mutex> lk(s.mtx);
            s.items = std::move(loaded);
            s.dedupe_keys = std::move(keys);
            s.next_id.store(next);
        }
        if (skipped > 0) {
            s.unsaved_changes.fetch_add(1, std::memory_order_acq_rel);
            save_to_disk();
        }
        diag::log_tagged_fmt("burp", "issue_store loaded count=%zu next_id=%llu",
            s.items.size(), static_cast<unsigned long long>(next));
        diag::log_tagged_fmt("issue", "load_from_disk ok count=%zu next_id=%llu", s.items.size(), static_cast<unsigned long long>(next));
        return true;
    } catch (const std::exception& ex) {
        diag::log_tagged_fmt("issue", "load_from_disk parse_or_schema_exception=%s", ex.what());
        return reset_store_after_load_failure(path, "parse or schema exception");
    } catch (...) {
        diag::log_tagged_fmt("issue", "load_from_disk parse_or_schema_exception=unknown");
        return reset_store_after_load_failure(path, "parse or schema exception");
    }
}

std::string last_error()
{
    diag::log_tagged_fmt("issue", "last_error queried");
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    diag::log_tagged_fmt("issue", "last_error=%s", s.last_error.c_str());
    return s.last_error;
}

}

}
}
