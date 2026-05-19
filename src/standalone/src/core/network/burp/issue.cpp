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
#include <cstring>
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
    std::string lc; lc.reserve(s.size());
    for (char c : s) lc.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lc == "info")     { out = severity_t::info;     return true; }
    if (lc == "low")      { out = severity_t::low;      return true; }
    if (lc == "medium")   { out = severity_t::medium;   return true; }
    if (lc == "high")     { out = severity_t::high;     return true; }
    if (lc == "critical") { out = severity_t::critical; return true; }
    return false;
}

bool parse_confidence(const std::string& s, confidence_t& out)
{
    std::string lc; lc.reserve(s.size());
    for (char c : s) lc.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lc == "tentative") { out = confidence_t::tentative; return true; }
    if (lc == "firm")      { out = confidence_t::firm;      return true; }
    if (lc == "certain")   { out = confidence_t::certain;   return true; }
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

void set_err(const std::string& msg)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    s.last_error = msg;
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
    k.reserve(i.type_key.size() + i.host.size() + i.parameter.size() + i.path.size() + 8);
    k += normalize_case(i.type_key);
    k += '|';
    k += normalize_case(i.host);
    k += '|';
    k += normalize_case(i.path);
    k += '|';
    k += normalize_case(i.parameter);
    return k;
}

void ensure_dir(const std::string& dir)
{
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
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
    auto& s = state();
    bool expected = false;
    if (!s.initialized.compare_exchange_strong(expected, true)) return true;
    load_from_disk();
    return true;
}

void shutdown()
{
    auto& s = state();
    if (!s.initialized.load()) return;
    save_to_disk();
}

nlohmann::json issue_to_json(const issue_t& i)
{
    nlohmann::json j;
    j["id"]               = i.id;
    j["type_key"]         = i.type_key;
    j["name"]             = i.name;
    j["description"]      = i.description;
    j["remediation"]      = i.remediation;
    j["cwe"]              = i.cwe;
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
    nlohmann::json ev_arr = nlohmann::json::array();
    for (const auto& e : i.evidence) ev_arr.push_back(evidence_to_json(e));
    j["evidence"] = std::move(ev_arr);
    return j;
}

uint64_t add(issue_t issue)
{
    auto& s = state();
    if (!s.initialized.load()) initialize();

    if (issue.seen_ms == 0) issue.seen_ms = now_ms();

    const std::string key = build_dedupe_key(issue);

    {
        std::lock_guard<std::mutex> lk(s.mtx);
        if (s.dedupe_keys.find(key) != s.dedupe_keys.end()) {
            for (auto& existing : s.items) {
                if (build_dedupe_key(existing) == key) {
                    if (!issue.evidence.empty() && existing.evidence.size() < 8) {
                        for (auto& e : issue.evidence) existing.evidence.push_back(std::move(e));
                    }
                    return existing.id;
                }
            }
        }
        issue.id = s.next_id.fetch_add(1);
        s.dedupe_keys.insert(key);
        s.items.push_back(std::move(issue));
    }

    if (s.autosave.load()) save_to_disk();
    return s.next_id.load() - 1;
}

bool remove(uint64_t id)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mtx);
    for (auto it = s.items.begin(); it != s.items.end(); ++it) {
        if (it->id == id) {
            s.dedupe_keys.erase(build_dedupe_key(*it));
            s.items.erase(it);
            return true;
        }
    }
    return false;
}

void clear()
{
    auto& s = state();
    {
        std::lock_guard<std::mutex> lk(s.mtx);
        s.items.clear();
        s.dedupe_keys.clear();
    }
    if (s.autosave.load()) save_to_disk();
}

size_t count()
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mtx);
    return s.items.size();
}

bool get(uint64_t id, issue_t& out)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mtx);
    for (const auto& iss : s.items) {
        if (iss.id == id) { out = iss; return true; }
    }
    return false;
}

size_t count_by_severity(severity_t sev)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mtx);
    size_t c = 0;
    for (const auto& it : s.items) if (it.severity == sev) ++c;
    return c;
}

std::vector<issue_t> list(const issue_filter_t& filter)
{
    auto& s = state();
    std::vector<issue_t> out;
    std::lock_guard<std::mutex> lk(s.mtx);
    out.reserve(s.items.size());
    for (const auto& it : s.items) {
        if (filter.has_severity_min && static_cast<int>(it.severity) < static_cast<int>(filter.severity_min)) continue;
        if (filter.has_confidence_min && static_cast<int>(it.confidence) < static_cast<int>(filter.confidence_min)) continue;
        if (filter.has_audit_id && it.audit_id != filter.audit_id) continue;
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
    return out;
}

nlohmann::json export_json(const issue_filter_t& filter)
{
    auto items = list(filter);
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& it : items) arr.push_back(issue_to_json(it));
    nlohmann::json doc;
    doc["count"]  = arr.size();
    doc["issues"] = std::move(arr);
    return doc;
}

std::string storage_path()
{
    std::string dir = resolve_appdata_dir() + "\\AiDA\\Standalone\\burp";
    ensure_dir(dir);
    return dir + "\\issues.json";
}

bool save_to_disk()
{
    auto& s = state();
    std::vector<issue_t> snapshot;
    {
        std::lock_guard<std::mutex> lk(s.mtx);
        snapshot = s.items;
    }
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
        if (!f.is_open()) { set_err("issue_store.save: open failed"); return false; }
        const std::string out = doc.dump(2);
        f.write(out.data(), static_cast<std::streamsize>(out.size()));
        f.close();
        std::error_code ec;
        std::filesystem::rename(tmp_path, path, ec);
        if (ec) {
            std::filesystem::remove(path, ec);
            std::filesystem::rename(tmp_path, path, ec);
            if (ec) { set_err("issue_store.save: rename failed"); return false; }
        }
        return true;
    } catch (...) {
        set_err("issue_store.save: serialization exception");
        return false;
    }
}

bool load_from_disk()
{
    auto& s = state();
    const std::string path = storage_path();
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return false;
    std::string raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (raw.empty()) return false;
    nlohmann::json doc;
    try { doc = nlohmann::json::parse(raw); }
    catch (...) { set_err("issue_store.load: parse failed"); return false; }
    if (!doc.is_object() || !doc.contains("issues") || !doc["issues"].is_array()) return false;
    std::vector<issue_t> loaded;
    std::unordered_set<std::string> keys;
    for (const auto& j : doc["issues"]) {
        if (!j.is_object()) continue;
        issue_t it;
        if (j.contains("id") && j["id"].is_number_unsigned()) it.id = j["id"].get<uint64_t>();
        if (j.contains("type_key") && j["type_key"].is_string()) it.type_key = j["type_key"].get<std::string>();
        if (j.contains("name") && j["name"].is_string()) it.name = j["name"].get<std::string>();
        if (j.contains("description") && j["description"].is_string()) it.description = j["description"].get<std::string>();
        if (j.contains("remediation") && j["remediation"].is_string()) it.remediation = j["remediation"].get<std::string>();
        if (j.contains("cwe") && j["cwe"].is_array()) {
            for (const auto& c : j["cwe"]) if (c.is_string()) it.cwe.push_back(c.get<std::string>());
        }
        if (j.contains("severity")   && j["severity"].is_string())   parse_severity(j["severity"].get<std::string>(), it.severity);
        if (j.contains("confidence") && j["confidence"].is_string()) parse_confidence(j["confidence"].get<std::string>(), it.confidence);
        if (j.contains("scheme") && j["scheme"].is_string()) it.scheme = j["scheme"].get<std::string>();
        if (j.contains("host")   && j["host"].is_string())   it.host   = j["host"].get<std::string>();
        if (j.contains("port")   && j["port"].is_number_unsigned()) it.port = static_cast<uint16_t>(j["port"].get<unsigned int>());
        if (j.contains("path")   && j["path"].is_string()) it.path = j["path"].get<std::string>();
        if (j.contains("parameter")       && j["parameter"].is_string())       it.parameter       = j["parameter"].get<std::string>();
        if (j.contains("insertion_point") && j["insertion_point"].is_string()) it.insertion_point = j["insertion_point"].get<std::string>();
        if (j.contains("seen_ms")         && j["seen_ms"].is_number_unsigned()) it.seen_ms        = j["seen_ms"].get<uint64_t>();
        if (j.contains("src_exchange_id") && j["src_exchange_id"].is_number_unsigned()) it.src_exchange_id = j["src_exchange_id"].get<uint64_t>();
        if (j.contains("audit_id")        && j["audit_id"].is_number_unsigned()) it.audit_id = j["audit_id"].get<uint64_t>();
        if (j.contains("evidence") && j["evidence"].is_array()) {
            for (const auto& je : j["evidence"]) {
                evidence_t ev;
                if (evidence_from_json(je, ev)) it.evidence.push_back(std::move(ev));
            }
        }
        keys.insert(build_dedupe_key(it));
        loaded.push_back(std::move(it));
    }
    uint64_t next = 1;
    if (doc.contains("next_id") && doc["next_id"].is_number_unsigned()) next = doc["next_id"].get<uint64_t>();
    for (const auto& it : loaded) if (it.id >= next) next = it.id + 1;
    {
        std::lock_guard<std::mutex> lk(s.mtx);
        s.items = std::move(loaded);
        s.dedupe_keys = std::move(keys);
        s.next_id.store(next);
    }
    diag::log_tagged_fmt("burp", "issue_store loaded count=%zu next_id=%llu",
        s.items.size(), static_cast<unsigned long long>(next));
    return true;
}

std::string last_error()
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    return s.last_error;
}

}

}
}
