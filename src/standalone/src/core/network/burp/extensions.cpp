#include "extensions.hpp"

#define NOMINMAX
#include <windows.h>
#include <shlobj.h>

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <set>
#include <system_error>
#include <utility>

namespace aida {
namespace burp {
namespace extensions {

namespace {

using json = nlohmann::json;

constexpr std::uintmax_t kMaxManifestBytes = 256u * 1024u;
constexpr std::uintmax_t kMaxDescriptorBytes = 256u * 1024u;
constexpr std::uintmax_t kMaxScriptBytes = 4u * 1024u * 1024u;
constexpr std::size_t kMaxExtensions = 256;
constexpr std::size_t kMaxScriptsPerExtension = 64;
constexpr std::size_t kMaxToolsPerExtension = 128;
constexpr std::size_t kMaxDescriptorFilesPerExtension = 64;

struct state_t
{
    std::mutex mtx;
    std::vector<extension_record_t> records;
    std::map<std::string, bool> enabled;
    std::uint64_t generation = 0;
    std::string last_error;
    bool state_loaded = false;
};

state_t& state()
{
    static state_t s;
    return s;
}

std::string wide_to_utf8(const std::wstring& text)
{
    if (text.empty())
        return {};
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return {};
    std::string out(static_cast<std::size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

std::string path_to_utf8(const std::filesystem::path& path)
{
    return wide_to_utf8(path.wstring());
}

std::filesystem::path root_without_create()
{
    PWSTR appdata = nullptr;
    std::filesystem::path base;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata)) && appdata) {
        base = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"burp" / L"extensions";
        CoTaskMemFree(appdata);
    } else {
        base = std::filesystem::current_path() / "aida_burp_extensions";
    }
    return base;
}

std::filesystem::path state_path()
{
    return approved_extension_root() / L"extensions_state.json";
}

std::string lower_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

bool valid_id_char(unsigned char c)
{
    return std::isalnum(c) || c == '_' || c == '-' || c == '.';
}

bool valid_tool_char(unsigned char c)
{
    return std::islower(c) || std::isdigit(c) || c == '_';
}

bool is_valid_extension_id(const std::string& id)
{
    if (id.size() < 3 || id.size() > 96)
        return false;
    if (id.front() == '.' || id.back() == '.')
        return false;
    for (unsigned char c : id)
        if (!valid_id_char(c))
            return false;
    return true;
}

bool is_valid_descriptor_id(const std::string& id)
{
    if (id.size() < 2 || id.size() > 96)
        return false;
    if (id.front() == '.' || id.back() == '.')
        return false;
    for (unsigned char c : id)
        if (!valid_id_char(c))
            return false;
    return true;
}

bool is_valid_tool_name(const std::string& name)
{
    if (name.size() < 10 || name.size() > 96)
        return false;
    if (name.rfind("burp_ext_", 0) != 0)
        return false;
    for (unsigned char c : name)
        if (!valid_tool_char(c))
            return false;
    return true;
}

bool bounded_string(const json& j, const char* key, std::size_t min_len, std::size_t max_len, std::string& out, std::string& error)
{
    if (!j.contains(key) || !j[key].is_string()) {
        error = std::string("missing string field: ") + key;
        return false;
    }
    out = j[key].get<std::string>();
    if (out.size() < min_len || out.size() > max_len) {
        error = std::string("invalid string length for field: ") + key;
        return false;
    }
    return true;
}

std::string optional_string(const json& j, const char* key, std::size_t max_len)
{
    if (!j.contains(key) || !j[key].is_string())
        return {};
    std::string out = j[key].get<std::string>();
    if (out.size() > max_len)
        out.resize(max_len);
    return out;
}

bool has_remote_marker(const std::string& value)
{
    const std::string lowered = lower_ascii(value);
    return lowered.find("://") != std::string::npos || lowered.rfind("file:", 0) == 0;
}

bool is_child_path(const std::filesystem::path& root, const std::filesystem::path& child)
{
    std::string root_str = lower_ascii(root.lexically_normal().string());
    std::string child_str = lower_ascii(child.lexically_normal().string());
    std::replace(root_str.begin(), root_str.end(), '/', '\\');
    std::replace(child_str.begin(), child_str.end(), '/', '\\');
    if (root_str.empty() || child_str.size() < root_str.size())
        return false;
    if (child_str.compare(0, root_str.size(), root_str) != 0)
        return false;
    if (child_str.size() == root_str.size())
        return true;
    return child_str[root_str.size()] == '\\';
}

bool resolve_existing_child_path(const std::filesystem::path& root, const std::filesystem::path& base, const std::string& relative, std::filesystem::path& out, std::string& error)
{
    if (relative.empty() || relative.size() > 260) {
        error = "invalid relative path length";
        return false;
    }
    if (has_remote_marker(relative)) {
        error = "remote paths are not allowed";
        return false;
    }
    std::filesystem::path rel(relative);
    if (rel.is_absolute()) {
        error = "absolute paths are not allowed";
        return false;
    }
    for (const auto& part : rel) {
        const std::wstring token = part.wstring();
        if (token == L"." || token == L"..") {
            error = "path traversal is not allowed";
            return false;
        }
    }
    std::error_code ec;
    const auto root_canon = std::filesystem::weakly_canonical(root, ec);
    if (ec) {
        error = "extension root cannot be resolved";
        return false;
    }
    const auto target = std::filesystem::weakly_canonical(base / rel, ec);
    if (ec || !std::filesystem::exists(target, ec) || !std::filesystem::is_regular_file(target, ec)) {
        error = "referenced local file is unavailable";
        return false;
    }
    if (!is_child_path(root_canon, target)) {
        error = "referenced file is outside approved extension root";
        return false;
    }
    out = target;
    return true;
}

std::string relative_to_root(const std::filesystem::path& root, const std::filesystem::path& child)
{
    std::error_code ec;
    const auto rel = std::filesystem::relative(child, root, ec);
    if (!ec)
        return path_to_utf8(rel);
    return path_to_utf8(child.filename());
}

bool read_text_file_limited(const std::filesystem::path& path, std::uintmax_t max_bytes, std::string& out, std::string& error)
{
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) {
        error = "file is not regular";
        return false;
    }
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size > max_bytes) {
        error = "file size limit exceeded";
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "file open failed";
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

json parse_json_file_limited(const std::filesystem::path& path, std::uintmax_t max_bytes, std::string& error)
{
    std::string text;
    if (!read_text_file_limited(path, max_bytes, text, error))
        return json();
    json parsed = json::parse(text, nullptr, false);
    if (parsed.is_discarded()) {
        error = "invalid json";
        return json();
    }
    return parsed;
}

std::string language_from_path(const std::string& relative)
{
    const std::string lowered = lower_ascii(std::filesystem::path(relative).extension().string());
    if (lowered == ".js" || lowered == ".mjs")
        return "javascript";
    if (lowered == ".py")
        return "python";
    if (lowered == ".lua")
        return "lua";
    if (lowered == ".json")
        return "json";
    return {};
}

bool validate_script(const json& item, const std::filesystem::path& root, const std::filesystem::path& manifest_dir, script_descriptor_t& out, std::string& error)
{
    if (!item.is_object()) {
        error = "script descriptor must be an object";
        return false;
    }
    if (!bounded_string(item, "id", 2, 96, out.id, error))
        return false;
    if (!is_valid_descriptor_id(out.id)) {
        error = "invalid script id";
        return false;
    }
    if (!bounded_string(item, "name", 1, 120, out.name, error))
        return false;
    if (!bounded_string(item, "path", 1, 260, out.relative_path, error))
        return false;
    out.language = optional_string(item, "language", 32);
    if (out.language.empty())
        out.language = language_from_path(out.relative_path);
    if (out.language != "javascript" && out.language != "python" && out.language != "lua" && out.language != "json") {
        error = "unsupported script descriptor language";
        return false;
    }
    std::filesystem::path script_path;
    if (!resolve_existing_child_path(root, manifest_dir, out.relative_path, script_path, error))
        return false;
    std::error_code ec;
    out.size_bytes = std::filesystem::file_size(script_path, ec);
    if (ec || out.size_bytes > kMaxScriptBytes) {
        error = "script descriptor size limit exceeded";
        return false;
    }
    return true;
}

bool validate_tool(const json& item, const std::set<std::string>& script_ids, tool_descriptor_t& out, std::string& error)
{
    if (!item.is_object()) {
        error = "tool descriptor must be an object";
        return false;
    }
    if (!bounded_string(item, "name", 10, 96, out.name, error))
        return false;
    if (!is_valid_tool_name(out.name)) {
        error = "tool names must use the burp_ext_ prefix and lowercase identifier characters";
        return false;
    }
    if (!bounded_string(item, "description", 1, 512, out.description, error))
        return false;
    if (!item.contains("read_only") || !item["read_only"].is_boolean()) {
        error = "tool descriptor requires explicit read_only boolean";
        return false;
    }
    out.read_only = item["read_only"].get<bool>();
    out.script_id = optional_string(item, "script_id", 96);
    if (!out.script_id.empty() && script_ids.find(out.script_id) == script_ids.end()) {
        error = "tool descriptor references an unknown script id";
        return false;
    }
    if (item.contains("input_schema")) {
        if (!item["input_schema"].is_object()) {
            error = "input_schema must be an object";
            return false;
        }
        out.input_schema = item["input_schema"];
    } else {
        out.input_schema = json{{"type", "object"}, {"properties", json::object()}};
    }
    if (!out.input_schema.contains("type") || !out.input_schema["type"].is_string() || out.input_schema["type"].get<std::string>() != "object") {
        error = "input_schema type must be object";
        return false;
    }
    return true;
}

bool append_tool_descriptor_array(const json& arr, const std::set<std::string>& script_ids, std::vector<tool_descriptor_t>& tools, std::set<std::string>& tool_names, std::string& error)
{
    if (!arr.is_array()) {
        error = "tools must be an array";
        return false;
    }
    for (const auto& item : arr) {
        if (tools.size() >= kMaxToolsPerExtension) {
            error = "tool descriptor limit exceeded";
            return false;
        }
        tool_descriptor_t tool;
        if (!validate_tool(item, script_ids, tool, error))
            return false;
        if (!tool_names.insert(tool.name).second) {
            error = "duplicate tool descriptor name";
            return false;
        }
        tools.push_back(std::move(tool));
    }
    return true;
}

bool load_tool_descriptor_file(const std::filesystem::path& root,
                               const std::filesystem::path& manifest_dir,
                               const std::string& relative,
                               const std::set<std::string>& script_ids,
                               std::vector<tool_descriptor_t>& tools,
                               std::set<std::string>& tool_names,
                               std::string& error)
{
    std::filesystem::path descriptor_path;
    if (!resolve_existing_child_path(root, manifest_dir, relative, descriptor_path, error))
        return false;
    const std::string ext = lower_ascii(descriptor_path.extension().string());
    if (ext != ".json") {
        error = "tool descriptor files must be json";
        return false;
    }
    json doc = parse_json_file_limited(descriptor_path, kMaxDescriptorBytes, error);
    if (doc.is_null())
        return false;
    if (doc.is_object() && doc.contains("tools"))
        return append_tool_descriptor_array(doc["tools"], script_ids, tools, tool_names, error);
    if (doc.is_array())
        return append_tool_descriptor_array(doc, script_ids, tools, tool_names, error);
    if (doc.is_object()) {
        tool_descriptor_t tool;
        if (!validate_tool(doc, script_ids, tool, error))
            return false;
        if (!tool_names.insert(tool.name).second) {
            error = "duplicate tool descriptor name";
            return false;
        }
        tools.push_back(std::move(tool));
        return true;
    }
    error = "invalid tool descriptor json";
    return false;
}

bool reject_remote_manifest_fields(const json& manifest, std::string& error)
{
    static const char* const remote_keys[] = {
        "remote", "remote_url", "download_url", "update_url", "install_url", "registry_url", "package_url"
    };
    for (const char* key : remote_keys) {
        if (manifest.contains(key)) {
            error = std::string("remote loading field is not allowed: ") + key;
            return false;
        }
    }
    return true;
}

extension_record_t validate_manifest(const std::filesystem::path& root, const std::filesystem::path& manifest_path, const std::map<std::string, bool>& enabled_state)
{
    extension_record_t rec;
    rec.manifest_path = relative_to_root(root, manifest_path);
    std::string error;
    std::error_code manifest_ec;
    const auto manifest_canon = std::filesystem::weakly_canonical(manifest_path, manifest_ec);
    if (manifest_ec || !is_child_path(root, manifest_canon)) {
        rec.validation_error = "manifest target is outside approved extension root";
        return rec;
    }
    rec.manifest_path = relative_to_root(root, manifest_canon);
    json manifest = parse_json_file_limited(manifest_canon, kMaxManifestBytes, error);
    if (manifest.is_null() || !manifest.is_object()) {
        rec.validation_error = error.empty() ? "manifest must be a json object" : error;
        return rec;
    }
    if (!reject_remote_manifest_fields(manifest, error)) {
        rec.validation_error = error;
        return rec;
    }
    if (!bounded_string(manifest, "id", 3, 96, rec.id, error) || !is_valid_extension_id(rec.id)) {
        rec.validation_error = error.empty() ? "invalid extension id" : error;
        return rec;
    }
    if (!bounded_string(manifest, "name", 1, 120, rec.name, error)) {
        rec.validation_error = error;
        return rec;
    }
    rec.version = optional_string(manifest, "version", 64);
    if (rec.version.empty())
        rec.version = "0.0.0";
    rec.description = optional_string(manifest, "description", 512);
    rec.author = optional_string(manifest, "author", 120);
    const auto manifest_dir = manifest_canon.parent_path();
    std::set<std::string> script_ids;
    if (manifest.contains("scripts")) {
        if (!manifest["scripts"].is_array()) {
            rec.validation_error = "scripts must be an array";
            return rec;
        }
        for (const auto& item : manifest["scripts"]) {
            if (rec.scripts.size() >= kMaxScriptsPerExtension) {
                rec.validation_error = "script descriptor limit exceeded";
                return rec;
            }
            script_descriptor_t script;
            if (!validate_script(item, root, manifest_dir, script, error)) {
                rec.validation_error = error;
                return rec;
            }
            if (!script_ids.insert(script.id).second) {
                rec.validation_error = "duplicate script id";
                return rec;
            }
            rec.scripts.push_back(std::move(script));
        }
    }
    std::set<std::string> tool_names;
    if (manifest.contains("tools")) {
        if (!append_tool_descriptor_array(manifest["tools"], script_ids, rec.tools, tool_names, error)) {
            rec.validation_error = error;
            return rec;
        }
    }
    if (manifest.contains("tool_descriptors")) {
        if (!manifest["tool_descriptors"].is_array()) {
            rec.validation_error = "tool_descriptors must be an array";
            return rec;
        }
        if (manifest["tool_descriptors"].size() > kMaxDescriptorFilesPerExtension) {
            rec.validation_error = "tool descriptor file limit exceeded";
            return rec;
        }
        for (const auto& item : manifest["tool_descriptors"]) {
            if (!item.is_string()) {
                rec.validation_error = "tool descriptor path must be a string";
                return rec;
            }
            if (!load_tool_descriptor_file(root, manifest_dir, item.get<std::string>(), script_ids, rec.tools, tool_names, error)) {
                rec.validation_error = error;
                return rec;
            }
        }
    }
    auto enabled_it = enabled_state.find(rec.id);
    rec.enabled = enabled_it != enabled_state.end() && enabled_it->second;
    rec.valid = true;
    return rec;
}

bool manifest_name_matches(const std::filesystem::path& path)
{
    const std::string name = lower_ascii(path.filename().string());
    return name == "manifest.json" || name == "aida-burp-extension.json" || name == ".aida-burp.json";
}

bool load_enabled_state_locked(std::string* error)
{
    auto& st = state();
    st.enabled.clear();
    st.state_loaded = true;
    const auto path = state_path();
    std::error_code ec;
    if (!std::filesystem::exists(path, ec))
        return true;
    std::string parse_error;
    json doc = parse_json_file_limited(path, kMaxDescriptorBytes, parse_error);
    if (doc.is_null()) {
        if (error)
            *error = parse_error;
        st.last_error = parse_error;
        return false;
    }
    json items = doc.contains("extensions") ? doc["extensions"] : doc;
    if (!items.is_object()) {
        if (error)
            *error = "extension state must be an object";
        st.last_error = "extension state must be an object";
        return false;
    }
    for (auto it = items.begin(); it != items.end(); ++it) {
        if (!is_valid_extension_id(it.key()))
            continue;
        if (it.value().is_boolean())
            st.enabled[it.key()] = it.value().get<bool>();
        else if (it.value().is_object() && it.value().contains("enabled") && it.value()["enabled"].is_boolean())
            st.enabled[it.key()] = it.value()["enabled"].get<bool>();
    }
    return true;
}

bool save_enabled_state_locked(std::string* error)
{
    const auto path = state_path();
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        if (error)
            *error = "failed to create extension state directory";
        return false;
    }
    json doc;
    doc["version"] = 1;
    doc["extensions"] = json::object();
    for (const auto& kv : state().enabled)
        doc["extensions"][kv.first] = json{{"enabled", kv.second}};
    const auto temp = path.string() + ".tmp";
    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error)
                *error = "failed to open extension state file";
            return false;
        }
        out << doc.dump(2);
    }
    std::filesystem::rename(temp, path, ec);
    if (ec) {
        std::filesystem::remove(path, ec);
        ec.clear();
        std::filesystem::rename(temp, path, ec);
    }
    if (ec) {
        if (error)
            *error = "failed to replace extension state file";
        return false;
    }
    return true;
}

json script_to_json(const script_descriptor_t& script)
{
    return json{
        {"id", script.id},
        {"name", script.name},
        {"language", script.language},
        {"path", script.relative_path},
        {"size_bytes", script.size_bytes}
    };
}

json tool_to_json(const tool_descriptor_t& tool, bool include_descriptors)
{
    json out{
        {"name", tool.name},
        {"description", tool.description},
        {"read_only", tool.read_only},
        {"mutating", !tool.read_only}
    };
    if (!tool.script_id.empty())
        out["script_id"] = tool.script_id;
    if (include_descriptors)
        out["input_schema"] = tool.input_schema;
    return out;
}

json extension_to_json(const extension_record_t& ext, bool include_descriptors)
{
    json out{
        {"id", ext.id},
        {"name", ext.name},
        {"version", ext.version},
        {"description", ext.description},
        {"author", ext.author},
        {"manifest_path", ext.manifest_path},
        {"enabled", ext.enabled},
        {"valid", ext.valid}
    };
    if (!ext.validation_error.empty())
        out["validation_error"] = ext.validation_error;
    json scripts = json::array();
    for (const auto& script : ext.scripts)
        scripts.push_back(script_to_json(script));
    out["scripts"] = std::move(scripts);
    json tools = json::array();
    for (const auto& tool : ext.tools)
        tools.push_back(tool_to_json(tool, include_descriptors));
    out["tools"] = std::move(tools);
    return out;
}

}

std::filesystem::path approved_extension_root()
{
    auto root = root_without_create();
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    return root;
}

bool refresh(std::string* error)
{
    auto& st = state();
    const auto root = approved_extension_root();
    std::error_code ec;
    const auto root_canon = std::filesystem::weakly_canonical(root, ec);
    if (ec) {
        const std::string msg = "extension root cannot be canonicalized";
        std::lock_guard<std::mutex> lk(st.mtx);
        st.last_error = msg;
        if (error)
            *error = msg;
        return false;
    }
    std::vector<extension_record_t> loaded;
    std::string state_error;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        if (!load_enabled_state_locked(&state_error)) {
            if (error)
                *error = state_error;
            return false;
        }
    }
    std::map<std::string, bool> enabled_copy;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        enabled_copy = st.enabled;
    }
    if (std::filesystem::exists(root_canon, ec)) {
        std::filesystem::recursive_directory_iterator it(root_canon, std::filesystem::directory_options::skip_permission_denied, ec);
        std::filesystem::recursive_directory_iterator end;
        for (; !ec && it != end; it.increment(ec)) {
            if (loaded.size() >= kMaxExtensions)
                break;
            if (!it->is_regular_file(ec))
                continue;
            if (!manifest_name_matches(it->path()))
                continue;
            extension_record_t rec = validate_manifest(root_canon, it->path(), enabled_copy);
            if (rec.id.empty())
                rec.id = "invalid_" + std::to_string(loaded.size() + 1);
            loaded.push_back(std::move(rec));
        }
    }
    std::sort(loaded.begin(), loaded.end(), [](const extension_record_t& a, const extension_record_t& b) {
        return a.id < b.id;
    });
    for (std::size_t i = 1; i < loaded.size(); ++i) {
        if (!loaded[i].id.empty() && loaded[i].id == loaded[i - 1].id) {
            loaded[i].valid = false;
            loaded[i].enabled = false;
            loaded[i].validation_error = "duplicate extension id";
            loaded[i - 1].valid = false;
            loaded[i - 1].enabled = false;
            loaded[i - 1].validation_error = "duplicate extension id";
        }
    }
    std::size_t valid_count = 0;
    std::size_t enabled_count = 0;
    for (const auto& rec : loaded) {
        if (rec.valid)
            ++valid_count;
        if (rec.enabled)
            ++enabled_count;
    }
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.records = std::move(loaded);
        st.last_error.clear();
        ++st.generation;
    }
    diag::log_tagged_fmt("burp_ext", "refresh root=%s total=%zu valid=%zu enabled=%zu",
        path_to_utf8(root_canon).c_str(), snapshot().extensions.size(), valid_count, enabled_count);
    return true;
}

registry_snapshot_t snapshot()
{
    auto& st = state();
    std::lock_guard<std::mutex> lk(st.mtx);
    registry_snapshot_t snap;
    snap.root = path_to_utf8(root_without_create());
    snap.generation = st.generation;
    snap.last_error = st.last_error;
    snap.extensions = st.records;
    return snap;
}

std::optional<extension_record_t> find_extension(const std::string& id)
{
    auto snap = snapshot();
    for (const auto& ext : snap.extensions)
        if (ext.id == id)
            return ext;
    return std::nullopt;
}

bool set_enabled(const std::string& id, bool enabled, std::string* error)
{
    if (!is_valid_extension_id(id)) {
        if (error)
            *error = "invalid extension id";
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(state().mtx);
        if (!state().state_loaded && !load_enabled_state_locked(error))
            return false;
    }
    auto existing = find_extension(id);
    if (!existing) {
        if (error)
            *error = "extension not found";
        return false;
    }
    if (!existing->valid) {
        if (error)
            *error = existing->validation_error.empty() ? "extension is invalid" : existing->validation_error;
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(state().mtx);
        state().enabled[id] = enabled;
        if (!save_enabled_state_locked(error))
            return false;
        for (auto& rec : state().records) {
            if (rec.id == id) {
                rec.enabled = enabled;
                break;
            }
        }
        ++state().generation;
    }
    diag::log_tagged_fmt("burp_ext", "set_enabled id=%s enabled=%d", id.c_str(), enabled ? 1 : 0);
    return true;
}

json snapshot_json(bool include_disabled, bool include_descriptors)
{
    auto snap = snapshot();
    json out;
    out["root"] = snap.root;
    out["generation"] = snap.generation;
    out["last_error"] = snap.last_error;
    out["disabled_by_default"] = true;
    out["remote_loading_allowed"] = false;
    out["descriptor_inventory_only"] = true;
    out["execution_supported"] = false;
    out["dynamic_mcp_registration_supported"] = false;
    out["enable_semantics"] = "inventory_visibility_only";
    out["extensions"] = json::array();
    for (const auto& ext : snap.extensions) {
        if (!include_disabled && !ext.enabled)
            continue;
        out["extensions"].push_back(extension_to_json(ext, include_descriptors));
    }
    return out;
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(state().mtx);
    return state().last_error;
}

}
}
}
