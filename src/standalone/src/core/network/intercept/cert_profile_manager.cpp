#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include "cert_profile_manager.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <iterator>
#include <sstream>

namespace cert_intercept {
namespace profiles {
namespace {

using json = nlohmann::json;

std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0) return std::wstring();
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), needed);
    return out;
}

std::filesystem::path local_appdata() {
    PWSTR known = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &known)) && known) {
        std::filesystem::path out(known);
        CoTaskMemFree(known);
        return out;
    }
    wchar_t buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) return std::filesystem::path(buf);
    return std::filesystem::path(L"C:\\Users\\Public");
}

std::string env_string(const char* name, const char* fallback) {
    char buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA(name, buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) return std::string(buf, len);
    return fallback ? std::string(fallback) : std::string();
}

bool file_exists(const std::string& path) {
    if (path.empty()) return false;
    std::wstring w = utf8_to_wide(path);
    DWORD attrs = GetFileAttributesW(w.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

bool file_nonempty(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::is_regular_file(path, ec) && !ec && std::filesystem::file_size(path, ec) > 0 && !ec;
}

bool read_text_file(const std::filesystem::path& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

bool text_has(const std::string& text, const std::string& needle) {
    return text.find(needle) != std::string::npos;
}

std::string json_escaped_path(const std::filesystem::path& path);
std::string js_string_literal(std::string value);

bool policies_declare_ca_install(const std::filesystem::path& path) {
    std::string text;
    if (!read_text_file(path, text)) return false;
    try {
        json parsed = json::parse(text);
        auto& certs = parsed["policies"]["Certificates"];
        return certs.value("ImportEnterpriseRoots", false) &&
            certs.contains("Install") &&
            certs["Install"].is_array() &&
            !certs["Install"].empty();
    } catch (...) {
        return false;
    }
}

bool policies_declare_ca_install(const std::filesystem::path& path,
                                 const std::filesystem::path& pem_path,
                                 const std::filesystem::path& der_path) {
    std::string text;
    if (!read_text_file(path, text)) return false;
    try {
        json parsed = json::parse(text);
        auto& certs = parsed["policies"]["Certificates"];
        if (!certs.value("ImportEnterpriseRoots", false)) return false;
        if (!certs.contains("Install") || !certs["Install"].is_array()) return false;
        bool has_pem = false;
        bool has_der = false;
        const std::string pem = json_escaped_path(pem_path);
        const std::string der = json_escaped_path(der_path);
        for (const auto& item : certs["Install"]) {
            if (!item.is_string()) continue;
            const std::string value = item.get<std::string>();
            has_pem = has_pem || value == pem;
            has_der = has_der || value == der;
        }
        return has_pem && has_der;
    } catch (...) {
        return false;
    }
}

bool user_js_matches(const std::filesystem::path& path, const std::string& proxy_host, uint16_t proxy_port) {
    std::string text;
    if (!read_text_file(path, text)) return false;
    return text_has(text, "security.enterprise_roots.enabled\", true") &&
        text_has(text, "network.proxy.type\", 1") &&
        text_has(text, "network.proxy.http\", \"" + js_string_literal(proxy_host) + "\"") &&
        text_has(text, "network.proxy.http_port\", " + std::to_string(static_cast<unsigned>(proxy_port))) &&
        text_has(text, "network.proxy.ssl\", \"" + js_string_literal(proxy_host) + "\"") &&
        text_has(text, "network.proxy.ssl_port\", " + std::to_string(static_cast<unsigned>(proxy_port))) &&
        text_has(text, "network.http.http3.enabled\", false");
}

bool current_ca_files_match(const cert_generator::root_ca_t& ca,
                            const std::filesystem::path& pem_path,
                            const std::filesystem::path& der_path) {
    std::string expected_pem;
    if (!cert_generator::export_ca_certificate_pem(ca, expected_pem)) return false;
    std::string actual_pem;
    if (!read_text_file(pem_path, actual_pem) || actual_pem != expected_pem) return false;
    std::vector<uint8_t> expected_der;
    if (!cert_generator::export_ca_certificate_der(ca, expected_der)) return false;
    std::ifstream in(der_path, std::ios::binary);
    if (!in) return false;
    std::vector<uint8_t> actual_der((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return actual_der == expected_der;
}

std::string registry_app_path() {
    HKEY k = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe",
                      0, KEY_READ, &k) != ERROR_SUCCESS) {
        return std::string();
    }
    char buf[1024] = {};
    DWORD sz = sizeof(buf);
    DWORD type = 0;
    LONG rc = RegQueryValueExA(k, nullptr, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &sz);
    RegCloseKey(k);
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) return std::string();
    if (sz > 0 && buf[sz - 1] == '\0') sz--;
    return std::string(buf, sz);
}

std::string json_escaped_path(const std::filesystem::path& path) {
    return path.u8string();
}

std::string js_string_literal(std::string value) {
    std::string out;
    out.reserve(value.size());
    for (char ch : value) {
        if (ch == '\\' || ch == '"') out.push_back('\\');
        out.push_back(ch);
    }
    return out;
}

bool write_text_if_changed(const std::filesystem::path& path, const std::string& text, std::string& error) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        error = ec.message();
        return false;
    }
    {
        std::ifstream in(path, std::ios::binary);
        if (in) {
            std::ostringstream ss;
            ss << in.rdbuf();
            if (ss.str() == text) return true;
        }
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "open_failed";
        return false;
    }
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!out.good()) {
        error = "write_failed";
        return false;
    }
    return true;
}

bool write_bytes_if_changed(const std::filesystem::path& path, const std::vector<uint8_t>& bytes, std::string& error) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        error = ec.message();
        return false;
    }
    {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (in) {
            std::streamsize size = in.tellg();
            if (size == static_cast<std::streamsize>(bytes.size())) {
                in.seekg(0, std::ios::beg);
                std::vector<uint8_t> current(bytes.size());
                if (in.read(reinterpret_cast<char*>(current.data()), size) && current == bytes) return true;
            }
        }
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "open_failed";
        return false;
    }
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!out.good()) {
        error = "write_failed";
        return false;
    }
    return true;
}

std::string user_js_text(const std::string& proxy_host, uint16_t proxy_port) {
    std::ostringstream ss;
    ss << "user_pref(\"security.enterprise_roots.enabled\", true);\n";
    ss << "user_pref(\"network.proxy.type\", 1);\n";
    ss << "user_pref(\"network.proxy.http\", \"" << js_string_literal(proxy_host) << "\");\n";
    ss << "user_pref(\"network.proxy.http_port\", " << static_cast<unsigned>(proxy_port) << ");\n";
    ss << "user_pref(\"network.proxy.ssl\", \"" << js_string_literal(proxy_host) << "\");\n";
    ss << "user_pref(\"network.proxy.ssl_port\", " << static_cast<unsigned>(proxy_port) << ");\n";
    ss << "user_pref(\"network.proxy.no_proxies_on\", \"localhost, 127.0.0.1, ::1\");\n";
    ss << "user_pref(\"network.http.http3.enabled\", false);\n";
    return ss.str();
}

json policies_json(const std::filesystem::path& pem_path, const std::filesystem::path& der_path) {
    json root;
    root["policies"]["Certificates"]["ImportEnterpriseRoots"] = true;
    root["policies"]["Certificates"]["Install"] = json::array({
        json_escaped_path(pem_path),
        json_escaped_path(der_path)
    });
    return root;
}

}

std::filesystem::path intercept_root() {
    return local_appdata() / L"AiDA" / L"Standalone" / L"intercept";
}

std::filesystem::path ca_export_root() {
    return intercept_root() / L"ca";
}

std::filesystem::path firefox_profile_root() {
    return intercept_root() / L"firefox-profile";
}

bool detect_firefox_path(std::string& out_path) {
    std::vector<std::string> candidates;
    candidates.push_back(env_string("ProgramFiles", "C:\\Program Files") + "\\Mozilla Firefox\\firefox.exe");
    candidates.push_back(env_string("ProgramFiles(x86)", "C:\\Program Files (x86)") + "\\Mozilla Firefox\\firefox.exe");
    candidates.push_back(registry_app_path());
    for (const auto& candidate : candidates) {
        if (file_exists(candidate)) {
            out_path = candidate;
            return true;
        }
    }
    out_path.clear();
    return false;
}

public_ca_export_t export_public_ca_files(const cert_generator::root_ca_t& ca) {
    public_ca_export_t result;
    result.directory = ca_export_root();
    result.pem_path = result.directory / L"aida_root_ca.pem";
    result.der_path = result.directory / L"aida_root_ca.der";

    std::string pem;
    if (!cert_generator::export_ca_certificate_pem(ca, pem)) {
        result.error = "pem_export_failed";
        return result;
    }
    std::vector<uint8_t> der;
    if (!cert_generator::export_ca_certificate_der(ca, der)) {
        result.error = "der_export_failed";
        return result;
    }
    if (!write_text_if_changed(result.pem_path, pem, result.error)) return result;
    if (!write_bytes_if_changed(result.der_path, der, result.error)) return result;
    result.ok = true;
    return result;
}

firefox_profile_status_t prepare_firefox_profile(const cert_generator::root_ca_t& ca,
                                                 const std::string& proxy_host,
                                                 uint16_t proxy_port) {
    firefox_profile_status_t status;
    status.profile_path = firefox_profile_root();
    status.user_js_path = status.profile_path / L"user.js";
    status.proxy_endpoint = proxy_host + ":" + std::to_string(static_cast<unsigned>(proxy_port));

    std::error_code ec;
    std::filesystem::create_directories(status.profile_path, ec);
    if (ec) {
        status.error = ec.message();
        return status;
    }

    public_ca_export_t exported = export_public_ca_files(ca);
    status.ca_exported = exported.ok;
    status.ca_pem_path = exported.pem_path;
    status.ca_der_path = exported.der_path;
    if (!exported.ok) {
        status.error = exported.error;
        return status;
    }

    std::filesystem::path policy_dir = status.profile_path / L"distribution";
    status.policies_path = policy_dir / L"policies.json";
    std::string error;
    if (!write_text_if_changed(status.user_js_path, user_js_text(proxy_host, proxy_port), error)) {
        status.error = error;
        return status;
    }
    json policy = policies_json(status.ca_pem_path, status.ca_der_path);
    if (!write_text_if_changed(status.policies_path, policy.dump(2), error)) {
        status.error = error;
        return status;
    }

    status.firefox_detected = detect_firefox_path(status.firefox_path);
    std::ostringstream launch;
    if (status.firefox_detected) {
        launch << '"' << status.firefox_path << "\" --no-remote --profile \"" << status.profile_path.u8string() << "\"";
    } else {
        launch << "firefox.exe --no-remote --profile \"" << status.profile_path.u8string() << "\"";
    }
    status.launch_arguments = launch.str();
    status.enterprise_roots_enabled = true;
    status.policy_install_declared = true;
    status.proxy_configured = true;
    status.http3_disabled = true;
    status.ca_files_nonempty = file_nonempty(status.ca_pem_path) && file_nonempty(status.ca_der_path);
    status.current_user_ca_trusted = cert_generator::is_root_ca_installed(ca);
    status.trust_readiness_verified = status.current_user_ca_trusted;
    status.runtime_validation_performed = false;
    status.runtime_validation_valid = false;
    status.profile_files_valid = status.ca_files_nonempty &&
        user_js_matches(status.user_js_path, proxy_host, proxy_port) &&
        policies_declare_ca_install(status.policies_path, status.ca_pem_path, status.ca_der_path) &&
        current_ca_files_match(ca, status.ca_pem_path, status.ca_der_path);
    if (!status.profile_files_valid) {
        status.error = "profile_validation_failed";
        return status;
    }
    if (!status.current_user_ca_trusted) {
        status.error = "current_user_ca_not_trusted";
        status.notes.push_back("Firefox profile files are valid but current-user CA trust is not confirmed");
        return status;
    }
    status.prepared = true;
    status.ok = true;
    status.notes.push_back("Firefox profile user.js enables current-user enterprise roots and proxy routing");
    status.notes.push_back("Policy artifact declares public AiDA CA install without modifying the Firefox install directory");
    status.notes.push_back("HTTP/3 is disabled in the dedicated profile to keep traffic on the configured proxy path");
    status.notes.push_back("Runtime browser trust validation is not performed during profile preparation");
    return status;
}

firefox_profile_status_t inspect_firefox_profile() {
    firefox_profile_status_t status;
    status.profile_path = firefox_profile_root();
    status.user_js_path = status.profile_path / L"user.js";
    status.policies_path = status.profile_path / L"distribution" / L"policies.json";
    status.ca_pem_path = ca_export_root() / L"aida_root_ca.pem";
    status.ca_der_path = ca_export_root() / L"aida_root_ca.der";
    status.firefox_detected = detect_firefox_path(status.firefox_path);
    status.ca_files_nonempty = file_nonempty(status.ca_pem_path) && file_nonempty(status.ca_der_path);
    status.ca_exported = status.ca_files_nonempty;

    std::string user_js;
    if (read_text_file(status.user_js_path, user_js)) {
        status.enterprise_roots_enabled = text_has(user_js, "security.enterprise_roots.enabled\", true");
        status.proxy_configured = text_has(user_js, "network.proxy.type\", 1") &&
            text_has(user_js, "network.proxy.http") &&
            text_has(user_js, "network.proxy.ssl");
        status.http3_disabled = text_has(user_js, "network.http.http3.enabled\", false");
    }

    status.policy_install_declared = policies_declare_ca_install(status.policies_path, status.ca_pem_path, status.ca_der_path);
    bool ca_matches_current = false;
    if (cert_generator::is_ready()) {
        const auto& ca = cert_generator::get_root_ca();
        ca_matches_current = current_ca_files_match(ca, status.ca_pem_path, status.ca_der_path);
        status.current_user_ca_trusted = cert_generator::is_root_ca_installed(ca);
        status.trust_readiness_verified = status.current_user_ca_trusted && ca_matches_current;
    } else {
        status.trust_readiness_verified = false;
        status.notes.push_back("Current AiDA CA is not loaded locally; profile trust readiness is unverifiable");
    }
    status.runtime_validation_performed = false;
    status.runtime_validation_valid = false;
    status.profile_files_valid = status.ca_files_nonempty &&
        status.enterprise_roots_enabled &&
        status.proxy_configured &&
        status.http3_disabled &&
        status.policy_install_declared &&
        ca_matches_current;
    status.prepared = std::filesystem::exists(status.profile_path) && status.profile_files_valid && status.trust_readiness_verified;
    if (!status.prepared)
        status.error = status.profile_files_valid ? "firefox_profile_trust_unverified" : "firefox_profile_not_prepared";
    if (status.firefox_detected) {
        std::ostringstream launch;
        launch << '"' << status.firefox_path << "\" --no-remote --profile \"" << status.profile_path.u8string() << "\"";
        status.launch_arguments = launch.str();
    } else {
        std::ostringstream launch;
        launch << "firefox.exe --no-remote --profile \"" << status.profile_path.u8string() << "\"";
        status.launch_arguments = launch.str();
    }
    status.ok = status.prepared;
    return status;
}

firefox_profile_status_t launch_firefox_profile(const firefox_profile_status_t& prepared_status) {
    firefox_profile_status_t status = prepared_status;
    if (!status.prepared || !status.profile_files_valid) {
        status.ok = false;
        status.error = "firefox_profile_not_prepared";
        return status;
    }
    if (!status.firefox_detected && !detect_firefox_path(status.firefox_path)) {
        status.ok = false;
        status.error = "firefox_not_detected";
        return status;
    }

    std::ostringstream launch;
    launch << '"' << status.firefox_path << "\" --no-remote --profile \"" << status.profile_path.u8string() << "\"";
    status.launch_arguments = launch.str();

    std::wstring command = utf8_to_wide(status.launch_arguments);
    if (command.empty()) {
        status.ok = false;
        status.error = "launch_command_encoding_failed";
        return status;
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    BOOL created = CreateProcessW(
        nullptr,
        mutable_command.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_PROCESS_GROUP,
        nullptr,
        nullptr,
        &si,
        &pi);
    if (!created) {
        status.ok = false;
        status.error = "create_process_failed_" + std::to_string(GetLastError());
        return status;
    }

    status.launched = true;
    status.launched_pid = static_cast<uint32_t>(pi.dwProcessId);
    status.post_launch_profile_validated = false;
    uint32_t launched_pid = status.launched_pid;
    DWORD exit_code = 0;
    bool process_alive = GetExitCodeProcess(pi.hProcess, &exit_code) && exit_code == STILL_ACTIVE;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    firefox_profile_status_t checked = inspect_firefox_profile();
    status.profile_files_valid = checked.profile_files_valid;
    status.current_user_ca_trusted = checked.current_user_ca_trusted;
    status.trust_readiness_verified = checked.trust_readiness_verified;
    status.runtime_validation_performed = false;
    status.runtime_validation_valid = false;
    status.post_launch_profile_validated = process_alive && status.profile_files_valid && status.trust_readiness_verified;
    status.launched = true;
    status.launched_pid = launched_pid;
    status.ok = status.post_launch_profile_validated;
    if (!status.ok) status.error = "post_launch_profile_validation_failed";
    status.notes = checked.notes;
    status.notes.push_back("Firefox process was launched; network browser trust validation was not performed locally");
    if (!process_alive) status.notes.push_back("Firefox process exited before post-launch profile validation completed");
    return status;
}

}
}
