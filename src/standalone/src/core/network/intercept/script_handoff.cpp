#include "script_handoff.hpp"

#include <nlohmann/json.hpp>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace cert_intercept {
namespace {

using json = nlohmann::json;

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

bool openssl_export_template_candidate(const module_summary_t& module) {
    const std::string joined = lower_ascii(module.name + " " + module.path);
    return module.stable_export_candidate
        && joined.find("boringssl") == std::string::npos;
}

std::string timestamp_token() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &tt);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y%m%d-%H%M%S");
    return oss.str();
}

std::string sanitize_name(std::string value) {
    if (value.empty()) return "target";
    for (char& ch : value) {
        const unsigned char u = static_cast<unsigned char>(ch);
        if (!std::isalnum(u) && ch != '-' && ch != '_' && ch != '.') ch = '_';
    }
    return value;
}

json module_to_json(const module_summary_t& module, bool include_path) {
    json out;
    out["name"] = module.name;
    if (include_path) out["path"] = module.path;
    out["base"] = module.base;
    out["size"] = module.size;
    out["browser_runtime"] = module.browser_runtime;
    out["system_tls"] = module.system_tls;
    out["app_tls_stack"] = module.app_tls_stack;
    out["managed_runtime"] = module.managed_runtime;
    out["quic_capable"] = module.quic_capable;
    out["proxy_aware"] = module.proxy_aware;
    out["stable_export_candidate"] = module.stable_export_candidate;
    out["evidence"] = module.evidence;
    return out;
}

json finding_to_json(const diagnostic_finding_t& finding) {
    json out;
    out["classification"] = to_string(finding.classification);
    out["severity"] = to_string(finding.severity);
    out["title"] = finding.title;
    out["evidence"] = finding.evidence;
    out["next_action"] = finding.next_action;
    return out;
}

json provider_to_json(const provider_status_t& provider) {
    json out;
    out["provider_id"] = provider.descriptor.provider_id;
    out["display_name"] = provider.descriptor.display_name;
    out["state"] = to_string(provider.state);
    out["active"] = provider.active;
    out["intent"] = provider.descriptor.intent;
    out["behavior"] = provider.descriptor.behavior;
    out["forces_certificate_success"] = provider.descriptor.forces_certificate_success;
    out["reason"] = provider.reason;
    out["evidence"] = provider.evidence;
    return out;
}

std::string openssl_observer_template() {
    return R"JS(
const targets = [
  ["libssl-3-x64.dll", "SSL_get_verify_result"],
  ["libssl-1_1-x64.dll", "SSL_get_verify_result"],
  ["libcrypto-3-x64.dll", "X509_verify_cert"],
  ["libcrypto-1_1-x64.dll", "X509_verify_cert"]
];

for (const [moduleName, exportName] of targets) {
  const address = Module.findExportByName(moduleName, exportName);
  if (address === null) continue;
  Interceptor.attach(address, {
    onEnter(args) {
      this.exportName = exportName;
    },
    onLeave(retval) {
      send({
        kind: "tls_export_observation",
        export_name: this.exportName,
        retval: retval.toString()
      });
    }
  });
}
)JS";
}

bool write_text_file(const std::filesystem::path& path, const std::string& data, std::string& error) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "failed to open " + path.string();
        return false;
    }
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!out.good()) {
        error = "failed to write " + path.string();
        return false;
    }
    return true;
}

}

std::filesystem::path default_handoff_root() {
    wchar_t buffer[MAX_PATH] = {};
    const DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", buffer, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        return std::filesystem::path(buffer) / L"AiDA" / L"Standalone" / L"intercept" / L"handoff";
    }
    return std::filesystem::current_path() / "intercept" / "handoff";
}

handoff_result_t generate_handoff(const handoff_request_t& request) {
    handoff_result_t result;
    std::error_code ec;

    const std::string label = sanitize_name(!request.target_label.empty()
        ? request.target_label
        : request.diagnostics.process_name);
    const std::string dir_name = std::to_string(request.diagnostics.pid) + "-" + label + "-" + timestamp_token();
    result.directory = default_handoff_root() / dir_name;

    std::filesystem::create_directories(result.directory, ec);
    if (ec) {
        result.error = ec.message();
        return result;
    }

    json metadata;
    metadata["schema"] = "aida.intercept.handoff.v1";
    metadata["pid"] = request.diagnostics.pid;
    metadata["process_name"] = request.diagnostics.process_name;
    metadata["classification"] = to_string(request.diagnostics.primary);
    metadata["recommended_tier"] = request.diagnostics.recommended_tier;
    metadata["summary"] = request.diagnostics.summary;
    metadata["read_only_diagnostics"] = request.diagnostics.read_only;
    metadata["proxy_endpoint"] = request.proxy_endpoint;
    metadata["ca_cert_pem_path"] = request.ca_cert_pem_path;
    metadata["ca_cert_der_path"] = request.ca_cert_der_path;
    metadata["generated_at"] = timestamp_token();
    metadata["modules"] = json::array();
    metadata["findings"] = json::array();
    metadata["providers"] = json::array();
    metadata["scripts"] = json::array();

    bool wrote_export_template = false;
    for (const auto& module : request.diagnostics.modules) {
        metadata["modules"].push_back(module_to_json(module, request.include_module_paths));
        if (!wrote_export_template
            && request.diagnostics.primary == classification_t::true_pinning
            && openssl_export_template_candidate(module)) {
            const auto script_path = result.directory / "openssl_export_observer.js";
            if (!write_text_file(script_path, openssl_observer_template(), result.error)) return result;
            result.script_paths.push_back(script_path);
            metadata["scripts"].push_back(script_path.filename().string());
            wrote_export_template = true;
        }
    }

    for (const auto& finding : request.diagnostics.findings) {
        metadata["findings"].push_back(finding_to_json(finding));
    }
    for (const auto& provider : request.provider_statuses) {
        metadata["providers"].push_back(provider_to_json(provider));
    }

    result.metadata_path = result.directory / "handoff.json";
    if (!write_text_file(result.metadata_path, metadata.dump(2), result.error)) return result;

    result.ok = true;
    return result;
}

}
