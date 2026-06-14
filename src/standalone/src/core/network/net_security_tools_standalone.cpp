


#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

#include "standalone_compat.hpp"
#include "comm.h"
#include "net_security.hpp"
#include "cert_generator.hpp"
#include "mitm_proxy.hpp"
#include "intercept/cert_profile_manager.hpp"
#include "intercept/diagnostics.hpp"
#include "intercept/instrumentation_provider.hpp"
#include "obfuscation.hpp"
#include "pro.h"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <map>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;
namespace net_security_tools {

#ifdef __NT__

static std::string ns_bytes_to_hex(const std::uint8_t* data, std::size_t len) {
    std::string result;
    for (std::size_t i = 0; i < len; i++) {
        char hex[4]; qsnprintf(hex, sizeof(hex), "%02X", data[i]);
        result += hex;
    }
    return result;
}

static std::vector<std::uint8_t> ns_hex_to_bytes(const std::string& hex) {
    std::vector<std::uint8_t> out;
    std::string clean;
    for (char c : hex) {
        if (c != ' ' && c != ':' && c != '-') clean += c;
    }
    out.reserve(clean.size() / 2);
    for (std::size_t i = 0; i + 1 < clean.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
        };
        int h = nib(clean[i]), l = nib(clean[i+1]);
        if (h >= 0 && l >= 0) out.push_back(static_cast<std::uint8_t>((h << 4) | l));
    }
    return out;
}

static std::string ns_env_var(const char* name) {
    char env_buffer[32767] = {};
    DWORD len = GetEnvironmentVariableA(name, env_buffer, static_cast<DWORD>(sizeof(env_buffer)));
    if (len == 0 || len >= sizeof(env_buffer))
        return {};
    return std::string(env_buffer, len);
}

static void ns_add_unique_path(std::vector<std::string>& paths, const std::string& path) {
    if (path.empty())
        return;
    if (std::find(paths.begin(), paths.end(), path) == paths.end())
        paths.push_back(path);
}

static std::vector<std::string> ns_tshark_search_paths() {
    std::vector<std::string> paths;
    ns_add_unique_path(paths, ns_env_var("AIDA_TSHARK"));
    ns_add_unique_path(paths, ns_env_var("TSHARK_PATH"));
    const std::string program_files = ns_env_var("ProgramFiles");
    if (!program_files.empty())
        ns_add_unique_path(paths, program_files + "\\Wireshark\\tshark.exe");
    const std::string program_files_x86 = ns_env_var("ProgramFiles(x86)");
    if (!program_files_x86.empty())
        ns_add_unique_path(paths, program_files_x86 + "\\Wireshark\\tshark.exe");
    const std::string path_env = ns_env_var("PATH");
    size_t start = 0;
    while (start <= path_env.size()) {
        const size_t end = path_env.find(';', start);
        std::string dir = path_env.substr(start, end == std::string::npos ? std::string::npos : end - start);
        while (!dir.empty() && (dir.front() == '"' || dir.front() == ' '))
            dir.erase(dir.begin());
        while (!dir.empty() && (dir.back() == '"' || dir.back() == ' '))
            dir.pop_back();
        if (!dir.empty()) {
            if (dir.back() == '\\' || dir.back() == '/')
                ns_add_unique_path(paths, dir + "tshark.exe");
            else
                ns_add_unique_path(paths, dir + "\\tshark.exe");
        }
        if (end == std::string::npos)
            break;
        start = end + 1;
    }
    return paths;
}

static json ns_paths_to_json(const std::vector<std::string>& paths) {
    json arr = json::array();
    for (const auto& path : paths) {
        json item;
        item["path"] = path;
        std::error_code ec;
        item["exists"] = std::filesystem::exists(path, ec);
        if (ec)
            item["exists_error"] = ec.message();
        arr.push_back(std::move(item));
    }
    return arr;
}

struct ns_pcap_probe_t {
    bool exists = false;
    bool readable = false;
    bool valid = false;
    bool truncated = false;
    bool pcapng = false;
    std::uint64_t file_size = 0;
    std::uint32_t packet_count = 0;
    std::uint32_t block_count = 0;
    std::string format;
    std::string reason;
};

struct ns_keylog_probe_t {
    bool exists = false;
    bool readable = false;
    bool valid = false;
    std::uint64_t file_size = 0;
    std::uint32_t entry_count = 0;
    std::string reason;
};

static std::uint32_t ns_read_u32_le(const std::vector<std::uint8_t>& data, std::size_t off) {
    return static_cast<std::uint32_t>(data[off]) |
        (static_cast<std::uint32_t>(data[off + 1]) << 8) |
        (static_cast<std::uint32_t>(data[off + 2]) << 16) |
        (static_cast<std::uint32_t>(data[off + 3]) << 24);
}

static std::uint32_t ns_read_u32_be(const std::vector<std::uint8_t>& data, std::size_t off) {
    return (static_cast<std::uint32_t>(data[off]) << 24) |
        (static_cast<std::uint32_t>(data[off + 1]) << 16) |
        (static_cast<std::uint32_t>(data[off + 2]) << 8) |
        static_cast<std::uint32_t>(data[off + 3]);
}

static std::uint32_t ns_read_u32_ordered(const std::vector<std::uint8_t>& data, std::size_t off, bool little) {
    return little ? ns_read_u32_le(data, off) : ns_read_u32_be(data, off);
}

static bool ns_is_hex_token(const std::string& token) {
    if (token.empty() || (token.size() % 2) != 0)
        return false;
    for (char ch : token) {
        if (!std::isxdigit(static_cast<unsigned char>(ch)))
            return false;
    }
    return true;
}

static ns_pcap_probe_t ns_probe_pcap_file(const std::string& path) {
    ns_pcap_probe_t out;
    std::error_code ec;
    out.exists = std::filesystem::exists(path, ec);
    if (ec) {
        out.reason = ec.message();
        return out;
    }
    if (!out.exists) {
        out.reason = "pcap file does not exist";
        return out;
    }
    out.file_size = static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
    if (ec) {
        out.reason = ec.message();
        return out;
    }
    if (out.file_size < 4) {
        out.reason = "pcap file is shorter than a capture header";
        return out;
    }
    if (out.file_size > 64ull * 1024ull * 1024ull) {
        out.reason = "pcap fixture probe refuses files larger than 64 MiB without tshark";
        return out;
    }
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        out.reason = "pcap file could not be opened";
        return out;
    }
    std::vector<std::uint8_t> data(static_cast<std::size_t>(out.file_size));
    if (!data.empty())
        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!file && static_cast<std::uint64_t>(file.gcount()) != out.file_size) {
        out.reason = "pcap file read was incomplete";
        return out;
    }
    out.readable = true;
    const std::uint32_t magic_le = ns_read_u32_le(data, 0);
    if (magic_le == 0xA1B2C3D4u || magic_le == 0xA1B23C4Du ||
        magic_le == 0xD4C3B2A1u || magic_le == 0x4D3CB2A1u) {
        if (data.size() < 24) {
            out.truncated = true;
            out.reason = "pcap global header is truncated";
            return out;
        }
        const bool little = magic_le == 0xA1B2C3D4u || magic_le == 0xA1B23C4Du;
        out.format = "pcap";
        std::size_t off = 24;
        while (off < data.size()) {
            if (data.size() - off < 16) {
                out.truncated = true;
                out.reason = "pcap packet header is truncated";
                return out;
            }
            const std::uint32_t incl_len = ns_read_u32_ordered(data, off + 8, little);
            if (incl_len > data.size() - off - 16) {
                out.truncated = true;
                out.reason = "pcap packet payload exceeds file size";
                return out;
            }
            ++out.packet_count;
            off += 16 + static_cast<std::size_t>(incl_len);
        }
        out.valid = off == data.size();
        out.reason = out.valid ? (out.packet_count == 0 ? "valid empty pcap" : "valid pcap") : "pcap parser ended off boundary";
        return out;
    }
    if (magic_le == 0x0A0D0D0Au) {
        if (data.size() < 28) {
            out.truncated = true;
            out.reason = "pcapng section header is truncated";
            return out;
        }
        out.format = "pcapng";
        out.pcapng = true;
        bool little = true;
        std::size_t off = 0;
        while (off < data.size()) {
            if (data.size() - off < 12) {
                out.truncated = true;
                out.reason = "pcapng block header is truncated";
                return out;
            }
            const std::uint32_t type_le = ns_read_u32_le(data, off);
            if (type_le == 0x0A0D0D0Au && data.size() - off >= 12) {
                const std::uint32_t bom_le = ns_read_u32_le(data, off + 8);
                if (bom_le == 0x1A2B3C4Du)
                    little = true;
                else if (bom_le == 0x4D3C2B1Au)
                    little = false;
                else {
                    out.reason = "pcapng byte-order magic is invalid";
                    return out;
                }
            }
            const std::uint32_t block_type = ns_read_u32_ordered(data, off, little);
            const std::uint32_t block_len = ns_read_u32_ordered(data, off + 4, little);
            if (block_len < 12 || block_len > data.size() - off) {
                out.truncated = true;
                out.reason = "pcapng block length is invalid";
                return out;
            }
            const std::uint32_t block_len_tail = ns_read_u32_ordered(data, off + block_len - 4, little);
            if (block_len_tail != block_len) {
                out.reason = "pcapng trailing block length mismatch";
                return out;
            }
            ++out.block_count;
            if (block_type == 0x00000006u || block_type == 0x00000003u)
                ++out.packet_count;
            off += block_len;
        }
        out.valid = off == data.size() && out.block_count != 0;
        out.reason = out.valid ? (out.packet_count == 0 ? "valid empty pcapng" : "valid pcapng") : "pcapng parser ended off boundary";
        return out;
    }
    out.reason = "capture magic is not pcap or pcapng";
    return out;
}

static ns_keylog_probe_t ns_probe_keylog_file(const std::string& path) {
    ns_keylog_probe_t out;
    std::error_code ec;
    out.exists = std::filesystem::exists(path, ec);
    if (ec) {
        out.reason = ec.message();
        return out;
    }
    if (!out.exists) {
        out.reason = "keylog file does not exist";
        return out;
    }
    out.file_size = static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
    if (ec) {
        out.reason = ec.message();
        return out;
    }
    if (out.file_size > 16ull * 1024ull * 1024ull) {
        out.reason = "keylog fixture probe refuses files larger than 16 MiB without tshark";
        return out;
    }
    std::ifstream file(path);
    if (!file) {
        out.reason = "keylog file could not be opened";
        return out;
    }
    out.readable = true;
    std::string line;
    while (std::getline(file, line)) {
        line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](unsigned char ch) { return !std::isspace(ch); }));
        while (!line.empty() && std::isspace(static_cast<unsigned char>(line.back())))
            line.pop_back();
        if (line.empty() || line[0] == '#')
            continue;
        std::istringstream is(line);
        std::string label;
        std::string first;
        std::string second;
        is >> label >> first >> second;
        if (!label.empty() && ns_is_hex_token(first) && ns_is_hex_token(second))
            ++out.entry_count;
    }
    out.valid = true;
    out.reason = out.entry_count == 0 ? "readable keylog with no parsed entries" : "readable keylog";
    return out;
}

static json ns_pcap_probe_to_json(const ns_pcap_probe_t& probe) {
    json j;
    j["exists"] = probe.exists;
    j["readable"] = probe.readable;
    j["valid"] = probe.valid;
    j["truncated"] = probe.truncated;
    j["format"] = probe.format;
    j["pcapng"] = probe.pcapng;
    j["file_size"] = probe.file_size;
    j["packet_count"] = probe.packet_count;
    j["block_count"] = probe.block_count;
    j["reason"] = probe.reason;
    return j;
}

static json ns_keylog_probe_to_json(const ns_keylog_probe_t& probe) {
    json j;
    j["exists"] = probe.exists;
    j["readable"] = probe.readable;
    j["valid"] = probe.valid;
    j["file_size"] = probe.file_size;
    j["entry_count"] = probe.entry_count;
    j["reason"] = probe.reason;
    return j;
}

static bool ns_hex_to_bytes_strict(const std::string& hex, std::vector<std::uint8_t>& out) {
    out.clear();
    std::string clean;
    for (char c : hex) {
        if (c != ' ' && c != ':' && c != '-')
            clean += c;
    }
    if (clean.empty() || (clean.size() % 2) != 0)
        return false;
    out.reserve(clean.size() / 2);
    for (std::size_t i = 0; i + 1 < clean.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
        };
        const int h = nib(clean[i]);
        const int l = nib(clean[i + 1]);
        if (h < 0 || l < 0) {
            out.clear();
            return false;
        }
        out.push_back(static_cast<std::uint8_t>((h << 4) | l));
    }
    return true;
}

static bool ns_decode_pem_certificate_der(const std::string& pem, std::vector<std::uint8_t>& out) {
    out.clear();
    if (pem.empty())
        return false;
    DWORD needed = 0;
    if (!CryptStringToBinaryA(pem.c_str(), static_cast<DWORD>(pem.size()), CRYPT_STRING_BASE64HEADER, nullptr, &needed, nullptr, nullptr) || needed == 0)
        return false;
    out.resize(needed);
    if (!CryptStringToBinaryA(pem.c_str(), static_cast<DWORD>(pem.size()), CRYPT_STRING_BASE64HEADER, out.data(), &needed, nullptr, nullptr)) {
        out.clear();
        return false;
    }
    out.resize(needed);
    return true;
}

static bool ns_is_valid_certificate_der(const std::vector<std::uint8_t>& der, std::string& subject) {
    subject.clear();
    if (der.empty() || der.size() > 0x100000)
        return false;
    PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        der.data(), static_cast<DWORD>(der.size()));
    if (!ctx)
        return false;
    char name[512] = {};
    CertGetNameStringA(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, static_cast<DWORD>(sizeof(name)));
    subject = name;
    CertFreeCertificateContext(ctx);
    return true;
}

static bool ns_valid_sha1_thumbprint_text(const std::string& thumbprint) {
    std::size_t n = 0;
    for (char c : thumbprint) {
        if (c == ' ' || c == ':' || c == '-')
            continue;
        const bool hex = (c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F');
        if (!hex)
            return false;
        ++n;
    }
    return n == 40;
}

static json ns_module_to_json(const cert_intercept::module_summary_t& module) {
    json out;
    out["name"] = module.name;
    out["path"] = module.path;
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

static json ns_finding_to_json(const cert_intercept::diagnostic_finding_t& finding) {
    json out;
    out["classification"] = cert_intercept::to_string(finding.classification);
    out["severity"] = cert_intercept::to_string(finding.severity);
    out["title"] = finding.title;
    out["evidence"] = finding.evidence;
    out["next_action"] = finding.next_action;
    return out;
}

static json ns_diagnostics_to_json(const cert_intercept::process_diagnostics_t& diagnostics) {
    json out;
    out["pid"] = diagnostics.pid;
    out["process_name"] = diagnostics.process_name;
    out["primary"] = cert_intercept::to_string(diagnostics.primary);
    out["read_only"] = diagnostics.read_only;
    out["recommended_tier"] = diagnostics.recommended_tier;
    out["summary"] = diagnostics.summary;
    out["modules"] = json::array();
    for (const auto& module : diagnostics.modules) out["modules"].push_back(ns_module_to_json(module));
    out["findings"] = json::array();
    for (const auto& finding : diagnostics.findings) out["findings"].push_back(ns_finding_to_json(finding));
    return out;
}

static json ns_provider_to_json(const cert_intercept::provider_status_t& provider) {
    json out;
    out["provider_id"] = provider.descriptor.provider_id;
    out["display_name"] = provider.descriptor.display_name;
    out["state"] = cert_intercept::to_string(provider.state);
    out["active"] = provider.active;
    out["intent"] = provider.descriptor.intent;
    out["behavior"] = provider.descriptor.behavior;
    out["forces_certificate_success"] = provider.descriptor.forces_certificate_success;
    out["requires_explicit_target"] = provider.descriptor.requires_explicit_target;
    out["supports_attach"] = provider.descriptor.supports_attach;
    out["reason"] = provider.reason;
    out["evidence"] = provider.evidence;
    return out;
}

static std::string ns_lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

static bool ns_has_any(const std::string& value, std::initializer_list<const char*> needles) {
    const std::string lowered = ns_lower_copy(value);
    for (const char* needle : needles) {
        if (lowered.find(needle) != std::string::npos) return true;
    }
    return false;
}

static void ns_apply_proxy_observations(cert_intercept::diagnostic_context_t& context) {
    auto observations = mitm_proxy::get_tls_observations(64);
    for (const auto& obs : observations) {
        std::string evidence = std::string(mitm_proxy::to_string(obs.kind)) + " host=" + obs.target_host;
        if (!obs.sni.empty()) evidence += " sni=" + obs.sni;
        if (!obs.alpn.empty()) evidence += " alpn=" + obs.alpn;
        if (!obs.detail.empty()) evidence += " detail=" + obs.detail;
        switch (obs.kind) {
        case mitm_proxy::tls_observation_kind_t::http_tls:
            context.interception_observed = true;
            break;
        case mitm_proxy::tls_observation_kind_t::sni_authority_mismatch:
            context.hostname_san_mismatch_observed = true;
            context.interception_still_failing = true;
            context.observation_evidence.push_back(std::move(evidence));
            break;
        case mitm_proxy::tls_observation_kind_t::client_handshake_failed:
            if (ns_has_any(obs.detail, {"certificate", "unknown ca", "bad certificate", "required", "alert"})) {
                context.browser_trust_policy_or_ct_block = true;
                context.interception_still_failing = true;
                context.observation_evidence.push_back(std::move(evidence));
            }
            break;
        case mitm_proxy::tls_observation_kind_t::upstream_handshake_failed:
            if (ns_has_any(obs.detail, {"certificate required", "bad certificate", "handshake failure", "alert certificate"})) {
                context.mutual_tls_requested = true;
                context.interception_still_failing = true;
                context.observation_evidence.push_back(std::move(evidence));
            }
            break;
        case mitm_proxy::tls_observation_kind_t::non_http_tls:
            context.non_http_tls_observed = true;
            context.interception_still_failing = true;
            context.observation_evidence.push_back(std::move(evidence));
            break;
        default:
            break;
        }
    }
}

static cert_intercept::diagnostic_context_t ns_make_diagnostic_context(const json& params) {
    cert_intercept::diagnostic_context_t context;
    context.proxy_running = params.value("proxy_running", mitm_proxy::is_running());
    context.controlled_browser = params.value("controlled_browser", false);
    if (params.value("use_proxy_observations", true)) ns_apply_proxy_observations(context);
    if (params.value("quic_observed", false)) context.quic_observed = true;
    if (params.value("interception_observed", false)) context.interception_observed = true;
    if (params.value("interception_still_failing", false)) context.interception_still_failing = true;
    if (params.value("hostname_san_mismatch_observed", false)) context.hostname_san_mismatch_observed = true;
    if (params.value("browser_trust_policy_or_ct_block", false)) context.browser_trust_policy_or_ct_block = true;
    if (params.value("mutual_tls_requested", false)) context.mutual_tls_requested = true;
    if (params.value("non_http_tls_observed", false)) context.non_http_tls_observed = true;
    context.process_name = params.value("process_name", std::string());
    if (params.contains("proxy_endpoint") && params["proxy_endpoint"].is_string()) {
        context.proxy_endpoint = params["proxy_endpoint"].get<std::string>();
    } else {
        const auto& cfg = mitm_proxy::g_state.config;
        context.proxy_endpoint = cfg.bind_addr + ":" + std::to_string(static_cast<unsigned>(cfg.bind_port));
    }
    if (cert_generator::is_ready()) {
        const auto& ca = cert_generator::get_root_ca();
        context.ca_trusted = cert_generator::is_root_ca_installed(ca);
        context.ca_certificate_path = cert_generator::get_ca_storage_dir() + "\\aida_root_ca.pem";
    } else {
        context.ca_trusted = false;
    }
    if (params.contains("ca_trusted") && params["ca_trusted"].is_boolean())
        context.ca_trusted = params["ca_trusted"].get<bool>();
    if (params.contains("ca_certificate_path") && params["ca_certificate_path"].is_string())
        context.ca_certificate_path = params["ca_certificate_path"].get<std::string>();
    return context;
}

static bool ns_pin_method_from_string(const std::string& method, net_security::pin_bypass_method& out) {
    if (method.empty() || method == "all") {
        out = net_security::pin_bypass_method::all;
        return true;
    }
    if (method == "wintrust" || method == "windows_trust") {
        out = net_security::pin_bypass_method::windows_trust;
        return true;
    }
    if (method == "crypt32" || method == "chain_policy") {
        out = net_security::pin_bypass_method::windows_chain_policy;
        return true;
    }
    if (method == "schannel" || method == "windows_tls") {
        out = net_security::pin_bypass_method::windows_tls;
        return true;
    }
    if (method == "dotnet" || method == "managed") {
        out = net_security::pin_bypass_method::managed_dotnet;
        return true;
    }
    return false;
}

static std::string ns_get_downloads_folder() {
    char buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA("USERPROFILE", buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH)
        return std::string(buf, len) + "\\Downloads";
    return ".";
}

tool_result_t tls_extract_keys(const json& params) {
    std::uint32_t pid = params.value("pid", 0u);
    diag::log_tagged_fmt("net_sec", "tls_extract_keys entry pid=%u scan_schannel=%d scan_openssl=%d scan_nss=%d scan_boringssl=%d",
        pid,
        (int)params.value("scan_schannel", true),
        (int)params.value("scan_openssl", true),
        (int)params.value("scan_nss", true),
        (int)params.value("scan_boringssl", true));
    if (!device || !device->is_connected()) {
        diag::log_tagged("net_sec", "tls_extract_keys driver not connected");
        return tool_result_t::error(OBFSTR("Driver not connected"));
    }

    net_security::tls_key_scan_config_t config;
    config.pid = pid;
    config.scan_schannel = params.value("scan_schannel", true);
    config.scan_openssl = params.value("scan_openssl", true);
    config.scan_nss = params.value("scan_nss", true);
    config.scan_boringssl = params.value("scan_boringssl", true);
    config.max_results = params.value("max_results", 64u);

    auto keys = net_security::TlsKeyExtractor::instance().extract_keys(config);
    diag::log_tagged_fmt("net_sec", "tls_extract_keys keys_found=%zu pid=%u", keys.size(), pid);
    json result;
    result["keys_found"] = keys.size();
    json arr = json::array();
    for (const auto& k : keys) {
        json kj;
        kj["label"] = k.label;
        kj["client_random"] = ns_bytes_to_hex(k.client_random.data(), k.client_random.size());
        kj["secret"] = ns_bytes_to_hex(k.secret.data(), k.secret.size());
        kj["tls_version"] = k.tls_version;
        kj["pid"] = k.pid;
        kj["library"] = k.library;
        kj["timestamp"] = k.timestamp;
        diag::log_tagged_fmt("net_sec", "tls_extract_keys key label=%s library=%s pid=%u", k.label.c_str(), k.library.c_str(), k.pid);
        arr.push_back(kj);
    }
    result["keys"] = arr;
    return tool_result_t::ok(OBFSTR("Extracted ") + std::to_string(keys.size()) + OBFSTR(" TLS session keys"), result);
}

tool_result_t tls_start_keylog(const json& params) {
    diag::log_tagged_fmt("net_sec", "tls_start_keylog entry pid=%u output_file=%s poll_interval_ms=%u",
        params.value("pid", 0u),
        params.value("output_file", "").c_str(),
        params.value("poll_interval_ms", 2000u));
    net_security::keylog_config_t config;
    config.pid = params.value("pid", 0u);
    config.output_file = params.value("output_file", "");
    config.poll_interval_ms = params.value("poll_interval_ms", 2000u);
    config.append = params.value("append", true);

    if (config.output_file.empty()) {
        config.output_file = ns_get_downloads_folder() + "\\sslkeylog.txt";
        diag::log_tagged_fmt("net_sec", "tls_start_keylog using default output_file=%s", config.output_file.c_str());
    }

    bool started = net_security::TlsKeyExtractor::instance().start_keylog(config);
    diag::log_tagged_fmt("net_sec", "tls_start_keylog started=%d output_file=%s", (int)started, config.output_file.c_str());
    if (started) {
        json r;
        r["status"] = "started";
        r["output_file"] = config.output_file;
        r["poll_interval_ms"] = config.poll_interval_ms;
        return tool_result_t::ok(OBFSTR("TLS keylogging started -> ") + config.output_file, r);
    }
    return tool_result_t::error(OBFSTR("Keylogging already active or failed to start"));
}

tool_result_t tls_stop_keylog(const json&) {
    diag::log_tagged("net_sec", "tls_stop_keylog entry");
    bool stopped = net_security::TlsKeyExtractor::instance().stop_keylog();
    diag::log_tagged_fmt("net_sec", "tls_stop_keylog stopped=%d", (int)stopped);
    if (stopped) {
        json r;
        r["status"] = "stopped";
        return tool_result_t::ok(OBFSTR("TLS keylogging stopped"), r);
    }
    return tool_result_t::error(OBFSTR("No active keylogging session"));
}

tool_result_t tls_get_extracted_keys(const json&) {
    diag::log_tagged("net_sec", "tls_get_extracted_keys entry");
    auto& ext = net_security::TlsKeyExtractor::instance();
    auto seen = ext.get_seen_keys();
    diag::log_tagged_fmt("net_sec", "tls_get_extracted_keys total_keys=%zu", seen.size());

    json result;
    result["total_keys"] = seen.size();
    json arr = json::array();
    for (const auto& [key, val] : seen) {
        json kj;
        kj["label"] = val.label;
        kj["client_random"] = ns_bytes_to_hex(val.client_random.data(), val.client_random.size());
        kj["secret"] = ns_bytes_to_hex(val.secret.data(), val.secret.size());
        kj["library"] = val.library;
        kj["pid"] = val.pid;
        arr.push_back(kj);
    }
    result["keys"] = arr;
    return tool_result_t::ok(OBFSTR("Retrieved ") + std::to_string(seen.size()) + OBFSTR(" cached TLS keys"), result);
}

tool_result_t cert_inject(const json& params) {
    const bool validate_only = params.contains("validate_only") &&
        params["validate_only"].is_boolean() &&
        params["validate_only"].get<bool>();
    diag::log_tagged_fmt("net_sec", "cert_inject entry store_name=%s system_wide=%d has_pem=%d has_der_hex=%d validate_only=%d",
        params.value("store_name", "ROOT").c_str(),
        (int)params.value("system_wide", false),
        (int)params.contains("cert_pem"),
        (int)params.contains("cert_der_hex"),
        validate_only ? 1 : 0);
    net_security::cert_injection_config_t config;
    config.cert_pem = params.value("cert_pem", "");
    config.store_name = params.value("store_name", "ROOT");
    config.system_wide = params.value("system_wide", false);

    if (params.contains("cert_der_hex") && params["cert_der_hex"].is_string()) {
        auto hex = params["cert_der_hex"].get<std::string>();
        config.cert_der = ns_hex_to_bytes(hex);
        diag::log_tagged_fmt("net_sec", "cert_inject der_hex len=%zu bytes=%zu", hex.size(), config.cert_der.size());
    }

    if (validate_only) {
        std::vector<std::uint8_t> der;
        std::string format;
        if (params.contains("cert_der_hex")) {
            if (!params["cert_der_hex"].is_string())
                return tool_result_t::error(OBFSTR("cert_der_hex must be a string"));
            if (!ns_hex_to_bytes_strict(params["cert_der_hex"].get<std::string>(), der))
                return tool_result_t::error(OBFSTR("cert_der_hex is not valid hex DER data"));
            format = OBFSTR("der_hex");
        } else if (params.contains("cert_pem")) {
            if (!params["cert_pem"].is_string())
                return tool_result_t::error(OBFSTR("cert_pem must be a string"));
            if (!ns_decode_pem_certificate_der(params["cert_pem"].get<std::string>(), der))
                return tool_result_t::error(OBFSTR("cert_pem is not a valid PEM certificate"));
            format = OBFSTR("pem");
        } else {
            return tool_result_t::error(OBFSTR("cert_pem or cert_der_hex is required"));
        }
        std::string subject;
        if (!ns_is_valid_certificate_der(der, subject))
            return tool_result_t::error(OBFSTR("certificate data is not a valid X.509 certificate"));
        json r;
        r["success"] = true;
        r["validate_only"] = true;
        r["format"] = format;
        r["cert_size"] = der.size();
        r["subject_cn"] = subject;
        r["store_name"] = config.store_name;
        r["system_wide"] = config.system_wide;
        return tool_result_t::ok(OBFSTR("Validated certificate injection request without modifying the certificate store."), r);
    }

    auto result = net_security::CertificateInjector::instance().inject_certificate(config);
    diag::log_tagged_fmt("net_sec", "cert_inject result success=%d thumbprint=%s subject_cn=%s store=%s method=%s",
        (int)result.success, result.thumbprint.c_str(), result.subject_cn.c_str(), result.store_name.c_str(), result.method.c_str());
    json r;
    r["success"] = result.success;
    r["thumbprint"] = result.thumbprint;
    r["subject_cn"] = result.subject_cn;
    r["store_name"] = result.store_name;
    r["method"] = result.method;
    if (result.success)
        return tool_result_t::ok(OBFSTR("Certificate injected: ") + result.subject_cn, r);
    return tool_result_t::error(OBFSTR("Certificate injection failed"), r);
}

tool_result_t cert_remove(const json& params) {
    std::string thumbprint = params.value("thumbprint", "");
    std::string store_name = params.value("store_name", "ROOT");
    const bool validate_only = params.contains("validate_only") &&
        params["validate_only"].is_boolean() &&
        params["validate_only"].get<bool>();
    diag::log_tagged_fmt("net_sec", "cert_remove entry thumbprint=%s store_name=%s validate_only=%d", thumbprint.c_str(), store_name.c_str(), validate_only ? 1 : 0);
    if (thumbprint.empty()) {
        diag::log_tagged("net_sec", "cert_remove thumbprint empty -> error");
        return tool_result_t::error(OBFSTR("thumbprint is required"));
    }

    if (validate_only) {
        if (!ns_valid_sha1_thumbprint_text(thumbprint))
            return tool_result_t::error(OBFSTR("thumbprint must be a 40-hex-character SHA-1 certificate thumbprint"));
        json r;
        r["removed"] = false;
        r["validate_only"] = true;
        r["thumbprint"] = thumbprint;
        r["store_name"] = store_name;
        return tool_result_t::ok(OBFSTR("Validated certificate removal request without modifying the certificate store."), r);
    }

    bool removed = net_security::CertificateInjector::instance().remove_certificate(thumbprint, store_name);
    diag::log_tagged_fmt("net_sec", "cert_remove removed=%d thumbprint=%s", (int)removed, thumbprint.c_str());
    if (removed) {
        json r;
        r["removed"] = true;
        r["thumbprint"] = thumbprint;
        return tool_result_t::ok(OBFSTR("Certificate removed"), r);
    }
    return tool_result_t::error(OBFSTR("Failed to remove certificate"));
}

tool_result_t cert_generate_ca(const json& params) {
    std::string cn = params.value("cn", "AiDA Proxy CA");
    std::uint32_t days = params.value("validity_days", 3650u);
    const bool validate_only = params.contains("validate_only") &&
        params["validate_only"].is_boolean() &&
        params["validate_only"].get<bool>();
    diag::log_tagged_fmt("net_sec", "cert_generate_ca entry cn=%s days=%u validate_only=%d", cn.c_str(), days, validate_only ? 1 : 0);

    if (validate_only) {
        if (!cert_generator::is_ready() && !cert_generator::initialize())
            return tool_result_t::error(OBFSTR("AiDA CA is not ready"));
        std::vector<std::uint8_t> cert_der;
        if (!cert_generator::export_ca_certificate_der(cert_generator::get_root_ca(), cert_der) || cert_der.empty())
            return tool_result_t::error(OBFSTR("Failed to export AiDA public CA certificate"));
        std::string subject;
        if (!ns_is_valid_certificate_der(cert_der, subject))
            return tool_result_t::error(OBFSTR("Generated CA certificate did not validate as X.509"));
        json r;
        r["success"] = true;
        r["validate_only"] = true;
        r["private_key_exported"] = false;
        r["cert_size"] = cert_der.size();
        r["subject_cn"] = subject.empty() ? cn : subject;
        r["validity_days"] = days;
        return tool_result_t::ok(OBFSTR("Validated public CA certificate generation path without exporting private key material"), r);
    }

    std::vector<std::uint8_t> cert_der;
    std::string subject_cn;
    bool ok = cert_generator::generate_public_ca_certificate_der(cn, days, cert_der, subject_cn);
    diag::log_tagged_fmt("net_sec", "cert_generate_ca ok=%d cert_size=%zu cn=%s subject=%s",
        (int)ok, cert_der.size(), cn.c_str(), subject_cn.c_str());
    json r;
    r["success"] = ok;
    r["backend"] = "openssl_public_der";
    r["private_key_exported"] = false;
    r["cert_size"] = cert_der.size();
    r["subject_cn"] = subject_cn.empty() ? cn : subject_cn;
    r["validity_days"] = days;
    if (ok) {
        r["cert_der_hex"] = ns_bytes_to_hex(cert_der.data(), cert_der.size());
        return tool_result_t::ok(OBFSTR("Generated public CA certificate: ") + cn, r);
    }
    return tool_result_t::error(OBFSTR("Failed to generate CA certificate"), r);
}

tool_result_t cert_list(const json& params) {
    std::string store_name = params.value("store_name", "ROOT");
    diag::log_tagged_fmt("net_sec", "cert_list entry store_name=%s", store_name.c_str());
    auto certs = net_security::CertificateInjector::instance().list_certificates(store_name);
    diag::log_tagged_fmt("net_sec", "cert_list count=%zu store_name=%s", certs.size(), store_name.c_str());

    json result;
    result["store_name"] = store_name;
    result["count"] = certs.size();
    json arr = json::array();
    for (const auto& c : certs) {
        json cj;
        cj["thumbprint"] = c.thumbprint;
        cj["subject"] = c.subject;
        cj["issuer"] = c.issuer;
        cj["not_before"] = c.not_before;
        cj["not_after"] = c.not_after;
        cj["is_ca"] = c.is_ca;
        arr.push_back(cj);
    }
    result["certificates"] = arr;
    return tool_result_t::ok(OBFSTR("Listed ") + std::to_string(certs.size()) + OBFSTR(" certificates"), result);
}

tool_result_t pin_bypass(const json& params) {
    std::uint32_t pid = params.value("pid", 0u);
    std::string method = params.value("method", "all");
    diag::log_tagged_fmt("net_sec", "pin_bypass entry pid=%u method=%s", pid, method.c_str());
    const std::string method_lc = ns_lower_copy(method);
    net_security::pin_bypass_method parsed_method = net_security::pin_bypass_method::all;
    if (!ns_pin_method_from_string(method_lc, parsed_method)) {
        json r;
        r["success"] = false;
        r["camoufox_only"] = true;
        r["supported_browser"] = "camoufox";
        r["unsupported_method"] = method;
        return tool_result_t::error(OBFSTR("Unsupported certificate diagnostic method; Camoufox is the only AiDA browser"), r);
    }
    if (pid == 0 && device && device->is_connected()) pid = device->get_process_id();

    net_security::pin_bypass_config_t config;
    config.pid = pid;
    config.method = parsed_method;

    auto legacy = net_security::CertPinBypasser::instance().bypass_pins(config);
    auto context = ns_make_diagnostic_context(params);
    auto diagnostics = cert_intercept::diagnose_process(pid, context);
    auto providers = cert_intercept::provider_registry_t::instance().evaluate(pid, diagnostics);
    diag::log_tagged_fmt("net_sec", "pin_bypass diagnostics primary=%s providers=%zu pid=%u",
        cert_intercept::to_string(diagnostics.primary).c_str(), providers.size(), pid);

    json r;
    r["success"] = false;
    r["pid"] = pid;
    r["read_only"] = true;
    r["target_process_modified"] = false;
    r["legacy_patching_disabled"] = legacy.legacy_patching_disabled;
    r["diagnostic_summary"] = legacy.diagnostic_summary;
    r["recommended_action"] = legacy.recommended_action;
    r["methods_requested"] = legacy.methods_requested;
    r["disabled_operations"] = legacy.disabled_operations;
    r["diagnostics"] = ns_diagnostics_to_json(diagnostics);
    r["providers"] = json::array();
    for (const auto& provider : providers) r["providers"].push_back(ns_provider_to_json(provider));
    return tool_result_t::ok(OBFSTR("Certificate interception diagnostics completed without process modification"), r);
}

tool_result_t quic_detect_connections(const json& params) {
    std::uint32_t pid = params.value("pid", 0u);
    diag::log_tagged_fmt("net_sec", "quic_detect_connections entry pid=%u", pid);
    if (!device || !device->is_connected()) {
        diag::log_tagged("net_sec", "quic_detect_connections driver not connected");
        return tool_result_t::error(OBFSTR("Driver not connected"));
    }

    auto conns = net_security::QuicAnalyzer::instance().detect_quic_connections(pid);
    diag::log_tagged_fmt("net_sec", "quic_detect_connections count=%zu pid=%u", conns.size(), pid);

    json result;
    result["count"] = conns.size();
    json arr = json::array();
    for (const auto& c : conns) {
        json cj;
        cj["pid"] = c.pid;
        cj["src_port"] = c.src_port;
        cj["dst_port"] = c.dst_port;
        cj["dcid"] = ns_bytes_to_hex(c.dcid.data(), c.dcid.size());
        cj["scid"] = ns_bytes_to_hex(c.scid.data(), c.scid.size());
        cj["packets_sent"] = c.packets_sent;
        cj["packets_recv"] = c.packets_recv;
        cj["bytes_sent"] = c.bytes_sent;
        cj["bytes_recv"] = c.bytes_recv;
        cj["alpn"] = c.alpn;
        arr.push_back(cj);
    }
    result["connections"] = arr;
    return tool_result_t::ok(OBFSTR("Detected ") + std::to_string(conns.size()) + OBFSTR(" QUIC connections"), result);
}

tool_result_t quic_decrypt_initial(const json& params) {
    diag::log_tagged("net_sec", "quic_decrypt_initial entry");
    if (!params.contains("packet_hex")) {
        diag::log_tagged("net_sec", "quic_decrypt_initial missing packet_hex");
        return tool_result_t::error(OBFSTR("packet_hex is required"));
    }

    auto pkt_bytes = ns_hex_to_bytes(params["packet_hex"].get<std::string>());
    diag::log_tagged_fmt("net_sec", "quic_decrypt_initial packet_bytes=%zu", pkt_bytes.size());
    if (pkt_bytes.empty()) {
        diag::log_tagged("net_sec", "quic_decrypt_initial invalid packet hex data");
        return tool_result_t::error(OBFSTR("Invalid packet hex data"));
    }

    auto result = net_security::QuicAnalyzer::instance().decrypt_initial_packet(pkt_bytes.data(), pkt_bytes.size());
    diag::log_tagged_fmt("net_sec", "quic_decrypt_initial result success=%d version=0x%x type=%s", (int)result.success, result.quic_version, result.packet_type.c_str());
    json r;
    r["success"] = result.success;
    r["quic_version"] = result.quic_version;
    r["packet_type"] = result.packet_type;
    r["dcid"] = ns_bytes_to_hex(result.dcid.data(), result.dcid.size());
    r["scid"] = ns_bytes_to_hex(result.scid.data(), result.scid.size());
    if (result.success)
        return tool_result_t::ok(OBFSTR("QUIC Initial packet decoded"), r);
    return tool_result_t::error(OBFSTR("Failed to decode QUIC Initial packet"));
}

tool_result_t quic_extract_keys(const json& params) {
    std::uint32_t pid = params.value("pid", 0u);
    diag::log_tagged_fmt("net_sec", "quic_extract_keys entry pid=%u", pid);
    if (!device || !device->is_connected()) {
        diag::log_tagged("net_sec", "quic_extract_keys driver not connected");
        return tool_result_t::error(OBFSTR("Driver not connected"));
    }

    auto keys = net_security::QuicAnalyzer::instance().extract_quic_traffic_keys(pid);
    diag::log_tagged_fmt("net_sec", "quic_extract_keys keys_found=%zu pid=%u", keys.size(), pid);

    json result;
    result["keys_found"] = keys.size();
    json arr = json::array();
    for (const auto& k : keys) {
        json kj;
        kj["label"] = k.label;
        kj["client_random"] = ns_bytes_to_hex(k.client_random.data(), k.client_random.size());
        kj["secret"] = ns_bytes_to_hex(k.secret.data(), k.secret.size());
        kj["library"] = k.library;
        kj["pid"] = k.pid;
        arr.push_back(kj);
    }
    result["keys"] = arr;
    return tool_result_t::ok(OBFSTR("Extracted ") + std::to_string(keys.size()) + OBFSTR(" QUIC keys"), result);
}

tool_result_t dtls_detect_sessions(const json& params) {
    std::uint32_t pid = params.value("pid", 0u);
    diag::log_tagged_fmt("net_sec", "dtls_detect_sessions entry pid=%u", pid);
    if (!device || !device->is_connected()) {
        diag::log_tagged("net_sec", "dtls_detect_sessions driver not connected");
        return tool_result_t::error(OBFSTR("Driver not connected"));
    }

    auto sessions = net_security::DtlsAnalyzer::instance().detect_dtls_sessions(pid);
    diag::log_tagged_fmt("net_sec", "dtls_detect_sessions count=%zu pid=%u", sessions.size(), pid);

    json result;
    result["count"] = sessions.size();
    json arr = json::array();
    for (const auto& s : sessions) {
        json sj;
        sj["pid"] = s.pid;
        sj["src_port"] = s.src_port;
        sj["dst_port"] = s.dst_port;
        sj["dtls_version"] = s.dtls_version;
        sj["epoch"] = s.epoch;
        sj["state"] = s.state;
        sj["content_type"] = s.content_type;
        arr.push_back(sj);
    }
    result["sessions"] = arr;
    return tool_result_t::ok(OBFSTR("Detected ") + std::to_string(sessions.size()) + OBFSTR(" DTLS sessions"), result);
}

tool_result_t dtls_extract_keys(const json& params) {
    std::uint32_t pid = params.value("pid", 0u);
    diag::log_tagged_fmt("net_sec", "dtls_extract_keys entry pid=%u", pid);
    if (!device || !device->is_connected()) {
        diag::log_tagged("net_sec", "dtls_extract_keys driver not connected");
        return tool_result_t::error(OBFSTR("Driver not connected"));
    }

    auto keys = net_security::TlsKeyExtractor::instance().extract_dtls_keys(pid);
    diag::log_tagged_fmt("net_sec", "dtls_extract_keys keys_found=%zu pid=%u", keys.size(), pid);

    json result;
    result["keys_found"] = keys.size();
    json arr = json::array();
    for (const auto& k : keys) {
        json kj;
        kj["dtls_version"] = k.dtls_version;
        kj["client_random"] = ns_bytes_to_hex(k.client_random.data(), k.client_random.size());
        kj["master_secret"] = ns_bytes_to_hex(k.master_secret.data(), k.master_secret.size());
        kj["library"] = k.library;
        kj["pid"] = k.pid;
        arr.push_back(kj);
    }
    result["keys"] = arr;
    return tool_result_t::ok(OBFSTR("Extracted ") + std::to_string(keys.size()) + OBFSTR(" DTLS keys"), result);
}

tool_result_t network_decrypt_capture(const json& params) {
    std::string pcap_path = params.value("pcap_path", "");
    std::string keylog_path = params.value("keylog_path", "");
    std::string display_filter = params.value("display_filter", "http2");
    diag::log_tagged_fmt("net_sec", "network_decrypt_capture entry pcap_path=%s keylog_path=%s display_filter=%s",
        pcap_path.c_str(), keylog_path.c_str(), display_filter.c_str());

    if (pcap_path.empty()) {
        diag::log_tagged("net_sec", "network_decrypt_capture pcap_path empty -> error");
        return tool_result_t::error(OBFSTR("pcap_path is required"));
    }


    if (keylog_path.empty()) {
        char buf[MAX_PATH] = {};
        DWORD len = GetEnvironmentVariableA("SSLKEYLOGFILE", buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) keylog_path = std::string(buf, len);
        diag::log_tagged_fmt("net_sec", "network_decrypt_capture SSLKEYLOGFILE env keylog_path=%s", keylog_path.c_str());
    }
    if (keylog_path.empty()) {
        diag::log_tagged("net_sec", "network_decrypt_capture keylog_path empty -> error");
        return tool_result_t::error(OBFSTR("keylog_path is required (or set SSLKEYLOGFILE environment variable)"));
    }

    auto searched_paths = ns_tshark_search_paths();
    const ns_pcap_probe_t pcap_probe = ns_probe_pcap_file(pcap_path);
    const ns_keylog_probe_t keylog_probe = ns_probe_keylog_file(keylog_path);
    std::string tshark_path = net_security::TlsKeyExtractor::instance().find_tshark_path();
    if (tshark_path.empty()) {
        json r;
        const bool empty_fixture_ok = pcap_probe.valid && pcap_probe.packet_count == 0 && keylog_probe.valid;
        r["success"] = empty_fixture_ok;
        r["backend"] = empty_fixture_ok ? "builtin_empty_pcap_fixture" : "tshark";
        r["safe_parser_backend"] = "builtin_empty_pcap_fixture";
        r["dependency_available"] = empty_fixture_ok;
        r["dependency_unavailable"] = !empty_fixture_ok;
        r["tshark_available"] = false;
        r["selected"] = nullptr;
        r["searched_paths"] = ns_paths_to_json(searched_paths);
        r["pcap_file"] = pcap_path;
        r["keylog_file"] = keylog_path;
        r["display_filter"] = display_filter;
        r["pcap"] = ns_pcap_probe_to_json(pcap_probe);
        r["keylog"] = ns_keylog_probe_to_json(keylog_probe);
        r["pcap_valid"] = pcap_probe.valid;
        r["pcap_packet_count"] = pcap_probe.packet_count;
        r["keylog_entry_count"] = keylog_probe.entry_count;
        r["total_packets"] = pcap_probe.packet_count;
        r["decrypted_packets"] = 0;
        r["http2_frames"] = json::array();
        if (empty_fixture_ok) {
            r["expected_empty"] = true;
            r["reason"] = "valid empty capture fixture parsed without tshark";
            diag::log_tagged_fmt("net_sec", "network_decrypt_capture empty_fixture backend=builtin pcap=%s keylog=%s filter=%s packets=%u keylog_entries=%u searched_paths=%zu",
                pcap_path.c_str(), keylog_path.c_str(), display_filter.c_str(),
                pcap_probe.packet_count, keylog_probe.entry_count, searched_paths.size());
            return tool_result_t::ok(OBFSTR("Validated empty TLS capture fixture without tshark"), r);
        }
        r["reason"] = pcap_probe.valid && pcap_probe.packet_count != 0
            ? "non-empty capture requires tshark for decryption"
            : (!pcap_probe.valid ? pcap_probe.reason : (!keylog_probe.valid ? keylog_probe.reason : "tshark backend unavailable"));
        r["error"] = "tshark not found. Install Wireshark to enable PCAP decryption.";
        diag::log_tagged_fmt("net_sec", "network_decrypt_capture dependency_unavailable backend=tshark pcap=%s keylog=%s filter=%s pcap_valid=%d packets=%u keylog_valid=%d keylog_entries=%u reason=%s searched_paths=%zu",
            pcap_path.c_str(), keylog_path.c_str(), display_filter.c_str(),
            pcap_probe.valid ? 1 : 0, pcap_probe.packet_count,
            keylog_probe.valid ? 1 : 0, keylog_probe.entry_count,
            r["reason"].get<std::string>().c_str(), searched_paths.size());
        return tool_result_t::error(OBFSTR("tshark not found. Install Wireshark to enable PCAP decryption."), r);
    }
    ns_add_unique_path(searched_paths, tshark_path);

    diag::log_tagged_fmt("net_sec", "network_decrypt_capture calling tshark pcap=%s keylog=%s filter=%s tshark=%s", pcap_path.c_str(), keylog_path.c_str(), display_filter.c_str(), tshark_path.c_str());
    auto decrypt_result = net_security::TlsKeyExtractor::instance().decrypt_pcap_with_tshark(
        pcap_path, keylog_path, display_filter);
    diag::log_tagged_fmt("net_sec", "network_decrypt_capture result success=%d total_packets=%u decrypted=%u http2_frames=%zu",
        (int)decrypt_result.success, decrypt_result.total_packets, decrypt_result.decrypted_packets, decrypt_result.http2_frames.size());

    json r;
    r["success"] = decrypt_result.success;
    r["backend"] = "tshark";
    r["dependency_available"] = true;
    r["dependency_unavailable"] = false;
    r["selected"] = tshark_path;
    r["searched_paths"] = ns_paths_to_json(searched_paths);
    r["tshark_path"] = tshark_path;
    r["pcap_file"] = decrypt_result.pcap_file_used;
    r["keylog_file"] = decrypt_result.keylog_file_used;
    r["pcap"] = ns_pcap_probe_to_json(pcap_probe);
    r["keylog"] = ns_keylog_probe_to_json(keylog_probe);
    r["pcap_valid"] = pcap_probe.valid;
    r["pcap_packet_count"] = pcap_probe.packet_count;
    r["keylog_entry_count"] = keylog_probe.entry_count;
    r["total_packets"] = decrypt_result.total_packets;
    r["decrypted_packets"] = decrypt_result.decrypted_packets;
    r["reason"] = decrypt_result.success
        ? "tshark decrypted capture"
        : (decrypt_result.error_message.empty() ? "tshark completed without matching decrypted packets" : decrypt_result.error_message);

    if (!decrypt_result.error_message.empty())
        r["error"] = decrypt_result.error_message;

    json frames = json::array();
    for (const auto& f : decrypt_result.http2_frames) {
        json fj;
        if (!f.stream_id.empty()) fj["stream_id"] = f.stream_id;
        if (!f.method.empty()) fj["method"] = f.method;
        if (!f.url.empty()) fj["url"] = f.url;
        if (!f.authority.empty()) fj["authority"] = f.authority;
        if (!f.content_type.empty()) fj["content_type"] = f.content_type;
        if (f.status_code != 0) fj["status_code"] = f.status_code;
        if (!f.frame_type.empty()) fj["frame_type"] = f.frame_type;
        if (!f.headers.empty()) {
            json hdrs = json::object();
            for (const auto& [k, v] : f.headers) hdrs[k] = v;
            fj["headers"] = hdrs;
        }
        if (!f.body.empty()) fj["body"] = f.body;
        frames.push_back(fj);
    }
    r["http2_frames"] = frames;

    if (decrypt_result.success)
        return tool_result_t::ok(
            OBFSTR("Decrypted ") + std::to_string(decrypt_result.decrypted_packets) +
            OBFSTR(" packets, found ") + std::to_string(decrypt_result.http2_frames.size()) +
            OBFSTR(" HTTP/2 frames"), r);

    return tool_result_t::error(decrypt_result.error_message.empty() ?
        OBFSTR("Decryption failed - no matching packets found") : decrypt_result.error_message, r);
}

tool_result_t autoresponder_add_rule(const json& params) {
    std::string mt = params.value("match_type", "prefix_url");
    std::string match_pattern = params.value("match_pattern", "");
    diag::log_tagged_fmt("net_sec", "autoresponder_add_rule entry match_type=%s match_pattern=%s status_code=%u",
        mt.c_str(), match_pattern.c_str(), params.value("status_code", 200u));
    net_security::autoresponder_rule_t rule;
    rule.enabled = params.value("enabled", true);
    rule.priority = params.value("priority", 0);
    if (mt == "exact_url") rule.match_type = net_security::autoresponder_match_type::exact_url;
    else if (mt == "prefix_url") rule.match_type = net_security::autoresponder_match_type::prefix_url;
    else if (mt == "regex_url") rule.match_type = net_security::autoresponder_match_type::regex_url;
    else if (mt == "method_and_url") rule.match_type = net_security::autoresponder_match_type::method_and_url;
    else if (mt == "header_contains") rule.match_type = net_security::autoresponder_match_type::header_contains;
    else if (mt == "body_contains") rule.match_type = net_security::autoresponder_match_type::body_contains;
    else if (mt == "sni_contains") rule.match_type = net_security::autoresponder_match_type::sni_contains;
    else rule.match_type = net_security::autoresponder_match_type::prefix_url;

    rule.match_pattern = params.value("match_pattern", "");
    rule.match_method = params.value("match_method", "");
    rule.status_code = params.value("status_code", 200u);
    rule.status_reason = params.value("status_reason", "");
    rule.response_body = params.value("response_body", "");
    rule.response_file_path = params.value("response_file_path", "");
    rule.latency_ms = params.value("latency_ms", 0u);
    rule.drop_request = params.value("drop_request", false);
    rule.passthrough = params.value("passthrough", false);

    if (params.contains("response_headers") && params["response_headers"].is_object()) {
        for (auto it = params["response_headers"].begin(); it != params["response_headers"].end(); ++it)
            rule.response_headers[it.key()] = it.value().get<std::string>();
    }

    std::uint32_t id = net_security::AutoResponder::instance().add_rule(rule);
    diag::log_tagged_fmt("net_sec", "autoresponder_add_rule rule_id=%u match_type=%s match_pattern=%s", id, mt.c_str(), match_pattern.c_str());
    json r;
    r["rule_id"] = id;
    return tool_result_t::ok(OBFSTR("AutoResponder rule added with ID ") + std::to_string(id), r);
}

tool_result_t autoresponder_remove_rule(const json& params) {
    std::uint32_t rule_id = params.value("rule_id", 0u);
    diag::log_tagged_fmt("net_sec", "autoresponder_remove_rule entry rule_id=%u", rule_id);
    bool removed = net_security::AutoResponder::instance().remove_rule(rule_id);
    diag::log_tagged_fmt("net_sec", "autoresponder_remove_rule removed=%d rule_id=%u", (int)removed, rule_id);
    if (removed) {
        json r;
        r["removed"] = true;
        r["rule_id"] = rule_id;
        return tool_result_t::ok(OBFSTR("Rule removed"), r);
    }
    return tool_result_t::error(OBFSTR("Rule not found"));
}

tool_result_t autoresponder_list_rules(const json&) {
    diag::log_tagged("net_sec", "autoresponder_list_rules entry");
    auto rules = net_security::AutoResponder::instance().list_rules();
    diag::log_tagged_fmt("net_sec", "autoresponder_list_rules count=%zu", rules.size());
    json result;
    result["count"] = rules.size();
    json arr = json::array();
    for (const auto& rule : rules) {
        json rj;
        rj["rule_id"] = rule.rule_id;
        rj["enabled"] = rule.enabled;
        rj["priority"] = rule.priority;
        rj["match_pattern"] = rule.match_pattern;
        rj["match_method"] = rule.match_method;
        rj["status_code"] = rule.status_code;
        rj["match_count"] = rule.match_count;
        rj["drop_request"] = rule.drop_request;
        rj["passthrough"] = rule.passthrough;
        arr.push_back(rj);
    }
    result["rules"] = arr;
    return tool_result_t::ok(OBFSTR("Listed ") + std::to_string(rules.size()) + OBFSTR(" autoresponder rules"), result);
}

tool_result_t autoresponder_start(const json&) {
    diag::log_tagged("net_sec", "autoresponder_start entry");
    bool started = net_security::AutoResponder::instance().start();
    diag::log_tagged_fmt("net_sec", "autoresponder_start started=%d", (int)started);
    if (started) {
        json r;
        r["status"] = "started";
        return tool_result_t::ok(OBFSTR("AutoResponder started"), r);
    }
    return tool_result_t::error(OBFSTR("AutoResponder already running or failed"));
}

tool_result_t autoresponder_stop(const json&) {
    diag::log_tagged("net_sec", "autoresponder_stop entry");
    bool stopped = net_security::AutoResponder::instance().stop();
    diag::log_tagged_fmt("net_sec", "autoresponder_stop stopped=%d", (int)stopped);
    if (stopped) {
        json r;
        r["status"] = "stopped";
        return tool_result_t::ok(OBFSTR("AutoResponder stopped"), r);
    }
    return tool_result_t::error(OBFSTR("AutoResponder is not running"));
}

tool_result_t autoresponder_import_rules(const json& params) {
    std::string rules_json = params.value("rules_json", "");
    diag::log_tagged_fmt("net_sec", "autoresponder_import_rules entry rules_json_len=%zu", rules_json.size());
    if (rules_json.empty()) {
        diag::log_tagged("net_sec", "autoresponder_import_rules rules_json empty -> error");
        return tool_result_t::error(OBFSTR("rules_json is required"));
    }

    bool imported = net_security::AutoResponder::instance().import_rules(rules_json);
    diag::log_tagged_fmt("net_sec", "autoresponder_import_rules imported=%d", (int)imported);
    if (imported) {
        auto count = net_security::AutoResponder::instance().list_rules().size();
        diag::log_tagged_fmt("net_sec", "autoresponder_import_rules total_rules=%zu", count);
        json r;
        r["imported"] = true;
        r["total_rules"] = count;
        return tool_result_t::ok(OBFSTR("Rules imported, total: ") + std::to_string(count), r);
    }
    return tool_result_t::error(OBFSTR("Failed to import rules - invalid JSON"));
}

tool_result_t autoresponder_export_rules(const json& params) {
    diag::log_tagged("net_sec", "autoresponder_export_rules entry");
    std::string exported = net_security::AutoResponder::instance().export_rules();
    const auto count = net_security::AutoResponder::instance().list_rules().size();
    const std::string path = params.value("path", std::string());
    bool wrote_file = false;
    uint64_t file_size = 0;
    std::error_code fs_ec;
    if (!path.empty()) {
        std::filesystem::path out_path(path);
        if (!out_path.parent_path().empty())
            std::filesystem::create_directories(out_path.parent_path(), fs_ec);
        if (!fs_ec) {
            std::ofstream ofs(out_path, std::ios::binary | std::ios::trunc);
            if (ofs) {
                ofs.write(exported.data(), static_cast<std::streamsize>(exported.size()));
                ofs.flush();
                wrote_file = !ofs.fail();
            }
        }
        if (wrote_file) {
            std::error_code size_ec;
            file_size = static_cast<uint64_t>(std::filesystem::file_size(out_path, size_ec));
            if (size_ec)
                file_size = 0;
        }
    }
    diag::log_tagged_fmt("net_sec", "autoresponder_export_rules exported_len=%zu count=%zu path=%s wrote=%d file_size=%llu ec=%lu",
        exported.size(), count, path.c_str(), wrote_file ? 1 : 0,
        static_cast<unsigned long long>(file_size), static_cast<unsigned long>(fs_ec.value()));
    json r;
    r["rules_json"] = exported;
    r["rule_count"] = count;
    r["path"] = path;
    r["wrote_file"] = wrote_file;
    r["file_size"] = file_size;
    r["fs_error"] = fs_ec.value();
    if (!path.empty() && (!wrote_file || file_size == 0)) {
        diag::log_tagged_fmt("net_sec", "autoresponder_export_rules write_failed path=%s wrote=%d file_size=%llu ec=%lu",
            path.c_str(), wrote_file ? 1 : 0,
            static_cast<unsigned long long>(file_size), static_cast<unsigned long>(fs_ec.value()));
        return tool_result_t::error(OBFSTR("AutoResponder rules export file write failed"), r);
    }
    return tool_result_t::ok(OBFSTR("AutoResponder rules exported"), r);
}

#else

tool_result_t tls_extract_keys(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t tls_start_keylog(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t tls_stop_keylog(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t tls_get_extracted_keys(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t cert_inject(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t cert_remove(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t cert_generate_ca(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t cert_list(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t pin_bypass(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t quic_detect_connections(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t quic_decrypt_initial(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t quic_extract_keys(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t dtls_detect_sessions(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t dtls_extract_keys(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_add_rule(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_remove_rule(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_list_rules(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_start(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_stop(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_import_rules(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_export_rules(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t network_decrypt_capture(const json&) { return tool_result_t::error("Not supported on this platform"); }
#endif

void register_net_security_tools(mcp_standalone::server_t& srv) {
    diag::log_tagged("net_sec", "register_net_security_tools entry");

    register_compat(srv, {
        OBFSTR("tls_manage"), OBFSTR("network_security"),
        OBFSTR("Manage TLS key extraction and keylog capture. Actions: extract_keys, start_keylog, stop_keylog, get_extracted_keys."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("extract_keys|start_keylog|stop_keylog|get_extracted_keys"), true},
         {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "extract_keys") return tls_extract_keys(p);
            if (action == "start_keylog") return tls_start_keylog(p);
            if (action == "stop_keylog") return tls_stop_keylog(p);
            if (action == "get_extracted_keys") return tls_get_extracted_keys(p);
            return compat_unknown_action("tls_manage", action);
        },
        false});

    register_compat(srv, {
        OBFSTR("cert_manage"), OBFSTR("network_security"),
        OBFSTR("Manage certificate generation and Windows certificate store operations. Actions: inject, remove, generate_ca, list."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("inject|remove|generate_ca|list"), true},
         {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "inject") return cert_inject(p);
            if (action == "remove") return cert_remove(p);
            if (action == "generate_ca") return cert_generate_ca(p);
            if (action == "list") return cert_list(p);
            return compat_unknown_action("cert_manage", action);
        },
        false});

    register_compat(srv, {
        OBFSTR("pin_bypass"), OBFSTR("network_security"),
        OBFSTR("Run read-only certificate interception diagnostics for a target process. Reports proxy, CA trust, "
               "Camoufox, provider, and handoff readiness; normal builds do not modify target process code."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID (0 = current attached)"), false},
         {OBFSTR("method"), OBFSTR("string"), OBFSTR("Diagnostic focus: 'all', 'wintrust', 'crypt32', 'schannel', 'dotnet' (default: all)"), false},
         {OBFSTR("proxy_running"), OBFSTR("boolean"), OBFSTR("Override proxy route readiness"), false},
         {OBFSTR("ca_trusted"), OBFSTR("boolean"), OBFSTR("Override AiDA CA trust readiness"), false},
         {OBFSTR("interception_still_failing"), OBFSTR("boolean"), OBFSTR("Set when proxy and trust are present but interception still fails"), false}},
        pin_bypass, true});

    register_compat(srv, {
        OBFSTR("quic_manage"), OBFSTR("network_security"),
        OBFSTR("Manage QUIC analysis. Actions: detect_connections, decrypt_initial, extract_keys."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("detect_connections|decrypt_initial|extract_keys"), true},
         {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "detect_connections") return quic_detect_connections(p);
            if (action == "decrypt_initial") return quic_decrypt_initial(p);
            if (action == "extract_keys") return quic_extract_keys(p);
            return compat_unknown_action("quic_manage", action);
        },
        false});

    register_compat(srv, {
        OBFSTR("dtls_manage"), OBFSTR("network_security"),
        OBFSTR("Manage DTLS analysis. Actions: detect_sessions, extract_keys."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("detect_sessions|extract_keys"), true},
         {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "detect_sessions") return dtls_detect_sessions(p);
            if (action == "extract_keys") return dtls_extract_keys(p);
            return compat_unknown_action("dtls_manage", action);
        },
        false});

    register_compat(srv, {
        OBFSTR("autoresponder_manage"), OBFSTR("network_security"),
        OBFSTR("Manage AutoResponder rules and runtime state. Actions: add_rule, remove_rule, list_rules, start, stop, import_rules, export_rules."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("add_rule|remove_rule|list_rules|start|stop|import_rules|export_rules"), true},
         {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "add_rule") return autoresponder_add_rule(p);
            if (action == "remove_rule") return autoresponder_remove_rule(p);
            if (action == "list_rules") return autoresponder_list_rules(p);
            if (action == "start") return autoresponder_start(p);
            if (action == "stop") return autoresponder_stop(p);
            if (action == "import_rules") return autoresponder_import_rules(p);
            if (action == "export_rules") return autoresponder_export_rules(p);
            return compat_unknown_action("autoresponder_manage", action);
        },
        false});

    register_compat(srv, {
        OBFSTR("network_decrypt_capture"), OBFSTR("network_security"),
        OBFSTR("Decrypt a captured PCAP file using TLS session keys and return the decrypted HTTP/2 frames. "
               "Uses tshark (Wireshark CLI) with an SSLKEYLOGFILE to decrypt TLS traffic. "
               "Automatically reads the SSLKEYLOGFILE path from the environment if keylog_path is not specified. "
               "Returns decrypted HTTP/2 request/response headers, methods, URLs, and bodies. "
               "The target process must have been started with SSLKEYLOGFILE set for key logging to work."),
        {{OBFSTR("pcap_path"), OBFSTR("string"), OBFSTR("Path to the PCAP file to decrypt"), true},
         {OBFSTR("keylog_path"), OBFSTR("string"), OBFSTR("Path to the SSLKEYLOGFILE (auto-detected from env if empty)"), false},
         {OBFSTR("display_filter"), OBFSTR("string"), OBFSTR("Wireshark display filter (default: 'http2')"), false}},
        network_decrypt_capture, true});

    diag::log_tagged("net_sec", "register_net_security_tools complete");
}

}
