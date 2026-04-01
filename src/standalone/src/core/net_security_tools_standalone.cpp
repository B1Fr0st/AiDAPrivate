// net_security_tools_standalone.cpp — TLS/certificate/QUIC tools for AiDA Standalone.
// Ported from agent_tools.cpp (DLL) net_security_tools namespace.
// Uses net_security.hpp for TLS key extraction and certificate management,
// and comm.h for kernel-level process memory scanning.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "comm.h"
#include "net_security.hpp"
#include "obfuscation.hpp"
#include "pro.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
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

static std::string ns_get_downloads_folder() {
    char buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA("USERPROFILE", buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH)
        return std::string(buf, len) + "\\Downloads";
    return ".";
}

tool_result_t tls_extract_keys(const json& params) {
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    net_security::tls_key_scan_config_t config;
    config.pid = params.value("pid", 0u);
    config.scan_schannel = params.value("scan_schannel", true);
    config.scan_openssl = params.value("scan_openssl", true);
    config.scan_nss = params.value("scan_nss", true);
    config.scan_boringssl = params.value("scan_boringssl", true);
    config.max_results = params.value("max_results", 64u);

    auto keys = net_security::TlsKeyExtractor::instance().extract_keys(config);
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
        arr.push_back(kj);
    }
    result["keys"] = arr;
    return tool_result_t::ok(OBFSTR("Extracted ") + std::to_string(keys.size()) + OBFSTR(" TLS session keys"), result);
}

tool_result_t tls_start_keylog(const json& params) {
    net_security::keylog_config_t config;
    config.pid = params.value("pid", 0u);
    config.output_file = params.value("output_file", "");
    config.poll_interval_ms = params.value("poll_interval_ms", 2000u);
    config.append = params.value("append", true);

    if (config.output_file.empty()) {
        config.output_file = ns_get_downloads_folder() + "\\sslkeylog.txt";
    }

    if (net_security::TlsKeyExtractor::instance().start_keylog(config)) {
        json r;
        r["status"] = "started";
        r["output_file"] = config.output_file;
        r["poll_interval_ms"] = config.poll_interval_ms;
        return tool_result_t::ok(OBFSTR("TLS keylogging started -> ") + config.output_file, r);
    }
    return tool_result_t::error(OBFSTR("Keylogging already active or failed to start"));
}

tool_result_t tls_stop_keylog(const json&) {
    if (net_security::TlsKeyExtractor::instance().stop_keylog()) {
        json r;
        r["status"] = "stopped";
        return tool_result_t::ok(OBFSTR("TLS keylogging stopped"), r);
    }
    return tool_result_t::error(OBFSTR("No active keylogging session"));
}

tool_result_t tls_get_extracted_keys(const json&) {
    auto& ext = net_security::TlsKeyExtractor::instance();
    auto& seen = ext.get_seen_keys();

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
    net_security::cert_injection_config_t config;
    config.cert_pem = params.value("cert_pem", "");
    config.store_name = params.value("store_name", "ROOT");
    config.system_wide = params.value("system_wide", false);

    if (params.contains("cert_der_hex") && params["cert_der_hex"].is_string()) {
        auto hex = params["cert_der_hex"].get<std::string>();
        config.cert_der = ns_hex_to_bytes(hex);
    }

    auto result = net_security::CertificateInjector::instance().inject_certificate(config);
    json r;
    r["success"] = result.success;
    r["thumbprint"] = result.thumbprint;
    r["subject_cn"] = result.subject_cn;
    r["store_name"] = result.store_name;
    r["method"] = result.method;
    if (result.success)
        return tool_result_t::ok(OBFSTR("Certificate injected: ") + result.subject_cn, r);
    return tool_result_t::error(OBFSTR("Certificate injection failed"));
}

tool_result_t cert_remove(const json& params) {
    std::string thumbprint = params.value("thumbprint", "");
    std::string store_name = params.value("store_name", "ROOT");
    if (thumbprint.empty())
        return tool_result_t::error(OBFSTR("thumbprint is required"));

    if (net_security::CertificateInjector::instance().remove_certificate(thumbprint, store_name)) {
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

    std::vector<std::uint8_t> cert_der, key_der;
    if (net_security::CertificateInjector::instance().generate_ca_certificate(cn, days, cert_der, key_der)) {
        json r;
        r["success"] = true;
        r["cert_der_hex"] = ns_bytes_to_hex(cert_der.data(), cert_der.size());
        r["key_der_hex"] = ns_bytes_to_hex(key_der.data(), key_der.size());
        r["cert_size"] = cert_der.size();
        r["subject_cn"] = cn;
        r["validity_days"] = days;
        return tool_result_t::ok(OBFSTR("Generated CA certificate: ") + cn, r);
    }
    return tool_result_t::error(OBFSTR("Failed to generate CA certificate"));
}

tool_result_t cert_list(const json& params) {
    std::string store_name = params.value("store_name", "ROOT");
    auto certs = net_security::CertificateInjector::instance().list_certificates(store_name);

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
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    net_security::pin_bypass_config_t config;
    config.pid = params.value("pid", 0u);
    std::string method = params.value("method", "all");
    if (method == "wintrust") config.method = net_security::pin_bypass_method::patch_wintrust;
    else if (method == "crypt32") config.method = net_security::pin_bypass_method::patch_crypt32;
    else if (method == "schannel") config.method = net_security::pin_bypass_method::patch_schannel;
    else if (method == "chrome") config.method = net_security::pin_bypass_method::patch_chrome_pins;
    else if (method == "dotnet") config.method = net_security::pin_bypass_method::patch_dotnet_callback;
    else config.method = net_security::pin_bypass_method::all;

    auto result = net_security::CertPinBypasser::instance().bypass_pins(config);
    json r;
    r["success"] = result.success;
    r["patches_applied"] = result.patches_applied;
    r["patches_failed"] = result.patches_failed;
    if (result.success)
        return tool_result_t::ok(OBFSTR("Pin bypass applied: ") + std::to_string(result.patches_applied.size()) + OBFSTR(" patches"), r);
    return tool_result_t::error(OBFSTR("Pin bypass failed for all methods"));
}

tool_result_t pin_bypass_revert(const json& params) {
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t pid = params.value("pid", 0u);
    if (pid == 0) pid = device->get_process_id();

    if (net_security::CertPinBypasser::instance().revert_bypass(pid)) {
        json r;
        r["reverted"] = true;
        r["pid"] = pid;
        return tool_result_t::ok(OBFSTR("Pin bypass reverted for PID ") + std::to_string(pid), r);
    }
    return tool_result_t::error(OBFSTR("No active bypass to revert for this PID"));
}

tool_result_t pin_bypass_status(const json& params) {
    std::uint32_t pid = params.value("pid", 0u);
    if (pid == 0 && device && device->is_connected()) pid = device->get_process_id();
    bool active = net_security::CertPinBypasser::instance().is_bypass_active(pid);
    json r;
    r["pid"] = pid;
    r["bypass_active"] = active;
    return tool_result_t::ok(active ? OBFSTR("Pin bypass is ACTIVE") : OBFSTR("No active pin bypass"), r);
}

tool_result_t quic_detect_connections(const json& params) {
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t pid = params.value("pid", 0u);
    auto conns = net_security::QuicAnalyzer::instance().detect_quic_connections(pid);

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
    if (!params.contains("packet_hex"))
        return tool_result_t::error(OBFSTR("packet_hex is required"));

    auto pkt_bytes = ns_hex_to_bytes(params["packet_hex"].get<std::string>());
    if (pkt_bytes.empty())
        return tool_result_t::error(OBFSTR("Invalid packet hex data"));

    auto result = net_security::QuicAnalyzer::instance().decrypt_initial_packet(pkt_bytes.data(), pkt_bytes.size());
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
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t pid = params.value("pid", 0u);
    auto keys = net_security::QuicAnalyzer::instance().extract_quic_traffic_keys(pid);

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
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t pid = params.value("pid", 0u);
    auto sessions = net_security::DtlsAnalyzer::instance().detect_dtls_sessions(pid);

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
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t pid = params.value("pid", 0u);
    auto keys = net_security::TlsKeyExtractor::instance().extract_dtls_keys(pid);

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

    if (pcap_path.empty())
        return tool_result_t::error(OBFSTR("pcap_path is required"));


    if (keylog_path.empty()) {
        char buf[MAX_PATH] = {};
        DWORD len = GetEnvironmentVariableA("SSLKEYLOGFILE", buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) keylog_path = std::string(buf, len);
    }
    if (keylog_path.empty())
        return tool_result_t::error(OBFSTR("keylog_path is required (or set SSLKEYLOGFILE environment variable)"));

    auto decrypt_result = net_security::TlsKeyExtractor::instance().decrypt_pcap_with_tshark(
        pcap_path, keylog_path, display_filter);

    json r;
    r["success"] = decrypt_result.success;
    r["pcap_file"] = decrypt_result.pcap_file_used;
    r["keylog_file"] = decrypt_result.keylog_file_used;
    r["total_packets"] = decrypt_result.total_packets;
    r["decrypted_packets"] = decrypt_result.decrypted_packets;

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
        OBFSTR("Decryption failed - no matching packets found") : decrypt_result.error_message);
}

tool_result_t tls_ensure_keylogfile(const json& params) {
    std::string path = params.value("path", "");
    if (net_security::TlsKeyExtractor::instance().ensure_sslkeylogfile_env(path)) {
        char buf[MAX_PATH] = {};
        DWORD len = GetEnvironmentVariableA("SSLKEYLOGFILE", buf, MAX_PATH);
        json r;
        r["status"] = "configured";
        r["path"] = (len > 0) ? std::string(buf, len) : path;
        r["note"] = "SSLKEYLOGFILE set at user level. Newly started processes (browsers, VS Code, etc.) "
                    "will log TLS session keys to this file. Restart the target application for it to take effect.";
        return tool_result_t::ok(OBFSTR("SSLKEYLOGFILE configured"), r);
    }
    return tool_result_t::error(OBFSTR("Failed to set SSLKEYLOGFILE environment variable"));
}

tool_result_t autoresponder_add_rule(const json& params) {
    net_security::autoresponder_rule_t rule;
    rule.enabled = params.value("enabled", true);
    rule.priority = params.value("priority", 0);

    std::string mt = params.value("match_type", "prefix_url");
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
    json r;
    r["rule_id"] = id;
    return tool_result_t::ok(OBFSTR("AutoResponder rule added with ID ") + std::to_string(id), r);
}

tool_result_t autoresponder_remove_rule(const json& params) {
    std::uint32_t rule_id = params.value("rule_id", 0u);
    if (net_security::AutoResponder::instance().remove_rule(rule_id)) {
        json r;
        r["removed"] = true;
        r["rule_id"] = rule_id;
        return tool_result_t::ok(OBFSTR("Rule removed"), r);
    }
    return tool_result_t::error(OBFSTR("Rule not found"));
}

tool_result_t autoresponder_list_rules(const json&) {
    auto rules = net_security::AutoResponder::instance().list_rules();
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
    if (net_security::AutoResponder::instance().start()) {
        json r;
        r["status"] = "started";
        return tool_result_t::ok(OBFSTR("AutoResponder started"), r);
    }
    return tool_result_t::error(OBFSTR("AutoResponder already running or failed"));
}

tool_result_t autoresponder_stop(const json&) {
    if (net_security::AutoResponder::instance().stop()) {
        json r;
        r["status"] = "stopped";
        return tool_result_t::ok(OBFSTR("AutoResponder stopped"), r);
    }
    return tool_result_t::error(OBFSTR("AutoResponder is not running"));
}

tool_result_t autoresponder_import_rules(const json& params) {
    std::string rules_json = params.value("rules_json", "");
    if (rules_json.empty())
        return tool_result_t::error(OBFSTR("rules_json is required"));

    if (net_security::AutoResponder::instance().import_rules(rules_json)) {
        auto count = net_security::AutoResponder::instance().list_rules().size();
        json r;
        r["imported"] = true;
        r["total_rules"] = count;
        return tool_result_t::ok(OBFSTR("Rules imported, total: ") + std::to_string(count), r);
    }
    return tool_result_t::error(OBFSTR("Failed to import rules - invalid JSON"));
}

tool_result_t autoresponder_export_rules(const json&) {
    std::string exported = net_security::AutoResponder::instance().export_rules();
    json r;
    r["rules_json"] = exported;
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
tool_result_t pin_bypass_revert(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t pin_bypass_status(const json&) { return tool_result_t::error("Not supported on this platform"); }
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
tool_result_t tls_ensure_keylogfile(const json&) { return tool_result_t::error("Not supported on this platform"); }
#endif

void register_net_security_tools(mcp_standalone::server_t& srv) {
    

    register_compat(srv, {
        OBFSTR("tls_extract_keys"), OBFSTR("network_security"),
        OBFSTR("Extract TLS session keys from a target process by scanning memory for SChannel, OpenSSL, NSS, and BoringSSL key material. "
               "Returns CLIENT_RANDOM + master_secret pairs compatible with Wireshark SSLKEYLOGFILE format. "
               "Supports TLS 1.0-1.3. For TLS 1.3, also extracts handshake and traffic secrets."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID (0 = current attached process)"), false},
         {OBFSTR("scan_schannel"), OBFSTR("boolean"), OBFSTR("Scan for Windows SChannel keys (default: true)"), false},
         {OBFSTR("scan_openssl"), OBFSTR("boolean"), OBFSTR("Scan for OpenSSL keys (default: true)"), false},
         {OBFSTR("scan_nss"), OBFSTR("boolean"), OBFSTR("Scan for NSS/Firefox keys (default: true)"), false},
         {OBFSTR("scan_boringssl"), OBFSTR("boolean"), OBFSTR("Scan for BoringSSL/Chrome keys (default: true)"), false},
         {OBFSTR("max_results"), OBFSTR("number"), OBFSTR("Maximum keys to return (default: 64)"), false}},
        tls_extract_keys, true});

    register_compat(srv, {
        OBFSTR("tls_start_keylog"), OBFSTR("network_security"),
        OBFSTR("Start continuous TLS session key logging to a file (SSLKEYLOGFILE format). "
               "Periodically scans the target process for new keys and appends them. "
               "Output file can be loaded in Wireshark for live decryption."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID"), false},
         {OBFSTR("output_file"), OBFSTR("string"), OBFSTR("Output file path (default: Downloads/sslkeylog.txt)"), false},
         {OBFSTR("poll_interval_ms"), OBFSTR("number"), OBFSTR("Polling interval in ms (default: 2000)"), false},
         {OBFSTR("append"), OBFSTR("boolean"), OBFSTR("Append to existing file (default: true)"), false}},
        tls_start_keylog, false});

    register_compat(srv, {
        OBFSTR("tls_stop_keylog"), OBFSTR("network_security"),
        OBFSTR("Stop the active TLS session key logging thread."),
        {},
        tls_stop_keylog, false});

    register_compat(srv, {
        OBFSTR("tls_get_extracted_keys"), OBFSTR("network_security"),
        OBFSTR("Get all TLS session keys extracted so far from the cache. Keys persist across multiple scan operations."),
        {},
        tls_get_extracted_keys, true});

    register_compat(srv, {
        OBFSTR("cert_inject"), OBFSTR("network_security"),
        OBFSTR("Inject a certificate into the Windows certificate store. Supports PEM or DER format. "
               "Can inject into user or system stores (ROOT, CA, MY, etc.). "
               "Useful for MITM/proxy setups where a custom CA certificate needs to be trusted."),
        {{OBFSTR("cert_pem"), OBFSTR("string"), OBFSTR("PEM-encoded certificate string"), false},
         {OBFSTR("cert_der_hex"), OBFSTR("string"), OBFSTR("DER-encoded certificate as hex string"), false},
         {OBFSTR("store_name"), OBFSTR("string"), OBFSTR("Certificate store name (default: ROOT)"), false},
         {OBFSTR("system_wide"), OBFSTR("boolean"), OBFSTR("Install system-wide vs current user (default: false)"), false}},
        cert_inject, false});

    register_compat(srv, {
        OBFSTR("cert_remove"), OBFSTR("network_security"),
        OBFSTR("Remove a certificate from the Windows certificate store by its SHA-1 thumbprint."),
        {{OBFSTR("thumbprint"), OBFSTR("string"), OBFSTR("SHA-1 thumbprint of the certificate to remove"), true},
         {OBFSTR("store_name"), OBFSTR("string"), OBFSTR("Certificate store name (default: ROOT)"), false}},
        cert_remove, false});

    register_compat(srv, {
        OBFSTR("cert_generate_ca"), OBFSTR("network_security"),
        OBFSTR("Generate a self-signed CA certificate with a 2048-bit RSA key pair. "
               "Returns the certificate and private key in DER format (hex-encoded). "
               "The CA certificate can then be injected into the trust store for MITM purposes."),
        {{OBFSTR("cn"), OBFSTR("string"), OBFSTR("Common Name for the CA (default: 'AiDA Proxy CA')"), false},
         {OBFSTR("validity_days"), OBFSTR("number"), OBFSTR("Validity period in days (default: 3650)"), false}},
        cert_generate_ca, false});

    register_compat(srv, {
        OBFSTR("cert_list"), OBFSTR("network_security"),
        OBFSTR("List all certificates in a Windows certificate store. Shows subject, issuer, thumbprint, validity dates, and CA status."),
        {{OBFSTR("store_name"), OBFSTR("string"), OBFSTR("Store name: ROOT, CA, MY, TrustedPeople, etc. (default: ROOT)"), false}},
        cert_list, true});

    register_compat(srv, {
        OBFSTR("pin_bypass"), OBFSTR("network_security"),
        OBFSTR("Bypass certificate pinning in a target process by patching validation functions in memory. "
               "Supports WinVerifyTrust, CertVerifyCertificateChainPolicy (crypt32), SChannel validation, "
               "Chrome/Edge public key pins, and .NET certificate callbacks. Reverted on session end."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID (0 = current attached)"), false},
         {OBFSTR("method"), OBFSTR("string"), OBFSTR("Bypass method: 'all', 'wintrust', 'crypt32', 'schannel', 'chrome', 'dotnet' (default: all)"), false}},
        pin_bypass, false});

    register_compat(srv, {
        OBFSTR("pin_bypass_revert"), OBFSTR("network_security"),
        OBFSTR("Revert all certificate pinning bypass patches for a target process, restoring original function prologues."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID"), false}},
        pin_bypass_revert, false});

    register_compat(srv, {
        OBFSTR("pin_bypass_status"), OBFSTR("network_security"),
        OBFSTR("Check if certificate pin bypass is currently active for a process."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID (0 = current)"), false}},
        pin_bypass_status, true});

    register_compat(srv, {
        OBFSTR("quic_detect_connections"), OBFSTR("network_security"),
        OBFSTR("Detect active QUIC/HTTP3 connections by analyzing captured UDP packets for QUIC headers. "
               "Parses long and short QUIC headers, extracts connection IDs, and tracks packet counts."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by process ID (0 = all)"), false}},
        quic_detect_connections, true});

    register_compat(srv, {
        OBFSTR("quic_decrypt_initial"), OBFSTR("network_security"),
        OBFSTR("Decrypt a QUIC Initial packet. Initial packets use deterministic key derivation from the "
               "Destination Connection ID, requiring no secret material. Parses header, extracts versions and CIDs."),
        {{OBFSTR("packet_hex"), OBFSTR("string"), OBFSTR("Raw QUIC packet data as hex string"), true}},
        quic_decrypt_initial, true});

    register_compat(srv, {
        OBFSTR("quic_extract_keys"), OBFSTR("network_security"),
        OBFSTR("Extract QUIC traffic encryption keys from a process. Scans for TLS 1.3 traffic secrets "
               "used by QUIC implementations (msquic, BoringSSL). Keys enable full QUIC payload decryption."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID"), false}},
        quic_extract_keys, true});

    register_compat(srv, {
        OBFSTR("dtls_detect_sessions"), OBFSTR("network_security"),
        OBFSTR("Detect active DTLS sessions by analyzing captured UDP packets for DTLS record headers. "
               "Identifies DTLS versions (1.0/1.2), handshake state, epochs, and sequence numbers."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by process ID (0 = all)"), false}},
        dtls_detect_sessions, true});

    register_compat(srv, {
        OBFSTR("dtls_extract_keys"), OBFSTR("network_security"),
        OBFSTR("Extract DTLS session keys from a process. Scans memory for DTLS version markers adjacent to "
               "client_random and master_secret pairs. Supports DTLS 1.0 (0xFEFF) and DTLS 1.2 (0xFEFD)."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID"), false}},
        dtls_extract_keys, true});

    register_compat(srv, {
        OBFSTR("autoresponder_add_rule"), OBFSTR("network_security"),
        OBFSTR("Add an AutoResponder rule (similar to Fiddler's AutoResponder). Rules match intercepted HTTP requests "
               "by URL pattern, method, headers, or body content, and return custom responses. For HTTPS/TLS traffic, "
               "use match_type 'sni_contains' to match on the TLS Server Name Indication (domain). "
               "Supports exact, prefix, regex URL matching, SNI matching, custom status codes, headers, response bodies, and file-based responses."),
        {{OBFSTR("match_type"), OBFSTR("string"), OBFSTR("Match type: exact_url, prefix_url, regex_url, method_and_url, header_contains, body_contains, sni_contains (for HTTPS)"), false},
         {OBFSTR("match_pattern"), OBFSTR("string"), OBFSTR("Pattern to match against"), true},
         {OBFSTR("match_method"), OBFSTR("string"), OBFSTR("HTTP method filter (e.g., GET, POST)"), false},
         {OBFSTR("status_code"), OBFSTR("number"), OBFSTR("HTTP status code for the response (default: 200)"), false},
         {OBFSTR("status_reason"), OBFSTR("string"), OBFSTR("HTTP status reason phrase"), false},
         {OBFSTR("response_body"), OBFSTR("string"), OBFSTR("Response body content"), false},
         {OBFSTR("response_file_path"), OBFSTR("string"), OBFSTR("File path to serve as response body"), false},
         {OBFSTR("response_headers"), OBFSTR("object"), OBFSTR("Custom response headers as key-value pairs"), false},
         {OBFSTR("priority"), OBFSTR("number"), OBFSTR("Rule priority (lower = higher priority, default: 0)"), false},
         {OBFSTR("latency_ms"), OBFSTR("number"), OBFSTR("Artificial response latency in ms"), false},
         {OBFSTR("drop_request"), OBFSTR("boolean"), OBFSTR("Drop the request silently (default: false)"), false},
         {OBFSTR("passthrough"), OBFSTR("boolean"), OBFSTR("Let the request pass through unmodified (default: false)"), false},
         {OBFSTR("enabled"), OBFSTR("boolean"), OBFSTR("Enable the rule (default: true)"), false}},
        autoresponder_add_rule, false});

    register_compat(srv, {
        OBFSTR("autoresponder_remove_rule"), OBFSTR("network_security"),
        OBFSTR("Remove an AutoResponder rule by its ID."),
        {{OBFSTR("rule_id"), OBFSTR("number"), OBFSTR("Rule ID to remove"), true}},
        autoresponder_remove_rule, false});

    register_compat(srv, {
        OBFSTR("autoresponder_list_rules"), OBFSTR("network_security"),
        OBFSTR("List all AutoResponder rules with their match patterns, status codes, and hit counts."),
        {},
        autoresponder_list_rules, true});

    register_compat(srv, {
        OBFSTR("autoresponder_start"), OBFSTR("network_security"),
        OBFSTR("Start the AutoResponder engine. Automatically enables packet capture and interception. "
               "Monitors both HTTP (plaintext) and HTTPS (via TLS SNI extraction) traffic. "
               "Works on any network interface including WiFi. Use sni_contains rules for HTTPS domain blocking."),
        {},
        autoresponder_start, false});

    register_compat(srv, {
        OBFSTR("autoresponder_stop"), OBFSTR("network_security"),
        OBFSTR("Stop the AutoResponder engine."),
        {},
        autoresponder_stop, false});

    register_compat(srv, {
        OBFSTR("autoresponder_import_rules"), OBFSTR("network_security"),
        OBFSTR("Import AutoResponder rules from a JSON array string. Each rule object should have match_type, match_pattern, "
               "status_code, response_body, response_headers, and other fields."),
        {{OBFSTR("rules_json"), OBFSTR("string"), OBFSTR("JSON array of rule objects"), true}},
        autoresponder_import_rules, false});

    register_compat(srv, {
        OBFSTR("autoresponder_export_rules"), OBFSTR("network_security"),
        OBFSTR("Export all AutoResponder rules as a JSON array string. Can be saved and re-imported later."),
        {},
        autoresponder_export_rules, true});

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

    register_compat(srv, {
        OBFSTR("tls_ensure_keylogfile"), OBFSTR("network_security"),
        OBFSTR("Ensure the SSLKEYLOGFILE environment variable is set at the user level so that all newly launched "
               "Chromium-based browsers, VS Code, Electron apps, and other BoringSSL/OpenSSL applications "
               "will log TLS session keys to a file. The target application must be RESTARTED after this is set. "
               "Once set, use tls_extract_keys or network_decrypt_capture to read the logged keys and decrypt traffic."),
        {{OBFSTR("path"), OBFSTR("string"), OBFSTR("File path for the keylog file (default: %USERPROFILE%\\sslkeys.log)"), false}},
        tls_ensure_keylogfile, false});
}

}

