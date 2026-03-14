#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <functional>
#include <chrono>
#include <regex>
#include <fstream>
#include <thread>

#ifdef __NT__
#include <windows.h>
#endif

namespace net_security {

// ============================================================
// TLS Key Extraction Structures
// ============================================================

struct tls_session_key_t {
    std::string label;              // e.g. "CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
    std::vector<std::uint8_t> client_random;   // 32 bytes
    std::vector<std::uint8_t> secret;          // master secret or derived secret
    std::uint16_t tls_version = 0; // detected TLS version
    std::uint64_t timestamp = 0;   // extraction time
    std::uint32_t pid = 0;         // source process
    std::string library;           // "SChannel", "OpenSSL", "NSS", "BoringSSL", etc.
};

struct tls_key_scan_config_t {
    std::uint32_t pid = 0;         // target process (0 for attached)
    bool scan_schannel = true;     // scan for Windows SChannel structures
    bool scan_openssl = true;      // scan for OpenSSL SSL_SESSION
    bool scan_nss = true;          // scan for NSS/Firefox structures
    bool scan_boringssl = true;    // scan for BoringSSL (Chrome) structures
    std::uint32_t max_results = 64;
};

// ============================================================
// Certificate Injection Structures
// ============================================================

struct cert_injection_config_t {
    std::uint32_t pid = 0;         // target process
    std::vector<std::uint8_t> cert_der; // DER-encoded certificate to inject
    std::string cert_pem;          // PEM-encoded cert (alternative)
    std::string store_name;        // "ROOT", "MY", "CA", etc.
    bool system_wide = false;      // inject into system store vs process store
};

struct cert_injection_result_t {
    bool success = false;
    std::string thumbprint;
    std::string subject_cn;
    std::string store_name;
    std::string method;
};

// ============================================================
// Certificate Pin Bypass Structures
// ============================================================

enum class pin_bypass_method {
    patch_wintrust,         // Patch WinVerifyTrust
    patch_crypt32,          // Patch CertVerifyCertificateChainPolicy
    patch_schannel,         // Patch SChannel validation
    patch_chrome_pins,      // Bypass Chrome HPKP/CT
    patch_dotnet_callback,  // .NET ServicePointManager callback
    all                     // Apply all available patches
};

struct pin_bypass_config_t {
    std::uint32_t pid = 0;
    pin_bypass_method method = pin_bypass_method::all;
    bool persistent = false;       // re-apply on DLL load
};

struct pin_bypass_result_t {
    bool success = false;
    std::vector<std::string> patches_applied;
    std::vector<std::string> patches_failed;
};

// ============================================================
// TLS Session Key Logger
// ============================================================

struct keylog_config_t {
    std::uint32_t pid = 0;
    std::string output_file;       // path for SSLKEYLOGFILE output
    std::uint32_t poll_interval_ms = 500;
    bool append = true;
    bool log_tls12 = true;
    bool log_tls13 = true;
};

// ============================================================
// QUIC / HTTP3 Structures
// ============================================================

struct quic_connection_info_t {
    std::uint32_t pid = 0;
    std::uint8_t src_addr[16] = {};
    std::uint8_t dst_addr[16] = {};
    std::uint32_t src_port = 0;
    std::uint32_t dst_port = 0;
    std::uint32_t address_family = 2; // AF_INET
    std::uint8_t version[4] = {};  // QUIC version
    std::vector<std::uint8_t> dcid; // destination connection ID
    std::vector<std::uint8_t> scid; // source connection ID
    std::uint64_t packets_sent = 0;
    std::uint64_t packets_recv = 0;
    std::uint64_t bytes_sent = 0;
    std::uint64_t bytes_recv = 0;
    std::string alpn;              // "h3", "h3-29", etc.
    std::uint16_t tls_version = 0;
};

struct quic_key_info_t {
    std::string label;             // "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET", etc.
    std::vector<std::uint8_t> client_random;
    std::vector<std::uint8_t> secret;
    std::uint32_t pid = 0;
    std::string library;           // "msquic", "quiche", "ngtcp2", etc.
};

struct quic_initial_decrypt_result_t {
    bool success = false;
    std::uint32_t quic_version = 0;
    std::vector<std::uint8_t> dcid;
    std::vector<std::uint8_t> scid;
    std::string packet_type;
    std::uint64_t packet_number = 0;
    std::vector<std::uint8_t> decrypted_payload;
    std::string crypto_frame_hex;
};

// ============================================================
// DTLS Structures
// ============================================================

struct dtls_session_info_t {
    std::uint32_t pid = 0;
    std::uint8_t src_addr[16] = {};
    std::uint8_t dst_addr[16] = {};
    std::uint32_t src_port = 0;
    std::uint32_t dst_port = 0;
    std::uint32_t address_family = 2;
    std::uint16_t dtls_version = 0; // 0xFEFF = 1.0, 0xFEFD = 1.2
    std::uint16_t epoch = 0;
    std::uint64_t sequence_number = 0;
    std::uint8_t content_type = 0;
    std::vector<std::uint8_t> payload;
    std::string state; // "handshake", "established", "closing"
};

struct dtls_key_info_t {
    std::uint16_t dtls_version = 0;
    std::vector<std::uint8_t> client_random;
    std::vector<std::uint8_t> master_secret;
    std::uint32_t pid = 0;
    std::string library;
};

// ============================================================
// AutoResponder Structures
// ============================================================

enum class autoresponder_match_type {
    exact_url,
    prefix_url,
    regex_url,
    method_and_url,
    header_contains,
    body_contains
};

struct autoresponder_rule_t {
    std::uint32_t rule_id = 0;
    bool enabled = true;
    int priority = 0;              // lower = higher priority

    // Match criteria
    autoresponder_match_type match_type = autoresponder_match_type::prefix_url;
    std::string match_pattern;     // URL pattern, regex, or header value
    std::string match_method;      // optional HTTP method filter

    // Response definition
    std::uint32_t status_code = 200;
    std::string status_reason;
    std::map<std::string, std::string> response_headers;
    std::string response_body;
    std::string response_file_path; // serve from file if set

    // Behavior
    std::uint32_t latency_ms = 0;  // artificial delay before response
    bool drop_request = false;     // silently drop instead of responding
    bool passthrough = false;      // log but forward to real server
    std::uint64_t match_count = 0;
    std::uint64_t last_match_time = 0;
};

// ============================================================
// TLS Key Extraction Engine
// ============================================================

class TlsKeyExtractor {
public:
    static TlsKeyExtractor& instance();

    // Extract TLS session keys from a process's memory
    std::vector<tls_session_key_t> extract_keys(const tls_key_scan_config_t& config);

    // Extract QUIC keys from process memory
    std::vector<quic_key_info_t> extract_quic_keys(std::uint32_t pid);

    // Extract DTLS keys from process memory
    std::vector<dtls_key_info_t> extract_dtls_keys(std::uint32_t pid);

    // Write keys to SSLKEYLOGFILE format
    bool write_keylog_file(const std::string& path, const std::vector<tls_session_key_t>& keys, bool append);

    // Start continuous key logging
    bool start_keylog(const keylog_config_t& config);
    bool stop_keylog();
    bool is_keylogging() const { return _keylog_active.load(); }

    // Access cached extracted keys
    const std::map<std::string, tls_session_key_t>& get_seen_keys() const { return _seen_keys; }

private:
    TlsKeyExtractor() = default;

    // SChannel key extraction (Windows native TLS)
    std::vector<tls_session_key_t> scan_schannel(std::uint32_t pid);

    // OpenSSL key extraction
    std::vector<tls_session_key_t> scan_openssl(std::uint32_t pid);

    // NSS key extraction (Firefox)
    std::vector<tls_session_key_t> scan_nss(std::uint32_t pid);

    // BoringSSL key extraction (Chrome/Edge)
    std::vector<tls_session_key_t> scan_boringssl(std::uint32_t pid);

    // Pattern-based key scanning
    std::vector<tls_session_key_t> scan_generic_patterns(std::uint32_t pid);

    // Memory scanning helpers
    bool find_module_in_process(std::uint32_t pid, const char* module_name,
                                std::uint64_t& base, std::uint32_t& size);
    std::vector<std::uint64_t> scan_for_pattern(std::uint32_t pid, std::uint64_t start,
                                                 std::uint64_t size, const std::uint8_t* pattern,
                                                 const std::uint8_t* mask, std::size_t pattern_len);
    bool read_process_memory(std::uint32_t pid, std::uint64_t address, void* buffer, std::size_t size);
    bool validate_client_random(const std::uint8_t* data, std::size_t len);
    bool validate_master_secret(const std::uint8_t* data, std::size_t len);

    std::mutex _mutex;
    std::atomic<bool> _keylog_active{false};
    std::thread _keylog_thread;
    keylog_config_t _keylog_config;
    std::map<std::string, tls_session_key_t> _seen_keys; // dedup by client_random hex
};

// ============================================================
// Certificate Injection Engine
// ============================================================

class CertificateInjector {
public:
    static CertificateInjector& instance();

    // Inject a CA certificate into target's trust store
    cert_injection_result_t inject_certificate(const cert_injection_config_t& config);

    // Remove a previously injected certificate
    bool remove_certificate(const std::string& thumbprint, const std::string& store_name);

    // Generate a self-signed CA certificate (DER + private key)
    bool generate_ca_certificate(const std::string& cn, std::uint32_t validity_days,
                                 std::vector<std::uint8_t>& out_cert_der,
                                 std::vector<std::uint8_t>& out_key_der);

    // List certificates in a store
    struct cert_info_t {
        std::string thumbprint;
        std::string subject;
        std::string issuer;
        std::string not_before;
        std::string not_after;
        bool is_ca = false;
    };
    std::vector<cert_info_t> list_certificates(const std::string& store_name);

    // Get list of injected certificates (tracked)
    const std::vector<std::string>& get_injected_thumbprints() const { return _injected; }

private:
    CertificateInjector() = default;
    std::vector<std::string> _injected;
    mutable std::mutex _mutex;
};

// ============================================================
// Certificate Pin Bypass Engine
// ============================================================

class CertPinBypasser {
public:
    static CertPinBypasser& instance();

    // Apply certificate pinning bypass to a process
    pin_bypass_result_t bypass_pins(const pin_bypass_config_t& config);

    // Revert pinning bypass
    bool revert_bypass(std::uint32_t pid);

    // Check if bypass is active for a process
    bool is_bypass_active(std::uint32_t pid) const;

private:
    CertPinBypasser() = default;

    bool patch_wintrust(std::uint32_t pid);
    bool patch_crypt32(std::uint32_t pid);
    bool patch_schannel_validation(std::uint32_t pid);
    bool patch_chrome_pins(std::uint32_t pid);
    bool patch_dotnet_callback(std::uint32_t pid);

    // Store original bytes for revert
    struct patch_record_t {
        std::uint64_t address;
        std::vector<std::uint8_t> original_bytes;
        std::string description;
    };

    mutable std::mutex _mutex;
    std::map<std::uint32_t, std::vector<patch_record_t>> _active_patches;
};

// ============================================================
// QUIC/HTTP3 Analyzer
// ============================================================

class QuicAnalyzer {
public:
    static QuicAnalyzer& instance();

    // Detect QUIC connections from captured UDP traffic
    std::vector<quic_connection_info_t> detect_quic_connections(std::uint32_t filter_pid = 0);

    // Decrypt QUIC Initial packet using connection ID
    quic_initial_decrypt_result_t decrypt_initial_packet(
        const std::uint8_t* packet_data, std::size_t packet_len);

    // Extract QUIC traffic keys from process memory
    std::vector<quic_key_info_t> extract_quic_traffic_keys(std::uint32_t pid);

    // Parse QUIC packet header (long/short)
    struct quic_header_t {
        bool is_long_header = false;
        std::uint8_t packet_type = 0; // 0=Initial, 1=0-RTT, 2=Handshake, 3=Retry
        std::uint32_t version = 0;
        std::vector<std::uint8_t> dcid;
        std::vector<std::uint8_t> scid;
        std::uint32_t token_length = 0;
        std::uint32_t payload_length = 0;
    };
    bool parse_quic_header(const std::uint8_t* data, std::size_t len, quic_header_t& out);

private:
    QuicAnalyzer() = default;

    // QUIC Initial packet crypto
    bool derive_initial_keys(const std::uint8_t* dcid, std::size_t dcid_len,
                             std::uint32_t version,
                             std::uint8_t* client_key, std::uint8_t* client_iv, std::uint8_t* client_hp,
                             std::uint8_t* server_key, std::uint8_t* server_iv, std::uint8_t* server_hp);

    std::mutex _mutex;
};

// ============================================================
// DTLS Analyzer
// ============================================================

class DtlsAnalyzer {
public:
    static DtlsAnalyzer& instance();

    // Detect DTLS sessions from captured UDP traffic
    std::vector<dtls_session_info_t> detect_dtls_sessions(std::uint32_t filter_pid = 0);

    // Extract DTLS session keys from process memory
    std::vector<dtls_key_info_t> extract_dtls_keys(std::uint32_t pid);

    // Parse a DTLS record header
    struct dtls_record_t {
        std::uint8_t content_type = 0;
        std::uint16_t version = 0;
        std::uint16_t epoch = 0;
        std::uint64_t sequence = 0;
        std::uint16_t length = 0;
        bool is_handshake = false;
        std::uint8_t handshake_type = 0;
    };
    bool parse_dtls_record(const std::uint8_t* data, std::size_t len, dtls_record_t& out);

private:
    DtlsAnalyzer() = default;
    std::mutex _mutex;
};

// ============================================================
// AutoResponder Engine
// ============================================================

class AutoResponder {
public:
    static AutoResponder& instance();

    // Rule management
    std::uint32_t add_rule(const autoresponder_rule_t& rule);
    bool update_rule(std::uint32_t rule_id, const autoresponder_rule_t& rule);
    bool remove_rule(std::uint32_t rule_id);
    bool enable_rule(std::uint32_t rule_id, bool enabled);
    void clear_rules();
    std::vector<autoresponder_rule_t> list_rules() const;
    const autoresponder_rule_t* get_rule(std::uint32_t rule_id) const;

    // Engine control
    bool start();
    bool stop();
    bool is_active() const { return _active.load(); }

    // Match a request against rules
    struct match_result_t {
        bool matched = false;
        std::uint32_t rule_id = 0;
        std::string response_status_line;
        std::string response_headers_str;
        std::string response_body;
    };
    match_result_t match_request(const std::string& method, const std::string& url,
                                 const std::map<std::string, std::string>& headers,
                                 const std::string& body);

    // Import/Export rules (JSON format)
    bool import_rules(const std::string& json_str);
    std::string export_rules() const;

private:
    AutoResponder() = default;

    bool match_pattern(const autoresponder_rule_t& rule, const std::string& method,
                       const std::string& url, const std::map<std::string, std::string>& headers,
                       const std::string& body);
    std::string build_response(const autoresponder_rule_t& rule);

    mutable std::mutex _mutex;
    std::map<std::uint32_t, autoresponder_rule_t> _rules;
    std::uint32_t _next_rule_id = 1;
    std::atomic<bool> _active{false};
    std::thread _responder_thread;
};

} // namespace net_security
