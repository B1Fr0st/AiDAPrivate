#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <condition_variable>
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


struct tls_session_key_t {
    std::string label;
    std::vector<std::uint8_t> client_random;
    std::vector<std::uint8_t> secret;
    std::uint16_t tls_version = 0;
    std::uint64_t timestamp = 0;
    std::uint32_t pid = 0;
    std::string library;
};

struct tls_key_scan_config_t {
    std::uint32_t pid = 0;
    bool scan_schannel = true;
    bool scan_openssl = true;
    bool scan_nss = true;
    bool scan_boringssl = true;
    std::uint32_t max_results = 64;
};


struct cert_injection_config_t {
    std::uint32_t pid = 0;
    std::vector<std::uint8_t> cert_der;
    std::string cert_pem;
    std::string store_name;
    bool system_wide = false;
};

struct cert_injection_result_t {
    bool success = false;
    std::string thumbprint;
    std::string subject_cn;
    std::string store_name;
    std::string method;
};


enum class pin_bypass_method {
    windows_trust,
    windows_chain_policy,
    windows_tls,
    chromium_browser,
    managed_dotnet,
    all
};

struct pin_bypass_config_t {
    std::uint32_t pid = 0;
    pin_bypass_method method = pin_bypass_method::all;
    bool persistent = false;
};

struct pin_bypass_result_t {
    bool success = false;
    bool read_only = true;
    bool legacy_patching_disabled = true;
    std::string diagnostic_summary;
    std::string recommended_action;
    std::vector<std::string> methods_requested;
    std::vector<std::string> disabled_operations;
};


struct keylog_config_t {
    std::uint32_t pid = 0;
    std::string output_file;
    std::uint32_t poll_interval_ms = 500;
    bool append = true;
    bool log_tls12 = true;
    bool log_tls13 = true;
};


struct quic_connection_info_t {
    std::uint32_t pid = 0;
    std::uint8_t src_addr[16] = {};
    std::uint8_t dst_addr[16] = {};
    std::uint32_t src_port = 0;
    std::uint32_t dst_port = 0;
    std::uint32_t address_family = 2;
    std::uint8_t version[4] = {};
    std::vector<std::uint8_t> dcid;
    std::vector<std::uint8_t> scid;
    std::uint64_t packets_sent = 0;
    std::uint64_t packets_recv = 0;
    std::uint64_t bytes_sent = 0;
    std::uint64_t bytes_recv = 0;
    std::string alpn;
    std::uint16_t tls_version = 0;
};

struct quic_key_info_t {
    std::string label;
    std::vector<std::uint8_t> client_random;
    std::vector<std::uint8_t> secret;
    std::uint32_t pid = 0;
    std::string library;
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


struct dtls_session_info_t {
    std::uint32_t pid = 0;
    std::uint8_t src_addr[16] = {};
    std::uint8_t dst_addr[16] = {};
    std::uint32_t src_port = 0;
    std::uint32_t dst_port = 0;
    std::uint32_t address_family = 2;
    std::uint16_t dtls_version = 0;
    std::uint16_t epoch = 0;
    std::uint64_t sequence_number = 0;
    std::uint8_t content_type = 0;
    std::vector<std::uint8_t> payload;
    std::string state;
};

struct dtls_key_info_t {
    std::uint16_t dtls_version = 0;
    std::vector<std::uint8_t> client_random;
    std::vector<std::uint8_t> master_secret;
    std::uint32_t pid = 0;
    std::string library;
};


struct pcap_decrypt_result_t {
    bool success = false;
    std::string error_message;
    std::string keylog_file_used;
    std::string pcap_file_used;
    std::uint32_t total_packets = 0;
    std::uint32_t decrypted_packets = 0;
    struct http2_frame_t {
        std::string stream_id;
        std::string method;
        std::string url;
        std::string authority;
        std::string content_type;
        std::map<std::string, std::string> headers;
        std::string body;
        std::string frame_type;
        std::uint32_t status_code = 0;
    };
    std::vector<http2_frame_t> http2_frames;
    std::string raw_output;
};


enum class autoresponder_match_type {
    exact_url,
    prefix_url,
    regex_url,
    method_and_url,
    header_contains,
    body_contains,
    sni_contains
};

struct autoresponder_rule_t {
    std::uint32_t rule_id = 0;
    bool enabled = true;
    int priority = 0;


    autoresponder_match_type match_type = autoresponder_match_type::prefix_url;
    std::string match_pattern;
    std::string match_method;


    std::uint32_t status_code = 200;
    std::string status_reason;
    std::map<std::string, std::string> response_headers;
    std::string response_body;
    std::string response_file_path;


    std::uint32_t latency_ms = 0;
    bool drop_request = false;
    bool passthrough = false;
    std::uint64_t match_count = 0;
    std::uint64_t last_match_time = 0;
};


class TlsKeyExtractor {
public:
    static TlsKeyExtractor& instance();


    std::vector<tls_session_key_t> extract_keys(const tls_key_scan_config_t& config);


    std::vector<quic_key_info_t> extract_quic_keys(std::uint32_t pid);


    std::vector<dtls_key_info_t> extract_dtls_keys(std::uint32_t pid);


    bool write_keylog_file(const std::string& path, const std::vector<tls_session_key_t>& keys, bool append);


    bool start_keylog(const keylog_config_t& config);
    bool stop_keylog();
    bool is_keylogging() const { return _keylog_active.load(); }


    std::map<std::string, tls_session_key_t> get_seen_keys() const;


    std::vector<tls_session_key_t> read_keylog_file(const std::string& path);


    pcap_decrypt_result_t decrypt_pcap_with_tshark(const std::string& pcap_path,
                                                    const std::string& keylog_path,
                                                    const std::string& display_filter = "http2");


    std::string find_tshark_path();


    bool ensure_sslkeylogfile_env(const std::string& path = "");


    bool find_module_in_process(std::uint32_t pid, const char* module_name,
                                std::uint64_t& base, std::uint32_t& size);
    std::vector<std::uint64_t> scan_for_pattern(std::uint32_t pid, std::uint64_t start,
                                                 std::uint64_t size, const std::uint8_t* pattern,
                                                 const std::uint8_t* mask, std::size_t pattern_len);
    bool read_process_memory(std::uint32_t pid, std::uint64_t address, void* buffer, std::size_t size);

private:
    TlsKeyExtractor() = default;


    std::vector<tls_session_key_t> scan_schannel(std::uint32_t pid);


    std::vector<tls_session_key_t> scan_openssl(std::uint32_t pid);


    std::vector<tls_session_key_t> scan_nss(std::uint32_t pid);


    std::vector<tls_session_key_t> scan_boringssl(std::uint32_t pid);


    std::vector<tls_session_key_t> scan_generic_patterns(std::uint32_t pid);

    bool validate_client_random(const std::uint8_t* data, std::size_t len);
    bool validate_master_secret(const std::uint8_t* data, std::size_t len);
    void keylog_worker_loop(const char* mode, std::uint64_t generation);
    bool wait_keylog_worker_done(std::uint64_t generation, DWORD timeout_ms);

    mutable std::mutex _mutex;
    std::mutex _keylog_lifecycle_mutex;
    std::mutex _keylog_worker_mutex;
    std::condition_variable _keylog_worker_cv;
    std::atomic<bool> _keylog_active{false};
    std::atomic<bool> _keylog_worker_done{true};
    std::atomic<std::uint64_t> _keylog_generation{0};
    std::atomic<DWORD> _keylog_worker_tid{0};
    keylog_config_t _keylog_config;
    std::map<std::string, tls_session_key_t> _seen_keys;
};


class CertificateInjector {
public:
    static CertificateInjector& instance();


    cert_injection_result_t inject_certificate(const cert_injection_config_t& config);


    bool remove_certificate(const std::string& thumbprint, const std::string& store_name);


    bool generate_ca_certificate(const std::string& cn, std::uint32_t validity_days,
                                 std::vector<std::uint8_t>& out_cert_der,
                                 std::vector<std::uint8_t>& out_key_der,
                                 bool export_private_key = false);


    struct cert_info_t {
        std::string thumbprint;
        std::string subject;
        std::string issuer;
        std::string not_before;
        std::string not_after;
        bool is_ca = false;
    };
    std::vector<cert_info_t> list_certificates(const std::string& store_name);


    const std::vector<std::string>& get_injected_thumbprints() const { return _injected; }

private:
    CertificateInjector() = default;
    std::vector<std::string> _injected;
    mutable std::mutex _mutex;
};


class CertPinBypasser {
public:
    static CertPinBypasser& instance();


    pin_bypass_result_t bypass_pins(const pin_bypass_config_t& config);


    bool revert_bypass(std::uint32_t pid);


    bool is_bypass_active(std::uint32_t pid) const;

private:
    CertPinBypasser() = default;

    struct patch_record_t {
        std::uint64_t address;
        std::vector<std::uint8_t> original_bytes;
        std::string description;
    };

    mutable std::mutex _mutex;
    std::map<std::uint32_t, std::vector<patch_record_t>> _active_patches;
};


class QuicAnalyzer {
public:
    static QuicAnalyzer& instance();


    std::vector<quic_connection_info_t> detect_quic_connections(std::uint32_t filter_pid = 0);


    quic_initial_decrypt_result_t decrypt_initial_packet(
        const std::uint8_t* packet_data, std::size_t packet_len);


    std::vector<quic_key_info_t> extract_quic_traffic_keys(std::uint32_t pid);


    struct quic_header_t {
        bool is_long_header = false;
        std::uint8_t packet_type = 0;
        std::uint32_t version = 0;
        std::vector<std::uint8_t> dcid;
        std::vector<std::uint8_t> scid;
        std::uint32_t token_length = 0;
        std::uint32_t payload_length = 0;
    };
    bool parse_quic_header(const std::uint8_t* data, std::size_t len, quic_header_t& out);

private:
    QuicAnalyzer() = default;


    bool derive_initial_keys(const std::uint8_t* dcid, std::size_t dcid_len,
                             std::uint32_t version,
                             std::uint8_t* client_key, std::uint8_t* client_iv, std::uint8_t* client_hp,
                             std::uint8_t* server_key, std::uint8_t* server_iv, std::uint8_t* server_hp);

    std::mutex _mutex;
};


class DtlsAnalyzer {
public:
    static DtlsAnalyzer& instance();


    std::vector<dtls_session_info_t> detect_dtls_sessions(std::uint32_t filter_pid = 0);


    std::vector<dtls_key_info_t> extract_dtls_keys(std::uint32_t pid);


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


class AutoResponder {
public:
    static AutoResponder& instance();


    std::uint32_t add_rule(const autoresponder_rule_t& rule);
    bool update_rule(std::uint32_t rule_id, const autoresponder_rule_t& rule);
    bool remove_rule(std::uint32_t rule_id);
    bool enable_rule(std::uint32_t rule_id, bool enabled);
    void clear_rules();
    std::vector<autoresponder_rule_t> list_rules() const;
    const autoresponder_rule_t* get_rule(std::uint32_t rule_id) const;


    bool start();
    bool stop();
    bool is_active() const { return _active.load(); }


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


    bool import_rules(const std::string& json_str);
    std::string export_rules() const;

private:
    AutoResponder() = default;

    bool match_pattern(const autoresponder_rule_t& rule, const std::string& method,
                       const std::string& url, const std::map<std::string, std::string>& headers,
                       const std::string& body);
    std::string build_response(const autoresponder_rule_t& rule);
    void worker_loop(const char* mode, std::uint64_t generation);
    bool wait_worker_done(std::uint64_t generation, DWORD timeout_ms);

    mutable std::mutex _mutex;
    std::mutex _lifecycle_mutex;
    std::mutex _worker_mutex;
    std::condition_variable _worker_cv;
    std::map<std::uint32_t, autoresponder_rule_t> _rules;
    std::uint32_t _next_rule_id = 1;
    std::atomic<bool> _active{false};
    std::atomic<bool> _worker_done{true};
    std::atomic<std::uint64_t> _worker_generation{0};
    std::atomic<DWORD> _worker_tid{0};
};

}
