#pragma once

#include <string>
#include <atomic>
#include <cstdint>

class license_manager_t
{
public:
    static license_manager_t& instance();
    bool validate();
    bool is_valid() const;
    void invalidate_runtime();
    bool show_activation_dialog();
    std::string get_plan() const;
    uint64_t get_runtime_nonce() const;
    bool verify_integrity_inline() const;
    uint64_t compute_integrity_checksum() const;
    void start_revalidation_timer();
    bool detect_clock_rollback() const;
    void snapshot_function_prologues();
    bool verify_function_prologues() const;
    bool verify_nonce_consistency() const;
    bool perform_heartbeat();
    bool is_hwid_banned() const;
    bool is_ip_banned() const;
    bool is_dll_leaked() const;
    std::string get_public_ip() const;
    std::string get_last_ban_reason() const;

    friend int idaapi license_revalidation_timer_cb(void*);

private:
    license_manager_t() = default;
    license_manager_t(const license_manager_t&) = delete;
    license_manager_t& operator=(const license_manager_t&) = delete;

    std::string generate_hwid() const;
    bool validate_with_server(const std::string& key);
    nlohmann::json read_license_config() const;
    bool write_license_config(const nlohmann::json& config) const;

    std::string encrypt_local(const std::string& plaintext) const;
    std::string decrypt_local(const std::string& ciphertext) const;
    std::string decrypt_local_legacy(const std::string& ciphertext) const;

    bool firebase_authenticate();
    bool firebase_refresh_token_if_needed();
    bool validate_with_cloud_function(const std::string& key, const std::string& hwid);
    std::string generate_session_nonce() const;
    void terminate_plugin();
    void compute_session_credentials(const std::string& key, const std::string& hwid,
                                     int64_t ts, const std::string& server_token);
    std::string compute_hmac(const std::string& key,
                             const unsigned char* data, size_t len) const;
    bool verify_server_signature(const std::string& response_body,
                                 const std::string& signature) const;
    void secure_clear_string(std::string& s) const;

    std::atomic<bool> m_valid{false};
    std::string m_plan;
    std::atomic<uint64_t> m_runtime_nonce{0};
    std::atomic<uint64_t> m_integrity_seed{0};

    std::string m_id_token;
    std::string m_refresh_token;
    int64_t m_token_expiry = 0;

    std::atomic<int64_t> m_last_known_time{0};

    std::atomic<bool> m_revalidation_pending{false};
    std::string m_cached_key;

    std::string m_server_session_token;
    std::string m_session_id;
    int64_t m_server_issued_at{0};
    int64_t m_server_ttl{3600};
    std::string m_client_nonce;
    std::atomic<int> m_consecutive_heartbeat_failures{0};
    std::atomic<bool> m_online_validated_this_session{false};
    std::string m_server_signature;

    std::atomic<uint64_t> m_nonce_canary{0};
    std::string m_heartbeat_nonce;

    static constexpr int MAX_HEARTBEAT_FAILURES = 1;
    static constexpr int REVALIDATION_INTERVAL_MS = 1800000;

    static constexpr size_t PROLOGUE_HASH_COUNT = 8;
    static constexpr size_t PROLOGUE_BYTES      = 32;
    uint64_t m_prologue_hashes[PROLOGUE_HASH_COUNT]{};
    bool     m_prologues_initialized{false};

    std::atomic<bool>  m_hwid_banned{false};
    std::atomic<bool>  m_ip_banned{false};
    std::atomic<bool>  m_dll_leaked{false};
    std::string m_public_ip;
    std::string m_ban_reason;
    std::string m_bound_hwid;
    void handle_ban_response(const nlohmann::json& response);
    void check_dll_leak(const std::string& current_hwid);
};

#ifdef __NT__
#include <windows.h>
#define VERIFY_LICENSE_INLINE() do { \
    const auto& _lic = license_manager_t::instance(); \
    uint64_t _n = _lic.get_runtime_nonce(); \
     \
    uint64_t _check = _n ^ (0xA5B4C3D2E1F0ULL + __LINE__); \
     \
    if (_n == 0 || _n == 0xFFFFFFFFFFFFFFFFULL \
        || _n == 0xDEADBEEFCAFEBABEULL \
        || _check == 0xA5B4C3D2E1F0ULL + __LINE__) { \
         \
        __fastfail(FAST_FAIL_FATAL_APP_EXIT); \
        TerminateProcess(GetCurrentProcess(), 0xDEADu); \
        volatile int* _p = nullptr; *_p = 0x41694441; \
    } \
} while (0)
#else
#define VERIFY_LICENSE_INLINE() do { \
    const auto& _lic = license_manager_t::instance(); \
    uint64_t _n = _lic.get_runtime_nonce(); \
    if (_n == 0) { _exit(1); abort(); } \
} while (0)
#endif
