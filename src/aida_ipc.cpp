#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "aida_ipc.hpp"

#include "aida_pro.hpp"

#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace
{
    constexpr int   kDefaultStandaloneMcpPort      = 29117;
    constexpr int   kVerifyConnectionTimeoutSec    = 1;
    constexpr int   kVerifyReadTimeoutSec          = 2;
    constexpr DWORD kWatchdogIntervalMs            = 5000;
    constexpr int   kWatchdogFailThreshold         = 3;
    constexpr DWORD kStandaloneAuthFastFailCode    = 0xA1DA1DA1u;

    std::atomic<bool> g_watchdog_running{false};
    std::atomic<bool> g_watchdog_started{false};
    std::atomic<bool> g_standalone_authenticated{false};
    std::atomic<int>  g_verified_port{0};
    std::mutex        g_state_mutex;
    std::string       g_last_failure;

    std::string bytes_to_hex(const unsigned char* data, size_t size)
    {
        static const char digits[] = "0123456789abcdef";
        std::string out(size * 2, '\0');
        for (size_t i = 0; i < size; ++i)
        {
            out[(i * 2) + 0] = digits[(data[i] >> 4) & 0x0F];
            out[(i * 2) + 1] = digits[data[i] & 0x0F];
        }
        return out;
    }

    std::vector<unsigned char> base64_decode(const std::string& text)
    {
        static const signed char table[256] = {
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
            52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
            15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
            -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
            41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
        };
        std::vector<unsigned char> out;
        int val = 0;
        int valb = -8;
        for (unsigned char c : text)
        {
            if (c == '=')
                break;
            if (std::isspace(c))
                continue;
            int d = table[c];
            if (d < 0)
                return {};
            val = (val << 6) | d;
            valb += 6;
            if (valb >= 0)
            {
                out.push_back(static_cast<unsigned char>((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }

    bool constant_time_equal(const std::string& a, const std::string& b)
    {
        if (a.size() != b.size())
            return false;
        unsigned char diff = 0;
        for (size_t i = 0; i < a.size(); ++i)
            diff |= static_cast<unsigned char>(a[i] ^ b[i]);
        return diff == 0;
    }

    std::string sha256_hex(const std::string& text)
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        unsigned char digest[32] = {};
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
            return {};
        if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return {};
        }
        bool ok = BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(text.data())),
            static_cast<ULONG>(text.size()),
            0) == 0 &&
            BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0;
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        if (!ok)
        {
            SecureZeroMemory(digest, sizeof(digest));
            return {};
        }
        std::string out = bytes_to_hex(digest, sizeof(digest));
        SecureZeroMemory(digest, sizeof(digest));
        return out;
    }

    std::string hmac_sha256_hex(const std::vector<unsigned char>& key, const std::string& data)
    {
        if (key.empty())
            return {};
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        unsigned char digest[32] = {};
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            return {};
        if (BCryptCreateHash(alg, &hash, nullptr, 0,
                const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0) != 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return {};
        }
        bool ok = BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
            static_cast<ULONG>(data.size()),
            0) == 0 &&
            BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0;
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        if (!ok)
        {
            SecureZeroMemory(digest, sizeof(digest));
            return {};
        }
        std::string out = bytes_to_hex(digest, sizeof(digest));
        SecureZeroMemory(digest, sizeof(digest));
        return out;
    }

    std::string generate_challenge_hex()
    {
        unsigned char challenge[32] = {};
        if (BCryptGenRandom(nullptr, challenge, sizeof(challenge), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            return {};
        std::string out = bytes_to_hex(challenge, sizeof(challenge));
        SecureZeroMemory(challenge, sizeof(challenge));
        return out;
    }

    bool json_u32(const nlohmann::json& j, const char* key, uint32_t& out)
    {
        if (!j.contains(key))
            return false;
        if (j[key].is_number_unsigned())
        {
            out = j[key].get<uint32_t>();
            return true;
        }
        if (j[key].is_number_integer())
        {
            int64_t v = j[key].get<int64_t>();
            if (v >= 0 && v <= 0xFFFFFFFFll)
            {
                out = static_cast<uint32_t>(v);
                return true;
            }
        }
        return false;
    }

    bool json_u64(const nlohmann::json& j, const char* key, uint64_t& out)
    {
        if (!j.contains(key))
            return false;
        if (j[key].is_number_unsigned())
        {
            out = j[key].get<uint64_t>();
            return true;
        }
        if (j[key].is_number_integer())
        {
            int64_t v = j[key].get<int64_t>();
            if (v >= 0)
            {
                out = static_cast<uint64_t>(v);
                return true;
            }
        }
        return false;
    }

    std::string ida_plugin_proof_canonical(const nlohmann::json& proof)
    {
        uint32_t plugin_pid = 0;
        uint32_t standalone_pid = 0;
        uint32_t mcp_port = 0;
        uint64_t issued_tick = 0;
        uint64_t expires_tick = 0;
        uint64_t server_nonce_hash = 0;
        json_u32(proof, "plugin_pid", plugin_pid);
        json_u32(proof, "standalone_pid", standalone_pid);
        json_u32(proof, "mcp_port", mcp_port);
        json_u64(proof, "issued_tick_ms", issued_tick);
        json_u64(proof, "expires_tick_ms", expires_tick);
        json_u64(proof, "server_nonce_hash", server_nonce_hash);

        std::ostringstream ss;
        ss << "AIDA_IDA_PLUGIN_AUTH_V1\n";
        ss << "challenge=" << proof.value("challenge", std::string()) << "\n";
        ss << "plugin_pid=" << plugin_pid << "\n";
        ss << "standalone_pid=" << standalone_pid << "\n";
        ss << "mcp_port=" << mcp_port << "\n";
        ss << "issued_tick_ms=" << issued_tick << "\n";
        ss << "expires_tick_ms=" << expires_tick << "\n";
        ss << "validated=" << (proof.value("validated", false) ? 1 : 0) << "\n";
        ss << "arc_loaded=" << (proof.value("arc_loaded", false) ? 1 : 0) << "\n";
        ss << "lifecycle_ready=" << (proof.value("lifecycle_ready", false) ? 1 : 0) << "\n";
        ss << "exports_verified=" << (proof.value("exports_verified", false) ? 1 : 0) << "\n";
        ss << "server_nonce_hash=" << server_nonce_hash << "\n";
        ss << "signed_payload_sha256=" << proof.value("signed_payload_sha256", std::string()) << "\n";
        return ss.str();
    }

    bool valid_port(int port)
    {
        return port > 0 && port <= 65535;
    }

    void set_failure(const std::string& failure)
    {
        std::lock_guard<std::mutex> lk(g_state_mutex);
        g_last_failure = failure;
    }

    bool parse_port_text(const char* text, int& out_port)
    {
        if (text == nullptr || *text == '\0')
            return false;
        char* end = nullptr;
        long value = std::strtol(text, &end, 10);
        if (end == text || (end != nullptr && *end != '\0'))
            return false;
        if (!valid_port(static_cast<int>(value)))
            return false;
        out_port = static_cast<int>(value);
        return true;
    }

    bool read_env_port(int& out_port)
    {
        char value[32] = {};
        DWORD n = GetEnvironmentVariableA("AIDA_STANDALONE_MCP_PORT", value, static_cast<DWORD>(sizeof(value)));
        if (n == 0 || n >= sizeof(value))
            return false;
        return parse_port_text(value, out_port);
    }

    std::string standalone_settings_path()
    {
        char appdata[MAX_PATH] = {};
        DWORD n = GetEnvironmentVariableA("APPDATA", appdata, static_cast<DWORD>(sizeof(appdata)));
        if (n == 0 || n >= sizeof(appdata))
            return {};
        std::string path(appdata);
        if (!path.empty() && path.back() != '\\' && path.back() != '/')
            path.push_back('\\');
        path += "AiDA\\Standalone\\settings.json";
        return path;
    }

    bool read_settings_port(int& out_port)
    {
        const std::string path = standalone_settings_path();
        if (path.empty())
            return false;
        std::ifstream in(path, std::ios::binary);
        if (!in)
            return false;
        std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (data.empty())
            return false;
        nlohmann::json j = nlohmann::json::parse(data, nullptr, false);
        if (j.is_discarded() || !j.is_object())
            return false;
        if (j.contains("mcp_enabled") && j["mcp_enabled"].is_boolean() && !j["mcp_enabled"].get<bool>())
            return false;
        if (!j.contains("mcp_port") || !j["mcp_port"].is_number_integer())
            return false;
        int port = j["mcp_port"].get<int>();
        if (!valid_port(port))
            return false;
        out_port = port;
        return true;
    }

    void add_unique_port(std::vector<int>& ports, int port)
    {
        if (!valid_port(port))
            return;
        for (int existing : ports)
            if (existing == port)
                return;
        ports.push_back(port);
    }

    std::vector<int> candidate_ports()
    {
        std::vector<int> ports;
        int port = 0;
        if (read_env_port(port))
            add_unique_port(ports, port);
        if (read_settings_port(port))
            add_unique_port(ports, port);
        add_unique_port(ports, kDefaultStandaloneMcpPort);
        return ports;
    }

    bool process_basename_is_standalone(uint32_t pid)
    {
        if (pid == 0 || pid == GetCurrentProcessId())
            return false;
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process)
            return false;
        wchar_t image[MAX_PATH * 2] = {};
        DWORD size = static_cast<DWORD>(sizeof(image) / sizeof(image[0]));
        BOOL ok = QueryFullProcessImageNameW(process, 0, image, &size);
        CloseHandle(process);
        if (!ok || size == 0)
            return false;
        const wchar_t* base = image;
        for (const wchar_t* p = image; *p != L'\0'; ++p)
            if (*p == L'\\' || *p == L'/')
                base = p + 1;
        return _wcsicmp(base, L"AiDAStandalone.exe") == 0;
    }

    bool verify_ida_plugin_auth_proof(const nlohmann::json& proof,
                                      const std::string& challenge,
                                      int expected_port,
                                      std::string& failure)
    {
        if (!proof.is_object())
        {
            failure = "auth proof response was not JSON object";
            return false;
        }
        if (proof.value("status", std::string()) != "ok" ||
            proof.value("proof_version", 0) != 1 ||
            proof.value("server", std::string()) != "aida-pro-mcp")
        {
            failure = "auth proof identity mismatch";
            return false;
        }
        if (proof.value("challenge", std::string()) != challenge)
        {
            failure = "auth proof challenge mismatch";
            return false;
        }

        uint32_t plugin_pid = 0;
        uint32_t standalone_pid = 0;
        uint32_t proof_port = 0;
        uint64_t issued_tick = 0;
        uint64_t expires_tick = 0;
        if (!json_u32(proof, "plugin_pid", plugin_pid) ||
            !json_u32(proof, "standalone_pid", standalone_pid) ||
            !json_u32(proof, "mcp_port", proof_port) ||
            !json_u64(proof, "issued_tick_ms", issued_tick) ||
            !json_u64(proof, "expires_tick_ms", expires_tick))
        {
            failure = "auth proof numeric fields missing";
            return false;
        }
        if (plugin_pid != GetCurrentProcessId())
        {
            failure = "auth proof plugin pid mismatch";
            return false;
        }
        if (proof_port != static_cast<uint32_t>(expected_port))
        {
            failure = "auth proof port mismatch";
            return false;
        }
        if (!process_basename_is_standalone(standalone_pid))
        {
            failure = "auth proof process identity mismatch";
            return false;
        }
        if (!proof.value("validated", false) ||
            !proof.value("arc_loaded", false) ||
            !proof.value("lifecycle_ready", false) ||
            !proof.value("exports_verified", false))
        {
            failure = "auth proof runtime state is not authorized";
            return false;
        }

        const uint64_t now_tick = static_cast<uint64_t>(GetTickCount64());
        if (expires_tick <= issued_tick ||
            expires_tick < now_tick ||
            issued_tick > now_tick + 5000ull ||
            expires_tick > now_tick + 60000ull)
        {
            failure = "auth proof lifetime invalid";
            return false;
        }

        const std::string server_payload_b64 = proof.value("server_payload_b64", std::string());
        const std::string server_sig_b64 = proof.value("server_sig_b64", std::string());
        const int server_kid = proof.value("server_kid", 0);
        const std::string signed_payload_sha256 = proof.value("signed_payload_sha256", std::string());
        const std::string proof_mac = proof.value("proof_mac", std::string());
        if (server_payload_b64.empty() || server_sig_b64.empty() || server_kid <= 0 ||
            signed_payload_sha256.size() != 64 || proof_mac.size() != 64)
        {
            failure = "auth proof signed session fields missing";
            return false;
        }

        std::vector<unsigned char> payload_bytes = base64_decode(server_payload_b64);
        std::vector<unsigned char> sig_bytes = base64_decode(server_sig_b64);
        if (payload_bytes.empty() || sig_bytes.size() != 64)
        {
            if (!payload_bytes.empty())
                SecureZeroMemory(payload_bytes.data(), payload_bytes.size());
            if (!sig_bytes.empty())
                SecureZeroMemory(sig_bytes.data(), sig_bytes.size());
            failure = "auth proof signed session decode failed";
            return false;
        }

        std::string signed_payload(reinterpret_cast<const char*>(payload_bytes.data()), payload_bytes.size());
        SecureZeroMemory(payload_bytes.data(), payload_bytes.size());
        const std::string computed_payload_hash = sha256_hex(signed_payload);
        if (!constant_time_equal(computed_payload_hash, signed_payload_sha256))
        {
            SecureZeroMemory(signed_payload.data(), signed_payload.size());
            SecureZeroMemory(sig_bytes.data(), sig_bytes.size());
            failure = "auth proof signed payload hash mismatch";
            return false;
        }

        std::string sig_hex = bytes_to_hex(sig_bytes.data(), sig_bytes.size());
        SecureZeroMemory(sig_bytes.data(), sig_bytes.size());
        if (!license_manager_t::instance().verify_server_signature_with_kid(signed_payload, sig_hex, server_kid))
        {
            SecureZeroMemory(signed_payload.data(), signed_payload.size());
            SecureZeroMemory(sig_hex.data(), sig_hex.size());
            failure = "auth proof server signature invalid";
            return false;
        }
        SecureZeroMemory(sig_hex.data(), sig_hex.size());

        nlohmann::json signed_json = nlohmann::json::parse(signed_payload, nullptr, false);
        if (signed_json.is_discarded() || !signed_json.is_object())
        {
            SecureZeroMemory(signed_payload.data(), signed_payload.size());
            failure = "auth proof signed payload parse failed";
            return false;
        }

        const std::string auth_key_b64 = signed_json.value("auth_hmac_key_b64", std::string());
        const std::string session_token = signed_json.value("session_token", std::string());
        const int signed_kid = signed_json.value("kid", 0);
        const int64_t issued_at = signed_json.value("issued_at", int64_t{0});
        const int64_t ttl = signed_json.value("ttl", int64_t{0});
        const int64_t now_epoch = static_cast<int64_t>(std::time(nullptr));
        if (signed_json.value("status", std::string()) != "valid" ||
            signed_kid != server_kid ||
            auth_key_b64.empty() ||
            session_token.size() < 16 ||
            issued_at <= 0 ||
            ttl <= 0 ||
            now_epoch < issued_at - 60 ||
            now_epoch > issued_at + ttl + 60)
        {
            SecureZeroMemory(signed_payload.data(), signed_payload.size());
            failure = "auth proof signed payload is not current";
            return false;
        }

        std::vector<unsigned char> auth_key = base64_decode(auth_key_b64);
        if (auth_key.size() != 32)
        {
            SecureZeroMemory(signed_payload.data(), signed_payload.size());
            if (!auth_key.empty())
                SecureZeroMemory(auth_key.data(), auth_key.size());
            failure = "auth proof key invalid";
            return false;
        }

        const std::string canonical = ida_plugin_proof_canonical(proof);
        const std::string computed_mac = hmac_sha256_hex(auth_key, canonical);
        SecureZeroMemory(auth_key.data(), auth_key.size());
        SecureZeroMemory(signed_payload.data(), signed_payload.size());
        if (computed_mac.empty() || !constant_time_equal(computed_mac, proof_mac))
        {
            failure = "auth proof MAC invalid";
            return false;
        }
        return true;
    }

    bool verify_health_payload(const nlohmann::json& health, std::string& failure)
    {
        if (!health.is_object())
        {
            failure = "health response was not JSON object";
            return false;
        }
        if (health.value("status", std::string()) != "ok")
        {
            failure = "health status was not ok";
            return false;
        }
        if (health.value("server", std::string()) != "aida-pro-mcp")
        {
            failure = "health server identity mismatch";
            return false;
        }
        if (!health.value("authenticated", false) ||
            !health.value("validated", false) ||
            !health.value("arc_loaded", false) ||
            !health.value("lifecycle_ready", false))
        {
            failure = "standalone runtime is not authenticated";
            return false;
        }
        uint32_t pid = 0;
        if (health.contains("pid") && health["pid"].is_number_unsigned())
            pid = health["pid"].get<uint32_t>();
        else if (health.contains("pid") && health["pid"].is_number_integer())
        {
            int64_t signed_pid = health["pid"].get<int64_t>();
            if (signed_pid > 0 && signed_pid <= 0xFFFFFFFFll)
                pid = static_cast<uint32_t>(signed_pid);
        }
        if (!process_basename_is_standalone(pid))
        {
            failure = "standalone process identity mismatch";
            return false;
        }
        return true;
    }

    bool verify_initialize_payload(const nlohmann::json& response, std::string& failure)
    {
        if (!response.is_object())
        {
            failure = "initialize response was not JSON object";
            return false;
        }
        if (response.contains("error"))
        {
            failure = "standalone initialize returned error";
            return false;
        }
        if (!response.contains("result") || !response["result"].is_object())
        {
            failure = "initialize result missing";
            return false;
        }
        const auto& result = response["result"];
        if (result.value("protocolVersion", std::string()) != "2025-06-18")
        {
            failure = "standalone protocol mismatch";
            return false;
        }
        if (!result.contains("serverInfo") || !result["serverInfo"].is_object())
        {
            failure = "standalone serverInfo missing";
            return false;
        }
        const auto& server_info = result["serverInfo"];
        if (server_info.value("name", std::string()) != "aida-pro-mcp")
        {
            failure = "standalone MCP identity mismatch";
            return false;
        }
        return true;
    }

    bool verify_port(int port, std::string& failure)
    {
        try
        {
            httplib::Client client("127.0.0.1", port);
            client.set_connection_timeout(kVerifyConnectionTimeoutSec);
            client.set_read_timeout(kVerifyReadTimeoutSec);
            client.set_write_timeout(kVerifyReadTimeoutSec);
            client.set_keep_alive(false);

            auto health_res = client.Get("/health");
            if (!health_res)
            {
                failure = "no health response on port " + std::to_string(port);
                return false;
            }
            if (health_res->status != 200)
            {
                failure = "health returned HTTP " + std::to_string(health_res->status);
                return false;
            }
            nlohmann::json health = nlohmann::json::parse(health_res->body, nullptr, false);
            if (!verify_health_payload(health, failure))
                return false;

            std::string challenge = generate_challenge_hex();
            if (challenge.empty())
            {
                failure = "auth challenge generation failed";
                return false;
            }

            nlohmann::json auth_req;
            auth_req["challenge"] = challenge;
            auth_req["plugin_pid"] = static_cast<uint32_t>(GetCurrentProcessId());
            auth_req["plugin_version"] = AIDA_VERSION;

            httplib::Headers auth_headers = {
                {"Content-Type", "application/json"},
                {"Accept", "application/json"}
            };
            auto auth_res = client.Post("/ida-plugin-auth", auth_headers, json_dump_safe(auth_req), "application/json");
            if (!auth_res)
            {
                failure = "no standalone auth proof response on port " + std::to_string(port);
                return false;
            }
            if (auth_res->status != 200)
            {
                failure = "standalone auth proof returned HTTP " + std::to_string(auth_res->status);
                return false;
            }
            nlohmann::json auth_json = nlohmann::json::parse(auth_res->body, nullptr, false);
            if (!verify_ida_plugin_auth_proof(auth_json, challenge, port, failure))
                return false;

            nlohmann::json init_req;
            init_req["jsonrpc"] = "2.0";
            init_req["id"] = "aida-plugin-auth";
            init_req["method"] = "initialize";
            init_req["params"] = {
                {"protocolVersion", "2025-06-18"},
                {"capabilities", nlohmann::json::object()},
                {"clientInfo", {{"name", "aida-plugin"}, {"version", AIDA_VERSION}}}
            };

            httplib::Headers headers = {
                {"Content-Type", "application/json"},
                {"Accept", "application/json"},
                {"MCP-Protocol-Version", "2025-06-18"}
            };
            auto init_res = client.Post("/mcp", headers, json_dump_safe(init_req), "application/json");
            if (!init_res)
            {
                failure = "no initialize response on port " + std::to_string(port);
                return false;
            }
            if (init_res->status < 200 || init_res->status >= 300)
            {
                failure = "initialize returned HTTP " + std::to_string(init_res->status);
                return false;
            }
            nlohmann::json init_json = nlohmann::json::parse(init_res->body, nullptr, false);
            if (!verify_initialize_payload(init_json, failure))
                return false;
            return true;
        }
        catch (const std::exception& ex)
        {
            failure = ex.what();
            return false;
        }
        catch (...)
        {
            failure = "unknown verification exception";
            return false;
        }
    }

    bool verify_any_candidate(std::string* failure)
    {
        std::string last;
        for (int port : candidate_ports())
        {
            std::string port_failure;
            if (verify_port(port, port_failure))
            {
                g_verified_port.store(port, std::memory_order_release);
                g_standalone_authenticated.store(true, std::memory_order_release);
                set_failure({});
                return true;
            }
            last = port_failure;
        }
        if (last.empty())
            last = "no standalone MCP candidate port responded";
        g_standalone_authenticated.store(false, std::memory_order_release);
        set_failure(last);
        if (failure)
            *failure = last;
        return false;
    }

    void watchdog_thread()
    {
        int consecutive_failures = 0;
        while (g_watchdog_running.load(std::memory_order_acquire))
        {
            Sleep(kWatchdogIntervalMs);
            if (!g_watchdog_running.load(std::memory_order_acquire))
                break;

            std::string failure;
            bool ok = false;
            int port = g_verified_port.load(std::memory_order_acquire);
            if (valid_port(port))
                ok = verify_port(port, failure);
            if (!ok)
                ok = verify_any_candidate(&failure);

            if (ok)
            {
                consecutive_failures = 0;
                continue;
            }

            ++consecutive_failures;
            if (consecutive_failures >= kWatchdogFailThreshold)
                __fastfail(kStandaloneAuthFastFailCode);
        }
        g_standalone_authenticated.store(false, std::memory_order_release);
        g_watchdog_started.store(false, std::memory_order_release);
    }
}

namespace aida_ipc
{
    bool verify_standalone_runtime(std::string* failure)
    {
        return verify_any_candidate(failure);
    }

    bool start_standalone_watchdog()
    {
        bool expected = false;
        if (!g_watchdog_started.compare_exchange_strong(expected, true))
            return g_watchdog_running.load(std::memory_order_acquire);
        g_watchdog_running.store(true, std::memory_order_release);
        try
        {
            std::thread(watchdog_thread).detach();
            return true;
        }
        catch (...)
        {
            g_watchdog_running.store(false, std::memory_order_release);
            g_watchdog_started.store(false, std::memory_order_release);
            g_standalone_authenticated.store(false, std::memory_order_release);
            return false;
        }
    }

    void shutdown()
    {
        g_watchdog_running.store(false, std::memory_order_release);
        g_standalone_authenticated.store(false, std::memory_order_release);
    }

    bool is_standalone_alive()
    {
        return g_standalone_authenticated.load(std::memory_order_acquire);
    }
}
