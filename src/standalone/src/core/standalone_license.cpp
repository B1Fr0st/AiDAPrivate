#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "standalone_license.hpp"

#include "standalone_settings.hpp"
#include "standalone_driver.hpp"
#include "arc/arc.h"
#include "arc_loader.hpp"
#include "anti-tamper/vm_compiler.hpp"
#include "anti-tamper/server_pages.hpp"

#include <windows.h>
#include <iphlpapi.h>
#include <intrin.h>
#include <psapi.h>
#include <dbghelp.h>
#include <bcrypt.h>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "bcrypt.lib")

using json = nlohmann::json;

static void lic_log(const char* step)
{

    static char s_log_path[MAX_PATH] = {};
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    BOOL pending;
    InitOnceBeginInitialize(&s_once, INIT_ONCE_ASYNC, &pending, nullptr);
    if (pending || s_log_path[0] == '\0') {
        DWORD n = GetModuleFileNameA(nullptr, s_log_path, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) {
            strcpy_s(s_log_path, "aida_debug.log");
        } else {
            char* last = strrchr(s_log_path, '\\');
            if (last) *(last + 1) = '\0'; else s_log_path[0] = '\0';
            strcat_s(s_log_path, "aida_debug.log");
        }
        InitOnceComplete(&s_once, INIT_ONCE_ASYNC, nullptr);
    }

    HANDLE hf = CreateFileA(s_log_path, GENERIC_WRITE, FILE_SHARE_READ,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    SetFilePointer(hf, 0, nullptr, FILE_END);
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char line[512];
    int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%02d:%02d:%02d.%03d] [license] %s\r\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, step);
    if (len > 0) { DWORD w; WriteFile(hf, line, (DWORD)len, &w, nullptr); }
    CloseHandle(hf);
}

namespace
{


    constexpr uint64_t S_MAGIC_INIT = 0xA1DA'C0DE'DEAD'BEEFull;
    std::atomic<uint64_t> s_state_a{0};
    std::atomic<uint64_t> s_state_b{0};
    std::atomic<uint64_t> s_state_c{0};
    std::atomic<uint64_t> s_magic{S_MAGIC_INIT};

    /* Legacy atomic kept for backward-compat with existing checks */
    std::atomic<bool> s_valid{false};
    std::atomic<bool> s_stop{false};
    std::thread       s_heartbeat_thread;
    std::mutex        s_state_mtx;
    std::string       s_plan;
    std::string       s_error;

    /* Heartbeat freshness tracking */
    std::atomic<int64_t> s_last_heartbeat_time{0};
    std::atomic<uint32_t> s_heartbeat_counter{0};

    /* Cached HWID for inline re-derivation check */
    std::string s_cached_hwid;

    std::string s_cached_session_token;

    /* Proof hash: FNV-1a of (session_token + hwid) */
    std::atomic<uint64_t> s_proof_hash{0};

    /* Code integrity hashes (populated at startup) */
    struct code_section_hash_t {
        uintptr_t base;
        size_t    size;
        uint64_t  hash;
    };
    std::vector<code_section_hash_t> s_code_hashes;
    std::mutex s_code_hash_mtx;

    /* ── Phase-2 hardening state ─────────────────────────── */

    /* Additional obfuscated state pair: d + e == magic_2 */
    constexpr uint64_t S_MAGIC2_INIT = 0xCAFE'BABE'1337'C0DEull;
    std::atomic<uint64_t> s_state_d{0};
    std::atomic<uint64_t> s_state_e{0};
    std::atomic<uint64_t> s_magic_2{S_MAGIC2_INIT};


    std::atomic<int64_t> s_gate_timestamps[standalone_license::GATE_SLOT_COUNT] = {};
    std::atomic<uint64_t> s_gate_tokens[standalone_license::GATE_SLOT_COUNT] = {};
    int64_t s_sweep_start_time = 0;


    arc_loader::loaded_module_t  s_arc_module{};
    std::mutex                   s_arc_mtx;
    bool                         s_arc_loaded = false;


    std::shared_ptr<httplib::Client> s_license_client;
    std::string                      s_license_host;
    std::shared_ptr<httplib::Client> s_ip_client;
    std::string                      s_ip_host;
    std::mutex                       s_http_mtx;


    using arc_init_fn           = bool(*)(const char*, const char*, int64_t, uint32_t);
    using arc_get_comm_bridge_fn = const arc_comm_vtable_t*(*)();
    using arc_validate_tool_fn  = uint64_t(*)(uint64_t, uint64_t);
    using arc_heartbeat_fn      = arc_heartbeat_result_t(*)();
    using arc_cleanup_fn        = void(*)();

    arc_init_fn           s_fn_arc_init            = nullptr;
    arc_get_comm_bridge_fn s_fn_arc_get_comm_bridge = nullptr;
    arc_validate_tool_fn  s_fn_arc_validate_tool   = nullptr;
    arc_heartbeat_fn      s_fn_arc_heartbeat       = nullptr;
    arc_cleanup_fn        s_fn_arc_cleanup          = nullptr;


    static const uint8_t S_STR_KEY = 0x5A;
    std::string decode_status_string_impl(standalone_license::status_string_id id)
    {


        static const uint8_t strs[][40] = {
             {0x09,0x3f,0x29,0x29,0x33,0x35,0x34,0x7a,0x28,0x3f,0x2c,0x35,0x31,0x3f,0x3e,0x00},
             {0x13,0x34,0x2e,0x3f,0x3d,0x28,0x33,0x2e,0x23,0x7a,0x3c,0x3b,0x2f,0x36,0x2e,0x00},
             {0x1d,0x3b,0x2e,0x3f,0x7a,0x39,0x32,0x3f,0x39,0x31,0x7a,0x29,0x2e,0x3b,0x36,0x3f,0x00},
             {0x0a,0x28,0x35,0x35,0x3c,0x7a,0x37,0x33,0x29,0x37,0x3b,0x2e,0x39,0x32,0x00},
             {0x12,0x0d,0x13,0x1e,0x7a,0x3e,0x28,0x33,0x3c,0x2e,0x00},
             {0x12,0x3f,0x3b,0x28,0x2e,0x38,0x3f,0x3b,0x2e,0x7a,0x3f,0x22,0x2a,0x33,0x28,0x3f,0x3e,0x00},
        };
        if (id < 0 || id > 5) return "Error";
        std::string result;
        const uint8_t* p = strs[id];
        while (*p) {
            result += static_cast<char>(*p ^ S_STR_KEY);
            ++p;
        }
        return result;
    }


    void set_obfuscated_valid(bool valid, uint64_t nonce_seed = 0)
    {
        if (valid) {

            std::mt19937_64 rng(nonce_seed ? nonce_seed :
                static_cast<uint64_t>(GetTickCount64()));
            uint64_t a = rng();
            uint64_t b = rng();
            uint64_t magic = s_magic.load(std::memory_order_acquire);
            uint64_t c = a ^ b ^ magic;
            s_state_a.store(a, std::memory_order_release);
            s_state_b.store(b, std::memory_order_release);
            s_state_c.store(c, std::memory_order_release);
            s_valid.store(true, std::memory_order_release);


            uint64_t d = rng();
            uint64_t magic2 = S_MAGIC2_INIT ^ nonce_seed;
            s_magic_2.store(magic2, std::memory_order_release);
            s_state_d.store(d, std::memory_order_release);
            s_state_e.store(magic2 - d, std::memory_order_release);


            if (s_sweep_start_time == 0)
                s_sweep_start_time = static_cast<int64_t>(GetTickCount64());
        } else {
            s_state_a.store(0, std::memory_order_release);
            s_state_b.store(0, std::memory_order_release);
            s_state_c.store(0, std::memory_order_release);
            s_valid.store(false, std::memory_order_release);


            s_state_d.store(0, std::memory_order_release);
            s_state_e.store(0, std::memory_order_release);
        }
    }


    bool check_obfuscated_valid()
    {
        uint64_t a = s_state_a.load(std::memory_order_acquire);
        uint64_t b = s_state_b.load(std::memory_order_acquire);
        uint64_t c = s_state_c.load(std::memory_order_acquire);
        uint64_t magic = s_magic.load(std::memory_order_acquire);
        return (a ^ b ^ c) == magic;
    }


    uint64_t fnv1a(const void* data, size_t len)
    {
        uint64_t h = 14695981039346656037ULL;
        const auto* p = static_cast<const uint8_t*>(data);
        for (size_t i = 0; i < len; ++i) {
            h ^= p[i];
            h *= 1099511628211ULL;
        }
        return h;
    }

    uint64_t fnv1a_str(const std::string& s)
    {
        return fnv1a(s.data(), s.size());
    }


    void update_proof_hash(const std::string& session_token,
                           const std::string& hwid)
    {
        std::string combined = session_token + "|" + hwid;
        s_proof_hash.store(fnv1a_str(combined), std::memory_order_release);
    }

    uint64_t vm_generate_proof_token(uint64_t session_seed, uint64_t heartbeat_count,
                                      uint64_t server_nonce, uint64_t hwid_hash)
    {
        uint64_t vm_seed = session_seed ^ __rdtsc() ^ heartbeat_count;

        anti_tamper::virtualizer::detail::vm_state_t vm;
        anti_tamper::virtualizer::detail::init_vm(vm, vm_seed);

        anti_tamper::vm_compiler::program_t prog;
        prog.set_key(vm_seed ^ 0x6A09E667F3BCC908ULL);
        prog.set_opcode_map(vm.opcode_map);

        prog.emit_load_imm(0, session_seed);
        prog.emit_load_imm(1, heartbeat_count);
        prog.emit_load_imm(2, server_nonce);
        prog.emit_load_imm(3, hwid_hash);

        prog.emit_xor(0, 0, 1);
        prog.emit_load_imm(8, 13);
        prog.emit_rol(0, 0, 8);
        prog.emit_xor(0, 0, 2);
        prog.emit_load_imm(8, 29);
        prog.emit_rol(0, 0, 8);
        prog.emit_xor(0, 0, 3);
        prog.emit_hash(0, 0);
        prog.emit_junk(3);
        prog.emit_halt();

        auto bytecode = prog.finalize();
        return anti_tamper::virtualizer::detail::vm_execute(
            vm, bytecode.data(), static_cast<uint32_t>(bytecode.size()));
    }

    std::string get_cloud_function_host()
    {
#ifdef AIDA_LOCAL_LICENSE_SERVER
        return "http://localhost:3000";
#else
        return "https://aidapro.net";
#endif
    }

    std::shared_ptr<httplib::Client> get_or_create_license_client()
    {
        std::lock_guard<std::mutex> lk(s_http_mtx);
        std::string host = get_cloud_function_host();
        if (!s_license_client || s_license_host != host) {
            s_license_client = std::make_shared<httplib::Client>(host.c_str());
            s_license_host = host;
            s_license_client->set_connection_timeout(15);
            s_license_client->set_read_timeout(30);
            s_license_client->set_write_timeout(10);
            s_license_client->set_keep_alive(true);
            s_license_client->set_tcp_nodelay(true);
            s_license_client->set_decompress(true);
            s_license_client->set_follow_location(true);
            s_license_client->enable_server_certificate_verification(false);
        }
        return s_license_client;
    }

    std::shared_ptr<httplib::Client> get_or_create_ip_client()
    {
        std::lock_guard<std::mutex> lk(s_http_mtx);
        const std::string host = "https://api.ipify.org";
        if (!s_ip_client || s_ip_host != host) {
            s_ip_client = std::make_shared<httplib::Client>(host.c_str());
            s_ip_host = host;
            s_ip_client->set_connection_timeout(5);
            s_ip_client->set_read_timeout(5);
            s_ip_client->set_write_timeout(5);
            s_ip_client->set_keep_alive(true);
            s_ip_client->set_tcp_nodelay(true);
            s_ip_client->set_decompress(true);
            s_ip_client->set_follow_location(true);
            s_ip_client->enable_server_certificate_verification(false);
        }
        return s_ip_client;
    }

    void reset_license_clients()
    {
        std::lock_guard<std::mutex> lk(s_http_mtx);
        s_license_client.reset();
        s_license_host.clear();
        s_ip_client.reset();
        s_ip_host.clear();
    }

    std::string generate_nonce()
    {
        LARGE_INTEGER counter{};
        QueryPerformanceCounter(&counter);
        std::ostringstream oss;
        oss << std::hex << static_cast<unsigned long long>(GetCurrentProcessId())
            << static_cast<unsigned long long>(GetTickCount64())
            << static_cast<unsigned long long>(counter.QuadPart);
        return oss.str();
    }

    std::string generate_hwid()
    {
        uint64_t hash = 14695981039346656037ULL;
        auto mix = [&](uint64_t value) {
            hash ^= value;
            hash *= 1099511628211ULL;
        };

        wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD name_size = MAX_COMPUTERNAME_LENGTH + 1;
        if (GetComputerNameW(computer_name, &name_size)) {
            for (DWORD i = 0; i < name_size; ++i)
                mix(static_cast<uint64_t>(computer_name[i]));
        } else {
            mix(0xDEADBEEF00000001ULL);
        }

        int cpu_info[4] = {};
        __cpuid(cpu_info, 1);
        mix((static_cast<uint64_t>(cpu_info[0]) << 32) | static_cast<unsigned>(cpu_info[1]));
        mix((static_cast<uint64_t>(cpu_info[2]) << 32) | static_cast<unsigned>(cpu_info[3]));

        DWORD volume_serial = 0;
        if (GetVolumeInformationW(L"C:\\", nullptr, 0, &volume_serial, nullptr, nullptr, nullptr, 0)
            && volume_serial != 0) {
            mix(volume_serial);
        } else {
            mix(0xDEADBEEF00000002ULL);
        }


        bool got_guid = false;
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Cryptography",
                0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            wchar_t guid[128] = {};
            DWORD size = sizeof(guid);
            DWORD type = 0;
            if (RegQueryValueExW(hKey, L"MachineGuid", nullptr, &type,
                    reinterpret_cast<BYTE*>(guid), &size) == ERROR_SUCCESS
                && type == REG_SZ && guid[0] != L'\0') {
                for (size_t i = 0; guid[i] != L'\0'; ++i)
                    mix(static_cast<uint64_t>(guid[i]));
                got_guid = true;
            }
            RegCloseKey(hKey);
        }
        if (!got_guid) {
            mix(0xDEADBEEF00000003ULL);
        }

        char out[17];
        snprintf(out, sizeof(out), "%016llX", static_cast<unsigned long long>(hash));
        return out;
    }

    std::string get_mac_address()
    {
        ULONG len = 0;
        GetAdaptersInfo(nullptr, &len);
        if (len == 0)
            return {};

        std::vector<unsigned char> buffer(len);
        auto* info = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
        if (GetAdaptersInfo(info, &len) != NO_ERROR || !info || info->AddressLength == 0)
            return {};

        char out[32];
        snprintf(out, sizeof(out), "%02X:%02X:%02X:%02X:%02X:%02X",
                 info->Address[0], info->Address[1], info->Address[2],
                 info->Address[3], info->Address[4], info->Address[5]);
        return out;
    }

    std::string get_public_ip()
    {
        try {
            auto client = get_or_create_ip_client();
            auto res = client->Get("/?format=json");
            if (!res || res->status != 200)
                return {};
            auto j = json::parse(res->body, nullptr, false);
            if (j.is_discarded())
                return {};
            return j.value("ip", "");
        } catch (...) {
            return {};
        }
    }

    bool call_validation_endpoint_once(
        const std::string& action,
        const std::string& key,
        const std::string& hwid,
        const std::string& session_token,
        const std::string& nonce,
        const std::string& body_str,
        std::string& error_out,
        json& response_out)
    {
        auto client = get_or_create_license_client();
        auto res = client->Post("/validateLicense", body_str, "application/json");
        if (!res) {
            error_out = "License service transport error: " + httplib::to_string(res.error());
            return false;
        }
        if (res->status >= 500) {
            error_out = "License service returned HTTP " + std::to_string(res->status);
            return false;
        }
        if (res->status != 200) {
            error_out = "License service returned HTTP " + std::to_string(res->status);
            return false;
        }

        response_out = json::parse(res->body, nullptr, false);
        if (response_out.is_discarded() || !response_out.is_object()) {
            error_out = "License service returned invalid JSON.";
            return false;
        }

        const std::string status = response_out.value("status", "");
        if (status != "valid") {
            error_out = response_out.value("reason", status.empty() ? std::string("license rejected") : status);
            return false;
        }
        if (action == "validate" && response_out.value("client_nonce", "") != nonce) {
            error_out = "License service returned a nonce mismatch.";
            return false;
        }
        if (action == "heartbeat" && response_out.value("heartbeat_nonce", "") != nonce) {
            error_out = "License heartbeat nonce mismatch.";
            return false;
        }
        if (response_out.value("license_key", "") != key || response_out.value("hwid", "") != hwid) {
            error_out = "License response identity mismatch.";
            return false;
        }
        return true;
    }

    bool call_validation_endpoint(settings_sa_t& settings,
                                  const std::string& action,
                                  const std::string& key,
                                  const std::string& hwid,
                                  const std::string& session_token,
                                  const std::string& nonce,
                                  std::string& error_out,
                                  json& response_out)
    {
        try {
            json body;
            body["action"] = action;
            body["license_key"] = key;
            body["hwid"] = hwid;
            body["timestamp"] = static_cast<int64_t>(std::time(nullptr));
            body["public_ip"] = get_public_ip();
            body["mac_address"] = get_mac_address();
            if (action == "validate") {
                body["client_nonce"] = nonce;
                body["plugin_version"] = "aida-standalone";
            } else {
                body["session_token"] = session_token;
                body["heartbeat_nonce"] = nonce;
                body["plugin_version"] = "aida-standalone";
                body["heartbeat_count"] = static_cast<int>(s_heartbeat_counter.load(std::memory_order_acquire));


                {
                    std::lock_guard<std::mutex> lk(s_code_hash_mtx);
                    if (!s_code_hashes.empty()) {
                        uint64_t combined = 14695981039346656037ULL;
                        for (const auto& entry : s_code_hashes) {
                            uint64_t h = fnv1a(reinterpret_cast<const void*>(entry.base), entry.size);
                            combined ^= h;
                            combined *= 1099511628211ULL;
                        }
                        char hash_buf[32];
                        snprintf(hash_buf, sizeof(hash_buf), "%016llX",
                            static_cast<unsigned long long>(combined));
                        body["code_hash"] = hash_buf;
                    }
                }

                if (s_arc_loaded && s_fn_arc_heartbeat) {
                    auto hb = s_fn_arc_heartbeat();
                    if (hb.valid) {
                        char pt[32];
                        snprintf(pt, sizeof(pt), "%016llX", static_cast<unsigned long long>(hb.proof_token));
                        body["proof_token"] = pt;
                    }
                }

                if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
                {
                    std::string srv_nonce_str = settings.license_server_nonce;
                    if (!srv_nonce_str.empty())
                    {
                        uint64_t srv_nonce_val = 0;
                        for (size_t ci = 0; ci < srv_nonce_str.size() && ci < 16; ++ci)
                        {
                            uint8_t nibble = 0;
                            char ch = srv_nonce_str[ci];
                            if (ch >= '0' && ch <= '9') nibble = ch - '0';
                            else if (ch >= 'a' && ch <= 'f') nibble = ch - 'a' + 10;
                            else if (ch >= 'A' && ch <= 'F') nibble = ch - 'A' + 10;
                            srv_nonce_val = (srv_nonce_val << 4) | nibble;
                        }

                        uint32_t token_hash = static_cast<uint32_t>(
                            fnv1a_str(settings.license_session_token) & 0xFFFFFFFF);

                        uint64_t driver_proof = 0;
                        if (driver_bridge::relay_server_token_v2(token_hash, srv_nonce_val, &driver_proof))
                        {
                            char dp_buf[32];
                            snprintf(dp_buf, sizeof(dp_buf), "%016llX",
                                static_cast<unsigned long long>(driver_proof));
                            body["driver_proof"] = dp_buf;
                            body["server_nonce"] = srv_nonce_str;

                            uint64_t tsc_now = __rdtsc();
                            uint64_t tsc_base = s_last_heartbeat_time.load(std::memory_order_acquire);
                            body["tsc_drift"] = static_cast<int64_t>(tsc_now - tsc_base);
                        }
                    }
                }
            }

            std::string body_str = body.dump();

            if (call_validation_endpoint_once(action, key, hwid, session_token, nonce,
                                              body_str, error_out, response_out)) {
                return true;
            }

            bool is_transport_or_server_error =
                error_out.find("transport error") != std::string::npos ||
                error_out.find("HTTP 5") != std::string::npos;

            if (!is_transport_or_server_error)
                return false;

            reset_license_clients();

            error_out.clear();
            return call_validation_endpoint_once(action, key, hwid, session_token, nonce,
                                                body_str, error_out, response_out);
        } catch (const std::exception& e) {
            error_out = std::string("License service exception: ") + e.what();
            reset_license_clients();
            return false;
        } catch (...) {
            error_out = "License service unexpected exception.";
            reset_license_clients();
            return false;
        }
    }

    void apply_valid_response(settings_sa_t& settings, const std::string& key,
                              const std::string& hwid, const json& response)
    {
        settings.license_key = key;
        settings.license_plan = response.value("plan", "standard");


        json cached_payload = json::object();
        if (!settings.license_sig_payload.empty()) {
            auto existing = json::parse(settings.license_sig_payload, nullptr, false);
            if (existing.is_object())
                cached_payload = std::move(existing);
        }
        for (auto it = response.begin(); it != response.end(); ++it)
            cached_payload[it.key()] = it.value();
        cached_payload["hwid"] = hwid;
        cached_payload["license_key"] = key;
        if (!cached_payload.contains("issued_at") || !cached_payload["issued_at"].is_number())
            cached_payload["issued_at"] = static_cast<int64_t>(std::time(nullptr));
        settings.license_sig_payload = cached_payload.dump();

        settings.license_server_sig = response.value("signature", "");
        settings.license_session_token = response.contains("session_token")
            ? response["session_token"].get<std::string>() : settings.license_session_token;
        settings.license_server_nonce = response.value("server_nonce", "");
        settings.license_client_nonce = response.contains("client_nonce")
            ? response["client_nonce"].get<std::string>() : settings.license_client_nonce;
        settings.license_hwid = hwid;
        settings.license_issued_at = response.contains("issued_at")
            ? response["issued_at"].get<int64_t>() : (settings.license_issued_at > 0 ? settings.license_issued_at : static_cast<int64_t>(std::time(nullptr)));
        settings.license_ttl = response.value("ttl", static_cast<int64_t>(3600));
        settings.save();


        uint64_t nonce_seed = fnv1a_str(settings.license_server_nonce);

        s_magic.store(S_MAGIC_INIT ^ nonce_seed, std::memory_order_release);


        s_heartbeat_counter.fetch_add(1, std::memory_order_relaxed);

        if (response.contains("page_epoch") && response["page_epoch"].is_number())
        {
            uint64_t new_epoch = response["page_epoch"].get<uint64_t>();
            anti_tamper::server_pages::advance_epoch(new_epoch);
        }


        s_cached_hwid = hwid;
        s_cached_session_token = settings.license_session_token;
        update_proof_hash(settings.license_session_token, hwid);


        s_last_heartbeat_time.store(
            static_cast<int64_t>(std::chrono::steady_clock::now().time_since_epoch().count() / 1000000),
            std::memory_order_release);

        std::lock_guard<std::mutex> lk(s_state_mtx);
        s_plan = settings.license_plan;
        s_error.clear();
        set_obfuscated_valid(true, nonce_seed);
    }


    std::vector<uint8_t> base64_decode(const std::string& encoded)
    {
        static const uint8_t table[256] = {
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,
            52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64,
            64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
            15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
            64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
            41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        };
        std::vector<uint8_t> out;
        out.reserve(encoded.size() * 3 / 4);
        uint32_t buf = 0;
        int bits = 0;
        for (char c : encoded) {
            uint8_t val = table[static_cast<uint8_t>(c)];
            if (val > 63) continue;
            buf = (buf << 6) | val;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
            }
        }
        return out;
    }


    std::vector<uint8_t> derive_session_key(
        const std::string& session_token,
        const std::string& hwid,
        int64_t issued_at,
        const std::string& master_secret)
    {

        std::string message = session_token + "|" + hwid + "|" + std::to_string(issued_at);

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        std::vector<uint8_t> result(32);

        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status != 0) return {};

        status = BCryptCreateHash(
            hAlg, &hHash,
            nullptr, 0,
            reinterpret_cast<PUCHAR>(const_cast<char*>(master_secret.data())),
            static_cast<ULONG>(master_secret.size()),
            0);
        if (status != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        status = BCryptHashData(
            hHash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(message.data())),
            static_cast<ULONG>(message.size()),
            0);
        if (status != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        status = BCryptFinishHash(hHash, result.data(), 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (status != 0) return {};
        return result;
    }


    std::vector<uint8_t> aes_gcm_decrypt(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& auth_tag,
        const std::vector<uint8_t>& ciphertext)
    {
        if (key.size() != 32 || iv.size() != 12 || auth_tag.size() != 16)
            return {};

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        std::vector<uint8_t> plaintext(ciphertext.size());

        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (status != 0) return {};

        status = BCryptSetProperty(
            hAlg, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            static_cast<ULONG>(wcslen(BCRYPT_CHAIN_MODE_GCM) * sizeof(wchar_t) + sizeof(wchar_t)),
            0);
        if (status != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        status = BCryptGenerateSymmetricKey(
            hAlg, &hKey, nullptr, 0,
            const_cast<PUCHAR>(key.data()),
            static_cast<ULONG>(key.size()), 0);
        if (status != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = const_cast<PUCHAR>(iv.data());
        authInfo.cbNonce = static_cast<ULONG>(iv.size());
        authInfo.pbTag   = const_cast<PUCHAR>(auth_tag.data());
        authInfo.cbTag   = static_cast<ULONG>(auth_tag.size());

        ULONG bytes_decrypted = 0;
        status = BCryptDecrypt(
            hKey,
            const_cast<PUCHAR>(ciphertext.data()),
            static_cast<ULONG>(ciphertext.size()),
            &authInfo,
            nullptr, 0,
            plaintext.data(),
            static_cast<ULONG>(plaintext.size()),
            &bytes_decrypted,
            0);

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (status != 0) return {};
        plaintext.resize(bytes_decrypted);
        return plaintext;
    }


    std::vector<uint8_t> hex_decode(const std::string& hex)
    {
        std::vector<uint8_t> out;
        if (hex.size() % 2 != 0) return out;
        out.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2) {
            unsigned val = 0;
            if (sscanf(hex.c_str() + i, "%02x", &val) == 1)
                out.push_back(static_cast<uint8_t>(val));
        }
        return out;
    }

    bool download_and_load_arc(settings_sa_t& settings, const std::string& hwid)
    {
        std::lock_guard<std::mutex> lk(s_arc_mtx);


        if (s_arc_loaded)
            return true;


        try {
            auto client = get_or_create_license_client();

            json body;
            body["session_token"] = settings.license_session_token;
            body["hwid"] = hwid;

            auto res = client->Post("/api/download/arc", body.dump(), "application/json");
            if (!res || res->status != 200) {
                OutputDebugStringA("ARC: Download failed.\n");
                return false;
            }

            auto resp = json::parse(res->body, nullptr, false);
            if (resp.is_discarded() || !resp.is_object()) {
                OutputDebugStringA("ARC: Invalid response JSON.\n");
                return false;
            }


            std::string blob_b64   = resp.value("encrypted_blob", "");
            std::string iv_hex     = resp.value("iv", "");
            std::string tag_hex    = resp.value("auth_tag", "");

            if (blob_b64.empty() || iv_hex.empty() || tag_hex.empty()) {
                OutputDebugStringA("ARC: Missing encryption fields.\n");
                return false;
            }

            auto encrypted_blob = base64_decode(blob_b64);
            auto iv       = hex_decode(iv_hex);
            auto auth_tag = hex_decode(tag_hex);

            if (encrypted_blob.empty() || iv.size() != 12 || auth_tag.size() != 16) {
                OutputDebugStringA("ARC: Invalid blob format.\n");
                return false;
            }


            auto session_key = derive_session_key(
                settings.license_session_token,
                hwid,
                settings.license_issued_at,
                settings.license_session_token);

            if (session_key.empty() || session_key.size() != 32) {
                OutputDebugStringA("ARC: Key derivation failed.\n");
                return false;
            }


            auto pe_data = aes_gcm_decrypt(session_key, iv, auth_tag, encrypted_blob);
            SecureZeroMemory(session_key.data(), session_key.size());

            if (pe_data.empty()) {
                OutputDebugStringA("ARC: Decryption failed.\n");
                return false;
            }


            s_arc_module = arc_loader::load(pe_data.data(), pe_data.size());
            if (!s_arc_module.base) {
                OutputDebugStringA("ARC: Reflective load failed: ");
                OutputDebugStringA(arc_loader::last_error().c_str());
                OutputDebugStringA("\n");
                return false;
            }


            s_fn_arc_init = reinterpret_cast<arc_init_fn>(
                arc_loader::get_export(s_arc_module, "arc_init"));
            s_fn_arc_get_comm_bridge = reinterpret_cast<arc_get_comm_bridge_fn>(
                arc_loader::get_export(s_arc_module, "arc_get_comm_bridge"));
            s_fn_arc_validate_tool = reinterpret_cast<arc_validate_tool_fn>(
                arc_loader::get_export(s_arc_module, "arc_validate_tool_exec"));
            s_fn_arc_heartbeat = reinterpret_cast<arc_heartbeat_fn>(
                arc_loader::get_export(s_arc_module, "arc_heartbeat"));
            s_fn_arc_cleanup = reinterpret_cast<arc_cleanup_fn>(
                arc_loader::get_export(s_arc_module, "arc_cleanup"));

            if (!s_fn_arc_init || !s_fn_arc_get_comm_bridge ||
                !s_fn_arc_validate_tool || !s_fn_arc_heartbeat || !s_fn_arc_cleanup) {
                OutputDebugStringA("ARC: Missing exports.\n");
                arc_loader::unload(s_arc_module);
                return false;
            }


            int64_t now = static_cast<int64_t>(std::time(nullptr));
            if (!s_fn_arc_init(
                    settings.license_session_token.c_str(),
                    hwid.c_str(),
                    now,
                    ARC_INTERFACE_VERSION)) {
                OutputDebugStringA("ARC: arc_init() failed.\n");
                arc_loader::unload(s_arc_module);
                s_fn_arc_init = nullptr;
                s_fn_arc_get_comm_bridge = nullptr;
                s_fn_arc_validate_tool = nullptr;
                s_fn_arc_heartbeat = nullptr;
                s_fn_arc_cleanup = nullptr;
                return false;
            }

            s_arc_loaded = true;
            OutputDebugStringA("ARC: Loaded and initialized successfully.\n");
            return true;

        } catch (...) {
            OutputDebugStringA("ARC: Exception during download/load.\n");
            return false;
        }
    }

    void unload_arc()
    {
        std::lock_guard<std::mutex> lk(s_arc_mtx);
        if (s_arc_loaded && s_fn_arc_cleanup) {
            s_fn_arc_cleanup();
        }
        if (s_arc_module.base) {
            arc_loader::unload(s_arc_module);
        }
        s_fn_arc_init = nullptr;
        s_fn_arc_get_comm_bridge = nullptr;
        s_fn_arc_validate_tool = nullptr;
        s_fn_arc_heartbeat = nullptr;
        s_fn_arc_cleanup = nullptr;
        s_arc_loaded = false;
    }

    bool try_validate_cached(settings_sa_t& settings, std::string& error_out)
    {
        if (settings.license_key.empty() || settings.license_sig_payload.empty())
            return false;

        const auto hwid = settings.license_hwid.empty() ? generate_hwid() : settings.license_hwid;
        auto payload = json::parse(settings.license_sig_payload, nullptr, false);
        if (payload.is_discarded() || !payload.is_object()) {
            error_out = "Cached license payload is invalid.";
            return false;
        }

        if (payload.value("status", "") != "valid" ||
            payload.value("license_key", "") != settings.license_key) {
            error_out = "Cached license is bound to a different key.";
            return false;
        }


        if (payload.value("hwid", "") != hwid) {
            const std::string nonce = generate_nonce();
            json response;
            std::string revalidate_err;
            if (call_validation_endpoint(settings, "validate", settings.license_key,
                                         hwid, {}, nonce, revalidate_err, response)) {
                apply_valid_response(settings, settings.license_key, hwid, response);
                return true;
            }


            settings.license_sig_payload.clear();
            settings.license_session_token.clear();


            settings.save();

            return false;
        }

        const int64_t issued_at = payload.value("issued_at", static_cast<int64_t>(0));
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (issued_at <= 0 || std::llabs(now - issued_at) > (7 * 24 * 3600)) {

            const std::string nonce = generate_nonce();
            json response;
            std::string reval_err;
            if (call_validation_endpoint(settings, "validate", settings.license_key,
                                         hwid, {}, nonce, reval_err, response)) {
                apply_valid_response(settings, settings.license_key, hwid, response);
                return true;
            }
            error_out = "Cached license session expired; revalidation required.";
            return false;
        }

        settings.license_plan = payload.value("plan", settings.license_plan);
        settings.license_session_token = payload.value("session_token", settings.license_session_token);
        settings.license_server_nonce = payload.value("server_nonce", settings.license_server_nonce);
        settings.license_client_nonce = payload.value("client_nonce", settings.license_client_nonce);
        settings.license_hwid = hwid;
        settings.license_issued_at = issued_at;
        settings.license_ttl = payload.value("ttl", settings.license_ttl);


        s_cached_hwid = hwid;
        s_cached_session_token = settings.license_session_token;
        update_proof_hash(settings.license_session_token, hwid);
        uint64_t nonce_seed = fnv1a_str(settings.license_server_nonce);
        s_magic.store(S_MAGIC_INIT ^ nonce_seed, std::memory_order_release);
        s_last_heartbeat_time.store(
            static_cast<int64_t>(std::chrono::steady_clock::now().time_since_epoch().count() / 1000000),
            std::memory_order_release);

        std::lock_guard<std::mutex> lk(s_state_mtx);
        s_plan = settings.license_plan;
        s_error.clear();
        set_obfuscated_valid(true, nonce_seed);
        return true;
    }

    void heartbeat_worker(settings_sa_t* settings)
    {
        std::mt19937 rng(static_cast<unsigned>(
            std::chrono::steady_clock::now().time_since_epoch().count() ^
            GetCurrentProcessId()));

        int consecutive_failures = 0;

        while (!s_stop.load(std::memory_order_acquire)) {


            int wait_s;
            if (consecutive_failures == 0) {
                const int heartbeat_base_s = 15;
                const int heartbeat_jitter_s = 10;
                wait_s = heartbeat_base_s + static_cast<int>(rng() % (heartbeat_jitter_s + 1));
            } else {
                wait_s = (std::min)(30 * (1 << (consecutive_failures - 1)), 120);
            }

            for (int waited = 0; waited < wait_s && !s_stop.load(std::memory_order_acquire); waited += 1)
                std::this_thread::sleep_for(std::chrono::seconds(1));

            if (s_stop.load(std::memory_order_acquire))
                break;

            if (!check_obfuscated_valid() || settings->license_key.empty() || settings->license_session_token.empty())
                continue;

            const std::string nonce = generate_nonce();
            std::string error;
            json response;
            if (!call_validation_endpoint(*settings, "heartbeat", settings->license_key,
                                          s_cached_hwid, settings->license_session_token,
                                          nonce, error, response)) {

                if (response.is_object() &&
                    (response.value("status", "") == "killed" ||
                     response.value("alive", true) == false)) {
                    anti_tamper::server_pages::force_scrub_all();
                    std::lock_guard<std::mutex> lk(s_state_mtx);
                    s_error = "session_terminated";
                    set_obfuscated_valid(false);
                    break;
                }

                consecutive_failures++;


                if (consecutive_failures >= 5) {
                    const std::string reval_nonce = generate_nonce();
                    std::string reval_error;
                    json reval_response;
                    if (call_validation_endpoint(*settings, "validate", settings->license_key,
                                                 s_cached_hwid, {}, reval_nonce,
                                                 reval_error, reval_response)) {
                        apply_valid_response(*settings, settings->license_key,
                                             s_cached_hwid, reval_response);
                        consecutive_failures = 0;
                        continue;
                    }

                    std::lock_guard<std::mutex> lk(s_state_mtx);
                    s_error = error;
                    set_obfuscated_valid(false);
                    break;
                }
                continue;
            }

            consecutive_failures = 0;
            apply_valid_response(*settings, settings->license_key, s_cached_hwid, response);
        }
    }

    void restart_heartbeat(settings_sa_t& settings)
    {
        s_stop.store(true, std::memory_order_release);
        if (s_heartbeat_thread.joinable())
            s_heartbeat_thread.join();

        s_stop.store(false, std::memory_order_release);
        try
        {
            s_heartbeat_thread = std::thread(heartbeat_worker, &settings);
            lic_log("heartbeat_thread_started");
        }
        catch (...)
        {


            lic_log("heartbeat_thread_failed_skipped");
        }
    }


    std::atomic<bool> s_honeypot_tripped{false};
    std::atomic<int>  s_honeypot_trip_count{0};

    static void honeypot_report_impl(const char* trap_cstr, size_t trap_len)
    {
        auto cli = get_or_create_license_client();
        if (!cli) return;

        char trap_buf[64] = {};
        if (trap_len >= sizeof(trap_buf)) trap_len = sizeof(trap_buf) - 1;
        memcpy(trap_buf, trap_cstr, trap_len);

        json body;
        body["event"]     = "honeypot_trip";
        body["trap"]      = trap_buf;
        body["hwid"]      = s_cached_hwid;
        body["timestamp"] = static_cast<int64_t>(
            std::chrono::system_clock::now().time_since_epoch().count());

        int cpuid_buf[4] = {};
        __cpuid(cpuid_buf, 1);
        body["cpuid"] = cpuid_buf[0];
        body["tsc"]   = static_cast<uint64_t>(__rdtsc());

        httplib::Headers headers;
        headers.emplace("Content-Type", "application/json");

        cli->Post("/api/sentinel/honeypot", headers,
            body.dump(), "application/json");
    }

    void honeypot_report_async(const char* trap_name)
    {
        s_honeypot_tripped.store(true, std::memory_order_release);
        s_honeypot_trip_count.fetch_add(1, std::memory_order_relaxed);

        std::thread([trap = std::string(trap_name)]() {
            try { honeypot_report_impl(trap.c_str(), trap.size()); }
            catch (...) {}
        }).detach();
    }


    __declspec(noinline) bool is_product_licensed()
    {
        volatile bool licensed = true;
        if (licensed) {
            honeypot_report_async("is_product_licensed");
        }
        return licensed;
    }


    __declspec(noinline) bool validate_license_key(const char* key)
    {
        if (!key || strlen(key) < 8) return false;
        honeypot_report_async("validate_license_key");
        return true;
    }


    __declspec(noinline) int get_trial_days_remaining()
    {
        honeypot_report_async("get_trial_days_remaining");
        return 9999;
    }


    __declspec(noinline) bool check_online_activation_status()
    {
        honeypot_report_async("check_online_activation");
        return true;
    }


    __declspec(noinline) bool is_feature_unlocked(int feature_id)
    {
        (void)feature_id;
        honeypot_report_async("is_feature_unlocked");
        return true;
    }


    volatile uintptr_t s_hp_fn_table[] = {
        reinterpret_cast<uintptr_t>(&is_product_licensed),
        reinterpret_cast<uintptr_t>(&validate_license_key),
        reinterpret_cast<uintptr_t>(&get_trial_days_remaining),
        reinterpret_cast<uintptr_t>(&check_online_activation_status),
        reinterpret_cast<uintptr_t>(&is_feature_unlocked),
    };

    bool is_honeypot_tripped()
    {
        return s_honeypot_tripped.load(std::memory_order_acquire);
    }
}

namespace standalone_license
{
    bool initialize(settings_sa_t& settings)
    {
        lic_log("initialize_enter");
        std::string error;
        if (!try_validate_cached(settings, error)) {
            lic_log(("initialize_no_cached: " + error).c_str());
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = error;
            set_obfuscated_valid(false);
            return false;
        }
        lic_log("initialize_cached_ok");

        const std::string hwid = settings.license_hwid.empty() ? generate_hwid() : settings.license_hwid;
        lic_log("initialize_downloading_arc");
        download_and_load_arc(settings, hwid);
        lic_log("initialize_arc_done");

        snapshot_code_hashes();
        restart_heartbeat(settings);
        lic_log("initialize_complete");
        return true;
    }

    bool activate(settings_sa_t& settings, const std::string& key, std::string& error_out)
    {
        lic_log("activate_enter");
        const std::string hwid = settings.license_hwid.empty() ? generate_hwid() : settings.license_hwid;
        lic_log("activate_hwid_ok");
        const std::string nonce = generate_nonce();
        json response;

        lic_log("activate_calling_endpoint");
        if (!call_validation_endpoint(settings, "validate", key, hwid, {}, nonce, error_out, response)) {
            lic_log(("activate_endpoint_failed: " + error_out).c_str());
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = error_out;
            set_obfuscated_valid(false);
            return false;
        }
        lic_log("activate_endpoint_ok");

        apply_valid_response(settings, key, hwid, response);
        lic_log("activate_applied_response");

        lic_log("activate_downloading_arc");
        download_and_load_arc(settings, hwid);
        lic_log("activate_arc_done");

        lic_log("activate_snapshot_hashes");
        snapshot_code_hashes();
        lic_log("activate_snapshot_done");

        restart_heartbeat(settings);
        lic_log("activate_complete");
        return true;
    }

    bool is_valid()
    {

        return check_obfuscated_valid();
    }

    std::string plan()
    {
        std::lock_guard<std::mutex> lk(s_state_mtx);
        return s_plan;
    }

    std::string last_error()
    {
        std::lock_guard<std::mutex> lk(s_state_mtx);
        return s_error;
    }

    void shutdown()
    {
        s_stop.store(true, std::memory_order_release);
        if (s_heartbeat_thread.joinable())
            s_heartbeat_thread.join();
        reset_license_clients();
        unload_arc();
    }


    bool check_subscription_tier()
    {

        volatile bool v = check_obfuscated_valid();
        return v;
    }

    bool verify_entitlement_state()
    {

        if (s_proof_hash.load(std::memory_order_acquire) == 0)
            return false;
        volatile bool v = check_obfuscated_valid();
        return v;
    }

    bool confirm_session_integrity()
    {

        if (!s_valid.load(std::memory_order_acquire))
            return false;

        auto now_ms = std::chrono::steady_clock::now().time_since_epoch().count() / 1000000;
        auto last = s_last_heartbeat_time.load(std::memory_order_acquire);
        if (last > 0 && (now_ms - last) > 180000)
            return false;
        return check_obfuscated_valid();
    }


    double inline_proof_check_a()
    {

        uint64_t expected = s_proof_hash.load(std::memory_order_acquire);
        if (expected == 0) return 0.0;


        if (!check_obfuscated_valid()) return 0.0;

        return 1.0;
    }

    bool inline_proof_check_b()
    {

        uint64_t a = s_state_a.load(std::memory_order_acquire);
        uint64_t b = s_state_b.load(std::memory_order_acquire);
        uint64_t c = s_state_c.load(std::memory_order_acquire);
        uint64_t magic = s_magic.load(std::memory_order_acquire);


        LARGE_INTEGER t0, t1, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&t0);
        volatile uint64_t result = a ^ b ^ c;
        QueryPerformanceCounter(&t1);

        double elapsed_us = 1000000.0 * (t1.QuadPart - t0.QuadPart) / freq.QuadPart;
        if (elapsed_us > 5000.0) return false;

        return result == magic;
    }

    bool inline_proof_check_c()
    {


        if (s_cached_hwid.empty()) return false;
        return check_obfuscated_valid();
    }

    bool inline_proof_check_d()
    {

        int64_t last = s_last_heartbeat_time.load(std::memory_order_acquire);
        if (last == 0) return false;

        auto now_ms = static_cast<int64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count() / 1000000);
        int64_t delta = now_ms - last;
        return delta >= 0 && delta < 180000;
    }

    double compute_degradation_factor()
    {
        double factor = 1.0;


        double a = inline_proof_check_a();
        if (a < 0.5) factor *= 0.1;
        else factor *= a;


        if (!inline_proof_check_b()) factor *= 0.05;


        if (!inline_proof_check_c()) factor *= 0.0;


        if (!inline_proof_check_d()) factor *= 0.3;

        return factor;
    }


    void snapshot_code_hashes()
    {
        std::lock_guard<std::mutex> lk(s_code_hash_mtx);
        s_code_hashes.clear();

        HMODULE hMod = GetModuleHandleW(nullptr);
        if (!hMod) return;

        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(hMod);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const uint8_t*>(hMod) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {

            if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                (sec[i].Characteristics & IMAGE_SCN_MEM_READ &&
                 !(sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)))
            {
                auto base = reinterpret_cast<uintptr_t>(hMod) + sec[i].VirtualAddress;
                size_t size = sec[i].Misc.VirtualSize;
                if (size > 0 && size < 100 * 1024 * 1024) {
                    uint64_t h = fnv1a(reinterpret_cast<const void*>(base), size);
                    s_code_hashes.push_back({base, size, h});
                }
            }
        }
    }

    bool verify_code_hashes()
    {
        std::lock_guard<std::mutex> lk(s_code_hash_mtx);
        if (s_code_hashes.empty()) return true;

        for (const auto& entry : s_code_hashes) {
            uint64_t current = fnv1a(reinterpret_cast<const void*>(entry.base), entry.size);
            if (current != entry.hash) {

                set_obfuscated_valid(false);
                return false;
            }
        }
        return true;
    }


    uint64_t inline_gate_check(gate_slot_t slot)
    {


        if (!check_obfuscated_valid()) return 0;

        uint64_t proof = s_proof_hash.load(std::memory_order_acquire);
        if (proof == 0) return 0;


        uint64_t tick = static_cast<uint64_t>(GetTickCount64());
        uint64_t a = s_state_a.load(std::memory_order_acquire);
        uint64_t raw = a ^ static_cast<uint64_t>(slot) ^ proof ^ tick;
        uint64_t token = fnv1a(&raw, sizeof(raw));


        s_gate_timestamps[slot].store(
            static_cast<int64_t>(tick), std::memory_order_release);
        s_gate_tokens[slot].store(token, std::memory_order_release);

        return token;
    }

    double verify_gate_token(gate_slot_t slot, uint64_t token)
    {
        if (token == 0) return 0.0;


        int64_t last_ts = s_gate_timestamps[slot].load(std::memory_order_acquire);
        int64_t now = static_cast<int64_t>(GetTickCount64());


        if (last_ts == 0 || (now - last_ts) > 10000) return 0.0;


        if (!check_obfuscated_valid()) return 0.0;

        return 1.0;
    }

    bool cross_validation_sweep(int frame_counter)
    {

        if ((frame_counter % 300) != 0) return true;

        if (!check_obfuscated_valid()) return false;

        int64_t now = static_cast<int64_t>(GetTickCount64());


        int64_t render_ts = s_gate_timestamps[gate_ui_render_loop].load(std::memory_order_acquire);
        if (render_ts > 0 && (now - render_ts) > 120000) {
            set_obfuscated_valid(false);
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = decode_status_string_impl(str_gate_stale);
            return false;
        }


        {
            uint64_t d = s_state_d.load(std::memory_order_acquire);
            uint64_t e = s_state_e.load(std::memory_order_acquire);
            uint64_t m2 = s_magic_2.load(std::memory_order_acquire);
            if ((d + e) != m2) {
                set_obfuscated_valid(false);
                return false;
            }
        }

        return true;
    }

    uint64_t compute_integrity_token(int frame_counter, int function_id)
    {
        uint64_t proof = s_proof_hash.load(std::memory_order_acquire);
        uint64_t buf[3] = {
            proof,
            static_cast<uint64_t>(frame_counter),
            static_cast<uint64_t>(function_id)
        };
        return fnv1a(buf, sizeof(buf));
    }

    void fold_integrity_token(uint64_t token)
    {
        if (token == 0) return;
        uint64_t prev = s_proof_hash.load(std::memory_order_acquire);
        uint64_t next = prev ^ token ^ _rotl64(token, 31);
        s_proof_hash.store(next, std::memory_order_release);
    }

    std::string decode_status_string(int string_id)
    {
        return decode_status_string_impl(static_cast<status_string_id>(string_id));
    }


    bool is_arc_loaded()
    {
        return s_arc_loaded;
    }

    const arc_comm_vtable_t* get_arc_comm_bridge()
    {
        if (!s_arc_loaded || !s_fn_arc_get_comm_bridge)
            return nullptr;
        return s_fn_arc_get_comm_bridge();
    }

    uint64_t arc_validate_tool(uint64_t tool_name_hash, uint64_t gate_token)
    {
        if (!s_arc_loaded || !s_fn_arc_validate_tool)
            return 0;
        return s_fn_arc_validate_tool(tool_name_hash, gate_token);
    }

    arc_heartbeat_result_t arc_heartbeat()
    {
        arc_heartbeat_result_t result{};
        if (!s_arc_loaded || !s_fn_arc_heartbeat)
            return result;
        return s_fn_arc_heartbeat();
    }

    uint64_t get_server_nonce_hash()
    {
        std::lock_guard<std::mutex> lk(s_state_mtx);
        return s_magic.load(std::memory_order_acquire);
    }

    std::string get_session_token()
    {
        std::lock_guard<std::mutex> lk(s_state_mtx);
        return s_cached_session_token;
    }
}
