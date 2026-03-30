#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "standalone_license.hpp"

#include "standalone_settings.hpp"

#include <windows.h>
#include <iphlpapi.h>
#include <intrin.h>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")

using json = nlohmann::json;

namespace
{
    std::atomic<bool> s_valid{false};
    std::atomic<bool> s_stop{false};
    std::thread       s_heartbeat_thread;
    std::mutex        s_state_mtx;
    std::string       s_plan;
    std::string       s_error;

    std::string get_cloud_function_host()
    {
        return "https://europe-west1-aida-license-prod.cloudfunctions.net";
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
        GetComputerNameW(computer_name, &name_size);
        for (DWORD i = 0; i < name_size; ++i)
            mix(static_cast<uint64_t>(computer_name[i]));

        int cpu_info[4] = {};
        __cpuid(cpu_info, 1);
        mix((static_cast<uint64_t>(cpu_info[0]) << 32) | static_cast<unsigned>(cpu_info[1]));
        mix((static_cast<uint64_t>(cpu_info[2]) << 32) | static_cast<unsigned>(cpu_info[3]));

        DWORD volume_serial = 0;
        GetVolumeInformationW(L"C:\\", nullptr, 0, &volume_serial, nullptr, nullptr, nullptr, 0);
        mix(volume_serial);

        ULONG len = 0;
        GetAdaptersInfo(nullptr, &len);
        if (len > 0) {
            std::vector<unsigned char> buffer(len);
            auto* info = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
            if (GetAdaptersInfo(info, &len) == NO_ERROR && info) {
                for (UINT i = 0; i < info->AddressLength; ++i)
                    mix(info->Address[i]);
            }
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
            httplib::Client client("https://api.ipify.org");
            client.set_connection_timeout(5);
            client.set_read_timeout(5);
            client.enable_server_certificate_verification(false);
            auto res = client.Get("/?format=json");
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

    bool call_validation_endpoint(settings_sa_t& /*settings*/,
                                  const std::string& action,
                                  const std::string& key,
                                  const std::string& hwid,
                                  const std::string& session_token,
                                  const std::string& nonce,
                                  std::string& error_out,
                                  json& response_out)
    {
        try {
            httplib::Client client(get_cloud_function_host());
            client.set_connection_timeout(15);
            client.set_read_timeout(20);
            client.set_write_timeout(10);
            client.set_follow_location(true);
            client.enable_server_certificate_verification(false);

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
            }

            auto res = client.Post("/validateLicense", body.dump(), "application/json");
            if (!res) {
                error_out = "License service transport error: " + httplib::to_string(res.error());
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
        } catch (const std::exception& e) {
            error_out = std::string("License service exception: ") + e.what();
            return false;
        } catch (...) {
            error_out = "License service unexpected exception.";
            return false;
        }
    }

    void apply_valid_response(settings_sa_t& settings, const std::string& key,
                              const std::string& hwid, const json& response)
    {
        settings.license_key = key;
        settings.license_plan = response.value("plan", "standard");
        settings.license_sig_payload = response.dump();
        settings.license_server_sig = response.value("signature", "");
        settings.license_session_token = response.value("session_token", "");
        settings.license_server_nonce = response.value("server_nonce", "");
        settings.license_client_nonce = response.value("client_nonce", "");
        settings.license_hwid = hwid;
        settings.license_issued_at = response.value("issued_at", static_cast<int64_t>(std::time(nullptr)));
        settings.license_ttl = response.value("ttl", static_cast<int64_t>(3600));
        settings.save();

        std::lock_guard<std::mutex> lk(s_state_mtx);
        s_plan = settings.license_plan;
        s_error.clear();
        s_valid.store(true, std::memory_order_release);
    }

    bool try_validate_cached(settings_sa_t& settings, std::string& error_out)
    {
        if (settings.license_key.empty() || settings.license_sig_payload.empty())
            return false;

        const auto hwid = generate_hwid();
        auto payload = json::parse(settings.license_sig_payload, nullptr, false);
        if (payload.is_discarded() || !payload.is_object()) {
            error_out = "Cached license payload is invalid.";
            return false;
        }

        if (payload.value("status", "") != "valid" ||
            payload.value("license_key", "") != settings.license_key ||
            payload.value("hwid", "") != hwid) {
            error_out = "Cached license is bound to a different device or key.";
            return false;
        }

        const int64_t issued_at = payload.value("issued_at", static_cast<int64_t>(0));
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (issued_at <= 0 || std::llabs(now - issued_at) > (7 * 24 * 3600)) {
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

        std::lock_guard<std::mutex> lk(s_state_mtx);
        s_plan = settings.license_plan;
        s_error.clear();
        s_valid.store(true, std::memory_order_release);
        return true;
    }

    void heartbeat_worker(settings_sa_t* settings)
    {
        while (!s_stop.load(std::memory_order_acquire)) {
            const int64_t ttl = (std::max<int64_t>)(settings->license_ttl, 1800);
            for (int64_t waited = 0; waited < ttl && !s_stop.load(std::memory_order_acquire); waited += 5)
                std::this_thread::sleep_for(std::chrono::seconds(5));

            if (s_stop.load(std::memory_order_acquire))
                break;

            if (!s_valid.load(std::memory_order_acquire) || settings->license_key.empty() || settings->license_session_token.empty())
                continue;

            const std::string nonce = generate_nonce();
            std::string error;
            json response;
            if (!call_validation_endpoint(*settings, "heartbeat", settings->license_key,
                                          generate_hwid(), settings->license_session_token,
                                          nonce, error, response)) {
                std::lock_guard<std::mutex> lk(s_state_mtx);
                s_error = error;
                s_valid.store(false, std::memory_order_release);
                break;
            }

            apply_valid_response(*settings, settings->license_key, generate_hwid(), response);
        }
    }

    void restart_heartbeat(settings_sa_t& settings)
    {
        s_stop.store(true, std::memory_order_release);
        if (s_heartbeat_thread.joinable())
            s_heartbeat_thread.join();

        s_stop.store(false, std::memory_order_release);
        s_heartbeat_thread = std::thread(heartbeat_worker, &settings);
    }
}

namespace standalone_license
{
    bool initialize(settings_sa_t& settings)
    {
        std::string error;
        if (!try_validate_cached(settings, error)) {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = error;
            s_valid.store(false, std::memory_order_release);
            return false;
        }

        restart_heartbeat(settings);
        return true;
    }

    bool activate(settings_sa_t& settings, const std::string& key, std::string& error_out)
    {
        const std::string hwid = generate_hwid();
        const std::string nonce = generate_nonce();
        json response;

        if (!call_validation_endpoint(settings, "validate", key, hwid, {}, nonce, error_out, response)) {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = error_out;
            s_valid.store(false, std::memory_order_release);
            return false;
        }

        apply_valid_response(settings, key, hwid, response);
        restart_heartbeat(settings);
        return true;
    }

    bool is_valid()
    {
        return s_valid.load(std::memory_order_acquire);
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
    }
}
