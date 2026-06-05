#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "aida_ipc.hpp"

#include "aida_pro.hpp"

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <mutex>
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
