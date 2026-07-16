#define AIDA_C03_STANDALONE_AI_CANCEL_FIXTURE 1
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include "../../../../src/core/ai/standalone_ai_client.hpp"
#include "../../../../src/core/settings/standalone_settings.hpp"
#include "../../../../src/helpers/globals.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

void require(bool condition, const char* message)
{
    if (!condition)
        throw std::runtime_error(message);
}

bool starts_with_error(const std::string& value)
{
    return value.rfind("Error:", 0) == 0;
}

struct socket_owner_t
{
    SOCKET value = INVALID_SOCKET;

    socket_owner_t() = default;
    explicit socket_owner_t(SOCKET socket) noexcept : value(socket) {}
    socket_owner_t(const socket_owner_t&) = delete;
    socket_owner_t& operator=(const socket_owner_t&) = delete;

    ~socket_owner_t()
    {
        if (value != INVALID_SOCKET)
            closesocket(value);
    }
};

class loopback_server_t
{
public:
    enum class mode_t : uint8_t
    {
        success,
        incomplete,
        stream_success,
        residual_stream,
        hold,
        drop
    };

    loopback_server_t()
    {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
            throw std::runtime_error("Winsock initialization failed");
        winsock_started_ = true;
        listener_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener_ == INVALID_SOCKET)
            fail_startup("listener creation failed");

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (bind(listener_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0)
            fail_startup("listener bind failed");
        int size = sizeof(address);
        if (getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &size) != 0)
            fail_startup("listener port discovery failed");
        port_ = ntohs(address.sin_port);
        if (listen(listener_, 16) != 0)
            fail_startup("listener start failed");
        try {
            accept_thread_ = std::thread([this]() noexcept { accept_loop(); });
        } catch (...) {
            fail_startup("listener worker creation failed");
        }
    }

    loopback_server_t(const loopback_server_t&) = delete;
    loopback_server_t& operator=(const loopback_server_t&) = delete;

    ~loopback_server_t()
    {
        stop_.store(true, std::memory_order_release);
        release_hold();
        if (listener_ != INVALID_SOCKET) {
            closesocket(listener_);
            listener_ = INVALID_SOCKET;
        }
        if (accept_thread_.joinable())
            accept_thread_.join();
        std::vector<std::thread> workers;
        {
            std::lock_guard<std::mutex> lock(worker_mutex_);
            workers.swap(workers_);
        }
        for (auto& worker : workers) {
            if (worker.joinable())
                worker.join();
        }
        if (winsock_started_)
            WSACleanup();
    }

    void set_mode(mode_t mode)
    {
        if (mode == mode_t::hold) {
            std::unique_lock<std::mutex> lock(hold_mutex_);
            require(hold_drained_cv_.wait_for(lock, std::chrono::seconds(5), [this]() noexcept {
                return hold_active_ == 0;
            }), "previous held request did not drain");
            hold_released_ = false;
        }
        mode_.store(mode, std::memory_order_release);
    }

    std::string base_url() const
    {
        return "http://127.0.0.1:" + std::to_string(port_);
    }

    uint64_t accepted() const noexcept
    {
        return accepted_.load(std::memory_order_acquire);
    }

    void wait_accepted(uint64_t target)
    {
        std::unique_lock<std::mutex> lock(accepted_mutex_);
        require(accepted_cv_.wait_for(lock, std::chrono::seconds(5), [&]() {
            return accepted() >= target;
        }), "loopback request did not arrive before fixture deadline");
    }

    void release_hold()
    {
        std::lock_guard<std::mutex> lock(hold_mutex_);
        hold_released_ = true;
        hold_cv_.notify_all();
    }

private:
    void fail_startup(const char* message)
    {
        if (listener_ != INVALID_SOCKET) {
            closesocket(listener_);
            listener_ = INVALID_SOCKET;
        }
        if (winsock_started_) {
            WSACleanup();
            winsock_started_ = false;
        }
        throw std::runtime_error(message);
    }

    static bool send_all(SOCKET client, const std::string& response) noexcept
    {
        size_t sent = 0;
        while (sent < response.size()) {
            const int count = send(
                client, response.data() + sent,
                static_cast<int>((std::min)(response.size() - sent, size_t{1 << 20})), 0);
            if (count <= 0)
                return false;
            sent += static_cast<size_t>(count);
        }
        return true;
    }

    static std::string response_with_body(
        const std::string& content_type,
        const std::string& body,
        size_t declared_size)
    {
        return "HTTP/1.1 200 OK\r\nContent-Type: " + content_type
            + "\r\nContent-Length: " + std::to_string(declared_size)
            + "\r\nConnection: close\r\n\r\n" + body;
    }

    static void consume_request(SOCKET client) noexcept
    {
        DWORD timeout = 2000;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        std::string request;
        request.reserve(8192);
        char buffer[2048];
        size_t target = 0;
        while (request.size() < 1 << 20) {
            const int count = recv(client, buffer, sizeof(buffer), 0);
            if (count <= 0)
                break;
            request.append(buffer, static_cast<size_t>(count));
            const auto header_end = request.find("\r\n\r\n");
            if (header_end == std::string::npos)
                continue;
            if (target == 0) {
                const auto marker = request.find("Content-Length:");
                size_t content_length = 0;
                if (marker != std::string::npos) {
                    const auto value_start = marker + 15;
                    const auto value_end = request.find("\r\n", value_start);
                    try {
                        content_length = static_cast<size_t>(std::stoull(
                            request.substr(value_start, value_end - value_start)));
                    } catch (...) {
                        content_length = 0;
                    }
                }
                target = header_end + 4 + content_length;
            }
            if (request.size() >= target)
                break;
        }
    }

    void handle(SOCKET socket_value, mode_t mode) noexcept
    {
        socket_owner_t client(socket_value);
        consume_request(client.value);
        if (mode == mode_t::drop)
            return;
        if (mode == mode_t::hold) {
            std::unique_lock<std::mutex> lock(hold_mutex_);
            ++hold_active_;
            hold_cv_.wait_for(lock, std::chrono::seconds(10), [this]() noexcept {
                return hold_released_ || stop_.load(std::memory_order_acquire);
            });
            --hold_active_;
            hold_drained_cv_.notify_all();
            return;
        }

        const std::string json_body =
            R"({"choices":[{"message":{"content":"fixture-ok"}}],"usage":{"prompt_tokens":7,"completion_tokens":3}})";
        std::string response;
        if (mode == mode_t::success) {
            response = response_with_body("application/json", json_body, json_body.size());
        } else if (mode == mode_t::incomplete) {
            response = response_with_body("application/json", json_body, json_body.size() + 64);
        } else {
            const std::string event =
                R"({"choices":[{"delta":{"content":"fixture-stream"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}})";
            const std::string body = mode == mode_t::stream_success
                ? "data: " + event + "\n\ndata: [DONE]\n\n"
                : "data: " + event;
            response = response_with_body("text/event-stream", body, body.size());
        }
        send_all(client.value, response);
        shutdown(client.value, SD_SEND);
    }

    void accept_loop() noexcept
    {
        while (!stop_.load(std::memory_order_acquire)) {
            fd_set read_set;
            FD_ZERO(&read_set);
            FD_SET(listener_, &read_set);
            timeval timeout{};
            timeout.tv_usec = 100000;
            const int ready = select(0, &read_set, nullptr, nullptr, &timeout);
            if (ready <= 0)
                continue;
            SOCKET client = accept(listener_, nullptr, nullptr);
            if (client == INVALID_SOCKET)
                continue;
            const auto mode = mode_.load(std::memory_order_acquire);
            accepted_.fetch_add(1, std::memory_order_acq_rel);
            accepted_cv_.notify_all();
            try {
                std::lock_guard<std::mutex> lock(worker_mutex_);
                workers_.emplace_back([this, client, mode]() noexcept { handle(client, mode); });
            } catch (...) {
                closesocket(client);
            }
        }
    }

    SOCKET listener_ = INVALID_SOCKET;
    int port_ = 0;
    bool winsock_started_ = false;
    std::thread accept_thread_;
    std::atomic<bool> stop_{false};
    std::atomic<mode_t> mode_{mode_t::success};
    std::atomic<uint64_t> accepted_{0};
    std::mutex accepted_mutex_;
    std::condition_variable accepted_cv_;
    std::mutex hold_mutex_;
    std::condition_variable hold_cv_;
    std::condition_variable hold_drained_cv_;
    bool hold_released_ = false;
    size_t hold_active_ = 0;
    std::mutex worker_mutex_;
    std::vector<std::thread> workers_;
};

settings_sa_t fixture_settings(const std::string& base_url)
{
    settings_sa_t settings;
    settings.provider_profiles.clear();
    settings.default_provider_id.clear();
    settings.default_model_id.clear();
    settings.active_provider_profile_id = "fixture-local";
    provider_profile_t profile;
    profile.id = "fixture-local";
    profile.display_name = "Fixture Local";
    profile.kind = "local";
    profile.base_url = base_url;
    profile.api_key = "fixture-key";
    profile.model = "fixture-model";
    profile.headers_json = "{}";
    settings.provider_profiles.push_back(std::move(profile));
    return settings;
}

void verify_success_and_accounting(loopback_server_t& server, standalone_ai_client_t& client)
{
    cost_tracking::reset();
    server.set_mode(loopback_server_t::mode_t::success);
    const std::string result = client.chat_blocking("fixture success", {});
    require(result == "fixture-ok", "real client success response mismatch");
    const auto usage = cost_tracking::snapshot();
    require(usage.request_count == 1 && usage.input_tokens == 7 && usage.output_tokens == 3,
        "successful terminal accounting mismatch");
}

void verify_cancel_and_reuse(loopback_server_t& server, standalone_ai_client_t& client)
{
    cost_tracking::reset();
    server.set_mode(loopback_server_t::mode_t::hold);
    const uint64_t target = server.accepted() + 1;
    std::string cancelled_result;
    std::thread request([&]() {
        cancelled_result = client.chat_blocking("fixture cancel", {});
    });
    server.wait_accepted(target);
    const auto started = std::chrono::steady_clock::now();
    client.cancel();
    server.release_hold();
    request.join();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    require(starts_with_error(cancelled_result) &&
        cancelled_result.find("cancel") != std::string::npos,
        "cancelled request was accepted as a completion");
    require(elapsed <= std::chrono::milliseconds(1000),
        "cancellation exceeded the fixture responsiveness bound");
    require(cost_tracking::snapshot().request_count == 0,
        "cancelled request changed terminal accounting");

    server.set_mode(loopback_server_t::mode_t::success);
    const std::string reused = client.chat_blocking("fixture reuse", {});
    require(reused == "fixture-ok", "cancel poisoned the next request generation");
}

void verify_incomplete_and_callback_failure(
    loopback_server_t& server,
    standalone_ai_client_t& client)
{
    const auto before = cost_tracking::snapshot();
    server.set_mode(loopback_server_t::mode_t::incomplete);
    require(starts_with_error(client.chat_blocking("fixture incomplete", {})),
        "incomplete HTTP response was accepted");

    server.set_mode(loopback_server_t::mode_t::stream_success);
    const std::string callback_failure = client.chat_blocking(
        "fixture callback", {}, [](const std::string&) {
            throw std::runtime_error("fixture callback failure");
        });
    require(starts_with_error(callback_failure) &&
        callback_failure.find("callback") != std::string::npos,
        "stream callback failure was accepted");

    server.set_mode(loopback_server_t::mode_t::residual_stream);
    const std::string residual = client.chat_blocking(
        "fixture residual", {}, [](const std::string&) {});
    require(starts_with_error(residual) && residual.find("SSE") != std::string::npos,
        "residual SSE frame was accepted");
    const auto after = cost_tracking::snapshot();
    require(after.request_count == before.request_count,
        "failed transport changed terminal accounting");
}

void verify_concurrency_bound(loopback_server_t& server, standalone_ai_client_t& client)
{
    server.set_mode(loopback_server_t::mode_t::hold);
    const uint64_t target = server.accepted() + 8;
    std::vector<std::string> results(8);
    std::vector<std::thread> requests;
    requests.reserve(8);
    for (size_t index = 0; index < results.size(); ++index) {
        requests.emplace_back([&, index]() {
            results[index] = client.chat_blocking("fixture bounded " + std::to_string(index), {});
        });
    }
    server.wait_accepted(target);
    const auto started = std::chrono::steady_clock::now();
    const std::string overflow = client.chat_blocking("fixture overflow", {});
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    require(overflow == "Error: Too many concurrent AI requests.",
        "ninth concurrent request bypassed the active-operation bound");
    require(elapsed <= std::chrono::milliseconds(250),
        "active-operation rejection was not immediate");
    client.cancel();
    server.release_hold();
    for (auto& request : requests)
        request.join();
    require(std::all_of(results.begin(), results.end(), [](const std::string& value) {
        return starts_with_error(value);
    }), "bounded requests published a false success after cancellation");
}

void verify_retry_deadline(loopback_server_t& server, standalone_ai_client_t& client)
{
    server.set_mode(loopback_server_t::mode_t::drop);
    const auto started = std::chrono::steady_clock::now();
    const std::string result = client.chat_blocking("fixture retry deadline", {});
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    require(starts_with_error(result), "transport failure was accepted");
    require(elapsed <= std::chrono::milliseconds(3000),
        "retry attempts reset the aggregate fixture deadline");

    server.set_mode(loopback_server_t::mode_t::success);
    require(client.chat_blocking("fixture after deadline", {}) == "fixture-ok",
        "timed-out generation poisoned a later request");
}

void verify_expired_handle(const settings_sa_t& settings)
{
    standalone_ai_client_t::cancellation_handle_t handle;
    {
        auto client = std::make_unique<standalone_ai_client_t>(settings);
        handle = client->cancellation_handle();
        require(handle.valid(), "live client cancellation handle is invalid");
    }
    require(!handle.valid(), "destroyed client cancellation handle retained ownership");
    handle.cancel();
}

}

int main()
{
    try {
        loopback_server_t server;
        settings_sa_t settings = fixture_settings(server.base_url());
        standalone_ai_client_t client(settings);
        require(client.is_available(), "fixture client is not configured");
        verify_success_and_accounting(server, client);
        verify_cancel_and_reuse(server, client);
        verify_incomplete_and_callback_failure(server, client);
        verify_concurrency_bound(server, client);
        verify_retry_deadline(server, client);
        verify_expired_handle(settings);
        std::cout << "standalone_ai_cancel_harness passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "standalone_ai_cancel_harness failed: " << error.what() << '\n';
        return 1;
    } catch (...) {
        std::cerr << "standalone_ai_cancel_harness failed: unknown exception\n";
        return 1;
    }
}
