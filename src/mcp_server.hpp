#pragma once

#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>

class mcp_server_t
{
public:
    mcp_server_t();
    ~mcp_server_t();

    bool start(int port);
    void stop();
    bool is_running() const;
    int get_port() const;
    void write_mcp_client_configs() const;

private:
    void server_thread_func(int port);

    std::thread _server_thread;
    std::atomic<bool> _running{false};
    std::atomic<bool> _stop_requested{false};

    void* _active_server = nullptr;
    std::mutex _server_mutex;
    int _port = 0;
};
