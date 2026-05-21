#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <cstdint>
#include <atomic>

namespace test_target {
namespace http_server {

struct config_t {
    uint16_t port;
    bool     verbose;
};

void run_all(const config_t& cfg, std::atomic<bool>& running);
void shutdown_all();

}
}
