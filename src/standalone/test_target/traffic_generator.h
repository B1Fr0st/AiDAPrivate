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
namespace traffic {

struct config_t {
    uint16_t base_port;
    uint16_t http_port;
    uint32_t rate_ms;
    bool     verbose;
    bool     no_external;
    bool     skip_network;
};

void run_all(const config_t& cfg, std::atomic<bool>& running);
void shutdown_all();

}
}
