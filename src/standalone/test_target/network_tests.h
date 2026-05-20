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
namespace network {

struct config_t {
    uint16_t listen_port;
    bool     verbose;
};

void run_all(const config_t& cfg, std::atomic<bool>& running);

void test_tcp_connect(const config_t& cfg);
void test_udp_send(const config_t& cfg);
void test_dns_lookup(const config_t& cfg);
void test_http_get(const config_t& cfg);
void test_http_post(const config_t& cfg);
void test_listen_socket(const config_t& cfg, std::atomic<bool>& running);
void test_multiport_io(const config_t& cfg);

}
}
