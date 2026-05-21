#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <cstdint>
#include <atomic>

namespace test_target {
namespace resident {

struct config_t {
    bool verbose;
};

void init(const config_t& cfg, std::atomic<bool>& running);
void shutdown_all();

}
}
