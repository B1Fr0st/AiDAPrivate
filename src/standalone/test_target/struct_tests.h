#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <cstdint>
#include <atomic>

namespace test_target {
namespace structs {

struct config_t {
    bool verbose;
};

void run_all(const config_t& cfg, std::atomic<bool>& running);

}
}
