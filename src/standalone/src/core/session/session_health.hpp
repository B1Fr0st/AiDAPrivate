#pragma once

#include <cstdint>

namespace session_health {

bool initialize();
void shutdown();
bool shutdown_and_wait(uint32_t timeout_ms);

bool is_alive(uint32_t pid);

}
