#pragma once

#include <cstdint>

namespace session_health {

bool initialize();
void shutdown();

bool is_alive(uint32_t pid);

}
