#pragma once

#include <cstdint>
#include <string>

namespace network_view {
struct state_t;
}

namespace aida::preview::network {

void initialize(network_view::state_t& state);
void shutdown(network_view::state_t& state);
uint64_t monotonic_ms();
void record_receipt(std::string action, std::string detail);
const std::string& receipt();

}
