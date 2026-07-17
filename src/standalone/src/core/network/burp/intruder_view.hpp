#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace intruder_view {

void initialize();
void shutdown();
bool open_new_attack_with(const std::string& host, std::uint16_t port, bool use_tls,
                          const std::string& raw_request, std::string& reason);
bool resolve_retained_artifact(std::uint64_t job_id, std::uint64_t result_index,
                               std::uint64_t started_ms, std::vector<std::uint8_t>& bytes,
                               std::string& reason);

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
}
}
