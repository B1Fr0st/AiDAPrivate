#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace h2_editor_view {

void initialize();
void shutdown();
bool resolve_retained_artifact(uint64_t exchange_id, uint64_t generation, bool response,
                               std::vector<uint8_t>& bytes, std::string& unavailable_reason);

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
}
}
