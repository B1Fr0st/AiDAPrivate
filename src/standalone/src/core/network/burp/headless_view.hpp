#pragma once

#include <cstdint>
#include <string>

namespace aida {
namespace burp {
namespace headless_view {

bool initialize();
void shutdown();

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

std::string last_error();

}
}
}
