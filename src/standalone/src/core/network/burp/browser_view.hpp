#pragma once

#include <string>

namespace aida {
namespace burp {
namespace browser {

bool stage_camoufox_url(const std::string& url, std::string& reason);

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
}
}
