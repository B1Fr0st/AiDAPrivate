#pragma once

namespace aida {
namespace burp {
namespace collaborator_view {

void initialize();
void shutdown();

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
}
}
