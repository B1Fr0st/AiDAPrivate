#pragma once

#include <string>

namespace network_view { struct artifact_identity_t; }

namespace aida {
namespace burp {
namespace session_handler_view {

bool stage_reviewed_context(const network_view::artifact_identity_t& identity,
                            std::string& unavailable_reason);

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
}
}
