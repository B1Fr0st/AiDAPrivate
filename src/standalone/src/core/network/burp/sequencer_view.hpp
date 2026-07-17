#pragma once

#include <cstdint>
#include <string>

namespace aida {
namespace burp {
namespace sequencer_view {

void initialize();
void shutdown();
bool open_new_collection_with(const std::string& url, const std::string& host,
                              std::uint16_t port, bool use_tls,
                              const std::string& raw_request, std::string& reason);

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
}
}
