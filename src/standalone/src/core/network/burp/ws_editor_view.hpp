#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace ws_editor_view {

struct state_t
{
    bool        active = false;
    int         scheme_idx = 1;
    char        host_buf[256] = {};
    int         port = 443;
    char        path_buf[1024] = "/";
    char        origin_buf[256] = {};
    char        subprotocol_buf[128] = {};
    char        headers_buf[4096] = {};
    bool        verify_tls = true;

    int         selected_conn_index = -1;
    uint64_t    selected_frame_id = 0;
    int         compose_mode_idx = 0;
    char        compose_text_buf[16384] = {};
    char        compose_hex_buf[16384] = {};
    int         compose_opcode = 1;
    bool        compose_fin = true;
    bool        compose_masked = true;

    std::mutex  lock;
    std::string last_action;
    std::string last_action_kind;
};

state_t& get_state();
bool resolve_retained_artifact(uint64_t connection_id, uint64_t frame_id,
                               std::vector<uint8_t>& bytes, std::string& unavailable_reason);

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
}
}
