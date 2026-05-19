#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>

namespace aida {
namespace burp {
namespace report_view {

struct state_t
{
    bool                    active = false;
    char                    title_buf[256] = {};
    char                    client_buf[256] = {};
    char                    scope_buf[2048] = {};
    char                    output_path_buf[1024] = {};
    int                     format_idx = 0;
    bool                    include_evidence = true;
    bool                    include_remediation = true;
    std::atomic<bool>       generating{false};
    int                     selected_history = -1;
    std::mutex              lock;
    std::string             last_action;
    std::string             last_action_kind;
};

state_t& get_state();

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
}
}
