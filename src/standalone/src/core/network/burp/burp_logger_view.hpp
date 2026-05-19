#pragma once

#include <cstdint>
#include <mutex>
#include <string>

namespace aida {
namespace burp {
namespace logger_view {

struct state_t
{
    bool        active = false;
    char        method_filter_buf[16] = {};
    char        host_regex_buf[256] = {};
    char        url_regex_buf[512] = {};
    int         status_min = 0;
    int         status_max = 599;
    char        source_buf[32] = {};
    char        mime_buf[64] = {};
    int         row_limit = 1000;
    int         selected_row = -1;
    char        export_path_buf[512] = {};
    std::mutex  lock;
    std::string last_action;
    std::string last_action_kind;
};

state_t& get_state();

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
}
}
