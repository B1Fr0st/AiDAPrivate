#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace api_view {

struct state_t
{
    bool                            active = false;
    int                             selected_collection_index = -1;
    int                             selected_request_index = -1;
    char                            import_path_buf[512] = {};
    char                            import_url_buf[512] = {};
    int                             import_format_idx = 0;
    char                            send_path_value_buf[512] = {};
    char                            send_query_value_buf[512] = {};
    char                            send_header_value_buf[2048] = {};
    std::string                     response_raw;
    int                             response_status = 0;
    uint64_t                        response_latency_ms = 0;
    std::atomic<bool>               sending{false};
    std::atomic<bool>               importing{false};
    std::mutex                      lock;
    std::string                     last_action_message;
    std::string                     last_action_kind;
    char                            audit_auth_buf[1024] = {};
    std::atomic<bool>               auditing{false};
};

state_t& get_state();

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
}
}
