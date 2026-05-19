#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace graphql_view {

struct history_row_t
{
    uint64_t    ts_ms = 0;
    std::string endpoint;
    std::string query_preview;
    int         status_code = 0;
    uint64_t    latency_ms = 0;
};

struct state_t
{
    bool                     active = false;
    int                      active_tab = 0;
    char                     endpoint_buf[1024] = {};
    char                     headers_buf[4096] = {};
    int                      depth = 2;
    int                      batch_count = 5;
    int                      selected_type_index = -1;
    int                      selected_field_index = -1;
    std::mutex               lock;
    std::string              last_schema_raw;
    std::string              schema_status;
    std::string              query_text;
    std::string              variables_text;
    std::string              last_response_raw;
    int                      last_status = 0;
    uint64_t                 last_latency_ms = 0;
    std::atomic<bool>        introspecting{false};
    std::atomic<bool>        sending{false};
    std::deque<history_row_t> history;
    size_t                   history_max = 256;
};

state_t& get_state();

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
}
}
