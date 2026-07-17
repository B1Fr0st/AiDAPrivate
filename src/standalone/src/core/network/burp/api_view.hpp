#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace api_view {

struct retained_exchange_t
{
    uint64_t            id = 0;
    uint64_t            generation = 0;
    uint64_t            collection_id = 0;
    std::string         request_template_id;
    std::string         label;
    std::string         host;
    uint16_t            port = 0;
    bool                use_tls = false;
    int                 response_status = 0;
    uint64_t            response_latency_ms = 0;
    uint64_t            request_hash = 0;
    uint64_t            response_hash = 0;
    size_t              request_size = 0;
    size_t              response_size = 0;
    std::vector<uint8_t> request;
    std::vector<uint8_t> response;
};

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
    std::atomic<bool>               sending{false};
    std::atomic<bool>               importing{false};
    std::mutex                      lock;
    std::string                     last_action_message;
    std::string                     last_action_kind;
    char                            audit_auth_buf[1024] = {};
    std::atomic<bool>               auditing{false};
    uint64_t                        next_exchange_id = 1;
    std::deque<retained_exchange_t> retained_exchanges;
};

state_t& get_state();
bool resolve_retained_artifact(uint64_t exchange_id, uint64_t generation, bool response,
                               std::vector<uint8_t>& bytes, std::string& unavailable_reason);
bool resolve_retained_endpoint(uint64_t exchange_id, uint64_t generation,
                               std::string& host, uint16_t& port, bool& use_tls,
                               std::string& unavailable_reason);

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
}
}
