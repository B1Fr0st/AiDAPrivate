#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace ws_editor {

struct ws_connection_config_t
{
    std::string                                       scheme;
    std::string                                       host;
    uint16_t                                          port = 0;
    std::string                                       path;
    std::vector<std::pair<std::string, std::string>>  headers;
    std::string                                       origin;
    std::string                                       subprotocol;
    bool                                              verify_tls = true;
    int                                               connect_timeout_ms = 10000;
    int                                               read_timeout_ms    = 60000;
};

struct ws_status_t
{
    uint64_t    id = 0;
    std::string url;
    bool        connected = false;
    size_t      frames_sent = 0;
    size_t      frames_received = 0;
    uint64_t    opened_ms = 0;
    std::string last_error;
};

struct ws_frame_log_t
{
    uint64_t                id = 0;
    uint64_t                ts_ms = 0;
    bool                    outbound = false;
    uint8_t                 opcode = 0;
    std::vector<uint8_t>    payload;
    std::string             preview;
};

bool        initialize();
void        shutdown();

uint64_t    connect(const ws_connection_config_t& cfg);
bool        disconnect(uint64_t conn_id);
bool        disconnect_all();

std::vector<ws_status_t>    list_connections();
bool                        get_status(uint64_t conn_id, ws_status_t& out);
bool                        get_frame(uint64_t conn_id, uint64_t frame_id, ws_frame_log_t& out);

bool        send_text(uint64_t conn_id, const std::string& msg);
bool        send_binary(uint64_t conn_id, const std::vector<uint8_t>& data);
bool        send_raw_frame(uint64_t conn_id, uint8_t opcode, bool fin, bool masked, const std::vector<uint8_t>& payload);
bool        send_ping(uint64_t conn_id, const std::vector<uint8_t>& payload);
bool        send_pong(uint64_t conn_id, const std::vector<uint8_t>& payload);
bool        send_close(uint64_t conn_id, uint16_t code, const std::string& reason);

std::vector<ws_frame_log_t> frames(uint64_t conn_id, size_t start, size_t max);
size_t                      frame_count(uint64_t conn_id);
void                        clear_frames(uint64_t conn_id);

std::string                 last_error();

}
}
}
