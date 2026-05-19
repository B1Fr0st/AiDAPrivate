#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace h2_editor {

struct pseudo_headers_t
{
    std::string method = "GET";
    std::string path   = "/";
    std::string scheme = "https";
    std::string authority;
};

enum class send_flags_t : uint32_t
{
    none         = 0,
    end_stream   = 1u << 0,
    end_headers  = 1u << 1,
    padded       = 1u << 2,
    priority     = 1u << 3
};

struct frame_t
{
    uint32_t                length = 0;
    uint8_t                 type = 0;
    uint8_t                 flags = 0;
    bool                    r_bit = false;
    uint32_t                stream_id = 0;
    std::vector<uint8_t>    payload;
};

struct request_t
{
    std::string                                      host;
    uint16_t                                         port = 443;
    pseudo_headers_t                                 pseudo;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t>                             body;
    uint32_t                                         flags = static_cast<uint32_t>(send_flags_t::end_stream)
                                                          | static_cast<uint32_t>(send_flags_t::end_headers);
    std::vector<frame_t>                             raw_frames;
    bool                                             use_raw_frames = false;
    int                                              timeout_ms = 15000;
};

struct response_t
{
    bool                                             ok = false;
    int                                              status_code = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t>                             body;
    uint64_t                                         latency_ms = 0;
    std::string                                      error_msg;
    std::vector<uint8_t>                             raw_wire_in;
    std::vector<uint8_t>                             raw_wire_out;
};

response_t  send(const request_t& req);

std::vector<uint8_t> encode_frame(const frame_t& f);
bool                 decode_frames(const std::vector<uint8_t>& data, std::vector<frame_t>& out);

std::string  last_error();

}
}
}
