#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace protocol_parser {


struct http_header {
    std::string name;
    std::string value;
};

struct http_request {
    std::string method;
    std::string uri;
    std::string version;
    std::vector<http_header> headers;
    std::vector<uint8_t> body;
    bool valid = false;
    bool complete = false;
    size_t total_consumed = 0;
};

struct http_response {
    int status_code = 0;
    std::string reason;
    std::string version;
    std::vector<http_header> headers;
    std::vector<uint8_t> body;
    bool valid = false;
    bool complete = false;
    size_t total_consumed = 0;
};

http_request  parse_http_request(const uint8_t* data, size_t len);
http_response parse_http_response(const uint8_t* data, size_t len);

std::string find_header(const std::vector<http_header>& headers, const std::string& name);
std::vector<uint8_t> decompress_body(const std::vector<uint8_t>& body, const std::string& encoding);

enum class content_type_t { unknown, json, xml, html, text, form_urlencoded, multipart, binary };
content_type_t detect_content_type(const std::vector<http_header>& headers);
std::string content_type_name(content_type_t ct);


enum class h2_frame_type : uint8_t {
    DATA          = 0x0,
    HEADERS       = 0x1,
    PRIORITY      = 0x2,
    RST_STREAM    = 0x3,
    SETTINGS      = 0x4,
    PUSH_PROMISE  = 0x5,
    PING          = 0x6,
    GOAWAY        = 0x7,
    WINDOW_UPDATE = 0x8,
    CONTINUATION  = 0x9
};

struct h2_frame {
    uint32_t     length = 0;
    h2_frame_type type  = h2_frame_type::DATA;
    uint8_t      flags  = 0;
    uint32_t     stream_id = 0;
    std::vector<uint8_t> payload;
};

struct h2_header_field {
    std::string name;
    std::string value;
};

struct h2_parsed_headers {
    std::vector<h2_header_field> fields;
    bool valid = false;
};


struct hpack_context {
    std::vector<h2_header_field> dynamic_table;
    size_t dynamic_table_size = 0;
    size_t max_dynamic_table_size = 4096;
};

std::vector<h2_frame> parse_h2_frames(const uint8_t* data, size_t len);
h2_parsed_headers decode_hpack(const uint8_t* data, size_t len, hpack_context& ctx);
std::string h2_frame_type_name(h2_frame_type t);


enum class ws_opcode : uint8_t {
    continuation = 0x0,
    text         = 0x1,
    binary       = 0x2,
    close        = 0x8,
    ping         = 0x9,
    pong         = 0xA
};

struct ws_frame {
    bool     fin = false;
    ws_opcode opcode = ws_opcode::text;
    bool     masked = false;
    uint64_t payload_length = 0;
    uint8_t  masking_key[4] = {};
    std::vector<uint8_t> payload;
    bool     valid = false;
    size_t   total_consumed = 0;
};

bool is_websocket_upgrade(const http_request& req);
bool is_websocket_accept(const http_response& resp);
ws_frame parse_ws_frame(const uint8_t* data, size_t len);
std::vector<uint8_t> unmask_payload(const ws_frame& frame);
std::string ws_opcode_name(ws_opcode op);


struct quic_header {
    bool     is_long_header = false;
    uint8_t  first_byte = 0;
    uint32_t version = 0;
    std::vector<uint8_t> dcid;
    std::vector<uint8_t> scid;
    std::string packet_type;
    std::string version_name;
    bool     valid = false;
};

bool is_quic_packet(const uint8_t* data, size_t len, uint16_t dst_port);
quic_header parse_quic_header(const uint8_t* data, size_t len);
std::string quic_version_name(uint32_t version);


enum class detected_protocol_t {
    unknown,
    http_request,
    http_response,
    http2,
    websocket,
    tls,
    dns,
    quic
};

struct detection_result {
    detected_protocol_t protocol = detected_protocol_t::unknown;
    std::string label;
    std::string summary;
};

detection_result detect_protocol(const uint8_t* data, size_t len,
                                 uint16_t src_port, uint16_t dst_port,
                                 uint32_t ip_protocol);


struct tls_record {
    uint8_t  content_type = 0;
    uint16_t version = 0;
    uint16_t length = 0;
    std::vector<uint8_t> fragment;
    bool valid = false;
};

struct tls_client_hello {
    uint16_t version = 0;
    std::string sni;
    std::vector<uint16_t> cipher_suites;
    std::vector<std::string> alpn_protocols;
    bool valid = false;
};

tls_record parse_tls_record(const uint8_t* data, size_t len);
tls_client_hello parse_client_hello(const uint8_t* data, size_t len);

std::string tls_content_type_name(uint8_t ct);
std::string tls_version_name(uint16_t ver);

}
