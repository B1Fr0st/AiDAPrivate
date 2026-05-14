#pragma once


#include "protocol_parser.hpp"
#include "decoder_pipeline.hpp"

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace script_engine {


enum class hook_type {
    on_request,
    on_response,
    on_websocket_frame,
    on_packet,
    on_dns,
    on_connection,
    on_connection_close,
    COUNT
};

inline const char* hook_type_name(hook_type h) {
    switch (h) {
        case hook_type::on_request:          return "on_request";
        case hook_type::on_response:         return "on_response";
        case hook_type::on_websocket_frame:  return "on_websocket_frame";
        case hook_type::on_packet:           return "on_packet";
        case hook_type::on_dns:              return "on_dns";
        case hook_type::on_connection:       return "on_connection";
        case hook_type::on_connection_close: return "on_connection_close";
        default: return "unknown";
    }
}


struct script_info {
    std::string name;
    std::string path;
    std::string source;
    bool        enabled = true;
    bool        loaded  = false;
    std::string last_error;
    uint64_t    load_time = 0;
    uint64_t    last_run  = 0;
    uint32_t    run_count = 0;
};


enum class log_level {
    info,
    warn,
    error,
    debug,
    output,
    command
};

inline const char* log_level_name(log_level lv) {
    switch (lv) {
        case log_level::info:    return "info";
        case log_level::warn:    return "warn";
        case log_level::error:   return "error";
        case log_level::debug:   return "debug";
        case log_level::output:  return "output";
        case log_level::command: return "command";
        default:                 return "info";
    }
}

struct log_entry {
    uint64_t    timestamp = 0;
    uint64_t    wall_seconds = 0;
    std::string script_name;
    log_level   level = log_level::info;
    std::string message;
    uint32_t    repeat_count = 1;
};


struct hook_request_data {
    std::string method;
    std::string uri;
    std::string host;
    uint16_t    port = 0;
    bool        is_tls = false;
    std::map<std::string, std::string> headers;
    std::vector<uint8_t> body;


    bool        modified = false;
    bool        dropped  = false;
};

struct hook_response_data {
    int         status_code = 0;
    std::string reason;
    std::string host;
    uint16_t    port = 0;
    std::map<std::string, std::string> headers;
    std::vector<uint8_t> body;
    uint64_t    latency_ms = 0;

    bool        modified = false;
    bool        dropped  = false;
};

struct hook_ws_frame_data {
    std::string opcode;
    bool        from_server = false;
    bool        is_outbound = false;
    bool        is_text = false;
    std::vector<uint8_t> payload;
    std::string host;
    uint16_t    port = 0;

    bool        modified = false;
    bool        dropped  = false;
};

struct hook_packet_data {
    uint32_t    pid = 0;
    uint8_t     protocol = 0;
    uint8_t     direction = 0;
    uint16_t    src_port = 0;
    uint16_t    dst_port = 0;
    std::string src_addr;
    std::string dst_addr;
    std::vector<uint8_t> payload;

    bool        dropped = false;
};

struct hook_dns_data {
    uint32_t    pid = 0;
    std::string domain;
    uint16_t    query_type = 0;
    std::string resolved_addr;
    uint32_t    response_code = 0;

    bool        blocked = false;
    std::string spoof_addr;
};

struct hook_connection_data {
    uint32_t    pid = 0;
    std::string process_name;
    std::string local_addr;
    uint16_t    local_port = 0;
    std::string remote_addr;
    uint16_t    remote_port = 0;
    uint8_t     protocol = 0;
    bool        is_tls = false;

    bool        blocked = false;
};

struct protobuf_message_t {
    std::vector<decoder_pipeline::protobuf_field> fields;
};


bool initialize();


void shutdown();


bool is_initialized();


bool load_script(const std::string& path);


bool load_script_source(const std::string& name, const std::string& source);


bool unload_script(const std::string& name);


bool reload_script(const std::string& name);


void set_script_enabled(const std::string& name, bool enabled);


std::vector<script_info> get_scripts();


const script_info* find_script(const std::string& name);


bool invoke_hook(hook_type type, hook_request_data& data);
bool invoke_hook(hook_type type, hook_response_data& data);
bool invoke_hook(hook_type type, hook_ws_frame_data& data);
bool invoke_hook(hook_type type, hook_packet_data& data);
bool invoke_hook(hook_type type, hook_dns_data& data);
bool invoke_hook(hook_type type, hook_connection_data& data);


bool dispatch_request(hook_request_data& data);
bool dispatch_response(hook_response_data& data);
bool dispatch_websocket_frame(hook_ws_frame_data& data);
bool dispatch_packet(hook_packet_data& data);
bool dispatch_dns(hook_dns_data& data);
bool dispatch_connection(hook_connection_data& data);
bool dispatch_connection_close(hook_connection_data& data);


size_t registered_hook_count(hook_type type);
size_t registered_hook_count();


std::string execute(const std::string& code);


std::vector<log_entry> get_log(size_t max_count = 0);
void clear_log();


struct api_function {
    std::string name;
    std::string signature;
    std::string description;
};

std::vector<api_function> get_api_listing();

}
