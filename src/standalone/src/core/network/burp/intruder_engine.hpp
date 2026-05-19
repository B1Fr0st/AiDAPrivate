#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace intruder {

enum class attack_mode_t : int
{
    sniper        = 0,
    battering_ram = 1,
    pitchfork     = 2,
    clusterbomb   = 3,
    turbo         = 4,
    race          = 5
};

enum class engine_mode_t : int
{
    http1_serial        = 0,
    http1_pipelined     = 1,
    http1_pooled        = 2,
    http2_multiplexed   = 3,
    http2_single_packet = 4
};

struct config_t
{
    std::string                              scheme;
    std::string                              host;
    uint16_t                                 port = 0;
    std::vector<uint8_t>                     base_request;
    attack_mode_t                            attack_mode = attack_mode_t::sniper;
    engine_mode_t                            engine_mode = engine_mode_t::http1_pooled;
    std::vector<std::pair<size_t, size_t>>   positions;
    std::vector<std::vector<std::string>>    payload_sets;
    size_t                                   requests_per_second_cap = 0;
    size_t                                   concurrency = 32;
    size_t                                   total_requests_cap = 0;
    int                                      follow_redirects = 0;
    int                                      timeout_ms = 15000;
    bool                                     reuse_session_cookies = true;
    bool                                     record_history = true;
    size_t                                   race_gate_size = 30;
    int                                      race_warmup_count = 0;
    size_t                                   max_response_body_bytes = 65536;
};

struct result_t
{
    uint64_t                                 job_id = 0;
    size_t                                   index = 0;
    std::vector<std::string>                 payloads;
    int                                      status_code = 0;
    size_t                                   response_size = 0;
    uint64_t                                 latency_ms = 0;
    std::string                              response_preview;
    std::vector<uint8_t>                     response_raw;
    bool                                     error = false;
    std::string                              error_msg;
};

struct status_t
{
    uint64_t  job_id = 0;
    size_t    total = 0;
    size_t    sent = 0;
    size_t    errors = 0;
    bool      running = false;
    double    current_rps = 0.0;
    uint64_t  started_unix_ms = 0;
    uint64_t  finished_unix_ms = 0;
};

uint64_t              start(config_t cfg);
bool                  stop(uint64_t job_id);
status_t              status(uint64_t job_id);
std::vector<result_t> results(uint64_t job_id, size_t start_idx, size_t max);
bool                  clear(uint64_t job_id);
std::vector<status_t> list_jobs();

std::string           last_error();
const char*           attack_mode_name(attack_mode_t m);
const char*           engine_mode_name(engine_mode_t m);
bool                  parse_attack_mode(const std::string& s, attack_mode_t& out);
bool                  parse_engine_mode(const std::string& s, engine_mode_t& out);

}
}
}
