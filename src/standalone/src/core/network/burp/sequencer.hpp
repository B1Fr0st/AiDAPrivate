#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace aida {
namespace burp {
namespace sequencer {

struct collection_config_t
{
    std::string                  url;
    std::vector<uint8_t>         raw_request;
    bool                         use_tls = true;
    std::string                  host;
    uint16_t                     port = 443;
    std::string                  extract_regex;
    int                          capture_group = 1;
    size_t                       target_count = 200;
    size_t                       concurrency = 4;
    size_t                       throttle_ms = 0;
    std::string                  name;
};

struct collection_status_t
{
    uint64_t    id = 0;
    std::string url;
    std::string name;
    size_t      collected = 0;
    size_t      target = 0;
    bool        running = false;
    bool        error = false;
    std::string error_message;
    uint64_t    started_ms = 0;
    uint64_t    last_sample_ms = 0;
};

struct analysis_result_t
{
    uint64_t    collection_id = 0;
    size_t      samples_count = 0;
    size_t      token_length_mode = 0;
    size_t      total_bits = 0;
    double      shannon_entropy_bits = 0.0;
    double      chi_square = 0.0;
    double      chi_square_p_value = 0.0;
    double      monobit_p_value = 0.0;
    size_t      monobit_ones = 0;
    size_t      monobit_zeros = 0;
    double      poker_p_value = 0.0;
    double      runs_p_value = 0.0;
    double      long_run_p_value = 0.0;
    double      maurer_universal = 0.0;
    double      autocorrelation = 0.0;
    double      position_bias[256] = {};
    size_t      byte_frequency[256] = {};
    bool        passes_fips_140_2 = false;
    bool        valid = false;
    std::string verdict;
    std::string notes;
};

uint64_t                  start_collection(const collection_config_t& cfg);
bool                      stop_collection(uint64_t id);
collection_status_t       status(uint64_t id);
std::vector<std::string>  samples(uint64_t id, size_t max_count = 0);
analysis_result_t         analyze(uint64_t id);
std::vector<collection_status_t> list_collections();
bool                      delete_collection(uint64_t id);

std::string               last_error();

}
}
}
