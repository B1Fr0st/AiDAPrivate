#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace param_miner {

enum class location_t : int
{
    query     = 0,
    body_form = 1,
    json_body = 2,
    header    = 3,
    cookie    = 4
};

struct config_t
{
    std::string  target_url;
    location_t   location = location_t::query;
    std::string  wordlist_id;
    std::vector<std::string> custom_words;
    size_t       concurrency = 8;
    int          throttle_ms = 0;
    int          timeout_ms = 12000;
    size_t       baseline_count = 5;
    double       diff_sigma_threshold = 3.0;
    bool         report_as_issues = true;
};

struct hit_t
{
    uint64_t    id = 0;
    std::string param_name;
    std::string location_label;
    int         status_code = 0;
    size_t      response_size = 0;
    std::string evidence;
    double      size_diff_sigma = 0.0;
    bool        cache_diff = false;
    bool        echoed = false;
    bool        header_echoed = false;
};

struct status_t
{
    uint64_t job_id = 0;
    size_t   total = 0;
    size_t   tried = 0;
    size_t   hits = 0;
    bool     running = false;
};

uint64_t              start(config_t cfg);
bool                  stop(uint64_t id);
status_t              status(uint64_t id);
std::vector<hit_t>    results(uint64_t id);
bool                  clear(uint64_t id);
std::vector<status_t> list_jobs();

bool        parse_location(const std::string& v, location_t& out);
const char* location_name(location_t v);

std::string last_error();

}
}
}
