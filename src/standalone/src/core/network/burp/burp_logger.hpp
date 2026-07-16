#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "burp_events.hpp"

namespace aida {
namespace burp {
namespace logger {

enum class source_t : int
{
    proxy = 0,
    repeater = 1,
    scanner = 2,
    intruder = 3,
    crawler = 4,
    manual = 5,
    api = 6,
    fuzzer = 7
};

const char* source_label(source_t s);
bool        parse_source(const std::string& s, source_t& out);

struct log_row_t
{
    uint64_t        id = 0;
    uint64_t        ts_ms = 0;
    std::string     method;
    std::string     url;
    std::string     host;
    uint16_t        port = 0;
    int             status = 0;
    size_t          request_length = 0;
    size_t          response_length = 0;
    uint64_t        latency_ms = 0;
    std::string     mime_type;
    source_t        source = source_t::manual;
    uint64_t        exchange_id = 0;
};

struct log_filter_t
{
    std::string     method;
    std::string     host_regex;
    std::string     url_regex;
    int             status_min = 0;
    int             status_max = 1000;
    std::string     source;
    uint64_t        time_from_ms = 0;
    uint64_t        time_to_ms = 0;
    std::string     mime_type;
};

bool                initialize();
void                shutdown();

uint64_t            record(source_t src, const exchange_observed_t& ex);
std::vector<log_row_t>   query(const log_filter_t& f, size_t limit);
size_t              total_rows();
uint64_t            generation();
void                clear();
bool                export_csv(const std::string& path, const log_filter_t& f);
nlohmann::json      row_to_json(const log_row_t& row);
bool                row_from_json(const nlohmann::json& doc, log_row_t& row);
bool                import_rows(const std::vector<log_row_t>& rows, bool replace_existing);

void                set_capacity(size_t rows);
size_t              capacity();

std::string         last_error();

}
}
}
