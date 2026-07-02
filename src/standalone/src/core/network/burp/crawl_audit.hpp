#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace crawl_audit {

struct pipeline_config_t
{
    std::vector<std::string> start_urls;
    int                      max_depth = 3;
    int                      max_pages = 500;
    bool                     same_host_only = true;
    bool                     scope_only = true;
    std::vector<std::string> enabled_modules;
    int                      max_concurrent = 16;
    int                      throttle_ms = 0;
    bool                     audit_after_crawl = true;
};

struct pipeline_status_t
{
    uint64_t                   id = 0;
    uint64_t                   crawl_id = 0;
    std::vector<uint64_t>      audit_ids;
    int                        pages_discovered = 0;
    int                        audits_started = 0;
    int                        issues_found = 0;
    std::string                phase;
    uint64_t                   started_ms = 0;
    uint64_t                   finished_ms = 0;
    std::string                last_error;
};

bool                          initialize();
void                          shutdown();

uint64_t                      start(const pipeline_config_t& config);
bool                          stop(uint64_t pipeline_id);
pipeline_status_t             status(uint64_t pipeline_id);
std::vector<pipeline_status_t> list();

}
}
}
