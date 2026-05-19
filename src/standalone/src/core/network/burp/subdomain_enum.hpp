#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace subdomain_enum {

struct config_t
{
    std::string              domain;
    std::vector<std::string> passive_sources;
    std::string              brute_wordlist_id = "subdomains/top1000";
    std::string              brute_wordlist_file;
    int                      resolver_concurrency = 32;
    int                      request_timeout_ms = 6000;
    bool                     run_passive = true;
    bool                     run_brute = true;
    bool                     bypass_dns_cache = true;
    std::string              user_agent = "AiDA-SubdomainEnum/1.0";
};

enum class enum_phase_t : int
{
    pending = 0,
    passive = 1,
    brute = 2,
    stopping = 3,
    complete = 4,
    error = 5
};

struct subdomain_t
{
    std::string              fqdn;
    std::vector<std::string> ips;
    std::vector<std::string> sources;
    bool                     resolves = false;
    uint64_t                 discovered_unix_ms = 0;
};

struct enum_status_t
{
    uint64_t                  id = 0;
    enum_phase_t              phase = enum_phase_t::pending;
    int                       passive_count = 0;
    int                       brute_attempts = 0;
    int                       brute_resolved = 0;
    uint64_t                  started_unix_ms = 0;
    uint64_t                  finished_unix_ms = 0;
    std::string               last_error;
    config_t                  config;
    std::vector<subdomain_t>  results;
};

bool                            initialize();
void                            shutdown();

uint64_t                        start(const config_t& cfg);
bool                            stop(uint64_t id);
enum_status_t                   status(uint64_t id);
std::vector<enum_status_t>      list();
std::vector<subdomain_t>        results(uint64_t id);
bool                            remove(uint64_t id);
std::string                     export_csv(uint64_t id);

std::string                     last_error();

}
}
}
