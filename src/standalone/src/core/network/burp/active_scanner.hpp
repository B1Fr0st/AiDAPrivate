#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "burp_events.hpp"
#include "scanner_module.hpp"

namespace aida {
namespace burp {
namespace active_scanner {

struct audit_config_t
{
    bool                       scope_only = true;
    std::vector<std::string>   enabled_modules;
    size_t                     max_concurrent_requests = 16;
    size_t                     request_throttle_ms = 0;
    size_t                     per_module_request_cap = 64;
    int                        timeout_ms = 15000;
    bool                       follow_redirects = false;
    bool                       max_concurrent_explicit = false;
    bool                       request_throttle_explicit = false;
};

struct audit_status_t
{
    uint64_t      id = 0;
    std::string   url;
    std::string   host;
    uint16_t      port = 0;
    bool          tls = false;
    size_t        total_points = 0;
    size_t        total_probes = 0;
    size_t        completed_probes = 0;
    size_t        issues_found = 0;
    bool          running = false;
    bool          cancelled = false;
    bool          cancel_requested = false;
    bool          drained = false;
    uint64_t      started_ms = 0;
    uint64_t      ended_ms = 0;
    size_t        request_length = 0;
    size_t        queued_workers = 0;
    size_t        active_workers = 0;
    size_t        in_flight_requests = 0;
    size_t        responses_received = 0;
    size_t        no_response_count = 0;
    size_t        transport_failures = 0;
    std::string   last_transport_error;
    uint32_t      transport_error_code = 0;
    std::string   transport_error_class;
    bool          transport_circuit_breaker_open = false;
    size_t        transport_circuit_breaker_hits = 0;
    size_t        transport_circuit_breaker_threshold = 0;
    size_t        effective_max_concurrent = 0;
    size_t        effective_throttle_ms = 0;
    size_t        transport_backoff_ms = 0;
};

struct scanner_load_t
{
    size_t        active_audits = 0;
    size_t        running_audits = 0;
    size_t        queue_depth = 0;
    size_t        active_workers = 0;
    size_t        in_flight_requests = 0;
    size_t        max_active_audits = 0;
    bool          shutting_down = false;
};

bool      initialize();
void      shutdown();

uint64_t  enqueue_target(const std::vector<uint8_t>& raw_request,
                         const std::string& url,
                         const audit_config_t& cfg);

bool      cancel_audit(uint64_t audit_id);
bool      wait_for_audit_idle(uint64_t audit_id, uint32_t timeout_ms);

std::vector<audit_status_t> list_audits();
bool      get_status(uint64_t audit_id, audit_status_t& out);
scanner_load_t load_snapshot();

std::string last_error();
std::string last_error_code();

}
}
}
