#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "burp_events.hpp"

namespace aida {
namespace burp {
namespace sitemap {

struct path_node_t
{
    std::string                                   segment;
    std::map<std::string, std::shared_ptr<path_node_t>> children;
    std::vector<exchange_observed_t>              exchanges;
    bool                                          in_scope = true;
    size_t                                        total_requests = 0;
    size_t                                        issue_count = 0;
    int                                           last_status = 0;
    uint64_t                                      last_seen_ms = 0;
};

struct host_node_t
{
    std::string                                   host;
    uint16_t                                      port = 0;
    bool                                          tls = false;
    std::shared_ptr<path_node_t>                  root;
    bool                                          in_scope = true;
    size_t                                        total_requests = 0;
    size_t                                        issue_count = 0;
    uint64_t                                      last_seen_ms = 0;
};

struct host_summary_t
{
    std::string host;
    uint16_t    port = 0;
    bool        tls = false;
    bool        in_scope = true;
    size_t      total_requests = 0;
    size_t      issue_count = 0;
};

bool initialize();
void shutdown();

void                ingest_exchange(const exchange_observed_t& e);

uint64_t            get_selected_exchange_id();
void                set_selected_exchange_id(uint64_t id);
void                clear_selection();

bool                find_exchange(uint64_t id, exchange_observed_t& out);
std::vector<exchange_observed_t> list_exchanges_for(const std::string& host, uint16_t port, const std::string& path);
std::vector<host_summary_t>      list_hosts(bool scope_only);
std::vector<std::string>         list_paths(const std::string& host, uint16_t port);

void                send_to(uint64_t exchange_id, const std::string& target, const std::string& source_view);

nlohmann::json      exchange_to_json(const exchange_observed_t& e, bool include_bodies);

void                render(float pos_x, float pos_y, float width, float height,
                           float alpha, float accent_r, float accent_g, float accent_b);

std::string         last_error();
size_t              total_exchanges();
void                clear_all();

}
}
}
