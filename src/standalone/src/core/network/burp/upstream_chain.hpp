#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace upstream {

struct upstream_hop_t
{
    std::string type;
    std::string host;
    uint16_t    port = 0;
    std::string username;
    std::string password;
};

struct upstream_chain_t
{
    uint64_t                    id = 0;
    std::string                 label;
    std::vector<upstream_hop_t> hops;
    bool                        active = false;
};

bool initialize();
void shutdown();

uint64_t                       add_chain(const upstream_chain_t& c);
bool                           remove_chain(uint64_t id);
std::vector<upstream_chain_t>  list_chains();
bool                           get_chain(uint64_t id, upstream_chain_t& out);
bool                           set_active_chain(uint64_t id);
uint64_t                       get_active_chain_id();
bool                           update_chain(const upstream_chain_t& c);

uintptr_t   open_through_chain(const std::string& target_host, uint16_t target_port, std::string& err_out);
uintptr_t   open_through_chain_id(uint64_t chain_id, const std::string& target_host, uint16_t target_port, std::string& err_out);
bool        test_chain(uint64_t chain_id, const std::string& target_host, uint16_t target_port, std::string& err_out);

std::string storage_path();
bool        save_to_disk();
bool        load_from_disk();
std::string last_error();

}
}
}
