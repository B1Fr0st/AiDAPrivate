#pragma once

#include <atomic>
#include <cstdint>
#include <string>

namespace aida {
namespace burp {
namespace passive_scanner {

struct stats_t
{
    uint64_t exchanges_scanned = 0;
    uint64_t issues_found = 0;
    uint64_t last_scan_ms = 0;
};

bool   initialize();
void   shutdown();
bool   is_enabled();
void   set_enabled(bool e);
stats_t get_stats();
std::string last_error();

}
}
}
