#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace comparer {

struct slot_t
{
    uint64_t                id = 0;
    std::string             label;
    std::vector<uint8_t>    data;
    std::string             source_hint;
    uint64_t                created_ms = 0;
};

enum class diff_mode_t : int
{
    bytes      = 0,
    chars      = 1,
    words      = 2,
    lines      = 3
};

struct diff_block_t
{
    enum class kind_t : int
    {
        equal    = 0,
        insert   = 1,
        delete_  = 2,
        replace  = 3
    };

    kind_t kind = kind_t::equal;
    size_t a_start = 0;
    size_t a_end   = 0;
    size_t b_start = 0;
    size_t b_end   = 0;
};

struct diff_stats_t
{
    size_t equal_runs   = 0;
    size_t insert_runs  = 0;
    size_t delete_runs  = 0;
    size_t replace_runs = 0;
    size_t bytes_equal     = 0;
    size_t bytes_inserted  = 0;
    size_t bytes_deleted   = 0;
    size_t bytes_replaced  = 0;
    size_t a_size = 0;
    size_t b_size = 0;
    bool   truncated = false;
    size_t window_used = 0;
};

uint64_t                add_slot(const slot_t& s);
uint64_t                add_slot_from_bytes(const std::string& label, const std::vector<uint8_t>& data, const std::string& source_hint);
bool                    add_slot_from_file(const std::string& label, const std::string& path);
std::vector<slot_t>     list_slots();
bool                    get_slot(uint64_t id, slot_t& out);
void                    clear_slots();
bool                    remove_slot(uint64_t id);

std::vector<diff_block_t> compute_diff(uint64_t slot_a, uint64_t slot_b, diff_mode_t mode);
std::vector<diff_block_t> compute_diff_with_stats(uint64_t slot_a, uint64_t slot_b, diff_mode_t mode, diff_stats_t& stats);

std::string             last_error();

}
}
}
