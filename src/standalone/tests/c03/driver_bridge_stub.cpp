#include <cstdint>
#include <vector>
#include <string>

namespace driver_bridge {

struct process_info_t {
    uint32_t    pid = 0;
    std::string name;
    std::string path;
    std::string window_title;
};

struct module_info_t {
    uint64_t    base = 0;
    uint32_t    size = 0;
    std::string name;
    std::string path;
};

struct memory_region_t {
    uint64_t    base = 0;
    uint64_t    size = 0;
    uint32_t    state = 0;
    uint32_t    protect = 0;
    uint32_t    type = 0;
};

bool read_memory_for(uint32_t, uint64_t, size_t, std::vector<uint8_t>&) {
    return false;
}

std::vector<module_info_t> enumerate_modules_for(uint32_t) {
    return {};
}

}
