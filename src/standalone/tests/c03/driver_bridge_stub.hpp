#include <vector>
#include <cstdint>

namespace driver_bridge {

struct module_info_t {
    std::uint64_t base;
    std::uint64_t size;
    std::string name;
    std::vector<std::uint8_t> fingerprint;
};

inline bool read_memory_for(unsigned int, std::uint64_t, std::uint64_t, std::vector<unsigned char>&) {
    return false;
}

inline std::vector<module_info_t> enumerate_modules_for(unsigned int) {
    return {};
}

}
