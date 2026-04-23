#pragma once
#include <cstdint>
#include <intrin.h>

#include "transforms.hpp"

namespace protector {
namespace bind {

inline uint32_t collect_cpuid_fingerprint() {
    return protector::collect_cpuid_fingerprint();
}

inline void apply_machine_binding_xor(uint8_t master[32], const uint8_t salt[16], uint32_t fp) {
    protector::apply_machine_binding_xor(master, salt, fp);
}

}
}
