#pragma once

#include <cstdint>

namespace aida::infra::allocator {

bool initialize() noexcept;
void trim() noexcept;
bool override_active() noexcept;
std::uint64_t version() noexcept;

}
