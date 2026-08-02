#include "allocator.hpp"

#include "../../helpers/diag_log.hpp"

#include <atomic>
#include <cstddef>
#include <new>

#include <mimalloc.h>
#include <mimalloc-new-delete.h>

namespace aida::infra::allocator {

namespace {

std::atomic<bool> g_backend_logged{false};

}

bool initialize() noexcept {
    const bool active = override_active();
    bool expected = false;
    if (g_backend_logged.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        diag::log_tagged_fmt("allocator",
            "allocator_backend kind=mimalloc version=%u override_active=%u",
            static_cast<unsigned>(mi_version()),
            active ? 1u : 0u);
    }
    return active;
}

void trim() noexcept {
    mi_collect(true);
}

bool override_active() noexcept {
    void* block = ::operator new(sizeof(void*) * 2u, std::nothrow);
    if (block == nullptr)
        return false;
    const bool inside = mi_is_in_heap_region(block);
    ::operator delete(block);
    return inside;
}

std::uint64_t version() noexcept {
    return static_cast<std::uint64_t>(mi_version());
}

}
