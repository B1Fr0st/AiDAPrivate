#pragma once

#include "parallel_hashmap/phmap.h"
#include "concurrentqueue.h"
#include "blockingconcurrentqueue.h"

#include <cstddef>
#include <cstdint>

namespace aida::infra {

struct fast_u64_hash_t {
    std::size_t operator()(std::uint64_t value) const noexcept {
        value ^= value >> 33U;
        value *= 0xFF51AFD7ED558CCDULL;
        value ^= value >> 33U;
        return static_cast<std::size_t>(value);
    }
};

template <typename K, typename V, typename Hash = phmap::priv::hash_default_hash<K>>
using fast_flat_map = phmap::flat_hash_map<K, V, Hash>;

template <typename K, typename Hash = phmap::priv::hash_default_hash<K>>
using fast_flat_set = phmap::flat_hash_set<K, Hash>;

template <typename V>
using fast_u64_map = phmap::flat_hash_map<std::uint64_t, V, fast_u64_hash_t>;

template <typename T>
using fast_queue = moodycamel::ConcurrentQueue<T>;

template <typename T>
using fast_blocking_queue = moodycamel::BlockingConcurrentQueue<T>;

}
