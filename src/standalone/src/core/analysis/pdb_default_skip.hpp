#pragma once

#include <atomic>

namespace pdb_default_skip {

inline std::atomic<bool> g_value{false};

inline void set(bool v)
{
	g_value.store(v, std::memory_order_release);
}

inline bool get()
{
	return g_value.load(std::memory_order_acquire);
}

}
