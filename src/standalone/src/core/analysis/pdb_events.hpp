#pragma once

#include <cstdint>
#include <string>

#include "../infra/event_bus.hpp"

namespace aida {
namespace events {

struct event_pdb_loaded
{
	std::string module_name;
	uint64_t    base = 0;
	uint64_t    size = 0;
	bool        success = false;
	uint32_t    symbol_count = 0;
	uint32_t    struct_count = 0;
	uint32_t    enum_count = 0;
};

struct event_pdb_unloaded
{
	std::string module_name;
};

inline constexpr event_def_t<event_pdb_loaded>   event_pdb_loaded_def{"aida.pdb.loaded"};
inline constexpr event_def_t<event_pdb_unloaded> event_pdb_unloaded_def{"aida.pdb.unloaded"};

}
}
