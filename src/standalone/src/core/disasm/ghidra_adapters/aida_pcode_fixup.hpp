#pragma once

#include "aida_ghidra_preamble.hpp"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

namespace ghidra {
class Funcdata;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

namespace aida_ghidra {

class architecture_t;

class pcode_fixup_preprocessor_t
{
public:
	static void fixup_shared_return_jump_to_imports(ghidra::Funcdata* func, architecture_t& arch);
};

}
