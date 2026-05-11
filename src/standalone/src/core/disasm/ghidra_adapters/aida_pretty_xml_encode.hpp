#pragma once

#include "aida_ghidra_preamble.hpp"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "marshal.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

namespace aida_ghidra {

inline ghidra::XmlEncode make_pretty_xml_encoder(std::ostream& s)
{
	return ghidra::XmlEncode(s, true);
}

}
