#pragma once

#include "aida_ghidra_preamble.hpp"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "printc.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

namespace aida_ghidra {

class print_c_t : public ghidra::PrintC
{
protected:
	void pushUnnamedLocation(const ghidra::Address& addr,
	                         const ghidra::Varnode* vn,
	                         const ghidra::PcodeOp* op) override;
	std::string genericFunctionName(const ghidra::Address& addr) override;

public:
	explicit print_c_t(ghidra::Architecture* g, const std::string& nm = "aida-c-language");
};

class print_c_capability_t : public ghidra::PrintLanguageCapability
{
private:
	static print_c_capability_t inst_;
	print_c_capability_t();

public:
	ghidra::PrintLanguage* buildLanguage(ghidra::Architecture* glb) override;
};

}
