#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "aida_print_c.hpp"
#include "aida_architecture.hpp"
#include "aida_function_db.hpp"

#include "varnode.hh"
#include "architecture.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

namespace aida_ghidra {

print_c_capability_t print_c_capability_t::inst_;

print_c_capability_t::print_c_capability_t()
{
	name = "aida-c-language";
	isdefault = false;
}

ghidra::PrintLanguage* print_c_capability_t::buildLanguage(ghidra::Architecture* glb)
{
	return new print_c_t(glb, name);
}

print_c_t::print_c_t(ghidra::Architecture* g, const std::string& nm)
	: ghidra::PrintC(g, nm)
{
}

void print_c_t::pushUnnamedLocation(const ghidra::Address& addr,
                                    const ghidra::Varnode* vn,
                                    const ghidra::PcodeOp* op)
{
	ghidra::AddrSpace* space = addr.getSpace();
	if (space->getType() == ghidra::IPTR_PROCESSOR) {
		pushOp(&dereference, op);
		auto type = glb->types->getTypePointer(
			space->getAddrSize(),
			vn->getType(),
			space->getWordSize());
		pushConstant(addr.getOffset(), type, vartoken, vn, op, 0);
		return;
	}
	ghidra::PrintC::pushUnnamedLocation(addr, vn, op);
}

std::string print_c_t::genericFunctionName(const ghidra::Address& addr)
{
	auto arch = dynamic_cast<architecture_t*>(glb);
	if (arch) {
		const function_db_t& db = arch->symbol_database();
		const symbol_record_t* sym = db.find_by_address(addr.getOffset());
		if (sym && !sym->display_name.empty())
			return sym->display_name;
		if (sym && !sym->name.empty())
			return sym->name;
	}
	return ghidra::PrintC::genericFunctionName(addr);
}

}
