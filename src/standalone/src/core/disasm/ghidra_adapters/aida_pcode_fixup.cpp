#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4099 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "aida_pcode_fixup.hpp"
#include "aida_architecture.hpp"
#include "aida_function_db.hpp"

#include "funcdata.hh"
#include "fspec.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

namespace aida_ghidra {

void pcode_fixup_preprocessor_t::fixup_shared_return_jump_to_imports(ghidra::Funcdata* func, architecture_t& arch)
{
	if (!func)
		return;

	auto code_space = arch.getDefaultCodeSpace();
	if (!code_space)
		return;

	const function_db_t& db = arch.symbol_database();

	for (auto iter = func->beginOpAll(); iter != func->endOpAll(); ++iter) {
		ghidra::PcodeOp* op = iter->second;
		if (!op)
			continue;

		ghidra::OpCode opc = op->code();
		if (opc != ghidra::CPUI_BRANCH && opc != ghidra::CPUI_CBRANCH)
			continue;

		const ghidra::Varnode* target_vn = op->getIn(0);
		if (!target_vn || !target_vn->isConstant())
			continue;

		uint64_t target = target_vn->getOffset();
		const symbol_record_t* sym = db.find_by_address(target);
		if (!sym || !sym->is_external)
			continue;

		ghidra::Address from = op->getAddr();
		func->getOverride().insertFlowOverride(from, ghidra::Override::stringToType("callreturn"));
	}
}

}
