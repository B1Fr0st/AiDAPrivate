#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "aida_architecture.hpp"
#include "aida_load_image.hpp"
#include "aida_scope.hpp"
#include "aida_comment_database.hpp"

#include "funcdata.hh"
#include "coreaction.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <algorithm>
#include <cctype>

namespace aida_ghidra {

namespace {

const std::map<std::string, std::string>& cc_map_x64()
{
	static const std::map<std::string, std::string> map = {
		{ "stdcall", "__stdcall" },
		{ "cdecl", "__cdecl" },
		{ "fastcall", "__fastcall" },
		{ "thiscall", "__thiscall" },
		{ "ms", "__fastcall" },
		{ "win64", "__stdcall" },
		{ "x64", "__stdcall" },
		{ "amd64", "__stdcall" },
		{ "windows", "__stdcall" },
		{ "default", "__stdcall" },
	};
	return map;
}

std::string lowercase_(const std::string& s)
{
	std::string out;
	out.reserve(s.size());
	for (char c : s) {
		out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
	}
	return out;
}

}

architecture_t::architecture_t(const std::string& target,
                               std::ostream* err_stream)
	: ghidra::SleighArchitecture("aida_program", target, err_stream)
{
}

void architecture_t::take_loader(std::unique_ptr<load_image_t> loader)
{
	staged_loader_ = std::move(loader);
}

ghidra::ProtoModel* architecture_t::proto_model_from_cc(const std::string& cc) const
{
	const auto& m = cc_map_x64();
	auto it = m.find(lowercase_(cc));
	if (it == m.end())
		return nullptr;

	auto proto_it = protoModels.find(it->second);
	if (proto_it == protoModels.end())
		return nullptr;
	return proto_it->second;
}

ghidra::Address architecture_t::register_address_from_name(const std::string& reg_name) const
{
	auto it = registers_.find(reg_name);
	if (it == registers_.end())
		it = registers_.find(lowercase_(reg_name));
	if (it == registers_.end())
		return ghidra::Address();
	return it->second.getAddr();
}

void architecture_t::load_registers_(const ghidra::Translate* trans)
{
	registers_.clear();
	if (!trans)
		return;
	std::map<ghidra::VarnodeData, std::string> regs;
	trans->getAllRegisters(regs);
	for (const auto& reg : regs) {
		registers_[reg.second] = reg.first;
		auto lower = lowercase_(reg.second);
		if (registers_.find(lower) == registers_.end())
			registers_[lower] = reg.first;
	}
}

ghidra::Translate* architecture_t::buildTranslator(ghidra::DocumentStorage& store)
{
	ghidra::Translate* ret = ghidra::SleighArchitecture::buildTranslator(store);
	load_registers_(ret);
	return ret;
}

void architecture_t::buildLoader(ghidra::DocumentStorage& /*store*/)
{
	collectSpecFiles(*errorstream);
	if (staged_loader_) {
		auto raw = staged_loader_.release();
		raw->set_address_space_manager(this);
		loader = raw;
		owns_loader_ = true;
	}
}

ghidra::Scope* architecture_t::buildDatabase(ghidra::DocumentStorage& /*store*/)
{
	symboltab = new ghidra::Database(this, false);
	auto* gscope = new scope_t(this);
	symboltab->attachScope(gscope, nullptr);
	return gscope;
}

void architecture_t::buildTypegrp(ghidra::DocumentStorage& /*store*/)
{
	types = new ghidra::TypeFactory(this);
}

void architecture_t::buildCoreTypes(ghidra::DocumentStorage& /*store*/)
{
	types->setCoreType("void", 1, ghidra::TYPE_VOID, false);
	types->setCoreType("bool", 1, ghidra::TYPE_BOOL, false);
	types->setCoreType("uint8_t", 1, ghidra::TYPE_UINT, false);
	types->setCoreType("uint16_t", 2, ghidra::TYPE_UINT, false);
	types->setCoreType("uint32_t", 4, ghidra::TYPE_UINT, false);
	types->setCoreType("uint64_t", 8, ghidra::TYPE_UINT, false);
	types->setCoreType("char", 1, ghidra::TYPE_INT, true);
	types->setCoreType("int8_t", 1, ghidra::TYPE_INT, false);
	types->setCoreType("int16_t", 2, ghidra::TYPE_INT, false);
	types->setCoreType("int32_t", 4, ghidra::TYPE_INT, false);
	types->setCoreType("int64_t", 8, ghidra::TYPE_INT, false);
	types->setCoreType("float", 4, ghidra::TYPE_FLOAT, false);
	types->setCoreType("double", 8, ghidra::TYPE_FLOAT, false);
	types->setCoreType("float16", 16, ghidra::TYPE_FLOAT, false);
	types->setCoreType("undefined", 1, ghidra::TYPE_UNKNOWN, false);
	types->setCoreType("undefined2", 2, ghidra::TYPE_UNKNOWN, false);
	types->setCoreType("undefined4", 4, ghidra::TYPE_UNKNOWN, false);
	types->setCoreType("undefined8", 8, ghidra::TYPE_UNKNOWN, false);
	types->setCoreType("code", 1, ghidra::TYPE_CODE, false);
	types->setCoreType("char16_t", 2, ghidra::TYPE_INT, true);
	types->setCoreType("char32_t", 4, ghidra::TYPE_INT, true);
	types->cacheCoreTypes();
}

void architecture_t::buildCommentDB(ghidra::DocumentStorage& /*store*/)
{
	commentdb = new comment_database_t();
}

void architecture_t::postSpecFile()
{
	for (auto& s : symbol_db_.symbols) {
		if (!s.is_noreturn)
			continue;
		if (s.kind != symbol_kind_t::function && s.kind != symbol_kind_t::import && s.kind != symbol_kind_t::export_)
			continue;
		ghidra::Address addr(getDefaultCodeSpace(), s.address);
		ghidra::Funcdata* fd = symboltab->getGlobalScope()->queryFunction(addr);
		if (!fd)
			continue;
		fd->getFuncProto().setNoReturn(true);
	}
}

void architecture_t::buildAction(ghidra::DocumentStorage& store)
{
	parseExtraRules(store);
	allacts.universalAction(this);
	allacts.resetDefaults();
	if (rawptr_) {
		allacts.cloneGroup("decompile", "decompile-deuglified");
		allacts.removeFromGroup("decompile-deuglified", "fixateglobals");
		allacts.setCurrent("decompile-deuglified");
	}
}

}
