#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "aida_scope.hpp"
#include "aida_architecture.hpp"
#include "aida_function_db.hpp"

#include "funcdata.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <cstdio>

namespace aida_ghidra {

scope_t::scope_t(architecture_t* arch)
	: ghidra::Scope(0, "", arch, this),
	  arch_(arch),
	  cache_(new scope_internal_proxy_t(0, "aida-internal", arch, this)),
	  next_id_(new ghidra::uint8)
{
	*next_id_ = 1;
}

scope_t::~scope_t()
{
	delete cache_;
}

ghidra::Scope* scope_t::buildSubScope(ghidra::uint8 id, const std::string& nm)
{
	return new ghidra::ScopeInternal(id, nm, arch_);
}

ghidra::FunctionSymbol* scope_t::register_function_(uint64_t address, bool is_external) const
{
	const function_db_t& db = arch_->symbol_database();
	const symbol_record_t* sym = db.find_by_address(address);

	std::string name;
	if (sym && !sym->name.empty()) {
		name = sym->name;
	} else {
		char buf[32];
		std::snprintf(buf, sizeof(buf), is_external ? "ext_%llx" : "sub_%llx",
		              static_cast<unsigned long long>(address));
		name = buf;
	}

	ghidra::Address addr(arch_->getDefaultCodeSpace(), address);
	auto fs = cache_->addFunction(addr, name);
	if (fs && sym && sym->is_noreturn) {
		auto fd = fs->getFunction();
		if (fd)
			fd->getFuncProto().setNoReturn(true);
	}
	if (fs && is_external) {
		auto fd = fs->getFunction();
		if (fd) {
			fd->getFuncProto().setInputLock(true);
			fd->getFuncProto().setOutputLock(true);
		}
	}
	return fs;
}

ghidra::Symbol* scope_t::register_external_(uint64_t address) const
{
	const function_db_t& db = arch_->symbol_database();
	const symbol_record_t* sym = db.find_by_address(address);
	if (!sym)
		return nullptr;

	std::string name = sym->name.empty() ? std::string("ext_") + std::to_string(address) : sym->name;
	ghidra::Address ref(arch_->getDefaultCodeSpace(), address);
	auto fs = cache_->addExternalRef(ref, ref, name);
	return fs;
}

ghidra::Symbol* scope_t::register_global_(uint64_t address) const
{
	const function_db_t& db = arch_->symbol_database();
	const symbol_record_t* sym = db.find_by_address(address);
	if (!sym || sym->kind == symbol_kind_t::function || sym->kind == symbol_kind_t::import || sym->kind == symbol_kind_t::export_)
		return nullptr;

	auto type = arch_->types->getTypeCode();
	if (!type)
		return nullptr;

	ghidra::Address addr(arch_->getDefaultCodeSpace(), address);
	std::string name = sym->name.empty() ? std::string("data_") + std::to_string(address) : sym->name;
	auto entry = cache_->addSymbol(name, type, addr, ghidra::Address());
	if (!entry)
		return nullptr;

	auto symbol = entry->getSymbol();
	cache_->setAttribute(symbol, ghidra::Varnode::namelock | ghidra::Varnode::typelock);
	return symbol;
}

ghidra::Symbol* scope_t::query_aida_(const ghidra::Address& addr, bool ) const
{
	if (addr.getSpace() != arch_->getDefaultCodeSpace() && addr.getSpace() != arch_->getDefaultDataSpace())
		return nullptr;

	uint64_t off = addr.getOffset();
	const function_db_t& db = arch_->symbol_database();
	const symbol_record_t* sym = db.find_by_address(off);
	if (!sym)
		return nullptr;

	switch (sym->kind) {
	case symbol_kind_t::function:
	case symbol_kind_t::export_: {
		auto fs = register_function_(off, false);
		return fs;
	}
	case symbol_kind_t::import: {
		if (sym->is_external) {
			auto fs = register_function_(off, true);
			return fs;
		}
		return nullptr;
	}
	case symbol_kind_t::data:
	case symbol_kind_t::label:
	case symbol_kind_t::unknown:
	default:
		return register_global_(off);
	}
}

ghidra::SymbolEntry* scope_t::findAddr(const ghidra::Address& addr, const ghidra::Address& usepoint) const
{
	auto entry = cache_->findAddr(addr, usepoint);
	if (entry)
		return entry->getAddr() == addr ? entry : nullptr;

	entry = cache_->findContainer(addr, 1, ghidra::Address());
	if (entry)
		return nullptr;

	auto sym = query_aida_(addr, false);
	entry = sym ? sym->getMapEntry(addr) : nullptr;
	return (entry && entry->getAddr() == addr) ? entry : nullptr;
}

ghidra::SymbolEntry* scope_t::findContainer(const ghidra::Address& addr, ghidra::int4 size,
                                            const ghidra::Address& usepoint) const
{
	auto entry = cache_->findClosestFit(addr, size, usepoint);
	if (!entry) {
		auto sym = query_aida_(addr, true);
		entry = sym ? sym->getMapEntry(addr) : nullptr;
	}
	if (entry) {
		ghidra::uintb last = entry->getAddr().getOffset() + entry->getSize() - 1;
		if (last < addr.getOffset() + size - 1)
			return nullptr;
	}
	return entry;
}

ghidra::Funcdata* scope_t::findFunction(const ghidra::Address& addr) const
{
	auto fd = cache_->findFunction(addr);
	if (fd)
		return fd;

	if (cache_->findContainer(addr, 1, ghidra::Address()))
		return nullptr;

	auto sym = dynamic_cast<ghidra::FunctionSymbol*>(query_aida_(addr, false));
	if (sym)
		return sym->getFunction();
	return nullptr;
}

ghidra::ExternRefSymbol* scope_t::findExternalRef(const ghidra::Address& addr) const
{
	auto sym = cache_->findExternalRef(addr);
	if (sym)
		return sym;

	if (cache_->findContainer(addr, 1, ghidra::Address()))
		return nullptr;

	const function_db_t& db = arch_->symbol_database();
	const symbol_record_t* rec = db.find_by_address(addr.getOffset());
	if (!rec || !rec->is_external)
		return nullptr;

	std::string name = rec->name.empty()
		? std::string("ext_") + std::to_string(addr.getOffset())
		: rec->name;
	auto extsym = cache_->addExternalRef(addr, addr, name);
	return extsym;
}

ghidra::LabSymbol* scope_t::findCodeLabel(const ghidra::Address& addr) const
{
	auto sym = cache_->findCodeLabel(addr);
	if (sym)
		return sym;

	if (cache_->findAddr(addr, ghidra::Address()))
		return nullptr;

	const function_db_t& db = arch_->symbol_database();
	const symbol_record_t* rec = db.find_by_address(addr.getOffset());
	if (!rec || rec->kind != symbol_kind_t::label)
		return nullptr;

	std::string name = rec->name.empty()
		? std::string("lab_") + std::to_string(addr.getOffset())
		: rec->name;
	return cache_->addCodeLabel(addr, name);
}

ghidra::Funcdata* scope_t::resolveExternalRefFunction(ghidra::ExternRefSymbol* sym) const
{
	if (!sym)
		return nullptr;
	return queryFunction(sym->getRefAddr());
}

}
