#pragma once

#include "aida_ghidra_preamble.hpp"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "database.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <memory>

namespace aida_ghidra {

class architecture_t;

class scope_internal_proxy_t : public ghidra::ScopeInternal
{
public:
	using ghidra::ScopeInternal::ScopeInternal;
	using ghidra::ScopeInternal::addSymbolInternal;
	using ghidra::ScopeInternal::addMapInternal;
	using ghidra::ScopeInternal::addDynamicMapInternal;
};

class scope_t : public ghidra::Scope
{
private:
	architecture_t* arch_;
	scope_internal_proxy_t* cache_;
	std::unique_ptr<ghidra::uint8> next_id_;

	ghidra::uint8 make_id_() const { return (*next_id_)++; }

	ghidra::FunctionSymbol* register_function_(uint64_t address, bool is_external) const;
	ghidra::Symbol* register_external_(uint64_t address) const;
	ghidra::Symbol* register_global_(uint64_t address) const;
	ghidra::Symbol* query_aida_(const ghidra::Address& addr, bool contain) const;

protected:
	void removeRange(ghidra::AddrSpace* /*spc*/, ghidra::uintb /*first*/, ghidra::uintb /*last*/) override
	{
	}
	void addSymbolInternal(ghidra::Symbol* sym) override
	{
		cache_->addSymbolInternal(sym);
	}
	ghidra::SymbolEntry* addMapInternal(ghidra::Symbol* sym, ghidra::uint4 exfl,
	                                    const ghidra::Address& addr, ghidra::int4 off,
	                                    ghidra::int4 sz, const ghidra::RangeList& uselim) override
	{
		return cache_->addMapInternal(sym, exfl, addr, off, sz, uselim);
	}
	ghidra::SymbolEntry* addDynamicMapInternal(ghidra::Symbol* sym, ghidra::uint4 exfl,
	                                           ghidra::uint8 hash, ghidra::int4 off,
	                                           ghidra::int4 sz, const ghidra::RangeList& uselim) override
	{
		return cache_->addDynamicMapInternal(sym, exfl, hash, off, sz, uselim);
	}

public:
	explicit scope_t(architecture_t* arch);
	~scope_t() override;

	ghidra::Scope* buildSubScope(ghidra::uint8 id, const std::string& nm) override;
	void clear() override { cache_->clear(); }
	ghidra::SymbolEntry* addSymbol(const std::string& name, ghidra::Datatype* ct,
	                               const ghidra::Address& addr,
	                               const ghidra::Address& usepoint) override
	{
		return cache_->addSymbol(name, ct, addr, usepoint);
	}
	std::string buildVariableName(const ghidra::Address& addr, const ghidra::Address& pc,
	                              ghidra::Datatype* ct, ghidra::int4& index, ghidra::uint4 flags) const override
	{
		return cache_->buildVariableName(addr, pc, ct, index, flags);
	}
	std::string buildUndefinedName() const override { return cache_->buildUndefinedName(); }
	void setAttribute(ghidra::Symbol* sym, ghidra::uint4 attr) override { cache_->setAttribute(sym, attr); }
	void clearAttribute(ghidra::Symbol* sym, ghidra::uint4 attr) override { cache_->clearAttribute(sym, attr); }
	void setDisplayFormat(ghidra::Symbol* sym, ghidra::uint4 attr) override { cache_->setDisplayFormat(sym, attr); }

	void adjustCaches() override { cache_->adjustCaches(); }
	ghidra::SymbolEntry* findAddr(const ghidra::Address& addr, const ghidra::Address& usepoint) const override;
	ghidra::SymbolEntry* findContainer(const ghidra::Address& addr, ghidra::int4 size,
	                                   const ghidra::Address& usepoint) const override;
	ghidra::SymbolEntry* findClosestFit(const ghidra::Address& addr, ghidra::int4 size,
	                                    const ghidra::Address& usepoint) const override
	{
		return cache_->findClosestFit(addr, size, usepoint);
	}
	ghidra::Funcdata* findFunction(const ghidra::Address& addr) const override;
	ghidra::ExternRefSymbol* findExternalRef(const ghidra::Address& addr) const override;
	ghidra::LabSymbol* findCodeLabel(const ghidra::Address& /*addr*/) const override;
	bool isNameUsed(const std::string& name, const Scope* op2) const override
	{
		return cache_->isNameUsed(name, op2);
	}
	ghidra::Funcdata* resolveExternalRefFunction(ghidra::ExternRefSymbol* sym) const override;

	ghidra::SymbolEntry* findOverlap(const ghidra::Address& addr, ghidra::int4 size) const override
	{
		return cache_->findOverlap(addr, size);
	}
	void findByName(const std::string& name, std::vector<ghidra::Symbol*>& res) const override
	{
		cache_->findByName(name, res);
	}
	ghidra::MapIterator begin() const override
	{
		return cache_->begin();
	}
	ghidra::MapIterator end() const override
	{
		return cache_->end();
	}
	std::list<ghidra::SymbolEntry>::const_iterator beginDynamic() const override
	{
		return cache_->beginDynamic();
	}
	std::list<ghidra::SymbolEntry>::const_iterator endDynamic() const override
	{
		return cache_->endDynamic();
	}
	std::list<ghidra::SymbolEntry>::iterator beginDynamic() override
	{
		return cache_->beginDynamic();
	}
	std::list<ghidra::SymbolEntry>::iterator endDynamic() override
	{
		return cache_->endDynamic();
	}
	void clearCategory(ghidra::int4 cat) override
	{
		cache_->clearCategory(cat);
	}
	void clearUnlockedCategory(ghidra::int4 cat) override
	{
		cache_->clearUnlockedCategory(cat);
	}
	void clearUnlocked() override
	{
		cache_->clearUnlocked();
	}
	void removeSymbolMappings(ghidra::Symbol* symbol) override
	{
		cache_->removeSymbolMappings(symbol);
	}
	void removeSymbol(ghidra::Symbol* symbol) override
	{
		cache_->removeSymbol(symbol);
	}
	void renameSymbol(ghidra::Symbol* sym, const std::string& newname) override
	{
		cache_->renameSymbol(sym, newname);
	}
	void retypeSymbol(ghidra::Symbol* sym, ghidra::Datatype* ct) override
	{
		cache_->retypeSymbol(sym, ct);
	}
	std::string makeNameUnique(const std::string& nm) const override
	{
		return cache_->makeNameUnique(nm);
	}
	void encode(ghidra::Encoder& encoder) const override { cache_->encode(encoder); }
	void decode(ghidra::Decoder& decoder) override
	{
		cache_->decode(decoder);
	}
	void printEntries(std::ostream& s) const override
	{
		cache_->printEntries(s);
	}
	ghidra::int4 getCategorySize(ghidra::int4 cat) const override
	{
		return cache_->getCategorySize(cat);
	}
	ghidra::Symbol* getCategorySymbol(ghidra::int4 cat, ghidra::int4 ind) const override
	{
		return cache_->getCategorySymbol(cat, ind);
	}
	void setCategory(ghidra::Symbol* sym, ghidra::int4 cat, ghidra::int4 ind) override
	{
		cache_->setCategory(sym, cat, ind);
	}
};

}
