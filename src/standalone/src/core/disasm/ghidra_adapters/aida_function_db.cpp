#include "aida_function_db.hpp"
#include "../zydis_disasm.hpp"
#include "standalone_driver.hpp"

#include <algorithm>
#include <cctype>

namespace aida_ghidra {

void function_db_t::clear()
{
	symbols.clear();
	by_address.clear();
	by_name.clear();
	image_base = 0;
	image_size = 0;
	is_pe = false;
	is_64bit = true;
}

void function_db_t::add_symbol(symbol_record_t rec)
{
	if (rec.address == 0)
		return;

	auto it = by_address.find(rec.address);
	if (it != by_address.end()) {
		auto& existing = symbols[it->second];
		if (existing.kind == symbol_kind_t::unknown && rec.kind != symbol_kind_t::unknown)
			existing.kind = rec.kind;
		if (existing.name.empty() && !rec.name.empty()) {
			existing.name = rec.name;
			by_name[rec.name] = it->second;
		}
		if (existing.display_name.empty() && !rec.display_name.empty())
			existing.display_name = rec.display_name;
		if (rec.is_external)
			existing.is_external = true;
		if (rec.is_thunk)
			existing.is_thunk = true;
		if (rec.is_noreturn)
			existing.is_noreturn = true;
		if (existing.module_name.empty() && !rec.module_name.empty())
			existing.module_name = rec.module_name;
		if (existing.calling_convention.empty() && !rec.calling_convention.empty())
			existing.calling_convention = rec.calling_convention;
		if (rec.size > existing.size)
			existing.size = rec.size;
		return;
	}

	size_t index = symbols.size();
	by_address[rec.address] = index;
	if (!rec.name.empty())
		by_name[rec.name] = index;
	symbols.push_back(std::move(rec));
}

const symbol_record_t* function_db_t::find_by_address(uint64_t addr) const
{
	auto it = by_address.find(addr);
	if (it == by_address.end())
		return nullptr;
	return &symbols[it->second];
}

const symbol_record_t* function_db_t::find_containing(uint64_t addr) const
{
	const symbol_record_t* best = nullptr;
	uint64_t best_size = UINT64_MAX;
	for (auto& s : symbols) {
		if (s.size == 0)
			continue;
		if (addr >= s.address && addr < s.address + s.size) {
			if (s.size < best_size) {
				best = &s;
				best_size = s.size;
			}
		}
	}
	return best;
}

const symbol_record_t* function_db_t::find_by_name(const std::string& name) const
{
	auto it = by_name.find(name);
	if (it == by_name.end())
		return nullptr;
	return &symbols[it->second];
}

bool function_db_t::address_in_image(uint64_t addr) const
{
	if (image_base == 0 || image_size == 0)
		return false;
	return addr >= image_base && addr < image_base + image_size;
}

namespace {

std::string sanitize_symbol_name(const std::string& raw)
{
	std::string out;
	out.reserve(raw.size());
	for (char c : raw) {
		unsigned char uc = static_cast<unsigned char>(c);
		if (std::isalnum(uc) || c == '_')
			out.push_back(c);
		else if (c == '@' || c == '?' || c == '$')
			out.push_back('_');
		else
			out.push_back('_');
	}
	if (out.empty())
		return "anon_sym";
	if (std::isdigit(static_cast<unsigned char>(out[0])))
		out.insert(out.begin(), '_');
	return out;
}

bool name_is_noreturn_default(const std::string& name)
{
	static const char* kNoreturn[] = {
		"abort", "_abort", "exit", "_exit",
		"ExitProcess", "ExitThread", "TerminateProcess", "TerminateThread",
		"FatalAppExitA", "FatalAppExitW", "FatalExit",
		"_invoke_watson", "_invalid_parameter_noinfo_noreturn",
		"longjmp", "_longjmp", "RaiseException",
		"__cxa_throw", "_CxxThrowException",
		"unhandled_exception", "abort_program",
	};
	for (auto p : kNoreturn) {
		if (name == p)
			return true;
	}
	return false;
}

}

void populate_from_pe(function_db_t& db,
                      const DisasmFile& file,
                      const pe_parser::pe_info_t* pe_info)
{
	db.clear();

	if (!file.loaded || file.sections.empty())
		return;

	db.image_base = file.image_base;
	uint64_t computed_size = 0;
	for (auto& s : file.sections) {
		uint64_t end = s.va + s.bytes.size();
		uint64_t rel = end > file.image_base ? end - file.image_base : 0;
		if (rel > computed_size)
			computed_size = rel;
	}
	db.image_size = computed_size;
	db.is_pe = true;

	if (pe_info) {
		db.is_64bit = pe_info->is_64bit;

		for (auto& exp : pe_info->exports) {
			symbol_record_t rec;
			rec.address = exp.address ? exp.address : (db.image_base + exp.rva);
			rec.size = 0;
			rec.name = sanitize_symbol_name(exp.name.empty()
				? std::string("ord_") + std::to_string(exp.ordinal)
				: exp.name);
			rec.display_name = exp.name.empty()
				? rec.name
				: exp.name;
			rec.kind = exp.is_forwarded ? symbol_kind_t::import : symbol_kind_t::export_;
			rec.is_external = exp.is_forwarded;
			rec.is_noreturn = !exp.name.empty() && name_is_noreturn_default(exp.name);
			db.add_symbol(std::move(rec));
		}

		for (auto& imp : pe_info->imports) {
			symbol_record_t rec;
			rec.address = imp.iat_address;
			if (rec.address == 0)
				continue;
			std::string base = imp.function_name.empty()
				? std::string("ord_") + std::to_string(imp.ordinal)
				: imp.function_name;
			rec.name = std::string("imp_") + sanitize_symbol_name(base);
			rec.display_name = imp.function_name.empty()
				? base
				: imp.function_name;
			rec.module_name = imp.module_name;
			rec.kind = symbol_kind_t::import;
			rec.is_external = true;
			rec.is_thunk = false;
			rec.is_noreturn = !imp.function_name.empty() && name_is_noreturn_default(imp.function_name);
			db.add_symbol(std::move(rec));
		}

		for (auto& sec : pe_info->sections) {
			if (sec.virtual_address == 0 || sec.virtual_size == 0)
				continue;
			symbol_record_t rec;
			rec.address = db.image_base + sec.virtual_address;
			rec.size = sec.virtual_size;
			rec.name = std::string("sec_") + sanitize_symbol_name(sec.name);
			rec.display_name = sec.name;
			rec.kind = symbol_kind_t::data;
			db.add_symbol(std::move(rec));
		}
	}

	if (file.entry_point != 0) {
		symbol_record_t rec;
		rec.address = file.entry_point;
		rec.name = "entry_point";
		rec.display_name = "entry_point";
		rec.kind = symbol_kind_t::function;
		db.add_symbol(std::move(rec));
	}
}

void populate_from_driver(function_db_t& db, uint64_t module_base)
{
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		if (module_base == 0 || (module_base >= m.base && module_base < m.base + m.size)) {
			db.image_base = m.base;
			db.image_size = m.size;
			db.is_pe = true;
			break;
		}
	}
}

void populate_default_noreturn(function_db_t& db)
{
	for (auto& s : db.symbols) {
		if (!s.is_noreturn && name_is_noreturn_default(s.display_name.empty() ? s.name : s.display_name))
			s.is_noreturn = true;
	}
}

}
