#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "../../analysis/pe_parser.hpp"

struct DisasmFile;

namespace aida_ghidra {

enum class symbol_kind_t : uint8_t
{
	unknown = 0,
	function = 1,
	import = 2,
	export_ = 3,
	data = 4,
	label = 5,
};

struct symbol_record_t
{
	uint64_t address = 0;
	uint64_t size = 0;
	std::string name;
	std::string display_name;
	std::string module_name;
	std::string calling_convention;
	symbol_kind_t kind = symbol_kind_t::unknown;
	bool is_external = false;
	bool is_thunk = false;
	bool is_noreturn = false;
};

struct function_db_t
{
	std::vector<symbol_record_t> symbols;
	std::unordered_map<uint64_t, size_t> by_address;
	std::unordered_map<std::string, size_t> by_name;
	uint64_t image_base = 0;
	uint64_t image_size = 0;
	bool is_pe = false;
	bool is_64bit = true;

	void clear();
	void add_symbol(symbol_record_t rec);
	const symbol_record_t* find_by_address(uint64_t addr) const;
	const symbol_record_t* find_containing(uint64_t addr) const;
	const symbol_record_t* find_by_name(const std::string& name) const;
	bool address_in_image(uint64_t addr) const;
};

void populate_from_pe(function_db_t& db,
                      const DisasmFile& file,
                      const pe_parser::pe_info_t* pe_info);

void populate_from_driver(function_db_t& db, uint64_t module_base);

void populate_default_noreturn(function_db_t& db);

}
