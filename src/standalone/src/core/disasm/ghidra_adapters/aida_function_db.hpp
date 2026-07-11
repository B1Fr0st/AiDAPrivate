#pragma once

#include "aida_arch_map.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "../../analysis/pe_parser.hpp"
#include "../../analysis/workspace/compact_ir.hpp"
#include "../../analysis/workspace/workspace_identity.hpp"

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

void populate_from_symbol_store(function_db_t& db);

void populate_from_workspace(
	function_db_t& db,
	const aida::analysis::workspace_identity_t& identity,
	const aida::analysis::pe_image_t* image,
	const aida::analysis::analysis_snapshot_t* snapshot);

void populate_default_noreturn(function_db_t& db);

}

namespace aida::analysis::ghidra_adapter {

struct ghidra_entity_address_key_t {
    entity_id_t entity_id = 0;
    address_t address;

    friend bool operator==(const ghidra_entity_address_key_t& lhs,
                           const ghidra_entity_address_key_t& rhs) noexcept {
        return lhs.entity_id == rhs.entity_id && lhs.address == rhs.address;
    }
};

struct ghidra_entity_address_key_hash_t {
    std::size_t operator()(const ghidra_entity_address_key_t& key) const noexcept;
};

struct ghidra_function_record_t {
    ghidra_entity_address_key_t key;
    address_t end;
    std::optional<entity_id_t> symbol_id;
    std::string name;
    std::string display_name;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    bool thunk = false;
    bool noreturn = false;
    std::vector<address_range_t> chunks;
};

struct ghidra_symbol_record_t {
    ghidra_entity_address_key_t key;
    std::string name;
    std::string ghidra_name;
    symbol_kind_t kind = symbol_kind_t::data;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct ghidra_type_record_t {
    entity_id_t id = 0;
    std::optional<address_t> address;
    std::string display_name;
    std::string canonical_type;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    bool explicitly_unknown = false;
};

struct ghidra_source_mapping_t {
    entity_id_t id = 0;
    entity_id_t function_id = 0;
    address_t address;
    std::uint32_t source_line = 0;
    std::uint32_t source_column = 0;
    std::string source_path;
};

struct ghidra_function_database_limits_t {
    std::size_t max_functions = 1U << 20;
    std::size_t max_symbols = 1U << 22;
    std::size_t max_types = 1U << 20;
    std::size_t max_source_mappings = 1U << 22;
    std::size_t max_record_string_bytes = 1U << 20;
    std::uint64_t max_total_string_bytes = 64ULL * 1024ULL * 1024ULL;
};

class ghidra_function_database_t final {
public:
    static workspace_result_t<std::shared_ptr<const ghidra_function_database_t>> create(
        const workspace_identity_t& identity,
        const workspace_image_t& image,
        const analysis_snapshot_t& snapshot,
        ghidra_language_spec_t language,
        ghidra_adapter_revision_t revision,
        std::vector<ghidra_type_record_t> types = {},
        std::vector<ghidra_source_mapping_t> source_mappings = {},
        ghidra_function_database_limits_t limits = {},
        const cancellation_token_t& cancel = {});

    const ghidra_language_spec_t& language() const noexcept { return language_; }
    const ghidra_adapter_revision_t& revision() const noexcept { return revision_; }
    const ghidra_adapter_cache_key_t& cache_key() const noexcept { return cache_key_; }
    const std::vector<ghidra_function_record_t>& functions() const noexcept {
        return functions_;
    }
    const std::vector<ghidra_symbol_record_t>& symbols() const noexcept { return symbols_; }
    const std::vector<ghidra_type_record_t>& types() const noexcept { return types_; }
    const std::vector<ghidra_source_mapping_t>& source_mappings() const noexcept {
        return source_mappings_;
    }

    const ghidra_function_record_t* find_function(
        const ghidra_entity_address_key_t& key) const noexcept;
    const ghidra_function_record_t* find_function(entity_id_t id) const noexcept;
    const ghidra_function_record_t* find_containing_function(
        const address_t& address) const noexcept;
    const ghidra_symbol_record_t* find_symbol(
        const ghidra_entity_address_key_t& key) const noexcept;
    const ghidra_symbol_record_t* find_symbol(entity_id_t id) const noexcept;
    const ghidra_type_record_t* find_type(entity_id_t id) const noexcept;

private:
    ghidra_function_database_t(
        ghidra_language_spec_t language,
        ghidra_adapter_revision_t revision,
        ghidra_adapter_cache_key_t cache_key,
        std::vector<ghidra_function_record_t> functions,
        std::vector<ghidra_symbol_record_t> symbols,
        std::vector<ghidra_type_record_t> types,
        std::vector<ghidra_source_mapping_t> source_mappings,
        std::unordered_map<entity_id_t, std::size_t> function_by_id,
        std::unordered_map<ghidra_entity_address_key_t, std::size_t,
                           ghidra_entity_address_key_hash_t> function_by_key,
        std::unordered_map<entity_id_t, std::size_t> symbol_by_id,
        std::unordered_map<ghidra_entity_address_key_t, std::size_t,
                           ghidra_entity_address_key_hash_t> symbol_by_key,
        std::unordered_map<entity_id_t, std::size_t> type_by_id);

    ghidra_language_spec_t language_;
    ghidra_adapter_revision_t revision_;
    ghidra_adapter_cache_key_t cache_key_;
    std::vector<ghidra_function_record_t> functions_;
    std::vector<ghidra_symbol_record_t> symbols_;
    std::vector<ghidra_type_record_t> types_;
    std::vector<ghidra_source_mapping_t> source_mappings_;
    std::unordered_map<entity_id_t, std::size_t> function_by_id_;
    std::unordered_map<ghidra_entity_address_key_t, std::size_t,
                       ghidra_entity_address_key_hash_t> function_by_key_;
    std::unordered_map<entity_id_t, std::size_t> symbol_by_id_;
    std::unordered_map<ghidra_entity_address_key_t, std::size_t,
                       ghidra_entity_address_key_hash_t> symbol_by_key_;
    std::unordered_map<entity_id_t, std::size_t> type_by_id_;
};

}
