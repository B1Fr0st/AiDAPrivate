#pragma once

#include <windows.h>
#include <shlobj.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <memory>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "workspace/workspace_types.hpp"

#include "pdb_default_skip.hpp"
#include "pdb_events.hpp"
#include "pdb_parser.hpp"
#include "pdb_downloader.hpp"
#include "standalone_driver.hpp"
#include "standalone_settings.hpp"
#include "../testlab/test_all_features.hpp"
#include "../anti-tamper/state.hpp"
#include "../infra/executor.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "../infra/cancellation_watchdog.hpp"
#include "../../helpers/diag_log.hpp"

extern settings_sa_t g_settings;

namespace symbol_store {

inline constexpr size_t kMaximumModules = 4096;
inline constexpr size_t kMaximumPaths = 4096;
inline constexpr size_t kMaximumPathBytes = 1024 * 1024;
inline constexpr size_t kMaximumSymbols = 4 * 1024 * 1024;
inline constexpr size_t kMaximumStructs = 1024 * 1024;
inline constexpr size_t kMaximumEnums = 1024 * 1024;
inline constexpr size_t kMaximumMembers = 4 * 1024 * 1024;
inline constexpr size_t kMaximumSourceLines = 4 * 1024 * 1024;
inline constexpr size_t kMaximumSourceFiles = 1024 * 1024;
inline constexpr size_t kMaximumUtf8Bytes = 512ULL * 1024ULL * 1024ULL;
inline constexpr size_t kMaximumStringBytes = 64 * 1024;
inline constexpr size_t kMaximumResolvedNameBytes = 128 * 1024;

struct module_symbols_t {
	std::string                               module_name;
	uint64_t                                  base = 0;
	uint64_t                                  size = 0;
	pdb_parser::pdb_info_t                    pdb;
	bool                                      loading = false;
	bool                                      failed = false;
	bool                                      load_declined = false;
	std::string                               status_text;
	std::string                               pdb_path;
	uint64_t                                  pdb_file_size = 0;
	bool                                      parse_completed = false;
	std::string                               load_failure_detail;
	std::string                               load_phase;
	uint64_t                                  load_generation = 0;
	uint64_t                                  load_started_ms = 0;
	uint32_t                                  load_timeout_ms = 0;
	float                                     parse_progress = 0.0f;
	uint64_t                                  parse_progress_ms = 0;
	std::string                               parse_diagnostic;
	uint64_t                                  download_total = 0;
	uint64_t                                  download_received = 0;
	int                                       download_percent = 0;
	bool                                      downloading = false;
};

struct state_t {
	std::unordered_map<std::string, module_symbols_t> modules;
	std::mutex                                        mutex;
	std::vector<std::string>                          search_paths;
	std::string                                       cache_dir;
	bool                                              auto_download = false;
	std::string                                       symbol_server_url = "https://msdl.microsoft.com/download/symbols";
};

struct workspace_symbol_t {
	aida::analysis::address_t address;
	std::uint64_t size = 0;
	std::string name;
	std::string module_name;
	bool is_function = false;
};

struct workspace_path_snapshot_t {
	std::vector<std::string> search_paths;
	std::string cache_dir;
	uint64_t revision = 0;
	bool truncated = false;
};

struct source_module_snapshot_t {
	std::string module_name;
	uint64_t base = 0;
	uint64_t size = 0;
	uint64_t load_generation = 0;
	std::shared_ptr<const pdb_parser::source_line_table_t> source_lines;
};

class workspace_state_t {
public:
	explicit workspace_state_t(aida::analysis::binary_id_t binary_id)
		: binary_id_(std::move(binary_id)) {}

	const aida::analysis::binary_id_t& binary_id() const noexcept { return binary_id_; }
	uint64_t revision() const noexcept { return revision_.load(std::memory_order_acquire); }

	bool upsert_module(module_symbols_t module) {
		module_budget_t budget;
		if (!measure_module(module, budget)) return false;
		auto function_index = build_function_index(module);
		const std::string key = module_key(module.module_name);
		if (key.empty()) return false;
		std::lock_guard<std::mutex> lock(mutex_);
		const auto existing = modules_.find(key);
		if (existing == modules_.end() && modules_.size() >= kMaximumModules)
			return false;
		if (!module_range_fits_locked(key, module) ||
			!aggregate_fits_locked(key, budget)) return false;
		modules_.insert_or_assign(key, std::move(module));
		module_budgets_.insert_or_assign(key, budget);
		function_indexes_.insert_or_assign(key, std::move(function_index));
		revision_.fetch_add(1, std::memory_order_acq_rel);
		return true;
	}

	bool update_module(const std::string& module_name, module_symbols_t module) {
		const std::string key = module_key(module_name);
		if (key.empty() || module_key(module.module_name) != key) return false;
		module_budget_t budget;
		if (!measure_module(module, budget)) return false;
		auto function_index = build_function_index(module);
		std::lock_guard<std::mutex> lock(mutex_);
		auto found = modules_.find(key);
		if (found == modules_.end()) return false;
		if (!module_range_fits_locked(key, module) ||
			!aggregate_fits_locked(key, budget)) return false;
		found->second = std::move(module);
		module_budgets_.insert_or_assign(key, budget);
		function_indexes_.insert_or_assign(key, std::move(function_index));
		revision_.fetch_add(1, std::memory_order_acq_rel);
		return true;
	}

	void erase_module(const std::string& module_name) {
		const std::string key = module_key(module_name);
		if (key.empty()) return;
		std::lock_guard<std::mutex> lock(mutex_);
		if (modules_.erase(key) != 0) {
			module_budgets_.erase(key);
			function_indexes_.erase(key);
			revision_.fetch_add(1, std::memory_order_acq_rel);
		}
	}

	void clear() {
		std::lock_guard<std::mutex> lock(mutex_);
		if (modules_.empty() && search_paths_.empty() && cache_dir_.empty()) return;
		modules_.clear();
		module_budgets_.clear();
		function_indexes_.clear();
		search_paths_.clear();
		cache_dir_.clear();
		revision_.fetch_add(1, std::memory_order_acq_rel);
	}

	bool configure_paths(std::vector<std::string> search_paths,
		std::string cache_dir) {
		if (search_paths.size() > kMaximumPaths ||
			cache_dir.size() > kMaximumPathBytes ||
			cache_dir.find('\0') != std::string::npos)
			return false;
		size_t consumed = cache_dir.size();
		for (const auto& path : search_paths) {
			if (path.empty() || path.size() > 32768 ||
				path.find('\0') != std::string::npos ||
				path.size() > kMaximumPathBytes - consumed)
				return false;
			consumed += path.size();
		}
		std::lock_guard<std::mutex> lock(mutex_);
		if (search_paths_ == search_paths && cache_dir_ == cache_dir) return true;
		search_paths_ = std::move(search_paths);
		cache_dir_ = std::move(cache_dir);
		revision_.fetch_add(1, std::memory_order_acq_rel);
		return true;
	}

	workspace_path_snapshot_t path_snapshot(
		size_t maximum_paths = 4096,
		size_t maximum_utf8_bytes = 1024 * 1024) const {
		workspace_path_snapshot_t output;
		if (maximum_paths == 0 || maximum_paths > 4096 ||
			maximum_utf8_bytes == 0 || maximum_utf8_bytes > 1024 * 1024) {
			output.truncated = true;
			return output;
		}
		std::lock_guard<std::mutex> lock(mutex_);
		output.revision = revision_.load(std::memory_order_acquire);
		size_t consumed = 0;
		output.search_paths.reserve((std::min)(maximum_paths, search_paths_.size()));
		for (const auto& path : search_paths_) {
			if (output.search_paths.size() == maximum_paths ||
				path.size() > maximum_utf8_bytes - consumed) {
				output.truncated = true;
				break;
			}
			consumed += path.size();
			output.search_paths.push_back(path);
		}
		if (cache_dir_.size() <= maximum_utf8_bytes - consumed) {
			output.cache_dir = cache_dir_;
		} else {
			output.truncated = true;
		}
		if (output.search_paths.size() != search_paths_.size())
			output.truncated = true;
		return output;
	}

	std::optional<module_symbols_t> module_snapshot(
		const std::string& module_name,
		size_t maximum_symbols = 4 * 1024 * 1024) const {
		if (module_name.empty() || maximum_symbols == 0 ||
			maximum_symbols > kMaximumSymbols)
			return std::nullopt;
		const std::string key = module_key(module_name);
		if (key.empty()) return std::nullopt;
		std::lock_guard<std::mutex> lock(mutex_);
		auto found = modules_.find(key);
		if (found == modules_.end() ||
			found->second.pdb.symbols.size() > maximum_symbols)
			return std::nullopt;
		return found->second;
	}

	std::optional<module_symbols_t> module_snapshot_containing(
		const aida::analysis::address_t& address,
		size_t maximum_symbols = 4 * 1024 * 1024) const {
		if ((address.space != aida::analysis::address_space_id_t::virtual_address &&
			 address.space != aida::analysis::address_space_id_t::live_virtual) ||
			maximum_symbols == 0 || maximum_symbols > kMaximumSymbols)
			return std::nullopt;
		std::lock_guard<std::mutex> lock(mutex_);
		for (const auto& item : modules_) {
			const auto& module = item.second;
			if (module.size == 0 || address.value < module.base ||
				address.value - module.base >= module.size)
				continue;
			if (module.pdb.symbols.size() > maximum_symbols)
				return std::nullopt;
			return module;
		}
		return std::nullopt;
	}

	std::optional<workspace_symbol_t> symbol_snapshot_exact(
		const aida::analysis::address_t& address) const {
		if (address.space != aida::analysis::address_space_id_t::virtual_address &&
			address.space != aida::analysis::address_space_id_t::live_virtual)
			return std::nullopt;
		std::lock_guard<std::mutex> lock(mutex_);
		for (const auto& item : modules_) {
			const auto& module = item.second;
			if (!module.pdb.loaded || module.size == 0 || address.value < module.base ||
				address.value - module.base >= module.size)
				continue;
			const uint64_t rva = address.value - module.base;
			auto found = module.pdb.symbol_by_rva.find(rva);
			if (found == module.pdb.symbol_by_rva.end() ||
				found->second >= module.pdb.symbols.size())
				return std::nullopt;
			const auto& symbol = module.pdb.symbols[found->second];
			workspace_symbol_t result;
			result.address = address;
			result.size = symbol.size;
			result.name = symbol.name;
			result.module_name = module.module_name;
			result.is_function = symbol.is_function;
			return result;
		}
		return std::nullopt;
	}

	std::string resolve_exact(const aida::analysis::address_t& address) const {
		auto symbol = symbol_snapshot_exact(address);
		return symbol ? symbol->name : std::string{};
	}

	std::string resolve_nearest(const aida::analysis::address_t& address,
		uint64_t maximum_distance = 0x10000) const {
		if ((address.space != aida::analysis::address_space_id_t::virtual_address &&
			 address.space != aida::analysis::address_space_id_t::live_virtual) ||
			maximum_distance == 0 || maximum_distance > 0x1000000)
			return {};
		std::lock_guard<std::mutex> lock(mutex_);
		for (const auto& item : modules_) {
			const auto& module = item.second;
			if (!module.pdb.loaded || module.size == 0 || address.value < module.base ||
				address.value - module.base >= module.size)
				continue;
			const uint64_t rva = address.value - module.base;
			auto exact = module.pdb.symbol_by_rva.find(rva);
			if (exact != module.pdb.symbol_by_rva.end() &&
				exact->second < module.pdb.symbols.size())
				return format_resolved_name(module.module_name,
					module.pdb.symbols[exact->second].name, 0);
			const auto index_found = function_indexes_.find(item.first);
			if (index_found == function_indexes_.end() || index_found->second.empty())
				return {};
			const auto& index = index_found->second;
			auto after = std::upper_bound(index.begin(), index.end(), rva,
				[](uint64_t value, const auto& item) { return value < item.first; });
			if (after == index.begin()) return {};
			--after;
			if (after->second >= module.pdb.symbols.size()) return {};
			const auto& best = module.pdb.symbols[after->second];
			const uint64_t distance = rva - best.rva;
			if (distance >= maximum_distance) return {};
			return format_resolved_name(module.module_name, best.name, distance);
		}
		return {};
	}

	std::vector<std::pair<std::string, module_symbols_t>> modules_snapshot(
		size_t maximum_modules = kMaximumModules) const {
		if (maximum_modules == 0 || maximum_modules > kMaximumModules) return {};
		std::lock_guard<std::mutex> lock(mutex_);
		if (modules_.size() > maximum_modules) return {};
		std::vector<std::pair<std::string, module_symbols_t>> output;
		output.reserve(modules_.size());
		for (const auto& item : modules_)
			output.emplace_back(item.second.module_name, item.second);
		return output;
	}

	std::vector<workspace_symbol_t> function_snapshot(
		aida::analysis::architecture_id_t architecture,
		aida::analysis::architecture_mode_t mode,
		size_t maximum_functions = kMaximumSymbols,
		aida::analysis::address_space_id_t address_space =
			aida::analysis::address_space_id_t::virtual_address) const {
		if (maximum_functions == 0 || maximum_functions > kMaximumSymbols ||
			(address_space != aida::analysis::address_space_id_t::virtual_address &&
			 address_space != aida::analysis::address_space_id_t::live_virtual))
			return {};
		std::lock_guard<std::mutex> lock(mutex_);
		std::vector<workspace_symbol_t> output;
		size_t total_functions = 0;
		for (const auto& item : function_indexes_) {
			if (item.second.size() > maximum_functions - total_functions) return {};
			total_functions += item.second.size();
		}
		output.reserve(total_functions);
		for (const auto& module_item : modules_) {
			const auto& module = module_item.second;
			if (!module.pdb.loaded || module.size == 0)
				continue;
			const auto index_found = function_indexes_.find(module_item.first);
			if (index_found == function_indexes_.end()) continue;
			for (const auto& indexed : index_found->second) {
				if (indexed.second >= module.pdb.symbols.size()) continue;
				const auto& symbol = module.pdb.symbols[indexed.second];
				if (module.base > UINT64_MAX - symbol.rva)
					continue;
				workspace_symbol_t item;
				item.address.space = address_space;
				item.address.value = module.base + symbol.rva;
				item.address.architecture = architecture;
				item.address.mode = mode;
				item.size = symbol.size;
				item.name = symbol.name;
				item.module_name = module.module_name;
				item.is_function = true;
				output.push_back(std::move(item));
			}
		}
		std::sort(output.begin(), output.end(),
			[](const workspace_symbol_t& left, const workspace_symbol_t& right) {
				if (left.address != right.address)
					return left.address < right.address;
				if (left.name != right.name)
					return left.name < right.name;
				return left.module_name < right.module_name;
			});
		return output;
	}

private:
	struct module_budget_t {
		size_t symbols = 0;
		size_t structs = 0;
		size_t enums = 0;
		size_t members = 0;
		size_t source_lines = 0;
		size_t source_files = 0;
		size_t utf8_bytes = 0;
	};

	using function_index_t = std::vector<std::pair<uint64_t, size_t>>;

	static std::string module_key(const std::string& value) {
		if (value.empty()) return {};
		std::string key = value;
		std::transform(key.begin(), key.end(), key.begin(), [](unsigned char ch) {
			return static_cast<char>(std::tolower(ch));
		});
		return key;
	}

	static std::string format_resolved_name(const std::string& module_name,
		const std::string& symbol_name, uint64_t distance) {
		if (module_name.empty() || symbol_name.empty()) return {};
		char suffix[32]{};
		if (distance != 0) {
			std::snprintf(suffix, sizeof(suffix), "+0x%llX",
				static_cast<unsigned long long>(distance));
		}
		const size_t suffix_size = std::strlen(suffix);
		if (module_name.size() > kMaximumResolvedNameBytes ||
			symbol_name.size() > kMaximumResolvedNameBytes - module_name.size() ||
			1 + suffix_size > kMaximumResolvedNameBytes - module_name.size() -
				symbol_name.size())
			return {};
		std::string result;
		result.reserve(module_name.size() + 1 + symbol_name.size() + suffix_size);
		result.append(module_name);
		result.push_back('!');
		result.append(symbol_name);
		result.append(suffix, suffix_size);
		return result;
	}

	static bool add_string_budget(size_t& total, const std::string& value) {
		if (value.size() > kMaximumStringBytes ||
			value.find('\0') != std::string::npos ||
			value.size() > kMaximumUtf8Bytes - total)
			return false;
		total += value.size();
		return true;
	}

	static bool measure_module(const module_symbols_t& module,
		module_budget_t& budget) {
		if (module.module_name.empty() || module.module_name.size() > 4096 ||
			module.module_name.find('\0') != std::string::npos ||
			(module.size != 0 && module.base > UINT64_MAX - module.size) ||
			module.pdb.symbols.size() > kMaximumSymbols ||
			module.pdb.structs.size() > kMaximumStructs ||
			module.pdb.enums.size() > kMaximumEnums ||
			module.pdb.symbol_by_name.size() > module.pdb.symbols.size() ||
			module.pdb.symbol_by_rva.size() > module.pdb.symbols.size() ||
			module.pdb.struct_by_name.size() > module.pdb.structs.size() ||
			module.pdb.struct_by_ti.size() > module.pdb.structs.size())
			return false;
		budget.symbols = module.pdb.symbols.size();
		budget.structs = module.pdb.structs.size();
		budget.enums = module.pdb.enums.size();
		if (module.pdb.source_lines) {
			const auto& source = *module.pdb.source_lines;
			if (source.lines.size() > kMaximumSourceLines ||
				source.files.size() > kMaximumSourceFiles ||
				source.line_by_rva.size() > source.lines.size())
				return false;
			budget.source_lines = source.lines.size();
			budget.source_files = source.files.size();
			if (!add_string_budget(budget.utf8_bytes, source.detail)) return false;
			for (const auto& file : source.files) {
				if (!add_string_budget(budget.utf8_bytes, file.file_path) ||
					!add_string_budget(budget.utf8_bytes, file.object_path))
					return false;
			}
			for (const auto& line : source.lines) {
				if (line.line == 0 || line.file_index >= source.files.size()) return false;
			}
			for (const auto& indexed : source.line_by_rva) {
				if (indexed.second >= source.lines.size() ||
					source.lines[indexed.second].rva != indexed.first)
					return false;
			}
			for (const auto& indexed : source.lines_by_file_line) {
				if (!add_string_budget(budget.utf8_bytes, indexed.first)) return false;
				for (const auto line_index : indexed.second) {
					if (line_index >= source.lines.size()) return false;
				}
			}
		}
		if (!add_string_budget(budget.utf8_bytes, module.module_name) ||
			!add_string_budget(budget.utf8_bytes, module.status_text) ||
			!add_string_budget(budget.utf8_bytes, module.pdb_path) ||
			!add_string_budget(budget.utf8_bytes, module.load_failure_detail) ||
			!add_string_budget(budget.utf8_bytes, module.load_phase) ||
			!add_string_budget(budget.utf8_bytes, module.parse_diagnostic) ||
			!add_string_budget(budget.utf8_bytes, module.pdb.file_path) ||
			!add_string_budget(budget.utf8_bytes, module.pdb.module_name))
			return false;
		for (const auto& symbol : module.pdb.symbols) {
			if (!add_string_budget(budget.utf8_bytes, symbol.name)) return false;
		}
		for (const auto& structure : module.pdb.structs) {
			if (!add_string_budget(budget.utf8_bytes, structure.name) ||
				structure.members.size() > kMaximumMembers - budget.members)
				return false;
			budget.members += structure.members.size();
			for (const auto& member : structure.members) {
				if (!add_string_budget(budget.utf8_bytes, member.name) ||
					!add_string_budget(budget.utf8_bytes, member.type_name))
					return false;
			}
		}
		for (const auto& enumeration : module.pdb.enums) {
			if (!add_string_budget(budget.utf8_bytes, enumeration.name) ||
				enumeration.members.size() > kMaximumMembers - budget.members)
				return false;
			budget.members += enumeration.members.size();
			for (const auto& member : enumeration.members) {
				if (!add_string_budget(budget.utf8_bytes, member.name)) return false;
			}
		}
		for (const auto& item : module.pdb.symbol_by_name) {
			if (item.second >= module.pdb.symbols.size() ||
				module.pdb.symbols[item.second].name != item.first ||
				!add_string_budget(budget.utf8_bytes, item.first))
				return false;
		}
		for (const auto& item : module.pdb.symbol_by_rva) {
			if (item.second >= module.pdb.symbols.size() ||
				module.pdb.symbols[item.second].rva != item.first)
				return false;
		}
		for (const auto& item : module.pdb.struct_by_name) {
			if (item.second >= module.pdb.structs.size() ||
				module.pdb.structs[item.second].name != item.first ||
				!add_string_budget(budget.utf8_bytes, item.first))
				return false;
		}
		for (const auto& item : module.pdb.struct_by_ti) {
			if (item.second >= module.pdb.structs.size() ||
				module.pdb.structs[item.second].type_index != item.first)
				return false;
		}
		return true;
	}

	static function_index_t build_function_index(const module_symbols_t& module) {
		function_index_t output;
		output.reserve(module.pdb.symbols.size());
		for (size_t index = 0; index < module.pdb.symbols.size(); ++index) {
			const auto& symbol = module.pdb.symbols[index];
			if (!symbol.is_function || symbol.name.empty() ||
				module.size == 0 || symbol.rva >= module.size)
				continue;
			output.emplace_back(symbol.rva, index);
		}
		std::sort(output.begin(), output.end(), [&module](const auto& left,
			const auto& right) {
			if (left.first != right.first) return left.first < right.first;
			const auto& left_name = module.pdb.symbols[left.second].name;
			const auto& right_name = module.pdb.symbols[right.second].name;
			if (left_name != right_name) return left_name < right_name;
			return left.second < right.second;
		});
		output.erase(std::unique(output.begin(), output.end(),
			[](const auto& left, const auto& right) {
				return left.first == right.first;
			}), output.end());
		return output;
	}

	bool module_range_fits_locked(const std::string& replacing,
		const module_symbols_t& candidate) const {
		if (candidate.size == 0) return true;
		const uint64_t candidate_end = candidate.base + candidate.size;
		for (const auto& item : modules_) {
			if (item.first == replacing || item.second.size == 0) continue;
			const uint64_t existing_end = item.second.base + item.second.size;
			if (candidate.base < existing_end && item.second.base < candidate_end)
				return false;
		}
		return true;
	}

	bool aggregate_fits_locked(const std::string& replacing,
		const module_budget_t& candidate) const {
		module_budget_t total = candidate;
		for (const auto& item : module_budgets_) {
			if (item.first == replacing) continue;
			const auto& value = item.second;
			if (value.symbols > kMaximumSymbols - total.symbols ||
				value.structs > kMaximumStructs - total.structs ||
				value.enums > kMaximumEnums - total.enums ||
				value.members > kMaximumMembers - total.members ||
				value.source_lines > kMaximumSourceLines - total.source_lines ||
				value.source_files > kMaximumSourceFiles - total.source_files ||
				value.utf8_bytes > kMaximumUtf8Bytes - total.utf8_bytes)
				return false;
			total.symbols += value.symbols;
			total.structs += value.structs;
			total.enums += value.enums;
			total.members += value.members;
			total.source_lines += value.source_lines;
			total.source_files += value.source_files;
			total.utf8_bytes += value.utf8_bytes;
		}
		return true;
	}

	aida::analysis::binary_id_t binary_id_;
	mutable std::mutex mutex_;
	std::map<std::string, module_symbols_t> modules_;
	std::map<std::string, module_budget_t> module_budgets_;
	std::map<std::string, function_index_t> function_indexes_;
	std::vector<std::string> search_paths_;
	std::string cache_dir_;
	std::atomic<uint64_t> revision_{0};
};

struct pdb_module_persist_header_t {
	std::string                    module_name;
	uint64_t                       base = 0;
	uint64_t                       size = 0;
	std::array<uint8_t, 16>        pdb_guid{};
	uint32_t                       pdb_age = 0;
	std::string                    pdb_path;
	uint64_t                       pdb_file_size = 0;
	uint64_t                       pdb_volume_serial = 0;
	std::array<uint8_t, 16>        pdb_file_id{};
	uint64_t                       pdb_last_write_100ns = 0;
	uint32_t                       symbol_count = 0;
	uint32_t                       struct_count = 0;
	uint32_t                       enum_count = 0;
	uint32_t                       source_line_count = 0;
};

inline constexpr uint32_t kPdbModulePersistMagic = 0x4D424450;
inline constexpr uint32_t kPdbSourceLinesPersistMagic = 0x53424450;
inline constexpr uint32_t kPdbModulePersistVersion = 1;
inline constexpr size_t kMaximumPdbModulePersistBytes = 256ULL * 1024ULL * 1024ULL;

class pdb_persist_writer_t {
public:
	pdb_persist_writer_t() { buffer_.reserve(1024 * 1024); }

	bool ok() const noexcept { return ok_; }
	size_t size() const noexcept { return buffer_.size(); }
	const std::vector<uint8_t>& data() const noexcept { return buffer_; }

	bool u8(uint8_t value) { return raw(&value, sizeof(value)); }
	bool u32(uint32_t value) { return raw(&value, sizeof(value)); }
	bool u64(uint64_t value) { return raw(&value, sizeof(value)); }
	bool i32(int32_t value) { return raw(&value, sizeof(value)); }
	bool i64(int64_t value) { return raw(&value, sizeof(value)); }

	bool raw(const void* data, size_t count) {
		if (!ok_ || count > kMaximumPdbModulePersistBytes - buffer_.size()) {
			ok_ = false;
			return false;
		}
		const auto* first = static_cast<const uint8_t*>(data);
		try {
			buffer_.insert(buffer_.end(), first, first + count);
		} catch (...) {
			ok_ = false;
			return false;
		}
		return true;
	}

	bool text(const std::string& value) {
		if (!ok_ || value.size() > kMaximumStringBytes ||
			value.find('\0') != std::string::npos ||
			value.size() > kMaximumUtf8Bytes - utf8_bytes_) {
			ok_ = false;
			return false;
		}
		if (!u32(static_cast<uint32_t>(value.size())))
			return false;
		if (!value.empty() && !raw(value.data(), value.size()))
			return false;
		utf8_bytes_ += value.size();
		return true;
	}

private:
	std::vector<uint8_t> buffer_;
	size_t utf8_bytes_ = 0;
	bool ok_ = true;
};

class pdb_persist_reader_t {
public:
	pdb_persist_reader_t(const uint8_t* data, size_t size) : data_(data), size_(size) {}
	explicit pdb_persist_reader_t(const std::vector<uint8_t>& bytes)
		: data_(bytes.data()), size_(bytes.size()) {}

	bool ok() const noexcept { return ok_; }
	size_t remaining() const noexcept { return size_ - cursor_; }
	bool eof() const noexcept { return cursor_ == size_; }

	bool u8(uint8_t& value) { return raw(&value, sizeof(value)); }
	bool u32(uint32_t& value) { return raw(&value, sizeof(value)); }
	bool u64(uint64_t& value) { return raw(&value, sizeof(value)); }
	bool i32(int32_t& value) { return raw(&value, sizeof(value)); }
	bool i64(int64_t& value) { return raw(&value, sizeof(value)); }

	bool raw(void* output, size_t count) {
		if (!ok_ || count > size_ - cursor_) {
			ok_ = false;
			return false;
		}
		if (count != 0)
			std::memcpy(output, data_ + cursor_, count);
		cursor_ += count;
		return true;
	}

	bool text(std::string& value) {
		uint32_t length = 0;
		if (!u32(length) || length > kMaximumStringBytes ||
			length > kMaximumUtf8Bytes - utf8_bytes_ ||
			length > size_ - cursor_) {
			ok_ = false;
			return false;
		}
		if (length == 0) {
			value.clear();
			return true;
		}
		try {
			value.assign(reinterpret_cast<const char*>(data_ + cursor_),
				static_cast<size_t>(length));
		} catch (...) {
			ok_ = false;
			return false;
		}
		if (value.find('\0') != std::string::npos) {
			ok_ = false;
			return false;
		}
		cursor_ += length;
		utf8_bytes_ += length;
		return true;
	}

private:
	const uint8_t* data_ = nullptr;
	size_t size_ = 0;
	size_t cursor_ = 0;
	size_t utf8_bytes_ = 0;
	bool ok_ = true;
};

namespace pdb_persist_detail {

inline bool count_fits(uint32_t count, size_t maximum, size_t min_record_bytes,
	const pdb_persist_reader_t& reader) {
	return count <= maximum &&
		(min_record_bytes == 0 || count <= reader.remaining() / min_record_bytes);
}

inline bool serialize_symbols(pdb_persist_writer_t& writer, const pdb_parser::pdb_info_t& pdb) {
	if (pdb.symbols.size() > kMaximumSymbols)
		return false;
	if (!writer.u32(static_cast<uint32_t>(pdb.symbols.size())))
		return false;
	for (const auto& symbol : pdb.symbols) {
		if (!writer.text(symbol.name) || !writer.u64(symbol.rva) ||
			!writer.u32(symbol.type_index) || !writer.u32(symbol.size) ||
			!writer.u8(symbol.is_function ? 1 : 0))
			return false;
	}
	return true;
}

inline bool serialize_structs(pdb_persist_writer_t& writer, const pdb_parser::pdb_info_t& pdb) {
	if (pdb.structs.size() > kMaximumStructs)
		return false;
	if (!writer.u32(static_cast<uint32_t>(pdb.structs.size())))
		return false;
	size_t members = 0;
	for (const auto& structure : pdb.structs) {
		if (structure.members.size() > kMaximumMembers - members)
			return false;
		members += structure.members.size();
		if (!writer.text(structure.name) || !writer.u64(structure.size) ||
			!writer.u32(structure.type_index) ||
			!writer.u8(structure.is_union ? 1 : 0) ||
			!writer.u32(static_cast<uint32_t>(structure.members.size())))
			return false;
		for (const auto& member : structure.members) {
			if (!writer.text(member.name) || !writer.text(member.type_name) ||
				!writer.u64(member.offset) || !writer.u64(member.size) ||
				!writer.u32(member.type_index) ||
				!writer.i32(static_cast<int32_t>(member.bit_offset)) ||
				!writer.i32(static_cast<int32_t>(member.bit_size)) ||
				!writer.u8(member.is_pointer ? 1 : 0) ||
				!writer.i32(static_cast<int32_t>(member.pointer_depth)) ||
				!writer.u8(member.is_array ? 1 : 0) ||
				!writer.i32(static_cast<int32_t>(member.array_count)))
				return false;
		}
	}
	return true;
}

inline bool serialize_enums(pdb_persist_writer_t& writer, const pdb_parser::pdb_info_t& pdb) {
	if (pdb.enums.size() > kMaximumEnums)
		return false;
	if (!writer.u32(static_cast<uint32_t>(pdb.enums.size())))
		return false;
	size_t members = 0;
	for (const auto& enumeration : pdb.enums) {
		if (enumeration.members.size() > kMaximumMembers - members)
			return false;
		members += enumeration.members.size();
		if (!writer.text(enumeration.name) || !writer.u32(enumeration.type_index) ||
			!writer.u32(static_cast<uint32_t>(enumeration.members.size())))
			return false;
		for (const auto& member : enumeration.members) {
			if (!writer.text(member.name) || !writer.i64(member.value))
				return false;
		}
	}
	return true;
}

inline bool write_source_line_fields(pdb_persist_writer_t& writer,
	const pdb_parser::source_line_table_t& source) {
	if (source.files.size() > kMaximumSourceFiles ||
		source.lines.size() > kMaximumSourceLines)
		return false;
	if (!writer.u64(source.generation) ||
		!writer.u8(static_cast<uint8_t>(source.state)) ||
		!writer.text(source.detail) ||
		!writer.u32(static_cast<uint32_t>(source.files.size())))
		return false;
	for (const auto& file : source.files) {
		if (!writer.text(file.file_path) || !writer.text(file.object_path))
			return false;
	}
	if (!writer.u32(static_cast<uint32_t>(source.lines.size())))
		return false;
	for (const auto& line : source.lines) {
		if (!writer.u64(line.rva) || !writer.u32(line.line) ||
			!writer.u32(line.file_index))
			return false;
	}
	return true;
}

inline bool serialize_source_lines(pdb_persist_writer_t& writer,
	const pdb_parser::source_line_table_t* source) {
	if (!source)
		return writer.u8(0);
	return writer.u8(1) && write_source_line_fields(writer, *source);
}

inline bool read_source_line_fields(pdb_persist_reader_t& reader,
	pdb_parser::source_line_table_t& source) {
	uint8_t state = 0;
	uint32_t file_count = 0;
	if (!reader.u64(source.generation) || !reader.u8(state) || state > 6 ||
		!reader.text(source.detail) || !reader.u32(file_count) ||
		!count_fits(file_count, kMaximumSourceFiles, 8, reader))
		return false;
	source.state = static_cast<pdb_parser::source_line_state_t>(state);
	try {
		source.files.reserve(file_count);
	} catch (...) {
		return false;
	}
	for (uint32_t index = 0; index < file_count; ++index) {
		pdb_parser::source_file_t file;
		if (!reader.text(file.file_path) || !reader.text(file.object_path))
			return false;
		try {
			source.files.push_back(std::move(file));
		} catch (...) {
			return false;
		}
	}
	uint32_t line_count = 0;
	if (!reader.u32(line_count) ||
		!count_fits(line_count, kMaximumSourceLines, 16, reader))
		return false;
	try {
		source.lines.reserve(line_count);
	} catch (...) {
		return false;
	}
	for (uint32_t index = 0; index < line_count; ++index) {
		pdb_parser::source_line_t line;
		if (!reader.u64(line.rva) || !reader.u32(line.line) ||
			!reader.u32(line.file_index))
			return false;
		if (line.line == 0 || line.file_index >= source.files.size())
			return false;
		try {
			source.lines.push_back(line);
		} catch (...) {
			return false;
		}
	}
	return true;
}

inline bool rebuild_source_line_indexes(pdb_parser::source_line_table_t& source) {
	for (size_t index = 0; index < source.lines.size(); ++index) {
		const auto& line = source.lines[index];
		source.line_by_rva.try_emplace(line.rva, index);
		const auto key = pdb_parser::detail::source_file_line_key(
			pdb_parser::detail::source_path_key(source.files[line.file_index].file_path),
			line.line);
		if (key.empty())
			continue;
		try {
			source.lines_by_file_line[key].push_back(index);
		} catch (...) {
			return false;
		}
	}
	return true;
}

inline bool deserialize_source_lines(pdb_persist_reader_t& reader, pdb_parser::pdb_info_t& pdb,
	uint32_t& line_count_out) {
	uint8_t has_source = 0;
	if (!reader.u8(has_source) || has_source > 1)
		return false;
	line_count_out = 0;
	if (has_source == 0)
		return true;
	std::shared_ptr<pdb_parser::source_line_table_t> source_owner;
	try {
		source_owner = std::make_shared<pdb_parser::source_line_table_t>();
	} catch (...) {
		return false;
	}
	if (!read_source_line_fields(reader, *source_owner) ||
		!rebuild_source_line_indexes(*source_owner))
		return false;
	line_count_out = static_cast<uint32_t>(source_owner->lines.size());
	pdb.source_lines = std::shared_ptr<const pdb_parser::source_line_table_t>(
		std::move(source_owner));
	return true;
}

inline bool deserialize_symbols(pdb_persist_reader_t& reader, pdb_parser::pdb_info_t& pdb,
	uint32_t& count_out) {
	uint32_t count = 0;
	if (!reader.u32(count) ||
		!count_fits(count, kMaximumSymbols, 21, reader))
		return false;
	try {
		pdb.symbols.reserve(count);
	} catch (...) {
		return false;
	}
	for (uint32_t index = 0; index < count; ++index) {
		pdb_parser::pdb_symbol_t symbol;
		uint8_t is_function = 0;
		if (!reader.text(symbol.name) || !reader.u64(symbol.rva) ||
			!reader.u32(symbol.type_index) || !reader.u32(symbol.size) ||
			!reader.u8(is_function) || is_function > 1)
			return false;
		symbol.is_function = is_function != 0;
		try {
			pdb.symbols.push_back(std::move(symbol));
		} catch (...) {
			return false;
		}
	}
	count_out = count;
	return true;
}

inline bool deserialize_structs(pdb_persist_reader_t& reader, pdb_parser::pdb_info_t& pdb,
	size_t& members_total, uint32_t& count_out) {
	uint32_t count = 0;
	if (!reader.u32(count) ||
		!count_fits(count, kMaximumStructs, 21, reader))
		return false;
	try {
		pdb.structs.reserve(count);
	} catch (...) {
		return false;
	}
	for (uint32_t index = 0; index < count; ++index) {
		pdb_parser::struct_def_t structure;
		uint8_t is_union = 0;
		uint32_t member_count = 0;
		if (!reader.text(structure.name) || !reader.u64(structure.size) ||
			!reader.u32(structure.type_index) || !reader.u8(is_union) ||
			is_union > 1 || !reader.u32(member_count) ||
			member_count > kMaximumMembers - members_total ||
			!count_fits(member_count, kMaximumMembers, 46, reader))
			return false;
		structure.is_union = is_union != 0;
		try {
			structure.members.reserve(member_count);
		} catch (...) {
			return false;
		}
		for (uint32_t member_index = 0; member_index < member_count; ++member_index) {
			pdb_parser::struct_member_t member;
			int32_t bit_offset = 0;
			int32_t bit_size = 0;
			uint8_t is_pointer = 0;
			int32_t pointer_depth = 0;
			uint8_t is_array = 0;
			int32_t array_count = 0;
			if (!reader.text(member.name) || !reader.text(member.type_name) ||
				!reader.u64(member.offset) || !reader.u64(member.size) ||
				!reader.u32(member.type_index) || !reader.i32(bit_offset) ||
				!reader.i32(bit_size) || !reader.u8(is_pointer) || is_pointer > 1 ||
				!reader.i32(pointer_depth) || !reader.u8(is_array) || is_array > 1 ||
				!reader.i32(array_count))
				return false;
			member.bit_offset = bit_offset;
			member.bit_size = bit_size;
			member.is_pointer = is_pointer != 0;
			member.pointer_depth = pointer_depth;
			member.is_array = is_array != 0;
			member.array_count = array_count;
			try {
				structure.members.push_back(std::move(member));
			} catch (...) {
				return false;
			}
		}
		members_total += member_count;
		try {
			pdb.structs.push_back(std::move(structure));
		} catch (...) {
			return false;
		}
	}
	count_out = count;
	return true;
}

inline bool deserialize_enums(pdb_persist_reader_t& reader, pdb_parser::pdb_info_t& pdb,
	size_t& members_total, uint32_t& count_out) {
	uint32_t count = 0;
	if (!reader.u32(count) ||
		!count_fits(count, kMaximumEnums, 12, reader))
		return false;
	try {
		pdb.enums.reserve(count);
	} catch (...) {
		return false;
	}
	for (uint32_t index = 0; index < count; ++index) {
		pdb_parser::enum_def_t enumeration;
		uint32_t member_count = 0;
		if (!reader.text(enumeration.name) || !reader.u32(enumeration.type_index) ||
			!reader.u32(member_count) ||
			member_count > kMaximumMembers - members_total ||
			!count_fits(member_count, kMaximumMembers, 12, reader))
			return false;
		try {
			enumeration.members.reserve(member_count);
		} catch (...) {
			return false;
		}
		for (uint32_t member_index = 0; member_index < member_count; ++member_index) {
			pdb_parser::enum_member_t member;
			if (!reader.text(member.name) || !reader.i64(member.value))
				return false;
			try {
				enumeration.members.push_back(std::move(member));
			} catch (...) {
				return false;
			}
		}
		members_total += member_count;
		try {
			pdb.enums.push_back(std::move(enumeration));
		} catch (...) {
			return false;
		}
	}
	count_out = count;
	return true;
}

}

inline std::optional<std::vector<uint8_t>> serialize_module(
	const pdb_module_persist_header_t& header, const module_symbols_t& module,
	bool include_source_lines = true) {
	if (header.module_name.empty() || header.module_name != module.module_name ||
		header.module_name.size() > 4096 ||
		header.module_name.find('\0') != std::string::npos ||
		header.base != module.base || header.size != module.size ||
		(module.size != 0 && module.base > UINT64_MAX - module.size) ||
		header.symbol_count != module.pdb.symbols.size() ||
		header.struct_count != module.pdb.structs.size() ||
		header.enum_count != module.pdb.enums.size() ||
		header.symbol_count > kMaximumSymbols ||
		header.struct_count > kMaximumStructs ||
		header.enum_count > kMaximumEnums)
		return std::nullopt;
	const uint64_t source_line_count = module.pdb.source_lines
		? static_cast<uint64_t>(module.pdb.source_lines->lines.size()) : 0;
	if (header.source_line_count != source_line_count ||
		header.source_line_count > kMaximumSourceLines)
		return std::nullopt;
	const pdb_parser::source_line_table_t* embedded_source =
		(include_source_lines && module.pdb.source_lines)
		? module.pdb.source_lines.get() : nullptr;
	pdb_persist_writer_t writer;
	if (!writer.u32(kPdbModulePersistMagic) ||
		!writer.u32(kPdbModulePersistVersion) ||
		!writer.text(header.module_name) ||
		!writer.u64(header.base) || !writer.u64(header.size) ||
		!writer.raw(header.pdb_guid.data(), header.pdb_guid.size()) ||
		!writer.u32(header.pdb_age) ||
		!writer.text(header.pdb_path) ||
		!writer.u64(header.pdb_file_size) ||
		!writer.u64(header.pdb_volume_serial) ||
		!writer.raw(header.pdb_file_id.data(), header.pdb_file_id.size()) ||
		!writer.u64(header.pdb_last_write_100ns) ||
		!writer.u32(header.symbol_count) ||
		!writer.u32(header.struct_count) ||
		!writer.u32(header.enum_count) ||
		!writer.u32(header.source_line_count) ||
		!writer.text(module.pdb.file_path) ||
		!writer.text(module.pdb.module_name) ||
		!writer.u8(module.pdb.loaded ? 1 : 0) ||
		!pdb_persist_detail::serialize_symbols(writer, module.pdb) ||
		!pdb_persist_detail::serialize_structs(writer, module.pdb) ||
		!pdb_persist_detail::serialize_enums(writer, module.pdb) ||
		!pdb_persist_detail::serialize_source_lines(writer, embedded_source) ||
		!writer.ok())
		return std::nullopt;
	return writer.data();
}

inline std::optional<std::vector<uint8_t>> serialize_module_source_lines(
	const pdb_parser::source_line_table_t& source) {
	pdb_persist_writer_t writer;
	if (!writer.u32(kPdbSourceLinesPersistMagic) ||
		!writer.u32(kPdbModulePersistVersion) ||
		!pdb_persist_detail::write_source_line_fields(writer, source) ||
		!writer.ok())
		return std::nullopt;
	return writer.data();
}

inline std::optional<std::shared_ptr<const pdb_parser::source_line_table_t>>
	deserialize_module_source_lines(pdb_persist_reader_t& reader) {
	if (reader.remaining() > kMaximumPdbModulePersistBytes)
		return std::nullopt;
	uint32_t magic = 0;
	uint32_t version = 0;
	if (!reader.u32(magic) || magic != kPdbSourceLinesPersistMagic ||
		!reader.u32(version) || version != kPdbModulePersistVersion)
		return std::nullopt;
	std::shared_ptr<pdb_parser::source_line_table_t> source_owner;
	try {
		source_owner = std::make_shared<pdb_parser::source_line_table_t>();
	} catch (...) {
		return std::nullopt;
	}
	if (!pdb_persist_detail::read_source_line_fields(reader, *source_owner) ||
		!pdb_persist_detail::rebuild_source_line_indexes(*source_owner) ||
		!reader.eof())
		return std::nullopt;
	return std::shared_ptr<const pdb_parser::source_line_table_t>(
		std::move(source_owner));
}

inline std::optional<module_symbols_t> deserialize_module(
	pdb_persist_reader_t& reader, pdb_module_persist_header_t* header_out = nullptr) {
	if (reader.remaining() > kMaximumPdbModulePersistBytes)
		return std::nullopt;
	uint32_t magic = 0;
	uint32_t version = 0;
	pdb_module_persist_header_t header;
	if (!reader.u32(magic) || magic != kPdbModulePersistMagic ||
		!reader.u32(version) || version != kPdbModulePersistVersion ||
		!reader.text(header.module_name) ||
		header.module_name.empty() || header.module_name.size() > 4096 ||
		!reader.u64(header.base) || !reader.u64(header.size) ||
		!reader.raw(header.pdb_guid.data(), header.pdb_guid.size()) ||
		!reader.u32(header.pdb_age) ||
		!reader.text(header.pdb_path) ||
		!reader.u64(header.pdb_file_size) ||
		!reader.u64(header.pdb_volume_serial) ||
		!reader.raw(header.pdb_file_id.data(), header.pdb_file_id.size()) ||
		!reader.u64(header.pdb_last_write_100ns) ||
		!reader.u32(header.symbol_count) ||
		!reader.u32(header.struct_count) ||
		!reader.u32(header.enum_count) ||
		!reader.u32(header.source_line_count))
		return std::nullopt;
	if (header.symbol_count > kMaximumSymbols ||
		header.struct_count > kMaximumStructs ||
		header.enum_count > kMaximumEnums ||
		header.source_line_count > kMaximumSourceLines ||
		(header.size != 0 && header.base > UINT64_MAX - header.size))
		return std::nullopt;
	module_symbols_t module;
	uint8_t pdb_loaded = 0;
	if (!reader.text(module.pdb.file_path) ||
		!reader.text(module.pdb.module_name) ||
		!reader.u8(pdb_loaded) || pdb_loaded > 1)
		return std::nullopt;
	module.pdb.loaded = pdb_loaded != 0;
	uint32_t symbol_count = 0;
	uint32_t struct_count = 0;
	uint32_t enum_count = 0;
	uint32_t source_line_count = 0;
	size_t members_total = 0;
	if (!pdb_persist_detail::deserialize_symbols(reader, module.pdb, symbol_count) ||
		!pdb_persist_detail::deserialize_structs(reader, module.pdb, members_total,
			struct_count) ||
		!pdb_persist_detail::deserialize_enums(reader, module.pdb, members_total,
			enum_count) ||
		!pdb_persist_detail::deserialize_source_lines(reader, module.pdb,
			source_line_count))
		return std::nullopt;
	if (symbol_count != header.symbol_count ||
		struct_count != header.struct_count ||
		enum_count != header.enum_count ||
		(module.pdb.source_lines && source_line_count != header.source_line_count) ||
		!reader.eof())
		return std::nullopt;
	module.module_name = header.module_name;
	module.base = header.base;
	module.size = header.size;
	module.pdb_path = header.pdb_path;
	module.pdb_file_size = header.pdb_file_size;
	try {
		for (size_t index = 0; index < module.pdb.symbols.size(); ++index) {
			module.pdb.symbol_by_name[module.pdb.symbols[index].name] = index;
			module.pdb.symbol_by_rva[module.pdb.symbols[index].rva] = index;
		}
		for (size_t index = 0; index < module.pdb.structs.size(); ++index) {
			if (module.pdb.structs[index].name.empty())
				continue;
			module.pdb.struct_by_name[module.pdb.structs[index].name] = index;
			module.pdb.struct_by_ti[module.pdb.structs[index].type_index] = index;
		}
	} catch (...) {
		return std::nullopt;
	}
	module.parse_completed = true;
	module.parse_progress = 1.0f;
	if (header_out)
		*header_out = std::move(header);
	return module;
}

inline state_t g_state;
inline std::atomic<uint64_t> g_load_generation{1};
inline std::atomic<uint64_t> g_source_line_generation{1};
inline constexpr uint32_t k_explicit_pdb_load_timeout_ms = 120000;

struct pdb_automation_context_t {
	bool is_running = false;
	bool anti_tamper_full_test_running = false;
	bool full_test_env_active = false;
	bool unattended_active = false;
	bool post_suppression_active = false;
	uint64_t post_suppression_remaining_ms = 0;
	bool pdb_automation_active = false;
	bool user_default_skip_active = false;
	bool pdb_skip_active = false;
};

inline bool full_test_env_active_for_pdb()
{
	char value[16] = {};
	DWORD n = GetEnvironmentVariableA("AIDA_FULL_TEST_RUNNING", value, static_cast<DWORD>(sizeof(value)));
	if (n == 0) return false;
	if (n >= sizeof(value)) return true;
	return value[0] != '\0' && !(value[0] == '0' && value[1] == '\0');
}

inline pdb_automation_context_t pdb_automation_context()
{
	pdb_automation_context_t ctx;
	ctx.is_running = test_all_features::is_running();
	ctx.anti_tamper_full_test_running = anti_tamper::state::get().full_test_running.load(std::memory_order_acquire);
	ctx.full_test_env_active = full_test_env_active_for_pdb();
	ctx.unattended_active = test_all_features::is_unattended_full_test_active();
	ctx.post_suppression_active = anti_tamper::state::full_test_suppression_active(&ctx.post_suppression_remaining_ms);
	ctx.pdb_automation_active = ctx.unattended_active || ctx.post_suppression_active;
	ctx.user_default_skip_active = pdb_default_skip::get();
	ctx.pdb_skip_active = ctx.pdb_automation_active || ctx.user_default_skip_active;
	return ctx;
}

inline bool pdb_automation_active()
{
	return pdb_automation_context().pdb_automation_active;
}

inline bool pdb_skip_active()
{
	return pdb_automation_context().pdb_skip_active;
}

inline uint64_t next_load_generation()
{
	return g_load_generation.fetch_add(1, std::memory_order_acq_rel);
}

struct load_timeout_context_t {
	std::string module_name;
	std::string phase;
	uint64_t generation = 0;
	uint32_t timeout_ms = 0;
	uint64_t scheduled_ms = 0;
	HANDLE timer = nullptr;
};

inline void apply_loading_timeout(const load_timeout_context_t& ctx) noexcept
{
	try {
		const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
		const bool dbghelp_quarantined_before = pdb_parser::dbghelp_is_quarantined();
		diag::log_tagged_critical_fmt("symbol_store",
			"apply_loading_timeout_recycle_attempt module=%s generation=%llu phase=%s timeout_ms=%u dbghelp_quarantined_before=%d",
			ctx.module_name.c_str(),
			static_cast<unsigned long long>(ctx.generation),
			ctx.phase.c_str(),
			ctx.timeout_ms,
			dbghelp_quarantined_before ? 1 : 0);
		aida::events::event_pdb_loaded ev_payload;
		bool publish_event = false;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto it = g_state.modules.find(ctx.module_name);
			if (it == g_state.modules.end())
				return;
			auto& ms = it->second;
			if (!ms.loading || ms.load_generation != ctx.generation || ms.load_phase != ctx.phase)
				return;
			ms.loading = false;
			ms.downloading = false;
			ms.failed = true;
			ms.load_declined = false;
			ms.parse_completed = false;
			ms.load_failure_detail = parser_diag;
			ms.parse_diagnostic = parser_diag;
			ms.parse_progress_ms = ms.load_started_ms ? GetTickCount64() - ms.load_started_ms : 0;
			ms.load_phase.clear();
			char buf[768];
			snprintf(buf, sizeof(buf), "Failed: PDB %s timed out after %u ms; progress=%.1f%% elapsed=%llu ms; %s",
				ctx.phase.c_str(),
				ctx.timeout_ms,
				static_cast<double>(ms.parse_progress) * 100.0,
				static_cast<unsigned long long>(ms.parse_progress_ms),
				parser_diag.c_str());
			ms.status_text = buf;
			ev_payload.module_name = ms.module_name;
			ev_payload.base = ms.base;
			ev_payload.size = ms.size;
			ev_payload.success = false;
			publish_event = true;
			diag::log_tagged_fmt("symbol_store",
				"pdb_load_timeout module=%s generation=%llu phase=%s timeout_ms=%u started_ms=%llu scheduled_ms=%llu fired_ms=%llu path='%s' file_size=%llu progress=%.3f progress_ms=%llu parser_diag=\"%s\"",
				ctx.module_name.c_str(),
				static_cast<unsigned long long>(ctx.generation),
				ctx.phase.c_str(),
				ctx.timeout_ms,
				static_cast<unsigned long long>(ms.load_started_ms),
				static_cast<unsigned long long>(ctx.scheduled_ms),
				static_cast<unsigned long long>(GetTickCount64()),
				ms.pdb_path.c_str(),
				static_cast<unsigned long long>(ms.pdb_file_size),
				static_cast<double>(ms.parse_progress),
				static_cast<unsigned long long>(ms.parse_progress_ms),
				parser_diag.c_str());
		}
		if (publish_event)
			aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);

		pdb_parser::quarantine_dbghelp_and_recycle();
		const bool dbghelp_quarantined_after = pdb_parser::dbghelp_is_quarantined();
		diag::log_tagged_critical_fmt("symbol_store",
			"apply_loading_timeout_recycle_done module=%s generation=%llu phase=%s ok=%d still_quarantined=%d",
			ctx.module_name.c_str(),
			static_cast<unsigned long long>(ctx.generation),
			ctx.phase.c_str(),
			dbghelp_quarantined_after ? 0 : 1,
			dbghelp_quarantined_after ? 1 : 0);
	} catch (const std::exception& ex) {
		auto rt = aida::infra::taskflow_runtime::active_snapshot();
		diag::log_tagged_fmt("symbol_store",
			"pdb_timeout_task_exception module=%s generation=%llu phase=%s timeout_ms=%u err=%s work_pending=%llu work_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u total_rejected=%llu",
			ctx.module_name.c_str(),
			static_cast<unsigned long long>(ctx.generation),
			ctx.phase.c_str(),
			ctx.timeout_ms,
			ex.what(),
			static_cast<unsigned long long>(rt.work_queue_pending),
			rt.work_queue_active,
			static_cast<unsigned long long>(rt.service_queue_pending),
			rt.service_queue_active,
			static_cast<unsigned long long>(rt.critical_queue_pending),
			rt.critical_queue_active,
			static_cast<unsigned long long>(rt.total_rejected));
	} catch (...) {
		auto rt = aida::infra::taskflow_runtime::active_snapshot();
		diag::log_tagged_fmt("symbol_store",
			"pdb_timeout_task_exception module=%s generation=%llu phase=%s timeout_ms=%u err=<unknown> work_pending=%llu work_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u total_rejected=%llu",
			ctx.module_name.c_str(),
			static_cast<unsigned long long>(ctx.generation),
			ctx.phase.c_str(),
			ctx.timeout_ms,
			static_cast<unsigned long long>(rt.work_queue_pending),
			rt.work_queue_active,
			static_cast<unsigned long long>(rt.service_queue_pending),
			rt.service_queue_active,
			static_cast<unsigned long long>(rt.critical_queue_pending),
			rt.critical_queue_active,
			static_cast<unsigned long long>(rt.total_rejected));
	}
}

inline void CALLBACK load_timeout_timer_cb(PVOID param, BOOLEAN) noexcept
{
	std::unique_ptr<load_timeout_context_t> ctx(static_cast<load_timeout_context_t*>(param));
	if (!ctx)
		return;
	HANDLE timer = ctx->timer;
	apply_loading_timeout(*ctx);
	if (timer && !DeleteTimerQueueTimer(nullptr, timer, nullptr)) {
		DWORD gle = GetLastError();
		if (gle != ERROR_IO_PENDING) {
			diag::log_tagged_fmt("symbol_store",
				"pdb_timeout_timer_delete_failed module=%s generation=%llu phase=%s timeout_ms=%u gle=%lu",
				ctx->module_name.c_str(),
				static_cast<unsigned long long>(ctx->generation),
				ctx->phase.c_str(),
				ctx->timeout_ms,
				static_cast<unsigned long>(gle));
		}
	}
}

inline bool schedule_loading_timeout(const std::string& module_name, uint64_t generation, uint32_t timeout_ms, const std::string& phase) noexcept
{
	try {
		auto ctx = std::make_unique<load_timeout_context_t>();
		ctx->module_name = module_name;
		ctx->generation = generation;
		ctx->timeout_ms = timeout_ms;
		ctx->phase = phase;
		ctx->scheduled_ms = GetTickCount64();

		HANDLE timer = nullptr;
		if (!CreateTimerQueueTimer(&timer, nullptr, load_timeout_timer_cb, ctx.get(), timeout_ms, 0, WT_EXECUTEDEFAULT)) {
			DWORD gle = GetLastError();
			auto rt = aida::infra::taskflow_runtime::active_snapshot();
			diag::log_tagged_fmt("symbol_store",
				"pdb_timeout_schedule_failed module=%s generation=%llu phase=%s timeout_ms=%u gle=%lu accepting=%d work_pending=%llu work_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u total_rejected=%llu",
				module_name.c_str(),
				static_cast<unsigned long long>(generation),
				phase.c_str(),
				timeout_ms,
				static_cast<unsigned long>(gle),
				rt.accepting ? 1 : 0,
				static_cast<unsigned long long>(rt.work_queue_pending),
				rt.work_queue_active,
				static_cast<unsigned long long>(rt.service_queue_pending),
				rt.service_queue_active,
				static_cast<unsigned long long>(rt.critical_queue_pending),
				rt.critical_queue_active,
				static_cast<unsigned long long>(rt.total_rejected));
			return false;
		}

		ctx->timer = timer;
		ctx.release();
		auto rt = aida::infra::taskflow_runtime::active_snapshot();
		diag::log_tagged_fmt("symbol_store",
			"pdb_timeout_schedule_ok module=%s generation=%llu phase=%s timeout_ms=%u work_pending=%llu work_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u",
			module_name.c_str(),
			static_cast<unsigned long long>(generation),
			phase.c_str(),
			timeout_ms,
			static_cast<unsigned long long>(rt.work_queue_pending),
			rt.work_queue_active,
			static_cast<unsigned long long>(rt.service_queue_pending),
			rt.service_queue_active,
			static_cast<unsigned long long>(rt.critical_queue_pending),
			rt.critical_queue_active);
		return true;
	} catch (const std::exception& ex) {
		auto rt = aida::infra::taskflow_runtime::active_snapshot();
		diag::log_tagged_fmt("symbol_store",
			"pdb_timeout_schedule_outer_exception module=%s generation=%llu phase=%s timeout_ms=%u err=%s work_pending=%llu work_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u total_rejected=%llu",
			module_name.c_str(),
			static_cast<unsigned long long>(generation),
			phase.c_str(),
			timeout_ms,
			ex.what(),
			static_cast<unsigned long long>(rt.work_queue_pending),
			rt.work_queue_active,
			static_cast<unsigned long long>(rt.service_queue_pending),
			rt.service_queue_active,
			static_cast<unsigned long long>(rt.critical_queue_pending),
			rt.critical_queue_active,
			static_cast<unsigned long long>(rt.total_rejected));
		return false;
	} catch (...) {
		auto rt = aida::infra::taskflow_runtime::active_snapshot();
		diag::log_tagged_fmt("symbol_store",
			"pdb_timeout_schedule_outer_exception module=%s generation=%llu phase=%s timeout_ms=%u err=<unknown> work_pending=%llu work_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u total_rejected=%llu",
			module_name.c_str(),
			static_cast<unsigned long long>(generation),
			phase.c_str(),
			timeout_ms,
			static_cast<unsigned long long>(rt.work_queue_pending),
			rt.work_queue_active,
			static_cast<unsigned long long>(rt.service_queue_pending),
			rt.service_queue_active,
			static_cast<unsigned long long>(rt.critical_queue_pending),
			rt.critical_queue_active,
			static_cast<unsigned long long>(rt.total_rejected));
		return false;
	}
}

inline void publish_failed_load_result(const std::string& module_name, uint64_t generation, const std::string& status_text, const char* diag_name, const char* detail_text, uint64_t elapsed_ms) noexcept
{
	try {
		aida::events::event_pdb_loaded ev_payload;
		bool publish_event = false;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto it = g_state.modules.find(module_name);
			if (it == g_state.modules.end()) {
				diag::log_tagged_fmt("symbol_store", "%s_missing module=%s generation=%llu detail=%s",
					diag_name ? diag_name : "pdb_load_failed",
					module_name.c_str(),
					static_cast<unsigned long long>(generation),
					detail_text ? detail_text : "<empty>");
				return;
			}
			auto& ms = it->second;
			if (ms.load_generation != generation) {
				diag::log_tagged_fmt("symbol_store", "%s_stale module=%s generation=%llu current_generation=%llu detail=%s",
					diag_name ? diag_name : "pdb_load_failed",
					module_name.c_str(),
					static_cast<unsigned long long>(generation),
					static_cast<unsigned long long>(ms.load_generation),
					detail_text ? detail_text : "<empty>");
				return;
			}
			if (!ms.loading) {
				diag::log_tagged_fmt("symbol_store", "%s_inactive module=%s generation=%llu status='%s' detail=%s",
					diag_name ? diag_name : "pdb_load_failed",
					module_name.c_str(),
					static_cast<unsigned long long>(generation),
					ms.status_text.c_str(),
					detail_text ? detail_text : "<empty>");
				return;
			}
			ms.loading = false;
			ms.downloading = false;
			ms.failed = true;
			ms.load_declined = false;
			ms.parse_completed = false;
			ms.load_failure_detail = detail_text ? detail_text : "";
			ms.load_phase.clear();
			ms.status_text = status_text;
			ev_payload.module_name = ms.module_name;
			ev_payload.base = ms.base;
			ev_payload.size = ms.size;
			ev_payload.success = false;
			publish_event = true;
		}
		diag::log_tagged_fmt("symbol_store", "%s module=%s generation=%llu elapsed_ms=%llu detail=%s",
			diag_name ? diag_name : "pdb_load_failed",
			module_name.c_str(),
			static_cast<unsigned long long>(generation),
			static_cast<unsigned long long>(elapsed_ms),
			detail_text ? detail_text : "<empty>");
		if (publish_event)
			aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
	} catch (...) {
		diag::log_tagged_fmt("symbol_store", "pdb_load_failed_publish_exception module=%s generation=%llu diag=%s",
			module_name.c_str(),
			static_cast<unsigned long long>(generation),
			diag_name ? diag_name : "<empty>");
	}
}

inline std::string pdb_parse_failure_status(const char* prefix)
{
	const std::string detail = pdb_parser::last_error();
	const std::string loader = pdb_parser::dbghelp_load_diagnostic();
	std::string out = prefix ? std::string(prefix) : std::string("Failed to parse PDB");
	if (!detail.empty())
		out += ": " + detail;
	if (!loader.empty())
		out += " [" + loader + "]";
	return out;
}

namespace detail {

inline std::filesystem::path get_cache_dir()
{
	if (!g_state.cache_dir.empty())
		return std::filesystem::path(g_state.cache_dir);

	wchar_t* appdata = nullptr;
	if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
		auto path = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"symbols";
		CoTaskMemFree(appdata);
		std::filesystem::create_directories(path);
		return path;
	}
	return std::filesystem::current_path() / "symbols";
}

inline std::string build_search_path()
{
	std::string sp;
	for (auto& p : g_state.search_paths) {
		if (!sp.empty()) sp += ";";
		sp += p;
	}

	auto cache = get_cache_dir().string();
	if (!sp.empty()) sp += ";";
	sp += cache;

	if (g_state.auto_download && !g_state.symbol_server_url.empty()) {
		if (!sp.empty()) sp += ";";
		sp += "srv*" + cache + "*" + g_state.symbol_server_url;
	}

	return sp;
}

inline std::string find_pdb_local(const std::string& module_name)
{
	std::string pdb_name = module_name;
	auto dot = pdb_name.rfind('.');
	if (dot != std::string::npos)
		pdb_name = pdb_name.substr(0, dot);
	pdb_name += ".pdb";

	for (auto& sp : g_state.search_paths) {
		auto candidate = std::filesystem::path(sp) / pdb_name;
		if (std::filesystem::exists(candidate))
			return candidate.string();
	}

	auto cache = get_cache_dir();
	for (auto& entry : std::filesystem::recursive_directory_iterator(cache, std::filesystem::directory_options::skip_permission_denied)) {
		if (!entry.is_regular_file()) continue;
		auto fn = entry.path().filename().string();
		if (_stricmp(fn.c_str(), pdb_name.c_str()) == 0)
			return entry.path().string();
	}

	return {};
}

}

inline void init_from_settings()
{
	g_state.search_paths.clear();

	std::string paths_str = g_settings.pdb_search_paths;
	if (!paths_str.empty()) {
		size_t pos = 0;
		while (pos < paths_str.size()) {
			size_t sep = paths_str.find(';', pos);
			if (sep == std::string::npos) sep = paths_str.size();
			std::string p = paths_str.substr(pos, sep - pos);
			if (!p.empty()) g_state.search_paths.push_back(p);
			pos = sep + 1;
		}
	}

	g_state.cache_dir = g_settings.symbol_cache_dir;
	g_state.auto_download = g_settings.symbol_auto_download;
	g_state.symbol_server_url = g_settings.symbol_server_url;
}

inline const char* log_value(const std::string& s)
{
	return s.empty() ? "<none>" : s.c_str();
}

inline std::string fallback_pdb_name_for_module(const std::string& module_name)
{
	std::filesystem::path p(module_name);
	std::string stem = p.stem().string();
	if (stem.empty()) stem = module_name;
	return stem + ".pdb";
}

inline std::string expected_cache_path_for_hint(const std::string& pdb_name,
                                                const std::string& pdb_guid,
                                                uint32_t pdb_age)
{
	if (pdb_name.empty() || pdb_guid.empty()) return {};
	char age_buf[16] = {};
	std::snprintf(age_buf, sizeof(age_buf), "%X", static_cast<unsigned>(pdb_age));
	return (detail::get_cache_dir() / pdb_name / (pdb_guid + age_buf) / pdb_name).string();
}

inline std::string safe_find_local_pdb_for_suppression(const std::string& module_name,
                                                       const char* source) noexcept
{
	try {
		return detail::find_pdb_local(module_name);
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("symbol_store",
			"fulltest_symbol_store_pdb_candidate_error source=%s module=%s err=%s",
			source && *source ? source : "<unknown>",
			log_value(module_name),
			ex.what());
	} catch (...) {
		diag::log_tagged_fmt("symbol_store",
			"fulltest_symbol_store_pdb_candidate_error source=%s module=%s err=<unknown>",
			source && *source ? source : "<unknown>",
			log_value(module_name));
	}
	return {};
}

inline bool suppress_full_test_pdb_load(const char* source,
                                        const std::string& module_name,
                                        uint64_t base,
                                        uint64_t size,
                                        const std::string& pdb_name,
                                        const std::string& pdb_guid,
                                        uint32_t pdb_age,
                                        const std::string& local_candidate,
                                        const std::string& cache_path,
                                        const std::string& explicit_path,
                                        const char* reason,
                                        bool update_module_state = true)
{
	const auto automation = pdb_automation_context();
	if (!automation.pdb_skip_active) return false;
	const uint64_t generation = next_load_generation();
	bool module_present = false;
	bool already_loaded = false;
	bool already_loading = false;
	bool final_failed = false;
	bool final_declined = false;
	bool state_updated = false;
	if (update_module_state && !module_name.empty()) {
		std::lock_guard<std::mutex> lk(g_state.mutex);
		auto it = g_state.modules.find(module_name);
		module_present = it != g_state.modules.end();
		auto& ms = module_present ? it->second : g_state.modules[module_name];
		already_loaded = ms.pdb.loaded;
		already_loading = ms.loading;
		if (!already_loaded && !already_loading) {
			ms.module_name = module_name;
			ms.base = base;
			ms.size = size;
			ms.loading = false;
			ms.downloading = false;
			ms.failed = false;
			ms.load_declined = true;
			ms.parse_completed = false;
			ms.load_phase.clear();
			ms.load_generation = generation;
			ms.load_started_ms = GetTickCount64();
			ms.load_timeout_ms = 0;
			ms.parse_progress = 0.0f;
			ms.parse_progress_ms = 0;
			ms.parse_diagnostic.clear();
			ms.load_failure_detail.clear();
			ms.pdb_path = explicit_path.empty() ? local_candidate : explicit_path;
			ms.status_text = "PDB load skipped by full-test policy";
			state_updated = true;
		}
		final_failed = ms.failed;
		final_declined = ms.load_declined;
	}
	if (!update_module_state) {
		final_failed = false;
		final_declined = true;
	}

	diag::log_tagged_fmt("symbol_store",
		"fulltest_pdb_final_decision source=%s module=%s base=0x%llX size=0x%llX pdb=%s guid=%s age=%u decision=do_not_load_pdb reason=%s local_candidate=%s cache_path=%s explicit_path=%s prompt_suppressed=1 is_running=%d anti_tamper_full_test_running=%d full_test_env_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu pdb_automation_active=%d user_default_skip_active=%d pdb_skip_active=%d",
		source && *source ? source : "<unknown>",
		log_value(module_name),
		static_cast<unsigned long long>(base),
		static_cast<unsigned long long>(size),
		log_value(pdb_name),
		log_value(pdb_guid),
		static_cast<unsigned>(pdb_age),
		reason && *reason ? reason : "full_test_declined_pdb_load",
		log_value(local_candidate),
		log_value(cache_path),
		log_value(explicit_path),
		automation.is_running ? 1 : 0,
		automation.anti_tamper_full_test_running ? 1 : 0,
		automation.full_test_env_active ? 1 : 0,
		automation.unattended_active ? 1 : 0,
		automation.post_suppression_active ? 1 : 0,
		static_cast<unsigned long long>(automation.post_suppression_remaining_ms),
		automation.pdb_automation_active ? 1 : 0,
		automation.user_default_skip_active ? 1 : 0,
		automation.pdb_skip_active ? 1 : 0);
	diag::log_tagged_fmt("symbol_store",
		"fulltest_symbol_store_pdb_suppressed decision=do_not_load_pdb source=%s module=%s base=0x%llX size=0x%llX pdb=%s guid=%s age=%u local_candidate=%s cache_path=%s explicit_path=%s reason=%s generation=%llu prompt_created=0 prompt_suppressed=1 module_present=%d loaded=%d loading=%d failed=%d declined=%d state_updated=%d is_running=%d anti_tamper_full_test_running=%d full_test_env_active=%d unattended_active=%d post_suppression_active=%d post_suppression_remaining_ms=%llu pdb_automation_active=%d user_default_skip_active=%d pdb_skip_active=%d",
		source && *source ? source : "<unknown>",
		log_value(module_name),
		static_cast<unsigned long long>(base),
		static_cast<unsigned long long>(size),
		log_value(pdb_name),
		log_value(pdb_guid),
		static_cast<unsigned>(pdb_age),
		log_value(local_candidate),
		log_value(cache_path),
		log_value(explicit_path),
		reason && *reason ? reason : "full_test_declined_pdb_load",
		static_cast<unsigned long long>(generation),
		module_present ? 1 : 0,
		already_loaded ? 1 : 0,
		already_loading ? 1 : 0,
		final_failed ? 1 : 0,
		final_declined ? 1 : 0,
		state_updated ? 1 : 0,
		automation.is_running ? 1 : 0,
		automation.anti_tamper_full_test_running ? 1 : 0,
		automation.full_test_env_active ? 1 : 0,
		automation.unattended_active ? 1 : 0,
		automation.post_suppression_active ? 1 : 0,
		static_cast<unsigned long long>(automation.post_suppression_remaining_ms),
		automation.pdb_automation_active ? 1 : 0,
		automation.user_default_skip_active ? 1 : 0,
		automation.pdb_skip_active ? 1 : 0);
	return true;
}

inline void load_pdb_from_explicit_path(const std::string& module_name, uint64_t base, uint64_t size,
                                        const std::string& pdb_path);

inline void load_pdb_for_module(const std::string& module_name, uint64_t base, uint64_t size)
{
	if (pdb_skip_active()) {
		const std::string pdb_name = fallback_pdb_name_for_module(module_name);
		const std::string local_candidate = safe_find_local_pdb_for_suppression(module_name, "load_pdb_for_module");
		if (!local_candidate.empty()) {
			diag::log_tagged_fmt("symbol_store",
				"load_pdb_for_module_auto_accept_local module=%s local_candidate=%s pdb_name=%s",
				module_name.c_str(), local_candidate.c_str(), pdb_name.c_str());
			load_pdb_from_explicit_path(module_name, base, size, local_candidate);
			return;
		}
		suppress_full_test_pdb_load("load_pdb_for_module", module_name, base, size,
			pdb_name, {}, 0, local_candidate, {}, {},
			g_state.auto_download ? "full_test_declined_auto_symbol_server_load" : "full_test_declined_auto_local_pdb_scan");
		return;
	}
	uint64_t generation = next_load_generation();
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		auto it = g_state.modules.find(module_name);
		if (it != g_state.modules.end()) {
			if (it->second.pdb.loaded || it->second.loading)
				return;
		}

		auto& ms = g_state.modules[module_name];
		ms.module_name = module_name;
		ms.base = base;
		ms.size = size;
		ms.loading = true;
		ms.failed = false;
		ms.load_declined = false;
		ms.load_phase = "queue";
		ms.load_generation = generation;
		ms.load_started_ms = GetTickCount64();
		ms.load_timeout_ms = 30000;
		ms.status_text = "Searching for PDB...";
	}

	aida::infra::executor::submission_t load_sub;
	load_sub.owner_subsystem = "symbol_store";
	load_sub.label = "symbol_store.load_pdb_for_module";
	load_sub.thread_class = "external_tool";
	load_sub.domain = aida::infra::executor::domain_t::external_tool;
	load_sub.priority = 2;
	load_sub.generation = generation;
	load_sub.target_id = module_name.c_str();
	load_sub.failure_policy = "reject_not_started";
	load_sub.body = [module_name, generation]() {
		std::string pdb_path = detail::find_pdb_local(module_name);

		if (pdb_path.empty()) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[module_name];
			if (ms.load_generation != generation || !ms.loading) {
				diag::log_tagged_fmt("symbol_store", "load_pdb_for_module_stale_before_download module=%s generation=%llu",
					module_name.c_str(), static_cast<unsigned long long>(generation));
				return;
			}

			if (g_state.auto_download) {
				ms.status_text = "Attempting symbol server download...";
			} else {
				ms.loading = false;
				ms.failed = true;
				ms.load_declined = false;
				ms.load_phase.clear();
				ms.status_text = "PDB not found";
				return;
			}
		}

		std::string search_path = detail::build_search_path();

		if (pdb_path.empty()) {
			std::string pdb_name = module_name;
			auto dot = pdb_name.rfind('.');
			if (dot != std::string::npos)
				pdb_name = pdb_name.substr(0, dot);
			pdb_path = pdb_name + ".pdb";
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[module_name];
			if (ms.load_generation != generation || !ms.loading) {
				diag::log_tagged_fmt("symbol_store", "load_pdb_for_module_stale_before_parse module=%s generation=%llu",
					module_name.c_str(), static_cast<unsigned long long>(generation));
				return;
			}
			ms.status_text = "Parsing PDB...";
			ms.load_phase = "parse";
			ms.load_started_ms = GetTickCount64();
			ms.load_timeout_ms = 30000;
		}
		schedule_loading_timeout(module_name, generation, 30000, "parse");

		pdb_parser::pdb_info_t info;
		std::atomic<float> progress{0.f};
		bool ok = pdb_parser::parse_pdb_bounded(pdb_path, search_path, info, &progress, nullptr, k_explicit_pdb_load_timeout_ms);

		aida::events::event_pdb_loaded ev_payload;
		bool publish_event = false;

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[module_name];
			if (ms.load_generation != generation || !ms.loading) {
				diag::log_tagged_fmt("symbol_store", "load_pdb_for_module_late_result_ignored module=%s generation=%llu ok=%d progress=%.3f",
					module_name.c_str(), static_cast<unsigned long long>(generation), ok ? 1 : 0,
					static_cast<double>(progress.load()));
				return;
			}
			ms.loading = false;
			ms.load_phase.clear();

			if (ok) {
				ms.pdb = std::move(info);
				g_source_line_generation.fetch_add(1, std::memory_order_acq_rel);
				ms.load_declined = false;
				char buf[64];
				snprintf(buf, sizeof(buf), "Loaded: %zu symbols, %zu types",
				         ms.pdb.symbols.size(), ms.pdb.structs.size());
				ms.status_text = buf;

				ev_payload.module_name = ms.module_name;
				ev_payload.base = ms.base;
				ev_payload.size = ms.size;
				ev_payload.success = true;
				ev_payload.symbol_count = static_cast<uint32_t>(ms.pdb.symbols.size());
				ev_payload.struct_count = static_cast<uint32_t>(ms.pdb.structs.size());
				ev_payload.enum_count = static_cast<uint32_t>(ms.pdb.enums.size());
				publish_event = true;
			} else {
				ms.failed = true;
				ms.load_declined = false;
				ms.load_phase.clear();
				ms.status_text = pdb_parse_failure_status("Failed to parse PDB");

				ev_payload.module_name = ms.module_name;
				ev_payload.base = ms.base;
				ev_payload.size = ms.size;
				ev_payload.success = false;
				ev_payload.symbol_count = 0;
				ev_payload.struct_count = 0;
				ev_payload.enum_count = 0;
				publish_event = true;
			}
		}

		if (publish_event) {
			aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
		}
	};
	const bool posted = aida::infra::executor::submit(std::move(load_sub)).submitted;
	if (!posted) {
		aida::events::event_pdb_loaded ev_payload;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[module_name];
			if (ms.load_generation != generation)
				return;
			ms.loading = false;
			ms.failed = true;
			ms.load_declined = false;
			ms.load_phase.clear();
			ms.status_text = "Failed to queue PDB parse";
			ev_payload.module_name = ms.module_name;
			ev_payload.base = ms.base;
			ev_payload.size = ms.size;
			ev_payload.success = false;
		}
		diag::log_tagged_fmt("symbol_store", "load_pdb_for_module_post_failed module=%s generation=%llu",
			module_name.c_str(), static_cast<unsigned long long>(generation));
		aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
	} else {
		schedule_loading_timeout(module_name, generation, 30000, "queue");
	}
}

inline void load_pdb_with_hint(const std::string& module_name, uint64_t base, uint64_t size,
                               const std::string& pdb_name, const std::string& pdb_guid,
                               uint32_t pdb_age, const std::string& symbol_server_base)
{
	if (pdb_skip_active()) {
		std::string cache_path;
		try {
			cache_path = expected_cache_path_for_hint(pdb_name, pdb_guid, pdb_age);
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("symbol_store",
				"fulltest_symbol_store_pdb_cache_error source=load_pdb_with_hint module=%s pdb=%s guid=%s age=%u err=%s",
				log_value(module_name),
				log_value(pdb_name),
				log_value(pdb_guid),
				static_cast<unsigned>(pdb_age),
				ex.what());
		} catch (...) {
			diag::log_tagged_fmt("symbol_store",
				"fulltest_symbol_store_pdb_cache_error source=load_pdb_with_hint module=%s pdb=%s guid=%s age=%u err=<unknown>",
				log_value(module_name),
				log_value(pdb_name),
				log_value(pdb_guid),
				static_cast<unsigned>(pdb_age));
		}
		std::string local_candidate;
		if (!cache_path.empty()) {
			std::error_code ec;
			if (std::filesystem::is_regular_file(cache_path, ec) && !ec)
				local_candidate = cache_path;
		}
		if (local_candidate.empty()) {
			local_candidate = safe_find_local_pdb_for_suppression(module_name, "load_pdb_with_hint");
		}
		if (!local_candidate.empty()) {
			diag::log_tagged_fmt("symbol_store",
				"load_pdb_with_hint_auto_accept_local module=%s local_candidate=%s pdb_name=%s guid=%s age=%u",
				module_name.c_str(), local_candidate.c_str(), pdb_name.c_str(),
				log_value(pdb_guid), static_cast<unsigned>(pdb_age));
			load_pdb_from_explicit_path(module_name, base, size, local_candidate);
			return;
		}
		suppress_full_test_pdb_load("load_pdb_with_hint", module_name, base, size,
			pdb_name, pdb_guid, pdb_age, local_candidate, cache_path, {},
			symbol_server_base.empty()
				? "full_test_declined_hinted_symbol_load_default_server"
				: "full_test_declined_hinted_symbol_load_configured_server");
		return;
	}
	uint64_t generation = next_load_generation();
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		auto it = g_state.modules.find(module_name);
		if (it != g_state.modules.end()) {
			if (it->second.pdb.loaded || it->second.loading)
				return;
		}

		auto& ms = g_state.modules[module_name];
		ms.module_name = module_name;
		ms.base = base;
		ms.size = size;
		ms.loading = true;
		ms.failed = false;
		ms.load_declined = false;
		ms.load_phase = "queue";
		ms.load_generation = generation;
		ms.load_started_ms = GetTickCount64();
		ms.load_timeout_ms = 60000;
		ms.downloading = false;
		ms.download_total = 0;
		ms.download_received = 0;
		ms.download_percent = 0;
		ms.status_text = "Resolving PDB...";
	}

	std::string mod_copy = module_name;
	std::string pdb_name_copy = pdb_name;
	std::string pdb_guid_copy = pdb_guid;
	std::string server_copy = symbol_server_base;

	aida::infra::executor::submission_t hint_sub;
	hint_sub.owner_subsystem = "symbol_store";
	hint_sub.label = "symbol_store.load_pdb_with_hint";
	hint_sub.thread_class = "external_tool";
	hint_sub.domain = aida::infra::executor::domain_t::external_tool;
	hint_sub.priority = 2;
	hint_sub.generation = generation;
	hint_sub.target_id = mod_copy.c_str();
	hint_sub.failure_policy = "reject_not_started";
	hint_sub.body = [mod_copy, pdb_name_copy, pdb_guid_copy, pdb_age, server_copy, generation]() {
		std::string cache_root = detail::get_cache_dir().string();

		pdb_downloader::download_request_t req;
		req.pdb_name = pdb_name_copy;
		req.pdb_guid = pdb_guid_copy;
		req.pdb_age = pdb_age;
		req.cache_root = cache_root;
		req.server_base = server_copy.empty()
			? std::string("http://msdl.microsoft.com/download/symbols")
			: server_copy;

		std::string local_path;
		bool from_cache = pdb_downloader::resolve_cache_path(req, local_path);

		if (!from_cache) {
			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				auto& ms = g_state.modules[mod_copy];
				if (ms.load_generation != generation || !ms.loading) {
					diag::log_tagged_fmt("symbol_store", "hint_pdb_stale_before_download module=%s generation=%llu",
						mod_copy.c_str(), static_cast<unsigned long long>(generation));
					return;
				}
				ms.downloading = true;
				ms.status_text = "Downloading PDB...";
				ms.load_phase = "download";
				ms.load_started_ms = GetTickCount64();
				ms.load_timeout_ms = 60000;
			}
			schedule_loading_timeout(mod_copy, generation, 60000, "download");

			pdb_downloader::download_result_t result;
			auto on_progress = [&mod_copy, generation](const pdb_downloader::progress_t& p) {
				std::lock_guard<std::mutex> lk(g_state.mutex);
				auto it = g_state.modules.find(mod_copy);
				if (it == g_state.modules.end()) return;
				if (it->second.load_generation != generation || !it->second.loading) return;
				it->second.download_percent = p.percent;
				it->second.download_received = p.bytes_received;
				it->second.download_total = p.bytes_total;
				char buf[96];
				if (p.bytes_total > 0) {
					snprintf(buf, sizeof(buf), "Downloading PDB: %d%% (%llu / %llu bytes)",
					         p.percent,
					         static_cast<unsigned long long>(p.bytes_received),
					         static_cast<unsigned long long>(p.bytes_total));
				} else {
					snprintf(buf, sizeof(buf), "Downloading PDB: %llu bytes",
					         static_cast<unsigned long long>(p.bytes_received));
				}
				it->second.status_text = buf;
			};

			bool dl_ok = pdb_downloader::download_pdb_sync(req, on_progress, nullptr, result);

			if (!dl_ok) {
				aida::events::event_pdb_loaded ev_payload;
				{
					std::lock_guard<std::mutex> lk(g_state.mutex);
					auto& ms = g_state.modules[mod_copy];
					if (ms.load_generation != generation || !ms.loading) {
						diag::log_tagged_fmt("symbol_store", "hint_pdb_late_download_failure_ignored module=%s generation=%llu",
							mod_copy.c_str(), static_cast<unsigned long long>(generation));
						return;
					}
					ms.loading = false;
					ms.downloading = false;
					ms.failed = true;
					ms.load_declined = false;
					ms.load_phase.clear();
					ms.status_text = "Download failed: " + result.error;
					ev_payload.module_name = ms.module_name;
					ev_payload.base = ms.base;
					ev_payload.size = ms.size;
					ev_payload.success = false;
				}
				aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
				return;
			}

			local_path = result.local_path;
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[mod_copy];
			if (ms.load_generation != generation || !ms.loading) {
				diag::log_tagged_fmt("symbol_store", "hint_pdb_stale_before_parse module=%s generation=%llu",
					mod_copy.c_str(), static_cast<unsigned long long>(generation));
				return;
			}
			ms.downloading = false;
			ms.download_percent = 100;
			ms.status_text = from_cache ? "Parsing cached PDB..." : "Parsing PDB...";
			ms.load_phase = "parse";
			ms.load_started_ms = GetTickCount64();
			ms.load_timeout_ms = 30000;
		}
		schedule_loading_timeout(mod_copy, generation, 30000, "parse");

		pdb_parser::pdb_info_t info;
		std::atomic<float> parse_progress{0.f};
		bool parse_ok = pdb_parser::parse_pdb_bounded(local_path, "", info, &parse_progress, nullptr, k_explicit_pdb_load_timeout_ms);

		aida::events::event_pdb_loaded ev_payload;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[mod_copy];
			if (ms.load_generation != generation || !ms.loading) {
				diag::log_tagged_fmt("symbol_store", "hint_pdb_late_parse_result_ignored module=%s generation=%llu ok=%d progress=%.3f",
					mod_copy.c_str(), static_cast<unsigned long long>(generation), parse_ok ? 1 : 0,
					static_cast<double>(parse_progress.load()));
				return;
			}
			ms.loading = false;
			ms.load_phase.clear();
			if (parse_ok) {
				ms.load_declined = false;
				ms.pdb = std::move(info);
				g_source_line_generation.fetch_add(1, std::memory_order_acq_rel);
				char buf[96];
				snprintf(buf, sizeof(buf), "Loaded: %zu symbols, %zu types",
				         ms.pdb.symbols.size(), ms.pdb.structs.size());
				ms.status_text = buf;
				ev_payload.module_name = ms.module_name;
				ev_payload.base = ms.base;
				ev_payload.size = ms.size;
				ev_payload.success = true;
				ev_payload.symbol_count = static_cast<uint32_t>(ms.pdb.symbols.size());
				ev_payload.struct_count = static_cast<uint32_t>(ms.pdb.structs.size());
				ev_payload.enum_count = static_cast<uint32_t>(ms.pdb.enums.size());
			} else {
				ms.failed = true;
				ms.load_declined = false;
				ms.load_phase.clear();
				ms.status_text = pdb_parse_failure_status("Failed to parse PDB");
				ev_payload.module_name = ms.module_name;
				ev_payload.base = ms.base;
				ev_payload.size = ms.size;
				ev_payload.success = false;
			}
		}
		aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
	};
	const bool posted = aida::infra::executor::submit(std::move(hint_sub)).submitted;
	if (!posted) {
		aida::events::event_pdb_loaded ev_payload;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[module_name];
			if (ms.load_generation != generation)
				return;
			ms.loading = false;
			ms.downloading = false;
			ms.failed = true;
			ms.load_declined = false;
			ms.load_phase.clear();
			ms.status_text = "Failed to queue hinted PDB load";
			ev_payload.module_name = ms.module_name;
			ev_payload.base = ms.base;
			ev_payload.size = ms.size;
			ev_payload.success = false;
		}
		diag::log_tagged_fmt("symbol_store", "hint_pdb_post_failed module=%s generation=%llu",
			module_name.c_str(), static_cast<unsigned long long>(generation));
		aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
	} else {
		schedule_loading_timeout(module_name, generation, 60000, "queue");
	}
}

struct explicit_pdb_parse_monitor_chain_t : std::enable_shared_from_this<explicit_pdb_parse_monitor_chain_t> {
	std::mutex mtx;
	aida::infra::cancellation_watchdog::watch_id_t watch_id;
	bool done = false;
	std::string module_name;
	std::string path;
	uint64_t generation = 0;
	std::shared_ptr<std::atomic<float>> parse_progress;
	uint64_t last_log_ms = 0;

	void stop() {
		aida::infra::cancellation_watchdog::watch_id_t id;
		{
			std::lock_guard<std::mutex> lk(mtx);
			done = true;
			id = watch_id;
			watch_id = {};
		}
		if (id.valid())
			aida::infra::cancellation_watchdog::unregister_watch(id);
	}

	void fire() {
		const uint64_t now_ms = GetTickCount64();
		const float progress_value = parse_progress->load(std::memory_order_acquire);
		const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
		uint64_t elapsed = 0;
		bool updated = false;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto it = g_state.modules.find(module_name);
			if (it != g_state.modules.end() && it->second.load_generation == generation && it->second.loading && it->second.load_phase == "parse") {
				auto& ms = it->second;
				elapsed = ms.load_started_ms ? now_ms - ms.load_started_ms : 0;
				ms.parse_progress = progress_value;
				ms.parse_progress_ms = elapsed;
				ms.parse_diagnostic = parser_diag;
				char status[512];
				snprintf(status, sizeof(status), "Parsing user-supplied PDB: progress=%.1f%% elapsed=%llu / %u ms; %s",
					static_cast<double>(progress_value) * 100.0,
					static_cast<unsigned long long>(elapsed),
					ms.load_timeout_ms,
					parser_diag.c_str());
				ms.status_text = status;
				updated = true;
			}
		}
		if (updated && now_ms - last_log_ms >= 5000) {
			last_log_ms = now_ms;
			diag::log_tagged_fmt("symbol_store",
				"explicit_pdb_parse_progress module=%s generation=%llu path='%s' progress=%.3f elapsed_ms=%llu parser_diag=\"%s\"",
				module_name.c_str(),
				static_cast<unsigned long long>(generation),
				path.c_str(),
				static_cast<double>(progress_value),
				static_cast<unsigned long long>(elapsed),
				parser_diag.c_str());
		}
		std::lock_guard<std::mutex> lk(mtx);
		if (done)
			return;
		aida::infra::cancellation_watchdog::watch_descriptor_t next_watch;
		next_watch.deadline_ms = GetTickCount64() + 1000;
		auto self = shared_from_this();
		next_watch.on_fire = [self]() { self->fire(); };
		watch_id = aida::infra::cancellation_watchdog::register_watch(std::move(next_watch));
	}
};

inline void load_pdb_from_explicit_path(const std::string& module_name, uint64_t base, uint64_t size,
                                        const std::string& pdb_path)
{
	uint64_t generation = next_load_generation();
	std::error_code path_ec;
	std::filesystem::path exact_path_fs = std::filesystem::absolute(std::filesystem::path(pdb_path), path_ec);
	const std::string exact_path = path_ec ? pdb_path : exact_path_fs.string();
	std::error_code size_ec;
	uint64_t file_size = 0;
	auto explicit_size = std::filesystem::file_size(exact_path, size_ec);
	if (!size_ec)
		file_size = static_cast<uint64_t>(explicit_size);
	diag::log_tagged_fmt("symbol_store",
		"explicit_pdb_request module=%s generation=%llu input_path='%s' exact_path='%s' file_size=%llu file_size_ok=%d file_size_ec=%d base=0x%llX size=0x%llX parser_diag=\"%s\"",
		module_name.c_str(),
		static_cast<unsigned long long>(generation),
		pdb_path.c_str(),
		exact_path.c_str(),
		static_cast<unsigned long long>(file_size),
		size_ec ? 0 : 1,
		size_ec ? size_ec.value() : 0,
		static_cast<unsigned long long>(base),
		static_cast<unsigned long long>(size),
		pdb_parser::dbghelp_load_diagnostic().c_str());
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		auto& ms = g_state.modules[module_name];
		if (ms.pdb.loaded) {
			diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_already_loaded module=%s generation=%llu requested_path='%s' loaded_path='%s' file_size=%llu symbols=%zu structs=%zu enums=%zu types=%zu parse_completed=%d status='%s' failure_detail='%s'",
				module_name.c_str(),
				static_cast<unsigned long long>(ms.load_generation),
				exact_path.c_str(),
				ms.pdb_path.c_str(),
				static_cast<unsigned long long>(ms.pdb_file_size),
				ms.pdb.symbols.size(),
				ms.pdb.structs.size(),
				ms.pdb.enums.size(),
				ms.pdb.structs.size() + ms.pdb.enums.size(),
				ms.parse_completed ? 1 : 0,
				ms.status_text.c_str(),
				ms.load_failure_detail.c_str());
			return;
		}
		if (ms.loading) {
			const uint64_t now = GetTickCount64();
			const uint64_t elapsed = ms.load_started_ms ? now - ms.load_started_ms : 0;
			const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
			char status[256];
			snprintf(status, sizeof(status), "PDB load already in progress (%s, %llu / %u ms); %s",
				ms.load_phase.empty() ? "unknown" : ms.load_phase.c_str(),
				static_cast<unsigned long long>(elapsed),
				ms.load_timeout_ms,
				parser_diag.c_str());
			ms.status_text = status;
			ms.load_failure_detail = parser_diag;
			diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_already_loading module=%s generation=%llu phase=%s elapsed_ms=%llu timeout_ms=%u requested_path='%s' active_path='%s' file_size=%llu parse_completed=%d parser_diag=\"%s\" status='%s'",
				module_name.c_str(),
				static_cast<unsigned long long>(ms.load_generation),
				ms.load_phase.c_str(),
				static_cast<unsigned long long>(elapsed),
				ms.load_timeout_ms,
				exact_path.c_str(),
				ms.pdb_path.c_str(),
				static_cast<unsigned long long>(ms.pdb_file_size),
				ms.parse_completed ? 1 : 0,
				parser_diag.c_str(),
				ms.status_text.c_str());
			return;
		}
		ms.module_name = module_name;
		ms.base = base;
		ms.size = size;
		ms.loading = true;
		ms.failed = false;
		ms.load_declined = false;
		ms.pdb_path = exact_path;
		ms.pdb_file_size = file_size;
		ms.parse_completed = false;
		ms.load_failure_detail.clear();
		ms.load_phase = "queue";
		ms.load_generation = generation;
		ms.load_started_ms = GetTickCount64();
		ms.load_timeout_ms = k_explicit_pdb_load_timeout_ms;
		ms.parse_progress = 0.0f;
		ms.parse_progress_ms = 0;
		ms.parse_diagnostic.clear();
		ms.downloading = false;
		ms.download_total = 0;
		ms.download_received = 0;
		ms.download_percent = 0;
		ms.status_text = "Parsing user-supplied PDB...";
	}

	std::string mod_copy = module_name;
	std::string path_copy = exact_path;
	uint64_t file_size_copy = file_size;

	auto parse_job = [mod_copy, path_copy, file_size_copy, generation]() {
		uint64_t job_start = GetTickCount64();
		const DWORD worker_pid = GetCurrentProcessId();
		const DWORD worker_tid = GetCurrentThreadId();
		bool parser_called = false;
		bool parse_monitor_unavailable = false;
		std::string parse_monitor_error;
		try {
			diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_start module=%s path='%s' file_size=%llu generation=%llu worker_pid=%lu worker_tid=%lu parser_diag=\"%s\"",
				mod_copy.c_str(),
				path_copy.c_str(),
				static_cast<unsigned long long>(file_size_copy),
				static_cast<unsigned long long>(generation),
				worker_pid,
				worker_tid,
				pdb_parser::dbghelp_load_diagnostic().c_str());
			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				auto& ms = g_state.modules[mod_copy];
				if (ms.load_generation != generation || !ms.loading) {
					diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_stale_before_parse module=%s generation=%llu path='%s' status='%s'",
						mod_copy.c_str(), static_cast<unsigned long long>(generation), path_copy.c_str(), ms.status_text.c_str());
					return;
				}
				ms.load_phase = "parse";
				ms.load_started_ms = GetTickCount64();
				ms.load_timeout_ms = k_explicit_pdb_load_timeout_ms;
				ms.parse_progress = 0.0f;
				ms.parse_progress_ms = 0;
				ms.parse_diagnostic = pdb_parser::dbghelp_load_diagnostic();
				char status[384];
				snprintf(status, sizeof(status), "Parsing user-supplied PDB: progress=0.0%% elapsed=0 ms; %s", ms.parse_diagnostic.c_str());
				ms.status_text = status;
			}
			auto rt_before_timeout = aida::infra::taskflow_runtime::active_snapshot();
			diag::log_tagged_fmt("symbol_store",
				"explicit_pdb_timeout_schedule_begin module=%s path='%s' file_size=%llu generation=%llu phase=parse timeout_ms=%u work_pending=%llu work_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u total_rejected=%llu",
				mod_copy.c_str(),
				path_copy.c_str(),
				static_cast<unsigned long long>(file_size_copy),
				static_cast<unsigned long long>(generation),
				k_explicit_pdb_load_timeout_ms,
				static_cast<unsigned long long>(rt_before_timeout.work_queue_pending),
				rt_before_timeout.work_queue_active,
				static_cast<unsigned long long>(rt_before_timeout.service_queue_pending),
				rt_before_timeout.service_queue_active,
				static_cast<unsigned long long>(rt_before_timeout.critical_queue_pending),
				rt_before_timeout.critical_queue_active,
				static_cast<unsigned long long>(rt_before_timeout.total_rejected));
			const bool parse_timeout_scheduled = schedule_loading_timeout(mod_copy, generation, k_explicit_pdb_load_timeout_ms, "parse");
			auto rt_after_timeout = aida::infra::taskflow_runtime::active_snapshot();
			diag::log_tagged_fmt("symbol_store",
				"explicit_pdb_timeout_schedule_end module=%s path='%s' file_size=%llu generation=%llu phase=parse scheduled=%d timeout_ms=%u work_pending=%llu work_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u total_rejected=%llu",
				mod_copy.c_str(),
				path_copy.c_str(),
				static_cast<unsigned long long>(file_size_copy),
				static_cast<unsigned long long>(generation),
				parse_timeout_scheduled ? 1 : 0,
				k_explicit_pdb_load_timeout_ms,
				static_cast<unsigned long long>(rt_after_timeout.work_queue_pending),
				rt_after_timeout.work_queue_active,
				static_cast<unsigned long long>(rt_after_timeout.service_queue_pending),
				rt_after_timeout.service_queue_active,
				static_cast<unsigned long long>(rt_after_timeout.critical_queue_pending),
				rt_after_timeout.critical_queue_active,
				static_cast<unsigned long long>(rt_after_timeout.total_rejected));
			pdb_parser::pdb_info_t info;
			auto parse_progress = std::make_shared<std::atomic<float>>(0.f);
			std::string search_path = std::filesystem::path(path_copy).parent_path().string();
			auto parse_monitor_chain = std::make_shared<explicit_pdb_parse_monitor_chain_t>();
			parse_monitor_chain->module_name = mod_copy;
			parse_monitor_chain->path = path_copy;
			parse_monitor_chain->generation = generation;
			parse_monitor_chain->parse_progress = parse_progress;
			bool monitor_registered = false;
			constexpr int k_parse_monitor_max_attempts = 3;
			for (int attempt = 1; attempt <= k_parse_monitor_max_attempts; ++attempt) {
				aida::infra::cancellation_watchdog::watch_descriptor_t first_watch;
				first_watch.deadline_ms = GetTickCount64() + 1000;
				first_watch.on_fire = [parse_monitor_chain]() { parse_monitor_chain->fire(); };
				aida::infra::cancellation_watchdog::watch_id_t registered;
				{
					std::lock_guard<std::mutex> lk(parse_monitor_chain->mtx);
					registered = aida::infra::cancellation_watchdog::register_watch(std::move(first_watch));
					if (registered.valid())
						parse_monitor_chain->watch_id = registered;
				}
				if (registered.valid()) {
					monitor_registered = true;
					parse_monitor_unavailable = false;
					parse_monitor_error.clear();
					break;
				}
				parse_monitor_unavailable = true;
				parse_monitor_error = "watchdog_register_rejected";
				diag::log_tagged_fmt("symbol_store",
					"explicit_pdb_parse_monitor_retry module=%s generation=%llu attempt=%d max_attempts=%d err='%s'",
					mod_copy.c_str(),
					static_cast<unsigned long long>(generation),
					attempt,
					k_parse_monitor_max_attempts,
					parse_monitor_error.c_str());
				if (attempt < k_parse_monitor_max_attempts) {
					Sleep(static_cast<DWORD>(100 * attempt * attempt));
					continue;
				}
				const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
				auto rt = aida::infra::taskflow_runtime::active_snapshot();
				{
					std::lock_guard<std::mutex> lk(g_state.mutex);
					auto it = g_state.modules.find(mod_copy);
					if (it != g_state.modules.end() && it->second.load_generation == generation && it->second.loading && it->second.load_phase == "parse") {
						auto& ms = it->second;
						ms.parse_diagnostic = parser_diag;
						ms.load_failure_detail = std::string("parse monitor unavailable: ") + parse_monitor_error + " | " + parser_diag;
					}
				}
				diag::log_tagged_critical_fmt("symbol_store",
					"explicit_pdb_parse_monitor_giveup module=%s generation=%llu path='%s' file_size=%llu attempts=%d err='%s' parser_diag=\"%s\" work_pending=%llu work_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u total_rejected=%llu",
					mod_copy.c_str(),
					static_cast<unsigned long long>(generation),
					path_copy.c_str(),
					static_cast<unsigned long long>(file_size_copy),
					k_parse_monitor_max_attempts,
					parse_monitor_error.c_str(),
					parser_diag.c_str(),
					static_cast<unsigned long long>(rt.work_queue_pending),
					rt.work_queue_active,
					static_cast<unsigned long long>(rt.service_queue_pending),
					rt.service_queue_active,
					static_cast<unsigned long long>(rt.critical_queue_pending),
					rt.critical_queue_active,
					static_cast<unsigned long long>(rt.total_rejected));
			}
			auto stop_parse_monitor = [&]() {
				parse_monitor_chain->stop();
			};
			if (parse_monitor_unavailable) {
				const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
				diag::log_tagged_fmt("symbol_store",
					"explicit_pdb_parse_monitor_unavailable_proceeding module=%s generation=%llu path='%s' attempts=%d monitor_error='%s' parser_diag=\"%s\"",
					mod_copy.c_str(),
					static_cast<unsigned long long>(generation),
					path_copy.c_str(),
					k_parse_monitor_max_attempts,
					parse_monitor_error.c_str(),
					parser_diag.c_str());
			}
			bool parse_ok = false;
			try {
				diag::log_tagged_fmt("symbol_store",
					"explicit_pdb_parse_call_enter module=%s generation=%llu path='%s' file_size=%llu search_path='%s' monitor_available=%d monitor_error='%s' parser_diag=\"%s\"",
					mod_copy.c_str(),
					static_cast<unsigned long long>(generation),
					path_copy.c_str(),
					static_cast<unsigned long long>(file_size_copy),
					search_path.c_str(),
					monitor_registered ? 1 : 0,
					parse_monitor_error.c_str(),
					pdb_parser::dbghelp_load_diagnostic().c_str());
			parser_called = true;
			parse_ok = pdb_parser::parse_pdb_bounded(path_copy, search_path, info, parse_progress.get(), nullptr, k_explicit_pdb_load_timeout_ms);
				stop_parse_monitor();
			} catch (...) {
				stop_parse_monitor();
				throw;
			}
			const bool parse_completed = parse_ok && info.loaded;
			const std::string parser_status = pdb_parser::last_error();
			const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
			diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_done module=%s generation=%llu ok=%d parse_completed=%d path='%s' file_size=%llu symbols=%zu structs=%zu enums=%zu types=%zu progress=%.3f elapsed_ms=%llu parser_status='%s' parser_diag=\"%s\"",
				mod_copy.c_str(),
				static_cast<unsigned long long>(generation),
				parse_ok ? 1 : 0,
				parse_completed ? 1 : 0,
				path_copy.c_str(),
				static_cast<unsigned long long>(file_size_copy),
				info.symbols.size(),
				info.structs.size(),
				info.enums.size(),
				info.structs.size() + info.enums.size(),
				static_cast<double>(parse_progress->load()),
				static_cast<unsigned long long>(GetTickCount64() - job_start),
				parser_status.c_str(),
				parser_diag.c_str());

			aida::events::event_pdb_loaded ev_payload;
			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				auto& ms = g_state.modules[mod_copy];
				if (ms.load_generation != generation || !ms.loading) {
					diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_late_result_ignored module=%s generation=%llu ok=%d parse_completed=%d path='%s' file_size=%llu progress=%.3f elapsed_ms=%llu status='%s' parser_status='%s' parser_diag=\"%s\"",
						mod_copy.c_str(),
						static_cast<unsigned long long>(generation),
						parse_ok ? 1 : 0,
						parse_completed ? 1 : 0,
						path_copy.c_str(),
						static_cast<unsigned long long>(file_size_copy),
						static_cast<double>(parse_progress->load()),
						static_cast<unsigned long long>(GetTickCount64() - job_start),
						ms.status_text.c_str(),
						parser_status.c_str(),
						parser_diag.c_str());
					return;
				}
				ms.loading = false;
				ms.load_phase.clear();
				if (parse_completed) {
					ms.pdb = std::move(info);
					g_source_line_generation.fetch_add(1, std::memory_order_acq_rel);
					ms.parse_completed = ms.pdb.loaded;
					ms.failed = false;
					ms.load_declined = false;
					ms.pdb_path = path_copy;
					ms.pdb_file_size = file_size_copy;
					ms.load_failure_detail.clear();
					ms.parse_progress = parse_progress->load();
					ms.parse_progress_ms = GetTickCount64() - job_start;
					ms.parse_diagnostic = parser_diag;
					char buf[192];
					snprintf(buf, sizeof(buf), "Loaded from %s: %zu symbols, %zu types",
					         std::filesystem::path(path_copy).filename().string().c_str(),
					         ms.pdb.symbols.size(), ms.pdb.structs.size() + ms.pdb.enums.size());
					ms.status_text = buf;
					ev_payload.module_name = ms.module_name;
					ev_payload.base = ms.base;
					ev_payload.size = ms.size;
					ev_payload.success = true;
					ev_payload.symbol_count = static_cast<uint32_t>(ms.pdb.symbols.size());
					ev_payload.struct_count = static_cast<uint32_t>(ms.pdb.structs.size());
					ev_payload.enum_count = static_cast<uint32_t>(ms.pdb.enums.size());
				} else {
					ms.failed = true;
					ms.load_declined = false;
					ms.parse_completed = false;
					ms.load_phase.clear();
					ms.load_failure_detail = parser_status.empty() ? parser_diag : parser_status + " | " + parser_diag;
					ms.parse_progress = parse_progress->load();
					ms.parse_progress_ms = GetTickCount64() - job_start;
					ms.parse_diagnostic = parser_diag;
					ms.status_text = pdb_parse_failure_status("Failed to parse user-supplied PDB");
					ev_payload.module_name = ms.module_name;
					ev_payload.base = ms.base;
					ev_payload.size = ms.size;
					ev_payload.success = false;
				}
				diag::log_tagged_fmt("symbol_store",
					"explicit_pdb_state_commit module=%s generation=%llu success=%d parse_completed=%d path='%s' file_size=%llu symbols=%zu structs=%zu enums=%zu types=%zu status='%s' failure_detail='%s'",
					ms.module_name.c_str(),
					static_cast<unsigned long long>(generation),
					ev_payload.success ? 1 : 0,
					ms.parse_completed ? 1 : 0,
					ms.pdb_path.c_str(),
					static_cast<unsigned long long>(ms.pdb_file_size),
					ms.pdb.symbols.size(),
					ms.pdb.structs.size(),
					ms.pdb.enums.size(),
					ms.pdb.structs.size() + ms.pdb.enums.size(),
					ms.status_text.c_str(),
					ms.load_failure_detail.c_str());
			}

			auto parent_dir = std::filesystem::path(path_copy).parent_path().string();
			if (!parent_dir.empty()) {
				bool already = false;
				{
					std::lock_guard<std::mutex> lk(g_state.mutex);
					for (auto& sp : g_state.search_paths) {
						if (_stricmp(sp.c_str(), parent_dir.c_str()) == 0) { already = true; break; }
					}
					if (!already) g_state.search_paths.push_back(parent_dir);
				}
			}

			aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
		} catch (const std::exception& ex) {
			char status[512];
			const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
			if (parser_called) {
				snprintf(status, sizeof(status), "Failed to parse user-supplied PDB: %s; %s", ex.what(), parser_diag.c_str());
			} else {
				snprintf(status, sizeof(status), "PDB pre-parser resource failure: %s; %s", ex.what(), parser_diag.c_str());
			}
			std::string detail = std::string("parser_called=") + (parser_called ? "1" : "0") +
				" monitor_unavailable=" + (parse_monitor_unavailable ? "1" : "0") +
				" monitor_error='" + parse_monitor_error + "' exception='" + ex.what() + "' | " + parser_diag;
			publish_failed_load_result(mod_copy, generation, status,
				parser_called ? "explicit_pdb_parse_exception" : "explicit_pdb_preparser_exception",
				detail.c_str(), GetTickCount64() - job_start);
		} catch (...) {
			const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
			std::string status = parser_called
				? "Failed to parse user-supplied PDB: unknown exception; " + parser_diag
				: "PDB pre-parser resource failure: unknown exception; " + parser_diag;
			std::string detail = std::string("parser_called=") + (parser_called ? "1" : "0") +
				" monitor_unavailable=" + (parse_monitor_unavailable ? "1" : "0") +
				" monitor_error='" + parse_monitor_error + "' exception='<unknown>' | " + parser_diag;
			publish_failed_load_result(mod_copy, generation, status,
				parser_called ? "explicit_pdb_parse_exception" : "explicit_pdb_preparser_exception",
				detail.c_str(), GetTickCount64() - job_start);
		}
	};
	auto rt_before_post = aida::infra::taskflow_runtime::active_snapshot();
	diag::log_tagged_fmt("symbol_store",
		"explicit_pdb_parse_queue_begin module=%s path='%s' file_size=%llu generation=%llu work_pending=%llu work_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u total_rejected=%llu parser_diag=\"%s\"",
		mod_copy.c_str(),
		path_copy.c_str(),
		static_cast<unsigned long long>(file_size_copy),
		static_cast<unsigned long long>(generation),
		static_cast<unsigned long long>(rt_before_post.work_queue_pending),
		rt_before_post.work_queue_active,
		static_cast<unsigned long long>(rt_before_post.service_queue_pending),
		rt_before_post.service_queue_active,
		static_cast<unsigned long long>(rt_before_post.critical_queue_pending),
		rt_before_post.critical_queue_active,
		static_cast<unsigned long long>(rt_before_post.total_rejected),
		pdb_parser::dbghelp_load_diagnostic().c_str());
	bool posted = false;
	const char* posted_queue = "none";
	try {
		aida::infra::executor::submission_t parse_sub;
		parse_sub.owner_subsystem = "symbol_store";
		parse_sub.label = "symbol_store.explicit_pdb_parse";
		parse_sub.thread_class = "external_tool";
		parse_sub.domain = aida::infra::executor::domain_t::external_tool;
		parse_sub.priority = 1;
		parse_sub.generation = generation;
		parse_sub.target_id = mod_copy.c_str();
		parse_sub.failure_policy = "reject_not_started";
		parse_sub.body = std::move(parse_job);
		posted = aida::infra::executor::submit(std::move(parse_sub)).submitted;
		if (posted)
			posted_queue = "external_tool";
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_queue_exception queue=external_tool module=%s path='%s' file_size=%llu generation=%llu err=%s",
			mod_copy.c_str(), path_copy.c_str(), static_cast<unsigned long long>(file_size_copy), static_cast<unsigned long long>(generation), ex.what());
	} catch (...) {
		diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_queue_exception queue=external_tool module=%s path='%s' file_size=%llu generation=%llu err=<unknown>",
			mod_copy.c_str(), path_copy.c_str(), static_cast<unsigned long long>(file_size_copy), static_cast<unsigned long long>(generation));
	}
	auto rt_after_post = aida::infra::taskflow_runtime::active_snapshot();
	diag::log_tagged_fmt("symbol_store",
		"explicit_pdb_parse_queue_end module=%s path='%s' file_size=%llu generation=%llu posted=%d queue=%s work_pending=%llu work_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u total_rejected=%llu parser_diag=\"%s\"",
		mod_copy.c_str(),
		path_copy.c_str(),
		static_cast<unsigned long long>(file_size_copy),
		static_cast<unsigned long long>(generation),
		posted ? 1 : 0,
		posted_queue,
		static_cast<unsigned long long>(rt_after_post.work_queue_pending),
		rt_after_post.work_queue_active,
		static_cast<unsigned long long>(rt_after_post.service_queue_pending),
		rt_after_post.service_queue_active,
		static_cast<unsigned long long>(rt_after_post.critical_queue_pending),
		rt_after_post.critical_queue_active,
		static_cast<unsigned long long>(rt_after_post.total_rejected),
		pdb_parser::dbghelp_load_diagnostic().c_str());
	if (!posted) {
		const std::string parser_diag = pdb_parser::dbghelp_load_diagnostic();
		diag::log_tagged_fmt("symbol_store", "explicit_pdb_parse_post_failed module=%s path='%s' file_size=%llu generation=%llu parser_diag=\"%s\"",
			mod_copy.c_str(), path_copy.c_str(), static_cast<unsigned long long>(file_size_copy), static_cast<unsigned long long>(generation), parser_diag.c_str());
		aida::events::event_pdb_loaded ev_payload;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[mod_copy];
			if (ms.load_generation != generation)
				return;
			ms.loading = false;
			ms.failed = true;
			ms.load_declined = false;
			ms.parse_completed = false;
			ms.load_failure_detail = parser_diag;
			ms.load_phase.clear();
			char status[768];
			snprintf(status, sizeof(status), "Failed to queue user-supplied PDB parse; %s", parser_diag.c_str());
			ms.status_text = status;
			ev_payload.module_name = ms.module_name;
			ev_payload.base = ms.base;
			ev_payload.size = ms.size;
			ev_payload.success = false;
		}
		aida::events::publish(aida::events::event_pdb_loaded_def, ev_payload);
	} else {
		auto rt_before_timeout = aida::infra::taskflow_runtime::active_snapshot();
		diag::log_tagged_fmt("symbol_store",
			"explicit_pdb_timeout_schedule_begin module=%s path='%s' file_size=%llu generation=%llu phase=queue timeout_ms=%u work_pending=%llu work_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u total_rejected=%llu parser_diag=\"%s\"",
			module_name.c_str(),
			path_copy.c_str(),
			static_cast<unsigned long long>(file_size_copy),
			static_cast<unsigned long long>(generation),
			k_explicit_pdb_load_timeout_ms,
			static_cast<unsigned long long>(rt_before_timeout.work_queue_pending),
			rt_before_timeout.work_queue_active,
			static_cast<unsigned long long>(rt_before_timeout.service_queue_pending),
			rt_before_timeout.service_queue_active,
			static_cast<unsigned long long>(rt_before_timeout.critical_queue_pending),
			rt_before_timeout.critical_queue_active,
			static_cast<unsigned long long>(rt_before_timeout.total_rejected),
			pdb_parser::dbghelp_load_diagnostic().c_str());
		const bool queue_timeout_scheduled = schedule_loading_timeout(module_name, generation, k_explicit_pdb_load_timeout_ms, "queue");
		auto rt_after_timeout = aida::infra::taskflow_runtime::active_snapshot();
		diag::log_tagged_fmt("symbol_store",
			"explicit_pdb_timeout_schedule_end module=%s path='%s' file_size=%llu generation=%llu phase=queue scheduled=%d timeout_ms=%u work_pending=%llu work_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u total_rejected=%llu parser_diag=\"%s\"",
			module_name.c_str(),
			path_copy.c_str(),
			static_cast<unsigned long long>(file_size_copy),
			static_cast<unsigned long long>(generation),
			queue_timeout_scheduled ? 1 : 0,
			k_explicit_pdb_load_timeout_ms,
			static_cast<unsigned long long>(rt_after_timeout.work_queue_pending),
			rt_after_timeout.work_queue_active,
			static_cast<unsigned long long>(rt_after_timeout.service_queue_pending),
			rt_after_timeout.service_queue_active,
			static_cast<unsigned long long>(rt_after_timeout.critical_queue_pending),
			rt_after_timeout.critical_queue_active,
			static_cast<unsigned long long>(rt_after_timeout.total_rejected),
			pdb_parser::dbghelp_load_diagnostic().c_str());
	}
}

inline void auto_load_attached_modules()
{
	if (pdb_skip_active()) {
		auto skip_modules = driver_bridge::enumerate_modules();
		bool any_loaded = false;
		for (auto& m : skip_modules) {
			bool already_present = false;
			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				already_present = g_state.modules.find(m.name) != g_state.modules.end();
			}
			if (already_present) continue;
			std::string lower_name = m.name;
			std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
			bool worth_loading = (lower_name.find(".exe") != std::string::npos ||
			                      lower_name.find("game") != std::string::npos ||
			                      lower_name.find("engine") != std::string::npos);
			if (!worth_loading) continue;
			const std::string local_candidate = safe_find_local_pdb_for_suppression(m.name, "auto_load_attached_modules");
			if (!local_candidate.empty()) {
				diag::log_tagged_fmt("symbol_store",
					"auto_load_attached_modules_auto_accept_local module=%s local_candidate=%s base=0x%llX size=0x%X",
					m.name.c_str(), local_candidate.c_str(),
					static_cast<unsigned long long>(m.base), m.size);
				load_pdb_from_explicit_path(m.name, m.base, static_cast<uint64_t>(m.size), local_candidate);
				any_loaded = true;
			}
		}
		if (!any_loaded) {
			suppress_full_test_pdb_load("auto_load_attached_modules", "<attached_modules>",
				0, 0, "<auto>", {}, 0, {}, {}, {},
				"full_test_declined_attached_module_auto_load", false);
		}
		return;
	}
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		bool worth_loading = true;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (g_state.modules.find(m.name) == g_state.modules.end()) {
				std::string lower_name = m.name;
				std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

				worth_loading = (lower_name.find(".exe") != std::string::npos ||
				                 lower_name.find("game") != std::string::npos ||
				                 lower_name.find("engine") != std::string::npos);
			}
		}

		if (!worth_loading) continue;

		load_pdb_for_module(m.name, m.base, m.size);
	}
}

inline std::string resolve_symbol(uint64_t address)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);

	for (auto& [mod_name, ms] : g_state.modules) {
		if (!ms.pdb.loaded) continue;
		if (address < ms.base || address >= ms.base + ms.size) continue;

		uint64_t rva = address - ms.base;

		auto it = ms.pdb.symbol_by_rva.find(rva);
		if (it != ms.pdb.symbol_by_rva.end()) {
			return mod_name + "!" + ms.pdb.symbols[it->second].name;
		}

		std::string best_name;
		uint64_t best_rva = 0;
		for (auto& sym : ms.pdb.symbols) {
			if (sym.is_function && sym.rva <= rva && sym.rva > best_rva) {
				best_rva = sym.rva;
				best_name = sym.name;
			}
		}

		if (!best_name.empty() && (rva - best_rva) < 0x10000) {
			char buf[256];
			snprintf(buf, sizeof(buf), "%s!%s+0x%llX", mod_name.c_str(), best_name.c_str(),
			         static_cast<unsigned long long>(rva - best_rva));
			return buf;
		}
	}

	return {};
}

inline std::string resolve_function_display_name(uint64_t address)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);

	for (auto& [mod_name, ms] : g_state.modules) {
		if (!ms.pdb.loaded) continue;
		if (address < ms.base || address >= ms.base + ms.size) continue;

		uint64_t rva = address - ms.base;
		auto it = ms.pdb.symbol_by_rva.find(rva);
		if (it != ms.pdb.symbol_by_rva.end())
			return ms.pdb.symbols[it->second].name;

		const std::string* best_name = nullptr;
		uint64_t best_rva = 0;
		for (auto& sym : ms.pdb.symbols) {
			if (sym.is_function && sym.rva <= rva && sym.rva > best_rva &&
			    (rva - sym.rva) < 0x10000) {
				best_rva = sym.rva;
				best_name = &sym.name;
			}
		}
		if (best_name && best_rva == rva)
			return *best_name;
	}

	return {};
}

inline std::string resolve_symbol_exact(uint64_t address)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);

	for (auto& [mod_name, ms] : g_state.modules) {
		if (!ms.pdb.loaded) continue;
		if (address < ms.base || address >= ms.base + ms.size) continue;

		uint64_t rva = address - ms.base;
		auto it = ms.pdb.symbol_by_rva.find(rva);
		if (it != ms.pdb.symbol_by_rva.end())
			return ms.pdb.symbols[it->second].name;
	}

	return {};
}

inline uint64_t resolve_name_to_addr(const std::string& input)
{
	if (input.empty())
		return 0;

	std::string trimmed = input;
	while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t'))
		trimmed.erase(trimmed.begin());
	while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '\t'))
		trimmed.pop_back();
	if (trimmed.empty())
		return 0;

	std::string mod_filter;
	std::string name = trimmed;
	auto bang = trimmed.find('!');
	if (bang != std::string::npos) {
		mod_filter = trimmed.substr(0, bang);
		name = trimmed.substr(bang + 1);
	}

	int64_t extra_offset = 0;
	auto plus = name.rfind('+');
	if (plus != std::string::npos && plus > 0) {
		std::string off_str = name.substr(plus + 1);
		std::string base_name = name.substr(0, plus);
		if (!off_str.empty()) {
			uint64_t off_val = 0;
			const char* off_cstr = off_str.c_str();
			if (off_str.size() > 2 && off_str[0] == '0' && (off_str[1] == 'x' || off_str[1] == 'X'))
				off_cstr = off_str.c_str() + 2;
			char* end = nullptr;
			off_val = std::strtoull(off_cstr, &end, 16);
			if (end && *end == '\0') {
				extra_offset = static_cast<int64_t>(off_val);
				name = base_name;
			}
		}
	}

	if (name.empty())
		return 0;

	auto eq_ci = [](const std::string& a, const std::string& b) {
		if (a.size() != b.size()) return false;
		for (size_t i = 0; i < a.size(); ++i) {
			char ca = a[i];
			char cb = b[i];
			if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
			if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
			if (ca != cb) return false;
		}
		return true;
	};

	if (name.size() > 4) {
		bool prefix_match = (name[0] == 's' || name[0] == 'S')
			&& (name[1] == 'u' || name[1] == 'U')
			&& (name[2] == 'b' || name[2] == 'B')
			&& name[3] == '_';
		if (prefix_match) {
			std::string hex_part = name.substr(4);
			if (!hex_part.empty()) {
				char* end = nullptr;
				uint64_t addr = std::strtoull(hex_part.c_str(), &end, 16);
				if (end && *end == '\0' && addr != 0)
					return addr + static_cast<uint64_t>(extra_offset);
			}
		}
	}

	std::lock_guard<std::mutex> lk(g_state.mutex);

	for (auto& [mod_name, ms] : g_state.modules) {
		if (!ms.pdb.loaded) continue;
		if (!mod_filter.empty()) {
			std::string mod_no_ext = mod_name;
			auto dot = mod_no_ext.rfind('.');
			if (dot != std::string::npos) mod_no_ext = mod_no_ext.substr(0, dot);
			if (!eq_ci(mod_filter, mod_name) && !eq_ci(mod_filter, mod_no_ext))
				continue;
		}

		auto it = ms.pdb.symbol_by_name.find(name);
		if (it != ms.pdb.symbol_by_name.end()) {
			uint64_t rva = ms.pdb.symbols[it->second].rva;
			return ms.base + rva + static_cast<uint64_t>(extra_offset);
		}
	}

	for (auto& [mod_name, ms] : g_state.modules) {
		if (!ms.pdb.loaded) continue;
		if (!mod_filter.empty()) {
			std::string mod_no_ext = mod_name;
			auto dot = mod_no_ext.rfind('.');
			if (dot != std::string::npos) mod_no_ext = mod_no_ext.substr(0, dot);
			if (!eq_ci(mod_filter, mod_name) && !eq_ci(mod_filter, mod_no_ext))
				continue;
		}

		for (auto& sym : ms.pdb.symbols) {
			if (eq_ci(sym.name, name))
				return ms.base + sym.rva + static_cast<uint64_t>(extra_offset);
		}
	}

	return 0;
}

inline const pdb_parser::struct_def_t* find_struct(const std::string& name)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);

	for (auto& [mod_name, ms] : g_state.modules) {
		if (!ms.pdb.loaded) continue;
		auto it = ms.pdb.struct_by_name.find(name);
		if (it != ms.pdb.struct_by_name.end())
			return &ms.pdb.structs[it->second];
	}

	return nullptr;
}

inline std::vector<std::string> list_loaded_modules()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	std::vector<std::string> out;
	out.reserve(g_state.modules.size());
	for (auto& [name, ms] : g_state.modules)
		out.push_back(name);
	return out;
}

inline bool source_modules_snapshot(std::vector<source_module_snapshot_t>& output,
	std::string& error, size_t maximum_modules = 4096)
{
	output.clear();
	error.clear();
	if (maximum_modules == 0 || maximum_modules > 4096) {
		error = "Source-module snapshot bound is invalid";
		return false;
	}
	std::lock_guard<std::mutex> lk(g_state.mutex);
	if (g_state.modules.size() > maximum_modules) {
		error = "Loaded source modules exceed the 4,096-module snapshot bound";
		return false;
	}
	output.reserve(g_state.modules.size());
	for (const auto& item : g_state.modules) {
		const auto& module = item.second;
		if (!module.pdb.loaded) continue;
		output.push_back({module.module_name, module.base, module.size,
			module.load_generation, module.pdb.source_lines});
	}
	return true;
}

inline const module_symbols_t* get_module(const std::string& name)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	auto it = g_state.modules.find(name);
	if (it != g_state.modules.end())
		return &it->second;
	return nullptr;
}

inline void clear_all()
{
	std::vector<std::string> unloaded_names;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		unloaded_names.reserve(g_state.modules.size());
		for (auto& kv : g_state.modules) {
			if (kv.second.pdb.loaded)
				unloaded_names.push_back(kv.first);
		}
		g_state.modules.clear();
		g_source_line_generation.fetch_add(1, std::memory_order_acq_rel);
	}

	for (auto& name : unloaded_names) {
		aida::events::event_pdb_unloaded ev;
		ev.module_name = name;
		aida::events::publish(aida::events::event_pdb_unloaded_def, ev);
	}
}

inline void add_search_path(const std::string& path)
{
	for (auto& p : g_state.search_paths) {
		if (p == path) return;
	}
	g_state.search_paths.push_back(path);
}

inline void add_target_module_search_path(const std::string& module_dir)
{
	if (module_dir.empty()) return;
	add_search_path(module_dir);
	diag::log_tagged_fmt("symbol_store",
		"add_target_module_search_path dir=%s total_search_paths=%zu",
		module_dir.c_str(), g_state.search_paths.size());
}

}
