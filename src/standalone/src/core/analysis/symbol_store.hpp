#pragma once

#include <windows.h>
#include <shlobj.h>
#include <algorithm>
#include <atomic>
#include "work_queue.hpp"
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "pdb_events.hpp"
#include "pdb_parser.hpp"
#include "standalone_driver.hpp"
#include "standalone_settings.hpp"

extern settings_sa_t g_settings;

namespace symbol_store {

struct module_symbols_t {
	std::string                               module_name;
	uint64_t                                  base = 0;
	uint64_t                                  size = 0;
	pdb_parser::pdb_info_t                    pdb;
	bool                                      loading = false;
	bool                                      failed = false;
	std::string                               status_text;
};

struct state_t {
	std::unordered_map<std::string, module_symbols_t> modules;
	std::mutex                                        mutex;
	std::vector<std::string>                          search_paths;
	std::string                                       cache_dir;
	bool                                              auto_download = false;
	std::string                                       symbol_server_url = "https://msdl.microsoft.com/download/symbols";
};

inline state_t g_state;

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

inline void load_pdb_for_module(const std::string& module_name, uint64_t base, uint64_t size)
{
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
		ms.status_text = "Searching for PDB...";
	}

	work_queue::post([module_name]() {
		std::string pdb_path = detail::find_pdb_local(module_name);

		if (pdb_path.empty()) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[module_name];

			if (g_state.auto_download) {
				ms.status_text = "Attempting symbol server download...";
			} else {
				ms.loading = false;
				ms.failed = true;
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
			g_state.modules[module_name].status_text = "Parsing PDB...";
		}

		pdb_parser::pdb_info_t info;
		std::atomic<float> progress{0.f};
		bool ok = pdb_parser::parse_pdb(pdb_path, search_path, info, &progress);

		aida::events::event_pdb_loaded ev_payload;
		bool publish_event = false;

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			auto& ms = g_state.modules[module_name];
			ms.loading = false;

			if (ok) {
				ms.pdb = std::move(info);
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
				ms.status_text = "Failed to parse PDB";

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
	});
}

inline void auto_load_attached_modules()
{
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		std::lock_guard<std::mutex> lk(g_state.mutex);
		if (g_state.modules.find(m.name) == g_state.modules.end()) {
			std::string lower_name = m.name;
			std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

			bool worth_loading = (lower_name.find(".exe") != std::string::npos ||
			                      lower_name.find("game") != std::string::npos ||
			                      lower_name.find("engine") != std::string::npos);
			if (!worth_loading) continue;
		}

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

}
