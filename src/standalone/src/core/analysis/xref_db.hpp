#pragma once

#include <windows.h>
#include <shlobj.h>
#include <algorithm>
#include <atomic>
#include "work_queue.hpp"
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "standalone_driver.hpp"
#include "xref_engine.hpp"
#include "zydis_disasm.hpp"

#include <nlohmann/json.hpp>

namespace xref_db {

struct xref_entry_t {
	uint64_t                 from_addr = 0;
	uint64_t                 to_addr   = 0;
	xref_engine::xref_type_t type      = xref_engine::xref_type_t::call;
	std::string              disasm_text;
};

struct module_index_t {
	std::string name;
	uint64_t    base = 0;
	uint32_t    size = 0;
	uint64_t    timestamp = 0;

	std::unordered_map<uint64_t, std::vector<xref_entry_t>> to_index;
	std::unordered_map<uint64_t, std::vector<xref_entry_t>> from_index;

	size_t total_xrefs = 0;
	bool   built = false;
};

struct call_graph_node_t {
	uint64_t addr = 0;
	std::string name;
	std::vector<uint64_t> callees;
	std::vector<uint64_t> callers;
};

struct state_t {
	std::unordered_map<std::string, module_index_t> modules;
	std::mutex          mutex;
	std::atomic<bool>   building{false};
	std::atomic<float>  progress{0.f};
	std::atomic<bool>   cancel{false};
	std::string         building_module;

	std::vector<xref_entry_t> query_results;
	bool                      query_is_to = true;
	uint64_t                  query_addr = 0;

	std::string filter_text;
	int         filter_type = -1;

	std::unordered_map<uint64_t, call_graph_node_t> call_graph;
};

inline state_t g_state;

struct snapshot_t {
	std::unordered_map<std::string, module_index_t> modules;
	bool                building = false;
	float               progress = 0.f;
	bool                cancel = false;
	std::string         building_module;
	std::vector<xref_entry_t> query_results;
	bool                      query_is_to = true;
	uint64_t                  query_addr = 0;
	std::string filter_text;
	int         filter_type = -1;
	std::unordered_map<uint64_t, call_graph_node_t> call_graph;
};

inline std::unique_ptr<snapshot_t> detach_snapshot() {
	std::lock_guard<std::mutex> lk(g_state.mutex);
	auto out = std::make_unique<snapshot_t>();
	out->modules = std::move(g_state.modules);
	out->building = g_state.building.load(std::memory_order_acquire);
	out->progress = g_state.progress.load(std::memory_order_acquire);
	out->cancel = g_state.cancel.load(std::memory_order_acquire);
	out->building_module = std::move(g_state.building_module);
	out->query_results = std::move(g_state.query_results);
	out->query_is_to = g_state.query_is_to;
	out->query_addr = g_state.query_addr;
	out->filter_text = std::move(g_state.filter_text);
	out->filter_type = g_state.filter_type;
	out->call_graph = std::move(g_state.call_graph);
	g_state.modules.clear();
	g_state.building.store(false, std::memory_order_release);
	g_state.progress.store(0.f, std::memory_order_release);
	g_state.cancel.store(false, std::memory_order_release);
	g_state.building_module.clear();
	g_state.query_results.clear();
	g_state.query_is_to = true;
	g_state.query_addr = 0;
	g_state.filter_text.clear();
	g_state.filter_type = -1;
	g_state.call_graph.clear();
	return out;
}

inline void attach_snapshot(std::unique_ptr<snapshot_t> snap) {
	std::lock_guard<std::mutex> lk(g_state.mutex);
	if (!snap) snap = std::make_unique<snapshot_t>();
	g_state.modules = std::move(snap->modules);
	g_state.building.store(snap->building, std::memory_order_release);
	g_state.progress.store(snap->progress, std::memory_order_release);
	g_state.cancel.store(snap->cancel, std::memory_order_release);
	g_state.building_module = std::move(snap->building_module);
	g_state.query_results = std::move(snap->query_results);
	g_state.query_is_to = snap->query_is_to;
	g_state.query_addr = snap->query_addr;
	g_state.filter_text = std::move(snap->filter_text);
	g_state.filter_type = snap->filter_type;
	g_state.call_graph = std::move(snap->call_graph);
}

namespace detail {

inline constexpr uint32_t k_cache_version = 2;

inline std::filesystem::path cache_dir()
{
	wchar_t* appdata = nullptr;
	if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
		auto p = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"xref_cache";
		CoTaskMemFree(appdata);
		return p;
	}
	return std::filesystem::current_path() / "xref_cache";
}

inline std::string module_cache_filename(const std::string& name, uint64_t base, uint32_t size)
{
	char buf[256];
	snprintf(buf, sizeof(buf), "%s_%llX_%X.json", name.c_str(),
	         static_cast<unsigned long long>(base), size);
	return buf;
}

inline void save_module_cache(const module_index_t& mod)
{
	auto dir = cache_dir();
	std::filesystem::create_directories(dir);

	nlohmann::json root;
	root["version"] = k_cache_version;
	root["name"] = mod.name;
	root["base"] = mod.base;
	root["size"] = mod.size;
	root["timestamp"] = mod.timestamp;
	root["total_xrefs"] = mod.total_xrefs;

	nlohmann::json xrefs = nlohmann::json::array();
	for (auto& [addr, entries] : mod.to_index) {
		for (auto& e : entries) {
			nlohmann::json j;
			j["f"] = e.from_addr;
			j["t"] = e.to_addr;
			j["y"] = static_cast<int>(e.type);
			j["d"] = e.disasm_text;
			xrefs.push_back(std::move(j));
		}
	}
	root["xrefs"] = std::move(xrefs);

	auto path = dir / module_cache_filename(mod.name, mod.base, mod.size);
	std::ofstream ofs(path);
	if (ofs.is_open())
		ofs << root.dump();
}

inline bool load_module_cache(const std::string& name, uint64_t base, uint32_t size,
                              module_index_t& out)
{
	auto path = cache_dir() / module_cache_filename(name, base, size);
	if (!std::filesystem::exists(path))
		return false;

	std::ifstream ifs(path);
	if (!ifs.is_open())
		return false;

	nlohmann::json root = nlohmann::json::parse(ifs, nullptr, false);
	if (root.is_discarded()) return false;
	if (root.value("version", uint32_t(0)) != k_cache_version) return false;

	out.name = name;
	out.base = base;
	out.size = size;
	out.timestamp = root.value("timestamp", uint64_t(0));
	out.total_xrefs = root.value("total_xrefs", size_t(0));
	out.built = true;

	out.to_index.clear();
	out.from_index.clear();

	if (root.contains("xrefs") && root["xrefs"].is_array()) {
		for (auto& j : root["xrefs"]) {
			xref_entry_t e;
			e.from_addr = j.value("f", uint64_t(0));
			e.to_addr = j.value("t", uint64_t(0));
			e.type = static_cast<xref_engine::xref_type_t>(j.value("y", 0));
			e.disasm_text = j.value("d", std::string());
			out.to_index[e.to_addr].push_back(e);
			out.from_index[e.from_addr].push_back(e);
		}
	}

	return true;
}

inline module_index_t scan_module_index(const std::string& name, uint64_t base, uint32_t size)
{
	module_index_t mod;
	mod.name = name;
	mod.base = base;
	mod.size = size;
	mod.timestamp = static_cast<uint64_t>(
		std::chrono::system_clock::now().time_since_epoch().count());

	const size_t page_size = 4096;
	uint64_t total = size ? size : 1;
	uint64_t scanned = 0;
	size_t xref_count = 0;

	for (uint64_t offset = 0; offset < size && !g_state.cancel.load(); offset += page_size) {
		size_t chunk = page_size;
		if (offset + chunk > size)
			chunk = static_cast<size_t>(size - offset);

		std::vector<uint8_t> page_data;
		if (!driver_bridge::read_memory(base + offset, chunk, page_data)) {
			scanned += chunk;
			g_state.progress.store(static_cast<float>(scanned) / static_cast<float>(total));
			continue;
		}

		const uint8_t* data = page_data.data();
		int sz = static_cast<int>(page_data.size());
		int pos = 0;

		while (pos < sz && !g_state.cancel.load()) {
			int avail = sz - pos;
			if (avail > 15) avail = 15;

			uint64_t ins_addr = base + offset + pos;
			AsmInstr ins = zydis_decode_one(data + pos, avail, ins_addr);
			const int ins_len = (ins.len > 0 && ins.len <= avail) ? ins.len : 1;

			uint64_t target = 0;
			if (ins.len > 0 && ins.len <= avail &&
				xref_engine::detail::extract_target(data + pos, ins.len, ins_addr, ins, target)) {
				xref_entry_t e;
				e.from_addr = ins_addr;
				e.to_addr = target;
				e.type = xref_engine::detail::classify_instruction(ins);
				char full_text[256];
				snprintf(full_text, sizeof(full_text), "%s %s", ins.mnem, ins.ops);
				e.disasm_text = full_text;

				mod.to_index[target].push_back(e);
				mod.from_index[ins_addr].push_back(e);
				++xref_count;
			}

			pos += ins_len;
		}

		scanned += chunk;
		g_state.progress.store(static_cast<float>(scanned) / static_cast<float>(total));
	}

	mod.total_xrefs = xref_count;
	mod.built = true;
	return mod;
}

inline void sort_unique_entries(std::vector<xref_entry_t>& entries)
{
	std::sort(entries.begin(), entries.end(),
		[](const xref_entry_t& a, const xref_entry_t& b) {
			if (a.from_addr != b.from_addr) return a.from_addr < b.from_addr;
			if (a.to_addr != b.to_addr) return a.to_addr < b.to_addr;
			if (a.type != b.type) return static_cast<int>(a.type) < static_cast<int>(b.type);
			return a.disasm_text < b.disasm_text;
		});
	entries.erase(std::unique(entries.begin(), entries.end(),
		[](const xref_entry_t& a, const xref_entry_t& b) {
			return a.from_addr == b.from_addr
				&& a.to_addr == b.to_addr
				&& a.type == b.type;
		}), entries.end());
}

inline void append_xrefs_to_locked(uint64_t addr, std::vector<xref_entry_t>& out)
{
	for (auto& [name, mod] : g_state.modules) {
		if (!mod.built) continue;
		auto it = mod.to_index.find(addr);
		if (it != mod.to_index.end()) {
			out.insert(out.end(), it->second.begin(), it->second.end());
		}
	}
}

inline void append_xrefs_from_locked(uint64_t addr, std::vector<xref_entry_t>& out)
{
	for (auto& [name, mod] : g_state.modules) {
		if (!mod.built) continue;
		auto it = mod.from_index.find(addr);
		if (it != mod.from_index.end()) {
			out.insert(out.end(), it->second.begin(), it->second.end());
		}
	}
}

inline bool find_module_for_addr(uint64_t addr, driver_bridge::module_info_t& out)
{
	auto modules = driver_bridge::enumerate_modules();
	for (const auto& m : modules) {
		if (m.base == 0 || m.size == 0) continue;
		if (addr >= m.base && addr < m.base + m.size) {
			out = m;
			return true;
		}
	}
	return false;
}

inline bool module_is_built_locked(const driver_bridge::module_info_t& m)
{
	auto it = g_state.modules.find(m.name);
	return it != g_state.modules.end()
		&& it->second.built
		&& it->second.base == m.base
		&& it->second.size == m.size;
}

inline bool ensure_module_index_for_addr(uint64_t addr)
{
	driver_bridge::module_info_t m;
	if (!find_module_for_addr(addr, m)) return false;

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		if (module_is_built_locked(m)) return true;
	}

	bool expected = false;
	if (!g_state.building.compare_exchange_strong(expected, true))
		return false;

	struct build_finish_t {
		~build_finish_t() { g_state.building.store(false); }
	} build_finish;

	g_state.cancel.store(false);
	g_state.progress.store(0.f);
	g_state.building_module = m.name;

	module_index_t mod;
	if (!load_module_cache(m.name, m.base, m.size, mod)) {
		mod = scan_module_index(m.name, m.base, m.size);
		save_module_cache(mod);
	}

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.modules[m.name] = std::move(mod);
	}
	return true;
}

}

inline std::vector<driver_bridge::module_info_t> get_module_list()
{
	return driver_bridge::enumerate_modules();
}

inline bool is_module_indexed(const std::string& name)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	auto it = g_state.modules.find(name);
	return it != g_state.modules.end() && it->second.built;
}

inline void build_module_index(const std::string& name, uint64_t base, uint32_t size)
{
	if (g_state.building.load())
		return;

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		module_index_t cached;
		if (detail::load_module_cache(name, base, size, cached)) {
			g_state.modules[name] = std::move(cached);
			return;
		}
	}

	g_state.building.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);
	g_state.building_module = name;

	if (!work_queue::post([name, base, size]() {
		struct build_finish_t {
			~build_finish_t() { g_state.building.store(false); }
		} build_finish;

		module_index_t mod = detail::scan_module_index(name, base, size);
		detail::save_module_cache(mod);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.modules[name] = std::move(mod);
		}

		g_state.building.store(false);
	})) {
		g_state.building.store(false);
	}
}

inline void build_call_graph(const std::string& module_name)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	auto it = g_state.modules.find(module_name);
	if (it == g_state.modules.end() || !it->second.built)
		return;

	g_state.call_graph.clear();
	auto& mod = it->second;

	for (auto& [addr, entries] : mod.from_index) {
		for (auto& e : entries) {
			if (e.type != xref_engine::xref_type_t::call)
				continue;

			auto& caller_node = g_state.call_graph[e.from_addr];
			caller_node.addr = e.from_addr;
			if (std::find(caller_node.callees.begin(), caller_node.callees.end(), e.to_addr) == caller_node.callees.end())
				caller_node.callees.push_back(e.to_addr);

			auto& callee_node = g_state.call_graph[e.to_addr];
			callee_node.addr = e.to_addr;
			if (std::find(callee_node.callers.begin(), callee_node.callers.end(), e.from_addr) == callee_node.callers.end())
				callee_node.callers.push_back(e.from_addr);
		}
	}
}

inline void query_xrefs_to(uint64_t addr)
{
	std::vector<xref_entry_t> results;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		detail::append_xrefs_to_locked(addr, results);
	}

	if (results.empty()) {
		if (detail::ensure_module_index_for_addr(addr)) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			detail::append_xrefs_to_locked(addr, results);
		}
	}

	detail::sort_unique_entries(results);

	std::lock_guard<std::mutex> lk(g_state.mutex);
	g_state.query_results = std::move(results);
	g_state.query_is_to = true;
	g_state.query_addr = addr;
}

inline void query_xrefs_from(uint64_t addr)
{
	std::vector<xref_entry_t> results;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		detail::append_xrefs_from_locked(addr, results);
	}

	if (results.empty()) {
		if (detail::ensure_module_index_for_addr(addr)) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			detail::append_xrefs_from_locked(addr, results);
		}
	}

	detail::sort_unique_entries(results);

	std::lock_guard<std::mutex> lk(g_state.mutex);
	g_state.query_results = std::move(results);
	g_state.query_is_to = false;
	g_state.query_addr = addr;
}

inline size_t total_indexed_xrefs()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	size_t total = 0;
	for (auto& [name, mod] : g_state.modules)
		if (mod.built) total += mod.total_xrefs;
	return total;
}

inline void clear_all()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	g_state.modules.clear();
	g_state.call_graph.clear();
	g_state.query_results.clear();
}

inline void cancel_build()
{
	g_state.cancel.store(true);
}

}
