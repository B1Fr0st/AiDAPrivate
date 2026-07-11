#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "workspace/analysis_workspace.hpp"
#include "workspace/decompiler_service.hpp"
#include "workspace/pe_image.hpp"
#include "workspace/compact_ir.hpp"
#include "workspace/workspace_types.hpp"
#include "../infra/executor.hpp"
#include "../../helpers/diag_log.hpp"

namespace source_reconstructor {

enum class stage_t : int {
	idle = 0,
	collect,
	decompile,
	cluster,
	headers,
	modules,
	metadata,
	done,
	failed
};

struct workspace_reconstruction_config_t {
	std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
	std::string output_dir;
	std::string project_name = "reconstructed";
	bool include_imports = true;
	bool include_exports = true;
	bool generate_cmake = true;
	int max_functions = 0;
};

struct workspace_reconstruction_result_t {
	bool success = false;
	std::string error;
	std::string module_name;
	int total_functions = 0;
	int decompiled_functions = 0;
	int modules_created = 0;
	std::vector<std::string> files_created;
	std::string output_dir;
};

struct workspace_reconstruction_state_t {
	std::atomic<bool> running{false};
	std::atomic<bool> cancel_requested{false};
	std::atomic<float> progress{0.f};
	std::atomic<int> stage{0};
	mutable std::mutex mutex;
	std::string status_text;
	workspace_reconstruction_result_t last_result;
};

struct function_info_t {
	uint64_t address = 0;
	uint64_t end_address = 0;
	std::string name;
	std::string pseudocode;
	std::vector<uint64_t> callees;
	bool is_export = false;
	bool decompiled = false;
	int cluster_id = -1;
};

inline bool is_running_workspace(const workspace_reconstruction_state_t& state) {
	return state.running.load(std::memory_order_acquire);
}

inline float get_progress_workspace(const workspace_reconstruction_state_t& state) {
	return state.progress.load(std::memory_order_relaxed);
}

inline std::string get_status_workspace(const workspace_reconstruction_state_t& state) {
	std::lock_guard<std::mutex> lk(state.mutex);
	return state.status_text;
}

inline int get_total_functions_workspace(const workspace_reconstruction_state_t& state) {
	std::lock_guard<std::mutex> lk(state.mutex);
	return state.last_result.total_functions;
}

inline int get_decompiled_count_workspace(const workspace_reconstruction_state_t& state) {
	std::lock_guard<std::mutex> lk(state.mutex);
	return state.last_result.decompiled_functions;
}

inline const workspace_reconstruction_result_t& get_last_result_workspace(
	const workspace_reconstruction_state_t& state) {
	return state.last_result;
}

inline void cancel_workspace(workspace_reconstruction_state_t& state) {
	state.cancel_requested.store(true, std::memory_order_release);
}

namespace detail {

inline void set_status(workspace_reconstruction_state_t& state, const std::string& s) {
	std::lock_guard<std::mutex> lk(state.mutex);
	state.status_text = s;
}

inline void set_stage(workspace_reconstruction_state_t& state, stage_t s) {
	state.stage.store(static_cast<int>(s), std::memory_order_release);
}

inline bool cancelled(const workspace_reconstruction_state_t& state) {
	return state.cancel_requested.load(std::memory_order_acquire);
}

inline std::string to_hex(uint64_t v) {
	char buf[32];
	snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
	return buf;
}

inline std::string sanitize_name(const std::string& raw) {
	std::string out;
	out.reserve(raw.size());
	for (char c : raw) {
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '_')
			out.push_back(c);
		else
			out.push_back('_');
	}
	if (!out.empty() && out[0] >= '0' && out[0] <= '9')
		out.insert(out.begin(), '_');
	return out;
}

inline uint64_t resolve_runtime(const aida::analysis::address_t& addr, uint64_t image_base) {
	using namespace aida::analysis;
	if (addr.space == address_space_id_t::virtual_address ||
	    addr.space == address_space_id_t::live_virtual)
		return addr.value;
	if (addr.space == address_space_id_t::relative_virtual)
		return image_base + addr.value;
	return addr.value;
}

inline std::vector<function_info_t> collect_functions(
	const aida::analysis::analysis_snapshot_t& snapshot,
	const aida::analysis::pe_image_t& image,
	int max_functions)
{
	std::vector<function_info_t> funcs;
	std::set<uint64_t> seen;
	const uint64_t image_base = image.image_base();

	for (const auto& fr : snapshot.functions) {
		if (max_functions > 0 && static_cast<int>(funcs.size()) >= max_functions)
			break;

		uint64_t addr = resolve_runtime(fr.start, image_base);
		uint64_t end_addr = resolve_runtime(fr.end, image_base);
		if (!seen.insert(addr).second) continue;

		function_info_t fi;
		fi.address = addr;
		fi.end_address = end_addr;

		auto sym_it = std::lower_bound(snapshot.symbols.begin(), snapshot.symbols.end(),
		    fr.start,
		    [](const aida::analysis::symbol_record_t& s, const aida::analysis::address_t& a) {
			    return s.address < a;
		    });
		if (sym_it != snapshot.symbols.end() && sym_it->address == fr.start && !sym_it->name.empty())
			fi.name = sanitize_name(sym_it->name);
		else {
			char nm[64];
			snprintf(nm, sizeof(nm), "sub_%llX", static_cast<unsigned long long>(addr));
			fi.name = nm;
		}

		for (const auto& exp : image.exports()) {
			if (exp.forwarder) continue;
			if (exp.rva == fr.start.value) {
				fi.is_export = true;
				if (exp.name && !exp.name->empty())
					fi.name = sanitize_name(*exp.name);
				break;
			}
		}

		funcs.push_back(std::move(fi));
	}

	for (const auto& exp : image.exports()) {
		if (max_functions > 0 && static_cast<int>(funcs.size()) >= max_functions)
			break;
		if (exp.forwarder) continue;
		uint64_t addr = image_base + exp.rva;
		if (!seen.insert(addr).second) continue;

		function_info_t fi;
		fi.address = addr;
		fi.name = exp.name ? sanitize_name(*exp.name) : ("ordinal_" + std::to_string(exp.ordinal));
		fi.is_export = true;
		funcs.push_back(std::move(fi));
	}

	std::sort(funcs.begin(), funcs.end(), [](const function_info_t& a, const function_info_t& b) {
		return a.address < b.address;
	});

	if (max_functions > 0 && static_cast<int>(funcs.size()) > max_functions)
		funcs.resize(max_functions);

	return funcs;
}

inline void extract_all_callees(
	std::vector<function_info_t>& funcs,
	const aida::analysis::analysis_snapshot_t& snapshot,
	const aida::analysis::pe_image_t& image)
{
	using namespace aida::analysis;
	const uint64_t image_base = image.image_base();

	struct func_range_t {
		uint64_t start;
		uint64_t end;
		int idx;
	};
	std::vector<func_range_t> ranges;
	ranges.reserve(funcs.size());
	for (int i = 0; i < static_cast<int>(funcs.size()); ++i) {
		func_range_t r;
		r.start = funcs[i].address;
		r.end = funcs[i].end_address > r.start ? funcs[i].end_address : r.start + 1;
		r.idx = i;
		ranges.push_back(r);
	}
	std::sort(ranges.begin(), ranges.end(), [](const func_range_t& a, const func_range_t& b) {
		return a.start < b.start;
	});

	std::unordered_map<uint64_t, int> addr_to_idx;
	for (int i = 0; i < static_cast<int>(funcs.size()); ++i)
		addr_to_idx[funcs[i].address] = i;

	auto find_func = [&](uint64_t addr) -> int {
		auto it = std::upper_bound(ranges.begin(), ranges.end(), addr,
		    [](uint64_t v, const func_range_t& r) { return v < r.start; });
		if (it == ranges.begin()) return -1;
		--it;
		if (addr >= it->start && addr < it->end) return it->idx;
		return -1;
	};

	for (const auto& xref : snapshot.xrefs) {
		if (xref.kind != xref_kind_t::call) continue;

		uint64_t src = resolve_runtime(xref.source, image_base);
		uint64_t tgt = resolve_runtime(xref.target, image_base);

		int src_idx = find_func(src);
		if (src_idx < 0) continue;

		auto tgt_it = addr_to_idx.find(tgt);
		if (tgt_it != addr_to_idx.end())
			funcs[src_idx].callees.push_back(tgt);
	}
}

inline std::map<int, std::vector<int>> cluster_functions(
	std::vector<function_info_t>& funcs)
{
	std::unordered_map<uint64_t, int> addr_to_idx;
	for (int i = 0; i < static_cast<int>(funcs.size()); ++i)
		addr_to_idx[funcs[i].address] = i;

	std::vector<std::vector<int>> adj(funcs.size());
	for (int i = 0; i < static_cast<int>(funcs.size()); ++i) {
		for (auto callee_addr : funcs[i].callees) {
			auto it = addr_to_idx.find(callee_addr);
			if (it != addr_to_idx.end()) {
				adj[i].push_back(it->second);
				adj[it->second].push_back(i);
			}
		}
	}

	int cluster_id = 0;
	std::vector<bool> visited(funcs.size(), false);

	for (int i = 0; i < static_cast<int>(funcs.size()); ++i) {
		if (visited[i]) continue;

		std::deque<int> queue;
		queue.push_back(i);
		visited[i] = true;
		std::vector<int> component;

		while (!queue.empty()) {
			int cur = queue.front();
			queue.pop_front();
			component.push_back(cur);
			funcs[cur].cluster_id = cluster_id;

			for (int nb : adj[cur]) {
				if (!visited[nb]) {
					visited[nb] = true;
					queue.push_back(nb);
				}
			}
		}

		cluster_id++;
	}

	const int max_cluster_size = 200;
	for (int c = 0; c < cluster_id; ++c) {
		std::vector<int> members;
		for (int i = 0; i < static_cast<int>(funcs.size()); ++i)
			if (funcs[i].cluster_id == c)
				members.push_back(i);

		if (static_cast<int>(members.size()) > max_cluster_size) {
			int sub = 0;
			int new_base = cluster_id;
			for (int j = 0; j < static_cast<int>(members.size()); ++j) {
				if (j > 0 && j % max_cluster_size == 0) {
					sub++;
				}
				funcs[members[j]].cluster_id = (sub == 0) ? c : (new_base + sub - 1);
			}
			cluster_id = new_base + sub;
		}
	}

	std::map<int, std::vector<int>> clusters;
	for (int i = 0; i < static_cast<int>(funcs.size()); ++i)
		clusters[funcs[i].cluster_id].push_back(i);

	return clusters;
}

inline std::string guess_module_name(const std::vector<function_info_t>& funcs,
                                     const std::vector<int>& indices)
{
	std::unordered_map<std::string, int> prefix_counts;
	for (int idx : indices) {
		auto& name = funcs[idx].name;
		auto pos = name.find('_');
		if (pos != std::string::npos && pos > 1 && pos < 20) {
			std::string prefix = name.substr(0, pos);
			bool all_lower = true;
			for (char c : prefix) {
				if (c < 'a' || c > 'z') { all_lower = false; break; }
			}
			if (all_lower) prefix_counts[prefix]++;
		}
	}

	std::string best;
	int best_count = 0;
	for (auto& [k, v] : prefix_counts) {
		if (v > best_count) { best = k; best_count = v; }
	}

	if (best_count >= 3)
		return "module_" + best;

	return "";
}

inline void generate_common_header(
	const std::string& dir,
	const std::string& project_name,
	const aida::analysis::pe_image_t& image,
	bool include_imports,
	std::vector<std::string>& files_created)
{
	std::filesystem::path hdr_path = std::filesystem::path(dir) / "include" / (project_name + "_types.h");
	std::filesystem::create_directories(hdr_path.parent_path());

	std::ofstream ofs(hdr_path, std::ios::binary);
	if (!ofs) return;

	ofs << "#pragma once\n\n";
	ofs << "#include <stdint.h>\n";
	ofs << "#include <stddef.h>\n\n";

	ofs << "typedef unsigned char  BYTE;\n";
	ofs << "typedef unsigned short WORD;\n";
	ofs << "typedef unsigned long  DWORD;\n";
	ofs << "typedef unsigned long long QWORD;\n";
	ofs << "typedef int BOOL;\n";
	ofs << "typedef void* PVOID;\n";
	ofs << "typedef void* HANDLE;\n\n";

	if (include_imports && !image.imports().empty()) {
		ofs << "\n";
		std::set<std::string> import_modules;
		for (const auto& imp : image.imports())
			import_modules.insert(imp.library);

		for (auto& mod : import_modules) {
			ofs << "// imports from " << mod << "\n";
		}
		ofs << "\n";

		for (const auto& imp : image.imports()) {
			if (!imp.name) continue;
			ofs << "extern void* __imp_" << sanitize_name(*imp.name) << ";\n";
		}
		ofs << "\n";
	}

	ofs.close();
	files_created.push_back(hdr_path.string());
}

inline void generate_exports_header(
	const std::string& dir,
	const std::string& project_name,
	const std::vector<function_info_t>& funcs,
	std::vector<std::string>& files_created)
{
	std::filesystem::path hdr_path = std::filesystem::path(dir) / "include" / (project_name + "_exports.h");
	std::filesystem::create_directories(hdr_path.parent_path());

	std::ofstream ofs(hdr_path, std::ios::binary);
	if (!ofs) return;

	ofs << "#pragma once\n\n";
	ofs << "#include \"" << project_name << "_types.h\"\n\n";

	for (auto& fi : funcs) {
		if (!fi.is_export) continue;
		if (fi.decompiled && !fi.pseudocode.empty()) {
			auto first_line = fi.pseudocode.substr(0, fi.pseudocode.find('\n'));
			if (!first_line.empty() && first_line.back() == '{')
				first_line.pop_back();
			while (!first_line.empty() && (first_line.back() == ' ' || first_line.back() == '\t'))
				first_line.pop_back();
			ofs << first_line << ";\n";
		} else {
			ofs << "void " << fi.name << "(void);\n";
		}
	}

	ofs.close();
	files_created.push_back(hdr_path.string());
}

inline void generate_module_source(
	const std::string& dir,
	const std::string& project_name,
	const std::string& module_name,
	const std::vector<function_info_t>& funcs,
	const std::vector<int>& indices,
	std::vector<std::string>& files_created)
{
	std::filesystem::path src_path = std::filesystem::path(dir) / "src" / (module_name + ".cpp");
	std::filesystem::create_directories(src_path.parent_path());

	std::ofstream ofs(src_path, std::ios::binary);
	if (!ofs) return;

	ofs << "#include \"../include/" << project_name << "_types.h\"\n";
	ofs << "#include \"../include/" << project_name << "_exports.h\"\n\n";

	for (int idx : indices) {
		auto& fi = funcs[idx];

		if (fi.decompiled && !fi.pseudocode.empty()) {
			ofs << fi.pseudocode << "\n\n";
		} else {
			ofs << "void " << fi.name << "(void) {\n";
			ofs << "}\n\n";
		}
	}

	ofs.close();
	files_created.push_back(src_path.string());
}

inline void generate_cmake(
	const std::string& dir,
	const std::string& project_name,
	const std::vector<std::string>& source_files,
	std::vector<std::string>& files_created)
{
	std::filesystem::path cmake_path = std::filesystem::path(dir) / "CMakeLists.txt";

	std::ofstream ofs(cmake_path, std::ios::binary);
	if (!ofs) return;

	ofs << "cmake_minimum_required(VERSION 3.15)\n";
	ofs << "project(" << project_name << " LANGUAGES CXX)\n\n";
	ofs << "set(CMAKE_CXX_STANDARD 17)\n";
	ofs << "set(CMAKE_CXX_STANDARD_REQUIRED ON)\n\n";
	ofs << "include_directories(include)\n\n";
	ofs << "add_library(" << project_name << " STATIC\n";

	for (auto& sf : source_files) {
		auto rel = std::filesystem::relative(sf, dir);
		ofs << "    " << rel.generic_string() << "\n";
	}

	ofs << ")\n";

	ofs.close();
	files_created.push_back(cmake_path.string());
}

inline void generate_xref_json(
	const std::string& dir,
	const std::vector<function_info_t>& funcs,
	std::vector<std::string>& files_created)
{
	std::filesystem::path json_path = std::filesystem::path(dir) / "xrefs.json";

	std::ofstream ofs(json_path, std::ios::binary);
	if (!ofs) return;

	ofs << "{\n";
	bool first = true;
	for (auto& fi : funcs) {
		if (fi.callees.empty()) continue;
		if (!first) ofs << ",\n";
		first = false;
		ofs << "  \"" << to_hex(fi.address) << "\": {\n";
		ofs << "    \"name\": \"" << fi.name << "\",\n";
		ofs << "    \"callees\": [";
		for (size_t j = 0; j < fi.callees.size(); ++j) {
			if (j > 0) ofs << ", ";
			ofs << "\"" << to_hex(fi.callees[j]) << "\"";
		}
		ofs << "]\n  }";
	}
	ofs << "\n}\n";

	ofs.close();
	files_created.push_back(json_path.string());
}

inline void generate_module_map_json(
	const std::string& dir,
	const std::vector<function_info_t>& funcs,
	const std::map<int, std::string>& cluster_names,
	std::vector<std::string>& files_created)
{
	std::filesystem::path json_path = std::filesystem::path(dir) / "module_map.json";

	std::ofstream ofs(json_path, std::ios::binary);
	if (!ofs) return;

	ofs << "{\n";
	bool first = true;
	for (auto& fi : funcs) {
		if (!first) ofs << ",\n";
		first = false;

		std::string mod_name = "unknown";
		auto it = cluster_names.find(fi.cluster_id);
		if (it != cluster_names.end()) mod_name = it->second;

		ofs << "  \"" << to_hex(fi.address) << "\": {\n";
		ofs << "    \"name\": \"" << fi.name << "\",\n";
		ofs << "    \"module\": \"" << mod_name << "\",\n";
		ofs << "    \"export\": " << (fi.is_export ? "true" : "false") << ",\n";
		ofs << "    \"decompiled\": " << (fi.decompiled ? "true" : "false") << "\n";
		ofs << "  }";
	}
	ofs << "\n}\n";

	ofs.close();
	files_created.push_back(json_path.string());
}

}

inline void reconstruct_workspace(
	const workspace_reconstruction_config_t& config,
	workspace_reconstruction_state_t& state)
{
	if (state.running.load(std::memory_order_acquire)) {
		diag::log_tagged_fmt("source_recon", "reconstruct_workspace_rejected reason=already_running");
		return;
	}

	if (!config.workspace || config.workspace->closed()) {
		diag::log_tagged_fmt("source_recon", "reconstruct_workspace_rejected reason=invalid_workspace");
		{
			std::lock_guard<std::mutex> lk(state.mutex);
			state.last_result = {};
			state.last_result.success = false;
			state.last_result.error = "Workspace is unavailable or closed.";
			state.status_text = "Failed: Workspace is unavailable or closed.";
		}
		state.stage.store(static_cast<int>(stage_t::failed), std::memory_order_release);
		return;
	}

	auto workspace = config.workspace;
	auto snapshot = workspace->snapshot();
	if (!snapshot) {
		diag::log_tagged_fmt("source_recon", "reconstruct_workspace_rejected reason=no_snapshot");
		{
			std::lock_guard<std::mutex> lk(state.mutex);
			state.last_result = {};
			state.last_result.success = false;
			state.last_result.error = "Workspace snapshot is not available.";
			state.status_text = "Failed: Workspace snapshot is not available.";
		}
		state.stage.store(static_cast<int>(stage_t::failed), std::memory_order_release);
		return;
	}

	auto image = workspace->image();
	if (!image) {
		diag::log_tagged_fmt("source_recon", "reconstruct_workspace_rejected reason=no_image");
		{
			std::lock_guard<std::mutex> lk(state.mutex);
			state.last_result = {};
			state.last_result.success = false;
			state.last_result.error = "Workspace PE image is not available.";
			state.status_text = "Failed: Workspace PE image is not available.";
		}
		state.stage.store(static_cast<int>(stage_t::failed), std::memory_order_release);
		return;
	}

	auto decompiler = workspace->decompiler();
	if (!decompiler) {
		diag::log_tagged_fmt("source_recon", "reconstruct_workspace_rejected reason=no_decompiler");
		{
			std::lock_guard<std::mutex> lk(state.mutex);
			state.last_result = {};
			state.last_result.success = false;
			state.last_result.error = "Workspace decompiler service is not installed.";
			state.status_text = "Failed: Workspace decompiler service is not installed.";
		}
		state.stage.store(static_cast<int>(stage_t::failed), std::memory_order_release);
		return;
	}

	state.running.store(true, std::memory_order_release);
	state.cancel_requested.store(false, std::memory_order_release);
	state.progress.store(0.f);
	state.stage.store(static_cast<int>(stage_t::collect), std::memory_order_release);

	{
		std::lock_guard<std::mutex> lk(state.mutex);
		state.status_text = "Starting reconstruction...";
		state.last_result = {};
		state.last_result.output_dir = config.output_dir;
		state.last_result.module_name = workspace->identity().bin_name();
	}

	const std::string module_name = workspace->identity().bin_name();
	const std::string output_dir = config.output_dir;
	const std::string project_name = config.project_name;

	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "source_reconstructor";
	submission.label = "source_recon.reconstruct_workspace";
	submission.thread_class = "source_reconstruction";
	submission.domain = aida::infra::executor::domain_t::long_running;
	submission.priority = 2;
	submission.target_id = module_name.c_str();
	submission.failure_policy = "reject_not_started";
	submission.body = [config, workspace, snapshot, image, decompiler, module_name, output_dir, project_name, &state]() {
		const uint64_t worker_start_ms = GetTickCount64();
		diag::log_tagged_fmt("source_recon",
			"worker_enter module=%s max_functions=%d tid=%lu",
			module_name.c_str(),
			config.max_functions,
			GetCurrentThreadId());

		workspace_reconstruction_result_t result;
		result.output_dir = output_dir;
		result.module_name = module_name;

		auto finish = [&](bool success, const std::string& err = "") {
			result.success = success;
			result.error = err;
			diag::log_tagged_fmt("source_recon",
				"worker_finish success=%d error='%s' total=%d decompiled=%d modules=%d files=%zu elapsed_ms=%llu cancel=%d",
				success ? 1 : 0,
				err.c_str(),
				result.total_functions,
				result.decompiled_functions,
				result.modules_created,
				result.files_created.size(),
				static_cast<unsigned long long>(GetTickCount64() - worker_start_ms),
				state.cancel_requested.load(std::memory_order_acquire) ? 1 : 0);
			{
				std::lock_guard<std::mutex> lk(state.mutex);
				state.last_result = result;
				state.status_text = success ? "Reconstruction complete." : ("Failed: " + err);
			}
			detail::set_stage(state, success ? stage_t::done : stage_t::failed);
			state.progress.store(success ? 1.f : state.progress.load());
			state.running.store(false, std::memory_order_release);
		};

		try {
		std::filesystem::path out_dir(output_dir);
		{
			std::error_code mkdir_ec;
			std::filesystem::create_directories(out_dir / "src", mkdir_ec);
			if (mkdir_ec) {
				finish(false, "Failed to create output directories.");
				return;
			}
			std::filesystem::create_directories(out_dir / "include", mkdir_ec);
			if (mkdir_ec) {
				finish(false, "Failed to create output directories.");
				return;
			}
		}

		detail::set_stage(state, stage_t::collect);
		detail::set_status(state, "Collecting functions from workspace snapshot...");
		state.progress.store(0.02f);

		auto funcs = detail::collect_functions(*snapshot, *image, config.max_functions);

		if (detail::cancelled(state)) { finish(false, "Cancelled."); return; }

		result.total_functions = static_cast<int>(funcs.size());
		{
			std::lock_guard<std::mutex> lk(state.mutex);
			state.last_result.total_functions = result.total_functions;
		}

		if (funcs.empty()) {
			finish(false, "No functions found in workspace snapshot.");
			return;
		}

		char collect_msg[256];
		snprintf(collect_msg, sizeof(collect_msg), "Collected %d functions.",
		         static_cast<int>(funcs.size()));
		detail::set_status(state, collect_msg);
		state.progress.store(0.05f);

		detail::set_stage(state, stage_t::decompile);
		detail::set_status(state, "Decompiling functions via workspace decompiler service...");

		aida::analysis::cancellation_source_t cancel_source;
		auto cancel_token = cancel_source.token();

		const int total = static_cast<int>(funcs.size());
		int successful_decompiles = 0;

		for (int i = 0; i < total; ++i) {
			if (detail::cancelled(state)) {
				cancel_source.request_cancel();
				break;
			}

			aida::analysis::decompiler_request_t req;
			req.use_memory_cache = true;
			req.use_persistent_cache = true;

			aida::analysis::address_t func_addr;
			func_addr.space = aida::analysis::address_space_id_t::virtual_address;
			func_addr.value = funcs[i].address;
			func_addr.architecture = workspace->identity().architecture();
			func_addr.mode = image->architecture_mode();

			for (const auto& fr : snapshot->functions) {
				uint64_t fr_runtime = detail::resolve_runtime(fr.start, image->image_base());
				if (fr_runtime == funcs[i].address) {
					func_addr.space = fr.start.space;
					func_addr.value = fr.start.value;
					break;
				}
			}

			auto decomp_result = decompiler->decompile(func_addr, req, cancel_token);

			if (decomp_result) {
				auto& dr = decomp_result.value();
				if (!dr.pseudocode.empty()) {
					funcs[i].pseudocode = std::move(dr.pseudocode);
					funcs[i].decompiled = true;
					++successful_decompiles;
					if (!dr.function_name.empty() && dr.function_name.find("FUN_") != 0 &&
					    dr.function_name.find("sub_") != 0)
						funcs[i].name = detail::sanitize_name(dr.function_name);
				}
			}

			{
				std::lock_guard<std::mutex> lk(state.mutex);
				state.last_result.decompiled_functions = successful_decompiles;
			}

			float pct = 0.07f + 0.63f * (static_cast<float>(i + 1) / static_cast<float>(total));
			state.progress.store(pct);

			char dmsg[256];
			snprintf(dmsg, sizeof(dmsg), "Decompiling %d / %d", i + 1, total);
			detail::set_status(state, dmsg);
		}

		if (detail::cancelled(state)) { finish(false, "Cancelled."); return; }

		result.decompiled_functions = successful_decompiles;
		{
			std::lock_guard<std::mutex> lk(state.mutex);
			state.last_result.decompiled_functions = successful_decompiles;
		}

		diag::log_tagged_fmt("source_recon",
			"decompile_accounted total=%d success=%d failed=%d",
			total, successful_decompiles, total - successful_decompiles);

		detail::set_stage(state, stage_t::cluster);
		detail::set_status(state, "Extracting call graph from workspace snapshot...");
		state.progress.store(0.72f);

		std::set<uint64_t> addr_set;
		for (auto& fi : funcs) addr_set.insert(fi.address);

		detail::extract_all_callees(funcs, *snapshot, *image);

		detail::set_status(state, "Clustering functions into modules...");
		state.progress.store(0.75f);

		auto clusters = detail::cluster_functions(funcs);

		std::map<int, std::string> cluster_names;
		int unnamed_idx = 0;
		for (auto& [cid, indices] : clusters) {
			std::string guessed = detail::guess_module_name(funcs, indices);
			if (guessed.empty()) {
				char nm[64];
				snprintf(nm, sizeof(nm), "module_%03d", unnamed_idx++);
				guessed = nm;
			}
			cluster_names[cid] = guessed;
		}

		if (detail::cancelled(state)) { finish(false, "Cancelled."); return; }

		detail::set_stage(state, stage_t::headers);
		detail::set_status(state, "Generating headers...");
		state.progress.store(0.80f);

		detail::generate_common_header(
			output_dir, project_name, *image,
			config.include_imports, result.files_created);

		if (config.include_exports) {
			detail::generate_exports_header(
				output_dir, project_name, funcs, result.files_created);
		}

		if (detail::cancelled(state)) { finish(false, "Cancelled."); return; }

		detail::set_stage(state, stage_t::modules);
		detail::set_status(state, "Generating source modules...");
		state.progress.store(0.82f);

		std::vector<std::string> source_files;
		int module_idx = 0;
		int total_clusters = static_cast<int>(clusters.size());

		for (auto& [cid, indices] : clusters) {
			if (detail::cancelled(state)) { finish(false, "Cancelled."); return; }

			float mod_pct = 0.82f + 0.10f * (static_cast<float>(module_idx) / static_cast<float>((std::max)(total_clusters, 1)));
			state.progress.store(mod_pct);

			std::string mod_name = cluster_names[cid];
			detail::generate_module_source(
				output_dir, project_name, mod_name,
				funcs, indices, result.files_created);

			source_files.push_back(
				(std::filesystem::path(output_dir) / "src" / (mod_name + ".cpp")).string());
			module_idx++;
		}

		result.modules_created = module_idx;

		detail::set_stage(state, stage_t::metadata);
		detail::set_status(state, "Generating metadata...");
		state.progress.store(0.93f);

		if (config.generate_cmake) {
			detail::generate_cmake(
				output_dir, project_name,
				source_files, result.files_created);
		}

		detail::generate_xref_json(output_dir, funcs, result.files_created);
		detail::generate_module_map_json(output_dir, funcs, cluster_names, result.files_created);

		state.progress.store(0.98f);
		detail::set_status(state, "Finalizing...");

		result.total_functions = static_cast<int>(funcs.size());

		finish(true);
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("source_recon",
				"worker_exception kind=std module=%s stage=%d progress=%.3f elapsed_ms=%llu err=%s",
				module_name.c_str(),
				state.stage.load(std::memory_order_acquire),
				static_cast<double>(state.progress.load(std::memory_order_acquire)),
				static_cast<unsigned long long>(GetTickCount64() - worker_start_ms),
				ex.what());
			try {
				finish(false, std::string("Unhandled reconstruction exception: ") + ex.what());
			} catch (...) {
				detail::set_stage(state, stage_t::failed);
				state.running.store(false, std::memory_order_release);
			}
		} catch (...) {
			diag::log_tagged_fmt("source_recon",
				"worker_exception kind=unknown module=%s stage=%d progress=%.3f elapsed_ms=%llu",
				module_name.c_str(),
				state.stage.load(std::memory_order_acquire),
				static_cast<double>(state.progress.load(std::memory_order_acquire)),
				static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));
			try {
				finish(false, "Unhandled reconstruction exception.");
			} catch (...) {
				detail::set_stage(state, stage_t::failed);
				state.running.store(false, std::memory_order_release);
			}
		}
	};
	const bool posted = aida::infra::executor::submit(std::move(submission)).submitted;
	if (!posted) {
		diag::log_tagged_fmt("source_recon",
			"reconstruct_workspace_post_failed module=%s",
			module_name.c_str());
		std::lock_guard<std::mutex> lk(state.mutex);
		state.last_result.success = false;
		state.last_result.error = "Failed to schedule reconstruction worker.";
		state.status_text = "Failed: Failed to schedule reconstruction worker.";
		state.stage.store(static_cast<int>(stage_t::failed), std::memory_order_release);
		state.running.store(false, std::memory_order_release);
	}
}

}
