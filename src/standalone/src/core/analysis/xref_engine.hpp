#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "../infra/executor.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"
#include "workspace/analysis_workspace.hpp"

namespace xref_engine {

enum class xref_type_t : int {
	call,
	jump,
	conditional_jump,
	lea,
	data_ref,
};

struct xref_t {
	uint64_t    from_addr = 0;
	uint64_t    to_addr = 0;
	xref_type_t type = xref_type_t::call;
	std::string disasm_text;
	std::string module_name;
};

struct scan_state_t {
	std::vector<xref_t> results;
	std::mutex          mutex;
	std::atomic<bool>   scanning{false};
	std::atomic<float>  progress{0.f};
	std::atomic<bool>   cancel{false};
};

inline scan_state_t g_state;

inline std::string xref_type_name(xref_type_t t)
{
	switch (t) {
	case xref_type_t::call:             return "CALL";
	case xref_type_t::jump:             return "JMP";
	case xref_type_t::conditional_jump: return "Jcc";
	case xref_type_t::lea:              return "LEA";
	case xref_type_t::data_ref:         return "DATA";
	}
	return "???";
}

inline aida::analysis::workspace_result_t<aida::analysis::address_t>
normalize_address(
	const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	const aida::analysis::address_t& address)
{
	using namespace aida::analysis;
	if (!workspace) {
		return workspace_result_t<address_t>::failure(make_workspace_error(
			workspace_error_code_t::target_not_found,
			"Xref query requires an explicit workspace", "xref_engine.address"));
	}
	if (address.architecture != architecture_id_t::unknown &&
		address.architecture != workspace->identity().architecture()) {
		return workspace_result_t<address_t>::failure(make_workspace_error(
			workspace_error_code_t::unsupported_address_space,
			"Xref query architecture does not match the workspace",
			"xref_engine.address"));
	}
	if (workspace->target_kind() == target_kind_t::live_snapshot) {
		return workspace_result_t<address_t>::failure(make_workspace_error(
			workspace_error_code_t::live_target_bulk_analysis_unsupported,
			"A live target has no whole-module xref index", "xref_engine.address"));
	}
	auto image = workspace->image();
	if (!image) {
		return workspace_result_t<address_t>::failure(make_workspace_error(
			workspace_error_code_t::malformed_pe,
			"Xref workspace has no normalized image", "xref_engine.address"));
	}
	address_t result = address;
	result.architecture = image->architecture();
	result.mode = image->architecture_mode();
	if (address.space == address_space_id_t::relative_virtual) {
		if (address.value >= image->image_size()) {
			return workspace_result_t<address_t>::failure(make_workspace_error(
				workspace_error_code_t::out_of_range,
				"Xref RVA is outside the normalized image", "xref_engine.address"));
		}
		result.space = address_space_id_t::relative_virtual;
	} else if (address.space == address_space_id_t::file_offset) {
		auto rva = image->file_offset_to_rva(address.value);
		if (!rva) return workspace_result_t<address_t>::failure(rva.error());
		result.space = address_space_id_t::relative_virtual;
		result.value = rva.value();
	} else if (address.space == address_space_id_t::virtual_address) {
		if (address.value < image->image_base() ||
			address.value - image->image_base() >= image->image_size()) {
			return workspace_result_t<address_t>::failure(make_workspace_error(
				workspace_error_code_t::out_of_range,
				"Xref virtual address is outside the normalized image",
				"xref_engine.address"));
		}
		result.space = address_space_id_t::relative_virtual;
		result.value = address.value - image->image_base();
	} else {
		return workspace_result_t<address_t>::failure(make_workspace_error(
			workspace_error_code_t::unsupported_address_space,
			"Xref query address space is unsupported", "xref_engine.address"));
	}
	return workspace_result_t<address_t>::success(result);
}

inline uint64_t workspace_display_address(
	const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	const aida::analysis::address_t& address)
{
	using namespace aida::analysis;
	if (!workspace) return 0;
	if (address.space == address_space_id_t::virtual_address ||
		address.space == address_space_id_t::live_virtual)
		return address.value;
	const auto image = workspace->image();
	if (!image) return 0;
	uint64_t rva = 0;
	if (address.space == address_space_id_t::relative_virtual) {
		rva = address.value;
	} else if (address.space == address_space_id_t::file_offset) {
		auto translated = image->file_offset_to_rva(address.value);
		if (!translated) return 0;
		rva = translated.value();
	} else {
		return 0;
	}
	if (rva >= image->image_size() || image->image_base() > UINT64_MAX - rva)
		return 0;
	return image->image_base() + rva;
}

inline xref_type_t workspace_xref_type(aida::analysis::xref_kind_t kind)
{
	switch (kind) {
	case aida::analysis::xref_kind_t::call: return xref_type_t::call;
	case aida::analysis::xref_kind_t::code: return xref_type_t::jump;
	case aida::analysis::xref_kind_t::read:
	case aida::analysis::xref_kind_t::write:
	case aida::analysis::xref_kind_t::address:
	case aida::analysis::xref_kind_t::relocation:
		return xref_type_t::data_ref;
	}
	return xref_type_t::data_ref;
}

inline aida::analysis::workspace_result_t<std::vector<xref_t>> find_xrefs_to(
	const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	const aida::analysis::address_t& target, size_t limit = 1000,
	const aida::analysis::cancellation_token_t& cancel = {})
{
	using namespace aida::analysis;
	if (limit > 100000) {
		return workspace_result_t<std::vector<xref_t>>::failure(make_workspace_error(
			workspace_error_code_t::limit_exceeded,
			"Xref query exceeds 100000 records", "xref_engine.query_to"));
	}
	auto normalized = normalize_address(workspace, target);
	if (!normalized)
		return workspace_result_t<std::vector<xref_t>>::failure(normalized.error());
	if (limit == 0)
		return workspace_result_t<std::vector<xref_t>>::success(std::vector<xref_t>{});
	auto publication = workspace->analysis_publication();
	if (!publication || !publication->snapshot) {
		return workspace_result_t<std::vector<xref_t>>::failure(make_workspace_error(
			workspace_error_code_t::analysis_in_progress,
			"Xref index is not published yet", "xref_engine.query_to"));
	}
	if (publication->binary_id != workspace->identity().binary_id() ||
		publication->generation != workspace->generation()) {
		return workspace_result_t<std::vector<xref_t>>::failure(make_workspace_error(
			workspace_error_code_t::stale_generation,
			"Xref publication does not match the workspace generation",
			"xref_engine.query_to"));
	}
	const auto workspace_cancel = workspace->cancellation_token();
	auto cancellation_error = [&]() {
		const bool deadline = cancel.deadline_exceeded() ||
			workspace_cancel.deadline_exceeded();
		auto error = make_workspace_error(deadline
			? workspace_error_code_t::deadline_exceeded
			: workspace_error_code_t::cancelled,
			deadline ? "Xref query deadline expired" : "Xref query was cancelled",
			"xref_engine.query_to");
		error.deadline = deadline;
		error.cancellation = !deadline;
		return error;
	};
	if (cancel.stop_requested() || workspace_cancel.stop_requested())
		return workspace_result_t<std::vector<xref_t>>::failure(cancellation_error());
	const auto& snapshot = publication->snapshot;
	std::vector<xref_t> result;
	result.reserve((std::min)(limit, snapshot->xrefs.size()));
	size_t visited = 0;
	for (const auto& entry : snapshot->xrefs) {
		if ((++visited & 0xFFFu) == 0 &&
			(cancel.stop_requested() || workspace_cancel.stop_requested()))
			return workspace_result_t<std::vector<xref_t>>::failure(cancellation_error());
		if (entry.target.space != normalized.value().space ||
			entry.target.value != normalized.value().value)
			continue;
		xref_t item;
		item.from_addr = workspace_display_address(workspace, entry.source);
		item.to_addr = workspace_display_address(workspace, entry.target);
		if (item.from_addr == 0 || item.to_addr == 0) continue;
		item.type = workspace_xref_type(entry.kind);
		item.module_name = workspace->identity().bin_name();
		result.push_back(std::move(item));
		if (result.size() == limit) break;
	}
	return workspace_result_t<std::vector<xref_t>>::success(std::move(result));
}

inline aida::analysis::workspace_result_t<std::vector<xref_t>> find_xrefs_from(
	const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	const aida::analysis::address_t& source, size_t limit = 1000,
	const aida::analysis::cancellation_token_t& cancel = {})
{
	using namespace aida::analysis;
	if (limit > 100000) {
		return workspace_result_t<std::vector<xref_t>>::failure(make_workspace_error(
			workspace_error_code_t::limit_exceeded,
			"Xref query exceeds 100000 records", "xref_engine.query_from"));
	}
	auto normalized = normalize_address(workspace, source);
	if (!normalized)
		return workspace_result_t<std::vector<xref_t>>::failure(normalized.error());
	if (limit == 0)
		return workspace_result_t<std::vector<xref_t>>::success(std::vector<xref_t>{});
	auto publication = workspace->analysis_publication();
	if (!publication || !publication->snapshot) {
		return workspace_result_t<std::vector<xref_t>>::failure(make_workspace_error(
			workspace_error_code_t::analysis_in_progress,
			"Xref index is not published yet", "xref_engine.query_from"));
	}
	if (publication->binary_id != workspace->identity().binary_id() ||
		publication->generation != workspace->generation()) {
		return workspace_result_t<std::vector<xref_t>>::failure(make_workspace_error(
			workspace_error_code_t::stale_generation,
			"Xref publication does not match the workspace generation",
			"xref_engine.query_from"));
	}
	const auto workspace_cancel = workspace->cancellation_token();
	auto cancellation_error = [&]() {
		const bool deadline = cancel.deadline_exceeded() ||
			workspace_cancel.deadline_exceeded();
		auto error = make_workspace_error(deadline
			? workspace_error_code_t::deadline_exceeded
			: workspace_error_code_t::cancelled,
			deadline ? "Xref query deadline expired" : "Xref query was cancelled",
			"xref_engine.query_from");
		error.deadline = deadline;
		error.cancellation = !deadline;
		return error;
	};
	if (cancel.stop_requested() || workspace_cancel.stop_requested())
		return workspace_result_t<std::vector<xref_t>>::failure(cancellation_error());
	const auto& snapshot = publication->snapshot;
	std::vector<xref_t> result;
	result.reserve((std::min)(limit, snapshot->xrefs.size()));
	size_t visited = 0;
	for (const auto& entry : snapshot->xrefs) {
		if ((++visited & 0xFFFu) == 0 &&
			(cancel.stop_requested() || workspace_cancel.stop_requested()))
			return workspace_result_t<std::vector<xref_t>>::failure(cancellation_error());
		if (entry.source.space != normalized.value().space ||
			entry.source.value != normalized.value().value)
			continue;
		xref_t item;
		item.from_addr = workspace_display_address(workspace, entry.source);
		item.to_addr = workspace_display_address(workspace, entry.target);
		if (item.from_addr == 0 || item.to_addr == 0) continue;
		item.type = workspace_xref_type(entry.kind);
		item.module_name = workspace->identity().bin_name();
		result.push_back(std::move(item));
		if (result.size() == limit) break;
	}
	return workspace_result_t<std::vector<xref_t>>::success(std::move(result));
}

inline bool wait_until_idle(uint32_t timeout_ms)
{
	const auto start = std::chrono::steady_clock::now();
	for (;;) {
		if (!g_state.scanning.load(std::memory_order_acquire))
			return true;
		const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now() - start).count();
		if (elapsed >= static_cast<int64_t>(timeout_ms))
			return false;
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

namespace detail {

inline xref_type_t classify_instruction(const AsmInstr& ins)
{
	if (ins.is_call) return xref_type_t::call;
	if (ins.is_branch) {
		char m0 = ins.mnem[0];
		if (m0 == 'j' || m0 == 'J') {
			if (std::strcmp(ins.mnem, "jmp") == 0 || std::strcmp(ins.mnem, "JMP") == 0)
				return xref_type_t::jump;
			return xref_type_t::conditional_jump;
		}
		return xref_type_t::jump;
	}
	if (std::strncmp(ins.mnem, "lea", 3) == 0 || std::strncmp(ins.mnem, "LEA", 3) == 0)
		return xref_type_t::lea;
	return xref_type_t::data_ref;
}

inline bool extract_target(const uint8_t* code, int code_len, uint64_t ins_addr, const AsmInstr& ins, uint64_t& target)
{
	(void)code;
	(void)code_len;

	if ((ins.is_call || ins.is_branch) && ins.branch_target != 0) {
		target = ins.branch_target;
		return true;
	}

	if (ins.has_mem_op && ins.mem_op.base_reg == static_cast<uint16_t>(ZYDIS_REGISTER_RIP)) {
		int64_t computed = static_cast<int64_t>(ins_addr) + static_cast<int64_t>(ins.len) + ins.mem_op.disp;
		if (computed >= 0) {
			target = static_cast<uint64_t>(computed);
			return true;
		}
	}

	return false;
}

}

inline bool find_xrefs_to(uint64_t target_addr, uint64_t search_start, uint64_t search_size)
{
	if (g_state.scanning.load(std::memory_order_acquire)) {
		g_state.cancel.store(true, std::memory_order_release);
		if (!wait_until_idle(1000))
			return false;
	}

	g_state.scanning.store(true, std::memory_order_release);
	g_state.cancel.store(false, std::memory_order_release);
	g_state.progress.store(0.f, std::memory_order_release);
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.results.clear();
	}

	std::string module_name;
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		if (target_addr >= m.base && target_addr < m.base + m.size) {
			module_name = m.name;
			break;
		}
	}

	auto worker = [target_addr, search_start, search_size, module_name]() {
		struct scan_finish_t {
			~scan_finish_t() { g_state.scanning.store(false); }
		} scan_finish;

		const size_t page_size = 4096;
		uint64_t total = search_size ? search_size : 1;
		uint64_t scanned = 0;

		for (uint64_t offset = 0; offset < search_size && !g_state.cancel.load(); offset += page_size) {
			size_t chunk = page_size;
			if (offset + chunk > search_size)
				chunk = static_cast<size_t>(search_size - offset);

			std::vector<uint8_t> page_data;
			if (!driver_bridge::read_memory(search_start + offset, chunk, page_data)) {
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

				uint64_t ins_addr = search_start + offset + pos;
				AsmInstr ins = zydis_decode_one(data + pos, avail, ins_addr);
				const int ins_len = (ins.len > 0 && ins.len <= avail) ? ins.len : 1;

				uint64_t resolved_target = 0;
				if (ins.len > 0 && ins.len <= avail && detail::extract_target(data + pos, ins.len, ins_addr, ins, resolved_target)) {
					if (resolved_target == target_addr) {
						xref_t xref;
						xref.from_addr = ins_addr;
						xref.to_addr = target_addr;
						xref.type = detail::classify_instruction(ins);
						char full_text[256];
						snprintf(full_text, sizeof(full_text), "%s %s", ins.mnem, ins.ops);
						xref.disasm_text = full_text;
						xref.module_name = module_name;
						std::lock_guard<std::mutex> lk(g_state.mutex);
						g_state.results.push_back(std::move(xref));
					}
				}

				pos += ins_len;
			}

			scanned += chunk;
			g_state.progress.store(static_cast<float>(scanned) / static_cast<float>(total));
		}

	};
	if (search_size <= 0x100000) {
		worker();
		return true;
	}
	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "analysis";
	sub.label = "analysis.xref.find_to";
	sub.thread_class = "bounded_task";
	sub.domain = aida::infra::executor::domain_t::feature_worker;
	sub.priority = 2;
	sub.body = std::move(worker);
	if (!aida::infra::executor::submit(std::move(sub)).submitted) {
		g_state.scanning.store(false, std::memory_order_release);
		return false;
	}
	return true;
}

inline void find_xrefs_from(uint64_t source_addr, size_t max_instructions, std::vector<xref_t>& out)
{
	out.clear();

	size_t read_size = max_instructions * 15;
	if (read_size > 0x100000) read_size = 0x100000;

	std::vector<uint8_t> mem;
	if (!driver_bridge::read_memory(source_addr, read_size, mem) || mem.empty())
		return;

	std::string module_name;
	auto modules = driver_bridge::enumerate_modules();

	const uint8_t* data = mem.data();
	int sz = static_cast<int>(mem.size());
	int pos = 0;
	size_t count = 0;

	while (pos < sz && count < max_instructions) {
		int avail = sz - pos;
		if (avail > 15) avail = 15;

		uint64_t ins_addr = source_addr + pos;
		AsmInstr ins = zydis_decode_one(data + pos, avail, ins_addr);
		const int ins_len = (ins.len > 0 && ins.len <= avail) ? ins.len : 1;

		uint64_t resolved_target = 0;
		if (ins.len > 0 && ins.len <= avail && detail::extract_target(data + pos, ins.len, ins_addr, ins, resolved_target)) {
			xref_t xref;
			xref.from_addr = ins_addr;
			xref.to_addr = resolved_target;
			xref.type = detail::classify_instruction(ins);
			char full_text[256];
			snprintf(full_text, sizeof(full_text), "%s %s", ins.mnem, ins.ops);
			xref.disasm_text = full_text;

			for (auto& m : modules) {
				if (resolved_target >= m.base && resolved_target < m.base + m.size) {
					xref.module_name = m.name;
					break;
				}
			}

			out.push_back(std::move(xref));
		}

		if (ins.is_ret)
			break;

		pos += ins_len;
		++count;
	}
}

inline void cancel_scan()
{
	g_state.cancel.store(true);
}

inline bool is_scanning()
{
	return g_state.scanning.load();
}

inline bool find_xrefs_to(uint64_t target_addr)
{
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		if (target_addr >= m.base && target_addr < m.base + m.size) {
			return find_xrefs_to(target_addr, m.base, m.size);
		}
	}
	if (!modules.empty()) {
		return find_xrefs_to(target_addr, modules[0].base, modules[0].size);
	}
	return false;
}

}
