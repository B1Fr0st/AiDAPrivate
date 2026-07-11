#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "xref_engine.hpp"

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


namespace detail {

using publication_ptr_t = std::shared_ptr<const aida::analysis::analysis_publication_t>;

inline aida::analysis::workspace_result_t<publication_ptr_t> publication_for(
	const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	const char* phase)
{
	using namespace aida::analysis;
	if (!workspace) {
		return workspace_result_t<publication_ptr_t>::failure(make_workspace_error(
			workspace_error_code_t::target_not_found,
			"Xref database requires an explicit workspace", phase));
	}
	if (workspace->target_kind() == target_kind_t::live_snapshot) {
		return workspace_result_t<publication_ptr_t>::failure(make_workspace_error(
			workspace_error_code_t::live_target_bulk_analysis_unsupported,
			"A live target has no whole-module xref database", phase));
	}
	auto publication = workspace->analysis_publication();
	if (!publication || !publication->snapshot || !publication->snapshot->image) {
		return workspace_result_t<publication_ptr_t>::failure(make_workspace_error(
			workspace_error_code_t::analysis_in_progress,
			"Xref database is not published yet", phase));
	}
	if (publication->binary_id != workspace->identity().binary_id() ||
		publication->generation != workspace->generation()) {
		return workspace_result_t<publication_ptr_t>::failure(make_workspace_error(
			workspace_error_code_t::stale_generation,
			"Xref publication does not match the workspace generation", phase));
	}
	return workspace_result_t<publication_ptr_t>::success(std::move(publication));
}

inline bool stopped(const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	const aida::analysis::cancellation_token_t& cancel)
{
	return cancel.stop_requested() || workspace->cancellation_token().stop_requested();
}

inline aida::analysis::workspace_error_t cancellation_error(
	const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	const aida::analysis::cancellation_token_t& cancel,
	const char* phase)
{
	using namespace aida::analysis;
	const bool deadline = cancel.deadline_exceeded() ||
		workspace->cancellation_token().deadline_exceeded();
	auto error = make_workspace_error(deadline
		? workspace_error_code_t::deadline_exceeded
		: workspace_error_code_t::cancelled,
		deadline ? "Xref database deadline expired" : "Xref database request was cancelled",
		phase);
	error.deadline = deadline;
	error.cancellation = !deadline;
	return error;
}

inline aida::analysis::workspace_result_t<module_index_t> build_module_index(
	const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	const publication_ptr_t& publication,
	const aida::analysis::cancellation_token_t& cancel)
{
	using namespace aida::analysis;
	if (stopped(workspace, cancel))
		return workspace_result_t<module_index_t>::failure(
			cancellation_error(workspace, cancel, "xref_db.workspace_index"));
	const auto& snapshot = publication->snapshot;
	const auto& image = snapshot->image;
	module_index_t result;
	result.name = workspace->identity().bin_name();
	result.base = image->image_base();
	result.size = static_cast<uint32_t>((std::min<std::uint64_t>)(
		image->image_size(), (std::numeric_limits<uint32_t>::max)()));
	result.timestamp = image->timestamp();
	result.built = snapshot->baseline_complete;
	size_t visited = 0;
	for (const auto& record : snapshot->xrefs) {
		if ((++visited & 0xFFFu) == 0 && stopped(workspace, cancel))
			return workspace_result_t<module_index_t>::failure(
				cancellation_error(workspace, cancel, "xref_db.workspace_index"));
		xref_entry_t entry;
		entry.from_addr = xref_engine::workspace_display_address(workspace, record.source);
		entry.to_addr = xref_engine::workspace_display_address(workspace, record.target);
		if (entry.from_addr == 0 || entry.to_addr == 0) continue;
		entry.type = xref_engine::workspace_xref_type(record.kind);
		result.to_index[entry.to_addr].push_back(entry);
		result.from_index[entry.from_addr].push_back(std::move(entry));
		++result.total_xrefs;
	}
	auto order = [](const xref_entry_t& left, const xref_entry_t& right) {
		if (left.from_addr != right.from_addr) return left.from_addr < right.from_addr;
		if (left.to_addr != right.to_addr) return left.to_addr < right.to_addr;
		return static_cast<int>(left.type) < static_cast<int>(right.type);
	};
	for (auto& item : result.to_index) std::sort(item.second.begin(), item.second.end(), order);
	for (auto& item : result.from_index) std::sort(item.second.begin(), item.second.end(), order);
	return workspace_result_t<module_index_t>::success(std::move(result));
}

}

inline aida::analysis::workspace_result_t<module_index_t> build_module_index(
	const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	const aida::analysis::cancellation_token_t& cancel = {})
{
	auto publication = detail::publication_for(workspace, "xref_db.workspace_index");
	if (!publication)
		return aida::analysis::workspace_result_t<module_index_t>::failure(
			publication.error());
	return detail::build_module_index(workspace, publication.value(), cancel);
}

inline aida::analysis::workspace_result_t<std::vector<xref_entry_t>> query_xrefs_to(
	const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	const aida::analysis::address_t& address, size_t limit = 1000,
	const aida::analysis::cancellation_token_t& cancel = {})
{
	using namespace aida::analysis;
	if (limit > 100000) {
		return workspace_result_t<std::vector<xref_entry_t>>::failure(
			make_workspace_error(workspace_error_code_t::limit_exceeded,
				"Xref database page exceeds 100000 records", "xref_db.query_to"));
	}
	auto normalized = xref_engine::normalize_address(workspace, address);
	if (!normalized)
		return workspace_result_t<std::vector<xref_entry_t>>::failure(normalized.error());
	auto publication = detail::publication_for(workspace, "xref_db.query_to");
	if (!publication)
		return workspace_result_t<std::vector<xref_entry_t>>::failure(publication.error());
	if (limit == 0)
		return workspace_result_t<std::vector<xref_entry_t>>::success({});
	std::vector<xref_entry_t> result;
	result.reserve((std::min)(limit, publication.value()->snapshot->xrefs.size()));
	size_t visited = 0;
	for (const auto& record : publication.value()->snapshot->xrefs) {
		if ((++visited & 0xFFFu) == 0 && detail::stopped(workspace, cancel))
			return workspace_result_t<std::vector<xref_entry_t>>::failure(
				detail::cancellation_error(workspace, cancel, "xref_db.query_to"));
		if (record.target.space != normalized.value().space ||
			record.target.value != normalized.value().value)
			continue;
		xref_entry_t entry;
		entry.from_addr = xref_engine::workspace_display_address(workspace, record.source);
		entry.to_addr = xref_engine::workspace_display_address(workspace, record.target);
		if (entry.from_addr == 0 || entry.to_addr == 0) continue;
		entry.type = xref_engine::workspace_xref_type(record.kind);
		result.push_back(std::move(entry));
		if (result.size() == limit) break;
	}
	return workspace_result_t<std::vector<xref_entry_t>>::success(std::move(result));
}

inline aida::analysis::workspace_result_t<std::vector<xref_entry_t>> query_xrefs_from(
	const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	const aida::analysis::address_t& address, size_t limit = 1000,
	const aida::analysis::cancellation_token_t& cancel = {})
{
	using namespace aida::analysis;
	if (limit > 100000) {
		return workspace_result_t<std::vector<xref_entry_t>>::failure(
			make_workspace_error(workspace_error_code_t::limit_exceeded,
				"Xref database page exceeds 100000 records", "xref_db.query_from"));
	}
	auto normalized = xref_engine::normalize_address(workspace, address);
	if (!normalized)
		return workspace_result_t<std::vector<xref_entry_t>>::failure(normalized.error());
	auto publication = detail::publication_for(workspace, "xref_db.query_from");
	if (!publication)
		return workspace_result_t<std::vector<xref_entry_t>>::failure(publication.error());
	if (limit == 0)
		return workspace_result_t<std::vector<xref_entry_t>>::success({});
	std::vector<xref_entry_t> result;
	result.reserve((std::min)(limit, publication.value()->snapshot->xrefs.size()));
	size_t visited = 0;
	for (const auto& record : publication.value()->snapshot->xrefs) {
		if ((++visited & 0xFFFu) == 0 && detail::stopped(workspace, cancel))
			return workspace_result_t<std::vector<xref_entry_t>>::failure(
				detail::cancellation_error(workspace, cancel, "xref_db.query_from"));
		if (record.source.space != normalized.value().space ||
			record.source.value != normalized.value().value)
			continue;
		xref_entry_t entry;
		entry.from_addr = xref_engine::workspace_display_address(workspace, record.source);
		entry.to_addr = xref_engine::workspace_display_address(workspace, record.target);
		if (entry.from_addr == 0 || entry.to_addr == 0) continue;
		entry.type = xref_engine::workspace_xref_type(record.kind);
		result.push_back(std::move(entry));
		if (result.size() == limit) break;
	}
	return workspace_result_t<std::vector<xref_entry_t>>::success(std::move(result));
}

inline aida::analysis::workspace_result_t<std::vector<call_graph_node_t>> build_call_graph(
	const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	size_t max_nodes = 100000,
	const aida::analysis::cancellation_token_t& cancel = {})
{
	using namespace aida::analysis;
	if (max_nodes == 0 || max_nodes > 100000) {
		return workspace_result_t<std::vector<call_graph_node_t>>::failure(
			make_workspace_error(workspace_error_code_t::limit_exceeded,
				"Call graph node limit must be between 1 and 100000",
				"xref_db.call_graph"));
	}
	auto publication = detail::publication_for(workspace, "xref_db.call_graph");
	if (!publication)
		return workspace_result_t<std::vector<call_graph_node_t>>::failure(
			publication.error());
	const auto& snapshot = publication.value()->snapshot;
	std::vector<const function_record_t*> functions;
	functions.reserve(snapshot->functions.size());
	for (const auto& function : snapshot->functions) functions.push_back(&function);
	std::sort(functions.begin(), functions.end(), [](const auto* left, const auto* right) {
		return left->start < right->start;
	});
	std::unordered_map<entity_id_t, std::string> names;
	names.reserve(snapshot->symbols.size());
	for (const auto& symbol : snapshot->symbols) {
		if (!symbol.name.empty()) names.emplace(symbol.id, symbol.name);
	}
	std::map<uint64_t, call_graph_node_t> nodes;
	auto enclosing = [&](const address_t& address) -> const function_record_t* {
		auto found = std::upper_bound(functions.begin(), functions.end(), address,
			[](const auto& value, const auto* function) { return value < function->start; });
		if (found == functions.begin()) return nullptr;
		--found;
		const auto* function = *found;
		if (address.space != function->start.space ||
			address.value < function->start.value ||
			address.value >= function->end.value)
			return nullptr;
		return function;
	};
	auto assign_name = [&](call_graph_node_t& node, const function_record_t* function) {
		if (!node.name.empty()) return;
		if (function && function->symbol_id) {
			const auto found = names.find(*function->symbol_id);
			if (found != names.end()) node.name = found->second;
		}
		if (node.name.empty()) {
			char text[32]{};
			std::snprintf(text, sizeof(text), "sub_%llX",
				static_cast<unsigned long long>(node.addr));
			node.name = text;
		}
	};
	size_t visited = 0;
	for (const auto& edge : snapshot->xrefs) {
		if ((++visited & 0xFFFu) == 0 && detail::stopped(workspace, cancel))
			return workspace_result_t<std::vector<call_graph_node_t>>::failure(
				detail::cancellation_error(workspace, cancel, "xref_db.call_graph"));
		if (edge.kind != xref_kind_t::call) continue;
		const auto* caller_function = enclosing(edge.source);
		const auto* callee_function = enclosing(edge.target);
		const address_t& caller_address = caller_function ? caller_function->start : edge.source;
		const address_t& callee_address = callee_function ? callee_function->start : edge.target;
		const uint64_t caller = xref_engine::workspace_display_address(workspace, caller_address);
		const uint64_t callee = xref_engine::workspace_display_address(workspace, callee_address);
		if (caller == 0 || callee == 0) continue;
			auto& caller_node = nodes[caller];
			caller_node.addr = caller;
			auto& callee_node = nodes[callee];
			callee_node.addr = callee;
			assign_name(caller_node, caller_function);
			assign_name(callee_node, callee_function);
			if (std::find(caller_node.callees.begin(), caller_node.callees.end(), callee)
				== caller_node.callees.end())
				caller_node.callees.push_back(callee);
			if (std::find(callee_node.callers.begin(), callee_node.callers.end(), caller)
				== callee_node.callers.end())
				callee_node.callers.push_back(caller);
			if (nodes.size() > max_nodes) {
				return workspace_result_t<std::vector<call_graph_node_t>>::failure(
					make_workspace_error(workspace_error_code_t::limit_exceeded,
						"Call graph exceeded its node limit", "xref_db.call_graph"));
			}
	}
	std::vector<call_graph_node_t> result;
	result.reserve(nodes.size());
	for (auto& item : nodes) {
		std::sort(item.second.callees.begin(), item.second.callees.end());
		std::sort(item.second.callers.begin(), item.second.callers.end());
		result.push_back(std::move(item.second));
	}
	return workspace_result_t<std::vector<call_graph_node_t>>::success(std::move(result));
}

inline size_t total_indexed_xrefs(
	const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
{
	auto publication = workspace ? workspace->analysis_publication() : nullptr;
	return publication && publication->snapshot &&
		publication->binary_id == workspace->identity().binary_id() &&
		publication->generation == workspace->generation()
		? publication->snapshot->xrefs.size() : 0;
}

}
