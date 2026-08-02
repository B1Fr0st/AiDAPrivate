#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "workspace/string_arena.hpp"
#include "workspace/publication_indexes.hpp"
#include "xref_engine.hpp"

namespace xref_db {

struct xref_entry_t {
	uint64_t                 from_addr = 0;
	uint64_t                 to_addr   = 0;
	xref_engine::xref_type_t type      = xref_engine::xref_type_t::call;
	std::string              disasm_text;
};

struct xref_entry_v2_t {
	uint64_t                 from_addr        = 0;
	uint64_t                 to_addr          = 0;
	std::uint32_t            disasm_string_id = aida::analysis::string_arena_t::null_id;
	xref_engine::xref_type_t type             = xref_engine::xref_type_t::call;
};

static_assert(sizeof(xref_entry_v2_t) == 24,
			  "xref_entry_v2_t must remain 24 bytes for bounded xref residency");

struct module_index_t {
	std::string name;
	uint64_t    base = 0;
	uint32_t    size = 0;
	uint64_t    timestamp = 0;

	std::vector<xref_entry_v2_t>      to_sorted;
	std::vector<xref_entry_v2_t>      from_sorted;
	aida::analysis::string_arena_t    disasm_strings;

	size_t total_xrefs = 0;
	bool   built = false;

	std::vector<xref_entry_t> entries_to(uint64_t address, size_t limit = 1000) const
	{
		std::vector<xref_entry_t> result;
		auto it = std::lower_bound(to_sorted.begin(), to_sorted.end(), address,
			[](const xref_entry_v2_t& entry, uint64_t value) { return entry.to_addr < value; });
		for (; it != to_sorted.end() && it->to_addr == address && result.size() < limit; ++it) {
			xref_entry_t entry;
			entry.from_addr = it->from_addr;
			entry.to_addr = it->to_addr;
			entry.type = it->type;
			entry.disasm_text = disasm_strings.str(it->disasm_string_id);
			result.push_back(std::move(entry));
		}
		return result;
	}

	std::vector<xref_entry_t> entries_from(uint64_t address, size_t limit = 1000) const
	{
		std::vector<xref_entry_t> result;
		auto it = std::lower_bound(from_sorted.begin(), from_sorted.end(), address,
			[](const xref_entry_v2_t& entry, uint64_t value) { return entry.from_addr < value; });
		for (; it != from_sorted.end() && it->from_addr == address && result.size() < limit; ++it) {
			xref_entry_t entry;
			entry.from_addr = it->from_addr;
			entry.to_addr = it->to_addr;
			entry.type = it->type;
			entry.disasm_text = disasm_strings.str(it->disasm_string_id);
			result.push_back(std::move(entry));
		}
		return result;
	}
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
	auto indexes = publication_indexes::for_publication_result(publication, cancel);
	if (!indexes) {
		if (indexes.error().cancellation || indexes.error().deadline)
			return workspace_result_t<module_index_t>::failure(
				cancellation_error(workspace, cancel, "xref_db.workspace_index"));
		return workspace_result_t<module_index_t>::failure(indexes.error());
	}
	const auto& snapshot = publication->snapshot;
	const auto& image = snapshot->image;
	module_index_t result;
	result.name = workspace->identity().bin_name();
	result.base = image->image_base();
	result.size = static_cast<uint32_t>((std::min<std::uint64_t>)(
		image->image_size(), (std::numeric_limits<uint32_t>::max)()));
	result.timestamp = image->timestamp();
	result.built = snapshot->baseline_complete;
	auto pairs = indexes.value()->module_index_pairs(
		[&workspace](const address_t& address) {
			return xref_engine::workspace_display_address(workspace, address);
		},
		[](xref_kind_t kind) {
			return static_cast<int>(xref_engine::workspace_xref_type(kind));
		},
		cancel,
		[&workspace, &cancel] { return detail::stopped(workspace, cancel); });
	if (!pairs) {
		if (pairs.error().cancellation || pairs.error().deadline)
			return workspace_result_t<module_index_t>::failure(
				cancellation_error(workspace, cancel, "xref_db.workspace_index"));
		return workspace_result_t<module_index_t>::failure(pairs.error());
	}
	const auto fill = [](const std::vector<publication_indexes::module_entry_t>& source,
		std::vector<xref_entry_v2_t>& output) {
		output.reserve(source.size());
		for (const auto& item : source) {
			xref_entry_v2_t entry;
			entry.from_addr = item.from;
			entry.to_addr = item.to;
			entry.type = static_cast<xref_engine::xref_type_t>(item.type);
			output.push_back(entry);
		}
	};
	fill(pairs.value().first, result.to_sorted);
	fill(pairs.value().second, result.from_sorted);
	result.total_xrefs = result.from_sorted.size();
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
	auto indexes = publication_indexes::for_publication_result(publication.value(), cancel);
	if (!indexes)
		return workspace_result_t<std::vector<xref_entry_t>>::failure(indexes.error());
	const auto& xrefs = publication.value()->snapshot->xrefs;
	std::vector<xref_entry_t> result;
	result.reserve((std::min)(limit, publication.value()->snapshot->xrefs.size()));
	const auto range = indexes.value()->xrefs_to(normalized.value());
	size_t visited = 0;
	for (std::uint32_t ordinal = range.begin; ordinal < range.end; ++ordinal) {
		if ((++visited & 0xFFFu) == 0 && detail::stopped(workspace, cancel))
			return workspace_result_t<std::vector<xref_entry_t>>::failure(
				detail::cancellation_error(workspace, cancel, "xref_db.query_to"));
		const auto& record = xrefs[indexes.value()->xref_to_entry(ordinal)];
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
	auto indexes = publication_indexes::for_publication_result(publication.value(), cancel);
	if (!indexes)
		return workspace_result_t<std::vector<xref_entry_t>>::failure(indexes.error());
	const auto& xrefs = publication.value()->snapshot->xrefs;
	std::vector<xref_entry_t> result;
	result.reserve((std::min)(limit, publication.value()->snapshot->xrefs.size()));
	const auto range = indexes.value()->xrefs_from(normalized.value());
	size_t visited = 0;
	for (std::uint32_t ordinal = range.begin; ordinal < range.end; ++ordinal) {
		if ((++visited & 0xFFFu) == 0 && detail::stopped(workspace, cancel))
			return workspace_result_t<std::vector<xref_entry_t>>::failure(
				detail::cancellation_error(workspace, cancel, "xref_db.query_from"));
		const auto& record = xrefs[indexes.value()->xref_from_entry(ordinal)];
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
	auto indexes = publication_indexes::for_publication_result(publication.value(), cancel);
	if (!indexes) {
		if (indexes.error().cancellation || indexes.error().deadline)
			return workspace_result_t<std::vector<call_graph_node_t>>::failure(
				detail::cancellation_error(workspace, cancel, "xref_db.call_graph"));
		return workspace_result_t<std::vector<call_graph_node_t>>::failure(indexes.error());
	}
	auto graph = indexes.value()->call_graph(max_nodes, cancel,
		[&workspace, &cancel] { return detail::stopped(workspace, cancel); });
	if (!graph) {
		if (graph.error().cancellation || graph.error().deadline)
			return workspace_result_t<std::vector<call_graph_node_t>>::failure(
				detail::cancellation_error(workspace, cancel, "xref_db.call_graph"));
		return workspace_result_t<std::vector<call_graph_node_t>>::failure(graph.error());
	}
	return workspace_result_t<std::vector<call_graph_node_t>>::success(*graph.value());
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
