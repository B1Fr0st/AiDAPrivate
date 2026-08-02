#pragma once

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "function_index.hpp"
#include "../analysis/workspace/publication_indexes.hpp"

namespace xref_index {

	enum class kind_t { code, data };
	enum class edge_t { jump, call_proc, offset_ref };

	struct annotation_t {
		kind_t      kind = kind_t::code;
		edge_t      edge = edge_t::jump;
		bool        up = false;
		uint64_t    source_addr = 0;
		std::string source_label;
	};


	inline aida::analysis::workspace_result_t<std::vector<annotation_t>> query_to(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& target, size_t limit = 16,
		const aida::analysis::cancellation_token_t& cancel = {})
	{
		using namespace aida::analysis;
		if (limit > 100000) {
			return workspace_result_t<std::vector<annotation_t>>::failure(
				make_workspace_error(workspace_error_code_t::limit_exceeded,
					"Xref page exceeds 100000 records", "xref_index.query_to"));
		}
		auto normalized = function_index::normalize_workspace_address(workspace, target);
		if (!normalized)
			return workspace_result_t<std::vector<annotation_t>>::failure(normalized.error());
		if (workspace->target_kind() == target_kind_t::live_snapshot) {
			return workspace_result_t<std::vector<annotation_t>>::failure(
				make_workspace_error(
					workspace_error_code_t::live_target_bulk_analysis_unsupported,
					"A live target has no whole-module xref index",
					"xref_index.query_to"));
		}
		if (limit == 0)
			return workspace_result_t<std::vector<annotation_t>>::success(
				std::vector<annotation_t>{});
		auto publication = workspace->analysis_publication();
		if (!publication || !publication->snapshot) {
			return workspace_result_t<std::vector<annotation_t>>::failure(
				make_workspace_error(workspace_error_code_t::analysis_in_progress,
					"Xref index is not published yet", "xref_index.query_to"));
		}
		if (publication->binary_id != workspace->identity().binary_id() ||
			publication->generation != workspace->generation()) {
			return workspace_result_t<std::vector<annotation_t>>::failure(
				make_workspace_error(workspace_error_code_t::stale_generation,
					"Xref publication does not match the workspace generation",
					"xref_index.query_to"));
		}
		const auto workspace_cancel = workspace->cancellation_token();
		auto cancellation_error = [&]() {
			const bool deadline = cancel.deadline_exceeded() ||
				workspace_cancel.deadline_exceeded();
			auto error = make_workspace_error(deadline
				? workspace_error_code_t::deadline_exceeded
				: workspace_error_code_t::cancelled,
				deadline ? "Xref query deadline expired" : "Xref query was cancelled",
				"xref_index.query_to");
			error.deadline = deadline;
			error.cancellation = !deadline;
			return error;
		};
		if (cancel.stop_requested() || workspace_cancel.stop_requested())
			return workspace_result_t<std::vector<annotation_t>>::failure(
				cancellation_error());
		auto indexes = publication_indexes::for_publication_result(publication, cancel);
		if (!indexes)
			return workspace_result_t<std::vector<annotation_t>>::failure(indexes.error());
		const auto& snapshot = publication->snapshot;
		const auto& xrefs = snapshot->xrefs;
		const auto names = function_index::workspace_name_snapshot(workspace);
		std::vector<annotation_t> result;
		result.reserve((std::min)(limit, snapshot->xrefs.size()));
		const auto range = indexes.value()->xrefs_to(normalized.value());
		size_t visited = 0;
		for (std::uint32_t ordinal = range.begin; ordinal < range.end; ++ordinal) {
			if ((++visited & 0xFFFu) == 0 &&
				(cancel.stop_requested() || workspace_cancel.stop_requested()))
				return workspace_result_t<std::vector<annotation_t>>::failure(
					cancellation_error());
			const auto& xref = xrefs[indexes.value()->xref_to_entry(ordinal)];
			annotation_t item;
			item.kind = xref.kind == xref_kind_t::read ||
				xref.kind == xref_kind_t::write ||
				xref.kind == xref_kind_t::address ||
				xref.kind == xref_kind_t::relocation
				? kind_t::data : kind_t::code;
			item.edge = xref.kind == xref_kind_t::call
				? edge_t::call_proc
				: (item.kind == kind_t::data ? edge_t::offset_ref : edge_t::jump);
			const uint64_t source = function_index::workspace_display_address(workspace, xref.source);
			const uint64_t target_address = function_index::workspace_display_address(workspace, xref.target);
			if (source == 0 || target_address == 0) continue;
			item.up = source < target_address;
			item.source_addr = source;
			item.source_label = function_index::synthetic_name(names, xref.source);
			result.push_back(std::move(item));
			if (result.size() == limit) break;
		}
		return workspace_result_t<std::vector<annotation_t>>::success(std::move(result));
	}

	inline bool has_more(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& target, size_t returned,
		const aida::analysis::cancellation_token_t& cancel = {})
	{
		auto normalized = function_index::normalize_workspace_address(workspace, target);
		auto publication = workspace ? workspace->analysis_publication() : nullptr;
		if (!normalized || !publication || !publication->snapshot ||
			publication->binary_id != workspace->identity().binary_id() ||
			publication->generation != workspace->generation()) return false;
		const auto workspace_cancel = workspace->cancellation_token();
		if (cancel.stop_requested() || workspace_cancel.stop_requested())
			return false;
		const auto indexes = aida::analysis::publication_indexes::for_publication(publication, cancel);
		if (!indexes)
			return false;
		return indexes->xref_count_to(normalized.value()) > returned;
	}

}
