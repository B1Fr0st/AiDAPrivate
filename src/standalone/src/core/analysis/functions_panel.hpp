#pragma once

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../ui/application_view_registry.hpp"
#include "zydis_disasm.hpp"
#include "disasm_view.hpp"
#include "../infra/executor.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/diag_log.hpp"
#endif
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/components.hpp"
#include "ui/empty_state.hpp"
#include "ui/fonts.hpp"
#include "ui/ui_anim.hpp"
#include "../ui/analysis_context_menu.hpp"
#include "xref_db_view.hpp"
#include "../disasm/pseudocode_view.hpp"
#include "../disasm/rename_dialog.hpp"
#include "../disasm/comment_dialog.hpp"
#include "workspace/overlay_journal.hpp"
#include "workspace/workspace_registry.hpp"
#include "../session/analysis_session.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstddef>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <mutex>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace cfg_view {
	void build_cfg(const disasm_view::workspace_context_t& context,
		uint64_t entry_address);
}

namespace functions_panel {

	struct function_entry_t {
		uint64_t    address = 0;
		uint32_t    size = 0;
		std::string name;
		std::string section;
		uint32_t    calls_in = 0;
		uint32_t    calls_out = 0;
		bool        synthetic_name = true;
	};

	struct presentation_snapshot_t {
		std::shared_ptr<const std::vector<function_entry_t>> entries;
		std::vector<int> sorted_indices;
		std::unordered_map<uint64_t, std::size_t> row_by_address;
	};

	struct view_state_t {
		std::mutex                     mtx;
		std::shared_ptr<const std::vector<function_entry_t>> entries =
			std::make_shared<const std::vector<function_entry_t>>();
		std::shared_ptr<const presentation_snapshot_t> presentation =
			std::make_shared<const presentation_snapshot_t>();
		std::atomic<bool>              ready{false};
		std::atomic<bool>              building{false};
		std::atomic<bool>              cancel{false};
		uint64_t                       cached_module_base = 0;
		uint32_t                       cached_module_size = 0;
		std::string                    cached_module_name;
		uint64_t                       cached_pid_token = 0;
		uint64_t                       cached_generation = 0;
		uint64_t                       cached_analysis_revision = 0;
		uint64_t                       cached_overlay_revision = 0;
		uint64_t                       cached_symbol_revision = 0;

		char                           filter_buf[160] = {};
		std::string                    last_filter_lower;
		std::vector<int>               filtered_indices;
		bool                           filter_dirty = true;

		int                            selected_row = -1;
		uint64_t                       selected_addr = 0;
		float                          row_anim_time = 0.f;
		int                            ctx_row = -1;
		uint64_t                       ctx_addr = 0;

		int                            sort_column = 0;
		bool                           sort_ascending = true;
		bool                           sort_dirty = false;
	};

	inline std::mutex& workspace_states_mutex() {
		static std::mutex mutex;
		return mutex;
	}

	inline std::unordered_map<std::string, std::shared_ptr<view_state_t>>&
	workspace_states() {
		static std::unordered_map<std::string, std::shared_ptr<view_state_t>> states;
		return states;
	}

	inline std::shared_ptr<aida::analysis::analysis_workspace_t>& render_workspace() {
		thread_local std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
		return workspace;
	}

	inline std::shared_ptr<view_state_t> state_handle_for(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace) {
		if (!workspace) {
			static auto empty = std::make_shared<view_state_t>();
			return empty;
		}
		const std::string id = workspace->identity().binary_id().to_hex();
		std::lock_guard<std::mutex> lock(workspace_states_mutex());
		auto& slot = workspace_states()[id];
		if (!slot) slot = std::make_shared<view_state_t>();
		return slot;
	}

	inline view_state_t& state_for(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace) {
		return *state_handle_for(workspace);
	}

	inline view_state_t& state() {
		return state_for(render_workspace());
	}

	namespace detail {

		inline std::string to_lower_copy(const std::string& s) {
			std::string out;
			out.resize(s.size());
			for (size_t i = 0; i < s.size(); ++i) {
				out[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(s[i])));
			}
			return out;
		}

		inline int compare_case_insensitive(const std::string& lhs, const std::string& rhs) {
			const std::size_t shared = (std::min)(lhs.size(), rhs.size());
			for (std::size_t index = 0; index < shared; ++index) {
				const int left = std::tolower(static_cast<unsigned char>(lhs[index]));
				const int right = std::tolower(static_cast<unsigned char>(rhs[index]));
				if (left < right) return -1;
				if (left > right) return 1;
			}
			if (lhs.size() < rhs.size()) return -1;
			if (lhs.size() > rhs.size()) return 1;
			return 0;
		}

		inline std::string make_synthetic_name(uint64_t addr) {
			char buf[32];
			std::snprintf(buf, sizeof(buf), "sub_%llX",
				static_cast<unsigned long long>(addr));
			return std::string(buf);
		}

		inline std::string strip_module_prefix(const std::string& s) {
			auto pos = s.find('!');
			if (pos == std::string::npos) return s;
			return s.substr(pos + 1);
		}

		inline void refresh_from_workspace(
			const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
		{
			if (!workspace) return;
			auto state_handle = state_handle_for(workspace);
			auto publication = workspace->analysis_publication();
			if (!publication || !publication->snapshot) {
				if (workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot) {
					std::lock_guard<std::mutex> lock(state_handle->mtx);
					state_handle->entries =
						std::make_shared<const std::vector<function_entry_t>>();
					state_handle->presentation =
						std::make_shared<const presentation_snapshot_t>();
					state_handle->filtered_indices.clear();
					state_handle->cached_module_base = workspace->identity().image_base();
					state_handle->cached_module_size = workspace->identity().module()
						? static_cast<uint32_t>((std::min<std::uint64_t>)(
							workspace->identity().module()->size, UINT32_MAX)) : 0;
					state_handle->cached_module_name = workspace->identity().bin_name();
					state_handle->ready.store(true, std::memory_order_release);
					state_handle->building.store(false, std::memory_order_release);
				}
				return;
			}
			{
				std::lock_guard<std::mutex> lock(state_handle->mtx);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				const uint64_t symbol_revision = 0;
#else
				const auto current_symbols = analysis_session::symbols_for_workspace(workspace);
				const uint64_t symbol_revision = current_symbols ? current_symbols->revision() : 0;
#endif
				if (state_handle->cached_generation == publication->generation &&
					state_handle->cached_analysis_revision == publication->analysis_revision &&
					state_handle->cached_overlay_revision == publication->overlay_revision &&
					state_handle->cached_symbol_revision == symbol_revision)
					return;
			}
			bool expected = false;
			if (!state_handle->building.compare_exchange_strong(
					expected, true, std::memory_order_acq_rel))
				return;
			state_handle->ready.store(false, std::memory_order_release);
			const auto snapshot = publication->snapshot;
			const auto overlay = workspace->overlay();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			std::shared_ptr<symbol_store::workspace_state_t> debug_symbols;
			uint64_t debug_symbol_revision = 0;
#else
			const auto debug_symbols = analysis_session::symbols_for_workspace(workspace);
			const uint64_t debug_symbol_revision = debug_symbols ? debug_symbols->revision() : 0;
#endif
			aida::infra::executor::submission_t submission;
			submission.owner_subsystem = "analysis";
			submission.label = "analysis.functions_panel.workspace_projection";
			submission.thread_class = "bounded_task";
			submission.domain = aida::infra::executor::domain_t::feature_worker;
			submission.priority = 2;
			submission.generation = publication->generation;
			submission.body = [workspace, state_handle, publication, snapshot, overlay,
				debug_symbols, debug_symbol_revision]() {
				std::unordered_map<aida::analysis::entity_id_t, std::string> symbols;
				symbols.reserve(snapshot->symbols.size());
				for (const auto& symbol : snapshot->symbols) {
					if (!symbol.name.empty()) symbols.emplace(symbol.id, symbol.name);
				}
				const auto image = snapshot->image;
				std::unordered_map<uint64_t, std::string> debug_symbol_names;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
				if (debug_symbols) {
					const auto mode = image ? image->architecture_mode() :
						(workspace->identity().architecture() ==
							aida::analysis::architecture_id_t::x86_64
							? aida::analysis::architecture_mode_t::x86_64
							: (workspace->identity().architecture() ==
								aida::analysis::architecture_id_t::x86
								? aida::analysis::architecture_mode_t::x86_32
								: aida::analysis::architecture_mode_t::unknown));
					auto entries = debug_symbols->function_snapshot(
						workspace->identity().architecture(), mode);
					debug_symbol_names.reserve(entries.size());
					for (auto& entry : entries) {
						if (!entry.name.empty())
							debug_symbol_names.emplace(entry.address.value,
								std::move(entry.name));
					}
				}
#else
				(void)debug_symbols;
#endif
				std::unordered_map<uint64_t, std::string> overlay_names;
				if (overlay) {
					const auto overlay_snapshot = overlay->snapshot();
					if (overlay_snapshot.revision == publication->overlay_revision) {
						for (const auto& item : overlay_snapshot.items) {
							const auto& operation = item.second;
							if (operation.kind != aida::analysis::overlay_operation_kind_t::name ||
								operation.name.empty())
								continue;
							uint64_t operation_va = 0;
							if (operation.address.space ==
								aida::analysis::address_space_id_t::relative_virtual) {
								if (!image || operation.address.value >= image->image_size() ||
									image->image_base() > UINT64_MAX - operation.address.value)
									continue;
								operation_va = image->image_base() + operation.address.value;
							} else if (operation.address.space ==
								aida::analysis::address_space_id_t::virtual_address ||
								operation.address.space ==
								aida::analysis::address_space_id_t::live_virtual) {
								operation_va = operation.address.value;
							} else if (image) {
								auto rva = image->file_offset_to_rva(operation.address.value);
								if (!rva || image->image_base() > UINT64_MAX - rva.value())
									continue;
								operation_va = image->image_base() + rva.value();
							}
							if (operation_va != 0)
								overlay_names.emplace(operation_va, operation.name);
						}
					}
				}
				std::vector<const aida::analysis::function_record_t*> ordered;
				ordered.reserve(snapshot->functions.size());
				for (const auto& function : snapshot->functions)
					ordered.push_back(&function);
				std::sort(ordered.begin(), ordered.end(), [](const auto* left, const auto* right) {
					return left->start < right->start;
				});
				auto enclosing = [&](const aida::analysis::address_t& address)
					-> const aida::analysis::function_record_t* {
					auto found = std::upper_bound(ordered.begin(), ordered.end(), address,
						[](const auto& value, const auto* function) {
							return value < function->start;
						});
					if (found == ordered.begin()) return nullptr;
					--found;
					const auto* function = *found;
					if (address.space != function->start.space ||
						address.value < function->start.value ||
						address.value >= function->end.value)
						return nullptr;
					return function;
				};
				std::unordered_map<aida::analysis::entity_id_t, uint32_t> calls_in;
				std::unordered_map<aida::analysis::entity_id_t, uint32_t> calls_out;
				for (const auto& edge : snapshot->edges) {
					if (workspace->cancellation_token().stop_requested()) {
						state_handle->building.store(false, std::memory_order_release);
						return;
					}
					if (edge.kind != aida::analysis::edge_kind_t::call &&
						edge.kind != aida::analysis::edge_kind_t::tail_call)
						continue;
					const auto* caller = enclosing(edge.source);
					const auto* callee = enclosing(edge.target);
					if (caller && calls_out[caller->id] != UINT32_MAX) ++calls_out[caller->id];
					if (callee && calls_in[callee->id] != UINT32_MAX) ++calls_in[callee->id];
				}
				std::vector<function_entry_t> entries;
				entries.reserve(ordered.size());
				for (const auto* function : ordered) {
					if (workspace->cancellation_token().stop_requested()) {
						state_handle->building.store(false, std::memory_order_release);
						return;
					}
					function_entry_t entry;
					uint64_t function_rva = 0;
					bool have_function_rva = false;
					if (function->start.space == aida::analysis::address_space_id_t::relative_virtual) {
						if (!image || function->start.value >= image->image_size() ||
							image->image_base() > UINT64_MAX - function->start.value)
							continue;
						function_rva = function->start.value;
						have_function_rva = true;
						entry.address = image->image_base() + function_rva;
					} else if (function->start.space == aida::analysis::address_space_id_t::virtual_address ||
						function->start.space == aida::analysis::address_space_id_t::live_virtual) {
						entry.address = function->start.value;
						if (image && entry.address >= image->image_base()) {
							function_rva = entry.address - image->image_base();
							have_function_rva = true;
						}
					} else {
						continue;
					}
					const uint64_t span = function->end.value > function->start.value
						? function->end.value - function->start.value : 0;
					entry.size = static_cast<uint32_t>((std::min<std::uint64_t>)(span, UINT32_MAX));
					const auto overlay_name = overlay_names.find(entry.address);
					if (overlay_name != overlay_names.end())
						entry.name = overlay_name->second;
					if (entry.name.empty()) {
						const auto debug_name = debug_symbol_names.find(entry.address);
						if (debug_name != debug_symbol_names.end())
							entry.name = debug_name->second;
					}
					if (entry.name.empty() && function->symbol_id) {
						const auto found = symbols.find(*function->symbol_id);
						if (found != symbols.end()) entry.name = found->second;
					}
					entry.synthetic_name = entry.name.empty();
					if (entry.synthetic_name) entry.name = make_synthetic_name(entry.address);
					if (image && have_function_rva) {
						const auto* section = image->section_for_rva(function_rva);
						if (section) entry.section = section->name;
					}
					entry.calls_in = calls_in[function->id];
					entry.calls_out = calls_out[function->id];
					entries.push_back(std::move(entry));
				}
				{
					std::lock_guard<std::mutex> lock(state_handle->mtx);
					if (workspace->generation() != publication->generation) {
						state_handle->building.store(false, std::memory_order_release);
						return;
					}
					state_handle->entries =
						std::make_shared<const std::vector<function_entry_t>>(std::move(entries));
					state_handle->presentation =
						std::make_shared<const presentation_snapshot_t>();
					state_handle->filtered_indices.clear();
					state_handle->cached_module_base = workspace->identity().image_base();
					state_handle->cached_module_size = image ? image->image_size() : 0;
					state_handle->cached_module_name = workspace->identity().bin_name();
					state_handle->cached_generation = publication->generation;
					state_handle->cached_analysis_revision = publication->analysis_revision;
					state_handle->cached_overlay_revision = publication->overlay_revision;
					state_handle->cached_symbol_revision = debug_symbol_revision;
					state_handle->filter_dirty = true;
					state_handle->sort_dirty = true;
				}
				state_handle->ready.store(true, std::memory_order_release);
				state_handle->building.store(false, std::memory_order_release);
			};
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			auto preview_body = std::move(submission.body);
			preview_body();
#else
			const auto submitted = aida::infra::executor::submit(std::move(submission));
			if (!submitted.submitted) {
				state_handle->building.store(false, std::memory_order_release);
				diag::log_tagged_fmt("functions_panel",
					"workspace_projection_submit_failed binary_id=%s reason=%s",
					workspace->identity().binary_id().to_hex().c_str(),
					submitted.reject_reason.c_str());
			}
#endif
		}

		inline void launch_build_if_needed(view_state_t&)
		{
			refresh_from_workspace(render_workspace());
		}

		inline void rebuild_filter(view_state_t& s) {
			std::string current = to_lower_copy(s.filter_buf);
			std::shared_ptr<const std::vector<function_entry_t>> entries;
			{
				std::lock_guard<std::mutex> lock(s.mtx);
				if (!s.filter_dirty && current == s.last_filter_lower) return;
				s.last_filter_lower = current;
				s.filter_dirty = false;
				entries = s.entries;
			}
			std::vector<int> filtered;
			filtered.reserve(entries ? entries->size() : 0);
			if (current.empty()) {
				for (int index = 0; entries && index < static_cast<int>(entries->size()); ++index)
					filtered.push_back(index);
			} else {
				std::string addr_query = current;
				if (addr_query.size() > 2 && addr_query[0] == '0' && addr_query[1] == 'x')
					addr_query = addr_query.substr(2);
				char addr_buf[32];
				for (int index = 0; entries && index < static_cast<int>(entries->size()); ++index) {
					const auto& entry = (*entries)[static_cast<std::size_t>(index)];
					std::snprintf(addr_buf, sizeof(addr_buf), "%llx",
						static_cast<unsigned long long>(entry.address));
					bool matched = std::strstr(addr_buf, addr_query.c_str()) != nullptr;
					if (!matched)
						matched = to_lower_copy(entry.name).find(current) != std::string::npos;
					if (!matched && !entry.section.empty())
						matched = to_lower_copy(entry.section).find(current) != std::string::npos;
					if (matched) filtered.push_back(index);
				}
			}
			{
				std::lock_guard<std::mutex> lock(s.mtx);
				if (s.entries != entries) {
					s.filter_dirty = true;
					return;
				}
				s.filtered_indices = std::move(filtered);
				s.sort_dirty = true;
			}
		}

		inline void apply_sort(view_state_t& s) {
			std::shared_ptr<const std::vector<function_entry_t>> entries;
			std::vector<int> sorted;
			int column = 0;
			bool ascending = true;
			{
				std::lock_guard<std::mutex> lock(s.mtx);
				if (!s.sort_dirty) return;
				s.sort_dirty = false;
				entries = s.entries;
				sorted = s.filtered_indices;
				column = s.sort_column;
				ascending = s.sort_ascending;
			}
			auto compare = [column, ascending, &entries](int left, int right) {
				const auto& a = (*entries)[static_cast<std::size_t>(left)];
				const auto& b = (*entries)[static_cast<std::size_t>(right)];
				int c = 0;
				switch (column) {
					case 0:
						if (a.address < b.address) c = -1;
						else if (a.address > b.address) c = 1;
						break;
					case 1:
						c = compare_case_insensitive(a.name, b.name);
						break;
					case 2:
						if (a.size < b.size) c = -1;
						else if (a.size > b.size) c = 1;
						break;
					case 3:
						c = compare_case_insensitive(a.section, b.section);
						break;
					case 4: {
						uint64_t ax = static_cast<uint64_t>(a.calls_in)
							+ static_cast<uint64_t>(a.calls_out);
						uint64_t bx = static_cast<uint64_t>(b.calls_in)
							+ static_cast<uint64_t>(b.calls_out);
						if (ax < bx) c = -1;
						else if (ax > bx) c = 1;
						break;
					}
					default:
						if (a.address < b.address) c = -1;
						else if (a.address > b.address) c = 1;
						break;
				}
				if (c == 0) {
					if (a.address < b.address) c = -1;
					else if (a.address > b.address) c = 1;
				}
				return ascending ? (c < 0) : (c > 0);
			};
			if (entries)
				std::sort(sorted.begin(), sorted.end(), compare);
			auto presentation = std::make_shared<presentation_snapshot_t>();
			presentation->entries = entries;
			presentation->sorted_indices = std::move(sorted);
			presentation->row_by_address.reserve(presentation->sorted_indices.size());
			for (std::size_t row = 0; row < presentation->sorted_indices.size(); ++row) {
				const int source = presentation->sorted_indices[row];
				if (entries && source >= 0 && source < static_cast<int>(entries->size()))
					presentation->row_by_address.emplace(
						(*entries)[static_cast<std::size_t>(source)].address, row);
			}
			{
				std::lock_guard<std::mutex> lock(s.mtx);
				if (s.entries != entries || s.sort_column != column ||
					s.sort_ascending != ascending) {
					s.sort_dirty = true;
					return;
				}
				if (s.selected_addr != 0) {
					const auto selected = presentation->row_by_address.find(s.selected_addr);
					if (selected == presentation->row_by_address.end()) {
						s.selected_row = -1;
						s.selected_addr = 0;
					} else {
						s.selected_row = static_cast<int>(selected->second);
					}
				}
				s.presentation = std::move(presentation);
			}
		}

		inline void jump_to_disasm(uint64_t addr) {
			if (addr == 0) return;
			auto context = disasm_view::capture_workspace(render_workspace());
			if (!context) return;
			aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
			disasm_view::goto_address(addr, context);
		}

		inline void select_function(uint64_t addr) {
			if (addr == 0) return;
			auto context = disasm_view::capture_workspace(render_workspace());
			if (!context) return;
			disasm_view::select_address(addr, context);
		}

		inline void open_in_graph(uint64_t addr) {
			if (addr == 0) return;
			auto context = disasm_view::capture_workspace(render_workspace());
			if (!context) return;
			cfg_view::build_cfg(context, addr);
			aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.graph"));
		}

		inline void open_in_pseudocode(uint64_t addr) {
			if (addr == 0) return;
			auto context = disasm_view::capture_workspace(render_workspace());
			if (!context) return;
			pseudocode_view::request_decompile(context, addr, false);
			aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("document.pseudocode"));
		}

		inline void rename_function(uint64_t addr) {
			if (addr == 0) return;
			auto context = disasm_view::capture_workspace(render_workspace());
			if (!context) return;
			disasm_view::select_address(addr, context);
			rename_dialog::open(context,
				aida::analysis::address_t{aida::analysis::address_space_id_t::virtual_address, addr});
		}

		inline void comment_function(uint64_t addr) {
			if (addr == 0) return;
			auto context = disasm_view::capture_workspace(render_workspace());
			if (!context) return;
			disasm_view::select_address(addr, context);
			comment_dialog::open(context,
				aida::analysis::address_t{aida::analysis::address_space_id_t::virtual_address, addr});
		}

		inline void open_in_view(uint64_t addr, const char* stable_id) {
			if (addr == 0) return;
			select_function(addr);
			aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t(stable_id));
		}

		inline void show_xrefs_to(uint64_t addr) {
			if (addr == 0) return;
			auto context = disasm_view::capture_workspace(render_workspace());
			if (!context) return;
			aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
			disasm_view::goto_address(addr, context);
			disasm_view::open_xrefs(addr, context);
		}

		inline void show_xrefs_direction(uint64_t addr, bool query_to) {
			if (addr == 0) return;
			auto context = disasm_view::capture_workspace(render_workspace());
			if (!context) return;
			const auto typed = disasm_view::typed_address(context, addr);
			const auto xrefs = xref_db_view::state_for(context);
			if (!typed || !xrefs) return;
			xref_db_view::submit_query(context, xrefs, *typed, query_to);
			aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("view.analysis.references"));
		}

		inline ImU32 alpha_u32(ImU32 c, float a) {
			return aida::ui::with_alpha(c, a);
		}

		inline void draw_loading_strip(ImDrawList* dl, ImVec2 a, ImVec2 b, ImU32 col) {
			float t = aida::ui::clock::seconds() * 1.2f;
			float phase = t - std::floor(t);
			float w = b.x - a.x;
			float bw = w * 0.30f;
			float bx = a.x + (w + bw) * phase - bw;
			ImVec2 ba = ImVec2(bx, a.y);
			ImVec2 bb = ImVec2(bx + bw, b.y);
			if (ba.x < a.x) ba.x = a.x;
			if (bb.x > b.x) bb.x = b.x;
			dl->PushClipRect(a, b, true);
			dl->AddRectFilledMultiColor(ba, bb,
				aida::ui::with_alpha(col, 0.f),
				aida::ui::with_alpha(col, 1.f),
				aida::ui::with_alpha(col, 1.f),
				aida::ui::with_alpha(col, 0.f));
			dl->PopClipRect();
		}

	}

	inline void render_impl(float, float, float w, float h) {
		auto& s = state();
		const auto& th = aida::ui::resolved();
		const float dt = aida::ui::clock::dt();
		s.row_anim_time += dt;

		if (w < 120.f) {
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
			ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.f);
			ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::ColorConvertU32ToFloat4(th.bg_base));
			const ImGuiWindowFlags narrow_flags =
				ImGuiWindowFlags_NoTitleBar |
				ImGuiWindowFlags_NoResize |
				ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_NoCollapse |
				ImGuiWindowFlags_NoScrollbar |
				ImGuiWindowFlags_NoScrollWithMouse |
				ImGuiWindowFlags_NoBringToFrontOnFocus;
			ImGui::BeginChild("##functions_panel_content", ImVec2(w, h), false, narrow_flags);
			ImDrawList* ndl = ImGui::GetWindowDrawList();
			ImVec2 nwp = ImGui::GetWindowPos();
			ImFont* ncap = aida::ui::fonts::caption();
			if (!ncap) ncap = ImGui::GetFont();
			const char* nmsg = "Functions panel too narrow";
			float nfs = aida::ui::components::detail::ui_fs() * 0.88f;
			ImVec2 nts = ncap->CalcTextSizeA(nfs, FLT_MAX, w - 8.f, nmsg);
			ImVec2 npos = ImVec2(nwp.x + (w - nts.x) * 0.5f, nwp.y + (h - nts.y) * 0.5f);
			ndl->AddText(ncap, nfs, npos, th.text_dim, nmsg);
			ImGui::EndChild();
			ImGui::PopStyleColor();
			ImGui::PopStyleVar(2);
			return;
		}

		const bool compact = (w < 220.f);

		detail::launch_build_if_needed(s);

		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.f);
		ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::ColorConvertU32ToFloat4(th.bg_base));

		const ImGuiWindowFlags wflags =
			ImGuiWindowFlags_NoTitleBar |
			ImGuiWindowFlags_NoResize |
			ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoCollapse |
			ImGuiWindowFlags_NoScrollbar |
			ImGuiWindowFlags_NoScrollWithMouse |
			ImGuiWindowFlags_NoBringToFrontOnFocus;

		ImGui::BeginChild("##functions_panel_content", ImVec2(w, h), false, wflags);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();

		const float header_h = 62.f;
		const float pad = 8.f;

		ImVec2 hdr_a = ImVec2(wp.x, wp.y);
		ImVec2 hdr_b = ImVec2(wp.x + w, wp.y + header_h);
		dl->AddRectFilledMultiColor(hdr_a, hdr_b,
			th.panel_header, th.panel_header, th.panel_bg, th.panel_bg);
		dl->AddLine(ImVec2(hdr_a.x, hdr_b.y - 0.5f),
			ImVec2(hdr_b.x, hdr_b.y - 0.5f), th.border_subtle, 1.f);

		ImFont* title_font = aida::ui::fonts::body_strong();
		if (!title_font) title_font = ImGui::GetFont();
		ImFont* body_font = aida::ui::fonts::body();
		if (!body_font) body_font = ImGui::GetFont();
		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = body_font;
		ImFont* caption_font = aida::ui::fonts::caption();
		if (!caption_font) caption_font = body_font;

		const float fs_fp_base = aida::ui::components::detail::ui_fs();
		const float title_fs = fs_fp_base * 1.10f;
		const float title_x = wp.x + pad + 2.f;
		const float title_y = wp.y + 5.f;
		dl->AddText(title_font, title_fs,
			ImVec2(title_x, title_y),
			th.text_primary, "Functions");
		{
			ImVec2 title_size = title_font->CalcTextSizeA(title_fs, FLT_MAX, 0.f, "Functions");
			float underline_y = title_y + title_size.y + 1.f;
			dl->AddLine(ImVec2(title_x, underline_y),
				ImVec2(title_x + 22.f, underline_y),
				th.accent_u32, 2.f);
		}

		size_t total_count = 0;
		size_t shown_count = 0;
		bool ready = s.ready.load(std::memory_order_acquire);
		bool building = s.building.load(std::memory_order_acquire);
		{
			std::lock_guard<std::mutex> lk(s.mtx);
			total_count = s.entries ? s.entries->size() : 0;
		}

		ImGui::PushFont(body_font);

		const float input_y = 27.f;
		const float input_h = 26.f;
		const float input_w_max = w - pad * 2.f - 110.f;
		float input_w = input_w_max;
		if (input_w < 120.f) input_w = w - pad * 2.f;

		{
			float shadow_x0 = wp.x + pad;
			float shadow_y0 = wp.y + input_y + input_h;
			float shadow_x1 = shadow_x0 + input_w;
			float shadow_y1 = shadow_y0 + 3.f;
			ImU32 shadow_top = IM_COL32(0, 0, 0, 30);
			ImU32 shadow_bot = IM_COL32(0, 0, 0, 0);
			dl->AddRectFilledMultiColor(
				ImVec2(shadow_x0, shadow_y0),
				ImVec2(shadow_x1, shadow_y1),
				shadow_top, shadow_top, shadow_bot, shadow_bot);
		}

		ImGui::SetCursorScreenPos(ImVec2(wp.x + pad, wp.y + input_y));
		bool filter_changed = aida::ui::input_text(
			"##fn_filter", s.filter_buf, sizeof(s.filter_buf),
			"Filter functions...", false,
			ImVec2(input_w, input_h));
		if (filter_changed) {
			std::lock_guard<std::mutex> lock(s.mtx);
			s.filter_dirty = true;
		}

		if (input_w_max == input_w && input_w_max < w - pad * 2.f) {
			char count_buf[48];
			std::snprintf(count_buf, sizeof(count_buf), "%zu functions", total_count);
			ImFont* badge_font = caption_font;
			float bfs = fs_fp_base * 0.85f;
			float bw = badge_font->CalcTextSizeA(bfs, FLT_MAX, 0.f, count_buf).x + 16.f;
			float bh = 22.f;
			ImVec2 ba = ImVec2(wp.x + w - pad - bw, wp.y + input_y + (input_h - bh) * 0.5f);
			ImVec2 bb = ImVec2(ba.x + bw, ba.y + bh);
			ImU32 badge_col = building
				? aida::ui::with_alpha(th.warning, 0.55f)
				: aida::ui::with_alpha(th.accent_u32, 0.85f);
			dl->AddRectFilled(ba, bb, badge_col, 6.f);
			ImU32 badge_border = aida::ui::lighten(th.accent_u32, 15);
			dl->AddRect(ba, bb, badge_border, 6.f, 0, 1.f);
			ImU32 text_on_badge = IM_COL32(255, 255, 255, 240);
			dl->AddText(badge_font, bfs,
				ImVec2(ba.x + 8.f, ba.y + (bh - bfs) * 0.5f),
				text_on_badge, count_buf);
		}

		if (building) {
			float bar_y = wp.y + header_h - 2.f;
			detail::draw_loading_strip(dl,
				ImVec2(wp.x, bar_y),
				ImVec2(wp.x + w, bar_y + 2.f),
				aida::ui::lighten(th.accent_u32, 8));
		}

		ImGui::SetCursorScreenPos(ImVec2(wp.x + pad, wp.y + header_h + 4.f));

		const float content_h = h - header_h - 8.f;
		ImVec2 content_pos = ImVec2(wp.x + pad, wp.y + header_h + 4.f);
		ImVec2 content_size = ImVec2(w - pad * 2.f, content_h);

		if (!ready && building) {
			ImGui::BeginChild("##fn_loading", content_size, false,
				ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);
			ImVec2 cp = ImGui::GetCursorScreenPos();
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::cpu;
			cfg.title = "Building functions list...";
			cfg.body = "Walking exception directory and resolving symbols on a worker thread.";
			cfg.max_width = std::min(content_size.x - 32.f, 360.f);
			aida::ui::empty_state::render(cp, content_size, cfg);
			ImGui::EndChild();
			ImGui::PopFont();
			ImGui::EndChild();
			ImGui::PopStyleColor();
			ImGui::PopStyleVar(2);
			return;
		}

		if (!ready && !building) {
			ImGui::BeginChild("##fn_empty_no_module", content_size, false,
				ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);
			ImVec2 cp = ImGui::GetCursorScreenPos();
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
			cfg.title = "No analyzed functions yet";
			cfg.body = "Open a binary or attach to a running process to populate the symbol list.";
			cfg.max_width = std::min(content_size.x - 32.f, 360.f);
			aida::ui::empty_state::render(cp, content_size, cfg);
			ImGui::EndChild();
			ImGui::PopFont();
			ImGui::EndChild();
			ImGui::PopStyleColor();
			ImGui::PopStyleVar(2);
			return;
		}

		detail::rebuild_filter(s);
		detail::apply_sort(s);

		std::shared_ptr<const presentation_snapshot_t> row_view;
		{
			std::lock_guard<std::mutex> lk(s.mtx);
			row_view = s.presentation;
			shown_count = row_view ? row_view->sorted_indices.size() : 0;
		}

		ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(7.f, 3.f));
		ImGui::PushStyleColor(ImGuiCol_TableHeaderBg, th.panel_header);
		ImGui::PushStyleColor(ImGuiCol_TableBorderLight, th.border_subtle);
		ImGui::PushStyleColor(ImGuiCol_TableBorderStrong, th.border_subtle);
		ImGui::PushStyleColor(ImGuiCol_TableRowBg, ImVec4(0.f, 0.f, 0.f, 0.f));
		ImGui::PushStyleColor(ImGuiCol_TableRowBgAlt,
			ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.panel_bg, 0.45f)));

		const ImGuiTableFlags tflags =
			ImGuiTableFlags_Resizable |
			ImGuiTableFlags_Reorderable |
			ImGuiTableFlags_Sortable |
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_BordersInnerV |
			ImGuiTableFlags_ScrollY |
			ImGuiTableFlags_SizingStretchProp;

		ImVec2 outer = ImVec2(content_size.x, content_size.y);
		ImGui::SetCursorScreenPos(content_pos);
		bool ctx_menu_request = false;

		if (compact) {
			ImGui::SetCursorScreenPos(content_pos);
			ImGui::BeginChild("##fn_compact", content_size, false,
				ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);

			ImDrawList* cdl = ImGui::GetWindowDrawList();
			const float row_h = (std::max)(34.f, fs_fp_base * 2.15f);

			ImGuiListClipper clipper;
			clipper.Begin(row_view ? static_cast<int>(row_view->sorted_indices.size()) : 0,
				row_h);
			while (clipper.Step()) {
				for (int row_idx = clipper.DisplayStart; row_idx < clipper.DisplayEnd; ++row_idx) {
					const int entry_idx = row_view->sorted_indices[static_cast<std::size_t>(row_idx)];
					if (!row_view->entries || entry_idx < 0 ||
						entry_idx >= static_cast<int>(row_view->entries->size()))
						continue;
					const auto& e = (*row_view->entries)[static_cast<std::size_t>(entry_idx)];

					ImGui::PushID(row_idx);

					ImVec2 row_min = ImGui::GetCursorScreenPos();
					ImVec2 row_max = ImVec2(row_min.x + content_size.x, row_min.y + row_h);

					char btn_label[40];
					std::snprintf(btn_label, sizeof(btn_label), "##fn_cb_%d", row_idx);
					ImGui::InvisibleButton(btn_label, ImVec2(content_size.x, row_h));

					bool is_selected = (s.selected_addr != 0 && s.selected_addr == e.address);
					bool hovered = ImGui::IsItemHovered();
					bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
					bool dbl_clicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)
						&& ImGui::IsItemHovered();
					bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);

					if ((row_idx & 1) == 1) {
						cdl->AddRectFilled(row_min, row_max,
							aida::ui::with_alpha(th.panel_bg, 0.35f));
					}
					if (is_selected) {
						cdl->AddRectFilled(row_min, row_max,
							aida::ui::with_alpha(th.selection, 1.f));
						cdl->AddRectFilled(
							ImVec2(row_min.x, row_min.y),
							ImVec2(row_min.x + 3.f, row_max.y),
							th.accent_u32);
					}
					else if (hovered) {
						cdl->AddRectFilled(row_min, row_max,
							aida::ui::with_alpha(th.hover_wash, 1.f));
					}

					float icon_cx = row_min.x + 11.f;
					float icon_cy = row_min.y + row_h * 0.5f;
					if (e.synthetic_name) {
						ImVec2 q0 = ImVec2(icon_cx, icon_cy - 5.f);
						ImVec2 q1 = ImVec2(icon_cx + 5.f, icon_cy);
						ImVec2 q2 = ImVec2(icon_cx, icon_cy + 5.f);
						ImVec2 q3 = ImVec2(icon_cx - 5.f, icon_cy);
						cdl->AddQuad(q0, q1, q2, q3, th.text_dim, 1.f);
					}
					else if (e.section == ".text") {
						cdl->AddCircleFilled(ImVec2(icon_cx, icon_cy), 5.f,
							th.accent_dim, 16);
					}
					else {
						ImVec2 ra = ImVec2(icon_cx - 5.f, icon_cy - 4.f);
						ImVec2 rb = ImVec2(icon_cx + 5.f, icon_cy + 4.f);
						cdl->AddRect(ra, rb, th.text_secondary, 0.f, 0, 1.f);
					}

					const float text_x = row_min.x + 22.f;
					const float name_fs = fs_fp_base * 0.92f;
					const float line1_y = row_min.y + 4.f;
					const float line2_y = row_min.y + name_fs + 8.f;
					const float text_w_avail = content_size.x - 22.f - 6.f;

					ImU32 name_col = e.synthetic_name ? th.text_dim : th.text_primary;
					std::string name_disp = e.name;
					float name_w = code_font->CalcTextSizeA(name_fs, FLT_MAX, 0.f, name_disp.c_str()).x;
					if (name_w > text_w_avail && name_disp.size() > 3) {
						std::string trimmed = name_disp;
						while (trimmed.size() > 1) {
							trimmed.pop_back();
							std::string probe = trimmed + "..";
							float pw = code_font->CalcTextSizeA(name_fs, FLT_MAX, 0.f, probe.c_str()).x;
							if (pw <= text_w_avail) {
								name_disp = probe;
								break;
							}
						}
					}
					cdl->AddText(code_font, name_fs,
						ImVec2(text_x, line1_y), name_col, name_disp.c_str());

					char addr_buf[32];
					std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
						static_cast<unsigned long long>(e.address));
					const float meta_fs = fs_fp_base * 0.82f;
					ImVec2 addr_size = code_font->CalcTextSizeA(meta_fs, FLT_MAX, 0.f, addr_buf);
					float cursor_x = text_x;
					cdl->AddText(code_font, meta_fs,
						ImVec2(cursor_x, line2_y), th.text_address, addr_buf);
					cursor_x += addr_size.x + 5.f;

					ImVec2 dot_size = code_font->CalcTextSizeA(meta_fs, FLT_MAX, 0.f, "\xc2\xb7");
					cdl->AddText(code_font, meta_fs,
						ImVec2(cursor_x, line2_y), th.text_dim, "\xc2\xb7");
					cursor_x += dot_size.x + 5.f;

					const char* sec_txt = e.section.empty() ? "\xe2\x80\x94" : e.section.c_str();
					ImVec2 sec_size = code_font->CalcTextSizeA(meta_fs, FLT_MAX, 0.f, sec_txt);
					cdl->AddText(code_font, meta_fs,
						ImVec2(cursor_x, line2_y), th.text_secondary, sec_txt);
					cursor_x += sec_size.x + 5.f;

					cdl->AddText(code_font, meta_fs,
						ImVec2(cursor_x, line2_y), th.text_dim, "\xc2\xb7");
					cursor_x += dot_size.x + 5.f;

					char size_buf[24];
					if (e.size == 0) {
						std::snprintf(size_buf, sizeof(size_buf), "-");
					}
					else if (e.size < 1024) {
						std::snprintf(size_buf, sizeof(size_buf), "%uB", e.size);
					}
					else {
						std::snprintf(size_buf, sizeof(size_buf), "%.1fK",
							static_cast<double>(e.size) / 1024.0);
					}
					ImVec2 size_text_size = code_font->CalcTextSizeA(meta_fs, FLT_MAX, 0.f, size_buf);
					cdl->AddText(code_font, meta_fs,
						ImVec2(cursor_x, line2_y), th.text_secondary, size_buf);
					cursor_x += size_text_size.x + 5.f;

					cdl->AddText(code_font, meta_fs,
						ImVec2(cursor_x, line2_y), th.text_dim, "\xc2\xb7");
					cursor_x += dot_size.x + 5.f;

					char calls_buf[32];
					std::snprintf(calls_buf, sizeof(calls_buf), "%u/%u",
						e.calls_in, e.calls_out);
					cdl->AddText(code_font, meta_fs,
						ImVec2(cursor_x, line2_y), th.text_dim, calls_buf);

					if (clicked) {
						s.selected_row = row_idx;
						s.selected_addr = e.address;
						detail::select_function(e.address);
					}
					if (dbl_clicked) {
						detail::jump_to_disasm(e.address);
					}
					if (right_clicked) {
						s.ctx_row = row_idx;
						s.ctx_addr = e.address;
						s.selected_row = row_idx;
						s.selected_addr = e.address;
						ctx_menu_request = true;
					}

					ImGui::PopID();
				}
			}
			clipper.End();

			ImGui::EndChild();
		}
		else if (ImGui::BeginTable("##fn_table", 5, tflags, outer)) {
			ImGui::TableSetupScrollFreeze(0, 1);
			ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 132.f);
			ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 1.0f);
			ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 76.f);
			ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 88.f);
			ImGui::TableSetupColumn("Calls", ImGuiTableColumnFlags_WidthFixed, 72.f);

			ImGui::PushFont(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : body_font);
			ImGui::TableHeadersRow();
			ImGui::PopFont();

			if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs()) {
				if (sort_specs->SpecsDirty && sort_specs->SpecsCount > 0) {
					int col = sort_specs->Specs[0].ColumnIndex;
					bool asc = sort_specs->Specs[0].SortDirection == ImGuiSortDirection_Ascending;
					if (col != s.sort_column || asc != s.sort_ascending) {
						{
							std::lock_guard<std::mutex> lock(s.mtx);
							s.sort_column = col;
							s.sort_ascending = asc;
							s.sort_dirty = true;
						}
						detail::apply_sort(s);
						std::lock_guard<std::mutex> lock(s.mtx);
						row_view = s.presentation;
						shown_count = row_view ? row_view->sorted_indices.size() : 0;
					}
					sort_specs->SpecsDirty = false;
				}
			}

			ImGuiListClipper clipper;
			clipper.Begin(row_view ? static_cast<int>(row_view->sorted_indices.size()) : 0,
				20.f);
			while (clipper.Step()) {
				for (int row_idx = clipper.DisplayStart; row_idx < clipper.DisplayEnd; ++row_idx) {
					const int entry_idx = row_view->sorted_indices[static_cast<std::size_t>(row_idx)];
					if (!row_view->entries || entry_idx < 0 ||
						entry_idx >= static_cast<int>(row_view->entries->size()))
						continue;
					const auto& e = (*row_view->entries)[static_cast<std::size_t>(entry_idx)];

					ImGui::TableNextRow(0, 20.f);
					ImGui::TableSetColumnIndex(0);

					bool is_selected = (s.selected_addr != 0 && s.selected_addr == e.address);

					ImGui::PushID(row_idx);
					char sel_label[32];
					std::snprintf(sel_label, sizeof(sel_label), "##fn_sel_%d", row_idx);

					if (ImGui::Selectable(sel_label, is_selected,
						ImGuiSelectableFlags_SpanAllColumns |
						ImGuiSelectableFlags_AllowDoubleClick |
						ImGuiSelectableFlags_AllowItemOverlap,
						ImVec2(0.f, 18.f)))
					{
						s.selected_row = row_idx;
						s.selected_addr = e.address;
						detail::select_function(e.address);
						if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
							detail::jump_to_disasm(e.address);
						}
					}

					if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
						s.ctx_row = row_idx;
						s.ctx_addr = e.address;
						s.selected_row = row_idx;
						s.selected_addr = e.address;
						ctx_menu_request = true;
					}

					if (is_selected) {
						ImVec2 row_min = ImGui::GetItemRectMin();
						ImVec2 row_max = ImGui::GetItemRectMax();
						ImDrawList* tdl = ImGui::GetWindowDrawList();
						tdl->AddRectFilled(
							ImVec2(row_min.x - 1.f, row_min.y),
							ImVec2(row_min.x + 2.f, row_max.y),
							th.accent_u32);
					}

					ImGui::PopID();

					ImGui::SameLine();
					ImGui::PushFont(code_font);
					char addr_str[32];
					std::snprintf(addr_str, sizeof(addr_str), "0x%llX",
						static_cast<unsigned long long>(e.address));
					ImGui::PushStyleColor(ImGuiCol_Text,
						ImGui::ColorConvertU32ToFloat4(th.text_address));
					ImGui::TextUnformatted(addr_str);
					ImGui::PopStyleColor();
					ImGui::PopFont();

					ImGui::TableSetColumnIndex(1);
					ImGui::PushFont(code_font);
					ImU32 name_col = e.synthetic_name ? th.text_dim : th.text_primary;
					ImGui::PushStyleColor(ImGuiCol_Text,
						ImGui::ColorConvertU32ToFloat4(name_col));
					ImGui::TextUnformatted(e.name.c_str());
					ImGui::PopStyleColor();
					ImGui::PopFont();
					if (ImGui::IsItemHovered()) {
						ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.f, 6.f));
						if (ImGui::BeginTooltip()) {
							ImGui::PushFont(code_font);
							ImGui::TextUnformatted(e.name.c_str());
							ImGui::PopFont();
							ImGui::EndTooltip();
						}
						ImGui::PopStyleVar();
					}

					ImGui::TableSetColumnIndex(2);
					ImGui::PushFont(code_font);
					if (e.size > 0) {
						char size_buf[24];
						if (e.size >= 1024) {
							std::snprintf(size_buf, sizeof(size_buf), "%u (%.1fK)",
								e.size, static_cast<double>(e.size) / 1024.0);
						}
						else {
							std::snprintf(size_buf, sizeof(size_buf), "%u", e.size);
						}
						ImGui::PushStyleColor(ImGuiCol_Text,
							ImGui::ColorConvertU32ToFloat4(th.text_secondary));
						ImGui::TextUnformatted(size_buf);
						ImGui::PopStyleColor();
					}
					else {
						ImGui::PushStyleColor(ImGuiCol_Text,
							ImGui::ColorConvertU32ToFloat4(th.text_dim));
						ImGui::TextUnformatted("-");
						ImGui::PopStyleColor();
					}
					ImGui::PopFont();

					ImGui::TableSetColumnIndex(3);
					if (e.section.empty()) {
						ImGui::PushStyleColor(ImGuiCol_Text,
							ImGui::ColorConvertU32ToFloat4(th.text_dim));
						ImGui::TextUnformatted("-");
						ImGui::PopStyleColor();
					}
					else {
						ImGui::PushFont(code_font);
						ImGui::PushStyleColor(ImGuiCol_Text,
							ImGui::ColorConvertU32ToFloat4(th.text_secondary));
						ImGui::TextUnformatted(e.section.c_str());
						ImGui::PopStyleColor();
						ImGui::PopFont();
					}

					ImGui::TableSetColumnIndex(4);
					ImGui::PushFont(code_font);
					char calls_buf[32];
					std::snprintf(calls_buf, sizeof(calls_buf), "%u/%u",
						e.calls_in, e.calls_out);
					ImGui::PushStyleColor(ImGuiCol_Text,
						ImGui::ColorConvertU32ToFloat4(th.text_dim));
					ImGui::TextUnformatted(calls_buf);
					ImGui::PopStyleColor();
					ImGui::PopFont();
				}
			}
			clipper.End();

			ImGui::EndTable();
		}

		ImGui::PopStyleColor(5);
		ImGui::PopStyleVar();

		function_entry_t selected_entry;
		bool have_selected_entry = false;
		if (s.selected_addr != 0 && row_view && row_view->entries) {
			const auto selected = row_view->row_by_address.find(s.selected_addr);
			if (selected != row_view->row_by_address.end() &&
				selected->second < row_view->sorted_indices.size()) {
				const int source = row_view->sorted_indices[selected->second];
				if (source >= 0 && source < static_cast<int>(row_view->entries->size())) {
					selected_entry = (*row_view->entries)[static_cast<std::size_t>(source)];
					have_selected_entry = true;
				}
			}
		}

		const bool accepts_shortcuts = have_selected_entry &&
			ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
			!ImGui::IsAnyItemActive() && !ImGui::GetIO().WantTextInput;
		if (accepts_shortcuts) {
			int navigation_delta = 0;
			if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, false)) navigation_delta = -1;
			if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, false)) navigation_delta = 1;
			if (ImGui::IsKeyPressed(ImGuiKey_PageUp, false)) navigation_delta = -10;
			if (ImGui::IsKeyPressed(ImGuiKey_PageDown, false)) navigation_delta = 10;
			if (navigation_delta != 0 || ImGui::IsKeyPressed(ImGuiKey_Home, false) ||
				ImGui::IsKeyPressed(ImGuiKey_End, false)) {
				uint64_t next_address = 0;
				int next_row = s.selected_row;
				if (row_view && row_view->entries && !row_view->sorted_indices.empty()) {
					const auto current = row_view->row_by_address.find(s.selected_addr);
					std::ptrdiff_t position = current == row_view->row_by_address.end() ? 0 :
						static_cast<std::ptrdiff_t>(current->second);
					if (ImGui::IsKeyPressed(ImGuiKey_Home, false)) position = 0;
					else if (ImGui::IsKeyPressed(ImGuiKey_End, false))
						position = static_cast<std::ptrdiff_t>(row_view->sorted_indices.size() - 1);
					else position = (std::max<std::ptrdiff_t>)(0,
						(std::min<std::ptrdiff_t>)(static_cast<std::ptrdiff_t>(row_view->sorted_indices.size() - 1),
							position + navigation_delta));
					next_row = static_cast<int>(position);
					const int source = row_view->sorted_indices[static_cast<std::size_t>(position)];
					if (source >= 0 && source < static_cast<int>(row_view->entries->size()))
						next_address = (*row_view->entries)[static_cast<std::size_t>(source)].address;
				}
				if (next_address != 0) {
					s.selected_row = next_row;
					s.selected_addr = next_address;
					detail::select_function(next_address);
				}
			}
			if (ImGui::GetIO().KeyCtrl && (ImGui::IsKeyPressed(ImGuiKey_C, false) ||
				ImGui::IsKeyPressed(ImGuiKey_Insert, false)))
				ImGui::SetClipboardText(selected_entry.name.c_str());
		}

		aida::ui::context_menu_open_origin_t function_origin{};
		const bool function_keyboard = s.selected_addr != 0 &&
			ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
			aida::ui::analysis_context_menu::keyboard_request(function_origin);
		if (ctx_menu_request || function_keyboard) {
			using namespace aida::ui::analysis_context_menu;
			using aida::ui::action_handler_result_t;
			const auto target = ctx_menu_request ? s.ctx_addr : s.selected_addr;
			auto workspace = render_workspace();
			if (workspace) {
				context_t menu;
				menu.kind = menu_kind_t::function;
				menu.entity_id = "function:" + std::to_string(target);
				const auto generation = workspace->generation();
				const auto revision = workspace->analysis_revision();
				menu.generation = generation ^ (revision + 0x9E3779B97F4A7C15ull +
					(generation << 6u) + (generation >> 2u));
				menu.live_generation = [workspace]() {
					const auto current = workspace->generation();
					const auto current_revision = workspace->analysis_revision();
					return current ^ (current_revision + 0x9E3779B97F4A7C15ull +
						(current << 6u) + (current >> 2u));
				};
				menu.validate_identity = [&s, target]() {
					std::lock_guard<std::mutex> lock(s.mtx);
					return s.selected_addr == target
						? aida::ui::capability_state_t::available()
						: aida::ui::capability_state_t::unavailable(
							"The selected function changed");
				};
				menu.actions["analysis.navigate.disassembly"].invoke = [target]() {
					detail::jump_to_disasm(target);
					return action_handler_result_t::completed();
				};
				menu.actions["analysis.navigate.graph"].invoke = [target]() {
					detail::open_in_graph(target);
					return action_handler_result_t::completed();
				};
				menu.actions["analysis.navigate.pseudocode"].invoke = [target]() {
					detail::open_in_pseudocode(target);
					return action_handler_result_t::completed();
				};
				menu.actions["analysis.navigate.hex"].invoke = [target]() {
					detail::open_in_view(target, "document.hex");
					return action_handler_result_t::completed();
				};
				menu.actions["analysis.navigate.types"].invoke = [target]() {
					detail::open_in_view(target, "view.types.inferred");
					return action_handler_result_t::completed();
				};
				menu.actions["analysis.navigate.structures"].invoke = [target]() {
					detail::open_in_view(target, "view.types.structures");
					return action_handler_result_t::completed();
				};
				menu.actions["analysis.navigate.xrefs"].invoke = [target]() {
					detail::show_xrefs_to(target);
					return action_handler_result_t::completed();
				};
				menu.actions["analysis.navigate.xrefs_from"].invoke = [target]() {
					detail::show_xrefs_direction(target, false);
					return action_handler_result_t::completed();
				};
				menu.actions["analysis.navigate.callers"].invoke = [target]() {
					detail::show_xrefs_direction(target, true);
					return action_handler_result_t::completed();
				};
				menu.actions["analysis.navigate.callees"].invoke = [target]() {
					detail::show_xrefs_direction(target, false);
					return action_handler_result_t::completed();
				};
				menu.actions["analysis.modify.rename"].invoke = [target]() {
					detail::rename_function(target);
					return action_handler_result_t::completed();
				};
				menu.actions["analysis.modify.comment"].invoke = [target]() {
					detail::comment_function(target);
					return action_handler_result_t::completed();
				};
				char address[32]{};
				std::snprintf(address, sizeof(address), "0x%llX",
					static_cast<unsigned long long>(target));
				menu.actions["analysis.copy.address"].invoke = [value = std::string(address)]() {
					ImGui::SetClipboardText(value.c_str());
					return action_handler_result_t::completed();
				};
				menu.actions["analysis.copy.address_va"].invoke = [value = std::string(address)]() {
					ImGui::SetClipboardText(value.c_str());
					return action_handler_result_t::completed();
				};
				if (have_selected_entry) {
					menu.actions["analysis.copy.name"].invoke = [value = selected_entry.name]() {
						ImGui::SetClipboardText(value.c_str());
						return action_handler_result_t::completed();
					};
					menu.actions["analysis.copy.text"].invoke = [value = selected_entry.name]() {
						ImGui::SetClipboardText(value.c_str());
						return action_handler_result_t::completed();
					};
					menu.actions["analysis.copy.line"].invoke = [value = std::string(address) + "\t" + selected_entry.name]() {
						ImGui::SetClipboardText(value.c_str());
						return action_handler_result_t::completed();
					};
				}
				open(std::move(menu), ctx_menu_request
					? aida::ui::context_menu_open_origin_t::pointer : function_origin);
			}
		}

		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6.f, 6.f));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 4.f));
		ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.f, 4.f));
		ImGui::PushStyleColor(ImGuiCol_PopupBg, th.bg_overlay);
		ImGui::PushStyleColor(ImGuiCol_Border, th.border_subtle);
		ImGui::PopStyleColor(2);
		ImGui::PopStyleVar(3);
		aida::ui::analysis_context_menu::render();
		rename_dialog::render();
		comment_dialog::render();

		if (ready && !building && total_count == 0) {
			ImVec2 cp = ImVec2(wp.x + pad, wp.y + header_h + 8.f);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
			cfg.title = "No analyzed functions yet";
			cfg.body = "Open a binary or attach to a running process to populate the symbol list.";
			cfg.max_width = std::min(content_size.x - 32.f, 360.f);
			aida::ui::empty_state::render(cp, content_size, cfg);
		}
		else if (ready && shown_count == 0 && total_count > 0) {
			ImVec2 cp = ImVec2(wp.x + pad, wp.y + header_h + 8.f);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::search;
			cfg.title = "No matches";
			cfg.body = "Nothing matches the current filter. Try a shorter query.";
			cfg.max_width = std::min(content_size.x - 32.f, 360.f);
			aida::ui::empty_state::render(cp, content_size, cfg);
		}

		ImGui::PopFont();

		ImGui::EndChild();
		ImGui::PopStyleColor();
		ImGui::PopStyleVar(2);
	}

	inline void render(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		float x, float y, float w, float h)
	{
		auto& slot = render_workspace();
		auto previous = slot;
		slot = workspace;
		struct restore_t {
			std::shared_ptr<aida::analysis::analysis_workspace_t>& slot;
			std::shared_ptr<aida::analysis::analysis_workspace_t> previous;
			~restore_t() { slot = std::move(previous); }
		} restore{slot, std::move(previous)};
		detail::refresh_from_workspace(workspace);
		render_impl(x, y, w, h);
	}

	inline void render(float x, float y, float w, float h)
	{
		render(aida::analysis::workspace_registry().selected_for_ui(), x, y, w, h);
	}

}
