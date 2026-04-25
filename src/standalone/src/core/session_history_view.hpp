#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "event_bus.hpp"
#include "session_store.hpp"
#include "standalone_chat.hpp"
#include "standalone_driver.hpp"


namespace aida::session_history {


	namespace detail {

		struct row_t
		{
			std::string id;
			std::string parent_id;
			std::string title;
			std::string agent;
			int64_t     time_updated_unix = 0;
			int64_t     time_archived_unix = 0;
			double      total_cost_usd = 0.0;
			int64_t     in_tokens = 0;
			int64_t     out_tokens = 0;
			int64_t     cache_read = 0;
			int64_t     cache_write = 0;
			int         depth = 0;
			bool        has_compaction = false;
			std::vector<std::pair<std::string, double>> last_msg_costs;
		};

		struct ctx_target_t
		{
			std::string id;
			std::string title;
			bool        archived = false;
		};

		struct state_t
		{
			std::mutex                                   mtx;
			std::string                                  last_error;

			char                                         search_buf[128] = {};
			bool                                         show_archived = false;
			bool                                         expanded = true;

			std::string                                  active_session_id;
			std::string                                  selected_id;
			std::string                                  rename_target_id;
			char                                         rename_buf[256] = {};

			std::vector<row_t>                           rows;
			std::vector<size_t>                          visible_indices;
			std::unordered_map<std::string, std::vector<size_t>> children_index;
			std::unordered_set<std::string>              collapsed_parents;
			std::unordered_set<std::string>              compacted_cache;
			std::atomic<bool>                            compacted_dirty{true};

			std::atomic<int64_t>                         next_refresh_unix_ms{0};
			std::atomic<bool>                            initialized{false};

			ctx_target_t                                 ctx;
			bool                                         open_ctx_menu = false;
			bool                                         open_rename_popup = false;
			bool                                         open_delete_popup = false;
			bool                                         open_archive_popup = false;
			std::string                                  pending_archive_id;
			std::string                                  pending_delete_id;

			double                                       total_visible_cost = 0.0;
			double                                       total_all_cost = 0.0;

			aida::events::subscription_handle_t          sub_compacted;
			aida::events::subscription_handle_t          sub_binary_loaded;
		};

		inline state_t& g_state()
		{
			static state_t s;
			return s;
		}

		inline void set_last_error_locked(state_t& st, const std::string& msg)
		{
			st.last_error = msg;
		}

		inline std::string trim_copy(const std::string& s)
		{
			size_t a = 0;
			while (a < s.size() && (unsigned char)s[a] <= 0x20) ++a;
			size_t b = s.size();
			while (b > a && (unsigned char)s[b - 1] <= 0x20) --b;
			return s.substr(a, b - a);
		}

		inline bool icontains(const std::string& haystack, const std::string& needle)
		{
			if (needle.empty()) return true;
			if (haystack.size() < needle.size()) return false;
			std::string h = haystack;
			std::string n = needle;
			for (auto& c : h) c = (char)tolower((unsigned char)c);
			for (auto& c : n) c = (char)tolower((unsigned char)c);
			return h.find(n) != std::string::npos;
		}

		inline std::string current_binary_path()
		{
			std::string p = standalone_driver::attached_process_name();
			if (!p.empty()) return p;
			return std::string();
		}

		inline std::string format_cost_str(double usd)
		{
			char buf[32];
			if (usd < 0.001) {
				return std::string("<$0.001");
			} else if (usd < 1.0) {
				snprintf(buf, sizeof(buf), "$%.4f", usd);
			} else if (usd < 100.0) {
				snprintf(buf, sizeof(buf), "$%.2f", usd);
			} else {
				snprintf(buf, sizeof(buf), "$%.0f", usd);
			}
			return std::string(buf);
		}

		inline std::string format_relative_time_str(int64_t unix_ms)
		{
			if (unix_ms <= 0) return std::string("never");
			const int64_t now_ms = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::system_clock::now().time_since_epoch()).count();
			int64_t delta_s = (now_ms - unix_ms) / 1000;
			if (delta_s < 0) delta_s = 0;
			char buf[64];
			if (delta_s < 60) {
				snprintf(buf, sizeof(buf), "%llds ago", (long long)delta_s);
			} else if (delta_s < 3600) {
				snprintf(buf, sizeof(buf), "%lldm ago", (long long)(delta_s / 60));
			} else if (delta_s < 86400) {
				snprintf(buf, sizeof(buf), "%lldh ago", (long long)(delta_s / 3600));
			} else if (delta_s < 86400 * 7) {
				snprintf(buf, sizeof(buf), "%lldd ago", (long long)(delta_s / 86400));
			} else {
				time_t t = (time_t)(unix_ms / 1000);
				struct tm tmv;
				localtime_s(&tmv, &t);
				strftime(buf, sizeof(buf), "%Y-%m-%d", &tmv);
			}
			return std::string(buf);
		}

		inline bool detect_compaction(const std::string& session_id)
		{
			std::vector<aida::session::message_t> msgs;
			if (!aida::session::list_messages(session_id, msgs, -1)) return false;
			for (const auto& m : msgs) {
				for (const auto& p : m.parts) {
					if (p.kind == aida::session::part_t::kind_t::compaction) return true;
				}
			}
			return false;
		}

		inline void compute_last_costs(const std::string& session_id,
			std::vector<std::pair<std::string, double>>& out)
		{
			std::vector<aida::session::message_t> msgs;
			if (!aida::session::list_messages(session_id, msgs, -1)) return;
			std::vector<std::pair<std::string, double>> per_msg;
			per_msg.reserve(msgs.size());
			for (const auto& m : msgs) {
				double cost_sum = 0.0;
				for (const auto& p : m.parts) {
					if (p.kind == aida::session::part_t::kind_t::step_finish) {
						cost_sum += p.step_finish.cost_usd;
					}
				}
				if (cost_sum > 0.0) {
					std::string label;
					switch (m.role) {
						case aida::session::message_t::role_t::user:        label = "user"; break;
						case aida::session::message_t::role_t::assistant:   label = "assistant"; break;
						case aida::session::message_t::role_t::tool_result: label = "tool"; break;
					}
					per_msg.emplace_back(label, cost_sum);
				}
			}
			const size_t n = per_msg.size();
			const size_t take = (n > 5) ? 5 : n;
			out.assign(per_msg.end() - (long)take, per_msg.end());
		}

		inline void rebuild_visible_locked(state_t& st)
		{
			st.visible_indices.clear();
			st.children_index.clear();
			std::string filter = st.search_buf;
			std::vector<size_t> roots;
			for (size_t i = 0; i < st.rows.size(); ++i) {
				const auto& r = st.rows[i];
				if (r.parent_id.empty()) roots.push_back(i);
				else st.children_index[r.parent_id].push_back(i);
			}
			std::sort(roots.begin(), roots.end(), [&](size_t a, size_t b) {
				return st.rows[a].time_updated_unix > st.rows[b].time_updated_unix;
			});
			std::function<bool(size_t)> any_match = [&](size_t i) -> bool {
				const auto& r = st.rows[i];
				if (filter.empty() || icontains(r.title, filter) || icontains(r.id, filter)) return true;
				auto it = st.children_index.find(r.id);
				if (it != st.children_index.end()) {
					for (size_t cidx : it->second) {
						if (any_match(cidx)) return true;
					}
				}
				return false;
			};
			std::function<void(size_t, int)> push_subtree = [&](size_t idx, int depth) {
				st.rows[idx].depth = depth;
				if (!st.show_archived && st.rows[idx].time_archived_unix > 0) return;
				if (!any_match(idx)) return;
				st.visible_indices.push_back(idx);
				if (st.collapsed_parents.count(st.rows[idx].id) == 0) {
					auto it = st.children_index.find(st.rows[idx].id);
					if (it != st.children_index.end()) {
						auto sorted_children = it->second;
						std::sort(sorted_children.begin(), sorted_children.end(),
							[&](size_t a, size_t b) {
								return st.rows[a].time_updated_unix > st.rows[b].time_updated_unix;
							});
						for (size_t cidx : sorted_children) {
							push_subtree(cidx, depth + 1);
						}
					}
				}
			};
			for (size_t r : roots) push_subtree(r, 0);
			st.total_visible_cost = 0.0;
			for (size_t idx : st.visible_indices) {
				st.total_visible_cost += st.rows[idx].total_cost_usd;
			}
		}

		inline void refresh_locked(state_t& st)
		{
			std::vector<aida::session::session_info_t> infos;
			std::string bp = current_binary_path();
			bool ok = false;
			if (!bp.empty()) {
				ok = aida::session::list(bp, infos);
			} else {
				ok = aida::session::list_all(infos);
			}
			if (!ok) {
				set_last_error_locked(st, aida::session::last_error());
				return;
			}
			st.rows.clear();
			st.rows.reserve(infos.size());
			st.total_all_cost = 0.0;
			for (const auto& info : infos) {
				row_t r;
				r.id                  = info.id;
				r.parent_id           = info.parent_id;
				r.title               = info.title.empty() ? std::string("Untitled session") : info.title;
				r.time_updated_unix   = info.time_updated_unix;
				r.time_archived_unix  = info.time_archived_unix;
				r.total_cost_usd      = info.total_cost_usd > 0.0 ? info.total_cost_usd : aida::session::session_cost(info.id);
				const auto tk         = aida::session::session_tokens(info.id);
				r.in_tokens           = tk.input;
				r.out_tokens          = tk.output;
				r.cache_read          = tk.cache_read;
				r.cache_write         = tk.cache_write;
				r.has_compaction      = st.compacted_cache.count(info.id) > 0;
				st.total_all_cost     += r.total_cost_usd;
				st.rows.push_back(std::move(r));
			}
			rebuild_visible_locked(st);
		}

		inline void maybe_refresh()
		{
			state_t& st = g_state();
			const int64_t now_ms = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::system_clock::now().time_since_epoch()).count();
			if (now_ms < st.next_refresh_unix_ms.load()) return;
			st.next_refresh_unix_ms.store(now_ms + 1500);
			std::lock_guard<std::mutex> lk(st.mtx);
			refresh_locked(st);
		}

		inline void force_refresh()
		{
			state_t& st = g_state();
			st.next_refresh_unix_ms.store(0);
			std::lock_guard<std::mutex> lk(st.mtx);
			refresh_locked(st);
		}

		inline void on_session_compacted(const aida::events::session_compacted_t& ev)
		{
			state_t& st = g_state();
			std::lock_guard<std::mutex> lk(st.mtx);
			st.compacted_cache.insert(ev.session_id);
			for (auto& r : st.rows) {
				if (r.id == ev.session_id) r.has_compaction = true;
			}
		}

		inline void on_binary_loaded(const aida::events::binary_loaded_t&)
		{
			state_t& st = g_state();
			st.next_refresh_unix_ms.store(0);
		}

		inline void open_session(const std::string& session_id)
		{
			if (session_id.empty()) return;
			chat_bind_session(session_id);
			aida::events::session_selected_t ev;
			ev.session_id = session_id;
			aida::events::publish(aida::events::event_session_selected, ev);
			state_t& st = g_state();
			std::lock_guard<std::mutex> lk(st.mtx);
			st.active_session_id = session_id;
			st.selected_id = session_id;
		}

		inline void create_new_session()
		{
			std::string bp = current_binary_path();
			std::string project_id;
			aida::session::session_info_t out_info;
			if (!aida::session::create(out_info, project_id, bp, std::string())) {
				state_t& st = g_state();
				std::lock_guard<std::mutex> lk(st.mtx);
				set_last_error_locked(st, aida::session::last_error());
				return;
			}
			open_session(out_info.id);
			force_refresh();
		}

		inline void fork_session(const std::string& session_id)
		{
			if (session_id.empty()) return;
			aida::session::session_info_t out_new;
			if (!aida::session::fork(session_id, std::string(), out_new)) {
				state_t& st = g_state();
				std::lock_guard<std::mutex> lk(st.mtx);
				set_last_error_locked(st, aida::session::last_error());
				return;
			}
			open_session(out_new.id);
			force_refresh();
		}

		inline void toggle_archive_session(const std::string& session_id, bool currently_archived)
		{
			if (session_id.empty()) return;
			int64_t ts = currently_archived ? 0 : (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::system_clock::now().time_since_epoch()).count();
			if (!aida::session::set_archived(session_id, ts)) {
				state_t& st = g_state();
				std::lock_guard<std::mutex> lk(st.mtx);
				set_last_error_locked(st, aida::session::last_error());
				return;
			}
			force_refresh();
		}

		inline void delete_session(const std::string& session_id)
		{
			if (session_id.empty()) return;
			if (!aida::session::remove(session_id)) {
				state_t& st = g_state();
				std::lock_guard<std::mutex> lk(st.mtx);
				set_last_error_locked(st, aida::session::last_error());
				return;
			}
			state_t& st = g_state();
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				if (st.active_session_id == session_id) st.active_session_id.clear();
				if (st.selected_id == session_id) st.selected_id.clear();
			}
			force_refresh();
		}

		inline void rename_session(const std::string& session_id, const std::string& new_title)
		{
			if (session_id.empty()) return;
			std::string trimmed = trim_copy(new_title);
			if (trimmed.empty()) return;
			if (!aida::session::set_title(session_id, trimmed)) {
				state_t& st = g_state();
				std::lock_guard<std::mutex> lk(st.mtx);
				set_last_error_locked(st, aida::session::last_error());
				return;
			}
			force_refresh();
		}

		inline int find_visible_idx_for_id(const state_t& st, const std::string& id)
		{
			for (int i = 0; i < (int)st.visible_indices.size(); ++i) {
				if (st.rows[st.visible_indices[i]].id == id) return i;
			}
			return -1;
		}

		inline void move_selection(int delta)
		{
			state_t& st = g_state();
			std::lock_guard<std::mutex> lk(st.mtx);
			if (st.visible_indices.empty()) return;
			int cur = find_visible_idx_for_id(st, st.selected_id);
			if (cur < 0) cur = 0;
			else cur = std::clamp(cur + delta, 0, (int)st.visible_indices.size() - 1);
			st.selected_id = st.rows[st.visible_indices[cur]].id;
		}

		inline void handle_keyboard()
		{
			ImGuiIO& io = ImGui::GetIO();
			if (io.WantTextInput) return;
			if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, true)) move_selection(+1);
			if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, true)) move_selection(-1);
			if (ImGui::IsKeyPressed(ImGuiKey_Enter, false)) {
				state_t& st = g_state();
				std::string sid;
				{ std::lock_guard<std::mutex> lk(st.mtx); sid = st.selected_id; }
				if (!sid.empty()) open_session(sid);
			}
			if (ImGui::IsKeyPressed(ImGuiKey_Delete, false)) {
				state_t& st = g_state();
				std::string sid;
				bool was_archived = false;
				{
					std::lock_guard<std::mutex> lk(st.mtx);
					sid = st.selected_id;
					for (const auto& r : st.rows) {
						if (r.id == sid) { was_archived = r.time_archived_unix > 0; break; }
					}
				}
				if (sid.empty()) return;
				if (io.KeyShift) {
					st.pending_delete_id = sid;
					st.open_delete_popup = true;
				} else {
					toggle_archive_session(sid, was_archived);
				}
			}
			if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_N, false)) {
				create_new_session();
			}
		}

	}


	inline void initialize()
	{
		auto& st = detail::g_state();
		bool expected = false;
		if (!st.initialized.compare_exchange_strong(expected, true)) return;

		if (st.sub_compacted.valid()) aida::events::unsubscribe(st.sub_compacted);
		if (st.sub_binary_loaded.valid()) aida::events::unsubscribe(st.sub_binary_loaded);

		st.sub_compacted = aida::events::subscribe(
			aida::events::event_session_compacted,
			std::function<void(const aida::events::session_compacted_t&)>(&detail::on_session_compacted));

		st.sub_binary_loaded = aida::events::subscribe(
			aida::events::event_binary_loaded,
			std::function<void(const aida::events::binary_loaded_t&)>(&detail::on_binary_loaded));

		st.next_refresh_unix_ms.store(0);
	}


	inline void shutdown()
	{
		auto& st = detail::g_state();
		bool expected = true;
		if (!st.initialized.compare_exchange_strong(expected, false)) return;
		if (st.sub_compacted.valid()) {
			aida::events::unsubscribe(st.sub_compacted);
			st.sub_compacted = aida::events::subscription_handle_t{};
		}
		if (st.sub_binary_loaded.valid()) {
			aida::events::unsubscribe(st.sub_binary_loaded);
			st.sub_binary_loaded = aida::events::subscription_handle_t{};
		}
		std::lock_guard<std::mutex> lk(st.mtx);
		st.rows.clear();
		st.visible_indices.clear();
		st.children_index.clear();
		st.collapsed_parents.clear();
		st.compacted_cache.clear();
	}


	inline void on_session_changed(const std::string& session_id)
	{
		auto& st = detail::g_state();
		std::lock_guard<std::mutex> lk(st.mtx);
		st.active_session_id = session_id;
	}


	inline const std::string& last_error()
	{
		return detail::g_state().last_error;
	}


	inline void render(float panel_w, float panel_h)
	{
		using namespace detail;

		if (panel_w < 8.f || panel_h < 8.f) return;

		state_t& st = g_state();
		maybe_refresh();

		ImGui::PushID("##aida_session_history");

		const float toolbar_h = 28.f;
		const float footer_h  = 36.f;
		const float row_h     = 22.f;

		const ImU32 col_text     = IM_COL32(220, 222, 235, 240);
		const ImU32 col_dim      = IM_COL32(150, 150, 170, 200);
		const ImU32 col_faint    = IM_COL32(110, 115, 130, 200);
		const ImU32 col_sel      = IM_COL32(70, 72, 110, 140);
		const ImU32 col_hov      = IM_COL32(255, 255, 255, 18);
		const ImU32 col_active   = IM_COL32(120, 130, 220, 200);
		const ImU32 col_archived = IM_COL32(160, 120, 100, 220);
		const ImU32 col_tree     = IM_COL32(110, 115, 130, 130);

		{
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(4.f, 4.f));
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4.f, 3.f));

			float toolbar_w = panel_w - 8.f;

			ImGui::SetCursorPos(ImVec2(4.f, 4.f));
			ImGui::PushItemWidth(toolbar_w * 0.55f);
			char prev_buf[128];
			std::string prev;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				memcpy(prev_buf, st.search_buf, sizeof(prev_buf));
				prev = st.search_buf;
			}
			char tmp_buf[128];
			memcpy(tmp_buf, prev_buf, sizeof(tmp_buf));
			if (ImGui::InputTextWithHint("##sh_search", "search sessions", tmp_buf, sizeof(tmp_buf))) {
				std::lock_guard<std::mutex> lk(st.mtx);
				memcpy(st.search_buf, tmp_buf, sizeof(st.search_buf));
				rebuild_visible_locked(st);
			}
			ImGui::PopItemWidth();

			ImGui::SameLine(0.f, 4.f);
			if (ImGui::SmallButton("+ New")) create_new_session();
			if (ImGui::IsItemHovered()) ImGui::SetTooltip("New session (Ctrl+N)");

			ImGui::SameLine(0.f, 4.f);
			bool show_arch_local;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				show_arch_local = st.show_archived;
			}
			if (ImGui::Checkbox("Archived", &show_arch_local)) {
				std::lock_guard<std::mutex> lk(st.mtx);
				st.show_archived = show_arch_local;
				rebuild_visible_locked(st);
			}

			ImGui::PopStyleVar(2);
		}

		float body_y = 4.f + toolbar_h;
		float body_h = panel_h - body_y - footer_h;
		if (body_h < 16.f) body_h = 16.f;

		ImGui::SetCursorPos(ImVec2(0.f, body_y));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
		ImGui::BeginChild("##sh_body", ImVec2(panel_w, body_h), false,
			ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_AlwaysVerticalScrollbar);

		bool any_hovered_in_body = ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows);
		if (any_hovered_in_body) detail::handle_keyboard();

		std::vector<size_t> visible_copy;
		std::vector<row_t>  rows_copy;
		std::string         active_id_copy;
		std::string         selected_id_copy;
		std::unordered_set<std::string> collapsed_copy;
		std::unordered_map<std::string, size_t> child_count_for;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			visible_copy   = st.visible_indices;
			rows_copy      = st.rows;
			active_id_copy = st.active_session_id;
			selected_id_copy = st.selected_id;
			collapsed_copy = st.collapsed_parents;
			for (const auto& kv : st.children_index) child_count_for[kv.first] = kv.second.size();
		}

		ImDrawList* dl = ImGui::GetWindowDrawList();

		struct ctx_payload_t {
			bool        request_open = false;
			std::string id;
			std::string title;
			bool        archived = false;
		} ctx_payload;

		if (visible_copy.empty()) {
			ImGui::SetCursorPos(ImVec2(8.f, 12.f));
			ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.7f, 0.9f), "No sessions for this binary.");
		}

		for (size_t vi = 0; vi < visible_copy.size(); ++vi) {
			const auto& r = rows_copy[visible_copy[vi]];
			bool is_active = !r.id.empty() && r.id == active_id_copy;
			bool is_selected = !r.id.empty() && r.id == selected_id_copy;
			bool archived = r.time_archived_unix > 0;

			float indent = 6.f + (float)r.depth * 14.f;
			ImVec2 cp = ImGui::GetCursorScreenPos();
			ImVec2 rmin(cp.x, cp.y);
			ImVec2 rmax(cp.x + panel_w, cp.y + row_h);
			bool hov = ImGui::IsMouseHoveringRect(rmin, rmax, false);

			if (r.depth > 0) {
				float vline_x = cp.x + 6.f + (float)(r.depth - 1) * 14.f + 6.f;
				dl->AddLine(ImVec2(vline_x, cp.y), ImVec2(vline_x, cp.y + row_h), col_tree, 1.f);
				dl->AddLine(ImVec2(vline_x, cp.y + row_h * 0.5f),
					ImVec2(vline_x + 8.f, cp.y + row_h * 0.5f), col_tree, 1.f);
			}

			if (is_selected) dl->AddRectFilled(rmin, rmax, col_sel);
			else if (hov) dl->AddRectFilled(rmin, rmax, col_hov);

			float arrow_x = rmin.x + indent;
			bool has_children = child_count_for.count(r.id) > 0 && child_count_for[r.id] > 0;
			if (has_children) {
				bool collapsed = collapsed_copy.count(r.id) > 0;
				const char* ar = collapsed ? ">" : "v";
				dl->AddText(ImVec2(arrow_x, rmin.y + 3.f), col_dim, ar);
			}
			float title_x = arrow_x + 14.f;

			if (is_active) {
				dl->AddCircleFilled(ImVec2(title_x - 6.f, rmin.y + row_h * 0.5f), 3.f, col_active);
			}

			std::string display_title = r.title;
			if (display_title.empty()) display_title = r.id.substr(0, 8);
			if (r.has_compaction) display_title = std::string("[C] ") + display_title;
			if (archived) display_title = std::string("(archived) ") + display_title;

			ImU32 title_col = archived ? col_archived : col_text;
			dl->AddText(ImVec2(title_x, rmin.y + 3.f), title_col, display_title.c_str());

			std::string time_str = format_relative_time_str(r.time_updated_unix);
			std::string cost_str = format_cost_str(r.total_cost_usd);
			std::string right_str = cost_str + std::string("  ") + time_str;
			ImVec2 rs = ImGui::CalcTextSize(right_str.c_str());
			float right_x = rmax.x - 8.f - rs.x;
			if (right_x < title_x + ImGui::CalcTextSize(display_title.c_str()).x + 12.f) {
				right_x = title_x + ImGui::CalcTextSize(display_title.c_str()).x + 12.f;
				if (right_x > rmax.x - 8.f - rs.x * 0.5f) right_x = rmax.x - 8.f - rs.x;
			}
			dl->AddText(ImVec2(right_x, rmin.y + 3.f), col_faint, right_str.c_str());

			ImGui::SetCursorScreenPos(rmin);
			ImGui::PushID((int)vi);
			ImGui::InvisibleButton("##sh_row", ImVec2(panel_w, row_h));
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool dbl = ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
			bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);

			if (ImGui::IsItemHovered()) {
				ImGui::BeginTooltip();
				ImGui::TextUnformatted(display_title.c_str());
				ImGui::Separator();
				char tk_buf[256];
				snprintf(tk_buf, sizeof(tk_buf),
					"in: %lld   out: %lld\ncache r: %lld   w: %lld\nupdated: %s",
					(long long)r.in_tokens, (long long)r.out_tokens,
					(long long)r.cache_read, (long long)r.cache_write,
					format_relative_time_str(r.time_updated_unix).c_str());
				ImGui::TextUnformatted(tk_buf);
				if (!r.last_msg_costs.empty()) {
					ImGui::Separator();
					ImGui::TextUnformatted("Last messages:");
					for (const auto& mc : r.last_msg_costs) {
						char l[128];
						snprintf(l, sizeof(l), "  %s  %s", mc.first.c_str(),
							format_cost_str(mc.second).c_str());
						ImGui::TextUnformatted(l);
					}
				}
				ImGui::EndTooltip();
				if (r.last_msg_costs.empty()) {
					std::vector<std::pair<std::string, double>> tmp;
					compute_last_costs(r.id, tmp);
					std::lock_guard<std::mutex> lk(st.mtx);
					for (auto& rr : st.rows) {
						if (rr.id == r.id) { rr.last_msg_costs = std::move(tmp); break; }
					}
				}
			}

			if (clicked) {
				std::lock_guard<std::mutex> lk(st.mtx);
				st.selected_id = r.id;
				if (has_children) {
					if (collapsed_copy.count(r.id) > 0) st.collapsed_parents.erase(r.id);
					else if (cp.x + indent + 12.f >= ImGui::GetIO().MousePos.x) st.collapsed_parents.insert(r.id);
					rebuild_visible_locked(st);
				}
			}
			if (dbl) open_session(r.id);
			if (right_clicked) {
				ctx_payload.request_open = true;
				ctx_payload.id           = r.id;
				ctx_payload.title        = r.title;
				ctx_payload.archived     = archived;
			}

			ImGui::PopID();
		}

		ImGui::EndChild();
		ImGui::PopStyleVar();

		if (ctx_payload.request_open) {
			std::lock_guard<std::mutex> lk(st.mtx);
			st.ctx.id = ctx_payload.id;
			st.ctx.title = ctx_payload.title;
			st.ctx.archived = ctx_payload.archived;
			st.selected_id = ctx_payload.id;
			ImGui::OpenPopup("##sh_ctx");
		}

		if (ImGui::BeginPopup("##sh_ctx")) {
			detail::ctx_target_t target;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				target = st.ctx;
			}
			ImGui::TextDisabled("%s", target.title.empty() ? target.id.c_str() : target.title.c_str());
			ImGui::Separator();
			if (ImGui::MenuItem("Open")) open_session(target.id);
			if (ImGui::MenuItem("Fork at last message")) fork_session(target.id);
			if (ImGui::MenuItem("Rename")) {
				std::lock_guard<std::mutex> lk(st.mtx);
				st.rename_target_id = target.id;
				memset(st.rename_buf, 0, sizeof(st.rename_buf));
				size_t cn = (std::min<size_t>)(target.title.size(), sizeof(st.rename_buf) - 1);
				memcpy(st.rename_buf, target.title.data(), cn);
				st.open_rename_popup = true;
			}
			if (ImGui::MenuItem(target.archived ? "Unarchive" : "Archive")) {
				toggle_archive_session(target.id, target.archived);
			}
			ImGui::Separator();
			if (ImGui::MenuItem("Delete...")) {
				std::lock_guard<std::mutex> lk(st.mtx);
				st.pending_delete_id = target.id;
				st.open_delete_popup = true;
			}
			ImGui::EndPopup();
		}

		if (st.open_rename_popup) {
			st.open_rename_popup = false;
			ImGui::OpenPopup("##sh_rename");
		}
		if (ImGui::BeginPopupModal("##sh_rename", nullptr,
			ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
			ImGui::Text("Rename session");
			ImGui::Separator();
			char buf[256];
			std::string id_local;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				memcpy(buf, st.rename_buf, sizeof(buf));
				id_local = st.rename_target_id;
			}
			ImGui::SetNextItemWidth(360.f);
			bool submit = ImGui::InputText("##sh_rename_in", buf, sizeof(buf),
				ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				memcpy(st.rename_buf, buf, sizeof(st.rename_buf));
			}
			if (submit || ImGui::Button("OK", ImVec2(80.f, 0.f))) {
				rename_session(id_local, std::string(buf));
				ImGui::CloseCurrentPopup();
			}
			ImGui::SameLine();
			if (ImGui::Button("Cancel", ImVec2(80.f, 0.f))) ImGui::CloseCurrentPopup();
			ImGui::EndPopup();
		}

		if (st.open_delete_popup) {
			st.open_delete_popup = false;
			ImGui::OpenPopup("##sh_delete");
		}
		if (ImGui::BeginPopupModal("##sh_delete", nullptr,
			ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
			std::string id_local;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				id_local = st.pending_delete_id;
			}
			ImGui::Text("Delete this session permanently?");
			ImGui::TextDisabled("%s", id_local.c_str());
			ImGui::Separator();
			if (ImGui::Button("Delete", ImVec2(90.f, 0.f))) {
				delete_session(id_local);
				ImGui::CloseCurrentPopup();
			}
			ImGui::SameLine();
			if (ImGui::Button("Cancel", ImVec2(90.f, 0.f))) ImGui::CloseCurrentPopup();
			ImGui::EndPopup();
		}

		{
			float fy = panel_h - footer_h;
			ImGui::SetCursorPos(ImVec2(0.f, fy));
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6.f, 3.f));
			ImGui::BeginChild("##sh_footer", ImVec2(panel_w, footer_h), false, ImGuiWindowFlags_NoBackground);
			double total_visible_local = 0.0;
			double total_all_local = 0.0;
			std::string sel_id_local;
			double sel_cost = 0.0;
			int sel_msg_count = 0;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				total_visible_local = st.total_visible_cost;
				total_all_local     = st.total_all_cost;
				sel_id_local        = st.selected_id.empty() ? st.active_session_id : st.selected_id;
				if (!sel_id_local.empty()) {
					for (const auto& rr : st.rows) {
						if (rr.id == sel_id_local) { sel_cost = rr.total_cost_usd; break; }
					}
				}
			}
			if (!sel_id_local.empty()) {
				std::vector<aida::session::message_t> msgs;
				if (aida::session::list_messages(sel_id_local, msgs, -1)) {
					sel_msg_count = (int)msgs.size();
				}
			}
			char l1[128], l2[160];
			snprintf(l1, sizeof(l1), "Visible: %s   All: %s",
				format_cost_str(total_visible_local).c_str(),
				format_cost_str(total_all_local).c_str());
			if (!sel_id_local.empty()) {
				snprintf(l2, sizeof(l2), "Selected: %s across %d messages",
					format_cost_str(sel_cost).c_str(), sel_msg_count);
			} else {
				snprintf(l2, sizeof(l2), "Selected: -");
			}
			ImGui::TextColored(ImVec4(0.66f, 0.66f, 0.78f, 0.9f), "%s", l1);
			ImGui::TextColored(ImVec4(0.55f, 0.58f, 0.7f, 0.9f), "%s", l2);
			ImGui::EndChild();
			ImGui::PopStyleVar();
		}

		ImGui::PopID();
	}


}
