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
#include <utility>
#include <vector>

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "event_bus.hpp"
#include "session_store.hpp"
#include "standalone_chat.hpp"
#include "standalone_driver.hpp"

#include "../ui/avatar.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/brand.hpp"
#include "../ui/clock.hpp"
#include "../ui/components.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/fonts.hpp"
#include "../ui/motion.hpp"
#include "../ui/theme.hpp"
#include "../ui/transition.hpp"


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
			bool        last_msg_costs_loaded = false;
			std::vector<std::pair<std::string, double>> last_msg_costs;
		};

		struct ctx_target_t
		{
			std::string id;
			std::string title;
			bool        archived = false;
		};

		struct row_anim_t
		{
			aida::ui::hover_state_t hover;
			aida::ui::transition_t  entrance;
			aida::ui::transition_t  arrow_rotate;
			bool                    arrow_collapsed = false;
		};

		enum class group_kind_t : int
		{
			today = 0,
			yesterday,
			this_week,
			this_month,
			older,
			count
		};

		inline const char* group_label(group_kind_t k)
		{
			switch (k) {
			case group_kind_t::today:       return "Today";
			case group_kind_t::yesterday:   return "Yesterday";
			case group_kind_t::this_week:   return "This week";
			case group_kind_t::this_month:  return "This month";
			case group_kind_t::older:       return "Older";
			default: return "";
			}
		}

		inline group_kind_t classify_unix_ms(int64_t unix_ms)
		{
			if (unix_ms <= 0) return group_kind_t::older;
			const int64_t now_ms = static_cast<int64_t>(
				std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::system_clock::now().time_since_epoch()).count());
			int64_t delta_s = (now_ms - unix_ms) / 1000;
			if (delta_s < 0) delta_s = 0;
			if (delta_s < 86400) return group_kind_t::today;
			if (delta_s < 86400 * 2) return group_kind_t::yesterday;
			if (delta_s < 86400 * 7) return group_kind_t::this_week;
			if (delta_s < 86400 * 31) return group_kind_t::this_month;
			return group_kind_t::older;
		}

		struct state_t
		{
			std::mutex                                   mtx;
			std::string                                  last_error;
			char                                         search_buf[128] = {};
			bool                                         show_archived = false;
			std::string                                  active_session_id;
			std::string                                  selected_id;
			std::string                                  rename_target_id;
			char                                         rename_buf[256] = {};
			std::vector<row_t>                           rows;
			std::vector<size_t>                          visible_indices;
			std::unordered_map<std::string, std::vector<size_t>> children_index;
			std::unordered_set<std::string>              collapsed_parents;
			std::unordered_set<std::string>              compacted_cache;
			std::atomic<int64_t>                         next_refresh_unix_ms{0};
			std::atomic<bool>                            initialized{false};
			ctx_target_t                                 ctx;
			bool                                         open_rename_popup = false;
			bool                                         open_delete_popup = false;
			std::string                                  pending_delete_id;
			double                                       total_visible_cost = 0.0;
			double                                       total_all_cost = 0.0;
			aida::events::subscription_handle_t          sub_compacted;
			aida::events::subscription_handle_t          sub_binary_loaded;
			std::unordered_map<std::string, row_anim_t>  row_anims;
			std::string                                  last_visible_signature;
		};

		inline state_t& g_state()
		{
			static state_t s;
			return s;
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
			std::string p = driver_bridge::attached_process_name();
			if (!p.empty()) return p;
			return std::string();
		}

		inline std::string format_cost_str(double usd)
		{
			char buf[32];
			if (usd < 0.001) return std::string("<$0.001");
			if (usd < 1.0) snprintf(buf, sizeof(buf), "$%.4f", usd);
			else if (usd < 100.0) snprintf(buf, sizeof(buf), "$%.2f", usd);
			else snprintf(buf, sizeof(buf), "$%.0f", usd);
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
			if (delta_s < 60) snprintf(buf, sizeof(buf), "%llds ago", (long long)delta_s);
			else if (delta_s < 3600) snprintf(buf, sizeof(buf), "%lldm ago", (long long)(delta_s / 60));
			else if (delta_s < 86400) snprintf(buf, sizeof(buf), "%lldh ago", (long long)(delta_s / 3600));
			else if (delta_s < 86400 * 7) snprintf(buf, sizeof(buf), "%lldd ago", (long long)(delta_s / 86400));
			else {
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
			for (const auto& m : msgs)
				for (const auto& p : m.parts)
					if (p.kind == aida::session::part_t::kind_t::compaction) return true;
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
				for (const auto& p : m.parts)
					if (p.kind == aida::session::part_t::kind_t::step_finish)
						cost_sum += p.step_finish.cost_usd;
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
				if (it != st.children_index.end())
					for (size_t cidx : it->second)
						if (any_match(cidx)) return true;
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
						for (size_t cidx : sorted_children) push_subtree(cidx, depth + 1);
					}
				}
			};
			for (size_t r : roots) push_subtree(r, 0);
			st.total_visible_cost = 0.0;
			for (size_t idx : st.visible_indices) st.total_visible_cost += st.rows[idx].total_cost_usd;
		}

		inline void refresh_locked(state_t& st)
		{
			std::vector<aida::session::session_info_t> infos;
			std::string bp = current_binary_path();
			bool ok = bp.empty() ? aida::session::list_all(infos) : aida::session::list(bp, infos);
			if (!ok) { st.last_error = aida::session::last_error(); return; }
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
				if (st.compacted_cache.count(info.id) > 0) r.has_compaction = true;
				else if (detect_compaction(info.id)) {
					r.has_compaction = true;
					st.compacted_cache.insert(info.id);
				}
				st.total_all_cost += r.total_cost_usd;
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
			for (auto& r : st.rows) if (r.id == ev.session_id) r.has_compaction = true;
		}

		inline void on_binary_loaded(const aida::events::binary_loaded_t&)
		{
			g_state().next_refresh_unix_ms.store(0);
		}

		inline void open_session_internal(const std::string& session_id)
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
				st.last_error = aida::session::last_error();
				return;
			}
			open_session_internal(out_info.id);
			force_refresh();
		}

		inline void fork_session(const std::string& session_id)
		{
			if (session_id.empty()) return;
			aida::session::session_info_t out_new;
			if (!aida::session::fork(session_id, std::string(), out_new)) {
				state_t& st = g_state();
				std::lock_guard<std::mutex> lk(st.mtx);
				st.last_error = aida::session::last_error();
				return;
			}
			open_session_internal(out_new.id);
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
				st.last_error = aida::session::last_error();
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
				st.last_error = aida::session::last_error();
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
				st.last_error = aida::session::last_error();
				return;
			}
			force_refresh();
		}

		inline int find_visible_idx_for_id(const state_t& st, const std::string& id)
		{
			for (int i = 0; i < (int)st.visible_indices.size(); ++i)
				if (st.rows[st.visible_indices[i]].id == id) return i;
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
				if (!sid.empty()) open_session_internal(sid);
			}
			if (ImGui::IsKeyPressed(ImGuiKey_Delete, false)) {
				state_t& st = g_state();
				std::string sid;
				bool was_archived = false;
				{
					std::lock_guard<std::mutex> lk(st.mtx);
					sid = st.selected_id;
					for (const auto& r : st.rows) if (r.id == sid) { was_archived = r.time_archived_unix > 0; break; }
				}
				if (sid.empty()) return;
				if (io.KeyShift) {
					st.pending_delete_id = sid;
					st.open_delete_popup = true;
				} else {
					toggle_archive_session(sid, was_archived);
				}
			}
			if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_N, false)) create_new_session();
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
		st.row_anims.clear();
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
		const auto& th = aida::ui::resolved();
		const float dt = aida::ui::clock::dt();
		maybe_refresh();

		ImGui::PushID("##aida_session_history");

		const float toolbar_h = 36.f;
		const float footer_h  = 44.f;
		const float row_h     = 30.f;

		{
			float toolbar_w = panel_w - 8.f;
			float new_btn_w = 32.f;
			float arch_w = 110.f;
			float search_w = toolbar_w - new_btn_w - arch_w - 16.f;
			if (search_w < 80.f) search_w = 80.f;
			ImGui::SetCursorPos(ImVec2(4.f, 4.f));
			char tmp_buf[128];
			{ std::lock_guard<std::mutex> lk(st.mtx); std::memcpy(tmp_buf, st.search_buf, sizeof(tmp_buf)); }
			if (aida::ui::input_text("##sh_search", tmp_buf, sizeof(tmp_buf),
					"Search sessions", false, ImVec2(search_w, 28.f))) {
				std::lock_guard<std::mutex> lk(st.mtx);
				std::memcpy(st.search_buf, tmp_buf, sizeof(st.search_buf));
				rebuild_visible_locked(st);
			}
			ImGui::SetCursorPos(ImVec2(4.f + search_w + 6.f, 4.f));
			if (aida::ui::button("+##sh_new",
					aida::ui::button_kind_t::primary,
					aida::ui::size_t_::sm,
					ImVec2(new_btn_w, 28.f))) {
				create_new_session();
			}
			ImGui::SetCursorPos(ImVec2(4.f + search_w + 6.f + new_btn_w + 8.f, 9.f));
			bool show_arch_local;
			{ std::lock_guard<std::mutex> lk(st.mtx); show_arch_local = st.show_archived; }
			if (aida::ui::toggle_switch("Archived##sh_archived", &show_arch_local, aida::ui::size_t_::sm)) {
				std::lock_guard<std::mutex> lk(st.mtx);
				st.show_archived = show_arch_local;
				rebuild_visible_locked(st);
			}
		}

		float body_y = 4.f + toolbar_h;
		float body_h = panel_h - body_y - footer_h;
		if (body_h < 16.f) body_h = 16.f;

		ImGui::SetCursorPos(ImVec2(0.f, body_y));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
		ImGui::BeginChild("##sh_body", ImVec2(panel_w, body_h), false,
			ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_AlwaysVerticalScrollbar);

		bool body_hovered = ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows);
		if (body_hovered) handle_keyboard();

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

		std::string sig;
		sig.reserve(visible_copy.size() * 16);
		for (size_t vi : visible_copy) sig.append(rows_copy[vi].id).push_back(';');
		bool first_render_this_filter = false;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			if (sig != st.last_visible_signature) {
				st.last_visible_signature = sig;
				first_render_this_filter = true;
				for (size_t vi = 0; vi < visible_copy.size(); ++vi) {
					auto& ra = st.row_anims[rows_copy[visible_copy[vi]].id];
					ra.entrance.start(0.36f, aida::motion::ease::out_quint, 0.018f * vi);
				}
			}
		}
		(void)first_render_this_filter;

		ImDrawList* dl = ImGui::GetWindowDrawList();

		struct ctx_payload_t {
			bool        request_open = false;
			std::string id;
			std::string title;
			bool        archived = false;
		} ctx_payload;

		if (visible_copy.empty()) {
			ImVec2 region_pos = ImGui::GetCursorScreenPos();
			ImVec2 region_size(panel_w, body_h);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::message;
			cfg.title = "No sessions yet";
			cfg.body = "Press + to start a new chat session for this binary.";
			cfg.max_width = panel_w * 0.85f;
			aida::ui::empty_state::render(region_pos, region_size, cfg);
		}

		group_kind_t last_group = group_kind_t::count;
		for (size_t vi = 0; vi < visible_copy.size(); ++vi) {
			const auto& r = rows_copy[visible_copy[vi]];
			bool is_active = !r.id.empty() && r.id == active_id_copy;
			bool is_selected = !r.id.empty() && r.id == selected_id_copy;
			bool archived = r.time_archived_unix > 0;

			if (r.depth == 0) {
				group_kind_t g = classify_unix_ms(r.time_updated_unix);
				if (g != last_group) {
					last_group = g;
					ImVec2 hp = ImGui::GetCursorScreenPos();
					float hh = 22.f;
					dl->AddText(aida::ui::fonts::caption(), 11.f,
						ImVec2(hp.x + 12.f, hp.y + 4.f),
						aida::ui::with_alpha(th.text_dim, 0.95f),
						group_label(g));
					dl->AddLine(
						ImVec2(hp.x + 12.f + ImGui::CalcTextSize(group_label(g)).x + 8.f, hp.y + hh * 0.5f),
						ImVec2(hp.x + panel_w - 14.f, hp.y + hh * 0.5f),
						aida::ui::with_alpha(th.border_subtle, 0.7f), 1.f);
					ImGui::Dummy(ImVec2(panel_w, hh));
				}
			}

			row_anim_t* ra = nullptr;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				ra = &st.row_anims[r.id];
			}
			ra->entrance.tick(dt);
			ra->arrow_rotate.tick(dt);
			float ent_p = ra->entrance.eased();
			float ent_y = (1.f - ent_p) * 8.f;
			float ent_alpha = ent_p;

			float indent = 8.f + (float)r.depth * 14.f;
			ImVec2 cp = ImGui::GetCursorScreenPos();
			cp.y += ent_y;

			ImGui::PushID((int)vi);
			ImGui::SetCursorScreenPos(cp);
			ImGui::InvisibleButton("##sh_row", ImVec2(panel_w, row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool dbl = ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
			bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);

			float hov_v = ra->hover.tick(hov, dt, aida::motion::spring::playful);
			float lift = hov_v * 2.f;
			ImVec2 rmin(cp.x + 4.f, cp.y - lift);
			ImVec2 rmax(cp.x + panel_w - 4.f, cp.y + row_h - 2.f - lift);

			if (is_selected) {
				dl->AddRectFilled(rmin, rmax,
					aida::ui::with_alpha(th.selection, ent_alpha * 0.85f), 8.f);
				dl->AddRect(rmin, rmax,
					aida::ui::with_alpha(th.accent_u32, ent_alpha), 8.f, 0, 1.5f);
				aida::ui::blur::render_inner_glow(dl, rmin, rmax, 8.f,
					aida::ui::with_alpha(th.accent_glow, ent_alpha), 3);
			} else if (hov_v > 0.02f) {
				dl->AddRectFilled(rmin, rmax,
					aida::ui::with_alpha(th.hover_wash, ent_alpha * hov_v), 8.f);
				if (hov_v > 0.05f) {
					aida::ui::blur::render_inner_glow(dl, rmin, rmax, 8.f,
						aida::ui::with_alpha(th.accent_glow, ent_alpha * hov_v * 0.4f), 2);
				}
			}

			if (r.depth > 0) {
				float vline_x = cp.x + 8.f + (float)(r.depth - 1) * 14.f + 6.f;
				dl->AddLine(ImVec2(vline_x, cp.y - lift),
					ImVec2(vline_x, cp.y + row_h - lift),
					aida::ui::with_alpha(th.border_subtle, ent_alpha * 0.7f), 1.f);
				dl->AddLine(ImVec2(vline_x, cp.y + row_h * 0.5f - lift),
					ImVec2(vline_x + 8.f, cp.y + row_h * 0.5f - lift),
					aida::ui::with_alpha(th.border_subtle, ent_alpha * 0.7f), 1.f);
			}

			float arrow_x = rmin.x + indent;
			float arrow_y = (rmin.y + rmax.y) * 0.5f;
			bool has_children = child_count_for.count(r.id) > 0 && child_count_for[r.id] > 0;
			bool collapsed = collapsed_copy.count(r.id) > 0;
			if (has_children) {
				if (ra->arrow_collapsed != collapsed) {
					ra->arrow_collapsed = collapsed;
					if (!collapsed)
						ra->arrow_rotate.start(0.18f, aida::motion::ease::out_cubic);
					else
						ra->arrow_rotate.start_reverse(0.18f, aida::motion::ease::in_cubic);
				}
				float p = ra->arrow_rotate.eased();
				float ang = (1.f - p) * 0.f + p * 1.5707963f;
				if (collapsed) ang = (1.f - p) * 1.5707963f;
				ImVec2 t0(-3.f, -3.f), t1(3.f, 0.f), t2(-3.f, 3.f);
				float ca = cosf(ang), sa = sinf(ang);
				ImVec2 p0(arrow_x + t0.x * ca - t0.y * sa, arrow_y + t0.x * sa + t0.y * ca);
				ImVec2 p1(arrow_x + t1.x * ca - t1.y * sa, arrow_y + t1.x * sa + t1.y * ca);
				ImVec2 p2(arrow_x + t2.x * ca - t2.y * sa, arrow_y + t2.x * sa + t2.y * ca);
				dl->AddTriangleFilled(p0, p1, p2,
					aida::ui::with_alpha(th.text_secondary, ent_alpha));
			}
			float title_x = arrow_x + 14.f;

			if (is_active) {
				dl->AddCircleFilled(ImVec2(title_x - 6.f, arrow_y), 3.f,
					aida::ui::with_alpha(th.accent_u32, ent_alpha));
			}

			std::string display_title = r.title;
			if (display_title.empty()) display_title = r.id.substr(0, 8);

			ImU32 title_col = archived
				? aida::ui::with_alpha(th.text_dim, ent_alpha * 0.8f)
				: aida::ui::with_alpha(th.text_primary, ent_alpha);
			dl->AddText(aida::ui::fonts::body(), 13.f,
				ImVec2(title_x, rmin.y + 5.f), title_col, display_title.c_str());

			if (r.has_compaction) {
				ImVec2 ds = aida::ui::fonts::body()->CalcTextSizeA(13.f, FLT_MAX, 0.f, display_title.c_str());
				ImGui::SetCursorScreenPos(ImVec2(title_x + ds.x + 8.f, rmin.y + 5.f));
				aida::ui::badge("C", aida::ui::with_alpha(th.warning, ent_alpha * 0.85f), 4.f);
			}
			if (archived) {
				ImVec2 ds = aida::ui::fonts::body()->CalcTextSizeA(13.f, FLT_MAX, 0.f, display_title.c_str());
				ImGui::SetCursorScreenPos(ImVec2(title_x + ds.x + (r.has_compaction ? 30.f : 8.f), rmin.y + 5.f));
				aida::ui::badge("archived", aida::ui::with_alpha(th.text_dim, ent_alpha * 0.85f), 4.f);
			}

			std::string time_str = format_relative_time_str(r.time_updated_unix);
			std::string cost_str = format_cost_str(r.total_cost_usd);
			std::string right_str = cost_str + std::string("  ") + time_str;
			ImVec2 rs = aida::ui::fonts::caption()->CalcTextSizeA(11.f, FLT_MAX, 0.f, right_str.c_str());
			float right_x = rmax.x - 8.f - rs.x;
			dl->AddText(aida::ui::fonts::caption(), 11.f,
				ImVec2(right_x, rmin.y + 8.f),
				aida::ui::with_alpha(th.text_dim, ent_alpha * 0.95f), right_str.c_str());

			if (ImGui::IsItemHovered()) {
				const auto& tt = aida::ui::resolved();
				ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(tt.bg_overlay));
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.f, 8.f));
				if (ImGui::BeginTooltip()) {
					ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(tt.text_primary));
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
							snprintf(l, sizeof(l), "  %s  %s", mc.first.c_str(), format_cost_str(mc.second).c_str());
							ImGui::TextUnformatted(l);
						}
					}
					ImGui::PopStyleColor();
					ImGui::EndTooltip();
				}
				ImGui::PopStyleVar();
				ImGui::PopStyleColor();

				if (!r.last_msg_costs_loaded) {
					std::vector<std::pair<std::string, double>> tmp;
					compute_last_costs(r.id, tmp);
					std::lock_guard<std::mutex> lk(st.mtx);
					for (auto& rr : st.rows) if (rr.id == r.id) {
						rr.last_msg_costs = std::move(tmp);
						rr.last_msg_costs_loaded = true;
						break;
					}
				}
			}

			if (clicked) {
				std::lock_guard<std::mutex> lk(st.mtx);
				st.selected_id = r.id;
				if (has_children) {
					ImVec2 mp = ImGui::GetIO().MousePos;
					if (mp.x < arrow_x + 12.f) {
						if (collapsed_copy.count(r.id) > 0) st.collapsed_parents.erase(r.id);
						else st.collapsed_parents.insert(r.id);
						rebuild_visible_locked(st);
					}
				}
			}
			if (dbl) open_session_internal(r.id);
			if (right_clicked) {
				ctx_payload.request_open = true;
				ctx_payload.id           = r.id;
				ctx_payload.title        = r.title;
				ctx_payload.archived     = archived;
			}

			ImGui::PopID();
			ImGui::SetCursorScreenPos(ImVec2(cp.x, cp.y - ent_y + row_h));
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
			ctx_target_t target;
			{ std::lock_guard<std::mutex> lk(st.mtx); target = st.ctx; }
			ImGui::TextDisabled("%s", target.title.empty() ? target.id.c_str() : target.title.c_str());
			ImGui::Separator();
			if (ImGui::MenuItem("Open")) open_session_internal(target.id);
			if (ImGui::MenuItem("Fork at last message")) fork_session(target.id);
			if (ImGui::MenuItem("Rename")) {
				std::lock_guard<std::mutex> lk(st.mtx);
				st.rename_target_id = target.id;
				std::memset(st.rename_buf, 0, sizeof(st.rename_buf));
				size_t cn = (std::min<size_t>)(target.title.size(), sizeof(st.rename_buf) - 1);
				std::memcpy(st.rename_buf, target.title.data(), cn);
				st.open_rename_popup = true;
			}
			if (ImGui::MenuItem(target.archived ? "Unarchive" : "Archive"))
				toggle_archive_session(target.id, target.archived);
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
				std::memcpy(buf, st.rename_buf, sizeof(buf));
				id_local = st.rename_target_id;
			}
			ImGui::SetNextItemWidth(360.f);
			bool submit = ImGui::InputText("##sh_rename_in", buf, sizeof(buf),
				ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
			{ std::lock_guard<std::mutex> lk(st.mtx); std::memcpy(st.rename_buf, buf, sizeof(st.rename_buf)); }
			if (submit || aida::ui::button("OK", aida::ui::button_kind_t::primary,
					aida::ui::size_t_::md, ImVec2(80.f, 28.f))) {
				rename_session(id_local, std::string(buf));
				ImGui::CloseCurrentPopup();
			}
			ImGui::SameLine();
			if (aida::ui::button("Cancel", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::md, ImVec2(80.f, 28.f))) {
				ImGui::CloseCurrentPopup();
			}
			ImGui::EndPopup();
		}

		if (st.open_delete_popup) {
			st.open_delete_popup = false;
			ImGui::OpenPopup("##sh_delete");
		}
		if (ImGui::BeginPopupModal("##sh_delete", nullptr,
			ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
			std::string id_local;
			{ std::lock_guard<std::mutex> lk(st.mtx); id_local = st.pending_delete_id; }
			ImGui::Text("Delete this session permanently?");
			ImGui::TextDisabled("%s", id_local.c_str());
			ImGui::Separator();
			if (aida::ui::button("Delete", aida::ui::button_kind_t::destructive,
					aida::ui::size_t_::md, ImVec2(90.f, 28.f))) {
				delete_session(id_local);
				ImGui::CloseCurrentPopup();
			}
			ImGui::SameLine();
			if (aida::ui::button("Cancel", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::md, ImVec2(90.f, 28.f))) {
				ImGui::CloseCurrentPopup();
			}
			ImGui::EndPopup();
		}

		{
			float fy = panel_h - footer_h;
			ImGui::SetCursorPos(ImVec2(0.f, fy));
			ImVec2 fpos = ImGui::GetCursorScreenPos();
			ImDrawList* fdl = ImGui::GetWindowDrawList();
			ImVec2 fa(fpos.x + 4.f, fpos.y);
			ImVec2 fb(fpos.x + panel_w - 4.f, fpos.y + footer_h - 2.f);
			fdl->AddRectFilled(fa, fb, aida::ui::with_alpha(th.panel_header, 0.55f), 8.f);
			fdl->AddRect(fa, fb, aida::ui::with_alpha(th.border_subtle, 0.85f), 8.f, 0, 1.f);

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
				if (!sel_id_local.empty()) for (const auto& rr : st.rows)
					if (rr.id == sel_id_local) { sel_cost = rr.total_cost_usd; break; }
			}
			if (!sel_id_local.empty()) {
				std::vector<aida::session::message_t> msgs;
				if (aida::session::list_messages(sel_id_local, msgs, -1)) sel_msg_count = (int)msgs.size();
			}

			ImFont* cap = aida::ui::fonts::caption();
			if (!cap) cap = ImGui::GetFont();
			ImFont* body = aida::ui::fonts::body();
			if (!body) body = ImGui::GetFont();

			std::string vis_v = format_cost_str(total_visible_local);
			std::string all_v = format_cost_str(total_all_local);
			std::string sel_v;
			if (!sel_id_local.empty()) {
				char tmp[64];
				snprintf(tmp, sizeof(tmp), "%s · %d msg", format_cost_str(sel_cost).c_str(), sel_msg_count);
				sel_v = tmp;
			} else {
				sel_v = "—";
			}

			float col_w = (fb.x - fa.x) / 3.f;
			float row1_y = fa.y + 4.f;
			float row2_y = fa.y + 20.f;

			auto draw_metric = [&](float cx0, const char* lbl, const std::string& val){
				fdl->AddText(cap, 10.f, ImVec2(cx0 + 8.f, row1_y),
					aida::ui::with_alpha(th.text_dim, 0.95f), lbl);
				fdl->AddText(body, 12.f, ImVec2(cx0 + 8.f, row2_y),
					aida::ui::with_alpha(th.text_primary, 0.95f), val.c_str());
			};

			draw_metric(fa.x + 0.f * col_w, "VISIBLE", vis_v);
			draw_metric(fa.x + 1.f * col_w, "ALL", all_v);
			draw_metric(fa.x + 2.f * col_w, "SELECTED", sel_v);

			ImGui::Dummy(ImVec2(panel_w, footer_h));
		}

		ImGui::PopID();
	}


}
