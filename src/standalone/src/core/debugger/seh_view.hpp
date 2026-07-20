#pragma once

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "imgui/imgui.h"
#include "standalone_driver.hpp"
#include "debugger_engine.hpp"
#include "debugger_interaction_context.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/debugger_preview_runtime.hpp"
#endif
#include "disasm_view.hpp"
#include "ui_anim.hpp"
#include "../ui/application_view_registry.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../ui/task_center.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../helpers/diag_log.hpp"
#include "../infra/executor.hpp"
#else
#include "../../preview/ui_task_executor.hpp"
#endif

namespace seh_view {

struct seh_entry_t {
	uint64_t    handler_addr = 0;
	uint64_t    filter_addr = 0;
	uint64_t    frame_addr = 0;
	std::string module_name;
	std::string handler_name;
	int         index = 0;
};

struct seh_diagnostics_t {
	uint32_t target_pid = 0;
	uint32_t active_tid = 0;
	uint32_t teb_query_returned = 0;
	uint32_t stack_scan_candidates = 0;
	uint32_t chain_entries = 0;
	uint64_t teb_va = 0;
	uint64_t raw_exception_list = 0;
	uint64_t rsp = 0;
	uint64_t stack_scan_start = 0;
	uint64_t stack_scan_size = 0;
	uint64_t stack_scan_bytes = 0;
	uint64_t stack_scan_candidate_frame = 0;
	uint64_t stack_scan_candidate_handler = 0;
	bool teb_query_attempted = false;
	bool teb_query_ok = false;
	bool teb_read_ok = false;
	bool teb_read_succeeded = false;
	bool exception_list_read_ok = false;
	bool sentinel_reached = false;
	bool x64_empty_chain_proven = false;
	bool stack_scan_attempted = false;
	bool stack_scan_read_ok = false;
	bool stack_scan_candidate_found = false;
	std::string empty_reason;
	std::string stack_scan_reason;
	std::string chain_stop_reason;
};

struct ui_state_t {
	std::vector<seh_entry_t> entries;
	seh_diagnostics_t        diagnostics;
	std::string              last_error;
	int                      selected = -1;
	float                    scroll_y = 0.f;
	float                    target_scroll_y = 0.f;
	std::mutex               mutex;
	std::atomic<bool>        refreshing{false};
	bool                     scrollbar_dragging = false;
	float                    scrollbar_drag_offset = 0.f;
};

inline ui_state_t g_ui;

inline void register_background_task(const aida::infra::executor::submit_result_t& submitted) {
	if (!submitted.submitted || submitted.task_id == 0) return;
	aida::ui::task_center::task_registration_t registration;
	registration.owner = "debugger";
	registration.owner_view = "view.debug.seh";
	registration.owner_action = "debugger.seh_refresh";
	registration.label = "Refresh SEH chain";
	registration.stage = "Queued";
	registration.progress = -1.f;
	registration.target = driver_bridge::attached_pid() == 0 ? std::string{} :
		"PID " + std::to_string(driver_bridge::attached_pid());
	registration.cancellation_is_safe = false;
	static_cast<void>(aida::ui::task_center::register_executor_job(
		submitted.task_id, std::move(registration)));
}

inline void draw_clipped_text(ImDrawList* dl, ImVec2 pos, float width, float row_h, ImU32 color, const char* text)
{
	const char* value = (text && text[0]) ? text : "Unresolved";
	float clipped_w = std::max(4.f, width);
	ImVec2 a(pos.x, pos.y - 2.f);
	ImVec2 b(pos.x + clipped_w, pos.y + row_h);
	dl->PushClipRect(a, b, true);
	dl->AddText(pos, color, value);
	dl->PopClipRect();
	if (ImGui::IsMouseHoveringRect(a, b, false) && ImGui::CalcTextSize(value).x > clipped_w)
		ImGui::SetTooltip("%s", value);
}

inline uint64_t resolve_thread_teb(uint32_t tid)
{
	if (tid == 0)
		return 0;
	struct teb_basic_t {
		long      exit_status;
		void*     teb_base;
		void*     unique_process;
		void*     unique_thread;
		uintptr_t affinity_mask;
		long      priority;
		long      base_priority;
	};
	teb_basic_t tbi{};
	uint32_t returned = 0;
	if (!driver_bridge::query_thread_information(tid, 0, &tbi, sizeof(tbi), &returned))
		return 0;
	return reinterpret_cast<uint64_t>(tbi.teb_base);
}

inline void refresh()
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	{
		std::lock_guard<std::mutex> lock(g_ui.mutex);
		g_ui.entries = {
			{0x00007FFDA193AF28, 0, 0x0000007C52CFF430, "ntdll.dll", "KiUserExceptionDispatcher", 0},
			{0x00007FF7A4C16A32, 0x00007FF7A4C169D0, 0x0000007C52CFF4C0, "sample.exe", "sample_exception_filter", 1},
			{0x00007FF7A4C1B420, 0, 0x0000007C52CFF540, "sample.exe", "decrypt_stage", 2}
		};
		g_ui.diagnostics.target_pid = 6420;
		g_ui.diagnostics.active_tid = 6872;
		g_ui.diagnostics.teb_query_attempted = true;
		g_ui.diagnostics.teb_query_ok = true;
		g_ui.diagnostics.teb_va = 0x0000007C52CFF000;
		g_ui.diagnostics.chain_entries = static_cast<uint32_t>(g_ui.entries.size());
		g_ui.diagnostics.chain_stop_reason = "Preview fixture chain complete";
	}
	g_ui.refreshing.store(false);
	aida::preview::debugger::record("refresh_seh", "3 handlers");
	return;
#endif
	bool expected = false;
	if (!g_ui.refreshing.compare_exchange_strong(expected, true))
		return;
	diag::log_tagged_fmt("seh",
		"seh_refresh_request attached_pid=%u active_tid=%u",
		static_cast<unsigned>(driver_bridge::attached_pid()),
		static_cast<unsigned>(debugger_engine::g_state.active_tid));
	try {
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "debugger";
		sub.label = "debugger.seh_refresh";
		sub.thread_class = "debugger_refresh";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 3;
		const std::uint32_t target_pid = driver_bridge::attached_pid();
		const std::uint64_t target_generation = debugger_interaction::current_stop_generation();
		sub.target_pid = target_pid;
		sub.generation = target_generation;
		sub.body = [target_pid, target_generation]() {
		try {
		if (driver_bridge::attached_pid() != target_pid ||
			debugger_interaction::current_stop_generation() != target_generation) {
			g_ui.refreshing.store(false);
			return;
		}
		std::vector<seh_entry_t> entries;
		seh_diagnostics_t diag_state{};
		diag_state.target_pid = driver_bridge::attached_pid();
		diag_state.active_tid = debugger_engine::g_state.active_tid;

		auto modules = driver_bridge::enumerate_modules();
		auto regs = debugger_engine::get_registers();
		diag_state.rsp = regs.rsp;

		diag_state.teb_query_attempted = diag_state.active_tid != 0;
		uint64_t teb_addr = 0;
		if (diag_state.active_tid != 0) {
			struct teb_basic_t {
				long      exit_status;
				void*     teb_base;
				void*     unique_process;
				void*     unique_thread;
				uintptr_t affinity_mask;
				long      priority;
				long      base_priority;
			};
			teb_basic_t tbi{};
			uint32_t returned = 0;
			const bool query_ok = driver_bridge::query_thread_information(diag_state.active_tid, 0, &tbi, sizeof(tbi), &returned);
			diag_state.teb_query_ok = query_ok;
			diag_state.teb_query_returned = returned;
			if (query_ok)
				teb_addr = reinterpret_cast<uint64_t>(tbi.teb_base);
		}
		diag_state.teb_va = teb_addr;
		uint64_t nt_tib_seh = 0;
		bool found_seh = false;

		if (teb_addr != 0) {
			std::vector<uint8_t> teb_buf;
			diag_state.teb_read_ok = driver_bridge::read_memory(teb_addr, 8, teb_buf);
			diag_state.teb_read_succeeded = diag_state.teb_read_ok && teb_buf.size() >= 8;
			diag_state.exception_list_read_ok = diag_state.teb_read_succeeded;
			if (diag_state.teb_read_succeeded) {
				std::memcpy(&nt_tib_seh, teb_buf.data(), 8);
				diag_state.raw_exception_list = nt_tib_seh;
				diag_state.sentinel_reached = nt_tib_seh == 0xFFFFFFFFFFFFFFFFULL;
				found_seh = (nt_tib_seh != 0 && nt_tib_seh != 0xFFFFFFFFFFFFFFFFULL);
			}
		}

		if (!found_seh) {
			diag_state.stack_scan_attempted = regs.rsp != 0;
			if (regs.rsp != 0) {
				std::vector<uint8_t> stack_buf;
				size_t scan_size = 4096;
				diag_state.stack_scan_start = regs.rsp;
				diag_state.stack_scan_size = scan_size;
				diag_state.stack_scan_read_ok = driver_bridge::read_memory(regs.rsp, scan_size, stack_buf);
				diag_state.stack_scan_bytes = stack_buf.size();
				if (diag_state.stack_scan_read_ok && stack_buf.size() >= 16) {
					for (size_t i = 8; i + 8 <= stack_buf.size(); i += 8) {
						uint64_t candidate = 0;
						std::memcpy(&candidate, stack_buf.data() + i, 8);
						if (candidate > 0x10000 && candidate < 0x7FFFFFFFFFFF) {
							++diag_state.stack_scan_candidates;
							for (auto& m : modules) {
								if (candidate >= m.base && candidate < m.base + m.size) {
									uint64_t potential_next = 0;
									std::memcpy(&potential_next, stack_buf.data() + i - 8, 8);
									if (potential_next > regs.rsp && potential_next < regs.rsp + 0x100000) {
										nt_tib_seh = regs.rsp + i - 8;
										found_seh = true;
										diag_state.stack_scan_candidate_found = true;
										diag_state.stack_scan_candidate_frame = nt_tib_seh;
										diag_state.stack_scan_candidate_handler = candidate;
										diag_state.stack_scan_reason = "candidate_frame_selected";
									} else {
										diag_state.stack_scan_reason = "candidate_next_out_of_stack_window";
									}
									break;
								}
							}
						}
						if (found_seh) break;
					}
					if (!found_seh && diag_state.stack_scan_reason.empty())
						diag_state.stack_scan_reason = diag_state.stack_scan_candidates != 0 ? "no_valid_stack_frame_candidate" : "no_module_handler_candidate";
				} else {
					diag_state.stack_scan_reason = diag_state.stack_scan_read_ok ? "stack_read_too_short" : "stack_read_failed";
				}
			} else {
				diag_state.stack_scan_reason = "rsp_zero";
			}
		}

		if (found_seh && nt_tib_seh != 0 && nt_tib_seh != 0xFFFFFFFFFFFFFFFFULL) {
			uint64_t current = nt_tib_seh;
			int idx = 0;
			const int max_chain = 256;

			while (current != 0 && current != 0xFFFFFFFFFFFFFFFFULL && idx < max_chain) {
				std::vector<uint8_t> rec_buf;
				bool read_ok = driver_bridge::read_memory(current, 16, rec_buf);
				if (!read_ok || rec_buf.size() < 16) {
					diag_state.chain_stop_reason = read_ok ? "record_read_too_short" : "record_read_failed";
					break;
				}

				seh_entry_t entry;
				entry.frame_addr = current;
				entry.index = idx;

				uint64_t next = 0;
				std::memcpy(&next, rec_buf.data(), 8);
				std::memcpy(&entry.handler_addr, rec_buf.data() + 8, 8);

				for (auto& m : modules) {
					if (entry.handler_addr >= m.base && entry.handler_addr < m.base + m.size) {
						entry.module_name = m.name;
						char off_buf[32];
						snprintf(off_buf, sizeof(off_buf), "+0x%llX",
								 static_cast<unsigned long long>(entry.handler_addr - m.base));
						entry.handler_name = m.name + off_buf;
						break;
					}
				}

				entries.push_back(std::move(entry));
				if (next == current) {
					diag_state.chain_stop_reason = "self_link";
					break;
				}
				if (next == 0) {
					diag_state.chain_stop_reason = "null_next";
					break;
				}
				if (next == 0xFFFFFFFFFFFFFFFFULL) {
					diag_state.chain_stop_reason = "sentinel_next";
					diag_state.sentinel_reached = true;
					break;
				}
				current = next;
				++idx;
			}
			if (idx >= max_chain && diag_state.chain_stop_reason.empty())
				diag_state.chain_stop_reason = "max_chain_reached";
		}

		diag_state.chain_entries = static_cast<uint32_t>(entries.size());
		if (entries.empty()) {
			if (diag_state.teb_read_succeeded && diag_state.sentinel_reached)
				diag_state.empty_reason = "teb_exception_list_sentinel";
			else if (diag_state.teb_read_succeeded && diag_state.raw_exception_list == 0)
				diag_state.empty_reason = "teb_exception_list_null";
			else if (diag_state.teb_va == 0)
				diag_state.empty_reason = "teb_unresolved";
			else if (!diag_state.teb_read_succeeded)
				diag_state.empty_reason = "teb_exception_list_read_failed";
			else
				diag_state.empty_reason = "no_valid_chain_after_stack_scan";
			diag_state.x64_empty_chain_proven = diag_state.teb_read_succeeded &&
				(diag_state.sentinel_reached || diag_state.raw_exception_list == 0) &&
				!diag_state.stack_scan_candidate_found;
		} else if (diag_state.chain_stop_reason.empty()) {
			diag_state.chain_stop_reason = "chain_entries_collected";
		}

		size_t n = entries.size();
		if (driver_bridge::attached_pid() == target_pid &&
			debugger_interaction::current_stop_generation() == target_generation) {
			std::lock_guard<std::mutex> lk(g_ui.mutex);
			g_ui.entries = std::move(entries);
			g_ui.diagnostics = diag_state;
			g_ui.last_error.clear();
		}
		diag::log_tagged_fmt("seh",
			"seh_refresh_done pid=%u tid=%u chain_depth=%zu teb_query_ok=%d teb_va=0x%llX teb_read_ok=%d raw_exception_list=0x%llX sentinel=%d x64_empty_chain_proven=%d empty_reason=%s stack_attempted=%d stack_read_ok=%d stack_candidates=%u stack_found=%d stack_reason=%s chain_stop=%s",
			diag_state.target_pid,
			diag_state.active_tid,
			n,
			diag_state.teb_query_ok ? 1 : 0,
			static_cast<unsigned long long>(diag_state.teb_va),
			diag_state.teb_read_succeeded ? 1 : 0,
			static_cast<unsigned long long>(diag_state.raw_exception_list),
			diag_state.sentinel_reached ? 1 : 0,
			diag_state.x64_empty_chain_proven ? 1 : 0,
			diag_state.empty_reason.c_str(),
			diag_state.stack_scan_attempted ? 1 : 0,
			diag_state.stack_scan_read_ok ? 1 : 0,
			diag_state.stack_scan_candidates,
			diag_state.stack_scan_candidate_found ? 1 : 0,
			diag_state.stack_scan_reason.c_str(),
			diag_state.chain_stop_reason.c_str());
		g_ui.refreshing.store(false);
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("seh", "seh_refresh_worker_exception err='%s'", ex.what());
			{
				std::lock_guard<std::mutex> lk(g_ui.mutex);
				g_ui.last_error = std::string("SEH refresh failed: ") + ex.what();
			}
			g_ui.refreshing.store(false);
			throw;
		} catch (...) {
			diag::log_tagged("seh", "seh_refresh_worker_exception err='<unknown>'");
			{
				std::lock_guard<std::mutex> lk(g_ui.mutex);
				g_ui.last_error = "SEH refresh failed with an unknown error.";
			}
			g_ui.refreshing.store(false);
			throw;
		}
	};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			diag::log_tagged("seh", "seh_refresh_worker_post_failed");
			std::unique_lock<std::mutex> lock(g_ui.mutex, std::try_to_lock);
			if (lock.owns_lock())
				g_ui.last_error = "SEH refresh could not be queued: " + submitted.reject_reason;
			g_ui.refreshing.store(false);
		} else register_background_task(submitted);
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("seh", "seh_refresh_worker_create_failed err='%s'", ex.what());
		std::unique_lock<std::mutex> lock(g_ui.mutex, std::try_to_lock);
		if (lock.owns_lock()) g_ui.last_error = std::string("SEH refresh setup failed: ") + ex.what();
		g_ui.refreshing.store(false);
	} catch (...) {
		diag::log_tagged("seh", "seh_refresh_worker_create_failed err='<unknown>'");
		std::unique_lock<std::mutex> lock(g_ui.mutex, std::try_to_lock);
		if (lock.owns_lock()) g_ui.last_error = "SEH refresh setup failed with an unknown error.";
		g_ui.refreshing.store(false);
	}
}

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float ar, float ag, float ab)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (g_ui.entries.empty())
		refresh();
#endif
	ImDrawList* dl = ImGui::GetWindowDrawList();
	float dt = ImGui::GetIO().DeltaTime;
	const auto& _t = aida::ui::resolved();
	const auto _ta = [alpha](ImU32 c) -> ImU32 {
		return aida::ui::with_alpha(c, alpha);
	};
	static std::vector<seh_entry_t> snapshot;
	static std::string error_snapshot;
	std::unique_lock<std::mutex> seh_lock(g_ui.mutex, std::try_to_lock);
	if (seh_lock.owns_lock()) error_snapshot = g_ui.last_error;
	if (seh_lock.owns_lock() && g_ui.entries.size() <= 256U) {
		snapshot = g_ui.entries;
	}
	if (seh_lock.owns_lock()) seh_lock.unlock();

	dl->AddRectFilled(ImVec2(pos_x, pos_y), ImVec2(pos_x + width, pos_y + height),
					  _ta(_t.bg_base));

	float header_h = 32.f;
	float row_h = 20.f;
	float col_header_h = 22.f;

	ui_anim::render_toolbar(dl, pos_x, pos_y, width, header_h, ar, ag, ab, alpha);
	dl->AddText(ImVec2(pos_x + 10.f, pos_y + 8.f),
				_ta(_t.text_primary), "SEH Chain");

	float refresh_x = pos_x + 90.f;
	ImVec2 btn_min(refresh_x, pos_y + 4.f);
	ImVec2 btn_max(refresh_x + 60.f, pos_y + 26.f);
	bool btn_hover = ImGui::IsMouseHoveringRect(btn_min, btn_max, false);
	dl->AddRectFilled(btn_min, btn_max,
					  btn_hover ? _ta(ui_anim::lighten(_t.panel_header, 14))
								: _ta(_t.panel_header), 3.f);
	dl->AddText(ImVec2(refresh_x + 8.f, pos_y + 7.f),
				_ta(_t.text_secondary), "Refresh");
	if (btn_hover && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
		refresh();

	float strip_y = pos_y + header_h;
	const float strip_h = 44.f;
	{
		int depth = 0;
		int unresolved = 0;
		int distinct_modules = 0;
		uint32_t active_tid = debugger_engine::g_state.active_tid;
		{
			depth = static_cast<int>(snapshot.size());
			std::vector<std::string> seen_modules;
			seen_modules.reserve(snapshot.size());
			for (auto& e : snapshot) {
				if (e.module_name.empty()) unresolved++;
				else {
					bool already = false;
					for (auto& sm : seen_modules) {
						if (sm == e.module_name) { already = true; break; }
					}
					if (!already) seen_modules.push_back(e.module_name);
				}
			}
			distinct_modules = static_cast<int>(seen_modules.size());
		}
		char depth_buf[16];
		char tid_buf[16];
		char unres_buf[16];
		char mod_buf[16];
		std::snprintf(depth_buf, sizeof(depth_buf), "%d", depth);
		std::snprintf(tid_buf, sizeof(tid_buf), "%u", active_tid);
		std::snprintf(unres_buf, sizeof(unres_buf), "%d", unresolved);
		std::snprintf(mod_buf, sizeof(mod_buf), "%d", distinct_modules);

		ImU32 unres_col = unresolved > 0
			? _t.warning
			: _t.success;

		ui_anim::stat_strip_item_t items[4];
		items[0] = { "Chain Depth", depth_buf, nullptr, 0, nullptr, 0, 0 };
		items[1] = { "Active TID",   tid_buf,   nullptr, 0, nullptr, 0, 0 };
		items[2] = { "Unresolved",   unres_buf, nullptr, 0, nullptr, 0, unres_col };
		items[3] = { "Modules",      mod_buf,   nullptr, 0, nullptr, 0, 0 };
		ui_anim::render_stat_strip(dl, pos_x + 6.f, strip_y + 4.f, width - 12.f, strip_h - 8.f,
			items, 4, ar, ag, ab, alpha);
	}

	float table_y = strip_y + strip_h;

	const float table_pad = 10.f;
	float content_w = std::max(240.f, width - table_pad * 2.f);
	float idx_w = 44.f;
	float frame_w = std::min(172.f, std::max(126.f, content_w * 0.20f));
	float handler_w = std::min(180.f, std::max(132.f, content_w * 0.22f));
	float module_w = std::min(180.f, std::max(96.f, content_w * 0.18f));
	float name_w = content_w - idx_w - frame_w - handler_w - module_w;
	if (name_w < 96.f) {
		float deficit = 96.f - name_w;
		auto shrink = [](float& value, float min_value, float& amount) {
			float room = std::max(0.f, value - min_value);
			float cut = std::min(room, amount);
			value -= cut;
			amount -= cut;
		};
		shrink(module_w, 72.f, deficit);
		shrink(handler_w, 116.f, deficit);
		shrink(frame_w, 116.f, deficit);
		name_w = std::max(72.f, content_w - idx_w - frame_w - handler_w - module_w);
	}

	float col_idx = pos_x + table_pad;
	float col_frame = col_idx + idx_w;
	float col_handler = col_frame + frame_w;
	float col_module = col_handler + handler_w;
	float col_name = col_module + module_w;

	{
		ui_anim::table_col_t cols[] = {{"#", idx_w}, {"Frame Address", frame_w}, {"Handler Address", handler_w}, {"Module", module_w}, {"Name", name_w}};
		ui_anim::render_table_header(dl, pos_x, table_y, width, col_header_h, cols, 5, ar, ag, ab, alpha);
	}

	float list_y = table_y + col_header_h;
	float list_h = height - header_h - strip_h - col_header_h;
	if (list_h <= 0.f) return;

	dl->PushClipRect(ImVec2(pos_x, list_y), ImVec2(pos_x + width, list_y + list_h), true);

	if (snapshot.empty()) {
		float cw = std::min(width - 40.f, 540.f);
		if (cw < 160.f) cw = std::max(160.f, width - 20.f);
		float cx = pos_x + (width - cw) * 0.5f;
		float cy = list_y + list_h * 0.5f - 34.f;
		const char* message = error_snapshot.empty()
			? "No SEH chain found. Empty chains are normal for many x64 targets."
			: error_snapshot.c_str();
		ui_anim::render_inline_callout(dl, cx, cy, cw, 52.f, message,
			error_snapshot.empty() ? ui_anim::callout_kind_t::info : ui_anim::callout_kind_t::warn,
			ar, ag, ab, alpha);
		const char* hint = "SEH is per active thread; switch threads and refresh when needed.";
		ImVec2 hint_sz = ImGui::CalcTextSize(hint);
		dl->AddText(ImVec2(pos_x + (width - hint_sz.x) * 0.5f, cy + 58.f),
			_ta(_t.text_secondary), hint);
		dl->PopClipRect();
		return;
	}

	float content_h = static_cast<float>(snapshot.size()) * row_h;
	float max_scroll = content_h - list_h;
	if (max_scroll < 0.f) max_scroll = 0.f;

	if (ImGui::IsMouseHoveringRect(ImVec2(pos_x, list_y), ImVec2(pos_x + width, list_y + list_h), false))
		ui_anim::handle_scroll_input(g_ui.target_scroll_y, 0.f, max_scroll, row_h);
	ui_anim::clamp_scroll(g_ui.target_scroll_y, 0.f, max_scroll);
	ui_anim::smooth_scroll(g_ui.scroll_y, g_ui.target_scroll_y, 15.f, dt);

	int first_visible = static_cast<int>(g_ui.scroll_y / row_h);
	if (first_visible < 0) first_visible = 0;
	int visible_count = static_cast<int>(list_h / row_h) + 2;

	bool open_seh_context = false;
	auto seh_context_origin = aida::ui::context_menu_open_origin_t::pointer;
	for (int vi = 0; vi < visible_count; ++vi) {
		int idx = first_visible + vi;
		if (idx < 0) continue;
		const std::size_t snapshot_index = static_cast<std::size_t>(idx);
		if (snapshot_index >= snapshot.size()) break;

		auto& e = snapshot[snapshot_index];
		float ry = list_y + static_cast<float>(idx) * row_h - g_ui.scroll_y;
		if (ry + row_h < list_y || ry > list_y + list_h) continue;

		float row_alpha = ui_anim::render_row_entrance(idx, static_cast<float>(first_visible), dt, alpha);
		ui_anim::row_hover_select(dl, pos_x, ry, width - 12.f, row_h, idx, g_ui.selected, row_alpha, ar, ag, ab);

		char idx_buf[8];
		snprintf(idx_buf, sizeof(idx_buf), "%d", e.index);
		draw_clipped_text(dl, ImVec2(col_idx, ry + 2.f), idx_w - 6.f, row_h,
			_ta(_t.text_secondary), idx_buf);

		char frame_buf[24];
		snprintf(frame_buf, sizeof(frame_buf), "%016llX", static_cast<unsigned long long>(e.frame_addr));
		draw_clipped_text(dl, ImVec2(col_frame, ry + 2.f), frame_w - 8.f, row_h,
			_ta(_t.text_primary), frame_buf);

		char handler_buf[24];
		snprintf(handler_buf, sizeof(handler_buf), "%016llX", static_cast<unsigned long long>(e.handler_addr));
		draw_clipped_text(dl, ImVec2(col_handler, ry + 2.f), handler_w - 8.f, row_h,
			_ta(_t.text_primary), handler_buf);

		draw_clipped_text(dl, ImVec2(col_module, ry + 2.f), module_w - 8.f, row_h,
			_ta(_t.text_secondary), e.module_name.c_str());

		draw_clipped_text(dl, ImVec2(col_name, ry + 2.f), name_w - 8.f, row_h,
			_ta(_t.text_primary), e.handler_name.c_str());

		if (idx == g_ui.selected && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
			open_seh_context = true;
	}

	dl->PopClipRect();

	float sb_w = 8.f;
	ui_anim::render_custom_scrollbar(dl, pos_x + width - sb_w - 2.f, list_y, sb_w, list_h,
									 g_ui.scroll_y, content_h, list_h, alpha,
									 g_ui.scrollbar_dragging, g_ui.scrollbar_drag_offset);

	if (g_ui.selected >= 0 && ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
		(ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
		 (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false)))) {
		open_seh_context = true;
		seh_context_origin = ImGui::IsKeyPressed(ImGuiKey_Menu, false)
			? aida::ui::context_menu_open_origin_t::menu_key
			: aida::ui::context_menu_open_origin_t::shift_f10;
	}
	if (open_seh_context) {
		if (g_ui.selected >= 0) {
			const std::size_t selected_index = static_cast<std::size_t>(g_ui.selected);
			if (selected_index < snapshot.size()) {
				const auto entry = snapshot[selected_index];
				const auto target_pid = driver_bridge::attached_pid();
				const auto generation = debugger_interaction::current_stop_generation();
				aida::ui::application_ui::retained_entity_context_t retained;
				retained.owner_id = "debugger.seh.handler";
				retained.entity_id = std::to_string(entry.index) + "@" + std::to_string(entry.handler_addr);
				retained.entity_generation = generation;
				retained.active_view = aida::ui::stable_view_id_t("view.debug.seh");
				retained.validate_identity = [entry, target_pid, generation]() {
					if (driver_bridge::attached_pid() != target_pid ||
						debugger_interaction::current_stop_generation() != generation)
						return aida::ui::capability_state_t::unavailable("The target or debugger stop generation changed.");
					std::lock_guard<std::mutex> lock(g_ui.mutex);
					const bool exists = std::any_of(g_ui.entries.begin(), g_ui.entries.end(), [&](const auto& current) {
						return current.index == entry.index && current.handler_addr == entry.handler_addr;
					});
					return exists ? aida::ui::capability_state_t::available()
						: aida::ui::capability_state_t::unavailable("The exception handler is no longer published.");
				};
				retained.actions.push_back({"debugger.seh.follow_handler",
					entry.handler_addr != 0 ? aida::ui::capability_state_t::available()
						: aida::ui::capability_state_t::unavailable("The handler has no resolved address."), [entry]() {
					diag::log_tagged_fmt("seh",
						"seh_go_handler idx=%d handler=0x%llx",
						entry.index,
						static_cast<unsigned long long>(entry.handler_addr));
					aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
					disasm_view::goto_address(entry.handler_addr,
						disasm_view::capture_selected_workspace());
					return aida::ui::action_handler_result_t::completed();
				}});
				retained.actions.push_back({"debugger.entity.copy_address",
					aida::ui::capability_state_t::available(), [entry]() {
					char abuf[24];
					snprintf(abuf, sizeof(abuf), "%016llX",
							 static_cast<unsigned long long>(entry.handler_addr));
					ImGui::SetClipboardText(abuf);
					return aida::ui::action_handler_result_t::completed();
				}});
				aida::ui::application_ui::open_retained_entity_context_menu(
					std::move(retained), seh_context_origin);
			}
		}
	}
	aida::ui::application_ui::render_retained_entity_context_menu("debugger.seh.handler");
}

}
