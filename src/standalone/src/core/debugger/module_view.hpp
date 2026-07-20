#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "imgui/imgui.h"
#include "standalone_driver.hpp"
#include "debugger_interaction_context.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "pe_parser.hpp"
#else
#include "../../preview/debugger_preview_runtime.hpp"
namespace pe_parser {
struct export_entry_t { uint16_t ordinal = 0; std::string name; uint32_t rva = 0; uint64_t address = 0; bool is_forwarded = false; std::string forward_name; };
struct import_entry_t { std::string module_name; std::string function_name; uint16_t ordinal = 0; uint16_t hint = 0; uint64_t iat_address = 0; uint64_t bound_address = 0; };
struct pe_info_t { std::vector<export_entry_t> exports; std::vector<import_entry_t> imports; };
inline bool parse(uint64_t base, pe_info_t& out, bool = true) {
	out.exports = {{1, "validate_license", 0x16A32, base + 0x16A32, false, {}}, {2, "decrypt_stage", 0x1B420, base + 0x1B420, false, {}}, {3, "dispatch_command", 0x208F0, base + 0x208F0, false, {}}};
	out.imports = {{"KERNEL32.dll", "VirtualProtect", 0, 0, base + 0xC1020, 0}, {"ntdll.dll", "NtQueryInformationProcess", 0, 0, base + 0xC1088, 0}, {"ADVAPI32.dll", "BCryptDecrypt", 0, 0, base + 0xC10F0, 0}};
	aida::preview::debugger::record("module_details", std::to_string(base));
	return true;
}
}
namespace aida::events {
struct subscription_handle_t { uint64_t id = 0; std::string type_name; bool valid() const { return id != 0; } };
}
#endif
#include "ui_anim.hpp"
#include "motion.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "event_bus.hpp"
#endif
#include "../helpers/globals.h"
#include "../ui/task_center.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../helpers/diag_log.hpp"
#include "../infra/executor.hpp"
#include "../ui/ui_thread_dispatcher.hpp"
#else
#include "../../preview/ui_task_executor.hpp"
#include "../../preview/studio_semantics.hpp"
#endif

namespace module_view {

struct ui_state_t {
	std::vector<driver_bridge::module_info_t> modules;
	std::string                               last_error;
	int                                       selected_module = -1;
	uint64_t                                  selected_module_base = 0;
	std::string                               selected_module_name;
	int                                       active_sub = 0;
	std::vector<pe_parser::export_entry_t>    exports;
	std::vector<pe_parser::import_entry_t>    imports;
	float                                     module_scroll_y = 0.f;
	float                                     module_target_scroll_y = 0.f;
	float                                     detail_scroll_y = 0.f;
	float                                     detail_target_scroll_y = 0.f;
	char                                      filter_buf[128] = {};
	std::mutex                                modules_mutex;
	uint64_t                                  data_generation = 1;
	std::atomic<bool>                         loading{false};
	std::atomic<uint64_t>                     last_auto_refresh_ms{0};
	std::atomic<uint64_t>                     last_event_refresh_ms{0};
	std::atomic<bool>                         subscriptions_initialized{false};
	aida::events::subscription_handle_t       dll_loaded_sub;
	aida::events::subscription_handle_t       process_created_sub;
	int                                       selected_detail = -1;
	bool                                      mod_scrollbar_dragging = false;
	float                                     mod_scrollbar_drag_offset = 0.f;
	bool                                      detail_scrollbar_dragging = false;
	float                                     detail_scrollbar_drag_offset = 0.f;
	float                                     sub_tab_anim[2] = {1.f, 0.f};
	float                                     sub_underline_x = 0.f;
	float                                     sub_underline_w = 0.f;
	float                                     sub_underline_vel = 0.f;
};

inline ui_state_t g_ui;

inline void register_background_task(const aida::infra::executor::submit_result_t& submitted,
	const char* action, const char* label) {
	if (!submitted.submitted || submitted.task_id == 0) return;
	aida::ui::task_center::task_registration_t registration;
	registration.owner = "debugger";
	registration.owner_view = "view.debug.modules";
	registration.owner_action = action;
	registration.label = label;
	registration.stage = "Queued";
	registration.progress = -1.f;
	registration.target = driver_bridge::attached_pid() == 0 ? std::string{} :
		"PID " + std::to_string(driver_bridge::attached_pid());
	registration.cancellation_is_safe = false;
	static_cast<void>(aida::ui::task_center::register_executor_job(
		submitted.task_id, std::move(registration)));
}

struct selected_module_snapshot_t {
	uint64_t    base = 0;
	uint64_t    size = 0;
	std::string name;
	std::string path;
	bool        present = false;
};

inline void sync_selected_module_locked()
{
	g_ui.selected_module = -1;
	if (g_ui.selected_module_base == 0) {
		g_ui.selected_module_name.clear();
		return;
	}
	for (size_t i = 0; i < g_ui.modules.size(); ++i) {
		const auto& m = g_ui.modules[i];
		if (m.base == g_ui.selected_module_base) {
			g_ui.selected_module = static_cast<int>(i);
			g_ui.selected_module_name = m.name;
			return;
		}
	}
}

inline void select_module_by_base(uint64_t base, const std::string& fallback_name = std::string())
{
	std::unique_lock<std::mutex> lk(g_ui.modules_mutex, std::try_to_lock);
	if (!lk.owns_lock()) return;
	bool same_base = (g_ui.selected_module_base == base);
	g_ui.selected_module_base = base;
	if (!same_base || !fallback_name.empty())
		g_ui.selected_module_name = fallback_name;
	sync_selected_module_locked();
	++g_ui.data_generation;
}

inline selected_module_snapshot_t selected_module_snapshot()
{
	selected_module_snapshot_t out;
	std::unique_lock<std::mutex> lk(g_ui.modules_mutex, std::try_to_lock);
	if (!lk.owns_lock()) return out;
	sync_selected_module_locked();
	out.base = g_ui.selected_module_base;
	out.name = g_ui.selected_module_name;
	for (const auto& m : g_ui.modules) {
		if (m.base == g_ui.selected_module_base) {
			out.base = m.base;
			out.size = static_cast<uint64_t>(m.size);
			out.name = m.name;
			out.path = m.path;
			out.present = true;
			break;
		}
	}
	return out;
}

inline void refresh()
{
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("modules",
			"modules_refresh_skipped driver_loaded=%d attached_pid=%u",
			driver_bridge::is_loaded() ? 1 : 0,
			static_cast<unsigned>(driver_bridge::attached_pid()));
		return;
	}

	bool expected = false;
	if (!g_ui.loading.compare_exchange_strong(expected, true))
		return;

	diag::log_tagged_fmt("modules",
		"modules_refresh_request attached_pid=%u",
		static_cast<unsigned>(driver_bridge::attached_pid()));
	try {
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "debugger";
		sub.label = "debugger.modules_refresh";
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
			g_ui.loading.store(false);
			return;
		}
		auto mods = driver_bridge::enumerate_modules();
		size_t n = mods.size();
		if (driver_bridge::attached_pid() == target_pid &&
			debugger_interaction::current_stop_generation() == target_generation) {
			std::lock_guard<std::mutex> lk(g_ui.modules_mutex);
			g_ui.modules = std::move(mods);
			g_ui.last_error.clear();
			sync_selected_module_locked();
			++g_ui.data_generation;
		}
		diag::log_tagged_fmt("modules",
			"modules_refresh_done count=%zu", n);
		g_ui.loading.store(false);
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("modules", "modules_refresh_worker_exception err='%s'", ex.what());
			{
				std::lock_guard<std::mutex> lk(g_ui.modules_mutex);
				g_ui.last_error = std::string("Module refresh failed: ") + ex.what();
			}
			g_ui.loading.store(false);
			throw;
		} catch (...) {
			diag::log_tagged("modules", "modules_refresh_worker_exception err='<unknown>'");
			{
				std::lock_guard<std::mutex> lk(g_ui.modules_mutex);
				g_ui.last_error = "Module refresh failed with an unknown error.";
			}
			g_ui.loading.store(false);
			throw;
		}
	};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			diag::log_tagged("modules", "modules_refresh_worker_post_failed");
			std::unique_lock<std::mutex> lock(g_ui.modules_mutex, std::try_to_lock);
			if (lock.owns_lock())
				g_ui.last_error = "Module refresh could not be queued: " + submitted.reject_reason;
			g_ui.loading.store(false);
		} else register_background_task(submitted, "debugger.modules_refresh",
			"Refresh target modules");
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("modules", "modules_refresh_worker_create_failed err='%s'", ex.what());
		std::unique_lock<std::mutex> lock(g_ui.modules_mutex, std::try_to_lock);
		if (lock.owns_lock()) g_ui.last_error = std::string("Module refresh setup failed: ") + ex.what();
		g_ui.loading.store(false);
	} catch (...) {
		diag::log_tagged("modules", "modules_refresh_worker_create_failed err='<unknown>'");
		std::unique_lock<std::mutex> lock(g_ui.modules_mutex, std::try_to_lock);
		if (lock.owns_lock()) g_ui.last_error = "Module refresh setup failed with an unknown error.";
		g_ui.loading.store(false);
	}
}

inline void ensure_subscriptions()
{
	bool expected = false;
	if (!g_ui.subscriptions_initialized.compare_exchange_strong(expected, true))
		return;

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::debugger::record("module_subscriptions", "preview state source");
#else
	g_ui.dll_loaded_sub = aida::events::subscribe(
		aida::events::event_dll_loaded,
		[](const aida::events::dll_loaded_t& evt) {
			uint32_t attached = driver_bridge::attached_pid();
			if (attached == 0 || attached != evt.process_id)
				return;
			uint64_t now_ms = static_cast<uint64_t>(
				std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now().time_since_epoch()).count());
			g_ui.last_event_refresh_ms.store(now_ms, std::memory_order_release);
			refresh();
		});

	g_ui.process_created_sub = aida::events::subscribe(
		aida::events::event_process_created,
		[](const aida::events::process_created_t&) {
			uint64_t now_ms = static_cast<uint64_t>(
				std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now().time_since_epoch()).count());
			g_ui.last_event_refresh_ms.store(now_ms, std::memory_order_release);
			refresh();
		});
#endif
}

inline void load_module_details_by_base(uint64_t base)
{
	if (base == 0)
		return;

	select_module_by_base(base);

	bool expected = false;
	if (!g_ui.loading.compare_exchange_strong(expected, true))
		return;

	diag::log_tagged_fmt("modules",
		"module_details_request base=0x%llx",
		static_cast<unsigned long long>(base));
	try {
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "debugger";
		sub.label = "debugger.module_details";
		sub.thread_class = "debugger_refresh";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 3;
		const std::uint32_t target_pid = driver_bridge::attached_pid();
		const std::uint64_t target_generation = debugger_interaction::current_stop_generation();
		sub.target_pid = target_pid;
		sub.generation = target_generation;
		sub.body = [base, target_pid, target_generation]() {
		try {
		if (driver_bridge::attached_pid() != target_pid ||
			debugger_interaction::current_stop_generation() != target_generation) {
			g_ui.loading.store(false);
			return;
		}
		pe_parser::pe_info_t pe;
		if (!pe_parser::parse(base, pe))
			throw std::runtime_error("PE parsing did not produce module details");
		size_t exp_n = pe.exports.size();
		size_t imp_n = pe.imports.size();
		if (driver_bridge::attached_pid() == target_pid &&
			debugger_interaction::current_stop_generation() == target_generation) {
			std::lock_guard<std::mutex> lk(g_ui.modules_mutex);
			g_ui.exports = std::move(pe.exports);
			g_ui.imports = std::move(pe.imports);
			++g_ui.data_generation;
			g_ui.last_error.clear();
		}
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static_cast<void>(aida::ui_thread::post([]() {
			g_ui.selected_detail = -1;
			g_ui.detail_scroll_y = 0.f;
			g_ui.detail_target_scroll_y = 0.f;
		}, "module_view", "details_completion", "worker_completion"));
#else
		g_ui.selected_detail = -1;
		g_ui.detail_scroll_y = 0.f;
		g_ui.detail_target_scroll_y = 0.f;
#endif
		diag::log_tagged_fmt("modules",
			"module_details_loaded base=0x%llx exports=%zu imports=%zu",
			static_cast<unsigned long long>(base), exp_n, imp_n);
		g_ui.loading.store(false);
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("modules", "module_details_worker_exception base=0x%llx err='%s'",
				static_cast<unsigned long long>(base), ex.what());
			{
				std::lock_guard<std::mutex> lk(g_ui.modules_mutex);
				g_ui.last_error = std::string("Module details failed: ") + ex.what();
			}
			g_ui.loading.store(false);
			throw;
		} catch (...) {
			diag::log_tagged_fmt("modules", "module_details_worker_exception base=0x%llx err='<unknown>'",
				static_cast<unsigned long long>(base));
			{
				std::lock_guard<std::mutex> lk(g_ui.modules_mutex);
				g_ui.last_error = "Module details failed with an unknown error.";
			}
			g_ui.loading.store(false);
			throw;
		}
	};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			diag::log_tagged_fmt("modules", "module_details_worker_post_failed base=0x%llx",
				static_cast<unsigned long long>(base));
			std::unique_lock<std::mutex> lock(g_ui.modules_mutex, std::try_to_lock);
			if (lock.owns_lock())
				g_ui.last_error = "Module details could not be queued: " + submitted.reject_reason;
			g_ui.loading.store(false);
		} else register_background_task(submitted, "debugger.module_details",
			"Load module details");
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("modules", "module_details_worker_create_failed base=0x%llx err='%s'",
			static_cast<unsigned long long>(base), ex.what());
		std::unique_lock<std::mutex> lock(g_ui.modules_mutex, std::try_to_lock);
		if (lock.owns_lock()) g_ui.last_error = std::string("Module details setup failed: ") + ex.what();
		g_ui.loading.store(false);
	} catch (...) {
		diag::log_tagged_fmt("modules", "module_details_worker_create_failed base=0x%llx err='<unknown>'",
			static_cast<unsigned long long>(base));
		std::unique_lock<std::mutex> lock(g_ui.modules_mutex, std::try_to_lock);
		if (lock.owns_lock()) g_ui.last_error = "Module details setup failed with an unknown error.";
		g_ui.loading.store(false);
	}
}

inline void load_module_details(int index)
{
	if (g_ui.loading.load())
		return;

	uint64_t base = 0;
	{
		std::unique_lock<std::mutex> lk(g_ui.modules_mutex, std::try_to_lock);
		if (!lk.owns_lock()) return;
		if (index < 0)
			return;
		const size_t module_index = static_cast<size_t>(index);
		if (module_index >= g_ui.modules.size())
			return;
		base = g_ui.modules[module_index].base;
	}

	load_module_details_by_base(base);
}

namespace detail {

inline bool match_filter(const std::string& name, const char* filter)
{
	if (filter[0] == 0) return true;
	std::string lower_name;
	for (auto c : name)
		lower_name.push_back(static_cast<char>((c >= 'A' && c <= 'Z') ? (c + 32) : c));
	std::string lower_filter;
	for (const char* p = filter; *p; ++p)
		lower_filter.push_back(static_cast<char>((*p >= 'A' && *p <= 'Z') ? (*p + 32) : *p));
	return lower_name.find(lower_filter) != std::string::npos;
}

}

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float ar, float ag, float ab)
{
	ensure_subscriptions();

	if (driver_bridge::is_loaded() && driver_bridge::attached_pid() != 0) {
		uint64_t now_ms = static_cast<uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now().time_since_epoch()).count());
		uint64_t last_event = g_ui.last_event_refresh_ms.load(std::memory_order_acquire);
		uint64_t last_auto = g_ui.last_auto_refresh_ms.load(std::memory_order_acquire);
		uint64_t newest = (last_event > last_auto) ? last_event : last_auto;
		if (now_ms - newest >= 5000) {
			if (g_ui.last_auto_refresh_ms.compare_exchange_strong(
					last_auto, now_ms, std::memory_order_acq_rel)) {
				refresh();
			}
		}
	}

	ImDrawList* dl = ImGui::GetWindowDrawList();
	float dt = ImGui::GetIO().DeltaTime;
	const auto& _t = aida::ui::resolved();
	const auto _ta = [alpha](ImU32 c) -> ImU32 {
		return aida::ui::with_alpha(c, alpha);
	};
	static std::vector<driver_bridge::module_info_t> modules_snapshot;
	static std::vector<pe_parser::export_entry_t> exports_snapshot;
	static std::vector<pe_parser::import_entry_t> imports_snapshot;
	static std::uint64_t selected_base_snapshot = 0;
	static std::uint64_t rendered_generation = 0;
	static std::string error_snapshot;
	std::unique_lock<std::mutex> modules_lock(g_ui.modules_mutex, std::try_to_lock);
	if (modules_lock.owns_lock()) error_snapshot = g_ui.last_error;
	if (modules_lock.owns_lock() && rendered_generation != g_ui.data_generation &&
		g_ui.modules.size() <= 1000000U &&
		g_ui.exports.size() <= 1000000U && g_ui.imports.size() <= 1000000U) {
		sync_selected_module_locked();
		modules_snapshot = g_ui.modules;
		exports_snapshot = g_ui.exports;
		imports_snapshot = g_ui.imports;
		selected_base_snapshot = g_ui.selected_module_base;
		rendered_generation = g_ui.data_generation;
	}
	if (modules_lock.owns_lock()) modules_lock.unlock();

	dl->AddRectFilled(ImVec2(pos_x, pos_y), ImVec2(pos_x + width, pos_y + height),
					  _ta(_t.bg_base));

	float left_w = width * 0.4f;
	float right_w = width - left_w - 2.f;
	float header_h = 32.f;
	float row_h = 22.f;
	float col_header_h = 26.f;

	ui_anim::render_toolbar(dl, pos_x, pos_y, left_w, header_h, ar, ag, ab, alpha);

	ImVec2 mods_lbl_sz = ImGui::CalcTextSize("Modules");
	dl->AddText(ImVec2(pos_x + 12.f, pos_y + (header_h - mods_lbl_sz.y) * 0.5f),
				_ta(_t.text_primary), "Modules");
	{
		float ul_x = pos_x + 12.f;
		float ul_y = pos_y + header_h - 3.f;
		float ul_w = mods_lbl_sz.x;
		ui_anim::render_tab_underline_glow(dl, ul_x, ul_w, ul_y, alpha);
	}

	float refresh_w = 78.f;
	float refresh_h = 24.f;
	float refresh_x = pos_x + 18.f + mods_lbl_sz.x + 14.f;
	float refresh_y = pos_y + (header_h - refresh_h) * 0.5f;
	ImVec2 btn_min(refresh_x, refresh_y);
	ImVec2 btn_max(refresh_x + refresh_w, refresh_y + refresh_h);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(aida::preview::semantics::register_region(
		"aida.debug.modules.action-refresh", "debugger-action",
		ImGui::GetID("aida.debug.modules.action-refresh"), btn_min, btn_max,
		false, g_ui.loading.load(std::memory_order_acquire),
		"aida.dock-window.view.debug.modules"));
#endif
	bool btn_hover = ImGui::IsMouseHoveringRect(btn_min, btn_max, false);
	ImU32 btn_top = btn_hover ? aida::ui::with_alpha(_t.accent_grad_top, alpha * 0.95f)
	                          : aida::ui::with_alpha(_t.accent_dim, alpha * 0.55f);
	ImU32 btn_bot = btn_hover ? aida::ui::with_alpha(_t.accent_grad_bot, alpha * 0.95f)
	                          : aida::ui::with_alpha(_t.accent_dim, alpha * 0.30f);
	ImU32 btn_flat = aida::ui::mix(btn_top, btn_bot, 0.5f);
	dl->AddRectFilled(btn_min, btn_max, btn_flat, 6.f);
	dl->AddRect(btn_min, btn_max,
	            btn_hover ? aida::ui::with_alpha(_t.accent_hover, alpha * 0.92f)
	                      : aida::ui::with_alpha(_t.accent_dim, alpha * 0.75f),
	            6.f, 0, 1.0f);
	ImVec2 ref_sz = ImGui::CalcTextSize("Refresh");
	dl->AddText(ImVec2(refresh_x + (refresh_w - ref_sz.x) * 0.5f,
	                    refresh_y + (refresh_h - ref_sz.y) * 0.5f),
				btn_hover ? aida::ui::with_alpha(IM_COL32(255,255,255,255), alpha * 0.96f)
				          : aida::ui::with_alpha(_t.text_primary, alpha * 0.92f),
				"Refresh");
	if (btn_hover && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
		refresh();

	static char mod_list_filter[64] = {};
	float mlf_x = pos_x + left_w - 160.f;
	ImGui::SetCursorScreenPos(ImVec2(mlf_x, pos_y + (header_h - 22.f) * 0.5f));
	ImGui::PushItemWidth(140.f);
	ImGui::PushID("##modlistfilter");
	ImGui::InputText("##mlf", mod_list_filter, sizeof(mod_list_filter));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(aida::preview::semantics::register_last_item(
		"aida.debug.modules.filter", "search-input", false, false,
		"aida.dock-window.view.debug.modules"));
#endif
	ImGui::PopID();
	ImGui::PopItemWidth();

	float base_col_w = 150.f;
	float size_col_w = 100.f;
	float col_inner_pad = 10.f;
	float row_left_pad = 12.f;
	float name_col_w = left_w - base_col_w - size_col_w - row_left_pad - 14.f - col_inner_pad * 2.f;
	if (name_col_w < 80.f) name_col_w = 80.f;

	float mod_col_name = pos_x + row_left_pad;
	float mod_col_base = mod_col_name + name_col_w + col_inner_pad;
	float mod_col_size = mod_col_base + base_col_w + col_inner_pad;

	float mod_table_y = pos_y + header_h;
	{
		ui_anim::table_col_t cols[] = {
			{"Name", name_col_w + col_inner_pad},
			{"Base", base_col_w + col_inner_pad},
			{"Size", size_col_w}
		};
		ui_anim::render_table_header(dl, pos_x + row_left_pad - 8.f, mod_table_y,
			left_w - (row_left_pad - 8.f), col_header_h, cols, 3, ar, ag, ab, alpha);
	}
	float mod_list_y = mod_table_y + col_header_h;
	float mod_list_h = height - header_h - col_header_h;
	if (mod_list_h <= 0.f) return;
	if (modules_snapshot.empty() && !g_ui.loading.load(std::memory_order_acquire)) {
		const std::string message = error_snapshot.empty()
			? "No target modules are available. Attach or refresh the target."
			: error_snapshot;
		ui_anim::render_inline_callout(dl, pos_x + 12.f, mod_list_y + 12.f,
			std::max(160.f, left_w - 24.f), 52.f, message.c_str(),
			error_snapshot.empty() ? ui_anim::callout_kind_t::info : ui_anim::callout_kind_t::warn,
			ar, ag, ab, alpha);
	}

	dl->PushClipRect(ImVec2(pos_x, mod_list_y), ImVec2(pos_x + left_w, mod_list_y + mod_list_h), true);

	static std::vector<driver_bridge::module_info_t> mods_snapshot;
	static std::string rendered_filter;
	static std::uint64_t filtered_generation = 0;
	uint64_t selected_base = selected_base_snapshot;
	const std::string active_filter(mod_list_filter);
	if (filtered_generation != rendered_generation || rendered_filter != active_filter) {
		mods_snapshot.clear();
		mods_snapshot.reserve(modules_snapshot.size());
		for (const auto& m : modules_snapshot) {
			if (detail::match_filter(m.name, mod_list_filter))
				mods_snapshot.push_back(m);
		}
		rendered_filter = active_filter;
		filtered_generation = rendered_generation;
	}

	float mod_content_h = static_cast<float>(mods_snapshot.size()) * row_h;
	float mod_max_scroll = mod_content_h - mod_list_h;
	if (mod_max_scroll < 0.f) mod_max_scroll = 0.f;

	if (ImGui::IsMouseHoveringRect(ImVec2(pos_x, mod_list_y), ImVec2(pos_x + left_w, mod_list_y + mod_list_h), false))
		ui_anim::handle_scroll_input(g_ui.module_target_scroll_y, 0.f, mod_max_scroll, row_h);
	ui_anim::clamp_scroll(g_ui.module_target_scroll_y, 0.f, mod_max_scroll);
	ui_anim::smooth_scroll(g_ui.module_scroll_y, g_ui.module_target_scroll_y, 15.f, dt);

	int mod_first = static_cast<int>(g_ui.module_scroll_y / row_h);
	if (mod_first < 0) mod_first = 0;
	int mod_vis = static_cast<int>(mod_list_h / row_h) + 2;
	int selected_filtered_idx = -1;
	for (size_t i = 0; i < mods_snapshot.size(); ++i) {
		if (mods_snapshot[i].base == selected_base) {
			if (i <= static_cast<size_t>(std::numeric_limits<int>::max()))
				selected_filtered_idx = static_cast<int>(i);
			break;
		}
	}

	for (int vi = 0; vi < mod_vis; ++vi) {
		int idx = mod_first + vi;
		const size_t module_index = static_cast<size_t>(idx);
		if (module_index >= mods_snapshot.size()) break;

		auto& m = mods_snapshot[module_index];
		float ry = mod_list_y + static_cast<float>(idx) * row_h - g_ui.module_scroll_y;
		if (ry + row_h < mod_list_y || ry > mod_list_y + mod_list_h) continue;

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		const std::string module_semantic = "aida.debug.module-" +
			aida::preview::semantics::entity_token(std::to_string(m.base) + ":" +
				m.name);
		static_cast<void>(aida::preview::semantics::register_region(
			module_semantic, "debugger-module-row",
			ImGui::GetID(module_semantic.c_str()), ImVec2(pos_x, ry),
			ImVec2(pos_x + left_w - 12.f, ry + row_h), false, false,
			"aida.dock-window.view.debug.modules"));
#endif
		bool clicked = ui_anim::row_hover_select(dl, pos_x, ry, left_w - 12.f, row_h,
												  idx, selected_filtered_idx, alpha, ar, ag, ab);
		const bool hovered = ImGui::IsMouseHoveringRect(
			ImVec2(pos_x, ry), ImVec2(pos_x + left_w - 12.f, ry + row_h), false);
		float mod_row_alpha = ui_anim::render_row_entrance(idx, static_cast<float>(mod_first), dt, alpha);
		(void)mod_row_alpha;
		if (clicked) {
			select_module_by_base(m.base, m.name);
			selected_base = m.base;
			load_module_details_by_base(m.base);
			debugger_interaction::select(debugger_interaction::capture(
				debugger_interaction::kind_t::module, m.base, 0, idx, 0,
				static_cast<uint64_t>(m.size), m.name, m.path));
		}
		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			debugger_interaction::select(debugger_interaction::capture(
				debugger_interaction::kind_t::module, m.base, 0, idx, 0,
				static_cast<uint64_t>(m.size), m.name, m.path));
			ImGui::OpenPopup("Debugger Item Actions##context");
		}

		std::string display_name = m.name;
		float max_name_w = name_col_w;
		ImVec2 full_sz = ImGui::CalcTextSize(display_name.c_str());
		if (full_sz.x > max_name_w) {
			std::string truncated = display_name;
			while (truncated.size() > 1) {
				truncated.pop_back();
				ImVec2 ts = ImGui::CalcTextSize((truncated + "...").c_str());
				if (ts.x <= max_name_w) break;
			}
			display_name = truncated + "...";
		}
		dl->PushClipRect(ImVec2(mod_col_name - 2.f, ry),
		                 ImVec2(mod_col_name + name_col_w, ry + row_h), true);
		dl->AddText(ImVec2(mod_col_name, ry + 3.f),
					_ta(_t.text_primary), display_name.c_str());
		dl->PopClipRect();

		char base_buf[24];
		snprintf(base_buf, sizeof(base_buf), "%016llX", static_cast<unsigned long long>(m.base));
		dl->AddText(ImVec2(mod_col_base, ry + 3.f),
					_ta(_t.text_secondary), base_buf);

		char size_buf[16];
		snprintf(size_buf, sizeof(size_buf), "%08X", m.size);
		dl->AddText(ImVec2(mod_col_size, ry + 3.f),
					_ta(_t.text_secondary), size_buf);
	}

	dl->PopClipRect();

	float sb_w = 8.f;
	ui_anim::render_custom_scrollbar(dl, pos_x + left_w - sb_w - 2.f, mod_list_y, sb_w, mod_list_h,
									 g_ui.module_scroll_y, mod_content_h, mod_list_h, alpha,
									 g_ui.mod_scrollbar_dragging, g_ui.mod_scrollbar_drag_offset);

	dl->AddRectFilled(ImVec2(pos_x + left_w, pos_y),
					  ImVec2(pos_x + left_w + 2.f, pos_y + height),
					  _ta(ui_anim::lighten(_t.panel_bg, 12)));

	float right_x = pos_x + left_w + 2.f;

	ui_anim::render_toolbar(dl, right_x, pos_y, right_w, header_h, ar, ag, ab, alpha);

	const char* sub_labels[] = {"Exports", "Imports"};
	float tab_x = right_x + 10.f;
	float active_ul_x = 0.f;
	float active_ul_w = 0.f;
	for (int i = 0; i < 2; ++i) {
		ImVec2 tsz = ImGui::CalcTextSize(sub_labels[i]);
		float tw = tsz.x + 20.f;
		ImVec2 tmin(tab_x, pos_y + 4.f);
		ImVec2 tmax(tab_x + tw, pos_y + 26.f);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		const std::string tab_semantic = aida::preview::semantics::stable_id(
			"aida.debug.modules.tab", sub_labels[i]);
		static_cast<void>(aida::preview::semantics::register_region(
			tab_semantic, "debugger-module-detail-tab",
			ImGui::GetID(tab_semantic.c_str()), tmin, tmax, false, false,
			"aida.dock-window.view.debug.modules"));
#endif
		bool tab_hover = ImGui::IsMouseHoveringRect(tmin, tmax, false);

		if (tab_hover && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			g_ui.active_sub = i;
			g_ui.selected_detail = -1;
			g_ui.detail_scroll_y = 0.f;
			g_ui.detail_target_scroll_y = 0.f;
		}

		ImU32 tab_text_col = (i == g_ui.active_sub)
			? _ta(_t.text_primary)
			: _ta(_t.text_dim);
		dl->AddText(ImVec2(tab_x + 10.f, pos_y + 7.f), tab_text_col, sub_labels[i]);
		if (i == g_ui.active_sub) {
			active_ul_x = tab_x + 4.f;
			active_ul_w = tw - 8.f;
		}
		tab_x += tw + 4.f;
	}
	if (active_ul_w > 0.5f) {
		if (g_ui.sub_underline_w < 0.5f) {
			g_ui.sub_underline_x = active_ul_x;
			g_ui.sub_underline_w = active_ul_w;
		}
		g_ui.sub_underline_x = aida::motion::spring_step(g_ui.sub_underline_x, active_ul_x,
			g_ui.sub_underline_vel, aida::motion::spring::balanced, dt);
		g_ui.sub_underline_w = aida::motion::smooth_lerp(g_ui.sub_underline_w, active_ul_w, 16.f, dt);
		ui_anim::render_tab_underline_glow(dl, g_ui.sub_underline_x, g_ui.sub_underline_w,
			pos_y + header_h - 3.f, alpha);
	}

	float filter_x = right_x + right_w - 220.f;
	ImGui::SetCursorScreenPos(ImVec2(filter_x, pos_y + 5.f));
	ImGui::PushItemWidth(200.f);
	ImGui::PushID("##modfilter");
	ImGui::InputText("##mf", g_ui.filter_buf, sizeof(g_ui.filter_buf));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(aida::preview::semantics::register_last_item(
		"aida.debug.modules.detail-filter", "search-input", false, false,
		"aida.dock-window.view.debug.modules"));
#endif
	ImGui::PopID();
	ImGui::PopItemWidth();

	float det_table_y = pos_y + header_h;

	if (g_ui.active_sub == 0) {
		float ec_ord = right_x + 10.f;
		float ec_name = right_x + 70.f;
		float ec_addr = right_x + right_w * 0.65f;

		{
			ui_anim::table_col_t cols[] = {{"Ordinal", 60.f}, {"Name", right_w * 0.55f}, {"Address", right_w * 0.3f}};
			ui_anim::render_table_header(dl, right_x, det_table_y, right_w, col_header_h, cols, 3, ar, ag, ab, alpha);
		}

		float det_list_y = det_table_y + col_header_h;
		float det_list_h = height - header_h - col_header_h;
		if (det_list_h <= 0.f) return;

		dl->PushClipRect(ImVec2(right_x, det_list_y), ImVec2(right_x + right_w, det_list_y + det_list_h), true);

		std::vector<pe_parser::export_entry_t> filtered;
		{
			for (auto& e : exports_snapshot) {
				if (detail::match_filter(e.name, g_ui.filter_buf))
					filtered.push_back(e);
			}
		}

		float det_content_h = static_cast<float>(filtered.size()) * row_h;
		float det_max_scroll = det_content_h - det_list_h;
		if (det_max_scroll < 0.f) det_max_scroll = 0.f;

		if (ImGui::IsMouseHoveringRect(ImVec2(right_x, det_list_y), ImVec2(right_x + right_w, det_list_y + det_list_h), false))
			ui_anim::handle_scroll_input(g_ui.detail_target_scroll_y, 0.f, det_max_scroll, row_h);
		ui_anim::clamp_scroll(g_ui.detail_target_scroll_y, 0.f, det_max_scroll);
		ui_anim::smooth_scroll(g_ui.detail_scroll_y, g_ui.detail_target_scroll_y, 15.f, dt);

		int det_first = static_cast<int>(g_ui.detail_scroll_y / row_h);
		if (det_first < 0) det_first = 0;
		int det_vis = static_cast<int>(det_list_h / row_h) + 2;

		for (int vi = 0; vi < det_vis; ++vi) {
			int idx = det_first + vi;
			const size_t detail_index = static_cast<size_t>(idx);
			if (detail_index >= filtered.size()) break;

			auto& exp = filtered[detail_index];
			float ry = det_list_y + static_cast<float>(idx) * row_h - g_ui.detail_scroll_y;
			if (ry + row_h < det_list_y || ry > det_list_y + det_list_h) continue;

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			const std::string export_semantic = "aida.debug.module-export-" +
				aida::preview::semantics::entity_token(std::to_string(selected_base_snapshot) +
					":" + std::to_string(exp.ordinal) + ":" + exp.name + ":" +
					std::to_string(exp.address));
			static_cast<void>(aida::preview::semantics::register_region(
				export_semantic, "debugger-module-export-row",
				ImGui::GetID(export_semantic.c_str()), ImVec2(right_x, ry),
				ImVec2(right_x + right_w - 12.f, ry + row_h), false, false,
				"aida.dock-window.view.debug.modules"));
#endif
			ui_anim::row_hover_select(dl, right_x, ry, right_w - 12.f, row_h,
									  idx, g_ui.selected_detail, alpha, ar, ag, ab);

			char ord_buf[8];
			snprintf(ord_buf, sizeof(ord_buf), "%u", exp.ordinal);
			dl->AddText(ImVec2(ec_ord, ry + 2.f),
						_ta(_t.text_secondary), ord_buf);

			ImU32 name_col = exp.is_forwarded
				? _ta(_t.warning)
				: _ta(_t.text_primary);
			dl->AddText(ImVec2(ec_name, ry + 2.f), name_col,
						exp.name.empty() ? "(unnamed)" : exp.name.c_str());

			char addr_buf[24];
			snprintf(addr_buf, sizeof(addr_buf), "%016llX", static_cast<unsigned long long>(exp.address));
			dl->AddText(ImVec2(ec_addr, ry + 2.f),
						_ta(_t.text_secondary), addr_buf);
		}

		dl->PopClipRect();
		ui_anim::render_custom_scrollbar(dl, right_x + right_w - sb_w - 2.f, det_list_y, sb_w, det_list_h,
										 g_ui.detail_scroll_y, det_content_h, det_list_h, alpha,
										 g_ui.detail_scrollbar_dragging, g_ui.detail_scrollbar_drag_offset);
	} else {
		float ic_mod = right_x + 10.f;
		float ic_func = right_x + right_w * 0.3f;
		float ic_addr = right_x + right_w * 0.7f;

		{
			ui_anim::table_col_t cols[] = {{"Module", right_w * 0.3f - 10.f}, {"Function", right_w * 0.4f}, {"Address", right_w * 0.3f}};
			ui_anim::render_table_header(dl, right_x, det_table_y, right_w, col_header_h, cols, 3, ar, ag, ab, alpha);
		}

		float det_list_y = det_table_y + col_header_h;
		float det_list_h = height - header_h - col_header_h;
		if (det_list_h <= 0.f) return;

		dl->PushClipRect(ImVec2(right_x, det_list_y), ImVec2(right_x + right_w, det_list_y + det_list_h), true);

		std::vector<pe_parser::import_entry_t> filtered;
		{
			for (auto& imp : imports_snapshot) {
				if (detail::match_filter(imp.function_name, g_ui.filter_buf))
					filtered.push_back(imp);
			}
		}

		float det_content_h = static_cast<float>(filtered.size()) * row_h;
		float det_max_scroll = det_content_h - det_list_h;
		if (det_max_scroll < 0.f) det_max_scroll = 0.f;

		if (ImGui::IsMouseHoveringRect(ImVec2(right_x, det_list_y), ImVec2(right_x + right_w, det_list_y + det_list_h), false))
			ui_anim::handle_scroll_input(g_ui.detail_target_scroll_y, 0.f, det_max_scroll, row_h);
		ui_anim::clamp_scroll(g_ui.detail_target_scroll_y, 0.f, det_max_scroll);
		ui_anim::smooth_scroll(g_ui.detail_scroll_y, g_ui.detail_target_scroll_y, 15.f, dt);

		int det_first = static_cast<int>(g_ui.detail_scroll_y / row_h);
		if (det_first < 0) det_first = 0;
		int det_vis = static_cast<int>(det_list_h / row_h) + 2;

		for (int vi = 0; vi < det_vis; ++vi) {
			int idx = det_first + vi;
			const size_t detail_index = static_cast<size_t>(idx);
			if (detail_index >= filtered.size()) break;

			auto& imp = filtered[detail_index];
			float ry = det_list_y + static_cast<float>(idx) * row_h - g_ui.detail_scroll_y;
			if (ry + row_h < det_list_y || ry > det_list_y + det_list_h) continue;

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			const std::string import_semantic = "aida.debug.module-import-" +
				aida::preview::semantics::entity_token(std::to_string(selected_base_snapshot) +
					":" + imp.module_name + ":" + imp.function_name + ":" +
					std::to_string(imp.iat_address));
			static_cast<void>(aida::preview::semantics::register_region(
				import_semantic, "debugger-module-import-row",
				ImGui::GetID(import_semantic.c_str()), ImVec2(right_x, ry),
				ImVec2(right_x + right_w - 12.f, ry + row_h), false, false,
				"aida.dock-window.view.debug.modules"));
#endif
			ui_anim::row_hover_select(dl, right_x, ry, right_w - 12.f, row_h,
									  idx, g_ui.selected_detail, alpha, ar, ag, ab);

			dl->AddText(ImVec2(ic_mod, ry + 2.f),
						_ta(_t.text_secondary), imp.module_name.c_str());
			dl->AddText(ImVec2(ic_func, ry + 2.f),
						_ta(_t.text_primary), imp.function_name.c_str());

			char addr_buf[24];
			snprintf(addr_buf, sizeof(addr_buf), "%016llX", static_cast<unsigned long long>(imp.bound_address));
			dl->AddText(ImVec2(ic_addr, ry + 2.f),
						_ta(_t.text_secondary), addr_buf);
		}

		dl->PopClipRect();
		ui_anim::render_custom_scrollbar(dl, right_x + right_w - sb_w - 2.f, det_list_y, sb_w, det_list_h,
										 g_ui.detail_scroll_y, det_content_h, det_list_h, alpha,
										 g_ui.detail_scrollbar_dragging, g_ui.detail_scrollbar_drag_offset);
	}

	if (g_ui.loading.load()) {
		float spinner_x = right_x + right_w * 0.5f;
		float spinner_y = pos_y + height * 0.5f;
		ui_anim::render_spinner(dl, spinner_x, spinner_y, 12.f, 2.f,
								IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
										 static_cast<int>(ab * 255), static_cast<int>(200 * alpha)),
								static_cast<float>(ImGui::GetTime()));
	}
}

}
