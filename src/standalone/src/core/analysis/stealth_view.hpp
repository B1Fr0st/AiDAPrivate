#pragma once

#include "stealth_engine.hpp"
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/transition.hpp"
#include "ui/components.hpp"
#include "ui/empty_state.hpp"
#include "ui/blur_layer.hpp"
#include "ui/skeleton.hpp"
#include "ui/fonts.hpp"
#include "ui/hub_strip.hpp"
#include "ui/design_system.hpp"
#include "ui/application_view_registry.hpp"
#include "ui/application_ui_runtime.hpp"
#include "imgui/imgui.h"
#include "../helpers/globals.h"
#include "../disasm/disasm_view.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/re_hubs_preview_adapter.hpp"
#endif

namespace stealth_view {

struct local_state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	int   selected_finding = -1;
	int   category_filter = -1;
	int   severity_filter = -1;
	int   applied_category_filter = -2;
	int   applied_severity_filter = -2;
	float anim_t = 0.f;
	std::uint64_t findings_generation = 0;
	std::shared_ptr<const std::vector<stealth_engine::finding_t>> findings;
	std::vector<std::size_t> filtered_findings;
	aida::ui::hub_strip::state_t strip;
};

static local_state_t s_state;

inline aida::ui::pill_kind_t severity_pill(stealth_engine::finding_severity_t s)
{
	switch (s) {
		case stealth_engine::finding_severity_t::critical: return aida::ui::pill_kind_t::error;
		case stealth_engine::finding_severity_t::high:     return aida::ui::pill_kind_t::warning;
		case stealth_engine::finding_severity_t::medium:   return aida::ui::pill_kind_t::warning;
		case stealth_engine::finding_severity_t::low:      return aida::ui::pill_kind_t::success;
		case stealth_engine::finding_severity_t::info:     return aida::ui::pill_kind_t::info;
	}
	return aida::ui::pill_kind_t::neutral;
}

inline ImU32 severity_token(stealth_engine::finding_severity_t s, float alpha)
{
	const auto& th = aida::ui::resolved();
	switch (s) {
		case stealth_engine::finding_severity_t::critical: return aida::ui::with_alpha(th.error,   alpha);
		case stealth_engine::finding_severity_t::high:     return aida::ui::with_alpha(th.warning, alpha);
		case stealth_engine::finding_severity_t::medium:   return aida::ui::with_alpha(th.warning, alpha * 0.85f);
		case stealth_engine::finding_severity_t::low:      return aida::ui::with_alpha(th.success, alpha);
		case stealth_engine::finding_severity_t::info:     return aida::ui::with_alpha(th.info,    alpha);
	}
	return aida::ui::with_alpha(th.text_dim, alpha);
}

inline constexpr aida::ui::hub_strip::tab_t s_subtabs[] = {
	{ "Protection Scan", "scan attached process", "Scan" },
	{ "Stealth Status", "automatic anti-debug state", "Auto" },
};

inline int sub_tab_count()
{
	return static_cast<int>(sizeof(s_subtabs) / sizeof(s_subtabs[0]));
}

inline void set_sub_tab(int idx)
{
	if (idx < 0 || idx >= sub_tab_count())
		return;
	aida::ui::hub_strip::notify_select(s_state.strip, idx);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::re_hubs::select(aida::preview::re_hubs::domain_t::protection,
		idx, s_subtabs[idx].label);
#endif
}

inline int active_sub_tab()
{
	return s_state.strip.active;
}

inline const char* sub_tab_label(int idx)
{
	if (idx < 0 || idx >= sub_tab_count())
		return "";
	return s_subtabs[idx].label;
}

inline void render_protection_scan(float pos_x, float pos_y, float w, float h,
                                    float alpha, ImDrawList* dl, ImVec2 wp)
{
	auto& st = s_state;
	const auto& th = aida::ui::resolved();
	static_cast<void>(dl);
	static_cast<void>(th);
	static_cast<void>(alpha);
	const auto metrics = aida::ui::design::metrics();
	const bool scanning = stealth_engine::g_scan.scanning.load(std::memory_order_acquire);
	const auto findings = stealth_engine::capture_protection_findings();
	const std::uint64_t generation = stealth_engine::g_scan.generation.load(std::memory_order_acquire);
	if (generation != st.findings_generation || findings != st.findings ||
		st.applied_category_filter != st.category_filter ||
		st.applied_severity_filter != st.severity_filter) {
		st.findings = findings;
		st.findings_generation = generation;
		st.applied_category_filter = st.category_filter;
		st.applied_severity_filter = st.severity_filter;
		st.filtered_findings.clear();
		if (findings) {
			st.filtered_findings.reserve(findings->size());
			for (std::size_t index = 0; index < findings->size(); ++index) {
				const auto& finding = (*findings)[index];
				if (st.severity_filter >= 0 &&
					static_cast<int>(finding.severity) != 4 - st.severity_filter)
					continue;
				if (st.category_filter >= 0 &&
					static_cast<int>(finding.category) != st.category_filter)
					continue;
				st.filtered_findings.push_back(index);
			}
		}
		if (!findings || st.selected_finding < 0 ||
			static_cast<std::size_t>(st.selected_finding) >= findings->size())
			st.selected_finding = -1;
	}

	ImGui::SetCursorScreenPos(ImVec2(wp.x + pos_x + metrics.spacing_sm,
		wp.y + pos_y + metrics.spacing_xs));
	ImGui::PushID("protection_scan");
	const bool has_findings = findings && !findings->empty();
	const aida::ui::design::action_t actions[] = {
		{"scan", "Scan", "Scan", "Scan the attached process for protection mechanisms",
			nullptr, nullptr, aida::ui::components::button_kind_t::primary,
			!scanning, false, true},
		{"stop", "Stop", "Stop", "Request cancellation of the active protection scan",
			nullptr, nullptr, aida::ui::components::button_kind_t::destructive,
			scanning, false, true},
		{"clear", "Clear", "Clear", "Clear the retained protection findings",
			nullptr, "Removes the retained scan result", aida::ui::components::button_kind_t::ghost,
			has_findings && !scanning, false, true}
	};
	const auto action = aida::ui::design::render_toolbar("protection.scan", actions,
		sizeof(actions) / sizeof(actions[0]), w - metrics.spacing_sm * 2.f);
	if (action.invoked && action.id) {
		if (std::strcmp(action.id, "scan") == 0) {
			diag::log_tagged("stealth", "view_scan_request");
			stealth_engine::run_protection_scan();
		} else if (std::strcmp(action.id, "stop") == 0) {
			diag::log_tagged("stealth", "view_scan_stop");
			stealth_engine::stop_protection_scan();
		} else if (std::strcmp(action.id, "clear") == 0) {
			std::size_t cleared = 0;
			if (stealth_engine::clear_protection_findings(cleared)) {
				st.selected_finding = -1;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::protection,
					0, "protection.clear", std::to_string(cleared) + " findings cleared");
#endif
				diag::log_tagged_fmt("stealth", "view_findings_cleared count=%zu", cleared);
			}
		}
	}

	const char* severities[] = {"All severities", "Critical", "High", "Medium", "Low", "Info"};
	const char* categories[] = {"All categories", "AC Driver", "Memory Guard", "Suspicious Module",
		"Thread", "Debug State", "Hook", "WFP Callback"};
	const float inner_width = (std::max)(1.f, w - metrics.spacing_sm * 2.f);
	const float filter_width = (std::max)(120.f * metrics.scale,
		(inner_width - metrics.spacing_sm) * 0.5f);
	ImGui::SetNextItemWidth(filter_width);
	int severity = st.severity_filter + 1;
	if (ImGui::Combo("##severity", &severity, severities, 6))
		st.severity_filter = severity - 1;
	aida::ui::design::tooltip_for_last_item("Filter findings by severity");
	aida::ui::design::draw_focus_ring_for_last_item();
	ImGui::SameLine(0.f, metrics.spacing_sm);
	ImGui::SetNextItemWidth((std::max)(1.f, inner_width - filter_width - metrics.spacing_sm));
	int category = st.category_filter + 1;
	if (ImGui::Combo("##category", &category, categories, 8))
		st.category_filter = category - 1;
	aida::ui::design::tooltip_for_last_item("Filter findings by category");
	aida::ui::design::draw_focus_ring_for_last_item();

	const auto status = stealth_engine::capture_protection_scan_status();
	if (scanning) {
		ImGui::ProgressBar(stealth_engine::g_scan.progress.load(std::memory_order_acquire),
			ImVec2(inner_width, metrics.control_height * 0.72f),
			status && !status->empty() ? status->c_str() : "Scanning");
	} else if (status && !status->empty()) {
		ImGui::TextDisabled("%s", status->c_str());
	}

	const float summary_height = metrics.control_height + metrics.spacing_sm;
	const float table_height = (std::max)(80.f * metrics.scale,
		wp.y + pos_y + h - ImGui::GetCursorScreenPos().y - summary_height);
	if (!has_findings && !scanning) {
		aida::ui::design::state_presentation_t empty;
		empty.stable_id = "protection.scan.empty";
		empty.state = aida::ui::design::view_state_t::empty;
		empty.title = "No protection findings";
		empty.message = "Run a scan to inspect the attached process for protection mechanisms.";
		empty.hint = "Scan remains available from this toolbar and the command surface.";
		aida::ui::design::render_state(empty, ImVec2(inner_width, table_height));
	} else if (st.filtered_findings.empty() && !scanning) {
		aida::ui::design::state_presentation_t empty;
		empty.stable_id = "protection.scan.filtered-empty";
		empty.state = aida::ui::design::view_state_t::empty;
		empty.title = "No matching findings";
		empty.message = "No retained finding matches the selected severity and category filters.";
		empty.hint = "Choose broader filters to restore hidden findings.";
		aida::ui::design::render_state(empty, ImVec2(inner_width, table_height));
	} else if (ImGui::BeginTable("##findings", 5,
		ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
		ImGuiTableFlags_BordersOuter | ImGuiTableFlags_Resizable |
		ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
		ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
		ImVec2(inner_width, table_height))) {
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 88.f * metrics.scale);
		ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, 124.f * metrics.scale);
		ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 142.f * metrics.scale);
		ImGui::TableSetupColumn("Finding", ImGuiTableColumnFlags_WidthStretch, 0.9f);
		ImGui::TableSetupColumn("Details", ImGuiTableColumnFlags_WidthStretch, 1.3f);
		ImGui::TableHeadersRow();
		if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
			!ImGui::GetIO().WantTextInput && !st.filtered_findings.empty()) {
			auto selected = std::find(st.filtered_findings.begin(), st.filtered_findings.end(),
				static_cast<std::size_t>((std::max)(st.selected_finding, 0)));
			if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, false)) {
				if (selected == st.filtered_findings.end()) selected = st.filtered_findings.begin();
				else if (++selected == st.filtered_findings.end()) --selected;
				st.selected_finding = static_cast<int>(*selected);
			} else if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, false)) {
				if (selected == st.filtered_findings.end()) selected = st.filtered_findings.begin();
				else if (selected != st.filtered_findings.begin()) --selected;
				st.selected_finding = static_cast<int>(*selected);
			}
		}
		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(st.filtered_findings.size()), metrics.table_row_height);
		while (clipper.Step()) {
			for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
				const std::size_t source_index = st.filtered_findings[static_cast<std::size_t>(row)];
				const auto& finding = (*findings)[source_index];
				ImGui::PushID(static_cast<int>(source_index));
				ImGui::TableNextRow(ImGuiTableRowFlags_None, metrics.table_row_height);
				ImGui::TableSetColumnIndex(0);
				const bool selected = st.selected_finding == static_cast<int>(source_index);
				if (ImGui::Selectable(stealth_engine::severity_name(finding.severity), selected,
					ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick,
					ImVec2(0.f, metrics.table_row_height))) {
					st.selected_finding = static_cast<int>(source_index);
					if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && finding.address != 0) {
						disasm_view::goto_address(finding.address,
							disasm_view::capture_selected_workspace());
						aida::ui::application_views::open_or_focus(
							aida::ui::stable_view_id_t("document.disassembly"));
					}
				}
				if (ImGui::IsItemHovered() && !finding.detail.empty())
					ImGui::SetTooltip("%s", finding.detail.c_str());
				const bool keyboard_context = selected &&
					aida::ui::design::selection_context_requested();
				const bool pointer_context = ImGui::IsItemClicked(ImGuiMouseButton_Right);
				if (pointer_context || keyboard_context) {
					st.selected_finding = static_cast<int>(source_index);
					aida::ui::application_ui::retained_entity_context_t retained;
					retained.owner_id = "analysis.protection.finding";
					retained.entity_id = std::to_string(source_index) + ":" + finding.title;
					retained.entity_generation = generation;
					retained.active_view = aida::ui::stable_view_id_t("view.analysis.protection");
					retained.validate_identity = [source_index, generation, findings] {
						if (stealth_engine::g_scan.generation.load(std::memory_order_acquire) != generation ||
							stealth_engine::capture_protection_findings() != findings)
							return aida::ui::capability_state_t::unavailable(
								"The protection scan publication changed; select the finding again");
						return source_index < findings->size()
							? aida::ui::capability_state_t::available()
							: aida::ui::capability_state_t::unavailable(
								"The retained finding no longer exists");
					};
					auto add_action = [&retained](const char* id, bool enabled,
						const char* reason, auto invoke) {
						aida::ui::application_ui::retained_entity_action_t action;
						action.action_id = id;
						action.capability = enabled
							? aida::ui::capability_state_t::available()
							: aida::ui::capability_state_t::unavailable(reason);
						action.invoke = std::move(invoke);
						retained.actions.push_back(std::move(action));
					};
					const std::uint64_t address = finding.address;
					add_action("analysis.protection.finding.follow_disassembly", address != 0,
						"This finding has no concrete address", [address] {
							disasm_view::goto_address(address,
								disasm_view::capture_selected_workspace());
							aida::ui::application_views::open_or_focus(
								aida::ui::stable_view_id_t("document.disassembly"));
							return aida::ui::action_handler_result_t::completed();
						});
					add_action("analysis.protection.finding.copy_address", address != 0,
						"This finding has no concrete address", [address] {
							char text[32]{};
							std::snprintf(text, sizeof(text), "0x%llX",
								static_cast<unsigned long long>(address));
							ImGui::SetClipboardText(text);
							return aida::ui::action_handler_result_t::completed();
						});
					const std::string title = finding.title;
					const std::string detail = finding.detail;
					const std::string module = finding.module;
					add_action("analysis.protection.finding.copy_title", true, "", [title] {
						ImGui::SetClipboardText(title.c_str());
						return aida::ui::action_handler_result_t::completed();
					});
					add_action("analysis.protection.finding.copy_details", !detail.empty(),
						"This finding has no detail text", [detail] {
						ImGui::SetClipboardText(detail.c_str());
						return aida::ui::action_handler_result_t::completed();
					});
					add_action("analysis.protection.finding.copy_module", !module.empty(),
						"This finding is not associated with a module", [module] {
						ImGui::SetClipboardText(module.c_str());
						return aida::ui::action_handler_result_t::completed();
					});
					aida::ui::application_ui::open_retained_entity_context_menu(
						std::move(retained), pointer_context
							? aida::ui::context_menu_open_origin_t::pointer
							: ImGui::IsKeyPressed(ImGuiKey_Menu, false)
							? aida::ui::context_menu_open_origin_t::menu_key
							: aida::ui::context_menu_open_origin_t::shift_f10);
				}
				aida::ui::application_ui::render_retained_entity_context_menu(
					"analysis.protection.finding");
				ImGui::TableSetColumnIndex(1);
				ImGui::TextUnformatted(stealth_engine::category_name(finding.category));
				ImGui::TableSetColumnIndex(2);
				if (finding.address != 0) ImGui::Text("0x%llX", static_cast<unsigned long long>(finding.address));
				else ImGui::TextDisabled("-");
				ImGui::TableSetColumnIndex(3);
				ImGui::TextUnformatted(finding.title.c_str());
				ImGui::TableSetColumnIndex(4);
				ImGui::TextUnformatted(finding.detail.c_str());
				ImGui::PopID();
			}
		}
		ImGui::EndTable();
	}

	int critical = 0, high = 0, medium = 0, low = 0, info = 0;
	if (findings) {
		for (const std::size_t index : st.filtered_findings) {
			switch ((*findings)[index].severity) {
			case stealth_engine::finding_severity_t::critical: ++critical; break;
			case stealth_engine::finding_severity_t::high: ++high; break;
			case stealth_engine::finding_severity_t::medium: ++medium; break;
			case stealth_engine::finding_severity_t::low: ++low; break;
			case stealth_engine::finding_severity_t::info: ++info; break;
			}
		}
	}
	ImGui::TextDisabled("%zu shown", st.filtered_findings.size());
	ImGui::SameLine();
	const std::string critical_status = std::to_string(critical) + " critical";
	const std::string high_status = std::to_string(high) + " high";
	aida::ui::components::status_badge(critical_status.c_str(),
		aida::ui::components::status_kind_t::error);
	ImGui::SameLine();
	aida::ui::components::status_badge(high_status.c_str(),
		aida::ui::components::status_kind_t::warning);
	ImGui::SameLine();
	ImGui::TextDisabled("Medium %d  Low %d  Info %d", medium, low, info);
	ImGui::PopID();
}

inline void render_stealth_controls(float pos_x, float pos_y, float w, float h,
                                     float alpha, ImDrawList* dl, ImVec2 wp)
{
	const auto& th = aida::ui::resolved();
	float ox = wp.x;
	float oy = wp.y;
	const float pad = 12.f;

	float cy = oy + pos_y + 6.f;
	float cx = ox + pos_x + pad;

	const float toolbar_h = 70.f;
	ImU32 bar_top = aida::ui::with_alpha(th.panel_header, alpha * 0.85f);
	ImU32 bar_bot = aida::ui::with_alpha(th.panel_bg, alpha * 0.85f);
	dl->AddRectFilledMultiColor(ImVec2(ox + pos_x, cy), ImVec2(ox + pos_x + w, cy + toolbar_h),
		bar_top, bar_top, bar_bot, bar_bot);
	dl->AddLine(ImVec2(ox + pos_x, cy + toolbar_h - 1.f), ImVec2(ox + pos_x + w, cy + toolbar_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	bool stealth_active = stealth_engine::is_active();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const uint32_t attached_pid = 4242;
#else
	const uint32_t attached_pid = driver_bridge::attached_pid();
#endif
	const std::string status_str = stealth_engine::get_status();

	ImFont* status_font = aida::ui::fonts::body_em();
	if (!status_font) status_font = ImGui::GetFont();
	ImU32 status_col = stealth_active
		? aida::ui::with_alpha(th.success, alpha)
		: aida::ui::with_alpha(th.text_dim, alpha);
	const char* state_text = stealth_active ? "Automatic stealth active" : "Automatic stealth idle";
	dl->AddText(status_font, 14.f, ImVec2(cx, cy + 10.f), status_col, state_text);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	char target_buf[96];
	if (attached_pid != 0) {
		std::snprintf(target_buf, sizeof(target_buf), "Attached PID %u", attached_pid);
	} else {
		std::snprintf(target_buf, sizeof(target_buf), "Attach a process to arm stealth automatically");
	}
	dl->AddText(body_font, 12.f, ImVec2(cx, cy + 30.f),
		aida::ui::with_alpha(th.text_secondary, alpha), target_buf);

	if (!status_str.empty()) {
		dl->AddText(body_font, 12.f, ImVec2(cx, cy + 48.f),
			aida::ui::with_alpha(th.text_dim, alpha), status_str.c_str());
	}

	cy += toolbar_h + 6.f;
	float hy = cy;

	const float row_h = 28.f;
	std::vector<stealth_engine::hook_entry_t> hooks_copy;
	bool peb_ok = false;
	bool rdtsc_ok = false;
	uint32_t session_pid = 0;
	{
		std::lock_guard<std::mutex> lk(stealth_engine::g_state.mutex);
		hooks_copy = stealth_engine::g_state.session.hooks;
		peb_ok = stealth_engine::g_state.session.peb_spoofed;
		rdtsc_ok = stealth_engine::g_state.session.rdtsc_hooked;
		session_pid = stealth_engine::g_state.session.pid;
	}

	const float col_target_w = 170.f;
	const float col_tramp_w  = 170.f;
	const float col_size_w   = 70.f;
	const float col_peb_w    = 70.f;
	const float col_active_w = 80.f;

	ImU32 hdr_bg = aida::ui::with_alpha(th.panel_header, alpha * 0.9f);
	dl->AddRectFilled(ImVec2(cx, hy), ImVec2(ox + pos_x + w - pad, hy + row_h), hdr_bg, 6.f);
	dl->AddLine(ImVec2(cx, hy + row_h - 1.f), ImVec2(ox + pos_x + w - pad, hy + row_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	ImFont* head_em = aida::ui::fonts::body_em();
	if (!head_em) head_em = ImGui::GetFont();
	ImU32 hc = aida::ui::with_alpha(th.text_secondary, alpha);
	float hx = cx + 6.f;
	dl->AddText(head_em, 13.f, ImVec2(hx, hy + 7.f), hc, "Target Address");
	hx += col_target_w;
	dl->AddText(head_em, 13.f, ImVec2(hx, hy + 7.f), hc, "Trampoline");
	hx += col_tramp_w;
	dl->AddText(head_em, 13.f, ImVec2(hx, hy + 7.f), hc, "Size");
	hx += col_size_w;
	dl->AddText(head_em, 13.f, ImVec2(hx, hy + 7.f), hc, "PEB");
	hx += col_peb_w;
	dl->AddText(head_em, 13.f, ImVec2(hx, hy + 7.f), hc, "Active");
	hy += row_h;

	int total_rows = static_cast<int>(hooks_copy.size());
	if (total_rows == 0 && stealth_active) {
		float card_y = hy + 8.f;
		float card_w = (w - pad * 2.f - 8.f) / 3.f;
		float sx = cx;

		auto draw_card = [&](const char* lbl, const char* val, ImU32 col) {
			ImVec2 ba = ImVec2(sx, card_y);
			ImVec2 bb = ImVec2(sx + card_w - 4.f, card_y + 44.f);
			aida::ui::blur::render_glass_fill(dl, ba, bb, 8.f, alpha);
			aida::ui::blur::render_glass_border(dl, ba, bb, 8.f, alpha, 1.f);
			ImFont* num = aida::ui::fonts::body_strong();
			if (!num) num = ImGui::GetFont();
			dl->AddText(num, 18.f, ImVec2(ba.x + 12.f, ba.y + 4.f), col, val);
			dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
				10.f, ImVec2(ba.x + 12.f, ba.y + 28.f),
				aida::ui::with_alpha(th.text_dim, alpha), lbl);
			sx += card_w;
		};

		char b_pid[16];
		std::snprintf(b_pid, sizeof(b_pid), "%u", session_pid);
		draw_card("Target PID", b_pid, aida::ui::with_alpha(th.accent_u32, alpha));
		draw_card("PEB Spoofed", peb_ok ? "Active" : "Inactive",
			peb_ok ? aida::ui::with_alpha(th.success, alpha) : aida::ui::with_alpha(th.error, alpha));
		draw_card("RDTSC Hook", rdtsc_ok ? "Active" : "Inactive",
			rdtsc_ok ? aida::ui::with_alpha(th.success, alpha) : aida::ui::with_alpha(th.error, alpha));
	}

	for (int i = 0; i < total_rows; ++i) {
		float ry = hy + static_cast<float>(i) * row_h;
		if (ry > oy + pos_y + h) break;

		auto& hook = hooks_copy[static_cast<size_t>(i)];
		bool hovered = ImGui::IsMouseHoveringRect(
			ImVec2(cx, ry), ImVec2(ox + pos_x + w - pad, ry + row_h));
		ImU32 row_fill = hovered
			? aida::ui::with_alpha(th.hover_wash, alpha)
			: ((i & 1) ? aida::ui::with_alpha(th.panel_bg, alpha * 0.45f) : 0u);
		if ((row_fill & 0xFF000000) != 0) {
			dl->AddRectFilled(ImVec2(cx, ry), ImVec2(ox + pos_x + w - pad, ry + row_h),
				row_fill, 4.f);
		}

		float rx = cx + 6.f;
		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();
		char addr_buf[24];
		std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
			static_cast<unsigned long long>(hook.target_addr));
		dl->AddText(code_font, 13.f, ImVec2(rx, ry + 7.f),
			aida::ui::with_alpha(th.text_address, alpha), addr_buf);
		rx += col_target_w;

		char tramp_buf[24];
		std::snprintf(tramp_buf, sizeof(tramp_buf), "0x%llX",
			static_cast<unsigned long long>(hook.trampoline_addr));
		dl->AddText(code_font, 13.f, ImVec2(rx, ry + 7.f),
			aida::ui::with_alpha(th.text_dim, alpha), tramp_buf);
		rx += col_tramp_w;

		char size_buf[8];
		std::snprintf(size_buf, sizeof(size_buf), "%d", hook.hook_size);
		dl->AddText(code_font, 13.f, ImVec2(rx, ry + 7.f),
			aida::ui::with_alpha(th.text_primary, alpha), size_buf);
		rx += col_size_w;

		ImU32 peb_col = peb_ok
			? aida::ui::with_alpha(th.success, alpha)
			: aida::ui::with_alpha(th.error, alpha);
		dl->AddText(code_font, 13.f, ImVec2(rx, ry + 7.f), peb_col, peb_ok ? "yes" : "no");
		rx += col_peb_w;

		ImU32 dot_col = hook.active
			? aida::ui::with_alpha(th.success, alpha)
			: aida::ui::with_alpha(th.error, alpha);
		aida::ui::components::status_dot(ImVec2(rx + 6.f, ry + row_h * 0.5f), 3.f,
			dot_col, hook.active, 1.4f);
		dl->AddText(code_font, 13.f, ImVec2(rx + 18.f, ry + 7.f),
			dot_col, hook.active ? "active" : "removed");
		(void)col_active_w;
	}

	if (total_rows == 0 && !stealth_active) {
		ImVec2 e_pos = ImVec2(ox + pos_x, hy + 6.f);
		ImVec2 e_sz = ImVec2(w, oy + pos_y + h - hy - 14.f);
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::shield;
		cfg.title = "Stealth auto-armed";
		cfg.body = "Attach a process to install default anti-debug protection automatically.";
		cfg.max_width = 360.f;
		aida::ui::empty_state::render(e_pos, e_sz, cfg);
	}
}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	(void)accent_r; (void)accent_g; (void)accent_b;

	ImGui::BeginChild("##protection_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;

	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	float w = width;
	float h = height;

	const auto& th = aida::ui::resolved();
	const float dt = aida::ui::clock::dt();
	st.anim_t += dt;

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		aida::ui::with_alpha(th.bg_base, alpha));

	const int subtab_count = static_cast<int>(sizeof(s_subtabs) / sizeof(s_subtabs[0]));
	aida::ui::hub_strip::render_strip(dl, wp, pos_x, pos_y, w,
		s_subtabs, subtab_count, st.strip, alpha);
	aida::ui::hub_strip::tick_swap(st.strip, dt);

	const float tab_h = 30.f;
	float content_pos_y = pos_y + tab_h + 2.f;
	float content_h = h - tab_h - 2.f;
	if (content_h < 1.f) {
		ImGui::EndChild();
		return;
	}

	int prev_idx = st.strip.prev;
	int new_idx  = st.strip.active;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (new_idx >= 0 && new_idx < subtab_count)
		aida::preview::re_hubs::rendered(aida::preview::re_hubs::domain_t::protection,
			new_idx, s_subtabs[new_idx].label);
#endif

	auto render_tab = [&](int idx) {
		if (idx == 0) render_protection_scan(pos_x, content_pos_y, w, content_h, alpha, dl, wp);
		else          render_stealth_controls(pos_x, content_pos_y, w, content_h, alpha, dl, wp);
	};

	if (!st.strip.swap_pending) {
		render_tab(new_idx);
	} else {
		float p = aida::ui::hub_strip::ease_out_cubic(st.strip.swap_progress);
		float slide = w * 0.06f * st.strip.direction_sign;
		float prev_off = -slide * p;
		float new_off  = slide * (1.f - p);

		ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * (1.f - p));
		render_tab(prev_idx);
		ImGui::PopStyleVar();
		(void)prev_off; (void)new_off;
		ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * p);
		render_tab(new_idx);
		ImGui::PopStyleVar();
	}

	ImGui::EndChild();
}

}
