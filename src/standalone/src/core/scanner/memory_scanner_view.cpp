#include "memory_scanner_view.hpp"
#include "memory_scanner.hpp"
#include "standalone_driver.hpp"
#include "../anti-tamper/webhook.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "disasm_view.hpp"
#include "../disasm/function_index.hpp"
#include "hex_view.hpp"
#include "../helpers/globals.h"
#include "../helpers/helpers.h"
#include "../helpers/diag_log.hpp"
#include "../infra/executor.hpp"
#include "ui_anim.hpp"
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/fonts.hpp"
#include "../ui/toast_notification.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <unordered_set>

namespace memory_scanner_view {

namespace {

constexpr float kToolbarHeight       = 56.f;
constexpr float kResultHeaderHeight  = 32.f;
constexpr float kResultRowHeight     = 30.f;
constexpr float kAddrHeaderHeight    = 32.f;
constexpr float kAddrTableHeaderH    = 26.f;
constexpr float kAddrRowHeight       = 30.f;
constexpr float kScrollbarTrackW     = 14.f;
constexpr float kSplitterThickness   = 6.f;
constexpr float kCalloutHeight       = 30.f;
constexpr int   kRegionRefreshChunk  = 4096;

constexpr int kColResultAddr     = 0;
constexpr int kColResultValue    = 1;
constexpr int kColResultPrevious = 2;
constexpr int kColResultModule   = 3;

constexpr int kColAddrFreeze     = 0;
constexpr int kColAddrDesc       = 1;
constexpr int kColAddrAddress    = 2;
constexpr int kColAddrType       = 3;
constexpr int kColAddrValue      = 4;

struct column_layout_t {
	float x0 = 0.f;
	float x1 = 0.f;
	float inner_x0 = 0.f;
	float inner_x1 = 0.f;
	const char* title = "";
};

std::atomic<bool> s_open_result_ctx{false};
std::atomic<bool> s_open_address_ctx{false};
std::atomic<bool> s_open_add_dialog{false};
std::atomic<uint64_t> s_pending_add_addr{0};
std::atomic<int> s_pending_add_vtype{0};
std::atomic<int> s_pending_edit_value_index{-1};
char s_edit_value_buf[128] = {};
std::atomic<int> s_pending_change_type_index{-1};
int s_pending_change_type_value = 0;

std::atomic<int>       s_view_owned_ctx_addr_row{-1};
std::atomic<uint64_t>  s_view_owned_ctx_addr_value{0};
std::atomic<uint64_t>  s_view_owned_ctx_result_addr{0};

bool input_is_active() {
	return ImGui::GetActiveID() != 0 && ImGui::IsAnyItemActive();
}

const char* region_kind_label(uint32_t type, uint32_t state) {
	if (state != 0x1000) return "Unmapped";
	if (type == 0x1000000) return "Image";
	if (type == 0x40000)   return "Mapped";
	if (type == 0x20000)   return "Private";
	return "Region";
}

std::string compose_module_label(const memory_scanner::scan_result_t& r,
								  const std::vector<region_cache_entry_t>& regions)
{
	if (!r.module_name.empty()) {
		char buf[160];
		snprintf(buf, sizeof(buf), "%s+0x%" PRIX64,
			r.module_name.c_str(),
			static_cast<unsigned long long>(r.module_offset));
		return std::string(buf);
	}
	if (regions.empty()) return std::string();
	auto it = std::upper_bound(regions.begin(), regions.end(), r.address,
		[](uint64_t addr, const region_cache_entry_t& e) { return addr < e.base; });
	if (it == regions.begin()) return std::string();
	--it;
	if (r.address < it->base || r.address >= it->end) return std::string();
	const char* kind = region_kind_label(it->type, it->state);
	char buf[96];
	snprintf(buf, sizeof(buf), "%s+0x%" PRIX64,
		kind, static_cast<unsigned long long>(r.address - it->base));
	return std::string(buf);
}

std::string clip_to_width(ImFont* font, float fs, const std::string& s, float max_w) {
	if (s.empty()) return s;
	ImVec2 full = font->CalcTextSizeA(fs, FLT_MAX, 0.f, s.c_str());
	if (full.x <= max_w) return s;
	const std::string ell("..");
	float ell_w = font->CalcTextSizeA(fs, FLT_MAX, 0.f, ell.c_str()).x;
	if (max_w <= ell_w + 2.f) return ell;
	float budget = max_w - ell_w;
	size_t lo = 0;
	size_t hi = s.size();
	size_t best = 0;
	while (lo <= hi) {
		size_t mid = (lo + hi) / 2;
		ImVec2 w = font->CalcTextSizeA(fs, FLT_MAX, 0.f, s.c_str(), s.c_str() + mid);
		if (w.x <= budget) { best = mid; lo = mid + 1; }
		else {
			if (mid == 0) break;
			hi = mid - 1;
		}
	}
	if (best == 0) return ell;
	std::string out(s.c_str(), s.c_str() + best);
	out += ell;
	return out;
}

void draw_clipped_text(ImDrawList* dl, ImFont* font, float fs,
                       float x, float y, float max_w,
                       ImU32 color, const std::string& s)
{
	if (s.empty()) return;
	std::string disp = clip_to_width(font, fs, s, max_w);
	dl->AddText(font, fs, ImVec2(x, y), color, disp.c_str());
}

void diag_log(const char* msg) {
	diag::log_tagged("value_scan", msg);
}

void diag_logf(const char* fmt, ...) {
	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	_vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
	va_end(ap);
	diag::log_tagged("value_scan", buf);
}

bool ctrl_held() {
	ImGuiIO& io = ImGui::GetIO();
	return io.KeyCtrl;
}
bool shift_held() {
	ImGuiIO& io = ImGui::GetIO();
	return io.KeyShift;
}

void interactive_scrollbar(scrollbar_state_t& sb,
                           ImDrawList* dl,
                           float ox, float oy, float w, float h,
                           float content_h, float visible_h,
                           float alpha)
{
	if (content_h <= visible_h) {
		sb.dragging = false;
		sb.track_pressed = false;
		return;
	}
	const auto& t = aida::ui::resolved();
	float ratio = visible_h / content_h;
	float thumb_h = std::max(h * ratio, 24.f);
	float track_range = std::max(0.f, h - thumb_h);
	float max_scroll = std::max(0.f, content_h - visible_h);

	if (sb.scroll_y < 0.f) sb.scroll_y = 0.f;
	if (sb.scroll_y > max_scroll) sb.scroll_y = max_scroll;
	if (sb.target_scroll_y < 0.f) sb.target_scroll_y = 0.f;
	if (sb.target_scroll_y > max_scroll) sb.target_scroll_y = max_scroll;

	float scroll_ratio = (max_scroll > 0.f) ? (sb.scroll_y / max_scroll) : 0.f;
	float thumb_y = oy + track_range * scroll_ratio;

	ImVec2 track_min(ox, oy);
	ImVec2 track_max(ox + w, oy + h);
	bool track_hover = ImGui::IsMouseHoveringRect(track_min, track_max, false);
	ImVec2 thumb_min(ox + 3.f, thumb_y);
	ImVec2 thumb_max(ox + w - 3.f, thumb_y + thumb_h);
	bool thumb_hover = ImGui::IsMouseHoveringRect(thumb_min, thumb_max, false);

	float dt = aida::ui::clock::dt();
	float hover_target = (thumb_hover || sb.dragging) ? 1.f : (track_hover ? 0.55f : 0.f);
	sb.hover_anim = ui_anim::smooth_lerp(sb.hover_anim, hover_target, 14.f, dt);
	float press_target = sb.dragging ? 1.f : 0.f;
	sb.press_anim = ui_anim::smooth_lerp(sb.press_anim, press_target, 16.f, dt);

	ImU32 track_bg_idle = aida::ui::with_alpha(t.bg_overlay, 0.18f * alpha);
	ImU32 track_bg_hov  = aida::ui::with_alpha(t.bg_overlay, 0.34f * alpha);
	ImU32 track_bg = aida::ui::mix(track_bg_idle, track_bg_hov, sb.hover_anim);
	dl->AddRectFilled(track_min, track_max, track_bg, w * 0.5f);
	dl->AddRect(track_min, track_max,
		aida::ui::with_alpha(t.border_subtle, 0.55f * alpha), w * 0.5f, 0, 1.f);

	if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
		sb.dragging = false;
		sb.track_pressed = false;
	}

	bool gated = ui_input_gate::popup_blocks_background_input();

	if (!gated && track_hover && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !sb.dragging) {
		if (thumb_hover) {
			sb.dragging = true;
			sb.drag_offset = ImGui::GetMousePos().y - thumb_y;
			diag_logf("scrollbar drag_begin track_y=%.1f thumb_y=%.1f offset=%.1f",
				oy, thumb_y, sb.drag_offset);
		} else {
			sb.track_pressed = true;
			float my = ImGui::GetMousePos().y;
			float page = visible_h * 0.85f;
			float new_scroll = sb.target_scroll_y;
			if (my < thumb_y) new_scroll -= page;
			else new_scroll += page;
			new_scroll = std::clamp(new_scroll, 0.f, max_scroll);
			sb.target_scroll_y = new_scroll;
			diag_logf("scrollbar track_page click_y=%.1f page=%.1f new_target=%.1f",
				my, page, new_scroll);
		}
	}

	if (sb.dragging) {
		float ny = ImGui::GetMousePos().y - sb.drag_offset;
		float r = (track_range > 0.f) ? ((ny - oy) / track_range) : 0.f;
		r = std::clamp(r, 0.f, 1.f);
		sb.scroll_y = r * max_scroll;
		sb.target_scroll_y = sb.scroll_y;
	}

	ImU32 thumb_idle = aida::ui::with_alpha(t.text_dim, 0.42f * alpha);
	ImU32 thumb_hov  = aida::ui::with_alpha(t.accent_u32, 0.78f * alpha);
	ImU32 thumb_drag = aida::ui::with_alpha(t.accent_u32, 0.95f * alpha);
	ImU32 thumb_col = aida::ui::mix(thumb_idle, thumb_hov, sb.hover_anim);
	thumb_col = aida::ui::mix(thumb_col, thumb_drag, sb.press_anim);
	float thumb_radius = (thumb_max.x - thumb_min.x) * 0.5f;
	dl->AddRectFilled(thumb_min, thumb_max, thumb_col, thumb_radius);
	if (sb.hover_anim > 0.04f) {
		dl->AddRect(thumb_min, thumb_max,
			aida::ui::with_alpha(t.accent_hover, 0.45f * sb.hover_anim * alpha),
			thumb_radius, 0, 1.f);
	}
}

void refresh_region_cache_locked(region_cache_t& c) {
	auto regs = driver_bridge::enumerate_memory_regions(kRegionRefreshChunk);
	std::vector<region_cache_entry_t> out;
	out.reserve(regs.size());
	for (const auto& r : regs) {
		region_cache_entry_t e;
		e.base = r.base;
		e.end  = r.base + r.size;
		e.state = r.state;
		e.protect = r.protect;
		e.type = r.type;
		out.push_back(e);
	}
	std::sort(out.begin(), out.end(),
		[](const region_cache_entry_t& a, const region_cache_entry_t& b) {
			return a.base < b.base;
		});
	std::lock_guard<std::mutex> lk(c.mtx);
	c.entries = std::move(out);
	c.generation += 1;
	c.refreshing = false;
}

void request_region_refresh() {
	auto& c = g_ui.region_cache;
	{
		std::lock_guard<std::mutex> lk(c.mtx);
		if (c.refreshing) return;
		c.refreshing = true;
	}
	diag_log("region_cache refresh_post");
	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "scanner";
	sub.label = "scanner.region_cache_refresh";
	sub.thread_class = "scanner_ui_refresh";
	sub.domain = aida::infra::executor::domain_t::diagnostics;
	sub.priority = 4;
	sub.target_pid = driver_bridge::attached_pid();
	sub.body = []() {
		refresh_region_cache_locked(g_ui.region_cache);
		diag::log_tagged("value_scan", "region_cache refresh_done");
	};
	bool posted = aida::infra::executor::submit(std::move(sub)).submitted;
	if (!posted) {
		std::lock_guard<std::mutex> lk(c.mtx);
		c.refreshing = false;
		diag_log("region_cache refresh_post_failed");
	}
}

void rebuild_sorted_indices(int total) {
	auto& ui = g_ui;
	auto& sc = memory_scanner::g_state;
	ui.sorted_result_indices.resize(static_cast<size_t>(total));
	for (int i = 0; i < total; ++i) ui.sorted_result_indices[static_cast<size_t>(i)] = i;

	std::vector<region_cache_entry_t> regions_snapshot;
	{
		std::lock_guard<std::mutex> lk(ui.region_cache.mtx);
		regions_snapshot = ui.region_cache.entries;
	}

	result_sort_t field = ui.result_sort_field;
	bool desc = ui.result_sort_desc;

	if (field != result_sort_t::by_index) {
		auto val_to_double = [&](const memory_scanner::scan_result_t& r,
		                          const std::vector<uint8_t>& bytes) -> double {
			(void)r;
			if (bytes.empty()) return 0.0;
			switch (sc.config.value_type) {
				case memory_scanner::value_type_t::byte_val:
					return static_cast<double>(bytes[0]);
				case memory_scanner::value_type_t::int16_val: {
					int16_t v; std::memcpy(&v, bytes.data(), std::min(bytes.size(), sizeof(v)));
					return static_cast<double>(v);
				}
				case memory_scanner::value_type_t::int32_val: {
					int32_t v; std::memcpy(&v, bytes.data(), std::min(bytes.size(), sizeof(v)));
					return static_cast<double>(v);
				}
				case memory_scanner::value_type_t::int64_val: {
					int64_t v; std::memcpy(&v, bytes.data(), std::min(bytes.size(), sizeof(v)));
					return static_cast<double>(v);
				}
				case memory_scanner::value_type_t::float_val: {
					float v; std::memcpy(&v, bytes.data(), std::min(bytes.size(), sizeof(v)));
					return static_cast<double>(v);
				}
				case memory_scanner::value_type_t::double_val: {
					double v; std::memcpy(&v, bytes.data(), std::min(bytes.size(), sizeof(v)));
					return v;
				}
				default:
					return 0.0;
			}
		};

		auto module_label = [&](const memory_scanner::scan_result_t& r) -> std::string {
			return compose_module_label(r, regions_snapshot);
		};

		std::sort(ui.sorted_result_indices.begin(), ui.sorted_result_indices.end(),
			[&](int aa, int bb) {
				if (aa < 0 || bb < 0) return aa < bb;
				if (aa >= static_cast<int>(sc.results.size()) ||
				    bb >= static_cast<int>(sc.results.size())) return aa < bb;
				const auto& ra = sc.results[static_cast<size_t>(aa)];
				const auto& rb = sc.results[static_cast<size_t>(bb)];
				int cmp = 0;
				switch (field) {
					case result_sort_t::by_address:
						cmp = (ra.address < rb.address) ? -1 : (ra.address > rb.address ? 1 : 0);
						break;
					case result_sort_t::by_value: {
						double da = val_to_double(ra, ra.current_value);
						double db = val_to_double(rb, rb.current_value);
						cmp = (da < db) ? -1 : (da > db ? 1 : 0);
						break;
					}
					case result_sort_t::by_previous: {
						double da = val_to_double(ra, ra.previous_value);
						double db = val_to_double(rb, rb.previous_value);
						cmp = (da < db) ? -1 : (da > db ? 1 : 0);
						break;
					}
					case result_sort_t::by_module: {
						std::string la = module_label(ra);
						std::string lb = module_label(rb);
						cmp = la.compare(lb);
						break;
					}
					default: break;
				}
				if (cmp == 0) return ra.address < rb.address;
				return desc ? (cmp > 0) : (cmp < 0);
			});
	}

	ui.sorted_indices_dirty = false;
}

void invalidate_sort() {
	g_ui.sorted_indices_dirty = true;
}

void render_toolbar(ImDrawList* dl, float ox, float oy, float w, float a) {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + kToolbarHeight),
		aida::ui::with_alpha(t.panel_header, a));
	ImU32 sheen_top = aida::ui::with_alpha(t.accent_glow, 0.10f * a);
	dl->AddRectFilledMultiColor(ImVec2(ox, oy),
		ImVec2(ox + w, oy + 16.f),
		sheen_top, sheen_top,
		IM_COL32(0, 0, 0, 0), IM_COL32(0, 0, 0, 0));
	dl->AddLine(ImVec2(ox, oy + kToolbarHeight),
		ImVec2(ox + w, oy + kToolbarHeight),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	float pad = 14.f;
	float cy = oy + (kToolbarHeight - 36.f) * 0.5f;
	float cx = ox + pad;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy + 4.f));
	ImGui::PushItemWidth(108.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.bg_elevated, a));
	ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, aida::ui::with_alpha(t.hover_wash, a));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_strong, a));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 5.f));
	if (ImGui::BeginCombo("##vtype", memory_scanner::value_type_name(sc.config.value_type))) {
		for (int i = 0; i < static_cast<int>(memory_scanner::value_type_t::COUNT); ++i) {
			auto vt = static_cast<memory_scanner::value_type_t>(i);
			bool sel = (sc.config.value_type == vt);
			if (ImGui::Selectable(memory_scanner::value_type_name(vt), sel)) {
				if (sc.config.value_type != vt) {
					diag_logf("toolbar value_type_change from=%s to=%s",
						memory_scanner::value_type_name(sc.config.value_type),
						memory_scanner::value_type_name(vt));
					sc.config.value_type = vt;
					invalidate_sort();
				}
			}
		}
		ImGui::EndCombo();
	}
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(5);
	ImGui::PopItemWidth();
	cx += 116.f;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy + 4.f));
	ImGui::PushItemWidth(190.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.bg_elevated, a));
	ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, aida::ui::with_alpha(t.hover_wash, a));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_strong, a));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 5.f));
	if (ImGui::BeginCombo("##smode", memory_scanner::scan_mode_name(sc.config.scan_mode))) {
		for (int i = 0; i < static_cast<int>(memory_scanner::scan_mode_t::COUNT); ++i) {
			auto sm = static_cast<memory_scanner::scan_mode_t>(i);
			bool sel = (sc.config.scan_mode == sm);
			if (ImGui::Selectable(memory_scanner::scan_mode_name(sm), sel)) {
				if (sc.config.scan_mode != sm) {
					diag_logf("toolbar scan_mode_change to=%s",
						memory_scanner::scan_mode_name(sm));
					sc.config.scan_mode = sm;
				}
			}
		}
		ImGui::EndCombo();
	}
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(5);
	ImGui::PopItemWidth();
	cx += 200.f;

	bool needs_value = (sc.config.scan_mode != memory_scanner::scan_mode_t::changed &&
	                    sc.config.scan_mode != memory_scanner::scan_mode_t::unchanged &&
	                    sc.config.scan_mode != memory_scanner::scan_mode_t::increased &&
	                    sc.config.scan_mode != memory_scanner::scan_mode_t::decreased &&
	                    sc.config.scan_mode != memory_scanner::scan_mode_t::unknown_initial);

	float input_h = 34.f;
	float input_y = oy + (kToolbarHeight - input_h) * 0.5f;
	if (needs_value) {
		float input_w = 200.f;
		ImVec2 ia(cx, input_y);
		ImVec2 ib(cx + input_w, input_y + input_h);
		dl->AddRectFilled(ia, ib, aida::ui::with_alpha(t.bg_elevated, a), 8.f);
		dl->AddRect(ia, ib, aida::ui::with_alpha(t.border_focus, a * 0.55f), 8.f, 0, 1.5f);
		ImGui::SetCursorScreenPos(ImVec2(cx + 4.f, input_y + 2.f));
		ImGui::PushItemWidth(input_w - 8.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, IM_COL32(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive, IM_COL32(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
		ImGui::PushStyleColor(ImGuiCol_TextSelectedBg, aida::ui::with_alpha(t.accent_dim, a));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 8.f));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::InputTextWithHint("##val", "value", ui.value_buf, sizeof(ui.value_buf));
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(5);
		ImGui::PopItemWidth();
		cx += input_w + 10.f;
	}

	if (sc.config.scan_mode == memory_scanner::scan_mode_t::value_between) {
		ImFont* body_fn = aida::ui::fonts::body();
		dl->AddText(body_fn, body_fn->FontSize,
			ImVec2(cx, oy + (kToolbarHeight - body_fn->FontSize) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, a), "to");
		cx += 28.f;
		float input2_w = 150.f;
		ImVec2 ia2(cx, input_y);
		ImVec2 ib2(cx + input2_w, input_y + input_h);
		dl->AddRectFilled(ia2, ib2, aida::ui::with_alpha(t.bg_elevated, a), 8.f);
		dl->AddRect(ia2, ib2, aida::ui::with_alpha(t.border_focus, a * 0.55f), 8.f, 0, 1.5f);
		ImGui::SetCursorScreenPos(ImVec2(cx + 4.f, input_y + 2.f));
		ImGui::PushItemWidth(input2_w - 8.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 8.f));
		ImGui::InputTextWithHint("##val2", "max", ui.value_buf2, sizeof(ui.value_buf2));
		ImGui::PopStyleVar();
		ImGui::PopStyleColor(2);
		ImGui::PopItemWidth();
		cx += input2_w + 10.f;
	}

	{
		ImFont* hex_fn = aida::ui::fonts::body();
		float lbl_w = hex_fn->CalcTextSizeA(hex_fn->FontSize, FLT_MAX, 0.f, "HEX").x;
		float pill_w = lbl_w + 44.f;
		float pill_h = input_h;
		float py = input_y;
		ImGui::SetCursorScreenPos(ImVec2(cx, py));
		ImGui::PushID("hex_toggle");
		ImGui::InvisibleButton("##hex_b", ImVec2(pill_w, pill_h));
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
		           !ui_input_gate::popup_blocks_background_input();
		bool hov = ImGui::IsItemHovered();
		if (clk) {
			sc.config.hex_input = !sc.config.hex_input;
			diag_logf("toolbar hex_toggle now=%d", static_cast<int>(sc.config.hex_input));
		}
		bool on = sc.config.hex_input;
		ImU32 track = on ? aida::ui::with_alpha(t.accent_dim, a * 0.92f)
		                  : aida::ui::with_alpha(t.bg_elevated, a);
		ImU32 border = on ? aida::ui::with_alpha(t.accent_u32, a * 0.95f)
		                   : aida::ui::with_alpha(t.border_strong, a);
		if (hov) border = aida::ui::with_alpha(t.accent_hover, a);
		ImVec2 pa(cx, py);
		ImVec2 pb(cx + pill_w, py + pill_h);
		dl->AddRectFilled(pa, pb, track, pill_h * 0.5f);
		dl->AddRect(pa, pb, border, pill_h * 0.5f, 0, 1.5f);
		float knob_r = (pill_h - 8.f) * 0.5f;
		float knob_x = on ? (cx + pill_w - knob_r - 6.f) : (cx + knob_r + 6.f);
		float knob_y = py + pill_h * 0.5f;
		dl->AddCircleFilled(ImVec2(knob_x, knob_y), knob_r,
			on ? aida::ui::with_alpha(t.accent_u32, a)
			   : aida::ui::with_alpha(t.text_dim, a * 0.85f), 24);
		ImU32 lbl_col = on ? aida::ui::with_alpha(t.text_primary, a)
		                   : aida::ui::with_alpha(t.text_secondary, a);
		float lbl_x = on ? (cx + 14.f) : (cx + pill_w - lbl_w - 16.f);
		dl->AddText(hex_fn, hex_fn->FontSize,
			ImVec2(lbl_x, py + (pill_h - hex_fn->FontSize) * 0.5f),
			lbl_col, "HEX");
		ImGui::PopID();
		cx += pill_w + 14.f;
	}

	bool scanning = sc.scanning.load();
	bool attached = driver_bridge::is_loaded() && driver_bridge::attached_pid() != 0;
	bool static_pe = function_index::detail::static_pe_active();
	bool any_target = attached || static_pe;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	if (scanning) {
		if (aida::ui::button("Stop", aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f))) {
			diag_log("toolbar stop_button");
			sc.scanning.store(false);
		}
		cx += 96.f;
	} else if (!sc.has_initial_scan) {
		if (aida::ui::button("First Scan", aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), !any_target)) {
			diag_logf("toolbar first_scan val='%s' val2='%s' vtype=%s mode=%s any_target=%d",
				ui.value_buf, ui.value_buf2,
				memory_scanner::value_type_name(sc.config.value_type),
				memory_scanner::scan_mode_name(sc.config.scan_mode),
				static_cast<int>(any_target));
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] memory_scanner first_scan invoked");
			sc.config.value_text = ui.value_buf;
			sc.config.value_text2 = ui.value_buf2;
			if (memory_scanner::first_scan(sc.config)) {
				ui.selected_result = -1;
				ui.result_multi_sel.clear();
				ui.last_result_anchor = -1;
				ui.result_sb.scroll_y = 0.f;
				ui.result_sb.target_scroll_y = 0.f;
				ui.user_scrolled_up = false;
				request_region_refresh();
				invalidate_sort();
			} else {
				toast_notification::push("Cannot start scan: attach a target first.",
					toast_notification::toast_type_t::warning, 4.f);
			}
		}
		cx += 132.f;
	} else {
		if (aida::ui::button("Next Scan", aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), !any_target)) {
			diag_logf("toolbar next_scan mode=%s val='%s'",
				memory_scanner::scan_mode_name(sc.config.scan_mode),
				ui.value_buf);
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] memory_scanner next_scan invoked");
			if (memory_scanner::next_scan(sc.config.scan_mode,
				std::string(ui.value_buf), std::string(ui.value_buf2)))
			{
				request_region_refresh();
				invalidate_sort();
			} else {
				toast_notification::push("Cannot run Next Scan.",
					toast_notification::toast_type_t::warning, 3.f);
			}
		}
		cx += 122.f;
	}

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	bool undo_disabled = scanning || !sc.has_initial_scan;
	if (aida::ui::button("Undo", aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::md, ImVec2(0.f, 0.f), undo_disabled)) {
		diag_log("toolbar undo_button");
		memory_scanner::undo_scan();
		invalidate_sort();
		ui.selected_result = -1;
		ui.result_multi_sel.clear();
		ui.last_result_anchor = -1;
	}
	cx += 86.f;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	bool reset_disabled = scanning || !sc.has_initial_scan;
	if (aida::ui::button("New Scan", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::md, ImVec2(0.f, 0.f), reset_disabled)) {
		diag_log("toolbar new_scan_button");
		memory_scanner::reset_scan();
		invalidate_sort();
		ui.selected_result = -1;
		ui.result_multi_sel.clear();
		ui.last_result_anchor = -1;
		ui.result_sb.scroll_y = 0.f;
		ui.result_sb.target_scroll_y = 0.f;
	}
	cx += 108.f;

	float right_cx = ox + w - pad;

	{
		char count_buf[64];
		snprintf(count_buf, sizeof(count_buf), "%zu found", sc.total_found);
		ImFont* body_fn = aida::ui::fonts::body();
		ImVec2 cts = body_fn->CalcTextSizeA(body_fn->FontSize, FLT_MAX, 0.f, count_buf);
		right_cx -= cts.x;
		dl->AddText(body_fn, body_fn->FontSize,
			ImVec2(right_cx, oy + (kToolbarHeight - cts.y) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, a), count_buf);
		right_cx -= 12.f;
	}

	if (scanning) {
		float prog = sc.scan_progress.load();
		float ring_r = 12.f;
		right_cx -= (ring_r * 2.f + 4.f);
		float ring_cx = right_cx + ring_r;
		float ring_cy = oy + kToolbarHeight * 0.5f;
		aida::ui::render_progress_ring(ImVec2(ring_cx, ring_cy), ring_r, 2.5f, prog, false);
		char pct_buf[8];
		snprintf(pct_buf, sizeof(pct_buf), "%d%%", static_cast<int>(prog * 100.f));
		ImFont* body_fn = aida::ui::fonts::body();
		ImVec2 pct_sz = body_fn->CalcTextSizeA(body_fn->FontSize, FLT_MAX, 0.f, pct_buf);
		dl->AddText(body_fn, body_fn->FontSize,
			ImVec2(ring_cx - pct_sz.x * 0.5f, ring_cy - pct_sz.y * 0.5f),
			aida::ui::with_alpha(t.text_primary, a), pct_buf);
		right_cx -= 12.f;
	}

	if (static_pe && !attached) {
		const char* lbl = "Static PE scan";
		ImFont* body_fn = aida::ui::fonts::body();
		ImVec2 lsz = body_fn->CalcTextSizeA(body_fn->FontSize, FLT_MAX, 0.f, lbl);
		float pad_x = 10.f;
		float pad_y = 5.f;
		float bw = lsz.x + pad_x * 2.f;
		float bh = lsz.y + pad_y * 2.f;
		right_cx -= bw;
		float by = oy + (kToolbarHeight - bh) * 0.5f;
		dl->AddRectFilled(ImVec2(right_cx, by),
			ImVec2(right_cx + bw, by + bh),
			aida::ui::with_alpha(t.warning, 0.18f * a), bh * 0.5f);
		dl->AddRect(ImVec2(right_cx, by),
			ImVec2(right_cx + bw, by + bh),
			aida::ui::with_alpha(t.warning, 0.65f * a), bh * 0.5f, 0, 1.f);
		dl->AddText(body_fn, body_fn->FontSize,
			ImVec2(right_cx + pad_x, by + pad_y),
			aida::ui::with_alpha(t.warning, a), lbl);
		right_cx -= 12.f;
	}
}

void compute_result_columns(float ox, float w,
                            column_layout_t cols[4],
                            float& content_w_total,
                            bool include_scrollbar)
{
	const float pad = 12.f;
	float right_reserve = include_scrollbar ? (kScrollbarTrackW + 12.f) : 12.f;
	float avail = w - pad - right_reserve;
	float col_addr_w = std::min(180.f, std::max(140.f, avail * 0.20f));
	float col_val_w  = std::min(170.f, std::max(110.f, avail * 0.18f));
	float col_prev_w = std::min(170.f, std::max(110.f, avail * 0.18f));
	float col_mod_w  = avail - col_addr_w - col_val_w - col_prev_w;
	if (col_mod_w < 100.f) col_mod_w = 100.f;

	float widths[4] = { col_addr_w, col_val_w, col_prev_w, col_mod_w };
	const char* names[4] = { "Address", "Value", "Previous", "Module / Region" };
	float cx = ox + pad;
	for (int i = 0; i < 4; ++i) {
		cols[i].x0 = cx;
		cols[i].x1 = cx + widths[i];
		cols[i].inner_x0 = cx + 6.f;
		cols[i].inner_x1 = cols[i].x1 - 8.f;
		cols[i].title = names[i];
		cx += widths[i];
	}
	content_w_total = cx - ox;
}

void compute_addr_columns(float ox, float w,
                          column_layout_t cols[5],
                          bool include_scrollbar)
{
	const float pad = 12.f;
	float right_reserve = include_scrollbar ? (kScrollbarTrackW + 12.f) : 12.f;
	float avail = w - pad - right_reserve;
	float col_freeze_w = 60.f;
	float col_addr_w = std::min(180.f, std::max(140.f, avail * 0.18f));
	float col_type_w = std::min(120.f, std::max(80.f, avail * 0.10f));
	float reserved = col_freeze_w + col_addr_w + col_type_w;
	float remaining = avail - reserved;
	if (remaining < 200.f) remaining = 200.f;
	float col_desc_w = remaining * 0.55f;
	float col_val_w  = remaining - col_desc_w;
	if (col_val_w < 100.f) {
		col_val_w = 100.f;
		col_desc_w = remaining - col_val_w;
	}

	float widths[5] = { col_freeze_w, col_desc_w, col_addr_w, col_type_w, col_val_w };
	const char* names[5] = { "Active", "Description", "Address", "Type", "Value" };

	float cx = ox + pad;
	for (int i = 0; i < 5; ++i) {
		cols[i].x0 = cx;
		cols[i].x1 = cx + widths[i];
		cols[i].inner_x0 = cx + 6.f;
		cols[i].inner_x1 = cols[i].x1 - 8.f;
		cols[i].title = names[i];
		cx += widths[i];
	}
}

ImU32 value_color(const memory_scanner::scan_result_t& r, float a, const aida::ui::theme_t& t) {
	if (r.previous_value.empty() || r.current_value.empty())
		return aida::ui::with_alpha(t.success, a);
	int64_t cv = 0, pv = 0;
	std::memcpy(&cv, r.current_value.data(), std::min(r.current_value.size(), sizeof(int64_t)));
	std::memcpy(&pv, r.previous_value.data(), std::min(r.previous_value.size(), sizeof(int64_t)));
	if (cv > pv) return aida::ui::with_alpha(t.success, a);
	if (cv < pv) return aida::ui::with_alpha(t.error, a);
	return aida::ui::with_alpha(t.text_primary, a);
}

void update_results_diff_flash(int total) {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	if (static_cast<int>(ui.row_flash.size()) < total)
		ui.row_flash.resize(static_cast<size_t>(total), 0.f);

	std::unordered_set<uint64_t> current;
	current.reserve(static_cast<size_t>(total));
	for (auto& r : sc.results) current.insert(r.address);

	bool changed = (current.size() != ui.prev_result_addresses.size());
	if (!changed) {
		for (auto a_addr : current) {
			if (ui.prev_result_addresses.find(a_addr) == ui.prev_result_addresses.end()) {
				changed = true; break;
			}
		}
	}
	if (changed) {
		for (int i = 0; i < total; ++i) {
			if (ui.prev_result_addresses.find(sc.results[static_cast<size_t>(i)].address) ==
				ui.prev_result_addresses.end())
			{
				if (i < static_cast<int>(ui.row_flash.size()))
					ui.row_flash[static_cast<size_t>(i)] = 1.f;
			}
		}
		ui.prev_result_addresses = std::move(current);
	}

	for (auto& f : ui.row_flash) {
		if (f > 0.f) {
			f -= aida::ui::clock::dt() * 1.66f;
			if (f < 0.f) f = 0.f;
		}
	}
}

void handle_multi_select(std::unordered_set<int>& set, int& anchor, int idx, int total) {
	bool ctrl = ctrl_held();
	bool shift = shift_held();
	if (shift && anchor >= 0 && anchor < total) {
		int lo = std::min(anchor, idx);
		int hi = std::max(anchor, idx);
		if (!ctrl) set.clear();
		for (int k = lo; k <= hi; ++k) set.insert(k);
	} else if (ctrl) {
		auto it = set.find(idx);
		if (it == set.end()) set.insert(idx);
		else set.erase(it);
		anchor = idx;
	} else {
		set.clear();
		set.insert(idx);
		anchor = idx;
	}
}

void render_results_pane(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy),
		ImVec2(ox + w, oy + kResultHeaderHeight),
		aida::ui::with_alpha(t.panel_header, a * 0.92f));
	dl->AddLine(ImVec2(ox, oy + kResultHeaderHeight),
		ImVec2(ox + w, oy + kResultHeaderHeight),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	column_layout_t cols[4];
	float content_w_total = 0.f;

	int total = 0;
	{
		std::lock_guard<std::mutex> lk(sc.results_mutex);
		total = static_cast<int>(sc.results.size());
	}
	bool include_sb = total > 0;
	compute_result_columns(ox, w, cols, content_w_total, include_sb);

	ImFont* hdr_font = aida::ui::fonts::body_em();
	float hdr_fs = hdr_font->FontSize;

	for (int c = 0; c < 4; ++c) {
		ImVec2 hmin(cols[c].x0, oy);
		ImVec2 hmax(cols[c].x1, oy + kResultHeaderHeight);
		bool hov = ImGui::IsMouseHoveringRect(hmin, hmax, false) &&
			!ui_input_gate::popup_blocks_background_input();
		ImGui::PushID(8000 + c);
		ImGui::SetCursorScreenPos(hmin);
		ImGui::InvisibleButton("##rh", ImVec2(hmax.x - hmin.x, hmax.y - hmin.y));
		bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
			!ui_input_gate::popup_blocks_background_input();
		ImGui::PopID();

		if (hov) {
			dl->AddRectFilled(hmin, hmax, aida::ui::with_alpha(t.hover_wash, 0.5f * a));
		}

		ImU32 lbl_col = aida::ui::with_alpha(t.text_secondary, a);
		result_sort_t field = result_sort_t::by_index;
		switch (c) {
			case kColResultAddr:     field = result_sort_t::by_address;  break;
			case kColResultValue:    field = result_sort_t::by_value;    break;
			case kColResultPrevious: field = result_sort_t::by_previous; break;
			case kColResultModule:   field = result_sort_t::by_module;   break;
		}
		bool active = (ui.result_sort_field == field);
		if (active)
			lbl_col = aida::ui::with_alpha(t.accent_u32, a);
		dl->AddText(hdr_font, hdr_fs,
			ImVec2(cols[c].inner_x0, oy + (kResultHeaderHeight - hdr_fs) * 0.5f),
			lbl_col, cols[c].title);

		if (active) {
			float tri_x = cols[c].inner_x0 +
				hdr_font->CalcTextSizeA(hdr_fs, FLT_MAX, 0.f, cols[c].title).x + 8.f;
			float tri_y = oy + kResultHeaderHeight * 0.5f;
			float trh = 5.f;
			ImU32 tcol = aida::ui::with_alpha(t.accent_u32, a);
			if (ui.result_sort_desc) {
				dl->AddTriangleFilled(
					ImVec2(tri_x, tri_y - trh * 0.5f),
					ImVec2(tri_x + trh * 1.5f, tri_y - trh * 0.5f),
					ImVec2(tri_x + trh * 0.75f, tri_y + trh * 0.7f), tcol);
			} else {
				dl->AddTriangleFilled(
					ImVec2(tri_x, tri_y + trh * 0.5f),
					ImVec2(tri_x + trh * 1.5f, tri_y + trh * 0.5f),
					ImVec2(tri_x + trh * 0.75f, tri_y - trh * 0.7f), tcol);
			}
		}

		if (clicked) {
			if (ui.result_sort_field == field) {
				if (!ui.result_sort_desc) ui.result_sort_desc = true;
				else { ui.result_sort_field = result_sort_t::by_index; ui.result_sort_desc = false; }
			} else {
				ui.result_sort_field = field;
				ui.result_sort_desc = false;
			}
			invalidate_sort();
			diag_logf("results column_sort_click col=%d field=%d desc=%d",
				c, static_cast<int>(ui.result_sort_field),
				static_cast<int>(ui.result_sort_desc));
		}
	}

	float body_y = oy + kResultHeaderHeight;
	float body_h = h - kResultHeaderHeight;
	if (body_h < 1.f) body_h = 1.f;
	int visible_rows = static_cast<int>(body_h / kResultRowHeight);
	if (visible_rows < 1) visible_rows = 1;

	std::lock_guard<std::mutex> lk(sc.results_mutex);
	total = static_cast<int>(sc.results.size());

	update_results_diff_flash(total);

	if (ui.sorted_indices_dirty || static_cast<int>(ui.sorted_result_indices.size()) != total)
		rebuild_sorted_indices(total);

	{
		uint64_t cur_gen = 0;
		{
			std::lock_guard<std::mutex> rgk(ui.region_cache.mtx);
			cur_gen = ui.region_cache.generation;
		}
		if (cur_gen != ui.last_region_refresh_gen &&
			ui.result_sort_field == result_sort_t::by_module &&
			!ui.sorted_indices_dirty)
		{
			ui.last_region_refresh_gen = cur_gen;
			invalidate_sort();
		}
	}

	float dt = aida::ui::clock::dt();

	bool body_hover = ImGui::IsMouseHoveringRect(
		ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), false) &&
		!ui_input_gate::popup_blocks_background_input();

	if (body_hover) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f) {
			ui.result_sb.target_scroll_y -= wheel * kResultRowHeight * 3.f;
			if (wheel > 0.f) ui.user_scrolled_up = true;
			diag_logf("results wheel=%.2f target=%.1f", wheel, ui.result_sb.target_scroll_y);
		}
	}

	float content_h = static_cast<float>(total) * kResultRowHeight;
	float max_scroll = std::max(0.f, content_h - body_h);
	ui.result_sb.target_scroll_y = std::clamp(ui.result_sb.target_scroll_y, 0.f, max_scroll);
	ui_anim::smooth_scroll(ui.result_sb.scroll_y, ui.result_sb.target_scroll_y, 22.f, dt);

	if (ui.result_sb.target_scroll_y >= max_scroll - 1.f) ui.user_scrolled_up = false;

	int first_row = static_cast<int>(ui.result_sb.scroll_y / kResultRowHeight);
	if (first_row < 0) first_row = 0;
	int last_row = std::min(total, first_row + visible_rows + 2);

	std::vector<region_cache_entry_t> regions_snapshot;
	{
		std::lock_guard<std::mutex> rgk(ui.region_cache.mtx);
		regions_snapshot = ui.region_cache.entries;
	}

	ImGui::PushClipRect(ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), true);

	static float result_row_anim_time = 0.f;
	result_row_anim_time += dt;

	ImFont* code_fn = aida::ui::fonts::code();
	float code_fs = code_fn->FontSize;
	ImFont* body_fn = aida::ui::fonts::body();
	float body_fs = body_fn->FontSize;

	int clicked_row = -1;
	int dbl_click_row = -1;
	int right_click_row = -1;

	float row_right_edge = include_sb ? (ox + w - kScrollbarTrackW - 6.f) : (ox + w);

	for (int i = first_row; i < last_row; ++i) {
		int src_index = i;
		if (i >= 0 && i < static_cast<int>(ui.sorted_result_indices.size()))
			src_index = ui.sorted_result_indices[static_cast<size_t>(i)];
		if (src_index < 0 || src_index >= total) continue;
		const auto& r = sc.results[static_cast<size_t>(src_index)];

		float ry = body_y + static_cast<float>(i) * kResultRowHeight - ui.result_sb.scroll_y;
		if (ry + kResultRowHeight < body_y || ry > body_y + body_h) continue;

		float row_entrance = ui_anim::render_row_entrance(i - first_row, result_row_anim_time, 0.012f);
		bool sel = (ui.result_multi_sel.count(i) > 0) || (ui.selected_result == i);
		bool hov = ImGui::IsMouseHoveringRect(
			ImVec2(ox, ry), ImVec2(row_right_edge, ry + kResultRowHeight), false) &&
			!ui_input_gate::popup_blocks_background_input();

		if (sel) {
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + w, ry + kResultRowHeight),
				aida::ui::with_alpha(t.selection, a * row_entrance));
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + 3.f, ry + kResultRowHeight),
				aida::ui::with_alpha(t.accent_u32, a * row_entrance));
		} else if (hov) {
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + w, ry + kResultRowHeight),
				aida::ui::with_alpha(t.hover_wash, a * row_entrance));
		} else if (i & 1) {
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + w, ry + kResultRowHeight),
				aida::ui::with_alpha(t.hover_wash, 0.20f * a * row_entrance));
		}

		float flash = (src_index < static_cast<int>(ui.row_flash.size()))
			? ui.row_flash[static_cast<size_t>(src_index)] : 0.f;
		if (flash > 0.f) {
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + w, ry + kResultRowHeight),
				aida::ui::with_alpha(t.accent_glow, a * flash * 0.85f));
		}

		char addr_buf[24];
		snprintf(addr_buf, sizeof(addr_buf), "%016" PRIX64,
			static_cast<unsigned long long>(r.address));
		dl->PushClipRect(ImVec2(cols[kColResultAddr].inner_x0, ry),
			ImVec2(cols[kColResultAddr].inner_x1, ry + kResultRowHeight), true);
		dl->AddText(code_fn, code_fs,
			ImVec2(cols[kColResultAddr].inner_x0, ry + (kResultRowHeight - code_fs) * 0.5f),
			aida::ui::with_alpha(t.text_address, a * row_entrance), addr_buf);
		dl->PopClipRect();

		std::string cur_str = memory_scanner::format_value(r.current_value, sc.config.value_type);
		ImU32 cur_col = value_color(r, a * row_entrance, t);
		float val_w = cols[kColResultValue].inner_x1 - cols[kColResultValue].inner_x0;
		dl->PushClipRect(ImVec2(cols[kColResultValue].inner_x0, ry),
			ImVec2(cols[kColResultValue].inner_x1, ry + kResultRowHeight), true);
		draw_clipped_text(dl, code_fn, code_fs,
			cols[kColResultValue].inner_x0, ry + (kResultRowHeight - code_fs) * 0.5f,
			val_w, cur_col, cur_str);
		dl->PopClipRect();

		if (!r.previous_value.empty()) {
			std::string prev_str = memory_scanner::format_value(r.previous_value, sc.config.value_type);
			float pw = cols[kColResultPrevious].inner_x1 - cols[kColResultPrevious].inner_x0;
			dl->PushClipRect(ImVec2(cols[kColResultPrevious].inner_x0, ry),
				ImVec2(cols[kColResultPrevious].inner_x1, ry + kResultRowHeight), true);
			draw_clipped_text(dl, code_fn, code_fs,
				cols[kColResultPrevious].inner_x0,
				ry + (kResultRowHeight - code_fs) * 0.5f,
				pw, aida::ui::with_alpha(t.text_dim, a * row_entrance), prev_str);
			dl->PopClipRect();
		}

		std::string mod_label = compose_module_label(r, regions_snapshot);
		ImU32 mod_col = aida::ui::with_alpha(t.text_secondary, a * row_entrance);
		if (mod_label.empty()) {
			mod_label = "Unknown";
			mod_col = aida::ui::with_alpha(t.text_dim, a * row_entrance);
		}
		float mod_w = cols[kColResultModule].inner_x1 - cols[kColResultModule].inner_x0;
		dl->PushClipRect(ImVec2(cols[kColResultModule].inner_x0, ry),
			ImVec2(cols[kColResultModule].inner_x1, ry + kResultRowHeight), true);
		draw_clipped_text(dl, body_fn, body_fs,
			cols[kColResultModule].inner_x0,
			ry + (kResultRowHeight - body_fs) * 0.5f,
			mod_w, mod_col, mod_label);
		dl->PopClipRect();

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			clicked_row = i;
		if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
			dbl_click_row = i;
		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
			right_click_row = i;
	}

	ImGui::PopClipRect();

	if (clicked_row >= 0) {
		ui.selected_result = clicked_row;
		handle_multi_select(ui.result_multi_sel, ui.last_result_anchor, clicked_row, total);
		diag_logf("results row_click idx=%d multi_count=%zu",
			clicked_row, ui.result_multi_sel.size());
	}
	if (dbl_click_row >= 0) {
		int src_index = dbl_click_row;
		if (src_index >= 0 && src_index < static_cast<int>(ui.sorted_result_indices.size()))
			src_index = ui.sorted_result_indices[static_cast<size_t>(src_index)];
		if (src_index >= 0 && src_index < total) {
			uint64_t addr = sc.results[static_cast<size_t>(src_index)].address;
			diag_logf("results dbl_click_add addr=0x%llX", static_cast<unsigned long long>(addr));
			s_pending_add_addr.store(addr);
			s_pending_add_vtype.store(static_cast<int>(sc.config.value_type));
			s_open_add_dialog.store(true);
		}
	}
	if (right_click_row >= 0) {
		int src_index = right_click_row;
		if (src_index >= 0 && src_index < static_cast<int>(ui.sorted_result_indices.size()))
			src_index = ui.sorted_result_indices[static_cast<size_t>(src_index)];
		if (src_index >= 0 && src_index < total) {
			uint64_t addr = sc.results[static_cast<size_t>(src_index)].address;
			ui.selected_result = right_click_row;
			if (ui.result_multi_sel.count(right_click_row) == 0) {
				ui.result_multi_sel.clear();
				ui.result_multi_sel.insert(right_click_row);
				ui.last_result_anchor = right_click_row;
			}
			s_view_owned_ctx_result_addr.store(addr);
			s_open_result_ctx.store(true);
			diag_logf("results right_click row=%d addr=0x%llX",
				right_click_row, static_cast<unsigned long long>(addr));
		}
	}

	if (include_sb) {
		float sb_x = ox + w - kScrollbarTrackW - 4.f;
		interactive_scrollbar(ui.result_sb, dl,
			sb_x, body_y, kScrollbarTrackW, body_h,
			content_h, body_h, a);
	}

	if (total == 0) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::memory;
		cfg.title = sc.has_initial_scan ? "No matches" : "Nothing scanned yet";
		cfg.body = sc.has_initial_scan
			? "Refine your filter or undo to widen the search."
			: "Pick a value type and a comparison, then start a scan.";
		aida::ui::empty_state::render(ImVec2(ox, body_y), ImVec2(w, body_h), cfg);
	} else if (sc.scanning.load() && total < 6) {
		float sk_y = body_y + static_cast<float>(total) * kResultRowHeight + 6.f;
		for (int s = 0; s < 4; ++s) {
			if (sk_y + 16.f > body_y + body_h) break;
			aida::ui::skeleton::render_block(dl,
				ImVec2(ox + 12.f, sk_y),
				ImVec2(ox + w - 24.f, sk_y + 14.f), 6.f, 1.4f);
			sk_y += 22.f;
		}
	}

	float pill_target = (ui.user_scrolled_up && total > visible_rows) ? 1.f : 0.f;
	ui.autoscroll_pill_alpha = aida::motion::smooth_lerp(
		ui.autoscroll_pill_alpha, pill_target, 12.f, dt);
	if (ui.autoscroll_pill_alpha > 0.02f) {
		float pa = ui.autoscroll_pill_alpha;
		const char* lbl = "Jump to bottom";
		ImFont* fnt = aida::ui::fonts::body();
		ImVec2 pts = fnt->CalcTextSizeA(fnt->FontSize, FLT_MAX, 0.f, lbl);
		float pad_x = 12.f;
		float pw = pts.x + pad_x * 2.f + 14.f;
		float ph = 28.f;
		float px = ox + w * 0.5f - pw * 0.5f;
		float py = oy + h - ph - 14.f;
		ImVec2 pa_min(px, py - (1.f - pa) * 6.f);
		ImVec2 pa_max(px + pw, py + ph - (1.f - pa) * 6.f);

		dl->AddRectFilled(pa_min, pa_max,
			aida::ui::with_alpha(t.bg_overlay, a * pa * 0.95f), ph * 0.5f);
		dl->AddRect(pa_min, pa_max,
			aida::ui::with_alpha(t.accent_u32, a * pa), ph * 0.5f, 0, 1.f);

		float dot_cx = pa_min.x + pad_x;
		float dot_cy = (pa_min.y + pa_max.y) * 0.5f;
		dl->AddTriangleFilled(
			ImVec2(dot_cx - 5.f, dot_cy - 3.f),
			ImVec2(dot_cx + 5.f, dot_cy - 3.f),
			ImVec2(dot_cx, dot_cy + 4.f),
			aida::ui::with_alpha(t.accent_u32, a * pa));
		dl->AddText(fnt, fnt->FontSize,
			ImVec2(dot_cx + 10.f, pa_min.y + (ph - fnt->FontSize) * 0.5f),
			aida::ui::with_alpha(t.text_primary, a * pa), lbl);

		ImGui::SetCursorScreenPos(pa_min);
		ImGui::PushID("##scroll_jump");
		ImGui::InvisibleButton("##sj_b", ImVec2(pw, ph));
		if (ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
			!ui_input_gate::popup_blocks_background_input())
		{
			ui.result_sb.target_scroll_y = max_scroll;
			ui.user_scrolled_up = false;
			diag_log("results jump_to_bottom");
		}
		ImGui::PopID();
	}
}

void render_address_pane(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + kAddrHeaderHeight),
		aida::ui::with_alpha(t.panel_header, a * 0.92f));
	dl->AddLine(ImVec2(ox, oy + kAddrHeaderHeight),
		ImVec2(ox + w, oy + kAddrHeaderHeight),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	ImFont* h_font = aida::ui::fonts::body_em();
	float h_fs = h_font->FontSize;
	dl->AddText(h_font, h_fs,
		ImVec2(ox + 12.f, oy + (kAddrHeaderHeight - h_fs) * 0.5f),
		aida::ui::with_alpha(t.text_primary, a), "Address List");

	size_t addr_count = 0;
	{
		std::lock_guard<std::mutex> lk(sc.address_mutex);
		addr_count = sc.address_list.size();
	}
	{
		char count_buf[40];
		snprintf(count_buf, sizeof(count_buf), "%zu items", addr_count);
		ImFont* body_fn = aida::ui::fonts::body();
		ImVec2 cts = body_fn->CalcTextSizeA(body_fn->FontSize, FLT_MAX, 0.f, count_buf);
		dl->AddText(body_fn, body_fn->FontSize,
			ImVec2(ox + 12.f + h_font->CalcTextSizeA(h_fs, FLT_MAX, 0.f, "Address List").x + 12.f,
				oy + (kAddrHeaderHeight - body_fn->FontSize) * 0.5f),
			aida::ui::with_alpha(t.text_dim, a), count_buf);
		(void)cts;
	}

	float right_x = ox + w - 12.f;

	ImFont* btn_fn = aida::ui::fonts::body();
	float btn_fs = btn_fn->FontSize;

	{
		const char* lbl = "Auto-refresh";
		ImVec2 lsz = btn_fn->CalcTextSizeA(btn_fs, FLT_MAX, 0.f, lbl);
		float track_w = 36.f;
		float gap = 6.f;
		float total_w = track_w + gap + lsz.x;
		float bx = right_x - total_w;
		float by = oy + (kAddrHeaderHeight - 20.f) * 0.5f;

		ImGui::PushID("##addr_auto_refresh");
		ImGui::SetCursorScreenPos(ImVec2(bx, by));
		ImGui::InvisibleButton("##af_b", ImVec2(total_w, 20.f));
		bool hov = ImGui::IsItemHovered();
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
			!ui_input_gate::popup_blocks_background_input();
		if (clk) {
			ui.auto_refresh = !ui.auto_refresh;
			diag_logf("address auto_refresh_toggle now=%d", static_cast<int>(ui.auto_refresh));
		}
		bool on = ui.auto_refresh;
		ImU32 trc = aida::ui::with_alpha(on ? t.accent_dim : t.bg_overlay, a);
		ImU32 brd = aida::ui::with_alpha(
			(on ? t.accent_u32 : (hov ? t.border_focus : t.border_strong)), a);
		ImVec2 ta(bx, by);
		ImVec2 tb(bx + track_w, by + 20.f);
		dl->AddRectFilled(ta, tb, trc, 10.f);
		dl->AddRect(ta, tb, brd, 10.f, 0, 1.f);
		float knob_r = (20.f - 4.f) * 0.5f;
		float knob_cx = on ? (bx + track_w - knob_r - 2.f) : (bx + knob_r + 2.f);
		float knob_cy = by + 10.f;
		dl->AddCircleFilled(ImVec2(knob_cx, knob_cy), knob_r,
			IM_COL32(240, 246, 255, 240), 16);
		ImU32 lbl_col = on
			? aida::ui::with_alpha(t.accent_u32, a)
			: aida::ui::with_alpha(t.text_dim, a);
		dl->AddText(btn_fn, btn_fs,
			ImVec2(tb.x + gap, by + (20.f - btn_fs) * 0.5f), lbl_col, lbl);
		ImGui::PopID();
		right_x -= (total_w + 16.f);
	}

	{
		const char* lbl = "Add Address";
		ImVec2 lsz = btn_fn->CalcTextSizeA(btn_fs, FLT_MAX, 0.f, lbl);
		float bw = lsz.x + 22.f;
		float bh = 24.f;
		float bx = right_x - bw;
		float by = oy + (kAddrHeaderHeight - bh) * 0.5f;
		ImGui::PushID("##addr_add_manual");
		ImGui::SetCursorScreenPos(ImVec2(bx, by));
		ImGui::InvisibleButton("##add_b", ImVec2(bw, bh));
		bool hov = ImGui::IsItemHovered();
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
			!ui_input_gate::popup_blocks_background_input();
		if (clk) {
			s_pending_add_addr.store(0);
			s_pending_add_vtype.store(static_cast<int>(sc.config.value_type));
			s_open_add_dialog.store(true);
			diag_log("address add_manual_button");
		}
		ImU32 bg = aida::ui::with_alpha(hov ? t.hover_wash : t.bg_overlay, a * 0.5f);
		ImU32 brd = aida::ui::with_alpha(hov ? t.accent_hover : t.border_strong, a);
		dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bw, by + bh), bg, bh * 0.5f);
		dl->AddRect(ImVec2(bx, by), ImVec2(bx + bw, by + bh), brd, bh * 0.5f, 0, 1.f);
		ImU32 plus_col = aida::ui::with_alpha(hov ? t.accent_u32 : t.text_secondary, a);
		dl->AddText(btn_fn, btn_fs,
			ImVec2(bx + 10.f, by + (bh - btn_fs) * 0.5f), plus_col, lbl);
		ImGui::PopID();
		right_x -= (bw + 8.f);
	}

	column_layout_t cols[5];
	int addr_total = static_cast<int>(addr_count);
	bool include_sb = addr_total > 0;
	compute_addr_columns(ox, w, cols, include_sb);

	float tbl_y0 = oy + kAddrHeaderHeight;
	dl->AddRectFilled(ImVec2(ox, tbl_y0),
		ImVec2(ox + w, tbl_y0 + kAddrTableHeaderH),
		aida::ui::with_alpha(t.bg_overlay, a * 0.40f));
	ImFont* col_fn = aida::ui::fonts::caption();
	if (!col_fn) col_fn = aida::ui::fonts::body();
	float col_fs = col_fn->FontSize;
	for (int c = 0; c < 5; ++c) {
		if (!cols[c].title || cols[c].title[0] == '\0') continue;
		dl->AddText(col_fn, col_fs,
			ImVec2(cols[c].inner_x0, tbl_y0 + (kAddrTableHeaderH - col_fs) * 0.5f),
			aida::ui::with_alpha(t.text_dim, a), cols[c].title);
	}

	float body_y = tbl_y0 + kAddrTableHeaderH;
	float body_h = h - kAddrHeaderHeight - kAddrTableHeaderH;
	if (body_h < 1.f) body_h = 1.f;
	int visible_rows = static_cast<int>(body_h / kAddrRowHeight);
	if (visible_rows < 1) visible_rows = 1;

	int freeze_toggle_idx = -1;
	bool freeze_toggle_val = false;
	int delete_idx = -1;
	int desc_edit_request_idx = -1;
	int value_edit_request_idx = -1;
	int change_type_request_idx = -1;
	int ctx_addr_request_row = -1;
	uint64_t ctx_addr_value = 0;

	std::unique_lock<std::mutex> lk(sc.address_mutex);
	int total = static_cast<int>(sc.address_list.size());

	bool body_hover = ImGui::IsMouseHoveringRect(
		ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), false) &&
		!ui_input_gate::popup_blocks_background_input();
	if (body_hover) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f) {
			ui.address_sb.target_scroll_y -= wheel * kAddrRowHeight * 3.f;
			diag_logf("address wheel=%.2f target=%.1f", wheel, ui.address_sb.target_scroll_y);
		}
	}

	float content_h = static_cast<float>(total) * kAddrRowHeight;
	float max_scroll = std::max(0.f, content_h - body_h);
	ui.address_sb.target_scroll_y = std::clamp(ui.address_sb.target_scroll_y, 0.f, max_scroll);
	float dt = aida::ui::clock::dt();
	ui_anim::smooth_scroll(ui.address_sb.scroll_y, ui.address_sb.target_scroll_y, 22.f, dt);

	int first_row = static_cast<int>(ui.address_sb.scroll_y / kAddrRowHeight);
	if (first_row < 0) first_row = 0;
	int last_row = std::min(total, first_row + visible_rows + 2);

	ImGui::PushClipRect(ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), true);

	ImFont* code_fn = aida::ui::fonts::code();
	float code_fs = code_fn->FontSize;
	ImFont* body_fn = aida::ui::fonts::body();
	float body_fs = body_fn->FontSize;

	float row_right_edge = include_sb ? (ox + w - kScrollbarTrackW - 6.f) : (ox + w);

	for (int i = first_row; i < last_row; ++i) {
		float ry = body_y + static_cast<float>(i) * kAddrRowHeight - ui.address_sb.scroll_y;
		if (ry + kAddrRowHeight < body_y || ry > body_y + body_h) continue;

		bool sel = (ui.address_multi_sel.count(i) > 0) || (ui.selected_address == i);
		bool hov = ImGui::IsMouseHoveringRect(
			ImVec2(ox, ry), ImVec2(row_right_edge, ry + kAddrRowHeight), false) &&
			!ui_input_gate::popup_blocks_background_input();

		if (sel) {
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + w, ry + kAddrRowHeight),
				aida::ui::with_alpha(t.selection, a));
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + 3.f, ry + kAddrRowHeight),
				aida::ui::with_alpha(t.accent_u32, a));
		} else if (hov) {
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + w, ry + kAddrRowHeight),
				aida::ui::with_alpha(t.hover_wash, a));
		} else if (i & 1) {
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + w, ry + kAddrRowHeight),
				aida::ui::with_alpha(t.hover_wash, 0.22f * a));
		}

		auto& e = sc.address_list[static_cast<size_t>(i)];

		{
			float box_w = 16.f;
			float box_h = 16.f;
			float bx = cols[kColAddrFreeze].inner_x0 + 6.f;
			float by = ry + (kAddrRowHeight - box_h) * 0.5f;
			ImGui::PushID(i * 11 + 3);
			ImGui::SetCursorScreenPos(ImVec2(bx, by));
			ImGui::InvisibleButton("##fz", ImVec2(box_w, box_h));
			bool fz_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
				!ui_input_gate::popup_blocks_background_input();
			ImGui::PopID();
			bool fzhov = ImGui::IsMouseHoveringRect(
				ImVec2(bx, by), ImVec2(bx + box_w, by + box_h), false);
			if (fz_clicked) {
				freeze_toggle_idx = i;
				freeze_toggle_val = !e.frozen;
				diag_logf("address freeze_toggle idx=%d addr=0x%llX now=%d",
					i, static_cast<unsigned long long>(e.address),
					static_cast<int>(freeze_toggle_val));
			}

			bool is_on = e.frozen;
			ImU32 box_bg = is_on
				? aida::ui::with_alpha(t.accent_dim, a)
				: aida::ui::with_alpha(t.bg_overlay, a);
			ImU32 box_brd = is_on
				? aida::ui::with_alpha(t.accent_u32, a)
				: aida::ui::with_alpha(fzhov ? t.accent_hover : t.border_strong, a);
			dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + box_w, by + box_h), box_bg, 4.f);
			dl->AddRect(ImVec2(bx, by), ImVec2(bx + box_w, by + box_h), box_brd, 4.f, 0, 1.5f);
			if (is_on) {
				ImU32 chk = aida::ui::with_alpha(t.text_primary, a);
				dl->AddLine(ImVec2(bx + 4.f, by + 8.f), ImVec2(bx + 7.f, by + 12.f), chk, 1.7f);
				dl->AddLine(ImVec2(bx + 7.f, by + 12.f), ImVec2(bx + 12.f, by + 5.f), chk, 1.7f);
			}
			float lock_x = bx + box_w + 8.f;
			float lock_y = ry + (kAddrRowHeight - body_fs) * 0.5f;
			const char* lock_lbl = is_on ? "Locked" : "Free";
			ImU32 lock_col = is_on
				? aida::ui::with_alpha(t.accent_u32, a)
				: aida::ui::with_alpha(t.text_dim, a);
			dl->PushClipRect(
				ImVec2(lock_x, ry),
				ImVec2(cols[kColAddrFreeze].inner_x1, ry + kAddrRowHeight), true);
			dl->AddText(body_fn, body_fs, ImVec2(lock_x, lock_y), lock_col, lock_lbl);
			dl->PopClipRect();
		}

		{
			std::string disp = e.description.empty()
				? std::string("<no description>")
				: e.description;
			ImU32 col = e.description.empty()
				? aida::ui::with_alpha(t.text_dim, a)
				: aida::ui::with_alpha(t.text_primary, a);
			float maxw = cols[kColAddrDesc].inner_x1 - cols[kColAddrDesc].inner_x0;
			dl->PushClipRect(
				ImVec2(cols[kColAddrDesc].inner_x0, ry),
				ImVec2(cols[kColAddrDesc].inner_x1, ry + kAddrRowHeight), true);
			draw_clipped_text(dl, body_fn, body_fs,
				cols[kColAddrDesc].inner_x0,
				ry + (kAddrRowHeight - body_fs) * 0.5f,
				maxw, col, disp);
			dl->PopClipRect();
		}

		{
			char abuf[24];
			snprintf(abuf, sizeof(abuf), "%016" PRIX64,
				static_cast<unsigned long long>(e.address));
			float maxw = cols[kColAddrAddress].inner_x1 - cols[kColAddrAddress].inner_x0;
			dl->PushClipRect(
				ImVec2(cols[kColAddrAddress].inner_x0, ry),
				ImVec2(cols[kColAddrAddress].inner_x1, ry + kAddrRowHeight), true);
			draw_clipped_text(dl, code_fn, code_fs,
				cols[kColAddrAddress].inner_x0,
				ry + (kAddrRowHeight - code_fs) * 0.5f,
				maxw, aida::ui::with_alpha(t.text_address, a),
				std::string(abuf));
			dl->PopClipRect();
		}

		{
			const char* tn = memory_scanner::value_type_name(e.value_type);
			float maxw = cols[kColAddrType].inner_x1 - cols[kColAddrType].inner_x0;
			dl->PushClipRect(
				ImVec2(cols[kColAddrType].inner_x0, ry),
				ImVec2(cols[kColAddrType].inner_x1, ry + kAddrRowHeight), true);
			draw_clipped_text(dl, body_fn, body_fs,
				cols[kColAddrType].inner_x0,
				ry + (kAddrRowHeight - body_fs) * 0.5f,
				maxw, aida::ui::with_alpha(t.text_secondary, a),
				std::string(tn));
			dl->PopClipRect();
		}

		{
			std::string val_str = memory_scanner::format_value(e.last_value, e.value_type);
			float maxw = cols[kColAddrValue].inner_x1 - cols[kColAddrValue].inner_x0;
			ImU32 vcol = aida::ui::with_alpha(e.frozen ? t.accent_u32 : t.success, a);
			dl->PushClipRect(
				ImVec2(cols[kColAddrValue].inner_x0, ry),
				ImVec2(cols[kColAddrValue].inner_x1, ry + kAddrRowHeight), true);
			draw_clipped_text(dl, code_fn, code_fs,
				cols[kColAddrValue].inner_x0,
				ry + (kAddrRowHeight - code_fs) * 0.5f,
				maxw, vcol, val_str);
			dl->PopClipRect();
		}

		float mx_now = ImGui::GetMousePos().x;
		bool in_freeze_col = (mx_now >= cols[kColAddrFreeze].x0 && mx_now < cols[kColAddrFreeze].x1);

		if (hov && !in_freeze_col && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			ui.selected_address = i;
			handle_multi_select(ui.address_multi_sel, ui.last_address_anchor, i, total);
			diag_logf("address row_click idx=%d multi=%zu",
				i, ui.address_multi_sel.size());
		}

		if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
			float mx = ImGui::GetMousePos().x;
			if (mx >= cols[kColAddrDesc].x0 && mx < cols[kColAddrDesc].x1) {
				desc_edit_request_idx = i;
				diag_logf("address desc_edit_request idx=%d", i);
			} else if (mx >= cols[kColAddrValue].x0 && mx < cols[kColAddrValue].x1) {
				value_edit_request_idx = i;
				diag_logf("address value_edit_request idx=%d", i);
			} else if (mx >= cols[kColAddrType].x0 && mx < cols[kColAddrType].x1) {
				change_type_request_idx = i;
				diag_logf("address change_type_request idx=%d", i);
			}
		}

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			ctx_addr_request_row = i;
			ctx_addr_value = e.address;
			ui.selected_address = i;
			if (ui.address_multi_sel.count(i) == 0) {
				ui.address_multi_sel.clear();
				ui.address_multi_sel.insert(i);
				ui.last_address_anchor = i;
			}
			diag_logf("address right_click idx=%d addr=0x%llX",
				i, static_cast<unsigned long long>(e.address));
		}

		if (sel && ImGui::IsKeyPressed(ImGuiKey_Delete, false) && !input_is_active()) {
			delete_idx = i;
			ui.selected_address = -1;
			diag_logf("address key_delete idx=%d", i);
			break;
		}
	}

	ImGui::PopClipRect();

	if (include_sb) {
		float sb_x = ox + w - kScrollbarTrackW - 4.f;
		interactive_scrollbar(ui.address_sb, dl,
			sb_x, body_y, kScrollbarTrackW, body_h,
			content_h, body_h, a);
	}

	if (total == 0) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::dots;
		cfg.title = "Watchlist is empty";
		cfg.body  = "Double-click a result to track. Right-click for more options.";
		aida::ui::empty_state::render(ImVec2(ox, body_y), ImVec2(w, body_h), cfg);
	}

	if (ctx_addr_request_row >= 0) {
		s_view_owned_ctx_addr_row.store(ctx_addr_request_row);
		s_view_owned_ctx_addr_value.store(ctx_addr_value);
		s_open_address_ctx.store(true);
	}

	if (desc_edit_request_idx >= 0) {
		ui.desc_edit.active = true;
		ui.desc_edit.address_index = desc_edit_request_idx;
		ui.desc_edit.open_from_add_dialog = false;
		const auto& cur = sc.address_list[static_cast<size_t>(desc_edit_request_idx)].description;
		_snprintf_s(ui.desc_edit.buf, sizeof(ui.desc_edit.buf), _TRUNCATE,
			"%s", cur.c_str());
	}

	if (value_edit_request_idx >= 0) {
		s_pending_edit_value_index.store(value_edit_request_idx);
		const auto& e = sc.address_list[static_cast<size_t>(value_edit_request_idx)];
		std::string vs = memory_scanner::format_value(e.last_value, e.value_type);
		_snprintf_s(s_edit_value_buf, sizeof(s_edit_value_buf), _TRUNCATE, "%s", vs.c_str());
	}

	if (change_type_request_idx >= 0) {
		s_pending_change_type_index.store(change_type_request_idx);
		s_pending_change_type_value = static_cast<int>(
			sc.address_list[static_cast<size_t>(change_type_request_idx)].value_type);
	}

	lk.unlock();

	if (freeze_toggle_idx >= 0)
		memory_scanner::freeze_address(static_cast<size_t>(freeze_toggle_idx), freeze_toggle_val);
	if (delete_idx >= 0)
		memory_scanner::remove_address(static_cast<size_t>(delete_idx));
}

void render_splitter(ImDrawList* dl, float ox, float oy, float w, float a,
                     float& result_h, float& addr_h, float pane_height)
{
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	float min_h = 80.f;
	float total = pane_height;

	float split_y = oy;
	ImVec2 a_min(ox + 2.f, split_y);
	ImVec2 a_max(ox + w - 2.f, split_y + kSplitterThickness);

	ImGui::PushID("##scanner_splitter");
	ImGui::SetCursorScreenPos(a_min);
	ImGui::InvisibleButton("##spl", ImVec2(a_max.x - a_min.x, a_max.y - a_min.y));
	bool hov = ImGui::IsItemHovered();
	bool act = ImGui::IsItemActive();
	bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
		!ui_input_gate::popup_blocks_background_input();
	ImGui::PopID();

	if (clicked) {
		ui.splitter_dragging = true;
		diag_log("splitter drag_begin");
	}
	if (ui.splitter_dragging && !ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
		ui.splitter_dragging = false;
		diag_logf("splitter drag_end ratio=%.3f", ui.result_pane_ratio);
	}
	if (ui.splitter_dragging) {
		float dy = ImGui::GetIO().MouseDelta.y;
		if (std::abs(dy) > 0.5f) {
			ui.result_pane_ratio += dy / total;
			ui.result_pane_ratio = std::clamp(ui.result_pane_ratio,
				min_h / total, 1.f - min_h / total);
		}
	}
	float target = (hov || act) ? 1.f : 0.f;
	ui.splitter_press_anim = ui_anim::smooth_lerp(
		ui.splitter_press_anim, target, 14.f, aida::ui::clock::dt());

	if (hov || act) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);

	ImU32 base = aida::ui::with_alpha(t.border_strong, 0.55f * a);
	ImU32 hi   = aida::ui::with_alpha(t.accent_u32, 0.95f * a);
	ImU32 cur = aida::ui::mix(base, hi, ui.splitter_press_anim);
	dl->AddRectFilled(a_min, a_max, cur, kSplitterThickness * 0.5f);

	if (ui.splitter_press_anim > 0.04f) {
		float cx = (a_min.x + a_max.x) * 0.5f;
		float cy = (a_min.y + a_max.y) * 0.5f;
		ImU32 dotc = aida::ui::with_alpha(t.text_primary, 0.85f * ui.splitter_press_anim * a);
		for (int i = -1; i <= 1; ++i) {
			dl->AddCircleFilled(
				ImVec2(cx + static_cast<float>(i) * 8.f, cy), 1.6f, dotc, 12);
		}
	}

	result_h = total * ui.result_pane_ratio;
	addr_h   = total - result_h - kSplitterThickness;
}

void process_add_dialog() {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	if (s_open_add_dialog.load()) {
		s_open_add_dialog.store(false);
		ImGui::OpenPopup("##value_scan_add_dialog");
		ui.desc_edit.buf[0] = '\0';
		ui.desc_edit.pending_add_address = s_pending_add_addr.load();
		ui.desc_edit.pending_add_value_type = s_pending_add_vtype.load();
		ui.desc_edit.open_from_add_dialog = true;
		diag_logf("dialog add_open addr=0x%llX vtype=%d",
			static_cast<unsigned long long>(ui.desc_edit.pending_add_address),
			ui.desc_edit.pending_add_value_type);
	}

	const auto& t = aida::ui::resolved();
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_strong, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, 1.f));
	ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 12.f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20.f, 16.f));

	ImGui::SetNextWindowSize(ImVec2(400.f, 0.f), ImGuiCond_Always);
	if (ImGui::BeginPopupModal("##value_scan_add_dialog", nullptr,
		ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
		ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImFont* h_fn = aida::ui::fonts::h2();
		ImGui::PushFont(h_fn);
		ImGui::TextUnformatted("Add to address list");
		ImGui::PopFont();

		ImGui::Spacing();
		ImGui::Dummy(ImVec2(0.f, 4.f));

		char addr_buf[40];
		snprintf(addr_buf, sizeof(addr_buf), "Address: 0x%016llX",
			static_cast<unsigned long long>(ui.desc_edit.pending_add_address));
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_secondary), "%s", addr_buf);
		ImGui::Spacing();

		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim), "Description (optional)");
		ImGui::SetNextItemWidth(-1.f);
		bool focus_now = ImGui::IsWindowAppearing();
		if (focus_now) ImGui::SetKeyboardFocusHere();
		ImGui::InputText("##add_desc", ui.desc_edit.buf, sizeof(ui.desc_edit.buf));

		ImGui::Spacing();
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim), "Type");
		const char* current_name = memory_scanner::value_type_name(
			static_cast<memory_scanner::value_type_t>(ui.desc_edit.pending_add_value_type));
		ImGui::SetNextItemWidth(-1.f);
		if (ImGui::BeginCombo("##add_type", current_name)) {
			for (int i = 0; i < static_cast<int>(memory_scanner::value_type_t::COUNT); ++i) {
				bool sel = (ui.desc_edit.pending_add_value_type == i);
				if (ImGui::Selectable(memory_scanner::value_type_name(
					static_cast<memory_scanner::value_type_t>(i)), sel))
				{
					ui.desc_edit.pending_add_value_type = i;
				}
			}
			ImGui::EndCombo();
		}

		ImGui::Spacing();
		ImGui::Dummy(ImVec2(0.f, 8.f));

		bool enter_submit = ImGui::IsKeyPressed(ImGuiKey_Enter, false) ||
			ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false);
		bool esc_cancel = ImGui::IsKeyPressed(ImGuiKey_Escape, false);

		float btn_w = 110.f;
		float spacing = 8.f;
		float total_btn_w = btn_w * 2.f + spacing;
		float region_w = ImGui::GetContentRegionAvail().x;
		ImGui::SetCursorPosX(ImGui::GetCursorPosX() + region_w - total_btn_w);

		bool cancel_clicked = aida::ui::button("Cancel",
			aida::ui::button_kind_t::ghost, aida::ui::size_t_::md,
			ImVec2(btn_w, 0.f));
		ImGui::SameLine(0.f, spacing);
		bool add_clicked = aida::ui::button("Add",
			aida::ui::button_kind_t::primary, aida::ui::size_t_::md,
			ImVec2(btn_w, 0.f));

		if (cancel_clicked || esc_cancel) {
			diag_log("dialog add_cancel");
			ImGui::CloseCurrentPopup();
		} else if (add_clicked || enter_submit) {
			std::string desc(ui.desc_edit.buf);
			memory_scanner::add_address(
				ui.desc_edit.pending_add_address, desc,
				static_cast<memory_scanner::value_type_t>(
					ui.desc_edit.pending_add_value_type));
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] memory_scanner add_address invoked");
			toast_notification::push("Added to address list.",
				toast_notification::toast_type_t::success, 2.5f);
			diag_logf("dialog add_submit desc='%s' vtype=%d",
				desc.c_str(), ui.desc_edit.pending_add_value_type);
			ImGui::CloseCurrentPopup();
		}
		(void)sc;
		ImGui::EndPopup();
	}

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(3);
}

void process_edit_description_dialog() {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	if (!ui.desc_edit.active || ui.desc_edit.open_from_add_dialog) return;

	static bool s_ed_was_open = false;
	bool is_open_now = ImGui::IsPopupOpen("##value_scan_edit_desc");
	if (s_ed_was_open && !is_open_now) {
		ui.desc_edit.active = false;
		s_ed_was_open = false;
		diag_log("dialog edit_desc_external_close");
		return;
	}
	if (!is_open_now) {
		ImGui::OpenPopup("##value_scan_edit_desc");
	}
	s_ed_was_open = true;

	const auto& t = aida::ui::resolved();
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_strong, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, 1.f));
	ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 12.f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20.f, 16.f));

	ImGui::SetNextWindowSize(ImVec2(420.f, 0.f), ImGuiCond_Always);
	if (ImGui::BeginPopupModal("##value_scan_edit_desc", nullptr,
		ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
		ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImFont* h_fn = aida::ui::fonts::h2();
		ImGui::PushFont(h_fn);
		ImGui::TextUnformatted("Edit description");
		ImGui::PopFont();
		ImGui::Spacing();
		ImGui::Dummy(ImVec2(0.f, 4.f));

		uint64_t cur_addr = 0;
		{
			std::lock_guard<std::mutex> lk(sc.address_mutex);
			if (ui.desc_edit.address_index >= 0 &&
				ui.desc_edit.address_index < static_cast<int>(sc.address_list.size()))
			{
				cur_addr = sc.address_list[static_cast<size_t>(ui.desc_edit.address_index)].address;
			}
		}
		char abuf[40];
		snprintf(abuf, sizeof(abuf), "Address: 0x%016llX",
			static_cast<unsigned long long>(cur_addr));
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_secondary), "%s", abuf);

		ImGui::Spacing();
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim), "Description");
		ImGui::SetNextItemWidth(-1.f);
		if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
		ImGui::InputText("##edit_desc_in", ui.desc_edit.buf, sizeof(ui.desc_edit.buf));

		ImGui::Spacing();
		ImGui::Dummy(ImVec2(0.f, 6.f));

		bool enter_submit = ImGui::IsKeyPressed(ImGuiKey_Enter, false) ||
			ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false);
		bool esc_cancel = ImGui::IsKeyPressed(ImGuiKey_Escape, false);

		float btn_w = 110.f;
		float spacing = 8.f;
		float total_btn_w = btn_w * 2.f + spacing;
		float region_w = ImGui::GetContentRegionAvail().x;
		ImGui::SetCursorPosX(ImGui::GetCursorPosX() + region_w - total_btn_w);

		bool cancel_clicked = aida::ui::button("Cancel",
			aida::ui::button_kind_t::ghost, aida::ui::size_t_::md,
			ImVec2(btn_w, 0.f));
		ImGui::SameLine(0.f, spacing);
		bool save_clicked = aida::ui::button("Save",
			aida::ui::button_kind_t::primary, aida::ui::size_t_::md,
			ImVec2(btn_w, 0.f));

		if (cancel_clicked || esc_cancel) {
			diag_log("dialog edit_desc_cancel");
			ImGui::CloseCurrentPopup();
			ui.desc_edit.active = false;
			s_ed_was_open = false;
		} else if (save_clicked || enter_submit) {
			std::string val(ui.desc_edit.buf);
			{
				std::lock_guard<std::mutex> lk(sc.address_mutex);
				if (ui.desc_edit.address_index >= 0 &&
					ui.desc_edit.address_index < static_cast<int>(sc.address_list.size()))
				{
					sc.address_list[static_cast<size_t>(ui.desc_edit.address_index)].description = val;
				}
			}
			diag_logf("dialog edit_desc_save idx=%d desc='%s'",
				ui.desc_edit.address_index, val.c_str());
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] memory_scanner edit_description");
			ImGui::CloseCurrentPopup();
			ui.desc_edit.active = false;
			s_ed_was_open = false;
		}
		ImGui::EndPopup();
	}

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(3);
}

void process_edit_value_dialog() {
	auto& sc = memory_scanner::g_state;
	int idx = s_pending_edit_value_index.load();
	if (idx < 0) return;

	static bool s_ev_was_open = false;
	bool is_open_now = ImGui::IsPopupOpen("##value_scan_edit_value");
	if (s_ev_was_open && !is_open_now) {
		s_pending_edit_value_index.store(-1);
		s_ev_was_open = false;
		diag_log("dialog edit_value_external_close");
		return;
	}
	if (!is_open_now) {
		ImGui::OpenPopup("##value_scan_edit_value");
	}
	s_ev_was_open = true;

	const auto& t = aida::ui::resolved();
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_strong, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, 1.f));
	ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 12.f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20.f, 16.f));

	ImGui::SetNextWindowSize(ImVec2(380.f, 0.f), ImGuiCond_Always);
	if (ImGui::BeginPopupModal("##value_scan_edit_value", nullptr,
		ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
		ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImFont* h_fn = aida::ui::fonts::h2();
		ImGui::PushFont(h_fn);
		ImGui::TextUnformatted("Change value");
		ImGui::PopFont();
		ImGui::Spacing();
		ImGui::Dummy(ImVec2(0.f, 4.f));

		uint64_t addr_v = 0;
		memory_scanner::value_type_t vt = memory_scanner::value_type_t::int32_val;
		{
			std::lock_guard<std::mutex> lk(sc.address_mutex);
			if (idx >= 0 && idx < static_cast<int>(sc.address_list.size())) {
				addr_v = sc.address_list[static_cast<size_t>(idx)].address;
				vt = sc.address_list[static_cast<size_t>(idx)].value_type;
			}
		}
		char abuf[64];
		snprintf(abuf, sizeof(abuf), "0x%016llX  (%s)",
			static_cast<unsigned long long>(addr_v),
			memory_scanner::value_type_name(vt));
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_secondary), "%s", abuf);
		ImGui::Spacing();
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim), "New value");
		ImGui::SetNextItemWidth(-1.f);
		if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
		ImGui::InputText("##edit_value_in", s_edit_value_buf, sizeof(s_edit_value_buf));

		ImGui::Spacing();
		ImGui::Dummy(ImVec2(0.f, 6.f));

		bool enter_submit = ImGui::IsKeyPressed(ImGuiKey_Enter, false) ||
			ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false);
		bool esc_cancel = ImGui::IsKeyPressed(ImGuiKey_Escape, false);

		float btn_w = 110.f;
		float spacing = 8.f;
		float total_btn_w = btn_w * 2.f + spacing;
		float region_w = ImGui::GetContentRegionAvail().x;
		ImGui::SetCursorPosX(ImGui::GetCursorPosX() + region_w - total_btn_w);

		bool cancel_clicked = aida::ui::button("Cancel",
			aida::ui::button_kind_t::ghost, aida::ui::size_t_::md,
			ImVec2(btn_w, 0.f));
		ImGui::SameLine(0.f, spacing);
		bool write_clicked = aida::ui::button("Write",
			aida::ui::button_kind_t::primary, aida::ui::size_t_::md,
			ImVec2(btn_w, 0.f));

		if (cancel_clicked || esc_cancel) {
			diag_log("dialog edit_value_cancel");
			ImGui::CloseCurrentPopup();
			s_pending_edit_value_index.store(-1);
			s_ev_was_open = false;
		} else if (write_clicked || enter_submit) {
			std::string text(s_edit_value_buf);
			memory_scanner::write_value(addr_v, vt, text, sc.config.hex_input);
			diag_logf("dialog edit_value_write addr=0x%llX val='%s'",
				static_cast<unsigned long long>(addr_v), text.c_str());
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] memory_scanner write_value");
			toast_notification::push("Wrote value.",
				toast_notification::toast_type_t::success, 2.f);
			ImGui::CloseCurrentPopup();
			s_pending_edit_value_index.store(-1);
			s_ev_was_open = false;
		}
		ImGui::EndPopup();
	}

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(3);
}

void process_change_type_dialog() {
	auto& sc = memory_scanner::g_state;
	int idx = s_pending_change_type_index.load();
	if (idx < 0) return;

	static bool s_ct_was_open = false;
	bool is_open_now = ImGui::IsPopupOpen("##value_scan_change_type");
	if (s_ct_was_open && !is_open_now) {
		s_pending_change_type_index.store(-1);
		s_ct_was_open = false;
		diag_log("dialog change_type_external_close");
		return;
	}
	if (!is_open_now) {
		ImGui::OpenPopup("##value_scan_change_type");
	}
	s_ct_was_open = true;

	const auto& t = aida::ui::resolved();
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_strong, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, 1.f));
	ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 12.f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20.f, 16.f));

	ImGui::SetNextWindowSize(ImVec2(380.f, 0.f), ImGuiCond_Always);
	if (ImGui::BeginPopupModal("##value_scan_change_type", nullptr,
		ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
		ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImFont* h_fn = aida::ui::fonts::h2();
		ImGui::PushFont(h_fn);
		ImGui::TextUnformatted("Change type");
		ImGui::PopFont();
		ImGui::Spacing();
		ImGui::Dummy(ImVec2(0.f, 4.f));

		const char* current_name = memory_scanner::value_type_name(
			static_cast<memory_scanner::value_type_t>(s_pending_change_type_value));
		ImGui::SetNextItemWidth(-1.f);
		if (ImGui::BeginCombo("##chtype_combo", current_name)) {
			for (int i = 0; i < static_cast<int>(memory_scanner::value_type_t::COUNT); ++i) {
				bool sel = (s_pending_change_type_value == i);
				if (ImGui::Selectable(memory_scanner::value_type_name(
					static_cast<memory_scanner::value_type_t>(i)), sel))
				{
					s_pending_change_type_value = i;
				}
			}
			ImGui::EndCombo();
		}

		ImGui::Spacing();
		ImGui::Dummy(ImVec2(0.f, 8.f));

		float btn_w = 110.f;
		float spacing = 8.f;
		float total_btn_w = btn_w * 2.f + spacing;
		float region_w = ImGui::GetContentRegionAvail().x;
		ImGui::SetCursorPosX(ImGui::GetCursorPosX() + region_w - total_btn_w);

		bool cancel_clicked = aida::ui::button("Cancel",
			aida::ui::button_kind_t::ghost, aida::ui::size_t_::md,
			ImVec2(btn_w, 0.f));
		ImGui::SameLine(0.f, spacing);
		bool save_clicked = aida::ui::button("Apply",
			aida::ui::button_kind_t::primary, aida::ui::size_t_::md,
			ImVec2(btn_w, 0.f));
		bool esc_cancel = ImGui::IsKeyPressed(ImGuiKey_Escape, false);

		if (cancel_clicked || esc_cancel) {
			diag_log("dialog change_type_cancel");
			ImGui::CloseCurrentPopup();
			s_pending_change_type_index.store(-1);
			s_ct_was_open = false;
		} else if (save_clicked) {
			{
				std::lock_guard<std::mutex> lk(sc.address_mutex);
				if (idx >= 0 && idx < static_cast<int>(sc.address_list.size())) {
					sc.address_list[static_cast<size_t>(idx)].value_type =
						static_cast<memory_scanner::value_type_t>(s_pending_change_type_value);
					sc.address_list[static_cast<size_t>(idx)].last_value.clear();
					sc.address_list[static_cast<size_t>(idx)].freeze_value.clear();
				}
			}
			diag_logf("dialog change_type_save idx=%d vtype=%d",
				idx, s_pending_change_type_value);
			ImGui::CloseCurrentPopup();
			s_pending_change_type_index.store(-1);
			s_ct_was_open = false;
		}
		ImGui::EndPopup();
	}

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(3);
}

void process_result_context_menu() {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	if (s_open_result_ctx.load()) {
		s_open_result_ctx.store(false);
		ImGui::OpenPopup("##value_scan_result_ctx");
	}

	uint64_t ctx_addr = s_view_owned_ctx_result_addr.load();
	const auto& t = aida::ui::resolved();
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_subtle, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, 1.f));
	ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 10.f);

	if (ImGui::BeginPopup("##value_scan_result_ctx")) {
		size_t multi_count = ui.result_multi_sel.size();
		if (multi_count > 1) {
			char hdr[64];
			snprintf(hdr, sizeof(hdr), "%zu selected", multi_count);
			ImGui::TextDisabled("%s", hdr);
			ImGui::Separator();
		}
		if (ImGui::MenuItem("Add to address list")) {
			diag_logf("ctx_result add_to_list count=%zu primary_addr=0x%llX",
				multi_count, static_cast<unsigned long long>(ctx_addr));
			std::vector<int> indices;
			if (multi_count > 0)
				for (int i : ui.result_multi_sel) indices.push_back(i);
			else
				indices.push_back(ui.selected_result);
			std::vector<uint64_t> addresses;
			{
				std::lock_guard<std::mutex> lk(sc.results_mutex);
				for (int sorted_i : indices) {
					int src_index = sorted_i;
					if (sorted_i >= 0 && sorted_i < static_cast<int>(ui.sorted_result_indices.size()))
						src_index = ui.sorted_result_indices[static_cast<size_t>(sorted_i)];
					if (src_index >= 0 && src_index < static_cast<int>(sc.results.size()))
						addresses.push_back(sc.results[static_cast<size_t>(src_index)].address);
				}
			}
			if (addresses.size() == 1) {
				s_pending_add_addr.store(addresses[0]);
				s_pending_add_vtype.store(static_cast<int>(sc.config.value_type));
				s_open_add_dialog.store(true);
			} else {
				for (uint64_t a_ : addresses)
					memory_scanner::add_address(a_, "", sc.config.value_type);
				char msg[64];
				snprintf(msg, sizeof(msg), "Added %zu addresses.", addresses.size());
				toast_notification::push(msg,
					toast_notification::toast_type_t::success, 2.5f);
			}
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] memory_scanner ctx add_to_list");
		}
		if (ImGui::MenuItem("Open in Hex view")) {
			diag_logf("ctx_result open_hex addr=0x%llX",
				static_cast<unsigned long long>(ctx_addr));
			if (ctx_addr != 0) {
				const auto context = disasm_view::capture_selected_workspace();
				if (hex_view::read_live_memory(context, ctx_addr, 256))
					globals::ui::active_center_view = center_view_t::hex_view;
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] memory_scanner ctx open_hex");
			}
		}
		if (ImGui::MenuItem("Open in Disassembly")) {
			diag_logf("ctx_result open_disasm addr=0x%llX",
				static_cast<unsigned long long>(ctx_addr));
			if (ctx_addr != 0) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(ctx_addr,
					disasm_view::capture_selected_workspace());
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] memory_scanner ctx open_disasm");
			}
		}
		ImGui::Separator();
		if (ImGui::MenuItem("Copy address")) {
			char abuf[24];
			snprintf(abuf, sizeof(abuf), "0x%016" PRIX64, ctx_addr);
			ImGui::SetClipboardText(abuf);
			diag_log("ctx_result copy_address");
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] memory_scanner ctx copy_address");
		}
		ImGui::EndPopup();
	}

	ImGui::PopStyleVar();
	ImGui::PopStyleColor(3);
}

void process_address_context_menu() {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	if (s_open_address_ctx.load()) {
		s_open_address_ctx.store(false);
		ImGui::OpenPopup("##value_scan_addr_ctx");
	}

	uint64_t ctx_addr = s_view_owned_ctx_addr_value.load();
	int ctx_row = s_view_owned_ctx_addr_row.load();
	const auto& t = aida::ui::resolved();
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_subtle, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, 1.f));
	ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 10.f);

	if (ImGui::BeginPopup("##value_scan_addr_ctx")) {
		size_t multi_count = ui.address_multi_sel.size();
		if (multi_count > 1) {
			char hdr[64];
			snprintf(hdr, sizeof(hdr), "%zu selected", multi_count);
			ImGui::TextDisabled("%s", hdr);
			ImGui::Separator();
		}
		if (ImGui::MenuItem("Edit description")) {
			diag_logf("ctx_addr edit_description row=%d", ctx_row);
			ui.desc_edit.active = true;
			ui.desc_edit.address_index = ctx_row;
			ui.desc_edit.open_from_add_dialog = false;
			{
				std::lock_guard<std::mutex> lk(sc.address_mutex);
				if (ctx_row >= 0 && ctx_row < static_cast<int>(sc.address_list.size())) {
					_snprintf_s(ui.desc_edit.buf, sizeof(ui.desc_edit.buf), _TRUNCATE,
						"%s", sc.address_list[static_cast<size_t>(ctx_row)].description.c_str());
				}
			}
		}
		if (ImGui::MenuItem("Change type")) {
			diag_logf("ctx_addr change_type row=%d", ctx_row);
			s_pending_change_type_index.store(ctx_row);
			{
				std::lock_guard<std::mutex> lk(sc.address_mutex);
				if (ctx_row >= 0 && ctx_row < static_cast<int>(sc.address_list.size())) {
					s_pending_change_type_value = static_cast<int>(
						sc.address_list[static_cast<size_t>(ctx_row)].value_type);
				}
			}
		}
		if (ImGui::MenuItem("Change value")) {
			diag_logf("ctx_addr change_value row=%d", ctx_row);
			s_pending_edit_value_index.store(ctx_row);
			std::lock_guard<std::mutex> lk(sc.address_mutex);
			if (ctx_row >= 0 && ctx_row < static_cast<int>(sc.address_list.size())) {
				const auto& e = sc.address_list[static_cast<size_t>(ctx_row)];
				std::string vs = memory_scanner::format_value(e.last_value, e.value_type);
				_snprintf_s(s_edit_value_buf, sizeof(s_edit_value_buf), _TRUNCATE,
					"%s", vs.c_str());
			}
		}
		ImGui::Separator();
		if (ImGui::MenuItem("Open in Hex view")) {
			diag_logf("ctx_addr open_hex addr=0x%llX",
				static_cast<unsigned long long>(ctx_addr));
			if (ctx_addr != 0) {
				const auto context = disasm_view::capture_selected_workspace();
				if (hex_view::read_live_memory(context, ctx_addr, 256))
					globals::ui::active_center_view = center_view_t::hex_view;
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] address_list ctx open_hex");
			}
		}
		if (ImGui::MenuItem("Open in Disassembly")) {
			diag_logf("ctx_addr open_disasm addr=0x%llX",
				static_cast<unsigned long long>(ctx_addr));
			if (ctx_addr != 0) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(ctx_addr,
					disasm_view::capture_selected_workspace());
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] address_list ctx open_disasm");
			}
		}
		ImGui::Separator();
		if (ImGui::MenuItem("Copy address")) {
			char abuf[24];
			snprintf(abuf, sizeof(abuf), "0x%016" PRIX64, ctx_addr);
			ImGui::SetClipboardText(abuf);
			diag_log("ctx_addr copy_address");
		}
		ImGui::Separator();
		if (ImGui::MenuItem("Remove")) {
			diag_logf("ctx_addr remove row=%d multi=%zu", ctx_row, multi_count);
			std::vector<int> to_remove;
			if (multi_count > 0) {
				for (int i : ui.address_multi_sel) to_remove.push_back(i);
			} else if (ctx_row >= 0) {
				to_remove.push_back(ctx_row);
			}
			std::sort(to_remove.begin(), to_remove.end(), std::greater<int>());
			for (int idx : to_remove)
				memory_scanner::remove_address(static_cast<size_t>(idx));
			ui.address_multi_sel.clear();
			ui.selected_address = -1;
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] address_list ctx remove");
		}
		ImGui::EndPopup();
	}

	ImGui::PopStyleVar();
	ImGui::PopStyleColor(3);
}

}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float, float, float)
{
	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::BeginChild("##scanner_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	float w = width;
	float h = height;
	float a = alpha;

	const auto& t = aida::ui::resolved();
	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		aida::ui::with_alpha(t.bg_base, a));

	auto& ui = g_ui;
	auto& sc = memory_scanner::g_state;

	bool attached_now = driver_bridge::is_loaded() && driver_bridge::attached_pid() != 0;
	bool static_pe_now = function_index::detail::static_pe_active();
	bool any_target = attached_now || static_pe_now;

	if (ui.auto_refresh && attached_now) {
		ui.refresh_timer += aida::ui::clock::dt();
		if (ui.refresh_timer >= ui.refresh_interval) {
			ui.refresh_timer = 0.f;
			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "scanner";
			sub.label = "scanner.address_list_refresh";
			sub.thread_class = "scanner_ui_refresh";
			sub.domain = aida::infra::executor::domain_t::diagnostics;
			sub.priority = 4;
			sub.target_pid = driver_bridge::attached_pid();
			sub.body = []() {
				memory_scanner::refresh_address_list();
			};
			if (!aida::infra::executor::submit(std::move(sub)).submitted)
				diag::log_tagged("value_scan", "address_list_refresh_post_failed");
		}
	}

	if (ui.region_cache.entries.empty() && attached_now) {
		request_region_refresh();
	}

	{
		size_t cur_total = 0;
		{
			std::lock_guard<std::mutex> lk(sc.results_mutex);
			cur_total = sc.results.size();
		}
		if (static_cast<size_t>(ui.row_flash.size()) != cur_total) {
			invalidate_sort();
		}
	}

	float callout_h = (!any_target) ? kCalloutHeight : 0.f;

	render_toolbar(dl, ox, oy, w, a);

	if (callout_h > 0.f) {
		ui_anim::render_inline_callout(dl, ox + 12.f, oy + kToolbarHeight + 4.f,
			w - 24.f, 22.f,
			"Value scan needs a live process. Attach a target from the Process Attach panel.",
			ui_anim::callout_kind_t::warn, 0.85f, 0.6f, 0.2f, a);
	}

	float remaining = h - kToolbarHeight - callout_h;
	if (remaining < 100.f) remaining = 100.f;
	float results_h = 0.f;
	float address_h = 0.f;

	float results_y = oy + kToolbarHeight + callout_h;
	float split_y = 0.f;

	{
		float panes_total = remaining - kSplitterThickness;
		if (panes_total < 80.f) panes_total = 80.f;
		float r_ratio = ui.result_pane_ratio;
		float min_h = 80.f;
		r_ratio = std::clamp(r_ratio,
			min_h / panes_total, 1.f - min_h / panes_total);
		ui.result_pane_ratio = r_ratio;
		results_h = panes_total * r_ratio;
		address_h = panes_total - results_h;
	}

	render_results_pane(dl, ox, results_y, w, results_h, a);

	split_y = results_y + results_h;
	render_splitter(dl, ox, split_y, w, a, results_h, address_h, remaining - kSplitterThickness);

	render_address_pane(dl, ox, split_y + kSplitterThickness, w, address_h, a);

	ImGui::EndChild();

	process_add_dialog();
	process_edit_description_dialog();
	process_edit_value_dialog();
	process_change_type_dialog();
	process_result_context_menu();
	process_address_context_menu();
}

}
