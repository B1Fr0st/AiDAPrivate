#pragma once

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "rename_store.hpp"
#include "symbol_store.hpp"
#include "disasm_view.hpp"
#include "imgui/imgui.h"
#include "../ui/components.hpp"
#include "../ui/theme.hpp"

namespace rename_dialog {

namespace detail {

inline bool& open_flag() {
	static bool v = false;
	return v;
}

inline bool& should_open() {
	static bool v = false;
	return v;
}

inline uint64_t& target_addr() {
	static uint64_t v = 0;
	return v;
}

inline char* buffer() {
	static char buf[256] = {};
	return buf;
}

inline std::string trim(const char* text) {
	std::string s(text);
	while (!s.empty()) {
		unsigned char c = static_cast<unsigned char>(s.back());
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
			s.pop_back();
		else
			break;
	}
	size_t start = 0;
	while (start < s.size()) {
		unsigned char c = static_cast<unsigned char>(s[start]);
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
			++start;
		else
			break;
	}
	if (start > 0) s.erase(0, start);
	return s;
}

inline bool has_whitespace(const std::string& s) {
	for (char c : s) {
		unsigned char u = static_cast<unsigned char>(c);
		if (u == ' ' || u == '\t' || u == '\r' || u == '\n')
			return true;
	}
	return false;
}

inline std::string current_name(uint64_t addr) {
	std::string existing = rename_store::get(addr);
	if (!existing.empty()) return existing;
	std::string sym = symbol_store::resolve_symbol_exact(addr);
	if (!sym.empty()) return sym;
	std::string sym_off = symbol_store::resolve_symbol(addr);
	if (!sym_off.empty()) {
		auto bang = sym_off.find('!');
		if (bang != std::string::npos) sym_off = sym_off.substr(bang + 1);
		return sym_off;
	}
	char buf[32];
	std::snprintf(buf, sizeof(buf), "sub_%llX", static_cast<unsigned long long>(addr));
	return std::string(buf);
}

}

inline bool is_open() {
	return detail::open_flag() || detail::should_open();
}

inline void open(uint64_t addr) {
	detail::target_addr() = addr;
	std::string current = detail::current_name(addr);
	char* buf = detail::buffer();
	size_t n = current.size();
	if (n >= 255) n = 255;
	if (n > 0) std::memcpy(buf, current.data(), n);
	buf[n] = '\0';
	detail::should_open() = true;
}

inline void render() {
	if (detail::should_open()) {
		ImGui::OpenPopup("##aida_rename_dialog");
		detail::should_open() = false;
		detail::open_flag() = true;
	}

	if (!detail::open_flag())
		return;

	const auto& tk = aida::ui::resolved();
	ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16.f, 14.f));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8.f, 8.f));
	ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(tk.bg_overlay));
	ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(tk.border_subtle));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(tk.panel_bg));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(tk.text_primary));

	ImVec2 viewport_center = ImGui::GetMainViewport()->GetCenter();
	ImGui::SetNextWindowPos(viewport_center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
	ImGui::SetNextWindowSize(ImVec2(420.f, 0.f), ImGuiCond_Appearing);

	char title_buf[80];
	std::snprintf(title_buf, sizeof(title_buf), "Rename symbol at 0x%llX###aida_rename_dialog",
	              static_cast<unsigned long long>(detail::target_addr()));

	bool open_flag_local = true;
	bool accept_now = false;
	bool cancel_now = false;

	if (ImGui::BeginPopupModal(title_buf, &open_flag_local,
	                           ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_AlwaysAutoResize)) {
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
		                   "New symbol name (no whitespace, non-empty)");
		ImGui::Spacing();

		ImGuiInputTextFlags itf = ImGuiInputTextFlags_EnterReturnsTrue
		                        | ImGuiInputTextFlags_AutoSelectAll;
		if (ImGui::IsWindowAppearing())
			ImGui::SetKeyboardFocusHere();
		ImGui::SetNextItemWidth(360.f);
		if (ImGui::InputText("##new_name", detail::buffer(), 256, itf))
			accept_now = true;

		ImGui::Spacing();

		ImGuiIO& io = ImGui::GetIO();
		if (ImGui::IsKeyPressed(ImGuiKey_Escape, false))
			cancel_now = true;
		(void)io;

		if (aida::ui::button("Rename", aida::ui::button_kind_t::primary,
		                     aida::ui::size_t_::md, ImVec2(0.f, 0.f), false, nullptr, false))
			accept_now = true;
		ImGui::SameLine();
		if (aida::ui::button("Cancel", aida::ui::button_kind_t::secondary,
		                     aida::ui::size_t_::md, ImVec2(0.f, 0.f), false, nullptr, false))
			cancel_now = true;

		if (accept_now) {
			std::string trimmed = detail::trim(detail::buffer());
			if (!trimmed.empty() && !detail::has_whitespace(trimmed)) {
				rename_store::set(detail::target_addr(), trimmed);
				disasm_view::bump_format_generation();
				ImGui::CloseCurrentPopup();
				detail::open_flag() = false;
			}
		} else if (cancel_now || !open_flag_local) {
			ImGui::CloseCurrentPopup();
			detail::open_flag() = false;
		}

		ImGui::EndPopup();
	} else {
		detail::open_flag() = false;
	}

	ImGui::PopStyleColor(4);
	ImGui::PopStyleVar(4);
}

}
