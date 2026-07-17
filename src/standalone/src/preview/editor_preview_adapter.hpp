#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "imgui/imgui.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::preview::editor
{
	namespace preferences
	{
		inline bool word_wrap = false;
		inline float font_size = 14.f;
		inline bool show_line_numbers = true;
		inline bool minimap = true;
		inline int tab_size = 4;
		inline bool highlight_current_line = true;
		inline bool bracket_match = true;
		inline bool auto_complete = true;
	}

	struct receipt_t
	{
		std::string action;
		std::string detail;
		std::uint64_t sequence = 0;
	};

	inline std::vector<receipt_t> receipts;
	inline std::uint64_t next_sequence = 1;
	inline bool ghost_text_enabled = true;
	inline constexpr std::uint64_t fixture_document_id = 0x5052455649455701ULL;
	inline std::uint64_t fixture_revision = 0;

	inline void record(std::string action, std::string detail = {})
	{
		receipts.push_back({ std::move(action), std::move(detail), next_sequence++ });
		if (receipts.size() > 256)
			receipts.erase(receipts.begin(), receipts.begin() + 64);
	}

	inline void load_fixture(std::string_view content, std::string name, std::string path)
	{
		static_cast<void>(code_editor_widget::load_document(fixture_document_id,
			++fixture_revision, content, name, path, false, 0, 0, 0.f, 0.f, true));
	}

	inline void ensure_fixture()
	{
		if (code_editor_widget::document_state(fixture_document_id).active)
			return;
		constexpr std::string_view source =
			"#include <cstdint>\n"
			"#include <span>\n"
			"#include <vector>\n\n"
			"namespace unpacker {\n\n"
			"struct section_t {\n"
			"    std::uint64_t virtual_address;\n"
			"    std::vector<std::uint8_t> bytes;\n"
			"};\n\n"
			"bool has_debug_guard(std::span<const std::uint8_t> code) {\n"
			"    constexpr std::uint8_t query_process_information = 0x19;\n"
			"    for (std::size_t index = 0; index + 1 < code.size(); ++index) {\n"
			"        if (code[index] == 0x6A &&\n"
			"            code[index + 1] == query_process_information) {\n"
			"            return true;\n"
			"        }\n"
			"    }\n"
			"    return false;\n"
			"}\n\n"
			"std::uint64_t resolve_entry(const section_t& text) {\n"
			"    return text.virtual_address + 0x2D0;\n"
			"}\n\n"
			"}\n";
		load_fixture(source, "unpacker.cpp", "C:/Preview/ReverseEngineering/unpacker.cpp");
		record("fixture_loaded",
			code_editor_widget::document_state(fixture_document_id).filepath);
	}

	inline std::string content()
	{
		ensure_fixture();
		return code_editor_widget::document_content(fixture_document_id);
	}

	inline bool save_document()
	{
		ensure_fixture();
		const auto state = code_editor_widget::document_state(fixture_document_id);
		code_editor_widget::mark_document_saved(fixture_document_id,
			code_editor_widget::document_revision(fixture_document_id),
			state.filename, state.filepath);
		record("save", state.filepath);
		return true;
	}

	inline std::string complete(std::string_view context)
	{
		if (context.empty())
			return {};
		const auto ends_with = [context](std::string_view suffix) {
			return context.size() >= suffix.size() &&
				context.substr(context.size() - suffix.size()) == suffix;
		};
		if (ends_with("return "))
			return "false;";
		if (ends_with("std::"))
			return "uint64_t";
		if (ends_with("text."))
			return "virtual_address";
		return {};
	}

	inline void copy_to_clipboard(const std::string& text)
	{
		if (!text.empty())
			ImGui::SetClipboardText(text.c_str());
	}

	inline std::string paste_from_clipboard()
	{
		const char* text = ImGui::GetClipboardText();
		if (!text)
			return {};
		std::string normalized;
		normalized.reserve(std::strlen(text));
		for (const char* cursor = text; *cursor; ++cursor) {
			if (*cursor != '\r')
				normalized.push_back(*cursor);
		}
		return normalized;
	}
}

#endif
