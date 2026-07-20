#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "imgui/imgui.h"
#include "preview_fixture_controls.hpp"

#include <algorithm>
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
	inline fixture_state_t fixture_state = fixture_state_t::normal;

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
		const int tab_index = file_tabs::find_document(fixture_document_id);
		if (file_tabs::is_valid_tab_index(tab_index)) {
			auto& tab = file_tabs::tabs[file_tabs::tab_index(tab_index)];
			tab.filename = std::move(name);
			tab.filepath = std::move(path);
			tab.buffer.assign(content);
			tab.buffer_loaded = true;
			tab.load_in_progress = false;
			tab.load_failed = false;
			tab.load_error.clear();
			tab.dirty = false;
			tab.revision = fixture_revision;
			tab.content_hash = file_tabs::content_fingerprint(tab.buffer);
			tab.caret_line = 0;
			tab.caret_column = 0;
			tab.pending_caret_navigation = false;
		}
	}

	inline constexpr std::string_view default_fixture_source =
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

	inline void ensure_fixture()
	{
		if (code_editor_widget::document_state(fixture_document_id).active)
			return;
		load_fixture(default_fixture_source, "unpacker.cpp",
			"C:/Preview/ReverseEngineering/unpacker.cpp");
		record("fixture_loaded",
			code_editor_widget::document_state(fixture_document_id).filepath);
	}

	inline void configure_fixture(fixture_state_t state, std::size_t cardinality)
	{
		fixture_state = state;
		if (state == fixture_state_t::empty) {
			load_fixture({}, "untitled.cpp", "C:/Preview/ReverseEngineering/untitled.cpp");
			return;
		}
		if (state == fixture_state_t::error) {
			load_fixture("#include <cstdint>\n\nint parse_image() {\n    return missing_symbol;\n}\n",
				"broken_parser.cpp", "C:/Preview/ReverseEngineering/broken_parser.cpp");
			static_cast<void>(code_editor_widget::configure_preview_stream_state(
				fixture_document_id, false, false,
				"The deterministic large-file index failed before publication; the retained editor state was preserved."));
			return;
		}
		if (state == fixture_state_t::loading ||
			state == fixture_state_t::cancellation_requested) {
			load_fixture(default_fixture_source, "large_index.cpp",
				"C:/Preview/ReverseEngineering/large_index.cpp");
			static_cast<void>(code_editor_widget::configure_preview_stream_state(
				fixture_document_id, true,
				state == fixture_state_t::cancellation_requested, {}));
			return;
		}
		if (state == fixture_state_t::disconnected) {
			load_fixture(default_fixture_source, "remote_source.cpp",
				"C:/Preview/Disconnected/remote_source.cpp");
			static_cast<void>(code_editor_widget::configure_preview_stream_state(
				fixture_document_id, false, false,
				"The workspace source provider disconnected before the retained file could be indexed."));
			return;
		}
		if (cardinality > 0U) {
			const std::size_t bounded = (std::min<std::size_t>)(cardinality, 10000U);
			std::string source;
			source.reserve(bounded * 48U);
			source = "#include <cstdint>\n\nnamespace generated {\n";
			for (std::size_t index = 0; index < bounded; ++index)
				source += "std::uint64_t symbol_" + std::to_string(index) + " = " +
					std::to_string(index) + "ULL;\n";
			source += "}\n";
			load_fixture(source, "large_symbols.cpp",
				"C:/Preview/ReverseEngineering/large_symbols.cpp");
			return;
		}
		load_fixture(default_fixture_source, "unpacker.cpp",
			"C:/Preview/ReverseEngineering/unpacker.cpp");
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

namespace aida::preview {
inline void configure_programming_fixture(fixture_state_t state, std::size_t cardinality)
{
	editor::configure_fixture(state, cardinality);
}
}

#endif
