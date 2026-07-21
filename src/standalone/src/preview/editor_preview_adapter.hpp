#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "imgui/imgui.h"
#include "../core/ui/application_view_registry.hpp"
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
	inline constexpr std::uint64_t fixture_header_document_id = 0x5052455649455702ULL;
	inline constexpr std::uint64_t fixture_script_document_id = 0x5052455649455703ULL;
	inline constexpr std::uint64_t fixture_notes_document_id = 0x5052455649455704ULL;
	inline std::uint64_t fixture_revision = 0;
	inline fixture_state_t fixture_state = fixture_state_t::normal;

	inline void record(std::string action, std::string detail = {})
	{
		receipts.push_back({ std::move(action), std::move(detail), next_sequence++ });
		if (receipts.size() > 256)
			receipts.erase(receipts.begin(), receipts.begin() + 64);
	}

	inline OpenTab& ensure_tab(std::uint64_t document_id, std::uint32_t group_id)
	{
		int index = file_tabs::find_document(document_id);
		if (!file_tabs::is_valid_tab_index(index)) {
			OpenTab tab;
			tab.document_id = document_id;
			tab.group_id = group_id;
			file_tabs::tabs.push_back(std::move(tab));
			index = static_cast<int>(file_tabs::tabs.size() - 1U);
		}
		auto& tab = file_tabs::tabs[file_tabs::tab_index(index)];
		tab.group_id = group_id;
		file_tabs::active_document_by_group[group_id] = document_id;
		return tab;
	}

	inline void load_fixture_document(std::uint64_t document_id, std::uint32_t group_id,
		std::string_view content, std::string name, std::string path, bool dirty = false)
	{
		static_cast<void>(code_editor_widget::load_document(document_id,
			++fixture_revision, content, name, path, dirty, 0, 0, 0.f, 0.f, true));
		auto& retained = ensure_tab(document_id, group_id);
		{
			auto& tab = retained;
			tab.filename = std::move(name);
			tab.filepath = std::move(path);
			tab.buffer.assign(content);
			tab.buffer_loaded = true;
			tab.load_in_progress = false;
			tab.load_failed = false;
			tab.load_error.clear();
			tab.dirty = dirty;
			tab.revision = fixture_revision;
			tab.content_hash = file_tabs::content_fingerprint(tab.buffer);
			tab.caret_line = 0;
			tab.caret_column = 0;
			tab.pending_caret_navigation = false;
			tab.streamed_document = false;
			tab.streamed_byte_length = 0;
			tab.save_in_progress = false;
			tab.save_error.clear();
			tab.external_conflict = false;
			tab.external_overwrite_approved = false;
		}
	}

	inline void load_fixture(std::string_view content, std::string name, std::string path,
		bool dirty = false)
	{
		load_fixture_document(fixture_document_id, 0U, content,
			std::move(name), std::move(path), dirty);
		file_tabs::active_tab = file_tabs::find_document(fixture_document_id);
		static_cast<void>(code_editor_widget::select_document_for_actions(fixture_document_id));
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

	inline void clear_secondary_fixture_documents()
	{
		for (const std::uint64_t id : {fixture_header_document_id,
				fixture_script_document_id, fixture_notes_document_id}) {
			const int index = file_tabs::find_document(id);
			if (file_tabs::is_valid_tab_index(index))
				file_tabs::tabs.erase(file_tabs::tabs.begin() + index);
			code_editor_widget::discard_document_state(id);
		}
		file_tabs::active_document_by_group.erase(1U);
		file_tabs::navigation_by_group.erase(1U);
	}

	inline std::string exact_editable_boundary_source()
	{
		constexpr std::size_t boundary = 1U << 20U;
		std::string source = "// Exactly 1 MiB: editable boundary fixture\n";
		constexpr std::string_view line = "std::uint64_t retained_boundary_symbol = 0x140001000ULL;\n";
		while (source.size() + line.size() <= boundary)
			source.append(line);
		source.append(boundary - source.size(), ' ');
		return source;
	}

	inline void configure_streamed_fixture(std::uint64_t advertised_size,
		bool loading, bool cancelling, std::string error)
	{
		constexpr std::string_view excerpt =
			"// Bounded deterministic publication for a synthetic large text file.\n"
			"// The retained byte length is authoritative; this excerpt avoids a giant allocation.\n"
			"std::uint64_t indexed_entry = 0x140001000ULL;\n";
		load_fixture(excerpt, "retained_large_source.cpp",
			"C:/Preview/MemoryBacked/retained_large_source.cpp");
		auto& tab = file_tabs::tabs[file_tabs::tab_index(
			file_tabs::find_document(fixture_document_id))];
		tab.streamed_document = true;
		tab.streamed_byte_length = advertised_size;
		tab.load_in_progress = loading;
		tab.load_failed = !error.empty();
		tab.load_error = error;
		static_cast<void>(code_editor_widget::configure_preview_stream_state(
			fixture_document_id, advertised_size, loading, cancelling, error));
	}

	inline void configure_fixture(fixture_state_t state, std::size_t cardinality)
	{
		fixture_state = state;
		file_tabs::preview_save_interceptor = [](int tab_index)
			-> std::optional<file_tabs::save_result_t> {
			if (!file_tabs::is_valid_tab_index(tab_index) ||
				file_tabs::tabs[file_tabs::tab_index(tab_index)].document_id != fixture_document_id)
				return std::nullopt;
			if (fixture_state != fixture_state_t::save_failure)
				return std::nullopt;
			auto& tab = file_tabs::tabs[file_tabs::tab_index(tab_index)];
			tab.dirty = true;
			tab.save_in_progress = false;
			tab.save_error = "The deterministic workspace provider rejected the revision-fenced save; the dirty editor buffer and recovery journal remain intact.";
			return file_tabs::save_result_t{false, tab.save_error};
		};
		clear_secondary_fixture_documents();
		if (state == fixture_state_t::empty) {
			load_fixture({}, "untitled.cpp", "C:/Preview/ReverseEngineering/untitled.cpp");
			return;
		}
		if (state == fixture_state_t::error) {
			configure_streamed_fixture(50ULL << 20U, false, false,
				"The deterministic large-file index failed before publication; the retained editor state was preserved.");
			return;
		}
		if (state == fixture_state_t::loading ||
			state == fixture_state_t::cancellation_requested) {
			configure_streamed_fixture(50ULL << 20U, true,
				state == fixture_state_t::cancellation_requested, {});
			return;
		}
		if (state == fixture_state_t::disconnected) {
			configure_streamed_fixture(50ULL << 20U, false, false,
				"The workspace source provider disconnected before the retained file could be indexed.");
			return;
		}
		if (state == fixture_state_t::save_failure) {
			load_fixture(default_fixture_source, "unsaved_parser.cpp",
				"C:/Preview/ReadOnlyWorkspace/unsaved_parser.cpp", true);
			auto& tab = file_tabs::tabs[file_tabs::tab_index(
				file_tabs::find_document(fixture_document_id))];
			tab.save_error = "The deterministic workspace provider rejected the revision-fenced save; the dirty editor buffer and recovery journal remain intact.";
			return;
		}
		if (state == fixture_state_t::external_conflict) {
			load_fixture(default_fixture_source, "conflicted_parser.cpp",
				"C:/Preview/ExternalConflict/conflicted_parser.cpp", true);
			auto& tab = file_tabs::tabs[file_tabs::tab_index(
				file_tabs::find_document(fixture_document_id))];
			tab.disk_write_version = 41;
			tab.external_observed_write_version = 42;
			tab.external_conflict = true;
			tab.external_overwrite_approved = false;
			return;
		}
		if (state == fixture_state_t::document_groups) {
			load_fixture(default_fixture_source, "unpacker.cpp",
				"C:/Preview/Workspace/src/unpacker.cpp", true);
			load_fixture_document(fixture_header_document_id, 0U,
				"#pragma once\n\nstd::uint64_t resolve_entry();\n", "unpacker.hpp",
				"C:/Preview/Workspace/include/unpacker.hpp");
			load_fixture_document(fixture_script_document_id, 1U,
				"def annotate_entry(address):\n    return hex(address)\n", "annotate.py",
				"C:/Preview/Workspace/tools/annotate.py", true);
			load_fixture_document(fixture_notes_document_id, 1U,
				"# Evidence\n\nEntry point validated against the static image.\n", "evidence.md",
				"C:/Preview/Workspace/evidence.md");
			file_tabs::active_document_by_group[0U] = fixture_document_id;
			file_tabs::active_document_by_group[1U] = fixture_script_document_id;
			file_tabs::active_tab = file_tabs::find_document(fixture_script_document_id);
			static_cast<void>(code_editor_widget::select_document_for_actions(
				fixture_script_document_id));
			static_cast<void>(aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("document.code")));
			file_tabs::active_tab = file_tabs::find_document(fixture_document_id);
			static_cast<void>(code_editor_widget::select_document_for_actions(fixture_document_id));
			return;
		}
		if (state == fixture_state_t::size_editable_boundary) {
			load_fixture(exact_editable_boundary_source(), "exactly_1_mib.cpp",
				"C:/Preview/MemoryBacked/exactly_1_mib.cpp", true);
			return;
		}
		if (state == fixture_state_t::size_mapped_read_only) {
			configure_streamed_fixture((1ULL << 20U) + 1ULL, false, false, {});
			return;
		}
		if (state == fixture_state_t::size_stream_loading) {
			configure_streamed_fixture(50ULL << 20U, true, false, {});
			return;
		}
		if (state == fixture_state_t::size_stream_cancelling) {
			configure_streamed_fixture(500ULL << 20U, true, true, {});
			return;
		}
		if (state == fixture_state_t::size_stream_error) {
			configure_streamed_fixture(500ULL << 20U, false, false,
				"The bounded synthetic index publication failed its revision fence; no prior publication was replaced.");
			return;
		}
		if (state == fixture_state_t::size_stream_ready) {
			configure_streamed_fixture(500ULL << 20U, false, false, {});
			return;
		}
		if (state == fixture_state_t::size_rejected) {
			load_fixture({}, "oversize_trace.txt",
				"C:/Preview/MemoryBacked/oversize_trace.txt");
			auto& tab = file_tabs::tabs[file_tabs::tab_index(
				file_tabs::find_document(fixture_document_id))];
			tab.buffer_loaded = false;
			tab.load_failed = true;
			tab.load_error = "The 500 MiB editor-view limit was exceeded. Open this artifact in Hex View or Binary Map.";
			tab.streamed_document = true;
			tab.streamed_byte_length = (500ULL << 20U) + 1ULL;
			static_cast<void>(code_editor_widget::configure_preview_stream_state(
				fixture_document_id, tab.streamed_byte_length, false, false,
				tab.load_error));
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
		const int tab_index = file_tabs::find_document(fixture_document_id);
		if (!file_tabs::is_valid_tab_index(tab_index)) {
			record("save_rejected", "retained fixture tab is unavailable");
			return false;
		}
		const auto result = file_tabs::save_tab_to_disk_result(tab_index);
		if (!result.succeeded) {
			record("save_rejected", result.detail);
			return false;
		}
		record("save", file_tabs::tabs[file_tabs::tab_index(tab_index)].filepath);
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
