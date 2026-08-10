#include "shell_preview.hpp"

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "../helpers/globals.h"
#include "../helpers/helpers.h"
#include "editor_preview_adapter.hpp"
#include "debugger_preview_runtime.hpp"
#include "workspace_preview_fixture.hpp"
#include "../core/debugger/debugger_interaction_context.hpp"
#include "../core/session/analysis_session.hpp"
#include "../core/ui/clock.hpp"
#include "../core/ui/application_view_registry.hpp"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <utility>

ID3D11Device* g_pd3dDevice = nullptr;
HWND g_hwnd = nullptr;

namespace aida::preview::debugger
{
	std::vector<receipt_t> receipts;
	std::uint64_t next_sequence = 1;
	bool fixture_initialized = false;
	fixture_state_t fixture_state = fixture_state_t::normal;
	bool driver_available = true;
	std::uint64_t process_creation_time_100ns = 1;
}

namespace aida::preview
{
	namespace
	{
		std::atomic<bool> initialized{false};
		std::atomic<bool> desktop_focus_applied{false};
		std::atomic<bool> fixture_ready{true};
		shell_phase_t active_phase = shell_phase_t::ide;
		std::vector<shell_receipt_t> action_receipts;
		std::uint64_t next_sequence = 1;
		std::uint32_t active_pid = 0;
		std::string active_process_name;
		shell_controls_t fixture_controls;

		bool stable_id_has_prefix(std::string_view value, std::string_view prefix) noexcept
		{
			return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
		}

		bool legacy_domain_contains(center_view_t domain, std::string_view id) noexcept
		{
			switch (domain) {
				case center_view_t::analysis_hub:
					return stable_id_has_prefix(id, "view.analysis.");
				case center_view_t::debugger_view:
					return stable_id_has_prefix(id, "view.debug.");
				case center_view_t::network_view:
					return stable_id_has_prefix(id, "view.network.");
				case center_view_t::scan_hub:
					return stable_id_has_prefix(id, "view.memory.");
				case center_view_t::types_hub:
					return stable_id_has_prefix(id, "view.types.");
				case center_view_t::workbench:
					return id == "document.disassembly" || id == "document.hex" ||
						id == "document.pseudocode" || id == "document.graph" ||
						id == "document.image" || id == "view.navigator" ||
						id == "view.inspector";
				default:
					return false;
			}
		}

		const char* legacy_domain_default(center_view_t domain) noexcept
		{
			switch (domain) {
				case center_view_t::analysis_hub: return "view.analysis.functions";
				case center_view_t::debugger_view: return "view.debug.cpu";
				case center_view_t::network_view: return "view.network.proxy";
				case center_view_t::scan_hub: return "view.memory.value_scan";
				case center_view_t::types_hub: return "view.types.struct_recon";
				case center_view_t::workbench: return "document.disassembly";
				default: return nullptr;
			}
		}

		std::string retained_legacy_domain_view(center_view_t domain)
		{
			aida::ui::application_views::initialize();
			auto& registry = aida::ui::application_views::registry();
			if (const auto focused = registry.focused_instance(); focused &&
				legacy_domain_contains(domain, focused->view.value()) &&
				registry.find_descriptor(focused->view))
				return focused->view.value();

			std::string retained;
			std::uint64_t retained_focus_sequence = 0;
			bool retained_open = false;
			registry.for_each_instance(
				[&](const aida::ui::view_descriptor_t& descriptor,
					const aida::ui::view_instance_state_t& instance) {
					if (!legacy_domain_contains(domain, descriptor.id.value()))
						return;
					const bool better_focus = instance.last_focus_sequence > retained_focus_sequence;
					const bool better_open = instance.last_focus_sequence == retained_focus_sequence &&
						instance.open && !retained_open;
					const bool deterministic_first = retained.empty();
					if (!better_focus && !better_open && !deterministic_first)
						return;
					retained = descriptor.id.value();
					retained_focus_sequence = instance.last_focus_sequence;
					retained_open = instance.open;
				}, false);
			if (!retained.empty())
				return retained;
			const char* fallback = legacy_domain_default(domain);
			return fallback ? std::string(fallback) : std::string{};
		}

		std::string legacy_preview_view_id(int value)
		{
			switch (static_cast<center_view_t>(value)) {
				case center_view_t::code_editor: return "document.code";
				case center_view_t::disassembly: return "document.disassembly";
				case center_view_t::hex_view: return "document.hex";
				case center_view_t::welcome: return "view.start_center";
				case center_view_t::settings_view: return "view.settings";
				case center_view_t::network_view:
				case center_view_t::debugger_view:
				case center_view_t::scan_hub:
				case center_view_t::types_hub:
				case center_view_t::analysis_hub:
				case center_view_t::workbench:
					return retained_legacy_domain_view(static_cast<center_view_t>(value));
				case center_view_t::memory_scanner: return "view.memory.value_scan";
				case center_view_t::pseudocode: return "document.pseudocode";
				case center_view_t::struct_recon: return "view.types.struct_recon";
				case center_view_t::crypto_scanner: return "view.memory.crypto";
				case center_view_t::aob_generator: return "view.memory.aob";
				case center_view_t::fuzzer_view: return "view.analysis.fuzzer";
				case center_view_t::xref_browser: return "view.analysis.references";
				case center_view_t::snapshot_diff: return "view.memory.snapshots";
				case center_view_t::pointer_scanner: return "view.memory.pointers";
				case center_view_t::decrypt_oracle: return "view.memory.decrypt";
				case center_view_t::integrity_hunter: return "view.memory.integrity";
				case center_view_t::symbolic_view: return "view.analysis.symbolic";
				case center_view_t::taint_view: return "view.analysis.taint";
				case center_view_t::deobfuscation_view: return "view.analysis.deobfuscation";
				case center_view_t::stealth_view: return "view.analysis.protection";
				case center_view_t::binary_map: return "view.analysis.binary_map";
				case center_view_t::graph_view: return "document.graph";
				case center_view_t::image_view: return "document.image";
				case center_view_t::test_lab: return {};
				case center_view_t::functions_panel: return "view.analysis.functions";
				case center_view_t::xref_database: return "view.analysis.references";
			}
			return {};
		}

		const std::vector<process_fixture_t> process_rows = {
			{ 6248, "AiDA_TestTarget.exe", "C:/Preview/AiDA_TestTarget.exe", "AiDA Reverse Engineering Test Target" },
			{ 7812, "notepad.exe", "C:/Windows/System32/notepad.exe", "analysis_notes.txt - Notepad" },
			{ 9104, "sample_game.exe", "C:/Preview/sample_game.exe", "Sample Game" },
			{ 11420, "service_host.exe", "C:/Preview/service_host.exe", "" }
		};
		const std::vector<module_fixture_t> module_rows = {
			{ 0x0000000140000000ULL, "sample.exe" },
			{ 0x00007FFB84200000ULL, "ntdll.dll" },
			{ 0x00007FFB81A00000ULL, "kernel32.dll" },
			{ 0x00007FFB7F300000ULL, "user32.dll" }
		};
		const std::vector<thread_fixture_t> thread_rows = {
			{ 9108, 8 },
			{ 9320, 10 },
			{ 10444, 8 },
			{ 12016, 9 }
		};

		void copy_path(const char* source, char* destination, std::size_t capacity)
		{
			if (!destination || capacity == 0)
				return;
			const std::size_t length = (std::min)(std::strlen(source), capacity - 1);
			std::memcpy(destination, source, length);
			destination[length] = '\0';
		}

		ChatMessage chat_message(std::string text, bool is_user, std::int64_t timestamp)
		{
			ChatMessage message;
			message.text = std::move(text);
			message.is_user = is_user;
			message.timestamp = timestamp;
			return message;
		}
	}

	void initialize_shell_fixture(const ImVec2& display_size)
	{
		const ImGuiViewport* viewport = ImGui::GetMainViewport();
		const float dpi_scale = viewport && viewport->DpiScale > 0.0f
			? viewport->DpiScale : 1.0f;
		globals::ui::dpi_scale = dpi_scale;
		if (aida::ui::dpi_scale() != dpi_scale) {
			aida::ui::set_dpi_scale(dpi_scale);
			aida::ui::apply_imgui_style(aida::ui::resolved());
		}
		globals::ui::bg_init_done = &fixture_ready;
		globals::ui::bg_init_step.store(globals::ui::bg_init_total.load(std::memory_order_acquire), std::memory_order_release);
		globals::ui::window_w = display_size.x > 0.f ? display_size.x : 1280.f;
		globals::ui::window_h = display_size.y > 0.f ? display_size.y : 760.f;
		globals::ui::welcome_done = active_phase == shell_phase_t::ide || active_phase == shell_phase_t::license;
		globals::ui::ui_alpha = active_phase == shell_phase_t::ide ? 1.f : 0.f;
		if (initialized.exchange(true, std::memory_order_acq_rel)) {
			if (!desktop_focus_applied.exchange(true, std::memory_order_acq_rel)) {
				aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.analysis.functions"));
				aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.inspector"));
				static_cast<void>(set_requested_view(fixture_controls, "document.disassembly"));
			}
			return;
		}
		globals::ui::command_palette_open = false;
		globals::ui::command_palette_buf[0] = '\0';

		aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("view.project_explorer"));
		aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("view.output"));
		aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("view.analysis.functions"));
		aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("view.inspector"));
		static_cast<void>(set_requested_view(fixture_controls, "document.disassembly"));
		globals::ui::breadcrumb_segments = { "AiDA", "sample.exe", ".text", "main" };
		globals::ui::status_file_info = "sample.exe  x64  PE32+";
		globals::ui::status_driver_info = "Preview fixture";
		globals::ui::status_model_info = "AiDA Analyst";

		file_browser::current_dir = "C:/Preview/ReverseEngineering";
		std::strncpy(file_browser::path_buf, file_browser::current_dir.c_str(), sizeof(file_browser::path_buf) - 1);
		file_browser::entries = {
			{ "samples", "C:/Preview/ReverseEngineering/samples", true, true, 0 },
			{ "sample.exe", "C:/Preview/ReverseEngineering/samples/sample.exe", false, false, 1 },
			{ "packed_sample.dll", "C:/Preview/ReverseEngineering/samples/packed_sample.dll", false, false, 1 },
			{ "symbols", "C:/Preview/ReverseEngineering/symbols", true, false, 0 },
			{ "notes.md", "C:/Preview/ReverseEngineering/notes.md", false, false, 0 }
		};
		file_browser::selected_idx = 1;
		file_browser::needs_refresh = false;

		file_tabs::tabs.clear();
		OpenTab sample_tab;
		sample_tab.filename = "sample.cpp";
		sample_tab.filepath = "C:/Preview/ReverseEngineering/sample.cpp";
		sample_tab.buffer_loaded = true;
		file_tabs::tabs.push_back(std::move(sample_tab));
		OpenTab notes_tab;
		notes_tab.filename = "notes.md";
		notes_tab.filepath = "C:/Preview/ReverseEngineering/notes.md";
		notes_tab.buffer_loaded = true;
		notes_tab.dirty = true;
		file_tabs::tabs.push_back(std::move(notes_tab));
		file_tabs::active_tab = 0;
		const char* code = "int main() {\n    return analyze_target(\"sample.exe\");\n}\n";
		aida::preview::editor::load_fixture(code, "sample.cpp",
			"C:/Preview/ReverseEngineering/sample.cpp");
		if (!file_tabs::tabs.empty()) {
			file_tabs::tabs.front().document_id =
				aida::preview::editor::fixture_document_id;
			file_tabs::tabs.front().buffer = code;
			file_tabs::tabs.front().content_hash = file_tabs::content_fingerprint(code);
			file_tabs::tabs.front().revision =
				aida::preview::editor::fixture_revision;
		}
		file_tabs::normalize_document_identities();

		g_chat_messages = {
			chat_message("Analyze the entry point and identify anti-debug checks.", true, 1),
			chat_message("The entry path initializes a timing check, queries the process debug flags, and then enters the unpacking stub. I mapped the relevant branches and cross-references in the active workspace.", false, 2)
		};
		g_chat_scroll_to_bottom = true;
		conversations::history = {
			{ "fixture-analysis", "Entry point analysis", 3, 8 },
			{ "fixture-network", "Protocol reconstruction", 2, 12 },
			{ "fixture-unpack", "Packed sample notes", 1, 6 }
		};
		conversations::current_id = "fixture-analysis";

		output_log::push(bottom_tab_t::output, "[analysis] Loaded sample.exe (x64, 7 sections)");
		output_log::push(bottom_tab_t::output, "[analysis] 64 functions indexed");
		output_log::push(bottom_tab_t::mcp_log, "[mcp] ImGui Studio preview connected");
		output_log::push(bottom_tab_t::driver_log, "[driver] Runtime access disabled in UI preview");
		output_log::push(bottom_tab_t::sandbox_log, "[sandbox] Deterministic fixture active");
		output_log::push(bottom_tab_t::terminal, "PS C:\\Preview\\ReverseEngineering> dumpbin /headers sample.exe");
		output_log::push(bottom_tab_t::terminal, "PE32+ executable (console) x86-64, 7 sections");
		output_log::push(bottom_tab_t::terminal, "PS C:\\Preview\\ReverseEngineering> _");
	}

	void reset_shell_fixture()
	{
		aida::ui::clock::reset();
		initialized.store(false, std::memory_order_release);
		active_phase = shell_phase_t::ide;
		action_receipts.clear();
		next_sequence = 1;
		active_pid = 0;
		active_process_name.clear();
		const std::uint64_t next_revision = fixture_controls.revision + 1;
		fixture_controls = shell_controls_t{};
		fixture_controls.revision = next_revision;
		globals::ui::command_palette_open = false;
		globals::ui::command_palette_buf[0] = '\0';
		for (int index = 0; index < static_cast<int>(bottom_tab_t::COUNT); ++index)
			output_log::clear(static_cast<bottom_tab_t>(index));
	}

	shell_controls_t& controls()
	{
		return fixture_controls;
	}

	bool set_requested_view(shell_controls_t& target, std::string_view id)
	{
		if (id.empty() || id.size() >= target.requested_view_id.size() ||
			id.find('\0') != std::string_view::npos)
			return false;
		const std::string candidate(id);
		if (!aida::ui::is_valid_stable_id(candidate) ||
			(candidate.rfind("view.", 0) != 0 && candidate.rfind("document.", 0) != 0) ||
			!aida::ui::application_views::registry().find_descriptor(
				aida::ui::stable_view_id_t(candidate)))
			return false;
		target.requested_view_id.fill('\0');
		std::memcpy(target.requested_view_id.data(), id.data(), id.size());
		target.center_view = -1;
		target.revision = target.revision == UINT64_MAX ? 1 : target.revision + 1;
		return true;
	}

	bool apply_requested_view(const shell_controls_t& source)
	{
		std::string candidate;
		if (source.center_view >= 0) {
			if (source.center_view > static_cast<int>(center_view_t::xref_database))
				return false;
			candidate = legacy_preview_view_id(source.center_view);
			if (candidate.empty())
				return false;
		} else {
			const auto terminator = std::find(source.requested_view_id.begin(),
				source.requested_view_id.end(), '\0');
			if (terminator == source.requested_view_id.end())
				return false;
			candidate.assign(source.requested_view_id.begin(), terminator);
			if (candidate.empty())
				return false;
		}
		if (!aida::ui::is_valid_stable_id(candidate) ||
			(candidate.rfind("view.", 0) != 0 && candidate.rfind("document.", 0) != 0))
			return false;
		const aida::ui::stable_view_id_t id(candidate);
		if (!aida::ui::application_views::registry().find_descriptor(id))
			return false;
		return aida::ui::application_views::open_or_focus(id).ok();
	}

	void set_phase(shell_phase_t value)
	{
		active_phase = value;
	}

	shell_phase_t phase()
	{
		return active_phase;
	}

	bool runtime_ready()
	{
		return active_phase == shell_phase_t::ide;
	}

	bool loading()
	{
		return active_phase == shell_phase_t::loading;
	}

	bool welcome_done()
	{
		return active_phase == shell_phase_t::ide || active_phase == shell_phase_t::license;
	}

	bool mouse_button_down(ImGuiMouseButton button)
	{
		return ImGui::IsMouseDown(button);
	}

	void record(shell_action_t action, const std::string& detail)
	{
		action_receipts.push_back({ action, detail, next_sequence++ });
		if (action_receipts.size() > 256)
			action_receipts.erase(action_receipts.begin(), action_receipts.begin() + 64);
	}

	const std::vector<shell_receipt_t>& receipts()
	{
		return action_receipts;
	}

	bool choose_open_file(char* out_path, std::size_t out_path_capacity)
	{
		copy_path("C:/Preview/ReverseEngineering/samples/sample.exe", out_path, out_path_capacity);
		record(shell_action_t::open_file, out_path ? out_path : "");
		return true;
	}

	bool choose_save_file(char* out_path, std::size_t out_path_capacity)
	{
		copy_path("C:/Preview/ReverseEngineering/exported_sample.cpp", out_path, out_path_capacity);
		record(shell_action_t::save_file, out_path ? out_path : "");
		return true;
	}

	bool choose_folder(std::string& out_path)
	{
		out_path = "C:/Preview/ReverseEngineering";
		record(shell_action_t::open_folder, out_path);
		return true;
	}

	void apply_open_file()
	{
		static_cast<void>(aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("document.disassembly")));
		globals::ui::breadcrumb_segments = { "AiDA", "sample.exe", ".text", "main" };
		output_log::push(bottom_tab_t::output, "[preview] Opened sample.exe fixture");
	}

	void apply_open_folder()
	{
		aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("view.project_explorer"));
		output_log::push(bottom_tab_t::output, "[preview] Opened ReverseEngineering fixture workspace");
	}

	void apply_save_file()
	{
		if (aida::preview::editor::save_document()) {
			output_log::push(bottom_tab_t::output, "[preview] Saved active document fixture");
			return;
		}
		std::string reason = "The retained document save was rejected";
		const int tab_index = file_tabs::find_document(aida::preview::editor::fixture_document_id);
		if (file_tabs::is_valid_tab_index(tab_index)) {
			const auto& tab = file_tabs::tabs[file_tabs::tab_index(tab_index)];
			if (!tab.save_error.empty()) reason = tab.save_error;
		}
		output_log::push(bottom_tab_t::output, "[preview] Save rejected: " + reason);
	}

	void apply_chat_send(const std::string& prompt)
	{
		if (prompt.empty())
			return;
		g_chat_messages.push_back(chat_message(prompt, true, static_cast<std::int64_t>(next_sequence)));
		g_chat_messages.push_back(chat_message("Preview receipt recorded. Runtime analysis is disabled while the original UI remains fully interactive.", false, static_cast<std::int64_t>(next_sequence + 1)));
		g_chat_scroll_to_bottom = true;
		record(shell_action_t::chat_send, prompt);
	}

	const std::vector<process_fixture_t>& processes()
	{
		return process_rows;
	}

	const std::vector<module_fixture_t>& modules()
	{
		return module_rows;
	}

	const std::vector<thread_fixture_t>& threads()
	{
		return thread_rows;
	}

	std::uint32_t attached_pid()
	{
		return active_pid;
	}

	const std::string& attached_process_name()
	{
		return active_process_name;
	}

	void attach_process(const process_fixture_t& process)
	{
		active_pid = process.pid;
		active_process_name = process.name;
		static_cast<void>(aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("document.disassembly")));
		record(shell_action_t::attach_process, process.name);
		output_log::push(bottom_tab_t::driver_log, "[preview] Attached deterministic process fixture " + process.name);
	}

	void detach_process()
	{
		record(shell_action_t::detach_process, active_process_name);
		active_pid = 0;
		active_process_name.clear();
	}

	void configure_debugger_fixture(fixture_state_t state, std::size_t cardinality)
	{
		debugger::process_creation_time_100ns = 1;
		debugger::apply_fixture_state(state, cardinality);
		debugger_engine::preview_last_error() = state == fixture_state_t::error
			? "The debug target terminated while reading thread context" : std::string{};
	}

	void configure_analysis_mutation_fixture(fixture_state_t state)
	{
		if (state == fixture_state_t::analysis_mutation_current) {
			debugger::process_creation_time_100ns = 1;
			debugger::apply_fixture_state(fixture_state_t::normal, 0U);
			configure_workspace_preview_target(workspace_preview_target_t::live_process);
			while (analysis_session::session_count() != 0U)
				if (!analysis_session::close_session(0U))
					break;
			const auto& fixture = workspace_preview_fixture();
			static_cast<void>(analysis_session::open_session(fixture.source_path));
			debugger_interaction::synchronize_target_snapshot(6420, true,
				debugger_engine::g_state.registers.rip,
				debugger_engine::g_state.active_tid);
			record(shell_action_t::attach_process,
				"analysis mutation current pid=6420 creation=1");
			return;
		}
		if (state == fixture_state_t::analysis_mutation_stale_stop) {
			debugger_interaction::advance_stop_generation();
			record(shell_action_t::attach_process,
				"analysis mutation stale stop generation=" +
					std::to_string(debugger_interaction::current_stop_generation()));
			return;
		}
		if (state == fixture_state_t::analysis_mutation_pid_reuse) {
			debugger::process_creation_time_100ns = 2;
			debugger_interaction::synchronize_target_snapshot(6420, true,
				debugger_engine::g_state.registers.rip,
				debugger_engine::g_state.active_tid);
			record(shell_action_t::attach_process,
				"analysis mutation reused pid=6420 creation=2");
		}
	}
}

#endif
