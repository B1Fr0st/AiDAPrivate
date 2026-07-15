#include "shell_preview.hpp"

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "../helpers/globals.h"
#include "../helpers/helpers.h"
#include "../core/ui/clock.hpp"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <utility>

ID3D11Device* g_pd3dDevice = nullptr;
HWND g_hwnd = nullptr;

namespace aida::preview
{
	namespace
	{
		std::atomic<bool> initialized{false};
		std::atomic<bool> fixture_ready{true};
		shell_phase_t active_phase = shell_phase_t::ide;
		std::vector<shell_receipt_t> action_receipts;
		std::uint64_t next_sequence = 1;
		std::uint32_t active_pid = 0;
		std::string active_process_name;
		shell_controls_t fixture_controls;
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
		globals::ui::bg_init_done = &fixture_ready;
		globals::ui::bg_init_step.store(globals::ui::bg_init_total.load(std::memory_order_acquire), std::memory_order_release);
		globals::ui::window_w = display_size.x > 0.f ? display_size.x : 1280.f;
		globals::ui::window_h = display_size.y > 0.f ? display_size.y : 760.f;
		globals::ui::welcome_done = active_phase == shell_phase_t::ide || active_phase == shell_phase_t::license;
		globals::ui::ui_alpha = active_phase == shell_phase_t::ide ? 1.f : 0.f;
		license::validated = active_phase == shell_phase_t::ide;
		license::checking = false;
		license::activation_worker_active.store(false, std::memory_order_release);
		license::check_failed = false;
		if (initialized.exchange(true, std::memory_order_acq_rel))
			return;
		globals::ui::command_palette_open = false;
		globals::ui::command_palette_buf[0] = '\0';

		globals::ui::panel_left_visible = true;
		globals::ui::panel_right_visible = true;
		globals::ui::panel_bottom_visible = true;
		globals::ui::active_activity = activity_item_t::explorer;
		globals::ui::active_bottom_tab = bottom_tab_t::output;
		globals::ui::active_center_view = center_view_t::welcome;
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
		file_tabs::tabs.push_back({ "sample.cpp", "C:/Preview/ReverseEngineering/sample.cpp", "", true, false });
		file_tabs::tabs.push_back({ "notes.md", "C:/Preview/ReverseEngineering/notes.md", "", true, true });
		file_tabs::active_tab = 0;
		code_editor::filename = "sample.cpp";
		code_editor::filepath = "C:/Preview/ReverseEngineering/sample.cpp";
		const char* code = "int main() {\n    return analyze_target(\"sample.exe\");\n}\n";
		code_editor::buffer.assign(code, code + std::strlen(code) + 1);
		code_editor::active = true;
		code_editor::dirty = false;

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
		output_log::push(bottom_tab_t::output, "[analysis] 1,284 functions indexed");
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
		globals::ui::active_center_view = center_view_t::workbench;
		globals::ui::breadcrumb_segments = { "AiDA", "sample.exe", ".text", "main" };
		output_log::push(bottom_tab_t::output, "[preview] Opened sample.exe fixture");
	}

	void apply_open_folder()
	{
		globals::ui::panel_left_visible = true;
		globals::ui::active_activity = activity_item_t::explorer;
		output_log::push(bottom_tab_t::output, "[preview] Opened ReverseEngineering fixture workspace");
	}

	void apply_save_file()
	{
		code_editor::dirty = false;
		if (file_tabs::active_tab >= 0 && static_cast<std::size_t>(file_tabs::active_tab) < file_tabs::tabs.size())
			file_tabs::tabs[static_cast<std::size_t>(file_tabs::active_tab)].dirty = false;
		output_log::push(bottom_tab_t::output, "[preview] Saved active document fixture");
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
		globals::ui::active_center_view = center_view_t::disassembly;
		record(shell_action_t::attach_process, process.name);
		output_log::push(bottom_tab_t::driver_log, "[preview] Attached deterministic process fixture " + process.name);
	}

	void detach_process()
	{
		record(shell_action_t::detach_process, active_process_name);
		active_pid = 0;
		active_process_name.clear();
	}
}

#endif
