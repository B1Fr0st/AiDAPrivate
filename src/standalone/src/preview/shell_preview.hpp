#pragma once

#include "imgui/imgui.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace aida::preview
{
	enum class shell_phase_t : int
	{
		ide,
		loading,
		welcome,
		license
	};

	enum class shell_action_t : int
	{
		close_window,
		minimize_window,
		toggle_maximize,
		move_window,
		open_file,
		open_folder,
		save_file,
		run_target,
		attach_process,
		detach_process,
		terminal_input,
		terminal_clear,
		chat_send,
		chat_cancel,
		copy_text,
		source_reconstruct,
		license_activate
	};

	struct shell_receipt_t
	{
		shell_action_t action = shell_action_t::open_file;
		std::string detail;
		std::uint64_t sequence = 0;
	};

	struct process_fixture_t
	{
		std::uint32_t pid = 0;
		std::string name;
		std::string path;
		std::string window_title;
	};

	struct module_fixture_t
	{
		std::uint64_t base = 0;
		std::string name;
	};

	struct thread_fixture_t
	{
		std::uint32_t tid = 0;
		int priority = 0;
	};

	struct shell_controls_t
	{
		std::uint64_t revision = 1;
		bool settle_animations = true;
		int open_menu = -1;
		int center_view = -1;
		bool theme_popup_open = false;
		bool tab_dropdown_open = false;
		bool hub_overflow_open = false;
		bool run_picker_open = false;
		bool run_confirmation_open = false;
		bool chat_history_open = false;
		bool chat_scrolled_up = false;
		bool chat_slash_commands_open = false;
		int bottom_tab = -1;
		bool process_dialog_open = false;
		int process_selection = 0;
		bool driver_dialog_open = false;
		int driver_tab = 0;
		bool shortcuts_dialog_open = false;
		bool invalidate_bottom_cache = false;
	};

	void initialize_shell_fixture(const ImVec2& display_size);
	void reset_shell_fixture();
	shell_controls_t& controls();
	void set_phase(shell_phase_t phase);
	shell_phase_t phase();
	bool runtime_ready();
	bool loading();
	bool welcome_done();
	bool mouse_button_down(ImGuiMouseButton button);
	void record(shell_action_t action, const std::string& detail = {});
	const std::vector<shell_receipt_t>& receipts();
	bool choose_open_file(char* out_path, std::size_t out_path_capacity);
	bool choose_save_file(char* out_path, std::size_t out_path_capacity);
	bool choose_folder(std::string& out_path);
	void apply_open_file();
	void apply_open_folder();
	void apply_save_file();
	void apply_chat_send(const std::string& prompt);
	const std::vector<process_fixture_t>& processes();
	const std::vector<module_fixture_t>& modules();
	const std::vector<thread_fixture_t>& threads();
	std::uint32_t attached_pid();
	const std::string& attached_process_name();
	void attach_process(const process_fixture_t& process);
	void detach_process();
}
