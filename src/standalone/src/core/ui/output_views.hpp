#pragma once

#include <cstddef>
#include <string>
#include <string_view>

enum class bottom_tab_t : int;

namespace aida::ui::output_views {

struct operation_result_t {
    bool succeeded = false;
    std::string detail;
};

void render(bottom_tab_t tab, std::string_view stable_view_id,
    std::string_view stable_instance_key = {});
operation_result_t copy_all(bottom_tab_t tab);
operation_result_t clear(bottom_tab_t tab);
operation_result_t select_all(bottom_tab_t tab);
operation_result_t toggle_follow(bottom_tab_t tab);
operation_result_t focus_filter(bottom_tab_t tab);
operation_result_t export_all(bottom_tab_t tab);
operation_result_t terminal_new();
operation_result_t terminal_new_at(const std::string& working_directory);
operation_result_t terminal_close();
operation_result_t terminal_restart();
operation_result_t terminal_next();
operation_result_t terminal_previous();
operation_result_t terminal_split_vertical();
operation_result_t terminal_split_horizontal();
operation_result_t terminal_unsplit();
operation_result_t terminal_focus_search();
operation_result_t terminal_paste();
bool has_content(bottom_tab_t tab);
bool supports_filter(bottom_tab_t tab) noexcept;
bool follows_tail(bottom_tab_t tab);
bool source_available(bottom_tab_t tab) noexcept;
std::size_t terminal_session_count() noexcept;
bool terminal_is_split() noexcept;

}
