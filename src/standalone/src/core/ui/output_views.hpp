#pragma once

#include <string>

enum class bottom_tab_t : int;

namespace aida::ui::output_views {

struct operation_result_t {
    bool succeeded = false;
    std::string detail;
};

void render(bottom_tab_t tab);
operation_result_t copy_all(bottom_tab_t tab);
operation_result_t clear(bottom_tab_t tab);
operation_result_t select_all(bottom_tab_t tab);
operation_result_t toggle_follow(bottom_tab_t tab);
operation_result_t focus_filter(bottom_tab_t tab);
operation_result_t export_all(bottom_tab_t tab);
bool has_content(bottom_tab_t tab);
bool supports_filter(bottom_tab_t tab) noexcept;
bool follows_tail(bottom_tab_t tab);
bool source_available(bottom_tab_t tab) noexcept;

}
