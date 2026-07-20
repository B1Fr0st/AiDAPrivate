#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace aida::ui::programming_tasks {

struct operation_result_t {
    bool succeeded = false;
    std::string detail;
};

void render_output_controls();
void render_automation_scripts();
void render_modals();
bool output_line_visible(std::string_view line);
std::string selected_output_channel();
operation_result_t request_run_selected();
operation_result_t request_run_selected_for_file(const std::string& path, bool launch);
operation_result_t request_test_selected_for_file(const std::string& path);
operation_result_t request_cancel_active();
operation_result_t request_retry_last();
operation_result_t open_configurations();
operation_result_t reload_configurations();
bool has_active_run();
std::size_t problem_count();
std::string run_unavailable_reason();
std::string run_for_file_unavailable_reason(const std::string& path, bool launch);
std::string test_for_file_unavailable_reason(const std::string& path);
std::string cancel_unavailable_reason();
std::string retry_unavailable_reason();

}
