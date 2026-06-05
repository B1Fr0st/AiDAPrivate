#pragma once

#include <cstddef>

namespace test_all_features {

	bool start_tests();
	void cancel_tests();
	void begin_test_guard(const char* source);
	void end_test_guard(const char* source, bool arm_post_suppression = true);
	void render_overlay(float vw, float vh);
	bool is_running();
	void set_progress_step(const char* label);
	void format_debug_snapshot(char* out, std::size_t cap);
	void run_parser_proof_smoke();
	void write_full_test_log_line(void* hf, const char* data, std::size_t size, bool force_flush = false);
	void flush_full_test_log(void* hf);
	void mirror_full_test_log_line(const char* tag, const char* detail, const char* line);

}
