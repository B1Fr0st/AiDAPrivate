#pragma once

#include <cstddef>

namespace test_all_features {

	bool start_tests();
	void render_overlay(float vw, float vh);
	bool is_running();
	void set_progress_step(const char* label);
	void format_debug_snapshot(char* out, std::size_t cap);
	void run_parser_proof_smoke();

}
