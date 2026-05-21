#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../runtime/standalone_driver.hpp"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <string>

namespace {

	std::string dec_u32(std::uint32_t v) {
		char b[16];
		std::snprintf(b, sizeof(b), "%u", static_cast<unsigned>(v));
		return std::string(b);
	}

	void render_inputs_dbga(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("Verify the standalone driver bridge is latched onto the spawned target.");
		ImGui::TextDisabled("Reports loaded state, memory access, attached pid and process name.");
	}

	void run_dbga(test_lab::state_t& s, test_lab::result_t& r) {
		bool loaded = driver_bridge::is_loaded();
		bool can_read = driver_bridge::can_read_memory();
		std::uint32_t pid = driver_bridge::attached_pid();
		std::string name = driver_bridge::attached_process_name();
		std::string status = driver_bridge::status();

		if (s.pid != 0 && pid != 0 && s.pid != pid) {
			r.parsed.push_back({ "expected_pid", dec_u32(s.pid) });
		}

		r.parsed.push_back({ "driver_loaded", loaded ? "true" : "false" });
		r.parsed.push_back({ "can_read_memory", can_read ? "true" : "false" });
		r.parsed.push_back({ "attached_pid", dec_u32(pid) });
		r.parsed.push_back({ "attached_process", name.empty() ? "<none>" : name });
		r.parsed.push_back({ "status", status });

		r.bytes_returned = static_cast<std::uint32_t>(name.size());

		if (pid == 0) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
			r.error = "no target attached (driver_bridge::attached_pid() == 0)";
			r.ok = false;
			return;
		}

		if (!loaded) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
			r.error = "target latched but driver bridge reports not loaded";
			r.ok = false;
			return;
		}

		r.ntstatus = 0;
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_dbga,
	"debug-attach",
	test_lab::driver_e::whoswho,
	"DBGA",
	"Verify the standalone driver bridge is attached to the spawned target process.",
	&render_inputs_dbga,
	&run_dbga);
