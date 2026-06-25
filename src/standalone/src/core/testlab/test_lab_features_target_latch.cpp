#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

	std::string hex_u32(std::uint32_t v) {
		char b[12];
		std::snprintf(b, sizeof(b), "0x%08X", static_cast<unsigned>(v));
		return std::string(b);
	}

	std::string hex_u64(std::uint64_t v) {
		char b[20];
		std::snprintf(b, sizeof(b), "0x%llX", static_cast<unsigned long long>(v));
		return std::string(b);
	}

	void render_inputs_tira(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("Query whether any tier-A target driver is currently latched.");
		ImGui::TextDisabled("Returns a boolean flag and a bitmask of latched tier-A signatures.");
	}

	void run_tira(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}

		bool present = false;
		std::uint32_t tier_mask = 0;
		std::uint64_t first_driver_base = 0;
		bool ok = device->tier_a_driver_present_query(present, &tier_mask, &first_driver_base);

		voyager::detail::tier_a_query_request synthetic{};
		synthetic.present_flag = present ? 1u : 0u;
		synthetic.tier_mask = tier_mask;
		synthetic.first_driver_base = first_driver_base;
		r.raw.resize(sizeof(synthetic));
		std::memcpy(r.raw.data(), &synthetic, sizeof(synthetic));
		r.bytes_returned = static_cast<std::uint32_t>(sizeof(synthetic));

		if (!ok) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
			r.error = "tier_a_driver_present_query wrapper returned false (driver rejected)";
			r.ok = false;
		} else {
			r.ntstatus = 0;
			r.ok = true;
		}

		r.parsed.push_back({ "via", "device->tier_a_driver_present_query() (public wrapper)" });
		r.parsed.push_back({ "present", present ? "true" : "false" });
		r.parsed.push_back({ "tier_mask", hex_u32(tier_mask) });
		r.parsed.push_back({ "first_driver_base", hex_u64(first_driver_base) });
		r.parsed.push_back({ "coverage_kind", present ? "health_present_review_required" : "health_absence" });
		r.parsed.push_back({ "health_check_pass", ok && !present ? "true" : "false" });
		r.parsed.push_back({ "positive_detection_coverage", "false" });
		r.parsed.push_back({ "positive_fixture_available", "false" });
		r.parsed.push_back({ "positive_detection_result", present ? "live_presence_not_controlled_fixture" : "not_exercised_absent" });
		r.parsed.push_back({ "absence_expected_healthy", present ? "false" : "true" });
	}

}

TESTLAB_REGISTER(g_reg_tira,
	"target-latch",
	test_lab::driver_e::whoswho,
	"TIRA",
	"Query whether a tier-A target driver is currently latched.",
	&render_inputs_tira,
	&run_tira);
