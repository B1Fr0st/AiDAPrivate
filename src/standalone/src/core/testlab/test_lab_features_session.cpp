#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

	void push_u32_hex(test_lab::result_t& r, const char* label, std::uint32_t v) {
		char b[32];
		std::snprintf(b, sizeof(b), "%u (0x%08X)", v, v);
		r.parsed.push_back({ label, b });
	}

	void push_u64_hex(test_lab::result_t& r, const char* label, std::uint64_t v) {
		char b[40];
		std::snprintf(b, sizeof(b), "0x%016llX", static_cast<unsigned long long>(v));
		r.parsed.push_back({ label, b });
	}

	void render_inputs_hb(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("No inputs. Issues one additional heartbeat IOCTL via device_t::send_heartbeat().");
		ImGui::TextDisabled("The running standalone already heartbeats continuously; this is non-destructive.");
	}

	void run_hb(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}

		bool ok = device->send_heartbeat();

		DWORD hb_error    = device->get_last_heartbeat_error();
		DWORD hb_bytes    = device->get_last_heartbeat_bytes_returned();
		std::uint64_t hb_response = device->get_last_heartbeat_response();
		std::uint32_t hb_ioctl    = device->get_last_heartbeat_ioctl_code();
		std::uint32_t hb_magic    = device->get_last_heartbeat_magic();
		BOOL  hb_dioctl_result    = device->get_last_heartbeat_dioctl_result();
		bool  bridge_ready        = device->sentinel_bridge_ready();
		std::uint64_t bridge_since = device->sentinel_ready_since_tsc();

		r.bytes_returned = static_cast<std::uint32_t>(hb_bytes);

		push_u32_hex(r, "ioctl_code (HB)", hb_ioctl);
		push_u32_hex(r, "heartbeat_magic", hb_magic);
		push_u64_hex(r, "response (counter ^ key)", hb_response);
		push_u32_hex(r, "bytes_returned",  static_cast<std::uint32_t>(hb_bytes));
		push_u32_hex(r, "GetLastError",    static_cast<std::uint32_t>(hb_error));
		r.parsed.push_back({ "DeviceIoControl", hb_dioctl_result ? "TRUE" : "FALSE" });
		r.parsed.push_back({ "sentinel_bridge_ready", bridge_ready ? "yes" : "no" });
		push_u64_hex(r, "sentinel_ready_since_tsc", bridge_since);

		if (!ok) {
			r.ok = false;
			r.error = "send_heartbeat returned false";
			if (r.ntstatus == 0) {
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			}
			return;
		}
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_hb, "session", test_lab::driver_e::whoswho, "HB",
	"Heartbeat round-trip (one extra HB; dumps response counter, last sentinel/whoswho TSC bridge state).",
	&render_inputs_hb, &run_hb);
