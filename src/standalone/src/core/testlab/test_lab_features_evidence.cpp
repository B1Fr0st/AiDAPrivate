#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

	std::string hex_u64(std::uint64_t v) {
		char b[20];
		std::snprintf(b, sizeof(b), "0x%llX", static_cast<unsigned long long>(v));
		return std::string(b);
	}

	std::string hex_u32(std::uint32_t v) {
		char b[12];
		std::snprintf(b, sizeof(b), "0x%08X", static_cast<unsigned>(v));
		return std::string(b);
	}

	void render_inputs_recu(test_lab::state_t& s) {
		ImGui::TextDisabled("Submit a synthetic RE-evidence blob to WhosWho.");
		ImGui::TextDisabled("Kernel rejects requests with an invalid session key.");
		ImGui::Dummy(ImVec2(0.f, 4.f));

		int max_entries = static_cast<int>(s.u32_a);
		if (ImGui::InputInt("max_entries", &max_entries, 1, 8)) {
			if (max_entries < 0) max_entries = 0;
			if (max_entries > 512) max_entries = 512;
			s.u32_a = static_cast<std::uint32_t>(max_entries);
		}

		int signal_family = static_cast<int>(s.u32_b);
		if (ImGui::InputInt("signal_family", &signal_family, 1, 4)) {
			if (signal_family < 0) signal_family = 0;
			if (signal_family > 0xFFFF) signal_family = 0xFFFF;
			s.u32_b = static_cast<std::uint32_t>(signal_family);
		}

		ImGui::TextDisabled("A successful RECU on a live driver triggers a kernel bugcheck.");
	}

	void run_recu(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}

		voyager::detail::re_confirmed_usermode_request req{};
		req.magic = 0;
		req.session_key = 0;
		req.evidence.magic = 0xA1DAE71DE7C0DEULL;
		req.evidence.version = 1;
		req.evidence.signal_family = s.u32_b;
		req.evidence.signal_id = 0;
		req.evidence.score = 0;
		req.evidence.pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		req.evidence.reserved0 = 0;
		req.evidence.caller_image_hash = 0;
		req.evidence.signals_bitmap_hash = 0;
		req.evidence.timestamp = 0;

		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(
			ioctl_codes::RECU(), &req, static_cast<std::uint32_t>(sizeof(req)), bytes_returned);

		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));

		if (!ok) {
			DWORD le = GetLastError();
			r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
			char buf[160];
			std::snprintf(buf, sizeof(buf),
				"send_ioctl_raw rejected (GetLastError=%lu, kernel requires session_key)", le);
			r.error = buf;
			r.ok = false;
		} else {
			r.ntstatus = 0;
			r.ok = true;
		}

		std::uint32_t cap = s.u32_a;
		if (cap == 0u) cap = 1u;
		if (cap > 50u) cap = 50u;

		char label[24];
		char value[160];
		for (std::uint32_t i = 0; i < cap; ++i) {
			std::snprintf(label, sizeof(label), "Evt[%u]", i);
			if (i == 0u) {
				std::snprintf(value, sizeof(value),
					"family=%u id=%u score=%u pid=%u tsc=0 reason=submitted",
					req.evidence.signal_family,
					req.evidence.signal_id,
					req.evidence.score,
					req.evidence.pid);
			} else {
				std::snprintf(value, sizeof(value),
					"tsc=0 reason=ring_unavailable (RECU is a submit-only IOCTL on WhosWho)");
			}
			r.parsed.push_back({ label, value });
		}

		r.parsed.push_back({ "magic", hex_u32(req.magic) });
		r.parsed.push_back({ "session_key", hex_u32(req.session_key) });
		r.parsed.push_back({ "evidence.magic", hex_u64(req.evidence.magic) });
		r.parsed.push_back({ "evidence.version", std::to_string(req.evidence.version) });
		r.parsed.push_back({ "evidence.signal_family", std::to_string(req.evidence.signal_family) });
		r.parsed.push_back({ "evidence.pid", std::to_string(req.evidence.pid) });
	}

}

TESTLAB_REGISTER(g_reg_recu,
	"evidence",
	test_lab::driver_e::whoswho,
	"RECU",
	"Submit synthetic RE-evidence blob (kernel rejects without session key).",
	&render_inputs_recu,
	&run_recu);
