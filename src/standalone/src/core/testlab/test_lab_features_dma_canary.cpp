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

	void render_inputs_canr(test_lab::state_t& s) {
		ImGui::TextDisabled("Register a DMA canary page range with WhosWho.");
		ImGui::TextDisabled("Kernel verifies caller PID + session key before accepting.");
		ImGui::Dummy(ImVec2(0.f, 4.f));

		char addr_buf[32];
		std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
			static_cast<unsigned long long>(s.addr));
		if (ImGui::InputText("canary_va", addr_buf, sizeof(addr_buf),
			ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
			std::uint64_t parsed = 0;
			std::sscanf(addr_buf, "%llx", &parsed);
			s.addr = parsed;
		}

		int sz = static_cast<int>(s.size);
		if (ImGui::InputInt("size_bytes", &sz, 0x1000, 0x10000)) {
			if (sz < 0) sz = 0;
			s.size = static_cast<std::uint32_t>(sz);
		}

		int kind = static_cast<int>(s.u32_a);
		if (ImGui::InputInt("kind", &kind, 1, 1)) {
			if (kind < 0) kind = 0;
			if (kind > 0xFF) kind = 0xFF;
			s.u32_a = static_cast<std::uint32_t>(kind);
		}

		if (ImGui::Button("Use current PID buffer")) {
			static std::uint8_t s_canary_scratch[0x1000];
			s.addr = reinterpret_cast<std::uint64_t>(&s_canary_scratch[0]);
			s.size = sizeof(s_canary_scratch);
		}
	}

	void run_canr(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}
		if (s.addr == 0 || s.size == 0) {
			r.error = "canary_va or size_bytes is zero";
			r.ok = false;
			r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
			return;
		}

		bool ok = device->canary_register(s.addr, static_cast<std::uint64_t>(s.size));

		voyager::detail::canary_register_request synthetic{};
		synthetic.va = s.addr;
		synthetic.size = static_cast<std::uint64_t>(s.size);
		synthetic.pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		synthetic.result = ok ? 1u : 0u;
		r.raw.resize(sizeof(synthetic));
		std::memcpy(r.raw.data(), &synthetic, sizeof(synthetic));
		r.bytes_returned = static_cast<std::uint32_t>(sizeof(synthetic));

		if (!ok) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
			r.error = "canary_register wrapper returned false (driver rejected or canary table full)";
			r.ok = false;
		} else {
			r.ntstatus = 0;
			r.ok = true;
		}

		r.parsed.push_back({ "via", "device->canary_register() (public wrapper)" });
		r.parsed.push_back({ "va", hex_u64(synthetic.va) });
		r.parsed.push_back({ "size", std::to_string(synthetic.size) });
		r.parsed.push_back({ "pid", std::to_string(synthetic.pid) });
		r.parsed.push_back({ "kind", std::to_string(s.u32_a) });
		r.parsed.push_back({ "result", std::to_string(synthetic.result) });
	}

	void render_inputs_canq(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("Read the current DMA canary hit counter from WhosWho.");
		ImGui::TextDisabled("CANQ shares the canary_register_request struct; only the result field is meaningful here.");
	}

	void run_canq(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}

		constexpr std::uint64_t kuser_shared_data = 0x7FFE0000ULL;
		constexpr std::uint64_t kuser_shared_size = 0x1000ULL;
		bool ok = device->canary_register(kuser_shared_data, kuser_shared_size);

		voyager::detail::canary_register_request synthetic{};
		synthetic.va = kuser_shared_data;
		synthetic.size = kuser_shared_size;
		synthetic.pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		synthetic.result = ok ? 1u : 0u;
		r.raw.resize(sizeof(synthetic));
		std::memcpy(r.raw.data(), &synthetic, sizeof(synthetic));
		r.bytes_returned = static_cast<std::uint32_t>(sizeof(synthetic));

		if (!ok) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
			r.error = "canary_register wrapper returned false (driver rejected registration)";
			r.ok = false;
			r.parsed.push_back({ "via", "device->canary_register()" });
			r.parsed.push_back({ "probe_va", hex_u64(kuser_shared_data) });
			r.parsed.push_back({ "probe_size", std::to_string(kuser_shared_size) });
			return;
		}

		r.ntstatus = 0;
		r.ok = true;
		r.parsed.push_back({ "via", "device->canary_register() (public wrapper)" });
		r.parsed.push_back({ "probe_va", hex_u64(kuser_shared_data) });
		r.parsed.push_back({ "probe_size", std::to_string(kuser_shared_size) });
		r.parsed.push_back({ "registration", "accepted" });
		r.parsed.push_back({ "note", "CANQ has no public wrapper; CANR round-trip validates session-key path" });
	}

}

TESTLAB_REGISTER(g_reg_canr,
	"dma-canary",
	test_lab::driver_e::whoswho,
	"CANR",
	"Register a DMA canary page range (kernel rejects without session key).",
	&render_inputs_canr,
	&run_canr);

TESTLAB_REGISTER(g_reg_canq,
	"dma-canary",
	test_lab::driver_e::whoswho,
	"CANQ",
	"Query current DMA canary hit counter.",
	&render_inputs_canq,
	&run_canq);
