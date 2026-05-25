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

	void* canary_fixture_page() {
		static void* page = nullptr;
		if (!page)
			page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (page)
			std::memset(page, 0xA5, 0x1000);
		return page;
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
			void* page = canary_fixture_page();
			if (page) {
				s.addr = reinterpret_cast<std::uint64_t>(page);
				s.size = 0x1000;
				s.pid = static_cast<std::uint32_t>(GetCurrentProcessId());
			}
		}
	}

	void run_canr(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}
		const std::uint32_t current_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		std::uint64_t register_va = s.addr;
		std::uint64_t register_size = static_cast<std::uint64_t>(s.size);
		std::uint32_t register_pid = s.pid != 0 ? s.pid : current_pid;
		bool used_self_fixture = false;

		if (register_va == 0 || register_size == 0 || register_pid != current_pid) {
			void* page = canary_fixture_page();
			if (!page) {
				r.error = "failed to allocate current-process canary fixture page";
				r.ok = false;
				r.ntstatus = static_cast<std::int32_t>(0xC0000017u);
				return;
			}
			register_va = reinterpret_cast<std::uint64_t>(page);
			register_size = 0x1000;
			register_pid = current_pid;
			used_self_fixture = true;
		}

		if (register_va == 0 || register_size == 0) {
			r.error = "canary_va or size_bytes is zero";
			r.ok = false;
			r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
			return;
		}

		bool ok = device->canary_register_for_pid(register_va, register_size, register_pid);
		std::uint32_t canary_count = 0;
		bool query_ok = device->canary_query_count(canary_count);

		voyager::detail::canary_register_request synthetic{};
		synthetic.va = register_va;
		synthetic.size = register_size;
		synthetic.pid = register_pid;
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

		r.parsed.push_back({ "via", "device->canary_register_for_pid() (public wrapper)" });
		r.parsed.push_back({ "used_self_fixture", used_self_fixture ? "true" : "false" });
		r.parsed.push_back({ "requested_va", hex_u64(s.addr) });
		r.parsed.push_back({ "requested_size", std::to_string(s.size) });
		r.parsed.push_back({ "requested_pid", std::to_string(s.pid) });
		r.parsed.push_back({ "va", hex_u64(synthetic.va) });
		r.parsed.push_back({ "size", std::to_string(synthetic.size) });
		r.parsed.push_back({ "pid", std::to_string(synthetic.pid) });
		r.parsed.push_back({ "kind", std::to_string(s.u32_a) });
		r.parsed.push_back({ "result", std::to_string(synthetic.result) });
		r.parsed.push_back({ "query_after_register", query_ok ? std::to_string(canary_count) : "unavailable" });
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

		std::uint32_t canary_count = 0;
		bool ok = device->canary_query_count(canary_count);

		voyager::detail::canary_register_request synthetic{};
		synthetic.va = 0;
		synthetic.size = 0;
		synthetic.pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		synthetic.result = ok ? canary_count : 0u;
		r.raw.resize(sizeof(synthetic));
		std::memcpy(r.raw.data(), &synthetic, sizeof(synthetic));
		r.bytes_returned = static_cast<std::uint32_t>(sizeof(synthetic));

		if (!ok) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
			r.error = "canary_query_count wrapper returned false (driver rejected query)";
			r.ok = false;
			r.parsed.push_back({ "via", "device->canary_query_count()" });
			return;
		}

		r.ntstatus = 0;
		r.ok = true;
		r.parsed.push_back({ "via", "device->canary_query_count() (public wrapper)" });
		r.parsed.push_back({ "canary_count", std::to_string(canary_count) });
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
