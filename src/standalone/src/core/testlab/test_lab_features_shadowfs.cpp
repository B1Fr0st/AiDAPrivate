#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../runtime/shadow_fs_client.hpp"
#include "imgui/imgui.h"

#include <Windows.h>

#include <cstdio>
#include <cstdint>
#include <string>

namespace {

	std::wstring widen_utf8(const std::string& s) {
		std::wstring out;
		out.reserve(s.size());
		for (std::size_t i = 0; i < s.size();) {
			unsigned char c = static_cast<unsigned char>(s[i]);
			std::uint32_t cp = 0;
			std::size_t n = 1;
			if (c < 0x80u) {
				cp = c;
				n = 1;
			} else if ((c & 0xE0u) == 0xC0u && i + 1 < s.size()) {
				cp = (static_cast<std::uint32_t>(c & 0x1Fu) << 6) |
					 static_cast<std::uint32_t>(static_cast<unsigned char>(s[i + 1]) & 0x3Fu);
				n = 2;
			} else if ((c & 0xF0u) == 0xE0u && i + 2 < s.size()) {
				cp = (static_cast<std::uint32_t>(c & 0x0Fu) << 12) |
					 (static_cast<std::uint32_t>(static_cast<unsigned char>(s[i + 1]) & 0x3Fu) << 6) |
					 static_cast<std::uint32_t>(static_cast<unsigned char>(s[i + 2]) & 0x3Fu);
				n = 3;
			} else if ((c & 0xF8u) == 0xF0u && i + 3 < s.size()) {
				cp = (static_cast<std::uint32_t>(c & 0x07u) << 18) |
					 (static_cast<std::uint32_t>(static_cast<unsigned char>(s[i + 1]) & 0x3Fu) << 12) |
					 (static_cast<std::uint32_t>(static_cast<unsigned char>(s[i + 2]) & 0x3Fu) << 6) |
					 static_cast<std::uint32_t>(static_cast<unsigned char>(s[i + 3]) & 0x3Fu);
				n = 4;
			} else {
				cp = 0xFFFDu;
				n = 1;
			}
			if (cp <= 0xFFFFu) {
				out.push_back(static_cast<wchar_t>(cp));
			} else {
				std::uint32_t v = cp - 0x10000u;
				out.push_back(static_cast<wchar_t>(0xD800u + (v >> 10)));
				out.push_back(static_cast<wchar_t>(0xDC00u + (v & 0x3FFu)));
			}
			i += n;
		}
		return out;
	}

	void push_u32(test_lab::result_t& r, const char* label, std::uint32_t v) {
		char b[32];
		std::snprintf(b, sizeof(b), "%u", static_cast<unsigned>(v));
		r.parsed.push_back({ label, b });
	}

	void push_i64(test_lab::result_t& r, const char* label, std::int64_t v) {
		char b[32];
		std::snprintf(b, sizeof(b), "%lld", static_cast<long long>(v));
		r.parsed.push_back({ label, b });
	}

	void render_inputs_register_pid(test_lab::state_t& s) {
		if (s.u32_a == 0) {
			s.u32_a = shadow_fs_client::k_default_flags;
		}
		int pid_value = static_cast<int>(s.pid);
		if (ImGui::InputInt("PID", &pid_value)) {
			if (pid_value < 0) pid_value = 0;
			s.pid = static_cast<std::uint32_t>(pid_value);
		}
		int flags_value = static_cast<int>(s.u32_a);
		if (ImGui::InputInt("Flags (hex)", &flags_value, 1, 16, ImGuiInputTextFlags_CharsHexadecimal)) {
			if (flags_value < 0) flags_value = 0;
			s.u32_a = static_cast<std::uint32_t>(flags_value);
		}
		char path_buf[260];
		std::snprintf(path_buf, sizeof(path_buf), "%s", s.text_a.c_str());
		if (ImGui::InputText("Sandbox root (UTF-8)", path_buf, sizeof(path_buf))) {
			s.text_a.assign(path_buf);
		}
		ImGui::TextDisabled("Registers a PID with the ShadowFS minifilter; writes are redirected into the sandbox root tree.");
	}

	void run_register_pid(test_lab::state_t& s, test_lab::result_t& r) {
		if (!shadow_fs_client::is_connected()) {
			shadow_fs_client::initialize();
		}
		if (!shadow_fs_client::is_connected()) {
			r.ok = false;
			r.error = "shadowfs port not connected";
			return;
		}
		if (s.pid == 0) {
			r.ok = false;
			r.error = "pid must be non-zero";
			return;
		}
		if (s.text_a.empty()) {
			r.ok = false;
			r.error = "sandbox root path required";
			return;
		}
		std::wstring root = widen_utf8(s.text_a);
		bool ok = shadow_fs_client::register_sandbox_pid(s.pid, s.u32_a, root);
		if (!ok) {
			r.ok = false;
			const std::string& err = shadow_fs_client::last_error();
			r.error = err.empty() ? std::string("register_sandbox_pid failed") : err;
			return;
		}
		push_u32(r, "pid", s.pid);
		char fb[16];
		std::snprintf(fb, sizeof(fb), "0x%08X", static_cast<unsigned>(s.u32_a));
		r.parsed.push_back({ "flags", fb });
		r.parsed.push_back({ "sandbox_root", s.text_a });
		r.parsed.push_back({ "status", "registered" });
		if (s.pid == static_cast<std::uint32_t>(GetCurrentProcessId())) {
			shadow_fs_client::unregister_sandbox_pid(s.pid);
			r.parsed.push_back({ "auto_unregister", "yes (self-pid, prevents subsequent writes from being intercepted)" });
		}
		r.ok = true;
	}

	void render_inputs_unregister_pid(test_lab::state_t& s) {
		int pid_value = static_cast<int>(s.pid);
		if (ImGui::InputInt("PID", &pid_value)) {
			if (pid_value < 0) pid_value = 0;
			s.pid = static_cast<std::uint32_t>(pid_value);
		}
		ImGui::TextDisabled("Removes a PID from the ShadowFS sandbox set.");
	}

	void run_unregister_pid(test_lab::state_t& s, test_lab::result_t& r) {
		if (!shadow_fs_client::is_connected()) {
			shadow_fs_client::initialize();
		}
		if (!shadow_fs_client::is_connected()) {
			r.ok = false;
			r.error = "shadowfs port not connected";
			return;
		}
		if (s.pid == 0) {
			r.ok = false;
			r.error = "pid must be non-zero";
			return;
		}
		bool ok = shadow_fs_client::unregister_sandbox_pid(s.pid);
		if (!ok) {
			r.ok = false;
			const std::string& err = shadow_fs_client::last_error();
			r.error = err.empty() ? std::string("unregister_sandbox_pid failed") : err;
			return;
		}
		push_u32(r, "pid", s.pid);
		r.parsed.push_back({ "status", "unregistered" });
		r.ok = true;
	}

	void render_inputs_ping(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("Pings the ShadowFS minifilter communication port.");
	}

	void run_ping(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!shadow_fs_client::is_connected()) {
			shadow_fs_client::initialize();
		}
		if (!shadow_fs_client::is_connected()) {
			r.ok = false;
			r.error = "shadowfs port not connected";
			return;
		}
		bool ok = shadow_fs_client::ping();
		if (!ok) {
			r.ok = false;
			const std::string& err = shadow_fs_client::last_error();
			r.error = err.empty() ? std::string("ping failed") : err;
			return;
		}
		r.parsed.push_back({ "alive", "1" });
		r.ok = true;
	}

	void render_inputs_query_stats(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("Reads the ShadowFS minifilter counters (denials, redirects, copies, byte totals, per-channel denial breakdown).");
	}

	void run_query_stats(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!shadow_fs_client::is_connected()) {
			shadow_fs_client::initialize();
		}
		if (!shadow_fs_client::is_connected()) {
			r.ok = false;
			r.error = "shadowfs port not connected";
			return;
		}
		shadow_fs_client::shadow_stats_t st{};
		bool ok = shadow_fs_client::query_stats(st);
		if (!ok) {
			r.ok = false;
			const std::string& err = shadow_fs_client::last_error();
			r.error = err.empty() ? std::string("query_stats failed") : err;
			return;
		}
		push_u32(r, "active_pid_count", st.active_pid_count);
		push_i64(r, "denials", st.denials);
		push_i64(r, "redirects", st.redirects);
		push_i64(r, "copies", st.copies);
		push_i64(r, "bytes_copied", st.bytes_copied);
		push_i64(r, "fsctl_denials", st.fsctl_denials);
		push_i64(r, "ads_denials", st.ads_denials);
		push_i64(r, "mapping_denials", st.mapping_denials);
		push_i64(r, "unc_denials", st.unc_denials);
		push_i64(r, "raw_device_denials", st.raw_device_denials);
		push_i64(r, "set_info_denials", st.set_info_denials);
		push_i64(r, "dir_merge_emits", st.dir_merge_emits);
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_shadowfs_register_pid,
	"shadowfs", test_lab::driver_e::shadowfs,
	"REGISTER_PID", "Register a PID for ShadowFS write redirection",
	&render_inputs_register_pid, &run_register_pid);

TESTLAB_REGISTER(g_reg_shadowfs_unregister_pid,
	"shadowfs", test_lab::driver_e::shadowfs,
	"UNREGISTER_PID", "Remove a PID from the ShadowFS sandbox set",
	&render_inputs_unregister_pid, &run_unregister_pid);

TESTLAB_REGISTER(g_reg_shadowfs_ping,
	"shadowfs", test_lab::driver_e::shadowfs,
	"PING", "Heartbeat the minifilter communication port",
	&render_inputs_ping, &run_ping);

TESTLAB_REGISTER(g_reg_shadowfs_query_stats,
	"shadowfs", test_lab::driver_e::shadowfs,
	"QUERY_STATS", "Dump ShadowFS counters (denials, redirects, copies, bytes_copied)",
	&render_inputs_query_stats, &run_query_stats);
