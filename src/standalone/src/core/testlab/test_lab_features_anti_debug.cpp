#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

	struct debug_attach_request_k_t {
		std::uint32_t magic;
		std::uint32_t session_key;
		std::uint32_t pid;
		std::uint32_t result_flags;
		std::uint64_t reserved;
	};
	static_assert(sizeof(debug_attach_request_k_t) == 24, "debug_attach_request_k_t must mirror kernel struct (24 bytes)");

	const char* anti_debug_op_label(std::uint32_t op) {
		switch (op) {
			case 0u:  return "query";
			case 1u:  return "clear_dr_all_cpus";
			case 2u:  return "scan_debugger_processes";
			case 3u:  return "hide_thread";
			case 4u:  return "clear_process_dr";
			case 5u:  return "hide_all_process_threads";
			case 6u:  return "install_instrumentation_cb";
			case 7u:  return "remove_instrumentation_cb";
			case 8u:  return "start_continuous";
			case 9u:  return "stop_continuous";
			case 10u: return "clear_debug_object";
			default:  return "unknown";
		}
	}

	void render_inputs_adbg(test_lab::state_t& s) {
		static const char* items[] = {
			"0 query",
			"1 clear DR (all CPUs)",
			"2 scan debugger processes",
			"3 hide thread (needs pid + tid)",
			"4 clear process DRs (needs pid)",
			"5 hide all process threads (needs pid)",
			"6 install instrumentation callback (needs pid)",
			"7 remove instrumentation callback (needs pid)",
			"8 start continuous (needs pid)",
			"9 stop continuous",
			"10 clear debug object (needs pid)",
		};
		int current = static_cast<int>(s.u32_a);
		if (current < 0 || current >= static_cast<int>(sizeof(items) / sizeof(items[0]))) current = 0;
		if (ImGui::Combo("Operation", &current, items, static_cast<int>(sizeof(items) / sizeof(items[0])))) {
			s.u32_a = static_cast<std::uint32_t>(current);
		}
		ImGui::InputScalar("PID (optional)", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::InputScalar("TID (op 3 only)", ImGuiDataType_U32, &s.tid, nullptr, nullptr, "%u");
		ImGui::InputScalar("Callback VA (op 6 only)", ImGuiDataType_U64, &s.u64_a, nullptr, nullptr, "%llX",
			ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::TextDisabled("Operation %u -> %s", s.u32_a, anti_debug_op_label(s.u32_a));
	}

	void run_adbg(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}
		voyager::detail::anti_debug_request req{};
		req.operation = s.u32_a;
		req.pid = s.pid;
		req.tid = s.tid;
		req.detected_debugger_pid = s.u64_a;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::ADBG(), &req, sizeof(req), bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		if (!ok) {
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		char buf[64];
		std::snprintf(buf, sizeof(buf), "%u (%s)", req.operation, anti_debug_op_label(req.operation));
		r.parsed.push_back({ "operation", buf });
		std::snprintf(buf, sizeof(buf), "0x%08X", req.result_flags);
		r.parsed.push_back({ "result_flags", buf });
		std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(req.detected_debugger_pid));
		r.parsed.push_back({ "detected_debugger_pid", buf });
		std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(req.dr_clear_count));
		r.parsed.push_back({ "dr_clear_count", buf });
		r.ok = true;
	}

	const char* debug_attach_op_label(std::uint32_t op) {
		switch (op) {
			case 0u: return "query (caller PID if pid=0)";
			case 1u: return "query (explicit PID)";
			default: return "query";
		}
	}

	void render_inputs_dbga(test_lab::state_t& s) {
		static const char* items[] = {
			"0 query caller (pid=0 -> registered client)",
			"1 query explicit pid",
		};
		int current = static_cast<int>(s.u32_a);
		if (current < 0 || current >= static_cast<int>(sizeof(items) / sizeof(items[0]))) current = 0;
		if (ImGui::Combo("Subcommand", &current, items, static_cast<int>(sizeof(items) / sizeof(items[0])))) {
			s.u32_a = static_cast<std::uint32_t>(current);
		}
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Driver returns result_flags bit0=KD-on-since-attach, bit1=DebugPort-present.");
		ImGui::TextDisabled("WARNING: non-zero flags trigger SentinelBridge evidence + KeBugCheckEx if KeBugCheckEx is resolved.");
	}

	void run_dbga(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}
		debug_attach_request_k_t req{};
		req.magic = voyager::detail::get_heartbeat_magic();
		req.session_key = 0u;
		req.pid = (s.u32_a == 1u) ? s.pid : 0u;
		req.result_flags = 0u;
		req.reserved = 0u;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::DBGA(), &req, sizeof(req), bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		if (!ok) {
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		char buf[64];
		std::snprintf(buf, sizeof(buf), "%u (%s)", s.u32_a, debug_attach_op_label(s.u32_a));
		r.parsed.push_back({ "subcommand", buf });
		std::snprintf(buf, sizeof(buf), "%u", req.pid);
		r.parsed.push_back({ "resolved_pid", buf });
		std::snprintf(buf, sizeof(buf), "0x%08X", req.result_flags);
		r.parsed.push_back({ "result_flags", buf });
		r.parsed.push_back({ "kd_transitioned_to_enabled", (req.result_flags & 0x1u) ? "1" : "0" });
		r.parsed.push_back({ "debug_port_present",           (req.result_flags & 0x2u) ? "1" : "0" });
		r.ok = true;
	}

	const char* event_type_label(std::uint32_t et) {
		switch (et) {
			case 0u: return "invalid";
			case 1u: return "image_loaded";
			case 2u: return "process_created";
			case 3u: return "process_exited";
			default: return "unknown";
		}
	}

	void render_inputs_evts(test_lab::state_t& s) {
		ImGui::InputScalar("PID filter (0 = registered client)", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Driver-side filter is per registered_client_pid; the PID input is informational only.");
		ImGui::TextDisabled("Drains up to DRAIN_DEBUG_EVENTS_CAP (64) events per call.");
	}

	void run_evts(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}

		std::vector<voyager::device_t::debug_event_record> events;
		voyager::device_t::debug_event_drain_stats stats{};
		bool ok = device->drain_debug_events(events, voyager::detail::DRAIN_DEBUG_EVENTS_CAP, &stats);

		struct evts_header_dump_t {
			std::uint32_t returned_count;
			std::uint32_t dropped_since_last_drain;
			std::uint64_t total_dropped;
			std::uint64_t total_published;
			std::uint64_t reserved;
		};
		evts_header_dump_t header{};
		header.returned_count = stats.returned_count;
		header.dropped_since_last_drain = stats.dropped_since_last_drain;
		header.total_dropped = stats.total_dropped;
		header.total_published = stats.total_published;
		header.reserved = 0;
		r.raw.resize(sizeof(header));
		std::memcpy(r.raw.data(), &header, sizeof(header));
		r.bytes_returned = static_cast<std::uint32_t>(sizeof(header));

		if (!ok) {
			r.error = "drain_debug_events wrapper returned false (driver rejected)";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}

		char buf[256];
		std::snprintf(buf, sizeof(buf), "%u", stats.returned_count);
		r.parsed.push_back({ "returned_count", buf });
		std::snprintf(buf, sizeof(buf), "%u", stats.dropped_since_last_drain);
		r.parsed.push_back({ "dropped_since_last_drain", buf });
		std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(stats.total_dropped));
		r.parsed.push_back({ "total_dropped", buf });
		std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(stats.total_published));
		r.parsed.push_back({ "total_published", buf });
		r.parsed.push_back({ "via", "device->drain_debug_events() (public wrapper)" });

		std::size_t cap = events.size();
		if (cap > 16u) cap = 16u;
		for (std::size_t i = 0; i < cap; ++i) {
			const auto& e = events[i];
			char label[32];
			std::snprintf(label, sizeof(label), "event[%zu]", i);
			char path_ascii[voyager::detail::DEBUG_EVENT_PATH_CHARS + 1];
			std::size_t out_len = 0;
			for (std::size_t k = 0; k < e.image_path.size() && k < voyager::detail::DEBUG_EVENT_PATH_CHARS; ++k) {
				wchar_t wc = e.image_path[k];
				if (wc == L'\0') break;
				if (wc < 0x20 || wc >= 0x7F) {
					path_ascii[out_len++] = '?';
				} else {
					path_ascii[out_len++] = static_cast<char>(wc);
				}
			}
			path_ascii[out_len] = '\0';
			std::snprintf(buf, sizeof(buf),
				"type=%u(%s) pid=%u tid=%u flags=0x%08X base=0x%llX size=0x%llX path=%s",
				static_cast<std::uint32_t>(e.type),
				event_type_label(static_cast<std::uint32_t>(e.type)),
				e.process_id, e.thread_id, e.flags,
				static_cast<unsigned long long>(e.image_base),
				static_cast<unsigned long long>(e.image_size),
				path_ascii);
			r.parsed.push_back({ label, buf });
		}
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_adbg, "anti-debug", test_lab::driver_e::whoswho,
	"ADBG", "Query / control kernel anti-debug state (DR clear, debugger scan, thread hide, instrumentation callback, continuous mode).",
	&render_inputs_adbg, &run_adbg);

TESTLAB_REGISTER(g_reg_dbga, "anti-debug", test_lab::driver_e::whoswho,
	"DBGA", "Debug-attach query for a process: returns KD-on / DebugPort flags. Non-zero flags publish RE evidence and may bugcheck.",
	&render_inputs_dbga, &run_dbga);

TESTLAB_REGISTER(g_reg_evts, "anti-debug", test_lab::driver_e::whoswho,
	"EVTS", "Drain queued debug events (image loads, child process create/exit) for the registered client PID.",
	&render_inputs_evts, &run_evts);
