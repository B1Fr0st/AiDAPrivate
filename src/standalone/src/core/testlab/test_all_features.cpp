#include "test_all_features.hpp"
#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "test_all_debugger.h"
#include "test_all_scanner.h"
#include "test_all_analysis.h"
#include "test_all_network.h"
#include "test_all_burp.h"
#include "test_all_disasm.h"
#include "test_all_mcp.h"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "../ui/theme.hpp"
#include "../debugger/debugger_engine.hpp"
#include "../network/mitm_proxy.hpp"
#include "../runtime/run_target.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../anti-tamper/state.hpp"
#include "../scanner/memory_scanner.hpp"
#include "../scanner/aob_generator.hpp"
#include "../disasm/cfg_view.hpp"
#include "../disasm/decompiler_engine.hpp"
#include "../disasm/pseudocode_view.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../helpers/globals.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include "../../../../../driver/comm.h"

#pragma comment(lib, "ws2_32.lib")

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace test_all_features {

	namespace {


		std::atomic<bool> g_running{ false };
		std::atomic<bool> g_cancel_requested{ false };
		std::atomic<bool> g_target_unavailable{ false };

		std::atomic<int>  g_total{ 0 };
		std::atomic<int>  g_current{ 0 };
		std::atomic<int>  g_passed{ 0 };
		std::atomic<int>  g_failed{ 0 };
		std::atomic<int>  g_skipped{ 0 };

		std::atomic<int>  g_suspect{ 0 };

		std::atomic<std::uint32_t> g_target_pid{ 0 };
		std::atomic<std::uint64_t> g_target_addr{ 0 };
		std::atomic<std::uint64_t> g_target_image_base{ 0 };
		std::atomic<bool>          g_driver_attached{ false };
		std::atomic<std::uint64_t> g_saved_dtb{ 0 };

		std::mutex        g_log_mtx;
		std::deque<std::string> g_log_lines;
		constexpr std::size_t kMaxLogLines = 4096;

		std::mutex        g_phase_mtx;
		std::string       g_phase_label;
		std::mutex        g_step_mtx;
		std::string       g_step_label;
		std::atomic<std::uint64_t> g_run_id{ 0 };
		std::atomic<std::uint64_t> g_run_start_tick{ 0 };
		std::atomic<std::uint64_t> g_phase_start_tick{ 0 };
		std::atomic<std::uint64_t> g_step_start_tick{ 0 };


		const char* log_path() {
			return "C:\\Users\\Public\\Desktop\\aida_full_test.log";
		}

		constexpr const char* kFullTestEnvName = "AIDA_FULL_TEST_RUNNING";
		constexpr const char* kTargetArgsText = "--no-external --duration 0 --net-rate 2000 --absorb-external-single-step";
		constexpr const wchar_t* kTargetArgsWide = L"--no-external --duration 0 --net-rate 2000 --absorb-external-single-step";
		constexpr int kLaunchFeatureTests = 1;
		constexpr int kExtendedFeatureTests = 6;
		constexpr int kDebuggerFeatureTests = 83;
		constexpr int kScannerFeatureTests = 64;
		constexpr int kAnalysisFeatureTests = 77;
		constexpr int kNetworkFeatureTests = 125;
		constexpr int kBurpFeatureTests = 184;
		constexpr int kDisasmFeatureTests = 110;
		constexpr int kMcpFeatureTests = 509;


		void format_timestamp(char* out, std::size_t cap) {
			SYSTEMTIME st;
			GetLocalTime(&st);
			std::snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
				static_cast<unsigned>(st.wYear),
				static_cast<unsigned>(st.wMonth),
				static_cast<unsigned>(st.wDay),
				static_cast<unsigned>(st.wHour),
				static_cast<unsigned>(st.wMinute),
				static_cast<unsigned>(st.wSecond),
				static_cast<unsigned>(st.wMilliseconds));
		}

		HANDLE open_log_file() {
			return CreateFileA(
				log_path(),
				FILE_APPEND_DATA | SYNCHRONIZE,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				nullptr,
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				nullptr);
		}

		void write_log_file(HANDLE hf, const std::string& line) {
			if (hf == INVALID_HANDLE_VALUE) return;
			DWORD wrote = 0;
			WriteFile(hf, line.data(), static_cast<DWORD>(line.size()), &wrote, nullptr);
			FlushFileBuffers(hf);
		}

		void push_log(const std::string& line) {
			std::lock_guard<std::mutex> lk(g_log_mtx);
			g_log_lines.push_back(line);
			if (g_log_lines.size() > kMaxLogLines)
				g_log_lines.pop_front();
		}

		void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
			char ts[40];
			format_timestamp(ts, sizeof(ts));

			char detail[1024];
			va_list ap;
			va_start(ap, fmt);
			_vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap);
			va_end(ap);


			char line[1200];
			_snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
			std::string s(line);


			write_log_file(hf, s);


			diag::log_tagged_fmt("test_all", "%s: %s", tag, detail);
			OutputDebugStringA(s.c_str());


			push_log(s);
		}

		std::uint64_t now_ms_tick() {
			return static_cast<std::uint64_t>(GetTickCount64());
		}

		void copy_label_try(std::mutex& mtx, const std::string& value, char* out, std::size_t cap, const char* busy_text) {
			if (cap == 0) return;
			out[0] = '\0';
			if (mtx.try_lock()) {
				_snprintf_s(out, cap, _TRUNCATE, "%s", value.empty() ? "<none>" : value.c_str());
				mtx.unlock();
			} else {
				_snprintf_s(out, cap, _TRUNCATE, "%s", busy_text ? busy_text : "<lock-busy>");
			}
		}

		void format_debug_snapshot_impl(char* out, std::size_t cap) {
			if (out == nullptr || cap == 0) return;

			char phase[192] = {};
			char step[256] = {};
			copy_label_try(g_phase_mtx, g_phase_label, phase, sizeof(phase), "<phase-lock-busy>");
			copy_label_try(g_step_mtx, g_step_label, step, sizeof(step), "<step-lock-busy>");

			const std::uint64_t now = now_ms_tick();
			const std::uint64_t run_start = g_run_start_tick.load(std::memory_order_acquire);
			const std::uint64_t phase_start = g_phase_start_tick.load(std::memory_order_acquire);
			const std::uint64_t step_start = g_step_start_tick.load(std::memory_order_acquire);
			const std::uint64_t run_age = (run_start != 0 && now >= run_start) ? (now - run_start) : 0;
			const std::uint64_t phase_age = (phase_start != 0 && now >= phase_start) ? (now - phase_start) : 0;
			const std::uint64_t step_age = (step_start != 0 && now >= step_start) ? (now - step_start) : 0;

			_snprintf_s(out, cap, _TRUNCATE,
				"run_id=%llu running=%d cancel=%d target_unavailable=%d phase=\"%.160s\" phase_age_ms=%llu "
				"step=\"%.220s\" step_age_ms=%llu run_age_ms=%llu total=%d current=%d "
				"pass=%d fail=%d skip=%d suspect=%d target_pid=%u driver_attached=%d "
				"image_base=0x%016llX target_addr=0x%016llX saved_dtb=0x%016llX",
				static_cast<unsigned long long>(g_run_id.load(std::memory_order_acquire)),
				g_running.load(std::memory_order_acquire) ? 1 : 0,
				g_cancel_requested.load(std::memory_order_acquire) ? 1 : 0,
				g_target_unavailable.load(std::memory_order_acquire) ? 1 : 0,
				phase,
				static_cast<unsigned long long>(phase_age),
				step,
				static_cast<unsigned long long>(step_age),
				static_cast<unsigned long long>(run_age),
				g_total.load(std::memory_order_acquire),
				g_current.load(std::memory_order_acquire),
				g_passed.load(std::memory_order_acquire),
				g_failed.load(std::memory_order_acquire),
				g_skipped.load(std::memory_order_acquire),
				g_suspect.load(std::memory_order_acquire),
				g_target_pid.load(std::memory_order_acquire),
				g_driver_attached.load(std::memory_order_acquire) ? 1 : 0,
				static_cast<unsigned long long>(g_target_image_base.load(std::memory_order_acquire)),
				static_cast<unsigned long long>(g_target_addr.load(std::memory_order_acquire)),
				static_cast<unsigned long long>(g_saved_dtb.load(std::memory_order_acquire)));
		}

		void log_debug_snapshot(HANDLE hf, const char* tag, const char* prefix) {
			char snap[1200] = {};
			format_debug_snapshot_impl(snap, sizeof(snap));
			log_msg(hf, tag ? tag : "snapshot", "%s%s%s",
				prefix ? prefix : "snapshot",
				(prefix && *prefix) ? " | " : "",
				snap);
		}

		void set_full_test_env(HANDLE hf, bool enabled, const char* reason) {
			BOOL ok = SetEnvironmentVariableA(kFullTestEnvName, enabled ? "1" : nullptr);
			DWORD err = ok ? 0UL : GetLastError();
			log_msg(hf, "env", "%s %s ok=%d err=%lu",
				enabled ? "set" : "clear",
				kFullTestEnvName,
				ok ? 1 : 0,
				static_cast<unsigned long>(err));
			diag::log_tagged_fmt("test_all", "%s %s reason=%s ok=%d err=%lu",
				enabled ? "set" : "clear",
				kFullTestEnvName,
				reason ? reason : "",
				ok ? 1 : 0,
				static_cast<unsigned long>(err));
		}

		void set_step(const char* label) {
			{
				std::lock_guard<std::mutex> lk(g_step_mtx);
				g_step_label = (label != nullptr) ? label : "";
			}
			g_step_start_tick.store(now_ms_tick(), std::memory_order_release);
		}

		void set_stepf(const char* fmt, ...) {
			char detail[256];
			va_list ap;
			va_start(ap, fmt);
			_vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap);
			va_end(ap);
			set_step(detail);
		}

		void cleanup_network_runtime(HANDLE hf, const char* reason) {
			set_stepf("network cleanup: %s", reason ? reason : "unspecified");
			log_debug_snapshot(hf, "net-cleanup", "ENTRY");
			bool proxy_running = mitm_proxy::is_running();
			log_msg(hf, "net-cleanup", "local MITM proxy running=%d before cleanup (%s)",
				proxy_running ? 1 : 0, reason ? reason : "unspecified");
			if (proxy_running) {
				mitm_proxy::drop_all();
				mitm_proxy::stop();
				log_msg(hf, "net-cleanup", "local MITM proxy stop/drop attempted; running=%d",
					mitm_proxy::is_running() ? 1 : 0);
			}

			if (!device || !device->is_connected()) {
				log_msg(hf, "net-cleanup", "SKIP -- driver not connected (%s)",
					reason ? reason : "unspecified");
				log_debug_snapshot(hf, "net-cleanup", "EXIT skipped");
				return;
			}

			log_msg(hf, "net-cleanup", "BEGIN -- clearing stateful WFP/test modes (%s)",
				reason ? reason : "unspecified");

			auto send_cleanup = [&](const char* name, DWORD code, void* req, std::size_t size) {
				std::uint32_t bytes_returned = 0;
				bool ok = device->send_ioctl_raw(code, req, static_cast<std::uint32_t>(size), bytes_returned);
				log_msg(hf, "net-cleanup", "%s ok=%d bytes=%u",
					name, ok ? 1 : 0, bytes_returned);
			};

			voyager::detail::net_cap_ctrl_request cap{};
			cap.operation = 1u;
			send_cleanup("NCAP stop", ioctl_codes::NCAP(), &cap, sizeof(cap));

			voyager::detail::intercept_request ihld{};
			ihld.operation = 1u;
			send_cleanup("IHLD stop+drop-held", ioctl_codes::IHLD(), &ihld, sizeof(ihld));

			voyager::detail::net_filter_rule_request filter{};
			filter.operation = 2u;
			send_cleanup("NFLT clear", ioctl_codes::NFLT(), &filter, sizeof(filter));

			bool mod_clear = driver_bridge::packet_mod_rule_op(3);
			log_msg(hf, "net-cleanup", "PMOD clear ok=%d", mod_clear ? 1 : 0);

			bool redir_clear = driver_bridge::traffic_redirect_op(3);
			log_msg(hf, "net-cleanup", "PRED clear ok=%d", redir_clear ? 1 : 0);

			bool stream_clear = driver_bridge::stream_reassemble_op(4);
			log_msg(hf, "net-cleanup", "STRM clear ok=%d", stream_clear ? 1 : 0);

			voyager::detail::dns_spoof_rule dns{};
			dns.operation = 3u;
			send_cleanup("DNSS clear", ioctl_codes::DNSS(), &dns, sizeof(dns));

			voyager::detail::net_fingerprint_request fp{};
			fp.operation = 1u;
			send_cleanup("NFPR stop", ioctl_codes::NFPR(), &fp, sizeof(fp));

			voyager::detail::bw_monitor_request bw{};
			bw.operation = 1u;
			send_cleanup("BWMN stop", ioctl_codes::BWMN(), &bw, sizeof(bw));
			bw = {};
			bw.operation = 3u;
			send_cleanup("BWMN reset", ioctl_codes::BWMN(), &bw, sizeof(bw));

			log_msg(hf, "net-cleanup", "END -- stateful network cleanup attempted");
			log_debug_snapshot(hf, "net-cleanup", "EXIT");
		}

		void set_phase(const char* label) {
			std::lock_guard<std::mutex> lk(g_phase_mtx);
			g_phase_label = (label != nullptr) ? label : "";
			g_phase_start_tick.store(now_ms_tick(), std::memory_order_release);
		}

		bool cancelled() {
			return g_cancel_requested.load(std::memory_order_acquire);
		}

		int running_done() {
			return g_passed.load() + g_failed.load() + g_skipped.load();
		}

		bool memory_scanner_scan_idle() {
			auto& st = memory_scanner::g_state;
			return !st.scanning.load(std::memory_order_acquire) &&
				st.scan_thread_done.load(std::memory_order_acquire);
		}

		bool memory_scanner_all_idle() {
			auto& st = memory_scanner::g_state;
			return memory_scanner_scan_idle() &&
				!st.pointer_scanning.load(std::memory_order_acquire) &&
				st.pointer_thread_done.load(std::memory_order_acquire);
		}

		void request_memory_scanner_stop() {
			auto& st = memory_scanner::g_state;
			st.scanning.store(false, std::memory_order_release);
			st.pointer_scanning.store(false, std::memory_order_release);
		}

		bool wait_memory_scanner_scan_idle(DWORD timeout_ms) {
			const std::uint64_t deadline = now_ms_tick() + timeout_ms;
			while (!memory_scanner_scan_idle()) {
				if (now_ms_tick() >= deadline) return memory_scanner_scan_idle();
				Sleep(10);
			}
			return true;
		}

		bool wait_memory_scanner_all_idle(DWORD timeout_ms) {
			const std::uint64_t deadline = now_ms_tick() + timeout_ms;
			while (!memory_scanner_all_idle()) {
				if (now_ms_tick() >= deadline) return memory_scanner_all_idle();
				Sleep(10);
			}
			return true;
		}

		bool snapshot_memory_scan_results(std::size_t& found, std::uint64_t& first_addr, DWORD timeout_ms) {
			auto& st = memory_scanner::g_state;
			const std::uint64_t deadline = now_ms_tick() + timeout_ms;
			for (;;) {
				try {
					if (st.results_mutex.try_lock()) {
						std::lock_guard<std::mutex> lk(st.results_mutex, std::adopt_lock);
						found = st.results.size();
						first_addr = st.results.empty() ? 0 : st.results.front().address;
						return true;
					}
				} catch (...) {
					return false;
				}
				if (now_ms_tick() >= deadline) return false;
				Sleep(5);
			}
		}

		void cleanup_memory_scanner_runtime(HANDLE hf, const char* reason, DWORD timeout_ms) {
			auto& st = memory_scanner::g_state;
			const bool active =
				st.scanning.load(std::memory_order_acquire) ||
				!st.scan_thread_done.load(std::memory_order_acquire) ||
				st.pointer_scanning.load(std::memory_order_acquire) ||
				!st.pointer_thread_done.load(std::memory_order_acquire);
			if (!active) return;

			log_msg(hf, "memscan-cleanup",
				"BEGIN -- %s scanning=%d scan_done=%d pointer_scanning=%d pointer_done=%d",
				reason ? reason : "unspecified",
				st.scanning.load(std::memory_order_acquire) ? 1 : 0,
				st.scan_thread_done.load(std::memory_order_acquire) ? 1 : 0,
				st.pointer_scanning.load(std::memory_order_acquire) ? 1 : 0,
				st.pointer_thread_done.load(std::memory_order_acquire) ? 1 : 0);

			request_memory_scanner_stop();
			const bool idle = wait_memory_scanner_all_idle(timeout_ms);

			log_msg(hf, "memscan-cleanup",
				"END -- %s idle=%d scanning=%d scan_done=%d pointer_scanning=%d pointer_done=%d",
				reason ? reason : "unspecified",
				idle ? 1 : 0,
				st.scanning.load(std::memory_order_acquire) ? 1 : 0,
				st.scan_thread_done.load(std::memory_order_acquire) ? 1 : 0,
				st.pointer_scanning.load(std::memory_order_acquire) ? 1 : 0,
				st.pointer_thread_done.load(std::memory_order_acquire) ? 1 : 0);
		}

		void log_phase_begin(HANDLE hf, const char* phase) {
			log_msg(hf, "phase", "BEGIN %s | running totals pass=%d fail=%d skip=%d done=%d",
				phase, g_passed.load(), g_failed.load(), g_skipped.load(), running_done());
			log_debug_snapshot(hf, "phase", "BEGIN snapshot");
		}

		void log_phase_end(HANDLE hf, const char* phase) {
			log_msg(hf, "phase", "END %s | running totals pass=%d fail=%d skip=%d done=%d",
				phase, g_passed.load(), g_failed.load(), g_skipped.load(), running_done());
			log_debug_snapshot(hf, "phase", "END snapshot");
		}

		bool target_unavailable() {
			return g_target_unavailable.load(std::memory_order_acquire);
		}

		void mark_target_unavailable(HANDLE hf, const char* tag, const char* reason, std::uint32_t pid, std::uint32_t attached, std::uint32_t exit_code) {
			g_driver_attached.store(false, std::memory_order_release);
			g_target_unavailable.store(true, std::memory_order_release);
			log_msg(hf, tag ? tag : "target-live", "TARGET-UNAVAILABLE -- %s pid=%u attached=%u exit_code_or_err=0x%08X",
				reason ? reason : "target unavailable",
				pid,
				attached,
				exit_code);
		}

		void skip_phase_target_unavailable(HANDLE hf, const char* phase, int tests) {
			const char* label = phase ? phase : "target-dependent phase";
			set_phase(label);
			set_stepf("skip phase: %s", label);
			log_phase_begin(hf, label);
			if (tests > 0)
				g_skipped.fetch_add(tests);
			log_msg(hf, "phase", "SKIP -- %s requires a live attached target; target unavailable; skipped=%d",
				label,
				tests);
			log_phase_end(hf, label);
		}


		bool is_destructive(const char* category, const char* name) {
			if (category == nullptr || name == nullptr) return false;
			struct destructive_feature_t {
				const char* category;
				const char* name;
				const char* reason;
			};
			static const destructive_feature_t kSkip[] = {
				{ "tamper", "ABRT", "kernel tamper abort can bugcheck" },
				{ "evidence", "RECU", "kernel evidence recovery can bugcheck" },
				{ "remote-call", "RC", "executes a target-process remote call" },
				{ "thread", "TSR", "suspends or resumes a target thread" },
				{ "module", "PINJ", "injects a transport-layer packet" },
				{ "anti-debug", "DBGA", "debug-attach evidence path may bugcheck on positive detection" }
			};
			for (const auto& s : kSkip) {
				if (std::strcmp(category, s.category) == 0 && std::strcmp(name, s.name) == 0) return true;
			}
			return false;
		}

		const char* destructive_reason(const char* category, const char* name) {
			if (category == nullptr || name == nullptr) return "unknown destructive guard";
			if (std::strcmp(category, "tamper") == 0 && std::strcmp(name, "ABRT") == 0) return "kernel tamper abort can bugcheck";
			if (std::strcmp(category, "evidence") == 0 && std::strcmp(name, "RECU") == 0) return "kernel evidence recovery can bugcheck";
			if (std::strcmp(category, "remote-call") == 0 && std::strcmp(name, "RC") == 0) return "executes a target-process remote call";
			if (std::strcmp(category, "thread") == 0 && std::strcmp(name, "TSR") == 0) return "suspends or resumes a target thread";
			if (std::strcmp(category, "module") == 0 && std::strcmp(name, "PINJ") == 0) return "injects a transport-layer packet";
			if (std::strcmp(category, "anti-debug") == 0 && std::strcmp(name, "DBGA") == 0) return "debug-attach evidence path may bugcheck on positive detection";
			return "unknown destructive guard";
		}

		bool name_starts_with(const char* name, const char* prefix) {
			if (name == nullptr || prefix == nullptr) return false;
			return std::strncmp(name, prefix, std::strlen(prefix)) == 0;
		}


		std::uint32_t current_target_pid() {
			return g_target_pid.load(std::memory_order_acquire);
		}

		std::uint64_t current_target_addr() {
			return g_target_addr.load(std::memory_order_acquire);
		}

		std::uint64_t current_target_image_base() {
			return g_target_image_base.load(std::memory_order_acquire);
		}

		bool verify_target_liveness(HANDLE hf, const char* checkpoint, bool abort_on_dead = true) {
			(void)abort_on_dead;
			const std::uint32_t pid = current_target_pid();
			if (pid == 0) {
				g_target_unavailable.store(true, std::memory_order_release);
				log_msg(hf, "target-live", "SKIP -- no target pid at %s",
					checkpoint ? checkpoint : "checkpoint");
				return false;
			}

			std::uint32_t attached = driver_bridge::attached_pid();
			if (attached != pid) {
				const bool reattached = driver_bridge::attach(pid);
				log_msg(hf, "target-live", "reattach attempt at %s target_pid=%u previous_attached=%u ok=%d status=\"%s\" last_error=\"%s\"",
					checkpoint ? checkpoint : "checkpoint",
					pid,
					attached,
					reattached ? 1 : 0,
					driver_bridge::status().c_str(),
					driver_bridge::last_error().c_str());
				attached = driver_bridge::attached_pid();
			}

			std::uint32_t exit_code = 0;
			const bool alive = (attached == pid) && driver_bridge::attached_process_alive(&exit_code);
			if (alive) {
				g_driver_attached.store(true, std::memory_order_release);
				g_target_unavailable.store(false, std::memory_order_release);
				log_msg(hf, "target-live", "OK -- target alive at %s pid=%u attached=%u exit_code=0x%08X",
					checkpoint ? checkpoint : "checkpoint", pid, attached, exit_code);
				return true;
			}

			g_failed.fetch_add(1);
			mark_target_unavailable(hf, "target-live", "target is not alive; target-dependent phases will be skipped", pid, attached, exit_code);
			log_msg(hf, "target-live", "FAIL -- target is not alive at %s pid=%u attached=%u exit_code_or_err=0x%08X",
				checkpoint ? checkpoint : "checkpoint",
				pid,
				attached,
				exit_code);
			log_debug_snapshot(hf, "target-live", "DEAD target snapshot");
			return false;
		}


		void populate_defaults(test_lab::state_t& s, std::uint32_t target_pid) {
			s.pid = target_pid;
			s.tid = 0;
			s.addr = current_target_addr();
			s.size = 64;
			s.u32_a = 0;
			s.u32_b = 0;
			s.u64_a = 0;
			s.buf.clear();
			s.text_a = "ntdll.dll";
			s.text_b = "127.0.0.1";
			s.user = nullptr;

			if (target_pid != 0) {
				auto threads = driver_bridge::enumerate_threads_for(target_pid);
				for (const auto& th : threads) {
					if (th.owner_pid == target_pid && th.tid != 0) {
						s.tid = th.tid;
						break;
					}
				}
			}
		}


		bool probe_candidate(HANDLE hf, const std::wstring& candidate, const char* label) {
			char narrow[MAX_PATH] = {};
			WideCharToMultiByte(CP_UTF8, 0, candidate.c_str(), -1, narrow, MAX_PATH, nullptr, nullptr);
			bool exists = (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES);
			log_msg(hf, "find_target", "probe[%s] %s -> %s", label, narrow, exists ? "EXISTS" : "missing");
			diag::log_tagged_fmt("test_all", "find_test_target probe[%s] %s -> %s",
				label, narrow, exists ? "EXISTS" : "missing");
			return exists;
		}


		std::wstring find_test_target(HANDLE hf) {
			wchar_t self[MAX_PATH] = {};
			GetModuleFileNameW(nullptr, self, MAX_PATH);
			std::wstring module_dir(self);
			auto pos = module_dir.find_last_of(L"\\/");
			if (pos != std::wstring::npos) module_dir.resize(pos + 1);

			wchar_t cwd[MAX_PATH] = {};
			DWORD cwd_len = GetCurrentDirectoryW(MAX_PATH, cwd);
			std::wstring cwd_dir;
			if (cwd_len > 0 && cwd_len < MAX_PATH) {
				cwd_dir.assign(cwd, cwd_len);
				if (!cwd_dir.empty() && cwd_dir.back() != L'\\' && cwd_dir.back() != L'/')
					cwd_dir.push_back(L'\\');
			}

			wchar_t env_buf[MAX_PATH] = {};
			DWORD env_len = GetEnvironmentVariableW(L"AIDA_TEST_TARGET", env_buf, MAX_PATH);
			if (env_len > 0 && env_len < MAX_PATH) {
				std::wstring env_path(env_buf, env_len);
				if (probe_candidate(hf, env_path, "AIDA_TEST_TARGET"))
					return env_path;
			} else {
				log_msg(hf, "find_target", "probe[AIDA_TEST_TARGET] env var not set");
			}

			const std::wstring module_candidate = module_dir + L"AiDA_TestTarget.exe";
			if (probe_candidate(hf, module_candidate, "module_dir"))
				return module_candidate;

			const std::wstring module_subdir_candidate = module_dir + L"test_target\\AiDA_TestTarget.exe";
			if (probe_candidate(hf, module_subdir_candidate, "module_dir/test_target"))
				return module_subdir_candidate;

			if (!cwd_dir.empty()) {
				const std::wstring cwd_candidate = cwd_dir + L"AiDA_TestTarget.exe";
				if (probe_candidate(hf, cwd_candidate, "cwd"))
					return cwd_candidate;
			} else {
				log_msg(hf, "find_target", "probe[cwd] working directory unavailable");
			}

			const std::wstring fallback = L"C:\\Users\\ruar1337\\AiDAPrivate\\build-ninja\\Release\\AiDA_TestTarget.exe";
			if (probe_candidate(hf, fallback, "fallback"))
				return fallback;

			log_msg(hf, "find_target", "FAIL -- AiDA_TestTarget.exe not found in any candidate path");
			return {};
		}


		bool verify_driver_attach(HANDLE hf, std::uint32_t pid) {
			set_phase("Verifying driver attach");

			bool kernel = driver_bridge::using_kernel_driver();
			bool can_read = driver_bridge::can_read_memory();
			std::uint32_t attached = driver_bridge::attached_pid();
			std::string drv_status = driver_bridge::status();
			std::string drv_err = driver_bridge::last_error();

			log_msg(hf, "attach", "driver status=\"%s\" using_kernel_driver=%d can_read_memory=%d attached_pid=%u target_pid=%u",
				drv_status.c_str(), static_cast<int>(kernel), static_cast<int>(can_read), attached, pid);

			if (attached == 0 || attached != pid) {
				log_msg(hf, "attach", "FAIL -- driver attached_pid=%u does not match target pid=%u (last_error=\"%s\")",
					attached, pid, drv_err.c_str());
				g_driver_attached.store(false, std::memory_order_release);
				g_failed.fetch_add(1);
				return false;
			}

			auto modules = driver_bridge::enumerate_modules_for(pid);
			std::uint64_t exe_base = 0;
			std::string image_name;
			std::uint64_t ntdll_base = 0;
			for (const auto& m : modules) {
				if (m.name.empty()) continue;
				const char* dot = std::strrchr(m.name.c_str(), '.');
				bool is_exe = (dot != nullptr) && (_stricmp(dot, ".exe") == 0);
				if (is_exe && exe_base == 0) {
					exe_base = m.base;
					image_name = m.name;
				}
				if (ntdll_base == 0 && _stricmp(m.name.c_str(), "ntdll.dll") == 0)
					ntdll_base = m.base;
			}

			std::uint64_t image_base = exe_base;

			driver_bridge::peb_info_t peb{};
			if (driver_bridge::read_peb_for(pid, peb) && peb.image_base != 0) {
				image_base = peb.image_base;
				log_msg(hf, "attach", "PEB image_base=0x%016llX peb=0x%016llX",
					static_cast<unsigned long long>(peb.image_base),
					static_cast<unsigned long long>(peb.peb_address));
			}

			if (image_base == 0) {
				log_msg(hf, "attach", "FAIL -- could not resolve target image base (modules=%zu)", modules.size());
				g_driver_attached.store(false, std::memory_order_release);
				g_failed.fetch_add(1);
				return false;
			}

			log_msg(hf, "attach", "target image base=0x%016llX module=\"%s\" modules_enumerated=%zu",
				static_cast<unsigned long long>(image_base),
				image_name.empty() ? "<unknown>" : image_name.c_str(),
				modules.size());

			std::vector<std::uint8_t> sample;
			bool read_ok = driver_bridge::read_memory_for(pid, image_base, 64, sample);
			if (!read_ok || sample.size() < 2) {
				log_msg(hf, "attach", "FAIL -- sanity read of image base returned %zu bytes (read_ok=%d last_error=\"%s\")",
					sample.size(), static_cast<int>(read_ok), driver_bridge::last_error().c_str());
				g_driver_attached.store(false, std::memory_order_release);
				g_failed.fetch_add(1);
				return false;
			}

			std::uint16_t mz = static_cast<std::uint16_t>(sample[0]) |
				(static_cast<std::uint16_t>(sample[1]) << 8);
			bool is_mz = (mz == 0x5A4D);

			log_msg(hf, "attach", "sanity read OK bytes=%zu first4=%02X %02X %02X %02X mz=0x%04X (%s)",
				sample.size(),
				sample[0], sample[1],
				sample.size() > 2 ? sample[2] : 0,
				sample.size() > 3 ? sample[3] : 0,
				static_cast<unsigned>(mz),
				is_mz ? "MZ valid" : "NOT MZ");

			if (!is_mz) {
				log_msg(hf, "attach", "FAIL -- target image base does not start with MZ header (driver read suspect)");
				g_driver_attached.store(false, std::memory_order_release);
				g_failed.fetch_add(1);
				return false;
			}

			std::uint64_t fn_addr = 0;
			if (ntdll_base != 0) {
				fn_addr = driver_bridge::resolve_export(ntdll_base, "NtClose");
				log_msg(hf, "attach", "resolved target ntdll.dll base=0x%016llX NtClose=0x%016llX",
					static_cast<unsigned long long>(ntdll_base),
					static_cast<unsigned long long>(fn_addr));
			} else {
				log_msg(hf, "attach", "WARN -- ntdll.dll not found in target module list (functions defaulting to image base)");
			}

			g_target_image_base.store(image_base, std::memory_order_release);
			g_target_addr.store(fn_addr != 0 ? fn_addr : image_base, std::memory_order_release);
			g_driver_attached.store(true, std::memory_order_release);

			log_msg(hf, "attach", "PASS -- driver attach VERIFIED to pid=%u image_base=0x%016llX known_good_addr=0x%016llX",
				pid,
				static_cast<unsigned long long>(image_base),
				static_cast<unsigned long long>(current_target_addr()));
			g_passed.fetch_add(1);
			return true;
		}


		bool phase_launch_target(HANDLE hf, std::uint32_t& out_pid) {
			set_phase("Launch AiDA_TestTarget.exe");
			log_phase_begin(hf, "launch target");
			log_msg(hf, "launch", "searching for AiDA_TestTarget.exe ...");

			std::wstring exe = find_test_target(hf);
			if (exe.empty()) {
				log_msg(hf, "launch", "FAIL -- AiDA_TestTarget.exe not found; downstream feature tests will run with no attached target");
				g_failed.fetch_add(1);
				log_phase_end(hf, "launch target");
				return false;
			}

			char narrow[MAX_PATH] = {};
			WideCharToMultiByte(CP_UTF8, 0, exe.c_str(), -1, narrow, MAX_PATH, nullptr, nullptr);
			log_msg(hf, "launch", "found: %s", narrow);

			auto t0 = std::chrono::steady_clock::now();


			std::wstring work_dir = exe;
			auto slash = work_dir.find_last_of(L"\\/");
			if (slash != std::wstring::npos) work_dir.resize(slash);

			std::uint32_t pid = 0;
			set_step("launch: spawn_and_attach_target");
			log_debug_snapshot(hf, "launch", "BEFORE spawn_and_attach_target");
			BOOL env_ok = SetEnvironmentVariableA("AIDA_TARGET_LOG_PATH", log_path());
			log_msg(hf, "launch", "set AIDA_TARGET_LOG_PATH ok=%d err=%lu path=%s",
				env_ok ? 1 : 0,
				env_ok ? 0UL : static_cast<unsigned long>(GetLastError()),
				log_path());
			log_msg(hf, "launch", "target args: %s", kTargetArgsText);
			bool ok = debugger_engine::spawn_and_attach_target(exe, kTargetArgsWide, work_dir, &pid);
			DWORD spawn_gle = GetLastError();
			SetEnvironmentVariableA("AIDA_TARGET_LOG_PATH", nullptr);

			auto t1 = std::chrono::steady_clock::now();
			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
			log_msg(hf, "launch", "spawn_and_attach_target returned ok=%d pid=%u elapsed=%lld ms gle=%lu driver_status=\"%s\" driver_last_error=\"%s\"",
				ok ? 1 : 0,
				pid,
				(long long)ms,
				static_cast<unsigned long>(spawn_gle),
				driver_bridge::status().c_str(),
				driver_bridge::last_error().c_str());
			log_debug_snapshot(hf, "launch", "AFTER spawn_and_attach_target");

			if (!ok || pid == 0) {
				log_msg(hf, "launch", "FAIL -- spawn_and_attach_target returned false pid=%u (elapsed %lld ms) last_error=\"%s\"",
					pid, (long long)ms, driver_bridge::last_error().c_str());
				g_failed.fetch_add(1);
				log_phase_end(hf, "launch target");
				return false;
			}

			out_pid = pid;
			g_target_pid.store(pid, std::memory_order_release);
			log_msg(hf, "launch", "spawn_and_attach_target returned true pid=%u (elapsed %lld ms)", pid, (long long)ms);


			set_phase("Waiting for test_target READY");
			log_msg(hf, "launch", "waiting for WhosWhoTestReady event (8s timeout) ...");

			HANDLE hReady = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\WhosWhoTestReady");
			DWORD global_ready_err = hReady ? 0 : GetLastError();
			log_msg(hf, "launch", "OpenEvent Global\\WhosWhoTestReady handle=%p err=%lu",
				hReady, static_cast<unsigned long>(global_ready_err));
			if (!hReady) {
				hReady = OpenEventW(SYNCHRONIZE, FALSE, L"Local\\WhosWhoTestReady");
				log_msg(hf, "launch", "OpenEvent Local\\WhosWhoTestReady handle=%p err=%lu",
					hReady, static_cast<unsigned long>(hReady ? 0 : GetLastError()));
			}
			if (hReady) {
				set_step("launch: wait READY event");
				DWORD wait = WaitForSingleObject(hReady, 8000);
				DWORD wait_err = (wait == WAIT_FAILED) ? GetLastError() : 0;
				CloseHandle(hReady);
				if (wait == WAIT_OBJECT_0) {
					log_msg(hf, "launch", "READY event signaled wait=0x%08lX", static_cast<unsigned long>(wait));
				} else {
					DWORD exit_code = STILL_ACTIVE;
					HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
					BOOL got_exit = hp ? GetExitCodeProcess(hp, &exit_code) : FALSE;
					DWORD hp_err = hp ? 0 : GetLastError();
					if (hp) CloseHandle(hp);
					log_msg(hf, "launch", "READY wait did not signal wait=0x%08lX wait_err=%lu child_handle=%s child_exit_known=%d exit_code=0x%08lX open_err=%lu (proceeding anyway)",
						static_cast<unsigned long>(wait),
						static_cast<unsigned long>(wait_err),
						hp ? "opened" : "null",
						got_exit ? 1 : 0,
						static_cast<unsigned long>(exit_code),
						static_cast<unsigned long>(hp_err));
				}
			} else {
				log_msg(hf, "launch", "could not open READY event handle, sleeping 3s");
				Sleep(3000);
			}

			bool attach_ok = verify_driver_attach(hf, pid);
			if (!attach_ok) {
				log_msg(hf, "launch", "FAIL -- driver attach verification failed for pid=%u; feature tests cannot trust target reads", pid);
			} else {
				log_msg(hf, "launch", "PASS -- target launched and driver attach verified pid=%u", pid);
			}

			log_phase_end(hf, "launch target");
			return attach_ok;
		}

		DWORD run_testlab_feature_seh(test_lab::run_fn fn, test_lab::state_t& s, test_lab::result_t& r) {
			__try {
				fn(s, r);
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				return GetExceptionCode();
			}
			return 0;
		}


		void phase_testlab_features(HANDLE hf, std::uint32_t target_pid) {
			set_phase("Test Lab features");
			log_phase_begin(hf, "testlab features");
			const auto& features = test_lab::all_features();
			int total = static_cast<int>(features.size());
			log_msg(hf, "testlab", "running %d registered features against target pid=%u ...", total, target_pid);

			if (target_pid == 0) {
				log_msg(hf, "testlab", "WARN -- no attached target pid; testlab features run with pid=0 and are expected to fail/skip");
			}

			for (int i = 0; i < total; ++i) {
				if (cancelled()) {
					log_msg(hf, "testlab", "cancelled by user");
					break;
				}

				const auto& f = features[static_cast<std::size_t>(i)];
				g_current.store(i + 1);

				const char* name = (f.name != nullptr) ? f.name : "?";
				const char* cat  = (f.category != nullptr) ? f.category : "?";

				if (is_destructive(f.category, f.name)) {
					const int before = g_skipped.load(std::memory_order_acquire);
					const int after = g_skipped.fetch_add(1, std::memory_order_acq_rel) + 1;
					log_msg(hf, "testlab", "[%d/%d] SKIP %s/%s (destructive guard reason=\"%s\" skip_before=%d skip_after=%d)",
						i + 1, total, cat, name, destructive_reason(f.category, f.name), before, after);
					continue;
				}
				if (f.run == nullptr) {
					log_msg(hf, "testlab", "[%d/%d] FAIL %s/%s (no run fn)", i + 1, total, cat, name);
					g_failed.fetch_add(1);
					continue;
				}

				test_lab::state_t s;
				populate_defaults(s, target_pid);
				std::uint64_t cleanup_alloc = 0;

				if (name_starts_with(name, "PMOD")) {
					s.u32_a = 2;
				} else if (name_starts_with(name, "PRED")) {
					s.u32_a = 1;
				} else if (name_starts_with(name, "NLOG")) {
					s.u32_a = 1;
				} else if (name_starts_with(name, "NCAP")) {
					s.u32_a = 1;
					s.pid = target_pid;
				} else if (name_starts_with(name, "NFLT")) {
					s.u32_a = 3;
				} else if (name_starts_with(name, "IHLD")) {
					s.u32_a = 2;
					s.pid = target_pid;
				} else if (name_starts_with(name, "NFPR")) {
					s.u32_b = 2;
				} else if (name_starts_with(name, "DNSS")) {
					s.u32_a = 1;
				} else if (name_starts_with(name, "BWMN")) {
					s.u32_a = 2;
				} else if (name_starts_with(name, "REGISTER_PID") || name_starts_with(name, "UNREGISTER_PID")) {
					char tmp[MAX_PATH];
					GetTempPathA(MAX_PATH, tmp);
					s.text_a = std::string(tmp) + "aida_sandbox_test";
					if (s.pid == 0) {
						s.pid = static_cast<std::uint32_t>(GetCurrentProcessId());
					}
				} else if (name_starts_with(name, "PCEX")) {
					char tmp[MAX_PATH];
					GetTempPathA(MAX_PATH, tmp);
					s.text_a = std::string(tmp) + "aida_test_capture.pcap";
				} else if (name_starts_with(name, "ADMP")) {
					s.u32_a = 4;
					s.pid = 0;
				} else if (name_starts_with(name, "SRVT")) {
					s.text_a = "00112233445566778899AABBCCDDEEFF";
				} else if (name_starts_with(name, "SRV2")) {
					s.text_a = "00112233445566778899AABBCCDDEEFF";
					s.u32_a = 1;
				} else if (name_starts_with(name, "CANR")) {
					static std::uint8_t canary_scratch[0x1000];
					s.addr = reinterpret_cast<std::uint64_t>(&canary_scratch[0]);
					s.size = sizeof(canary_scratch);
					s.u32_a = 0;
				} else if (name_starts_with(name, "FM")) {
					std::uint64_t alloc = driver_bridge::allocate_memory(0x1000);
					if (alloc != 0) {
						s.addr = alloc;
						s.size = 0x1000;
						cleanup_alloc = alloc;
						log_msg(hf, "testlab", "[%d/%d] memory-fixture %s: allocated target page 0x%016llX for free validation",
							i + 1, total, name, static_cast<unsigned long long>(alloc));
					} else {
						log_msg(hf, "testlab", "[%d/%d] memory-fixture %s: WARN allocate_memory failed; using default addr=0x%016llX",
							i + 1, total, name, static_cast<unsigned long long>(s.addr));
					}
				} else if (name_starts_with(name, "PM")) {
					std::uint64_t alloc = driver_bridge::allocate_memory(0x1000);
					if (alloc != 0) {
						s.addr = alloc;
						s.size = 0x1000;
						s.u32_a = PAGE_READWRITE;
						cleanup_alloc = alloc;
						log_msg(hf, "testlab", "[%d/%d] memory-fixture %s: allocated target page 0x%016llX protect=0x%08X",
							i + 1, total, name, static_cast<unsigned long long>(alloc), s.u32_a);
					} else {
						s.u32_a = PAGE_READWRITE;
						log_msg(hf, "testlab", "[%d/%d] memory-fixture %s: WARN allocate_memory failed; using default addr=0x%016llX protect=0x%08X",
							i + 1, total, name, static_cast<unsigned long long>(s.addr), s.u32_a);
					}
				} else if (name_starts_with(name, "PHYS") || name_starts_with(name, "MEX") || name_starts_with(name, "V2P")) {
					std::uint64_t saved = g_saved_dtb.load(std::memory_order_acquire);
					if (saved != 0) {
						s.u64_a = saved;
						log_msg(hf, "testlab", "[%d/%d] DTB-inject %s: injecting saved_dtb=0x%016llX into u64_a",
							i + 1, total, name, static_cast<unsigned long long>(saved));
					} else {
						log_msg(hf, "testlab", "[%d/%d] DTB-inject %s: WARN no saved dtb (u64_a=0); test may fail",
							i + 1, total, name);
					}
					if (name_starts_with(name, "MEX")) {
						for (const auto& mod : driver_bridge::enumerate_modules_for(target_pid)) {
							if (_stricmp(mod.name.c_str(), "ntdll.dll") == 0) {
								s.addr = mod.base;
								s.text_a = mod.name;
								s.text_b = "NtClose";
								log_msg(hf, "testlab", "[%d/%d] MEX-fixture: module=%s base=0x%016llX export=%s",
									i + 1, total, mod.name.c_str(),
									static_cast<unsigned long long>(mod.base), s.text_b.c_str());
								break;
							}
						}
					}
				}

				test_lab::result_t r;

				log_msg(hf, "testlab", "[%d/%d] START %s/%s pid=%u tid=%u addr=0x%016llX u64_a=0x%016llX u32_a=%u u32_b=%u size=%u text_a=\"%.32s\"",
					i + 1, total, cat, name, s.pid, s.tid,
					static_cast<unsigned long long>(s.addr),
					static_cast<unsigned long long>(s.u64_a),
					s.u32_a, s.u32_b, s.size,
					s.text_a.empty() ? "(none)" : s.text_a.c_str());
				set_stepf("testlab %d/%d %s/%s", i + 1, total, cat, name);
				auto t0 = std::chrono::steady_clock::now();
				DWORD seh_code = 0;
				bool cpp_exception = false;
				std::string cpp_error;
				try {
					seh_code = run_testlab_feature_seh(f.run, s, r);
				} catch (const std::exception& ex) {
					cpp_exception = true;
					cpp_error = ex.what();
				} catch (...) {
					cpp_exception = true;
					cpp_error = "unknown C++ exception";
				}
				auto t1 = std::chrono::steady_clock::now();
				auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
				if (r.elapsed_us == 0) r.elapsed_us = static_cast<std::uint64_t>(us);
				log_msg(hf, "testlab", "[%d/%d] END-RUN %s/%s seh=0x%08lX cpp_exception=%d elapsed=%llu us state=%d ok=%d bytes=%u fields=%zu raw=%zu",
					i + 1, total, cat, name,
					static_cast<unsigned long>(seh_code),
					cpp_exception ? 1 : 0,
					static_cast<unsigned long long>(r.elapsed_us),
					static_cast<int>(r.state.load()),
					r.ok ? 1 : 0,
					r.bytes_returned,
					r.parsed.size(),
					r.raw.size());

				if (seh_code != 0) {
					g_failed.fetch_add(1);
					log_msg(hf, "testlab", "[%d/%d] FAIL %s/%s threw SEH exception 0x%08lX elapsed=%llu us",
						i + 1, total, cat, name,
						static_cast<unsigned long>(seh_code),
						static_cast<unsigned long long>(r.elapsed_us));
					if (cleanup_alloc != 0) {
						bool freed = driver_bridge::free_memory(cleanup_alloc);
						log_msg(hf, "testlab", "[%d/%d] memory-fixture cleanup after SEH addr=0x%016llX freed=%d",
							i + 1, total, static_cast<unsigned long long>(cleanup_alloc), freed ? 1 : 0);
					}
					continue;
				}

				if (cpp_exception) {
					g_failed.fetch_add(1);
					log_msg(hf, "testlab", "[%d/%d] FAIL %s/%s threw C++ exception \"%s\" elapsed=%llu us",
						i + 1, total, cat, name,
						cpp_error.c_str(),
						static_cast<unsigned long long>(r.elapsed_us));
					if (cleanup_alloc != 0) {
						bool freed = driver_bridge::free_memory(cleanup_alloc);
						log_msg(hf, "testlab", "[%d/%d] memory-fixture cleanup after C++ exception addr=0x%016llX freed=%d",
							i + 1, total, static_cast<unsigned long long>(cleanup_alloc), freed ? 1 : 0);
					}
					continue;
				}

				if (name_starts_with(name, "DTB") && r.ok) {
					for (const auto& kv : r.parsed) {
						if (kv.label == "CR3 (DTB)") {
							std::uint64_t dtb = std::strtoull(kv.value.c_str(), nullptr, 16);
							if (dtb != 0) {
								g_saved_dtb.store(dtb, std::memory_order_release);
								log_msg(hf, "testlab", "[%d/%d] DTB-save: cr3=0x%016llX saved for PHYS/MEX/V2P tests",
									i + 1, total, static_cast<unsigned long long>(dtb));
							}
							break;
						}
					}
				}

				for (const auto& kv : r.parsed) {
					log_msg(hf, "testlab", "[%d/%d] FIELD %s/%s \"%s\" = \"%s\"",
						i + 1, total, cat, name, kv.label.c_str(), kv.value.c_str());
				}

				if (!r.raw.empty()) {
					char hex_preview[97] = {};
					std::size_t preview_n = std::min(r.raw.size(), std::size_t(16));
					for (std::size_t bi = 0; bi < preview_n; ++bi) {
						std::snprintf(hex_preview + bi * 3, sizeof(hex_preview) - bi * 3, "%02X ", static_cast<unsigned>(r.raw[bi]));
					}
					log_msg(hf, "testlab", "[%d/%d] RAW %s/%s total_bytes=%zu raw_preview=[%s]",
						i + 1, total, cat, name, r.raw.size(), hex_preview);
				}

				if (r.ok) {
					g_passed.fetch_add(1);
					bool target_verified = g_driver_attached.load(std::memory_order_acquire) && target_pid != 0;
					if (!target_verified) {
						g_suspect.fetch_add(1);
						log_msg(hf, "testlab", "[%d/%d] PASS %s/%s SUSPECT (no verified target attach; success may be against host/self) ntstatus=%s bytes=%u elapsed=%llu us",
							i + 1, total, cat, name,
							test_lab_format::ntstatus_to_string(r.ntstatus),
							r.bytes_returned,
							static_cast<unsigned long long>(r.elapsed_us));
					} else {
						log_msg(hf, "testlab", "[%d/%d] PASS %s/%s ntstatus=%s bytes=%u parsed_fields=%zu elapsed=%llu us",
							i + 1, total, cat, name,
							test_lab_format::ntstatus_to_string(r.ntstatus),
							r.bytes_returned,
							r.parsed.size(),
							static_cast<unsigned long long>(r.elapsed_us));
					}
				} else {
					g_failed.fetch_add(1);
					log_msg(hf, "testlab", "[%d/%d] FAIL %s/%s ntstatus=%s error=\"%s\" elapsed=%llu us",
						i + 1, total, cat, name,
						test_lab_format::ntstatus_to_string(r.ntstatus),
						r.error.c_str(),
						static_cast<unsigned long long>(r.elapsed_us));
				}
				if (cleanup_alloc != 0 && (!name_starts_with(name, "FM") || !r.ok)) {
					bool freed = driver_bridge::free_memory(cleanup_alloc);
					log_msg(hf, "testlab", "[%d/%d] memory-fixture cleanup addr=0x%016llX freed=%d",
						i + 1, total, static_cast<unsigned long long>(cleanup_alloc), freed ? 1 : 0);
				}
			}
			log_phase_end(hf, "testlab features");
		}


		bool require_target(HANDLE hf, const char* tag) {
			std::uint32_t pid = current_target_pid();
			bool attached = g_driver_attached.load(std::memory_order_acquire);
			if (pid == 0 || !attached || driver_bridge::attached_pid() != pid) {
				mark_target_unavailable(hf, tag, "no verified attached target", pid, driver_bridge::attached_pid(), 0);
				log_msg(hf, tag, "FAIL -- no verified attached target (pid=%u attached=%d driver_pid=%u)",
					pid, static_cast<int>(attached), driver_bridge::attached_pid());
				g_failed.fetch_add(1);
				return false;
			}
			std::uint32_t exit_code = 0;
			if (!driver_bridge::attached_process_alive(&exit_code)) {
				mark_target_unavailable(hf, tag, "attached target is dead; target-dependent tests will be skipped", pid, driver_bridge::attached_pid(), exit_code);
				log_msg(hf, tag, "FAIL -- attached target pid=%u is dead exit_code_or_err=0x%08X",
					pid, exit_code);
				g_failed.fetch_add(1);
				return false;
			}
			return true;
		}


		void test_disassembly_view(HANDLE hf) {
			const char* tag = "disasm";
			set_phase("Disassembly view");
			log_msg(hf, tag, "START -- decode disassembly window from attached target function");
			auto t0 = std::chrono::steady_clock::now();

			if (!require_target(hf, tag)) return;

			std::uint32_t pid = current_target_pid();
			std::uint64_t addr = current_target_addr();
			if (addr == 0) {
				log_msg(hf, tag, "FAIL -- no known-good target address resolved");
				g_failed.fetch_add(1);
				return;
			}

			log_msg(hf, tag, "requesting disasm refresh at target 0x%016llX (pid=%u)",
				static_cast<unsigned long long>(addr), pid);

			std::uint64_t expected_base = (addr > 0x100) ? addr - 0x100 : 0;
			debugger_engine::request_disasm_refresh(addr, 0);

			std::vector<std::uint8_t> bytes;
			std::uint64_t base_out = 0;
			for (int i = 0; i < 60; ++i) {
				if (cancelled()) break;
				Sleep(50);
				bytes = debugger_engine::cached_disasm_window(base_out);
				if (!bytes.empty() && base_out == expected_base) break;
				debugger_engine::request_disasm_refresh(addr, 0);
			}

			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - t0).count();

			if (bytes.empty() || base_out != expected_base) {
				log_msg(hf, tag, "FAIL -- disasm window not populated for target (bytes=%zu base=0x%016llX expected=0x%016llX) (elapsed %lld ms)",
					bytes.size(), static_cast<unsigned long long>(base_out),
					static_cast<unsigned long long>(expected_base), (long long)ms);
				g_failed.fetch_add(1);
				return;
			}

			std::uint64_t offset = (addr > base_out) ? (addr - base_out) : 0;
			int decoded = 0;
			int non_db = 0;
			char first_mnem[32] = {};
			std::uint64_t scan = offset;
			while (scan + 1 < bytes.size() && decoded < 8) {
				int avail = static_cast<int>(bytes.size() - scan);
				if (avail > 15) avail = 15;
				AsmInstr ins = zydis_decode_one(bytes.data() + scan, avail, base_out + scan);
				if (decoded == 0)
					std::snprintf(first_mnem, sizeof(first_mnem), "%s", ins.mnem);
				if (std::strcmp(ins.mnem, "db") != 0)
					++non_db;
				if (ins.len <= 0) break;
				scan += static_cast<std::uint64_t>(ins.len);
				++decoded;
			}

			if (non_db > 0) {
				log_msg(hf, tag, "PASS -- disasm window %zu bytes at base 0x%016llX, decoded %d instrs (%d real, first=\"%s\") (elapsed %lld ms)",
					bytes.size(), static_cast<unsigned long long>(base_out),
					decoded, non_db, first_mnem, (long long)ms);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, tag, "FAIL -- disasm window had %zu bytes but no instruction decoded (decoded=%d) (elapsed %lld ms)",
					bytes.size(), decoded, (long long)ms);
				g_failed.fetch_add(1);
			}
		}


		void test_memory_scanner(HANDLE hf) {
			const char* tag = "memscan";
			const int done_before = running_done();
			set_phase("Memory scanner");
			try {
				log_msg(hf, tag, "START -- scan attached target for resident PE marker string");
				auto t0 = std::chrono::steady_clock::now();

				if (!require_target(hf, tag)) return;

				std::uint32_t pid = current_target_pid();
				std::uint64_t image_base = current_target_image_base();

				cleanup_memory_scanner_runtime(hf, "before memory scanner feature", 3000);
				memory_scanner::reset_scan();
				memory_scanner::scan_config_t cfg;
				cfg.value_type = memory_scanner::value_type_t::string_ascii;
				cfg.scan_mode = memory_scanner::scan_mode_t::exact;
				cfg.value_text = "This program cannot be run in DOS mode";
				cfg.writable_only = false;
				cfg.executable_exclude = false;
				cfg.range_base = image_base;
				cfg.range_size = image_base != 0 ? 0x1000 : 0;

				log_msg(hf, tag, "first_scan ASCII \"%s\" against pid=%u range=0x%016llX+0x%llX",
					cfg.value_text.c_str(), pid,
					static_cast<unsigned long long>(cfg.range_base),
					static_cast<unsigned long long>(cfg.range_size));
				bool ok = memory_scanner::first_scan(cfg);
				if (!ok) {
					auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
						std::chrono::steady_clock::now() - t0).count();
					log_msg(hf, tag, "FAIL -- first_scan rejected attached target pid=%u range=0x%016llX+0x%llX (elapsed %lld ms)",
						pid,
						static_cast<unsigned long long>(cfg.range_base),
						static_cast<unsigned long long>(cfg.range_size),
						(long long)ms);
					g_failed.fetch_add(1);
					return;
				}

				bool idle = false;
				for (int i = 0; i < 100; ++i) {
					if (cancelled()) break;
					if (memory_scanner_scan_idle()) {
						idle = true;
						break;
					}
					Sleep(100);
				}
				if (!idle)
					idle = wait_memory_scanner_scan_idle(5000);
				if (!idle) {
					request_memory_scanner_stop();
					wait_memory_scanner_scan_idle(3000);
					auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
						std::chrono::steady_clock::now() - t0).count();
					auto& st = memory_scanner::g_state;
					log_msg(hf, tag, "FAIL -- first_scan timed out before results became idle scanning=%d scan_done=%d progress=%.3f (elapsed %lld ms)",
						st.scanning.load(std::memory_order_acquire) ? 1 : 0,
						st.scan_thread_done.load(std::memory_order_acquire) ? 1 : 0,
						st.scan_progress.load(std::memory_order_acquire),
						(long long)ms);
					g_failed.fetch_add(1);
					return;
				}

				std::size_t found = 0;
				std::uint64_t first_addr = 0;
				if (!snapshot_memory_scan_results(found, first_addr, 2000)) {
					auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
						std::chrono::steady_clock::now() - t0).count();
					log_msg(hf, tag, "FAIL -- scanner results mutex remained busy after idle scan (elapsed %lld ms)",
						(long long)ms);
					g_failed.fetch_add(1);
					return;
				}

				auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now() - t0).count();

				if (found > 0) {
					log_msg(hf, tag, "PASS -- scanner found %zu live matches in target (first=0x%016llX) (elapsed %lld ms)",
						found, static_cast<unsigned long long>(first_addr), (long long)ms);
					g_passed.fetch_add(1);
					return;
				}

				log_msg(hf, tag, "scanner string scan empty after successful idle scan; validating target memory directly");

				std::vector<std::uint8_t> sample;
				bool read_ok = (image_base != 0) &&
					driver_bridge::read_memory_for(pid, image_base, 0x1000, sample);
				ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now() - t0).count();

				const std::string marker = cfg.value_text;
				bool marker_present = read_ok && sample.size() >= marker.size() &&
					std::search(sample.begin(), sample.end(), marker.begin(), marker.end()) != sample.end();
				bool mz_present = read_ok && sample.size() >= 2 && sample[0] == 'M' && sample[1] == 'Z';

				if (marker_present) {
					log_msg(hf, tag, "FAIL -- scanner missed readable PE marker at target image base 0x%016llX (read bytes=%zu elapsed %lld ms)",
						static_cast<unsigned long long>(image_base), sample.size(), (long long)ms);
				} else if (mz_present) {
					log_msg(hf, tag, "FAIL -- target image base was readable but expected PE marker was absent from first page (bytes=%zu elapsed %lld ms)",
						sample.size(), (long long)ms);
				} else {
					log_msg(hf, tag, "FAIL -- scanner found 0 matches and direct target read failed or returned non-PE data (read_ok=%d bytes=%zu elapsed %lld ms)",
						static_cast<int>(read_ok), sample.size(), (long long)ms);
				}
				g_failed.fetch_add(1);
			} catch (const std::exception& ex) {
				request_memory_scanner_stop();
				wait_memory_scanner_scan_idle(3000);
				log_msg(hf, tag, "FAIL -- memory scanner test raised C++ exception: %s", ex.what());
				if (running_done() == done_before)
					g_failed.fetch_add(1);
			} catch (...) {
				request_memory_scanner_stop();
				wait_memory_scanner_scan_idle(3000);
				log_msg(hf, tag, "FAIL -- memory scanner test raised unknown C++ exception");
				if (running_done() == done_before)
					g_failed.fetch_add(1);
			}
		}


		void test_network_view(HANDLE hf) {
			const char* tag = "netview";
			set_phase("Network view");
			log_msg(hf, tag, "START -- enumerate live network endpoints of attached target");
			auto t0 = std::chrono::steady_clock::now();

			if (!require_target(hf, tag)) return;

			if (!driver_bridge::using_kernel_driver()) {
				log_msg(hf, tag, "FAIL -- kernel driver not loaded, cannot enumerate target network state");
				g_failed.fetch_add(1);
				return;
			}

			std::uint32_t pid = current_target_pid();

			std::vector<driver_bridge::net_connection_info_t> conns;
			std::vector<driver_bridge::socket_info_t> sockets;
			std::vector<driver_bridge::tcpip_connection_t> tcpip;
			std::size_t observed = 0;
			std::uint32_t attempts = 0;
			for (std::uint32_t attempt = 0; attempt < 20; ++attempt) {
				++attempts;
				conns = driver_bridge::enumerate_connections(pid, 0);
				sockets = driver_bridge::get_socket_handles(pid);
				tcpip = driver_bridge::dump_tcpip_connections(pid, 0);
				observed = conns.size() + sockets.size() + tcpip.size();
				if (observed > 0)
					break;
				std::this_thread::sleep_for(std::chrono::milliseconds(250));
			}

			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - t0).count();

			log_msg(hf, tag, "target pid=%u connections=%zu sockets=%zu tcpip=%zu attempts=%u",
				pid, conns.size(), sockets.size(), tcpip.size(), attempts);

			if (observed > 0) {
				std::uint32_t lport = 0, rport = 0;
				if (!conns.empty()) {
					lport = conns.front().local_port;
					rport = conns.front().remote_port;
				} else if (!sockets.empty()) {
					lport = sockets.front().local_port;
					rport = sockets.front().remote_port;
				} else if (!tcpip.empty()) {
					lport = tcpip.front().local_port;
					rport = tcpip.front().remote_port;
				}
				log_msg(hf, tag, "PASS -- observed %zu live endpoints for target (first local_port=%u remote_port=%u) (elapsed %lld ms)",
					observed, lport, rport, (long long)ms);
				g_passed.fetch_add(1);
			} else {
				auto all_conns = driver_bridge::enumerate_connections(0, 0);
				ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now() - t0).count();
				if (!all_conns.empty()) {
					log_msg(hf, tag, "SKIP -- target had 0 live endpoints after %u attempts while driver enumerated %zu system-wide; target not network-active at sample time (elapsed %lld ms)",
						attempts,
						all_conns.size(), (long long)ms);
					g_skipped.fetch_add(1);
				} else {
					log_msg(hf, tag, "FAIL -- driver returned 0 connections target-scoped and system-wide (elapsed %lld ms)", (long long)ms);
					g_failed.fetch_add(1);
				}
			}
		}


		void test_hex_view(HANDLE hf) {
			const char* tag = "hexview";
			set_phase("Hex view");
			log_msg(hf, tag, "START -- read attached target image base through driver and validate MZ header");
			auto t0 = std::chrono::steady_clock::now();

			if (!require_target(hf, tag)) return;

			std::uint32_t pid = current_target_pid();
			std::uint64_t image_base = current_target_image_base();
			if (image_base == 0) {
				log_msg(hf, tag, "FAIL -- target image base unknown");
				g_failed.fetch_add(1);
				return;
			}

			std::vector<std::uint8_t> data;
			bool read_ok = driver_bridge::read_memory_for(pid, image_base, 256, data);

			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - t0).count();

			if (!read_ok || data.size() < 64) {
				log_msg(hf, tag, "FAIL -- driver read returned %zu bytes (read_ok=%d last_error=\"%s\") (elapsed %lld ms)",
					data.size(), static_cast<int>(read_ok), driver_bridge::last_error().c_str(), (long long)ms);
				g_failed.fetch_add(1);
				return;
			}

			bool is_mz = (data[0] == 'M' && data[1] == 'Z');
			std::uint32_t e_lfanew = 0;
			if (data.size() >= 0x40) {
				e_lfanew = static_cast<std::uint32_t>(data[0x3C]) |
					(static_cast<std::uint32_t>(data[0x3D]) << 8) |
					(static_cast<std::uint32_t>(data[0x3E]) << 16) |
					(static_cast<std::uint32_t>(data[0x3F]) << 24);
			}

			if (is_mz) {
				log_msg(hf, tag, "PASS -- target image base 0x%016llX hex dump %zu bytes, MZ header present, e_lfanew=0x%08X (elapsed %lld ms)",
					static_cast<unsigned long long>(image_base), data.size(),
					e_lfanew, (long long)ms);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, tag, "FAIL -- target image base read %zu bytes but no MZ header (first=%02X %02X) (elapsed %lld ms)",
					data.size(), data[0], data[1], (long long)ms);
				g_failed.fetch_add(1);
			}
		}


		void test_aob_generator(HANDLE hf) {
			const char* tag = "aobgen";
			set_phase("AOB generator");
			log_msg(hf, tag, "START -- generate AOB signature from attached target function");
			auto t0 = std::chrono::steady_clock::now();

			if (!require_target(hf, tag)) return;

			std::uint64_t addr = current_target_addr();
			if (addr == 0) {
				log_msg(hf, tag, "FAIL -- no known-good target address resolved");
				g_failed.fetch_add(1);
				return;
			}

			std::uint32_t pid = current_target_pid();
			log_msg(hf, tag, "generate_from_address target addr=0x%016llX (pid=%u)",
				static_cast<unsigned long long>(addr), pid);

			aob_generator::generate_from_address(addr, 8, true);

			bool done = false;
			for (int i = 0; i < 80; ++i) {
				if (cancelled()) break;
				if (!aob_generator::g_state.generating.load()) { done = true; break; }
				Sleep(50);
			}

			std::size_t byte_count = 0;
			std::uint64_t result_addr = 0;
			std::string sig_text;
			std::string err;
			{
				std::lock_guard<std::mutex> lk(aob_generator::g_state.mutex);
				byte_count = aob_generator::g_state.current.bytes.size();
				result_addr = aob_generator::g_state.current.address;
				sig_text = aob_generator::format_signature(aob_generator::g_state.current);
				err = aob_generator::g_state.last_error;
			}

			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - t0).count();

			if (done && byte_count > 0 && result_addr == addr) {
				log_msg(hf, tag, "PASS -- generated %zu-byte signature for target 0x%016llX: %s (elapsed %lld ms)",
					byte_count, static_cast<unsigned long long>(result_addr),
					sig_text.c_str(), (long long)ms);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, tag, "FAIL -- AOB generation produced %zu bytes for addr=0x%016llX (done=%d error=\"%s\") (elapsed %lld ms)",
					byte_count, static_cast<unsigned long long>(result_addr),
					static_cast<int>(done), err.c_str(), (long long)ms);
				g_failed.fetch_add(1);
			}
		}


		void test_cfg_view(HANDLE hf) {
			const char* tag = "cfgview";
			set_phase("CFG view");
			log_msg(hf, tag, "START -- build control flow graph for attached target function");
			auto t0 = std::chrono::steady_clock::now();

			if (!require_target(hf, tag)) return;

			std::uint64_t addr = current_target_addr();
			if (addr == 0) {
				log_msg(hf, tag, "FAIL -- no known-good target address resolved");
				g_failed.fetch_add(1);
				return;
			}

			std::uint32_t pid = current_target_pid();
			log_msg(hf, tag, "build_cfg target entry=0x%016llX (pid=%u)",
				static_cast<unsigned long long>(addr), pid);

			cfg_view::clear();
			cfg_view::build_cfg(addr);

			bool finished = false;
			for (int i = 0; i < 120; ++i) {
				if (cancelled()) break;
				if (!cfg_view::g_state.building.load()) { finished = true; break; }
				Sleep(50);
			}

			std::size_t blocks = 0;
			std::size_t nodes = 0;
			std::size_t edges = 0;
			bool built = false;
			std::uint64_t entry = 0;
			{
				std::lock_guard<std::mutex> lk(cfg_view::g_state.mutex);
				blocks = cfg_view::g_state.blocks.size();
				nodes = cfg_view::g_state.graph.nodes.size();
				edges = cfg_view::g_state.graph.edges.size();
				built = cfg_view::g_state.built;
				entry = cfg_view::g_state.entry_addr;
			}

			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - t0).count();

			if (finished && built && blocks > 0 && entry == addr) {
				log_msg(hf, tag, "PASS -- CFG built for target 0x%016llX: %zu blocks, %zu nodes, %zu edges (elapsed %lld ms)",
					static_cast<unsigned long long>(addr), blocks, nodes, edges, (long long)ms);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, tag, "FAIL -- CFG build incomplete blocks=%zu built=%d finished=%d entry=0x%016llX (elapsed %lld ms)",
					blocks, static_cast<int>(built), static_cast<int>(finished),
					static_cast<unsigned long long>(entry), (long long)ms);
				g_failed.fetch_add(1);
			}
		}


		void phase_extended_features(HANDLE hf) {
			set_phase("Extended feature tests");
			log_phase_begin(hf, "extended features");
			log_msg(hf, "extended", "running 6 extended feature tests against attached target ...");

			if (!cancelled()) test_disassembly_view(hf);
			if (!cancelled()) test_memory_scanner(hf);
			if (!cancelled()) test_network_view(hf);
			if (!cancelled()) test_hex_view(hf);
			if (!cancelled()) test_aob_generator(hf);
			if (!cancelled()) test_cfg_view(hf);

			log_phase_end(hf, "extended features");
		}

		void drain_decompiler_runtime(HANDLE hf, const char* reason) {
			set_stepf("decompiler drain: %s", reason ? reason : "unspecified");
			const bool before_decompiling = decompiler_engine::g_state.decompiling.load(std::memory_order_acquire);
			const bool before_batch = decompiler_engine::g_state.batch_running.load(std::memory_order_acquire);
			const bool before_next = decompiler_engine::g_state.next_pending.load(std::memory_order_acquire);
			const int before_tabs = pseudocode_view::tab_count();
			log_msg(hf, "decompiler-drain",
				"BEGIN -- %s decompiling=%d batch=%d next_pending=%d tabs=%d",
				reason ? reason : "unspecified",
				before_decompiling ? 1 : 0,
				before_batch ? 1 : 0,
				before_next ? 1 : 0,
				before_tabs);

			pseudocode_view::cancel_active_decompile();
			const bool idle = decompiler_engine::wait_for_idle(12000, 25);
			const int tabs_after_wait = pseudocode_view::tab_count();
			if (idle) {
				pseudocode_view::close_all_tabs();
			} else {
				g_suspect.fetch_add(1);
			}

			log_msg(hf, "decompiler-drain",
				"%s -- idle=%d tabs_after_wait=%d tabs_final=%d decompiling=%d batch=%d next_pending=%d",
				idle ? "PASS" : "SUSPECT",
				idle ? 1 : 0,
				tabs_after_wait,
				pseudocode_view::tab_count(),
				decompiler_engine::g_state.decompiling.load(std::memory_order_acquire) ? 1 : 0,
				decompiler_engine::g_state.batch_running.load(std::memory_order_acquire) ? 1 : 0,
				decompiler_engine::g_state.next_pending.load(std::memory_order_acquire) ? 1 : 0);
		}


		void phase_stop_target(HANDLE hf, std::uint32_t pid) {
			if (pid == 0) return;
			set_phase("Stopping test_target");
			auto threads = driver_bridge::enumerate_threads_for(pid);
			uint32_t observed_threads = 0;
			uint32_t resume_calls = 0;
			uint32_t resume_failures = 0;
			for (const auto& th : threads) {
				if (th.owner_pid != pid || th.tid == 0)
					continue;
				++observed_threads;
				for (int guard = 0; guard < 8; ++guard) {
					uint32_t prev_count = 0;
					if (!driver_bridge::resume_thread(th.tid, &prev_count)) {
						++resume_failures;
						break;
					}
					++resume_calls;
					if (prev_count <= 1)
						break;
				}
			}
			log_msg(hf, "cleanup", "pre-signal thread resume sweep pid=%u threads=%u resume_calls=%u failures=%u",
				pid,
				observed_threads,
				resume_calls,
				resume_failures);
			log_msg(hf, "cleanup", "signaling test_target done event for pid=%u", pid);

			HANDLE hDone = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Global\\WhosWhoTestDone");
			if (!hDone) {
				DWORD global_err = GetLastError();
				log_msg(hf, "cleanup", "OpenEvent Global\\WhosWhoTestDone failed err=%lu", static_cast<unsigned long>(global_err));
				hDone = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Local\\WhosWhoTestDone");
				if (!hDone) {
					DWORD local_err = GetLastError();
					log_msg(hf, "cleanup", "OpenEvent Local\\WhosWhoTestDone failed err=%lu", static_cast<unsigned long>(local_err));
				}
			}
			if (hDone) {
				BOOL signaled = SetEvent(hDone);
				DWORD signal_err = signaled ? 0 : GetLastError();
				CloseHandle(hDone);
				log_msg(hf, "cleanup", "WhosWhoTestDone signal_result=%d err=%lu; waiting for process to exit...",
					signaled ? 1 : 0, static_cast<unsigned long>(signal_err));
			} else {
				log_msg(hf, "cleanup", "could not open WhosWhoTestDone event; sending TerminateProcess directly");
			}

			HANDLE hProc = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, static_cast<DWORD>(pid));
			if (hProc) {
				DWORD wait_result = WaitForSingleObject(hProc, 6000);
				if (wait_result != WAIT_OBJECT_0) {
					DWORD exit_code = 0;
					BOOL got_exit = GetExitCodeProcess(hProc, &exit_code);
					log_msg(hf, "cleanup", "process pid=%u did not exit in 6s wait_result=%lu get_exit=%d exit_code=0x%08lX wait_err=%lu; forcing TerminateProcess",
						pid,
						static_cast<unsigned long>(wait_result),
						got_exit ? 1 : 0,
						static_cast<unsigned long>(exit_code),
						static_cast<unsigned long>(GetLastError()));
					BOOL term_ok = TerminateProcess(hProc, 0);
					DWORD term_err = term_ok ? 0 : GetLastError();
					DWORD post_wait = WaitForSingleObject(hProc, 2000);
					DWORD post_exit = 0;
					BOOL got_post_exit = GetExitCodeProcess(hProc, &post_exit);
					log_msg(hf, "cleanup", "TerminateProcess result=%d err=%lu post_wait=%lu get_exit=%d exit_code=0x%08lX",
						term_ok ? 1 : 0,
						static_cast<unsigned long>(term_err),
						static_cast<unsigned long>(post_wait),
						got_post_exit ? 1 : 0,
						static_cast<unsigned long>(post_exit));
				} else {
					DWORD exit_code = 0;
					BOOL got_exit = GetExitCodeProcess(hProc, &exit_code);
					log_msg(hf, "cleanup", "process pid=%u exited cleanly get_exit=%d exit_code=0x%08lX",
						pid,
						got_exit ? 1 : 0,
						static_cast<unsigned long>(exit_code));
				}
				CloseHandle(hProc);
			} else {
				log_msg(hf, "cleanup", "could not open process handle for pid=%u (err=%lu); assuming already exited", pid, static_cast<unsigned long>(GetLastError()));
			}

			log_msg(hf, "cleanup", "test_target shutdown complete");
		}

		struct run_cleanup_guard_t {
			HANDLE* hf = nullptr;
			std::uint32_t* target_pid = nullptr;
			bool active = true;

			~run_cleanup_guard_t() {
				if (!active) return;
				HANDLE h = hf ? *hf : INVALID_HANDLE_VALUE;
				log_msg(h, "cleanup", "abnormal/early exit cleanup guard fired");
				try {
					cleanup_memory_scanner_runtime(h, "abnormal/early exit", 5000);
				} catch (...) {
				}
				cleanup_network_runtime(h, "abnormal/early exit");
				if (target_pid) {
					phase_stop_target(h, *target_pid);
				}
				if (hf && *hf != INVALID_HANDLE_VALUE) {
					CloseHandle(*hf);
					*hf = INVALID_HANDLE_VALUE;
				}
				g_running.store(false, std::memory_order_release);
			}
		};

		struct full_test_env_guard_t {
			HANDLE* hf = nullptr;
			bool active = false;

			explicit full_test_env_guard_t(HANDLE* handle) : hf(handle), active(true) {
				anti_tamper::state::get().full_test_running.store(true, std::memory_order_release);
				set_full_test_env(hf ? *hf : INVALID_HANDLE_VALUE, true, "run_all begin");
			}

			void clear(const char* reason) {
				if (!active) return;
				set_full_test_env(hf ? *hf : INVALID_HANDLE_VALUE, false, reason ? reason : "run_all end");
				anti_tamper::state::get().full_test_running.store(false, std::memory_order_release);
				active = false;
			}

			~full_test_env_guard_t() {
				clear("run_all scope exit");
			}
		};

		struct run_heartbeat_t {
			std::atomic<bool> stop{ false };
			std::thread worker;

			void start(HANDLE hf) {
				try {
					worker = std::thread([this]() {
						while (!stop.load(std::memory_order_acquire)) {
							for (int i = 0; i < 50; ++i) {
								if (stop.load(std::memory_order_acquire)) return;
								Sleep(100);
							}
							HANDLE hh = open_log_file();
							log_debug_snapshot(hh, "heartbeat", "FULL-TEST live heartbeat");
							if (hh != INVALID_HANDLE_VALUE) CloseHandle(hh);
						}
					});
				} catch (const std::exception& ex) {
					log_msg(hf, "heartbeat", "disabled live heartbeat worker: %s", ex.what());
				} catch (...) {
					log_msg(hf, "heartbeat", "disabled live heartbeat worker: unknown exception");
				}
			}

			void stop_and_join() {
				stop.store(true, std::memory_order_release);
				if (worker.joinable()) worker.join();
			}

			~run_heartbeat_t() {
				stop_and_join();
			}
		};


		void run_all() {
			HANDLE hf = open_log_file();
			full_test_env_guard_t full_test_env_guard{ &hf };
			std::uint32_t target_pid = 0;
			run_cleanup_guard_t cleanup_guard{ &hf, &target_pid, true };
			run_heartbeat_t heartbeat;
			heartbeat.start(hf);
			const std::uint64_t this_run = g_run_id.fetch_add(1, std::memory_order_acq_rel) + 1;
			g_run_start_tick.store(now_ms_tick(), std::memory_order_release);
			set_step("run_all entry");

			char ts[40];
			format_timestamp(ts, sizeof(ts));
			char header[512];
			_snprintf_s(header, sizeof(header), _TRUNCATE,
				"\n"
				"================================================================\n"
				"[%s] AiDA Full Feature Test -- START\n"
				"================================================================\n",
				ts);
			write_log_file(hf, std::string(header));
			push_log(header);

			diag::log_tagged_fmt("test_all", "========== Full Feature Test START ==========");
			log_msg(hf, "run", "run_id=%llu thread=%lu log_path=%s",
				static_cast<unsigned long long>(this_run),
				static_cast<unsigned long>(GetCurrentThreadId()),
				log_path());
			log_debug_snapshot(hf, "run", "initial snapshot");

			const auto& features = test_lab::all_features();
			int testlab_count = static_cast<int>(features.size());
			int total_estimate =
				kLaunchFeatureTests +
				testlab_count +
				kExtendedFeatureTests +
				kDebuggerFeatureTests +
				kScannerFeatureTests +
				kAnalysisFeatureTests +
				kNetworkFeatureTests +
				kBurpFeatureTests +
				kDisasmFeatureTests +
				kMcpFeatureTests;
			g_total.store(total_estimate);
			log_msg(hf, "run", "progress total estimate=%d launch=%d testlab=%d extended=%d debugger=%d scanner=%d analysis=%d network=%d burp=%d disasm=%d mcp=%d",
				total_estimate,
				kLaunchFeatureTests,
				testlab_count,
				kExtendedFeatureTests,
				kDebuggerFeatureTests,
				kScannerFeatureTests,
				kAnalysisFeatureTests,
				kNetworkFeatureTests,
				kBurpFeatureTests,
				kDisasmFeatureTests,
				kMcpFeatureTests);

			bool attach_ok = false;
			if (!cancelled()) {
				set_step("phase call: launch target");
				log_debug_snapshot(hf, "checkpoint", "BEFORE phase_launch_target");
				attach_ok = phase_launch_target(hf, target_pid);
				g_target_unavailable.store(!attach_ok, std::memory_order_release);
				log_debug_snapshot(hf, "checkpoint", "AFTER phase_launch_target");
			}

			log_msg(hf, "summary", "post-launch state: target_pid=%u driver_attached=%d attach_ok=%d",
				current_target_pid(),
				static_cast<int>(g_driver_attached.load()),
				static_cast<int>(attach_ok));

			cleanup_network_runtime(hf, "pre-run reset");

			if (!cancelled()) {
				set_step("phase call: testlab features");
				log_debug_snapshot(hf, "checkpoint", "BEFORE phase_testlab_features");
				phase_testlab_features(hf, target_pid);
				log_debug_snapshot(hf, "checkpoint", "AFTER phase_testlab_features");
				verify_target_liveness(hf, "after testlab features");
			}

			cleanup_network_runtime(hf, "after testlab features");

			if (!cancelled()) {
				if (target_unavailable()) {
					skip_phase_target_unavailable(hf, "extended features", kExtendedFeatureTests);
				} else {
					set_step("phase call: extended features");
					log_debug_snapshot(hf, "checkpoint", "BEFORE phase_extended_features");
					phase_extended_features(hf);
					log_debug_snapshot(hf, "checkpoint", "AFTER phase_extended_features");
					verify_target_liveness(hf, "after extended features");
				}
			}

			if (!cancelled()) {
				if (target_unavailable()) {
					skip_phase_target_unavailable(hf, "debugger feature tests", kDebuggerFeatureTests);
				} else {
					set_phase("Debugger feature tests");
					set_step("phase call: debugger feature tests");
					log_phase_begin(hf, "debugger feature tests");
					phase_debugger_tests(hf, g_passed, g_failed, g_skipped, cancelled);
					log_phase_end(hf, "debugger feature tests");
					verify_target_liveness(hf, "after debugger feature tests");
				}
			}

			if (!cancelled()) {
				if (target_unavailable()) {
					skip_phase_target_unavailable(hf, "scanner feature tests", kScannerFeatureTests);
				} else {
					set_phase("Scanner feature tests");
					set_step("phase call: scanner feature tests");
					log_phase_begin(hf, "scanner feature tests");
					phase_scanner_tests(hf, g_passed, g_failed, g_skipped, cancelled);
					log_phase_end(hf, "scanner feature tests");
					verify_target_liveness(hf, "after scanner feature tests");
				}
			}

			if (!cancelled()) {
				set_phase("Analysis feature tests");
				set_step("phase call: analysis feature tests");
				log_phase_begin(hf, "analysis feature tests");
				phase_analysis_tests(hf, g_passed, g_failed, g_skipped, cancelled);
				log_phase_end(hf, "analysis feature tests");
				if (!target_unavailable())
					verify_target_liveness(hf, "after analysis feature tests");
			}

			if (!cancelled()) {
				set_phase("Network feature tests");
				set_step("phase call: network feature tests");
				log_phase_begin(hf, "network feature tests");
				phase_network_tests(hf, g_passed, g_failed, g_skipped, cancelled);
				log_phase_end(hf, "network feature tests");
				if (!target_unavailable())
					verify_target_liveness(hf, "after network feature tests");
			}

			cleanup_network_runtime(hf, "after network feature tests");

			if (!cancelled()) {
				set_phase("Burp suite feature tests");
				set_step("phase call: burp suite feature tests");
				log_phase_begin(hf, "burp suite feature tests");
				phase_burp_tests(hf, g_passed, g_failed, g_skipped, cancelled);
				log_phase_end(hf, "burp suite feature tests");
				if (!target_unavailable())
					verify_target_liveness(hf, "after burp suite feature tests");
			}

			if (!cancelled()) {
				if (target_unavailable()) {
					skip_phase_target_unavailable(hf, "disassembly & decompiler tests", kDisasmFeatureTests);
				} else {
					set_phase("Disassembly & decompiler tests");
					set_step("phase call: disassembly & decompiler tests");
					log_phase_begin(hf, "disassembly & decompiler tests");
					phase_disasm_tests(hf, g_passed, g_failed, g_skipped, cancelled);
					log_phase_end(hf, "disassembly & decompiler tests");
					verify_target_liveness(hf, "after disassembly & decompiler tests");
				}
			}

			if (!cancelled()) {
				drain_decompiler_runtime(hf, "after disassembly before MCP");
			}

			if (!cancelled()) {
				set_phase("MCP tool tests");
				set_step("phase call: MCP tool tests");
				log_phase_begin(hf, "MCP tool tests");
				phase_mcp_tests(hf, g_passed, g_failed, g_skipped, cancelled);
				log_phase_end(hf, "MCP tool tests");
			}

			cleanup_network_runtime(hf, "final cleanup");
			phase_stop_target(hf, target_pid);

			set_phase("Complete");
			int p = g_passed.load();
			int f = g_failed.load();
			int s = g_skipped.load();
			int executed = p + f + s;
			int planned = g_total.load();

			log_msg(hf, "summary", "================ VALIDATION SUMMARY ================");
			log_msg(hf, "summary", "target_pid=%u driver_attached=%d target_unavailable=%d image_base=0x%016llX known_good_addr=0x%016llX",
				current_target_pid(),
				static_cast<int>(g_driver_attached.load()),
				target_unavailable() ? 1 : 0,
				static_cast<unsigned long long>(current_target_image_base()),
				static_cast<unsigned long long>(current_target_addr()));

			if (current_target_pid() == 0 || !g_driver_attached.load()) {
				log_msg(hf, "summary", "SUSPECT -- no verified target attach; every PASS that depended on the target is unreliable");
			}

			int suspect = g_suspect.load();
			if (suspect > 0) {
				log_msg(hf, "summary", "SUSPECT -- %d test(s) reported PASS while returning zero/empty content; review log entries tagged SUSPECT",
					suspect);
			} else {
				log_msg(hf, "summary", "no SUSPECT (empty-pass) tests detected by orchestrator");
			}

			if (planned > executed) {
				log_msg(hf, "summary", "INCOMPLETE -- planned=%d executed=%d remaining=%d cancel=%d target_unavailable=%d",
					planned,
					executed,
					planned - executed,
					cancelled() ? 1 : 0,
					target_unavailable() ? 1 : 0);
			}

			log_msg(hf, "summary", "TOTAL=%d EXECUTED=%d PASSED=%d FAILED=%d SKIPPED=%d SUSPECT=%d", planned, executed, p, f, s, suspect);

			format_timestamp(ts, sizeof(ts));
			char footer[512];
			_snprintf_s(footer, sizeof(footer), _TRUNCATE,
				"[%s] AiDA Full Feature Test -- DONE  (total=%d executed=%d passed=%d failed=%d skipped=%d suspect=%d)\n"
				"================================================================\n\n",
				ts, planned, executed, p, f, s, suspect);
			write_log_file(hf, std::string(footer));
			push_log(footer);

			diag::log_tagged_fmt("test_all", "========== Full Feature Test DONE: total=%d executed=%d passed=%d failed=%d skipped=%d suspect=%d ==========", planned, executed, p, f, s, suspect);

			full_test_env_guard.clear("run_all normal completion");

			if (hf != INVALID_HANDLE_VALUE)
				CloseHandle(hf);
			hf = INVALID_HANDLE_VALUE;

			g_running.store(false, std::memory_order_release);
			cleanup_guard.active = false;
		}


		void log_worker_escape(const char* kind, DWORD code, const char* message) {
			HANDLE hf = open_log_file();
			char snap[1200] = {};
			format_debug_snapshot_impl(snap, sizeof(snap));
			log_msg(hf, "fatal", "FULL-TEST worker escaped kind=%s code=0x%08lX message=\"%s\" snapshot=%s",
				kind ? kind : "?",
				static_cast<unsigned long>(code),
				message ? message : "",
				snap);
			set_full_test_env(hf, false, "worker exception escape");
			try {
				cleanup_memory_scanner_runtime(hf, "worker exception escape", 5000);
			} catch (...) {
			}
			cleanup_network_runtime(hf, "worker exception escape");
			std::uint32_t pid = g_target_pid.load(std::memory_order_acquire);
			if (pid != 0)
				phase_stop_target(hf, pid);
			g_running.store(false, std::memory_order_release);
			if (hf != INVALID_HANDLE_VALUE) CloseHandle(hf);
		}

		void run_all_cpp_guarded() {
			try {
				run_all();
			} catch (const std::exception& ex) {
				log_worker_escape("c++", 0, ex.what());
			} catch (...) {
				log_worker_escape("c++", 0, "unknown C++ exception");
			}
		}

		DWORD run_all_seh_guarded() {
			__try {
				run_all_cpp_guarded();
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				DWORD code = GetExceptionCode();
				log_worker_escape("seh", code, "SEH exception escaped run_all");
				return code;
			}
			return 0;
		}

		bool start_tests_impl() {
			bool expected = false;
			if (!g_running.compare_exchange_strong(expected, true)) {
				char snap[1200] = {};
				format_debug_snapshot_impl(snap, sizeof(snap));
				diag::log_tagged_fmt("test_all", "start_tests rejected: run already active | %s", snap);
				HANDLE hf = open_log_file();
				log_msg(hf, "start", "REJECTED -- run already active | %s", snap);
				if (hf != INVALID_HANDLE_VALUE) CloseHandle(hf);
				return false;
			}

			g_cancel_requested.store(false);
			g_target_unavailable.store(false);
			g_total.store(0);
			g_current.store(0);
			g_passed.store(0);
			g_failed.store(0);
			g_skipped.store(0);
			g_suspect.store(0);
			g_target_pid.store(0);
			g_target_addr.store(0);
			g_target_image_base.store(0);
			g_driver_attached.store(false);
			g_saved_dtb.store(0, std::memory_order_release);

			{
				std::lock_guard<std::mutex> lk(g_log_mtx);
				g_log_lines.clear();
			}
			set_phase("Initializing...");
			set_step("start_tests_impl queued");

			diag::log_tagged_fmt("test_all", "user triggered Test All Features");

			try {
				std::thread([]() {
					(void)run_all_seh_guarded();
				}).detach();
			} catch (const std::exception& ex) {
				HANDLE hf = open_log_file();
				log_msg(hf, "start", "FAIL -- full-test worker thread could not start: %s", ex.what());
				g_failed.fetch_add(1);
				g_running.store(false, std::memory_order_release);
				if (hf != INVALID_HANDLE_VALUE) CloseHandle(hf);
				diag::log_tagged_fmt("test_all", "full-test worker thread start failed: %s", ex.what());
				return false;
			} catch (...) {
				HANDLE hf = open_log_file();
				log_msg(hf, "start", "FAIL -- full-test worker thread could not start: unknown exception");
				g_failed.fetch_add(1);
				g_running.store(false, std::memory_order_release);
				if (hf != INVALID_HANDLE_VALUE) CloseHandle(hf);
				diag::log_tagged("test_all", "full-test worker thread start failed: unknown exception");
				return false;
			}
			diag::log_tagged("test_all", "dedicated full test worker thread started");
			return true;
		}

		void cancel_tests() {
			g_cancel_requested.store(true, std::memory_order_release);
			diag::log_tagged_fmt("test_all", "user cancelled Test All Features");
		}

	}


	bool start_tests() {
		return start_tests_impl();
	}

	bool is_running() {
		return g_running.load(std::memory_order_acquire);
	}

	void set_progress_step(const char* label) {
		set_step(label ? label : "");
	}

	void format_debug_snapshot(char* out, std::size_t cap) {
		format_debug_snapshot_impl(out, cap);
	}

	void render_overlay(float vw, float vh) {
		if (!globals::ui::test_all_visible) return;

		const auto& t = aida::ui::resolved();

		float ow = vw * 0.7f;
		if (ow < 600.f) ow = 600.f;
		if (ow > vw - 40.f) ow = vw - 40.f;

		float oh = vh * 0.75f;
		if (oh < 400.f) oh = 400.f;
		if (oh > vh - 40.f) oh = vh - 40.f;

		float ox = (vw - ow) * 0.5f;
		float oy = (vh - oh) * 0.5f;

		ImGui::SetNextWindowPos(ImVec2(ox, oy), ImGuiCond_Always);
		ImGui::SetNextWindowSize(ImVec2(ow, oh), ImGuiCond_Always);

		ImGuiWindowFlags flags =
			ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings |
			ImGuiWindowFlags_NoDocking;

		bool open = globals::ui::test_all_visible;
		if (ImGui::Begin("Test All Features##test_all_overlay", &open, flags)) {

			bool running = g_running.load(std::memory_order_acquire);


			if (running) ImGui::BeginDisabled();
			if (ImGui::Button("TEST ALL FEATURES", ImVec2(190.f, 30.f))) {
				start_tests();
			}
			if (running) ImGui::EndDisabled();

			ImGui::SameLine();

			if (!running) ImGui::BeginDisabled();
			if (ImGui::Button("Cancel", ImVec2(100.f, 30.f))) {
				cancel_tests();
			}
			if (!running) ImGui::EndDisabled();

			ImGui::SameLine(0.f, 20.f);


			{
				std::lock_guard<std::mutex> lk(g_phase_mtx);
				if (!g_phase_label.empty()) {
					ImGui::PushStyleColor(ImGuiCol_Text, t.text_dim);
					ImGui::Text("Phase: %s", g_phase_label.c_str());
					ImGui::PopStyleColor();
				}
			}

			ImGui::Dummy(ImVec2(0.f, 6.f));


			{
				std::uint32_t tpid = g_target_pid.load();
				bool attached = g_driver_attached.load();
				if (tpid != 0 && attached) {
					ImGui::PushStyleColor(ImGuiCol_Text, t.success);
					ImGui::Text("Target pid: %u   Driver: ATTACHED", tpid);
					ImGui::PopStyleColor();
				} else if (tpid != 0) {
					ImGui::PushStyleColor(ImGuiCol_Text, t.warning);
					ImGui::Text("Target pid: %u   Driver: NOT ATTACHED", tpid);
					ImGui::PopStyleColor();
				} else {
					ImGui::PushStyleColor(ImGuiCol_Text, t.text_dim);
					ImGui::TextUnformatted("Target pid: (none)   Driver: not attached");
					ImGui::PopStyleColor();
				}
			}

			ImGui::Dummy(ImVec2(0.f, 4.f));


			{
				int total   = g_total.load();
				int passed  = g_passed.load();
				int failed  = g_failed.load();
				int skipped = g_skipped.load();
				int done    = passed + failed + skipped;

				ImGui::PushStyleColor(ImGuiCol_Text, t.text_secondary);
				ImGui::Text("Total: %d", total);
				ImGui::PopStyleColor();
				ImGui::SameLine(0.f, 16.f);

				ImGui::PushStyleColor(ImGuiCol_Text, t.success);
				ImGui::Text("Passed: %d", passed);
				ImGui::PopStyleColor();
				ImGui::SameLine(0.f, 16.f);

				ImGui::PushStyleColor(ImGuiCol_Text, t.error);
				ImGui::Text("Failed: %d", failed);
				ImGui::PopStyleColor();
				ImGui::SameLine(0.f, 16.f);

				ImGui::PushStyleColor(ImGuiCol_Text, t.warning);
				ImGui::Text("Skipped: %d", skipped);
				ImGui::PopStyleColor();
				ImGui::SameLine(0.f, 16.f);

				if (total > 0) {
					float progress = static_cast<float>(done) / static_cast<float>(total);
					ImGui::ProgressBar(progress, ImVec2(200.f, 20.f));
				}
			}

			ImGui::Dummy(ImVec2(0.f, 4.f));
			ImGui::Separator();
			ImGui::Dummy(ImVec2(0.f, 4.f));


			ImGui::PushStyleColor(ImGuiCol_Text, t.text_dim);
			ImGui::TextUnformatted("TEST LOG");
			ImGui::PopStyleColor();

			float log_h = oh - ImGui::GetCursorPosY() - 30.f;
			if (log_h < 100.f) log_h = 100.f;

			ImGui::BeginChild("##test_all_log", ImVec2(-1.f, log_h), true,
				ImGuiWindowFlags_HorizontalScrollbar);

			if (g_code_font) ImGui::PushFont(g_code_font);

			{
				std::lock_guard<std::mutex> lk(g_log_mtx);
				for (const auto& line : g_log_lines) {

					if (line.find("SUSPECT") != std::string::npos) {
						ImGui::PushStyleColor(ImGuiCol_Text, t.warning);
						ImGui::TextUnformatted(line.c_str());
						ImGui::PopStyleColor();
					} else if (line.find("PASS") != std::string::npos) {
						ImGui::PushStyleColor(ImGuiCol_Text, t.success);
						ImGui::TextUnformatted(line.c_str());
						ImGui::PopStyleColor();
					} else if (line.find("FAIL") != std::string::npos) {
						ImGui::PushStyleColor(ImGuiCol_Text, t.error);
						ImGui::TextUnformatted(line.c_str());
						ImGui::PopStyleColor();
					} else if (line.find("SKIP") != std::string::npos) {
						ImGui::PushStyleColor(ImGuiCol_Text, t.warning);
						ImGui::TextUnformatted(line.c_str());
						ImGui::PopStyleColor();
					} else {
						ImGui::TextUnformatted(line.c_str());
					}
				}
			}


			if (running) {
				ImGui::SetScrollHereY(1.0f);
			}

			if (g_code_font) ImGui::PopFont();

			ImGui::EndChild();


			ImGui::PushStyleColor(ImGuiCol_Text, t.text_dim);
			ImGui::Text("Log file: %s", log_path());
			ImGui::PopStyleColor();
		}
		ImGui::End();

		globals::ui::test_all_visible = open;
	}

}
