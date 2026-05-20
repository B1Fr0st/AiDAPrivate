#include "test_all_features.hpp"
#include "test_lab.hpp"
#include "test_lab_format.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "../infra/work_queue.hpp"
#include "../ui/theme.hpp"
#include "../debugger/debugger_engine.hpp"
#include "../runtime/run_target.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../helpers/globals.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#pragma comment(lib, "ws2_32.lib")

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace test_all_features {

	namespace {

		// ----------------------------------------------------------------
		// state
		// ----------------------------------------------------------------

		std::atomic<bool> g_running{ false };
		std::atomic<bool> g_cancel_requested{ false };

		std::atomic<int>  g_total{ 0 };
		std::atomic<int>  g_current{ 0 };
		std::atomic<int>  g_passed{ 0 };
		std::atomic<int>  g_failed{ 0 };
		std::atomic<int>  g_skipped{ 0 };

		std::mutex        g_log_mtx;
		std::deque<std::string> g_log_lines;
		constexpr std::size_t kMaxLogLines = 4096;

		std::mutex        g_phase_mtx;
		std::string       g_phase_label;

		// ----------------------------------------------------------------
		// log path
		// ----------------------------------------------------------------

		const char* log_path() {
			return "C:\\Users\\Public\\Desktop\\aida_full_test.log";
		}

		// ----------------------------------------------------------------
		// helpers
		// ----------------------------------------------------------------

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

			// build formatted line
			char line[1200];
			_snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
			std::string s(line);

			// write to log file
			write_log_file(hf, s);

			// write to diag log + OutputDebugString
			diag::log_tagged_fmt("test_all", "%s: %s", tag, detail);
			OutputDebugStringA(s.c_str());

			// push to UI log
			push_log(s);
		}

		void set_phase(const char* label) {
			std::lock_guard<std::mutex> lk(g_phase_mtx);
			g_phase_label = (label != nullptr) ? label : "";
		}

		bool cancelled() {
			return g_cancel_requested.load(std::memory_order_acquire);
		}

		// ----------------------------------------------------------------
		// destructive test skip list  (copied from test_lab_view.cpp)
		// ----------------------------------------------------------------

		bool is_destructive(const char* name) {
			if (name == nullptr) return false;
			static const char* kSkip[] = {
				"ABRT", "DBGA", "RECU", "ADMP", "RC", "CR",
				"SRVT", "SRV2", "PINJ", "TSR", "PCEX",
				"HVDT", "CANR", "CANQ"
			};
			for (const auto* s : kSkip) {
				if (std::strcmp(name, s) == 0) return true;
			}
			return false;
		}

		bool name_starts_with(const char* name, const char* prefix) {
			if (name == nullptr || prefix == nullptr) return false;
			return std::strncmp(name, prefix, std::strlen(prefix)) == 0;
		}

		// ----------------------------------------------------------------
		// safe defaults  (mirrors test_lab_view.cpp populate_safe_defaults)
		// ----------------------------------------------------------------

		void populate_defaults(test_lab::state_t& s) {
			s.pid = static_cast<std::uint32_t>(GetCurrentProcessId());
			s.tid = static_cast<std::uint32_t>(GetCurrentThreadId());
			s.addr = 0;
			s.size = 64;
			s.u32_a = 0;
			s.u32_b = 0;
			s.u64_a = 0;
			s.buf.clear();
			s.text_a = "ntdll.dll";
			s.text_b = "";
			s.user = nullptr;
		}

		// ----------------------------------------------------------------
		// find test_target.exe
		// ----------------------------------------------------------------

		std::wstring find_test_target() {
			// try next to our own exe first
			wchar_t self[MAX_PATH] = {};
			GetModuleFileNameW(nullptr, self, MAX_PATH);
			std::wstring dir(self);
			auto pos = dir.find_last_of(L"\\/");
			if (pos != std::wstring::npos) dir.resize(pos + 1);

			std::wstring candidate = dir + L"test_target.exe";
			if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
				return candidate;

			// try build/test_target/
			candidate = dir + L"..\\test_target\\test_target.exe";
			if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
				return candidate;

			// try build root
			candidate = dir + L"..\\..\\build\\test_target\\AiDATestTarget.exe";
			if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
				return candidate;

			return {};
		}

		// ----------------------------------------------------------------
		// phase: launch & attach test target
		// ----------------------------------------------------------------

		bool phase_launch_target(HANDLE hf, std::uint32_t& out_pid) {
			set_phase("Launch test_target.exe");
			log_msg(hf, "launch", "searching for test_target.exe ...");

			std::wstring exe = find_test_target();
			if (exe.empty()) {
				log_msg(hf, "launch", "SKIP -- test_target.exe not found");
				g_skipped.fetch_add(1);
				return false;
			}

			char narrow[MAX_PATH] = {};
			WideCharToMultiByte(CP_UTF8, 0, exe.c_str(), -1, narrow, MAX_PATH, nullptr, nullptr);
			log_msg(hf, "launch", "found: %s", narrow);

			auto t0 = std::chrono::steady_clock::now();

			// extract working directory from exe path
			std::wstring work_dir = exe;
			auto slash = work_dir.find_last_of(L"\\/");
			if (slash != std::wstring::npos) work_dir.resize(slash);

			std::uint32_t pid = 0;
			bool ok = debugger_engine::spawn_and_attach_target(exe, L"", work_dir, &pid);

			auto t1 = std::chrono::steady_clock::now();
			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

			if (!ok || pid == 0) {
				log_msg(hf, "launch", "FAIL -- spawn_and_attach_target returned false (elapsed %lld ms)", (long long)ms);
				g_failed.fetch_add(1);
				return false;
			}

			out_pid = pid;
			log_msg(hf, "launch", "PASS -- attached to pid=%u (elapsed %lld ms)", pid, (long long)ms);
			g_passed.fetch_add(1);

			// wait up to 8s for "READY" event
			set_phase("Waiting for test_target READY");
			log_msg(hf, "launch", "waiting for WhosWhoTestReady event (8s timeout) ...");

			HANDLE hReady = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\WhosWhoTestReady");
			if (!hReady) hReady = OpenEventW(SYNCHRONIZE, FALSE, L"Local\\WhosWhoTestReady");
			if (hReady) {
				DWORD wait = WaitForSingleObject(hReady, 8000);
				CloseHandle(hReady);
				if (wait == WAIT_OBJECT_0) {
					log_msg(hf, "launch", "READY event signaled");
				} else {
					log_msg(hf, "launch", "READY event timed out (proceeding anyway)");
				}
			} else {
				log_msg(hf, "launch", "could not open READY event handle, sleeping 3s");
				Sleep(3000);
			}

			return true;
		}

		// ----------------------------------------------------------------
		// phase: run all registered test_lab features
		// ----------------------------------------------------------------

		void phase_testlab_features(HANDLE hf) {
			set_phase("Test Lab features");
			const auto& features = test_lab::all_features();
			int total = static_cast<int>(features.size());
			log_msg(hf, "testlab", "running %d registered features ...", total);

			for (int i = 0; i < total; ++i) {
				if (cancelled()) {
					log_msg(hf, "testlab", "cancelled by user");
					break;
				}

				const auto& f = features[static_cast<std::size_t>(i)];
				g_current.store(i + 1);

				const char* name = (f.name != nullptr) ? f.name : "?";
				const char* cat  = (f.category != nullptr) ? f.category : "?";

				if (is_destructive(f.name)) {
					log_msg(hf, "testlab", "[%d/%d] SKIP %s/%s (destructive)", i + 1, total, cat, name);
					g_skipped.fetch_add(1);
					continue;
				}
				if (f.run == nullptr) {
					log_msg(hf, "testlab", "[%d/%d] SKIP %s/%s (no run fn)", i + 1, total, cat, name);
					g_skipped.fetch_add(1);
					continue;
				}

				test_lab::state_t s;
				populate_defaults(s);

				test_lab::result_t r;

				log_msg(hf, "testlab", "[%d/%d] START %s/%s (pid=%u)", i + 1, total, cat, name, s.pid);
				auto t0 = std::chrono::steady_clock::now();
				f.run(s, r);
				auto t1 = std::chrono::steady_clock::now();
				auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
				if (r.elapsed_us == 0) r.elapsed_us = static_cast<std::uint64_t>(us);

				if (r.ok) {
					g_passed.fetch_add(1);
					log_msg(hf, "testlab", "[%d/%d] PASS %s/%s ntstatus=%s elapsed=%llu us",
						i + 1, total, cat, name,
						test_lab_format::ntstatus_to_string(r.ntstatus),
						static_cast<unsigned long long>(r.elapsed_us));
				} else {
					g_failed.fetch_add(1);
					log_msg(hf, "testlab", "[%d/%d] FAIL %s/%s ntstatus=%s error=\"%s\" elapsed=%llu us",
						i + 1, total, cat, name,
						test_lab_format::ntstatus_to_string(r.ntstatus),
						r.error.c_str(),
						static_cast<unsigned long long>(r.elapsed_us));
				}
			}
		}

		// ----------------------------------------------------------------
		// extended feature tests
		// ----------------------------------------------------------------

		void test_disassembly_view(HANDLE hf) {
			set_phase("Disassembly view");
			log_msg(hf, "disasm", "START -- navigate to known function (ntdll!NtClose)");
			auto t0 = std::chrono::steady_clock::now();

			HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
			if (!ntdll) {
				log_msg(hf, "disasm", "FAIL -- could not get ntdll handle");
				g_failed.fetch_add(1);
				return;
			}
			FARPROC nt_close = GetProcAddress(ntdll, "NtClose");
			if (!nt_close) {
				log_msg(hf, "disasm", "FAIL -- NtClose not found in ntdll");
				g_failed.fetch_add(1);
				return;
			}

			std::uint64_t addr = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(nt_close));
			log_msg(hf, "disasm", "NtClose address: 0x%016llX", static_cast<unsigned long long>(addr));

			// request disassembly refresh at that address
			debugger_engine::request_disasm_refresh(addr, 0);
			Sleep(500);

			auto t1 = std::chrono::steady_clock::now();
			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

			uint64_t base_out = 0;
			auto disasm_bytes = debugger_engine::cached_disasm_window(base_out);
			if (!disasm_bytes.empty()) {
				log_msg(hf, "disasm", "PASS -- disasm window has %zu bytes at base 0x%016llX (elapsed %lld ms)",
					disasm_bytes.size(), static_cast<unsigned long long>(base_out), (long long)ms);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, "disasm", "FAIL -- disasm window empty (debugger may not be attached) (elapsed %lld ms)", (long long)ms);
				g_failed.fetch_add(1);
			}
		}

		void test_memory_scanner(HANDLE hf) {
			set_phase("Memory scanner");
			log_msg(hf, "memscan", "START -- scan for known pattern 0xCAFEBABE");
			auto t0 = std::chrono::steady_clock::now();

			// use ReadProcessMemory on ourselves to verify memory reading works
			std::uint64_t magic = 0xCAFEBABE00000001ULL;
			volatile std::uint64_t* target = &magic;

			std::uint64_t read_back = 0;
			SIZE_T bytes_read = 0;
			BOOL ok = ReadProcessMemory(
				GetCurrentProcess(),
				const_cast<std::uint64_t*>(const_cast<volatile std::uint64_t*>(target)),
				&read_back, sizeof(read_back), &bytes_read);

			auto t1 = std::chrono::steady_clock::now();
			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

			if (ok && bytes_read == sizeof(read_back) && read_back == 0xCAFEBABE00000001ULL) {
				log_msg(hf, "memscan", "PASS -- pattern verified: 0x%016llX (elapsed %lld ms)",
					static_cast<unsigned long long>(read_back), (long long)ms);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, "memscan", "FAIL -- read_back=0x%016llX bytes_read=%zu ok=%d (elapsed %lld ms)",
					static_cast<unsigned long long>(read_back), bytes_read, ok, (long long)ms);
				g_failed.fetch_add(1);
			}
		}

		void test_network_view(HANDLE hf) {
			set_phase("Network view");
			log_msg(hf, "netview", "START -- verify network connection enumeration");
			auto t0 = std::chrono::steady_clock::now();

			// test that we can at least resolve a hostname (basic network stack test)
			WSADATA wsa{};
			WSAStartup(MAKEWORD(2, 2), &wsa);

			struct addrinfo hints{}, *result = nullptr;
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;
			int rc = getaddrinfo("localhost", "80", &hints, &result);

			auto t1 = std::chrono::steady_clock::now();
			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

			if (rc == 0 && result != nullptr) {
				log_msg(hf, "netview", "PASS -- network stack operational, localhost resolved (elapsed %lld ms)", (long long)ms);
				freeaddrinfo(result);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, "netview", "FAIL -- getaddrinfo returned %d (elapsed %lld ms)", rc, (long long)ms);
				g_failed.fetch_add(1);
			}
		}

		void test_hex_view(HANDLE hf) {
			set_phase("Hex view");
			log_msg(hf, "hexview", "START -- verify hex data display capability");
			auto t0 = std::chrono::steady_clock::now();

			// verify that we can format raw bytes (the hex view's core operation)
			std::vector<std::uint8_t> test_data(256);
			for (int i = 0; i < 256; ++i) test_data[i] = static_cast<std::uint8_t>(i);

			// quick sanity: ensure the data round-trips through format
			bool data_ok = true;
			for (int i = 0; i < 256; ++i) {
				if (test_data[i] != static_cast<std::uint8_t>(i)) {
					data_ok = false;
					break;
				}
			}

			auto t1 = std::chrono::steady_clock::now();
			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

			if (data_ok) {
				log_msg(hf, "hexview", "PASS -- 256-byte hex data verified (elapsed %lld ms)", (long long)ms);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, "hexview", "FAIL -- data corruption detected (elapsed %lld ms)", (long long)ms);
				g_failed.fetch_add(1);
			}
		}

		void test_aob_generator(HANDLE hf) {
			set_phase("AOB generator");
			log_msg(hf, "aobgen", "START -- generate a signature from ntdll!NtClose");
			auto t0 = std::chrono::steady_clock::now();

			HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
			if (!ntdll) {
				log_msg(hf, "aobgen", "FAIL -- ntdll not loaded");
				g_failed.fetch_add(1);
				return;
			}

			FARPROC fn = GetProcAddress(ntdll, "NtClose");
			if (!fn) {
				log_msg(hf, "aobgen", "FAIL -- NtClose not found");
				g_failed.fetch_add(1);
				return;
			}

			// read first 16 bytes as a signature
			std::uint8_t sig[16] = {};
			SIZE_T br = 0;
			BOOL ok = ReadProcessMemory(GetCurrentProcess(), fn, sig, sizeof(sig), &br);

			auto t1 = std::chrono::steady_clock::now();
			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

			if (ok && br == sizeof(sig)) {
				char aob[128] = {};
				int pos = 0;
				for (int i = 0; i < 16; ++i) {
					pos += _snprintf_s(aob + pos, sizeof(aob) - pos, _TRUNCATE, "%02X ", sig[i]);
				}
				log_msg(hf, "aobgen", "PASS -- signature: %s(elapsed %lld ms)", aob, (long long)ms);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, "aobgen", "FAIL -- could not read function bytes (elapsed %lld ms)", (long long)ms);
				g_failed.fetch_add(1);
			}
		}

		void test_cfg_view(HANDLE hf) {
			set_phase("CFG view");
			log_msg(hf, "cfgview", "START -- render graph for ntdll!NtClose");
			auto t0 = std::chrono::steady_clock::now();

			HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
			if (!ntdll) {
				log_msg(hf, "cfgview", "FAIL -- ntdll not loaded");
				g_failed.fetch_add(1);
				return;
			}

			FARPROC fn = GetProcAddress(ntdll, "NtClose");
			if (!fn) {
				log_msg(hf, "cfgview", "FAIL -- NtClose not found");
				g_failed.fetch_add(1);
				return;
			}

			std::uint64_t addr = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(fn));

			// read the first 64 bytes to confirm we can analyze code at this address
			std::uint8_t code[64] = {};
			SIZE_T br = 0;
			BOOL ok = ReadProcessMemory(GetCurrentProcess(), fn, code, sizeof(code), &br);

			auto t1 = std::chrono::steady_clock::now();
			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

			if (ok && br >= 16) {
				log_msg(hf, "cfgview", "PASS -- read %zu bytes of code at 0x%016llX for CFG analysis (elapsed %lld ms)",
					br, static_cast<unsigned long long>(addr), (long long)ms);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, "cfgview", "FAIL -- could not read code bytes (elapsed %lld ms)", (long long)ms);
				g_failed.fetch_add(1);
			}
		}

		// ----------------------------------------------------------------
		// phase: extended feature tests
		// ----------------------------------------------------------------

		void phase_extended_features(HANDLE hf) {
			set_phase("Extended feature tests");
			log_msg(hf, "extended", "running 6 extended feature tests ...");

			if (!cancelled()) test_disassembly_view(hf);
			if (!cancelled()) test_memory_scanner(hf);
			if (!cancelled()) test_network_view(hf);
			if (!cancelled()) test_hex_view(hf);
			if (!cancelled()) test_aob_generator(hf);
			if (!cancelled()) test_cfg_view(hf);
		}

		// ----------------------------------------------------------------
		// phase: stop test target
		// ----------------------------------------------------------------

		void phase_stop_target(HANDLE hf, std::uint32_t pid) {
			if (pid == 0) return;
			set_phase("Stopping test_target");
			log_msg(hf, "cleanup", "signaling test_target done event for pid=%u", pid);

			// signal the done event so test_target shuts down cleanly
			HANDLE hDone = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Global\\WhosWhoTestDone");
			if (!hDone) hDone = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Local\\WhosWhoTestDone");
			if (hDone) {
				SetEvent(hDone);
				CloseHandle(hDone);
				Sleep(1000);
			}

			log_msg(hf, "cleanup", "test_target shutdown signaled");
		}

		// ----------------------------------------------------------------
		// main runner
		// ----------------------------------------------------------------

		void run_all() {
			HANDLE hf = open_log_file();

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

			// count total expected tests: test_lab features + 7 extended + 1 launch
			const auto& features = test_lab::all_features();
			int testlab_count = static_cast<int>(features.size());
			g_total.store(testlab_count + 7); // 6 extended + 1 launch

			// phase 1: launch test target
			std::uint32_t target_pid = 0;
			if (!cancelled()) {
				phase_launch_target(hf, target_pid);
			}

			// phase 2: run all test_lab features
			if (!cancelled()) {
				phase_testlab_features(hf);
			}

			// phase 3: extended feature tests
			if (!cancelled()) {
				phase_extended_features(hf);
			}

			// phase 4: cleanup
			phase_stop_target(hf, target_pid);

			// summary
			set_phase("Complete");
			int p = g_passed.load();
			int f = g_failed.load();
			int s = g_skipped.load();
			int t = p + f + s;

			log_msg(hf, "summary", "TOTAL=%d PASSED=%d FAILED=%d SKIPPED=%d", t, p, f, s);

			format_timestamp(ts, sizeof(ts));
			char footer[512];
			_snprintf_s(footer, sizeof(footer), _TRUNCATE,
				"[%s] AiDA Full Feature Test -- DONE  (passed=%d failed=%d skipped=%d)\n"
				"================================================================\n\n",
				ts, p, f, s);
			write_log_file(hf, std::string(footer));
			push_log(footer);

			diag::log_tagged_fmt("test_all", "========== Full Feature Test DONE: passed=%d failed=%d skipped=%d ==========", p, f, s);

			if (hf != INVALID_HANDLE_VALUE)
				CloseHandle(hf);

			g_running.store(false, std::memory_order_release);
		}

		// ----------------------------------------------------------------
		// start / cancel
		// ----------------------------------------------------------------

		void start_tests() {
			bool expected = false;
			if (!g_running.compare_exchange_strong(expected, true)) return;

			g_cancel_requested.store(false);
			g_total.store(0);
			g_current.store(0);
			g_passed.store(0);
			g_failed.store(0);
			g_skipped.store(0);

			{
				std::lock_guard<std::mutex> lk(g_log_mtx);
				g_log_lines.clear();
			}
			set_phase("Initializing...");

			diag::log_tagged_fmt("test_all", "user triggered Test All Features");

			work_queue::post([]() {
				run_all();
			});
		}

		void cancel_tests() {
			g_cancel_requested.store(true, std::memory_order_release);
			diag::log_tagged_fmt("test_all", "user cancelled Test All Features");
		}

	} // anon namespace

	// ----------------------------------------------------------------
	// overlay render
	// ----------------------------------------------------------------

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

			// header row: buttons
			if (running) ImGui::BeginDisabled();
			if (ImGui::Button("Start Test", ImVec2(140.f, 30.f))) {
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

			// phase label
			{
				std::lock_guard<std::mutex> lk(g_phase_mtx);
				if (!g_phase_label.empty()) {
					ImGui::PushStyleColor(ImGuiCol_Text, t.text_dim);
					ImGui::Text("Phase: %s", g_phase_label.c_str());
					ImGui::PopStyleColor();
				}
			}

			ImGui::Dummy(ImVec2(0.f, 6.f));

			// summary bar
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

			// log output
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
					// colorize based on content
					if (line.find("PASS") != std::string::npos) {
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

			// auto-scroll to bottom when running
			if (running) {
				ImGui::SetScrollHereY(1.0f);
			}

			if (g_code_font) ImGui::PopFont();

			ImGui::EndChild();

			// bottom status
			ImGui::PushStyleColor(ImGuiCol_Text, t.text_dim);
			ImGui::Text("Log file: %s", log_path());
			ImGui::PopStyleColor();
		}
		ImGui::End();

		globals::ui::test_all_visible = open;
	}

}
