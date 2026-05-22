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

#include "../infra/work_queue.hpp"
#include "../ui/theme.hpp"
#include "../debugger/debugger_engine.hpp"
#include "../runtime/run_target.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../scanner/memory_scanner.hpp"
#include "../scanner/aob_generator.hpp"
#include "../disasm/cfg_view.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../helpers/globals.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#pragma comment(lib, "ws2_32.lib")

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace test_all_features {

	namespace {


		std::atomic<bool> g_running{ false };
		std::atomic<bool> g_cancel_requested{ false };

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


		const char* log_path() {
			return "C:\\Users\\Public\\Desktop\\aida_full_test.log";
		}


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

		void set_phase(const char* label) {
			std::lock_guard<std::mutex> lk(g_phase_mtx);
			g_phase_label = (label != nullptr) ? label : "";
		}

		bool cancelled() {
			return g_cancel_requested.load(std::memory_order_acquire);
		}

		int running_done() {
			return g_passed.load() + g_failed.load() + g_skipped.load();
		}

		void log_phase_begin(HANDLE hf, const char* phase) {
			log_msg(hf, "phase", "BEGIN %s | running totals pass=%d fail=%d skip=%d done=%d",
				phase, g_passed.load(), g_failed.load(), g_skipped.load(), running_done());
		}

		void log_phase_end(HANDLE hf, const char* phase) {
			log_msg(hf, "phase", "END %s | running totals pass=%d fail=%d skip=%d done=%d",
				phase, g_passed.load(), g_failed.load(), g_skipped.load(), running_done());
		}


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


		std::uint32_t current_target_pid() {
			return g_target_pid.load(std::memory_order_acquire);
		}

		std::uint64_t current_target_addr() {
			return g_target_addr.load(std::memory_order_acquire);
		}

		std::uint64_t current_target_image_base() {
			return g_target_image_base.load(std::memory_order_acquire);
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
			bool ok = debugger_engine::spawn_and_attach_target(exe, L"--no-external --duration 300 --net-rate 2000", work_dir, &pid);

			auto t1 = std::chrono::steady_clock::now();
			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

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

			bool attach_ok = verify_driver_attach(hf, pid);
			if (!attach_ok) {
				log_msg(hf, "launch", "FAIL -- driver attach verification failed for pid=%u; feature tests cannot trust target reads", pid);
			} else {
				log_msg(hf, "launch", "PASS -- target launched and driver attach verified pid=%u", pid);
			}

			log_phase_end(hf, "launch target");
			return attach_ok;
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
				populate_defaults(s, target_pid);

				if (std::strcmp(name, "PMOD") == 0) {
					s.u32_a = 2;
				} else if (std::strcmp(name, "PRED") == 0) {
					s.u32_a = 1;
				} else if (std::strcmp(name, "NLOG") == 0) {
					s.u32_a = 1;
				} else if (std::strcmp(name, "REGISTER_PID") == 0 || std::strcmp(name, "UNREGISTER_PID") == 0) {
					char tmp[MAX_PATH];
					GetTempPathA(MAX_PATH, tmp);
					s.text_a = std::string(tmp) + "aida_sandbox_test";
					if (s.pid == 0) {
						s.pid = static_cast<std::uint32_t>(GetCurrentProcessId());
					}
				} else if (std::strcmp(name, "PCEX") == 0) {
					char tmp[MAX_PATH];
					GetTempPathA(MAX_PATH, tmp);
					s.text_a = std::string(tmp) + "aida_test_capture.pcap";
				} else if (std::strcmp(name, "PHYS") == 0 || std::strcmp(name, "MEX") == 0 || std::strcmp(name, "V2P") == 0) {
					std::uint64_t saved = g_saved_dtb.load(std::memory_order_acquire);
					if (saved != 0) {
						s.u64_a = saved;
						log_msg(hf, "testlab", "[%d/%d] DTB-inject %s: injecting saved_dtb=0x%016llX into u64_a",
							i + 1, total, name, static_cast<unsigned long long>(saved));
					} else {
						log_msg(hf, "testlab", "[%d/%d] DTB-inject %s: WARN no saved dtb (u64_a=0); test may fail",
							i + 1, total, name);
					}
				}

				test_lab::result_t r;

				log_msg(hf, "testlab", "[%d/%d] START %s/%s pid=%u tid=%u addr=0x%016llX u64_a=0x%016llX u32_a=%u u32_b=%u size=%u text_a=\"%.32s\"",
					i + 1, total, cat, name, s.pid, s.tid,
					static_cast<unsigned long long>(s.addr),
					static_cast<unsigned long long>(s.u64_a),
					s.u32_a, s.u32_b, s.size,
					s.text_a.empty() ? "(none)" : s.text_a.c_str());
				auto t0 = std::chrono::steady_clock::now();
				f.run(s, r);
				auto t1 = std::chrono::steady_clock::now();
				auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
				if (r.elapsed_us == 0) r.elapsed_us = static_cast<std::uint64_t>(us);

				if (std::strcmp(name, "DTB") == 0 && r.ok) {
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
			}
			log_phase_end(hf, "testlab features");
		}


		bool require_target(HANDLE hf, const char* tag) {
			std::uint32_t pid = current_target_pid();
			bool attached = g_driver_attached.load(std::memory_order_acquire);
			if (pid == 0 || !attached || driver_bridge::attached_pid() != pid) {
				log_msg(hf, tag, "FAIL -- no verified attached target (pid=%u attached=%d driver_pid=%u)",
					pid, static_cast<int>(attached), driver_bridge::attached_pid());
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
			set_phase("Memory scanner");
			log_msg(hf, tag, "START -- scan attached target for resident PE marker string");
			auto t0 = std::chrono::steady_clock::now();

			if (!require_target(hf, tag)) return;

			std::uint32_t pid = current_target_pid();

			memory_scanner::reset_scan();
			memory_scanner::scan_config_t cfg;
			cfg.value_type = memory_scanner::value_type_t::string_ascii;
			cfg.scan_mode = memory_scanner::scan_mode_t::exact;
			cfg.value_text = "This program cannot be run in DOS mode";
			cfg.writable_only = false;
			cfg.executable_exclude = false;

			log_msg(hf, tag, "first_scan ASCII \"%s\" against pid=%u", cfg.value_text.c_str(), pid);
			bool ok = memory_scanner::first_scan(cfg);

			for (int i = 0; i < 100; ++i) {
				if (cancelled()) break;
				if (!memory_scanner::g_state.scanning.load()) break;
				Sleep(100);
			}

			std::size_t found = 0;
			{
				std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
				found = memory_scanner::g_state.results.size();
			}

			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - t0).count();

			if (ok && found > 0) {
				std::uint64_t first_addr = 0;
				{
					std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
					if (!memory_scanner::g_state.results.empty())
						first_addr = memory_scanner::g_state.results.front().address;
				}
				log_msg(hf, tag, "PASS -- scanner found %zu live matches in target (first=0x%016llX) (elapsed %lld ms)",
					found, static_cast<unsigned long long>(first_addr), (long long)ms);
				g_passed.fetch_add(1);
				return;
			}

			log_msg(hf, tag, "scanner string scan empty (ok=%d found=%zu); falling back to direct driver read of image base",
				static_cast<int>(ok), found);

			std::uint64_t image_base = current_target_image_base();
			std::vector<std::uint8_t> sample;
			bool read_ok = (image_base != 0) &&
				driver_bridge::read_memory_for(pid, image_base, 2, sample);
			ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - t0).count();

			if (read_ok && sample.size() >= 2 && sample[0] == 'M' && sample[1] == 'Z') {
				log_msg(hf, tag, "PASS -- fallback driver read confirmed MZ at target image base 0x%016llX (elapsed %lld ms)",
					static_cast<unsigned long long>(image_base), (long long)ms);
				g_passed.fetch_add(1);
			} else {
				log_msg(hf, tag, "FAIL -- scanner found 0 matches and fallback read failed (read_ok=%d bytes=%zu) (elapsed %lld ms)",
					static_cast<int>(read_ok), sample.size(), (long long)ms);
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

			auto conns = driver_bridge::enumerate_connections(pid, 0);
			auto sockets = driver_bridge::get_socket_handles(pid);
			auto tcpip = driver_bridge::dump_tcpip_connections(pid, 0);

			std::size_t observed = conns.size() + sockets.size() + tcpip.size();

			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - t0).count();

			log_msg(hf, tag, "target pid=%u connections=%zu sockets=%zu tcpip=%zu",
				pid, conns.size(), sockets.size(), tcpip.size());

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
					log_msg(hf, tag, "FAIL -- target had 0 endpoints though driver enumerated %zu system-wide; target not network-active (elapsed %lld ms)",
						all_conns.size(), (long long)ms);
				} else {
					log_msg(hf, tag, "FAIL -- driver returned 0 connections target-scoped and system-wide (elapsed %lld ms)", (long long)ms);
				}
				g_failed.fetch_add(1);
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


		void phase_stop_target(HANDLE hf, std::uint32_t pid) {
			if (pid == 0) return;
			set_phase("Stopping test_target");
			log_msg(hf, "cleanup", "signaling test_target done event for pid=%u", pid);

			HANDLE hDone = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Global\\WhosWhoTestDone");
			if (!hDone) hDone = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Local\\WhosWhoTestDone");
			if (hDone) {
				SetEvent(hDone);
				CloseHandle(hDone);
				log_msg(hf, "cleanup", "WhosWhoTestDone signaled; waiting for process to exit...");
			} else {
				log_msg(hf, "cleanup", "could not open WhosWhoTestDone event; sending TerminateProcess directly");
			}

			HANDLE hProc = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, static_cast<DWORD>(pid));
			if (hProc) {
				DWORD wait_result = WaitForSingleObject(hProc, 6000);
				if (wait_result != WAIT_OBJECT_0) {
					log_msg(hf, "cleanup", "process pid=%u did not exit in 6s (wait_result=%lu); forcing TerminateProcess", pid, static_cast<unsigned long>(wait_result));
					TerminateProcess(hProc, 0);
					WaitForSingleObject(hProc, 2000);
				} else {
					log_msg(hf, "cleanup", "process pid=%u exited cleanly", pid);
				}
				CloseHandle(hProc);
			} else {
				log_msg(hf, "cleanup", "could not open process handle for pid=%u (err=%lu); assuming already exited", pid, static_cast<unsigned long>(GetLastError()));
			}

			log_msg(hf, "cleanup", "test_target shutdown complete");
		}


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

			const auto& features = test_lab::all_features();
			int testlab_count = static_cast<int>(features.size());
			g_total.store(testlab_count + 250);

			std::uint32_t target_pid = 0;
			bool attach_ok = false;
			if (!cancelled()) {
				attach_ok = phase_launch_target(hf, target_pid);
			}

			log_msg(hf, "summary", "post-launch state: target_pid=%u driver_attached=%d attach_ok=%d",
				current_target_pid(),
				static_cast<int>(g_driver_attached.load()),
				static_cast<int>(attach_ok));

			if (!cancelled()) {
				phase_testlab_features(hf, target_pid);
			}

			if (!cancelled()) {
				phase_extended_features(hf);
			}

			if (!cancelled()) {
				set_phase("Debugger feature tests");
				log_phase_begin(hf, "debugger feature tests");
				phase_debugger_tests(hf, g_passed, g_failed, g_skipped, cancelled);
				log_phase_end(hf, "debugger feature tests");
			}

			if (!cancelled()) {
				set_phase("Scanner feature tests");
				log_phase_begin(hf, "scanner feature tests");
				phase_scanner_tests(hf, g_passed, g_failed, g_skipped, cancelled);
				log_phase_end(hf, "scanner feature tests");
			}

			if (!cancelled()) {
				set_phase("Analysis feature tests");
				log_phase_begin(hf, "analysis feature tests");
				phase_analysis_tests(hf, g_passed, g_failed, g_skipped, cancelled);
				log_phase_end(hf, "analysis feature tests");
			}

			if (!cancelled()) {
				set_phase("Network feature tests");
				log_phase_begin(hf, "network feature tests");
				phase_network_tests(hf, g_passed, g_failed, g_skipped, cancelled);
				log_phase_end(hf, "network feature tests");
			}

			if (!cancelled()) {
				set_phase("Burp suite feature tests");
				log_phase_begin(hf, "burp suite feature tests");
				phase_burp_tests(hf, g_passed, g_failed, g_skipped, cancelled);
				log_phase_end(hf, "burp suite feature tests");
			}

			if (!cancelled()) {
				set_phase("Disassembly & decompiler tests");
				log_phase_begin(hf, "disassembly & decompiler tests");
				phase_disasm_tests(hf, g_passed, g_failed, g_skipped, cancelled);
				log_phase_end(hf, "disassembly & decompiler tests");
			}

			if (!cancelled()) {
				set_phase("MCP tool tests");
				log_phase_begin(hf, "MCP tool tests");
				phase_mcp_tests(hf, g_passed, g_failed, g_skipped, cancelled);
				log_phase_end(hf, "MCP tool tests");
			}

			phase_stop_target(hf, target_pid);

			set_phase("Complete");
			int p = g_passed.load();
			int f = g_failed.load();
			int s = g_skipped.load();
			int t = p + f + s;

			log_msg(hf, "summary", "================ VALIDATION SUMMARY ================");
			log_msg(hf, "summary", "target_pid=%u driver_attached=%d image_base=0x%016llX known_good_addr=0x%016llX",
				current_target_pid(),
				static_cast<int>(g_driver_attached.load()),
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

			log_msg(hf, "summary", "TOTAL=%d PASSED=%d FAILED=%d SKIPPED=%d SUSPECT=%d", t, p, f, s, suspect);

			format_timestamp(ts, sizeof(ts));
			char footer[512];
			_snprintf_s(footer, sizeof(footer), _TRUNCATE,
				"[%s] AiDA Full Feature Test -- DONE  (passed=%d failed=%d skipped=%d suspect=%d)\n"
				"================================================================\n\n",
				ts, p, f, s, suspect);
			write_log_file(hf, std::string(footer));
			push_log(footer);

			diag::log_tagged_fmt("test_all", "========== Full Feature Test DONE: passed=%d failed=%d skipped=%d suspect=%d ==========", p, f, s, suspect);

			if (hf != INVALID_HANDLE_VALUE)
				CloseHandle(hf);

			g_running.store(false, std::memory_order_release);
		}


		void start_tests() {
			bool expected = false;
			if (!g_running.compare_exchange_strong(expected, true)) return;

			g_cancel_requested.store(false);
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

			diag::log_tagged_fmt("test_all", "user triggered Test All Features");

			work_queue::post([]() {
				run_all();
			});
		}

		void cancel_tests() {
			g_cancel_requested.store(true, std::memory_order_release);
			diag::log_tagged_fmt("test_all", "user cancelled Test All Features");
		}

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
