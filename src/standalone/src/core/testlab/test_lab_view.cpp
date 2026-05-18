#include "test_lab_view.hpp"
#include "test_lab.hpp"
#include "test_lab_format.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "../infra/work_queue.hpp"
#include "../ui/theme.hpp"
#include "../ui/ui_anim.hpp"
#include "../../../../driver/comm.h"
#include "../runtime/shadow_fs_client.hpp"
#include "../../helpers/diag_log.hpp"

#include <Windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace test_lab_view {

	namespace {

		int                                 g_selected_idx = -1;
		test_lab::state_t                   g_state;
		std::shared_ptr<test_lab::result_t> g_result = std::make_shared<test_lab::result_t>();
		std::mutex                          g_result_mtx;

		const char* driver_label(test_lab::driver_e d) {
			switch (d) {
				case test_lab::driver_e::whoswho:  return "WHO";
				case test_lab::driver_e::shadowfs: return "SFS";
				case test_lab::driver_e::sentinel: return "SEN";
			}
			return "?";
		}

		ImU32 driver_badge_color(test_lab::driver_e d, float alpha) {
			const auto& t = aida::ui::resolved();
			switch (d) {
				case test_lab::driver_e::whoswho:  return aida::ui::with_alpha(t.accent_u32, alpha);
				case test_lab::driver_e::shadowfs: return aida::ui::with_alpha(t.info, alpha);
				case test_lab::driver_e::sentinel: return aida::ui::with_alpha(t.warning, alpha);
			}
			return aida::ui::with_alpha(t.text_dim, alpha);
		}

		ImU32 status_dot_color(test_lab::run_state_e s, bool ok, float alpha) {
			const auto& t = aida::ui::resolved();
			switch (s) {
				case test_lab::run_state_e::idle:     return aida::ui::with_alpha(t.text_dim, alpha);
				case test_lab::run_state_e::running:  return aida::ui::with_alpha(t.accent_u32, alpha);
				case test_lab::run_state_e::complete: return aida::ui::with_alpha(ok ? t.success : t.error, alpha);
			}
			return aida::ui::with_alpha(t.text_dim, alpha);
		}

		std::atomic<bool> g_run_all_active{ false };
		std::atomic<int>  g_run_all_current{ 0 };
		std::atomic<int>  g_run_all_total{ 0 };
		std::atomic<int>  g_run_all_ok{ 0 };
		std::atomic<int>  g_run_all_fail{ 0 };
		std::atomic<int>  g_run_all_skipped{ 0 };
		std::mutex        g_run_all_status_mtx;
		std::string       g_run_all_status_line;
		std::string       g_run_all_current_name;

		const char* run_all_log_path() {
			return "C:\\Users\\Public\\Desktop\\aida_test_results.log";
		}

		bool is_destructive_by_name(const char* name) {
			if (name == nullptr) return false;
			static const std::unordered_set<std::string> kSkip = {
				"ABRT",
				"DBGA",
				"RECU",
				"ADMP",
				"RC",
				"CR",
				"SRVT",
				"SRV2",
				"PINJ",
				"TSR",
				"PCEX",
				"HVDT",
				"CANR",
				"CANQ"
			};
			return kSkip.find(std::string(name)) != kSkip.end();
		}

		void populate_safe_defaults(test_lab::state_t& s) {
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

		void format_local_timestamp(char* out, std::size_t cap) {
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

		const char* driver_name(test_lab::driver_e d) {
			switch (d) {
				case test_lab::driver_e::whoswho:  return "whoswho";
				case test_lab::driver_e::shadowfs: return "shadowfs";
				case test_lab::driver_e::sentinel: return "sentinel";
			}
			return "unknown";
		}

		void append_log_line(HANDLE hFile, const std::string& line) {
			if (hFile == INVALID_HANDLE_VALUE) return;
			DWORD wrote = 0;
			WriteFile(hFile, line.data(), static_cast<DWORD>(line.size()), &wrote, nullptr);
			FlushFileBuffers(hFile);
		}

		void append_log_starting(HANDLE hFile,
			const test_lab::feature_t& f,
			const test_lab::state_t& s)
		{
			char ts[40];
			format_local_timestamp(ts, sizeof(ts));
			std::string line;
			line.reserve(256);
			line.append("[").append(ts).append("] [").append(driver_name(f.driver)).append("] ");
			line.append(f.category != nullptr ? f.category : "?").append("/");
			line.append(f.name != nullptr ? f.name : "?");
			line.append(" -- STARTING\n");
			char tmp[160];
			std::snprintf(tmp, sizeof(tmp), "    state: pid=%u tid=%u addr=0x%llX size=%u u32_a=%u\n",
				static_cast<unsigned>(s.pid),
				static_cast<unsigned>(s.tid),
				static_cast<unsigned long long>(s.addr),
				static_cast<unsigned>(s.size),
				static_cast<unsigned>(s.u32_a));
			line.append(tmp);
			append_log_line(hFile, line);
		}

		void append_log_skip(HANDLE hFile, const test_lab::feature_t& f, const char* reason) {
			char ts[40];
			format_local_timestamp(ts, sizeof(ts));
			std::string line;
			line.reserve(256);
			line.append("[").append(ts).append("] [").append(driver_name(f.driver)).append("] ");
			line.append(f.category != nullptr ? f.category : "?").append("/");
			line.append(f.name != nullptr ? f.name : "?");
			line.append(" -- SKIPPED (").append(reason != nullptr ? reason : "no reason").append(")\n");
			append_log_line(hFile, line);
		}

		void append_log_result(HANDLE hFile,
			const test_lab::feature_t& f,
			const test_lab::state_t& s,
			const test_lab::result_t& r,
			std::uint64_t elapsed_us)
		{
			char ts[40];
			format_local_timestamp(ts, sizeof(ts));
			std::string line;
			line.reserve(1024);
			line.append("[").append(ts).append("] [").append(driver_name(f.driver)).append("] ");
			line.append(f.category != nullptr ? f.category : "?").append("/");
			line.append(f.name != nullptr ? f.name : "?");
			line.append(r.ok ? " -- OK" : " -- FAIL");
			char tmp[64];
			std::snprintf(tmp, sizeof(tmp), " ntstatus=%s bytes=%u elapsed_us=%llu\n",
				test_lab_format::ntstatus_to_string(r.ntstatus),
				static_cast<unsigned>(r.bytes_returned),
				static_cast<unsigned long long>(elapsed_us));
			line.append(tmp);

			std::snprintf(tmp, sizeof(tmp), "    state: pid=%u tid=%u addr=0x%llX size=%u u32_a=%u\n",
				static_cast<unsigned>(s.pid),
				static_cast<unsigned>(s.tid),
				static_cast<unsigned long long>(s.addr),
				static_cast<unsigned>(s.size),
				static_cast<unsigned>(s.u32_a));
			line.append(tmp);

			if (!r.ok && !r.error.empty()) {
				line.append("    error: ").append(r.error).append("\n");
			}
			for (const auto& p : r.parsed) {
				line.append("    ").append(p.label).append(": ").append(p.value).append("\n");
			}
			if (!r.raw.empty()) {
				std::size_t limit = r.raw.size();
				if (limit > 64) limit = 64;
				line.append("    raw[0..");
				std::snprintf(tmp, sizeof(tmp), "%zu]: ", limit);
				line.append(tmp);
				for (std::size_t i = 0; i < limit; ++i) {
					std::snprintf(tmp, sizeof(tmp), "%02X ", static_cast<unsigned>(r.raw[i]));
					line.append(tmp);
				}
				line.append("\n");
			}
			append_log_line(hFile, line);
		}

		HANDLE open_log_for_append() {
			return CreateFileA(
				run_all_log_path(),
				FILE_APPEND_DATA | SYNCHRONIZE,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				nullptr,
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				nullptr);
		}

		bool name_starts_with(const char* name, const char* prefix) {
			if (name == nullptr || prefix == nullptr) return false;
			std::size_t i = 0;
			while (prefix[i] != '\0') {
				if (name[i] == '\0' || name[i] != prefix[i]) return false;
				++i;
			}
			return true;
		}

		struct run_all_cache_t {
			std::uint64_t dtb = 0;
			std::uint64_t base = 0;
			std::uint64_t alloc_addr = 0;
			bool sandbox_self_registered = false;
			bool shadowfs_self_registered = false;
		};

		const char* shadowfs_sandbox_root_a() {
			return "C:\\Users\\Public\\Desktop\\aida_test_sandbox\\";
		}

		const wchar_t* shadowfs_sandbox_root_w() {
			return L"C:\\Users\\Public\\Desktop\\aida_test_sandbox\\";
		}

		std::uint64_t resolve_ntdll_base() {
			HMODULE h = GetModuleHandleW(L"ntdll.dll");
			if (h == nullptr) return 0;
			return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(h));
		}

		void prime_run_all_cache(run_all_cache_t& cache) {
			cache.dtb = 0;
			cache.base = 0;
			cache.alloc_addr = 0;
			cache.sandbox_self_registered = false;
			cache.shadowfs_self_registered = false;
			if (!device || !device->is_connected()) return;
			std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
			device->set_process_id(self_pid);
			device->solve_dtb();
			cache.dtb = device->get_dtb();
			cache.base = device->get_base_address();
			std::uint64_t alloc_va = device->allocate_memory(0x1000);
			if (alloc_va != 0) cache.alloc_addr = alloc_va;
			CreateDirectoryA(shadowfs_sandbox_root_a(), nullptr);
			diag::log_tagged_fmt("testlab",
				"run-all cache primed: pid=%u dtb=0x%016llX base=0x%016llX alloc_addr=0x%016llX",
				static_cast<unsigned>(self_pid),
				static_cast<unsigned long long>(cache.dtb),
				static_cast<unsigned long long>(cache.base),
				static_cast<unsigned long long>(cache.alloc_addr));
		}

		void apply_smart_defaults(const test_lab::feature_t& f,
			test_lab::state_t& s,
			run_all_cache_t& cache)
		{
			const char* name = f.name;
			if (name == nullptr) return;

			if (name_starts_with(name, "PHYS") ||
				name_starts_with(name, "V2P"))
			{
				s.u64_a = cache.dtb;
				if (s.addr == 0) {
					if (cache.base != 0) {
						s.addr = cache.base;
					} else {
						HMODULE h_self = GetModuleHandleW(nullptr);
						if (h_self != nullptr) {
							s.addr = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(h_self));
						}
					}
				}
				if (s.size == 0) s.size = 256;
				return;
			}
			if (name_starts_with(name, "DPIN")) {
				s.u64_a = cache.dtb;
				return;
			}
			if (name_starts_with(name, "MEX")) {
				s.u64_a = cache.dtb;
				std::uint64_t mex_base = resolve_ntdll_base();
				if (mex_base == 0) mex_base = cache.base;
				if (mex_base == 0) {
					HMODULE h_self = GetModuleHandleW(nullptr);
					if (h_self != nullptr) {
						mex_base = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(h_self));
					}
				}
				if (mex_base != 0) s.addr = mex_base;
				if (s.text_a.empty() || s.text_a == "ntdll.dll") s.text_a = "ntdll.dll";
				s.text_b = "NtClose";
				return;
			}
			if (name_starts_with(name, "FM")) {
				if (cache.alloc_addr != 0) {
					s.addr = cache.alloc_addr;
				}
				s.size = 64;
				return;
			}
			if (name_starts_with(name, "PMOD")) {
				s.text_a = "tag1|0|6|80|0|DEAD|BEEF";
				s.u32_a = 0;
				return;
			}
			if (name_starts_with(name, "PM")) {
				if (cache.alloc_addr != 0) {
					s.addr = cache.alloc_addr;
				}
				s.size = 64;
				s.u32_a = 0x04u;
				return;
			}
			if (name_starts_with(name, "PRED") || name_starts_with(name, "CKIL")) {
				s.text_a = "tcp://127.0.0.1:80";
				s.text_b = "tcp://127.0.0.1:443";
				s.u32_a = 0;
				return;
			}
			if (name_starts_with(name, "DNSS")) {
				s.text_a = "test.example.com";
				s.text_b = "127.0.0.1";
				s.u32_a = 0;
				return;
			}
			if (name_starts_with(name, "DPRT")) {
				s.u32_a = 1u;
				return;
			}
			if (name_starts_with(name, "CANR")) {
				s.addr = 0x7FFE0000ULL;
				s.size = 64;
				s.u32_a = 0;
				return;
			}
			if (name_starts_with(name, "STRM")) {
				s.u64_a = (static_cast<std::uint64_t>(80u) << 16) | static_cast<std::uint64_t>(443u);
				return;
			}
			if (name_starts_with(name, "PSBX")) {
				return;
			}
			if (name_starts_with(name, "USBX")) {
				if (!cache.sandbox_self_registered && device && device->is_connected()) {
					std::uint64_t denials = 0;
					if (device->protect_sandbox_pid(s.pid, 0, &denials)) {
						cache.sandbox_self_registered = true;
					}
				}
				return;
			}
			if (name_starts_with(name, "NLOG")) {
				if (!cache.sandbox_self_registered && device && device->is_connected()) {
					std::uint64_t denials = 0;
					if (device->protect_sandbox_pid(s.pid, 0, &denials)) {
						cache.sandbox_self_registered = true;
					}
				}
				s.u32_a = 1u;
				return;
			}
			if (name_starts_with(name, "REGISTER_PID")) {
				if (!shadow_fs_client::is_connected()) {
					shadow_fs_client::initialize();
				}
				s.text_a = shadowfs_sandbox_root_a();
				s.u32_a = 0;
				return;
			}
			if (name_starts_with(name, "UNREGISTER_PID")) {
				if (!shadow_fs_client::is_connected()) {
					shadow_fs_client::initialize();
				}
				if (!cache.shadowfs_self_registered && shadow_fs_client::is_connected()) {
					if (shadow_fs_client::register_sandbox_pid(
						s.pid, 0, shadowfs_sandbox_root_w()))
					{
						cache.shadowfs_self_registered = true;
					}
				}
				return;
			}
			if (name_starts_with(name, "PING") ||
				name_starts_with(name, "QUERY_STATS"))
			{
				if (!shadow_fs_client::is_connected()) {
					shadow_fs_client::initialize();
				}
				return;
			}
		}

		void start_run_all_safe() {
			bool expected = false;
			if (!g_run_all_active.compare_exchange_strong(expected, true)) return;
			g_run_all_current.store(0);
			g_run_all_ok.store(0);
			g_run_all_fail.store(0);
			g_run_all_skipped.store(0);
			{
				std::lock_guard<std::mutex> lk(g_run_all_status_mtx);
				g_run_all_status_line = "starting...";
				g_run_all_current_name.clear();
			}

			work_queue::post([]() {
				const auto& features = test_lab::all_features();
				g_run_all_total.store(static_cast<int>(features.size()));

				HANDLE hFile = open_log_for_append();
				if (hFile != INVALID_HANDLE_VALUE) {
					char ts[40];
					format_local_timestamp(ts, sizeof(ts));
					char header[256];
					std::snprintf(header, sizeof(header),
						"\n========================================\n"
						"[%s] Run All Safe Tests started (total=%d)\n"
						"========================================\n",
						ts, static_cast<int>(features.size()));
					append_log_line(hFile, std::string(header));
				}

				run_all_cache_t cache;
				prime_run_all_cache(cache);

				for (std::size_t i = 0; i < features.size(); ++i) {
					const auto& f = features[i];
					g_run_all_current.store(static_cast<int>(i + 1));
					{
						std::lock_guard<std::mutex> lk(g_run_all_status_mtx);
						g_run_all_current_name = (f.name != nullptr ? f.name : "?");
					}

					if (is_destructive_by_name(f.name)) {
						g_run_all_skipped.fetch_add(1);
						append_log_skip(hFile, f, "destructive (BSOD/kill)");
						test_lab_format::testlab_diag_log_skip(f, "destructive (BSOD/kill)");
						continue;
					}
					if (f.run == nullptr) {
						g_run_all_skipped.fetch_add(1);
						append_log_skip(hFile, f, "no run function");
						test_lab_format::testlab_diag_log_skip(f, "no run function");
						continue;
					}

					test_lab::state_t s;
					populate_safe_defaults(s);
					apply_smart_defaults(f, s, cache);
					test_lab::result_t r;
					append_log_starting(hFile, f, s);
					test_lab_format::testlab_diag_log_entry(f, s);
					auto t0 = std::chrono::steady_clock::now();
					f.run(s, r);
					auto t1 = std::chrono::steady_clock::now();
					std::uint64_t elapsed_us = static_cast<std::uint64_t>(
						std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
					if (r.elapsed_us == 0) r.elapsed_us = elapsed_us;

					if (r.ok) g_run_all_ok.fetch_add(1);
					else      g_run_all_fail.fetch_add(1);

					append_log_result(hFile, f, s, r, r.elapsed_us);
					test_lab_format::testlab_diag_log_exit(f, r, r.elapsed_us);
				}

				if (hFile != INVALID_HANDLE_VALUE) {
					char ts2[40];
					format_local_timestamp(ts2, sizeof(ts2));
					char footer[256];
					std::snprintf(footer, sizeof(footer),
						"[%s] Run All complete: ok=%d fail=%d skipped=%d total=%d\n"
						"========================================\n\n",
						ts2,
						g_run_all_ok.load(),
						g_run_all_fail.load(),
						g_run_all_skipped.load(),
						g_run_all_total.load());
					append_log_line(hFile, std::string(footer));
					CloseHandle(hFile);
				}

				{
					std::lock_guard<std::mutex> lk(g_run_all_status_mtx);
					char buf[160];
					std::snprintf(buf, sizeof(buf),
						"done: ok=%d fail=%d skipped=%d (log on Desktop)",
						g_run_all_ok.load(),
						g_run_all_fail.load(),
						g_run_all_skipped.load());
					g_run_all_status_line = buf;
					g_run_all_current_name.clear();
				}
				g_run_all_active.store(false);
			});
		}

		struct grouped_row_t {
			int  feature_idx = -1;
			bool is_header = false;
			std::string header_text;
		};

		void build_grouped_rows(std::vector<grouped_row_t>& out) {
			out.clear();
			const auto& features = test_lab::all_features();
			std::string current_cat;
			for (std::size_t i = 0; i < features.size(); ++i) {
				const auto& f = features[i];
				const char* cat = (f.category != nullptr) ? f.category : "Uncategorized";
				if (current_cat != cat) {
					current_cat = cat;
					grouped_row_t hdr;
					hdr.is_header = true;
					hdr.header_text = current_cat;
					out.push_back(hdr);
				}
				grouped_row_t row;
				row.feature_idx = static_cast<int>(i);
				out.push_back(row);
			}
		}

		void render_left_pane(float pane_w, float pane_h, float accumulated_time) {
			const auto& t = aida::ui::resolved();
			ImGui::BeginChild("##testlab_left", ImVec2(pane_w, pane_h), false,
				ImGuiWindowFlags_NoBackground);

			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 wp = ImGui::GetWindowPos();
			dl->AddRectFilled(wp, ImVec2(wp.x + pane_w, wp.y + pane_h),
				aida::ui::with_alpha(t.panel_bg, 0.55f), 6.f);

			ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.f, 4.f));
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 6.f));

			ImGui::Dummy(ImVec2(0.f, 4.f));
			ImGui::Indent(10.f);
			ImGui::PushStyleColor(ImGuiCol_Text, t.text_secondary);
			ImGui::TextUnformatted("DRIVER TEST LAB");
			ImGui::PopStyleColor();
			ImGui::Unindent(10.f);
			ImGui::Dummy(ImVec2(0.f, 2.f));
			ImGui::Separator();
			ImGui::Dummy(ImVec2(0.f, 2.f));

			ImGui::BeginChild("##testlab_left_scroll",
				ImVec2(pane_w - 4.f, pane_h - 64.f), false, ImGuiWindowFlags_None);

			std::vector<grouped_row_t> rows;
			build_grouped_rows(rows);
			const auto& features = test_lab::all_features();

			int rendered_index = 0;
			for (std::size_t r = 0; r < rows.size(); ++r) {
				const auto& row = rows[r];
				float ent = ui_anim::render_row_entrance(rendered_index, accumulated_time, 0.012f);
				++rendered_index;

				if (row.is_header) {
					ImGui::Dummy(ImVec2(0.f, 4.f));
					ImGui::Indent(10.f);
					ImGui::PushStyleColor(ImGuiCol_Text,
						aida::ui::with_alpha(t.text_dim, ent));
					ImGui::TextUnformatted(row.header_text.c_str());
					ImGui::PopStyleColor();
					ImGui::Unindent(10.f);
					continue;
				}

				int fidx = row.feature_idx;
				if (fidx < 0 || fidx >= static_cast<int>(features.size())) continue;
				const auto& f = features[static_cast<std::size_t>(fidx)];

				ImGui::PushID(fidx);
				bool is_selected = (g_selected_idx == fidx);

				float row_h = 34.f;
				ImVec2 row_start = ImGui::GetCursorScreenPos();
				ImGui::InvisibleButton("##row", ImVec2(pane_w - 24.f, row_h));
				bool hov = ImGui::IsItemHovered();
				bool clicked = ImGui::IsItemClicked();

				ImU32 row_bg = is_selected
					? aida::ui::with_alpha(t.selection_strong, 0.85f * ent)
					: (hov ? aida::ui::with_alpha(t.hover_wash, 0.55f * ent)
					       : aida::ui::with_alpha(t.panel_bg, 0.0f));
				ImDrawList* rdl = ImGui::GetWindowDrawList();
				rdl->AddRectFilled(row_start,
					ImVec2(row_start.x + pane_w - 24.f, row_start.y + row_h),
					row_bg, 4.f);

				float dot_r = 4.f;
				ImVec2 dot_p(row_start.x + 10.f, row_start.y + row_h * 0.5f);
				test_lab::run_state_e rs = test_lab::run_state_e::idle;
				bool rok = false;
				if (is_selected) {
					std::shared_ptr<test_lab::result_t> snap;
					{
						std::lock_guard<std::mutex> lk(g_result_mtx);
						snap = g_result;
					}
					rs = snap->state.load(std::memory_order_acquire);
					rok = snap->ok;
				}
				rdl->AddCircleFilled(dot_p, dot_r, status_dot_color(rs, rok, ent));

				float badge_w = 34.f;
				float badge_h = 16.f;
				ImVec2 ba(row_start.x + 22.f, row_start.y + (row_h - badge_h) * 0.5f);
				ImVec2 bb(ba.x + badge_w, ba.y + badge_h);
				rdl->AddRectFilled(ba, bb, driver_badge_color(f.driver, 0.35f * ent), 3.f);
				rdl->AddRect(ba, bb, driver_badge_color(f.driver, 0.85f * ent), 3.f, 0, 1.f);
				const char* dl_label = driver_label(f.driver);
				ImVec2 dlts = ImGui::CalcTextSize(dl_label);
				rdl->AddText(ImVec2(ba.x + (badge_w - dlts.x) * 0.5f,
						ba.y + (badge_h - dlts.y) * 0.5f),
					aida::ui::with_alpha(t.text_primary, ent), dl_label);

				ImU32 name_col = aida::ui::with_alpha(
					is_selected ? t.text_primary : t.text_secondary, ent);
				rdl->AddText(ImVec2(row_start.x + 64.f, row_start.y + (row_h - ImGui::GetTextLineHeight()) * 0.5f),
					name_col, f.name != nullptr ? f.name : "");

				if (clicked && fidx != g_selected_idx) {
					g_selected_idx = fidx;
					std::lock_guard<std::mutex> lk(g_result_mtx);
					g_result = std::make_shared<test_lab::result_t>();
				}
				ImGui::PopID();
			}

			ImGui::EndChild();

			ImGui::PopStyleVar();
			ImGui::PopStyleVar();

			ImGui::EndChild();
		}

		void render_inputs_section(const test_lab::feature_t& f) {
			const auto& t = aida::ui::resolved();
			ImGui::PushStyleColor(ImGuiCol_Text, t.text_secondary);
			ImGui::TextUnformatted("INPUTS");
			ImGui::PopStyleColor();
			ImGui::Separator();
			ImGui::Dummy(ImVec2(0.f, 4.f));
			if (f.render_inputs != nullptr) {
				f.render_inputs(g_state);
			} else {
				ImGui::TextDisabled("This feature does not require inputs.");
			}
		}

		void run_fn_post_with_feature(const test_lab::feature_t& f);

		void render_action_row(const test_lab::feature_t& f) {
			std::shared_ptr<test_lab::result_t> snap;
			{
				std::lock_guard<std::mutex> lk(g_result_mtx);
				snap = g_result;
			}
			test_lab::run_state_e rs = snap->state.load(std::memory_order_acquire);
			bool running = (rs == test_lab::run_state_e::running);

			ImGui::Dummy(ImVec2(0.f, 4.f));

			if (running) ImGui::BeginDisabled();
			if (ImGui::Button("Run", ImVec2(110.f, 28.f))) {
				run_fn_post_with_feature(f);
			}
			if (running) ImGui::EndDisabled();
			ImGui::SameLine();

			bool has_result = (snap->state.load(std::memory_order_acquire) ==
				test_lab::run_state_e::complete);

			if (!has_result) ImGui::BeginDisabled();
			if (ImGui::Button("Copy raw", ImVec2(110.f, 28.f))) {
				const auto& raw = snap->raw;
				std::string out;
				out.reserve(raw.size() * 3);
				char tmp[8];
				for (std::size_t i = 0; i < raw.size(); ++i) {
					std::snprintf(tmp, sizeof(tmp), "%02X ", static_cast<unsigned>(raw[i]));
					out.append(tmp);
				}
				ImGui::SetClipboardText(out.c_str());
			}
			ImGui::SameLine();
			if (ImGui::Button("Copy parsed", ImVec2(110.f, 28.f))) {
				std::string out;
				for (const auto& p : snap->parsed) {
					out.append(p.label);
					out.append(": ");
					out.append(p.value);
					out.append("\n");
				}
				ImGui::SetClipboardText(out.c_str());
			}
			if (!has_result) ImGui::EndDisabled();
			ImGui::SameLine();
			if (ImGui::Button("Clear", ImVec2(110.f, 28.f))) {
				std::lock_guard<std::mutex> lk(g_result_mtx);
				g_result = std::make_shared<test_lab::result_t>();
			}
		}

		void run_fn_post_with_feature(const test_lab::feature_t& f) {
			test_lab::state_t snapshot = g_state;
			std::shared_ptr<test_lab::result_t> new_result = std::make_shared<test_lab::result_t>();
			new_result->state.store(test_lab::run_state_e::running, std::memory_order_release);
			{
				std::lock_guard<std::mutex> lk(g_result_mtx);
				g_result = new_result;
			}
			test_lab::feature_t feature_copy = f;
			work_queue::post([feature_copy, snapshot, new_result]() mutable {
				if (feature_copy.run == nullptr) {
					new_result->ok = false;
					new_result->error = "no run function";
					test_lab_format::testlab_diag_log_skip(feature_copy, "no run function");
					new_result->state.store(test_lab::run_state_e::complete, std::memory_order_release);
					return;
				}
				test_lab_format::testlab_diag_log_entry(feature_copy, snapshot);
				auto t0 = std::chrono::steady_clock::now();
				test_lab::result_t local;
				local.state.store(test_lab::run_state_e::running, std::memory_order_release);
				feature_copy.run(snapshot, local);
				auto t1 = std::chrono::steady_clock::now();
				std::uint64_t elapsed_us = static_cast<std::uint64_t>(
					std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
				if (local.elapsed_us == 0) local.elapsed_us = elapsed_us;
				test_lab_format::testlab_diag_log_exit(feature_copy, local, local.elapsed_us);
				{
					std::lock_guard<std::mutex> lk(g_result_mtx);
					new_result->ok = local.ok;
					new_result->ntstatus = local.ntstatus;
					new_result->bytes_returned = local.bytes_returned;
					new_result->elapsed_us = local.elapsed_us;
					new_result->error = std::move(local.error);
					new_result->raw = std::move(local.raw);
					new_result->parsed = std::move(local.parsed);
				}
				new_result->state.store(test_lab::run_state_e::complete, std::memory_order_release);
			});
		}

		void render_result_section() {
			const auto& t = aida::ui::resolved();

			std::shared_ptr<test_lab::result_t> snap;
			{
				std::lock_guard<std::mutex> lk(g_result_mtx);
				snap = g_result;
			}
			test_lab::run_state_e rs = snap->state.load(std::memory_order_acquire);

			ImGui::PushStyleColor(ImGuiCol_Text, t.text_secondary);
			ImGui::TextUnformatted("RESULT");
			ImGui::PopStyleColor();
			ImGui::Separator();
			ImGui::Dummy(ImVec2(0.f, 4.f));

			if (rs == test_lab::run_state_e::idle) {
				ImGui::TextDisabled("No execution yet.");
				return;
			}
			if (rs == test_lab::run_state_e::running) {
				ImGui::PushStyleColor(ImGuiCol_Text, t.accent_u32);
				ImGui::TextUnformatted("Running...");
				ImGui::PopStyleColor();
				return;
			}

			test_lab::result_t local_copy;
			{
				std::lock_guard<std::mutex> lk(g_result_mtx);
				local_copy.ok = snap->ok;
				local_copy.ntstatus = snap->ntstatus;
				local_copy.bytes_returned = snap->bytes_returned;
				local_copy.elapsed_us = snap->elapsed_us;
				local_copy.error = snap->error;
				local_copy.raw = snap->raw;
				local_copy.parsed = snap->parsed;
			}

			ImU32 status_col = local_copy.ok ? t.success : t.error;
			ImGui::PushStyleColor(ImGuiCol_Text, status_col);
			ImGui::Text("%s  (0x%08X)",
				test_lab_format::ntstatus_to_string(local_copy.ntstatus),
				static_cast<unsigned>(static_cast<std::uint32_t>(local_copy.ntstatus)));
			ImGui::PopStyleColor();

			ImGui::Text("bytes_returned: %u    elapsed: %llu us",
				static_cast<unsigned>(local_copy.bytes_returned),
				static_cast<unsigned long long>(local_copy.elapsed_us));

			if (!local_copy.error.empty()) {
				ImGui::PushStyleColor(ImGuiCol_Text, t.error);
				ImGui::TextWrapped("error: %s", local_copy.error.c_str());
				ImGui::PopStyleColor();
			}

			ImGui::Dummy(ImVec2(0.f, 6.f));
			ImGui::PushStyleColor(ImGuiCol_Text, t.text_dim);
			ImGui::TextUnformatted("RAW BYTES");
			ImGui::PopStyleColor();
			ImGui::Separator();
			ImGui::BeginChild("##testlab_raw_dump", ImVec2(0.f, 180.f), true,
				ImGuiWindowFlags_HorizontalScrollbar);
			test_lab_format::render_hex_ascii(local_copy.raw);
			ImGui::EndChild();

			ImGui::Dummy(ImVec2(0.f, 6.f));
			ImGui::PushStyleColor(ImGuiCol_Text, t.text_dim);
			ImGui::TextUnformatted("PARSED FIELDS");
			ImGui::PopStyleColor();
			ImGui::Separator();
			if (local_copy.parsed.empty()) {
				ImGui::TextDisabled("(none)");
			} else {
				if (ImGui::BeginTable("##testlab_parsed", 2,
					ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_RowBg |
					ImGuiTableFlags_SizingStretchProp)) {
					ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthStretch, 0.35f);
					ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 0.65f);
					ImGui::TableHeadersRow();
					for (const auto& p : local_copy.parsed) {
						ImGui::TableNextRow();
						ImGui::TableSetColumnIndex(0);
						ImGui::TextUnformatted(p.label.c_str());
						ImGui::TableSetColumnIndex(1);
						ImGui::TextWrapped("%s", p.value.c_str());
					}
					ImGui::EndTable();
				}
			}
		}

		void render_right_pane(float pane_w, float pane_h) {
			const auto& t = aida::ui::resolved();
			ImGui::BeginChild("##testlab_right", ImVec2(pane_w, pane_h), false,
				ImGuiWindowFlags_NoBackground);
			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 wp = ImGui::GetWindowPos();
			dl->AddRectFilled(wp, ImVec2(wp.x + pane_w, wp.y + pane_h),
				aida::ui::with_alpha(t.panel_bg, 0.45f), 6.f);

			ImGui::Dummy(ImVec2(0.f, 6.f));
			ImGui::Indent(12.f);

			const auto& features = test_lab::all_features();
			if (g_selected_idx < 0 || g_selected_idx >= static_cast<int>(features.size())) {
				ImGui::PushStyleColor(ImGuiCol_Text, t.text_dim);
				ImGui::TextUnformatted("Select a feature from the left to begin.");
				ImGui::PopStyleColor();
				ImGui::Unindent(12.f);
				ImGui::EndChild();
				return;
			}

			const auto& f = features[static_cast<std::size_t>(g_selected_idx)];

			ImGui::PushStyleColor(ImGuiCol_Text, t.text_primary);
			ImGui::Text("%s", f.name != nullptr ? f.name : "");
			ImGui::PopStyleColor();
			if (f.summary != nullptr && f.summary[0] != '\0') {
				ImGui::PushStyleColor(ImGuiCol_Text, t.text_dim);
				ImGui::TextWrapped("%s", f.summary);
				ImGui::PopStyleColor();
			}
			ImGui::Dummy(ImVec2(0.f, 6.f));

			ImGui::BeginChild("##testlab_right_scroll",
				ImVec2(pane_w - 32.f, pane_h - 64.f), false, ImGuiWindowFlags_None);

			render_inputs_section(f);
			ImGui::Dummy(ImVec2(0.f, 8.f));
			render_action_row(f);
			ImGui::Dummy(ImVec2(0.f, 10.f));
			render_result_section();

			ImGui::EndChild();
			ImGui::Unindent(12.f);
			ImGui::EndChild();
		}

	}

	void render(float vw, float vh, float accumulated_time) {
		const float top_bar_h = 38.f;
		const float gap = 8.f;

		ImVec2 origin_top = ImGui::GetCursorPos();
		const auto& t = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp_top = ImGui::GetCursorScreenPos();
		dl->AddRectFilled(wp_top,
			ImVec2(wp_top.x + vw, wp_top.y + top_bar_h),
			aida::ui::with_alpha(t.panel_bg, 0.55f), 6.f);

		ImGui::Dummy(ImVec2(0.f, 4.f));
		ImGui::Indent(10.f);

		bool running = g_run_all_active.load(std::memory_order_acquire);
		if (running) ImGui::BeginDisabled();
		if (ImGui::Button("Run All Safe Tests", ImVec2(180.f, 26.f))) {
			start_run_all_safe();
		}
		if (running) ImGui::EndDisabled();
		ImGui::SameLine();

		std::string status_copy;
		std::string current_name_copy;
		{
			std::lock_guard<std::mutex> lk(g_run_all_status_mtx);
			status_copy = g_run_all_status_line;
			current_name_copy = g_run_all_current_name;
		}

		ImGui::PushStyleColor(ImGuiCol_Text, t.text_dim);
		if (running) {
			ImGui::Text("Running %d / %d  (%s)",
				g_run_all_current.load(),
				g_run_all_total.load(),
				current_name_copy.c_str());
		}
		else if (!status_copy.empty()) {
			ImGui::Text("%s", status_copy.c_str());
		}
		else {
			ImGui::TextUnformatted("Output: C:\\Users\\Public\\Desktop\\aida_test_results.log");
		}
		ImGui::PopStyleColor();
		ImGui::Unindent(10.f);

		ImGui::SetCursorPos(ImVec2(origin_top.x, origin_top.y + top_bar_h + gap));

		const float left_pane_w = 280.f;
		float right_pane_w = vw - left_pane_w - gap;
		if (right_pane_w < 200.f) right_pane_w = 200.f;
		float remaining_h = vh - top_bar_h - gap;
		if (remaining_h < 100.f) remaining_h = 100.f;

		ImVec2 origin = ImGui::GetCursorPos();
		render_left_pane(left_pane_w, remaining_h, accumulated_time);

		ImGui::SetCursorPos(ImVec2(origin.x + left_pane_w + gap, origin.y));
		render_right_pane(right_pane_w, remaining_h);
	}

}
