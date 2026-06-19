#pragma once

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "../../helpers/diag_log.hpp"
#include "../helpers/globals.h"
#include "../../helpers/helpers.h"
#include "../../helpers/win32_dialog.hpp"
#include "binary_map.hpp"
#include "../editor/hex_view.hpp"
#include "disasm_view.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"
#include "function_index.hpp"
#include "event_bus.hpp"
#include "toast_notification.hpp"
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/transition.hpp"
#include "ui/components.hpp"
#include "ui/blur_layer.hpp"
#include "ui/empty_state.hpp"
#include "ui/no_target_overlay.hpp"
#include "ui/responsive.hpp"
#include "ui/skeleton.hpp"
#include "ui/fonts.hpp"
#include "work_queue.hpp"
#include "../session/analysis_session.hpp"

#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

extern DisasmState g_disasm;

namespace aida {
namespace binary_map_view {

	struct fn_pulse_t {
		float v = 0.f;
	};

	enum class display_mode_t : int {
		auto_detect = 0,
		static_only,
		live_only
	};

	enum class active_mode_t : int {
		none = 0,
		pe_static,
		live_process,
		merged
	};

	struct live_region_t {
		uint64_t    base = 0;
		uint64_t    size = 0;
		uint32_t    state = 0;
		uint32_t    protect = 0;
		uint32_t    type = 0;
		std::string module_name;
		std::string module_path;
		std::string section_name;
		std::string info;
		uint32_t    owner_tid = 0;
		bool        is_image = false;
		bool        is_mapped = false;
		bool        is_private = false;
		bool        is_stack = false;
		bool        is_heap = false;
		bool        is_committed = false;
		bool        is_reserved = false;
		bool        is_guard = false;
		bool        is_noaccess = false;
	};

	struct live_snapshot_t {
		std::vector<live_region_t>                regions;
		std::vector<driver_bridge::module_info_t> modules;
		std::vector<driver_bridge::thread_info_t> threads;
		uint64_t                                  process_heap = 0;
		uint64_t                                  total_committed = 0;
		uint64_t                                  total_reserved = 0;
		uint32_t                                  rwx_count = 0;
		uint32_t                                  pid = 0;
		std::string                               process_name;
		int64_t                                   generated_unix = 0;
		uint64_t                                  enum_elapsed_ms = 0;
	};

	struct view_state_t
	{
		std::mutex                              mutex;
		binary_map::map_t                       map;
		binary_map::map_options_t               opts;
		std::string                             rendered_text;
		std::set<std::string>                   collapsed_groups;
		std::set<std::string>                   expanded_imports;
		char                                    filter_buf[160] = {};
		std::string                             filter_lower;
		std::string                             last_error;
		std::atomic<bool>                       has_map{false};
		std::atomic<bool>                       refreshing{false};
		std::atomic<bool>                       refresh_requested{false};
		std::atomic<uint64_t>                   selected_va{0};
		std::atomic<int>                        ctx_target{-1};
		uint64_t                                ctx_va = 0;
		float                                   left_split = 0.58f;
		float                                   list_scroll_y = 0.f;
		float                                   list_target_scroll_y = 0.f;
		float                                   row_anim_time = 0.f;
		bool                                    initialized = false;
		bool                                    auto_refreshed_once = false;
		std::string                             last_binary_identity_path;
		uint64_t                                last_binary_identity_base = 0;
		uint32_t                                last_binary_identity_size = 0;
		aida::events::subscription_handle_t     subscription_binary;
		aida::events::subscription_handle_t     subscription_proc_created;
		aida::events::subscription_handle_t     subscription_proc_exited;
		std::unordered_map<uint64_t, aida::ui::flash_t> pin_flashes;
		std::unordered_map<uint64_t, fn_pulse_t>        fn_pulses;
		aida::ui::hover_state_t                 splitter_hover;
		float                                   splitter_hover_v = 0.f;
		uint64_t                                hover_function_va = 0;
		display_mode_t                          mode_pref = display_mode_t::auto_detect;
		std::atomic<int>                        active_mode_atomic{0};
		live_snapshot_t                         live;
		std::atomic<bool>                       live_refreshing{false};
		std::atomic<bool>                       live_refresh_requested{false};
		std::atomic<int64_t>                    live_last_refresh_unix{0};
		std::atomic<uint64_t>                   live_selected_base{0};
		std::atomic<int>                        live_hover_index{-1};
		float                                   live_list_scroll_y = 0.f;
		float                                   live_list_target_scroll_y = 0.f;
		float                                   canvas_zoom = 1.f;
		float                                   canvas_target_zoom = 1.f;
		double                                  canvas_offset_norm = 0.0;
		double                                  canvas_target_offset_norm = 0.0;
		bool                                    canvas_dragging = false;
		float                                   canvas_drag_anchor = 0.f;
		double                                  canvas_drag_offset_start = 0.0;
		bool                                    change_protect_open = false;
		uint64_t                                change_protect_addr = 0;
		uint64_t                                change_protect_size = 0;
		int                                     change_protect_choice = 0;
		uint32_t                                change_protect_old = 0;
	};

	inline view_state_t& state()
	{
		static view_state_t s;
		return s;
	}

	namespace detail {

		inline std::string to_lower_copy(const std::string& s)
		{
			std::string out;
			out.resize(s.size());
			for (size_t i = 0; i < s.size(); ++i) {
				const unsigned char c = static_cast<unsigned char>(s[i]);
				out[i] = static_cast<char>(std::tolower(c));
			}
			return out;
		}

		inline bool filter_matches(const std::string& filter_lower, const std::string& text)
		{
			if (filter_lower.empty()) return true;
			std::string lower = to_lower_copy(text);
			return lower.find(filter_lower) != std::string::npos;
		}

		inline std::string format_size_human(uint64_t bytes)
		{
			char buf[48];
			if (bytes >= (1ull << 30)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 30);
				std::snprintf(buf, sizeof(buf), "%.2f GiB", v);
			} else if (bytes >= (1ull << 20)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 20);
				std::snprintf(buf, sizeof(buf), "%.2f MiB", v);
			} else if (bytes >= (1ull << 10)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 10);
				std::snprintf(buf, sizeof(buf), "%.2f KiB", v);
			} else {
				std::snprintf(buf, sizeof(buf), "%llu B",
					static_cast<unsigned long long>(bytes));
			}
			return std::string(buf);
		}

		inline std::string format_protect_word(uint32_t protect)
		{
			if (protect == 0) return "---";
			std::string out;
			const uint32_t base = protect & 0xFF;
			switch (base) {
				case 0x01: out = "----"; break;
				case 0x02: out = "R---"; break;
				case 0x04: out = "RW--"; break;
				case 0x08: out = "RWC-"; break;
				case 0x10: out = "--X-"; break;
				case 0x20: out = "R-X-"; break;
				case 0x40: out = "RWX-"; break;
				case 0x80: out = "RWXC"; break;
				default: {
					char buf[16];
					std::snprintf(buf, sizeof(buf), "0x%02X", base);
					out = buf;
					break;
				}
			}
			if (protect & 0x100) out += " G";
			if (protect & 0x200) out += " NC";
			if (protect & 0x400) out += " WC";
			return out;
		}

		inline std::string format_state_word(uint32_t state)
		{
			if (state == 0x1000)  return "COMMIT";
			if (state == 0x2000)  return "RESERVE";
			if (state == 0x10000) return "FREE";
			char buf[16];
			std::snprintf(buf, sizeof(buf), "0x%X", state);
			return std::string(buf);
		}

		inline std::string format_type_word(uint32_t type)
		{
			if (type == 0x1000000) return "IMAGE";
			if (type == 0x20000)   return "PRIVATE";
			if (type == 0x40000)   return "MAPPED";
			if (type == 0) return "";
			char buf[16];
			std::snprintf(buf, sizeof(buf), "0x%X", type);
			return std::string(buf);
		}

		inline ImU32 section_color(const binary_map::map_section_t& s, float a)
		{
			const auto& t = aida::ui::resolved();
			ImU32 base = t.info;
			if (s.executable && s.writable) base = t.warning;
			else if (s.executable)          base = t.error;
			else if (s.writable)            base = t.success;
			else                            base = t.info;
			return aida::ui::with_alpha(base, a);
		}

		inline ImU32 region_color(const live_region_t& r, float alpha)
		{
			const auto& t = aida::ui::resolved();
			ImU32 base = t.text_dim;
			if (r.is_guard || r.is_noaccess) base = t.error;
			else if (r.is_stack)             base = t.warning;
			else if (r.is_heap)              base = t.info_soft;
			else if (r.is_image)             base = t.success;
			else if (r.is_mapped)            base = t.info;
			else if (r.is_private && r.is_committed) base = t.accent_dim;
			else if (r.is_reserved)          base = t.text_dim;

			float fade = 1.f;
			if (!r.is_committed && !r.is_reserved) fade = 0.32f;
			else if (r.is_reserved) fade = 0.55f;

			return aida::ui::with_alpha(base, alpha * fade);
		}

		inline std::string section_perm_string(const binary_map::map_section_t& s)
		{
			std::string out;
			out += s.readable ? 'R' : '-';
			out += s.writable ? 'W' : '-';
			out += s.executable ? 'X' : '-';
			return out;
		}

		inline std::string region_kind_label(const live_region_t& r)
		{
			if (r.is_guard) return "GUARD";
			if (r.is_noaccess) return "NOACCESS";
			if (r.is_stack) return "STACK";
			if (r.is_heap) return "HEAP";
			if (r.is_image) return "IMAGE";
			if (r.is_mapped) return "MAPPED";
			if (r.is_private && r.is_committed) return "PRIVATE";
			if (r.is_reserved) return "RESERVED";
			return "FREE";
		}

		inline std::string format_function_summary(const binary_map::map_function_t& f)
		{
			std::string callees;
			for (size_t i = 0; i < f.top_callees.size() && i < 5; ++i) {
				if (i > 0) callees += ", ";
				callees += f.top_callees[i];
			}
			if (callees.empty()) callees = "(none)";

			char buf[512];
			std::snprintf(buf, sizeof(buf),
				"%s @ 0x%llX (xrefs=%d, callees: %s)",
				f.name.c_str(),
				static_cast<unsigned long long>(f.va),
				f.xref_count,
				callees.c_str());
			return std::string(buf);
		}

		inline void rebuild_text_locked(view_state_t& s)
		{
			s.rendered_text = binary_map::render_text(s.map, s.opts);
		}

		inline void inject_to_chat(const std::string& text)
		{
			if (text.empty()) return;

			const size_t cap = sizeof(g_chat_buf) - 1u;
			const size_t cur = std::strlen(g_chat_buf);

			if (cur + text.size() < cap) {
				if (cur > 0) {
					if (cur + 2u < cap) {
						g_chat_buf[cur] = '\n';
						g_chat_buf[cur + 1u] = '\n';
						g_chat_buf[cur + 2u] = '\0';
					}
				}
				const size_t now = std::strlen(g_chat_buf);
				const size_t room = cap - now;
				const size_t copy = (text.size() < room) ? text.size() : room;
				std::memcpy(g_chat_buf + now, text.data(), copy);
				g_chat_buf[now + copy] = '\0';
				toast_notification::push("Binary map appended to chat input",
					toast_notification::toast_type_t::info, 3.0f);
			} else {
				ImGui::SetClipboardText(text.c_str());
				toast_notification::push(
					"Binary map exceeds chat buffer; copied to clipboard instead",
					toast_notification::toast_type_t::warning, 4.0f);
			}
		}

		inline bool live_available()
		{
			return driver_bridge::is_loaded()
				&& driver_bridge::attached_pid() != 0
				&& driver_bridge::can_read_memory();
		}

		inline bool static_available()
		{
			return function_index::detail::static_pe_active();
		}

		inline active_mode_t resolve_active_mode(display_mode_t pref)
		{
			const bool live = live_available();
			const bool stat = static_available();
			if (pref == display_mode_t::live_only)   return live ? active_mode_t::live_process : active_mode_t::none;
			if (pref == display_mode_t::static_only) return stat ? active_mode_t::pe_static : active_mode_t::none;
			if (live && stat) return active_mode_t::merged;
			if (live)         return active_mode_t::live_process;
			if (stat)         return active_mode_t::pe_static;
			return active_mode_t::none;
		}

		inline void classify_region(live_region_t& r,
			const std::vector<driver_bridge::module_info_t>& modules,
			const std::vector<driver_bridge::thread_info_t>& threads,
			uint64_t process_heap)
		{
			r.is_committed = (r.state == 0x1000);
			r.is_reserved  = (r.state == 0x2000);
			r.is_guard     = (r.protect & 0x100) != 0;
			r.is_noaccess  = ((r.protect & 0xFF) == 0x01);
			r.is_image     = (r.type == 0x1000000);
			r.is_mapped    = (r.type == 0x40000);
			r.is_private   = (r.type == 0x20000);

			for (const auto& m : modules) {
				if (r.base >= m.base && r.base < m.base + static_cast<uint64_t>(m.size)) {
					r.module_name = m.name;
					r.module_path = m.path;
					break;
				}
			}

			for (const auto& th : threads) {
				if (th.rip == 0) continue;
				if (r.base <= th.rip && th.rip < r.base + r.size && r.is_private && r.is_committed) {
					r.is_stack = true;
					r.owner_tid = th.tid;
					break;
				}
			}

			if (!r.is_stack && r.is_private && r.is_committed && process_heap != 0) {
				if (r.base == process_heap) r.is_heap = true;
			}
		}

		inline void perform_refresh(view_state_t& s)
		{
			if (s.refreshing.exchange(true)) {
				diag::log_tagged_fmt("binary_map",
					"refresh SKIPPED already_in_flight");
				return;
			}

			binary_map::map_options_t opts_copy;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				opts_copy = s.opts;
			}

			diag::log_tagged_fmt("binary_map",
				"refresh START max_functions=%d max_globals=%d max_callees=%d imp=%d exp=%d",
				opts_copy.max_functions, opts_copy.max_globals,
				opts_copy.max_callees_per_function,
				opts_copy.include_imports ? 1 : 0,
				opts_copy.include_exports ? 1 : 0);

			const bool posted = work_queue::post([&s, opts_copy]() {
				const auto start_clock = std::chrono::steady_clock::now();
				binary_map::clear_cache();

				binary_map::map_t fresh;
				const bool ok = binary_map::generate(opts_copy, fresh);
				std::string err_copy;
				if (!ok) err_copy = binary_map::last_error();

				size_t f = 0, g_count = 0, i = 0, e = 0, sec = 0;
				std::string mod;
				if (ok) {
					f = fresh.functions.size();
					g_count = fresh.globals.size();
					i = fresh.imports.size();
					e = fresh.exports.size();
					sec = fresh.sections.size();
					mod = fresh.module_name;
				}

				{
					std::lock_guard<std::mutex> g(s.mutex);
					if (ok) {
						s.map = std::move(fresh);
						s.has_map.store(true);
						s.last_error.clear();
						rebuild_text_locked(s);
					} else {
						s.last_error = std::move(err_copy);
					}
				}
				s.refreshing.store(false);

				const auto end_clock = std::chrono::steady_clock::now();
				const auto dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					end_clock - start_clock).count();

				if (ok) {
					diag::log_tagged_fmt("binary_map",
						"refresh DONE module='%s' sections=%zu funcs=%zu globals=%zu imports=%zu exports=%zu duration_ms=%lld",
						mod.c_str(), sec, f, g_count, i, e, static_cast<long long>(dur_ms));
				} else {
					diag::log_tagged_fmt("binary_map",
						"refresh FAILED err='%s' duration_ms=%lld",
						s.last_error.c_str(), static_cast<long long>(dur_ms));
				}
			});

			if (!posted) {
				s.refreshing.store(false);
				diag::log_tagged_fmt("binary_map",
					"refresh FAILED post rejected by work_queue");
			}
		}

		inline void perform_live_refresh(view_state_t& s)
		{
			if (!live_available()) {
				diag::log_tagged_fmt("binary_map",
					"live_refresh SKIPPED driver_loaded=%d attached_pid=%u",
					driver_bridge::is_loaded() ? 1 : 0,
					static_cast<unsigned>(driver_bridge::attached_pid()));
				return;
			}
			if (s.live_refreshing.exchange(true)) {
				diag::log_tagged_fmt("binary_map",
					"live_refresh SKIPPED already_in_flight");
				return;
			}

			diag::log_tagged_fmt("binary_map",
				"live_refresh START pid=%u",
				static_cast<unsigned>(driver_bridge::attached_pid()));

			const bool posted = work_queue::post([&s]() {
				const auto start_clock = std::chrono::steady_clock::now();

				const uint32_t pid = driver_bridge::attached_pid();
				auto regions_raw = driver_bridge::enumerate_memory_regions(8192);
				auto modules     = driver_bridge::enumerate_modules();
				auto threads     = driver_bridge::enumerate_threads();
				const std::string proc_name = driver_bridge::attached_process_name();

				driver_bridge::peb_info_t peb{};
				uint64_t process_heap = 0;
				if (driver_bridge::read_peb(peb)) {
					process_heap = peb.process_heap;
				}

				live_snapshot_t snap;
				snap.modules = std::move(modules);
				snap.threads = std::move(threads);
				snap.process_heap = process_heap;
				snap.pid = pid;
				snap.process_name = proc_name;
				snap.regions.reserve(regions_raw.size());

				uint64_t total_committed = 0;
				uint64_t total_reserved = 0;
				uint32_t rwx = 0;

				for (const auto& src : regions_raw) {
					live_region_t r;
					r.base = src.base;
					r.size = src.size;
					r.state = src.state;
					r.protect = src.protect;
					r.type = src.type;
					classify_region(r, snap.modules, snap.threads, snap.process_heap);

					if (r.is_committed) total_committed += r.size;
					if (r.is_reserved)  total_reserved  += r.size;

					const bool exec  = (r.protect & 0xF0) != 0;
					const uint32_t low = r.protect & 0xFF;
					const bool write = (low == 0x04) || (low == 0x08) || (low == 0x40) || (low == 0x80);
					if (exec && write) ++rwx;

					if (r.is_image && !r.module_name.empty()) {
						r.section_name.clear();
						if (function_index::detail::static_pe_active()
							&& g_disasm.file.image_base != 0
							&& r.base >= g_disasm.file.image_base
							&& r.base < g_disasm.file.image_base + 0x10000000ull)
						{
							for (const auto& sec : g_disasm.file.sections) {
								if (r.base >= sec.va && r.base < sec.va + sec.bytes.size()) {
									r.section_name = "static_section";
									break;
								}
							}
						}
					}

					if (r.is_stack) {
						char buf[64];
						std::snprintf(buf, sizeof(buf), "Thread %u stack",
							static_cast<unsigned>(r.owner_tid));
						r.info = buf;
					} else if (r.is_heap) {
						r.info = "Process heap";
					} else if (r.is_image && !r.module_name.empty()) {
						r.info = r.module_name;
					}

					snap.regions.push_back(std::move(r));
				}

				snap.total_committed = total_committed;
				snap.total_reserved  = total_reserved;
				snap.rwx_count = rwx;
				snap.generated_unix = static_cast<int64_t>(
					std::chrono::duration_cast<std::chrono::seconds>(
						std::chrono::system_clock::now().time_since_epoch()).count());

				const auto end_clock = std::chrono::steady_clock::now();
				snap.enum_elapsed_ms = static_cast<uint64_t>(
					std::chrono::duration_cast<std::chrono::milliseconds>(
						end_clock - start_clock).count());

				{
					std::lock_guard<std::mutex> g(s.mutex);
					s.live = std::move(snap);
				}
				s.live_last_refresh_unix.store(static_cast<int64_t>(
					std::chrono::duration_cast<std::chrono::seconds>(
						std::chrono::system_clock::now().time_since_epoch()).count()));
				s.live_refreshing.store(false);

				diag::log_tagged_fmt("binary_map",
					"live_refresh DONE pid=%u proc='%s' regions=%zu modules=%zu threads=%zu committed=%llu reserved=%llu rwx=%u elapsed_ms=%llu",
					static_cast<unsigned>(s.live.pid),
					s.live.process_name.c_str(),
					s.live.regions.size(),
					s.live.modules.size(),
					s.live.threads.size(),
					static_cast<unsigned long long>(s.live.total_committed),
					static_cast<unsigned long long>(s.live.total_reserved),
					static_cast<unsigned>(s.live.rwx_count),
					static_cast<unsigned long long>(s.live.enum_elapsed_ms));
			});

			if (!posted) {
				s.live_refreshing.store(false);
				diag::log_tagged_fmt("binary_map",
					"live_refresh FAILED post rejected by work_queue");
			}
		}

		inline void ensure_subscriptions(view_state_t& s)
		{
			if (!s.subscription_binary.valid()) {
				s.subscription_binary = aida::events::subscribe(
					aida::events::event_binary_loaded,
					[](const aida::events::binary_loaded_t& payload)
					{
						view_state_t& vs = state();
						vs.refresh_requested.store(true);
						vs.live_refresh_requested.store(true);
						bool identity_changed = false;
						{
							std::lock_guard<std::mutex> g(vs.mutex);
							identity_changed =
								vs.last_binary_identity_path != payload.binary_path ||
								vs.last_binary_identity_base != payload.image_base ||
								vs.last_binary_identity_size != payload.image_size;
							vs.last_binary_identity_path = payload.binary_path;
							vs.last_binary_identity_base = payload.image_base;
							vs.last_binary_identity_size = payload.image_size;
							if (identity_changed) {
								vs.collapsed_groups.clear();
								vs.expanded_imports.clear();
								vs.rendered_text.clear();
								vs.fn_pulses.clear();
							}
						}
						if (identity_changed) {
							vs.auto_refreshed_once = false;
							vs.selected_va.store(0);
							vs.hover_function_va = 0;
						}
						diag::log_tagged_fmt("binary_map",
							"event_binary_loaded path='%s' image_base=0x%llX image_size=%u identity_changed=%d -> refresh_requested + live_refresh_requested",
							payload.binary_path.c_str(),
							static_cast<unsigned long long>(payload.image_base),
							static_cast<unsigned>(payload.image_size),
							identity_changed ? 1 : 0);
					});
			}
			if (!s.subscription_proc_created.valid()) {
				s.subscription_proc_created = aida::events::subscribe(
					aida::events::event_process_created,
					[](const aida::events::process_created_t& payload)
					{
						view_state_t& vs = state();
						vs.live_refresh_requested.store(true);
						diag::log_tagged_fmt("binary_map",
							"event_process_created pid=%u image='%s' -> live_refresh_requested",
							static_cast<unsigned>(payload.process_id),
							payload.image_name.c_str());
					});
			}
			if (!s.subscription_proc_exited.valid()) {
				s.subscription_proc_exited = aida::events::subscribe(
					aida::events::event_process_exited,
					[](const aida::events::process_exited_t& payload)
					{
						view_state_t& vs = state();
						{
							std::lock_guard<std::mutex> g(vs.mutex);
							vs.live = live_snapshot_t{};
						}
						vs.live_selected_base.store(0);
						vs.live_hover_index.store(-1);
						diag::log_tagged_fmt("binary_map",
							"event_process_exited pid=%u -> live snapshot cleared",
							static_cast<unsigned>(payload.process_id));
					});
			}
		}

		inline void jump_to_address(uint64_t va)
		{
			if (va == 0) {
				diag::log_tagged_fmt("binary_map",
					"jump_to_address SKIPPED va=0x0");
				return;
			}
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(va, g_disasm);
			diag::log_tagged_fmt("binary_map",
				"jump_to_disasm va=0x%llX",
				static_cast<unsigned long long>(va));
		}

		inline void jump_to_hex(uint64_t va, size_t size)
		{
			if (va == 0) {
				diag::log_tagged_fmt("binary_map",
					"[binmap_audit] jump_to_hex SKIPPED va=0x0");
				return;
			}
			if (size == 0) size = 0x200;
			const size_t kMaxHex = 1u * 1024u * 1024u;
			if (size > kMaxHex) size = kMaxHex;

			const bool live_ok = driver_bridge::is_loaded()
				&& driver_bridge::can_read_memory()
				&& driver_bridge::attached_pid() != 0;
			bool used_static = false;
			bool ok = false;
			if (live_ok) {
				ok = hex_view::read_from_process(va, size);
			}
			if (!ok) {
				std::vector<uint8_t> blob;
				if (static_analysis::read_bytes_from_pe(g_disasm.file, va, size, blob)
					&& !blob.empty()) {
					char label[96];
					std::snprintf(label, sizeof(label), "Static @ %016llX",
						static_cast<unsigned long long>(va));
					hex_view::set_data(blob, va, label);
					ok = true;
					used_static = true;
				}
			}
			if (ok) {
				globals::ui::active_center_view = center_view_t::hex_view;
				diag::log_tagged_fmt("binary_map",
					"jump_to_hex va=0x%llX size=%zu path=%s",
					static_cast<unsigned long long>(va), size,
					used_static ? "static_pe" : "live");
			} else {
				toast_notification::push("Hex view: failed to read bytes",
					toast_notification::toast_type_t::warning, 2.5f);
				diag::log_tagged_fmt("binary_map",
					"[binmap_audit] jump_to_hex FAILED va=0x%llX size=%zu live_ok=%d",
					static_cast<unsigned long long>(va), size,
					live_ok ? 1 : 0);
			}
		}

		inline bool dump_region_to_disk(uint64_t base, uint64_t size, const std::string& kind_label)
		{
			if (size == 0) {
				toast_notification::push("Region has zero size",
					toast_notification::toast_type_t::error, 2.5f);
				return false;
			}
			const uint64_t kMaxDump = 256ULL * 1024ULL * 1024ULL;
			if (size > kMaxDump) {
				toast_notification::push("Region exceeds 256 MiB dump cap",
					toast_notification::toast_type_t::warning, 3.0f);
				return false;
			}

			char default_name[96] = {};
			std::snprintf(default_name, sizeof(default_name),
				"dump_%s_%016llX_%llu.bin",
				kind_label.empty() ? "region" : kind_label.c_str(),
				static_cast<unsigned long long>(base),
				static_cast<unsigned long long>(size));

			char path_buf[MAX_PATH] = {};
			std::strncpy(path_buf, default_name, sizeof(path_buf) - 1);

			static const char k_dump_filter[] =
				"Binary (*.bin)\0*.bin\0"
				"All files (*.*)\0*.*\0\0";

			if (!win32_dialog::show_save_file_dialog(g_hwnd,
				"Dump Region",
				k_dump_filter,
				"bin",
				path_buf, sizeof(path_buf),
				"binary_map_view::dump_region"))
			{
				diag::log_tagged_fmt("binary_map",
					"dump_region cancelled base=0x%llX size=%llu",
					static_cast<unsigned long long>(base),
					static_cast<unsigned long long>(size));
				return false;
			}

			diag::log_tagged_critical_fmt("binary_map",
				"dump_region START base=0x%llX size=%llu path='%s'",
				static_cast<unsigned long long>(base),
				static_cast<unsigned long long>(size),
				path_buf);

			std::vector<uint8_t> buf;
			const bool ok_read = driver_bridge::read_memory(base, static_cast<size_t>(size), buf);

			if (!ok_read || buf.empty()) {
				if (g_disasm.file.loaded && !g_disasm.file.sections.empty()) {
					std::vector<uint8_t> static_buf;
					if (static_analysis::read_bytes_from_pe(g_disasm.file, base,
							static_cast<size_t>(size), static_buf) && !static_buf.empty())
					{
						buf = std::move(static_buf);
					}
				}
			}

			if (buf.empty()) {
				diag::log_tagged_fmt("binary_map",
					"dump_region FAILED_read base=0x%llX size=%llu",
					static_cast<unsigned long long>(base),
					static_cast<unsigned long long>(size));
				toast_notification::push("Failed to read region for dump",
					toast_notification::toast_type_t::error, 3.0f);
				return false;
			}

			std::ofstream ofs(path_buf, std::ios::binary | std::ios::trunc);
			if (!ofs.is_open()) {
				diag::log_tagged_fmt("binary_map",
					"dump_region FAILED_open path='%s'", path_buf);
				toast_notification::push("Failed to open dump file for writing",
					toast_notification::toast_type_t::error, 3.0f);
				return false;
			}
			ofs.write(reinterpret_cast<const char*>(buf.data()),
				static_cast<std::streamsize>(buf.size()));
			ofs.close();

			diag::log_tagged_critical_fmt("binary_map",
				"dump_region DONE bytes=%zu path='%s'",
				buf.size(), path_buf);

			char msg[MAX_PATH + 64];
			std::snprintf(msg, sizeof(msg), "Dumped %llu bytes to %s",
				static_cast<unsigned long long>(buf.size()), path_buf);
			toast_notification::push(msg, toast_notification::toast_type_t::info, 3.5f);
			return true;
		}

		inline std::string make_function_chat_payload(const binary_map::map_function_t& f)
		{
			std::string out = "Binary map function summary:\n";
			out += format_function_summary(f);
			if (!f.section_name.empty()) {
				out += "\nSection: ";
				out += f.section_name;
			}
			if (f.pinned) out += "\n(pinned)";
			out += "\n";
			return out;
		}

		inline std::string make_global_chat_payload(const binary_map::map_global_t& g)
		{
			char buf[256];
			std::snprintf(buf, sizeof(buf),
				"Binary map global: %s @ 0x%llX (xrefs=%d, %s%s)\n",
				g.name.c_str(),
				static_cast<unsigned long long>(g.va),
				g.xref_count,
				g.writable ? "rw" : "ro",
				g.section_name.empty() ? "" : (std::string(", ") + g.section_name).c_str());
			return std::string(buf);
		}

		inline std::string make_region_chat_payload(const live_region_t& r)
		{
			std::string out = "Live memory region:\n";
			char buf[512];
			std::snprintf(buf, sizeof(buf),
				"  Base 0x%016llX  Size %s\n"
				"  Kind %s  State %s  Type %s  Protect %s\n",
				static_cast<unsigned long long>(r.base),
				format_size_human(r.size).c_str(),
				region_kind_label(r).c_str(),
				format_state_word(r.state).c_str(),
				format_type_word(r.type).c_str(),
				format_protect_word(r.protect).c_str());
			out += buf;
			if (!r.module_name.empty()) {
				std::snprintf(buf, sizeof(buf), "  Module %s\n", r.module_name.c_str());
				out += buf;
			}
			if (!r.info.empty()) {
				std::snprintf(buf, sizeof(buf), "  Info %s\n", r.info.c_str());
				out += buf;
			}
			return out;
		}

		inline std::string region_to_json(const live_region_t& r)
		{
			std::string out = "{";
			char buf[256];
			std::snprintf(buf, sizeof(buf), "\"base\":\"0x%016llX\",",
				static_cast<unsigned long long>(r.base)); out += buf;
			std::snprintf(buf, sizeof(buf), "\"size\":%llu,",
				static_cast<unsigned long long>(r.size)); out += buf;
			std::snprintf(buf, sizeof(buf), "\"protect\":\"0x%X\",", r.protect); out += buf;
			std::snprintf(buf, sizeof(buf), "\"state\":\"0x%X\",", r.state); out += buf;
			std::snprintf(buf, sizeof(buf), "\"type\":\"0x%X\",", r.type); out += buf;
			out += "\"kind\":\"" + region_kind_label(r) + "\",";
			out += "\"module\":\"" + r.module_name + "\",";
			out += "\"info\":\"" + r.info + "\"";
			out += "}";
			return out;
		}

		inline std::string export_live_snapshot_json(const live_snapshot_t& snap)
		{
			std::string out;
			char hdr[256];
			std::snprintf(hdr, sizeof(hdr),
				"{\"pid\":%u,\"process\":\"%s\",\"committed\":%llu,\"reserved\":%llu,"
				"\"rwx_count\":%u,\"region_count\":%zu,\"regions\":[",
				static_cast<unsigned>(snap.pid),
				snap.process_name.c_str(),
				static_cast<unsigned long long>(snap.total_committed),
				static_cast<unsigned long long>(snap.total_reserved),
				static_cast<unsigned>(snap.rwx_count),
				snap.regions.size());
			out = hdr;
			for (size_t i = 0; i < snap.regions.size(); ++i) {
				if (i) out += ",";
				out += region_to_json(snap.regions[i]);
			}
			out += "]}";
			return out;
		}

		inline bool group_is_collapsed(view_state_t& s, const std::string& key)
		{
			return s.collapsed_groups.count(key) != 0;
		}

		inline void toggle_group(view_state_t& s, const std::string& key)
		{
			auto it = s.collapsed_groups.find(key);
			if (it == s.collapsed_groups.end())
				s.collapsed_groups.insert(key);
			else
				s.collapsed_groups.erase(it);
		}

		inline float section_entropy_normalized(const binary_map::map_section_t& s)
		{
			if (s.sampled_bytes == 0) return 0.f;
			float e = s.entropy;
			if (e < 0.f) e = 0.f;
			if (e > 1.f) e = 1.f;
			return e;
		}

		inline void render_section_strip(ImDrawList* dl, ImVec2 origin, float width,
			const std::vector<binary_map::map_section_t>& sections,
			uint64_t image_size, float alpha, float anim_time)
		{
			if (sections.empty()) {
				const auto& t = aida::ui::resolved();
				dl->AddText(ImVec2(origin.x + 8.f, origin.y + 8.f),
					aida::ui::with_alpha(t.text_dim, alpha),
					"(no section table available)");
				return;
			}
			const auto& t = aida::ui::resolved();
			float total_size = 0.f;
			for (const auto& s : sections) total_size += static_cast<float>(s.size);
			if (total_size < 1.f) total_size = 1.f;
			float min_size = static_cast<float>(image_size);
			if (min_size < total_size) min_size = total_size;

			const float strip_h = 38.f;
			const float gap = 2.f;
			float x = origin.x;
			float y = origin.y;

			float anim_p = anim_time * 0.45f;
			if (anim_p > 1.f) anim_p = 1.f;
			float reveal = aida::motion::ease::out_cubic(anim_p);

			float total_w = width - gap * static_cast<float>(sections.size() - 1);
			for (size_t i = 0; i < sections.size(); ++i) {
				const auto& s = sections[i];
				float frac = static_cast<float>(s.size) / total_size;
				float sw = total_w * frac;
				if (sw < 28.f) sw = 28.f;
				if (x + sw > origin.x + width) sw = origin.x + width - x;
				if (sw <= 1.f) break;

				float effective_w = sw * reveal;
				ImVec2 a = ImVec2(x, y);
				ImVec2 b = ImVec2(x + effective_w, y + strip_h);

				ImU32 base = section_color(s, alpha);
				ImU32 dim  = aida::ui::with_alpha(base, alpha * 0.32f);

				dl->AddRectFilled(a, b, dim, 4.f);
				dl->AddRectFilledMultiColor(a, b,
					base, base,
					aida::ui::with_alpha(base, alpha * 0.55f),
					aida::ui::with_alpha(base, alpha * 0.55f));
				dl->AddRect(a, b, aida::ui::with_alpha(t.border_subtle, alpha), 4.f, 0, 1.f);

				ImFont* font = aida::ui::fonts::body_em();
				if (!font) font = ImGui::GetFont();
				float fs = font->FontSize > 0.f ? font->FontSize : 16.f;
				ImU32 lbl_col = aida::ui::with_alpha(IM_COL32(255, 255, 255, 245), alpha);
				ImVec2 ts = font->CalcTextSizeA(fs, FLT_MAX, 0.f, s.name.c_str());
				if (effective_w > ts.x + 14.f) {
					dl->AddText(font, fs, ImVec2(a.x + 8.f, a.y + (strip_h - fs) * 0.5f),
						lbl_col, s.name.c_str());

					float perm_w = effective_w - ts.x - 18.f;
					ImFont* perm_font = aida::ui::fonts::caption();
					if (!perm_font) perm_font = font;
					float perm_fs = perm_font->FontSize > 0.f ? perm_font->FontSize : 13.f;
					if (perm_w > 36.f) {
						std::string p = section_perm_string(s);
						ImVec2 perm_sz = perm_font->CalcTextSizeA(perm_fs, FLT_MAX, 0.f, p.c_str());
						dl->AddText(perm_font, perm_fs,
							ImVec2(b.x - perm_sz.x - 8.f, a.y + (strip_h - perm_fs) * 0.5f),
							aida::ui::with_alpha(IM_COL32(255, 255, 255, 220), alpha * 0.85f),
							p.c_str());
					}
				}

				ImGui::SetCursorScreenPos(a);
				ImGui::PushID(static_cast<int>(i));
				ImGui::InvisibleButton("##sec", ImVec2(effective_w, strip_h));
				if (ImGui::IsItemHovered()) {
					ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 6.f));
					ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(t.bg_overlay));
					if (ImGui::BeginTooltip()) {
						ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(t.text_primary));
						ImGui::Text("%s   %s   %s",
							s.name.c_str(),
							section_perm_string(s).c_str(),
							format_size_human(s.size).c_str());
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
							"VA   0x%llX", static_cast<unsigned long long>(s.va));
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
							"End  0x%llX", static_cast<unsigned long long>(s.va + s.size));
						const float ent01 = section_entropy_normalized(s);
						if (s.sampled_bytes > 0) {
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_secondary),
								"Entropy %.2f bits/byte  (%.0f%%)",
								static_cast<double>(ent01) * 8.0,
								static_cast<double>(ent01) * 100.0);
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
								"sampled %s of %s",
								format_size_human(s.sampled_bytes).c_str(),
								format_size_human(s.size).c_str());
							const char* verdict =
								(ent01 > 0.94f) ? "very high (packed/encrypted)" :
								(ent01 > 0.80f) ? "high (compressed)" :
								(ent01 > 0.55f) ? "moderate (mixed code/data)" :
								(ent01 > 0.30f) ? "low (text/structured)" :
								                  "very low (sparse)";
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_secondary),
								"Verdict: %s", verdict);
						} else {
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
								"Entropy: (not sampled)");
						}
						ImGui::PopStyleColor();
						ImGui::EndTooltip();
					}
					ImGui::PopStyleColor();
					ImGui::PopStyleVar();
				}
				if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
					diag::log_tagged_fmt("binary_map",
						"section_strip_click name='%s' va=0x%llX size=%llu perm=%s entropy01=%.3f",
						s.name.c_str(),
						static_cast<unsigned long long>(s.va),
						static_cast<unsigned long long>(s.size),
						section_perm_string(s).c_str(),
						static_cast<double>(section_entropy_normalized(s)));
					detail::jump_to_address(s.va);
				}
				if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
					diag::log_tagged_fmt("binary_map",
						"section_strip_right_click_open_hex name='%s' va=0x%llX size=%llu",
						s.name.c_str(),
						static_cast<unsigned long long>(s.va),
						static_cast<unsigned long long>(s.size));
					detail::jump_to_hex(s.va, static_cast<size_t>(s.size));
				}
				ImGui::PopID();

				x += sw + gap;
				if (x >= origin.x + width) break;
			}

			float entropy_y = y + strip_h + 4.f;
			x = origin.x;
			for (size_t i = 0; i < sections.size(); ++i) {
				const auto& s = sections[i];
				float frac = static_cast<float>(s.size) / total_size;
				float sw = total_w * frac;
				if (sw < 28.f) sw = 28.f;
				if (x + sw > origin.x + width) sw = origin.x + width - x;
				if (sw <= 1.f) break;
				float entropy = section_entropy_normalized(s) * reveal;
				const float bar_track_w = sw - 8.f;
				float bar_w = bar_track_w * entropy;
				if (bar_w < 0.f) bar_w = 0.f;
				if (bar_w > bar_track_w) bar_w = bar_track_w;
				ImU32 ec = (s.sampled_bytes > 0)
					? aida::ui::mix(t.success, t.error, entropy)
					: aida::ui::with_alpha(t.text_dim, alpha * 0.5f);
				const float bar_h = 4.f;
				dl->AddRectFilled(ImVec2(x + 4.f, entropy_y),
					ImVec2(x + 4.f + bar_track_w, entropy_y + bar_h),
					aida::ui::with_alpha(t.border_subtle, alpha * 0.55f), 1.5f);
				if (bar_w > 0.5f) {
					dl->AddRectFilled(ImVec2(x + 4.f, entropy_y),
						ImVec2(x + 4.f + bar_w, entropy_y + bar_h),
						aida::ui::with_alpha(ec, alpha * 0.9f), 1.5f);
				}
				if (s.sampled_bytes > 0) {
					ImFont* tiny = aida::ui::fonts::caption();
					if (!tiny) tiny = ImGui::GetFont();
					const float tiny_fs = tiny->FontSize > 0.f ? tiny->FontSize * 0.85f : 11.f;
					char ebuf[24];
					std::snprintf(ebuf, sizeof(ebuf), "%.2f",
						static_cast<double>(section_entropy_normalized(s)) * 8.0);
					ImVec2 esz = tiny->CalcTextSizeA(tiny_fs, FLT_MAX, 0.f, ebuf);
					if (sw > esz.x + 18.f) {
						dl->AddText(tiny, tiny_fs,
							ImVec2(x + sw - esz.x - 6.f, entropy_y + bar_h + 2.f),
							aida::ui::with_alpha(ec, alpha * 0.95f), ebuf);
					}
				}
				x += sw + gap;
			}
		}

		inline ImU32 heatmap_color(int xrefs, int max_xrefs, float alpha)
		{
			const auto& t = aida::ui::resolved();
			float v = (max_xrefs > 0) ? static_cast<float>(xrefs) / static_cast<float>(max_xrefs) : 0.f;
			if (v > 1.f) v = 1.f;
			ImU32 cool = t.info_soft;
			ImU32 mid  = t.accent_dim;
			ImU32 hot  = t.warning;
			ImU32 c;
			if (v < 0.5f) {
				c = aida::ui::mix(cool, mid, v * 2.f);
			} else {
				c = aida::ui::mix(mid, hot, (v - 0.5f) * 2.f);
			}
			return aida::ui::with_alpha(c, alpha * (0.45f + v * 0.55f));
		}

		inline void render_function_heatmap(ImDrawList* dl, ImVec2 origin, float width, float height,
			const std::vector<binary_map::map_function_t>& funcs,
			view_state_t& vs, float alpha, float anim_time, uint64_t selected_va)
		{
			const auto& t = aida::ui::resolved();
			vs.hover_function_va = 0;
			if (funcs.empty()) {
				ImVec2 sz = ImVec2(width, height);
				aida::ui::empty_state::config_t cfg;
				cfg.glyph = aida::ui::empty_state::glyph_t::dots;
				cfg.title = "No functions available";
				cfg.body  = "Run analysis or wait for the binary map to populate.";
				cfg.max_width = 320.f;
				aida::ui::empty_state::render(origin, sz, cfg);
				return;
			}

			int max_xrefs = 0;
			for (const auto& f : funcs)
				if (f.xref_count > max_xrefs) max_xrefs = f.xref_count;
			if (max_xrefs <= 0) max_xrefs = 1;

			const float cell_size = 14.f;
			const float gap = 3.f;
			int cols = static_cast<int>((width + gap) / (cell_size + gap));
			if (cols < 4) cols = 4;
			int rows = (static_cast<int>(funcs.size()) + cols - 1) / cols;
			float used_h = static_cast<float>(rows) * (cell_size + gap);
			if (used_h > height) used_h = height;

			float anim_p = anim_time * 0.5f;
			if (anim_p > 1.f) anim_p = 1.f;

			for (size_t i = 0; i < funcs.size(); ++i) {
				int r = static_cast<int>(i) / cols;
				int c = static_cast<int>(i) % cols;
				float ax = origin.x + static_cast<float>(c) * (cell_size + gap);
				float ay = origin.y + static_cast<float>(r) * (cell_size + gap);
				if (ay + cell_size > origin.y + used_h) break;

				const auto& fn = funcs[i];
				float entrance = anim_p - static_cast<float>(i) * 0.0008f;
				if (entrance < 0.f) entrance = 0.f;
				if (entrance > 1.f) entrance = 1.f;
				float scale = 0.7f + 0.3f * aida::motion::ease::out_back(entrance);

				ImGui::SetCursorScreenPos(ImVec2(ax, ay));
				ImGui::PushID(static_cast<int>(0x10000000 | i));
				ImGui::InvisibleButton("##bm_heat_cell", ImVec2(cell_size, cell_size));
				const bool hovered = ImGui::IsItemHovered();
				const bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
				const bool double_clicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)
					&& ImGui::IsItemHovered();
				const bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);
				ImGui::PopID();

				bool selected = (selected_va == fn.va) && (fn.va != 0);
				ImU32 fill = heatmap_color(fn.xref_count, max_xrefs, alpha * entrance);
				ImU32 border = aida::ui::with_alpha(t.border_subtle, alpha * 0.6f);
				if (selected) border = aida::ui::with_alpha(t.accent_u32, alpha);

				float ch = cell_size * scale;
				float pad = (cell_size - ch) * 0.5f;
				ImVec2 ca = ImVec2(ax + pad, ay + pad);
				ImVec2 cb = ImVec2(ax + cell_size - pad, ay + cell_size - pad);

				if (fn.pinned) {
					ImU32 ring = aida::ui::with_alpha(t.accent_u32, alpha * 0.85f);
					dl->AddRect(ImVec2(ca.x - 1.f, ca.y - 1.f), ImVec2(cb.x + 1.f, cb.y + 1.f),
						ring, 3.f, 0, 1.5f);
				}

				dl->AddRectFilled(ca, cb, fill, 3.f);
				dl->AddRect(ca, cb, border, 3.f, 0, 1.f);

				auto& pulse = vs.fn_pulses[fn.va];
				if (hovered) pulse.v = aida::motion::smooth_lerp(pulse.v, 1.f, 18.f, aida::ui::clock::dt());
				else         pulse.v = aida::motion::smooth_lerp(pulse.v, 0.f, 12.f, aida::ui::clock::dt());
				if (pulse.v > 0.01f) {
					ImU32 hov_ring = aida::ui::with_alpha(t.accent_hover, alpha * 0.9f * pulse.v);
					float exp = pulse.v * 2.f;
					dl->AddRect(ImVec2(ca.x - exp, ca.y - exp), ImVec2(cb.x + exp, cb.y + exp),
						hov_ring, 4.f, 0, 1.5f);
				}

				if (hovered) {
					vs.hover_function_va = fn.va;
					const ImVec2 mp = ImGui::GetMousePos();
					ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 6.f));
					ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(t.bg_overlay));
					ImGui::SetNextWindowPos(ImVec2(mp.x + 14.f, mp.y + 14.f));
					if (ImGui::Begin("##bm_fn_tip", nullptr,
						ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
						ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
						ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_AlwaysAutoResize |
						ImGuiWindowFlags_NoNav | ImGuiWindowFlags_Tooltip)) {
						ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(t.text_primary));
						ImGui::TextUnformatted(fn.name.c_str());
						ImGui::PopStyleColor();
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
							"0x%llX", static_cast<unsigned long long>(fn.va));
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_secondary),
							"xrefs %d   callees %d", fn.xref_count, fn.callee_count);
						if (!fn.section_name.empty()) {
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
								"in %s", fn.section_name.c_str());
						}
					}
					ImGui::End();
					ImGui::PopStyleColor();
					ImGui::PopStyleVar();
				}
				if (clicked) {
					vs.selected_va.store(fn.va);
					diag::log_tagged_fmt("binary_map",
						"heatmap_select name='%s' va=0x%llX xrefs=%d callees=%d",
						fn.name.c_str(),
						static_cast<unsigned long long>(fn.va),
						fn.xref_count, fn.callee_count);
				}
				if (double_clicked) {
					diag::log_tagged_fmt("binary_map",
						"heatmap_double_click name='%s' va=0x%llX",
						fn.name.c_str(),
						static_cast<unsigned long long>(fn.va));
					jump_to_address(fn.va);
				}
				if (right_clicked) {
					diag::log_tagged_fmt("binary_map",
						"heatmap_right_click name='%s' va=0x%llX",
						fn.name.c_str(),
						static_cast<unsigned long long>(fn.va));
					vs.selected_va.store(fn.va);
					ImGui::OpenPopup("##bm_heat_ctx");
				}
				if (ImGui::BeginPopup("##bm_heat_ctx")) {
					if (ImGui::MenuItem("Jump to disassembly")) {
						const uint64_t va_local = fn.va;
						ImGui::CloseCurrentPopup();
						jump_to_address(va_local);
					}
					if (ImGui::MenuItem("Open in hex view")) {
						const uint64_t va_local = fn.va;
						ImGui::CloseCurrentPopup();
						jump_to_hex(va_local, 0x400);
					}
					ImGui::EndPopup();
				}
			}
		}

		inline int region_index_for_va(const std::vector<live_region_t>& regions, uint64_t va)
		{
			for (size_t i = 0; i < regions.size(); ++i) {
				const auto& r = regions[i];
				if (va >= r.base && va < r.base + r.size) return static_cast<int>(i);
			}
			return -1;
		}

		inline void render_address_space_canvas(ImDrawList* dl, ImVec2 origin, float width, float height,
			const std::vector<live_region_t>& regions,
			const std::vector<driver_bridge::thread_info_t>& threads,
			view_state_t& vs, float alpha, float anim_time, uint64_t selected_base)
		{
			const auto& t = aida::ui::resolved();
			ImVec2 a = origin;
			ImVec2 b = ImVec2(origin.x + width, origin.y + height);

			aida::ui::blur::render_glass_fill(dl, a, b, 8.f, alpha);
			aida::ui::blur::render_glass_border(dl, a, b, 8.f, alpha, 1.f);

			ImFont* hdr_font = aida::ui::fonts::body_em();
			if (!hdr_font) hdr_font = ImGui::GetFont();
			const float hdr_fs = hdr_font->FontSize > 0.f ? hdr_font->FontSize : 16.f;
			dl->AddText(hdr_font, hdr_fs, ImVec2(a.x + 12.f, a.y + 8.f),
				aida::ui::with_alpha(t.text_secondary, alpha), "Address Space");

			if (regions.empty()) {
				ImFont* body = aida::ui::fonts::body();
				if (!body) body = ImGui::GetFont();
				const float body_fs = body->FontSize > 0.f ? body->FontSize : 16.f;
				const char* msg = "Attach to a process or refresh to see live mappings.";
				ImVec2 ts = body->CalcTextSizeA(body_fs, FLT_MAX, 0.f, msg);
				dl->AddText(body, body_fs,
					ImVec2(a.x + (width - ts.x) * 0.5f, a.y + (height - ts.y) * 0.5f),
					aida::ui::with_alpha(t.text_dim, alpha), msg);
				return;
			}

			const float canvas_top = a.y + 36.f;
			const float canvas_bot = b.y - 24.f;
			const float canvas_h = canvas_bot - canvas_top;
			if (canvas_h <= 10.f) return;

			const float canvas_left = a.x + 14.f;
			const float canvas_right = b.x - 110.f;
			const float canvas_w = canvas_right - canvas_left;
			if (canvas_w <= 20.f) return;

			uint64_t va_min = regions.front().base;
			uint64_t va_max = regions.back().base + regions.back().size;
			if (va_max <= va_min) va_max = va_min + 1;
			const double full_span = static_cast<double>(va_max - va_min);

			const float zoom = vs.canvas_zoom;
			const double visible_span = full_span / static_cast<double>(zoom);
			double offset_norm = vs.canvas_offset_norm;
			if (offset_norm < 0.0) offset_norm = 0.0;
			if (offset_norm > 1.0 - 1.0 / static_cast<double>(zoom)) {
				offset_norm = 1.0 - 1.0 / static_cast<double>(zoom);
				if (offset_norm < 0.0) offset_norm = 0.0;
			}
			vs.canvas_offset_norm = offset_norm;
			vs.canvas_target_offset_norm = offset_norm;

			const double view_low_off = offset_norm * full_span;
			const uint64_t view_va_low  = va_min + static_cast<uint64_t>(view_low_off);
			const uint64_t view_va_high = view_va_low + static_cast<uint64_t>(visible_span);

			ImVec2 strip_a = ImVec2(canvas_left, canvas_top);
			ImVec2 strip_b = ImVec2(canvas_right, canvas_bot);
			dl->PushClipRect(strip_a, strip_b, true);
			dl->AddRectFilled(strip_a, strip_b,
				aida::ui::with_alpha(t.panel_header, alpha * 0.45f), 4.f);

			int hover_idx = -1;
			ImVec2 mp = ImGui::GetMousePos();

			for (size_t i = 0; i < regions.size(); ++i) {
				const auto& r = regions[i];
				if (r.base + r.size <= view_va_low) continue;
				if (r.base >= view_va_high) break;

				const uint64_t clip_lo = (r.base < view_va_low) ? view_va_low : r.base;
				const uint64_t clip_hi = ((r.base + r.size) > view_va_high) ? view_va_high : (r.base + r.size);
				if (clip_hi <= clip_lo) continue;

				const double lo_frac = static_cast<double>(clip_lo - view_va_low) / visible_span;
				const double hi_frac = static_cast<double>(clip_hi - view_va_low) / visible_span;
				const float yl = canvas_top + static_cast<float>(lo_frac) * canvas_h;
				const float yh = canvas_top + static_cast<float>(hi_frac) * canvas_h;
				const float h = (yh - yl < 2.f) ? 2.f : (yh - yl);

				ImU32 col = region_color(r, alpha);
				dl->AddRectFilled(ImVec2(canvas_left + 2.f, yl),
					ImVec2(canvas_right - 2.f, yl + h), col, 2.f);

				if (mp.x >= canvas_left && mp.x <= canvas_right
					&& mp.y >= yl && mp.y <= yl + h)
				{
					hover_idx = static_cast<int>(i);
				}

				const bool is_selected = (selected_base == r.base && r.base != 0);
				if (is_selected) {
					dl->AddRect(ImVec2(canvas_left, yl - 1.f),
						ImVec2(canvas_right, yl + h + 1.f),
						aida::ui::with_alpha(t.accent_u32, alpha), 2.f, 0, 1.6f);
				}
			}

			for (const auto& th : threads) {
				if (th.rip == 0) continue;
				if (th.rip < view_va_low || th.rip >= view_va_high) continue;
				const double frac = static_cast<double>(th.rip - view_va_low) / visible_span;
				const float ty = canvas_top + static_cast<float>(frac) * canvas_h;
				const ImU32 mark_col = aida::ui::with_alpha(t.accent_glow, alpha);
				dl->AddLine(ImVec2(canvas_left, ty), ImVec2(canvas_right, ty), mark_col, 1.4f);
				dl->AddTriangleFilled(
					ImVec2(canvas_left - 6.f, ty - 4.f),
					ImVec2(canvas_left - 6.f, ty + 4.f),
					ImVec2(canvas_left,       ty),
					mark_col);
			}

			dl->PopClipRect();

			ImGui::SetCursorScreenPos(strip_a);
			ImGui::InvisibleButton("##bm_canvas_strip", ImVec2(canvas_w, canvas_h));
			const bool strip_hov = ImGui::IsItemHovered();
			if (strip_hov) {
				const ImGuiIO& io = ImGui::GetIO();
				if (io.MouseWheel != 0.f) {
					float new_zoom = vs.canvas_zoom * (1.f + io.MouseWheel * 0.18f);
					if (new_zoom < 1.f) new_zoom = 1.f;
					if (new_zoom > 4096.f) new_zoom = 4096.f;
					const double mouse_frac = static_cast<double>((mp.y - canvas_top) / canvas_h);
					const double mouse_va_off = view_low_off + visible_span * mouse_frac;
					const double new_visible_span = full_span / static_cast<double>(new_zoom);
					double new_low_off = mouse_va_off - new_visible_span * mouse_frac;
					if (new_low_off < 0.0) new_low_off = 0.0;
					if (new_low_off > full_span - new_visible_span) new_low_off = full_span - new_visible_span;
					if (new_low_off < 0.0) new_low_off = 0.0;
					vs.canvas_zoom = new_zoom;
					vs.canvas_target_zoom = new_zoom;
					vs.canvas_offset_norm = new_low_off / full_span;
					vs.canvas_target_offset_norm = vs.canvas_offset_norm;
					diag::log_tagged_fmt("binary_map",
						"canvas_zoom new_zoom=%.3f offset_norm=%.4f",
						static_cast<double>(new_zoom),
						vs.canvas_offset_norm);
				}
				if (ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
					if (!vs.canvas_dragging) {
						vs.canvas_dragging = true;
						vs.canvas_drag_anchor = mp.y;
						vs.canvas_drag_offset_start = vs.canvas_offset_norm;
					}
					const float dy = mp.y - vs.canvas_drag_anchor;
					const double dy_frac = static_cast<double>(-dy / canvas_h) / static_cast<double>(zoom);
					double new_off = vs.canvas_drag_offset_start + dy_frac;
					const double max_off = 1.0 - 1.0 / static_cast<double>(zoom);
					if (new_off < 0.0) new_off = 0.0;
					if (new_off > max_off) new_off = max_off;
					vs.canvas_offset_norm = new_off;
					vs.canvas_target_offset_norm = new_off;
				}
			}
			if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
				if (vs.canvas_dragging) {
					diag::log_tagged_fmt("binary_map",
						"canvas_drag_release offset_norm=%.4f zoom=%.3f",
						vs.canvas_offset_norm,
						static_cast<double>(vs.canvas_zoom));
					vs.canvas_dragging = false;
				}
			}

			if (hover_idx >= 0) {
				const auto& hr = regions[static_cast<size_t>(hover_idx)];
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 8.f));
				ImGui::PushStyleColor(ImGuiCol_PopupBg,
					ImGui::ColorConvertU32ToFloat4(t.bg_overlay));
				char tip[768];
				std::snprintf(tip, sizeof(tip),
					"%s\n0x%016llX - 0x%016llX\n%s | %s | %s\n%s",
					hr.module_name.empty() ? region_kind_label(hr).c_str() : hr.module_name.c_str(),
					static_cast<unsigned long long>(hr.base),
					static_cast<unsigned long long>(hr.base + hr.size),
					format_protect_word(hr.protect).c_str(),
					format_state_word(hr.state).c_str(),
					format_type_word(hr.type).c_str(),
					format_size_human(hr.size).c_str());
				ImGui::SetTooltip("%s", tip);
				ImGui::PopStyleColor();
				ImGui::PopStyleVar();

				if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !vs.canvas_dragging) {
					vs.live_selected_base.store(hr.base);
					diag::log_tagged_fmt("binary_map",
						"canvas_select base=0x%llX size=%llu kind=%s",
						static_cast<unsigned long long>(hr.base),
						static_cast<unsigned long long>(hr.size),
						region_kind_label(hr).c_str());
				}
				if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
					diag::log_tagged_fmt("binary_map",
						"canvas_double_click base=0x%llX -> jump_to_disasm",
						static_cast<unsigned long long>(hr.base));
					jump_to_address(hr.base);
				}
			}

			vs.live_hover_index.store(hover_idx);

			ImFont* code_font = aida::ui::fonts::code();
			if (!code_font) code_font = ImGui::GetFont();
			const float tick_fs = (code_font->FontSize > 0.f ? code_font->FontSize : 13.f) * 0.95f;
			const int tick_count = 6;
			for (int ti = 0; ti < tick_count; ++ti) {
				const float frac = static_cast<float>(ti) / static_cast<float>(tick_count - 1);
				const float ty = canvas_top + frac * canvas_h;
				dl->AddLine(ImVec2(canvas_right + 4.f, ty), ImVec2(canvas_right + 8.f, ty),
					aida::ui::with_alpha(t.text_dim, alpha), 1.f);
				const uint64_t va = view_va_low + static_cast<uint64_t>(visible_span * static_cast<double>(frac));
				char buf[24];
				std::snprintf(buf, sizeof(buf), "%012" PRIX64, va);
				dl->AddText(code_font, tick_fs,
					ImVec2(canvas_right + 12.f, ty - tick_fs * 0.5f),
					aida::ui::with_alpha(t.text_dim, alpha), buf);
			}

			char zoom_buf[48];
			std::snprintf(zoom_buf, sizeof(zoom_buf), "zoom %.1fx", static_cast<double>(zoom));
			ImFont* cap = aida::ui::fonts::caption();
			if (!cap) cap = ImGui::GetFont();
			const float cap_fs = cap->FontSize > 0.f ? cap->FontSize : 13.f;
			dl->AddText(cap, cap_fs,
				ImVec2(a.x + 12.f, b.y - cap_fs - 6.f),
				aida::ui::with_alpha(t.text_dim, alpha), zoom_buf);

			char range_buf[64];
			std::snprintf(range_buf, sizeof(range_buf),
				"0x%llX - 0x%llX",
				static_cast<unsigned long long>(view_va_low),
				static_cast<unsigned long long>(view_va_high));
			dl->AddText(cap, cap_fs,
				ImVec2(a.x + 80.f, b.y - cap_fs - 6.f),
				aida::ui::with_alpha(t.text_dim, alpha), range_buf);
		}

		inline void render_legend(ImDrawList* dl, ImVec2 origin, float width, float alpha)
		{
			const auto& t = aida::ui::resolved();
			ImFont* cap = aida::ui::fonts::caption();
			if (!cap) cap = ImGui::GetFont();
			const float fs = cap->FontSize > 0.f ? cap->FontSize : 13.f;

			struct entry_t { const char* lbl; ImU32 col; };
			entry_t entries[] = {
				{ "image",   aida::ui::with_alpha(t.success, alpha) },
				{ "mapped",  aida::ui::with_alpha(t.info, alpha) },
				{ "private", aida::ui::with_alpha(t.accent_dim, alpha) },
				{ "stack",   aida::ui::with_alpha(t.warning, alpha) },
				{ "heap",    aida::ui::with_alpha(t.info_soft, alpha) },
				{ "guard",   aida::ui::with_alpha(t.error, alpha) },
				{ "reserved", aida::ui::with_alpha(t.text_dim, alpha * 0.6f) }
			};
			float x = origin.x;
			for (auto& e : entries) {
				dl->AddRectFilled(ImVec2(x, origin.y + 4.f),
					ImVec2(x + 10.f, origin.y + 4.f + fs * 0.9f),
					e.col, 2.f);
				dl->AddText(cap, fs, ImVec2(x + 14.f, origin.y + 4.f),
					aida::ui::with_alpha(t.text_secondary, alpha), e.lbl);
				ImVec2 ts = cap->CalcTextSizeA(fs, FLT_MAX, 0.f, e.lbl);
				x += 14.f + ts.x + 14.f;
				if (x > origin.x + width) break;
			}
		}

	}

	inline void initialize()
	{
		view_state_t& s = state();
		std::lock_guard<std::mutex> g(s.mutex);
		if (s.initialized) return;
		s.opts.max_functions = 200;
		s.opts.max_globals = 60;
		s.opts.max_callees_per_function = 5;
		s.opts.max_chars = 16384;
		s.opts.include_imports = true;
		s.opts.include_exports = true;
		s.canvas_zoom = 1.f;
		s.canvas_target_zoom = 1.f;
		s.canvas_offset_norm = 0.0;
		s.canvas_target_offset_norm = 0.0;
		detail::ensure_subscriptions(s);
		s.initialized = true;
		diag::log_tagged_fmt("binary_map",
			"view_initialize max_functions=%d max_globals=%d max_chars=%zu include_imp=%d include_exp=%d",
			s.opts.max_functions, s.opts.max_globals, s.opts.max_chars,
			s.opts.include_imports ? 1 : 0, s.opts.include_exports ? 1 : 0);
	}

	inline void shutdown()
	{
		view_state_t& s = state();
		std::lock_guard<std::mutex> g(s.mutex);
		if (s.subscription_binary.valid()) {
			aida::events::unsubscribe(s.subscription_binary);
			s.subscription_binary = aida::events::subscription_handle_t{};
		}
		if (s.subscription_proc_created.valid()) {
			aida::events::unsubscribe(s.subscription_proc_created);
			s.subscription_proc_created = aida::events::subscription_handle_t{};
		}
		if (s.subscription_proc_exited.valid()) {
			aida::events::unsubscribe(s.subscription_proc_exited);
			s.subscription_proc_exited = aida::events::subscription_handle_t{};
		}
		s.collapsed_groups.clear();
		s.expanded_imports.clear();
		s.rendered_text.clear();
		s.map = binary_map::map_t{};
		s.has_map.store(false);
		s.live = live_snapshot_t{};
		s.initialized = false;
	}

	inline const std::string& last_error()
	{
		view_state_t& s = state();
		std::lock_guard<std::mutex> g(s.mutex);
		return s.last_error;
	}

	inline void refresh()
	{
		state().refresh_requested.store(true);
		state().live_refresh_requested.store(true);
	}

	namespace detail {

		inline void render_pe_left_pane(ImDrawList* dl, view_state_t& s,
			float panel_x, float panel_y, float panel_w, float content_h, float content_y,
			float a, const std::vector<binary_map::map_section_t>& sections_copy,
			const std::vector<binary_map::map_function_t>& functions_copy,
			uint64_t image_size, uint64_t selected_va_local, float full_h)
		{
			const auto& t = aida::ui::resolved();
			ImFont* sec_label = aida::ui::fonts::body_em();
			if (!sec_label) sec_label = ImGui::GetFont();
			const float sec_label_fs = sec_label->FontSize > 0.f ? sec_label->FontSize : 16.f;
			dl->AddText(sec_label, sec_label_fs, ImVec2(panel_x, panel_y),
				aida::ui::with_alpha(t.text_secondary, a), "Section Layout");

			float strip_top = panel_y + 24.f;
			render_section_strip(dl, ImVec2(panel_x, strip_top), panel_w,
				sections_copy, image_size, a, s.row_anim_time);

			float heat_top = strip_top + 38.f + 44.f;
			{
				ImFont* hh_font = aida::ui::fonts::body_em();
				if (!hh_font) hh_font = ImGui::GetFont();
				const float hh_fs = hh_font->FontSize > 0.f ? hh_font->FontSize : 16.f;
				dl->AddText(hh_font, hh_fs, ImVec2(panel_x, heat_top - hh_fs - 6.f),
					aida::ui::with_alpha(t.text_secondary, a), "Function Heatmap");
			}

			float heat_h = full_h - (heat_top - content_y) - 12.f;
			if (heat_h < 120.f) heat_h = 120.f;
			render_function_heatmap(dl, ImVec2(panel_x, heat_top),
				panel_w, heat_h, functions_copy, s, a, s.row_anim_time, selected_va_local);
		}

		inline void render_live_left_pane(ImDrawList* dl, view_state_t& s,
			float panel_x, float panel_y, float panel_w, float content_h, float content_y,
			float a, const std::vector<live_region_t>& regions_copy,
			const std::vector<driver_bridge::thread_info_t>& threads_copy,
			uint64_t selected_base, float full_h)
		{
			const auto& t = aida::ui::resolved();

			ImFont* hdr_font = aida::ui::fonts::body_em();
			if (!hdr_font) hdr_font = ImGui::GetFont();
			const float hdr_fs = hdr_font->FontSize > 0.f ? hdr_font->FontSize : 16.f;
			dl->AddText(hdr_font, hdr_fs, ImVec2(panel_x, panel_y),
				aida::ui::with_alpha(t.text_secondary, a), "Address Space Map");

			const float canvas_top = panel_y + 24.f;
			float canvas_h = full_h * 0.55f;
			if (canvas_h < 220.f) canvas_h = 220.f;
			if (canvas_h > full_h - 70.f) canvas_h = full_h - 70.f;
			render_address_space_canvas(dl, ImVec2(panel_x, canvas_top),
				panel_w, canvas_h, regions_copy, threads_copy, s, a, s.row_anim_time, selected_base);

			const float legend_y = canvas_top + canvas_h + 4.f;
			render_legend(dl, ImVec2(panel_x + 12.f, legend_y), panel_w - 24.f, a);

			const float stats_y = legend_y + 24.f;
			ImFont* cap = aida::ui::fonts::caption();
			if (!cap) cap = ImGui::GetFont();
			const float cap_fs = cap->FontSize > 0.f ? cap->FontSize : 13.f;
			const float strong_fs = hdr_fs * 1.05f;

			uint64_t committed = 0, reserved = 0;
			uint32_t rwx = 0;
			uint32_t pid = 0;
			std::string proc;
			size_t region_n = 0, module_n = 0, thread_n = 0;
			uint64_t enum_ms = 0;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				committed = s.live.total_committed;
				reserved  = s.live.total_reserved;
				rwx       = s.live.rwx_count;
				pid       = s.live.pid;
				proc      = s.live.process_name;
				region_n  = s.live.regions.size();
				module_n  = s.live.modules.size();
				thread_n  = s.live.threads.size();
				enum_ms   = s.live.enum_elapsed_ms;
			}

			struct stat_pod_t { const char* label; std::string value; ImU32 color; };
			char b_regions[24], b_committed[40], b_reserved[40], b_rwx[24], b_modules[24], b_threads[24];
			std::snprintf(b_regions, sizeof(b_regions), "%zu", region_n);
			std::snprintf(b_modules, sizeof(b_modules), "%zu", module_n);
			std::snprintf(b_threads, sizeof(b_threads), "%zu", thread_n);
			std::snprintf(b_rwx, sizeof(b_rwx), "%u", static_cast<unsigned>(rwx));
			std::string committed_s = format_size_human(committed);
			std::string reserved_s = format_size_human(reserved);
			std::snprintf(b_committed, sizeof(b_committed), "%s", committed_s.c_str());
			std::snprintf(b_reserved, sizeof(b_reserved), "%s", reserved_s.c_str());

			stat_pod_t pods[] = {
				{ "REGIONS",   b_regions,   t.accent_u32 },
				{ "MODULES",   b_modules,   t.info },
				{ "THREADS",   b_threads,   t.info },
				{ "COMMITTED", b_committed, t.success },
				{ "RESERVED",  b_reserved,  t.text_dim },
				{ "RWX",       b_rwx,       rwx > 0 ? t.error : t.success }
			};

			const int pod_count = static_cast<int>(sizeof(pods) / sizeof(pods[0]));
			const float pod_gap = 8.f;
			const float pod_w = (panel_w - 24.f - pod_gap * (pod_count - 1)) / static_cast<float>(pod_count);
			const float pod_h = 56.f;
			float px = panel_x + 12.f;
			for (int i = 0; i < pod_count; ++i) {
				ImVec2 pa(px, stats_y);
				ImVec2 pb(px + pod_w, stats_y + pod_h);
				dl->AddRectFilled(pa, pb,
					aida::ui::with_alpha(t.panel_bg, a * 0.85f), 8.f);
				dl->AddRectFilled(pa, pb,
					aida::ui::with_alpha(t.glass_tint, a * 0.55f), 8.f);
				dl->AddRect(pa, pb,
					aida::ui::with_alpha(t.border_subtle, a), 8.f, 0, 1.f);
				dl->AddRectFilled(pa, ImVec2(pa.x + 3.f, pa.y + pod_h),
					aida::ui::with_alpha(pods[i].color, a * 0.85f), 1.f);
				dl->AddText(cap, cap_fs * 0.95f,
					ImVec2(pa.x + 10.f, pa.y + 6.f),
					aida::ui::with_alpha(t.text_dim, a), pods[i].label);
				dl->AddText(hdr_font, strong_fs,
					ImVec2(pa.x + 10.f, pa.y + 22.f),
					aida::ui::with_alpha(t.text_primary, a), pods[i].value.c_str());
				px += pod_w + pod_gap;
			}

			const float meta_y = stats_y + pod_h + 8.f;
			char meta_buf[128];
			if (pid != 0) {
				std::snprintf(meta_buf, sizeof(meta_buf),
					"PID %u   %s   enum %llu ms",
					static_cast<unsigned>(pid),
					proc.c_str(),
					static_cast<unsigned long long>(enum_ms));
			} else {
				std::snprintf(meta_buf, sizeof(meta_buf), "No attached process");
			}
			dl->AddText(cap, cap_fs, ImVec2(panel_x + 12.f, meta_y),
				aida::ui::with_alpha(t.text_dim, a), meta_buf);
		}

	}

	inline void render(int x, int y, float w, float h,
		float anim, float anim_x, float anim_y, float anim_z)
	{
		view_state_t& s = state();
		if (!s.initialized) initialize();

		const active_mode_t resolved_mode = detail::resolve_active_mode(s.mode_pref);
		const int prev_mode = s.active_mode_atomic.exchange(static_cast<int>(resolved_mode));
		if (prev_mode != static_cast<int>(resolved_mode)) {
			diag::log_tagged_fmt("binary_map",
				"mode_switch from=%d to=%d pref=%d live_available=%d static_available=%d",
				prev_mode,
				static_cast<int>(resolved_mode),
				static_cast<int>(s.mode_pref),
				detail::live_available() ? 1 : 0,
				detail::static_available() ? 1 : 0);
		}

		const bool want_static = (resolved_mode == active_mode_t::pe_static)
			|| (resolved_mode == active_mode_t::merged);
		const bool want_live = (resolved_mode == active_mode_t::live_process)
			|| (resolved_mode == active_mode_t::merged);

		if (s.refresh_requested.exchange(false) && want_static) {
			detail::perform_refresh(s);
		}
		if (s.live_refresh_requested.exchange(false) && want_live) {
			detail::perform_live_refresh(s);
		}

		const auto& t = aida::ui::resolved();
		const float a = anim;
		const float dt = aida::ui::clock::dt();
		s.row_anim_time += dt;

		ImGui::BeginChild("##binary_map_view", ImVec2(w, h), false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

		if (!analysis_session::has_active_target() && !detail::live_available()) {
			ImVec2 wp = ImGui::GetWindowPos();
			aida::ui::no_target_overlay::render(wp, ImVec2(w, h),
				"No binary or process",
				"The Binary Map shows PE sections, functions, imports/exports for a static binary, and every mapped region for a live process. Open a file, attach to a running process, or launch a binary to begin.",
				a, aida::ui::empty_state::glyph_t::binary_file);
			ImGui::EndChild();
			return;
		}

		const float kBmMinPanelW = 720.f;
		if (w < kBmMinPanelW) {
			static bool s_logged_bm_narrow = false;
			if (!s_logged_bm_narrow) {
				s_logged_bm_narrow = true;
				::diag::log_tagged_fmt("responsive",
					"binary_map_view clamp_overlay width=%.0f min=%.0f",
					w, kBmMinPanelW);
			}
			ImVec2 wpc = ImGui::GetWindowPos();
			aida::ui::responsive::draw_clamp_overlay(
				wpc, ImVec2(w, h),
				"Widen the panel to view the Binary Map");
			ImGui::EndChild();
			return;
		}

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		const float ox = wp.x;
		const float oy = wp.y;

		dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
			aida::ui::with_alpha(t.bg_base, a));

		(void)anim_x; (void)anim_y; (void)anim_z;

		const float toolbar_h = 92.f;
		const float pad = 12.f;

		ImU32 bar_top = aida::ui::with_alpha(t.panel_header, a * 0.85f);
		ImU32 bar_bot = aida::ui::with_alpha(t.panel_bg, a * 0.85f);
		dl->AddRectFilledMultiColor(ImVec2(ox, oy), ImVec2(ox + w, oy + toolbar_h),
			bar_top, bar_top, bar_bot, bar_bot);
		dl->AddLine(ImVec2(ox, oy + toolbar_h - 1.f), ImVec2(ox + w, oy + toolbar_h - 1.f),
			aida::ui::with_alpha(t.border_subtle, a));

		int total_funcs = 0;
		int total_globs = 0;
		int total_imports = 0;
		int total_exports = 0;
		int total_sections = 0;
		std::string module_name;
		std::string module_format;
		uint64_t image_base = 0;
		uint64_t image_size = 0;
		size_t live_region_count = 0;
		uint32_t live_pid_now = 0;
		std::string live_proc_name;
		std::vector<binary_map::map_section_t> sections_copy;
		std::vector<binary_map::map_function_t> functions_copy;
		std::vector<binary_map::map_global_t> globals_copy;
		std::vector<std::string> imports_copy;
		std::vector<std::string> exports_copy;
		std::vector<live_region_t> regions_copy;
		std::vector<driver_bridge::thread_info_t> threads_copy;
		std::string last_error_copy;

		uint64_t selected_va_local = s.selected_va.load();
		uint64_t live_selected_base = s.live_selected_base.load();

		{
			std::lock_guard<std::mutex> g(s.mutex);
			total_funcs    = static_cast<int>(s.map.functions.size());
			total_globs    = static_cast<int>(s.map.globals.size());
			total_imports  = static_cast<int>(s.map.imports.size());
			total_exports  = static_cast<int>(s.map.exports.size());
			total_sections = static_cast<int>(s.map.sections.size());
			module_name    = s.map.module_name;
			module_format  = s.map.format;
			image_base     = s.map.image_base;
			image_size     = s.map.image_size;
			sections_copy  = s.map.sections;
			functions_copy = s.map.functions;
			globals_copy   = s.map.globals;
			imports_copy   = s.map.imports;
			exports_copy   = s.map.exports;
			last_error_copy = s.last_error;
			regions_copy = s.live.regions;
			threads_copy = s.live.threads;
			live_region_count = s.live.regions.size();
			live_pid_now = s.live.pid;
			live_proc_name = s.live.process_name;
		}

		ImGui::SetCursorScreenPos(ImVec2(ox + pad, oy + 6.f));
		ImFont* head = aida::ui::fonts::body_strong();
		if (!head) head = ImGui::GetFont();
		const float head_fs = head->FontSize > 0.f ? head->FontSize : 16.f;
		dl->AddText(head, head_fs, ImVec2(ox + pad, oy + 6.f),
			aida::ui::with_alpha(t.text_primary, a), "Binary Map");

		const char* mode_text =
			(resolved_mode == active_mode_t::merged)        ? "merged: static PE + live process" :
			(resolved_mode == active_mode_t::live_process)  ? "live process" :
			(resolved_mode == active_mode_t::pe_static)     ? "static PE" :
			                                                  "no target";
		std::string subtitle;
		if (resolved_mode == active_mode_t::live_process || resolved_mode == active_mode_t::merged) {
			char buf[256];
			if (live_pid_now != 0) {
				std::snprintf(buf, sizeof(buf), "%s  -  PID %u  %s  regions %zu",
					mode_text, static_cast<unsigned>(live_pid_now),
					live_proc_name.c_str(), live_region_count);
			} else {
				std::snprintf(buf, sizeof(buf), "%s  -  no active process", mode_text);
			}
			subtitle = buf;
		} else if (resolved_mode == active_mode_t::pe_static) {
			char buf[256];
			std::snprintf(buf, sizeof(buf), "%s  -  %s  %s  base 0x%llX  %s",
				mode_text,
				module_name.empty() ? "(generating)" : module_name.c_str(),
				module_format.empty() ? "" : module_format.c_str(),
				static_cast<unsigned long long>(image_base),
				detail::format_size_human(image_size).c_str());
			subtitle = buf;
		} else {
			subtitle = "no target";
		}
		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();
		const float code_fs = code_font->FontSize > 0.f ? code_font->FontSize : 14.f;
		dl->AddText(code_font, code_fs, ImVec2(ox + pad + 130.f, oy + 12.f),
			aida::ui::with_alpha(t.text_dim, a), subtitle.c_str());

		float chip_y = oy + 34.f;
		float chip_x = ox + pad;
		ImGui::SetCursorScreenPos(ImVec2(chip_x, chip_y));

		auto render_count_chip = [&](const char* lbl, const char* val, ImU32 col) {
			ImFont* f = aida::ui::fonts::body();
			if (!f) f = ImGui::GetFont();
			float fs = f->FontSize > 0.f ? f->FontSize : 16.f;
			float lblw = f->CalcTextSizeA(fs, FLT_MAX, 0.f, lbl).x;
			float valw = f->CalcTextSizeA(fs, FLT_MAX, 0.f, val).x;
			float pad_x = 10.f;
			float w_chip = lblw + valw + pad_x * 2.f + 8.f;
			float h_chip = 24.f;
			ImVec2 cp = ImGui::GetCursorScreenPos();
			ImVec2 ca = cp;
			ImVec2 cb = ImVec2(cp.x + w_chip, cp.y + h_chip);
			dl->AddRectFilled(ca, cb, aida::ui::with_alpha(col, a * 0.18f), h_chip * 0.5f);
			dl->AddRect(ca, cb, aida::ui::with_alpha(col, a * 0.55f), h_chip * 0.5f, 0, 1.f);
			dl->AddText(f, fs, ImVec2(ca.x + pad_x, ca.y + (h_chip - fs) * 0.5f),
				aida::ui::with_alpha(t.text_secondary, a), lbl);
			dl->AddText(f, fs, ImVec2(ca.x + pad_x + lblw + 8.f, ca.y + (h_chip - fs) * 0.5f),
				aida::ui::with_alpha(col, a), val);
			ImGui::Dummy(ImVec2(w_chip, h_chip));
			ImGui::SameLine(0.f, 8.f);
		};

		char buf_funcs[24], buf_globs[24], buf_imp[24], buf_exp[24], buf_sec[24], buf_regions[24];
		std::snprintf(buf_funcs,   sizeof(buf_funcs),   "%d", total_funcs);
		std::snprintf(buf_globs,   sizeof(buf_globs),   "%d", total_globs);
		std::snprintf(buf_imp,     sizeof(buf_imp),     "%d", total_imports);
		std::snprintf(buf_exp,     sizeof(buf_exp),     "%d", total_exports);
		std::snprintf(buf_sec,     sizeof(buf_sec),     "%d", total_sections);
		std::snprintf(buf_regions, sizeof(buf_regions), "%zu", live_region_count);

		if (want_static) {
			render_count_chip("Sections", buf_sec,   t.info);
			render_count_chip("Functions", buf_funcs, t.accent_u32);
			render_count_chip("Globals",   buf_globs, t.success);
			render_count_chip("Imports",   buf_imp,   t.warning);
			render_count_chip("Exports",   buf_exp,   t.accent_hover);
		}
		if (want_live) {
			render_count_chip("Regions", buf_regions, t.accent_dim);
		}

		float seg_x = ox + pad;
		float seg_y = oy + 60.f;
		float seg_h = 26.f;
		float seg_label_w = 70.f;
		ImFont* cap_font = aida::ui::fonts::caption();
		if (!cap_font) cap_font = ImGui::GetFont();
		const float cap_fs = cap_font->FontSize > 0.f ? cap_font->FontSize : 13.f;
		dl->AddText(cap_font, cap_fs, ImVec2(seg_x, seg_y + (seg_h - cap_fs) * 0.5f),
			aida::ui::with_alpha(t.text_dim, a), "Mode:");

		struct mode_btn_t { const char* label; display_mode_t value; };
		const mode_btn_t modes_arr[] = {
			{ "Auto",    display_mode_t::auto_detect },
			{ "Static",  display_mode_t::static_only },
			{ "Live",    display_mode_t::live_only }
		};
		const int mode_count = static_cast<int>(sizeof(modes_arr) / sizeof(modes_arr[0]));
		float mode_btn_w = 78.f;
		float mode_btn_x = seg_x + seg_label_w;
		for (int i = 0; i < mode_count; ++i) {
			ImVec2 ma(mode_btn_x, seg_y);
			ImVec2 mb(mode_btn_x + mode_btn_w, seg_y + seg_h);
			const bool sel = (s.mode_pref == modes_arr[i].value);
			ImU32 fill = sel
				? aida::ui::with_alpha(t.accent_u32, a * 0.35f)
				: aida::ui::with_alpha(t.panel_bg, a * 0.65f);
			ImU32 border = sel
				? aida::ui::with_alpha(t.accent_u32, a)
				: aida::ui::with_alpha(t.border_subtle, a);
			dl->AddRectFilled(ma, mb, fill, 5.f);
			dl->AddRect(ma, mb, border, 5.f, 0, sel ? 1.4f : 1.f);
			ImFont* btn_font = aida::ui::fonts::body();
			if (!btn_font) btn_font = ImGui::GetFont();
			const float btn_fs = btn_font->FontSize > 0.f ? btn_font->FontSize : 16.f;
			ImVec2 ts = btn_font->CalcTextSizeA(btn_fs, FLT_MAX, 0.f, modes_arr[i].label);
			ImU32 txt_col = sel
				? aida::ui::with_alpha(t.text_primary, a)
				: aida::ui::with_alpha(t.text_secondary, a);
			dl->AddText(btn_font, btn_fs,
				ImVec2(ma.x + (mode_btn_w - ts.x) * 0.5f, ma.y + (seg_h - btn_fs) * 0.5f),
				txt_col, modes_arr[i].label);

			ImGui::SetCursorScreenPos(ma);
			ImGui::PushID(static_cast<int>(0x90000000 | i));
			ImGui::InvisibleButton("##bm_mode_btn", ImVec2(mode_btn_w, seg_h));
			if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
				const display_mode_t prev = s.mode_pref;
				s.mode_pref = modes_arr[i].value;
				diag::log_tagged_fmt("binary_map",
					"mode_toggle prev=%d new=%d",
					static_cast<int>(prev), static_cast<int>(s.mode_pref));
				s.refresh_requested.store(true);
				s.live_refresh_requested.store(true);
			}
			ImGui::PopID();
			mode_btn_x += mode_btn_w + 4.f;
		}

		const float right_anchor = ox + w - pad;
		const float btn_y = oy + 60.f;
		const float btn_w = 102.f;
		const float btn_h = 30.f;
		const float btn_gap = 8.f;
		float bx = right_anchor;

		bx -= btn_w;
		ImGui::SetCursorScreenPos(ImVec2(bx, btn_y));
		bool refreshing_now = s.refreshing.load() || s.live_refreshing.load();
		if (aida::ui::button(refreshing_now ? "Refreshing" : "Refresh",
			aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm,
			ImVec2(btn_w, btn_h),
			refreshing_now, nullptr, refreshing_now)) {
			if (!refreshing_now) {
				diag::log_tagged_fmt("binary_map",
					"toolbar refresh_clicked want_static=%d want_live=%d mode_pref=%d",
					want_static ? 1 : 0, want_live ? 1 : 0,
					static_cast<int>(s.mode_pref));
				if (want_static) s.refresh_requested.store(true);
				if (want_live)   s.live_refresh_requested.store(true);
			}
		}

		bx -= (btn_w + btn_gap);
		ImGui::SetCursorScreenPos(ImVec2(bx, btn_y));
		if (aida::ui::button("To chat", aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::sm, ImVec2(btn_w, btn_h))) {
			std::string payload;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				if (s.rendered_text.empty()) detail::rebuild_text_locked(s);
				payload = s.rendered_text;
			}
			if (resolved_mode == active_mode_t::live_process) {
				std::string live_payload = "Live memory map:\n";
				uint64_t committed_total = 0;
				uint32_t rwx_total = 0;
				for (const auto& r : regions_copy) {
					if (r.is_committed) committed_total += r.size;
					const bool exec_b  = (r.protect & 0xF0) != 0;
					const uint32_t low_b = r.protect & 0xFF;
					const bool write_b = (low_b == 0x04) || (low_b == 0x08) || (low_b == 0x40) || (low_b == 0x80);
					if (exec_b && write_b) ++rwx_total;
				}
				const std::string committed_str = detail::format_size_human(committed_total);
				char hbuf[200];
				std::snprintf(hbuf, sizeof(hbuf),
					"PID %u %s  regions=%zu  committed=%s  RWX=%u\n",
					static_cast<unsigned>(live_pid_now),
					live_proc_name.c_str(),
					regions_copy.size(),
					committed_str.c_str(),
					static_cast<unsigned>(rwx_total));
				live_payload += hbuf;
				for (size_t i = 0; i < regions_copy.size() && i < 64; ++i) {
					live_payload += detail::make_region_chat_payload(regions_copy[i]);
				}
				payload = live_payload;
			}
			diag::log_tagged_fmt("binary_map",
				"toolbar to_chat bytes=%zu module='%s'",
				payload.size(), module_name.c_str());
			if (payload.empty()) {
				toast_notification::push("Binary map is empty; refresh first",
					toast_notification::toast_type_t::warning, 3.0f);
			} else {
				detail::inject_to_chat(payload);
			}
		}

		bx -= (btn_w + btn_gap);
		ImGui::SetCursorScreenPos(ImVec2(bx, btn_y));
		ImGui::PushID("bm_toolbar_copy");
		if (aida::ui::button("Copy", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::sm, ImVec2(btn_w, btn_h))) {
			std::string payload;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				if (s.rendered_text.empty()) detail::rebuild_text_locked(s);
				payload = s.rendered_text;
			}
			diag::log_tagged_fmt("binary_map",
				"toolbar copy bytes=%zu module='%s'",
				payload.size(), module_name.c_str());
			ImGui::SetClipboardText(payload.c_str());
			toast_notification::push("Binary map copied to clipboard",
				toast_notification::toast_type_t::info, 3.0f);
		}
		ImGui::PopID();

		bx -= (btn_w + btn_gap);
		ImGui::SetCursorScreenPos(ImVec2(bx, btn_y));
		ImGui::PushID("bm_export_live");
		if (aida::ui::button("Export", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::sm, ImVec2(btn_w, btn_h))) {
			if (resolved_mode == active_mode_t::live_process || resolved_mode == active_mode_t::merged) {
				live_snapshot_t snap_copy;
				{
					std::lock_guard<std::mutex> g(s.mutex);
					snap_copy = s.live;
				}
				const std::string js = detail::export_live_snapshot_json(snap_copy);
				char path_buf[MAX_PATH] = {};
				std::snprintf(path_buf, sizeof(path_buf), "memory_map_pid%u.json",
					static_cast<unsigned>(snap_copy.pid));
				static const char k_filter[] =
					"JSON (*.json)\0*.json\0All files (*.*)\0*.*\0\0";
				if (win32_dialog::show_save_file_dialog(g_hwnd,
					"Export Memory Map",
					k_filter,
					"json",
					path_buf, sizeof(path_buf),
					"binary_map_view::export_live"))
				{
					std::ofstream ofs(path_buf, std::ios::binary | std::ios::trunc);
					if (ofs.is_open()) {
						ofs.write(js.data(), static_cast<std::streamsize>(js.size()));
						ofs.close();
						diag::log_tagged_fmt("binary_map",
							"export_live DONE bytes=%zu path='%s'", js.size(), path_buf);
						toast_notification::push("Memory map exported",
							toast_notification::toast_type_t::info, 3.0f);
					} else {
						diag::log_tagged_fmt("binary_map",
							"export_live FAILED_open path='%s'", path_buf);
						toast_notification::push("Failed to write export file",
							toast_notification::toast_type_t::error, 3.0f);
					}
				}
			} else {
				std::string payload;
				{
					std::lock_guard<std::mutex> g(s.mutex);
					if (s.rendered_text.empty()) detail::rebuild_text_locked(s);
					payload = s.rendered_text;
				}
				char path_buf[MAX_PATH] = "binary_map.txt";
				static const char k_filter[] =
					"Text (*.txt)\0*.txt\0All files (*.*)\0*.*\0\0";
				if (win32_dialog::show_save_file_dialog(g_hwnd,
					"Export Binary Map",
					k_filter,
					"txt",
					path_buf, sizeof(path_buf),
					"binary_map_view::export_pe"))
				{
					std::ofstream ofs(path_buf, std::ios::binary | std::ios::trunc);
					if (ofs.is_open()) {
						ofs.write(payload.data(), static_cast<std::streamsize>(payload.size()));
						ofs.close();
						diag::log_tagged_fmt("binary_map",
							"export_pe DONE bytes=%zu path='%s'", payload.size(), path_buf);
						toast_notification::push("Binary map exported",
							toast_notification::toast_type_t::info, 3.0f);
					} else {
						diag::log_tagged_fmt("binary_map",
							"export_pe FAILED_open path='%s'", path_buf);
						toast_notification::push("Failed to write export file",
							toast_notification::toast_type_t::error, 3.0f);
					}
				}
			}
		}
		ImGui::PopID();

		const float content_y = oy + toolbar_h;
		const float content_h = h - toolbar_h;

		float left_w = std::max(360.f, w * s.left_split);
		float min_left = std::max(360.f, w * 0.35f);
		if (left_w < min_left) left_w = min_left;
		if (left_w > w - 320.f) left_w = w - 320.f;
		const float right_w = w - left_w - 1.f;
		const float split_x = ox + left_w;

		float splitter_target = 0.f;
		ImGui::SetCursorScreenPos(ImVec2(split_x - 4.f, content_y));
		ImGui::InvisibleButton("##bm_splitter", ImVec2(8.f, content_h));
		bool splitter_hov = ImGui::IsItemHovered();
		bool splitter_active = ImGui::IsItemActive();
		bool splitter_released = ImGui::IsItemDeactivated();
		if (splitter_hov) {
			ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
			splitter_target = 1.f;
		}
		if (splitter_active && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
			float dx = ImGui::GetIO().MouseDelta.x;
			float new_left = left_w + dx;
			if (new_left >= min_left && new_left <= w - 320.f)
				s.left_split = new_left / std::max(1.f, w);
			splitter_target = 1.f;
		}
		if (splitter_released) {
			diag::log_tagged_fmt("binary_map",
				"splitter_release left_split=%.3f left_w=%.1f total_w=%.1f",
				s.left_split, left_w, w);
		}
		s.splitter_hover_v = aida::motion::smooth_lerp(s.splitter_hover_v, splitter_target, 16.f, dt);

		ImU32 sep_base = aida::ui::with_alpha(t.border_strong, a * 0.85f);
		ImU32 sep_hov  = aida::ui::with_alpha(t.accent_u32, a * 0.95f);
		ImU32 sep_col  = aida::ui::mix(sep_base, sep_hov, s.splitter_hover_v);
		dl->AddLine(ImVec2(split_x, content_y + 2.f), ImVec2(split_x, content_y + content_h - 2.f),
			sep_col, 1.2f + s.splitter_hover_v * 1.4f);

		const float left_pad = 12.f;
		float panel_x = ox + left_pad;
		float panel_w = left_w - left_pad * 2.f;
		float panel_y = content_y + 8.f;
		float left_full_h = content_h - 16.f;

		if (resolved_mode == active_mode_t::pe_static) {
			detail::render_pe_left_pane(dl, s, panel_x, panel_y, panel_w, content_h, content_y, a,
				sections_copy, functions_copy, image_size, selected_va_local, left_full_h);
		} else if (resolved_mode == active_mode_t::live_process) {
			detail::render_live_left_pane(dl, s, panel_x, panel_y, panel_w, content_h, content_y, a,
				regions_copy, threads_copy, live_selected_base, left_full_h);
		} else if (resolved_mode == active_mode_t::merged) {
			float half = (left_full_h - 12.f) * 0.55f;
			detail::render_live_left_pane(dl, s, panel_x, panel_y, panel_w, content_h, content_y, a,
				regions_copy, threads_copy, live_selected_base, half);
			float pe_y = panel_y + half + 12.f;
			detail::render_pe_left_pane(dl, s, panel_x, pe_y, panel_w, content_h, content_y, a,
				sections_copy, functions_copy, image_size, selected_va_local,
				left_full_h - half - 12.f);
		} else {
			ImFont* body = aida::ui::fonts::body();
			if (!body) body = ImGui::GetFont();
			const float body_fs = body->FontSize > 0.f ? body->FontSize : 16.f;
			dl->AddText(body, body_fs,
				ImVec2(panel_x + panel_w * 0.5f - 80.f, panel_y + content_h * 0.4f),
				aida::ui::with_alpha(t.text_dim, a),
				"No target. Use the toolbar to refresh.");
		}

		const float right_x = ox + left_w + 1.f;
		const float right_pad = 12.f;
		ImVec2 r_a = ImVec2(right_x + right_pad, content_y + 8.f);
		ImVec2 r_b = ImVec2(right_x + right_w - right_pad, content_y + content_h - 12.f);

		aida::ui::blur::layer_request_t req;
		req.pos = r_a;
		req.size = ImVec2(r_b.x - r_a.x, r_b.y - r_a.y);
		req.radius = 12.f;
		req.strength = 0.55f;
		req.alpha = a;
		aida::ui::blur::schedule(req);
		aida::ui::blur::render_glass_fill(dl, r_a, r_b, 12.f, a);
		aida::ui::blur::render_glass_border(dl, r_a, r_b, 12.f, a, 1.f);

		float panel_inner_top = r_a.y + 10.f;
		float panel_inner_left = r_a.x + 12.f;
		float panel_inner_w = r_b.x - r_a.x - 24.f;

		ImFont* head_em = aida::ui::fonts::body_em();
		if (!head_em) head_em = ImGui::GetFont();
		const float head_em_fs = head_em->FontSize > 0.f ? head_em->FontSize : 16.f;

		const char* right_header = (resolved_mode == active_mode_t::live_process)
			? "Live Regions"
			: ((resolved_mode == active_mode_t::merged) ? "Layout & Live Regions" : "Layout & Symbols");
		dl->AddText(head_em, head_em_fs, ImVec2(panel_inner_left, panel_inner_top),
			aida::ui::with_alpha(t.text_secondary, a), right_header);

		ImGui::SetCursorScreenPos(ImVec2(r_b.x - 100.f, panel_inner_top - 6.f));
		ImGui::PushID("bm_preview_copy");
		if (aida::ui::button("Copy", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::md, ImVec2(96.f, 30.f))) {
			std::string payload;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				if (s.rendered_text.empty()) detail::rebuild_text_locked(s);
				payload = s.rendered_text;
			}
			diag::log_tagged_fmt("binary_map",
				"preview copy bytes=%zu module='%s'",
				payload.size(), module_name.c_str());
			ImGui::SetClipboardText(payload.c_str());
			toast_notification::push("Preview copied to clipboard",
				toast_notification::toast_type_t::info, 3.0f);
		}
		ImGui::PopID();

		float filter_y = panel_inner_top + head_em_fs + 14.f;
		ImGui::SetCursorScreenPos(ImVec2(panel_inner_left, filter_y));
		if (aida::ui::input_text("##bm_filter", s.filter_buf, sizeof(s.filter_buf),
			"Filter sections, regions, modules, imports...", false,
			ImVec2(panel_inner_w, 32.f))) {
		}
		s.filter_lower = detail::to_lower_copy(std::string(s.filter_buf));

		float section_y = filter_y + 42.f;
		float section_inner_h = (r_b.y - section_y) - 12.f;
		ImGui::SetCursorScreenPos(ImVec2(panel_inner_left, section_y));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0,0,0,0));
		ImGui::PushFont(code_font);

		ImGui::BeginChild("##bm_preview_pane", ImVec2(panel_inner_w, section_inner_h), false,
			ImGuiWindowFlags_NoBackground);

		const std::string& filter_lower = s.filter_lower;
		bool refresh_after_pin = false;
		bool open_change_protect_popup_local = false;

		auto draw_section_header = [&](const char* title, int count_value,
		                                const std::string& key) -> bool {
			char hbuf[160];
			std::snprintf(hbuf, sizeof(hbuf), "%s  (%d)", title, count_value);
			const bool collapsed = detail::group_is_collapsed(s, key);
			ImVec2 cp = ImGui::GetCursorScreenPos();
			float row_w = ImGui::GetContentRegionAvail().x;
			float row_h = 30.f;
			bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
			ImU32 fill = hov
				? aida::ui::with_alpha(t.hover_wash, a)
				: aida::ui::with_alpha(t.panel_header, a * 0.55f);
			dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h), fill, 6.f);
			ImU32 arrow_col = aida::ui::with_alpha(t.accent_u32, a);
			float arrow_x = cp.x + 12.f;
			float arrow_y = cp.y + row_h * 0.5f;
			ImVec2 a1, a2, a3;
			if (collapsed) {
				a1 = ImVec2(arrow_x, arrow_y - 5.f);
				a2 = ImVec2(arrow_x + 7.f, arrow_y);
				a3 = ImVec2(arrow_x, arrow_y + 5.f);
			} else {
				a1 = ImVec2(arrow_x - 1.f, arrow_y - 2.f);
				a2 = ImVec2(arrow_x + 8.f, arrow_y - 2.f);
				a3 = ImVec2(arrow_x + 3.f, arrow_y + 5.f);
			}
			dl->AddTriangleFilled(a1, a2, a3, arrow_col);

			ImFont* f_strong = aida::ui::fonts::body_em();
			if (!f_strong) f_strong = ImGui::GetFont();
			const float gh_fs = f_strong->FontSize > 0.f ? f_strong->FontSize : 16.f;
			dl->AddText(f_strong, gh_fs, ImVec2(cp.x + 30.f, cp.y + (row_h - gh_fs) * 0.5f),
				aida::ui::with_alpha(t.text_primary, a), hbuf);
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				detail::toggle_group(s, key);
				diag::log_tagged_fmt("binary_map",
					"group_toggle key='%s' now_collapsed=%d",
					key.c_str(), (!collapsed) ? 1 : 0);
			}
			ImGui::Dummy(ImVec2(row_w, row_h + 6.f));
			return !collapsed;
		};

		auto render_region_row = [&](const live_region_t& r, int idx) {
			ImVec2 cp = ImGui::GetCursorScreenPos();
			float row_w = ImGui::GetContentRegionAvail().x;
			float row_h = 32.f;
			bool sel = (live_selected_base == r.base && r.base != 0);
			ImGui::PushID(static_cast<int>(0x80000000u | static_cast<unsigned>(idx)));
			ImGui::InvisibleButton("##bm_reg_row", ImVec2(row_w, row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);
			bool double_clicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)
				&& ImGui::IsItemHovered();
			if (sel) {
				dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
					aida::ui::with_alpha(t.selection, a), 5.f);
				dl->AddRectFilled(cp, ImVec2(cp.x + 3.f, cp.y + row_h),
					aida::ui::with_alpha(t.accent_u32, a), 1.f);
			} else if (hov) {
				dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
					aida::ui::with_alpha(t.hover_wash, a), 4.f);
			}
			ImU32 dot_col = detail::region_color(r, a);
			dl->AddRectFilled(ImVec2(cp.x + 8.f, cp.y + 7.f),
				ImVec2(cp.x + 16.f, cp.y + row_h - 7.f),
				dot_col, 2.f);

			char addr_buf[24];
			std::snprintf(addr_buf, sizeof(addr_buf), "0x%012llX",
				static_cast<unsigned long long>(r.base));
			ImFont* code_f = aida::ui::fonts::code();
			if (!code_f) code_f = ImGui::GetFont();
			const float code_row_fs = code_f->FontSize > 0.f ? code_f->FontSize : 14.f;
			ImFont* body_f = aida::ui::fonts::body();
			if (!body_f) body_f = ImGui::GetFont();
			const float body_row_fs = body_f->FontSize > 0.f ? body_f->FontSize : 16.f;

			const float addr_y = cp.y + (row_h - code_row_fs) * 0.5f;
			dl->AddText(code_f, code_row_fs,
				ImVec2(cp.x + 24.f, addr_y),
				aida::ui::with_alpha(t.text_address, a), addr_buf);

			std::string sz_s = detail::format_size_human(r.size);
			dl->AddText(code_f, code_row_fs,
				ImVec2(cp.x + 24.f + 140.f, addr_y),
				aida::ui::with_alpha(t.text_secondary, a), sz_s.c_str());

			std::string lbl = detail::region_kind_label(r);
			ImU32 lbl_col = detail::region_color(r, a);
			ImFont* cap_f = aida::ui::fonts::caption();
			if (!cap_f) cap_f = ImGui::GetFont();
			const float cap_row_fs = cap_f->FontSize > 0.f ? cap_f->FontSize : 13.f;
			ImVec2 lbl_sz = cap_f->CalcTextSizeA(cap_row_fs, FLT_MAX, 0.f, lbl.c_str());
			const float chip_h = cap_row_fs + 6.f;
			const float chip_y = cp.y + (row_h - chip_h) * 0.5f;
			const float chip_x_start = cp.x + 24.f + 220.f;
			dl->AddRectFilled(ImVec2(chip_x_start, chip_y),
				ImVec2(chip_x_start + lbl_sz.x + 14.f, chip_y + chip_h),
				aida::ui::with_alpha(lbl_col, a * 0.22f), chip_h * 0.5f);
			dl->AddText(cap_f, cap_row_fs,
				ImVec2(chip_x_start + 7.f, chip_y + (chip_h - cap_row_fs) * 0.5f),
				aida::ui::with_alpha(lbl_col, a), lbl.c_str());

			std::string perm_s = detail::format_protect_word(r.protect);
			ImVec2 perm_sz = cap_f->CalcTextSizeA(cap_row_fs, FLT_MAX, 0.f, perm_s.c_str());
			dl->AddText(cap_f, cap_row_fs,
				ImVec2(cp.x + row_w - perm_sz.x - 88.f, chip_y + (chip_h - cap_row_fs) * 0.5f),
				aida::ui::with_alpha(t.text_dim, a), perm_s.c_str());

			if (!r.module_name.empty()) {
				std::string mn = r.module_name;
				if (mn.size() > 24) mn = mn.substr(0, 21) + "...";
				dl->AddText(body_f, body_row_fs,
					ImVec2(cp.x + row_w - 200.f, cp.y + (row_h - body_row_fs) * 0.5f),
					aida::ui::with_alpha(t.text_secondary, a), mn.c_str());
			}

			if (clicked) {
				s.live_selected_base.store(r.base);
				diag::log_tagged_fmt("binary_map",
					"region_row_click base=0x%llX size=%llu kind=%s protect=0x%X",
					static_cast<unsigned long long>(r.base),
					static_cast<unsigned long long>(r.size),
					lbl.c_str(),
					static_cast<unsigned>(r.protect));
			}
			if (double_clicked) {
				diag::log_tagged_fmt("binary_map",
					"region_row_double_click base=0x%llX",
					static_cast<unsigned long long>(r.base));
				detail::jump_to_address(r.base);
			}
			if (right_clicked) {
				s.live_selected_base.store(r.base);
				s.ctx_va = r.base;
				diag::log_tagged_fmt("binary_map",
					"region_row_right_click base=0x%llX",
					static_cast<unsigned long long>(r.base));
				ImGui::OpenPopup("##bm_reg_ctx");
			}
			if (ImGui::BeginPopup("##bm_reg_ctx")) {
				if (ImGui::MenuItem("Jump to disassembly")) {
					const uint64_t va_local = r.base;
					ImGui::CloseCurrentPopup();
					detail::jump_to_address(va_local);
				}
				if (ImGui::MenuItem("Open in hex view")) {
					const uint64_t va_local = r.base;
					const uint64_t sz_local = r.size;
					ImGui::CloseCurrentPopup();
					detail::jump_to_hex(va_local,
						sz_local > 0x100000ULL ? 0x100000u : static_cast<size_t>(sz_local));
				}
				if (ImGui::MenuItem("Dump region")) {
					const uint64_t va_local = r.base;
					const uint64_t sz_local = r.size;
					const std::string klabel = detail::region_kind_label(r);
					ImGui::CloseCurrentPopup();
					detail::dump_region_to_disk(va_local, sz_local, klabel);
				}
				if (ImGui::MenuItem("Change protection")) {
					s.change_protect_addr = r.base;
					s.change_protect_size = r.size;
					s.change_protect_old = r.protect;
					s.change_protect_choice = 0;
					s.change_protect_open = true;
					open_change_protect_popup_local = true;
					ImGui::CloseCurrentPopup();
				}
				if (ImGui::MenuItem("Copy VA")) {
					char vbuf[32];
					std::snprintf(vbuf, sizeof(vbuf), "0x%llX",
						static_cast<unsigned long long>(r.base));
					ImGui::SetClipboardText(vbuf);
					toast_notification::push("Region VA copied",
						toast_notification::toast_type_t::info, 2.0f);
				}
				if (ImGui::MenuItem("Copy as JSON")) {
					std::string js = detail::region_to_json(r);
					ImGui::SetClipboardText(js.c_str());
					diag::log_tagged_fmt("binary_map",
						"region_ctx copy_json base=0x%llX bytes=%zu",
						static_cast<unsigned long long>(r.base), js.size());
					toast_notification::push("Region JSON copied",
						toast_notification::toast_type_t::info, 2.0f);
				}
				if (ImGui::MenuItem("Copy summary to chat")) {
					std::string p = detail::make_region_chat_payload(r);
					detail::inject_to_chat(p);
				}
				ImGui::EndPopup();
			}
			ImGui::PopID();
		};

		if (resolved_mode == active_mode_t::live_process || resolved_mode == active_mode_t::merged) {
			std::vector<int> filtered;
			filtered.reserve(regions_copy.size());
			for (size_t i = 0; i < regions_copy.size(); ++i) {
				const auto& r = regions_copy[i];
				if (filter_lower.empty()
					|| detail::filter_matches(filter_lower, r.module_name)
					|| detail::filter_matches(filter_lower, detail::region_kind_label(r))
					|| detail::filter_matches(filter_lower, r.info)
					|| detail::filter_matches(filter_lower, detail::format_protect_word(r.protect)))
				{
					filtered.push_back(static_cast<int>(i));
				}
			}
			int header_count = static_cast<int>(filtered.size());
			if (draw_section_header("Regions", header_count, "regions")) {
				for (int idx : filtered) {
					render_region_row(regions_copy[static_cast<size_t>(idx)], idx);
				}
			}
			std::vector<driver_bridge::module_info_t> mods_copy;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				mods_copy = s.live.modules;
			}
			if (draw_section_header("Modules", static_cast<int>(mods_copy.size()), "modules"))
			{
				int mi = 0;
				for (const auto& m : mods_copy) {
					if (!detail::filter_matches(filter_lower, m.name)) { ++mi; continue; }
					ImVec2 cp = ImGui::GetCursorScreenPos();
					float row_w = ImGui::GetContentRegionAvail().x;
					float row_h = 28.f;
					bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
					if (hov) {
						dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
							aida::ui::with_alpha(t.hover_wash, a), 4.f);
					}
					char addr_buf[24];
					std::snprintf(addr_buf, sizeof(addr_buf), "0x%012llX",
						static_cast<unsigned long long>(m.base));
					ImFont* code_f = aida::ui::fonts::code();
					if (!code_f) code_f = ImGui::GetFont();
					const float crfs = code_f->FontSize > 0.f ? code_f->FontSize : 14.f;
					ImFont* body_f = aida::ui::fonts::body();
					if (!body_f) body_f = ImGui::GetFont();
					const float brfs = body_f->FontSize > 0.f ? body_f->FontSize : 16.f;
					dl->AddText(code_f, crfs, ImVec2(cp.x + 12.f, cp.y + (row_h - crfs) * 0.5f),
						aida::ui::with_alpha(t.text_address, a), addr_buf);
					dl->AddText(body_f, brfs, ImVec2(cp.x + 12.f + 140.f, cp.y + (row_h - brfs) * 0.5f),
						aida::ui::with_alpha(t.text_primary, a), m.name.c_str());
					char sz_buf[24];
					std::snprintf(sz_buf, sizeof(sz_buf), "%s",
						detail::format_size_human(m.size).c_str());
					ImVec2 ssz = code_f->CalcTextSizeA(crfs, FLT_MAX, 0.f, sz_buf);
					dl->AddText(code_f, crfs,
						ImVec2(cp.x + row_w - ssz.x - 12.f, cp.y + (row_h - crfs) * 0.5f),
						aida::ui::with_alpha(t.text_dim, a), sz_buf);
					ImGui::SetCursorScreenPos(cp);
					ImGui::PushID(static_cast<int>(0x91000000u | static_cast<unsigned>(mi)));
					ImGui::InvisibleButton("##bm_mod_row", ImVec2(row_w, row_h));
					if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
						diag::log_tagged_fmt("binary_map",
							"module_row_click name='%s' base=0x%llX size=%u",
							m.name.c_str(),
							static_cast<unsigned long long>(m.base),
							static_cast<unsigned>(m.size));
						s.live_selected_base.store(m.base);
					}
					if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && ImGui::IsItemHovered()) {
						detail::jump_to_address(m.base);
					}
					if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
						ImGui::OpenPopup("##bm_mod_ctx");
					}
					if (ImGui::BeginPopup("##bm_mod_ctx")) {
						if (ImGui::MenuItem("Jump to disassembly")) {
							const uint64_t v = m.base;
							ImGui::CloseCurrentPopup();
							detail::jump_to_address(v);
						}
						if (ImGui::MenuItem("Open in hex view")) {
							const uint64_t v = m.base;
							ImGui::CloseCurrentPopup();
							detail::jump_to_hex(v, 0x400);
						}
						if (ImGui::MenuItem("Copy module name")) {
							ImGui::SetClipboardText(m.name.c_str());
							toast_notification::push("Module name copied",
								toast_notification::toast_type_t::info, 2.0f);
						}
						if (ImGui::MenuItem("Copy module path")) {
							ImGui::SetClipboardText(m.path.c_str());
							toast_notification::push("Module path copied",
								toast_notification::toast_type_t::info, 2.0f);
						}
						ImGui::EndPopup();
					}
					ImGui::PopID();
					ImGui::Dummy(ImVec2(row_w, row_h));
					++mi;
				}
			}
		}

		if (resolved_mode == active_mode_t::pe_static || resolved_mode == active_mode_t::merged) {
			if (draw_section_header("Sections", static_cast<int>(sections_copy.size()), "sections")) {
				int idx = 0;
				const float sec_row_fs = code_font->FontSize > 0.f ? code_font->FontSize : 14.f;
				ImFont* sec_name_font = aida::ui::fonts::body();
				if (!sec_name_font) sec_name_font = code_font;
				const float sec_name_fs = sec_name_font->FontSize > 0.f ? sec_name_font->FontSize : 16.f;
				ImFont* sec_perm_font = aida::ui::fonts::caption();
				if (!sec_perm_font) sec_perm_font = code_font;
				const float sec_perm_fs = sec_perm_font->FontSize > 0.f ? sec_perm_font->FontSize : 13.f;
				for (const auto& sec : sections_copy) {
					if (!detail::filter_matches(filter_lower, sec.name)) continue;
					ImVec2 cp = ImGui::GetCursorScreenPos();
					float row_w = ImGui::GetContentRegionAvail().x;
					float row_h = 28.f;
					ImGui::PushID(static_cast<int>(0x30000000 | idx));
					ImGui::InvisibleButton("##bm_sec_row", ImVec2(row_w, row_h));
					bool hov = ImGui::IsItemHovered();
					bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
					bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);
					bool double_clicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)
						&& ImGui::IsItemHovered();
					if (hov) {
						dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
							aida::ui::with_alpha(t.hover_wash, a), 4.f);
					}
					char addr_buf[24];
					std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
						static_cast<unsigned long long>(sec.va));
					ImU32 sc = detail::section_color(sec, a * 0.85f);
					dl->AddRectFilled(ImVec2(cp.x + 8.f, cp.y + 8.f), ImVec2(cp.x + 16.f, cp.y + row_h - 8.f),
						sc, 2.f);
					const float name_y = cp.y + (row_h - sec_name_fs) * 0.5f;
					const float code_y = cp.y + (row_h - sec_row_fs) * 0.5f;
					const float perm_y = cp.y + (row_h - sec_perm_fs) * 0.5f;
					dl->AddText(sec_name_font, sec_name_fs, ImVec2(cp.x + 24.f, name_y),
						aida::ui::with_alpha(t.text_primary, a), sec.name.c_str());
					dl->AddText(code_font, sec_row_fs, ImVec2(cp.x + 130.f, code_y),
						aida::ui::with_alpha(t.text_address, a), addr_buf);
					std::string sz = detail::format_size_human(sec.size);
					dl->AddText(code_font, sec_row_fs, ImVec2(cp.x + 250.f, code_y),
						aida::ui::with_alpha(t.text_secondary, a), sz.c_str());

					const float ent01 = detail::section_entropy_normalized(sec);
					const float ent_track_x = cp.x + 340.f;
					const float ent_track_w = 84.f;
					const float ent_y = cp.y + (row_h - 6.f) * 0.5f;
					dl->AddRectFilled(ImVec2(ent_track_x, ent_y),
						ImVec2(ent_track_x + ent_track_w, ent_y + 6.f),
						aida::ui::with_alpha(t.border_subtle, a * 0.6f), 1.5f);
					if (sec.sampled_bytes > 0 && ent_track_w > 4.f) {
						float fill_w = ent_track_w * ent01;
						if (fill_w < 0.f) fill_w = 0.f;
						if (fill_w > ent_track_w) fill_w = ent_track_w;
						ImU32 ec = aida::ui::mix(t.success, t.error, ent01);
						dl->AddRectFilled(ImVec2(ent_track_x, ent_y),
							ImVec2(ent_track_x + fill_w, ent_y + 6.f),
							aida::ui::with_alpha(ec, a * 0.9f), 1.5f);
						char ebuf[16];
						std::snprintf(ebuf, sizeof(ebuf), "%.2f",
							static_cast<double>(ent01) * 8.0);
						dl->AddText(sec_perm_font, sec_perm_fs,
							ImVec2(ent_track_x + ent_track_w + 6.f, perm_y),
							aida::ui::with_alpha(t.text_secondary, a), ebuf);
					} else {
						dl->AddText(sec_perm_font, sec_perm_fs,
							ImVec2(ent_track_x + ent_track_w + 6.f, perm_y),
							aida::ui::with_alpha(t.text_dim, a), "--");
					}

					std::string p = detail::section_perm_string(sec);
					ImVec2 perm_sz = sec_perm_font->CalcTextSizeA(sec_perm_fs, FLT_MAX, 0.f, p.c_str());
					dl->AddText(sec_perm_font, sec_perm_fs,
						ImVec2(cp.x + row_w - perm_sz.x - 12.f, perm_y),
						aida::ui::with_alpha(t.text_dim, a), p.c_str());
					if (clicked) {
						diag::log_tagged_fmt("binary_map",
							"section_row_click name='%s' va=0x%llX size=%llu perm=%s",
							sec.name.c_str(),
							static_cast<unsigned long long>(sec.va),
							static_cast<unsigned long long>(sec.size),
							p.c_str());
						detail::jump_to_address(sec.va);
					}
					if (double_clicked) {
						diag::log_tagged_fmt("binary_map",
							"section_row_double_click name='%s' va=0x%llX (jump_to_hex)",
							sec.name.c_str(),
							static_cast<unsigned long long>(sec.va));
						detail::jump_to_hex(sec.va, static_cast<size_t>(sec.size));
					}
					if (right_clicked) {
						ImGui::OpenPopup("##bm_sec_ctx");
					}
					if (ImGui::BeginPopup("##bm_sec_ctx")) {
						if (ImGui::MenuItem("Jump to disassembly")) {
							const uint64_t va_local = sec.va;
							ImGui::CloseCurrentPopup();
							detail::jump_to_address(va_local);
						}
						if (ImGui::MenuItem("Open in hex view")) {
							const uint64_t va_local = sec.va;
							const size_t sz_local = static_cast<size_t>(sec.size);
							ImGui::CloseCurrentPopup();
							detail::jump_to_hex(va_local, sz_local);
						}
						if (ImGui::MenuItem("Dump section")) {
							const uint64_t va_local = sec.va;
							const uint64_t sz_local = sec.size;
							const std::string klabel = sec.name.empty() ? std::string("section") : sec.name;
							ImGui::CloseCurrentPopup();
							detail::dump_region_to_disk(va_local, sz_local, klabel);
						}
						if (ImGui::MenuItem("Copy section name")) {
							ImGui::SetClipboardText(sec.name.c_str());
							toast_notification::push("Section name copied",
								toast_notification::toast_type_t::info, 2.0f);
						}
						if (ImGui::MenuItem("Copy section VA")) {
							ImGui::SetClipboardText(addr_buf);
							toast_notification::push("Section VA copied",
								toast_notification::toast_type_t::info, 2.0f);
						}
						ImGui::EndPopup();
					}
					ImGui::PopID();
					++idx;
				}
			}

			if (draw_section_header("Functions", static_cast<int>(functions_copy.size()), "functions")) {
				int idx = 0;
				uint64_t cur_sel = s.selected_va.load();
				const float fn_code_fs = code_font->FontSize > 0.f ? code_font->FontSize : 14.f;
				ImFont* fn_name_font = aida::ui::fonts::body();
				if (!fn_name_font) fn_name_font = ImGui::GetFont();
				const float fn_name_fs = fn_name_font->FontSize > 0.f ? fn_name_font->FontSize : 16.f;
				ImFont* fn_chip_font = aida::ui::fonts::caption();
				if (!fn_chip_font) fn_chip_font = code_font;
				const float fn_chip_fs = fn_chip_font->FontSize > 0.f ? fn_chip_font->FontSize : 13.f;
				for (auto& fn : functions_copy) {
					if (!detail::filter_matches(filter_lower, fn.name)) continue;
					ImVec2 cp = ImGui::GetCursorScreenPos();
					float row_w = ImGui::GetContentRegionAvail().x;
					float row_h = 36.f;
					bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
					bool sel = (cur_sel == fn.va) && fn.va != 0;
					if (sel) {
						dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
							aida::ui::with_alpha(t.selection, a), 5.f);
						dl->AddRectFilled(cp, ImVec2(cp.x + 3.f, cp.y + row_h),
							aida::ui::with_alpha(t.accent_u32, a), 1.f);
					} else if (hov) {
						dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
							aida::ui::with_alpha(t.hover_wash, a), 5.f);
					}

					auto& flash = s.pin_flashes[fn.va];
					flash.tick(dt, 3.0f);
					float pin_scale = 1.f + flash.v * 0.6f;
					ImU32 star_col = fn.pinned
						? aida::ui::with_alpha(t.accent_u32, a)
						: aida::ui::with_alpha(t.text_dim, a);
					ImVec2 star_pos = ImVec2(cp.x + 14.f, cp.y + row_h * 0.5f);
					dl->AddCircleFilled(star_pos, 5.f * pin_scale,
						aida::ui::with_alpha(star_col, a * 0.85f), 12);
					if (fn.pinned) {
						dl->AddCircleFilled(star_pos, 7.f * pin_scale,
							aida::ui::with_alpha(t.accent_glow, a * (0.5f + flash.v * 0.5f)), 16);
					}

					ImGui::SetCursorScreenPos(ImVec2(cp.x + 4.f, cp.y));
					ImGui::PushID(static_cast<int>(idx));
					if (ImGui::InvisibleButton("##bm_pin_btn", ImVec2(24.f, row_h))) {
						const bool was_pinned = fn.pinned;
						if (was_pinned) binary_map::unpin_function(fn.va);
						else            binary_map::pin_function(fn.va);
						flash.trigger();
						refresh_after_pin = true;
						diag::log_tagged_fmt("binary_map",
							"pin_btn_click name='%s' va=0x%llX was_pinned=%d action=%s",
							fn.name.c_str(),
							static_cast<unsigned long long>(fn.va),
							was_pinned ? 1 : 0,
							was_pinned ? "unpin" : "pin");
					}
					ImGui::PopID();

					char addr_buf[24];
					std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
						static_cast<unsigned long long>(fn.va));
					const float addr_y = cp.y + 5.f;
					const float name_y = cp.y + (row_h - fn_name_fs) * 0.5f;
					dl->AddText(code_font, fn_code_fs, ImVec2(cp.x + 30.f, addr_y),
						aida::ui::with_alpha(t.text_address, a), addr_buf);
					dl->AddText(fn_name_font, fn_name_fs,
						ImVec2(cp.x + 30.f + 138.f, name_y),
						aida::ui::with_alpha(t.text_primary, a), fn.name.c_str());

					char chip_xref[24];
					std::snprintf(chip_xref, sizeof(chip_xref), "x%d", fn.xref_count);
					char chip_call[24];
					std::snprintf(chip_call, sizeof(chip_call), "c%d", fn.callee_count);
					float chip_h = fn_chip_fs + 6.f;
					float chip_y = cp.y + row_h - chip_h - 4.f;
					float chip_x = cp.x + 30.f + 138.f;

					auto draw_mini_chip = [&](const char* label, ImU32 col) {
						ImFont* f = fn_chip_font;
						float fs = fn_chip_fs;
						ImVec2 sz = f->CalcTextSizeA(fs, FLT_MAX, 0.f, label);
						float pad_x = 7.f;
						float wc = sz.x + pad_x * 2.f;
						float hc = chip_h;
						dl->AddRectFilled(ImVec2(chip_x, chip_y),
							ImVec2(chip_x + wc, chip_y + hc),
							aida::ui::with_alpha(col, a * 0.22f), hc * 0.5f);
						dl->AddText(f, fs, ImVec2(chip_x + pad_x, chip_y + (hc - fs) * 0.5f),
							aida::ui::with_alpha(col, a), label);
						chip_x += wc + 6.f;
					};
					draw_mini_chip(chip_xref, t.info);
					draw_mini_chip(chip_call, t.accent_u32);

					ImGui::SetCursorScreenPos(ImVec2(cp.x + 30.f, cp.y));
					ImGui::PushID(static_cast<int>(0x40000000 | idx));
					ImGui::InvisibleButton("##bm_fn_row", ImVec2(row_w - 30.f, row_h));
					if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
						s.selected_va.store(fn.va);
						diag::log_tagged_fmt("binary_map",
							"function_row_click name='%s' va=0x%llX xrefs=%d callees=%d pinned=%d",
							fn.name.c_str(),
							static_cast<unsigned long long>(fn.va),
							fn.xref_count, fn.callee_count,
							fn.pinned ? 1 : 0);
					}
					if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
						s.ctx_target.store(idx);
						s.ctx_va = fn.va;
						diag::log_tagged_fmt("binary_map",
							"function_row_right_click name='%s' va=0x%llX",
							fn.name.c_str(),
							static_cast<unsigned long long>(fn.va));
						ImGui::OpenPopup("##bm_fn_ctx");
					}
					if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && ImGui::IsItemHovered()) {
						diag::log_tagged_fmt("binary_map",
							"function_row_double_click name='%s' va=0x%llX",
							fn.name.c_str(),
							static_cast<unsigned long long>(fn.va));
						detail::jump_to_address(fn.va);
					}
					if (ImGui::BeginPopup("##bm_fn_ctx")) {
						if (ImGui::MenuItem("Copy summary to chat")) {
							std::string payload = detail::make_function_chat_payload(fn);
							detail::inject_to_chat(payload);
						}
						if (ImGui::MenuItem(fn.pinned ? "Unpin" : "Pin")) {
							const bool was_pinned = fn.pinned;
							if (was_pinned) binary_map::unpin_function(fn.va);
							else            binary_map::pin_function(fn.va);
							flash.trigger();
							refresh_after_pin = true;
						}
						if (ImGui::MenuItem("Jump to disassembly")) {
							const uint64_t va = fn.va;
							ImGui::CloseCurrentPopup();
							detail::jump_to_address(va);
						}
						if (ImGui::MenuItem("Open in hex view")) {
							const uint64_t va = fn.va;
							ImGui::CloseCurrentPopup();
							detail::jump_to_hex(va, 0x400);
						}
						if (ImGui::MenuItem("Copy VA")) {
							char vbuf[32];
							std::snprintf(vbuf, sizeof(vbuf), "0x%llX",
								static_cast<unsigned long long>(fn.va));
							ImGui::SetClipboardText(vbuf);
							toast_notification::push("Function VA copied",
								toast_notification::toast_type_t::info, 2.0f);
						}
						if (ImGui::MenuItem("Copy name")) {
							ImGui::SetClipboardText(fn.name.c_str());
							toast_notification::push("Function name copied",
								toast_notification::toast_type_t::info, 2.0f);
						}
						ImGui::EndPopup();
					}
					ImGui::PopID();
					ImGui::Dummy(ImVec2(row_w, row_h));
					++idx;
				}
			}

			if (draw_section_header("Globals", static_cast<int>(globals_copy.size()), "globals")) {
				int idx = 0;
				const float gl_code_fs = code_font->FontSize > 0.f ? code_font->FontSize : 14.f;
				ImFont* gl_name_font = aida::ui::fonts::body();
				if (!gl_name_font) gl_name_font = ImGui::GetFont();
				const float gl_name_fs = gl_name_font->FontSize > 0.f ? gl_name_font->FontSize : 16.f;
				ImFont* gl_chip_font = aida::ui::fonts::caption();
				if (!gl_chip_font) gl_chip_font = code_font;
				const float gl_chip_fs = gl_chip_font->FontSize > 0.f ? gl_chip_font->FontSize : 13.f;
				for (const auto& gl : globals_copy) {
					if (!detail::filter_matches(filter_lower, gl.name)) continue;
					ImVec2 cp = ImGui::GetCursorScreenPos();
					float row_w = ImGui::GetContentRegionAvail().x;
					float row_h = 30.f;
					bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
					if (hov) {
						dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
							aida::ui::with_alpha(t.hover_wash, a), 4.f);
					}
					char addr_buf[24];
					std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
						static_cast<unsigned long long>(gl.va));
					const float gl_code_y = cp.y + (row_h - gl_code_fs) * 0.5f;
					const float gl_name_y = cp.y + (row_h - gl_name_fs) * 0.5f;
					dl->AddText(code_font, gl_code_fs, ImVec2(cp.x + 10.f, gl_code_y),
						aida::ui::with_alpha(t.text_address, a), addr_buf);
					dl->AddText(gl_name_font, gl_name_fs,
						ImVec2(cp.x + 130.f, gl_name_y),
						aida::ui::with_alpha(t.text_primary, a), gl.name.c_str());

					char chip_buf[16];
					std::snprintf(chip_buf, sizeof(chip_buf), "x%d", gl.xref_count);
					ImVec2 sz = gl_chip_font->CalcTextSizeA(gl_chip_fs, FLT_MAX, 0.f, chip_buf);
					float chip_w = sz.x + 14.f;
					float chip_h = gl_chip_fs + 6.f;
					ImVec2 ca = ImVec2(cp.x + row_w - chip_w - 44.f, cp.y + (row_h - chip_h) * 0.5f);
					ImVec2 cb = ImVec2(ca.x + chip_w, ca.y + chip_h);
					dl->AddRectFilled(ca, cb, aida::ui::with_alpha(t.info, a * 0.22f), chip_h * 0.5f);
					dl->AddText(gl_chip_font, gl_chip_fs,
						ImVec2(ca.x + 7.f, ca.y + (chip_h - gl_chip_fs) * 0.5f),
						aida::ui::with_alpha(t.info, a), chip_buf);

					ImU32 perm_col = gl.writable
						? aida::ui::with_alpha(t.success, a)
						: aida::ui::with_alpha(t.text_dim, a);
					dl->AddText(gl_chip_font, gl_chip_fs,
						ImVec2(cp.x + row_w - 30.f, cp.y + (row_h - gl_chip_fs) * 0.5f),
						perm_col, gl.writable ? "rw" : "ro");

					ImGui::SetCursorScreenPos(cp);
					ImGui::PushID(static_cast<int>(0x50000000 | idx));
					ImGui::InvisibleButton("##bm_gl_row", ImVec2(row_w, row_h));
					if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
						diag::log_tagged_fmt("binary_map",
							"global_row_click name='%s' va=0x%llX xrefs=%d writable=%d",
							gl.name.c_str(),
							static_cast<unsigned long long>(gl.va),
							gl.xref_count,
							gl.writable ? 1 : 0);
						detail::jump_to_hex(gl.va, 0x200);
					}
					if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && ImGui::IsItemHovered()) {
						detail::jump_to_address(gl.va);
					}
					if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
						ImGui::OpenPopup("##bm_gl_ctx");
					}
					if (ImGui::BeginPopup("##bm_gl_ctx")) {
						if (ImGui::MenuItem("Copy summary to chat")) {
							std::string payload = detail::make_global_chat_payload(gl);
							detail::inject_to_chat(payload);
						}
						if (ImGui::MenuItem("Open in hex view")) {
							const uint64_t va = gl.va;
							ImGui::CloseCurrentPopup();
							detail::jump_to_hex(va, 0x200);
						}
						if (ImGui::MenuItem("Jump to disassembly")) {
							const uint64_t va = gl.va;
							ImGui::CloseCurrentPopup();
							detail::jump_to_address(va);
						}
						if (ImGui::MenuItem("Copy VA")) {
							char vbuf[32];
							std::snprintf(vbuf, sizeof(vbuf), "0x%llX",
								static_cast<unsigned long long>(gl.va));
							ImGui::SetClipboardText(vbuf);
							toast_notification::push("Global VA copied",
								toast_notification::toast_type_t::info, 2.0f);
						}
						if (ImGui::MenuItem("Copy name")) {
							ImGui::SetClipboardText(gl.name.c_str());
							toast_notification::push("Global name copied",
								toast_notification::toast_type_t::info, 2.0f);
						}
						ImGui::EndPopup();
					}
					ImGui::PopID();
					++idx;
				}
			}

			if (draw_section_header("Imports", total_imports, "imports")) {
				int imp_idx = 0;
				for (const auto& imp : imports_copy) {
					const auto colon = imp.find(':');
					const std::string dll = (colon == std::string::npos) ? imp : imp.substr(0, colon);
					std::string func_list;
					if (colon != std::string::npos && colon + 1 < imp.size()) {
						size_t start = colon + 1;
						while (start < imp.size() && imp[start] == ' ') ++start;
						func_list = imp.substr(start);
					}

					std::vector<std::string> funcs;
					{
						size_t pos = 0;
						while (pos < func_list.size()) {
							size_t next = func_list.find(',', pos);
							if (next == std::string::npos) next = func_list.size();
							std::string token = func_list.substr(pos, next - pos);
							while (!token.empty() && token.front() == ' ') token.erase(token.begin());
							while (!token.empty() && token.back() == ' ') token.pop_back();
							if (!token.empty()) funcs.push_back(std::move(token));
							pos = next + 1u;
						}
					}

					bool any_match = detail::filter_matches(filter_lower, dll);
					if (!any_match) {
						for (const auto& fn : funcs) {
							if (detail::filter_matches(filter_lower, fn)) {
								any_match = true;
								break;
							}
						}
					}
					if (!any_match) continue;

					const std::string key = std::string("imports::") + dll;
					bool collapsed = detail::group_is_collapsed(s, key);

					ImVec2 cp = ImGui::GetCursorScreenPos();
					float row_w = ImGui::GetContentRegionAvail().x;
					float row_h = 26.f;
					bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
					ImU32 fill = hov
						? aida::ui::with_alpha(t.hover_wash, a)
						: aida::ui::with_alpha(t.panel_bg, a * 0.7f);
					dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h), fill, 4.f);
					ImU32 ar = aida::ui::with_alpha(t.accent_u32, a);
					float arrow_x = cp.x + 12.f;
					float arrow_y = cp.y + row_h * 0.5f;
					if (collapsed) {
						dl->AddTriangleFilled(
							ImVec2(arrow_x, arrow_y - 4.f),
							ImVec2(arrow_x + 6.f, arrow_y),
							ImVec2(arrow_x, arrow_y + 4.f), ar);
					} else {
						dl->AddTriangleFilled(
							ImVec2(arrow_x - 1.f, arrow_y - 2.f),
							ImVec2(arrow_x + 7.f, arrow_y - 2.f),
							ImVec2(arrow_x + 3.f, arrow_y + 4.f), ar);
					}
					char hbuf[200];
					std::snprintf(hbuf, sizeof(hbuf), "%s  (%d)",
						dll.c_str(), static_cast<int>(funcs.size()));
					ImFont* imp_hdr_font = aida::ui::fonts::body_em();
					if (!imp_hdr_font) imp_hdr_font = ImGui::GetFont();
					const float imp_hdr_fs = imp_hdr_font->FontSize > 0.f ? imp_hdr_font->FontSize : 16.f;
					dl->AddText(imp_hdr_font, imp_hdr_fs,
						ImVec2(cp.x + 28.f, cp.y + (row_h - imp_hdr_fs) * 0.5f),
						aida::ui::with_alpha(t.text_primary, a), hbuf);

					ImGui::SetCursorScreenPos(cp);
					ImGui::PushID(static_cast<int>(0x60000000 | imp_idx));
					ImGui::InvisibleButton("##bm_imp_hdr", ImVec2(row_w, row_h));
					if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
						diag::log_tagged_fmt("binary_map",
							"import_dll_toggle dll='%s' funcs=%zu now_collapsed=%d",
							dll.c_str(), funcs.size(), (!collapsed) ? 1 : 0);
						detail::toggle_group(s, key);
					}
					if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
						ImGui::OpenPopup("##bm_imp_hdr_ctx");
					}
					if (ImGui::BeginPopup("##bm_imp_hdr_ctx")) {
						if (ImGui::MenuItem("Copy DLL name")) {
							ImGui::SetClipboardText(dll.c_str());
							toast_notification::push("DLL name copied",
								toast_notification::toast_type_t::info, 2.0f);
						}
						if (ImGui::MenuItem("Copy function list")) {
							std::string joined;
							for (size_t fi = 0; fi < funcs.size(); ++fi) {
								if (fi) joined += "\n";
								joined += funcs[fi];
							}
							ImGui::SetClipboardText(joined.c_str());
							toast_notification::push("Function list copied",
								toast_notification::toast_type_t::info, 2.0f);
						}
						ImGui::EndPopup();
					}
					ImGui::PopID();

					if (!collapsed) {
						const float imp_fn_fs = code_font->FontSize > 0.f ? code_font->FontSize : 14.f;
						const float imp_row_h = imp_fn_fs + 10.f;
						int fn_idx = 0;
						for (const auto& fn : funcs) {
							if (!detail::filter_matches(filter_lower, fn) &&
								!detail::filter_matches(filter_lower, dll)) { ++fn_idx; continue; }
							ImVec2 ip = ImGui::GetCursorScreenPos();
							bool fn_hov = ImGui::IsMouseHoveringRect(ip,
								ImVec2(ip.x + row_w, ip.y + imp_row_h), true);
							if (fn_hov) {
								dl->AddRectFilled(ip, ImVec2(ip.x + row_w, ip.y + imp_row_h),
									aida::ui::with_alpha(t.hover_wash, a * 0.7f), 3.f);
							}
							dl->AddText(code_font, imp_fn_fs,
								ImVec2(ip.x + 36.f, ip.y + (imp_row_h - imp_fn_fs) * 0.5f),
								aida::ui::with_alpha(t.text_secondary, a), fn.c_str());
							ImGui::SetCursorScreenPos(ip);
							ImGui::PushID(static_cast<int>(0x70000000 | (imp_idx * 4096 + fn_idx)));
							ImGui::InvisibleButton("##bm_imp_fn", ImVec2(row_w, imp_row_h));
							if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
								std::string clip = dll + "!" + fn;
								ImGui::SetClipboardText(clip.c_str());
								toast_notification::push("Import symbol copied",
									toast_notification::toast_type_t::info, 2.0f);
							}
							if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
								ImGui::OpenPopup("##bm_imp_fn_ctx");
							}
							if (ImGui::BeginPopup("##bm_imp_fn_ctx")) {
								if (ImGui::MenuItem("Copy DLL!fn")) {
									std::string clip = dll + "!" + fn;
									ImGui::SetClipboardText(clip.c_str());
									toast_notification::push("Import symbol copied",
										toast_notification::toast_type_t::info, 2.0f);
								}
								if (ImGui::MenuItem("Copy function name")) {
									ImGui::SetClipboardText(fn.c_str());
								}
								ImGui::EndPopup();
							}
							ImGui::PopID();
							ImGui::Dummy(ImVec2(row_w, imp_row_h));
							++fn_idx;
						}
					}
					++imp_idx;
				}
			}

			if (draw_section_header("Exports", total_exports, "exports")) {
				int idx = 0;
				const float exp_fs = code_font->FontSize > 0.f ? code_font->FontSize : 14.f;
				const float exp_row_h = exp_fs + 10.f;
				for (const auto& ex : exports_copy) {
					if (!detail::filter_matches(filter_lower, ex)) continue;
					ImVec2 cp = ImGui::GetCursorScreenPos();
					float row_w = ImGui::GetContentRegionAvail().x;
					ImGui::PushID(static_cast<int>(0x7E000000 | (idx & 0x00FFFFFF)));
					ImGui::InvisibleButton("##bm_exp_row", ImVec2(row_w, exp_row_h));
					bool hov = ImGui::IsItemHovered();
					bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
					bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);
					if (hov) {
						dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + exp_row_h),
							aida::ui::with_alpha(t.hover_wash, a), 3.f);
					}
					dl->AddText(code_font, exp_fs,
						ImVec2(cp.x + 18.f, cp.y + (exp_row_h - exp_fs) * 0.5f),
						aida::ui::with_alpha(t.text_primary, a), ex.c_str());
					uint64_t resolved_va = 0;
					{
						std::lock_guard<std::mutex> gl(s.mutex);
						for (const auto& fn : s.map.functions) {
							if (fn.name == ex) { resolved_va = fn.va; break; }
						}
					}
					if (clicked) {
						if (resolved_va != 0) {
							detail::jump_to_address(resolved_va);
						} else {
							ImGui::SetClipboardText(ex.c_str());
							toast_notification::push("Export name copied (no VA resolved)",
								toast_notification::toast_type_t::info, 2.5f);
						}
					}
					if (right_clicked) {
						ImGui::OpenPopup("##bm_exp_ctx");
					}
					if (ImGui::BeginPopup("##bm_exp_ctx")) {
						if (resolved_va != 0 && ImGui::MenuItem("Jump to disassembly")) {
							const uint64_t va_local = resolved_va;
							ImGui::CloseCurrentPopup();
							detail::jump_to_address(va_local);
						}
						if (ImGui::MenuItem("Copy export name")) {
							ImGui::SetClipboardText(ex.c_str());
							toast_notification::push("Export name copied",
								toast_notification::toast_type_t::info, 2.0f);
						}
						ImGui::EndPopup();
					}
					ImGui::PopID();
					ImGui::Dummy(ImVec2(row_w, exp_row_h));
					++idx;
				}
			}
		}

		if (resolved_mode == active_mode_t::pe_static
			&& functions_copy.empty() && !refreshing_now)
		{
			ImVec2 cp = ImGui::GetCursorScreenPos();
			ImVec2 sz = ImVec2(panel_inner_w, std::max(120.f, section_inner_h * 0.5f));
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
			cfg.title = "No binary loaded";
			cfg.body = last_error_copy.empty()
				? "Open a binary or press Refresh to build the map."
				: last_error_copy;
			cfg.max_width = 320.f;
			aida::ui::empty_state::render(cp, sz, cfg);
		} else if (resolved_mode == active_mode_t::live_process
			&& regions_copy.empty() && !refreshing_now)
		{
			ImVec2 cp = ImGui::GetCursorScreenPos();
			ImVec2 sz = ImVec2(panel_inner_w, std::max(120.f, section_inner_h * 0.5f));
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::memory;
			cfg.title = "No live regions";
			cfg.body = "Press Refresh while attached to enumerate memory regions.";
			cfg.max_width = 320.f;
			aida::ui::empty_state::render(cp, sz, cfg);
		}

		ImGui::EndChild();
		ImGui::PopFont();
		ImGui::PopStyleColor(3);

		ImGui::EndChild();

		if (open_change_protect_popup_local) {
			ImGui::OpenPopup("Change Protection");
		}

		if (ImGui::BeginPopupModal("Change Protection", &s.change_protect_open, ImGuiWindowFlags_AlwaysAutoResize)) {
			ImGui::Text("Address: %016llX", static_cast<unsigned long long>(s.change_protect_addr));
			ImGui::Text("Size:    %llu bytes", static_cast<unsigned long long>(s.change_protect_size));
			ImGui::Text("Current: 0x%X", s.change_protect_old);
			ImGui::Separator();
			const char* labels_arr[] = {
				"PAGE_NOACCESS (0x01)",
				"PAGE_READONLY (0x02)",
				"PAGE_READWRITE (0x04)",
				"PAGE_WRITECOPY (0x08)",
				"PAGE_EXECUTE (0x10)",
				"PAGE_EXECUTE_READ (0x20)",
				"PAGE_EXECUTE_READWRITE (0x40)",
				"PAGE_EXECUTE_WRITECOPY (0x80)"
			};
			const uint32_t values_arr[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
			const int val_count = static_cast<int>(sizeof(values_arr) / sizeof(values_arr[0]));
			if (s.change_protect_choice < 0) s.change_protect_choice = 0;
			if (s.change_protect_choice >= val_count) s.change_protect_choice = val_count - 1;
			ImGui::Combo("##bm_new_protect", &s.change_protect_choice, labels_arr, val_count);
			ImGui::Separator();
			if (ImGui::Button("Apply", ImVec2(100.f, 0.f))) {
				const uint32_t new_protect = values_arr[s.change_protect_choice];
				uint32_t old_protect = 0;
				diag::log_tagged_critical_fmt("binary_map",
					"change_protect_request addr=0x%llx size=%llu new=0x%X",
					static_cast<unsigned long long>(s.change_protect_addr),
					static_cast<unsigned long long>(s.change_protect_size),
					static_cast<unsigned>(new_protect));
				const bool ok = driver_bridge::protect_memory(
					s.change_protect_addr, s.change_protect_size, new_protect, &old_protect);
				diag::log_tagged_critical_fmt("binary_map",
					"change_protect_done addr=0x%llx ok=%d old=0x%X new=0x%X",
					static_cast<unsigned long long>(s.change_protect_addr),
					ok ? 1 : 0,
					static_cast<unsigned>(old_protect),
					static_cast<unsigned>(new_protect));
				if (ok) {
					char msg[96];
					std::snprintf(msg, sizeof(msg), "Protection changed 0x%X -> 0x%X",
						old_protect, new_protect);
					toast_notification::push(msg, toast_notification::toast_type_t::info, 3.0f);
					s.live_refresh_requested.store(true);
				} else {
					toast_notification::push("Failed to change protection",
						toast_notification::toast_type_t::error, 3.0f);
				}
				s.change_protect_open = false;
				ImGui::CloseCurrentPopup();
			}
			ImGui::SameLine();
			if (ImGui::Button("Cancel", ImVec2(100.f, 0.f))) {
				s.change_protect_open = false;
				ImGui::CloseCurrentPopup();
			}
			ImGui::EndPopup();
		}

		if (refresh_after_pin) {
			s.refresh_requested.store(true);
		}

		if (!s.auto_refreshed_once) {
			if (want_static && !s.refreshing.load()) {
				s.refresh_requested.store(true);
			}
			if (want_live && !s.live_refreshing.load() && detail::live_available()) {
				s.live_refresh_requested.store(true);
			}
			s.auto_refreshed_once = true;
		}

		if (want_live && detail::live_available() && !s.live_refreshing.load()) {
			const uint32_t live_pid_attached = driver_bridge::attached_pid();
			uint32_t cached_pid = 0;
			size_t cached_regions = 0;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				cached_pid = s.live.pid;
				cached_regions = s.live.regions.size();
			}
			if (cached_pid != live_pid_attached || (live_pid_attached != 0 && cached_regions == 0)) {
				diag::log_tagged_fmt("binary_map",
					"live_auto_refresh_trigger cached_pid=%u attached_pid=%u cached_regions=%zu",
					static_cast<unsigned>(cached_pid),
					static_cast<unsigned>(live_pid_attached),
					cached_regions);
				s.live_refresh_requested.store(true);
			}
		}
	}

}
}
