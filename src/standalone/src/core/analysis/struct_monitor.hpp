#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "struct_recon_engine.hpp"
#include "page_guard_engine.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"
#include "../infra/executor.hpp"
#include "../../helpers/diag_log.hpp"

namespace struct_monitor {

struct live_access_t {
	uint64_t    rip = 0;
	uint64_t    field_offset = 0;
	int         access_size = 0;
	bool        is_write = false;
	std::string disasm;
	struct_recon::field_type_t inferred_type = struct_recon::field_type_t::unknown;
	int         hit_count = 0;
	uint64_t    last_timestamp = 0;
};

struct monitor_session_t {
	uint64_t base_address = 0;
	int      struct_size = 0;
	uint32_t pid = 0;
	uint32_t pg_session_id = 0;
	bool     using_page_guard = false;
	bool     using_hwbp = false;
	bool     using_polling = false;
	uint32_t primary_tid = 0;
	std::vector<uint8_t> polling_baseline;
};

struct state_t {
	std::atomic<bool> active{false};
	std::atomic<bool> stop_requested{false};
	std::atomic<uint64_t> total_captures{0};
	std::atomic<uint64_t> captures_per_second{0};
	std::mutex access_mutex;
	std::map<uint64_t, live_access_t> offset_accesses;
	std::map<uint64_t, struct_recon::insn_analysis::decoded_access_t> rip_cache;
	monitor_session_t session;
};

inline state_t g_state;

inline void record_polling_deltas(uint64_t timestamp)
{
	monitor_session_t& sess = g_state.session;
	if (!sess.using_polling || sess.base_address == 0 || sess.struct_size <= 0 || sess.polling_baseline.empty())
		return;

	std::vector<uint8_t> current;
	if (!driver_bridge::read_memory(sess.base_address, static_cast<size_t>(sess.struct_size), current) || current.empty()) {
		diag::log_tagged_fmt("struct_monitor", "polling_sample_failed base=0x%llX size=%d baseline=%zu",
			static_cast<unsigned long long>(sess.base_address),
			sess.struct_size,
			sess.polling_baseline.size());
		return;
	}

	const size_t n = (std::min)(current.size(), sess.polling_baseline.size());
	uint64_t hits = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.access_mutex);
		for (size_t i = 0; i < n && hits < 64; ++i) {
			if (current[i] == sess.polling_baseline[i])
				continue;

			const uint64_t off = static_cast<uint64_t>(i);
			auto it = g_state.offset_accesses.find(off);
			if (it == g_state.offset_accesses.end()) {
				live_access_t la;
				la.rip = 0;
				la.field_offset = off;
				la.access_size = 1;
				la.is_write = true;
				la.disasm = "polling_delta";
				la.inferred_type = struct_recon::field_type_t::uint8;
				la.hit_count = 1;
				la.last_timestamp = timestamp;
				g_state.offset_accesses[off] = std::move(la);
			} else {
				it->second.hit_count++;
				it->second.last_timestamp = timestamp;
			}
			++hits;
		}
	}

	if (hits != 0) {
		g_state.total_captures.fetch_add(hits);
		diag::log_tagged_fmt("struct_monitor", "polling_sample_delta base=0x%llX size=%d hits=%llu",
			static_cast<unsigned long long>(sess.base_address),
			sess.struct_size,
			static_cast<unsigned long long>(hits));
	}
	sess.polling_baseline = std::move(current);
}

inline void start(uint64_t base_address, int struct_size, const std::string& name, const std::string& backend = "auto")
{
	if (g_state.active.load()) return;

	uint32_t pid = driver_bridge::attached_pid();
	if (pid == 0) return;

	g_state.active.store(true);
	g_state.stop_requested.store(false);
	g_state.total_captures.store(0);
	g_state.captures_per_second.store(0);

	{
		std::lock_guard<std::mutex> lk(g_state.access_mutex);
		g_state.offset_accesses.clear();
		g_state.rip_cache.clear();
	}

	g_state.session = {};
	g_state.session.base_address = base_address;
	g_state.session.struct_size = struct_size;
	g_state.session.pid = pid;

	std::string backend_pref = backend;
	std::transform(backend_pref.begin(), backend_pref.end(), backend_pref.begin(), [](unsigned char c) {
		return static_cast<char>(std::tolower(c));
	});
	if (backend_pref.empty())
		backend_pref = "auto";

	monitor_session_t& sess = g_state.session;
	const bool want_auto = backend_pref == "auto";
	const bool want_page_guard = want_auto || backend_pref == "page_guard";
	const bool want_polling = want_auto || backend_pref == "polling" || backend_pref == "snapshot";
	const bool want_hwbp = want_auto || backend_pref == "hardware_breakpoint" || backend_pref == "hwbp";
	bool pg_ok = false;

	if (!struct_recon::g_state.active) {
		struct_recon::reconstruct_from_snapshot(base_address, struct_size, name);
		int wait = 0;
		while (struct_recon::g_state.monitoring.load() && wait < 20) {
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
			++wait;
		}
		if (struct_recon::g_state.monitoring.load())
			struct_recon::cancel();
	}

	if (want_page_guard && driver_bridge::using_kernel_driver()) {
		uint64_t page_base = base_address & ~0xFFFULL;
		uint64_t page_end = (base_address + static_cast<uint64_t>(struct_size) + 0xFFF) & ~0xFFFULL;
		uint64_t region_size = page_end - page_base;

		uint32_t sid = page_guard_engine::g_pg_engine.install(pid, page_base, region_size);
		if (sid != 0) {
			sess.pg_session_id = sid;
			sess.using_page_guard = true;
			pg_ok = true;
		}
		diag::log_tagged_fmt("struct_monitor", "backend_page_guard base=0x%llX size=%d sid=%u ok=%d",
			static_cast<unsigned long long>(base_address),
			struct_size,
			sid,
			pg_ok ? 1 : 0);
	}

	if (!pg_ok && want_polling) {
		std::vector<uint8_t> baseline;
		if (driver_bridge::read_memory(base_address, static_cast<size_t>(struct_size), baseline) && !baseline.empty()) {
			sess.polling_baseline = std::move(baseline);
			sess.using_polling = true;
		}
		diag::log_tagged_fmt("struct_monitor", "backend_polling base=0x%llX size=%d baseline=%zu ok=%d",
			static_cast<unsigned long long>(base_address),
			struct_size,
			sess.polling_baseline.size(),
			sess.using_polling ? 1 : 0);
	}

	if (!pg_ok && !sess.using_polling && want_hwbp) {
		auto threads = driver_bridge::enumerate_threads();
		if (!threads.empty()) {
			sess.primary_tid = threads[0].tid;
			sess.using_hwbp = true;

			int offsets[] = {0, 8, 16, 32};
			for (int i = 0; i < 4; ++i) {
				if (offsets[i] >= struct_size) continue;
				uint64_t watch = base_address + static_cast<uint64_t>(offsets[i]);
				driver_bridge::set_hardware_breakpoint(sess.primary_tid, i, watch, 1, 3);
			}
		}
		diag::log_tagged_fmt("struct_monitor", "backend_hwbp base=0x%llX size=%d tid=%u ok=%d",
			static_cast<unsigned long long>(base_address),
			struct_size,
			sess.primary_tid,
			sess.using_hwbp ? 1 : 0);
	}

	diag::log_tagged_fmt("struct_monitor", "start_backend_ready backend=%s pg=%d polling=%d hwbp=%d",
		backend_pref.c_str(),
		sess.using_page_guard ? 1 : 0,
		sess.using_polling ? 1 : 0,
		sess.using_hwbp ? 1 : 0);

	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "analysis";
	sub.label = "analysis.struct_monitor.loop";
	sub.thread_class = "long_running";
	sub.domain = aida::infra::executor::domain_t::long_running;
	sub.priority = 2;
	sub.target_pid = pid;
	sub.body = [base_address, struct_size]() {
		monitor_session_t& sess = g_state.session;

		uint64_t total = 0;
		auto last_rate_check = std::chrono::steady_clock::now();
		uint64_t captures_since_last = 0;

		while (!g_state.stop_requested.load()) {
			std::this_thread::sleep_for(std::chrono::milliseconds(30));

			auto now = std::chrono::steady_clock::now();
			auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_rate_check).count();
			if (elapsed_ms >= 1000) {
				g_state.captures_per_second.store(captures_since_last);
				captures_since_last = 0;
				last_rate_check = now;
			}

			std::vector<page_guard_engine::pg_capture_t> captures;

			if (sess.using_page_guard && sess.pg_session_id != 0) {
				captures = page_guard_engine::g_pg_engine.get_captures(sess.pg_session_id);
			}

			if (sess.using_polling) {
				std::vector<uint8_t> current;
				if (driver_bridge::read_memory(base_address, static_cast<size_t>(struct_size), current) && !current.empty()) {
					const size_t n = (std::min)(current.size(), sess.polling_baseline.size());
					const uint64_t ts = static_cast<uint64_t>(
						std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
					for (size_t i = 0; i < n && captures.size() < 64; ++i) {
						if (current[i] == sess.polling_baseline[i])
							continue;
						page_guard_engine::pg_capture_t cap{};
						cap.timestamp = ts;
						cap.fault_addr = base_address + static_cast<uint64_t>(i);
						cap.rip = 0;
						cap.access_type = 1;
						captures.push_back(cap);
					}
					sess.polling_baseline = std::move(current);
				}
			}

			if (captures.empty()) continue;

			std::lock_guard<std::mutex> lk(g_state.access_mutex);

			for (auto& cap : captures) {
				if (cap.fault_addr < base_address ||
				    cap.fault_addr >= base_address + static_cast<uint64_t>(struct_size))
					continue;

				uint64_t field_offset = cap.fault_addr - base_address;

				if (sess.using_polling && cap.rip == 0) {
					struct_recon::insn_analysis::decoded_access_t decoded;
					decoded.rip = 0;
					decoded.access_addr = cap.fault_addr;
					decoded.access_size = 1;
					decoded.is_write = true;
					decoded.inferred_type = struct_recon::field_type_t::uint8;
					decoded.disasm = "polling_delta";
					g_state.rip_cache[cap.fault_addr] = decoded;
				} else {
					auto rip_it = g_state.rip_cache.find(cap.rip);
					if (rip_it == g_state.rip_cache.end()) {
						auto decoded = struct_recon::insn_analysis::analyze_captured_rip(
							cap.rip, cap.fault_addr, cap.access_type);
						g_state.rip_cache[cap.rip] = decoded;
					}
				}

				auto& decoded = g_state.rip_cache[(sess.using_polling && cap.rip == 0) ? cap.fault_addr : cap.rip];

				auto off_it = g_state.offset_accesses.find(field_offset);
				if (off_it == g_state.offset_accesses.end()) {
					live_access_t la;
					la.rip = cap.rip;
					la.field_offset = field_offset;
					la.access_size = decoded.access_size;
					la.is_write = decoded.is_write;
					la.disasm = decoded.disasm;
					la.inferred_type = decoded.inferred_type;
					la.hit_count = 1;
					la.last_timestamp = cap.timestamp;
					g_state.offset_accesses[field_offset] = la;
				} else {
					off_it->second.hit_count++;
					off_it->second.last_timestamp = cap.timestamp;
					if (off_it->second.inferred_type == struct_recon::field_type_t::unknown &&
					    decoded.inferred_type != struct_recon::field_type_t::unknown) {
						off_it->second.inferred_type = decoded.inferred_type;
						off_it->second.access_size = decoded.access_size;
					}
				}

				++total;
				++captures_since_last;
			}

			g_state.total_captures.store(total);

			{
				std::lock_guard<std::mutex> sr_lk(struct_recon::g_state.mutex);
				for (auto& [off, la] : g_state.offset_accesses) {
					bool found = false;
					for (auto& field : struct_recon::g_state.current.fields) {
						if (off >= field.offset &&
						    off < field.offset + static_cast<uint64_t>(field.size)) {
							found = true;

							if (la.inferred_type != struct_recon::field_type_t::unknown) {
								float current_conf = field.type_confidence;
								float new_conf = 0.5f + static_cast<float>(la.hit_count) * 0.05f;
								if (new_conf > 0.99f) new_conf = 0.99f;

								if (new_conf > current_conf ||
								    field.type == struct_recon::field_type_t::unknown ||
								    field.type == struct_recon::field_type_t::uint64 ||
								    field.type == struct_recon::field_type_t::uint32) {
									field.type = la.inferred_type;
									field.size = la.access_size;
									field.type_confidence = new_conf;
								}
							}

							bool access_exists = false;
							for (auto& acc : field.accesses) {
								if (acc.instruction_addr == la.rip) {
									acc.hit_count = la.hit_count;
									access_exists = true;
									break;
								}
							}
							if (!access_exists) {
								struct_recon::access_record_t rec;
								rec.instruction_addr = la.rip;
								rec.access_offset = off;
								rec.access_size = la.access_size;
								rec.is_write = la.is_write;
								rec.disasm_text = la.disasm;
								rec.hit_count = la.hit_count;
								field.accesses.push_back(rec);
							}
							break;
						}
					}

					if (!found) {
						struct_recon::struct_field_t new_field;
						new_field.offset = off;
						new_field.size = la.access_size;
						new_field.type = la.inferred_type;
						char fname[32];
						std::snprintf(fname, sizeof(fname), "field_%03llX",
						              static_cast<unsigned long long>(off));
						new_field.name = fname;

						struct_recon::access_record_t rec;
						rec.instruction_addr = la.rip;
						rec.access_offset = off;
						rec.access_size = la.access_size;
						rec.is_write = la.is_write;
						rec.disasm_text = la.disasm;
						rec.hit_count = la.hit_count;
						new_field.accesses.push_back(rec);

						struct_recon::g_state.current.fields.push_back(new_field);

						std::sort(struct_recon::g_state.current.fields.begin(),
						          struct_recon::g_state.current.fields.end(),
						          [](const struct_recon::struct_field_t& a,
						             const struct_recon::struct_field_t& b) {
							          return a.offset < b.offset;
						          });
					}
				}
			}

			std::vector<uint8_t> data;
			driver_bridge::read_memory(base_address, static_cast<size_t>(struct_size), data);
			if (!data.empty()) {
				std::lock_guard<std::mutex> sr_lk(struct_recon::g_state.mutex);
				for (auto& field : struct_recon::g_state.current.fields) {
					if (field.offset + 8 <= data.size()) {
						uint64_t val = 0;
						int copy_size = (std::min)(field.size, 8);
						std::memcpy(&val, data.data() + field.offset, static_cast<size_t>(copy_size));
						field.value_history.push(val);
					}
				}
			}
		}

		if (sess.using_page_guard && sess.pg_session_id != 0) {
			page_guard_engine::g_pg_engine.uninstall(sess.pg_session_id);
		}

		if (sess.using_hwbp && sess.primary_tid != 0) {
			for (int i = 0; i < 4; ++i) {
				driver_bridge::clear_hardware_breakpoint(sess.primary_tid, i);
			}
		}

		g_state.active.store(false);
	};
	if (!aida::infra::executor::submit(std::move(sub)).submitted) {
		if (sess.using_page_guard && sess.pg_session_id != 0)
			page_guard_engine::g_pg_engine.uninstall(sess.pg_session_id);
		if (sess.using_hwbp && sess.primary_tid != 0) {
			for (int i = 0; i < 4; ++i)
				driver_bridge::clear_hardware_breakpoint(sess.primary_tid, i);
		}
		g_state.active.store(false);
		diag::log_tagged_fmt("struct_monitor",
			"monitor_loop_post_failed base=0x%llX size=%d pid=%u",
			static_cast<unsigned long long>(base_address),
			struct_size,
			pid);
	}
}

inline void stop()
{
	auto now = std::chrono::steady_clock::now();
	uint64_t timestamp = static_cast<uint64_t>(
		std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
	record_polling_deltas(timestamp);
	g_state.stop_requested.store(true);
}

inline std::vector<live_access_t> get_access_snapshot()
{
	std::vector<live_access_t> result;
	std::lock_guard<std::mutex> lk(g_state.access_mutex);
	result.reserve(g_state.offset_accesses.size());
	for (auto& [off, la] : g_state.offset_accesses) {
		result.push_back(la);
	}
	return result;
}

inline void resolve_vtable_entries(uint64_t vtable_addr, std::vector<struct_recon::vtable_entry_t>& entries)
{
	entries.clear();
	auto modules = driver_bridge::enumerate_modules();

	for (int i = 0; i < 64; ++i) {
		std::vector<uint8_t> ptr_buf;
		driver_bridge::read_memory(vtable_addr + static_cast<uint64_t>(i) * 8, 8, ptr_buf);
		if (ptr_buf.size() < 8) break;

		uint64_t func_addr = 0;
		std::memcpy(&func_addr, ptr_buf.data(), 8);

		if (func_addr == 0) break;

		uint64_t top16 = func_addr >> 48;
		if (top16 != 0x0000 && top16 != 0x7FFF) break;

		struct_recon::vtable_entry_t entry;
		entry.func_addr = func_addr;
		entry.index = i;

		for (auto& m : modules) {
			if (func_addr >= m.base && func_addr < m.base + m.size) {
				char nbuf[128];
				std::snprintf(nbuf, sizeof(nbuf), "%s+0x%llX",
				              m.name.c_str(),
				              static_cast<unsigned long long>(func_addr - m.base));
				entry.name = nbuf;
				break;
			}
		}

		if (entry.name.empty()) {
			char nbuf[32];
			std::snprintf(nbuf, sizeof(nbuf), "vfunc_%d", i);
			entry.name = nbuf;
		}

		entries.push_back(entry);
	}
}

}
