#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "memory_scanner.hpp"
#include "standalone_driver.hpp"
#include "../anti-tamper/state.hpp"
#include "../helpers/diag_log.hpp"
#include "../infra/executor.hpp"
#include "scanner_task_center.hpp"
#include "../mcp/downstream_producer_governor.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <map>
#include <sstream>
#include <iomanip>
#include <limits>
#include <type_traits>

namespace memory_scanner {


std::vector<uint8_t> parse_value(const std::string& text, value_type_t type, bool hex) {
	std::vector<uint8_t> out;
	if (text.empty()) return out;

	auto push_le = [&](const void* src, size_t n) {
		const auto* p = static_cast<const uint8_t*>(src);
		out.assign(p, p + n);
	};

	switch (type) {
		case value_type_t::byte_val: {
			uint8_t v = static_cast<uint8_t>(strtoul(text.c_str(), nullptr, hex ? 16 : 10));
			push_le(&v, 1);
			break;
		}
		case value_type_t::int16_val: {
			auto v = static_cast<int16_t>(strtol(text.c_str(), nullptr, hex ? 16 : 10));
			push_le(&v, 2);
			break;
		}
		case value_type_t::int32_val: {
			auto v = static_cast<int32_t>(strtol(text.c_str(), nullptr, hex ? 16 : 10));
			push_le(&v, 4);
			break;
		}
		case value_type_t::int64_val: {
			auto v = static_cast<int64_t>(strtoll(text.c_str(), nullptr, hex ? 16 : 10));
			push_le(&v, 8);
			break;
		}
		case value_type_t::float_val: {
			float v = strtof(text.c_str(), nullptr);
			push_le(&v, 4);
			break;
		}
		case value_type_t::double_val: {
			double v = strtod(text.c_str(), nullptr);
			push_le(&v, 8);
			break;
		}
		case value_type_t::string_ascii: {
			out.assign(text.begin(), text.end());
			break;
		}
		case value_type_t::string_utf16: {
			int len = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
			if (len > 0) {
				std::vector<wchar_t> ws(len);
				MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, ws.data(), len);
				size_t byte_len = (static_cast<size_t>(len) - 1) * sizeof(wchar_t);
				const auto* p = reinterpret_cast<const uint8_t*>(ws.data());
				out.assign(p, p + byte_len);
			}
			break;
		}
		case value_type_t::byte_array: {
			std::istringstream iss(text);
			std::string token;
			while (iss >> token) {
				if (token == "??" || token == "?") {
					out.push_back(0);
				} else {
					out.push_back(static_cast<uint8_t>(strtoul(token.c_str(), nullptr, 16)));
				}
			}
			break;
		}
		default:
			break;
	}
	return out;
}

std::string format_value(const std::vector<uint8_t>& bytes, value_type_t type) {
	if (bytes.empty()) return "";
	char buf[64];

	switch (type) {
		case value_type_t::byte_val:
			if (bytes.size() >= 1) {
				snprintf(buf, sizeof(buf), "%u", bytes[0]);
				return buf;
			}
			break;
		case value_type_t::int16_val:
			if (bytes.size() >= 2) {
				int16_t v;
				std::memcpy(&v, bytes.data(), 2);
				snprintf(buf, sizeof(buf), "%d", static_cast<int>(v));
				return buf;
			}
			break;
		case value_type_t::int32_val:
			if (bytes.size() >= 4) {
				int32_t v;
				std::memcpy(&v, bytes.data(), 4);
				snprintf(buf, sizeof(buf), "%d", v);
				return buf;
			}
			break;
		case value_type_t::int64_val:
			if (bytes.size() >= 8) {
				int64_t v;
				std::memcpy(&v, bytes.data(), 8);
				snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v));
				return buf;
			}
			break;
		case value_type_t::float_val:
			if (bytes.size() >= 4) {
				float v;
				std::memcpy(&v, bytes.data(), 4);
				snprintf(buf, sizeof(buf), "%.6g", static_cast<double>(v));
				return buf;
			}
			break;
		case value_type_t::double_val:
			if (bytes.size() >= 8) {
				double v;
				std::memcpy(&v, bytes.data(), 8);
				snprintf(buf, sizeof(buf), "%.10g", v);
				return buf;
			}
			break;
		case value_type_t::string_ascii:
			return std::string(bytes.begin(), bytes.end());
		case value_type_t::string_utf16: {
			if (bytes.size() >= 2) {
				int len = WideCharToMultiByte(CP_UTF8, 0,
					reinterpret_cast<const wchar_t*>(bytes.data()),
					static_cast<int>(bytes.size() / sizeof(wchar_t)),
					nullptr, 0, nullptr, nullptr);
				if (len > 0) {
					std::string s(len, '\0');
					WideCharToMultiByte(CP_UTF8, 0,
						reinterpret_cast<const wchar_t*>(bytes.data()),
						static_cast<int>(bytes.size() / sizeof(wchar_t)),
						s.data(), len, nullptr, nullptr);
					return s;
				}
			}
			break;
		}
		case value_type_t::byte_array: {
			std::ostringstream oss;
			for (size_t i = 0; i < bytes.size(); ++i) {
				if (i > 0) oss << ' ';
				oss << std::uppercase << std::hex << std::setfill('0') << std::setw(2)
					<< static_cast<unsigned>(bytes[i]);
			}
			return oss.str();
		}
		default:
			break;
	}
	return "";
}


static bool compare_exact(const uint8_t* mem, const uint8_t* target, size_t sz) {
	return std::memcmp(mem, target, sz) == 0;
}

template <typename T>
static bool compare_bigger(const uint8_t* mem, const uint8_t* target) {
	T a, b;
	std::memcpy(&a, mem, sizeof(T));
	std::memcpy(&b, target, sizeof(T));
	if constexpr (std::is_floating_point_v<T>) {
		if (!(a == a) || !(b == b)) return false;
	}
	return a > b;
}

template <typename T>
static bool compare_smaller(const uint8_t* mem, const uint8_t* target) {
	T a, b;
	std::memcpy(&a, mem, sizeof(T));
	std::memcpy(&b, target, sizeof(T));
	if constexpr (std::is_floating_point_v<T>) {
		if (!(a == a) || !(b == b)) return false;
	}
	return a < b;
}

template <typename T>
static bool compare_between(const uint8_t* mem, const uint8_t* lo, const uint8_t* hi) {
	T v, l, h;
	std::memcpy(&v, mem, sizeof(T));
	std::memcpy(&l, lo, sizeof(T));
	std::memcpy(&h, hi, sizeof(T));
	if constexpr (std::is_floating_point_v<T>) {
		if (!(v == v) || !(l == l) || !(h == h)) return false;
	}
	return v >= l && v <= h;
}

template <typename T>
static bool compare_changed(const uint8_t* cur, const uint8_t* prev) {
	return std::memcmp(cur, prev, sizeof(T)) != 0;
}

template <typename T>
static bool compare_increased(const uint8_t* cur, const uint8_t* prev) {
	T a, b;
	std::memcpy(&a, cur, sizeof(T));
	std::memcpy(&b, prev, sizeof(T));
	if constexpr (std::is_floating_point_v<T>) {
		if (!(a == a) || !(b == b)) return false;
	}
	return a > b;
}

template <typename T>
static bool compare_decreased(const uint8_t* cur, const uint8_t* prev) {
	T a, b;
	std::memcpy(&a, cur, sizeof(T));
	std::memcpy(&b, prev, sizeof(T));
	if constexpr (std::is_floating_point_v<T>) {
		if (!(a == a) || !(b == b)) return false;
	}
	return a < b;
}


static void annotate_modules(std::vector<scan_result_t>& results) {
	auto modules = driver_bridge::enumerate_modules();
	for (auto& r : results) {
		for (const auto& m : modules) {
			if (r.address >= m.base && r.address < m.base + m.size) {
				r.module_name = m.name;
				r.module_offset = r.address - m.base;
				break;
			}
		}
	}
}


static void first_scan_thread(scan_config_t config) {
	auto& st = g_state;
	st.scan_progress.store(0.f);

	auto t_start = std::chrono::steady_clock::now();
	auto regions = driver_bridge::enumerate_memory_regions(4096);
	diag::log_tagged_fmt("mem_scanner", "first_scan_thread enter pid=%u regions=%zu val_type=%s mode=%s writable_only=%d exec_exclude=%d hex=%d align=%zu range=0x%llX+0x%llX",
		driver_bridge::attached_pid(), regions.size(),
		value_type_name(config.value_type), scan_mode_name(config.scan_mode),
		static_cast<int>(config.writable_only), static_cast<int>(config.executable_exclude),
		static_cast<int>(config.hex_input), config.alignment,
		static_cast<unsigned long long>(config.range_base),
		static_cast<unsigned long long>(config.range_size));

	std::vector<driver_bridge::memory_region_t> scan_regions;
	const bool has_range = config.range_base != 0 && config.range_size != 0;
	const uint64_t range_start = config.range_base;
	const uint64_t max_u64 = std::numeric_limits<uint64_t>::max();
	const uint64_t range_end = has_range
		? (max_u64 - config.range_base < config.range_size ? max_u64 : config.range_base + config.range_size)
		: 0;
	size_t skipped_state = 0;
	size_t skipped_guard = 0;
	size_t skipped_protect = 0;
	size_t skipped_writable = 0;
	size_t skipped_exec = 0;
	size_t skipped_type = 0;
	size_t skipped_range = 0;
	for (const auto& r : regions) {
		if (r.state != 0x1000) { ++skipped_state; continue; }
		if (r.protect & 0x100) { ++skipped_guard; continue; }
		uint32_t base_prot = r.protect & 0xFF;
		if (base_prot == 0x01 || base_prot == 0x00) { ++skipped_protect; continue; }
		if (config.writable_only && !(base_prot & 0xCC)) { ++skipped_writable; continue; }
		if (config.executable_exclude && (base_prot & 0xF0)) { ++skipped_exec; continue; }
		if (r.type == 0x40000) { ++skipped_type; continue; }
		if (has_range) {
			const uint64_t region_start = r.base;
			const uint64_t region_end = max_u64 - r.base < r.size ? max_u64 : r.base + r.size;
			const uint64_t clipped_start = std::max(region_start, range_start);
			const uint64_t clipped_end = std::min(region_end, range_end);
			if (clipped_start >= clipped_end) { ++skipped_range; continue; }
			auto clipped = r;
			clipped.base = clipped_start;
			clipped.size = clipped_end - clipped_start;
			scan_regions.push_back(clipped);
		} else {
			scan_regions.push_back(r);
		}
	}
	diag::log_tagged_fmt("mem_scanner",
		"first_scan_thread region_filter raw=%zu eligible=%zu skipped_state=%zu skipped_guard=%zu skipped_protect=%zu skipped_writable=%zu skipped_exec=%zu skipped_type=%zu skipped_range=%zu",
		regions.size(),
		scan_regions.size(),
		skipped_state,
		skipped_guard,
		skipped_protect,
		skipped_writable,
		skipped_exec,
		skipped_type,
		skipped_range);

	if (scan_regions.empty()) {
		diag::log_tagged_fmt("mem_scanner", "first_scan_thread no_eligible_regions raw=%zu filtered=0", regions.size());
		st.scan_progress.store(1.f);
		st.scanning.store(false);
		return;
	}

	size_t val_sz = value_type_size(config.value_type);
	std::vector<uint8_t> target_val = parse_value(config.value_text, config.value_type, config.hex_input);
	std::vector<uint8_t> target_val2;
	if (config.scan_mode == scan_mode_t::value_between)
		target_val2 = parse_value(config.value_text2, config.value_type, config.hex_input);

	bool is_string = (config.value_type == value_type_t::string_ascii ||
					  config.value_type == value_type_t::string_utf16);
	bool is_bytearray = (config.value_type == value_type_t::byte_array);
	bool is_unknown = (config.scan_mode == scan_mode_t::unknown_initial);

	if (is_string || is_bytearray)
		val_sz = target_val.size();

	if (is_unknown && val_sz == 0)
		val_sz = (config.value_type == value_type_t::string_utf16) ? 2 : 1;

	size_t align = config.alignment;
	if (is_string || is_bytearray) align = 1;
	if (align == 0) align = 1;

	if (!is_unknown && (val_sz == 0 || target_val.size() < val_sz)) {
		diag::log_tagged_fmt("mem_scanner", "first_scan_thread invalid_target_val val_sz=%zu got=%zu text='%s'",
			val_sz, target_val.size(), config.value_text.c_str());
		st.scanning.store(false);
		st.scan_progress.store(1.f);
		return;
	}
	if (config.scan_mode == scan_mode_t::value_between && target_val2.size() < val_sz) {
		diag::log_tagged_fmt("mem_scanner", "first_scan_thread invalid_value2 val_sz=%zu got=%zu text2='%s'",
			val_sz, target_val2.size(), config.value_text2.c_str());
		st.scanning.store(false);
		st.scan_progress.store(1.f);
		return;
	}

	std::vector<scan_result_t> all_results;
	std::mutex results_mtx;
	std::atomic<size_t> read_failures{0};
	std::atomic<size_t> read_successes{0};
	std::atomic<size_t> matched_regions{0};

	size_t total_bytes = 0;
	for (const auto& r : scan_regions) total_bytes += r.size;
	std::atomic<size_t> bytes_done{0};

	auto scan_region = [&](const driver_bridge::memory_region_t& region) {
		std::vector<uint8_t> buf;
		if (!driver_bridge::read_memory(region.base, static_cast<size_t>(region.size), buf)) {
			size_t failures = read_failures.fetch_add(1, std::memory_order_acq_rel) + 1;
			if (failures <= 16 || (failures % 256) == 0) {
				diag::log_tagged_fmt("mem_scanner",
					"first_scan_thread read_failed base=0x%llX size=0x%llX failures=%zu",
					static_cast<unsigned long long>(region.base),
					static_cast<unsigned long long>(region.size),
					failures);
			}
			return;
		}
		read_successes.fetch_add(1, std::memory_order_acq_rel);

		std::vector<scan_result_t> local;
		local.reserve(256);

		size_t end = buf.size();
		if (!is_unknown && val_sz > 0 && end >= val_sz)
			end = end - val_sz + 1;

		for (size_t i = 0; i < end; i += align) {
			if ((i & 0xFFFF) == 0 && !st.scanning.load()) break;
			bool match = false;

			if (is_unknown) {
				match = true;
			} else if (config.scan_mode == scan_mode_t::exact) {
				match = compare_exact(buf.data() + i, target_val.data(), val_sz);
			} else if (config.scan_mode == scan_mode_t::value_between && !target_val2.empty()) {
				switch (config.value_type) {
					case value_type_t::byte_val:    match = compare_between<uint8_t>(buf.data()+i, target_val.data(), target_val2.data()); break;
					case value_type_t::int16_val:   match = compare_between<int16_t>(buf.data()+i, target_val.data(), target_val2.data()); break;
					case value_type_t::int32_val:   match = compare_between<int32_t>(buf.data()+i, target_val.data(), target_val2.data()); break;
					case value_type_t::int64_val:   match = compare_between<int64_t>(buf.data()+i, target_val.data(), target_val2.data()); break;
					case value_type_t::float_val:   match = compare_between<float>(buf.data()+i, target_val.data(), target_val2.data()); break;
					case value_type_t::double_val:  match = compare_between<double>(buf.data()+i, target_val.data(), target_val2.data()); break;
					default: break;
				}
			} else {
				switch (config.scan_mode) {
					case scan_mode_t::bigger_than:
						switch (config.value_type) {
							case value_type_t::byte_val:    match = compare_bigger<uint8_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::int16_val:   match = compare_bigger<int16_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::int32_val:   match = compare_bigger<int32_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::int64_val:   match = compare_bigger<int64_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::float_val:   match = compare_bigger<float>(buf.data()+i, target_val.data()); break;
							case value_type_t::double_val:  match = compare_bigger<double>(buf.data()+i, target_val.data()); break;
							default: break;
						}
						break;
					case scan_mode_t::smaller_than:
						switch (config.value_type) {
							case value_type_t::byte_val:    match = compare_smaller<uint8_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::int16_val:   match = compare_smaller<int16_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::int32_val:   match = compare_smaller<int32_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::int64_val:   match = compare_smaller<int64_t>(buf.data()+i, target_val.data()); break;
							case value_type_t::float_val:   match = compare_smaller<float>(buf.data()+i, target_val.data()); break;
							case value_type_t::double_val:  match = compare_smaller<double>(buf.data()+i, target_val.data()); break;
							default: break;
						}
						break;
					default: break;
				}
			}

			if (match) {
				scan_result_t res;
				res.address = region.base + i;
				size_t copy_sz = val_sz;
				if (i + copy_sz <= buf.size())
					res.current_value.assign(buf.data() + i, buf.data() + i + copy_sz);
				local.push_back(std::move(res));

				if (local.size() >= 2000000) break;
			}
		}

		if (!local.empty()) {
			size_t matched = matched_regions.fetch_add(1, std::memory_order_acq_rel) + 1;
			if (matched <= 16) {
				diag::log_tagged_fmt("mem_scanner",
					"first_scan_thread matched_region base=0x%llX size=0x%llX local_hits=%zu",
					static_cast<unsigned long long>(region.base),
					static_cast<unsigned long long>(region.size),
					local.size());
			}
			std::lock_guard<std::mutex> lk(results_mtx);
			all_results.insert(all_results.end(),
				std::make_move_iterator(local.begin()),
				std::make_move_iterator(local.end()));
		}
		bytes_done.fetch_add(static_cast<size_t>(region.size));
		if (total_bytes > 0)
			st.scan_progress.store(static_cast<float>(bytes_done.load()) / static_cast<float>(total_bytes));
	};


	const bool full_test_running = anti_tamper::state::get().full_test_running.load(std::memory_order_acquire);
	const std::size_t scanner_wg_size = mcp_standalone::downstream::governor_t::instance().quotas().scanner_worker_group_size;
	const int worker_count = full_test_running ? 0 : static_cast<int>(scanner_wg_size);
	if (full_test_running) {
		diag::log_tagged_fmt("mem_scanner",
			"first_scan_thread full_test_inline_workers regions=%zu bytes=%zu",
			scan_regions.size(),
			total_bytes);
	}
	mcp_standalone::downstream::producer_identity_t scan_id;
	scan_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	scan_id.tool_name = "first_scan";
	mcp_standalone::downstream::scoped_admission_t scan_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(scan_id);
	if (!scan_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(scan_id);
		diag::log_tagged_fmt("mem_scanner",
			"FEATURE-WORKER-GROUP-REJECT first_scan reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		st.scan_progress.store(1.f);
		st.scanning.store(false);
		return;
	}
	diag::log_tagged_fmt("mem_scanner",
		"FEATURE-WORKER-GROUP-ADMIT first_scan token=%llu worker_group_size=%zu",
		static_cast<unsigned long long>(scan_admission.token()), scanner_wg_size);
	std::atomic<size_t> next_region{0};
	std::vector<aida::infra::win_thread::joinable_thread_t> workers;
	const int actual_workers = static_cast<int>((std::min<size_t>)(static_cast<size_t>(worker_count), scan_regions.size()));
	try {
		workers.reserve(static_cast<size_t>(actual_workers));
		for (int w = 0; w < actual_workers; ++w) {
			aida::infra::win_thread::joinable_thread_t t;
			std::string err;
			char tname[32];
			_snprintf_s(tname, sizeof(tname), _TRUNCATE, "mem_scan.fs.%d", w);
			if (t.start([&]() {
				for (;;) {
					size_t idx = next_region.fetch_add(1);
					if (idx >= scan_regions.size()) break;
					if (!st.scanning.load()) break;
					try {
						scan_region(scan_regions[idx]);
					} catch (...) {
						read_failures.fetch_add(1, std::memory_order_acq_rel);
					}
				}
			}, &err, aida::infra::win_thread::default_stack_reserve, tname))
				workers.push_back(std::move(t));
			else
				diag::log_tagged_fmt("mem_scanner", "first_scan_thread worker_start_failed w=%d err='%s'", w, err.c_str());
		}
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("mem_scanner", "first_scan_thread local_worker_create_failed err='%s'", ex.what());
	} catch (...) {
		diag::log_tagged("mem_scanner", "first_scan_thread local_worker_create_failed err='<unknown>'");
	}
	if (workers.empty()) {
		for (size_t idx = 0; idx < scan_regions.size(); ++idx) {
			if (!st.scanning.load()) break;
			scan_region(scan_regions[idx]);
		}
	} else {
		for (auto& worker : workers) {
			if (worker.joinable())
				worker.join();
		}
	}
	diag::log_tagged_fmt("mem_scanner",
		"FEATURE-WORKER-GROUP-RELEASE first_scan token=%llu reason=completed",
		static_cast<unsigned long long>(scan_admission.token()));
	scan_admission.release("completed");


	std::sort(all_results.begin(), all_results.end(),
		[](const scan_result_t& a, const scan_result_t& b) { return a.address < b.address; });


	constexpr size_t MAX_RESULTS = 5000000;
	size_t total = all_results.size();
	if (all_results.size() > MAX_RESULTS) {
		diag::log_tagged_fmt("mem_scanner", "first_scan_thread result_truncated raw=%zu kept=%zu",
			total, static_cast<size_t>(MAX_RESULTS));
		all_results.resize(MAX_RESULTS);
	}

	annotate_modules(all_results);

	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		st.results = std::move(all_results);
		st.total_found = total;
		st.has_initial_scan = true;
		st.scan_count = 1;
	}

	auto t_end = std::chrono::steady_clock::now();
	uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
	diag::log_tagged_fmt("mem_scanner", "first_scan_thread done regions=%zu bytes=%zu hits=%zu duration_ms=%llu read_ok=%zu read_failed=%zu matched_regions=%zu",
		scan_regions.size(),
		total_bytes,
		total,
		static_cast<unsigned long long>(dur_ms),
		read_successes.load(std::memory_order_acquire),
		read_failures.load(std::memory_order_acquire),
		matched_regions.load(std::memory_order_acquire));

	st.scan_progress.store(1.f);
	st.scanning.store(false);
}


static void next_scan_thread(scan_mode_t mode, std::string value_text, std::string value_text2) {
	auto& st = g_state;
	st.scan_progress.store(0.f);
	auto t_start = std::chrono::steady_clock::now();

	std::vector<scan_result_t> prev;
	value_type_t vtype;
	bool hex_input;
	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		prev = st.results;
		vtype = st.config.value_type;
		hex_input = st.config.hex_input;
	}

	diag::log_tagged_fmt("mem_scanner", "next_scan_thread enter mode=%s prev_count=%zu val='%s' val2='%s' vtype=%s",
		scan_mode_name(mode), prev.size(), value_text.c_str(), value_text2.c_str(), value_type_name(vtype));

	if (prev.empty()) {
		diag::log_tagged("mem_scanner", "next_scan_thread no_prev_results");
		st.scan_progress.store(1.f);
		st.scanning.store(false);
		return;
	}

	size_t val_sz = value_type_size(vtype);
	std::vector<uint8_t> target_val;
	std::vector<uint8_t> target_val2_bytes;

	bool needs_value = (mode == scan_mode_t::exact || mode == scan_mode_t::bigger_than ||
						mode == scan_mode_t::smaller_than || mode == scan_mode_t::value_between);
	if (needs_value)
		target_val = parse_value(value_text, vtype, hex_input);
	if (mode == scan_mode_t::value_between)
		target_val2_bytes = parse_value(value_text2, vtype, hex_input);

	bool is_varlen = (vtype == value_type_t::string_ascii ||
					  vtype == value_type_t::string_utf16 ||
					  vtype == value_type_t::byte_array);
	if (is_varlen) {
		if (needs_value && !target_val.empty())
			val_sz = target_val.size();
		else if (!prev.empty() && !prev[0].current_value.empty())
			val_sz = prev[0].current_value.size();
	}

	if (val_sz == 0) {
		diag::log_tagged("mem_scanner", "next_scan_thread val_sz_zero");
		st.scanning.store(false);
		st.scan_progress.store(1.f);
		return;
	}
	if (needs_value && target_val.size() < val_sz) {
		diag::log_tagged_fmt("mem_scanner", "next_scan_thread invalid_value val_sz=%zu got=%zu",
			val_sz, target_val.size());
		st.scanning.store(false);
		st.scan_progress.store(1.f);
		return;
	}
	if (mode == scan_mode_t::value_between && target_val2_bytes.size() < val_sz) {
		diag::log_tagged_fmt("mem_scanner", "next_scan_thread invalid_value2 val_sz=%zu got=%zu",
			val_sz, target_val2_bytes.size());
		st.scanning.store(false);
		st.scan_progress.store(1.f);
		return;
	}

	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		st.scan_history.push_back(prev);
		if (st.scan_history.size() > 10)
			st.scan_history.erase(st.scan_history.begin());
	}

	std::vector<scan_result_t> new_results;
	new_results.reserve(prev.size());

	for (size_t i = 0; i < prev.size(); ++i) {
		if (!st.scanning.load()) break;

		auto& pr = prev[i];
		std::vector<uint8_t> cur_bytes;
		if (!driver_bridge::read_memory(pr.address, val_sz, cur_bytes))
			continue;
		if (cur_bytes.size() < val_sz)
			continue;

		bool match = false;
		switch (mode) {
			case scan_mode_t::exact:
				if (target_val.size() >= val_sz)
					match = compare_exact(cur_bytes.data(), target_val.data(), val_sz);
				break;
			case scan_mode_t::bigger_than:
				if (target_val.size() >= val_sz) {
					switch (vtype) {
						case value_type_t::byte_val:    match = compare_bigger<uint8_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::int16_val:   match = compare_bigger<int16_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::int32_val:   match = compare_bigger<int32_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::int64_val:   match = compare_bigger<int64_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::float_val:   match = compare_bigger<float>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::double_val:  match = compare_bigger<double>(cur_bytes.data(), target_val.data()); break;
						default: break;
					}
				}
				break;
			case scan_mode_t::smaller_than:
				if (target_val.size() >= val_sz) {
					switch (vtype) {
						case value_type_t::byte_val:    match = compare_smaller<uint8_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::int16_val:   match = compare_smaller<int16_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::int32_val:   match = compare_smaller<int32_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::int64_val:   match = compare_smaller<int64_t>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::float_val:   match = compare_smaller<float>(cur_bytes.data(), target_val.data()); break;
						case value_type_t::double_val:  match = compare_smaller<double>(cur_bytes.data(), target_val.data()); break;
						default: break;
					}
				}
				break;
			case scan_mode_t::value_between:
				if (target_val.size() >= val_sz && target_val2_bytes.size() >= val_sz) {
					switch (vtype) {
						case value_type_t::byte_val:    match = compare_between<uint8_t>(cur_bytes.data(), target_val.data(), target_val2_bytes.data()); break;
						case value_type_t::int16_val:   match = compare_between<int16_t>(cur_bytes.data(), target_val.data(), target_val2_bytes.data()); break;
						case value_type_t::int32_val:   match = compare_between<int32_t>(cur_bytes.data(), target_val.data(), target_val2_bytes.data()); break;
						case value_type_t::int64_val:   match = compare_between<int64_t>(cur_bytes.data(), target_val.data(), target_val2_bytes.data()); break;
						case value_type_t::float_val:   match = compare_between<float>(cur_bytes.data(), target_val.data(), target_val2_bytes.data()); break;
						case value_type_t::double_val:  match = compare_between<double>(cur_bytes.data(), target_val.data(), target_val2_bytes.data()); break;
						default: break;
					}
				}
				break;
			case scan_mode_t::changed:
				if (pr.current_value.size() >= val_sz) {
					switch (vtype) {
						case value_type_t::byte_val:    match = compare_changed<uint8_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int16_val:   match = compare_changed<int16_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int32_val:   match = compare_changed<int32_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int64_val:   match = compare_changed<int64_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::float_val:   match = compare_changed<float>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::double_val:  match = compare_changed<double>(cur_bytes.data(), pr.current_value.data()); break;
						default: match = !compare_exact(cur_bytes.data(), pr.current_value.data(), val_sz); break;
					}
				}
				break;
			case scan_mode_t::unchanged:
				if (pr.current_value.size() >= val_sz)
					match = compare_exact(cur_bytes.data(), pr.current_value.data(), val_sz);
				break;
			case scan_mode_t::increased:
				if (pr.current_value.size() >= val_sz) {
					switch (vtype) {
						case value_type_t::byte_val:    match = compare_increased<uint8_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int16_val:   match = compare_increased<int16_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int32_val:   match = compare_increased<int32_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int64_val:   match = compare_increased<int64_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::float_val:   match = compare_increased<float>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::double_val:  match = compare_increased<double>(cur_bytes.data(), pr.current_value.data()); break;
						default: break;
					}
				}
				break;
			case scan_mode_t::decreased:
				if (pr.current_value.size() >= val_sz) {
					switch (vtype) {
						case value_type_t::byte_val:    match = compare_decreased<uint8_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int16_val:   match = compare_decreased<int16_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int32_val:   match = compare_decreased<int32_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::int64_val:   match = compare_decreased<int64_t>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::float_val:   match = compare_decreased<float>(cur_bytes.data(), pr.current_value.data()); break;
						case value_type_t::double_val:  match = compare_decreased<double>(cur_bytes.data(), pr.current_value.data()); break;
						default: break;
					}
				}
				break;
			default: break;
		}

		if (match) {
			scan_result_t res;
			res.address = pr.address;
			res.current_value = std::move(cur_bytes);
			res.previous_value = pr.current_value;
			res.module_name = pr.module_name;
			res.module_offset = pr.module_offset;
			new_results.push_back(std::move(res));
		}

		if ((i % 1024) == 0)
			st.scan_progress.store(static_cast<float>(i) / static_cast<float>(prev.size()));
	}

	size_t hits = new_results.size();
	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		st.total_found = hits;
		st.results = std::move(new_results);
		st.scan_count++;
	}

	auto t_end = std::chrono::steady_clock::now();
	uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
	diag::log_tagged_fmt("mem_scanner", "next_scan_thread done prev=%zu hits=%zu duration_ms=%llu scan_count=%d",
		prev.size(), hits, static_cast<unsigned long long>(dur_ms), g_state.scan_count);

	st.scan_progress.store(1.f);
	st.scanning.store(false);
}


static bool wait_scan_worker_ready(const char* op) {
	auto& st = g_state;
	const ULONGLONG start = GetTickCount64();
	for (;;) {
		if (st.scan_thread_done.load(std::memory_order_acquire))
			return true;
		if (!st.scanning.load(std::memory_order_acquire)) {
			st.scan_thread_done.store(true, std::memory_order_release);
			diag::log_tagged_fmt("mem_scanner",
				"%s recovered stale scan_thread_done=0 scanning=0 elapsed_ms=%llu",
				op ? op : "scan",
				static_cast<unsigned long long>(GetTickCount64() - start));
			return true;
		}
		if (GetTickCount64() - start >= 5000) {
			diag::log_tagged_fmt("mem_scanner",
				"%s refused previous_worker_busy elapsed_ms=%llu progress=%.3f",
				op ? op : "scan",
				static_cast<unsigned long long>(GetTickCount64() - start),
				static_cast<double>(st.scan_progress.load(std::memory_order_acquire)));
			return false;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

static bool should_run_first_scan_inline(const scan_config_t& config)
{
	constexpr uint64_t kMaxInlineRange = 16ull * 1024ull * 1024ull;
	return config.range_base != 0 && config.range_size != 0 && config.range_size <= kMaxInlineRange;
}

static bool should_run_next_scan_inline()
{
	std::lock_guard<std::mutex> lk(g_state.results_mutex);
	return g_state.results.size() <= 250000;
}

static bool should_run_pointer_scan_inline(uint64_t scan_base, uint64_t scan_size, int max_depth)
{
	constexpr uint64_t kMaxInlineRange = 16ull * 1024ull * 1024ull;
	return scan_base != 0 && scan_size != 0 && scan_size <= kMaxInlineRange && max_depth <= 3;
}


static void freeze_loop() {
	auto& st = g_state;
	diag::log_tagged("mem_scanner", "freeze_loop start");
	std::vector<std::pair<uint64_t, std::vector<uint8_t>>> snapshot;
	uint64_t last_logged_count = static_cast<uint64_t>(-1);
	auto last_log_time = std::chrono::steady_clock::now();
	while (st.freeze_active.load()) {
		snapshot.clear();
		{
			std::lock_guard<std::mutex> lk(st.address_mutex);
			for (auto& entry : st.address_list) {
				if (entry.frozen && !entry.freeze_value.empty())
					snapshot.emplace_back(entry.address, entry.freeze_value);
			}
		}
		auto now = std::chrono::steady_clock::now();
		uint64_t count = snapshot.size();
		bool count_changed = (count != last_logged_count);
		bool throttle_elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_log_time).count() >= 30;
		if (count_changed || (count > 0 && throttle_elapsed)) {
			diag::log_tagged_fmt("mem_scanner", "freeze_loop tick count=%llu",
				static_cast<unsigned long long>(count));
			last_logged_count = count;
			last_log_time = now;
		}
		for (auto& p : snapshot) {
			if (!st.freeze_active.load()) break;
			driver_bridge::write_memory(p.first, p.second);
		}
		if (!snapshot.empty()) Sleep(10);
		else Sleep(100);
	}
	diag::log_tagged("mem_scanner", "freeze_loop stop");
}


struct pointer_entry_t {
	uint64_t address = 0;
	uint64_t value = 0;
	bool     is_static = false;
	std::string module_name;
	uint64_t module_offset = 0;
};

static bool address_in_modules(uint64_t addr,
                               const std::vector<driver_bridge::module_info_t>& modules,
                               std::string& out_name, uint64_t& out_offset) {
	for (const auto& m : modules) {
		if (addr >= m.base && addr < m.base + m.size) {
			out_name = m.name;
			out_offset = addr - m.base;
			return true;
		}
	}
	return false;
}

static void pointer_dfs(const std::multimap<uint64_t, pointer_entry_t>& reverse_map,
                        uint64_t value_to_find,
                        int level,
                        int max_depth,
                        int64_t max_offset,
                        std::vector<int64_t>& current_offsets,
                        std::vector<uint64_t>& visited,
                        std::vector<pointer_result_t>& results,
                        std::mutex& results_mutex,
                        const std::atomic<bool>& cancel,
                        size_t max_results) {
	if (cancel.load()) return;
	if (level >= max_depth) return;

	{
		std::lock_guard<std::mutex> lk(results_mutex);
		if (results.size() >= max_results) return;
	}

	for (auto v : visited) {
		if (v == value_to_find) return;
	}
	visited.push_back(value_to_find);

	uint64_t lo = (value_to_find > static_cast<uint64_t>(max_offset))
	              ? (value_to_find - static_cast<uint64_t>(max_offset)) : 0;
	uint64_t hi = value_to_find + static_cast<uint64_t>(max_offset);

	auto it_low = reverse_map.lower_bound(lo);
	auto it_high = reverse_map.upper_bound(hi);

	for (auto it = it_low; it != it_high; ++it) {
		if (cancel.load()) break;

		uint64_t pointer_value = it->first;
		int64_t offset = static_cast<int64_t>(value_to_find) - static_cast<int64_t>(pointer_value);
		if (offset < -max_offset || offset > max_offset) continue;

		const pointer_entry_t& pe = it->second;

		{
			std::lock_guard<std::mutex> lk(results_mutex);
			if (results.size() >= max_results) {
				visited.pop_back();
				return;
			}
		}

		current_offsets.push_back(offset);

		if (pe.is_static) {
			pointer_result_t chain;
			chain.base_address = pe.address;
			chain.module_name = pe.module_name;
			chain.module_offset = pe.module_offset;
			chain.offsets.assign(current_offsets.rbegin(), current_offsets.rend());

			std::lock_guard<std::mutex> lk(results_mutex);
			if (results.size() < max_results)
				results.push_back(std::move(chain));
		}

		if (level + 1 < max_depth) {
			pointer_dfs(reverse_map, pe.address, level + 1, max_depth, max_offset,
			            current_offsets, visited, results, results_mutex, cancel, max_results);
		}

		current_offsets.pop_back();
	}

	visited.pop_back();
}

static void pointer_scan_thread(uint64_t target_address, int max_depth, int max_offset, uint64_t scan_base, uint64_t scan_size) {
	auto& st = g_state;
	st.pointer_progress.store(0.f);
	auto t_start = std::chrono::steady_clock::now();

	auto modules = driver_bridge::enumerate_modules();
	auto regions = driver_bridge::enumerate_memory_regions(4096);

	diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread enter target=0x%llX max_depth=%d max_offset=0x%X scan_range=0x%llX+0x%llX modules=%zu regions=%zu",
		static_cast<unsigned long long>(target_address), max_depth, max_offset,
		static_cast<unsigned long long>(scan_base),
		static_cast<unsigned long long>(scan_size),
		modules.size(), regions.size());

	if (max_depth < 1) max_depth = 4;
	if (max_depth > 7) max_depth = 7;
	if (max_offset < 0) max_offset = 0x1000;
	if (max_offset > 0x10000) max_offset = 0x10000;

	const bool has_scan_range = scan_base != 0 && scan_size != 0;
	const uint64_t max_u64 = (std::numeric_limits<uint64_t>::max)();
	const uint64_t scan_end = has_scan_range
		? (max_u64 - scan_base < scan_size ? max_u64 : scan_base + scan_size)
		: 0;
	size_t skipped_state = 0;
	size_t skipped_guard = 0;
	size_t skipped_protect = 0;
	size_t skipped_size = 0;
	size_t skipped_range = 0;
	std::vector<driver_bridge::memory_region_t> scan_regions;
	for (const auto& r : regions) {
		if (r.state != 0x1000) { ++skipped_state; continue; }
		if (r.protect & 0x100) { ++skipped_guard; continue; }
		uint32_t protect_flags = r.protect & 0xFF;
		if (protect_flags == 0x01 || protect_flags == 0x00) { ++skipped_protect; continue; }
		if (r.size > 0x10000000) { ++skipped_size; continue; }
		driver_bridge::memory_region_t selected = r;
		if (has_scan_range) {
			const uint64_t region_end = max_u64 - r.base < r.size ? max_u64 : r.base + r.size;
			const uint64_t clipped_start = (std::max)(r.base, scan_base);
			const uint64_t clipped_end = (std::min)(region_end, scan_end);
			if (clipped_start >= clipped_end) { ++skipped_range; continue; }
			selected.base = clipped_start;
			selected.size = clipped_end - clipped_start;
		}
		scan_regions.push_back(selected);
	}
	diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread region_filter raw=%zu selected=%zu skipped_state=%zu skipped_guard=%zu skipped_protect=%zu skipped_size=%zu skipped_range=%zu",
		regions.size(),
		scan_regions.size(),
		skipped_state,
		skipped_guard,
		skipped_protect,
		skipped_size,
		skipped_range);

	const std::size_t ptr_wg_size = mcp_standalone::downstream::governor_t::instance().quotas().scanner_worker_group_size;
	const int ptr_worker_count = static_cast<int>(ptr_wg_size);
	std::vector<std::multimap<uint64_t, pointer_entry_t>> partial_maps(static_cast<size_t>(ptr_worker_count));
	std::atomic<size_t> region_idx{0};
	std::atomic<uint64_t> bytes_scanned{0};
	uint64_t total_bytes = 0;
	for (const auto& r : scan_regions) total_bytes += r.size;
	if (total_bytes == 0) total_bytes = 1;

	auto scan_pointer_worker = [&](int w) {
			auto& local_map = partial_maps[static_cast<size_t>(w)];
			size_t idx;
			while ((idx = region_idx.fetch_add(1)) < scan_regions.size()) {
				if (!st.pointer_scanning.load()) break;

				const auto& region = scan_regions[idx];
				const size_t chunk_size = 65536;
				for (uint64_t off = 0; off < region.size; off += chunk_size) {
					if (!st.pointer_scanning.load()) break;
					size_t read_sz = chunk_size;
					if (off + read_sz > region.size)
						read_sz = static_cast<size_t>(region.size - off);

					std::vector<uint8_t> buf;
					if (!driver_bridge::read_memory(region.base + off, read_sz, buf)) {
						bytes_scanned.fetch_add(read_sz);
						st.pointer_progress.store(
							static_cast<float>(bytes_scanned.load()) / static_cast<float>(total_bytes) * 0.5f);
						continue;
					}

					for (size_t i = 0; i + 8 <= buf.size(); i += 8) {
						uint64_t value = 0;
						std::memcpy(&value, buf.data() + i, 8);
						if (value < 0x10000 || value > 0x00007FFFFFFFFFFFULL) continue;

						bool valid = false;
						for (const auto& r2 : scan_regions) {
							if (value >= r2.base && value < r2.base + r2.size) {
								valid = true;
								break;
							}
						}
						if (!valid) {
							const uint64_t lo = (target_address > static_cast<uint64_t>(max_offset))
								? (target_address - static_cast<uint64_t>(max_offset)) : 0;
							const uint64_t hi = max_u64 - target_address < static_cast<uint64_t>(max_offset)
								? max_u64 : target_address + static_cast<uint64_t>(max_offset);
							valid = value >= lo && value <= hi;
						}
						if (!valid) continue;

						pointer_entry_t pe;
						pe.address = region.base + off + i;
						pe.value = value;
						pe.is_static = address_in_modules(pe.address, modules, pe.module_name, pe.module_offset);
						local_map.emplace(value, std::move(pe));
					}

					bytes_scanned.fetch_add(read_sz);
				st.pointer_progress.store(
					static_cast<float>(bytes_scanned.load()) / static_cast<float>(total_bytes) * 0.5f);
			}
		}
	};
	mcp_standalone::downstream::producer_identity_t ptr_id;
	ptr_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	ptr_id.tool_name = "pointer_scan_map";
	mcp_standalone::downstream::scoped_admission_t ptr_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(ptr_id);
	if (!ptr_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(ptr_id);
		diag::log_tagged_fmt("pointer_scan",
			"FEATURE-WORKER-GROUP-REJECT pointer_scan_map reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		st.pointer_progress.store(1.f);
		st.pointer_scanning.store(false);
		return;
	}
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-ADMIT pointer_scan_map token=%llu worker_group_size=%zu",
		static_cast<unsigned long long>(ptr_admission.token()), ptr_wg_size);
	std::vector<aida::infra::win_thread::joinable_thread_t> ptr_workers;
	try {
		ptr_workers.reserve(static_cast<size_t>(ptr_worker_count));
		for (int w = 0; w < ptr_worker_count; ++w) {
			aida::infra::win_thread::joinable_thread_t t;
			std::string err;
			char tname[32];
			_snprintf_s(tname, sizeof(tname), _TRUNCATE, "ptr_scan.map.%d", w);
			if (t.start([&scan_pointer_worker, w]() { scan_pointer_worker(w); }, &err, aida::infra::win_thread::default_stack_reserve, tname))
				ptr_workers.push_back(std::move(t));
			else
				diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread map_worker_start_failed w=%d err='%s'", w, err.c_str());
		}
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread map_worker_create_failed err='%s'", ex.what());
	} catch (...) {
		diag::log_tagged("pointer_scan", "pointer_scan_thread map_worker_create_failed err='<unknown>'");
	}
	if (ptr_workers.empty()) {
		for (int w = 0; w < ptr_worker_count; ++w)
			scan_pointer_worker(w);
	} else {
		for (auto& worker : ptr_workers) {
			if (worker.joinable())
				worker.join();
		}
	}
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-RELEASE pointer_scan_map token=%llu reason=completed",
		static_cast<unsigned long long>(ptr_admission.token()));
	ptr_admission.release("completed");

	if (!st.pointer_scanning.load()) {
		st.pointer_progress.store(1.f);
		return;
	}

	std::multimap<uint64_t, pointer_entry_t> reverse_map;
	for (auto& pm : partial_maps) {
		for (auto& kv : pm)
			reverse_map.emplace(kv.first, std::move(kv.second));
		pm.clear();
	}

	st.pointer_progress.store(0.5f);

	std::vector<pointer_result_t> results;
	std::mutex result_mtx;
	constexpr size_t MAX_RESULTS = 10000;

	std::vector<uint64_t> seed_values;
	{
		uint64_t lo = (target_address > static_cast<uint64_t>(max_offset))
		              ? (target_address - static_cast<uint64_t>(max_offset)) : 0;
		uint64_t hi = target_address + static_cast<uint64_t>(max_offset);
		auto it_low = reverse_map.lower_bound(lo);
		auto it_high = reverse_map.upper_bound(hi);
		std::vector<uint64_t> uniq;
		for (auto it = it_low; it != it_high; ++it) {
			if (uniq.empty() || uniq.back() != it->first)
				uniq.push_back(it->first);
		}
		seed_values = std::move(uniq);
	}

	if (seed_values.empty()) {
		diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread no_seeds map_entries=%zu",
			reverse_map.size());
		std::lock_guard<std::mutex> lk(st.pointer_mutex);
		st.pointer_results.clear();
		st.pointer_progress.store(1.f);
		st.pointer_scanning.store(false);
		return;
	}

	diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread map_built entries=%zu seeds=%zu",
		reverse_map.size(), seed_values.size());

	std::atomic<size_t> seed_idx{0};
	std::atomic<bool> dfs_cancel{false};

	auto dfs_worker = [&]() {
			std::vector<int64_t> current_offsets;
			std::vector<uint64_t> visited;
			visited.push_back(target_address);
			while (true) {
				size_t idx = seed_idx.fetch_add(1);
				if (idx >= seed_values.size()) break;
				if (!st.pointer_scanning.load()) {
					dfs_cancel.store(true);
					break;
				}

				{
					std::lock_guard<std::mutex> lk(result_mtx);
					if (results.size() >= MAX_RESULTS) {
						dfs_cancel.store(true);
						break;
					}
				}

				uint64_t seed_val = seed_values[idx];
				int64_t offset = static_cast<int64_t>(target_address) - static_cast<int64_t>(seed_val);
				if (offset < -max_offset || offset > max_offset) continue;

				auto range = reverse_map.equal_range(seed_val);
				for (auto it = range.first; it != range.second; ++it) {
					if (!st.pointer_scanning.load() || dfs_cancel.load()) break;
					{
						std::lock_guard<std::mutex> lk(result_mtx);
						if (results.size() >= MAX_RESULTS) {
							dfs_cancel.store(true);
							break;
						}
					}

					const pointer_entry_t& pe = it->second;
					current_offsets.clear();
					current_offsets.push_back(offset);

					{
						pointer_result_t chain;
						chain.base_address = pe.address;
						chain.module_name = pe.module_name;
						chain.module_offset = pe.module_offset;
						chain.offsets.assign(current_offsets.rbegin(), current_offsets.rend());
						std::lock_guard<std::mutex> lk(result_mtx);
						if (results.size() < MAX_RESULTS)
							results.push_back(std::move(chain));
					}

					if (max_depth > 1) {
						pointer_dfs(reverse_map, pe.address, 1, max_depth, max_offset,
						            current_offsets, visited, results, result_mtx,
						            dfs_cancel, MAX_RESULTS);
					}
				}

			st.pointer_progress.store(
				0.5f + (static_cast<float>(idx + 1) / static_cast<float>(seed_values.size())) * 0.5f);
		}
	};
	mcp_standalone::downstream::producer_identity_t dfs_id;
	dfs_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	dfs_id.tool_name = "pointer_scan_dfs";
	mcp_standalone::downstream::scoped_admission_t dfs_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(dfs_id);
	if (!dfs_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(dfs_id);
		diag::log_tagged_fmt("pointer_scan",
			"FEATURE-WORKER-GROUP-REJECT pointer_scan_dfs reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		st.pointer_progress.store(1.f);
		st.pointer_scanning.store(false);
		return;
	}
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-ADMIT pointer_scan_dfs token=%llu worker_group_size=%zu",
		static_cast<unsigned long long>(dfs_admission.token()), ptr_wg_size);
	std::vector<aida::infra::win_thread::joinable_thread_t> dfs_workers;
	try {
		dfs_workers.reserve(static_cast<size_t>(ptr_worker_count));
		for (int w = 0; w < ptr_worker_count; ++w) {
			aida::infra::win_thread::joinable_thread_t t;
			std::string err;
			char tname[32];
			_snprintf_s(tname, sizeof(tname), _TRUNCATE, "ptr_scan.dfs.%d", w);
			if (t.start(dfs_worker, &err, aida::infra::win_thread::default_stack_reserve, tname))
				dfs_workers.push_back(std::move(t));
			else
				diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread dfs_worker_start_failed w=%d err='%s'", w, err.c_str());
		}
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread dfs_worker_create_failed err='%s'", ex.what());
	} catch (...) {
		diag::log_tagged("pointer_scan", "pointer_scan_thread dfs_worker_create_failed err='<unknown>'");
	}
	if (dfs_workers.empty()) {
		dfs_worker();
	} else {
		for (auto& worker : dfs_workers) {
			if (worker.joinable())
				worker.join();
		}
	}
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-RELEASE pointer_scan_dfs token=%llu reason=completed",
		static_cast<unsigned long long>(dfs_admission.token()));
	dfs_admission.release("completed");

	std::sort(results.begin(), results.end(),
		[](const pointer_result_t& a, const pointer_result_t& b) {
			if (!a.module_name.empty() && b.module_name.empty()) return true;
			if (a.module_name.empty() && !b.module_name.empty()) return false;
			if (a.offsets.size() != b.offsets.size())
				return a.offsets.size() < b.offsets.size();
			return a.base_address < b.base_address;
		});

	if (results.size() > MAX_RESULTS)
		results.resize(MAX_RESULTS);

	size_t final_count = results.size();
	{
		std::lock_guard<std::mutex> lk(st.pointer_mutex);
		st.pointer_results = std::move(results);
	}

	auto t_end = std::chrono::steady_clock::now();
	uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
	diag::log_tagged_fmt("pointer_scan", "pointer_scan_thread done chains=%zu duration_ms=%llu cancelled=%d",
		final_count, static_cast<unsigned long long>(dur_ms),
		static_cast<int>(!st.pointer_scanning.load()));

	st.pointer_progress.store(1.f);
	st.pointer_scanning.store(false);
}


void initialize() {
	auto& st = g_state;
	st.scanning.store(false);
	st.pointer_scanning.store(false);
	for (int i = 0; i < 100 && !st.scan_thread_done.load(std::memory_order_acquire); ++i)
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	for (int i = 0; i < 100 && !st.pointer_thread_done.load(std::memory_order_acquire); ++i)
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		size_t had = st.results.size();
		st.results.clear();
		st.scan_history.clear();
		st.total_found = 0;
		st.has_initial_scan = false;
		st.scan_count = 0;
		diag::log_tagged_fmt("mem_scanner", "initialize reset_results cleared=%zu", had);
	}
	{
		std::lock_guard<std::mutex> lk(st.pointer_mutex);
		st.pointer_results.clear();
	}
	if (st.freeze_active.load(std::memory_order_acquire) &&
		!st.freeze_thread_done.load(std::memory_order_acquire)) {
		diag::log_tagged("mem_scanner", "initialize freeze_loop_already_running");
		return;
	}
	st.freeze_active.store(true);
	st.freeze_thread_done.store(false, std::memory_order_release);
	diag::log_tagged("mem_scanner", "initialize posting_freeze_loop");
	mcp_standalone::downstream::producer_identity_t freeze_id;
	freeze_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	freeze_id.tool_name = "freeze_loop";
	mcp_standalone::downstream::scoped_admission_t freeze_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(freeze_id);
	if (!freeze_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(freeze_id);
		diag::log_tagged_fmt("mem_scanner",
			"FEATURE-WORKER-GROUP-REJECT freeze_loop reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		st.freeze_thread_done.store(true, std::memory_order_release);
		return;
	}
	diag::log_tagged_fmt("mem_scanner",
		"FEATURE-WORKER-GROUP-ADMIT freeze_loop token=%llu",
		static_cast<unsigned long long>(freeze_admission.token()));
	aida::infra::executor::submission_t freeze_sub;
	freeze_sub.owner_subsystem = "scanner";
	freeze_sub.label = "scanner.freeze_loop";
	freeze_sub.thread_class = "scanner_freeze_loop";
	freeze_sub.domain = aida::infra::executor::domain_t::long_running;
	freeze_sub.priority = 2;
	freeze_sub.target_pid = driver_bridge::attached_pid();
	freeze_sub.lease_token = freeze_admission.token();
	freeze_sub.body = []() {
			freeze_loop();
			g_state.freeze_thread_done.store(true, std::memory_order_release);
		};
	if (!aida::infra::executor::submit(std::move(freeze_sub)).submitted)
	{
		diag::log_tagged("mem_scanner", "initialize freeze_loop_post_failed");
		st.freeze_thread_done.store(true, std::memory_order_release);
	}
	diag::log_tagged_fmt("mem_scanner",
		"FEATURE-WORKER-GROUP-RELEASE freeze_loop token=%llu reason=dispatched",
		static_cast<unsigned long long>(freeze_admission.token()));
	freeze_admission.release("dispatched");
}

void shutdown() {
	diag::log_tagged("mem_scanner", "shutdown enter");
	auto& st = g_state;
	st.scanning.store(false);
	st.pointer_scanning.store(false);
	st.freeze_active.store(false);
	for (int i = 0; i < 100 && (st.scanning.load() || st.pointer_scanning.load()); ++i)
		Sleep(20);
	while (!st.scan_thread_done.load(std::memory_order_acquire))
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	while (!st.pointer_thread_done.load(std::memory_order_acquire))
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	while (!st.freeze_thread_done.load(std::memory_order_acquire))
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	diag::log_tagged("mem_scanner", "shutdown done");
}

bool first_scan(const scan_config_t& config) {
	auto& st = g_state;
	if (st.scanning.load()) {
		diag::log_tagged("mem_scanner", "first_scan refused already_scanning");
		return false;
	}
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("mem_scanner", "first_scan refused not_attached driver_loaded=%d pid=%u",
			static_cast<int>(driver_bridge::is_loaded()), driver_bridge::attached_pid());
		return false;
	}
	diag::log_tagged_fmt("mem_scanner", "first_scan start type=%s mode=%s val='%s' val2='%s' hex=%d",
		value_type_name(config.value_type), scan_mode_name(config.scan_mode),
		config.value_text.c_str(), config.value_text2.c_str(),
		static_cast<int>(config.hex_input));

	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		st.results.clear();
		st.scan_history.clear();
		st.total_found = 0;
		st.has_initial_scan = false;
		st.scan_count = 0;
		st.config = config;
	}

	if (!wait_scan_worker_ready("first_scan"))
		return false;

	st.scanning.store(true);
	st.scan_thread_done.store(false, std::memory_order_release);
	if (should_run_first_scan_inline(config)) {
		diag::log_tagged_fmt("mem_scanner",
			"first_scan inline_dispatch pid=%u range=0x%llX+0x%llX",
			driver_bridge::attached_pid(),
			static_cast<unsigned long long>(config.range_base),
			static_cast<unsigned long long>(config.range_size));
		try {
			first_scan_thread(config);
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("mem_scanner", "first_scan inline exception err='%s'", ex.what());
			st.scanning.store(false, std::memory_order_release);
			st.scan_progress.store(1.f, std::memory_order_release);
		} catch (...) {
			diag::log_tagged("mem_scanner", "first_scan inline exception err='<unknown>'");
			st.scanning.store(false, std::memory_order_release);
			st.scan_progress.store(1.f, std::memory_order_release);
		}
		st.scan_thread_done.store(true, std::memory_order_release);
		return true;
	}
	try {
		mcp_standalone::downstream::producer_identity_t fs_id;
		fs_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
		fs_id.tool_name = "first_scan_dispatch";
		mcp_standalone::downstream::scoped_admission_t fs_admission =
			mcp_standalone::downstream::scoped_admission_t::acquire(fs_id);
		if (!fs_admission.active()) {
			auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(fs_id);
			diag::log_tagged_fmt("mem_scanner",
				"FEATURE-WORKER-GROUP-REJECT first_scan_dispatch reason=%s quota=%s observed=%zu limit=%zu",
				rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
			st.scan_thread_done.store(true, std::memory_order_release);
			st.scanning.store(false);
			return false;
		}
		diag::log_tagged_fmt("mem_scanner",
			"FEATURE-WORKER-GROUP-ADMIT first_scan_dispatch token=%llu",
			static_cast<unsigned long long>(fs_admission.token()));
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "scanner";
		sub.label = "scanner.memory_first_scan";
		sub.thread_class = "scanner_scan";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 3;
		sub.target_pid = driver_bridge::attached_pid();
		sub.lease_token = fs_admission.token();
		sub.body = [config]() {
			try {
				first_scan_thread(config);
			} catch (const std::exception& ex) {
				diag::log_tagged_fmt("mem_scanner", "first_scan worker exception err='%s'", ex.what());
				g_state.scanning.store(false, std::memory_order_release);
				g_state.scan_progress.store(1.f, std::memory_order_release);
			} catch (...) {
				diag::log_tagged("mem_scanner", "first_scan worker exception err='<unknown>'");
				g_state.scanning.store(false, std::memory_order_release);
				g_state.scan_progress.store(1.f, std::memory_order_release);
			}
			g_state.scan_thread_done.store(true, std::memory_order_release);
		};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			diag::log_tagged("mem_scanner", "first_scan worker_post_failed");
			st.scan_thread_done.store(true, std::memory_order_release);
			st.scanning.store(false);
			return false;
		}
		scanner_task_center::register_executor_task(submitted,
			"view.memory.scanner", "memory.first_scan", "Initial memory scan",
			driver_bridge::attached_pid(), true, []() {
				g_state.scanning.store(false, std::memory_order_release);
				return true;
			});
		diag::log_tagged_fmt("mem_scanner",
			"FEATURE-WORKER-GROUP-RELEASE first_scan_dispatch token=%llu reason=dispatched",
			static_cast<unsigned long long>(fs_admission.token()));
		fs_admission.release("dispatched");
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("mem_scanner", "first_scan worker_create_failed err='%s'", ex.what());
		st.scan_thread_done.store(true, std::memory_order_release);
		st.scanning.store(false);
		return false;
	} catch (...) {
		diag::log_tagged("mem_scanner", "first_scan worker_create_failed err='<unknown>'");
		st.scan_thread_done.store(true, std::memory_order_release);
		st.scanning.store(false);
		return false;
	}
	return true;
}

bool next_scan(scan_mode_t mode, const std::string& value_text, const std::string& value_text2) {
	auto& st = g_state;
	if (st.scanning.load()) {
		diag::log_tagged("mem_scanner", "next_scan refused already_scanning");
		return false;
	}
	if (!st.has_initial_scan) {
		diag::log_tagged("mem_scanner", "next_scan refused no_initial_scan");
		return false;
	}
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("mem_scanner", "next_scan refused not_attached driver_loaded=%d pid=%u",
			static_cast<int>(driver_bridge::is_loaded()), driver_bridge::attached_pid());
		return false;
	}
	diag::log_tagged_fmt("mem_scanner", "next_scan start mode=%s val='%s' val2='%s'",
		scan_mode_name(mode), value_text.c_str(), value_text2.c_str());

	if (!wait_scan_worker_ready("next_scan"))
		return false;

	st.scanning.store(true);
	st.scan_thread_done.store(false, std::memory_order_release);
	if (should_run_next_scan_inline()) {
		diag::log_tagged_fmt("mem_scanner",
			"next_scan inline_dispatch mode=%s",
			scan_mode_name(mode));
		try {
			next_scan_thread(mode, value_text, value_text2);
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("mem_scanner", "next_scan inline exception err='%s'", ex.what());
			st.scanning.store(false, std::memory_order_release);
			st.scan_progress.store(1.f, std::memory_order_release);
		} catch (...) {
			diag::log_tagged("mem_scanner", "next_scan inline exception err='<unknown>'");
			st.scanning.store(false, std::memory_order_release);
			st.scan_progress.store(1.f, std::memory_order_release);
		}
		st.scan_thread_done.store(true, std::memory_order_release);
		return true;
	}
	try {
		mcp_standalone::downstream::producer_identity_t ns_id;
		ns_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
		ns_id.tool_name = "next_scan_dispatch";
		mcp_standalone::downstream::scoped_admission_t ns_admission =
			mcp_standalone::downstream::scoped_admission_t::acquire(ns_id);
		if (!ns_admission.active()) {
			auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(ns_id);
			diag::log_tagged_fmt("mem_scanner",
				"FEATURE-WORKER-GROUP-REJECT next_scan_dispatch reason=%s quota=%s observed=%zu limit=%zu",
				rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
			st.scan_thread_done.store(true, std::memory_order_release);
			st.scanning.store(false);
			return false;
		}
		diag::log_tagged_fmt("mem_scanner",
			"FEATURE-WORKER-GROUP-ADMIT next_scan_dispatch token=%llu",
			static_cast<unsigned long long>(ns_admission.token()));
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "scanner";
		sub.label = "scanner.memory_next_scan";
		sub.thread_class = "scanner_scan";
		sub.domain = aida::infra::executor::domain_t::feature_worker;
		sub.priority = 3;
		sub.target_pid = driver_bridge::attached_pid();
		sub.lease_token = ns_admission.token();
		sub.body = [mode, value_text, value_text2]() {
			try {
				next_scan_thread(mode, value_text, value_text2);
			} catch (const std::exception& ex) {
				diag::log_tagged_fmt("mem_scanner", "next_scan worker exception err='%s'", ex.what());
				g_state.scanning.store(false, std::memory_order_release);
				g_state.scan_progress.store(1.f, std::memory_order_release);
			} catch (...) {
				diag::log_tagged("mem_scanner", "next_scan worker exception err='<unknown>'");
				g_state.scanning.store(false, std::memory_order_release);
				g_state.scan_progress.store(1.f, std::memory_order_release);
			}
			g_state.scan_thread_done.store(true, std::memory_order_release);
		};
		const auto submitted = aida::infra::executor::submit(std::move(sub));
		if (!submitted.submitted) {
			diag::log_tagged("mem_scanner", "next_scan worker_post_failed");
			st.scan_thread_done.store(true, std::memory_order_release);
			st.scanning.store(false);
			return false;
		}
		scanner_task_center::register_executor_task(submitted,
			"view.memory.scanner", "memory.next_scan", "Refine memory scan",
			driver_bridge::attached_pid(), true, []() {
				g_state.scanning.store(false, std::memory_order_release);
				return true;
			});
		diag::log_tagged_fmt("mem_scanner",
			"FEATURE-WORKER-GROUP-RELEASE next_scan_dispatch token=%llu reason=dispatched",
			static_cast<unsigned long long>(ns_admission.token()));
		ns_admission.release("dispatched");
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("mem_scanner", "next_scan worker_create_failed err='%s'", ex.what());
		st.scan_thread_done.store(true, std::memory_order_release);
		st.scanning.store(false);
		return false;
	} catch (...) {
		diag::log_tagged("mem_scanner", "next_scan worker_create_failed err='<unknown>'");
		st.scan_thread_done.store(true, std::memory_order_release);
		st.scanning.store(false);
		return false;
	}
	return true;
}

void undo_scan() {
	auto& st = g_state;
	if (st.scanning.load()) {
		diag::log_tagged("mem_scanner", "undo_scan refused scanning_in_progress");
		return;
	}
	std::lock_guard<std::mutex> lk(st.results_mutex);
	if (st.scan_history.empty()) {
		diag::log_tagged("mem_scanner", "undo_scan refused history_empty");
		return;
	}
	st.results = std::move(st.scan_history.back());
	st.scan_history.pop_back();
	st.total_found = st.results.size();
	if (st.scan_count > 0) st.scan_count--;
	if (st.scan_count == 0) st.has_initial_scan = false;
	diag::log_tagged_fmt("mem_scanner", "undo_scan restored=%zu scan_count=%d",
		st.total_found, st.scan_count);
}

void reset_scan() {
	auto& st = g_state;
	if (st.scanning.load()) {
		diag::log_tagged_fmt("mem_scanner",
			"reset_scan cancelling active scan progress=%.3f",
			static_cast<double>(st.scan_progress.load(std::memory_order_acquire)));
		st.scanning.store(false, std::memory_order_release);
		if (!wait_scan_worker_ready("reset_scan")) {
			diag::log_tagged("mem_scanner", "reset_scan refused worker_still_busy");
			return;
		}
	} else if (!st.scan_thread_done.load(std::memory_order_acquire)) {
		st.scan_thread_done.store(true, std::memory_order_release);
		diag::log_tagged("mem_scanner", "reset_scan recovered stale scan_thread_done=0");
	}
	std::lock_guard<std::mutex> lk(st.results_mutex);
	size_t had = st.results.size();
	st.results.clear();
	st.scan_history.clear();
	st.total_found = 0;
	st.has_initial_scan = false;
	st.scan_count = 0;
	st.scan_progress.store(1.f, std::memory_order_release);
	diag::log_tagged_fmt("mem_scanner", "reset_scan cleared=%zu", had);
}

void add_address(uint64_t address, const std::string& description, value_type_t type) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.address_mutex);
	for (const auto& e : st.address_list) {
		if (e.address == address) {
			diag::log_tagged_fmt("mem_scanner", "add_address skipped_duplicate addr=0x%llX",
				static_cast<unsigned long long>(address));
			return;
		}
	}
	address_entry_t entry;
	entry.address = address;
	entry.description = description;
	entry.value_type = type;
	st.address_list.push_back(std::move(entry));
	diag::log_tagged_fmt("mem_scanner", "add_address addr=0x%llX type=%s desc='%s' total=%zu",
		static_cast<unsigned long long>(address), value_type_name(type),
		description.c_str(), st.address_list.size());
}

void remove_address(size_t index) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.address_mutex);
	if (index < st.address_list.size()) {
		uint64_t addr = st.address_list[index].address;
		st.address_list.erase(st.address_list.begin() + static_cast<ptrdiff_t>(index));
		diag::log_tagged_fmt("mem_scanner", "remove_address index=%zu addr=0x%llX remaining=%zu",
			index, static_cast<unsigned long long>(addr), st.address_list.size());
	} else {
		diag::log_tagged_fmt("mem_scanner", "remove_address out_of_range index=%zu size=%zu",
			index, st.address_list.size());
	}
}

void freeze_address(size_t index, bool enable) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.address_mutex);
	if (index < st.address_list.size()) {
		auto& e = st.address_list[index];
		e.frozen = enable;
		if (enable && !e.last_value.empty())
			e.freeze_value = e.last_value;
		diag::log_tagged_fmt("mem_scanner", "freeze_address addr=0x%llX enable=%d has_value=%d",
			static_cast<unsigned long long>(e.address), static_cast<int>(enable),
			static_cast<int>(!e.freeze_value.empty()));
	} else {
		diag::log_tagged_fmt("mem_scanner", "freeze_address out_of_range index=%zu size=%zu",
			index, st.address_list.size());
	}
}

void write_value(uint64_t address, value_type_t type, const std::string& value_text, bool hex) {
	auto bytes = parse_value(value_text, type, hex);
	if (bytes.empty()) {
		diag::log_tagged_fmt("mem_scanner", "write_value parse_failed addr=0x%llX text='%s' hex=%d",
			static_cast<unsigned long long>(address), value_text.c_str(), static_cast<int>(hex));
		return;
	}
	bool ok = driver_bridge::write_memory(address, bytes);
	diag::log_tagged_fmt("mem_scanner", "write_value addr=0x%llX size=%zu type=%s ok=%d",
		static_cast<unsigned long long>(address), bytes.size(),
		value_type_name(type), static_cast<int>(ok));
}

std::string read_value_string(uint64_t address, value_type_t type) {
	size_t sz = value_type_size(type);
	if (type == value_type_t::string_ascii || type == value_type_t::string_utf16)
		sz = 256;
	std::vector<uint8_t> buf;
	if (!driver_bridge::read_memory(address, sz, buf)) return "<read error>";
	if (type == value_type_t::string_ascii) {
		auto it = std::find(buf.begin(), buf.end(), 0);
		if (it != buf.end()) buf.erase(it, buf.end());
	}
	return format_value(buf, type);
}

void refresh_address_list() {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.address_mutex);
	for (auto& entry : st.address_list) {
		size_t sz = value_type_size(entry.value_type);
		if (entry.value_type == value_type_t::string_ascii ||
			entry.value_type == value_type_t::string_utf16) sz = 256;
		std::vector<uint8_t> buf;
		if (driver_bridge::read_memory(entry.address, sz, buf)) {
			if (entry.value_type == value_type_t::string_ascii) {
				auto it = std::find(buf.begin(), buf.end(), 0);
				if (it != buf.end()) buf.erase(it, buf.end());
			}
			entry.last_value = std::move(buf);
		}
	}
}

bool start_pointer_scan(uint64_t target_address, int max_depth, int max_offset, uint64_t scan_base, uint64_t scan_size) {
	auto& st = g_state;
	if (st.pointer_scanning.load()) {
		diag::log_tagged("pointer_scan", "start_pointer_scan refused already_scanning");
		return false;
	}
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("pointer_scan", "start_pointer_scan refused not_attached driver_loaded=%d pid=%u",
			static_cast<int>(driver_bridge::is_loaded()), driver_bridge::attached_pid());
		return false;
	}
	diag::log_tagged_fmt("pointer_scan", "start_pointer_scan target=0x%llX depth=%d offset=0x%X scan_range=0x%llX+0x%llX",
		static_cast<unsigned long long>(target_address), max_depth, max_offset,
		static_cast<unsigned long long>(scan_base),
		static_cast<unsigned long long>(scan_size));
	st.pointer_scanning.store(true);
	{
		std::lock_guard<std::mutex> lk(st.pointer_mutex);
		st.pointer_results.clear();
	}
	while (!st.pointer_thread_done.load(std::memory_order_acquire))
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	st.pointer_thread_done.store(false, std::memory_order_release);
	if (should_run_pointer_scan_inline(scan_base, scan_size, max_depth)) {
		diag::log_tagged_fmt("pointer_scan",
			"start_pointer_scan inline_dispatch target=0x%llX range=0x%llX+0x%llX",
			static_cast<unsigned long long>(target_address),
			static_cast<unsigned long long>(scan_base),
			static_cast<unsigned long long>(scan_size));
		try {
			pointer_scan_thread(target_address, max_depth, max_offset, scan_base, scan_size);
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("pointer_scan", "inline worker_exception err='%s'", ex.what());
			st.pointer_progress.store(1.f, std::memory_order_release);
			st.pointer_scanning.store(false, std::memory_order_release);
		} catch (...) {
			diag::log_tagged("pointer_scan", "inline worker_exception err='<unknown>'");
			st.pointer_progress.store(1.f, std::memory_order_release);
			st.pointer_scanning.store(false, std::memory_order_release);
		}
		st.pointer_thread_done.store(true, std::memory_order_release);
		return true;
	}
	mcp_standalone::downstream::producer_identity_t ps_id;
	ps_id.kind = mcp_standalone::downstream::producer_kind_t::scanner;
	ps_id.tool_name = "pointer_scan_dispatch";
	mcp_standalone::downstream::scoped_admission_t ps_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(ps_id);
	if (!ps_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(ps_id);
		diag::log_tagged_fmt("pointer_scan",
			"FEATURE-WORKER-GROUP-REJECT pointer_scan_dispatch reason=%s quota=%s observed=%zu limit=%zu",
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		st.pointer_thread_done.store(true, std::memory_order_release);
		st.pointer_scanning.store(false);
		return false;
	}
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-ADMIT pointer_scan_dispatch token=%llu",
		static_cast<unsigned long long>(ps_admission.token()));
	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "scanner";
	sub.label = "scanner.pointer_scan";
	sub.thread_class = "scanner_pointer_scan";
	sub.domain = aida::infra::executor::domain_t::long_running;
	sub.priority = 2;
	sub.target_pid = driver_bridge::attached_pid();
	sub.lease_token = ps_admission.token();
	sub.body = [target_address, max_depth, max_offset, scan_base, scan_size]() {
			pointer_scan_thread(target_address, max_depth, max_offset, scan_base, scan_size);
			g_state.pointer_thread_done.store(true, std::memory_order_release);
		};
	const auto submitted = aida::infra::executor::submit(std::move(sub));
	if (!submitted.submitted)
	{
		diag::log_tagged("pointer_scan", "start_pointer_scan worker_post_failed");
		st.pointer_thread_done.store(true, std::memory_order_release);
		st.pointer_scanning.store(false);
		return false;
	}
	scanner_task_center::register_executor_task(submitted,
		"view.memory.pointer_scan", "memory.pointer_scan", "Pointer scan",
		driver_bridge::attached_pid(), true, []() {
			cancel_pointer_scan();
			return true;
		});
	diag::log_tagged_fmt("pointer_scan",
		"FEATURE-WORKER-GROUP-RELEASE pointer_scan_dispatch token=%llu reason=dispatched",
		static_cast<unsigned long long>(ps_admission.token()));
	ps_admission.release("dispatched");
	return true;
}

void cancel_pointer_scan() {
	diag::log_tagged("pointer_scan", "cancel_pointer_scan signalled");
	g_state.pointer_scanning.store(false);
}

}
