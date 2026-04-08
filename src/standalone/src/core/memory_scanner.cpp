#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "memory_scanner.hpp"
#include "standalone_driver.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <iomanip>

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
	return a > b;
}

template <typename T>
static bool compare_smaller(const uint8_t* mem, const uint8_t* target) {
	T a, b;
	std::memcpy(&a, mem, sizeof(T));
	std::memcpy(&b, target, sizeof(T));
	return a < b;
}

template <typename T>
static bool compare_between(const uint8_t* mem, const uint8_t* lo, const uint8_t* hi) {
	T v, l, h;
	std::memcpy(&v, mem, sizeof(T));
	std::memcpy(&l, lo, sizeof(T));
	std::memcpy(&h, hi, sizeof(T));
	return v >= l && v <= h;
}

template <typename T>
static bool compare_changed(const uint8_t* cur, const uint8_t* prev) {
	T a, b;
	std::memcpy(&a, cur, sizeof(T));
	std::memcpy(&b, prev, sizeof(T));
	return a != b;
}

template <typename T>
static bool compare_increased(const uint8_t* cur, const uint8_t* prev) {
	T a, b;
	std::memcpy(&a, cur, sizeof(T));
	std::memcpy(&b, prev, sizeof(T));
	return a > b;
}

template <typename T>
static bool compare_decreased(const uint8_t* cur, const uint8_t* prev) {
	T a, b;
	std::memcpy(&a, cur, sizeof(T));
	std::memcpy(&b, prev, sizeof(T));
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

	auto regions = driver_bridge::enumerate_memory_regions(4096);

	std::vector<driver_bridge::memory_region_t> scan_regions;
	for (const auto& r : regions) {
		if (r.state != 0x1000) continue;
		if (config.writable_only && !(r.protect & 0xCC)) continue;
		if (config.executable_exclude && (r.protect & 0xF0)) continue;
		if (r.type == 0x40000) continue;
		scan_regions.push_back(r);
	}

	if (scan_regions.empty()) {
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

	size_t align = config.alignment;
	if (is_string || is_bytearray) align = 1;
	if (align == 0) align = 1;

	std::vector<scan_result_t> all_results;
	std::mutex results_mtx;

	size_t total_bytes = 0;
	for (const auto& r : scan_regions) total_bytes += r.size;
	std::atomic<size_t> bytes_done{0};

	auto scan_region = [&](const driver_bridge::memory_region_t& region) {
		std::vector<uint8_t> buf;
		if (!driver_bridge::read_memory(region.base, static_cast<size_t>(region.size), buf))
			return;

		std::vector<scan_result_t> local;
		local.reserve(256);

		size_t end = buf.size();
		if (!is_unknown && val_sz > 0 && end >= val_sz)
			end = end - val_sz + 1;

		for (size_t i = 0; i < end; i += align) {
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

				if (local.size() >= 10000000) break;
			}
		}

		if (!local.empty()) {
			std::lock_guard<std::mutex> lk(results_mtx);
			all_results.insert(all_results.end(),
				std::make_move_iterator(local.begin()),
				std::make_move_iterator(local.end()));
		}
		bytes_done.fetch_add(static_cast<size_t>(region.size));
		if (total_bytes > 0)
			st.scan_progress.store(static_cast<float>(bytes_done.load()) / static_cast<float>(total_bytes));
	};


	constexpr int WORKER_COUNT = 4;
	std::vector<std::thread> workers;
	std::atomic<size_t> next_region{0};

	for (int w = 0; w < WORKER_COUNT; ++w) {
		workers.emplace_back([&]() {
			size_t idx;
			while ((idx = next_region.fetch_add(1)) < scan_regions.size()) {
				if (!st.scanning.load()) break;
				scan_region(scan_regions[idx]);
			}
		});
	}
	for (auto& wk : workers) wk.join();


	std::sort(all_results.begin(), all_results.end(),
		[](const scan_result_t& a, const scan_result_t& b) { return a.address < b.address; });


	constexpr size_t MAX_RESULTS = 5000000;
	size_t total = all_results.size();
	if (all_results.size() > MAX_RESULTS)
		all_results.resize(MAX_RESULTS);

	annotate_modules(all_results);

	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		st.results = std::move(all_results);
		st.total_found = total;
		st.has_initial_scan = true;
		st.scan_count = 1;
	}

	st.scan_progress.store(1.f);
	st.scanning.store(false);
}


static void next_scan_thread(scan_mode_t mode, std::string value_text, std::string value_text2) {
	auto& st = g_state;
	st.scan_progress.store(0.f);

	std::vector<scan_result_t> prev;
	value_type_t vtype;
	bool hex_input;
	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		prev = st.results;
		vtype = st.config.value_type;
		hex_input = st.config.hex_input;
	}

	if (prev.empty()) {
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

		bool match = false;
		switch (mode) {
			case scan_mode_t::exact:
				match = compare_exact(cur_bytes.data(), target_val.data(), val_sz);
				break;
			case scan_mode_t::bigger_than:
				switch (vtype) {
					case value_type_t::byte_val:    match = compare_bigger<uint8_t>(cur_bytes.data(), target_val.data()); break;
					case value_type_t::int16_val:   match = compare_bigger<int16_t>(cur_bytes.data(), target_val.data()); break;
					case value_type_t::int32_val:   match = compare_bigger<int32_t>(cur_bytes.data(), target_val.data()); break;
					case value_type_t::int64_val:   match = compare_bigger<int64_t>(cur_bytes.data(), target_val.data()); break;
					case value_type_t::float_val:   match = compare_bigger<float>(cur_bytes.data(), target_val.data()); break;
					case value_type_t::double_val:  match = compare_bigger<double>(cur_bytes.data(), target_val.data()); break;
					default: break;
				}
				break;
			case scan_mode_t::smaller_than:
				switch (vtype) {
					case value_type_t::byte_val:    match = compare_smaller<uint8_t>(cur_bytes.data(), target_val.data()); break;
					case value_type_t::int16_val:   match = compare_smaller<int16_t>(cur_bytes.data(), target_val.data()); break;
					case value_type_t::int32_val:   match = compare_smaller<int32_t>(cur_bytes.data(), target_val.data()); break;
					case value_type_t::int64_val:   match = compare_smaller<int64_t>(cur_bytes.data(), target_val.data()); break;
					case value_type_t::float_val:   match = compare_smaller<float>(cur_bytes.data(), target_val.data()); break;
					case value_type_t::double_val:  match = compare_smaller<double>(cur_bytes.data(), target_val.data()); break;
					default: break;
				}
				break;
			case scan_mode_t::value_between:
				if (!target_val2_bytes.empty()) {
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
				if (!pr.current_value.empty()) {
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
				if (!pr.current_value.empty())
					match = compare_exact(cur_bytes.data(), pr.current_value.data(), val_sz);
				break;
			case scan_mode_t::increased:
				if (!pr.current_value.empty()) {
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
				if (!pr.current_value.empty()) {
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

	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		st.total_found = new_results.size();
		st.results = std::move(new_results);
		st.scan_count++;
	}

	st.scan_progress.store(1.f);
	st.scanning.store(false);
}


static void freeze_loop() {
	auto& st = g_state;
	while (st.freeze_active.load()) {
		{
			std::lock_guard<std::mutex> lk(st.address_mutex);
			for (auto& entry : st.address_list) {
				if (entry.frozen && !entry.freeze_value.empty())
					driver_bridge::write_memory(entry.address, entry.freeze_value);
			}
		}
		Sleep(10);
	}
}


static void pointer_scan_thread(uint64_t target_address, int max_depth, int max_offset) {
	auto& st = g_state;
	st.pointer_progress.store(0.f);

	auto modules = driver_bridge::enumerate_modules();
	auto regions = driver_bridge::enumerate_memory_regions(4096);

	if (max_depth < 1) max_depth = 4;
	if (max_depth > 7) max_depth = 7;
	if (max_offset < 0) max_offset = 0x1000;
	if (max_offset > 0x10000) max_offset = 0x10000;

	std::vector<driver_bridge::memory_region_t> scan_regions;
	for (const auto& r : regions) {
		if (r.state != 0x1000) continue;
		if (r.size > 0x10000000) continue;
		scan_regions.push_back(r);
	}

	std::vector<pointer_result_t> results;
	std::mutex result_mtx;


	uint64_t search_lo = target_address > static_cast<uint64_t>(max_offset) ? target_address - max_offset : 0;
	uint64_t search_hi = target_address + max_offset;

	std::atomic<size_t> region_idx{0};
	constexpr int WORKERS = 4;
	std::vector<std::thread> workers;

	for (int w = 0; w < WORKERS; ++w) {
		workers.emplace_back([&]() {
			size_t idx;
			while ((idx = region_idx.fetch_add(1)) < scan_regions.size()) {
				if (!st.pointer_scanning.load()) break;

				auto& region = scan_regions[idx];
				std::vector<uint8_t> buf;
				if (!driver_bridge::read_memory(region.base, static_cast<size_t>(region.size), buf))
					continue;

				std::vector<pointer_result_t> local;
				for (size_t i = 0; i + 8 <= buf.size(); i += 8) {
					uint64_t ptr_val;
					std::memcpy(&ptr_val, buf.data() + i, 8);
					if (ptr_val >= search_lo && ptr_val <= search_hi) {
						int64_t off = static_cast<int64_t>(target_address) - static_cast<int64_t>(ptr_val);
						pointer_result_t pr;
						pr.base_address = region.base + i;
						pr.offsets.push_back(off);
						for (const auto& m : modules) {
							if (pr.base_address >= m.base && pr.base_address < m.base + m.size) {
								pr.module_name = m.name;
								pr.module_offset = pr.base_address - m.base;
								break;
							}
						}
						local.push_back(std::move(pr));
						if (local.size() >= 100000) break;
					}
				}
				if (!local.empty()) {
					std::lock_guard<std::mutex> lk(result_mtx);
					results.insert(results.end(),
						std::make_move_iterator(local.begin()),
						std::make_move_iterator(local.end()));
				}
				st.pointer_progress.store(static_cast<float>(idx) / static_cast<float>(scan_regions.size()));
			}
		});
	}
	for (auto& wk : workers) wk.join();

	std::sort(results.begin(), results.end(),
		[](const pointer_result_t& a, const pointer_result_t& b) {
			if (!a.module_name.empty() && b.module_name.empty()) return true;
			if (a.module_name.empty() && !b.module_name.empty()) return false;
			return a.base_address < b.base_address;
		});

	if (results.size() > 500000)
		results.resize(500000);

	{
		std::lock_guard<std::mutex> lk(st.pointer_mutex);
		st.pointer_results = std::move(results);
	}
	st.pointer_progress.store(1.f);
	st.pointer_scanning.store(false);
}


void initialize() {
	auto& st = g_state;
	st.freeze_active.store(true);
	st.freeze_thread = std::thread(freeze_loop);
}

void shutdown() {
	auto& st = g_state;
	st.scanning.store(false);
	st.pointer_scanning.store(false);
	st.freeze_active.store(false);
	if (st.scan_thread.joinable()) st.scan_thread.join();
	if (st.pointer_thread.joinable()) st.pointer_thread.join();
	if (st.freeze_thread.joinable()) st.freeze_thread.join();
}

bool first_scan(const scan_config_t& config) {
	auto& st = g_state;
	if (st.scanning.load()) return false;
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) return false;

	{
		std::lock_guard<std::mutex> lk(st.results_mutex);
		st.results.clear();
		st.scan_history.clear();
		st.total_found = 0;
		st.has_initial_scan = false;
		st.scan_count = 0;
		st.config = config;
	}

	st.scanning.store(true);
	if (st.scan_thread.joinable()) st.scan_thread.join();
	st.scan_thread = std::thread(first_scan_thread, config);
	return true;
}

bool next_scan(scan_mode_t mode, const std::string& value_text, const std::string& value_text2) {
	auto& st = g_state;
	if (st.scanning.load()) return false;
	if (!st.has_initial_scan) return false;

	st.scanning.store(true);
	if (st.scan_thread.joinable()) st.scan_thread.join();
	st.scan_thread = std::thread(next_scan_thread, mode, value_text, value_text2);
	return true;
}

void undo_scan() {
	auto& st = g_state;
	if (st.scanning.load()) return;
	std::lock_guard<std::mutex> lk(st.results_mutex);
	if (st.scan_history.empty()) return;
	st.results = std::move(st.scan_history.back());
	st.scan_history.pop_back();
	st.total_found = st.results.size();
	if (st.scan_count > 0) st.scan_count--;
}

void reset_scan() {
	auto& st = g_state;
	if (st.scanning.load()) return;
	std::lock_guard<std::mutex> lk(st.results_mutex);
	st.results.clear();
	st.scan_history.clear();
	st.total_found = 0;
	st.has_initial_scan = false;
	st.scan_count = 0;
}

void add_address(uint64_t address, const std::string& description, value_type_t type) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.address_mutex);
	for (const auto& e : st.address_list)
		if (e.address == address) return;
	address_entry_t entry;
	entry.address = address;
	entry.description = description;
	entry.value_type = type;
	st.address_list.push_back(std::move(entry));
}

void remove_address(size_t index) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.address_mutex);
	if (index < st.address_list.size())
		st.address_list.erase(st.address_list.begin() + static_cast<ptrdiff_t>(index));
}

void freeze_address(size_t index, bool enable) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.address_mutex);
	if (index < st.address_list.size()) {
		auto& e = st.address_list[index];
		e.frozen = enable;
		if (enable && !e.last_value.empty())
			e.freeze_value = e.last_value;
	}
}

void write_value(uint64_t address, value_type_t type, const std::string& value_text, bool hex) {
	auto bytes = parse_value(value_text, type, hex);
	if (!bytes.empty())
		driver_bridge::write_memory(address, bytes);
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

void start_pointer_scan(uint64_t target_address, int max_depth, int max_offset) {
	auto& st = g_state;
	if (st.pointer_scanning.load()) return;
	st.pointer_scanning.store(true);
	{
		std::lock_guard<std::mutex> lk(st.pointer_mutex);
		st.pointer_results.clear();
	}
	if (st.pointer_thread.joinable()) st.pointer_thread.join();
	st.pointer_thread = std::thread(pointer_scan_thread, target_address, max_depth, max_offset);
}

void cancel_pointer_scan() {
	g_state.pointer_scanning.store(false);
}

}
