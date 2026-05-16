#pragma once

#include <algorithm>
#include "work_queue.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"
#include "../helpers/diag_log.hpp"

#ifdef AIDA_STANDALONE
#include <Zydis/Zydis.h>
#endif

namespace aob_generator {

struct aob_byte_t {
	uint8_t value = 0;
	bool    wildcard = false;
};

struct signature_t {
	uint64_t             id = 0;
	std::string          name;
	uint64_t             address = 0;
	std::vector<aob_byte_t> bytes;
	bool                 unique = false;
	int                  uniqueness_count = 0;
	std::string          module_name;
	float                quality_score = 0.f;
};

struct state_t {
	std::vector<signature_t> saved_signatures;
	signature_t              current;
	std::mutex               mutex;
	std::atomic<bool>        generating{false};
	std::atomic<bool>        validating{false};
	std::atomic<bool>        batch_generating{false};
	std::atomic<int>         batch_total{0};
	std::atomic<int>         batch_done{0};
	char                     address_input[32] = {};
	char                     name_input[64] = {};
	int                      instruction_count = 16;
	bool                     auto_wildcard = true;
	bool                     validate_uniqueness = true;
};

inline state_t g_state;

inline std::atomic<uint64_t> g_next_signature_id{1};

inline uint64_t allocate_signature_id()
{
	return g_next_signature_id.fetch_add(1, std::memory_order_relaxed);
}

inline std::string format_signature(const signature_t& sig)
{
	std::string result;
	result.reserve(sig.bytes.size() * 3);
	for (size_t i = 0; i < sig.bytes.size(); ++i) {
		if (i > 0) result += ' ';
		if (sig.bytes[i].wildcard) {
			result += "??";
		} else {
			char buf[4];
			std::snprintf(buf, sizeof(buf), "%02X", sig.bytes[i].value);
			result += buf;
		}
	}
	return result;
}

inline std::string format_ida_signature(const signature_t& sig)
{
	std::string result;
	result.reserve(sig.bytes.size() * 4);
	for (size_t i = 0; i < sig.bytes.size(); ++i) {
		if (i > 0) result += ' ';
		if (sig.bytes[i].wildcard) {
			result += '?';
		} else {
			char buf[4];
			std::snprintf(buf, sizeof(buf), "%02X", sig.bytes[i].value);
			result += buf;
		}
	}
	return result;
}

inline std::string format_code_signature(const signature_t& sig)
{
	std::string pattern = "\"";
	std::string mask = "\"";
	for (auto& b : sig.bytes) {
		char buf[8];
		if (b.wildcard) {
			pattern += "\\x00";
			mask += "?";
		} else {
			std::snprintf(buf, sizeof(buf), "\\x%02X", b.value);
			pattern += buf;
			mask += "x";
		}
	}
	pattern += "\"";
	mask += "\"";
	return pattern + ", " + mask;
}

inline std::string format_yara_rule(const signature_t& sig)
{
	std::string safe_name;
	for (char c : sig.name) {
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_')
			safe_name += c;
		else
			safe_name += '_';
	}
	if (safe_name.empty()) safe_name = "unnamed_sig";
	if (safe_name[0] >= '0' && safe_name[0] <= '9') safe_name = "sig_" + safe_name;

	std::string hex_str;
	hex_str.reserve(sig.bytes.size() * 3);
	for (size_t i = 0; i < sig.bytes.size(); ++i) {
		if (i > 0) hex_str += ' ';
		if (sig.bytes[i].wildcard) {
			hex_str += "??";
		} else {
			char buf[4];
			std::snprintf(buf, sizeof(buf), "%02X", sig.bytes[i].value);
			hex_str += buf;
		}
	}

	std::string rule;
	rule += "rule " + safe_name + "\n";
	rule += "{\n";
	rule += "    meta:\n";
	rule += "        address = \"0x";
	char addr_buf[20];
	std::snprintf(addr_buf, sizeof(addr_buf), "%llX", static_cast<unsigned long long>(sig.address));
	rule += addr_buf;
	rule += "\"\n";
	if (!sig.module_name.empty())
		rule += "        module = \"" + sig.module_name + "\"\n";
	char q_buf[16];
	std::snprintf(q_buf, sizeof(q_buf), "%.1f", sig.quality_score);
	rule += "        quality = \"" + std::string(q_buf) + "\"\n";
	rule += "    strings:\n";
	rule += "        $pattern = { " + hex_str + " }\n";
	rule += "    condition:\n";
	rule += "        $pattern\n";
	rule += "}\n";
	return rule;
}

inline std::string format_x64dbg_signature(const signature_t& sig)
{
	std::string result;
	result.reserve(sig.bytes.size() * 3);
	for (size_t i = 0; i < sig.bytes.size(); ++i) {
		if (i > 0) result += ' ';
		if (sig.bytes[i].wildcard) {
			result += "??";
		} else {
			char buf[4];
			std::snprintf(buf, sizeof(buf), "%02x", sig.bytes[i].value);
			result += buf;
		}
	}
	return result;
}

namespace detail {

#ifdef AIDA_STANDALONE

struct decoded_instr_t {
	ZydisDecodedInstruction instr;
	ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];
	uint64_t                address;
	uint8_t                 raw[15];
	uint8_t                 length;
};

inline bool should_wildcard_operand_bytes(const ZydisDecodedInstruction& instr,
                                           const ZydisDecodedOperand* operands,
                                           size_t op_count)
{
	for (size_t i = 0; i < op_count && i < instr.operand_count; ++i) {
		auto& op = operands[i];
		if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			if (op.imm.is_relative) return true;
			if (instr.raw.imm[0].size >= 32) return true;
		}
		if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
			if (op.mem.base == ZYDIS_REGISTER_RIP) return true;
			if (op.mem.disp.size > 0 && instr.raw.disp.size >= 32) return true;
		}
	}
	return false;
}

inline void wildcard_dynamic_bytes(decoded_instr_t& di, std::vector<aob_byte_t>& out)
{
	bool needs_wildcard = should_wildcard_operand_bytes(di.instr, di.operands, ZYDIS_MAX_OPERAND_COUNT);

	for (uint8_t b = 0; b < di.length; ++b) {
		aob_byte_t ab;
		ab.value = di.raw[b];
		ab.wildcard = false;

		if (needs_wildcard) {
			if (di.instr.raw.disp.size > 0) {
				uint8_t disp_off = di.instr.raw.disp.offset;
				uint8_t disp_sz = static_cast<uint8_t>(di.instr.raw.disp.size / 8);
				if (b >= disp_off && b < disp_off + disp_sz) {
					ab.wildcard = true;
				}
			}
			for (int imm_idx = 0; imm_idx < 2; ++imm_idx) {
				if (di.instr.raw.imm[imm_idx].size > 0) {
					uint8_t imm_off = di.instr.raw.imm[imm_idx].offset;
					uint8_t imm_sz = static_cast<uint8_t>(di.instr.raw.imm[imm_idx].size / 8);
					if (b >= imm_off && b < imm_off + imm_sz) {
						ab.wildcard = true;
					}
				}
			}
		}

		out.push_back(ab);
	}
}

#endif

inline int count_pattern_in_data(const uint8_t* data, size_t data_len,
                                  const std::vector<aob_byte_t>& pattern)
{
	if (pattern.empty() || data_len < pattern.size()) return 0;
	int count = 0;
	size_t limit = data_len - pattern.size();
	for (size_t i = 0; i <= limit; ++i) {
		bool match = true;
		for (size_t j = 0; j < pattern.size(); ++j) {
			if (!pattern[j].wildcard && data[i + j] != pattern[j].value) {
				match = false;
				break;
			}
		}
		if (match) {
			++count;
			if (count > 1) return count;
		}
	}
	return count;
}

}

inline float compute_quality_score(const signature_t& sig)
{
	if (sig.bytes.empty()) return 0.f;

	size_t total = sig.bytes.size();
	size_t wildcards = 0;
	for (auto& b : sig.bytes) {
		if (b.wildcard) ++wildcards;
	}

	float wildcard_ratio = static_cast<float>(wildcards) / static_cast<float>(total);
	float specificity = 1.f - wildcard_ratio;

	float length_score;
	if (total >= 32) length_score = 1.f;
	else if (total >= 16) length_score = 0.7f + 0.3f * (static_cast<float>(total) - 16.f) / 16.f;
	else if (total >= 8) length_score = 0.4f + 0.3f * (static_cast<float>(total) - 8.f) / 8.f;
	else length_score = static_cast<float>(total) / 20.f;

	float uniqueness_bonus = 1.f;
	if (sig.uniqueness_count == 1) uniqueness_bonus = 1.3f;
	else if (sig.uniqueness_count > 1) uniqueness_bonus = 0.5f;

	float raw = specificity * length_score * uniqueness_bonus;
	if (raw > 1.f) raw = 1.f;
	if (raw < 0.f) raw = 0.f;
	return raw;
}

inline const char* score_grade(float score)
{
	if (score >= 0.85f) return "A";
	if (score >= 0.7f) return "B";
	if (score >= 0.5f) return "C";
	if (score >= 0.3f) return "D";
	return "F";
}

inline void generate_from_address(uint64_t address, int num_instructions, bool auto_wildcard)
{
#ifdef AIDA_STANDALONE
	if (g_state.generating.load()) {
		diag::log_tagged("aob", "generate_from_address refused already_generating");
		return;
	}
	if (address == 0) {
		diag::log_tagged("aob", "generate_from_address refused zero_address");
		return;
	}
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("aob", "generate_from_address refused not_attached driver_loaded=%d pid=%u",
			static_cast<int>(driver_bridge::is_loaded()), driver_bridge::attached_pid());
		return;
	}
	diag::log_tagged_fmt("aob", "generate_from_address start addr=0x%llX instructions=%d auto_wildcard=%d",
		static_cast<unsigned long long>(address), num_instructions, static_cast<int>(auto_wildcard));
	g_state.generating.store(true);

	work_queue::post([address, num_instructions, auto_wildcard]() {
		auto t_start = std::chrono::steady_clock::now();
		signature_t sig;
		sig.id = allocate_signature_id();
		sig.address = address;

		auto modules = driver_bridge::enumerate_modules();
		for (auto& m : modules) {
			if (address >= m.base && address < m.base + m.size) {
				sig.module_name = m.name;
				break;
			}
		}

		size_t read_size = static_cast<size_t>(num_instructions) * 15;
		std::vector<uint8_t> code;
		driver_bridge::read_memory(address, read_size, code);
		if (code.empty()) {
			diag::log_tagged_fmt("aob", "generate_from_address read_memory_failed addr=0x%llX size=%zu",
				static_cast<unsigned long long>(address), read_size);
			g_state.generating.store(false);
			return;
		}

		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

		std::vector<detail::decoded_instr_t> instrs;
		uint64_t offset = 0;
		int decoded_count = 0;

		while (offset < code.size() && decoded_count < num_instructions) {
			detail::decoded_instr_t di{};
			di.address = address + offset;

			auto status = ZydisDecoderDecodeFull(
				&decoder, code.data() + offset, code.size() - offset,
				&di.instr, di.operands);

			if (!ZYAN_SUCCESS(status)) break;

			di.length = static_cast<uint8_t>(di.instr.length);
			std::memcpy(di.raw, code.data() + offset, di.length);

			instrs.push_back(di);
			offset += di.length;
			++decoded_count;
		}

		std::vector<aob_byte_t> pattern;
		for (auto& di : instrs) {
			if (auto_wildcard) {
				detail::wildcard_dynamic_bytes(di, pattern);
			} else {
				for (uint8_t b = 0; b < di.length; ++b) {
					aob_byte_t ab;
					ab.value = di.raw[b];
					ab.wildcard = false;
					pattern.push_back(ab);
				}
			}
		}

		size_t pattern_size = pattern.size();
		size_t decoded_instrs = instrs.size();
		float qs = 0.f;
		sig.bytes = std::move(pattern);
		sig.quality_score = compute_quality_score(sig);
		qs = sig.quality_score;

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current = std::move(sig);
		}

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
		diag::log_tagged_fmt("aob", "generate_from_address done addr=0x%llX decoded=%zu bytes=%zu quality=%.2f duration_ms=%llu",
			static_cast<unsigned long long>(address), decoded_instrs, pattern_size,
			static_cast<double>(qs), static_cast<unsigned long long>(dur_ms));

		g_state.generating.store(false);
	});
#else
	(void)address;
	(void)num_instructions;
	(void)auto_wildcard;
#endif
}

inline void generate_from_file(const DisasmFile& file, uint64_t address, int num_instructions, bool auto_wildcard)
{
#ifdef AIDA_STANDALONE
	if (g_state.generating.load()) return;
	g_state.generating.store(true);

	auto file_copy = file;
	work_queue::post([file_copy, address, num_instructions, auto_wildcard]() {
		signature_t sig;
		sig.id = allocate_signature_id();
		sig.address = address;
		sig.module_name = file_copy.filename;

		const uint8_t* code_data = nullptr;
		size_t code_size = 0;
		uint64_t section_va = 0;
		for (auto& sec : file_copy.sections) {
			uint64_t sec_start = sec.va;
			uint64_t sec_end = sec_start + sec.bytes.size();
			if (address >= sec_start && address < sec_end) {
				code_data = sec.bytes.data() + (address - sec_start);
				code_size = sec.bytes.size() - static_cast<size_t>(address - sec_start);
				section_va = sec.va;
				break;
			}
		}

		if (!code_data || code_size == 0) {
			g_state.generating.store(false);
			return;
		}

		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

		std::vector<detail::decoded_instr_t> instrs;
		uint64_t offset = 0;
		int decoded_count = 0;

		while (offset < code_size && decoded_count < num_instructions) {
			detail::decoded_instr_t di{};
			di.address = address + offset;

			auto status = ZydisDecoderDecodeFull(
				&decoder, code_data + offset, code_size - offset,
				&di.instr, di.operands);

			if (!ZYAN_SUCCESS(status)) break;

			di.length = static_cast<uint8_t>(di.instr.length);
			std::memcpy(di.raw, code_data + offset, di.length);

			instrs.push_back(di);
			offset += di.length;
			++decoded_count;
		}

		std::vector<aob_byte_t> pattern;
		for (auto& di : instrs) {
			if (auto_wildcard) {
				detail::wildcard_dynamic_bytes(di, pattern);
			} else {
				for (uint8_t b = 0; b < di.length; ++b) {
					aob_byte_t ab;
					ab.value = di.raw[b];
					ab.wildcard = false;
					pattern.push_back(ab);
				}
			}
		}

		sig.bytes = std::move(pattern);
		sig.quality_score = compute_quality_score(sig);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current = std::move(sig);
		}

		g_state.generating.store(false);
	});
#else
	(void)file;
	(void)address;
	(void)num_instructions;
	(void)auto_wildcard;
#endif
}

inline void validate_uniqueness_process(signature_t& sig)
{
	if (g_state.validating.load()) {
		diag::log_tagged("aob", "validate_uniqueness_process refused already_validating");
		return;
	}
	if (sig.id == 0) sig.id = allocate_signature_id();
	diag::log_tagged_fmt("aob", "validate_uniqueness_process start id=%llu bytes=%zu",
		static_cast<unsigned long long>(sig.id), sig.bytes.size());
	g_state.validating.store(true);

	work_queue::post([sig_copy = sig]() mutable {
		int total_count = 0;
		auto regions = driver_bridge::enumerate_memory_regions(4096);

		for (auto& region : regions) {
			if (region.state != 0x1000) continue;
			if (region.protect & 0x100) continue;
			uint32_t prot = region.protect & 0xFF;
			if (prot == 0x01 || prot == 0x00) continue;
			if (region.size > 0x10000000) continue;

			std::vector<uint8_t> data;
			driver_bridge::read_memory(region.base, static_cast<size_t>(region.size), data);
			if (data.empty()) continue;

			total_count += detail::count_pattern_in_data(data.data(), data.size(), sig_copy.bytes);
			if (total_count > 1) break;
		}

		sig_copy.unique = (total_count == 1);
		sig_copy.uniqueness_count = total_count;
		sig_copy.quality_score = compute_quality_score(sig_copy);
		diag::log_tagged_fmt("aob", "validate_uniqueness_process result id=%llu count=%d unique=%d quality=%.2f",
			static_cast<unsigned long long>(sig_copy.id), total_count,
			static_cast<int>(sig_copy.unique), static_cast<double>(sig_copy.quality_score));

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			bool written = false;
			for (auto& live : g_state.saved_signatures) {
				if (live.id == sig_copy.id) {
					live.unique = sig_copy.unique;
					live.uniqueness_count = sig_copy.uniqueness_count;
					live.quality_score = sig_copy.quality_score;
					written = true;
					break;
				}
			}
			if (!written && g_state.current.id == sig_copy.id) {
				g_state.current.unique = sig_copy.unique;
				g_state.current.uniqueness_count = sig_copy.uniqueness_count;
				g_state.current.quality_score = sig_copy.quality_score;
			}
		}

		g_state.validating.store(false);
	});
}

inline void validate_uniqueness_file(const DisasmFile& file, signature_t& sig)
{
	int total_count = 0;
	for (auto& sec : file.sections) {
		if (sec.bytes.empty()) continue;
		total_count += detail::count_pattern_in_data(sec.bytes.data(), sec.bytes.size(), sig.bytes);
		if (total_count > 1) break;
	}
	sig.unique = (total_count == 1);
	sig.uniqueness_count = total_count;
	sig.quality_score = compute_quality_score(sig);
}

inline void save_current()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	if (g_state.current.bytes.empty()) {
		diag::log_tagged("aob", "save_current refused empty_current");
		return;
	}
	if (g_state.name_input[0])
		g_state.current.name = g_state.name_input;
	else {
		char buf[32];
		std::snprintf(buf, sizeof(buf), "sig_%llX", static_cast<unsigned long long>(g_state.current.address));
		g_state.current.name = buf;
	}
	signature_t copy = g_state.current;
	if (copy.id == 0) copy.id = allocate_signature_id();
	std::string saved_name = copy.name;
	size_t bytes_count = copy.bytes.size();
	g_state.saved_signatures.push_back(std::move(copy));
	diag::log_tagged_fmt("aob", "save_current saved name='%s' bytes=%zu total_saved=%zu",
		saved_name.c_str(), bytes_count, g_state.saved_signatures.size());
}

inline void generate_batch(const std::vector<uint64_t>& addresses, int num_instructions, bool auto_wildcard)
{
#ifdef AIDA_STANDALONE
	if (g_state.batch_generating.load()) {
		diag::log_tagged("aob", "generate_batch refused already_running");
		return;
	}
	if (addresses.empty()) {
		diag::log_tagged("aob", "generate_batch refused empty_address_list");
		return;
	}
	diag::log_tagged_fmt("aob", "generate_batch start count=%zu instructions=%d auto_wildcard=%d",
		addresses.size(), num_instructions, static_cast<int>(auto_wildcard));
	g_state.batch_generating.store(true);
	g_state.batch_total.store(static_cast<int>(addresses.size()));
	g_state.batch_done.store(0);

	auto addrs = addresses;
	work_queue::post([addrs, num_instructions, auto_wildcard]() {
		auto t_start = std::chrono::steady_clock::now();
		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

		auto modules = driver_bridge::enumerate_modules();

		for (size_t ai = 0; ai < addrs.size(); ++ai) {
			uint64_t address = addrs[ai];

			signature_t sig;
			sig.id = allocate_signature_id();
			sig.address = address;

			for (auto& m : modules) {
				if (address >= m.base && address < m.base + m.size) {
					sig.module_name = m.name;
					break;
				}
			}

			size_t read_size = static_cast<size_t>(num_instructions) * 15;
			std::vector<uint8_t> code;
			driver_bridge::read_memory(address, read_size, code);
			if (code.empty()) {
				g_state.batch_done.fetch_add(1);
				continue;
			}

			std::vector<detail::decoded_instr_t> instrs;
			uint64_t offset = 0;
			int decoded_count = 0;

			while (offset < code.size() && decoded_count < num_instructions) {
				detail::decoded_instr_t di{};
				di.address = address + offset;

				auto status = ZydisDecoderDecodeFull(
					&decoder, code.data() + offset, code.size() - offset,
					&di.instr, di.operands);

				if (!ZYAN_SUCCESS(status)) break;

				di.length = static_cast<uint8_t>(di.instr.length);
				std::memcpy(di.raw, code.data() + offset, di.length);

				instrs.push_back(di);
				offset += di.length;
				++decoded_count;
			}

			std::vector<aob_byte_t> pattern;
			for (auto& di : instrs) {
				if (auto_wildcard) {
					detail::wildcard_dynamic_bytes(di, pattern);
				} else {
					for (uint8_t b = 0; b < di.length; ++b) {
						aob_byte_t ab;
						ab.value = di.raw[b];
						ab.wildcard = false;
						pattern.push_back(ab);
					}
				}
			}

			sig.bytes = std::move(pattern);
			sig.quality_score = compute_quality_score(sig);

			char name_buf[32];
			std::snprintf(name_buf, sizeof(name_buf), "batch_%llX", static_cast<unsigned long long>(address));
			sig.name = name_buf;

			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.saved_signatures.push_back(std::move(sig));
			}

			g_state.batch_done.fetch_add(1);
		}

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
		diag::log_tagged_fmt("aob", "generate_batch done total=%zu done=%d duration_ms=%llu",
			addrs.size(), g_state.batch_done.load(), static_cast<unsigned long long>(dur_ms));
		g_state.batch_generating.store(false);
	});
#else
	(void)addresses;
	(void)num_instructions;
	(void)auto_wildcard;
#endif
}

inline void optimize_signature(signature_t& sig)
{
#ifdef AIDA_STANDALONE
	if (sig.bytes.size() < 4) {
		diag::log_tagged_fmt("aob", "optimize_signature refused too_short bytes=%zu",
			sig.bytes.size());
		return;
	}
	diag::log_tagged_fmt("aob", "optimize_signature start id=%llu bytes=%zu",
		static_cast<unsigned long long>(sig.id), sig.bytes.size());

	std::vector<uint8_t> concrete;
	concrete.reserve(sig.bytes.size());
	for (auto& b : sig.bytes) {
		if (!b.wildcard) concrete.push_back(b.value);
	}
	if (concrete.size() < 4) return;

	auto regions = driver_bridge::enumerate_memory_regions(4096);

	std::vector<uint8_t> all_data;
	std::vector<std::pair<uint64_t, size_t>> region_offsets;
	for (auto& region : regions) {
		if (region.state != 0x1000) continue;
		if (region.protect & 0x100) continue;
		uint32_t prot = region.protect & 0xFF;
		if (prot == 0x01 || prot == 0x00) continue;
		if (region.size > 0x10000000) continue;

		std::vector<uint8_t> data;
		driver_bridge::read_memory(region.base, static_cast<size_t>(region.size), data);
		if (data.empty()) continue;

		region_offsets.push_back({region.base, all_data.size()});
		all_data.insert(all_data.end(), data.begin(), data.end());
	}

	if (all_data.empty()) return;

	auto count_matches = [&](const std::vector<aob_byte_t>& pat) -> int {
		return detail::count_pattern_in_data(all_data.data(), all_data.size(), pat);
	};

	int full_count = count_matches(sig.bytes);
	if (full_count != 1) return;

	size_t best_start = 0;
	size_t best_len = sig.bytes.size();

	for (size_t start = 0; start < sig.bytes.size(); ++start) {
		size_t lo = 1;
		size_t hi = sig.bytes.size() - start;
		if (hi < lo) continue;

		bool found_unique = false;
		size_t min_len = hi;
		while (lo <= hi) {
			size_t mid = (lo + hi) / 2;
			std::vector<aob_byte_t> sub(sig.bytes.begin() + start,
										sig.bytes.begin() + start + mid);
			int cnt = count_matches(sub);
			if (cnt == 1) {
				min_len = mid;
				found_unique = true;
				if (mid == 0) break;
				hi = mid - 1;
			} else {
				lo = mid + 1;
			}
		}

		if (found_unique && min_len < best_len) {
			best_len = min_len;
			best_start = start;
		}
	}

	if (best_len < sig.bytes.size()) {
		size_t old_size = sig.bytes.size();
		std::vector<aob_byte_t> optimized(sig.bytes.begin() + best_start,
										  sig.bytes.begin() + best_start + best_len);
		sig.bytes = std::move(optimized);
		sig.unique = true;
		sig.uniqueness_count = 1;
		sig.quality_score = compute_quality_score(sig);
		diag::log_tagged_fmt("aob", "optimize_signature done from=%zu to=%zu start=%zu quality=%.2f",
			old_size, best_len, best_start, static_cast<double>(sig.quality_score));
	} else {
		diag::log_tagged_fmt("aob", "optimize_signature no_improvement keep=%zu", sig.bytes.size());
	}
#else
	(void)sig;
#endif
}

inline std::string get_aob_cache_dir()
{
	char* appdata = nullptr;
	size_t len = 0;
	_dupenv_s(&appdata, &len, "APPDATA");
	std::string dir;
	if (appdata) {
		dir = std::string(appdata) + "\\AiDA\\Standalone\\aob_signatures";
		free(appdata);
	}
	return dir;
}

inline void export_signatures_json(const std::string& path)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	nlohmann::json arr = nlohmann::json::array();

	for (auto& sig : g_state.saved_signatures) {
		nlohmann::json obj;
		obj["id"] = sig.id;
		obj["name"] = sig.name;
		obj["address"] = sig.address;
		obj["module"] = sig.module_name;
		obj["quality"] = sig.quality_score;
		obj["unique"] = sig.unique;
		obj["uniqueness_count"] = sig.uniqueness_count;

		std::string hex = format_signature(sig);
		obj["pattern"] = hex;
		obj["ida_pattern"] = format_ida_signature(sig);

		nlohmann::json bytes_arr = nlohmann::json::array();
		for (auto& b : sig.bytes) {
			nlohmann::json bo;
			bo["value"] = b.value;
			bo["wildcard"] = b.wildcard;
			bytes_arr.push_back(bo);
		}
		obj["bytes"] = bytes_arr;
		arr.push_back(obj);
	}

	std::ofstream f(path);
	if (f.is_open()) {
		f << arr.dump(2);
		diag::log_tagged_fmt("aob", "export_signatures_json ok path='%s' count=%zu",
			path.c_str(), arr.size());
	} else {
		diag::log_tagged_fmt("aob", "export_signatures_json failed path='%s'", path.c_str());
	}
}

inline void export_signatures_header(const std::string& path)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	std::ofstream f(path);
	if (!f.is_open()) {
		diag::log_tagged_fmt("aob", "export_signatures_header failed path='%s'", path.c_str());
		return;
	}

	f << "#pragma once\n\n";
	f << "#include <cstdint>\n\n";
	f << "namespace signatures {\n\n";

	for (auto& sig : g_state.saved_signatures) {
		std::string safe_name;
		for (char c : sig.name) {
			if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '_')
				safe_name += c;
			else
				safe_name += '_';
		}
		if (safe_name.empty()) safe_name = "unnamed";

		auto code_fmt = format_code_signature(sig);
		f << "constexpr auto " << safe_name << "_pattern = " << code_fmt << ";\n";
	}

	f << "\n}\n";
	diag::log_tagged_fmt("aob", "export_signatures_header ok path='%s' count=%zu",
		path.c_str(), g_state.saved_signatures.size());
}

inline void export_signatures_yara(const std::string& path)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	std::ofstream f(path);
	if (!f.is_open()) {
		diag::log_tagged_fmt("aob", "export_signatures_yara failed path='%s'", path.c_str());
		return;
	}

	for (auto& sig : g_state.saved_signatures) {
		f << format_yara_rule(sig) << "\n";
	}
	diag::log_tagged_fmt("aob", "export_signatures_yara ok path='%s' count=%zu",
		path.c_str(), g_state.saved_signatures.size());
}

inline void import_signatures_json(const std::string& path)
{
	std::ifstream f(path);
	if (!f.is_open()) {
		diag::log_tagged_fmt("aob", "import_signatures_json failed_to_open path='%s'", path.c_str());
		return;
	}

	nlohmann::json arr;
	try {
		f >> arr;
	} catch (...) {
		diag::log_tagged_fmt("aob", "import_signatures_json parse_failed path='%s'", path.c_str());
		return;
	}

	if (!arr.is_array()) {
		diag::log_tagged_fmt("aob", "import_signatures_json not_an_array path='%s'", path.c_str());
		return;
	}

	std::lock_guard<std::mutex> lk(g_state.mutex);
	for (auto& obj : arr) {
		signature_t sig;
		sig.id = obj.value("id", static_cast<uint64_t>(0));
		sig.name = obj.value("name", "");
		sig.address = obj.value("address", static_cast<uint64_t>(0));
		sig.module_name = obj.value("module", "");
		sig.quality_score = obj.value("quality", 0.0f);
		sig.unique = obj.value("unique", false);
		sig.uniqueness_count = obj.value("uniqueness_count", 0);

		if (obj.contains("bytes") && obj["bytes"].is_array()) {
			for (auto& bo : obj["bytes"]) {
				aob_byte_t b;
				b.value = bo.value("value", static_cast<uint8_t>(0));
				b.wildcard = bo.value("wildcard", false);
				sig.bytes.push_back(b);
			}
		}

		if (sig.id == 0)
			sig.id = allocate_signature_id();
		else {
			uint64_t expected = g_next_signature_id.load(std::memory_order_relaxed);
			while (sig.id >= expected &&
				!g_next_signature_id.compare_exchange_weak(expected, sig.id + 1, std::memory_order_relaxed)) {}
		}

		if (!sig.bytes.empty())
			g_state.saved_signatures.push_back(std::move(sig));
	}
}

inline void save_signatures_to_disk()
{
	auto dir = get_aob_cache_dir();
	if (dir.empty()) {
		diag::log_tagged("aob", "save_signatures_to_disk no_appdata");
		return;
	}
	std::error_code ec;
	std::filesystem::create_directories(dir, ec);
	std::string path = dir + "\\saved.json";
	export_signatures_json(path);
}

inline void load_signatures_from_disk()
{
	auto dir = get_aob_cache_dir();
	if (dir.empty()) {
		diag::log_tagged("aob", "load_signatures_from_disk no_appdata");
		return;
	}
	std::string path = dir + "\\saved.json";
	if (!std::filesystem::exists(path)) {
		diag::log_tagged_fmt("aob", "load_signatures_from_disk missing path='%s'", path.c_str());
		return;
	}
	import_signatures_json(path);
	diag::log_tagged_fmt("aob", "load_signatures_from_disk loaded path='%s' total=%zu",
		path.c_str(), g_state.saved_signatures.size());
}

struct comparison_result_t {
	std::string name;
	uint64_t    original_address;
	bool        still_found;
	int         match_count;
	uint64_t    new_address;
};

inline std::vector<comparison_result_t> compare_signatures_against_process(
	const std::vector<signature_t>& sigs)
{
#ifdef AIDA_STANDALONE
	std::vector<comparison_result_t> results;
	auto t_start = std::chrono::steady_clock::now();
	diag::log_tagged_fmt("aob", "compare_signatures_against_process start count=%zu pid=%u",
		sigs.size(), driver_bridge::attached_pid());

	auto regions = driver_bridge::enumerate_memory_regions(4096);
	std::vector<uint8_t> all_data;
	std::vector<std::pair<uint64_t, size_t>> region_map;

	for (auto& region : regions) {
		if (region.state != 0x1000) continue;
		if (region.protect & 0x100) continue;
		uint32_t prot = region.protect & 0xFF;
		if (prot == 0x01 || prot == 0x00) continue;
		if (region.size > 0x10000000) continue;

		std::vector<uint8_t> data;
		driver_bridge::read_memory(region.base, static_cast<size_t>(region.size), data);
		if (data.empty()) continue;

		region_map.push_back({region.base, all_data.size()});
		all_data.insert(all_data.end(), data.begin(), data.end());
	}

	for (auto& sig : sigs) {
		comparison_result_t cr;
		cr.name = sig.name;
		cr.original_address = sig.address;
		cr.match_count = 0;
		cr.new_address = 0;
		cr.still_found = false;

		if (all_data.empty() || sig.bytes.empty() || sig.bytes.size() > all_data.size()) {
			results.push_back(cr);
			continue;
		}

		for (size_t i = 0; i <= all_data.size() - sig.bytes.size(); ++i) {
			bool match = true;
			for (size_t j = 0; j < sig.bytes.size(); ++j) {
				if (!sig.bytes[j].wildcard && all_data[i + j] != sig.bytes[j].value) {
					match = false;
					break;
				}
			}
			if (match) {
				cr.match_count++;
				if (cr.match_count == 1) {
					uint64_t found_addr = 0;
					for (auto it = region_map.rbegin(); it != region_map.rend(); ++it) {
						if (i >= it->second) {
							found_addr = it->first + (i - it->second);
							break;
						}
					}
					cr.new_address = found_addr;
				}
				if (cr.match_count > 100) break;
			}
		}

		cr.still_found = (cr.match_count > 0);
		results.push_back(cr);
	}

	auto t_end = std::chrono::steady_clock::now();
	uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
	size_t still_found = 0;
	for (auto& r : results) if (r.still_found) ++still_found;
	diag::log_tagged_fmt("aob", "compare_signatures_against_process done total=%zu still_found=%zu duration_ms=%llu",
		results.size(), still_found, static_cast<unsigned long long>(dur_ms));

	return results;
#else
	(void)sigs;
	return {};
#endif
}

}
