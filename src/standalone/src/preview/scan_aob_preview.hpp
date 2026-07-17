#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "scan_preview_runtime.hpp"
#include "../core/disasm/disasm_view.hpp"

namespace aob_generator {

struct aob_byte_t {
	std::uint8_t value = 0;
	bool wildcard = false;
};

struct signature_t {
	std::uint64_t id = 0;
	std::string name;
	std::uint64_t address = 0;
	std::vector<aob_byte_t> bytes;
	bool unique = false;
	int uniqueness_count = 0;
	std::string module_name;
	float quality_score = 0.f;
};

enum class export_format_t : std::uint8_t { json, yara, header };

struct state_t {
	std::vector<signature_t> saved_signatures;
	std::atomic<std::uint64_t> catalog_generation{1};
	signature_t current;
	std::mutex mutex;
	std::atomic<bool> generating{false};
	std::atomic<bool> validating{false};
	std::atomic<bool> batch_generating{false};
	std::atomic<int> batch_total{0};
	std::atomic<int> batch_done{0};
	char address_input[32] = {};
	char name_input[64] = {};
	int instruction_count = 16;
	bool auto_wildcard = true;
	bool validate_uniqueness = true;
	std::string last_error;
	std::string pending_clipboard;
	std::atomic<bool> pending_clipboard_ready{false};
	std::uint64_t last_request_addr = 0;
	int last_request_count = 0;
	bool last_request_auto_wildcard = true;
	bool show_no_address_modal = false;
};

inline state_t g_state;
inline std::atomic<std::uint64_t> g_next_signature_id{1};

inline std::mutex& workspace_states_mutex()
{
	static std::mutex value;
	return value;
}

inline std::unordered_map<std::string, std::shared_ptr<state_t>>& workspace_states()
{
	static std::unordered_map<std::string, std::shared_ptr<state_t>> value;
	return value;
}

inline std::shared_ptr<state_t> state_for(const disasm_view::workspace_context_t& context)
{
	if (!context.workspace) return {};
	const std::string key = context.workspace->identity().binary_id().to_hex();
	std::lock_guard<std::mutex> lock(workspace_states_mutex());
	auto& value = workspace_states()[key];
	if (!value) value = std::make_shared<state_t>();
	return value;
}

inline std::shared_ptr<state_t> legacy_state()
{
	return std::shared_ptr<state_t>(&g_state, [](state_t*) {});
}

inline std::string format_signature(const signature_t& signature)
{
	std::string result;
	for (std::size_t index = 0; index < signature.bytes.size(); ++index) {
		if (index) result.push_back(' ');
		if (signature.bytes[index].wildcard) result += "??";
		else {
			char buffer[4]{};
			std::snprintf(buffer, sizeof(buffer), "%02X", signature.bytes[index].value);
			result += buffer;
		}
	}
	return result;
}

inline std::string format_ida_signature(const signature_t& signature)
{
	std::string result = format_signature(signature);
	for (std::size_t position = result.find("??"); position != std::string::npos;
		position = result.find("??", position + 1)) result.replace(position, 2, "?");
	return result;
}

inline std::string format_code_signature(const signature_t& signature)
{
	std::string pattern = "\"";
	std::string mask = "\"";
	for (const auto& byte : signature.bytes) {
		char buffer[8]{};
		std::snprintf(buffer, sizeof(buffer), "\\x%02X", byte.wildcard ? 0 : byte.value);
		pattern += buffer;
		mask += byte.wildcard ? '?' : 'x';
	}
	return pattern + "\", " + mask + "\"";
}

inline std::string format_yara_rule(const signature_t& signature)
{
	std::string name;
	for (char character : signature.name) {
		if (std::isalnum(static_cast<unsigned char>(character)) || character == '_') name += character;
		else name += '_';
	}
	if (name.empty()) name = "unnamed_sig";
	if (std::isdigit(static_cast<unsigned char>(name[0]))) name = "sig_" + name;
	char address[20]{};
	std::snprintf(address, sizeof(address), "%llX", static_cast<unsigned long long>(signature.address));
	char quality[16]{};
	std::snprintf(quality, sizeof(quality), "%.1f", signature.quality_score);
	std::string rule = "rule " + name + "\n{\n    meta:\n        address = \"0x" + address + "\"\n";
	if (!signature.module_name.empty()) rule += "        module = \"" + signature.module_name + "\"\n";
	rule += "        quality = \"" + std::string(quality) + "\"\n";
	rule += "    strings:\n        $pattern = { " + format_signature(signature) + " }\n";
	rule += "    condition:\n        $pattern\n}\n";
	return rule;
}

inline std::string format_x64dbg_signature(const signature_t& signature)
{
	std::string result;
	for (std::size_t index = 0; index < signature.bytes.size(); ++index) {
		if (index) result.push_back(' ');
		if (signature.bytes[index].wildcard) result += "??";
		else {
			char buffer[4]{};
			std::snprintf(buffer, sizeof(buffer), "%02x", signature.bytes[index].value);
			result += buffer;
		}
	}
	return result;
}

inline float compute_quality_score(const signature_t& signature)
{
	if (signature.bytes.empty()) return 0.f;
	const auto concrete = std::count_if(signature.bytes.begin(), signature.bytes.end(),
		[](const aob_byte_t& byte) { return !byte.wildcard; });
	const float density = static_cast<float>(concrete) / static_cast<float>(signature.bytes.size());
	const float length = (std::min)(1.f, static_cast<float>(signature.bytes.size()) / 24.f);
	return (std::min)(1.f, density * 0.7f + length * 0.3f);
}

inline const char* score_grade(float score)
{
	if (score >= .85f) return "Excellent";
	if (score >= .70f) return "Good";
	if (score >= .50f) return "Fair";
	return "Weak";
}

inline void generate_from_address(const disasm_view::workspace_context_t& context,
	std::uint64_t address, int instruction_count, bool auto_wildcard)
{
	auto state = state_for(context);
	if (!state) return;
	signature_t signature;
	signature.id = g_next_signature_id.fetch_add(1);
	signature.address = address;
	signature.name = state->name_input[0] ? state->name_input : "sub_signature";
	signature.module_name = context.workspace->identity().bin_name();
	const std::size_t count = static_cast<std::size_t>((std::max)(8, (std::min)(instruction_count * 2, 48)));
	for (std::size_t index = 0; index < count; ++index) {
		const std::uint8_t value = static_cast<std::uint8_t>((address >> ((index % 8) * 8)) ^ (index * 37U + 0x48U));
		signature.bytes.push_back({value, auto_wildcard && (index == 3 || index == 7 || index == 14)});
	}
	signature.uniqueness_count = 1;
	signature.unique = true;
	signature.quality_score = compute_quality_score(signature);
	std::lock_guard<std::mutex> lock(state->mutex);
	state->current = std::move(signature);
	state->last_request_addr = address;
	state->last_request_count = instruction_count;
	state->last_request_auto_wildcard = auto_wildcard;
	state->last_error.clear();
	aida::preview::scan::record("aob.generate", std::to_string(address));
}

inline void regenerate_last(const disasm_view::workspace_context_t& context,
	const std::shared_ptr<state_t>& state)
{
	if (!state || state->last_request_addr == 0) return;
	generate_from_address(context, state->last_request_addr, state->last_request_count,
		state->last_request_auto_wildcard);
}

inline void save_current(const std::shared_ptr<state_t>& state)
{
	if (!state) return;
	std::lock_guard<std::mutex> lock(state->mutex);
	if (state->current.bytes.empty()) return;
	state->saved_signatures.push_back(state->current);
	state->catalog_generation.fetch_add(1, std::memory_order_acq_rel);
	aida::preview::scan::record("aob.save", state->current.name);
}

inline bool take_pending_clipboard(const std::shared_ptr<state_t>& state, std::string& output)
{
	if (!state || !state->pending_clipboard_ready.exchange(false)) return false;
	std::lock_guard<std::mutex> lock(state->mutex);
	output = std::move(state->pending_clipboard);
	return true;
}

inline void optimize_signature(std::uint32_t, signature_t& signature)
{
	for (std::size_t index = 5; index < signature.bytes.size(); index += 11)
		signature.bytes[index].wildcard = true;
	signature.quality_score = compute_quality_score(signature);
}

struct comparison_result_t {
	std::string name;
	std::uint64_t original_address = 0;
	bool still_found = false;
	int match_count = 0;
	std::uint64_t new_address = 0;
};

inline std::vector<comparison_result_t> compare_signatures_against_process(
	std::uint32_t, const std::vector<signature_t>& signatures,
	const std::shared_ptr<std::atomic<bool>>& cancellation,
	const std::function<bool()>&, std::string& error)
{
	if (cancellation && cancellation->load(std::memory_order_acquire)) {
		error = "AOB comparison cancelled";
		return {};
	}
	std::vector<comparison_result_t> results;
	results.reserve(signatures.size());
	for (const auto& signature : signatures)
		results.push_back({signature.name, signature.address, true, 1, signature.address});
	aida::preview::scan::record("aob.compare", std::to_string(results.size()));
	return results;
}

}
