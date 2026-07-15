#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../core/analysis/workspace/workspace_types.hpp"

namespace crypto_scanner {

enum class crypto_category_t : int {
	symmetric = 0,
	hash,
	stream_cipher,
	block_cipher,
	checksum,
	encoding,
	asymmetric,
	COUNT
};

struct crypto_signature_t {
	const char* name;
	const char* algorithm;
	const char* description;
	crypto_category_t category;
	const std::uint8_t* pattern;
	std::size_t pattern_size;
	std::size_t min_match;
};

struct crypto_hit_t {
	std::string signature_name;
	std::string algorithm;
	crypto_category_t category = crypto_category_t::symmetric;
	std::uint64_t address = 0;
	std::string module_name;
	std::uint64_t module_offset = 0;
	std::vector<std::uint64_t> referencing_functions;
};

struct entropy_region_t {
	std::uint64_t address = 0;
	float entropy = 0.f;
	std::uint32_t block_size = 256;
	std::string module_name;
};

struct custom_signature_t {
	std::string name;
	std::string algorithm;
	std::string description;
	crypto_category_t category = crypto_category_t::symmetric;
	std::vector<std::uint8_t> pattern;
};

struct label_scan_diagnostics_t {
	std::size_t result_count = 0;
	std::size_t module_count = 0;
	std::size_t scanned_regions = 0;
	std::size_t candidate_references = 0;
	std::size_t labels_written = 0;
	std::uint64_t first_target_va = 0;
	std::uint64_t first_module_base = 0;
	std::uint64_t first_module_end = 0;
	std::string first_module_name;
};

struct label_query_diagnostics_t {
	std::uint64_t query_va = 0;
	bool found = false;
	std::size_t map_size = 0;
	std::string label;
	std::string source;
};

struct scan_state_t {
	std::vector<crypto_hit_t> results;
	std::vector<entropy_region_t> entropy_map;
	std::vector<custom_signature_t> custom_sigs;
	std::mutex mutex;
	std::atomic<bool> scanning{false};
	std::atomic<float> progress{0.f};
	std::atomic<bool> cancel{false};
	bool active = false;
	std::unordered_map<std::uint64_t, std::string> function_labels;
	float entropy_threshold = 7.f;
	label_scan_diagnostics_t last_label_scan;
	label_query_diagnostics_t last_label_query;
};

struct workspace_crypto_hit_t {
	std::string signature_name;
	std::string algorithm;
	crypto_category_t category = crypto_category_t::symmetric;
	aida::analysis::address_t address;
	std::string module_name;
	std::uint64_t module_offset = 0;
	std::vector<aida::analysis::address_t> referencing_functions;
};

struct workspace_entropy_region_t {
	aida::analysis::address_t address;
	float entropy = 0.f;
	std::uint32_t block_size = 256;
	std::string module_name;
};

struct workspace_scan_snapshot_t {
	std::vector<workspace_crypto_hit_t> results;
	std::vector<workspace_entropy_region_t> entropy_map;
	std::vector<custom_signature_t> custom_signatures;
	std::map<aida::analysis::address_t, std::string> function_labels;
	float entropy_threshold = 7.f;
	float progress = 0.f;
	bool scanning = false;
	bool cancellation_requested = false;
};

inline scan_state_t g_state;

inline std::vector<crypto_signature_t> get_signatures()
{
	static constexpr std::array<std::uint8_t, 16> aes_sbox_prefix{
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
		0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76};
	static constexpr std::array<std::uint8_t, 8> sha256_initial{
		0x67, 0xE6, 0x09, 0x6A, 0x85, 0xAE, 0x67, 0xBB};
	static constexpr std::array<std::uint8_t, 8> chacha_constant{
		0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x33};
	return {
		{"AES S-box", "AES", "Rijndael substitution table", crypto_category_t::symmetric,
			aes_sbox_prefix.data(), aes_sbox_prefix.size(), aes_sbox_prefix.size()},
		{"SHA-256 IV", "SHA-256", "SHA-256 initial state", crypto_category_t::hash,
			sha256_initial.data(), sha256_initial.size(), sha256_initial.size()},
		{"ChaCha constant", "ChaCha20", "ChaCha state constant", crypto_category_t::stream_cipher,
			chacha_constant.data(), chacha_constant.size(), chacha_constant.size()}
	};
}

inline const char* category_name(crypto_category_t category)
{
	static constexpr const char* names[] = {
		"Symmetric", "Hash", "Stream Cipher", "Block Cipher",
		"Checksum", "Encoding", "Asymmetric"};
	const int index = static_cast<int>(category);
	return index >= 0 && index < static_cast<int>(crypto_category_t::COUNT) ? names[index] : "Unknown";
}

namespace detail {

inline float compute_shannon_entropy(const std::uint8_t* data, std::size_t size)
{
	if (!data || size == 0) return 0.f;
	std::array<std::size_t, 256> counts{};
	for (std::size_t index = 0; index < size; ++index) ++counts[data[index]];
	double entropy = 0.0;
	for (std::size_t count : counts) {
		if (count == 0) continue;
		const double probability = static_cast<double>(count) / static_cast<double>(size);
		entropy -= probability * std::log2(probability);
	}
	return static_cast<float>(entropy);
}

}

}
