#pragma once

#include <atomic>
#include "work_queue.hpp"
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "standalone_driver.hpp"
#include "standalone_ai_client.hpp"
#include "standalone_settings.hpp"
#include "xref_engine.hpp"
#include "zydis_disasm.hpp"
#include "../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

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
	const char*        name;
	const char*        algorithm;
	const char*        description;
	crypto_category_t  category;
	const uint8_t*     pattern;
	size_t             pattern_size;
	size_t             min_match;
};

struct crypto_hit_t {
	std::string   signature_name;
	std::string   algorithm;
	crypto_category_t category;
	uint64_t      address = 0;
	std::string   module_name;
	uint64_t      module_offset = 0;
	std::vector<uint64_t> referencing_functions;
};

struct entropy_region_t {
	uint64_t address = 0;
	float    entropy = 0.f;
	uint32_t block_size = 256;
	std::string module_name;
};

struct custom_signature_t {
	std::string   name;
	std::string   algorithm;
	std::string   description;
	crypto_category_t category = crypto_category_t::symmetric;
	std::vector<uint8_t> pattern;
};

struct scan_state_t {
	std::vector<crypto_hit_t> results;
	std::vector<entropy_region_t> entropy_map;
	std::vector<custom_signature_t> custom_sigs;
	std::mutex                mutex;
	std::atomic<bool>         scanning{false};
	std::atomic<float>        progress{0.f};
	std::atomic<bool>         cancel{false};
	bool                      active = false;
	std::unordered_map<uint64_t, std::string> function_labels;
	float                     entropy_threshold = 7.0f;
};

inline scan_state_t g_state;

struct snapshot_t {
	std::vector<crypto_hit_t> results;
	std::vector<entropy_region_t> entropy_map;
	std::vector<custom_signature_t> custom_sigs;
	bool                      scanning = false;
	float                     progress = 0.f;
	bool                      cancel = false;
	bool                      active = false;
	std::unordered_map<uint64_t, std::string> function_labels;
	float                     entropy_threshold = 7.0f;
};

inline std::unique_ptr<snapshot_t> detach_snapshot() {
	std::lock_guard<std::mutex> lk(g_state.mutex);
	auto out = std::make_unique<snapshot_t>();
	out->results = std::move(g_state.results);
	out->entropy_map = std::move(g_state.entropy_map);
	out->custom_sigs = std::move(g_state.custom_sigs);
	out->scanning = g_state.scanning.load(std::memory_order_acquire);
	out->progress = g_state.progress.load(std::memory_order_acquire);
	out->cancel = g_state.cancel.load(std::memory_order_acquire);
	out->active = g_state.active;
	out->function_labels = std::move(g_state.function_labels);
	out->entropy_threshold = g_state.entropy_threshold;
	g_state.results.clear();
	g_state.entropy_map.clear();
	g_state.custom_sigs.clear();
	g_state.scanning.store(false, std::memory_order_release);
	g_state.progress.store(0.f, std::memory_order_release);
	g_state.cancel.store(false, std::memory_order_release);
	g_state.active = false;
	g_state.function_labels.clear();
	g_state.entropy_threshold = 7.0f;
	return out;
}

inline void attach_snapshot(std::unique_ptr<snapshot_t> snap) {
	std::lock_guard<std::mutex> lk(g_state.mutex);
	if (!snap) snap = std::make_unique<snapshot_t>();
	g_state.results = std::move(snap->results);
	g_state.entropy_map = std::move(snap->entropy_map);
	g_state.custom_sigs = std::move(snap->custom_sigs);
	g_state.scanning.store(snap->scanning, std::memory_order_release);
	g_state.progress.store(snap->progress, std::memory_order_release);
	g_state.cancel.store(snap->cancel, std::memory_order_release);
	g_state.active = snap->active;
	g_state.function_labels = std::move(snap->function_labels);
	g_state.entropy_threshold = snap->entropy_threshold;
}

namespace constants {

static constexpr uint8_t aes_sbox[256] = {
	0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
	0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
	0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
	0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
	0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
	0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
	0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
	0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
	0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
	0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
	0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
	0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
	0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
	0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
	0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
	0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

static constexpr uint8_t aes_inv_sbox[256] = {
	0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
	0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
	0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
	0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
	0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
	0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
	0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
	0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
	0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
	0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
	0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
	0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
	0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
	0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
	0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
	0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

static constexpr uint8_t aes_rcon[11] = {
	0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

static constexpr uint32_t sha256_h[8] = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static constexpr uint32_t sha256_k[64] = {
	0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
	0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
	0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
	0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
	0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
	0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
	0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
	0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
};

static constexpr uint64_t sha512_h[8] = {
	0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
	0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
	0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
	0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

static constexpr uint32_t md5_t_table[64] = {
	0xD76AA478,0xE8C7B756,0x242070DB,0xC1BDCEEE,0xF57C0FAF,0x4787C62A,0xA8304613,0xFD469501,
	0x698098D8,0x8B44F7AF,0xFFFF5BB1,0x895CD7BE,0x6B901122,0xFD987193,0xA679438E,0x49B40821,
	0xF61E2562,0xC040B340,0x265E5A51,0xE9B6C7AA,0xD62F105D,0x02441453,0xD8A1E681,0xE7D3FBC8,
	0x21E1CDE6,0xC33707D6,0xF4D50D87,0x455A14ED,0xA9E3E905,0xFCEFA3F8,0x676F02D9,0x8D2A4C8A,
	0xFFFA3942,0x8771F681,0x6D9D6122,0xFDE5380C,0xA4BEEA44,0x4BDECFA9,0xF6BB4B60,0xBEBFBC70,
	0x289B7EC6,0xEAA127FA,0xD4EF3085,0x04881D05,0xD9D4D039,0xE6DB99E5,0x1FA27CF8,0xC4AC5665,
	0xF4292244,0x432AFF97,0xAB9423A7,0xFC93A039,0x655B59C3,0x8F0CCC92,0xFFEFF47D,0x85845DD1,
	0x6FA87E4F,0xFE2CE6E0,0xA3014314,0x4E0811A1,0xF7537E82,0xBD3AF235,0x2AD7D2BB,0xEB86D391
};

static constexpr uint32_t md5_init[4] = {
	0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
};

static constexpr uint8_t chacha20_constant[16] = {
	'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
};

static constexpr uint8_t salsa20_constant[16] = {
	'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
};

static constexpr uint8_t base64_alphabet[65] = {
	'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
	'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
	'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
	'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/',0
};

static constexpr uint32_t crc32_table[32] = {
	0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,0x9E6495A3,
	0x0EDB8832,0x79DCB8A4,0xE0D5E91B,0x97D2D988,0x09B64C2B,0x7EB17CBF,0xE7B82D09,0x90BF1D9F,
	0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,
	0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5
};

static constexpr uint32_t blowfish_p_init[18] = {
	0x243F6A88,0x85A308D3,0x13198A2E,0x03707344,0xA4093822,0x299F31D0,
	0x082EFA98,0xEC4E6C89,0x452821E6,0x38D01377,0xBE5466CF,0x34E90C6C,
	0xC0AC29B7,0xC97C50DD,0x3F84D5B5,0xB5470917,0x9216D5D9,0x8979FB1B
};

static constexpr uint8_t des_ip_table[64] = {
	58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
	62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
	57,49,41,33,25,17, 9,1,59,51,43,35,27,19,11,3,
	61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
};

static constexpr uint32_t sha1_init[5] = {
	0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
};

static constexpr uint64_t sha384_init[8] = {
	0xCBBB9D5DC1059ED8, 0x629A292A367CD507,
	0x9159015A3070DD17, 0x152FECD8F70E5939,
	0x67332667FFC00B31, 0x8EB44A8768581511,
	0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4
};

static constexpr uint64_t sha512_k[80] = {
	0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
	0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
	0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
	0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
	0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
	0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
	0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
	0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
	0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
	0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
	0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
	0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
	0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
	0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
	0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
	0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
	0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
	0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
	0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
	0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
};

static constexpr uint32_t ripemd160_init[5] = {
	0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
};

static constexpr uint32_t tea_delta = 0x9E3779B9;

static constexpr uint32_t blowfish_sbox0_head[16] = {
	0xD1310BA6,0x98DFB5AC,0x2FFD72DB,0xD01ADFB7,0xB8E1AFED,0x6A267E96,
	0xBA7C9045,0xF12C7F99,0x24A19947,0xB3916CF7,0x0801F2E2,0x858EFC16,
	0x636920D8,0x71574E69,0xA458FEA3,0xF4933D7E
};

static constexpr uint8_t des_sbox1[64] = {
	14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7,
	 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8,
	 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0,
	15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13
};

static constexpr uint8_t des_sbox2[64] = {
	15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
	 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
	 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
	13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9
};

static constexpr uint8_t des_sbox3[64] = {
	10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8,
	13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1,
	13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7,
	 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12
};

static constexpr uint8_t des_sbox4[64] = {
	 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15,
	13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9,
	10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4,
	 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14
};

static constexpr uint8_t rc4_identity[256] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,
	0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,
	0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,
	0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F,
	0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,
	0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A,0x7B,0x7C,0x7D,0x7E,0x7F,
	0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F,
	0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F,
	0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
	0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF,
	0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF,
	0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF,
	0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF,
	0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF
};

static constexpr uint8_t salsa20_constant_16[16] = {
	'e','x','p','a','n','d',' ','1','6','-','b','y','t','e',' ','k'
};

static constexpr uint8_t whirlpool_sbox_head[32] = {
	0x18,0x23,0xC6,0xE8,0x87,0xB8,0x01,0x4F,0x36,0xA6,0xD2,0xF5,0x79,0x6F,0x91,0x52,
	0x60,0xBC,0x9B,0x8E,0xA3,0x0C,0x7B,0x35,0x1D,0xE0,0xD7,0xC2,0x2E,0x4B,0xFE,0x57
};

static constexpr uint32_t camellia_sigma[12] = {
	0xA09E667F, 0x3BCC908B, 0xB67AE858, 0x4CAA73B2,
	0xC6EF372F, 0xE94F82BE, 0x54FF53A5, 0xF1D36F1C,
	0x10E527FA, 0xDE682D1D, 0xB05688C2, 0xB3E6C1FD
};

static constexpr uint32_t serpent_phi = 0x9E3779B9;

static constexpr uint8_t twofish_q0_head[16] = {
	0xA9,0x67,0xB3,0xE8,0x04,0xFD,0xA3,0x76,0x9A,0x92,0x80,0x78,0xE4,0xDD,0xD1,0x38
};

static constexpr uint8_t twofish_q1_head[16] = {
	0x75,0xF3,0xC6,0xF4,0xDB,0x7B,0xFB,0xC8,0x4A,0xD3,0xE6,0x6B,0x45,0x7D,0xE8,0x4B
};

static constexpr uint32_t cast5_sbox1_head[16] = {
	0x30FB40D4,0x9FA0FF0B,0x6BECCD2F,0x3F258C7A,
	0x1E213F2F,0x9C004DD3,0x6003E540,0xCF9FC949,
	0xBFD4AF27,0x88BBBDB5,0xE2034090,0x98D09675,
	0x6E63A0E0,0x15C361D2,0xC2E7661D,0x22D4FF8E
};

static constexpr uint32_t seed_key_sched[16] = {
	0x9E3779B9, 0x3C6EF373, 0x78DDE6E6, 0xF1BBCDCC,
	0xE3779B99, 0xC6EF3733, 0x8DDE6E67, 0x1BBCDCCF,
	0x3779B99E, 0x6EF3733C, 0xDDE6E678, 0xBBCDCCF1,
	0x779B99E3, 0xEF3733C6, 0xDE6E678D, 0xBCDCCF1B
};

static constexpr uint16_t crc16_table_head[16] = {
	0x0000,0xC0C1,0xC181,0x0140,0xC301,0x03C0,0x0280,0xC241,
	0xC601,0x06C0,0x0780,0xC741,0x0500,0xC5C1,0xC481,0x0440
};

static constexpr uint8_t gost_sbox_head[16] = {
	4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3
};

}

namespace detail {

inline bool mem_search(const uint8_t* haystack, size_t hay_len,
                       const uint8_t* needle, size_t needle_len)
{
	if (needle_len > hay_len) return false;
	size_t limit = hay_len - needle_len;
	for (size_t i = 0; i <= limit; ++i) {
		if (std::memcmp(haystack + i, needle, needle_len) == 0)
			return true;
	}
	return false;
}

inline std::vector<uint64_t> find_pattern_in_region(const uint8_t* data, size_t data_len,
                                                     uint64_t region_base,
                                                     const uint8_t* pattern, size_t pat_len)
{
	std::vector<uint64_t> hits;
	if (pat_len > data_len) return hits;
	size_t limit = data_len - pat_len;
	for (size_t i = 0; i <= limit; ++i) {
		if (std::memcmp(data + i, pattern, pat_len) == 0) {
			hits.push_back(region_base + i);
		}
	}
	return hits;
}

}

inline std::vector<crypto_signature_t> get_signatures()
{
	std::vector<crypto_signature_t> sigs;

	sigs.push_back({"AES S-Box", "AES", "AES Forward Substitution Box (256 bytes)",
	    crypto_category_t::symmetric, constants::aes_sbox, 256, 256});

	sigs.push_back({"AES Inverse S-Box", "AES", "AES Inverse Substitution Box (256 bytes)",
	    crypto_category_t::symmetric, constants::aes_inv_sbox, 256, 256});

	sigs.push_back({"AES Rcon", "AES", "AES Round Constants",
	    crypto_category_t::symmetric, constants::aes_rcon, 11, 10});

	sigs.push_back({"SHA-256 Init", "SHA-256", "SHA-256 Initial Hash Values (H0-H7)",
	    crypto_category_t::hash, reinterpret_cast<const uint8_t*>(constants::sha256_h), 32, 32});

	sigs.push_back({"SHA-256 K Constants", "SHA-256", "SHA-256 Round Constants (64 x uint32)",
	    crypto_category_t::hash, reinterpret_cast<const uint8_t*>(constants::sha256_k), 256, 64});

	sigs.push_back({"SHA-512 Init", "SHA-512", "SHA-512 Initial Hash Values",
	    crypto_category_t::hash, reinterpret_cast<const uint8_t*>(constants::sha512_h), 64, 64});

	sigs.push_back({"MD5 T Table", "MD5", "MD5 Sine-derived Constants (64 x uint32)",
	    crypto_category_t::hash, reinterpret_cast<const uint8_t*>(constants::md5_t_table), 256, 64});

	sigs.push_back({"MD5 Init", "MD5", "MD5 Initial Values (A,B,C,D)",
	    crypto_category_t::hash, reinterpret_cast<const uint8_t*>(constants::md5_init), 16, 16});

	sigs.push_back({"ChaCha20/Salsa20", "ChaCha20", "expand 32-byte k constant",
	    crypto_category_t::stream_cipher, constants::chacha20_constant, 16, 16});

	sigs.push_back({"Base64 Alphabet", "Base64", "Standard Base64 encoding alphabet",
	    crypto_category_t::encoding, constants::base64_alphabet, 64, 52});

	sigs.push_back({"Blowfish P-Array", "Blowfish", "Blowfish P-array initialization values",
	    crypto_category_t::block_cipher, reinterpret_cast<const uint8_t*>(constants::blowfish_p_init), 72, 72});

	sigs.push_back({"DES IP Table", "DES", "DES Initial Permutation Table",
	    crypto_category_t::block_cipher, constants::des_ip_table, 64, 64});

	sigs.push_back({"CRC32 Table", "CRC32", "CRC32 polynomial lookup table (first 128 bytes)",
	    crypto_category_t::checksum, reinterpret_cast<const uint8_t*>(constants::crc32_table), 128, 64});

	sigs.push_back({"SHA-1 Init", "SHA-1", "SHA-1 Initial Hash Values (H0-H4)",
	    crypto_category_t::hash, reinterpret_cast<const uint8_t*>(constants::sha1_init), 20, 20});

	sigs.push_back({"SHA-384 Init", "SHA-384", "SHA-384 Initial Hash Values",
	    crypto_category_t::hash, reinterpret_cast<const uint8_t*>(constants::sha384_init), 64, 64});

	sigs.push_back({"SHA-512 K Constants", "SHA-512", "SHA-512 Round Constants (80 x uint64)",
	    crypto_category_t::hash, reinterpret_cast<const uint8_t*>(constants::sha512_k), 256, 64});

	sigs.push_back({"RIPEMD-160 Init", "RIPEMD-160", "RIPEMD-160 Initial Values",
	    crypto_category_t::hash, reinterpret_cast<const uint8_t*>(constants::ripemd160_init), 20, 20});

	sigs.push_back({"TEA/XTEA Delta", "TEA", "TEA/XTEA Golden Ratio Constant 0x9E3779B9",
	    crypto_category_t::block_cipher, reinterpret_cast<const uint8_t*>(&constants::tea_delta), 4, 4});

	sigs.push_back({"Blowfish S-Box 0", "Blowfish", "Blowfish S-Box 0 header (64 bytes)",
	    crypto_category_t::block_cipher, reinterpret_cast<const uint8_t*>(constants::blowfish_sbox0_head), 64, 64});

	sigs.push_back({"DES S-Box 1", "DES", "DES Substitution Box 1",
	    crypto_category_t::block_cipher, constants::des_sbox1, 64, 64});

	sigs.push_back({"DES S-Box 2", "DES", "DES Substitution Box 2",
	    crypto_category_t::block_cipher, constants::des_sbox2, 64, 64});

	sigs.push_back({"DES S-Box 3", "DES", "DES Substitution Box 3",
	    crypto_category_t::block_cipher, constants::des_sbox3, 64, 64});

	sigs.push_back({"DES S-Box 4", "DES", "DES Substitution Box 4",
	    crypto_category_t::block_cipher, constants::des_sbox4, 64, 64});

	sigs.push_back({"RC4 Identity", "RC4", "RC4 Identity Permutation (0x00-0xFF sequential)",
	    crypto_category_t::stream_cipher, constants::rc4_identity, 256, 256});

	sigs.push_back({"Salsa20 (16-byte key)", "Salsa20", "expand 16-byte k constant",
	    crypto_category_t::stream_cipher, constants::salsa20_constant_16, 16, 16});

	sigs.push_back({"Whirlpool S-Box", "Whirlpool", "Whirlpool Substitution Box header",
	    crypto_category_t::hash, constants::whirlpool_sbox_head, 32, 32});

	sigs.push_back({"Camellia Sigma", "Camellia", "Camellia Sigma Constants",
	    crypto_category_t::block_cipher, reinterpret_cast<const uint8_t*>(constants::camellia_sigma), 48, 48});

	sigs.push_back({"Serpent Phi", "Serpent", "Serpent Golden Ratio Constant",
	    crypto_category_t::block_cipher, reinterpret_cast<const uint8_t*>(&constants::serpent_phi), 4, 4});

	sigs.push_back({"Twofish Q0", "Twofish", "Twofish Q0 Permutation header",
	    crypto_category_t::block_cipher, constants::twofish_q0_head, 16, 16});

	sigs.push_back({"Twofish Q1", "Twofish", "Twofish Q1 Permutation header",
	    crypto_category_t::block_cipher, constants::twofish_q1_head, 16, 16});

	sigs.push_back({"CAST5 S-Box 1", "CAST5", "CAST5 S-Box 1 header",
	    crypto_category_t::block_cipher, reinterpret_cast<const uint8_t*>(constants::cast5_sbox1_head), 64, 64});

	sigs.push_back({"SEED Key Schedule", "SEED", "SEED Key Schedule Constants",
	    crypto_category_t::block_cipher, reinterpret_cast<const uint8_t*>(constants::seed_key_sched), 64, 64});

	sigs.push_back({"CRC16 Table", "CRC16", "CRC16 Polynomial Table header",
	    crypto_category_t::checksum, reinterpret_cast<const uint8_t*>(constants::crc16_table_head), 32, 32});

	sigs.push_back({"GOST S-Box", "GOST", "GOST R 34.11-94 S-Box header",
	    crypto_category_t::hash, constants::gost_sbox_head, 16, 16});

	return sigs;
}

inline const char* category_name(crypto_category_t cat)
{
	switch (cat) {
	case crypto_category_t::symmetric:     return "Symmetric";
	case crypto_category_t::hash:          return "Hash";
	case crypto_category_t::stream_cipher: return "Stream Cipher";
	case crypto_category_t::block_cipher:  return "Block Cipher";
	case crypto_category_t::checksum:      return "Checksum";
	case crypto_category_t::encoding:      return "Encoding";
	case crypto_category_t::asymmetric:    return "Asymmetric";
	default: return "Unknown";
	}
}

inline void auto_label_references();

struct process_scan_config_t {
	size_t      max_regions = 4096;
	uint64_t    max_bytes = 0;
	size_t      max_hits = 0;
	uint32_t    timeout_ms = 0;
	std::string module_filter;
};

inline void scan_process(const process_scan_config_t& cfg)
{
	if (g_state.scanning.load()) {
		diag::log_tagged("crypto_scan", "scan_process refused already_scanning");
		return;
	}
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("crypto_scan", "scan_process refused not_attached driver_loaded=%d pid=%u",
			static_cast<int>(driver_bridge::is_loaded()), driver_bridge::attached_pid());
		return;
	}
	diag::log_tagged_fmt("crypto_scan", "scan_process start pid=%u max_regions=%zu max_bytes=%llu max_hits=%zu timeout_ms=%u module_filter='%s'",
		driver_bridge::attached_pid(),
		cfg.max_regions,
		static_cast<unsigned long long>(cfg.max_bytes),
		cfg.max_hits,
		cfg.timeout_ms,
		cfg.module_filter.c_str());

	g_state.scanning.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.results.clear();
		g_state.active = true;
	}

	work_queue::post([cfg]() {
		auto t_start = std::chrono::steady_clock::now();
		auto signatures = get_signatures();
		std::string module_filter = cfg.module_filter;
		for (char& c : module_filter)
			c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

		std::vector<custom_signature_t> custom_copy;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			custom_copy = g_state.custom_sigs;
		}
		for (auto& cs : custom_copy) {
			crypto_signature_t sig;
			sig.name = cs.name.c_str();
			sig.algorithm = cs.algorithm.c_str();
			sig.description = cs.description.c_str();
			sig.category = cs.category;
			sig.pattern = cs.pattern.data();
			sig.pattern_size = cs.pattern.size();
			sig.min_match = cs.pattern.size();
			signatures.push_back(sig);
		}

		auto regions = driver_bridge::enumerate_memory_regions(4096);
		auto modules = driver_bridge::enumerate_modules();

		auto find_module = [&](uint64_t addr) -> std::pair<std::string, uint64_t> {
			for (auto& m : modules) {
				if (addr >= m.base && addr < m.base + m.size)
					return {m.name, addr - m.base};
			}
			return {"<unknown>", addr};
		};

		std::vector<driver_bridge::memory_region_t> scan_regions;
		for (auto& r : regions) {
			if (cfg.max_regions != 0 && scan_regions.size() >= cfg.max_regions) break;
			if (r.state != 0x1000) continue;
			if (r.protect & 0x100) continue;
			uint32_t prot = r.protect & 0xFF;
			if (prot == 0x01 || prot == 0x00) continue;
			if (r.size > 0x10000000) continue;
			if (!module_filter.empty()) {
				auto mod = find_module(r.base);
				std::string mod_name = mod.first;
				for (char& c : mod_name)
					c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
				if (mod_name.find(module_filter) == std::string::npos)
					continue;
			}
			scan_regions.push_back(r);
		}

		uint64_t total_bytes = 0;
		for (auto& r : scan_regions) {
			uint64_t remaining_cap = cfg.max_bytes == 0 || total_bytes >= cfg.max_bytes
				? r.size
				: cfg.max_bytes - total_bytes;
			uint64_t accounted = (std::min)(r.size, remaining_cap);
			total_bytes += accounted;
			if (cfg.max_bytes != 0 && total_bytes >= cfg.max_bytes)
				break;
		}
		if (total_bytes == 0) total_bytes = 1;
		uint64_t scanned = 0;
		size_t hit_count_live = 0;

		for (auto& region : scan_regions) {
			if (g_state.cancel.load()) break;
			if (cfg.timeout_ms != 0) {
				auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now() - t_start).count();
				if (elapsed_ms >= cfg.timeout_ms) {
					g_state.cancel.store(true);
					break;
				}
			}
			if (cfg.max_bytes != 0 && scanned >= cfg.max_bytes) break;

			std::vector<uint8_t> data;
			uint64_t remaining = cfg.max_bytes == 0 ? region.size : cfg.max_bytes - scanned;
			uint64_t read_size64 = (std::min)(region.size, remaining);
			size_t read_size = static_cast<size_t>((std::min)(read_size64, static_cast<uint64_t>(0x10000000)));
			driver_bridge::read_memory(region.base, read_size, data);
			if (data.empty()) {
				scanned += read_size64;
				g_state.progress.store(static_cast<float>(scanned) / static_cast<float>(total_bytes));
				continue;
			}

			for (auto& sig : signatures) {
				if (g_state.cancel.load()) break;
				if (cfg.max_hits != 0 && hit_count_live >= cfg.max_hits) {
					g_state.cancel.store(true);
					break;
				}

				auto hits = detail::find_pattern_in_region(
					data.data(), data.size(), region.base,
					sig.pattern, sig.min_match);

				for (auto hit_addr : hits) {
					if (cfg.max_hits != 0 && hit_count_live >= cfg.max_hits) {
						g_state.cancel.store(true);
						break;
					}
					auto [mod_name, mod_offset] = find_module(hit_addr);

					crypto_hit_t hit;
					hit.signature_name = sig.name;
					hit.algorithm = sig.algorithm;
					hit.category = sig.category;
					hit.address = hit_addr;
					hit.module_name = mod_name;
					hit.module_offset = mod_offset;

					diag::log_tagged_fmt("crypto_scan", "scan_process hit name='%s' algo='%s' addr=0x%llX module='%s'+0x%llX",
						sig.name, sig.algorithm,
						static_cast<unsigned long long>(hit_addr),
						mod_name.c_str(),
						static_cast<unsigned long long>(mod_offset));

					std::lock_guard<std::mutex> lk(g_state.mutex);
					g_state.results.push_back(std::move(hit));
					++hit_count_live;
				}
			}

			scanned += read_size64;
			g_state.progress.store(static_cast<float>(scanned) / static_cast<float>(total_bytes));
		}

		if (!g_state.cancel.load())
			auto_label_references();

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
		size_t hit_count = 0;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			hit_count = g_state.results.size();
		}
		diag::log_tagged_fmt("crypto_scan", "scan_process done sigs=%zu regions=%zu bytes=%llu hits=%zu duration_ms=%llu cancelled=%d",
			signatures.size(), scan_regions.size(), static_cast<unsigned long long>(total_bytes),
			hit_count, static_cast<unsigned long long>(dur_ms),
			static_cast<int>(g_state.cancel.load()));

		g_state.scanning.store(false);
	});
}

inline void scan_process()
{
	process_scan_config_t cfg;
	scan_process(cfg);
}

inline void scan_file(const DisasmFile& file)
{
	if (g_state.scanning.load()) {
		diag::log_tagged("crypto_scan", "scan_file refused already_scanning");
		return;
	}
	if (!file.loaded) {
		diag::log_tagged("crypto_scan", "scan_file refused file_not_loaded");
		return;
	}
	diag::log_tagged_fmt("crypto_scan", "scan_file start filename='%s' sections=%zu",
		file.filename.c_str(), file.sections.size());

	g_state.scanning.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.results.clear();
		g_state.active = true;
	}

	work_queue::post([file]() {
		auto t_start = std::chrono::steady_clock::now();
		auto signatures = get_signatures();

		size_t total_bytes = 0;
		for (auto& sec : file.sections) total_bytes += sec.bytes.size();
		if (total_bytes == 0) total_bytes = 1;
		size_t scanned = 0;

		for (auto& sec : file.sections) {
			if (g_state.cancel.load()) break;
			if (sec.bytes.empty()) continue;

			for (auto& sig : signatures) {
				if (g_state.cancel.load()) break;

				auto hits = detail::find_pattern_in_region(
					sec.bytes.data(), sec.bytes.size(),
					sec.va,
					sig.pattern, sig.min_match);

				for (auto hit_addr : hits) {
					crypto_hit_t hit;
					hit.signature_name = sig.name;
					hit.algorithm = sig.algorithm;
					hit.category = sig.category;
					hit.address = hit_addr;
					hit.module_name = file.filename;
					hit.module_offset = hit_addr - file.image_base;

					std::lock_guard<std::mutex> lk(g_state.mutex);
					g_state.results.push_back(std::move(hit));
				}
			}

			scanned += sec.bytes.size();
			g_state.progress.store(static_cast<float>(scanned) / static_cast<float>(total_bytes));
		}

		auto_label_references();

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
		size_t hit_count = 0;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			hit_count = g_state.results.size();
		}
		diag::log_tagged_fmt("crypto_scan", "scan_file done filename='%s' sigs=%zu bytes=%zu hits=%zu duration_ms=%llu cancelled=%d",
			file.filename.c_str(), signatures.size(), total_bytes,
			hit_count, static_cast<unsigned long long>(dur_ms),
			static_cast<int>(g_state.cancel.load()));

		g_state.scanning.store(false);
	});
}

inline void auto_label_references()
{
	std::vector<crypto_hit_t> results_copy;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		results_copy = g_state.results;
	}

	if (results_copy.empty()) return;

	auto modules = driver_bridge::enumerate_modules();

	struct module_cache_t {
		uint64_t base = 0;
		uint64_t size = 0;
		std::vector<uint8_t> data;
	};
	std::unordered_map<uint64_t, module_cache_t> mod_cache;

	std::unordered_map<uint64_t, std::string> labels;

	for (auto& hit : results_copy) {
		if (g_state.cancel.load()) break;

		for (auto& m : modules) {
			if (hit.address < m.base || hit.address >= m.base + m.size)
				continue;

			auto cache_it = mod_cache.find(m.base);
			if (cache_it == mod_cache.end()) {
				module_cache_t mc;
				mc.base = m.base;
				mc.size = m.size;
				size_t read_size = static_cast<size_t>((std::min)(static_cast<uint64_t>(m.size), static_cast<uint64_t>(0x400000)));
				driver_bridge::read_memory(m.base, read_size, mc.data);
				if (mc.data.empty()) break;
				cache_it = mod_cache.emplace(m.base, std::move(mc)).first;
			}

			auto& mc = cache_it->second;
			const uint8_t* data = mc.data.data();
			size_t data_size = mc.data.size();

			std::string label = "crypto_" + hit.algorithm;
			for (auto& c : label) {
				if (c == ' ' || c == '-' || c == '/' || c == '(' || c == ')') c = '_';
			}

			for (size_t pos = 0; pos + 5 <= data_size; ++pos) {
				uint8_t op = data[pos];
				bool is_rel32 = (op == 0xE8 || op == 0xE9);
				bool is_lea = false;

				if (!is_rel32 && pos + 7 <= data_size) {
					uint8_t b0 = data[pos];
					int off = 0;
					if ((b0 & 0xF0) == 0x40) { off = 1; b0 = data[pos + off]; }
					if (b0 == 0x8D && pos + off + 6 <= data_size) {
						uint8_t modrm = data[pos + off + 1];
						uint8_t mod = (modrm >> 6) & 3;
						uint8_t rm = modrm & 7;
						if (mod == 0 && rm == 5) is_lea = true;
					}
				}

				if (is_rel32) {
					int32_t rel = 0;
					std::memcpy(&rel, data + pos + 1, 4);
					uint64_t ins_addr = mc.base + pos;
					uint64_t target = ins_addr + 5 + rel;
					if (target == hit.address) {
						hit.referencing_functions.push_back(ins_addr);
						labels[ins_addr] = label;
					}
				}
				else if (is_lea) {
					uint8_t b0 = data[pos];
					int off = ((b0 & 0xF0) == 0x40) ? 1 : 0;
					int ins_len = off + 6;
					int32_t disp = 0;
					std::memcpy(&disp, data + pos + off + 2, 4);
					uint64_t ins_addr = mc.base + pos;
					uint64_t target = ins_addr + ins_len + disp;
					if (target == hit.address) {
						hit.referencing_functions.push_back(ins_addr);
						labels[ins_addr] = label;
					}
				}
			}

			break;
		}
	}

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.results = std::move(results_copy);
		for (auto& [addr, lbl] : labels) {
			g_state.function_labels[addr] = lbl;
		}
	}
}

inline std::string get_function_label(uint64_t addr)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	auto it = g_state.function_labels.find(addr);
	if (it != g_state.function_labels.end()) return it->second;
	return {};
}

inline void cancel()
{
	diag::log_tagged("crypto_scan", "cancel signalled");
	g_state.cancel.store(true);
}

namespace detail {

inline float compute_shannon_entropy(const uint8_t* data, size_t len)
{
	if (len == 0) return 0.f;

	uint32_t freq[256] = {};
	for (size_t i = 0; i < len; ++i) freq[data[i]]++;

	float entropy = 0.f;
	float inv_len = 1.f / static_cast<float>(len);
	for (int i = 0; i < 256; ++i) {
		if (freq[i] == 0) continue;
		float p = static_cast<float>(freq[i]) * inv_len;
		entropy -= p * std::log2(p);
	}
	return entropy;
}

}

inline void scan_entropy()
{
	if (g_state.scanning.load()) {
		diag::log_tagged("crypto_scan", "scan_entropy refused already_scanning");
		return;
	}
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("crypto_scan", "scan_entropy refused not_attached driver_loaded=%d pid=%u",
			static_cast<int>(driver_bridge::is_loaded()), driver_bridge::attached_pid());
		return;
	}
	diag::log_tagged_fmt("crypto_scan", "scan_entropy start pid=%u threshold=%.2f",
		driver_bridge::attached_pid(), static_cast<double>(g_state.entropy_threshold));

	g_state.scanning.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.active = true;
	}

	work_queue::post([]() {
		auto t_start = std::chrono::steady_clock::now();
		auto regions = driver_bridge::enumerate_memory_regions(4096);
		auto modules = driver_bridge::enumerate_modules();

		auto find_module = [&](uint64_t addr) -> std::string {
			for (auto& m : modules) {
				if (addr >= m.base && addr < m.base + m.size)
					return m.name;
			}
			return "<unknown>";
		};

		std::vector<driver_bridge::memory_region_t> scan_regions;
		for (auto& r : regions) {
			if (r.state != 0x1000) continue;
			if (r.protect & 0x100) continue;
			uint32_t prot = r.protect & 0xFF;
			if (prot == 0x01 || prot == 0x00) continue;
			if (r.size > 0x10000000) continue;
			scan_regions.push_back(r);
		}

		uint64_t total_bytes = 0;
		for (auto& r : scan_regions) total_bytes += r.size;
		if (total_bytes == 0) total_bytes = 1;
		uint64_t scanned = 0;

		std::vector<entropy_region_t> high_entropy;
		float threshold = g_state.entropy_threshold;

		for (auto& region : scan_regions) {
			if (g_state.cancel.load()) break;

			std::vector<uint8_t> data;
			driver_bridge::read_memory(region.base, static_cast<size_t>(region.size), data);
			if (data.empty()) {
				scanned += region.size;
				g_state.progress.store(static_cast<float>(scanned) / static_cast<float>(total_bytes));
				continue;
			}

			constexpr size_t block = 256;
			for (size_t off = 0; off + block <= data.size(); off += block) {
				float ent = detail::compute_shannon_entropy(data.data() + off, block);
				if (ent >= threshold) {
					entropy_region_t er;
					er.address = region.base + off;
					er.entropy = ent;
					er.block_size = static_cast<uint32_t>(block);
					er.module_name = find_module(er.address);
					high_entropy.push_back(er);
				}
			}

			scanned += region.size;
			g_state.progress.store(static_cast<float>(scanned) / static_cast<float>(total_bytes));
		}

		size_t found = high_entropy.size();
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.entropy_map = std::move(high_entropy);
		}

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
		diag::log_tagged_fmt("crypto_scan", "scan_entropy done regions=%zu bytes=%llu high_entropy=%zu duration_ms=%llu cancelled=%d",
			scan_regions.size(), static_cast<unsigned long long>(total_bytes),
			found, static_cast<unsigned long long>(dur_ms),
			static_cast<int>(g_state.cancel.load()));

		g_state.scanning.store(false);
	});
}

inline void add_custom_signature(const std::string& name, const std::string& algorithm,
                                  const std::string& description, crypto_category_t cat,
                                  const std::vector<uint8_t>& pattern)
{
	if (pattern.empty()) {
		diag::log_tagged_fmt("crypto_scan", "add_custom_signature refused empty_pattern name='%s'",
			name.c_str());
		return;
	}
	custom_signature_t sig;
	sig.name = name;
	sig.algorithm = algorithm;
	sig.description = description;
	sig.category = cat;
	sig.pattern = pattern;

	std::lock_guard<std::mutex> lk(g_state.mutex);
	g_state.custom_sigs.push_back(std::move(sig));
	diag::log_tagged_fmt("crypto_scan", "add_custom_signature name='%s' algo='%s' bytes=%zu total=%zu",
		name.c_str(), algorithm.c_str(), pattern.size(), g_state.custom_sigs.size());
}

inline void remove_custom_signature(int index)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	if (index >= 0 && index < static_cast<int>(g_state.custom_sigs.size())) {
		std::string nm = g_state.custom_sigs[static_cast<size_t>(index)].name;
		g_state.custom_sigs.erase(g_state.custom_sigs.begin() + index);
		diag::log_tagged_fmt("crypto_scan", "remove_custom_signature index=%d name='%s'",
			index, nm.c_str());
	} else {
		diag::log_tagged_fmt("crypto_scan", "remove_custom_signature out_of_range index=%d size=%zu",
			index, g_state.custom_sigs.size());
	}
}

inline void export_results_json(const std::string& path)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);

	nlohmann::json j;
	nlohmann::json hits = nlohmann::json::array();
	for (auto& r : g_state.results) {
		nlohmann::json h;
		h["signature"] = r.signature_name;
		h["algorithm"] = r.algorithm;
		h["category"] = category_name(r.category);
		h["address"] = r.address;
		h["module"] = r.module_name;
		h["offset"] = r.module_offset;
		nlohmann::json refs = nlohmann::json::array();
		for (auto addr : r.referencing_functions) refs.push_back(addr);
		h["references"] = refs;
		hits.push_back(h);
	}
	j["hits"] = hits;

	nlohmann::json ent = nlohmann::json::array();
	for (auto& e : g_state.entropy_map) {
		nlohmann::json er;
		er["address"] = e.address;
		er["entropy"] = e.entropy;
		er["module"] = e.module_name;
		ent.push_back(er);
	}
	j["entropy_regions"] = ent;

	std::ofstream ofs(path);
	if (ofs.is_open()) {
		ofs << j.dump(2);
		diag::log_tagged_fmt("crypto_scan", "export_results_json ok path='%s' hits=%zu entropy=%zu",
			path.c_str(), g_state.results.size(), g_state.entropy_map.size());
	} else {
		diag::log_tagged_fmt("crypto_scan", "export_results_json failed path='%s'", path.c_str());
	}
}

inline void export_results_csv(const std::string& path)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);

	std::ofstream ofs(path);
	if (!ofs.is_open()) {
		diag::log_tagged_fmt("crypto_scan", "export_results_csv failed path='%s'", path.c_str());
		return;
	}

	ofs << "Type,Name,Algorithm,Address,Module,Offset,References\n";
	for (auto& r : g_state.results) {
		char buf[512];
		std::snprintf(buf, sizeof(buf), "Signature,%s,%s,0x%llX,%s,0x%llX,%zu\n",
			r.signature_name.c_str(), r.algorithm.c_str(),
			static_cast<unsigned long long>(r.address),
			r.module_name.c_str(),
			static_cast<unsigned long long>(r.module_offset),
			r.referencing_functions.size());
		ofs << buf;
	}
	for (auto& e : g_state.entropy_map) {
		char buf[256];
		std::snprintf(buf, sizeof(buf), "Entropy,%.3f,,0x%llX,%s,,\n",
			e.entropy, static_cast<unsigned long long>(e.address), e.module_name.c_str());
		ofs << buf;
	}
	diag::log_tagged_fmt("crypto_scan", "export_results_csv ok path='%s' hits=%zu entropy=%zu",
		path.c_str(), g_state.results.size(), g_state.entropy_map.size());
}

inline void save_custom_signatures()
{
	const char* appdata = std::getenv("APPDATA");
	if (!appdata) return;
	std::string path = std::string(appdata) + "\\AiDA\\Standalone\\crypto_custom_sigs.json";

	std::error_code ec;
	std::filesystem::create_directories(std::string(appdata) + "\\AiDA\\Standalone", ec);

	std::lock_guard<std::mutex> lk(g_state.mutex);
	nlohmann::json j = nlohmann::json::array();
	for (auto& s : g_state.custom_sigs) {
		nlohmann::json js;
		js["name"] = s.name;
		js["algorithm"] = s.algorithm;
		js["description"] = s.description;
		js["category"] = static_cast<int>(s.category);
		std::string hex;
		for (auto b : s.pattern) {
			char hx[4];
			std::snprintf(hx, sizeof(hx), "%02X", b);
			hex += hx;
		}
		js["pattern_hex"] = hex;
		j.push_back(js);
	}

	std::ofstream ofs(path);
	if (ofs.is_open()) ofs << j.dump(2);
}

inline void load_custom_signatures()
{
	const char* appdata = std::getenv("APPDATA");
	if (!appdata) return;
	std::string path = std::string(appdata) + "\\AiDA\\Standalone\\crypto_custom_sigs.json";

	std::ifstream ifs(path);
	if (!ifs.is_open()) return;

	try {
		nlohmann::json j;
		ifs >> j;
		if (!j.is_array()) return;

		std::lock_guard<std::mutex> lk(g_state.mutex);
		for (auto& js : j) {
			custom_signature_t sig;
			sig.name = js.value("name", std::string{});
			sig.algorithm = js.value("algorithm", std::string{});
			sig.description = js.value("description", std::string{});
			sig.category = static_cast<crypto_category_t>(js.value("category", 0));

			std::string hex = js.value("pattern_hex", std::string{});
			for (size_t k = 0; k + 2 <= hex.size(); k += 2) {
				uint8_t byte = static_cast<uint8_t>(std::strtoul(hex.substr(k, 2).c_str(), nullptr, 16));
				sig.pattern.push_back(byte);
			}

			if (!sig.name.empty() && !sig.pattern.empty())
				g_state.custom_sigs.push_back(std::move(sig));
		}
	} catch (...) {}
}

}
