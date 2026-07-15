#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "imgui.h"
#include "crypto_scanner.hpp"
#include "disasm_view.hpp"
#include "hex_view.hpp"
#include "ui_anim.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview_platform.hpp"
#else
#include "../anti-tamper/webhook.hpp"
#include "../helpers/diag_log.hpp"
#endif
#include "../helpers/globals.h"
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/fonts.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/scan_preview_runtime.hpp"
#else
#include "../infra/taskflow_runtime.hpp"
#endif

namespace crypto_scanner_view {

struct state_t {
	float  scroll_y = 0.f;
	float  target_scroll_y = 0.f;
	bool   scrollbar_dragging = false;
	float  scrollbar_drag_offset = 0.f;
	int    category_filter = -1;
	char   search_filter[128] = {};
	int    sort_column = -1;
	bool   sort_ascending = true;
	int    ctx_hit_idx = -1;
	float  sort_arrow_anim = 0.f;
	int    last_sort_column = -1;
	std::mutex mutex;
	std::string last_error;
	std::atomic<bool> scanning{false};
	std::atomic<bool> cancellation_requested{false};
	std::atomic<float> progress{0.0f};
	std::shared_ptr<const crypto_scanner::workspace_scan_snapshot_t> snapshot;
	std::shared_ptr<const std::vector<crypto_scanner::crypto_hit_t>> filtered_results;
	std::string requested_filter;
	int requested_category = -2;
	int requested_sort_column = -2;
	bool requested_sort_ascending = true;
	const crypto_scanner::workspace_scan_snapshot_t* requested_snapshot = nullptr;
	std::atomic<std::uint64_t> filter_serial{0};
	std::atomic<bool> filtering{false};
	std::atomic<std::size_t> total_hits{0};
	std::atomic<std::size_t> cipher_hits{0};
	std::atomic<std::size_t> hash_hits{0};
	std::atomic<std::size_t> referenced_hits{0};
};

inline state_t g_state;

inline std::mutex& workspace_states_mutex()
{
	static std::mutex mutex;
	return mutex;
}

inline std::unordered_map<std::string, std::shared_ptr<state_t>>& workspace_view_states()
{
	static std::unordered_map<std::string, std::shared_ptr<state_t>> states;
	return states;
}

inline std::shared_ptr<state_t> state_for(const disasm_view::workspace_context_t& context)
{
	if (!context.workspace) return {};
	const std::string key = context.workspace->identity().binary_id().to_hex();
	std::lock_guard<std::mutex> lock(workspace_states_mutex());
	auto view = workspace_view_states()[key];
	if (!view) {
		view = std::make_shared<state_t>();
		workspace_view_states()[key] = view;
	}
	return view;
}

namespace detail {

inline ImU32 algo_color(crypto_scanner::crypto_category_t cat) {
	const auto& t = aida::ui::resolved();
	switch (cat) {
	case crypto_scanner::crypto_category_t::symmetric:    return t.info;
	case crypto_scanner::crypto_category_t::hash:         return t.success;
	case crypto_scanner::crypto_category_t::stream_cipher:return t.warning;
	case crypto_scanner::crypto_category_t::block_cipher: return t.accent_u32;
	case crypto_scanner::crypto_category_t::checksum:     return t.warning;
	case crypto_scanner::crypto_category_t::encoding:     return t.text_secondary;
	case crypto_scanner::crypto_category_t::asymmetric:   return t.error;
	default:                                              return t.text_secondary;
	}
}

inline aida::ui::components::pill_kind_t category_pill_kind(crypto_scanner::crypto_category_t cat) {
	switch (cat) {
	case crypto_scanner::crypto_category_t::symmetric:    return aida::ui::components::pill_kind_t::info;
	case crypto_scanner::crypto_category_t::hash:         return aida::ui::components::pill_kind_t::success;
	case crypto_scanner::crypto_category_t::stream_cipher:return aida::ui::components::pill_kind_t::warning;
	case crypto_scanner::crypto_category_t::block_cipher: return aida::ui::components::pill_kind_t::accent;
	case crypto_scanner::crypto_category_t::checksum:     return aida::ui::components::pill_kind_t::warning;
	case crypto_scanner::crypto_category_t::encoding:     return aida::ui::components::pill_kind_t::neutral;
	case crypto_scanner::crypto_category_t::asymmetric:   return aida::ui::components::pill_kind_t::error;
	default:                                              return aida::ui::components::pill_kind_t::neutral;
	}
}

enum class glyph_kind_t {
	aes_grid,
	sha_chain,
	rsa_keys,
	md_block,
	stream_flow,
	checksum_loop,
	encode_alpha,
	generic_hex
};

inline glyph_kind_t glyph_for(const std::string& algo, crypto_scanner::crypto_category_t cat) {
	std::string a;
	a.reserve(algo.size());
	for (char ch : algo) a.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
	if (a.find("aes") != std::string::npos)        return glyph_kind_t::aes_grid;
	if (a.find("sha") != std::string::npos)        return glyph_kind_t::sha_chain;
	if (a.find("rsa") != std::string::npos)        return glyph_kind_t::rsa_keys;
	if (a.find("ecc") != std::string::npos ||
	    a.find("ecdsa") != std::string::npos ||
	    a.find("dsa") != std::string::npos)        return glyph_kind_t::rsa_keys;
	if (a.find("md") != std::string::npos)         return glyph_kind_t::md_block;
	if (a.find("rc4") != std::string::npos ||
	    a.find("salsa") != std::string::npos ||
	    a.find("chacha") != std::string::npos)     return glyph_kind_t::stream_flow;
	if (a.find("crc") != std::string::npos)        return glyph_kind_t::checksum_loop;
	if (a.find("base") != std::string::npos)       return glyph_kind_t::encode_alpha;
	switch (cat) {
	case crypto_scanner::crypto_category_t::symmetric:
	case crypto_scanner::crypto_category_t::block_cipher: return glyph_kind_t::aes_grid;
	case crypto_scanner::crypto_category_t::hash:         return glyph_kind_t::sha_chain;
	case crypto_scanner::crypto_category_t::asymmetric:   return glyph_kind_t::rsa_keys;
	case crypto_scanner::crypto_category_t::stream_cipher:return glyph_kind_t::stream_flow;
	case crypto_scanner::crypto_category_t::checksum:     return glyph_kind_t::checksum_loop;
	case crypto_scanner::crypto_category_t::encoding:     return glyph_kind_t::encode_alpha;
	default: return glyph_kind_t::generic_hex;
	}
}

inline void glyph_aes(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	float side = r * 1.6f;
	float cell = side / 4.f;
	ImVec2 a(c.x - side * 0.5f, c.y - side * 0.5f);
	float t = aida::ui::clock::seconds();
	for (int row = 0; row < 4; ++row) {
		for (int co = 0; co < 4; ++co) {
			float ph = sinf(t * 1.6f + static_cast<float>(row * 4 + co) * 0.4f) * 0.5f + 0.5f;
			ImU32 fill = aida::ui::with_alpha(col, 0.18f + ph * 0.30f);
			ImVec2 ca(a.x + cell * static_cast<float>(co) + 1.f,
				a.y + cell * static_cast<float>(row) + 1.f);
			ImVec2 cb(ca.x + cell - 2.f, ca.y + cell - 2.f);
			dl->AddRectFilled(ca, cb, fill, 1.5f);
		}
	}
	dl->AddRect(a, ImVec2(a.x + side, a.y + side),
		aida::ui::with_alpha(col, 0.7f), 2.f, 0, 1.f);
}

inline void glyph_sha(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	float w = r * 1.8f;
	int n = 4;
	float gap = w / static_cast<float>(n + 1);
	float t = aida::ui::clock::seconds();
	for (int i = 0; i < n; ++i) {
		float lx = c.x - w * 0.5f + gap * static_cast<float>(i + 1);
		float ph = static_cast<float>(i) * 0.4f;
		float vy = sinf(t * 1.4f + ph) * 1.5f;
		dl->AddCircle(ImVec2(lx, c.y + vy), r * 0.32f,
			aida::ui::with_alpha(col, 0.85f), 18, 1.5f);
		if (i + 1 < n) {
			float lx2 = c.x - w * 0.5f + gap * static_cast<float>(i + 2);
			float vy2 = sinf(t * 1.4f + static_cast<float>(i + 1) * 0.4f) * 1.5f;
			dl->AddLine(
				ImVec2(lx + r * 0.32f, c.y + vy),
				ImVec2(lx2 - r * 0.32f, c.y + vy2),
				aida::ui::with_alpha(col, 0.6f), 1.5f);
		}
	}
}

inline void glyph_rsa(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	float t = aida::ui::clock::seconds();
	float ang = sinf(t * 1.0f) * 0.12f;
	auto draw_key = [&](float ox, float angle_off) {
		float kr = r * 0.34f;
		ImVec2 head(c.x + ox, c.y - r * 0.18f);
		dl->AddCircle(head, kr, aida::ui::with_alpha(col, 0.85f), 20, 1.6f);
		float dx = sinf(angle_off) * 1.f;
		ImVec2 stem_a(head.x + dx, head.y + kr - 1.f);
		ImVec2 stem_b(head.x + dx, head.y + r * 1.05f);
		dl->AddLine(stem_a, stem_b, aida::ui::with_alpha(col, 0.85f), 1.5f);
		dl->AddLine(ImVec2(stem_b.x - 5.f, stem_b.y - 6.f), stem_b,
			aida::ui::with_alpha(col, 0.85f), 1.5f);
		dl->AddLine(ImVec2(stem_b.x + 5.f, stem_b.y - 12.f),
			ImVec2(stem_b.x, stem_b.y - 6.f),
			aida::ui::with_alpha(col, 0.85f), 1.5f);
	};
	draw_key(-r * 0.5f,  ang);
	draw_key( r * 0.5f, -ang);
}

inline void glyph_md(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	float w = r * 1.4f;
	float h_each = (r * 1.6f) / 5.f;
	float t = aida::ui::clock::seconds();
	for (int i = 0; i < 5; ++i) {
		float y0 = c.y + r * 0.8f - h_each * static_cast<float>(i + 1);
		float y1 = y0 + h_each - 1.5f;
		float ph = sinf(t * 1.4f + static_cast<float>(i) * 0.55f) * 0.5f + 0.5f;
		ImU32 fill = aida::ui::with_alpha(col, 0.20f + ph * 0.45f);
		dl->AddRectFilled(ImVec2(c.x - w * 0.5f, y0),
			ImVec2(c.x + w * 0.5f, y1), fill, 2.f);
	}
}

inline void glyph_stream(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	float t = aida::ui::clock::seconds();
	for (int i = 0; i < 3; ++i) {
		ImVec2 prev = ImVec2(c.x - r * 0.9f, c.y + static_cast<float>(i - 1) * r * 0.45f);
		for (int s = 1; s <= 16; ++s) {
			float fx = static_cast<float>(s) / 16.f;
			float wave = sinf(t * 2.f + fx * 7.5f + static_cast<float>(i) * 1.0f) * r * 0.18f;
			ImVec2 nx = ImVec2(c.x - r * 0.9f + fx * r * 1.8f,
			                   c.y + static_cast<float>(i - 1) * r * 0.45f + wave);
			dl->AddLine(prev, nx, aida::ui::with_alpha(col, 0.65f), 1.4f);
			prev = nx;
		}
	}
}

inline void glyph_checksum(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	float t = aida::ui::clock::seconds() * 1.6f;
	dl->AddCircle(c, r * 0.85f, aida::ui::with_alpha(col, 0.75f), 32, 1.5f);
	float arc_start = t;
	float arc_end = t + 1.4f;
	dl->PathArcTo(c, r * 0.85f, arc_start, arc_end, 24);
	dl->PathStroke(aida::ui::with_alpha(col, 1.f), 0, 2.f);
	float ax = c.x + cosf(arc_end) * r * 0.85f;
	float ay = c.y + sinf(arc_end) * r * 0.85f;
	dl->AddCircleFilled(ImVec2(ax, ay), 3.f, aida::ui::with_alpha(col, 1.f), 12);
}

inline void glyph_encode(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	const char* glyphs[3] = { "01", "AB", "+/" };
	float t = aida::ui::clock::seconds();
	int idx = static_cast<int>(floorf(t * 1.0f)) % 3;
	if (idx < 0) idx += 3;
	const char* lbl = glyphs[idx];
	dl->AddRectFilled(ImVec2(c.x - r * 0.7f, c.y - r * 0.5f),
		ImVec2(c.x + r * 0.7f, c.y + r * 0.5f),
		aida::ui::with_alpha(col, 0.18f), 4.f);
	dl->AddRect(ImVec2(c.x - r * 0.7f, c.y - r * 0.5f),
		ImVec2(c.x + r * 0.7f, c.y + r * 0.5f),
		aida::ui::with_alpha(col, 0.7f), 4.f, 0, 1.f);
	ImVec2 ts = ImGui::CalcTextSize(lbl);
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float code_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());
	dl->AddText(code_font, code_size,
		ImVec2(c.x - ts.x * 0.5f, c.y - ts.y * 0.5f),
		aida::ui::with_alpha(col, 1.f), lbl);
}

inline void glyph_hex(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	dl->AddCircle(c, r * 0.7f, aida::ui::with_alpha(col, 0.7f), 24, 1.5f);
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float code_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());
	dl->AddText(code_font, code_size,
		ImVec2(c.x - 5.f, c.y - 5.f),
		aida::ui::with_alpha(col, 1.f), "??");
}

inline void render_glyph(ImDrawList* dl, ImVec2 center, float radius,
	const std::string& algo, crypto_scanner::crypto_category_t cat, ImU32 col)
{
	switch (glyph_for(algo, cat)) {
	case glyph_kind_t::aes_grid:      glyph_aes(dl, center, radius, col); break;
	case glyph_kind_t::sha_chain:     glyph_sha(dl, center, radius, col); break;
	case glyph_kind_t::rsa_keys:      glyph_rsa(dl, center, radius, col); break;
	case glyph_kind_t::md_block:      glyph_md(dl, center, radius, col); break;
	case glyph_kind_t::stream_flow:   glyph_stream(dl, center, radius, col); break;
	case glyph_kind_t::checksum_loop: glyph_checksum(dl, center, radius, col); break;
	case glyph_kind_t::encode_alpha:  glyph_encode(dl, center, radius, col); break;
	default:                          glyph_hex(dl, center, radius, col); break;
	}
}

struct scan_region_t {
	std::uint64_t provider_offset = 0;
	std::uint64_t size = 0;
	std::uint64_t runtime_address = 0;
};

inline std::vector<scan_region_t> scan_regions(
	const disasm_view::workspace_context_t& context)
{
	std::vector<scan_region_t> regions;
	if (!context.workspace) return regions;
	const std::uint64_t provider_size = context.workspace->provider().size();
	if (context.workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot) {
		const auto& module = context.workspace->identity().module();
		if (module && provider_size != 0) regions.push_back({0, provider_size, module->base});
		return regions;
	}
	if (!context.image) return regions;
	for (const auto& section : context.image->sections()) {
		if (section.raw_size == 0 || section.raw_offset >= provider_size) continue;
		const std::uint64_t size = (std::min)(provider_size - section.raw_offset,
			static_cast<std::uint64_t>(section.raw_size));
		if (size != 0) regions.push_back({section.raw_offset, size,
			context.image->image_base() + section.virtual_address});
	}
	return regions;
}

inline void set_scan_error(const std::shared_ptr<state_t>& state, std::string error)
{
	if (!state) return;
	std::lock_guard<std::mutex> lock(state->mutex);
	state->last_error = std::move(error);
}

inline void start_workspace_scan(
	const disasm_view::workspace_context_t& context,
	const std::shared_ptr<state_t>& view_state,
	bool entropy_only)
{
	if (!context.workspace || !view_state) return;
	bool expected = false;
	if (!view_state->scanning.compare_exchange_strong(expected, true,
		std::memory_order_acq_rel, std::memory_order_acquire)) return;
	view_state->cancellation_requested.store(false, std::memory_order_release);
	view_state->progress.store(0.0f, std::memory_order_release);
	std::shared_ptr<const crypto_scanner::workspace_scan_snapshot_t> previous;
	{
		std::lock_guard<std::mutex> lock(view_state->mutex);
		previous = view_state->snapshot;
	}
	set_scan_error(view_state, {});
	aida::infra::taskflow_runtime::task_descriptor_t descriptor;
	descriptor.owner_subsystem = "scanner";
	descriptor.label = entropy_only ? "scanner.crypto.entropy.workspace" :
		"scanner.crypto.signatures.workspace";
	descriptor.thread_class = "bounded_task";
	descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
	descriptor.priority = 2;
	const std::string target_id = context.workspace->identity().binary_id().to_hex();
	descriptor.target_id = target_id.c_str();
	descriptor.generation = context.workspace->generation();
	descriptor.cancellable_body = [context, view_state, previous, entropy_only](
		const aida::infra::taskflow_runtime::cancellation_token_t& runtime_cancel) {
		constexpr std::uint64_t chunk_size = 4ULL * 1024ULL * 1024ULL;
		constexpr std::size_t max_hits = 100000;
		constexpr std::size_t max_entropy_regions = 100000;
		auto regions = scan_regions(context);
		if (regions.empty()) {
			set_scan_error(view_state, "The selected workspace has no bounded scan ranges.");
			view_state->scanning.store(false, std::memory_order_release);
			return;
		}
		auto signatures = crypto_scanner::get_signatures();
		if (previous) {
			for (const auto& custom : previous->custom_signatures) {
				if (custom.pattern.empty()) continue;
				signatures.push_back({custom.name.c_str(), custom.algorithm.c_str(),
					custom.description.c_str(), custom.category, custom.pattern.data(),
					custom.pattern.size(), custom.pattern.size()});
			}
		}
		std::size_t overlap = 0;
		for (const auto& signature : signatures)
			overlap = (std::max)(overlap, signature.min_match > 0 ? signature.min_match - 1 : 0);
		std::uint64_t total = 0;
		for (const auto& region : regions) {
			if (total > UINT64_MAX - region.size) {
				set_scan_error(view_state, "Workspace scan range total overflowed.");
				view_state->scanning.store(false, std::memory_order_release);
				return;
			}
			total += region.size;
		}
		std::uint64_t processed = 0;
		std::vector<crypto_scanner::workspace_crypto_hit_t> hits =
			entropy_only && previous ? previous->results :
			std::vector<crypto_scanner::workspace_crypto_hit_t>{};
		std::vector<crypto_scanner::workspace_entropy_region_t> entropy;
		for (const auto& region : regions) {
			for (std::uint64_t cursor = 0; cursor < region.size;) {
				if (runtime_cancel.requested.load(std::memory_order_acquire) ||
					view_state->cancellation_requested.load(std::memory_order_acquire) ||
					context.workspace->cancellation_token().stop_requested()) {
					view_state->scanning.store(false, std::memory_order_release);
					return;
				}
				const std::uint64_t logical = (std::min)(chunk_size, region.size - cursor);
				const std::uint64_t tail = (std::min)(static_cast<std::uint64_t>(overlap),
					region.size - cursor - logical);
				auto lease = context.workspace->provider().lease(region.provider_offset + cursor,
					logical + tail, context.workspace->cancellation_token());
				if (!lease) {
					set_scan_error(view_state, lease.error().message);
					view_state->scanning.store(false, std::memory_order_release);
					return;
				}
				const auto& bytes = lease.value();
				if (!entropy_only) {
					for (const auto& signature : signatures) {
						if (!signature.pattern || signature.min_match == 0 ||
							signature.min_match > bytes.size()) continue;
						const std::size_t limit = bytes.size() - signature.min_match;
						for (std::size_t offset = 0; offset <= limit; ++offset) {
							if (offset >= logical || hits.size() >= max_hits) break;
							if (std::memcmp(bytes.data() + offset, signature.pattern,
								signature.min_match) != 0) continue;
							const std::uint64_t runtime = region.runtime_address + cursor + offset;
							const auto address = disasm_view::typed_address(context, runtime);
							if (!address) continue;
							crypto_scanner::workspace_crypto_hit_t hit;
							hit.signature_name = signature.name;
							hit.algorithm = signature.algorithm;
							hit.category = signature.category;
							hit.address = *address;
							hit.module_name = context.workspace->identity().bin_name();
							const auto& module = context.workspace->identity().module();
							const std::uint64_t module_base = module ? module->base :
								context.workspace->identity().image_base();
							hit.module_offset = runtime >= module_base ? runtime - module_base : offset;
							hits.push_back(std::move(hit));
						}
						if (hits.size() >= max_hits) break;
					}
				} else {
					for (std::size_t offset = 0; offset + 256 <= logical &&
						entropy.size() < max_entropy_regions; offset += 256) {
						const float value = crypto_scanner::detail::compute_shannon_entropy(
							bytes.data() + offset, 256);
						if (value < 7.0f) continue;
						const auto address = disasm_view::typed_address(context,
							region.runtime_address + cursor + offset);
						if (address) entropy.push_back({*address, value, 256,
							context.workspace->identity().bin_name()});
					}
				}
				cursor += logical;
				processed += logical;
				view_state->progress.store(total == 0 ? 1.0f : static_cast<float>(
					static_cast<double>(processed) / static_cast<double>(total)));
			}
		}
		if (!entropy_only && context.publication && context.publication->snapshot) {
			std::map<aida::analysis::address_t,
				std::vector<aida::analysis::address_t>> references;
			for (const auto& xref : context.publication->snapshot->xrefs)
				references[xref.target].push_back(xref.source);
			for (auto& hit : hits) {
				auto found = references.find(hit.address);
				if (found != references.end()) hit.referencing_functions = std::move(found->second);
			}
		}
		std::size_t cipher_count = 0;
		std::size_t hash_count = 0;
		std::size_t referenced_count = 0;
		for (const auto& hit : hits) {
			const int category = static_cast<int>(hit.category);
			if (category == 0 || category == 3 || category == 4) ++cipher_count;
			else if (category == 1) ++hash_count;
			if (!hit.referencing_functions.empty()) ++referenced_count;
		}
		view_state->total_hits.store(hits.size(), std::memory_order_release);
		view_state->cipher_hits.store(cipher_count, std::memory_order_release);
		view_state->hash_hits.store(hash_count, std::memory_order_release);
		view_state->referenced_hits.store(referenced_count, std::memory_order_release);
		auto publication = std::make_shared<crypto_scanner::workspace_scan_snapshot_t>();
		publication->results = std::move(hits);
		publication->entropy_map = std::move(entropy);
		if (previous) publication->custom_signatures = previous->custom_signatures;
		publication->progress = 1.0f;
		publication->scanning = false;
		publication->cancellation_requested = false;
		{
			std::lock_guard<std::mutex> lock(view_state->mutex);
			view_state->snapshot = std::move(publication);
			view_state->filtered_results.reset();
			view_state->requested_snapshot = nullptr;
			view_state->filter_serial.fetch_add(1, std::memory_order_acq_rel);
		}
		view_state->progress.store(1.0f, std::memory_order_release);
		view_state->scanning.store(false, std::memory_order_release);
	};
	const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
	if (!submitted.submitted) {
		set_scan_error(view_state, submitted.reject_reason);
		view_state->scanning.store(false, std::memory_order_release);
	}
}

inline void open_hit_in_hex(const disasm_view::workspace_context_t& context,
	std::uint64_t address)
{
	if (context.workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot) {
		hex_view::read_live_memory(context, address, 256);
		return;
	}
	hex_view::activate(context);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::scan::record("crypto.open_hex", std::to_string(address));
#endif
}

inline std::string lowercase(std::string value)
{
	for (char& character : value)
		character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
	return value;
}

inline void request_filtered_results(
	const disasm_view::workspace_context_t& context,
	const std::shared_ptr<state_t>& state,
	const std::shared_ptr<const crypto_scanner::workspace_scan_snapshot_t>& snapshot,
	std::string filter,
	int category,
	int sort_column,
	bool sort_ascending)
{
	if (!context.workspace || !state || !snapshot) return;
	filter = lowercase(std::move(filter));
	std::uint64_t serial = 0;
	{
		std::lock_guard<std::mutex> lock(state->mutex);
		if (state->requested_snapshot == snapshot.get() &&
			state->requested_filter == filter && state->requested_category == category &&
			state->requested_sort_column == sort_column &&
			state->requested_sort_ascending == sort_ascending) return;
		state->requested_snapshot = snapshot.get();
		state->requested_filter = filter;
		state->requested_category = category;
		state->requested_sort_column = sort_column;
		state->requested_sort_ascending = sort_ascending;
		serial = state->filter_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
		state->filtering.store(true, std::memory_order_release);
	}
	aida::infra::taskflow_runtime::task_descriptor_t descriptor;
	descriptor.owner_subsystem = "scanner";
	descriptor.label = "scanner.crypto.filter.workspace";
	descriptor.thread_class = "bounded_task";
	descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
	descriptor.priority = 3;
	const std::string target_id = context.workspace->identity().binary_id().to_hex();
	descriptor.target_id = target_id.c_str();
	descriptor.generation = context.workspace->generation();
	descriptor.body = [context, state, snapshot, filter = std::move(filter), category,
		sort_column, sort_ascending, serial, generation = context.workspace->generation()]() {
		auto filtered = std::make_shared<std::vector<crypto_scanner::crypto_hit_t>>();
		filtered->reserve(snapshot->results.size());
		for (const auto& workspace_hit : snapshot->results) {
			if (state->filter_serial.load(std::memory_order_acquire) != serial) return;
			if (context.workspace->cancellation_token().stop_requested()) {
				state->filtering.store(false, std::memory_order_release);
				return;
			}
			if (category >= 0 && static_cast<int>(workspace_hit.category) != category) continue;
			if (!filter.empty() && lowercase(workspace_hit.signature_name).find(filter) == std::string::npos &&
				lowercase(workspace_hit.algorithm).find(filter) == std::string::npos &&
				lowercase(workspace_hit.module_name).find(filter) == std::string::npos) continue;
			crypto_scanner::crypto_hit_t hit;
			hit.signature_name = workspace_hit.signature_name;
			hit.algorithm = workspace_hit.algorithm;
			hit.category = workspace_hit.category;
			const auto runtime = disasm_view::runtime_address(context, workspace_hit.address);
			if (!runtime) continue;
			hit.address = *runtime;
			hit.module_name = workspace_hit.module_name;
			hit.module_offset = workspace_hit.module_offset;
			for (const auto& reference : workspace_hit.referencing_functions) {
				const auto address = disasm_view::runtime_address(context, reference);
				if (address) hit.referencing_functions.push_back(*address);
			}
			filtered->push_back(std::move(hit));
		}
		if (sort_column >= 0) {
			std::sort(filtered->begin(), filtered->end(),
				[sort_column, sort_ascending](const auto& left, const auto& right) {
					int comparison = 0;
					switch (sort_column) {
					case 0: comparison = left.algorithm.compare(right.algorithm); break;
					case 1: comparison = left.signature_name.compare(right.signature_name); break;
					case 2: comparison = left.address < right.address ? -1 :
						(left.address > right.address ? 1 : 0); break;
					case 3: comparison = left.module_name.compare(right.module_name); break;
					default: break;
					}
					return sort_ascending ? comparison < 0 : comparison > 0;
				});
		}
		if (context.workspace->generation() != generation ||
			state->filter_serial.load(std::memory_order_acquire) != serial) return;
		{
			std::lock_guard<std::mutex> lock(state->mutex);
			state->filtered_results = std::move(filtered);
		}
		state->filtering.store(false, std::memory_order_release);
	};
	const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
	if (!submitted.submitted) {
		set_scan_error(state, submitted.reject_reason);
		state->filtering.store(false, std::memory_order_release);
	}
}

inline void export_results(const disasm_view::workspace_context_t& context,
	std::shared_ptr<const crypto_scanner::workspace_scan_snapshot_t> snapshot,
	std::string path,
	bool csv)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const std::size_t count = snapshot ? snapshot->results.size() : 0;
	aida::preview::scan::record(csv ? "crypto.export.csv" : "crypto.export.json",
		context.workspace->identity().bin_name() + ": " + std::to_string(count) + " results");
	(void)path;
#else
	aida::infra::taskflow_runtime::task_descriptor_t descriptor;
	descriptor.owner_subsystem = "scanner";
	descriptor.label = csv ? "scanner.crypto.export.csv" : "scanner.crypto.export.json";
	descriptor.thread_class = "bounded_task";
	descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
	descriptor.priority = 2;
	const std::string target_id = context.workspace->identity().binary_id().to_hex();
	descriptor.target_id = target_id.c_str();
	descriptor.generation = context.workspace->generation();
	descriptor.body = [context, snapshot = std::move(snapshot), path = std::move(path), csv]() {
		if (!snapshot) return;
		std::ofstream stream(path, std::ios::binary | std::ios::trunc);
		if (!stream.is_open()) return;
		if (csv) {
			stream << "algorithm,signature,address,module,module_offset,references\n";
			for (const auto& hit : snapshot->results) {
				const auto address = disasm_view::runtime_address(context, hit.address);
				if (!address) continue;
				stream << '"' << hit.algorithm << "\",\"" << hit.signature_name << "\",0x"
					<< std::hex << *address << std::dec << ",\"" << hit.module_name << "\",0x"
					<< std::hex << hit.module_offset << std::dec << ','
					<< hit.referencing_functions.size() << '\n';
			}
			return;
		}
		nlohmann::json output;
		output["binary_id"] = context.workspace->identity().binary_id().to_hex();
		output["bin_name"] = context.workspace->identity().bin_name();
		output["results"] = nlohmann::json::array();
		for (const auto& hit : snapshot->results) {
			const auto address = disasm_view::runtime_address(context, hit.address);
			if (!address) continue;
			nlohmann::json item;
			item["algorithm"] = hit.algorithm;
			item["signature"] = hit.signature_name;
			item["address"] = *address;
			item["module"] = hit.module_name;
			item["module_offset"] = hit.module_offset;
			item["references"] = hit.referencing_functions.size();
			output["results"].push_back(std::move(item));
		}
		stream << output.dump(2);
	};
	aida::infra::taskflow_runtime::submit(std::move(descriptor));
#endif
}

}

inline void render(float, float, float width, float height,
                   float alpha, float, float, float,
				   const disasm_view::workspace_context_t& context)
{
	ImGui::BeginChild("##crypto_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	const auto view_state = state_for(context);
	if (!view_state) {
		aida::ui::empty_state::config_t config;
		config.glyph = aida::ui::empty_state::glyph_t::shield;
		config.title = "No analysis target";
		config.body = "Open a binary or attach a live target before scanning.";
		aida::ui::empty_state::render(ImGui::GetWindowPos(), ImGui::GetWindowSize(), config);
		ImGui::EndChild();
		return;
	}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	{
		std::lock_guard<std::mutex> lock(view_state->mutex);
		if (!view_state->snapshot) {
			const auto make_address = [&](std::uint64_t offset) {
				aida::analysis::address_t address;
				address.space = aida::analysis::address_space_id_t::virtual_address;
				address.value = context.workspace->identity().image_base() + offset;
				return address;
			};
			auto snapshot = std::make_shared<crypto_scanner::workspace_scan_snapshot_t>();
			snapshot->results = {
				{"AES S-box", "AES", crypto_scanner::crypto_category_t::symmetric,
					make_address(0x5200), context.workspace->identity().bin_name(), 0x5200, {}},
				{"SHA-256 IV", "SHA-256", crypto_scanner::crypto_category_t::hash,
					make_address(0x87A0), context.workspace->identity().bin_name(), 0x87A0, {}},
				{"ChaCha constant", "ChaCha20", crypto_scanner::crypto_category_t::stream_cipher,
					make_address(0xC180), context.workspace->identity().bin_name(), 0xC180, {}}
			};
			snapshot->entropy_map = {
				{make_address(0x12000), 7.84f, 256, context.workspace->identity().bin_name()}
			};
			view_state->snapshot = std::move(snapshot);
			view_state->total_hits.store(3);
			view_state->cipher_hits.store(2);
			view_state->hash_hits.store(1);
			view_state->referenced_hits.store(0);
		}
	}
#endif
	std::shared_ptr<const crypto_scanner::workspace_scan_snapshot_t> scan_snapshot;
	{
		std::lock_guard<std::mutex> lock(view_state->mutex);
		scan_snapshot = view_state->snapshot;
	}
	static const auto empty_snapshot =
		std::make_shared<const crypto_scanner::workspace_scan_snapshot_t>();
	if (!scan_snapshot) scan_snapshot = empty_snapshot;
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = *view_state;
	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height),
		aida::ui::with_alpha(t.bg_base, alpha));

	float toolbar_h = 48.f;
	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + toolbar_h),
		aida::ui::with_alpha(t.panel_header, alpha));
	dl->AddLine(ImVec2(ox, oy + toolbar_h), ImVec2(ox + width, oy + toolbar_h),
		aida::ui::with_alpha(t.border_subtle, alpha), 1.f);

	float cx = ox + 16.f;
	float cy = oy + (toolbar_h - 32.f) * 0.5f;

	dl->AddText(aida::ui::fonts::body_em(), 14.f,
		ImVec2(cx, oy + (toolbar_h - 14.f) * 0.5f),
		aida::ui::with_alpha(t.text_primary, alpha), "Crypto Scanner");
	cx += 140.f;

	const bool scanning = view_state->scanning.load(std::memory_order_acquire);
	const bool attached_now = context.workspace->target_kind() ==
		aida::analysis::target_kind_t::live_snapshot;
	const bool pe_loaded = context.workspace->target_kind() ==
		aida::analysis::target_kind_t::static_file && static_cast<bool>(context.image);

	const float btn_gap = 14.f;
	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		const char* lbl = scanning ? "Cancel" : "Scan Process";
		if (aida::ui::button(lbl,
				scanning ? aida::ui::button_kind_t::destructive : aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), !scanning && !attached_now, nullptr, false)) {
			if (scanning) {
				view_state->cancellation_requested.store(true, std::memory_order_release);
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] crypto_scanner cancel");
			} else {
				detail::start_workspace_scan(context, view_state, false);
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] crypto_scanner scan_process");
			}
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}
	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		bool fl = !pe_loaded;
		if (aida::ui::button("Scan File", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), scanning || fl)) {
			detail::start_workspace_scan(context, view_state, false);
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] crypto_scanner scan_file");
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}
	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Entropy", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), scanning || !attached_now)) {
			detail::start_workspace_scan(context, view_state, true);
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] crypto_scanner scan_entropy");
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}
	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("JSON", aida::ui::button_kind_t::ghost,
				aida::ui::size_t_::md)) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			detail::export_results(context, scan_snapshot, {}, false);
#else
			char* appdata = nullptr;
			size_t len = 0;
			_dupenv_s(&appdata, &len, "APPDATA");
			if (appdata) {
				std::string path = std::string(appdata) + "\\AiDA\\Standalone\\crypto_export_" +
					context.workspace->identity().binary_id().to_hex().substr(0, 16) + ".json";
				free(appdata);
				detail::export_results(context, scan_snapshot, path, false);
			}
#endif
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}
	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("CSV", aida::ui::button_kind_t::ghost,
				aida::ui::size_t_::md)) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			detail::export_results(context, scan_snapshot, {}, true);
#else
			char* appdata = nullptr;
			size_t len = 0;
			_dupenv_s(&appdata, &len, "APPDATA");
			if (appdata) {
				std::string path = std::string(appdata) + "\\AiDA\\Standalone\\crypto_export_" +
					context.workspace->identity().binary_id().to_hex().substr(0, 16) + ".csv";
				free(appdata);
				detail::export_results(context, scan_snapshot, path, true);
			}
#endif
		}
	}

	if (scanning) {
		float prog = view_state->progress.load(std::memory_order_acquire);
		float bar_w = 160.f;
		float bar_x = ox + width - bar_w - 16.f;
		float bar_y = oy + (toolbar_h - 6.f) * 0.5f;
		aida::ui::render_progress_bar(ImVec2(bar_x, bar_y), bar_w, 6.f, prog, false, true);
	}

	cy = oy + toolbar_h + 6.f;
	std::string scan_error;
	{
		std::lock_guard<std::mutex> lock(view_state->mutex);
		scan_error = view_state->last_error;
	}
	if (!scan_error.empty()) {
		ui_anim::render_inline_callout(dl, ox + 16.f, cy, width - 32.f, 22.f,
			scan_error.c_str(), ui_anim::callout_kind_t::error,
			0.9f, 0.25f, 0.25f, alpha);
		cy += 28.f;
	}
	if (!attached_now && !pe_loaded) {
		ui_anim::render_inline_callout(dl, ox + 16.f, cy, width - 32.f, 22.f,
			"Scan needs either a live attach or a loaded PE.",
			ui_anim::callout_kind_t::warn, 0.85f, 0.6f, 0.2f, alpha);
		cy += 28.f;
	} else {
		cy += 6.f;
	}

	{
		ImGui::SetCursorScreenPos(ImVec2(ox + 16.f, cy));
		aida::ui::input_text("##crypto_filter", st.search_filter, sizeof(st.search_filter),
			"Filter algorithm, signature, module...", false, ImVec2(280.f, 32.f));

		const char* cats[] = {"All", "Symmetric", "Hash", "Stream Cipher", "Block Cipher", "Checksum", "Encoding", "Asymmetric"};
		ImGui::SetCursorScreenPos(ImVec2(ox + 16.f + 290.f, cy + 2.f));
		ImGui::PushItemWidth(160.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, alpha));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, alpha));
		ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
		ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_subtle, alpha));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
		int combo_sel = st.category_filter + 1;
		if (ImGui::Combo("##cat_combo", &combo_sel, cats, 8)) {
			st.category_filter = combo_sel - 1;
		}
		ImGui::PopStyleVar();
		ImGui::PopStyleColor(4);
		ImGui::PopItemWidth();

		const int total = static_cast<int>(view_state->total_hits.load(std::memory_order_acquire));
		const int sym = static_cast<int>(view_state->cipher_hits.load(std::memory_order_acquire));
		const int hash = static_cast<int>(view_state->hash_hits.load(std::memory_order_acquire));
		const int referenced = static_cast<int>(
			view_state->referenced_hits.load(std::memory_order_acquire));

		float pill_x = ox + 16.f + 290.f + 170.f + 20.f;
		float pill_y = cy + 6.f;
		auto chip = [&](const char* label, int n, aida::ui::components::pill_kind_t k) {
			char buf[48];
			snprintf(buf, sizeof(buf), "%s · %d", label, n);
			ImGui::SetCursorScreenPos(ImVec2(pill_x, pill_y));
			aida::ui::pill_kind(buf, k, aida::ui::size_t_::sm, true);
			pill_x = ImGui::GetItemRectMax().x + 12.f;
		};
		chip("hits", total, aida::ui::components::pill_kind_t::accent);
		chip("ciph", sym, aida::ui::components::pill_kind_t::info);
		chip("hash", hash, aida::ui::components::pill_kind_t::success);
		chip("refs", referenced, aida::ui::components::pill_kind_t::neutral);
	}

	cy += 44.f;

	detail::request_filtered_results(context, view_state, scan_snapshot,
		st.search_filter, st.category_filter, st.sort_column, st.sort_ascending);
	std::shared_ptr<const std::vector<crypto_scanner::crypto_hit_t>> filtered_snapshot;
	{
		std::lock_guard<std::mutex> lock(view_state->mutex);
		filtered_snapshot = view_state->filtered_results;
	}
	static const auto empty_results =
		std::make_shared<const std::vector<crypto_scanner::crypto_hit_t>>();
	if (!filtered_snapshot) filtered_snapshot = empty_results;
	const auto& filtered = *filtered_snapshot;

	const float row_h = 30.f;
	const float table_top = cy;
	const float table_h = oy + height - cy - 8.f;
	const float col_widths[6] = { width * 0.18f, width * 0.18f, width * 0.14f, width * 0.22f, width * 0.14f, width * 0.12f };
	const char* col_names[6] = { "Algorithm", "Signature", "Address", "Module + Offset", "Category", "Refs" };

	float hdr_h = 28.f;
	dl->AddRectFilled(ImVec2(ox, cy),
		ImVec2(ox + width, cy + hdr_h),
		aida::ui::with_alpha(t.panel_header, alpha * 0.85f));
	dl->AddLine(ImVec2(ox, cy + hdr_h),
		ImVec2(ox + width, cy + hdr_h),
		aida::ui::with_alpha(t.border_subtle, alpha), 1.f);

	{
		float dt = aida::ui::clock::dt();
		if (st.last_sort_column != st.sort_column) {
			st.sort_arrow_anim = 0.f;
			st.last_sort_column = st.sort_column;
		}
		st.sort_arrow_anim = aida::motion::smooth_lerp(st.sort_arrow_anim, 1.f, 14.f, dt);
	}

	float hx = ox + 12.f;
	for (int c = 0; c < 6; ++c) {
		ImGui::PushID(c);
		ImGui::SetCursorScreenPos(ImVec2(hx, cy));
		ImGui::InvisibleButton("##hdr", ImVec2(col_widths[c] - 6.f, hdr_h));
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		bool hov = ImGui::IsItemHovered();
		if (clk && c < 4) {
			if (st.sort_column == c) st.sort_ascending = !st.sort_ascending;
			else { st.sort_column = c; st.sort_ascending = true; }
		}

		ImU32 lc = hov ? aida::ui::with_alpha(t.text_primary, alpha)
		               : aida::ui::with_alpha(t.text_dim, alpha);
		ImFont* hdr_fn = aida::ui::fonts::body();
		if (!hdr_fn) hdr_fn = ImGui::GetFont();
		float hdr_fs = aida::ui::fonts::size_or(hdr_fn, ImGui::GetFontSize());
		dl->AddText(hdr_fn, hdr_fs,
			ImVec2(hx + 4.f, cy + (hdr_h - hdr_fs) * 0.5f), lc, col_names[c]);
		ImVec2 ts = ImGui::CalcTextSize(col_names[c]);

		if (st.sort_column == c) {
			float aax = hx + 4.f + ts.x + 8.f;
			float aay = cy + hdr_h * 0.5f;
			float aw = 6.f;
			float pop = st.sort_arrow_anim * 3.f;
			if (st.sort_ascending) {
				dl->AddTriangleFilled(
					ImVec2(aax, aay - aw * 0.5f - pop),
					ImVec2(aax + aw, aay + aw * 0.5f - pop * 0.5f),
					ImVec2(aax - aw, aay + aw * 0.5f - pop * 0.5f),
					aida::ui::with_alpha(t.accent_u32, alpha));
			} else {
				dl->AddTriangleFilled(
					ImVec2(aax, aay + aw * 0.5f + pop),
					ImVec2(aax + aw, aay - aw * 0.5f + pop * 0.5f),
					ImVec2(aax - aw, aay - aw * 0.5f + pop * 0.5f),
					aida::ui::with_alpha(t.accent_u32, alpha));
			}
		}

		ImGui::PopID();
		hx += col_widths[c];
	}
	cy += hdr_h;

	float content_h = static_cast<float>(filtered.size()) * row_h;
	float visible_h = table_h - hdr_h - 36.f;

	float dt = aida::ui::clock::dt();
	ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, std::max(0.f, content_h - visible_h), row_h);
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 12.f, dt);

	ImGui::PushClipRect(ImVec2(ox, cy), ImVec2(ox + width - 14.f, cy + visible_h), true);

	int first_visible = static_cast<int>(st.scroll_y / row_h);
	int last_visible = first_visible + static_cast<int>(visible_h / row_h) + 2;
	if (first_visible < 0) first_visible = 0;
	if (last_visible > static_cast<int>(filtered.size())) last_visible = static_cast<int>(filtered.size());

	static float crypto_anim_time = 0.f;
	crypto_anim_time += dt;

	char addr_buf[32];
	char offset_buf[96];
	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	const float body_font_size = aida::ui::fonts::size_or(body_font, ImGui::GetFontSize());
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float code_font_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());

	for (int i = first_visible; i < last_visible; ++i) {
		float ry = cy + static_cast<float>(i) * row_h - st.scroll_y;
		if (ry + row_h < cy || ry > cy + visible_h) continue;

		auto& hit = filtered[static_cast<size_t>(i)];
		ImVec2 row_min(ox, ry);
		ImVec2 row_max(ox + width - 14.f, ry + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(row_min, row_max);
		float entrance = ui_anim::render_row_entrance(i - first_visible, crypto_anim_time, 0.012f);

		if (hovered) {
			dl->AddRectFilled(row_min, row_max,
				aida::ui::with_alpha(t.hover_wash, alpha * entrance));
		} else if (i & 1) {
			dl->AddRectFilled(row_min, row_max,
				aida::ui::with_alpha(IM_COL32(255, 255, 255, 4), alpha * entrance));
		}

		if (hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(hit.address, context);
		}

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			st.ctx_hit_idx = i;
			ImGui::OpenPopup("##crypto_ctx");
		}

		float rx = ox + 12.f;
		ImU32 algo_col = aida::ui::with_alpha(detail::algo_color(hit.category), alpha * entrance);

		{
			float gr = 11.f;
			ImVec2 gctr(rx + gr + 2.f, ry + row_h * 0.5f);
			detail::render_glyph(dl, gctr, gr, hit.algorithm, hit.category, algo_col);
			dl->AddText(aida::ui::fonts::body_em(), 13.f,
				ImVec2(rx + 30.f, ry + (row_h - 13.f) * 0.5f),
				algo_col, hit.algorithm.c_str());
		}
		rx += col_widths[0];

		dl->AddText(body_font, body_font_size,
			ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_primary, alpha * entrance), hit.signature_name.c_str());
		rx += col_widths[1];

		std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX", static_cast<unsigned long long>(hit.address));
		dl->AddText(code_font, code_font_size,
			ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_address, alpha * entrance), addr_buf);
		rx += col_widths[2];

		std::snprintf(offset_buf, sizeof(offset_buf), "%s+0x%llX",
		              hit.module_name.c_str(), static_cast<unsigned long long>(hit.module_offset));
		dl->AddText(body_font, body_font_size,
			ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, alpha * entrance), offset_buf);
		rx += col_widths[3];

		ImGui::SetCursorScreenPos(ImVec2(rx, ry + (row_h - 18.f) * 0.5f));
		ImGui::PushID(i + 12345);
		aida::ui::pill_kind(crypto_scanner::category_name(hit.category),
			detail::category_pill_kind(hit.category),
			aida::ui::size_t_::sm, true);
		ImGui::PopID();
		rx += col_widths[4];

		if (!hit.referencing_functions.empty()) {
			char ref_buf[32];
			std::snprintf(ref_buf, sizeof(ref_buf), "%zu refs", hit.referencing_functions.size());
			dl->AddText(body_font, body_font_size,
				ImVec2(rx, ry + (row_h - 11.f) * 0.5f),
				aida::ui::with_alpha(t.accent_u32, alpha * entrance), ref_buf);
		}
	}

	ImGui::PopClipRect();

	if (filtered.empty()) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::shield;
		cfg.title = "No crypto hits";
		cfg.body = scanning
			? "Scanning the target memory regions..."
			: "Run Scan Process or Scan File to detect cryptographic primitives.";
		aida::ui::empty_state::render(ImVec2(ox, cy), ImVec2(width, visible_h), cfg);
	} else if (scanning && filtered.size() < 4) {
		float sk_y = cy + static_cast<float>(filtered.size()) * row_h + 6.f;
		for (int s = 0; s < 5; ++s) {
			if (sk_y + 18.f > cy + visible_h) break;
			aida::ui::skeleton::render_block(dl,
				ImVec2(ox + 16.f, sk_y),
				ImVec2(ox + width - 28.f, sk_y + 16.f), 6.f, 1.4f);
			sk_y += 24.f;
		}
	}

	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_subtle, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, 1.f));
	ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 10.f);
	if (ImGui::BeginPopup("##crypto_ctx")) {
		if (st.ctx_hit_idx >= 0 && st.ctx_hit_idx < static_cast<int>(filtered.size())) {
			auto& ctx_hit = filtered[static_cast<size_t>(st.ctx_hit_idx)];

			if (ImGui::MenuItem("Go to Disassembly")) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(ctx_hit.address, context);
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] crypto_scanner ctx open_disasm");
			}

			if (ImGui::MenuItem("Open in Hex")) {
				detail::open_hit_in_hex(context, ctx_hit.address);
				globals::ui::active_center_view = center_view_t::hex_view;
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] crypto_scanner ctx open_hex");
			}

			if (!ctx_hit.referencing_functions.empty()) {
				if (ImGui::BeginMenu("Show References")) {
					for (auto ref_addr : ctx_hit.referencing_functions) {
						char ref_label[64];
						std::snprintf(ref_label, sizeof(ref_label), "0x%llX", static_cast<unsigned long long>(ref_addr));
						std::string lbl;
						if (const auto typed = disasm_view::typed_address(context, ref_addr))
							lbl = disasm_view::resolve_name(context, *typed);
						std::string menu_text = ref_label;
						if (!lbl.empty()) menu_text += " (" + lbl + ")";
						if (ImGui::MenuItem(menu_text.c_str())) {
							globals::ui::active_center_view = center_view_t::disassembly;
							disasm_view::goto_address(ref_addr, context);
							anti_tamper::webhook::write_log("scan_audit",
								"[scan_audit] crypto_scanner ctx show_ref");
						}
					}
					ImGui::EndMenu();
				}
			}

			ImGui::Separator();
			if (ImGui::MenuItem("Copy Address")) {
				char addr_copy[32];
				std::snprintf(addr_copy, sizeof(addr_copy), "0x%llX", static_cast<unsigned long long>(ctx_hit.address));
				ImGui::SetClipboardText(addr_copy);
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] crypto_scanner ctx copy_address");
			}
			if (ImGui::MenuItem("Copy Algorithm")) {
				ImGui::SetClipboardText(ctx_hit.algorithm.c_str());
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] crypto_scanner ctx copy_algo");
			}
		}
		ImGui::EndPopup();
	}
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(3);

	{
		float footer_h = 26.f;
		float fy = oy + height - footer_h - 4.f;
		dl->AddRectFilled(ImVec2(ox + 8.f, fy), ImVec2(ox + width - 8.f, fy + footer_h),
			aida::ui::with_alpha(t.panel_bg, alpha * 0.6f), 6.f);
		char count_buf[160];
		const size_t entropy_count = scan_snapshot->entropy_map.size();
		if (entropy_count > 0) {
			std::snprintf(count_buf, sizeof(count_buf), "%zu results  ·  %zu entropy regions", filtered.size(), entropy_count);
		} else {
			std::snprintf(count_buf, sizeof(count_buf), "%zu results", filtered.size());
		}
		ImVec2 fts = ImGui::CalcTextSize(count_buf);
		dl->AddText(body_font, body_font_size,
			ImVec2(ox + width - fts.x - 18.f, fy + (footer_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_dim, alpha), count_buf);
	}

	if (content_h > visible_h) {
		ui_anim::render_custom_scrollbar(dl, ox + width - 12.f, table_top + hdr_h,
		                                  8.f, visible_h, st.scroll_y, content_h, visible_h,
		                                  alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	}
	ImGui::EndChild();
}

inline void render(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b)
{
	render(pos_x, pos_y, width, height, alpha, accent_r, accent_g, accent_b,
		disasm_view::capture_selected_workspace());
}

}
