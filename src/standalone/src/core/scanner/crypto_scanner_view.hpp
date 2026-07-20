#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <limits>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "imgui.h"
#include "crypto_scanner.hpp"
#include "disasm_view.hpp"
#include "hex_view.hpp"
#include "scanner_async_io.hpp"
#include "ui_anim.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview_platform.hpp"
#include "../../preview/studio_semantics.hpp"
#else
#include "../anti-tamper/webhook.hpp"
#include "../helpers/diag_log.hpp"
#include "../infra/executor.hpp"
#include "../ui/task_center.hpp"
#include "../ui/ui_thread_dispatcher.hpp"
#endif
#include "../ui/application_view_registry.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../ai/entity_evidence_handoff.hpp"
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

inline constexpr std::size_t k_max_crypto_reference_publication = 0x400000;

enum class export_terminal_t : std::uint8_t {
	idle,
	queued,
	running,
	succeeded,
	failed,
	cancelled,
	stale
};

struct export_status_t {
	export_terminal_t terminal = export_terminal_t::idle;
	std::string message;
	std::string path;
};

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
	uint64_t context_address = 0;
	std::string context_algorithm;
	std::string context_signature;
	std::vector<std::uint64_t> reference_choices;
	std::uint64_t reference_generation = 0;
	bool open_reference_chooser = false;
	int reference_selected = 0;
	bool reference_focus_pending = false;
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
	export_status_t export_status;
	std::atomic<bool> export_pending{false};
	std::atomic<bool> export_dispatch_failed{false};
	std::atomic<std::uint64_t> export_serial{0};
	bool last_export_csv = false;
	std::string last_export_path;
};

inline state_t g_state;

inline bool context_key_pressed()
{
	return ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
		(ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false));
}

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
		hex_view::request_live_memory(context, address, 256);
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

inline constexpr std::size_t max_export_results = 100000;
inline constexpr std::size_t max_export_string = 512;

inline void set_export_status(const std::shared_ptr<state_t>& state,
	export_terminal_t terminal, std::string message, std::string path = {})
{
	if (!state) return;
	std::lock_guard<std::mutex> lock(state->mutex);
	state->export_status = {terminal, std::move(message), std::move(path)};
}

inline bool export_workspace_matches(
	const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	const std::shared_ptr<state_t>& state,
	const std::shared_ptr<const crypto_scanner::workspace_scan_snapshot_t>& snapshot,
	const std::string& binary_id, std::uint64_t workspace_generation,
	std::uint64_t publication_generation, std::uint32_t pid)
{
	if (!workspace || workspace->closing() || workspace->closed() ||
		workspace->identity().binary_id().to_hex() != binary_id ||
		workspace->generation() != workspace_generation) return false;
	const auto publication = workspace->analysis_publication();
	if (!publication || publication->generation != publication_generation) return false;
	const auto process = workspace->identity().process();
	if (pid == 0 ? static_cast<bool>(process) : !process || process->pid != pid) return false;
	std::lock_guard<std::mutex> lock(state->mutex);
	return state->snapshot == snapshot;
}

inline bool append_export(std::string& output, const std::string& value, std::string& error)
{
	if (output.size() > scanner_async_io::max_serialized_bytes ||
		value.size() > scanner_async_io::max_serialized_bytes - output.size()) {
		error = "Crypto export exceeds the 64 MiB serialized-output limit";
		return false;
	}
	output.append(value);
	return true;
}

inline std::string csv_field(const std::string& value)
{
	std::string output;
	output.reserve(value.size() + 2);
	output.push_back('"');
	for (char character : value) {
		if (character == '"') output.push_back('"');
		output.push_back(character);
	}
	output.push_back('"');
	return output;
}

inline bool serialize_export(const disasm_view::workspace_context_t& context,
	const crypto_scanner::workspace_scan_snapshot_t& snapshot, bool csv,
	const std::shared_ptr<std::atomic<bool>>& cancellation, std::string& output,
	std::string& error)
{
	if (snapshot.results.size() > max_export_results) {
		error = "Crypto export exceeds the 100000-result limit";
		return false;
	}
	try {
	output.clear();
	output.reserve((std::min)(scanner_async_io::max_serialized_bytes,
		snapshot.results.size() * static_cast<std::size_t>(192) + 256));
	if (csv) {
		if (!append_export(output,
			"algorithm,signature,address,module,module_offset,references\n", error)) return false;
	} else {
		const std::string prefix = "{\n  \"binary_id\": " +
			nlohmann::json(context.workspace->identity().binary_id().to_hex()).dump() +
			",\n  \"bin_name\": " + nlohmann::json(context.workspace->identity().bin_name()).dump() +
			",\n  \"results\": [";
		if (!append_export(output, prefix, error)) return false;
	}
	bool first = true;
	for (const auto& hit : snapshot.results) {
		if (scanner_async_io::cancellation_requested(cancellation)) {
			error = "Crypto export cancelled";
			return false;
		}
		if (hit.algorithm.size() > max_export_string || hit.signature_name.size() > max_export_string ||
			hit.module_name.size() > max_export_string) {
			error = "Crypto export contains a string that exceeds 512 bytes";
			return false;
		}
		const auto address = disasm_view::runtime_address(context, hit.address);
		if (!address) continue;
		char address_text[32]{};
		char offset_text[32]{};
		std::snprintf(address_text, sizeof(address_text), "0x%llX",
			static_cast<unsigned long long>(*address));
		std::snprintf(offset_text, sizeof(offset_text), "0x%llX",
			static_cast<unsigned long long>(hit.module_offset));
		std::string row;
		if (csv) {
			row = csv_field(hit.algorithm) + "," + csv_field(hit.signature_name) + "," +
				address_text + "," + csv_field(hit.module_name) + "," + offset_text + "," +
				std::to_string(hit.referencing_functions.size()) + "\n";
		} else {
			nlohmann::json item;
			item["algorithm"] = hit.algorithm;
			item["signature"] = hit.signature_name;
			item["address"] = *address;
			item["module"] = hit.module_name;
			item["module_offset"] = hit.module_offset;
			item["references"] = hit.referencing_functions.size();
			row = (first ? "\n    " : ",\n    ") + item.dump();
			first = false;
		}
		if (!append_export(output, row, error)) return false;
	}
	return csv || append_export(output, first ? "]\n}\n" : "\n  ]\n}\n", error);
	} catch (const std::exception& exception) {
		output.clear();
		error = "Crypto export serialization failed: " + std::string(exception.what());
		return false;
	}
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline std::atomic<std::uint64_t> export_task_sequence{1};

inline std::string register_export_task(bool csv, const std::string& target,
	const std::shared_ptr<std::atomic<bool>>& cancellation,
	const std::shared_ptr<std::atomic<std::uint8_t>>& commit_gate)
{
	const std::string id = "scanner.crypto.export." +
		std::to_string(export_task_sequence.fetch_add(1, std::memory_order_acq_rel));
	aida::ui::task_center::task_registration_t registration;
	registration.id = id;
	registration.source = "human";
	registration.owner = "Crypto Scanner";
	registration.owner_view = "view.memory.crypto";
	registration.owner_action = csv ? "scanner.crypto.export.csv" : "scanner.crypto.export.json";
	registration.target = target;
	registration.label = csv ? "Export crypto results as CSV" : "Export crypto results as JSON";
	registration.stage = "Queued";
	registration.progress = -1.0f;
	registration.cancellation_is_safe = true;
	registration.callbacks.cancel = [cancellation, commit_gate] {
		std::uint8_t expected_gate = scanner_async_io::operation_reversible;
		if (!commit_gate->compare_exchange_strong(expected_gate,
			scanner_async_io::operation_cancelled, std::memory_order_acq_rel,
			std::memory_order_acquire)) return false;
		bool expected = false;
		return cancellation->compare_exchange_strong(expected, true, std::memory_order_acq_rel);
	};
	registration.callbacks.focus = [] {
		static_cast<void>(aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("view.memory.crypto")));
	};
	return aida::ui::task_center::register_task(std::move(registration)) ? id : std::string();
}

inline void finish_export_task(const std::string& id, export_terminal_t terminal,
	const std::string& stage, const std::string& summary)
{
	if (id.empty()) return;
	auto state = aida::ui::task_center::task_state_t::failed;
	if (terminal == export_terminal_t::succeeded)
		state = aida::ui::task_center::task_state_t::completed;
	else if (terminal == export_terminal_t::cancelled || terminal == export_terminal_t::stale)
		state = aida::ui::task_center::task_state_t::cancelled;
	static_cast<void>(aida::ui::task_center::update_task(id, state, 1.0f, stage, summary));
}
#endif

inline void export_results(const disasm_view::workspace_context_t& context,
	const std::shared_ptr<state_t>& state,
	std::shared_ptr<const crypto_scanner::workspace_scan_snapshot_t> snapshot,
	std::string path, bool csv)
{
	if (!context.workspace || !context.publication || !state || !snapshot) return;
	bool expected = false;
	if (!state->export_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
	const std::uint64_t serial = state->export_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
	{
		std::lock_guard<std::mutex> lock(state->mutex);
		state->last_export_csv = csv;
		state->last_export_path = path;
		state->export_status = {export_terminal_t::queued, "Queued immutable crypto export", path};
	}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(serial);
	aida::preview::scan::record(csv ? "crypto.export.csv" : "crypto.export.json",
		context.workspace->identity().binary_id().to_hex() + ":" +
		std::to_string(snapshot->results.size()));
	set_export_status(state, export_terminal_t::succeeded,
		"Studio receipt recorded for immutable crypto export", path);
	state->export_pending.store(false, std::memory_order_release);
#else
	const auto workspace = context.workspace;
	const std::string binary_id = workspace->identity().binary_id().to_hex();
	const std::uint64_t workspace_generation = workspace->generation();
	const std::uint64_t publication_generation = context.publication->generation;
	const auto process = workspace->identity().process();
	const std::uint32_t pid = process ? process->pid : 0;
	auto cancellation = std::make_shared<std::atomic<bool>>(false);
	auto commit_gate = std::make_shared<std::atomic<std::uint8_t>>(
		scanner_async_io::operation_reversible);
	const std::string task_id = register_export_task(csv, binary_id, cancellation, commit_gate);
	if (task_id.empty()) {
		state->export_pending.store(false, std::memory_order_release);
		set_export_status(state, export_terminal_t::failed,
			"Task Center rejected crypto export ownership", path);
		return;
	}
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "scanner.crypto";
	submission.label = csv ? "scanner.crypto.export.csv" : "scanner.crypto.export.json";
	submission.thread_class = "bounded_task";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 2;
	submission.target_pid = pid;
	submission.generation = publication_generation;
	submission.cancel_hook = [cancellation, commit_gate] {
		std::uint8_t expected_gate = scanner_async_io::operation_reversible;
		if (commit_gate->compare_exchange_strong(expected_gate, scanner_async_io::operation_cancelled,
			std::memory_order_acq_rel, std::memory_order_acquire))
			cancellation->store(true, std::memory_order_release);
	};
	submission.body = [context, workspace, state, snapshot = std::move(snapshot), path = std::move(path),
		csv, cancellation, task_id, binary_id, workspace_generation, publication_generation,
		pid, serial, commit_gate]() mutable {
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::running, 0.1f, "Serializing bounded crypto results"));
		static_cast<void>(aida::ui_thread::post([state, serial] {
			if (state->export_serial.load(std::memory_order_acquire) == serial &&
				state->export_pending.load(std::memory_order_acquire))
				set_export_status(state, export_terminal_t::running,
					"Serializing bounded crypto results");
		}, "scanner.crypto", "publish_export_running", "worker_progress"));
		std::string output;
		std::string error;
		bool serialized = serialize_export(context, *snapshot, csv, cancellation, output, error);
		if (serialized && path.empty()) {
			char* appdata = nullptr;
			std::size_t length = 0;
			_dupenv_s(&appdata, &length, "APPDATA");
			if (appdata) {
				path = (std::filesystem::path(appdata) / "AiDA" / "Standalone" /
					("crypto_export_" + binary_id.substr(0, 16) + (csv ? ".csv" : ".json"))).string();
				free(appdata);
			}
			if (path.empty()) { serialized = false; error = "APPDATA is unavailable for crypto export"; }
		}
		auto current = [workspace, state, snapshot, binary_id, workspace_generation,
			publication_generation, pid] {
			return export_workspace_matches(workspace, state, snapshot, binary_id,
				workspace_generation, publication_generation, pid);
		};
		scanner_async_io::result_t write;
		if (serialized && current())
			write = scanner_async_io::atomic_replace(path, output, true, cancellation, current, commit_gate);
		else if (serialized)
			write.error = "Crypto workspace, target, publication, or snapshot changed";
		const bool cancelled = scanner_async_io::cancellation_requested(cancellation) || write.cancelled;
		const bool stale = !cancelled && !current();
		const bool success = serialized && write.success && !stale;
		if (!success && error.empty()) error = write.error;
		const export_terminal_t terminal = success ? export_terminal_t::succeeded :
			cancelled ? export_terminal_t::cancelled : stale ? export_terminal_t::stale :
			export_terminal_t::failed;
		auto publish = [state, serial, terminal, error = std::move(error), path, task_id]() mutable {
			if (state->export_serial.load(std::memory_order_acquire) != serial) return;
			set_export_status(state, terminal,
				terminal == export_terminal_t::succeeded ? "Crypto export committed atomically" : error, path);
			state->export_pending.store(false, std::memory_order_release);
			finish_export_task(task_id, terminal,
				terminal == export_terminal_t::succeeded ? "Crypto export complete" : "Crypto export failed",
				terminal == export_terminal_t::succeeded ? path : error);
		};
		if (!aida::ui_thread::post(std::move(publish), "scanner.crypto", "publish_export", "worker_completion")) {
			state->export_pending.store(false, std::memory_order_release);
			state->export_dispatch_failed.store(true, std::memory_order_release);
			finish_export_task(task_id, export_terminal_t::failed, "UI publication rejected",
				"Crypto export completion was not published");
		}
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		state->export_pending.store(false, std::memory_order_release);
		set_export_status(state, export_terminal_t::failed,
			"Worker queue rejected crypto export: " + submitted.reject_reason, state->last_export_path);
		finish_export_task(task_id, export_terminal_t::failed, "Worker queue rejected", submitted.reject_reason);
	}
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
	if (view_state->export_dispatch_failed.exchange(false, std::memory_order_acq_rel))
		detail::set_export_status(view_state, export_terminal_t::failed,
			"UI dispatcher rejected crypto export completion");
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
		const bool export_pending = view_state->export_pending.load(std::memory_order_acquire);
		if (aida::ui::button("JSON", aida::ui::button_kind_t::ghost,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), export_pending))
			detail::export_results(context, view_state, scan_snapshot, {}, false);
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}
	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("CSV", aida::ui::button_kind_t::ghost,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f),
				view_state->export_pending.load(std::memory_order_acquire)))
			detail::export_results(context, view_state, scan_snapshot, {}, true);
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
	export_status_t export_status;
	{
		std::lock_guard<std::mutex> lock(view_state->mutex);
		export_status = view_state->export_status;
	}
	if (export_status.terminal != export_terminal_t::idle) {
		const bool failed = export_status.terminal == export_terminal_t::failed ||
			export_status.terminal == export_terminal_t::stale ||
			export_status.terminal == export_terminal_t::cancelled;
		ui_anim::render_inline_callout(dl, ox + 16.f, cy, width - 32.f, 22.f,
			export_status.message.c_str(), failed ? ui_anim::callout_kind_t::error :
			ui_anim::callout_kind_t::info, failed ? 0.9f : 0.3f,
			failed ? 0.25f : 0.55f, failed ? 0.25f : 0.95f, alpha);
		if (failed && !view_state->export_pending.load(std::memory_order_acquire)) {
			bool csv = false;
			std::string path;
			{
				std::lock_guard<std::mutex> lock(view_state->mutex);
				csv = view_state->last_export_csv;
				path = view_state->last_export_path;
			}
			ImGui::SetCursorScreenPos(ImVec2(ox + width - 82.f, cy - 4.f));
			if (aida::ui::button("Retry", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm))
				detail::export_results(context, view_state, scan_snapshot, std::move(path), csv);
		}
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

	bool open_crypto_context = false;
	auto crypto_context_origin = aida::ui::context_menu_open_origin_t::pointer;
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
			aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
			disasm_view::goto_address(hit.address, context);
		}
		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			st.ctx_hit_idx = i;
			st.context_address = hit.address;
			st.context_algorithm = hit.algorithm;
			st.context_signature = hit.signature_name;
		}

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			st.ctx_hit_idx = i;
			st.context_address = hit.address;
			st.context_algorithm = hit.algorithm;
			st.context_signature = hit.signature_name;
			open_crypto_context = true;
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
	if (ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) && context_key_pressed() &&
		st.ctx_hit_idx >= 0) {
		open_crypto_context = true;
		crypto_context_origin = ImGui::IsKeyPressed(ImGuiKey_Menu, false)
			? aida::ui::context_menu_open_origin_t::menu_key
			: aida::ui::context_menu_open_origin_t::shift_f10;
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

	if (open_crypto_context) {
		const auto current_hit = std::find_if(filtered.begin(), filtered.end(), [&](const auto& hit) {
			return hit.address == st.context_address && hit.algorithm == st.context_algorithm &&
				hit.signature_name == st.context_signature;
		});
		if (current_hit != filtered.end()) {
			const auto hit = *current_hit;
			const auto workspace_hit = std::find_if(scan_snapshot->results.begin(),
				scan_snapshot->results.end(), [&](const auto& item) {
					const auto runtime = disasm_view::runtime_address(context, item.address);
					return runtime && *runtime == hit.address &&
						item.algorithm == hit.algorithm &&
						item.signature_name == hit.signature_name;
				});
			const bool hit_identity_available = workspace_hit != scan_snapshot->results.end();
			const auto hit_address_identity = hit_identity_available
				? workspace_hit->address : aida::analysis::address_t{};
			const auto workspace = context.workspace;
			const auto generation = context.publication ? context.publication->generation : 0;
			const auto target_pid = driver_bridge::attached_pid();
			aida::ui::application_ui::retained_entity_context_t retained;
			retained.owner_id = "memory.crypto.hit";
			retained.entity_id = hit.algorithm + "@" + std::to_string(hit.address);
			retained.entity_generation = generation;
			retained.active_view = aida::ui::stable_view_id_t("view.memory.crypto");
			retained.validate_identity = [workspace, generation, hit, scan_snapshot, target_pid,
				hit_identity_available, hit_address_identity]() {
				if (!workspace) return aida::ui::capability_state_t::unavailable("The crypto workspace was closed.");
				if (driver_bridge::attached_pid() != target_pid)
					return aida::ui::capability_state_t::unavailable("The crypto scan target process changed; reopen the menu.");
				const auto publication = workspace->analysis_publication();
				if (!publication || publication->generation != generation)
					return aida::ui::capability_state_t::unavailable("The analysis publication changed; reopen the menu.");
				if (!hit_identity_available)
					return aida::ui::capability_state_t::unavailable("The selected crypto hit identity is no longer available.");
				const bool current = std::any_of(scan_snapshot->results.begin(), scan_snapshot->results.end(), [&](const auto& item) {
					return item.address == hit_address_identity && item.algorithm == hit.algorithm &&
						item.signature_name == hit.signature_name;
				});
				return current ? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable("The selected crypto hit changed or was removed.");
			};
			auto add = [&](const char* id, auto invoke) {
				retained.actions.push_back({id, aida::ui::capability_state_t::available(), invoke});
			};
			add("memory.entity.open_disassembly", [hit, context]() {
				aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
				disasm_view::goto_address(hit.address, context);
				anti_tamper::webhook::write_log("scan_audit", "[scan_audit] crypto_scanner ctx open_disasm");
				return aida::ui::action_handler_result_t::completed();
			});
			add("memory.entity.open_hex", [hit, context]() {
				detail::open_hit_in_hex(context, hit.address);
				aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.hex"));
				anti_tamper::webhook::write_log("scan_audit", "[scan_audit] crypto_scanner ctx open_hex");
				return aida::ui::action_handler_result_t::completed();
			});
			if (!hit.referencing_functions.empty()) {
				const bool bounded = hit.referencing_functions.size() <=
					k_max_crypto_reference_publication;
				retained.actions.push_back({"memory.crypto.show_references", bounded
					? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable(
						"The reference publication exceeds the 4 MiB scanner-module bound."),
					[view_state, hit, generation]() {
					view_state->reference_choices.clear();
					view_state->reference_choices.reserve(hit.referencing_functions.size());
					std::unordered_set<std::uint64_t> seen;
					seen.reserve(hit.referencing_functions.size());
					for (const auto address : hit.referencing_functions)
						if (seen.insert(address).second)
							view_state->reference_choices.push_back(address);
					view_state->reference_generation = generation;
					view_state->reference_selected = 0;
					view_state->reference_focus_pending = true;
					view_state->open_reference_chooser = true;
					return aida::ui::action_handler_result_t::completed();
				}});
			}
			add("memory.entity.copy_address", [hit]() {
				char address[32]{};
				std::snprintf(address, sizeof(address), "0x%llX", static_cast<unsigned long long>(hit.address));
				ImGui::SetClipboardText(address);
				anti_tamper::webhook::write_log("scan_audit", "[scan_audit] crypto_scanner ctx copy_address");
				return aida::ui::action_handler_result_t::completed();
			});
			add("memory.crypto.copy_algorithm", [hit]() {
				ImGui::SetClipboardText(hit.algorithm.c_str());
				anti_tamper::webhook::write_log("scan_audit", "[scan_audit] crypto_scanner ctx copy_algo");
				return aida::ui::action_handler_result_t::completed();
			});
			char evidence_address[24]{};
			std::snprintf(evidence_address, sizeof(evidence_address), "0x%016llX",
				static_cast<unsigned long long>(hit.address));
			aida::automation_ui::entity_evidence::snapshot_t evidence;
			evidence.workspace_id = target_pid != 0 ? "pid:" + std::to_string(target_pid)
				: workspace->identity().binary_id().to_hex();
			evidence.source_view_id = "view.memory.crypto";
			evidence.source_kind = "crypto_scan_hit";
			evidence.entity_id = retained.entity_id;
			evidence.display_label = hit.algorithm + " / " + hit.signature_name;
			evidence.excerpt = "PID: " + std::to_string(target_pid) +
				"\nPublication generation: " + std::to_string(generation) +
				"\nAlgorithm: " + hit.algorithm + "\nSignature: " + hit.signature_name +
				"\nCategory: " + crypto_scanner::category_name(hit.category) +
				"\nAddress: " + evidence_address + "\nModule: " + hit.module_name +
				"\nModule offset: " + std::to_string(hit.module_offset) +
				"\nReference count: " + std::to_string(hit.referencing_functions.size());
			evidence.address = hit.address;
			evidence.revision = generation;
			evidence.generation = generation;
			evidence.sensitive = target_pid != 0;
			const auto evidence_hit_address = hit.address;
			const auto evidence_hit_algorithm = hit.algorithm;
			const auto evidence_hit_signature = hit.signature_name;
			const auto evidence_hit_module = hit.module_name;
			const auto evidence_hit_module_offset = hit.module_offset;
			const auto evidence_hit_reference_count = hit.referencing_functions.size();
			evidence.return_to_source = [workspace, generation, evidence_hit_address,
				evidence_hit_algorithm, evidence_hit_signature, evidence_hit_module,
				evidence_hit_module_offset, evidence_hit_reference_count, scan_snapshot,
				view_state, hit_identity_available, hit_address_identity](std::string& reason) {
			const auto publication = workspace ? workspace->analysis_publication() : nullptr;
			if (!publication || publication->generation != generation || !hit_identity_available ||
				!std::any_of(scan_snapshot->results.begin(), scan_snapshot->results.end(),
					[&](const auto& item) {
						return item.address == hit_address_identity &&
							item.algorithm == evidence_hit_algorithm &&
							item.signature_name == evidence_hit_signature &&
							item.module_name == evidence_hit_module &&
							item.module_offset == evidence_hit_module_offset &&
							item.referencing_functions.size() == evidence_hit_reference_count;
					})) {
				reason = "The crypto publication or retained hit changed; capture it again.";
				return false;
			}
			{
				std::lock_guard<std::mutex> lock(view_state->mutex);
				view_state->context_address = evidence_hit_address;
				view_state->context_algorithm = evidence_hit_algorithm;
				view_state->context_signature = evidence_hit_signature;
				view_state->ctx_hit_idx = -1;
				if (view_state->filtered_results) {
					const auto found = std::find_if(view_state->filtered_results->begin(),
						view_state->filtered_results->end(), [&](const auto& item) {
							return item.address == evidence_hit_address &&
								item.algorithm == evidence_hit_algorithm &&
								item.signature_name == evidence_hit_signature;
						});
					if (found != view_state->filtered_results->end())
						view_state->ctx_hit_idx = static_cast<int>(std::distance(
							view_state->filtered_results->begin(), found));
				}
			}
			const auto opened = aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("view.memory.crypto"));
			if (!opened.ok()) {
				reason = opened.detail;
				return false;
			}
			reason.clear();
			return true;
		};
			aida::automation_ui::entity_evidence::append_actions(retained,
				std::move(evidence));
			aida::ui::application_ui::open_retained_entity_context_menu(
				std::move(retained), crypto_context_origin);
		}
	}
	aida::ui::application_ui::render_retained_entity_context_menu("memory.crypto.hit");
	if (st.open_reference_chooser) {
		st.open_reference_chooser = false;
		ImGui::OpenPopup("Crypto References##retained_chooser");
	}
	if (ImGui::BeginPopup("Crypto References##retained_chooser")) {
		const bool current = context.publication &&
			context.publication->generation == st.reference_generation;
		auto activate_reference = [&](std::uint64_t address) {
			if (!context.publication ||
				context.publication->generation != st.reference_generation)
				return false;
			aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("document.disassembly"));
			disasm_view::goto_address(address, context);
			anti_tamper::webhook::write_log(
				"scan_audit", "[scan_audit] crypto_scanner ctx show_ref");
			ImGui::CloseCurrentPopup();
			return true;
		};
		if (ImGui::IsKeyPressed(ImGuiKey_Escape, false))
			ImGui::CloseCurrentPopup();
		if (current && !st.reference_choices.empty()) {
			if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, false))
				st.reference_selected = (std::max)(0, st.reference_selected - 1);
			if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, false))
				st.reference_selected = (std::min)(
					static_cast<int>(st.reference_choices.size() - 1),
					st.reference_selected + 1);
			if (ImGui::IsKeyPressed(ImGuiKey_Enter, false))
				static_cast<void>(activate_reference(st.reference_choices[
					static_cast<std::size_t>(st.reference_selected)]));
		}
		if (!current)
			ImGui::TextDisabled("The analysis publication changed; reopen the hit context menu.");
		if (!current) ImGui::BeginDisabled();
		ImGui::TextDisabled("%zu retained references", st.reference_choices.size());
		ImGui::BeginChild("##crypto_reference_rows", ImVec2(460.f,
			(std::min)(360.f, 28.f * static_cast<float>((std::max)(std::size_t{1}, st.reference_choices.size())))),
			ImGuiChildFlags_Borders);
		const float reference_row_height = ImGui::GetTextLineHeightWithSpacing();
		if (st.reference_focus_pending) {
			ImGui::SetScrollY(reference_row_height * static_cast<float>(st.reference_selected));
		}
		ImGuiListClipper reference_clipper;
		const int clipped_reference_count = st.reference_choices.size() >
			static_cast<std::size_t>((std::numeric_limits<int>::max)())
			? (std::numeric_limits<int>::max)()
			: static_cast<int>(st.reference_choices.size());
		reference_clipper.Begin(clipped_reference_count, reference_row_height);
		while (reference_clipper.Step()) for (int visible_index = reference_clipper.DisplayStart;
			visible_index < reference_clipper.DisplayEnd; ++visible_index) {
			const std::size_t index = static_cast<std::size_t>(visible_index);
			const auto address = st.reference_choices[index];
			char raw[32]{};
			std::snprintf(raw, sizeof(raw), "0x%016llX", static_cast<unsigned long long>(address));
			std::string label = raw;
			if (const auto typed = disasm_view::typed_address(context, address)) {
				const std::string name = disasm_view::resolve_name(context, *typed);
				if (!name.empty()) label += "  " + name;
			}
			const std::string semantic_label = label + "##crypto.reference." +
				std::to_string(address) + "." + std::to_string(index);
			ImGui::PushID(static_cast<int>(index));
			if (st.reference_focus_pending && visible_index == st.reference_selected)
				ImGui::SetKeyboardFocusHere();
			const bool selected = ImGui::Selectable(semantic_label.c_str(),
				visible_index == st.reference_selected);
			if (ImGui::IsItemFocused())
				st.reference_selected = visible_index;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			const std::string semantic_id = aida::preview::semantics::stable_id(
				"aida.memory.crypto-reference", std::to_string(address) + "-" +
					std::to_string(index));
			aida::preview::semantics::register_last_item(
				semantic_id, "crypto-reference-row", false, !current,
				"aida.dock-window.view.memory.crypto");
#endif
			if (selected) {
				static_cast<void>(activate_reference(address));
			}
			ImGui::PopID();
		}
		st.reference_focus_pending = false;
		ImGui::EndChild();
		if (!current) ImGui::EndDisabled();
		ImGui::EndPopup();
	}

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
