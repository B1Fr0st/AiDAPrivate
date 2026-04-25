#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "provider_view.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <vector>

#include <windows.h>
#include <shlobj.h>

#include "imgui/imgui.h"
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "auth_store.hpp"
#include "event_bus.hpp"
#include "provider_catalog.hpp"
#include "provider_transforms.hpp"
#include "standalone_settings.hpp"
#include "toast_notification.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"

namespace aida {
namespace provider_view {

namespace {

	using catalog_provider_t = aida::provider::provider_info_t;
	using catalog_model_t = aida::provider::model_info_t;
	using auth_info_t = aida::auth::auth_info_t;
	using auth_kind_t = aida::auth::auth_kind_t;

	struct test_result_t
	{
		bool        completed = false;
		bool        success = false;
		int         latency_ms = 0;
		int         http_status = 0;
		std::string message;
		std::string provider_id;
		std::string model_id;
	};

	struct refresh_state_t
	{
		std::atomic<bool> in_flight{ false };
		std::atomic<bool> completed{ false };
		std::atomic<bool> success{ false };
		std::string       message;
	};

	struct view_state_t
	{
		std::mutex                            mtx;
		std::string                           last_error;
		std::string                           selected_detail_provider_id;
		char                                  search_buf[128] = {};
		char                                  detail_base_url_buf[1024] = {};
		char                                  detail_headers_buf[4096] = {};
		bool                                  detail_buffers_loaded = false;
		bool                                  show_raw_model_json = false;
		std::map<std::string, test_result_t>  pending_results;
		std::map<std::string, std::shared_ptr<std::atomic<bool>>> in_flight_tests;
		refresh_state_t                       refresh;
		std::atomic<bool>                     shutdown_flag{ false };
		bool                                  initialized = false;
	};

	view_state_t& g_state()
	{
		static view_state_t state;
		return state;
	}

	std::string lower_copy(const std::string& s)
	{
		std::string out = s;
		std::transform(out.begin(), out.end(), out.begin(),
			[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		return out;
	}

	std::string truncate_text(const std::string& s, size_t max_len)
	{
		if (s.size() <= max_len)
			return s;
		std::string out = s.substr(0, max_len);
		out += "...";
		return out;
	}

	ImU32 hash_color_for(const std::string& provider_id)
	{
		uint32_t h = 2166136261u;
		for (unsigned char c : provider_id) {
			h ^= c;
			h *= 16777619u;
		}
		const int r = static_cast<int>(60 + (h & 0x7F));
		const int g = static_cast<int>(60 + ((h >> 8) & 0x7F));
		const int b = static_cast<int>(60 + ((h >> 16) & 0x7F));
		return IM_COL32(r, g, b, 230);
	}

	char glyph_for(const catalog_provider_t& p)
	{
		const std::string& base = p.name.empty() ? p.id : p.name;
		for (unsigned char c : base) {
			if (std::isalnum(c))
				return static_cast<char>(std::toupper(c));
		}
		return '?';
	}

	std::string format_cost_pair(double in_per_m, double out_per_m)
	{
		char buf[96];
		if (in_per_m <= 0.0 && out_per_m <= 0.0) {
			std::snprintf(buf, sizeof(buf), "free");
		} else {
			std::snprintf(buf, sizeof(buf), "$%.2f / $%.2f per M", in_per_m, out_per_m);
		}
		return std::string(buf);
	}

	std::string format_context(int64_t context)
	{
		if (context <= 0)
			return std::string("ctx ?");
		char buf[32];
		if (context >= 1000) {
			std::snprintf(buf, sizeof(buf), "ctx %lldK", static_cast<long long>(context / 1000));
		} else {
			std::snprintf(buf, sizeof(buf), "ctx %lld", static_cast<long long>(context));
		}
		return std::string(buf);
	}

	bool has_auth_for(const std::string& provider_id, auth_info_t& out)
	{
		if (!aida::auth::store::get(provider_id, out))
			return false;
		if (out.kind == auth_kind_t::none)
			return false;
		return true;
	}

	struct status_pill_t
	{
		std::string label;
		ImU32       fill;
		ImU32       text;
	};

	status_pill_t status_pill_for(const std::string& provider_id)
	{
		status_pill_t pill;
		auth_info_t info;
		const bool present = aida::auth::store::get(provider_id, info);
		if (!present || info.kind == auth_kind_t::none) {
			pill.label = "Not configured";
			pill.fill = IM_COL32(70, 75, 90, 200);
			pill.text = IM_COL32(220, 222, 232, 240);
			return pill;
		}
		const auto now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch()).count());
		if (info.kind == auth_kind_t::oauth) {
			if (info.expires_unix > 0 && info.expires_unix <= now) {
				pill.label = "Token expired";
				pill.fill = IM_COL32(170, 110, 60, 220);
				pill.text = IM_COL32(255, 240, 220, 240);
				return pill;
			}
			pill.label = "OAuth";
		} else if (info.kind == auth_kind_t::api) {
			pill.label = "API key";
		} else if (info.kind == auth_kind_t::wellknown) {
			pill.label = "Well-known";
		} else {
			pill.label = "Authenticated";
		}
		pill.fill = IM_COL32(70, 140, 90, 220);
		pill.text = IM_COL32(220, 250, 230, 245);
		return pill;
	}

	std::vector<const catalog_model_t*> collect_models_sorted(const std::string& provider_id)
	{
		std::vector<const catalog_model_t*> out;
		const auto* prov = aida::provider::catalog::get_provider(provider_id);
		if (!prov)
			return out;
		out.reserve(prov->model_ids.size());
		for (const auto& id : prov->model_ids) {
			const auto* m = aida::provider::catalog::get_model(provider_id, id);
			if (m)
				out.push_back(m);
		}
		std::sort(out.begin(), out.end(), [](const catalog_model_t* a, const catalog_model_t* b) {
			const double ca = a->cost.input_per_million + a->cost.output_per_million;
			const double cb = b->cost.input_per_million + b->cost.output_per_million;
			if (ca != cb)
				return ca < cb;
			return a->id < b->id;
		});
		return out;
	}

	std::string preferred_model_for(const std::string& provider_id)
	{
		auto& prefs = g_sa_settings.preferred_model_per_provider;
		auto it = prefs.find(provider_id);
		if (it != prefs.end() && !it->second.empty()) {
			if (aida::provider::catalog::get_model(provider_id, it->second) != nullptr)
				return it->second;
		}
		const auto* def = aida::provider::catalog::default_model(provider_id);
		if (def)
			return def->id;
		return std::string();
	}

	void set_preferred_model_for(const std::string& provider_id, const std::string& model_id)
	{
		g_sa_settings.preferred_model_per_provider[provider_id] = model_id;
	}

	std::string base_url_for(const std::string& provider_id)
	{
		const auto& overrides = g_sa_settings.provider_base_url_overrides;
		auto it = overrides.find(provider_id);
		if (it != overrides.end() && !it->second.empty())
			return it->second;
		const auto* p = aida::provider::catalog::get_provider(provider_id);
		if (p)
			return p->base_url;
		return std::string();
	}

	std::string headers_override_for(const std::string& provider_id)
	{
		const auto& overrides = g_sa_settings.provider_headers_overrides;
		auto it = overrides.find(provider_id);
		if (it != overrides.end())
			return it->second;
		return std::string("{}");
	}

	std::string raw_model_json_for(const std::string& provider_id, const std::string& model_id)
	{
		const auto* m = aida::provider::catalog::get_model(provider_id, model_id);
		if (!m)
			return std::string("{}");
		nlohmann::json j;
		j["id"] = m->id;
		j["name"] = m->name;
		j["family"] = m->family;
		j["release_date"] = m->release_date;
		j["status"] = static_cast<int>(m->status);
		j["api"] = { { "id", m->api.id }, { "url", m->api.url }, { "npm", m->api.npm } };
		j["capabilities"] = {
			{ "temperature", m->capabilities.temperature },
			{ "reasoning", m->capabilities.reasoning },
			{ "attachment", m->capabilities.attachment },
			{ "tool_call", m->capabilities.tool_call },
			{ "interleaved", m->capabilities.interleaved },
			{ "input_modalities", m->capabilities.input_modalities },
			{ "output_modalities", m->capabilities.output_modalities },
		};
		j["cost"] = {
			{ "input_per_million", m->cost.input_per_million },
			{ "output_per_million", m->cost.output_per_million },
			{ "cache_read_per_million", m->cost.cache_read_per_million },
			{ "cache_write_per_million", m->cost.cache_write_per_million },
			{ "over_200k_input_per_million", m->cost.over_200k_input_per_million },
			{ "over_200k_output_per_million", m->cost.over_200k_output_per_million },
		};
		j["limit"] = {
			{ "context", m->limit.context },
			{ "input", m->limit.input },
			{ "output", m->limit.output },
		};
		j["options"] = m->options;
		j["headers"] = m->headers;
		j["variants"] = m->variants;
		return j.dump(2);
	}

	bool split_url(const std::string& url, std::string& host_out, std::string& path_out)
	{
		const size_t scheme_pos = url.find("://");
		if (scheme_pos == std::string::npos) {
			host_out = url;
			path_out = "/";
			return false;
		}
		const size_t host_start = scheme_pos + 3;
		const size_t path_pos = url.find('/', host_start);
		if (path_pos == std::string::npos) {
			host_out = url;
			path_out = "/";
			return true;
		}
		host_out = url.substr(0, path_pos);
		path_out = url.substr(path_pos);
		if (path_out.empty())
			path_out = "/";
		return true;
	}

	std::string trim_trailing_slash(std::string s)
	{
		while (!s.empty() && s.back() == '/')
			s.pop_back();
		return s;
	}

	nlohmann::json build_test_body(const std::string& provider_id, const std::string& model_id)
	{
		nlohmann::json body;
		if (provider_id == "anthropic") {
			body["model"] = model_id;
			body["max_tokens"] = 1;
			nlohmann::json msg;
			msg["role"] = "user";
			msg["content"] = "ping";
			body["messages"] = nlohmann::json::array({ msg });
			return body;
		}
		if (provider_id == "google" || provider_id == "google-vertex" || provider_id == "vertex") {
			nlohmann::json part;
			part["text"] = "ping";
			nlohmann::json content;
			content["role"] = "user";
			content["parts"] = nlohmann::json::array({ part });
			body["contents"] = nlohmann::json::array({ content });
			body["generationConfig"] = { { "maxOutputTokens", 1 } };
			return body;
		}
		body["model"] = model_id;
		body["max_tokens"] = 1;
		body["max_completion_tokens"] = 1;
		body["stream"] = false;
		nlohmann::json msg;
		msg["role"] = "user";
		msg["content"] = "ping";
		body["messages"] = nlohmann::json::array({ msg });
		return body;
	}

	std::string compose_test_path(const std::string& provider_id,
		const std::string& model_id, const std::string& base_path)
	{
		if (provider_id == "anthropic") {
			if (base_path.find("/v1/messages") != std::string::npos)
				return base_path;
			std::string p = trim_trailing_slash(base_path);
			if (p.empty() || p == "/")
				return "/v1/messages";
			return p + "/v1/messages";
		}
		if (provider_id == "google" || provider_id == "google-vertex" || provider_id == "vertex") {
			std::string p = trim_trailing_slash(base_path);
			if (p.empty() || p == "/")
				p = "";
			return p + "/v1beta/models/" + model_id + ":generateContent";
		}
		if (base_path.find("/chat/completions") != std::string::npos)
			return base_path;
		if (base_path.find("/responses") != std::string::npos)
			return base_path;
		std::string p = trim_trailing_slash(base_path);
		if (p.empty() || p == "/")
			return "/v1/chat/completions";
		return p + "/v1/chat/completions";
	}

	void run_test_connection(const std::string& provider_id, const std::string& model_id)
	{
		auto& st = g_state();
		const std::string key = provider_id + "/" + model_id;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			auto it = st.in_flight_tests.find(key);
			if (it != st.in_flight_tests.end() && it->second && it->second->load())
				return;
			auto flag = std::make_shared<std::atomic<bool>>(true);
			st.in_flight_tests[key] = flag;
			test_result_t pending;
			pending.provider_id = provider_id;
			pending.model_id = model_id;
			pending.completed = false;
			st.pending_results[key] = pending;
		}

		std::thread worker([provider_id, model_id, key]() {
			auth_info_t auth_info;
			has_auth_for(provider_id, auth_info);
			std::string endpoint = aida::provider::transforms::resolve_endpoint(provider_id, model_id, auth_info);
			std::map<std::string, std::string> headers = aida::provider::transforms::compute_headers(provider_id, model_id, auth_info);

			const std::string base_url_override = base_url_for(provider_id);
			if (!base_url_override.empty()) {
				std::string ohost;
				std::string opath;
				if (split_url(base_url_override, ohost, opath)) {
					std::string ehost;
					std::string epath;
					if (split_url(endpoint, ehost, epath))
						endpoint = trim_trailing_slash(ohost) + epath;
					else
						endpoint = trim_trailing_slash(ohost);
				}
			}

			const std::string headers_json = headers_override_for(provider_id);
			if (!headers_json.empty()) {
				auto extra = nlohmann::json::parse(headers_json, nullptr, false);
				if (!extra.is_discarded() && extra.is_object()) {
					for (auto it = extra.begin(); it != extra.end(); ++it) {
						if (it.value().is_string())
							headers[it.key()] = it.value().get<std::string>();
					}
				}
			}

			test_result_t result;
			result.provider_id = provider_id;
			result.model_id = model_id;
			result.completed = true;

			if (endpoint.empty()) {
				result.success = false;
				result.message = "no endpoint resolved (auth or catalog missing)";
				auto& st2 = g_state();
				std::lock_guard<std::mutex> lk(st2.mtx);
				st2.pending_results[key] = result;
				auto fit = st2.in_flight_tests.find(key);
				if (fit != st2.in_flight_tests.end() && fit->second)
					fit->second->store(false);
				return;
			}

			std::string host;
			std::string path;
			if (!split_url(endpoint, host, path)) {
				result.success = false;
				result.message = std::string("malformed endpoint: ") + endpoint;
				auto& st2 = g_state();
				std::lock_guard<std::mutex> lk(st2.mtx);
				st2.pending_results[key] = result;
				auto fit = st2.in_flight_tests.find(key);
				if (fit != st2.in_flight_tests.end() && fit->second)
					fit->second->store(false);
				return;
			}

			path = compose_test_path(provider_id, model_id, path);

			httplib::Client cli(host.c_str());
			cli.set_connection_timeout(15);
			cli.set_read_timeout(15);
			cli.set_write_timeout(10);
			cli.set_follow_location(true);
			cli.enable_server_certificate_verification(true);

			httplib::Headers hpp_headers;
			hpp_headers.emplace("User-Agent", "AiDAStandalone/1.0");
			hpp_headers.emplace("Accept", "application/json");
			for (const auto& kv : headers)
				hpp_headers.emplace(kv.first, kv.second);

			const nlohmann::json body = build_test_body(provider_id, model_id);
			const std::string body_str = body.dump();

			const auto t0 = std::chrono::steady_clock::now();
			auto res = cli.Post(path.c_str(), hpp_headers, body_str, "application/json");
			const auto t1 = std::chrono::steady_clock::now();
			result.latency_ms = static_cast<int>(
				std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

			if (!res) {
				result.success = false;
				result.message = std::string("transport error: ") + httplib::to_string(res.error());
			} else {
				result.http_status = res->status;
				if (res->status >= 200 && res->status < 300) {
					result.success = true;
					result.message = std::string("HTTP ") + std::to_string(res->status);
				} else if (res->status == 400 || res->status == 422) {
					result.success = true;
					result.message = std::string("HTTP ") + std::to_string(res->status) + " (auth ok, body rejected)";
				} else if (res->status == 401 || res->status == 403) {
					result.success = false;
					result.message = std::string("HTTP ") + std::to_string(res->status) + " (auth rejected)";
				} else {
					result.success = false;
					std::string snippet = res->body.substr(0, 200);
					result.message = std::string("HTTP ") + std::to_string(res->status) + ": " + snippet;
				}
			}

			auto& st2 = g_state();
			std::lock_guard<std::mutex> lk(st2.mtx);
			st2.pending_results[key] = result;
			auto fit = st2.in_flight_tests.find(key);
			if (fit != st2.in_flight_tests.end() && fit->second)
				fit->second->store(false);
		});
		worker.detach();
	}

	void start_refresh_thread()
	{
		auto& st = g_state();
		bool expected = false;
		if (!st.refresh.in_flight.compare_exchange_strong(expected, true))
			return;
		st.refresh.completed.store(false);
		st.refresh.success.store(false);
		st.refresh.message.clear();

		std::thread worker([]() {
			const bool ok = aida::provider::catalog::fetch_and_cache(10000);
			auto& s = g_state();
			s.refresh.success.store(ok);
			if (!ok)
				s.refresh.message = aida::provider::catalog::last_error();
			else
				s.refresh.message = "Catalog updated";
			s.refresh.completed.store(true);
			s.refresh.in_flight.store(false);
		});
		worker.detach();
	}

	bool buffer_match(const std::string& haystack, const std::string& needle_lower)
	{
		if (needle_lower.empty())
			return true;
		const std::string lh = lower_copy(haystack);
		return lh.find(needle_lower) != std::string::npos;
	}

	bool provider_matches_filter(const catalog_provider_t& p, const std::string& needle)
	{
		if (needle.empty())
			return true;
		if (buffer_match(p.id, needle)) return true;
		if (buffer_match(p.name, needle)) return true;
		for (const auto& mid : p.model_ids) {
			if (buffer_match(mid, needle))
				return true;
		}
		return false;
	}

	void draw_brand_glyph(ImDrawList* dl, float cx, float cy, float radius,
		const catalog_provider_t& p, float alpha)
	{
		const ImU32 fill = ui_anim::theme_alpha(hash_color_for(p.id), alpha);
		const ImU32 ring = ui_anim::theme_alpha(IM_COL32(255, 255, 255, 60), alpha);
		dl->AddCircleFilled(ImVec2(cx, cy), radius, fill, 32);
		dl->AddCircle(ImVec2(cx, cy), radius, ring, 32, 1.5f);
		char letter[2] = { glyph_for(p), '\0' };
		const ImVec2 ts = ImGui::CalcTextSize(letter);
		dl->AddText(ImVec2(cx - ts.x * 0.5f, cy - ts.y * 0.5f),
			ui_anim::theme_alpha(IM_COL32(255, 255, 255, 240), alpha), letter);
	}

	void draw_status_pill(ImDrawList* dl, float x, float y, const status_pill_t& pill, float alpha)
	{
		const ImVec2 ts = ImGui::CalcTextSize(pill.label.c_str());
		const float pad_x = 8.f;
		const float h = ts.y + 4.f;
		const float w = ts.x + pad_x * 2.f;
		const ImU32 fill = ui_anim::theme_alpha(pill.fill, alpha);
		const ImU32 text = ui_anim::theme_alpha(pill.text, alpha);
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h), fill, h * 0.5f);
		dl->AddText(ImVec2(x + pad_x, y + 2.f), text, pill.label.c_str());
	}

	void load_detail_buffers(const std::string& provider_id)
	{
		auto& st = g_state();
		const std::string base = base_url_for(provider_id);
		std::snprintf(st.detail_base_url_buf, sizeof(st.detail_base_url_buf), "%s", base.c_str());
		const std::string headers_json = headers_override_for(provider_id);
		std::snprintf(st.detail_headers_buf, sizeof(st.detail_headers_buf), "%s",
			headers_json.empty() ? "{}" : headers_json.c_str());
		st.detail_buffers_loaded = true;
	}

	void render_provider_card(float ox, float oy, float card_w, float card_h,
		const catalog_provider_t& provider, float alpha,
		float ar, float ag, float ab)
	{
		auto* dl = ImGui::GetWindowDrawList();
		auto& st = g_state();

		const bool selected = (st.selected_detail_provider_id == provider.id);

		const ImU32 panel_bg = ui_anim::theme_alpha(IM_COL32(28, 30, 40, 220), alpha);
		const ImU32 panel_bg_hover = ui_anim::theme_alpha(IM_COL32(38, 42, 56, 230), alpha);
		const ImU32 panel_border = ui_anim::theme_alpha(IM_COL32(60, 66, 82, 150), alpha);
		const ImU32 accent_border = IM_COL32(
			static_cast<int>(ar * 255), static_cast<int>(ag * 255),
			static_cast<int>(ab * 255), static_cast<int>(220 * alpha));

		const ImVec2 card_min(ox, oy);
		const ImVec2 card_max(ox + card_w, oy + card_h);
		const bool hovered = ImGui::IsMouseHoveringRect(card_min, card_max, false);

		dl->AddRectFilled(card_min, card_max, hovered ? panel_bg_hover : panel_bg, 8.f);
		dl->AddRect(card_min, card_max, selected ? accent_border : panel_border,
			8.f, 0, selected ? 2.f : 1.f);

		const float glyph_radius = 20.f;
		const float glyph_cx = ox + 8.f + glyph_radius;
		const float glyph_cy = oy + card_h * 0.5f;
		draw_brand_glyph(dl, glyph_cx, glyph_cy, glyph_radius, provider, alpha);

		const float middle_x = glyph_cx + glyph_radius + 14.f;
		const float middle_w = card_w * 0.40f;

		const ImU32 text_primary = ui_anim::theme_alpha(IM_COL32(225, 228, 240, 245), alpha);
		const ImU32 text_dim = ui_anim::theme_alpha(IM_COL32(160, 165, 180, 200), alpha);

		const std::string display_name = provider.name.empty() ? provider.id : provider.name;
		dl->AddText(ImVec2(middle_x, oy + 10.f), text_primary, display_name.c_str());

		const status_pill_t pill = status_pill_for(provider.id);
		draw_status_pill(dl, middle_x, oy + 32.f, pill, alpha);

		char count_buf[64];
		std::snprintf(count_buf, sizeof(count_buf), "%d models",
			static_cast<int>(provider.model_ids.size()));
		dl->AddText(ImVec2(middle_x, oy + card_h - 22.f), text_dim, count_buf);

		const float right_x = middle_x + middle_w + 14.f;
		const float right_w = card_w - (right_x - ox) - 16.f;
		if (right_w < 100.f)
			return;

		std::string current_model_id = preferred_model_for(provider.id);
		const auto* current_model = current_model_id.empty()
			? nullptr
			: aida::provider::catalog::get_model(provider.id, current_model_id);

		ImGui::SetCursorScreenPos(ImVec2(right_x, oy + 8.f));
		ImGui::PushID(provider.id.c_str());
		ImGui::PushItemWidth(right_w);

		const std::string preview = current_model ? current_model->name : std::string("(no model)");
		const std::string combo_id = std::string("##model_") + provider.id;
		if (ImGui::BeginCombo(combo_id.c_str(), preview.c_str())) {
			const auto models = collect_models_sorted(provider.id);
			for (const auto* m : models) {
				const bool is_sel = (current_model_id == m->id);
				char label[160];
				std::snprintf(label, sizeof(label), "%s  -  %s",
					m->name.c_str(),
					format_cost_pair(m->cost.input_per_million, m->cost.output_per_million).c_str());
				if (ImGui::Selectable(label, is_sel)) {
					set_preferred_model_for(provider.id, m->id);
					g_sa_settings.save();
				}
				if (is_sel)
					ImGui::SetItemDefaultFocus();
			}
			ImGui::EndCombo();
		}
		ImGui::PopItemWidth();

		const float info_y = oy + 38.f;
		std::string cost_label = "cost: ";
		std::string ctx_label = "context: ";
		if (current_model) {
			cost_label += format_cost_pair(current_model->cost.input_per_million,
				current_model->cost.output_per_million);
			ctx_label += format_context(current_model->limit.context);
		} else {
			cost_label += "-";
			ctx_label += "-";
		}
		dl->AddText(ImVec2(right_x, info_y), text_dim, cost_label.c_str());
		dl->AddText(ImVec2(right_x, info_y + 16.f), text_dim, ctx_label.c_str());

		ImGui::SetCursorScreenPos(ImVec2(right_x, oy + card_h - 30.f));

		const std::string test_key = current_model_id.empty()
			? std::string()
			: (provider.id + std::string("/") + current_model_id);
		bool test_running = false;
		test_result_t test_res;
		bool has_result = false;
		if (!test_key.empty()) {
			std::lock_guard<std::mutex> lk(st.mtx);
			auto fit = st.in_flight_tests.find(test_key);
			if (fit != st.in_flight_tests.end() && fit->second)
				test_running = fit->second->load();
			auto rit = st.pending_results.find(test_key);
			if (rit != st.pending_results.end()) {
				test_res = rit->second;
				has_result = test_res.completed;
			}
		}

		const std::string test_label = test_running ? std::string("Testing...") : std::string("Test");
		if (ImGui::Button((test_label + std::string("##") + provider.id).c_str(), ImVec2(80.f, 22.f))) {
			if (!test_running && !current_model_id.empty()) {
				run_test_connection(provider.id, current_model_id);
			}
		}
		ImGui::SameLine();

		const bool is_default = (g_sa_settings.default_provider_id == provider.id);
		const std::string default_label = is_default ? std::string("Default *") : std::string("Set default");
		if (ImGui::Button((default_label + std::string("##def_") + provider.id).c_str(), ImVec2(110.f, 22.f))) {
			if (!current_model_id.empty()) {
				g_sa_settings.set_selection(provider.id, current_model_id);
				g_sa_settings.save();
				aida::events::model_changed_t evt;
				evt.session_id.clear();
				evt.provider_id = provider.id;
				evt.model_id = current_model_id;
				aida::events::publish(aida::events::event_model_changed, evt);
				toast_notification::push(std::string("Default set: ") + display_name + " / " + current_model_id,
					toast_notification::toast_type_t::info, 3.5f);
			} else {
				toast_notification::push("Pick a model first",
					toast_notification::toast_type_t::warning, 3.0f);
			}
		}
		ImGui::SameLine();
		const std::string detail_label = (selected ? std::string("Hide details") : std::string("Details"));
		if (ImGui::Button((detail_label + std::string("##det_") + provider.id).c_str(), ImVec2(96.f, 22.f))) {
			if (selected) {
				st.selected_detail_provider_id.clear();
				st.detail_buffers_loaded = false;
			} else {
				st.selected_detail_provider_id = provider.id;
				load_detail_buffers(provider.id);
			}
		}

		if (has_result) {
			const ImU32 res_col = test_res.success
				? ui_anim::theme_alpha(IM_COL32(110, 200, 130, 230), alpha)
				: ui_anim::theme_alpha(IM_COL32(220, 110, 110, 230), alpha);
			char buf[256];
			if (test_res.success) {
				std::snprintf(buf, sizeof(buf), "OK %dms - %s",
					test_res.latency_ms, test_res.message.c_str());
			} else {
				std::snprintf(buf, sizeof(buf), "FAIL: %s", truncate_text(test_res.message, 90).c_str());
			}
			dl->AddText(ImVec2(right_x, oy + card_h - 50.f), res_col, buf);
		}

		ImGui::PopID();
	}

	void render_detail_pane(float panel_w, float panel_h, float ox, float oy,
		float pane_w, float pane_h, float alpha, float ar, float ag, float ab)
	{
		(void)panel_w;
		(void)panel_h;
		auto* dl = ImGui::GetWindowDrawList();
		auto& st = g_state();
		if (st.selected_detail_provider_id.empty())
			return;

		const ImU32 bg = ui_anim::theme_alpha(IM_COL32(20, 22, 30, 230), alpha);
		const ImU32 border = ui_anim::theme_alpha(IM_COL32(60, 66, 82, 160), alpha);
		dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + pane_w, oy + pane_h), bg, 8.f);
		dl->AddRect(ImVec2(ox, oy), ImVec2(ox + pane_w, oy + pane_h), border, 8.f, 0, 1.f);

		const auto* prov = aida::provider::catalog::get_provider(st.selected_detail_provider_id);
		if (!prov) {
			st.selected_detail_provider_id.clear();
			return;
		}

		ImGui::PushID("provider_detail_pane");
		const ImU32 text_primary = ui_anim::theme_alpha(IM_COL32(225, 228, 240, 245), alpha);
		const std::string title = std::string("Details: ") + (prov->name.empty() ? prov->id : prov->name);
		dl->AddText(ImVec2(ox + 14.f, oy + 10.f), text_primary, title.c_str());

		ImGui::SetCursorScreenPos(ImVec2(ox + 14.f, oy + 36.f));
		const float input_w = pane_w - 28.f;

		ImGui::TextUnformatted("Base URL");
		ImGui::SetCursorScreenPos(ImVec2(ox + 14.f, oy + 56.f));
		ImGui::PushItemWidth(input_w);
		ImGui::InputText("##detail_base_url", st.detail_base_url_buf, sizeof(st.detail_base_url_buf));
		ImGui::PopItemWidth();

		ImGui::SetCursorScreenPos(ImVec2(ox + 14.f, oy + 88.f));
		ImGui::TextUnformatted("Extra headers JSON");
		ImGui::SetCursorScreenPos(ImVec2(ox + 14.f, oy + 108.f));
		ImGui::InputTextMultiline("##detail_headers", st.detail_headers_buf, sizeof(st.detail_headers_buf),
			ImVec2(input_w, 100.f));

		ImGui::SetCursorScreenPos(ImVec2(ox + 14.f, oy + 220.f));
		if (ImGui::Button("Save##detail_save", ImVec2(110.f, 24.f))) {
			const std::string base = sa_settings_detail::trim(std::string(st.detail_base_url_buf));
			if (base.empty())
				g_sa_settings.provider_base_url_overrides.erase(st.selected_detail_provider_id);
			else
				g_sa_settings.provider_base_url_overrides[st.selected_detail_provider_id] = base;
			std::string headers_text = std::string(st.detail_headers_buf);
			auto parsed = nlohmann::json::parse(headers_text, nullptr, false);
			if (parsed.is_discarded() || !parsed.is_object()) {
				toast_notification::push("Headers JSON invalid - not saved",
					toast_notification::toast_type_t::warning, 4.0f);
			} else {
				g_sa_settings.provider_headers_overrides[st.selected_detail_provider_id] = headers_text;
				g_sa_settings.save();
				toast_notification::push("Provider details saved",
					toast_notification::toast_type_t::info, 3.0f);
			}
		}
		ImGui::SameLine();
		if (ImGui::Button("Reset##detail_reset", ImVec2(110.f, 24.f))) {
			g_sa_settings.provider_base_url_overrides.erase(st.selected_detail_provider_id);
			g_sa_settings.provider_headers_overrides.erase(st.selected_detail_provider_id);
			g_sa_settings.save();
			load_detail_buffers(st.selected_detail_provider_id);
			toast_notification::push("Provider overrides cleared",
				toast_notification::toast_type_t::info, 3.0f);
		}
		ImGui::SameLine();
		ImGui::Checkbox("Show raw model.json", &st.show_raw_model_json);

		if (st.show_raw_model_json) {
			const std::string mid = preferred_model_for(st.selected_detail_provider_id);
			const std::string raw = raw_model_json_for(st.selected_detail_provider_id, mid);
			ImGui::SetCursorScreenPos(ImVec2(ox + 14.f, oy + 256.f));
			ImGui::PushTextWrapPos(ox + pane_w - 14.f);
			const ImU32 dim = ui_anim::theme_alpha(IM_COL32(170, 175, 195, 220), alpha);
			ImGui::PushStyleColor(ImGuiCol_Text, dim);
			ImGui::TextUnformatted(raw.c_str());
			ImGui::PopStyleColor();
			ImGui::PopTextWrapPos();
		}

		(void)ar; (void)ag; (void)ab;
		ImGui::PopID();
	}

}

void initialize()
{
	auto& st = g_state();
	if (st.initialized)
		return;
	st.initialized = true;
	st.shutdown_flag.store(false);
	if (aida::provider::catalog::list_providers().empty()) {
		std::thread bg([]() {
			aida::provider::catalog::load_cached_or_fetch(86400);
		});
		bg.detach();
	}
}

void shutdown()
{
	auto& st = g_state();
	st.shutdown_flag.store(true);
	st.initialized = false;
}

const std::string& last_error()
{
	auto& st = g_state();
	return st.last_error;
}

void render(float panel_w, float panel_h)
{
	auto& st = g_state();
	if (!st.initialized)
		initialize();

	const float ar = globals::ui::accent.x;
	const float ag = globals::ui::accent.y;
	const float ab = globals::ui::accent.z;
	const float alpha = 1.0f;

	{
		std::lock_guard<std::mutex> lk(st.mtx);
		if (st.refresh.completed.exchange(false)) {
			if (st.refresh.success.load()) {
				toast_notification::push("Provider catalog refreshed",
					toast_notification::toast_type_t::info, 3.0f);
			} else {
				toast_notification::push(std::string("Refresh failed: ") + truncate_text(st.refresh.message, 200),
					toast_notification::toast_type_t::error, 5.0f);
			}
		}
	}

	ImGui::BeginChild("##provider_view_root", ImVec2(panel_w, panel_h), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

	const ImVec2 wp = ImGui::GetWindowPos();
	const float root_x = wp.x;
	const float root_y = wp.y;
	const float root_w = panel_w;
	const float root_h = panel_h;

	const float toolbar_h = 32.f;
	const float pad = 12.f;

	const float search_w = (root_w - pad * 3.f) * 0.62f;
	ImGui::SetCursorScreenPos(ImVec2(root_x + pad, root_y + 4.f));
	ui_anim::render_filter_input_chip("##provider_filter", st.search_buf, sizeof(st.search_buf),
		"Filter providers / models", search_w, ar, ag, ab, alpha);

	const float btn_w = 220.f;
	const float btn_x = root_x + root_w - pad - btn_w;
	ImGui::SetCursorScreenPos(ImVec2(btn_x, root_y + 4.f));
	const bool refreshing = st.refresh.in_flight.load();
	const std::string refresh_label = refreshing
		? std::string("Refreshing...##rf")
		: std::string("Refresh from models.dev##rf");
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(ar * 0.35f, ag * 0.35f, ab * 0.35f, 0.6f));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(ar * 0.55f, ag * 0.55f, ab * 0.55f, 0.8f));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(ar * 0.7f, ag * 0.7f, ab * 0.7f, 1.f));
	if (ImGui::Button(refresh_label.c_str(), ImVec2(btn_w, 24.f))) {
		if (!refreshing)
			start_refresh_thread();
	}
	ImGui::PopStyleColor(3);

	const auto& providers = aida::provider::catalog::list_providers();
	const std::string filter = lower_copy(std::string(st.search_buf));

	std::vector<const catalog_provider_t*> filtered;
	filtered.reserve(providers.size());
	for (const auto& p : providers) {
		if (provider_matches_filter(p, filter))
			filtered.push_back(&p);
	}

	const float body_y = root_y + toolbar_h + 8.f;
	const bool detail_open = !st.selected_detail_provider_id.empty();
	const float detail_w = detail_open ? std::min(420.f, root_w * 0.34f) : 0.f;
	const float list_w = root_w - detail_w - (detail_open ? pad : 0.f);
	const float body_h = root_h - (toolbar_h + 8.f) - 36.f;

	ImGui::SetCursorScreenPos(ImVec2(root_x, body_y));
	ImGui::BeginChild("##provider_list_scroll", ImVec2(list_w, body_h), false,
		ImGuiWindowFlags_NoBackground);

	const float list_inner_w = list_w - pad * 2.f;
	const float card_w = list_inner_w;
	const float card_h = 96.f;
	const float gap = 10.f;

	if (filtered.empty()) {
		auto* dl = ImGui::GetWindowDrawList();
		const ImVec2 wp_inner = ImGui::GetCursorScreenPos();
		const ImU32 dim = IM_COL32(170, 175, 195, static_cast<int>(220 * alpha));
		const char* msg = providers.empty()
			? "Catalog empty - click Refresh to fetch from models.dev"
			: "No providers match the filter";
		dl->AddText(ImVec2(wp_inner.x + pad, wp_inner.y + 8.f), dim, msg);
		ImGui::Dummy(ImVec2(card_w, 32.f));
	}

	for (const auto* prov : filtered) {
		ImGui::Dummy(ImVec2(pad, 0.f));
		ImGui::SameLine();
		const ImVec2 sp = ImGui::GetCursorScreenPos();
		render_provider_card(sp.x, sp.y, card_w, card_h, *prov, alpha, ar, ag, ab);
		ImGui::SetCursorScreenPos(sp);
		ImGui::Dummy(ImVec2(card_w, card_h + gap));
	}

	ImGui::EndChild();

	if (detail_open) {
		const float detail_x = root_x + list_w + pad * 0.5f;
		render_detail_pane(panel_w, panel_h, detail_x, body_y, detail_w, body_h, alpha, ar, ag, ab);
	}

	auto* dl = ImGui::GetWindowDrawList();
	const float callout_y = root_y + root_h - 30.f;
	const float callout_h = 24.f;
	bool show_age_callout = false;
	int64_t cache_age = -1;
	{
		std::error_code ec;
		wchar_t* appdata = nullptr;
		std::filesystem::path cache_p;
		if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
			cache_p = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"models.json";
			CoTaskMemFree(appdata);
		}
		if (!cache_p.empty() && std::filesystem::exists(cache_p, ec)) {
			const auto ftime = std::filesystem::last_write_time(cache_p, ec);
			if (!ec) {
				const auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
					ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
				const auto now = std::chrono::system_clock::now();
				cache_age = std::chrono::duration_cast<std::chrono::seconds>(now - sctp).count();
			}
		}
	}
	if (cache_age > 3600)
		show_age_callout = true;

	if (show_age_callout) {
		ui_anim::render_inline_callout(dl, root_x + pad, callout_y,
			root_w - pad * 2.f, callout_h,
			"Catalog cached - click Refresh for latest",
			ui_anim::callout_kind_t::info, ar, ag, ab, alpha);
	}

	ImGui::EndChild();
}

void render_chat_header_picker(float max_width)
{
	auto& st = g_state();
	if (!st.initialized)
		initialize();

	const std::string current_provider = g_sa_settings.default_provider_id;
	const std::string current_model = g_sa_settings.default_model_id;

	std::string label;
	if (current_provider.empty() || current_model.empty()) {
		label = "Select model";
	} else {
		const auto* prov = aida::provider::catalog::get_provider(current_provider);
		const auto* model = aida::provider::catalog::get_model(current_provider, current_model);
		const std::string p_disp = prov ? (prov->name.empty() ? prov->id : prov->name) : current_provider;
		const std::string m_disp = model ? model->name : current_model;
		label = p_disp + " / " + m_disp;
	}

	const float w = (max_width <= 0.f) ? 360.f : std::min(max_width, 480.f);
	ImGui::PushID("chat_header_picker");
	ImGui::PushItemWidth(w);
	if (ImGui::BeginCombo("##chat_model_picker", label.c_str())) {
		const auto& providers = aida::provider::catalog::list_providers();
		for (const auto& p : providers) {
			if (p.model_ids.empty())
				continue;
			const std::string p_label = p.name.empty() ? p.id : p.name;
			ImGui::Separator();
			ImGui::TextDisabled("%s", p_label.c_str());
			const auto models = collect_models_sorted(p.id);
			for (const auto* m : models) {
				const bool is_sel = (current_provider == p.id) && (current_model == m->id);
				char ml[256];
				const std::string cost = format_cost_pair(m->cost.input_per_million, m->cost.output_per_million);
				const std::string ctx = format_context(m->limit.context);
				std::snprintf(ml, sizeof(ml), "  %s   %s   %s##%s_%s",
					m->name.c_str(), cost.c_str(), ctx.c_str(),
					p.id.c_str(), m->id.c_str());
				if (ImGui::Selectable(ml, is_sel)) {
					g_sa_settings.set_selection(p.id, m->id);
					set_preferred_model_for(p.id, m->id);
					g_sa_settings.save();
					aida::events::model_changed_t evt;
					evt.session_id.clear();
					evt.provider_id = p.id;
					evt.model_id = m->id;
					aida::events::publish(aida::events::event_model_changed, evt);
				}
				if (is_sel)
					ImGui::SetItemDefaultFocus();
			}
		}
		ImGui::EndCombo();
	}
	ImGui::PopItemWidth();
	ImGui::PopID();
}

}
}
