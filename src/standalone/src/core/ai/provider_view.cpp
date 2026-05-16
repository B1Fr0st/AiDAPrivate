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
#include <nlohmann/json.hpp>

#include "auth_store.hpp"
#include "../auth/auth_http.hpp"
#include "event_bus.hpp"
#include "provider_catalog.hpp"
#include "provider_transforms.hpp"
#include "standalone_settings.hpp"
#include "toast_notification.hpp"
#include "ui_anim.hpp"
#include "work_queue.hpp"
#include "../ui/avatar.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/brand.hpp"
#include "../ui/clock.hpp"
#include "../ui/components.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/fonts.hpp"
#include "../ui/motion.hpp"
#include "../ui/theme.hpp"
#include "../ui/transition.hpp"
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

	struct card_anim_t
	{
		aida::ui::hover_state_t hover;
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
		std::unordered_map<std::string, card_anim_t> card_anims;
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

	struct status_summary_t
	{
		std::string label;
		aida::ui::pill_kind_t kind;
		bool dot_pulse;
	};

	status_summary_t status_for(const std::string& provider_id)
	{
		status_summary_t s;
		auth_info_t info;
		const bool present = aida::auth::store::get(provider_id, info);
		if (!present || info.kind == auth_kind_t::none) {
			s.label = "Not configured";
			s.kind = aida::ui::pill_kind_t::neutral;
			s.dot_pulse = false;
			return s;
		}
		const auto now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch()).count());
		if (info.kind == auth_kind_t::oauth) {
			if (info.expires_unix > 0 && info.expires_unix <= now) {
				s.label = "Token expired";
				s.kind = aida::ui::pill_kind_t::warning;
				s.dot_pulse = true;
				return s;
			}
			s.label = "OAuth";
		} else if (info.kind == auth_kind_t::api) {
			s.label = "API key";
		} else if (info.kind == auth_kind_t::wellknown) {
			s.label = "Well-known";
		} else {
			s.label = "Authenticated";
		}
		s.kind = aida::ui::pill_kind_t::success;
		s.dot_pulse = true;
		return s;
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
		const bool is_o_series =
			model_id.find("o1") != std::string::npos ||
			model_id.find("o3") != std::string::npos ||
			model_id.find("o4") != std::string::npos ||
			model_id.find("o5") != std::string::npos;
		if (is_o_series)
			body["max_completion_tokens"] = 1;
		else
			body["max_tokens"] = 1;
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

	struct test_job_t
	{
		std::string                       provider_id;
		std::string                       model_id;
		std::string                       key;
		std::shared_ptr<std::atomic<bool>> flag;
	};

	void finalize_test_result(const std::shared_ptr<test_job_t>& job, const test_result_t& result)
	{
		auto& st = g_state();
		std::lock_guard<std::mutex> lk(st.mtx);
		if (st.shutdown_flag.load()) {
			if (job->flag)
				job->flag->store(false);
			st.in_flight_tests.erase(job->key);
			st.pending_results.erase(job->key);
			return;
		}
		st.pending_results[job->key] = result;
		auto fit = st.in_flight_tests.find(job->key);
		if (fit != st.in_flight_tests.end() && fit->second)
			fit->second->store(false);
	}

	void run_test_connection(const std::string& provider_id, const std::string& model_id)
	{
		auto& st = g_state();
		if (st.shutdown_flag.load())
			return;
		auto job = std::make_shared<test_job_t>();
		job->provider_id = provider_id;
		job->model_id = model_id;
		job->key = provider_id + "/" + model_id;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			if (st.shutdown_flag.load())
				return;
			auto it = st.in_flight_tests.find(job->key);
			if (it != st.in_flight_tests.end() && it->second && it->second->load())
				return;
			job->flag = std::make_shared<std::atomic<bool>>(true);
			st.in_flight_tests[job->key] = job->flag;
			test_result_t pending;
			pending.provider_id = provider_id;
			pending.model_id = model_id;
			pending.completed = false;
			st.pending_results[job->key] = pending;
		}

		const bool posted = work_queue::post([job]() {
			auto& st_w = g_state();
			if (st_w.shutdown_flag.load()) {
				std::lock_guard<std::mutex> lk(st_w.mtx);
				if (job->flag)
					job->flag->store(false);
				st_w.in_flight_tests.erase(job->key);
				st_w.pending_results.erase(job->key);
				return;
			}

			auth_info_t auth_info;
			has_auth_for(job->provider_id, auth_info);
			std::string endpoint = aida::provider::transforms::resolve_endpoint(job->provider_id, job->model_id, auth_info);
			std::map<std::string, std::string> headers = aida::provider::transforms::compute_headers(job->provider_id, job->model_id, auth_info);

			if (st_w.shutdown_flag.load()) {
				std::lock_guard<std::mutex> lk(st_w.mtx);
				if (job->flag)
					job->flag->store(false);
				st_w.in_flight_tests.erase(job->key);
				st_w.pending_results.erase(job->key);
				return;
			}

			const std::string base_url_override = base_url_for(job->provider_id);
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

			const std::string headers_json = headers_override_for(job->provider_id);
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
			result.provider_id = job->provider_id;
			result.model_id = job->model_id;
			result.completed = true;

			if (endpoint.empty()) {
				result.success = false;
				result.message = "no endpoint resolved (auth or catalog missing)";
				finalize_test_result(job, result);
				return;
			}

			std::string host;
			std::string path;
			if (!split_url(endpoint, host, path)) {
				result.success = false;
				result.message = std::string("malformed endpoint: ") + endpoint;
				finalize_test_result(job, result);
				return;
			}

			if (st_w.shutdown_flag.load()) {
				std::lock_guard<std::mutex> lk(st_w.mtx);
				if (job->flag)
					job->flag->store(false);
				st_w.in_flight_tests.erase(job->key);
				st_w.pending_results.erase(job->key);
				return;
			}

			path = compose_test_path(job->provider_id, job->model_id, path);

			aida::auth::http::header_list_t test_headers;
			test_headers.reserve(headers.size() + 2);
			test_headers.emplace_back("User-Agent", "AiDAStandalone/1.0");
			test_headers.emplace_back("Accept", "application/json");
			for (const auto& kv : headers)
				test_headers.emplace_back(kv.first, kv.second);

			const nlohmann::json body = build_test_body(job->provider_id, job->model_id);
			const std::string body_str = body.dump();

			std::string post_host = host;
			while (!post_host.empty() && post_host.back() == '/')
				post_host.pop_back();
			const std::string test_url = post_host
				+ (path.empty() ? std::string("/") : (path.front() == '/' ? path : std::string("/") + path));

			const auto t0 = std::chrono::steady_clock::now();
			aida::auth::http::response_t res = aida::auth::http::post(
				test_url, test_headers, body_str,
				std::string("application/json"), 20);
			const auto t1 = std::chrono::steady_clock::now();
			result.latency_ms = static_cast<int>(
				std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

			if (st_w.shutdown_flag.load()) {
				std::lock_guard<std::mutex> lk(st_w.mtx);
				if (job->flag)
					job->flag->store(false);
				st_w.in_flight_tests.erase(job->key);
				st_w.pending_results.erase(job->key);
				return;
			}

			if (!res.ok && res.status == 0) {
				result.success = false;
				result.message = std::string("transport error: ")
					+ (res.error.empty() ? std::string("connection failed") : res.error);
			} else {
				result.http_status = res.status;
				if (res.status >= 200 && res.status < 300) {
					result.success = true;
					result.message = std::string("HTTP ") + std::to_string(res.status);
				} else if (res.status == 400 || res.status == 422) {
					result.success = true;
					result.message = std::string("HTTP ") + std::to_string(res.status) + " (auth ok, body rejected)";
				} else if (res.status == 401 || res.status == 403) {
					result.success = false;
					result.message = std::string("HTTP ") + std::to_string(res.status) + " (auth rejected)";
				} else {
					result.success = false;
					std::string snippet = res.body.substr(0, 200);
					result.message = std::string("HTTP ") + std::to_string(res.status) + ": " + snippet;
				}
			}

			finalize_test_result(job, result);
		});

		if (!posted) {
			std::lock_guard<std::mutex> lk(st.mtx);
			if (job->flag)
				job->flag->store(false);
			st.in_flight_tests.erase(job->key);
			st.pending_results.erase(job->key);
		}
	}

	void start_refresh_thread()
	{
		auto& st = g_state();
		if (st.shutdown_flag.load())
			return;
		bool expected = false;
		if (!st.refresh.in_flight.compare_exchange_strong(expected, true))
			return;
		st.refresh.completed.store(false);
		st.refresh.success.store(false);
		st.refresh.message.clear();

		const bool posted = work_queue::post([]() {
			auto& s = g_state();
			if (s.shutdown_flag.load()) {
				s.refresh.completed.store(false);
				s.refresh.in_flight.store(false);
				return;
			}
			const bool ok = aida::provider::catalog::fetch_and_cache(10000);
			if (s.shutdown_flag.load()) {
				s.refresh.completed.store(false);
				s.refresh.in_flight.store(false);
				return;
			}
			s.refresh.success.store(ok);
			if (!ok)
				s.refresh.message = aida::provider::catalog::last_error();
			else
				s.refresh.message = "Catalog updated";
			s.refresh.completed.store(true);
			s.refresh.in_flight.store(false);
		});

		if (!posted) {
			st.refresh.in_flight.store(false);
			st.refresh.completed.store(false);
		}
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

	void draw_anthropic_glyph(ImDrawList* dl, ImVec2 c, float r, ImU32 col, float alpha)
	{
		ImU32 cf = aida::ui::with_alpha(col, alpha);
		ImVec2 p0(c.x - r * 0.5f, c.y + r * 0.55f);
		ImVec2 p1(c.x, c.y - r * 0.65f);
		ImVec2 p2(c.x + r * 0.5f, c.y + r * 0.55f);
		dl->AddLine(p0, p1, cf, r * 0.18f);
		dl->AddLine(p1, p2, cf, r * 0.18f);
		dl->AddLine(ImVec2(c.x - r * 0.2f, c.y + r * 0.05f),
			ImVec2(c.x + r * 0.2f, c.y + r * 0.05f), cf, r * 0.14f);
	}

	void draw_openai_glyph(ImDrawList* dl, ImVec2 c, float r, ImU32 col, float alpha)
	{
		ImU32 cf = aida::ui::with_alpha(col, alpha);
		const int lobes = 3;
		for (int i = 0; i < lobes; ++i) {
			float ang = static_cast<float>(i) * (6.2831853f / lobes) - 1.5707963f;
			ImVec2 lc(c.x + cosf(ang) * r * 0.35f, c.y + sinf(ang) * r * 0.35f);
			dl->AddCircle(lc, r * 0.45f, cf, 32, r * 0.10f);
		}
	}

	void draw_google_glyph(ImDrawList* dl, ImVec2 c, float r, ImU32 col, float alpha)
	{
		ImU32 cf = aida::ui::with_alpha(col, alpha);
		dl->PathArcTo(c, r * 0.7f, 0.f, 5.f, 32);
		dl->PathStroke(cf, 0, r * 0.18f);
		dl->AddLine(ImVec2(c.x + r * 0.7f, c.y), ImVec2(c.x + r * 0.15f, c.y),
			cf, r * 0.18f);
	}

	void draw_mistral_glyph(ImDrawList* dl, ImVec2 c, float r, ImU32 col, float alpha)
	{
		ImU32 cf = aida::ui::with_alpha(col, alpha);
		float h = r * 1.2f;
		for (int i = 0; i < 4; ++i) {
			float x = c.x + (-1.5f + static_cast<float>(i)) * (r * 0.30f);
			dl->AddLine(ImVec2(x, c.y - h * 0.35f), ImVec2(x, c.y + h * 0.35f), cf, r * 0.14f);
		}
		dl->AddLine(ImVec2(c.x - r * 0.55f, c.y - h * 0.35f),
			ImVec2(c.x + r * 0.55f, c.y - h * 0.35f), cf, r * 0.14f);
	}

	void draw_provider_mark(ImDrawList* dl, ImVec2 center, float radius,
		const catalog_provider_t& p, float alpha)
	{
		const auto& th = aida::ui::resolved();
		ImU32 base = aida::ui::brand::hash_color(p.id.c_str(), th.is_dark ? 0.55f : 0.50f);
		ImU32 top = aida::ui::lighten(base, 30);
		ImU32 bot = aida::ui::darken(base, 20);
		int segs = 32;
		for (int i = 0; i < segs; ++i) {
			float a0 = (static_cast<float>(i) / segs) * 6.2831853f - 1.5707963f;
			float a1 = (static_cast<float>(i + 1) / segs) * 6.2831853f - 1.5707963f;
			float fy = (sinf(a0) + 1.f) * 0.5f;
			ImU32 col = aida::ui::mix(top, bot, fy);
			ImVec2 p0(center.x + cosf(a0) * radius, center.y + sinf(a0) * radius);
			ImVec2 p1(center.x + cosf(a1) * radius, center.y + sinf(a1) * radius);
			dl->AddTriangleFilled(center, p0, p1, aida::ui::with_alpha(col, alpha));
		}

		ImU32 ring = aida::ui::with_alpha(th.is_dark ? IM_COL32(255, 255, 255, 50)
			: IM_COL32(0, 0, 0, 60), alpha);
		dl->AddCircle(center, radius - 0.5f, ring, 32, 1.f);

		ImU32 fg = IM_COL32(255, 255, 255, 240);
		float r = (static_cast<float>((base >> IM_COL32_R_SHIFT) & 0xFF)) / 255.f;
		float g = (static_cast<float>((base >> IM_COL32_G_SHIFT) & 0xFF)) / 255.f;
		float b = (static_cast<float>((base >> IM_COL32_B_SHIFT) & 0xFF)) / 255.f;
		float lum = 0.299f * r + 0.587f * g + 0.114f * b;
		if (lum > 0.65f) fg = IM_COL32(20, 20, 30, 240);

		const std::string& id = p.id;
		if (id == "anthropic") draw_anthropic_glyph(dl, center, radius * 0.85f, fg, alpha);
		else if (id == "openai") draw_openai_glyph(dl, center, radius * 0.85f, fg, alpha);
		else if (id == "google" || id == "google-vertex" || id == "vertex")
			draw_google_glyph(dl, center, radius * 0.85f, fg, alpha);
		else if (id == "mistral" || id == "mistralai") draw_mistral_glyph(dl, center, radius * 0.85f, fg, alpha);
		else {
			std::string seed = p.name.empty() ? p.id : p.name;
			char glyph[2] = { aida::ui::avatar::first_glyph(seed), 0 };
			ImFont* f = aida::ui::fonts::body_strong();
			float fs = radius * 1.05f;
			ImVec2 sz = f->CalcTextSizeA(fs, FLT_MAX, 0.f, glyph);
			dl->AddText(f, fs, ImVec2(center.x - sz.x * 0.5f, center.y - sz.y * 0.5f),
				aida::ui::with_alpha(fg, alpha), glyph);
		}
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

	double max_total_cost_in_catalog()
	{
		const auto& providers = aida::provider::catalog::list_providers();
		double max_v = 0.0;
		for (const auto& p : providers) {
			std::string mid = preferred_model_for(p.id);
			if (mid.empty()) continue;
			const auto* m = aida::provider::catalog::get_model(p.id, mid);
			if (!m) continue;
			double total = m->cost.input_per_million + m->cost.output_per_million;
			if (total > max_v) max_v = total;
		}
		if (max_v <= 0.0) max_v = 1.0;
		return max_v;
	}

	void render_capability_badges(ImVec2 origin, const catalog_model_t* m, float alpha)
	{
		if (m == nullptr) return;
		const auto& th = aida::ui::resolved();
		struct cap_t { const char* label; bool active; ImU32 col; };
		ImU32 col_temp = th.info;
		ImU32 col_reason = th.accent_u32;
		ImU32 col_attach = th.success;
		ImU32 col_tool = th.warning;
		ImU32 col_inter = th.accent_grad_top;
		cap_t caps[] = {
			{ "temp", m->capabilities.temperature, col_temp },
			{ "reason", m->capabilities.reasoning, col_reason },
			{ "attach", m->capabilities.attachment, col_attach },
			{ "tools", m->capabilities.tool_call, col_tool },
			{ "inter", m->capabilities.interleaved, col_inter },
		};
		float x = origin.x;
		float y = origin.y;
		for (const auto& c : caps) {
			if (!c.active) continue;
			ImGui::SetCursorScreenPos(ImVec2(x, y));
			aida::ui::badge(c.label, aida::ui::with_alpha(c.col, alpha * 0.85f), 4.f);
			ImVec2 sz = ImGui::CalcTextSize(c.label);
			x += sz.x + 14.f;
		}
	}

	void render_provider_card(float ox, float oy, float card_w, float card_h,
		const catalog_provider_t& provider, float alpha, double max_total_cost,
		float dt)
	{
		auto& st = g_state();
		const auto& th = aida::ui::resolved();
		auto* dl = ImGui::GetWindowDrawList();

		const bool selected = (st.selected_detail_provider_id == provider.id);

		card_anim_t* ca = nullptr;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			ca = &st.card_anims[provider.id];
		}

		ImGui::PushID(provider.id.c_str());
		ImGui::SetCursorScreenPos(ImVec2(ox, oy));
		ImGui::SetNextItemAllowOverlap();
		ImGui::InvisibleButton("##card_hit", ImVec2(card_w, card_h));
		bool hov = ImGui::IsItemHovered();
		bool clicked = ImGui::IsItemClicked();
		ImGui::PopID();

		float hov_v = ca->hover.tick(hov, dt, aida::motion::spring::playful);
		float lift = hov_v * 3.f;

		ImVec2 card_a(ox, oy - lift);
		ImVec2 card_b(ox + card_w, oy + card_h - lift);

		if (hov_v > 0.05f) {
			aida::ui::blur::render_drop_shadow(dl, card_a, card_b, 12.f, 5,
				0.30f * hov_v, ImVec2(0.f, 4.f * hov_v));
		}

		ImU32 fill = aida::ui::mix(
			aida::ui::with_alpha(th.panel_header, alpha * 0.85f),
			aida::ui::with_alpha(th.bg_elevated, alpha),
			0.3f + hov_v * 0.3f);
		dl->AddRectFilled(card_a, card_b, fill, 12.f);
		dl->AddRect(card_a, card_b,
			selected ? th.accent_u32 :
			aida::ui::with_alpha(th.border_subtle, alpha * (0.7f + hov_v * 0.4f)),
			12.f, 0, selected ? 1.6f : 1.f);

		const float glyph_radius = 22.f;
		const float glyph_cx = card_a.x + 14.f + glyph_radius;
		const float glyph_cy = (card_a.y + card_b.y) * 0.5f;
		draw_provider_mark(dl, ImVec2(glyph_cx, glyph_cy), glyph_radius, provider, alpha);

		const float middle_x = glyph_cx + glyph_radius + 14.f;
		const float middle_w = card_w * 0.36f;

		const float card_fs = aida::ui::components::detail::ui_fs();
		const std::string display_name = provider.name.empty() ? provider.id : provider.name;
		dl->AddText(aida::ui::fonts::body_strong(), card_fs * 1.06f,
			ImVec2(middle_x, card_a.y + 12.f),
			aida::ui::with_alpha(th.text_primary, alpha), display_name.c_str());

		status_summary_t status = status_for(provider.id);
		ImGui::SetCursorScreenPos(ImVec2(middle_x, card_a.y + 38.f));
		aida::ui::pill_kind(status.label.c_str(), status.kind,
			aida::ui::size_t_::sm, status.dot_pulse);

		std::string current_model_id = preferred_model_for(provider.id);
		const auto* current_model = current_model_id.empty()
			? nullptr
			: aida::provider::catalog::get_model(provider.id, current_model_id);

		if (current_model) {
			render_capability_badges(ImVec2(middle_x, card_a.y + card_h - 28.f),
				current_model, alpha);
		} else {
			char count_buf[64];
			std::snprintf(count_buf, sizeof(count_buf), "%d models",
				static_cast<int>(provider.model_ids.size()));
			dl->AddText(aida::ui::fonts::caption(), card_fs * 0.86f,
				ImVec2(middle_x, card_a.y + card_h - 24.f),
				aida::ui::with_alpha(th.text_secondary, alpha), count_buf);
		}

		const float right_x = middle_x + middle_w + 14.f;
		const float right_w = card_w - (right_x - card_a.x) - 16.f;
		if (right_w < 100.f) {
			if (clicked) {
				if (selected) {
					st.selected_detail_provider_id.clear();
					st.detail_buffers_loaded = false;
				} else {
					st.selected_detail_provider_id = provider.id;
					load_detail_buffers(provider.id);
				}
			}
			return;
		}

		ImGui::SetCursorScreenPos(ImVec2(right_x, card_a.y + 8.f));
		ImGui::PushID(provider.id.c_str());
		ImGui::PushItemWidth(right_w);

		const std::string preview = current_model ? current_model->name : std::string("(no model)");
		const std::string combo_id = std::string("##model_") + provider.id;
		if (ImGui::BeginCombo(combo_id.c_str(), preview.c_str())) {
			const auto models = collect_models_sorted(provider.id);
			for (const auto* m : models) {
				const bool is_sel = (current_model_id == m->id);
				char label[160];
				std::snprintf(label, sizeof(label), "%s  -  %s##%s",
					m->name.c_str(),
					format_cost_pair(m->cost.input_per_million, m->cost.output_per_million).c_str(),
					m->id.c_str());
				ImGui::PushID(m->id.c_str());
				if (ImGui::Selectable(label, is_sel)) {
					set_preferred_model_for(provider.id, m->id);
					g_sa_settings.save();
				}
				if (is_sel)
					ImGui::SetItemDefaultFocus();
				ImGui::PopID();
			}
			ImGui::EndCombo();
		}
		ImGui::PopItemWidth();

		const float info_y = card_a.y + 40.f;
		const float info_fs = card_fs * 0.86f;
		double total_cost = 0.0;
		if (current_model) {
			total_cost = current_model->cost.input_per_million + current_model->cost.output_per_million;
			std::string cost_label = "cost: " + format_cost_pair(
				current_model->cost.input_per_million,
				current_model->cost.output_per_million);
			std::string ctx_label = "ctx: " + format_context(current_model->limit.context);
			dl->AddText(aida::ui::fonts::caption(), info_fs,
				ImVec2(right_x, info_y),
				aida::ui::with_alpha(th.text_secondary, alpha), cost_label.c_str());
			dl->AddText(aida::ui::fonts::caption(), info_fs,
				ImVec2(right_x, info_y + info_fs + 4.f),
				aida::ui::with_alpha(th.text_secondary, alpha), ctx_label.c_str());

			const float bar_y = info_y + (info_fs + 4.f) * 2.f + 4.f;
			const float bar_w = right_w * 0.6f;
			const float bar_h = 4.f;
			float ratio = static_cast<float>(total_cost / max_total_cost);
			if (ratio < 0.f) ratio = 0.f;
			if (ratio > 1.f) ratio = 1.f;
			ImVec2 bg_a(right_x, bar_y);
			ImVec2 bg_b(right_x + bar_w, bar_y + bar_h);
			dl->AddRectFilled(bg_a, bg_b,
				aida::ui::with_alpha(th.panel_header, alpha), bar_h * 0.5f);
			{
				ImU32 prog_flat = aida::ui::mix(th.accent_grad_top, th.accent_grad_bot, 0.5f);
				dl->AddRectFilled(
					bg_a, ImVec2(right_x + bar_w * ratio, bar_y + bar_h),
					prog_flat, bar_h * 0.5f);
			}
		}

		ImGui::SetCursorScreenPos(ImVec2(right_x, card_b.y - 32.f));

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

		const std::string test_label = test_running ? std::string("Testing") : std::string("Test");
		if (aida::ui::button(test_label.c_str(),
				aida::ui::button_kind_t::ghost,
				aida::ui::size_t_::sm,
				ImVec2(80.f, 24.f),
				false, nullptr, test_running)) {
			if (!test_running && !current_model_id.empty()) {
				run_test_connection(provider.id, current_model_id);
			}
		}
		ImGui::SameLine(0.f, 6.f);

		const bool is_default = (g_sa_settings.default_provider_id == provider.id);
		if (aida::ui::button(is_default ? "Default *" : "Set default",
				is_default ? aida::ui::button_kind_t::primary : aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm,
				ImVec2(112.f, 24.f))) {
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
		ImGui::SameLine(0.f, 6.f);
		if (aida::ui::button(selected ? "Hide" : "Details",
				aida::ui::button_kind_t::ghost,
				aida::ui::size_t_::sm,
				ImVec2(80.f, 24.f))) {
			if (selected) {
				st.selected_detail_provider_id.clear();
				st.detail_buffers_loaded = false;
			} else {
				st.selected_detail_provider_id = provider.id;
				load_detail_buffers(provider.id);
			}
		}

		if (has_result) {
			ImU32 res_col = test_res.success
				? aida::ui::with_alpha(th.success, alpha)
				: aida::ui::with_alpha(th.error, alpha);
			char buf[256];
			if (test_res.success) {
				std::snprintf(buf, sizeof(buf), "OK %dms - %s",
					test_res.latency_ms, test_res.message.c_str());
			} else {
				std::snprintf(buf, sizeof(buf), "FAIL: %s", truncate_text(test_res.message, 90).c_str());
			}
			dl->AddText(aida::ui::fonts::caption(), card_fs * 0.84f,
				ImVec2(right_x, card_b.y - 52.f), res_col, buf);
		}

		if (clicked) {
			if (selected) {
				st.selected_detail_provider_id.clear();
				st.detail_buffers_loaded = false;
			} else {
				st.selected_detail_provider_id = provider.id;
				load_detail_buffers(provider.id);
			}
		}

		ImGui::PopID();
	}

	void render_detail_pane(float ox, float oy, float pane_w, float pane_h, float alpha)
	{
		const auto& th = aida::ui::resolved();
		auto& st = g_state();
		auto* dl = ImGui::GetWindowDrawList();
		if (st.selected_detail_provider_id.empty())
			return;

		ImVec2 a(ox, oy);
		ImVec2 b(ox + pane_w, oy + pane_h);

		aida::ui::blur::layer_request_t br;
		br.pos = a;
		br.size = ImVec2(pane_w, pane_h);
		br.radius = 12.f;
		br.strength = 0.7f;
		br.alpha = alpha;
		aida::ui::blur::schedule(br);

		aida::ui::blur::render_drop_shadow(dl, a, b, 12.f, 4, 0.30f * alpha,
			ImVec2(0.f, 4.f));
		aida::ui::blur::render_glass_fill(dl, a, b, 12.f, alpha);
		aida::ui::blur::render_glass_border(dl, a, b, 12.f, alpha, 1.f);

		const auto* prov = aida::provider::catalog::get_provider(st.selected_detail_provider_id);
		if (!prov) {
			st.selected_detail_provider_id.clear();
			return;
		}

		ImGui::PushID("provider_detail_pane");
		const float detail_fs = aida::ui::components::detail::ui_fs();
		const std::string title = std::string("Details: ") + (prov->name.empty() ? prov->id : prov->name);
		dl->AddText(aida::ui::fonts::h2(), detail_fs * 1.2f, ImVec2(a.x + 14.f, a.y + 10.f),
			aida::ui::with_alpha(th.text_primary, alpha), title.c_str());

		ImGui::SetCursorScreenPos(ImVec2(a.x + 14.f, a.y + 40.f));
		dl->AddText(aida::ui::fonts::body_em(), detail_fs * 0.96f,
			ImVec2(a.x + 14.f, a.y + 40.f),
			aida::ui::with_alpha(th.text_secondary, alpha), "Base URL");

		ImGui::SetCursorScreenPos(ImVec2(a.x + 14.f, a.y + 58.f));
		aida::ui::input_text("##detail_base_url",
			st.detail_base_url_buf, sizeof(st.detail_base_url_buf),
			"https://api.host", false, ImVec2(pane_w - 28.f, 32.f));

		ImGui::SetCursorScreenPos(ImVec2(a.x + 14.f, a.y + 100.f));
		dl->AddText(aida::ui::fonts::body_em(), detail_fs * 0.96f,
			ImVec2(a.x + 14.f, a.y + 100.f),
			aida::ui::with_alpha(th.text_secondary, alpha), "Extra headers JSON");

		ImGui::SetCursorScreenPos(ImVec2(a.x + 14.f, a.y + 118.f));
		ImGui::InputTextMultiline("##detail_headers", st.detail_headers_buf, sizeof(st.detail_headers_buf),
			ImVec2(pane_w - 28.f, 100.f));

		ImGui::SetCursorScreenPos(ImVec2(a.x + 14.f, a.y + 230.f));
		if (aida::ui::button("Save", aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(110.f, 28.f))) {
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
		ImGui::SameLine(0.f, 8.f);
		if (aida::ui::button("Reset", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md, ImVec2(110.f, 28.f))) {
			g_sa_settings.provider_base_url_overrides.erase(st.selected_detail_provider_id);
			g_sa_settings.provider_headers_overrides.erase(st.selected_detail_provider_id);
			g_sa_settings.save();
			load_detail_buffers(st.selected_detail_provider_id);
			toast_notification::push("Provider overrides cleared",
				toast_notification::toast_type_t::info, 3.0f);
		}
		ImGui::SameLine(0.f, 12.f);
		aida::ui::toggle_switch("Show raw model.json", &st.show_raw_model_json,
			aida::ui::size_t_::sm);

		if (st.show_raw_model_json) {
			const std::string mid = preferred_model_for(st.selected_detail_provider_id);
			const std::string raw = raw_model_json_for(st.selected_detail_provider_id, mid);
			ImGui::SetCursorScreenPos(ImVec2(a.x + 14.f, a.y + 268.f));
			ImGui::PushTextWrapPos(a.x + pane_w - 14.f);
			ImGui::PushStyleColor(ImGuiCol_Text,
				ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)));
			ImGui::TextUnformatted(raw.c_str());
			ImGui::PopStyleColor();
			ImGui::PopTextWrapPos();
		}

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
		work_queue::post([]() {
			auto& s = g_state();
			if (s.shutdown_flag.load())
				return;
			aida::provider::catalog::load_cached_or_fetch(86400);
		});
	}
}

void shutdown()
{
	auto& st = g_state();
	st.shutdown_flag.store(true);
	std::lock_guard<std::mutex> lk(st.mtx);
	st.initialized = false;
	for (auto& kv : st.in_flight_tests) {
		if (kv.second)
			kv.second->store(false);
	}
	st.in_flight_tests.clear();
	st.pending_results.clear();
	st.refresh.in_flight.store(false);
	st.refresh.completed.store(false);
	st.refresh.success.store(false);
	st.refresh.message.clear();
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

	const auto& th = aida::ui::resolved();
	const float dt = aida::ui::clock::dt();
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

	const float toolbar_h = 36.f;
	const float pad = 12.f;

	const float search_w = (root_w - pad * 3.f) * 0.62f;
	ImGui::SetCursorScreenPos(ImVec2(root_x + pad, root_y + 4.f));
	char search_local[128];
	std::memcpy(search_local, st.search_buf, sizeof(search_local));
	if (aida::ui::input_text("##provider_filter", search_local, sizeof(search_local),
			"Filter providers / models", false, ImVec2(search_w, 30.f))) {
		std::lock_guard<std::mutex> lk(st.mtx);
		std::memcpy(st.search_buf, search_local, sizeof(st.search_buf));
	}

	const float btn_w = 220.f;
	const float btn_x = root_x + root_w - pad - btn_w;
	ImGui::SetCursorScreenPos(ImVec2(btn_x, root_y + 4.f));
	const bool refreshing = st.refresh.in_flight.load();
	if (aida::ui::button(refreshing ? "Refreshing" : "Refresh from models.dev",
			aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::md,
			ImVec2(btn_w, 30.f),
			false, nullptr, refreshing)) {
		if (!refreshing)
			start_refresh_thread();
	}

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
	const float card_h = 128.f;
	const float gap = 12.f;

	if (filtered.empty()) {
		ImVec2 region_pos = ImGui::GetCursorScreenPos();
		ImVec2 region_size(card_w, body_h - 16.f);
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::dots;
		cfg.title = providers.empty() ? "Catalog empty" : "No matches";
		cfg.body = providers.empty()
			? "Click Refresh to fetch providers from models.dev."
			: "No providers match your filter.";
		cfg.max_width = card_w * 0.7f;
		aida::ui::empty_state::render(region_pos, region_size, cfg);
	}

	const double max_cost = max_total_cost_in_catalog();

	for (const auto* prov : filtered) {
		ImGui::Dummy(ImVec2(pad, 0.f));
		ImGui::SameLine();
		const ImVec2 sp = ImGui::GetCursorScreenPos();
		render_provider_card(sp.x, sp.y, card_w, card_h, *prov, alpha, max_cost, dt);
		ImGui::SetCursorScreenPos(sp);
		ImGui::Dummy(ImVec2(card_w, card_h + gap));
	}

	ImGui::EndChild();

	if (detail_open) {
		const float detail_x = root_x + list_w + pad * 0.5f;
		render_detail_pane(detail_x, body_y, detail_w, body_h, alpha);
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
		float ar = globals::ui::accent.x;
		float ag = globals::ui::accent.y;
		float ab = globals::ui::accent.z;
		ui_anim::render_inline_callout(dl, root_x + pad, callout_y,
			root_w - pad * 2.f, callout_h,
			"Catalog cached - click Refresh for latest",
			ui_anim::callout_kind_t::info, ar, ag, ab, alpha);
	}

	ImGui::EndChild();
	(void)th;
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
