#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "provider_catalog.hpp"
#include "../infra/work_queue.hpp"

#include <windows.h>
#include <shlobj.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <httplib.h>
#include <nlohmann/json.hpp>

namespace aida {
namespace provider {
namespace catalog {

namespace {

	std::mutex s_mtx;
	std::string s_last_error;
	std::vector<provider_info_t> s_providers;
	std::vector<model_info_t> s_models;
	bool s_loaded = false;
	std::atomic<bool> s_init_started{false};
	std::atomic<bool> s_refresh_inflight{false};

	void set_error(const std::string& msg)
	{
		s_last_error = msg;
	}

	std::filesystem::path cache_path()
	{
		wchar_t* appdata = nullptr;
		if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
			std::filesystem::path p = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"models.json";
			CoTaskMemFree(appdata);
			std::error_code ec;
			std::filesystem::create_directories(p.parent_path(), ec);
			return p;
		}
		return std::filesystem::current_path() / "models.json";
	}

	std::string lower(std::string s)
	{
		std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		return s;
	}

	model_info_t::status_t parse_status(const std::string& s)
	{
		if (s == "alpha") return model_info_t::status_t::alpha;
		if (s == "beta") return model_info_t::status_t::beta;
		if (s == "deprecated") return model_info_t::status_t::deprecated;
		return model_info_t::status_t::active;
	}

	void parse_models_dev_json(const nlohmann::json& root)
	{
		s_providers.clear();
		s_models.clear();

		if (!root.is_object())
			return;

		s_providers.reserve(root.size());

		for (auto it = root.begin(); it != root.end(); ++it) {
			const std::string& provider_id = it.key();
			const nlohmann::json& pj = it.value();
			if (!pj.is_object())
				continue;

			provider_info_t pi;
			pi.id = provider_id;
			if (pj.contains("name") && pj["name"].is_string())
				pi.name = pj["name"].get<std::string>();
			else
				pi.name = provider_id;
			if (pj.contains("npm") && pj["npm"].is_string())
				pi.npm = pj["npm"].get<std::string>();
			if (pj.contains("api") && pj["api"].is_string())
				pi.base_url = pj["api"].get<std::string>();
			if (pj.contains("env") && pj["env"].is_array() && !pj["env"].empty() && pj["env"][0].is_string())
				pi.env_var = pj["env"][0].get<std::string>();

			if (pj.contains("models") && pj["models"].is_object()) {
				for (auto mit = pj["models"].begin(); mit != pj["models"].end(); ++mit) {
					const std::string& model_id = mit.key();
					const nlohmann::json& mj = mit.value();
					if (!mj.is_object())
						continue;

					model_info_t mi;
					mi.id = model_id;
					mi.provider_id = provider_id;
					if (mj.contains("name") && mj["name"].is_string())
						mi.name = mj["name"].get<std::string>();
					else
						mi.name = model_id;
					if (mj.contains("family") && mj["family"].is_string())
						mi.family = mj["family"].get<std::string>();
					if (mj.contains("release_date") && mj["release_date"].is_string())
						mi.release_date = mj["release_date"].get<std::string>();
					if (mj.contains("status") && mj["status"].is_string())
						mi.status = parse_status(mj["status"].get<std::string>());

					if (mj.contains("temperature") && mj["temperature"].is_boolean())
						mi.capabilities.temperature = mj["temperature"].get<bool>();
					if (mj.contains("reasoning") && mj["reasoning"].is_boolean())
						mi.capabilities.reasoning = mj["reasoning"].get<bool>();
					if (mj.contains("attachment") && mj["attachment"].is_boolean())
						mi.capabilities.attachment = mj["attachment"].get<bool>();
					if (mj.contains("tool_call") && mj["tool_call"].is_boolean())
						mi.capabilities.tool_call = mj["tool_call"].get<bool>();
					if (mj.contains("interleaved")) {
						const auto& iv = mj["interleaved"];
						if (iv.is_boolean()) mi.capabilities.interleaved = iv.get<bool>();
						else if (iv.is_object()) mi.capabilities.interleaved = true;
					}
					if (mj.contains("modalities") && mj["modalities"].is_object()) {
						const auto& mods = mj["modalities"];
						if (mods.contains("input") && mods["input"].is_array()) {
							for (const auto& x : mods["input"]) {
								if (x.is_string())
									mi.capabilities.input_modalities.push_back(x.get<std::string>());
							}
						}
						if (mods.contains("output") && mods["output"].is_array()) {
							for (const auto& x : mods["output"]) {
								if (x.is_string())
									mi.capabilities.output_modalities.push_back(x.get<std::string>());
							}
						}
					}

					if (mj.contains("cost") && mj["cost"].is_object()) {
						const auto& cj = mj["cost"];
						if (cj.contains("input") && cj["input"].is_number())
							mi.cost.input_per_million = cj["input"].get<double>();
						if (cj.contains("output") && cj["output"].is_number())
							mi.cost.output_per_million = cj["output"].get<double>();
						if (cj.contains("cache_read") && cj["cache_read"].is_number())
							mi.cost.cache_read_per_million = cj["cache_read"].get<double>();
						if (cj.contains("cache_write") && cj["cache_write"].is_number())
							mi.cost.cache_write_per_million = cj["cache_write"].get<double>();
						if (cj.contains("context_over_200k") && cj["context_over_200k"].is_object()) {
							const auto& oj = cj["context_over_200k"];
							if (oj.contains("input") && oj["input"].is_number())
								mi.cost.over_200k_input_per_million = oj["input"].get<double>();
							if (oj.contains("output") && oj["output"].is_number())
								mi.cost.over_200k_output_per_million = oj["output"].get<double>();
							if (oj.contains("cache_read") && oj["cache_read"].is_number())
								mi.cost.over_200k_cache_read_per_million = oj["cache_read"].get<double>();
							if (oj.contains("cache_write") && oj["cache_write"].is_number())
								mi.cost.over_200k_cache_write_per_million = oj["cache_write"].get<double>();
						}
					}

					if (mj.contains("limit") && mj["limit"].is_object()) {
						const auto& lj = mj["limit"];
						if (lj.contains("context") && lj["context"].is_number_integer())
							mi.limit.context = lj["context"].get<int64_t>();
						if (lj.contains("input") && lj["input"].is_number_integer())
							mi.limit.input = lj["input"].get<int64_t>();
						if (lj.contains("output") && lj["output"].is_number_integer())
							mi.limit.output = lj["output"].get<int64_t>();
					}

					mi.api.id = model_id;
					mi.api.url = pi.base_url;
					mi.api.npm = pi.npm;
					if (mj.contains("provider") && mj["provider"].is_object()) {
						const auto& spj = mj["provider"];
						if (spj.contains("npm") && spj["npm"].is_string())
							mi.api.npm = spj["npm"].get<std::string>();
						if (spj.contains("api") && spj["api"].is_string())
							mi.api.url = spj["api"].get<std::string>();
					}

					if (mj.contains("options") && mj["options"].is_object())
						mi.options = mj["options"];
					if (mj.contains("headers") && mj["headers"].is_object())
						mi.headers = mj["headers"];
					if (mj.contains("variants") && (mj["variants"].is_object() || mj["variants"].is_array()))
						mi.variants = mj["variants"];

					pi.model_ids.push_back(model_id);
					s_models.push_back(std::move(mi));
				}
			}

			std::sort(pi.model_ids.begin(), pi.model_ids.end());
			s_providers.push_back(std::move(pi));
		}

		std::sort(s_providers.begin(), s_providers.end(),
			[](const provider_info_t& a, const provider_info_t& b) { return a.id < b.id; });
	}

	bool parse_and_replace(const std::string& body)
	{
		auto parsed = nlohmann::json::parse(body, nullptr, false);
		if (parsed.is_discarded() || !parsed.is_object()) {
			set_error("models.dev returned malformed JSON");
			return false;
		}
		parse_models_dev_json(parsed);
		s_loaded = true;
		s_last_error.clear();
		return true;
	}

	bool write_cache_file(const std::string& body)
	{
		const auto path = cache_path();
		std::error_code ec;
		std::filesystem::create_directories(path.parent_path(), ec);
		std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
		if (!ofs.is_open())
			return false;
		ofs.write(body.data(), static_cast<std::streamsize>(body.size()));
		return ofs.good();
	}

	bool read_cache_file(std::string& out)
	{
		const auto path = cache_path();
		std::ifstream ifs(path, std::ios::binary);
		if (!ifs.is_open())
			return false;
		std::ostringstream ss;
		ss << ifs.rdbuf();
		out = ss.str();
		return !out.empty();
	}

	int64_t cache_age_seconds()
	{
		const auto path = cache_path();
		std::error_code ec;
		const auto ftime = std::filesystem::last_write_time(path, ec);
		if (ec)
			return -1;
		const auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
			ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
		const auto now = std::chrono::system_clock::now();
		const auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - sctp).count();
		return diff;
	}

	const model_info_t* find_model_locked(const std::string& provider_id, const std::string& model_id)
	{
		for (const auto& m : s_models) {
			if (m.provider_id == provider_id && m.id == model_id)
				return &m;
		}
		return nullptr;
	}

	int64_t context_cost_score(const model_info_t& m)
	{
		const double cost_sum = m.cost.input_per_million + m.cost.output_per_million;
		const double ctx = m.limit.context > 0 ? static_cast<double>(m.limit.context) : 1.0;
		return static_cast<int64_t>(ctx * (cost_sum + 1.0));
	}

}

bool fetch_and_cache(int timeout_ms)
{
	std::lock_guard<std::mutex> lk(s_mtx);

	httplib::Client client("https://models.dev");
	client.set_address_family(AF_INET);
	const int connect_secs = (timeout_ms / 1000) > 0 ? (timeout_ms / 1000) : 5;
	const int read_secs = (timeout_ms / 1000) > 0 ? (timeout_ms / 1000) : 10;
	client.set_connection_timeout(connect_secs);
	client.set_read_timeout(read_secs);
	client.set_write_timeout(connect_secs);
	client.set_keep_alive(false);
	client.set_decompress(true);
	client.set_follow_location(true);
	client.enable_server_certificate_verification(true);

	httplib::Headers headers = {
		{ "User-Agent", "AiDAStandalone/1.0" },
		{ "Accept", "application/json" },
	};

	auto res = client.Get("/api.json", headers);
	if (!res) {
		const auto err = res.error();
		std::ostringstream oss;
		oss << "models.dev unreachable: " << httplib::to_string(err);
		set_error(oss.str());
		return false;
	}
	if (res->status < 200 || res->status >= 300) {
		std::ostringstream oss;
		oss << "models.dev returned HTTP " << res->status;
		set_error(oss.str());
		return false;
	}
	if (res->body.empty()) {
		set_error("models.dev returned empty body");
		return false;
	}

	if (!parse_and_replace(res->body))
		return false;

	if (!write_cache_file(res->body)) {
		set_error("failed to write models cache file");
		return true;
	}
	return true;
}

bool load_cached_or_fetch(int max_age_seconds)
{
	{
		std::lock_guard<std::mutex> lk(s_mtx);
		const auto path = cache_path();
		std::error_code ec;
		if (std::filesystem::exists(path, ec)) {
			const int64_t age = cache_age_seconds();
			if (age >= 0 && age <= max_age_seconds) {
				std::string body;
				if (read_cache_file(body) && parse_and_replace(body))
					return true;
			}
		}
	}

	return fetch_and_cache();
}

void initialize_async(int max_age_seconds)
{
	bool expected = false;
	if (!s_init_started.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
		return;

	{
		std::lock_guard<std::mutex> lk(s_mtx);
		const auto path = cache_path();
		std::error_code ec;
		if (std::filesystem::exists(path, ec)) {
			std::string body;
			if (read_cache_file(body))
				(void)parse_and_replace(body);
		}
	}

	bool needs_refresh = true;
	{
		std::lock_guard<std::mutex> lk(s_mtx);
		const auto path = cache_path();
		std::error_code ec;
		if (s_loaded && std::filesystem::exists(path, ec)) {
			const int64_t age = cache_age_seconds();
			if (age >= 0 && age <= max_age_seconds)
				needs_refresh = false;
		}
	}

	if (!needs_refresh)
		return;

	bool refresh_expected = false;
	if (!s_refresh_inflight.compare_exchange_strong(refresh_expected, true, std::memory_order_acq_rel))
		return;

	work_queue::post([]() {
		(void)fetch_and_cache();
		s_refresh_inflight.store(false, std::memory_order_release);
	});
}

const std::vector<provider_info_t>& list_providers()
{
	initialize_async();
	std::lock_guard<std::mutex> lk(s_mtx);
	return s_providers;
}

const provider_info_t* get_provider(const std::string& provider_id)
{
	initialize_async();
	std::lock_guard<std::mutex> lk(s_mtx);
	for (const auto& p : s_providers) {
		if (p.id == provider_id)
			return &p;
	}
	return nullptr;
}

const model_info_t* get_model(const std::string& provider_id, const std::string& model_id)
{
	initialize_async();
	std::lock_guard<std::mutex> lk(s_mtx);
	return find_model_locked(provider_id, model_id);
}

std::vector<const model_info_t*> closest(const std::string& provider_id, const std::vector<std::string>& query_terms)
{
	initialize_async();
	std::lock_guard<std::mutex> lk(s_mtx);
	std::vector<const model_info_t*> result;
	if (query_terms.empty())
		return result;

	for (const auto& term : query_terms) {
		const std::string lt = lower(term);
		for (const auto& m : s_models) {
			if (m.provider_id != provider_id)
				continue;
			const std::string lid = lower(m.id);
			const std::string lname = lower(m.name);
			const std::string lfam = lower(m.family);
			if (lid.find(lt) != std::string::npos ||
				lname.find(lt) != std::string::npos ||
				(!lfam.empty() && lfam.find(lt) != std::string::npos)) {
				bool already = false;
				for (const auto* p : result) {
					if (p == &m) { already = true; break; }
				}
				if (!already)
					result.push_back(&m);
			}
		}
	}
	return result;
}

const model_info_t* get_small_model(const std::string& provider_id)
{
	initialize_async();
	std::lock_guard<std::mutex> lk(s_mtx);

	std::vector<std::string> priority = {
		"claude-haiku-4-5",
		"claude-haiku-4.5",
		"3-5-haiku",
		"3.5-haiku",
		"gemini-3-flash",
		"gemini-2.5-flash",
		"gpt-5-nano",
	};
	if (provider_id.rfind("opencode", 0) == 0)
		priority = { "gpt-5-nano" };
	if (provider_id.rfind("github-copilot", 0) == 0) {
		std::vector<std::string> head = { "gpt-5-mini", "claude-haiku-4.5" };
		head.insert(head.end(), priority.begin(), priority.end());
		priority = std::move(head);
	}

	const provider_info_t* prov = nullptr;
	for (const auto& p : s_providers) {
		if (p.id == provider_id) { prov = &p; break; }
	}
	if (!prov)
		return nullptr;

	for (const auto& token : priority) {
		if (provider_id == "amazon-bedrock") {
			const std::vector<std::string> cross_region_prefixes = { "global.", "us.", "eu." };
			std::vector<const model_info_t*> candidates;
			for (const auto& m : s_models) {
				if (m.provider_id != provider_id) continue;
				if (m.id.find(token) != std::string::npos)
					candidates.push_back(&m);
			}
			for (const auto* c : candidates) {
				if (c->id.rfind("global.", 0) == 0)
					return c;
			}
			for (const auto* c : candidates) {
				bool prefixed = false;
				for (const auto& pr : cross_region_prefixes) {
					if (c->id.rfind(pr, 0) == 0) { prefixed = true; break; }
				}
				if (!prefixed)
					return c;
			}
		} else {
			for (const auto& m : s_models) {
				if (m.provider_id != provider_id) continue;
				if (m.id.find(token) != std::string::npos)
					return &m;
			}
		}
	}

	const model_info_t* best = nullptr;
	int64_t best_score = 0;
	for (const auto& m : s_models) {
		if (m.provider_id != provider_id) continue;
		const int64_t score = context_cost_score(m);
		if (best == nullptr || score < best_score) {
			best = &m;
			best_score = score;
		}
	}
	return best;
}

const model_info_t* default_model(const std::string& provider_id)
{
	initialize_async();
	std::lock_guard<std::mutex> lk(s_mtx);

	static const std::vector<std::string> priority = {
		"gpt-5",
		"claude-sonnet-4",
		"big-pickle",
		"gemini-3-pro",
	};

	for (const auto& token : priority) {
		for (const auto& m : s_models) {
			if (m.provider_id != provider_id) continue;
			if (m.id.find(token) != std::string::npos)
				return &m;
		}
	}

	const model_info_t* first = nullptr;
	for (const auto& m : s_models) {
		if (m.provider_id != provider_id) continue;
		if (!first || m.id < first->id)
			first = &m;
	}
	return first;
}

const std::string& last_error()
{
	std::lock_guard<std::mutex> lk(s_mtx);
	return s_last_error;
}

}
}
}
