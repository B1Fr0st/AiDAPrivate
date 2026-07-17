#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace provider {

	struct model_capabilities_t {
		bool temperature = true;
		bool reasoning = false;
		bool attachment = false;
		bool tool_call = true;
		bool interleaved = false;
		std::vector<std::string> input_modalities;
		std::vector<std::string> output_modalities;
	};

	struct model_cost_t {
		double input_per_million = 0.0;
		double output_per_million = 0.0;
		double cache_read_per_million = 0.0;
		double cache_write_per_million = 0.0;
		double over_200k_input_per_million = 0.0;
		double over_200k_output_per_million = 0.0;
		double over_200k_cache_read_per_million = 0.0;
		double over_200k_cache_write_per_million = 0.0;
	};

	struct model_limit_t {
		int64_t context = 0;
		int64_t input = 0;
		int64_t output = 0;
	};

	struct model_api_t {
		std::string id;
		std::string url;
		std::string npm;
	};

	struct model_info_t {
		enum class status_t : int {
			active = 0,
			alpha = 1,
			beta = 2,
			deprecated = 3,
		};

		std::string id;
		std::string provider_id;
		std::string name;
		std::string family;
		std::string release_date;
		model_api_t api;
		status_t status = status_t::active;
		model_capabilities_t capabilities;
		model_cost_t cost;
		model_limit_t limit;
		nlohmann::json options = nlohmann::json::object();
		nlohmann::json headers = nlohmann::json::object();
		nlohmann::json variants = nlohmann::json::object();
	};

	struct provider_info_t {
		std::string id;
		std::string name;
		std::string npm;
		std::string env_var;
		std::string base_url;
		std::vector<std::string> model_ids;
	};

	struct model_list_validation_t {
		bool valid = false;
		int model_count = 0;
		std::string error;
	};

namespace catalog {

	bool fetch_and_cache(int timeout_ms = 10000);
	bool load_cached_or_fetch(int max_age_seconds = 3600);
	int64_t cached_age_seconds() noexcept;
	model_list_validation_t validate_provider_model_list_response(
		const std::string& provider_id, const std::string& body);
	bool initialize_async(int max_age_seconds = 86400);
	void cancel_initialize() noexcept;
	const std::vector<provider_info_t>& list_providers();
	const provider_info_t* get_provider(const std::string& provider_id);
	const model_info_t* get_model(const std::string& provider_id, const std::string& model_id);
	std::vector<const model_info_t*> closest(const std::string& provider_id, const std::vector<std::string>& query_terms);
	const model_info_t* get_small_model(const std::string& provider_id);
	const model_info_t* default_model(const std::string& provider_id);
	std::string last_error();

}

}
}
