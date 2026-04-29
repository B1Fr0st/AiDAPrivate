#pragma once

#include <map>
#include <string>

#include <nlohmann/json.hpp>

#include "auth_store.hpp"

namespace aida {
namespace provider {
namespace transforms {

	struct request_context_t {
		std::string session_id;
		bool has_parent_session = false;
		bool is_compaction_continued = false;
		const nlohmann::json* request_body = nullptr;
	};

	bool transform_request(const std::string& provider_id, const std::string& model_id, nlohmann::json& request);
	bool transform_response(const std::string& provider_id, const std::string& model_id, nlohmann::json& response);
	std::map<std::string, std::string> compute_headers(const std::string& provider_id, const std::string& model_id, const aida::auth::auth_info_t& auth);
	std::map<std::string, std::string> compute_headers(const std::string& provider_id, const std::string& model_id, const aida::auth::auth_info_t& auth, const request_context_t& ctx);
	std::string resolve_endpoint(const std::string& provider_id, const std::string& model_id, const aida::auth::auth_info_t& auth);
	bool copilot_uses_responses_api(const std::string& model_id);
	const std::string& last_error();

}
}
}
