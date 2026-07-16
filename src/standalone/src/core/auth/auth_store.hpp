#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace auth {

	enum class auth_kind_t : int {
		none = 0,
		oauth = 1,
		api = 2,
		wellknown = 3,
	};

	struct auth_info_t {
		auth_kind_t kind = auth_kind_t::none;
		std::string refresh;
		std::string access;
		std::string account_id;
		std::string enterprise_url;
		std::string email;
		int64_t expires_unix = 0;
		std::string api_key;
		std::string wellknown_key;
		std::string wellknown_token;
		nlohmann::json metadata = nlohmann::json::object();
		std::string custom_client_id;
		std::string custom_redirect_uri;
		std::vector<std::string> custom_scopes;
	};

namespace store {

	bool load();
	bool save();
	bool get(const std::string& provider_id, auth_info_t& out);
	bool set(const std::string& provider_id, const auth_info_t& info);
	bool set_if(const std::string& provider_id, const auth_info_t& info,
		const std::function<bool()>& commit_guard);
	bool remove(const std::string& provider_id);
	bool all(std::vector<std::pair<std::string, auth_info_t>>& out);
	std::string last_error();

}

}
}
