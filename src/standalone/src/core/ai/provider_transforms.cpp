#include "provider_transforms.hpp"
#include "provider_catalog.hpp"

#include <algorithm>
#include <cctype>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>

namespace aida {
namespace provider {
namespace transforms {

namespace {

	std::mutex s_mtx;
	std::string s_last_error;

	void set_error(const std::string& msg)
	{
		std::lock_guard<std::mutex> lk(s_mtx);
		s_last_error = msg;
	}

	std::string lower(std::string s)
	{
		std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		return s;
	}

	bool starts_with(const std::string& s, const std::string& prefix)
	{
		return s.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), s.begin());
	}

	bool any_message_has_cache_control(const nlohmann::json& request)
	{
		if (!request.is_object())
			return false;

		auto inspect_array = [](const nlohmann::json& arr) -> bool {
			if (!arr.is_array())
				return false;
			for (const auto& msg : arr) {
				if (!msg.is_object())
					continue;
				if (msg.contains("cache_control"))
					return true;
				if (msg.contains("providerOptions") && msg["providerOptions"].is_object()) {
					const auto& po = msg["providerOptions"];
					for (auto it = po.begin(); it != po.end(); ++it) {
						if (it.value().is_object() && it.value().contains("cacheControl"))
							return true;
					}
				}
				if (msg.contains("content") && msg["content"].is_array()) {
					for (const auto& part : msg["content"]) {
						if (!part.is_object())
							continue;
						if (part.contains("cache_control"))
							return true;
						if (part.contains("providerOptions") && part["providerOptions"].is_object()) {
							const auto& po = part["providerOptions"];
							for (auto it = po.begin(); it != po.end(); ++it) {
								if (it.value().is_object() && it.value().contains("cacheControl"))
									return true;
							}
						}
					}
				}
			}
			return false;
		};

		if (request.contains("messages") && inspect_array(request["messages"]))
			return true;
		if (request.contains("system") && inspect_array(request["system"]))
			return true;
		return false;
	}

	std::string substitute_placeholder(std::string url, const std::string& token, const std::string& value)
	{
		const std::string needle = "{" + token + "}";
		std::string::size_type pos = 0;
		while ((pos = url.find(needle, pos)) != std::string::npos) {
			url.replace(pos, needle.size(), value);
			pos += value.size();
		}
		return url;
	}

	std::string apply_bedrock_region_prefix(const std::string& model_id, const std::string& region_hint)
	{
		static const std::vector<std::string> cross_region_prefixes = {
			"global.", "us.", "eu.", "jp.", "apac.", "au."
		};
		for (const auto& p : cross_region_prefixes) {
			if (starts_with(model_id, p))
				return model_id;
		}
		std::string region = region_hint;
		if (region.empty())
			region = "us-east-1";
		std::string prefix = region;
		auto dash = prefix.find('-');
		if (dash != std::string::npos)
			prefix = prefix.substr(0, dash);

		const std::string lid = lower(model_id);

		if (prefix == "us") {
			if (starts_with(region, "us-gov"))
				return model_id;
			static const std::vector<std::string> needs = {
				"nova-micro", "nova-lite", "nova-pro", "nova-premier", "nova-2",
				"claude", "deepseek"
			};
			for (const auto& n : needs) {
				if (lid.find(n) != std::string::npos)
					return prefix + "." + model_id;
			}
			return model_id;
		}
		if (prefix == "eu") {
			static const std::vector<std::string> rok = {
				"eu-west-1", "eu-west-2", "eu-west-3",
				"eu-north-1", "eu-central-1", "eu-south-1", "eu-south-2"
			};
			bool region_ok = false;
			for (const auto& r : rok) {
				if (region.find(r) != std::string::npos) { region_ok = true; break; }
			}
			if (!region_ok)
				return model_id;
			static const std::vector<std::string> needs = {
				"claude", "nova-lite", "nova-micro", "llama3", "pixtral"
			};
			for (const auto& n : needs) {
				if (lid.find(n) != std::string::npos)
					return prefix + "." + model_id;
			}
			return model_id;
		}
		if (prefix == "ap") {
			const bool is_aus = (region == "ap-southeast-2" || region == "ap-southeast-4");
			const bool is_tokyo = (region == "ap-northeast-1");
			if (is_aus) {
				static const std::vector<std::string> needs = {
					"anthropic.claude-sonnet-4-5", "anthropic.claude-haiku"
				};
				for (const auto& n : needs) {
					if (lid.find(n) != std::string::npos)
						return std::string("au.") + model_id;
				}
				return model_id;
			}
			if (is_tokyo) {
				static const std::vector<std::string> needs = { "claude", "nova-lite", "nova-micro", "nova-pro" };
				for (const auto& n : needs) {
					if (lid.find(n) != std::string::npos)
						return std::string("jp.") + model_id;
				}
				return model_id;
			}
			static const std::vector<std::string> needs = { "claude", "nova-lite", "nova-micro", "nova-pro" };
			for (const auto& n : needs) {
				if (lid.find(n) != std::string::npos)
					return std::string("apac.") + model_id;
			}
			return model_id;
		}
		return model_id;
	}

	std::string read_metadata_string(const aida::auth::auth_info_t& auth, const std::string& key)
	{
		if (!auth.metadata.is_object())
			return {};
		if (!auth.metadata.contains(key))
			return {};
		const auto& v = auth.metadata.at(key);
		if (v.is_string())
			return v.get<std::string>();
		return {};
	}

}

bool copilot_uses_responses_api(const std::string& model_id)
{
	if (starts_with(model_id, "o1") || starts_with(model_id, "o3"))
		return true;
	std::regex re("^gpt-(\\d+)");
	std::smatch m;
	if (std::regex_search(model_id, m, re)) {
		try {
			const int major = std::stoi(m[1].str());
			if (major >= 5 && !starts_with(model_id, "gpt-5-mini"))
				return true;
		} catch (...) {
			return false;
		}
	}
	return false;
}

bool transform_request(const std::string& provider_id, const std::string& model_id, nlohmann::json& request)
{
	if (!request.is_object()) {
		set_error("transform_request: request must be a JSON object");
		return false;
	}

	if (provider_id == "amazon-bedrock" || provider_id == "bedrock") {
		const auto* model = aida::provider::catalog::get_model(provider_id, model_id);
		std::string region;
		if (model && model->options.is_object() && model->options.contains("region")) {
			const auto& r = model->options.at("region");
			if (r.is_string())
				region = r.get<std::string>();
		}
		const std::string mapped = apply_bedrock_region_prefix(model_id, region);
		if (mapped != model_id) {
			request["model"] = mapped;
			request["__bedrock_region_model"] = mapped;
		}
	}

	return true;
}

bool transform_response(const std::string&, const std::string&, nlohmann::json& response)
{
	if (!response.is_object() && !response.is_array()) {
		set_error("transform_response: response must be a JSON object or array");
		return false;
	}
	return true;
}

std::map<std::string, std::string> compute_headers(const std::string& provider_id, const std::string& model_id, const aida::auth::auth_info_t& auth)
{
	std::map<std::string, std::string> headers;

	if (provider_id == "anthropic") {
		headers["anthropic-version"] = "2023-06-01";
		headers["anthropic-beta"] = "interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14,prompt-caching-2024-07-31";
		if (!auth.api_key.empty())
			headers["x-api-key"] = auth.api_key;
		else if (!auth.access.empty())
			headers["authorization"] = std::string("Bearer ") + auth.access;
		return headers;
	}

	if (provider_id == "github-copilot") {
		if (!auth.access.empty())
			headers["authorization"] = std::string("Bearer ") + auth.access;
		headers["copilot-integration-id"] = "vscode-chat";
		headers["editor-version"] = "AiDAStandalone/1.0";
		headers["editor-plugin-version"] = "AiDAStandalone/1.0";
		return headers;
	}

	if (provider_id == "openai" || provider_id == "openai-codex" || provider_id == "openai_native" || provider_id == "openai_codex") {
		if (!auth.api_key.empty())
			headers["authorization"] = std::string("Bearer ") + auth.api_key;
		else if (!auth.access.empty())
			headers["authorization"] = std::string("Bearer ") + auth.access;
		const std::string acct = read_metadata_string(auth, "account_id");
		if (!acct.empty())
			headers["openai-account"] = acct;
		const std::string org = read_metadata_string(auth, "organization");
		if (!org.empty())
			headers["openai-organization"] = org;
		return headers;
	}

	if (provider_id == "google" || provider_id == "google-vertex" || provider_id == "vertex") {
		if (!auth.access.empty())
			headers["authorization"] = std::string("Bearer ") + auth.access;
		else if (!auth.api_key.empty())
			headers["x-goog-api-key"] = auth.api_key;
		return headers;
	}

	if (provider_id == "azure") {
		if (!auth.api_key.empty())
			headers["api-key"] = auth.api_key;
		else if (!auth.access.empty())
			headers["authorization"] = std::string("Bearer ") + auth.access;
		return headers;
	}

	if (provider_id == "amazon-bedrock" || provider_id == "bedrock") {
		if (!auth.access.empty())
			headers["authorization"] = std::string("Bearer ") + auth.access;
		return headers;
	}

	if (provider_id == "openrouter") {
		if (!auth.api_key.empty())
			headers["authorization"] = std::string("Bearer ") + auth.api_key;
		headers["http-referer"] = "https://aida.dev/";
		headers["x-title"] = "AiDA";
		return headers;
	}

	if (provider_id == "mistral") {
		if (!auth.api_key.empty())
			headers["authorization"] = std::string("Bearer ") + auth.api_key;
		return headers;
	}

	if (provider_id == "gitlab") {
		if (!auth.api_key.empty())
			headers["authorization"] = std::string("Bearer ") + auth.api_key;
		return headers;
	}

	if (!auth.api_key.empty())
		headers["authorization"] = std::string("Bearer ") + auth.api_key;
	else if (!auth.access.empty())
		headers["authorization"] = std::string("Bearer ") + auth.access;

	(void)model_id;
	return headers;
}

std::string resolve_endpoint(const std::string& provider_id, const std::string& model_id, const aida::auth::auth_info_t& auth)
{
	const auto* model = aida::provider::catalog::get_model(provider_id, model_id);
	std::string base_url;
	if (model)
		base_url = model->api.url;
	if (base_url.empty()) {
		const auto* prov = aida::provider::catalog::get_provider(provider_id);
		if (prov)
			base_url = prov->base_url;
	}

	if (provider_id == "github-copilot") {
		if (base_url.empty())
			base_url = "https://api.githubcopilot.com";
		while (!base_url.empty() && base_url.back() == '/')
			base_url.pop_back();
		if (copilot_uses_responses_api(model_id))
			return base_url + "/responses";
		return base_url + "/chat/completions";
	}

	if (provider_id == "google-vertex" || provider_id == "vertex") {
		std::string region = read_metadata_string(auth, "region");
		if (region.empty())
			region = "us-central1";
		std::string url = base_url.empty() ? std::string("https://{region}-aiplatform.googleapis.com") : base_url;
		url = substitute_placeholder(url, "region", region);
		std::string project = read_metadata_string(auth, "project_id");
		if (!project.empty())
			url = substitute_placeholder(url, "project", project);
		return url;
	}

	if (provider_id == "amazon-bedrock" || provider_id == "bedrock") {
		std::string region = read_metadata_string(auth, "region");
		if (region.empty())
			region = "us-east-1";
		if (base_url.empty())
			base_url = std::string("https://bedrock-runtime.") + region + ".amazonaws.com";
		else
			base_url = substitute_placeholder(base_url, "region", region);
		return base_url;
	}

	if (provider_id == "azure") {
		std::string resource = read_metadata_string(auth, "resource_name");
		if (resource.empty() && !base_url.empty())
			return base_url;
		if (!resource.empty())
			return std::string("https://") + resource + ".openai.azure.com";
		return base_url;
	}

	if (base_url.empty()) {
		set_error(std::string("resolve_endpoint: no base URL for ") + provider_id + "/" + model_id);
	}
	return base_url;
}

const std::string& last_error()
{
	std::lock_guard<std::mutex> lk(s_mtx);
	return s_last_error;
}

}
}
}
