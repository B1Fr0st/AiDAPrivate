#include "provider_transforms.hpp"
#include "provider_catalog.hpp"

#include <algorithm>
#include <cctype>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace aida {
namespace provider {
namespace transforms {

namespace {

	std::mutex s_mtx;
	std::string s_last_error;

	constexpr const char* k_aida_user_agent_version = "1.0";

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

	std::string windows_release_string()
	{
#if defined(_WIN32)
		typedef LONG (WINAPI* RtlGetVersionFn)(PRTL_OSVERSIONINFOW);
		HMODULE hmod = GetModuleHandleW(L"ntdll.dll");
		if (hmod) {
			auto fn = reinterpret_cast<RtlGetVersionFn>(reinterpret_cast<void*>(GetProcAddress(hmod, "RtlGetVersion")));
			if (fn) {
				RTL_OSVERSIONINFOW vi;
				vi.dwOSVersionInfoSize = sizeof(vi);
				if (fn(&vi) == 0) {
					std::ostringstream os;
					os << vi.dwMajorVersion << "." << vi.dwMinorVersion << "." << vi.dwBuildNumber;
					return os.str();
				}
			}
		}
		return std::string("10.0.0");
#else
		return std::string("0.0.0");
#endif
	}

	std::string build_opencode_user_agent()
	{
		std::ostringstream os;
		os << "opencode/" << k_aida_user_agent_version
		   << " (windows " << windows_release_string() << "; x64)";
		return os.str();
	}

	bool is_anthropic_or_bedrock(const std::string& provider_id)
	{
		if (provider_id == "anthropic")
			return true;
		const std::string lid = lower(provider_id);
		if (lid.find("bedrock") != std::string::npos)
			return true;
		return false;
	}

	bool is_claude_model(const std::string& model_id)
	{
		const std::string lid = lower(model_id);
		return lid.find("claude") != std::string::npos;
	}

	bool message_has_image_part(const nlohmann::json& msg)
	{
		if (!msg.is_object())
			return false;
		if (!msg.contains("content"))
			return false;
		const auto& content = msg["content"];
		if (!content.is_array())
			return false;
		for (const auto& part : content) {
			if (!part.is_object())
				continue;
			const std::string type = part.value("type", std::string());
			if (type == "image" || type == "image_url" || type == "input_image")
				return true;
			if (type == "tool_result" && part.contains("content") && part["content"].is_array()) {
				for (const auto& nested : part["content"]) {
					if (!nested.is_object())
						continue;
					const std::string nt = nested.value("type", std::string());
					if (nt == "image" || nt == "image_url" || nt == "input_image")
						return true;
				}
			}
		}
		return false;
	}

	bool request_has_image_content(const nlohmann::json& request)
	{
		if (!request.is_object())
			return false;
		if (!request.contains("messages") || !request["messages"].is_array())
			return false;
		for (const auto& msg : request["messages"]) {
			if (message_has_image_part(msg))
				return true;
		}
		return false;
	}

	bool is_empty_text_or_reasoning_part(const nlohmann::json& part)
	{
		if (!part.is_object())
			return false;
		const std::string type = part.value("type", std::string());
		if (type != "text" && type != "reasoning")
			return false;
		const std::string text = part.value("text", std::string());
		return text.empty();
	}

	void filter_empty_messages_anthropic(nlohmann::json& request)
	{
		if (!request.is_object())
			return;
		if (!request.contains("messages") || !request["messages"].is_array())
			return;

		nlohmann::json filtered = nlohmann::json::array();
		for (const auto& msg : request["messages"]) {
			if (!msg.is_object())
				continue;
			if (!msg.contains("content")) {
				filtered.push_back(msg);
				continue;
			}
			const auto& content = msg["content"];
			if (content.is_string()) {
				if (content.get<std::string>().empty())
					continue;
				filtered.push_back(msg);
				continue;
			}
			if (!content.is_array()) {
				filtered.push_back(msg);
				continue;
			}
			nlohmann::json kept_parts = nlohmann::json::array();
			for (const auto& part : content) {
				if (is_empty_text_or_reasoning_part(part))
					continue;
				kept_parts.push_back(part);
			}
			if (kept_parts.empty())
				continue;
			nlohmann::json new_msg = msg;
			new_msg["content"] = kept_parts;
			filtered.push_back(std::move(new_msg));
		}
		request["messages"] = std::move(filtered);
	}

	std::string scrub_claude_tool_id(const std::string& id)
	{
		static const std::regex re("[^a-zA-Z0-9_-]");
		return std::regex_replace(id, re, std::string("_"));
	}

	void scrub_claude_tool_ids(nlohmann::json& request)
	{
		if (!request.is_object())
			return;
		if (!request.contains("messages") || !request["messages"].is_array())
			return;
		for (auto& msg : request["messages"]) {
			if (!msg.is_object())
				continue;
			if (!msg.contains("content") || !msg["content"].is_array())
				continue;
			for (auto& part : msg["content"]) {
				if (!part.is_object())
					continue;
				const std::string type = part.value("type", std::string());
				if (type == "tool_use" || type == "tool-call") {
					if (part.contains("id") && part["id"].is_string()) {
						const std::string id = part["id"].get<std::string>();
						part["id"] = scrub_claude_tool_id(id);
					}
					if (part.contains("toolCallId") && part["toolCallId"].is_string()) {
						const std::string id = part["toolCallId"].get<std::string>();
						part["toolCallId"] = scrub_claude_tool_id(id);
					}
				} else if (type == "tool_result" || type == "tool-result") {
					if (part.contains("tool_use_id") && part["tool_use_id"].is_string()) {
						const std::string id = part["tool_use_id"].get<std::string>();
						part["tool_use_id"] = scrub_claude_tool_id(id);
					}
					if (part.contains("toolCallId") && part["toolCallId"].is_string()) {
						const std::string id = part["toolCallId"].get<std::string>();
						part["toolCallId"] = scrub_claude_tool_id(id);
					}
				}
			}
		}
	}

	void apply_cache_control_to_message(nlohmann::json& msg)
	{
		if (!msg.is_object())
			return;
		nlohmann::json cc = { {"type", "ephemeral"} };
		if (!msg.contains("content")) {
			msg["cache_control"] = cc;
			return;
		}
		auto& content = msg["content"];
		if (content.is_string()) {
			msg["cache_control"] = cc;
			return;
		}
		if (!content.is_array() || content.empty()) {
			msg["cache_control"] = cc;
			return;
		}
		auto& last = content.at(content.size() - 1);
		if (!last.is_object()) {
			msg["cache_control"] = cc;
			return;
		}
		const std::string type = last.value("type", std::string());
		if (type == "tool-approval-request" || type == "tool-approval-response") {
			msg["cache_control"] = cc;
			return;
		}
		last["cache_control"] = cc;
	}

	void inject_anthropic_cache_control(nlohmann::json& request)
	{
		if (!request.is_object())
			return;

		std::vector<nlohmann::json*> system_targets;
		std::vector<nlohmann::json*> final_targets;

		if (request.contains("system") && request["system"].is_array()) {
			auto& sys = request["system"];
			const std::size_t cap = (std::min)(static_cast<std::size_t>(2), sys.size());
			for (std::size_t i = 0; i < cap; ++i) {
				system_targets.push_back(&sys.at(i));
			}
		}

		if (request.contains("messages") && request["messages"].is_array()) {
			auto& msgs = request["messages"];

			if (system_targets.size() < 2) {
				for (std::size_t i = 0; i < msgs.size() && system_targets.size() < 2; ++i) {
					if (!msgs.at(i).is_object())
						continue;
					const std::string role = msgs.at(i).value("role", std::string());
					if (role != "system")
						continue;
					system_targets.push_back(&msgs.at(i));
				}
			}

			std::vector<std::size_t> non_system_indices;
			non_system_indices.reserve(msgs.size());
			for (std::size_t i = 0; i < msgs.size(); ++i) {
				if (!msgs.at(i).is_object())
					continue;
				const std::string role = msgs.at(i).value("role", std::string());
				if (role == "system")
					continue;
				non_system_indices.push_back(i);
			}
			const std::size_t take = (std::min)(static_cast<std::size_t>(2), non_system_indices.size());
			if (take > 0) {
				const std::size_t start = non_system_indices.size() - take;
				for (std::size_t k = start; k < non_system_indices.size(); ++k) {
					final_targets.push_back(&msgs.at(non_system_indices.at(k)));
				}
			}
		}

		std::vector<nlohmann::json*> unique_targets;
		unique_targets.reserve(system_targets.size() + final_targets.size());
		auto push_unique = [&unique_targets](nlohmann::json* p) {
			for (auto* q : unique_targets) {
				if (q == p)
					return;
			}
			unique_targets.push_back(p);
		};
		for (auto* p : system_targets)
			push_unique(p);
		for (auto* p : final_targets)
			push_unique(p);

		for (auto* p : unique_targets) {
			apply_cache_control_to_message(*p);
		}
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

	if (is_anthropic_or_bedrock(provider_id)) {
		filter_empty_messages_anthropic(request);
		if (!any_message_has_cache_control(request))
			inject_anthropic_cache_control(request);
	}

	if (provider_id == "anthropic" && is_claude_model(model_id)) {
		scrub_claude_tool_ids(request);
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

std::map<std::string, std::string> compute_headers(const std::string& provider_id, const std::string& model_id, const aida::auth::auth_info_t& auth, const request_context_t& ctx)
{
	std::map<std::string, std::string> headers;

	if (provider_id == "anthropic") {
		headers["anthropic-version"] = "2023-06-01";
		std::string beta = "interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14,prompt-caching-2024-07-31";
		const bool is_oauth = (auth.kind == aida::auth::auth_kind_t::oauth) && !auth.access.empty();
		if (is_oauth)
			beta += ",oauth-2025-04-20";
		headers["anthropic-beta"] = beta;
		if (!auth.api_key.empty())
			headers["x-api-key"] = auth.api_key;
		else if (!auth.access.empty())
			headers["authorization"] = std::string("Bearer ") + auth.access;
		return headers;
	}

	if (provider_id == "github-copilot") {
		if (!auth.access.empty())
			headers["Authorization"] = std::string("Bearer ") + auth.access;
		headers["copilot-integration-id"] = "vscode-chat";
		headers["Editor-Version"] = "vscode/1.95.0";
		headers["Editor-Plugin-Version"] = "copilot-chat/0.20.0";
		headers["editor-version"] = "vscode/1.95.0";
		headers["editor-plugin-version"] = "copilot-chat/0.20.0";
		headers["User-Agent"] = std::string("opencode/") + k_aida_user_agent_version;
		headers["Openai-Intent"] = "conversation-edits";
		const bool is_agent = ctx.has_parent_session || ctx.is_compaction_continued;
		headers["x-initiator"] = is_agent ? "agent" : "user";
		if (ctx.request_body && request_has_image_content(*ctx.request_body))
			headers["Copilot-Vision-Request"] = "true";
		return headers;
	}

	if (provider_id == "openai" || provider_id == "openai-codex" || provider_id == "openai_native" || provider_id == "openai_codex") {
		if (!auth.api_key.empty())
			headers["authorization"] = std::string("Bearer ") + auth.api_key;
		else if (!auth.access.empty())
			headers["authorization"] = std::string("Bearer ") + auth.access;
		std::string acct = auth.account_id;
		if (acct.empty())
			acct = read_metadata_string(auth, "account_id");
		if (acct.empty())
			acct = read_metadata_string(auth, "accountId");
		const bool is_codex = (provider_id == "openai-codex" || provider_id == "openai_codex");
		if (!acct.empty())
			headers["ChatGPT-Account-Id"] = acct;
		if (is_codex) {
			headers["originator"] = "opencode";
			headers["User-Agent"] = build_opencode_user_agent();
			if (!ctx.session_id.empty())
				headers["session_id"] = ctx.session_id;
		}
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

std::map<std::string, std::string> compute_headers(const std::string& provider_id, const std::string& model_id, const aida::auth::auth_info_t& auth)
{
	request_context_t empty_ctx;
	return compute_headers(provider_id, model_id, auth, empty_ctx);
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
