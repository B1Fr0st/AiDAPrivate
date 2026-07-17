#pragma once

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace agent {

	struct permission_rule_t
	{
		enum class action_t : int
		{
			allow = 0,
			deny  = 1,
			ask   = 2,
		};

		std::string permission_key;
		std::string pattern;
		action_t    action = action_t::ask;
	};

	using ruleset_t = std::vector<permission_rule_t>;

	struct agent_model_override_t
	{
		std::string provider_id;
		std::string model_id;
	};

	struct agent_info_t
	{
		enum class mode_t : int
		{
			primary  = 0,
			subagent = 1,
			all      = 2,
		};

		std::string                            name;
		std::string                            description;
		mode_t                                 mode = mode_t::primary;
		bool                                   native = true;
		bool                                   hidden = false;
		std::string                            color;
		std::string                            system_prompt;
		ruleset_t                              permissions;
		std::vector<std::string>               tools_allowed;
		std::vector<std::string>               tools_denied;
		std::optional<agent_model_override_t>  model_override;
		double                                 temperature = 1.0;
		double                                 top_p = 1.0;
		int                                    max_steps = 0;
		nlohmann::json                         options = nlohmann::json::object();
	};

	struct custom_catalog_snapshot_t
	{
		std::uint64_t generation = 0;
		std::vector<agent_info_t> agents;
	};

	bool                              initialize();
	const std::vector<agent_info_t>&  list();
	std::vector<const agent_info_t*>  primary_agents();
	std::vector<const agent_info_t*>  subagents();
	const agent_info_t*               get(const std::string& name);
	const std::string&                default_agent_name();
	const agent_info_t*               small_compaction_agent_for(const std::string& provider_id);
	bool                              register_custom(const agent_info_t& info);
	bool                              unregister_custom(const std::string& name);
	bool                              save_custom_to_disk();
	bool                              load_custom_from_disk();
	custom_catalog_snapshot_t         custom_catalog_snapshot();
	bool                              commit_custom_catalog(
		std::uint64_t expected_generation,
		const std::vector<agent_info_t>& agents,
		std::string& error);
	bool                              reload_custom_catalog(
		std::uint64_t expected_generation,
		std::string& error);
	const std::string&                last_error();

	const std::string&                active_agent_name();
	bool                              set_active_agent(const std::string& name);
	const agent_info_t*               active_agent();
	void                              set_default_agent_name(const std::string& name);

	permission_rule_t::action_t       evaluate_ruleset(const ruleset_t& rules,
	                                                   const std::string& permission_key,
	                                                   const std::string& pattern_arg);
	bool                              tool_allowed(const agent_info_t& agent, const std::string& tool_name);
	std::string                       permission_key_for_tool(const std::string& tool_name);
	bool                              wildcard_match(const std::string& pattern, const std::string& target);

	nlohmann::json                    to_json(const agent_info_t& info);
	bool                              from_json(const nlohmann::json& obj, agent_info_t& out);

	namespace task {

		bool execute(const std::string& agent_name,
		             const std::string& prompt_text,
		             int max_steps,
		             const std::string& parent_session_id,
		             std::string& out_result,
		             std::atomic<bool>* cancel_flag = nullptr);

		const std::string& last_error();

	}

}
}
