#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>


namespace aida {
namespace commands {


	enum class command_source_t : int
	{
		builtin = 0,
		mcp     = 1,
		skill   = 2,
		agent   = 3,
	};


	struct command_t
	{
		std::string                                                                            name;
		std::string                                                                            description;
		command_source_t                                                                       source = command_source_t::builtin;
		std::string                                                                            template_text;
		std::vector<std::string>                                                               placeholder_hints;
		std::optional<std::string>                                                             agent_override;
		std::optional<std::string>                                                             model_override;
		bool                                                                                   subtask = false;
		std::string                                                                            source_path;
		std::function<bool(const std::vector<std::string>& args, std::string& out_text)>       resolver;
	};


	bool                                  initialize();
	bool                                  reindex();
	const std::vector<command_t>&         list();
	const command_t*                      find(const std::string& name);
	std::vector<const command_t*>         fuzzy_search(const std::string& query, int limit = 50);
	bool                                  execute(const std::string& name,
	                                              const std::vector<std::string>& args,
	                                              std::string& out_resolved_text);
	const std::string&                    last_error();


	std::vector<std::string>              extract_placeholder_hints(const std::string& template_text);
	std::string                           apply_placeholders(const std::string& template_text,
	                                                          const std::vector<std::string>& args);


}
}
