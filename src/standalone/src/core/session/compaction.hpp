#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "session_store.hpp"
#include "provider_catalog.hpp"


namespace aida {
namespace compaction {


	struct compaction_options_t
	{
		double trigger_ratio              = 0.85;
		int    preserve_recent_messages   = 2;
		int    preserve_recent_tokens     = 8000;
		int    max_summary_tokens         = 4000;
		int    truncate_tool_output_chars = 2000;
	};


	struct compaction_result_t
	{
		bool        ran                   = false;
		int         messages_summarized   = 0;
		int         tokens_freed          = 0;
		std::string summary_text;
		std::string compaction_message_id;
		std::string tail_start_message_id;
		std::string error;
	};


	bool should_trigger(const std::string& session_id,
	                    int64_t used_tokens,
	                    int64_t context_limit,
	                    const compaction_options_t& opts = compaction_options_t{});


	bool run(const std::string& session_id,
	         const compaction_options_t& opts,
	         compaction_result_t& out);


	bool truncate_tool_outputs(std::vector<aida::session::message_t>& messages,
	                           int max_chars);


	std::vector<aida::session::message_t> filter_compacted(
		const std::vector<aida::session::message_t>& messages);


	bool maybe_auto_title(const std::string& session_id,
	                      const std::string& first_user_message,
	                      const std::string& provider_id);


	const std::string& last_error();


}
}
