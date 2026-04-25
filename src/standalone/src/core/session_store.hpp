#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include <nlohmann/json.hpp>


namespace aida::session {


struct usage_tokens_t
{
    int64_t input        = 0;
    int64_t output       = 0;
    int64_t reasoning    = 0;
    int64_t cache_read   = 0;
    int64_t cache_write  = 0;
};


struct part_text_t
{
    std::string text;
    bool        synthetic = false;
};


struct part_tool_t
{
    enum class state_t
    {
        pending,
        running,
        completed,
        error
    };

    std::string    call_id;
    std::string    tool_name;
    state_t        state = state_t::pending;
    nlohmann::json arguments;
    std::string    output_text;
    nlohmann::json metadata;
    std::string    error_message;
    int64_t        time_start_unix = 0;
    int64_t        time_end_unix   = 0;
};


struct part_compaction_t
{
    std::string summary_text;
    bool        auto_triggered = false;
    bool        overflow       = false;
    std::string tail_start_message_id;
};


struct part_reasoning_t
{
    std::string text;
    int64_t     time_start_unix = 0;
    int64_t     time_end_unix   = 0;
};


struct part_step_finish_t
{
    double          cost_usd = 0.0;
    usage_tokens_t  tokens;
    std::string     finish_reason;
};


struct part_t
{
    enum class kind_t
    {
        text,
        tool,
        compaction,
        reasoning,
        step_finish
    };

    kind_t              kind = kind_t::text;
    part_text_t         text;
    part_tool_t         tool;
    part_compaction_t   compaction;
    part_reasoning_t    reasoning;
    part_step_finish_t  step_finish;
};


struct message_t
{
    enum class role_t
    {
        user,
        assistant,
        tool_result
    };

    std::string         id;
    std::string         session_id;
    role_t              role = role_t::user;
    std::string         agent;
    std::string         model_provider_id;
    std::string         model_id;
    std::vector<part_t> parts;
    int64_t             created_unix = 0;
};


struct session_summary_t
{
    int additions = 0;
    int deletions = 0;
    int files     = 0;
};


struct session_info_t
{
    std::string         id;
    std::string         slug;
    std::string         project_id;
    std::string         parent_id;
    std::string         title;
    std::string         binary_path;
    std::string         directory;
    int                 version = 1;
    session_summary_t   summary;
    int64_t             time_created_unix    = 0;
    int64_t             time_updated_unix    = 0;
    int64_t             time_archived_unix   = 0;
    int64_t             time_compacting_unix = 0;
    nlohmann::json      revert_data;
    nlohmann::json      permission;
    double              total_cost_usd       = 0.0;
};


bool initialize();
bool shutdown();

bool create(session_info_t& out_info,
            const std::string& project_id,
            const std::string& binary_path,
            const std::string& parent_id = "");
bool get(const std::string& session_id, session_info_t& out);
bool update(const session_info_t& info);
bool list(const std::string& binary_path_filter, std::vector<session_info_t>& out);
bool list_all(std::vector<session_info_t>& out);
bool list_children(const std::string& parent_id, std::vector<session_info_t>& out);
bool fork(const std::string& session_id,
          const std::string& fork_at_message_id,
          session_info_t& out_new);
bool set_archived(const std::string& session_id, int64_t archived_unix);
bool remove(const std::string& session_id);
bool set_title(const std::string& session_id, const std::string& title);

bool append_message(const message_t& message);
bool list_messages(const std::string& session_id,
                   std::vector<message_t>& out,
                   int limit = -1);
bool update_message(const message_t& message);

double         session_cost(const std::string& session_id);
usage_tokens_t session_tokens(const std::string& session_id);

const std::string& last_error();


}
