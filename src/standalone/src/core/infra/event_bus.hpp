#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <typeindex>
#include <typeinfo>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace events {

    template <typename Payload>
    struct event_def_t
    {
        const char* type_name;
    };

    using subscription_id_t = uint64_t;

    struct subscription_handle_t
    {
        subscription_id_t id = 0;
        std::string       type_name;

        bool valid() const { return id != 0 && !type_name.empty(); }
    };

    namespace detail {

        using callback_invoker_t = std::function<void(const void*)>;

        struct subscription_record_t
        {
            subscription_id_t  id = 0;
            std::type_index    payload_type{typeid(void)};
            callback_invoker_t invoker;
        };

        struct registry_t
        {
            std::shared_mutex                                                   mutex;
            std::unordered_map<std::string, std::vector<subscription_record_t>> by_type;
            std::atomic<subscription_id_t>                                      next_id{1};
            std::atomic<bool>                                                   shutdown_flag{false};
        };

        registry_t& get_registry();

        std::string last_error_slot();
        void        set_last_error(const std::string& msg);

        subscription_id_t register_subscription(const std::string& type_name, std::type_index payload_type, callback_invoker_t invoker);
        bool              remove_subscription(const std::string& type_name, subscription_id_t id);
        void              snapshot_subscribers(const std::string& type_name, std::vector<subscription_record_t>& out);

    }

    inline std::string last_error()
    {
        return detail::last_error_slot();
    }

    template <typename Payload, typename Callable>
    subscription_handle_t subscribe(const event_def_t<Payload>& def, Callable&& callback)
    {
        subscription_handle_t handle;
        if (def.type_name == nullptr || def.type_name[0] == '\0')
        {
            detail::set_last_error("event_bus.subscribe: invalid event type_name");
            return handle;
        }

        std::function<void(const Payload&)> cb_copy(std::forward<Callable>(callback));
        if (!cb_copy)
        {
            detail::set_last_error("event_bus.subscribe: null callback");
            return handle;
        }

        const std::type_index expected_type(typeid(Payload));
        detail::callback_invoker_t invoker = [cb_copy, expected_type](const void* payload_ptr)
        {
            const Payload& typed = *static_cast<const Payload*>(payload_ptr);
            cb_copy(typed);
            (void)expected_type;
        };

        std::string type_name(def.type_name);
        const subscription_id_t id = detail::register_subscription(type_name, expected_type, std::move(invoker));
        if (id == 0)
        {
            return handle;
        }

        handle.id        = id;
        handle.type_name = std::move(type_name);
        return handle;
    }

    template <typename Payload>
    void publish(const event_def_t<Payload>& def, const Payload& payload)
    {
        if (detail::get_registry().shutdown_flag.load(std::memory_order_acquire)) return;

        if (def.type_name == nullptr || def.type_name[0] == '\0')
        {
            detail::set_last_error("event_bus.publish: invalid event type_name");
            return;
        }

        std::vector<detail::subscription_record_t> snapshot;
        detail::snapshot_subscribers(std::string(def.type_name), snapshot);

        const std::type_index expected_type(typeid(Payload));
        const void* payload_ptr = static_cast<const void*>(&payload);
        for (const auto& rec : snapshot)
        {
            if (detail::get_registry().shutdown_flag.load(std::memory_order_acquire)) break;
            if (!rec.invoker) continue;
            if (rec.payload_type != expected_type)
            {
                detail::set_last_error("event_bus.publish: payload type mismatch for event type_name");
                continue;
            }
            try { rec.invoker(payload_ptr); } catch (...) { detail::set_last_error("event_bus.publish: subscriber callback raised"); }
        }
    }

    bool unsubscribe(const subscription_handle_t& handle);

    void shutdown();

    struct permission_asked_t
    {
        std::string    session_id;
        std::string    request_id;
        std::string    permission_key;
        std::string    pattern;
        std::string    tool_name;
        nlohmann::json arguments;
    };

    struct permission_replied_t
    {
        enum class reply_t { allow_once, allow_always, deny };

        std::string session_id;
        std::string request_id;
        reply_t     reply = reply_t::deny;
    };

    struct session_compacted_t
    {
        std::string session_id;
        int         messages_summarized = 0;
        int         tokens_freed        = 0;
    };

    struct tool_state_changed_t
    {
        enum class state_t { pending, running, completed, error };

        std::string session_id;
        std::string call_id;
        std::string tool_name;
        state_t     state = state_t::pending;
        std::string error_message;
    };

    struct oauth_completed_t
    {
        std::string provider_id;
        std::string email;
    };

    struct oauth_failed_t
    {
        std::string provider_id;
        std::string error;
    };

    struct model_changed_t
    {
        std::string session_id;
        std::string provider_id;
        std::string model_id;
    };

    struct binary_loaded_t
    {
        std::string binary_path;
        uint64_t    image_base = 0;
        uint32_t    image_size = 0;
    };

    struct mcp_tools_changed_t
    {
        std::string server_name;
        int         tool_count = 0;
    };

    struct agent_changed_t
    {
        std::string session_id;
        std::string previous_agent;
        std::string new_agent;
    };

    struct session_selected_t
    {
        std::string session_id;
    };

    struct session_created_t
    {
        std::string session_id;
        std::string project_id;
        std::string parent_id;
    };

    struct session_updated_t
    {
        std::string session_id;
        std::string fields_changed;
    };

    struct session_deleted_t
    {
        std::string session_id;
    };

    struct command_executed_t
    {
        std::string session_id;
        std::string command_name;
        std::string source;
        std::string args;
    };

    struct file_edited_t
    {
        std::string path;
        std::string kind;
        std::string session_id;
    };

    struct dll_loaded_t
    {
        uint32_t    process_id = 0;
        uint32_t    thread_id = 0;
        uint64_t    image_base = 0;
        uint64_t    image_size = 0;
        uint64_t    timestamp = 0;
        uint32_t    flags = 0;
        std::string image_path;
        std::string image_name;
    };

    struct process_created_t
    {
        uint32_t    process_id = 0;
        uint64_t    timestamp = 0;
        std::string image_path;
        std::string image_name;
    };

    struct process_exited_t
    {
        uint32_t process_id = 0;
        uint64_t timestamp = 0;
    };

    struct debug_events_drained_t
    {
        uint32_t returned_count = 0;
        uint32_t dropped_since_last_drain = 0;
        uint64_t total_dropped = 0;
        uint64_t total_published = 0;
    };

    inline constexpr event_def_t<permission_asked_t>   event_permission_asked{"aida.permission.asked"};
    inline constexpr event_def_t<permission_replied_t> event_permission_replied{"aida.permission.replied"};
    inline constexpr event_def_t<session_compacted_t>  event_session_compacted{"aida.session.compacted"};
    inline constexpr event_def_t<tool_state_changed_t> event_tool_state_changed{"aida.tool.state_changed"};
    inline constexpr event_def_t<oauth_completed_t>    event_oauth_completed{"aida.oauth.completed"};
    inline constexpr event_def_t<oauth_failed_t>       event_oauth_failed{"aida.oauth.failed"};
    inline constexpr event_def_t<model_changed_t>      event_model_changed{"aida.model.changed"};
    inline constexpr event_def_t<binary_loaded_t>      event_binary_loaded{"aida.binary.loaded"};
    inline constexpr event_def_t<mcp_tools_changed_t>  event_mcp_tools_changed{"aida.mcp.tools_changed"};
    inline constexpr event_def_t<agent_changed_t>      event_agent_changed{"aida.agent.changed"};
    inline constexpr event_def_t<session_selected_t>   event_session_selected{"aida.session.selected"};
    inline constexpr event_def_t<session_created_t>    event_session_created{"aida.session.created"};
    inline constexpr event_def_t<session_updated_t>    event_session_updated{"aida.session.updated"};
    inline constexpr event_def_t<session_deleted_t>    event_session_deleted{"aida.session.deleted"};
    inline constexpr event_def_t<command_executed_t>   event_command_executed{"aida.command.executed"};
    inline constexpr event_def_t<file_edited_t>        event_file_edited{"aida.file.edited"};
    inline constexpr event_def_t<dll_loaded_t>            event_dll_loaded{"aida.target.dll_loaded"};
    inline constexpr event_def_t<process_created_t>       event_process_created{"aida.target.process_created"};
    inline constexpr event_def_t<process_exited_t>        event_process_exited{"aida.target.process_exited"};
    inline constexpr event_def_t<debug_events_drained_t>  event_debug_events_drained{"aida.target.debug_events_drained"};

}
}
