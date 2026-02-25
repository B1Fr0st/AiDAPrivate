#pragma once

#include <memory>
#include <vector>
#include <deque>
#include <mutex>
#include <string>
#include <algorithm>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <dbg.hpp>

#ifdef __NT__
#include <windows.h>
#endif

class AIClient;
class mcp_server_t;

struct ui_event_listener_t : public event_listener_t
{
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct dbg_event_listener_t : public event_listener_t
{
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct dbg_event_record_t
{
    uint64_t          timestamp_ms;
    dbg_notification_t notification;
    ea_t              ea;
    int               pid;
    int               tid;
    std::string       detail;
};

class dbg_event_log_t
{
public:
    static constexpr size_t MAX_EVENTS = 512;

    void push(dbg_event_record_t rec)
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_events.size() >= MAX_EVENTS)
            m_events.pop_front();
        m_events.push_back(std::move(rec));
    }

    std::vector<dbg_event_record_t> snapshot(size_t last_n = 0) const
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (last_n == 0 || last_n >= m_events.size())
            return {m_events.begin(), m_events.end()};
        return {m_events.end() - static_cast<ptrdiff_t>(last_n), m_events.end()};
    }

    std::vector<dbg_event_record_t> since(uint64_t after_ts) const
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        std::vector<dbg_event_record_t> out;
        for (auto it = m_events.rbegin(); it != m_events.rend(); ++it)
        {
            if (it->timestamp_ms <= after_ts)
                break;
            out.push_back(*it);
        }
        std::reverse(out.begin(), out.end());
        return out;
    }

    void clear()
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_events.clear();
    }

    size_t size() const
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_events.size();
    }

private:
    mutable std::mutex              m_mtx;
    std::deque<dbg_event_record_t>  m_events;
};

inline dbg_event_log_t g_dbg_event_log;

class aida_plugin_t : public plugmod_t
{
public:
    std::unique_ptr<AIClient> ai_client;
    std::vector<std::unique_ptr<AIClient>> m_stale_clients;
    qstrvec_t actions_list;
    ui_event_listener_t ui_listener;
    dbg_event_listener_t dbg_listener;
    std::unique_ptr<mcp_server_t> mcp_server;

    aida_plugin_t();
    ~aida_plugin_t() override;

    bool idaapi run(size_t arg) override;
    void reinit_ai_client();
    void check_for_updates();
    void start_mcp_server();
    void stop_mcp_server();
    void toggle_mcp_server();
    void start_copilot_proxy();
    void stop_copilot_proxy();

#ifdef __NT__
    HANDLE m_copilot_process = nullptr;
    HANDLE m_copilot_job = nullptr;
#endif

private:
    void register_actions();
    void unregister_actions();
};