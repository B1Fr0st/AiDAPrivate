#pragma once


#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <vector>
#include <functional>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <deque>
#include <chrono>

#include <nlohmann/json.hpp>


namespace httplib { class Client; }

struct settings_sa_t;


using ai_callback_t        = std::function<void(const std::string& result)>;
using ai_stream_chunk_t    = std::function<void(const std::string& chunk)>;
using ai_stop_predicate_t  = std::function<bool(const std::string& accumulated)>;


class standalone_ai_client_t
{
public:
    explicit standalone_ai_client_t(const settings_sa_t& settings);
    ~standalone_ai_client_t();


    standalone_ai_client_t(const standalone_ai_client_t&) = delete;
    standalone_ai_client_t& operator=(const standalone_ai_client_t&) = delete;


    bool is_available() const;


    void chat_async(
        const std::string& user_message,
        const std::vector<std::pair<std::string, std::string>>& history,
        ai_callback_t on_complete,
        ai_stream_chunk_t on_chunk = nullptr);


    std::string chat_blocking(
        const std::string& user_message,
        const std::vector<std::pair<std::string, std::string>>& history,
        ai_stream_chunk_t on_chunk = nullptr,
        ai_stop_predicate_t stop_check = nullptr);


    bool poll();


    void cancel();


    bool is_busy() const { return !_task_done.load(); }

private:
    const settings_sa_t& _settings;

    std::thread            _worker;
    std::mutex             _worker_mtx;
    std::atomic<bool>      _task_done{true};
    std::atomic<bool>      _cancelled{false};


    std::shared_ptr<httplib::Client> _http;
    std::mutex                       _http_mtx;
    std::string                      _last_host;


    struct pending_result_t { ai_callback_t cb; std::string text; };
    std::mutex                     _result_mtx;
    std::deque<pending_result_t>   _results;


    std::mutex                                 _chunk_mtx;
    std::deque<std::pair<ai_stream_chunk_t, std::string>> _chunks;


    std::shared_ptr<httplib::Client> get_or_create_client(const std::string& host);
    void reset_client();

    std::string do_generate(
        const std::string& prompt,
        double temperature,
        ai_stream_chunk_t on_chunk,
        ai_stop_predicate_t stop_check);


    std::string generate_gemini(const std::string& prompt, double temperature, ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check);
    std::string generate_openai(const std::string& prompt, double temperature, ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check);
    std::string generate_anthropic(const std::string& prompt, double temperature, ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check);
    std::string generate_openrouter(const std::string& prompt, double temperature, ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check);
    std::string generate_local(const std::string& prompt, double temperature, ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check);


    std::string streaming_post(
        const std::string& host,
        const std::string& path,
        const std::map<std::string, std::string>& headers,
        const std::string& body,
        std::function<std::string(const std::string& sse_data)> chunk_parser,
        ai_stream_chunk_t on_chunk,
        ai_stop_predicate_t stop_check);


    std::string simple_post(
        const std::string& host,
        const std::string& path,
        const std::map<std::string, std::string>& headers,
        const std::string& body,
        std::function<std::string(const nlohmann::json&)> response_parser);

    static std::string build_chat_prompt(
        const std::string& user_message,
        const std::vector<std::pair<std::string, std::string>>& history);
};


inline std::unique_ptr<standalone_ai_client_t> g_sa_ai_client;
