/*
 * standalone_chat.cpp
 *
 * Replaces the hardcoded dummy AI in globals.h with real AI integration.
 * Implements:
 *   - Agentic tool-calling loop (text-based, works with ALL providers)
 *   - Thread-safe UI updates from the AI worker thread
 *   - Settings configuration popup (ImGui)
 *   - Initialization / shutdown of AI client, MCP server, kernel driver
 */

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <windows.h>

#include "mcp_standalone.hpp"
#include "standalone_ai_client.hpp"
#include "standalone_settings.hpp"
#include "standalone_driver.hpp"

#include "../helpers/globals.h"

#include <thread>
#include <mutex>
#include <atomic>
#include <deque>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <cstring>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ============================================================================
//  Thread-safe update queue  (worker thread -> main/render thread)
// ============================================================================
namespace {

struct ai_update_t
{
    enum type_t { THINKING, CHUNK, COMPLETE, ERR } type;
    std::string text;
};

std::mutex              s_update_mtx;
std::deque<ai_update_t> s_updates;

void post_update(ai_update_t::type_t type, const std::string& text = {})
{
    std::lock_guard<std::mutex> lk(s_update_mtx);
    s_updates.push_back({type, text});
}

// ============================================================================
//  Background AI worker state
// ============================================================================
std::thread       s_ai_thread;
std::mutex        s_ai_thread_mtx;
std::atomic<bool> s_ai_running{false};
std::atomic<bool> s_cancel{false};

// ============================================================================
//  MCP server instance (for tool execution)
// ============================================================================
mcp_standalone::server_t s_mcp_server;
bool                     s_server_started = false;
bool                     s_initialized    = false;

// ============================================================================
//  Tool-call parsing helpers
// ============================================================================
struct parsed_tool_call_t
{
    std::string name;
    json        arguments;
};

std::vector<parsed_tool_call_t> parse_tool_calls(const std::string& text)
{
    std::vector<parsed_tool_call_t> calls;
    const std::string open_tag  = "<tool_call>";
    const std::string close_tag = "</tool_call>";

    size_t pos = 0;
    while (pos < text.size()) {
        size_t start = text.find(open_tag, pos);
        if (start == std::string::npos) break;
        size_t body_start = start + open_tag.size();
        size_t end = text.find(close_tag, body_start);
        if (end == std::string::npos) break;

        std::string payload = text.substr(body_start, end - body_start);
        /* Trim whitespace */
        while (!payload.empty() && (payload.front() == ' ' || payload.front() == '\n' ||
               payload.front() == '\r' || payload.front() == '\t'))
            payload.erase(0, 1);
        while (!payload.empty() && (payload.back() == ' ' || payload.back() == '\n' ||
               payload.back() == '\r' || payload.back() == '\t'))
            payload.pop_back();

        auto j = json::parse(payload, nullptr, false);
        if (!j.is_discarded() && j.is_object()) {
            parsed_tool_call_t tc;
            tc.name      = j.value("name", "");
            tc.arguments = j.value("arguments", json::object());
            if (!tc.name.empty())
                calls.push_back(std::move(tc));
        }

        pos = end + close_tag.size();
    }
    return calls;
}

std::string strip_tool_blocks(const std::string& text)
{
    std::string result;
    const std::string open_tag  = "<tool_call>";
    const std::string close_tag = "</tool_call>";
    const std::string open_res  = "<tool_result";
    const std::string close_res = "</tool_result>";

    size_t pos = 0;
    while (pos < text.size()) {
        /* Skip <tool_call>...</tool_call> */
        size_t tc_start = text.find(open_tag, pos);
        size_t tr_start = text.find(open_res, pos);
        size_t next_tag = (std::min)(tc_start, tr_start);

        if (next_tag == std::string::npos) {
            result += text.substr(pos);
            break;
        }

        result += text.substr(pos, next_tag - pos);

        if (next_tag == tc_start) {
            size_t end = text.find(close_tag, tc_start);
            pos = (end != std::string::npos) ? end + close_tag.size() : text.size();
        } else {
            size_t end = text.find(close_res, tr_start);
            pos = (end != std::string::npos) ? end + close_res.size() : text.size();
        }
    }

    /* Trim leading/trailing whitespace and runs of blank lines */
    while (!result.empty() && (result.front() == '\n' || result.front() == '\r'))
        result.erase(0, 1);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}

// ============================================================================
//  System prompt builder (includes tool descriptions)
// ============================================================================
std::string build_system_prompt()
{
    std::string prompt;
    prompt.reserve(8192);

    prompt +=
        "You are AiDA, a state-of-the-art reverse engineering, binary analysis, "
        "and debugging assistant. You operate through a kernel driver for live "
        "process memory analysis, Zydis for x64 disassembly, and a Windows "
        "AppContainer sandbox for safe malware execution.\n\n"
        "## Rules\n"
        "- Be precise, technical, and concise.\n"
        "- When asked to analyze, disassemble, or inspect something, USE YOUR TOOLS.\n"
        "- Always call `driver_status` before attempting memory operations.\n"
        "- Call `driver_attach` with a process name before reading process memory.\n"
        "- Use `disassemble_file` to load and disassemble PE files from disk.\n"
        "- Use `disassemble_address` for live memory disassembly.\n"
        "- Use `sandbox_execute` for running untrusted binaries safely.\n"
        "- For number conversions, ALWAYS use `convert_number`.\n"
        "- Do NOT fabricate tool results. If you need data, call a tool.\n\n";

    prompt += "## Available Tools\n\n";

    auto& tools = s_mcp_server.get_tools();
    for (const auto& t : tools) {
        prompt += "### " + t.name + "\n";
        prompt += t.description + "\n";
        if (!t.params.empty()) {
            prompt += "Parameters:\n";
            for (const auto& p : t.params) {
                prompt += "- `" + p.name + "` (" + p.type;
                if (p.required) prompt += ", required";
                prompt += "): " + p.description + "\n";
            }
        }
        prompt += "\n";
    }

    prompt +=
        "## How to call a tool\n\n"
        "When you need to call a tool, output EXACTLY this format (one call per block):\n\n"
        "<tool_call>\n"
        "{\"name\": \"TOOL_NAME\", \"arguments\": {\"PARAM\": \"VALUE\"}}\n"
        "</tool_call>\n\n"
        "After each tool call you will receive its result inside <tool_result> tags.\n"
        "You may make multiple tool calls in sequence across turns.\n"
        "When you are done using tools, provide your final analysis as plain text "
        "WITHOUT any <tool_call> tags.\n";

    return prompt;
}

// ============================================================================
//  Tool execution (calls MCP server handlers directly, no HTTP round-trip)
// ============================================================================
std::string execute_tool(const std::string& name, const json& arguments)
{
    auto& tools = s_mcp_server.get_tools();
    for (const auto& t : tools) {
        if (t.name == name) {
            mcp_standalone::tool_result_t tr;
            try {
                tr = t.handler(arguments);
            } catch (const std::exception& e) {
                return std::string("Error: ") + e.what();
            } catch (...) {
                return "Error: Unknown exception executing tool.";
            }
            std::string output = tr.text;
            if (!tr.data.is_null() && !tr.data.empty()) {
                if (!output.empty()) output += "\n";
                try { output += tr.data.dump(2); } catch (...) {}
            }
            if (output.size() > 12000) {
                output.resize(12000);
                output += "\n... (output truncated to 12000 chars)";
            }
            return output;
        }
    }
    return "Error: Unknown tool '" + name + "'. Use the tools/list to see available tools.";
}

// ============================================================================
//  Agentic loop  (runs entirely in background thread)
// ============================================================================
void run_agentic(std::string user_message,
                 std::vector<std::pair<std::string, std::string>> history)
{
    post_update(ai_update_t::THINKING);

    /* ---- build the full prompt ---- */
    std::string system_prompt = build_system_prompt();

    std::string conversation;
    conversation.reserve(4096);
    if (!history.empty()) {
        conversation += "## Previous conversation\n\n";
        for (auto& [role, text] : history)
            conversation += role + ": " + text + "\n\n";
    }
    conversation += "User: " + user_message + "\n\nAssistant:";

    std::string full_prompt = system_prompt + "\n\n" + conversation;

    constexpr int MAX_TURNS = 15;

    for (int turn = 0; turn < MAX_TURNS; ++turn) {
        if (s_cancel.load()) {
            post_update(ai_update_t::COMPLETE);
            return;
        }

        /* Post a thinking status for tool turns after the first */
        if (turn > 0)
            post_update(ai_update_t::THINKING, "Processing tool results...");

        /* ---- call the AI (blocking, no streaming) ---- */
        std::string response;
        try {
            response = g_sa_ai_client->chat_blocking(full_prompt, {}, nullptr, nullptr);
        } catch (const std::exception& e) {
            post_update(ai_update_t::ERR, std::string("Exception: ") + e.what());
            return;
        }

        if (s_cancel.load()) {
            post_update(ai_update_t::COMPLETE);
            return;
        }

        /* ---- check for errors ---- */
        if (response.size() >= 6 && response.substr(0, 6) == "Error:") {
            post_update(ai_update_t::ERR, response);
            return;
        }

        /* ---- parse tool calls ---- */
        auto calls = parse_tool_calls(response);

        if (calls.empty()) {
            /* No tool calls -> this is the final response. */
            std::string clean = strip_tool_blocks(response);
            if (clean.empty()) clean = response; /* fallback */

            /* Simulate streaming output for a smooth UI experience */
            constexpr size_t CHARS_PER_CHUNK = 24;
            for (size_t i = 0; i < clean.size() && !s_cancel.load(); ) {
                size_t n = (std::min)(CHARS_PER_CHUNK, clean.size() - i);
                post_update(ai_update_t::CHUNK, clean.substr(i, n));
                i += n;
                std::this_thread::sleep_for(std::chrono::milliseconds(12));
            }
            post_update(ai_update_t::COMPLETE);
            return;
        }

        /* ---- execute each tool call ---- */
        std::string tool_results;
        for (auto& tc : calls) {
            if (s_cancel.load()) {
                post_update(ai_update_t::COMPLETE);
                return;
            }
            post_update(ai_update_t::THINKING, "Calling " + tc.name + "...");

            std::string result = execute_tool(tc.name, tc.arguments);
            tool_results += "\n<tool_result name=\"" + tc.name + "\">\n"
                          + result
                          + "\n</tool_result>\n";
        }

        /* ---- append assistant response + tool results for the next turn ---- */
        full_prompt += " " + response + "\n"
                     + tool_results
                     + "\nContinue your analysis using the tool results above. "
                       "If you need more data, call more tools. "
                       "Otherwise, provide your final answer as plain text.\n\nAssistant:";
    }

    post_update(ai_update_t::ERR, "Reached maximum tool-calling rounds (15). Stopping.");
}

} // anonymous namespace

// ============================================================================
//  Settings popup state  (visible to helpers.cpp via extern in globals.h)
// ============================================================================
bool g_settings_open = false;

// ============================================================================
//  PUBLIC API  -  called from helpers.cpp / main.cpp
// ============================================================================

void init_standalone_chat()
{
    if (s_initialized) return;

    /* Load persisted settings (api keys, model, provider, etc.) */
    g_sa_settings.load();

    /* Create the AI HTTP client */
    g_sa_ai_client = std::make_unique<standalone_ai_client_t>(g_sa_settings);

    /* Register all tools and start the MCP server */
    mcp_standalone::register_standalone_tools(s_mcp_server);
    if (g_sa_settings.mcp_enabled) {
        if (s_mcp_server.start(g_sa_settings.mcp_port)) {
            s_server_started = true;
            s_mcp_server.write_client_configs();
        }
    }

    /* Attempt to load the kernel driver (non-fatal if it fails) */
    driver_bridge::initialize();

    s_initialized = true;
}

void shutdown_standalone_chat()
{
    s_cancel = true;
    {
        std::lock_guard<std::mutex> lk(s_ai_thread_mtx);
        if (s_ai_thread.joinable())
            s_ai_thread.join();
    }
    if (s_server_started)
        s_mcp_server.stop();
    g_sa_ai_client.reset();
    s_initialized = false;
}

/*
 * tick_ai_chat() - called every frame from the render thread.
 * Detects when the user has posted a new message and kicks off
 * the agentic AI loop in a background thread.
 */
void tick_ai_chat()
{
    if (!s_initialized) return;
    if (g_chat_messages.empty()) return;

    auto& last = g_chat_messages.back();
    if (!last.is_user || g_dummy_triggered) return;

    /* ----- User sent a new message ----- */
    std::string user_text = last.text;
    g_dummy_triggered = true;

    /* Check availability */
    if (!g_sa_ai_client || !g_sa_ai_client->is_available()) {
        ChatMessage ai;
        ai.is_user       = false;
        ai.has_thinking   = false;
        ai.streaming      = false;
        ai.text           = "AI not configured. Click \"Settings\" in the chat header to set your API key and model.";
        g_chat_messages.push_back(ai);
        g_chat_scroll_to_bottom = true;
        g_dummy_triggered = false;
        return;
    }

    /* Reset thinking state */
    g_think_done  = false;
    g_think_timer = 0.f;

    /* Push an empty AI message placeholder */
    ChatMessage ai;
    ai.is_user       = false;
    ai.has_thinking   = true;
    ai.streaming      = true;
    ai.thinking_text  = "";
    ai.text           = "";
    g_chat_messages.push_back(ai);
    g_chat_scroll_to_bottom = true;

    /* Collect conversation history (skip the placeholder we just pushed) */
    std::vector<std::pair<std::string, std::string>> history;
    for (int i = 0; i < (int)g_chat_messages.size() - 2; ++i) {
        auto& m = g_chat_messages[i];
        if (!m.text.empty())
            history.emplace_back(m.is_user ? "User" : "Assistant", m.text);
    }

    /* Cancel any existing run */
    {
        std::lock_guard<std::mutex> lk(s_ai_thread_mtx);
        if (s_ai_running.load()) {
            s_cancel = true;
            if (g_sa_ai_client) g_sa_ai_client->cancel();
            if (s_ai_thread.joinable())
                s_ai_thread.join();
        }
        s_cancel      = false;
        s_ai_running  = true;
        s_ai_thread   = std::thread(run_agentic,
                                    std::move(user_text),
                                    std::move(history));
    }
}

/*
 * poll_ai_chat() - called every frame from the render thread.
 * Drains the update queue posted by the background AI worker
 * and applies changes to the live ChatMessage objects.
 */
void poll_ai_chat()
{
    if (!s_initialized) return;

    std::deque<ai_update_t> local;
    {
        std::lock_guard<std::mutex> lk(s_update_mtx);
        std::swap(local, s_updates);
    }

    for (auto& u : local) {
        if (g_chat_messages.empty()) continue;
        auto& last = g_chat_messages.back();
        if (last.is_user) continue;

        switch (u.type) {
        case ai_update_t::THINKING:
            if (!u.text.empty()) {
                if (!last.thinking_text.empty())
                    last.thinking_text += "\n";
                last.thinking_text += u.text;
            }
            break;

        case ai_update_t::CHUNK:
            if (!g_think_done) g_think_done = true;
            last.text += u.text;
            g_chat_scroll_to_bottom = true;
            break;

        case ai_update_t::COMPLETE:
            last.streaming = false;
            g_think_done         = true;
            g_dummy_triggered    = false;
            s_ai_running         = false;
            g_chat_scroll_to_bottom = true;
            break;

        case ai_update_t::ERR:
            g_think_done         = true;
            if (!u.text.empty()) last.text = u.text;
            last.streaming       = false;
            g_dummy_triggered    = false;
            s_ai_running         = false;
            g_chat_scroll_to_bottom = true;
            break;
        }
    }
}

// ============================================================================
//  Settings popup  (rendered within the main ImGui window)
// ============================================================================
void render_settings_popup()
{
    if (!g_settings_open) return;

    ImGui::OpenPopup("##sa_settings_modal");

    float ww = globals::ui::window_w;
    float wh = globals::ui::window_h;
    float pw = 440.f, ph = 480.f;
    ImGui::SetNextWindowPos(ImVec2((ww - pw) * 0.5f, (wh - ph) * 0.5f), ImGuiCond_Appearing);
    ImGui::SetNextWindowSize(ImVec2(pw, ph), ImGuiCond_Always);

    float a = globals::ui::ui_alpha;
    float ax = globals::ui::accent.x, ay = globals::ui::accent.y, az = globals::ui::accent.z;

    ImGui::PushStyleColor(ImGuiCol_PopupBg,        ImVec4(0.075f, 0.075f, 0.10f, 0.97f));
    ImGui::PushStyleColor(ImGuiCol_Border,          ImVec4(1.f, 1.f, 1.f, 0.08f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg,         ImVec4(0.12f, 0.12f, 0.16f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,  ImVec4(0.16f, 0.16f, 0.22f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive,   ImVec4(0.18f, 0.18f, 0.25f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_Button,          ImVec4(ax * 0.4f, ay * 0.4f, az * 0.4f, 0.7f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,   ImVec4(ax * 0.55f, ay * 0.55f, az * 0.55f, 0.85f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,    ImVec4(ax * 0.65f, ay * 0.65f, az * 0.65f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_Header,          ImVec4(ax * 0.3f, ay * 0.3f, az * 0.3f, 0.4f));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered,   ImVec4(ax * 0.4f, ay * 0.4f, az * 0.4f, 0.6f));
    ImGui::PushStyleColor(ImGuiCol_HeaderActive,    ImVec4(ax * 0.5f, ay * 0.5f, az * 0.5f, 0.8f));
    ImGui::PushStyleColor(ImGuiCol_Text,            ImVec4(0.88f, 0.87f, 0.94f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_SliderGrab,      ImVec4(ax, ay, az, 0.8f));
    ImGui::PushStyleColor(ImGuiCol_SliderGrabActive,ImVec4(ax, ay, az, 1.f));
    ImGui::PushStyleColor(ImGuiCol_CheckMark,       ImVec4(ax, ay, az, 1.f));

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,  ImVec2(18.f, 14.f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding,  6.f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,   ImVec2(8.f, 5.f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,    ImVec2(8.f, 8.f));

    bool still_open = true;
    if (ImGui::BeginPopupModal("##sa_settings_modal", &still_open,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove))
    {
        /* ---- static buffers, initialized from g_sa_settings once ---- */
        static bool        s_first = true;
        static int         s_provider = 0;
        static char        s_api_key[512]   = {};
        static char        s_base_url[512]  = {};
        static int         s_model_idx = 0;
        static char        s_custom_model[256] = {};
        static float       s_temperature = 0.7f;
        static int         s_mcp_port = 29117;
        static bool        s_mcp_enabled = true;
        static char        s_local_url[512] = {};

        auto find_provider_idx = [](const std::string& id) -> int {
            if (id == "gemini")      return 0;
            if (id == "openai")      return 1;
            if (id == "anthropic")   return 2;
            if (id == "openrouter")  return 3;
            if (id == "local_llm")   return 4;
            return 0;
        };

        auto provider_id = [](int idx) -> const char* {
            switch (idx) {
            case 0: return "gemini";
            case 1: return "openai";
            case 2: return "anthropic";
            case 3: return "openrouter";
            case 4: return "local_llm";
            default: return "gemini";
            }
        };

        auto get_api_key = [](int idx) -> std::string {
            switch (idx) {
            case 0: return g_sa_settings.gemini_api_key;
            case 1: return g_sa_settings.openai_api_key;
            case 2: return g_sa_settings.anthropic_api_key;
            case 3: return g_sa_settings.openrouter_api_key;
            case 4: return g_sa_settings.local_llm_api_key;
            default: return {};
            }
        };

        auto get_base_url = [](int idx) -> std::string {
            switch (idx) {
            case 0: return g_sa_settings.gemini_base_url;
            case 1: return g_sa_settings.openai_base_url;
            case 2: return g_sa_settings.anthropic_base_url;
            case 4: return g_sa_settings.local_llm_base_url;
            default: return {};
            }
        };

        auto get_model_list = [](int idx) -> const std::vector<std::string>& {
            switch (idx) {
            case 0: return settings_sa_t::gemini_models();
            case 1: return settings_sa_t::openai_models();
            case 2: return settings_sa_t::anthropic_models();
            case 3: return settings_sa_t::openrouter_models();
            case 4: return settings_sa_t::local_llm_models();
            default: { static std::vector<std::string> e; return e; }
            }
        };

        auto get_model_name = [](int idx) -> std::string {
            switch (idx) {
            case 0: return g_sa_settings.gemini_model_name;
            case 1: return g_sa_settings.openai_model_name;
            case 2: return g_sa_settings.anthropic_model_name;
            case 3: return g_sa_settings.openrouter_model_name;
            case 4: return g_sa_settings.local_llm_model_name;
            default: return {};
            }
        };

        /* Populate buffers from settings on first open */
        if (s_first) {
            s_first       = false;
            s_provider    = find_provider_idx(g_sa_settings.api_provider);
            s_temperature = static_cast<float>(g_sa_settings.temperature);
            s_mcp_port    = g_sa_settings.mcp_port;
            s_mcp_enabled = g_sa_settings.mcp_enabled;

            auto key = get_api_key(s_provider);
            snprintf(s_api_key, sizeof(s_api_key), "%s", key.c_str());

            auto url = get_base_url(s_provider);
            snprintf(s_base_url, sizeof(s_base_url), "%s", url.c_str());

            snprintf(s_local_url, sizeof(s_local_url), "%s",
                     g_sa_settings.local_llm_base_url.c_str());

            auto model = get_model_name(s_provider);
            snprintf(s_custom_model, sizeof(s_custom_model), "%s", model.c_str());

            auto& models = get_model_list(s_provider);
            s_model_idx = 0;
            for (int i = 0; i < (int)models.size(); ++i) {
                if (models[i] == model) { s_model_idx = i; break; }
            }
        }

        /* ---- Title ---- */
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 wp = ImGui::GetWindowPos();
        {
            const char* title = "AI Configuration";
            ImVec2 tts = ImGui::CalcTextSize(title);
            dl->AddText(ImVec2(wp.x + 18, wp.y + 14),
                IM_COL32((int)(ax*255), (int)(ay*255), (int)(az*255), 220), title);
            ImGui::Dummy(ImVec2(0, tts.y + 6));
        }

        float iw = pw - 36.f;

        /* ---- Provider ---- */
        {
            ImGui::Text("Provider");
            const char* providers[] = {"Gemini", "OpenAI", "Anthropic", "OpenRouter", "Local LLM"};
            int prev = s_provider;
            ImGui::SetNextItemWidth(iw);
            ImGui::Combo("##provider", &s_provider, providers, IM_ARRAYSIZE(providers));
            if (s_provider != prev) {
                /* Reload fields for the new provider */
                auto key = get_api_key(s_provider);
                snprintf(s_api_key, sizeof(s_api_key), "%s", key.c_str());
                auto url = get_base_url(s_provider);
                snprintf(s_base_url, sizeof(s_base_url), "%s", url.c_str());
                auto model = get_model_name(s_provider);
                snprintf(s_custom_model, sizeof(s_custom_model), "%s", model.c_str());
                auto& models = get_model_list(s_provider);
                s_model_idx = 0;
                for (int i = 0; i < (int)models.size(); ++i)
                    if (models[i] == model) { s_model_idx = i; break; }
            }
        }

        /* ---- API Key ---- */
        if (s_provider != 4 || !std::string(s_api_key).empty()) {
            ImGui::Text("API Key");
            ImGui::SetNextItemWidth(iw);
            ImGui::InputText("##apikey", s_api_key, sizeof(s_api_key),
                             ImGuiInputTextFlags_Password);
        }

        /* ---- Model ---- */
        {
            ImGui::Text("Model");
            auto& models = get_model_list(s_provider);
            if (!models.empty()) {
                if (s_model_idx >= (int)models.size()) s_model_idx = 0;
                ImGui::SetNextItemWidth(iw);
                if (ImGui::BeginCombo("##model", models[s_model_idx].c_str())) {
                    for (int i = 0; i < (int)models.size(); ++i) {
                        bool selected = (i == s_model_idx);
                        if (ImGui::Selectable(models[i].c_str(), selected))
                            s_model_idx = i;
                        if (selected)
                            ImGui::SetItemDefaultFocus();
                    }
                    ImGui::EndCombo();
                }
            }
            ImGui::Text("Custom Model (overrides dropdown)");
            ImGui::SetNextItemWidth(iw);
            ImGui::InputText("##custom_model", s_custom_model, sizeof(s_custom_model));
        }

        /* ---- Base URL (optional) ---- */
        {
            const char* label = s_provider == 4 ? "Base URL (required)" : "Base URL (optional, for proxies)";
            ImGui::Text("%s", label);
            ImGui::SetNextItemWidth(iw);
            if (s_provider == 4) {
                ImGui::InputText("##baseurl_local", s_local_url, sizeof(s_local_url));
            } else {
                ImGui::InputText("##baseurl", s_base_url, sizeof(s_base_url));
            }
        }

        /* ---- Temperature ---- */
        {
            ImGui::Text("Temperature");
            ImGui::SetNextItemWidth(iw);
            ImGui::SliderFloat("##temp", &s_temperature, 0.0f, 2.0f, "%.2f");
        }

        /* ---- MCP Server ---- */
        {
            ImGui::Checkbox("Enable MCP Server", &s_mcp_enabled);
            if (s_mcp_enabled) {
                ImGui::SameLine();
                ImGui::SetNextItemWidth(80.f);
                ImGui::InputInt("Port", &s_mcp_port, 0, 0);
                if (s_mcp_port < 1) s_mcp_port = 1;
                if (s_mcp_port > 65535) s_mcp_port = 65535;
            }
        }

        ImGui::Dummy(ImVec2(0, 6));

        /* ---- Save / Cancel buttons ---- */
        float btn_w = 100.f;
        float btn_spacing = 12.f;
        float total_btn_w = btn_w * 2 + btn_spacing;
        ImGui::SetCursorPosX((pw - total_btn_w) * 0.5f - 9.f);

        if (ImGui::Button("Save", ImVec2(btn_w, 30))) {
            /* Copy buffers back to settings */
            g_sa_settings.api_provider = provider_id(s_provider);
            g_sa_settings.temperature  = static_cast<double>(s_temperature);
            g_sa_settings.mcp_port     = s_mcp_port;
            g_sa_settings.mcp_enabled  = s_mcp_enabled;

            std::string key_str    = s_api_key;
            std::string model_str  = s_custom_model[0] ? std::string(s_custom_model)
                                   : (!get_model_list(s_provider).empty()
                                       ? get_model_list(s_provider)[s_model_idx] : "");
            std::string url_str    = (s_provider == 4) ? std::string(s_local_url)
                                                       : std::string(s_base_url);

            switch (s_provider) {
            case 0:
                g_sa_settings.gemini_api_key    = key_str;
                g_sa_settings.gemini_model_name = model_str;
                g_sa_settings.gemini_base_url   = url_str;
                break;
            case 1:
                g_sa_settings.openai_api_key    = key_str;
                g_sa_settings.openai_model_name = model_str;
                g_sa_settings.openai_base_url   = url_str;
                break;
            case 2:
                g_sa_settings.anthropic_api_key    = key_str;
                g_sa_settings.anthropic_model_name = model_str;
                g_sa_settings.anthropic_base_url   = url_str;
                break;
            case 3:
                g_sa_settings.openrouter_api_key    = key_str;
                g_sa_settings.openrouter_model_name = model_str;
                break;
            case 4:
                g_sa_settings.local_llm_api_key    = key_str;
                g_sa_settings.local_llm_model_name = model_str;
                g_sa_settings.local_llm_base_url   = std::string(s_local_url);
                break;
            }

            g_sa_settings.save();

            /* Recreate the AI client so it picks up the new host/key immediately */
            if (g_sa_ai_client)
                g_sa_ai_client.reset();
            g_sa_ai_client = std::make_unique<standalone_ai_client_t>(g_sa_settings);

            g_settings_open = false;
            ImGui::CloseCurrentPopup();
        }

        ImGui::SameLine(0, btn_spacing);

        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.22f, 0.22f, 0.28f, 0.8f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,  ImVec4(0.30f, 0.30f, 0.38f, 0.9f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,   ImVec4(0.36f, 0.36f, 0.44f, 1.f));
        if (ImGui::Button("Cancel", ImVec2(btn_w, 30))) {
            s_first = true; /* re-read settings on next open */
            g_settings_open = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(3);

        ImGui::EndPopup();
    }

    if (!still_open) {
        s_first = true;
        g_settings_open = false;
    }

    ImGui::PopStyleVar(5);
    ImGui::PopStyleColor(15);
}
