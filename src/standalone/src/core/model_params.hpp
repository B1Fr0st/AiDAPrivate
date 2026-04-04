#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <algorithm>
#include <cmath>

#include "standalone_context.hpp"


namespace model_params {


enum class reasoning_mode_t
{
    none,
    budget,
    effort,
    binary
};


struct resolved_params_t
{
    std::optional<int32_t>     max_tokens;
    std::optional<float>       temperature;
    std::optional<std::string> reasoning_effort;
    std::optional<int32_t>     reasoning_budget;
    reasoning_mode_t           reasoning_mode = reasoning_mode_t::none;
};


struct reasoning_settings_t
{
    bool        enable_reasoning = false;
    int         reasoning_budget = 10000;
    std::string reasoning_effort = "medium";
};


inline bool should_use_reasoning_budget(const context_mgmt::model_info_t& model, const reasoning_settings_t& settings)
{
    if (!model.supports_reasoning) return false;

    if (!model.reasoning_effort_param.empty())
        return false;

    return settings.enable_reasoning;
}


inline bool should_use_reasoning_effort(const context_mgmt::model_info_t& model, const reasoning_settings_t& settings)
{
    if (!model.supports_reasoning) return false;
    if (model.reasoning_effort_param.empty()) return false;

    return settings.enable_reasoning;
}


inline reasoning_mode_t get_reasoning_mode(const context_mgmt::model_info_t& model, const reasoning_settings_t& settings)
{
    if (!model.supports_reasoning) return reasoning_mode_t::none;
    if (!settings.enable_reasoning) return reasoning_mode_t::none;

    if (!model.reasoning_effort_param.empty())
        return reasoning_mode_t::effort;

    return reasoning_mode_t::budget;
}


inline int32_t get_max_output_tokens(
    const std::string& model_id,
    const context_mgmt::model_info_t& model,
    const reasoning_settings_t& settings,
    std::optional<int32_t> user_override = std::nullopt)
{
    if (user_override.has_value())
        return user_override.value();

    auto mode = get_reasoning_mode(model, settings);

    if (mode == reasoning_mode_t::budget)
        return 16384;

    if (model_id.find("gpt-5") != std::string::npos)
        return static_cast<int32_t>(model.context_window * 0.5);

    if (model_id.find("claude") != std::string::npos && mode == reasoning_mode_t::none)
        return 4096;

    return static_cast<int32_t>(model.context_window * 0.2);
}


inline std::optional<float> resolve_temperature(
    const std::string& model_id,
    const context_mgmt::model_info_t& model,
    const reasoning_settings_t& settings,
    std::optional<float> user_override = std::nullopt)
{
    auto mode = get_reasoning_mode(model, settings);

    if (mode == reasoning_mode_t::budget)
        return 1.0f;

    if (mode == reasoning_mode_t::effort) {
        if (model_id.find("o1") != std::string::npos ||
            model_id.find("o3-mini") != std::string::npos)
            return std::nullopt;
    }

    if (user_override.has_value())
        return user_override.value();

    return 0.0f;
}


inline resolved_params_t resolve(
    const std::string& model_id,
    const context_mgmt::model_info_t& model,
    const reasoning_settings_t& settings,
    std::optional<float> user_temperature = std::nullopt,
    std::optional<int32_t> user_max_tokens = std::nullopt)
{
    resolved_params_t p;

    p.max_tokens = get_max_output_tokens(model_id, model, settings, user_max_tokens);
    p.temperature = resolve_temperature(model_id, model, settings, user_temperature);
    p.reasoning_mode = get_reasoning_mode(model, settings);

    if (p.reasoning_mode == reasoning_mode_t::budget) {
        int32_t budget = settings.reasoning_budget;

        if (p.max_tokens.has_value() && budget > static_cast<int32_t>(p.max_tokens.value() * 0.8))
            budget = static_cast<int32_t>(p.max_tokens.value() * 0.8);

        bool is_gemini_25_pro = model_id.find("gemini-2.5-pro") != std::string::npos;
        int32_t min_budget = is_gemini_25_pro ? 128 : 1024;
        if (budget < min_budget)
            budget = min_budget;

        p.reasoning_budget = budget;

    } else if (p.reasoning_mode == reasoning_mode_t::effort) {
        std::string effort = settings.reasoning_effort;
        if (effort.empty()) effort = model.reasoning_effort_param;
        if (effort.empty()) effort = "medium";
        p.reasoning_effort = effort;
    }

    return p;
}


struct anthropic_reasoning_t
{
    bool enabled = false;
    int32_t budget_tokens = 0;
};

struct openai_reasoning_t
{
    std::string effort;
};

struct gemini_reasoning_t
{
    std::string thinking_level;
    bool include_thoughts = true;
    int32_t thinking_budget = 0;
};


inline anthropic_reasoning_t get_anthropic_reasoning(const resolved_params_t& params)
{
    anthropic_reasoning_t r;
    if (params.reasoning_mode == reasoning_mode_t::budget && params.reasoning_budget.has_value()) {
        r.enabled = true;
        r.budget_tokens = params.reasoning_budget.value();
    }
    return r;
}

inline openai_reasoning_t get_openai_reasoning(const resolved_params_t& params)
{
    openai_reasoning_t r;
    if (params.reasoning_mode == reasoning_mode_t::effort && params.reasoning_effort.has_value()) {
        r.effort = params.reasoning_effort.value();
        if (r.effort == "xhigh") r.effort = "high";
        if (r.effort == "minimal") r.effort = "low";
    }
    return r;
}

inline gemini_reasoning_t get_gemini_reasoning(const resolved_params_t& params)
{
    gemini_reasoning_t r;
    if (params.reasoning_mode == reasoning_mode_t::budget && params.reasoning_budget.has_value()) {
        r.include_thoughts = true;
        r.thinking_budget = params.reasoning_budget.value();
    }
    return r;
}


}
