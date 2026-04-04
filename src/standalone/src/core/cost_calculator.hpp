#pragma once

#include <string>
#include <cstdint>
#include <optional>
#include <algorithm>

#include "standalone_context.hpp"


namespace cost_calc {


struct cost_result_t
{
    int64_t total_input_tokens  = 0;
    int64_t total_output_tokens = 0;
    double  total_cost          = 0.0;
};


enum class cost_model_t
{
    anthropic,
    openai,
    generic
};


inline cost_model_t get_cost_model(const std::string& provider_kind)
{
    if (provider_kind == "anthropic" || provider_kind == "bedrock" || provider_kind == "vertex")
        return cost_model_t::anthropic;
    if (provider_kind == "openai" || provider_kind == "deepseek" || provider_kind == "xai" ||
        provider_kind == "mistral" || provider_kind == "openai_compatible")
        return cost_model_t::openai;
    return cost_model_t::generic;
}


inline cost_result_t calculate_anthropic(
    const context_mgmt::model_info_t& model,
    int64_t input_tokens,
    int64_t output_tokens,
    int64_t cache_write_tokens = 0,
    int64_t cache_read_tokens = 0)
{
    cost_result_t r;
    r.total_input_tokens  = input_tokens + cache_write_tokens + cache_read_tokens;
    r.total_output_tokens = output_tokens;

    double base_input_cost  = (model.input_price  / 1'000'000.0) * input_tokens;
    double cache_write_cost = (model.cache_write_price / 1'000'000.0) * cache_write_tokens;
    double cache_read_cost  = (model.cache_read_price  / 1'000'000.0) * cache_read_tokens;
    double output_cost      = (model.output_price / 1'000'000.0) * output_tokens;

    r.total_cost = base_input_cost + cache_write_cost + cache_read_cost + output_cost;
    return r;
}


inline cost_result_t calculate_openai(
    const context_mgmt::model_info_t& model,
    int64_t input_tokens,
    int64_t output_tokens,
    int64_t cache_write_tokens = 0,
    int64_t cache_read_tokens = 0)
{
    cost_result_t r;
    r.total_input_tokens  = input_tokens;
    r.total_output_tokens = output_tokens;

    int64_t non_cached = (std::max)(static_cast<int64_t>(0),
                                     input_tokens - cache_write_tokens - cache_read_tokens);

    double base_input_cost  = (model.input_price  / 1'000'000.0) * non_cached;
    double cache_write_cost = (model.cache_write_price / 1'000'000.0) * cache_write_tokens;
    double cache_read_cost  = (model.cache_read_price  / 1'000'000.0) * cache_read_tokens;
    double output_cost      = (model.output_price / 1'000'000.0) * output_tokens;

    r.total_cost = base_input_cost + cache_write_cost + cache_read_cost + output_cost;
    return r;
}


inline cost_result_t calculate_generic(
    const context_mgmt::model_info_t& model,
    int64_t input_tokens,
    int64_t output_tokens)
{
    cost_result_t r;
    r.total_input_tokens  = input_tokens;
    r.total_output_tokens = output_tokens;
    r.total_cost = (model.input_price / 1'000'000.0) * input_tokens
                 + (model.output_price / 1'000'000.0) * output_tokens;
    return r;
}


inline cost_result_t calculate(
    const std::string& provider_kind,
    const context_mgmt::model_info_t& model,
    int64_t input_tokens,
    int64_t output_tokens,
    int64_t cache_write_tokens = 0,
    int64_t cache_read_tokens = 0)
{
    auto cm = get_cost_model(provider_kind);
    switch (cm) {
    case cost_model_t::anthropic:
        return calculate_anthropic(model, input_tokens, output_tokens, cache_write_tokens, cache_read_tokens);
    case cost_model_t::openai:
        return calculate_openai(model, input_tokens, output_tokens, cache_write_tokens, cache_read_tokens);
    default:
        return calculate_generic(model, input_tokens, output_tokens);
    }
}


}
