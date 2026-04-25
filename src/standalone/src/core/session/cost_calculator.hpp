#pragma once

#include <string>
#include <cstdint>
#include <optional>
#include <algorithm>

#include "standalone_context.hpp"
#include "provider_catalog.hpp"
#include "session_store.hpp"


namespace cost_calc {


inline context_mgmt::model_info_t model_info_from_catalog(const aida::provider::model_info_t& m)
{
    context_mgmt::model_info_t out;
    out.context_window     = m.limit.context > 0 ? static_cast<int>(m.limit.context) : 128000;
    out.supports_tools     = m.capabilities.tool_call;
    out.supports_reasoning = m.capabilities.reasoning;
    out.supports_caching   = (m.cost.cache_read_per_million > 0.0) || (m.cost.cache_write_per_million > 0.0);
    out.supports_images    = m.capabilities.attachment;
    out.input_price        = m.cost.input_per_million;
    out.output_price       = m.cost.output_per_million;
    out.cache_read_price   = m.cost.cache_read_per_million;
    out.cache_write_price  = m.cost.cache_write_per_million;
    out.openai_compatible  = (m.api.npm == "@ai-sdk/openai" || m.api.npm == "@ai-sdk/openai-compatible");
    return out;
}


inline context_mgmt::model_info_t resolve_model_info(const std::string& provider_id, const std::string& model_id)
{
    const auto* m = aida::provider::catalog::get_model(provider_id, model_id);
    if (m)
        return model_info_from_catalog(*m);
    return context_mgmt::get_model_info(model_id);
}


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


struct turn_cost_t
{
    double input_cost       = 0.0;
    double output_cost      = 0.0;
    double cache_read_cost  = 0.0;
    double cache_write_cost = 0.0;
    double total_cost       = 0.0;
};


inline turn_cost_t compute_turn_cost(const aida::provider::model_info_t& model,
                                      const aida::session::usage_tokens_t& usage)
{
    turn_cost_t r;
    const double per = 1'000'000.0;
    r.input_cost       = (model.cost.input_per_million       / per) * static_cast<double>(usage.input);
    r.output_cost      = (model.cost.output_per_million      / per) * static_cast<double>(usage.output);
    r.cache_read_cost  = (model.cost.cache_read_per_million  / per) * static_cast<double>(usage.cache_read);
    r.cache_write_cost = (model.cost.cache_write_per_million / per) * static_cast<double>(usage.cache_write);
    r.total_cost       = r.input_cost + r.output_cost + r.cache_read_cost + r.cache_write_cost;
    return r;
}


bool persist_step_finish(const std::string& session_id,
                         const std::string& message_id,
                         const aida::provider::model_info_t& model,
                         const aida::session::usage_tokens_t& usage,
                         const std::string& finish_reason);


}
