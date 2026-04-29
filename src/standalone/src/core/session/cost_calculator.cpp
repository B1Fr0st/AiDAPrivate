#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "cost_calculator.hpp"

#include <vector>

#include "session_store.hpp"


namespace cost_calc {


bool persist_step_finish(const std::string& session_id,
                         const std::string& message_id,
                         const aida::provider::model_info_t& model,
                         const aida::session::usage_tokens_t& usage,
                         const std::string& finish_reason)
{
	if (session_id.empty()) return false;
	if (message_id.empty()) return false;

	std::vector<aida::session::message_t> messages;
	if (!aida::session::list_messages(session_id, messages, -1)) return false;

	aida::session::message_t* target = nullptr;
	for (auto& m : messages) {
		if (m.id == message_id) {
			target = &m;
			break;
		}
	}
	if (target == nullptr) return false;

	const turn_cost_t tc = compute_turn_cost(model, usage);

	for (auto it = target->parts.begin(); it != target->parts.end(); ) {
		if (it->kind == aida::session::part_t::kind_t::step_finish) {
			it = target->parts.erase(it);
		} else {
			++it;
		}
	}

	aida::session::part_t step;
	step.kind = aida::session::part_t::kind_t::step_finish;
	step.step_finish.cost_usd       = tc.total_cost;
	step.step_finish.tokens         = usage;
	step.step_finish.finish_reason  = finish_reason;
	target->parts.push_back(std::move(step));

	if (!aida::session::update_message(*target)) return false;
	return true;
}


bool aggregate_subagent_cost(const std::string& parent_session_id,
                             const std::string& parent_message_id,
                             const std::string& child_session_id)
{
	if (parent_session_id.empty()) return false;
	if (child_session_id.empty()) return false;

	double child_cost = 0.0;
	aida::session::usage_tokens_t child_usage;
	{
		std::vector<aida::session::message_t> child_msgs;
		if (!aida::session::list_messages(child_session_id, child_msgs, -1)) return false;
		for (const auto& m : child_msgs) {
			for (const auto& p : m.parts) {
				if (p.kind != aida::session::part_t::kind_t::step_finish) continue;
				child_cost          += p.step_finish.cost_usd;
				child_usage.input       += p.step_finish.tokens.input;
				child_usage.output      += p.step_finish.tokens.output;
				child_usage.reasoning   += p.step_finish.tokens.reasoning;
				child_usage.cache_read  += p.step_finish.tokens.cache_read;
				child_usage.cache_write += p.step_finish.tokens.cache_write;
			}
		}
	}

	if (child_cost <= 0.0 &&
	    child_usage.input == 0 && child_usage.output == 0 &&
	    child_usage.reasoning == 0 &&
	    child_usage.cache_read == 0 && child_usage.cache_write == 0) {
		return true;
	}

	{
		aida::session::session_info_t parent_info;
		if (!aida::session::get(parent_session_id, parent_info)) return false;
		parent_info.total_cost_usd += child_cost;
		if (!aida::session::update(parent_info)) return false;
	}

	if (parent_message_id.empty()) return true;

	std::vector<aida::session::message_t> parent_msgs;
	if (!aida::session::list_messages(parent_session_id, parent_msgs, -1)) return false;

	aida::session::message_t* target = nullptr;
	for (auto& m : parent_msgs) {
		if (m.id == parent_message_id) {
			target = &m;
			break;
		}
	}
	if (target == nullptr) return true;

	aida::session::part_t* step = nullptr;
	for (auto& p : target->parts) {
		if (p.kind == aida::session::part_t::kind_t::step_finish) {
			step = &p;
			break;
		}
	}
	if (step == nullptr) {
		aida::session::part_t added;
		added.kind = aida::session::part_t::kind_t::step_finish;
		added.step_finish.cost_usd       = child_cost;
		added.step_finish.tokens         = child_usage;
		added.step_finish.finish_reason  = "subagent";
		target->parts.push_back(std::move(added));
	} else {
		step->step_finish.cost_usd          += child_cost;
		step->step_finish.tokens.input      += child_usage.input;
		step->step_finish.tokens.output     += child_usage.output;
		step->step_finish.tokens.reasoning  += child_usage.reasoning;
		step->step_finish.tokens.cache_read += child_usage.cache_read;
		step->step_finish.tokens.cache_write+= child_usage.cache_write;
	}

	(void)aida::session::update_message(*target);
	return true;
}


}
