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


}
