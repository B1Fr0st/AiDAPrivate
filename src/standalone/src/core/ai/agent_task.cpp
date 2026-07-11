#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "agent_registry.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "standalone_ai_client.hpp"
#include "standalone_settings.hpp"
#include "session_store.hpp"
#include "binary_map.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "standalone_chat.hpp"
#include "mcp_standalone.hpp"
#include "cost_calculator.hpp"
#include "provider_catalog.hpp"
#include "../infra/executor.hpp"

#include "../helpers/diag_log.hpp"

namespace aida {
namespace agent {
namespace task {

	namespace {

		std::mutex&  task_error_mutex() { static std::mutex m; return m; }
		std::string& task_error_slot() { static std::string s; return s; }

		void set_task_error(const std::string& msg)
		{
			std::lock_guard<std::mutex> lk(task_error_mutex());
			task_error_slot() = msg;
		}

		std::string make_id()
		{
			static std::atomic<uint64_t> counter{0};
			uint64_t n = counter.fetch_add(1) + 1;
			auto now = std::chrono::system_clock::now().time_since_epoch();
			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
			std::ostringstream oss;
			oss << "task_" << ms << "_" << n;
			return oss.str();
		}

		int64_t unix_now()
		{
			return std::chrono::duration_cast<std::chrono::seconds>(
				std::chrono::system_clock::now().time_since_epoch()).count();
		}

		std::vector<mcp_standalone::tool_def_t> filter_tools(
			const agent_info_t& agent,
			const std::vector<mcp_standalone::tool_def_t>& all)
		{
			std::vector<mcp_standalone::tool_def_t> out;
			out.reserve(all.size());
			for (const auto& t : all) {
				if (!aida::agent::tool_allowed(agent, t.name)) continue;
				out.push_back(t);
			}
			return out;
		}

		std::string find_latest_assistant_message_id(const std::string& session_id)
		{
			if (session_id.empty()) return std::string{};
			std::vector<aida::session::message_t> msgs;
			if (!aida::session::list_messages(session_id, msgs, -1)) return std::string{};
			std::string latest_id;
			int64_t latest_unix = 0;
			for (const auto& m : msgs) {
				if (m.role != aida::session::message_t::role_t::assistant) continue;
				if (latest_id.empty() || m.created_unix >= latest_unix) {
					latest_id = m.id;
					latest_unix = m.created_unix;
				}
			}
			return latest_id;
		}

	}

	const std::string& last_error()
	{
		std::lock_guard<std::mutex> lk(task_error_mutex());
		return task_error_slot();
	}

	bool execute(const std::string& agent_name,
	             const std::string& prompt_text,
	             int max_steps,
	             const std::string& parent_session_id,
	             std::string& out_result,
	             std::atomic<bool>* cancel_flag)
	{
		out_result.clear();

		const aida::agent::agent_info_t* agent_info = aida::agent::get(agent_name);
		if (agent_info == nullptr) {
			set_task_error("agent not found: " + agent_name);
			out_result = "Error: agent '" + agent_name + "' not found.";
			return false;
		}

		aida::agent::agent_info_t agent = *agent_info;

		std::atomic<bool> done{false};
		std::string thread_result;
		std::string thread_error;
		std::string sub_session_id;
		bool         aborted = false;
		std::atomic<standalone_ai_client_t*> active_client_ptr{nullptr};

		auto is_cancelled = [cancel_flag]() -> bool {
			return cancel_flag != nullptr &&
			       cancel_flag->load(std::memory_order_acquire);
		};

		auto ws = aida::analysis::workspace_registry().selected_for_ui();

		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "ai_agent_task";
		sub.label = "agent_task.execute";
		sub.thread_class = "bounded_task";
		sub.domain = aida::infra::executor::domain_t::external_tool;
		sub.priority = 3;
		sub.body = [&, ws]() {
			std::unique_ptr<standalone_ai_client_t> local_client;
			try {
				local_client = std::make_unique<standalone_ai_client_t>(g_sa_settings);
			} catch (const std::exception& ex) {
				thread_error = std::string("Failed to construct subagent AI client: ") + ex.what();
				thread_result = "Error: " + thread_error;
				done.store(true, std::memory_order_release);
				return;
			} catch (...) {
				thread_error = "Failed to construct subagent AI client: unknown exception";
				thread_result = "Error: " + thread_error;
				done.store(true, std::memory_order_release);
				return;
			}

			active_client_ptr.store(local_client.get(), std::memory_order_release);

			if (!local_client || !local_client->is_available()) {
				thread_error = "subagent AI client is not available";
				thread_result = "Error: " + thread_error;
				done.store(true, std::memory_order_release);
				return;
			}

			try {
				aida::session::session_info_t sub_session;
				if (!parent_session_id.empty()) {
					(void)aida::session::create(sub_session, std::string{}, std::string{}, parent_session_id);
				} else {
					(void)aida::session::create(sub_session, std::string{}, std::string{}, std::string{});
				}
				if (!sub_session.id.empty()) {
					std::string preview = prompt_text.substr(0, 60);
					if (prompt_text.size() > 60) preview += "...";
					(void)aida::session::set_title(sub_session.id, std::string("[task] ") + preview);
					sub_session_id = sub_session.id;
				}

				std::string system_prompt = agent.system_prompt;
				{
					std::string injected = ws ? aida::binary_map::auto_inject_text(ws, 4096) : std::string{};
					if (!injected.empty()) {
						system_prompt += "\n\n# Binary Map (auto-generated)\n";
						system_prompt += injected;
					}
				}

				if (!sub_session.id.empty()) {
					aida::session::message_t user_msg;
					user_msg.id = make_id();
					user_msg.session_id = sub_session.id;
					user_msg.role = aida::session::message_t::role_t::user;
					user_msg.agent = agent.name;
					aida::session::part_t pt;
					pt.kind = aida::session::part_t::kind_t::text;
					pt.text.text = prompt_text;
					user_msg.parts.push_back(pt);
					user_msg.created_unix = unix_now();
					(void)aida::session::append_message(user_msg);
				}

				auto local_tools_all = snapshot_local_tools();
				auto allowed_tools = filter_tools(agent, local_tools_all);

				nlohmann::json messages = nlohmann::json::array();
				messages.push_back({{"role", "user"}, {"content", prompt_text}});

				int hard_steps = max_steps > 0 ? max_steps : (agent.max_steps > 0 ? agent.max_steps : 16);
				if (hard_steps > 64) hard_steps = 64;

				std::string final_text;
				for (int turn = 0; turn < hard_steps; ++turn) {
					if (is_cancelled()) {
						aborted = true;
						break;
					}
					ai_generation_result_t gen;
					try {
						gen = local_client->generate_with_tools(messages, system_prompt, allowed_tools, nullptr);
					} catch (const std::exception& ex) {
						thread_error = std::string("Exception: ") + ex.what();
						break;
					} catch (...) {
						thread_error = "Unknown exception in subagent loop.";
						break;
					}

					if (is_cancelled()) {
						aborted = true;
						break;
					}

					if (gen.is_error) {
						thread_error = gen.text;
						break;
					}

					std::string assistant_message_id;
					if (!sub_session.id.empty() && (!gen.text.empty() || !gen.tool_calls.empty())) {
						aida::session::message_t am;
						am.id = make_id();
						am.session_id = sub_session.id;
						am.role = aida::session::message_t::role_t::assistant;
						am.agent = agent.name;
						if (agent.model_override.has_value()) {
							am.model_provider_id = agent.model_override->provider_id;
							am.model_id = agent.model_override->model_id;
						}
						if (!gen.text.empty()) {
							aida::session::part_t pt;
							pt.kind = aida::session::part_t::kind_t::text;
							pt.text.text = gen.text;
							am.parts.push_back(pt);
						}
						for (const auto& tc : gen.tool_calls) {
							aida::session::part_t pt;
							pt.kind = aida::session::part_t::kind_t::tool;
							pt.tool.call_id = tc.id;
							pt.tool.tool_name = tc.name;
							pt.tool.state = aida::session::part_tool_t::state_t::pending;
							pt.tool.arguments = tc.arguments;
							pt.tool.time_start_unix = unix_now();
							am.parts.push_back(pt);
						}
						am.created_unix = unix_now();
						(void)aida::session::append_message(am);
						assistant_message_id = am.id;
					}

					if (!assistant_message_id.empty() &&
					    (gen.input_tokens > 0 || gen.output_tokens > 0 ||
					     gen.cache_read > 0 || gen.cache_write > 0)) {
						aida::session::usage_tokens_t usage;
						usage.input       = gen.input_tokens;
						usage.output      = gen.output_tokens;
						usage.cache_read  = gen.cache_read;
						usage.cache_write = gen.cache_write;

						std::string provider_id = agent.model_override.has_value()
							? agent.model_override->provider_id : std::string{};
						std::string model_id = agent.model_override.has_value()
							? agent.model_override->model_id : std::string{};
						const aida::provider::model_info_t* mi = nullptr;
						if (!provider_id.empty() && !model_id.empty())
							mi = aida::provider::catalog::get_model(provider_id, model_id);
						if (mi != nullptr) {
							(void)cost_calc::persist_step_finish(sub_session.id, assistant_message_id,
								*mi, usage, gen.stop_reason.empty() ? std::string("stop") : gen.stop_reason);
						}
					}

					if (gen.tool_calls.empty()) {
						final_text = gen.text;
						break;
					}

					nlohmann::json assistant_content = nlohmann::json::array();
					if (!gen.text.empty())
						assistant_content.push_back({{"type", "text"}, {"text", gen.text}});
					for (const auto& tc : gen.tool_calls) {
						assistant_content.push_back({
							{"type", "tool_use"},
							{"id", tc.id},
							{"name", tc.name},
							{"input", tc.arguments}
						});
					}
					messages.push_back({{"role", "assistant"}, {"content", assistant_content}});

					nlohmann::json tool_result_content = nlohmann::json::array();
					for (const auto& tc : gen.tool_calls) {
						if (is_cancelled()) {
							aborted = true;
							break;
						}
						std::string r;
						bool tool_is_error = false;
						if (!aida::agent::tool_allowed(agent, tc.name)) {
							r = std::string("Error: subagent '") + agent.name +
							     "' is not permitted to call tool '" + tc.name + "'.";
							tool_is_error = true;
						} else {
							try {
								r = execute_local_tool(tc.name, tc.arguments);
							} catch (const std::exception& ex) {
								r = std::string("Error: ") + ex.what();
								tool_is_error = true;
							} catch (...) {
								r = "Error: tool execution threw unknown exception.";
								tool_is_error = true;
							}
							if (r.size() >= 6 && r.compare(0, 6, "Error:") == 0)
								tool_is_error = true;
						}
						tool_result_content.push_back(
							standalone_ai_client_t::make_tool_result_block(tc.id, r, tool_is_error));
					}
					if (aborted) break;
					messages.push_back({{"role", "user"}, {"content", tool_result_content}});
				}

				if (aborted) {
					thread_result = std::string("(subagent ") + agent.name +
					                 " aborted: cancellation requested)";
					if (final_text.empty()) {
						thread_result += "\naborted: true";
					}
				} else if (!thread_error.empty()) {
					thread_result = std::string("Error: ") + thread_error;
				} else {
					thread_result = final_text.empty()
						? std::string("(subagent ") + agent.name + " produced no final text)"
						: final_text;
				}
			} catch (const std::exception& ex) {
				thread_error = std::string("Exception in subagent thread: ") + ex.what();
				thread_result = "Error: " + thread_error;
			} catch (...) {
				thread_error = "Unknown exception in subagent thread";
				thread_result = "Error: " + thread_error;
			}
			active_client_ptr.store(nullptr, std::memory_order_release);
			done.store(true, std::memory_order_release);
		};
		const bool posted = aida::infra::executor::submit(std::move(sub)).submitted;
		if (!posted) {
			thread_error = "failed to schedule subagent AI worker";
			thread_result = "Error: " + thread_error;
			done.store(true, std::memory_order_release);
		}

		if (cancel_flag != nullptr) {
			bool propagated = false;
			while (!done.load(std::memory_order_acquire)) {
				if (!propagated &&
				    cancel_flag->load(std::memory_order_acquire)) {
					standalone_ai_client_t* cli =
						active_client_ptr.load(std::memory_order_acquire);
					if (cli != nullptr) cli->cancel();
					propagated = true;
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(50));
			}
		} else {
			while (!done.load(std::memory_order_acquire)) {
				std::this_thread::sleep_for(std::chrono::milliseconds(50));
			}
		}

		if (!parent_session_id.empty() && !sub_session_id.empty()) {
			const std::string parent_msg_id = find_latest_assistant_message_id(parent_session_id);
			(void)cost_calc::aggregate_subagent_cost(parent_session_id, parent_msg_id, sub_session_id);
		}

		out_result = thread_result;
		if (aborted) {
			set_task_error("subagent cancelled");
			return false;
		}
		if (!thread_error.empty()) {
			set_task_error(thread_error);
			return false;
		}
		return true;
	}

}
}
}
