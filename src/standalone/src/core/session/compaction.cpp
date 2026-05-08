#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "compaction.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "session_store.hpp"
#include "standalone_context.hpp"

#include "../helpers/diag_log.hpp"


namespace aida {
namespace compaction {

	namespace {

		std::mutex&  error_mutex() { static std::mutex m; return m; }
		std::string& error_slot()  { static std::string s; return s; }

		void set_last_error(const std::string& msg)
		{
			std::lock_guard<std::mutex> lk(error_mutex());
			error_slot() = msg;
		}

		int64_t now_unix_ms()
		{
			using namespace std::chrono;
			return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
		}

		std::string make_message_id()
		{
			static std::atomic<uint64_t> counter{0};
			const uint64_t n = counter.fetch_add(1, std::memory_order_relaxed) + 1;
			std::ostringstream oss;
			oss << "compact_" << now_unix_ms() << "_" << n;
			return oss.str();
		}

		int64_t estimate_message_tokens(const aida::session::message_t& m)
		{
			int64_t total = 0;
			for (const auto& p : m.parts) {
				switch (p.kind) {
					case aida::session::part_t::kind_t::text:
						total += context_mgmt::estimate_token_count(p.text.text);
						break;
					case aida::session::part_t::kind_t::tool: {
						total += context_mgmt::estimate_token_count(p.tool.tool_name);
						const std::string args = p.tool.arguments.is_null()
							? std::string()
							: p.tool.arguments.dump();
						total += context_mgmt::estimate_token_count(args);
						total += context_mgmt::estimate_token_count(p.tool.output_text);
						total += context_mgmt::estimate_token_count(p.tool.error_message);
						break;
					}
					case aida::session::part_t::kind_t::compaction:
						total += context_mgmt::estimate_token_count(p.compaction.summary_text);
						break;
					case aida::session::part_t::kind_t::reasoning:
						total += context_mgmt::estimate_token_count(p.reasoning.text);
						break;
					case aida::session::part_t::kind_t::step_finish:
						break;
					case aida::session::part_t::kind_t::file:
						total += context_mgmt::estimate_token_count(p.file.mime);
						total += context_mgmt::estimate_token_count(p.file.filename);
						total += context_mgmt::estimate_token_count(p.file.url);
						break;
					case aida::session::part_t::kind_t::step_start:
						break;
				}
			}
			return total;
		}

		std::string role_label(aida::session::message_t::role_t r)
		{
			switch (r) {
				case aida::session::message_t::role_t::assistant:   return "Assistant";
				case aida::session::message_t::role_t::tool_result: return "Tool";
				case aida::session::message_t::role_t::user:
				default:                                            return "User";
			}
		}

		std::string render_message_block(const aida::session::message_t& m)
		{
			std::string out;
			out.reserve(256);
			out += role_label(m.role);
			out += ":\n";
			for (const auto& p : m.parts) {
				switch (p.kind) {
					case aida::session::part_t::kind_t::text:
						if (!p.text.text.empty()) {
							out += p.text.text;
							out += '\n';
						}
						break;
					case aida::session::part_t::kind_t::tool: {
						out += "[tool ";
						out += p.tool.tool_name;
						out += "] ";
						if (!p.tool.arguments.is_null()) {
							out += p.tool.arguments.dump();
							out += '\n';
						}
						if (!p.tool.output_text.empty()) {
							out += "[output] ";
							out += p.tool.output_text;
							out += '\n';
						}
						if (!p.tool.error_message.empty()) {
							out += "[error] ";
							out += p.tool.error_message;
							out += '\n';
						}
						break;
					}
					case aida::session::part_t::kind_t::compaction:
						if (!p.compaction.summary_text.empty()) {
							out += "[previous-summary]\n";
							out += p.compaction.summary_text;
							out += '\n';
						}
						break;
					case aida::session::part_t::kind_t::reasoning:
						if (!p.reasoning.text.empty()) {
							out += "[reasoning] ";
							out += p.reasoning.text;
							out += '\n';
						}
						break;
					case aida::session::part_t::kind_t::step_finish:
						break;
					case aida::session::part_t::kind_t::file:
						if (!p.file.filename.empty() || !p.file.mime.empty()) {
							out += "[file ";
							out += p.file.mime;
							if (!p.file.filename.empty()) {
								out += ' ';
								out += p.file.filename;
							}
							out += "]\n";
						}
						break;
					case aida::session::part_t::kind_t::step_start:
						break;
				}
			}
			out += '\n';
			return out;
		}

		const char* SUMMARY_TEMPLATE =
			"Output exactly this Markdown structure and keep the section order unchanged:\n"
			"---\n"
			"## Goal\n"
			"- [single-sentence task summary]\n\n"
			"## Constraints & Preferences\n"
			"- [user constraints, preferences, specs, or \"(none)\"]\n\n"
			"## Progress\n"
			"### Done\n"
			"- [completed work or \"(none)\"]\n\n"
			"### In Progress\n"
			"- [current work or \"(none)\"]\n\n"
			"### Blocked\n"
			"- [blockers or \"(none)\"]\n\n"
			"## Key Decisions\n"
			"- [decision and why, or \"(none)\"]\n\n"
			"## Next Steps\n"
			"- [ordered next actions or \"(none)\"]\n\n"
			"## Critical Context\n"
			"- [important technical facts, errors, open questions, or \"(none)\"]\n\n"
			"## Relevant Files\n"
			"- [file or directory path: why it matters, or \"(none)\"]\n"
			"---\n\n"
			"Rules:\n"
			"- Keep every section, even when empty.\n"
			"- Use terse bullets, not prose paragraphs.\n"
			"- Preserve exact file paths, commands, error strings, and identifiers when known.\n"
			"- Do not mention the summary process or that context was compacted.";

		std::string build_compaction_prompt(const std::string& history_blob,
		                                    const std::string& previous_summary)
		{
			std::string out;
			out.reserve(history_blob.size() + 2048);
			out += "<conversation-history>\n";
			out += history_blob;
			out += "</conversation-history>\n\n";
			if (!previous_summary.empty()) {
				out += "Update the anchored summary below using the conversation history above.\n";
				out += "Preserve still-true details, remove stale details, and merge in the new facts.\n";
				out += "<previous-summary>\n";
				out += previous_summary;
				out += "\n</previous-summary>\n\n";
			} else {
				out += "Create a new anchored summary from the conversation history above.\n\n";
			}
			out += SUMMARY_TEMPLATE;
			return out;
		}

		bool find_previous_summary(const std::vector<aida::session::message_t>& messages,
		                            std::string& out_summary)
		{
			for (auto it = messages.rbegin(); it != messages.rend(); ++it) {
				for (const auto& p : it->parts) {
					if (p.kind == aida::session::part_t::kind_t::compaction
						&& !p.compaction.summary_text.empty()) {
						out_summary = p.compaction.summary_text;
						return true;
					}
				}
			}
			out_summary.clear();
			return false;
		}

		size_t pick_cut_point(const std::vector<aida::session::message_t>& messages,
		                       const compaction_options_t& opts)
		{
			if (messages.empty()) return 0;

			const int recent_msgs = opts.preserve_recent_messages > 0 ? opts.preserve_recent_messages : 0;
			const int token_budget = opts.preserve_recent_tokens > 0 ? opts.preserve_recent_tokens : 0;

			size_t cut = messages.size();
			if (recent_msgs > 0) {
				if (static_cast<size_t>(recent_msgs) >= messages.size()) {
					cut = 0;
				} else {
					cut = messages.size() - static_cast<size_t>(recent_msgs);
				}
			}

			if (token_budget > 0 && cut > 0) {
				int64_t accumulated = 0;
				size_t i = messages.size();
				while (i > 0) {
					--i;
					accumulated += estimate_message_tokens(messages[i]);
					if (accumulated > token_budget) {
						i = (std::min<size_t>)(i + 1, messages.size());
						break;
					}
					if (i == 0) break;
				}
				if (i < cut) cut = i;
			}

			return cut;
		}

		std::string build_history_blob(const std::vector<aida::session::message_t>& head)
		{
			std::string blob;
			blob.reserve(head.size() * 256);
			for (const auto& m : head) {
				blob += render_message_block(m);
			}
			return blob;
		}

		bool message_is_compaction(const aida::session::message_t& m)
		{
			for (const auto& p : m.parts) {
				if (p.kind == aida::session::part_t::kind_t::compaction) return true;
			}
			return false;
		}

		bool set_compacting_marker(const std::string& session_id, int64_t value, std::string& err)
		{
			aida::session::session_info_t info;
			if (!aida::session::get(session_id, info)) {
				err = aida::session::last_error();
				return false;
			}
			info.time_compacting_unix = value;
			info.time_updated_unix = now_unix_ms();
			if (!aida::session::update(info)) {
				err = aida::session::last_error();
				return false;
			}
			return true;
		}

		std::string trim_copy(const std::string& s)
		{
			size_t start = 0;
			size_t end = s.size();
			while (start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n'))
				++start;
			while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' || s[end - 1] == '\r' || s[end - 1] == '\n'))
				--end;
			return s.substr(start, end - start);
		}

		void warn_missing_sections(const std::string& summary, const std::string& session_id)
		{
			static const char* kSections[] = {
				"## Goal",
				"## Constraints",
				"## Progress",
				"## Key Decisions",
				"## Next Steps",
				"## Critical Context",
				"## Relevant Files",
			};
			for (const char* sec : kSections) {
				if (summary.find(sec) == std::string::npos) {
					std::string line = std::string("summary missing section '") + sec
						+ "' session=" + session_id;
					diag::log_tagged("compaction", line.c_str());
				}
			}
		}

	}


	const std::string& last_error()
	{
		std::lock_guard<std::mutex> lk(error_mutex());
		return error_slot();
	}


	bool should_trigger(const std::string& session_id,
	                    int64_t used_tokens,
	                    int64_t context_limit,
	                    const compaction_options_t& opts)
	{
		if (session_id.empty()) return false;
		if (context_limit <= 0) return false;
		if (used_tokens <= 0) return false;

		const double ratio = opts.trigger_ratio > 0.0 ? opts.trigger_ratio : 0.85;
		const double threshold = static_cast<double>(context_limit) * ratio;
		if (static_cast<double>(used_tokens) <= threshold) return false;

		aida::session::session_info_t info;
		if (!aida::session::get(session_id, info)) return false;
		if (info.time_compacting_unix != 0) return false;

		return true;
	}


	bool truncate_tool_outputs(std::vector<aida::session::message_t>& messages,
	                           int max_chars)
	{
		if (max_chars <= 0) return true;
		const size_t cap = static_cast<size_t>(max_chars);
		bool any = false;
		for (auto& m : messages) {
			for (auto& p : m.parts) {
				if (p.kind != aida::session::part_t::kind_t::tool) continue;
				if (p.tool.output_text.size() <= cap) continue;
				const size_t dropped = p.tool.output_text.size() - cap;
				p.tool.output_text = p.tool.output_text.substr(0, cap)
					+ "\n... [truncated " + std::to_string(dropped) + " chars]";
				any = true;
			}
		}
		(void)any;
		return true;
	}


	std::vector<aida::session::message_t> filter_compacted(
		const std::vector<aida::session::message_t>& messages)
	{
		std::vector<aida::session::message_t> result;
		if (messages.empty()) return result;

		for (auto it = messages.rbegin(); it != messages.rend(); ++it) {
			result.push_back(*it);
			if (message_is_compaction(*it)) break;
		}

		std::reverse(result.begin(), result.end());
		return result;
	}


	bool run(const std::string& session_id,
	         const compaction_options_t& opts,
	         compaction_result_t& out)
	{
		out = compaction_result_t{};

		if (session_id.empty()) {
			set_last_error("compaction.run: empty session_id");
			out.error = "empty session_id";
			return false;
		}

		std::string err_buf;
		if (!set_compacting_marker(session_id, now_unix_ms(), err_buf)) {
			set_last_error("compaction.run: " + err_buf);
			out.error = err_buf;
			return false;
		}

		struct marker_guard_t
		{
			std::string session_id;
			bool        active = true;
			~marker_guard_t()
			{
				if (active) {
					std::string e;
					(void)set_compacting_marker(session_id, 0, e);
				}
			}
		} guard{session_id, true};

		std::vector<aida::session::message_t> messages;
		if (!aida::session::list_messages(session_id, messages, -1)) {
			const std::string em = aida::session::last_error();
			set_last_error("compaction.run: list_messages: " + em);
			out.error = em;
			return false;
		}

		if (messages.size() <= 1) {
			set_last_error("compaction.run: not enough messages");
			out.error = "not enough messages";
			return false;
		}

		const size_t cut = pick_cut_point(messages, opts);
		if (cut == 0) {
			set_last_error("compaction.run: cut at zero, nothing to compact");
			out.error = "cut at zero";
			return false;
		}
		if (cut >= messages.size()) {
			set_last_error("compaction.run: cut at end, no tail");
			out.error = "cut at end";
			return false;
		}

		std::string tail_id = messages[cut].id;

		std::vector<aida::session::message_t> head(messages.begin(), messages.begin() + cut);
		(void)truncate_tool_outputs(head, opts.truncate_tool_output_chars);

		int64_t head_tokens = 0;
		for (const auto& m : head) head_tokens += estimate_message_tokens(m);

		std::string previous_summary;
		(void)find_previous_summary(messages, previous_summary);

		std::string history_blob = build_history_blob(head);
		std::string prompt = build_compaction_prompt(history_blob, previous_summary);

		std::string provider_id;
		std::string model_id;
		for (auto it = messages.rbegin(); it != messages.rend(); ++it) {
			if (it->role == aida::session::message_t::role_t::assistant
				&& !it->model_provider_id.empty()) {
				provider_id = it->model_provider_id;
				model_id    = it->model_id;
				break;
			}
		}

		std::string agent_name = "compaction";
		if (!provider_id.empty()) {
			const aida::agent::agent_info_t* sm_agent =
				aida::agent::small_compaction_agent_for(provider_id);
			if (sm_agent != nullptr) agent_name = sm_agent->name;
		}

		std::string summary_text;
		const bool ok = aida::agent::task::execute(agent_name, prompt, 1, session_id, summary_text);
		if (!ok) {
			const std::string em = aida::agent::task::last_error();
			set_last_error("compaction.run: agent failed: " + em);
			out.error = em;
			return false;
		}

		summary_text = trim_copy(summary_text);
		if (summary_text.empty()) {
			set_last_error("compaction.run: empty summary");
			out.error = "empty summary";
			return false;
		}
		warn_missing_sections(summary_text, session_id);

		aida::session::message_t compaction_msg;
		compaction_msg.id                = make_message_id();
		compaction_msg.session_id        = session_id;
		compaction_msg.role              = aida::session::message_t::role_t::user;
		compaction_msg.agent             = "compaction";
		compaction_msg.model_provider_id = provider_id;
		compaction_msg.model_id          = model_id;
		compaction_msg.created_unix      = messages[cut].created_unix > 0
			? messages[cut].created_unix - 1
			: now_unix_ms();

		aida::session::part_t cpart;
		cpart.kind = aida::session::part_t::kind_t::compaction;
		cpart.compaction.summary_text          = summary_text;
		cpart.compaction.auto_triggered        = true;
		cpart.compaction.overflow              = false;
		cpart.compaction.tail_start_message_id = tail_id;
		compaction_msg.parts.push_back(std::move(cpart));

		if (!aida::session::append_message(compaction_msg)) {
			const std::string em = aida::session::last_error();
			set_last_error("compaction.run: append compaction failed: " + em);
			out.error = em;
			return false;
		}

		guard.active = false;
		std::string clear_err;
		if (!set_compacting_marker(session_id, 0, clear_err)) {
			std::string line = std::string("failed to clear compacting marker: ") + clear_err;
			diag::log_tagged("compaction", line.c_str());
		}

		out.ran                   = true;
		out.messages_summarized   = static_cast<int>(cut);
		out.tokens_freed          = static_cast<int>(head_tokens);
		out.summary_text          = summary_text;
		out.compaction_message_id = compaction_msg.id;
		out.tail_start_message_id = tail_id;

		aida::events::session_compacted_t evt;
		evt.session_id          = session_id;
		evt.messages_summarized = out.messages_summarized;
		evt.tokens_freed        = out.tokens_freed;
		aida::events::publish(aida::events::event_session_compacted, evt);

		return true;
	}


	bool maybe_auto_title(const std::string& session_id,
	                      const std::string& first_user_message,
	                      const std::string& provider_id)
	{
		if (session_id.empty()) {
			set_last_error("maybe_auto_title: empty session_id");
			return false;
		}
		if (first_user_message.empty()) {
			set_last_error("maybe_auto_title: empty first_user_message");
			return false;
		}

		static std::atomic<bool> s_title_in_flight{false};
		bool expected = false;
		if (!s_title_in_flight.compare_exchange_strong(
				expected, true,
				std::memory_order_acq_rel,
				std::memory_order_acquire)) {
			set_last_error("maybe_auto_title: already running");
			return false;
		}
		struct release_guard_t
		{
			std::atomic<bool>* flag;
			~release_guard_t() { if (flag) flag->store(false, std::memory_order_release); }
		} release_guard{&s_title_in_flight};

		aida::session::session_info_t info;
		if (!aida::session::get(session_id, info)) {
			set_last_error("maybe_auto_title: session not found");
			return false;
		}

		const bool needs_title = info.title.empty()
			|| info.title.rfind("untitled", 0) == 0
			|| info.title.rfind("(fork)", 0) == 0
			|| info.title.rfind("[task] ", 0) == 0;
		if (!needs_title) return true;

		(void)provider_id;

		std::string raw_title;
		const bool ok = aida::agent::task::execute("title", first_user_message, 1, session_id, raw_title);
		if (!ok) {
			set_last_error("maybe_auto_title: " + aida::agent::task::last_error());
			return false;
		}

		std::string trimmed = trim_copy(raw_title);
		if (!trimmed.empty()) {
			char first = trimmed.front();
			if (first == '"' || first == '\'') {
				trimmed.erase(0, 1);
			}
		}
		if (!trimmed.empty()) {
			char last = trimmed.back();
			if (last == '"' || last == '\'' || last == '.') {
				trimmed.pop_back();
			}
		}
		trimmed = trim_copy(trimmed);

		size_t newline = trimmed.find('\n');
		if (newline != std::string::npos) trimmed = trimmed.substr(0, newline);
		trimmed = trim_copy(trimmed);

		if (trimmed.size() > 60) trimmed = trimmed.substr(0, 60);

		if (trimmed.empty()) {
			set_last_error("maybe_auto_title: agent returned empty title");
			return false;
		}

		if (!aida::session::set_title(session_id, trimmed)) {
			set_last_error("maybe_auto_title: set_title: " + aida::session::last_error());
			return false;
		}
		return true;
	}


}
}
