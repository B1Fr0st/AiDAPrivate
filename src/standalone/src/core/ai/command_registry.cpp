#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "command_registry.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "agent_registry.hpp"
#include "compaction.hpp"
#include "event_bus.hpp"
#include "mcp_client.hpp"
#include "session_store.hpp"
#include "settings_overlay.hpp"
#include "skills.hpp"
#include "standalone_chat.hpp"
#include "standalone_settings.hpp"

#include "../helpers/diag_log.hpp"
#include "../ui/application_view_registry.hpp"
#include "../ui/application_ui_runtime.hpp"


extern mcp_client::manager_t s_mcp_client_mgr;


namespace aida {
namespace commands {

	namespace {


		std::mutex&  registry_mutex()  { static std::mutex m; return m; }
		std::mutex&  error_mutex()     { static std::mutex m; return m; }
		std::string& error_slot()      { static std::string s; return s; }
		bool&        initialized_flag(){ static bool b = false; return b; }


		std::vector<command_t>& commands_vector()
		{
			static std::vector<command_t> v;
			return v;
		}


		aida::events::subscription_handle_t& mcp_sub_handle()
		{
			static aida::events::subscription_handle_t h;
			return h;
		}


		void set_last_error(const std::string& msg)
		{
			std::lock_guard<std::mutex> lk(error_mutex());
			error_slot() = msg;
		}


		std::string to_lower_ascii(const std::string& s)
		{
			std::string out;
			out.reserve(s.size());
			for (char c : s)
				out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
			return out;
		}


		std::string trim_copy(const std::string& s)
		{
			size_t a = 0;
			size_t b = s.size();
			while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
			while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
			return s.substr(a, b - a);
		}


		std::string join_args(const std::vector<std::string>& args)
		{
			std::string out;
			for (size_t i = 0; i < args.size(); ++i) {
				if (i > 0) out.push_back(' ');
				out += args[i];
			}
			return out;
		}


		std::string get_chat_session_id_safe()
		{
			std::string sid = chat_active_session();
			return sid;
		}


		const char* PROMPT_INITIALIZE =
			"Create or update `AGENTS.md` for this repository.\n"
			"\n"
			"The goal is a compact instruction file that helps future AiDA sessions avoid mistakes and ramp up quickly. Every line should answer: \"Would an agent likely miss this without help?\" If not, leave it out.\n"
			"\n"
			"User-provided focus or constraints (honor these):\n"
			"$ARGUMENTS\n"
			"\n"
			"## How to investigate\n"
			"\n"
			"Read the highest-value sources first:\n"
			"- `README*`, root manifests, workspace config, lockfiles\n"
			"- build, test, lint, formatter, typecheck, and codegen config\n"
			"- CI workflows and pre-commit / task runner config\n"
			"- existing instruction files (`AGENTS.md`, `CLAUDE.md`, `.cursor/rules/`, `.cursorrules`, `.github/copilot-instructions.md`)\n"
			"- repo-local AiDA config such as `aida.json`\n"
			"\n"
			"If architecture is still unclear after reading config and docs, inspect a small number of representative code files to find the real entrypoints, package boundaries, and execution flow. Prefer reading the files that explain how the system is wired together over random leaf files.\n"
			"\n"
			"Prefer executable sources of truth over prose. If docs conflict with config or scripts, trust the executable source and only keep what you can verify.\n"
			"\n"
			"## What to extract\n"
			"\n"
			"Look for the highest-signal facts for an agent working in this repo:\n"
			"- exact developer commands, especially non-obvious ones\n"
			"- how to run a single test, a single package, or a focused verification step\n"
			"- required command order when it matters, such as `lint -> typecheck -> test`\n"
			"- monorepo or multi-package boundaries, ownership of major directories, and the real app/library entrypoints\n"
			"- framework or toolchain quirks: generated code, migrations, codegen, build artifacts, special env loading, dev servers, infra deploy flow\n"
			"- repo-specific style or workflow conventions that differ from defaults\n"
			"- testing quirks: fixtures, integration test prerequisites, snapshot workflows, required services, flaky or expensive suites\n"
			"- important constraints from existing instruction files worth preserving\n"
			"\n"
			"Good `AGENTS.md` content is usually hard-earned context that took reading multiple files to infer.\n"
			"\n"
			"## Questions\n"
			"\n"
			"Only ask the user questions if the repo cannot answer something important. Use the `question` tool for one short batch at most.\n"
			"\n"
			"Good questions:\n"
			"- undocumented team conventions\n"
			"- branch / PR / release expectations\n"
			"- missing setup or test prerequisites that are known but not written down\n"
			"\n"
			"Do not ask about anything the repo already makes clear.\n"
			"\n"
			"## Writing rules\n"
			"\n"
			"Include only high-signal, repo-specific guidance such as:\n"
			"- exact commands and shortcuts the agent would otherwise guess wrong\n"
			"- architecture notes that are not obvious from filenames\n"
			"- conventions that differ from language or framework defaults\n"
			"- setup requirements, environment quirks, and operational gotchas\n"
			"- references to existing instruction sources that matter\n"
			"\n"
			"Exclude:\n"
			"- generic software advice\n"
			"- long tutorials or exhaustive file trees\n"
			"- obvious language conventions\n"
			"- speculative claims or anything you could not verify\n"
			"- content better stored in another file referenced via `aida.json` `instructions`\n"
			"\n"
			"When in doubt, omit.\n"
			"\n"
			"Prefer short sections and bullets. If the repo is simple, keep the file simple. If the repo is large, summarize the few structural facts that actually change how an agent should work.\n"
			"\n"
			"If `AGENTS.md` already exists at the workspace root, improve it in place rather than rewriting blindly. Preserve verified useful guidance, delete fluff or stale claims, and reconcile it with the current codebase.\n";


		const char* PROMPT_REVIEW =
			"You are a code reviewer. Your job is to review code changes and provide actionable feedback.\n"
			"\n"
			"---\n"
			"\n"
			"Input: $ARGUMENTS\n"
			"\n"
			"---\n"
			"\n"
			"## Determining What to Review\n"
			"\n"
			"Based on the input provided, determine which type of review to perform:\n"
			"\n"
			"1. **No arguments (default)**: Review all uncommitted changes\n"
			"   - Run: `git diff` for unstaged changes\n"
			"   - Run: `git diff --cached` for staged changes\n"
			"   - Run: `git status --short` to identify untracked (net new) files\n"
			"\n"
			"2. **Commit hash** (40-char SHA or short hash): Review that specific commit\n"
			"   - Run: `git show $ARGUMENTS`\n"
			"\n"
			"3. **Branch name**: Compare current branch to the specified branch\n"
			"   - Run: `git diff $ARGUMENTS...HEAD`\n"
			"\n"
			"4. **PR URL or number** (contains \"github.com\" or \"pull\" or looks like a PR number): Review the pull request\n"
			"   - Run: `gh pr view $ARGUMENTS` to get PR context\n"
			"   - Run: `gh pr diff $ARGUMENTS` to get the diff\n"
			"\n"
			"Use best judgement when processing input.\n"
			"\n"
			"---\n"
			"\n"
			"## Gathering Context\n"
			"\n"
			"**Diffs alone are not enough.** After getting the diff, read the entire file(s) being modified to understand the full context. Code that looks wrong in isolation may be correct given surrounding logic - and vice versa.\n"
			"\n"
			"- Use the diff to identify which files changed\n"
			"- Use `git status --short` to identify untracked files, then read their full contents\n"
			"- Read the full file to understand existing patterns, control flow, and error handling\n"
			"- Check for existing style guide or conventions files (CONVENTIONS.md, AGENTS.md, .editorconfig, etc.)\n"
			"\n"
			"---\n"
			"\n"
			"## What to Look For\n"
			"\n"
			"**Bugs** - Your primary focus.\n"
			"- Logic errors, off-by-one mistakes, incorrect conditionals\n"
			"- If-else guards: missing guards, incorrect branching, unreachable code paths\n"
			"- Edge cases: null/empty/undefined inputs, error conditions, race conditions\n"
			"- Security issues: injection, auth bypass, data exposure\n"
			"- Broken error handling that swallows failures, throws unexpectedly or returns error types that are not caught.\n"
			"\n"
			"**Structure** - Does the code fit the codebase?\n"
			"- Does it follow existing patterns and conventions?\n"
			"- Are there established abstractions it should use but doesn't?\n"
			"- Excessive nesting that could be flattened with early returns or extraction\n"
			"\n"
			"**Performance** - Only flag if obviously problematic.\n"
			"- O(n^2) on unbounded data, N+1 queries, blocking I/O on hot paths\n"
			"\n"
			"**Behavior Changes** - If a behavioral change is introduced, raise it (especially if it's possibly unintentional).\n"
			"\n"
			"---\n"
			"\n"
			"## Before You Flag Something\n"
			"\n"
			"**Be certain.** If you're going to call something a bug, you need to be confident it actually is one.\n"
			"\n"
			"- Only review the changes - do not review pre-existing code that wasn't modified\n"
			"- Don't flag something as a bug if you're unsure - investigate first\n"
			"- Don't invent hypothetical problems - if an edge case matters, explain the realistic scenario where it breaks\n"
			"- If you need more context to be sure, use the tools below to get it\n"
			"\n"
			"**Don't be a zealot about style.** When checking code against conventions:\n"
			"\n"
			"- Verify the code is *actually* in violation. Don't complain about else statements if early returns are already being used correctly.\n"
			"- Some \"violations\" are acceptable when they're the simplest option. A `let` statement is fine if the alternative is convoluted.\n"
			"- Excessive nesting is a legitimate concern regardless of other style choices.\n"
			"- Don't flag style preferences as issues unless they clearly violate established project conventions.\n"
			"\n"
			"---\n"
			"\n"
			"## Output\n"
			"\n"
			"1. If there is a bug, be direct and clear about why it is a bug.\n"
			"2. Clearly communicate severity of issues. Do not overstate severity.\n"
			"3. Critiques should clearly and explicitly communicate the scenarios, environments, or inputs that are necessary for the bug to arise. The comment should immediately indicate that the issue's severity depends on these factors.\n"
			"4. Your tone should be matter-of-fact and not accusatory or overly positive. It should read as a helpful AI assistant suggestion without sounding too much like a human reviewer.\n"
			"5. Write so the reader can quickly understand the issue without reading too closely.\n"
			"6. AVOID flattery, do not give any comments that are not helpful to the reader. Avoid phrasing like \"Great job ...\", \"Thanks for ...\".\n";


		bool resolver_compact(const std::vector<std::string>& args, std::string& out_text)
		{
			(void)args;
			std::string sid = get_chat_session_id_safe();
			if (sid.empty()) {
				out_text = "[compact] no active session";
				return true;
			}
			aida::compaction::compaction_options_t opts;
			aida::compaction::compaction_result_t result;
			const bool ok = aida::compaction::run(sid, opts, result);
			if (!ok) {
				out_text = std::string("[compact] failed: ") + result.error;
				return true;
			}
			std::ostringstream oss;
			oss << "[compacted: " << result.messages_summarized
			    << " messages -> " << result.tokens_freed << " tokens freed]";
			out_text = oss.str();
			return true;
		}


		bool resolver_help(const std::vector<std::string>& args, std::string& out_text)
		{
			(void)args;
			std::vector<command_t> snapshot;
			{
				std::lock_guard<std::mutex> lk(registry_mutex());
				snapshot = commands_vector();
			}
			std::sort(snapshot.begin(), snapshot.end(),
				[](const command_t& a, const command_t& b) { return a.name < b.name; });
			std::ostringstream oss;
			oss << "Available commands (" << snapshot.size() << "):\n";
			for (const auto& c : snapshot) {
				oss << "  /" << c.name;
				if (!c.description.empty())
					oss << " - " << c.description;
				oss << "\n";
			}
			out_text = oss.str();
			return true;
		}


		bool resolver_title(const std::vector<std::string>& args, std::string& out_text)
		{
			std::string sid = get_chat_session_id_safe();
			if (sid.empty()) {
				out_text = "[title] no active session";
				return true;
			}

			std::string requested = trim_copy(join_args(args));
			if (!requested.empty()) {
				if (!aida::session::set_title(sid, requested)) {
					out_text = std::string("[title] set_title failed: ") + aida::session::last_error();
					return true;
				}
				out_text = std::string("[title] updated: ") + requested;
				return true;
			}

			std::string first_user;
			std::vector<aida::session::message_t> msgs;
			if (aida::session::list_messages(sid, msgs)) {
				for (const auto& m : msgs) {
					if (m.role != aida::session::message_t::role_t::user) continue;
					for (const auto& p : m.parts) {
						if (p.kind == aida::session::part_t::kind_t::text) {
							first_user = p.text.text;
							break;
						}
					}
					if (!first_user.empty()) break;
				}
			}

			if (first_user.empty()) {
				out_text = "[title] no user message yet to derive title from";
				return true;
			}

			const std::string provider_id = g_sa_settings.selected_provider_id();
			const bool ok = aida::compaction::maybe_auto_title(sid, first_user, provider_id);
			if (!ok) {
				out_text = std::string("[title] auto-title failed: ") + aida::compaction::last_error();
				return true;
			}

			aida::session::session_info_t after;
			if (aida::session::get(sid, after))
				out_text = std::string("[title] updated: ") + after.title;
			else
				out_text = "[title] auto-title scheduled";
			return true;
		}


		bool resolver_clear(const std::vector<std::string>& args, std::string& out_text)
		{
			(void)args;
			(void)start_new_conversation();
			out_text = "[clear] chat history cleared";
			return true;
		}


		bool resolver_init(const std::vector<std::string>& args, std::string& out_text)
		{
			out_text = apply_placeholders(PROMPT_INITIALIZE, args);
			return true;
		}


		bool resolver_review(const std::vector<std::string>& args, std::string& out_text)
		{
			out_text = apply_placeholders(PROMPT_REVIEW, args);
			return true;
		}


		bool resolver_agent_switch(const std::string& agent_name,
		                           const std::vector<std::string>& args,
		                           std::string& out_text)
		{
			(void)args;
			if (!aida::agent::set_active_agent(agent_name)) {
				out_text = std::string("[agent] failed to switch: ") + aida::agent::last_error();
				return true;
			}
			out_text = std::string("[agent] switched to: ") + agent_name;
			return true;
		}


		bool resolver_view_switch(const char* target,
		                          const std::vector<std::string>& args,
		                          std::string& out_text)
		{
			(void)args;
			const auto result = aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t(target));
			out_text = result.ok() ? "[view] switched" :
				"[view] unavailable: " + result.detail;
			return result.ok();
		}


		bool resolver_open_settings(const std::vector<std::string>& args, std::string& out_text)
		{
			(void)args;
			aida::settings_overlay::open();
			out_text = "[settings] opened";
			return true;
		}


		bool resolver_toggle_left(const std::vector<std::string>& args, std::string& out_text)
		{
			(void)args;
			const aida::ui::stable_view_id_t id("view.project_explorer");
			const auto result = aida::ui::application_views::is_open(id)
				? aida::ui::application_views::close(id)
				: aida::ui::application_views::open_or_focus(id);
			out_text = result.ok() ? "[view] project explorer toggled" : "[view] project explorer unavailable: " + result.detail;
			return result.ok();
		}


		bool resolver_toggle_right(const std::vector<std::string>& args, std::string& out_text)
		{
			(void)args;
			aida::settings_overlay::toggle();
			out_text = aida::settings_overlay::is_open()
				? "[settings] opened" : "[settings] closed";
			return true;
		}


		bool resolver_toggle_bottom(const std::vector<std::string>& args, std::string& out_text)
		{
			(void)args;
			const aida::ui::stable_view_id_t id("view.output");
			const auto result = aida::ui::application_views::is_open(id)
				? aida::ui::application_views::close(id)
				: aida::ui::application_views::open_or_focus(id);
			out_text = result.ok() ? "[view] output toggled" : "[view] output unavailable: " + result.detail;
			return result.ok();
		}


		void register_builtins_locked(std::vector<command_t>& dst)
		{
			{
				command_t c;
				c.name              = "init";
				c.description       = "guided AGENTS.md setup";
				c.source            = command_source_t::builtin;
				c.template_text     = PROMPT_INITIALIZE;
				c.placeholder_hints = extract_placeholder_hints(PROMPT_INITIALIZE);
				c.resolver          = resolver_init;
				dst.push_back(std::move(c));
			}

			{
				command_t c;
				c.name              = "review";
				c.description       = "review changes [commit|branch|pr], defaults to uncommitted";
				c.source            = command_source_t::builtin;
				c.template_text     = PROMPT_REVIEW;
				c.placeholder_hints = extract_placeholder_hints(PROMPT_REVIEW);
				c.subtask           = true;
				c.resolver          = resolver_review;
				dst.push_back(std::move(c));
			}

			{
				command_t c;
				c.name        = "compact";
				c.description = "summarize older messages and free context tokens";
				c.source      = command_source_t::builtin;
				c.resolver    = resolver_compact;
				dst.push_back(std::move(c));
			}

			{
				command_t c;
				c.name        = "help";
				c.description = "list every available command";
				c.source      = command_source_t::builtin;
				c.resolver    = resolver_help;
				dst.push_back(std::move(c));
			}

			{
				command_t c;
				c.name        = "title";
				c.description = "rerun auto-title for the current session";
				c.source      = command_source_t::builtin;
				c.resolver    = resolver_title;
				dst.push_back(std::move(c));
			}

			{
				command_t c;
				c.name        = "clear";
				c.description = "clear chat history (no LLM call)";
				c.source      = command_source_t::builtin;
				c.resolver    = resolver_clear;
				dst.push_back(std::move(c));
			}

			{
				command_t c;
				c.name        = "settings";
				c.description = "open the Settings overlay";
				c.source      = command_source_t::builtin;
				c.resolver    = resolver_open_settings;
				dst.push_back(std::move(c));
			}

			struct view_entry_t { const char* name; const char* desc; const char* target; };
			static const view_entry_t view_entries[] = {
				{ "view:editor",            "switch to code editor",         "document.code" },
				{ "view:disassembly",       "switch to disassembly view",    "document.disassembly" },
				{ "view:hex",               "switch to hex view",            "document.hex" },
				{ "view:network",           "switch to network monitor",     "view.network.connections" },
				{ "view:scanner",           "switch to scanner hub",         "view.memory.value_scan" },
				{ "view:analysis",          "switch to analysis hub",        "view.analysis.symbolic" },
				{ "view:debugger",          "switch to debugger",            "view.debug.cpu" },
				{ "view:decompiler",        "switch to pseudocode",          "document.pseudocode" },
				{ "view:struct",            "switch to struct recon",        "view.types.struct_recon" },
				{ "view:crypto",            "switch to crypto scanner",      "view.memory.crypto" },
				{ "view:aob",               "switch to aob generator",       "view.memory.aob" },
				{ "view:fuzzer",            "switch to fuzzer",              "view.analysis.fuzzer" },
				{ "view:xrefs",             "switch to cross references",     "view.analysis.references" },
				{ "view:snapshot",          "switch to snapshot diff",       "view.memory.snapshots" },
				{ "view:pointer",           "switch to pointer scanner",     "view.memory.pointers" },
				{ "view:decrypt-oracle",    "switch to decrypt oracle",      "view.memory.decrypt" },
				{ "view:integrity",         "switch to integrity hunter",    "view.memory.integrity" },
				{ "view:symbolic",          "switch to symbolic engine",     "view.analysis.symbolic" },
				{ "view:taint",             "switch to taint view",          "view.analysis.taint" },
				{ "view:deobfuscation",     "switch to deobfuscation",       "view.analysis.deobfuscation" },
				{ "view:stealth",           "switch to stealth view",        "view.analysis.protection" },
				{ "view:types",             "switch to types hub",           "view.types.structures" },
				{ "view:binary-map",        "switch to binary map",          "view.analysis.binary_map" },
				{ "view:memory-scanner",    "switch to memory scanner",      "view.memory.value_scan" },
			};
			for (const auto& v : view_entries) {
				command_t c;
				c.name        = v.name;
				c.description = v.desc;
				c.source      = command_source_t::builtin;
				const char* target = v.target;
				c.resolver = [target](const std::vector<std::string>& args, std::string& out) -> bool {
					return resolver_view_switch(target, args, out);
				};
				dst.push_back(std::move(c));
			}

			{
				command_t c;
				c.name        = "panel:left";
				c.description = "toggle left panel (explorer)";
				c.source      = command_source_t::builtin;
				c.resolver    = resolver_toggle_left;
				dst.push_back(std::move(c));
			}
			{
				command_t c;
				c.name        = "panel:right";
				c.description = "toggle right panel (chat)";
				c.source      = command_source_t::builtin;
				c.resolver    = resolver_toggle_right;
				dst.push_back(std::move(c));
			}
			{
				command_t c;
				c.name        = "panel:bottom";
				c.description = "toggle bottom panel (output)";
				c.source      = command_source_t::builtin;
				c.resolver    = resolver_toggle_bottom;
				dst.push_back(std::move(c));
			}
		}


		void register_skills_locked(std::vector<command_t>& dst, std::set<std::string>& taken_names)
		{
			auto skills_cmds = aida::skills::all_as_commands();
			for (auto& s : skills_cmds) {
				if (s.name.empty()) continue;
				if (taken_names.count(s.name) > 0) continue;
				command_t c;
				c.name              = s.name;
				c.description       = s.description;
				c.source            = command_source_t::skill;
				c.template_text     = s.template_text;
				c.placeholder_hints = s.placeholder_hints;
				c.source_path       = s.source_path;
				dst.push_back(std::move(c));
				taken_names.insert(s.name);
			}
		}


		void register_mcp_prompts_locked(std::vector<command_t>& dst, std::set<std::string>& taken_names)
		{
			std::vector<mcp_client::remote_prompt_t> all = s_mcp_client_mgr.get_all_prompts();
			for (auto& pr : all) {
				if (pr.server_name.empty() || pr.name.empty()) continue;
				const std::string qualified = pr.server_name + ":" + pr.name;
				if (taken_names.count(qualified) > 0) continue;

				std::vector<std::string> hints;
				hints.reserve(pr.arguments.size());
				for (size_t i = 0; i < pr.arguments.size(); ++i) {
					std::string h = "$" + std::to_string(i + 1);
					if (!pr.arguments[i].name.empty())
						h += " (" + pr.arguments[i].name + ")";
					hints.push_back(std::move(h));
				}

				const std::string server  = pr.server_name;
				const std::string prompt  = pr.name;
				std::vector<mcp_client::prompt_argument_t> arg_schema = pr.arguments;

				command_t c;
				c.name              = qualified;
				c.description       = pr.description.empty()
					? (std::string("MCP prompt from ") + pr.server_name)
					: pr.description;
				c.source            = command_source_t::mcp;
				c.template_text     = std::string();
				c.placeholder_hints = std::move(hints);
				c.resolver = [server, prompt, arg_schema](const std::vector<std::string>& args,
				                                           std::string& out) -> bool {
					std::map<std::string, std::string> params;
					for (size_t i = 0; i < arg_schema.size(); ++i) {
						const std::string& key = arg_schema[i].name;
						if (key.empty()) continue;
						if (i < args.size())
							params[key] = args[i];
						else if (arg_schema[i].required)
							params[key] = std::string();
					}
					out = s_mcp_client_mgr.get_prompt(server, prompt, params);
					if (out.empty())
						out = std::string("[mcp:") + server + "/" + prompt + "] returned no content";
					return true;
				};

				dst.push_back(std::move(c));
				taken_names.insert(qualified);
			}
		}


		void register_mcp_tools_locked(std::vector<command_t>& dst, std::set<std::string>& taken_names)
		{
			std::vector<mcp_client::remote_tool_t> all = s_mcp_client_mgr.get_all_tools();
			for (auto& rt : all) {
				if (rt.name.empty()) continue;
				if (taken_names.count(rt.name) > 0) continue;

				const std::string server  = rt.server_name;
				const std::string tool    = rt.original_name.empty() ? rt.name : rt.original_name;
				const std::string display = rt.name;

				command_t c;
				c.name        = display;
				c.description = rt.description.empty()
					? (std::string("MCP tool from ") + server)
					: rt.description;
				c.source         = command_source_t::mcp;
				c.template_text  = std::string();
				c.resolver = [display, server, tool](const std::vector<std::string>& args,
				                                      std::string& out) -> bool {
					nlohmann::json arguments = nlohmann::json::object();
					if (!args.empty()) {
						const std::string joined = [&]() {
							std::string s;
							for (size_t i = 0; i < args.size(); ++i) {
								if (i > 0) s.push_back(' ');
								s += args[i];
							}
							return s;
						}();
						if (!joined.empty()) {
							try {
								arguments = nlohmann::json::parse(joined);
								if (!arguments.is_object())
									arguments = nlohmann::json{{"input", joined}};
							} catch (...) {
								arguments = nlohmann::json{{"input", joined}};
							}
						}
					}

					mcp_client::call_result_t r = s_mcp_client_mgr.call_tool(display, arguments);
					if (!r.success) {
						out = std::string("[mcp:") + server + "/" + tool + "] " +
						      (r.text.empty() ? "tool call failed" : r.text);
						return true;
					}
					out = r.text;
					if (!r.data.is_null() && !r.data.empty()) {
						try {
							if (!out.empty()) out += "\n";
							out += r.data.dump(2);
						} catch (...) {}
					}
					if (out.empty())
						out = std::string("[mcp:") + server + "/" + tool + "] (no output)";
					return true;
				};

				dst.push_back(std::move(c));
				taken_names.insert(display);
			}
		}


		void register_agents_locked(std::vector<command_t>& dst, std::set<std::string>& taken_names)
		{
			auto primary = aida::agent::primary_agents();
			for (const auto* a : primary) {
				if (a == nullptr) continue;
				if (a->hidden) continue;
				const std::string qualified = std::string("agent:") + a->name;
				if (taken_names.count(qualified) > 0) continue;

				const std::string agent_name = a->name;
				command_t c;
				c.name        = qualified;
				c.description = a->description.empty()
					? (std::string("switch to agent: ") + a->name)
					: a->description;
				c.source         = command_source_t::agent;
				c.agent_override = a->name;
				c.resolver       = [agent_name](const std::vector<std::string>& args,
				                                 std::string& out) -> bool {
					return resolver_agent_switch(agent_name, args, out);
				};

				dst.push_back(std::move(c));
				taken_names.insert(qualified);
			}
		}


		void rebuild_locked()
		{
			auto& dst = commands_vector();
			dst.clear();
			std::set<std::string> taken_names;

			register_builtins_locked(dst);
			for (const auto& c : dst) taken_names.insert(c.name);

			register_skills_locked(dst, taken_names);
			register_mcp_prompts_locked(dst, taken_names);
			register_mcp_tools_locked(dst, taken_names);
			register_agents_locked(dst, taken_names);
		}


		void on_mcp_tools_changed(const aida::events::mcp_tools_changed_t& payload)
		{
			(void)payload;
			(void)reindex();
		}


		int fuzzy_score(const std::string& query_lower, const std::string& target_lower)
		{
			if (query_lower.empty()) return 0;
			size_t qi = 0;
			size_t ti = 0;
			int    last_match = -1;
			int    gap_penalty = 0;
			int    matched = 0;
			while (qi < query_lower.size() && ti < target_lower.size()) {
				if (query_lower[qi] == target_lower[ti]) {
					if (last_match >= 0) {
						const int gap = static_cast<int>(ti) - last_match - 1;
						gap_penalty += gap;
					}
					last_match = static_cast<int>(ti);
					++qi;
					++matched;
				}
				++ti;
			}
			if (qi < query_lower.size()) return -1;
			int score = 1000 - gap_penalty - static_cast<int>(target_lower.size()) + matched * 8;
			return score;
		}


		void append_application_actions(std::vector<command_t>& result)
		{
			const auto actions = aida::ui::application_ui::list_actions(
				aida::ui::action_surface_t::command_palette);
			result.reserve(result.size() + actions.size());
			for (const auto& action : actions) {
				if (!action.visible)
					continue;
				command_t command;
				command.name = std::string("action:") + action.id;
				command.display_name = action.label;
				command.description = action.description;
				command.category = action.category;
				command.shortcut = action.shortcut;
				command.application_action_id = action.id;
				command.disabled_reason = action.disabled_reason;
				command.source = command_source_t::builtin;
				command.enabled = action.enabled;
				result.push_back(std::move(command));
			}
		}


	}


	std::vector<std::string> extract_placeholder_hints(const std::string& template_text)
	{
		std::vector<std::string> result;
		std::set<std::string>    seen;
		const char* p   = template_text.c_str();
		const char* end = p + template_text.size();
		while (p < end) {
			if (*p == '$') {
				const char* q = p + 1;
				if (q < end && *q >= '1' && *q <= '9') {
					std::string tok;
					tok.push_back('$');
					tok.push_back(*q);
					if (seen.insert(tok).second) result.push_back(tok);
					p = q + 1;
					continue;
				}
				if (q + 9 <= end && std::string(q, q + 9) == "ARGUMENTS") {
					const std::string tok = "$ARGUMENTS";
					if (seen.insert(tok).second) result.push_back(tok);
					p = q + 9;
					continue;
				}
			}
			++p;
		}
		std::sort(result.begin(), result.end());
		return result;
	}


	std::string apply_placeholders(const std::string& template_text,
	                                const std::vector<std::string>& args)
	{
		std::string out;
		out.reserve(template_text.size() + 64);
		const char* p   = template_text.c_str();
		const char* end = p + template_text.size();
		const std::string joined = join_args(args);

		while (p < end) {
			if (*p == '$') {
				const char* q = p + 1;
				if (q < end && *q >= '1' && *q <= '9') {
					const int idx = (*q - '1');
					if (idx >= 0 && idx < static_cast<int>(args.size()))
						out += args[idx];
					p = q + 1;
					continue;
				}
				if (q + 9 <= end && std::string(q, q + 9) == "ARGUMENTS") {
					out += joined;
					p = q + 9;
					continue;
				}
			}
			out.push_back(*p);
			++p;
		}
		return out;
	}


	bool initialize()
	{
		{
			std::lock_guard<std::mutex> lk(registry_mutex());
			if (initialized_flag()) return true;
			rebuild_locked();
			initialized_flag() = true;
		}

		auto& handle = mcp_sub_handle();
		if (!handle.valid()) {
			handle = aida::events::subscribe(aida::events::event_mcp_tools_changed,
				std::function<void(const aida::events::mcp_tools_changed_t&)>(on_mcp_tools_changed));
		}
		return true;
	}


	bool reindex()
	{
		std::lock_guard<std::mutex> lk(registry_mutex());
		rebuild_locked();
		return true;
	}


	std::vector<command_t> list()
	{
		std::vector<command_t> result;
		{
			std::lock_guard<std::mutex> lk(registry_mutex());
			result = commands_vector();
		}
		append_application_actions(result);
		return result;
	}


	bool find(const std::string& name, command_t& out)
	{
		std::lock_guard<std::mutex> lk(registry_mutex());
		const auto& v = commands_vector();
		for (const auto& c : v) {
			if (c.name == name) {
				out = c;
				return true;
			}
		}
		return false;
	}


	std::vector<command_t> fuzzy_search(const std::string& query, int limit)
	{
		std::vector<command_t> available;
		{
			std::lock_guard<std::mutex> lk(registry_mutex());
			available = commands_vector();
		}
		append_application_actions(available);
		const auto& v = available;
		const std::string q = to_lower_ascii(trim_copy(query));

		std::vector<command_t> result;
		if (q.empty()) {
			result.reserve(v.size());
			for (const auto& c : v) result.push_back(c);
			std::sort(result.begin(), result.end(),
				[](const command_t& a, const command_t& b) { return a.name < b.name; });
			if (limit > 0 && static_cast<int>(result.size()) > limit)
				result.resize(static_cast<size_t>(limit));
			return result;
		}

		std::vector<std::pair<int, const command_t*>> scored;
		scored.reserve(v.size());
		for (const auto& c : v) {
			const std::string name_lower = to_lower_ascii(
				c.display_name.empty() ? c.name : c.display_name);
			const std::string desc_lower = to_lower_ascii(c.description);
			const std::string category_lower = to_lower_ascii(c.category);
			const std::string shortcut_lower = to_lower_ascii(c.shortcut);
			int score = fuzzy_score(q, name_lower);
			if (score < 0) {
				const int desc_score = fuzzy_score(q, desc_lower);
				const int category_score = fuzzy_score(q, category_lower);
				const int shortcut_score = fuzzy_score(q, shortcut_lower);
				if (desc_score < 0 && category_score < 0 && shortcut_score < 0)
					continue;
				score = (std::max)(desc_score - 200,
					(std::max)(category_score - 120, shortcut_score - 80));
			}
			scored.emplace_back(score, &c);
		}
		std::sort(scored.begin(), scored.end(),
			[](const std::pair<int, const command_t*>& a,
			   const std::pair<int, const command_t*>& b) {
				if (a.first != b.first) return a.first > b.first;
				return a.second->name < b.second->name;
			});

		result.reserve(scored.size());
		for (auto& kv : scored) result.push_back(*kv.second);
		if (limit > 0 && static_cast<int>(result.size()) > limit)
			result.resize(static_cast<size_t>(limit));
		return result;
	}


	bool execute(const std::string& name,
	              const std::vector<std::string>& args,
	              std::string& out_resolved_text)
	{
		out_resolved_text.clear();

		command_t snapshot;
		bool found = false;
		{
			std::lock_guard<std::mutex> lk(registry_mutex());
			const auto& v = commands_vector();
			for (const auto& c : v) {
				if (c.name == name) {
					snapshot = c;
					found = true;
					break;
				}
			}
		}

		if (!found) {
			set_last_error("command not found: " + name);
			return false;
		}

		auto publish_executed = [&](const std::string& text) {
			(void)text;
			aida::events::command_executed_t evt;
			evt.session_id   = get_chat_session_id_safe();
			evt.command_name = name;
			switch (snapshot.source) {
				case command_source_t::builtin: evt.source = "builtin"; break;
				case command_source_t::mcp:     evt.source = "mcp";     break;
				case command_source_t::skill:   evt.source = "skill";   break;
				case command_source_t::agent:   evt.source = "agent";   break;
			}
			evt.args = join_args(args);
			aida::events::publish(aida::events::event_command_executed, evt);
		};

		if (snapshot.resolver) {
			std::string text;
			const bool ok = snapshot.resolver(args, text);
			if (!ok) {
				set_last_error("resolver failed: " + name);
				return false;
			}
			out_resolved_text = std::move(text);
			publish_executed(out_resolved_text);
			return true;
		}

		out_resolved_text = apply_placeholders(snapshot.template_text, args);
		publish_executed(out_resolved_text);
		return true;
	}


	const std::string& last_error()
	{
		std::lock_guard<std::mutex> lk(error_mutex());
		return error_slot();
	}


}
}
