#include "binary_map.hpp"

#include <algorithm>
#include <chrono>
#include <climits>
#include <cmath>
#include <cstdio>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace aida {
namespace binary_map {

	namespace {

		std::mutex& state_mutex()
		{
			static std::mutex m;
			return m;
		}

		std::string& last_error_storage()
		{
			static std::string s;
			return s;
		}

		void set_last_error(const std::string& msg)
		{
			std::lock_guard<std::mutex> guard(state_mutex());
			last_error_storage() = msg;
		}





		struct workspace_map_state_t
		{
			std::mutex mutex;
			std::set<uint64_t> pins;
			map_t cached_map;
			std::string cache_key;
			std::string error;
			bool cache_valid = false;
		};

		std::mutex& workspace_map_states_mutex()
		{
			static std::mutex mutex;
			return mutex;
		}

		std::unordered_map<std::string, std::shared_ptr<workspace_map_state_t>>&
		workspace_map_states()
		{
			static std::unordered_map<std::string, std::shared_ptr<workspace_map_state_t>> states;
			return states;
		}

		std::shared_ptr<workspace_map_state_t> workspace_map_state(
			const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
		{
			if (!workspace) return {};
			const std::string id = workspace->identity().binary_id().to_hex();
			std::lock_guard<std::mutex> lock(workspace_map_states_mutex());
			auto& state = workspace_map_states()[id];
			if (!state) state = std::make_shared<workspace_map_state_t>();
			return state;
		}










		float compute_shannon_entropy(const uint8_t* data, size_t length)
		{
			if (data == nullptr || length == 0)
				return 0.f;
			uint64_t freq[256] = {};
			for (size_t i = 0; i < length; ++i)
				++freq[data[i]];
			const double inv = 1.0 / static_cast<double>(length);
			double h = 0.0;
			for (int i = 0; i < 256; ++i) {
				if (freq[i] == 0) continue;
				const double p = static_cast<double>(freq[i]) * inv;
				h -= p * (std::log(p) / std::log(2.0));
			}
			if (h < 0.0) h = 0.0;
			if (h > 8.0) h = 8.0;
			return static_cast<float>(h / 8.0);
		}









		std::string format_size_human(uint64_t bytes)
		{
			char buf[64];
			if (bytes >= (1ull << 30)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 30);
				std::snprintf(buf, sizeof(buf), "%.2f GB", v);
			} else if (bytes >= (1ull << 20)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 20);
				std::snprintf(buf, sizeof(buf), "%.2f MB", v);
			} else if (bytes >= (1ull << 10)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 10);
				std::snprintf(buf, sizeof(buf), "%.2f KB", v);
			} else {
				std::snprintf(buf, sizeof(buf), "%llu B",
					static_cast<unsigned long long>(bytes));
			}
			return buf;
		}

		std::string default_function_name(uint64_t va)
		{
			char buf[32];
			std::snprintf(buf, sizeof(buf), "sub_%llX",
				static_cast<unsigned long long>(va));
			return buf;
		}

		std::string default_global_name(uint64_t va)
		{
			char buf[32];
			std::snprintf(buf, sizeof(buf), "data_%llX",
				static_cast<unsigned long long>(va));
			return buf;
		}












		int score_function(int xrefs, int callees, bool pinned)
		{
			int s = xrefs * 3 + callees;
			if (pinned)
				s += 1000;
			return s;
		}

		uint64_t now_unix_seconds()
		{
			using namespace std::chrono;
			return static_cast<uint64_t>(
				duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
		}

		std::string render_to_string(const map_t& map, const map_options_t& opts)
		{
			std::ostringstream oss;
			char hex[64];

			std::snprintf(hex, sizeof(hex), "0x%llX",
				static_cast<unsigned long long>(map.image_base));
			oss << "module " << (map.module_name.empty() ? std::string("<unnamed>") : map.module_name)
				<< " (" << (map.format.empty() ? std::string("PE") : map.format)
				<< " " << (map.architecture.empty() ? std::string("?") : map.architecture)
				<< ", base=" << hex
				<< ", size=" << format_size_human(map.image_size) << ")";
			oss << "\n\nsections:\n";

			for (const auto& s : map.sections) {
				const char* perm = s.executable
					? (s.writable ? "[exec rw]" : "[exec ro]")
					: (s.writable ? "[rw]" : "[ro]");
				char range[96];
				std::snprintf(range, sizeof(range), "0x%llX-0x%llX",
					static_cast<unsigned long long>(s.va),
					static_cast<unsigned long long>(s.va + s.size));
				char ent_buf[48];
				if (s.sampled_bytes > 0) {
					std::snprintf(ent_buf, sizeof(ent_buf), " H=%.2f",
						static_cast<double>(s.entropy) * 8.0);
				} else {
					ent_buf[0] = '\0';
				}
				oss << "  " << (s.name.empty() ? std::string("<unnamed>") : s.name)
					<< " " << perm
					<< " " << range
					<< " (" << format_size_human(s.size) << ")"
					<< ent_buf << "\n";
			}

			oss << "\nfunctions (top " << map.functions.size() << " by score):\n";
			for (const auto& fn : map.functions) {
				char addr[32];
				std::snprintf(addr, sizeof(addr), "0x%llX",
					static_cast<unsigned long long>(fn.va));
				oss << "  " << addr;
				if (!fn.name.empty() && fn.name != default_function_name(fn.va))
					oss << " \"" << fn.name << "\"";
				oss << " - " << fn.xref_count << " xrefs";
				if (fn.callee_count > 0) {
					oss << ", calls: ";
					for (size_t i = 0; i < fn.top_callees.size(); ++i) {
						if (i != 0) oss << ", ";
						oss << fn.top_callees[i];
					}
					if (fn.callee_count > static_cast<int>(fn.top_callees.size()))
						oss << ", ...";
				}
				if (fn.pinned)
					oss << " [pinned]";
				oss << "\n";
			}

			if (!map.globals.empty()) {
				oss << "\nglobals:\n";
				for (const auto& g : map.globals) {
					char addr[32];
					std::snprintf(addr, sizeof(addr), "0x%llX",
						static_cast<unsigned long long>(g.va));
					oss << "  " << g.name
						<< " (" << (g.writable ? "rw" : "ro")
						<< ") at " << addr
						<< " - " << g.xref_count << " xrefs\n";
				}
			}

			if (opts.include_imports && !map.imports.empty()) {
				oss << "\nimports:\n";
				for (const auto& line : map.imports)
					oss << "  " << line << "\n";
			}

			if (opts.include_exports && !map.exports.empty()) {
				oss << "\nexports:\n";
				for (size_t i = 0; i < map.exports.size(); ++i) {
					if (i != 0) oss << ", ";
					if (i % 8 == 0 && i != 0) oss << "\n  ";
					if (i == 0) oss << "  ";
					oss << map.exports[i];
				}
				oss << "\n";
			}

			return oss.str();
		}

		std::string render_text_locked(const map_t& map, const map_options_t& opts)
		{
			std::string result = render_to_string(map, opts);
			const size_t budget = (opts.max_chars == 0) ? 4096u : opts.max_chars;
			if (result.size() <= budget)
				return result;

			map_t trimmed = map;
			while (result.size() > budget && !trimmed.functions.empty()) {
				size_t drop_idx = trimmed.functions.size();
				for (size_t i = trimmed.functions.size(); i > 0; --i) {
					if (!trimmed.functions[i - 1].pinned) {
						drop_idx = i - 1;
						break;
					}
				}
				if (drop_idx >= trimmed.functions.size())
					break;
				trimmed.functions.erase(trimmed.functions.begin() + static_cast<std::ptrdiff_t>(drop_idx));
				result = render_to_string(trimmed, opts);
			}

			if (result.size() > budget) {
				if (budget >= 16)
					result.resize(budget - 16);
				result += "\n... [truncated]\n";
			}
			return result;
		}

	}


	bool generate(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const map_options_t& opts, map_t& out)
	{
		using namespace aida::analysis;
		out = {};
		auto map_state = workspace_map_state(workspace);
		if (!workspace || !map_state) {
			set_last_error("TARGET_NOT_FOUND: binary map requires an explicit workspace");
			return false;
		}
		if (workspace->target_kind() == target_kind_t::live_snapshot) {
			std::lock_guard<std::mutex> lock(map_state->mutex);
			map_state->error = "LIVE_TARGET_BULK_ANALYSIS_UNSUPPORTED";
			set_last_error(map_state->error);
			return false;
		}
		auto publication = workspace->analysis_publication();
		auto image = workspace->image();
		if (!publication || !publication->snapshot || !image) {
			std::lock_guard<std::mutex> lock(map_state->mutex);
			map_state->error = "ANALYSIS_IN_PROGRESS: binary map snapshot is not published";
			set_last_error(map_state->error);
			return false;
		}
		char cache_text[320]{};
		std::snprintf(cache_text, sizeof(cache_text),
			"%s:%llu:%llu:%llu:%d:%d:%d:%zu:%d:%d:%d:%d",
			workspace->identity().binary_id().to_hex().c_str(),
			static_cast<unsigned long long>(publication->generation),
			static_cast<unsigned long long>(publication->analysis_revision),
			static_cast<unsigned long long>(publication->overlay_revision),
			opts.max_functions, opts.max_globals, opts.max_callees_per_function,
			opts.max_chars, opts.include_imports ? 1 : 0,
			opts.include_exports ? 1 : 0, opts.include_xrefs ? 1 : 0,
			opts.include_entropy ? 1 : 0);
		const std::string cache_key(cache_text);
		std::set<uint64_t> pins;
		{
			std::lock_guard<std::mutex> lock(map_state->mutex);
			if (map_state->cache_valid && map_state->cache_key == cache_key) {
				out = map_state->cached_map;
				return true;
			}
			pins = map_state->pins;
		}
		const auto snapshot = publication->snapshot;
		const auto cancel = workspace->cancellation_token();
		if (cancel.stop_requested()) {
			set_last_error("CANCELLED: binary map request was cancelled");
			return false;
		}
		map_t fresh;
		fresh.module_name = workspace->identity().bin_name();
		fresh.module_path = workspace->identity().normalized_source_path();
		fresh.image_base = image->image_base();
		fresh.image_size = image->image_size();
		fresh.architecture = image->architecture() == architecture_id_t::x86_64
			? "x86-64" : (image->architecture() == architecture_id_t::x86 ? "x86" : "unknown");
		fresh.format = image->format() == format_id_t::pe32_plus
			? "PE32+" : (image->format() == format_id_t::pe32 ? "PE32" : "unknown");
		auto display_address = [&image](const address_t& address) -> std::optional<uint64_t> {
			if (address.space == address_space_id_t::virtual_address ||
				address.space == address_space_id_t::live_virtual)
				return address.value;
			uint64_t rva = 0;
			if (address.space == address_space_id_t::relative_virtual) {
				rva = address.value;
			} else if (address.space == address_space_id_t::file_offset) {
				auto translated = image->file_offset_to_rva(address.value);
				if (!translated) return std::nullopt;
				rva = translated.value();
			} else {
				return std::nullopt;
			}
			if (rva >= image->image_size() || image->image_base() > UINT64_MAX - rva)
				return std::nullopt;
			return image->image_base() + rva;
		};
		fresh.sections.reserve(image->sections().size());
		for (const auto& section : image->sections()) {
			if (cancel.stop_requested()) {
				set_last_error("CANCELLED: binary map request was cancelled");
				return false;
			}
			map_section_t mapped;
			mapped.name = section.name;
			auto section_address = image->rva_to_va(section.virtual_address);
			if (!section_address) {
				set_last_error(section_address.error().stable_code() + ": " +
					section_address.error().message);
				return false;
			}
			mapped.va = section_address.value();
			mapped.size = section.virtual_size != 0
				? section.virtual_size : section.raw_size;
			mapped.executable = section.executable;
			mapped.readable = section.readable;
			mapped.writable = section.writable;
			if (opts.include_entropy && section.raw_size != 0) {
				const uint64_t sample_size = (std::min<std::uint64_t>)(
					section.raw_size, 64ull * 1024ull);
				auto leased = workspace->provider().lease(
					section.raw_offset, sample_size, cancel);
				if (leased) {
					mapped.entropy = compute_shannon_entropy(
						leased.value().data(), leased.value().size());
					mapped.sampled_bytes = leased.value().size();
				}
			}
			fresh.sections.push_back(std::move(mapped));
		}
		if (opts.include_imports) {
			std::map<std::string, std::vector<std::string>> grouped;
			for (const auto& entry : image->imports()) {
				std::string name;
				if (entry.name) name = *entry.name;
				else if (entry.ordinal) name = "Ordinal#" + std::to_string(*entry.ordinal);
				grouped[entry.library].push_back(std::move(name));
			}
			for (auto& group : grouped) {
				std::sort(group.second.begin(), group.second.end());
				group.second.erase(std::unique(group.second.begin(), group.second.end()),
					group.second.end());
				std::string line = group.first + ": ";
				for (size_t index = 0; index < group.second.size(); ++index) {
					if (index != 0) line += ", ";
					line += group.second[index];
				}
				fresh.imports.push_back(std::move(line));
			}
		}
		if (opts.include_exports) {
			for (const auto& entry : image->exports()) {
				if (!entry.forwarder && entry.name)
					fresh.exports.push_back(*entry.name);
			}
			std::sort(fresh.exports.begin(), fresh.exports.end());
			fresh.exports.erase(std::unique(fresh.exports.begin(), fresh.exports.end()),
				fresh.exports.end());
		}
		std::unordered_map<entity_id_t, std::string> symbol_by_id;
		std::unordered_map<uint64_t, std::string> symbol_by_address;
		for (const auto& symbol : snapshot->symbols) {
			if (!symbol.name.empty()) {
				symbol_by_id.emplace(symbol.id, symbol.name);
				const auto address = display_address(symbol.address);
				if (address) symbol_by_address.emplace(*address, symbol.name);
			}
		}
		std::vector<const function_record_t*> ordered_functions;
		ordered_functions.reserve(snapshot->functions.size());
		for (const auto& function : snapshot->functions)
			ordered_functions.push_back(&function);
		std::sort(ordered_functions.begin(), ordered_functions.end(),
			[](const auto* left, const auto* right) { return left->start < right->start; });
		auto enclosing = [&](const address_t& address) -> const function_record_t* {
			auto found = std::upper_bound(ordered_functions.begin(), ordered_functions.end(),
				address, [](const auto& value, const auto* function) {
					return value < function->start;
				});
			if (found == ordered_functions.begin()) return nullptr;
			--found;
			const auto* function = *found;
			if (address.space != function->start.space ||
				address.value < function->start.value ||
				address.value >= function->end.value)
				return nullptr;
			return function;
		};
		std::unordered_map<entity_id_t, int> incoming;
		std::unordered_map<entity_id_t, std::vector<uint64_t>> callees;
		if (opts.include_xrefs) {
			for (const auto& xref : snapshot->xrefs) {
				const auto* target = enclosing(xref.target);
				if (target && incoming[target->id] < INT_MAX) ++incoming[target->id];
			}
			for (const auto& edge : snapshot->edges) {
				if (edge.kind != edge_kind_t::call && edge.kind != edge_kind_t::tail_call)
					continue;
				const auto* source = enclosing(edge.source);
				if (!source) continue;
				const auto target_address = display_address(edge.target);
				if (!target_address) continue;
				auto& targets = callees[source->id];
				if (std::find(targets.begin(), targets.end(), *target_address) == targets.end())
					targets.push_back(*target_address);
			}
		}
		std::vector<map_function_t> all_functions;
		all_functions.reserve(ordered_functions.size());
		for (const auto* function : ordered_functions) {
			if (cancel.stop_requested()) {
				set_last_error("CANCELLED: binary map request was cancelled");
				return false;
			}
			map_function_t mapped;
			const auto function_address = display_address(function->start);
			if (!function_address) continue;
			mapped.va = *function_address;
			if (function->symbol_id) {
				const auto name = symbol_by_id.find(*function->symbol_id);
				if (name != symbol_by_id.end()) mapped.name = name->second;
			}
			if (mapped.name.empty()) mapped.name = default_function_name(mapped.va);
			mapped.xref_count = incoming[function->id];
			auto targets = callees.find(function->id);
			if (targets != callees.end()) {
				std::sort(targets->second.begin(), targets->second.end());
				mapped.callee_count = static_cast<int>((std::min<size_t>)(
					targets->second.size(), static_cast<size_t>(INT_MAX)));
				const int requested = opts.max_callees_per_function > 0
					? opts.max_callees_per_function : 5;
				const size_t take = (std::min)(targets->second.size(),
					static_cast<size_t>((std::min)(requested, 10000)));
				for (size_t index = 0; index < take; ++index) {
					const auto name = symbol_by_address.find(targets->second[index]);
					mapped.top_callees.push_back(name == symbol_by_address.end()
						? default_function_name(targets->second[index]) : name->second);
				}
			}
			for (const auto& section : fresh.sections) {
				if (mapped.va >= section.va && mapped.va - section.va < section.size) {
					mapped.section_name = section.name;
					break;
				}
			}
			mapped.pinned = pins.find(mapped.va) != pins.end();
			mapped.score = score_function(mapped.xref_count, mapped.callee_count, mapped.pinned);
			all_functions.push_back(std::move(mapped));
		}
		std::sort(all_functions.begin(), all_functions.end(),
			[](const auto& left, const auto& right) {
				if (left.pinned != right.pinned) return left.pinned > right.pinned;
				if (left.score != right.score) return left.score > right.score;
				if (left.xref_count != right.xref_count)
					return left.xref_count > right.xref_count;
				return left.va < right.va;
			});
		const size_t function_budget = static_cast<size_t>((std::max)(
			0, (std::min)(opts.max_functions > 0 ? opts.max_functions : 50, 100000)));
		if (all_functions.size() > function_budget) all_functions.resize(function_budget);
		fresh.functions = std::move(all_functions);
		std::map<uint64_t, map_global_t> globals;
		for (const auto& symbol : snapshot->symbols) {
			if (symbol.kind != symbol_kind_t::data) continue;
			const auto symbol_address = display_address(symbol.address);
			if (!symbol_address) continue;
			map_global_t& mapped = globals[*symbol_address];
			mapped.va = *symbol_address;
			mapped.name = symbol.name.empty()
				? default_global_name(mapped.va) : symbol.name;
		}
		if (opts.include_xrefs) {
			for (const auto& xref : snapshot->xrefs) {
				if (xref.kind == xref_kind_t::call || xref.kind == xref_kind_t::code)
					continue;
				const auto target_address = display_address(xref.target);
				if (!target_address || *target_address < fresh.image_base ||
					*target_address - fresh.image_base >= fresh.image_size)
					continue;
				map_global_t& mapped = globals[*target_address];
				mapped.va = *target_address;
				if (mapped.name.empty()) {
					const auto named = symbol_by_address.find(mapped.va);
					mapped.name = named == symbol_by_address.end()
						? default_global_name(mapped.va) : named->second;
				}
				if (mapped.xref_count < INT_MAX) ++mapped.xref_count;
			}
		}
		std::vector<map_global_t> all_globals;
		all_globals.reserve(globals.size());
		for (auto& item : globals) {
			auto& mapped = item.second;
			for (const auto& section : fresh.sections) {
				if (mapped.va >= section.va && mapped.va - section.va < section.size) {
					mapped.section_name = section.name;
					mapped.writable = section.writable;
					break;
				}
			}
			if (!mapped.section_name.empty()) all_globals.push_back(std::move(mapped));
		}
		std::sort(all_globals.begin(), all_globals.end(),
			[](const auto& left, const auto& right) {
				if (left.xref_count != right.xref_count)
					return left.xref_count > right.xref_count;
				return left.va < right.va;
			});
		const size_t global_budget = static_cast<size_t>((std::max)(
			0, (std::min)(opts.max_globals > 0 ? opts.max_globals : 30, 100000)));
		if (all_globals.size() > global_budget) all_globals.resize(global_budget);
		fresh.globals = std::move(all_globals);
		fresh.generated_unix = static_cast<int64_t>(now_unix_seconds());
		{
			std::lock_guard<std::mutex> lock(map_state->mutex);
			map_state->cached_map = fresh;
			map_state->cache_key = cache_key;
			map_state->cache_valid = true;
			map_state->error.clear();
		}
		out = std::move(fresh);
		set_last_error({});
		return true;
	}

	std::string render_text(const map_t& map, const map_options_t& opts)
	{
		std::lock_guard<std::mutex> guard(state_mutex());
		return render_text_locked(map, opts);
	}


	bool pin_function(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		uint64_t va)
	{
		auto state = workspace_map_state(workspace);
		if (!workspace || !state || va == 0) return false;
		const auto image = workspace->image();
		if (image && (va < image->image_base() ||
			va - image->image_base() >= image->image_size()))
			return false;
		std::lock_guard<std::mutex> lock(state->mutex);
		const bool inserted = state->pins.insert(va).second;
		if (inserted) state->cache_valid = false;
		return inserted;
	}

	bool unpin_function(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		uint64_t va)
	{
		auto state = workspace_map_state(workspace);
		if (!state || va == 0) return false;
		std::lock_guard<std::mutex> lock(state->mutex);
		const bool erased = state->pins.erase(va) != 0;
		if (erased) state->cache_valid = false;
		return erased;
	}

	std::vector<uint64_t> pinned_functions(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
	{
		auto state = workspace_map_state(workspace);
		if (!state) return {};
		std::lock_guard<std::mutex> lock(state->mutex);
		return std::vector<uint64_t>(state->pins.begin(), state->pins.end());
	}

	bool clear_cache(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
	{
		auto state = workspace_map_state(workspace);
		if (!state) return false;
		std::lock_guard<std::mutex> lock(state->mutex);
		state->cache_valid = false;
		state->cache_key.clear();
		state->cached_map = {};
		return true;
	}

	const std::string& last_error()
	{
		thread_local std::string snapshot;
		std::lock_guard<std::mutex> guard(state_mutex());
		snapshot = last_error_storage();
		return snapshot;
	}


	std::string auto_inject_text(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		size_t max_chars)
	{
		if (!workspace) return {};
		map_options_t opts;
		opts.max_chars = max_chars > 0 ? max_chars : 4096;
		map_t map;
		if (!generate(workspace, opts, map)) return {};
		std::string body = render_text(map, opts);
		if (body.empty()) return {};
		const std::string header = "<binary_context>\n";
		const std::string footer = "\n</binary_context>";
		const size_t reserve = header.size() + footer.size();
		if (opts.max_chars > reserve && body.size() > opts.max_chars - reserve) {
			const size_t room = opts.max_chars - reserve;
			if (room > 16) {
				body.resize(room - 16);
				body += "\n... [truncated]";
			} else {
				body.resize(room);
			}
		}
		return header + body + footer;
	}

}
}
