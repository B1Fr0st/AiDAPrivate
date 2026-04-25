#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace skills {


	struct skill_metadata_t
	{
		std::string                 name;
		std::string                 description;
		std::string                 source;
		std::vector<std::string>    agent_slugs;
		std::string                 file_path;
	};


	struct skill_content_t : skill_metadata_t
	{
		std::string instructions;
	};


	struct remote_index_entry_t
	{
		std::string                 name;
		std::string                 description;
		std::vector<std::string>    files;
	};


	struct remote_index_t
	{
		std::string                         url;
		std::vector<remote_index_entry_t>   entries;
	};


	struct skill_as_command_t
	{
		std::string                 name;
		std::string                 description;
		std::string                 template_text;
		std::vector<std::string>    placeholder_hints;
		std::string                 source_path;
		std::vector<std::string>    agent_slugs;
	};


	const std::string&  last_error();


	bool parse_yaml_frontmatter(const std::string& content, skill_metadata_t& meta, std::string& body);


	class manager_t
	{
	public:
		void                                  add_search_path(const std::string& path);
		void                                  discover();
		std::vector<skill_metadata_t>         get_all() const;
		std::vector<skill_metadata_t>         get_for_agent(const std::string& agent_slug) const;
		std::vector<skill_metadata_t>         get_for_mode(const std::string& mode_slug) const;
		skill_content_t                       resolve(const std::string& name) const;
		void                                  reload();
		bool                                  has_skill(const std::string& name) const;
		const skill_metadata_t*               find(const std::string& name) const;
		std::vector<std::string>              search_paths() const;

	private:
		mutable std::mutex                  _mtx;
		std::vector<std::string>            _search_paths;
		std::map<std::string, skill_metadata_t> _skills;
	};


	manager_t&                                  global();
	void                                        configure_default_paths(const std::string& workspace_dir);
	bool                                        reindex();

	std::vector<skill_metadata_t>               all();
	const skill_metadata_t*                     find(const std::string& name);
	skill_content_t                             resolve(const std::string& name);
	std::vector<std::string>                    placeholder_hints_for(const std::string& template_text);
	std::vector<skill_as_command_t>             all_as_commands();


	bool                                        fetch_remote_index(const std::string& url, remote_index_t& out, int timeout_ms = 10000);
	bool                                        install_remote_skill(const std::string& url, const std::string& name);
	bool                                        uninstall_remote_skill(const std::string& name);
	std::vector<std::string>                    list_remote_urls();
	bool                                        add_remote_url(const std::string& url);
	bool                                        remove_remote_url(const std::string& url);


	std::vector<const skill_metadata_t*>        available_for_agent(const std::string& agent_name);


}
}


namespace skills {

	using skill_metadata_t = ::aida::skills::skill_metadata_t;
	using skill_content_t  = ::aida::skills::skill_content_t;
	using manager_t        = ::aida::skills::manager_t;
	inline bool parse_yaml_frontmatter(const std::string& content, skill_metadata_t& meta, std::string& body)
	{
		return ::aida::skills::parse_yaml_frontmatter(content, meta, body);
	}

}


#ifdef AIDA_SKILLS_IMPLEMENTATION

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <windows.h>
#include <shlobj.h>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "agent_registry.hpp"


namespace aida {
namespace skills {

	namespace {

		std::mutex          s_error_mtx;
		std::string         s_last_error;

		std::mutex          s_remote_mtx;
		bool                s_remote_loaded = false;
		std::vector<std::string> s_remote_urls;

		std::unique_ptr<manager_t> s_manager;
		std::mutex                 s_manager_mtx;
		std::string                s_workspace_dir;


		void set_error(const std::string& msg)
		{
			std::lock_guard<std::mutex> lk(s_error_mtx);
			s_last_error = msg;
		}

		std::string trim_copy(const std::string& s)
		{
			size_t a = 0;
			size_t b = s.size();
			while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
			while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
			return s.substr(a, b - a);
		}

		std::filesystem::path appdata_root()
		{
			wchar_t* w = nullptr;
			if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &w))) {
				std::filesystem::path p = std::filesystem::path(w) / L"AiDA";
				CoTaskMemFree(w);
				return p;
			}
			return std::filesystem::current_path() / "AiDA";
		}

		std::filesystem::path aida_json_path()
		{
			return appdata_root() / L"aida.json";
		}

		std::filesystem::path skills_cache_root()
		{
			return appdata_root() / L"skills_cache";
		}

		std::filesystem::path standalone_global_skills_dir()
		{
			return appdata_root() / L"Standalone" / L"skills";
		}

		bool ensure_dir(const std::filesystem::path& p)
		{
			std::error_code ec;
			if (std::filesystem::exists(p, ec)) return true;
			ec.clear();
			std::filesystem::create_directories(p, ec);
			if (ec) {
				set_error("create_directories failed: " + ec.message());
				return false;
			}
			return true;
		}

		bool read_file_text(const std::filesystem::path& p, std::string& out)
		{
			std::ifstream ifs(p, std::ios::binary);
			if (!ifs) {
				set_error("failed to open file: " + p.string());
				return false;
			}
			std::ostringstream ss;
			ss << ifs.rdbuf();
			out = ss.str();
			return true;
		}

		bool write_file_text(const std::filesystem::path& p, const std::string& data)
		{
			std::error_code ec;
			std::filesystem::create_directories(p.parent_path(), ec);
			std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
			if (!ofs) {
				set_error("failed to write file: " + p.string());
				return false;
			}
			ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
			return ofs.good();
		}

		bool write_file_bytes(const std::filesystem::path& p, const std::vector<char>& data)
		{
			std::error_code ec;
			std::filesystem::create_directories(p.parent_path(), ec);
			std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
			if (!ofs) {
				set_error("failed to write file: " + p.string());
				return false;
			}
			if (!data.empty())
				ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
			return ofs.good();
		}

		void load_aida_json_section(nlohmann::json& root)
		{
			std::string raw;
			const auto path = aida_json_path();
			std::error_code ec;
			if (!std::filesystem::exists(path, ec)) {
				root = nlohmann::json::object();
				return;
			}
			if (!read_file_text(path, raw)) {
				root = nlohmann::json::object();
				return;
			}
			try {
				root = nlohmann::json::parse(raw);
				if (!root.is_object()) root = nlohmann::json::object();
			} catch (...) {
				root = nlohmann::json::object();
			}
		}

		bool save_aida_json(const nlohmann::json& root)
		{
			const auto path = aida_json_path();
			std::error_code ec;
			std::filesystem::create_directories(path.parent_path(), ec);
			return write_file_text(path, root.dump(2));
		}

		void load_remote_urls_locked()
		{
			if (s_remote_loaded) return;
			s_remote_loaded = true;
			s_remote_urls.clear();
			nlohmann::json root;
			load_aida_json_section(root);
			if (!root.contains("skills") || !root["skills"].is_object()) return;
			const auto& sec = root["skills"];
			if (!sec.contains("urls") || !sec["urls"].is_array()) return;
			for (const auto& u : sec["urls"]) {
				if (!u.is_string()) continue;
				const auto val = u.get<std::string>();
				if (val.empty()) continue;
				s_remote_urls.push_back(val);
			}
		}

		bool save_remote_urls_locked()
		{
			nlohmann::json root;
			load_aida_json_section(root);
			if (!root.contains("skills") || !root["skills"].is_object())
				root["skills"] = nlohmann::json::object();
			root["skills"]["urls"] = nlohmann::json::array();
			for (const auto& u : s_remote_urls)
				root["skills"]["urls"].push_back(u);
			return save_aida_json(root);
		}

		std::string sanitize_segment(const std::string& s)
		{
			std::string out;
			out.reserve(s.size());
			for (char c : s) {
				const unsigned char uc = static_cast<unsigned char>(c);
				if ((uc >= 'a' && uc <= 'z') || (uc >= 'A' && uc <= 'Z') ||
				    (uc >= '0' && uc <= '9') || uc == '-' || uc == '_' || uc == '.')
					out.push_back(static_cast<char>(uc));
				else
					out.push_back('_');
			}
			if (out.empty()) out = "_";
			return out;
		}

		bool split_url(const std::string& full, std::string& scheme, std::string& host, int& port, std::string& path_out, bool& is_https)
		{
			scheme.clear();
			host.clear();
			path_out = "/";
			port = 0;
			is_https = false;
			auto sp = full.find("://");
			if (sp == std::string::npos) {
				set_error("invalid url: " + full);
				return false;
			}
			scheme = full.substr(0, sp);
			std::string rest = full.substr(sp + 3);
			auto slash = rest.find('/');
			std::string host_port;
			if (slash == std::string::npos) {
				host_port = rest;
				path_out = "/";
			} else {
				host_port = rest.substr(0, slash);
				path_out = rest.substr(slash);
			}
			auto colon = host_port.find(':');
			if (colon == std::string::npos) {
				host = host_port;
			} else {
				host = host_port.substr(0, colon);
				try {
					port = std::stoi(host_port.substr(colon + 1));
				} catch (...) {
					set_error("invalid port in url: " + full);
					return false;
				}
			}
			if (scheme == "https") {
				is_https = true;
				if (port == 0) port = 443;
			} else if (scheme == "http") {
				is_https = false;
				if (port == 0) port = 80;
			} else {
				set_error("unsupported url scheme: " + scheme);
				return false;
			}
			if (host.empty()) {
				set_error("empty host in url: " + full);
				return false;
			}
			return true;
		}

		std::unique_ptr<httplib::Client> make_client(const std::string& host, int port, bool is_https, int timeout_ms)
		{
			std::unique_ptr<httplib::Client> cli;
			std::string base;
			if (is_https) base = "https://"; else base = "http://";
			base += host;
			base += ":";
			base += std::to_string(port);
			cli.reset(new httplib::Client(base));
			const time_t sec_part = static_cast<time_t>(timeout_ms / 1000);
			const time_t usec_part = static_cast<time_t>((timeout_ms % 1000) * 1000);
			cli->set_connection_timeout(sec_part, usec_part);
			cli->set_read_timeout(sec_part, usec_part);
			cli->set_write_timeout(sec_part, usec_part);
			cli->set_follow_location(true);
			cli->enable_server_certificate_verification(true);
			return cli;
		}

		bool http_get(const std::string& url, std::string& body_out, int timeout_ms)
		{
			std::string scheme, host, path;
			int port = 0;
			bool is_https = false;
			if (!split_url(url, scheme, host, port, path, is_https)) return false;
			auto cli = make_client(host, port, is_https, timeout_ms);
			httplib::Headers headers = {
				{ "User-Agent", "AiDA/1.0" },
				{ "Accept", "*/*" }
			};
			auto res = cli->Get(path, headers);
			if (!res) {
				set_error("http get failed: " + httplib::to_string(res.error()) + " for " + url);
				return false;
			}
			if (res->status < 200 || res->status >= 300) {
				set_error("http status " + std::to_string(res->status) + " for " + url);
				return false;
			}
			body_out = res->body;
			return true;
		}

		std::string url_join(const std::string& base, const std::string& sub)
		{
			if (sub.empty()) return base;
			if (sub.find("://") != std::string::npos) return sub;
			std::string b = base;
			if (!b.empty() && b.back() != '/') b.push_back('/');
			std::string s = sub;
			while (!s.empty() && s.front() == '/') s.erase(s.begin());
			return b + s;
		}

		std::string url_host_only(const std::string& url)
		{
			std::string scheme, host, path;
			int port = 0;
			bool is_https = false;
			if (!split_url(url, scheme, host, port, path, is_https)) return "unknown_host";
			return sanitize_segment(host);
		}

		std::filesystem::path remote_skill_dir(const std::string& url, const std::string& skill_name)
		{
			return skills_cache_root() / url_host_only(url) / sanitize_segment(skill_name);
		}

		void register_remote_dir(manager_t& mgr, const std::filesystem::path& dir)
		{
			std::error_code ec;
			if (!std::filesystem::exists(dir, ec)) return;
			mgr.add_search_path(dir.string());
		}

		void add_remote_paths_locked(manager_t& mgr)
		{
			std::error_code ec;
			const auto root = skills_cache_root();
			if (!std::filesystem::exists(root, ec)) return;
			for (const auto& host_entry : std::filesystem::directory_iterator(root, ec)) {
				if (!host_entry.is_directory()) continue;
				register_remote_dir(mgr, host_entry.path());
			}
		}

		bool walk_up_collect(const std::filesystem::path& start, std::vector<std::filesystem::path>& out)
		{
			std::error_code ec;
			std::filesystem::path cur = std::filesystem::weakly_canonical(start, ec);
			if (ec || cur.empty()) cur = start;
			out.clear();
			std::set<std::filesystem::path> seen;
			while (!cur.empty()) {
				if (seen.count(cur) > 0) break;
				seen.insert(cur);
				out.push_back(cur);
				const auto parent = cur.parent_path();
				if (parent == cur) break;
				cur = parent;
			}
			return !out.empty();
		}

		std::string body_after_frontmatter(const std::string& content)
		{
			skill_metadata_t tmp;
			std::string body;
			parse_yaml_frontmatter(content, tmp, body);
			return body;
		}

	}


	const std::string& last_error()
	{
		std::lock_guard<std::mutex> lk(s_error_mtx);
		return s_last_error;
	}


	bool parse_yaml_frontmatter(const std::string& content, skill_metadata_t& meta, std::string& body)
	{
		if (content.size() < 3 || content.substr(0, 3) != "---") {
			body = content;
			return false;
		}

		auto end_pos = content.find("\n---", 3);
		if (end_pos == std::string::npos) {
			body = content;
			return false;
		}

		std::string frontmatter = content.substr(3, end_pos - 3);
		body = content.substr(end_pos + 4);
		if (!body.empty() && body[0] == '\n') body = body.substr(1);

		std::istringstream stream(frontmatter);
		std::string line;
		while (std::getline(stream, line)) {
			if (!line.empty() && line.back() == '\r') line.pop_back();

			auto colon_pos = line.find(':');
			if (colon_pos == std::string::npos) continue;

			std::string key = line.substr(0, colon_pos);
			std::string value = line.substr(colon_pos + 1);

			key = trim_copy(key);
			value = trim_copy(value);

			if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
				value = value.substr(1, value.size() - 2);
			else if (value.size() >= 2 && value.front() == '\'' && value.back() == '\'')
				value = value.substr(1, value.size() - 2);

			if (key == "name") {
				meta.name = value;
			} else if (key == "description") {
				meta.description = value;
			} else if (key == "agent_slugs" || key == "agentSlugs" ||
			           key == "mode_slugs" || key == "modeSlugs") {
				meta.agent_slugs.clear();
				if (value.size() >= 2 && value.front() == '[' && value.back() == ']')
					value = value.substr(1, value.size() - 2);
				std::istringstream vs(value);
				std::string item;
				while (std::getline(vs, item, ',')) {
					item = trim_copy(item);
					if (item.size() >= 2 && item.front() == '"' && item.back() == '"')
						item = item.substr(1, item.size() - 2);
					else if (item.size() >= 2 && item.front() == '\'' && item.back() == '\'')
						item = item.substr(1, item.size() - 2);
					if (!item.empty())
						meta.agent_slugs.push_back(item);
				}
			}
		}

		return true;
	}


	void manager_t::add_search_path(const std::string& path)
	{
		std::lock_guard<std::mutex> lk(_mtx);
		for (const auto& existing : _search_paths) {
			if (existing == path) return;
		}
		_search_paths.push_back(path);
	}


	void manager_t::discover()
	{
		std::vector<std::string> paths;
		{
			std::lock_guard<std::mutex> lk(_mtx);
			paths = _search_paths;
		}

		std::map<std::string, skill_metadata_t> found;
		std::error_code ec;

		for (const auto& base : paths) {
			std::filesystem::path base_path(base);
			if (!std::filesystem::exists(base_path, ec)) continue;
			ec.clear();

			std::error_code iter_ec;
			for (auto it = std::filesystem::recursive_directory_iterator(base_path,
			         std::filesystem::directory_options::skip_permission_denied, iter_ec);
			     it != std::filesystem::recursive_directory_iterator(); ++it) {
				if (iter_ec) { iter_ec.clear(); break; }
				bool is_file = it->is_regular_file(iter_ec);
				if (iter_ec) { iter_ec.clear(); is_file = false; }
				if (!is_file) continue;
				if (it->path().filename() != "SKILL.md") continue;

				std::string content;
				if (!read_file_text(it->path(), content)) continue;

				skill_metadata_t meta;
				std::string body;
				parse_yaml_frontmatter(content, meta, body);

				if (meta.name.empty())
					meta.name = it->path().parent_path().filename().string();
				meta.file_path = it->path().string();

				if (meta.description.empty())
					meta.description = "Skill: " + meta.name;

				const auto src_str = it->path().string();
				const auto cache_root = skills_cache_root().string();
				const auto global_dir = standalone_global_skills_dir().string();
				if (!cache_root.empty() && src_str.find(cache_root) == 0)
					meta.source = "remote";
				else if (!global_dir.empty() && src_str.find(global_dir) == 0)
					meta.source = "global";
				else if (src_str.find("AppData") != std::string::npos || src_str.find("appdata") != std::string::npos)
					meta.source = "global";
				else
					meta.source = "project";

				if (found.find(meta.name) == found.end())
					found.emplace(meta.name, std::move(meta));
			}
		}

		std::lock_guard<std::mutex> lk(_mtx);
		_skills = std::move(found);
	}


	std::vector<skill_metadata_t> manager_t::get_all() const
	{
		std::vector<skill_metadata_t> out;
		std::lock_guard<std::mutex> lk(_mtx);
		out.reserve(_skills.size());
		for (const auto& kv : _skills) out.push_back(kv.second);
		std::sort(out.begin(), out.end(), [](const skill_metadata_t& a, const skill_metadata_t& b) {
			return a.name < b.name;
		});
		return out;
	}


	std::vector<skill_metadata_t> manager_t::get_for_agent(const std::string& agent_slug) const
	{
		std::vector<skill_metadata_t> out;
		std::lock_guard<std::mutex> lk(_mtx);
		for (const auto& kv : _skills) {
			const auto& m = kv.second;
			if (m.agent_slugs.empty()) {
				out.push_back(m);
			} else {
				for (const auto& slug : m.agent_slugs) {
					if (slug == agent_slug) {
						out.push_back(m);
						break;
					}
				}
			}
		}
		std::sort(out.begin(), out.end(), [](const skill_metadata_t& a, const skill_metadata_t& b) {
			return a.name < b.name;
		});
		return out;
	}


	std::vector<skill_metadata_t> manager_t::get_for_mode(const std::string& mode_slug) const
	{
		return get_for_agent(mode_slug);
	}


	skill_content_t manager_t::resolve(const std::string& name) const
	{
		skill_content_t sc;
		std::string file_path;
		{
			std::lock_guard<std::mutex> lk(_mtx);
			auto it = _skills.find(name);
			if (it == _skills.end()) return sc;
			static_cast<skill_metadata_t&>(sc) = it->second;
			file_path = it->second.file_path;
		}

		std::string content;
		if (!read_file_text(file_path, content)) return sc;
		sc.instructions = body_after_frontmatter(content);
		return sc;
	}


	void manager_t::reload() { discover(); }


	bool manager_t::has_skill(const std::string& name) const
	{
		std::lock_guard<std::mutex> lk(_mtx);
		return _skills.count(name) > 0;
	}


	const skill_metadata_t* manager_t::find(const std::string& name) const
	{
		std::lock_guard<std::mutex> lk(_mtx);
		auto it = _skills.find(name);
		if (it == _skills.end()) return nullptr;
		return &it->second;
	}


	std::vector<std::string> manager_t::search_paths() const
	{
		std::lock_guard<std::mutex> lk(_mtx);
		return _search_paths;
	}


	manager_t& global()
	{
		std::lock_guard<std::mutex> lk(s_manager_mtx);
		if (!s_manager) s_manager.reset(new manager_t());
		return *s_manager;
	}


	void configure_default_paths(const std::string& workspace_dir)
	{
		auto& mgr = global();

		std::set<std::string> existing;
		for (const auto& p : mgr.search_paths()) existing.insert(p);

		auto add_if_dir = [&](const std::filesystem::path& p) {
			std::error_code ec;
			if (!std::filesystem::exists(p, ec)) return;
			if (!std::filesystem::is_directory(p, ec)) return;
			const auto s = p.string();
			if (existing.count(s) == 0) {
				mgr.add_search_path(s);
				existing.insert(s);
			}
		};

		add_if_dir(standalone_global_skills_dir());

		const auto home_appdata = appdata_root();
		add_if_dir(home_appdata / L".aida" / L"skills");
		add_if_dir(home_appdata / L".claude" / L"skills");

		{
			std::lock_guard<std::mutex> lk(s_manager_mtx);
			s_workspace_dir = workspace_dir;
		}

		std::vector<std::filesystem::path> chain;
		if (!workspace_dir.empty())
			walk_up_collect(std::filesystem::path(workspace_dir), chain);

		std::vector<std::filesystem::path> aida_first;
		std::vector<std::filesystem::path> claude_second;
		for (const auto& dir : chain) {
			const auto aida_dir = dir / ".aida" / "skills";
			const auto claude_dir = dir / ".claude" / "skills";
			std::error_code ec;
			if (std::filesystem::exists(aida_dir, ec) && std::filesystem::is_directory(aida_dir, ec))
				aida_first.push_back(aida_dir);
			ec.clear();
			if (std::filesystem::exists(claude_dir, ec) && std::filesystem::is_directory(claude_dir, ec))
				claude_second.push_back(claude_dir);
		}
		for (const auto& p : aida_first) add_if_dir(p);
		for (const auto& p : claude_second) add_if_dir(p);

		add_remote_paths_locked(mgr);

		mgr.discover();
	}


	bool reindex()
	{
		auto& mgr = global();
		mgr.discover();
		return true;
	}


	std::vector<skill_metadata_t> all()
	{
		return global().get_all();
	}


	const skill_metadata_t* find(const std::string& name)
	{
		return global().find(name);
	}


	skill_content_t resolve(const std::string& name)
	{
		return global().resolve(name);
	}


	std::vector<std::string> placeholder_hints_for(const std::string& template_text)
	{
		std::vector<std::string> result;
		std::set<std::string> seen;
		const char* p = template_text.c_str();
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


	std::vector<skill_as_command_t> all_as_commands()
	{
		std::vector<skill_as_command_t> out;
		auto& mgr = global();
		auto list = mgr.get_all();
		out.reserve(list.size());
		for (const auto& meta : list) {
			std::string content;
			if (!read_file_text(std::filesystem::path(meta.file_path), content)) continue;
			std::string body = body_after_frontmatter(content);

			skill_as_command_t rec;
			rec.name = meta.name;
			rec.description = meta.description;
			rec.template_text = body;
			rec.placeholder_hints = placeholder_hints_for(body);
			rec.source_path = meta.file_path;
			rec.agent_slugs = meta.agent_slugs;
			out.push_back(std::move(rec));
		}
		return out;
	}


	bool fetch_remote_index(const std::string& url, remote_index_t& out, int timeout_ms)
	{
		out.url = url;
		out.entries.clear();

		std::string index_url = url;
		const bool ends_with_json = index_url.size() >= 5 &&
			index_url.compare(index_url.size() - 5, 5, ".json") == 0;
		if (!ends_with_json) {
			if (index_url.empty() || index_url.back() != '/') index_url.push_back('/');
			index_url += "index.json";
		}

		std::string body;
		if (!http_get(index_url, body, timeout_ms)) return false;

		try {
			auto root = nlohmann::json::parse(body);
			if (!root.is_object() || !root.contains("skills") || !root["skills"].is_array()) {
				set_error("remote index missing 'skills' array");
				return false;
			}
			for (const auto& sj : root["skills"]) {
				if (!sj.is_object()) continue;
				remote_index_entry_t entry;
				if (sj.contains("name") && sj["name"].is_string())
					entry.name = sj["name"].get<std::string>();
				if (entry.name.empty()) continue;
				if (sj.contains("description") && sj["description"].is_string())
					entry.description = sj["description"].get<std::string>();
				bool has_skill_md = false;
				if (sj.contains("files") && sj["files"].is_array()) {
					for (const auto& fj : sj["files"]) {
						if (!fj.is_string()) continue;
						const auto f = fj.get<std::string>();
						if (f.empty()) continue;
						entry.files.push_back(f);
						if (f == "SKILL.md") has_skill_md = true;
					}
				}
				if (!has_skill_md) {
					set_error("skill entry missing SKILL.md: " + entry.name);
					continue;
				}
				out.entries.push_back(std::move(entry));
			}
		} catch (const std::exception& e) {
			set_error(std::string("failed to parse remote index: ") + e.what());
			return false;
		}
		return true;
	}


	bool install_remote_skill(const std::string& url, const std::string& name)
	{
		remote_index_t idx;
		if (!fetch_remote_index(url, idx, 15000)) return false;

		const remote_index_entry_t* match = nullptr;
		for (const auto& e : idx.entries) {
			if (e.name == name) { match = &e; break; }
		}
		if (match == nullptr) {
			set_error("skill not found in remote index: " + name);
			return false;
		}

		std::string base = url;
		const bool ends_with_json = base.size() >= 5 &&
			base.compare(base.size() - 5, 5, ".json") == 0;
		if (ends_with_json) {
			auto last_slash = base.find_last_of('/');
			if (last_slash != std::string::npos) base = base.substr(0, last_slash + 1);
		} else if (!base.empty() && base.back() != '/') {
			base.push_back('/');
		}

		const auto root_dir = remote_skill_dir(url, name);
		if (!ensure_dir(root_dir)) return false;

		bool got_skill_md = false;
		for (const auto& file_rel : match->files) {
			const std::string file_url = url_join(base + sanitize_segment(name) + "/", file_rel);
			std::string body;
			if (!http_get(file_url, body, 30000)) {
				set_error("download failed: " + file_url);
				return false;
			}
			std::vector<char> bytes(body.begin(), body.end());
			const auto out_path = root_dir / file_rel;
			if (!write_file_bytes(out_path, bytes)) return false;
			if (file_rel == "SKILL.md") got_skill_md = true;
		}
		if (!got_skill_md) {
			set_error("install completed but SKILL.md not present for: " + name);
			return false;
		}

		auto& mgr = global();
		mgr.add_search_path(skills_cache_root().string());
		mgr.discover();
		return true;
	}


	bool uninstall_remote_skill(const std::string& name)
	{
		std::error_code ec;
		const auto root = skills_cache_root();
		if (!std::filesystem::exists(root, ec)) {
			set_error("skills_cache root not found");
			return false;
		}
		bool removed_any = false;
		for (const auto& host_entry : std::filesystem::directory_iterator(root, ec)) {
			if (!host_entry.is_directory()) continue;
			const auto candidate = host_entry.path() / sanitize_segment(name);
			if (std::filesystem::exists(candidate, ec) && std::filesystem::is_directory(candidate, ec)) {
				std::filesystem::remove_all(candidate, ec);
				if (!ec) removed_any = true;
			}
			ec.clear();
		}
		if (!removed_any) {
			set_error("no installed remote skill found: " + name);
			return false;
		}
		auto& mgr = global();
		mgr.discover();
		return true;
	}


	std::vector<std::string> list_remote_urls()
	{
		std::lock_guard<std::mutex> lk(s_remote_mtx);
		load_remote_urls_locked();
		return s_remote_urls;
	}


	bool add_remote_url(const std::string& url)
	{
		std::lock_guard<std::mutex> lk(s_remote_mtx);
		load_remote_urls_locked();
		const auto trimmed = trim_copy(url);
		if (trimmed.empty()) {
			set_error("add_remote_url: empty url");
			return false;
		}
		for (const auto& u : s_remote_urls) {
			if (u == trimmed) return true;
		}
		s_remote_urls.push_back(trimmed);
		if (!save_remote_urls_locked()) return false;
		return true;
	}


	bool remove_remote_url(const std::string& url)
	{
		std::lock_guard<std::mutex> lk(s_remote_mtx);
		load_remote_urls_locked();
		const auto before = s_remote_urls.size();
		s_remote_urls.erase(
			std::remove(s_remote_urls.begin(), s_remote_urls.end(), url),
			s_remote_urls.end());
		if (s_remote_urls.size() == before) {
			set_error("url not found: " + url);
			return false;
		}
		return save_remote_urls_locked();
	}


	std::vector<const skill_metadata_t*> available_for_agent(const std::string& agent_name)
	{
		std::vector<const skill_metadata_t*> out;
		auto& mgr = global();

		const ::aida::agent::agent_info_t* agent = ::aida::agent::get(agent_name);

		std::vector<skill_metadata_t> snapshot = mgr.get_all();
		std::sort(snapshot.begin(), snapshot.end(), [](const skill_metadata_t& a, const skill_metadata_t& b) {
			return a.name < b.name;
		});

		for (const auto& meta : snapshot) {
			const auto* live = mgr.find(meta.name);
			if (live == nullptr) continue;

			if (!live->agent_slugs.empty() && !agent_name.empty()) {
				bool match = false;
				for (const auto& slug : live->agent_slugs) {
					if (slug == agent_name) { match = true; break; }
				}
				if (!match) continue;
			}

			if (agent != nullptr) {
				const auto act_name = ::aida::agent::evaluate_ruleset(
					agent->permissions, "skill", live->name);
				if (act_name == ::aida::agent::permission_rule_t::action_t::deny) continue;

				const auto act_path = ::aida::agent::evaluate_ruleset(
					agent->permissions, "skill_path", live->file_path);
				if (act_path == ::aida::agent::permission_rule_t::action_t::deny) continue;
			}

			out.push_back(live);
		}
		return out;
	}


}
}

#endif
