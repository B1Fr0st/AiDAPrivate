#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace binary_map {

	struct map_section_t
	{
		std::string name;
		uint64_t    va = 0;
		uint64_t    size = 0;
		bool        executable = false;
		bool        readable = true;
		bool        writable = false;
		float       entropy = 0.f;
		uint64_t    sampled_bytes = 0;
	};

	struct map_function_t
	{
		uint64_t                 va = 0;
		std::string              name;
		int                      xref_count = 0;
		int                      callee_count = 0;
		std::vector<std::string> top_callees;
		std::string              section_name;
		bool                     pinned = false;
		int                      score = 0;
	};

	struct map_global_t
	{
		uint64_t    va = 0;
		std::string name;
		int         xref_count = 0;
		bool        writable = false;
		std::string section_name;
	};

	struct map_options_t
	{
		int    max_functions = 50;
		int    max_globals = 30;
		int    max_callees_per_function = 5;
		size_t max_chars = 4096;
		bool   include_imports = true;
		bool   include_exports = true;
	};

	struct map_t
	{
		std::string                  module_name;
		std::string                  module_path;
		std::string                  architecture;
		std::string                  format;
		uint64_t                     image_base = 0;
		uint64_t                     image_size = 0;
		std::vector<map_section_t>   sections;
		std::vector<map_function_t>  functions;
		std::vector<map_global_t>    globals;
		std::vector<std::string>     imports;
		std::vector<std::string>     exports;
		int64_t                      generated_unix = 0;
	};

	bool                  generate(const map_options_t& opts, map_t& out);
	std::string           render_text(const map_t& map, const map_options_t& opts);
	bool                  pin_function(uint64_t va);
	bool                  unpin_function(uint64_t va);
	std::vector<uint64_t> pinned_functions();
	bool                  clear_cache();
	const std::string&    last_error();
	std::string           auto_inject_text(size_t max_chars);

}
}
