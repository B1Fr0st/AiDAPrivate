#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ghidra {
class Funcdata;
}

namespace aida_ghidra {

inline constexpr std::size_t default_max_annotations = 1U << 20;
inline constexpr std::size_t default_max_line_mappings = 1U << 20;

enum class annotation_kind_t : uint8_t
{
	none = 0,
	offset = 1,
	function_name = 2,
	syntax_keyword = 3,
	syntax_comment = 4,
	syntax_type = 5,
	syntax_funcname = 6,
	syntax_var = 7,
	syntax_const = 8,
	syntax_param = 9,
	syntax_global = 10,
	syntax_special = 11,
	global_variable = 12,
	constant_variable = 13,
	local_variable = 14,
	function_parameter = 15,
};

struct code_annotation_t
{
	annotation_kind_t kind = annotation_kind_t::none;
	size_t start = 0;
	size_t end = 0;
	uint64_t offset = 0;
	std::string name;
};

struct annotated_code_t
{
	std::string code;
	std::vector<code_annotation_t> annotations;
	std::vector<std::pair<int, uint64_t>> line_to_address;
};

bool parse_code_xml(ghidra::Funcdata* func, const std::string& xml, annotated_code_t& out,
                    std::size_t max_annotations = default_max_annotations,
                    std::size_t max_line_mappings = default_max_line_mappings,
                    std::atomic<bool>* cancel = nullptr);

}
