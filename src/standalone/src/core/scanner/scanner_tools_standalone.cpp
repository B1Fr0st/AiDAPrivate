
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "memory_scanner.hpp"
#include "obfuscation.hpp"
#include "struct_dissector.hpp"
#include "../helpers/diag_log.hpp"

#include <cinttypes>
#include <sstream>
#include <string>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace scanner_tools {


static memory_scanner::value_type_t parse_value_type(const std::string& s) {
	if (s == "byte")    return memory_scanner::value_type_t::byte_val;
	if (s == "int16")   return memory_scanner::value_type_t::int16_val;
	if (s == "int32")   return memory_scanner::value_type_t::int32_val;
	if (s == "int64")   return memory_scanner::value_type_t::int64_val;
	if (s == "float")   return memory_scanner::value_type_t::float_val;
	if (s == "double")  return memory_scanner::value_type_t::double_val;
	if (s == "string" || s == "ascii")  return memory_scanner::value_type_t::string_ascii;
	if (s == "utf16" || s == "wstring") return memory_scanner::value_type_t::string_utf16;
	if (s == "aob" || s == "byte_array") return memory_scanner::value_type_t::byte_array;
	return memory_scanner::value_type_t::int32_val;
}

static memory_scanner::scan_mode_t parse_scan_mode(const std::string& s) {
	if (s == "exact")      return memory_scanner::scan_mode_t::exact;
	if (s == "bigger")     return memory_scanner::scan_mode_t::bigger_than;
	if (s == "smaller")    return memory_scanner::scan_mode_t::smaller_than;
	if (s == "between")    return memory_scanner::scan_mode_t::value_between;
	if (s == "changed")    return memory_scanner::scan_mode_t::changed;
	if (s == "unchanged")  return memory_scanner::scan_mode_t::unchanged;
	if (s == "increased")  return memory_scanner::scan_mode_t::increased;
	if (s == "decreased")  return memory_scanner::scan_mode_t::decreased;
	if (s == "unknown")    return memory_scanner::scan_mode_t::unknown_initial;
	return memory_scanner::scan_mode_t::exact;
}

static std::string results_to_json(size_t limit = 100) {
	auto& st = memory_scanner::g_state;
	std::lock_guard<std::mutex> lk(st.results_mutex);

	json arr = json::array();
	size_t n = std::min(st.results.size(), limit);
	for (size_t i = 0; i < n; ++i) {
		auto& r = st.results[i];
		json obj;
		char buf[20];
		snprintf(buf, sizeof(buf), "0x%" PRIX64, r.address);
		obj["address"] = buf;
		obj["value"] = memory_scanner::format_value(r.current_value, st.config.value_type);
		if (!r.previous_value.empty())
			obj["previous"] = memory_scanner::format_value(r.previous_value, st.config.value_type);
		if (!r.module_name.empty()) {
			snprintf(buf, sizeof(buf), "0x%" PRIX64, r.module_offset);
			obj["module"] = r.module_name + "+" + buf;
		}
		arr.push_back(std::move(obj));
	}

	json result;
	result["total_found"] = st.total_found;
	result["showing"] = n;
	result["scan_count"] = st.scan_count;
	result["results"] = std::move(arr);
	return result.dump(2);
}


static tool_result_t handle_first_scan(const json& params) {
	memory_scanner::scan_config_t cfg;

	if (params.contains("value_type"))
		cfg.value_type = parse_value_type(params["value_type"].get<std::string>());
	if (params.contains("scan_mode"))
		cfg.scan_mode = parse_scan_mode(params["scan_mode"].get<std::string>());
	if (params.contains("value"))
		cfg.value_text = params["value"].get<std::string>();
	if (params.contains("value2"))
		cfg.value_text2 = params["value2"].get<std::string>();
	if (params.contains("hex") && params["hex"].is_boolean())
		cfg.hex_input = params["hex"].get<bool>();
	if (params.contains("writable_only") && params["writable_only"].is_boolean())
		cfg.writable_only = params["writable_only"].get<bool>();
	if (params.contains("alignment") && params["alignment"].is_number())
		cfg.alignment = params["alignment"].get<size_t>();

	diag::log_tagged_fmt("scanner", "mcp first_scan request value='%s' type=%s mode=%s",
		cfg.value_text.c_str(),
		memory_scanner::value_type_name(cfg.value_type),
		memory_scanner::scan_mode_name(cfg.scan_mode));

	if (!memory_scanner::first_scan(cfg)) {
		diag::log_tagged("scanner", "mcp first_scan refused");
		return tool_result_t::error(OBFSTR("Scanner busy or not attached to a process."));
	}


	for (int i = 0; i < 300; ++i) {
		if (!memory_scanner::g_state.scanning.load()) break;
		Sleep(100);
	}

	diag::log_tagged_fmt("scanner", "mcp first_scan completed total=%zu",
		memory_scanner::g_state.total_found);

	return tool_result_t::ok(results_to_json());
}

static tool_result_t handle_next_scan(const json& params) {
	auto mode = memory_scanner::scan_mode_t::exact;
	std::string val, val2;

	if (params.contains("scan_mode"))
		mode = parse_scan_mode(params["scan_mode"].get<std::string>());
	if (params.contains("value"))
		val = params["value"].get<std::string>();
	if (params.contains("value2"))
		val2 = params["value2"].get<std::string>();

	diag::log_tagged_fmt("scanner", "mcp next_scan request mode=%s val='%s'",
		memory_scanner::scan_mode_name(mode), val.c_str());

	if (!memory_scanner::next_scan(mode, val, val2)) {
		diag::log_tagged("scanner", "mcp next_scan refused");
		return tool_result_t::error(OBFSTR("Scanner busy or no initial scan performed."));
	}

	for (int i = 0; i < 300; ++i) {
		if (!memory_scanner::g_state.scanning.load()) break;
		Sleep(100);
	}

	diag::log_tagged_fmt("scanner", "mcp next_scan completed total=%zu",
		memory_scanner::g_state.total_found);

	return tool_result_t::ok(results_to_json());
}

static tool_result_t handle_get_results(const json& params) {
	size_t limit = 100;
	if (params.contains("limit") && params["limit"].is_number())
		limit = params["limit"].get<size_t>();
	return tool_result_t::ok(results_to_json(limit));
}

static tool_result_t handle_reset_scan(const json&) {
	memory_scanner::reset_scan();
	return tool_result_t::ok(OBFSTR("Scanner reset."));
}

static tool_result_t handle_undo_scan(const json&) {
	memory_scanner::undo_scan();
	auto& st = memory_scanner::g_state;
	json result;
	result["total_found"] = st.total_found;
	result["scan_count"] = st.scan_count;
	return tool_result_t::ok(result.dump());
}

static tool_result_t handle_add_address(const json& params) {
	if (!params.contains("address"))
		return tool_result_t::error(OBFSTR("Missing 'address' parameter."));

	uint64_t addr = 0;
	auto& v = params["address"];
	if (v.is_string()) {
		auto parsed = sa_parse_address(v.get<std::string>());
		if (!parsed) return tool_result_t::error(OBFSTR("Invalid address format."));
		addr = *parsed;
	} else if (v.is_number()) {
		addr = v.get<uint64_t>();
	}

	std::string desc;
	if (params.contains("description"))
		desc = params["description"].get<std::string>();

	auto vtype = memory_scanner::value_type_t::int32_val;
	if (params.contains("value_type"))
		vtype = parse_value_type(params["value_type"].get<std::string>());

	memory_scanner::add_address(addr, desc, vtype);

	char buf[20];
	snprintf(buf, sizeof(buf), "0x%" PRIX64, addr);
	return tool_result_t::ok(std::string(OBFSTR("Address ")) + buf + OBFSTR(" added to list."));
}

static tool_result_t handle_remove_address(const json& params) {
	if (!params.contains("index"))
		return tool_result_t::error(OBFSTR("Missing 'index' parameter."));
	size_t idx = params["index"].get<size_t>();
	memory_scanner::remove_address(idx);
	return tool_result_t::ok(OBFSTR("Address removed."));
}

static tool_result_t handle_freeze_address(const json& params) {
	if (!params.contains("index"))
		return tool_result_t::error(OBFSTR("Missing 'index' parameter."));
	size_t idx = params["index"].get<size_t>();
	bool enable = true;
	if (params.contains("enable") && params["enable"].is_boolean())
		enable = params["enable"].get<bool>();
	memory_scanner::freeze_address(idx, enable);
	return tool_result_t::ok(enable ? OBFSTR("Address frozen.") : OBFSTR("Address unfrozen."));
}

static tool_result_t handle_read_value(const json& params) {
	if (!params.contains("address"))
		return tool_result_t::error(OBFSTR("Missing 'address' parameter."));

	uint64_t addr = 0;
	auto& v = params["address"];
	if (v.is_string()) {
		auto parsed = sa_parse_address(v.get<std::string>());
		if (!parsed) return tool_result_t::error(OBFSTR("Invalid address format."));
		addr = *parsed;
	} else if (v.is_number()) {
		addr = v.get<uint64_t>();
	}

	auto vtype = memory_scanner::value_type_t::int32_val;
	if (params.contains("value_type"))
		vtype = parse_value_type(params["value_type"].get<std::string>());

	std::string result = memory_scanner::read_value_string(addr, vtype);
	json obj;
	char abuf[20];
	snprintf(abuf, sizeof(abuf), "0x%" PRIX64, addr);
	obj["address"] = abuf;
	obj["type"] = memory_scanner::value_type_name(vtype);
	obj["value"] = result;
	return tool_result_t::ok(obj.dump(2));
}

static tool_result_t handle_get_address_list(const json&) {
	auto& st = memory_scanner::g_state;
	memory_scanner::refresh_address_list();

	std::lock_guard<std::mutex> lk(st.address_mutex);
	json arr = json::array();
	for (size_t i = 0; i < st.address_list.size(); ++i) {
		auto& e = st.address_list[i];
		json obj;
		obj["index"] = i;
		char buf[20];
		snprintf(buf, sizeof(buf), "0x%" PRIX64, e.address);
		obj["address"] = buf;
		obj["description"] = e.description;
		obj["type"] = memory_scanner::value_type_name(e.value_type);
		obj["frozen"] = e.frozen;
		obj["value"] = memory_scanner::format_value(e.last_value, e.value_type);
		arr.push_back(std::move(obj));
	}
	return tool_result_t::ok(arr.dump(2));
}

static tool_result_t handle_pointer_scan(const json& params) {
	if (!params.contains("address"))
		return tool_result_t::error(OBFSTR("Missing 'address' parameter."));

	uint64_t addr = 0;
	auto& v = params["address"];
	if (v.is_string()) {
		auto parsed = sa_parse_address(v.get<std::string>());
		if (!parsed) return tool_result_t::error(OBFSTR("Invalid address format."));
		addr = *parsed;
	} else if (v.is_number()) {
		addr = v.get<uint64_t>();
	}

	int max_depth = 4, max_offset = 0x1000;
	if (params.contains("max_depth") && params["max_depth"].is_number())
		max_depth = params["max_depth"].get<int>();
	if (params.contains("max_offset") && params["max_offset"].is_number())
		max_offset = params["max_offset"].get<int>();

	diag::log_tagged_fmt("scanner", "mcp pointer_scan request addr=0x%llX depth=%d offset=0x%X",
		static_cast<unsigned long long>(addr), max_depth, max_offset);

	memory_scanner::start_pointer_scan(addr, max_depth, max_offset);

	for (int i = 0; i < 600; ++i) {
		if (!memory_scanner::g_state.pointer_scanning.load()) break;
		Sleep(100);
	}

	auto& st = memory_scanner::g_state;
	std::lock_guard<std::mutex> lk(st.pointer_mutex);

	json arr = json::array();
	size_t n = std::min(st.pointer_results.size(), static_cast<size_t>(200));
	for (size_t i = 0; i < n; ++i) {
		auto& p = st.pointer_results[i];
		json obj;
		char buf[20];
		snprintf(buf, sizeof(buf), "0x%" PRIX64, p.base_address);
		obj["base"] = buf;
		if (!p.module_name.empty()) {
			snprintf(buf, sizeof(buf), "0x%" PRIX64, p.module_offset);
			obj["module"] = p.module_name + "+" + buf;
		}
		json offsets = json::array();
		for (auto off : p.offsets)
			offsets.push_back(off);
		obj["offsets"] = std::move(offsets);
		arr.push_back(std::move(obj));
	}

	json result;
	result["total"] = st.pointer_results.size();
	result["showing"] = n;
	result["results"] = std::move(arr);
	return tool_result_t::ok(result.dump(2));
}

static tool_result_t handle_write_value(const json& params) {
	if (!params.contains("address") || !params.contains("value"))
		return tool_result_t::error(OBFSTR("Missing 'address' or 'value' parameter."));

	uint64_t addr = 0;
	auto& v = params["address"];
	if (v.is_string()) {
		auto parsed = sa_parse_address(v.get<std::string>());
		if (!parsed) return tool_result_t::error(OBFSTR("Invalid address format."));
		addr = *parsed;
	} else if (v.is_number()) {
		addr = v.get<uint64_t>();
	}

	auto vtype = memory_scanner::value_type_t::int32_val;
	if (params.contains("value_type"))
		vtype = parse_value_type(params["value_type"].get<std::string>());

	bool hex = false;
	if (params.contains("hex") && params["hex"].is_boolean())
		hex = params["hex"].get<bool>();

	std::string val_str = params["value"].get<std::string>();

	memory_scanner::write_value(addr, vtype, val_str, hex);

	return tool_result_t::ok(OBFSTR("Value written successfully."));
}


void register_scanner_tools(mcp_standalone::server_t& srv) {

	register_compat(srv, {OBFSTR("scanner_first_scan"), OBFSTR("memory_scanner"),
		OBFSTR("Start a new memory scan. Scans all committed memory of the attached process for values matching the criteria. Operates on the currently active binary_id session; pass binary_id explicitly in multi-target sessions."),
		{{OBFSTR("value"), OBFSTR("string"), OBFSTR("Value to search for"), true},
		 {OBFSTR("value_type"), OBFSTR("string"), OBFSTR("Type: byte/int16/int32/int64/float/double/ascii/utf16/aob"), false},
		 {OBFSTR("scan_mode"), OBFSTR("string"), OBFSTR("Mode: exact/bigger/smaller/between/unknown"), false},
		 {OBFSTR("value2"), OBFSTR("string"), OBFSTR("Second value for 'between' mode"), false},
		 {OBFSTR("hex"), OBFSTR("boolean"), OBFSTR("Interpret value as hexadecimal"), false},
		 {OBFSTR("writable_only"), OBFSTR("boolean"), OBFSTR("Only scan writable pages (default true)"), false},
		 {OBFSTR("alignment"), OBFSTR("number"), OBFSTR("Scan alignment in bytes (default: type size)"), false}},
		handle_first_scan, false});

	register_compat(srv, {OBFSTR("scanner_next_scan"), OBFSTR("memory_scanner"),
		OBFSTR("Refine previous scan results by applying a new comparison. Narrows down results from the last scan."),
		{{OBFSTR("scan_mode"), OBFSTR("string"), OBFSTR("Mode: exact/bigger/smaller/between/changed/unchanged/increased/decreased"), true},
		 {OBFSTR("value"), OBFSTR("string"), OBFSTR("Value for comparison (not needed for changed/unchanged/increased/decreased)"), false},
		 {OBFSTR("value2"), OBFSTR("string"), OBFSTR("Second value for 'between' mode"), false}},
		handle_next_scan, false});

	register_compat(srv, {OBFSTR("scanner_get_results"), OBFSTR("memory_scanner"),
		OBFSTR("Get current scan results. Returns addresses, values, and module info."),
		{{OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum results to return (default 100)"), false}},
		handle_get_results, true});

	register_compat(srv, {OBFSTR("scanner_reset"), OBFSTR("memory_scanner"),
		OBFSTR("Reset the scanner, clearing all results and scan history."),
		{}, handle_reset_scan, false});

	register_compat(srv, {OBFSTR("scanner_undo"), OBFSTR("memory_scanner"),
		OBFSTR("Undo the last scan refinement, restoring previous results."),
		{}, handle_undo_scan, false});

	register_compat(srv, {OBFSTR("scanner_add_address"), OBFSTR("memory_scanner"),
		OBFSTR("Add an address to the watch/address list for monitoring."),
		{{OBFSTR("address"), OBFSTR("string"), OBFSTR("Memory address (hex)"), true},
		 {OBFSTR("description"), OBFSTR("string"), OBFSTR("Description label"), false},
		 {OBFSTR("value_type"), OBFSTR("string"), OBFSTR("Type: byte/int16/int32/int64/float/double/ascii/utf16"), false}},
		handle_add_address, false});

	register_compat(srv, {OBFSTR("scanner_remove_address"), OBFSTR("memory_scanner"),
		OBFSTR("Remove an address from the watch list by index."),
		{{OBFSTR("index"), OBFSTR("number"), OBFSTR("Index in the address list"), true}},
		handle_remove_address, false});

	register_compat(srv, {OBFSTR("scanner_freeze_address"), OBFSTR("memory_scanner"),
		OBFSTR("Freeze or unfreeze an address to keep its value constant."),
		{{OBFSTR("index"), OBFSTR("number"), OBFSTR("Index in the address list"), true},
		 {OBFSTR("enable"), OBFSTR("boolean"), OBFSTR("True to freeze, false to unfreeze"), false}},
		handle_freeze_address, false});

	register_compat(srv, {OBFSTR("scanner_read_value"), OBFSTR("memory_scanner"),
		OBFSTR("Read the current value at a memory address."),
		{{OBFSTR("address"), OBFSTR("string"), OBFSTR("Memory address (hex)"), true},
		 {OBFSTR("value_type"), OBFSTR("string"), OBFSTR("Type: byte/int16/int32/int64/float/double/ascii/utf16"), false}},
		handle_read_value, true});

	register_compat(srv, {OBFSTR("scanner_write_value"), OBFSTR("memory_scanner"),
		OBFSTR("Write a value to a memory address in the attached process."),
		{{OBFSTR("address"), OBFSTR("string"), OBFSTR("Memory address (hex)"), true},
		 {OBFSTR("value"), OBFSTR("string"), OBFSTR("Value to write"), true},
		 {OBFSTR("value_type"), OBFSTR("string"), OBFSTR("Type: byte/int16/int32/int64/float/double"), false},
		 {OBFSTR("hex"), OBFSTR("boolean"), OBFSTR("Interpret value as hex"), false}},
		handle_write_value, false});

	register_compat(srv, {OBFSTR("scanner_get_address_list"), OBFSTR("memory_scanner"),
		OBFSTR("Get all entries in the address watch list with current values."),
		{}, handle_get_address_list, true});

	register_compat(srv, {OBFSTR("scanner_pointer_scan"), OBFSTR("memory_scanner"),
		OBFSTR("Perform a pointer scan to find pointer chains that lead to the target address. Useful for finding stable pointers. Operates on the currently active binary_id session; pass binary_id explicitly in multi-target sessions."),
		{{OBFSTR("address"), OBFSTR("string"), OBFSTR("Target address to find pointers to"), true},
		 {OBFSTR("max_depth"), OBFSTR("number"), OBFSTR("Maximum pointer chain depth (1-7, default 4)"), false},
		 {OBFSTR("max_offset"), OBFSTR("number"), OBFSTR("Maximum offset from pointer base (default 0x1000)"), false}},
		handle_pointer_scan, true});

	register_compat(srv, {OBFSTR("scanner_cancel_pointer_scan"), OBFSTR("memory_scanner"),
		OBFSTR("Cancel a running pointer scan."),
		{},
		[](const json&) -> tool_result_t {
			memory_scanner::cancel_pointer_scan();
			return tool_result_t::ok(OBFSTR("Pointer scan cancelled."));
		}, false});

	register_compat(srv, {OBFSTR("scanner_define_struct"), OBFSTR("memory_scanner"),
		OBFSTR("Define a new structure for memory analysis at a base address."),
		{{OBFSTR("name"), OBFSTR("string"), OBFSTR("Structure name"), true},
		 {OBFSTR("base_address"), OBFSTR("string"), OBFSTR("Base address for live reading (hex)"), true}},
		[](const json& params) -> tool_result_t {
			if (!params.contains("name") || !params["name"].is_string())
				return tool_result_t::error(OBFSTR("'name' is required."));
			if (!params.contains("base_address") || !params["base_address"].is_string())
				return tool_result_t::error(OBFSTR("'base_address' is required."));
			auto addr = sa_parse_address(params["base_address"].get<std::string>());
			if (!addr) return tool_result_t::error(OBFSTR("Invalid base_address."));
			int idx = struct_dissector::create_struct(params["name"].get<std::string>());
			if (idx < 0)
				return tool_result_t::error(OBFSTR("Failed to create struct."));
			{
				std::lock_guard<std::mutex> lk(struct_dissector::g_state.mtx);
				struct_dissector::g_state.active_struct = idx;
				struct_dissector::g_state.base_address = *addr;
			}
			json result;
			result["struct_index"] = idx;
			result["name"] = params["name"].get<std::string>();
			result["base_address"] = sa_format_address(*addr);
			return tool_result_t::ok(
				OBFSTR("Structure '") + params["name"].get<std::string>() + OBFSTR("' created at index ") + std::to_string(idx), result);
		}, false});

	register_compat(srv, {OBFSTR("scanner_add_struct_field"), OBFSTR("memory_scanner"),
		OBFSTR("Add a field to a structure definition."),
		{{OBFSTR("struct_index"), OBFSTR("number"), OBFSTR("Index of the structure to modify"), true},
		 {OBFSTR("name"), OBFSTR("string"), OBFSTR("Field name"), true},
		 {OBFSTR("offset"), OBFSTR("number"), OBFSTR("Offset from struct base in bytes"), true},
		 {OBFSTR("field_type"), OBFSTR("string"), OBFSTR("Type: int8/uint8/int16/uint16/int32/uint32/int64/uint64/float32/float64/pointer/ascii_string/utf16_string/byte_array/padding"), true}},
		[](const json& params) -> tool_result_t {
			if (!params.contains("struct_index") || !params["struct_index"].is_number())
				return tool_result_t::error(OBFSTR("'struct_index' is required."));
			if (!params.contains("name") || !params["name"].is_string())
				return tool_result_t::error(OBFSTR("'name' is required."));
			if (!params.contains("offset") || !params["offset"].is_number())
				return tool_result_t::error(OBFSTR("'offset' is required."));
			if (!params.contains("field_type") || !params["field_type"].is_string())
				return tool_result_t::error(OBFSTR("'field_type' is required."));
			int si = params["struct_index"].get<int>();
			std::string type_str = params["field_type"].get<std::string>();
			struct_dissector::field_type_t ft = struct_dissector::field_type_t::int32;
			if (type_str == "int8") ft = struct_dissector::field_type_t::int8;
			else if (type_str == "uint8") ft = struct_dissector::field_type_t::uint8;
			else if (type_str == "int16") ft = struct_dissector::field_type_t::int16;
			else if (type_str == "uint16") ft = struct_dissector::field_type_t::uint16;
			else if (type_str == "int32") ft = struct_dissector::field_type_t::int32;
			else if (type_str == "uint32") ft = struct_dissector::field_type_t::uint32;
			else if (type_str == "int64") ft = struct_dissector::field_type_t::int64;
			else if (type_str == "uint64") ft = struct_dissector::field_type_t::uint64;
			else if (type_str == "float32") ft = struct_dissector::field_type_t::float32;
			else if (type_str == "float64") ft = struct_dissector::field_type_t::float64;
			else if (type_str == "pointer") ft = struct_dissector::field_type_t::pointer;
			else if (type_str == "ascii_string") ft = struct_dissector::field_type_t::ascii_string;
			else if (type_str == "utf16_string") ft = struct_dissector::field_type_t::utf16_string;
			else if (type_str == "byte_array") ft = struct_dissector::field_type_t::byte_array;
			else if (type_str == "padding") ft = struct_dissector::field_type_t::padding;
			else return tool_result_t::error(OBFSTR("Unknown field_type: ") + type_str);
			struct_dissector::field_def_t fld;
			fld.name = params["name"].get<std::string>();
			fld.type = ft;
			fld.offset = static_cast<uint32_t>(params["offset"].get<int>());
			int fi = struct_dissector::add_field(si, fld);
			if (fi < 0)
				return tool_result_t::error(OBFSTR("Failed to add field."));
			json result;
			result["field_index"] = fi;
			result["name"] = fld.name;
			result["offset"] = fld.offset;
			result["type"] = type_str;
			return tool_result_t::ok(
				OBFSTR("Field '") + fld.name + OBFSTR("' added at offset ") + std::to_string(fld.offset), result);
		}, false});

	register_compat(srv, {OBFSTR("scanner_get_struct"), OBFSTR("memory_scanner"),
		OBFSTR("Get a structure definition with live values read from memory."),
		{{OBFSTR("struct_index"), OBFSTR("number"), OBFSTR("Index of the structure"), true}},
		[](const json& params) -> tool_result_t {
			if (!params.contains("struct_index") || !params["struct_index"].is_number())
				return tool_result_t::error(OBFSTR("'struct_index' is required."));
			int si = params["struct_index"].get<int>();
			{
				std::lock_guard<std::mutex> lk(struct_dissector::g_state.mtx);
				if (si < 0 || si >= static_cast<int>(struct_dissector::g_state.structs.size()))
					return tool_result_t::error(OBFSTR("Invalid struct_index."));
				struct_dissector::g_state.active_struct = si;
			}
			struct_dissector::refresh_values();
			std::lock_guard<std::mutex> lk(struct_dissector::g_state.mtx);
			const auto& sd = struct_dissector::g_state.structs[static_cast<size_t>(si)];
			json fields_arr = json::array();
			for (size_t fi = 0; fi < sd.fields.size(); ++fi) {
				const auto& f = sd.fields[fi];
				json fj;
				fj["index"] = fi;
				fj["name"] = f.name;
				fj["offset"] = f.offset;
				fj["type"] = struct_dissector::field_type_name(f.type);
				fj["size"] = f.size;
				if (fi < struct_dissector::g_state.cached_values.size())
					fj["value"] = struct_dissector::g_state.cached_values[fi].display_text;
				fields_arr.push_back(std::move(fj));
			}
			json result;
			result["name"] = sd.name;
			result["base_address"] = sa_format_address(struct_dissector::g_state.base_address);
			result["total_size"] = sd.total_size;
			result["field_count"] = sd.fields.size();
			result["fields"] = std::move(fields_arr);
			return tool_result_t::ok(
				OBFSTR("Struct '") + sd.name + OBFSTR("': ") + std::to_string(sd.fields.size()) + OBFSTR(" field(s)."), result);
		}, true});

	register_compat(srv, {OBFSTR("scanner_export_struct_c"), OBFSTR("memory_scanner"),
		OBFSTR("Export a structure definition as C source code."),
		{{OBFSTR("struct_index"), OBFSTR("number"), OBFSTR("Index of the structure to export"), true}},
		[](const json& params) -> tool_result_t {
			if (!params.contains("struct_index") || !params["struct_index"].is_number())
				return tool_result_t::error(OBFSTR("'struct_index' is required."));
			int si = params["struct_index"].get<int>();
			std::string code = struct_dissector::export_to_c(si);
			if (code.empty())
				return tool_result_t::error(OBFSTR("Invalid struct_index or empty struct."));
			json result;
			result["c_code"] = code;
			return tool_result_t::ok(code, result);
		}, true});

}

}
