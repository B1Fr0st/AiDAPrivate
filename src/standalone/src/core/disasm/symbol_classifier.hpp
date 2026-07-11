#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "event_bus.hpp"
#include "pdb_events.hpp"
#include "pe_parser.hpp"
#include "standalone_driver.hpp"
#include "symbol_store.hpp"
#include "../analysis/workspace/analysis_workspace.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "../infra/executor.hpp"
#include "../session/analysis_session.hpp"

namespace symbol_classifier {

	enum class kind_t {
		unknown          = 0,
		regular_function = 1,
		library_function = 2,
		lumina_function  = 3,
		external_import  = 4,
		instruction      = 5,
		data             = 6,
		string           = 7,
		label            = 8,
		register_op      = 9,
		immediate        = 10,
		comment          = 11,
		data_byte        = 12,
		data_word        = 13,
		data_dword       = 14,
		data_qword       = 15,
		data_xmmword     = 16,
		data_ymmword     = 17,
		data_zmmword     = 18,
		data_tbyte       = 19,
		data_fword       = 20,
		string_ascii     = 21,
		string_unicode   = 22,
		struct_ref       = 23,
		array_ref        = 24,
		offset_ref       = 25,
		segment_ref      = 26,
		pointer_ref      = 27,
		data_unknown     = 28,
		align_directive  = 29,
		jump_thunk       = 30,
		case_label       = 31,
		default_case     = 32,
		stack_var        = 33,
		stack_arg        = 34,
		saved_reg        = 35,
		restored_reg     = 36,
		section_text     = 37,
		section_data     = 38,
		section_rdata    = 39,
		section_bss      = 40,
		section_rsrc     = 41,
		section_other    = 42,
		custom_struct    = 43,
		enum_value       = 44,
		typelib_type     = 45,
		mnem_branch      = 46,
		mnem_call        = 47,
		mnem_ret         = 48,
		mnem_arith       = 49,
		mnem_logic       = 50,
		mnem_data        = 51,
		mnem_sse         = 52,
		mnem_string      = 53,
		mnem_priv        = 54,
		mnem_nop         = 55,
		mnem_int         = 56,
		mnem_other       = 57,
		imp_function     = 58,
		entry_point      = 59,
		main_function    = 60,
		winmain_function = 61,
		dllmain_function = 62
	};

	inline const char* kind_name(kind_t kind) {
		switch (kind) {
			case kind_t::regular_function: return "regular_function";
			case kind_t::library_function: return "library_function";
			case kind_t::lumina_function:  return "lumina_function";
			case kind_t::external_import:  return "external_import";
			case kind_t::instruction:      return "instruction";
			case kind_t::data:             return "data";
			case kind_t::string:           return "string";
			case kind_t::label:            return "label";
			case kind_t::register_op:      return "register_op";
			case kind_t::immediate:        return "immediate";
			case kind_t::comment:          return "comment";
			case kind_t::data_byte:        return "data_byte";
			case kind_t::data_word:        return "data_word";
			case kind_t::data_dword:       return "data_dword";
			case kind_t::data_qword:       return "data_qword";
			case kind_t::data_xmmword:     return "data_xmmword";
			case kind_t::data_ymmword:     return "data_ymmword";
			case kind_t::data_zmmword:     return "data_zmmword";
			case kind_t::data_tbyte:       return "data_tbyte";
			case kind_t::data_fword:       return "data_fword";
			case kind_t::string_ascii:     return "string_ascii";
			case kind_t::string_unicode:   return "string_unicode";
			case kind_t::struct_ref:       return "struct_ref";
			case kind_t::array_ref:        return "array_ref";
			case kind_t::offset_ref:       return "offset_ref";
			case kind_t::segment_ref:      return "segment_ref";
			case kind_t::pointer_ref:      return "pointer_ref";
			case kind_t::data_unknown:     return "data_unknown";
			case kind_t::align_directive:  return "align_directive";
			case kind_t::jump_thunk:       return "jump_thunk";
			case kind_t::case_label:       return "case_label";
			case kind_t::default_case:     return "default_case";
			case kind_t::stack_var:        return "stack_var";
			case kind_t::stack_arg:        return "stack_arg";
			case kind_t::saved_reg:        return "saved_reg";
			case kind_t::restored_reg:     return "restored_reg";
			case kind_t::section_text:     return "section_text";
			case kind_t::section_data:     return "section_data";
			case kind_t::section_rdata:    return "section_rdata";
			case kind_t::section_bss:      return "section_bss";
			case kind_t::section_rsrc:     return "section_rsrc";
			case kind_t::section_other:    return "section_other";
			case kind_t::custom_struct:    return "custom_struct";
			case kind_t::enum_value:       return "enum_value";
			case kind_t::typelib_type:     return "typelib_type";
			case kind_t::mnem_branch:      return "mnem_branch";
			case kind_t::mnem_call:        return "mnem_call";
			case kind_t::mnem_ret:         return "mnem_ret";
			case kind_t::mnem_arith:       return "mnem_arith";
			case kind_t::mnem_logic:       return "mnem_logic";
			case kind_t::mnem_data:        return "mnem_data";
			case kind_t::mnem_sse:         return "mnem_sse";
			case kind_t::mnem_string:      return "mnem_string";
			case kind_t::mnem_priv:        return "mnem_priv";
			case kind_t::mnem_nop:         return "mnem_nop";
			case kind_t::mnem_int:         return "mnem_int";
			case kind_t::mnem_other:       return "mnem_other";
			case kind_t::imp_function:     return "imp_function";
			case kind_t::entry_point:      return "entry_point";
			case kind_t::main_function:    return "main_function";
			case kind_t::winmain_function: return "winmain_function";
			case kind_t::dllmain_function: return "dllmain_function";
			case kind_t::unknown:          return "unknown";
		}
		return "unknown";
	}

	inline aida::analysis::workspace_result_t<aida::analysis::address_t>
	normalize_workspace_address(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& address)
	{
		using namespace aida::analysis;
		if (!workspace) {
			return workspace_result_t<address_t>::failure(make_workspace_error(
				workspace_error_code_t::target_not_found,
				"Symbol classification requires an explicit workspace",
				"symbol_classifier.address"));
		}
		if (address.architecture != architecture_id_t::unknown &&
			address.architecture != workspace->identity().architecture()) {
			return workspace_result_t<address_t>::failure(make_workspace_error(
				workspace_error_code_t::unsupported_address_space,
				"Symbol address architecture does not match the workspace",
				"symbol_classifier.address"));
		}
		auto image = workspace->image();
		address_t result = address;
		result.architecture = workspace->identity().architecture();
		result.mode = image ? image->architecture_mode() : address.mode;
		if (workspace->target_kind() == target_kind_t::live_snapshot) {
			const auto& module = workspace->identity().module();
			if (!module || module->size == 0 ||
				module->base > UINT64_MAX - module->size) {
				return workspace_result_t<address_t>::failure(make_workspace_error(
					workspace_error_code_t::target_stale,
					"Live symbol workspace has no valid module range",
					"symbol_classifier.address"));
			}
			if (address.space == address_space_id_t::relative_virtual) {
				if (address.value >= module->size ||
					module->base > UINT64_MAX - address.value) {
					return workspace_result_t<address_t>::failure(make_workspace_error(
						workspace_error_code_t::out_of_range,
						"Live symbol RVA is outside the captured module",
						"symbol_classifier.address"));
				}
				result.value = module->base + address.value;
			} else if (address.space == address_space_id_t::virtual_address ||
				address.space == address_space_id_t::live_virtual) {
				if (address.value < module->base ||
					address.value - module->base >= module->size) {
					return workspace_result_t<address_t>::failure(make_workspace_error(
						workspace_error_code_t::out_of_range,
						"Live symbol address is outside the captured module",
						"symbol_classifier.address"));
				}
			} else {
				return workspace_result_t<address_t>::failure(make_workspace_error(
					workspace_error_code_t::unsupported_address_space,
					"Live symbol classification requires a virtual address",
					"symbol_classifier.address"));
			}
			result.space = address_space_id_t::live_virtual;
			return workspace_result_t<address_t>::success(result);
		}
		if (!image) {
			return workspace_result_t<address_t>::failure(make_workspace_error(
				workspace_error_code_t::malformed_pe,
				"Static symbol classification requires a normalized image",
				"symbol_classifier.address"));
		}
		if (address.space == address_space_id_t::relative_virtual) {
			if (address.value >= image->image_size()) {
				return workspace_result_t<address_t>::failure(make_workspace_error(
					workspace_error_code_t::out_of_range,
					"Symbol RVA is outside the normalized image",
					"symbol_classifier.address"));
			}
			result.space = address_space_id_t::relative_virtual;
		} else if (address.space == address_space_id_t::file_offset) {
			auto rva = image->file_offset_to_rva(address.value);
			if (!rva) return workspace_result_t<address_t>::failure(rva.error());
			result.space = address_space_id_t::relative_virtual;
			result.value = rva.value();
		} else if (address.space == address_space_id_t::virtual_address) {
			if (address.value < image->image_base() ||
				address.value - image->image_base() >= image->image_size()) {
				return workspace_result_t<address_t>::failure(make_workspace_error(
					workspace_error_code_t::out_of_range,
					"Symbol address is outside the normalized image",
					"symbol_classifier.address"));
			}
			result.space = address_space_id_t::relative_virtual;
			result.value = address.value - image->image_base();
		} else {
			return workspace_result_t<address_t>::failure(make_workspace_error(
				workspace_error_code_t::unsupported_address_space,
				"Symbol address space is unsupported", "symbol_classifier.address"));
		}
		return workspace_result_t<address_t>::success(result);
	}

	inline kind_t classify(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& address)
	{
		using namespace aida::analysis;
		auto normalized = normalize_workspace_address(workspace, address);
		if (!normalized) return kind_t::unknown;
		auto publication = workspace->analysis_publication();
		auto snapshot = publication &&
			publication->binary_id == workspace->identity().binary_id() &&
			publication->generation == workspace->generation()
			? publication->snapshot : nullptr;
		if (snapshot) {
			for (const auto& symbol : snapshot->symbols) {
				if (symbol.address.space != normalized.value().space ||
					symbol.address.value != normalized.value().value)
					continue;
				switch (symbol.kind) {
				case symbol_kind_t::function:
				case symbol_kind_t::export_symbol:
				case symbol_kind_t::debug_symbol:
					return kind_t::regular_function;
				case symbol_kind_t::import_symbol: return kind_t::external_import;
				case symbol_kind_t::data: return kind_t::data;
				case symbol_kind_t::type_symbol: return kind_t::typelib_type;
				case symbol_kind_t::metadata: return kind_t::label;
				}
			}
			for (const auto& string : snapshot->strings) {
				if (string.address.space != normalized.value().space ||
					normalized.value().value < string.address.value ||
					normalized.value().value - string.address.value >= string.byte_length)
					continue;
				return string.encoding == string_encoding_t::utf16_le
					? kind_t::string_unicode : kind_t::string_ascii;
			}
			for (const auto& function : snapshot->functions) {
				if (function.start.space != normalized.value().space ||
					normalized.value().value < function.start.value ||
					normalized.value().value >= function.end.value)
					continue;
				if (normalized.value().value == function.start.value)
					return function.thunk ? kind_t::jump_thunk : kind_t::regular_function;
				return kind_t::instruction;
			}
			for (const auto& instruction : snapshot->instructions) {
				if (instruction.address.space == normalized.value().space &&
					instruction.address.value == normalized.value().value)
					return kind_t::instruction;
			}
		}
		auto image = workspace->image();
		if (auto symbols = analysis_session::symbols_for_workspace(workspace)) {
			auto symbol_address = normalized.value();
			if (symbol_address.space == address_space_id_t::relative_virtual) {
				if (image && image->image_base() <= UINT64_MAX - symbol_address.value) {
					symbol_address.space = address_space_id_t::virtual_address;
					symbol_address.value += image->image_base();
				}
			} else if (symbol_address.space == address_space_id_t::virtual_address &&
				workspace->target_kind() == target_kind_t::live_snapshot) {
				symbol_address.space = address_space_id_t::live_virtual;
			}
			if (auto symbol = symbols->symbol_snapshot_exact(symbol_address))
				return symbol->is_function ? kind_t::regular_function : kind_t::data;
		}
		if (!image) return kind_t::unknown;
		if (normalized.value().space == address_space_id_t::relative_virtual &&
			normalized.value().value == image->entry_rva())
			return kind_t::entry_point;
		for (const auto& entry : image->imports()) {
			if (normalized.value().space == address_space_id_t::relative_virtual &&
				normalized.value().value == entry.iat_rva)
				return kind_t::imp_function;
		}
		if (normalized.value().space != address_space_id_t::relative_virtual)
			return kind_t::unknown;
		const auto* section = image->section_for_rva(normalized.value().value);
		if (!section) return kind_t::unknown;
		std::string name = section->name;
		std::transform(name.begin(), name.end(), name.begin(), [](unsigned char value) {
			return static_cast<char>(std::tolower(value));
		});
		if (name == ".text" || section->executable) return kind_t::section_text;
		if (name == ".rdata") return kind_t::section_rdata;
		if (name == ".data") return kind_t::section_data;
		if (name == ".bss") return kind_t::section_bss;
		if (name == ".rsrc") return kind_t::section_rsrc;
		return section->writable ? kind_t::data : kind_t::section_other;
	}

	inline const char* classify_name(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& address)
	{
		return kind_name(classify(workspace, address));
	}

	inline bool lookup_import_by_iat(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::analysis::address_t& address,
		std::string& module_name, std::string& function_name)
	{
		module_name.clear();
		function_name.clear();
		auto normalized = normalize_workspace_address(workspace, address);
		auto image = workspace ? workspace->image() : nullptr;
		if (!normalized || !image) return false;
		for (const auto& entry : image->imports()) {
			if (normalized.value().space != aida::analysis::address_space_id_t::relative_virtual ||
				normalized.value().value != entry.iat_rva) continue;
			module_name = entry.library;
			if (entry.name) function_name = *entry.name;
			else if (entry.ordinal) function_name = "Ordinal#" + std::to_string(*entry.ordinal);
			return !function_name.empty();
		}
		return false;
	}

	namespace detail {

		enum class build_state_t : uint32_t {
			idle = 0,
			building = 1,
			built = 2,
			failed = 3
		};

		struct section_range_t {
			uint64_t start_va = 0;
			uint64_t end_va = 0;
			uint32_t characteristics = 0;
			bool     is_code = false;
			bool     is_data = false;
		};

		struct struct_field_t {
			std::string name;
			uint32_t    offset = 0;
			uint32_t    size = 0;
			uint32_t    type_id = 0;
			std::string type_name;
		};

		struct struct_binding_t {
			uint32_t                                type_id = 0;
			std::string                             struct_name;
			uint32_t                                size = 0;
			std::vector<struct_field_t>             fields;
			std::unordered_map<uint32_t, size_t>    field_by_offset;
			uint64_t                                base_va = 0;
		};

		using address_kind_map_t = std::unordered_map<uint64_t, kind_t>;
		using struct_binding_map_t = std::map<uint32_t, struct_binding_t>;
		using enum_value_map_t = std::map<std::string, std::vector<std::pair<int64_t, std::string>>>;
		using iat_funcname_map_t = std::map<uint64_t, std::string>;

		inline std::shared_ptr<const address_kind_map_t> empty_address_kind_snapshot() {
			static const std::shared_ptr<const address_kind_map_t> s_empty
				= std::make_shared<const address_kind_map_t>();
			return s_empty;
		}

		inline std::shared_ptr<const struct_binding_map_t> empty_struct_binding_snapshot() {
			static const std::shared_ptr<const struct_binding_map_t> s_empty
				= std::make_shared<const struct_binding_map_t>();
			return s_empty;
		}

		inline std::shared_ptr<const enum_value_map_t> empty_enum_value_snapshot() {
			static const std::shared_ptr<const enum_value_map_t> s_empty
				= std::make_shared<const enum_value_map_t>();
			return s_empty;
		}

		inline std::shared_ptr<const iat_funcname_map_t> empty_iat_funcname_snapshot() {
			static const std::shared_ptr<const iat_funcname_map_t> s_empty
				= std::make_shared<const iat_funcname_map_t>();
			return s_empty;
		}

		struct module_entry_t {
			std::string                                          name;
			uint64_t                                             base = 0;
			uint64_t                                             size = 0;
			std::vector<section_range_t>                         sections;
			std::shared_ptr<const address_kind_map_t>            address_kind = empty_address_kind_snapshot();
			std::shared_ptr<const struct_binding_map_t>          struct_bindings = empty_struct_binding_snapshot();
			std::shared_ptr<const enum_value_map_t>              enum_value_tables = empty_enum_value_snapshot();
			std::shared_ptr<const iat_funcname_map_t>            iat_to_funcname = empty_iat_funcname_snapshot();
			std::unordered_set<std::string>                      external_names;
			std::atomic<uint32_t>                                state{static_cast<uint32_t>(build_state_t::idle)};
			std::mutex                                           apply_lock;
			std::atomic<bool>                                    apply_in_flight{false};
			std::atomic<uint64_t>                                apply_generation{0};
		};

		struct module_range_t {
			uint64_t                          start_va = 0;
			uint64_t                          end_va = 0;
			std::shared_ptr<module_entry_t>   entry;
		};

		struct registry_t {
			std::shared_mutex                                              rw;
			std::unordered_map<std::string, std::shared_ptr<module_entry_t>> modules;
			std::vector<module_range_t>                                    table;
			std::atomic<bool>                                              table_built{false};
			std::atomic<bool>                                              subscription_armed{false};
			aida::events::subscription_handle_t                            subscription;
			std::atomic<uint64_t>                                          generation{0};
			std::atomic<bool>                                              rebuild_in_flight{false};
			std::atomic<bool>                                              pdb_subscription_armed{false};
			aida::events::subscription_handle_t                            pdb_subscription;
		};

		inline registry_t& registry() {
			static registry_t r;
			return r;
		}

		inline bool ascii_eq_lower(char a, char b) {
			if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
			if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
			return a == b;
		}

		inline bool name_starts_with(std::string_view name, std::string_view prefix) {
			if (name.size() < prefix.size()) return false;
			for (size_t i = 0; i < prefix.size(); ++i) {
				if (!ascii_eq_lower(name[i], prefix[i])) return false;
			}
			return true;
		}

		inline bool name_contains_ci(std::string_view name, std::string_view needle) {
			if (needle.empty()) return true;
			if (name.size() < needle.size()) return false;
			const size_t limit = name.size() - needle.size();
			for (size_t i = 0; i <= limit; ++i) {
				bool match = true;
				for (size_t j = 0; j < needle.size(); ++j) {
					if (!ascii_eq_lower(name[i + j], needle[j])) {
						match = false;
						break;
					}
				}
				if (match) return true;
			}
			return false;
		}

		inline bool is_register_token(std::string_view name) {
			if (name.empty() || name.size() > 6) return false;
			static constexpr std::array<std::string_view, 89> kRegs = {
				"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
				"r8","r9","r10","r11","r12","r13","r14","r15",
				"eax","ebx","ecx","edx","esi","edi","ebp","esp",
				"r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
				"ax","bx","cx","dx","si","di","bp","sp",
				"r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w",
				"al","bl","cl","dl","ah","bh","ch","dh","sil","dil","bpl","spl",
				"r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b",
				"rip","eip","ip","cs","ds","es","fs","gs","ss",
				"st0","st1","st2","st3","st4","st5","st6","st7",
				"mxcsr","eflags","rflags","fpu"
			};
			for (auto r : kRegs) {
				if (name.size() != r.size()) continue;
				bool eq = true;
				for (size_t i = 0; i < r.size(); ++i) {
					if (!ascii_eq_lower(name[i], r[i])) { eq = false; break; }
				}
				if (eq) return true;
			}
			if (name.size() >= 3 && name.size() <= 6) {
				char c0 = name[0]; if (c0 >= 'A' && c0 <= 'Z') c0 = static_cast<char>(c0 - 'A' + 'a');
				char c1 = name[1]; if (c1 >= 'A' && c1 <= 'Z') c1 = static_cast<char>(c1 - 'A' + 'a');
				const bool dr   = (c0 == 'd' && c1 == 'r');
				const bool cr   = (c0 == 'c' && c1 == 'r');
				if ((dr || cr) && name.size() >= 3) {
					for (size_t i = 2; i < name.size(); ++i) {
						if (name[i] < '0' || name[i] > '9') return false;
					}
					return true;
				}
				if (name.size() >= 4) {
					char c2 = name[2]; if (c2 >= 'A' && c2 <= 'Z') c2 = static_cast<char>(c2 - 'A' + 'a');
					const bool xmm  = (c0 == 'x' && c1 == 'm' && c2 == 'm');
					const bool ymm  = (c0 == 'y' && c1 == 'm' && c2 == 'm');
					const bool zmm  = (c0 == 'z' && c1 == 'm' && c2 == 'm');
					if (xmm || ymm || zmm) {
						for (size_t i = 3; i < name.size(); ++i) {
							if (name[i] < '0' || name[i] > '9') return false;
						}
						return true;
					}
				}
			}
			return false;
		}

		inline bool is_library_name(std::string_view name) {
			if (name.empty()) return false;
			static constexpr std::array<std::string_view, 87> kLibPrefixes = {
				"__security_",
				"__scrt_",
				"__std_",
				"__msvcrt_",
				"__report_",
				"__acrt_",
				"__crt_",
				"__vcrt_",
				"_RTC_",
				"_CRT_",
				"_amsg_",
				"_alloca_probe",
				"__chkstk",
				"__C_specific_handler",
				"__GSHandlerCheck",
				"__CxxFrameHandler",
				"__except_handler",
				"_fltused",
				"__threadhandle",
				"__threadid",
				"__guard_",
				"_initterm",
				"_initterm_e",
				"mainCRTStartup",
				"WinMainCRTStartup",
				"DllMainCRTStartup",
				"_DllMainCRTStartup",
				"__dyn_tls_init",
				"_RTC_CheckEsp",
				"_RTC_CheckStackVars",
				"_RTC_AllocaHelper",
				"_RTC_GetSrcLine",
				"__GSHandlerCheck_EH",
				"__GSHandlerCheck_SEH",
				"__GSHandlerCheck_EH4",
				"__std_terminate",
				"__std_exception_copy",
				"__std_exception_destroy",
				"__std_type_info_destroy_list",
				"__std_type_info_compare",
				"__std_type_info_hash",
				"__std_type_info_name",
				"__delayLoadHelper2",
				"__tailMerge_",
				"__delay_load_dll",
				"_CIacos",
				"_CIasin",
				"_CIatan",
				"_CIatan2",
				"_CIcos",
				"_CIcosh",
				"_CIexp",
				"_CIfmod",
				"_CIlog",
				"_CIlog10",
				"_CIpow",
				"_CIsin",
				"_CIsinh",
				"_CIsqrt",
				"_CItan",
				"_CItanh",
				"__umoddi3",
				"__udivdi3",
				"__divdi3",
				"__moddi3",
				"_aullshr",
				"_aullshl",
				"_alldiv",
				"_aulldiv",
				"_allmul",
				"_aullrem",
				"_allrem",
				"__xc_a",
				"__xc_z",
				"__xi_a",
				"__xi_z",
				"_NLG_Notify",
				"_NLG_Return2",
				"__except1",
				"__except2",
				"__except_validate_context_record",
				"__except_validate_jump_buffer",
				"__JustMyCode_Default",
				"__GetExceptionInfo",
				"vtordisp_",
				"_purecall",
				"__report_gsfailure"
			};
			for (auto p : kLibPrefixes) {
				if (name_starts_with(name, p)) return true;
			}
			return false;
		}

		inline bool is_os_module(std::string_view module_name) {
			if (module_name.empty()) return false;
			static constexpr std::array<std::string_view, 32> kOsDlls = {
				"kernel32.dll", "kernelbase.dll", "ntdll.dll",
				"msvcrt.dll", "msvcr120.dll", "msvcr110.dll", "msvcr100.dll",
				"ucrtbase.dll", "ucrtbased.dll",
				"vcruntime.dll", "vcruntime140.dll", "vcruntime140d.dll",
				"vcruntime140_1.dll", "vcruntime140_1d.dll",
				"advapi32.dll", "user32.dll", "gdi32.dll", "gdi32full.dll",
				"shell32.dll", "shcore.dll", "ole32.dll", "oleaut32.dll",
				"ws2_32.dll", "wsock32.dll", "shlwapi.dll", "shlwapi.lib",
				"crypt32.dll", "bcrypt.dll", "bcryptprimitives.dll",
				"rpcrt4.dll", "sechost.dll", "combase.dll"
			};
			for (auto d : kOsDlls) {
				if (module_name.size() != d.size()) {
					if (name_contains_ci(module_name, d)) return true;
					continue;
				}
				bool eq = true;
				for (size_t i = 0; i < d.size(); ++i) {
					if (!ascii_eq_lower(module_name[i], d[i])) { eq = false; break; }
				}
				if (eq) return true;
			}
			return name_starts_with(module_name, "api-ms-win-");
		}

		inline bool section_name_is_data(const std::string& name) {
			if (name.empty()) return false;
			if (name == ".rdata") return true;
			if (name == ".data") return true;
			if (name == ".bss")  return true;
			if (name == ".idata") return true;
			if (name == ".tls") return true;
			if (name == ".CRT") return true;
			if (name == ".rodata") return true;
			return false;
		}

		inline bool section_name_is_code(uint32_t characteristics) {
			return (characteristics & 0x20000000u) != 0u;
		}

		inline section_range_t make_section_range(uint64_t module_base, const pe_parser::section_info_t& s) {
			section_range_t r;
			r.start_va = module_base + static_cast<uint64_t>(s.virtual_address);
			r.end_va = r.start_va + static_cast<uint64_t>(s.virtual_size != 0 ? s.virtual_size : s.raw_size);
			r.characteristics = s.characteristics;
			r.is_code = section_name_is_code(s.characteristics);
			r.is_data = !r.is_code && (((s.characteristics & 0x40000000u) != 0u) || section_name_is_data(s.name));
			return r;
		}

		inline const section_range_t* find_section(const std::vector<section_range_t>& secs, uint64_t va) {
			for (const auto& s : secs) {
				if (va >= s.start_va && va < s.end_va) return &s;
			}
			return nullptr;
		}

		inline bool read_runtime_function_starts(uint64_t module_base, std::vector<uint32_t>& out_starts) {
			out_starts.clear();
			uint16_t dos_magic = 0;
			if (!pe_parser::detail::read_mem(module_base, &dos_magic, 2)) return false;
			if (dos_magic != 0x5A4D) return false;
			uint32_t e_lfanew = 0;
			if (!pe_parser::detail::read_mem(module_base + 0x3C, &e_lfanew, 4)) return false;
			if (e_lfanew == 0 || e_lfanew > 0x1000) return false;
			uint64_t opt_addr = module_base + e_lfanew + 24;
			uint16_t opt_magic = 0;
			if (!pe_parser::detail::read_mem(opt_addr, &opt_magic, 2)) return false;
			if (opt_magic != 0x020B) return true;
			uint32_t exception_dir_rva = 0;
			uint32_t exception_dir_size = 0;
			if (!pe_parser::detail::read_mem(opt_addr + 136, &exception_dir_rva, 4)) return false;
			if (!pe_parser::detail::read_mem(opt_addr + 140, &exception_dir_size, 4)) return false;
			if (exception_dir_rva == 0 || exception_dir_size < 12) return true;
			const uint32_t entry_size = 12;
			uint32_t count = exception_dir_size / entry_size;
			if (count == 0 || count > 0x100000) return true;
			std::vector<uint8_t> table;
			if (!driver_bridge::read_memory(module_base + exception_dir_rva,
				static_cast<size_t>(count) * entry_size, table)) return false;
			if (table.size() < static_cast<size_t>(count) * entry_size) {
				count = static_cast<uint32_t>(table.size() / entry_size);
			}
			out_starts.reserve(count);
			for (uint32_t i = 0; i < count; ++i) {
				uint32_t begin_rva = 0;
				uint32_t end_rva = 0;
				std::memcpy(&begin_rva, table.data() + i * entry_size + 0, 4);
				std::memcpy(&end_rva, table.data() + i * entry_size + 4, 4);
				if (begin_rva == 0 || end_rva <= begin_rva) continue;
				out_starts.push_back(begin_rva);
			}
			return true;
		}

		inline void scan_strings_in_blob(uint64_t base_va, const std::vector<uint8_t>& bytes,
			std::unordered_map<uint64_t, kind_t>& map)
		{
			const size_t n = bytes.size();
			if (n < 4) return;
			size_t i = 0;
			while (i < n) {
				size_t run_start = i;
				size_t printable = 0;
				while (i < n) {
					uint8_t b = bytes[i];
					bool ok = (b >= 0x20 && b < 0x7F) || b == '\t' || b == '\r' || b == '\n';
					if (!ok) break;
					++printable;
					++i;
				}
				if (printable >= 4 && i < n && bytes[i] == 0x00) {
					map[base_va + run_start] = kind_t::string;
				}
				while (i < n && bytes[i] == 0x00) ++i;
				if (printable < 4) {
					if (i == run_start) ++i;
				}
			}
			if (n >= 8) {
				size_t j = 0;
				while (j + 1 < n) {
					size_t run_start = j;
					size_t printable_w = 0;
					while (j + 1 < n) {
						uint8_t lo = bytes[j];
						uint8_t hi = bytes[j + 1];
						bool ok = (hi == 0) && ((lo >= 0x20 && lo < 0x7F) || lo == '\t' || lo == '\r' || lo == '\n');
						if (!ok) break;
						++printable_w;
						j += 2;
					}
					if (printable_w >= 4 && j + 1 < n && bytes[j] == 0 && bytes[j + 1] == 0) {
						uint64_t va = base_va + run_start;
						auto it = map.find(va);
						if (it == map.end()) map[va] = kind_t::string;
					}
					while (j + 1 < n && bytes[j] == 0 && bytes[j + 1] == 0) j += 2;
					if (printable_w < 4) {
						if (j == run_start) ++j;
					}
				}
			}
		}

		inline std::optional<symbol_store::module_symbols_t>
		live_module_symbols(const std::string& module_name) {
			const uint32_t pid = driver_bridge::attached_pid();
			if (pid == 0) return std::nullopt;
			auto workspace = aida::analysis::workspace_registry().find_by_pid(pid);
			if (workspace) {
				auto symbols = analysis_session::symbols_for_workspace(workspace);
				if (symbols) return symbols->module_snapshot(module_name);
			}
			std::lock_guard<std::mutex> lock(symbol_store::g_state.mutex);
			auto found = symbol_store::g_state.modules.find(module_name);
			if (found == symbol_store::g_state.modules.end() ||
				found->second.pdb.symbols.size() > 4 * 1024 * 1024)
				return std::nullopt;
			return found->second;
		}

		inline void apply_pdb_symbols(std::shared_ptr<module_entry_t>& mod) {
			if (!mod) return;
			std::vector<std::pair<uint64_t, kind_t>> updates;
			if (auto module = live_module_symbols(mod->name);
				module && module->pdb.loaded) {
				updates.reserve(module->pdb.symbols.size());
				for (const auto& sym : module->pdb.symbols) {
					if (!sym.is_function) continue;
					if (mod->base > UINT64_MAX - sym.rva) continue;
					uint64_t va = mod->base + sym.rva;
					if (va < mod->base || va - mod->base >= mod->size) continue;
					kind_t k = is_library_name(sym.name) ? kind_t::library_function : kind_t::regular_function;
					updates.emplace_back(va, k);
				}
			} else return;

			std::lock_guard<std::mutex> lk(mod->apply_lock);
			auto cur = std::atomic_load(&mod->address_kind);
			auto next = std::make_shared<address_kind_map_t>(cur ? *cur : address_kind_map_t());
			for (const auto& u : updates) {
				auto eit = next->find(u.first);
				if (eit == next->end()) {
					next->emplace(u.first, u.second);
				} else if (eit->second == kind_t::regular_function && u.second == kind_t::library_function) {
					eit->second = kind_t::library_function;
				}
			}
			std::shared_ptr<const address_kind_map_t> new_snapshot(std::move(next));
			std::atomic_store(&mod->address_kind, new_snapshot);
			mod->apply_generation.fetch_add(1, std::memory_order_acq_rel);
		}

		inline void apply_pdb_types(std::shared_ptr<module_entry_t>& mod) {
			if (!mod) return;
			std::vector<std::pair<uint32_t, struct_binding_t>> binding_updates;
			std::vector<std::pair<std::string, std::vector<std::pair<int64_t, std::string>>>> enum_updates;
			std::vector<std::pair<uint64_t, kind_t>> address_updates;
			if (auto module = live_module_symbols(mod->name);
				module && module->pdb.loaded) {
				const auto& ms = *module;

				binding_updates.reserve(ms.pdb.structs.size());
				for (const auto& sd : ms.pdb.structs) {
					struct_binding_t b;
					b.type_id = sd.type_index;
					b.struct_name = sd.name;
					b.size = static_cast<uint32_t>(sd.size);
					b.fields.reserve(sd.members.size());
					for (const auto& mem : sd.members) {
						struct_field_t f;
						f.name = mem.name;
						f.offset = static_cast<uint32_t>(mem.offset);
						f.size = static_cast<uint32_t>(mem.size);
						f.type_id = mem.type_index;
						f.type_name = mem.type_name;
						b.fields.push_back(std::move(f));
					}
					b.field_by_offset.reserve(b.fields.size());
					for (size_t fi = 0; fi < b.fields.size(); ++fi) {
						b.field_by_offset.emplace(b.fields[fi].offset, fi);
					}

					auto sym_it = ms.pdb.symbol_by_name.find(sd.name);
					if (sym_it != ms.pdb.symbol_by_name.end()) {
						const auto& s = ms.pdb.symbols[sym_it->second];
						uint64_t va = mod->base + s.rva;
						if (va >= mod->base && va < mod->base + mod->size) {
							b.base_va = va;
							address_updates.emplace_back(va, kind_t::custom_struct);
						}
					}
					binding_updates.emplace_back(sd.type_index, std::move(b));
				}

				enum_updates.reserve(ms.pdb.enums.size());
				for (const auto& ed : ms.pdb.enums) {
					std::vector<std::pair<int64_t, std::string>> entries;
					entries.reserve(ed.members.size());
					for (const auto& em : ed.members) {
						entries.emplace_back(em.value, em.name);
					}
					enum_updates.emplace_back(ed.name, std::move(entries));
				}
			} else return;

			std::lock_guard<std::mutex> lk(mod->apply_lock);

			auto cur_bindings = std::atomic_load(&mod->struct_bindings);
			auto next_bindings = std::make_shared<struct_binding_map_t>(cur_bindings ? *cur_bindings : struct_binding_map_t());
			for (auto& bu : binding_updates) {
				(*next_bindings)[bu.first] = std::move(bu.second);
			}
			std::shared_ptr<const struct_binding_map_t> bindings_snapshot(std::move(next_bindings));
			std::atomic_store(&mod->struct_bindings, bindings_snapshot);

			auto cur_enums = std::atomic_load(&mod->enum_value_tables);
			auto next_enums = std::make_shared<enum_value_map_t>(cur_enums ? *cur_enums : enum_value_map_t());
			for (auto& eu : enum_updates) {
				(*next_enums)[eu.first] = std::move(eu.second);
			}
			std::shared_ptr<const enum_value_map_t> enums_snapshot(std::move(next_enums));
			std::atomic_store(&mod->enum_value_tables, enums_snapshot);

			if (!address_updates.empty()) {
				auto cur_kinds = std::atomic_load(&mod->address_kind);
				auto next_kinds = std::make_shared<address_kind_map_t>(cur_kinds ? *cur_kinds : address_kind_map_t());
				for (const auto& u : address_updates) {
					(*next_kinds)[u.first] = u.second;
				}
				std::shared_ptr<const address_kind_map_t> kinds_snapshot(std::move(next_kinds));
				std::atomic_store(&mod->address_kind, kinds_snapshot);
			}

			mod->apply_generation.fetch_add(1, std::memory_order_acq_rel);
		}

		inline void build_module_classification(std::shared_ptr<module_entry_t> mod) {
			if (!mod) return;
			if (driver_bridge::attached_pid() == 0) {
				mod->state.store(static_cast<uint32_t>(build_state_t::failed), std::memory_order_release);
				return;
			}
			pe_parser::pe_info_t pe;
			const bool pe_ok = pe_parser::parse(mod->base, pe);
			std::vector<section_range_t> sections;
			if (pe_ok) {
				sections.reserve(pe.sections.size());
				for (const auto& s : pe.sections) {
					sections.push_back(make_section_range(mod->base, s));
				}
			}

			auto kinds = std::make_shared<address_kind_map_t>();
			auto iat_map = std::make_shared<iat_funcname_map_t>();
			std::unordered_set<std::string> external_names;
			kinds->reserve(8192);

			const bool host_module_is_os = is_os_module(mod->name);

			if (pe_ok) {
				for (const auto& imp : pe.imports) {
					if (imp.bound_address != 0) {
						(*kinds)[imp.bound_address] = kind_t::external_import;
					}
					if (imp.iat_address != 0) {
						auto it = kinds->find(imp.iat_address);
						if (it == kinds->end()) kinds->emplace(imp.iat_address, kind_t::external_import);
						if (!imp.function_name.empty()) {
							std::string composite;
							if (!imp.module_name.empty()) {
								composite = imp.module_name;
								composite.push_back('!');
							}
							composite.append(imp.function_name);
							iat_map->emplace(imp.iat_address, std::move(composite));
						}
					}
					if (!imp.function_name.empty()) {
						external_names.insert(imp.function_name);
						if (!imp.module_name.empty()) {
							std::string composite = imp.module_name;
							composite.push_back('!');
							composite.append(imp.function_name);
							external_names.insert(std::move(composite));
						}
					}
				}

				for (const auto& exp : pe.exports) {
					if (exp.address == 0) continue;
					kind_t k = (host_module_is_os || is_library_name(exp.name))
						? kind_t::library_function
						: kind_t::regular_function;
					auto it = kinds->find(exp.address);
					if (it == kinds->end()) {
						kinds->emplace(exp.address, k);
					} else if (it->second == kind_t::regular_function && k == kind_t::library_function) {
						it->second = kind_t::library_function;
					}
				}
			}

			std::vector<uint32_t> rfn_starts;
			read_runtime_function_starts(mod->base, rfn_starts);
			for (uint32_t rva : rfn_starts) {
				uint64_t va = mod->base + rva;
				if (va < mod->base || va >= mod->base + mod->size) continue;
				auto it = kinds->find(va);
				if (it == kinds->end()) {
					kinds->emplace(va, host_module_is_os ? kind_t::library_function : kind_t::regular_function);
				}
			}

			constexpr size_t kMaxStringScanBytes = 4u * 1024u * 1024u;
			for (const auto& sec : sections) {
				if (!sec.is_data) continue;
				uint64_t span = sec.end_va > sec.start_va ? (sec.end_va - sec.start_va) : 0;
				if (span == 0) continue;
				size_t to_read = static_cast<size_t>(span < kMaxStringScanBytes ? span : kMaxStringScanBytes);
				std::vector<uint8_t> blob;
				if (!driver_bridge::read_memory(sec.start_va, to_read, blob) || blob.empty()) continue;
				scan_strings_in_blob(sec.start_va, blob, *kinds);
			}

			mod->sections = std::move(sections);
			mod->external_names = std::move(external_names);

			std::shared_ptr<const address_kind_map_t> kinds_snapshot(std::move(kinds));
			std::atomic_store(&mod->address_kind, kinds_snapshot);

			std::shared_ptr<const iat_funcname_map_t> iat_snapshot(std::move(iat_map));
			std::atomic_store(&mod->iat_to_funcname, iat_snapshot);

			apply_pdb_symbols(mod);
			apply_pdb_types(mod);

			mod->state.store(static_cast<uint32_t>(build_state_t::built), std::memory_order_release);
		}

		inline std::shared_ptr<module_entry_t> get_or_create_module_unlocked(registry_t& reg,
			const driver_bridge::module_info_t& m)
		{
			auto it = reg.modules.find(m.name);
			if (it != reg.modules.end()) {
				if (it->second->base == m.base && it->second->size == m.size)
					return it->second;
				reg.modules.erase(it);
			}
			auto mod = std::make_shared<module_entry_t>();
			mod->name = m.name;
			mod->base = m.base;
			mod->size = m.size;
			reg.modules.emplace(m.name, mod);
			return mod;
		}

		inline void rebuild_module_table_unlocked(registry_t& reg) {
			reg.table.clear();
			if (driver_bridge::attached_pid() == 0) {
				reg.table_built.store(true, std::memory_order_release);
				return;
			}
			auto mods = driver_bridge::enumerate_modules();
			reg.table.reserve(mods.size());
			for (const auto& m : mods) {
				if (m.base == 0 || m.size == 0) continue;
				module_range_t r;
				r.start_va = m.base;
				r.end_va = m.base + m.size;
				r.entry = get_or_create_module_unlocked(reg, m);
				reg.table.push_back(std::move(r));
			}
			std::sort(reg.table.begin(), reg.table.end(),
				[](const module_range_t& a, const module_range_t& b) {
					return a.start_va < b.start_va;
				});
			reg.table_built.store(true, std::memory_order_release);
		}

		inline bool rebuild_module_table_offlock(registry_t& reg) {
			if (driver_bridge::attached_pid() == 0) {
				std::scoped_lock<std::shared_mutex> w(reg.rw);
				reg.table.clear();
				reg.table_built.store(true, std::memory_order_release);
				return true;
			}

			auto mods = driver_bridge::enumerate_modules();

			std::vector<module_range_t> staged;
			staged.reserve(mods.size());
			std::vector<std::pair<std::string, std::shared_ptr<module_entry_t>>> new_modules;
			new_modules.reserve(mods.size());

			{
				std::shared_lock<std::shared_mutex> r_lk(reg.rw);
				for (const auto& m : mods) {
					if (m.base == 0 || m.size == 0) continue;
					module_range_t r;
					r.start_va = m.base;
					r.end_va = m.base + m.size;

					auto it = reg.modules.find(m.name);
					if (it != reg.modules.end() && it->second->base == m.base && it->second->size == m.size) {
						r.entry = it->second;
					} else {
						auto mod = std::make_shared<module_entry_t>();
						mod->name = m.name;
						mod->base = m.base;
						mod->size = m.size;
						r.entry = mod;
						new_modules.emplace_back(m.name, mod);
					}
					staged.push_back(std::move(r));
				}
			}

			std::sort(staged.begin(), staged.end(),
				[](const module_range_t& a, const module_range_t& b) {
					return a.start_va < b.start_va;
				});

			{
				std::scoped_lock<std::shared_mutex> w(reg.rw);
				for (auto& kv : new_modules) {
					auto it = reg.modules.find(kv.first);
					if (it == reg.modules.end()) {
						reg.modules.emplace(kv.first, kv.second);
					} else if (it->second->base != kv.second->base || it->second->size != kv.second->size) {
						it->second = kv.second;
					}
				}
				reg.table.swap(staged);
				reg.table_built.store(true, std::memory_order_release);
			}
			return true;
		}

		inline std::shared_ptr<module_entry_t> lookup_cached_module(uint64_t addr) {
			auto& reg = registry();
			std::shared_lock<std::shared_mutex> lk(reg.rw);
			if (!reg.table_built.load(std::memory_order_acquire)) return nullptr;
			if (reg.table.empty()) return nullptr;
			auto it = std::upper_bound(reg.table.begin(), reg.table.end(), addr,
				[](uint64_t a, const module_range_t& r) {
					return a < r.start_va;
				});
			if (it == reg.table.begin()) return nullptr;
			--it;
			if (addr < it->start_va || addr >= it->end_va) return nullptr;
			return it->entry;
		}

		inline void schedule_build_locked(std::shared_ptr<module_entry_t> mod) {
			if (!mod) return;
			uint32_t expected = static_cast<uint32_t>(build_state_t::idle);
			if (!mod->state.compare_exchange_strong(expected,
				static_cast<uint32_t>(build_state_t::building),
				std::memory_order_acq_rel))
				return;
			std::weak_ptr<module_entry_t> weak = mod;
			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "disasm";
			sub.label = "disasm.symbol_classifier.build_module";
			sub.thread_class = "bounded_task";
			sub.domain = aida::infra::executor::domain_t::feature_worker;
			sub.priority = 2;
			sub.body = [weak]() {
				auto strong = weak.lock();
				if (!strong) return;
				build_module_classification(strong);
			};
			if (!aida::infra::executor::submit(std::move(sub)).submitted)
				mod->state.store(static_cast<uint32_t>(build_state_t::failed),
					std::memory_order_release);
		}

		inline void clear_caches() {
			auto& reg = registry();
			{
				std::unique_lock<std::shared_mutex> lk(reg.rw);
				reg.table.clear();
				reg.modules.clear();
			}
			reg.table_built.store(false, std::memory_order_release);
			reg.rebuild_in_flight.store(false, std::memory_order_release);
			reg.generation.fetch_add(1, std::memory_order_acq_rel);
		}

		inline void schedule_table_rebuild_async() {
			auto& reg = registry();
			bool expected = false;
			if (!reg.rebuild_in_flight.compare_exchange_strong(expected, true,
				std::memory_order_acq_rel))
				return;
			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "disasm";
			sub.label = "disasm.symbol_classifier.rebuild_table";
			sub.thread_class = "bounded_task";
			sub.domain = aida::infra::executor::domain_t::feature_worker;
			sub.priority = 2;
			sub.body = [&reg]() {
				rebuild_module_table_offlock(reg);
				reg.rebuild_in_flight.store(false, std::memory_order_release);
			};
			if (!aida::infra::executor::submit(std::move(sub)).submitted)
				reg.rebuild_in_flight.store(false, std::memory_order_release);
		}

		inline void ensure_subscription() {
			auto& reg = registry();
			if (reg.subscription_armed.load(std::memory_order_acquire)) return;
			bool expected = false;
			if (!reg.subscription_armed.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
			reg.subscription = aida::events::subscribe(
				aida::events::event_binary_loaded,
				[](const aida::events::binary_loaded_t&) {
					clear_caches();
					schedule_table_rebuild_async();
				});
			if (!reg.subscription.valid()) {
				reg.subscription_armed.store(false, std::memory_order_release);
			}
		}

	}

	inline kind_t classify(uint64_t addr) {
		if (addr == 0) return kind_t::unknown;
		auto& reg = detail::registry();
		std::shared_ptr<detail::module_entry_t> entry;
		{
			std::shared_lock<std::shared_mutex> lk(reg.rw);
			if (!reg.table_built.load(std::memory_order_acquire)) return kind_t::unknown;
			if (reg.table.empty()) return kind_t::unknown;
			auto it = std::upper_bound(reg.table.begin(), reg.table.end(), addr,
				[](uint64_t a, const detail::module_range_t& r) {
					return a < r.start_va;
				});
			if (it == reg.table.begin()) return kind_t::unknown;
			--it;
			if (addr < it->start_va || addr >= it->end_va) return kind_t::unknown;
			entry = it->entry;
		}
		if (!entry) return kind_t::unknown;
		uint32_t st = entry->state.load(std::memory_order_acquire);
		if (st != static_cast<uint32_t>(detail::build_state_t::built)) return kind_t::unknown;
		auto m = std::atomic_load(&entry->address_kind);
		if (m) {
			auto kit = m->find(addr);
			if (kit != m->end()) return kit->second;
		}
		const detail::section_range_t* sec = detail::find_section(entry->sections, addr);
		if (sec) {
			if (sec->is_data) return kind_t::data;
			if (sec->is_code) return kind_t::unknown;
		}
		return kind_t::unknown;
	}

	inline kind_t classify_name(const std::string& name) {
		if (name.empty()) return kind_t::unknown;
		std::string_view nv(name);
		while (!nv.empty() && (nv.front() == ' ' || nv.front() == '\t')) nv.remove_prefix(1);
		while (!nv.empty() && (nv.back() == ' ' || nv.back() == '\t')) nv.remove_suffix(1);
		if (nv.empty()) return kind_t::unknown;

		if (detail::name_starts_with(nv, "__imp_")) return kind_t::imp_function;
		if (detail::name_starts_with(nv, "j_sub_")) return kind_t::jump_thunk;
		if (detail::name_starts_with(nv, "j_")) return kind_t::jump_thunk;
		if (detail::name_starts_with(nv, "sub_")) return kind_t::regular_function;
		if (detail::name_starts_with(nv, "nullsub_")) return kind_t::regular_function;
		if (detail::name_starts_with(nv, "locret_")) return kind_t::label;
		if (detail::name_starts_with(nv, "loc_")) return kind_t::label;
		if (detail::name_starts_with(nv, "case_")) return kind_t::case_label;
		if (detail::name_starts_with(nv, "def_")) return kind_t::default_case;
		if (detail::name_starts_with(nv, "off_")) return kind_t::offset_ref;
		if (detail::name_starts_with(nv, "seg_")) return kind_t::segment_ref;
		if (detail::name_starts_with(nv, "ptr_")) return kind_t::pointer_ref;
		if (detail::name_starts_with(nv, "stru_")) return kind_t::struct_ref;
		if (detail::name_starts_with(nv, "arr_")) return kind_t::array_ref;
		if (detail::name_starts_with(nv, "xmmword_")) return kind_t::data_xmmword;
		if (detail::name_starts_with(nv, "ymmword_")) return kind_t::data_ymmword;
		if (detail::name_starts_with(nv, "zmmword_")) return kind_t::data_zmmword;
		if (detail::name_starts_with(nv, "tbyte_")) return kind_t::data_tbyte;
		if (detail::name_starts_with(nv, "fword_")) return kind_t::data_fword;
		if (detail::name_starts_with(nv, "qword_")) return kind_t::data_qword;
		if (detail::name_starts_with(nv, "dword_")) return kind_t::data_dword;
		if (detail::name_starts_with(nv, "word_")) return kind_t::data_word;
		if (detail::name_starts_with(nv, "byte_")) return kind_t::data_byte;
		if (detail::name_starts_with(nv, "unk_")) return kind_t::data_unknown;
		if (detail::name_starts_with(nv, "align_")) return kind_t::align_directive;
		if (detail::name_starts_with(nv, "asc_")) return kind_t::string_ascii;
		if (detail::name_starts_with(nv, "str_")) return kind_t::string_unicode;
		if (nv.size() >= 3 && nv[0] == 'a' && nv[1] == 'S'
		    && ((nv[2] >= 'A' && nv[2] <= 'Z')
		        || (nv[2] >= 'a' && nv[2] <= 'z')
		        || (nv[2] >= '0' && nv[2] <= '9')
		        || nv[2] == '_')) {
			return kind_t::string_ascii;
		}
		if (detail::name_starts_with(nv, "var_")) return kind_t::stack_var;
		if (detail::name_starts_with(nv, "arg_")) return kind_t::stack_arg;
		if (detail::name_starts_with(nv, "saved_")) return kind_t::saved_reg;
		auto sr_tail_is_hex_or_reg = [](std::string_view rest) -> bool {
			if (rest.empty() || rest.size() > 8) return false;
			bool all_hex = true;
			for (char c : rest) {
				if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
					all_hex = false;
					break;
				}
			}
			if (all_hex) return true;
			return detail::is_register_token(rest);
		};
		if (detail::name_starts_with(nv, "s_") && nv.size() > 2 && sr_tail_is_hex_or_reg(nv.substr(2)))
			return kind_t::saved_reg;
		if (detail::name_starts_with(nv, "r_") && nv.size() > 2 && sr_tail_is_hex_or_reg(nv.substr(2)))
			return kind_t::restored_reg;

		if (nv.size() >= 2 && nv.front() == '.') {
			if (nv == ".text") return kind_t::section_text;
			if (nv == ".data") return kind_t::section_data;
			if (nv == ".rdata") return kind_t::section_rdata;
			if (nv == ".bss") return kind_t::section_bss;
			if (nv == ".rsrc") return kind_t::section_rsrc;
			if (nv == ".idata" || nv == ".tls" || nv == ".CRT" || nv == ".pdata"
			    || nv == ".xdata" || nv == ".reloc" || nv == ".edata" || nv == ".rodata") {
				return kind_t::section_other;
			}
		}

		if (nv == "start") return kind_t::entry_point;
		if (nv == "main" || nv == "_main" || nv == "wmain") return kind_t::main_function;
		if (nv == "WinMain" || nv == "wWinMain" || nv == "_WinMain") return kind_t::winmain_function;
		if (nv == "DllMain" || nv == "_DllMain" || nv == "DllEntryPoint") return kind_t::dllmain_function;

		if (detail::is_register_token(nv)) return kind_t::register_op;

		const auto bang = nv.find('!');
		if (bang != std::string_view::npos && bang > 0 && bang + 1 < nv.size()) {
			std::string_view module_part = nv.substr(0, bang);
			if (detail::is_os_module(module_part)) return kind_t::external_import;
		}

		auto& reg = detail::registry();
		{
			std::shared_lock<std::shared_mutex> lk(reg.rw);
			std::string key(nv);
			for (const auto& kv : reg.modules) {
				if (!kv.second) continue;
				uint32_t st = kv.second->state.load(std::memory_order_acquire);
				if (st != static_cast<uint32_t>(detail::build_state_t::built)) continue;
				if (kv.second->external_names.find(key) != kv.second->external_names.end()) {
					return kind_t::external_import;
				}
			}
		}

		if (detail::is_library_name(nv)) return kind_t::library_function;

		return kind_t::unknown;
	}

	inline const char* data_prefix_for_size(int size_bytes) {
		switch (size_bytes) {
			case 1:  return "byte";
			case 2:  return "word";
			case 4:  return "dword";
			case 6:  return "fword";
			case 8:  return "qword";
			case 10: return "tbyte";
			case 16: return "xmmword";
			case 32: return "ymmword";
			case 64: return "zmmword";
			default: return "unk";
		}
	}

	inline kind_t kind_for_data_size(int size_bytes) {
		switch (size_bytes) {
			case 1:  return kind_t::data_byte;
			case 2:  return kind_t::data_word;
			case 4:  return kind_t::data_dword;
			case 6:  return kind_t::data_fword;
			case 8:  return kind_t::data_qword;
			case 10: return kind_t::data_tbyte;
			case 16: return kind_t::data_xmmword;
			case 32: return kind_t::data_ymmword;
			case 64: return kind_t::data_zmmword;
			default: return kind_t::data_unknown;
		}
	}

	inline void warm_range(uint64_t lo_addr, uint64_t hi_addr) {
		if (hi_addr <= lo_addr) return;

		detail::ensure_subscription();

		auto& reg = detail::registry();

		if (!reg.table_built.load(std::memory_order_acquire)) {
			bool expected = false;
			if (reg.rebuild_in_flight.compare_exchange_strong(expected, true,
				std::memory_order_acq_rel))
			{
				aida::infra::executor::submission_t sub;
				sub.owner_subsystem = "disasm";
				sub.label = "disasm.symbol_classifier.warm_rebuild_table";
				sub.thread_class = "bounded_task";
				sub.domain = aida::infra::executor::domain_t::feature_worker;
				sub.priority = 2;
				sub.body = [&reg]() {
					detail::rebuild_module_table_offlock(reg);
					reg.rebuild_in_flight.store(false, std::memory_order_release);
				};
				if (!aida::infra::executor::submit(std::move(sub)).submitted)
					reg.rebuild_in_flight.store(false, std::memory_order_release);
			}
			return;
		}

		std::vector<std::shared_ptr<detail::module_entry_t>> targets;
		{
			std::shared_lock<std::shared_mutex> lk(reg.rw);
			targets.reserve(reg.table.size());
			for (const auto& r : reg.table) {
				if (r.end_va <= lo_addr || r.start_va >= hi_addr) continue;
				if (!r.entry) continue;
				uint32_t s = r.entry->state.load(std::memory_order_acquire);
				if (s != static_cast<uint32_t>(detail::build_state_t::idle)) continue;
				targets.push_back(r.entry);
			}
		}

		for (auto& mod : targets) {
			detail::schedule_build_locked(mod);
		}
	}

	inline void on_attach_changed() {
		detail::clear_caches();
		detail::ensure_subscription();
		detail::schedule_table_rebuild_async();
	}

	inline std::shared_ptr<detail::module_entry_t> find_module_by_address(uint64_t addr) {
		auto& reg = detail::registry();
		std::shared_lock<std::shared_mutex> lk(reg.rw);
		if (!reg.table_built.load(std::memory_order_acquire)) return nullptr;
		if (reg.table.empty()) return nullptr;
		auto it = std::upper_bound(reg.table.begin(), reg.table.end(), addr,
			[](uint64_t a, const detail::module_range_t& r) {
				return a < r.start_va;
			});
		if (it == reg.table.begin()) return nullptr;
		--it;
		if (addr < it->start_va || addr >= it->end_va) return nullptr;
		return it->entry;
	}

	inline std::shared_ptr<detail::module_entry_t> find_module_by_name(std::string_view module_name) {
		auto& reg = detail::registry();
		std::shared_lock<std::shared_mutex> lk(reg.rw);
		std::string key(module_name);
		auto it = reg.modules.find(key);
		if (it != reg.modules.end()) return it->second;
		for (const auto& kv : reg.modules) {
			if (!kv.second) continue;
			if (kv.first.size() == module_name.size()) {
				bool eq = true;
				for (size_t i = 0; i < module_name.size(); ++i) {
					if (!detail::ascii_eq_lower(kv.first[i], module_name[i])) { eq = false; break; }
				}
				if (eq) return kv.second;
			}
		}
		return nullptr;
	}

	inline bool mark_address_kind(uint64_t va, kind_t k) {
		if (va == 0) return false;
		auto mod = find_module_by_address(va);
		if (!mod) return false;
		std::lock_guard<std::mutex> lk(mod->apply_lock);
		auto cur = std::atomic_load(&mod->address_kind);
		auto next = std::make_shared<detail::address_kind_map_t>(cur ? *cur : detail::address_kind_map_t());
		(*next)[va] = k;
		std::shared_ptr<const detail::address_kind_map_t> snapshot(std::move(next));
		std::atomic_store(&mod->address_kind, snapshot);
		mod->apply_generation.fetch_add(1, std::memory_order_acq_rel);
		return true;
	}

	inline bool lookup_import_by_iat(uint64_t iat_va, std::string& out_name) {
		out_name.clear();
		if (iat_va == 0) return false;
		auto mod = find_module_by_address(iat_va);
		if (!mod) {
			auto& reg = detail::registry();
			std::vector<std::shared_ptr<detail::module_entry_t>> mods;
			{
				std::shared_lock<std::shared_mutex> lk(reg.rw);
				mods.reserve(reg.modules.size());
				for (const auto& kv : reg.modules) {
					if (kv.second) mods.push_back(kv.second);
				}
			}
			for (auto& m : mods) {
				auto snap = std::atomic_load(&m->iat_to_funcname);
				if (!snap) continue;
				auto it = snap->find(iat_va);
				if (it != snap->end()) {
					out_name = it->second;
					return true;
				}
			}
			return false;
		}
		auto snap = std::atomic_load(&mod->iat_to_funcname);
		if (!snap) return false;
		auto it = snap->find(iat_va);
		if (it == snap->end()) return false;
		out_name = it->second;
		return true;
	}

	inline std::shared_ptr<const detail::struct_binding_map_t> get_struct_bindings(std::shared_ptr<detail::module_entry_t> mod) {
		if (!mod) return detail::empty_struct_binding_snapshot();
		auto snap = std::atomic_load(&mod->struct_bindings);
		if (!snap) return detail::empty_struct_binding_snapshot();
		return snap;
	}

	inline std::shared_ptr<const detail::enum_value_map_t> get_enum_value_tables(std::shared_ptr<detail::module_entry_t> mod) {
		if (!mod) return detail::empty_enum_value_snapshot();
		auto snap = std::atomic_load(&mod->enum_value_tables);
		if (!snap) return detail::empty_enum_value_snapshot();
		return snap;
	}

	inline uint64_t module_apply_generation(std::shared_ptr<detail::module_entry_t> mod) {
		if (!mod) return 0;
		return mod->apply_generation.load(std::memory_order_acquire);
	}

	namespace detail {

		inline void handle_pdb_loaded(const aida::events::event_pdb_loaded& ev) {
			if (ev.module_name.empty()) return;
			if (!ev.success) return;
			auto& reg = registry();
			std::vector<std::shared_ptr<module_entry_t>> targets;
			{
				std::shared_lock<std::shared_mutex> lk(reg.rw);
				auto it = reg.modules.find(ev.module_name);
				if (it != reg.modules.end() && it->second) {
					targets.push_back(it->second);
				} else {
					for (const auto& kv : reg.modules) {
						if (!kv.second) continue;
						if (kv.first.size() != ev.module_name.size()) continue;
						bool eq = true;
						for (size_t i = 0; i < kv.first.size(); ++i) {
							if (!ascii_eq_lower(kv.first[i], ev.module_name[i])) { eq = false; break; }
						}
						if (eq) {
							targets.push_back(kv.second);
							break;
						}
					}
				}
			}

			for (auto& mod : targets) {
				if (!mod) continue;
				uint32_t st = mod->state.load(std::memory_order_acquire);
				if (st != static_cast<uint32_t>(build_state_t::built)) continue;
				bool expected = false;
				if (!mod->apply_in_flight.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
					continue;
				}
				std::weak_ptr<module_entry_t> weak = mod;
				aida::infra::executor::submission_t sub;
				sub.owner_subsystem = "disasm";
				sub.label = "disasm.symbol_classifier.apply_pdb";
				sub.thread_class = "bounded_task";
				sub.domain = aida::infra::executor::domain_t::feature_worker;
				sub.priority = 2;
				sub.body = [weak]() {
					auto strong = weak.lock();
					if (!strong) return;
					apply_pdb_symbols(strong);
					apply_pdb_types(strong);
					strong->apply_in_flight.store(false, std::memory_order_release);
				};
				if (!aida::infra::executor::submit(std::move(sub)).submitted)
					mod->apply_in_flight.store(false, std::memory_order_release);
			}
		}

	}

	inline void subscribe_pdb_events() {
		auto& reg = detail::registry();
		if (reg.pdb_subscription_armed.load(std::memory_order_acquire)) return;
		bool expected = false;
		if (!reg.pdb_subscription_armed.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
		reg.pdb_subscription = aida::events::subscribe(
			aida::events::event_pdb_loaded_def,
			[](const aida::events::event_pdb_loaded& ev) {
				detail::handle_pdb_loaded(ev);
			});
		if (!reg.pdb_subscription.valid()) {
			reg.pdb_subscription_armed.store(false, std::memory_order_release);
		}
	}

	inline void unsubscribe_pdb_events() {
		auto& reg = detail::registry();
		if (!reg.pdb_subscription_armed.load(std::memory_order_acquire)) return;
		if (reg.pdb_subscription.valid()) {
			aida::events::unsubscribe(reg.pdb_subscription);
		}
		reg.pdb_subscription = aida::events::subscription_handle_t{};
		reg.pdb_subscription_armed.store(false, std::memory_order_release);
	}

}
