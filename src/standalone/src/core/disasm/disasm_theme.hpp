#pragma once

#include <cstdint>
#include "imgui/imgui.h"
#include "../ui/theme.hpp"

namespace disasm_theme {

	enum kind_int_t {
		kind_unknown          = 0,
		kind_regular_function = 1,
		kind_library_function = 2,
		kind_lumina_function  = 3,
		kind_external_import  = 4,
		kind_instruction      = 5,
		kind_data             = 6,
		kind_string           = 7,
		kind_label            = 8,
		kind_register_op      = 9,
		kind_immediate        = 10,
		kind_comment          = 11,
		kind_data_byte        = 12,
		kind_data_word        = 13,
		kind_data_dword       = 14,
		kind_data_qword       = 15,
		kind_data_xmmword     = 16,
		kind_data_ymmword     = 17,
		kind_data_zmmword     = 18,
		kind_data_tbyte       = 19,
		kind_data_fword       = 20,
		kind_string_ascii     = 21,
		kind_string_unicode   = 22,
		kind_struct_ref       = 23,
		kind_array_ref        = 24,
		kind_offset_ref       = 25,
		kind_segment_ref      = 26,
		kind_pointer_ref      = 27,
		kind_data_unknown     = 28,
		kind_align_directive  = 29,
		kind_jump_thunk       = 30,
		kind_case_label       = 31,
		kind_default_case     = 32,
		kind_stack_var        = 33,
		kind_stack_arg        = 34,
		kind_saved_reg        = 35,
		kind_restored_reg     = 36,
		kind_section_text     = 37,
		kind_section_data     = 38,
		kind_section_rdata    = 39,
		kind_section_bss      = 40,
		kind_section_rsrc     = 41,
		kind_section_other    = 42,
		kind_custom_struct    = 43,
		kind_enum_value       = 44,
		kind_typelib_type     = 45,
		kind_mnem_branch      = 46,
		kind_mnem_call        = 47,
		kind_mnem_ret         = 48,
		kind_mnem_arith       = 49,
		kind_mnem_logic       = 50,
		kind_mnem_data        = 51,
		kind_mnem_sse         = 52,
		kind_mnem_string      = 53,
		kind_mnem_priv        = 54,
		kind_mnem_nop         = 55,
		kind_mnem_int         = 56,
		kind_mnem_other       = 57,
		kind_imp_function     = 58,
		kind_entry_point      = 59,
		kind_main_function    = 60,
		kind_winmain_function = 61,
		kind_dllmain_function = 62
	};

	inline bool is_dark_theme() { return aida::ui::resolved().is_dark; }

	inline ImU32 with_a(ImU32 c, int a) {
		return (c & 0x00FFFFFFu) | (static_cast<ImU32>(a & 0xFF) << 24);
	}

	inline ImU32 segment()           { return aida::ui::resolved().text_dim; }
	inline ImU32 address()           { return aida::ui::resolved().syn_address; }
	inline ImU32 bytes()             { return aida::ui::resolved().text_dim; }
	inline ImU32 mnemonic()          { return aida::ui::resolved().syn_keyword; }
	inline ImU32 reg()               { return aida::ui::resolved().syn_register; }
	inline ImU32 reg_ptr()           { return aida::ui::resolved().syn_register; }
	inline ImU32 immediate_num()     { return aida::ui::resolved().syn_number; }
	inline ImU32 immediate_offset()  { return aida::ui::resolved().text_secondary; }
	inline ImU32 string_ref()        { return aida::ui::resolved().syn_string; }
	inline ImU32 imp_func()          { return aida::ui::resolved().error; }
	inline ImU32 external_func()     { return aida::ui::resolved().error; }
	inline ImU32 library_func()      { return aida::ui::resolved().info; }
	inline ImU32 lumina_func()       { return aida::ui::resolved().success; }
	inline ImU32 sub_label()         { return aida::ui::resolved().syn_function; }
	inline ImU32 loc_label()         { return aida::ui::resolved().syn_function; }
	inline ImU32 func_name()         { return aida::ui::resolved().syn_function; }
	inline ImU32 data_ref()          { return aida::ui::resolved().syn_register; }
	inline ImU32 comment()           { return aida::ui::resolved().syn_comment; }
	inline ImU32 xref()              { return with_a(aida::ui::resolved().success, 235); }
	inline ImU32 separator()         { return aida::ui::resolved().border_subtle; }
	inline ImU32 banner()            { return aida::ui::resolved().accent_u32; }
	inline ImU32 var_decl()          { return aida::ui::resolved().syn_register; }
	inline ImU32 var_use()           { return aida::ui::resolved().syn_identifier; }
	inline ImU32 keyword()           { return aida::ui::resolved().syn_keyword; }
	inline ImU32 directive()         { return aida::ui::resolved().syn_preprocessor; }
	inline ImU32 selection_bg()      { return aida::ui::resolved().selection; }
	inline ImU32 cursor_line_bg()    { return aida::ui::resolved().hover_wash; }
	inline ImU32 gutter_bg()         { return aida::ui::resolved().bg_elevated; }
	inline ImU32 panel_bg()          { return aida::ui::resolved().bg_base; }
	inline ImU32 arrow_up()          { return aida::ui::resolved().success; }
	inline ImU32 arrow_down()        { return aida::ui::resolved().warning; }

	inline ImU32 data_byte()         { return aida::ui::resolved().syn_number; }
	inline ImU32 data_word()         { return aida::ui::resolved().syn_number; }
	inline ImU32 data_dword()        { return aida::ui::resolved().syn_number; }
	inline ImU32 data_qword()        { return aida::ui::resolved().syn_number; }
	inline ImU32 data_xmmword()      { return aida::ui::resolved().syn_type; }
	inline ImU32 data_ymmword()      { return aida::ui::resolved().syn_type; }
	inline ImU32 data_zmmword()      { return aida::ui::resolved().syn_type; }
	inline ImU32 data_tbyte()        { return aida::ui::resolved().warning; }
	inline ImU32 data_fword()        { return aida::ui::resolved().warning; }
	inline ImU32 string_ascii()      { return aida::ui::resolved().syn_string; }
	inline ImU32 string_unicode()    { return aida::ui::resolved().syn_string; }
	inline ImU32 struct_ref()        { return aida::ui::resolved().syn_type; }
	inline ImU32 array_ref()         { return aida::ui::resolved().syn_type; }
	inline ImU32 offset_ref()        { return aida::ui::resolved().text_secondary; }
	inline ImU32 segment_ref()       { return aida::ui::resolved().text_dim; }
	inline ImU32 pointer_ref()       { return aida::ui::resolved().info; }
	inline ImU32 data_unknown()      { return aida::ui::resolved().text_dim; }
	inline ImU32 align_directive()   { return aida::ui::resolved().syn_comment; }
	inline ImU32 jump_thunk()        { return aida::ui::resolved().error; }
	inline ImU32 case_label()        { return aida::ui::resolved().syn_register; }
	inline ImU32 default_case()      { return aida::ui::resolved().warning; }
	inline ImU32 stack_var()         { return aida::ui::resolved().syn_register; }
	inline ImU32 stack_arg()         { return aida::ui::resolved().syn_identifier; }
	inline ImU32 saved_reg()         { return aida::ui::resolved().text_dim; }
	inline ImU32 restored_reg()      { return aida::ui::resolved().text_secondary; }
	inline ImU32 section_text()      { return aida::ui::resolved().info; }
	inline ImU32 section_data()      { return aida::ui::resolved().syn_register; }
	inline ImU32 section_rdata()     { return aida::ui::resolved().syn_type; }
	inline ImU32 section_bss()       { return aida::ui::resolved().text_dim; }
	inline ImU32 section_rsrc()      { return aida::ui::resolved().warning; }
	inline ImU32 section_other()     { return aida::ui::resolved().text_secondary; }
	inline ImU32 custom_struct()     { return aida::ui::resolved().syn_type; }
	inline ImU32 enum_value()        { return aida::ui::resolved().syn_number; }
	inline ImU32 typelib_type()      { return aida::ui::resolved().syn_type; }
	inline ImU32 mnem_branch()       { return aida::ui::resolved().warning; }
	inline ImU32 mnem_call()         { return aida::ui::resolved().syn_keyword; }
	inline ImU32 mnem_ret()          { return aida::ui::resolved().error; }
	inline ImU32 mnem_arith()        { return aida::ui::resolved().syn_keyword; }
	inline ImU32 mnem_logic()        { return aida::ui::resolved().syn_keyword; }
	inline ImU32 mnem_data()         { return aida::ui::resolved().syn_keyword; }
	inline ImU32 mnem_sse()          { return aida::ui::resolved().syn_type; }
	inline ImU32 mnem_string()       { return aida::ui::resolved().syn_string; }
	inline ImU32 mnem_priv()         { return aida::ui::resolved().warning; }
	inline ImU32 mnem_nop()          { return aida::ui::resolved().text_dim; }
	inline ImU32 mnem_int()          { return aida::ui::resolved().error; }
	inline ImU32 mnem_other()        { return aida::ui::resolved().syn_keyword; }
	inline ImU32 entry_point()       { return aida::ui::resolved().accent_u32; }
	inline ImU32 main_function()     { return aida::ui::resolved().success; }
	inline ImU32 winmain_function()  { return aida::ui::resolved().success; }
	inline ImU32 dllmain_function()  { return aida::ui::resolved().success; }

	inline ImU32 color_for_kind(int kind) {
		switch (kind) {
			case kind_regular_function: return sub_label();
			case kind_library_function: return library_func();
			case kind_lumina_function:  return lumina_func();
			case kind_external_import:  return imp_func();
			case kind_instruction:      return mnemonic();
			case kind_data:             return data_ref();
			case kind_string:           return string_ref();
			case kind_label:            return loc_label();
			case kind_register_op:      return reg();
			case kind_immediate:        return immediate_num();
			case kind_comment:          return comment();
			case kind_data_byte:        return data_byte();
			case kind_data_word:        return data_word();
			case kind_data_dword:       return data_dword();
			case kind_data_qword:       return data_qword();
			case kind_data_xmmword:     return data_xmmword();
			case kind_data_ymmword:     return data_ymmword();
			case kind_data_zmmword:     return data_zmmword();
			case kind_data_tbyte:       return data_tbyte();
			case kind_data_fword:       return data_fword();
			case kind_string_ascii:     return string_ascii();
			case kind_string_unicode:   return string_unicode();
			case kind_struct_ref:       return struct_ref();
			case kind_array_ref:        return array_ref();
			case kind_offset_ref:       return offset_ref();
			case kind_segment_ref:      return segment_ref();
			case kind_pointer_ref:      return pointer_ref();
			case kind_data_unknown:     return data_unknown();
			case kind_align_directive:  return align_directive();
			case kind_jump_thunk:       return jump_thunk();
			case kind_case_label:       return case_label();
			case kind_default_case:     return default_case();
			case kind_stack_var:        return stack_var();
			case kind_stack_arg:        return stack_arg();
			case kind_saved_reg:        return saved_reg();
			case kind_restored_reg:     return restored_reg();
			case kind_section_text:     return section_text();
			case kind_section_data:     return section_data();
			case kind_section_rdata:    return section_rdata();
			case kind_section_bss:      return section_bss();
			case kind_section_rsrc:     return section_rsrc();
			case kind_section_other:    return section_other();
			case kind_custom_struct:    return custom_struct();
			case kind_enum_value:       return enum_value();
			case kind_typelib_type:     return typelib_type();
			case kind_mnem_branch:      return mnem_branch();
			case kind_mnem_call:        return mnem_call();
			case kind_mnem_ret:         return mnem_ret();
			case kind_mnem_arith:       return mnem_arith();
			case kind_mnem_logic:       return mnem_logic();
			case kind_mnem_data:        return mnem_data();
			case kind_mnem_sse:         return mnem_sse();
			case kind_mnem_string:      return mnem_string();
			case kind_mnem_priv:        return mnem_priv();
			case kind_mnem_nop:         return mnem_nop();
			case kind_mnem_int:         return mnem_int();
			case kind_mnem_other:       return mnem_other();
			case kind_imp_function:     return imp_func();
			case kind_entry_point:      return entry_point();
			case kind_main_function:    return main_function();
			case kind_winmain_function: return winmain_function();
			case kind_dllmain_function: return dllmain_function();
			case kind_unknown:
			default:                    return address();
		}
	}

	inline ImU32 color_for_section_name(const char* sec_name) {
		if (!sec_name || !*sec_name) return section_other();
		if (sec_name[0] != '.') return section_other();
		if (sec_name[1] == 't' && sec_name[2] == 'e' && sec_name[3] == 'x' && sec_name[4] == 't') return section_text();
		if (sec_name[1] == 'r' && sec_name[2] == 'd' && sec_name[3] == 'a' && sec_name[4] == 't' && sec_name[5] == 'a') return section_rdata();
		if (sec_name[1] == 'd' && sec_name[2] == 'a' && sec_name[3] == 't' && sec_name[4] == 'a') return section_data();
		if (sec_name[1] == 'b' && sec_name[2] == 's' && sec_name[3] == 's') return section_bss();
		if (sec_name[1] == 'r' && sec_name[2] == 's' && sec_name[3] == 'r' && sec_name[4] == 'c') return section_rsrc();
		return section_other();
	}

}
