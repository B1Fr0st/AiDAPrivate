#pragma once

#include <cstdint>
#include "imgui/imgui.h"

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
		kind_comment          = 11
	};

	inline ImU32 segment()           { return IM_COL32(108, 172, 202, 255); }
	inline ImU32 address()           { return IM_COL32(108, 198, 252, 255); }
	inline ImU32 bytes()             { return IM_COL32(132, 132, 142, 255); }
	inline ImU32 mnemonic()          { return IM_COL32(255,  95,  90, 255); }
	inline ImU32 reg()               { return IM_COL32(132, 202, 230, 255); }
	inline ImU32 reg_ptr()           { return IM_COL32(150, 212, 234, 255); }
	inline ImU32 immediate_num()     { return IM_COL32(240, 134, 134, 255); }
	inline ImU32 immediate_offset()  { return IM_COL32(228, 226, 240, 255); }
	inline ImU32 string_ref()        { return IM_COL32(232, 198, 116, 255); }
	inline ImU32 imp_func()          { return IM_COL32(255, 130, 200, 255); }
	inline ImU32 external_func()     { return IM_COL32(255, 130, 200, 255); }
	inline ImU32 library_func()      { return IM_COL32(100, 175, 255, 255); }
	inline ImU32 lumina_func()       { return IM_COL32(120, 220, 130, 255); }
	inline ImU32 sub_label()         { return IM_COL32(255, 165,  60, 255); }
	inline ImU32 loc_label()         { return IM_COL32(245, 180,  84, 255); }
	inline ImU32 func_name()         { return IM_COL32(255, 165,  60, 255); }
	inline ImU32 data_ref()          { return IM_COL32(255, 200, 100, 255); }
	inline ImU32 comment()           { return IM_COL32(132, 218, 134, 255); }
	inline ImU32 xref()              { return IM_COL32(112, 198, 112, 235); }
	inline ImU32 separator()         { return IM_COL32( 92,  92, 102, 255); }
	inline ImU32 banner()            { return IM_COL32(132, 220, 184, 255); }
	inline ImU32 var_decl()          { return IM_COL32(220, 220, 134, 255); }
	inline ImU32 var_use()           { return IM_COL32(222, 222, 152, 255); }
	inline ImU32 keyword()           { return IM_COL32(230, 152, 200, 255); }
	inline ImU32 directive()         { return IM_COL32(224, 156, 214, 255); }
	inline ImU32 selection_bg()      { return IM_COL32( 72,  96, 168,  80); }
	inline ImU32 cursor_line_bg()    { return IM_COL32( 60,  84, 138,  60); }
	inline ImU32 gutter_bg()         { return IM_COL32( 22,  24,  32, 255); }
	inline ImU32 panel_bg()          { return IM_COL32( 14,  16,  24, 255); }
	inline ImU32 arrow_up()          { return IM_COL32(120, 196, 244, 255); }
	inline ImU32 arrow_down()        { return IM_COL32(244, 188, 120, 255); }
	inline bool  is_dark_theme()     { return true; }

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
			case kind_unknown:
			default:                    return address();
		}
	}

}
