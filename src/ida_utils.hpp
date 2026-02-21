#pragma once

#include <string>
#include <utility>

#include <ida.hpp>
#include <typeinf.hpp>
#include <nlohmann/json.hpp>

class settings_t;

namespace ida_utils
{
    std::string markup_text_with_addresses(const std::string& text);
    using get_code_callback_t = std::function<void(const std::pair<std::string, std::string>&)>;
    void get_function_code(ea_t ea, get_code_callback_t callback, size_t max_len = 0, bool force_assembly = false);
    std::pair<std::string, std::string> get_function_code(ea_t ea, size_t max_len = 0, bool force_assembly = false);
    std::string get_code_xrefs_to(ea_t ea, const settings_t& settings);
    std::string get_code_xrefs_from(ea_t ea, const settings_t& settings);
    std::string get_struct_usage_context(ea_t ea);
    std::string get_data_xrefs_for_struct(const tinfo_t& struct_tif, const settings_t& settings);
    nlohmann::json get_context_for_prompt(ea_t ea, bool include_struct_context = false, size_t max_len = 0);
    std::string format_context_for_clipboard(const nlohmann::json& context);
    bool set_clipboard_text(const qstring& text);
    void apply_struct_from_cpp(const std::string& cpp_code, ea_t ea);
    std::string format_prompt(const char* prompt_template, const nlohmann::json& context);
    bool is_word_char(char c);
    func_t* get_function_for_item(ea_t ea);
    qstring qstring_tolower(const qstring& s);
    bool get_address_from_line_pos(ea_t* out_ea, const char* line, int x);
    qstring apply_renames_from_ai(ea_t func_ea, const std::string& cpp_code);

    std::string get_binary_metadata();
    std::string get_imports_for_function(ea_t ea);
    std::string get_type_context_for_function(ea_t ea);
    nlohmann::json get_rag_context(ea_t ea, const settings_t& settings, const nlohmann::json* cached_context = nullptr);

    nlohmann::json get_full_cached_context(ea_t ea, const settings_t& settings, bool include_struct_context = true, size_t max_len = 0);

    void invalidate_rag_cache();
    void invalidate_rag_cache_for(ea_t ea);

    void apply_struct_from_cpp_ex(const std::string& cpp_code, ea_t ea, const std::string& target_param = "");
    bool update_existing_struct(const std::string& struct_name, const std::string& new_definition);
}