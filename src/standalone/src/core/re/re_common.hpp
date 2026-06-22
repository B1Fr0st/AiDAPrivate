#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "../settings/standalone_compat.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../disasm/zydis_disasm.hpp"

namespace re
{
using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

struct parsed_pattern_byte_t
{
    std::uint8_t value = 0;
    bool wildcard = false;
};

struct module_section_t
{
    std::string name;
    std::uint64_t va = 0;
    std::uint64_t size = 0;
    std::uint32_t characteristics = 0;
};

struct module_layout_t
{
    driver_bridge::module_info_t module;
    std::uint16_t machine = 0;
    std::uint16_t optional_magic = 0;
    bool is_pe32_plus = false;
    std::uint32_t pointer_size = 0;
    std::vector<module_section_t> sections;
};

class active_process_scope_t
{
public:
    explicit active_process_scope_t(const json& params);
    explicit active_process_scope_t(std::uint32_t requested_pid);
    active_process_scope_t(const active_process_scope_t&) = delete;
    active_process_scope_t& operator=(const active_process_scope_t&) = delete;
    ~active_process_scope_t();

    bool ok() const noexcept;
    std::uint32_t pid() const noexcept;
    const std::string& error() const noexcept;

private:
    void enter(std::uint32_t requested_pid);
    std::uint32_t previous_pid_ = 0;
    std::uint32_t active_pid_ = 0;
    bool switched_ = false;
    bool ok_ = false;
    std::string error_;
};

std::string lower_ascii(std::string value);
std::string trim_ascii(std::string value);
bool process_alive(std::uint32_t pid);
bool parse_u64_value(const json& value, std::uint64_t& out);
bool parse_u32_value(const json& value, std::uint32_t& out);
bool parse_address_param(const json& params, const char* key, std::uint64_t& out);
bool parse_pid_param(const json& params, std::uint32_t& out);
std::uint64_t numeric_param(const json& params, const char* key, std::uint64_t fallback, std::uint64_t min_value, std::uint64_t max_value);
double number_param(const json& params, const char* key, double fallback, double min_value, double max_value);
bool bool_param(const json& params, const char* key, bool fallback);
std::string string_param(const json& params, const char* key, const std::string& fallback = {});
bool unsafe_confirmed(const json& params);
tool_result_t unsafe_required(const char* operation);

bool is_committed(const driver_bridge::memory_region_t& region);
bool is_guarded(const driver_bridge::memory_region_t& region);
bool is_readable(const driver_bridge::memory_region_t& region);
bool is_writable(const driver_bridge::memory_region_t& region);
bool is_executable(const driver_bridge::memory_region_t& region);

std::vector<driver_bridge::module_info_t> modules_for(std::uint32_t pid);
std::vector<driver_bridge::memory_region_t> regions_for(std::uint32_t pid, std::size_t max_regions = 4096);
std::vector<driver_bridge::thread_info_t> threads_for(std::uint32_t pid);
std::optional<driver_bridge::module_info_t> find_module_by_name(std::uint32_t pid, const std::string& name);
std::optional<driver_bridge::module_info_t> find_module_for_address(std::uint32_t pid, std::uint64_t address);
bool query_region(std::uint32_t pid, std::uint64_t address, driver_bridge::memory_region_t& out);
bool read_bytes(std::uint32_t pid, std::uint64_t address, std::size_t size, std::vector<std::uint8_t>& out);
bool write_bytes(std::uint32_t pid, std::uint64_t address, const std::vector<std::uint8_t>& data);
bool read_u64(std::uint32_t pid, std::uint64_t address, std::uint64_t& out);
bool read_u32(std::uint32_t pid, std::uint64_t address, std::uint32_t& out);
bool read_u16(std::uint32_t pid, std::uint64_t address, std::uint16_t& out);
bool write_u64(std::uint32_t pid, std::uint64_t address, std::uint64_t value);
std::uint64_t allocate_remote(std::uint32_t pid, std::size_t size);
bool free_remote(std::uint32_t pid, std::uint64_t address);
bool protect_remote(std::uint32_t pid, std::uint64_t address, std::uint64_t size, std::uint32_t protect, std::uint32_t* old_protect = nullptr);

std::string bytes_to_hex(const std::vector<std::uint8_t>& data, std::size_t max_bytes = static_cast<std::size_t>(-1));
std::vector<std::uint8_t> u64_to_le(std::uint64_t value);
bool parse_pattern(const std::string& text, std::vector<parsed_pattern_byte_t>& out, std::string* error = nullptr);
bool pattern_matches(const std::uint8_t* data, std::size_t len, const std::vector<parsed_pattern_byte_t>& pattern);
std::vector<std::uint64_t> scan_pattern(std::uint32_t pid,
                                        const std::vector<parsed_pattern_byte_t>& pattern,
                                        const std::string& module_hint,
                                        bool executable_only,
                                        std::size_t max_results);

AsmInstr decode_one(std::uint32_t pid, std::uint64_t address);
std::string disasm_text(const AsmInstr& ins);
std::vector<json> disasm_preview(std::uint32_t pid, std::uint64_t address, std::size_t max_instructions);
std::string classify_instruction_hint(const AsmInstr& ins);
std::string classify_function_hint(std::uint32_t pid, std::uint64_t address);

bool load_module_layout(std::uint32_t pid, const driver_bridge::module_info_t& module, module_layout_t& out);
std::string sanitize_identifier(std::string value, const std::string& fallback);
std::filesystem::path appdata_re_dir();
bool read_json_file(const std::filesystem::path& path, json& out);
bool write_json_file_atomic(const std::filesystem::path& path, const json& value);
std::uint64_t unix_time_ms();
json region_json(const driver_bridge::memory_region_t& region);
json module_json(const driver_bridge::module_info_t& module);
}
