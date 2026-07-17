#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace aida::theme_transfer {

inline constexpr std::size_t maximum_theme_count = 128;
inline constexpr std::size_t maximum_theme_name_bytes = 96;
inline constexpr std::size_t maximum_icon_path_bytes = 1024;

struct theme_t {
    std::string name;
    std::array<float, 3> accent{};
    std::uint32_t bg_base = 0;
    std::uint32_t panel_bg = 0;
    std::uint32_t panel_header = 0;
    std::uint32_t title_bar = 0;
    std::uint32_t text_primary = 0;
    std::uint32_t text_secondary = 0;
    std::uint32_t text_dim = 0;
    std::uint32_t acrylic_color = 0;
    int icon_index = -1;
    std::string icon_file_path;
};

enum class operation_t : std::uint8_t {
    import_theme,
    export_theme
};

enum class request_result_t : std::uint8_t {
    queued,
    preview_recorded,
    busy,
    rejected
};

struct completion_t {
    std::uint64_t serial = 0;
    operation_t operation = operation_t::import_theme;
    bool success = false;
    std::string error;
    std::optional<theme_t> imported_theme;
};

struct status_t {
    bool pending = false;
    bool failed = false;
    bool retryable = false;
    std::string stage;
    std::string error;
};

request_result_t request_import(std::string path) noexcept;
request_result_t request_export(std::string path, const theme_t& theme) noexcept;
std::optional<completion_t> take_completion() noexcept;
void acknowledge_import(std::uint64_t serial, bool applied, std::string error = {}) noexcept;
bool request_retry() noexcept;
status_t status() noexcept;

}
