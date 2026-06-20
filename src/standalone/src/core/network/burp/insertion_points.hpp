#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace aida {
namespace burp {

struct insertion_point_build_options_t
{
    bool force_json_string = false;
    bool preserve_json_scalar_type = true;
};

struct insertion_point_t
{
    std::string                                                     kind;
    std::string                                                     name;
    std::string                                                     original_value;
    std::string                                                     value_type;
    std::string                                                     base_request;
    size_t                                                          value_offset = 0;
    size_t                                                          value_length = 0;
    std::function<std::vector<uint8_t>(const std::string& injected)> build;
    std::function<std::vector<uint8_t>(const std::string& injected,
                                       const insertion_point_build_options_t& options)> build_with_options;
};

namespace insertion_points {

std::vector<insertion_point_t> analyze(const std::vector<uint8_t>& raw_request,
                                       const std::string& url);

std::string url_encode(const std::string& s);
std::string url_decode(const std::string& s);

}

}
}
