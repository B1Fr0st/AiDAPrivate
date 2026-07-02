#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace aida { namespace burp { namespace decoder {
struct transform_result_t { bool success=false; std::string output; std::vector<uint8_t> output_bytes; std::string error; std::string detected_format; };
std::vector<std::string> available_transforms();
transform_result_t apply_transform(const std::string& name, const std::vector<uint8_t>& input);
transform_result_t apply_pipeline(const std::vector<std::string>& transforms, const std::vector<uint8_t>& input);
transform_result_t smart_detect(const std::vector<uint8_t>& input);
}}}
