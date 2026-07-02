#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_decoder_mcp.hpp"
#include "decoder.hpp"
#include "../../settings/standalone_compat.hpp"
#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace decoder_mcp {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace {

std::vector<uint8_t> base64_decode_str(const std::string& s)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+' || c == '-') return 62;
        if (c == '/' || c == '_') return 63;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() * 3 / 4);
    uint32_t accum = 0;
    int bits = 0;
    for (char c : s)
    {
        if (c == '=' || c == '\0') continue;
        int v = val(c);
        if (v < 0) continue;
        accum = (accum << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((accum >> bits) & 0xFF));
        }
    }
    return out;
}

std::string base64_encode_str(const uint8_t* data, size_t len)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3)
    {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
        out.push_back(tbl[(n >> 18) & 0x3F]);
        out.push_back(tbl[(n >> 12) & 0x3F]);
        if (i + 1 < len) out.push_back(tbl[(n >> 6) & 0x3F]); else out.push_back('=');
        if (i + 2 < len) out.push_back(tbl[n & 0x3F]); else out.push_back('=');
    }
    return out;
}

tool_result_t handle_list_transforms(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "decoder_list_transforms entry");
    auto transforms = aida::burp::decoder::available_transforms();
    json arr = json::array();
    for (const auto& t : transforms) arr.push_back(t);
    json data;
    data["transforms"] = std::move(arr);
    data["count"] = transforms.size();
    diag::log_tagged_fmt("mcp_burp", "decoder_list_transforms ok count=%zu", transforms.size());
    return tool_result_t::ok("available transforms count=" + std::to_string(transforms.size()), data);
}

tool_result_t handle_decode(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "decoder_decode entry");

    if (!p.contains("transform") || !p["transform"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "decoder_decode missing_transform");
        return tool_result_t::error("transform parameter required for decode action");
    }
    std::string transform = p["transform"].get<std::string>();

    std::vector<uint8_t> input_bytes;
    if (p.contains("input_b64") && p["input_b64"].is_string() && !p["input_b64"].get<std::string>().empty())
    {
        input_bytes = base64_decode_str(p["input_b64"].get<std::string>());
    }
    else if (p.contains("input") && p["input"].is_string())
    {
        std::string s = p["input"].get<std::string>();
        input_bytes = std::vector<uint8_t>(s.begin(), s.end());
    }
    else
    {
        diag::log_tagged_fmt("mcp_burp", "decoder_decode missing_input");
        return tool_result_t::error("input or input_b64 parameter required");
    }

    diag::log_tagged_fmt("mcp_burp", "decoder_decode transform=%s input_len=%zu", transform.c_str(), input_bytes.size());

    auto r = aida::burp::decoder::apply_transform(transform, input_bytes);
    if (!r.success)
    {
        diag::log_tagged_fmt("mcp_burp", "decoder_decode failed err=%s", r.error.c_str());
        json data;
        data["error"] = r.error;
        data["transform"] = transform;
        data["input_length"] = input_bytes.size();
        return tool_result_t::error("decode failed: " + r.error, data);
    }

    json data;
    data["output"] = r.output;
    data["output_b64"] = base64_encode_str(r.output_bytes.data(), r.output_bytes.size());
    data["transform"] = transform;
    data["input_length"] = input_bytes.size();
    data["output_length"] = r.output_bytes.size();
    if (!r.detected_format.empty()) data["detected_format"] = r.detected_format;

    diag::log_tagged_fmt("mcp_burp", "decoder_decode ok transform=%s out_len=%zu", transform.c_str(), r.output_bytes.size());
    return tool_result_t::ok("decode '" + transform + "' output_length=" + std::to_string(r.output_bytes.size()), data);
}

tool_result_t handle_encode(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "decoder_encode entry");

    if (!p.contains("transform") || !p["transform"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "decoder_encode missing_transform");
        return tool_result_t::error("transform parameter required for encode action");
    }
    std::string transform = p["transform"].get<std::string>();

    std::vector<uint8_t> input_bytes;
    if (p.contains("input_b64") && p["input_b64"].is_string() && !p["input_b64"].get<std::string>().empty())
    {
        input_bytes = base64_decode_str(p["input_b64"].get<std::string>());
    }
    else if (p.contains("input") && p["input"].is_string())
    {
        std::string s = p["input"].get<std::string>();
        input_bytes = std::vector<uint8_t>(s.begin(), s.end());
    }
    else
    {
        diag::log_tagged_fmt("mcp_burp", "decoder_encode missing_input");
        return tool_result_t::error("input or input_b64 parameter required");
    }

    diag::log_tagged_fmt("mcp_burp", "decoder_encode transform=%s input_len=%zu", transform.c_str(), input_bytes.size());

    auto r = aida::burp::decoder::apply_transform(transform, input_bytes);
    if (!r.success)
    {
        diag::log_tagged_fmt("mcp_burp", "decoder_encode failed err=%s", r.error.c_str());
        json data;
        data["error"] = r.error;
        data["transform"] = transform;
        data["input_length"] = input_bytes.size();
        return tool_result_t::error("encode failed: " + r.error, data);
    }

    json data;
    data["output"] = r.output;
    data["output_b64"] = base64_encode_str(r.output_bytes.data(), r.output_bytes.size());
    data["transform"] = transform;
    data["input_length"] = input_bytes.size();
    data["output_length"] = r.output_bytes.size();
    if (!r.detected_format.empty()) data["detected_format"] = r.detected_format;

    diag::log_tagged_fmt("mcp_burp", "decoder_encode ok transform=%s out_len=%zu", transform.c_str(), r.output_bytes.size());
    return tool_result_t::ok("encode '" + transform + "' output_length=" + std::to_string(r.output_bytes.size()), data);
}

tool_result_t handle_transform(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "decoder_transform entry");

    if (!p.contains("pipeline") || !p["pipeline"].is_array() || p["pipeline"].empty())
    {
        diag::log_tagged_fmt("mcp_burp", "decoder_transform missing_pipeline");
        return tool_result_t::error("pipeline parameter (array of transform names) required for transform action");
    }

    std::vector<std::string> pipeline;
    for (const auto& item : p["pipeline"])
    {
        if (!item.is_string())
        {
            diag::log_tagged_fmt("mcp_burp", "decoder_transform invalid_pipeline_item");
            return tool_result_t::error("pipeline items must be strings");
        }
        pipeline.push_back(item.get<std::string>());
    }

    std::vector<uint8_t> input_bytes;
    if (p.contains("input_b64") && p["input_b64"].is_string() && !p["input_b64"].get<std::string>().empty())
    {
        input_bytes = base64_decode_str(p["input_b64"].get<std::string>());
    }
    else if (p.contains("input") && p["input"].is_string())
    {
        std::string s = p["input"].get<std::string>();
        input_bytes = std::vector<uint8_t>(s.begin(), s.end());
    }
    else
    {
        diag::log_tagged_fmt("mcp_burp", "decoder_transform missing_input");
        return tool_result_t::error("input or input_b64 parameter required");
    }

    diag::log_tagged_fmt("mcp_burp", "decoder_transform steps=%zu input_len=%zu", pipeline.size(), input_bytes.size());

    auto r = aida::burp::decoder::apply_pipeline(pipeline, input_bytes);
    if (!r.success)
    {
        diag::log_tagged_fmt("mcp_burp", "decoder_transform failed err=%s", r.error.c_str());
        json data;
        data["error"] = r.error;
        data["pipeline_steps"] = pipeline.size();
        data["input_length"] = input_bytes.size();
        return tool_result_t::error("transform pipeline failed: " + r.error, data);
    }

    json data;
    data["output"] = r.output;
    data["output_b64"] = base64_encode_str(r.output_bytes.data(), r.output_bytes.size());
    data["pipeline_steps"] = static_cast<uint64_t>(pipeline.size());
    data["input_length"] = input_bytes.size();
    data["output_length"] = r.output_bytes.size();
    if (!r.detected_format.empty()) data["detected_format"] = r.detected_format;

    diag::log_tagged_fmt("mcp_burp", "decoder_transform ok steps=%zu out_len=%zu", pipeline.size(), r.output_bytes.size());
    return tool_result_t::ok("pipeline " + std::to_string(pipeline.size()) + " steps output_length=" + std::to_string(r.output_bytes.size()), data);
}

tool_result_t handle_smart_detect(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "decoder_smart_detect entry");

    std::vector<uint8_t> input_bytes;
    if (p.contains("input_b64") && p["input_b64"].is_string() && !p["input_b64"].get<std::string>().empty())
    {
        input_bytes = base64_decode_str(p["input_b64"].get<std::string>());
    }
    else if (p.contains("input") && p["input"].is_string())
    {
        std::string s = p["input"].get<std::string>();
        input_bytes = std::vector<uint8_t>(s.begin(), s.end());
    }
    else
    {
        diag::log_tagged_fmt("mcp_burp", "decoder_smart_detect missing_input");
        return tool_result_t::error("input or input_b64 parameter required");
    }

    diag::log_tagged_fmt("mcp_burp", "decoder_smart_detect input_len=%zu", input_bytes.size());

    auto r = aida::burp::decoder::smart_detect(input_bytes);
    if (!r.success)
    {
        diag::log_tagged_fmt("mcp_burp", "decoder_smart_detect failed err=%s", r.error.c_str());
        json data;
        data["error"] = r.error;
        data["input_length"] = input_bytes.size();
        return tool_result_t::error("smart_detect failed: " + r.error, data);
    }

    json data;
    data["output"] = r.output;
    data["output_b64"] = base64_encode_str(r.output_bytes.data(), r.output_bytes.size());
    data["detected_format"] = r.detected_format;
    data["input_length"] = input_bytes.size();
    data["output_length"] = r.output_bytes.size();

    diag::log_tagged_fmt("mcp_burp", "decoder_smart_detect ok format=%s out_len=%zu", r.detected_format.c_str(), r.output_bytes.size());
    return tool_result_t::ok("smart_detect format=" + r.detected_format + " output_length=" + std::to_string(r.output_bytes.size()), data);
}

}

void register_decoder_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_decoder_manage", "burp",
        "Burp-style Decoder/Encoder for transforms: base64, base64url, url, html, hex, gzip, hashes (md5/sha1/sha256/sha512/crc32), json/xml formatting, jwt_decode, unicode escape/unescape, and smart format detection. Actions: decode, encode, transform, list_transforms, smart_detect.",
        {{"action", "string", "decode|encode|transform|list_transforms|smart_detect", true},
         {"input", "string", "Text input for the transform.", false},
         {"input_b64", "string", "Base64-encoded binary input.", false},
         {"pipeline", "array", "Array of transform names for sequential pipeline (transform action only).", false},
         {"transform", "string", "Transform name for decode/encode actions.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "decode") return handle_decode(p);
            if (action == "encode") return handle_encode(p);
            if (action == "transform") return handle_transform(p);
            if (action == "list_transforms") return handle_list_transforms(p);
            if (action == "smart_detect") return handle_smart_detect(p);
            return compat_unknown_action("burp_decoder_manage", action);
        },
        true
    });
}

}
}
}