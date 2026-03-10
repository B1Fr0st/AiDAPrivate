#pragma once

#define AIDA_VERSION "1.2.8"
#define AIDA_GITHUB_REPO "sigwl/AiDA"

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif

#ifndef CPPHTTPLIB_RECV_BUFSIZ
#define CPPHTTPLIB_RECV_BUFSIZ size_t(65536u)
#endif
#ifndef CPPHTTPLIB_SEND_BUFSIZ
#define CPPHTTPLIB_SEND_BUFSIZ size_t(65536u)
#endif

#ifndef CPPHTTPLIB_TCP_NODELAY
#define CPPHTTPLIB_TCP_NODELAY true
#endif

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <chrono>
#include <regex>
#include <future>
#include <sstream>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <fstream>
#include <mutex>
#include <condition_variable>
#include <algorithm>

#ifdef _MSC_VER
#pragma warning(push, 0)
#pragma warning(disable: 4267)
#endif

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#include <auto.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <entry.hpp>
#include <expr.hpp>
#include <fpro.h>
#include <frame.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <lines.hpp>
#include <llong.hpp>
#include <moves.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <netnode.hpp>
#include <offset.hpp>
#include <problems.hpp>
#include <range.hpp>
#include <search.hpp>
#include <segment.hpp>
#include <segregs.hpp>
#include <strlist.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include <demangle.hpp>
#include <graph.hpp>
#include <dirtree.hpp>
#include <registry.hpp>
#include <dbg.hpp>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#if defined(_MSC_VER) && !defined(__HAS_INT128__)
inline uint128 operator<<(const uint128 &x, int cnt)
{
    if (cnt == 0)
        return x;
    if (cnt >= 128)
        return uint128(0, 0);
    if (cnt >= 64)
        return uint128(0, low(x) << (cnt - 64));
    return uint128(low(x) << cnt, (high(x) << cnt) | (low(x) >> (64 - cnt)));
}
inline uint128 operator>>(const uint128 &x, int cnt)
{
    if (cnt == 0)
        return x;
    if (cnt >= 128)
        return uint128(0, 0);
    if (cnt >= 64)
        return uint128(high(x) >> (cnt - 64), 0);
    return uint128((low(x) >> cnt) | (high(x) << (64 - cnt)), high(x) >> cnt);
}
#endif

#ifdef mark_builtin_widgets
#undef mark_builtin_widgets
#endif
#define mark_builtin_widgets aida_request_refresh
inline void aida_request_refresh(builtin_widgets_mask_t mask, bool dirty = true)
{
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
    request_refresh(uint64(low(mask)), dirty);
#ifdef _MSC_VER
#pragma warning(pop)
#endif
}

inline std::string sanitize_utf8(const std::string& input)
{
    std::string output;
    output.reserve(input.size());

    const auto append_replacement = [&output]() {
        output.push_back(static_cast<char>(0xEF));
        output.push_back(static_cast<char>(0xBF));
        output.push_back(static_cast<char>(0xBD));
    };

    for (size_t i = 0; i < input.size();)
    {
        unsigned char c0 = static_cast<unsigned char>(input[i]);
        if (c0 <= 0x7F)
        {
            output.push_back(static_cast<char>(c0));
            ++i;
            continue;
        }

        auto is_cont = [&](size_t idx) -> bool {
            if (idx >= input.size())
                return false;
            unsigned char cc = static_cast<unsigned char>(input[idx]);
            return (cc & 0xC0) == 0x80;
        };

        if (c0 >= 0xC2 && c0 <= 0xDF)
        {
            if (is_cont(i + 1))
            {
                output.append(input, i, 2);
                i += 2;
            }
            else
            {
                append_replacement();
                ++i;
            }
            continue;
        }

        if (c0 == 0xE0)
        {
            if (i + 2 < input.size())
            {
                unsigned char c1 = static_cast<unsigned char>(input[i + 1]);
                if (c1 >= 0xA0 && c1 <= 0xBF && is_cont(i + 2))
                {
                    output.append(input, i, 3);
                    i += 3;
                    continue;
                }
            }
            append_replacement();
            ++i;
            continue;
        }

        if ((c0 >= 0xE1 && c0 <= 0xEC) || (c0 >= 0xEE && c0 <= 0xEF))
        {
            if (is_cont(i + 1) && is_cont(i + 2))
            {
                output.append(input, i, 3);
                i += 3;
            }
            else
            {
                append_replacement();
                ++i;
            }
            continue;
        }

        if (c0 == 0xED)
        {
            if (i + 2 < input.size())
            {
                unsigned char c1 = static_cast<unsigned char>(input[i + 1]);
                if (c1 >= 0x80 && c1 <= 0x9F && is_cont(i + 2))
                {
                    output.append(input, i, 3);
                    i += 3;
                    continue;
                }
            }
            append_replacement();
            ++i;
            continue;
        }

        if (c0 == 0xF0)
        {
            if (i + 3 < input.size())
            {
                unsigned char c1 = static_cast<unsigned char>(input[i + 1]);
                if (c1 >= 0x90 && c1 <= 0xBF && is_cont(i + 2) && is_cont(i + 3))
                {
                    output.append(input, i, 4);
                    i += 4;
                    continue;
                }
            }
            append_replacement();
            ++i;
            continue;
        }

        if (c0 >= 0xF1 && c0 <= 0xF3)
        {
            if (is_cont(i + 1) && is_cont(i + 2) && is_cont(i + 3))
            {
                output.append(input, i, 4);
                i += 4;
            }
            else
            {
                append_replacement();
                ++i;
            }
            continue;
        }

        if (c0 == 0xF4)
        {
            if (i + 3 < input.size())
            {
                unsigned char c1 = static_cast<unsigned char>(input[i + 1]);
                if (c1 >= 0x80 && c1 <= 0x8F && is_cont(i + 2) && is_cont(i + 3))
                {
                    output.append(input, i, 4);
                    i += 4;
                    continue;
                }
            }
            append_replacement();
            ++i;
            continue;
        }

        append_replacement();
        ++i;
    }

    return output;
}

inline void sanitize_json_utf8_inplace(nlohmann::json& value)
{
    if (value.is_string())
    {
        value = sanitize_utf8(value.get<std::string>());
        return;
    }

    if (value.is_array())
    {
        for (auto& item : value)
            sanitize_json_utf8_inplace(item);
        return;
    }

    if (value.is_object())
    {
        for (auto it = value.begin(); it != value.end(); ++it)
            sanitize_json_utf8_inplace(it.value());
    }
}

inline std::string json_dump_safe(const nlohmann::json& j, int indent = -1)
{
    return j.dump(indent, ' ', false, nlohmann::json::error_handler_t::replace);
}

inline std::string json_dump_fast(const nlohmann::json& j, int indent = -1)
{
    return j.dump(indent, ' ', false, nlohmann::json::error_handler_t::ignore);
}

inline std::string json_str(const nlohmann::json& j, const std::string& key, const std::string& default_val = "")
{
    if (!j.is_object())
        return sanitize_utf8(default_val);
    auto it = j.find(key);
    if (it == j.end() || it->is_null())
        return sanitize_utf8(default_val);
    if (it->is_string())
        return sanitize_utf8(it->get<std::string>());
    return sanitize_utf8(json_dump_safe(*it));
}

#include "obfuscation.hpp"
#include "settings.hpp"
#include "prompts.hpp"
#include "license.hpp"
#include "agent_tools.hpp"
#include "agentic.hpp"
#include "ai_client.hpp"
#include "ida_utils.hpp"
#include "mcp_server.hpp"
#include "ui.hpp"
#include "actions.hpp"
#include "aida.hpp"
