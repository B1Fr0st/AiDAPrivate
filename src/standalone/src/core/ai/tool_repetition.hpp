#pragma once

#include <string>
#include <deque>
#include <functional>
#include <cstdint>

#include <nlohmann/json.hpp>


namespace tool_repetition {


struct call_record_t
{
    std::string name;
    std::size_t args_hash = 0;
};


inline std::size_t hash_args_normalized(const std::string& args_json)
{
    if (args_json.empty()) return std::hash<std::string>{}(std::string{});
    auto parsed = nlohmann::json::parse(args_json, nullptr, false);
    if (parsed.is_discarded())
        return std::hash<std::string>{}(args_json);
    std::string canonical;
    try { canonical = parsed.dump(); }
    catch (...) { canonical = args_json; }
    return std::hash<std::string>{}(canonical);
}


class detector_t
{
public:
    static constexpr int WARNING_THRESHOLD  = 3;
    static constexpr int FORCE_ASK_THRESHOLD = 5;
    static constexpr int MAX_HISTORY = 20;

    void record(const std::string& tool_name, const std::string& args_json)
    {
        call_record_t rec;
        rec.name = tool_name;
        rec.args_hash = hash_args_normalized(args_json);

        _history.push_back(rec);
        if (static_cast<int>(_history.size()) > MAX_HISTORY)
            _history.pop_front();
    }

    int consecutive_identical() const
    {
        if (_history.empty()) return 0;

        const auto& last = _history.back();
        int count = 0;
        for (auto it = _history.rbegin(); it != _history.rend(); ++it) {
            if (it->name == last.name && it->args_hash == last.args_hash)
                ++count;
            else
                break;
        }
        return count;
    }

    bool should_warn() const { return consecutive_identical() >= WARNING_THRESHOLD; }
    bool should_force_ask() const { return consecutive_identical() >= FORCE_ASK_THRESHOLD; }

    std::string warning_message() const
    {
        int n = consecutive_identical();
        if (n >= FORCE_ASK_THRESHOLD)
            return "You have called the same tool with identical arguments " + std::to_string(n) +
                   " times. You must use ask_followup_question to clarify your approach before continuing.";
        if (n >= WARNING_THRESHOLD)
            return "You appear to be repeating the same action (" + _history.back().name +
                   ") with identical arguments. Consider a different approach.";
        return "";
    }

    void reset() { _history.clear(); }

private:
    std::deque<call_record_t> _history;
};


}
