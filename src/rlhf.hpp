

#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <fstream>
#include <algorithm>

#include "analysis_db.hpp"

namespace rlhf
{


struct feedback_t
{
    int         id = 0;
    std::string model_name;
    std::string prompt;
    std::string system_prompt;
    std::string response;
    bool        positive = false;
    std::string comment;
    uint64_t    timestamp_ms = 0;
    nlohmann::json metadata;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(feedback_t,
        id, model_name, prompt, system_prompt, response, positive,
        comment, timestamp_ms, metadata)
};


struct stats_t
{
    int total = 0;
    int upvotes = 0;
    int downvotes = 0;
    std::map<std::string, int> upvotes_by_model;
    std::map<std::string, int> downvotes_by_model;

    double approval_rate() const { return total > 0 ? static_cast<double>(upvotes) / total : 0; }

    double model_approval(const std::string& model) const
    {
        int up = 0, down = 0;
        auto uit = upvotes_by_model.find(model);
        if (uit != upvotes_by_model.end()) up = uit->second;
        auto dit = downvotes_by_model.find(model);
        if (dit != downvotes_by_model.end()) down = dit->second;
        int t = up + down;
        return t > 0 ? static_cast<double>(up) / t : 0;
    }
};


class FeedbackStore
{
public:
    static FeedbackStore& instance()
    {
        static FeedbackStore s;
        return s;
    }


    int record(const std::string& model, const std::string& prompt,
               const std::string& response, bool positive,
               const std::string& system_prompt = {},
               const std::string& comment = {},
               const nlohmann::json& metadata = {})
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        feedback_t fb;
        fb.id = m_next_id++;
        fb.model_name = model;
        fb.prompt = prompt;
        fb.system_prompt = system_prompt;
        fb.response = response;
        fb.positive = positive;
        fb.comment = comment;
        fb.timestamp_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count());
        fb.metadata = metadata;
        m_entries.push_back(fb);
        save_locked();
        return fb.id;
    }


    std::vector<feedback_t> all() const
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_entries;
    }


    std::vector<feedback_t> by_model(const std::string& model) const
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        std::vector<feedback_t> result;
        for (auto& e : m_entries)
            if (e.model_name == model) result.push_back(e);
        return result;
    }


    std::vector<feedback_t> recent(int count) const
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        int start = static_cast<int>(m_entries.size()) - count;
        if (start < 0) start = 0;
        return std::vector<feedback_t>(m_entries.begin() + start, m_entries.end());
    }


    stats_t get_stats() const
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        stats_t s;
        for (auto& e : m_entries)
        {
            ++s.total;
            if (e.positive)
            {
                ++s.upvotes;
                ++s.upvotes_by_model[e.model_name];
            }
            else
            {
                ++s.downvotes;
                ++s.downvotes_by_model[e.model_name];
            }
        }
        return s;
    }


    bool save()
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        return save_locked();
    }

    bool load()
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        return load_locked();
    }


    void clear()
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_entries.clear();
        m_next_id = 1;
    }

private:
    FeedbackStore()
    {
        load_locked();
    }
    FeedbackStore(const FeedbackStore&) = delete;
    FeedbackStore& operator=(const FeedbackStore&) = delete;

    std::string get_path() const
    {
        qstring dir = get_user_idadir();
        dir.append("/aida_db");
#ifdef __NT__
        CreateDirectoryA(dir.c_str(), nullptr);
#else
        mkdir(dir.c_str(), 0755);
#endif
        std::string result(dir.c_str());
        result += "/rlhf_feedback.json";
        return result;
    }

    bool save_locked()
    {
        std::string path = get_path();
        nlohmann::json j;
        j["version"] = 1;
        j["next_id"] = m_next_id;
        j["entries"] = m_entries;
        std::ofstream ofs(path, std::ios::binary);
        if (!ofs.is_open()) return false;
        ofs << j.dump(2);
        return true;
    }

    bool load_locked()
    {
        std::string path = get_path();
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open()) return false;
        try
        {
            nlohmann::json j = nlohmann::json::parse(ifs);
            m_next_id = j.value("next_id", 1);
            m_entries = j["entries"].get<std::vector<feedback_t>>();
            return true;
        }
        catch (const std::exception&) { return false; }
    }

    mutable std::mutex       m_mtx;
    std::vector<feedback_t>  m_entries;
    int                      m_next_id = 1;
};


inline int record_feedback(const std::string& model, const std::string& prompt,
                           const std::string& response, bool positive,
                           const std::string& system_prompt = {},
                           const std::string& comment = {},
                           const nlohmann::json& metadata = {})
{
    return FeedbackStore::instance().record(model, prompt, response, positive,
                                            system_prompt, comment, metadata);
}

inline stats_t get_stats()
{
    return FeedbackStore::instance().get_stats();
}

inline std::vector<feedback_t> recent_feedback(int count = 10)
{
    return FeedbackStore::instance().recent(count);
}

}
