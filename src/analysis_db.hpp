#pragma once


#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <fstream>
#include <cstdint>
#include <chrono>

#include <nlohmann/json.hpp>
#include <ida.hpp>
#include <diskio.hpp>
#include <nalt.hpp>

namespace aida_db
{


struct rlhf_entry_t
{
    std::string id;
    std::string model_name;
    std::string prompt;
    std::string system_prompt;
    std::string response;
    int         feedback = 0;
    uint64_t    timestamp_ms = 0;
    nlohmann::json metadata;
};

inline void to_json(nlohmann::json& j, const rlhf_entry_t& e)
{
    j = {
        {"id", e.id}, {"model_name", e.model_name},
        {"prompt", e.prompt}, {"system_prompt", e.system_prompt},
        {"response", e.response}, {"feedback", e.feedback},
        {"timestamp_ms", e.timestamp_ms}, {"metadata", e.metadata}
    };
}

inline void from_json(const nlohmann::json& j, rlhf_entry_t& e)
{
    j.at("id").get_to(e.id);
    j.at("model_name").get_to(e.model_name);
    e.prompt = j.value("prompt", "");
    e.system_prompt = j.value("system_prompt", "");
    j.at("response").get_to(e.response);
    j.at("feedback").get_to(e.feedback);
    j.at("timestamp_ms").get_to(e.timestamp_ms);
    e.metadata = j.value("metadata", nlohmann::json::object());
}


struct chat_entry_t
{
    std::string role;
    std::string content;
    uint64_t    timestamp_ms = 0;
    nlohmann::json metadata;
};

inline void to_json(nlohmann::json& j, const chat_entry_t& e)
{
    j = {{"role", e.role}, {"content", e.content},
         {"timestamp_ms", e.timestamp_ms}, {"metadata", e.metadata}};
}

inline void from_json(const nlohmann::json& j, chat_entry_t& e)
{
    j.at("role").get_to(e.role);
    j.at("content").get_to(e.content);
    e.timestamp_ms = j.value("timestamp_ms", uint64_t(0));
    e.metadata = j.value("metadata", nlohmann::json::object());
}


struct analysis_entry_t
{
    ea_t        address = BADADDR;
    std::string function_name;
    std::string analysis_type;
    std::string result;
    std::string model_name;
    uint64_t    timestamp_ms = 0;
};

inline void to_json(nlohmann::json& j, const analysis_entry_t& e)
{
    j = {{"address", e.address}, {"function_name", e.function_name},
         {"analysis_type", e.analysis_type}, {"result", e.result},
         {"model_name", e.model_name}, {"timestamp_ms", e.timestamp_ms}};
}

inline void from_json(const nlohmann::json& j, analysis_entry_t& e)
{
    e.address = j.value("address", ea_t(BADADDR));
    j.at("function_name").get_to(e.function_name);
    j.at("analysis_type").get_to(e.analysis_type);
    j.at("result").get_to(e.result);
    e.model_name = j.value("model_name", std::string());
    e.timestamp_ms = j.value("timestamp_ms", uint64_t(0));
}


class AnalysisDB
{
public:
    static AnalysisDB& instance()
    {
        static AnalysisDB s_inst;
        return s_inst;
    }


    std::string get_binary_hash() const
    {

        uchar md5[16];
        if (!retrieve_input_file_md5(md5))
            return {};
        char buf[33];
        for (int i = 0; i < 16; ++i)
            ::qsnprintf(buf + i * 2, static_cast<size_t>(3), "%02x", md5[i]);
        return std::string(buf, 32);
    }


    void add_rlhf(const rlhf_entry_t& entry)
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_rlhf.push_back(entry);
        m_dirty = true;
    }

    std::vector<rlhf_entry_t> get_rlhf_entries() const
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_rlhf;
    }

    struct rlhf_stats_t
    {
        int total = 0;
        int upvotes = 0;
        int downvotes = 0;
        std::unordered_map<std::string, int> by_model;
    };

    rlhf_stats_t get_rlhf_stats() const
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        rlhf_stats_t stats;
        stats.total = static_cast<int>(m_rlhf.size());
        for (auto& e : m_rlhf)
        {
            if (e.feedback > 0) ++stats.upvotes;
            else if (e.feedback < 0) ++stats.downvotes;
            ++stats.by_model[e.model_name];
        }
        return stats;
    }


    void add_chat(const std::string& binary_hash, const chat_entry_t& entry)
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_chat_history[binary_hash].push_back(entry);
        m_dirty = true;
    }

    std::vector<chat_entry_t> get_chat_history(const std::string& binary_hash) const
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_chat_history.find(binary_hash);
        return it != m_chat_history.end() ? it->second : std::vector<chat_entry_t>{};
    }

    void clear_chat_history(const std::string& binary_hash)
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_chat_history.erase(binary_hash);
        m_dirty = true;
    }


    void add_analysis(const std::string& binary_hash, const analysis_entry_t& entry)
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto& vec = m_analysis[binary_hash];

        for (auto& existing : vec)
        {
            if (existing.address == entry.address && existing.analysis_type == entry.analysis_type)
            {
                existing = entry;
                m_dirty = true;
                return;
            }
        }
        vec.push_back(entry);
        m_dirty = true;
    }

    std::vector<analysis_entry_t> get_analysis(const std::string& binary_hash, ea_t addr = BADADDR) const
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_analysis.find(binary_hash);
        if (it == m_analysis.end()) return {};
        if (addr == BADADDR) return it->second;
        std::vector<analysis_entry_t> out;
        for (auto& e : it->second)
            if (e.address == addr) out.push_back(e);
        return out;
    }


    bool save()
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (!m_dirty) return true;
        return save_locked();
    }

    bool load()
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        return load_locked();
    }

    bool is_dirty() const
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_dirty;
    }

private:
    AnalysisDB() = default;
    AnalysisDB(const AnalysisDB&) = delete;
    AnalysisDB& operator=(const AnalysisDB&) = delete;

    mutable std::mutex m_mtx;
    bool m_dirty = false;

    std::vector<rlhf_entry_t> m_rlhf;
    std::unordered_map<std::string, std::vector<chat_entry_t>> m_chat_history;
    std::unordered_map<std::string, std::vector<analysis_entry_t>> m_analysis;

    std::string get_db_path() const
    {
        qstring dir = get_user_idadir();
        dir.append("/aida_db");


#ifdef __NT__
        CreateDirectoryA(dir.c_str(), nullptr);
#else
        mkdir(dir.c_str(), 0755);
#endif
        std::string result(dir.c_str());
        result += "/analysis_db.json";
        return result;
    }

    bool save_locked()
    {
        nlohmann::json j;
        j["version"] = 1;
        j["rlhf"] = m_rlhf;
        j["chat_history"] = m_chat_history;
        j["analysis"] = m_analysis;

        std::string path = get_db_path();
        std::ofstream ofs(path, std::ios::binary);
        if (!ofs.is_open()) return false;
        ofs << j.dump(2);
        ofs.close();
        m_dirty = false;
        return true;
    }

    bool load_locked()
    {
        std::string path = get_db_path();
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open()) return false;

        try
        {
            nlohmann::json j = nlohmann::json::parse(ifs);
            if (j.contains("rlhf"))
                m_rlhf = j["rlhf"].get<std::vector<rlhf_entry_t>>();
            if (j.contains("chat_history"))
                m_chat_history = j["chat_history"].get<std::unordered_map<std::string, std::vector<chat_entry_t>>>();
            if (j.contains("analysis"))
                m_analysis = j["analysis"].get<std::unordered_map<std::string, std::vector<analysis_entry_t>>>();
            m_dirty = false;
            return true;
        }
        catch (const std::exception&)
        {
            return false;
        }
    }

    static uint64_t now_ms()
    {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
    }
};

}
