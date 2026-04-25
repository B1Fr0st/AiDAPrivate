#pragma once


#include <windows.h>
#include "work_queue.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>

#include <httplib.h>
#include <nlohmann/json.hpp>

namespace arc_page_manager {

    using json = nlohmann::json;

    struct page_cache_entry_t {
        std::vector<uint8_t> data;
        std::string          iv;
        std::string          auth_tag;
        std::string          hmac;
        int64_t              rotation_epoch;
        bool                 valid;
    };

    struct page_state_t {
        std::vector<page_cache_entry_t> pages;
        int64_t             current_epoch;
        std::string         rotation_key;
        int                 total_pages;
        int                 page_size;
        std::mutex          mtx;
        std::atomic<bool>   initialized{false};
        std::atomic<bool>   stop{false};
        std::thread         rotation_thread;


        std::string         license_key;
        std::string         session_token;
        std::string         hwid;
        std::string         server_host;
    };

    inline page_state_t& state()
    {
        static page_state_t s;
        return s;
    }

    inline bool check_rotation(std::shared_ptr<httplib::Client> client)
    {
        auto& s = state();
        std::lock_guard<std::mutex> lk(s.mtx);

        json body;
        body["license_key"]   = s.license_key;
        body["session_token"] = s.session_token;
        body["hwid"]          = s.hwid;
        body["client_epoch"]  = s.current_epoch;

        auto res = client->Post("/api/download/pages/rotate",
            body.dump(), "application/json");
        if (!res || res->status != 200) return false;

        auto resp = json::parse(res->body, nullptr, false);
        if (resp.is_discarded() || resp.value("status", "") != "ok") return false;

        int64_t server_epoch = resp.value("rotation_epoch", (int64_t)0);
        bool stale = resp.value("stale", false);

        if (stale || server_epoch > s.current_epoch) {

            for (auto& p : s.pages)
                p.valid = false;

            s.current_epoch = server_epoch;
            s.rotation_key  = resp.value("rotation_key", "");
            s.total_pages   = resp.value("total_pages", s.total_pages);
            return true;
        }

        return false;
    }

    inline bool download_page(std::shared_ptr<httplib::Client> client, int index)
    {
        auto& s = state();

        json body;
        body["license_key"]     = s.license_key;
        body["session_token"]   = s.session_token;
        body["hwid"]            = s.hwid;
        body["rotation_epoch"]  = s.current_epoch;

        std::string path = "/api/download/pages/rotated/" + std::to_string(index);
        auto res = client->Post(path.c_str(), body.dump(), "application/json");
        if (!res || res->status != 200) return false;

        auto resp = json::parse(res->body, nullptr, false);
        if (resp.is_discarded() || resp.value("status", "") != "ok") return false;

        std::lock_guard<std::mutex> lk(s.mtx);

        if (index >= static_cast<int>(s.pages.size()))
            s.pages.resize(index + 1);

        auto& entry = s.pages[index];


        std::string b64 = resp.value("encrypted_page", "");
        DWORD decoded_len = 0;
        CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
            CRYPT_STRING_BASE64, nullptr, &decoded_len, nullptr, nullptr);
        entry.data.resize(decoded_len);
        CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
            CRYPT_STRING_BASE64, entry.data.data(), &decoded_len, nullptr, nullptr);

        entry.iv             = resp.value("iv", "");
        entry.auth_tag       = resp.value("auth_tag", "");
        entry.hmac           = resp.value("hmac", "");
        entry.rotation_epoch = s.current_epoch;
        entry.valid          = true;

        return true;
    }

    inline void rotation_worker()
    {
        auto& s = state();

        auto client = std::make_shared<httplib::Client>(s.server_host.c_str());
        client->set_connection_timeout(10);
        client->set_read_timeout(30);
        client->set_write_timeout(10);
        client->set_keep_alive(true);
        client->set_tcp_nodelay(true);
        client->set_decompress(true);
        client->set_follow_location(true);
        client->enable_server_certificate_verification(true);

        while (!s.stop.load(std::memory_order_acquire))
        {

            for (int i = 0; i < 300 && !s.stop.load(std::memory_order_acquire); ++i)
                std::this_thread::sleep_for(std::chrono::seconds(1));

            if (s.stop.load(std::memory_order_acquire)) break;

            bool needs_refresh = check_rotation(client);
            if (needs_refresh)
            {
                int total = 0;
                {
                    std::lock_guard<std::mutex> lk(s.mtx);
                    total = s.total_pages;
                }

                for (int i = 0; i < total && !s.stop.load(); ++i)
                {
                    download_page(client, i);

                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
            }
        }
    }

    inline bool initialize(
        const std::string& license_key,
        const std::string& session_token,
        const std::string& hwid,
        const std::string& server_host)
    {
        auto& s = state();
        if (s.initialized.load()) return true;

        s.license_key   = license_key;
        s.session_token = session_token;
        s.hwid          = hwid;
        s.server_host   = server_host;
        s.current_epoch = 0;
        s.total_pages   = 0;
        s.page_size     = 4096;


        auto client = std::make_shared<httplib::Client>(server_host.c_str());
        client->set_connection_timeout(10);
        client->set_read_timeout(30);
        client->set_write_timeout(10);
        client->set_keep_alive(true);
        client->set_tcp_nodelay(true);
        client->set_decompress(true);
        client->set_follow_location(true);
        client->enable_server_certificate_verification(true);

        check_rotation(client);

        s.initialized.store(true);


        try {
            work_queue::post(rotation_worker);
        } catch (...) {}

        return true;
    }

    inline void shutdown()
    {
        auto& s = state();
        s.stop.store(true, std::memory_order_release);
        if (s.rotation_thread.joinable())
            s.rotation_thread.join();
        s.initialized.store(false);
    }

    inline bool is_page_valid(int index)
    {
        auto& s = state();
        std::lock_guard<std::mutex> lk(s.mtx);
        if (index < 0 || index >= static_cast<int>(s.pages.size()))
            return false;
        return s.pages[index].valid &&
               s.pages[index].rotation_epoch == s.current_epoch;
    }

    inline int64_t current_epoch()
    {
        return state().current_epoch;
    }

}
