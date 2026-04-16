#pragma once


#include "util.hpp"
#include <map>
#include <stdexcept>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

class HTTPException : public std::runtime_error {
public:
    HTTPException(const std::string& message) : std::runtime_error(message) {}
};

class HTTPResponse {
public:
    int status_code;
    std::string body;
    std::map<std::string, std::string> headers;

    HTTPResponse(int code, const std::string& body, const std::map<std::string, std::string>& hdrs)
        : status_code(code), body(body), headers(hdrs) {}

    json json_parse() const {
        return json::parse(body, nullptr, false);
    }
};

class HTTP {
public:
    static HTTPResponse get(const std::string& url, const std::map<std::string, std::string>& headers = {});
    static HTTPResponse post(const std::string& url, const std::string& data, const std::map<std::string, std::string>& headers = {});
    static HTTPResponse put(const std::string& url, const std::string& data, const std::map<std::string, std::string>& headers = {});

private:
    static HTTPResponse request(const std::string& url, const std::string& method, const std::string& data, const std::map<std::string, std::string>& headers);
    static std::map<std::string, std::string> parse_headers(const std::wstring& rawHeaders);
};
