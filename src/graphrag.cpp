

#include "aida_pro.hpp"
#include "graphrag.hpp"

#include <sstream>
#include <regex>
#include <random>
#include <numeric>
#include <nalt.hpp>
#include <idp.hpp>
#include <entry.hpp>
#include <strlist.hpp>
#include <lines.hpp>

namespace graphrag
{


static uint64_t now_ms()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count());
}

static bool icontains(const std::string& haystack, const std::string& needle)
{
    if (needle.empty()) return true;
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); }
    );
    return it != haystack.end();
}

static bool has_any(const std::vector<std::string>& vec, const std::set<std::string>& targets)
{
    for (auto& s : vec)
        if (targets.count(s)) return true;
    return false;
}


static const std::vector<std::string> NETWORK_API_PATTERNS = {
    "socket", "connect", "bind", "listen", "accept", "send", "recv",
    "sendto", "recvfrom", "sendmsg", "recvmsg",
    "WSASocket", "WSAConnect", "WSASend", "WSARecv", "WSASendTo", "WSARecvFrom",
    "WSAAccept", "WSAStartup", "WSACleanup",
    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
    "WinHttpReceiveResponse", "WinHttpReadData", "WinHttpWriteData",
    "InternetOpen", "InternetConnect", "InternetReadFile", "InternetWriteFile",
    "HttpOpenRequest", "HttpSendRequest", "HttpQueryInfo",
    "getaddrinfo", "gethostbyname", "gethostbyaddr", "getnameinfo", "gethostname",
    "SSL_read", "SSL_write", "SSL_connect", "SSL_accept",
    "curl_easy_perform", "curl_easy_send", "curl_easy_recv",
    "select", "poll", "epoll", "shutdown", "closesocket",
};

static const std::vector<std::string> FILE_IO_API_PATTERNS = {
    "fopen", "fclose", "fread", "fwrite", "fgets", "fputs", "fgetc", "fputc",
    "fprintf", "fscanf", "fseek", "ftell", "fflush", "freopen",
    "open", "close", "read", "write", "lseek", "stat", "fstat",
    "CreateFile", "ReadFile", "WriteFile", "CloseHandle", "DeleteFile",
    "CopyFile", "MoveFile", "FindFirstFile", "FindNextFile",
    "CreateDirectory", "RemoveDirectory", "GetTempPath", "GetTempFileName",
    "MapViewOfFile", "UnmapViewOfFile", "CreateFileMapping",
    "NtReadFile", "NtWriteFile", "NtCreateFile", "ZwReadFile", "ZwWriteFile",
};

static const std::vector<std::string> CRYPTO_API_PATTERNS = {
    "CryptAcquireContext", "CryptCreateHash", "CryptHashData", "CryptDeriveKey",
    "CryptEncrypt", "CryptDecrypt", "BCryptOpenAlgorithmProvider",
    "BCryptEncrypt", "BCryptDecrypt", "BCryptCreateHash", "BCryptHashData",
    "MD5Init", "MD5Update", "MD5Final", "SHA1Init", "SHA1Update",
    "EVP_EncryptInit", "EVP_DecryptInit", "EVP_DigestInit",
    "AES_encrypt", "AES_decrypt", "RSA_public_encrypt", "RSA_private_decrypt",
    "base64_encode", "base64_decode",
};

static const std::vector<std::string> PROCESS_API_PATTERNS = {
    "CreateProcess", "CreateProcessA", "CreateProcessW",
    "CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx",
    "TerminateProcess", "ExitProcess", "ExitThread",
    "OpenProcess", "OpenThread", "NtOpenProcess",
    "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualProtect",
    "WriteProcessMemory", "ReadProcessMemory", "NtWriteVirtualMemory",
    "ShellExecute", "ShellExecuteW", "WinExec", "system",
    "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "NtMapViewOfSection", "LdrLoadDll",
};


static const std::map<std::string, std::string> DANGEROUS_FUNCTIONS = {
    {"strcpy", "BUFFER_OVERFLOW_RISK"}, {"strcat", "BUFFER_OVERFLOW_RISK"},
    {"sprintf", "FORMAT_STRING_RISK"}, {"vsprintf", "FORMAT_STRING_RISK"},
    {"gets", "BUFFER_OVERFLOW_RISK"}, {"scanf", "BUFFER_OVERFLOW_RISK"},
    {"wcscpy", "BUFFER_OVERFLOW_RISK"}, {"wcscat", "BUFFER_OVERFLOW_RISK"},
    {"lstrcpy", "BUFFER_OVERFLOW_RISK"}, {"lstrcpyA", "BUFFER_OVERFLOW_RISK"},
    {"lstrcpyW", "BUFFER_OVERFLOW_RISK"}, {"lstrcat", "BUFFER_OVERFLOW_RISK"},
    {"printf", "FORMAT_STRING_RISK"}, {"fprintf", "FORMAT_STRING_RISK"},
    {"wprintf", "FORMAT_STRING_RISK"}, {"fwprintf", "FORMAT_STRING_RISK"},
    {"system", "COMMAND_INJECTION_RISK"}, {"popen", "COMMAND_INJECTION_RISK"},
    {"_popen", "COMMAND_INJECTION_RISK"}, {"WinExec", "COMMAND_INJECTION_RISK"},
    {"CreateProcess", "COMMAND_INJECTION_RISK"}, {"CreateProcessA", "COMMAND_INJECTION_RISK"},
    {"CreateProcessW", "COMMAND_INJECTION_RISK"},
    {"ShellExecute", "COMMAND_INJECTION_RISK"}, {"ShellExecuteW", "COMMAND_INJECTION_RISK"},
    {"mysql_query", "SQL_INJECTION_RISK"}, {"sqlite3_exec", "SQL_INJECTION_RISK"},
    {"PQexec", "SQL_INJECTION_RISK"},
    {"memcpy", "BUFFER_OVERFLOW_RISK"}, {"memmove", "BUFFER_OVERFLOW_RISK"},
    {"RtlCopyMemory", "BUFFER_OVERFLOW_RISK"},
};

SecurityFeatureExtractor::features_t
SecurityFeatureExtractor::extract_from_code(const std::string& func_name, const std::string& code) const
{
    features_t f;
    if (code.empty() && func_name.empty()) return f;

    std::string combined = func_name + "\n" + code;


    for (auto& api : NETWORK_API_PATTERNS)
        if (combined.find(api) != std::string::npos)
            f.network_apis.insert(api);

    for (auto& api : FILE_IO_API_PATTERNS)
        if (combined.find(api) != std::string::npos)
            f.file_io_apis.insert(api);

    for (auto& api : CRYPTO_API_PATTERNS)
        if (combined.find(api) != std::string::npos)
            f.crypto_apis.insert(api);

    for (auto& api : PROCESS_API_PATTERNS)
        if (combined.find(api) != std::string::npos)
            f.process_apis.insert(api);


    for (auto& [name, vuln] : DANGEROUS_FUNCTIONS)
        if (combined.find(name) != std::string::npos)
            f.dangerous_functions[name] = vuln;


    static const std::regex ip_re(R"(\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)");
    for (std::sregex_iterator it(combined.begin(), combined.end(), ip_re); it != std::sregex_iterator{}; ++it)
    {
        std::string ip = (*it)[1].str();
        if (ip != "0.0.0.0" && ip != "127.0.0.1" && ip != "255.255.255.255")
            f.ip_addresses.insert(ip);
    }


    static const std::regex url_re(R"(https?://[^\s\"'<>]+)");
    for (std::sregex_iterator it(combined.begin(), combined.end(), url_re); it != std::sregex_iterator{}; ++it)
        f.urls.insert((*it)[0].str());


    static const std::regex win_path_re(R"([A-Za-z]:\\[^\s\"']+)");
    for (std::sregex_iterator it(combined.begin(), combined.end(), win_path_re); it != std::sregex_iterator{}; ++it)
        f.file_paths.insert((*it)[0].str());


    static const std::regex unix_path_re(R"(/(?:etc|var|tmp|usr|home|root|opt)/[^\s\"']+)");
    for (std::sregex_iterator it(combined.begin(), combined.end(), unix_path_re); it != std::sregex_iterator{}; ++it)
        f.file_paths.insert((*it)[0].str());


    static const std::regex reg_re(R"(HK(?:EY_[A-Z_]+|LM|CU|CR|CC|U)\\[^\s\"']+)");
    for (std::sregex_iterator it(combined.begin(), combined.end(), reg_re); it != std::sregex_iterator{}; ++it)
        f.registry_keys.insert((*it)[0].str());

    return f;
}

std::vector<std::string> SecurityFeatureExtractor::features_t::generate_security_flags() const
{
    std::vector<std::string> flags;

    if (!network_apis.empty())
    {
        flags.push_back("NETWORK_CAPABLE");
        bool has_listen = false, has_connect = false, has_send = false, has_recv = false;
        for (auto& a : network_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("listen") != std::string::npos || low.find("accept") != std::string::npos)
                has_listen = true;
            if (low.find("connect") != std::string::npos)
                has_connect = true;
            if (low.find("send") != std::string::npos || low.find("write") != std::string::npos)
                has_send = true;
            if (low.find("recv") != std::string::npos || low.find("read") != std::string::npos)
                has_recv = true;
        }
        if (has_listen) flags.push_back("ACCEPTS_CONNECTIONS");
        if (has_connect) flags.push_back("INITIATES_CONNECTIONS");
        if (has_send) flags.push_back("SENDS_DATA");
        if (has_recv) flags.push_back("RECEIVES_DATA");

        for (auto& a : network_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("getaddrinfo") != std::string::npos ||
                low.find("gethostbyname") != std::string::npos ||
                low.find("gethostname") != std::string::npos)
            {
                flags.push_back("PERFORMS_DNS_LOOKUP");
                break;
            }
        }
    }

    if (!file_io_apis.empty())
    {
        bool has_read = false, has_write = false;
        for (auto& a : file_io_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("read") != std::string::npos || low.find("fread") != std::string::npos ||
                low.find("fgets") != std::string::npos || low.find("mapview") != std::string::npos)
                has_read = true;
            if (low.find("write") != std::string::npos || low.find("fwrite") != std::string::npos ||
                low.find("fputs") != std::string::npos || low.find("copy") != std::string::npos)
                has_write = true;
        }
        if (has_read) flags.push_back("READS_FILES");
        if (has_write) flags.push_back("WRITES_FILES");
    }

    if (!crypto_apis.empty())
        flags.push_back("USES_CRYPTO");

    if (!process_apis.empty())
    {
        flags.push_back("MANIPULATES_PROCESSES");
        for (auto& a : process_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("writeprocessmemory") != std::string::npos ||
                low.find("createremotethread") != std::string::npos ||
                low.find("ntmapviewofsection") != std::string::npos)
            {
                flags.push_back("PROCESS_INJECTION_CAPABLE");
                break;
            }
        }
    }

    for (auto& [name, vuln_type] : dangerous_functions)
    {
        if (std::find(flags.begin(), flags.end(), vuln_type) == flags.end())
            flags.push_back(vuln_type);
    }
    if (!dangerous_functions.empty())
        flags.push_back("CALLS_DANGEROUS_FUNCTIONS");

    if (!ip_addresses.empty()) flags.push_back("HAS_IP_ADDRESSES");
    if (!urls.empty()) flags.push_back("HAS_URLS");
    if (!domains.empty()) flags.push_back("HAS_DOMAINS");
    if (!registry_keys.empty()) flags.push_back("ACCESSES_REGISTRY");

    for (auto& p : file_paths)
    {
        std::string low = p;
        std::transform(low.begin(), low.end(), low.begin(), ::tolower);
        if (low.find("\\system32") != std::string::npos ||
            low.find("\\windows") != std::string::npos ||
            low.find("/etc/") != std::string::npos ||
            low.find("/root/") != std::string::npos)
        {
            flags.push_back("ACCESSES_SYSTEM_PATHS");
            break;
        }
    }

    return flags;
}

std::string SecurityFeatureExtractor::features_t::get_activity_profile() const
{
    std::vector<std::string> profiles;

    if (!network_apis.empty())
    {
        bool has_server = false, has_client = false;
        for (auto& a : network_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("listen") != std::string::npos || low.find("accept") != std::string::npos)
                has_server = true;
            if (low.find("connect") != std::string::npos || low.find("http") != std::string::npos ||
                low.find("internet") != std::string::npos || low.find("winhttp") != std::string::npos)
                has_client = true;
        }
        if (has_server) profiles.push_back("NETWORK_SERVER");
        if (has_client) profiles.push_back("NETWORK_CLIENT");
        if (!has_server && !has_client) profiles.push_back("NETWORK_IO");
    }

    if (!file_io_apis.empty())
    {
        bool has_read = false, has_write = false;
        for (auto& a : file_io_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("read") != std::string::npos) has_read = true;
            if (low.find("write") != std::string::npos) has_write = true;
        }
        if (has_read && has_write) profiles.push_back("FILE_RW");
        else if (has_write) profiles.push_back("FILE_WRITER");
        else if (has_read) profiles.push_back("FILE_READER");
    }

    if (!crypto_apis.empty())
    {
        bool enc = false, dec = false, hash = false;
        for (auto& a : crypto_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("encrypt") != std::string::npos) enc = true;
            if (low.find("decrypt") != std::string::npos) dec = true;
            if (low.find("hash") != std::string::npos || low.find("md5") != std::string::npos ||
                low.find("sha") != std::string::npos || low.find("digest") != std::string::npos)
                hash = true;
        }
        if (enc && dec) profiles.push_back("CRYPTO_CIPHER");
        else if (enc) profiles.push_back("CRYPTO_ENCRYPT");
        else if (dec) profiles.push_back("CRYPTO_DECRYPT");
        else if (hash) profiles.push_back("CRYPTO_HASH");
        else profiles.push_back("CRYPTO_USER");
    }

    if (!process_apis.empty())
    {
        bool inject = false;
        for (auto& a : process_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("writeprocessmemory") != std::string::npos ||
                low.find("createremotethread") != std::string::npos)
                inject = true;
        }
        profiles.push_back(inject ? "PROCESS_INJECTOR" : "PROCESS_SPAWNER");
    }

    std::string result;
    for (size_t i = 0; i < profiles.size(); ++i)
    {
        if (i > 0) result += ",";
        result += profiles[i];
    }
    return result;
}

std::string SecurityFeatureExtractor::features_t::get_risk_level() const
{
    int score = 0;
    if (!dangerous_functions.empty()) score += 3;
    if (!network_apis.empty()) score += 2;
    if (!process_apis.empty()) score += 2;
    if (!crypto_apis.empty()) score += 1;
    if (!ip_addresses.empty()) score += 1;
    if (!urls.empty()) score += 1;


    for (auto& a : process_apis)
    {
        std::string low = a;
        std::transform(low.begin(), low.end(), low.begin(), ::tolower);
        if (low.find("writeprocessmemory") != std::string::npos ||
            low.find("createremotethread") != std::string::npos)
        {
            score += 3;
            break;
        }
    }

    if (score >= 7) return "CRITICAL";
    if (score >= 5) return "HIGH";
    if (score >= 3) return "MEDIUM";
    if (score >= 1) return "LOW";
    return "NONE";
}

bool SecurityFeatureExtractor::features_t::is_empty() const
{
    return network_apis.empty() && file_io_apis.empty() && crypto_apis.empty() &&
           process_apis.empty() && dangerous_functions.empty() && ip_addresses.empty() &&
           urls.empty() && file_paths.empty() && domains.empty() && registry_keys.empty();
}


graph_node_t* GraphStore::upsert_node(graph_node_t node)
{
    std::lock_guard<std::mutex> lk(m_mtx);


    addr_key_t key{node.binary_hash, node.node_type, node.address};
    auto it = m_addr_index.find(key);

    uint64_t ts = now_ms();

    if (it != m_addr_index.end())
    {
        auto& existing = m_nodes[it->second];

        existing.name = node.name;
        if (!node.raw_code.empty()) existing.raw_code = node.raw_code;
        existing.security_flags = node.security_flags;
        existing.network_apis = node.network_apis;
        existing.file_io_apis = node.file_io_apis;
        existing.crypto_apis = node.crypto_apis;
        existing.process_apis = node.process_apis;
        existing.ip_addresses = node.ip_addresses;
        existing.urls = node.urls;
        existing.file_paths = node.file_paths;
        existing.domains = node.domains;
        existing.registry_keys = node.registry_keys;
        existing.risk_level = node.risk_level;
        existing.activity_profile = node.activity_profile;
        if (!node.llm_summary.empty()) existing.llm_summary = node.llm_summary;
        if (node.confidence > 0) existing.confidence = node.confidence;
        existing.is_stale = node.is_stale;
        existing.updated_at = ts;
        return &existing;
    }

    node.id = m_next_node_id++;
    node.created_at = ts;
    node.updated_at = ts;
    int id = node.id;
    m_nodes[id] = std::move(node);
    m_addr_index[key] = id;
    return &m_nodes[id];
}

graph_node_t* GraphStore::get_node(int id)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_nodes.find(id);
    return it != m_nodes.end() ? &it->second : nullptr;
}

graph_node_t* GraphStore::get_node_by_address(const std::string& binary_hash, node_type_t type, ea_t addr)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    addr_key_t key{binary_hash, type, addr};
    auto it = m_addr_index.find(key);
    if (it == m_addr_index.end()) return nullptr;
    auto nit = m_nodes.find(it->second);
    return nit != m_nodes.end() ? &nit->second : nullptr;
}

std::vector<graph_node_t*> GraphStore::get_nodes_by_type(const std::string& binary_hash, node_type_t type)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_node_t*> result;
    for (auto& [id, node] : m_nodes)
        if (node.binary_hash == binary_hash && node.node_type == type)
            result.push_back(&node);
    return result;
}

std::vector<graph_node_t*> GraphStore::get_all_nodes(const std::string& binary_hash)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_node_t*> result;
    for (auto& [id, node] : m_nodes)
        if (node.binary_hash == binary_hash)
            result.push_back(&node);
    return result;
}

graph_edge_t* GraphStore::add_edge(graph_edge_t edge)
{
    std::lock_guard<std::mutex> lk(m_mtx);


    for (auto& eid : m_edges_from[edge.source_id])
    {
        auto& e = m_edges[eid];
        if (e.target_id == edge.target_id && e.edge_type == edge.edge_type)
            return &e;
    }

    edge.id = m_next_edge_id++;
    int id = edge.id;
    m_edges[id] = std::move(edge);
    m_edges_from[m_edges[id].source_id].push_back(id);
    m_edges_to[m_edges[id].target_id].push_back(id);
    return &m_edges[id];
}

bool GraphStore::has_edge(int source_id, int target_id, edge_type_t type) const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_edges_from.find(source_id);
    if (it == m_edges_from.end()) return false;
    for (int eid : it->second)
    {
        auto eit = m_edges.find(eid);
        if (eit != m_edges.end() && eit->second.target_id == target_id && eit->second.edge_type == type)
            return true;
    }
    return false;
}

std::vector<graph_edge_t*> GraphStore::get_edges_from(int source_id)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_edge_t*> result;
    auto it = m_edges_from.find(source_id);
    if (it != m_edges_from.end())
        for (int eid : it->second)
            if (m_edges.count(eid)) result.push_back(&m_edges[eid]);
    return result;
}

std::vector<graph_edge_t*> GraphStore::get_edges_to(int target_id)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_edge_t*> result;
    auto it = m_edges_to.find(target_id);
    if (it != m_edges_to.end())
        for (int eid : it->second)
            if (m_edges.count(eid)) result.push_back(&m_edges[eid]);
    return result;
}

std::vector<graph_edge_t*> GraphStore::get_edges_for_node(int node_id)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_edge_t*> result;
    auto from_it = m_edges_from.find(node_id);
    if (from_it != m_edges_from.end())
        for (int eid : from_it->second)
            if (m_edges.count(eid)) result.push_back(&m_edges[eid]);
    auto to_it = m_edges_to.find(node_id);
    if (to_it != m_edges_to.end())
        for (int eid : to_it->second)
            if (m_edges.count(eid)) result.push_back(&m_edges[eid]);
    return result;
}

std::vector<graph_edge_t*> GraphStore::get_edges_by_types(const std::string& binary_hash, const std::vector<edge_type_t>& types)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::set<edge_type_t> type_set(types.begin(), types.end());
    std::vector<graph_edge_t*> result;
    for (auto& [id, edge] : m_edges)
        if (edge.binary_hash == binary_hash && type_set.count(edge.edge_type))
            result.push_back(&edge);
    return result;
}

std::vector<graph_node_t*> GraphStore::get_callers(const std::string& binary_hash, int node_id)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_node_t*> result;
    auto it = m_edges_to.find(node_id);
    if (it != m_edges_to.end())
    {
        for (int eid : it->second)
        {
            auto eit = m_edges.find(eid);
            if (eit == m_edges.end()) continue;
            if (eit->second.edge_type != edge_type_t::CALLS) continue;
            auto nit = m_nodes.find(eit->second.source_id);
            if (nit != m_nodes.end() && nit->second.binary_hash == binary_hash)
                result.push_back(&nit->second);
        }
    }
    return result;
}

std::vector<graph_node_t*> GraphStore::get_callees(const std::string& binary_hash, int node_id)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_node_t*> result;
    auto it = m_edges_from.find(node_id);
    if (it != m_edges_from.end())
    {
        for (int eid : it->second)
        {
            auto eit = m_edges.find(eid);
            if (eit == m_edges.end()) continue;
            if (eit->second.edge_type != edge_type_t::CALLS) continue;
            auto nit = m_nodes.find(eit->second.target_id);
            if (nit != m_nodes.end() && nit->second.binary_hash == binary_hash)
                result.push_back(&nit->second);
        }
    }
    return result;
}

void GraphStore::add_community(community_t comm)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    m_communities.push_back(std::move(comm));
}

std::vector<community_t> GraphStore::get_communities(const std::string& binary_hash) const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<community_t> result;
    for (auto& c : m_communities)
        if (c.binary_hash == binary_hash)
            result.push_back(c);
    return result;
}

bool GraphStore::communities_exist(const std::string& binary_hash) const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto& c : m_communities)
        if (c.binary_hash == binary_hash) return true;
    return false;
}

int GraphStore::delete_communities(const std::string& binary_hash)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    int count = 0;
    auto it = m_communities.begin();
    while (it != m_communities.end())
    {
        if (it->binary_hash == binary_hash)
        {
            it = m_communities.erase(it);
            ++count;
        }
        else ++it;
    }

    for (auto& [id, node] : m_nodes)
        if (node.binary_hash == binary_hash)
            node.community_id = -1;
    return count;
}

std::vector<graph_node_t*> GraphStore::search_nodes(const std::string& binary_hash,
                                                     const std::string& query, int limit)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_node_t*> result;


    std::vector<std::string> tokens;
    std::istringstream iss(query);
    std::string tok;
    while (iss >> tok)
    {

        if (tok == "OR" || tok == "or") continue;
        std::transform(tok.begin(), tok.end(), tok.begin(), ::tolower);
        tokens.push_back(tok);
    }


    struct scored_t { graph_node_t* node; int score; };
    std::vector<scored_t> scored;

    for (auto& [id, node] : m_nodes)
    {
        if (node.binary_hash != binary_hash) continue;

        int score = 0;
        std::string name_lower = node.name;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
        std::string summary_lower = node.llm_summary;
        std::transform(summary_lower.begin(), summary_lower.end(), summary_lower.begin(), ::tolower);

        for (auto& t : tokens)
        {
            if (name_lower.find(t) != std::string::npos) score += 3;
            if (summary_lower.find(t) != std::string::npos) score += 2;
            for (auto& flag : node.security_flags)
            {
                std::string flag_lower = flag;
                std::transform(flag_lower.begin(), flag_lower.end(), flag_lower.begin(), ::tolower);
                if (flag_lower.find(t) != std::string::npos) score += 1;
            }
        }

        if (score > 0) scored.push_back({&node, score});
    }

    std::sort(scored.begin(), scored.end(), [](auto& a, auto& b) { return a.score > b.score; });

    int count = 0;
    for (auto& s : scored)
    {
        result.push_back(s.node);
        if (++count >= limit) break;
    }
    return result;
}

GraphStore::graph_stats_t GraphStore::get_stats(const std::string& binary_hash) const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    graph_stats_t stats;
    for (auto& [id, node] : m_nodes)
    {
        if (node.binary_hash != binary_hash) continue;
        ++stats.nodes;
        if (node.is_stale) ++stats.stale;
    }
    for (auto& [id, edge] : m_edges)
        if (edge.binary_hash == binary_hash) ++stats.edges;
    for (auto& c : m_communities)
        if (c.binary_hash == binary_hash) ++stats.communities;
    return stats;
}

void GraphStore::delete_graph(const std::string& binary_hash)
{
    std::lock_guard<std::mutex> lk(m_mtx);


    auto eit = m_edges.begin();
    while (eit != m_edges.end())
    {
        if (eit->second.binary_hash == binary_hash)
            eit = m_edges.erase(eit);
        else ++eit;
    }


    auto nit = m_nodes.begin();
    while (nit != m_nodes.end())
    {
        if (nit->second.binary_hash == binary_hash)
        {
            addr_key_t key{binary_hash, nit->second.node_type, nit->second.address};
            m_addr_index.erase(key);
            nit = m_nodes.erase(nit);
        }
        else ++nit;
    }


    auto cit = m_communities.begin();
    while (cit != m_communities.end())
    {
        if (cit->binary_hash == binary_hash)
            cit = m_communities.erase(cit);
        else ++cit;
    }


    m_edges_from.clear();
    m_edges_to.clear();
    for (auto& [id, edge] : m_edges)
    {
        m_edges_from[edge.source_id].push_back(id);
        m_edges_to[edge.target_id].push_back(id);
    }
}

std::string GraphStore::get_graph_path(const std::string& binary_hash) const
{
    qstring dir = get_user_idadir();
    dir.append("/aida_db");
#ifdef __NT__
    CreateDirectoryA(dir.c_str(), nullptr);
#else
    mkdir(dir.c_str(), 0755);
#endif
    std::string result(dir.c_str());
    result += "/graph_";
    result += binary_hash;
    result += ".json";
    return result;
}

bool GraphStore::save_to_file(const std::string& path)
{
    std::lock_guard<std::mutex> lk(m_mtx);

    nlohmann::json j;
    j["version"] = 1;
    j["next_node_id"] = m_next_node_id;
    j["next_edge_id"] = m_next_edge_id;

    j["nodes"] = nlohmann::json::array();
    for (auto& [id, node] : m_nodes)
        j["nodes"].push_back(node);

    j["edges"] = nlohmann::json::array();
    for (auto& [id, edge] : m_edges)
        j["edges"].push_back(edge);

    j["communities"] = m_communities;

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) return false;
    ofs << j.dump(2);
    return true;
}

bool GraphStore::load_from_file(const std::string& path)
{
    std::lock_guard<std::mutex> lk(m_mtx);

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) return false;

    try
    {
        nlohmann::json j = nlohmann::json::parse(ifs);

        m_nodes.clear();
        m_edges.clear();
        m_communities.clear();
        m_addr_index.clear();
        m_edges_from.clear();
        m_edges_to.clear();

        m_next_node_id = j.value("next_node_id", 1);
        m_next_edge_id = j.value("next_edge_id", 1);

        if (j.contains("nodes"))
        {
            for (auto& nj : j["nodes"])
            {
                graph_node_t n = nj.get<graph_node_t>();
                int id = n.id;
                addr_key_t key{n.binary_hash, n.node_type, n.address};
                m_addr_index[key] = id;
                m_nodes[id] = std::move(n);
            }
        }

        if (j.contains("edges"))
        {
            for (auto& ej : j["edges"])
            {
                graph_edge_t e = ej.get<graph_edge_t>();
                int id = e.id;
                m_edges_from[e.source_id].push_back(id);
                m_edges_to[e.target_id].push_back(id);
                m_edges[id] = std::move(e);
            }
        }

        if (j.contains("communities"))
            m_communities = j["communities"].get<std::vector<community_t>>();

        return true;
    }
    catch (const std::exception&)
    {
        return false;
    }
}


StructureExtractor::StructureExtractor(GraphStore& store) : m_store(store) {}

std::string StructureExtractor::get_raw_code(ea_t func_ea)
{

    func_t* pfn = get_func(func_ea);
    if (pfn != nullptr)
    {
        hexrays_failure_t hf;
        cfuncptr_t cfunc = decompile(pfn, &hf, DECOMP_WARNINGS);
        if (cfunc != nullptr)
        {
            const strvec_t& sv = cfunc->get_pseudocode();
            std::string code;
            for (size_t i = 0; i < sv.size(); ++i)
            {
                qstring buf;
                tag_remove(&buf, sv[i].line);
                code += buf.c_str();
                code += "\n";
            }
            return code;
        }
    }


    func_t* func = pfn ? pfn : get_func(func_ea);
    if (!func) return {};

    std::string asm_text;
    ea_t ea = func->start_ea;
    while (ea < func->end_ea && ea != BADADDR)
    {
        qstring buf;
        generate_disasm_line(&buf, ea, GENDSM_REMOVE_TAGS);
        asm_text += buf.c_str();
        asm_text += "\n";
        ea = next_head(ea, func->end_ea);
    }
    return asm_text;
}

graph_node_t* StructureExtractor::extract_function(ea_t func_ea, const std::string& binary_hash)
{
    if (func_ea == BADADDR || binary_hash.empty()) return nullptr;


    qstring name_buf;
    get_func_name(&name_buf, func_ea);
    std::string func_name = name_buf.c_str();
    if (func_name.empty())
        func_name = "sub_" + std::to_string(func_ea);


    graph_node_t* existing = m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, func_ea);

    graph_node_t node;
    if (existing)
        node = *existing;
    else
    {
        node.binary_hash = binary_hash;
        node.node_type = node_type_t::FUNCTION;
        node.address = func_ea;
    }
    node.name = func_name;


    std::string raw_code = get_raw_code(func_ea);


    auto features = m_security.extract_from_code(func_name, raw_code);
    node.security_flags = features.generate_security_flags();
    node.network_apis.assign(features.network_apis.begin(), features.network_apis.end());
    node.file_io_apis.assign(features.file_io_apis.begin(), features.file_io_apis.end());
    node.crypto_apis.assign(features.crypto_apis.begin(), features.crypto_apis.end());
    node.process_apis.assign(features.process_apis.begin(), features.process_apis.end());
    node.ip_addresses.assign(features.ip_addresses.begin(), features.ip_addresses.end());
    node.urls.assign(features.urls.begin(), features.urls.end());
    node.file_paths.assign(features.file_paths.begin(), features.file_paths.end());
    node.domains.assign(features.domains.begin(), features.domains.end());
    node.registry_keys.assign(features.registry_keys.begin(), features.registry_keys.end());
    node.activity_profile = features.get_activity_profile();
    node.risk_level = features.get_risk_level();
    if (!raw_code.empty()) node.raw_code = raw_code;
    node.is_stale = true;

    graph_node_t* result = m_store.upsert_node(node);


    extract_call_edges(func_ea, binary_hash, *result);
    return result;
}

int StructureExtractor::extract_call_edges(ea_t func_ea, const std::string& binary_hash,
                                            graph_node_t& node)
{
    int edges_created = 0;
    func_t* func = get_func(func_ea);
    if (!func) return 0;


    std::set<ea_t> callee_addrs;
    ea_t ea = func->start_ea;
    while (ea < func->end_ea && ea != BADADDR)
    {
        xrefblk_t xb;
        for (bool ok = xb.first_from(ea, XREF_FAR); ok; ok = xb.next_from())
        {
            if (xb.type == fl_CN || xb.type == fl_CF)
            {
                func_t* callee_func = get_func(xb.to);
                if (callee_func && callee_func->start_ea != func_ea)
                    callee_addrs.insert(callee_func->start_ea);
            }
        }
        ea = next_head(ea, func->end_ea);
    }

    for (ea_t callee_ea : callee_addrs)
    {
        if (m_cancelled) break;

        qstring callee_name_buf;
        get_func_name(&callee_name_buf, callee_ea);
        std::string callee_name = callee_name_buf.c_str();
        if (callee_name.empty()) callee_name = "sub_" + std::to_string(callee_ea);

        graph_node_t* callee_node = m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, callee_ea);
        if (!callee_node)
        {
            graph_node_t cn;
            cn.binary_hash = binary_hash;
            cn.node_type = node_type_t::FUNCTION;
            cn.address = callee_ea;
            cn.name = callee_name;
            cn.is_stale = true;
            callee_node = m_store.upsert_node(cn);
        }

        graph_edge_t edge;
        edge.binary_hash = binary_hash;
        edge.source_id = node.id;
        edge.target_id = callee_node->id;
        edge.edge_type = edge_type_t::CALLS;
        edge.weight = 1.0;
        m_store.add_edge(edge);
        ++edges_created;


        if (!callee_node->security_flags.empty())
        {
            bool has_risk = false;
            for (auto& f : callee_node->security_flags)
                if (f.find("_RISK") != std::string::npos) { has_risk = true; break; }
            if (has_risk)
            {
                graph_edge_t vuln_edge;
                vuln_edge.binary_hash = binary_hash;
                vuln_edge.source_id = node.id;
                vuln_edge.target_id = callee_node->id;
                vuln_edge.edge_type = edge_type_t::CALLS_VULNERABLE;
                vuln_edge.weight = 1.0;
                m_store.add_edge(vuln_edge);
                ++edges_created;

                if (std::find(node.security_flags.begin(), node.security_flags.end(),
                              "CALLS_VULNERABLE_FUNCTION") == node.security_flags.end())
                {
                    node.security_flags.push_back("CALLS_VULNERABLE_FUNCTION");
                    m_store.upsert_node(node);
                }
            }
        }
    }

    return edges_created;
}

StructureExtractor::extraction_result_t
StructureExtractor::extract_all(const std::string& binary_hash, progress_fn on_progress)
{
    extraction_result_t result;
    m_cancelled = false;


    size_t total = get_func_qty();
    if (total == 0) return result;

    for (size_t i = 0; i < total; ++i)
    {
        if (m_cancelled) break;


        func_t* func = getn_func(i);
        if (!func) continue;

        if (on_progress)
            on_progress(static_cast<int>(i + 1), static_cast<int>(total), "Indexing: " + std::to_string(i + 1) + "/" + std::to_string(total));

        graph_node_t* node = extract_function(func->start_ea, binary_hash);
        if (node)
        {
            ++result.functions_extracted;
        }
    }

    return result;
}


TaintAnalyzer::TaintAnalyzer(GraphStore& store) : m_store(store) {}

const std::set<std::string>& TaintAnalyzer::taint_sources()
{
    static const std::set<std::string> s = {
        "recv", "recvfrom", "recvmsg", "read", "WSARecv", "WSARecvFrom",
        "InternetReadFile", "HttpQueryInfo", "WinHttpReadData",
        "fread", "fgets", "fgetc", "getc", "ReadFile", "ReadFileEx",
        "NtReadFile", "ZwReadFile",
        "scanf", "fscanf", "sscanf", "gets", "getline", "getdelim",
        "getenv", "GetEnvironmentVariable",
        "MapViewOfFile", "mmap",
    };
    return s;
}

const std::set<std::string>& TaintAnalyzer::taint_sinks()
{
    static const std::set<std::string> s = {
        "strcpy", "strcat", "sprintf", "vsprintf", "gets", "wcscpy", "wcscat",
        "lstrcpy", "lstrcpyA", "lstrcpyW", "lstrcat",
        "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
        "system", "popen", "_popen", "CreateProcess", "CreateProcessA",
        "CreateProcessW", "ShellExecute", "ShellExecuteA", "ShellExecuteW", "WinExec",
        "fopen", "open", "CreateFile", "CreateFileA", "CreateFileW",
        "mysql_query", "sqlite3_exec", "PQexec",
        "memcpy", "memmove", "memset", "RtlCopyMemory",
    };
    return s;
}

static const std::set<std::string> TAINT_SOURCE_FLAGS = {
    "NETWORK_CAPABLE", "READS_FILES", "ACCEPTS_CONNECTIONS",
    "INITIATES_CONNECTIONS", "PERFORMS_DNS_LOOKUP",
};

static const std::set<std::string> TAINT_SINK_FLAGS = {
    "BUFFER_OVERFLOW_RISK", "COMMAND_INJECTION_RISK",
    "FORMAT_STRING_RISK", "PATH_TRAVERSAL_RISK",
    "SQL_INJECTION_RISK", "CALLS_DANGEROUS_FUNCTIONS",
};

std::vector<graph_node_t*> TaintAnalyzer::find_source_nodes(const std::string& binary_hash)
{
    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    std::vector<graph_node_t*> sources;
    auto& ts = taint_sources();
    for (auto* n : nodes)
    {
        bool is_source = false;
        for (auto& f : n->security_flags)
            if (TAINT_SOURCE_FLAGS.count(f)) { is_source = true; break; }
        if (!is_source)
            for (auto& a : n->network_apis)
                if (ts.count(a)) { is_source = true; break; }
        if (!is_source)
            for (auto& a : n->file_io_apis)
                if (ts.count(a)) { is_source = true; break; }
        if (is_source) sources.push_back(n);
    }
    return sources;
}

std::vector<graph_node_t*> TaintAnalyzer::find_sink_nodes(const std::string& binary_hash)
{
    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    std::vector<graph_node_t*> sinks;
    auto& ts = taint_sinks();
    for (auto* n : nodes)
    {
        bool is_sink = false;
        for (auto& f : n->security_flags)
            if (TAINT_SINK_FLAGS.count(f)) { is_sink = true; break; }
        if (!is_sink)
            for (auto& a : n->network_apis)
                if (ts.count(a)) { is_sink = true; break; }
        if (!is_sink)
            for (auto& a : n->file_io_apis)
                if (ts.count(a)) { is_sink = true; break; }
        if (is_sink) sinks.push_back(n);
    }
    return sinks;
}

std::vector<std::pair<std::vector<int>, graph_node_t*>> TaintAnalyzer::dfs_paths(
    int source_id, const std::unordered_map<int, graph_node_t*>& sinks,
    const std::string& binary_hash, int remaining)
{
    std::vector<std::pair<std::vector<int>, graph_node_t*>> results;
    std::vector<std::pair<int, std::vector<int>>> stack;
    stack.push_back({source_id, {source_id}});

    while (!stack.empty() && remaining > 0)
    {
        if (m_cancelled) break;
        auto [node_id, path] = stack.back();
        stack.pop_back();

        if (static_cast<int>(path.size()) > MAX_PATH_LENGTH) continue;

        if (node_id != source_id)
        {
            auto it = sinks.find(node_id);
            if (it != sinks.end())
            {
                results.push_back({path, it->second});
                --remaining;
                continue;
            }
        }


        auto edges = m_store.get_edges_from(node_id);
        for (auto* e : edges)
        {
            if (e->edge_type != edge_type_t::CALLS) continue;

            bool in_path = false;
            for (int pid : path)
                if (pid == e->target_id) { in_path = true; break; }
            if (in_path) continue;

            auto new_path = path;
            new_path.push_back(e->target_id);
            stack.push_back({e->target_id, new_path});
        }
    }
    return results;
}

std::vector<taint_path_t> TaintAnalyzer::find_taint_paths(const std::string& binary_hash,
                                                           int max_paths, bool create_edges)
{
    m_cancelled = false;

    auto sources = find_source_nodes(binary_hash);
    auto sink_nodes = find_sink_nodes(binary_hash);

    if (sources.empty() || sink_nodes.empty()) return {};

    std::unordered_map<int, graph_node_t*> sink_map;
    for (auto* n : sink_nodes) sink_map[n->id] = n;

    std::vector<taint_path_t> paths;
    for (auto* source : sources)
    {
        if (m_cancelled) break;
        if (static_cast<int>(paths.size()) >= max_paths) break;

        auto found = dfs_paths(source->id, sink_map, binary_hash, max_paths - static_cast<int>(paths.size()));
        for (auto& [path_ids, sink_node] : found)
        {
            if (m_cancelled) break;

            taint_path_t tp;
            tp.source_id = source->id;
            tp.sink_id = sink_node->id;
            tp.path = path_ids;
            tp.source_name = source->name;
            tp.sink_name = sink_node->name;
            paths.push_back(tp);

            if (create_edges)
            {

                for (size_t i = 0; i + 1 < path_ids.size(); ++i)
                {
                    graph_edge_t edge;
                    edge.binary_hash = binary_hash;
                    edge.source_id = path_ids[i];
                    edge.target_id = path_ids[i + 1];
                    edge.edge_type = edge_type_t::TAINT_FLOWS_TO;
                    edge.weight = 1.0;
                    m_store.add_edge(edge);
                }


                graph_edge_t vuln_edge;
                vuln_edge.binary_hash = binary_hash;
                vuln_edge.source_id = source->id;
                vuln_edge.target_id = sink_node->id;
                vuln_edge.edge_type = edge_type_t::VULNERABLE_VIA;
                vuln_edge.weight = 1.0;
                m_store.add_edge(vuln_edge);
            }
        }
    }
    return paths;
}


CommunityDetector::CommunityDetector(GraphStore& store) : m_store(store) {}


static const std::map<std::string, std::vector<std::string>> PURPOSE_PATTERNS = {
    {"network", {"socket", "connect", "send", "recv", "http", "dns", "net", "tcp", "udp",
                 "WSA", "inet", "listen", "accept", "bind", "gethost"}},
    {"file_io", {"file", "read", "write", "open", "close", "fopen", "fwrite", "fread",
                 "CreateFile", "ReadFile", "WriteFile"}},
    {"crypto", {"crypt", "aes", "sha", "md5", "encrypt", "decrypt", "hash", "rsa",
                "cipher", "hmac", "base64"}},
    {"memory", {"alloc", "malloc", "free", "heap", "realloc", "calloc", "mmap",
                "VirtualAlloc", "VirtualFree", "HeapAlloc"}},
    {"string", {"str", "sprintf", "strcpy", "strcat", "strlen", "strcmp", "string",
                "wcs", "memcpy", "memset"}},
    {"process", {"thread", "process", "exec", "spawn", "fork", "CreateProcess",
                 "CreateThread", "TerminateProcess", "ExitProcess"}},
    {"registry", {"reg", "registry", "hkey", "RegOpen", "RegQuery", "RegSet"}},
    {"init", {"init", "setup", "start", "main", "entry", "constructor", "ctor",
              "initialize", "DllMain", "WinMain"}},
    {"gui", {"window", "dialog", "button", "menu", "paint", "draw", "CreateWindow",
             "ShowWindow", "MessageBox", "SendMessage"}},
};

std::string CommunityDetector::infer_community_purpose(const std::vector<graph_node_t*>& members)
{
    std::map<std::string, int> scores;
    for (auto* m : members)
    {
        std::string name_lower = m->name;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
        for (auto& [purpose, keywords] : PURPOSE_PATTERNS)
            for (auto& kw : keywords)
            {
                std::string kw_lower = kw;
                std::transform(kw_lower.begin(), kw_lower.end(), kw_lower.begin(), ::tolower);
                if (name_lower.find(kw_lower) != std::string::npos)
                    ++scores[purpose];
            }
    }

    if (scores.empty()) return "general";

    auto best = std::max_element(scores.begin(), scores.end(),
        [](auto& a, auto& b) { return a.second < b.second; });
    return best->first;
}

int CommunityDetector::detect(const std::string& binary_hash, int min_size,
                               int max_iterations, bool force, progress_fn on_progress)
{
    m_cancelled = false;

    if (!force && m_store.communities_exist(binary_hash))
        return static_cast<int>(m_store.get_communities(binary_hash).size());

    if (force)
        m_store.delete_communities(binary_hash);

    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    if (nodes.empty()) return 0;


    auto edges = m_store.get_edges_by_types(binary_hash, {edge_type_t::CALLS, edge_type_t::CALLS_VULNERABLE});
    std::unordered_map<int, std::set<int>> adjacency;
    for (auto* e : edges)
    {
        adjacency[e->source_id].insert(e->target_id);
        adjacency[e->target_id].insert(e->source_id);
    }


    std::unordered_map<int, int> labels;
    for (auto* n : nodes)
        labels[n->id] = n->id;


    for (int iter = 0; iter < max_iterations; ++iter)
    {
        if (m_cancelled) return 0;
        if (on_progress) on_progress(iter + 1, max_iterations);

        bool changed = false;
        for (auto* n : nodes)
        {
            auto& neighbors = adjacency[n->id];
            if (neighbors.empty()) continue;


            std::map<int, int> label_counts;
            for (int neighbor_id : neighbors)
            {
                auto it = labels.find(neighbor_id);
                if (it != labels.end())
                    ++label_counts[it->second];
            }
            if (label_counts.empty()) continue;


            int best_label = labels[n->id];
            int best_count = 0;
            for (auto& [lbl, cnt] : label_counts)
            {
                if (cnt > best_count)
                {
                    best_count = cnt;
                    best_label = lbl;
                }
            }


            int current_count = label_counts.count(labels[n->id]) ? label_counts[labels[n->id]] : 0;
            if (current_count < best_count)
            {
                labels[n->id] = best_label;
                changed = true;
            }
        }

        if (!changed) break;
    }

    if (m_cancelled) return 0;


    std::unordered_map<int, std::vector<graph_node_t*>> groups;
    for (auto* n : nodes)
        groups[labels[n->id]].push_back(n);


    std::unordered_map<int, int> merge_map;
    for (auto& [label, members] : groups)
    {
        if (static_cast<int>(members.size()) >= min_size) continue;


        std::map<int, int> neighbor_community_sizes;
        for (auto* m : members)
        {
            for (int neighbor_id : adjacency[m->id])
            {
                int neighbor_label = labels[neighbor_id];
                if (neighbor_label != label)
                    ++neighbor_community_sizes[neighbor_label];
            }
        }
        if (!neighbor_community_sizes.empty())
        {
            int best = std::max_element(neighbor_community_sizes.begin(),
                                         neighbor_community_sizes.end(),
                                         [](auto& a, auto& b) { return a.second < b.second; })->first;
            merge_map[label] = best;
        }
    }


    for (auto& [old_label, new_label] : merge_map)
    {
        for (auto* n : groups[old_label])
            labels[n->id] = new_label;
    }


    groups.clear();
    for (auto* n : nodes)
        groups[labels[n->id]].push_back(n);


    int comm_id = 1;
    int count = 0;
    for (auto& [label, members] : groups)
    {
        if (static_cast<int>(members.size()) < min_size) continue;

        community_t comm;
        comm.id = comm_id++;
        comm.binary_hash = binary_hash;
        comm.purpose = infer_community_purpose(members);
        comm.label = comm.purpose + "_" + std::to_string(comm.id);
        for (auto* m : members)
        {
            comm.member_ids.push_back(m->id);
            m->community_id = comm.id;
            m_store.upsert_node(*m);
        }
        m_store.add_community(comm);
        ++count;
    }

    return count;
}


NetworkFlowAnalyzer::NetworkFlowAnalyzer(GraphStore& store) : m_store(store) {}

const std::set<std::string>& NetworkFlowAnalyzer::send_apis()
{
    static const std::set<std::string> s = {
        "send", "sendto", "sendmsg", "write",
        "WSASend", "WSASendTo", "WSASendMsg",
        "SSL_write", "WinHttpWriteData", "WinHttpSendRequest",
        "InternetWriteFile", "HttpSendRequest", "HttpSendRequestA", "HttpSendRequestW",
        "curl_easy_send",
    };
    return s;
}

const std::set<std::string>& NetworkFlowAnalyzer::recv_apis()
{
    static const std::set<std::string> s = {
        "recv", "recvfrom", "recvmsg", "read",
        "WSARecv", "WSARecvFrom", "WSARecvMsg",
        "SSL_read", "WinHttpReadData", "WinHttpReceiveResponse",
        "InternetReadFile", "InternetReadFileEx", "HttpQueryInfo",
        "curl_easy_recv",
    };
    return s;
}

const std::set<std::string>& NetworkFlowAnalyzer::entry_point_names()
{
    static const std::set<std::string> s = {
        "main", "_main", "wmain", "_wmain",
        "WinMain", "wWinMain", "_WinMain@16", "_wWinMain@16",
        "DllMain", "_DllMain@12", "DllEntryPoint",
        "start", "_start", "entry", "_entry",
        "mainCRTStartup", "wmainCRTStartup",
        "WinMainCRTStartup", "wWinMainCRTStartup",
    };
    return s;
}

std::vector<graph_node_t*> NetworkFlowAnalyzer::find_send_nodes(const std::string& binary_hash)
{
    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    auto& apis = send_apis();
    std::vector<graph_node_t*> result;
    for (auto* n : nodes)
    {
        for (auto& a : n->network_apis)
            if (apis.count(a)) { result.push_back(n); break; }
    }
    return result;
}

std::vector<graph_node_t*> NetworkFlowAnalyzer::find_recv_nodes(const std::string& binary_hash)
{
    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    auto& apis = recv_apis();
    std::vector<graph_node_t*> result;
    for (auto* n : nodes)
    {
        for (auto& a : n->network_apis)
            if (apis.count(a)) { result.push_back(n); break; }
    }
    return result;
}

NetworkFlowAnalyzer::result_t
NetworkFlowAnalyzer::analyze(const std::string& binary_hash, progress_fn on_progress)
{
    m_cancelled = false;
    result_t result;

    auto send_nodes = find_send_nodes(binary_hash);
    auto recv_nodes = find_recv_nodes(binary_hash);

    for (auto* n : send_nodes) result.send_functions.push_back(n->name);
    for (auto* n : recv_nodes) result.recv_functions.push_back(n->name);

    if (on_progress)
        on_progress(10, 100, "Found " + std::to_string(send_nodes.size()) + " send, " +
                    std::to_string(recv_nodes.size()) + " recv functions");


    auto& entries = entry_point_names();
    auto all_nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    std::vector<graph_node_t*> entry_nodes;
    for (auto* n : all_nodes)
        if (entries.count(n->name)) entry_nodes.push_back(n);


    std::unordered_set<int> send_ids;
    for (auto* n : send_nodes) send_ids.insert(n->id);

    for (auto* entry : entry_nodes)
    {
        if (m_cancelled) break;
        auto paths = bfs_find_paths(entry->id, send_ids, binary_hash);
        for (auto& fp : paths)
        {
            if (m_cancelled) break;
            fp.source_name = entry->name;

            auto* target = m_store.get_node(fp.target_id);
            if (target)
            {
                fp.target_name = target->name;
                auto& apis = send_apis();
                for (auto& a : target->network_apis)
                    if (apis.count(a)) { fp.api_name = a; break; }
            }
            result.send_paths.push_back(fp);

            if (!m_store.has_edge(entry->id, fp.target_id, edge_type_t::NETWORK_SEND))
            {
                graph_edge_t edge;
                edge.binary_hash = binary_hash;
                edge.source_id = entry->id;
                edge.target_id = fp.target_id;
                edge.edge_type = edge_type_t::NETWORK_SEND;
                edge.weight = 1.0 / fp.hop_count;
                m_store.add_edge(edge);
                ++result.send_edges_created;
            }
            else
                ++result.send_edges_existing;
        }
    }

    if (on_progress) on_progress(60, 100, "Analyzing recv flow...");


    for (auto* recv : recv_nodes)
    {
        if (m_cancelled) break;
        auto callers = m_store.get_callers(binary_hash, recv->id);
        for (auto* caller : callers)
        {
            if (m_cancelled) break;

            flow_path_t fp;
            fp.source_id = recv->id;
            fp.target_id = caller->id;
            fp.path = {recv->id, caller->id};
            fp.source_name = recv->name;
            fp.target_name = caller->name;
            fp.hop_count = 1;
            auto& apis = recv_apis();
            for (auto& a : recv->network_apis)
                if (apis.count(a)) { fp.api_name = a; break; }
            result.recv_paths.push_back(fp);

            if (!m_store.has_edge(recv->id, caller->id, edge_type_t::NETWORK_RECV))
            {
                graph_edge_t edge;
                edge.binary_hash = binary_hash;
                edge.source_id = recv->id;
                edge.target_id = caller->id;
                edge.edge_type = edge_type_t::NETWORK_RECV;
                edge.weight = 1.0;
                m_store.add_edge(edge);
                ++result.recv_edges_created;
            }
            else
                ++result.recv_edges_existing;


            auto callers2 = m_store.get_callers(binary_hash, caller->id);
            for (auto* caller2 : callers2)
            {
                if (m_cancelled) break;
                flow_path_t fp2;
                fp2.source_id = recv->id;
                fp2.target_id = caller2->id;
                fp2.path = {recv->id, caller->id, caller2->id};
                fp2.source_name = recv->name;
                fp2.target_name = caller2->name;
                fp2.api_name = fp.api_name;
                fp2.hop_count = 2;
                result.recv_paths.push_back(fp2);
            }
        }
    }

    if (on_progress) on_progress(100, 100, "Complete");
    return result;
}

std::vector<NetworkFlowAnalyzer::flow_path_t>
NetworkFlowAnalyzer::bfs_find_paths(int source_id, const std::unordered_set<int>& targets,
                                     const std::string& binary_hash)
{
    std::vector<flow_path_t> found;
    if (targets.empty()) return found;


    std::deque<std::pair<int, std::vector<int>>> queue;
    std::unordered_set<int> visited;
    queue.push_back({source_id, {source_id}});
    visited.insert(source_id);

    while (!queue.empty() && !m_cancelled)
    {
        auto [current, path] = queue.front();
        queue.pop_front();

        if (static_cast<int>(path.size()) > MAX_PATH_LENGTH) continue;

        if (current != source_id && targets.count(current))
        {
            flow_path_t fp;
            fp.source_id = source_id;
            fp.target_id = current;
            fp.path = path;
            fp.hop_count = static_cast<int>(path.size()) - 1;
            found.push_back(fp);
            continue;
        }

        auto edges = m_store.get_edges_from(current);
        for (auto* e : edges)
        {
            if (e->edge_type != edge_type_t::CALLS) continue;
            if (visited.count(e->target_id)) continue;
            visited.insert(e->target_id);
            auto new_path = path;
            new_path.push_back(e->target_id);
            queue.push_back({e->target_id, new_path});
        }
    }

    return found;
}


QueryEngine::QueryEngine(GraphStore& store) : m_store(store) {}

std::string QueryEngine::node_display_name(const graph_node_t* n) const
{
    if (!n) return "unknown";
    if (!n->name.empty()) return n->name;
    if (n->address != BADADDR)
    {
        char buf[32];
        qsnprintf(buf, sizeof(buf), "sub_%llx", (unsigned long long)n->address);
        return buf;
    }
    return "node_" + std::to_string(n->id);
}

nlohmann::json QueryEngine::get_semantic_analysis(const std::string& binary_hash, ea_t address)
{
    auto* node = m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, address);
    if (!node)
    {
        return {
            {"name", "unknown"}, {"address", address},
            {"has_semantic_analysis", false}, {"has_structure_data", false},
            {"message", "Function not found in graph."}
        };
    }

    auto callers = m_store.get_callers(binary_hash, node->id);
    auto callees = m_store.get_callees(binary_hash, node->id);
    bool has_semantic = !node->llm_summary.empty();
    bool has_structure = !node->raw_code.empty() || !callers.empty() || !callees.empty();

    nlohmann::json j;
    j["name"] = node_display_name(node);
    j["address"] = node->address;
    j["has_semantic_analysis"] = has_semantic;
    j["has_structure_data"] = has_structure;
    j["summary"] = has_semantic ? node->llm_summary : "(Analysis pending - structure data available)";
    j["security_flags"] = node->security_flags;
    j["risk_level"] = node->risk_level;
    j["activity_profile"] = node->activity_profile;
    j["confidence"] = node->confidence;

    j["callers"] = nlohmann::json::array();
    for (auto* c : callers)
        j["callers"].push_back(node_display_name(c));

    j["callees"] = nlohmann::json::array();
    for (auto* c : callees)
        j["callees"].push_back(node_display_name(c));

    if (!node->raw_code.empty())
    {
        std::string truncated = node->raw_code;
        if (truncated.size() > 2000) truncated = truncated.substr(0, 2000) + "\n... (truncated)";
        j["raw_code"] = truncated;
    }

    if (node->community_id >= 0)
    {
        auto communities = m_store.get_communities(binary_hash);
        for (auto& comm : communities)
        {
            if (comm.id == node->community_id)
            {
                j["community"] = {{"id", comm.id}, {"label", comm.label},
                                  {"purpose", comm.purpose}, {"size", comm.member_ids.size()}};
                break;
            }
        }
    }

    return j;
}

nlohmann::json QueryEngine::search_semantic(const std::string& binary_hash,
                                             const std::string& query, int limit)
{
    auto results = m_store.search_nodes(binary_hash, query, limit);
    nlohmann::json j = nlohmann::json::array();
    for (auto* n : results)
    {
        nlohmann::json entry;
        entry["function_name"] = node_display_name(n);
        entry["address"] = n->address;
        std::string summary = n->llm_summary;
        if (summary.size() > 200) summary = summary.substr(0, 200) + "...";
        entry["summary"] = summary;
        entry["security_flags"] = n->security_flags;
        entry["risk_level"] = n->risk_level;
        j.push_back(entry);
    }
    return j;
}

nlohmann::json QueryEngine::get_similar_functions(const std::string& binary_hash,
                                                   ea_t address, int limit)
{
    auto* source = m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, address);
    if (!source) return nlohmann::json::array();

    nlohmann::json j = nlohmann::json::array();
    std::set<int> seen = {source->id};


    auto callers = m_store.get_callers(binary_hash, source->id);
    for (auto* caller : callers)
    {
        if (static_cast<int>(j.size()) >= limit) break;
        auto siblings = m_store.get_callees(binary_hash, caller->id);
        for (auto* sibling : siblings)
        {
            if (static_cast<int>(j.size()) >= limit) break;
            if (seen.count(sibling->id)) continue;
            seen.insert(sibling->id);
            j.push_back({
                {"function_name", node_display_name(sibling)},
                {"address", sibling->address},
                {"similarity", 0.7}, {"reason", "SHARED_CALLERS"}
            });
        }
    }


    auto callees = m_store.get_callees(binary_hash, source->id);
    for (auto* callee : callees)
    {
        if (static_cast<int>(j.size()) >= limit) break;
        auto sibling_callers = m_store.get_callers(binary_hash, callee->id);
        for (auto* sibling : sibling_callers)
        {
            if (static_cast<int>(j.size()) >= limit) break;
            if (seen.count(sibling->id)) continue;
            seen.insert(sibling->id);
            j.push_back({
                {"function_name", node_display_name(sibling)},
                {"address", sibling->address},
                {"similarity", 0.6}, {"reason", "SHARED_CALLEES"}
            });
        }
    }

    return j;
}

nlohmann::json QueryEngine::get_call_context(const std::string& binary_hash,
                                              ea_t address, int depth)
{
    auto* node = m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, address);
    if (!node) return {{"error", "Function not found"}};

    nlohmann::json j;
    j["function"] = node_display_name(node);
    j["address"] = node->address;


    std::function<nlohmann::json(int, int, bool)> build_tree =
        [&](int nid, int max_depth, bool is_callers) -> nlohmann::json
    {
        nlohmann::json arr = nlohmann::json::array();
        if (max_depth <= 0) return arr;

        auto nodes = is_callers ? m_store.get_callers(binary_hash, nid)
                                : m_store.get_callees(binary_hash, nid);
        for (auto* n : nodes)
        {
            nlohmann::json entry;
            entry["name"] = node_display_name(n);
            entry["address"] = n->address;
            if (max_depth > 1)
                entry[is_callers ? "callers" : "callees"] = build_tree(n->id, max_depth - 1, is_callers);
            arr.push_back(entry);
        }
        return arr;
    };

    j["callers"] = build_tree(node->id, depth, true);
    j["callees"] = build_tree(node->id, depth, false);

    return j;
}

nlohmann::json QueryEngine::get_taint_paths(const std::string& binary_hash, ea_t address)
{
    auto* node = m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, address);
    if (!node) return {{"error", "Function not found"}};


    auto edges_from = m_store.get_edges_from(node->id);
    auto edges_to = m_store.get_edges_to(node->id);

    nlohmann::json j;
    j["function"] = node_display_name(node);
    j["address"] = node->address;

    nlohmann::json taint_from = nlohmann::json::array();
    nlohmann::json taint_to = nlohmann::json::array();

    for (auto* e : edges_from)
    {
        if (e->edge_type == edge_type_t::TAINT_FLOWS_TO || e->edge_type == edge_type_t::VULNERABLE_VIA)
        {
            auto* target = m_store.get_node(e->target_id);
            taint_from.push_back({
                {"target", node_display_name(target)},
                {"type", edge_type_str(e->edge_type)}
            });
        }
    }

    for (auto* e : edges_to)
    {
        if (e->edge_type == edge_type_t::TAINT_FLOWS_TO || e->edge_type == edge_type_t::VULNERABLE_VIA)
        {
            auto* source = m_store.get_node(e->source_id);
            taint_to.push_back({
                {"source", node_display_name(source)},
                {"type", edge_type_str(e->edge_type)}
            });
        }
    }

    j["taint_flows_to"] = taint_from;
    j["taint_flows_from"] = taint_to;
    j["is_taint_source"] = !taint_from.empty() && taint_to.empty();
    j["is_taint_sink"] = taint_to.empty() && !taint_from.empty();

    return j;
}

nlohmann::json QueryEngine::get_community_info(const std::string& binary_hash, ea_t address)
{
    auto* node = m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, address);
    if (!node || node->community_id < 0)
        return {{"error", "Function not in a community"}};

    auto communities = m_store.get_communities(binary_hash);
    for (auto& comm : communities)
    {
        if (comm.id != node->community_id) continue;

        nlohmann::json j;
        j["community_id"] = comm.id;
        j["label"] = comm.label;
        j["purpose"] = comm.purpose;
        j["size"] = comm.member_ids.size();

        nlohmann::json members = nlohmann::json::array();
        for (int mid : comm.member_ids)
        {
            auto* m = m_store.get_node(mid);
            if (m) members.push_back({{"name", node_display_name(m)}, {"address", m->address}});
        }
        j["members"] = members;
        return j;
    }

    return {{"error", "Community not found"}};
}


nlohmann::json QueryEngine::get_security_analysis(const std::string& binary_hash, int limit)
{
    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);

    nlohmann::json j;
    j["total_functions"] = nodes.size();

    int critical = 0, high = 0, medium = 0, low = 0;
    nlohmann::json risky_funcs = nlohmann::json::array();

    std::map<std::string, int> flag_counts;

    for (auto* n : nodes)
    {
        if (n->risk_level == "CRITICAL") ++critical;
        else if (n->risk_level == "HIGH") ++high;
        else if (n->risk_level == "MEDIUM") ++medium;
        else if (n->risk_level == "LOW") ++low;

        for (auto& f : n->security_flags)
            ++flag_counts[f];

        if ((n->risk_level == "CRITICAL" || n->risk_level == "HIGH")
            && static_cast<int>(risky_funcs.size()) < limit)
        {
            risky_funcs.push_back({
                {"name", node_display_name(n)},
                {"address", n->address},
                {"risk_level", n->risk_level},
                {"security_flags", n->security_flags},
                {"activity_profile", n->activity_profile}
            });
        }
    }

    j["risk_summary"] = {
        {"critical", critical}, {"high", high}, {"medium", medium}, {"low", low}
    };
    j["high_risk_functions"] = risky_funcs;

    nlohmann::json flags_j = nlohmann::json::object();
    for (auto& [flag, count] : flag_counts)
        flags_j[flag] = count;
    j["security_flag_distribution"] = flags_j;

    return j;
}

nlohmann::json QueryEngine::get_activity_analysis(const std::string& binary_hash,
                                                    const std::string& activity_filter)
{
    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);

    std::map<std::string, std::vector<nlohmann::json>> by_activity;
    for (auto* n : nodes)
    {
        if (n->activity_profile.empty()) continue;

        std::istringstream iss(n->activity_profile);
        std::string token;
        while (std::getline(iss, token, ','))
        {
            if (!activity_filter.empty() && token != activity_filter) continue;
            nlohmann::json entry;
            entry["name"] = node_display_name(n);
            entry["address"] = n->address;
            entry["risk_level"] = n->risk_level;
            by_activity[token].push_back(entry);
        }
    }

    nlohmann::json j;
    j["total_functions_with_activity"] = 0;
    nlohmann::json activities = nlohmann::json::object();
    for (auto& [activity, funcs] : by_activity)
    {
        activities[activity] = {
            {"count", funcs.size()},
            {"functions", funcs}
        };
        j["total_functions_with_activity"] =
            j["total_functions_with_activity"].get<int>() + static_cast<int>(funcs.size());
    }
    j["activities"] = activities;
    return j;
}

nlohmann::json QueryEngine::get_all_communities(const std::string& binary_hash)
{
    auto communities = m_store.get_communities(binary_hash);

    nlohmann::json j;
    j["total_communities"] = communities.size();

    nlohmann::json comms = nlohmann::json::array();
    for (auto& comm : communities)
    {
        nlohmann::json cj;
        cj["id"] = comm.id;
        cj["label"] = comm.label;
        cj["purpose"] = comm.purpose;
        cj["size"] = comm.member_ids.size();

        nlohmann::json members = nlohmann::json::array();
        for (int mid : comm.member_ids)
        {
            auto* m = m_store.get_node(mid);
            if (m)
                members.push_back({{"name", node_display_name(m)}, {"address", m->address}});
        }
        cj["members"] = members;
        comms.push_back(cj);
    }
    j["communities"] = comms;
    return j;
}


void initialize(const std::string& binary_hash)
{
    if (binary_hash.empty()) return;
    auto& store = GraphStore::instance();

    std::string path = store.get_graph_path(binary_hash);
    store.load_from_file(path);

    msg("[AiDA GraphRAG] Loaded graph for %s\n", binary_hash.c_str());
    auto stats = store.get_stats(binary_hash);
    msg("[AiDA GraphRAG] Nodes: %d, Edges: %d, Communities: %d\n",
        stats.nodes, stats.edges, stats.communities);
}

void save_graph(const std::string& binary_hash)
{
    if (binary_hash.empty()) return;
    auto& store = GraphStore::instance();
    std::string path = store.get_graph_path(binary_hash);
    if (store.save_to_file(path))
        msg("[AiDA GraphRAG] Graph saved to %s\n", path.c_str());
}

void load_graph(const std::string& binary_hash)
{
    initialize(binary_hash);
}

}
