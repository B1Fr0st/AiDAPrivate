#pragma once

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <shlobj.h>
#include <shellapi.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <iphlpapi.h>
#include <Lmcons.h>

#include <string>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <memory>
#include <thread>
#include <mutex>
#include <regex>
#include <stdexcept>
#include <functional>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <ctime>

#include <nlohmann/json.hpp>

#include "xor.hpp"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shlwapi.lib")

using json = nlohmann::json;

#ifdef DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif
