#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "auth_store.hpp"

#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <aclapi.h>
#include <sddl.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <unordered_map>

#include "anti-tamper/webhook.hpp"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Advapi32.lib")

namespace aida {
namespace auth {
namespace store {

	namespace {

		std::mutex& state_mutex()
		{
			static std::mutex m;
			return m;
		}

		std::string& last_error_ref()
		{
			static std::string s;
			return s;
		}

		std::unordered_map<std::string, auth_info_t>& cache()
		{
			static std::unordered_map<std::string, auth_info_t> c;
			return c;
		}

		bool& loaded_flag()
		{
			static bool b = false;
			return b;
		}

		void set_last_error(const std::string& text)
		{
			last_error_ref() = text;
			if (!text.empty()) {
				const std::string line = std::string("[aida.auth.store] ") + text;
				anti_tamper::webhook::write_log("auth.store", line.c_str());
			}
		}

		const char kBase64Charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

		std::string base64_encode(const unsigned char* data, size_t length)
		{
			std::string out;
			out.reserve(((length + 2) / 3) * 4);
			size_t i = 0;
			while (i + 3 <= length) {
				const unsigned int v = (static_cast<unsigned int>(data[i]) << 16)
					| (static_cast<unsigned int>(data[i + 1]) << 8)
					| static_cast<unsigned int>(data[i + 2]);
				out.push_back(kBase64Charset[(v >> 18) & 0x3F]);
				out.push_back(kBase64Charset[(v >> 12) & 0x3F]);
				out.push_back(kBase64Charset[(v >> 6) & 0x3F]);
				out.push_back(kBase64Charset[v & 0x3F]);
				i += 3;
			}
			if (i < length) {
				const size_t left = length - i;
				unsigned int v = static_cast<unsigned int>(data[i]) << 16;
				if (left == 2)
					v |= static_cast<unsigned int>(data[i + 1]) << 8;
				out.push_back(kBase64Charset[(v >> 18) & 0x3F]);
				out.push_back(kBase64Charset[(v >> 12) & 0x3F]);
				if (left == 2) {
					out.push_back(kBase64Charset[(v >> 6) & 0x3F]);
					out.push_back('=');
				} else {
					out.push_back('=');
					out.push_back('=');
				}
			}
			return out;
		}

		bool base64_decode(const std::string& text, std::vector<unsigned char>& out)
		{
			static int8_t table[256];
			static bool table_ready = false;
			if (!table_ready) {
				for (int i = 0; i < 256; ++i)
					table[i] = -1;
				for (int i = 0; i < 64; ++i)
					table[static_cast<unsigned char>(kBase64Charset[i])] = static_cast<int8_t>(i);
				table_ready = true;
			}

			out.clear();
			out.reserve((text.size() / 4) * 3);
			unsigned int buffer = 0;
			int bits = 0;
			for (char ch : text) {
				if (ch == '=' || ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t')
					continue;
				const int8_t v = table[static_cast<unsigned char>(ch)];
				if (v < 0)
					return false;
				buffer = (buffer << 6) | static_cast<unsigned int>(v);
				bits += 6;
				if (bits >= 8) {
					bits -= 8;
					out.push_back(static_cast<unsigned char>((buffer >> bits) & 0xFF));
				}
			}
			return true;
		}

		std::filesystem::path data_directory()
		{
			wchar_t* appdata = nullptr;
			if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
				auto path = std::filesystem::path(appdata) / L"AiDA";
				CoTaskMemFree(appdata);
				return path;
			}
			return std::filesystem::current_path() / "AiDA";
		}

		std::filesystem::path data_path()
		{
			return data_directory() / L"auth.json";
		}

		bool ensure_directory(const std::filesystem::path& dir)
		{
			std::error_code ec;
			if (std::filesystem::exists(dir, ec))
				return true;
			ec.clear();
			if (!std::filesystem::create_directories(dir, ec)) {
				if (ec) {
					set_last_error("create_directories failed: " + ec.message());
					return false;
				}
			}
			return true;
		}

		bool restrict_acl_to_current_user(const std::filesystem::path& path)
		{
			HANDLE token = nullptr;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
				return false;

			DWORD needed = 0;
			GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
			if (needed == 0) {
				CloseHandle(token);
				return false;
			}

			std::vector<BYTE> buffer(needed);
			if (!GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed)) {
				CloseHandle(token);
				return false;
			}
			CloseHandle(token);

			auto* user_info = reinterpret_cast<TOKEN_USER*>(buffer.data());
			PSID user_sid = user_info->User.Sid;

			EXPLICIT_ACCESSW ea{};
			ea.grfAccessPermissions = GENERIC_ALL;
			ea.grfAccessMode = SET_ACCESS;
			ea.grfInheritance = NO_INHERITANCE;
			ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
			ea.Trustee.ptstrName = static_cast<LPWSTR>(user_sid);

			PACL new_acl = nullptr;
			if (SetEntriesInAclW(1, &ea, nullptr, &new_acl) != ERROR_SUCCESS)
				return false;

			std::wstring wpath = path.wstring();
			DWORD rc = SetNamedSecurityInfoW(
				const_cast<LPWSTR>(wpath.c_str()),
				SE_FILE_OBJECT,
				DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
				nullptr,
				nullptr,
				new_acl,
				nullptr);

			if (new_acl)
				LocalFree(new_acl);

			return rc == ERROR_SUCCESS;
		}

		bool dpapi_protect(const std::string& plaintext, std::vector<unsigned char>& out)
		{
			out.clear();
			DATA_BLOB input_blob{
				static_cast<DWORD>(plaintext.size()),
				reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data())),
			};
			static const char kEntropy[] = "AiDA:auth:store:v1";
			DATA_BLOB entropy_blob{
				static_cast<DWORD>(std::strlen(kEntropy)),
				reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy)),
			};
			DATA_BLOB output_blob{};
			if (!CryptProtectData(&input_blob, L"AiDA Auth Store", &entropy_blob,
					nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output_blob))
				return false;
			out.assign(output_blob.pbData, output_blob.pbData + output_blob.cbData);
			SecureZeroMemory(output_blob.pbData, output_blob.cbData);
			LocalFree(output_blob.pbData);
			return true;
		}

		bool dpapi_unprotect(const std::vector<unsigned char>& cipher, std::string& plaintext)
		{
			plaintext.clear();
			if (cipher.empty())
				return false;
			DATA_BLOB input_blob{
				static_cast<DWORD>(cipher.size()),
				const_cast<BYTE*>(cipher.data()),
			};
			static const char kEntropy[] = "AiDA:auth:store:v1";
			DATA_BLOB entropy_blob{
				static_cast<DWORD>(std::strlen(kEntropy)),
				reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy)),
			};
			DATA_BLOB output_blob{};
			if (!CryptUnprotectData(&input_blob, nullptr, &entropy_blob, nullptr, nullptr,
					CRYPTPROTECT_UI_FORBIDDEN, &output_blob))
				return false;
			plaintext.assign(reinterpret_cast<const char*>(output_blob.pbData), output_blob.cbData);
			SecureZeroMemory(output_blob.pbData, output_blob.cbData);
			LocalFree(output_blob.pbData);
			return true;
		}

		std::string normalize_provider(const std::string& key)
		{
			std::string norm = key;
			while (!norm.empty() && norm.back() == '/')
				norm.pop_back();
			return norm;
		}

		nlohmann::json info_to_json(const auth_info_t& info)
		{
			nlohmann::json j = nlohmann::json::object();
			switch (info.kind) {
				case auth_kind_t::oauth: {
					j["type"] = "oauth";
					j["refresh"] = info.refresh;
					j["access"] = info.access;
					j["expires"] = info.expires_unix;
					if (!info.account_id.empty())
						j["accountId"] = info.account_id;
					if (!info.enterprise_url.empty())
						j["enterpriseUrl"] = info.enterprise_url;
					if (!info.email.empty())
						j["email"] = info.email;
					break;
				}
				case auth_kind_t::api: {
					j["type"] = "api";
					j["key"] = info.api_key;
					if (!info.metadata.is_null() && !info.metadata.empty())
						j["metadata"] = info.metadata;
					break;
				}
				case auth_kind_t::wellknown: {
					j["type"] = "wellknown";
					j["key"] = info.wellknown_key;
					j["token"] = info.wellknown_token;
					break;
				}
				case auth_kind_t::none:
				default:
					j["type"] = "none";
					break;
			}
			if (!info.custom_client_id.empty())
				j["customClientId"] = info.custom_client_id;
			if (!info.custom_redirect_uri.empty())
				j["customRedirectUri"] = info.custom_redirect_uri;
			if (!info.custom_scopes.empty())
				j["customScopes"] = info.custom_scopes;
			return j;
		}

		bool json_to_info(const nlohmann::json& j, auth_info_t& out)
		{
			out = auth_info_t{};
			if (!j.is_object())
				return false;
			const std::string type_str = j.value("type", std::string{});
			if (type_str == "oauth") {
				out.kind = auth_kind_t::oauth;
				out.refresh = j.value("refresh", std::string{});
				out.access = j.value("access", std::string{});
				out.expires_unix = j.value("expires", static_cast<int64_t>(0));
				out.account_id = j.value("accountId", std::string{});
				out.enterprise_url = j.value("enterpriseUrl", std::string{});
				out.email = j.value("email", std::string{});
			} else if (type_str == "api") {
				out.kind = auth_kind_t::api;
				out.api_key = j.value("key", std::string{});
				if (j.contains("metadata") && j["metadata"].is_object())
					out.metadata = j["metadata"];
			} else if (type_str == "wellknown") {
				out.kind = auth_kind_t::wellknown;
				out.wellknown_key = j.value("key", std::string{});
				out.wellknown_token = j.value("token", std::string{});
			} else {
				out.kind = auth_kind_t::none;
			}
			if (j.contains("customClientId") && j["customClientId"].is_string())
				out.custom_client_id = j["customClientId"].get<std::string>();
			if (j.contains("customRedirectUri") && j["customRedirectUri"].is_string())
				out.custom_redirect_uri = j["customRedirectUri"].get<std::string>();
			if (j.contains("customScopes") && j["customScopes"].is_array()) {
				for (const auto& s : j["customScopes"]) {
					if (s.is_string())
						out.custom_scopes.push_back(s.get<std::string>());
				}
			}
			return true;
		}

		bool save_locked()
		{
			nlohmann::json data = nlohmann::json::object();
			for (const auto& [k, v] : cache())
				data[k] = info_to_json(v);

			const std::string serialized = data.dump();
			std::vector<unsigned char> cipher;
			if (!dpapi_protect(serialized, cipher)) {
				set_last_error("CryptProtectData failed gle=" + std::to_string(GetLastError()));
				return false;
			}

			nlohmann::json wrapper = nlohmann::json::object();
			wrapper["v"] = 1;
			wrapper["enc"] = base64_encode(cipher.data(), cipher.size());
			const std::string out_str = wrapper.dump();

			const auto dir = data_directory();
			if (!ensure_directory(dir))
				return false;

			const auto path = data_path();
			const auto tmp_path = path.parent_path() / (path.filename().wstring() + L".tmp");

			{
				std::ofstream ofs(tmp_path, std::ios::binary | std::ios::trunc);
				if (!ofs.is_open()) {
					set_last_error("open auth tmp file failed");
					return false;
				}
				ofs.write(out_str.data(), static_cast<std::streamsize>(out_str.size()));
				if (!ofs.good()) {
					set_last_error("write auth tmp file failed");
					return false;
				}
			}

			std::error_code ec;
			std::filesystem::rename(tmp_path, path, ec);
			if (ec) {
				std::filesystem::remove(path, ec);
				ec.clear();
				std::filesystem::rename(tmp_path, path, ec);
				if (ec) {
					set_last_error("rename auth file failed: " + ec.message());
					return false;
				}
			}

			restrict_acl_to_current_user(path);
			set_last_error({});
			return true;
		}

		bool load_locked()
		{
			cache().clear();
			loaded_flag() = true;

			const auto path = data_path();
			std::error_code ec;
			if (!std::filesystem::exists(path, ec))
				return true;

			std::ifstream ifs(path, std::ios::binary);
			if (!ifs.is_open()) {
				set_last_error("open auth file failed");
				return false;
			}

			std::ostringstream oss;
			oss << ifs.rdbuf();
			const std::string raw = oss.str();
			if (raw.empty())
				return true;

			nlohmann::json wrapper;
			try {
				wrapper = nlohmann::json::parse(raw);
			} catch (...) {
				set_last_error("auth file json parse failed");
				return false;
			}

			if (!wrapper.is_object() || !wrapper.contains("enc") || !wrapper["enc"].is_string()) {
				set_last_error("auth file wrapper malformed");
				return false;
			}

			std::vector<unsigned char> cipher;
			if (!base64_decode(wrapper["enc"].get<std::string>(), cipher)) {
				set_last_error("auth file base64 decode failed");
				return false;
			}

			std::string plaintext;
			if (!dpapi_unprotect(cipher, plaintext)) {
				set_last_error("CryptUnprotectData failed gle=" + std::to_string(GetLastError()));
				return false;
			}

			nlohmann::json data;
			try {
				data = nlohmann::json::parse(plaintext);
			} catch (...) {
				SecureZeroMemory(plaintext.data(), plaintext.size());
				set_last_error("auth payload json parse failed");
				return false;
			}
			SecureZeroMemory(plaintext.data(), plaintext.size());

			if (!data.is_object()) {
				set_last_error("auth payload not object");
				return false;
			}

			for (auto it = data.begin(); it != data.end(); ++it) {
				auth_info_t info;
				if (json_to_info(it.value(), info))
					cache()[it.key()] = info;
			}

			set_last_error({});
			return true;
		}

	}

	bool load()
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		return load_locked();
	}

	bool save()
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		if (!loaded_flag()) {
			if (!load_locked())
				return false;
		}
		return save_locked();
	}

	bool get(const std::string& provider_id, auth_info_t& out)
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		if (!loaded_flag()) {
			if (!load_locked())
				return false;
		}
		const std::string key = normalize_provider(provider_id);
		auto it = cache().find(key);
		if (it == cache().end()) {
			it = cache().find(provider_id);
			if (it == cache().end())
				return false;
		}
		out = it->second;
		return true;
	}

	bool set(const std::string& provider_id, const auth_info_t& info)
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		if (!loaded_flag()) {
			if (!load_locked())
				return false;
		}
		const std::string key = normalize_provider(provider_id);
		cache().erase(provider_id);
		cache().erase(key + "/");
		cache()[key] = info;
		return save_locked();
	}

	bool remove(const std::string& provider_id)
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		if (!loaded_flag()) {
			if (!load_locked())
				return false;
		}
		const std::string key = normalize_provider(provider_id);
		cache().erase(provider_id);
		cache().erase(key);
		cache().erase(key + "/");
		return save_locked();
	}

	std::vector<std::pair<std::string, auth_info_t>> all()
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		if (!loaded_flag())
			load_locked();
		std::vector<std::pair<std::string, auth_info_t>> out;
		out.reserve(cache().size());
		for (const auto& kv : cache())
			out.emplace_back(kv.first, kv.second);
		std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
			return a.first < b.first;
		});
		return out;
	}

	const std::string& last_error()
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		return last_error_ref();
	}

}
}
}
