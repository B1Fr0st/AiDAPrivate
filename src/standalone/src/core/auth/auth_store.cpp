#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "auth_store.hpp"

#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace auth {
namespace store {

namespace {

	std::mutex& preview_mutex()
	{
		static std::mutex value;
		return value;
	}

	std::string& preview_error()
	{
		thread_local std::string value;
		return value;
	}

	void set_preview_error()
	{
		preview_error() = "preview_auth_store_unavailable";
	}

}

bool load()
{
	std::lock_guard<std::mutex> lock(preview_mutex());
	set_preview_error();
	return false;
}

bool save()
{
	std::lock_guard<std::mutex> lock(preview_mutex());
	set_preview_error();
	return false;
}

bool get(const std::string&, auth_info_t& out)
{
	std::lock_guard<std::mutex> lock(preview_mutex());
	out = auth_info_t{};
	set_preview_error();
	return false;
}

bool set(const std::string&, const auth_info_t&)
{
	std::lock_guard<std::mutex> lock(preview_mutex());
	set_preview_error();
	return false;
}

bool set_if(const std::string&, const auth_info_t&,
	const std::function<bool()>&)
{
	std::lock_guard<std::mutex> lock(preview_mutex());
	set_preview_error();
	return false;
}

bool remove(const std::string&)
{
	std::lock_guard<std::mutex> lock(preview_mutex());
	set_preview_error();
	return false;
}

bool all(std::vector<std::pair<std::string, auth_info_t>>& out)
{
	std::lock_guard<std::mutex> lock(preview_mutex());
	out.clear();
	set_preview_error();
	return false;
}

std::string last_error()
{
	std::lock_guard<std::mutex> lock(preview_mutex());
	return preview_error();
}

}
}
}

#else

#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include "auth_store.hpp"

#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <aclapi.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <limits>
#include <mutex>
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
			thread_local std::string s;
			return s;
		}

		using auth_map_t = std::unordered_map<std::string, auth_info_t>;

		auth_map_t& cache()
		{
			static auth_map_t c;
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
		constexpr std::uint64_t kMaximumStoreBytes = 16ull * 1024ull * 1024ull;
		constexpr std::size_t kMaximumProviders = 128;
		constexpr std::size_t kMaximumCredentialBytes = 1024u * 1024u;
		constexpr std::size_t kMaximumIdentityBytes = 16u * 1024u;
		constexpr std::size_t kMaximumScopeBytes = 4096;
		constexpr std::size_t kMaximumScopes = 128;
		constexpr std::size_t kMaximumMetadataBytes = 1024u * 1024u;
		constexpr std::size_t kMaximumMetadataDepth = 32;
		constexpr std::size_t kMaximumMetadataNodes = 8192;

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
			if (text.empty() || text.size() % 4 != 0) return false;
			const std::size_t padding = text.back() == '='
				? (text.size() > 1 && text[text.size() - 2] == '=' ? 2u : 1u) : 0u;
			if (padding == 1) {
				const int8_t final_digit = table[static_cast<unsigned char>(text[text.size() - 2])];
				if (final_digit < 0 || (static_cast<unsigned>(final_digit) & 0x03u) != 0) return false;
			} else if (padding == 2) {
				const int8_t final_digit = table[static_cast<unsigned char>(text[text.size() - 3])];
				if (final_digit < 0 || (static_cast<unsigned>(final_digit) & 0x0Fu) != 0) return false;
			}
			out.reserve((text.size() / 4) * 3 - padding);
			for (std::size_t offset = 0; offset < text.size(); offset += 4) {
				unsigned value = 0;
				for (std::size_t index = 0; index < 4; ++index) {
					const unsigned char ch = static_cast<unsigned char>(text[offset + index]);
					const bool is_padding = ch == '=';
					const bool expected_padding = offset + 4 == text.size()
						&& padding != 0 && index >= 4 - padding;
					if (is_padding != expected_padding) return false;
					if (is_padding) {
						value <<= 6;
						continue;
					}
					const int8_t digit = table[ch];
					if (digit < 0) return false;
					value = (value << 6) | static_cast<unsigned>(digit);
				}
				out.push_back(static_cast<unsigned char>((value >> 16) & 0xFF));
				if (offset + 4 != text.size() || padding < 2)
					out.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
				if (offset + 4 != text.size() || padding == 0)
					out.push_back(static_cast<unsigned char>(value & 0xFF));
			}
			return !out.empty();
		}

		std::filesystem::path data_directory()
		{
			wchar_t* appdata = nullptr;
			const HRESULT result = SHGetKnownFolderPath(
				FOLDERID_RoamingAppData, 0, nullptr, &appdata);
			if (SUCCEEDED(result) && appdata != nullptr) {
				auto path = std::filesystem::path(appdata) / L"AiDA";
				CoTaskMemFree(appdata);
				return path;
			}
			if (appdata != nullptr) CoTaskMemFree(appdata);
			set_last_error("resolve auth data directory failed hr="
				+ std::to_string(static_cast<long>(result)));
			return {};
		}

		std::filesystem::path data_path()
		{
			const auto directory = data_directory();
			return directory.empty() ? std::filesystem::path{}
				: directory / L"auth.json";
		}

		bool ensure_directory(const std::filesystem::path& dir)
		{
			if (dir.empty()) return false;
			std::error_code ec;
			if (std::filesystem::exists(dir, ec)) {
				const DWORD attributes = GetFileAttributesW(dir.c_str());
				if (attributes == INVALID_FILE_ATTRIBUTES
					|| (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0
					|| (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
					set_last_error("auth data directory identity invalid");
					return false;
				}
				return true;
			}
			if (ec) {
				set_last_error("query auth data directory failed: " + ec.message());
				return false;
			}
			ec.clear();
			if (!std::filesystem::create_directories(dir, ec)) {
				if (ec) {
					set_last_error("create_directories failed: " + ec.message());
					return false;
				}
			}
			const DWORD attributes = GetFileAttributesW(dir.c_str());
			if (attributes == INVALID_FILE_ATTRIBUTES
				|| (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0
				|| (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
				set_last_error("created auth data directory identity invalid");
				return false;
			}
			return true;
		}

		bool build_current_user_acl(PACL& acl) noexcept
		{
			acl = nullptr;
			HANDLE token = nullptr;
			try {
				if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
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
				token = nullptr;
				auto* user_info = reinterpret_cast<TOKEN_USER*>(buffer.data());
				EXPLICIT_ACCESSW access{};
				access.grfAccessPermissions = GENERIC_ALL;
				access.grfAccessMode = SET_ACCESS;
				access.grfInheritance = NO_INHERITANCE;
				access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
				access.Trustee.TrusteeType = TRUSTEE_IS_USER;
				access.Trustee.ptstrName = static_cast<LPWSTR>(user_info->User.Sid);
				const DWORD result = SetEntriesInAclW(1, &access, nullptr, &acl);
				if (result != ERROR_SUCCESS) {
					SetLastError(result);
					return false;
				}
				return true;
			} catch (...) {
				if (token != nullptr) CloseHandle(token);
				if (acl != nullptr) {
					LocalFree(acl);
					acl = nullptr;
				}
				SetLastError(ERROR_NOT_ENOUGH_MEMORY);
				return false;
			}
		}

		bool restrict_acl_to_current_user(const std::filesystem::path& path)
		{
			PACL acl = nullptr;
			if (!build_current_user_acl(acl)) return false;

			DWORD rc = ERROR_NOT_ENOUGH_MEMORY;
			try {
				std::wstring wpath = path.wstring();
				rc = SetNamedSecurityInfoW(
					const_cast<LPWSTR>(wpath.c_str()),
					SE_FILE_OBJECT,
					DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
					nullptr,
					nullptr,
					acl,
					nullptr);
			} catch (...) {
			}
			LocalFree(acl);

			if (rc != ERROR_SUCCESS) SetLastError(rc);
			return rc == ERROR_SUCCESS;
		}

		bool restrict_acl_to_current_user(HANDLE file)
		{
			if (file == nullptr || file == INVALID_HANDLE_VALUE) {
				SetLastError(ERROR_INVALID_HANDLE);
				return false;
			}
			PACL acl = nullptr;
			if (!build_current_user_acl(acl)) return false;
			const DWORD result = SetSecurityInfo(file, SE_FILE_OBJECT,
				DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
				nullptr, nullptr, acl, nullptr);
			LocalFree(acl);
			if (result != ERROR_SUCCESS) SetLastError(result);
			return result == ERROR_SUCCESS;
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
			try {
				out.assign(output_blob.pbData, output_blob.pbData + output_blob.cbData);
			} catch (...) {
				SecureZeroMemory(output_blob.pbData, output_blob.cbData);
				LocalFree(output_blob.pbData);
				out.clear();
				SetLastError(ERROR_NOT_ENOUGH_MEMORY);
				return false;
			}
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
			try {
				plaintext.assign(reinterpret_cast<const char*>(output_blob.pbData), output_blob.cbData);
			} catch (...) {
				SecureZeroMemory(output_blob.pbData, output_blob.cbData);
				LocalFree(output_blob.pbData);
				plaintext.clear();
				SetLastError(ERROR_NOT_ENOUGH_MEMORY);
				return false;
			}
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

		bool valid_provider_key(const std::string& key) noexcept;

		bool bounded_json_text(const std::string& text, std::size_t maximum_string,
			std::size_t maximum_tokens) noexcept
		{
			std::size_t depth = 0;
			std::size_t string_bytes = 0;
			std::size_t tokens = 0;
			bool quoted = false;
			bool escaped = false;
			for (unsigned char ch : text) {
				if (quoted) {
					if (++string_bytes > maximum_string) return false;
					if (escaped) {
						escaped = false;
					} else if (ch == '\\') {
						escaped = true;
					} else if (ch == '"') {
						quoted = false;
					}
					continue;
				}
				if (ch == '"') {
					quoted = true;
					string_bytes = 0;
				} else if (ch == '{' || ch == '[') {
					if (++depth > kMaximumMetadataDepth + 4 || ++tokens > maximum_tokens)
						return false;
				} else if (ch == '}' || ch == ']') {
					if (depth == 0) return false;
					--depth;
				} else if ((ch == ',' || ch == ':') && ++tokens > maximum_tokens) {
					return false;
				}
			}
			return !quoted && !escaped && depth == 0;
		}

		bool bounded_metadata(const nlohmann::json& metadata)
		{
			if (!metadata.is_object()) return false;
			struct node_t {
				const nlohmann::json* value = nullptr;
				std::size_t depth = 0;
			};
			std::vector<node_t> pending;
			pending.push_back(node_t{ &metadata, 1 });
			std::size_t nodes = 0;
			std::size_t aggregate = 0;
			while (!pending.empty()) {
				const node_t current = pending.back();
				pending.pop_back();
				if (!current.value || current.depth > kMaximumMetadataDepth
					|| ++nodes > kMaximumMetadataNodes) return false;
				const auto& value = *current.value;
				if (value.is_string()) {
					const auto& string_value = value.get_ref<const std::string&>();
					if (string_value.size() > kMaximumIdentityBytes
						|| string_value.size() > kMaximumMetadataBytes - aggregate) return false;
					aggregate += string_value.size();
				} else if (value.is_object()) {
					if (value.size() > kMaximumMetadataNodes - nodes) return false;
					for (auto it = value.begin(); it != value.end(); ++it) {
						if (it.key().empty() || it.key().size() > kMaximumIdentityBytes
							|| it.key().size() > kMaximumMetadataBytes - aggregate) return false;
						aggregate += it.key().size();
						pending.push_back(node_t{ &it.value(), current.depth + 1 });
					}
				} else if (value.is_array()) {
					if (value.size() > kMaximumMetadataNodes - nodes) return false;
					for (const auto& child : value)
						pending.push_back(node_t{ &child, current.depth + 1 });
				} else if (!value.is_null() && !value.is_boolean()
					&& !value.is_number()) {
					return false;
				}
			}
			return aggregate <= kMaximumMetadataBytes;
		}

		bool bounded_string(const std::string& value, std::size_t maximum,
			bool required = false) noexcept
		{
			return value.size() <= maximum && (!required || !value.empty());
		}

		bool valid_auth_info(const auth_info_t& info)
		{
			if (!bounded_string(info.custom_client_id, kMaximumIdentityBytes)
				|| !bounded_string(info.custom_redirect_uri, kMaximumIdentityBytes)
				|| info.custom_scopes.size() > kMaximumScopes
				|| !bounded_metadata(info.metadata)) return false;
			std::size_t scope_bytes = 0;
			for (const auto& scope : info.custom_scopes) {
				if (!bounded_string(scope, kMaximumScopeBytes, true)
					|| scope.size() > kMaximumMetadataBytes - scope_bytes) return false;
				scope_bytes += scope.size();
			}
			if (!bounded_string(info.account_id, kMaximumIdentityBytes)
				|| !bounded_string(info.enterprise_url, kMaximumIdentityBytes)
				|| !bounded_string(info.email, kMaximumIdentityBytes)) return false;
			switch (info.kind) {
				case auth_kind_t::oauth:
					return bounded_string(info.access, kMaximumCredentialBytes, true)
						&& bounded_string(info.refresh, kMaximumCredentialBytes)
						&& info.expires_unix >= 0
						&& info.api_key.empty() && info.wellknown_key.empty()
						&& info.wellknown_token.empty();
				case auth_kind_t::api:
					return bounded_string(info.api_key, kMaximumCredentialBytes, true)
						&& info.refresh.empty() && info.access.empty()
						&& info.account_id.empty() && info.enterprise_url.empty()
						&& info.email.empty() && info.expires_unix == 0
						&& info.wellknown_key.empty() && info.wellknown_token.empty();
				case auth_kind_t::wellknown:
					return bounded_string(info.wellknown_key, kMaximumCredentialBytes)
						&& bounded_string(info.wellknown_token, kMaximumCredentialBytes, true)
						&& info.refresh.empty() && info.access.empty()
						&& info.account_id.empty() && info.enterprise_url.empty()
						&& info.email.empty() && info.expires_unix == 0
						&& info.api_key.empty();
				case auth_kind_t::none:
				default:
					return false;
			}
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
			if (!info.metadata.is_null() && !info.metadata.empty())
				j["metadata"] = info.metadata;
			return j;
		}

		bool json_to_info(const nlohmann::json& j, auth_info_t& out)
		{
			out = auth_info_t{};
			if (!j.is_object() || !j.contains("type") || !j["type"].is_string())
				return false;
			const std::string type_str = j["type"].get<std::string>();
			auto allowed = [&](const std::string& key) noexcept {
				if (key == "type" || key == "metadata" || key == "customClientId"
					|| key == "customRedirectUri" || key == "customScopes") return true;
				if (type_str == "oauth") return key == "refresh" || key == "access"
					|| key == "expires" || key == "accountId"
					|| key == "enterpriseUrl" || key == "email";
				if (type_str == "api") return key == "key";
				if (type_str == "wellknown") return key == "key" || key == "token";
				return false;
			};
			for (auto it = j.begin(); it != j.end(); ++it) {
				if (!allowed(it.key())) return false;
			}
			auth_info_t candidate;
			auto required_string = [&](const char* key, std::string& value,
				std::size_t maximum, bool nonempty) {
				if (!j.contains(key) || !j[key].is_string()) return false;
				value = j[key].get<std::string>();
				return bounded_string(value, maximum, nonempty);
			};
			auto optional_string = [&](const char* key, std::string& value,
				std::size_t maximum) {
				if (!j.contains(key)) return true;
				if (!j[key].is_string()) return false;
				value = j[key].get<std::string>();
				return bounded_string(value, maximum);
			};
			if (type_str == "oauth") {
				candidate.kind = auth_kind_t::oauth;
				if (!required_string("refresh", candidate.refresh, kMaximumCredentialBytes, false)
					|| !required_string("access", candidate.access, kMaximumCredentialBytes, true)
					|| !j.contains("expires") || !j["expires"].is_number_integer()
					|| !optional_string("accountId", candidate.account_id, kMaximumIdentityBytes)
					|| !optional_string("enterpriseUrl", candidate.enterprise_url, kMaximumIdentityBytes)
					|| !optional_string("email", candidate.email, kMaximumIdentityBytes)) return false;
				candidate.expires_unix = j["expires"].get<std::int64_t>();
			} else if (type_str == "api") {
				candidate.kind = auth_kind_t::api;
				if (!required_string("key", candidate.api_key, kMaximumCredentialBytes, true))
					return false;
			} else if (type_str == "wellknown") {
				candidate.kind = auth_kind_t::wellknown;
				if (!required_string("key", candidate.wellknown_key,
						kMaximumCredentialBytes, false)
					|| !required_string("token", candidate.wellknown_token,
						kMaximumCredentialBytes, true)) return false;
			} else {
				return false;
			}
			if (j.contains("metadata")) {
				if (!j["metadata"].is_object() || !bounded_metadata(j["metadata"]))
					return false;
				candidate.metadata = j["metadata"];
			}
			if (!optional_string("customClientId", candidate.custom_client_id,
					kMaximumIdentityBytes)
				|| !optional_string("customRedirectUri", candidate.custom_redirect_uri,
					kMaximumIdentityBytes)) return false;
			if (j.contains("customScopes")) {
				if (!j["customScopes"].is_array()
					|| j["customScopes"].size() > kMaximumScopes) return false;
				for (const auto& scope : j["customScopes"]) {
					if (!scope.is_string()) return false;
					std::string value = scope.get<std::string>();
					if (!bounded_string(value, kMaximumScopeBytes, true)) return false;
					candidate.custom_scopes.push_back(std::move(value));
				}
			}
			if (!valid_auth_info(candidate)) return false;
			out = std::move(candidate);
			return true;
		}

		bool read_file_bounded(const std::filesystem::path& path, std::string& raw)
		{
			raw.clear();
			HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
				nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
			if (file == INVALID_HANDLE_VALUE) {
				set_last_error("open auth file failed gle=" + std::to_string(GetLastError()));
				return false;
			}
			FILE_ATTRIBUTE_TAG_INFO identity{};
			if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo,
					&identity, static_cast<DWORD>(sizeof(identity)))
				|| (identity.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
				|| (identity.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
				const DWORD error = GetLastError();
				CloseHandle(file);
				set_last_error("auth file identity invalid gle=" + std::to_string(error));
				return false;
			}
			LARGE_INTEGER size{};
			if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0
				|| static_cast<std::uint64_t>(size.QuadPart) > kMaximumStoreBytes) {
				const DWORD error = GetLastError();
				CloseHandle(file);
				set_last_error(size.QuadPart <= 0 ? "auth file is empty"
					: size.QuadPart > static_cast<LONGLONG>(kMaximumStoreBytes)
						? "auth file exceeds size limit"
						: "auth file size query failed gle=" + std::to_string(error));
				return false;
			}
			try {
				raw.resize(static_cast<std::size_t>(size.QuadPart));
			} catch (...) {
				CloseHandle(file);
				set_last_error("auth file allocation failed");
				return false;
			}
			std::size_t offset = 0;
			while (offset < raw.size()) {
				DWORD transferred = 0;
				const DWORD requested = static_cast<DWORD>((std::min)(raw.size() - offset,
					static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
				if (!ReadFile(file, raw.data() + offset, requested, &transferred, nullptr)
					|| transferred == 0) {
					const DWORD error = GetLastError();
					CloseHandle(file);
					raw.clear();
					set_last_error("read auth file failed gle=" + std::to_string(error));
					return false;
				}
				offset += transferred;
			}
			CloseHandle(file);
			return true;
		}

		bool decode_document(const std::string& raw, auth_map_t& decoded)
		{
			decoded.clear();
			if (raw.empty() || raw.size() > kMaximumStoreBytes) {
				set_last_error(raw.empty() ? "auth file is empty" : "auth file exceeds size limit");
				return false;
			}
			if (!bounded_json_text(raw, static_cast<std::size_t>(kMaximumStoreBytes), 64)) {
				set_last_error("auth file wrapper resource limits exceeded");
				return false;
			}
			nlohmann::json wrapper;
			try {
				wrapper = nlohmann::json::parse(raw);
			} catch (...) {
				set_last_error("auth file json parse failed");
				return false;
			}
			if (!wrapper.is_object() || wrapper.size() != 2
				|| !wrapper.contains("v") || !wrapper["v"].is_number_integer()
				|| wrapper["v"].get<int>() != 1
				|| !wrapper.contains("enc") || !wrapper["enc"].is_string()) {
				set_last_error("auth file wrapper malformed");
				return false;
			}
			const std::string encoded = wrapper["enc"].get<std::string>();
			if (encoded.size() > kMaximumStoreBytes) {
				set_last_error("auth ciphertext exceeds size limit");
				return false;
			}
			std::vector<unsigned char> cipher;
			if (!base64_decode(encoded, cipher)) {
				set_last_error("auth file base64 decode failed");
				return false;
			}
			std::string plaintext;
			if (!dpapi_unprotect(cipher, plaintext)) {
				set_last_error("CryptUnprotectData failed gle=" + std::to_string(GetLastError()));
				return false;
			}
			if (!cipher.empty()) SecureZeroMemory(cipher.data(), cipher.size());
			if (plaintext.empty() || plaintext.size() > kMaximumStoreBytes) {
				if (!plaintext.empty()) SecureZeroMemory(plaintext.data(), plaintext.size());
				set_last_error("auth payload size invalid");
				return false;
			}
			const std::size_t maximum_tokens = kMaximumMetadataNodes * 4u
				+ kMaximumProviders * 16u;
			if (!bounded_json_text(plaintext, kMaximumCredentialBytes, maximum_tokens)) {
				SecureZeroMemory(plaintext.data(), plaintext.size());
				set_last_error("auth payload resource limits exceeded");
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
			if (!data.is_object() || data.size() > kMaximumProviders) {
				set_last_error("auth payload not object");
				return false;
			}
			try {
				for (auto it = data.begin(); it != data.end(); ++it) {
					if (!valid_provider_key(it.key())) {
						set_last_error("auth provider key invalid");
						return false;
					}
					auth_info_t info;
					if (!json_to_info(it.value(), info) || !valid_auth_info(info)) {
						set_last_error("auth provider entry malformed");
						return false;
					}
					if (!decoded.emplace(it.key(), std::move(info)).second) {
						set_last_error("duplicate auth provider entry");
						return false;
					}
				}
			} catch (...) {
				decoded.clear();
				set_last_error("auth payload materialization failed");
				return false;
			}
			return true;
		}

		std::filesystem::path temporary_path(const std::filesystem::path& path)
		{
			static std::atomic<std::uint64_t> sequence{1};
			return path.parent_path() / (path.filename().wstring() + L".tmp."
				+ std::to_wstring(GetCurrentProcessId()) + L"."
				+ std::to_wstring(sequence.fetch_add(1, std::memory_order_relaxed)));
		}

		struct temporary_file_guard_t {
			const std::filesystem::path* path = nullptr;
			bool active = false;
			explicit temporary_file_guard_t(const std::filesystem::path& value) noexcept
				: path(&value), active(true) {}
			~temporary_file_guard_t()
			{
				if (active && path) DeleteFileW(path->c_str());
			}
			void release() noexcept { active = false; }
		};

		bool write_and_validate_temporary(const std::filesystem::path& path,
			const std::string& document)
		{
			HANDLE file = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | WRITE_DAC,
				0, nullptr,
				CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH
					| FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
			if (file == INVALID_HANDLE_VALUE) {
				set_last_error("create auth temporary file failed gle=" + std::to_string(GetLastError()));
				return false;
			}
			if (!restrict_acl_to_current_user(file)) {
				const DWORD error = GetLastError();
				CloseHandle(file);
				DeleteFileW(path.c_str());
				set_last_error("restrict auth temporary ACL failed gle=" + std::to_string(error));
				return false;
			}
			std::size_t offset = 0;
			while (offset < document.size()) {
				DWORD transferred = 0;
				const DWORD requested = static_cast<DWORD>((std::min)(document.size() - offset,
					static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
				if (!WriteFile(file, document.data() + offset, requested, &transferred, nullptr)
					|| transferred == 0) {
					const DWORD error = GetLastError();
					CloseHandle(file);
					DeleteFileW(path.c_str());
					set_last_error("write auth temporary file failed gle=" + std::to_string(error));
					return false;
				}
				offset += transferred;
			}
			if (!FlushFileBuffers(file)) {
				const DWORD error = GetLastError();
				CloseHandle(file);
				DeleteFileW(path.c_str());
				set_last_error("flush auth temporary file failed gle=" + std::to_string(error));
				return false;
			}
			LARGE_INTEGER zero{};
			if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN)) {
				const DWORD error = GetLastError();
				CloseHandle(file);
				DeleteFileW(path.c_str());
				set_last_error("rewind auth temporary file failed gle=" + std::to_string(error));
				return false;
			}
			std::string verified;
			try { verified.resize(document.size()); } catch (...) {
				CloseHandle(file);
				DeleteFileW(path.c_str());
				set_last_error("auth temporary validation allocation failed");
				return false;
			}
			offset = 0;
			while (offset < verified.size()) {
				DWORD transferred = 0;
				const DWORD requested = static_cast<DWORD>((std::min)(verified.size() - offset,
					static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
				if (!ReadFile(file, verified.data() + offset, requested, &transferred, nullptr)
					|| transferred == 0) {
					const DWORD error = GetLastError();
					CloseHandle(file);
					DeleteFileW(path.c_str());
					set_last_error("validate auth temporary file failed gle=" + std::to_string(error));
					return false;
				}
				offset += transferred;
			}
			CloseHandle(file);
			if (verified != document) {
				DeleteFileW(path.c_str());
				set_last_error("auth temporary file verification mismatch");
				return false;
			}
			auth_map_t validation;
			if (!decode_document(verified, validation)) {
				DeleteFileW(path.c_str());
				return false;
			}
			return true;
		}

		bool replace_document(const std::filesystem::path& temporary,
			const std::filesystem::path& target)
		{
			const DWORD attributes = GetFileAttributesW(target.c_str());
			if (attributes != INVALID_FILE_ATTRIBUTES) {
				if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
					set_last_error("auth file reparse point rejected");
					return false;
				}
				if (!restrict_acl_to_current_user(target)) {
					set_last_error("restrict existing auth ACL failed gle="
						+ std::to_string(GetLastError()));
					return false;
				}
				if (!ReplaceFileW(target.c_str(), temporary.c_str(), nullptr,
						0, nullptr, nullptr)) {
					set_last_error("replace auth file failed gle=" + std::to_string(GetLastError()));
					return false;
				}
				return true;
			}
			const DWORD query_error = GetLastError();
			if (query_error != ERROR_FILE_NOT_FOUND && query_error != ERROR_PATH_NOT_FOUND) {
				set_last_error("query auth file failed gle=" + std::to_string(query_error));
				return false;
			}
			if (!MoveFileExW(temporary.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH)) {
				set_last_error("publish auth file failed gle=" + std::to_string(GetLastError()));
				return false;
			}
			return true;
		}

		bool save_map_locked(const auth_map_t& source,
			const std::function<bool()>& commit_guard = {})
		{
			if (source.size() > kMaximumProviders) {
				set_last_error("auth provider count exceeds the limit");
				return false;
			}
			for (const auto& [key, value] : source) {
				if (!valid_provider_key(key) || !valid_auth_info(value)) {
					set_last_error("auth provider entry violates schema or resource limits");
					return false;
				}
			}
			nlohmann::json data = nlohmann::json::object();
			try {
				for (const auto& [key, value] : source) data[key] = info_to_json(value);
			} catch (...) {
				set_last_error("auth payload serialization failed");
				return false;
			}
			std::string serialized;
			try { serialized = data.dump(); } catch (...) {
				set_last_error("auth payload serialization failed");
				return false;
			}
			if (serialized.empty() || serialized.size() > kMaximumStoreBytes) {
				if (!serialized.empty()) SecureZeroMemory(serialized.data(), serialized.size());
				set_last_error("auth payload size invalid");
				return false;
			}
			std::vector<unsigned char> cipher;
			if (!dpapi_protect(serialized, cipher)) {
				SecureZeroMemory(serialized.data(), serialized.size());
				set_last_error("CryptProtectData failed gle=" + std::to_string(GetLastError()));
				return false;
			}
			SecureZeroMemory(serialized.data(), serialized.size());
			nlohmann::json wrapper = nlohmann::json::object();
			wrapper["v"] = 1;
			wrapper["enc"] = base64_encode(cipher.data(), cipher.size());
			std::string document;
			try { document = wrapper.dump(); } catch (...) {
				set_last_error("auth wrapper serialization failed");
				return false;
			}
			if (document.empty() || document.size() > kMaximumStoreBytes) {
				set_last_error("auth document size invalid");
				return false;
			}
			const auto directory = data_directory();
			if (directory.empty()) return false;
			if (!ensure_directory(directory)) return false;
			if (!restrict_acl_to_current_user(directory)) {
				set_last_error("restrict auth directory ACL failed gle=" + std::to_string(GetLastError()));
				return false;
			}
			const auto target = data_path();
			if (target.empty()) return false;
			const auto temporary = temporary_path(target);
			if (!write_and_validate_temporary(temporary, document)) return false;
			temporary_file_guard_t temporary_guard(temporary);
			bool authorized = true;
			if (commit_guard) {
				try { authorized = commit_guard(); } catch (...) { authorized = false; }
			}
			if (!authorized) {
				set_last_error("credential commit cancelled");
				return false;
			}
			if (!replace_document(temporary, target)) return false;
			temporary_guard.release();
			set_last_error({});
			return true;
		}

		bool load_locked()
		{
			const auto path = data_path();
			if (path.empty()) return false;
			const DWORD attributes = GetFileAttributesW(path.c_str());
			if (attributes == INVALID_FILE_ATTRIBUTES) {
				const DWORD error = GetLastError();
				if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
					set_last_error("query auth file failed gle=" + std::to_string(error));
					return false;
				}
				cache().clear();
				loaded_flag() = true;
				set_last_error({});
				return true;
			}
			if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
				set_last_error("auth file reparse point rejected");
				return false;
			}
			if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
				set_last_error("auth file path is a directory");
				return false;
			}
			if (!restrict_acl_to_current_user(path)) {
				set_last_error("restrict existing auth ACL failed gle="
					+ std::to_string(GetLastError()));
				return false;
			}
			std::string raw;
			if (!read_file_bounded(path, raw)) return false;
			auth_map_t decoded;
			if (!decode_document(raw, decoded)) return false;
			cache().swap(decoded);
			loaded_flag() = true;
			set_last_error({});
			return true;
		}

		bool valid_provider_key(const std::string& key) noexcept
		{
			if (key.empty() || key.size() > 512) return false;
			for (unsigned char ch : key) {
				if (ch < 0x21 || ch == 0x7F || ch == '\\') return false;
			}
			return true;
		}

		bool set_locked(const std::string& provider_id, const auth_info_t& info,
			const std::function<bool()>& commit_guard)
		{
			const std::string key = normalize_provider(provider_id);
			if (!valid_provider_key(key) || !valid_auth_info(info)) {
				set_last_error("auth provider or credential kind invalid");
				return false;
			}
			if (!loaded_flag() && !load_locked()) return false;
			auth_map_t candidate;
			try {
				candidate = cache();
				candidate.erase(provider_id);
				candidate.erase(key + "/");
				candidate[key] = info;
				if (candidate.size() > kMaximumProviders) {
					set_last_error("auth provider count exceeds the limit");
					return false;
				}
			} catch (...) {
				set_last_error("auth credential staging failed");
				return false;
			}
			if (!save_map_locked(candidate, commit_guard)) return false;
			cache().swap(candidate);
			return true;
		}

	}

	bool load()
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		try {
			const bool loaded = load_locked();
			if (!loaded) {
				cache().clear();
				loaded_flag() = false;
			}
			return loaded;
		} catch (...) {
			cache().clear();
			loaded_flag() = false;
			try { set_last_error("auth store load exception"); } catch (...) {}
			return false;
		}
	}

	bool save()
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		try {
			if (!loaded_flag() && !load_locked()) return false;
			return save_map_locked(cache());
		} catch (...) {
			try { set_last_error("auth store save exception"); } catch (...) {}
			return false;
		}
	}

	bool get(const std::string& provider_id, auth_info_t& out)
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		out = auth_info_t{};
		try {
			if (!loaded_flag() && !load_locked()) return false;
			const std::string key = normalize_provider(provider_id);
			if (!valid_provider_key(key)) return false;
			auto it = cache().find(key);
			if (it == cache().end()) {
				it = cache().find(provider_id);
				if (it == cache().end()) return false;
			}
			out = it->second;
			return true;
		} catch (...) {
			out = auth_info_t{};
			try { set_last_error("auth store read exception"); } catch (...) {}
			return false;
		}
	}

	bool set(const std::string& provider_id, const auth_info_t& info)
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		try { return set_locked(provider_id, info, {}); } catch (...) {
			try { set_last_error("auth store write exception"); } catch (...) {}
			return false;
		}
	}

	bool set_if(const std::string& provider_id, const auth_info_t& info,
		const std::function<bool()>& commit_guard)
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		if (!commit_guard) {
			set_last_error("credential commit guard missing");
			return false;
		}
		try { return set_locked(provider_id, info, commit_guard); } catch (...) {
			try { set_last_error("guarded auth store write exception"); } catch (...) {}
			return false;
		}
	}

	bool remove(const std::string& provider_id)
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		try {
			if (!loaded_flag() && !load_locked()) return false;
			const std::string key = normalize_provider(provider_id);
			if (!valid_provider_key(key)) return false;
			auth_map_t candidate = cache();
			candidate.erase(provider_id);
			candidate.erase(key);
			candidate.erase(key + "/");
			if (!save_map_locked(candidate)) return false;
			cache().swap(candidate);
			return true;
		} catch (...) {
			try { set_last_error("auth store removal exception"); } catch (...) {}
			return false;
		}
	}

	bool all(std::vector<std::pair<std::string, auth_info_t>>& out)
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		out.clear();
		try {
			if (!loaded_flag() && !load_locked()) return false;
			out.reserve(cache().size());
			for (const auto& value : cache()) out.emplace_back(value.first, value.second);
			std::sort(out.begin(), out.end(), [](const auto& left, const auto& right) {
				return left.first < right.first;
			});
			return true;
		} catch (...) {
			out.clear();
			try { set_last_error("auth store enumeration exception"); } catch (...) {}
			return false;
		}
	}

	std::string last_error()
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		return last_error_ref();
	}

}
}
}

#endif
