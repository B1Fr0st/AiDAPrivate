#pragma once

#include <string>
#include <cstdint>

namespace aida::tls_exporter
{
    inline constexpr const char* kHeaderName   = "X-TLS-Exporter";
    inline constexpr const char* kExporterLabel = "aida/v1";
    inline constexpr uint32_t     kExporterLen  = 32;

    std::string compute_header_value_schannel(void* schannel_ctx) noexcept;
    std::string derive_expected(const std::string& secret_hex) noexcept;
}
