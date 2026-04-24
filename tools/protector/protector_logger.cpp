

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "verify_api.hpp"

#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct options_t {
    std::string input;
    std::string output;
    std::string protector_path;
    std::string protected_path;
    uint64_t    seed = 0;
    bool        seed_provided = false;
    bool        keep_protected = false;
};

std::string path_dir(const std::string& p) {
    size_t slash = p.find_last_of("\\/");
    if (slash == std::string::npos) { return "."; }
    return p.substr(0, slash);
}
std::string path_base(const std::string& p) {
    size_t slash = p.find_last_of("\\/");
    return (slash == std::string::npos) ? p : p.substr(slash + 1);
}
std::string path_stem(const std::string& base) {
    size_t dot = base.find_last_of('.');
    return (dot == std::string::npos) ? base : base.substr(0, dot);
}

bool file_exists(const std::string& p) {
    DWORD a = GetFileAttributesA(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

std::string self_dir() {
    char buf[MAX_PATH]{};
    DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (n == 0) { return "."; }
    std::string s(buf, n);
    return path_dir(s);
}

bool read_all(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { return false; }
    f.seekg(0, std::ios::end);
    std::streampos sz = f.tellg();
    if (sz < 0) { return false; }
    out.resize(static_cast<size_t>(sz));
    f.seekg(0, std::ios::beg);
    if (!out.empty()) { f.read(reinterpret_cast<char*>(out.data()), out.size()); }
    return f.good() || f.eof();
}

std::string sha256_hex(const std::vector<uint8_t>& data) {
    uint8_t h[32]{};
    protector::sha256_detail::sha256(data.empty() ? reinterpret_cast<const uint8_t*>("") : data.data(),
                                     data.size(), h);
    static const char hex[] = "0123456789abcdef";
    std::string s(64, '0');
    for (int i = 0; i < 32; ++i) {
        s[2 * i + 0] = hex[(h[i] >> 4) & 0xF];
        s[2 * i + 1] = hex[h[i] & 0xF];
    }
    return s;
}

struct spawn_result_t {
    bool  launched = false;
    DWORD exit_code = 0xFFFFFFFFu;
    std::string captured;
};

spawn_result_t run_capture(const std::string& cmdline, DWORD timeout_ms) {
    spawn_result_t r{};

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) { return r; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError  = wr;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::string cmd = cmdline;
    BOOL ok = CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wr);
    if (!ok) { CloseHandle(rd); return r; }
    r.launched = true;

    char buf[4096];
    DWORD n = 0;
    while (ReadFile(rd, buf, sizeof(buf), &n, nullptr) && n > 0) {
        r.captured.append(buf, buf + n);
    }
    CloseHandle(rd);

    WaitForSingleObject(pi.hProcess, timeout_ms);
    GetExitCodeProcess(pi.hProcess, &r.exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return r;
}

void usage(FILE* f) {
    std::fprintf(f,
        "Usage: aida_protector_logger --input <exe> [--output <report.json>]\n"
        "                             [--protector <aida_protector.exe>]\n"
        "                             [--protected <out.exe>]\n"
        "                             [--seed 0xA11CE] [--keep]\n");
}

int parse_opts(int argc, char** argv, options_t& o) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: %s requires a value\n", name);
                std::exit(1);
            }
            return argv[++i];
        };
        if (a == "--input" || a == "-i") { o.input = need("--input"); }
        else if (a == "--output" || a == "-o") { o.output = need("--output"); }
        else if (a == "--protector") { o.protector_path = need("--protector"); }
        else if (a == "--protected") { o.protected_path = need("--protected"); }
        else if (a == "--seed") {
            std::string v = need("--seed");
            o.seed = std::strtoull(v.c_str(), nullptr, 0);
            o.seed_provided = true;
        }
        else if (a == "--keep") { o.keep_protected = true; }
        else if (a == "-h" || a == "--help") { usage(stdout); std::exit(0); }
        else {
            std::fprintf(stderr, "Error: unknown arg %s\n", a.c_str());
            usage(stderr);
            return 1;
        }
    }
    if (o.input.empty()) { usage(stderr); return 1; }
    return 0;
}

std::string quote(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (char c : s) {
        if (c == '\\' || c == '"') { out.push_back('\\'); out.push_back(c); }
        else if (c == '\n') { out += "\\n"; }
        else if (c == '\r') { out += "\\r"; }
        else if (c == '\t') { out += "\\t"; }
        else if (static_cast<unsigned char>(c) < 0x20) {
            char b[8]; std::snprintf(b, sizeof(b), "\\u%04X", static_cast<unsigned>(c) & 0xFFu);
            out += b;
        }
        else { out.push_back(c); }
    }
    out.push_back('"');
    return out;
}

std::string phase_name(int bit) {
    switch (bit) {
        case 0: return "polymorphic";
        case 1: return "merge";
        case 2: return "flatten";
        case 3: return "deep_steal";
        case 4: return "ghost_veh";
        case 5: return "rdtsc";
        case 6: return "opaque";
        case 7: return "ast_poison";
        case 8: return "symexec_bombs";
        case 9: return "llm_poison";
        case 10: return "jit_enclave";
        default: return "bit" + std::to_string(bit);
    }
}

}

int main(int argc, char** argv) {
    options_t opt;
    if (int rc = parse_opts(argc, argv, opt); rc != 0) { return rc; }

    if (!file_exists(opt.input)) {
        std::fprintf(stderr, "[!] input not found: %s\n", opt.input.c_str());
        return 2;
    }
    if (opt.protector_path.empty()) {
        opt.protector_path = self_dir() + "\\aida_protector.exe";
    }
    if (!file_exists(opt.protector_path)) {
        std::fprintf(stderr, "[!] protector not found: %s\n", opt.protector_path.c_str());
        return 3;
    }
    if (opt.protected_path.empty()) {
        std::string dir  = path_dir(opt.input);
        std::string stem = path_stem(path_base(opt.input));
        opt.protected_path = dir + "\\" + stem + "_protected.exe";
    }


    std::ostringstream cmd;
    cmd << "\"" << opt.protector_path << "\""
        << " --input \""  << opt.input << "\""
        << " --output \"" << opt.protected_path << "\""
        << " --all --embed-watermark"
        << " --watermark A1DA10C6E12A3B4C5D6E7F8091A2B3C4";
    if (opt.seed_provided) {
        char sb[32]; std::snprintf(sb, sizeof(sb), " --seed 0x%llX",
                                   static_cast<unsigned long long>(opt.seed));
        cmd << sb;
    }

    auto t0 = std::chrono::steady_clock::now();
    spawn_result_t pr = run_capture(cmd.str(), 120000);
    auto t1 = std::chrono::steady_clock::now();
    long long protect_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    if (!pr.launched) {
        std::fprintf(stderr, "[!] failed to spawn protector\n");
        return 4;
    }


    std::vector<uint8_t> in_bytes, out_bytes;
    read_all(opt.input, in_bytes);
    bool have_output = file_exists(opt.protected_path);
    if (have_output) { read_all(opt.protected_path, out_bytes); }

    std::string in_sha  = sha256_hex(in_bytes);
    std::string out_sha = have_output ? sha256_hex(out_bytes) : std::string(64, '0');


    verifier::verify_report_t rep;
    auto v0 = std::chrono::steady_clock::now();
    if (have_output) { rep = verifier::verify_report(opt.protected_path); }
    auto v1 = std::chrono::steady_clock::now();
    long long verify_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(v1 - v0).count();


    uint32_t pf = rep.phase_flags & 0x7FFu;
    int phases_fired = 0;
    std::vector<std::string> names;
    for (int i = 0; i < 11; ++i) {
        if (pf & (1u << i)) { ++phases_fired; names.push_back(phase_name(i)); }
    }


    std::ostringstream j;
    j << "{\n";
    j << "  \"tool\": \"aida_protector_logger\",\n";
    j << "  \"version\": 1,\n";
    j << "  \"input\": {\"path\": "   << quote(opt.input)
      << ", \"size\": "  << in_bytes.size()
      << ", \"sha256\": " << quote(in_sha) << "},\n";
    j << "  \"output\": {\"path\": "  << quote(opt.protected_path)
      << ", \"size\": "  << out_bytes.size()
      << ", \"sha256\": " << quote(out_sha) << "},\n";
    j << "  \"timings_ms\": {\"protect\": " << protect_ms
      << ", \"verify\": " << verify_ms << "},\n";
    j << "  \"protect_exit_code\": " << pr.exit_code << ",\n";
    j << "  \"phase_flags\": " << (rep.phase_flags) << ",\n";
    j << "  \"phases_fired\": {\"count\": " << phases_fired
      << ", \"total\": 11, \"names\": [";
    for (size_t i = 0; i < names.size(); ++i) {
        if (i) { j << ", "; }
        j << quote(names[i]);
    }
    j << "]},\n";
    j << "  \"probes\": [\n";
    for (size_t i = 0; i < rep.probes.size(); ++i) {
        const auto& p = rep.probes[i];
        j << "    {\"id\": " << quote(p.id)
          << ", \"desc\": "  << quote(p.desc ? p.desc : "")
          << ", \"pass\": "  << (p.pass ? "true" : "false")
          << ", \"detail\": " << quote(p.detail) << "}";
        if (i + 1 < rep.probes.size()) { j << ","; }
        j << "\n";
    }
    j << "  ],\n";
    j << "  \"probes_passed\": " << rep.passed << ",\n";
    j << "  \"probes_total\": "  << rep.total  << "\n";
    j << "}\n";

    std::string json_text = j.str();
    if (opt.output.empty()) {
        std::fwrite(json_text.data(), 1, json_text.size(), stdout);
    } else {
        std::ofstream f(opt.output, std::ios::binary);
        if (!f) {
            std::fprintf(stderr, "[!] cannot write %s\n", opt.output.c_str());
            std::fwrite(json_text.data(), 1, json_text.size(), stdout);
            return 5;
        }
        f.write(json_text.data(), json_text.size());
        std::fprintf(stderr, "[+] wrote %s (%zu bytes)\n",
                     opt.output.c_str(), json_text.size());
        std::fwrite(json_text.data(), 1, json_text.size(), stdout);
    }

    if (!opt.keep_protected && have_output) {

    }

    if (!have_output) { return 6; }
    if (pr.exit_code != 0u) { return 7; }
    return (rep.passed == rep.total) ? 0 : 8;
}
