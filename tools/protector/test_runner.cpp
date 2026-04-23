#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

struct run_result_t {
    DWORD exit_code;
    std::string stdout_text;
    bool launched;
};

run_result_t run_capture(const std::string& cmdline) {
    run_result_t r{};
    r.launched = false;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE rd = nullptr;
    HANDLE wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) { return r; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

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
        r.stdout_text.append(buf, buf + n);
    }
    CloseHandle(rd);

    WaitForSingleObject(pi.hProcess, 30000);
    GetExitCodeProcess(pi.hProcess, &r.exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return r;
}

bool file_exists(const char* p) {
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr, "Usage: aida_protector_test <protector.exe> <input.exe> <output.exe>\n");
        return 1;
    }
    const char* protector = argv[1];
    const char* input = argv[2];
    const char* output = argv[3];

    if (!file_exists(protector)) { std::fprintf(stderr, "[!] missing %s\n", protector); return 2; }
    if (!file_exists(input)) { std::fprintf(stderr, "[!] missing %s\n", input); return 2; }

    {
        run_result_t baseline = run_capture(std::string("\"") + input + "\"");
        if (!baseline.launched) {
            std::fprintf(stderr, "[!] failed to launch baseline input\n");
            return 3;
        }
        std::printf("[baseline] exit=%lu stdout=%s\n",
                    baseline.exit_code, baseline.stdout_text.c_str());
        if (baseline.exit_code != 42 || baseline.stdout_text.find("PASS") == std::string::npos) {
            std::fprintf(stderr, "[!] baseline test_payload behaved unexpectedly\n");
            return 3;
        }
    }

    DeleteFileA(output);
    std::string cmd = std::string("\"") + protector + "\""
                      + " -i \"" + input + "\""
                      + " -o \"" + output + "\""
                      + " --all --embed-watermark"
                      + " --watermark deadbeefcafebabe0123456789abcdef"
                      + " --tamper-level 1"
                      + " --seed 0xA1B2C3D4E5F60718";
    std::printf("[protect] %s\n", cmd.c_str());
    run_result_t pr = run_capture(cmd);
    if (!pr.launched) { std::fprintf(stderr, "[!] failed to launch protector\n"); return 3; }
    std::printf("[protect] exit=%lu\n%s\n", pr.exit_code, pr.stdout_text.c_str());
    if (pr.exit_code != 0) { std::fprintf(stderr, "[!] protect failed\n"); return 3; }
    if (!file_exists(output)) { std::fprintf(stderr, "[!] protected output missing\n"); return 3; }

    run_result_t out = run_capture(std::string("\"") + output + "\"");
    std::printf("[run] exit=%lu stdout=%s\n", out.exit_code, out.stdout_text.c_str());

    bool stdout_ok = out.stdout_text.find("PASS") != std::string::npos;
    bool exit_ok = (out.exit_code == 42);

    int rc = 0;
    if (!exit_ok) { std::fprintf(stderr, "[FAIL] exit code %lu (expected 42)\n", out.exit_code); rc = 1; }
    if (!stdout_ok) { std::fprintf(stderr, "[FAIL] stdout missing PASS marker\n"); rc = 1; }
    if (rc == 0) { std::printf("[OK] round-trip PASS\n"); }
    return rc;
}
