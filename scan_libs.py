"""
scan_libs.py — Scan a directory for .lib/.exp files and flag suspicious (RAT-like) indicators.
Runs lib.exe /list, dumpbin.exe /EXPORTS, and dumpbin.exe /ALL against each file.
Results are written to a .txt file named after the scanned folder.
"""

import os
import sys
import math
import struct
import re
import subprocess
import glob
from pathlib import Path
from datetime import datetime
from collections import Counter

# ─── HARDCODED DIRECTORY TO SCAN ───
SCAN_DIR = r"C:\Users\ruar\Downloads\Cs2 Revenge"
# ────────────────────────────────────

# ─── VISUAL STUDIO TOOLCHAIN PATHS ───
# Auto-detected below; override here if needed.
_VS_PATHS = [
    r"C:\Program Files\Microsoft Visual Studio\2022\Community",
    r"C:\Program Files\Microsoft Visual Studio\2022\Professional",
    r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise",
    r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community",
    r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional",
    r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise",
]


def _find_tool(name: str) -> str | None:
    """Locate lib.exe or dumpbin.exe from a VS installation."""
    for vs in _VS_PATHS:
        pattern = os.path.join(vs, "VC", "Tools", "MSVC", "*", "bin", "Hostx64", "x64", name)
        hits = glob.glob(pattern)
        if hits:
            return hits[-1]  # latest MSVC version
    return None


LIB_EXE     = _find_tool("lib.exe")
DUMPBIN_EXE = _find_tool("dumpbin.exe")
# ──────────────────────────────────────

# Suspicious Win32 API names commonly abused by RATs / trojans
SUSPICIOUS_IMPORTS = {
    # ── Process / thread injection ──
    b"CreateRemoteThread", b"NtCreateThreadEx", b"RtlCreateUserThread",
    b"VirtualAllocEx", b"VirtualProtectEx", b"WriteProcessMemory",
    b"ReadProcessMemory", b"NtWriteVirtualMemory", b"NtReadVirtualMemory",
    b"OpenProcess", b"NtOpenProcess", b"ZwOpenProcess",
    b"QueueUserAPC", b"NtQueueApcThread", b"SetThreadContext",
    b"NtSetContextThread", b"ResumeThread",

    # ── Code loading / reflective loading ──
    b"LoadLibraryA", b"LoadLibraryW", b"LoadLibraryExA", b"LoadLibraryExW",
    b"GetProcAddress", b"LdrLoadDll", b"LdrGetProcedureAddress",
    b"NtMapViewOfSection", b"NtUnmapViewOfSection",

    # ── Networking (C2 channels) ──
    b"WSAStartup", b"socket", b"connect", b"send", b"recv",
    b"WSASend", b"WSARecv", b"WSASocketA", b"WSASocketW",
    b"InternetOpenA", b"InternetOpenW", b"InternetConnectA", b"InternetConnectW",
    b"HttpOpenRequestA", b"HttpOpenRequestW", b"HttpSendRequestA", b"HttpSendRequestW",
    b"InternetOpenUrlA", b"InternetOpenUrlW", b"InternetReadFile",
    b"URLDownloadToFileA", b"URLDownloadToFileW",
    b"WinHttpOpen", b"WinHttpConnect", b"WinHttpSendRequest",

    # ── Keylogging / input capture ──
    b"SetWindowsHookExA", b"SetWindowsHookExW",
    b"GetAsyncKeyState", b"GetKeyState", b"GetKeyboardState",
    b"RegisterRawInputDevices", b"GetRawInputData",

    # ── Screen / clipboard capture ──
    b"BitBlt", b"GetDC", b"GetDesktopWindow", b"CreateCompatibleDC",
    b"OpenClipboard", b"GetClipboardData",

    # ── Registry persistence ──
    b"RegSetValueExA", b"RegSetValueExW",
    b"RegCreateKeyExA", b"RegCreateKeyExW",

    # ── File-system stealth / dropper ──
    b"CreateFileA", b"CreateFileW", b"DeleteFileA", b"DeleteFileW",
    b"MoveFileA", b"MoveFileW", b"CopyFileA", b"CopyFileW",
    b"NtCreateFile", b"NtDeleteFile",

    # ── Privilege escalation / token manipulation ──
    b"AdjustTokenPrivileges", b"OpenProcessToken",
    b"LookupPrivilegeValueA", b"LookupPrivilegeValueW",
    b"ImpersonateLoggedOnUser", b"DuplicateTokenEx",

    # ── Anti-analysis / evasion ──
    b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent",
    b"NtQueryInformationProcess", b"NtSetInformationThread",
    b"VirtualProtect", b"NtProtectVirtualMemory",

    # ── Shellcode / manual mapping helpers ──
    b"NtAllocateVirtualMemory", b"NtFreeVirtualMemory",
    b"RtlMoveMemory", b"RtlCopyMemory", b"memcpy",

    # ── Service / task persistence ──
    b"CreateServiceA", b"CreateServiceW",
    b"StartServiceA", b"StartServiceW",
    b"OpenSCManagerA", b"OpenSCManagerW",

    # ── Crypto (potential data exfiltration encryption) ──
    b"CryptEncrypt", b"CryptDecrypt", b"CryptAcquireContextA",
    b"BCryptEncrypt", b"BCryptDecrypt",
}

# Suspicious plaintext strings that may appear in RAT payloads
SUSPICIOUS_STRINGS = [
    # C2 / exfiltration keywords
    rb"cmd\.exe", rb"powershell", rb"command\s*&\s*control",
    rb"reverse.?shell", rb"bind.?shell", rb"rat\b", rb"trojan",
    rb"keylog", rb"screenshot", rb"screen.?capture",
    rb"webcam", rb"microphone", rb"clipboard",
    rb"exfiltrat", rb"upload.?file", rb"download.?file",
    rb"remote.?desktop", rb"vnc", rb"back.?door", rb"rootkit",
    rb"shellcode", rb"inject", rb"payload",
    rb"persistence", rb"startup.?folder", rb"run.?key",
    rb"bot.?net", rb"ddos", rb"flood",
    rb"credential", rb"password", rb"steal",
    rb"discord.?webhook", rb"telegram.?bot", rb"ngrok",
    rb"pastebin\.com", rb"hastebin", rb"raw\.githubusercontent",
    rb"185\.\d+\.\d+\.\d+", rb"194\.\d+\.\d+\.\d+",  # common malicious IP ranges
    rb"\\\\\.\\\\pipe\\\\",  # named pipe (C2 channel)
]

# Severity levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"
SEVERITY_INFO     = "INFO"


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0.0 – 8.0)."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_printable_strings(data: bytes, min_length: int = 4):
    """Yield ASCII strings of at least `min_length` printable characters."""
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    for match in pattern.finditer(data):
        yield match.group()


def check_suspicious_imports(data: bytes):
    """Return list of (import_name, severity) tuples found in binary data."""
    hits = []
    for imp in SUSPICIOUS_IMPORTS:
        if imp in data:
            hits.append(imp.decode("ascii", errors="replace"))
    return hits


def check_suspicious_strings(data: bytes):
    """Return list of (pattern_desc, matched_text, severity) tuples."""
    hits = []
    for pat in SUSPICIOUS_STRINGS:
        for m in re.finditer(pat, data, re.IGNORECASE):
            hits.append((pat.pattern if hasattr(pat, "pattern") else pat.decode("ascii", errors="replace"),
                         m.group().decode("ascii", errors="replace")))
    return hits


def classify_risk(import_hits, string_hits, entropy):
    """Return an overall risk verdict based on aggregated findings."""
    score = 0
    # Network + injection combo is a strong RAT signal
    network_kw = {"WSAStartup", "socket", "connect", "send", "recv",
                  "InternetOpenA", "InternetOpenW", "InternetConnectA",
                  "HttpSendRequestA", "HttpSendRequestW", "WinHttpOpen",
                  "URLDownloadToFileA", "URLDownloadToFileW"}
    inject_kw = {"CreateRemoteThread", "NtCreateThreadEx", "WriteProcessMemory",
                 "VirtualAllocEx", "QueueUserAPC", "NtMapViewOfSection"}

    found_network = bool(network_kw & set(import_hits))
    found_inject  = bool(inject_kw & set(import_hits))

    if found_network and found_inject:
        score += 40
    elif found_network:
        score += 15
    elif found_inject:
        score += 20

    score += min(len(import_hits) * 2, 30)
    score += min(len(string_hits) * 5, 30)

    if entropy > 7.5:
        score += 10  # likely packed / encrypted

    if score >= 60:
        return SEVERITY_CRITICAL, score
    elif score >= 40:
        return SEVERITY_HIGH, score
    elif score >= 20:
        return SEVERITY_MEDIUM, score
    elif score >= 5:
        return SEVERITY_LOW, score
    else:
        return SEVERITY_INFO, score


def run_tool(exe_path: str | None, args: list[str], filepath: str) -> str:
    """Run an external tool and return its stdout, or an error message."""
    if exe_path is None:
        return f"[TOOL NOT FOUND — skipped]"
    cmd = [exe_path] + args + [filepath]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = proc.stdout.strip()
        if proc.returncode != 0 and proc.stderr.strip():
            output += "\n[stderr] " + proc.stderr.strip()
        return output if output else "[no output]"
    except subprocess.TimeoutExpired:
        return "[TIMEOUT — tool took >30s]"
    except Exception as e:
        return f"[ERROR running tool] {e}"


def scan_file(filepath: str):
    """Scan a single .lib or .exp file and return a findings dict."""
    result = {
        "path": filepath,
        "size": 0,
        "entropy": 0.0,
        "import_hits": [],
        "string_hits": [],
        "severity": SEVERITY_INFO,
        "score": 0,
        "error": None,
        "lib_list": "",
        "dumpbin_exports": "",
        "dumpbin_all": "",
    }
    try:
        data = Path(filepath).read_bytes()
        result["size"] = len(data)
        result["entropy"] = round(shannon_entropy(data), 4)
        result["import_hits"] = check_suspicious_imports(data)
        result["string_hits"] = check_suspicious_strings(data)

        # ── Run VS toolchain ──
        is_lib = filepath.lower().endswith(".lib")
        if is_lib:
            result["lib_list"] = run_tool(LIB_EXE, ["/list"], filepath)
        result["dumpbin_exports"] = run_tool(DUMPBIN_EXE, ["/EXPORTS"], filepath)
        result["dumpbin_all"]     = run_tool(DUMPBIN_EXE, ["/ALL"], filepath)

        # Also scan the dumpbin text output for suspicious symbols
        combined_tool_text = (result["dumpbin_exports"] + "\n" + result["dumpbin_all"]).encode("utf-8", errors="replace")
        tool_import_hits = check_suspicious_imports(combined_tool_text)
        tool_string_hits = check_suspicious_strings(combined_tool_text)
        # Merge (deduplicate imports)
        existing_imports = set(result["import_hits"])
        for h in tool_import_hits:
            if h not in existing_imports:
                result["import_hits"].append(h)
                existing_imports.add(h)
        existing_strings = {(p, m) for p, m in result["string_hits"]}
        for h in tool_string_hits:
            if h not in existing_strings:
                result["string_hits"].append(h)
                existing_strings.add(h)

        sev, sc = classify_risk(result["import_hits"], result["string_hits"], result["entropy"])
        result["severity"] = sev
        result["score"] = sc
    except Exception as e:
        result["error"] = str(e)
    return result


def format_report(results, scan_dir, elapsed):
    """Build a human-readable text report."""
    lines = []
    border = "=" * 90
    lines.append(border)
    lines.append("  LIB / EXP  MALWARE  SCANNER  —  RAT  INDICATOR  REPORT")
    lines.append(border)
    lines.append(f"  Scanned directory : {scan_dir}")
    lines.append(f"  Date              : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Files analysed    : {len(results)}")
    lines.append(f"  Elapsed           : {elapsed:.2f}s")
    lines.append(f"  lib.exe           : {LIB_EXE or 'NOT FOUND'}")
    lines.append(f"  dumpbin.exe       : {DUMPBIN_EXE or 'NOT FOUND'}")
    lines.append(border)
    lines.append("")

    # Summary table
    severity_order = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]
    counts = Counter(r["severity"] for r in results)
    lines.append("  ┌─────────────────────────────────────────────────┐")
    lines.append("  │              S U M M A R Y                      │")
    lines.append("  ├──────────────┬──────────────────────────────────┤")
    for sev in severity_order:
        c = counts.get(sev, 0)
        flag = " <<<" if sev in (SEVERITY_CRITICAL, SEVERITY_HIGH) and c > 0 else ""
        lines.append(f"  │ {sev:<12} │  {c:>4} file(s){flag:<24}│")
    lines.append("  └──────────────┴──────────────────────────────────┘")
    lines.append("")

    # Per-file details (sorted by score descending)
    results_sorted = sorted(results, key=lambda r: r["score"], reverse=True)
    for i, r in enumerate(results_sorted, 1):
        lines.append(f"─── File #{i}  [{r['severity']}]  (score {r['score']}) {'─' * 40}")
        lines.append(f"  Path    : {r['path']}")
        lines.append(f"  Size    : {r['size']:,} bytes")
        lines.append(f"  Entropy : {r['entropy']}  {'(HIGH — possible packing/encryption)' if r['entropy'] > 7.0 else ''}")

        if r["error"]:
            lines.append(f"  ERROR   : {r['error']}")
            lines.append("")
            continue

        if r["import_hits"]:
            lines.append(f"  Suspicious imports ({len(r['import_hits'])}):")
            for imp in sorted(r["import_hits"]):
                lines.append(f"      • {imp}")
        else:
            lines.append("  Suspicious imports : none")

        if r["string_hits"]:
            lines.append(f"  Suspicious strings ({len(r['string_hits'])}):")
            for pat, matched in r["string_hits"]:
                lines.append(f"      • pattern: {pat}")
                lines.append(f"        matched: {matched}")
        else:
            lines.append("  Suspicious strings : none")

        # ── Toolchain output sections ──
        lines.append("")

        if r["path"].lower().endswith(".lib") and r.get("lib_list"):
            lines.append(f"  ┌── lib.exe /list ──────────────────────────────────────────────")
            for ln in r["lib_list"].splitlines():
                lines.append(f"  │ {ln}")
            lines.append(f"  └──────────────────────────────────────────────────────────────")
            lines.append("")

        if r.get("dumpbin_exports"):
            lines.append(f"  ┌── dumpbin.exe /EXPORTS ───────────────────────────────────────")
            for ln in r["dumpbin_exports"].splitlines():
                lines.append(f"  │ {ln}")
            lines.append(f"  └──────────────────────────────────────────────────────────────")
            lines.append("")

        if r.get("dumpbin_all"):
            lines.append(f"  ┌── dumpbin.exe /ALL ───────────────────────────────────────────")
            for ln in r["dumpbin_all"].splitlines():
                lines.append(f"  │ {ln}")
            lines.append(f"  └──────────────────────────────────────────────────────────────")

        lines.append("")

    lines.append(border)
    if counts.get(SEVERITY_CRITICAL, 0) or counts.get(SEVERITY_HIGH, 0):
        lines.append("  !! FILES WITH CRITICAL / HIGH SEVERITY SHOULD BE TREATED AS POTENTIALLY MALICIOUS !!")
        lines.append("  !! DO NOT EXECUTE OR LINK AGAINST THEM WITHOUT FURTHER MANUAL ANALYSIS             !!")
    else:
        lines.append("  No critical or high-severity indicators detected.")
    lines.append(border)
    return "\n".join(lines)


def main():
    import time

    scan_path = Path(SCAN_DIR).resolve()
    if not scan_path.is_dir():
        print(f"[!] Directory does not exist: {scan_path}")
        sys.exit(1)

    folder_name = scan_path.name
    output_file = scan_path.parent / f"{folder_name}.txt"

    print(f"[*] Scanning: {scan_path}")
    print(f"[*] Looking for .lib and .exp files...")

    targets = []
    for root, _dirs, files in os.walk(scan_path):
        for fname in files:
            if fname.lower().endswith((".lib", ".exp")):
                targets.append(os.path.join(root, fname))

    if not targets:
        print("[!] No .lib or .exp files found.")
        sys.exit(0)

    print(f"[*] Found {len(targets)} file(s). Analysing...")

    t0 = time.time()
    results = [scan_file(fp) for fp in targets]
    elapsed = time.time() - t0

    report = format_report(results, str(scan_path), elapsed)

    output_file.write_text(report, encoding="utf-8")
    print(report)
    print(f"\n[*] Full report saved to: {output_file}")


if __name__ == "__main__":
    main()
