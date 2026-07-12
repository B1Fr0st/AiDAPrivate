#!/usr/bin/env python3
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "standalone")

SENSITIVE_PATTERNS = [
    re.compile(r'\b(Nt|Zw|Ldr|Mm|Ke|Ps|Ob|Rtl)[A-Z]\w*\b'),
    re.compile(r'\b\w+\.dll\b', re.IGNORECASE),
    re.compile(r'https?://', re.IGNORECASE),
    re.compile(r'/api/', re.IGNORECASE),
    re.compile(r'\b(dump|minidump|dbghelp)\b', re.IGNORECASE),
]

OBF_MACROS = ('OBFSTR', 'WOBFSTR', 'OBFSTR_C', 'WOBFSTR_C')

STRING_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
WIDE_STRING_LITERAL_RE = re.compile(r'L"((?:\\.|[^"\\])*)"')
OBF_WRAP_RE = re.compile(r'\b(?:' + '|'.join(OBF_MACROS) + r')\s*\(')

def line_has_obf_wrap(line, match_start):
    paren_depth = 0
    for i in range(match_start - 1, -1, -1):
        ch = line[i]
        if ch == ')':
            paren_depth += 1
        elif ch == '(':
            if paren_depth == 0:
                before = line[:i].rstrip()
                for macro in OBF_MACROS:
                    if before.endswith(macro):
                        return True
                return False
            paren_depth -= 1
    return False

def is_in_obf_call(line, match_start):
    if line_has_obf_wrap(line, match_start):
        return True
    for macro in OBF_MACROS:
        if macro + '(' in line:
            return True
    return False

def audit_file(filepath):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except Exception:
        return findings

    for lineno, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith('#'):
            continue

        for regex in (STRING_LITERAL_RE, WIDE_STRING_LITERAL_RE):
            for m in regex.finditer(line):
                content = m.group(1)
                if not content or len(content) < 2:
                    continue

                matched = False
                for pat in SENSITIVE_PATTERNS:
                    if pat.search(content):
                        matched = True
                        break
                if not matched:
                    continue

                if is_in_obf_call(line, m.start()):
                    continue

                findings.append((filepath, lineno, line.rstrip()))
    return findings

def main():
    all_findings = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        for fn in filenames:
            if fn.endswith(('.hpp', '.cpp', '.h', '.c')):
                fp = os.path.join(dirpath, fn)
                all_findings.extend(audit_file(fp))

    if not all_findings:
        print("No unobfuscated sensitive string literals found.")
        return 0

    for fp, lineno, content in all_findings:
        rel = os.path.relpath(fp, os.path.dirname(ROOT))
        print(f"{rel}:{lineno}: {content}")
    print(f"\nTotal findings: {len(all_findings)}")
    return 1

if __name__ == '__main__':
    sys.exit(main())
