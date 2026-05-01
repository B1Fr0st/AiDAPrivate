import re
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(SCRIPT_DIR, "whoswho_encrypted.h")

with open(TARGET, "r", encoding="utf-8") as f:
    text = f.read()

m = re.search(r"(g_whoswho_ciphertext\[\d+\] = \{)([^}]+)(\})", text, re.DOTALL)
if not m:
    print("[!] could not find g_whoswho_ciphertext array")
    sys.exit(1)

body = m.group(2)
matches = list(re.finditer(r"0x([0-9A-Fa-f]{2})", body))
if not matches:
    print("[!] no bytes found")
    sys.exit(1)

target = matches[100]
orig = int(target.group(1), 16)
flipped = orig ^ 0x01
new_body = body[:target.start()] + f"0x{flipped:02X}" + body[target.end():]
new_text = text[:m.start()] + m.group(1) + new_body + m.group(3) + text[m.end():]

with open(TARGET, "w", encoding="utf-8", newline="\n") as f:
    f.write(new_text)

print(f"[+] flipped byte 100 in g_whoswho_ciphertext: 0x{orig:02X} -> 0x{flipped:02X}")
