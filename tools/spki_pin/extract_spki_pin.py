import argparse
import hashlib
import socket
import ssl
import subprocess
import sys


def extract_via_python(host, port):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)
    if not der_cert:
        raise RuntimeError("no peer certificate returned by " + host)
    cert = ssl.DER_cert_to_PEM_cert(der_cert)
    p = subprocess.run(
        ["openssl", "x509", "-pubkey", "-noout"],
        input=cert.encode("ascii"),
        capture_output=True,
        check=True,
    )
    pubkey_pem = p.stdout
    p = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=pubkey_pem,
        capture_output=True,
        check=True,
    )
    pubkey_der = p.stdout
    digest = hashlib.sha256(pubkey_der).digest()
    return digest


def extract_via_openssl(host, port):
    cmd = (
        "openssl s_client -connect {h}:{p} -servername {h} </dev/null 2>/dev/null"
        " | openssl x509 -pubkey -noout"
        " | openssl pkey -pubin -outform DER"
        " | openssl dgst -sha256 -binary"
    ).format(h=host, p=port)
    p = subprocess.run(["bash", "-c", cmd], capture_output=True)
    if p.returncode != 0 or len(p.stdout) != 32:
        raise RuntimeError("openssl pipeline failed")
    return p.stdout


def main():
    parser = argparse.ArgumentParser(description="Extract SPKI SHA-256 pin from a TLS host.")
    parser.add_argument("--host", default="aidapro.net")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--format", choices=["hex", "c-array"], default="hex")
    parser.add_argument("--use-shell-openssl", action="store_true",
                        help="prefer the shell s_client pipeline (Linux/macOS)")
    args = parser.parse_args()

    try:
        if args.use_shell_openssl:
            digest = extract_via_openssl(args.host, args.port)
        else:
            digest = extract_via_python(args.host, args.port)
    except Exception as exc:
        print("ERROR: " + repr(exc), file=sys.stderr)
        sys.exit(1)

    if args.format == "hex":
        print(digest.hex())
        return

    formatted = ", ".join("0x{:02x}".format(b) for b in digest)
    print("static constexpr uint8_t k_baked_spki_pin_primary[32] = {")
    line = ""
    for i, byte in enumerate(digest):
        if i % 8 == 0 and i != 0:
            print("    " + line.rstrip())
            line = ""
        line += "0x{:02x}, ".format(byte)
    if line:
        print("    " + line.rstrip())
    print("};")


if __name__ == "__main__":
    main()
