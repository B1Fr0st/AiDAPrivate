import os
import re

# Hardcoded target directory
TARGET_DIR = r"C:\Users\ruar\Downloads\Rynz Ext\others"

def extract_bytes_from_header(header_filename, output_filename):
    header_path = os.path.join(TARGET_DIR, header_filename)
    output_path = os.path.join(TARGET_DIR, output_filename)

    if not os.path.exists(header_path):
        print(f"[-] Error: {header_path} not found.")
        return

    try:
        with open(header_path, 'r') as f:
            content = f.read()

        # Regex to find all hex byte patterns (e.g., 0x4D, 0x5A, 0x00)
        hex_values = re.findall(r'0x[0-9a-fA-F]{1,2}', content)

        if not hex_values:
            print(f"[-] No byte array patterns found in {header_filename}.")
            return

        # Convert the list of hex strings into a proper byte array
        byte_data = bytearray(int(val, 16) for val in hex_values)

        # Write the binary data to the output file
        with open(output_path, 'wb') as f:
            f.write(byte_data)

        print(f"[+] Successfully converted: {header_filename} -> {output_filename} ({len(byte_data)} bytes)")

    except Exception as e:
        print(f"[-] An error occurred while processing {header_filename}: {e}")

def main():
    if not os.path.exists(TARGET_DIR):
        print(f"[-] The directory {TARGET_DIR} does not exist.")
        return

    print(f"Scanning directory: {TARGET_DIR}...\n")

    # Convert driver.h to driver.sys
    extract_bytes_from_header("driver.h", "driver.sys")

    # Convert mapper.h to mapper.exe
    extract_bytes_from_header("mapper.h", "mapper.exe")

if __name__ == "__main__":
    main()