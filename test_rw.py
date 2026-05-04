#!/usr/bin/env python3
"""Minimal test - just verify we can read and write the binary"""
import sys

binary_path = "temp/Payload/DumpApp.app/DumpApp"

try:
    # Read
    with open(binary_path, "rb") as f:
        data = bytearray(f.read())

    print(f"[+] Read {len(data)} bytes")

    # Write back unchanged
    with open(binary_path, "wb") as f:
        f.write(data)

    print("[+] Write successful")
    print("[+] Binary unchanged - this is just a test")

except Exception as e:
    print(f"[!] Error: {e}")
    sys.exit(1)
