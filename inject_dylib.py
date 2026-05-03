#!/usr/bin/env python3
import struct
import sys

def inject_dylib(binary_path, dylib_path):
    with open(binary_path, "rb") as f:
        data = bytearray(f.read())

    # Find ARM64 slice
    magic = struct.unpack("<I", data[0:4])[0]
    if magic == 0xCAFEBABE:  # FAT binary
        narch = struct.unpack(">I", data[4:8])[0]
        offset = None
        for i in range(narch):
            base = 8 + i * 20
            cpu_type = struct.unpack(">I", data[base:base+4])[0]
            if cpu_type == 0x0100000C:  # ARM64
                offset = struct.unpack(">I", data[base+8:base+12])[0]
                break
        if offset is None:
            print("[!] ARM64 slice not found")
            sys.exit(1)
    else:
        offset = 0

    # Read mach header
    ncmds = struct.unpack("<I", data[offset+16:offset+20])[0]
    sizeofcmds = struct.unpack("<I", data[offset+20:offset+24])[0]

    # Create LC_LOAD_WEAK_DYLIB command
    path_bytes = dylib_path.encode() + b'\x00'
    path_len = len(path_bytes)
    cmd_size = 24 + ((path_len + 7) // 8) * 8  # Align to 8 bytes

    lc_load_dylib = struct.pack("<II", 0x80000018, cmd_size)  # LC_LOAD_WEAK_DYLIB
    lc_load_dylib += struct.pack("<IIII", 24, 0, 0, 0)  # dylib struct
    lc_load_dylib += path_bytes
    lc_load_dylib += b'\x00' * (cmd_size - 24 - path_len)

    # Insert after mach header
    insert_pos = offset + 32 + sizeofcmds
    data[insert_pos:insert_pos] = lc_load_dylib

    # Update header
    data[offset+16:offset+20] = struct.pack("<I", ncmds + 1)
    data[offset+20:offset+24] = struct.pack("<I", sizeofcmds + cmd_size)

    with open(binary_path, "wb") as f:
        f.write(data)

    print(f"[+] Injected {dylib_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <binary> <dylib_path>")
        sys.exit(1)
    inject_dylib(sys.argv[1], sys.argv[2])
