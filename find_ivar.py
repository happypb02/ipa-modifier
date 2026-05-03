#!/usr/bin/env python3
"""
Check if selectVC is an ivar and find its offset
"""
import struct
import sys

binary_path = "temp/Payload/DumpApp.app/DumpApp"

def read_u64(data, off):
    return struct.unpack("<Q", data[off:off+8])[0]

def read_u32(data, off):
    return struct.unpack("<I", data[off:off+4])[0]

with open(binary_path, "rb") as f:
    data = f.read()

# Parse Mach-O
magic = read_u32(data, 0)
if magic == 0xFEEDFACF:
    offset = 0
elif magic == 0xCAFEBABE:
    narch = struct.unpack(">I", data[4:8])[0]
    offset = None
    for i in range(narch):
        base = 8 + i * 20
        cpu_type = struct.unpack(">I", data[base:base+4])[0]
        if cpu_type == 0x0100000C:
            offset = struct.unpack(">I", data[base+8:base+12])[0]
            break
else:
    sys.exit(1)

ncmds = read_u32(data, offset + 16)
sections = {}
cmd_off = offset + 32

for _ in range(ncmds):
    cmd = read_u32(data, cmd_off)
    cmdsize = read_u32(data, cmd_off + 4)

    if cmd == 0x19:
        segname = data[cmd_off+8:cmd_off+24].rstrip(b'\x00').decode()
        nsects = read_u32(data, cmd_off + 64)
        sect_off = cmd_off + 72

        for i in range(nsects):
            sectname = data[sect_off:sect_off+16].rstrip(b'\x00').decode()
            vaddr = read_u64(data, sect_off + 32)
            size = read_u64(data, sect_off + 40)
            foff = read_u32(data, sect_off + 48)
            sections[(segname, sectname)] = (foff, vaddr, size)
            sect_off += 80

    cmd_off += cmdsize

# Find DASignProcessVC class
classname = b'DASignProcessVC\x00'
classname_foff = data.find(classname)
classname_vaddr = None
for (seg, sect), (foff, vaddr, size) in sections.items():
    if foff <= classname_foff < foff + size:
        classname_vaddr = vaddr + (classname_foff - foff)
        break

if not classname_vaddr:
    print("[!] DASignProcessVC not found")
    sys.exit(1)

print(f"[+] DASignProcessVC class name at: {classname_vaddr:#x}")

# Find class_ro_t
classname_bytes = struct.pack("<Q", classname_vaddr)

for search_foff in range(0, len(data) - 48, 8):
    if data[search_foff+24:search_foff+32] == classname_bytes:
        print(f"\n[+] Found potential class_ro_t at file offset {search_foff:#x}")

        flags = read_u32(data, search_foff)
        instanceStart = read_u32(data, search_foff + 4)
        instanceSize = read_u32(data, search_foff + 8)
        ivarLayout = read_u64(data, search_foff + 16)
        name_ptr = read_u64(data, search_foff + 24)
        baseMethods = read_u64(data, search_foff + 32)
        baseProtocols = read_u64(data, search_foff + 40)
        ivars_ptr = read_u64(data, search_foff + 48)

        print(f"  flags: {flags:#x}")
        print(f"  instanceStart: {instanceStart}")
        print(f"  instanceSize: {instanceSize}")
        print(f"  ivars_ptr: {ivars_ptr:#x}")

        if ivars_ptr == 0:
            print("  [!] No ivars")
            continue

        # Find ivars section
        for (seg, sect), (foff, vaddr, size) in sections.items():
            if vaddr <= ivars_ptr < vaddr + size:
                ivars_foff = foff + (ivars_ptr - vaddr)
                print(f"  [+] ivars at file offset {ivars_foff:#x}")

                entsize = read_u32(data, ivars_foff)
                count = read_u32(data, ivars_foff + 4)
                print(f"  [+] {count} ivars, entsize={entsize}")

                for i in range(count):
                    ivar_base = ivars_foff + 8 + i * entsize
                    ivar_offset_ptr = read_u64(data, ivar_base)
                    ivar_name_ptr = read_u64(data, ivar_base + 8)
                    ivar_type_ptr = read_u64(data, ivar_base + 16)

                    # Find ivar name
                    ivar_name = "?"
                    ivar_offset = -1

                    for (seg2, sect2), (foff2, vaddr2, size2) in sections.items():
                        if vaddr2 <= ivar_name_ptr < vaddr2 + size2:
                            name_foff = foff2 + (ivar_name_ptr - vaddr2)
                            name_end = data.find(b'\x00', name_foff)
                            if name_end > name_foff:
                                ivar_name = data[name_foff:name_end].decode('utf-8', errors='ignore')
                            break

                    # Read offset value
                    for (seg2, sect2), (foff2, vaddr2, size2) in sections.items():
                        if vaddr2 <= ivar_offset_ptr < vaddr2 + size2:
                            offset_foff = foff2 + (ivar_offset_ptr - vaddr2)
                            ivar_offset = read_u32(data, offset_foff)
                            break

                    print(f"    [{i}] {ivar_name}: offset={ivar_offset}")

                    if 'selectVC' in ivar_name:
                        print(f"\n[+] *** Found {ivar_name} ivar at offset {ivar_offset}! ***\n")
                break
