#!/usr/bin/env python3
"""
Search for properties in DASignProcessVC class
"""
import struct
import sys

binary_path = "temp/Payload/DumpApp.app/DumpApp"

def r64(d, o): return struct.unpack("<Q", d[o:o+8])[0]
def r32(d, o): return struct.unpack("<I", d[o:o+4])[0]

with open(binary_path, "rb") as f:
    data = f.read()

magic = r32(data, 0)
if magic == 0xFEEDFACF:
    offset = 0
elif magic == 0xCAFEBABE:
    narch = struct.unpack(">I", data[4:8])[0]
    offset = None
    for i in range(narch):
        base = 8 + i * 20
        if struct.unpack(">I", data[base:base+4])[0] == 0x0100000C:
            offset = struct.unpack(">I", data[base+8:base+12])[0]
            break
else:
    sys.exit(1)

ncmds = r32(data, offset + 16)
sections = {}
cmd_off = offset + 32

for _ in range(ncmds):
    cmd = r32(data, cmd_off)
    cmdsize = r32(data, cmd_off + 4)
    if cmd == 0x19:
        segname = data[cmd_off+8:cmd_off+24].rstrip(b'\x00').decode()
        nsects = r32(data, cmd_off + 64)
        sect_off = cmd_off + 72
        for i in range(nsects):
            sectname = data[sect_off:sect_off+16].rstrip(b'\x00').decode()
            vaddr = r64(data, sect_off + 32)
            size = r64(data, sect_off + 40)
            foff = r32(data, sect_off + 48)
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

# Find class_ro_t with properties
classname_bytes = struct.pack("<Q", classname_vaddr)

for search_foff in range(0, len(data) - 56, 8):
    if data[search_foff+24:search_foff+32] == classname_bytes:
        print(f"\n[+] Found class_ro_t at file offset {search_foff:#x}")

        properties_ptr = r64(data, search_foff + 56)
        if properties_ptr == 0:
            print("  [!] No properties")
            continue

        # Find properties section
        for (seg, sect), (foff, vaddr, size) in sections.items():
            if vaddr <= properties_ptr < vaddr + size:
                props_foff = foff + (properties_ptr - vaddr)
                print(f"  [+] Properties at file offset {props_foff:#x}")

                entsize = r32(data, props_foff)
                count = r32(data, props_foff + 4)
                print(f"  [+] {count} properties, entsize={entsize}")

                for i in range(count):
                    prop_base = props_foff + 8 + i * entsize
                    name_ptr = r64(data, prop_base)
                    attrs_ptr = r64(data, prop_base + 8)

                    # Find property name
                    prop_name = "?"
                    for (seg2, sect2), (foff2, vaddr2, size2) in sections.items():
                        if vaddr2 <= name_ptr < vaddr2 + size2:
                            name_foff = foff2 + (name_ptr - vaddr2)
                            name_end = data.find(b'\x00', name_foff)
                            if name_end > name_foff:
                                prop_name = data[name_foff:name_end].decode('utf-8', errors='ignore')
                            break

                    # Find attributes
                    attrs = "?"
                    for (seg2, sect2), (foff2, vaddr2, size2) in sections.items():
                        if vaddr2 <= attrs_ptr < vaddr2 + size2:
                            attrs_foff = foff2 + (attrs_ptr - vaddr2)
                            attrs_end = data.find(b'\x00', attrs_foff)
                            if attrs_end > attrs_foff:
                                attrs = data[attrs_foff:attrs_end].decode('utf-8', errors='ignore')
                            break

                    print(f"    [{i}] {prop_name}: {attrs}")

                    # Check if it's a DASelectAppVC type
                    if 'DASelectAppVC' in attrs or 'select' in prop_name.lower():
                        print(f"        ^^^ THIS MIGHT BE IT!")
                break
