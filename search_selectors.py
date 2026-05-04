#!/usr/bin/env python3
"""
Search for all selectors containing 'select' or 'VC'
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

# Search method names
mn_foff, mn_vaddr, mn_size = sections[('__TEXT', '__objc_methname')]
methnames = data[mn_foff:mn_foff + mn_size]

print("[+] Searching for selectors containing 'select' or 'VC':")
print()

pos = 0
found = []
while pos < len(methnames):
    end = methnames.find(b'\x00', pos)
    if end < 0:
        break

    name = methnames[pos:end].decode('utf-8', errors='ignore')
    if name and ('select' in name.lower() or 'vc' in name.lower()):
        found.append(name)

    pos = end + 1

# Sort and print
found.sort()
for name in found:
    print(f"  - {name}")

print(f"\n[+] Total found: {len(found)}")

# Also search for 'sign'
print("\n[+] Searching for selectors containing 'sign':")
pos = 0
sign_found = []
while pos < len(methnames):
    end = methnames.find(b'\x00', pos)
    if end < 0:
        break

    name = methnames[pos:end].decode('utf-8', errors='ignore')
    if name and 'sign' in name.lower():
        sign_found.append(name)

    pos = end + 1

sign_found.sort()
for name in sign_found[:20]:  # Show first 20
    print(f"  - {name}")

if len(sign_found) > 20:
    print(f"  ... and {len(sign_found) - 20} more")
