#!/usr/bin/env python3
"""
Search for selectVC method in DASignProcessVC
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

# Find class_ro_t and methods
classname_bytes = struct.pack("<Q", classname_vaddr)

for search_foff in range(0, len(data) - 56, 8):
    if data[search_foff+24:search_foff+32] == classname_bytes:
        print(f"\n[+] Found class_ro_t at file offset {search_foff:#x}")

        base_methods_vm = r64(data, search_foff + 32)
        if base_methods_vm == 0:
            print("  [!] No methods")
            continue

        # Find methods section
        for (seg, sect), (foff, vaddr, size) in sections.items():
            if vaddr <= base_methods_vm < vaddr + size:
                methods_foff = foff + (base_methods_vm - vaddr)
                print(f"  [+] Methods at file offset {methods_foff:#x}")

                entsize = r32(data, methods_foff) & 0xFFFF
                count = r32(data, methods_foff + 4)
                print(f"  [+] {count} methods, entsize={entsize}")

                found_selectvc = False
                for i in range(count):
                    method_base = methods_foff + 8 + i * entsize
                    sel_vm = r64(data, method_base)
                    imp_vm = r64(data, method_base + 8)

                    # Find selector name
                    for (seg2, sect2), (foff2, vaddr2, size2) in sections.items():
                        if vaddr2 <= sel_vm < vaddr2 + size2:
                            sel_foff = foff2 + (sel_vm - vaddr2)
                            sel_end = data.find(b'\x00', sel_foff)
                            if sel_end > sel_foff:
                                sel_name = data[sel_foff:sel_end].decode('utf-8', errors='ignore')

                                # Print methods containing 'select' or 'VC'
                                if 'select' in sel_name.lower() or sel_name == 'vc':
                                    print(f"    [{i}] {sel_name}: IMP={imp_vm:#x}")
                                    if sel_name == 'selectVC':
                                        found_selectvc = True
                                        print(f"        ^^^ FOUND selectVC getter!")
                            break

                if not found_selectvc:
                    print("\n  [!] selectVC method NOT found in this class")
                    print("  [!] Listing ALL methods:")
                    for i in range(min(count, 30)):  # Show first 30
                        method_base = methods_foff + 8 + i * entsize
                        sel_vm = r64(data, method_base)
                        for (seg2, sect2), (foff2, vaddr2, size2) in sections.items():
                            if vaddr2 <= sel_vm < vaddr2 + size2:
                                sel_foff = foff2 + (sel_vm - vaddr2)
                                sel_end = data.find(b'\x00', sel_foff)
                                if sel_end > sel_foff:
                                    sel_name = data[sel_foff:sel_end].decode('utf-8', errors='ignore')
                                    print(f"      - {sel_name}")
                                break
                    if count > 30:
                        print(f"      ... and {count - 30} more")

                break
