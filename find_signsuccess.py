#!/usr/bin/env python3
"""
Find signSuccess method implementation and analyze what it does
"""
import struct
import sys

binary_path = "temp/Payload/DumpApp.app/DumpApp"

def read_u64(data, off):
    return struct.unpack("<Q", data[off:off+8])[0]

def read_u32(data, off):
    return struct.unpack("<I", data[off:off+4])[0]

with open(binary_path, "rb") as f:
    data = bytearray(f.read())

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

# Find signSuccess in DASelectAppVC
mn_foff, mn_vaddr, mn_size = sections[('__TEXT', '__objc_methname')]
methnames_data = data[mn_foff:mn_foff + mn_size]

# Find DASelectAppVC class
classname = b'DASelectAppVC\x00'
classname_foff = data.find(classname)
classname_vaddr = None
for (seg, sect), (foff, vaddr, size) in sections.items():
    if foff <= classname_foff < foff + size:
        classname_vaddr = vaddr + (classname_foff - foff)
        break

if not classname_vaddr:
    print("[!] DASelectAppVC not found")
    sys.exit(1)

print(f"[+] DASelectAppVC class at: {classname_vaddr:#x}")

# Find signSuccess method in DASelectAppVC
classname_bytes = struct.pack("<Q", classname_vaddr)
ss_imp_vaddr = None

for search_foff in range(0, len(data) - 48, 8):
    if data[search_foff+24:search_foff+32] == classname_bytes:
        base_methods_vm = read_u64(data, search_foff + 32)
        if base_methods_vm:
            for (seg, sect), (foff, vaddr, size) in sections.items():
                if vaddr <= base_methods_vm < vaddr + size:
                    methods_foff = foff + (base_methods_vm - vaddr)
                    entsize = read_u32(data, methods_foff) & 0xFFFF
                    count = read_u32(data, methods_foff + 4)

                    print(f"[+] DASelectAppVC has {count} methods")
                    for i in range(count):
                        method_base = methods_foff + 8 + i * entsize
                        sel_vm = read_u64(data, method_base)
                        imp_vm = read_u64(data, method_base + 8)

                        # Find selector name
                        for (seg2, sect2), (foff2, vaddr2, size2) in sections.items():
                            if vaddr2 <= sel_vm < vaddr2 + size2:
                                sel_foff = foff2 + (sel_vm - vaddr2)
                                sel_end = data.find(b'\x00', sel_foff)
                                if sel_end > sel_foff:
                                    sel_name = data[sel_foff:sel_end].decode('utf-8', errors='ignore')
                                    if sel_name == 'signSuccess':
                                        ss_imp_vaddr = imp_vm
                                        print(f"[+] signSuccess IMP at: {ss_imp_vaddr:#x}")

                                        # Find file offset
                                        text_foff, text_vaddr, text_size = sections[('__TEXT', '__text')]
                                        if text_vaddr <= ss_imp_vaddr < text_vaddr + text_size:
                                            ss_imp_foff = text_foff + (ss_imp_vaddr - text_vaddr)
                                            print(f"[+] signSuccess file offset: {ss_imp_foff:#x}")

                                            # Dump first 32 instructions
                                            print("\n[*] First 32 instructions of signSuccess:")
                                            for j in range(0, 128, 4):
                                                insn = read_u32(data, ss_imp_foff + j)
                                                print(f"  {ss_imp_vaddr + j:#x}: {insn:08x}")
                                        break
                                break
                    break
        if ss_imp_vaddr:
            break

if not ss_imp_vaddr:
    print("[!] signSuccess not found in DASelectAppVC")
