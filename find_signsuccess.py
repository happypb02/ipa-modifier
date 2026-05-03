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

                                        # Check if it's in __TEXT::__text
                                        text_foff, text_vaddr, text_size = sections[('__TEXT', '__text')]
                                        if text_vaddr <= ss_imp_vaddr < text_vaddr + text_size:
                                            print(f"[+] signSuccess is in __TEXT::__text - valid code")
                                        else:
                                            print(f"[!] signSuccess IMP is NOT in __TEXT::__text - invalid, will search by selref")
                                            ss_imp_vaddr = None  # Mark as invalid
                                break
                        break
                    break
        if ss_imp_vaddr:
            break

# Always search by selref to find the real implementation
print("\n[*] Searching for signSuccess by selref references...")

# Find signSuccess selref
    ss_off = methnames_data.find(b'signSuccess\x00')
    if ss_off < 0:
        print("[!] signSuccess selector string not found")
        sys.exit(1)

    ss_str_vaddr = mn_vaddr + ss_off
    print(f"[+] signSuccess selector string at: {ss_str_vaddr:#x}")

    # Find selref
    selrefs_key = ('__DATA', '__objc_selrefs')
    if selrefs_key not in sections:
        selrefs_key = ('__DATA_CONST', '__objc_selrefs')
    sr_foff, sr_vaddr, sr_size = sections[selrefs_key]

    ss_selref_vaddr = None
    for i in range(0, sr_size, 8):
        ptr = read_u64(data, sr_foff + i)
        if ptr == ss_str_vaddr:
            ss_selref_vaddr = sr_vaddr + i
            break

    if not ss_selref_vaddr:
        print("[!] signSuccess selref not found")
        sys.exit(1)

    print(f"[+] signSuccess selref at: {ss_selref_vaddr:#x}")

    # Search for references in code
    text_foff, text_vaddr, text_size = sections[('__TEXT', '__text')]
    print(f"[+] Searching in __TEXT::__text...")

    found_refs = []
    for i in range(0, text_size - 8, 4):
        insn1 = read_u32(data, text_foff + i)
        insn2 = read_u32(data, text_foff + i + 4)

        if (insn1 & 0x9F000000) == 0x90000000:
            rd = insn1 & 0x1F
            immlo = (insn1 >> 29) & 0x3
            immhi = (insn1 >> 5) & 0x7FFFF
            imm = ((immhi << 2) | immlo) << 12
            if imm & (1 << 32):
                imm -= (1 << 33)

            pc = text_vaddr + i
            target_page = (pc & ~0xFFF) + imm

            if (insn2 & 0x1F) == rd or ((insn2 >> 5) & 0x1F) == rd:
                if (insn2 & 0xFFC00000) == 0x91000000:
                    add_imm = (insn2 >> 10) & 0xFFF
                    target = target_page + add_imm
                elif (insn2 & 0xFFC00000) == 0xF9400000:
                    ldr_imm = ((insn2 >> 10) & 0xFFF) * 8
                    target = target_page + ldr_imm
                else:
                    continue

                if target == ss_selref_vaddr:
                    func_addr = text_vaddr + i
                    found_refs.append(func_addr)

    print(f"[+] Found {len(found_refs)} references to signSuccess selref")
    for ref in found_refs[:5]:  # Show first 5
        print(f"  - {ref:#x}")

    if found_refs:
        # Use first reference and find function start
        ref_addr = found_refs[0]
        search_start = ref_addr - text_vaddr

        for i in range(search_start, max(0, search_start - 2048), -4):
            insn = read_u32(data, text_foff + i)
            if (insn & 0xFFC00000) == 0xA9800000:
                ss_imp_vaddr = text_vaddr + i
                ss_imp_foff = text_foff + i
                print(f"\n[+] signSuccess function starts at: {ss_imp_vaddr:#x}")

                # Dump first 64 instructions
                print("\n[*] First 64 instructions:")
                for j in range(0, 256, 4):
                    insn = read_u32(data, ss_imp_foff + j)
                    addr = ss_imp_vaddr + j
                    marker = " <-- ref" if addr == ref_addr else ""
                    print(f"  {addr:#x}: {insn:08x}{marker}")
                break
