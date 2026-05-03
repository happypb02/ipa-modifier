#!/usr/bin/env python3
import struct
import sys

binary_path = "temp/Payload/DumpApp.app/DumpApp"

def read_u64(data, off):
    return struct.unpack("<Q", data[off:off+8])[0]

def read_u32(data, off):
    return struct.unpack("<I", data[off:off+4])[0]

with open(binary_path, "rb") as f:
    data = bytearray(f.read())

# Parse Mach-O to find __TEXT::__text
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
    print(f"[!] Unknown magic: {magic:#x}")
    sys.exit(1)

ncmds = read_u32(data, offset + 16)
sections = {}
cmd_off = offset + 32

for _ in range(ncmds):
    cmd = read_u32(data, cmd_off)
    cmdsize = read_u32(data, cmd_off + 4)

    if cmd == 0x19:  # LC_SEGMENT_64
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

# Find installClick selref
mn_foff, mn_vaddr, mn_size = sections[('__TEXT', '__objc_methname')]
methnames_data = data[mn_foff:mn_foff + mn_size]
ic_off = methnames_data.find(b'installClick\x00')
ic_str_vaddr = mn_vaddr + ic_off

selrefs_key = ('__DATA', '__objc_selrefs')
if selrefs_key not in sections:
    selrefs_key = ('__DATA_CONST', '__objc_selrefs')
sr_foff, sr_vaddr, sr_size = sections[selrefs_key]

ic_selref_vaddr = None
for i in range(0, sr_size, 8):
    ptr = read_u64(data, sr_foff + i)
    if ptr == ic_str_vaddr:
        ic_selref_vaddr = sr_vaddr + i
        break

print(f"[+] installClick selref at: {ic_selref_vaddr:#x}")

# Search __TEXT::__text for references to this selref
text_foff, text_vaddr, text_size = sections[('__TEXT', '__text')]
print(f"[+] Searching in __TEXT::__text ({text_size} bytes)...")

# Look for ADRP + ADD/LDR pattern that loads the selref
# ADRP Xn, page
# ADD Xn, Xn, #pageoff  OR  LDR Xn, [Xn, #pageoff]

found_refs = []
for i in range(0, text_size - 8, 4):
    insn1 = read_u32(data, text_foff + i)
    insn2 = read_u32(data, text_foff + i + 4)

    # Check if insn1 is ADRP
    if (insn1 & 0x9F000000) == 0x90000000:
        # Extract register and immediate
        rd = insn1 & 0x1F
        immlo = (insn1 >> 29) & 0x3
        immhi = (insn1 >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & (1 << 32):
            imm -= (1 << 33)

        pc = text_vaddr + i
        target_page = (pc & ~0xFFF) + imm

        # Check if insn2 uses the same register
        if (insn2 & 0x1F) == rd or ((insn2 >> 5) & 0x1F) == rd:
            # Check ADD or LDR
            if (insn2 & 0xFFC00000) == 0x91000000:  # ADD
                add_imm = (insn2 >> 10) & 0xFFF
                target = target_page + add_imm
            elif (insn2 & 0xFFC00000) == 0xF9400000:  # LDR
                ldr_imm = ((insn2 >> 10) & 0xFFF) * 8
                target = target_page + ldr_imm
            else:
                continue

            if target == ic_selref_vaddr:
                func_addr = text_vaddr + i
                print(f"[+] Found reference at: {func_addr:#x}")
                found_refs.append(func_addr)

if not found_refs:
    print("[!] No references to installClick selref found")
    sys.exit(1)

# Use the first reference as installClick
installclick_addr = found_refs[0]
print(f"[+] Using {installclick_addr:#x} as installClick")

# Find function start (scan backwards for function prologue)
search_start = installclick_addr - text_vaddr
for i in range(search_start, max(0, search_start - 1024), -4):
    insn = read_u32(data, text_foff + i)
    # Look for STP X29, X30, [SP, #-xx]!
    if (insn & 0xFFC07FFF) == 0xA9807BFD or (insn & 0xFFC07FFF) == 0xA9BF7BFD:
        func_start = text_vaddr + i
        func_start_foff = text_foff + i
        print(f"[+] Function starts at: {func_start:#x} (file offset {func_start_foff:#x})")

        # Dump first 64 bytes
        print("\n[*] First 16 instructions:")
        for j in range(0, 64, 4):
            insn = read_u32(data, func_start_foff + j)
            print(f"  {func_start + j:#x}: {insn:08x}")
        break
