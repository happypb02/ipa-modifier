#!/usr/bin/env python3
"""
Disassemble installClick to understand what it does
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

mn_foff, mn_vaddr, mn_size = sections[('__TEXT', '__objc_methname')]
methnames = data[mn_foff:mn_foff + mn_size]

sr_key = ('__DATA', '__objc_selrefs') if ('__DATA', '__objc_selrefs') in sections else ('__DATA_CONST', '__objc_selrefs')
sr_foff, sr_vaddr, sr_size = sections[sr_key]

def find_selref(name):
    off = methnames.find(name.encode() + b'\x00')
    if off < 0:
        return None
    str_vaddr = mn_vaddr + off
    for i in range(0, sr_size, 8):
        ptr = r64(data, sr_foff + i)
        if ptr == str_vaddr:
            return sr_vaddr + i
    return None

installclick_sel = find_selref('installClick')
text_foff, text_vaddr, text_size = sections[('__TEXT', '__text')]

installclick_ref = None
for i in range(0, text_size - 8, 4):
    insn1 = r32(data, text_foff + i)
    if (insn1 & 0x9F000000) != 0x90000000:
        continue

    insn2 = r32(data, text_foff + i + 4)
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
            target = target_page + ((insn2 >> 10) & 0xFFF)
        elif (insn2 & 0xFFC00000) == 0xF9400000:
            target = target_page + (((insn2 >> 10) & 0xFFF) * 8)
        else:
            continue

        if target == installclick_sel:
            installclick_ref = i
            break

if installclick_ref is None:
    sys.exit(1)

func_start = None
for j in range(installclick_ref, max(0, installclick_ref - 4096), -4):
    insn = r32(data, text_foff + j)
    if (insn & 0xFFC00000) == 0xA9800000 or (insn & 0xFFC00000) == 0xA9000000:
        func_start = j
        func_addr = text_vaddr + j
        break

if not func_start:
    sys.exit(1)

print(f"[+] installClick function at: {func_addr:#x}")
print(f"[+] First 100 instructions:")
print()

for i in range(100):
    off = func_start + i * 4
    if off >= text_size:
        break

    insn = r32(data, text_foff + off)
    addr = text_vaddr + off

    # Stop at next function
    if i > 0 and ((insn & 0xFFC00000) == 0xA9800000 or (insn & 0xFFC00000) == 0xA9000000):
        print(f"[+] Next function starts here")
        break

    # Highlight important instructions
    marker = ""
    if insn == 0xD65F03C0:
        marker = " <-- RET"
    elif (insn & 0xFC000000) == 0x94000000:
        marker = " <-- BL"
    elif (insn & 0x9F000000) == 0x90000000:
        marker = " <-- ADRP"

    print(f"{addr:#010x}: {insn:#010x}{marker}")
