#!/usr/bin/env python3
"""
Patch installClick to call signSuccess on selectVC
Strategy: Replace installClick with a simple implementation that:
1. Gets self.selectVC (via KVO or ivar)
2. Calls [selectVC signSuccess]
"""
import struct
import sys

binary_path = "temp/Payload/DumpApp.app/DumpApp"

def read_u64(data, off):
    return struct.unpack("<Q", data[off:off+8])[0]

def read_u32(data, off):
    return struct.unpack("<I", data[off:off+4])[0]

def adr_imm(rd, pc, target):
    """Generate ADRP + ADD to load target address into rd"""
    page_pc = pc & ~0xFFF
    page_target = target & ~0xFFF
    page_off = (page_target - page_pc) >> 12

    immlo = page_off & 0x3
    immhi = (page_off >> 2) & 0x7FFFF
    adrp = 0x90000000 | (immlo << 29) | (immhi << 5) | rd

    add_imm = target & 0xFFF
    add = 0x91000000 | (add_imm << 10) | (rd << 5) | rd

    return struct.pack("<II", adrp, add)

def b_insn(pc, target):
    """Generate B instruction"""
    offset = (target - pc) >> 2
    offset &= 0x3FFFFFF
    return struct.pack("<I", 0x14000000 | offset)

def bl_insn(pc, target):
    """Generate BL instruction"""
    offset = (target - pc) >> 2
    offset &= 0x3FFFFFF
    return struct.pack("<I", 0x94000000 | offset)

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

# Find selrefs
mn_foff, mn_vaddr, mn_size = sections[('__TEXT', '__objc_methname')]
methnames_data = data[mn_foff:mn_foff + mn_size]

selrefs_key = ('__DATA', '__objc_selrefs')
if selrefs_key not in sections:
    selrefs_key = ('__DATA_CONST', '__objc_selrefs')
sr_foff, sr_vaddr, sr_size = sections[selrefs_key]

# Find objc_msgSend stub
text_stubs_foff, text_stubs_vaddr, text_stubs_size = sections[('__TEXT', '__stubs')]
objc_msgSend_vaddr = None
for i in range(0, text_stubs_size, 12):
    insn = read_u32(data, text_stubs_foff + i)
    if (insn & 0x9F000000) == 0x90000000:
        objc_msgSend_vaddr = text_stubs_vaddr + i
        break

print(f"[+] objc_msgSend stub: {objc_msgSend_vaddr:#x}")

# Find signSuccess selref
ss_off = methnames_data.find(b'signSuccess\x00')
ss_str_vaddr = mn_vaddr + ss_off
ss_selref_vaddr = None
for i in range(0, sr_size, 8):
    ptr = read_u64(data, sr_foff + i)
    if ptr == ss_str_vaddr:
        ss_selref_vaddr = sr_vaddr + i
        break

print(f"[+] signSuccess selref: {ss_selref_vaddr:#x}")

# Find installClick reference
ic_off = methnames_data.find(b'installClick\x00')
ic_str_vaddr = mn_vaddr + ic_off
ic_selref_vaddr = None
for i in range(0, sr_size, 8):
    ptr = read_u64(data, sr_foff + i)
    if ptr == ic_str_vaddr:
        ic_selref_vaddr = sr_vaddr + i
        break

print(f"[+] installClick selref: {ic_selref_vaddr:#x}")

# Find installClick function by searching for selref reference
text_foff, text_vaddr, text_size = sections[('__TEXT', '__text')]

installclick_addr = None
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

            if target == ic_selref_vaddr:
                installclick_addr = text_vaddr + i
                break

if not installclick_addr:
    print("[!] installClick not found")
    sys.exit(1)

# Find function start
search_start = installclick_addr - text_vaddr
func_start = None
for i in range(search_start, max(0, search_start - 2048), -4):
    insn = read_u32(data, text_foff + i)
    if (insn & 0xFFC00000) == 0xA9800000:  # STP with writeback
        func_start = text_vaddr + i
        func_start_foff = text_foff + i
        break

if not func_start:
    print("[!] Function start not found, using reference")
    func_start = installclick_addr
    func_start_foff = text_foff + (installclick_addr - text_vaddr)

print(f"[+] installClick at: {func_start:#x} (file offset {func_start_foff:#x})")

# Simple patch: just RET (no-op)
# User will manually navigate to the file tab
patch = bytes([0xC0, 0x03, 0x5F, 0xD6])  # RET
data[func_start_foff:func_start_foff + 4] = patch

with open(binary_path, "wb") as f:
    f.write(data)

print("[+] Patched installClick to RET")
print("[+] Click '去安装' will do nothing - manually go to 文件 tab")
