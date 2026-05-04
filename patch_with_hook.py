#!/usr/bin/env python3
"""
Find free space in __text section and hook installClick's RET
"""
import struct
import sys
import os

binary_path = "temp/Payload/DumpApp.app/DumpApp"

def r64(d, o): return struct.unpack("<Q", d[o:o+8])[0]
def r32(d, o): return struct.unpack("<I", d[o:o+4])[0]
def w32(d, o, v): d[o:o+4] = struct.pack("<I", v)

def adrp_add_ldr(rd, pc, target):
    page_pc = pc & ~0xFFF
    page_target = target & ~0xFFF
    page_diff = (page_target - page_pc) >> 12
    if page_diff < -(1 << 20) or page_diff >= (1 << 20):
        return None
    if page_diff < 0:
        page_diff = (1 << 21) + page_diff
    immlo = page_diff & 0x3
    immhi = (page_diff >> 2) & 0x7FFFF
    adrp = 0x90000000 | (immlo << 29) | (immhi << 5) | rd
    page_off = (target & 0xFFF) >> 3
    ldr = 0xF9400000 | (page_off << 10) | (rd << 5) | rd
    return [adrp, ldr]

def bl_insn(pc, target):
    offset = (target - pc) >> 2
    if offset < -(1 << 25) or offset >= (1 << 25):
        return None
    if offset < 0:
        offset = (1 << 26) + offset
    return 0x94000000 | (offset & 0x3FFFFFF)

def b_insn(pc, target):
    offset = (target - pc) >> 2
    if offset < -(1 << 25) or offset >= (1 << 25):
        return None
    if offset < 0:
        offset = (1 << 26) + offset
    return 0x14000000 | (offset & 0x3FFFFFF)

with open(binary_path, "rb") as f:
    data = bytearray(f.read())

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

text_foff, text_vaddr, text_size = sections[('__TEXT', '__text')]
stubs_foff, stubs_vaddr, stubs_size = sections[('__TEXT', '__stubs')]

# Find free space at end of __text (before __stubs)
free_space_foff = text_foff + text_size - 128  # Try last 128 bytes
free_space_vaddr = text_vaddr + text_size - 128

print(f"[+] __text section: {text_vaddr:#x} - {text_vaddr + text_size:#x}")
print(f"[+] Trying free space at: {free_space_vaddr:#x}")

# Check if it's actually free (all zeros or NOPs)
is_free = True
for i in range(32):  # Check 32 instructions
    insn = r32(data, free_space_foff + i * 4)
    if insn != 0 and insn != 0xD503201F:  # Not zero and not NOP
        is_free = False
        break

if not is_free:
    print("[!] Space not free, trying earlier")
    free_space_foff = text_foff + text_size - 256
    free_space_vaddr = text_vaddr + text_size - 256

print(f"[+] Using free space at: {free_space_vaddr:#x}")

# Find selectors
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

signsuccess_sel = find_selref('signSuccess')
installclick_sel = find_selref('installClick')

if not signsuccess_sel or not installclick_sel:
    print("[!] Selectors not found")
    sys.exit(1)

# Find installClick
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

if not installclick_ref:
    print("[!] installClick not found")
    sys.exit(1)

func_start = None
for j in range(installclick_ref, max(0, installclick_ref - 4096), -4):
    insn = r32(data, text_foff + j)
    if (insn & 0xFFC00000) == 0xA9800000 or (insn & 0xFFC00000) == 0xA9000000:
        func_start = j
        break

if not func_start:
    print("[!] Function start not found")
    sys.exit(1)

# Find all RETs in function
rets = []
for j in range(func_start, min(text_size, func_start + 8192), 4):
    insn = r32(data, text_foff + j)
    if insn == 0xD65F03C0:
        rets.append(j)
    # Stop at next function prologue
    elif j > func_start + 16 and ((insn & 0xFFC00000) == 0xA9800000 or (insn & 0xFFC00000) == 0xA9000000):
        break

if not rets:
    print("[!] No RET found in installClick")
    sys.exit(1)

# Use the last RET (main exit point)
ret_off = rets[-1]
print(f"[+] Found {len(rets)} RET(s), using last one")

ret_addr = text_vaddr + ret_off
print(f"[+] installClick RET at: {ret_addr:#x}")

# Build hook code in free space
pc = free_space_vaddr
hook = []

# Save X19 (callee-saved)
hook.append(0xF81F0FF3)  # STR X19, [SP, #-16]!
pc += 4

# Save self (X0) to X19
hook.append(0xAA0003F3)  # MOV X19, X0
pc += 4

# Load signSuccess selector
insns = adrp_add_ldr(1, pc, signsuccess_sel)
if not insns:
    print("[!] signSuccess out of range")
    sys.exit(1)
hook.extend(insns)
pc += 8

# Restore X0 from X19
hook.append(0xAA1303E0)  # MOV X0, X19
pc += 4

# Call objc_msgSend
bl = bl_insn(pc, stubs_vaddr)
if not bl:
    print("[!] objc_msgSend out of range")
    sys.exit(1)
hook.append(bl)
pc += 4

# Restore X19
hook.append(0xF84107F3)  # LDR X19, [SP], #16
pc += 4

# RET
hook.append(0xD65F03C0)

print(f"[+] Hook code: {len(hook)} instructions")

# Write hook
for idx, insn in enumerate(hook):
    w32(data, free_space_foff + idx * 4, insn)

# Replace RET with B to hook
b_to_hook = b_insn(ret_addr, free_space_vaddr)
if not b_to_hook:
    print("[!] Hook too far")
    sys.exit(1)

w32(data, text_foff + ret_off, b_to_hook)

with open(binary_path, "wb") as f:
    f.write(data)

print("[+] Patched! installClick will call signSuccess before returning")
