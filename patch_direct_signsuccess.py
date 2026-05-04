#!/usr/bin/env python3
"""
Simple patch: Call [self signSuccess] directly
Since DASignProcessVC has signSuccess method, we don't need selectVC
"""
import struct
import sys
import os

binary_path = "temp/Payload/DumpApp.app/DumpApp"
if not os.path.exists(binary_path):
    print(f"[!] Binary not found: {binary_path}")
    sys.exit(1)

def r64(d, o): return struct.unpack("<Q", d[o:o+8])[0]
def r32(d, o): return struct.unpack("<I", d[o:o+4])[0]
def w32(d, o, v): d[o:o+4] = struct.pack("<I", v)

def adrp_add(rd, pc, target):
    """Generate ADRP + ADD to load address"""
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

    page_off = target & 0xFFF
    add = 0x91000000 | (page_off << 10) | (rd << 5) | rd

    return [adrp, add]

def bl_insn(pc, target):
    """Generate BL instruction"""
    offset = (target - pc) >> 2
    if offset < -(1 << 25) or offset >= (1 << 25):
        return None
    if offset < 0:
        offset = (1 << 26) + offset
    return 0x94000000 | (offset & 0x3FFFFFF)

with open(binary_path, "rb") as f:
    data = bytearray(f.read())

print(f"[+] Binary size: {len(data)} bytes")

# Parse Mach-O
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
    print(f"[!] Unknown magic: {magic:#x}")
    sys.exit(1)

# Parse sections
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

# Find objc_msgSend stub
stubs_foff, stubs_vaddr, stubs_size = sections[('__TEXT', '__stubs')]
objc_msgSend_stub = stubs_vaddr
print(f"[+] objc_msgSend stub: {objc_msgSend_stub:#x}")

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
    print(f"[!] Selectors not found")
    print(f"    signSuccess: {signsuccess_sel}")
    print(f"    installClick: {installclick_sel}")
    sys.exit(1)

print(f"[+] signSuccess selref: {signsuccess_sel:#x}")
print(f"[+] installClick selref: {installclick_sel:#x}")

# Find installClick function
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
            print(f"[+] Found installClick reference at: {pc:#x}")
            break

if installclick_ref is None:
    print("[!] installClick not found")
    sys.exit(1)

# Find function start
func_foff = None
func_addr = None

for j in range(installclick_ref, max(0, installclick_ref - 4096), -4):
    insn = r32(data, text_foff + j)
    if (insn & 0xFFC00000) == 0xA9800000 or (insn & 0xFFC00000) == 0xA9000000:
        func_foff = text_foff + j
        func_addr = text_vaddr + j
        break

if not func_foff:
    print("[!] Function start not found, using reference location")
    func_foff = text_foff + installclick_ref
    func_addr = text_vaddr + installclick_ref

print(f"[+] Patching at: {func_addr:#x}")

# Generate patch code
# X0 = self (already set by caller)
pc = func_addr
patch = []

# Load signSuccess selector into X1
insns = adrp_add(1, pc, signsuccess_sel)
if not insns:
    print("[!] signSuccess selector out of range")
    sys.exit(1)
patch.extend(insns)
pc += 8

# LDR X1, [X1] - load actual selector pointer
patch.append(0xF9400021)  # LDR X1, [X1]
pc += 4

# Call objc_msgSend -> call [self signSuccess]
bl = bl_insn(pc, objc_msgSend_stub)
if not bl:
    print("[!] objc_msgSend out of range")
    sys.exit(1)
patch.append(bl)
pc += 4

# RET
patch.append(0xD65F03C0)

print(f"[+] Generated {len(patch)} instructions ({len(patch)*4} bytes)")

# Write patch
for idx, insn in enumerate(patch):
    w32(data, func_foff + idx * 4, insn)

with open(binary_path, "wb") as f:
    f.write(data)

print("[+] Patched successfully!")
print("[+] installClick will now call [self signSuccess]")
