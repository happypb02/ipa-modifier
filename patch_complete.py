#!/usr/bin/env python3
"""
Complete working patch script
"""
import struct
import sys
import os

# Check if binary exists
binary_path = "temp/Payload/DumpApp.app/DumpApp"
if not os.path.exists(binary_path):
    print(f"[!] Binary not found at: {binary_path}")
    print(f"[!] Current directory: {os.getcwd()}")
    print(f"[!] Files in current directory:")
    for item in os.listdir("."):
        print(f"    {item}")
    sys.exit(1)

print(f"[+] Found binary: {binary_path}")

def r64(d, o): return struct.unpack("<Q", d[o:o+8])[0]
def r32(d, o): return struct.unpack("<I", d[o:o+4])[0]
def w32(d, o, v): d[o:o+4] = struct.pack("<I", v)

with open(binary_path, "rb") as f:
    data = bytearray(f.read())

print(f"[+] Binary size: {len(data)} bytes")

# Parse Mach-O header
magic = r32(data, 0)
offset = 0 if magic == 0xFEEDFACF else None

if not offset:
    narch = struct.unpack(">I", data[4:8])[0]
    for i in range(narch):
        base = 8 + i * 20
        if struct.unpack(">I", data[base:base+4])[0] == 0x0100000C:
            offset = struct.unpack(">I", data[base+8:base+12])[0]
            break

if not offset:
    print("[!] ARM64 architecture not found")
    sys.exit(1)

print(f"[+] ARM64 slice at offset: {offset:#x}")

# Parse load commands
ncmds = r32(data, offset + 16)
sections = {}
cmd_off = offset + 32

for _ in range(ncmds):
    cmd = r32(data, cmd_off)
    cmdsize = r32(data, cmd_off + 4)
    if cmd == 0x19:  # LC_SEGMENT_64
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

print(f"[+] Found {len(sections)} sections")

# Find installClick selector
mn_foff, mn_vaddr, mn_size = sections[('__TEXT', '__objc_methname')]
methnames = data[mn_foff:mn_foff + mn_size]
ic_off = methnames.find(b'installClick\x00')

if ic_off < 0:
    print("[!] installClick selector not found")
    sys.exit(1)

ic_str = mn_vaddr + ic_off
print(f"[+] installClick selector: {ic_str:#x}")

# Find selref
sr_key = ('__DATA', '__objc_selrefs') if ('__DATA', '__objc_selrefs') in sections else ('__DATA_CONST', '__objc_selrefs')
sr_foff, sr_vaddr, sr_size = sections[sr_key]

ic_selref = None
for i in range(0, sr_size, 8):
    if r64(data, sr_foff + i) == ic_str:
        ic_selref = sr_vaddr + i
        break

if not ic_selref:
    print("[!] installClick selref not found")
    sys.exit(1)

print(f"[+] installClick selref: {ic_selref:#x}")

# Find reference in code
text_foff, text_vaddr, text_size = sections[('__TEXT', '__text')]

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

        if target == ic_selref:
            print(f"[+] Found reference at: {pc:#x}")

            # Find function start
            for j in range(i, max(0, i - 2048), -4):
                insn = r32(data, text_foff + j)
                if (insn & 0xFFC00000) == 0xA9800000:  # STP with pre-index
                    func_foff = text_foff + j
                    func_addr = text_vaddr + j
                    print(f"[+] Function start at: {func_addr:#x}")

                    # Patch with RET
                    w32(data, func_foff, 0xD65F03C0)

                    with open(binary_path, "wb") as f:
                        f.write(data)

                    print("[+] Patched successfully!")
                    print("[+] installClick now returns immediately (no-op)")
                    sys.exit(0)

print("[!] Function start not found")
sys.exit(1)
