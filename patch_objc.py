#!/usr/bin/env python3
"""
Final working patch:
Replace installClick with ARM64 code that:
1. MOV X1, #selectVC_selector
2. BL objc_msgSend  -> X0 = selectVC object
3. MOV X1, #signSuccess_selector
4. BL objc_msgSend  -> call signSuccess
5. RET

This requires finding objc_msgSend stub and selector addresses.
"""
import struct
import sys

binary_path = "temp/Payload/DumpApp.app/DumpApp"

def read_u64(data, off):
    return struct.unpack("<Q", data[off:off+8])[0]

def read_u32(data, off):
    return struct.unpack("<I", data[off:off+4])[0]

def write_u32(data, off, val):
    data[off:off+4] = struct.pack("<I", val)

def adrp_add(rd, pc, target):
    """Generate ADRP + ADD pair to load address into register"""
    page_pc = pc & ~0xFFF
    page_target = target & ~0xFFF
    page_diff = (page_target - page_pc) >> 12

    # Check if offset is in range
    if page_diff < -(1 << 20) or page_diff >= (1 << 20):
        return None

    # Handle sign extension
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

# Find objc_msgSend in stubs
stubs_foff, stubs_vaddr, stubs_size = sections[('__TEXT', '__stubs')]
objc_msgSend_addr = stubs_vaddr  # Usually first stub
print(f"[+] objc_msgSend stub: {objc_msgSend_addr:#x}")

# Find selectors
mn_foff, mn_vaddr, mn_size = sections[('__TEXT', '__objc_methname')]
methnames_data = data[mn_foff:mn_foff + mn_size]

selrefs_key = ('__DATA', '__objc_selrefs')
if selrefs_key not in sections:
    selrefs_key = ('__DATA_CONST', '__objc_selrefs')
sr_foff, sr_vaddr, sr_size = sections[selrefs_key]

def find_selref(name):
    off = methnames_data.find(name.encode() + b'\x00')
    if off < 0:
        return None
    str_vaddr = mn_vaddr + off
    for i in range(0, sr_size, 8):
        ptr = read_u64(data, sr_foff + i)
        if ptr == str_vaddr:
            return sr_vaddr + i
    return None

selectvc_sel = find_selref('selectVC')
signsuccess_sel = find_selref('signSuccess')

if not selectvc_sel or not signsuccess_sel:
    print(f"[!] Selectors not found: selectVC={selectvc_sel}, signSuccess={signsuccess_sel}")
    sys.exit(1)

print(f"[+] selectVC selector: {selectvc_sel:#x}")
print(f"[+] signSuccess selector: {signsuccess_sel:#x}")

# Find installClick function
ic_selref = find_selref('installClick')
text_foff, text_vaddr, text_size = sections[('__TEXT', '__text')]

installclick_ref = None
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

            if target == ic_selref:
                installclick_ref = text_vaddr + i
                break

if not installclick_ref:
    print("[!] installClick not found")
    sys.exit(1)

# Find function start
search_start = installclick_ref - text_vaddr
func_start = None
func_start_foff = None

for i in range(search_start, max(0, search_start - 2048), -4):
    insn = read_u32(data, text_foff + i)
    if (insn & 0xFFC00000) == 0xA9800000:  # STP with writeback
        func_start = text_vaddr + i
        func_start_foff = text_foff + i
        break

if not func_start:
    func_start = installclick_ref
    func_start_foff = text_foff + (installclick_ref - text_vaddr)

print(f"[+] installClick at: {func_start:#x} (file {func_start_foff:#x})")

# Generate patch code
# X0 already contains self
pc = func_start
patch_code = []

# Load selectVC selector into X1
insns = adrp_add(1, pc, selectvc_sel)
if not insns:
    print("[!] selectVC selector out of range")
    sys.exit(1)
patch_code.extend(insns)
pc += 8

# Call objc_msgSend -> X0 = selectVC object
bl = bl_insn(pc, objc_msgSend_addr)
if not bl:
    print("[!] objc_msgSend out of range")
    sys.exit(1)
patch_code.append(bl)
pc += 4

# Load signSuccess selector into X1
insns = adrp_add(1, pc, signsuccess_sel)
if not insns:
    print("[!] signSuccess selector out of range")
    sys.exit(1)
patch_code.extend(insns)
pc += 8

# Call objc_msgSend -> call signSuccess
bl = bl_insn(pc, objc_msgSend_addr)
if not bl:
    print("[!] objc_msgSend out of range for second call")
    sys.exit(1)
patch_code.append(bl)
pc += 4

# RET
patch_code.append(0xD65F03C0)

print(f"\n[+] Generated {len(patch_code)} instructions ({len(patch_code)*4} bytes)")

# Write patch
for i, insn in enumerate(patch_code):
    write_u32(data, func_start_foff + i * 4, insn)

with open(binary_path, "wb") as f:
    f.write(data)

print("[+] Patched successfully!")
print("[+] installClick will now call [self.selectVC signSuccess]")
