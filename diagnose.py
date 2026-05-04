#!/usr/bin/env python3
"""Diagnostic script - print everything we find"""
import struct, sys, traceback

binary_path = "temp/Payload/DumpApp.app/DumpApp"

try:
    def r64(d, o): return struct.unpack("<Q", d[o:o+8])[0]
    def r32(d, o): return struct.unpack("<I", d[o:o+4])[0]

    with open(binary_path, "rb") as f:
        data = f.read()

    print(f"[+] Binary size: {len(data)} bytes")

    magic = r32(data, 0)
    print(f"[+] Magic: {magic:#x}")

    offset = 0 if magic == 0xFEEDFACF else None
    if not offset:
        narch = struct.unpack(">I", data[4:8])[0]
        print(f"[+] Fat binary with {narch} architectures")
        for i in range(narch):
            base = 8 + i * 20
            cpu = struct.unpack(">I", data[base:base+4])[0]
            if cpu == 0x0100000C:
                offset = struct.unpack(">I", data[base+8:base+12])[0]
                print(f"[+] ARM64 slice at offset {offset:#x}")
                break

    if not offset:
        print("[!] ARM64 slice not found")
        sys.exit(1)

    ncmds = r32(data, offset + 16)
    print(f"[+] Load commands: {ncmds}")

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

    print(f"[+] Sections found: {len(sections)}")

    # Check required sections
    required = [
        ('__TEXT', '__objc_methname'),
        ('__TEXT', '__text'),
    ]
    for seg, sect in required:
        if (seg, sect) in sections:
            foff, vaddr, size = sections[(seg, sect)]
            print(f"[+] {seg}::{sect}: vaddr={vaddr:#x} size={size}")
        else:
            print(f"[!] {seg}::{sect} not found")

    # Find selrefs
    sr_key = None
    for k in [('__DATA', '__objc_selrefs'), ('__DATA_CONST', '__objc_selrefs')]:
        if k in sections:
            sr_key = k
            break

    if not sr_key:
        print("[!] __objc_selrefs not found")
        sys.exit(1)

    print(f"[+] Using {sr_key[0]}::{sr_key[1]} for selrefs")

    # Find installClick selector
    mn_foff, mn_vaddr, mn_size = sections[('__TEXT', '__objc_methname')]
    methnames = data[mn_foff:mn_foff + mn_size]
    ic_off = methnames.find(b'installClick\x00')

    if ic_off < 0:
        print("[!] installClick selector string not found")
        sys.exit(1)

    ic_str = mn_vaddr + ic_off
    print(f"[+] installClick selector string: {ic_str:#x}")

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

    # Search in __TEXT::__text
    text_foff, text_vaddr, text_size = sections[('__TEXT', '__text')]
    print(f"[+] Searching {text_size} bytes of code...")

    found = False
    for i in range(0, text_size - 8, 4):
        insn1 = r32(data, text_foff + i)
        if (insn1 & 0x9F000000) != 0x90000000:
            continue

        insn2 = r32(data, text_foff + i + 4)
        rd = insn1 & 0x1F
        immlo = (insn1 >> 29) & 0x3
        immhi = (insn1 >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & (1 << 32): imm -= (1 << 33)

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
                found = True
                break

    if not found:
        print("[!] No reference to installClick selref found")
        sys.exit(1)

    print("[+] All checks passed!")
    print("[+] Ready to patch")

except Exception as e:
    print(f"[!] Exception: {e}")
    traceback.print_exc()
    sys.exit(1)
