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

# Parse Mach-O header
magic = read_u32(data, 0)
if magic == 0xFEEDFACF:  # MH_MAGIC_64
    offset = 0
elif magic == 0xCAFEBABE:  # FAT
    narch = struct.unpack(">I", data[4:8])[0]
    offset = None
    for i in range(narch):
        base = 8 + i * 20
        cpu_type = struct.unpack(">I", data[base:base+4])[0]
        if cpu_type == 0x0100000C:  # ARM64
            offset = struct.unpack(">I", data[base+8:base+12])[0]
            break
    if offset is None:
        print("[!] ARM64 slice not found")
        sys.exit(1)
else:
    print(f"[!] Unknown magic: {magic:#x}")
    sys.exit(1)

ncmds = read_u32(data, offset + 16)
sizeofcmds = read_u32(data, offset + 20)

# Parse load commands to find sections
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

print("[+] Found sections:")
for key in sections:
    print(f"  {key}")

# Find __objc_methname
mn_key = ('__TEXT', '__objc_methname')
if mn_key not in sections:
    print("[!] __objc_methname not found")
    sys.exit(1)

mn_foff, mn_vaddr, mn_size = sections[mn_key]
methnames_data = data[mn_foff:mn_foff + mn_size]

# Find installClick selector
ic_off = methnames_data.find(b'installClick\x00')
if ic_off < 0:
    print("[!] installClick selector not found")
    sys.exit(1)

ic_str_vaddr = mn_vaddr + ic_off
print(f"[+] installClick selector at: {ic_str_vaddr:#x}")

# Find selref
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

if not ic_selref_vaddr:
    print("[!] installClick selref not found")
    sys.exit(1)

print(f"[+] installClick selref at: {ic_selref_vaddr:#x}")

# Find DASignProcessVC class and installClick method
classname = b'DASignProcessVC\x00'
classname_foff = data.find(classname)
classname_vaddr = None
for (seg, sect), (foff, vaddr, size) in sections.items():
    if foff <= classname_foff < foff + size:
        classname_vaddr = vaddr + (classname_foff - foff)
        break

if not classname_vaddr:
    print("[!] DASignProcessVC class name not found")
    sys.exit(1)

print(f"[+] DASignProcessVC class name at: {classname_vaddr:#x}")

# Find class_ro_t
classname_bytes = struct.pack("<Q", classname_vaddr)
installclick_imp_vaddr = None

for search_foff in range(0, len(data) - 48, 8):
    if data[search_foff+24:search_foff+32] == classname_bytes:
        base_methods_vm = read_u64(data, search_foff + 32)
        if base_methods_vm:
            for (seg, sect), (foff, vaddr, size) in sections.items():
                if vaddr <= base_methods_vm < vaddr + size:
                    methods_foff = foff + (base_methods_vm - vaddr)
                    entsize = read_u32(data, methods_foff) & 0xFFFF
                    count = read_u32(data, methods_foff + 4)

                    print(f"[+] Found {count} methods in DASignProcessVC")
                    for i in range(count):
                        method_base = methods_foff + 8 + i * entsize
                        sel_vm = read_u64(data, method_base)
                        imp_vm = read_u64(data, method_base + 8)

                        # Debug: print all method selectors
                        for (seg2, sect2), (foff2, vaddr2, size2) in sections.items():
                            if vaddr2 <= sel_vm < vaddr2 + size2:
                                sel_foff = foff2 + (sel_vm - vaddr2)
                                sel_end = data.find(b'\x00', sel_foff)
                                if sel_end > sel_foff:
                                    sel_name = data[sel_foff:sel_end].decode('utf-8', errors='ignore')
                                    print(f"  Method: {sel_name} (sel={sel_vm:#x}, imp={imp_vm:#x})")
                                    if sel_name == 'installClick':
                                        installclick_imp_vaddr = imp_vm
                                        print(f"[+] Found installClick IMP at: {installclick_imp_vaddr:#x}")
                                break
                    break
        if installclick_imp_vaddr:
            break

if not installclick_imp_vaddr:
    print("[!] installClick method not found")
    sys.exit(1)

# Find file offset of IMP
installclick_imp_foff = None
for (seg, sect), (foff, vaddr, size) in sections.items():
    if vaddr <= installclick_imp_vaddr < vaddr + size:
        installclick_imp_foff = foff + (installclick_imp_vaddr - vaddr)
        break

if installclick_imp_foff is None:
    print("[!] installClick IMP file offset not found")
    sys.exit(1)

print(f"[+] installClick IMP file offset: {installclick_imp_foff:#x}")

# Try to find selectVC getter method
print("\n[*] Looking for selectVC getter...")
sv_off = methnames_data.find(b'selectVC\x00')
if sv_off >= 0:
    sv_str_vaddr = mn_vaddr + sv_off
    print(f"[+] selectVC selector string at: {sv_str_vaddr:#x}")

    # Find selectVC selref
    sv_selref_vaddr = None
    for i in range(0, sr_size, 8):
        ptr = read_u64(data, sr_foff + i)
        if ptr == sv_str_vaddr:
            sv_selref_vaddr = sr_vaddr + i
            print(f"[+] selectVC selref at: {sv_selref_vaddr:#x}")
            break

    if not sv_selref_vaddr:
        print("[!] selectVC selref not found - property might use direct ivar access")

        # Try to find the getter by looking at DASignProcessVC methods
        for search_foff in range(0, len(data) - 48, 8):
            if data[search_foff+24:search_foff+32] == classname_bytes:
                base_methods_vm = read_u64(data, search_foff + 32)
                if base_methods_vm:
                    for (seg, sect), (foff, vaddr, size) in sections.items():
                        if vaddr <= base_methods_vm < vaddr + size:
                            methods_foff = foff + (base_methods_vm - vaddr)
                            entsize = read_u32(data, methods_foff) & 0xFFFF
                            count = read_u32(data, methods_foff + 4)

                            print(f"[+] DASignProcessVC has {count} methods")
                            for i in range(count):
                                method_base = methods_foff + 8 + i * entsize
                                sel_vm = read_u64(data, method_base)
                                imp_vm = read_u64(data, method_base + 8)

                                # Find selector name
                                for (seg2, sect2), (foff2, vaddr2, size2) in sections.items():
                                    if vaddr2 <= sel_vm < vaddr2 + size2:
                                        sel_foff = foff2 + (sel_vm - vaddr2)
                                        sel_end = data.find(b'\x00', sel_foff)
                                        sel_name = data[sel_foff:sel_end].decode('utf-8', errors='ignore')
                                        if 'select' in sel_name.lower():
                                            print(f"  - {sel_name}: IMP at {imp_vm:#x}")
                                        break
                            break
                break

# Patch: just RET
patch = bytes([0xC0, 0x03, 0x5F, 0xD6])  # RET
data[installclick_imp_foff:installclick_imp_foff + 4] = patch

with open(binary_path, "wb") as f:
    f.write(data)

print("[+] Patched installClick to RET (no-op)")
print("[+] Binary patched successfully")
