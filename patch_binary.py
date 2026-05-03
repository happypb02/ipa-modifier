#!/usr/bin/env python3
import struct, sys

binary_path = "temp/Payload/DumpApp.app/DumpApp"

with open(binary_path, "rb") as f:
    data = bytearray(f.read())

def read_u32(data, off): return struct.unpack_from("<I", data, off)[0]
def read_u64(data, off): return struct.unpack_from("<Q", data, off)[0]

LC_SEGMENT_64 = 0x19
LC_SYMTAB     = 0x2
LC_DYSYMTAB   = 0xB

def find_sections(data, mh_off):
    sections = {}
    sec_reserved1 = {}
    ncmds = read_u32(data, mh_off + 16)
    p = mh_off + 32
    for _ in range(ncmds):
        cmd     = read_u32(data, p)
        cmdsize = read_u32(data, p + 4)
        if cmd == LC_SEGMENT_64:
            segname = data[p+8:p+24].rstrip(b'\x00').decode()
            nsects  = read_u32(data, p + 64)
            sp = p + 72
            for _ in range(nsects):
                sectname  = data[sp:sp+16].rstrip(b'\x00').decode()
                vm_addr   = read_u64(data, sp + 32)
                vm_size   = read_u64(data, sp + 40)
                file_off  = read_u32(data, sp + 48)
                reserved1 = read_u32(data, sp + 56)
                key = (segname, sectname)
                sections[key] = (file_off, vm_addr, vm_size)
                sec_reserved1[key] = reserved1
                sp += 80
        p += cmdsize
    return sections, sec_reserved1

def vm_to_file(sections, vm_addr):
    for (seg, sect), (foff, vaddr, size) in sections.items():
        if vaddr <= vm_addr < vaddr + size:
            return foff + (vm_addr - vaddr)
    return None

# Locate ARM64 slice
magic  = read_u32(data, 0)
mh_off = 0
if magic == struct.unpack(">I", b'\xCA\xFE\xBA\xBE')[0]:
    narch = struct.unpack_from(">I", data, 4)[0]
    for i in range(narch):
        base     = 8 + i * 20
        cpu_type = struct.unpack_from(">I", data, base)[0]
        if cpu_type == 0x0100000C:
            mh_off = struct.unpack_from(">I", data, base + 8)[0]
            break

sections, sec_reserved1 = find_sections(data, mh_off)
ncmds = read_u32(data, mh_off + 16)

# Parse LC_SYMTAB / LC_DYSYMTAB
symtab_off = strtab_off = indirectsymoff = None
p = mh_off + 32
for _ in range(ncmds):
    cmd     = read_u32(data, p)
    cmdsize = read_u32(data, p + 4)
    if cmd == LC_SYMTAB:
        symtab_off = read_u32(data, p + 8)
        strtab_off = read_u32(data, p + 16)
    elif cmd == LC_DYSYMTAB:
        indirectsymoff = read_u32(data, p + 56)
    p += cmdsize

# Find _objc_msgSend stub address
objc_msgSend_vaddr = None
stubs_key = ('__TEXT', '__stubs')
if stubs_key in sections and symtab_off and indirectsymoff:
    stubs_foff, stubs_vaddr, stubs_size = sections[stubs_key]
    stub_sz    = 12
    stub_count = stubs_size // stub_sz
    reserved1  = sec_reserved1[stubs_key]
    for i in range(stub_count):
        idx = read_u32(data, indirectsymoff + (reserved1 + i) * 4)
        if idx >= 0x40000000:
            continue
        str_idx  = read_u32(data, symtab_off + idx * 16)
        j        = strtab_off + str_idx
        sym_name = b''
        while j < len(data) and data[j] != 0:
            sym_name += bytes([data[j]]); j += 1
        if sym_name == b'_objc_msgSend':
            objc_msgSend_vaddr = stubs_vaddr + i * stub_sz
            print("[+] _objc_msgSend stub vm: {0:#x}".format(objc_msgSend_vaddr))
            break

if not objc_msgSend_vaddr:
    print("[!] _objc_msgSend not found")
    print("[!] Available stubs:")
    for i in range(min(10, stub_count)):
        idx = read_u32(data, indirectsymoff + (reserved1 + i) * 4)
        if idx < 0x40000000:
            str_idx = read_u32(data, symtab_off + idx * 16)
            j = strtab_off + str_idx
            sym_name = b''
            while j < len(data) and data[j] != 0:
                sym_name += bytes([data[j]]); j += 1
            print(f"  [{i}] {sym_name.decode()}")
    sys.exit(1)

# Methnames
mn_key = ('__TEXT', '__objc_methnames')
if mn_key not in sections:
    mn_key = ('__TEXT', '__objc_methname')
mn_foff, mn_vaddr, mn_size = sections[mn_key]
methnames_data = data[mn_foff:mn_foff + mn_size]

ic_off = methnames_data.find(b'installClick\x00')
ss_off = methnames_data.find(b'signSuccess\x00')

if ic_off < 0 or ss_off < 0:
    print("[!] Missing selectors:")
    print(f"  installClick: {ic_off}")
    print(f"  signSuccess: {ss_off}")
    sys.exit(1)

ic_str_vaddr = mn_vaddr + ic_off
ss_str_vaddr = mn_vaddr + ss_off

# Selrefs
selrefs_key = ('__DATA', '__objc_selrefs')
if selrefs_key not in sections:
    selrefs_key = ('__DATA_CONST', '__objc_selrefs')
sr_foff, sr_vaddr, sr_size = sections[selrefs_key]

ic_selref_vaddr = ss_selref_vaddr = sv_selref_vaddr = None
for i in range(0, sr_size, 8):
    ptr = read_u64(data, sr_foff + i)
    if ptr == ic_str_vaddr: ic_selref_vaddr = sr_vaddr + i
    if ptr == ss_str_vaddr: ss_selref_vaddr = sr_vaddr + i
    # Also find selectVC selref for the getter
    if sv_selref_vaddr is None:
        sv_off2 = methnames_data.find(b'selectVC\x00')
        if sv_off2 >= 0:
            sv_str_va2 = mn_vaddr + sv_off2
            if ptr == sv_str_va2:
                sv_selref_vaddr = sr_vaddr + i
                print("[+] selectVC selref: {0:#x}".format(sv_selref_vaddr))

print("[+] installClick selref: {0:#x}".format(ic_selref_vaddr) if ic_selref_vaddr else "[!] installClick selref not found")
print("[+] signSuccess  selref: {0:#x}".format(ss_selref_vaddr) if ss_selref_vaddr else "[!] signSuccess selref not found")

if not all([ic_selref_vaddr, ss_selref_vaddr, sv_selref_vaddr]):
    print("[!] Missing required selrefs:")
    print(f"  installClick: {ic_selref_vaddr}")
    print(f"  signSuccess: {ss_selref_vaddr}")
    print(f"  selectVC: {sv_selref_vaddr}")
    sys.exit(1)

# Find installClick IMP
classname = b'DASignProcessVC\x00'
classname_foff = data.find(classname)
classname_vaddr = None
for (seg, sect), (foff, vaddr, size) in sections.items():
    if foff <= classname_foff < foff + size:
        classname_vaddr = vaddr + (classname_foff - foff); break

installclick_imp_vaddr = None
if classname_vaddr:
    classname_bytes = struct.pack("<Q", classname_vaddr)
    for search_foff in range(0, len(data) - 48, 8):
        if data[search_foff+24:search_foff+32] == classname_bytes:
            base_methods_vm = read_u64(data, search_foff + 32)
            if base_methods_vm:
                ml_foff = vm_to_file(sections, base_methods_vm)
                if ml_foff:
                    ml_flags = read_u32(data, ml_foff)
                    ml_count = read_u32(data, ml_foff + 4)
                    is_rel   = bool(ml_flags & 0x80000000)
                    msz = 12 if is_rel else 24
                    for i in range(ml_count):
                        m_foff  = ml_foff + 8 + i * msz
                        m_vaddr = base_methods_vm + 8 + i * msz
                        if not is_rel:
                            n_ptr = read_u64(data, m_foff)
                            if n_ptr == ic_str_vaddr or n_ptr == ic_selref_vaddr:
                                installclick_imp_vaddr = read_u64(data, m_foff + 16)
                                print("[+] installClick IMP vm: {0:#x}".format(installclick_imp_vaddr))
                                break
            if installclick_imp_vaddr: break

if not installclick_imp_vaddr:
    print("[!] installClick IMP not found"); sys.exit(1)

installclick_imp_foff = vm_to_file(sections, installclick_imp_vaddr)
print("[+] installClick IMP file offset: {0:#x}".format(installclick_imp_foff))

# === Build 112-byte patch ===
# installClick IMP (base_va = installclick_imp_vaddr)
# Prologue: STP+STP+ADD frame (12 bytes)
# Code: 17 instructions x 4 = 68 bytes
# Litpool: 4 x 8 = 32 bytes
# Total: 112 bytes

base = installclick_imp_vaddr

def adr_imm(rd, from_va, to_va):
    pc   = from_va + 4
    imm  = to_va - pc
    imm  = (imm + 0x200000) & 0x1FFFFF
    return struct.pack("<I", 0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | rd)

def bl_insn(pc_va, target_va):
    off   = target_va - pc_va
    imm26 = ((off >> 2) & 0x3FFFFFF)
    return struct.pack("<I", 0x94000000 | imm26)

def b_insn(pc_va, target_va):
    off   = target_va - pc_va
    imm26 = ((off >> 2) & 0x3FFFFFF)
    return struct.pack("<I", 0x14000000 | imm26)

# Litpool starts at base+32 (after 32 bytes of code)
litpool_va = base + 32

patch = bytearray()
patch += bytes([0xa9, 0xbf, 0x7b, 0xfd])   # STP X29,X30,[SP,#-32]!
patch += bytes([0x91, 0x00, 0x3f, 0xfd])   # ADD X29,SP,#0

# [self selectVC]
patch += adr_imm(1, base+8, litpool_va)
patch += bytes([0xf9, 0x40, 0x00, 0x01])   # LDR X1,[X1,#0]
patch += bl_insn(base+16, objc_msgSend_vaddr)

# Restore and tail call [selectVC signSuccess]
patch += bytes([0xa8, 0xc1, 0x7b, 0xfd])   # LDP X29,X30,[SP],#32
patch += adr_imm(1, base+24, litpool_va+8)
patch += bytes([0xf9, 0x40, 0x00, 0x01])   # LDR X1,[X1,#0]
patch += b_insn(base+32, objc_msgSend_vaddr)

assert len(patch) == 32, "code part is {0} bytes (expected 32)".format(len(patch))

# Litpool
patch += struct.pack("<Q", sv_selref_vaddr)  # selectVC selref
patch += struct.pack("<Q", ss_selref_vaddr)  # signSuccess selref

assert len(patch) == 48, "patch size {0} (expected 48)".format(len(patch))

data[installclick_imp_foff:installclick_imp_foff + 48] = patch
print("[+] Wrote {0}-byte ARM64 patch at file offset {1:#x}".format(len(patch), installclick_imp_foff))

with open(binary_path, "wb") as f:
    f.write(data)
print("[+] Binary patched successfully")
