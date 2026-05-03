import struct

def stp_pre(rt1, rt2, rn, imm):
    imm7 = (imm // 8) & 0x7F
    return struct.pack('<I', 0xA9800000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1)

def ldp_post(rt1, rt2, rn, imm):
    imm7 = (imm // 8) & 0x7F
    return struct.pack('<I', 0xA8C00000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1)

def add_imm(rd, rn, imm):
    return struct.pack('<I', 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd)

def adrp(rd, pc_va, target_va):
    pc_page  = pc_va & ~0xFFF
    tgt_page = target_va & ~0xFFF
    imm      = ((tgt_page - pc_page) >> 12) & 0x1FFFFF
    immlo    = imm & 3
    immhi    = (imm >> 2) & 0x7FFFF
    return struct.pack('<I', 0x90000000 | (immlo << 29) | (immhi << 5) | rd)

def ldr_imm(rt, rn, imm):
    imm12 = (imm // 8) & 0xFFF
    return struct.pack('<I', 0xF9400000 | (imm12 << 10) | (rn << 5) | rt)

def bl(pc_va, target_va):
    off   = (target_va - pc_va) & 0xFFFFFFFF
    imm26 = (off >> 2) & 0x3FFFFFF
    return struct.pack('<I', 0x94000000 | imm26)

def b_tail(pc_va, target_va):
    off   = (target_va - pc_va) & 0xFFFFFFFF
    imm26 = (off >> 2) & 0x3FFFFFF
    return struct.pack('<I', 0x14000000 | imm26)

X0,X1,X29,X30,SP = 0,1,29,30,31
installclick_imp_vaddr = 0x10027aa1c
sv_selref_vaddr = 0x100ee5670
ss_selref_vaddr = 0x100eecca0
objc_msgSend_vaddr = 0x100ad8fb8

base = installclick_imp_vaddr
patch = bytearray()
def pc(): return base + len(patch)

patch += stp_pre(X29, X30, SP, -16)
patch += add_imm(X29, SP, 0)
patch += adrp(X1, pc(), sv_selref_vaddr)
patch += ldr_imm(X1, X1, sv_selref_vaddr & 0xFFF)
patch += bl(pc(), objc_msgSend_vaddr)
patch += ldp_post(X29, X30, SP, 16)
patch += adrp(X1, pc(), ss_selref_vaddr)
patch += ldr_imm(X1, X1, ss_selref_vaddr & 0xFFF)
patch += b_tail(pc(), objc_msgSend_vaddr)

print('patch size:', len(patch))
for i in range(0, len(patch), 4):
    w = struct.unpack_from('<I', patch, i)[0]
    va = installclick_imp_vaddr + i
    print('  [%2d] %#x  %#010x' % (i//4, va, w))

# Verify ADRP+LDR for sv_selref (instr[2] and [3])
adrp_i = struct.unpack_from('<I', patch, 8)[0]
ldr_i  = struct.unpack_from('<I', patch, 12)[0]
adrp_va = installclick_imp_vaddr + 8
immlo = (adrp_i >> 29) & 3
immhi = (adrp_i >> 5) & 0x7FFFF
imm = ((immhi << 2) | immlo) << 12
if imm & (1 << 32): imm -= (1 << 33)
page = (adrp_va & ~0xFFF) + imm
imm12 = (ldr_i >> 10) & 0xFFF
resolved = page + imm12 * 8
print()
print('sv_selref resolved=%#x expected=%#x %s' % (resolved, sv_selref_vaddr, 'OK' if resolved==sv_selref_vaddr else 'MISMATCH'))

# Verify ADRP+LDR for ss_selref (instr[6] and [7])
adrp_i2 = struct.unpack_from('<I', patch, 24)[0]
ldr_i2  = struct.unpack_from('<I', patch, 28)[0]
adrp_va2 = installclick_imp_vaddr + 24
immlo2 = (adrp_i2 >> 29) & 3
immhi2 = (adrp_i2 >> 5) & 0x7FFFF
imm2 = ((immhi2 << 2) | immlo2) << 12
if imm2 & (1 << 32): imm2 -= (1 << 33)
page2 = (adrp_va2 & ~0xFFF) + imm2
imm12_2 = (ldr_i2 >> 10) & 0xFFF
resolved2 = page2 + imm12_2 * 8
print('ss_selref resolved=%#x expected=%#x %s' % (resolved2, ss_selref_vaddr, 'OK' if resolved2==ss_selref_vaddr else 'MISMATCH'))
