__author__  = "polaris"

from pwn import *

p = remote("arcade.fluxfingers.net",1821)

def ADD(a):
    p.recvuntil("-----------------------------*")
    p.sendline("ADD")
    p.recvuntil(" >>> ")
    p.sendline(hex(a)[2:])
    p.recvuntil("Ciphertext is ")
    return p.recvline().strip()+p.recvline().strip()

def XOR(a):
    p.recvuntil("-----------------------------*")
    p.sendline("XOR")
    p.recvuntil(" >>> ")
    p.sendline(hex(a)[2:])
    p.recvuntil("Ciphertext is ")
    return p.recvline().strip()+p.recvline().strip()

res = ""
for i in range(16*8):
    a = ADD(1<<i)
    b = XOR(1<<i)
    if a==b:
        res = "0"+res
    else:
        res = "1"+res
    print a
    print b
    print res

res = int(res,2)
import base64
from Crypto.Util.number import long_to_bytes

aaa = base64.b64encode(long_to_bytes(res))

p.recvuntil("-----------------------------*")
p.sendline("DEC")
p.recvuntil(" >>> ")
p.sendline(aaa)
p.interactive()
