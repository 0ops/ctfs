__author__ = "polaris"

from pwn import *
import string

context.log_level = "debug"
r = remote("crypto.chal.ctf.westerns.tokyo",14791)
table = string.printable[:-5]


r.recvuntil("encrypted flag: ")
enc = r.readline()[:-1]

flag = "TWCTF{6"
mmm = []
for c in table:
    payload = (flag+c).ljust(47,"B")
    r.recvuntil("message:")
    r.sendline(payload)
    r.recvuntil("ciphertext: ")
    a = r.readline()[:-1]
    assert(len(a)==len(enc))

    aa = 0
    for i in range(len(a)):
        if a[i]==enc[i]:
            aa+=1
        else:
            break
    mmm.append(aa)
print mmm