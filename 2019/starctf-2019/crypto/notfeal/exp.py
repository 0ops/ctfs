__author__ = "polaris"
from pwn import *
import string
from hashlib import sha256
table = string.ascii_letters+string.digits

p = remote("127.0.0.1",10001)
#p = remote("34.92.185.118",10001)
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

#POW()
def encrypt(data):
    p.recvuntil("(hex): ")
    tmp = hex(data)[2:]
    tmp = tmp.rjust(16,"0")
    print tmp
    p.sendline(tmp)
    enc = int(p.recvn(16),16)
    return enc

def encrypt_diff(data,diff):
    res1 = encrypt(data)
    res2 = encrypt(data^diff)
    return [[data,res1],[data^diff,res2]]

import random
from Crypto.Util.number import *
def reverse(data):
    a = long_to_bytes(data)
    a1 = a[:4]
    a2 = a[4:]
    return bytes_to_long(a1[::-1]+a2[::-1])




plain0 = [random.randint(0,2**64) for i in range(12)]
cipher0 = []
plain1 = []
plain2 = []
plain3 = []
cipher1 = []
cipher2 = []
cipher3 = []


for data in plain0:
    plain1.append(data^0x8080000080800002)
    plain2.append(data^0x8080000080800000)
    plain3.append(data^0x000000200000000)
    cipher0.append(encrypt(data))
    cipher1.append(encrypt(plain1[-1]))
    cipher2.append(encrypt(plain2[-1]))
    cipher3.append(encrypt(plain3[-1]))

p.sendline("")
p.recvuntil("flag:\n")
flag = p.recvline()
print flag
print "unsigned long long plain0[20] = "+plain0.__str__().replace("L","").replace("[","{").replace("]","};")
print "unsigned long long plain1[20] = "+plain1.__str__().replace("L","").replace("[","{").replace("]","};")
print "unsigned long long plain2[20] = "+plain2.__str__().replace("L","").replace("[","{").replace("]","};")
print "unsigned long long plain3[20] = "+plain3.__str__().replace("L","").replace("[","{").replace("]","};")
print "unsigned long long cipher0[20] = "+cipher0.__str__().replace("L","").replace("[","{").replace("]","};")
print "unsigned long long cipher1[20] = "+cipher1.__str__().replace("L","").replace("[","{").replace("]","};")
print "unsigned long long cipher2[20] = "+cipher2.__str__().replace("L","").replace("[","{").replace("]","};")
print "unsigned long long cipher3[20] = "+cipher3.__str__().replace("L","").replace("[","{").replace("]","};")

p.interactive()
