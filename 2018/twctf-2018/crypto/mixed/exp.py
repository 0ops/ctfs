__author__ = "polaris"

from pwn import *
from Crypto.Util.number import long_to_bytes,bytes_to_long,GCD
from Crypto.Cipher import AES
from mt19937predictor import MT19937Predictor
import random
import binascii
import math

BLOCK_SIZE = 16
r = remote("crypto.chal.ctf.westerns.tokyo",5643)
pre = MT19937Predictor()
#context.log_level = "debug"
def init():
    for i in range(6):
        r.recvline()

def encrypt(data):
    r.sendline("1")
    r.recvuntil("text: ")
    r.sendline(data)
    r.recvuntil("RSA: ")
    rsa = binascii.unhexlify(r.recvline()[:-1])
    r.recvuntil("AES: ")
    aes = binascii.unhexlify(r.recvline()[:-1])
    init()
    return (rsa,aes)

init()

#get n
def encrypt_n(n):
    (rsa,aes) = encrypt(chr(n))
    return bytes_to_long(rsa)
c2 = encrypt_n(2)
c5 = encrypt_n(5)
c4 = encrypt_n(4)
c25 = encrypt_n(25)
n1 = c2*c2-c4
n2 = c5*c5-c25
n = GCD(n1,n2)
print(n)
print("get n ok")

#get aeskey
def decrypt(data):
    r.sendline("2")
    r.recvuntil("text: ")
    r.sendline(data)
    r.recvuntil("RSA: ")
    rsa = binascii.unhexlify(r.recvline()[:-1])
    init()
    return bytes_to_long(rsa)

def get_key():
    r.sendline("4")
    r.recvline()
    key = binascii.unhexlify(r.recvline()[:-1])
    init()
    return bytes_to_long(key)

aeskey_enc = get_key()
print(aeskey_enc)
C = aeskey_enc
low = 0
high = n
iter_count = math.log(n, 2)
for i in range(0, math.ceil(iter_count)):
    print(i)
    C = ((C*(2**65537))%n)
    data = binascii.hexlify(long_to_bytes(C))
    rsa = decrypt(data)
    if (rsa&1)==1:
        low = (low+high)//2
    else:
        high = (low+high)//2
print(high)
print(low)
assert (((high**65537)%n)==aeskey_enc)
aeskey = long_to_bytes(high)
print(aeskey)
print("aeskey ok")

# predictor

for i in range(160):
    print(i)
    (rsa,aes) = encrypt("AAA")
    iv = bytes_to_long(aes[:BLOCK_SIZE])
    pre.setrandbits(iv,8*BLOCK_SIZE)
(rsa,aes) = encrypt("AAA")
iv = bytes_to_long(aes[:BLOCK_SIZE])
p = pre.getrandbits(8*BLOCK_SIZE)
assert iv==p
print(iv)
print(p)
print("predictor ok")


#get flag
def get_flag():
    r.sendline("3")
    r.recvline()
    r.recvline()
    flag = binascii.unhexlify(r.recvline()[:-1])
    init()
    return flag

flag_enc = get_flag()
print(flag_enc)
iv = long_to_bytes(pre.getrandbits(8*BLOCK_SIZE),16)
aes = AES.new(aeskey, AES.MODE_CBC, iv)
flag = aes.decrypt(flag_enc[BLOCK_SIZE:])
print(flag)