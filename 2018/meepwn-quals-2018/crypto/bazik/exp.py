from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes,bytes_to_long
from gmpy2 import iroot

#r = remote("178.128.17.82",31333)

public_key = RSA.importKey(open('key.pub', 'r').read())
print public_key.n
print public_key.e
n = public_key.n
e = public_key.e


"""
data = "Your OTP for transaction #731337 in ABCXYZ Bank is 678637830."
print hex(bytes_to_long(data))
data = "Your OTP for transaction #731337 in ABCXYZ Bank is 797953094."
print hex(bytes_to_long(data))
"""
"""
c = 0x67b8a854c0b75bfe36eafa5306cef4b5e127fd99ae30594f7a5b3605bd2e497e399ad202c2279df8a9d5ff56f85fbbc8379d88e02f3e366245ee3b949d6fb70749d8a84cfb96964057e4783c4b78324e070d89049da7fb8bf49f91d63d804e63f84489a3fdb8792a86928fcc512df5f4c7bfdc5102be5c7603964a717d9a3dc8
"""
"""
data = c
i=0
while 1:
    res = iroot(data,3)
    if(res[1] == True):
        print res
        break
    if i%10000==0:
        print "i="+str(i)
    data+=n
    i+=1
"""