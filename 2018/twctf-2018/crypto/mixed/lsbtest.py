from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long,long_to_bytes
import os

privkey = RSA.generate(1024)
pubkey = privkey.publickey()
aeskey = bytes_to_long(os.urandom(16))
print "aeskey:",hex(aeskey)[:-1]
aeskey_enc = pubkey.encrypt(aeskey, 0)[0]
print "aeskey_enc:",hex(aeskey_enc)

i = 0
x = 0
C = aeskey_enc
N = pubkey.n
for j in range(800):
    C = (C*(2**65537)%N)
    x = 2 * x
    i += 1

while N >> i:
    print i
    C = (C*(2**65537)%N)
    res = (privkey.decrypt(C)&1)
    if res:
        x = 2 * x + 1
    else:
        x = 2 * x
    i += 1
print hex((x+1) * N / 2 ** i)
print "aeskey:",hex(aeskey)[:-1]
