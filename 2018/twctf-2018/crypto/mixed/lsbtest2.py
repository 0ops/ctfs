from Crypto.Util.number import bytes_to_long,long_to_bytes,getPrime
import os

aeskey = bytes_to_long(os.urandom(2))
print "aeskey:",hex(aeskey)[:-1]

p = aeskey
N = getPrime(8)*getPrime(8)
print N
low = 0
high = N
while low<high-1:
    p = (p<<1)
    print (low<aeskey) and (aeskey<high),
    print hex(low),
    print hex(high),
    print hex(aeskey),
    print hex(p)
    if p>N:
        p-=N
        low = ((low+high)>>1)
    else:
        high = ((low+high)>>1)

i = 0
x = 0
while N >> i:
    res = query(i+1)
    if res:
        x = 2 * x + 1
    else:
        x = 2 * x
    i += 1
return (x+1) * n // 2 ** i
print "real: ",hex(aeskey)[:-1]
print "get:  ",hex(high)[:-1]
