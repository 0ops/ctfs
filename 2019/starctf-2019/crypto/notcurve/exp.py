__author__ = "polaris"
from Crypto.Util.number import *
from gmpy2 import *
import os,random,sys,string
from hashlib import sha256
from pwn import *
table = string.ascii_letters+string.digits
p = getPrime(15)*getPrime(15)
context.log_level = "debug"

def POW():
    r.recvuntil("sha256(XXXX+")
    suffix = r.recvn(16)
    print suffix
    r.recvuntil("== ")
    sha = r.recvn(64)
    for a in table:
        for b in table:
            for c in table:
                for d in table:
                    if sha256(a+b+c+d+suffix).hexdigest()==sha:
                        print a+b+c+d
                        r.sendline(a+b+c+d)
                        return

def i(x):
    return invert(x,p)

def check_point(A):
    (u,v) = A
    if (u**3+10*u-2)%p == (v**2)%p:
        return 1
    else:
        return 0
def add(A,B):
    assert check_point(A)==1 and check_point(B) == 1
    (u,v),(w,x) = A,B
    assert u!=w or v == x
    if u == w:
        m = (3*u*w+10)*i(v+x)
    else:
        m = (x-v)*i(w-u)
    y = m*m - u - w
    z = m*(u-y) - v
    return int(y % p), int(z % p)

primes = set()
for _ in range(2**15):
    primes.add(getPrime(15))

print "generate ok"
mmmap = {}
for a in primes:
    for b in primes:
        if a==b:
            continue
        p = a*b
        tmp = add((1,3),(1,3))
        mmmap[p] = tmp
print "build ok"
print len(mmmap)


r = remote("34.85.45.159",20005)
POW()
#r.interactive()
r.recvuntil("input>> ")
r.sendline("1")
r.recvline()
r.sendline("1,3")
r.recvline()
r.sendline("1,3")
r.recvuntil("is :")
res = eval(r.recvline().strip())
print res
point = "sacascascasc"
for d in mmmap:
    if mmmap[d]==res:
        point = d
        break
print point
aaaaaaa = [0]*2
for ppp in primes:
    if point%ppp==0:
        aaaaaaa[0] = ppp
        aaaaaaa[1] = point/ppp
r.recvuntil("input>> ")
r.sendline("5")
r.recvuntil("point(pi,qi)")
r.sendline("(%d,%d)"%(aaaaaaa[0],aaaaaaa[1]))
r.interactive()
