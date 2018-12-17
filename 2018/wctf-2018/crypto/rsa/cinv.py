#!/usr/bin/env python
# coding=utf-8

import sys
from struct import unpack, pack

def gcd(a,b):
    while a!=0:
        a,b = b%a,a
    return b

def inv(a,m):
    if gcd(a,m)!=1:
        return None
    u1,u2,u3 = 1,0,a
    v1,v2,v3 = 0,1,m
    while v3!=0:
        q = u3//v3
        v1,v2,v3,u1,u2,u3 = (u1-q*v1),(u2-q*v2),(u3-q*v3),v1,v2,v3
    return u1%m

def divmod(a, b, m):
    return inv(b, m) * a % m

start = int(sys.argv[2])
length = int(sys.argv[1])
m = 0x10000000000000000
n = 0x0bdd05cc7fef2c91f

f1 = open('record', 'rb')
f2 = open('inv{}'.format(start/length), 'wb')
f3 = open('rec{}'.format(start/length), 'wb')

f1.seek(start*8)
for i in xrange(length):
    if i & 0xfffff == 0:
        print hex(i)
    tmp = unpack('>Q', f1.read(8))[0]
    f3.write(pack('Q', tmp))
    f3.flush()
    if tmp % 2 == 0:
        f2.write(pack('Q', 0))
    else:
        tmp = divmod(n, tmp, m)
        f2.write(pack('Q', tmp))
    f2.flush()

f1.close()
f2.close()
f3.close()
