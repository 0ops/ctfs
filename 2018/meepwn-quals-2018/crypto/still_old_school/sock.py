#!/usr/bin/env python
# coding=utf-8

from pwn import remote, log
from hashlib import sha256
from itertools import product


def enc(m='a'*16):
    r.sendlineafter('> ', '1')
    r.sendlineafter(': ', m)
    res = r.recvline().strip()
    return res[:32].decode('hex'), res[32:].decode('hex')

def getflag():
    r.sendlineafter('> ', '3')
    res = r.recvline().strip()
    return res[:32].decode('hex'), res[32:].decode('hex')

def b2n(b):
    return int(b.encode('hex'), 16)

ns = '1234567890'

r = remote("206.189.32.108", 13579)
tmp = r.recvline()
log.info(tmp)
pre = tmp[9:].strip()
log.info(pre)

for i in product(ns, repeat=10):
    ans = ''.join(i)
    if sha256(pre.decode('hex')+ans).hexdigest().startswith('00000'):
        log.info('find %s', ans)
        r.sendlineafter('> ', ans)
        break
'''
iv, c = enc()
log.info('iv: %s, %d', repr(iv), len(iv))
log.info('ctext: %s, %d', repr(c), len(c))
iv, c = enc()
log.info('iv: %s, %d', repr(iv), len(iv))
log.info('ctext: %s, %d', repr(c), len(c))
'''
ivs = [int(pre, 16)]
for i in range(156):
    print i
    iv, c = enc()
    ivs.append(b2n(iv))
with open('record', 'w') as f:
    f.write(str(ivs))
log.info('iv: %s, %d', iv.encode('hex'), len(iv))
log.info('ctext: %s, %d', c.encode('hex'), len(c))
iv, c = getflag()
log.info('flag_iv: %s, %d', repr(iv), len(iv))
log.info('flag_ctext: %s, %d', repr(c), len(c))
