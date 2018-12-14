#!/usr/bin/env python
# coding=utf-8
# author: seabreeze

from random import choice
from pwn import *
#context.log_level = 'debug'
# r = process('./unconditional_security')
r = remote('117.50.21.216', 9705)

def test(p, solved=None):
    global idx
    tmp = bytearray([p[i] if i in p else '2' for i in xrange(1024)])
    r.sendafter('GOGOGO: \n', str(tmp))
    r.recvline()
    gained = r.recvline().strip()
    r.recvuntil('ABANDON :\n')
    ap = r.recvline().strip()
    r.recvuntil('ABANDON :\n')
    aq = r.recvline().strip()
    r.recvline()
    r.recvline()
    tmp = r.recvline()
    # log.info(tmp)
    if 'FOUND' not in tmp:
        r.recvline()
        if solved:
            key = ''.join([gained[i] for i in idx])
        else:
            key = ''
        r.sendline(key)
        tmp = r.recvline()
        log.info(tmp)
    return gained, ap, aq

def getp(idx):
    tr = {'0': '1', '1': '0'}
    n = len(idx)
    res = [None] * n
    while None in res:
        bits = [choice('01') for _ in xrange(n)]
        for i, b in enumerate(res):
            if b != None:
                bits[i] = b
        tmp = {idx[i]:bits[i] for i in xrange(n)}
        g, p, q = test(tmp)
        tmp = [i for i in xrange(n) if q[idx[i]] == '1']
        for i in tmp:
            assert res[i] is None
            res[i] = tr[bits[i]]
        # log.info(res)
    return res

if __name__ == '__main__':
    _, p, _ = test({})
    idx = [i for i in xrange(1024) if p[i] == '0']
    res = []
    for i in xrange(0, len(idx), 16):
        tmp1 = getp(idx[i:i+16])
        tmp2 = getp(idx[i:i+16])
        assert tmp1 == tmp2
        print i, tmp1
        res += tmp1
    tmp = {idx[i]:res[i] for i in xrange(len(idx))}
    test(tmp, 1)
    r.close()
