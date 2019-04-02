#!/usr/bin/env python
# coding=utf-8

from struct import unpack

def b2n(b):
    tmp = b[::-1].encode('hex')
    return int(tmp, 16)

def parse_ins():
    global vip
    tmp = unpack('H', code[vip:vip+2])[0]
    vip += 2
    op = tmp & 0xf
    arg1 = (tmp >> 4) & 0xf
    arg1 = 'r{}'.format(arg1)
    arg2 = (tmp >> 8) & 0xf
    arg2 = 'r{}'.format(arg2)
    arg3 = (tmp >> 12) & 0xf
    arg3 = 'r{}'.format(arg3)
    return op, arg1, arg2, arg3

with open('./encrypt', 'rb') as f:
    code = f.read()

vip = 0
while vip < len(code):
    old = vip
    op, arg1, arg2, arg3 = parse_ins()
    if op == 0:
        res = 'mov {}, [{} + {}]'.format(arg1, arg2, arg3)
    elif op == 1:
        res = 'mov [{} + {}], {}'.format(arg1, arg2, arg3)
    elif op == 2:
        res = 'jmp {}? if {} == {}'.format(arg3, arg1, arg2)
    elif op == 3:
        res = 'jmp {}? if {} < {}'.format(arg3, arg1, arg2)
    elif op == 5:
        res = 'add {}, {}, {}'.format(arg1, arg2, arg3)
    elif op == 6:
        res = 'sub {}, {}, {}'.format(arg1, arg2, arg3)
    elif op == 7:
        res = 'xor {}, {}, {}'.format(arg1, arg2, arg3)
    elif op == 8:
        res = 'shl {}, {}, {}'.format(arg1, arg2, arg3)
    elif op == 10:
        imm = b2n(code[vip:vip+64])
        vip += 64
        res = 'mov {}, {}'.format(arg1, hex(imm))
    elif op == 15:
        res = 'save enc data'
    else:
        print 'Error {}!'.format(op)
        exit(1)
    print hex(old)+'\t', res

