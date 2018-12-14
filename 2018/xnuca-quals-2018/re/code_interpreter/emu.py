#!/usr/bin/env python
# coding=utf-8
# author: seabreeze

from struct import unpack

def get_str(ins):
    global vpc
    a, b = code[vpc], code[vpc+1]
    vpc += 2
    if '{}' not in ins:
        res = '{}   {}, {}'.format(ins, a, b)
    else:
        res = ins.format(a, b)
    return res


with open('code', 'rb') as f:
    code = bytearray(f.read())

vpc = 0
vsp = 2

while vpc < len(code):
    op = code[vpc]
    vpc += 1
    if op == 0:
        res = 'end'
    elif op == 1:
        res = 'push 0x{:08x}'.format(unpack('I', str(code)[vpc:vpc+4])[0])
        vpc += 4
    elif op == 2:
        res = 'pop'
    elif op == 3:
        res = get_str('add')
    elif op == 4:
        res = get_str('sub')
    elif op == 5:
        res = get_str('mul')
    elif op == 6:
        res = get_str('shr')
    elif op == 7:
        res = get_str('mov')
    elif op == 8:
        res = get_str('mov {}, [rbp + {}]')
    elif op == 9:
        res = get_str('xor')
    elif op == 10:
        res = get_str('or')
    else:
        assert 0
    print res
