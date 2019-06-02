#!/usr/bin/env python
# coding=utf-8

from struct import unpack

# reg = ['eax', 'ebx', 'ecx', 'edx']
reg = ['r{}'.format(i) for i in range(16)]
with open('code', 'rb') as f:
    code = f.read()

def getins(s):
    global arg1, arg2
    return '{} {}, {}'.format(s, reg[arg1], reg[arg2])

vpc = 0
res = ''
while vpc < len(code):
    op, flag, arg1, arg2 = unpack('BBhh', code[vpc:vpc+6])
    old = vpc
    vpc += 6
    if op == 9:
        res = 'fail'
    elif op == 8:
        res = 'mov {}, {}'.format(reg[arg1], arg2)
    elif op == 3:
        res = getins('cmp')
    elif op == 4:
        res = 'jmp 0x{:x}'.format(vpc+arg1*6)
    elif op == 1:
        res = getins('add')
    elif op == 15:
        res = getins('shl')
    elif op == 10:
        res = 'mov {}, pw[{}]'.format(reg[arg1], reg[arg2])
    elif op == 13:
        res = getins('mul')
    elif op == 5:
        res = getins('mov')
    elif op == 16:
        res = getins('shr')
    elif op == 11:
        res = 'mov {}, key[{}]'.format(reg[arg1], reg[arg2])
    elif op == 255:
        res = 'right'
    else:
        print 'unknown', op
        break
    print '0x{:x}:\t{}\t{}'.format(old, res, flag)
