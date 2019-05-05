#!/usr/bin/env python
# coding=utf-8

from capstone import *
from pwn import asm
from struct import unpack
import re

start = 0x27a0
end = 0x10B80
with open('./test_matrix', 'rb') as f:
    out = bytearray(f.read(start))
    m = f.read()

def get_data(addr):
    addr = eval(addr)
    res = unpack('I', m[addr-0x1000-start:addr-0x1000-start+4])[0]
    return res

cs = Cs(CS_ARCH_X86,CS_MODE_32)
flag = False
flag1 = False
cnt1 = 0
for ins in cs.disasm(m, start):
    op, arg = ins.mnemonic, ins.op_str
    tmp = ins.bytes
    if flag:
        flag = False
        if op == 'jne':
            assert len(ins.bytes) == 2
            tmp = '\x90\x90'
    elif op in ('sub', 'xor'):
        a1, a2 = arg.split(', ')
        if a1 == a2:
            flag = True
    if op == 'lea' and len(arg) > 30:
        tmp = '\x90' * len(tmp)
    if flag1:
        e = None
        try:
            reg2, num = arg.split(', ')
        except ValueError as e:
            print hex(ins.address), op, arg
        if not e:
            try:
                num = eval(num)
            except NameError as e:
                pass
            except SyntaxError as e:
                pass
        if reg2 == reg1 and not e:
            cnt1 += len(tmp)
            tmp = ''
            if op == 'shl':
                data <<= num
                data &= 0xffffffff
            elif op == 'xor':
                data ^= num
            elif op == 'add':
                data = (data + num) & 0xffffffff
            elif op == 'sub':
                data = (data - num) & 0xffffffff
            elif op == 'shr':
                data >>= num
            else:
                print op
                assert 0
        else:
            flag1 = False
            resins = 'mov {}, {}'.format(reg1, data)
            print 'Result', resins
            new = asm(resins, arch='i386')
            tmp = '\x90'*(cnt1-len(new)) + new + tmp
            cnt1 = None
    elif op == 'mov':
        rex = re.search('(.*?), dword ptr \\[(0x[1234567890abcdef]*?)\\]', arg)
        if rex:
            print hex(ins.address), op, arg
            reg1, data = rex.group(1, 2)
            data = get_data(data)
            flag1 = True
            cnt1 = len(tmp)
            tmp = ''
    out += tmp
    if len(out) == end:
        break
out += m[end-start:]
with open('./test_matrix2', 'wb') as f:
    f.write(str(out))
