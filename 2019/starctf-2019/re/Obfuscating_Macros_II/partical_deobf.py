#!/usr/bin/env python
# coding=utf-8

from capstone import *
from pwn import asm, context
import re

start = 0x1006
end = 0x3c9d
with open('./obfuscating_macros_II.out', 'rb') as f:
    m = f.read()

context.arch = 'amd64'
cs = Cs(CS_ARCH_X86,CS_MODE_64)
out = bytearray(m[:start])

flag1 = False
cnt1 = 0
for ins in cs.disasm(m[start:], start+0x400000):
    op, arg = ins.mnemonic, ins.op_str
    tmp = ins.bytes
    if flag1:
        flag1 = False
        if op == 'call' and arg == '0x4040a2':
            assert len(tmp) == 5
            data ^= 0x78ABDA5F
            data -= 0x57419F8E
            data &= ((1<<64)-1)
            assert data < (1<<32)
            new = asm('mov eax, {}'.format(data))
            assert len(new) <= 5
            tmp = '\x90'*(5-len(new)) + new
            cnt1 += 1
    elif op == 'mov':
        arg1, arg2 = arg.split(', ')
        if arg1.endswith('di'):
            flag1 = True
            try:
                data = eval(arg2)
            except NameError as e:
                flag1 = False
            except SyntaxError as e:
                flag1 = False

    out += tmp
    if len(out) == end:
        out += m[end:]
        break

with open('./test_obf', 'wb') as f:
    f.write(str(out))
print cnt1
